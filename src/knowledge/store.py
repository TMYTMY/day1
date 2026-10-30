"""On-disk vector index for uploaded knowledge-base documents.

Chunks and their vectors live in SQLite under data/knowledge/. Search is
cosine similarity in NumPy. The warehouse database is never opened here, and
uploaded SQL is stored as text only.

Documents carry the role that uploaded them. Search, prompt notes and the
listing are scoped to that role, and only the uploader may delete or re-index
a file. Rows written before this scoping existed have an empty owner_role: they
stay visible in the listing so someone can adopt them, but they are excluded
from search and from prompt notes until re-indexed.

Each document also has an approval: ``draft``, ``approved``, or ``rejected``.
New uploads are ``draft``. Rows written before approval existed are
``approved`` (the column default). Live search returns approved, indexed text
only. PDF, XLSX, and PNG are stored under data/knowledge/files/ and never
chunked, so they cannot enter retrieval. PNG is marked ``non-indexed``.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import numpy as np

from src.config import Settings
from src.knowledge.chunk import chunk_document
from src.knowledge.embed import Embedder, KnowledgeEmbedError

INDEXED_EXTENSIONS = frozenset({"csv", "sql", "ddl", "md", "txt", "json"})
STORED_EXTENSIONS = frozenset({"pdf", "xlsx", "png"})
ALLOWED_EXTENSIONS = INDEXED_EXTENSIONS | STORED_EXTENSIONS
# Retrieval refuses these even if a later write put chunks on the row.
_NOT_RETRIEVED = frozenset({"pdf", "xlsx", "png"})
MAX_BYTES = 2_000_000
SCORE_MIN = 0.18
_LOCKS: dict[str, threading.Lock] = {}
_DOC_ID = re.compile(r"^[0-9a-f]{32}$")

APPROVAL_DRAFT = "draft"
APPROVAL_APPROVED = "approved"
APPROVAL_REJECTED = "rejected"
APPROVALS = frozenset({APPROVAL_DRAFT, APPROVAL_APPROVED, APPROVAL_REJECTED})

# Shown on the card. PNG's value is the badge text.
SKIP_REASONS = {
    "pdf": (
        "Stored only. PDF text is not extracted in this version, "
        "so this file is excluded from retrieval."
    ),
    "xlsx": (
        "Stored only. Spreadsheet text is not extracted in this version, "
        "so this file is excluded from retrieval."
    ),
    "png": "non-indexed",
}

# Viewer-scoping columns, added to indexes written by earlier builds.
# approval defaults to approved so files already in the index stay live.
_DOCUMENT_COLUMNS = (
    ("owner", "TEXT NOT NULL DEFAULT ''"),
    ("owner_role", "TEXT NOT NULL DEFAULT ''"),
    ("approval", "TEXT NOT NULL DEFAULT 'approved'"),
    ("indexed", "INTEGER NOT NULL DEFAULT 1"),
    ("skip_reason", "TEXT NOT NULL DEFAULT ''"),
)

# Documents are visible to their own role. The sentinel role below is reserved
# for material an operator deliberately wants every role to read.
SHARED_ROLE = "shared"



class KnowledgeError(Exception):
    """A document could not be indexed."""


@dataclass(frozen=True)
class KnowledgeDocument:
    id: str
    filename: str
    extension: str
    byte_size: int
    chunk_count: int
    updated_at: str
    embedding_id: str
    embedding_dim: int
    truncated: bool
    owner: str = ""
    owner_role: str = ""
    legacy: bool = False
    approval: str = APPROVAL_APPROVED
    indexed: bool = True
    skip_reason: str = ""


@dataclass(frozen=True)
class Snippet:
    filename: str
    text: str
    score: float


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    """Add scoping columns to an index created before per-role access.

    CREATE TABLE IF NOT EXISTS never alters an existing table, so an index
    written by an earlier build keeps the old shape and every insert fails.
    Probe the table first, then ALTER only what is missing.
    """
    present = {row["name"] for row in conn.execute("PRAGMA table_info(documents)")}
    for name, spec in _DOCUMENT_COLUMNS:
        if name not in present:
            conn.execute(f"ALTER TABLE documents ADD COLUMN {name} {spec}")


def _lock_for(path: Path) -> threading.Lock:
    key = str(path)
    lock = _LOCKS.get(key)
    if lock is None:
        lock = threading.Lock()
        _LOCKS[key] = lock
    return lock


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extension(filename: str) -> str:
    suffix = Path(filename).suffix.lower().lstrip(".")
    if suffix not in ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise KnowledgeError(f"Use one of these file types: {allowed}.")
    return suffix


class KnowledgeStore:
    def __init__(self, settings: Settings, post=None):
        self.settings = settings
        self.embedder = Embedder(settings, post=post)
        self.directory = Path(settings.knowledge_path)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "index.sqlite"
        self._lock = _lock_for(self.path.resolve())
        with self._lock, self._session() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    extension TEXT NOT NULL,
                    byte_size INTEGER NOT NULL,
                    chunk_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    embedding_id TEXT NOT NULL,
                    embedding_dim INTEGER NOT NULL,
                    truncated INTEGER NOT NULL,
                    body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chunks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    embedding BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_chunks_document
                    ON chunks(document_id);
                CREATE TABLE IF NOT EXISTS embedding_cache (
                    content_hash TEXT NOT NULL,
                    embedding_id TEXT NOT NULL,
                    dim INTEGER NOT NULL,
                    vector BLOB NOT NULL,
                    PRIMARY KEY (content_hash, embedding_id)
                );
                """
            )
            _add_missing_columns(conn)
        self.embedder.bind_cache(self._cached_embedding, self._store_embedding)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _cached_embedding(self, text: str) -> np.ndarray | None:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self._lock, self._session() as conn:
            row = conn.execute(
                """
                SELECT dim, vector FROM embedding_cache
                WHERE content_hash = ? AND embedding_id = ?
                """,
                (digest, self.embedder.embedding_id),
            ).fetchone()
        if row is None:
            return None
        vector = np.frombuffer(bytes(row["vector"]), dtype=np.float32).copy()
        if vector.shape != (int(row["dim"]),):
            return None
        return vector

    def _store_embedding(self, text: str, vector: np.ndarray) -> None:
        array = np.asarray(vector, dtype=np.float32).reshape(-1)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self._lock, self._session() as conn:
            conn.execute(
                """
                INSERT INTO embedding_cache (content_hash, embedding_id, dim, vector)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(content_hash, embedding_id) DO UPDATE SET
                    dim = excluded.dim,
                    vector = excluded.vector
                """,
                (digest, self.embedder.embedding_id, int(array.shape[0]), array.tobytes()),
            )

    @contextmanager
    def _session(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def list_documents(self, *, role: str, include_all: bool = False) -> list[KnowledgeDocument]:
        """List the documents this role may see.

        Unclaimed rows (empty owner_role) are listed as legacy so an operator
        can adopt them with re-index; they are not searchable. ``include_all``
        is the owner review list: every role, so approval is not limited to
        files the owner uploaded.
        """
        columns = """
            id, filename, extension, byte_size, chunk_count, updated_at,
            embedding_id, embedding_dim, truncated, owner, owner_role,
            approval, indexed, skip_reason
        """
        with self._lock, self._session() as conn:
            if include_all:
                rows = conn.execute(
                    f"""
                    SELECT {columns}
                    FROM documents
                    ORDER BY updated_at DESC, filename ASC
                    """
                ).fetchall()
            else:
                rows = conn.execute(
                    f"""
                    SELECT {columns}
                    FROM documents
                    WHERE owner_role = ? OR owner_role = ? OR owner_role = ''
                    ORDER BY updated_at DESC, filename ASC
                    """,
                    (role, SHARED_ROLE),
                ).fetchall()
        return [_document(row) for row in rows]

    def add_document(
        self,
        filename: str,
        data: bytes,
        *,
        owner: str,
        owner_role: str,
        approval: str = APPROVAL_DRAFT,
    ) -> KnowledgeDocument:
        safe_name = _safe_filename(filename)
        if len(data) > MAX_BYTES:
            raise KnowledgeError("Files must be 2 MB or smaller.")
        if not data:
            raise KnowledgeError("That file is empty.")
        extension = _extension(safe_name)
        approval = _normalize_approval(approval)
        stored_only = extension in STORED_EXTENSIONS
        if stored_only:
            text = ""
        else:
            if not data.strip():
                raise KnowledgeError("That file is empty.")
            text = data.decode("utf-8-sig", errors="replace").strip()
            if not text:
                raise KnowledgeError("That file has no text to index.")
        content_hash = hashlib.sha256(data).hexdigest()
        with self._lock, self._session() as conn:
            existing = conn.execute(
                """
                SELECT id, filename FROM documents
                WHERE content_hash = ? AND embedding_id = ? AND owner_role = ?
                """,
                (content_hash, self.embedder.embedding_id, owner_role),
            ).fetchone()
        if existing is not None:
            raise KnowledgeError(
                f"That file is already in the knowledge base as {existing['filename']}."
            )
        document_id = uuid4().hex
        if stored_only:
            self._write_blob(document_id, data)
        try:
            return self._write_document(
                document_id=document_id,
                filename=safe_name,
                extension=extension,
                byte_size=len(data),
                content_hash=content_hash,
                body=text,
                updated_at=_now(),
                owner=owner,
                owner_role=owner_role,
                approval=approval,
                indexed=not stored_only,
                skip_reason=SKIP_REASONS.get(extension, ""),
                embed=not stored_only,
            )
        except Exception:
            if stored_only:
                self._remove_blob(document_id)
            raise

    def delete(self, document_id: str, *, username: str) -> None:
        with self._lock, self._session() as conn:
            row = conn.execute(
                "SELECT owner, owner_role FROM documents WHERE id = ?",
                (document_id,),
            ).fetchone()
            if row is None:
                raise KnowledgeError("That document is no longer in the knowledge base.")
            if row["owner_role"] and row["owner"] != username:
                raise KnowledgeError("You can only delete files that you uploaded.")
            conn.execute("DELETE FROM chunks WHERE document_id = ?", (document_id,))
            conn.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        self._remove_blob(document_id)

    def reindex(self, document_id: str, *, username: str, role: str) -> KnowledgeDocument:
        """Rebuild one document with the current embedder.

        A row with no owner_role was indexed before scoping existed; re-indexing
        adopts it for the caller instead of failing, which is the only way such
        a row becomes searchable again.
        """
        with self._lock, self._session() as conn:
            row = conn.execute(
                """
                SELECT id, filename, extension, byte_size, content_hash, body,
                       owner, owner_role, approval
                FROM documents WHERE id = ?
                """,
                (document_id,),
            ).fetchone()
        if row is None:
            raise KnowledgeError("That document is no longer in the knowledge base.")
        owner = row["owner"] or ""
        owner_role = row["owner_role"] or ""
        if owner_role:
            if owner != username:
                raise KnowledgeError("You can only re-index files that you uploaded.")
        else:
            owner, owner_role = username, role
        approval = row["approval"] if row["approval"] in APPROVALS else APPROVAL_APPROVED
        extension = row["extension"]
        stored_only = extension in STORED_EXTENSIONS
        body = row["body"]
        byte_size = int(row["byte_size"])
        content_hash = row["content_hash"]
        if stored_only:
            blob = self._blob_path(row["id"])
            if not blob.is_file():
                raise KnowledgeError("The stored file is missing, so it cannot be re-indexed.")
            data = blob.read_bytes()
            byte_size = len(data)
            content_hash = hashlib.sha256(data).hexdigest()
            body = ""
        return self._write_document(
            document_id=row["id"],
            filename=row["filename"],
            extension=extension,
            byte_size=byte_size,
            content_hash=content_hash,
            body=body,
            updated_at=_now(),
            owner=owner,
            owner_role=owner_role,
            approval=approval,
            indexed=not stored_only,
            skip_reason=SKIP_REASONS.get(extension, "") if stored_only else "",
            embed=not stored_only,
        )

    def set_approval(self, document_id: str, approval: str) -> KnowledgeDocument:
        """Set ``draft``, ``approved``, or ``rejected``. Does not index binaries.

        The page only offers this to the admin role. Approving a PDF, spreadsheet,
        or PNG leaves it out of retrieval.
        """
        approval = _normalize_approval(approval)
        with self._lock, self._session() as conn:
            found = conn.execute(
                "SELECT id FROM documents WHERE id = ?",
                (document_id,),
            ).fetchone()
            if found is None:
                raise KnowledgeError("That document is no longer in the knowledge base.")
            conn.execute(
                "UPDATE documents SET approval = ?, updated_at = ? WHERE id = ?",
                (approval, _now(), document_id),
            )
            row = conn.execute(
                """
                SELECT id, filename, extension, byte_size, chunk_count, updated_at,
                       embedding_id, embedding_dim, truncated, owner, owner_role,
                       approval, indexed, skip_reason
                FROM documents WHERE id = ?
                """,
                (document_id,),
            ).fetchone()
        return _document(row)

    def search(self, query: str, *, role: str, limit: int = 4) -> list[Snippet]:
        query = (query or "").strip()
        if not query:
            return []
        embedding_id = self.embedder.embedding_id
        try:
            query_matrix = self.embedder.embed([query])
        except KnowledgeEmbedError:
            return []
        if query_matrix.size == 0:
            return []
        query_vector = query_matrix[0]
        with self._lock, self._session() as conn:
            rows = conn.execute(
                """
                SELECT documents.filename, chunks.text, chunks.embedding
                FROM chunks
                JOIN documents ON documents.id = chunks.document_id
                WHERE documents.embedding_id = ?
                  AND documents.embedding_dim = ?
                  AND documents.owner_role != ''
                  AND documents.approval = 'approved'
                  AND documents.indexed = 1
                  AND documents.extension NOT IN ('pdf', 'xlsx', 'png')
                  AND (documents.owner_role = ? OR documents.owner_role = ?)
                """,
                (embedding_id, int(query_vector.shape[0]), role, SHARED_ROLE),
            ).fetchall()
        if not rows:
            return []
        matrix = np.vstack(
            [np.frombuffer(bytes(row["embedding"]), dtype=np.float32) for row in rows]
        )
        if matrix.shape[1] != query_vector.shape[0]:
            return []
        scores = matrix @ query_vector
        order = np.argsort(scores)[::-1]
        snippets: list[Snippet] = []
        for index in order:
            score = float(scores[index])
            if score < SCORE_MIN:
                break
            snippets.append(
                Snippet(
                    filename=rows[int(index)]["filename"],
                    text=rows[int(index)]["text"][:600],
                    score=score,
                )
            )
            if len(snippets) >= limit:
                break
        return snippets

    def prompt_notes(self, query: str, *, role: str, limit: int = 4) -> list[str]:
        return [
            f"[{snippet.filename}] {snippet.text}"
            for snippet in self.search(query, role=role, limit=limit)
        ]

    def _write_document(
        self,
        *,
        document_id: str,
        filename: str,
        extension: str,
        byte_size: int,
        content_hash: str,
        body: str,
        updated_at: str,
        owner: str,
        owner_role: str,
        approval: str = APPROVAL_DRAFT,
        indexed: bool = True,
        skip_reason: str = "",
        embed: bool = True,
    ) -> KnowledgeDocument:
        approval = _normalize_approval(approval)
        if embed:
            chunks, truncated = chunk_document(body, extension)
            if not chunks:
                raise KnowledgeError("That file has no text to index.")
            try:
                vectors = self.embedder.embed(chunks)
            except KnowledgeEmbedError as exc:
                raise KnowledgeError(str(exc)) from None
            if vectors.shape[0] != len(chunks):
                raise KnowledgeError("Embedding the file produced an unexpected result.")
            embedding_dim = int(vectors.shape[1])
        else:
            chunks = []
            truncated = False
            vectors = None
            embedding_dim = 0
        embedding_id = self.embedder.embedding_id
        with self._lock, self._session() as conn:
            conn.execute("DELETE FROM chunks WHERE document_id = ?", (document_id,))
            conn.execute(
                """
                INSERT INTO documents (
                    id, filename, extension, byte_size, chunk_count, updated_at,
                    content_hash, embedding_id, embedding_dim, truncated, body,
                    owner, owner_role, approval, indexed, skip_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    filename = excluded.filename,
                    extension = excluded.extension,
                    byte_size = excluded.byte_size,
                    chunk_count = excluded.chunk_count,
                    updated_at = excluded.updated_at,
                    content_hash = excluded.content_hash,
                    embedding_id = excluded.embedding_id,
                    embedding_dim = excluded.embedding_dim,
                    truncated = excluded.truncated,
                    body = excluded.body,
                    owner = excluded.owner,
                    owner_role = excluded.owner_role,
                    approval = excluded.approval,
                    indexed = excluded.indexed,
                    skip_reason = excluded.skip_reason
                """,
                (
                    document_id,
                    filename,
                    extension,
                    byte_size,
                    len(chunks),
                    updated_at,
                    content_hash,
                    embedding_id,
                    embedding_dim,
                    int(truncated),
                    body,
                    owner,
                    owner_role,
                    approval,
                    int(indexed),
                    skip_reason,
                ),
            )
            if vectors is not None:
                conn.executemany(
                    """
                    INSERT INTO chunks (document_id, ordinal, text, embedding)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (
                            document_id,
                            ordinal,
                            text,
                            vectors[ordinal].astype(np.float32).tobytes(),
                        )
                        for ordinal, text in enumerate(chunks)
                    ],
                )
        return KnowledgeDocument(
            id=document_id,
            filename=filename,
            extension=extension,
            byte_size=byte_size,
            chunk_count=len(chunks),
            updated_at=updated_at,
            embedding_id=embedding_id,
            embedding_dim=embedding_dim,
            truncated=truncated,
            owner=owner,
            owner_role=owner_role,
            approval=approval,
            indexed=indexed,
            skip_reason=skip_reason,
        )

    def _blob_path(self, document_id: str) -> Path:
        if not _DOC_ID.fullmatch(document_id):
            raise KnowledgeError("That document is no longer in the knowledge base.")
        root = (self.directory / "files").resolve()
        path = (root / document_id).resolve()
        if path.parent != root:
            raise KnowledgeError("Rejected a document path that leaves the knowledge directory.")
        return path

    def _write_blob(self, document_id: str, data: bytes) -> None:
        path = self._blob_path(document_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def _remove_blob(self, document_id: str) -> None:
        if not _DOC_ID.fullmatch(document_id):
            return
        path = self._blob_path(document_id)
        if path.is_file():
            path.unlink()


def _safe_filename(filename: str) -> str:
    """Basename only. A path is not a place to write."""
    if not filename or "\x00" in filename:
        raise KnowledgeError("The file needs a name.")
    safe = Path(filename.replace("\\", "/")).name
    if not safe or safe in {".", ".."} or "/" in safe or "\\" in safe or "\x00" in safe:
        raise KnowledgeError("The file needs a name.")
    return safe


def _normalize_approval(approval: str) -> str:
    if approval not in APPROVALS:
        raise KnowledgeError("Approval must be draft, approved, or rejected.")
    return approval


def _document(row: sqlite3.Row) -> KnowledgeDocument:
    owner = row["owner"] or ""
    names = set(row.keys())
    approval = row["approval"] if "approval" in names and row["approval"] else APPROVAL_APPROVED
    if approval not in APPROVALS:
        approval = APPROVAL_APPROVED
    indexed = bool(row["indexed"]) if "indexed" in names and row["indexed"] is not None else True
    skip_reason = row["skip_reason"] or "" if "skip_reason" in names else ""
    return KnowledgeDocument(
        id=row["id"],
        filename=row["filename"],
        extension=row["extension"],
        byte_size=row["byte_size"],
        chunk_count=row["chunk_count"],
        updated_at=row["updated_at"],
        embedding_id=row["embedding_id"],
        embedding_dim=row["embedding_dim"],
        truncated=bool(row["truncated"]),
        owner=owner,
        owner_role=row["owner_role"] or "",
        legacy=not (row["owner_role"] or ""),
        approval=approval,
        indexed=indexed,
        skip_reason=skip_reason,
    )
