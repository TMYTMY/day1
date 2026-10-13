"""On-disk vector index for uploaded knowledge-base documents.

Chunks and their vectors live in SQLite under data/knowledge/. Search is
cosine similarity in NumPy. The warehouse database is never opened here, and
uploaded SQL is stored as text only.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import numpy as np

from src.config import Settings
from src.knowledge.chunk import chunk_document
from src.knowledge.embed import Embedder, KnowledgeEmbedError

ALLOWED_EXTENSIONS = frozenset({"csv", "sql", "ddl", "md", "txt", "json"})
MAX_BYTES = 2_000_000
SCORE_MIN = 0.18
_LOCKS: dict[str, threading.Lock] = {}


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


@dataclass(frozen=True)
class Snippet:
    filename: str
    text: str
    score: float


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
        with self._lock:
            with self._connect() as conn:
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
                    """
                )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def list_documents(self) -> list[KnowledgeDocument]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, filename, extension, byte_size, chunk_count, updated_at,
                       embedding_id, embedding_dim, truncated
                FROM documents
                ORDER BY updated_at DESC, filename ASC
                """
            ).fetchall()
        return [_document(row) for row in rows]

    def add_document(self, filename: str, data: bytes) -> KnowledgeDocument:
        safe_name = Path(filename).name
        if not safe_name or safe_name in {".", ".."}:
            raise KnowledgeError("The file needs a name.")
        if len(data) > MAX_BYTES:
            raise KnowledgeError("Files must be 2 MB or smaller.")
        if not data.strip():
            raise KnowledgeError("That file is empty.")
        extension = _extension(safe_name)
        text = data.decode("utf-8-sig", errors="replace").strip()
        if not text:
            raise KnowledgeError("That file has no text to index.")
        return self._write_document(
            document_id=uuid4().hex,
            filename=safe_name,
            extension=extension,
            byte_size=len(data),
            content_hash=hashlib.sha256(data).hexdigest(),
            body=text,
            updated_at=_now(),
        )

    def delete(self, document_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM chunks WHERE document_id = ?", (document_id,))
            conn.execute("DELETE FROM documents WHERE id = ?", (document_id,))

    def reindex(self, document_id: str) -> KnowledgeDocument:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, filename, extension, byte_size, content_hash, body
                FROM documents WHERE id = ?
                """,
                (document_id,),
            ).fetchone()
        if row is None:
            raise KnowledgeError("That document is no longer in the knowledge base.")
        return self._write_document(
            document_id=row["id"],
            filename=row["filename"],
            extension=row["extension"],
            byte_size=row["byte_size"],
            content_hash=row["content_hash"],
            body=row["body"],
            updated_at=_now(),
        )

    def search(self, query: str, limit: int = 4) -> list[Snippet]:
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
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT documents.filename, chunks.text, chunks.embedding
                FROM chunks
                JOIN documents ON documents.id = chunks.document_id
                WHERE documents.embedding_id = ?
                  AND documents.embedding_dim = ?
                """,
                (embedding_id, int(query_vector.shape[0])),
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

    def prompt_notes(self, query: str, limit: int = 4) -> list[str]:
        return [f"[{snippet.filename}] {snippet.text}" for snippet in self.search(query, limit=limit)]

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
    ) -> KnowledgeDocument:
        chunks, truncated = chunk_document(body, extension)
        if not chunks:
            raise KnowledgeError("That file has no text to index.")
        try:
            vectors = self.embedder.embed(chunks)
        except KnowledgeEmbedError as exc:
            raise KnowledgeError(str(exc)) from None
        if vectors.shape[0] != len(chunks):
            raise KnowledgeError("Embedding the file produced an unexpected result.")
        embedding_id = self.embedder.embedding_id
        embedding_dim = int(vectors.shape[1])
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM chunks WHERE document_id = ?", (document_id,))
            conn.execute(
                """
                INSERT INTO documents (
                    id, filename, extension, byte_size, chunk_count, updated_at,
                    content_hash, embedding_id, embedding_dim, truncated, body
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    body = excluded.body
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
                ),
            )
            conn.executemany(
                """
                INSERT INTO chunks (document_id, ordinal, text, embedding)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (document_id, ordinal, text, vectors[ordinal].astype(np.float32).tobytes())
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
        )


def _document(row: sqlite3.Row) -> KnowledgeDocument:
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
    )
