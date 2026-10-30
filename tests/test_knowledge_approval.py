"""Approval gate, legacy grandfather, and binary files that stay out of retrieval."""

from __future__ import annotations

import sqlite3

import pytest

from src.knowledge.embed import LOCAL_DIM, LOCAL_EMBEDDING_ID, embed_local
from src.knowledge.store import (
    MAX_BYTES,
    APPROVAL_APPROVED,
    KnowledgeError,
    KnowledgeStore,
)
from src.pipeline import answer_question

GLOSSARY = (
    "Booked revenue means the revenue_usd column. "
    "Northstar is the flagship product in the revenue table."
).encode()


class _Scripted:
    def __init__(self, reply: str):
        self.reply = reply
        self.configured = True
        self.seen: list = []

    def complete(self, messages):
        self.seen.append(messages)
        return self.reply


def test_new_uploads_are_draft_and_live_retrieval_is_approved_only(env):
    store = KnowledgeStore(env.settings)
    document = store.add_document(
        "glossary.md", GLOSSARY, owner="analyst", owner_role="analyst"
    )
    assert document.approval == "draft"
    assert store.search("revenue by product", role="analyst") == []
    assert store.prompt_notes("revenue by product", role="analyst") == []

    csv_doc = store.add_document(
        "terms.csv",
        b"term,means\nbooked,revenue_usd\n",
        owner="analyst",
        owner_role="analyst",
    )
    assert csv_doc.approval == "draft"
    assert store.search("booked revenue", role="analyst") == []

    llm = _Scripted(
        '{"sql": "SELECT product, SUM(revenue_usd) AS revenue_usd FROM revenue GROUP BY product", "assumptions": ""}'
    )
    answer = answer_question(
        "What was total revenue by product over the last 90 days?",
        env.analyst,
        settings=env.settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=llm,
        knowledge=store,
    )
    assert answer.status == "ok"
    assert answer.knowledge_snippets == []
    assert "glossary.md" not in llm.seen[0][0]["content"]

    store.set_approval(document.id, "approved")
    hits = store.search("revenue by product", role="analyst")
    assert hits and hits[0].filename == "glossary.md"

    store.set_approval(document.id, "rejected")
    assert store.search("revenue by product", role="analyst") == []
    assert store.prompt_notes("revenue by product", role="analyst") == []


def test_legacy_rows_without_an_approval_column_are_approved(env):
    path = env.settings.knowledge_path / "index.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = GLOSSARY.decode()
    vector = embed_local([text])[0]
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE documents (
            id TEXT PRIMARY KEY, filename TEXT NOT NULL, extension TEXT NOT NULL,
            byte_size INTEGER NOT NULL, chunk_count INTEGER NOT NULL,
            updated_at TEXT NOT NULL, content_hash TEXT NOT NULL,
            embedding_id TEXT NOT NULL, embedding_dim INTEGER NOT NULL,
            truncated INTEGER NOT NULL, body TEXT NOT NULL,
            owner TEXT NOT NULL DEFAULT '', owner_role TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, document_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL, text TEXT NOT NULL, embedding BLOB NOT NULL
        );
        """
    )
    conn.execute(
        """
        INSERT INTO documents (
            id, filename, extension, byte_size, chunk_count, updated_at, content_hash,
            embedding_id, embedding_dim, truncated, body, owner, owner_role
        ) VALUES ('abc', 'legacy.md', 'md', ?, 1, '2020-01-01T00:00:00Z', 'hash',
                  ?, ?, 0, ?, 'analyst', 'analyst')
        """,
        (len(GLOSSARY), LOCAL_EMBEDDING_ID, LOCAL_DIM, text),
    )
    conn.execute(
        "INSERT INTO chunks (document_id, ordinal, text, embedding) VALUES ('abc', 0, ?, ?)",
        (text, vector.astype("float32").tobytes()),
    )
    conn.commit()
    conn.close()

    store = KnowledgeStore(env.settings)
    listed = {item.filename: item for item in store.list_documents(role="analyst")}
    assert listed["legacy.md"].approval == APPROVAL_APPROVED
    assert listed["legacy.md"].indexed is True
    hits = store.search("revenue by product", role="analyst")
    assert hits and hits[0].filename == "legacy.md"


def test_pdf_xlsx_and_png_are_stored_and_stay_out_of_retrieval(env):
    store = KnowledgeStore(env.settings)
    pdf = store.add_document(
        "notes.pdf",
        b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n",
        owner="analyst",
        owner_role="analyst",
    )
    sheet = store.add_document(
        "book.xlsx",
        b"PK\x03\x04" + b"revenue_usd" * 5,
        owner="analyst",
        owner_role="analyst",
    )
    image = store.add_document(
        "logo.png",
        b"\x89PNG\r\n\x1a\n" + b"revenue",
        owner="analyst",
        owner_role="analyst",
    )
    assert pdf.approval == "draft" and pdf.indexed is False and pdf.chunk_count == 0
    assert "not extracted" in pdf.skip_reason
    assert sheet.indexed is False and "not extracted" in sheet.skip_reason
    assert image.skip_reason == "non-indexed"
    assert image.indexed is False

    blob = (store.directory / "files" / pdf.id).resolve()
    assert blob.is_file()
    assert blob.parent == (store.directory / "files").resolve()
    assert blob.read_bytes().startswith(b"%PDF")

    for document in (pdf, sheet, image):
        store.set_approval(document.id, "approved")
    assert store.search("revenue", role="analyst") == []

    vector = embed_local(["booked revenue means revenue_usd"])[0]
    with store._connect() as conn:
        conn.execute("UPDATE documents SET indexed = 1, embedding_dim = ? WHERE id = ?", (LOCAL_DIM, pdf.id))
        conn.execute(
            "INSERT INTO chunks (document_id, ordinal, text, embedding) VALUES (?, 0, ?, ?)",
            (pdf.id, "booked revenue means revenue_usd", vector.astype("float32").tobytes()),
        )
    assert store.search("booked revenue", role="analyst") == []


def test_path_traversal_and_the_size_cap_are_rejected(env):
    store = KnowledgeStore(env.settings)
    document = store.add_document(
        "../../secret.md",
        b"revenue_usd is booked revenue",
        owner="analyst",
        owner_role="analyst",
        approval="approved",
    )
    assert document.filename == "secret.md"
    windows = store.add_document(
        "..\\..\\secret2.md",
        b"revenue_usd is booked revenue too",
        owner="analyst",
        owner_role="analyst",
    )
    assert windows.filename == "secret2.md"
    assert not (store.directory / ".." / "secret.md").exists()
    with pytest.raises(KnowledgeError):
        store.add_document("bad\x00.md", b"revenue", owner="analyst", owner_role="analyst")
    with pytest.raises(KnowledgeError, match="2 MB"):
        store.add_document(
            "big.md",
            b"a" * (MAX_BYTES + 1),
            owner="analyst",
            owner_role="analyst",
        )
    outside = store.add_document(
        "/tmp/escaped.pdf",
        b"%PDF-1.4\n%%EOF\n",
        owner="analyst",
        owner_role="analyst",
    )
    stored = (store.directory / "files" / outside.id).resolve()
    assert stored.is_relative_to((store.directory / "files").resolve())
    assert outside.filename == "escaped.pdf"
