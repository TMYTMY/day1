"""知識庫 dashboard. Uploads are indexed locally and never executed."""

from __future__ import annotations

import streamlit as st

from src.config import Settings
from src.knowledge.store import KnowledgeDocument, KnowledgeError, KnowledgeStore


def render_knowledge_page(store: KnowledgeStore, settings: Settings) -> None:
    notice = st.session_state.pop("kb_notice", None)
    st.markdown('<p class="fn-kicker">Knowledge Base</p>', unsafe_allow_html=True)
    st.title("知識庫")
    st.caption(
        "Drop schema docs, DDL, a business glossary, or a synonym list. "
        "The routing map still chooses the table. Matching notes are added to the "
        "language-model prompt when it writes SQL."
    )
    if notice:
        st.success(notice)
    if settings.embedding_provider == "openrouter" and not settings.embedding_api_key:
        st.info(
            "Add EMBEDDING_API_KEY or OPENROUTER_API_KEY to embed with OpenRouter. "
            "Until then, this index uses local hash vectors."
        )
    uploads = st.file_uploader(
        "Drop files to index",
        type=["csv", "sql", "ddl", "md", "txt", "json"],
        accept_multiple_files=True,
        key="kb_upload",
        help="CSV, SQL, DDL, Markdown, text, or JSON. Files stay on this machine.",
    )
    _consume_uploads(store, uploads or [])
    documents = store.list_documents()
    current_embedding = store.embedder.embedding_id
    _metrics(store, documents)
    if not documents:
        st.info("No documents yet. A glossary or DDL file will show up here after it is indexed.")
        return
    columns = st.columns(2)
    for index, document in enumerate(documents):
        with columns[index % 2]:
            with st.container(border=True):
                st.markdown(f"**{document.filename}**")
                when = document.updated_at.replace("T", " ").replace("Z", " UTC")
                st.caption(
                    f"{document.extension.upper()} · {document.chunk_count} chunks · Updated {when}"
                )
                if document.truncated:
                    st.caption("Indexed the first 200 chunks.")
                if document.embedding_id != current_embedding:
                    st.caption("Re-index this file so it matches the current embedding provider.")
                left, right = st.columns(2)
                if left.button("Re-index", key=f"reindex-{document.id}", width="stretch"):
                    _reindex(store, document.id)
                if right.button("Delete", key=f"delete-{document.id}", width="stretch"):
                    store.delete(document.id)
                    st.rerun()


def _metrics(store: KnowledgeStore, documents: list[KnowledgeDocument]) -> None:
    total_chunks = sum(document.chunk_count for document in documents)
    first, second, third = st.columns(3)
    first.metric("Documents", len(documents))
    second.metric("Chunks", total_chunks)
    third.metric("Embeddings", store.embedder.label())


def _consume_uploads(store: KnowledgeStore, uploads: list) -> None:
    seen: list[str] = st.session_state.setdefault("kb_seen_ids", [])
    notices: list[str] = []
    for uploaded in uploads:
        file_id = getattr(uploaded, "file_id", None) or f"{uploaded.name}:{uploaded.size}"
        if file_id in seen:
            continue
        try:
            document = store.add_document(uploaded.name, uploaded.getvalue())
        except KnowledgeError as exc:
            st.error(f"{uploaded.name}: {exc}")
            continue
        seen.append(file_id)
        notices.append(f"Indexed {document.filename} · {document.chunk_count} chunks.")
    if notices:
        st.session_state.kb_seen_ids = seen
        for notice in notices:
            st.success(notice)


def _reindex(store: KnowledgeStore, document_id: str) -> None:
    try:
        document = store.reindex(document_id)
    except KnowledgeError as exc:
        st.error(str(exc))
        return
    st.session_state.kb_notice = f"Re-indexed {document.filename} · {document.chunk_count} chunks."
    st.rerun()
