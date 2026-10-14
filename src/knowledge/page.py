"""知識庫 dashboard. Uploads are indexed locally and never executed."""

from __future__ import annotations

import streamlit as st

from src.config import Settings
from src.knowledge.store import KnowledgeDocument, KnowledgeError, KnowledgeStore
from src.models import User


def render_knowledge_page(store: KnowledgeStore, settings: Settings, user: User) -> None:
    notice = st.session_state.pop("kb_notice", None)
    st.markdown('<p class="fn-kicker">Knowledge Base</p>', unsafe_allow_html=True)
    st.title("知識庫")
    st.caption(
        "Drop schema docs, DDL, a business glossary, or a synonym list. "
        "The routing map still chooses the table. Matching notes are added to the "
        "language-model prompt when it writes SQL. Files are scoped to your role, "
        "and only the uploader can delete or re-index a file."
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
    _consume_uploads(store, uploads or [], user)
    documents = store.list_documents(role=user.role)
    current_embedding = store.embedder.embedding_id
    _metrics(store, documents)
    legacy = [document for document in documents if document.legacy]
    if legacy:
        st.warning(
            f"{len(legacy)} file(s) were indexed before files were scoped to a role "
            "and are hidden from answers. Re-index one to attach it to your role."
        )
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
                if document.legacy:
                    st.caption("Unowned · re-index to attach it to your role.")
                else:
                    st.caption(f"Uploaded by {document.owner or 'unknown'} ({document.owner_role})")
                if document.truncated:
                    st.caption("Indexed the first 200 chunks.")
                if document.embedding_id != current_embedding:
                    st.caption("Re-index this file so it matches the current embedding provider.")
                left, right = st.columns(2)
                if left.button("Re-index", key=f"reindex-{document.id}", width="stretch"):
                    _reindex(store, document.id, user)
                if document.legacy or document.owner == user.username:
                    if right.button("Delete", key=f"delete-{document.id}", width="stretch"):
                        _delete(store, document.id, user)
                else:
                    right.caption("Only the uploader can delete.")


def _metrics(store: KnowledgeStore, documents: list[KnowledgeDocument]) -> None:
    total_chunks = sum(document.chunk_count for document in documents)
    first, second, third = st.columns(3)
    first.metric("Documents", len(documents))
    second.metric("Chunks", total_chunks)
    third.metric("Embeddings", store.embedder.label())


def _consume_uploads(store: KnowledgeStore, uploads: list, user: User) -> None:
    seen: list[str] = st.session_state.setdefault("kb_seen_ids", [])
    notices: list[str] = []
    for uploaded in uploads:
        file_id = getattr(uploaded, "file_id", None) or f"{uploaded.name}:{uploaded.size}"
        if file_id in seen:
            continue
        try:
            document = store.add_document(
                uploaded.name,
                uploaded.getvalue(),
                owner=user.username,
                owner_role=user.role,
            )
        except KnowledgeError as exc:
            st.error(f"{uploaded.name}: {exc}")
            continue
        seen.append(file_id)
        notices.append(f"Indexed {document.filename} · {document.chunk_count} chunks.")
    if notices:
        st.session_state.kb_seen_ids = seen
        for notice in notices:
            st.success(notice)


def _reindex(store: KnowledgeStore, document_id: str, user: User) -> None:
    try:
        document = store.reindex(document_id, username=user.username, role=user.role)
    except KnowledgeError as exc:
        st.error(str(exc))
        return
    st.session_state.kb_notice = f"Re-indexed {document.filename} · {document.chunk_count} chunks."
    st.rerun()


def _delete(store: KnowledgeStore, document_id: str, user: User) -> None:
    try:
        store.delete(document_id, username=user.username)
    except KnowledgeError as exc:
        st.error(str(exc))
        return
    st.rerun()
