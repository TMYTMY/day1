"""知識庫 dashboard. Uploads are indexed locally and never executed.

PDF, XLSX, and PNG are stored on this page and do not enter retrieval.
New files start as draft. Only an approved text file is retrieved for an ask.
The admin role is the one that approves or rejects.
"""

from __future__ import annotations

import html
import sqlite3

import streamlit as st

from src.audit import AuditLog
from src.capabilities import ADMIN, authorize
from src.config import Settings
from src.knowledge.store import (
    STORED_EXTENSIONS,
    KnowledgeDocument,
    KnowledgeError,
    KnowledgeStore,
)
from src.models import User

# Same pill colors as the alert list. Approved uses the confirmed green.
# Rejected uses the danger red. The word on the pill stays the approval.
_APPROVAL_PILL = {
    "draft": "d1-state-draft",
    "approved": "d1-state-confirmed",
    "rejected": "d1-state-rejected",
}


def render_knowledge_page(
    store: KnowledgeStore,
    settings: Settings,
    user: User,
    audit: AuditLog | None = None,
) -> None:
    notice = st.session_state.pop("kb_notice", None)
    st.markdown('<p class="d1-kicker">Knowledge Base</p>', unsafe_allow_html=True)
    st.title("知識庫")
    st.caption(
        "Drop schema docs, DDL, a business glossary, or a synonym list. "
        "The routing map still chooses the table. Matching notes are added to the "
        "language-model prompt when it writes SQL, and only after this file is approved. "
        "Files are scoped to your role, and only the uploader can delete or re-index a file. "
        "PDF and Excel are stored but not indexed. PNG is stored as non-indexed."
    )
    if notice:
        st.success(notice)
    if settings.embedding_provider == "openrouter" and not settings.embedding_api_key:
        st.info(
            "Add EMBEDDING_API_KEY or OPENROUTER_API_KEY to embed with OpenRouter. "
            "Until then, this index uses local hash vectors."
        )
    uploads = st.file_uploader(
        "Drop files to store",
        type=["csv", "sql", "ddl", "md", "txt", "json", "pdf", "xlsx", "png"],
        accept_multiple_files=True,
        key="kb_upload",
        help="Text files can be approved into retrieval. PDF, Excel, and PNG are stored only. 2 MB max.",
    )
    _consume_uploads(store, uploads or [], user)
    reviewer = authorize(user, ADMIN).allowed
    documents = store.list_documents(role=user.role, include_all=reviewer)
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
    for document in documents:
        with st.container(border=True, key=f"kb_card_{document.id}"):
            _card(
                store,
                document,
                user,
                audit,
                reviewer=reviewer,
                current_embedding=current_embedding,
            )


def _card(
    store: KnowledgeStore,
    document: KnowledgeDocument,
    user: User,
    audit: AuditLog | None,
    *,
    reviewer: bool,
    current_embedding: str,
) -> None:
    """One file: a state pill, a detail well, then a single column of actions.

    Delete and Reject arm a second step, the way Clear mail does. The actions
    stay in one column so a narrow card does not turn into a row of four buttons.
    """
    when = document.updated_at.replace("T", " ").replace("Z", " UTC")
    pill = _APPROVAL_PILL.get(document.approval, "d1-state-draft")
    badges = (
        f'<span class="d1-state {pill}">{html.escape(document.approval)}</span>'
    )
    if document.extension == "png" or document.skip_reason == "non-indexed":
        badges += ' <span class="d1-state">non-indexed</span>'
    st.markdown(badges, unsafe_allow_html=True)
    st.markdown(f"**{html.escape(document.filename)}**")
    details = [
        ("Type", document.extension.upper()),
        ("Chunks", str(document.chunk_count)),
        ("Updated", when),
    ]
    if document.legacy:
        details.append(("Owner", "Unowned · re-index to attach it to your role."))
    else:
        details.append(
            ("Uploaded by", f"{document.owner or 'unknown'} ({document.owner_role})")
        )
    if document.extension in STORED_EXTENSIONS and document.skip_reason and document.skip_reason != "non-indexed":
        details.append(("Skip", document.skip_reason))
    if document.truncated:
        details.append(("Index", "Indexed the first 200 chunks."))
    if document.indexed and document.embedding_id != current_embedding:
        details.append(("Embeddings", "Re-index so it matches the current provider."))
    cells = "".join(
        f"<span>{html.escape(label)}</span><span>{html.escape(value)}</span>"
        for label, value in details
    )
    st.markdown(f'<div class="d1-alert-well">{cells}</div>', unsafe_allow_html=True)

    if st.button("Re-index", key=f"reindex-{document.id}", type="secondary"):
        _reindex(store, document.id, user)
    if reviewer:
        if st.button("Approve", key=f"approve-{document.id}", type="primary"):
            _set_approval(store, document.id, "approved", user, audit)
    else:
        st.caption("Only the owner can approve or reject.")
    if document.legacy or document.owner == user.username:
        _delete_control(store, document, user)
    else:
        st.caption("Only the uploader can delete.")
    if reviewer:
        _reject_control(store, document, user, audit)


def _confirming(kind: str, document_id: str) -> bool:
    return st.session_state.get("kb_confirm") == (kind, document_id)


def _arm(kind: str, document_id: str) -> None:
    st.session_state["kb_confirm"] = (kind, document_id)
    st.rerun()


def _keep(document_id: str) -> None:
    if st.session_state.get("kb_confirm", (None, None))[1] == document_id:
        st.session_state.pop("kb_confirm", None)
    st.rerun()


def _delete_control(store: KnowledgeStore, document: KnowledgeDocument, user: User) -> None:
    name = document.filename
    if _confirming("delete", document.id):
        st.markdown(
            f'<p class="d1-danger"><strong>Delete {html.escape(name)}?</strong></p>',
            unsafe_allow_html=True,
        )
        if st.button(f"Delete {name}", key=f"kb-delete-confirm-{document.id}", type="secondary"):
            _delete(store, document.id, user)
        if st.button(f"Keep {name}", key=f"kb-keep-delete-{document.id}", type="tertiary"):
            _keep(document.id)
        return
    if st.button("Delete", key=f"kb-delete-{document.id}", type="secondary"):
        _arm("delete", document.id)


def _reject_control(
    store: KnowledgeStore,
    document: KnowledgeDocument,
    user: User,
    audit: AuditLog | None,
) -> None:
    name = document.filename
    if _confirming("reject", document.id):
        st.markdown(
            f'<p class="d1-danger"><strong>Reject {html.escape(name)}?</strong></p>',
            unsafe_allow_html=True,
        )
        if st.button(f"Reject {name}", key=f"kb-reject-confirm-{document.id}", type="secondary"):
            _set_approval(store, document.id, "rejected", user, audit)
        if st.button(f"Keep {name}", key=f"kb-keep-reject-{document.id}", type="tertiary"):
            _keep(document.id)
        return
    if st.button("Reject", key=f"kb-reject-{document.id}", type="secondary"):
        _arm("reject", document.id)


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
        if document.indexed:
            notices.append(
                f"Stored {document.filename} as draft · {document.chunk_count} chunks."
            )
        else:
            notices.append(f"Stored {document.filename} as draft. {document.skip_reason}")
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


def _set_approval(
    store: KnowledgeStore,
    document_id: str,
    approval: str,
    user: User,
    audit: AuditLog | None,
) -> None:
    if not authorize(user, ADMIN).allowed:
        st.error(f"The {ADMIN} capability is not granted to the {user.role} role.")
        return
    try:
        document = store.set_approval(document_id, approval)
    except KnowledgeError as exc:
        st.error(str(exc))
        return
    if audit is not None:
        try:
            audit.record_event(
                username=user.username,
                role=user.role,
                status="ok",
                event_type="knowledge_approval",
                capability=ADMIN,
                question=f"{approval} {document.filename}",
            )
        except sqlite3.Error:
            st.caption("The approval was saved, and the usage log was not.")
    st.session_state.kb_notice = f"{document.filename} is {approval}."
    st.session_state.pop("kb_confirm", None)
    st.rerun()


def _delete(store: KnowledgeStore, document_id: str, user: User) -> None:
    try:
        store.delete(document_id, username=user.username)
    except KnowledgeError as exc:
        st.error(str(exc))
        return
    st.session_state.pop("kb_confirm", None)
    st.rerun()
