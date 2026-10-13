"""Fieldnote chat UI."""

from __future__ import annotations

import logging
from uuid import uuid4

import pandas as pd
import streamlit as st

from src.audit import AuditLog
from src.auth import authenticate, demo_accounts
from src.config import ConfigError, Settings, load_settings, redact
from src.db.factory import build_adapter
from src.export import ExportMeta, result_filename, stamp_now, to_csv, to_html
from src.knowledge.page import render_knowledge_page
from src.knowledge.store import KnowledgeStore
from src.llm import LlmClient
from src.models import Answer, User
from src.pipeline import answer_question
from src.present import column_label, format_value, is_money, looks_like_time
from src.routing import Catalog, load_catalog

logger = logging.getLogger("fieldnote")

PREVIEW_ROWS = 100
SUGGESTIONS = (
    ("revenue", "What was total revenue by product over the last 90 days?"),
    ("revenue", "Show the daily revenue trend for the last 30 days"),
    ("revenue", "Which region had the highest revenue last month?"),
    ("revenue", "過去 90 日各產品收入"),
    ("dau", "Show daily active users by platform for the last 30 days"),
    ("dau", "Which country has the highest DAU over the last 90 days?"),
    ("dau", "最近 30 日各平台日活"),
)


def _css() -> None:
    st.markdown(
        """
        <style>
          .block-container { max-width: 1080px; padding-top: 1.4rem; }
          .fn-kicker {
            letter-spacing: 0.14em;
            text-transform: uppercase;
            font-size: 0.75rem;
            color: #0E6B56;
            font-weight: 650;
            margin-bottom: 0;
          }
          div[data-testid="stMetric"] {
            background: #ffffff;
            border: 1px solid #d7e4de;
            padding: 0.55rem 0.75rem;
            border-radius: 8px;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _init_state() -> None:
    st.session_state.setdefault("user", None)
    st.session_state.setdefault("messages", [])
    st.session_state.setdefault("last_result", None)


def _queue_suggestion(label: str) -> None:
    st.session_state.pending = label


def _session_user() -> User | None:
    raw = st.session_state.get("user")
    if not raw:
        return None
    return User(
        username=raw["username"],
        role=raw["role"],
        allowed_tables=tuple(raw["allowed_tables"]),
    )


def _suggestions_for(tables: tuple[str, ...]) -> list[str]:
    allowed = set(tables)
    return [label for table, label in SUGGESTIONS if table in allowed][:4]


def _render_login(settings: Settings) -> None:
    st.markdown('<p class="fn-kicker">Fieldnote</p>', unsafe_allow_html=True)
    st.title("Ask the warehouse")
    st.caption(
        "Revenue and daily active users, answered with read-only SQL. "
        "Your role decides which tables can be used."
    )
    left, right = st.columns([1, 1], gap="large")
    with left:
        with st.form("login"):
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Sign in", key="login_submit", width="stretch")
        if submitted:
            try:
                user = authenticate(username, password, settings.users_path)
            except ConfigError as exc:
                st.error(str(exc))
                return
            if user is None:
                st.error("That username and password did not match.")
                return
            st.session_state.user = {
                "username": user.username,
                "role": user.role,
                "allowed_tables": list(user.allowed_tables),
            }
            st.session_state.messages = []
            st.session_state.last_result = None
            st.rerun()
    with right:
        st.markdown("**Demo accounts**")
        st.caption("A local stand-in for SSO. Replace src/auth.py before using real data.")
        lines = ["| Username | Password | Role | Tables |", "| --- | --- | --- | --- |"]
        for row in demo_accounts(settings.users_path):
            lines.append(
                f"| {row['username']} | {row['password']} | {row['role']} | {row['tables']} |"
            )
        st.markdown("\n".join(lines))


def _source_caption(payload: dict) -> str:
    if payload.get("source") == "openrouter":
        return f"SQL from {payload.get('model') or 'the language model'}."
    return "SQL from the local planner. Add OPENROUTER_API_KEY to send questions to a language model."


def _downloads(payload: dict, *, prefix: str) -> None:
    columns = payload["columns"]
    rows = payload["rows"]
    stamp = payload["stamp"]
    tables = payload["tables"]
    meta = ExportMeta(
        question=payload["question"],
        tables=tuple(tables),
        sql=payload.get("sql"),
        assumptions=payload.get("assumptions"),
        generated_at=stamp,
        truncated=bool(payload.get("truncated")),
        username=payload["username"],
    )
    labels = {column: column_label(column) for column in columns}
    csv_name = result_filename(tables, "csv", stamp)
    html_name = result_filename(tables, "html", stamp)
    left, right = st.columns(2)
    with left:
        st.download_button(
            "Download CSV",
            data=to_csv(columns, rows),
            file_name=csv_name,
            mime="text/csv",
            key=f"{prefix}-csv-{payload['id']}",
            width="stretch",
        )
    with right:
        st.download_button(
            "Download HTML",
            data=to_html(columns, rows, meta, labels),
            file_name=html_name,
            mime="text/html",
            key=f"{prefix}-html-{payload['id']}",
            width="stretch",
        )


def _column_config(frame: pd.DataFrame) -> dict:
    config = {}
    for name in frame.columns:
        label = column_label(str(name))
        if is_money(str(name)):
            config[name] = st.column_config.NumberColumn(label, format="$%,.2f")
        elif pd.api.types.is_numeric_dtype(frame[name]):
            config[name] = st.column_config.NumberColumn(label, format="%,d")
        else:
            config[name] = st.column_config.TextColumn(label)
    return config


def _chart(frame: pd.DataFrame) -> None:
    if frame.empty or frame.shape[1] < 2:
        return
    text_cols = [name for name in frame.columns if not pd.api.types.is_numeric_dtype(frame[name])]
    number_cols = [name for name in frame.columns if pd.api.types.is_numeric_dtype(frame[name])]
    if len(text_cols) != 1 or not number_cols:
        return
    axis = text_cols[0]
    metric = number_cols[0]
    if looks_like_time(frame[axis].tolist()):
        st.line_chart(frame, x=axis, y=metric)
    elif len(frame) <= 24:
        st.bar_chart(frame, x=axis, y=metric)


def _render_result(payload: dict) -> None:
    summary = payload.get("summary") or payload.get("message") or ""
    if summary:
        st.markdown(summary)
    if payload.get("assumptions"):
        st.caption(payload["assumptions"])
    columns = payload.get("columns") or []
    rows = payload.get("rows") or []
    if rows and columns:
        if len(rows) == 1 and len(columns) <= 4:
            metrics = st.columns(len(columns))
            for slot, name in zip(metrics, columns):
                slot.metric(column_label(name), format_value(name, rows[0].get(name)))
        else:
            preview = rows[:PREVIEW_ROWS]
            frame = pd.DataFrame(preview, columns=columns)
            _chart(frame)
            st.dataframe(
                frame,
                column_config=_column_config(frame),
                hide_index=True,
                width="stretch",
            )
            if len(rows) > PREVIEW_ROWS or payload.get("truncated"):
                st.caption(
                    f"Showing {min(len(rows), PREVIEW_ROWS)} rows on screen. "
                    f"The download includes {len(rows)} fetched rows."
                )
    notes = payload.get("knowledge_snippets") or []
    if notes:
        with st.expander(f"Knowledge base · {len(notes)} notes"):
            for note in notes:
                st.text(note)
    if payload.get("sql"):
        with st.expander("SQL"):
            st.caption(_source_caption(payload))
            st.code(payload["sql"], language="sql")
    if columns:
        _downloads(payload, prefix="answer")
    if payload.get("audit_saved") is False:
        st.caption("The usage log could not be written.")


def _render_message(message: dict) -> None:
    with st.chat_message(message["role"]):
        if message["role"] == "user":
            st.markdown(message["text"])
            return
        payload = message["payload"]
        status = payload["status"]
        if status == "ok":
            _render_result(payload)
        elif status == "clarify":
            st.info(payload["message"])
        elif status == "denied":
            st.warning(payload["message"])
        else:
            st.error(payload["message"])
            if status == "blocked" and payload.get("sql"):
                with st.expander("Blocked SQL"):
                    st.code(payload["sql"], language="sql")


def _pack(question: str, answer: Answer, settings: Settings, username: str) -> dict:
    return {
        "id": uuid4().hex[:8],
        "status": answer.status,
        "message": answer.message,
        "summary": answer.summary,
        "sql": answer.sql,
        "columns": answer.columns,
        "rows": answer.rows,
        "tables": answer.tables,
        "assumptions": answer.assumptions,
        "source": answer.source,
        "truncated": answer.truncated,
        "audit_saved": answer.audit_saved,
        "question": question,
        "stamp": stamp_now(),
        "username": username,
        "model": settings.openrouter_model,
        "knowledge_snippets": answer.knowledge_snippets,
    }


def _run_turn(
    question: str,
    user: User,
    settings: Settings,
    adapter: object,
    catalog: Catalog,
    audit: AuditLog,
    llm: LlmClient,
    knowledge: KnowledgeStore,
) -> None:
    try:
        answer = answer_question(
            question,
            user,
            settings=settings,
            adapter=adapter,
            catalog=catalog,
            audit=audit,
            llm=llm,
            knowledge=knowledge,
        )
    except Exception as exc:
        logger.error("answer failed: %s", type(exc).__name__)
        answer = Answer(
            status="error",
            message="The question could not be answered. "
            + redact(str(exc), settings.openrouter_api_key, settings.db_password),
        )
    payload = _pack(question, answer, settings, user.username)
    st.session_state.messages.append({"id": uuid4().hex[:8], "role": "user", "text": question})
    st.session_state.messages.append({"id": payload["id"], "role": "assistant", "payload": payload})
    st.session_state.messages = st.session_state.messages[-40:]
    if answer.status == "ok":
        st.session_state.last_result = payload


def _sidebar(user: User, settings: Settings, adapter: object, audit: AuditLog) -> None:
    with st.sidebar:
        st.markdown('<p class="fn-kicker">Signed in</p>', unsafe_allow_html=True)
        st.subheader(user.username)
        st.caption(f"Role · {user.role}")
        st.markdown("**Tables**")
        for table in user.allowed_tables:
            try:
                count = adapter.row_count(table)  # type: ignore[attr-defined]
                st.markdown(f"`{table}` · {count:,} rows")
            except Exception:
                st.markdown(f"`{table}`")
        if settings.openrouter_api_key:
            st.caption(f"SQL writer · {settings.openrouter_model}")
        else:
            st.caption("SQL writer · local planner")
        last = st.session_state.get("last_result")
        if last:
            st.markdown("**Current result**")
            st.caption(last["question"])
            _downloads(last, prefix="sidebar")
        recent = audit.recent(user.username)
        if recent:
            st.markdown("**Your recent questions**")
            for event in recent:
                when = str(event["ts"]).replace("T", " ")[:16]
                question = str(event["question"])
                if len(question) > 80:
                    question = question[:77] + "..."
                st.caption(f"{when} · {event['status']} · {question}")
        if st.button("Sign out", key="sign_out", width="stretch"):
            _sign_out()


def _sign_out() -> None:
    st.session_state.user = None
    st.session_state.messages = []
    st.session_state.last_result = None
    st.session_state.pop("pending", None)
    st.session_state.pop("nav_page", None)
    st.session_state.pop("kb_seen_ids", None)
    st.session_state.pop("kb_notice", None)
    st.rerun()


def _page_choice() -> str:
    with st.sidebar:
        return st.radio(
            "Navigate",
            options=["ask", "knowledge"],
            format_func=lambda value: "Ask" if value == "ask" else "知識庫",
            key="nav_page",
        )


def _consume_pending(
    user: User,
    settings: Settings,
    adapter: object,
    catalog: Catalog,
    audit: AuditLog,
    llm: LlmClient,
    knowledge: KnowledgeStore,
) -> None:
    pending = st.session_state.pop("pending", None)
    prompt = st.chat_input("Ask about revenue or daily active users", key="chat")
    if prompt:
        pending = prompt
    if pending:
        with st.spinner("Checking access and running a read-only query..."):
            _run_turn(pending, user, settings, adapter, catalog, audit, llm, knowledge)


def main() -> None:
    st.set_page_config(page_title="Fieldnote", page_icon="📗", layout="wide")
    _css()
    _init_state()
    try:
        settings = load_settings()
        adapter = build_adapter(settings)
        catalog = load_catalog(settings.routing_path)
        audit = AuditLog(settings.audit_path)
        llm = LlmClient(
            settings.openrouter_api_key,
            settings.openrouter_base_url,
            settings.openrouter_model,
        )
        knowledge = KnowledgeStore(settings)
    except (ConfigError, OSError) as exc:
        st.title("Fieldnote")
        st.error(str(exc))
        return

    if _session_user() is None:
        _render_login(settings)
        return

    user = _session_user()
    assert user is not None
    if settings.db_backend != "sqlite":
        st.warning(
            f"DB_BACKEND={settings.db_backend} is a stub in this build. "
            "Set DB_BACKEND=sqlite to use the demo database."
        )
    page = _page_choice()
    if page == "knowledge":
        with st.sidebar:
            st.markdown('<p class="fn-kicker">Signed in</p>', unsafe_allow_html=True)
            st.subheader(user.username)
            st.caption(f"Role · {user.role}")
            if st.button("Sign out", key="sign_out", width="stretch"):
                _sign_out()
        render_knowledge_page(knowledge, settings)
        return

    st.markdown('<p class="fn-kicker">Warehouse Q&A</p>', unsafe_allow_html=True)
    st.title("Fieldnote")
    st.caption(
        "Ask in English or Cantonese. The routing map picks a table, "
        "then a read-only query runs on the columns your role can access. "
        "Open 知識庫 to add glossary notes for the language model."
    )
    _consume_pending(user, settings, adapter, catalog, audit, llm, knowledge)
    _sidebar(user, settings, adapter, audit)
    for message in st.session_state.messages:
        _render_message(message)
    if not st.session_state.messages:
        st.markdown("**Try a question**")
        for index, label in enumerate(_suggestions_for(user.allowed_tables)):
            st.button(
                label,
                key=f"suggest_{index}",
                on_click=_queue_suggestion,
                args=(label,),
                width="stretch",
            )


if __name__ == "__main__":
    main()
