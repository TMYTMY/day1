"""Day 1 chat UI.

Session expiry is evaluated on user interaction only. Streamlit is request
driven, so an idle browser tab keeps its server-side session until the next event.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pandas as pd
import streamlit as st

from src.audit import AuditLog
from src.auth import authenticate
from src.config import ConfigError, Settings, load_settings
from src.connections import apply_enabled_connection
from src.connections_page import render_connections_page
from src.db.factory import build_adapter
from src.db.resolve import read_as_of
from src.db.sqlite import DEFAULT_STATEMENT_TIMEOUT_MS
from src.export import ExportMeta, result_filename, stamp_now, to_csv, to_html
from src.knowledge.page import render_knowledge_page
from src.knowledge.store import KnowledgeStore
from src.llm import LlmClient
from src.metrics import load_metrics
from src.models import Answer, User
from src.pipeline import answer_question
from src.present import column_label, format_value, is_money, looks_like_time
from src.routing import Catalog, load_catalog
from src.settings_pages import render_alerts_page, render_mail_page
from src.sources import (
    SourceSpec,
    load_sources,
    merge_catalog,
    source_status,
    sources_for_user,
)

logger = logging.getLogger("day1")

PREVIEW_ROWS = 100
IDLE_TIMEOUT_SECONDS = 1800
MAX_LOGIN_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300
SOURCE_URL = "https://github.com/TMYTMY/day1"
SUGGESTIONS = (
    ("revenue", "What was total revenue by product over the last 90 days?"),
    ("revenue", "Show the daily revenue trend for the last 30 days"),
    ("revenue", "Which region had the highest revenue last month?"),
    ("revenue", "過去 90 日各產品收入"),
    ("dau", "Show daily active users by platform for the last 30 days"),
    ("dau", "Which country has the highest DAU over the last 90 days?"),
    ("dau", "最近 30 日各平台日活"),
)


def _page_mark():
    """A teal mark for the browser tab. Not an emoji."""
    from PIL import Image, ImageDraw

    image = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((1, 1, 30, 30), radius=6, fill=(14, 107, 86, 255))
    draw.rectangle((8, 15, 24, 18), fill=(246, 244, 239, 255))
    return image


def _css() -> None:
    st.markdown(
        """
        <style>
          .stApp { --d1-danger: #9B2C2C; }
          .block-container { max-width: 1080px; padding-top: 1.4rem; }
          .d1-kicker {
            letter-spacing: 0.14em;
            text-transform: uppercase;
            font-size: 0.75rem;
            color: #0E6B56;
            font-weight: 650;
            margin-bottom: 0;
          }
          .d1-danger { color: var(--d1-danger); }
          .d1-sep {
            height: 0;
            border: 0;
            border-top: 1px solid rgba(28, 36, 33, 0.18);
            margin: 32px 0 20px;
          }
          .st-key-mail_clear button,
          .st-key-mail_clear_confirm button,
          .st-key-connection_disable button,
          [class*="st-key-kb-delete-"] button,
          [class*="st-key-kb-reject-"] button {
            background: transparent !important;
            color: var(--d1-danger) !important;
            border: 1px solid var(--d1-danger) !important;
          }
          .d1-state {
            display: inline-block;
            font-size: 0.75rem;
            line-height: 1.2;
            font-weight: 650;
            padding: 0.12rem 0.5rem;
            border-radius: 999px;
            border: 1px solid currentColor;
            background: transparent;
            white-space: nowrap;
          }
          .d1-identity-title { font-weight: 650; margin-top: 0.28rem; }
          .d1-identity-id { color: rgba(28, 36, 33, 0.62); font-size: 0.85rem; }
          [class*="st-key-alert_row_"] [data-testid="stVerticalBlock"] {
            align-items: flex-start;
          }
          .d1-state-confirmed { color: #0E6B56; }
          .d1-state-paused { color: #8A5A12; }
          .d1-state-rejected { color: var(--d1-danger); }
          .d1-state-superseded, .d1-state-draft { color: #5C6562; }
          .d1-alert-well {
            display: grid;
            grid-template-columns: 6.5rem minmax(0, 1fr);
            gap: 0.15rem 0.75rem;
            margin: 0.2rem 0 0.35rem;
            font-size: 0.92rem;
            color: #1C2421;
          }
          .d1-alert-well span:nth-child(odd) { color: rgba(28, 36, 33, 0.62); }
          [class*="st-key-alert_row_"] {
            border-bottom: 1px solid rgba(28, 36, 33, 0.12);
            padding-bottom: 0.45rem;
            margin-bottom: 0.35rem;
          }
          [class*="st-key-alert_row_"] [data-testid="stHorizontalBlock"] {
            flex-wrap: wrap;
            row-gap: 0.45rem;
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
    st.session_state.setdefault("last_seen", None)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _session_expired(last_seen: datetime | None) -> bool:
    """True when the signed-in session has been idle past the timeout.

    Streamlit only runs this on an event, so a tab left open keeps its
    server-side session until the next interaction.
    """
    if last_seen is None:
        return False
    return (_now() - last_seen).total_seconds() > IDLE_TIMEOUT_SECONDS


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
        capabilities=tuple(raw.get("capabilities") or ("query",)),
        email=raw.get("email") if isinstance(raw.get("email"), str) else None,
    )


def _suggestions_for(tables: tuple[str, ...]) -> list[str]:
    allowed = set(tables)
    return [label for table, label in SUGGESTIONS if table in allowed][:4]


def _source_link() -> None:
    """AGPL section 13: a network user can reach the source from the sidebar."""
    st.markdown(f"[Source]({SOURCE_URL})")


def _render_login(settings: Settings, audit: AuditLog) -> None:
    with st.sidebar:
        _source_link()
    st.markdown('<p class="d1-kicker">Day 1</p>', unsafe_allow_html=True)
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
            candidate = (username or "").strip()
            if audit.recent_failures(candidate, LOGIN_WINDOW_SECONDS) >= MAX_LOGIN_FAILURES:
                st.error("Too many failed attempts. Try again in a few minutes.")
                return
            try:
                user = authenticate(
                    candidate,
                    password,
                    settings.users_path,
                    settings_path=settings.settings_path,
                )
            except ConfigError as exc:
                st.error(str(exc))
                return
            audit.record_login(candidate, user is not None)
            if user is None:
                st.error("That username and password did not match.")
                return
            st.session_state.user = {
                "username": user.username,
                "role": user.role,
                "allowed_tables": list(user.allowed_tables),
                "capabilities": list(user.capabilities),
                "email": user.email,
            }
            st.session_state.messages = []
            st.session_state.last_result = None
            st.session_state.last_seen = _now()
            st.rerun()
    with right:
        st.markdown("**Demo accounts**")
        st.caption(
            "Demo accounts sign in with the demo password of the same name and are "
            "listed in README.md. The operator account has no password: it signs in with "
            "the secret `python -m src.operator_secret --init` prints on the host. This "
            "screen is a local stand-in for SSO — replace authenticate() in src/auth.py "
            "before pointing the app at real data."
        )


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
    if payload.get("grain_warning"):
        st.warning(payload["grain_warning"])
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
            if payload.get("grain_warning"):
                st.warning(payload["grain_warning"])
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
        "metric_id": answer.metric_id,
        "grain_warning": answer.grain_warning,
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
    sources: dict[str, SourceSpec],
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
            sources=sources,
            sources_db=settings.sources_db,
        )
    except Exception:
        logger.exception("answer failed")
        answer = Answer(
            status="error",
            message="The question could not be answered. The server log has the details.",
        )
    payload = _pack(question, answer, settings, user.username)
    st.session_state.messages.append({"id": uuid4().hex[:8], "role": "user", "text": question})
    st.session_state.messages.append({"id": payload["id"], "role": "assistant", "payload": payload})
    st.session_state.messages = st.session_state.messages[-40:]
    if answer.status == "ok":
        st.session_state.last_result = payload


def _sidebar(user: User, settings: Settings, adapter: object, audit: AuditLog) -> None:
    with st.sidebar:
        st.markdown('<p class="d1-kicker">Signed in</p>', unsafe_allow_html=True)
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
        _source_link()


def _sign_out() -> None:
    st.session_state.user = None
    st.session_state.messages = []
    st.session_state.last_result = None
    st.session_state.pop("pending", None)
    st.session_state.pop("nav_page", None)
    st.session_state.pop("kb_seen_ids", None)
    st.session_state.pop("kb_notice", None)
    st.session_state.pop("kb_confirm", None)
    st.session_state.pop("staged_seen_ids", None)
    st.rerun()


def _page_choice() -> str:
    labels = {
        "ask": "Ask",
        "knowledge": "知識庫",
        "connections": "資料庫連線",
        "sources": "Data sources",
        "mail": "Mail settings",
        "alerts": "Alerts",
    }
    with st.sidebar:
        return st.radio(
            "Navigate",
            options=["ask", "knowledge", "connections", "sources", "mail", "alerts"],
            format_func=lambda value: labels[value],
            key="nav_page",
        )


def _capability_line(sources: dict[str, SourceSpec]) -> str:
    line = "You can ask about revenue and daily active users, in English or Cantonese."
    titles = [spec.description or spec.table for spec in sources.values()]
    if titles:
        line += " Declared sources: " + ", ".join(titles) + "."
    return line


_STAGED_SUFFIXES = {".csv", ".tsv", ".xlsx", ".xlsm"}
_STAGED_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _user_staging_dir(user: User, settings: Settings) -> Path:
    safe = _STAGED_NAME.sub("_", user.username).strip("._") or "user"
    return settings.sources_staging_dir / safe


def _unused_staged_path(folder: Path, safe: str) -> Path:
    """A free path in ``folder``. An existing file is never replaced."""
    candidate = folder / safe
    if not candidate.exists():
        return candidate
    stem = Path(safe).stem
    suffix = Path(safe).suffix
    for offset in range(1, 1000):
        candidate = folder / f"{stem}-{offset}{suffix}"
        if not candidate.exists():
            return candidate
    raise ValueError("Could not stage the file without overwriting an existing one.")


def _stage_upload(uploaded, user: User, settings: Settings) -> Path:
    """Park an upload in that user's quarantine. This does not declare the source."""
    original = Path(str(getattr(uploaded, "name", "") or "")).name
    suffix = Path(original).suffix.lower()
    if suffix not in _STAGED_SUFFIXES:
        raise ValueError(
            f"Unsupported file type {suffix or '(none)'}. Accepted types: .csv, .tsv, .xlsx, .xlsm."
        )
    safe = _STAGED_NAME.sub("_", original).strip("._") or "upload"
    if not safe.lower().endswith(suffix):
        safe = f"{safe}{suffix}"
    folder = _user_staging_dir(user, settings)
    folder.mkdir(parents=True, exist_ok=True)
    destination = _unused_staged_path(folder, safe)
    destination.write_bytes(uploaded.getvalue())
    return destination


def _staged_files(user: User, settings: Settings) -> list[Path]:
    folder = _user_staging_dir(user, settings)
    if not folder.is_dir():
        return []
    return sorted(path for path in folder.iterdir() if path.is_file())


def _declare_command(path: Path) -> str:
    return (
        f"python -m src.sources_load {path.as_posix()} --id <source_id> "
        "--table <table> --owner-role <role> --description \"...\" --synonym <word>"
    )


def _bound_metric_ids(table: str, catalogue) -> str:
    return ", ".join(metric.id for metric in catalogue if metric.table == table)


def _source_rows(
    sources: dict[str, SourceSpec],
    catalogue,
    *,
    sources_db: Path,
    statement_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
) -> list[dict[str, object]]:
    rows = []
    for spec in sources.values():
        as_of = read_as_of(spec, sources_db, statement_timeout_ms=statement_timeout_ms)
        rows.append(
            {
                "source_id": spec.source_id,
                "table": spec.table,
                "owner_role": spec.owner_role,
                "row_count": spec.row_count,
                "loaded_at": spec.loaded_at,
                "sha256": spec.sha256[:8],
                "status": source_status(spec, catalogue),
                "metrics": _bound_metric_ids(spec.table, catalogue),
                "as_of": as_of or "",
            }
        )
    return rows


def _render_sources_page(user: User, settings: Settings, sources: dict[str, SourceSpec]) -> None:
    with st.sidebar:
        st.markdown('<p class="d1-kicker">Signed in</p>', unsafe_allow_html=True)
        st.subheader(user.username)
        st.caption(f"Role · {user.role}")
        if st.button("Sign out", key="sign_out_sources", width="stretch"):
            _sign_out()
        _source_link()
    st.markdown('<p class="d1-kicker">Data sources</p>', unsafe_allow_html=True)
    st.title("Data sources")
    visible = sources_for_user(sources, user)
    st.caption(_capability_line(visible))
    st.caption(
        "owner_role records who supplied the file. It does not grant access. "
        "A question is allowed only when the table is in your role's allowed tables."
    )
    st.warning("not declared = cannot be queried")
    uploads = st.file_uploader(
        "Stage a file for declaration",
        type=["csv", "tsv", "xlsx", "xlsm"],
        accept_multiple_files=True,
        key="source_upload",
        help="The file stays in quarantine until someone runs the declaration command.",
    )
    staged_now = _consume_staged_uploads(uploads or [], user, settings)
    try:
        catalogue = load_metrics(settings.metrics_path)
    except ConfigError as exc:
        st.error(str(exc))
        catalogue = []
    rows = _source_rows(
        visible,
        catalogue,
        sources_db=settings.sources_db,
        statement_timeout_ms=settings.sql_timeout_ms,
    )
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    elif sources:
        st.info("No declared sources are visible for your role.")
    else:
        st.info("No declared sources yet. A file is not queryable until its YAML manifest is written.")
    staged = _staged_files(user, settings)
    if staged or staged_now:
        st.markdown("**Quarantine**")
        st.caption("Each file below is still quarantined. Uploading it did not declare a source.")
        for path in staged:
            st.markdown(f"**{path.name}** · status `quarantined`")
            st.code(_declare_command(path), language="text")


def _consume_staged_uploads(uploads: list, user: User, settings: Settings) -> list[str]:
    seen: list[str] = st.session_state.setdefault("staged_seen_ids", [])
    fresh: list[str] = []
    for uploaded in uploads:
        file_id = getattr(uploaded, "file_id", None) or f"{uploaded.name}:{getattr(uploaded, 'size', 0)}"
        if file_id in seen:
            continue
        try:
            path = _stage_upload(uploaded, user, settings)
        except ValueError as exc:
            st.error(str(exc))
            continue
        seen.append(file_id)
        fresh.append(path.name)
        st.success(f"Staged {path.name}. not declared = cannot be queried")
        st.code(_declare_command(path), language="text")
    if fresh:
        st.session_state.staged_seen_ids = seen
    return fresh


def _consume_pending(
    user: User,
    settings: Settings,
    adapter: object,
    catalog: Catalog,
    audit: AuditLog,
    llm: LlmClient,
    knowledge: KnowledgeStore,
    sources: dict[str, SourceSpec],
) -> None:
    pending = st.session_state.pop("pending", None)
    prompt = st.chat_input("Ask about revenue or daily active users", key="chat")
    if prompt:
        pending = prompt
    if pending:
        with st.spinner("Checking access and running a read-only query..."):
            _run_turn(pending, user, settings, adapter, catalog, audit, llm, knowledge, sources)


def main() -> None:
    st.set_page_config(page_title="Day 1", page_icon=_page_mark(), layout="wide")
    _css()
    _init_state()
    try:
        settings = load_settings()
        # ``settings`` stays the environment. The adapter applies an enabled
        # UI connection on top of it and does not seed that file.
        effective = apply_enabled_connection(settings)
        adapter = build_adapter(settings)
        sources = load_sources(
            settings.sources_dir,
            routing_path=settings.routing_path,
            warehouse_path=effective.db_path,
        )
        catalog = merge_catalog(load_catalog(settings.routing_path), sources)
        audit = AuditLog(settings.audit_path)
        llm = LlmClient(
            settings.openrouter_api_key,
            settings.openrouter_base_url,
            settings.openrouter_model,
        )
        knowledge = KnowledgeStore(settings)
    except (ConfigError, OSError) as exc:
        st.title("Day 1")
        st.error(str(exc))
        return

    if _session_user() is None:
        _render_login(settings, audit)
        return

    user = _session_user()
    assert user is not None
    if _session_expired(st.session_state.get("last_seen")):
        _sign_out()
        return
    st.session_state.last_seen = _now()
    if effective.db_backend != "sqlite":
        st.warning(
            f"DB_BACKEND={effective.db_backend} is a stub in this build. "
            "Set DB_BACKEND=sqlite to use the demo database."
        )
    page = _page_choice()
    if page == "connections":
        render_connections_page(user, settings, audit)
        return
    if page == "knowledge":
        with st.sidebar:
            st.markdown('<p class="d1-kicker">Signed in</p>', unsafe_allow_html=True)
            st.subheader(user.username)
            st.caption(f"Role · {user.role}")
            if st.button("Sign out", key="sign_out", width="stretch"):
                _sign_out()
            _source_link()
        render_knowledge_page(knowledge, settings, user, audit)
        return
    if page == "sources":
        _render_sources_page(user, settings, sources)
        return
    if page == "mail":
        render_mail_page(user, settings, audit)
        return
    if page == "alerts":
        render_alerts_page(user, settings, audit, catalog)
        return

    st.markdown('<p class="d1-kicker">Warehouse Q&A</p>', unsafe_allow_html=True)
    st.title("Day 1")
    st.caption(
        "Ask in English or Cantonese. The routing map picks a table, "
        "then a read-only query runs on the columns your role can access. "
        "Open 知識庫 to add glossary notes for the language model."
    )
    st.caption(_capability_line(sources_for_user(sources, user)))
    _consume_pending(user, settings, adapter, catalog, audit, llm, knowledge, sources)
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
