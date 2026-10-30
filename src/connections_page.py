"""Connections page: one SQLite file, tested before it is enabled.

Owner/admin only. There is no Postgres form and no password field. The
operator secret is asked again before Test, Enable, or Disable, the same way
mail settings refuse a write from an unlocked session. The secret is not the
database credential, and it is dropped from the session after the click.
"""

from __future__ import annotations

import sqlite3

import streamlit as st

from src.audit import AuditLog
from src.capabilities import ADMIN, authorize
from src.connections import (
    HARD_TIMEOUT_SECONDS,
    ConnectionPolicyError,
    ConnectionStore,
    check_sqlite_target,
)
from src.config import Settings
from src.models import User
from src.operator_secret import has_secret as has_operator_secret
from src.operator_secret import verify_secret as verify_operator_secret

_SECRET_KEY = "connection_operator_secret"


def _sign_out() -> None:
    from app import _sign_out as sign_out

    sign_out()


def _sidebar(user: User) -> None:
    with st.sidebar:
        st.markdown('<p class="d1-kicker">Signed in</p>', unsafe_allow_html=True)
        st.subheader(user.username)
        st.caption(f"Role · {user.role}")
        if st.button("Sign out", key="sign_out_connections", width="stretch"):
            _sign_out()
        from app import _source_link

        _source_link()


def _purge_secret() -> None:
    if not st.session_state.pop("connection_purge_secret", False):
        return
    st.session_state.pop(_SECRET_KEY, None)


def _rerun_clean() -> None:
    st.session_state["connection_purge_secret"] = True
    st.rerun()


def _record(
    audit: AuditLog,
    user: User,
    event_type: str,
    *,
    status: str,
    question: str,
    error: str | None = None,
) -> None:
    try:
        audit.record_event(
            username=user.username,
            role=user.role,
            status=status,
            event_type=event_type,
            capability=ADMIN,
            question=question,
            error=error,
        )
    except sqlite3.Error:
        st.caption("The action was not written to the usage log.")


def _operator_refusal(settings: Settings, entered: str) -> str | None:
    path = settings.settings_path
    if not has_operator_secret(path):
        return (
            "This instance has no operator secret, so the connection cannot be changed here. "
            "Run `python -m src.operator_secret --init` on the host, then enter the secret it prints."
        )
    if not (entered or ""):
        return (
            "Enter the operator secret to test or change the connection. "
            "It is not kept in this browser."
        )
    if not verify_operator_secret(path, entered):
        return "The operator secret did not match. Nothing was changed."
    return None


def _require_admin(user: User, audit: AuditLog) -> bool:
    decision = authorize(user, ADMIN)
    if decision.allowed:
        return True
    message = decision.message or (
        f"The {ADMIN} capability is not granted to the {user.role} role."
    )
    st.error(message)
    _record(
        audit,
        user,
        "settings_refused",
        status="denied",
        question="connections page refused",
        error=message,
    )
    return False


def render_connections_page(user: User, settings: Settings, audit: AuditLog) -> None:
    _purge_secret()
    _sidebar(user)
    st.markdown('<p class="d1-kicker">Connections</p>', unsafe_allow_html=True)
    st.title("Connections")
    st.caption(
        "SQLite file only. The environment database stays in use until you enable "
        "a connection here. Disable it to fall back. Postgres is not configured on this page."
    )
    if not _require_admin(user, audit):
        return

    notice = st.session_state.pop("connection_notice", None)
    if isinstance(notice, tuple) and len(notice) == 2:
        kind, text = notice
        if kind == "error":
            st.error(text)
        else:
            st.success(text)

    store = ConnectionStore(settings.settings_path)
    current = store.get()
    if current is not None and current.enabled:
        st.success(
            "This SQLite connection is enabled. It replaces the environment database "
            "until you disable it."
        )
        st.caption(f"Enabled file: {current.path}")
    else:
        st.info(
            "No UI connection is enabled. "
            f"Environment fallback: {settings.db_backend} at {settings.db_path}."
        )
        if current is not None:
            st.caption(f"Saved file, not enabled: {current.path}")
    if current is not None and current.last_test_at:
        if current.last_test_ok:
            st.caption(f"Last test succeeded at {current.last_test_at}.")
        else:
            st.caption(
                f"Last test failed at {current.last_test_at}: {current.last_error_class or 'invalid'}."
            )

    st.text_input(
        "SQLite file path",
        key="connection_path",
        help="A local database file. A postgres or http URL is refused.",
    )
    st.text_input(
        "Operator secret",
        type="password",
        key=_SECRET_KEY,
        help="Asked again for Test, Enable, and Disable. It is not a database password.",
    )
    test_col, enable_col, disable_col = st.columns(3)
    if test_col.button("Test connection", key="connection_test", width="stretch"):
        _on_test(user, settings, audit, store)
    if enable_col.button("Enable", key="connection_enable", width="stretch"):
        _on_enable(user, settings, audit, store)
    if disable_col.button("Disable", key="connection_disable", width="stretch"):
        _on_disable(user, settings, audit, store)


def _entered_secret() -> str:
    value = st.session_state.get(_SECRET_KEY) or ""
    return value if isinstance(value, str) else ""


def _notify(kind: str, text: str) -> None:
    st.session_state["connection_notice"] = (kind, text)


def _on_test(user: User, settings: Settings, audit: AuditLog, store: ConnectionStore) -> None:
    secret = _entered_secret()
    refusal = _operator_refusal(settings, secret)
    if refusal is not None:
        _notify("error", refusal)
        _record(
            audit,
            user,
            "settings_refused",
            status="denied",
            question="connection test refused",
            error="operator secret refused",
        )
        _rerun_clean()
        return
    raw = st.session_state.get("connection_path") or ""
    verdict = check_sqlite_target(str(raw), timeout_seconds=HARD_TIMEOUT_SECONDS)
    if verdict.ok and verdict.path is not None:
        store.record_success(verdict.path, actor=user.username)
        _record(
            audit,
            user,
            "connection_tested",
            status="ok",
            question="sqlite connection test",
        )
        _notify("success", verdict.message)
    else:
        store.record_failure(verdict.error_class, actor=user.username)
        _record(
            audit,
            user,
            "connection_tested",
            status="failed",
            question="sqlite connection test",
            error=verdict.error_class,
        )
        _notify("error", verdict.message)
    _rerun_clean()


def _on_enable(user: User, settings: Settings, audit: AuditLog, store: ConnectionStore) -> None:
    secret = _entered_secret()
    refusal = _operator_refusal(settings, secret)
    if refusal is not None:
        _notify("error", refusal)
        _record(
            audit,
            user,
            "settings_refused",
            status="denied",
            question="connection enable refused",
            error="operator secret refused",
        )
        _rerun_clean()
        return
    try:
        store.set_enabled(True, actor=user.username)
    except ConnectionPolicyError as exc:
        _notify("error", str(exc))
        _record(
            audit,
            user,
            "connection_enabled",
            status="failed",
            question="sqlite connection enable",
            error=exc.error_class,
        )
        _rerun_clean()
        return
    _record(
        audit,
        user,
        "connection_enabled",
        status="ok",
        question="sqlite connection enable",
    )
    _notify(
        "success",
        "SQLite connection enabled. The environment database is the fallback while this is off.",
    )
    _rerun_clean()


def _on_disable(user: User, settings: Settings, audit: AuditLog, store: ConnectionStore) -> None:
    secret = _entered_secret()
    refusal = _operator_refusal(settings, secret)
    if refusal is not None:
        _notify("error", refusal)
        _record(
            audit,
            user,
            "settings_refused",
            status="denied",
            question="connection disable refused",
            error="operator secret refused",
        )
        _rerun_clean()
        return
    try:
        store.set_enabled(False, actor=user.username)
    except ConnectionPolicyError as exc:
        _notify("error", str(exc))
        _record(
            audit,
            user,
            "connection_disabled",
            status="failed",
            question="sqlite connection disable",
            error=exc.error_class,
        )
        _rerun_clean()
        return
    _record(
        audit,
        user,
        "connection_disabled",
        status="ok",
        question="sqlite connection disable",
    )
    _notify("success", "Connection disabled. The environment database is in use.")
    _rerun_clean()
