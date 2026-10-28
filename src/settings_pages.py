"""Settings pages: mail configuration and the alert list.

Both pages go through :func:`src.capabilities.authorize` for the ``admin``
capability. Mail writes go through :class:`src.mail_settings.MailSettingsStore`
and the test send goes through :func:`src.mail_setup.verify`, so the page does
not keep a second copy of the provider presets or the failure hints. Pause,
resume and run-now go through :class:`src.alerts.AlertService` and the worker.
"""

from __future__ import annotations

from dataclasses import replace

import streamlit as st

from src.audit import AuditLog
from src.capabilities import ADMIN, authorize
from src.config import Settings, redact
from src.crypto import SecretKeyError
from src.mail_settings import (
    SOURCE_UNCONFIGURED,
    MailSettingsStore,
    ResolvedMail,
)
from src.mail_setup import PRESETS, verify
from src.models import User

# One sentence, also in the README. Demo sign-in is not authentication, and
# these pages must not be treated as though it were.
DEMO_AUTH_WARNING = (
    "Day 1 still signs in with a demo password. "
    "Settings is not a substitute for authentication on an instance exposed to the public."
)

_TLS_LABELS = {
    "starttls": "STARTTLS (port 587)",
    "ssl": "Implicit TLS (port 465)",
    "none": "No TLS",
}


def _sign_out() -> None:
    """The same session clear as the rest of the app, without a circular import."""
    from app import _sign_out as sign_out

    sign_out()


def _sidebar(user: User, sign_out_key: str) -> None:
    with st.sidebar:
        st.markdown('<p class="d1-kicker">Signed in</p>', unsafe_allow_html=True)
        st.subheader(user.username)
        st.caption(f"Role · {user.role}")
        if st.button("Sign out", key=sign_out_key, width="stretch"):
            _sign_out()
        from app import _source_link

        _source_link()


def _audit(
    audit: AuditLog,
    user: User,
    event_type: str,
    *,
    status: str,
    question: str = "",
    error: str | None = None,
) -> None:
    """One settings event. ``question`` and ``error`` are field names and outcomes, never values."""
    audit.record_event(
        username=user.username,
        role=user.role,
        status=status,
        event_type=event_type,
        capability=ADMIN,
        question=question,
        error=error,
    )


def _require_admin(user: User, audit: AuditLog) -> bool:
    """Refuse the page when the role has no admin grant, and audit that refusal."""
    decision = authorize(user, ADMIN)
    if decision.allowed:
        return True
    message = decision.message or (
        f"The {ADMIN} capability is not granted to the {user.role} role."
    )
    st.error(message)
    _audit(
        audit,
        user,
        "settings_refused",
        status="denied",
        question="settings page refused",
        error=message,
    )
    return False


def _provider_name(snapshot: ResolvedMail) -> str:
    stored = snapshot["smtp_provider"].value
    if stored in PRESETS:
        return stored
    host = snapshot["smtp_host"].value
    for name, preset in PRESETS.items():
        if preset.host and host == preset.host:
            return name
    return "custom"


def _tls_name(snapshot: ResolvedMail) -> str:
    if snapshot["smtp_ssl"].value == "true":
        return "ssl"
    if snapshot["smtp_starttls"].value == "true":
        return "starttls"
    if (
        snapshot["smtp_ssl"].source == SOURCE_UNCONFIGURED
        and snapshot["smtp_starttls"].source == SOURCE_UNCONFIGURED
    ):
        return "starttls"
    return "none"


def _apply_provider() -> None:
    """Fill host, port and TLS from the preset the person just picked."""
    preset = PRESETS[st.session_state["mail_provider"]]
    st.session_state["mail_host"] = preset.host
    st.session_state["mail_port"] = str(preset.port)
    if preset.ssl:
        st.session_state["mail_tls"] = "ssl"
    elif preset.starttls:
        st.session_state["mail_tls"] = "starttls"
    else:
        st.session_state["mail_tls"] = "none"


def _load_form(snapshot: ResolvedMail) -> None:
    """First visit shows the resolved values. The password box stays empty."""
    if st.session_state.get("mail_form_ready"):
        return
    st.session_state["mail_provider"] = _provider_name(snapshot)
    st.session_state["mail_host"] = snapshot["smtp_host"].value or ""
    st.session_state["mail_port"] = snapshot["smtp_port"].value or ""
    st.session_state["mail_tls"] = _tls_name(snapshot)
    st.session_state["mail_user"] = snapshot["smtp_user"].value or ""
    st.session_state["mail_from"] = snapshot["smtp_from"].value or ""
    destination = snapshot["smtp_user"].value or ""
    st.session_state["mail_test_to"] = destination if "@" in destination else ""
    st.session_state["mail_form_ready"] = True


def _clear_password_box() -> None:
    """Drop a password the person just typed so the box is empty on the next draw."""
    if st.session_state.pop("mail_password_reset", False):
        st.session_state["mail_password"] = ""


def _show_feedback() -> None:
    notice = st.session_state.pop("mail_notice", None)
    if notice:
        st.success(notice)
    feedback = st.session_state.pop("mail_feedback", None)
    if not feedback:
        return
    if feedback["ok"]:
        st.success(feedback["detail"])
    else:
        st.error(feedback["detail"])
    if feedback.get("hint"):
        st.info(feedback["hint"])


def _source_lines(snapshot: ResolvedMail) -> None:
    """Where each effective value lives. A secret contributes its hint only."""
    labels = (
        ("smtp_provider", "Provider"),
        ("smtp_host", "Host"),
        ("smtp_port", "Port"),
        ("smtp_user", "Username"),
        ("smtp_from", "From"),
        ("smtp_starttls", "STARTTLS"),
        ("smtp_ssl", "Implicit TLS"),
        ("smtp_password", "Password"),
    )
    for name, label in labels:
        field = snapshot[name]
        shown = field.display or "not set"
        st.caption(f"{label}: {shown} · source: {field.source}")


def _safe(text: str, *secrets: str | None) -> str:
    return redact(text or "", *secrets)


def _save_mail(
    *,
    user: User,
    settings: Settings,
    audit: AuditLog,
    store: MailSettingsStore,
    provider: str,
    host: str,
    port: str,
    tls: str,
    username: str,
    password: str,
    sender: str,
) -> None:
    port_text = (port or "").strip()
    try:
        port_number = int(port_text)
    except ValueError:
        st.error(f"Port must be a number, not {port_text!r}.")
        return
    if not 1 <= port_number <= 65535:
        st.error("Port must be a number between 1 and 65535.")
        return
    values = {
        "smtp_provider": provider,
        "smtp_host": (host or "").strip(),
        "smtp_port": str(port_number),
        "smtp_user": (username or "").strip(),
        "smtp_from": (sender or "").strip(),
        "smtp_starttls": "true" if tls == "starttls" else "false",
        "smtp_ssl": "true" if tls == "ssl" else "false",
    }
    # Empty means keep the stored password. The value is never written into the audit row.
    if password:
        values["smtp_password"] = password
    try:
        written = store.save(values, updated_by=user.username, key=settings.secret_key)
    except SecretKeyError as exc:
        message = _safe(str(exc), password)
        st.error(message)
        _audit(
            audit,
            user,
            "settings_refused",
            status="denied",
            question="refused to save mail settings",
            error=message,
        )
        return
    _audit(
        audit,
        user,
        "mail_settings_updated",
        status="ok",
        question="fields: " + ", ".join(sorted(written)),
    )
    st.session_state["mail_notice"] = "Saved " + ", ".join(sorted(written)) + "."
    st.session_state["mail_password_reset"] = True
    st.rerun()


def _send_test(
    *,
    user: User,
    settings: Settings,
    audit: AuditLog,
    snapshot: ResolvedMail,
    host: str,
    port: str,
    tls: str,
    username: str,
    password: str,
    sender: str,
    destination: str,
) -> None:
    port_text = (port or "").strip()
    try:
        port_number = int(port_text)
    except ValueError:
        st.error(f"Port must be a number, not {port_text!r}.")
        return
    stored = snapshot["smtp_password"]
    if not password and stored.error:
        st.error(stored.error)
        _audit(
            audit,
            user,
            "settings_refused",
            status="denied",
            question="refused to send a test message",
            error=stored.error,
        )
        return
    # A blank box keeps the stored secret. The typed one, if any, is used once and not rendered.
    secret = password or stored.value
    trial = replace(
        settings,
        smtp_host=(host or "").strip() or None,
        smtp_port=port_number,
        smtp_user=(username or "").strip() or None,
        smtp_password=secret,
        smtp_from=(sender or "").strip() or settings.smtp_from,
        smtp_starttls=tls == "starttls",
        smtp_ssl=tls == "ssl",
    )
    result = verify(trial, (destination or "").strip(), timeout=15)
    detail = _safe(result.detail, secret, password, stored.value)
    hint = _safe(result.hint, secret, password, stored.value)
    outcome = "ok" if result.ok else "failed"
    recipient = (destination or "").strip()
    _audit(
        audit,
        user,
        "mail_test_sent",
        status=outcome,
        question=f"to={recipient} outcome={outcome}",
        error=None if result.ok else detail,
    )
    st.session_state["mail_feedback"] = {"ok": result.ok, "detail": detail, "hint": hint}
    st.session_state["mail_password_reset"] = True
    st.rerun()


def _clear_mail(user: User, settings: Settings, audit: AuditLog, store: MailSettingsStore) -> None:
    store.clear()
    _audit(
        audit,
        user,
        "mail_settings_cleared",
        status="ok",
        question="cleared mail settings",
    )
    st.session_state["mail_form_ready"] = False
    st.session_state["mail_notice"] = "Cleared stored mail settings."
    st.session_state["mail_password_reset"] = True
    st.rerun()


def render_mail_page(user: User, settings: Settings, audit: AuditLog) -> None:
    """Mail provider, write-only password, test send, and where each value came from."""
    _sidebar(user, "sign_out_mail")
    st.markdown('<p class="d1-kicker">Settings</p>', unsafe_allow_html=True)
    st.title("Mail settings")
    st.warning(DEMO_AUTH_WARNING)
    if not _require_admin(user, audit):
        return

    store = MailSettingsStore(settings.settings_path)
    snapshot = store.resolve(settings)
    for error in snapshot.errors:
        st.error(error)
    if snapshot.errors and not st.session_state.get("mail_decrypt_audited"):
        _audit(
            audit,
            user,
            "settings_refused",
            status="denied",
            question="refused to read stored mail settings",
            error=snapshot.errors[0],
        )
        st.session_state["mail_decrypt_audited"] = True

    _clear_password_box()
    _load_form(snapshot)
    _show_feedback()

    st.selectbox(
        "Provider",
        options=list(PRESETS),
        key="mail_provider",
        on_change=_apply_provider,
    )
    st.caption(PRESETS[st.session_state["mail_provider"]].note)
    st.caption("Leave the password blank to keep the stored one. It is never shown again.")
    _source_lines(snapshot)

    with st.form("mail_settings_form"):
        host = st.text_input("Host", key="mail_host")
        port = st.text_input("Port", key="mail_port")
        tls = st.selectbox(
            "TLS",
            options=list(_TLS_LABELS),
            format_func=lambda value: _TLS_LABELS[value],
            key="mail_tls",
        )
        username = st.text_input("Username", key="mail_user")
        password = st.text_input(
            "App password",
            type="password",
            key="mail_password",
            help="Write-only. Leave blank to keep the stored password.",
        )
        sender = st.text_input("From", key="mail_from")
        destination = st.text_input("Send the test message to", key="mail_test_to")
        save_clicked = st.form_submit_button("Save mail settings", key="mail_save")
        test_clicked = st.form_submit_button("Send test message", key="mail_test")

    if save_clicked:
        _save_mail(
            user=user,
            settings=settings,
            audit=audit,
            store=store,
            provider=st.session_state["mail_provider"],
            host=host,
            port=port,
            tls=tls,
            username=username,
            password=password,
            sender=sender,
        )
    if test_clicked:
        _send_test(
            user=user,
            settings=settings,
            audit=audit,
            snapshot=snapshot,
            host=host,
            port=port,
            tls=tls,
            username=username,
            password=password,
            sender=sender,
            destination=destination,
        )
    if st.button("Clear stored mail settings", key="mail_clear"):
        _clear_mail(user, settings, audit, store)
