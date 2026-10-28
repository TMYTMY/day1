"""Settings pages: mail configuration and the alert list.

Both pages go through :func:`src.capabilities.authorize` for the ``admin``
capability. Mail writes go through :class:`src.mail_settings.MailSettingsStore`
and the test send goes through :func:`src.mail_setup.verify`, so the page does
not keep a second copy of the provider presets or the failure hints. Pause,
resume and run-now go through :class:`src.alerts.AlertService` and the worker.

Three rules shape the mail page, and they are all about who is at the keyboard:

1. **The write surface is off by default.** Nothing here writes unless the
   operator started the app with ``DAY1_ALLOW_BROWSER_SETTINGS=1``. Repointing
   the sender is not a settings change: with a working mailbox and correct
   SPF/DKIM it is internal phishing infrastructure, and silencing a governance
   product's alerts is itself the attack.
2. **Every write re-enters the operator secret.** Signing in proves who opened
   the session; re-entering the secret proves the operator is still the person
   at the keyboard, so a session left unlocked at an unattended browser cannot
   repoint the sender. The secret is the one ``python -m
   src.operator_secret --init`` generated on the host.
3. **No page outcome is silent, and no password is kept.** Each submitted
   action writes exactly one audit row — its own event on success, a
   ``settings_refused`` row on a refusal or a failed write — and both password
   boxes are dropped from widget and session state before any handler runs.
4. **A test send is not a relay, and it is bounded.** The message leaves the
   company's authenticated mailbox, so its recipient must be an address this
   instance already knows and the number of tries per instance is limited in the
   instance database (see :mod:`src.send_safety`). The Alerts page carries the
   other half of the same story: one line per definition saying whether its
   deliveries are recorded, healthy, stale or failing — and saying so when there
   are no records at all.
"""

from __future__ import annotations

import html
import sqlite3
from dataclasses import replace

import streamlit as st

from src import send_safety
from src.alert_cli import condition, resolution, window
from src.alerts import (
    CONFIRMED,
    PAUSED,
    AlertDefinition,
    AlertService,
    may_operate,
)
from src.audit import AuditLog
from src.auth import user_named
from src.capabilities import ADMIN, QUERY, authorize
from src.config import Settings, redact
from src.crypto import SecretKeyError
from src.fires import FireStore
from src.mail_settings import (
    SOURCE_UNCONFIGURED,
    MailSettingsStore,
    ResolvedMail,
)
from src.mail_setup import PRESETS, verify
from src.metrics import Metric
from src.models import User
from src.operator_secret import has_secret as has_operator_secret
from src.operator_secret import verify_secret as verify_operator_secret
from src.routing import Catalog
from src.worker import Worker

# One sentence, also in the README. Demo sign-in is not authentication, and
# these pages must not be treated as though it were.
DEMO_AUTH_WARNING = (
    "Day 1 still signs in with a demo password. "
    "Settings is not a substitute for authentication on an instance exposed to the public."
)

# Said plainly, on the page, whenever the write surface is closed. An operator
# who wonders why the form is missing should not have to read the source.
BROWSER_SETTINGS_OFF = (
    "Browser settings are off on this instance, so this page is read-only. "
    "Configure mail from .env, or turn the form on by setting "
    "DAY1_ALLOW_BROWSER_SETTINGS=1 for the app (in .env or the service unit) and "
    "restarting it. Turning it on lets anybody who can reach this page repoint the "
    "sender, so it stays off until an operator decides otherwise."
)

# The audit event for a run started from this page. The worker writes its own
# outcome row as `worker`; this row says who pressed the button.
EVENT_RUN_NOW = "alert_run_now"

_STATUS_FOR_OUTCOME = {
    "refused": "denied",
    "failed": "failed",
    "suppressed": "suppressed",
}

_TLS_LABELS = {
    "starttls": "STARTTLS (port 587)",
    "ssl": "Implicit TLS (port 465)",
    "none": "No TLS",
}

# The form's non-secret boxes. They are remembered across a submit so a form
# that clears itself does not also clear what the person typed.
_FORM_KEYS = (
    "mail_provider",
    "mail_host",
    "mail_port",
    "mail_tls",
    "mail_user",
    "mail_from",
    "mail_test_to",
)

# Password boxes. Nothing may survive the run that read them.
_SECRET_KEYS = ("mail_password", "operator_secret", "mail_clear_secret")


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


def _record(
    audit: AuditLog,
    user: User,
    event_type: str,
    *,
    status: str,
    question: str = "",
    error: str | None = None,
) -> bool:
    """Write this action's one audit row, and never raise out of a page.

    ``question`` and ``error`` are field names and outcomes, never values. The
    return value is False when the usage log itself could not be written; the
    caller says so instead of showing a traceback, because a page that dies
    mid-write is how an unaudited change happens.
    """
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
        return True
    except sqlite3.Error:
        return False


def _require_admin(user: User, audit: AuditLog) -> bool:
    """Refuse the page when the role has no admin grant, and audit that refusal."""
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
    """Fill host, port and TLS from the preset the person just picked.

    Both the boxes and ``mail_pending`` are updated: the boxes so the person
    sees the preset now, and ``mail_pending`` so the values come back as the
    widgets' defaults after the form clears itself on the next submit.
    """
    name = st.session_state["mail_provider"]
    preset = PRESETS[name]
    if preset.ssl:
        tls = "ssl"
    elif preset.starttls:
        tls = "starttls"
    else:
        tls = "none"
    # A callback runs before this run's widgets exist, so the form's own keys
    # may be written here: that is how a preset replaces what is in the boxes.
    st.session_state["mail_host"] = preset.host
    st.session_state["mail_port"] = str(preset.port)
    st.session_state["mail_tls"] = tls
    remembered = dict(st.session_state.get("mail_pending") or {})
    remembered.update(
        {
            "mail_provider": name,
            "mail_host": preset.host,
            "mail_port": str(preset.port),
            "mail_tls": tls,
        }
    )
    st.session_state["mail_pending"] = remembered


def _form_values(snapshot: ResolvedMail) -> dict[str, str]:
    """The resolved values a first visit shows. The password box stays empty."""
    destination = snapshot["smtp_user"].value or ""
    return {
        "mail_provider": _provider_name(snapshot),
        "mail_host": snapshot["smtp_host"].value or "",
        "mail_port": snapshot["smtp_port"].value or "",
        "mail_tls": _tls_name(snapshot),
        "mail_user": snapshot["smtp_user"].value or "",
        "mail_from": snapshot["smtp_from"].value or "",
        "mail_test_to": destination if "@" in destination else "",
    }


def _form_defaults(snapshot: ResolvedMail) -> dict[str, str]:
    """What each non-secret box falls back to when its own state is empty.

    The form clears itself on every submit (``clear_on_submit``), which is what
    stops a password outliving the run that read it — and which also empties
    the honest boxes. The last submitted values are therefore kept in
    ``mail_pending`` and handed back as each widget's default; a widget that
    still holds what the person typed ignores its default, so an edit is never
    overwritten. A password is never among these values.
    """
    defaults = dict(st.session_state.get("mail_pending") or {})
    if not st.session_state.get("mail_form_ready"):
        st.session_state["mail_form_ready"] = True
        for key, value in _form_values(snapshot).items():
            defaults.setdefault(key, value)
    return defaults


def _remember_form(values: dict[str, str]) -> None:
    """Keep the non-secret boxes across the rerun a submit triggers."""
    remembered = dict(st.session_state.get("mail_pending") or {})
    remembered.update({key: values[key] for key in _FORM_KEYS if key in values})
    st.session_state["mail_pending"] = remembered


def _tls_index(value: str | None) -> int:
    """The index of a TLS mode in the selectbox, defaulting to STARTTLS."""
    options = list(_TLS_LABELS)
    return options.index(value) if value in options else options.index("starttls")


def _purge_secrets() -> None:
    """Drop what was typed into a password box, on the run after it was read.

    Popping a widget key in the same run that created the widget would leave
    the element tree holding a widget with no state, so the keys are dropped at
    the start of the next run instead - before those widgets exist again. That
    is one run later, and no code path reads them in between: the values a
    handler used were copied out of the widgets before the rerun.
    """
    if not st.session_state.pop("mail_purge_secrets", False):
        return
    for key in _SECRET_KEYS:
        st.session_state.pop(key, None)


def _rerun_clean() -> None:
    """Rerun, and let the next run drop both password boxes."""
    st.session_state["mail_purge_secrets"] = True
    st.rerun()


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


def _operator_refusal(settings: Settings, entered: str) -> str | None:
    """Why this write may not proceed, or None when the secret matched.

    Nothing is written before this answers. A refused secret writes one
    ``settings_refused`` row and touches neither the store nor the audit
    fields, so the page cannot half-do a change it then declines to log.
    """
    path = settings.settings_path
    if not has_operator_secret(path):
        return (
            "This instance has no operator secret, so mail settings cannot be changed here. "
            "Run `python -m src.operator_secret --init` on the host, then enter the secret it prints."
        )
    if not (entered or ""):
        return (
            "Enter the operator secret to change mail settings. It is not kept in this browser: "
            "the secret printed by `python -m src.operator_secret --init` must be typed again."
        )
    if not verify_operator_secret(path, entered):
        return "The operator secret did not match. Nothing was changed."
    return None


def _port(port: str) -> tuple[int | None, str]:
    """The port as a number, or the one sentence that says what is wrong."""
    text = (port or "").strip()
    try:
        number = int(text)
    except ValueError:
        return None, f"The port must be a whole number, not {text!r}."
    if not 1 <= number <= 65535:
        return None, "The port must be a number between 1 and 65535."
    return number, ""


def _browser_writes_allowed(settings: Settings) -> bool:
    """Whether this instance lets a browser change mail settings at all.

    The page checks this to decide whether to draw the form, and each write
    handler checks it again: a page that decided once, early, is not a gate a
    future caller inherits.
    """
    return bool(settings.allow_browser_settings)


def _refuse(
    user: User,
    audit: AuditLog,
    *,
    question: str,
    message: str,
    status: str = "denied",
    hint: str | None = None,
) -> None:
    """Refuse one submitted action: exactly one audit row, then the page says why."""
    if not _record(
        audit,
        user,
        "settings_refused",
        status=status,
        question=question,
        error=message,
    ):
        message = f"{message} The usage log could not be written."
    st.session_state["mail_feedback"] = {"ok": False, "detail": message, "hint": hint}
    _rerun_clean()


def _save_mail(
    *,
    user: User,
    settings: Settings,
    audit: AuditLog,
    store: MailSettingsStore,
    values: dict[str, str],
    port_number: int,
) -> None:
    """Write the settings, then record the outcome as exactly one event.

    The order is: every check that can refuse (flag, secret, port) with no side
    effect, then the one state change inside a guard, then one audit row
    describing what actually happened. The store is allowed to raise — a locked
    database is a normal outcome — and the raise is turned into that row rather
    than into a traceback with a changed database behind it.
    """
    if not _browser_writes_allowed(settings):
        _refuse(
            user,
            audit,
            question="refused to save mail settings",
            message=BROWSER_SETTINGS_OFF,
        )
        return
    password = values.pop("smtp_password", "")
    body = {
        "smtp_provider": values["smtp_provider"],
        "smtp_host": values["smtp_host"].strip(),
        "smtp_port": str(port_number),
        "smtp_user": values["smtp_user"].strip(),
        "smtp_from": values["smtp_from"].strip(),
        "smtp_starttls": "true" if values["smtp_tls"] == "starttls" else "false",
        "smtp_ssl": "true" if values["smtp_tls"] == "ssl" else "false",
    }
    # Empty means keep the stored password. The value never reaches an audit row.
    if password:
        body["smtp_password"] = password
    try:
        written = store.save(body, updated_by=user.username, key=settings.secret_key)
    except (SecretKeyError, sqlite3.Error, OSError, ValueError) as exc:
        _refuse(
            user,
            audit,
            question="refused to save mail settings",
            message=_safe(str(exc), password),
            status="failed",
        )
        return
    notice = "Saved " + ", ".join(sorted(written)) + "."
    if not _record(
        audit,
        user,
        "mail_settings_updated",
        status="ok",
        question="fields: " + ", ".join(sorted(written)),
    ):
        notice = f"{notice} The usage log could not be written."
    st.session_state["mail_notice"] = notice
    _rerun_clean()


def _send_test(
    *,
    user: User,
    settings: Settings,
    audit: AuditLog,
    snapshot: ResolvedMail,
    host: str,
    port_number: int,
    tls: str,
    username: str,
    password: str,
    sender: str,
    destination: str,
) -> None:
    """Send one test message and record its outcome, whatever the transport does.

    A test message is sent from the company's authenticated mailbox, so it is
    restricted to recipients this instance already knows and limited per
    instance. Both checks happen here rather than in the page's submit handler,
    because a handler is a caller: the rule belongs beside the send, so a second
    caller of this function cannot skip it.
    """
    if not _browser_writes_allowed(settings):
        _refuse(
            user,
            audit,
            question="refused to send a test message",
            message=BROWSER_SETTINGS_OFF,
        )
        return
    recipient = (destination or "").strip()
    refusal = send_safety.recipient_refusal(recipient, settings, operator=user)
    if refusal is not None:
        _refuse(
            user,
            audit,
            question="refused to send a test message",
            message=refusal.message,
        )
        return
    stored = snapshot["smtp_password"]
    if not password and stored.error:
        _refuse(
            user,
            audit,
            question="refused to send a test message",
            message=stored.error,
        )
        return
    limiter = send_safety.MailTestLimiter(settings.settings_path)
    throttled = limiter.refusal()
    if throttled is not None:
        _refuse(
            user,
            audit,
            question="refused to send a test message",
            message=throttled.message,
        )
        return
    try:
        # Counted before the transport is opened: the thing being limited is how
        # often this instance presents a credential to a provider, and a send
        # that cannot be counted is one the limit cannot bound.
        limiter.record(recipient=recipient)
    except sqlite3.Error as exc:
        _refuse(
            user,
            audit,
            question="refused to send a test message",
            message=(
                "The test-send limit could not be recorded, so nothing was sent: "
                f"{exc}"
            ),
            status="failed",
        )
        return
    # A blank box keeps the stored secret. The typed one is used once, never rendered.
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
    try:
        result = verify(trial, recipient, timeout=15)
        ok = result.ok
        detail = _safe(result.detail, secret, password, stored.value)
        hint = _safe(result.hint, secret, password, stored.value)
    except Exception as exc:  # a transport that raises is this send's failure
        ok = False
        detail = _safe(f"The test message could not be sent: {exc}", secret, password, stored.value)
        hint = None
    outcome = "ok" if ok else "failed"
    if not _record(
        audit,
        user,
        "mail_test_sent",
        status=outcome,
        question=f"to={recipient} outcome={outcome}",
        error=None if ok else detail,
    ):
        detail = f"{detail} The usage log could not be written."
    st.session_state["mail_feedback"] = {"ok": ok, "detail": detail, "hint": hint}
    _rerun_clean()


def _clear_mail(
    user: User,
    settings: Settings,
    audit: AuditLog,
    store: MailSettingsStore,
) -> None:
    """Remove every stored mail setting, audited once."""
    if not _browser_writes_allowed(settings):
        _refuse(
            user,
            audit,
            question="refused to clear mail settings",
            message=BROWSER_SETTINGS_OFF,
        )
        return
    try:
        store.clear()
    except (sqlite3.Error, OSError) as exc:
        _refuse(
            user,
            audit,
            question="refused to clear mail settings",
            message=f"The stored mail settings could not be removed: {exc}",
            status="failed",
        )
        return
    notice = "Cleared stored mail settings."
    if not _record(
        audit,
        user,
        "mail_settings_cleared",
        status="ok",
        question="cleared mail settings",
    ):
        notice = f"{notice} The usage log could not be written."
    st.session_state["mail_clear_armed"] = False
    st.session_state["mail_form_ready"] = False
    st.session_state.pop("mail_pending", None)
    st.session_state["mail_notice"] = notice
    _rerun_clean()


def _report_decrypt_refusal(user: User, audit: AuditLog, snapshot: ResolvedMail) -> None:
    """Audit a stored secret the key cannot open, once per distinct error.

    The old flag was a boolean set for the session, so a second, different
    decrypt failure after the first one was never recorded. Keying the
    deduplication on the message means it resets when the error changes or
    goes away.
    """
    if not snapshot.errors:
        st.session_state.pop("mail_decrypt_error", None)
        return
    error = snapshot.errors[0]
    if st.session_state.get("mail_decrypt_error") == error:
        return
    _record(
        audit,
        user,
        "settings_refused",
        status="denied",
        question="refused to read stored mail settings",
        error=error,
    )
    st.session_state["mail_decrypt_error"] = error


def render_mail_page(user: User, settings: Settings, audit: AuditLog) -> None:
    """Mail provider, write-only password, test send, and where each value came from."""
    # Before any widget on this page exists: a password typed into the
    # previous run is gone by the time its box is drawn again.
    _purge_secrets()
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
    _report_decrypt_refusal(user, audit, snapshot)

    defaults = _form_defaults(snapshot)
    _show_feedback()

    if not _browser_writes_allowed(settings):
        st.info(BROWSER_SETTINGS_OFF)
        _source_lines(snapshot)
        return

    if "mail_provider" not in st.session_state:
        # Outside the form, so this widget's own state persists; it only needs
        # a starting value on the first visit.
        st.session_state["mail_provider"] = defaults.get("mail_provider") or _provider_name(
            snapshot
        )
    st.selectbox(
        "Provider",
        options=list(PRESETS),
        key="mail_provider",
        on_change=_apply_provider,
    )
    st.caption(PRESETS[st.session_state["mail_provider"]].note)
    st.caption("Leave the password blank to keep the stored one. It is never shown again.")
    st.caption(
        send_safety.RECIPIENT_RULE
        + " Test messages are limited to "
        f"{send_safety.TEST_SEND_LIMIT} per instance per "
        f"{int(send_safety.TEST_SEND_WINDOW_SECONDS // 60)} minutes."
    )
    _source_lines(snapshot)

    with st.form("mail_settings_form", clear_on_submit=True):
        host = st.text_input("Host", value=defaults.get("mail_host", ""), key="mail_host")
        port = st.text_input("Port", value=defaults.get("mail_port", ""), key="mail_port")
        tls = st.selectbox(
            "TLS",
            options=list(_TLS_LABELS),
            index=_tls_index(defaults.get("mail_tls")),
            format_func=lambda value: _TLS_LABELS[value],
            key="mail_tls",
        )
        username = st.text_input(
            "Username", value=defaults.get("mail_user", ""), key="mail_user"
        )
        password = st.text_input(
            "App password",
            type="password",
            value="",
            key="mail_password",
            autocomplete="new-password",
            help="Write-only. Leave blank to keep the stored password.",
        )
        sender = st.text_input("From", value=defaults.get("mail_from", ""), key="mail_from")
        destination = st.text_input(
            "Send the test message to",
            value=defaults.get("mail_test_to", ""),
            key="mail_test_to",
        )
        operator_secret = st.text_input(
            "Operator secret",
            type="password",
            key="operator_secret",
            autocomplete="new-password",
            help=(
                "Type it again to save, test or clear. It is the secret "
                "`python -m src.operator_secret --init` printed, and it is kept nowhere "
                "in this browser."
            ),
        )
        save_clicked = st.form_submit_button(
            "Save mail settings", key="mail_save", type="primary"
        )
        test_clicked = st.form_submit_button(
            "Send test message", key="mail_test", type="secondary"
        )

    if save_clicked or test_clicked:
        _remember_form(
            {
                "mail_provider": st.session_state["mail_provider"],
                "mail_host": host,
                "mail_port": port,
                "mail_tls": tls,
                "mail_user": username,
                "mail_from": sender,
                "mail_test_to": destination,
            }
        )

    if save_clicked:
        problem = _operator_refusal(settings, operator_secret)
        if problem is not None:
            _refuse(
                user, audit, question="refused to save mail settings", message=problem
            )
            return
        port_number, error = _port(port)
        if port_number is None:
            _refuse(
                user, audit, question="refused to save mail settings", message=error
            )
            return
        _save_mail(
            user=user,
            settings=settings,
            audit=audit,
            store=store,
            values={
                "smtp_provider": st.session_state["mail_provider"],
                "smtp_host": host,
                "smtp_user": username,
                "smtp_from": sender,
                "smtp_tls": tls,
                "smtp_password": password,
            },
            port_number=port_number,
        )
        return

    if test_clicked:
        problem = _operator_refusal(settings, operator_secret)
        if problem is not None:
            _refuse(
                user,
                audit,
                question="refused to send a test message",
                message=problem,
            )
            return
        port_number, error = _port(port)
        if port_number is None:
            _refuse(
                user, audit, question="refused to send a test message", message=error
            )
            return
        _send_test(
            user=user,
            settings=settings,
            audit=audit,
            snapshot=snapshot,
            host=host,
            port_number=port_number,
            tls=tls,
            username=username,
            password=password,
            sender=sender,
            destination=destination,
        )
        return

    _render_clear_mail(user, settings, audit, store)


def _render_clear_mail(
    user: User,
    settings: Settings,
    audit: AuditLog,
    store: MailSettingsStore,
) -> None:
    """Destructive clear, last on the page, and only after a named confirmation.

    The first button arms the question. ``store.clear`` runs only when the
    person answers "Clear stored mail settings for this instance?" and types
    the operator secret in the same form, because clearing is as much a change
    of who receives the stored password as repointing the sender is.
    """
    st.markdown('<div class="d1-sep"></div>', unsafe_allow_html=True)
    st.markdown(
        '<p class="d1-danger">This removes the mail settings stored for this instance, '
        "including the password. It does not change .env.</p>",
        unsafe_allow_html=True,
    )
    if not st.session_state.get("mail_clear_armed"):
        if st.button("Clear stored mail settings", key="mail_clear", type="secondary"):
            st.session_state["mail_clear_armed"] = True
            _rerun_clean()
        return

    st.markdown(
        '<p class="d1-danger"><strong>Clear stored mail settings for this instance?</strong></p>',
        unsafe_allow_html=True,
    )
    with st.form("mail_clear_form", clear_on_submit=True):
        operator_secret = st.text_input(
            "Operator secret",
            type="password",
            key="mail_clear_secret",
            autocomplete="new-password",
            help="Type it again to clear. It is kept nowhere in this browser.",
        )
        confirm = st.form_submit_button(
            "Clear stored mail settings for this instance",
            key="mail_clear_confirm",
            type="secondary",
        )
        keep = st.form_submit_button(
            "Keep stored mail settings", key="mail_clear_keep", type="tertiary"
        )

    if confirm:
        problem = _operator_refusal(settings, operator_secret)
        if problem is not None:
            _refuse(
                user, audit, question="refused to clear mail settings", message=problem
            )
            return
        _clear_mail(user, settings, audit, store)
        return
    if keep:
        st.session_state["mail_clear_armed"] = False
        _rerun_clean()


def _topic_titles(service: AlertService) -> dict[str, str]:
    """The same table-to-topic-title map a fire passes to authorize()."""
    titles: dict[str, str] = {}
    for topic in service.catalog.topics:
        for table in topic.tables:
            titles.setdefault(table, topic.title)
    return titles


def _metric(service: AlertService, metric_id: str) -> Metric | None:
    for metric in service.metrics:
        if metric.id == metric_id:
            return metric
    return None


def _readable(user: User, metric: Metric | None, service: AlertService):
    """Whether this person may read the metric's table, decided the way a fire is.

    ``None`` when the catalogue no longer holds the metric: there is no table
    to refuse, and the row shows the metric id because there is nothing else.
    """
    if metric is None:
        return None
    return authorize(user, QUERY, (metric.table,), display=_topic_titles(service))


def _recipient_note(username: str, metric: Metric | None, service: AlertService) -> str:
    """Whether this recipient can still read the metric, checked the way a fire checks it."""
    person = user_named(username, service.users_path)
    if person is None:
        return f"{username} (not in the directory)"
    if metric is None:
        return f"{username} (metric is not in the catalogue)"
    decision = authorize(person, QUERY, (metric.table,), display=_topic_titles(service))
    if decision.allowed:
        return f"{username} (can read {metric.title})"
    return f"{username} ({decision.message})"


def _last_fire(fires: FireStore, alert_id: int) -> str:
    rows = fires.fires(alert_id)
    if not rows:
        return "Last fire: none"
    verdict = rows[-1].get("verdict") or "unknown"
    return f"Last fire: {verdict}"


def _remember_alert(message: str, *, ok: bool) -> None:
    st.session_state["alert_notice"] = message
    st.session_state["alert_notice_ok"] = ok
    st.rerun()


def _show_alert_notice() -> None:
    notice = st.session_state.pop("alert_notice", None)
    if notice is None:
        return
    if st.session_state.pop("alert_notice_ok", False):
        st.success(notice)
    else:
        st.error(notice)


def _record_run_now(
    user: User,
    audit: AuditLog,
    definition: AlertDefinition,
    *,
    status: str,
    outcome: str,
) -> bool:
    """One audit row for a run started from this page, naming the definition's owner."""
    return _record(
        audit,
        user,
        EVENT_RUN_NOW,
        status=status,
        question=(
            f"run alert definition #{definition.id} now "
            f"(owner {definition.owner}, outcome {outcome})"
        ),
        error=None if status == "ok" else f"run_now_{outcome}",
    )


def _run_definition(
    user: User,
    settings: Settings,
    audit: AuditLog,
    definition: AlertDefinition,
) -> None:
    """Run one definition through the worker seam, and audit the page's own act.

    The owner may run their own definition; the instance operator may run any
    definition. The worker still re-checks the *owner's* grants before any SQL,
    so an operator cannot run a definition whose owner has lost the table. It
    writes its own outcome row as ``worker``; this function writes the row that
    says which person pressed the button, once, whatever happened.
    """
    if not may_operate(definition, user):
        _record_run_now(user, audit, definition, status="denied", outcome="not_permitted")
        _remember_alert(
            "Only the owner of an alert definition can run it. "
            f"The owner is {definition.owner}.",
            ok=False,
        )
        return
    try:
        outcomes = Worker.from_settings(settings, audit=audit).tick(only={definition.id})
    except Exception as exc:  # a worker that cannot start is this click's outcome
        _record_run_now(user, audit, definition, status="failed", outcome="run_failed")
        _remember_alert(f"The run could not start: {exc}", ok=False)
        return
    if not outcomes:
        _record_run_now(
            user, audit, definition, status="denied", outcome="not_scheduled"
        )
        _remember_alert(
            f"Alert definition #{definition.id} is {definition.state}, so it is not scheduled.",
            ok=False,
        )
        return
    outcome = outcomes[0]
    written = _record_run_now(
        user,
        audit,
        definition,
        status=_STATUS_FOR_OUTCOME.get(outcome.outcome, "ok"),
        outcome=outcome.outcome,
    )
    message = f"Outcome: {outcome.outcome}. {outcome.message}"
    if not written:
        message = f"{message} The usage log could not be written."
    _remember_alert(message, ok=True)


def render_alerts_page(
    user: User, settings: Settings, audit: AuditLog, catalog: Catalog
) -> None:
    """Every definition, including paused and superseded, with the operator's actions."""
    _sidebar(user, "sign_out_alerts")
    st.markdown('<p class="d1-kicker">Settings</p>', unsafe_allow_html=True)
    st.title("Alerts")
    st.warning(DEMO_AUTH_WARNING)
    if not _require_admin(user, audit):
        return

    service = AlertService.from_settings(settings, audit=audit, catalog=catalog)
    fires = FireStore(settings.alerts_path)
    _show_alert_notice()
    definitions = service.definitions()
    if not definitions:
        st.info("No alert definitions on this instance.")
        return

    for definition in definitions:
        _render_alert_row(definition, user, service, fires, settings, audit)


def _render_alert_row(
    definition: AlertDefinition,
    user: User,
    service: AlertService,
    fires: FireStore,
    settings: Settings,
    audit: AuditLog,
) -> None:
    """One quiet row: state pill, metric, condition, last fire, then the actions.

    A metric whose table is outside this person's role is not summarized here.
    Reading the alert list is not a way to learn a metric title, a condition or
    a last-fire verdict that a question would refuse, so those three cells say
    they are hidden and the row stays identifiable by its definition id.
    """
    metric = _metric(service, definition.metric_id)
    decision = _readable(user, metric, service)
    visible = decision is None or decision.allowed
    # Delivery health is about this instance's mail, not about the metric: it
    # names a count of failures and a time, so it is shown on a restricted row
    # too. Hiding it would hide the one line that says whether the alert this
    # person is looking at could reach anybody.
    delivery_line = send_safety.health_line(definition, settings)
    state = (
        definition.state
        if definition.state in {"confirmed", "paused", "superseded", "draft"}
        else "draft"
    )
    if visible:
        title = metric.title if metric is not None else definition.metric_id
        identifier = definition.metric_id
        rule = condition(definition)
        fired_text = _last_fire(fires, definition.id)
        recipients = (
            ", ".join(
                _recipient_note(name, metric, service) for name in definition.recipients
            )
            or "none"
        )
        access = ""
    else:
        title = "Restricted metric"
        identifier = f"definition #{definition.id}"
        rule = "Condition hidden"
        fired_text = "Last fire hidden"
        recipients = (
            ", ".join(f"{name} (access hidden)" for name in definition.recipients)
            or "none"
        )
        access = (
            f"This metric is outside the {user.role} role, so its title, condition and "
            "last fire are not shown."
        )

    with st.container(key=f"alert_row_{definition.id}"):
        identity, rule_cell, fired, actions = st.columns([2.5, 1.8, 1.5, 1.7], gap="small")
        with identity:
            st.markdown(
                '<div class="d1-identity">'
                f'<div><span class="d1-state d1-state-{html.escape(state)}">'
                f"{html.escape(definition.state)}</span></div>"
                f'<div class="d1-identity-title">{html.escape(title)}</div>'
                f'<div class="d1-identity-id">{html.escape(identifier)}</div>'
                "</div>",
                unsafe_allow_html=True,
            )
        with rule_cell:
            # Composed text, so it is escaped and rendered as an HTML block: a
            # definition the model wrote must not be able to inject markup.
            st.markdown(
                f'<div class="d1-cell">{html.escape(rule)}</div>',
                unsafe_allow_html=True,
            )
        with fired:
            st.markdown(
                f'<div class="d1-cell">{html.escape(fired_text)}</div>',
                unsafe_allow_html=True,
            )
        with actions:
            if definition.state == CONFIRMED and st.button(
                "Pause", key=f"alert_pause_{definition.id}"
            ):
                result = service.pause(definition.id, user)
                _remember_alert(result.message, ok=result.ok)
            if definition.state == PAUSED and st.button(
                "Resume", key=f"alert_resume_{definition.id}"
            ):
                result = service.resume(definition.id, user)
                _remember_alert(result.message, ok=result.ok)
            if definition.state in (CONFIRMED, PAUSED) and st.button(
                "Run now", key=f"alert_run_{definition.id}"
            ):
                _run_definition(user, settings, audit, definition)
        st.markdown(
            '<div class="d1-alert-well">'
            f"<span>Window</span><span>{html.escape(window(definition))}</span>"
            f"<span>Confirmed</span><span>{html.escape(resolution(definition))}</span>"
            f"<span>Recipients</span><span>{html.escape(recipients)}</span>"
            f"<span>Delivery</span><span>{html.escape(delivery_line)}</span>"
            + (f"<span>Access</span><span>{html.escape(access)}</span>" if access else "")
            + "</div>",
            unsafe_allow_html=True,
        )
