"""The 口徑目錄 (metric catalogue) page: what a number means, and who signed it.

Every metric in :mod:`config.metrics` is shown as one block: what it is, which
table and grain it comes from, its status, the hash of the text in force, and
its owner. Three states decide what can be done:

1. **Draft** — nobody has signed this definition. The boxes are pre-filled from
   the file and an admin can sign them. Until then the answer path refuses the
   question, so the page and the answer agree about what is in force.
2. **Signed** — the signed text is shown read-only, with who signed it and
   when, and a revise form starts from that text.
3. **Signed, but the file was edited** — the file's text is not the signed
   text. The signature still wins, so the page says so and offers two ways
   forward: sign the file's version, or discard the file edit (which only
   re-renders; this page never writes the file).

Rules that shape the writes, borrowed from the mail page because they are the
same problem — a browser session that grants a change to what the product
means:

- The ``admin`` capability is required (the gate lives in
  :func:`src.capabilities.require_admin`).
- The instance operator secret must be re-entered. A wrong or empty secret
  writes one refusal row and changes nothing.
- A successful sign writes the signature row and its audit row in one
  transaction (:func:`src.metric_signatures.sign`), then re-renders with the
  secret dropped from widget and session state.
- There is no withdraw or delete: superseding is re-signing.
- ``synonyms``, ``table``, ``grain``, ``additive_over`` and ``measure`` stay
  file-level. This page signs prose and dates, not the shape of a query.
"""

from __future__ import annotations

import html
import sqlite3
from dataclasses import dataclass
from datetime import date

import streamlit as st

from src import operator_secret
from src.audit import AuditLog
from src.capabilities import (
    ADMIN,
    CAPABILITY_NOT_GRANTED,
    authorize,
    require_admin,
)
from src.config import Settings
from src.metric_signatures import (
    DRAFT,
    EVENT_REFUSED,
    SIGNED,
    SignedDefinition,
    active_signatures,
    sign,
)
from src.metrics import (
    Metric,
    carries_placeholder_marker,
    definition_hash,
    load_metrics,
)
from src.models import User

# Why a sign attempt was refused. The audit row records these in its error
# column, so keep them stable; the page shows the sentence beside them.
REASON_NO_ADMIN = CAPABILITY_NOT_GRANTED
REASON_SECRET_UNSET = "operator_secret_unset"
REASON_SECRET_EMPTY = "operator_secret_empty"
REASON_SECRET_MISMATCH = "operator_secret_mismatch"
REASON_DEFINITION_EMPTY = "definition_empty"
REASON_DEFINITION_PLACEHOLDER = "definition_placeholder"
REASON_OWNER_EMPTY = "owner_empty"
REASON_DATE_INVALID = "effective_from_invalid"

_SECRET_PREFIX = "metric_secret_"

_DEMO_WARNING = (
    "Day 1 still signs in with a demo password. This page is not a substitute "
    "for authentication on an instance exposed to the public."
)


@dataclass(frozen=True)
class SignOutcome:
    """What one press of a sign button did, in words a page can show."""

    ok: bool
    message: str
    signature: SignedDefinition | None = None


# --- pure helpers ----------------------------------------------------------


def file_diverges(draft: Metric, signed: SignedDefinition | None) -> bool:
    """True when the file's entry is not the text a human signed.

    Only the four fields a signature owns are compared. Table, grain,
    synonyms, additive_over and measure are file-level and cannot diverge:
    changing one changes the query, not the meaning of the prose.
    """
    if signed is None:
        return False
    return (
        draft.definition.strip() != signed.definition.strip()
        or draft.owner.strip() != signed.owner.strip()
        or draft.exceptions.strip() != signed.exceptions.strip()
        or draft.effective_from.isoformat() != signed.effective_from
    )


def status_badge(value: str) -> str:
    """The badge word for a status. One spelling, used by the page and tests."""
    return "Signed" if value == SIGNED else "Draft"


def secret_refusal(settings: Settings, entered: str) -> tuple[str, str] | None:
    """Why this secret cannot authorise a signature, or None when it can.

    The same rule as the mail page: this instance must have a secret, the box
    must not be empty, and the value must be the one the host printed. Nothing
    is written before this answers.
    """
    path = settings.settings_path
    if not operator_secret.has_secret(path):
        return (
            REASON_SECRET_UNSET,
            "This instance has no operator secret, so a definition cannot be signed "
            "here. Run `python -m src.operator_secret --init` on the host, then enter "
            "the secret it prints.",
        )
    if not (entered or ""):
        return (
            REASON_SECRET_EMPTY,
            "Enter the operator secret to sign a definition. It is not kept in this "
            "browser: the secret printed by `python -m src.operator_secret --init` "
            "must be typed again.",
        )
    if not operator_secret.verify_secret(path, entered):
        return (REASON_SECRET_MISMATCH, "The operator secret did not match. Nothing was signed.")
    return None


def field_refusal(
    definition: str, owner: str, effective_from: str
) -> tuple[str, str] | None:
    """The first empty or malformed field, named the way a person can fix it."""
    if not (definition or "").strip():
        return (REASON_DEFINITION_EMPTY, "A definition cannot be empty. Nothing was signed.")
    if not (owner or "").strip():
        return (REASON_OWNER_EMPTY, "A definition needs an owner. Nothing was signed.")
    if carries_placeholder_marker(definition, owner):
        return (
            REASON_DEFINITION_PLACEHOLDER,
            "This is still a placeholder, not a definition: the text says "
            "PLACEHOLDER or the owner is placeholder. Write the real definition "
            "and name the owner who confirmed it. Nothing was signed.",
        )
    try:
        date.fromisoformat((effective_from or "").strip())
    except ValueError:
        return (
            REASON_DATE_INVALID,
            "The effective date must be written YYYY-MM-DD. Nothing was signed.",
        )
    return None


def _refuse(
    user: User, audit: AuditLog, metric: Metric, *, reason: str, message: str
) -> SignOutcome:
    """Write this attempt's one refusal row, then hand back the sentence."""
    detail = message
    try:
        audit.record_event(
            username=user.username,
            role=user.role,
            status="denied",
            event_type=EVENT_REFUSED,
            capability=ADMIN,
            question=f"refused to sign the definition for {metric.id}: {reason}",
            metric_id=metric.id,
            error=reason,
        )
    except sqlite3.Error:
        detail = f"{message} The usage log could not be written."
    return SignOutcome(ok=False, message=detail)


def submit_signature(
    *,
    metric: Metric,
    definition: str,
    exceptions: str,
    owner: str,
    effective_from: str,
    secret: str,
    user: User,
    settings: Settings,
    audit: AuditLog,
) -> SignOutcome:
    """The one seam every sign button goes through: gate, secret, write, audit.

    Order matters and is the point: a role without ``admin`` learns nothing
    about the secret, a wrong secret writes nothing but its refusal, and only
    then is the text validated and written. Every attempt — success or
    refusal — leaves exactly one audit row.
    """
    decision = authorize(user, ADMIN)
    if not decision.allowed:
        return _refuse(
            user,
            audit,
            metric,
            reason=REASON_NO_ADMIN,
            message=decision.message
            or f"The {ADMIN} capability is not granted to the {user.role} role.",
        )

    refused = secret_refusal(settings, secret)
    if refused is not None:
        reason, message = refused
        return _refuse(user, audit, metric, reason=reason, message=message)

    refused = field_refusal(definition, owner, effective_from)
    if refused is not None:
        reason, message = refused
        return _refuse(user, audit, metric, reason=reason, message=message)

    try:
        record = sign(
            audit=audit,
            metric=metric,
            definition=definition,
            owner=owner,
            exceptions=exceptions,
            effective_from=date.fromisoformat(effective_from.strip()),
            signer=user,
        )
    except sqlite3.Error as exc:
        # The transaction rolled back with the audit row: nothing is in force.
        return SignOutcome(
            ok=False,
            message=(
                "The signature could not be stored, so nothing changed: "
                f"{exc}"
            ),
        )
    return SignOutcome(
        ok=True,
        message=(
            f"Signed the definition for {metric.id}. "
            "Questions about it can be answered again."
        ),
        signature=record,
    )


# --- Streamlit -------------------------------------------------------------


def _sign_out() -> None:
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


def _purge_secrets() -> None:
    """Drop every operator-secret box on the run after it was read.

    The same reason as the mail page: the value a handler used was copied out
    of the widget before the rerun, and the widget key is popped before the
    box exists again, so nothing typed survives its own run.
    """
    if not st.session_state.pop("metrics_purge_secrets", False):
        return
    for key in [name for name in st.session_state if str(name).startswith(_SECRET_PREFIX)]:
        st.session_state.pop(key, None)


def _rerun_clean() -> None:
    st.session_state["metrics_purge_secrets"] = True
    st.rerun()


def _remember(outcome: SignOutcome) -> None:
    st.session_state["metrics_notice"] = {"ok": outcome.ok, "detail": outcome.message}
    _rerun_clean()


def _show_notice() -> None:
    notice = st.session_state.pop("metrics_notice", None)
    if not notice:
        return
    if notice["ok"]:
        st.success(notice["detail"])
    else:
        st.error(notice["detail"])


def _identity(metric: Metric, in_force: str) -> None:
    """The lines that are true whatever state the metric is in."""
    badge = status_badge(in_force)
    st.markdown(
        '<div class="d1-identity">'
        f'<div><span class="d1-state d1-state-{"confirmed" if badge == "Signed" else "draft"}">'
        f"{html.escape(badge)}</span></div>"
        f'<div class="d1-identity-title">{html.escape(metric.title)}</div>'
        f'<div class="d1-identity-id">{html.escape(metric.id)}</div>'
        "</div>",
        unsafe_allow_html=True,
    )
    st.caption(f"Table · {metric.table} · grain · {', '.join(metric.grain)}")
    st.caption(f"Owner · {metric.owner} · effective from · {metric.effective_from.isoformat()}")
    st.caption(f"Hash of the text in force · {definition_hash(metric)}")


def _sign_form(
    *,
    metric: Metric,
    key: str,
    definition: str,
    exceptions: str,
    owner: str,
    effective_from: str,
    label: str,
    user: User,
    settings: Settings,
    audit: AuditLog,
) -> None:
    """A pre-filled sign form. Nothing is written unless its button is pressed."""
    with st.form(key=f"sign_{key}_{metric.id}", clear_on_submit=True):
        new_definition = st.text_area(
            "Definition", value=definition, height=110, key=f"{key}_{metric.id}_definition"
        )
        new_exceptions = st.text_area(
            "Exceptions", value=exceptions, height=80, key=f"{key}_{metric.id}_exceptions"
        )
        new_owner = st.text_input(
            "Owner", value=owner, key=f"{key}_{metric.id}_owner"
        )
        new_date = st.text_input(
            "Effective from (YYYY-MM-DD)",
            value=effective_from,
            key=f"{key}_{metric.id}_effective_from",
        )
        secret = st.text_input(
            "Operator secret",
            type="password",
            key=f"{_SECRET_PREFIX}{key}_{metric.id}",
            autocomplete="new-password",
            help=(
                "Type it again to sign. It is the secret `python -m "
                "src.operator_secret --init` printed, and it is kept nowhere in "
                "this browser."
            ),
        )
        pressed = st.form_submit_button(label, key=f"sign_submit_{key}_{metric.id}")
    if not pressed:
        return
    outcome = submit_signature(
        metric=metric,
        definition=new_definition,
        exceptions=new_exceptions,
        owner=new_owner,
        effective_from=new_date,
        secret=secret,
        user=user,
        settings=settings,
        audit=audit,
    )
    _remember(outcome)


def _signed_view(signed: SignedDefinition) -> None:
    st.text_area(
        "Signed definition",
        value=signed.definition,
        height=110,
        disabled=True,
        key=f"signed_definition_{signed.metric_id}",
    )
    if signed.exceptions:
        st.text_area(
            "Signed exceptions",
            value=signed.exceptions,
            height=80,
            disabled=True,
            key=f"signed_exceptions_{signed.metric_id}",
        )
    st.caption(
        f"Signed by {signed.signed_by} ({signed.signed_role}) at {signed.signed_at} · "
        f"hash {signed.definition_hash} · effective from {signed.effective_from}"
    )


def _render_metric(
    *,
    metric: Metric,
    draft: Metric,
    signed: SignedDefinition | None,
    user: User,
    settings: Settings,
    audit: AuditLog,
) -> None:
    """One metric block: identity, then whichever of the three cases applies."""
    with st.container(key=f"metric_{metric.id}"):
        # The effective catalogue overlays the signature, so a row that exists
        # is the text in force; the file may still differ (case 3).
        _identity(metric, SIGNED if signed is not None else DRAFT)
        if signed is None:
            st.info(
                "No confirmed definition. Questions about this number are refused "
                "until an admin signs one."
            )
            _sign_form(
                metric=metric,
                key="sign",
                definition=draft.definition,
                exceptions=draft.exceptions,
                owner=draft.owner,
                effective_from=draft.effective_from.isoformat(),
                label="Sign this definition",
                user=user,
                settings=settings,
                audit=audit,
            )
            st.markdown('<div class="d1-sep"></div>', unsafe_allow_html=True)
            return

        _signed_view(signed)
        if file_diverges(draft, signed):
            st.warning(
                "The file has been edited since this definition was signed. The file "
                "edit is not in force: the signed text above is what answers. Sign the "
                "file version to put the edit in force, or leave the file as it is."
            )
            st.text_area(
                "Text in config/metrics.yaml",
                value=draft.definition,
                height=110,
                disabled=True,
                key=f"file_definition_{metric.id}",
            )
            st.caption(
                f"In the file: owner {draft.owner} · effective from "
                f"{draft.effective_from.isoformat()} · exceptions "
                f"{draft.exceptions or '(none)'}"
            )
            if st.button("Discard the file edit", key=f"discard_{metric.id}"):
                # Re-render only: this page never writes the catalogue file.
                st.rerun()
            _sign_form(
                metric=metric,
                key="file",
                definition=draft.definition,
                exceptions=draft.exceptions,
                owner=draft.owner,
                effective_from=draft.effective_from.isoformat(),
                label="Sign the file version",
                user=user,
                settings=settings,
                audit=audit,
            )
        else:
            with st.expander("Revise and re-sign"):
                _sign_form(
                    metric=metric,
                    key="revise",
                    definition=signed.definition,
                    exceptions=signed.exceptions,
                    owner=signed.owner,
                    effective_from=signed.effective_from,
                    label="Revise and re-sign",
                    user=user,
                    settings=settings,
                    audit=audit,
                )
        st.markdown('<div class="d1-sep"></div>', unsafe_allow_html=True)


def render_metrics_page(
    user: User, settings: Settings, audit: AuditLog, catalogue: list[Metric]
) -> None:
    """Every metric, what is in force, and the one act that changes it."""
    _purge_secrets()
    _sidebar(user, "sign_out_metrics")
    st.markdown('<p class="d1-kicker">Governance</p>', unsafe_allow_html=True)
    st.title("口徑目錄")
    st.caption(
        "The definition in force for each number. A metric answers questions only "
        "after an admin signs its definition; the file is the draft, the signature "
        "is what counts."
    )
    st.warning(_DEMO_WARNING)
    if not require_admin(user, audit):
        return

    _show_notice()
    signatures = active_signatures(settings.audit_path)
    drafts = {item.id: item for item in load_metrics(settings.metrics_path)}
    if not catalogue:
        st.info("The metric catalogue is empty.")
        return
    for metric in catalogue:
        _render_metric(
            metric=metric,
            draft=drafts.get(metric.id, metric),
            signed=signatures.get(metric.id),
            user=user,
            settings=settings,
            audit=audit,
        )
