"""The definition a human signed, in the instance database.

``config/metrics.yaml`` is hand-authored and heavily commented: it declares
intent. A metric is only *in force* once someone with the ``admin`` capability
re-entered the instance operator secret and signed the text. The signed text
lives here, one row per metric, in the same database as ``audit_events`` so
the signature and the row that records it are one transaction.

Two invariants this module owns:

1. **One active signature per metric.** ``metric_id`` is the primary key.
   History is the audit log, which is already append-only; there is no version
   table to reconcile.
2. **The hash is the binding.** A signature stores
   :func:`src.metrics.definition_hash` of the text it signed. Any edit to the
   text — in the file or in a form — is a different definition and needs a new
   signature, because the stored hash no longer matches.

``status`` is the single authority for "is this confirmed". The answer path,
the alert path and the catalogue page all ask it, so a placeholder can no
longer answer a question just because nobody remembered to check.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Mapping

from src.audit import AuditLog
from src.capabilities import ADMIN
from src.config import Settings
from src.metrics import Metric, definition_hash, hash_definition_text, load_metrics
from src.models import User

SIGNED = "signed"
DRAFT = "draft"

# The audit event a successful sign writes. A refusal writes
# ``settings_refused``, the same event the mail page uses for a refused write.
EVENT_SIGNED = "metric_signed"
EVENT_REFUSED = "settings_refused"

_CREATE = """
CREATE TABLE IF NOT EXISTS metric_signatures (
    metric_id       TEXT PRIMARY KEY,
    definition      TEXT NOT NULL,
    owner           TEXT NOT NULL,
    exceptions      TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    definition_hash TEXT NOT NULL,
    signed_by       TEXT NOT NULL,
    signed_role     TEXT NOT NULL,
    signed_at       TEXT NOT NULL
)
"""

_COLUMNS = (
    "metric_id",
    "definition",
    "owner",
    "exceptions",
    "effective_from",
    "definition_hash",
    "signed_by",
    "signed_role",
    "signed_at",
)


@dataclass(frozen=True)
class SignedDefinition:
    """One row of ``metric_signatures``, exactly as stored."""

    metric_id: str
    definition: str
    owner: str
    exceptions: str
    effective_from: str
    definition_hash: str
    signed_by: str
    signed_role: str
    signed_at: str


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(Path(path), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def active_signatures(db_path: Path) -> dict[str, SignedDefinition]:
    """Every signature this instance holds, keyed by metric id.

    A missing database, a database without the table, and an unreadable file
    all mean "nothing has been signed here": the catalogue then reports every
    metric as a draft, which refuses rather than guesses. Reading never
    creates the file.
    """
    path = Path(db_path)
    if not path.exists():
        return {}
    try:
        conn = _connect(path)
    except sqlite3.Error:
        return {}
    try:
        present = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'metric_signatures'"
        ).fetchone()
        if present is None:
            return {}
        rows = conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM metric_signatures ORDER BY metric_id"
        ).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    return {row["metric_id"]: SignedDefinition(**{name: row[name] for name in _COLUMNS}) for row in rows}


def status(metric: Metric, signatures: Mapping[str, SignedDefinition]) -> str:
    """``signed`` only when a row exists and binds to this exact text."""
    signed = signatures.get(metric.id)
    if signed is not None and signed.definition_hash == definition_hash(metric):
        return SIGNED
    return DRAFT


def _effective_date(value: str, fallback: date) -> date:
    try:
        return date.fromisoformat(str(value).strip())
    except (TypeError, ValueError):
        # A stored date that no longer parses keeps the file's date rather
        # than making the whole catalogue unloadable. The text, owner and
        # exceptions still come from the signature.
        return fallback


def apply_signatures(
    metrics: list[Metric], signatures: Mapping[str, SignedDefinition]
) -> list[Metric]:
    """Overlay the signed text on the file's catalogue.

    Applied whenever a row exists, not only when its hash matches the file:
    a signature is what is in force, so editing the file cannot silently
    change what a number means. The edit shows up as a divergence on the
    catalogue page, and only signing it again puts it in force.
    """
    effective: list[Metric] = []
    for metric in metrics:
        signed = signatures.get(metric.id)
        if signed is None:
            effective.append(metric)
            continue
        effective.append(
            replace(
                metric,
                definition=signed.definition,
                owner=signed.owner,
                exceptions=signed.exceptions,
                effective_from=_effective_date(signed.effective_from, metric.effective_from),
            )
        )
    return effective


def effective_catalogue(settings: Settings) -> list[Metric]:
    """The one door to the metric catalogue: the file, overlaid by signatures."""
    return apply_signatures(
        load_metrics(settings.metrics_path), active_signatures(settings.audit_path)
    )


def sign(
    *,
    audit: AuditLog,
    metric: Metric,
    definition: str,
    owner: str,
    exceptions: str,
    effective_from: date,
    signer: User,
) -> SignedDefinition:
    """Record one signature and its audit row, in one transaction.

    The signature table lives in the audit database, and the row that says who
    signed is written on the same connection. An audit write that fails rolls
    the signature back with it, so a metric is never in force without the
    record of the person who put it there.

    This function is the store, not the gate: the caller must already have
    checked the ``admin`` capability and the operator secret
    (:func:`src.metrics_page.submit_signature` does).
    """
    text = (definition or "").strip()
    record = SignedDefinition(
        metric_id=metric.id,
        definition=text,
        owner=(owner or "").strip(),
        exceptions=(exceptions or "").strip(),
        effective_from=effective_from.isoformat(),
        definition_hash=hash_definition_text(text),
        signed_by=signer.username,
        signed_role=signer.role,
        signed_at=_stamp(),
    )
    conn = _connect(audit.path)
    try:
        with conn:
            conn.execute(_CREATE)
            conn.execute(
                f"""
                INSERT INTO metric_signatures ({', '.join(_COLUMNS)})
                VALUES ({', '.join('?' for _ in _COLUMNS)})
                ON CONFLICT(metric_id) DO UPDATE SET
                    definition = excluded.definition,
                    owner = excluded.owner,
                    exceptions = excluded.exceptions,
                    effective_from = excluded.effective_from,
                    definition_hash = excluded.definition_hash,
                    signed_by = excluded.signed_by,
                    signed_role = excluded.signed_role,
                    signed_at = excluded.signed_at
                """,
                tuple(getattr(record, name) for name in _COLUMNS),
            )
            audit.record_event(
                conn=conn,
                username=signer.username,
                role=signer.role,
                status="ok",
                event_type=EVENT_SIGNED,
                capability=ADMIN,
                question=f"Confirmed the definition for {metric.id}",
                metric_id=metric.id,
                definition_hash=record.definition_hash,
            )
    finally:
        conn.close()
    return record
