"""Alert definitions: a draft its owner confirms, and the refusals in between.

An alert definition is data, not prose (see
``docs/adr/0003-model-authors-definitions-not-execution.md``): one metric, one
comparison, one constant, one window, one cadence with a local time, a
recipient set, an owner, and the lifecycle fields that say whether it may run.
Nothing in this module calls a language model, and nothing here executes a
query: a draft never fires, and activation is a human confirmation by the
owner.

Two rules shape the code:

1. **A refusal happens at write time.** A draft naming a placeholder metric, a
   window beyond the instance maximum, a metric its owner may not read, or a
   recipient who may not read that metric is refused when it is written, not
   stored and refused later. A refusal names the offending field, writes one
   ``alert_refused`` audit row, returns the message to the caller, and leaves
   no row behind.
2. **A window is never clamped.** A window longer than the instance maximum is
   refused with the maximum in the message. Silently shortening it would
   answer a question the definer did not ask.

The store is the instance's own alert database (``Settings.alerts_path``). It
will later hold the job table and the delivery log, so this module owns only
the ``alert_definitions`` table today.

What is deliberately absent: no scheduler, no mail, no CLI and no UI. The
worker that evaluates a live definition is ``src/worker.py``; this module only
stores, validates and refuses.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

from src.alert_eval import (
    ABOVE_ABSOLUTE,
    BELOW_ABSOLUTE,
    CHANGE_PCT_DOWN,
    CHANGE_PCT_UP,
    COMPARISONS,
)
from src.audit import AuditLog
from src.auth import user_named
from src.capabilities import ALERT, CAPABILITY_NOT_GRANTED, QUERY, TABLE_NOT_ALLOWED, authorize
from src.config import Settings
from src.metrics import Metric, definition_hash, is_placeholder, load_metrics, measure_column
from src.models import User
from src.routing import Catalog

# --- vocabulary -----------------------------------------------------------

# Lifecycle states. Only ``CONFIRMED`` may fire.
DRAFT = "draft"
CONFIRMED = "confirmed"
PAUSED = "paused"
SUPERSEDED = "superseded"
STATES = frozenset({DRAFT, CONFIRMED, PAUSED, SUPERSEDED})

# The comparison kinds live in ``src/alert_eval.py`` and are imported above:
# the same four names decide a draft and decide a fire. An unknown kind is
# refused at write time rather than discovered by the worker.

# The evaluation cadence is daily today, so a cadence is a name rather than a
# cron expression.
DEFAULT_CADENCE = "daily"
CADENCES = (DEFAULT_CADENCE,)
DEFAULT_LOCAL_TIME = "09:00"

# Audit event types. The capability is always ``alert``.
EVENT_DRAFTED = "alert_drafted"
EVENT_CONFIRMED = "alert_confirmed"
EVENT_PAUSED = "alert_paused"
EVENT_RESUMED = "alert_resumed"
EVENT_REFUSED = "alert_refused"

# Refusal reasons, also written to the audit row's error column. Keep them
# stable: they are what a reviewer greps for.
METRIC_UNKNOWN = "metric_unknown"
METRIC_PLACEHOLDER = "metric_placeholder"
METRIC_NO_MEASURE = "metric_no_measure"
METRIC_NOT_READABLE = "metric_not_readable"
COMPARISON_UNKNOWN = "comparison_unknown"
CONSTANT_INVALID = "constant_invalid"
WINDOW_TOO_LONG = "window_too_long"
WINDOW_INVALID = "window_invalid"
CADENCE_UNKNOWN = "cadence_unknown"
LOCAL_TIME_INVALID = "local_time_invalid"
RECIPIENTS_EMPTY = "recipients_empty"
RECIPIENT_UNKNOWN = "recipient_unknown"
RECIPIENT_NO_CAPABILITY = "recipient_no_capability"
RECIPIENT_NOT_READABLE = "recipient_not_readable"
SUPERSEDES_UNKNOWN = "supersedes_unknown"
SUPERSEDES_NOT_CONFIRMED = "supersedes_not_confirmed"
SUPERSEDES_ALREADY_REPLACED = "supersedes_already_replaced"
OWNER_MISMATCH = "owner_mismatch"
NOT_OWNER = "not_owner"
ALERT_UNKNOWN = "alert_unknown"
STATE_NOT_DRAFT = "state_not_draft"
STATE_NOT_CONFIRMED = "state_not_confirmed"
STATE_NOT_PAUSED = "state_not_paused"

_LOCAL_TIME = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS alert_definitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_id TEXT NOT NULL,
    comparison TEXT NOT NULL,
    constant REAL NOT NULL,
    window_days INTEGER NOT NULL,
    cadence TEXT NOT NULL,
    local_time TEXT NOT NULL,
    recipients TEXT NOT NULL,
    owner TEXT NOT NULL,
    owner_role TEXT NOT NULL,
    state TEXT NOT NULL,
    supersedes INTEGER,
    superseded_by INTEGER,
    effective_from TEXT,
    created_at TEXT NOT NULL,
    confirmed_at TEXT,
    confirmed_by TEXT
)
"""


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _table_titles(catalog: Catalog) -> dict[str, str]:
    """Map each warehouse table to the topic title a person knows it by.

    The same mapping ``src/pipeline.py`` passes to ``authorize``: a refusal
    reads "Daily active users is outside the finance role", never "Table dau".
    Tables no topic claims keep the explicit "Table ..." wording.
    """
    titles: dict[str, str] = {}
    for topic in catalog.topics:
        for table in topic.tables:
            titles.setdefault(table, topic.title)
    return titles


# --- records --------------------------------------------------------------


@dataclass(frozen=True)
class AlertDraft:
    """The data a draft is made of, before it has an identity or a state."""

    metric_id: str
    comparison: str
    constant: float
    window_days: int
    cadence: str
    local_time: str
    recipients: tuple[str, ...]
    owner: str
    owner_role: str
    supersedes: int | None = None


@dataclass(frozen=True)
class AlertDefinition:
    """One stored alert definition, whatever its lifecycle state."""

    id: int
    metric_id: str
    comparison: str
    constant: float
    window_days: int
    cadence: str
    local_time: str
    recipients: tuple[str, ...]
    owner: str
    owner_role: str
    state: str
    created_at: str
    supersedes: int | None = None
    superseded_by: int | None = None
    effective_from: date | None = None
    confirmed_at: str | None = None
    confirmed_by: str | None = None

    @property
    def is_live(self) -> bool:
        """True only for a confirmed definition. A draft never runs."""
        return self.state == CONFIRMED


@dataclass(frozen=True)
class AlertResult:
    """What a caller gets back: a definition, or a refusal it can display.

    ``field`` names the offending field of a refusal, and ``reason`` is the
    stable code the audit row carries. ``audited`` is False when the audit
    write itself failed, which the message then says.
    """

    ok: bool
    message: str
    field: str | None = None
    reason: str | None = None
    definition: AlertDefinition | None = None
    audited: bool = True


# --- storage --------------------------------------------------------------


class AlertStore:
    """The instance's alert database. One file, one table, no shared state."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_owner ON alert_definitions(owner, id)"
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @contextmanager
    def _session(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def add(self, draft: AlertDraft) -> int:
        """Write one draft and return its id. The only way a row is created."""
        with self._session() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alert_definitions (
                    metric_id, comparison, constant, window_days, cadence, local_time,
                    recipients, owner, owner_role, state, supersedes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    draft.metric_id,
                    draft.comparison,
                    float(draft.constant),
                    int(draft.window_days),
                    draft.cadence,
                    draft.local_time,
                    json.dumps(list(draft.recipients), ensure_ascii=False),
                    draft.owner,
                    draft.owner_role,
                    DRAFT,
                    draft.supersedes,
                    _stamp(),
                ),
            )
            return int(cursor.lastrowid or 0)

    def get(self, alert_id: int) -> AlertDefinition | None:
        with self._session() as conn:
            row = conn.execute(
                "SELECT * FROM alert_definitions WHERE id = ?", (int(alert_id),)
            ).fetchone()
        return None if row is None else _row_to_definition(row)

    def definitions(self, owner: str | None = None) -> list[AlertDefinition]:
        with self._session() as conn:
            if owner is None:
                rows = conn.execute("SELECT * FROM alert_definitions ORDER BY id ASC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alert_definitions WHERE owner = ? ORDER BY id ASC", (owner,)
                ).fetchall()
        return [_row_to_definition(row) for row in rows]

    def live(self) -> list[AlertDefinition]:
        """Confirmed definitions only. This is what a worker may evaluate."""
        with self._session() as conn:
            rows = conn.execute(
                "SELECT * FROM alert_definitions WHERE state = ? ORDER BY id ASC", (CONFIRMED,)
            ).fetchall()
        return [_row_to_definition(row) for row in rows]

    def confirm(self, alert_id: int, *, by: str, at: str, effective_from: date) -> None:
        with self._session() as conn:
            conn.execute(
                """
                UPDATE alert_definitions
                SET state = ?, confirmed_by = ?, confirmed_at = ?, effective_from = ?
                WHERE id = ?
                """,
                (CONFIRMED, by, at, effective_from.isoformat(), int(alert_id)),
            )

    def supersede(self, alert_id: int, *, by_id: int) -> None:
        with self._session() as conn:
            conn.execute(
                "UPDATE alert_definitions SET state = ?, superseded_by = ? WHERE id = ?",
                (SUPERSEDED, int(by_id), int(alert_id)),
            )

    def pause(self, alert_id: int) -> None:
        """Stop evaluating a live definition without deleting its history."""
        with self._session() as conn:
            conn.execute(
                "UPDATE alert_definitions SET state = ? WHERE id = ?",
                (PAUSED, int(alert_id)),
            )

    def resume(self, alert_id: int) -> None:
        with self._session() as conn:
            conn.execute(
                "UPDATE alert_definitions SET state = ? WHERE id = ?",
                (CONFIRMED, int(alert_id)),
            )


def _row_to_definition(row: sqlite3.Row) -> AlertDefinition:
    effective = row["effective_from"]
    return AlertDefinition(
        id=int(row["id"]),
        metric_id=row["metric_id"],
        comparison=row["comparison"],
        constant=float(row["constant"]),
        window_days=int(row["window_days"]),
        cadence=row["cadence"],
        local_time=row["local_time"],
        recipients=tuple(json.loads(row["recipients"])),
        owner=row["owner"],
        owner_role=row["owner_role"],
        state=row["state"],
        created_at=row["created_at"],
        supersedes=None if row["supersedes"] is None else int(row["supersedes"]),
        superseded_by=None if row["superseded_by"] is None else int(row["superseded_by"]),
        effective_from=None if effective is None else date.fromisoformat(effective),
        confirmed_at=row["confirmed_at"],
        confirmed_by=row["confirmed_by"],
    )


# --- the service ----------------------------------------------------------


class AlertService:
    """Draft, confirm, supersede and read alert definitions for one instance.

    Construct it through :meth:`from_settings` so the alert database, the
    catalogue, the user directory and the instance maximum all come from the
    same place a deployment reads them from.
    """

    def __init__(
        self,
        *,
        store: AlertStore,
        audit: AuditLog,
        catalog: Catalog,
        metrics: list[Metric],
        users_path: Path,
        max_window_days: int,
    ):
        self.store = store
        self.audit = audit
        self.catalog = catalog
        self.metrics = list(metrics)
        self.users_path = Path(users_path)
        self.max_window_days = int(max_window_days)
        self._titles = _table_titles(catalog)

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        audit: AuditLog,
        catalog: Catalog,
        metrics: list[Metric] | None = None,
    ) -> AlertService:
        """Build the service the way a deployment does: everything from settings."""
        return cls(
            store=AlertStore(settings.alerts_path),
            audit=audit,
            catalog=catalog,
            metrics=load_metrics(settings.metrics_path) if metrics is None else list(metrics),
            users_path=settings.users_path,
            max_window_days=settings.max_alert_window_days,
        )

    # -- reads ------------------------------------------------------------

    def definition(self, alert_id: int) -> AlertDefinition | None:
        return self.store.get(alert_id)

    def definitions(self, owner: str | None = None) -> list[AlertDefinition]:
        return self.store.definitions(owner)

    def live(self) -> list[AlertDefinition]:
        """Confirmed definitions. A draft is never in this list."""
        return self.store.live()

    # -- writes -----------------------------------------------------------

    def draft(
        self,
        owner: User,
        *,
        metric_id: str,
        comparison: str,
        constant: object,
        window_days: object,
        cadence: str = DEFAULT_CADENCE,
        local_time: str = DEFAULT_LOCAL_TIME,
        recipients: object = (),
        supersedes: int | None = None,
    ) -> AlertResult:
        """Record a draft, or refuse it with the offending field named.

        Nothing is written until every check has passed, so a refusal never
        leaves a draft behind that a later reader could mistake for a real one.
        """
        grant = authorize(owner, ALERT)
        if not grant.allowed:
            return self._refuse(
                user=owner,
                action="draft",
                field="capability",
                reason=grant.reason or CAPABILITY_NOT_GRANTED,
                message=grant.message or "",
                metric=None,
            )

        metric = self._metric(metric_id)
        if metric is None:
            return self._refuse(
                user=owner,
                action="draft",
                field="metric",
                reason=METRIC_UNKNOWN,
                message=f"The metric {metric_id!r} is not in the metric catalogue.",
                metric=None,
            )

        readable = authorize(owner, ALERT, (metric.table,), display=self._titles)
        if not readable.allowed:
            return self._refuse(
                user=owner,
                action="draft",
                field="metric",
                reason=readable.reason or TABLE_NOT_ALLOWED,
                message=f"The metric cannot be alerted on. {readable.message}",
                metric=metric,
            )

        problem = self._check_metric(metric)
        if problem is not None:
            return self._refuse_validation(owner, "draft", problem, metric)

        problem = self._check_definition(
            comparison=comparison,
            constant=constant,
            window_days=window_days,
            cadence=cadence,
            local_time=local_time,
            recipients=recipients,
            metric=metric,
        )
        if problem is not None:
            return self._refuse_validation(owner, "draft", problem, metric)

        cleaned = self._clean_recipients(recipients)
        problem = self._check_supersedes(supersedes, owner=owner, metric=metric)
        if problem is not None:
            return self._refuse_validation(owner, "draft", problem, metric)

        draft = AlertDraft(
            metric_id=metric.id,
            comparison=str(comparison),
            constant=float(constant),  # type: ignore[arg-type]
            window_days=int(window_days),  # type: ignore[arg-type]
            cadence=str(cadence),
            local_time=str(local_time),
            recipients=cleaned,
            owner=owner.username,
            owner_role=owner.role,
            supersedes=None if supersedes is None else int(supersedes),
        )
        try:
            alert_id = self.store.add(draft)
        except sqlite3.Error as exc:
            return AlertResult(
                ok=False,
                message=f"The alert definition could not be stored: {exc}",
                field="store",
                reason="store_failed",
                audited=False,
            )

        record = self.store.get(alert_id)
        message = (
            f"Alert definition #{alert_id} is a draft. It will not run until "
            f"{owner.username} confirms it."
        )
        audited = self._audit(
            user=owner,
            status="ok",
            event_type=EVENT_DRAFTED,
            action=f"draft alert definition #{alert_id}",
            metric=metric,
            error=None,
            extra=f"window_days={draft.window_days}, comparison={draft.comparison}",
        )
        if not audited:
            message = f"{message} The usage log could not be written."
        return AlertResult(ok=True, message=message, definition=record, audited=audited)

    def confirm(self, alert_id: int, actor: User) -> AlertResult:
        """Activate a draft. Only its owner may confirm it, and only once."""
        record = self.store.get(alert_id)
        if record is None:
            return self._refuse(
                user=actor,
                action="confirm",
                field="alert",
                reason=ALERT_UNKNOWN,
                message=f"Alert definition #{alert_id} does not exist.",
                metric=None,
            )

        if record.owner != actor.username:
            return self._refuse(
                user=actor,
                action="confirm",
                field="owner",
                reason=NOT_OWNER,
                message=(
                    "Only the owner of an alert definition can confirm it. "
                    f"The owner is {record.owner}."
                ),
                metric=self._metric(record.metric_id),
                alert_id=alert_id,
            )

        grant = authorize(actor, ALERT)
        if not grant.allowed:
            return self._refuse(
                user=actor,
                action="confirm",
                field="capability",
                reason=grant.reason or CAPABILITY_NOT_GRANTED,
                message=grant.message or "",
                metric=None,
                alert_id=alert_id,
            )

        metric = self._metric(record.metric_id)
        if metric is None:
            return self._refuse(
                user=actor,
                action="confirm",
                field="metric",
                reason=METRIC_UNKNOWN,
                message=(
                    f"The metric {record.metric_id!r} is no longer in the metric catalogue, "
                    "so the alert definition cannot be confirmed."
                ),
                metric=None,
                alert_id=alert_id,
            )

        readable = authorize(actor, ALERT, (metric.table,), display=self._titles)
        if not readable.allowed:
            return self._refuse(
                user=actor,
                action="confirm",
                field="metric",
                reason=readable.reason or TABLE_NOT_ALLOWED,
                message=f"The metric cannot be alerted on. {readable.message}",
                metric=metric,
                alert_id=alert_id,
            )

        # The catalogue and the directory can both change between the draft and
        # the confirmation, so the definition is checked again here. A definition
        # whose metric has since become a placeholder cannot be activated.
        problem = self._check_metric(metric)
        if problem is not None:
            return self._refuse_validation(actor, "confirm", problem, metric, alert_id=alert_id)

        problem = self._check_recipients(record.recipients, metric)
        if problem is not None:
            return self._refuse_validation(actor, "confirm", problem, metric, alert_id=alert_id)

        if record.state != DRAFT:
            return self._refuse(
                user=actor,
                action="confirm",
                field="state",
                reason=STATE_NOT_DRAFT,
                message=(
                    f"Alert definition #{alert_id} is {record.state}, not a draft, "
                    "so it cannot be confirmed."
                ),
                metric=metric,
                alert_id=alert_id,
            )

        if record.supersedes is not None:
            replaced = self.store.get(record.supersedes)
            if replaced is not None and replaced.state == SUPERSEDED:
                return self._refuse(
                    user=actor,
                    action="confirm",
                    field="supersedes",
                    reason=SUPERSEDES_ALREADY_REPLACED,
                    message=(
                        f"Alert definition #{record.supersedes} has already been superseded "
                        f"by #{replaced.superseded_by}, so this draft cannot replace it."
                    ),
                    metric=metric,
                    alert_id=alert_id,
                )

        self.store.confirm(alert_id, by=actor.username, at=_stamp(), effective_from=_today())
        if record.supersedes is not None:
            self.store.supersede(record.supersedes, by_id=alert_id)

        updated = self.store.get(alert_id)
        message = f"Alert definition #{alert_id} is confirmed and live."
        if record.supersedes is not None:
            message = (
                f"{message} Alert definition #{record.supersedes} is now superseded."
            )
        audited = self._audit(
            user=actor,
            status="ok",
            event_type=EVENT_CONFIRMED,
            action=f"confirm alert definition #{alert_id}",
            metric=metric,
            error=None,
            extra="supersedes=" + ("none" if record.supersedes is None else f"#{record.supersedes}"),
        )
        if not audited:
            message = f"{message} The usage log could not be written."
        return AlertResult(ok=True, message=message, definition=updated, audited=audited)

    def pause(self, alert_id: int, actor: User) -> AlertResult:
        """Stop evaluating a live definition. Its history stays in the store."""
        record = self.store.get(alert_id)
        if record is None:
            return self._refuse(
                user=actor,
                action="pause",
                field="alert",
                reason=ALERT_UNKNOWN,
                message=f"Alert definition #{alert_id} does not exist.",
                metric=None,
            )
        if record.owner != actor.username:
            return self._refuse(
                user=actor,
                action="pause",
                field="owner",
                reason=NOT_OWNER,
                message=(
                    "Only the owner of an alert definition can pause it. "
                    f"The owner is {record.owner}."
                ),
                metric=self._metric(record.metric_id),
                alert_id=alert_id,
            )
        if record.state != CONFIRMED:
            return self._refuse(
                user=actor,
                action="pause",
                field="state",
                reason=STATE_NOT_CONFIRMED,
                message=(
                    f"Alert definition #{alert_id} is {record.state}, so there is nothing to pause."
                ),
                metric=self._metric(record.metric_id),
                alert_id=alert_id,
            )

        self.store.pause(alert_id)
        audited = self._audit(
            user=actor,
            status="ok",
            event_type=EVENT_PAUSED,
            action=f"pause alert definition #{alert_id}",
            metric=self._metric(record.metric_id),
            error=None,
            extra="state=paused",
        )
        message = (
            f"Alert definition #{alert_id} is paused. It stays in the audit trail and is "
            "no longer evaluated."
        )
        if not audited:
            message = f"{message} The usage log could not be written."
        return AlertResult(ok=True, message=message, definition=self.store.get(alert_id), audited=audited)

    def resume(self, alert_id: int, actor: User) -> AlertResult:
        """Make a paused definition live again. Only its owner may do it."""
        record = self.store.get(alert_id)
        if record is None:
            return self._refuse(
                user=actor,
                action="resume",
                field="alert",
                reason=ALERT_UNKNOWN,
                message=f"Alert definition #{alert_id} does not exist.",
                metric=None,
            )
        if record.owner != actor.username:
            return self._refuse(
                user=actor,
                action="resume",
                field="owner",
                reason=NOT_OWNER,
                message=(
                    "Only the owner of an alert definition can resume it. "
                    f"The owner is {record.owner}."
                ),
                metric=self._metric(record.metric_id),
                alert_id=alert_id,
            )
        if record.state != PAUSED:
            return self._refuse(
                user=actor,
                action="resume",
                field="state",
                reason=STATE_NOT_PAUSED,
                message=(
                    f"Alert definition #{alert_id} is {record.state}, so it is not paused."
                ),
                metric=self._metric(record.metric_id),
                alert_id=alert_id,
            )

        self.store.resume(alert_id)
        audited = self._audit(
            user=actor,
            status="ok",
            event_type=EVENT_RESUMED,
            action=f"resume alert definition #{alert_id}",
            metric=self._metric(record.metric_id),
            error=None,
            extra="state=confirmed",
        )
        message = f"Alert definition #{alert_id} is live again."
        if not audited:
            message = f"{message} The usage log could not be written."
        return AlertResult(ok=True, message=message, definition=self.store.get(alert_id), audited=audited)

    # -- validation helpers ----------------------------------------------

    def _metric(self, metric_id: str | None) -> Metric | None:
        if not metric_id:
            return None
        for metric in self.metrics:
            if metric.id == metric_id:
                return metric
        return None

    def _check_metric(self, metric: Metric) -> AlertResult | None:
        """A metric an alert cannot resolve has no authority as an alert.

        Two markers disqualify a metric, and the placeholder test runs first so
        an unconfirmed metric keeps the refusal it has always had. A metric
        with no measure is refused for its own reason: an alert compares a
        number, so a metric that names no column to sum would be a definition
        that can only fail at fire time.
        """
        if is_placeholder(metric):
            return AlertResult(
                ok=False,
                message=(
                    f"The metric {metric.title} still has a placeholder definition, "
                    "so no alert definition can be built on it."
                ),
                field="metric",
                reason=METRIC_PLACEHOLDER,
            )
        if measure_column(metric) is None:
            return AlertResult(
                ok=False,
                message=(
                    f"The metric {metric.title} names no measure to sum, "
                    "so no alert definition can be built on it."
                ),
                field="measure",
                reason=METRIC_NO_MEASURE,
            )
        return None

    def _check_definition(
        self,
        *,
        comparison: object,
        constant: object,
        window_days: object,
        cadence: object,
        local_time: object,
        recipients: object,
        metric: Metric,
    ) -> AlertResult | None:
        """Check every scalar field of a definition in a fixed order."""
        if comparison not in COMPARISONS:
            return AlertResult(
                ok=False,
                message=(
                    f"The comparison {comparison!r} is not one of "
                    f"{', '.join(COMPARISONS)}."
                ),
                field="comparison",
                reason=COMPARISON_UNKNOWN,
            )

        if isinstance(constant, bool) or not isinstance(constant, (int, float)):
            return AlertResult(
                ok=False,
                message=f"The constant {constant!r} is not a number.",
                field="constant",
                reason=CONSTANT_INVALID,
            )
        number = float(constant)
        if number != number or number in (float("inf"), float("-inf")):
            return AlertResult(
                ok=False,
                message=f"The constant {constant!r} is not a finite number.",
                field="constant",
                reason=CONSTANT_INVALID,
            )

        if isinstance(window_days, bool) or not isinstance(window_days, int):
            return AlertResult(
                ok=False,
                message=f"The window {window_days!r} is not a whole number of days.",
                field="window",
                reason=WINDOW_INVALID,
            )
        if window_days < 1:
            return AlertResult(
                ok=False,
                message=f"The window must be at least 1 day, not {window_days}.",
                field="window",
                reason=WINDOW_INVALID,
            )
        # Refused, never clamped: shortening the window silently would answer a
        # question the definer did not ask.
        if window_days > self.max_window_days:
            return AlertResult(
                ok=False,
                message=(
                    f"The window is {window_days} days, beyond the instance maximum "
                    f"of {self.max_window_days} days."
                ),
                field="window",
                reason=WINDOW_TOO_LONG,
            )

        if cadence not in CADENCES:
            return AlertResult(
                ok=False,
                message=(
                    f"The cadence {cadence!r} is not one of {', '.join(CADENCES)}."
                ),
                field="cadence",
                reason=CADENCE_UNKNOWN,
            )

        if not isinstance(local_time, str) or not _LOCAL_TIME.match(local_time.strip()):
            return AlertResult(
                ok=False,
                message=f"The local time {local_time!r} is not a 24-hour HH:MM value.",
                field="local_time",
                reason=LOCAL_TIME_INVALID,
            )

        if not isinstance(recipients, (list, tuple)):
            return AlertResult(
                ok=False,
                message="The recipients must be a list of usernames.",
                field="recipients",
                reason=RECIPIENTS_EMPTY,
            )
        if not self._clean_recipients(recipients):
            return AlertResult(
                ok=False,
                message=(
                    "The recipients list is empty. An alert definition needs at least "
                    "one recipient."
                ),
                field="recipients",
                reason=RECIPIENTS_EMPTY,
            )
        return self._check_recipients(recipients, metric)

    @staticmethod
    def _clean_recipients(recipients: object) -> tuple[str, ...]:
        if not isinstance(recipients, (list, tuple)):
            return ()
        cleaned: list[str] = []
        for name in recipients:
            if not isinstance(name, str):
                continue
            username = name.strip()
            if username and username not in cleaned:
                cleaned.append(username)
        return tuple(cleaned)

    def _check_recipients(self, recipients: object, metric: Metric) -> AlertResult | None:
        """Every recipient must be able to READ the metric.

        Receiving a number is a read, so the query capability and the table
        grant are what matter. The alert capability governs who may create or
        confirm a definition, not who may be told about one.

        Being sent an alert is a way of reading the metric, so a recipient is
        held to the same two grants its owner needed. Checked here, at write
        time; ticket #21 re-checks at fire time, because a role can change.
        """
        for username in self._clean_recipients(recipients):
            recipient = user_named(username, self.users_path)
            if recipient is None:
                return AlertResult(
                    ok=False,
                    message=f"The recipient {username} is not in the user directory.",
                    field="recipient",
                    reason=RECIPIENT_UNKNOWN,
                )
            decision = authorize(recipient, QUERY, (metric.table,), display=self._titles)
            if decision.allowed:
                continue
            if decision.reason == CAPABILITY_NOT_GRANTED:
                return AlertResult(
                    ok=False,
                    message=(
                        f"The recipient {username} does not hold the query capability."
                    ),
                    field="recipient",
                    reason=RECIPIENT_NO_CAPABILITY,
                )
            return AlertResult(
                ok=False,
                message=(
                    f"The recipient {username} cannot read the alert's metric. "
                    f"{decision.message}"
                ),
                field="recipient",
                reason=RECIPIENT_NOT_READABLE,
            )
        return None

    def _check_supersedes(
        self, supersedes: int | None, *, owner: User, metric: Metric
    ) -> AlertResult | None:
        """A replacement is a new draft for the same owner and metric."""
        if supersedes is None:
            return None
        previous = self.store.get(supersedes)
        if previous is None:
            return AlertResult(
                ok=False,
                message=f"Alert definition #{supersedes} does not exist.",
                field="supersedes",
                reason=SUPERSEDES_UNKNOWN,
            )
        if previous.owner != owner.username:
            return AlertResult(
                ok=False,
                message=(
                    f"Alert definition #{supersedes} belongs to {previous.owner}. "
                    f"The owner field can only supersede their own definition."
                ),
                field="owner",
                reason=OWNER_MISMATCH,
            )
        if previous.state != CONFIRMED:
            return AlertResult(
                ok=False,
                message=(
                    f"Alert definition #{supersedes} is {previous.state}, not confirmed, "
                    "so there is no live version to replace."
                ),
                field="supersedes",
                reason=SUPERSEDES_NOT_CONFIRMED,
            )
        return None

    # -- refusals and audit ----------------------------------------------

    def _refuse_validation(
        self,
        user: User,
        action: str,
        problem: AlertResult,
        metric: Metric | None,
        *,
        alert_id: int | None = None,
    ) -> AlertResult:
        return self._refuse(
            user=user,
            action=action,
            field=problem.field or "definition",
            reason=problem.reason or "refused",
            message=problem.message,
            metric=metric,
            alert_id=alert_id,
        )

    def _refuse(
        self,
        *,
        user: User,
        action: str,
        field: str,
        reason: str,
        message: str,
        metric: Metric | None,
        alert_id: int | None = None,
    ) -> AlertResult:
        """Audit one refusal and hand it back. The row is written first."""
        audited = self._audit(
            user=user,
            status="denied",
            event_type=EVENT_REFUSED,
            action=f"{action} alert definition" + ("" if alert_id is None else f" #{alert_id}"),
            metric=metric,
            error=f"{reason}: {message}",
            extra=f"field={field}",
        )
        if not audited:
            message = f"{message} The usage log could not be written."
        return AlertResult(
            ok=False,
            message=message,
            field=field,
            reason=reason,
            audited=audited,
        )

    def _audit(
        self,
        *,
        user: User,
        status: str,
        event_type: str,
        action: str,
        metric: Metric | None,
        error: str | None,
        extra: str,
    ) -> bool:
        """One row per attempt through the shared writer, capability ``alert``."""
        try:
            self.audit.record_event(
                username=user.username,
                role=user.role,
                status=status,
                event_type=event_type,
                capability=ALERT,
                question=f"{action} ({extra})",
                tables=(metric.table,) if metric is not None else (),
                error=error,
                metric_id=None if metric is None else metric.id,
                definition_hash=None if metric is None else definition_hash(metric),
            )
            return True
        except sqlite3.Error:
            return False
