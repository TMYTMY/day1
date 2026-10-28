"""Whether this instance can still deliver a notification, from stored state alone.

A governance product whose alerts stop arriving is worse than one with no
alerts at all, because silence reads as "nothing happened". So every delivery
attempt the worker makes leaves a row behind, in the instance's own settings
database (``Settings.settings_path``) — the same file the mail settings live in,
which survives a restart and needs no key to read:

* the timestamp of every attempt,
* its outcome — ``delivered``, ``suppressed`` (the comparison triggered and
  nobody who was named may still read the metric) or ``failed``,
* the definition and fire key it belongs to, for the audit trail,
* and, for a failure, the reason the transport gave, redacted.

Two rules make the answer honest:

**Suppressed is not an attempt.** Nothing is offered to a mail server when
every recipient is blocked, so it never proves the transport works and never
breaks a failure streak. It is recorded anyway, because a run of suppressions
is a delivery problem of its own kind.

**Reading writes nothing.** :meth:`DeliveryHealthStore.read` opens the file
read-only and, when the file or the table is absent, answers ``never_sent``
without creating either. That is what lets a page ask "is delivery alive?"
about an instance that has never sent anything.

**One question, one definition.** ``read(alert_id=...)`` narrows the whole
answer — last success, last failure, streak and history — to the attempts of
one alert definition. A definition with no attempts of its own reads
``never_sent`` even when other definitions have delivered, which is what lets
the Alerts page say something true about a row that has never fired. Omitting
``alert_id`` keeps the instance-wide answer.

This log is the canonical record of delivery health for the product. The alert
database keeps a different fact beside the fire log — the per-definition
authentication bookkeeping of :class:`src.send_safety.DeliveryGuard` — and
nothing derives health from it.

The state is one of four, and ``failing`` wins over ``stale`` because a failure
is a fact while staleness is an inference:

``never_sent``
    No delivery attempt has ever been recorded.
``healthy``
    A notification was delivered within the expected window.
``stale``
    Nothing has been delivered inside that window.
``failing``
    The most recent send attempts failed, and nothing has succeeded since.

The window is a parameter, not a constant of nature: an instance that sends one
daily digest and one that sends a monthly report are both healthy, and only the
operator knows which is which (``DELIVERY_ALIVE_WINDOW_HOURS``).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.redaction import redact_mail_error, transport_secrets

# One attempt's outcome. These mirror the delivery statuses in ``src.notify``,
# but they are this module's own vocabulary: the health record outlives one
# notifier implementation, and a mail transport that reports a new status must
# not be able to invent a new health state by accident.
ATTEMPT_DELIVERED = "delivered"
ATTEMPT_SUPPRESSED = "suppressed"
ATTEMPT_FAILED = "failed"
ATTEMPT_OUTCOMES = (ATTEMPT_DELIVERED, ATTEMPT_SUPPRESSED, ATTEMPT_FAILED)

# The outcomes that were actually offered to a mail server. A suppressed fire
# was never offered: it stops at the recipient check.
SEND_OUTCOMES = (ATTEMPT_DELIVERED, ATTEMPT_FAILED)

HEALTH_NEVER_SENT = "never_sent"
HEALTH_HEALTHY = "healthy"
HEALTH_STALE = "stale"
HEALTH_FAILING = "failing"
HEALTH_STATES = (HEALTH_NEVER_SENT, HEALTH_HEALTHY, HEALTH_STALE, HEALTH_FAILING)

# A daily alert delivers once a day; 26 hours leaves room for one late tick and
# one missed tick without calling a working instance dead. A slower cadence is
# the operator's number to set, not this module's to guess.
DEFAULT_ALIVE_WINDOW = timedelta(hours=26)

# How many attempts one read returns. The streak is computed over the whole
# log, so this only bounds the history a page renders.
ATTEMPT_HISTORY = 20

_STAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS delivery_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    outcome TEXT NOT NULL,
    alert_id INTEGER,
    fire_key TEXT,
    recipients INTEGER NOT NULL DEFAULT 0,
    error TEXT
)
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_outcome
    ON delivery_attempts(outcome, id DESC)
"""


def _stamp(moment: datetime) -> str:
    return _aware(moment).strftime(_STAMP_FORMAT)


def _aware(moment: datetime) -> datetime:
    """A UTC-aware datetime. A naive one is read as UTC, never as local time.

    Every other timestamp in this product is written in UTC with a trailing
    ``Z``; comparing a naive local datetime against one of those would make a
    healthy instance look stale by the size of its timezone offset.
    """
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _parse(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.strptime(str(text), _STAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _human(moment: datetime | None) -> str:
    if moment is None:
        return "never"
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _window_text(window: timedelta) -> str:
    hours = window.total_seconds() / 3600
    if hours >= 48 and hours % 24 == 0:
        days = int(hours // 24)
        return f"{days} days"
    if float(hours).is_integer():
        return f"{int(hours)} hours"
    return f"{hours:.1f} hours"


@dataclass(frozen=True)
class DeliveryAttempt:
    """One delivery attempt, as the worker recorded it.

    ``recipients`` is how many people the notification reached (0 for a failure
    or a suppression). ``error`` is the transport's reason, already redacted:
    a provider's reply can quote the ``AUTH`` line, and that line is the
    credential.
    """

    at: datetime
    outcome: str
    alert_id: int | None = None
    fire_key: str | None = None
    recipients: int = 0
    error: str | None = None

    @property
    def delivered(self) -> bool:
        return self.outcome == ATTEMPT_DELIVERED

    @property
    def failed(self) -> bool:
        return self.outcome == ATTEMPT_FAILED


@dataclass(frozen=True)
class DeliveryHealth:
    """The answer to "is delivery alive?", with the evidence behind it.

    Everything here comes from the attempt log: no network call, no send, no
    key, and no reading of the mail settings. ``attempts`` is newest first.

    Every field is scoped to the question that was asked: the whole instance
    when the read named no definition, and one definition's own attempts when
    it did.
    """

    state: str
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    # The reason the most recent *failed* attempt gave. It is history, not a
    # verdict: it stays after a later success, and ``state`` is what says
    # whether delivery works now.
    last_error: str | None = None
    streak: int = 0
    attempts: tuple[DeliveryAttempt, ...] = ()
    window: timedelta = DEFAULT_ALIVE_WINDOW
    checked_at: datetime | None = None

    @property
    def alive(self) -> bool:
        """True only when a send inside the window proves the path works.

        ``stale`` and ``never_sent`` are not alive: nothing has shown the
        transport works. ``failing`` is not alive: something has shown it does
        not. An unknown state fails closed for the same reason.
        """
        return self.state == HEALTH_HEALTHY

    @property
    def summary(self) -> str:
        """One sentence a page can render, in the words an operator uses."""
        if self.state == HEALTH_FAILING:
            head = (
                f"Delivery is failing: {self.streak} consecutive send "
                f"{'attempt' if self.streak == 1 else 'attempts'} failed, and nothing has "
                f"been delivered since {_human(self.last_success_at)}. "
                f"The last failure was {_human(self.last_failure_at)}"
            )
            return f"{head}: {self.last_error}" if self.last_error else f"{head}."
        if self.state == HEALTH_NEVER_SENT:
            return (
                "Delivery has never sent a notification from this instance, so nothing "
                "proves the mail path works."
            )
        if self.state == HEALTH_STALE:
            return (
                f"No notification has been delivered since {_human(self.last_success_at)}, "
                f"which is outside the {_window_text(self.window)} this instance expects. "
                "Either nothing has fired, or delivery has stopped."
            )
        if self.state == HEALTH_HEALTHY:
            return (
                f"Delivery is alive: the last notification was delivered at "
                f"{_human(self.last_success_at)}."
            )
        return "Delivery health cannot be determined from the stored attempts."


class DeliveryHealthStore:
    """The attempt log in one instance's settings database."""

    def __init__(self, path: Path):
        self.path = Path(path)

    # -- opening ------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
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

    @staticmethod
    def _read_only(path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    # -- writing ------------------------------------------------------------

    def record(
        self,
        *,
        outcome: str,
        at: datetime | None = None,
        alert_id: int | None = None,
        fire_key: str | None = None,
        recipients: int = 0,
        error: str | None = None,
        sender: object | None = None,
    ) -> DeliveryAttempt:
        """Store one attempt. The error text is redacted before it is stored.

        ``sender`` is the transport the attempt went through, and it is what
        makes the redaction complete: the credential that can appear in a
        server's reply is the one that transport presented. Pass it whenever a
        transport exists — without it the helper cannot name the secret and the
        text is stored as given.
        """
        if outcome not in ATTEMPT_OUTCOMES:
            raise ValueError(f"Unknown delivery outcome: {outcome!r}")
        when = _aware(at or datetime.now(timezone.utc))
        clean = None
        if error:
            secrets = transport_secrets(sender)
            clean = (
                redact_mail_error(
                    str(error),
                    password=secrets.get("password"),
                    user=secrets.get("user"),
                )
                or None
            )
        with self._session() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX)
            conn.execute(
                """
                INSERT INTO delivery_attempts (at, outcome, alert_id, fire_key, recipients, error)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    _stamp(when),
                    outcome,
                    None if alert_id is None else int(alert_id),
                    fire_key,
                    max(0, int(recipients)),
                    clean,
                ),
            )
        return DeliveryAttempt(
            at=when,
            outcome=outcome,
            alert_id=alert_id,
            fire_key=fire_key,
            recipients=max(0, int(recipients)),
            error=clean,
        )

    # -- reading ------------------------------------------------------------

    def read(
        self,
        *,
        now: datetime | None = None,
        window: timedelta = DEFAULT_ALIVE_WINDOW,
        attempts_limit: int = ATTEMPT_HISTORY,
        alert_id: int | None = None,
    ) -> DeliveryHealth:
        """Answer "is delivery alive?" from the stored attempts, and write nothing.

        A missing file, a missing table and an empty table all mean the same
        thing: nothing has been recorded, so nothing has been proved.

        ``alert_id`` narrows the answer to one definition. That definition's
        own attempts decide its state, so a definition that has never delivered
        reads ``never_sent`` while a neighbouring definition is healthy, and a
        failure of one definition never marks another failing. ``None`` asks
        the instance-wide question, which is the same answer this method gave
        before the filter existed.
        """
        checked_at = _aware(now or datetime.now(timezone.utc))
        span = window if window > timedelta(0) else DEFAULT_ALIVE_WINDOW
        wanted = None if alert_id is None else int(alert_id)
        rows = self._recent_attempts(attempts_limit, alert_id=wanted)
        attempts = tuple(_attempt(row) for row in rows)
        outcomes = self._send_outcomes(alert_id=wanted)

        last_success = next(
            (attempt.at for attempt in attempts if attempt.delivered), None
        )
        last_failure = next((attempt for attempt in attempts if attempt.failed), None)
        streak = 0
        for outcome in outcomes:  # newest first
            if outcome != ATTEMPT_FAILED:
                break
            streak += 1

        if streak:
            state = HEALTH_FAILING
        elif last_success is None:
            state = HEALTH_NEVER_SENT
        elif checked_at - last_success > span:
            state = HEALTH_STALE
        else:
            state = HEALTH_HEALTHY

        return DeliveryHealth(
            state=state,
            last_success_at=last_success,
            last_failure_at=None if last_failure is None else last_failure.at,
            # Redacted a second time on the way out. The stored text went
            # through the helper on the way in; this pass is what a reader can
            # rely on, whichever build wrote the row.
            last_error=(
                None
                if last_failure is None or not last_failure.error
                else redact_mail_error(last_failure.error) or None
            ),
            streak=streak,
            attempts=attempts,
            window=span,
            checked_at=checked_at,
        )

    def attempts(self, limit: int | None = None) -> list[DeliveryAttempt]:
        """Every recorded attempt, newest first. The whole log when ``limit`` is None."""
        return [_attempt(row) for row in self._recent_attempts(limit)]

    def has_log(self) -> bool:
        """True when this instance's attempt log exists and can be read.

        This is the question a page asks before it says anything else: a store
        that is absent, unreadable or written by a build that never recorded an
        attempt has no health answer at all, which is not the same as "nothing
        has been sent yet". Reading it writes nothing — no file, no table.
        """
        if not self.path.exists():
            return False
        try:
            conn = self._read_only(self.path)
        except sqlite3.Error:  # pragma: no cover - an unreadable file has no table
            return False
        try:
            found = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'delivery_attempts'"
            ).fetchone()
        except sqlite3.Error:  # pragma: no cover - a corrupt file has no table
            return False
        finally:
            conn.close()
        return found is not None

    def _recent_attempts(
        self, limit: int | None, *, alert_id: int | None = None
    ) -> list[sqlite3.Row]:
        """Stored attempts, newest first. A store with no table has none.

        ``alert_id`` restricts the rows to one definition's own attempts. It is
        a bound parameter, never interpolated: the id is a number from a stored
        definition, and a statement is not the place to find out otherwise.
        """
        if not self.has_log():
            return []
        sql = "SELECT * FROM delivery_attempts"
        conditions: list[str] = []
        parameters: list[object] = []
        if alert_id is not None:
            conditions.append("alert_id = ?")
            parameters.append(int(alert_id))
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            parameters.append(max(1, int(limit)))
        conn = self._read_only(self.path)
        try:
            return list(conn.execute(sql, tuple(parameters)).fetchall())
        finally:
            conn.close()

    def _send_outcomes(self, *, alert_id: int | None = None) -> list[str]:
        """The outcomes offered to a mail server, newest first.

        The streak is counted over this list and nothing else, so a suppression
        in the middle of a run of failures neither hides a failure nor pretends
        to be a success. Read in full: a bounded read would cap the streak at
        whatever number a page happened to ask for.

        A per-definition read counts that definition's streak, which is the one
        a definition's row is about; an instance-wide read counts the
        instance's.
        """
        if not self.has_log():
            return []
        sql = (
            "SELECT outcome FROM delivery_attempts WHERE outcome IN (?, ?)"
        )
        parameters: list[object] = list(SEND_OUTCOMES)
        if alert_id is not None:
            sql += " AND alert_id = ?"
            parameters.append(int(alert_id))
        sql += " ORDER BY id DESC"
        conn = self._read_only(self.path)
        try:
            rows = conn.execute(sql, tuple(parameters)).fetchall()
        finally:
            conn.close()
        return [str(row["outcome"]) for row in rows]


def _attempt(row: sqlite3.Row) -> DeliveryAttempt:
    moment = _parse(row["at"]) or datetime.min.replace(tzinfo=timezone.utc)
    return DeliveryAttempt(
        at=moment,
        outcome=str(row["outcome"]),
        alert_id=None if row["alert_id"] is None else int(row["alert_id"]),
        fire_key=row["fire_key"],
        recipients=int(row["recipients"] or 0),
        error=row["error"],
    )


def delivery_health(
    settings_path: Path | str,
    *,
    alert_id: int | None = None,
    now: datetime | None = None,
    window: timedelta = DEFAULT_ALIVE_WINDOW,
    attempts_limit: int = ATTEMPT_HISTORY,
) -> DeliveryHealth:
    """The read-only "is delivery alive?" answer for one instance.

    This is the whole surface a page needs: pass the instance settings
    database path (``Settings.settings_path``) and the window the instance
    expects, and render :attr:`DeliveryHealth.summary` with the fields behind
    it. It opens no socket, sends nothing, and needs no key.

    ``alert_id`` asks the same question about one alert definition; without it
    the answer is the instance's. A definition with no attempts of its own is
    ``never_sent`` even when other definitions have delivered.
    """
    return DeliveryHealthStore(Path(settings_path)).read(
        now=now, window=window, attempts_limit=attempts_limit, alert_id=alert_id
    )
