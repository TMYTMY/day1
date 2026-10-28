"""Who a test send may reach, how often, and what the instance knows about delivery.

Three rules, and they are all about one company mailbox.

**A test send is not a relay.** The Settings page authenticates to the company's
real mailbox. Any address typed into it would therefore be a message from that
mailbox, which is internal phishing infrastructure and damages the domain's
sender reputation. So the recipient of a test message has to be an address the
instance already knows: a recipient named on an alert definition, an alert
definition's owner, or the operator's own address (which includes the address
this instance sends from, because a mailbox that cannot mail itself cannot be
tested). :func:`recipient_refusal` is the only place that rule is decided, so
the page cannot drift from it.

**A limit lives in storage.** The number of test messages an instance may send
is limited per instance and *recorded in the instance database*, not in a
Streamlit session: a session counter is reset by a reload, a second browser, a
second operator, or a restart, and a limit that any of those erases is
decoration. An attempt is recorded *before* the transport is opened, so a
failing relay consumes the quota too — that is what stops a person (or a stuck
retry) from hammering a provider that is already refusing.

**A rejected password is not retried into a lockout.** Microsoft 365 and Google
lock an account after a run of failed authentications, and the account may be a
person's only mailbox. :class:`DeliveryGuard` therefore keeps, in storage, how
many authentication failures in a row one alert definition has produced, marks
the definition failing at :data:`AUTH_FAILURE_LIMIT`, and answers
:meth:`DeliveryGuard.refusal` with a reason until a delivery succeeds or the
window passes. The caller sends exactly one notice to the owner when the mark is
made, so a bad save cannot produce one email per attempt.

The bound and the window are module constants that a caller may override
(``AUTH_FAILURE_LIMIT``, ``AUTH_FAILURE_WINDOW_SECONDS``). They are *not*
``Settings`` fields because ``src/config.py`` is owned by another ticket in this
round; a deployment that needs a different bound passes it to
:class:`DeliveryGuard` and to :class:`src.notify.Notifier` rather than editing a
file this module does not own.

:func:`read_health` and :func:`health_line` are the read side: what this
instance recorded about delivery for one definition. They are deliberately
defensive. A missing database, a missing table, an unreadable file or an
unexpected exception produce :data:`UNKNOWN`, and the line then says delivery
health is unavailable. It never falls back to a healthy default: "I have no
records" and "everything is fine" are the two answers a person must never have
confused here.

Nothing in this module opens a socket, imports Streamlit or calls a model.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.auth import user_named
from src.config import Settings
from src.models import User

# --- the recipient rule ----------------------------------------------------

# One sentence, and it is the rule rather than a template: every refusal quotes
# it, and the page shows it beside the box so the person knows it before typing.
RECIPIENT_RULE = (
    "A test message may only go to an address this instance already knows: a "
    "recipient named on an alert definition, an alert definition's owner, or your "
    "own address (including the address this instance sends from)."
)

# Stable refusal codes. They are what a reviewer greps for in the audit log.
RECIPIENT_UNKNOWN = "test_recipient_unknown"
RECIPIENT_EMPTY = "test_recipient_empty"
RECIPIENT_NOT_AN_ADDRESS = "test_recipient_not_an_address"
TEST_SEND_THROTTLED = "test_send_throttled"
AUTH_FAILURE_STOPPED = "auth_failure_stopped"
HEALTH_UNAVAILABLE = "delivery_health_unavailable"

# Where a known address came from, in words: the page does not need it, but a
# refusal that says *which* rule matched is the difference between a rule and a
# wall.
SOURCE_ALERT_RECIPIENT = "alert recipient"
SOURCE_DEFINITION_OWNER = "alert definition owner"
SOURCE_OPERATOR = "your own address"
SOURCE_SENDER = "the address this instance sends from"

# A test message the operator sends to their own mailbox is the ordinary
# self-test, so the configured sender is a known address. Nothing else is.
_ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# The documented limit. Five in fifteen minutes is enough to debug a provider
# setting; it is not enough to use a company mailbox as a mailing list.
TEST_SEND_LIMIT = 5
TEST_SEND_WINDOW_SECONDS = 15 * 60

# The authentication-failure bound and window. Three is the number of wrong
# passwords a provider tolerates before it starts refusing the account; six
# hours is long enough that a scheduled worker does not keep probing, and short
# enough that an operator who fixes the password at lunchtime is delivering
# again the same afternoon.
AUTH_FAILURE_LIMIT = 3
AUTH_FAILURE_WINDOW_SECONDS = 6 * 60 * 60

# How old a successful delivery may be before the health line calls it stale.
# Two missed daily runs: at that point the worker is not delivering the alerts
# the page would like to believe are flowing.
STALE_AFTER_SECONDS = 48 * 60 * 60


def _stamp(now: datetime) -> str:
    """A UTC timestamp with a fixed width, so string order is time order."""
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _now(clock) -> datetime:
    return (clock or (lambda: datetime.now(timezone.utc)))()


@dataclass(frozen=True)
class Refusal:
    """One refused action: a stable reason, and the sentence a person reads."""

    reason: str
    message: str


def is_address(value: str) -> bool:
    """True for one bare email address: one ``@``, no space, no control character."""
    text = (value or "").strip()
    return bool(text) and not _CONTROL.search(text) and bool(_ADDRESS.match(text))


def _address_of(user: User) -> str:
    """The address a person is mailed at: the directory email, else the username.

    The same rule ``src.notify.address_for`` uses. It is repeated rather than
    imported because ``src.notify`` imports this module, and a circular import
    between the delivery path and its safety rules is not worth one line.
    """
    return (getattr(user, "email", None) or user.username).strip()


def _stored_definitions(path: Path) -> tuple[sqlite3.Row, ...]:
    """The alert definitions stored for this instance, or none.

    Read through the store's own table rather than by constructing
    :class:`src.alerts.AlertStore`, which would create the database file merely
    because somebody opened the mail settings page. A malformed or missing
    database is "no definitions" here: the page must still render, and a test
    send is refused rather than guessed at.
    """
    database = Path(path)
    if not database.exists():
        return ()
    try:
        conn = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:  # pragma: no cover - an unreadable file is no definitions
        return ()
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, recipients, owner FROM alert_definitions ORDER BY id ASC"
        ).fetchall()
    except sqlite3.Error:
        return ()
    finally:
        conn.close()
    return tuple(rows)


def known_addresses(settings: Settings, *, operator: User) -> tuple[tuple[str, str], ...]:
    """Every address this instance already knows, with where each came from.

    In order: the operator's own address, the mailbox this instance sends from,
    then each definition's owner and named recipients. The order is the order a
    person would expect to be allowed to mail, and it is stable so a refusal can
    be explained.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(value: str, source: str) -> None:
        address = (value or "").strip().lower()
        if not address or not is_address(address) or address in seen:
            return
        seen.add(address)
        found.append((address, source))

    add(_address_of(operator), SOURCE_OPERATOR)
    add(settings.smtp_from or "", SOURCE_SENDER)
    add(settings.smtp_user or "", SOURCE_SENDER)

    names: list[User | None] = []
    for row in _stored_definitions(settings.alerts_path):
        try:
            recipients = tuple(_recipients_of(row["recipients"]))
        except (TypeError, ValueError):  # pragma: no cover - a corrupt row is skipped
            recipients = ()
        owner = str(row["owner"] or "")
        if owner:
            names.append(user_named(owner, settings.users_path))
        for username in recipients:
            names.append(user_named(str(username), settings.users_path))
    for person in names:
        if person is not None:
            add(_address_of(person), SOURCE_ALERT_RECIPIENT)
    return tuple(found)


def _recipients_of(raw: object) -> list[str]:
    """The recipient names of one stored definition row, or nothing.

    A name is *not* an address and is not accepted as one: the alert sender
    resolves names through the directory, and this page accepts addresses only.
    """
    try:
        parsed = json.loads(str(raw))
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if isinstance(item, str) and item.strip()]


def recipient_refusal(
    destination: str, settings: Settings, *, operator: User
) -> Refusal | None:
    """Why this address may not receive a test message, or None when it may.

    This is the whole of the rule. Every caller that can send a test message
    from a browser session goes through it, so there is no second, weaker copy
    of "who may be mailed" to find later.
    """
    text = (destination or "").strip()
    if not text:
        return Refusal(
            reason=RECIPIENT_EMPTY,
            message=(
                f"Enter the address to send the test message to. {RECIPIENT_RULE}"
            ),
        )
    if _CONTROL.search(text) or not is_address(text):
        return Refusal(
            reason=RECIPIENT_NOT_AN_ADDRESS,
            message=(
                f"{text!r} is not one email address, so nothing was sent. "
                "A header value with a line break in it is how a second header gets "
                f"written. {RECIPIENT_RULE}"
            ),
        )
    known = {address for address, _ in known_addresses(settings, operator=operator)}
    if text.lower() in known:
        return None
    return Refusal(
        reason=RECIPIENT_UNKNOWN,
        message=(
            f"{text} is not an address this instance knows, so nothing was sent. "
            f"{RECIPIENT_RULE} A Settings page that sends to any address an operator "
            "types is a relay for internal phishing from the company's own mailbox. "
            "What counts as known is what is saved: the stored transport, the user "
            "directory and the alert definitions. Save the mail settings first if the "
            "address you want to mail is the one you have just typed into From."
        ),
    )


# --- the rate limit -------------------------------------------------------

_CREATE_TEST_SENDS = """
CREATE TABLE IF NOT EXISTS mail_test_sends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    recipient TEXT NOT NULL,
    outcome TEXT NOT NULL
)
"""

_CREATE_TEST_SENDS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_mail_test_sends_at ON mail_test_sends(at)
"""


class MailTestLimiter:
    """The per-instance test-send quota, in ``Settings.settings_path``.

    The row is written before the transport is opened and never updated: the
    quota counts *attempts*, because the thing being limited is how often this
    instance presents a credential to a provider whose answer nobody has read
    yet. A page that only counted successful sends would let a failing
    mailbox be retried without limit, which is the lockout this ticket is about.
    """

    def __init__(
        self,
        path: Path,
        *,
        limit: int = TEST_SEND_LIMIT,
        window_seconds: float = TEST_SEND_WINDOW_SECONDS,
        clock=None,
    ):
        self.path = Path(path)
        self.limit = max(1, int(limit))
        self.window_seconds = float(window_seconds)
        self._clock = clock

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _session(self):
        conn = self._connect()
        try:
            with conn:
                conn.execute(_CREATE_TEST_SENDS)
                conn.execute(_CREATE_TEST_SENDS_INDEX)
                yield conn
        finally:
            conn.close()

    def recent(self, *, now: datetime | None = None) -> list[sqlite3.Row]:
        """The attempts inside the window, oldest first."""
        moment = now or _now(self._clock)
        cutoff = _stamp(moment - timedelta(seconds=self.window_seconds))
        with self._session() as conn:
            rows = conn.execute(
                "SELECT at, recipient FROM mail_test_sends WHERE at >= ? ORDER BY at ASC",
                (cutoff,),
            ).fetchall()
        return list(rows)

    def refusal(self, *, now: datetime | None = None) -> Refusal | None:
        """Why one more test message may not be sent now, or None when it may."""
        moment = now or _now(self._clock)
        rows = self.recent(now=moment)
        if len(rows) < self.limit:
            return None
        oldest = _parse(rows[0]["at"])
        retry_at = (
            _stamp(oldest + timedelta(seconds=self.window_seconds))
            if oldest is not None
            else "later"
        )
        minutes = int(self.window_seconds // 60)
        return Refusal(
            reason=TEST_SEND_THROTTLED,
            message=(
                f"This instance has sent {len(rows)} test messages in the last "
                f"{minutes} minutes, which is the documented limit "
                f"({self.limit} per instance per {minutes} minutes). Nothing was sent. "
                f"Try again after {retry_at}, or fix the settings without a test message."
            ),
        )

    def record(self, *, recipient: str, now: datetime | None = None) -> None:
        """Count one attempt. Raises ``sqlite3.Error`` if storage cannot take it.

        The caller turns that raise into a refusal: an attempt that cannot be
        counted is an attempt the limit cannot bound, so it must not be sent.
        """
        moment = now or _now(self._clock)
        with self._session() as conn:
            conn.execute(
                "INSERT INTO mail_test_sends (at, recipient, outcome) VALUES (?, ?, ?)",
                (_stamp(moment), str(recipient), "attempted"),
            )


# --- authentication failures --------------------------------------------

_CREATE_ATTEMPTS = """
CREATE TABLE IF NOT EXISTS delivery_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    at TEXT NOT NULL,
    outcome TEXT NOT NULL,
    error TEXT
)
"""

_CREATE_ATTEMPTS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_definition
    ON delivery_attempts(alert_id, id DESC)
"""

_CREATE_AUTH_STATE = """
CREATE TABLE IF NOT EXISTS delivery_auth_state (
    alert_id INTEGER PRIMARY KEY,
    consecutive INTEGER NOT NULL,
    first_at TEXT NOT NULL,
    last_at TEXT NOT NULL,
    notified_at TEXT
)
"""

# The outcomes a delivery attempt is recorded under.
DELIVERED = "delivered"
FAILED = "failed"
AUTH_FAILED = "auth_failed"


@dataclass(frozen=True)
class AuthStop:
    """What one authentication failure did to a definition's streak.

    ``marked_failing`` says this failure is the one that reached the bound, and
    ``should_notify`` says the owner has not been told about this streak yet —
    which is what keeps the notice to exactly one.
    """

    alert_id: int
    consecutive: int
    limit: int
    marked_failing: bool
    should_notify: bool
    first_at: datetime
    last_at: datetime


class DeliveryGuard:
    """Consecutive authentication failures per definition, in the alert database.

    The store is the instance's own alert database (``Settings.alerts_path``),
    beside the fire log, so a fact about delivery survives the process that
    learned it. A worker started by cron tomorrow must know that the password
    was rejected three times today; a dictionary in memory cannot tell it.
    """

    def __init__(
        self,
        path: Path,
        *,
        limit: int = AUTH_FAILURE_LIMIT,
        window_seconds: float = AUTH_FAILURE_WINDOW_SECONDS,
        clock=None,
    ):
        self.path = Path(path)
        self.limit = max(1, int(limit))
        self.window_seconds = float(window_seconds)
        self._clock = clock

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
                conn.execute(_CREATE_ATTEMPTS)
                conn.execute(_CREATE_ATTEMPTS_INDEX)
                conn.execute(_CREATE_AUTH_STATE)
                yield conn
        finally:
            conn.close()

    # -- the stop ---------------------------------------------------------

    def refusal(self, alert_id: int, *, now: datetime | None = None) -> Refusal | None:
        """Why delivery for this definition must not be attempted, or None.

        The answer is a fact about storage, so two ticks in two processes agree.
        Once the window has passed the mark lapses and one probe is allowed: an
        operator who fixes the password should not have to wait for ever, and
        one attempt per window is not a lockout risk.
        """
        moment = now or _now(self._clock)
        try:
            with self._session() as conn:
                row = conn.execute(
                    "SELECT * FROM delivery_auth_state WHERE alert_id = ?",
                    (int(alert_id),),
                ).fetchone()
        except sqlite3.Error:
            # A store that cannot be read cannot say "stop", and refusing every
            # delivery because a table is missing would silence the alerts this
            # guard exists to protect. The transport's own failure is still
            # recorded and reported by the caller.
            return None
        if row is None:
            return None
        consecutive = int(row["consecutive"] or 0)
        if consecutive < self.limit:
            return None
        first = _parse(row["first_at"])
        if first is None:
            return None
        if (moment - first).total_seconds() >= self.window_seconds:
            return None
        until = _stamp(first + timedelta(seconds=self.window_seconds))
        return Refusal(
            reason=AUTH_FAILURE_STOPPED,
            message=(
                f"Delivery for alert definition #{int(alert_id)} was not attempted. The "
                f"mail server has rejected the password {consecutive} times in a row "
                f"since {row['first_at']}, so sending again would keep presenting a "
                "rejected credential and can lock the mailbox for the person who owns "
                "it. Fix the password in Settings, then send a test message; delivery "
                f"is tried again automatically after {until}."
            ),
        )

    def record_auth_failure(
        self,
        alert_id: int,
        *,
        at: datetime | None = None,
        error: str | None = None,
    ) -> AuthStop:
        """Count one authentication failure, and say whether it is the bound.

        A streak older than the window starts again at one: three failures in
        six hours is a broken password, three failures across three days is
        three people typing it wrong once.
        """
        moment = at or _now(self._clock)
        stamp = _stamp(moment)
        with self._session() as conn:
            conn.execute(
                "INSERT INTO delivery_attempts (alert_id, at, outcome, error) VALUES (?, ?, ?, ?)",
                (int(alert_id), stamp, AUTH_FAILED, error),
            )
            row = conn.execute(
                "SELECT * FROM delivery_auth_state WHERE alert_id = ?", (int(alert_id),)
            ).fetchone()
            first = _parse(row["first_at"]) if row is not None else None
            expired = (
                first is None
                or (moment - first).total_seconds() >= self.window_seconds
            )
            if row is None or expired or first is None:
                consecutive = 1
                started = moment
                notified = None
            else:
                consecutive = int(row["consecutive"] or 0) + 1
                started = first
                notified = row["notified_at"]
            conn.execute(
                """
                INSERT INTO delivery_auth_state
                    (alert_id, consecutive, first_at, last_at, notified_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    consecutive = excluded.consecutive,
                    first_at = excluded.first_at,
                    last_at = excluded.last_at,
                    notified_at = excluded.notified_at
                """,
                (int(alert_id), consecutive, _stamp(started), stamp, notified),
            )
        marked = consecutive >= self.limit
        return AuthStop(
            alert_id=int(alert_id),
            consecutive=consecutive,
            limit=self.limit,
            marked_failing=marked,
            should_notify=marked and not notified,
            first_at=started,
            last_at=moment,
        )

    def mark_notified(self, alert_id: int, *, at: datetime | None = None) -> None:
        """Record that the one owner notice for this streak has been sent."""
        moment = at or _now(self._clock)
        with self._session() as conn:
            conn.execute(
                "UPDATE delivery_auth_state SET notified_at = ? WHERE alert_id = ?",
                (_stamp(moment), int(alert_id)),
            )

    def record_success(self, alert_id: int, *, at: datetime | None = None) -> None:
        """Record a delivered message and clear the streak, mark and notice."""
        moment = at or _now(self._clock)
        with self._session() as conn:
            conn.execute(
                "INSERT INTO delivery_attempts (alert_id, at, outcome, error) VALUES (?, ?, ?, NULL)",
                (int(alert_id), _stamp(moment), DELIVERED),
            )
            conn.execute(
                "DELETE FROM delivery_auth_state WHERE alert_id = ?", (int(alert_id),)
            )

    def record_failure(
        self,
        alert_id: int,
        *,
        at: datetime | None = None,
        error: str | None = None,
    ) -> None:
        """Record a non-authentication failure, for the health line's count."""
        moment = at or _now(self._clock)
        with self._session() as conn:
            conn.execute(
                "INSERT INTO delivery_attempts (alert_id, at, outcome, error) VALUES (?, ?, ?, ?)",
                (int(alert_id), _stamp(moment), FAILED, error),
            )


# --- what the instance knows about delivery -------------------------------


NEVER_SENT = "never_sent"
HEALTHY = "healthy"
STALE = "stale"
FAILING = "failing"
UNKNOWN = "unknown"

# Said when the records are not there at all. It names the absence rather than
# the state, because "no records" and "healthy" must never look the same.
UNAVAILABLE = (
    "Delivery health: unavailable — this instance has no delivery-health records "
    "for this definition (the store is missing, unreadable, or written by a build "
    "that did not record them), so nothing here says whether alerts are reaching "
    "people. Check the mail settings and the worker's last run before trusting any "
    "alert to arrive."
)


@dataclass(frozen=True)
class Health:
    """What the instance recorded about delivery for one definition."""

    kind: str
    count: int = 0
    last_at: datetime | None = None
    error: str | None = None

    @property
    def known(self) -> bool:
        return self.kind != UNKNOWN


def read_health(
    path: Path,
    alert_id: int,
    *,
    now: datetime | None = None,
    stale_after_seconds: float = STALE_AFTER_SECONDS,
) -> Health:
    """Read the delivery records for one definition, or say they are unavailable.

    Every failure mode ends in :data:`UNKNOWN`: no database, no table, an
    unreadable file, a row that is not a timestamp. None of them ends in
    :data:`HEALTHY`, because a page that shows a green line when it read nothing
    is worse than a page with no line at all.
    """
    database = Path(path)
    if not database.exists():
        return Health(kind=UNKNOWN)
    try:
        conn = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return Health(kind=UNKNOWN)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT at, outcome, error FROM delivery_attempts "
            "WHERE alert_id = ? ORDER BY id DESC",
            (int(alert_id),),
        ).fetchall()
    except sqlite3.Error:
        return Health(kind=UNKNOWN)
    finally:
        conn.close()
    if not rows:
        return Health(kind=NEVER_SENT)
    moment = now or datetime.now(timezone.utc)
    latest = _parse(rows[0]["at"])
    if rows[0]["outcome"] == DELIVERED and latest is not None:
        age = (moment - latest).total_seconds()
        if age > stale_after_seconds:
            return Health(kind=STALE, count=0, last_at=latest)
        return Health(kind=HEALTHY, count=0, last_at=latest)
    consecutive = 0
    for row in rows:
        if row["outcome"] == DELIVERED:
            break
        consecutive += 1
    return Health(
        kind=FAILING,
        count=consecutive,
        last_at=latest,
        error=rows[0]["error"],
    )


def _age_words(moment: datetime | None, now: datetime) -> str:
    if moment is None:
        return "at an unreadable time"
    seconds = max(0.0, (now - moment).total_seconds())
    if seconds < 90:
        return "just now"
    minutes = int(seconds // 60)
    if minutes < 90:
        return f"{minutes} minutes ago"
    hours = int(minutes // 60)
    if hours < 48:
        return f"{hours} hours ago"
    return f"{hours // 24} days ago"


def health_line(definition: object, settings: Settings, *, now: datetime | None = None) -> str:
    """The one line the Alerts page shows about delivery, for one definition.

    Never raises: a health record that cannot be read is a line that says so.
    That is the whole point of the seam — #28 owns the records, and this page
    must be honest both before they exist and after.
    """
    alert_id = int(getattr(definition, "id", 0) or 0)
    moment = now or datetime.now(timezone.utc)
    try:
        health = read_health(Path(settings.alerts_path), alert_id, now=moment)
    except Exception:  # noqa: BLE001 - a page must not die reading a health record
        return UNAVAILABLE
    if health.kind == UNKNOWN:
        return UNAVAILABLE
    if health.kind == NEVER_SENT:
        return (
            "Delivery health: never sent — no delivery has been recorded for this "
            "definition, so nothing is known about whether its alert would arrive."
        )
    if health.kind == HEALTHY:
        return (
            f"Delivery health: healthy — last delivery {_age_words(health.last_at, moment)}."
        )
    if health.kind == STALE:
        return (
            "Delivery health: stale — the last delivery was "
            f"{_age_words(health.last_at, moment)}, and nothing has been sent since. "
            "A fire now may reach nobody."
        )
    detail = (
        f" ({health.error})" if health.error else ""
    )
    return (
        f"Delivery health: failing — {health.count} consecutive failed "
        f"deliver{'y' if health.count == 1 else 'ies'}, the last "
        f"{_age_words(health.last_at, moment)}{detail}."
    )
