"""A rejected password stops delivery instead of retrying into a lockout.

Every test here is about one of the two harms the ticket names. A wrong password
retried on a schedule is how Microsoft 365 and Google lock an account, and the
account may be a person's only mailbox. So: one attempt per delivery, a bounded
streak recorded in storage, a refusal before the transport is touched once the
bound is reached, and exactly one notice to the owner rather than one per
attempt.
"""

from __future__ import annotations

import smtplib
import sqlite3
from datetime import date, datetime, timedelta, timezone

from src.notify import (
    DELIVERY_DELIVERED,
    DELIVERY_FAILED,
    Notifier,
    RecordingSender,
    compose_auth_failure,
    is_auth_failure,
)
from src.send_safety import (
    AUTH_FAILED,
    AUTH_FAILURE_LIMIT,
    AUTH_FAILURE_WINDOW_SECONDS,
    DELIVERED,
    DeliveryGuard,
    read_health,
)
from tests.test_notify import METRIC, _USERS, _definition, _outcome

OWNER = "rita"
RECIPIENT = "alex"
# The two addresses, as ``address_for`` resolves them from the test directory:
# rita has an email, alex has only a username. alex is the analyst role, so he
# may actually read the metric; rita owns the definition and receives the
# notice about the password.
RECIPIENT_ADDRESS = "alex"
OWNER_ADDRESS = "rita@example.com"


def _users(tmp_path):
    path = tmp_path / "users.yaml"
    path.write_text(_USERS, encoding="utf-8")
    return path


def _definition_owned(**overrides):
    fields = {"recipients": (RECIPIENT,), "owner": OWNER, "owner_role": "analyst"}
    fields.update(overrides)
    return _definition(**fields)


class AuthRefusingSender:
    """A transport that refuses the login, recording every message it was given.

    The list of recipients is what lets a test count attempts: a retry would
    show up as a second message to the same address, and a repeated owner
    notice as a second message to the owner. ``fail_for`` narrows the refusal to
    one address, which is how a test lets the owner notice through while the
    recipient's message is rejected — a mailbox that refuses the recipient but
    accepts the owner is the ordinary case.
    """

    def __init__(self, *, fail_for: tuple[str, ...] | None = None):
        self.calls: list[tuple[str, ...]] = []
        self.fail_for = fail_for
        self.exc = smtplib.SMTPAuthenticationError(
            535, b"535 5.7.8 Username and Password not accepted"
        )

    def send(self, message) -> None:
        self.calls.append(tuple(message.to))
        if self.fail_for is None or any(address in self.fail_for for address in message.to):
            raise self.exc

    def count(self, to: str) -> int:
        return sum(1 for call in self.calls if to in call)


def _notifier(sender, tmp_path, *, guard_path=None, **guard_kwargs) -> Notifier:
    guard = None
    if guard_path is not None:
        guard = DeliveryGuard(guard_path, **guard_kwargs)
    return Notifier(
        sender=sender,
        users_path=_users(tmp_path),
        titles={"revenue": "Revenue"},
        sleep=lambda seconds: None,
        guard=guard,
    )


# --- what counts as an authentication failure -------------------------------


def test_a_rejected_login_is_recognised_and_a_dead_relay_is_not():
    assert is_auth_failure(smtplib.SMTPAuthenticationError(535, b"nope"))
    assert is_auth_failure(
        smtplib.SMTPResponseException(534, b"application-specific password required")
    )
    assert is_auth_failure(smtplib.SMTPResponseException(530, b"Authentication required"))
    assert is_auth_failure(smtplib.SMTPResponseException(538, b"Authentication failed"))
    assert is_auth_failure(OSError("535 5.7.8 Username and Password not accepted"))

    # Retryable conditions, none of which can lock an account.
    assert not is_auth_failure(OSError("connection refused"))
    assert not is_auth_failure(smtplib.SMTPServerDisconnected("connection unexpectedly closed"))
    assert not is_auth_failure(smtplib.SMTPConnectError(421, b"service not available"))
    assert not is_auth_failure(TimeoutError("timed out"))


# --- one attempt, one notice ------------------------------------------------


def test_a_rejected_password_is_not_retried_within_a_delivery(tmp_path):
    """Mutation: restoring the retry loop for auth failures turns this red.

    Three attempts are three rejected logins. The point of the ticket is that
    the second and third are the harm, not the diagnosis.
    """
    sender = AuthRefusingSender(fail_for=(RECIPIENT_ADDRESS,))
    notifier = _notifier(sender, tmp_path, guard_path=tmp_path / "alerts.db")

    delivery = notifier.deliver(_outcome(definition=_definition_owned()), METRIC)

    assert delivery.status == DELIVERY_FAILED
    assert delivery.auth_failed is True
    assert delivery.attempts == 1
    # Exactly one message reached the transport, and it went to the recipient.
    # Below the bound the owner is not written to: the notice is for the streak,
    # not for the attempt.
    assert sender.count(RECIPIENT_ADDRESS) == 1
    assert sender.count(OWNER_ADDRESS) == 0
    assert len(sender.calls) == 1
    assert delivery.error is not None
    assert delivery.error.startswith("authentication_failed:")
    assert "not retried" in delivery.error


def test_the_bound_is_reached_after_three_consecutive_rejections_and_one_notice(tmp_path):
    """Mutation: notifying on every failure, or never marking the definition, turns this red."""
    alerts = tmp_path / "alerts.db"
    sender = AuthRefusingSender(fail_for=(RECIPIENT_ADDRESS,))

    deliveries = []
    for _ in range(AUTH_FAILURE_LIMIT):
        deliveries.append(
            _notifier(sender, tmp_path, guard_path=alerts).deliver(
                _outcome(definition=_definition_owned()), METRIC
            )
        )

    # Each delivery tried exactly once. The first two stayed under the bound,
    # so the owner heard nothing; the third crossed it and one notice went out.
    assert [item.attempts for item in deliveries] == [1, 1, 1]
    assert [item.owner_notified for item in deliveries] == [False, False, True]
    assert sender.count(OWNER_ADDRESS) == 1

    refusal = DeliveryGuard(alerts).refusal(7)
    assert refusal is not None
    assert "was not attempted" in refusal.message
    assert "rejected the password 3 times" in refusal.message


def test_a_marked_definition_is_refused_before_the_transport_is_touched(tmp_path):
    """Mutation: dropping the guard check in deliver() turns the owner into an email loop."""
    alerts = tmp_path / "alerts.db"
    sender = AuthRefusingSender(fail_for=(RECIPIENT_ADDRESS,))
    for _ in range(AUTH_FAILURE_LIMIT):
        _notifier(sender, tmp_path, guard_path=alerts).deliver(
            _outcome(definition=_definition_owned()), METRIC
        )
    before = len(sender.calls)

    delivery = _notifier(sender, tmp_path, guard_path=alerts).deliver(
        _outcome(definition=_definition_owned()), METRIC
    )

    assert delivery.status == DELIVERY_FAILED
    assert delivery.stopped is True
    assert delivery.attempts == 0
    assert len(sender.calls) == before  # nothing new reached the transport
    assert "was not attempted" in delivery.message
    assert "Fix the password in Settings" in delivery.message
    # The status stays ``failed`` so the worker's existing outcome mapping still
    # treats this as a failed run with a non-zero exit code.
    assert delivery.error is not None
    assert delivery.error.startswith("auth_failure_stopped:")


def test_a_delivered_message_clears_the_streak(tmp_path):
    """Mutation: never clearing the streak turns a fixed password into a permanent stop."""
    alerts = tmp_path / "alerts.db"
    guard = DeliveryGuard(alerts)
    guard.record_auth_failure(7, error="first")
    guard.record_auth_failure(7, error="second")
    assert guard.refusal(7) is None  # under the bound

    sender = RecordingSender()
    delivery = _notifier(sender, tmp_path, guard_path=alerts).deliver(
        _outcome(definition=_definition_owned()), METRIC
    )

    assert delivery.status == DELIVERY_DELIVERED
    assert guard.refusal(7) is None
    # A new guard over the same file — the next tick — sees the cleared streak.
    assert DeliveryGuard(alerts).refusal(7) is None


def test_the_bound_lapses_after_the_window_so_one_probe_is_allowed(tmp_path):
    """The mark is not for ever: one attempt per window is not a lockout risk."""
    alerts = tmp_path / "alerts.db"
    start = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)
    guard = DeliveryGuard(alerts, window_seconds=60, clock=lambda: start)
    for _ in range(AUTH_FAILURE_LIMIT):
        guard.record_auth_failure(7)
    assert guard.refusal(7) is not None

    later = start + timedelta(seconds=61)
    assert guard.refusal(7, now=later) is None
    # A failure after the window starts a new streak rather than continuing it.
    stop = guard.record_auth_failure(7, at=later)
    assert stop.consecutive == 1
    assert stop.should_notify is False
    assert AUTH_FAILURE_WINDOW_SECONDS > 0


def test_without_a_store_the_delivery_still_stops_and_says_so(tmp_path):
    """No guard is a supported state, and the notice must not claim persistence."""
    sender = AuthRefusingSender(fail_for=(RECIPIENT_ADDRESS,))
    notifier = _notifier(sender, tmp_path, guard_path=None)

    delivery = notifier.deliver(_outcome(definition=_definition_owned()), METRIC)

    assert delivery.attempts == 1
    assert delivery.owner_notified is True
    assert len(sender.calls) == 2  # one attempt, one notice
    assert "no delivery-health store wired" in delivery.message


def test_a_relay_failure_is_still_retried_and_is_not_an_auth_failure(tmp_path):
    """The stop must not swallow the retries a restarting relay needs."""
    sender = RecordingSender(fail_times=2)
    notifier = _notifier(sender, tmp_path, guard_path=tmp_path / "alerts.db")

    delivery = notifier.deliver(_outcome(definition=_definition_owned()), METRIC)

    assert delivery.status == DELIVERY_DELIVERED
    assert delivery.attempts == 3
    assert delivery.auth_failed is False


def test_a_store_that_cannot_be_read_does_not_silence_the_alert(tmp_path):
    """A broken guard is a broken guard: the send still happens and still reports."""

    class BrokenGuard:
        def refusal(self, alert_id, *, now=None):
            raise sqlite3.OperationalError("database is locked")

        def record_auth_failure(self, alert_id, *, at=None, error=None):
            raise sqlite3.OperationalError("database is locked")

        def record_success(self, alert_id, *, at=None):
            raise sqlite3.OperationalError("database is locked")

        def record_failure(self, alert_id, *, at=None, error=None):
            raise sqlite3.OperationalError("database is locked")

        def mark_notified(self, alert_id, *, at=None):
            raise sqlite3.OperationalError("database is locked")

    sender = RecordingSender()
    notifier = Notifier(
        sender=sender,
        users_path=_users(tmp_path),
        sleep=lambda seconds: None,
        guard=BrokenGuard(),  # type: ignore[arg-type]
    )

    delivery = notifier.deliver(_outcome(definition=_definition_owned()), METRIC)

    assert delivery.status == DELIVERY_DELIVERED
    assert sender.recipients == [RECIPIENT_ADDRESS]


def test_the_owner_notice_explains_the_fix_and_mentions_the_bound():
    notification = compose_auth_failure(
        definition=_definition_owned(),
        metric_title="Revenue by product",
        consecutive=3,
        limit=3,
        first_at=datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc),
        error="authentication_failed: 535",
        fire_key="7:2026-10-27",
        window_start=date(2026, 10, 21),
        window_end=date(2026, 10, 27),
        marked_failing=True,
    )

    assert "Mail authentication is failing" in notification.subject
    assert "3 authentication failures in a row" in notification.body
    assert "Settings, then Mail settings" in notification.body
    assert "app password" in notification.body
    assert "send a test message" in notification.body
    assert "7:2026-10-27" in notification.body


# --- the storage the stop is made of ---------------------------------------


def test_the_streak_is_in_storage_not_in_a_process(tmp_path):
    """A cron worker tomorrow must know what today's worker learned."""
    alerts = tmp_path / "alerts.db"
    first = DeliveryGuard(alerts)
    for _ in range(AUTH_FAILURE_LIMIT):
        first.record_auth_failure(7, error="535")

    # A brand-new guard over the same file — the next process — still refuses.
    assert DeliveryGuard(alerts).refusal(7) is not None

    conn = sqlite3.connect(alerts)
    try:
        rows = conn.execute(
            "SELECT outcome FROM delivery_auth_attempts WHERE alert_id = 7"
        ).fetchall()
    finally:
        conn.close()
    assert [row[0] for row in rows] == [AUTH_FAILED] * AUTH_FAILURE_LIMIT


def _tables(path) -> set[str]:
    """The table names in one database file, or none when it does not exist."""
    if not path.exists():
        return set()
    conn = sqlite3.connect(path)
    try:
        return {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    finally:
        conn.close()


def test_a_success_is_recorded_as_delivered(tmp_path):
    guard = DeliveryGuard(tmp_path / "alerts.db")
    guard.record_auth_failure(7)
    guard.record_success(7)

    assert DeliveryGuard(tmp_path / "alerts.db").refusal(7) is None

    conn = sqlite3.connect(tmp_path / "alerts.db")
    try:
        outcome = conn.execute(
            "SELECT outcome FROM delivery_auth_attempts WHERE alert_id = 7 ORDER BY id DESC"
        ).fetchone()[0]
    finally:
        conn.close()
    assert outcome == DELIVERED


def test_the_notifier_keeps_no_second_health_log(tmp_path):
    """The alert database is authentication bookkeeping; health has one home.

    Mutation: writing delivery health from the notifier again puts the old
    ``delivery_attempts`` table back in this database, and the page would be
    reading a log that only one half of the product fills.
    """
    alerts = tmp_path / "alerts.db"
    notifier = _notifier(RecordingSender(), tmp_path, guard_path=alerts)
    notifier.deliver(_outcome(definition=_definition_owned()), METRIC)

    tables = _tables(alerts)
    assert "delivery_attempts" not in tables
    assert "delivery_auth_attempts" in tables
    # And the page's reader will not answer from this database at all: a store
    # with no delivery log is unknown, never healthy.
    assert read_health(alerts, 7).kind == "unknown"


def test_from_settings_wires_the_guard_to_the_instance_alert_database(tmp_path):
    """The seam a deployment uses: the guard's file comes from the settings.

    ``src/worker.py`` builds its notifier through ``Notifier.from_settings``
    (issue #30), so the constructor asserted here is the one a tick uses: a
    worker records the rejected password and remembers it between ticks.
    Delivery *health* is recorded by the worker itself, in the settings
    database (see ``tests/test_worker.py``).
    """
    from tests.test_notify import _smtp_settings

    settings = _smtp_settings(
        users_path=_users(tmp_path),
        alerts_path=tmp_path / "alerts.db",
    )
    sender = AuthRefusingSender(fail_for=(RECIPIENT_ADDRESS,))
    notifier = Notifier.from_settings(settings, sender=sender, sleep=lambda seconds: None)

    assert notifier.guard is not None
    assert notifier.guard.path == settings.alerts_path
    for _ in range(AUTH_FAILURE_LIMIT):
        notifier.deliver(_outcome(definition=_definition_owned()), METRIC)

    # The refusal is readable from a guard opened separately, over the same file.
    assert DeliveryGuard(settings.alerts_path).refusal(7) is not None
