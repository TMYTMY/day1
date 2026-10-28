"""Delivery health: the four states, the streak, and the redacted reason.

Every test here works on a temporary instance settings database and builds its
own attempts, so the four states are read from rows this test wrote rather than
from a worker's behaviour. Nothing sleeps, nothing sends, nothing listens.
"""

from __future__ import annotations

import base64
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from src.config import load_settings
from dataclasses import replace

from src.crypto import generate_key
from src.delivery_health import (
    ATTEMPT_DELIVERED,
    ATTEMPT_FAILED,
    ATTEMPT_SUPPRESSED,
    DEFAULT_ALIVE_WINDOW,
    HEALTH_FAILING,
    HEALTH_HEALTHY,
    HEALTH_NEVER_SENT,
    HEALTH_STALE,
    DeliveryHealthStore,
    delivery_health,
)
from src.mail_settings import MailSettingsStore

NOW = datetime(2026, 10, 28, 9, 10, tzinfo=timezone.utc)

SECRET = "day1-mail-secret-9912"
SMTP_USER = "owner@example.com"


@pytest.fixture
def path(tmp_path):
    return tmp_path / "instance.db"


@pytest.fixture
def store(path):
    return DeliveryHealthStore(path)


def _sender():
    """The two facts the redaction helper needs from a transport."""
    return SimpleNamespace(password=SECRET, user=SMTP_USER)


def _auth_plain(password: str, user: str) -> str:
    return base64.b64encode(f"\0{user}\0{password}".encode("utf-8")).decode("ascii")


# --- the four states ------------------------------------------------------


def test_a_fresh_instance_has_never_sent_and_reading_creates_nothing(store, path):
    health = store.read(now=NOW)

    assert health.state == HEALTH_NEVER_SENT
    assert health.alive is False
    assert health.last_success_at is None
    assert health.last_failure_at is None
    assert health.last_error is None
    assert health.streak == 0
    assert health.attempts == ()
    assert "never sent" in health.summary
    # The read-only question does not create the database it is asking about:
    # an instance that has never delivered has no attempt log, not an empty one.
    assert not path.exists()


def test_a_delivery_inside_the_window_is_alive(store):
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW - timedelta(hours=2), alert_id=1)

    health = store.read(now=NOW)

    assert health.state == HEALTH_HEALTHY
    assert health.alive is True
    assert health.last_success_at == NOW - timedelta(hours=2)
    assert health.last_failure_at is None
    assert health.streak == 0
    assert health.summary.startswith("Delivery is alive")


def test_a_delivery_outside_the_window_is_stale(store):
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW - timedelta(days=4), alert_id=1)

    health = store.read(now=NOW)

    assert health.state == HEALTH_STALE
    assert health.alive is False
    assert health.last_success_at == NOW - timedelta(days=4)
    assert health.streak == 0
    assert "outside the" in health.summary
    # Never a verdict of "broken": a long quiet period looks the same as a
    # stopped transport, and the words say so.
    assert "Either nothing has fired, or delivery has stopped" in health.summary


def test_the_window_is_the_callers_number_not_a_constant(store):
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW - timedelta(days=4), alert_id=1)

    monthly = store.read(now=NOW, window=timedelta(days=35))

    assert monthly.state == HEALTH_HEALTHY
    assert monthly.window == timedelta(days=35)
    # The default is the daily-cadence one, and it calls the same row stale.
    assert store.read(now=NOW).state == HEALTH_STALE


def test_a_failed_attempt_is_failing_and_carries_its_reason(store):
    store.record(
        outcome=ATTEMPT_FAILED,
        at=NOW - timedelta(minutes=5),
        alert_id=1,
        fire_key="alert:1:2026-10-27",
        error="attempt 3 of 3 failed: 535 authentication failed",
    )

    health = store.read(now=NOW)

    assert health.state == HEALTH_FAILING
    assert health.alive is False
    assert health.streak == 1
    assert health.last_failure_at == NOW - timedelta(minutes=5)
    assert "535 authentication failed" in health.last_error
    assert "Delivery is failing" in health.summary
    assert "1 consecutive send attempt failed" in health.summary


def test_failing_wins_over_stale_because_a_failure_is_a_fact(store):
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW - timedelta(days=5), alert_id=1)
    store.record(outcome=ATTEMPT_FAILED, at=NOW - timedelta(days=1), error="timed out")

    health = store.read(now=NOW)

    assert health.state == HEALTH_FAILING
    assert health.last_success_at == NOW - timedelta(days=5)


def test_the_streak_counts_consecutive_failures_and_a_success_resets_it(store):
    store.record(outcome=ATTEMPT_FAILED, at=NOW - timedelta(hours=3), error="one")
    store.record(outcome=ATTEMPT_FAILED, at=NOW - timedelta(hours=2), error="two")
    store.record(outcome=ATTEMPT_FAILED, at=NOW - timedelta(hours=1), error="three")

    assert store.read(now=NOW).streak == 3

    store.record(outcome=ATTEMPT_DELIVERED, at=NOW, alert_id=1)

    health = store.read(now=NOW)
    assert health.streak == 0
    assert health.state == HEALTH_HEALTHY
    # The last *failure's* reason stays as history; the state is the verdict.
    assert health.last_error == "three"
    assert health.last_failure_at == NOW - timedelta(hours=1)


def test_a_suppression_is_recorded_and_does_not_break_a_failing_streak(store):
    store.record(outcome=ATTEMPT_FAILED, at=NOW - timedelta(hours=2), error="relay down")
    store.record(outcome=ATTEMPT_SUPPRESSED, at=NOW - timedelta(hours=1), alert_id=2)

    health = store.read(now=NOW)

    # A suppression never reached a server, so it neither proves delivery works
    # nor hides the failure behind it.
    assert health.streak == 1
    assert health.state == HEALTH_FAILING
    assert [attempt.outcome for attempt in health.attempts] == [
        ATTEMPT_SUPPRESSED,
        ATTEMPT_FAILED,
    ]


def test_a_suppression_alone_is_never_sent(store):
    store.record(outcome=ATTEMPT_SUPPRESSED, at=NOW, alert_id=1, fire_key="alert:1:x")

    health = store.read(now=NOW)

    assert health.state == HEALTH_NEVER_SENT
    assert health.alive is False
    assert health.streak == 0
    assert len(health.attempts) == 1


def test_every_attempt_keeps_its_timestamp_and_identity_newest_first(store):
    store.record(
        outcome=ATTEMPT_DELIVERED,
        at=NOW - timedelta(hours=2),
        alert_id=7,
        fire_key="alert:7:2026-10-26",
        recipients=3,
    )
    store.record(
        outcome=ATTEMPT_FAILED,
        at=NOW - timedelta(hours=1),
        alert_id=8,
        fire_key="alert:8:2026-10-27",
        error="connection refused",
    )

    attempts = store.read(now=NOW).attempts

    assert [attempt.at for attempt in attempts] == [
        NOW - timedelta(hours=1),
        NOW - timedelta(hours=2),
    ]
    assert [attempt.outcome for attempt in attempts] == [ATTEMPT_FAILED, ATTEMPT_DELIVERED]
    assert attempts[1].alert_id == 7
    assert attempts[1].fire_key == "alert:7:2026-10-26"
    assert attempts[1].recipients == 3
    assert attempts[0].error == "connection refused"


def test_an_unknown_outcome_is_refused(store):
    with pytest.raises(ValueError, match="Unknown delivery outcome"):
        store.record(outcome="maybe", at=NOW)


# --- the reason cannot carry a credential --------------------------------


def test_the_stored_reason_is_redacted_in_plain_and_encoded_form(store):
    encoded = _auth_plain(SECRET, SMTP_USER)
    reason = f"535 authentication failed: AUTH PLAIN {encoded} (password {SECRET})"

    store.record(outcome=ATTEMPT_FAILED, at=NOW, error=reason, sender=_sender())

    health = store.read(now=NOW)
    stored = sqlite3.connect(store.path).execute(
        "SELECT error FROM delivery_attempts"
    ).fetchone()[0]

    for text in (health.last_error, stored):
        assert SECRET not in text
        assert encoded not in text
        assert "[redacted]" in text
        # The rest of the provider's reply is kept: it is what an operator acts on.
        assert "535 authentication failed" in text


def test_the_health_read_needs_no_encryption_key(path):
    """The attempt log and the identity sit beside the ciphertext, not behind it."""
    key = generate_key()
    settings = replace(
        load_settings(),
        settings_path=path,
        secret_key=key,
        smtp_host=None,
        smtp_user=None,
        smtp_password=None,
    )
    MailSettingsStore(path).save(
        {
            "smtp_host": "mail.example.com",
            "smtp_port": "587",
            "smtp_user": SMTP_USER,
            "smtp_password": SECRET,
            "smtp_from": SMTP_USER,
        },
        updated_by="owner",
        key=key,
    )
    DeliveryHealthStore(path).record(outcome=ATTEMPT_FAILED, at=NOW, error="boom")

    # No key in hand, and no key needed: an operator with sqlite3 can see this.
    without_key = replace(settings, secret_key=None)
    health = delivery_health(without_key.settings_path, now=NOW)

    assert health.state == HEALTH_FAILING
    assert health.last_error == "boom"


# --- the module-level read API the pages call -----------------------------


def test_delivery_health_is_a_function_of_a_path_and_a_window(path):
    DeliveryHealthStore(path).record(outcome=ATTEMPT_DELIVERED, at=NOW, alert_id=1)

    health = delivery_health(path, now=NOW)

    assert health.state == HEALTH_HEALTHY
    assert health.alive is True
    assert health.window == DEFAULT_ALIVE_WINDOW
    # A path works as well as a Path, because settings hand out Path objects and
    # a page may hold a string.
    assert delivery_health(str(path), now=NOW).state == HEALTH_HEALTHY


def test_a_naive_now_is_read_as_utc(store):
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW, alert_id=1)

    health = store.read(now=datetime(2026, 10, 28, 9, 10))

    assert health.state == HEALTH_HEALTHY
    assert health.checked_at == NOW


def test_a_zero_window_falls_back_to_the_default(store):
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW, alert_id=1)

    health = store.read(now=NOW, window=timedelta(0))

    assert health.window == DEFAULT_ALIVE_WINDOW
    assert health.state == HEALTH_HEALTHY


# --- one question, one definition (issue #30) -----------------------------


def test_an_alert_id_limits_the_answer_to_that_definitions_attempts(store):
    """The instance is failing while the definition that delivered is healthy."""
    delivered = NOW - timedelta(hours=1)
    store.record(outcome=ATTEMPT_DELIVERED, at=delivered, alert_id=99)
    store.record(outcome=ATTEMPT_FAILED, at=NOW, alert_id=7, error="relay down")

    instance = store.read(now=NOW)
    assert instance.state == HEALTH_FAILING
    assert instance.streak == 1

    healthy = store.read(now=NOW, alert_id=99)
    assert healthy.state == HEALTH_HEALTHY
    assert healthy.last_success_at == delivered
    assert healthy.last_failure_at is None
    assert healthy.streak == 0
    assert [attempt.alert_id for attempt in healthy.attempts] == [99]

    failing = store.read(now=NOW, alert_id=7)
    assert failing.state == HEALTH_FAILING
    assert failing.streak == 1
    assert failing.last_error == "relay down"
    assert failing.last_success_at is None


def test_a_definition_with_no_attempts_of_its_own_is_never_sent(store):
    """Another definition's delivery proves nothing about this one."""
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW - timedelta(minutes=1), alert_id=1)

    health = store.read(now=NOW, alert_id=2)

    assert health.state == HEALTH_NEVER_SENT
    assert health.alive is False
    assert health.attempts == ()
    assert health.last_success_at is None
    # The instance-wide question still sees the delivery.
    assert store.read(now=NOW).state == HEALTH_HEALTHY


def test_an_attempt_with_no_definition_belongs_to_the_instance_only(store):
    """A row the worker recorded without a definition is not any definition's."""
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW)

    assert store.read(now=NOW).state == HEALTH_HEALTHY
    assert store.read(now=NOW, alert_id=5).state == HEALTH_NEVER_SENT


def test_a_streak_is_counted_per_definition(store):
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW - timedelta(hours=3), alert_id=7)
    store.record(outcome=ATTEMPT_FAILED, at=NOW - timedelta(hours=2), alert_id=8, error="a")
    store.record(outcome=ATTEMPT_FAILED, at=NOW - timedelta(hours=1), alert_id=8, error="b")

    assert store.read(now=NOW, alert_id=7).streak == 0
    assert store.read(now=NOW, alert_id=7).state == HEALTH_HEALTHY
    assert store.read(now=NOW, alert_id=8).streak == 2
    assert store.read(now=NOW, alert_id=8).state == HEALTH_FAILING


def test_the_alert_id_is_a_bound_parameter(store):
    """A definition id is data: the statement that reads it is not built from it."""
    store.record(outcome=ATTEMPT_DELIVERED, at=NOW, alert_id=1)

    # An id that is not a number is refused by the conversion, not by SQL.
    with pytest.raises(ValueError):
        store.read(now=NOW, alert_id="1 OR 1=1")


def test_the_module_read_takes_the_same_filter(path):
    DeliveryHealthStore(path).record(outcome=ATTEMPT_DELIVERED, at=NOW, alert_id=3)

    assert delivery_health(path, now=NOW).state == HEALTH_HEALTHY
    assert delivery_health(path, alert_id=3, now=NOW).state == HEALTH_HEALTHY
    assert delivery_health(path, alert_id=4, now=NOW).state == HEALTH_NEVER_SENT


def test_presence_is_a_question_that_writes_nothing(path):
    store = DeliveryHealthStore(path)
    assert store.has_log() is False
    assert not path.exists()

    store.record(outcome=ATTEMPT_DELIVERED, at=NOW, alert_id=1)

    assert store.has_log() is True
    # The empty-file case: present, unreadable as a log, and still nothing's
    # proof. This is the state a page must render as unavailable.
    blank = path.parent / "blank.db"
    blank.write_bytes(b"")
    assert DeliveryHealthStore(blank).has_log() is False
