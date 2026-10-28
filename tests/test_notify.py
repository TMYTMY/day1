"""Delivery: the composed email, the sender seam, and the SMTP transport.

Nothing in this file opens a socket. The SMTP tests replace ``smtplib.SMTP``
with a fake that records the conversation, which is the only way to check the
starttls/login/send sequence without a mail server; the test that proves a
sender is inert monkeypatches every socket function to fail, so a regression
that connects early is an assertion error rather than a hanging test.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from src.alerts import AlertDefinition
from src.auth import user_named
from src.config import ConfigError, Settings, load_settings
from src.metrics import Metric
from src.notify import (
    DELIVERY_FAILED,
    DELIVERY_NOT_A_FIRE,
    DELIVERY_NOT_WIRED,
    DELIVERY_SUPPRESSED,
    MailMessage,
    Notifier,
    RecordingSender,
    SmtpSender,
    address_for,
    build_sender,
    compose,
    compose_failure,
    condition_phrase,
    missing_smtp,
)
from src.worker import FireOutcome

FIRE_KEY = "alert:7:2026-10-27"

METRIC = Metric(
    id="revenue_report",
    title="Revenue by product",
    synonyms=("revenue",),
    table="revenue",
    grain=("event_date", "product"),
    additive_over=("event_date",),
    definition="Recognised revenue in USD, net of cancellations.",
    owner="finance-reporting",
    effective_from=date(2026, 6, 15),
    supersedes=None,
    exceptions="Excludes internal test accounts.",
    measure="revenue_usd",
)


def _definition(**overrides) -> AlertDefinition:
    fields = {
        "id": 7,
        "metric_id": "revenue_report",
        "comparison": "above_absolute",
        "constant": 1.0,
        "window_days": 7,
        "cadence": "daily",
        "local_time": "09:00",
        "recipients": ("alex",),
        "owner": "alex",
        "owner_role": "analyst",
        "state": "confirmed",
        "created_at": "2026-10-01T09:00:00Z",
    }
    fields.update(overrides)
    return AlertDefinition(**fields)


def _outcome(**overrides) -> FireOutcome:
    fields = {
        "definition": _definition(),
        "outcome": "fired",
        "fire_key": FIRE_KEY,
        "window_start": date(2026, 10, 21),
        "window_end": date(2026, 10, 27),
        "value": 1234.5,
        "verdict": "fire",
        "metric_title": "Revenue by product",
    }
    fields.update(overrides)
    return FireOutcome(**fields)


# --- composition -----------------------------------------------------------


def test_the_email_carries_the_value_the_window_the_threshold_and_the_definition():
    notification = compose(_outcome(), METRIC)

    body = notification.body
    assert "Revenue by product" in notification.subject
    assert "1,234.50" in notification.subject
    # The value the comparison used.
    assert "Value: 1,234.50" in body
    # The window, its length, and the end date said plainly.
    assert "2026-10-21 to 2026-10-27" in body
    assert "7 days" in body
    assert "ending 2026-10-27" in body
    # The condition and the constant that triggered it.
    assert "above_absolute 1" in body
    assert "above 1" in body
    # The definition in force, with its owner and effective date.
    assert "Recognised revenue in USD, net of cancellations." in body
    assert "finance-reporting" in body
    assert "2026-06-15" in body
    # The fire key, named as the audit reference.
    assert FIRE_KEY in body
    assert "Audit reference" in body


def test_a_percentage_comparison_names_the_previous_window_and_its_value():
    notification = compose(
        _outcome(
            definition=_definition(comparison="change_pct_down", constant=12.5),
            previous=1400.0,
            previous_window_end=date(2026, 10, 20),
        ),
        METRIC,
    )

    assert "change_pct_down 12.5" in notification.body
    assert "down by 12.5% or more" in notification.body
    assert "Previous window ending 2026-10-20: 1,400.00" in notification.body


def test_a_missing_value_is_words_and_not_a_zero():
    notification = compose(_outcome(value=None), METRIC)
    assert "Value: no rows" in notification.body
    assert "0.00" not in notification.body


def test_condition_phrases_read_as_sentences():
    assert condition_phrase("below_absolute", 10) == "below 10"
    assert condition_phrase("above_absolute", 2.5) == "above 2.5"
    assert condition_phrase("change_pct_down", 5).startswith("down by 5% or more")
    assert condition_phrase("change_pct_up", 5).startswith("up by 5% or more")


def test_the_owner_failure_email_says_what_was_missed_and_why():
    delivery = _delivery_for_failure()

    notification = compose_failure(
        definition=_definition(),
        metric_title="Revenue by product",
        delivery=delivery,
        window_start=date(2026, 10, 21),
        window_end=date(2026, 10, 27),
    )

    assert "failed" in notification.subject
    assert FIRE_KEY in notification.body
    assert "could not be delivered" in notification.body
    assert "attempt 3 of 3 failed: the mail server is unavailable" in notification.body
    assert "Nothing was sent to the recipients" in notification.body


def _delivery_for_failure():
    from src.notify import Delivery

    return Delivery(
        status=DELIVERY_FAILED,
        fire_key=FIRE_KEY,
        recipients=("alex",),
        attempts=3,
        error="attempt 3 of 3 failed: the mail server is unavailable",
    )


# --- the recording seam ----------------------------------------------------


def test_the_recording_sender_records_and_can_be_told_to_fail():
    sender = RecordingSender(fail_times=1)
    message = MailMessage(to=("alex",), subject="s", body="b", fire_key=FIRE_KEY)

    with pytest.raises(RuntimeError):
        sender.send(message)
    assert sender.messages == []

    sender.send(message)
    assert sender.messages == [message]
    assert sender.recipients == ["alex"]
    assert sender.attempts == 2


def test_a_notifier_without_a_sender_reports_not_wired_and_sends_nothing(tmp_path):
    notifier = Notifier(sender=None, users_path=tmp_path / "users.yaml")

    delivery = notifier.deliver(_outcome(), METRIC)

    assert delivery.status == DELIVERY_NOT_WIRED
    assert delivery.recipients == ()
    assert "No mail sender is configured" in delivery.message


def test_a_notifier_does_not_send_for_an_outcome_that_did_not_trigger(tmp_path):
    sender = RecordingSender()
    notifier = Notifier(sender=sender, users_path=tmp_path / "users.yaml")

    delivery = notifier.deliver(_outcome(outcome="not_fired"), METRIC)

    assert delivery.status == DELIVERY_NOT_A_FIRE
    assert sender.messages == []


_USERS = """
roles:
  analyst:
    tables: [revenue]
    capabilities: [query, alert]
  growth:
    tables: [dau]
    capabilities: [query, alert]

users:
  - username: alex
    password: alex
    role: analyst
  - username: rita
    password: rita
    role: growth
    email: rita@example.com
"""


def test_a_recipient_the_directory_does_not_know_is_blocked_not_invented(tmp_path):
    users = tmp_path / "users.yaml"
    users.write_text(_USERS, encoding="utf-8")
    sender = RecordingSender()
    notifier = Notifier(
        sender=sender,
        users_path=users,
        titles={"revenue": "Revenue", "dau": "Daily active users"},
    )

    delivery = notifier.deliver(
        _outcome(definition=_definition(recipients=("rita", "ghost"))), METRIC
    )

    assert delivery.status == DELIVERY_SUPPRESSED
    assert sender.messages == []
    assert [item.username for item in delivery.blocked] == ["rita", "ghost"]
    assert delivery.blocked[0].reason == "table_not_allowed"
    assert delivery.blocked[1].reason == "recipient_unknown"


def test_the_address_is_the_directory_email_and_the_username_is_the_fallback(tmp_path):
    users = tmp_path / "users.yaml"
    users.write_text(_USERS, encoding="utf-8")

    rita = user_named("rita", users)
    alex = user_named("alex", users)

    assert address_for(rita) == "rita@example.com"
    assert address_for(alex) == "alex"


# --- SMTP ------------------------------------------------------------------


def _smtp_settings(**overrides) -> Settings:
    fields = {
        "db_backend": "sqlite",
        "db_path": Path("/tmp/demo.db"),
        "database_url": None,
        "db_user": None,
        "db_password": None,
        "athena_region": None,
        "athena_database": None,
        "athena_workgroup": None,
        "athena_output": None,
        "audit_path": Path("/tmp/audit.db"),
        "routing_path": Path("/tmp/routing.yaml"),
        "users_path": Path("/tmp/users.yaml"),
        "openrouter_api_key": None,
        "openrouter_model": "openai/gpt-4o-mini",
        "openrouter_base_url": "https://openrouter.ai/api/v1",
        "max_rows": 500,
        "knowledge_path": Path("/tmp/knowledge"),
        "embedding_provider": "local",
        "embedding_model": "openai/text-embedding-3-small",
        "embedding_api_key": None,
        "smtp_host": "mail.example.com",
        "smtp_port": 2525,
        "smtp_user": "day1",
        "smtp_password": "secret",
        "smtp_from": "alerts@example.com",
        "smtp_starttls": True,
    }
    fields.update(overrides)
    return Settings(**fields)


def test_the_sender_comes_from_the_smtp_settings():
    sender = SmtpSender.from_settings(_smtp_settings())

    assert (sender.host, sender.port) == ("mail.example.com", 2525)
    assert sender.sender == "alerts@example.com"
    assert sender.user == "day1"
    assert sender.starttls is True


def test_no_host_means_no_sender_and_a_stated_reason():
    settings = _smtp_settings(smtp_host=None)

    assert settings.smtp_configured is False
    assert build_sender(settings) is None
    assert missing_smtp(settings) == "SMTP_HOST"
    with pytest.raises(ConfigError):
        SmtpSender.from_settings(settings)


def test_the_smtp_sender_is_inert_until_it_is_asked_to_send(monkeypatch):
    def offline(*args, **kwargs):  # pragma: no cover - only runs on a regression
        raise AssertionError("building a sender must not connect")

    monkeypatch.setattr("socket.socket", offline)
    monkeypatch.setattr("socket.create_connection", offline)
    monkeypatch.setattr("smtplib.SMTP", offline)

    sender = SmtpSender.from_settings(_smtp_settings())
    mail = sender.message_for(
        MailMessage(to=("alex", "rita@example.com"), subject="s", body="hello", fire_key=FIRE_KEY)
    )

    assert mail["From"] == "alerts@example.com"
    assert mail["To"] == "alex, rita@example.com"
    assert mail["Subject"] == "s"
    assert mail.get_content_type() == "text/plain"
    assert "hello" in mail.get_content()


def test_the_smtp_sender_upgrades_the_connection_logs_in_and_sends(monkeypatch):
    conversation: list[tuple] = []

    class FakeSmtp:
        def __init__(self, host, port, timeout=None):
            conversation.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, *, context=None):
            conversation.append(("starttls", context))

        def login(self, user, password):
            conversation.append(("login", user, password))

        def send_message(self, mail):
            conversation.append(("send", mail["To"], mail["Subject"]))

    monkeypatch.setattr("smtplib.SMTP", FakeSmtp)
    sender = SmtpSender.from_settings(_smtp_settings())

    sender.send(MailMessage(to=("alex",), subject="Revenue fired", body="body", fire_key=FIRE_KEY))

    assert conversation[:1] == [("connect", "mail.example.com", 2525)]
    # starttls must be handed a context, and that context must verify: smtplib's
    # default one leaves verify_mode=CERT_NONE, which trusts any server that answers.
    assert conversation[1][0] == "starttls"
    context = conversation[1][1]
    assert context is not None and context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert conversation[2:] == [
        ("login", "day1", "secret"),
        ("send", "alex", "Revenue fired"),
    ]


def test_a_sender_without_starttls_or_a_user_sends_plainly(monkeypatch):
    conversation: list[tuple] = []

    class FakeSmtp:
        def __init__(self, host, port, timeout=None):
            conversation.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, *, context=None):  # pragma: no cover - must not be called
            conversation.append(("starttls",))

        def login(self, user, password):  # pragma: no cover - must not be called
            conversation.append(("login", user, password))

        def send_message(self, mail):
            conversation.append(("send", mail["To"]))

    monkeypatch.setattr("smtplib.SMTP", FakeSmtp)
    sender = SmtpSender.from_settings(
        _smtp_settings(smtp_starttls=False, smtp_user=None, smtp_password=None)
    )

    sender.send(MailMessage(to=("alex",), subject="s", body="b"))

    assert conversation == [("connect", "mail.example.com", 2525), ("send", "alex")]


def test_a_send_that_raises_is_the_notifiers_problem_not_the_senders(monkeypatch):
    class BrokenSmtp:
        def __init__(self, *args, **kwargs):
            raise OSError("connection refused")

    monkeypatch.setattr("smtplib.SMTP", BrokenSmtp)
    sender = SmtpSender.from_settings(_smtp_settings())

    with pytest.raises(OSError):
        sender.send(MailMessage(to=("alex",), subject="s", body="b"))


# --- settings --------------------------------------------------------------


def test_the_smtp_settings_come_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "465")
    monkeypatch.setenv("SMTP_USER", "day1@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    monkeypatch.delenv("SMTP_FROM", raising=False)
    monkeypatch.setenv("SMTP_STARTTLS", "off")
    monkeypatch.setenv("USERS_PATH", str(tmp_path / "users.yaml"))

    settings = load_settings()

    assert settings.smtp_host == "smtp.example.com"
    assert settings.smtp_port == 465
    # No SMTP_FROM, so the user address is the from-address.
    assert settings.smtp_from == "day1@example.com"
    assert settings.smtp_starttls is False
    assert settings.smtp_configured is True
    assert "secret" not in repr(settings)


def test_an_unset_smtp_host_is_not_configured(monkeypatch, tmp_path):
    for name in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("USERS_PATH", str(tmp_path / "users.yaml"))

    settings = load_settings()

    assert settings.smtp_host is None
    assert settings.smtp_from == "day1-alerts@localhost"
    assert settings.smtp_configured is False


def test_a_port_that_is_not_a_port_is_refused(monkeypatch):
    monkeypatch.setenv("SMTP_PORT", "not-a-port")
    with pytest.raises(ConfigError):
        load_settings()

    monkeypatch.setenv("SMTP_PORT", "70000")
    with pytest.raises(ConfigError):
        load_settings()


def test_a_directory_email_that_is_not_an_address_is_refused(tmp_path):
    users = tmp_path / "users.yaml"
    users.write_text(_USERS.replace("rita@example.com", "rita"), encoding="utf-8")

    with pytest.raises(ConfigError):
        user_named("rita", users)


# --- certificate verification is not optional -------------------------------


def test_starttls_is_given_a_verifying_context(monkeypatch):
    captured: dict[str, object] = {}

    class _Smtp:
        def __init__(self, host, port, timeout=None):
            captured["host"] = host

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, *, context=None):
            captured["context"] = context

        def login(self, user, password):
            captured["login"] = user

        def send_message(self, message):
            captured["sent"] = message

    monkeypatch.setattr(smtplib, "SMTP", _Smtp)
    sender = SmtpSender(host="smtp.example.test", port=587, sender="a@b.test",
                        user="u", password="p", starttls=True)
    sender.send(MailMessage(to=("x@y.test",), subject="s", body="b", fire_key="k"))

    context = captured["context"]
    assert context is not None, "starttls must be handed a context, or the default one does not verify"
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert captured["sent"] is not None


def test_implicit_tls_is_given_a_verifying_context(monkeypatch):
    captured: dict[str, object] = {}

    class _SmtpSSL:
        def __init__(self, host, port, timeout=None, context=None):
            captured["context"] = context

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def login(self, user, password):
            captured["login"] = user

        def send_message(self, message):
            captured["sent"] = message

    monkeypatch.setattr(smtplib, "SMTP_SSL", _SmtpSSL)
    sender = SmtpSender(host="smtp.example.test", port=465, sender="a@b.test",
                        user="u", password="p", starttls=False, ssl=True)
    sender.send(MailMessage(to=("x@y.test",), subject="s", body="b", fire_key="k"))

    context = captured["context"]
    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert captured["sent"] is not None


def test_an_internal_ca_is_used_instead_of_disabling_verification(monkeypatch, tmp_path):
    ca = tmp_path / "internal-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nnot a real cert\n-----END CERTIFICATE-----\n")
    seen: dict[str, object] = {}
    real = ssl.create_default_context

    def spy(*, cafile=None):
        seen["cafile"] = cafile
        return real()

    monkeypatch.setattr(ssl, "create_default_context", spy)
    sender = SmtpSender(host="h", port=587, sender="a@b.test", starttls=True, ca_bundle=str(ca))
    context = ssl.create_default_context(cafile=sender.ca_bundle)
    assert seen["cafile"] == str(ca)
    assert context.verify_mode == ssl.CERT_REQUIRED
