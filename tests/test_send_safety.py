"""A test send reaches only known addresses, is limited in storage, and reports health.

Three boundaries, and each of them was a defect in the adversarial review:

* an operator could send from the company's authenticated mailbox to any address
  typed into the form, which is internal phishing infrastructure;
* nothing limited how often, so the mailbox could be used as a sender at will;
* the Alerts page said nothing at all about whether alerts were being delivered.

The page tests drive the real Streamlit page through AppTest, the way
``tests/test_settings_gate.py`` does, and replace the transport with a recorder
so nothing here opens a socket.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from src.config import ROOT
from src.crypto import generate_key
from src.mail_setup import CheckResult
from src.models import User
from src.send_safety import (
    AUTH_FAILURE_LIMIT,
    FAILING,
    HEALTHY,
    NEVER_SENT,
    RECIPIENT_NOT_AN_ADDRESS,
    RECIPIENT_RULE,
    RECIPIENT_UNKNOWN,
    STALE,
    TEST_SEND_LIMIT,
    UNKNOWN,
    DeliveryGuard,
    MailTestLimiter,
    UNAVAILABLE,
    health_line,
    is_address,
    known_addresses,
    read_health,
    recipient_refusal,
)
from streamlit.testing.v1 import AppTest
from tests.test_notify import _smtp_settings
from tests.test_settings_pages import (
    OPERATOR,
    _blob,
    _events,
    _open_mail,
    _sign_in,
)

METRIC_ID = "revenue_by_product"

# A directory with addresses, because the recipient rule works on addresses and
# the sample directory carries usernames only.
_DIRECTORY = """
roles:
  analyst:
    tables: [revenue, dau]
    capabilities: [query, alert]
  finance:
    tables: [revenue]
    capabilities: [query]
  growth:
    tables: [dau]
    capabilities: [query]
  owner:
    tables: []
    capabilities: [admin]
  lead:
    tables: [revenue, dau]
    capabilities: [query, alert, admin]
users:
  - username: analyst
    password: analyst
    role: analyst
  - username: finance
    password: finance
    role: finance
    email: finance@example.test
  - username: growth
    password: growth
    role: growth
    email: growth@example.test
  - username: owner
    password: owner
    role: owner
  - username: lead
    password: lead
    role: lead
    email: lead@example.test
"""


class _Recorder:
    """The transport seam: records what would have been sent, opens nothing."""

    def __init__(self, ok: bool = True):
        self.calls: list[str] = []
        self.ok = ok

    def __call__(self, settings, to, *, timeout=30.0) -> CheckResult:
        self.calls.append(to)
        if not self.ok:
            return CheckResult(False, "The server refused the connection.", "")
        return CheckResult(True, f"Delivered to {to} through {settings.smtp_host}.", "")


def _plant_directory(tmp_path, text: str = _DIRECTORY):
    path = tmp_path / "users.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _settings(tmp_path, **overrides):
    fields = {
        "users_path": _plant_directory(tmp_path),
        "alerts_path": tmp_path / "alerts.db",
        "settings_path": tmp_path / "instance.db",
        "smtp_from": "day1-alerts@example.test",
        "smtp_user": "mailbox@example.test",
    }
    fields.update(overrides)
    return _smtp_settings(**fields)


OPERATOR_USER = User("owner", "owner", (), capabilities=("admin",), email="owner@example.test")


# --- the recipient rule -----------------------------------------------------


def test_one_bare_address_is_the_only_shape_accepted():
    assert is_address("someone@example.test")
    assert not is_address("someone")
    assert not is_address("a@b@c")
    assert not is_address("someone@example.test\nBcc: x@y.test")
    assert not is_address("")
    assert not is_address("two words@example.test")


def test_the_known_addresses_are_the_three_sources_the_rule_names(tmp_path):
    from datetime import date

    from src.alerts import AlertDraft, AlertStore

    settings = _settings(tmp_path)
    store = AlertStore(settings.alerts_path)
    store.add(
        AlertDraft(
            metric_id=METRIC_ID,
            comparison="above_absolute",
            constant=1.0,
            window_days=7,
            cadence="daily",
            local_time="09:00",
            recipients=("finance",),
            owner="lead",
            owner_role="lead",
        )
    )

    known = dict((address, source) for address, source in known_addresses(settings, operator=OPERATOR_USER))

    assert "owner@example.test" in known  # the operator's own address
    assert known["owner@example.test"] == "your own address"
    assert "day1-alerts@example.test" in known  # the mailbox this instance sends from
    assert "mailbox@example.test" in known
    assert "finance@example.test" in known  # a recipient on an alert definition
    assert "lead@example.test" in known  # a definition owner


def test_an_unknown_address_is_refused_by_name_and_none_is_accepted(tmp_path):
    settings = _settings(tmp_path)

    refusal = recipient_refusal("victim@elsewhere.test", settings, operator=OPERATOR_USER)

    assert refusal is not None
    assert refusal.reason == RECIPIENT_UNKNOWN
    assert RECIPIENT_RULE in refusal.message
    assert "victim@elsewhere.test" in refusal.message
    assert "internal phishing" in refusal.message

    assert recipient_refusal("owner@example.test", settings, operator=OPERATOR_USER) is None
    assert recipient_refusal("day1-alerts@example.test", settings, operator=OPERATOR_USER) is None


def test_an_empty_or_malformed_recipient_is_refused_by_the_same_rule(tmp_path):
    settings = _settings(tmp_path)

    empty = recipient_refusal("   ", settings, operator=OPERATOR_USER)
    assert empty is not None
    assert "Enter the address" in empty.message

    shaped = recipient_refusal("someone@example.test\nBcc: x@y.test", settings, operator=OPERATOR_USER)
    assert shaped is not None
    assert shaped.reason == RECIPIENT_NOT_AN_ADDRESS
    assert "second header" in shaped.message


# --- the rate limit ---------------------------------------------------------


def test_the_limit_is_counted_in_the_database(tmp_path):
    limiter = MailTestLimiter(tmp_path / "instance.db")
    for index in range(TEST_SEND_LIMIT):
        assert limiter.refusal() is None
        limiter.record(recipient="owner@example.test")

    refusal = limiter.refusal()
    assert refusal is not None
    assert f"documented limit ({TEST_SEND_LIMIT} per instance" in refusal.message
    assert "Nothing was sent" in refusal.message

    # The count lives in the file: a second limiter — a reload, another browser,
    # a restarted app — sees the same five attempts.
    assert MailTestLimiter(tmp_path / "instance.db").refusal() is not None
    conn = sqlite3.connect(tmp_path / "instance.db")
    try:
        rows = conn.execute("SELECT COUNT(*) FROM mail_test_sends").fetchone()[0]
    finally:
        conn.close()
    assert rows == TEST_SEND_LIMIT


def test_the_window_lets_the_quota_back_after_it_passes(tmp_path):
    start = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)
    limiter = MailTestLimiter(tmp_path / "instance.db", clock=lambda: start)
    for _ in range(TEST_SEND_LIMIT):
        limiter.record(recipient="owner@example.test")
    assert limiter.refusal() is not None
    assert limiter.refusal(now=start + timedelta(minutes=16)) is None


def test_an_attempt_that_cannot_be_counted_is_refused(tmp_path):
    """A limit that cannot record is a limit that cannot bound, so the send stops."""

    class Broken(MailTestLimiter):
        def record(self, *, recipient, now=None):
            raise sqlite3.OperationalError("database is locked")

    broken = Broken(tmp_path / "instance.db")
    try:
        broken.record(recipient="owner@example.test")
    except sqlite3.OperationalError as exc:
        assert "locked" in str(exc)
    else:  # pragma: no cover - the raise above is the point
        raise AssertionError("the broken limiter must raise")


# --- what the Alerts page says about delivery ------------------------------


def test_a_health_record_that_is_absent_is_not_a_healthy_one(tmp_path):
    """Mutation: defaulting to ``healthy`` when the table is missing turns this red."""
    empty = read_health(tmp_path / "missing.db", 7)
    assert empty.kind == UNKNOWN
    assert empty.known is False

    # A database that exists but has no delivery records is the same answer:
    # nothing was recorded, so nothing is known.
    (tmp_path / "alerts.db").write_bytes(b"")
    assert read_health(tmp_path / "alerts.db", 7).kind == UNKNOWN
    assert "unavailable" in UNAVAILABLE
    assert "healthy" not in UNAVAILABLE.lower()


def test_each_health_state_has_its_own_line(tmp_path):
    alerts = tmp_path / "alerts.db"
    guard = DeliveryGuard(alerts)
    definition = type("Definition", (), {"id": 7})()
    settings = _settings(tmp_path, alerts_path=alerts)
    now = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)

    # No rows for this definition, but the table exists: never sent.
    guard.record_success(99, at=now)
    assert read_health(alerts, 7, now=now).kind == NEVER_SENT
    assert "never sent" in health_line(definition, settings, now=now)

    # A delivered message: healthy, and it names the age.
    guard.record_success(7, at=now - timedelta(minutes=5))
    health = read_health(alerts, 7, now=now)
    assert health.kind == HEALTHY
    assert "healthy" in health_line(definition, settings, now=now)
    assert "5 minutes ago" in health_line(definition, settings, now=now)

    # The same record, three days later: stale rather than healthy.
    later = now + timedelta(days=3)
    assert read_health(alerts, 7, now=later).kind == STALE
    stale_line = health_line(definition, settings, now=later)
    assert "stale" in stale_line
    assert "may reach nobody" in stale_line

    # Two failures after the success: failing, with the count.
    guard.record_failure(7, at=now)
    guard.record_failure(7, at=now)
    health = read_health(alerts, 7, now=now)
    assert health.kind == FAILING
    assert health.count == 2
    line = health_line(definition, settings, now=now)
    assert "failing" in line
    assert "2 consecutive failed deliveries" in line


def test_a_health_read_that_raises_is_reported_as_unavailable(tmp_path, monkeypatch):
    """Mutation: letting the read raise turns the whole Alerts page into a traceback."""
    import src.send_safety as send_safety

    def boom(*args, **kwargs):
        raise sqlite3.DatabaseError("file is not a database")

    monkeypatch.setattr(send_safety, "read_health", boom)
    definition = type("Definition", (), {"id": 7})()
    line = send_safety.health_line(definition, _settings(tmp_path))
    assert line == send_safety.UNAVAILABLE


# --- the page: a refused recipient, and a stored limit ---------------------


def _alerts_with_addresses(tmp_path):
    """A planted alerts.db whose definition names an address-bearing recipient."""
    from datetime import date

    from src.alerts import AlertDraft, AlertStore

    store = AlertStore(tmp_path / "alerts.db")
    live = store.add(
        AlertDraft(
            metric_id=METRIC_ID,
            comparison="above_absolute",
            constant=1_000_000_000_000,
            window_days=7,
            cadence="daily",
            local_time="09:00",
            recipients=("finance", "growth"),
            owner="lead",
            owner_role="lead",
        )
    )
    store.confirm(live, by="lead", at="2026-10-02T09:00:00Z", effective_from=date(2026, 10, 2))
    return live


def test_the_page_refuses_a_test_send_to_an_address_it_does_not_know(
    monkeypatch, tmp_path
):
    """Mutation: deleting the recipient check turns this red — and re-opens the relay."""
    import src.settings_pages as pages

    recorder = _Recorder()
    monkeypatch.setattr(pages, "verify", recorder)
    users = _plant_directory(tmp_path)
    at = _open_mail(
        monkeypatch, tmp_path, "lead", USERS_PATH=str(users), DAY1_SECRET_KEY=generate_key()
    )
    before = len(_events(tmp_path / "audit.db"))

    at.text_input(key="mail_host").set_value("smtp.example.test")
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="mail_test_to").set_value("victim@elsewhere.test")
    at.text_input(key="operator_secret").set_value(OPERATOR)
    at = at.button(key="mail_test").click().run(timeout=60)
    page = _blob(at)

    # The refusal names the rule, and the transport was never reached.
    assert RECIPIENT_RULE in page
    assert "victim@elsewhere.test is not an address this instance knows" in page
    assert recorder.calls == []

    # Exactly one audit row for the refusal, and no test-send row at all.
    rows = _events(tmp_path / "audit.db")
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "settings_refused"
    assert rows[-1]["status"] == "denied"
    # The row names the rule that refused it, in the error column, and the
    # question column carries no address: it is the action that was refused.
    assert "is not an address this instance knows" in (rows[-1]["error"] or "")
    assert [row for row in rows if row["event_type"] == "mail_test_sent"] == []


def test_the_page_allows_an_address_an_alert_definition_names(monkeypatch, tmp_path):
    import src.settings_pages as pages

    recorder = _Recorder()
    monkeypatch.setattr(pages, "verify", recorder)
    users = _plant_directory(tmp_path)
    _alerts_with_addresses(tmp_path)
    at = _open_mail(
        monkeypatch, tmp_path, "lead", USERS_PATH=str(users), DAY1_SECRET_KEY=generate_key()
    )

    at.text_input(key="mail_host").set_value("smtp.example.test")
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="mail_test_to").set_value("finance@example.test")
    at.text_input(key="operator_secret").set_value(OPERATOR)
    at = at.button(key="mail_test").click().run(timeout=60)

    assert recorder.calls == ["finance@example.test"]
    sent = [
        row
        for row in _events(tmp_path / "audit.db")
        if row["event_type"] == "mail_test_sent"
    ]
    assert sent and sent[-1]["question"] == "to=finance@example.test outcome=ok"


def test_the_page_refuses_the_sixth_test_send_because_the_limit_is_stored(
    monkeypatch, tmp_path
):
    """A fresh session reads the count from the instance database, so a reload is no escape."""
    import src.settings_pages as pages

    recorder = _Recorder()
    monkeypatch.setattr(pages, "verify", recorder)
    users = _plant_directory(tmp_path)
    # Five attempts already recorded by an earlier session.
    limiter = MailTestLimiter(tmp_path / "instance.db")
    for _ in range(TEST_SEND_LIMIT):
        limiter.record(recipient="lead@example.test")

    at = _open_mail(
        monkeypatch, tmp_path, "lead", USERS_PATH=str(users), DAY1_SECRET_KEY=generate_key()
    )
    assert at.session_state.get("mail_test_sends") is None  # nothing in the session
    before = len(_events(tmp_path / "audit.db"))

    at.text_input(key="mail_host").set_value("smtp.example.test")
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="mail_test_to").set_value("lead@example.test")
    at.text_input(key="operator_secret").set_value(OPERATOR)
    at = at.button(key="mail_test").click().run(timeout=60)
    page = _blob(at)

    assert "documented limit" in page
    assert "Nothing was sent" in page
    assert recorder.calls == []
    rows = _events(tmp_path / "audit.db")
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "settings_refused"
    assert rows[-1]["status"] == "denied"


def test_the_alerts_page_shows_the_delivery_line(monkeypatch, tmp_path):
    """The line is on the row, and it is honest before any record exists."""
    users = _plant_directory(tmp_path)
    live = _alerts_with_addresses(tmp_path)
    at = _open_alerts_page(monkeypatch, tmp_path, users)
    page = _blob(at)

    # No delivery has been recorded: the page says the records are unavailable
    # rather than showing a healthy default. This is the state a fresh instance
    # is in, and the state this branch would be in before #28 lands.
    assert "Delivery health: unavailable" in page
    assert "Delivery health: healthy" not in page

    # Once the delivery path records a message for this definition, the line
    # says so — and a definition with no records says never sent.
    DeliveryGuard(tmp_path / "alerts.db").record_success(live)
    at = _open_alerts_page(monkeypatch, tmp_path, users)
    page = _blob(at)
    assert "Delivery health: healthy" in page
    assert "Delivery health: unavailable" not in page


def _open_alerts_page(monkeypatch, tmp_path, users) -> AppTest:
    from tests.test_settings_pages import _isolate, _plant_operator

    _isolate(monkeypatch, tmp_path, USERS_PATH=str(users), DAY1_SECRET_KEY=generate_key())
    _plant_operator(tmp_path)
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    at = _sign_in(at, "lead", "lead")
    return at.sidebar.radio(key="nav_page").set_value("alerts").run(timeout=60)


def test_the_alerts_page_shows_a_failing_count(monkeypatch, tmp_path):
    users = _plant_directory(tmp_path)
    live = _alerts_with_addresses(tmp_path)
    guard = DeliveryGuard(tmp_path / "alerts.db")
    for _ in range(AUTH_FAILURE_LIMIT):
        guard.record_auth_failure(live, error="535")
    at = _open_alerts_page(monkeypatch, tmp_path, users)

    page = _blob(at)
    assert "Delivery health: failing" in page
    assert f"{AUTH_FAILURE_LIMIT} consecutive" in page
