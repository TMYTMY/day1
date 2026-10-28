"""AppTest for the mail settings page: presets, save, clear, test send, the admin gate."""

from __future__ import annotations

import sqlite3

from src.config import ROOT
from src.crypto import generate_key
from streamlit.testing.v1 import AppTest

SECRET = "day1-mail-secret-9912"

# The secret the host generates with `python -m src.operator_secret --init`.
# Tests plant it the way that command does, then keep the plaintext, which is
# the only copy that exists: only a salted hash is stored.
OPERATOR = "day1-operator-secret-4711"


def _plant_operator(tmp_path) -> str:
    from src.operator_secret import store_secret

    store_secret(tmp_path / "instance.db", OPERATOR)
    return OPERATOR


def _blob(at: AppTest) -> str:
    parts: list[str] = []
    for group_name in ("markdown", "caption", "info", "warning", "error", "success", "text"):
        for element in getattr(at, group_name):
            value = getattr(element, "value", None)
            if isinstance(value, str):
                parts.append(value)
    return "\n".join(parts)


def _isolate(monkeypatch, tmp_path, **extra: str) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    monkeypatch.delenv("SMTP_FROM", raising=False)
    monkeypatch.delenv("DAY1_SECRET_KEY", raising=False)
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("ALERTS_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SETTINGS_PATH", str(tmp_path / "instance.db"))
    monkeypatch.setenv("KNOWLEDGE_PATH", str(tmp_path / "knowledge"))
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")
    # The write surface is off by default; a test that wants the form says so,
    # and the test that wants it off passes "0" in ``extra``.
    monkeypatch.setenv("DAY1_ALLOW_BROWSER_SETTINGS", "1")
    for name, value in extra.items():
        monkeypatch.setenv(name, value)


def _sign_in(at: AppTest, username: str, password: str) -> AppTest:
    at.text_input(key="login_user").set_value(username)
    at.text_input(key="login_password").set_value(password)
    at.button(key="login_submit").click().run(timeout=60)
    if at.session_state.get("user") and len(at.chat_input) == 0:
        at.run(timeout=60)
    return at


def _open_mail(monkeypatch, tmp_path, username: str, **extra: str) -> AppTest:
    _isolate(monkeypatch, tmp_path, **extra)
    _plant_operator(tmp_path)
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    # The operator account has no password: it signs in with the host secret.
    password = OPERATOR if username == "owner" else username
    at = _sign_in(at, username, password)
    return at.sidebar.radio(key="nav_page").set_value("mail").run(timeout=60)


def _operator(at: AppTest, secret: str = OPERATOR) -> AppTest:
    """Type the operator secret into the mail form, as a person must."""
    at.text_input(key="operator_secret").set_value(secret)
    return at


def _events(path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
    conn.close()
    return list(rows)


def test_a_role_without_admin_is_refused_and_the_owner_can_enter(monkeypatch, tmp_path):
    """Mutation: deleting the authorize() gate on this page turns this test red."""
    refused = _open_mail(monkeypatch, tmp_path, "analyst")
    page = _blob(refused)
    assert "The admin capability is not granted to the analyst role." in page
    assert "demo password" in page
    assert "not a substitute for authentication" in page
    assert "mail_host" not in [item.key for item in refused.text_input]
    events = _events(tmp_path / "audit.db")
    assert any(row["event_type"] == "settings_refused" for row in events)
    assert any("admin" in (row["error"] or "") and "analyst" in (row["error"] or "") for row in events)

    owner = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    assert owner.text_input(key="mail_host") is not None
    assert "demo password" in _blob(owner)
    assert owner.session_state["user"]["capabilities"] == ["admin"]

    # Direction change: this test used to assert that the documented
    # `owner / owner` login worked. That credential is removed, because a
    # password that grants admin and ships in the repository is a decorative
    # gate. What replaces it is the host-generated operator secret, asserted
    # here as "the old password opens nothing, the secret opens the account".
    _isolate(monkeypatch, tmp_path)
    _plant_operator(tmp_path)
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    stale = _sign_in(at, "owner", "owner")
    assert stale.session_state.get("user") is None
    assert "did not match" in _blob(stale)

    _isolate(monkeypatch, tmp_path)
    _plant_operator(tmp_path)
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    current = _sign_in(at, "owner", OPERATOR)
    assert current.session_state["user"]["username"] == "owner"
    assert current.session_state["user"]["capabilities"] == ["admin"]


def test_provider_presets_fill_host_port_and_tls(monkeypatch, tmp_path):
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    at.selectbox(key="mail_provider").set_value("gmail").run(timeout=60)
    assert at.text_input(key="mail_host").value == "smtp.gmail.com"
    assert at.text_input(key="mail_port").value == "587"
    assert at.selectbox(key="mail_tls").value == "starttls"
    assert "App Password" in _blob(at)

    at.selectbox(key="mail_provider").set_value("163").run(timeout=60)
    assert at.text_input(key="mail_host").value == "smtp.163.com"
    assert at.text_input(key="mail_port").value == "465"
    assert at.selectbox(key="mail_tls").value == "ssl"
    assert "465" in _blob(at)


def test_env_values_are_labelled_until_a_save_stores_them(monkeypatch, tmp_path):
    key = generate_key()
    at = _open_mail(
        monkeypatch,
        tmp_path,
        "owner",
        DAY1_SECRET_KEY=key,
        SMTP_HOST="smtp.env.example",
        SMTP_PORT="2525",
        SMTP_USER="user@env.example",
        SMTP_FROM="from@env.example",
        SMTP_STARTTLS="true",
        SMTP_SSL="false",
    )
    page = _blob(at)
    assert "Host: smtp.env.example · source: .env" in page
    assert "source: database" not in page

    at.text_input(key="mail_password").set_value(SECRET)
    at = _operator(at)
    at = at.button(key="mail_save").click().run(timeout=60)
    page = _blob(at)
    assert "source: database" in page
    assert "Saved" in page
    assert SECRET not in page
    assert at.text_input(key="mail_password").value in ("", None)

    events = _events(tmp_path / "audit.db")
    updated = [row for row in events if row["event_type"] == "mail_settings_updated"]
    assert updated
    assert "smtp_host" in updated[-1]["question"]
    assert "smtp_password" in updated[-1]["question"]
    assert SECRET not in (updated[-1]["question"] or "")
    assert SECRET not in (updated[-1]["error"] or "")


def test_an_empty_password_keeps_the_stored_one_and_clear_removes_it(monkeypatch, tmp_path):
    key = generate_key()
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=key)
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("smtp.example.com")
    at.text_input(key="mail_port").set_value("587")
    at.selectbox(key="mail_tls").set_value("starttls")
    at.text_input(key="mail_user").set_value("owner@example.com")
    at.text_input(key="mail_from").set_value("owner@example.com")
    at.text_input(key="mail_password").set_value(SECRET)
    at = _operator(at)
    at = at.button(key="mail_save").click().run(timeout=60)

    # The from-address is not part of the transport the password was entered
    # for, so a blank password box keeps it. Editing the port instead is
    # refused: that is the binding, and it has its own test.
    at.text_input(key="mail_from").set_value("alerts@example.com")
    assert at.text_input(key="mail_password").value in ("", None)
    # The secret is not kept either: changing the port needs it typed again.
    at = _operator(at)
    at = at.button(key="mail_save").click().run(timeout=60)

    from src.mail_settings import MailSettingsStore
    from src.config import load_settings

    store = MailSettingsStore(load_settings().settings_path)
    resolved = store.resolve(load_settings())
    assert resolved["smtp_password"].value == SECRET
    assert resolved["smtp_port"].value == "587"
    assert resolved["smtp_from"].value == "alerts@example.com"
    assert "smtp_password" not in _events(tmp_path / "audit.db")[-1]["question"]

    at = at.button(key="mail_clear").click().run(timeout=60)
    armed = _blob(at)
    assert "Clear stored mail settings for this instance?" in armed
    assert "Cleared stored mail settings." not in armed
    assert store.resolve(load_settings())["smtp_password"].value == SECRET
    # Clearing re-authenticates as well: it removes the stored password.
    at.text_input(key="mail_clear_secret").set_value(OPERATOR)
    at = at.button(key="mail_clear_confirm").click().run(timeout=60)
    assert "Cleared stored mail settings." in _blob(at)
    cleared = store.resolve(load_settings())
    assert cleared["smtp_password"].value is None
    assert cleared["smtp_host"].source == "unconfigured"
    assert any(row["event_type"] == "mail_settings_cleared" for row in _events(tmp_path / "audit.db"))


def test_save_without_a_key_is_refused_on_the_page(monkeypatch, tmp_path):
    at = _open_mail(monkeypatch, tmp_path, "owner")
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("smtp.example.com")
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="mail_password").set_value(SECRET)
    at = _operator(at)
    at = at.button(key="mail_save").click().run(timeout=60)
    page = _blob(at)
    assert "DAY1_SECRET_KEY" in page
    assert "not stored in the clear" in page
    assert SECRET not in page
    database = tmp_path / "instance.db"
    blob = database.read_bytes() if database.exists() else b""
    assert SECRET.encode() not in blob
    assert any(row["event_type"] == "settings_refused" for row in _events(tmp_path / "audit.db"))


def test_a_refused_test_send_renders_the_hint(monkeypatch, tmp_path):
    # Direction change (issue #29): this test used to send to
    # "someone@example.test", an address the instance had never seen. That is
    # exactly the relay the ticket removes, so the recipient is now the address
    # this instance sends from — which is a known one — and the test still
    # asserts what it was written for: a transport failure is rendered as a
    # hint and audited as one outcome.
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("127.0.0.1")
    at.text_input(key="mail_port").set_value("9")
    at.selectbox(key="mail_tls").set_value("none")
    at.text_input(key="mail_from").set_value("day1@example.test")
    at.text_input(key="mail_test_to").set_value("day1-alerts@localhost")
    at = _operator(at)
    at = at.button(key="mail_test").click().run(timeout=60)
    page = _blob(at)
    assert "Nothing is listening" in page
    sent = [row for row in _events(tmp_path / "audit.db") if row["event_type"] == "mail_test_sent"]
    assert sent
    assert "to=day1-alerts@localhost" in sent[-1]["question"]
    assert "outcome=failed" in sent[-1]["question"]
    assert SECRET not in (sent[-1]["question"] or "")


def test_a_test_send_to_a_local_relay_renders_the_success(monkeypatch, tmp_path):
    # Direction change (issue #29): the recipient is a known address now; see
    # the note on the refused-send test above.
    from tests.test_mail_setup import _Relay

    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    with _Relay() as relay:
        at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
        at.text_input(key="mail_host").set_value("127.0.0.1")
        at.text_input(key="mail_port").set_value(str(relay.port))
        at.selectbox(key="mail_tls").set_value("none")
        at.text_input(key="mail_from").set_value("day1@example.test")
        at.text_input(key="mail_test_to").set_value("day1-alerts@localhost")
        at = _operator(at)
        at = at.button(key="mail_test").click().run(timeout=60)
        assert "Delivered to day1-alerts@localhost" in _blob(at)
        assert relay.messages
    sent = [row for row in _events(tmp_path / "audit.db") if row["event_type"] == "mail_test_sent"]
    assert sent[-1]["question"] == "to=day1-alerts@localhost outcome=ok"


def _raw(path) -> bytes:
    blob = bytearray()
    if path.exists():
        blob += path.read_bytes()
    for suffix in ("-wal", "-shm"):
        side = path.with_name(path.name + suffix)
        if side.exists():
            blob += side.read_bytes()
    return bytes(blob)


def test_a_known_password_never_appears_in_the_store_the_audit_log_or_the_page(monkeypatch, tmp_path):
    """The password is written through the page and then grepped for.

    Mutation: storing the password as plaintext, or pre-filling the password
    box from the store, turns this test red.
    """
    key = generate_key()
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=key)
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("smtp.example.com")
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="mail_user").set_value("owner@example.com")
    at.text_input(key="mail_from").set_value("owner@example.com")
    at.text_input(key="mail_password").set_value(SECRET)
    at = _operator(at)
    at = at.button(key="mail_save").click().run(timeout=60)

    assert SECRET not in _blob(at)
    assert at.text_input(key="mail_password").value in ("", None)
    for widget in at.text_input:
        assert SECRET not in str(widget.value or "")

    assert SECRET.encode() not in _raw(tmp_path / "instance.db")
    assert SECRET.encode() not in _raw(tmp_path / "audit.db")
    # The hint names the fact and the length, never the characters: this used
    # to assert the last four were in the file, which is the leak.
    assert b"9912" not in _raw(tmp_path / "instance.db")
    assert b"set, 21 characters" in _raw(tmp_path / "instance.db")

    again = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=key)
    assert again.text_input(key="mail_password").value in ("", None)
    rendered = _blob(again)
    assert SECRET not in rendered
    assert "9912" not in rendered
    assert "set, 21 characters" in rendered
    assert "source: database" in rendered



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
  - username: growth
    password: growth
    role: growth
  - username: owner
    password: owner
    role: owner
  - username: lead
    password: lead
    role: lead
"""


def _plant(path):
    from datetime import date

    from src.alerts import AlertDraft, AlertStore

    store = AlertStore(path)
    draft = dict(
        metric_id="revenue_by_product",
        comparison="above_absolute",
        constant=1_000_000_000_000,
        window_days=7,
        cadence="daily",
        local_time="09:00",
        recipients=("finance", "growth"),
        owner="lead",
        owner_role="lead",
    )
    live = store.add(AlertDraft(**draft))
    store.confirm(live, by="lead", at="2026-10-02T09:00:00Z", effective_from=date(2026, 10, 2))
    paused = store.add(AlertDraft(**draft))
    store.confirm(paused, by="lead", at="2026-10-03T09:00:00Z", effective_from=date(2026, 10, 3))
    store.pause(paused)
    retired = store.add(AlertDraft(**{**draft, "recipients": ("finance",)}))
    store.confirm(retired, by="lead", at="2026-09-01T09:00:00Z", effective_from=date(2026, 9, 1))
    store.supersede(retired, by_id=live)
    return live, paused, retired


def test_the_alert_list_shows_every_state_and_the_owner_can_act(monkeypatch, tmp_path):
    users = tmp_path / "users.yaml"
    users.write_text(_DIRECTORY, encoding="utf-8")
    live, paused, retired = _plant(tmp_path / "alerts.db")
    at = _open_mail(
        monkeypatch,
        tmp_path,
        "lead",
        USERS_PATH=str(users),
        DAY1_SECRET_KEY=generate_key(),
    )
    at = at.sidebar.radio(key="nav_page").set_value("alerts").run(timeout=60)
    page = _blob(at)
    assert "demo password" in page
    assert "d1-state-confirmed" in page
    assert "d1-state-paused" in page
    assert "d1-state-superseded" in page
    assert "Revenue by product" in page
    assert "revenue_by_product" in page
    assert "above 1,000,000,000,000" in page
    assert "7 days" in page
    assert "2026-10-02" in page
    assert "finance (can read Revenue by product)" in page
    assert "Revenue is outside the growth role." in page
    assert "Last fire: none" in page
    keys = [button.key for button in at.button]
    assert f"alert_pause_{live}" in keys
    assert f"alert_resume_{paused}" in keys
    assert f"alert_run_{live}" in keys
    assert f"alert_pause_{retired}" not in keys

    at = at.button(key=f"alert_pause_{live}").click().run(timeout=60)
    assert "is paused" in _blob(at)
    assert any(row["event_type"] == "alert_paused" for row in _events(tmp_path / "audit.db"))

    at = at.button(key=f"alert_resume_{live}").click().run(timeout=60)
    assert "is live again" in _blob(at)
    assert any(row["event_type"] == "alert_resumed" for row in _events(tmp_path / "audit.db"))

    at = at.button(key=f"alert_run_{live}").click().run(timeout=90)
    page = _blob(at)
    assert "Outcome: not_fired" in page
    assert "Last fire: no_fire" in page
    assert any(row["event_type"] == "alert_not_fired" for row in _events(tmp_path / "audit.db"))

    # Direction change: this test used to assert that the owner role was
    # refused here ("Only the owner of an alert definition can pause it"),
    # because pause, resume and run were owner-only while only the `alert`
    # role could own a definition. The person who could open the page could
    # therefore never operate anything on it. An `admin` now acts as the
    # instance operator on any definition, and the audit row says so and
    # names the owner. The owner role reads no tables, so the row's title,
    # condition and last fire are not rendered for them.
    at = at.button(key="sign_out_alerts").click().run(timeout=60)
    at = _sign_in(at, "owner", "owner")
    at = at.sidebar.radio(key="nav_page").set_value("alerts").run(timeout=60)
    page = _blob(at)
    assert "Restricted metric" in page
    assert "Condition hidden" in page
    assert "Last fire hidden" in page
    assert "Revenue by product" not in page
    assert "above 1,000,000,000,000" not in page
    assert "This metric is outside the owner role" in page

    at = at.button(key=f"alert_pause_{live}").click().run(timeout=60)
    page = _blob(at)
    assert "is paused" in page
    assert "You acted as the instance operator on lead's definition." in page
    row = _events(tmp_path / "audit.db")[-1]
    assert row["event_type"] == "alert_paused"
    assert row["username"] == "owner"
    assert row["capability"] == "admin"
    assert "operator=true" in row["question"]
    assert "owner=lead" in row["question"]

    at = at.button(key=f"alert_resume_{live}").click().run(timeout=60)
    assert "is live again" in _blob(at)
    row = _events(tmp_path / "audit.db")[-1]
    assert row["event_type"] == "alert_resumed"
    assert row["capability"] == "admin"

    at = at.button(key=f"alert_run_{live}").click().run(timeout=90)
    assert "Outcome:" in _blob(at)
    run_now = [
        item for item in _events(tmp_path / "audit.db") if item["event_type"] == "alert_run_now"
    ]
    assert run_now
    assert run_now[-1]["username"] == "owner"
    assert run_now[-1]["capability"] == "admin"
    assert "run alert definition" in run_now[-1]["question"]
    assert "owner lead" in run_now[-1]["question"]


def test_the_alert_list_refuses_a_role_without_admin(monkeypatch, tmp_path):
    """Mutation: deleting the authorize() gate on this page turns this test red."""
    at = _open_mail(monkeypatch, tmp_path, "analyst")
    at = at.sidebar.radio(key="nav_page").set_value("alerts").run(timeout=60)
    page = _blob(at)
    assert "The admin capability is not granted to the analyst role." in page
    assert "not a substitute for authentication" in page
    assert "alert_pause_" not in " ".join(button.key or "" for button in at.button)
    assert any(row["event_type"] == "settings_refused" for row in _events(tmp_path / "audit.db"))

