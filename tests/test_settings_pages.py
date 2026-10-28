"""AppTest for the mail settings page: presets, save, clear, test send, the admin gate."""

from __future__ import annotations

import sqlite3

from src.config import ROOT
from src.crypto import generate_key
from streamlit.testing.v1 import AppTest

SECRET = "day1-mail-secret-9912"


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
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    at = _sign_in(at, username, username)
    return at.sidebar.radio(key="nav_page").set_value("mail").run(timeout=60)


def _events(path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT event_type, question, error, status FROM audit_events ORDER BY id"
    ).fetchall()
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
    at = at.button(key="mail_save").click().run(timeout=60)

    at.text_input(key="mail_port").set_value("2525")
    assert at.text_input(key="mail_password").value in ("", None)
    at = at.button(key="mail_save").click().run(timeout=60)

    from src.mail_settings import MailSettingsStore
    from src.config import load_settings

    store = MailSettingsStore(load_settings().settings_path)
    resolved = store.resolve(load_settings())
    assert resolved["smtp_password"].value == SECRET
    assert resolved["smtp_port"].value == "2525"
    assert "smtp_password" not in _events(tmp_path / "audit.db")[-1]["question"]

    at = at.button(key="mail_clear").click().run(timeout=60)
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
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("127.0.0.1")
    at.text_input(key="mail_port").set_value("9")
    at.selectbox(key="mail_tls").set_value("none")
    at.text_input(key="mail_from").set_value("day1@example.test")
    at.text_input(key="mail_test_to").set_value("someone@example.test")
    at = at.button(key="mail_test").click().run(timeout=60)
    page = _blob(at)
    assert "Nothing is listening" in page
    sent = [row for row in _events(tmp_path / "audit.db") if row["event_type"] == "mail_test_sent"]
    assert sent
    assert "to=someone@example.test" in sent[-1]["question"]
    assert "outcome=failed" in sent[-1]["question"]
    assert SECRET not in (sent[-1]["question"] or "")


def test_a_test_send_to_a_local_relay_renders_the_success(monkeypatch, tmp_path):
    from tests.test_mail_setup import _Relay

    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    with _Relay() as relay:
        at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
        at.text_input(key="mail_host").set_value("127.0.0.1")
        at.text_input(key="mail_port").set_value(str(relay.port))
        at.selectbox(key="mail_tls").set_value("none")
        at.text_input(key="mail_from").set_value("day1@example.test")
        at.text_input(key="mail_test_to").set_value("someone@example.test")
        at = at.button(key="mail_test").click().run(timeout=60)
        assert "Delivered to someone@example.test" in _blob(at)
        assert relay.messages
    sent = [row for row in _events(tmp_path / "audit.db") if row["event_type"] == "mail_test_sent"]
    assert sent[-1]["question"] == "to=someone@example.test outcome=ok"
