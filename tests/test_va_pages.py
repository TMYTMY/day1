"""AppTest for Connections and the approval controls on 知識庫."""

from __future__ import annotations

import sqlite3

from src.config import ROOT
from src.operator_secret import store_secret
from streamlit.testing.v1 import AppTest

OPERATOR = "day1-operator-secret-4711"
PLANTED = "s3cret-db-password"


def _blob(at: AppTest) -> str:
    parts: list[str] = []
    for group_name in ("markdown", "caption", "info", "warning", "error", "success", "text"):
        for element in getattr(at, group_name):
            value = getattr(element, "value", None)
            if isinstance(value, str):
                parts.append(value)
    return "\n".join(parts)


def _isolate(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("ALERTS_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SETTINGS_PATH", str(tmp_path / "instance.db"))
    monkeypatch.setenv("KNOWLEDGE_PATH", str(tmp_path / "knowledge"))
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")
    monkeypatch.setenv("DATABASE_URL", f"postgres://analyst:{PLANTED}@localhost/warehouse")
    monkeypatch.setenv("DB_PASSWORD", PLANTED)
    store_secret(tmp_path / "instance.db", OPERATOR)


def _sign_in(at: AppTest, username: str, password: str) -> AppTest:
    at.text_input(key="login_user").set_value(username)
    at.text_input(key="login_password").set_value(password)
    at.button(key="login_submit").click().run(timeout=60)
    if at.session_state.get("user") and len(at.chat_input) == 0 and len(at.sidebar.radio) == 0:
        at.run(timeout=60)
    return at


def _canary(path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE revenue (
            event_date TEXT NOT NULL,
            product TEXT NOT NULL,
            region TEXT NOT NULL,
            channel TEXT,
            revenue_usd REAL NOT NULL,
            orders INTEGER NOT NULL,
            ingest_batch TEXT NOT NULL,
            loaded_at TEXT NOT NULL,
            amount_currency TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO revenue VALUES (
            date('now'), 'CanaryProduct', 'APAC', 'direct', 10, 1, 'batch', 'loaded', 'USD'
        )
        """
    )
    conn.commit()
    conn.close()


def test_connections_page_is_sqlite_only_and_does_not_echo_secrets(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    canary = tmp_path / "canary.db"
    _canary(canary)

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    refused = _sign_in(at, "analyst", "analyst")
    refused.sidebar.radio(key="nav_page").set_value("connections").run(timeout=60)
    assert "The admin capability is not granted to the analyst role." in _blob(refused)
    assert "connection_path" not in [item.key for item in refused.text_input]
    assert PLANTED not in _blob(refused)

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    owner = _sign_in(at, "owner", OPERATOR)
    owner.sidebar.radio(key="nav_page").set_value("connections").run(timeout=60)
    page = _blob(owner)
    assert "SQLite file path" in [item.label for item in owner.text_input]
    assert "Postgres is not configured on this page." in page
    assert PLANTED not in page
    assert "postgres://" not in page
    labels = " ".join(item.label for item in owner.text_input)
    assert "Password" not in labels
    assert "Host" not in labels

    owner.text_input(key="connection_path").set_value(
        f"postgres://analyst:{PLANTED}@localhost/warehouse"
    )
    owner.text_input(key="connection_operator_secret").set_value(OPERATOR)
    owner.button(key="connection_test").click().run(timeout=60)
    assert "Only a local SQLite file path is accepted." in _blob(owner)
    assert PLANTED not in _blob(owner)
    audit = (tmp_path / "audit.db").read_bytes()
    instance = (tmp_path / "instance.db").read_bytes()
    assert PLANTED.encode() not in audit
    assert PLANTED.encode() not in instance

    owner.text_input(key="connection_path").set_value(str(canary))
    owner.text_input(key="connection_operator_secret").set_value(OPERATOR)
    owner.button(key="connection_test").click().run(timeout=60)
    assert "Connection test succeeded." in _blob(owner)
    assert "Last test succeeded" in _blob(owner)

    owner.text_input(key="connection_operator_secret").set_value(OPERATOR)
    owner.button(key="connection_enable").click().run(timeout=60)
    assert "This SQLite connection is enabled." in _blob(owner)
    assert PLANTED not in _blob(owner)

    owner.button(key="sign_out_connections").click().run(timeout=60)
    analyst = _sign_in(owner, "analyst", "analyst")
    analyst.chat_input[0].set_value(
        "What was total revenue by product over the last 90 days?"
    ).run(timeout=60)
    # One row is rendered as metrics, not a dataframe. The number is the canary's.
    asked = _blob(analyst)
    assert "CanaryProduct" in asked
    assert "$10.00" in asked
    assert "`revenue` · 1 rows" in asked

    analyst.sidebar.radio(key="nav_page").set_value("connections").run(timeout=60)
    analyst.button(key="sign_out_connections").click().run(timeout=60)
    owner = _sign_in(analyst, "owner", OPERATOR)
    owner.sidebar.radio(key="nav_page").set_value("connections").run(timeout=60)
    owner.text_input(key="connection_operator_secret").set_value(OPERATOR)
    owner.button(key="connection_disable").click().run(timeout=60)
    assert "No UI connection is enabled." in _blob(owner)

    owner.button(key="sign_out_connections").click().run(timeout=60)
    analyst = _sign_in(owner, "analyst", "analyst")
    analyst.chat_input[0].set_value(
        "What was total revenue by product over the last 90 days?"
    ).run(timeout=60)
    assert "Atlas" in set(analyst.dataframe[0].value["product"])
    assert "CanaryProduct" not in set(analyst.dataframe[0].value["product"])


def test_owner_approves_and_rejects_on_the_knowledge_page(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    analyst = _sign_in(at, "analyst", "analyst")
    analyst.sidebar.radio(key="nav_page").set_value("knowledge").run(timeout=60)
    glossary = (
        b"# Glossary\n\nBooked revenue means the revenue_usd column.\n"
    )
    analyst.file_uploader[0].upload("glossary.md", glossary, "text/markdown").run(timeout=60)
    page = _blob(analyst)
    assert "glossary.md" in page
    assert "Approval · draft" in page
    assert "chunks" in page
    assert not any(button.label == "Approve" for button in analyst.button)
    assert "Only the owner can approve or reject." in page

    analyst.button(key="sign_out").click().run(timeout=60)
    owner = _sign_in(analyst, "owner", OPERATOR)
    owner.sidebar.radio(key="nav_page").set_value("knowledge").run(timeout=60)
    assert "glossary.md" in _blob(owner)
    approve = next(button for button in owner.button if button.label == "Approve")
    approve.click().run(timeout=60)
    assert "Approval · approved" in _blob(owner)

    reject = next(button for button in owner.button if button.label == "Reject")
    reject.click().run(timeout=60)
    assert "Approval · rejected" in _blob(owner)

    png = b"\x89PNG\r\n\x1a\n" + b"pixels"
    owner.file_uploader[0].upload("logo.png", png, "image/png").run(timeout=60)
    assert "non-indexed" in _blob(owner)

    pdf = b"%PDF-1.4\n%%EOF\n"
    owner.file_uploader[0].upload("notes.pdf", pdf, "application/pdf").run(timeout=60)
    assert "not extracted" in _blob(owner)
    assert "notes.pdf" in _blob(owner)
