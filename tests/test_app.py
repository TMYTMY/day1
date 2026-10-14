"""UI smoke test. Covers sign-in, revenue, an unknown topic, DAU, and exports."""

from __future__ import annotations

from src.config import ROOT
from streamlit.testing.v1 import AppTest


def _blob(at: AppTest) -> str:
    parts: list[str] = []
    for group in (at.markdown, at.caption, at.info, at.warning, at.error, at.text):
        for element in group:
            value = getattr(element, "value", None)
            if isinstance(value, str):
                parts.append(value)
    return "\n".join(parts)


def _sign_in(at: AppTest, username: str, password: str) -> AppTest:
    at.text_input(key="login_user").set_value(username)
    at.text_input(key="login_password").set_value(password)
    at.button(key="login_submit").click().run(timeout=60)
    if at.session_state.get("user") and len(at.chat_input) == 0:
        at.run(timeout=60)
    return at


def test_analyst_can_ask_export_and_get_a_clarifying_question(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("KNOWLEDGE_PATH", str(tmp_path / "knowledge"))
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    assert at.button(key="login_submit") is not None
    at = _sign_in(at, "analyst", "analyst")
    assert at.session_state["user"]["role"] == "analyst"

    at.button(key="suggest_0").click().run(timeout=60)
    revenue_frame = at.dataframe[0].value
    assert set(revenue_frame["product"]) == {"Atlas", "Northstar", "Harbor"}
    sql = "\n".join(element.value for element in at.code)
    assert "FROM revenue" in sql
    assert "dau" not in sql.lower()
    labels = [button.label for button in at.download_button]
    assert "Download CSV" in labels
    assert "Download HTML" in labels

    at.chat_input[0].set_value("What's the weather in Hong Kong?").run(timeout=60)
    assert "I can answer questions about" in _blob(at)

    at.chat_input[0].set_value(
        "Show daily active users by platform for the last 30 days"
    ).run(timeout=60)
    dau_frame = at.dataframe[-1].value
    assert set(dau_frame["platform"]) == {"ios", "android", "web"}
    assert "FROM dau" in "\n".join(element.value for element in at.code)


def test_knowledge_base_page_indexes_and_deletes_a_glossary(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("KNOWLEDGE_PATH", str(tmp_path / "knowledge"))
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    at = _sign_in(at, "analyst", "analyst")
    at.sidebar.radio(key="nav_page").set_value("knowledge").run(timeout=60)
    assert any(element.value == "知識庫" for element in at.title)
    assert "No documents yet" in _blob(at)

    glossary = (
        b"# Glossary\n\n"
        b"Booked revenue means the revenue_usd column. "
        b"Northstar is the flagship product.\n"
    )
    at.file_uploader[0].upload("glossary.md", glossary, "text/markdown").run(timeout=60)
    page = _blob(at)
    assert "glossary.md" in page
    assert "chunks" in page
    assert any(button.label == "Re-index" for button in at.button)
    assert any(button.label == "Delete" for button in at.button)

    at = next(button for button in at.button if button.label == "Delete").click().run(timeout=60)
    if "No documents yet" not in _blob(at):
        at = at.run(timeout=60)
    page = _blob(at)
    assert "No documents yet" in page
    assert not any(button.label == "Re-index" for button in at.button)

    at.sidebar.radio(key="nav_page").set_value("ask").run(timeout=60)
    at.chat_input[0].set_value(
        "What was total revenue by product over the last 90 days?"
    ).run(timeout=60)
    assert set(at.dataframe[0].value["product"]) == {"Atlas", "Northstar", "Harbor"}


def test_finance_dau_question_stays_on_the_permission_message(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("KNOWLEDGE_PATH", str(tmp_path / "knowledge"))
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    at = _sign_in(at, "finance", "finance")
    at.chat_input[0].set_value("Show daily active users by platform").run(timeout=60)
    page = _blob(at)
    assert "outside the finance role" in page
    assert at.dataframe == []
    assert at.download_button == []


def test_login_page_does_not_render_the_demo_passwords(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("KNOWLEDGE_PATH", str(tmp_path / "knowledge"))

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    page = _blob(at)
    assert "| analyst | analyst |" not in page
    assert "| password |" not in page.lower()
    assert "listed in README.md" in page
