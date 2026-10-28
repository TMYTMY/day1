"""The Settings gate: the browser flag, the operator secret, one row per outcome.

Every test here is about a boundary rather than a widget: what the page refuses
to do, what it refuses to show, and what it writes down exactly once when it
does act.
"""

from __future__ import annotations

import sqlite3

import pytest
import yaml

from src.config import ROOT
from src.crypto import generate_key
from src.mail_settings import MailSettingsStore
from src.metrics import Metric
from src.models import User
from src.operator_secret import store_secret
from src.settings_pages import _report_decrypt_refusal
from streamlit.testing.v1 import AppTest
from tests.test_settings_pages import (
    OPERATOR,
    SECRET,
    _DIRECTORY,
    _blob,
    _events,
    _isolate,
    _open_mail,
    _plant,
    _sign_in,
)

_WRITE_EVENTS = {"mail_settings_updated", "mail_settings_cleared", "mail_test_sent"}

_HOSTILE_METRICS = [
    {
        "id": "revenue_by_product",
        "title": "Revenue <b>by</b> [product](https://evil.example)",
        "synonyms": ["revenue"],
        "table": "revenue",
        "grain": ["event_date", "product", "region", "channel"],
        "additive_over": ["event_date", "product", "region"],
        "definition": "Recognised revenue in USD, net of cancellations.",
        "owner": "finance-reporting",
        "effective_from": "2026-06-15",
        "supersedes": None,
        "exceptions": "Excludes internal test accounts.",
        "measure": "revenue_usd",
    }
]


def _rows(tmp_path) -> list[sqlite3.Row]:
    return _events(tmp_path / "audit.db")


def _open_alerts(monkeypatch, tmp_path, username: str, password: str, **extra) -> AppTest:
    """Reach the alert list as a named person from a planted user directory."""
    from tests.test_settings_pages import _plant_operator

    _isolate(monkeypatch, tmp_path, **extra)
    _plant_operator(tmp_path)
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    at = _sign_in(at, username, password)
    return at.sidebar.radio(key="nav_page").set_value("alerts").run(timeout=60)


# --- the browser write surface is off by default ----------------------------


def test_browser_settings_are_off_and_the_page_says_how_to_enable_them(
    monkeypatch, tmp_path
):
    at = _open_mail(
        monkeypatch,
        tmp_path,
        "owner",
        DAY1_ALLOW_BROWSER_SETTINGS="0",
        DAY1_SECRET_KEY=generate_key(),
    )
    page = _blob(at)
    assert "Browser settings are off on this instance" in page
    assert "DAY1_ALLOW_BROWSER_SETTINGS=1" in page
    assert "read-only" in page

    # No write control exists at all, so there is nothing to click by accident.
    keys = [widget.key for widget in at.text_input]
    assert "mail_host" not in keys
    assert "mail_password" not in keys
    assert "operator_secret" not in keys
    button_keys = [button.key for button in at.button]
    assert "mail_save" not in button_keys
    assert "mail_test" not in button_keys
    assert "mail_clear" not in button_keys

    # It is still useful: where each value comes from is readable.
    assert "Host: not set · source: unconfigured" in page
    assert [row for row in _rows(tmp_path) if row["event_type"] in _WRITE_EVENTS] == []


def test_the_flag_is_read_from_the_environment_per_run(monkeypatch, tmp_path):
    off = _open_mail(monkeypatch, tmp_path, "owner", DAY1_ALLOW_BROWSER_SETTINGS="0")
    assert "Browser settings are off" in _blob(off)
    on = _open_mail(monkeypatch, tmp_path, "owner", DAY1_ALLOW_BROWSER_SETTINGS="1")
    assert "Browser settings are off" not in _blob(on)
    assert on.text_input(key="mail_host") is not None


# --- re-authentication ------------------------------------------------------


def test_a_save_without_the_operator_secret_is_refused_on_the_page(
    monkeypatch, tmp_path
):
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    before = len(_rows(tmp_path))
    at.text_input(key="mail_host").set_value("smtp.attacker.example")
    at.text_input(key="mail_password").set_value(SECRET)
    at = at.button(key="mail_save").click().run(timeout=60)

    page = _blob(at)
    assert "Enter the operator secret" in page
    assert "Saved" not in page
    rows = _rows(tmp_path)
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "settings_refused"
    assert rows[-1]["status"] == "denied"
    assert "operator secret" in (rows[-1]["error"] or "").lower()
    assert SECRET not in (rows[-1]["question"] or "")
    assert SECRET not in (rows[-1]["error"] or "")

    # Nothing was written: the host the attacker typed is not the stored one.
    from src.config import load_settings

    resolved = MailSettingsStore(load_settings().settings_path).resolve(load_settings())
    assert resolved["smtp_host"].value is None
    assert resolved["smtp_password"].value is None


def test_a_wrong_operator_secret_is_refused_and_changes_nothing(monkeypatch, tmp_path):
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    before = len(_rows(tmp_path))
    at.text_input(key="mail_host").set_value("smtp.attacker.example")
    at.text_input(key="operator_secret").set_value("not-the-operator-secret")
    at = at.button(key="mail_save").click().run(timeout=60)

    page = _blob(at)
    assert "The operator secret did not match. Nothing was changed." in page
    rows = _rows(tmp_path)
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "settings_refused"
    assert "operator_secret" in (rows[-1]["error"] or "") or "did not match" in (
        rows[-1]["error"] or ""
    )
    # The secret itself is not echoed back into the page or the log.
    assert "not-the-operator-secret" not in page
    assert "not-the-operator-secret" not in str(rows[-1]["error"])

    from src.config import load_settings

    resolved = MailSettingsStore(load_settings().settings_path).resolve(load_settings())
    assert resolved["smtp_host"].value is None


def test_the_secret_is_required_again_for_every_action(monkeypatch, tmp_path):
    key = generate_key()
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=key)
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("smtp.example.com")
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="mail_from").set_value("day1@example.test")
    at.text_input(key="mail_password").set_value(SECRET)
    at.text_input(key="operator_secret").set_value(OPERATOR)
    at = at.button(key="mail_save").click().run(timeout=60)
    assert "Saved" in _blob(at)

    # The next action does not inherit the previous one's re-authentication.
    at.text_input(key="mail_test_to").set_value("someone@example.test")
    at = at.button(key="mail_test").click().run(timeout=60)
    assert "Enter the operator secret" in _blob(at)
    sent = [row for row in _rows(tmp_path) if row["event_type"] == "mail_test_sent"]
    assert sent == []


# --- exactly one audit row per outcome --------------------------------------


def test_a_page_render_writes_no_audit_row(monkeypatch, tmp_path):
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    before = len(_rows(tmp_path))
    at.run(timeout=60)
    at.run(timeout=60)
    assert len(_rows(tmp_path)) == before


def test_each_submit_writes_exactly_one_row(monkeypatch, tmp_path):
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("127.0.0.1")
    at.text_input(key="mail_port").set_value("not-a-port")
    at.text_input(key="mail_from").set_value("day1@example.test")
    at.text_input(key="operator_secret").set_value(OPERATOR)

    before = len(_rows(tmp_path))
    at = at.button(key="mail_save").click().run(timeout=60)
    assert "The port must be a whole number" in _blob(at)
    rows = _rows(tmp_path)
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "settings_refused"
    assert rows[-1]["status"] == "denied"

    before = len(rows)
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="operator_secret").set_value(OPERATOR)
    at = at.button(key="mail_save").click().run(timeout=60)
    assert "Saved" in _blob(at)
    rows = _rows(tmp_path)
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "mail_settings_updated"
    assert rows[-1]["status"] == "ok"

    before = len(rows)
    at.text_input(key="mail_test_to").set_value("someone@example.test")
    at.text_input(key="operator_secret").set_value(OPERATOR)
    at = at.button(key="mail_test").click().run(timeout=60)
    rows = _rows(tmp_path)
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "mail_test_sent"
    assert rows[-1]["question"].startswith("to=someone@example.test outcome=")


def test_a_store_that_raises_is_audited_once_and_never_shows_a_traceback(
    monkeypatch, tmp_path
):
    """Mutation: removing the guard around store.save turns this test red.

    An sqlite3.OperationalError used to escape the handler, so the page showed
    a traceback and the change (if any) was unaudited. Now the raise is an
    outcome: one row, and one sentence on the page.
    """

    def boom(self, values, *, updated_by, key):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(MailSettingsStore, "save", boom)
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("smtp.example.com")
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="operator_secret").set_value(OPERATOR)

    before = len(_rows(tmp_path))
    at = at.button(key="mail_save").click().run(timeout=60)
    page = _blob(at)
    assert "database is locked" in page
    assert "Traceback" not in page
    assert len(at.exception) == 0
    rows = _rows(tmp_path)
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "settings_refused"
    assert rows[-1]["status"] == "failed"
    assert "database is locked" in (rows[-1]["error"] or "")


def test_a_run_now_that_cannot_start_is_audited_once(monkeypatch, tmp_path):
    """A worker that cannot even be built is an outcome, not a traceback."""

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    users = tmp_path / "users.yaml"
    users.write_text(_DIRECTORY, encoding="utf-8")
    _plant(tmp_path / "alerts.db")
    at = _open_alerts(
        monkeypatch,
        tmp_path,
        "lead",
        "lead",
        USERS_PATH=str(users),
        DAY1_SECRET_KEY=generate_key(),
    )
    import src.settings_pages as pages

    monkeypatch.setattr(pages.Worker, "from_settings", boom)
    before = len(_rows(tmp_path))
    keys = [button.key for button in at.button]
    run_key = next(key for key in keys if key and key.startswith("alert_run_"))
    at = at.button(key=run_key).click().run(timeout=60)
    page = _blob(at)
    assert "could not start" in page
    assert "Traceback" not in page
    assert len(at.exception) == 0
    rows = _rows(tmp_path)
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "alert_run_now"
    assert rows[-1]["status"] == "failed"


def test_a_clear_that_raises_is_audited_once(monkeypatch, tmp_path):
    def boom(self):
        raise sqlite3.OperationalError("database is locked")

    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    monkeypatch.setattr(MailSettingsStore, "clear", boom)
    at = at.button(key="mail_clear").click().run(timeout=60)
    at.text_input(key="mail_clear_secret").set_value(OPERATOR)
    before = len(_rows(tmp_path))
    at = at.button(key="mail_clear_confirm").click().run(timeout=60)
    assert "could not be removed" in _blob(at)
    rows = _rows(tmp_path)
    assert len(rows) == before + 1
    assert rows[-1]["event_type"] == "settings_refused"
    assert rows[-1]["status"] == "failed"


# --- nothing typed into a password box is kept ------------------------------


def test_the_password_boxes_tell_the_browser_not_to_fill_them(monkeypatch, tmp_path):
    """A password manager on the same origin must not autofill the login here.

    Mutation: dropping ``autocomplete="new-password"`` turns this test red. A
    filled password box means "replace the stored password", so an autofilled
    login password would silently overwrite the SMTP password.
    """
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    for key in ("mail_password", "operator_secret"):
        widget = at.text_input(key=key)
        assert widget.proto.autocomplete == "new-password"
        assert widget.proto.type == 1  # PASSWORD
        # Both live inside the form that clears itself on submit.
        assert widget.proto.form_id == "mail_settings_form"


def test_a_validation_error_leaves_both_password_boxes_empty(monkeypatch, tmp_path):
    """Mutation: restoring the early return without the purge turns this red."""
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    at.text_input(key="mail_password").set_value(SECRET)
    at.text_input(key="operator_secret").set_value(OPERATOR)
    at.text_input(key="mail_port").set_value("70000")
    at = at.button(key="mail_save").click().run(timeout=60)

    page = _blob(at)
    assert "The port must be a number between 1 and 65535." in page
    assert SECRET not in page
    assert OPERATOR not in page
    assert at.text_input(key="mail_password").value in ("", None)
    assert at.text_input(key="operator_secret").value in ("", None)
    for key in ("mail_password", "operator_secret"):
        assert at.session_state[key] in ("", None)

    # And a page switch does not carry them either.
    at = at.sidebar.radio(key="nav_page").set_value("alerts").run(timeout=60)
    at = at.sidebar.radio(key="nav_page").set_value("mail").run(timeout=60)
    assert at.text_input(key="mail_password").value in ("", None)
    assert SECRET not in _blob(at)


def test_a_successful_save_leaves_no_password_in_widget_or_session_state(
    monkeypatch, tmp_path
):
    at = _open_mail(monkeypatch, tmp_path, "owner", DAY1_SECRET_KEY=generate_key())
    at.selectbox(key="mail_provider").set_value("custom").run(timeout=60)
    at.text_input(key="mail_host").set_value("smtp.example.com")
    at.text_input(key="mail_port").set_value("587")
    at.text_input(key="mail_password").set_value(SECRET)
    at.text_input(key="operator_secret").set_value(OPERATOR)
    at = at.button(key="mail_save").click().run(timeout=60)
    assert "Saved" in _blob(at)
    assert at.text_input(key="mail_password").value in ("", None)
    assert at.text_input(key="operator_secret").value in ("", None)
    assert at.session_state["mail_password"] in ("", None)
    assert at.session_state["operator_secret"] in ("", None)


def test_a_decrypt_refusal_is_audited_once_per_distinct_error(tmp_path):
    """Mutation: restoring the set-once-for-the-session flag turns this red."""
    from src.audit import AuditLog
    from src.mail_settings import MailField, ResolvedMail

    audit = AuditLog(tmp_path / "audit.db")
    operator = User("owner", "owner", (), capabilities=("admin",))

    def snapshot(error: str) -> ResolvedMail:
        return ResolvedMail(
            fields={
                "smtp_password": MailField(
                    name="smtp_password",
                    value=None,
                    source="database",
                    hint="set",
                    secret=True,
                    error=error,
                )
            }
        )

    class State(dict):
        pass

    # The function reads and writes st.session_state; a plain dict is enough.
    import src.settings_pages as pages

    original = pages.st.session_state

    class _Fake:
        def __init__(self, store):
            self._store = store

        def get(self, key, default=None):
            return self._store.get(key, default)

        def pop(self, key, default=None):
            return self._store.pop(key, default)

        def __getitem__(self, key):
            return self._store[key]

        def __setitem__(self, key, value):
            self._store[key] = value

    store = State()
    pages.st.session_state = _Fake(store)  # type: ignore[assignment]
    try:
        _report_decrypt_refusal(operator, audit, snapshot("key A cannot open field"))
        assert len(_rows(tmp_path)) == 1
        # The same error on the next render is not a second event.
        _report_decrypt_refusal(operator, audit, snapshot("key A cannot open field"))
        assert len(_rows(tmp_path)) == 1
        # A different error is, and so is a failure after the first one cleared.
        _report_decrypt_refusal(operator, audit, snapshot("key B cannot open field"))
        assert len(_rows(tmp_path)) == 2
        _report_decrypt_refusal(operator, audit, snapshot(""))
        _report_decrypt_refusal(operator, audit, snapshot("key A cannot open field"))
        assert len(_rows(tmp_path)) == 3
    finally:
        pages.st.session_state = original  # type: ignore[assignment]


# --- the alert list renders only what the person may read -------------------


def _write_metrics(tmp_path, entries) -> str:
    path = tmp_path / "metrics.yaml"
    path.write_text(yaml.safe_dump(entries, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return str(path)


def test_the_alert_list_escapes_a_title_it_does_not_trust(monkeypatch, tmp_path):
    users = tmp_path / "users.yaml"
    users.write_text(_DIRECTORY, encoding="utf-8")
    metrics = _write_metrics(tmp_path, _HOSTILE_METRICS)
    _plant(tmp_path / "alerts.db")
    at = _open_alerts(
        monkeypatch,
        tmp_path,
        "lead",
        "lead",
        USERS_PATH=str(users),
        METRICS_PATH=metrics,
        DAY1_SECRET_KEY=generate_key(),
    )
    page = _blob(at)

    # The catalogue's title is composed into HTML, so it is escaped: the markup
    # is visible as text and is not a tag, and the Markdown link is not a link.
    assert "&lt;b&gt;by&lt;/b&gt;" in page
    assert "<b>by</b>" not in page
    assert "href=\"https://evil.example\"" not in page
    assert "[product](https://evil.example)" in page


def test_the_alert_list_hides_a_metric_the_role_cannot_read(monkeypatch, tmp_path):
    users = tmp_path / "users.yaml"
    users.write_text(_DIRECTORY, encoding="utf-8")
    metrics = _write_metrics(tmp_path, _HOSTILE_METRICS)
    _plant(tmp_path / "alerts.db")

    reader = _open_alerts(
        monkeypatch,
        tmp_path,
        "lead",
        "lead",
        USERS_PATH=str(users),
        METRICS_PATH=metrics,
        DAY1_SECRET_KEY=generate_key(),
    )
    assert "Revenue &lt;b&gt;by&lt;/b&gt;" in _blob(reader)
    assert "above 1,000,000,000,000" in _blob(reader)
    assert "Last fire: none" in _blob(reader)

    # The owner role administers the instance and reads no tables, so the list
    # it can open must not summarise a metric it could not get an answer about.
    blinded = _open_alerts(
        monkeypatch, tmp_path, "owner", "owner", USERS_PATH=str(users), METRICS_PATH=metrics
    )
    page = _blob(blinded)
    assert "Restricted metric" in page
    assert "Condition hidden" in page
    assert "Last fire hidden" in page
    assert "Revenue" not in page
    assert "1,000,000,000,000" not in page
    assert "can read" not in page
    assert "(access hidden)" in page
    assert "This metric is outside the owner role" in page
    # The row is still operable, and still identifiable by its id.
    assert any(button.key and button.key.startswith("alert_pause_") for button in blinded.button)
    assert "definition #" in page


def test_a_metric_role_cannot_read_is_not_rendered_by_the_fire_verdict_either(
    monkeypatch, tmp_path
):
    """A last-fire verdict is data about the metric, so it is hidden too."""
    from src.fires import FireStore

    users = tmp_path / "users.yaml"
    users.write_text(_DIRECTORY, encoding="utf-8")
    metrics = _write_metrics(tmp_path, _HOSTILE_METRICS)
    live, _, _ = _plant(tmp_path / "alerts.db")
    fires = FireStore(tmp_path / "alerts.db")
    fires.claim(
        fire_key=f"{live}:2026-10-02",
        alert_id=live,
        window_start=__import__("datetime").date(2026, 9, 25),
        window_end=__import__("datetime").date(2026, 10, 2),
        at="2026-10-02T09:00:00Z",
    )
    fires.complete(f"{live}:2026-10-02", value=1.0, previous=None, verdict="fire")

    reader = _open_alerts(
        monkeypatch,
        tmp_path,
        "lead",
        "lead",
        USERS_PATH=str(users),
        METRICS_PATH=metrics,
        DAY1_SECRET_KEY=generate_key(),
    )
    assert "Last fire: fire" in _blob(reader)

    blinded = _open_alerts(
        monkeypatch, tmp_path, "owner", "owner", USERS_PATH=str(users), METRICS_PATH=metrics
    )
    page = _blob(blinded)
    assert "Last fire: fire" not in page
    assert "Last fire hidden" in page
