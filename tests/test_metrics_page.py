"""The 口徑目錄 page's pure helpers, and the page itself end to end.

The rendering rules are small and testable without mocking Streamlit: a
divergence is a comparison of four fields, a badge is one word, and a chip is
offered only when it lands on a signed metric. The page is then driven through
Streamlit's own test harness, because a sign button that cannot write is the
failure that matters most.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date

from streamlit.testing.v1 import AppTest

from src.audit import AuditLog
from src.config import ROOT, load_settings
from src.metric_signatures import (
    DRAFT,
    SIGNED,
    SignedDefinition,
    active_signatures,
    effective_catalogue,
    sign,
    status,
)
from src.metrics import load_metrics, match_metrics
from src.metrics_page import file_diverges, secret_refusal, status_badge
from src.models import User
from src.operator_secret import store_secret

from app import _suggestions_for

REAL_DEFINITION = "Distinct users with at least one session that day, per platform."
OPERATOR = "day1-metrics-page-secret-3301"

# One metric, hand-written, so this module never edits the checkout's file.
ONE_METRIC = """\
- id: dau_by_platform
  title: DAU by platform
  synonyms: [dau, daily active users]
  table: dau
  grain: [event_date, platform, country]
  additive_over: [event_date, platform]
  definition: "Distinct users with at least one session that day, per platform."
  owner: growth-lead
  effective_from: 2026-06-15
  supersedes: null
  exceptions: "Excludes internal test accounts."
"""


def _blob(at: AppTest) -> str:
    parts: list[str] = []
    for group in (at.markdown, at.caption, at.info, at.warning, at.error, at.success, at.text):
        for element in group:
            value = getattr(element, "value", None)
            if isinstance(value, str):
                parts.append(value)
    return "\n".join(parts)


# --- pure helpers ----------------------------------------------------------


def test_the_badge_reads_signed_only_for_a_signature():
    assert status_badge(SIGNED) == "Signed"
    assert status_badge(DRAFT) == "Draft"
    assert status_badge("anything else") == "Draft"


def test_a_divergence_is_any_signed_field_differing_from_the_file():
    metric = load_metrics(ROOT / "config" / "metrics.yaml")[0]
    signed = SignedDefinition(
        metric_id=metric.id,
        definition=metric.definition,
        owner=metric.owner,
        exceptions=metric.exceptions,
        effective_from=metric.effective_from.isoformat(),
        definition_hash="000000000000",
        signed_by="owner",
        signed_role="owner",
        signed_at="2026-11-09T00:00:00Z",
    )
    assert file_diverges(metric, signed) is False
    assert file_diverges(replace(metric, definition="something else"), signed) is True
    assert file_diverges(replace(metric, owner="another-team"), signed) is True
    assert file_diverges(replace(metric, exceptions="excludes trials"), signed) is True
    assert file_diverges(replace(metric, effective_from=date(2026, 1, 1)), signed) is True
    # Nothing was ever signed, so there is nothing to diverge from.
    assert file_diverges(metric, None) is False


def test_a_secret_refusal_names_what_is_missing(env):
    unset = secret_refusal(env.settings, OPERATOR)
    assert unset is not None
    assert unset[0] == "operator_secret_unset"
    assert "operator_secret --init" in unset[1]

    store_secret(env.settings.settings_path, OPERATOR)
    empty = secret_refusal(env.settings, "")
    wrong = secret_refusal(env.settings, "wrong")
    assert (empty is not None and empty[0] == "operator_secret_empty")
    assert (wrong is not None and wrong[0] == "operator_secret_mismatch")
    assert secret_refusal(env.settings, OPERATOR) is None


def test_the_ask_page_offers_no_draft_metric_as_a_chip(env):
    catalogue = effective_catalogue(env.settings)
    signatures = active_signatures(env.settings.audit_path)
    signed = [metric for metric in catalogue if status(metric, signatures) == SIGNED]

    chips = _suggestions_for(env.analyst.allowed_tables, signed)

    assert chips, "the signed revenue definition still gets chips"
    for chip in chips:
        matched = match_metrics(chip, catalogue)
        assert matched, chip
        # Every metric this chip could land on is signed: no chip can only clarify.
        assert all(status(metric, signatures) == SIGNED for metric in matched), chip
    assert not any("daily active" in chip.lower() for chip in chips)
    assert _suggestions_for(env.analyst.allowed_tables, []) == []
    assert all(
        status(metric, signatures) == DRAFT
        for metric in catalogue
        if metric.id in {"dau_by_platform", "dau_by_country"}
    )


# --- the page, driven end to end ------------------------------------------


def _isolate(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SETTINGS_PATH", str(tmp_path / "instance.db"))
    monkeypatch.setenv("KNOWLEDGE_PATH", str(tmp_path / "knowledge"))
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")
    store_secret(tmp_path / "instance.db", OPERATOR)


def _sign_in(at: AppTest, username: str, password: str) -> AppTest:
    at.text_input(key="login_user").set_value(username)
    at.text_input(key="login_password").set_value(password)
    at.button(key="login_submit").click().run(timeout=60)
    if at.session_state.get("user") and len(at.chat_input) == 0 and len(at.sidebar.radio) == 0:
        at.run(timeout=60)
    return at


def test_the_catalogue_page_signs_a_definition_and_the_question_then_answers(
    monkeypatch, tmp_path
):
    _isolate(monkeypatch, tmp_path)
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    at = _sign_in(at, "owner", OPERATOR)
    at.sidebar.radio(key="nav_page").set_value("metrics").run(timeout=60)

    assert any(title.value == "口徑目錄" for title in at.title)
    assert "Sign this definition" in [button.label for button in at.button]

    at.text_area(key="sign_dau_by_platform_definition").set_value(REAL_DEFINITION)
    at.text_input(key="metric_secret_sign_dau_by_platform").set_value(OPERATOR)
    at.button(key="sign_submit_sign_dau_by_platform").click().run(timeout=60)

    assert "Signed the definition for dau_by_platform" in _blob(at)
    signatures = active_signatures(tmp_path / "audit.db")
    assert signatures["dau_by_platform"].definition == REAL_DEFINITION
    assert signatures["dau_by_platform"].signed_by == "owner"

    # The demo beat: sign it, then ask again as a role that may read the table.
    at.button(key="sign_out_metrics").click().run(timeout=60)
    at = _sign_in(at, "growth", "growth")
    at.chat_input[0].set_value(
        "Show daily active users by platform for the last 30 days"
    ).run(timeout=60)
    page = _blob(at)
    assert "no confirmed definition" not in page
    assert at.dataframe, "the signed metric answers with rows"


def test_a_non_admin_sees_the_refusal_and_no_sign_form(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    at = _sign_in(at, "growth", "growth")
    at.sidebar.radio(key="nav_page").set_value("metrics").run(timeout=60)

    assert "The admin capability is not granted to the growth role." in _blob(at)
    assert "Sign this definition" not in [button.label for button in at.button]
    assert at.text_input == []


def test_the_page_reports_a_file_edit_as_not_in_force(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    metrics_path = tmp_path / "metrics.yaml"
    metrics_path.write_text(ONE_METRIC, encoding="utf-8")
    monkeypatch.setenv("METRICS_PATH", str(metrics_path))

    settings = load_settings()
    metric = load_metrics(settings.metrics_path)[0]
    sign(
        audit=AuditLog(settings.audit_path),
        metric=metric,
        definition=metric.definition,
        owner=metric.owner,
        exceptions=metric.exceptions,
        effective_from=metric.effective_from,
        signer=User("owner", "owner", (), ("admin",)),
    )
    metrics_path.write_text(
        ONE_METRIC.replace(
            REAL_DEFINITION,
            "Edited in the file after it was signed.",
        ),
        encoding="utf-8",
    )

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run(timeout=60)
    at = _sign_in(at, "owner", OPERATOR)
    at.sidebar.radio(key="nav_page").set_value("metrics").run(timeout=60)

    page = _blob(at)
    assert "The file has been edited since this definition was signed" in page
    assert "Sign the file version" in [button.label for button in at.button]
    assert "Discard the file edit" in [button.label for button in at.button]
    # Reading the page wrote nothing: the signed text is still in force.
    assert active_signatures(settings.audit_path)["dau_by_platform"].definition == (
        REAL_DEFINITION
    )
