"""The definition sign-off store, the answer-path refusal, and the one door.

A number is only issued against a definition a human signed. These tests pin
the four ways that claim could quietly stop being true:

1. an unsigned metric answering anyway,
2. a signed metric not answering,
3. a file edit changing what answers without a signature,
4. a signature written without the authority to write it, or without its
   audit row.

They also pin the shape of the seam: one catalogue accessor for the app, the
pipeline and the alert service, and one authority for "is this confirmed".
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import date

import pytest

from src.audit import AuditLog
from src.capabilities import ADMIN
from src.config import ROOT
from src.metric_signatures import (
    DRAFT,
    active_signatures,
    effective_catalogue,
    sign,
    status,
)
from src.metrics import definition_hash, load_metrics
from src.metrics_page import file_diverges, submit_signature
from src.models import User
from src.operator_secret import store_secret
from src.pipeline import answer_question

CATALOGUE = ROOT / "config" / "metrics.yaml"
QUESTION = "Show daily active users by platform for the last 30 days"
REAL_DEFINITION = "Distinct users with at least one session that day, per platform."
OPERATOR_SECRET = "day1-signoff-operator-secret-8821"


class _Off:
    """A local-mode client: the planner writes the SQL, no model is called."""

    configured = False
    model = "local"

    def complete(self, messages):
        raise AssertionError("local mode must not call the language model")


class _Counting:
    """A model client that counts calls and never answers one."""

    configured = True
    model = "stub"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        raise AssertionError("a draft definition must not reach the model")


def _operator() -> User:
    return User(username="owner", role="owner", allowed_tables=(), capabilities=(ADMIN,))


def _fresh(env, tmp_path, name="instance"):
    """An instance with its own catalogue copy, audit database and secret store.

    Copying the shipped file keeps these tests about the store rather than
    about the checkout: nothing here writes ``config/metrics.yaml``.
    """
    metrics_path = tmp_path / f"{name}-metrics.yaml"
    metrics_path.write_text(CATALOGUE.read_text(encoding="utf-8"), encoding="utf-8")
    settings = replace(
        env.settings,
        metrics_path=metrics_path,
        audit_path=tmp_path / f"{name}-audit.db",
        settings_path=tmp_path / f"{name}-instance.db",
    )
    return settings, AuditLog(settings.audit_path)


def _metric(settings, metric_id):
    return next(item for item in load_metrics(settings.metrics_path) if item.id == metric_id)


def _ask(env, settings, audit, question=QUESTION, llm=None, user=None):
    return answer_question(
        question,
        user or env.analyst,
        settings=settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=audit,
        llm=llm or _Off(),
    )


def _rows(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


# --- 1. unsigned refuses ---------------------------------------------------


def test_an_unsigned_definition_refuses_the_question(env, tmp_path):
    settings, audit = _fresh(env, tmp_path)
    draft = _metric(settings, "dau_by_platform")
    llm = _Counting()

    answer = _ask(env, settings, audit, llm=llm)

    assert answer.status == "clarify"
    assert answer.sql is None
    assert "no confirmed definition" in answer.message
    assert f"Owner: {draft.owner}" in answer.message
    assert "口徑目錄" in answer.message and "admin" in answer.message
    assert "Nothing was queried" in answer.message
    # No SQL, no model call, no rows read.
    assert llm.calls == 0
    assert answer.rows == []

    row = _rows(audit.path)[-1]
    assert row["event_type"] == "question"
    assert row["status"] == "clarify"
    assert row["metric_id"] == "dau_by_platform"
    assert row["sql"] is None
    # The hash recorded is the draft that was refused, so the audit can say
    # exactly which unconfirmed text a number was asked for.
    assert row["definition_hash"] == definition_hash(draft)


# --- 2. signed answers -----------------------------------------------------


def test_a_signed_definition_answers_with_the_signed_hash(env, tmp_path):
    settings, audit = _fresh(env, tmp_path)
    draft = _metric(settings, "dau_by_platform")
    record = sign(
        audit=audit,
        metric=draft,
        definition=REAL_DEFINITION,
        owner="growth-lead",
        exceptions="Excludes internal test accounts.",
        effective_from=date(2026, 6, 15),
        signer=_operator(),
    )

    answer = _ask(env, settings, audit)

    assert answer.status == "ok"
    assert answer.rows
    assert answer.metric_id == "dau_by_platform"
    row = _rows(audit.path)[-1]
    assert row["status"] == "ok"
    assert row["definition_hash"] == record.definition_hash
    assert row["definition_hash"] != definition_hash(draft)


# --- 3. the hash is the binding -------------------------------------------


def test_the_signed_text_is_in_force_and_a_file_edit_is_not(env, tmp_path):
    settings, audit = _fresh(env, tmp_path)
    draft = _metric(settings, "dau_by_platform")
    signed_text = "Distinct users active on that day, per platform (signed A)."
    sign(
        audit=audit,
        metric=draft,
        definition=signed_text,
        owner="growth-lead",
        exceptions="Excludes internal test accounts.",
        effective_from=date(2026, 6, 15),
        signer=_operator(),
    )

    def effective(settings, metric_id):
        return next(
            item for item in effective_catalogue(settings) if item.id == metric_id
        )

    # Signed text A is what answers.
    assert effective(settings, "dau_by_platform").definition == signed_text
    first = _ask(env, settings, audit)
    assert first.status == "ok"
    first_hash = _rows(audit.path)[-1]["definition_hash"]

    # A file edit is a different definition, and the file is only the draft.
    file_text = "Distinct users active on that day (edited to B)."
    source = settings.metrics_path.read_text(encoding="utf-8")
    edited = source.replace('definition: "PLACEHOLDER — 需由業務方確認"', f'definition: "{file_text}"', 1)
    assert edited != source
    settings.metrics_path.write_text(edited, encoding="utf-8")

    signatures = active_signatures(audit.path)
    file_metric = _metric(settings, "dau_by_platform")
    assert status(file_metric, signatures) == DRAFT
    assert file_diverges(file_metric, signatures["dau_by_platform"]) is True
    # The effective catalogue did not follow the edit, so the answers do not either.
    assert effective(settings, "dau_by_platform").definition == signed_text
    second = _ask(env, settings, audit)
    assert second.status == "ok"
    assert _rows(audit.path)[-1]["definition_hash"] == first_hash

    # Signing the file's version is what puts B in force.
    sign(
        audit=audit,
        metric=file_metric,
        definition=file_text,
        owner=file_metric.owner,
        exceptions=file_metric.exceptions,
        effective_from=file_metric.effective_from,
        signer=_operator(),
    )
    assert effective(settings, "dau_by_platform").definition == file_text
    third = _ask(env, settings, audit)
    assert third.status == "ok"
    assert _rows(audit.path)[-1]["definition_hash"] != first_hash


# --- 4. only admin signs ---------------------------------------------------


def test_a_role_without_admin_cannot_sign_and_no_row_is_written(env, tmp_path):
    settings, audit = _fresh(env, tmp_path)
    draft = _metric(settings, "dau_by_platform")
    store_secret(settings.settings_path, OPERATOR_SECRET)

    outcome = submit_signature(
        metric=draft,
        definition=REAL_DEFINITION,
        exceptions="",
        owner="growth-lead",
        effective_from="2026-06-15",
        secret=OPERATOR_SECRET,
        user=env.growth,
        settings=settings,
        audit=audit,
    )

    assert outcome.ok is False
    assert "admin" in outcome.message
    assert active_signatures(audit.path) == {}
    row = _rows(audit.path)[-1]
    assert row["event_type"] == "settings_refused"
    assert row["status"] == "denied"
    assert row["error"] == "capability_not_granted"
    assert row["metric_id"] == "dau_by_platform"


# --- 5. the secret is required --------------------------------------------


def test_the_operator_secret_is_required_and_good_secret_signs_once(env, tmp_path):
    settings, audit = _fresh(env, tmp_path)
    draft = _metric(settings, "dau_by_platform")

    # No secret on the instance at all: nothing is written but the refusal.
    unset = submit_signature(
        metric=draft,
        definition=REAL_DEFINITION,
        exceptions="",
        owner="growth-lead",
        effective_from="2026-06-15",
        secret="anything",
        user=_operator(),
        settings=settings,
        audit=audit,
    )
    assert unset.ok is False
    assert _rows(audit.path)[-1]["error"] == "operator_secret_unset"
    assert active_signatures(audit.path) == {}

    store_secret(settings.settings_path, OPERATOR_SECRET)

    empty = submit_signature(
        metric=draft,
        definition=REAL_DEFINITION,
        exceptions="",
        owner="growth-lead",
        effective_from="2026-06-15",
        secret="",
        user=_operator(),
        settings=settings,
        audit=audit,
    )
    assert empty.ok is False
    assert _rows(audit.path)[-1]["error"] == "operator_secret_empty"

    wrong = submit_signature(
        metric=draft,
        definition=REAL_DEFINITION,
        exceptions="",
        owner="growth-lead",
        effective_from="2026-06-15",
        secret="not-the-secret",
        user=_operator(),
        settings=settings,
        audit=audit,
    )
    assert wrong.ok is False
    assert _rows(audit.path)[-1]["error"] == "operator_secret_mismatch"
    assert active_signatures(audit.path) == {}

    good = submit_signature(
        metric=draft,
        definition=REAL_DEFINITION,
        exceptions="Excludes internal test accounts.",
        owner="growth-lead",
        effective_from="2026-06-15",
        secret=OPERATOR_SECRET,
        user=_operator(),
        settings=settings,
        audit=audit,
    )

    assert good.ok is True
    signatures = active_signatures(audit.path)
    assert list(signatures) == ["dau_by_platform"]
    assert signatures["dau_by_platform"].definition == REAL_DEFINITION
    assert signatures["dau_by_platform"].signed_by == "owner"

    signed_rows = [row for row in _rows(audit.path) if row["event_type"] == "metric_signed"]
    assert len(signed_rows) == 1
    signed_row = signed_rows[0]
    assert signed_row["capability"] == ADMIN
    assert signed_row["status"] == "ok"
    assert signed_row["metric_id"] == "dau_by_platform"
    assert signed_row["definition_hash"] == signatures["dau_by_platform"].definition_hash
    assert signed_row["username"] == "owner"
    assert signed_row["question"] == "Confirmed the definition for dau_by_platform"
    # Four attempts, four rows: three refusals and one signature.
    assert len(_rows(audit.path)) == 4


# --- 6. one transaction ----------------------------------------------------


def test_an_audit_failure_leaves_no_signature_row(env, tmp_path, monkeypatch):
    settings, audit = _fresh(env, tmp_path)
    draft = _metric(settings, "dau_by_platform")

    def unavailable(**kwargs):
        raise sqlite3.Error("the usage log is unavailable")

    monkeypatch.setattr(audit, "record_event", unavailable)

    with pytest.raises(sqlite3.Error):
        sign(
            audit=audit,
            metric=draft,
            definition=REAL_DEFINITION,
            owner="growth-lead",
            exceptions="",
            effective_from=date(2026, 6, 15),
            signer=_operator(),
        )
    assert active_signatures(audit.path) == {}

    # Through the page's seam the failure is a message, and still no row.
    store_secret(settings.settings_path, OPERATOR_SECRET)
    outcome = submit_signature(
        metric=draft,
        definition=REAL_DEFINITION,
        exceptions="",
        owner="growth-lead",
        effective_from="2026-06-15",
        secret=OPERATOR_SECRET,
        user=_operator(),
        settings=settings,
        audit=audit,
    )
    assert outcome.ok is False
    assert "nothing changed" in outcome.message
    assert active_signatures(audit.path) == {}


# --- 7. one door -----------------------------------------------------------


def test_the_three_readers_go_through_the_effective_catalogue():
    """No reader loads the file directly: signatures would be invisible."""
    for name in ("app.py", "src/pipeline.py", "src/alerts.py"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "load_metrics(" not in text, name
        assert "effective_catalogue(" in text, name


# --- 8. alerts unchanged, one authority -----------------------------------


def test_an_unsigned_metric_still_cannot_carry_an_alert(env, tmp_path):
    settings, audit = _fresh(env, tmp_path)
    service = _alert_service(settings, audit)

    result = service.draft(
        env.analyst,
        metric_id="dau_by_platform",
        comparison="below_absolute",
        constant=1000,
        window_days=7,
        recipients=["analyst"],
    )

    assert result.ok is False
    assert result.field == "metric"
    assert result.reason == "metric_placeholder"


def test_is_placeholder_has_no_consumer_outside_its_own_module():
    """The file's wording describes the file; the signature decides."""
    for path in sorted((ROOT / "src").rglob("*.py")):
        if path.name == "metrics.py":
            continue
        assert "is_placeholder" not in path.read_text(encoding="utf-8"), path


def _alert_service(settings, audit):
    from src.alerts import AlertService
    from src.routing import load_catalog

    catalog = load_catalog(ROOT / "config" / "routing.yaml")
    return AlertService.from_settings(settings, audit=audit, catalog=catalog)
