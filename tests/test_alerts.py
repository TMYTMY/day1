"""An alert definition: a draft, its owner's confirmation, and the refusals.

Every refusal has to happen at write time, name the offending field, write one
``alert_refused`` audit row and come back to the caller as a message. A draft
never runs, and only its owner can activate it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import yaml

import src.alerts as alerts_module
from src.alerts import (
    CONFIRMED,
    DRAFT,
    PAUSED,
    SUPERSEDED,
    AlertService,
)
from src.auth import authenticate
from src.capabilities import ALERT, QUERY
from src.config import ROOT, ConfigError, load_settings
from src.metrics import is_placeholder, load_metrics

CATALOGUE = ROOT / "config" / "metrics.yaml"
USERS = ROOT / "config" / "users.yaml"

# A temporary instance: a role that may only read revenue, one that may only
# read daily active users, both holding the alert capability, plus the two
# shipped roles that do not hold it. Small enough to reason about, hard enough
# that each refusal can be isolated.
_TEMP_USERS = """
roles:
  analyst:
    tables: [revenue, dau]
    capabilities: [query, alert]
  revonly:
    tables: [revenue]
    capabilities: [query, alert]
  dauonly:
    tables: [dau]
    capabilities: [query, alert]
  finance:
    tables: [revenue]
    capabilities: [query]
  growth:
    tables: [dau]
    capabilities: [query]

users:
  - username: alex
    password: alex
    role: analyst
  - username: rita
    password: rita
    role: revonly
  - username: dina
    password: dina
    role: dauonly
  - username: finn
    password: finn
    role: finance
  - username: gus
    password: gus
    role: growth
"""

# Two confirmed metric definitions, one on each warehouse table. The shipped
# catalogue's own metrics are tested separately; these keep a permission
# refusal from being mistaken for a placeholder refusal.
_TEMP_METRICS = [
    {
        "id": "revenue_confirmed",
        "title": "Revenue by product",
        "synonyms": ["revenue"],
        "table": "revenue",
        "grain": ["event_date", "product", "region", "channel"],
        "additive_over": ["event_date", "product", "region"],
        "definition": "Recognised revenue in USD, net of cancellations.",
        "owner": "finance-reporting",
        "effective_from": "2026-06-15",
        "supersedes": None,
        "exceptions": "Excludes internal test accounts.",
        # An alert compares a number, so an alertable metric names its measure.
        "measure": "revenue_usd",
    },
    {
        "id": "dau_confirmed",
        "title": "DAU by platform",
        "synonyms": ["daily active users"],
        "table": "dau",
        "grain": ["event_date", "platform", "country"],
        "additive_over": ["event_date", "platform"],
        "definition": "Distinct users with at least one session that day.",
        "owner": "growth-lead",
        "effective_from": "2026-06-15",
        "supersedes": None,
        "exceptions": "Excludes internal test accounts.",
        "measure": "dau",
    },
]


def _write_metrics(tmp_path, entries):
    path = tmp_path / "metrics.yaml"
    path.write_text(
        yaml.safe_dump(entries, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return path


def _write_users(tmp_path):
    path = tmp_path / "users.yaml"
    path.write_text(_TEMP_USERS, encoding="utf-8")
    return path


@pytest.fixture
def instance(env, tmp_path):
    """One instance with its own alert database, catalogue and user directory."""
    metrics_path = _write_metrics(tmp_path, _TEMP_METRICS)
    users_path = _write_users(tmp_path)
    settings = replace(
        env.settings,
        alerts_path=tmp_path / "alerts.db",
        metrics_path=metrics_path,
        users_path=users_path,
    )
    service = AlertService.from_settings(settings, audit=env.audit, catalog=env.catalog)
    return SimpleNamespace(
        settings=settings,
        service=service,
        audit=env.audit,
        users_path=users_path,
        metrics=load_metrics(metrics_path),
        catalog=env.catalog,
        alex=authenticate("alex", "alex", users_path),
        rita=authenticate("rita", "rita", users_path),
        dina=authenticate("dina", "dina", users_path),
        finn=authenticate("finn", "finn", users_path),
        gus=authenticate("gus", "gus", users_path),
    )


@pytest.fixture
def shipped(env, tmp_path):
    """One instance on the shipped catalogue and the shipped user directory."""
    settings = replace(env.settings, alerts_path=tmp_path / "alerts.db")
    service = AlertService.from_settings(settings, audit=env.audit, catalog=env.catalog)
    return SimpleNamespace(
        settings=settings,
        service=service,
        audit=env.audit,
        analyst=env.analyst,
        finance=env.finance,
    )


def _draft(service, owner, **overrides):
    """Draft the happy path, with only the fields a test cares about changed."""
    arguments = {
        "metric_id": "revenue_confirmed",
        "comparison": "below_absolute",
        "constant": 5000,
        "window_days": 7,
        "cadence": "daily",
        "local_time": "09:00",
        "recipients": ["alex"],
    }
    arguments.update(overrides)
    return service.draft(owner, **arguments)


def _rows(path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    conn.close()
    return rows


# --- the instance's own settings -------------------------------------------


def test_the_alert_database_and_window_maximum_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERTS_PATH", str(tmp_path / "company-b" / "alerts.db"))
    monkeypatch.setenv("MAX_ALERT_WINDOW_DAYS", "30")
    settings = load_settings()
    assert settings.alerts_path == tmp_path / "company-b" / "alerts.db"
    assert settings.max_alert_window_days == 30


def test_the_defaults_are_one_year_and_a_file_of_their_own(monkeypatch):
    monkeypatch.delenv("ALERTS_PATH", raising=False)
    monkeypatch.delenv("MAX_ALERT_WINDOW_DAYS", raising=False)
    settings = load_settings()
    assert settings.alerts_path == ROOT / "data" / "alerts.db"
    assert settings.max_alert_window_days == 365
    # Alert data is not the warehouse and not the usage log.
    assert settings.alerts_path not in {settings.db_path, settings.audit_path}


def test_a_nonsense_window_maximum_is_refused_at_startup(monkeypatch):
    monkeypatch.setenv("MAX_ALERT_WINDOW_DAYS", "0")
    with pytest.raises(ConfigError, match="MAX_ALERT_WINDOW_DAYS"):
        load_settings()
    monkeypatch.setenv("MAX_ALERT_WINDOW_DAYS", "a year")
    with pytest.raises(ConfigError, match="MAX_ALERT_WINDOW_DAYS"):
        load_settings()


# --- the capability grant --------------------------------------------------


def test_only_the_analyst_role_holds_the_alert_grant():
    analyst = authenticate("analyst", "analyst", USERS)
    assert analyst is not None
    assert analyst.capabilities == (QUERY, ALERT)
    for name in ("finance", "growth"):
        user = authenticate(name, name, USERS)
        assert user is not None
        assert ALERT not in user.capabilities
        assert QUERY in user.capabilities


def test_a_role_without_the_alert_grant_cannot_draft(shipped):
    result = shipped.service.draft(
        shipped.finance,
        metric_id="revenue_by_product",
        comparison="below_absolute",
        constant=5000,
        window_days=7,
        recipients=["finance"],
    )
    assert result.ok is False
    assert result.field == "capability"
    assert result.reason == "capability_not_granted"
    assert "alert" in result.message and "finance" in result.message
    assert shipped.service.definitions() == []


# --- the placeholder convention --------------------------------------------


def test_the_shipped_catalogue_marks_three_metrics_as_placeholders():
    """Pin the convention the catalogue actually carries, as data.

    Three entries say PLACEHOLDER in their definition text and name
    `placeholder` as owner. `revenue_by_product` carries a real sentence and a
    real owner, so the data test treats it as confirmed — a YAML comment is not
    data, and placeholder detection must not depend on one.
    """
    catalogue = load_metrics(CATALOGUE)
    placeholders = {metric.id for metric in catalogue if is_placeholder(metric)}
    assert placeholders == {"revenue_by_channel", "dau_by_platform", "dau_by_country"}
    confirmed = next(metric for metric in catalogue if metric.id == "revenue_by_product")
    assert is_placeholder(confirmed) is False


def test_placeholder_detection_reads_the_definition_text_or_the_owner(tmp_path):
    entry = dict(_TEMP_METRICS[0])
    path = _write_metrics(
        tmp_path,
        [
            {**entry, "id": "text_marker", "definition": "PLACEHOLDER — 需由業務方確認"},
            {**entry, "id": "owner_marker", "owner": "placeholder"},
            {**entry, "id": "confirmed"},
        ],
    )
    flags = {metric.id: is_placeholder(metric) for metric in load_metrics(path)}
    assert flags == {"text_marker": True, "owner_marker": True, "confirmed": False}


# --- a draft is data that does not run -------------------------------------


def test_a_draft_is_stored_in_the_instance_database_and_never_runs(instance):
    result = _draft(
        instance.service,
        instance.alex,
        comparison="change_pct_down",
        constant=12.5,
        window_days=30,
        cadence="daily",
        local_time="07:30",
        recipients=["alex", "rita"],
    )
    assert result.ok is True
    assert result.field is None and result.reason is None

    definition = result.definition
    assert definition is not None
    assert instance.settings.alerts_path.is_file()
    assert (definition.metric_id, definition.comparison) == ("revenue_confirmed", "change_pct_down")
    assert (definition.constant, definition.window_days) == (12.5, 30)
    assert (definition.cadence, definition.local_time) == ("daily", "07:30")
    assert definition.recipients == ("alex", "rita")
    assert (definition.owner, definition.owner_role) == ("alex", "analyst")

    # Lifecycle: a draft has not been confirmed, so it carries no authority and
    # cannot be evaluated. Nothing in `live()`.
    assert definition.state == DRAFT
    assert definition.is_live is False
    assert definition.effective_from is None
    assert (definition.confirmed_at, definition.confirmed_by) == (None, None)
    assert definition.supersedes is None
    assert instance.service.live() == []
    assert instance.service.definition(definition.id) == definition

    row = _rows(instance.audit.path)[-1]
    assert row["event_type"] == "alert_drafted"
    assert row["capability"] == "alert"
    assert row["status"] == "ok"
    assert row["metric_id"] == "revenue_confirmed"
    assert row["error"] is None


def test_the_owner_confirms_a_draft_into_a_live_definition(instance):
    drafted = _draft(instance.service, instance.alex)
    assert drafted.ok is True

    confirmed = instance.service.confirm(drafted.definition.id, instance.alex)
    assert confirmed.ok is True
    live = confirmed.definition
    assert live is not None
    assert live.state == CONFIRMED
    assert live.is_live is True
    assert live.confirmed_by == "alex"
    assert live.confirmed_at is not None
    assert live.effective_from == datetime.now(timezone.utc).date()
    assert [definition.id for definition in instance.service.live()] == [live.id]

    row = _rows(instance.audit.path)[-1]
    assert row["event_type"] == "alert_confirmed"
    assert row["capability"] == "alert"
    assert row["status"] == "ok"
    assert row["error"] is None


def test_confirmation_by_anybody_else_is_refused_naming_the_owner(instance):
    drafted = _draft(instance.service, instance.alex)
    # rita holds the alert capability and may read revenue, so the only thing
    # wrong with this confirmation is that she is not the owner.
    result = instance.service.confirm(drafted.definition.id, instance.rita)

    assert result.ok is False
    assert result.field == "owner"
    assert result.reason == "not_owner"
    assert "alex" in result.message
    assert "owner" in result.message
    assert instance.service.definition(drafted.definition.id).state == DRAFT
    assert instance.service.live() == []

    row = _rows(instance.audit.path)[-1]
    assert row["event_type"] == "alert_refused"
    assert row["capability"] == "alert"
    assert row["status"] == "denied"
    assert row["error"].startswith("not_owner")


def test_a_definition_cannot_be_confirmed_twice(instance):
    drafted = _draft(instance.service, instance.alex)
    assert instance.service.confirm(drafted.definition.id, instance.alex).ok is True

    again = instance.service.confirm(drafted.definition.id, instance.alex)
    assert again.ok is False
    assert again.field == "state"
    assert again.reason == "state_not_draft"
    assert "confirmed" in again.message
    assert len(instance.service.live()) == 1


def test_an_unknown_alert_definition_is_refused_and_audited(instance):
    result = instance.service.confirm(404, instance.alex)
    assert result.ok is False
    assert result.field == "alert"
    assert result.reason == "alert_unknown"
    assert "404" in result.message
    row = _rows(instance.audit.path)[-1]
    assert row["event_type"] == "alert_refused" and row["capability"] == "alert"


# --- refusals at write time ------------------------------------------------


def test_a_placeholder_metric_is_refused_when_the_draft_is_written(shipped):
    result = shipped.service.draft(
        shipped.analyst,
        metric_id="dau_by_platform",
        comparison="below_absolute",
        constant=1000,
        window_days=7,
        recipients=["analyst"],
    )
    assert result.ok is False
    assert result.field == "metric"
    assert result.reason == "metric_placeholder"
    assert "placeholder" in result.message
    assert "DAU by platform" in result.message
    # Nothing was written: a refused draft is not left behind for a later reader.
    assert shipped.service.definitions() == []

    row = _rows(shipped.audit.path)[-1]
    assert row["event_type"] == "alert_refused"
    assert row["capability"] == "alert"
    assert row["status"] == "denied"
    assert row["error"].startswith("metric_placeholder")


def test_a_metric_that_becomes_a_placeholder_cannot_be_confirmed(instance):
    drafted = _draft(instance.service, instance.alex)
    assert drafted.ok is True

    # The same store and the same user, but the catalogue now marks the metric
    # unconfirmed. Confirmation re-checks the definition, so it is refused.
    placeholder_catalogue = [
        replace(metric, definition="PLACEHOLDER — 需由業務方確認")
        if metric.id == "revenue_confirmed"
        else metric
        for metric in instance.metrics
    ]
    changed = AlertService(
        store=instance.service.store,
        audit=instance.audit,
        catalog=instance.catalog,
        metrics=placeholder_catalogue,
        users_path=instance.users_path,
        max_window_days=365,
    )
    result = changed.confirm(drafted.definition.id, instance.alex)

    assert result.ok is False
    assert result.field == "metric"
    assert result.reason == "metric_placeholder"
    assert instance.service.definition(drafted.definition.id).state == DRAFT


def test_a_window_beyond_the_maximum_is_refused_naming_the_maximum(instance):
    result = _draft(instance.service, instance.alex, window_days=366)
    assert result.ok is False
    assert result.field == "window"
    assert result.reason == "window_too_long"
    assert "366" in result.message
    assert "365" in result.message
    assert "maximum" in result.message
    assert instance.service.definitions() == []

    row = _rows(instance.audit.path)[-1]
    assert row["event_type"] == "alert_refused"
    assert row["error"].startswith("window_too_long")


def test_a_window_is_refused_rather_than_clamped(instance):
    """A shorter maximum is refused and the number is never shortened."""
    short = AlertService(
        store=instance.service.store,
        audit=instance.audit,
        catalog=instance.catalog,
        metrics=instance.metrics,
        users_path=instance.users_path,
        max_window_days=30,
    )
    refused = _draft(short, instance.alex, window_days=31)
    assert refused.ok is False
    assert "31" in refused.message and "30" in refused.message
    assert instance.service.definitions() == []

    accepted = _draft(short, instance.alex, window_days=30)
    assert accepted.ok is True
    assert accepted.definition is not None
    assert accepted.definition.window_days == 30


def test_a_window_shorter_than_one_day_is_refused(instance):
    result = _draft(instance.service, instance.alex, window_days=0)
    assert result.ok is False
    assert result.field == "window"
    assert result.reason == "window_invalid"
    assert instance.service.definitions() == []


def test_a_metric_the_owner_cannot_read_is_refused_naming_the_topic(instance):
    result = _draft(
        instance.service, instance.rita, metric_id="dau_confirmed", recipients=["rita"]
    )
    assert result.ok is False
    assert result.field == "metric"
    assert result.reason == "table_not_allowed"
    # The refusal names the topic a person knows, not the warehouse table id.
    assert "Daily active users" in result.message
    assert "revonly" in result.message
    assert "dau" not in result.message
    assert instance.service.definitions() == []


def test_a_recipient_who_cannot_read_the_metric_is_refused(instance):
    # dina holds the alert capability but may only read daily active users.
    result = _draft(instance.service, instance.alex, recipients=["alex", "dina"])
    assert result.ok is False
    assert result.field == "recipient"
    assert result.reason == "recipient_not_readable"
    assert "dina" in result.message
    assert "Revenue is outside the dauonly role" in result.message
    assert instance.service.definitions() == []


def test_a_recipient_without_the_alert_capability_is_refused(instance):
    result = _draft(instance.service, instance.alex, recipients=["finn"])
    assert result.ok is False
    assert result.field == "recipient"
    assert result.reason == "recipient_no_capability"
    assert "finn" in result.message and "alert capability" in result.message


def test_an_unknown_recipient_is_refused(instance):
    result = _draft(instance.service, instance.alex, recipients=["nobody"])
    assert result.ok is False
    assert result.field == "recipient"
    assert result.reason == "recipient_unknown"
    assert "nobody" in result.message


def test_an_empty_recipient_list_is_refused(instance):
    result = _draft(instance.service, instance.alex, recipients=[])
    assert result.ok is False
    assert result.field == "recipients"
    assert result.reason == "recipients_empty"
    assert "recipients" in result.message


def test_an_unknown_comparison_is_refused(instance):
    result = _draft(instance.service, instance.alex, comparison="below_a_bit")
    assert result.ok is False
    assert result.field == "comparison"
    assert result.reason == "comparison_unknown"
    assert "below_a_bit" in result.message
    for kind in ("below_absolute", "above_absolute", "change_pct_down", "change_pct_up"):
        assert kind in result.message


def test_a_non_numeric_constant_is_refused(instance):
    result = _draft(instance.service, instance.alex, constant="five thousand")
    assert result.ok is False
    assert result.field == "constant"
    assert result.reason == "constant_invalid"
    assert "constant" in result.message


def test_an_unknown_cadence_and_a_malformed_local_time_are_refused(instance):
    cadence = _draft(instance.service, instance.alex, cadence="weekly")
    assert cadence.ok is False
    assert cadence.field == "cadence"
    assert cadence.reason == "cadence_unknown"

    local_time = _draft(instance.service, instance.alex, local_time="9am")
    assert local_time.ok is False
    assert local_time.field == "local_time"
    assert local_time.reason == "local_time_invalid"
    assert instance.service.definitions() == []


def test_every_refusal_is_audited_once_and_returned(instance, shipped):
    """The five refusals the ticket names, each audited and each returned."""
    to_confirm = _draft(instance.service, instance.alex, metric_id="revenue_confirmed")
    assert to_confirm.ok is True and to_confirm.definition is not None

    cases = {
        "placeholder metric": lambda: shipped.service.draft(
            shipped.analyst,
            metric_id="dau_by_platform",
            comparison="below_absolute",
            constant=1,
            window_days=7,
            recipients=["analyst"],
        ),
        "window beyond the maximum": lambda: _draft(
            instance.service, instance.alex, window_days=4000
        ),
        "metric the owner cannot read": lambda: _draft(
            instance.service, instance.rita, metric_id="dau_confirmed", recipients=["rita"]
        ),
        "recipient without access": lambda: _draft(
            instance.service, instance.alex, recipients=["dina"]
        ),
        "non-owner confirmation": lambda: instance.service.confirm(
            to_confirm.definition.id, instance.rita
        ),
    }

    for name, call in cases.items():
        before = len(_rows(instance.audit.path))
        result = call()
        assert result.ok is False, name
        assert result.message, name
        assert result.field, name
        assert result.audited is True, name

        rows = _rows(instance.audit.path)
        assert len(rows) == before + 1, name
        row = rows[-1]
        assert row["event_type"] == "alert_refused", name
        assert row["capability"] == "alert", name
        assert row["status"] == "denied", name
        assert row["error"].startswith(result.reason), name


# --- supersession ----------------------------------------------------------


def test_superseding_writes_a_draft_that_must_be_confirmed_again(instance):
    first = _draft(instance.service, instance.alex, constant=5000)
    assert instance.service.confirm(first.definition.id, instance.alex).ok is True

    second = _draft(instance.service, instance.alex, constant=4000, supersedes=first.definition.id)
    assert second.ok is True
    assert second.definition.state == DRAFT
    assert second.definition.supersedes == first.definition.id
    # The live version keeps running while the replacement waits for a human.
    assert instance.service.definition(first.definition.id).state == CONFIRMED
    assert [definition.id for definition in instance.service.live()] == [first.definition.id]

    confirmed = instance.service.confirm(second.definition.id, instance.alex)
    assert confirmed.ok is True
    assert confirmed.definition.is_live is True

    previous = instance.service.definition(first.definition.id)
    assert previous.state == SUPERSEDED
    assert previous.superseded_by == second.definition.id
    # The record of who confirmed it, and when, survives the supersession.
    assert previous.confirmed_by == "alex"
    assert previous.confirmed_at is not None
    assert [definition.id for definition in instance.service.live()] == [second.definition.id]
    # Nothing was deleted: the history is two rows.
    assert len(instance.service.definitions(owner="alex")) == 2


def test_a_definition_owned_by_somebody_else_cannot_be_superseded(instance):
    rita_draft = _draft(instance.service, instance.rita, recipients=["rita"])
    assert instance.service.confirm(rita_draft.definition.id, instance.rita).ok is True

    result = _draft(instance.service, instance.alex, supersedes=rita_draft.definition.id)
    assert result.ok is False
    assert result.field == "owner"
    assert result.reason == "owner_mismatch"
    assert "rita" in result.message
    assert instance.service.definition(rita_draft.definition.id).state == CONFIRMED


def test_an_unconfirmed_definition_cannot_be_superseded(instance):
    drafted = _draft(instance.service, instance.alex)
    result = _draft(instance.service, instance.alex, supersedes=drafted.definition.id)
    assert result.ok is False
    assert result.field == "supersedes"
    assert result.reason == "supersedes_not_confirmed"


def test_two_drafts_cannot_both_replace_the_same_definition(instance):
    first = _draft(instance.service, instance.alex, constant=5000)
    assert instance.service.confirm(first.definition.id, instance.alex).ok is True

    replacement = _draft(instance.service, instance.alex, constant=4000, supersedes=first.definition.id)
    rival = _draft(instance.service, instance.alex, constant=3000, supersedes=first.definition.id)
    assert instance.service.confirm(replacement.definition.id, instance.alex).ok is True

    refused = instance.service.confirm(rival.definition.id, instance.alex)
    assert refused.ok is False
    assert refused.field == "supersedes"
    assert refused.reason == "supersedes_already_replaced"
    assert instance.service.definition(first.definition.id).superseded_by == replacement.definition.id
    assert instance.service.definition(rival.definition.id).state == DRAFT


# --- no model anywhere in this path ---------------------------------------


def test_the_definition_path_calls_no_language_model(instance, monkeypatch):
    """ADR 0003: a model may author a definition, never execute one."""

    def explode(*args, **kwargs):  # pragma: no cover - only runs on a regression
        raise AssertionError("an alert definition must not call a language model")

    monkeypatch.setattr("src.llm.LlmClient.complete", explode)
    monkeypatch.setattr("src.llm.LlmClient.summarize", explode, raising=False)
    assert not hasattr(alerts_module, "LlmClient")

    drafted = _draft(instance.service, instance.alex)
    assert drafted.ok is True
    assert instance.service.confirm(drafted.definition.id, instance.alex).ok is True


# --- pausing a live definition -------------------------------------------


def test_a_paused_definition_is_no_longer_live(instance):
    drafted = _draft(instance.service, instance.alex)
    instance.service.confirm(drafted.definition.id, instance.alex)
    assert len(instance.service.live()) == 1

    result = instance.service.pause(drafted.definition.id, instance.alex)
    assert result.ok is True
    assert instance.service.definition(drafted.definition.id).state == PAUSED
    assert instance.service.live() == []

    row = _rows(instance.audit.path)[-1]
    assert row["event_type"] == "alert_paused"
    assert row["capability"] == "alert"


def test_only_the_owner_may_pause_a_definition(instance):
    drafted = _draft(instance.service, instance.alex)
    instance.service.confirm(drafted.definition.id, instance.alex)

    result = instance.service.pause(drafted.definition.id, instance.rita)
    assert result.ok is False
    assert result.field == "owner"
    assert result.reason == "not_owner"
    assert instance.service.definition(drafted.definition.id).state == CONFIRMED
    assert len(instance.service.live()) == 1


def test_resuming_brings_the_definition_back(instance):
    drafted = _draft(instance.service, instance.alex)
    instance.service.confirm(drafted.definition.id, instance.alex)
    instance.service.pause(drafted.definition.id, instance.alex)

    result = instance.service.resume(drafted.definition.id, instance.alex)
    assert result.ok is True
    assert instance.service.definition(drafted.definition.id).state == CONFIRMED
    assert len(instance.service.live()) == 1


def test_a_draft_cannot_be_paused(instance):
    drafted = _draft(instance.service, instance.alex)
    result = instance.service.pause(drafted.definition.id, instance.alex)
    assert result.ok is False
    assert result.field == "state"
    assert result.reason == "state_not_confirmed"
