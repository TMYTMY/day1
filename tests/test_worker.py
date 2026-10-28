"""The worker: one tick, one window, one fire, one audit event each.

Every test runs against a temporary warehouse, a temporary alert database and a
temporary usage log, with a fixed clock. Nothing sleeps, nothing listens, and
nothing reaches the network. The numbers a test asserts on are read straight
from the warehouse with ``sqlite3``, so the resolver is checked against the
data rather than against itself.
"""

from __future__ import annotations

import sqlite3
from dataclasses import fields, replace
from datetime import date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import src.worker as worker_module
from src.alerts import AlertService
from src.alert_eval import FIRE, evaluate
from src.auth import authenticate
from src.config import ROOT
from src.db.sqlite import SqliteAdapter
from src.fires import FireStore
from src.metrics import load_metrics, measure_column
from src.worker import (
    OUTCOME_DUPLICATE,
    OUTCOME_FAILED,
    OUTCOME_FIRED,
    OUTCOME_INSUFFICIENT,
    OUTCOME_NOT_FIRED,
    OUTCOME_REFUSED,
    OUTCOME_SKIPPED,
    FireOutcome,
    Worker,
    _report,
)

CATALOGUE = ROOT / "config" / "metrics.yaml"
SHIPPED_USERS = ROOT / "config" / "users.yaml"

# Ten past nine on a Wednesday, in the instance's local time. Building the wall
# clock first and converting after keeps "ten past nine local" true in any zone.
_NOW = datetime(2026, 10, 28, 9, 10).astimezone()


def _local(year: int, month: int, day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute).astimezone()


_USERS = """
roles:
  analyst:
    tables: [revenue, dau]
    capabilities: [query, alert]
  growth:
    tables: [dau]
    capabilities: [query]

users:
  - username: alex
    password: alex
    role: analyst
"""

_USERS_WITHOUT_REVENUE = """
roles:
  analyst:
    tables: [dau]
    capabilities: [query, alert]

users:
  - username: alex
    password: alex
    role: analyst
"""


def _entry(**overrides):
    """One confirmed metric on the revenue table, with a measure."""
    entry = {
        "id": "revenue_report",
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
        "measure": "revenue_usd",
    }
    entry.update(overrides)
    return entry


_ENTRIES = [
    _entry(),
    # A confirmed metric with no measure: answerable by a question, not by an alert.
    _entry(id="revenue_unmeasured", synonyms=["unmeasured"], measure=None),
    # A measure that is not a column name: it must never reach a statement.
    _entry(
        id="revenue_bad_measure",
        synonyms=["bad measure"],
        measure="revenue_usd; DROP TABLE revenue",
    ),
]


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def instance(env, tmp_path):
    """One instance with its own alert database, catalogue and user directory."""
    metrics_path = tmp_path / "metrics.yaml"
    _write(metrics_path, yaml.safe_dump(_ENTRIES, allow_unicode=True, sort_keys=False))
    users_path = _write(tmp_path / "users.yaml", _USERS)
    settings = replace(
        env.settings,
        alerts_path=tmp_path / "alerts.db",
        metrics_path=metrics_path,
        users_path=users_path,
    )
    return SimpleNamespace(
        settings=settings,
        service=AlertService.from_settings(settings, audit=env.audit, catalog=env.catalog),
        audit=env.audit,
        adapter=env.adapter,
        catalog=env.catalog,
        metrics_path=metrics_path,
        users_path=users_path,
        alex=authenticate("alex", "alex", users_path),
    )


class _Counting:
    """An adapter that remembers every statement it was asked to run."""

    def __init__(self, inner, *, failures: int = 0):
        self.inner = inner
        self.calls: list[str] = []
        self.failures = failures

    def execute_select(self, sql: str, **kwargs):
        self.calls.append(sql)
        if self.failures:
            self.failures -= 1
            raise RuntimeError("the warehouse is unavailable")
        return self.inner.execute_select(sql, **kwargs)


def _worker(instance, *, now: datetime | None = None, adapter=None, titles=None) -> Worker:
    return Worker(
        service=instance.service,
        adapter=adapter if adapter is not None else instance.adapter,
        fires=FireStore(instance.settings.alerts_path),
        titles=titles,
        clock=lambda: now or _NOW,
    )


def _live(instance, **overrides):
    """Draft and confirm one definition as its owner, and return it."""
    arguments = {
        "metric_id": "revenue_report",
        "comparison": "above_absolute",
        "constant": 1.0,
        "window_days": 7,
        "recipients": ["alex"],
    }
    arguments.update(overrides)
    drafted = instance.service.draft(instance.alex, **arguments)
    assert drafted.ok is True, drafted.message
    confirmed = instance.service.confirm(drafted.definition.id, instance.alex)
    assert confirmed.ok is True, confirmed.message
    return confirmed.definition


def _audit_rows(instance) -> list[dict]:
    conn = sqlite3.connect(instance.audit.path)
    conn.row_factory = sqlite3.Row
    rows = [dict(row) for row in conn.execute("SELECT * FROM audit_events ORDER BY id ASC")]
    conn.close()
    return rows


def _fire_rows(instance) -> list[dict]:
    return FireStore(instance.settings.alerts_path).fires()


def _expected_sum(instance, start: date, end: date, *, measure="revenue_usd", table="revenue"):
    """The number a careful person would get: the same SUM, run by hand."""
    conn = sqlite3.connect(f"file:{instance.settings.db_path}?mode=ro", uri=True)
    try:
        row = conn.execute(
            f'SELECT SUM("{measure}") FROM "{table}" '
            "WHERE event_date >= ? AND event_date <= ?",
            (start.isoformat(), end.isoformat()),
        ).fetchone()
    finally:
        conn.close()
    return row[0]


# --- one tick, one evaluation ---------------------------------------------


def test_a_due_live_definition_is_evaluated_and_fires(instance):
    definition = _live(instance, comparison="above_absolute", constant=1.0)

    outcomes = _worker(instance).tick()

    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.outcome == OUTCOME_FIRED, outcome.message
    assert outcome.should_notify is True
    assert outcome.definition.id == definition.id
    assert outcome.alert_id == definition.id
    assert outcome.fire_key == "alert:1:2026-10-27"
    assert (outcome.window_start, outcome.window_end) == (date(2026, 10, 21), date(2026, 10, 27))
    assert outcome.value == pytest.approx(_expected_sum(instance, date(2026, 10, 21), date(2026, 10, 27)))
    assert outcome.verdict == FIRE
    assert outcome.previous is None
    assert outcome.recipients == ("alex",)

    fires = _fire_rows(instance)
    assert len(fires) == 1
    assert fires[0]["fire_key"] == outcome.fire_key
    assert fires[0]["verdict"] == "fire"
    assert fires[0]["value"] == pytest.approx(outcome.value)


def test_the_audit_row_names_the_worker_the_capability_and_the_statement(instance):
    _live(instance)
    _worker(instance).tick()

    row = _audit_rows(instance)[-1]
    assert row["event_type"] == "alert_fired"
    assert row["capability"] == "alert"
    assert row["status"] == "ok"
    assert (row["username"], row["role"]) == ("worker", "system")
    assert row["metric_id"] == "revenue_report"
    assert row["definition_hash"]
    assert row["routed_tables"] == "revenue"
    assert row["question"].count("alert:1:2026-10-27") == 1
    # The statement is in the audit trail, so an automated answer is as
    # traceable as an asked one.
    assert row["sql"].startswith('SELECT SUM("revenue_usd") AS value FROM "revenue"')
    assert "'2026-10-21'" in row["sql"] and "'2026-10-27'" in row["sql"]
    assert row["error"] is None


def test_a_comparison_that_is_not_met_is_still_recorded(instance):
    _live(instance, comparison="above_absolute", constant=10**12)

    outcome = _worker(instance).tick()[0]

    assert outcome.outcome == OUTCOME_NOT_FIRED
    assert outcome.should_notify is False
    assert outcome.verdict == "no_fire"
    assert _fire_rows(instance)[0]["verdict"] == "no_fire"
    row = _audit_rows(instance)[-1]
    assert row["event_type"] == "alert_not_fired"
    assert row["status"] == "ok"


def test_the_value_is_summed_over_the_window_and_no_wider(instance):
    """A 1-day window is one day of revenue, not the whole table."""
    _live(instance, window_days=1)

    # The demo warehouse stops a few days before today, so the clock is set to
    # a day whose window ends on data.
    outcome = _worker(instance, now=_local(2026, 10, 26, 9, 10)).tick()[0]

    assert outcome.window_start == outcome.window_end == date(2026, 10, 25)
    one_day = _expected_sum(instance, date(2026, 10, 25), date(2026, 10, 25))
    assert one_day is not None
    assert outcome.value == pytest.approx(one_day)
    assert outcome.value < _expected_sum(instance, date(2026, 10, 1), date(2026, 10, 25))


def test_a_percentage_comparison_needs_a_previous_window_and_says_so(instance):
    _live(instance, comparison="change_pct_down", constant=12.5)

    first = _worker(instance).tick()[0]

    assert first.outcome == OUTCOME_INSUFFICIENT
    assert first.verdict == "insufficient_data"
    assert first.should_notify is False
    assert first.previous is None
    # Not a zero, and not a guess: the fire is recorded as unevaluated data.
    assert first.value is not None
    assert _fire_rows(instance)[0]["verdict"] == "insufficient_data"
    assert _audit_rows(instance)[-1]["event_type"] == "alert_insufficient_data"

    tomorrow = _worker(instance, now=_local(2026, 10, 29, 9, 10)).tick()[0]

    assert tomorrow.fire_key != first.fire_key
    assert tomorrow.window_end == date(2026, 10, 28)
    assert tomorrow.previous == pytest.approx(first.value)
    assert tomorrow.previous_window_end == first.window_end
    assert tomorrow.verdict == evaluate(
        tomorrow.value, first.value, "change_pct_down", 12.5
    )
    assert tomorrow.outcome != OUTCOME_INSUFFICIENT


def test_a_window_with_no_rows_at_all_is_insufficient_data(instance):
    """A window before the data starts has no sum, and a missing sum is not zero."""
    _live(instance, comparison="below_absolute", constant=1.0)

    outcome = _worker(instance, now=_local(2020, 1, 2, 9, 10)).tick()[0]

    assert outcome.value is None
    assert outcome.outcome == OUTCOME_INSUFFICIENT
    assert outcome.should_notify is False


# --- the fire key: at most once per window --------------------------------


def test_a_second_tick_for_the_same_window_evaluates_nothing(instance):
    _live(instance)
    counting = _Counting(instance.adapter)
    worker = _worker(instance, adapter=counting)
    first = worker.tick()[0]
    assert first.outcome == OUTCOME_FIRED
    assert len(counting.calls) == 1

    second = worker.tick()[0]

    assert second.outcome == OUTCOME_DUPLICATE
    assert second.fire_key == first.fire_key
    assert second.should_notify is False
    # Nothing was read from the warehouse the second time.
    assert len(counting.calls) == 1
    assert len(_fire_rows(instance)) == 1
    assert _fire_rows(instance)[0]["value"] == pytest.approx(first.value)

    rows = _audit_rows(instance)
    assert [row["event_type"] for row in rows].count("alert_fired") == 1
    assert rows[-1]["event_type"] == "alert_duplicate"
    assert rows[-1]["status"] == "ok"


def test_the_fire_key_survives_a_restart(instance):
    _live(instance)
    _worker(instance).tick()

    # A new process: a new service, a new fire store, a new adapter, the same
    # files. The window is still the same window.
    restarted = Worker(
        service=AlertService.from_settings(
            instance.settings, audit=instance.audit, catalog=instance.catalog
        ),
        adapter=SqliteAdapter(instance.settings.db_path),
        fires=FireStore(instance.settings.alerts_path),
        clock=lambda: _NOW,
    )
    outcomes = restarted.tick()

    assert [outcome.outcome for outcome in outcomes] == [OUTCOME_DUPLICATE]
    assert len(_fire_rows(instance)) == 1
    assert [row["event_type"] for row in _audit_rows(instance)].count("alert_fired") == 1


def test_the_unique_constraint_is_what_refuses_a_second_claim(instance):
    """The duplicate guard is in the database, not in the worker's memory."""
    store = FireStore(instance.settings.alerts_path)
    arguments = {
        "fire_key": "alert:1:2026-10-27",
        "alert_id": 1,
        "window_start": date(2026, 10, 21),
        "window_end": date(2026, 10, 27),
        "at": "2026-10-28T09:10:00Z",
    }
    assert store.claim(**arguments) is True
    assert store.claim(**arguments) is False

    conn = sqlite3.connect(instance.settings.alerts_path)
    index = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'alert_fires'"
    ).fetchone()[0]
    conn.close()
    assert "UNIQUE (fire_key)" in index


def test_two_claims_racing_on_one_window_produce_one_winner(instance):
    """A double launch is two processes, so the test uses two threads."""
    from concurrent.futures import ThreadPoolExecutor

    store = FireStore(instance.settings.alerts_path)

    def claim() -> bool:
        return store.claim(
            fire_key="alert:1:2026-10-27",
            alert_id=1,
            window_start=date(2026, 10, 21),
            window_end=date(2026, 10, 27),
            at="2026-10-28T09:10:00Z",
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        won = list(pool.map(lambda _: claim(), range(5)))

    assert won.count(True) == 1
    assert len(_fire_rows(instance)) == 1


def test_a_different_window_is_a_different_fire(instance):
    _live(instance, comparison="above_absolute", constant=1.0)
    today = _worker(instance).tick()[0]
    tomorrow = _worker(instance, now=_local(2026, 10, 29, 9, 10)).tick()[0]

    assert today.outcome == OUTCOME_FIRED
    assert tomorrow.outcome == OUTCOME_FIRED
    assert today.fire_key != tomorrow.fire_key
    assert len(_fire_rows(instance)) == 2


def test_two_ticks_before_the_local_time_share_one_period(instance):
    _live(instance)
    first = _worker(instance, now=_local(2026, 10, 28, 8, 0)).tick()[0]
    again = _worker(instance, now=_local(2026, 10, 28, 8, 30)).tick()[0]
    evening = _worker(instance, now=_local(2026, 10, 28, 23, 0)).tick()[0]

    assert first.outcome == OUTCOME_FIRED
    assert first.window_end == date(2026, 10, 26)
    assert again.outcome == OUTCOME_DUPLICATE
    # At the definition's local time the next period becomes due, and it is a
    # new window rather than a repeat of the one already evaluated.
    assert evening.outcome == OUTCOME_FIRED
    assert evening.window_end == date(2026, 10, 27)


# --- a paused definition --------------------------------------------------


def test_a_paused_definition_is_skipped_audited_and_never_evaluated(instance):
    definition = _live(instance)
    assert instance.service.pause(definition.id, instance.alex).ok is True
    counting = _Counting(instance.adapter)

    outcomes = _worker(instance, adapter=counting).tick()

    assert [outcome.outcome for outcome in outcomes] == [OUTCOME_SKIPPED]
    assert outcomes[0].should_notify is False
    assert outcomes[0].verdict is None
    # No SQL, and no claim: a paused definition does not consume the window.
    assert counting.calls == []
    assert _fire_rows(instance) == []

    row = _audit_rows(instance)[-1]
    assert row["event_type"] == "alert_skipped"
    assert row["status"] == "skipped"
    assert row["sql"] is None
    assert "skipped" in row["question"]
    assert "paused" in outcomes[0].message


def test_a_resumed_definition_evaluates_the_window_it_skipped(instance):
    definition = _live(instance)
    instance.service.pause(definition.id, instance.alex)
    assert _worker(instance).tick()[0].outcome == OUTCOME_SKIPPED

    instance.service.resume(definition.id, instance.alex)
    outcome = _worker(instance).tick()[0]

    assert outcome.outcome == OUTCOME_FIRED
    assert len(_fire_rows(instance)) == 1


# --- what is considered, and what is not ----------------------------------


def test_a_draft_is_not_considered_and_not_audited(instance):
    drafted = instance.service.draft(
        instance.alex,
        metric_id="revenue_report",
        comparison="above_absolute",
        constant=1.0,
        window_days=7,
        recipients=["alex"],
    )
    assert drafted.ok is True
    before = len(_audit_rows(instance))

    outcomes = _worker(instance).tick()

    assert outcomes == []
    assert len(_audit_rows(instance)) == before
    assert _fire_rows(instance) == []


def test_a_superseded_definition_is_not_considered(instance):
    first = _live(instance, constant=1.0)
    second = _live(instance, constant=2.0, supersedes=first.id)
    assert instance.service.definition(first.id).state == "superseded"
    before = len(_audit_rows(instance))

    outcomes = _worker(instance).tick()

    assert [outcome.alert_id for outcome in outcomes] == [second.id]
    assert len(_audit_rows(instance)) == before + 1


def test_every_considered_definition_writes_exactly_one_event(instance):
    live = _live(instance)
    paused = _live(instance, constant=2.0)
    instance.service.pause(paused.id, instance.alex)
    before = len(_audit_rows(instance))

    outcomes = _worker(instance).tick()

    assert len(outcomes) == 2
    rows = _audit_rows(instance)[before:]
    assert len(rows) == 2
    assert {row["event_type"] for row in rows} == {"alert_fired", "alert_skipped"}
    assert len(_fire_rows(instance)) == 1

    # And a repeat tick still writes one event per definition: two more.
    _worker(instance).tick()
    assert len(_audit_rows(instance)) == before + 4


# --- the permission gate, before any SQL ----------------------------------


def test_a_run_its_owner_may_no_longer_make_is_refused_before_any_sql(instance):
    _live(instance)
    # The role loses the revenue table under a stored definition.
    _write(instance.users_path, _USERS_WITHOUT_REVENUE)
    counting = _Counting(instance.adapter)

    outcome = _worker(instance, adapter=counting).tick()[0]

    assert outcome.outcome == OUTCOME_REFUSED
    assert outcome.should_notify is False
    assert counting.calls == []
    assert _fire_rows(instance) == []
    assert "revenue" in outcome.message

    row = _audit_rows(instance)[-1]
    assert row["event_type"] == "alert_run_refused"
    assert row["status"] == "denied"
    assert row["sql"] is None
    assert row["error"].startswith("table_not_allowed")


def test_an_owner_who_left_the_directory_is_refused(instance):
    _live(instance)
    _write(
        instance.users_path,
        """
roles:
  analyst:
    tables: [revenue]
    capabilities: [query, alert]
users:
  - username: somebody-else
    password: x
    role: analyst
""",
    )
    counting = _Counting(instance.adapter)

    outcome = _worker(instance, adapter=counting).tick()[0]

    assert outcome.outcome == OUTCOME_FAILED
    assert counting.calls == []
    assert _audit_rows(instance)[-1]["error"].startswith("owner_unknown")


def test_the_refusal_names_the_topic_when_the_worker_is_given_the_titles(instance):
    _live(instance)
    _write(instance.users_path, _USERS_WITHOUT_REVENUE)
    titles = {}
    for topic in instance.catalog.topics:
        for table in topic.tables:
            titles.setdefault(table, topic.title)

    outcome = _worker(instance, titles=titles).tick()[0]

    assert "Revenue is outside the analyst role" in outcome.message


# --- a metric with no measure is refused when the draft is written --------


def test_a_metric_with_no_measure_is_refused_when_the_draft_is_written(instance):
    result = instance.service.draft(
        instance.alex,
        metric_id="revenue_unmeasured",
        comparison="above_absolute",
        constant=1.0,
        window_days=7,
        recipients=["alex"],
    )

    assert result.ok is False
    assert result.field == "measure"
    assert result.reason == "metric_no_measure"
    assert "names no measure" in result.message
    assert "Revenue by product" in result.message
    # Nothing was written, and the refusal is audited like any other.
    assert instance.service.definitions() == []
    row = _audit_rows(instance)[-1]
    assert row["event_type"] == "alert_refused"
    assert row["status"] == "denied"
    assert row["error"].startswith("metric_no_measure")


def test_a_measure_that_is_not_a_column_name_is_refused(instance):
    result = instance.service.draft(
        instance.alex,
        metric_id="revenue_bad_measure",
        comparison="above_absolute",
        constant=1.0,
        window_days=7,
        recipients=["alex"],
    )

    assert result.ok is False
    assert result.reason == "metric_no_measure"
    assert instance.service.definitions() == []


def test_the_shipped_catalogue_names_a_measure_on_the_one_metric_it_can_alert_on():
    catalogue = load_metrics(CATALOGUE)
    measures = {metric.id: measure_column(metric) for metric in catalogue}
    assert measures == {
        "revenue_by_product": "revenue_usd",
        "revenue_by_channel": None,
        "dau_by_platform": None,
        "dau_by_country": None,
    }


def test_the_shipped_placeholder_is_still_refused_for_being_a_placeholder(shipped_analyst):
    """The measure check does not displace the refusal a placeholder already has."""
    service, analyst = shipped_analyst
    result = service.draft(
        analyst,
        metric_id="dau_by_platform",
        comparison="above_absolute",
        constant=1.0,
        window_days=7,
        recipients=["analyst"],
    )
    assert result.ok is False
    assert result.reason == "metric_placeholder"


@pytest.fixture
def shipped_analyst(env, tmp_path):
    settings = replace(env.settings, alerts_path=tmp_path / "alerts.db")
    service = AlertService.from_settings(settings, audit=env.audit, catalog=env.catalog)
    return service, authenticate("analyst", "analyst", SHIPPED_USERS)


# --- failure, and what it leaves behind -----------------------------------


def test_a_failed_evaluation_is_released_so_the_next_tick_can_retry(instance):
    _live(instance)
    failing = _Counting(instance.adapter, failures=1)

    failed = _worker(instance, adapter=failing).tick()[0]

    assert failed.outcome == OUTCOME_FAILED
    assert failed.should_notify is False
    assert _fire_rows(instance) == []
    row = _audit_rows(instance)[-1]
    assert row["event_type"] == "alert_failed"
    assert row["status"] == "failed"
    assert row["error"].startswith("evaluation_failed")

    retried = _worker(instance).tick()[0]
    assert retried.outcome == OUTCOME_FIRED


def test_one_broken_definition_does_not_stop_the_others(instance):
    good = _live(instance, constant=1.0)
    bad = _live(instance, constant=2.0)

    adapter = _Counting(instance.adapter, failures=1)
    outcomes = _worker(instance, adapter=adapter).tick()

    assert [outcome.outcome for outcome in outcomes] == [OUTCOME_FAILED, OUTCOME_FIRED]
    assert [outcome.alert_id for outcome in outcomes] == [good.id, bad.id]


# --- no network, no model -------------------------------------------------


def test_the_worker_touches_no_network_and_calls_no_model(instance, monkeypatch):
    """ADR 0003: execution is deterministic, so a tick cannot need either."""

    def offline(*args, **kwargs):  # pragma: no cover - only runs on a regression
        raise AssertionError("the worker must not open a socket")

    def no_model(*args, **kwargs):  # pragma: no cover - only runs on a regression
        raise AssertionError("an alert fire must not call a language model")

    monkeypatch.setattr("socket.socket", offline)
    monkeypatch.setattr("socket.create_connection", offline)
    monkeypatch.setattr("src.llm.LlmClient.complete", no_model)
    monkeypatch.setattr("src.llm.LlmClient.summarize", no_model, raising=False)
    assert not hasattr(worker_module, "LlmClient")
    assert not hasattr(worker_module, "requests")

    _live(instance)
    outcomes = _worker(instance).tick()

    assert outcomes[0].outcome == OUTCOME_FIRED


# --- the hand-off to the notification capability --------------------------


def test_the_outcome_carries_everything_a_notifier_needs(instance):
    _live(instance)
    outcome = _worker(instance).tick()[0]

    declared = {field.name for field in fields(FireOutcome)}
    assert {
        "definition",
        "fire_key",
        "window_start",
        "window_end",
        "value",
        "previous",
        "verdict",
    } <= declared
    # The definition carries the recipients and the comparison the notification
    # body has to name, so nothing has to be re-read to write it.
    assert outcome.definition.recipients == ("alex",)
    assert outcome.definition.comparison == "above_absolute"
    assert outcome.definition.window_days == 7
    assert outcome.metric_title == "Revenue by product"


# --- the command ----------------------------------------------------------


def test_the_command_runs_one_tick_and_exits(instance, monkeypatch, capsys):
    _live(instance)
    for name, value in {
        "DB_PATH": instance.settings.db_path,
        "AUDIT_PATH": instance.settings.audit_path,
        "ALERTS_PATH": instance.settings.alerts_path,
        "METRICS_PATH": instance.metrics_path,
        "USERS_PATH": instance.users_path,
        "ROUTING_PATH": instance.settings.routing_path,
    }.items():
        monkeypatch.setenv(name, str(value))

    code = worker_module.main([])

    assert code == 0
    out = capsys.readouterr().out
    # The command reads the real clock, so the test asserts the shape of the
    # line rather than a date the seed cannot guarantee.
    assert "fired" in out and "alert #1" in out and "alert:1:" in out
    assert [row["event_type"] for row in _audit_rows(instance)][-1] == "alert_fired"
    assert len(_fire_rows(instance)) == 1


def test_the_command_exits_zero_when_nothing_is_due(instance, monkeypatch, capsys):
    for name, value in {
        "DB_PATH": instance.settings.db_path,
        "AUDIT_PATH": instance.settings.audit_path,
        "ALERTS_PATH": instance.settings.alerts_path,
        "METRICS_PATH": instance.metrics_path,
        "USERS_PATH": instance.users_path,
        "ROUTING_PATH": instance.settings.routing_path,
    }.items():
        monkeypatch.setenv(name, str(value))

    assert worker_module.main([]) == 0
    assert "0 alert definitions were due" in capsys.readouterr().out


def _outcome(outcome: str) -> FireOutcome:
    return FireOutcome(
        definition=SimpleNamespace(id=1, recipients=("alex",)),
        outcome=outcome,
        fire_key="alert:1:2026-10-27",
        window_start=date(2026, 10, 21),
        window_end=date(2026, 10, 27),
    )


def test_a_tick_that_needs_attention_exits_non_zero(capsys):
    assert _report([_outcome(OUTCOME_FIRED)]) == 0
    assert _report([_outcome(OUTCOME_SKIPPED)]) == 0
    assert _report([_outcome(OUTCOME_DUPLICATE)]) == 0
    assert _report([_outcome(OUTCOME_FAILED)]) == 1
    assert _report([_outcome(OUTCOME_REFUSED)]) == 1
    assert "alert:1:2026-10-27" in capsys.readouterr().out


def test_a_loop_interval_that_is_not_a_positive_number_is_refused(instance, monkeypatch):
    monkeypatch.setenv("ALERTS_PATH", str(instance.settings.alerts_path))
    with pytest.raises(SystemExit):
        worker_module.main(["--loop", "--interval", "0"])
