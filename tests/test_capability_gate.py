"""The shared permission gate and the shared audit writer.

Every capability has to pass one boundary: the capability grant and the table
grant. A refusal at either half returns a message that names the capability or
the table and the role, and writes exactly one audit row.
"""

from __future__ import annotations

import sqlite3

import pytest

import src.pipeline as pipeline
from src.audit import AuditLog
from src.auth import authenticate, load_directory
from src.capabilities import QUERY, authorize
from src.config import ROOT, ConfigError
from src.models import User
from tests.test_pipeline import _Boom, _Off

USERS = ROOT / "config" / "users.yaml"

_LEGACY_AUDIT_TABLE = """
    CREATE TABLE audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        question TEXT NOT NULL,
        routed_tables TEXT NOT NULL,
        sql TEXT,
        status TEXT NOT NULL,
        row_count INTEGER,
        error TEXT
    )
"""


def _ask(env, user, question, llm=None):
    return pipeline.answer_question(
        question,
        user,
        settings=env.settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=llm or _Off(),
    )


def _rows(path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    conn.close()
    return rows


def _write_users(tmp_path, body: str):
    path = tmp_path / "users.yaml"
    path.write_text(body, encoding="utf-8")
    return path


# --- configuration: capability grants are additive -------------------------


def test_every_role_carries_the_query_capability():
    directory = load_directory(USERS)
    for role in ("analyst", "finance", "growth"):
        assert directory.capabilities[role] == (QUERY,)
    analyst = authenticate("analyst", "analyst", USERS)
    assert analyst is not None and analyst.capabilities == (QUERY,)


def test_capability_grants_do_not_change_the_existing_table_grants():
    directory = load_directory(USERS)
    assert directory.roles == {
        "analyst": ("revenue", "dau"),
        "finance": ("revenue",),
        "growth": ("dau",),
    }


def test_a_role_without_a_capabilities_key_implies_query(tmp_path, env):
    """Backward compatibility: the old file shape still answers questions."""
    path = _write_users(
        tmp_path,
        """
roles:
  analyst:
    tables: [revenue, dau]
users:
  - username: analyst
    password: analyst
    role: analyst
""",
    )
    directory = load_directory(path)
    assert directory.capabilities["analyst"] == (QUERY,)
    user = authenticate("analyst", "analyst", path)
    assert user is not None
    assert user.capabilities == (QUERY,)
    assert user.allowed_tables == ("revenue", "dau")

    answer = _ask(env, user, "What was total revenue by product over the last 90 days?")
    assert answer.status == "ok"


def test_an_explicit_empty_capability_list_withholds_every_capability(tmp_path):
    path = _write_users(
        tmp_path,
        """
roles:
  analyst:
    tables: [revenue]
    capabilities: []
users:
  - username: analyst
    password: analyst
    role: analyst
""",
    )
    user = authenticate("analyst", "analyst", path)
    assert user is not None and user.capabilities == ()
    assert authorize(user, QUERY, ("revenue",)).allowed is False


def test_an_unknown_capability_name_is_refused_at_load_time(tmp_path):
    path = _write_users(
        tmp_path,
        """
roles:
  analyst:
    tables: [revenue]
    capabilities: [querry]
users:
  - username: analyst
    password: analyst
    role: analyst
""",
    )
    with pytest.raises(ConfigError, match="querry"):
        load_directory(path)


# --- the gate answers both questions in one place --------------------------


def test_both_grants_must_pass():
    revenue_only = User("rev", "rev", ("revenue",))
    assert authorize(revenue_only, QUERY, ("revenue",)).allowed is True
    assert authorize(revenue_only, QUERY, ("dau",)).allowed is False
    mute = User("mute", "mute", ("revenue",), capabilities=())
    assert authorize(mute, QUERY, ("revenue",)).allowed is False


def test_a_role_without_the_capability_is_refused_by_capability_and_role():
    mute = User("mute", "finance", ("revenue",), capabilities=())
    decision = authorize(mute, QUERY, ("revenue",))
    message = decision.message or ""
    assert decision.allowed is False
    assert decision.reason == "capability_not_granted"
    assert decision.tables == ()
    assert "query" in message
    assert "finance" in message


def test_a_table_outside_the_role_is_refused_by_table_and_role():
    finance = User("finance", "finance", ("revenue",))
    decision = authorize(finance, QUERY, ("dau",))
    message = decision.message or ""
    assert decision.allowed is False
    assert decision.reason == "table_not_allowed"
    assert decision.tables == ("dau",)
    assert "dau" in message
    assert "finance" in message


def test_the_capability_is_answered_before_the_table():
    mute = User("mute", "finance", ("revenue",), capabilities=())
    decision = authorize(mute, QUERY, ("dau",))
    assert decision.reason == "capability_not_granted"


def test_an_unimplemented_capability_is_rejected_by_the_gate():
    analyst = User("analyst", "analyst", ("revenue",))
    with pytest.raises(ValueError, match="alert"):
        authorize(analyst, "alert")


# --- refusals are audited, once each --------------------------------------


def test_a_capability_refusal_writes_one_row_and_names_capability_and_role(env):
    mute = User("intern", "intern", ("revenue",), capabilities=())
    answer = _ask(env, mute, "What was total revenue by product over the last 90 days?", llm=_Boom())
    assert answer.status == "denied"
    assert answer.sql is None
    assert "query" in answer.message
    assert "intern" in answer.message

    rows = _rows(env.audit.path)
    assert len(rows) == 1
    assert rows[0]["status"] == "denied"
    assert rows[0]["capability"] == "query"
    assert rows[0]["event_type"] == "capability_refusal"
    assert rows[0]["error"] == "capability_not_granted"


def test_a_table_refusal_writes_one_row_and_names_table_and_role(env):
    answer = _ask(env, env.finance, "Show daily active users by platform", llm=_Boom())
    assert answer.status == "denied"
    assert answer.sql is None
    # The refusal names the topic a person knows, not the warehouse table id.
    assert "Daily active users" in answer.message
    assert "finance" in answer.message
    assert "outside the finance role" in answer.message

    rows = _rows(env.audit.path)
    assert len(rows) == 1
    assert rows[0]["status"] == "denied"
    assert rows[0]["capability"] == "query"
    assert rows[0]["event_type"] == "capability_refusal"
    assert rows[0]["error"] == "table_not_allowed"


def test_every_outcome_still_writes_exactly_one_row(env):
    mute = User("intern", "intern", ("revenue",), capabilities=())
    cases = [
        (env.analyst, "What was total revenue by product over the last 90 days?", "ok"),
        (env.analyst, "What's the weather in Hong Kong?", "clarify"),
        (env.finance, "Show daily active users by platform", "denied"),
        (mute, "What was total revenue by product?", "denied"),
    ]
    for user, question, status in cases:
        before = len(_rows(env.audit.path))
        answer = _ask(env, user, question)
        rows = _rows(env.audit.path)
        assert answer.status == status
        assert len(rows) == before + 1
        assert rows[-1]["status"] == status
        assert rows[-1]["capability"] == "query"


def test_a_normal_answer_is_recorded_as_a_question_event(env):
    answer = _ask(env, env.analyst, "What was total revenue by product over the last 90 days?")
    assert answer.status == "ok"
    row = _rows(env.audit.path)[0]
    assert row["event_type"] == "question"
    assert row["capability"] == "query"


# --- ordering: the gate runs before any SQL is generated ------------------


def test_the_gate_runs_before_sql_is_generated(env, monkeypatch):
    order: list[str] = []
    real_authorize = pipeline.authorize
    real_plan = pipeline.plan_sql

    def spy_authorize(user, capability, tables=(), **kwargs):
        order.append("authorize")
        return real_authorize(user, capability, tables, **kwargs)

    def spy_plan(*args, **kwargs):
        order.append("plan_sql")
        return real_plan(*args, **kwargs)

    monkeypatch.setattr(pipeline, "authorize", spy_authorize)
    monkeypatch.setattr(pipeline, "plan_sql", spy_plan)

    answer = _ask(env, env.analyst, "What was total revenue by product over the last 90 days?")
    assert answer.status == "ok"
    assert "authorize" in order and "plan_sql" in order
    assert order.index("authorize") < order.index("plan_sql")


def test_a_refusal_stops_the_run_before_the_planner(env, monkeypatch):
    planned: list[str] = []
    real_plan = pipeline.plan_sql

    def spy_plan(*args, **kwargs):
        planned.append("plan")
        return real_plan(*args, **kwargs)

    monkeypatch.setattr(pipeline, "plan_sql", spy_plan)
    answer = _ask(env, env.finance, "Show daily active users by platform", llm=_Boom())
    assert answer.status == "denied"
    assert answer.sql is None
    assert planned == []


# --- the audit store records event type plus capability -------------------


def test_the_store_records_event_type_and_capability(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    log.record_event(
        username="ops",
        role="ops",
        status="ok",
        event_type="alert",
        capability="alert",
        question="weekly revenue summary",
        tables=("revenue",),
        row_count=3,
    )
    row = _rows(log.path)[0]
    assert row["event_type"] == "alert"
    assert row["capability"] == "alert"
    assert row["routed_tables"] == "revenue"
    assert row["row_count"] == 3


def test_a_legacy_audit_database_gains_the_new_columns(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute(_LEGACY_AUDIT_TABLE)
    conn.execute(
        "INSERT INTO audit_events (ts, username, role, question, routed_tables, status)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        ("2026-01-01T00:00:00Z", "analyst", "analyst", "old question", "revenue", "ok"),
    )
    conn.commit()
    conn.close()

    log = AuditLog(path)
    # An old row still reads, and a new one carries the new event columns.
    assert log.recent("analyst")[0]["status"] == "ok"
    log.record_event(
        username="analyst",
        role="analyst",
        status="ok",
        event_type="question",
        capability=QUERY,
        question="new question",
        tables=("revenue",),
    )
    rows = _rows(path)
    assert len(rows) == 2
    assert rows[1]["event_type"] == "question"
    assert rows[1]["capability"] == "query"


def test_a_refusal_names_the_topic_when_one_is_known():
    """A business user must never be handed a warehouse table id."""
    user = User("g", "growth", ("dau",))
    friendly = authorize(user, QUERY, ("revenue",), display={"revenue": "Revenue"})
    assert friendly.allowed is False
    assert friendly.message == "Revenue is outside the growth role."

    bare = authorize(user, QUERY, ("revenue",))
    assert bare.message == "Table revenue is outside the growth role."
