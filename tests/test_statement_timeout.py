"""The statement limit: a runaway query is aborted, normal work is untouched."""

from __future__ import annotations

from dataclasses import replace

import pytest

from src.config import ConfigError, load_settings
from src.db.seed import rebuild
from src.db.sqlite import (
    DEFAULT_STATEMENT_TIMEOUT_MS,
    QueryExecutionError,
    SqliteAdapter,
)
from src.pipeline import answer_question

# 3243 x 3243 rows: about 0.1 s on this box, so a 1 ms budget always trips.
_CROSS_JOIN = "SELECT COUNT(*) AS rows_seen FROM revenue a JOIN revenue b ON 1 = 1"


class _Scripted:
    configured = True
    model = "stub"

    def __init__(self, sql: str):
        self.sql = sql

    def complete(self, messages):
        return '{"sql": "%s", "assumptions": "from the model"}' % self.sql


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "demo.db"
    rebuild(path)
    return path


def test_a_runaway_query_is_aborted(database):
    adapter = SqliteAdapter(database, statement_timeout_ms=1)
    with pytest.raises(QueryExecutionError, match=r"exceeded the 0\.001s time limit"):
        adapter.execute_select(_CROSS_JOIN, allowed_tables={"revenue"}, max_rows=10)


def test_the_same_query_finishes_when_the_limit_is_disabled(database):
    adapter = SqliteAdapter(database, statement_timeout_ms=0)
    rows = adapter.row_count("revenue")
    result = adapter.execute_select(_CROSS_JOIN, allowed_tables={"revenue"}, max_rows=10)
    assert result.rows == ({"rows_seen": rows * rows},)
    assert result.truncated is False


def test_a_normal_query_is_not_affected_by_the_default_limit(database):
    adapter = SqliteAdapter(database)
    assert adapter.statement_timeout_ms == DEFAULT_STATEMENT_TIMEOUT_MS
    result = adapter.execute_select(
        "SELECT COUNT(*) AS rows_seen FROM revenue",
        allowed_tables={"revenue"},
        max_rows=10,
    )
    assert result.rows[0]["rows_seen"] == adapter.row_count("revenue")


def test_a_timed_out_statement_is_an_error_answer_not_a_crash(env):
    settings = replace(env.settings, sql_timeout_ms=1)
    adapter = SqliteAdapter(env.settings.db_path, statement_timeout_ms=1)
    answer = answer_question(
        "What was total revenue by product over the last 90 days?",
        env.analyst,
        settings=settings,
        adapter=adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=_Scripted(_CROSS_JOIN.replace('"', '\\"')),
    )
    assert answer.status == "error"
    assert "time limit" in answer.message
    assert answer.rows == []
    assert env.audit.recent("analyst")[0]["status"] == "error"


def test_the_limit_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("SQL_TIMEOUT_MS", "250")
    assert load_settings().sql_timeout_ms == 250


def test_a_non_integer_limit_is_a_config_error(monkeypatch):
    monkeypatch.setenv("SQL_TIMEOUT_MS", "soon")
    with pytest.raises(ConfigError, match="SQL_TIMEOUT_MS must be an integer"):
        load_settings()


def test_a_negative_limit_is_a_config_error(monkeypatch):
    monkeypatch.setenv("SQL_TIMEOUT_MS", "-1")
    with pytest.raises(ConfigError, match="SQL_TIMEOUT_MS must be zero or greater"):
        load_settings()
