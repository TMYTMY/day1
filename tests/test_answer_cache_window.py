"""A re-seeded warehouse on a new date window must miss the answer cache.

The demo seed resolves its window from ``SEED_END`` (or today minus three
days), so the same question covers different rows from one day to the next.
A cached answer payload carries the rows, so the window is part of what an
answer means and belongs in the cache key.
"""

from __future__ import annotations

import json
from datetime import date

import src.db.seed as seed
from src.db.sqlite import QueryExecutionError, SqliteAdapter
from src.metrics import load_metrics, metric_cache_key
from src.pipeline import _data_window, answer_question
from tests.test_pipeline import _Scripted

QUESTION = "What was total revenue by product?"


def _reply(marker: str) -> str:
    sql = (
        "SELECT product, SUM(revenue_usd) AS revenue_usd "
        f"FROM revenue GROUP BY product /* {marker} */"
    )
    return json.dumps({"sql": sql, "assumptions": marker})


def _metric(env):
    return next(
        item for item in load_metrics(env.settings.metrics_path) if item.id == "revenue_by_product"
    )


def _ask(env, adapter, llm):
    return answer_question(
        QUESTION,
        env.analyst,
        settings=env.settings,
        adapter=adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=llm,
    )


def test_the_data_window_is_part_of_the_cache_key(env):
    metric = _metric(env)
    base = metric_cache_key(metric, model="m", prompt_version="2")
    assert base == metric_cache_key(metric, model="m", prompt_version="2", data_window=None)
    one = metric_cache_key(metric, model="m", prompt_version="2", data_window="2026-10-12")
    other = metric_cache_key(metric, model="m", prompt_version="2", data_window="2026-10-13")
    assert one != other
    assert one != base


def test_reseeding_on_a_new_window_misses_the_cached_answer(env, tmp_path, monkeypatch):
    llm = _Scripted([_reply("gen1"), _reply("gen2")])
    first = _ask(env, env.adapter, llm)
    assert first.status == "ok"
    assert first.sql is not None and "gen1" in first.sql
    assert _data_window(env.adapter, "revenue") == seed.END.isoformat()

    repeated = _ask(env, env.adapter, llm)
    assert len(llm.seen) == 1, "the same question on the same window should reuse the cached answer"
    assert repeated.sql == first.sql

    monkeypatch.setenv("SEED_END", "2027-01-15")
    reseeded = tmp_path / "reseeded.db"
    seed.rebuild(reseeded)
    assert seed.END == date(2027, 1, 15)
    assert _data_window(SqliteAdapter(reseeded), "revenue") == "2027-01-15"

    second = _ask(env, SqliteAdapter(reseeded), llm)
    assert len(llm.seen) == 2, "a new date window must not reuse the previous window's rows"
    assert second.status == "ok"
    assert second.sql is not None and "gen2" in second.sql
    assert "gen1" not in second.sql


def test_a_table_without_a_date_leaves_the_window_unknown(env):
    class _NoDates:
        def execute_select(self, *args, **kwargs):
            raise QueryExecutionError("no such column: event_date")

    assert _data_window(_NoDates(), "revenue") is None
    assert _data_window(env.adapter, None) is None
    metric = _metric(env)
    assert metric_cache_key(metric, model="m", prompt_version="2") == metric_cache_key(
        metric, model="m", prompt_version="2", data_window=_data_window(_NoDates(), "revenue")
    )
