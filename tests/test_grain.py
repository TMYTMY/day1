from src.grain import grain_warning
from src.metrics import load_metrics
from src.pipeline import answer_question
from tests.test_pipeline import _Off, _Scripted


def _metric(env, metric_id: str):
    return next(item for item in load_metrics(env.settings.metrics_path) if item.id == metric_id)


def test_summing_a_non_additive_dimension_warns(env):
    metric = _metric(env, "revenue_by_product")
    warning = grain_warning(
        "SELECT channel, SUM(revenue_usd) AS revenue_usd FROM revenue GROUP BY channel",
        metric,
    )
    assert warning
    assert "channel" in warning
    assert "revenue_by_product" not in warning or metric.title in warning


def test_summing_an_additive_dimension_does_not_warn(env):
    metric = _metric(env, "revenue_by_product")
    assert (
        grain_warning(
            "SELECT product, SUM(revenue_usd) AS revenue_usd FROM revenue GROUP BY product",
            metric,
        )
        is None
    )
    assert grain_warning("SELECT SUM(revenue_usd) AS revenue_usd FROM revenue", metric) is None
    assert (
        grain_warning(
            "SELECT strftime('%Y-%W', event_date) AS week, SUM(revenue_usd) AS revenue_usd "
            "FROM revenue GROUP BY strftime('%Y-%W', event_date)",
            metric,
        )
        is None
    )


def test_a_non_additive_query_still_returns_rows(env):
    answer = answer_question(
        "Show revenue broken out by channels",
        env.analyst,
        settings=env.settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=_Off(),
    )
    assert answer.status == "ok"
    assert answer.metric_id == "revenue_by_product"
    assert answer.rows
    assert answer.grain_warning
    assert "channel" in answer.grain_warning

    safe = answer_question(
        "What was total revenue by product?",
        env.analyst,
        settings=env.settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=_Off(),
    )
    assert safe.status == "ok"
    assert safe.grain_warning is None


def test_scripted_channel_sql_warns_without_blocking(env):
    llm = _Scripted(
        [
            '{"sql": "SELECT channel, SUM(revenue_usd) AS revenue_usd FROM revenue GROUP BY channel", "assumptions": "By channel."}'
        ]
    )
    answer = answer_question(
        "What was total revenue?",
        env.analyst,
        settings=env.settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=llm,
    )
    assert answer.status == "ok"
    assert answer.source == "openrouter"
    assert answer.grain_warning
    assert "channel" in answer.grain_warning
