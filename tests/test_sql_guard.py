import pytest

from src.db.sqlite import QueryExecutionError
from src.sql_guard import GuardResult, cap_select, check_sql


def test_select_on_allowed_table_passes():
    result = check_sql(
        "SELECT product, SUM(revenue_usd) AS revenue_usd FROM revenue GROUP BY product",
        {"revenue"},
    )
    assert result == GuardResult(True, "ok")


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM revenue",
        "UPDATE revenue SET revenue_usd = 0",
        "INSERT INTO revenue SELECT * FROM revenue",
        "DROP TABLE revenue",
        "PRAGMA query_only",
        "ATTACH DATABASE 'other.db' AS other",
        "VACUUM",
        "SELECT * FROM revenue; DROP TABLE revenue",
        "SELECT load_extension('x')",
        "SELECT writefile('/tmp/x', 'a') FROM revenue",
        "SELECT * FROM dau",
        "WITH secret AS (SELECT * FROM secret) SELECT * FROM revenue WHERE EXISTS (SELECT 1 FROM secret)",
        "SELECT * FROM evil.revenue",
        "SELECT 1",
    ],
)
def test_non_select_and_escape_hatches_are_blocked(sql):
    result = check_sql(sql, {"revenue"})
    assert result.ok is False


def test_cte_that_reads_the_allowed_table_passes():
    sql = "WITH recent AS (SELECT * FROM revenue) SELECT product FROM recent"
    assert check_sql(sql, {"revenue"}).ok is True


def test_string_literal_does_not_count_as_a_statement():
    sql = "SELECT * FROM revenue WHERE product = 'drop table'"
    assert check_sql(sql, {"revenue"}).ok is True


def test_cap_preserves_a_small_limit_and_adds_one_when_missing():
    capped = cap_select("SELECT * FROM revenue ORDER BY revenue_usd DESC", max_rows=500)
    assert capped.sql.endswith("LIMIT 501")
    kept = cap_select("SELECT * FROM revenue LIMIT 10", max_rows=500)
    assert "LIMIT 10" in kept.sql
    assert kept.fetch == 10


def test_readonly_connection_rejects_writes(env, monkeypatch):
    from src.sql_guard import CappedSQL

    monkeypatch.setattr(
        "src.db.sqlite.cap_select",
        lambda sql, max_rows, dialect="sqlite": CappedSQL(sql, max_rows),
    )
    monkeypatch.setattr(
        "src.db.sqlite.check_sql",
        lambda *args, **kwargs: GuardResult(True, "ok"),
    )
    before = env.adapter.row_count("revenue")
    with pytest.raises(QueryExecutionError, match="readonly"):
        env.adapter.execute_select(
            "DELETE FROM revenue",
            allowed_tables={"revenue"},
            max_rows=10,
        )
    assert env.adapter.row_count("revenue") == before
