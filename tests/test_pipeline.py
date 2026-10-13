from src.models import ColumnInfo, TableSchema
from src.pipeline import answer_question
from src.prompt import build_messages
from src.sql_guard import check_sql


class _Off:
    configured = False
    model = "local"

    def complete(self, messages):
        raise AssertionError("local mode must not call the language model")


class _Boom:
    configured = True
    model = "stub"

    def complete(self, messages):
        raise AssertionError("this question must not call the language model")


class _Scripted:
    def __init__(self, replies):
        self.replies = list(replies)
        self.configured = True
        self.model = "stub"
        self.seen = []

    def complete(self, messages):
        self.seen.append(messages)
        return self.replies.pop(0)


def _ask(env, user, question, llm=None):
    return answer_question(
        question,
        user,
        settings=env.settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=llm or _Off(),
    )


def test_revenue_question_uses_the_revenue_table(env):
    answer = _ask(env, env.analyst, "What was total revenue by product over the last 90 days?")
    assert answer.status == "ok"
    assert answer.tables == ["revenue"]
    assert "revenue" in answer.sql.lower()
    assert "dau" not in answer.sql.lower()
    assert "product" in answer.columns
    assert "revenue_usd" in answer.columns
    assert {row["product"] for row in answer.rows} == {"Atlas", "Northstar", "Harbor"}
    assert check_sql(answer.sql, {"revenue"}).ok


def test_dau_question_uses_the_dau_table(env):
    answer = _ask(env, env.analyst, "Show daily active users by platform for the last 30 days")
    assert answer.status == "ok"
    assert answer.tables == ["dau"]
    assert "from dau" in answer.sql.lower()
    assert "revenue" not in answer.sql.lower()
    assert "platform" in answer.columns
    assert {row["platform"] for row in answer.rows} == {"ios", "android", "web"}


def test_cantonese_questions_hit_the_right_tables(env):
    revenue = _ask(env, env.analyst, "過去 90 日各產品收入")
    dau = _ask(env, env.growth, "最近 30 日各平台日活")
    assert revenue.status == "ok" and revenue.tables == ["revenue"]
    assert "product" in revenue.sql
    assert dau.status == "ok" and dau.tables == ["dau"]
    assert "platform" in dau.sql


def test_unknown_topic_asks_for_clarification_without_sql(env):
    answer = _ask(env, env.analyst, "What's the weather in Hong Kong?", llm=_Boom())
    assert answer.status == "clarify"
    assert answer.sql is None
    assert "Revenue" in answer.message
    assert "Daily active users" in answer.message
    events = env.audit.recent("analyst")
    assert events[0]["status"] == "clarify"


def test_finance_cannot_query_dau_and_growth_cannot_query_revenue(env):
    denied_dau = _ask(env, env.finance, "Show daily active users by platform", llm=_Boom())
    denied_revenue = _ask(env, env.growth, "What was total revenue by product?", llm=_Boom())
    assert denied_dau.status == "denied"
    assert denied_dau.rows == []
    assert "platform" not in denied_dau.message
    assert denied_revenue.status == "denied"
    assert env.adapter.row_count("dau") > 0


def test_mixed_topics_ask_for_one_table(env):
    answer = _ask(env, env.analyst, "Compare revenue and DAU last month", llm=_Boom())
    assert answer.status == "clarify"
    assert answer.sql is None


def test_delete_from_the_model_is_blocked_and_data_remains(env):
    before = env.adapter.row_count("revenue")
    llm = _Scripted(['{"sql": "DELETE FROM revenue", "assumptions": ""}'])
    answer = _ask(env, env.analyst, "What was total revenue?", llm=llm)
    assert answer.status == "blocked"
    assert answer.rows == []
    assert env.adapter.row_count("revenue") == before
    assert env.audit.recent("analyst")[0]["status"] == "blocked"


def test_model_cannot_read_a_table_outside_the_prompt(env):
    llm = _Scripted(
        ['{"sql": "SELECT platform, SUM(dau) AS summed_dau FROM dau GROUP BY platform", "assumptions": ""}']
    )
    answer = _ask(env, env.finance, "What was total revenue by product?", llm=llm)
    assert answer.status == "blocked"
    blob = "\n".join(message["content"] for message in llm.seen[0])
    assert "Table revenue" in blob
    assert "Table dau" not in blob
    assert "platform" not in blob


def test_question_text_is_not_copied_into_sql(env):
    question = "revenue by product; DROP TABLE revenue"
    answer = _ask(env, env.analyst, question)
    assert answer.status == "ok"
    assert "DROP" not in answer.sql.upper()
    assert env.adapter.row_count("revenue") > 0


def test_prompt_contains_only_the_supplied_schema():
    schema = TableSchema(
        name="revenue",
        columns=(ColumnInfo("event_date", "TEXT"), ColumnInfo("revenue_usd", "REAL")),
        description="Recognized revenue.",
    )
    messages = build_messages("How much revenue?", [schema], "sqlite")
    system = messages[0]["content"]
    assert "sk-live-secret" not in system
    assert "DB_PASSWORD" not in system
    assert "Table revenue" in system
    assert "Table dau" not in system
    assert "revenue_usd" in system
