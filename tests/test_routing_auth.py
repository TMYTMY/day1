from src.auth import authenticate
from src.config import ROOT
from src.routing import route_question

USERS = ROOT / "config" / "users.yaml"


def test_revenue_and_dau_routes(env):
    revenue = route_question("What was total revenue by product?", env.catalog)
    dau = route_question("Show daily active users by platform", env.catalog)
    assert revenue.tables == ("revenue",)
    assert dau.tables == ("dau",)


def test_cantonese_synonyms(env):
    assert route_question("過去 90 日各產品收入", env.catalog).tables == ("revenue",)
    assert route_question("最近 30 日各平台日活", env.catalog).tables == ("dau",)


def test_unknown_topic_does_not_match(env):
    route = route_question("What's the weather in Hong Kong?", env.catalog)
    assert route.matched is False


def test_both_topics_match(env):
    route = route_question("Compare revenue and DAU last month", env.catalog)
    assert set(route.tables) == {"revenue", "dau"}


def test_demo_passwords_and_table_map():
    analyst = authenticate("analyst", "analyst", USERS)
    finance = authenticate("finance", "finance", USERS)
    growth = authenticate("growth", "growth", USERS)
    assert analyst is not None and analyst.allowed_tables == ("revenue", "dau")
    assert finance is not None and finance.allowed_tables == ("revenue",)
    assert growth is not None and growth.allowed_tables == ("dau",)
    assert authenticate("finance", "wrong", USERS) is None
    assert authenticate("nobody", "finance", USERS) is None
