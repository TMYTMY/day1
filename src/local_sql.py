"""Deterministic SQLite for the demo tables when no model key is configured.

Literals come from fixed vocabularies, not from the raw question, so a
question cannot smuggle SQL through this planner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class PlannerError(Exception):
    """The local planner cannot build a query for this table."""


@dataclass(frozen=True)
class PlannedSQL:
    sql: str
    assumptions: str


_PRODUCTS = ("Atlas", "Northstar", "Harbor")
_REGIONS = (
    ("apac", "APAC"),
    ("asia", "APAC"),
    ("emea", "EMEA"),
    ("europe", "EMEA"),
    ("americas", "AMER"),
    ("amer", "AMER"),
)
_COUNTRIES = (
    ("hong kong", "HK"),
    ("singapore", "SG"),
    ("united states", "US"),
    ("united kingdom", "GB"),
    ("germany", "DE"),
)
_COUNTRY_CODES = {"HK", "SG", "US", "GB", "DE"}
_PLATFORMS = (
    (r"\bios\b|\biphone\b", "ios"),
    (r"\bandroid\b", "android"),
    (r"\bweb\b|\bbrowser\b", "web"),
)


def _sql_str(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9 _-]+", value):
        raise PlannerError("Refusing to interpolate an unexpected literal.")
    return "'" + value + "'"


def _has(question: str, *patterns: str) -> bool:
    return any(re.search(pattern, question, flags=re.IGNORECASE) for pattern in patterns)


def _window(question: str) -> tuple[str | None, str]:
    numbered = re.search(
        r"(?:過去|最近|last|past)\s*(\d+)\s*(?:days?|日|天)",
        question,
        flags=re.IGNORECASE,
    )
    if numbered:
        days = max(1, min(int(numbered.group(1)), 3650))
        return (
            f"event_date >= date('now', '-{days} day')",
            f"Filtered to the last {days} days.",
        )
    if _has(question, r"\blast\s+week\b", r"過去一週", r"上週", r"上周"):
        return "event_date >= date('now', '-7 day')", "Filtered to the last 7 days."
    if _has(question, r"\blast\s+month\b", r"上個月", r"上月"):
        return "event_date >= date('now', '-30 day')", "Filtered to the last 30 days."
    if _has(question, r"\b(last|past)\s+quarter\b", r"上季"):
        return "event_date >= date('now', '-90 day')", "Filtered to the last 90 days."
    if _has(question, r"\b(ytd|year to date|this year)\b", r"今年"):
        return "event_date >= date('now', 'start of year')", "Filtered to this calendar year."
    if _has(question, r"\byesterday\b", r"昨日", r"昨天"):
        return "event_date = date('now', '-1 day')", "Filtered to yesterday."
    if _has(question, r"\btoday\b", r"今日", r"今天"):
        return "event_date = date('now')", "Filtered to today."
    if _has(question, r"\b(all time|all-time|entire history)\b", r"全部時間", r"所有日期"):
        return None, "Showing every date in the warehouse."
    return "event_date >= date('now', '-90 day')", "No time range was named, so this uses the last 90 days."


def _time_dimension(question: str) -> tuple[str, str] | None:
    # "daily active" names the DAU metric. It is not a request for a daily grain.
    scrubbed = re.sub(r"\bdaily\s+active\b", " ", question, flags=re.IGNORECASE)
    if _has(question, r"\b(weekly|by week|per week)\b", r"每週", r"每周", r"按週", r"按周"):
        return "strftime('%Y-%W', event_date)", "week"
    if _has(question, r"\b(monthly|by month|per month)\b", r"每月", r"按月", r"月份"):
        return "strftime('%Y-%m', event_date)", "month"
    if _has(scrubbed, r"\b(daily|by day|per day|each day|over time|trend)\b", r"每日", r"趨勢", r"趋势"):
        return "event_date", "event_date"
    return None


def _rank(question: str) -> tuple[str | None, int | None]:
    numbered = re.search(r"\btop\s+(\d+)\b", question, flags=re.IGNORECASE)
    if numbered:
        return "high", max(1, min(int(numbered.group(1)), 100))
    if _has(question, r"\b(highest|most)\b", r"最高", r"最多"):
        return "high", 1
    if _has(question, r"\b(lowest|least)\b", r"最低", r"最少"):
        return "low", 1
    return None, None


def _mentioned_product(question: str) -> str | None:
    found = [name for name in _PRODUCTS if re.search(rf"\b{name}\b", question, flags=re.IGNORECASE)]
    if len(found) == 1:
        return found[0]
    return None


def _mentioned_region(question: str) -> str | None:
    lowered = question.lower()
    for phrase, code in _REGIONS:
        if re.search(rf"(?<![a-z0-9_]){re.escape(phrase)}(?![a-z0-9_])", lowered):
            return code
    return None


def _mentioned_channel(question: str) -> str | None:
    lowered = question.lower()
    if "self-serve" in lowered or "self serve" in lowered:
        return "self-serve"
    if re.search(r"\bpartner\b", lowered):
        return "partner"
    if re.search(r"\bdirect\b", lowered):
        return "direct"
    return None


def _mentioned_country(question: str) -> str | None:
    lowered = question.lower()
    for phrase, code in _COUNTRIES:
        if phrase in lowered:
            return code
    for code in _COUNTRY_CODES:
        if re.search(rf"\b{code}\b", question):
            return code
    return None


def _mentioned_platform(question: str) -> str | None:
    for pattern, code in _PLATFORMS:
        if re.search(pattern, question, flags=re.IGNORECASE):
            return code
    return None


def _is_total(question: str, has_dimension: bool) -> bool:
    if has_dimension:
        return False
    return _has(
        question,
        r"\b(total|how much|how many|overall|sum)\b",
        r"總計",
        r"总计",
        r"合計",
        r"合计",
        r"總額",
        r"总额",
    )


def _is_raw(question: str) -> bool:
    return _has(question, r"\b(raw|row level|row-level|sample rows|list rows)\b")


def _require(columns: set[str], needed: set[str], table: str) -> None:
    missing = needed - columns
    if missing:
        raise PlannerError(f"The {table} table is missing columns the local planner expects.")


def _assemble(
    table: str,
    dimensions: list[tuple[str, str]],
    metrics: list[tuple[str, str]],
    where: list[str],
    order: str,
    limit: int | None,
    notes: list[str],
) -> PlannedSQL:
    select_items = [expr if expr == alias else f"{expr} AS {alias}" for expr, alias in dimensions]
    select_items.extend(f"{expr} AS {alias}" for expr, alias in metrics)
    sql = f"SELECT {', '.join(select_items)} FROM {table}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    if dimensions:
        sql += " GROUP BY " + ", ".join(expr for expr, _ in dimensions)
    sql += f" ORDER BY {order}"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    return PlannedSQL(sql=sql, assumptions=" ".join(notes))


def plan_sql(question: str, table: str, columns: set[str], dialect: str) -> PlannedSQL:
    if dialect != "sqlite":
        raise PlannerError(
            "The local planner writes SQLite. Configure OPENROUTER_API_KEY for other dialects."
        )
    if table == "revenue":
        return _plan_revenue(question, columns)
    if table == "dau":
        return _plan_dau(question, columns)
    raise PlannerError(f"The local planner has no template for {table}.")


def _plan_revenue(question: str, columns: set[str]) -> PlannedSQL:
    _require(
        columns,
        {"event_date", "product", "region", "channel", "revenue_usd", "orders"},
        "revenue",
    )
    window, window_note = _window(question)
    where = [window] if window else []
    notes = [window_note]
    product = _mentioned_product(question)
    region = _mentioned_region(question)
    channel = _mentioned_channel(question)
    if product:
        where.append(f"product = {_sql_str(product)}")
        notes.append(f"Filtered to {product}.")
    if region:
        where.append(f"region = {_sql_str(region)}")
        notes.append(f"Filtered to {region}.")
    if channel:
        where.append(f"channel = {_sql_str(channel)}")
        notes.append(f"Filtered to the {channel} channel.")

    dimensions: list[tuple[str, str]] = []
    grain = _time_dimension(question)
    if grain:
        dimensions.append(grain)
    if _has(question, r"\bproducts?\b", r"產品", r"产品") and product is None:
        dimensions.append(("product", "product"))
    if _has(question, r"\bregions?\b", r"地區", r"地区") and region is None:
        dimensions.append(("region", "region"))
    if _has(question, r"\bchannels?\b", r"渠道") and channel is None:
        dimensions.append(("channel", "channel"))

    if _is_raw(question):
        limit = 50
        sql = (
            "SELECT event_date, product, region, channel, revenue_usd, orders "
            f"FROM revenue WHERE {' AND '.join(where)} ORDER BY event_date DESC LIMIT {limit}"
            if where
            else "SELECT event_date, product, region, channel, revenue_usd, orders "
            "FROM revenue ORDER BY event_date DESC LIMIT 50"
        )
        notes.append("Showing 50 source rows.")
        return PlannedSQL(sql=sql, assumptions=" ".join(notes))

    if not dimensions and not _is_total(question, has_dimension=False):
        dimensions.append(("product", "product"))
        notes.append("Grouped by product because the question did not name a breakdown.")

    if _has(question, r"\b(aov|average order value)\b"):
        metrics = [("SUM(revenue_usd) * 1.0 / NULLIF(SUM(orders), 0)", "average_order_value")]
    elif _has(question, r"\baverage daily revenue\b", r"平均每日收入"):
        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        sql = (
            "SELECT AVG(day_revenue) AS average_daily_revenue, "
            "AVG(day_orders) AS average_daily_orders FROM ("
            "SELECT event_date, SUM(revenue_usd) AS day_revenue, SUM(orders) AS day_orders "
            f"FROM revenue{where_sql} GROUP BY event_date)"
        )
        notes.append("Average of each day's total, across the filtered dates.")
        return PlannedSQL(sql=sql, assumptions=" ".join(notes))
    else:
        metrics = [("SUM(revenue_usd)", "revenue_usd"), ("SUM(orders)", "orders")]

    rank, limit = _rank(question)
    metric_alias = metrics[0][1]
    if rank == "high":
        order = f"{metric_alias} DESC"
    elif rank == "low":
        order = f"{metric_alias} ASC"
    elif dimensions and dimensions[0][1] in {"event_date", "week", "month"}:
        order = f"{dimensions[0][1]} ASC"
    else:
        order = f"{metric_alias} DESC"
    return _assemble("revenue", dimensions, metrics, where, order, limit, notes)


def _plan_dau(question: str, columns: set[str]) -> PlannedSQL:
    _require(
        columns,
        {"event_date", "platform", "country", "dau", "new_users"},
        "dau",
    )
    window, window_note = _window(question)
    where = [window] if window else []
    notes = [
        window_note,
        "Summed DAU adds country slices within a platform. Adding platforms together counts a person on two devices twice.",
    ]
    country = _mentioned_country(question)
    platform = _mentioned_platform(question)
    if country:
        where.append(f"country = {_sql_str(country)}")
        notes.append(f"Filtered to {country}.")
    if platform:
        where.append(f"platform = {_sql_str(platform)}")
        notes.append(f"Filtered to {platform}.")

    dimensions: list[tuple[str, str]] = []
    grain = _time_dimension(question)
    if grain:
        dimensions.append(grain)
    if _has(question, r"\bplatforms?\b", r"平台") and platform is None:
        dimensions.append(("platform", "platform"))
    if _has(question, r"\bcountr(?:y|ies)\b", r"國家", r"国家") and country is None:
        dimensions.append(("country", "country"))

    if _is_raw(question):
        sql = (
            "SELECT event_date, platform, country, dau, new_users "
            f"FROM dau WHERE {' AND '.join(where)} ORDER BY event_date DESC LIMIT 50"
            if where
            else "SELECT event_date, platform, country, dau, new_users "
            "FROM dau ORDER BY event_date DESC LIMIT 50"
        )
        notes.append("Showing 50 source rows.")
        return PlannedSQL(sql=sql, assumptions=" ".join(notes))

    if not dimensions and not _is_total(question, has_dimension=False):
        dimensions.append(("platform", "platform"))
        notes.append("Grouped by platform because the question did not name a breakdown.")

    if _has(question, r"\bnew users?\b", r"新用戶", r"新用户") and not _has(
        question, r"\b(dau|active users?)\b", r"日活", r"活躍", r"活跃"
    ):
        metrics = [("SUM(new_users)", "new_users"), ("SUM(dau)", "summed_dau")]
    else:
        metrics = [("SUM(dau)", "summed_dau"), ("SUM(new_users)", "new_users")]

    rank, limit = _rank(question)
    metric_alias = metrics[0][1]
    if rank == "high":
        order = f"{metric_alias} DESC"
    elif rank == "low":
        order = f"{metric_alias} ASC"
    elif dimensions and dimensions[0][1] in {"event_date", "week", "month"}:
        order = f"{dimensions[0][1]} ASC"
    else:
        order = f"{metric_alias} DESC"
    return _assemble("dau", dimensions, metrics, where, order, limit, notes)
