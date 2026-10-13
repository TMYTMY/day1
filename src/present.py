"""Display helpers for numbers, summaries, and charts."""

from __future__ import annotations

import re

_LABELS = {
    "revenue_usd": "Revenue",
    "orders": "Orders",
    "summed_dau": "Summed DAU",
    "dau": "DAU",
    "new_users": "New users",
    "average_order_value": "Average order value",
    "average_daily_revenue": "Average daily revenue",
    "average_daily_orders": "Average daily orders",
    "event_date": "Date",
    "product": "Product",
    "region": "Region",
    "channel": "Channel",
    "platform": "Platform",
    "country": "Country",
    "week": "Week",
    "month": "Month",
}


def column_label(name: str) -> str:
    if name in _LABELS:
        return _LABELS[name]
    return name.replace("_", " ").strip().capitalize()


def is_money(name: str) -> bool:
    lowered = name.lower()
    return "revenue" in lowered or lowered.endswith("_usd") or "average_order" in lowered or lowered == "aov"


def format_value(column: str, value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if is_money(column):
            return f"${value:,.2f}"
        if isinstance(value, float) and not value.is_integer():
            return f"{value:,.2f}"
        return f"{int(value):,}"
    return str(value)


def _number(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def local_summary(columns: list[str], rows: list[dict]) -> str:
    if not rows or not columns:
        return "No rows matched."
    metric = next((column for column in columns if _number(rows[0].get(column)) is not None), None)
    if len(rows) == 1:
        bits = [
            f"{column_label(column)} {format_value(column, row_value)}"
            for column in columns
            for row_value in [rows[0].get(column)]
        ]
        return "Result: " + ", ".join(bits) + "."
    sentence = f"{len(rows)} rows."
    if metric is None:
        return sentence
    dim = next((column for column in columns if column != metric and _number(rows[0].get(column)) is None), None)

    def sort_key(row: dict) -> float:
        value = _number(row.get(metric))
        return value if value is not None else float("-inf")

    top = max(rows, key=sort_key)
    amount = format_value(metric, top.get(metric))
    if dim is not None and top.get(dim) not in (None, ""):
        sentence += f" Highest {column_label(metric)} is {amount} for {top.get(dim)}."
    else:
        sentence += f" Highest {column_label(metric)} is {amount}."
    return sentence


def looks_like_time(values: list[object]) -> bool:
    sample = [str(value) for value in values if value not in (None, "")][:8]
    if not sample:
        return False
    pattern = re.compile(r"^\d{4}-\d{2}(-\d{2})?$")
    return all(pattern.match(value) for value in sample)
