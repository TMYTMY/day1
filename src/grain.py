"""Grain check for a chosen metric. A mismatch warns; it does not block."""

from __future__ import annotations

import sqlglot
from sqlglot import exp

from src.metrics import Metric


def grain_warning(sql: str, metric: Metric, dialect: str = "sqlite") -> str | None:
    """Warn when an aggregate over the metric table groups by a non-additive column.

    A query with no GROUP BY is a grand total, which is allowed. A parse failure
    returns no warning. This never decides whether the query may run.
    """
    if not sql or not sql.strip():
        return None
    try:
        statements = [stmt for stmt in sqlglot.parse(sql, read=dialect) if stmt is not None]
    except sqlglot.errors.SqlglotError:
        return None
    additive = {name.casefold() for name in metric.additive_over}
    outside: set[str] = set()
    for statement in statements:
        for select in statement.find_all(exp.Select):
            if metric.table.casefold() not in _immediate_tables(select):
                continue
            if not any(select.find_all(exp.AggFunc)):
                continue
            for name in _group_columns(select):
                if name.casefold() not in additive:
                    outside.add(name)
    if not outside:
        return None
    listed = ", ".join(sorted(outside, key=str.casefold))
    allowed = ", ".join(metric.additive_over) if metric.additive_over else "(none)"
    return (
        f"This query aggregates {metric.table} by {listed}, which is outside the additive "
        f"dimensions ({allowed}) for {metric.title}. "
        "The result is still shown, but the split may not be safe to sum."
    )


def _immediate_tables(select: exp.Select) -> set[str]:
    names: set[str] = set()
    source = select.args.get("from_")
    if source is not None and isinstance(source.this, exp.Table) and source.this.name:
        names.add(source.this.name.casefold())
    for join in select.args.get("joins") or []:
        if isinstance(join.this, exp.Table) and join.this.name:
            names.add(join.this.name.casefold())
    return names


def _group_columns(select: exp.Select) -> list[str]:
    group = select.args.get("group")
    if group is None:
        return []
    aliases = _aliases(select)
    found: list[str] = []
    for expr in group.expressions:
        target = _unwrap(expr, select, aliases)
        found.extend(column.name for column in target.find_all(exp.Column) if column.name)
    return found


def _aliases(select: exp.Select) -> dict[str, exp.Expression]:
    mapping: dict[str, exp.Expression] = {}
    for projection in select.expressions:
        if isinstance(projection, exp.Alias) and projection.alias:
            mapping[projection.alias.casefold()] = projection.this
    return mapping


def _unwrap(expr: exp.Expression, select: exp.Select, aliases: dict[str, exp.Expression]) -> exp.Expression:
    if isinstance(expr, exp.Literal) and expr.is_int:
        index = int(expr.this) - 1
        if 0 <= index < len(select.expressions):
            expr = select.expressions[index]
    if isinstance(expr, exp.Alias):
        expr = expr.this
    if isinstance(expr, exp.Column) and expr.name.casefold() in aliases:
        expr = aliases[expr.name.casefold()]
    return expr
