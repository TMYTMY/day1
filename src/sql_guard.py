"""SELECT-only allowlist. The database connection is read-only as well."""

from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

MAX_SQL_CHARS = 8000

_BANNED_FUNCTIONS = {
    "load_extension",
    "writefile",
    "readfile",
    "edit",
    "fts3_tokenizer",
}

_ALLOWED_ROOTS = (exp.Select, exp.Union, exp.Intersect, exp.Except)


def _forbidden_types() -> tuple[type, ...]:
    names = (
        "Insert",
        "Update",
        "Delete",
        "Drop",
        "Alter",
        "Create",
        "Command",
        "Pragma",
        "Attach",
        "Detach",
        "Merge",
        "Transaction",
        "Commit",
        "Rollback",
        "Copy",
        "Grant",
        "Revoke",
        "TruncateTable",
    )
    found = []
    for name in names:
        node = getattr(exp, name, None)
        if isinstance(node, type):
            found.append(node)
    return tuple(found)


FORBIDDEN_TYPES = _forbidden_types()


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    reason: str


class UnsafeSQLError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class CappedSQL:
    sql: str
    fetch: int


def check_sql(sql: str, allowed_tables: set[str], dialect: str = "sqlite") -> GuardResult:
    """Accept one read-only query whose physical tables are all allowed."""
    text = (sql or "").strip()
    if not text:
        return GuardResult(False, "empty")
    if len(text) > MAX_SQL_CHARS:
        return GuardResult(False, "too_long")
    try:
        statements = [stmt for stmt in sqlglot.parse(text, read=dialect) if stmt is not None]
    except sqlglot.errors.SqlglotError:
        return GuardResult(False, "parse_error")
    if len(statements) != 1:
        return GuardResult(False, "multi_statement")
    expr = statements[0]
    if isinstance(expr, FORBIDDEN_TYPES):
        return GuardResult(False, "forbidden_statement")
    if not isinstance(expr, _ALLOWED_ROOTS):
        return GuardResult(False, "not_select")
    for node in expr.walk():
        if isinstance(node, FORBIDDEN_TYPES):
            return GuardResult(False, "forbidden_statement")
        if isinstance(node, exp.Anonymous) and (node.name or "").lower() in _BANNED_FUNCTIONS:
            return GuardResult(False, "forbidden_function")
        if isinstance(node, exp.Func) and node.sql_name().lower() in _BANNED_FUNCTIONS:
            return GuardResult(False, "forbidden_function")

    allowed = {name.lower() for name in allowed_tables}
    try:
        scopes = list(traverse_scope(expr))
    except sqlglot.errors.SqlglotError:
        return GuardResult(False, "parse_error")
    physical: set[str] = set()
    for scope in scopes:
        for source in scope.sources.values():
            if not isinstance(source, exp.Table):
                continue
            catalog = (source.catalog or "").lower()
            database = (source.db or "").lower()
            if catalog or database not in {"", "main"}:
                return GuardResult(False, "schema_qualifier")
            physical.add(source.name.lower())
    if not physical:
        return GuardResult(False, "no_table")
    if not physical <= allowed:
        return GuardResult(False, "table_not_allowed")
    return GuardResult(True, "ok")


def cap_select(sql: str, max_rows: int, dialect: str = "sqlite") -> CappedSQL:
    """Put a LIMIT on the statement so a large scan cannot flood the UI.

    A LIMIT the caller already set is kept when it is within the cap, so an
    explicit top-N query stays ordered.
    """
    expr = sqlglot.parse_one(sql, read=dialect)
    fetch_cap = max_rows + 1
    limit = expr.args.get("limit")
    if limit is not None and isinstance(limit.expression, exp.Literal) and limit.expression.is_int:
        existing = int(limit.expression.this)
        if 0 < existing <= max_rows:
            return CappedSQL(expr.sql(dialect=dialect), existing)
    expr.set("limit", exp.Limit(expression=exp.Literal.number(fetch_cap)))
    return CappedSQL(expr.sql(dialect=dialect), fetch_cap)
