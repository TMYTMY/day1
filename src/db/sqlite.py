"""Read-only SQLite adapter for the demo warehouse."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from urllib.parse import quote

from src.db.seed import ensure_seeded
from src.models import ColumnInfo, QueryResult, TableSchema
from src.sql_guard import UnsafeSQLError, cap_select, check_sql

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class QueryExecutionError(Exception):
    """The database rejected the statement or failed while reading."""


def _quote_ident(name: str) -> str:
    if not _IDENT.fullmatch(name):
        raise QueryExecutionError("Invalid table name.")
    return '"' + name + '"'


def _cell(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _unique(names: list[str]) -> list[str]:
    seen: dict[str, int] = {}
    unique: list[str] = []
    for name in names:
        base = name or "column"
        count = seen.get(base, 0)
        seen[base] = count + 1
        unique.append(base if count == 0 else f"{base}_{count + 1}")
    return unique


class SqliteAdapter:
    """SQLite opened with mode=ro plus PRAGMA query_only.

    `execute_select` checks the SQL allowlist again before it runs anything.
    """

    dialect = "sqlite"
    display_name = "SQLite"

    def __init__(self, path: Path):
        self.path = Path(path)
        ensure_seeded(self.path)

    def _connect_readonly(self) -> sqlite3.Connection:
        quoted = quote(self.path.resolve().as_posix(), safe="/")
        uri = f"file:{quoted}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            conn.execute("PRAGMA query_only = ON")
        except sqlite3.Error:
            # mode=ro already rejects writes. Keep the connection.
            pass
        return conn

    def _known_table(self, table: str) -> bool:
        if not _IDENT.fullmatch(table):
            return False
        conn = self._connect_readonly()
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
        finally:
            conn.close()
        return row is not None

    def get_schema(self, table: str) -> TableSchema | None:
        if not self._known_table(table):
            return None
        conn = self._connect_readonly()
        try:
            info = conn.execute(f"PRAGMA table_info({_quote_ident(table)})").fetchall()
        finally:
            conn.close()
        columns = tuple(ColumnInfo(name=row[1], data_type=row[2] or "TEXT") for row in info)
        return TableSchema(name=table, columns=columns)

    def row_count(self, table: str) -> int:
        if not self._known_table(table):
            raise QueryExecutionError(f"Unknown table {table}.")
        conn = self._connect_readonly()
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {_quote_ident(table)}").fetchone()
        finally:
            conn.close()
        return int(row[0])

    def execute_select(
        self,
        sql: str,
        *,
        allowed_tables: set[str],
        max_rows: int,
    ) -> QueryResult:
        try:
            capped = cap_select(sql, max_rows=max_rows, dialect=self.dialect)
        except Exception as exc:
            raise UnsafeSQLError("parse_error") from exc
        verdict = check_sql(capped.sql, allowed_tables, dialect=self.dialect)
        if not verdict.ok:
            raise UnsafeSQLError(verdict.reason)
        conn = self._connect_readonly()
        try:
            try:
                cursor = conn.execute(capped.sql)
            except sqlite3.Error as exc:
                raise QueryExecutionError(str(exc)) from exc
            description = cursor.description or []
            columns = _unique([item[0] for item in description])
            fetched = cursor.fetchmany(max_rows + 1)
        finally:
            conn.close()
        truncated = len(fetched) > max_rows
        kept = fetched[:max_rows]
        rows = tuple(
            {columns[index]: _cell(record[index]) for index in range(len(columns))}
            for record in kept
        )
        return QueryResult(columns=tuple(columns), rows=rows, truncated=truncated)
