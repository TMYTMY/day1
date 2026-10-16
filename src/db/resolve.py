"""Map a table name to the read-only database that holds it.

``data/demo.db`` and ``data/sources.sqlite`` stay separate. Declared tables
use ``SqliteAdapter`` with the sources path. ``SqliteAdapter.__init__`` seeds
the demo warehouse, which would erase a sources file, so the sources adapter
is the same class with only the path set.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from src.db.sqlite import QueryExecutionError, SqliteAdapter
from src.sql_guard import UnsafeSQLError
from src.sources import SourceSpec, spec_for_table


@dataclass(frozen=True)
class ResolvedTable:
    adapter: object
    path: Path


def resolve_table(
    table: str,
    *,
    warehouse: object,
    sources: Mapping[str, SourceSpec],
    sources_path: Path,
) -> ResolvedTable:
    if spec_for_table(sources, table) is None:
        return ResolvedTable(warehouse, Path(getattr(warehouse, "path")))
    return ResolvedTable(_source_adapter(sources_path), Path(sources_path))


def read_as_of(spec: SourceSpec, sources_path: Path) -> str | None:
    """MAX of the declared as-of column. No date is assumed when the column is absent."""
    column = spec.as_of_column
    if not column or column not in spec.columns:
        return None
    if not Path(sources_path).is_file():
        return None
    adapter = _source_adapter(sources_path)
    sql = f'SELECT MAX("{column}") AS as_of FROM "{spec.table}"'
    try:
        result = adapter.execute_select(sql, allowed_tables={spec.table}, max_rows=1)
    except (UnsafeSQLError, QueryExecutionError, OSError, sqlite3.Error):
        return None
    if not result.rows:
        return None
    value = result.rows[0].get("as_of")
    if value is None:
        return None
    return str(value)


def _source_adapter(path: Path) -> SqliteAdapter:
    adapter = SqliteAdapter.__new__(SqliteAdapter)
    adapter.path = Path(path)
    return adapter
