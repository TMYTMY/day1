"""Map a table name to the read-only database that holds it.

``data/demo.db`` and ``data/sources.sqlite`` stay separate. Declared tables
use ``SqliteAdapter`` with the sources path. ``SqliteAdapter.__init__`` seeds
the demo warehouse, which would erase a sources file, so the sources adapter
is the same class with only the path set.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from src.db.sqlite import SqliteAdapter
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


def _source_adapter(path: Path) -> SqliteAdapter:
    adapter = SqliteAdapter.__new__(SqliteAdapter)
    adapter.path = Path(path)
    return adapter
