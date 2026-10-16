"""Declared sources. Uploading a file does not make it queryable; the YAML manifest does."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import yaml

from src.config import ROOT, ConfigError
from src.metrics import Metric, active_metrics
from src.models import User
from src.routing import Catalog, Topic, load_catalog

DEFAULT_SOURCES_DIR = ROOT / "config" / "sources"
DEFAULT_SOURCES_DB = ROOT / "data" / "sources.sqlite"
DEFAULT_STAGING_DIR = ROOT / "data" / "staging"
DEFAULT_WAREHOUSE_DB = ROOT / "data" / "demo.db"
DEFAULT_ROUTING = ROOT / "config" / "routing.yaml"

_REQUIRED = (
    "source_id",
    "table",
    "owner_role",
    "file_name",
    "sha256",
    "row_count",
    "columns",
    "loaded_at",
    "description",
    "synonyms",
)
_SOURCE_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_COLUMN = re.compile(r"[a-z_][a-z0-9_]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class SourceSpec:
    """One declared file.

    ``owner_role`` records who supplied the file. It does not grant access.
    A question is allowed only when the table is in the user's allowed tables.
    """

    source_id: str
    table: str
    owner_role: str
    file_name: str
    sha256: str
    row_count: int
    columns: tuple[str, ...]
    loaded_at: str
    description: str
    synonyms: tuple[str, ...]
    formula_cells_without_cache: int = 0
    as_of_column: str | None = None


def warehouse_tables(
    routing_path: Path | None = None,
    warehouse_path: Path | None = None,
) -> set[str]:
    """Table names already owned by the routing catalog or the demo warehouse."""
    names: set[str] = set()
    route = Path(routing_path) if routing_path is not None else DEFAULT_ROUTING
    if route.is_file():
        catalog = load_catalog(route)
        for topic in catalog.topics:
            names.update(topic.tables)
    database = Path(warehouse_path) if warehouse_path is not None else DEFAULT_WAREHOUSE_DB
    names.update(_physical_tables(database))
    return names


def reject_warehouse_table(
    table: str,
    *,
    source_id: str,
    routing_path: Path | None = None,
    warehouse_path: Path | None = None,
) -> None:
    """A declared source must not take the name of a warehouse table."""
    if table in warehouse_tables(routing_path, warehouse_path):
        raise ConfigError(
            f"Source {source_id} table {table} already exists in the warehouse. "
            "A declared source cannot use a warehouse table."
        )


def load_sources(
    directory: Path,
    *,
    routing_path: Path | None = None,
    warehouse_path: Path | None = None,
) -> dict[str, SourceSpec]:
    """Read ``config/sources/*.yaml``. Missing fields and duplicate ids or tables fail."""
    path = Path(directory)
    if not path.is_dir():
        raise ConfigError(f"Sources directory not found: {path}")
    specs: dict[str, SourceSpec] = {}
    tables: set[str] = set()
    for entry in sorted(path.glob("*.yaml")):
        spec = _parse_file(entry)
        reject_warehouse_table(
            spec.table,
            source_id=spec.source_id,
            routing_path=routing_path,
            warehouse_path=warehouse_path,
        )
        if spec.source_id in specs:
            raise ConfigError(f"Duplicate source id: {spec.source_id}")
        if spec.table in tables:
            raise ConfigError(f"Duplicate table: {spec.table}")
        specs[spec.source_id] = spec
        tables.add(spec.table)
    return specs


def sources_for_user(specs: Mapping[str, SourceSpec], user: User) -> dict[str, SourceSpec]:
    """Declarations this user may see. Query permission stays on allowed tables.

    A source is visible when its table is in ``allowed_tables`` or its advisory
    ``owner_role`` matches the user's role. Other declarations stay hidden.
    """
    allowed = set(user.allowed_tables)
    return {
        source_id: spec
        for source_id, spec in specs.items()
        if spec.table in allowed or spec.owner_role == user.role
    }


def declared_tables(specs: Mapping[str, SourceSpec]) -> set[str]:
    return {spec.table for spec in specs.values()}


def spec_for_table(specs: Mapping[str, SourceSpec], table: str) -> SourceSpec | None:
    for spec in specs.values():
        if spec.table == table:
            return spec
    return None


def source_status(spec: SourceSpec | None, metrics_catalogue: list[Metric]) -> str:
    """``quarantined`` has no declaration, ``declared_no_metric`` cannot be asked, ``answerable`` can."""
    if spec is None:
        return "quarantined"
    bound = [metric for metric in active_metrics(metrics_catalogue) if metric.table == spec.table]
    if not bound:
        return "declared_no_metric"
    return "answerable"


def merge_catalog(catalog: Catalog, specs: Mapping[str, SourceSpec]) -> Catalog:
    """Add declaration topics after ``load_catalog``. This is the only automatic binding.

    A declaration whose table is already in the catalog is left out, so it cannot
    take the warehouse route.
    """
    if not specs:
        return catalog
    descriptions = dict(catalog.descriptions)
    topics = list(catalog.topics)
    occupied = {table for topic in topics for table in topic.tables}
    for spec in specs.values():
        if spec.table in occupied:
            continue
        topics.append(_topic(spec))
        descriptions.setdefault(spec.table, spec.description)
        occupied.add(spec.table)
    return Catalog(topics=tuple(topics), descriptions=descriptions)


def _topic(spec: SourceSpec) -> Topic:
    synonyms = list(spec.synonyms)
    folded = {item.casefold() for item in synonyms}
    if spec.table.casefold() not in folded:
        synonyms.append(spec.table)
    return Topic(
        id=spec.source_id,
        title=spec.description or spec.table,
        tables=(spec.table,),
        synonyms=tuple(synonyms),
    )


def _physical_tables(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    quoted = quote(path.resolve().as_posix(), safe="/")
    try:
        conn = sqlite3.connect(f"file:{quoted}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return set()
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        return {str(row[0]) for row in rows}
    except sqlite3.Error:
        return set()
    finally:
        conn.close()


def _parse_file(path: Path) -> SourceSpec:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Source {path.name} is not valid YAML.") from exc
    return source_from_mapping(raw, filename=path.name)


def source_from_mapping(entry: object, *, filename: str) -> SourceSpec:
    if not isinstance(entry, dict):
        raise ConfigError(f"Source {filename} must be a mapping.")
    missing = [name for name in _REQUIRED if name not in entry]
    label = filename
    if isinstance(entry.get("source_id"), str) and entry["source_id"].strip():
        label = entry["source_id"].strip()
    if missing:
        raise ConfigError(f"Source {label} is missing fields: {', '.join(missing)}.")

    source_id = _identifier(entry["source_id"], label, "source_id", _SOURCE_ID)
    if Path(filename).name != f"{source_id}.yaml":
        raise ConfigError(f"Source id {source_id} does not match file name {Path(filename).name}.")
    table = _identifier(entry["table"], source_id, "table", _TABLE)
    owner_role = _text(entry["owner_role"], source_id, "owner_role")
    file_name = _text(entry["file_name"], source_id, "file_name")
    if "/" in file_name or "\\" in file_name:
        raise ConfigError(f"Source {source_id} file_name must be a file name, not a path.")
    sha256 = _sha256(entry["sha256"], source_id)
    row_count = _count(entry["row_count"], source_id, "row_count")
    columns = _columns(entry["columns"], source_id)
    loaded_at = _text(entry["loaded_at"], source_id, "loaded_at")
    description = _text(entry["description"], source_id, "description")
    synonyms = _synonyms(entry["synonyms"], source_id)
    uncached = 0
    if "formula_cells_without_cache" in entry:
        uncached = _count(
            entry["formula_cells_without_cache"],
            source_id,
            "formula_cells_without_cache",
        )
    as_of_column = None
    if "as_of_column" in entry and entry["as_of_column"] is not None:
        as_of_column = _identifier(entry["as_of_column"], source_id, "as_of_column", _COLUMN)
        if as_of_column not in columns:
            raise ConfigError(
                f"Source {source_id} as_of_column {as_of_column} is not a declared column."
            )
    return SourceSpec(
        source_id=source_id,
        table=table,
        owner_role=owner_role,
        file_name=file_name,
        sha256=sha256,
        row_count=row_count,
        columns=columns,
        loaded_at=loaded_at,
        description=description,
        synonyms=synonyms,
        formula_cells_without_cache=uncached,
        as_of_column=as_of_column,
    )


def _identifier(value: object, source_id: str, field: str, pattern: re.Pattern[str]) -> str:
    text = _text(value, source_id, field)
    if pattern.fullmatch(text) is None:
        raise ConfigError(f"Source {source_id} {field} must be a plain identifier.")
    return text


def _text(value: object, source_id: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"Source {source_id} needs a {field}.")
    return value.strip()


def _sha256(value: object, source_id: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ConfigError(f"Source {source_id} sha256 must be 64 lowercase hex characters.")
    return value


def _count(value: object, source_id: str, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"Source {source_id} {field} must be a non-negative integer.")
    return value


def _columns(value: object, source_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"Source {source_id} needs column names.")
    columns: list[str] = []
    seen: set[str] = set()
    for item in value:
        name = item.strip()
        if _COLUMN.fullmatch(name) is None:
            raise ConfigError(f"Source {source_id} column {item!r} must be a lowercase identifier.")
        if name in seen:
            raise ConfigError(f"Source {source_id} has a duplicate column: {name}")
        seen.add(name)
        columns.append(name)
    return tuple(columns)


def _synonyms(value: object, source_id: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        raise ConfigError(f"Source {source_id} needs synonyms.")
    return tuple(item.strip() for item in value)
