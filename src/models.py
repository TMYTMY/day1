"""Shared records. Kept free of I/O so every layer can import them."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    username: str
    role: str
    allowed_tables: tuple[str, ...]


@dataclass(frozen=True)
class ColumnInfo:
    name: str
    data_type: str


@dataclass(frozen=True)
class TableSchema:
    name: str
    columns: tuple[ColumnInfo, ...]
    description: str = ""


@dataclass(frozen=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: tuple[dict, ...]
    truncated: bool


@dataclass
class Answer:
    status: str
    message: str
    sql: str | None = None
    columns: list[str] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    assumptions: str | None = None
    source: str | None = None
    truncated: bool = False
    summary: str | None = None
    audit_saved: bool = True
    knowledge_snippets: list[str] = field(default_factory=list)
