"""Shared records. Kept free of I/O so every layer can import them."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    username: str
    role: str
    allowed_tables: tuple[str, ...]
    # Capability grants. The default is the pre-capability behaviour: a role
    # that may ask a question. See src/capabilities.py.
    capabilities: tuple[str, ...] = ("query",)
    # Where a notification is sent. Optional: a small instance whose relay
    # resolves usernames leaves it out, and the username is the address.
    email: str | None = None


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
    metric_id: str | None = None
    grain_warning: str | None = None
