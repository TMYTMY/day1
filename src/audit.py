"""Append-only usage log in a SQLite file separate from the warehouse."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class AuditEvent:
    username: str
    role: str
    question: str
    routed_tables: tuple[str, ...]
    sql: str | None
    status: str
    row_count: int | None
    error: str | None


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    question TEXT NOT NULL,
                    routed_tables TEXT NOT NULL,
                    sql TEXT,
                    status TEXT NOT NULL,
                    row_count INTEGER,
                    error TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(username, id)"
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def write(self, event: AuditEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    ts, username, role, question, routed_tables, sql, status, row_count, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    event.username,
                    event.role,
                    event.question[:2000],
                    ",".join(event.routed_tables),
                    (event.sql or "")[:8000] or None,
                    event.status,
                    event.row_count,
                    (event.error or "")[:500] or None,
                ),
            )

    def recent(self, username: str, limit: int = 8) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT ts, question, status, routed_tables, row_count
                FROM audit_events
                WHERE username = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (username, limit),
            ).fetchall()
        return [dict(row) for row in rows]
