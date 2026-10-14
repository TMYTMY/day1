"""Append-only usage log in a SQLite file separate from the warehouse."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_metric_columns(conn: sqlite3.Connection) -> None:
    """Add trace columns on databases created before the metric catalogue."""
    present = {row["name"] for row in conn.execute("PRAGMA table_info(audit_events)")}
    if "metric_id" not in present:
        conn.execute("ALTER TABLE audit_events ADD COLUMN metric_id TEXT")
    if "definition_hash" not in present:
        conn.execute("ALTER TABLE audit_events ADD COLUMN definition_hash TEXT")


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
    metric_id: str | None = None
    definition_hash: str | None = None


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as conn:
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    username TEXT NOT NULL,
                    success INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(username, id)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS answer_cache (
                    question TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (question, role)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL
                )
                """
            )
            _ensure_metric_columns(conn)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @contextmanager
    def _session(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def write(self, event: AuditEvent) -> None:
        with self._session() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    ts, username, role, question, routed_tables, sql, status, row_count, error,
                    metric_id, definition_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _stamp(),
                    event.username,
                    event.role,
                    event.question[:2000],
                    ",".join(event.routed_tables),
                    (event.sql or "")[:8000] or None,
                    event.status,
                    event.row_count,
                    (event.error or "")[:500] or None,
                    (event.metric_id or "")[:200] or None,
                    (event.definition_hash or "")[:64] or None,
                ),
            )

    def recent(self, username: str, limit: int = 8) -> list[dict]:
        with self._session() as conn:
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

    def record_login(self, username: str, success: bool) -> None:
        """Log one sign-in attempt, success or failure."""
        with self._session() as conn:
            conn.execute(
                "INSERT INTO login_attempts (ts, username, success) VALUES (?, ?, ?)",
                (_stamp(), username, int(success)),
            )

    def recent_failures(self, username: str, window_seconds: int = 300) -> int:
        """Count failed attempts for one username inside the window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        stamp = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._session() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS failures
                FROM login_attempts
                WHERE username = ? AND success = 0 AND ts >= ?
                """,
                (username, stamp),
            ).fetchone()
        return int(row["failures"])

    def cached_answer(self, question: str, role: str) -> str | None:
        """Return a cached answer payload for this question and role, if it is under 24 hours old."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._session() as conn:
            row = conn.execute(
                """
                SELECT payload, created_at FROM answer_cache
                WHERE question = ? AND role = ?
                """,
                (question, role),
            ).fetchone()
            if row is None:
                return None
            if row["created_at"] < cutoff:
                conn.execute(
                    "DELETE FROM answer_cache WHERE question = ? AND role = ?",
                    (question, role),
                )
                return None
            return str(row["payload"])

    def remember_answer(self, question: str, role: str, payload: str) -> None:
        with self._session() as conn:
            conn.execute(
                """
                INSERT INTO answer_cache (question, role, created_at, payload)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(question, role) DO UPDATE SET
                    created_at = excluded.created_at,
                    payload = excluded.payload
                """,
                (question, role, _stamp(), payload),
            )

    def llm_calls_today(self) -> int:
        """Count language-model calls since 00:00 UTC."""
        start = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
        with self._session() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS calls FROM llm_calls WHERE ts >= ?",
                (start,),
            ).fetchone()
        return int(row["calls"])

    def record_llm_call(self) -> None:
        with self._session() as conn:
            conn.execute("INSERT INTO llm_calls (ts) VALUES (?)", (_stamp(),))
