"""The fire log: one row per window evaluated, keyed so it cannot repeat.

A fire key is the alert definition's identity plus the resolved window end
(``src.alert_eval.fire_key``). This table holds it under a UNIQUE constraint,
so "evaluate a window at most once" is a property of the database and not of
the worker's memory or of how carefully the worker was launched:

* a restart re-reads the same definition and resolves the same window, and the
  claim fails, so nothing is evaluated a second time;
* a double launch, or two ticks that overlap, race on the same INSERT and
  SQLite lets exactly one of them through;
* nothing is held in a Python process, so nothing is lost with one.

The row is claimed *before* the window is resolved, and completed afterwards.
A row left in ``pending`` describes a claim whose evaluation never finished,
and it never becomes a fire: a claim that produced no verdict is released, so
the next tick can try again. That keeps the guarantee about *evaluation* exact
(a window with a verdict is never evaluated twice) without turning a transient
database error into a permanently unevaluated period.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import date
from pathlib import Path

# A claim that has been taken but has no verdict yet.
PENDING = "pending"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS alert_fires (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fire_key TEXT NOT NULL,
    alert_id INTEGER NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    value REAL,
    previous REAL,
    verdict TEXT NOT NULL,
    claimed_at TEXT NOT NULL,
    CONSTRAINT uq_alert_fires_key UNIQUE (fire_key)
)
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_alert_fires_definition
    ON alert_fires(alert_id, window_end DESC)
"""


class FireStore:
    """The instance's fire log, in the same file as its alert definitions."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX)

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

    # -- claims -----------------------------------------------------------

    def claim(
        self,
        *,
        fire_key: str,
        alert_id: int,
        window_start: date,
        window_end: date,
        at: str,
    ) -> bool:
        """Take the claim on one window. False when somebody already has it.

        The UNIQUE constraint is the arbiter, not a preceding SELECT: a
        SELECT-then-INSERT would leave a gap in which a second process could
        read the same absence and both would go on to evaluate.
        """
        with self._session() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO alert_fires (
                        fire_key, alert_id, window_start, window_end, verdict, claimed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fire_key,
                        int(alert_id),
                        window_start.isoformat(),
                        window_end.isoformat(),
                        PENDING,
                        at,
                    ),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def complete(
        self,
        fire_key: str,
        *,
        value: float | None,
        previous: float | None,
        verdict: str,
    ) -> None:
        """Record what the claimed window evaluated to."""
        with self._session() as conn:
            conn.execute(
                """
                UPDATE alert_fires
                SET value = ?, previous = ?, verdict = ?
                WHERE fire_key = ?
                """,
                (value, previous, verdict, fire_key),
            )

    def release(self, fire_key: str) -> None:
        """Give a claim back because no verdict came of it.

        Only a ``pending`` claim is released. A row that already carries a
        verdict stays, because that window has been evaluated and must never
        be evaluated again.
        """
        with self._session() as conn:
            conn.execute(
                "DELETE FROM alert_fires WHERE fire_key = ? AND verdict = ?",
                (fire_key, PENDING),
            )

    # -- reads ------------------------------------------------------------

    def previous_value(self, alert_id: int, *, before: date) -> tuple[float, date] | None:
        """The last value this definition produced for an earlier window.

        A percentage comparison needs a number to be a percentage of. The
        answer comes from this table and not from a second query, so it is the
        number that was reported then — the same number the audit trail holds —
        and not a re-read of a warehouse that may have been rebuilt since.
        """
        with self._session() as conn:
            row = conn.execute(
                """
                SELECT value, window_end FROM alert_fires
                WHERE alert_id = ? AND window_end < ?
                  AND value IS NOT NULL AND verdict != ?
                ORDER BY window_end DESC, id DESC
                LIMIT 1
                """,
                (int(alert_id), before.isoformat(), PENDING),
            ).fetchone()
        if row is None:
            return None
        return float(row["value"]), date.fromisoformat(row["window_end"])

    def get(self, fire_key: str) -> dict | None:
        with self._session() as conn:
            row = conn.execute(
                "SELECT * FROM alert_fires WHERE fire_key = ?", (fire_key,)
            ).fetchone()
        return None if row is None else dict(row)

    def fires(self, alert_id: int | None = None) -> list[dict]:
        """Every fire, oldest window first. The whole log is the audit of it."""
        with self._session() as conn:
            if alert_id is None:
                rows = conn.execute(
                    "SELECT * FROM alert_fires ORDER BY window_end ASC, id ASC"
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM alert_fires WHERE alert_id = ?
                    ORDER BY window_end ASC, id ASC
                    """,
                    (int(alert_id),),
                ).fetchall()
        return [dict(row) for row in rows]
