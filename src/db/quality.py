"""Five SQL checks for the defects planted by the demo seed.

Each query is plain SQLite. Run them with:

    python -m src.db.quality
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# One query per seeded defect. The count is the number of offending rows,
# except duplicate_rows, which is the number of grain keys ingested twice.
QUERIES: tuple[tuple[str, str], ...] = (
    (
        "duplicate_rows",
        """
        SELECT COUNT(*) FROM (
            SELECT event_date, product, region, channel
            FROM revenue
            GROUP BY event_date, product, region, channel
            HAVING COUNT(*) > 1
        )
        """,
    ),
    (
        "late_arriving_backfill",
        """
        SELECT COUNT(*) FROM revenue
        WHERE ingest_batch = 'backfill' AND loaded_at > event_date
        """,
    ),
    (
        "null_channel",
        """
        SELECT COUNT(*) FROM revenue WHERE channel IS NULL
        """,
    ),
    (
        "region_rename",
        """
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM revenue WHERE region = 'EMEA')
             AND EXISTS (SELECT 1 FROM revenue WHERE region = 'E.U.')
            THEN (SELECT COUNT(*) FROM revenue WHERE region = 'E.U.')
            ELSE 0
        END
        """,
    ),
    (
        "unit_contamination",
        """
        SELECT COUNT(*) FROM revenue WHERE amount_currency = 'EUR'
        """,
    ),
)


def defect_counts(path: Path) -> dict[str, int]:
    """Run the five detection queries against one warehouse file."""
    conn = sqlite3.connect(path)
    try:
        return {name: int(conn.execute(sql).fetchone()[0]) for name, sql in QUERIES}
    finally:
        conn.close()


def format_counts(counts: dict[str, int]) -> str:
    return "\n".join(f"{name}: {counts[name]}" for name, _sql in QUERIES)


def main() -> None:
    from src.config import ROOT
    from src.db.seed import ensure_seeded

    target = ROOT / "data" / "demo.db"
    ensure_seeded(target)
    print(format_counts(defect_counts(target)))


if __name__ == "__main__":
    main()
