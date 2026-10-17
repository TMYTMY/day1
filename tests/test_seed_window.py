"""The demo window follows SEED_END, and a new end rebuilds the file."""

from __future__ import annotations

import sqlite3
from datetime import date, timedelta

import src.db.seed as seed
from src.db.quality import defect_counts

# Counts measured by `SEED_END=2026-10-12 python -m src.db.quality` on the
# absolute window this offset set replaces. They are a reproduction check,
# not a new measurement.
PINNED_COUNTS = {
    "duplicate_rows": 3,
    "late_arriving_backfill": 279,
    "null_channel": 48,
    "region_rename": 378,
    "unit_contamination": 189,
}


def _rows(path) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        revenue = conn.execute(
            "SELECT * FROM revenue ORDER BY event_date, product, region, channel, ingest_batch"
        ).fetchall()
        dau = conn.execute(
            "SELECT * FROM dau ORDER BY event_date, platform, country"
        ).fetchall()
        return revenue + dau
    finally:
        conn.close()


def _inside(day: date) -> bool:
    return seed.START <= day <= seed.END


def test_pinned_seed_end_keeps_a_119_day_window_and_repeats(tmp_path, monkeypatch):
    monkeypatch.setenv("SEED_END", "2026-10-12")
    seed.resolve_seed_window()
    assert (seed.END - seed.START).days == 119
    assert seed.START == date(2026, 6, 15)
    assert seed.END == date(2026, 10, 12)
    assert seed._DUPLICATE_DATES == {"2026-06-15", "2026-06-16", "2026-06-17"}
    assert seed._BACKFILL_START == date(2026, 8, 1)
    assert seed._BACKFILL_END == date(2026, 8, 31)
    assert seed._BACKFILL_LOADED_AT == "2026-09-18"
    assert seed._REGION_RENAME_ON == date(2026, 9, 1)
    assert seed._EUR_START == date(2026, 10, 1)
    assert seed._EUR_END == date(2026, 10, 7)
    assert seed.LAUNCH == date(2026, 9, 8)
    assert seed._NULL_CHANNEL_BEFORE == date(2026, 7, 1)
    assert seed.SEED_VERSION == "3-2026-10-12"

    for raw in seed._DUPLICATE_DATES:
        assert _inside(date.fromisoformat(raw))
    day = seed._BACKFILL_START
    while day <= seed._BACKFILL_END:
        assert _inside(day)
        day += timedelta(days=1)
    assert _inside(date.fromisoformat(seed._BACKFILL_LOADED_AT))
    assert date.fromisoformat(seed._BACKFILL_LOADED_AT) > seed._BACKFILL_END
    assert _inside(seed._REGION_RENAME_ON)
    assert _inside(seed._EUR_START) and _inside(seed._EUR_END)
    assert _inside(seed.LAUNCH)
    assert _inside(seed._NULL_CHANNEL_BEFORE)
    assert seed.START < seed._NULL_CHANNEL_BEFORE

    first = tmp_path / "one.db"
    second = tmp_path / "two.db"
    seed.rebuild(first)
    seed.rebuild(second)
    assert defect_counts(first) == PINNED_COUNTS
    assert defect_counts(second) == defect_counts(first)
    assert _rows(first) == _rows(second)


def test_ensure_seeded_rebuilds_when_seed_end_changes(tmp_path, monkeypatch):
    monkeypatch.setenv("SEED_END", "2026-10-12")
    path = tmp_path / "warehouse.db"
    seed.ensure_seeded(path)
    assert seed._version(path) == "3-2026-10-12"
    conn = sqlite3.connect(path)
    try:
        conn.execute("INSERT INTO meta (key, value) VALUES ('sentinel', 'keep')")
        conn.commit()
    finally:
        conn.close()

    seed.ensure_seeded(path)
    conn = sqlite3.connect(path)
    try:
        kept = conn.execute("SELECT value FROM meta WHERE key = 'sentinel'").fetchone()
    finally:
        conn.close()
    assert kept == ("keep",)

    monkeypatch.setenv("SEED_END", "2027-01-15")
    seed.ensure_seeded(path)
    assert seed._version(path) == "3-2027-01-15"
    assert (seed.END - seed.START).days == 119
    assert seed.END == date(2027, 1, 15)
    conn = sqlite3.connect(path)
    try:
        sentinel = conn.execute("SELECT value FROM meta WHERE key = 'sentinel'").fetchone()
        latest = conn.execute("SELECT MAX(event_date) FROM revenue").fetchone()[0]
    finally:
        conn.close()
    assert sentinel is None
    assert latest == "2027-01-15"
    counts = defect_counts(path)
    assert all(count > 0 for count in counts.values())
    for raw in seed._DUPLICATE_DATES:
        assert _inside(date.fromisoformat(raw))
    assert _inside(seed._BACKFILL_START) and _inside(seed._BACKFILL_END)
    assert _inside(date.fromisoformat(seed._BACKFILL_LOADED_AT))
    assert _inside(seed._REGION_RENAME_ON)
    assert _inside(seed._EUR_START) and _inside(seed._EUR_END)
    assert _inside(seed.LAUNCH)
    assert _inside(seed._NULL_CHANNEL_BEFORE)
