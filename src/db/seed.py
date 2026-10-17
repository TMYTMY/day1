"""Deterministic sample warehouse for the SQLite demo.

The date window is relative. END is the SEED_END environment variable
(YYYY-MM-DD) when that variable is set, which pins the window, and otherwise
three days before today. START is 119 days before END, so the window length
stays fixed. The RNG seed is fixed, and the same SEED_END produces the same
rows on every run.

Revenue grain: event_date × product × region × channel.
DAU grain: event_date × platform × country. Countries partition a platform's
users.

The revenue load also plants five deterministic defects so the demo is not a
perfect table: duplicate grain rows, a late backfill, NULL channels, an
EMEA → E.U. rename, and a stretch of EUR amounts stored in revenue_usd.
Each defect is an offset from START or END, so it stays inside the window.
"""

from __future__ import annotations

import os
import random
import sqlite3
from datetime import date, timedelta
from pathlib import Path

# Inclusive span is one day longer. (END - START).days stays 119.
WINDOW_DAYS = 119
_EUR_LIST_FACTOR = 1.10

# Filled by resolve_seed_window(). Importers keep using these names.
SEED_VERSION = ""
START = date.min
END = date.min
LAUNCH = date.min
_BACKFILL_START = date.min
_BACKFILL_END = date.min
_BACKFILL_LOADED_AT = ""
_REGION_RENAME_ON = date.min
_EUR_START = date.min
_EUR_END = date.min
_DUPLICATE_DATES: frozenset[str] = frozenset()
# Harbor partner rows on days strictly before this date have a NULL channel.
_NULL_CHANNEL_BEFORE = date.min


def _month_containing(anchor: date) -> tuple[date, date]:
    first = date(anchor.year, anchor.month, 1)
    if anchor.month == 12:
        next_month = date(anchor.year + 1, 1, 1)
    else:
        next_month = date(anchor.year, anchor.month + 1, 1)
    return first, next_month - timedelta(days=1)


def resolve_seed_window(today: date | None = None) -> None:
    """Resolve START, END, and every defect anchor from SEED_END or today.

    Called once per seed or rebuild. Offsets below match the previous absolute
    dates when END is 2026-10-12: duplicates on START+0..2, the calendar month
    containing START+47, NULL channels before START+16, the region rename on
    START+78, the backfill load on START+95, EUR amounts from END-11 through
    END-5, and the product launch on START+85.
    """
    global SEED_VERSION, START, END, LAUNCH
    global _BACKFILL_START, _BACKFILL_END, _BACKFILL_LOADED_AT
    global _REGION_RENAME_ON, _EUR_START, _EUR_END
    global _DUPLICATE_DATES, _NULL_CHANNEL_BEFORE

    raw = os.environ.get("SEED_END", "").strip()
    if raw:
        end = date.fromisoformat(raw)
    else:
        end = (today or date.today()) - timedelta(days=3)
    start = end - timedelta(days=WINDOW_DAYS)
    backfill_start, backfill_end = _month_containing(start + timedelta(days=47))

    START = start
    END = end
    SEED_VERSION = f"3-{end.isoformat()}"
    LAUNCH = start + timedelta(days=85)
    _BACKFILL_START = backfill_start
    _BACKFILL_END = backfill_end
    _BACKFILL_LOADED_AT = (start + timedelta(days=95)).isoformat()
    _REGION_RENAME_ON = start + timedelta(days=78)
    _EUR_START = end - timedelta(days=11)
    _EUR_END = end - timedelta(days=5)
    _DUPLICATE_DATES = frozenset(
        (start + timedelta(days=offset)).isoformat() for offset in (0, 1, 2)
    )
    _NULL_CHANNEL_BEFORE = start + timedelta(days=16)


resolve_seed_window()

PRODUCTS = ("Atlas", "Northstar", "Harbor")
REGIONS = ("AMER", "EMEA", "APAC")
CHANNELS = ("direct", "partner", "self-serve")
PLATFORMS = ("ios", "android", "web")
COUNTRY_SHARE = (
    ("US", 0.38),
    ("GB", 0.14),
    ("DE", 0.12),
    ("HK", 0.16),
    ("SG", 0.20),
)


def _days() -> list[date]:
    count = (END - START).days
    return [START + timedelta(days=offset) for offset in range(count + 1)]


def _apportion(total: int, weights: tuple[tuple[str, float], ...]) -> dict[str, int]:
    raw = [(name, total * weight) for name, weight in weights]
    floors = {name: int(value) for name, value in raw}
    leftover = total - sum(floors.values())
    ranked = sorted(raw, key=lambda item: item[1] - int(item[1]), reverse=True)
    for index in range(leftover):
        floors[ranked[index][0]] += 1
    return floors


def _revenue_rows(rng: random.Random) -> list[tuple]:
    product_base = {"Atlas": 4800.0, "Northstar": 2200.0, "Harbor": 3100.0}
    region_mult = {"AMER": 1.15, "EMEA": 0.92, "APAC": 1.05}
    channel_mult = {"direct": 1.20, "partner": 0.75, "self-serve": 0.90}
    order_value = {"direct": 92.0, "partner": 150.0, "self-serve": 48.0}
    rows = []
    for day in _days():
        weekend = day.weekday() >= 5
        trend = 1 + (day - START).days * 0.0015
        for product in PRODUCTS:
            for region in REGIONS:
                for channel in CHANNELS:
                    value = product_base[product] * region_mult[region] * channel_mult[channel]
                    if weekend:
                        value *= 0.72
                    if product == "Northstar" and day >= LAUNCH:
                        value *= 1.65
                    value *= trend * (1 + rng.uniform(-0.08, 0.08))
                    revenue = round(value, 2)
                    orders = max(1, int(round(revenue / order_value[channel])))
                    rows.append((day.isoformat(), product, region, channel, revenue, orders))
    return _apply_revenue_defects(rows)


def _apply_revenue_defects(rows: list[tuple]) -> list[tuple]:
    """Return revenue rows plus the five fixed defects. No extra randomness."""
    daily: list[tuple] = []
    held_for_backfill: list[tuple] = []
    for event_date, product, region, channel, revenue, orders in rows:
        day = date.fromisoformat(event_date)
        ingest_batch = "daily"
        loaded_at = event_date
        currency = "USD"
        if region == "EMEA" and day >= _REGION_RENAME_ON:
            region = "E.U."
        if product == "Harbor" and channel == "partner" and day < _NULL_CHANNEL_BEFORE:
            channel = None
        if _EUR_START <= day <= _EUR_END:
            revenue = round(revenue * _EUR_LIST_FACTOR, 2)
            currency = "EUR"
        record = (event_date, product, region, channel, revenue, orders, ingest_batch, loaded_at, currency)
        if product == "Harbor" and _BACKFILL_START <= day <= _BACKFILL_END:
            held_for_backfill.append(record)
        else:
            daily.append(record)
    duplicates = [
        row
        for row in daily
        if row[0] in _DUPLICATE_DATES and row[1] == "Atlas" and row[2] == "AMER" and row[3] == "direct"
    ]
    backfill = [
        (event_date, product, region, channel, revenue, orders, "backfill", _BACKFILL_LOADED_AT, currency)
        for event_date, product, region, channel, revenue, orders, _batch, _loaded, currency in held_for_backfill
    ]
    return daily + duplicates + backfill


def _dau_rows(rng: random.Random) -> list[tuple]:
    platform_base = {"ios": 14000, "android": 16500, "web": 7200}
    rows = []
    for day in _days():
        weekend = day.weekday() >= 5
        trend = 1 + (day - START).days * 0.0012
        launch = 1.28 if day >= LAUNCH else 1.0
        new_ratio = 0.08 if day >= LAUNCH else 0.045
        for platform in PLATFORMS:
            base = platform_base[platform] * trend * launch
            if weekend:
                base *= 1.08
            total = max(0, int(round(base * (1 + rng.uniform(-0.04, 0.04)))))
            shares = _apportion(total, COUNTRY_SHARE)
            for country, dau in shares.items():
                new_users = min(dau, int(round(dau * new_ratio)))
                rows.append((day.isoformat(), platform, country, dau, new_users))
    return rows


def rebuild(path: Path) -> None:
    resolve_seed_window()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists():
            sidecar.unlink()
    rng = random.Random(7)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE revenue (
                event_date TEXT NOT NULL,
                product TEXT NOT NULL,
                region TEXT NOT NULL,
                channel TEXT,
                revenue_usd REAL NOT NULL,
                orders INTEGER NOT NULL,
                ingest_batch TEXT NOT NULL,
                loaded_at TEXT NOT NULL,
                amount_currency TEXT NOT NULL
            );
            CREATE TABLE dau (
                event_date TEXT NOT NULL,
                platform TEXT NOT NULL,
                country TEXT NOT NULL,
                dau INTEGER NOT NULL,
                new_users INTEGER NOT NULL
            );
            CREATE TABLE meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE INDEX idx_revenue_event_date ON revenue(event_date);
            CREATE INDEX idx_dau_event_date ON dau(event_date);
            """
        )
        conn.executemany(
            """
            INSERT INTO revenue (
                event_date, product, region, channel, revenue_usd, orders,
                ingest_batch, loaded_at, amount_currency
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            _revenue_rows(rng),
        )
        conn.executemany(
            "INSERT INTO dau VALUES (?, ?, ?, ?, ?)",
            _dau_rows(rng),
        )
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('seed_version', ?)",
            (SEED_VERSION,),
        )
        conn.commit()
    finally:
        conn.close()


def _version(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        conn = sqlite3.connect(path)
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'seed_version'"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    return str(row[0])


def ensure_seeded(path: Path) -> None:
    resolve_seed_window()
    if _version(path) == SEED_VERSION:
        return
    rebuild(path)


def main() -> None:
    from src.config import ROOT

    target = ROOT / "data" / "demo.db"
    rebuild(target)
    print(f"Wrote {target}")


if __name__ == "__main__":
    main()
