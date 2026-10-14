"""The demo seed plants five defects, and a clean rebuild still shows all five."""

from __future__ import annotations

from src.db.quality import QUERIES, defect_counts
from src.db.seed import rebuild

EXPECTED = (
    "duplicate_rows",
    "late_arriving_backfill",
    "null_channel",
    "region_rename",
    "unit_contamination",
)


def test_clean_rebuild_still_detects_every_seeded_defect(tmp_path):
    path = tmp_path / "warehouse.db"
    rebuild(path)
    first = defect_counts(path)
    assert tuple(name for name, _sql in QUERIES) == EXPECTED
    assert tuple(first) == EXPECTED
    assert all(count > 0 for count in first.values())

    rebuild(path)
    second = defect_counts(path)
    assert second == first
    assert all(count > 0 for count in second.values())
