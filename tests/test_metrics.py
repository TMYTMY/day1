from datetime import date
from pathlib import Path

import pytest
import yaml

from src.config import ROOT, ConfigError
from src.metrics import definition_hash, load_metrics, match_metrics

CATALOGUE = ROOT / "config" / "metrics.yaml"
TODAY = date(2026, 10, 14)

_TEMPLATE = {
    "title": "Revenue by product",
    "synonyms": ["revenue"],
    "table": "revenue",
    "grain": ["event_date", "product", "region", "channel"],
    "additive_over": ["event_date", "product", "region"],
    "definition": "PLACEHOLDER — 需由業務方確認",
    "owner": "placeholder",
    "effective_from": "2026-06-15",
    "supersedes": None,
    "exceptions": "PLACEHOLDER — 需由業務方確認",
}


def _write(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "metrics.yaml"
    path.write_text(yaml.safe_dump(entries, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path


def test_the_same_question_matches_the_same_metrics_three_times():
    question = "What was total revenue by product over the last 90 days?"
    first = match_metrics(question, today=TODAY)
    second = match_metrics(question, today=TODAY)
    third = match_metrics(question, today=TODAY)
    assert first == second == third
    assert [metric.id for metric in first] == ["revenue_by_product"]


def test_a_future_metric_is_not_matched(tmp_path):
    path = _write(
        tmp_path,
        [
            {
                **_TEMPLATE,
                "id": "revenue_future",
                "effective_from": "2099-01-01",
            }
        ],
    )
    catalogue = load_metrics(path)
    assert catalogue[0].effective_from == date(2099, 1, 1)
    assert match_metrics("total revenue", catalogue, today=TODAY) == []


def test_a_superseded_metric_is_not_matched(tmp_path):
    path = _write(
        tmp_path,
        [
            {**_TEMPLATE, "id": "revenue_old", "effective_from": "2026-01-01", "supersedes": None},
            {
                **_TEMPLATE,
                "id": "revenue_new",
                "effective_from": "2026-06-15",
                "supersedes": "revenue_old",
                "synonyms": ["revenue"],
            },
        ],
    )
    catalogue = load_metrics(path)
    matched = match_metrics("total revenue", catalogue, today=TODAY)
    assert [metric.id for metric in matched] == ["revenue_new"]

    future_path = _write(
        tmp_path,
        [
            {**_TEMPLATE, "id": "revenue_old", "effective_from": "2026-01-01"},
            {
                **_TEMPLATE,
                "id": "revenue_later",
                "effective_from": "2099-01-01",
                "supersedes": "revenue_old",
            },
        ],
    )
    later = match_metrics("total revenue", load_metrics(future_path), today=TODAY)
    assert [metric.id for metric in later] == ["revenue_old"]


def test_a_dangling_supersede_is_rejected(tmp_path):
    path = _write(
        tmp_path,
        [{**_TEMPLATE, "id": "revenue_old", "supersedes": "missing_metric"}],
    )
    with pytest.raises(ConfigError, match="not in the catalogue"):
        load_metrics(path)


def test_a_supersede_cycle_is_rejected(tmp_path):
    path = _write(
        tmp_path,
        [
            {**_TEMPLATE, "id": "revenue_a", "supersedes": "revenue_b"},
            {**_TEMPLATE, "id": "revenue_b", "supersedes": "revenue_a"},
        ],
    )
    with pytest.raises(ConfigError, match="cycle"):
        load_metrics(path)


def test_a_cross_table_supersede_is_rejected(tmp_path):
    path = _write(
        tmp_path,
        [
            {**_TEMPLATE, "id": "revenue_old", "table": "revenue"},
            {
                **_TEMPLATE,
                "id": "dau_new",
                "table": "dau",
                "synonyms": ["dau"],
                "supersedes": "revenue_old",
            },
        ],
    )
    with pytest.raises(ConfigError, match="cannot supersede"):
        load_metrics(path)


def test_definition_hash_is_stable_and_twelve_hex_characters():
    metric = next(item for item in load_metrics(CATALOGUE) if item.id == "revenue_by_product")
    digest = definition_hash(metric)
    assert digest == definition_hash(metric)
    assert len(digest) == 12
    assert digest == bytes.fromhex(digest).hex()


def test_a_missing_field_is_rejected(tmp_path):
    entry = {**_TEMPLATE, "id": "revenue_by_product"}
    del entry["definition"]
    path = _write(tmp_path, [entry])
    with pytest.raises(ConfigError, match="definition"):
        load_metrics(path)


def test_catalogue_definitions_are_marked_placeholder():
    text = CATALOGUE.read_text(encoding="utf-8")
    definition_lines = [line for line in text.splitlines() if line.strip().startswith("definition:")]
    assert len(definition_lines) >= 4
    assert all("# PLACEHOLDER — 需由業務方確認" in line for line in definition_lines)
