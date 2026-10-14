from pathlib import Path

import pytest
import yaml

from scripts.eval_golden import expected_ids
from src.config import ROOT
from src.metrics import match_metrics

CASES = yaml.safe_load((ROOT / "tests" / "golden" / "questions.yaml").read_text(encoding="utf-8"))


def test_the_golden_file_covers_both_topics_and_match_counts():
    assert len(CASES) >= 30
    tables = {case.get("expected_table") for case in CASES}
    assert "revenue" in tables and "dau" in tables
    sizes = {len(expected_ids(case)) for case in CASES}
    assert sizes == {0, 1, 2}
    english = [case for case in CASES if case["question"].isascii()]
    chinese = [case for case in CASES if not case["question"].isascii()]
    assert english and chinese


@pytest.mark.parametrize("case", CASES, ids=[case["question"] for case in CASES])
def test_golden_question_matches_the_labeled_metrics(case):
    got = {metric.id for metric in match_metrics(case["question"])}
    assert got == expected_ids(case)
