"""Score the golden question file against the metric matcher.

The printed accuracy is agreement with labels in tests/golden/questions.yaml.
Those labels were written for this catalogue, so the number is internal
consistency, not validation against a real business definition.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.metrics import match_metrics

QUESTIONS = ROOT / "tests" / "golden" / "questions.yaml"


def expected_ids(case: dict) -> set[str]:
    if "expected_metric_ids" in case:
        return set(case["expected_metric_ids"] or [])
    single = case.get("expected_metric_id")
    return {single} if single else set()


def evaluate(path: Path = QUESTIONS) -> tuple[int, int, list[str]]:
    cases = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or len(cases) < 30:
        raise SystemExit(f"Golden file needs at least 30 questions, found {len(cases) if isinstance(cases, list) else 0}.")
    failures: list[str] = []
    passed = 0
    for case in cases:
        question = case["question"]
        expected = expected_ids(case)
        got = {metric.id for metric in match_metrics(question)}
        table = case.get("expected_table")
        tables = {metric.table for metric in match_metrics(question)}
        table_ok = table is None or tables == {table} or (not got and table is None)
        if table is not None and got:
            table_ok = tables == {table}
        elif table is None:
            table_ok = True
        if got == expected and table_ok:
            passed += 1
        else:
            failures.append(f"{question!r}: expected {sorted(expected)}, got {sorted(got)}")
    return passed, len(cases), failures


def main() -> int:
    passed, total, failures = evaluate()
    ratio = passed / total if total else 0.0
    print(f"accuracy = {passed}/{total} = {ratio:.3f}")
    for line in failures:
        print(line)
    return 0 if ratio >= 0.8 else 1


if __name__ == "__main__":
    raise SystemExit(main())
