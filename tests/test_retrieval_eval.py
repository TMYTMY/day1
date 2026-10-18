"""Offline retrieval harness: arithmetic, review gate, schema, local embedder."""

from __future__ import annotations

from pathlib import Path

import yaml

from scripts.eval_retrieval import (
    DEFAULT_INDEX,
    DEFAULT_LABELS,
    aggregate,
    build_store,
    evaluate,
    load_index,
    render,
    run,
    score_filenames,
    to_json,
)
from src.config import ROOT

CORPUS = ROOT / "tests" / "retrieval" / "corpus"
INDEX = yaml.safe_load(DEFAULT_INDEX.read_text(encoding="utf-8"))
LABELS = yaml.safe_load(DEFAULT_LABELS.read_text(encoding="utf-8"))


def test_arithmetic_on_a_synthetic_fixture():
    scored = [
        score_filenames(["a.md"], ["a.md", "b.md", "c.md"], 4),
        score_filenames(["b.md"], ["a.md", "b.md", "c.md"], 4),
        score_filenames(["missing.md"], ["a.md", "b.md", "c.md"], 4),
    ]
    assert [item["rank"] for item in scored] == [1, 2, None]
    assert [item["outcome"] for item in scored] == ["rank", "rank", "miss"]
    recall_at_1, recall_at_k, mrr_at_k = aggregate(scored)
    assert recall_at_1 == 1 / 3
    assert recall_at_k == 2 / 3
    assert mrr_at_k == (1 + 0.5 + 0) / 3

    correct_negative = score_filenames([], [], 4)
    failed_negative = score_filenames([], ["other.md"], 4)
    assert correct_negative["outcome"] == "negative"
    assert correct_negative["hit_at_1"] is True
    assert correct_negative["reciprocal"] == 1.0
    assert failed_negative["outcome"] == "answered_a_negative"
    assert failed_negative["hit_at_k"] is False
    assert failed_negative["reciprocal"] == 0.0

    # Abstaining is not ranking: a correct negative is reported as abstention
    # and stays out of recall and MRR, or it would pass for a rank-1 hit.
    assert correct_negative["scored"] is False
    assert failed_negative["scored"] is False
    only_negatives = [correct_negative, failed_negative]
    try:
        aggregate(only_negatives)
    except ValueError:
        pass
    else:
        raise AssertionError("aggregate must refuse a list with no positively labelled query")
    mixed = [*scored, correct_negative, failed_negative]
    assert aggregate(mixed) == (1 / 3, 2 / 3, (1 + 0.5 + 0) / 3)


def test_review_gate_withholds_headline_until_every_label_is_reviewed():
    pending = [
        {
            "id": "q01",
            "question": "first",
            "role": "finance",
            "expected": ["a.md"],
            "reviewed": False,
        },
        {
            "id": "q02",
            "question": "second",
            "role": "finance",
            "expected": ["b.md"],
            "reviewed": False,
        },
        {
            "id": "q03",
            "question": "third",
            "role": "growth",
            "expected": ["missing.md"],
            "reviewed": True,
        },
    ]

    def search(question, *, role, limit):
        return [{"filename": "a.md"}, {"filename": "b.md"}, {"filename": "c.md"}][:limit]

    withheld = evaluate(pending, search, k=4, provider="Local hash")
    text = render(withheld)
    assert withheld["headline_withheld"] is True
    assert withheld["exit_code"] == 2
    assert withheld["unreviewed"] == 2
    assert "recall_at_1" not in withheld
    assert "2/3 labels not human-reviewed — headline number withheld" in text
    assert "recall@" not in text
    assert "MRR" not in text
    payload = to_json(withheld)
    assert payload["headline_withheld"] is True
    assert "recall_at_1" not in payload
    assert "mrr_at_k" not in payload

    opened_entries = [{**entry, "reviewed": True} for entry in pending]
    opened = evaluate(opened_entries, search, k=4, provider="Local hash")
    opened_text = render(opened)
    assert opened["headline_withheld"] is False
    assert opened["exit_code"] == 0
    assert opened["recall_at_1"] == 1 / 3
    assert opened["recall_at_k"] == 2 / 3
    assert opened["mrr_at_k"] == (1 + 0.5 + 0) / 3
    assert "provider: Local hash" in opened_text
    assert "recall@1 = " in opened_text
    assert "recall@4 = " in opened_text
    assert "MRR@4 = " in opened_text
    opened_payload = to_json(opened)
    assert opened_payload["headline_withheld"] is False
    assert opened_payload["recall_at_1"] == opened["recall_at_1"]
    assert opened_payload["mrr_at_k"] == opened["mrr_at_k"]


def test_label_file_matches_the_corpus_index():
    assert 12 <= len(INDEX) <= 15
    filenames = set()
    role_counts: dict[str, int] = {}
    for item in INDEX:
        assert {"filename", "owner_role", "summary"} <= set(item)
        name = item["filename"]
        assert name not in filenames
        filenames.add(name)
        body = (CORPUS / name).read_text(encoding="utf-8")
        assert 100 <= len(body.split()) <= 400
        role_counts[item["owner_role"]] = role_counts.get(item["owner_role"], 0) + 1
    assert role_counts["finance"] >= 3
    assert role_counts["growth"] >= 3
    assert role_counts["shared"] >= 3
    pair = [item for item in INDEX if item["filename"].endswith("-revenue-duplicate.md")]
    assert len(pair) == 2
    assert {item["owner_role"] for item in pair} == {"finance", "growth"}

    assert 20 <= len(LABELS) <= 25
    # The labels were read question-by-question and certified by a person, so
    # they count. A draft added later may start unreviewed: that is allowed,
    # and the evaluator withholds every figure until it is reviewed.
    assert sum(1 for entry in LABELS if entry["reviewed"]) >= 20
    ids = [entry["id"] for entry in LABELS]
    assert len(ids) == len(set(ids))
    raw = DEFAULT_LABELS.read_text(encoding="utf-8").lower()
    for banned in ("recall@", "mrr", "accuracy"):
        assert banned not in raw
    for entry in LABELS:
        assert isinstance(entry["id"], str) and entry["id"]
        assert isinstance(entry["question"], str) and entry["question"]
        assert isinstance(entry["role"], str) and entry["role"]
        assert isinstance(entry["reviewed"], bool)
        for key in ("recall", "mrr", "accuracy", "precision"):
            assert key not in entry
        expected = entry["expected"]
        assert isinstance(expected, list)
        for name in expected:
            assert name in filenames


def test_evaluator_builds_a_local_store_and_does_not_call_the_network(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("retrieval eval must not use the network")

    monkeypatch.setattr("src.knowledge.embed.requests.post", refuse)
    monkeypatch.setattr("requests.post", refuse)
    monkeypatch.setattr("requests.get", refuse)

    stray = CORPUS / "stray.md"
    assert not stray.exists()
    store = build_store(tmp_path / "store", DEFAULT_INDEX)
    assert store.embedder.provider == "local"
    assert store.embedder.label() == "Local hash"
    indexed = set()
    for role in ("finance", "growth"):
        indexed.update(item.filename for item in store.list_documents(role=role))
    assert indexed == {item["filename"] for item in load_index(DEFAULT_INDEX)}

    report = run(DEFAULT_LABELS, k=4, store_dir=tmp_path / "run")
    assert report["provider"] == "Local hash"
    # Every label is certified, so the headline is reported. The figures are
    # measured, never asserted to a floor: a test that pinned "recall >= 0.8"
    # would be an expectation dressed up as a measurement.
    assert report["headline_withheld"] is False
    assert report["exit_code"] == 0
    assert report["positives"] + report["negatives"] == report["total"]
    assert 0.0 <= report["recall_at_1"] <= 1.0
    assert 0.0 <= report["recall_at_k"] <= 1.0
    assert 0.0 <= report["mrr_at_k"] <= 1.0
    assert report["recall_at_1"] <= report["recall_at_k"]
    assert 0 <= report["abstained"] <= report["negatives"]
    text = render(report)
    assert "recall@1 = " in text and "MRR@4 = " in text
    assert f"scored over {report['positives']} positively labelled queries" in text
    assert "headline number withheld" not in text
    assert Path(str(tmp_path)).exists()
