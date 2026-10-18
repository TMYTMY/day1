"""Score knowledge-base retrieval against a labelled question file.

Headline figures stay withheld until every label is human-reviewed.
This script does not record a measurement of its own.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import ROOT as PROJECT_ROOT
from src.config import Settings
from src.knowledge.store import KnowledgeStore

DEFAULT_LABELS = PROJECT_ROOT / "tests" / "retrieval" / "labels.yaml"
DEFAULT_INDEX = PROJECT_ROOT / "tests" / "retrieval" / "corpus" / "index.yaml"


def load_index(path: Path) -> list[dict]:
    """Read the corpus manifest. Only files named here are indexed."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError(f"{path} must list the corpus files.")
    rows: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError(f"{path} entries must be mappings.")
        filename = item["filename"]
        owner_role = item["owner_role"]
        summary = item["summary"]
        if not isinstance(filename, str) or not isinstance(owner_role, str):
            raise ValueError(f"{path} needs filename and owner_role strings.")
        if not isinstance(summary, str):
            raise ValueError(f"{path} needs a one-line summary.")
        rows.append(
            {"filename": filename, "owner_role": owner_role, "summary": summary}
        )
    return rows


def load_labels(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError(f"{path} must list labelled questions.")
    rows: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError(f"{path} entries must be mappings.")
        expected = item.get("expected") or []
        if not isinstance(expected, list) or not all(isinstance(name, str) for name in expected):
            raise ValueError(f"{item.get('id', '?')} expected must be a list of filenames.")
        reviewed = item["reviewed"]
        if not isinstance(reviewed, bool):
            raise ValueError(f"{item.get('id', '?')} reviewed must be a boolean.")
        role = item["role"]
        question = item["question"]
        label_id = item["id"]
        if not all(isinstance(value, str) and value.strip() for value in (role, question, label_id)):
            raise ValueError(f"{path} needs id, question, and role strings.")
        rows.append(
            {
                "id": label_id,
                "question": question,
                "role": role,
                "expected": list(expected),
                "reviewed": reviewed,
                "note": item.get("note") or "",
            }
        )
    return rows


def score_filenames(expected: list[str], filenames: list[str], k: int) -> dict:
    """Score one result list.

    `filenames` is the ranked list already limited to hits at or above the
    store threshold. An empty `expected` list is a negative: the right
    behaviour is abstaining, which is a different question from ranking, so a
    negative is marked ``"scored": False`` and kept out of recall and MRR. It
    is reported as abstention instead; counting it as a rank-1 hit would
    inflate both figures by construction.
    """
    capped = list(filenames)[:k]
    if not expected:
        correct = not capped
        return {
            "outcome": "negative" if correct else "answered_a_negative",
            "rank": None,
            "hit_at_1": correct,
            "hit_at_k": correct,
            "reciprocal": 1.0 if correct else 0.0,
            "scored": False,
        }
    wanted = set(expected)
    for index, name in enumerate(capped, start=1):
        if name in wanted:
            return {
                "outcome": "rank",
                "rank": index,
                "hit_at_1": index == 1,
                "hit_at_k": True,
                "reciprocal": 1.0 / index,
                "scored": True,
            }
    return {
        "outcome": "miss",
        "rank": None,
        "hit_at_1": False,
        "hit_at_k": False,
        "reciprocal": 0.0,
        "scored": True,
    }


def aggregate(scored: list[dict]) -> tuple[float, float, float]:
    """Return recall@1, recall@k, and MRR@k for the positively labelled queries.

    Negatives are excluded: abstaining is measured separately, so a correct
    abstention cannot pass for a top-ranked hit.
    """
    scored = [item for item in scored if item.get("scored", True)]
    total = len(scored)
    if total == 0:
        raise ValueError("aggregate needs at least one positively labelled query.")
    recall_at_1 = sum(1 for item in scored if item["hit_at_1"]) / total
    recall_at_k = sum(1 for item in scored if item["hit_at_k"]) / total
    mrr_at_k = sum(float(item["reciprocal"]) for item in scored) / total
    return recall_at_1, recall_at_k, mrr_at_k


def evaluate(entries: list[dict], search, *, k: int, provider: str) -> dict:
    """Score `entries` with a search(question, role=, limit=) callable.

    Unreviewed labels withhold the headline figures. Per-query rank or miss
    is still returned so a reviewer can see the harness work.
    """
    scored_entries: list[dict] = []
    for entry in entries:
        hits = search(entry["question"], role=entry["role"], limit=k)
        filenames = []
        for hit in hits:
            if hasattr(hit, "filename"):
                name = hit.filename
            elif isinstance(hit, dict):
                name = hit["filename"]
            else:
                name = hit
            filenames.append(name)
        scored = score_filenames(list(entry.get("expected") or []), filenames, k)
        scored_entries.append({"id": entry["id"], **scored})
    unreviewed = sum(1 for entry in entries if entry["reviewed"] is not True)
    total = len(entries)
    withheld = unreviewed > 0
    positives = sum(1 for item in scored_entries if item.get("scored", True))
    negatives = [item for item in scored_entries if not item.get("scored", True)]
    report = {
        "provider": provider,
        "k": k,
        "headline_withheld": withheld,
        "unreviewed": unreviewed,
        "total": total,
        "positives": positives,
        "negatives": len(negatives),
        "abstained": sum(1 for item in negatives if item["outcome"] == "negative"),
        "entries": scored_entries,
        "exit_code": 2 if withheld else 0,
    }
    if not withheld:
        recall_at_1, recall_at_k, mrr_at_k = aggregate(scored_entries)
        report["recall_at_1"] = recall_at_1
        report["recall_at_k"] = recall_at_k
        report["mrr_at_k"] = mrr_at_k
    return report


def render(report: dict) -> str:
    lines = [f"provider: {report['provider']}"]
    for entry in report["entries"]:
        if entry["outcome"] == "rank":
            lines.append(f"{entry['id']}: rank {entry['rank']}")
        elif entry["outcome"] == "negative":
            lines.append(f"{entry['id']}: negative")
        else:
            lines.append(f"{entry['id']}: miss")
    if report["headline_withheld"]:
        lines.append(
            f"{report['unreviewed']}/{report['total']} labels not human-reviewed — headline number withheld"
        )
    else:
        k = report["k"]
        lines.append(
            f"scored over {report['positives']} positively labelled queries "
            f"(of {report['total']} labels)"
        )
        lines.append(f"recall@1 = {report['recall_at_1']}")
        lines.append(f"recall@{k} = {report['recall_at_k']}")
        lines.append(f"MRR@{k} = {report['mrr_at_k']}")
        if report["negatives"]:
            lines.append(
                f"abstention on negatives = {report['abstained']}/{report['negatives']}"
            )
    return "\n".join(lines)


def to_json(report: dict) -> dict:
    payload = {
        "provider": report["provider"],
        "k": report["k"],
        "headline_withheld": report["headline_withheld"],
        "unreviewed": report["unreviewed"],
        "total": report["total"],
        "positives": report["positives"],
        "negatives": report["negatives"],
        "abstained": report["abstained"],
        "entries": [
            {"id": entry["id"], "outcome": entry["outcome"], "rank": entry["rank"]}
            for entry in report["entries"]
        ],
    }
    if not report["headline_withheld"]:
        payload["positives_only"] = True
        payload["recall_at_1"] = report["recall_at_1"]
        payload["recall_at_k"] = report["recall_at_k"]
        payload["mrr_at_k"] = report["mrr_at_k"]
    return payload


def _settings(knowledge_path: Path) -> Settings:
    return Settings(
        db_backend="sqlite",
        db_path=knowledge_path / "unused.db",
        database_url=None,
        db_user=None,
        db_password=None,
        athena_region=None,
        athena_database=None,
        athena_workgroup=None,
        athena_output=None,
        audit_path=knowledge_path / "audit.db",
        routing_path=PROJECT_ROOT / "config" / "routing.yaml",
        users_path=PROJECT_ROOT / "config" / "users.yaml",
        openrouter_api_key=None,
        openrouter_model="openai/gpt-4o-mini",
        openrouter_base_url="https://openrouter.ai/api/v1",
        max_rows=500,
        knowledge_path=knowledge_path,
        embedding_provider="local",
        embedding_model="openai/text-embedding-3-small",
        embedding_api_key=None,
    )


def build_store(directory: Path, index_path: Path) -> KnowledgeStore:
    """Index the manifest into a throwaway store. Provider is local."""
    directory.mkdir(parents=True, exist_ok=True)
    store = KnowledgeStore(_settings(directory))
    if store.embedder.provider != "local":
        raise RuntimeError("The retrieval harness must use the local embedder.")
    for item in load_index(index_path):
        body = (index_path.parent / item["filename"]).read_bytes()
        store.add_document(
            item["filename"],
            body,
            owner="eval",
            owner_role=item["owner_role"],
        )
    return store


def run(
    labels_path: Path,
    *,
    k: int = 4,
    index_path: Path = DEFAULT_INDEX,
    store_dir: Path,
) -> dict:
    entries = load_labels(labels_path)
    store = build_store(store_dir, index_path)
    return evaluate(entries, store.search, k=k, provider=store.embedder.label())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the retrieval harness. Headline figures stay withheld until every label is reviewed."
    )
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--k", type=int, default=4)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.k < 1:
        print("k must be at least 1", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        report = run(args.labels, k=args.k, store_dir=Path(tmp))
    if args.json:
        print(json.dumps(to_json(report), indent=2, sort_keys=True))
    else:
        print(render(report))
    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
