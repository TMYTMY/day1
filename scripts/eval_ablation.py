"""Show that a knowledge note is the only change in the model request.

The default path uses a scripted reply and does not call a model. Identical
SQL on that path says nothing about how a live model would behave. The live
path is for a person to run by hand. Tests do not use it.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.audit import AuditLog
from src.auth import authenticate
from src.config import ROOT as PROJECT_ROOT
from src.config import Settings, load_settings
from src.db.seed import rebuild
from src.db.sqlite import SqliteAdapter
from src.knowledge.store import KnowledgeStore
from src.llm import LlmClient
from src.pipeline import answer_question
from src.routing import load_catalog

QUESTION = "What was total revenue by product over the last 90 days?"
NOTE = (
    "Booked revenue means the revenue_usd column. "
    "Northstar is the flagship product in the revenue table. "
    "FINANCE_NOTE_CANARY"
)
SCRIPTED_REPLY = (
    '{"sql": "SELECT product, SUM(revenue_usd) AS revenue_usd '
    'FROM revenue GROUP BY product", "assumptions": "Grouped by product."}'
)
_NOTES = "\n\nSupplemental notes from the knowledge base."
_METRIC = "\n\nAuthoritative metric definition"
_DEFAULT_BASE = "https://openrouter.ai/api/v1"
_WIRING = (
    "WIRING ONLY — the scripted model does not reason, so identical SQL here "
    "proves nothing about model behaviour"
)


class _Scripted:
    def __init__(self, reply: str):
        self.reply = reply
        self.configured = True
        self.seen: list = []

    def complete(self, messages):
        self.seen.append(messages)
        return self.reply


def _settings(root: Path) -> Settings:
    return Settings(
        db_backend="sqlite",
        db_path=root / "demo.db",
        database_url=None,
        db_user=None,
        db_password=None,
        athena_region=None,
        athena_database=None,
        athena_workgroup=None,
        athena_output=None,
        audit_path=root / "audit.db",
        routing_path=PROJECT_ROOT / "config" / "routing.yaml",
        users_path=PROJECT_ROOT / "config" / "users.yaml",
        openrouter_api_key=None,
        openrouter_model="openai/gpt-4o-mini",
        openrouter_base_url=_DEFAULT_BASE,
        max_rows=500,
        knowledge_path=root / "knowledge",
        embedding_provider="local",
        embedding_model="openai/text-embedding-3-small",
        embedding_api_key=None,
    )


def notes_block(system: str) -> str:
    if _NOTES not in system:
        return ""
    start = system.index(_NOTES)
    end = system.index(_METRIC, start) if _METRIC in system[start:] else len(system)
    return system[start:end]


def strip_notes(system: str) -> str:
    block = notes_block(system)
    if not block:
        return system
    return system.replace(block, "", 1)


def live_ready() -> bool:
    """True when a person has pointed this process at a model endpoint.

    A custom OPENROUTER_BASE_URL counts. The default OpenRouter host does not,
    unless OPENROUTER_API_KEY is set. This does not load a dotenv file.
    """
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    base = os.environ.get("OPENROUTER_BASE_URL", "").strip().rstrip("/")
    if key:
        return True
    return bool(base) and base != _DEFAULT_BASE


def _passes(root: Path, llm) -> dict:
    db_path = root / "demo.db"
    rebuild(db_path)
    base = _settings(root)
    noted_settings = replace(base, knowledge_path=root / "noted")
    empty_settings = replace(base, knowledge_path=root / "empty")
    noted_store = KnowledgeStore(noted_settings)
    noted_store.add_document("glossary.md", NOTE.encode(), owner="finance", owner_role="finance")
    empty_store = KnowledgeStore(empty_settings)
    user = authenticate("finance", "finance", base.users_path)
    catalog = load_catalog(base.routing_path)
    adapter = SqliteAdapter(db_path)
    noted_audit = AuditLog(root / "audit-noted.db")
    empty_audit = AuditLog(root / "audit-empty.db")
    noted = answer_question(
        QUESTION,
        user,
        settings=base,
        adapter=adapter,
        catalog=catalog,
        audit=noted_audit,
        llm=llm,
        knowledge=noted_store,
    )
    empty = answer_question(
        QUESTION,
        user,
        settings=base,
        adapter=adapter,
        catalog=catalog,
        audit=empty_audit,
        llm=llm,
        knowledge=empty_store,
    )
    noted_system = llm.seen[0][0]["content"]
    empty_system = llm.seen[1][0]["content"]
    return {
        "noted_block": notes_block(noted_system),
        "empty_block": notes_block(empty_system),
        "noted_sql": noted.sql or "",
        "empty_sql": empty.sql or "",
        "only_delta": strip_notes(noted_system) == empty_system and llm.seen[0][1] == llm.seen[1][1],
        "noted_snippets": list(noted.knowledge_snippets),
        "empty_snippets": list(empty.knowledge_snippets),
    }


def format_offline(result: dict) -> str:
    lines = [
        _WIRING,
        "notes block with the note:",
        result["noted_block"] or "(no notes block)",
        "notes block without the note:",
        result["empty_block"] or "(no notes block)",
        "sql with the note:",
        result["noted_sql"],
        "sql without the note:",
        result["empty_sql"],
        f"notes_are_only_delta: {result['only_delta']}",
        f"snippets_with_note: {len(result['noted_snippets'])}",
        f"snippets_without_note: {len(result['empty_snippets'])}",
    ]
    return "\n".join(lines)


def format_live(result: dict) -> str:
    differs = result["noted_sql"] != result["empty_sql"]
    lines = [
        "sql with the note:",
        result["noted_sql"],
        "sql without the note:",
        result["empty_sql"],
        f"sql_differs: {differs}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare one request with a knowledge note and one without."
    )
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(argv)
    if args.live:
        from dotenv import load_dotenv

        load_dotenv(PROJECT_ROOT / ".env", override=False)
        if not live_ready():
            print(
                "refusing: set OPENROUTER_API_KEY, or set OPENROUTER_BASE_URL to an "
                "OpenAI-compatible endpoint, before the live comparison.",
                file=sys.stderr,
            )
            return 2
        settings = load_settings()
        key = settings.openrouter_api_key
        if not key and settings.openrouter_base_url.rstrip("/") != _DEFAULT_BASE:
            key = "local"
        print(f"provider: {settings.openrouter_base_url}")
        print(f"model: {settings.openrouter_model}")
        print(f"question: {QUESTION}")
        sys.stdout.flush()
        llm = LlmClient(key, settings.openrouter_base_url, settings.openrouter_model)
        llm.seen = []
        original = llm.complete

        def complete(messages):
            llm.seen.append(messages)
            return original(messages)

        llm.complete = complete  # type: ignore[method-assign]
        with tempfile.TemporaryDirectory() as tmp:
            result = _passes(Path(tmp), llm)
        print(format_live(result))
        return 0

    llm = _Scripted(SCRIPTED_REPLY)
    with tempfile.TemporaryDirectory() as tmp:
        result = _passes(Path(tmp), llm)
    print(format_offline(result))
    return 0 if result["only_delta"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
