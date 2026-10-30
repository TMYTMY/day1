"""Notes change the request, and only the request, under the existing rules."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace

from src.audit import AuditLog
from src.knowledge.store import KnowledgeStore
from src.pipeline import answer_question

NOTE = (
    "Booked revenue means the revenue_usd column. "
    "Northstar is the flagship product in the revenue table. "
    "FINANCE_NOTE_CANARY"
)
GROWTH_NOTE = (
    "Booked revenue means the revenue_usd column. "
    "Northstar is the flagship product in the revenue table. "
    "GROWTH_ONLY_CANARY"
)
QUESTION = "What was total revenue by product over the last 90 days?"
SCRIPTED_SQL = (
    '{"sql": "SELECT product, SUM(revenue_usd) AS revenue_usd '
    'FROM revenue GROUP BY product", "assumptions": "Grouped by product."}'
)
_NOTES = "\n\nSupplemental notes from the knowledge base."
_METRIC = "\n\nAuthoritative metric definition"


class _Off:
    configured = False

    def complete(self, messages):
        raise AssertionError("local mode must not call the language model")


class _Scripted:
    def __init__(self, reply: str):
        self.reply = reply
        self.configured = True
        self.seen: list = []

    def complete(self, messages):
        self.seen.append(messages)
        return self.reply


def _ask(env, user, question, llm=None, knowledge=None, audit=None):
    return answer_question(
        question,
        user,
        settings=env.settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=audit or env.audit,
        llm=llm or _Off(),
        knowledge=knowledge,
    )


def _strip_notes(system: str) -> str:
    if _NOTES not in system:
        return system
    start = system.index(_NOTES)
    end = system.index(_METRIC, start)
    return system[:start] + system[end:]


def _cached_snippets(audit: AuditLog) -> list[str]:
    conn = sqlite3.connect(audit.path)
    try:
        rows = conn.execute("SELECT payload FROM answer_cache").fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    return list(json.loads(rows[0][0])["knowledge_snippets"])


def test_the_note_is_the_only_delta_in_the_request(env, tmp_path):
    noted_store = KnowledgeStore(env.settings)
    noted_store.add_document(
        "glossary.md",
        NOTE.encode(),
        owner="finance",
        owner_role="finance",
        approval="approved",
    )
    empty_store = KnowledgeStore(replace(env.settings, knowledge_path=tmp_path / "empty"))
    llm = _Scripted(SCRIPTED_SQL)
    noted_audit = AuditLog(tmp_path / "noted-audit.db")
    empty_audit = AuditLog(tmp_path / "empty-audit.db")

    noted = _ask(
        env,
        env.finance,
        QUESTION,
        llm=llm,
        knowledge=noted_store,
        audit=noted_audit,
    )
    empty = _ask(
        env,
        env.finance,
        QUESTION,
        llm=llm,
        knowledge=empty_store,
        audit=empty_audit,
    )

    assert noted.status == "ok"
    assert empty.status == "ok"
    noted_messages = llm.seen[0]
    empty_messages = llm.seen[1]
    noted_system = noted_messages[0]["content"]
    empty_system = empty_messages[0]["content"]
    notes_start = noted_system.index(_NOTES)
    notes_end = noted_system.index(_METRIC, notes_start)
    notes_block = noted_system[notes_start:notes_end]
    assert "FINANCE_NOTE_CANARY" in notes_block
    assert "<<<NOTE" in notes_block and ">>>" in notes_block
    assert "FINANCE_NOTE_CANARY" not in empty_system
    assert _strip_notes(noted_system) == empty_system
    assert noted_messages[1] == empty_messages[1]

    assert noted.audit_saved is True
    assert empty.audit_saved is True
    assert noted_audit.recent("finance")[0]["status"] == "ok"
    assert empty_audit.recent("finance")[0]["status"] == "ok"
    assert noted.knowledge_snippets
    assert empty.knowledge_snippets == []
    assert _cached_snippets(noted_audit) == noted.knowledge_snippets
    assert _cached_snippets(empty_audit) == []
    assert _cached_snippets(noted_audit) != _cached_snippets(empty_audit)


def test_a_note_owned_by_another_role_stays_out_of_the_prompt(env):
    store = KnowledgeStore(env.settings)
    store.add_document(
        "growth-only.md",
        GROWTH_NOTE.encode(),
        owner="growth",
        owner_role="growth",
        approval="approved",
    )
    llm = _Scripted(SCRIPTED_SQL)
    answer = _ask(env, env.finance, QUESTION, llm=llm, knowledge=store)
    assert answer.status == "ok"
    system = llm.seen[0][0]["content"]
    assert "GROWTH_ONLY_CANARY" not in system
    assert "growth-only.md" not in system
    assert answer.knowledge_snippets == []
    assert _NOTES not in system


def test_no_model_does_not_fetch_notes(env):
    store = KnowledgeStore(env.settings)
    store.add_document("glossary.md", NOTE.encode(), owner="analyst", owner_role="analyst")
    calls = {"notes": 0}
    original = store.prompt_notes

    def wrapped(query, *, role, limit=4):
        calls["notes"] += 1
        return original(query, role=role, limit=limit)

    store.prompt_notes = wrapped  # type: ignore[method-assign]
    answer = _ask(env, env.analyst, "What was total revenue by product?", knowledge=store)
    assert answer.status == "ok"
    assert answer.source == "local"
    assert answer.knowledge_snippets == []
    assert calls["notes"] == 0
    assert answer.audit_saved is True


def test_offline_script_labels_the_wiring_limit(capsys):
    from scripts.eval_ablation import _WIRING, main

    assert main([]) == 0
    out = capsys.readouterr().out
    assert _WIRING in out
    assert "FINANCE_NOTE_CANARY" in out
    assert "notes_are_only_delta: True" in out
    assert "(no notes block)" in out


def test_live_comparison_refuses_without_a_key_or_custom_endpoint(monkeypatch, capsys):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_BASE_URL", raising=False)

    def refuse(*args, **kwargs):
        raise AssertionError("the live comparison must not call the network")

    monkeypatch.setattr("src.llm.requests.post", refuse)
    monkeypatch.setattr("requests.post", refuse)
    from scripts.eval_ablation import main

    assert main(["--live"]) == 2
    assert "refusing" in capsys.readouterr().err
