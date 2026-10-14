"""Answer-cache identity must cover every input that can change the SQL."""

import json
import sqlite3
from dataclasses import fields, replace
from datetime import date

from src.audit import AuditLog
from src.config import ROOT
from src.metrics import Metric, definition_hash, load_metrics
from src.models import Answer
from src.pipeline import _dump_answer, answer_question
from tests.test_pipeline import _Scripted

QUESTION = "What was total revenue by product?"


def _reply(marker: str) -> str:
    sql = (
        "SELECT product, SUM(revenue_usd) AS revenue_usd "
        f"FROM revenue GROUP BY product /* {marker} */"
    )
    return json.dumps({"sql": sql, "assumptions": marker})


def _llm() -> _Scripted:
    return _Scripted([_reply("gen1"), _reply("gen2")])


def _copy_metrics(tmp_path):
    source = (ROOT / "config" / "metrics.yaml").read_text(encoding="utf-8")
    path = tmp_path / "metrics.yaml"
    path.write_text(source, encoding="utf-8")
    return path, source


def _revenue(path):
    return next(item for item in load_metrics(path) if item.id == "revenue_by_product")


def _ask(env, settings, llm, audit=None):
    return answer_question(
        QUESTION,
        env.analyst,
        settings=settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=audit or env.audit,
        llm=llm,
    )


def _audit_rows(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT sql, metric_id, definition_hash FROM audit_events ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return rows


def _prompt(messages) -> str:
    return "\n".join(message["content"] for message in messages)


def _distinct(value):
    """A different value of the same shape, for whatever field the dataclass grows."""
    if isinstance(value, tuple):
        return (*value, "cache-key-other")
    if isinstance(value, str):
        return value + "\ncache-key-other"
    if isinstance(value, date):
        return date.fromordinal(value.toordinal() + 1)
    if value is None:
        return "cache-key-other"
    if isinstance(value, bool):
        return not value
    if isinstance(value, int) and not isinstance(value, bool):
        return value + 1
    if isinstance(value, float):
        return value + 1.0
    if isinstance(value, list):
        return [*value, "cache-key-other"]
    if isinstance(value, dict):
        return {**value, "cache-key-other": True}
    return ("cache-key-other", value)


def test_editing_only_the_owner_misses_the_answer_cache(env, tmp_path):
    path, source = _copy_metrics(tmp_path)
    settings = replace(env.settings, metrics_path=path)
    llm = _llm()
    first = _ask(env, settings, llm)
    assert first.status == "ok"
    assert first.sql is not None and "gen1" in first.sql
    before = definition_hash(_revenue(path))

    updated = source.replace("owner: finance-reporting", "owner: revenue-controller", 1)
    assert updated != source
    path.write_text(updated, encoding="utf-8")
    edited = _revenue(path)
    assert edited.owner == "revenue-controller"
    assert definition_hash(edited) == before

    second = _ask(env, settings, llm)
    assert len(llm.seen) == 2, "editing owner must not reuse SQL generated for the previous owner"
    assert second.status == "ok"
    assert second.sql is not None and "gen2" in second.sql
    assert "gen1" not in second.sql
    assert "Owner: revenue-controller" in _prompt(llm.seen[1])
    assert "Owner: finance-reporting" in _prompt(llm.seen[0])

    rows = _audit_rows(env.audit.path)
    assert len(rows) == 2
    assert rows[0]["metric_id"] == rows[1]["metric_id"] == "revenue_by_product"
    assert rows[0]["definition_hash"] == rows[1]["definition_hash"] == before
    assert rows[0]["sql"] is not None and "gen1" in rows[0]["sql"]
    assert rows[1]["sql"] is not None and "gen2" in rows[1]["sql"]


def test_editing_only_effective_from_misses_the_answer_cache(env, tmp_path):
    path, source = _copy_metrics(tmp_path)
    settings = replace(env.settings, metrics_path=path)
    llm = _llm()
    first = _ask(env, settings, llm)
    assert first.status == "ok"
    assert first.sql is not None and "gen1" in first.sql
    before = definition_hash(_revenue(path))

    updated = source.replace("effective_from: 2026-06-15", "effective_from: 2026-01-01", 1)
    assert updated != source
    path.write_text(updated, encoding="utf-8")
    edited = _revenue(path)
    assert edited.effective_from == date(2026, 1, 1)
    assert definition_hash(edited) == before

    second = _ask(env, settings, llm)
    assert len(llm.seen) == 2, "editing effective_from must not reuse SQL from the previous date"
    assert second.status == "ok"
    assert second.sql is not None and "gen2" in second.sql
    assert "gen1" not in second.sql
    assert "Effective from: 2026-01-01" in _prompt(llm.seen[1])
    assert "Effective from: 2026-06-15" in _prompt(llm.seen[0])

    rows = _audit_rows(env.audit.path)
    assert len(rows) == 2
    assert rows[0]["definition_hash"] == rows[1]["definition_hash"] == before
    assert rows[0]["sql"] is not None and "gen1" in rows[0]["sql"]
    assert rows[1]["sql"] is not None and "gen2" in rows[1]["sql"]


def test_changing_the_model_id_misses_the_answer_cache(env):
    llm = _llm()
    assert llm.model == "stub"
    first_settings = replace(env.settings, openrouter_model="openai/gpt-4o-mini")
    first = _ask(env, first_settings, llm)
    assert first.status == "ok"
    assert first.sql is not None and "gen1" in first.sql
    digest = definition_hash(_revenue(env.settings.metrics_path))

    second_settings = replace(env.settings, openrouter_model="anthropic/claude-3.5-sonnet")
    second = _ask(env, second_settings, llm)
    assert len(llm.seen) == 2, "switching openrouter_model must not reuse SQL from the previous model"
    assert second.status == "ok"
    assert second.sql is not None and "gen2" in second.sql
    assert "gen1" not in second.sql
    assert llm.model == "stub"

    rows = _audit_rows(env.audit.path)
    assert len(rows) == 2
    assert rows[0]["definition_hash"] == rows[1]["definition_hash"] == digest
    assert rows[0]["sql"] is not None and "gen1" in rows[0]["sql"]
    assert rows[1]["sql"] is not None and "gen2" in rows[1]["sql"]


def test_editing_only_the_definition_misses_the_answer_cache(env, tmp_path):
    path, source = _copy_metrics(tmp_path)
    settings = replace(env.settings, metrics_path=path)
    llm = _llm()
    first = _ask(env, settings, llm)
    assert first.status == "ok"
    assert first.sql is not None and "gen1" in first.sql
    before = definition_hash(_revenue(path))

    confirmed = "Recognised revenue in USD after the business confirmation."
    updated = source.replace(
        "Recognised revenue in USD, net of cancellations. Channel splits sum to the total.",
        confirmed,
        1,
    )
    assert updated != source
    path.write_text(updated, encoding="utf-8")
    edited = _revenue(path)
    after = definition_hash(edited)
    assert edited.definition == confirmed
    assert after != before

    second = _ask(env, settings, llm)
    assert len(llm.seen) == 2
    assert second.status == "ok"
    assert second.sql is not None and "gen2" in second.sql
    assert "gen1" not in second.sql

    rows = _audit_rows(env.audit.path)
    assert len(rows) == 2
    assert rows[0]["definition_hash"] == before
    assert rows[1]["definition_hash"] == after
    assert rows[0]["sql"] is not None and "gen1" in rows[0]["sql"]
    assert rows[1]["sql"] is not None and "gen2" in rows[1]["sql"]
    assert rows[1]["metric_id"] == "revenue_by_product"


def test_a_legacy_question_role_cache_is_dropped_and_not_served(env, tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE answer_cache (
            question TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload TEXT NOT NULL,
            PRIMARY KEY (question, role)
        )
        """
    )
    stale = _dump_answer(
        Answer(
            status="ok",
            message="stale",
            sql="SELECT product FROM revenue /* stale */",
            columns=["product"],
            rows=[{"product": "Atlas"}],
            tables=["revenue"],
            source="openrouter",
            metric_id="revenue_by_product",
        )
    )
    conn.execute(
        "INSERT INTO answer_cache (question, role, created_at, payload) VALUES (?, ?, ?, ?)",
        (QUESTION, env.analyst.role, "2099-01-01T00:00:00Z", stale),
    )
    conn.commit()
    conn.close()

    audit = AuditLog(path)
    llm = _llm()
    answer = _ask(env, env.settings, llm, audit=audit)
    assert answer.status == "ok"
    assert answer.sql is not None and "gen1" in answer.sql
    assert "stale" not in answer.sql
    assert len(llm.seen) == 1

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    columns = list(conn.execute("PRAGMA table_info(answer_cache)"))
    payloads = [row["payload"] for row in conn.execute("SELECT payload FROM answer_cache")]
    conn.close()
    names = [column["name"] for column in columns]
    primary_key = [
        column["name"] for column in sorted(columns, key=lambda column: column["pk"]) if column["pk"]
    ]
    assert primary_key != ["question", "role"]
    assert all("stale" not in payload for payload in payloads)
    assert "cache_key" in names


def test_cache_key_changes_when_any_prompt_input_changes():
    from src.metrics import metric_cache_key

    metric = Metric(
        id="revenue_by_product",
        title="Revenue by product",
        synonyms=("revenue", "sales"),
        table="revenue",
        grain=("event_date", "product"),
        additive_over=("event_date", "product"),
        definition="Recognised revenue in USD.",
        owner="finance-reporting",
        effective_from=date(2026, 6, 15),
        supersedes=None,
        exceptions="Excludes internal test accounts.",
    )
    model = "openai/gpt-4o-mini"
    prompt_version = "1"
    base = metric_cache_key(metric, model=model, prompt_version=prompt_version)
    assert base == metric_cache_key(metric, model=model, prompt_version=prompt_version)
    assert len(base) == 12
    assert base == bytes.fromhex(base).hex()

    known = {
        "id",
        "title",
        "synonyms",
        "table",
        "grain",
        "additive_over",
        "definition",
        "owner",
        "effective_from",
        "supersedes",
        "exceptions",
    }
    declared = [field.name for field in fields(Metric)]
    assert known <= set(declared)

    seen = {base}
    for name in declared:
        mutated = replace(metric, **{name: _distinct(getattr(metric, name))})
        key = metric_cache_key(mutated, model=model, prompt_version=prompt_version)
        assert key != base, name
        assert key not in seen, name
        assert len(key) == 12
        seen.add(key)

    model_key = metric_cache_key(metric, model="anthropic/claude-3.5-sonnet", prompt_version=prompt_version)
    assert model_key != base, "model id must be part of the cache key"
    assert model_key not in seen

    version_key = metric_cache_key(metric, model=model, prompt_version="2")
    assert version_key != base, "prompt version must be part of the cache key"
    assert version_key != model_key


def test_changing_the_prompt_version_misses_the_answer_cache(env, monkeypatch):
    import src.pipeline as pipeline
    import src.prompt as prompt

    llm = _llm()
    first = _ask(env, env.settings, llm)
    assert first.status == "ok"
    assert first.sql is not None and "gen1" in first.sql
    assert len(llm.seen) == 1

    monkeypatch.setattr(prompt, "PROMPT_VERSION", "prompt-version-other", raising=False)
    monkeypatch.setattr(pipeline, "PROMPT_VERSION", "prompt-version-other", raising=False)
    second = _ask(env, env.settings, llm)
    assert len(llm.seen) == 2, "a new prompt template version must not reuse cached SQL"
    assert second.status == "ok"
    assert second.sql is not None and "gen2" in second.sql
    assert "gen1" not in second.sql


def test_the_same_inputs_hit_the_cache_with_no_new_model_call(env):
    llm = _llm()
    first = _ask(env, env.settings, llm)
    assert first.status == "ok"
    assert first.source == "openrouter"
    assert first.sql is not None and "gen1" in first.sql
    calls_after_first = env.audit.llm_calls_today()
    assert calls_after_first == 1
    assert len(llm.seen) == 1

    second = _ask(env, env.settings, llm)
    assert second.status == "ok"
    assert second.sql == first.sql
    assert "gen1" in second.sql
    assert len(llm.seen) == 1
    assert env.audit.llm_calls_today() == calls_after_first
