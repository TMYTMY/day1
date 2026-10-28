"""Question → route → permission → SQL → guard → read-only execute → answer."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

from src.audit import AuditLog
from src.capabilities import QUERY as CAPABILITY_QUERY
from src.capabilities import authorize, join_names
from src.config import Settings, redact
from src.db.resolve import resolve_table
from src.db.sqlite import QueryExecutionError
from src.grain import grain_warning
from src.knowledge.store import KnowledgeStore
from src.llm import LlmClient, LlmError, parse_model_output
from src.local_sql import PlannerError, plan_sql
from src.metrics import Metric, active_metrics, definition_hash, load_metrics, match_metrics, metric_cache_key
from src.models import Answer, TableSchema, User
from src.present import local_summary
from src.prompt import PROMPT_VERSION, build_messages, build_summary_messages
from src.routing import Catalog, route_question
from src.sources import (
    DEFAULT_SOURCES_DB,
    SourceSpec,
    source_status,
    spec_for_table,
)
from src.sql_guard import UnsafeSQLError, check_sql

_SUMMARY_ROW_THRESHOLD = 8
_MAX_QUESTION_CHARS = 2000


def _join(titles: list[str]) -> str:
    if not titles:
        return "the tables on your role"
    return join_names(titles)


def _allowed_topics(catalog: Catalog, allowed: set[str]) -> list[str]:
    titles = []
    for topic in catalog.topics:
        if any(table in allowed for table in topic.tables):
            titles.append(topic.title)
    return titles


def _examples(allowed: set[str]) -> str:
    examples = []
    if "revenue" in allowed:
        examples.append("revenue by product")
    if "dau" in allowed:
        examples.append("DAU by platform")
    return ", or ".join(examples)


def _clarify(catalog: Catalog, allowed: set[str]) -> str:
    titles = _allowed_topics(catalog, allowed)
    if not titles:
        return "Your role does not include any warehouse tables."
    examples = _examples(allowed)
    extra = f" For example: {examples}." if examples else ""
    return f"I can answer questions about {_join(titles)}.{extra}"


def _source_shadows_warehouse(catalog: Catalog, adapter: object, spec: SourceSpec) -> bool:
    """True when this declaration would hide a table the warehouse already owns."""
    for topic in catalog.topics:
        if spec.table in topic.tables and topic.id != spec.source_id:
            return True
    get_schema = getattr(adapter, "get_schema", None)
    if not callable(get_schema):
        return False
    try:
        schema = get_schema(spec.table)
    except (sqlite3.Error, OSError, NotImplementedError):
        return False
    return schema is not None


def _routed_source_id(
    tables: tuple[str, ...] | list[str],
    sources: Mapping[str, SourceSpec] | None,
    catalog: Catalog,
    adapter: object,
) -> str | None:
    """Source id when the route names exactly one declared table. None otherwise."""
    if not sources:
        return None
    found: list[str] = []
    for table in tables:
        spec = spec_for_table(sources, table)
        if spec is None or _source_shadows_warehouse(catalog, adapter, spec):
            continue
        if spec.source_id not in found:
            found.append(spec.source_id)
    if len(found) == 1:
        return found[0]
    return None


def _source_gap(spec: SourceSpec, status: str) -> str:
    title = spec.description or spec.table
    if status == "declared_no_metric":
        return (
            f"{title} is declared, but no metric is bound to {spec.table}. "
            "I need a metric before I can answer."
        )
    return f"{spec.table} is not declared, so it cannot be queried."


def _schemas(adapter: object, tables: list[str], catalog: Catalog) -> list[TableSchema] | str:
    schemas: list[TableSchema] = []
    for table in tables:
        try:
            schema = adapter.get_schema(table)  # type: ignore[attr-defined]
        except NotImplementedError as exc:
            return str(exc)
        except sqlite3.Error:
            return f"The routing map points at `{table}`, but that table is not in the database."
        if schema is None:
            return f"The routing map points at `{table}`, but that table is not in the database."
        description = catalog.descriptions.get(table, "")
        schemas.append(replace(schema, description=description))
    return schemas


def _record(
    audit: AuditLog,
    user: User,
    question: str,
    tables: list[str],
    sql: str | None,
    status: str,
    row_count: int | None,
    error: str | None,
    settings: Settings,
    metric_id: str | None = None,
    definition_digest: str | None = None,
    source_id: str | None = None,
    event_type: str = "question",
    capability: str = CAPABILITY_QUERY,
) -> bool:
    """Redact the error and hand the row to the one shared audit writer.

    The row itself is built and inserted by ``AuditLog.record_event``, so a
    second capability writes the same shape of row without copying this code.
    A write failure costs the note, never the answer.
    """
    try:
        audit.record_event(
            username=user.username,
            role=user.role,
            status=status,
            event_type=event_type,
            capability=capability,
            question=question,
            tables=tables,
            sql=sql,
            row_count=row_count,
            error=redact(error, settings.openrouter_api_key, settings.db_password) if error else None,
            metric_id=metric_id,
            definition_hash=definition_digest,
            source_id=source_id,
        )
        return True
    except sqlite3.Error:
        return False


def _blocked_message(reason: str) -> str:
    if reason == "table_not_allowed":
        return "The query was blocked because it references a table outside your access."
    if reason == "no_table":
        return "The query was blocked because it does not read one of your allowed tables."
    if reason == "schema_qualifier":
        return "The query was blocked because it uses a database qualifier outside this warehouse."
    if reason in {"forbidden_statement", "not_select", "multi_statement", "forbidden_function"}:
        return "The query was blocked because only a single read-only SELECT is allowed."
    if reason == "parse_error":
        return "The query was blocked because it could not be parsed as read-only SQL."
    return "The query was blocked by the read-only SQL check."


def _answer_cache_key(
    metric: Metric,
    settings: Settings,
    spec: SourceSpec | None = None,
    *,
    data_window: str | None = None,
) -> str:
    return metric_cache_key(
        metric,
        model=settings.openrouter_model,
        prompt_version=PROMPT_VERSION,
        source_id=None if spec is None else spec.source_id,
        source_sha256=None if spec is None else spec.sha256,
        data_window=data_window,
    )


def _data_window(adapter: object, table: str | None) -> str | None:
    """Newest date the warehouse rows cover, so a re-seed misses the cache.

    The demo warehouse is rebuilt on a moving window (``SEED_END``), so the
    same question means different rows tomorrow. Returns ``None`` when the
    table has no ``event_date`` column, which leaves the key unchanged for
    adapters that are not the seeded demo warehouse.
    """
    if not table:
        return None
    sql = f'SELECT MAX(event_date) AS as_of FROM "{table}"'
    try:
        result = adapter.execute_select(sql, allowed_tables={table}, max_rows=1)
    except (
        UnsafeSQLError,
        QueryExecutionError,
        sqlite3.Error,
        OSError,
        AttributeError,
        TypeError,
    ):
        return None
    rows = getattr(result, "rows", None) or []
    if not rows:
        return None
    value = rows[0].get("as_of")
    return None if value is None else str(value)


def _dump_answer(answer: Answer) -> str:
    return json.dumps(
        {
            "status": answer.status,
            "message": answer.message,
            "sql": answer.sql,
            "columns": list(answer.columns),
            "rows": answer.rows,
            "tables": list(answer.tables),
            "assumptions": answer.assumptions,
            "source": answer.source,
            "truncated": answer.truncated,
            "summary": answer.summary,
            "knowledge_snippets": list(answer.knowledge_snippets),
            "metric_id": answer.metric_id,
            "grain_warning": answer.grain_warning,
            "audit_saved": answer.audit_saved,
        }
    )


def _load_answer(payload: str) -> Answer | None:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    status = data.get("status")
    message = data.get("message")
    if not isinstance(status, str) or not isinstance(message, str):
        return None
    return Answer(
        status=status,
        message=message,
        sql=data.get("sql"),
        columns=list(data.get("columns") or []),
        rows=list(data.get("rows") or []),
        tables=list(data.get("tables") or []),
        assumptions=data.get("assumptions"),
        source=data.get("source"),
        truncated=bool(data.get("truncated")),
        summary=data.get("summary"),
        knowledge_snippets=list(data.get("knowledge_snippets") or []),
        metric_id=data.get("metric_id") if isinstance(data.get("metric_id"), str) else None,
        grain_warning=data.get("grain_warning") if isinstance(data.get("grain_warning"), str) else None,
        audit_saved=data.get("audit_saved") if isinstance(data.get("audit_saved"), bool) else True,
    )


def _maybe_summary(
    llm: LlmClient,
    question: str,
    columns: list[str],
    rows: list[dict],
    assumptions: str | None,
    source: str,
    audit: AuditLog,
    settings: Settings,
) -> str:
    summary = local_summary(columns, rows)
    if source != "openrouter" or not llm.configured or len(rows) < _SUMMARY_ROW_THRESHOLD:
        return summary
    try:
        if audit.llm_calls_today() >= settings.max_llm_calls_per_day:
            return summary
        audit.record_llm_call()
    except sqlite3.Error:
        return summary
    try:
        text = llm.complete(build_summary_messages(question, columns, rows, assumptions)).strip()
    except LlmError:
        return summary
    if not text or len(text) > 800:
        return summary
    return text


def answer_question(
    question: str,
    user: User,
    *,
    settings: Settings,
    adapter: object,
    catalog: Catalog,
    audit: AuditLog,
    llm: LlmClient,
    knowledge: KnowledgeStore | None = None,
    sources: Mapping[str, SourceSpec] | None = None,
    sources_db: Path | None = None,
) -> Answer:
    text = (question or "").strip()
    if not text:
        return Answer(status="clarify", message="Ask a question about revenue or daily active users.")
    text = text[:_MAX_QUESTION_CHARS]
    allowed = set(user.allowed_tables)
    route = route_question(text, catalog)
    selected = None
    declared: SourceSpec | None = None
    active = adapter
    data_window: str | None = None
    routed_source_id = _routed_source_id(route.tables, sources, catalog, adapter)

    def finish(answer: Answer, error: str | None = None, event_type: str = "question") -> Answer:
        metric_id = answer.metric_id
        digest = None
        if selected is not None:
            metric_id = selected.id
            digest = definition_hash(selected)
            if answer.metric_id is None:
                answer.metric_id = selected.id
            if answer.sql:
                answer.grain_warning = grain_warning(
                    answer.sql, selected, dialect=getattr(active, "dialect", "sqlite")
                )
        saved = _record(
            audit,
            user,
            text,
            answer.tables,
            answer.sql,
            answer.status,
            len(answer.rows) if answer.status == "ok" else None,
            error,
            settings,
            metric_id=metric_id,
            definition_digest=digest,
            source_id=routed_source_id,
            event_type=event_type,
        )
        answer.audit_saved = saved
        if not saved:
            note = "The usage log could not be written."
            answer.message = f"{answer.message} {note}".strip()
        if (
            answer.status == "ok"
            and answer.source == "openrouter"
            and selected is not None
            and digest
        ):
            try:
                audit.remember_answer(
                    text,
                    user.role,
                    selected.id,
                    digest,
                    _dump_answer(answer),
                    cache_key=_answer_cache_key(
                        selected, settings, declared, data_window=data_window
                    ),
                )
            except (sqlite3.Error, TypeError, ValueError):
                pass
        return answer

    # One boundary, two questions. The capability grant is checked first, then
    # the tables the route selected. Both run before any SQL exists, and a
    # refusal returns the gate's message, which names the capability or the
    # tables and the role.
    grant = authorize(user, CAPABILITY_QUERY)
    if not grant.allowed:
        return finish(
            Answer(status="denied", message=grant.message or ""),
            error=grant.reason,
            event_type="capability_refusal",
        )

    if not route.matched:
        return finish(Answer(status="clarify", message=_clarify(catalog, allowed)))

    decision = authorize(user, CAPABILITY_QUERY, route.tables)
    denied = list(decision.tables)
    permitted = [table for table in route.tables if table not in denied]
    if not permitted:
        message = f"{decision.message or ''} You can ask about {_join(_allowed_topics(catalog, allowed))}."
        return finish(
            Answer(status="denied", message=message),
            error=decision.reason,
            event_type="capability_refusal",
        )
    if len(route.tables) > 1:
        titles = [topic.title for topic in route.topics]
        if denied:
            message = (
                f"{_join(titles)} cannot be answered together, and part of that question "
                f"is outside the {user.role} role. Ask about {_join(_allowed_topics(catalog, allowed))} on its own."
            )
        else:
            message = (
                f"That question matches {_join(titles)}. "
                "Ask about one table at a time so the result stays on a single grain."
            )
        return finish(Answer(status="clarify", message=message, tables=permitted))

    table = permitted[0]
    catalogue = load_metrics(settings.metrics_path)
    declared = spec_for_table(sources or {}, table)
    if declared is not None and _source_shadows_warehouse(catalog, adapter, declared):
        declared = None
    if declared is not None:
        availability = source_status(declared, catalogue)
        if availability != "answerable":
            return finish(
                Answer(status="clarify", message=_source_gap(declared, availability), tables=[table])
            )
        resolved = resolve_table(
            table,
            warehouse=adapter,
            sources=sources or {},
            sources_path=sources_db or DEFAULT_SOURCES_DB,
            statement_timeout_ms=settings.sql_timeout_ms,
        )
        active = resolved.adapter
    else:
        # The demo warehouse is re-seeded on a moving date window, so the newest
        # date the rows cover belongs in the cache key (a declared source is
        # already bound by source_id + sha256).
        data_window = _data_window(active, table)
    matched = [metric for metric in match_metrics(text, catalogue) if metric.table == table]
    if len(matched) != 1:
        role_titles = [metric.title for metric in active_metrics(catalogue) if metric.table in allowed]
        if not matched:
            if role_titles:
                message = (
                    f"I need a metric before I can answer. "
                    f"Your role can use {_join(role_titles)}. Name one of them."
                )
            else:
                message = "I need a metric before I can answer. Your role has no active metric."
        else:
            message = (
                f"That question matches {_join([metric.title for metric in matched])}. "
                "Pick one metric. I will not choose for you."
            )
        return finish(Answer(status="clarify", message=message, tables=[table]))
    selected = matched[0]
    definition_digest = definition_hash(selected)
    try:
        cached_payload = audit.cached_answer(
            text,
            user.role,
            selected.id,
            definition_digest,
            cache_key=_answer_cache_key(
                selected, settings, declared, data_window=data_window
            ),
        )
    except sqlite3.Error:
        cached_payload = None
    cached = _load_answer(cached_payload) if cached_payload else None
    if cached is not None and cached.tables == [table] and cached.metric_id == selected.id:
        return finish(cached)

    schemas = _schemas(active, [table], catalog)
    if isinstance(schemas, str):
        return finish(Answer(status="error", message=schemas, tables=[table]))

    source = "local"
    assumptions = ""
    sql = ""
    llm_error: str | None = None
    over_cap = False
    notes: list[str] = []
    if llm.configured:
        try:
            over_cap = audit.llm_calls_today() >= settings.max_llm_calls_per_day
        except sqlite3.Error:
            over_cap = False
        if not over_cap:
            if knowledge is not None:
                try:
                    notes = knowledge.prompt_notes(text, role=user.role)
                except Exception:
                    notes = []
            try:
                try:
                    audit.record_llm_call()
                except sqlite3.Error:
                    pass
                raw = llm.complete(
                    build_messages(
                        text,
                        schemas,
                        dialect=active.dialect,
                        knowledge_notes=notes or None,
                        metric=selected,
                    )
                )
                sql, assumptions = parse_model_output(raw)
                source = "openrouter"
                if notes:
                    assumptions = f"{assumptions} Knowledge base notes were added to the prompt.".strip()
            except LlmError as exc:
                llm_error = str(exc)
                sql = ""
                notes = []
    if not sql:
        if source == "openrouter" and llm_error is None:
            message = assumptions or _clarify(catalog, allowed)
            return finish(Answer(status="clarify", message=message, tables=[table], assumptions=assumptions or None))
        try:
            if declared is not None:
                raise PlannerError("LLM configuration is required to answer a declared source.")
            planned = plan_sql(text, table, {column.name for column in schemas[0].columns}, active.dialect)
        except PlannerError as exc:
            return finish(Answer(status="error", message=str(exc), tables=[table]), error=str(exc))
        sql = planned.sql
        assumptions = planned.assumptions
        source = "local"
        if llm_error:
            assumptions = (
                f"{assumptions} The language model request failed, so this SQL came from the local planner."
            )
        elif over_cap:
            assumptions = (
                f"{assumptions} The daily language-model call limit was reached, "
                "so this SQL came from the local planner."
            ).strip()

    verdict = check_sql(sql, {table}, dialect=active.dialect)
    if not verdict.ok:
        return finish(
            Answer(
                status="blocked",
                message=_blocked_message(verdict.reason),
                sql=sql,
                tables=[table],
                assumptions=assumptions or None,
                source=source,
            ),
            error=verdict.reason,
        )

    try:
        result = active.execute_select(sql, allowed_tables={table}, max_rows=settings.max_rows)
    except UnsafeSQLError as exc:
        return finish(
            Answer(
                status="blocked",
                message=_blocked_message(exc.reason),
                sql=sql,
                tables=[table],
                source=source,
            ),
            error=exc.reason,
        )
    except (QueryExecutionError, NotImplementedError) as exc:
        safe = redact(str(exc), settings.openrouter_api_key, settings.db_password)
        return finish(
            Answer(status="error", message=f"The query failed: {safe}", sql=sql, tables=[table], source=source),
            error=safe,
        )

    rows = [dict(row) for row in result.rows]
    columns = list(result.columns)
    summary = _maybe_summary(llm, text, columns, rows, assumptions, source, audit, settings)
    return finish(
        Answer(
            status="ok",
            message=summary,
            summary=summary,
            sql=sql,
            columns=columns,
            rows=rows,
            tables=[table],
            assumptions=assumptions or None,
            source=source,
            truncated=result.truncated,
            knowledge_snippets=notes if source == "openrouter" else [],
        ),
        error=llm_error,
    )
