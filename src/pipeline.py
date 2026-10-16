"""Question → route → permission → SQL → guard → read-only execute → answer."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace

from src.audit import AuditEvent, AuditLog
from src.config import Settings, redact
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
from src.sql_guard import UnsafeSQLError, check_sql

_SUMMARY_ROW_THRESHOLD = 8
_MAX_QUESTION_CHARS = 2000


def _join(titles: list[str]) -> str:
    if not titles:
        return "the tables on your role"
    if len(titles) == 1:
        return titles[0]
    if len(titles) == 2:
        return f"{titles[0]} and {titles[1]}"
    return ", ".join(titles[:-1]) + f", and {titles[-1]}"


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


def _schemas(adapter: object, tables: list[str], catalog: Catalog) -> list[TableSchema] | str:
    schemas: list[TableSchema] = []
    for table in tables:
        try:
            schema = adapter.get_schema(table)  # type: ignore[attr-defined]
        except NotImplementedError as exc:
            return str(exc)
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
) -> bool:
    try:
        audit.write(
            AuditEvent(
                username=user.username,
                role=user.role,
                question=question,
                routed_tables=tuple(tables),
                sql=sql,
                status=status,
                row_count=row_count,
                error=redact(error, settings.openrouter_api_key, settings.db_password) if error else None,
                metric_id=metric_id,
                definition_hash=definition_digest,
            )
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


def _answer_cache_key(metric: Metric, settings: Settings) -> str:
    return metric_cache_key(
        metric,
        model=settings.openrouter_model,
        prompt_version=PROMPT_VERSION,
    )


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
) -> Answer:
    text = (question or "").strip()
    if not text:
        return Answer(status="clarify", message="Ask a question about revenue or daily active users.")
    text = text[:_MAX_QUESTION_CHARS]
    allowed = set(user.allowed_tables)
    route = route_question(text, catalog)
    selected = None

    def finish(answer: Answer, error: str | None = None) -> Answer:
        metric_id = answer.metric_id
        digest = None
        if selected is not None:
            metric_id = selected.id
            digest = definition_hash(selected)
            if answer.metric_id is None:
                answer.metric_id = selected.id
            if answer.sql:
                answer.grain_warning = grain_warning(
                    answer.sql, selected, dialect=getattr(adapter, "dialect", "sqlite")
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
                    cache_key=_answer_cache_key(selected, settings),
                )
            except (sqlite3.Error, TypeError, ValueError):
                pass
        return answer

    if not route.matched:
        return finish(Answer(status="clarify", message=_clarify(catalog, allowed)))

    permitted = [table for table in route.tables if table in allowed]
    denied = [table for table in route.tables if table not in allowed]
    if not permitted:
        denied_titles = [topic.title for topic in route.topics if any(table in denied for table in topic.tables)]
        verb = "is" if len(denied_titles) == 1 else "are"
        message = (
            f"{_join(denied_titles)} {verb} outside the {user.role} role. "
            f"You can ask about {_join(_allowed_topics(catalog, allowed))}."
        )
        return finish(Answer(status="denied", message=message))
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
            cache_key=_answer_cache_key(selected, settings),
        )
    except sqlite3.Error:
        cached_payload = None
    cached = _load_answer(cached_payload) if cached_payload else None
    if cached is not None and cached.tables == [table] and cached.metric_id == selected.id:
        return finish(cached)

    schemas = _schemas(adapter, [table], catalog)
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
                        dialect=adapter.dialect,
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
            planned = plan_sql(text, table, {column.name for column in schemas[0].columns}, adapter.dialect)
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

    verdict = check_sql(sql, {table}, dialect=adapter.dialect)
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
        result = adapter.execute_select(sql, allowed_tables={table}, max_rows=settings.max_rows)
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
