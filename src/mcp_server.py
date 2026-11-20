"""MCP server v0: installation, discovery, plain results, and an audit row.

This is plumbing, not an answer surface. It lists three tools, returns plain
data, and appends exactly one audit row per call. There is no question planner
in this module and no query execution: ``check_sql`` hands the string to
``src.sql_guard.check_sql`` and returns the verdict.

The role is fixed by the process, never by a tool argument. ``MCP_USER`` names
an account in ``config/users.yaml`` and its grants are read with
``src.auth.user_named``, the same loader the app uses, so a client cannot widen
a role by sending one. A server that cannot read a permitted identity refuses
to start: a gate that denies nothing is not a gate.

The audit row is the evidence, not the "connected" badge. One row per call,
written before the result is returned; if the row cannot be written, the call
reports an error and no data.

One identity per process is the v0 model, and it is why the tools close over a
context rather than take parameters. They are module-level functions with no
arguments so tests can call them without a transport.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

import sqlglot
from mcp.server.mcpserver import MCPServer
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

from src import sql_guard
from src.audit import AuditLog
from src.auth import user_named
from src.capabilities import QUERY
from src.config import ConfigError, Settings, load_settings
from src.connections import apply_enabled_connection, probe_sqlite
from src.db.factory import build_adapter
from src.db.sqlite import SqliteAdapter
from src.metrics import is_placeholder, load_metrics
from src.models import User
from src.sources import load_sources, sources_for_user

SERVER_NAME = "day1"
SERVER_VERSION = "0.1.0"

# Which account this process acts as. Defaults to the demo analyst.
MCP_USER_ENV = "MCP_USER"
DEFAULT_MCP_USER = "analyst"

# The audit capability for this front end. ``query`` would claim a read that
# did not happen, and nothing validates the column.
MCP_CAPABILITY = "mcp"
MCP_EVENT_TYPE = "mcp_tool_call"

# A success whose audit line is missing is the exact failure the product exists
# to prevent, so it is reported as an error with no data.
UNRECORDED = {
    "status": "error",
    "message": "the call was not recorded, so it is not reported as done",
}

# Long enough to name the statement, short enough to keep the audit row small.
PARAM_SUMMARY_CHARS = 120


@dataclass(frozen=True)
class ServerContext:
    """The identity and storage this process serves, resolved once at startup."""

    settings: Settings
    user: User
    audit: AuditLog


_CONTEXT: ServerContext | None = None


def _context() -> ServerContext:
    if _CONTEXT is None:
        raise RuntimeError("build_server() has not been called")
    return _CONTEXT


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _question(tool: str, summary: str = "") -> str:
    """The audit question column: the tool, then a short parameter summary."""
    text = f"mcp: {tool} {summary}".strip()
    return text[:200]


# ---------------------------------------------------------------------------
# Warehouse and catalogue probes. Read-only, and no business query anywhere.
# ---------------------------------------------------------------------------


def _warehouse(settings: Settings):
    """The configured warehouse, opened without seeding.

    ``build_adapter`` seeds the demo file, and a discovery tool must not write
    to the warehouse it is describing. The UI-selected connection still wins,
    the same way it does for a question.
    """
    effective = apply_enabled_connection(settings)
    if effective.db_backend == "sqlite":
        return SqliteAdapter(
            effective.db_path,
            seed=False,
            statement_timeout_ms=effective.sql_timeout_ms,
        )
    return build_adapter(effective)


def _database_block(settings: Settings) -> dict:
    """``probe_sqlite`` opens the file read-only and runs ``SELECT 1``.

    That one statement is the whole probe; no table is read.
    """
    effective = apply_enabled_connection(settings)
    if effective.db_backend != "sqlite":
        return {
            "backend": effective.db_backend,
            "reachable": False,
            "note": "v0 probes only the sqlite adapter",
        }
    try:
        probe_sqlite(Path(effective.db_path))
    except Exception:
        return {"backend": "sqlite", "reachable": False}
    return {"backend": "sqlite", "reachable": True}


def _catalogue_block(settings: Settings) -> dict:
    """Catalogue counts from the shipped file, placeholder-aware.

    PR #33's ``effective_catalogue`` and its signature ledger are not in this
    base, so this reads ``load_metrics`` and classifies with ``is_placeholder``.
    Both counts mean "not signed off by a business owner", which is the fact a
    v0 health line needs.
    """
    try:
        metrics = load_metrics(settings.metrics_path)
    except ConfigError:
        return {"total": 0, "signed": 0, "draft": 0}
    draft = sum(1 for metric in metrics if is_placeholder(metric))
    return {"total": len(metrics), "signed": len(metrics) - draft, "draft": draft}


def _audit_writable(path: Path) -> bool:
    """Write one probe row and roll it back. A path string is not a check."""
    try:
        conn = sqlite3.connect(path, timeout=2)
    except sqlite3.Error:
        return False
    try:
        conn.execute("BEGIN")
        conn.execute(
            """
            INSERT INTO audit_events (ts, username, role, question, routed_tables, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (_stamp(), "-", "-", "audit writability probe", "", "probe"),
        )
        conn.rollback()
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def _audit_summary(path: Path) -> dict:
    """Today's MCP counts and the newest MCP row, read after this call's row."""
    start = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
    conn = sqlite3.connect(path, timeout=5)
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS calls,
                   SUM(CASE WHEN status = 'denied' THEN 1 ELSE 0 END) AS denied,
                   MAX(ts) AS last_at
            FROM audit_events
            WHERE event_type = ? AND ts >= ?
            """,
            (MCP_EVENT_TYPE, start),
        ).fetchone()
    finally:
        conn.close()
    return {
        "last_event_at": row[2],
        "calls_today": int(row[0] or 0),
        "denied_today": int(row[1] or 0),
    }


def _declared_sources(ctx: ServerContext) -> list[dict]:
    """Declarations this identity may see, without column lists."""
    directory = Path(ctx.settings.sources_dir)
    if not directory.is_dir():
        return []
    specs = load_sources(
        directory,
        routing_path=ctx.settings.routing_path,
        warehouse_path=ctx.settings.db_path,
    )
    visible = sources_for_user(specs, ctx.user)
    ordered = sorted(visible.values(), key=lambda spec: spec.table)
    return [{"table": spec.table, "description": spec.description} for spec in ordered]


def _resolved_tables(sql: str) -> list[str]:
    """The physical tables in a statement the guard already accepted.

    ``src.sql_guard.check_sql`` returns a verdict and no table list, and this
    module must not re-decide the verdict. This only reports what was accepted.
    """
    try:
        expr = sqlglot.parse_one(sql, read="sqlite")
        scopes = list(traverse_scope(expr))
    except Exception:
        return []
    names: set[str] = set()
    for scope in scopes:
        for source in scope.sources.values():
            if isinstance(source, exp.Table):
                names.add(source.name.lower())
    return sorted(names)


# ---------------------------------------------------------------------------
# Audit-first wrappers. The row is written before the result is returned.
# ---------------------------------------------------------------------------


def _finish(
    ctx: ServerContext,
    tool: str,
    summary: str,
    *,
    status: str,
    error: str | None,
    payload: dict,
    tables: tuple[str, ...] = (),
) -> dict:
    try:
        ctx.audit.record_event(
            username=ctx.user.username,
            role=ctx.user.role,
            status=status,
            event_type=MCP_EVENT_TYPE,
            capability=MCP_CAPABILITY,
            question=_question(tool, summary),
            tables=tables,
            error=error,
        )
    except Exception:
        return dict(UNRECORDED)
    return payload


def _audited(tool: str, summary: str, action: Callable[[], dict]) -> dict:
    ctx = _context()
    try:
        payload = action()
    except Exception as exc:
        reason = str(exc) or type(exc).__name__
        return _finish(
            ctx,
            tool,
            summary,
            status="error",
            error=reason,
            payload={"status": "error", "message": reason},
        )
    # A guard refusal is recorded as denied, and the payload still says why.
    denied = payload.get("allowed") is False
    # Only check_sql reports table names; a table listing reports dicts and the
    # audit column takes names.
    names = tuple(name for name in (payload.get("tables") or ()) if isinstance(name, str))
    return _finish(
        ctx,
        tool,
        summary,
        status="denied" if denied else "ok",
        error=payload.get("reason") if denied else None,
        payload=payload,
        tables=names,
    )


# ---------------------------------------------------------------------------
# The three tools. No arguments: identity is the process, not the caller.
# ---------------------------------------------------------------------------


def health() -> dict:
    """Report the server, the resolved identity, the audit log, and no answers."""
    ctx = _context()
    payload = {
        "status": "ok",
        "server": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "identity": {
            "username": ctx.user.username,
            "role": ctx.user.role,
            "tables": len(ctx.user.allowed_tables),
        },
        "audit": {},
        "catalogue": _catalogue_block(ctx.settings),
        "database": _database_block(ctx.settings),
    }
    writable = _audit_writable(Path(ctx.settings.audit_path))
    try:
        ctx.audit.record_event(
            username=ctx.user.username,
            role=ctx.user.role,
            status="ok",
            event_type=MCP_EVENT_TYPE,
            capability=MCP_CAPABILITY,
            question=_question("health"),
        )
    except Exception:
        return dict(UNRECORDED)
    try:
        summary = _audit_summary(Path(ctx.settings.audit_path))
    except Exception:
        return {
            "status": "error",
            "message": "the call was recorded, but its audit summary could not be read",
        }
    payload["audit"] = {
        "path": str(ctx.settings.audit_path),
        "last_event_at": summary["last_event_at"],
        "calls_today": summary["calls_today"],
        "denied_today": summary["denied_today"],
        "writable": writable,
    }
    return payload


def list_allowed_tables() -> dict:
    """The warehouse tables this identity may read, plus its declared sources."""
    ctx = _context()

    def action() -> dict:
        adapter = _warehouse(ctx.settings)
        tables = [
            {"table": name, "kind": "warehouse"}
            for name in ctx.user.allowed_tables
            if adapter.get_schema(name) is not None
        ]
        payload: dict = {
            "role": ctx.user.role,
            "tables": tables,
            "declared": _declared_sources(ctx),
        }
        # An empty list is a real answer; say why rather than leaving it bare.
        if not tables:
            payload["note"] = "this identity has no readable tables"
        return payload

    return _audited("list_allowed_tables", "", action)


def check_sql(sql: str) -> dict:
    """Validate one statement through the guard. Never execute it."""
    ctx = _context()

    def action() -> dict:
        verdict = sql_guard.check_sql(sql, set(ctx.user.allowed_tables))
        payload = {
            "allowed": verdict.ok,
            "reason": verdict.reason,
            "tables": _resolved_tables(sql) if verdict.ok else [],
        }
        if verdict.ok:
            payload["note"] = "v0 does not execute queries"
        return payload

    summary = " ".join((sql or "").split())[:PARAM_SUMMARY_CHARS]
    return _audited("check_sql", summary, action)


# ---------------------------------------------------------------------------
# Wiring.
# ---------------------------------------------------------------------------


def build_server(settings: Settings, user: User) -> MCPServer:
    """Register the three tools against one resolved identity."""
    global _CONTEXT
    _CONTEXT = ServerContext(settings=settings, user=user, audit=AuditLog(settings.audit_path))
    server = MCPServer(
        name=SERVER_NAME,
        version=SERVER_VERSION,
        instructions=(
            "Day 1 plumbing probe. Three tools, one audit row per call. "
            "No tool answers a business question or runs SQL."
        ),
    )
    server.add_tool(
        health,
        description=(
            "Report server identity, catalogue counts, warehouse reachability and the "
            "local audit log. Does not answer questions."
        ),
    )
    server.add_tool(
        list_allowed_tables,
        description=(
            "List the warehouse tables this identity may read and the declared sources "
            "it may see. No column lists."
        ),
    )
    server.add_tool(
        check_sql,
        description=(
            "Validate one SQL statement against the SELECT allowlist and this identity's "
            "tables. Returns the verdict only; v0 does not execute queries."
        ),
    )
    return server


def _refuse(message: str) -> NoReturn:
    print(f"day1 mcp: {message}", file=sys.stderr)
    raise SystemExit(2)


def main() -> None:
    username = (os.environ.get(MCP_USER_ENV, DEFAULT_MCP_USER) or "").strip()
    username = username or DEFAULT_MCP_USER
    try:
        settings = load_settings()
        user = user_named(username, Path(settings.users_path))
    except ConfigError as exc:
        _refuse(f"configuration is unusable: {exc}")
    if user is None:
        _refuse(
            f"unknown {MCP_USER_ENV} user {username!r}; "
            f"add it to {settings.users_path} or set {MCP_USER_ENV} to an account there"
        )
    if QUERY not in user.capabilities:
        _refuse(
            f"{MCP_USER_ENV} user {username!r} has role {user.role!r}, "
            "which does not grant the query capability"
        )
    build_server(settings, user).run("stdio")


if __name__ == "__main__":
    main()
