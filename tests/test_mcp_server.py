"""Acceptance tests for the MCP server v0 (SPEC-day1-mcp-v0-cursor.md).

The nine tests below map one-to-one onto section 7 of the spec. Discovery is
exercised over a real stdio subprocess, not a mock; the rest call the same
tools in process so the audit rows can be read back directly.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import src.mcp_server as mcp_server
from src.audit import AuditLog
from src.auth import user_named
from src.config import ROOT, Settings
from src.db.seed import rebuild

USERS = ROOT / "config" / "users.yaml"
ROUTING = ROOT / "config" / "routing.yaml"
SERVER_SOURCE = ROOT / "src" / "mcp_server.py"

# Section 7.9: the base collected 600 tests and no change may lower that.
COLLECT_FLOOR = 600


def _settings(tmp_path: Path) -> Settings:
    db_path = tmp_path / "demo.db"
    if not db_path.is_file():
        rebuild(db_path)
    return Settings(
        db_backend="sqlite",
        db_path=db_path,
        database_url=None,
        db_user=None,
        db_password=None,
        athena_region=None,
        athena_database=None,
        athena_workgroup=None,
        athena_output=None,
        audit_path=tmp_path / "audit.db",
        routing_path=ROUTING,
        users_path=USERS,
        openrouter_api_key=None,
        openrouter_model="openai/gpt-4o-mini",
        openrouter_base_url="https://openrouter.ai/api/v1",
        max_rows=500,
        knowledge_path=tmp_path / "knowledge",
        embedding_provider="local",
        embedding_model="openai/text-embedding-3-small",
        embedding_api_key=None,
        settings_path=tmp_path / "instance.db",
        sources_dir=tmp_path / "sources",
    )


def _env(tmp_path: Path, user: str = "analyst") -> dict[str, str]:
    return {
        "MCP_USER": user,
        "DB_PATH": str(tmp_path / "demo.db"),
        "AUDIT_PATH": str(tmp_path / "audit.db"),
        "SETTINGS_PATH": str(tmp_path / "instance.db"),
        "SOURCES_DIR": str(tmp_path / "sources"),
    }


def _params(tmp_path: Path, user: str = "analyst") -> StdioServerParameters:
    if not (tmp_path / "demo.db").is_file():
        rebuild(tmp_path / "demo.db")
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "src.mcp_server"],
        cwd=str(ROOT),
        env=_env(tmp_path, user),
    )


def _payload(result) -> dict:
    """The JSON body a tool call returned, from its single text content block."""
    return json.loads(result.content[0].text)


def _call(server, name: str, arguments: dict | None = None) -> dict:
    return _payload(asyncio.run(server.call_tool(name, arguments or {})))


def _rows(path: Path) -> list[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM audit_events ORDER BY id")]
    finally:
        conn.close()


def _user(name: str):
    user = user_named(name, USERS)
    assert user is not None
    return user


def test_01_discovery_over_stdio_lists_exactly_the_three_tools(tmp_path):
    async def scenario() -> set[str]:
        async with stdio_client(_params(tmp_path)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listing = await session.list_tools()
                return {tool.name for tool in listing.tools}

    assert asyncio.run(scenario()) == {"health", "list_allowed_tables", "check_sql"}


def test_02_health_returns_a_structured_result_with_the_live_audit_row(tmp_path):
    settings = _settings(tmp_path)
    server = mcp_server.build_server(settings, _user("analyst"))

    payload = _call(server, "health")

    assert payload["status"] == "ok"
    assert payload["server"] == {"name": "day1", "version": "0.1.0"}
    assert payload["identity"] == {"username": "analyst", "role": "analyst", "tables": 2}
    assert {"path", "last_event_at", "calls_today", "denied_today", "writable"} <= set(
        payload["audit"]
    )
    assert payload["audit"]["path"] == str(settings.audit_path)
    # The row for this very call: written before the result, so never null.
    assert payload["audit"]["last_event_at"] is not None
    assert payload["audit"]["calls_today"] == 1
    assert payload["audit"]["writable"] is True
    assert payload["catalogue"] == {"total": 4, "signed": 1, "draft": 3}
    assert payload["database"]["reachable"] is True


def test_03_three_calls_write_exactly_three_audit_rows(tmp_path):
    settings = _settings(tmp_path)
    server = mcp_server.build_server(settings, _user("analyst"))

    assert _call(server, "health")["status"] == "ok"
    assert _call(server, "list_allowed_tables")["role"] == "analyst"
    assert _call(server, "check_sql", {"sql": "SELECT product FROM revenue"})["allowed"] is True

    rows = _rows(settings.audit_path)
    assert len(rows) == 3
    assert {row["event_type"] for row in rows} == {"mcp_tool_call"}
    assert {row["capability"] for row in rows} == {"mcp"}
    assert all(row["username"] == "analyst" and row["role"] == "analyst" for row in rows)

    questions = [row["question"] for row in rows]
    assert questions[0] == "mcp: health"
    assert questions[1] == "mcp: list_allowed_tables"
    assert questions[2].startswith("mcp: check_sql") and "revenue" in questions[2]


def test_04_a_denied_statement_is_refused_and_recorded_as_denied(tmp_path):
    settings = _settings(tmp_path)
    server = mcp_server.build_server(settings, _user("analyst"))

    payload = _call(server, "check_sql", {"sql": "DROP TABLE revenue"})

    assert payload["allowed"] is False
    assert payload["reason"]
    rows = _rows(settings.audit_path)
    assert len(rows) == 1
    assert rows[0]["status"] == "denied"
    assert rows[0]["error"]
    assert rows[0]["question"].startswith("mcp: check_sql")


def test_05_the_role_is_not_caller_controlled(tmp_path):
    async def scenario() -> tuple[list[dict], dict]:
        async with stdio_client(_params(tmp_path, user="finance")) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listing = await session.list_tools()
                schemas = [tool.input_schema or {} for tool in listing.tools]
                payload = _payload(await session.call_tool("list_allowed_tables", {}))
                return schemas, payload

    schemas, payload = asyncio.run(scenario())

    forbidden = {"role", "user", "username", "allowed_tables"}
    for schema in schemas:
        assert not set(schema.get("properties", {})) & forbidden

    # MCP_USER=finance, and the server read that account's grants.
    assert payload["role"] == "finance"
    assert [table["table"] for table in payload["tables"]] == ["revenue"]


@pytest.mark.parametrize(
    ("user", "needle"),
    [("nobody", "nobody"), ("owner", "owner")],
)
def test_06_the_server_refuses_to_start_without_a_permitted_identity(
    tmp_path, user: str, needle: str
):
    rebuild(tmp_path / "demo.db")
    completed = subprocess.run(
        [sys.executable, "-m", "src.mcp_server"],
        cwd=str(ROOT),
        env={**os.environ, **_env(tmp_path, user)},
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode != 0
    assert needle in completed.stderr
    if user == "owner":
        # Admin is a real grant, but not a grant to read tables.
        assert "query" in completed.stderr


def test_07_the_server_source_has_no_execution_path():
    source = SERVER_SOURCE.read_text(encoding="utf-8")

    for forbidden in (
        "answer_question",
        "plan_sql",
        "execute_select",
        "adapter.execute",
        ".query(",
        "cap_select",
    ):
        assert forbidden not in source, forbidden
    # It does validate, and through the one guard the app uses.
    assert "sql_guard.check_sql" in source


def test_08_a_failed_audit_write_is_an_error_with_no_data(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    server = mcp_server.build_server(settings, _user("analyst"))

    def refuse_to_record(self, **kwargs):
        raise sqlite3.OperationalError("audit log is not writable")

    monkeypatch.setattr(AuditLog, "record_event", refuse_to_record)

    payload = _call(server, "health")

    assert payload["status"] == "error"
    assert payload["status"] != "ok"
    assert payload["message"] == "the call was not recorded, so it is not reported as done"
    assert "identity" not in payload
    assert _rows(settings.audit_path) == []


def test_09_the_suite_still_collects_at_least_the_baseline():
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    collected = sum(
        int(line.rsplit(": ", 1)[1])
        for line in completed.stdout.splitlines()
        if line.startswith("tests/") and ": " in line
    )
    assert collected >= COLLECT_FLOOR
