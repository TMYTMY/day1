from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.audit import AuditLog
from src.auth import authenticate
from src.config import ROOT, Settings
from src.db.seed import rebuild
from src.db.sqlite import SqliteAdapter
from src.llm import LlmClient
from src.routing import load_catalog

USERS = ROOT / "config" / "users.yaml"
ROUTING = ROOT / "config" / "routing.yaml"


@pytest.fixture
def env(tmp_path):
    db_path = tmp_path / "demo.db"
    rebuild(db_path)
    settings = Settings(
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
    )
    return SimpleNamespace(
        settings=settings,
        adapter=SqliteAdapter(db_path),
        catalog=load_catalog(ROUTING),
        audit=AuditLog(settings.audit_path),
        llm=LlmClient(None, settings.openrouter_base_url, settings.openrouter_model),
        analyst=authenticate("analyst", "analyst", USERS),
        finance=authenticate("finance", "finance", USERS),
        growth=authenticate("growth", "growth", USERS),
    )
