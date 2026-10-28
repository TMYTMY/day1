"""A declared source belongs to the instance that declared it.

Two instances on one machine read their own routing map, users, metrics and
sources paths from the environment. One instance must never list, quote or
refuse on another instance's declared table.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from src.audit import AuditLog
from src.auth import authenticate
from src.config import ROOT, Settings, load_settings
from src.db.seed import rebuild
from src.db.sqlite import SqliteAdapter
from src.llm import LlmClient
from src.pipeline import answer_question
from src.routing import Catalog, load_catalog
from src.sources import SourceSpec, load_sources, merge_catalog
from src.sources_load import load_file

INSTANCE_A_TABLE = "sample_orders"
INSTANCE_A_DESCRIPTION = "Sample customer orders export"
INSTANCE_B_TABLE = "stock_moves"
INSTANCE_B_DESCRIPTION = "Stock moves recorded by instance B"


def _instance(tmp_path: Path, name: str) -> Path:
    """A company's own copy of the instance config files."""
    root = tmp_path / name
    (root / "config").mkdir(parents=True)
    (root / "data").mkdir(parents=True)
    for file_name in ("routing.yaml", "metrics.yaml", "users.yaml"):
        shutil.copyfile(ROOT / "config" / file_name, root / "config" / file_name)
    return root


def _point_at(monkeypatch, root: Path) -> None:
    """Configure one instance the way a deployment would: through the environment."""
    monkeypatch.setenv("DB_PATH", str(root / "data" / "demo.db"))
    monkeypatch.setenv("AUDIT_PATH", str(root / "data" / "audit.db"))
    monkeypatch.setenv("ROUTING_PATH", str(root / "config" / "routing.yaml"))
    monkeypatch.setenv("USERS_PATH", str(root / "config" / "users.yaml"))
    monkeypatch.setenv("METRICS_PATH", str(root / "config" / "metrics.yaml"))
    monkeypatch.setenv("KNOWLEDGE_PATH", str(root / "data" / "knowledge"))
    monkeypatch.setenv("SOURCES_DIR", str(root / "config" / "sources"))
    monkeypatch.setenv("SOURCES_DB", str(root / "data" / "sources.sqlite"))
    monkeypatch.setenv("SOURCES_STAGING_DIR", str(root / "data" / "staging"))


def _declare_a(root: Path) -> None:
    csv_path = root / "orders.csv"
    csv_path.write_text("order_id,amount\nso-1,10\nso-2,20\n", encoding="utf-8")
    # No paths passed: a declaration reads its destination from settings.
    load_file(
        csv_path,
        source_id="sample_orders_src",
        table=INSTANCE_A_TABLE,
        owner_role="logistics",
        description=INSTANCE_A_DESCRIPTION,
        synonyms=("sample orders",),
    )


def _declare_b(root: Path) -> None:
    csv_path = root / "moves.csv"
    csv_path.write_text("move_id,units\nsm-1,5\n", encoding="utf-8")
    load_file(
        csv_path,
        source_id="stock_moves_src",
        table=INSTANCE_B_TABLE,
        owner_role="logistics",
        description=INSTANCE_B_DESCRIPTION,
        synonyms=("stock moves",),
    )


def _catalogue(settings: Settings) -> tuple[dict[str, SourceSpec], Catalog]:
    """The wiring ``app.main`` uses: sources from settings, merged into routing."""
    sources = load_sources(
        settings.sources_dir,
        routing_path=settings.routing_path,
        warehouse_path=settings.db_path,
    )
    return sources, merge_catalog(load_catalog(settings.routing_path), sources)


def test_sources_paths_come_from_settings(tmp_path, monkeypatch):
    root_a = _instance(tmp_path, "a")
    root_b = _instance(tmp_path, "b")

    _point_at(monkeypatch, root_a)
    settings_a = load_settings()
    _point_at(monkeypatch, root_b)
    settings_b = load_settings()

    assert settings_a.sources_dir == root_a / "config" / "sources"
    assert settings_b.sources_dir == root_b / "config" / "sources"
    assert settings_a.sources_db == root_a / "data" / "sources.sqlite"
    assert settings_b.sources_db == root_b / "data" / "sources.sqlite"
    assert settings_a.sources_staging_dir == root_a / "data" / "staging"
    assert settings_b.sources_staging_dir == root_b / "data" / "staging"


def test_two_instances_do_not_share_declared_sources(tmp_path, monkeypatch):
    root_a = _instance(tmp_path, "a")
    root_b = _instance(tmp_path, "b")

    _point_at(monkeypatch, root_a)
    settings_a = load_settings()
    _declare_a(root_a)

    _point_at(monkeypatch, root_b)
    settings_b = load_settings()
    _declare_b(root_b)

    assert settings_a.sources_dir != settings_b.sources_dir
    assert (settings_b.sources_dir / "stock_moves_src.yaml").is_file()
    assert not (settings_b.sources_dir / "sample_orders_src.yaml").exists()
    assert settings_a.sources_db.is_file()
    assert settings_b.sources_db.is_file()

    sources_a, catalogue_a = _catalogue(settings_a)
    sources_b, catalogue_b = _catalogue(settings_b)

    # Both declarations still merge into their own catalogue.
    assert {topic.id for topic in catalogue_a.topics} & {"sample_orders_src"} == {"sample_orders_src"}
    assert {topic.id for topic in catalogue_b.topics} & {"stock_moves_src"} == {"stock_moves_src"}

    # Neither instance can see the other's declared table or description.
    assert all(INSTANCE_A_TABLE not in topic.tables for topic in catalogue_b.topics)
    assert INSTANCE_A_TABLE not in catalogue_b.descriptions
    assert all(INSTANCE_B_TABLE not in topic.tables for topic in catalogue_a.topics)
    assert INSTANCE_B_TABLE not in catalogue_a.descriptions
    titles_b = " ".join(topic.title for topic in catalogue_b.topics)
    assert INSTANCE_A_DESCRIPTION not in titles_b
    assert INSTANCE_A_DESCRIPTION not in " ".join(catalogue_b.descriptions.values())

    # A question about A's table is not answered, and the refusal names nothing
    # that belongs to A.
    rebuild(settings_b.db_path)
    analyst = authenticate("analyst", "analyst", settings_b.users_path)
    assert analyst is not None
    answer = answer_question(
        f"show {INSTANCE_A_TABLE}",
        analyst,
        settings=settings_b,
        adapter=SqliteAdapter(settings_b.db_path, seed=False),
        catalog=catalogue_b,
        audit=AuditLog(settings_b.audit_path),
        llm=LlmClient(None, settings_b.openrouter_base_url, settings_b.openrouter_model),
        sources=sources_b,
        sources_db=settings_b.sources_db,
    )
    assert answer.status == "clarify"
    assert INSTANCE_A_TABLE not in answer.message
    assert INSTANCE_A_DESCRIPTION not in answer.message
    assert "Revenue" in answer.message
