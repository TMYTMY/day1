import sqlite3

from src.audit import AuditEvent, AuditLog
from src.metrics import definition_hash, load_metrics
from src.pipeline import answer_question
from tests.test_pipeline import _Off


def _event(**overrides) -> AuditEvent:
    payload = dict(
        username="analyst",
        role="analyst",
        question="What was total revenue by product?",
        routed_tables=("revenue",),
        sql="SELECT 1",
        status="ok",
        row_count=1,
        error=None,
        metric_id="revenue_by_product",
        definition_hash="abc123abc123",
    )
    payload.update(overrides)
    return AuditEvent(**payload)


def _read(path) -> sqlite3.Row:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT metric_id, definition_hash FROM audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return row


def test_a_metric_event_round_trips_through_the_audit_log(tmp_path):
    log = AuditLog(tmp_path / "audit.db")
    log.write(_event())
    row = _read(log.path)
    assert row["metric_id"] == "revenue_by_product"
    assert row["definition_hash"] == "abc123abc123"


def test_an_old_audit_database_gains_the_metric_columns(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            question TEXT NOT NULL,
            routed_tables TEXT NOT NULL,
            sql TEXT,
            status TEXT NOT NULL,
            row_count INTEGER,
            error TEXT
        )
        """
    )
    conn.commit()
    conn.close()

    log = AuditLog(path)
    log.write(_event(metric_id="dau_by_platform", definition_hash="def456def456"))
    row = _read(path)
    assert row["metric_id"] == "dau_by_platform"
    assert row["definition_hash"] == "def456def456"


def test_a_successful_answer_stores_the_definition_hash(env):
    metric = next(item for item in load_metrics(env.settings.metrics_path) if item.id == "revenue_by_product")
    answer = answer_question(
        "What was total revenue by product?",
        env.analyst,
        settings=env.settings,
        adapter=env.adapter,
        catalog=env.catalog,
        audit=env.audit,
        llm=_Off(),
    )
    assert answer.status == "ok"
    assert answer.metric_id == "revenue_by_product"
    row = _read(env.settings.audit_path)
    assert row["metric_id"] == "revenue_by_product"
    assert row["definition_hash"] == definition_hash(metric)
