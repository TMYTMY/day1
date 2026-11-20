from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.audit import AuditLog
from src.auth import authenticate
from src.config import ROOT, Settings
from src.db.seed import rebuild
from src.db.sqlite import SqliteAdapter
from src.llm import LlmClient
from src.metric_signatures import sign
from src.metrics import load_metrics
from src.models import User
from src.routing import load_catalog

USERS = ROOT / "config" / "users.yaml"
ROUTING = ROOT / "config" / "routing.yaml"

# The catalogue's one real definition. The fixture instance is one an operator
# has already signed it on; the three placeholders stay drafts.
SIGNED_IN_FIXTURES = "revenue_by_product"


class _QuietAudit(AuditLog):
    """An audit log that accepts a row and writes nothing.

    Seeding a fixture reproduces the *state* of an instance where a definition
    was signed earlier. It is not a sign attempt, so it has no attempt to
    record; tests that exercise signing go through the page's own seam and
    assert the rows it writes.
    """

    def record_event(self, **kwargs) -> None:  # type: ignore[override]
        return None


def _seed_signature(settings: Settings, metric) -> None:
    """Put one signature in force, the way an earlier operator visit did."""
    signer = User(
        username="owner",
        role="owner",
        allowed_tables=(),
        capabilities=("admin",),
    )
    sign(
        audit=_QuietAudit(settings.audit_path),
        metric=metric,
        definition=metric.definition,
        owner=metric.owner,
        exceptions=metric.exceptions,
        effective_from=metric.effective_from,
        signer=signer,
    )


@pytest.fixture
def seed_signature():
    """Give a test the store-level way to put a definition in force."""

    def seed(settings: Settings, metric) -> None:
        _seed_signature(settings, metric)

    return seed


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
        # The instance settings database belongs to this test, not to the
        # checkout. The worker records its identity and its delivery health
        # there (issue #28), and a shared file would let one test's instance
        # identity refuse the next test's delivery.
        settings_path=tmp_path / "instance.db",
    )
    # An instance whose one real definition a human has signed: that is the
    # state the shipped demo runs in after the operator confirms it once. The
    # three placeholders stay drafts, so a question about them is refused
    # (tests/test_metric_signatures.py pins that path). The signature is
    # written without an audit row: the fixture seeds a state, it does not
    # make an attempt.
    shipped = load_metrics(settings.metrics_path)
    _seed_signature(
        settings, next(metric for metric in shipped if metric.id == SIGNED_IN_FIXTURES)
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
