"""SQLite connection policy: schemes, link-local, metadata, timeout, env fallback."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import replace

import pytest

from src.connections import (
    ConnectionPolicyError,
    ConnectionStore,
    apply_enabled_connection,
    inspect_sqlite_target,
    check_sqlite_target,
)
from src.db.factory import build_adapter
from src.export import ExportMeta, to_csv, to_html


SECRET = "s3cret-db-password"


def _refuse(raw: str) -> str:
    verdict = check_sqlite_target(raw, timeout_seconds=1)
    assert verdict.ok is False
    assert verdict.path is None
    assert SECRET not in verdict.message
    assert SECRET not in verdict.error_class
    assert raw not in verdict.message
    return verdict.error_class


def test_non_sqlite_schemes_are_refused():
    assert _refuse(f"postgres://analyst:{SECRET}@localhost/warehouse") == "scheme"
    assert _refuse("postgresql://db.internal/warehouse") == "scheme"
    assert _refuse("mysql://localhost/warehouse") == "scheme"
    assert _refuse("https://example.com/warehouse.db") == "scheme"
    assert _refuse("athena://us-east-1/warehouse") == "scheme"


def test_link_local_and_metadata_hosts_are_refused_before_any_open():
    assert _refuse("http://169.254.1.1/latest") == "link_local"
    assert _refuse("sqlite://[fe80::1]/tmp/warehouse.db") == "link_local"
    assert _refuse("file://169.254.1.8/tmp/warehouse.db") == "link_local"
    assert _refuse("http://169.254.169.254/latest/meta-data") == "metadata"
    assert _refuse("http://metadata.google.internal/computeMetadata/v1/") == "metadata"
    assert _refuse("//169.254.169.254/share/warehouse.db") == "metadata"
    assert _refuse("http://169.254.170.2/") == "metadata"
    assert _refuse("http://[fd00:ec2::254]/") == "metadata"
    assert _refuse("http://2852039166/latest/meta-data") == "metadata"
    assert _refuse(f"postgres://analyst:{SECRET}@169.254.169.254/warehouse") == "metadata"


def test_a_local_sqlite_file_passes_and_a_hang_hits_the_timeout(tmp_path):
    database = tmp_path / "warehouse.db"
    conn = sqlite3.connect(database)
    conn.execute("CREATE TABLE revenue (product TEXT)")
    conn.commit()
    conn.close()

    ok = check_sqlite_target(str(database), timeout_seconds=2)
    assert ok.ok is True
    assert ok.error_class == ""
    assert ok.path == database.resolve()
    assert SECRET not in ok.message

    uri = check_sqlite_target(f"sqlite:///{database.resolve().as_posix()}", timeout_seconds=2)
    assert uri.ok is True
    assert uri.path == database.resolve()

    started = time.monotonic()

    def hang(path):
        time.sleep(5)

    timed = check_sqlite_target(str(database), timeout_seconds=0.2, probe=hang)
    elapsed = time.monotonic() - started
    assert timed.ok is False
    assert timed.error_class == "timeout"
    assert elapsed < 1.5

    missing = check_sqlite_target(str(tmp_path / "absent.db"), timeout_seconds=1)
    assert missing.error_class == "not_found"
    text = tmp_path / "notes.txt"
    text.write_text("not a database", encoding="utf-8")
    assert check_sqlite_target(str(text), timeout_seconds=1).error_class == "not_sqlite"


def test_rejected_targets_are_not_stored_and_export_has_no_secret_column(tmp_path):
    raw = f"postgres://analyst:{SECRET}@localhost/warehouse"
    verdict = check_sqlite_target(raw, timeout_seconds=1)
    store = ConnectionStore(tmp_path / "instance.db")
    store.record_failure(verdict.error_class, actor="owner")
    blob = (tmp_path / "instance.db").read_bytes()
    assert SECRET.encode() not in blob
    assert b"postgres://" not in blob
    assert store.get() is None

    csv_bytes = to_csv(["product"], [{"product": "Atlas"}])
    html_bytes = to_html(
        ["product"],
        [{"product": "Atlas"}],
        ExportMeta(
            question="revenue",
            tables=("revenue",),
            sql="SELECT product FROM revenue",
            assumptions=None,
            generated_at="2026-10-30T00:00:00Z",
            truncated=False,
            username="analyst",
        ),
    )
    assert SECRET.encode() not in csv_bytes
    assert SECRET.encode() not in html_bytes


def test_env_is_the_warehouse_until_a_connection_is_enabled(env, tmp_path):
    other = tmp_path / "other.db"
    conn = sqlite3.connect(other)
    conn.execute("CREATE TABLE keep (id INTEGER)")
    conn.execute("INSERT INTO keep VALUES (1)")
    conn.commit()
    conn.close()

    settings = replace(
        env.settings,
        database_url=f"postgres://analyst:{SECRET}@localhost/warehouse",
        db_password=SECRET,
    )
    assert apply_enabled_connection(settings).db_path == settings.db_path
    assert apply_enabled_connection(settings).db_password == SECRET

    store = ConnectionStore(settings.settings_path)
    store.record_success(other, actor="owner")
    assert apply_enabled_connection(settings).db_path == settings.db_path

    store.set_enabled(True, actor="owner")
    effective = apply_enabled_connection(settings)
    assert effective.db_backend == "sqlite"
    assert effective.db_path == other.resolve()
    assert effective.database_url is None
    assert effective.db_password is None
    assert effective.db_user is None

    adapter = build_adapter(settings)
    conn = sqlite3.connect(other)
    try:
        assert conn.execute("SELECT id FROM keep").fetchone()[0] == 1
    finally:
        conn.close()
    assert adapter.path.resolve() == other.resolve()

    store.set_enabled(False, actor="owner")
    restored = apply_enabled_connection(settings)
    assert restored.db_path == settings.db_path
    assert restored.db_password == SECRET


def test_enable_without_a_successful_test_is_refused(tmp_path):
    store = ConnectionStore(tmp_path / "instance.db")
    with pytest.raises(ConnectionPolicyError) as caught:
        store.set_enabled(True, actor="owner")
    assert caught.value.error_class == "not_tested"


def test_inspect_does_not_echo_the_submitted_string():
    raw = f"http://user:{SECRET}@metadata.google.internal/latest"
    with pytest.raises(ConnectionPolicyError) as caught:
        inspect_sqlite_target(raw)
    assert SECRET not in str(caught.value)
    assert "metadata.google.internal" not in str(caught.value)
    assert caught.value.error_class == "metadata"
