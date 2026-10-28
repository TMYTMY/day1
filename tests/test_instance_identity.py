"""Instance identity: one UUID and the host it was written on, and the refusal.

The threat is a copy: an instance directory plus its ``.env`` is a second sender
with the same credentials and the same real recipients. These tests pin the two
halves of the answer — the record written at first configuration, and the check
that refuses a delivery from anywhere else until an operator says otherwise.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from src.config import load_settings
from src.crypto import generate_key
from src.instance_identity import (
    IdentityStore,
    InstanceIdentity,
    record_instance_identity,
    running_hostname,
)
from src.mail_settings import MailSettingsStore

SECRET = "day1-mail-secret-9912"


@pytest.fixture
def path(tmp_path):
    return tmp_path / "instance.db"


@pytest.fixture
def store(path):
    return IdentityStore(path)


def _save_mail(path, key, *, host="mail.example.com"):
    """Configure mail the way the Settings page does, which is what pins the instance."""
    settings = replace(
        load_settings(),
        settings_path=path,
        secret_key=key,
        smtp_host=None,
        smtp_user=None,
        smtp_password=None,
    )
    MailSettingsStore(path).save(
        {
            "smtp_host": host,
            "smtp_port": "587",
            "smtp_user": "owner@example.com",
            "smtp_password": SECRET,
            "smtp_from": "owner@example.com",
        },
        updated_by="owner",
        key=settings.secret_key,
    )


# --- the record -----------------------------------------------------------


def test_first_configuration_writes_a_uuid_the_host_and_the_path(store, path):
    key = generate_key()

    _save_mail(path, key)

    identity = store.read()
    assert identity is not None
    assert len(identity.instance_id) == 36
    assert identity.hostname == running_hostname()
    assert identity.path == str(path.resolve())
    assert identity.recorded_at.endswith("Z")
    assert identity.updated_at == identity.recorded_at
    assert identity.complete is True


def test_a_later_save_keeps_the_identity_it_already_has(store, path):
    key = generate_key()
    _save_mail(path, key)
    first = store.read()

    _save_mail(path, key, host="relay.example.com")

    second = store.read()
    assert second is not None and first is not None
    assert second.instance_id == first.instance_id
    assert second.hostname == first.hostname
    assert second.path == first.path


def test_reading_the_identity_needs_no_encryption_key(store, path):
    _save_mail(path, generate_key())

    # No key, no settings object, no Streamlit: one operator with sqlite3.
    even_if = replace(load_settings(), settings_path=path, secret_key=None)
    assert even_if.secret_key is None
    assert store.read() is not None


def test_an_unconfigured_instance_has_no_identity_and_reading_creates_nothing(
    store, path
):
    assert store.read() is None
    assert not path.exists()


# --- the check ------------------------------------------------------------


def test_the_configured_host_is_not_refused(store, path):
    _save_mail(path, generate_key())
    identity = store.read()
    assert identity is not None

    check = store.check(hostname=identity.hostname, running_path=path)

    assert check.refused is False
    assert check.reason is None
    assert check.adopted is False


def test_an_instance_with_no_identity_is_not_refused(store, path):
    check = store.check(hostname="some-host", running_path=path)

    assert check.recorded is False
    assert check.refused is False


def test_a_different_host_is_refused_and_the_reason_names_both(store, path):
    _save_mail(path, generate_key())

    check = store.check(hostname="copied-host", running_path=path)

    assert check.refused is True
    reason = check.reason
    assert reason is not None
    assert running_hostname() in reason  # where it was configured
    assert "copied-host" in reason  # where it is running
    assert store.read() is not None
    assert store.read().hostname == running_hostname()
    assert reason.count(store.read().instance_id) == 1


def test_a_copy_beside_the_original_is_refused_by_its_path(store, path, tmp_path):
    """The same host, a duplicated directory: only the path can tell them apart."""
    _save_mail(path, generate_key())

    check = store.check(hostname=running_hostname(), running_path=tmp_path / "copy")

    assert check.refused is True
    assert "copy" in (check.reason or "")


def test_a_refusal_does_not_write_anything(store, path):
    _save_mail(path, generate_key())
    before = store.read()

    store.check(hostname="copied-host", running_path=path)

    assert store.read() == before


def test_the_operator_can_confirm_the_move(store, path):
    _save_mail(path, generate_key())
    original = store.read()
    assert original is not None

    check = store.check(hostname="new-host", running_path=path, confirm=True)

    assert check.refused is False
    assert check.adopted is True
    assert check.identity is not None
    # Same instance, recorded as moved.
    assert check.identity.instance_id == original.instance_id
    assert check.identity.hostname == "new-host"
    assert check.identity.recorded_at == original.recorded_at
    # The row records who re-bound it, which is the audit trail for the move.
    conn = sqlite3.connect(path)
    try:
        recorded = conn.execute(
            "SELECT updated_by, updated_at FROM instance_identity WHERE id = 1"
        ).fetchone()
    finally:
        conn.close()
    assert recorded[0] == "operator"
    assert recorded[1] >= original.updated_at
    assert "new-host" in (check.moved_reason or "")
    assert original.hostname in (check.moved_reason or "")

    # And it stays moved: no flag is needed again.
    assert store.check(hostname="new-host", running_path=path).refused is False


def test_confirming_a_path_move_rebinds_the_path(store, path, tmp_path):
    _save_mail(path, generate_key())
    moved = tmp_path / "restored" / "instance.db"
    moved.parent.mkdir()

    check = store.check(hostname=running_hostname(), running_path=moved, confirm=True)

    assert check.adopted is True
    assert store.read().path == str(moved.resolve())


def test_an_empty_instance_id_is_refused(store, path):
    _save_mail(path, generate_key())

    conn = sqlite3.connect(path)
    conn.execute("UPDATE instance_identity SET instance_id = '' WHERE id = 1")
    conn.commit()
    conn.close()

    check = store.check(hostname=running_hostname(), running_path=path)

    assert check.id_missing is True
    assert check.refused is True
    assert "instance id is empty" in (check.reason or "")


def test_two_first_configurations_keep_one_identity(path):
    """Two processes pinning at once must not mint two ids."""
    first = record_instance_identity(path, hostname="host-a")
    second = record_instance_identity(path, hostname="host-b")

    assert first.instance_id == second.instance_id
    assert second.hostname == "host-a"  # the first writer wins
    conn = sqlite3.connect(path)
    rows = conn.execute("SELECT COUNT(*) FROM instance_identity").fetchone()[0]
    conn.close()
    assert rows == 1


def test_running_hostname_can_be_pinned(monkeypatch):
    monkeypatch.setenv("DAY1_INSTANCE_HOSTNAME", "day1-prod")

    settings = load_settings()

    assert settings.instance_hostname == "day1-prod"
    assert running_hostname(settings.instance_hostname) == "day1-prod"


def test_the_identity_is_a_plain_row_an_operator_can_read(store, path):
    _save_mail(path, generate_key())

    identity = store.read()
    assert isinstance(identity, InstanceIdentity)
    assert " " not in identity.instance_id


def test_the_pinned_name_and_the_working_name_come_from_one_place(
    monkeypatch, store, path
):
    """A pin taken by the page and a check made by the worker must agree.

    A container whose hostname is a fresh random id pins
    ``DAY1_INSTANCE_HOSTNAME``; the page saves mail settings without carrying a
    Settings object, so the pin and the check both read the override rather than
    one reading the kernel.
    """
    monkeypatch.setenv("DAY1_INSTANCE_HOSTNAME", "day1-prod")

    identity = record_instance_identity(path)
    settings = load_settings()
    check = store.check(hostname=running_hostname(settings.instance_hostname), running_path=path)

    assert identity.hostname == "day1-prod"
    assert check.refused is False
