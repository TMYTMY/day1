"""Mail settings: encrypted round trip, the hint, and database over .env."""

from __future__ import annotations

from dataclasses import replace

import pytest

from src.config import ROOT, load_settings
from src.crypto import SecretKeyError, generate_key
from src.mail_settings import (
    SOURCE_DATABASE,
    SOURCE_ENV,
    SOURCE_UNCONFIGURED,
    MailSettingsStore,
    resolve_mail_settings,
)

# A password the suite can grep for. The last four are the only hint allowed.
SECRET = "day1-mail-secret-9912"
ENV_SECRET = "env-password-should-not-be-used"


def _settings(tmp_path, **overrides):
    base = replace(
        load_settings(),
        db_path=tmp_path / "demo.db",
        audit_path=tmp_path / "audit.db",
        alerts_path=tmp_path / "alerts.db",
        settings_path=tmp_path / "instance.db",
        knowledge_path=tmp_path / "knowledge",
        secret_key=None,
        smtp_host=None,
        smtp_user=None,
        smtp_password=None,
        smtp_from="day1-alerts@localhost",
        smtp_port=587,
        smtp_starttls=True,
        smtp_ssl=False,
    )
    return replace(base, **overrides)


def _bytes(path) -> bytes:
    blob = b""
    if path.exists():
        blob += path.read_bytes()
    for suffix in ("-wal", "-shm"):
        side = path.parent / f"{path.name}{suffix}"
        if side.exists():
            blob += side.read_bytes()
    return blob


def test_settings_path_and_secret_key_come_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SETTINGS_PATH", str(tmp_path / "custom.db"))
    monkeypatch.setenv("DAY1_SECRET_KEY", "test-key")
    settings = load_settings()
    assert settings.settings_path == tmp_path / "custom.db"
    assert settings.secret_key == "test-key"
    assert "test-key" not in repr(settings)
    assert "secret_key=set" in repr(settings)


def test_a_relative_settings_path_stays_inside_the_instance(monkeypatch):
    monkeypatch.setenv("SETTINGS_PATH", "data/instance.db")
    assert load_settings().settings_path == ROOT / "data" / "instance.db"


def test_save_read_and_clear_round_trip_the_secret(tmp_path):
    key = generate_key()
    settings = _settings(tmp_path, secret_key=key, smtp_host="env.example", smtp_port=2525)
    store = MailSettingsStore(settings.settings_path)
    written = store.save(
        {
            "smtp_provider": "gmail",
            "smtp_host": "db.example",
            "smtp_port": "587",
            "smtp_user": "owner@example.com",
            "smtp_password": SECRET,
            "smtp_from": "owner@example.com",
            "smtp_starttls": "true",
            "smtp_ssl": "false",
        },
        updated_by="owner",
        key=key,
    )
    assert "smtp_password" in written
    assert SECRET not in " ".join(written)

    resolved = store.resolve(settings)
    assert resolved["smtp_host"].value == "db.example"
    assert resolved["smtp_host"].source == SOURCE_DATABASE
    assert resolved["smtp_port"].value == "587"
    assert resolved["smtp_password"].value == SECRET
    assert resolved["smtp_password"].hint == "9912"
    assert resolved["smtp_password"].display == "9912"
    assert resolved["smtp_password"].source == SOURCE_DATABASE
    # The env host and port lose to the database. The password was never in .env.
    assert resolved["smtp_host"].value != "env.example"

    applied = resolve_mail_settings(settings)
    assert applied.smtp_host == "db.example"
    assert applied.smtp_port == 587
    assert applied.smtp_password == SECRET

    store.clear()
    after = store.resolve(settings)
    assert after["smtp_host"].source == SOURCE_ENV
    assert after["smtp_host"].value == "env.example"
    assert after["smtp_port"].value == "2525"
    assert after["smtp_password"].source == SOURCE_UNCONFIGURED
    assert after["smtp_password"].value is None


def test_resolution_order_is_database_then_env_then_unconfigured(tmp_path):
    key = generate_key()
    bare = _settings(tmp_path)
    store = MailSettingsStore(bare.settings_path)
    unconfigured = store.resolve(bare)
    assert unconfigured["smtp_host"].source == SOURCE_UNCONFIGURED
    assert unconfigured["smtp_password"].source == SOURCE_UNCONFIGURED
    # A default port is not a configured transport.
    assert unconfigured["smtp_port"].source == SOURCE_UNCONFIGURED

    from_env = store.resolve(_settings(tmp_path, smtp_host="env.example", smtp_user="a@b.c"))
    assert from_env["smtp_host"].source == SOURCE_ENV
    assert from_env["smtp_user"].value == "a@b.c"
    assert from_env["smtp_provider"].source == SOURCE_UNCONFIGURED

    store.save(
        {"smtp_host": "db.example", "smtp_password": SECRET},
        updated_by="owner",
        key=key,
    )
    mixed = store.resolve(
        _settings(tmp_path, secret_key=key, smtp_host="env.example", smtp_user="a@b.c")
    )
    assert mixed["smtp_host"].source == SOURCE_DATABASE
    assert mixed["smtp_host"].value == "db.example"
    assert mixed["smtp_user"].source == SOURCE_ENV
    assert mixed["smtp_password"].source == SOURCE_DATABASE


def test_an_empty_password_keeps_the_stored_one(tmp_path):
    key = generate_key()
    settings = _settings(tmp_path, secret_key=key)
    store = MailSettingsStore(settings.settings_path)
    store.save(
        {"smtp_host": "db.example", "smtp_port": "587", "smtp_password": SECRET},
        updated_by="owner",
        key=key,
    )
    written = store.save(
        {"smtp_host": "db.example", "smtp_port": "2525", "smtp_password": ""},
        updated_by="owner",
        key=key,
    )
    assert "smtp_password" not in written
    resolved = store.resolve(settings)
    assert resolved["smtp_password"].value == SECRET
    assert resolved["smtp_port"].value == "2525"


def test_a_saved_password_is_not_in_the_database_bytes(tmp_path):
    """Mutation: storing the password as plaintext turns this test red."""
    key = generate_key()
    settings = _settings(tmp_path, secret_key=key)
    store = MailSettingsStore(settings.settings_path)
    store.save(
        {"smtp_host": "db.example", "smtp_password": SECRET},
        updated_by="owner",
        key=key,
    )
    blob = _bytes(settings.settings_path)
    assert SECRET.encode() not in blob
    assert b"9912" in blob
    row_value = store._rows()["smtp_password"]["value"]
    assert row_value != SECRET
    assert SECRET not in row_value


def test_a_missing_key_refuses_to_save_and_writes_nothing(tmp_path):
    settings = _settings(tmp_path, secret_key=None, smtp_password=ENV_SECRET)
    store = MailSettingsStore(settings.settings_path)
    with pytest.raises(SecretKeyError, match="DAY1_SECRET_KEY"):
        store.save(
            {"smtp_host": "db.example", "smtp_password": SECRET},
            updated_by="owner",
            key=None,
        )
    assert SECRET.encode() not in _bytes(settings.settings_path)
    assert not settings.settings_path.exists()
    # The refusal does not quietly adopt the .env password as a stored secret.
    resolved = store.resolve(settings)
    assert resolved["smtp_password"].source == SOURCE_ENV
    assert resolved["smtp_password"].value == ENV_SECRET
    assert resolved["smtp_host"].source == SOURCE_UNCONFIGURED


def test_a_wrong_key_is_loud_and_does_not_fall_back_to_env(tmp_path):
    key = generate_key()
    settings = _settings(tmp_path, secret_key=key)
    store = MailSettingsStore(settings.settings_path)
    store.save({"smtp_host": "db.example", "smtp_password": SECRET}, updated_by="owner", key=key)

    broken = _settings(
        tmp_path,
        secret_key=generate_key(),
        smtp_host="env.example",
        smtp_password=ENV_SECRET,
    )
    resolved = store.resolve(broken)
    assert resolved["smtp_password"].source == SOURCE_DATABASE
    assert resolved["smtp_password"].value is None
    assert resolved["smtp_password"].error
    assert "smtp_password" in resolved["smtp_password"].error
    assert SECRET not in resolved["smtp_password"].error
    assert ENV_SECRET not in resolved["smtp_password"].error
    # Host was not a secret, so it still resolves. The password does not.
    assert resolved["smtp_host"].value == "db.example"
    with pytest.raises(SecretKeyError, match="smtp_password"):
        resolve_mail_settings(broken)


def test_a_missing_key_cannot_decrypt_a_stored_password(tmp_path):
    key = generate_key()
    settings = _settings(tmp_path, secret_key=key)
    MailSettingsStore(settings.settings_path).save(
        {"smtp_password": SECRET}, updated_by="owner", key=key
    )
    broken = _settings(tmp_path, secret_key=None, smtp_password=ENV_SECRET)
    resolved = MailSettingsStore(broken.settings_path).resolve(broken)
    assert resolved["smtp_password"].value is None
    assert resolved["smtp_password"].error
    assert "DAY1_SECRET_KEY" in resolved["smtp_password"].error
    assert ENV_SECRET not in (resolved["smtp_password"].value or "")
    with pytest.raises(SecretKeyError, match="smtp_password"):
        resolve_mail_settings(broken)


def test_a_stored_port_that_is_not_a_port_names_the_field(tmp_path):
    key = generate_key()
    settings = _settings(tmp_path, secret_key=key, smtp_host="env.example")
    MailSettingsStore(settings.settings_path).save(
        {"smtp_port": "nope"}, updated_by="owner", key=key
    )
    from src.config import ConfigError

    with pytest.raises(ConfigError, match="smtp_port"):
        resolve_mail_settings(settings)


def test_repr_never_contains_the_secret_key_or_the_mail_password(tmp_path):
    key = generate_key()
    settings = _settings(tmp_path, secret_key=key, smtp_host="mail.example", smtp_password=SECRET)
    text = repr(settings)
    assert key not in text
    assert SECRET not in text
    assert "secret_key=set" in text
