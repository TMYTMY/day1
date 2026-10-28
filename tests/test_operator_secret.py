"""The operator secret: generated on the host, stored as a salted hash, never shipped."""

from __future__ import annotations

import sqlite3

import yaml

from src.auth import authenticate, load_directory
from src.config import ROOT, Settings, load_settings
from src.operator_secret import (
    created_at,
    generate_secret,
    hash_secret,
    has_secret,
    main,
    store_secret,
    verify_secret,
)

USERS = ROOT / "config" / "users.yaml"
SECRET = "a-generated-operator-secret-1f2e"


def _raw(path) -> bytes:
    blob = bytearray()
    if path.exists():
        blob += path.read_bytes()
    for suffix in ("-wal", "-shm"):
        side = path.with_name(path.name + suffix)
        if side.exists():
            blob += side.read_bytes()
    return bytes(blob)


def test_the_secret_is_printed_once_and_only_a_hash_is_stored(tmp_path, capsys, monkeypatch):
    path = tmp_path / "instance.db"
    monkeypatch.setenv("SETTINGS_PATH", str(path))

    assert main(["--init"]) == 0
    printed = capsys.readouterr().out

    secret = printed.split("    ")[1].splitlines()[0].strip()
    assert len(secret) >= 32
    assert has_secret(path) is True
    assert created_at(path)

    # Only a salted hash is on disk, and the plaintext is nowhere in the files.
    assert secret.encode() not in _raw(path)
    conn = sqlite3.connect(path)
    row = conn.execute("SELECT algorithm, salt, hash FROM operator_secret").fetchone()
    conn.close()
    assert row[0] == "scrypt"
    assert row[1] and row[2] and row[2] != secret
    assert len(row[1]) == 32 and len(row[2]) == 64

    assert verify_secret(path, secret) is True
    assert verify_secret(path, "not-the-secret") is False
    assert verify_secret(path, "") is False


def test_init_refuses_to_replace_a_secret_unless_forced(tmp_path, capsys, monkeypatch):
    path = tmp_path / "instance.db"
    monkeypatch.setenv("SETTINGS_PATH", str(path))
    store_secret(path, SECRET)

    assert main(["--init"]) == 1
    assert "refused" in capsys.readouterr().err
    # The original still works: a refusal is not a silent rotation.
    assert verify_secret(path, SECRET) is True

    assert main(["--init", "--force"]) == 0
    replacement = capsys.readouterr().out.split("    ")[1].splitlines()[0].strip()
    assert replacement != SECRET
    assert verify_secret(path, replacement) is True
    assert verify_secret(path, SECRET) is False


def test_status_says_whether_a_secret_is_set(tmp_path, capsys, monkeypatch):
    path = tmp_path / "instance.db"
    monkeypatch.setenv("SETTINGS_PATH", str(path))
    assert main(["--status"]) == 0
    assert "not set" in capsys.readouterr().out

    store_secret(path, SECRET)
    assert main(["--status"]) == 0
    assert "set" in capsys.readouterr().out


def test_an_unset_instance_refuses_every_candidate(tmp_path):
    path = tmp_path / "instance.db"
    assert has_secret(path) is False
    assert verify_secret(path, "") is False
    assert verify_secret(path, "anything") is False
    # Asking must not create the database: a page load is not a write.
    assert path.exists() is False


def test_the_hash_is_salted_so_the_same_secret_stores_differently(tmp_path):
    first = tmp_path / "one.db"
    second = tmp_path / "two.db"
    store_secret(first, SECRET)
    store_secret(second, SECRET)

    def row(path):
        conn = sqlite3.connect(path)
        value = conn.execute("SELECT salt, hash FROM operator_secret").fetchone()
        conn.close()
        return value

    assert row(first) != row(second)
    assert verify_secret(first, SECRET) and verify_secret(second, SECRET)


def test_an_empty_secret_is_refused(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        store_secret(tmp_path / "instance.db", "")
    assert has_secret(tmp_path / "instance.db") is False


def test_a_generated_secret_is_long_and_unique():
    secrets = {generate_secret() for _ in range(8)}
    assert len(secrets) == 8
    assert all(len(item) >= 32 for item in secrets)
    salt, digest = hash_secret(SECRET)
    assert (salt, digest) == hash_secret(SECRET, salt=bytes.fromhex(salt))


def test_the_shipped_directory_holds_no_password_for_the_admin_account():
    """The documented admin credential is gone; the account has no password at all."""
    raw = yaml.safe_load(USERS.read_text(encoding="utf-8"))
    admins = [entry for entry in raw["users"] if entry.get("role") == "owner"]
    assert len(admins) == 1
    account = admins[0]
    assert account["credential"] == "operator_secret"
    assert "password" not in account

    directory = load_directory(USERS)
    assert directory.accounts["owner"].credential == "operator_secret"
    assert directory.accounts["owner"].password == ""
    # The old credential opens nothing, with or without somewhere to check it.
    assert authenticate("owner", "owner", USERS) is None
    assert authenticate("owner", "owner", USERS, settings_path=ROOT / "data" / "nope.db") is None


def test_browser_settings_are_off_unless_the_flag_says_otherwise(monkeypatch):
    for name in ("DAY1_ALLOW_BROWSER_SETTINGS",):
        monkeypatch.delenv(name, raising=False)
    assert load_settings().allow_browser_settings is False

    for value, expected in (
        ("1", True),
        ("true", True),
        ("YES", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("", False),
        ("yes-please", False),
    ):
        monkeypatch.setenv("DAY1_ALLOW_BROWSER_SETTINGS", value)
        assert load_settings().allow_browser_settings is expected, value


def test_the_flag_is_a_field_of_settings_so_every_caller_sees_it():
    assert "allow_browser_settings" in Settings.__dataclass_fields__
    assert Settings.__dataclass_fields__["allow_browser_settings"].default is False
