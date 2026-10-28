"""The stored mail password cannot move to a transport it was not entered for.

Each test here is one refusal from issue #26: the binding, the tombstone, the
key-check value, and the value validation that stops a typo from dropping TLS.
The mutation each one is written to catch is named in its docstring.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from src.config import ConfigError, load_settings
from src.crypto import KeyCheckError, SecretKeyError, generate_key
from src.mail_settings import (
    BINDING_FIELD,
    KEY_CHECK_FIELD,
    SOURCE_DATABASE,
    SOURCE_ENV,
    SOURCE_UNCONFIGURED,
    TOMBSTONE,
    MailSettingsStore,
    MailValueError,
    SecretBindingError,
    password_hint,
    resolve_mail_settings,
)

# A password the suite can grep for. 21 characters, so the hint is stable.
SECRET = "day1-mail-secret-9912"
NEW_SECRET = "day1-mail-secret-4408"
ENV_SECRET = "env-password-should-not-be-used"

BOUND = {
    "smtp_host": "smtp.example.com",
    "smtp_port": "587",
    "smtp_user": "owner@example.com",
    "smtp_from": "owner@example.com",
    "smtp_starttls": "true",
    "smtp_ssl": "false",
}


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


def _store(tmp_path, key):
    return MailSettingsStore(tmp_path / "instance.db")


def _save(store, key, **overrides):
    values = dict(BOUND)
    values.update(overrides)
    return store.save(values, updated_by="owner", key=key)


def _rows(path) -> dict[str, sqlite3.Row]:
    """Every stored row, and an empty answer before anything has been stored."""
    if not path.exists():
        return {}
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return {
            row["key"]: row
            for row in conn.execute("SELECT * FROM instance_settings").fetchall()
        }
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()


# --- the binding -----------------------------------------------------------


def test_a_save_that_moves_the_host_without_a_password_is_refused(tmp_path):
    """Mutation: skipping the binding comparison carries the secret to a new host."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)
    ciphertext = _rows(store.path)["smtp_password"]["value"]

    with pytest.raises(SecretBindingError) as caught:
        _save(store, key, smtp_host="evil.example", smtp_password="")

    message = str(caught.value)
    assert "smtp_password" in message
    assert "host was smtp.example.com and is now evil.example" in message
    assert "Enter the password again" in message
    assert SECRET not in message

    # Nothing moved, and the stored secret was neither moved nor discarded.
    rows = _rows(store.path)
    assert rows["smtp_host"]["value"] == "smtp.example.com"
    assert rows["smtp_password"]["value"] == ciphertext
    resolved = store.resolve(_settings(tmp_path, secret_key=key))
    assert resolved["smtp_host"].value == "smtp.example.com"
    assert resolved["smtp_password"].value == SECRET


@pytest.mark.parametrize(
    ("change", "named"),
    [
        ({"smtp_host": "other.example"}, "host"),
        ({"smtp_port": "2525"}, "port"),
        ({"smtp_user": "someone@example.com"}, "username"),
        ({"smtp_starttls": "false", "smtp_ssl": "true"}, "TLS mode"),
    ],
)
def test_every_bound_field_is_named_when_it_moves(tmp_path, change, named):
    """Mutation: comparing only the host lets a port or TLS change carry the secret."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)

    with pytest.raises(SecretBindingError) as caught:
        _save(store, key, smtp_password="", **change)

    assert named in str(caught.value)
    assert store.resolve(_settings(tmp_path, secret_key=key))["smtp_password"].value == SECRET


def test_the_same_transport_with_a_fresh_password_rebinds_it(tmp_path):
    """A new password in the same save is what authorises the move."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)

    written = _save(store, key, smtp_host="other.example", smtp_password=NEW_SECRET)

    assert "smtp_password" in written
    settings = _settings(tmp_path, secret_key=key)
    assert store.resolve(settings)["smtp_host"].value == "other.example"
    assert resolve_mail_settings(settings).smtp_password == NEW_SECRET
    assert resolve_mail_settings(settings).smtp_host == "other.example"


def test_a_secret_with_no_recorded_binding_is_not_carried(tmp_path):
    """A store written before this ticket cannot prove where the password belongs."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)
    conn = sqlite3.connect(store.path)
    with conn:
        conn.execute("DELETE FROM instance_settings WHERE key = ?", (BINDING_FIELD,))
    conn.close()

    with pytest.raises(SecretBindingError, match="no record"):
        _save(store, key, smtp_password="")


def test_the_binding_records_only_the_transport(tmp_path):
    """The binding row is metadata: no ciphertext and no secret character."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)

    row = _rows(store.path)[BINDING_FIELD]
    assert row["secret"] == 0
    assert "smtp.example.com" in row["value"]
    assert SECRET not in row["value"]
    assert "9912" not in row["value"]


# --- the tombstone ---------------------------------------------------------


def test_a_clear_is_a_tombstone_that_env_cannot_fill(tmp_path):
    """Mutation: deleting the row lets SMTP_PASSWORD resurrect the credential."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)
    store.clear(cleared_by="owner")

    env = _settings(
        tmp_path,
        secret_key=key,
        smtp_host="env.example",
        smtp_user="env-user",
        smtp_password=ENV_SECRET,
    )
    resolved = store.resolve(env)
    password = resolved["smtp_password"]
    assert password.value is None
    assert password.source == SOURCE_UNCONFIGURED
    assert password.cleared is True
    assert password.display == "cleared"
    assert resolved.cleared is True
    # The environment's transport values still resolve, as a group.
    assert resolved.transport_source == SOURCE_ENV
    assert resolved["smtp_host"].value == "env.example"
    # The credential is gone from the transport that would be used.
    assert resolve_mail_settings(env).smtp_password is None
    assert resolve_mail_settings(env).smtp_host == "env.example"

    row = _rows(store.path)["smtp_password"]
    assert row["value"] == TOMBSTONE
    assert row["hint"] == "cleared"
    assert row["updated_by"] == "owner"


def test_a_clear_needs_no_key(tmp_path):
    """A lost key is exactly when an operator has to be able to clear."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)

    MailSettingsStore(store.path).clear()

    resolved = store.resolve(_settings(tmp_path, secret_key=None, smtp_host="env.example"))
    assert resolved.errors == ()
    assert resolved["smtp_password"].cleared is True
    assert resolved["smtp_host"].value == "env.example"


def test_a_tombstoned_password_does_not_block_saving_a_new_transport(tmp_path):
    """After a clear, the next save may change anything; it just has no secret."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)
    store.clear()

    written = _save(store, key, smtp_host="another.example", smtp_password="")

    assert "smtp_password" not in written
    resolved = store.resolve(_settings(tmp_path, secret_key=key))
    assert resolved["smtp_host"].value == "another.example"
    assert resolved["smtp_password"].value is None
    assert resolved["smtp_password"].cleared is True


# --- the key check ---------------------------------------------------------


def test_the_key_check_is_written_with_the_first_secret(tmp_path):
    """Mutation: skipping the key check turns a mixed-key store into silent errors."""
    key = generate_key()
    store = _store(tmp_path, key)
    assert KEY_CHECK_FIELD not in _rows(store.path)
    _save(store, key, smtp_password=SECRET)
    row = _rows(store.path)[KEY_CHECK_FIELD]
    assert row["secret"] == 1
    assert SECRET not in row["value"]
    # Saving a non-secret field does not rewrite it.
    before = row["value"]
    _save(store, key, smtp_from="alerts@example.com")
    assert _rows(store.path)[KEY_CHECK_FIELD]["value"] == before


def test_a_wrong_key_is_one_named_error_and_never_a_fallback(tmp_path):
    """Mutation: skipping the key check gives one decryption error per field."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)

    broken = _settings(
        tmp_path,
        secret_key=generate_key(),
        smtp_host="env.example",
        smtp_password=ENV_SECRET,
    )
    resolved = store.resolve(broken)
    assert resolved["smtp_password"].value is None
    assert resolved["smtp_password"].error
    assert "smtp_password" in resolved["smtp_password"].error
    assert "key-check" in resolved["smtp_password"].error
    assert SECRET not in resolved["smtp_password"].error
    assert ENV_SECRET not in resolved["smtp_password"].error
    # The plaintext transport is still readable, so an operator can see what broke.
    assert resolved["smtp_host"].value == "smtp.example.com"
    with pytest.raises(KeyCheckError, match="smtp_password"):
        store.verify_key(broken.secret_key)
    with pytest.raises(SecretKeyError, match="smtp_password"):
        resolve_mail_settings(broken)


def test_a_write_under_the_wrong_key_is_refused(tmp_path):
    """A second vintage of ciphertext in one table is the mixed-key state."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)

    with pytest.raises(KeyCheckError):
        store.save({"smtp_port": "2525"}, updated_by="owner", key=generate_key())

    assert _rows(store.path)["smtp_port"]["value"] == "587"


def test_a_store_written_before_the_key_check_still_verifies(tmp_path):
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)
    conn = sqlite3.connect(store.path)
    with conn:
        conn.execute("DELETE FROM instance_settings WHERE key = ?", (KEY_CHECK_FIELD,))
    conn.close()

    assert store.resolve(_settings(tmp_path, secret_key=key))["smtp_password"].value == SECRET
    broken = store.resolve(_settings(tmp_path, secret_key=generate_key()))
    assert broken["smtp_password"].value is None
    assert broken["smtp_password"].error


def test_clearing_the_last_secret_also_clears_the_key_check(tmp_path):
    """Otherwise a replacement key could never be adopted after a clear."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)
    store.clear()
    assert _rows(store.path).get(KEY_CHECK_FIELD) is None

    replacement = generate_key()
    _save(store, replacement, smtp_password=NEW_SECRET)
    resolved = store.resolve(_settings(tmp_path, secret_key=replacement))
    assert resolved["smtp_password"].value == NEW_SECRET


def test_the_key_check_is_verified_once_per_store(tmp_path, monkeypatch):
    """Mutation: verifying per field turns one error into one per field."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)

    calls = {"n": 0}
    real = MailSettingsStore._decrypt_check

    def counted(self, token, key):
        calls["n"] += 1
        return real(self, token, key)

    monkeypatch.setattr(MailSettingsStore, "_decrypt_check", counted)
    store.resolve(_settings(tmp_path, secret_key=key))
    assert calls["n"] == 1
    store.resolve(_settings(tmp_path, secret_key=key))
    assert calls["n"] == 1, "the key check ran again on the second resolve"


# --- validation ------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "named"),
    [
        ("smtp_port", "70000", "smtp_port"),
        ("smtp_port", "0", "smtp_port"),
        ("smtp_port", "nope", "smtp_port"),
        ("smtp_host", "http://smtp.example.com", "smtp_host"),
        ("smtp_host", "smtp.example.com\r\nBcc: e@example.com", "smtp_host"),
        ("smtp_user", "owner@example.com\nRCPT TO:<e@example.com>", "smtp_user"),
        ("smtp_from", "owner@example.com\nBcc: e@example.com", "smtp_from"),
        ("smtp_from", "not-an-address", "smtp_from"),
        ("smtp_starttls", "maybe", "smtp_starttls"),
        ("smtp_ssl", "TRUEISH", "smtp_ssl"),
    ],
)
def test_a_bad_value_is_refused_before_it_is_written(tmp_path, field, value, named):
    """Mutation: writing the value anyway turns a typo into a transport."""
    key = generate_key()
    store = _store(tmp_path, key)

    with pytest.raises(MailValueError) as caught:
        store.save({field: value}, updated_by="owner", key=key)

    assert named in str(caught.value)
    # The refusal happens before the write session opens, so nothing is created.
    assert not store.path.exists()


def test_both_tls_modes_at_once_is_refused(tmp_path):
    key = generate_key()
    store = _store(tmp_path, key)
    with pytest.raises(MailValueError, match="cannot both be true"):
        store.save(
            {"smtp_ssl": "true", "smtp_starttls": "true"}, updated_by="owner", key=key
        )


def test_a_corrupt_stored_flag_is_refused_instead_of_guessed(tmp_path):
    """Mutation: a loose parse reads an unknown word as a TLS setting."""
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)
    conn = sqlite3.connect(store.path)
    with conn:
        conn.execute(
            "UPDATE instance_settings SET value = 'maybe' WHERE key = 'smtp_starttls'"
        )
    conn.close()

    with pytest.raises(ConfigError, match="smtp_starttls"):
        resolve_mail_settings(_settings(tmp_path, secret_key=key))


def test_a_password_is_stored_exactly_as_typed(tmp_path):
    """Validation must not strip or normalise the credential itself."""
    key = generate_key()
    store = _store(tmp_path, key)
    spaced = "  leading and trailing  "
    _save(store, key, smtp_password=spaced)
    assert store.resolve(_settings(tmp_path, secret_key=key))["smtp_password"].value == spaced


# --- one source ------------------------------------------------------------


def test_a_stored_password_never_borrows_the_environment_host(tmp_path):
    """The highest-severity pair: a stored secret and an unconfigured host."""
    key = generate_key()
    store = _store(tmp_path, key)
    store.save({"smtp_password": SECRET}, updated_by="owner", key=key)

    resolved = store.resolve(_settings(tmp_path, secret_key=key, smtp_host="env.example"))
    assert resolved.transport_source == SOURCE_DATABASE
    assert resolved["smtp_host"].value is None
    assert resolved["smtp_host"].source == SOURCE_UNCONFIGURED
    assert resolve_mail_settings(
        _settings(tmp_path, secret_key=key, smtp_host="env.example")
    ).smtp_host is None


def test_the_environment_port_is_not_mixed_into_a_stored_transport(tmp_path):
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET, smtp_port="2525")

    applied = resolve_mail_settings(_settings(tmp_path, secret_key=key, smtp_port=587))
    assert applied.smtp_port == 2525
    store.clear()
    applied_after = resolve_mail_settings(
        _settings(tmp_path, secret_key=key, smtp_host="env.example", smtp_port=587)
    )
    assert applied_after.smtp_port == 587
    assert applied_after.smtp_host == "env.example"


def test_the_hint_names_no_character_of_the_secret(tmp_path):
    key = generate_key()
    store = _store(tmp_path, key)
    _save(store, key, smtp_password=SECRET)
    hint = store.resolve(_settings(tmp_path, secret_key=key))["smtp_password"].hint
    assert hint == password_hint(SECRET) == "set, 21 characters"
    assert "9912" not in hint
