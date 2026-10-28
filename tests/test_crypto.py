"""The cipher mail settings use. Round trip, a wrong key, a missing key."""

from __future__ import annotations

import pytest

from src.crypto import SecretKeyError, decrypt, encrypt, generate_key, require_key


def test_a_secret_round_trips_under_its_key():
    key = generate_key()
    token = encrypt("app-password", key)
    assert token != "app-password"
    assert "app-password" not in token
    assert decrypt(token, key, field="smtp_password") == "app-password"


def test_a_wrong_key_raises_and_does_not_return_garbage():
    token = encrypt("app-password", generate_key())
    with pytest.raises(SecretKeyError, match="smtp_password") as caught:
        decrypt(token, generate_key(), field="smtp_password")
    message = str(caught.value)
    assert "app-password" not in message
    assert "another source" in message


def test_a_corrupt_token_raises_rather_than_returning_it():
    with pytest.raises(SecretKeyError, match="smtp_password"):
        decrypt("not-a-token", generate_key(), field="smtp_password")


def test_a_missing_key_refuses_to_encrypt():
    with pytest.raises(SecretKeyError, match="DAY1_SECRET_KEY"):
        encrypt("app-password", None)
    with pytest.raises(SecretKeyError, match="DAY1_SECRET_KEY"):
        encrypt("app-password", "  ")
    with pytest.raises(SecretKeyError, match="not stored in the clear"):
        require_key(None)


def test_a_missing_key_refuses_to_decrypt_a_stored_field():
    token = encrypt("app-password", generate_key())
    with pytest.raises(SecretKeyError, match="smtp_password") as caught:
        decrypt(token, None, field="smtp_password")
    assert "app-password" not in str(caught.value)


def test_a_key_that_is_not_fernet_refuses_to_save():
    with pytest.raises(SecretKeyError, match="not a valid Fernet key"):
        require_key("not-a-fernet-key")
    with pytest.raises(SecretKeyError, match="smtp_password"):
        decrypt("gAAA", "not-a-fernet-key", field="smtp_password")


def test_the_key_check_error_is_a_secret_key_error():
    """Every caller that refuses a bad key refuses a key-check mismatch the same way."""
    from src.crypto import KeyCheckError

    assert issubclass(KeyCheckError, SecretKeyError)
    assert issubclass(KeyCheckError, Exception)
