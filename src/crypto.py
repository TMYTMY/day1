"""Fernet encryption for secrets the instance stores.

The key is ``DAY1_SECRET_KEY``, a url-safe base64 32-byte Fernet key that lives
in the environment, never in the settings database. Fernet is AES-128-CBC with
an HMAC-SHA256 tag: a wrong key or a corrupt token fails the check instead of
coming back as plaintext that was never stored.

This module does not decide where a secret is kept. It only encrypts and
decrypts. A missing key refuses to encrypt. A key that cannot decrypt a stored
value raises :class:`SecretKeyError` naming the field; callers must not treat
that as an empty secret and read the value from somewhere else.

The settings database also stores one **key-check** value: a fixed string
encrypted under the same key. It exists so a wrong or rotated key is found once,
by name, before any field is read, instead of surfacing as one decryption error
per field and leaving a mixed-key store possible.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

# The plaintext of the key-check value. Fixed, non-secret, and versioned: a
# future format can change it and old rows will then read as "a different
# key", which is the honest answer for a row this build cannot verify.
KEY_CHECK_PLAINTEXT = "day1 instance settings key check v1"


class SecretKeyError(Exception):
    """The encryption key is missing, invalid, or cannot decrypt a field."""


class KeyCheckError(SecretKeyError):
    """The key does not reproduce the key-check value stored beside the secrets.

    Raised by the settings store, which owns the stored row. It is a
    :class:`SecretKeyError` because every caller that already refuses a bad key
    refuses this one the same way: loudly, naming the field, and without
    reading the value from anywhere else.
    """


def generate_key() -> str:
    """A new Fernet key, as the text ``DAY1_SECRET_KEY`` stores."""
    return Fernet.generate_key().decode("ascii")


def require_key(key: str | None) -> str:
    """Return the key, or refuse when it is missing or not a Fernet key.

    Saving mail settings calls this before any write, so an instance with no
    key never falls through to a plaintext file.
    """
    if key is None or not str(key).strip():
        raise SecretKeyError(
            "DAY1_SECRET_KEY is not set, so mail settings cannot be saved. "
            "Create one with: python -m src.mail_setup --init-key. "
            "A password is not stored in the clear."
        )
    cleaned = str(key).strip()
    try:
        Fernet(cleaned.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise SecretKeyError(
            "DAY1_SECRET_KEY is not a valid Fernet key, so mail settings cannot be saved. "
            "A password is not stored in the clear."
        ) from exc
    return cleaned


def encrypt(plaintext: str, key: str | None) -> str:
    """Encrypt one string. The token does not contain the plaintext."""
    fernet = Fernet(require_key(key).encode("ascii"))
    token = fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
    if plaintext and plaintext in token:
        raise SecretKeyError("Refusing to store a secret that is visible in its ciphertext.")
    return token


def decrypt(token: str, key: str | None, *, field: str) -> str:
    """Decrypt one stored field, or raise naming that field.

    A missing key, a key in the wrong format, and a key that fails the
    authentication tag all raise. None of them return a best-effort string.
    """
    if key is None or not str(key).strip():
        raise SecretKeyError(
            f"Could not decrypt {field}: DAY1_SECRET_KEY is not set. "
            "The stored value will not be read from another source."
        )
    cleaned = str(key).strip()
    try:
        fernet = Fernet(cleaned.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise SecretKeyError(
            f"Could not decrypt {field}: DAY1_SECRET_KEY is not a valid Fernet key. "
            "The stored value will not be read from another source."
        ) from exc
    try:
        return fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise SecretKeyError(
            f"Could not decrypt {field}: DAY1_SECRET_KEY does not match the key "
            "that stored it, or the ciphertext is corrupt. "
            "The stored value will not be read from another source."
        ) from exc
