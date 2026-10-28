"""Redaction of transport error text: plaintext, base64, and the AUTH PLAIN form.

A mail server's refusal can quote the line that authenticated, so a password
reaches a log in at least three shapes. Each test names one.
"""

from __future__ import annotations

import base64
import smtplib

import pytest

from src.redaction import REDACTED, redact_exception, redact_mail_error, redact_transport_error

PASSWORD = "day1-mail-secret-9912"
USER = "owner@example.com"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def test_the_plaintext_is_removed():
    """Mutation: returning the server's reply verbatim leaks the password."""
    text = f"535 5.7.8 authentication failed for {USER}: {PASSWORD}"
    cleaned = redact_mail_error(text, password=PASSWORD, user=USER)
    assert PASSWORD not in cleaned
    assert REDACTED in cleaned
    assert "535 5.7.8 authentication failed" in cleaned


def test_the_base64_password_is_removed():
    text = f"535 reply quoted: {_b64(PASSWORD.encode())}"
    cleaned = redact_mail_error(text, password=PASSWORD, user=USER)
    assert _b64(PASSWORD.encode()) not in cleaned
    assert REDACTED in cleaned


def test_the_unpadded_base64_password_is_removed():
    """Servers strip the padding. The same secret, one character fewer."""
    secret = "pw12345"  # seven bytes, so its base64 carries padding
    padded = _b64(secret.encode())
    unpadded = padded.rstrip("=")
    assert unpadded != padded
    cleaned = redact_mail_error(f"rejected: {unpadded}", password=secret, user=USER)
    assert unpadded not in cleaned


def test_the_url_safe_alphabet_is_removed():
    """A wrapper that uses - and _ instead of + and / is the same secret."""
    urlsafe = base64.urlsafe_b64encode(PASSWORD.encode()).decode("ascii")
    cleaned = redact_mail_error(f"rejected: {urlsafe}", password=PASSWORD, user=USER)
    assert urlsafe not in cleaned
    assert REDACTED in cleaned


def test_the_auth_plain_form_is_removed():
    """AUTH PLAIN is base64 of NUL + user + NUL + password, and it gets echoed."""
    token = _b64(b"\0" + USER.encode() + b"\0" + PASSWORD.encode())
    cleaned = redact_mail_error(
        f"535 5.7.8 AUTH PLAIN {token} rejected", password=PASSWORD, user=USER
    )
    assert token not in cleaned
    assert "AUTH PLAIN" in cleaned
    assert REDACTED in cleaned


def test_the_login_form_is_removed():
    token = _b64(USER.encode() + b":" + PASSWORD.encode())
    cleaned = redact_mail_error(f"bad credentials {token}", password=PASSWORD, user=USER)
    assert token not in cleaned


def test_a_wrapping_the_helper_did_not_predict_is_found_by_decoding():
    """The server chooses the wrapping: anything that decodes to the secret goes."""
    token = _b64(b"prefix:" + PASSWORD.encode() + b":suffix")
    cleaned = redact_mail_error(f"535 <{token}>", password=PASSWORD, user=USER)
    assert token not in cleaned
    assert REDACTED in cleaned


def test_text_without_the_secret_is_unchanged():
    text = "Connection refused: nothing is listening on port 587"
    assert redact_mail_error(text, password=PASSWORD, user=USER) == text
    assert redact_mail_error(text) == text
    assert redact_mail_error("") == ""


def test_an_empty_password_redacts_nothing():
    """Replacing "" everywhere would destroy the message an operator needs."""
    text = "535 authentication failed"
    assert redact_mail_error(text, password="", user=USER) == text
    assert redact_mail_error(text, password=None) == text


def test_a_short_password_still_loses_its_auth_line():
    token = _b64(b"\0" + USER.encode() + b"\0" + b"pw")
    cleaned = redact_mail_error(f"AUTH PLAIN {token}", password="pw", user=USER)
    assert token not in cleaned
    # Ordinary words survive: the blind scan is not applied to short secrets.
    assert redact_mail_error("authentication failed", password="pw") == "authentication failed"


def test_redacting_an_exception_keeps_its_class_and_its_code():
    token = _b64(b"\0" + USER.encode() + b"\0" + PASSWORD.encode())
    exc = smtplib.SMTPAuthenticationError(535, f"AUTH PLAIN {token}".encode())
    assert token in str(exc)

    redact_exception(exc, password=PASSWORD, user=USER)

    assert isinstance(exc, smtplib.SMTPAuthenticationError)
    assert exc.smtp_code == 535
    assert token not in str(exc)
    assert PASSWORD not in str(exc)
    assert REDACTED in str(exc)


def test_an_exception_with_nothing_to_redact_is_left_alone():
    exc = OSError("connection refused")
    redact_exception(exc, password=PASSWORD, user=USER)
    assert str(exc) == "connection refused"
    assert exc.args == ("connection refused",)


def test_a_sender_carries_the_secret_the_text_is_redacted_with():
    class Sender:
        password = PASSWORD
        user = USER

    cleaned = redact_transport_error(
        OSError(f"535 AUTH PLAIN {_b64(b'\0' + USER.encode() + b'\0' + PASSWORD.encode())}"),
        sender=Sender(),
    )
    assert PASSWORD not in cleaned
    assert REDACTED in cleaned


def test_no_sender_still_redacts_what_it_can():
    text = "535 authentication failed"
    assert redact_transport_error(OSError(text), sender=None) == text


@pytest.mark.parametrize("secret", [PASSWORD, "app-password", "x" * 40])
def test_a_secret_never_survives_any_shape(secret):
    token = _b64(b"\0" + USER.encode() + b"\0" + secret.encode())
    text = f"535 {secret} {token} {_b64(secret.encode())}"
    cleaned = redact_mail_error(text, password=secret, user=USER)
    assert secret not in cleaned
    assert token not in cleaned
