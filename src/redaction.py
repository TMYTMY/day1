"""Redaction for the text smtplib puts in an exception.

A mail server's refusal can quote the conversation that caused it, and that
conversation includes the credential: ``AUTH PLAIN`` is sent as base64 of
``b"\\0" + user + b"\\0" + password``, and some servers echo the line back. So
the plaintext is not the only form a password takes in log text, audit text or
a page — the base64 and ``AUTH PLAIN`` forms count too, with or without padding
and with either the standard or the URL-safe alphabet.

:func:`redact_mail_error` removes all of them from one string, and
:func:`redact_exception` does the same in place to an exception *without*
changing its type, so a caller that catches ``smtplib.SMTPAuthenticationError``
still does. Every path that could show a transport failure calls one of them:
the notifier's audit text and owner email, ``mail_setup --check``, the worker's
notification failure and the test-send page. This module holds no state and
opens nothing.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Mapping

REDACTED = "[redacted]"

# A run of characters that can only be base64. Used to find an encoded secret
# whose word boundaries we cannot predict, because we do not know how the
# server wrapped or quoted it.
_CANDIDATE = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")


def _encodings(secret: str, user: str | None) -> set[str]:
    """Every base64 form of a credential the AUTH exchange can put on the wire."""
    plain = secret.encode("utf-8")
    forms: list[bytes] = [plain]
    if user:
        who = user.encode("utf-8")
        # AUTH PLAIN is authzid NUL authcid NUL passwd; smtplib also sends the
        # "user:password" form for LOGIN after the server asks for each part.
        forms.append(b"\0" + who + b"\0" + plain)
        forms.append(who + b"\0" + who + b"\0" + plain)
        forms.append(who + b":" + plain)
    variants: set[str] = set()
    for blob in forms:
        standard = base64.b64encode(blob).decode("ascii")
        urlsafe = base64.urlsafe_b64encode(blob).decode("ascii")
        for text in (standard, urlsafe):
            variants.add(text)
            variants.add(text.rstrip("="))
            variants.add(text.replace("=", ""))
    # A long password can also appear as its own hex digest of bytes.
    variants.add(plain.hex())
    return {item for item in variants if len(item) >= 8}


def _decodes_to(token: str, needle: bytes) -> bool:
    """True when this base64-looking token decodes to bytes containing ``needle``."""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = decoder(padded.encode("ascii"))
        except (binascii.Error, ValueError, UnicodeEncodeError):
            continue
        if needle and needle in raw:
            return True
    return False


# Below this length, a blind decode scan would match ordinary long words by
# chance and shred the message. The exact encodings above still cover the
# AUTH forms, which are the shape a mail server actually echoes back.
_SCAN_FLOOR = 6



def redact_mail_error(
    text: str,
    *,
    password: str | None = None,
    user: str | None = None,
    extra: Iterable[str | None] = (),
) -> str:
    """Remove a credential from transport error text in every form it takes.

    ``password`` is the credential the send used; ``user`` lets the AUTH PLAIN
    and LOGIN forms be recognised; ``extra`` covers another value the caller
    holds (a password just typed into a form that has not been stored yet). An
    empty or missing secret redacts nothing: replacing ``""`` everywhere would
    destroy the message the operator needs.
    """
    if not text:
        return ""
    cleaned = str(text)
    secrets = [value for value in (password, *extra) if value]
    for secret in secrets:
        cleaned = cleaned.replace(secret, REDACTED)
    needles: set[str] = set()
    for secret in secrets:
        needles |= _encodings(secret, user)
    if not needles:
        return cleaned
    for needle in sorted(needles, key=len, reverse=True):
        cleaned = cleaned.replace(needle, REDACTED)
    if len(secrets[0]) < _SCAN_FLOOR:
        return cleaned
    # Anything left that decodes to the password: the server chose the wrapping.
    raw_secret = secrets[0].encode("utf-8")
    return _CANDIDATE.sub(
        lambda match: REDACTED if _decodes_to(match.group(0), raw_secret) else match.group(0),
        cleaned,
    )


def redact_exception(exc: BaseException, *, password: str | None = None, user: str | None = None) -> None:
    """Redact an exception's own text in place, keeping its class.

    ``smtplib`` errors carry the server reply in ``args``; rewriting ``args``
    leaves ``smtp_code`` and the class intact, so a caller that matches on
    either still can, and nothing downstream can print the raw reply by
    accident.
    """
    original = str(exc)
    cleaned = redact_mail_error(original, password=password, user=user)
    if cleaned == original:
        return
    try:
        exc.args = (cleaned,)
    except (AttributeError, TypeError):  # pragma: no cover - exotic exception types
        return


def redact_transport_error(
    exc: BaseException,
    *,
    sender: object | None = None,
) -> str:
    """The redacted text of a failure from ``sender`` (a mail transport, or None).

    The notifier and the worker hold a sender rather than a ``Settings``, and
    the password they must redact is the one that transport would present, so
    the sender is asked for it rather than guessed at.
    """
    return redact_mail_error(
        str(exc),
        password=getattr(sender, "password", None),
        user=getattr(sender, "user", None),
    )


def transport_secrets(sender: object | None) -> Mapping[str, str | None]:
    """The redaction arguments for one sender, for callers building their own text."""
    return {
        "password": getattr(sender, "password", None),
        "user": getattr(sender, "user", None),
    }
