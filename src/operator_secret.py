"""The instance operator secret: generated on the host, stored only as a hash.

The demo passwords in ``config/users.yaml`` are stand-ins for SSO and prove
nothing about who is at the keyboard. One of them used to open the Settings
pages, so a documented credential granted ``admin``: anybody on the LAN could
sign in as the owner, repoint the SMTP host, and have the stored mailbox
password presented to a server of their choosing.

The operator account therefore has no password at all. It signs in with a
secret generated on this machine, by a command on this machine:

    python -m src.operator_secret --init     # generate, print once, store a hash
    python -m src.operator_secret --status   # is a secret set, and when

``--init`` refuses to replace an existing secret unless ``--force`` is given,
so a rotation is a deliberate act. The secret proves shell access to the box,
which is the real trust boundary for an on-prem instance: whoever can read the
settings database and ``.env`` already owns the instance, so a credential that
lives only in the operator's head is a gain, not a barrier, against them.

Only a salted scrypt hash is stored (standard library, ``hashlib.scrypt``), in
a table of its own in the instance settings database (``SETTINGS_PATH``). The
plaintext is printed once and is not recoverable; a lost secret is rotated.
Writing a secret touches no mail setting, so rotating one cannot silently
disable delivery.

The same secret is asked for again when the pages change anything: signing in
proves who opened the session, and re-entering it proves the person at the
keyboard right now is the operator, not a colleague who found it unlocked.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.config import load_settings

# 32 bytes of urandom, url-safe, so the secret survives a copy/paste and is not
# something a person is tempted to shorten.
SECRET_BYTES = 32

# scrypt parameters. 2**14 blocks with r=8 needs 16 MiB and takes a fraction of
# a second: enough that a stolen hash is not a cheap offline search, cheap
# enough that an operator does not notice it at sign-in.
SALT_BYTES = 16
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
ALGORITHM = "scrypt"

# One row, by construction. A second secret beside the first would make "which
# one is current" a question the code has to answer.
_CREATE = """
CREATE TABLE IF NOT EXISTS operator_secret (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    algorithm TEXT NOT NULL,
    salt TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_secret() -> str:
    """A new operator secret. Printed once by ``--init`` and never stored."""
    return secrets.token_urlsafe(SECRET_BYTES)


def _derive(secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        secret.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )


def hash_secret(secret: str, *, salt: bytes | None = None) -> tuple[str, str]:
    """Return ``(salt_hex, hash_hex)`` for one secret. The secret is not stored."""
    seed = secrets.token_bytes(SALT_BYTES) if salt is None else salt
    return seed.hex(), _derive(secret, seed).hex()


def _connect(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def store_secret(path: Path, secret: str) -> None:
    """Replace the instance's operator secret with the hash of ``secret``.

    Raises :class:`ValueError` for an empty secret, and leaves the database
    untouched when it does: an empty secret would be a secret anybody knows.
    """
    if not secret:
        raise ValueError("The operator secret cannot be empty.")
    salt_hex, hash_hex = hash_secret(secret)
    conn = _connect(Path(path))
    try:
        with conn:
            conn.execute(_CREATE)
            conn.execute(
                """
                INSERT INTO operator_secret (id, algorithm, salt, hash, created_at)
                VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    algorithm = excluded.algorithm,
                    salt = excluded.salt,
                    hash = excluded.hash,
                    created_at = excluded.created_at
                """,
                (ALGORITHM, salt_hex, hash_hex, _stamp()),
            )
    finally:
        conn.close()


def _row(path: Path) -> sqlite3.Row | None:
    path = Path(path)
    if not path.exists():
        return None
    conn = _connect(path)
    try:
        with conn:
            conn.execute(_CREATE)
        return conn.execute("SELECT * FROM operator_secret WHERE id = 1").fetchone()
    finally:
        conn.close()


def has_secret(path: Path) -> bool:
    """True when this instance has an operator secret to check against."""
    return _row(path) is not None


def created_at(path: Path) -> str | None:
    row = _row(path)
    return None if row is None else str(row["created_at"])


def verify_secret(path: Path, candidate: str) -> bool:
    """True only when ``candidate`` is the instance's operator secret.

    An unset secret refuses every candidate. The comparison is constant time,
    and a missing row still pays for one derivation, so a caller cannot learn
    from the clock whether the instance has a secret but the answer no.
    """
    row = _row(path)
    if row is None:
        _derive(candidate or "", b"\x00" * SALT_BYTES)
        return False
    if not candidate:
        _derive("", bytes.fromhex(row["salt"]))
        return False
    if row["algorithm"] != ALGORITHM:
        return False
    derived = _derive(candidate, bytes.fromhex(row["salt"]))
    return hmac.compare_digest(derived.hex(), str(row["hash"]))


def main(argv: list[str] | None = None) -> int:
    """Generate or report the instance operator secret. Exit 0, 1 or 2."""
    parser = argparse.ArgumentParser(
        prog="python -m src.operator_secret",
        description=(
            "Generate the secret the instance operator signs in with, or report whether one is set."
        ),
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--init",
        action="store_true",
        help="generate a secret, print it once, and store only its salted hash",
    )
    action.add_argument(
        "--status",
        action="store_true",
        help="say whether this instance has an operator secret, and when it was made",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="with --init, replace an existing secret (rotation): the old one stops working",
    )
    args = parser.parse_args(argv)
    if args.force and not args.init:
        parser.error("--force only applies to --init")

    path = load_settings().settings_path
    if args.status:
        if not has_secret(path):
            print(f"operator secret: not set ({path})")
            return 0
        print(f"operator secret: set ({path}, created {created_at(path)})")
        return 0

    if has_secret(path) and not args.force:
        print(
            "refused: an operator secret is already set for this instance. "
            "Use --force to replace it; the current secret will stop working.",
            file=sys.stderr,
        )
        return 1

    secret = generate_secret()
    try:
        store_secret(path, secret)
    except (sqlite3.Error, OSError, ValueError) as exc:
        print(f"refused: the operator secret could not be stored: {exc}", file=sys.stderr)
        return 1

    print("Operator secret for this instance. It is printed once and is not recoverable.")
    print()
    print(f"    {secret}")
    print()
    print(
        "Sign in as the operator account with it, and re-enter it to save, test "
        "or clear mail settings. Only a salted scrypt hash is kept, in " f"{path}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
