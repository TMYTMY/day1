"""One SQLite connection, stored in the instance settings database.

vA has no Postgres form and no database password. The path is not a secret,
so it is not encrypted: Fernet stays on the mail settings that actually hold
a credential. The row lives in the same settings file (``Settings.settings_path``)
as those mail settings.

The environment (``DB_BACKEND`` / ``DB_PATH``) remains the warehouse until an
operator enables this row. Disabling it, or a path that no longer passes the
policy, falls back to that environment. A UI-selected file is never seeded
and never rebuilt.

Connection Test refuses non-SQLite URL schemes, link-local addresses, and
metadata hosts before it opens anything, and the open itself is capped by a
hard timeout. Error text is a fixed sentence. The submitted string is not
copied into the message, the audit row, or the database when the policy
rejects it, so a URL that carried a password is not stored.

Rollback: leave the ``connections`` table in place. Older code does not read
it, and the environment database is the warehouse again.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

from src.config import Settings

# Wall clock for one Test, including the open. Not SQLite's busy timeout.
HARD_TIMEOUT_SECONDS = 3.0

CONNECTION_ID = "sqlite"
BACKEND = "sqlite"

_ALLOWED_SCHEMES = frozenset({"sqlite", "file"})
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")

# Hostnames that point at cloud instance metadata, whatever the scheme is.
_METADATA_NAMES = frozenset(
    {
        "metadata",
        "metadata.internal",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
_METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)

_CREATE = """
CREATE TABLE IF NOT EXISTS connections (
    id TEXT PRIMARY KEY,
    backend TEXT NOT NULL,
    path TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    last_test_at TEXT,
    last_test_ok INTEGER,
    last_error_class TEXT,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
)
"""


class ConnectionPolicyError(Exception):
    """A target Test will not open. ``error_class`` is the stable token."""

    def __init__(self, error_class: str, message: str):
        self.error_class = error_class
        super().__init__(message)


@dataclass(frozen=True)
class ConnectionVerdict:
    """The outcome of one Test. ``path`` is set only when the test succeeded."""

    ok: bool
    error_class: str
    message: str
    path: Path | None = None


@dataclass(frozen=True)
class Connection:
    id: str
    backend: str
    path: str
    enabled: bool
    last_test_at: str | None
    last_test_ok: bool | None
    last_error_class: str | None
    updated_at: str
    updated_by: str


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _message(error_class: str) -> str:
    if error_class == "metadata":
        return "Metadata hosts are refused."
    if error_class == "link_local":
        return "Link-local addresses are refused."
    if error_class == "scheme":
        return "Only a local SQLite file path is accepted."
    if error_class == "remote_host":
        return "Only a local SQLite file is accepted."
    if error_class == "timeout":
        return "The connection test timed out."
    if error_class == "not_found":
        return "That SQLite file does not exist."
    if error_class == "not_sqlite":
        return "That file is not a SQLite database."
    if error_class == "not_tested":
        return "Enable is available after a successful test of this file."
    return "Enter a SQLite file path."


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    token = host.strip().strip("[]")
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        pass
    if re.fullmatch(r"\d{1,10}", token):
        try:
            return ipaddress.ip_address(int(token))
        except ValueError:
            return None
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", token):
        try:
            return ipaddress.ip_address(int(token, 16))
        except ValueError:
            return None
    return None


def _host_class(host: str) -> str:
    """``metadata``, ``link_local``, ``loopback``, or ``remote``."""
    name = host.strip().strip("[]").rstrip(".").lower()
    if name in _METADATA_NAMES or name.endswith(".metadata.google.internal"):
        return "metadata"
    parsed = _ip(name)
    if parsed is not None:
        if parsed in _METADATA_IPS:
            return "metadata"
        if parsed.is_link_local:
            return "link_local"
        if parsed.is_loopback:
            return "loopback"
        return "remote"
    if name == "localhost":
        return "loopback"
    return "remote"


def _scheme_of(text: str) -> str | None:
    if _WINDOWS_PATH.match(text):
        return None
    matched = _SCHEME.match(text)
    if matched is None:
        return None
    # ``C:\...`` is already excluded. A single letter before a colon with no
    # slashes is still a scheme (``postgres:name``), which vA refuses.
    return matched.group(1).lower()


def _as_url(text: str, scheme: str | None) -> str | None:
    """The URL form of ``text``, or None when it is a plain filesystem path."""
    if text.startswith("\\\\") or text.startswith("//"):
        return text.replace("\\", "/")
    if scheme is None and "://" not in text:
        return None
    if scheme == "file" and text.startswith("file:") and not text.startswith("file://"):
        return "file://" + text[len("file:") :]
    return text


def _parsed_host(text: str, scheme: str | None) -> tuple[str | None, bool]:
    """Hostname, and whether the URL carried a username or password.

    A plain path returns ``(None, False)``. The password is not returned.
    """
    candidate = _as_url(text, scheme)
    if candidate is None:
        return None, False
    parsed = urlparse(candidate)
    return parsed.hostname, bool(parsed.username or parsed.password)


def _local_path(text: str, scheme: str | None) -> Path:
    candidate = _as_url(text, scheme)
    if candidate is None:
        return Path(text)
    parsed = urlparse(candidate)
    raw_path = parsed.path or ""
    if not raw_path:
        raise ConnectionPolicyError("invalid", _message("invalid"))
    return Path(raw_path)


def inspect_sqlite_target(raw: str) -> Path:
    """The local file ``raw`` names, or a policy error that does not echo ``raw``.

    This does not open the file. Callers that open it must use
    :func:`check_sqlite_target`, which applies the timeout.
    """
    text = (raw or "").strip()
    if not text or len(text) > 4096 or _CONTROL.search(text):
        raise ConnectionPolicyError("invalid", _message("invalid"))
    scheme = _scheme_of(text)
    try:
        host, has_secret = _parsed_host(text, scheme)
    except ValueError:
        raise ConnectionPolicyError("invalid", _message("invalid")) from None
    if host:
        kind = _host_class(host)
        if kind == "metadata":
            raise ConnectionPolicyError("metadata", _message("metadata"))
        if kind == "link_local":
            raise ConnectionPolicyError("link_local", _message("link_local"))
    if has_secret or (scheme is not None and scheme not in _ALLOWED_SCHEMES):
        raise ConnectionPolicyError("scheme", _message("scheme"))
    if host and _host_class(host) != "loopback":
        raise ConnectionPolicyError("remote_host", _message("remote_host"))
    if scheme is None and (text.startswith("//") or text.startswith("\\\\")):
        raise ConnectionPolicyError("remote_host", _message("remote_host"))
    try:
        path = _local_path(text, scheme)
    except ConnectionPolicyError:
        raise
    except (OSError, ValueError):
        raise ConnectionPolicyError("invalid", _message("invalid")) from None
    if not str(path):
        raise ConnectionPolicyError("invalid", _message("invalid"))
    try:
        return path.expanduser().resolve()
    except OSError:
        raise ConnectionPolicyError("invalid", _message("invalid")) from None


def probe_sqlite(path: Path) -> None:
    """Open ``path`` read-only and read one value. Does not create the file."""
    if not path.is_file():
        raise ConnectionPolicyError("not_found", _message("not_found"))
    with path.open("rb") as handle:
        header = handle.read(16)
    if header != b"SQLite format 3\x00":
        raise ConnectionPolicyError("not_sqlite", _message("not_sqlite"))
    quoted = quote(path.resolve().as_posix(), safe="/")
    uri = f"file:{quoted}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=1)
    except sqlite3.Error as exc:
        raise ConnectionPolicyError("not_sqlite", _message("not_sqlite")) from exc
    try:
        try:
            conn.execute("PRAGMA query_only = ON")
            conn.execute("SELECT 1").fetchone()
        except sqlite3.Error as exc:
            raise ConnectionPolicyError("not_sqlite", _message("not_sqlite")) from exc
    finally:
        conn.close()


def check_sqlite_target(
    raw: str,
    *,
    timeout_seconds: float = HARD_TIMEOUT_SECONDS,
    probe: Callable[[Path], None] | None = None,
) -> ConnectionVerdict:
    """Policy, then a read-only open capped by ``timeout_seconds``.

    ``probe`` replaces the open in tests so a hang can be proved without
    waiting on a real filesystem call. The submitted string is not part of
    the verdict.
    """
    try:
        path = inspect_sqlite_target(raw)
    except ConnectionPolicyError as exc:
        return ConnectionVerdict(False, exc.error_class, str(exc))
    opener = probe or probe_sqlite
    outcome: dict[str, object] = {}

    def run() -> None:
        try:
            opener(path)
        except ConnectionPolicyError as exc:
            outcome["error"] = exc
        except Exception:
            outcome["error"] = ConnectionPolicyError("not_sqlite", _message("not_sqlite"))
        else:
            outcome["ok"] = True

    worker = threading.Thread(target=run, name="day1-connection-test", daemon=True)
    worker.start()
    worker.join(max(0.0, float(timeout_seconds)))
    if worker.is_alive():
        return ConnectionVerdict(False, "timeout", _message("timeout"))
    if outcome.get("ok"):
        return ConnectionVerdict(True, "", "Connection test succeeded.", path)
    error = outcome.get("error")
    if isinstance(error, ConnectionPolicyError):
        return ConnectionVerdict(False, error.error_class, str(error))
    return ConnectionVerdict(False, "not_sqlite", _message("not_sqlite"))


class ConnectionStore:
    """The single SQLite connection row in one instance's settings database."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as conn:
            conn.execute(_CREATE)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @contextmanager
    def _session(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def get(self) -> Connection | None:
        with self._session() as conn:
            row = conn.execute(
                "SELECT * FROM connections WHERE id = ?",
                (CONNECTION_ID,),
            ).fetchone()
        if row is None:
            return None
        return _connection(row)

    def enabled(self) -> Connection | None:
        row = self.get()
        if row is None or not row.enabled or row.backend != BACKEND:
            return None
        return row

    def record_success(self, path: Path, *, actor: str) -> Connection:
        """Remember a path that just passed Test. Enabling is a separate step.

        A different path is stored disabled, so a test cannot silently repoint
        a connection that was already on.
        """
        checked = inspect_sqlite_target(str(path))
        now = _stamp()
        current = self.get()
        enabled = 0
        if current is not None and current.enabled and Path(current.path) == checked:
            enabled = 1
        with self._session() as conn:
            conn.execute(
                """
                INSERT INTO connections (
                    id, backend, path, enabled, last_test_at, last_test_ok,
                    last_error_class, updated_at, updated_by
                ) VALUES (?, ?, ?, ?, ?, 1, '', ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    backend = excluded.backend,
                    path = excluded.path,
                    enabled = excluded.enabled,
                    last_test_at = excluded.last_test_at,
                    last_test_ok = 1,
                    last_error_class = '',
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (CONNECTION_ID, BACKEND, str(checked), enabled, now, now, actor),
            )
        stored = self.get()
        if stored is None:
            raise ConnectionPolicyError("invalid", _message("invalid"))
        return stored

    def record_failure(self, error_class: str, *, actor: str) -> None:
        """Record the class of a failed test. The rejected string is not written."""
        current = self.get()
        if current is None:
            return
        now = _stamp()
        with self._session() as conn:
            conn.execute(
                """
                UPDATE connections
                SET last_test_at = ?, last_test_ok = 0, last_error_class = ?,
                    updated_at = ?, updated_by = ?
                WHERE id = ?
                """,
                (now, error_class[:64], now, actor, CONNECTION_ID),
            )

    def set_enabled(self, enabled: bool, *, actor: str) -> Connection:
        current = self.get()
        if current is None:
            raise ConnectionPolicyError("not_tested", _message("not_tested"))
        if enabled:
            if not current.last_test_ok:
                raise ConnectionPolicyError("not_tested", _message("not_tested"))
            inspect_sqlite_target(current.path)
        now = _stamp()
        with self._session() as conn:
            conn.execute(
                """
                UPDATE connections
                SET enabled = ?, updated_at = ?, updated_by = ?
                WHERE id = ?
                """,
                (int(enabled), now, actor, CONNECTION_ID),
            )
        stored = self.get()
        if stored is None:
            raise ConnectionPolicyError("invalid", _message("invalid"))
        return stored


def _connection(row: sqlite3.Row) -> Connection:
    ok = row["last_test_ok"]
    return Connection(
        id=row["id"],
        backend=row["backend"],
        path=row["path"],
        enabled=bool(row["enabled"]),
        last_test_at=row["last_test_at"],
        last_test_ok=None if ok is None else bool(ok),
        last_error_class=row["last_error_class"] or None,
        updated_at=row["updated_at"],
        updated_by=row["updated_by"],
    )


def apply_enabled_connection(settings: Settings) -> Settings:
    """Use the enabled UI connection when it still passes policy.

    Otherwise return ``settings`` unchanged, which is the environment.
    The database password and URL are dropped from the copy that uses the
    file, because that connection has no credential.
    """
    try:
        row = ConnectionStore(settings.settings_path).enabled()
    except sqlite3.Error:
        return settings
    if row is None:
        return settings
    try:
        path = inspect_sqlite_target(row.path)
    except ConnectionPolicyError:
        return settings
    return replace(
        settings,
        db_backend=BACKEND,
        db_path=path,
        database_url=None,
        db_user=None,
        db_password=None,
    )


def ui_sqlite_selected(original: Settings, effective: Settings) -> bool:
    """True when ``effective`` is a different SQLite file from the environment."""
    if effective.db_backend != BACKEND:
        return False
    try:
        return effective.db_path.resolve() != Path(original.db_path).resolve()
    except OSError:
        return False
