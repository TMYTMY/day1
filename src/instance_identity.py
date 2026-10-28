"""Which instance a settings database belongs to, and whether this process is it.

A copy of an instance directory plus its ``.env`` becomes a second sender with
the same credentials, the same recipients and the same real thresholds. Nothing
about a mail password is wrong there — it is the *same* instance as far as the
provider can tell — so the defence has to be that the copy is not the instance
that was configured:

At first configuration the instance writes an identity row into its settings
database: a UUID generated once, the hostname it was configured on, and the
path of the database itself. Three facts, none of them a secret, all readable
without the Fernet key, so an operator can inspect them with ``sqlite3``.

A delivery attempt from a process whose hostname, path or id does not match
that row is refused, with a reason that names the recorded host and the running
host. The refusal is the point: an instance that has been moved or copied must
not become a second sender by accident. A move that *is* intended is one
explicit decision — ``--confirm-instance-move`` on the worker, or
``DAY1_CONFIRM_INSTANCE_MOVE=1`` — after which the row is re-bound to the new
host and path and the move is audited.

Why the path and not just the hostname: the copy this exists to stop is
usually made on the same machine, a directory duplicated beside the original.
The hostname is identical there; only the path is not.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_STAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS instance_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    instance_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    instance_path TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
)
"""


def _stamp(moment: datetime | None = None) -> str:
    return (moment or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime(
        _STAMP_FORMAT
    )


def running_hostname(override: str | None = None) -> str:
    """The name this process reports as its host.

    ``DAY1_INSTANCE_HOSTNAME`` wins when it is set: a container whose hostname
    is a fresh random id on every start would otherwise look like a moved
    instance, and an operator, not the kernel, should decide what this host is
    called.
    """
    chosen = (override or "").strip()
    if chosen:
        return chosen
    try:
        found = socket.gethostname().strip()
    except OSError:  # pragma: no cover - a host with no name at all
        found = ""
    return found or "unknown-host"


def _normalise(path: Path | str | None) -> str:
    """One instance path, as an absolute string, so two spellings compare equal."""
    if path is None:
        return ""
    try:
        return str(Path(path).resolve())
    except OSError:  # pragma: no cover - an unreadable parent
        return str(Path(path).absolute())


@dataclass(frozen=True)
class InstanceIdentity:
    """Who this instance is: one generated id, one host, one path."""

    instance_id: str
    hostname: str
    path: str
    recorded_at: str
    updated_at: str

    @property
    def complete(self) -> bool:
        """True when every fact is present. An incomplete identity cannot be checked."""
        return bool(self.instance_id and self.hostname and self.path)


@dataclass(frozen=True)
class IdentityCheck:
    """The answer to "may this process deliver as that instance?".

    ``adopted`` is true when the operator confirmed a move and the stored
    identity now names this host and path. ``previous`` is the identity as it
    stood before that, so the audit row can name both.
    """

    identity: InstanceIdentity | None
    running_host: str
    running_path: str
    adopted: bool = False
    previous: InstanceIdentity | None = None

    @property
    def recorded(self) -> bool:
        """True when an identity has been written. An unconfigured instance has none."""
        return self.identity is not None

    @property
    def hostname_moved(self) -> bool:
        return self.identity is not None and self.identity.hostname != self.running_host

    @property
    def path_moved(self) -> bool:
        return (
            self.identity is not None
            and bool(self.identity.path)
            and self.identity.path != self.running_path
        )

    @property
    def id_missing(self) -> bool:
        return self.identity is not None and not self.identity.instance_id

    @property
    def refused(self) -> bool:
        """True when this process must not deliver, and nothing was sent.

        An instance with no identity is not refused: it has never been
        configured to send anything, so it cannot be a second sender of one.
        """
        if self.identity is None or self.adopted:
            return False
        return self.id_missing or self.hostname_moved or self.path_moved

    @property
    def reason(self) -> str | None:
        """The refusal, naming both the recorded and the running host."""
        if not self.refused or self.identity is None:
            return None
        changes: list[str] = []
        if self.id_missing:
            changes.append("its recorded instance id is empty")
        if self.hostname_moved:
            changes.append(
                f"it was configured on host {self.identity.hostname!r} and this process "
                f"runs on host {self.running_host!r}"
            )
        if self.path_moved:
            changes.append(
                f"it was configured at {self.identity.path!r} and this process opened "
                f"{self.running_path!r}"
            )
        instance = self.identity.instance_id or "missing"
        return (
            "this instance may not deliver a notification: "
            + "; ".join(changes)
            + f" (instance id {instance}). Nothing was sent. If the instance was moved "
            "on purpose, confirm the move with --confirm-instance-move (or "
            "DAY1_CONFIRM_INSTANCE_MOVE=1) to record it and deliver from here."
        )

    @property
    def moved_reason(self) -> str | None:
        """The audit text for a confirmed move, naming where it came from."""
        if not self.adopted or self.previous is None:
            return None
        return (
            f"instance {self.previous.instance_id or 'missing'} was confirmed moved: "
            f"configured on host {self.previous.hostname!r} at {self.previous.path!r}, "
            f"now running on host {self.running_host!r} at {self.running_path!r}"
        )


class IdentityStore:
    """The identity row in one instance's settings database. No key, no encryption."""

    def __init__(self, path: Path):
        self.path = Path(path)

    # -- opening ------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
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

    # -- reading ------------------------------------------------------------

    def read(self) -> InstanceIdentity | None:
        """The recorded identity, or None. Writes nothing, and never needs the key."""
        if not self.path.exists():
            return None
        try:
            conn = sqlite3.connect(
                f"{self.path.resolve().as_uri()}?mode=ro", uri=True, timeout=5
            )
        except sqlite3.Error:  # pragma: no cover - an unreadable file records nothing
            return None
        conn.row_factory = sqlite3.Row
        try:
            found = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'instance_identity'"
            ).fetchone()
            if found is None:
                return None
            row = conn.execute("SELECT * FROM instance_identity WHERE id = 1").fetchone()
        except sqlite3.Error:  # pragma: no cover - a corrupt file records nothing
            return None
        finally:
            conn.close()
        return None if row is None else _identity(row)

    # -- writing ------------------------------------------------------------

    def ensure(
        self,
        *,
        hostname: str,
        running_path: Path | str | None = None,
        by: str = "instance",
    ) -> InstanceIdentity:
        """Pin this instance if it is not pinned yet, and return what is stored.

        Called at first configuration. An identity that already exists is
        returned untouched: re-pointing it on every save would make the record
        describe the last writer instead of the instance, and the copy this
        exists to refuse would quietly adopt itself.
        """
        existing = self.read()
        if existing is not None:
            return existing
        instance_id = str(uuid.uuid4())
        stamp = _stamp()
        target = _normalise(running_path if running_path is not None else self.path)
        with self._session() as conn:
            conn.execute(_CREATE_TABLE)
            # Two processes configuring at once: one row, one id, and the
            # loser reads the winner's row back rather than overwriting it.
            conn.execute(
                """
                INSERT OR IGNORE INTO instance_identity (
                    id, instance_id, hostname, instance_path, recorded_at, updated_at, updated_by
                ) VALUES (1, ?, ?, ?, ?, ?, ?)
                """,
                (instance_id, hostname, target, stamp, stamp, by),
            )
        stored = self.read()
        if stored is None:  # pragma: no cover - the insert above always lands
            raise sqlite3.Error(f"Could not record the instance identity in {self.path}.")
        return stored

    def rebind(
        self,
        *,
        hostname: str,
        running_path: Path | str | None = None,
        by: str = "operator",
    ) -> InstanceIdentity:
        """Record a confirmed move: same instance id, new host and path.

        Only an explicit operator confirmation reaches this method. The id is
        kept, because a moved instance is still the same instance — its fire
        keys, its audit trail and its alert definitions belong to it.
        """
        target = _normalise(running_path if running_path is not None else self.path)
        with self._session() as conn:
            conn.execute(_CREATE_TABLE)
            updated = conn.execute(
                """
                UPDATE instance_identity
                SET hostname = ?, instance_path = ?, updated_at = ?, updated_by = ?
                WHERE id = 1
                """,
                (hostname, target, _stamp(), by),
            ).rowcount
        if not updated:
            return self.ensure(hostname=hostname, running_path=target, by=by)
        stored = self.read()
        if stored is None:  # pragma: no cover - the update above always lands
            raise sqlite3.Error(f"Could not read the instance identity in {self.path}.")
        return stored

    # -- the question -------------------------------------------------------

    def check(
        self,
        *,
        hostname: str,
        running_path: Path | str | None = None,
        confirm: bool = False,
    ) -> IdentityCheck:
        """Decide whether this process may deliver as the recorded instance.

        ``confirm`` is the operator saying "yes, I moved it". It re-binds the
        stored identity to this host and path, and only a call that carries it
        can change the record — which is why the flag is not something the
        worker infers from a failing check.
        """
        running = _normalise(running_path if running_path is not None else self.path)
        identity = self.read()
        if identity is None:
            return IdentityCheck(identity=None, running_host=hostname, running_path=running)
        current = IdentityCheck(
            identity=identity, running_host=hostname, running_path=running
        )
        if not current.refused or not confirm:
            return current
        adopted = self.rebind(hostname=hostname, running_path=running, by="operator")
        return IdentityCheck(
            identity=adopted,
            running_host=hostname,
            running_path=running,
            adopted=True,
            previous=identity,
        )


def _identity(row: sqlite3.Row) -> InstanceIdentity:
    return InstanceIdentity(
        instance_id=str(row["instance_id"] or ""),
        hostname=str(row["hostname"] or ""),
        path=str(row["instance_path"] or ""),
        recorded_at=str(row["recorded_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
    )


def record_instance_identity(
    settings_path: Path | str,
    *,
    hostname: str | None = None,
    running_path: Path | str | None = None,
    by: str = "settings",
) -> InstanceIdentity:
    """Pin the instance at first configuration. A no-op once it is pinned.

    Called by the mail settings store when mail is saved and by the worker when
    it is about to deliver for the first time, so a headless ``.env`` install is
    pinned too — that is exactly the instance a copied directory takes with it.

    ``DAY1_INSTANCE_HOSTNAME`` is honoured here as well as in a ``Settings``
    object: a page that saves mail settings does not carry the settings, and a
    pin taken from the kernel while the worker checks the configured name would
    refuse its own instance on the next send.
    """
    return IdentityStore(Path(settings_path)).ensure(
        hostname=running_hostname(hostname or os.environ.get("DAY1_INSTANCE_HOSTNAME")),
        running_path=running_path if running_path is not None else settings_path,
        by=by,
    )
