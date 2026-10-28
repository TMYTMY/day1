"""Encrypted mail settings for one instance, and the order they resolve in.

The page, the worker and the notifier all read mail through this store, so
they cannot disagree about which transport is in use. A value stored in the
instance settings database wins. Otherwise the value comes from the environment
(``.env`` / ``SMTP_*``). Otherwise it is unconfigured.

Secrets are ciphertext plus a non-secret hint (the last four characters, or
``set`` when the secret is shorter than that). The password itself is never
written into the database, the hint, or an error message. A ciphertext that
cannot be decrypted under ``DAY1_SECRET_KEY`` is a configuration error naming
the field: that field is not filled from ``.env`` instead.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.config import DEFAULT_SMTP_FROM, ConfigError, Settings
from src.crypto import SecretKeyError, decrypt, encrypt, require_key

# The mail keys this store owns. Anything else is refused, so a caller cannot
# turn the table into a general-purpose bag of secrets by accident.
MAIL_FIELD_NAMES = (
    "smtp_provider",
    "smtp_host",
    "smtp_port",
    "smtp_user",
    "smtp_password",
    "smtp_from",
    "smtp_starttls",
    "smtp_ssl",
)
SECRET_FIELDS = frozenset({"smtp_password"})

SOURCE_DATABASE = "database"
SOURCE_ENV = ".env"
SOURCE_UNCONFIGURED = "unconfigured"

_CREATE = """
CREATE TABLE IF NOT EXISTS instance_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    secret INTEGER NOT NULL,
    hint TEXT,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
)
"""


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def password_hint(password: str) -> str:
    """A non-secret reminder that a password is stored.

    Four characters is a hint. Anything shorter would be the whole secret, so
    the hint is the word ``set`` instead.
    """
    if len(password) >= 4:
        return password[-4:]
    return "set"


def _as_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


@dataclass(frozen=True)
class MailField:
    """One resolved mail setting, and where it came from.

    ``value`` is the effective value. For a secret it is the decrypted
    password, which callers that render a page must not display: use
    :attr:`display`. ``source`` is ``database``, ``.env``, or ``unconfigured``.
    ``error`` is set when a stored ciphertext cannot be decrypted; ``value`` is
    then empty and was not taken from another source.
    """

    name: str
    value: str | None
    source: str
    hint: str | None = None
    secret: bool = False
    error: str | None = None

    @property
    def display(self) -> str:
        """What a page may show. A secret contributes only its hint."""
        if self.secret:
            return self.hint or ""
        return self.value or ""


@dataclass(frozen=True)
class ResolvedMail:
    """Every mail field, already resolved. The page reads this; delivery applies it."""

    fields: Mapping[str, MailField]

    def __getitem__(self, name: str) -> MailField:
        return self.fields[name]

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(field.error for field in self.fields.values() if field.error)

    def apply(self, settings: Settings) -> Settings:
        """A ``Settings`` whose SMTP fields are these resolved values.

        Raises when a stored secret cannot be decrypted, or a stored port is
        not a port. It does not fill a failed field from ``settings``.
        """
        if self.errors:
            raise SecretKeyError(self.errors[0])
        host = self["smtp_host"].value or None
        user = self["smtp_user"].value or None
        password = self["smtp_password"].value or None
        sender = self["smtp_from"].value or settings.smtp_from or DEFAULT_SMTP_FROM
        port_text = self["smtp_port"].value
        if port_text:
            try:
                port = int(port_text)
            except ValueError as exc:
                raise ConfigError(
                    f"smtp_port must be an integer, not {port_text!r}."
                ) from exc
            if not 1 <= port <= 65535:
                raise ConfigError("smtp_port must be a port number between 1 and 65535.")
        else:
            port = settings.smtp_port
        ssl = _as_bool(self["smtp_ssl"].value, default=settings.smtp_ssl)
        starttls = False if ssl else _as_bool(
            self["smtp_starttls"].value, default=settings.smtp_starttls
        )
        return replace_mail(
            settings,
            smtp_host=host,
            smtp_port=port,
            smtp_user=user,
            smtp_password=password,
            smtp_from=sender,
            smtp_starttls=starttls,
            smtp_ssl=ssl,
        )


def replace_mail(settings: Settings, **smtp: object) -> Settings:
    """Copy ``settings`` with SMTP fields replaced. Isolated so tests can see it."""
    from dataclasses import replace

    return replace(settings, **smtp)


def resolve_mail_settings(settings: Settings) -> Settings:
    """The one resolution the worker, the notifier and ``--check`` share.

    A stored ciphertext that cannot be decrypted raises :class:`SecretKeyError`
    naming the field. The returned settings are not a silent mix of a failed
    database value and ``.env``.
    """
    return MailSettingsStore(settings.settings_path).resolve(settings).apply(settings)


class MailSettingsStore:
    """Key/value rows in the instance settings database (``Settings.settings_path``)."""

    def __init__(self, path: Path):
        self.path = Path(path)

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
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()

    def _ensure(self, conn: sqlite3.Connection) -> None:
        conn.execute(_CREATE)

    def _rows(self) -> dict[str, sqlite3.Row]:
        """Stored rows. A missing file is an empty store, and it stays missing."""
        if not self.path.exists():
            return {}
        with self._session() as conn:
            self._ensure(conn)
            found = conn.execute("SELECT * FROM instance_settings").fetchall()
        return {row["key"]: row for row in found}

    def resolve(self, settings: Settings) -> ResolvedMail:
        """Resolve each field: database, then ``.env``, then unconfigured."""
        stored = self._rows()
        env = _env_values(settings)
        fields: dict[str, MailField] = {}
        for name in MAIL_FIELD_NAMES:
            fields[name] = _resolve_field(name, stored.get(name), env.get(name), settings.secret_key)
        return ResolvedMail(fields)

    def save(
        self,
        values: Mapping[str, str],
        *,
        updated_by: str,
        key: str | None,
    ) -> list[str]:
        """Write mail settings. Requires a Fernet key even when no secret changes.

        An empty or absent ``smtp_password`` keeps the stored password. A new
        password is stored as ciphertext plus a hint. Returns the field names
        that were written, never the values.
        """
        require_key(key)
        unknown = sorted(set(values) - set(MAIL_FIELD_NAMES))
        if unknown:
            raise ValueError(f"Unknown mail setting: {', '.join(unknown)}")
        password = values.get("smtp_password") or ""
        token = encrypt(password, key) if password else None
        hint = password_hint(password) if password else None
        written: list[str] = []
        stamp = _stamp()
        with self._session() as conn:
            self._ensure(conn)
            for name in MAIL_FIELD_NAMES:
                if name == "smtp_password" or name not in values:
                    continue
                _upsert(
                    conn,
                    name,
                    values[name],
                    secret=False,
                    hint=None,
                    updated_at=stamp,
                    updated_by=updated_by,
                )
                written.append(name)
            if token is not None and hint is not None:
                _upsert(
                    conn,
                    "smtp_password",
                    token,
                    secret=True,
                    hint=hint,
                    updated_at=stamp,
                    updated_by=updated_by,
                )
                written.append("smtp_password")
        return written

    def clear(self) -> None:
        """Remove every mail setting. An explicit action, not an empty save."""
        if not self.path.exists():
            return
        with self._session() as conn:
            self._ensure(conn)
            placeholders = ",".join("?" for _ in MAIL_FIELD_NAMES)
            conn.execute(
                f"DELETE FROM instance_settings WHERE key IN ({placeholders})",
                MAIL_FIELD_NAMES,
            )


def _upsert(
    conn: sqlite3.Connection,
    key: str,
    value: str,
    *,
    secret: bool,
    hint: str | None,
    updated_at: str,
    updated_by: str,
) -> None:
    conn.execute(
        """
        INSERT INTO instance_settings (key, value, secret, hint, updated_at, updated_by)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            secret = excluded.secret,
            hint = excluded.hint,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
        """,
        (key, value, int(secret), hint, updated_at, updated_by),
    )


def _env_values(settings: Settings) -> dict[str, str | None]:
    """What ``.env`` contributes. Defaults alone are not a configured transport."""
    configured = bool(settings.smtp_host or settings.smtp_user or settings.smtp_password)
    if not configured:
        return {name: None for name in MAIL_FIELD_NAMES}
    return {
        "smtp_provider": None,
        "smtp_host": settings.smtp_host,
        "smtp_port": str(settings.smtp_port),
        "smtp_user": settings.smtp_user,
        "smtp_password": settings.smtp_password,
        "smtp_from": settings.smtp_from,
        "smtp_starttls": "true" if settings.smtp_starttls else "false",
        "smtp_ssl": "true" if settings.smtp_ssl else "false",
    }


def _resolve_field(
    name: str,
    row: sqlite3.Row | None,
    env_value: str | None,
    key: str | None,
) -> MailField:
    secret = name in SECRET_FIELDS
    if row is not None:
        if secret or row["secret"]:
            hint = row["hint"] or None
            try:
                value = decrypt(row["value"], key, field=name)
            except SecretKeyError as exc:
                return MailField(
                    name=name,
                    value=None,
                    source=SOURCE_DATABASE,
                    hint=hint,
                    secret=True,
                    error=str(exc),
                )
            return MailField(
                name=name,
                value=value or None,
                source=SOURCE_DATABASE,
                hint=hint or password_hint(value),
                secret=True,
            )
        stored = row["value"] or None
        return MailField(name=name, value=stored, source=SOURCE_DATABASE, secret=False)
    if env_value:
        hint = password_hint(env_value) if secret else None
        return MailField(
            name=name,
            value=env_value,
            source=SOURCE_ENV,
            hint=hint,
            secret=secret,
        )
    return MailField(name=name, value=None, source=SOURCE_UNCONFIGURED, secret=secret)
