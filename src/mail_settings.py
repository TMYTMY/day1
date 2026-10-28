"""Encrypted mail settings for one instance, and the one transport they resolve to.

The page, the worker and the notifier all read mail through this store, so they
cannot disagree about which transport is in use. Five rules, in the order they
bite:

**A stored password belongs where it was entered.** Beside the ciphertext the
store keeps the ``(host, port, username, TLS mode)`` the person was looking at
when they typed it. A save that would carry that password to a different
transport without a fresh one is refused, naming the field that moved, and the
stored secret is left exactly as it was. The alternative — keeping the old
ciphertext and writing the new host — presents a credential to a server it was
never given to, which is the worst thing this module could do.

**A clear is a clear.** ``clear()`` leaves a tombstone row for the password.
Deleting the row is not enough: resolution would fall through to ``.env`` and
the cancelled credential would take effect again on the next delivery.

**One transport, one source.** Every mail field resolves from the encrypted
database, or every field resolves from ``.env``. A transport assembled field by
field (host from the database, password from ``.env``) is how a stored secret
ended up paired with an endpoint nobody chose for it.

**A key-check value.** One fixed string, encrypted under the same key, is
written when the first secret is stored and verified once per process before
the store is used. A wrong or rotated key is then one named error instead of
one decryption error per field, and a mixed-key write is refused rather than
written.

**Values are validated.** A port is a port, a host is a host, and a TLS flag is
one of a closed set of words, both before a write and after a read, so a typo
cannot quietly drop TLS.

The password itself is never written into the database, the hint, or an error
message. The hint says only that a secret is set and how long it is: an older
build put the last four characters there, which is an entropy cut on a page.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.config import DEFAULT_SMTP_FROM, DEFAULT_SMTP_PORT, ConfigError, Settings
from src.crypto import (
    KEY_CHECK_PLAINTEXT,
    KeyCheckError,
    SecretKeyError,
    decrypt,
    encrypt,
    require_key,
)

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

# A stored transport is these fields, and a provider label is not one of them:
# a page that only remembers "gmail" has not configured anything.
TRANSPORT_FIELDS = tuple(name for name in MAIL_FIELD_NAMES if name != "smtp_provider")

# Beside the ciphertext: the transport the password was entered for, as
# canonical JSON, and the one key-check value.
BINDING_FIELD = "smtp_password_binding"
KEY_CHECK_FIELD = "instance_key_check"

# What a cleared password row holds. Not a Fernet token and not empty, so it
# can never be mistaken for a secret and never looks "unset" to the group rule.
TOMBSTONE = "!cleared"

# The hint a cleared row shows. It says nothing about the secret, because the
# secret no longer exists.
CLEARED_HINT = "cleared"

SOURCE_DATABASE = "database"
SOURCE_ENV = ".env"
SOURCE_UNCONFIGURED = "unconfigured"

_TRUE = frozenset({"true", "1", "yes", "on"})
_FALSE = frozenset({"false", "0", "no", "off"})

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HOST_SHAPE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,252}[A-Za-z0-9])?$")
_EMAIL_SHAPE = re.compile(r"^[^@\s]+@[^@\s]+$")

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


class MailSettingsRefused(SecretKeyError):
    """A save the store refuses, with a message written for the operator.

    It is a :class:`SecretKeyError` because the page already has exactly one
    refusal path for a save it must not perform — it renders the message,
    redacts the typed password out of it, and audits ``settings_refused`` —
    and a refusal about a secret belongs on that path rather than beside it.
    """


class MailValueError(MailSettingsRefused, ConfigError):
    """A mail value that cannot be stored: not a host, not a port, not a TLS flag.

    Both bases are deliberate. The page refuses it through the
    :class:`SecretKeyError` path it already has, and the worker and ``--check``
    refuse it through the :class:`ConfigError` path they already have, without
    either of them learning a second kind of refusal.
    """


class SecretBindingError(MailSettingsRefused):
    """A save would carry a stored password to a transport it was not entered for."""


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def password_hint(password: str) -> str:
    """A non-secret reminder that a password is stored.

    It contains no character of the secret: only the word ``set`` and the
    length. Who set it and when are the row's ``updated_by`` and
    ``updated_at``, so a page can say all four without cutting the secret's
    entropy. (An older build stored the last four characters here.)
    """
    length = len(password)
    unit = "character" if length == 1 else "characters"
    return f"set, {length} {unit}"


def _flag(value: str | None, *, field: str, default: bool | None = None) -> bool | None:
    """One TLS flag, from an exact set of words.

    A loose parse is a downgrade waiting to happen: anything unrecognised used
    to read as "on" for STARTTLS but as "off" for an empty string, and the two
    flags together decide whether the password crosses the network in the
    clear. An unknown word is refused instead of guessed at.
    """
    if value is None:
        return default
    token = str(value).strip().lower()
    if not token:
        return default
    if token in _TRUE:
        return True
    if token in _FALSE:
        return False
    raise MailValueError(
        f"{field} must be true or false (or on/off, yes/no, 1/0), not {value!r}. "
        "An unknown value is not read as either, because guessing wrong can drop TLS."
    )


def _reject_control(name: str, value: str) -> None:
    if _CONTROL.search(value):
        raise MailValueError(
            f"{name} must not contain a line break or a control character. "
            "A header value with a newline in it is how a second header gets written."
        )


def validate_mail_value(name: str, raw: object) -> str:
    """One mail value, canonicalised, or a refusal that names the field.

    Applied to a submitted value before it is written and to a stored value
    before it is used. A password is returned exactly as typed — no strip, no
    case change — because those characters are the credential.
    """
    text = "" if raw is None else str(raw)
    if name in SECRET_FIELDS:
        if len(text) > 512:
            raise MailValueError("smtp_password is longer than 512 characters.")
        _reject_control(name, text)
        return text
    value = text.strip()
    _reject_control(name, value)
    if name == "smtp_host":
        if value and (len(value) > 255 or not _HOST_SHAPE.match(value)):
            raise MailValueError(
                f"smtp_host must be a host name or an IP address, not {value!r}. "
                "Give the name the mail server answers to, without a scheme or a path."
            )
        return value
    if name == "smtp_port":
        if not value:
            raise MailValueError("smtp_port must be a port number between 1 and 65535.")
        try:
            port = int(value)
        except ValueError:
            raise MailValueError(f"smtp_port must be an integer, not {value!r}.") from None
        if not 1 <= port <= 65535:
            raise MailValueError("smtp_port must be a port number between 1 and 65535.")
        return str(port)
    if name in ("smtp_ssl", "smtp_starttls"):
        flag = _flag(value, field=name)
        return "" if flag is None else ("true" if flag else "false")
    if name == "smtp_from":
        if value and not _EMAIL_SHAPE.match(value):
            raise MailValueError(
                f"smtp_from must be one email address, not {value!r}."
            )
        if len(value) > 320:
            raise MailValueError("smtp_from is longer than 320 characters.")
        return value
    if name == "smtp_user":
        if len(value) > 320:
            raise MailValueError("smtp_user is longer than 320 characters.")
        return value
    if name == "smtp_provider":
        if len(value) > 40:
            raise MailValueError("smtp_provider is longer than 40 characters.")
        return value
    raise ValueError(f"Unknown mail setting: {name}")


def _as_bool_record(value: str | None, *, field: str, default: bool) -> bool:
    """A stored flag for reporting, tolerant only of "absent"."""
    parsed = _flag(value, field=field, default=default)
    return bool(parsed)


@dataclass(frozen=True)
class MailField:
    """One resolved mail setting, and where it came from.

    ``value`` is the effective value. For a secret it is the decrypted
    password, which callers that render a page must not display: use
    :attr:`display`. ``source`` is ``database``, ``.env``, or ``unconfigured``.
    ``error`` is set when a stored ciphertext cannot be read; ``value`` is then
    empty and was not taken from another source. ``cleared`` is true for a
    password the operator cancelled: there is no credential and ``.env`` may
    not supply one.
    """

    name: str
    value: str | None
    source: str
    hint: str | None = None
    secret: bool = False
    error: str | None = None
    cleared: bool = False
    updated_at: str | None = None
    updated_by: str | None = None

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
    # The one source every field came from, or ``unconfigured``. A page labels
    # the transport with this, not once per field.
    transport_source: str = SOURCE_UNCONFIGURED

    def __getitem__(self, name: str) -> MailField:
        return self.fields[name]

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(field.error for field in self.fields.values() if field.error)

    @property
    def cleared(self) -> bool:
        """True when the credential was cancelled rather than never set."""
        return self["smtp_password"].cleared

    def apply(self, settings: Settings) -> Settings:
        """A ``Settings`` whose SMTP fields are these resolved values.

        Raises when a stored secret cannot be read, or a stored value is not
        the kind of value it claims to be. It does not fill a failed field from
        ``settings``: a half-database, half-environment transport is the defect
        this store exists to prevent.
        """
        if self.errors:
            raise SecretKeyError(self.errors[0])
        host = self["smtp_host"].value or None
        if host:
            validate_mail_value("smtp_host", host)
        user = self["smtp_user"].value or None
        password = self["smtp_password"].value or None
        sender = self["smtp_from"].value or DEFAULT_SMTP_FROM
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
            port = DEFAULT_SMTP_PORT
        ssl = _as_bool_record(self["smtp_ssl"].value, field="smtp_ssl", default=False)
        starttls = False if ssl else _as_bool_record(
            self["smtp_starttls"].value, field="smtp_starttls", default=True
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

    A stored ciphertext that cannot be read raises :class:`SecretKeyError`
    naming the field. The returned settings are not a silent mix of a failed
    database value and ``.env``.
    """
    return MailSettingsStore(settings.settings_path).resolve(settings).apply(settings)


def stored_ciphertext_fields(path: Path) -> tuple[str, ...]:
    """The secret fields this settings database holds as ciphertext, without a key.

    ``--init-key`` asks this before it mints anything: a key created on top of
    stored ciphertext can never read it, so every stored secret would be
    orphaned in one command. It reads the table directly, because reading a
    secret would need the key we do not have yet.
    """
    database = Path(path)
    if not database.exists():
        return ()
    try:
        conn = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:  # pragma: no cover - an unreadable file is not ciphertext
        return ()
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT key, value FROM instance_settings WHERE secret = 1"
        ).fetchall()
    except sqlite3.Error:
        # No table (or no database) means nothing has ever been stored.
        return ()
    finally:
        conn.close()
    return tuple(
        sorted(
            row["key"]
            for row in rows
            if row["key"] in SECRET_FIELDS
            and row["value"]
            and row["value"] != TOMBSTONE
        )
    )


class MailSettingsStore:
    """Key/value rows in the instance settings database (``Settings.settings_path``)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        # The key last verified against the stored key-check value, so a page
        # that resolves and saves in one run checks once, not once per call.
        self._verified_for: str | None = None

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

    # -- the key ------------------------------------------------------------

    def verify_key(self, key: str | None, rows: Mapping[str, sqlite3.Row] | None = None) -> None:
        """Check the stored key-check value against ``key``, once per key.

        Called before a read that would decrypt and before any write, in the
        page's store and in the worker's, so a wrong or rotated key is one
        named error at the door rather than one per field behind it. A store
        with nothing encrypted needs no key: plaintext transport values stay
        readable, which is what lets an operator see and clear a broken
        instance.
        """
        stored = self._rows() if rows is None else rows
        fingerprints = stored.get(KEY_CHECK_FIELD)
        live = [name for name in SECRET_FIELDS if _live(stored.get(name))]
        if fingerprints is None and not live:
            return
        cleaned = self._require_key_named(key)
        if self._verified_for == cleaned:
            return
        if fingerprints is not None:
            plaintext = self._decrypt_check(fingerprints["value"], cleaned)
            if plaintext != KEY_CHECK_PLAINTEXT:
                raise KeyCheckError(self._mismatch_message())
        else:
            # A store written before the key-check row existed: the only
            # evidence that this key fits is that it opens what is there.
            for name in live:
                try:
                    decrypt(stored[name]["value"], cleaned, field=name)
                except SecretKeyError as exc:
                    raise KeyCheckError(self._mismatch_message()) from exc
        self._verified_for = cleaned

    def _require_key_named(self, key: str | None) -> str:
        """``require_key``, with the stored secret named in the refusal."""
        try:
            return require_key(key)
        except SecretKeyError as exc:
            raise SecretKeyError(
                "Could not read the stored smtp_password (and the other stored mail "
                f"settings): {exc} The stored value will not be read from another source."
            ) from exc

    def _decrypt_check(self, token: str, key: str) -> str:
        try:
            return decrypt(token, key, field="smtp_password")
        except SecretKeyError as exc:
            raise KeyCheckError(self._mismatch_message()) from exc

    @staticmethod
    def _mismatch_message() -> str:
        return (
            "Could not read the stored smtp_password: DAY1_SECRET_KEY does not reproduce "
            "the key-check value this instance wrote when it stored the password, so the "
            "key in use is not the key that wrote it (it was rotated, restored from "
            "another instance, or is missing). The stored value will not be read from "
            "another source. Restore the key that wrote it, or clear the stored mail "
            "settings and enter the password again."
        )

    # -- resolution ---------------------------------------------------------

    def resolve(self, settings: Settings) -> ResolvedMail:
        """Resolve the whole transport from one source: the database, or ``.env``.

        A stored password makes the database the source, so it can never be
        paired with a host that only exists in ``.env``. A password that cannot
        be read becomes an error on that field and is not replaced.
        """
        stored = self._rows()
        key_error: str | None = None
        try:
            self.verify_key(settings.secret_key, stored)
        except SecretKeyError as exc:
            key_error = str(exc)
        from_database = self._from_database(stored)
        source = SOURCE_DATABASE if from_database else SOURCE_ENV
        env = {} if from_database else _env_values(settings)
        fields = {
            name: _resolve_field(
                name,
                stored.get(name),
                env.get(name),
                settings.secret_key,
                source,
                key_error,
            )
            for name in MAIL_FIELD_NAMES
        }
        configured = from_database or any(value for value in env.values())
        return ResolvedMail(
            fields=fields,
            transport_source=source if configured else SOURCE_UNCONFIGURED,
        )

    @staticmethod
    def _from_database(stored: Mapping[str, sqlite3.Row]) -> bool:
        """True when anything about the transport is stored, so nothing comes from ``.env``."""
        return any(_live(stored.get(name)) for name in TRANSPORT_FIELDS)

    # -- writing ------------------------------------------------------------

    def save(
        self,
        values: Mapping[str, str],
        *,
        updated_by: str,
        key: str | None,
    ) -> list[str]:
        """Write mail settings. Requires a Fernet key even when no secret changes.

        A missing or empty ``smtp_password`` keeps the stored password, but only
        while the rest of the save leaves the transport it was entered for
        alone. Anything else is refused: the operator types the password again
        in the same save, and that is what binds it to the new endpoint. Returns
        the field names that were written, never the values.
        """
        require_key(key)
        unknown = sorted(set(values) - set(MAIL_FIELD_NAMES))
        if unknown:
            raise ValueError(f"Unknown mail setting: {', '.join(unknown)}")
        stored = self._rows()
        # A write under a key that cannot read what is already there would
        # leave two vintages of ciphertext in one table.
        self.verify_key(key, stored)

        clean = {
            name: validate_mail_value(name, raw)
            for name, raw in values.items()
            if name not in SECRET_FIELDS
        }
        password = validate_mail_value("smtp_password", values.get("smtp_password") or "")
        if clean.get("smtp_ssl") == "true" and clean.get("smtp_starttls") == "true":
            raise MailValueError(
                "smtp_ssl and smtp_starttls cannot both be true: 465 speaks TLS from the "
                "first byte and 587 starts in the clear, so they are alternatives."
            )
        current = _future_transport(clean, stored)
        stored_password = stored.get("smtp_password")
        secret_live = _live(stored_password)
        if not password and secret_live:
            recorded = _parse_binding(stored.get(BINDING_FIELD))
            if recorded is None:
                raise SecretBindingError(
                    "The stored smtp_password has no record of the transport it was entered "
                    "for, so it cannot be carried to this one. Enter the password again in "
                    "this save to bind it."
                )
            changes = _binding_changes(recorded, current)
            if changes:
                raise SecretBindingError(
                    "The stored smtp_password was entered for a different transport: "
                    + "; ".join(changes)
                    + ". Nothing was saved and the stored password was not moved to the new "
                    "endpoint. Enter the password again in the same save to bind it here."
                )

        stamp = _stamp()
        written: list[str] = []
        tls_names = ("smtp_ssl", "smtp_starttls")
        with self._session() as conn:
            self._ensure(conn)
            for name in MAIL_FIELD_NAMES:
                if name in SECRET_FIELDS or name in tls_names or name not in clean:
                    continue
                _upsert(
                    conn,
                    name,
                    clean[name],
                    secret=False,
                    hint=None,
                    updated_at=stamp,
                    updated_by=updated_by,
                )
                written.append(name)
            if any(name in clean for name in tls_names):
                # One mode, two columns, always written together so a stored
                # "ssl" can never sit next to a stale "starttls".
                chosen = current["tls"]
                for name, value in (
                    ("smtp_ssl", "true" if chosen == "ssl" else "false"),
                    ("smtp_starttls", "true" if chosen == "starttls" else "false"),
                ):
                    _upsert(
                        conn,
                        name,
                        value,
                        secret=False,
                        hint=None,
                        updated_at=stamp,
                        updated_by=updated_by,
                    )
                    written.append(name)
            if password:
                _upsert(
                    conn,
                    "smtp_password",
                    encrypt(password, key),
                    secret=True,
                    hint=password_hint(password),
                    updated_at=stamp,
                    updated_by=updated_by,
                )
                _upsert(
                    conn,
                    BINDING_FIELD,
                    _render_binding(current),
                    secret=False,
                    hint=None,
                    updated_at=stamp,
                    updated_by=updated_by,
                )
                written.append("smtp_password")
                self._ensure_key_check(conn, key)
            elif secret_live and stored_password is not None:
                self._refresh_hint(conn, stored_password, key)
        return written

    def _ensure_key_check(self, conn: sqlite3.Connection, key: str | None) -> None:
        """Write the key-check value with the first secret, and never rewrite it."""
        found = conn.execute(
            "SELECT 1 FROM instance_settings WHERE key = ?", (KEY_CHECK_FIELD,)
        ).fetchone()
        if found is not None:
            return
        _upsert(
            conn,
            KEY_CHECK_FIELD,
            encrypt(KEY_CHECK_PLAINTEXT, key),
            secret=True,
            hint=None,
            updated_at=_stamp(),
            updated_by="instance",
        )

    @staticmethod
    def _refresh_hint(
        conn: sqlite3.Connection, row: sqlite3.Row, key: str | None
    ) -> None:
        """Replace a hint an older build wrote from the secret's characters.

        The ciphertext is untouched: only the non-secret hint column changes,
        so the leak ends at the next save instead of at the next password
        change.
        """
        try:
            known = decrypt(row["value"], key, field="smtp_password")
        except SecretKeyError:  # pragma: no cover - verify_key ran first
            return
        expected = password_hint(known)
        if row["hint"] == expected:
            return
        conn.execute(
            "UPDATE instance_settings SET hint = ? WHERE key = ?",
            (expected, "smtp_password"),
        )

    def clear(self, *, cleared_by: str | None = None) -> None:
        """Remove every mail setting, and leave a tombstone for the password.

        Deleting the row is not a clear: resolution would fall back to ``.env``
        and the cancelled password would be presented on the next delivery. The
        tombstone is what makes the cancellation survive. Clearing needs no
        key, so an instance whose key is lost can still be cleared and set up
        again, and the key-check value goes with the last ciphertext so a
        replacement key can be adopted afterwards.
        """
        if not self.path.exists():
            return
        stamp = _stamp()
        with self._session() as conn:
            self._ensure(conn)
            names = [name for name in MAIL_FIELD_NAMES if name not in SECRET_FIELDS]
            placeholders = ",".join("?" for _ in names)
            conn.execute(
                f"DELETE FROM instance_settings WHERE key IN ({placeholders})", names
            )
            conn.execute(
                "DELETE FROM instance_settings WHERE key IN (?, ?)",
                (BINDING_FIELD, KEY_CHECK_FIELD),
            )
            _upsert(
                conn,
                "smtp_password",
                TOMBSTONE,
                secret=True,
                hint=CLEARED_HINT,
                updated_at=stamp,
                updated_by=cleared_by or "settings",
            )
        self._verified_for = None


def _live(row: sqlite3.Row | None) -> bool:
    """True when this row holds a real value: set, and not a tombstone."""
    if row is None:
        return False
    value = str(row["value"] or "")
    return bool(value.strip()) and value != TOMBSTONE


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


# --- the binding ----------------------------------------------------------


def _future_transport(
    submitted: Mapping[str, str], stored: Mapping[str, sqlite3.Row]
) -> dict[str, str]:
    """The transport this save would leave behind: ``(host, port, user, TLS mode)``.

    A field the save submits wins, including an empty one (the operator is
    clearing it). A field it does not submit keeps what is stored. ``.env`` is
    not consulted: a password is stored in the database, and a stored password
    makes the database the only source, so the endpoint it is bound to is the
    database's.
    """

    def after(name: str) -> str | None:
        if name in submitted:
            return submitted[name] or None
        row = stored.get(name)
        if row is None or row["value"] == TOMBSTONE:
            return None
        return str(row["value"] or "") or None

    ssl = _as_bool_record(after("smtp_ssl"), field="smtp_ssl", default=False)
    starttls = _as_bool_record(after("smtp_starttls"), field="smtp_starttls", default=True)
    if ssl:
        mode = "ssl"
    elif starttls:
        mode = "starttls"
    else:
        mode = "none"
    return {
        "host": after("smtp_host") or "",
        "port": after("smtp_port") or "",
        "user": after("smtp_user") or "",
        "tls": mode,
    }


_BINDING_KEYS = ("host", "port", "user", "tls")
_BINDING_LABELS = {"host": "host", "port": "port", "user": "username", "tls": "TLS mode"}


def _render_binding(transport: Mapping[str, str]) -> str:
    """Canonical JSON, so two equal bindings are equal strings."""
    return json.dumps(
        {key: str(transport.get(key) or "") for key in _BINDING_KEYS},
        sort_keys=True,
        separators=(",", ":"),
    )


def _parse_binding(row: sqlite3.Row | None) -> dict[str, str] | None:
    """The recorded binding, or None when this row is absent or unreadable."""
    if row is None:
        return None
    try:
        data = json.loads(row["value"])
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return {key: str(data.get(key) or "") for key in _BINDING_KEYS}


def _binding_changes(recorded: Mapping[str, str], current: Mapping[str, str]) -> list[str]:
    """The fields that moved, in words a person reads: field, old, new."""
    changes: list[str] = []
    for key in _BINDING_KEYS:
        before = recorded.get(key) or ""
        after = current.get(key) or ""
        if before != after:
            changes.append(
                f"{_BINDING_LABELS[key]} was {before or 'unset'} and is now {after or 'unset'}"
            )
    return changes


# --- resolution -----------------------------------------------------------


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
    source: str,
    key_error: str | None,
) -> MailField:
    secret = name in SECRET_FIELDS
    if row is None:
        return _from_environment(name, env_value, source, secret)
    stamp = {"updated_at": row["updated_at"], "updated_by": row["updated_by"]}
    if secret and row["value"] == TOMBSTONE:
        # The credential was cancelled. No source may fill it in again.
        return MailField(
            name=name,
            value=None,
            source=SOURCE_UNCONFIGURED,
            hint=CLEARED_HINT,
            secret=True,
            cleared=True,
            **stamp,
        )
    if source == SOURCE_DATABASE and _live(row):
        if secret or row["secret"]:
            if key_error:
                return MailField(
                    name=name,
                    value=None,
                    source=SOURCE_DATABASE,
                    hint=row["hint"] if row["hint"] == CLEARED_HINT else None,
                    secret=True,
                    error=key_error,
                    **stamp,
                )
            try:
                value = decrypt(row["value"], key, field=name)
            except SecretKeyError as exc:
                return MailField(
                    name=name,
                    value=None,
                    source=SOURCE_DATABASE,
                    secret=True,
                    error=str(exc),
                    **stamp,
                )
            # The hint is recomputed, never trusted: a row written by an older
            # build still holds four characters of the secret in that column.
            return MailField(
                name=name,
                value=value or None,
                source=SOURCE_DATABASE,
                hint=password_hint(value),
                secret=True,
                **stamp,
            )
        return MailField(
            name=name,
            value=str(row["value"]) or None,
            source=SOURCE_DATABASE,
            secret=False,
            **stamp,
        )
    return _from_environment(
        name, env_value, source, secret, row["updated_at"], row["updated_by"]
    )


def _from_environment(
    name: str,
    env_value: str | None,
    source: str,
    secret: bool,
    updated_at: str | None = None,
    updated_by: str | None = None,
) -> MailField:
    """The ``.env`` or unconfigured answer for one field."""
    if source == SOURCE_ENV and env_value:
        return MailField(
            name=name,
            value=env_value,
            source=SOURCE_ENV,
            hint=password_hint(env_value) if secret else None,
            secret=secret,
        )
    return MailField(
        name=name,
        value=None,
        source=SOURCE_UNCONFIGURED,
        secret=secret,
        updated_at=updated_at,
        updated_by=updated_by,
    )
