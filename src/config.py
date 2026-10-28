"""Environment-backed settings. Credentials stay in the process environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]

# Wall-clock limit on one statement, in milliseconds. 0 disables the limit.
DEFAULT_SQL_TIMEOUT_MS = 5000

# The longest window an alert definition may name, in days. A draft beyond it
# is refused with this number in the message; it is never clamped.
DEFAULT_MAX_ALERT_WINDOW_DAYS = 365

# Notification delivery. The submission port is the conventional default; the
# from-address is what a local relay accepts when the instance has no domain of
# its own. Neither is a secret, and neither is ever guessed from a password.
DEFAULT_SMTP_PORT = 587
DEFAULT_SMTP_FROM = "day1-alerts@localhost"

# Values of SMTP_STARTTLS that turn the upgrade off. Everything else (including
# the empty string) leaves it on, because a mail server that offers STARTTLS
# should be asked for it.
_FALSE = frozenset({"0", "false", "no", "off"})



class ConfigError(Exception):
    """The app cannot start because a config file or env value is invalid."""


def redact(text: str, *secrets: str | None) -> str:
    cleaned = text
    for secret in secrets:
        if secret:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned


@dataclass(frozen=True)
class Settings:
    db_backend: str
    db_path: Path
    database_url: str | None
    db_user: str | None
    db_password: str | None
    athena_region: str | None
    athena_database: str | None
    athena_workgroup: str | None
    athena_output: str | None
    audit_path: Path
    routing_path: Path
    users_path: Path
    openrouter_api_key: str | None
    openrouter_model: str
    openrouter_base_url: str
    max_rows: int
    knowledge_path: Path
    embedding_provider: str
    embedding_model: str
    embedding_api_key: str | None
    max_llm_calls_per_day: int = 500
    sql_timeout_ms: int = DEFAULT_SQL_TIMEOUT_MS
    metrics_path: Path = field(default_factory=lambda: ROOT / "config" / "metrics.yaml")
    # A declared source belongs to one instance. These three paths must never be
    # shared between two instances on the same machine.
    sources_dir: Path = field(default_factory=lambda: ROOT / "config" / "sources")
    sources_db: Path = field(default_factory=lambda: ROOT / "data" / "sources.sqlite")
    sources_staging_dir: Path = field(default_factory=lambda: ROOT / "data" / "staging")
    # The instance's own alert data. The file holds alert definitions today and
    # will hold the job table and the delivery log, so it is named for the data
    # rather than for one table in it.
    alerts_path: Path = field(default_factory=lambda: ROOT / "data" / "alerts.db")
    max_alert_window_days: int = DEFAULT_MAX_ALERT_WINDOW_DAYS
    # Notification delivery (issue #21). A worker with no SMTP_HOST refuses to
    # run rather than tick and deliver nothing, so these are not optional for a
    # deployment that has confirmed an alert definition.
    smtp_host: str | None = None
    smtp_port: int = DEFAULT_SMTP_PORT
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = DEFAULT_SMTP_FROM
    smtp_starttls: bool = True

    @property
    def smtp_configured(self) -> bool:
        """True when this instance has a host to deliver through."""
        return bool(self.smtp_host and self.smtp_from)

    def __repr__(self) -> str:
        key_state = "set" if self.openrouter_api_key else "unset"
        embed_key = "set" if self.embedding_api_key else "unset"
        mail_state = "set" if self.smtp_configured else "unset"
        return (
            f"Settings(db_backend={self.db_backend!r}, "
            f"model={self.openrouter_model!r}, api_key={key_state}, "
            f"embedding={self.embedding_provider!r}, embedding_key={embed_key}, "
            f"smtp={mail_state})"
        )


def _optional(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def _resolve(value: str, default: str) -> Path:
    raw = value.strip() or default
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    return path


def load_settings() -> Settings:
    """Load settings from the environment and an optional `.env` file.

    Existing environment variables win over the file. The API key and database
    password are never written into prompts or client code.
    """
    load_dotenv(ROOT / ".env", override=False)
    backend = os.environ.get("DB_BACKEND", "sqlite").strip().lower() or "sqlite"
    if backend not in {"sqlite", "postgres", "athena"}:
        raise ConfigError("DB_BACKEND must be sqlite, postgres, or athena.")
    try:
        max_rows = int(os.environ.get("MAX_RESULT_ROWS", "500"))
    except ValueError as exc:
        raise ConfigError("MAX_RESULT_ROWS must be an integer.") from exc
    max_rows = max(1, min(max_rows, 5000))
    embedding_provider = os.environ.get("EMBEDDING_PROVIDER", "local").strip().lower() or "local"
    if embedding_provider not in {"local", "openrouter"}:
        raise ConfigError("EMBEDDING_PROVIDER must be local or openrouter.")
    embedding_key = _optional("EMBEDDING_API_KEY")
    if embedding_provider == "openrouter" and not embedding_key:
        embedding_key = _optional("OPENROUTER_API_KEY")
    try:
        max_llm_calls_per_day = int(os.environ.get("MAX_LLM_CALLS_PER_DAY", "500"))
    except ValueError as exc:
        raise ConfigError("MAX_LLM_CALLS_PER_DAY must be an integer.") from exc
    if max_llm_calls_per_day < 0:
        raise ConfigError("MAX_LLM_CALLS_PER_DAY must be zero or greater.")
    try:
        sql_timeout_ms = int(os.environ.get("SQL_TIMEOUT_MS", str(DEFAULT_SQL_TIMEOUT_MS)))
    except ValueError as exc:
        raise ConfigError("SQL_TIMEOUT_MS must be an integer.") from exc
    if sql_timeout_ms < 0:
        raise ConfigError("SQL_TIMEOUT_MS must be zero or greater.")
    try:
        max_alert_window_days = int(
            os.environ.get("MAX_ALERT_WINDOW_DAYS", str(DEFAULT_MAX_ALERT_WINDOW_DAYS))
        )
    except ValueError as exc:
        raise ConfigError("MAX_ALERT_WINDOW_DAYS must be an integer.") from exc
    if max_alert_window_days < 1:
        raise ConfigError("MAX_ALERT_WINDOW_DAYS must be at least 1 day.")
    try:
        smtp_port = int(os.environ.get("SMTP_PORT", str(DEFAULT_SMTP_PORT)))
    except ValueError as exc:
        raise ConfigError("SMTP_PORT must be an integer.") from exc
    if not 1 <= smtp_port <= 65535:
        raise ConfigError("SMTP_PORT must be a port number between 1 and 65535.")
    smtp_user = _optional("SMTP_USER")
    smtp_from = _optional("SMTP_FROM") or (smtp_user if smtp_user and "@" in smtp_user else None)
    smtp_starttls = os.environ.get("SMTP_STARTTLS", "").strip().lower() not in _FALSE
    return Settings(
        db_backend=backend,
        db_path=_resolve(os.environ.get("DB_PATH", ""), "data/demo.db"),
        database_url=_optional("DATABASE_URL"),
        db_user=_optional("DB_USER"),
        db_password=_optional("DB_PASSWORD"),
        athena_region=_optional("ATHENA_REGION"),
        athena_database=_optional("ATHENA_DATABASE"),
        athena_workgroup=_optional("ATHENA_WORKGROUP"),
        athena_output=_optional("ATHENA_OUTPUT"),
        audit_path=_resolve(os.environ.get("AUDIT_PATH", ""), "data/audit.db"),
        routing_path=_resolve(os.environ.get("ROUTING_PATH", ""), "config/routing.yaml"),
        users_path=_resolve(os.environ.get("USERS_PATH", ""), "config/users.yaml"),
        openrouter_api_key=_optional("OPENROUTER_API_KEY"),
        openrouter_model=os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini").strip()
        or "openai/gpt-4o-mini",
        openrouter_base_url=os.environ.get(
            "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
        ).strip()
        or "https://openrouter.ai/api/v1",
        max_rows=max_rows,
        knowledge_path=_resolve(os.environ.get("KNOWLEDGE_PATH", ""), "data/knowledge"),
        embedding_provider=embedding_provider,
        embedding_model=os.environ.get("EMBEDDING_MODEL", "openai/text-embedding-3-small").strip()
        or "openai/text-embedding-3-small",
        embedding_api_key=embedding_key,
        max_llm_calls_per_day=max_llm_calls_per_day,
        sql_timeout_ms=sql_timeout_ms,
        metrics_path=_resolve(os.environ.get("METRICS_PATH", ""), "config/metrics.yaml"),
        sources_dir=_resolve(os.environ.get("SOURCES_DIR", ""), "config/sources"),
        sources_db=_resolve(os.environ.get("SOURCES_DB", ""), "data/sources.sqlite"),
        sources_staging_dir=_resolve(os.environ.get("SOURCES_STAGING_DIR", ""), "data/staging"),
        alerts_path=_resolve(os.environ.get("ALERTS_PATH", ""), "data/alerts.db"),
        max_alert_window_days=max_alert_window_days,
        smtp_host=_optional("SMTP_HOST"),
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_password=_optional("SMTP_PASSWORD"),
        smtp_from=smtp_from or DEFAULT_SMTP_FROM,
        smtp_starttls=smtp_starttls,
    )
