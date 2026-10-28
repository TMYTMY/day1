"""Environment-backed settings. Credentials stay in the process environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]

# Wall-clock limit on one statement, in milliseconds. 0 disables the limit.
DEFAULT_SQL_TIMEOUT_MS = 5000


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

    def __repr__(self) -> str:
        key_state = "set" if self.openrouter_api_key else "unset"
        embed_key = "set" if self.embedding_api_key else "unset"
        return (
            f"Settings(db_backend={self.db_backend!r}, "
            f"model={self.openrouter_model!r}, api_key={key_state}, "
            f"embedding={self.embedding_provider!r}, embedding_key={embed_key})"
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
    )
