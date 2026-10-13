"""Pick a database adapter from settings. SQLite is the only implemented one."""

from __future__ import annotations

from src.config import ConfigError, Settings
from src.db.athena import AthenaAdapter
from src.db.postgres import PostgresAdapter
from src.db.sqlite import SqliteAdapter


def build_adapter(settings: Settings) -> SqliteAdapter | PostgresAdapter | AthenaAdapter:
    if settings.db_backend == "sqlite":
        return SqliteAdapter(settings.db_path)
    if settings.db_backend == "postgres":
        if not settings.database_url:
            raise ConfigError("DB_BACKEND=postgres requires DATABASE_URL.")
        return PostgresAdapter(settings.database_url, settings.db_user, settings.db_password)
    if settings.db_backend == "athena":
        return AthenaAdapter(
            settings.athena_region,
            settings.athena_database,
            settings.athena_workgroup,
            settings.athena_output,
        )
    raise ConfigError(f"Unknown DB_BACKEND {settings.db_backend}.")
