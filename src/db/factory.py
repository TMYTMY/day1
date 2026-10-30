"""Pick a database adapter from settings. SQLite is the only implemented one."""

from __future__ import annotations

from src.config import ConfigError, Settings
from src.connections import apply_enabled_connection, ui_sqlite_selected
from src.db.athena import AthenaAdapter
from src.db.postgres import PostgresAdapter
from src.db.sqlite import SqliteAdapter


def build_adapter(settings: Settings) -> SqliteAdapter | PostgresAdapter | AthenaAdapter:
    """Open the warehouse. An enabled UI SQLite connection wins over the environment.

    That file is opened without seeding. The demo database is still seeded when
    the environment path is the one in use.
    """
    effective = apply_enabled_connection(settings)
    if effective.db_backend == "sqlite":
        seed = not ui_sqlite_selected(settings, effective)
        return SqliteAdapter(
            effective.db_path,
            seed=seed,
            statement_timeout_ms=effective.sql_timeout_ms,
        )
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
