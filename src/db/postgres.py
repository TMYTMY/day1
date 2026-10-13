"""Postgres swap-in. Not used by the demo.

Expected environment, all read by the adapter and never placed in a prompt:
  DATABASE_URL, DB_USER, DB_PASSWORD

Use a database role that can only SELECT. Implement `execute_select` with that
role, then keep the SQL guard in front of it.
"""

from __future__ import annotations

from src.models import QueryResult, TableSchema


class PostgresAdapter:
    dialect = "postgres"
    display_name = "Postgres"

    def __init__(self, dsn: str, user: str | None, password: str | None):
        self._dsn = dsn
        self._user = user
        self._password = password

    def __repr__(self) -> str:
        return "PostgresAdapter(configured)"

    def get_schema(self, table: str) -> TableSchema | None:
        raise NotImplementedError(
            "PostgresAdapter is a stub. Set DB_BACKEND=sqlite for the demo, "
            "or implement get_schema with the read-only role."
        )

    def row_count(self, table: str) -> int:
        raise NotImplementedError(
            "PostgresAdapter is a stub. Set DB_BACKEND=sqlite for the demo."
        )

    def execute_select(
        self,
        sql: str,
        *,
        allowed_tables: set[str],
        max_rows: int,
    ) -> QueryResult:
        raise NotImplementedError(
            "PostgresAdapter is a stub. Set DB_BACKEND=sqlite for the demo, "
            "or implement execute_select with a read-only DATABASE_URL."
        )
