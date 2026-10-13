"""Athena swap-in. Not used by the demo.

Expected environment, read by the adapter and never placed in a prompt:
  ATHENA_REGION, ATHENA_DATABASE, ATHENA_WORKGROUP, ATHENA_OUTPUT

AWS credentials should come from the standard provider chain. Use a workgroup
whose IAM policy can only run SELECT. The SQL guard dialect for this adapter
is Presto.
"""

from __future__ import annotations

from src.models import QueryResult, TableSchema


class AthenaAdapter:
    dialect = "presto"
    display_name = "Athena"

    def __init__(
        self,
        region: str | None,
        database: str | None,
        workgroup: str | None,
        output: str | None,
    ):
        self._region = region
        self._database = database
        self._workgroup = workgroup
        self._output = output

    def __repr__(self) -> str:
        return "AthenaAdapter(configured)"

    def get_schema(self, table: str) -> TableSchema | None:
        raise NotImplementedError(
            "AthenaAdapter is a stub. Set DB_BACKEND=sqlite for the demo, "
            "or implement get_schema against the Athena catalog."
        )

    def row_count(self, table: str) -> int:
        raise NotImplementedError(
            "AthenaAdapter is a stub. Set DB_BACKEND=sqlite for the demo."
        )

    def execute_select(
        self,
        sql: str,
        *,
        allowed_tables: set[str],
        max_rows: int,
    ) -> QueryResult:
        raise NotImplementedError(
            "AthenaAdapter is a stub. Set DB_BACKEND=sqlite for the demo, "
            "or implement execute_select with a read-only Athena workgroup."
        )
