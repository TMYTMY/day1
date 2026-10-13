"""Database adapters. SQLite is the demo; Postgres and Athena are swap-in points."""

from src.db.factory import build_adapter

__all__ = ["build_adapter"]
