"""CSV and HTML downloads of the current result only."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape


@dataclass(frozen=True)
class ExportMeta:
    question: str
    tables: tuple[str, ...]
    sql: str | None
    assumptions: str | None
    generated_at: str
    truncated: bool
    username: str


def stamp_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def result_filename(tables: list[str] | tuple[str, ...], extension: str, stamp: str) -> str:
    slug = "-".join(tables) if tables else "result"
    slug = re.sub(r"[^a-z0-9-]+", "", slug.lower()) or "result"
    compact = re.sub(r"[^0-9]", "", stamp)[:14] or "export"
    return f"day1-{slug}-{compact}.{extension}"


def _csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return str(value)


def to_csv(columns: list[str], rows: list[dict]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: _csv_cell(row.get(column)) for column in columns})
    return buffer.getvalue().encode("utf-8-sig")


def to_html(
    columns: list[str],
    rows: list[dict],
    meta: ExportMeta,
    labels: dict[str, str] | None = None,
) -> bytes:
    labels = labels or {}
    header = "".join(
        f"<th>{escape(labels.get(column, column))}</th>" for column in columns
    )
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{escape(_csv_cell(row.get(column)))}</td>" for column in columns)
        body_rows.append(f"<tr>{cells}</tr>")
    body = "\n".join(body_rows)
    note = "This export is capped." if meta.truncated else "This export is the full fetched result."
    assumption = escape(meta.assumptions or "")
    sql_block = ""
    if meta.sql:
        sql_block = f"<pre>{escape(meta.sql)}</pre>"
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Day1 result</title>
<style>
  body {{ margin: 40px; color: #1c2421; font-family: Georgia, "Times New Roman", serif; }}
  h1 {{ font-weight: 500; font-size: 1.6rem; margin-bottom: 0.2rem; }}
  p {{ color: #3d4f49; }}
  table {{ border-collapse: collapse; width: 100%; font-family: "Segoe UI", sans-serif; font-size: 14px; }}
  th {{ background: #0e6b56; color: white; text-align: left; padding: 8px; }}
  td {{ border-bottom: 1px solid #ddd; padding: 8px; }}
  pre {{ white-space: pre-wrap; background: #f4f7f6; padding: 12px; font-size: 13px; }}
</style>
</head>
<body>
<p>Day1</p>
<h1>{escape(meta.question)}</h1>
<p>{escape(meta.generated_at)} · {escape(meta.username)} · tables {escape(", ".join(meta.tables) or "none")}</p>
<p>{assumption}</p>
<p>{note} {len(rows)} rows, {len(columns)} columns.</p>
<table>
<thead><tr>{header}</tr></thead>
<tbody>
{body}
</tbody>
</table>
{sql_block}
</body>
</html>
"""
    return document.encode("utf-8")
