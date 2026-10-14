"""Split uploaded notes into retrieval chunks. Nothing here is executed."""

from __future__ import annotations

import csv
import io
import json
import re

CHUNK_SIZE = 800
CHUNK_OVERLAP = 100
MAX_CHUNKS = 200


def chunk_document(text: str, extension: str) -> tuple[list[str], bool]:
    """Return chunks and whether the file was cut at MAX_CHUNKS."""
    kind = extension.lower().lstrip(".")
    if kind == "csv":
        pieces = _chunk_csv(text)
    elif kind == "json":
        pieces = _chunk_json(text)
    else:
        pieces = _chunk_prose(text)
    truncated = len(pieces) > MAX_CHUNKS
    return pieces[:MAX_CHUNKS], truncated


def _chunk_prose(text: str) -> list[str]:
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not cleaned:
        return []
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", cleaned) if part.strip()]
    chunks: list[str] = []
    buffer = ""
    for paragraph in paragraphs:
        if buffer and len(buffer) + len(paragraph) + 2 > CHUNK_SIZE:
            chunks.append(buffer)
            tail = buffer[-CHUNK_OVERLAP:]
            buffer = f"{tail}\n{paragraph}".strip()
        elif buffer:
            buffer = f"{buffer}\n\n{paragraph}"
        else:
            buffer = paragraph
        while len(buffer) > CHUNK_SIZE:
            chunks.append(buffer[:CHUNK_SIZE])
            buffer = buffer[CHUNK_SIZE - CHUNK_OVERLAP :].strip()
    if buffer:
        chunks.append(buffer)
    return chunks


def _render_csv(header: list[str], rows: list[list[str]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(header)
    writer.writerows(rows)
    return output.getvalue().strip()


def _bounded(text: str) -> list[str]:
    if len(text) <= CHUNK_SIZE:
        return [text]
    return _chunk_prose(text)


def _chunk_csv(text: str) -> list[str]:
    reader = csv.reader(io.StringIO(text))
    rows = [row for row in reader if any(cell.strip() for cell in row)]
    if not rows:
        return []
    header = rows[0]
    body = rows[1:] or [header]
    chunks: list[str] = []
    batch: list[list[str]] = []

    def flush() -> None:
        if not batch:
            return
        chunks.extend(_bounded(_render_csv(header, batch)))

    for row in body:
        if batch:
            size = len(_render_csv(header, batch + [row]))
            if size >= CHUNK_SIZE or len(batch) >= 20:
                flush()
                batch = []
        batch.append(row)
        if len(batch) >= 20 or len(_render_csv(header, batch)) >= CHUNK_SIZE:
            flush()
            batch = []
    flush()
    return chunks or _chunk_prose(text)


def _chunk_json(text: str) -> list[str]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return _chunk_prose(text)
    if isinstance(value, list) and value:
        chunks: list[str] = []
        batch: list[object] = []
        for item in value:
            rendered_item = json.dumps(item, ensure_ascii=False, indent=2)
            if len(rendered_item) > CHUNK_SIZE:
                if batch:
                    chunks.append(json.dumps(batch, ensure_ascii=False, indent=2))
                    batch = []
                chunks.extend(_chunk_prose(rendered_item))
                continue
            trial = batch + [item]
            rendered = json.dumps(trial, ensure_ascii=False, indent=2)
            if batch and len(rendered) > CHUNK_SIZE:
                chunks.append(json.dumps(batch, ensure_ascii=False, indent=2))
                batch = [item]
            else:
                batch = trial
        if batch:
            chunks.append(json.dumps(batch, ensure_ascii=False, indent=2))
        return chunks
    rendered = json.dumps(value, ensure_ascii=False, indent=2)
    return _chunk_prose(rendered)
