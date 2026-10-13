"""Rule-based topic routing. No vector index in v1."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from src.config import ConfigError


@dataclass(frozen=True)
class Topic:
    id: str
    title: str
    tables: tuple[str, ...]
    synonyms: tuple[str, ...]


@dataclass(frozen=True)
class Catalog:
    topics: tuple[Topic, ...]
    descriptions: dict[str, str]


@dataclass(frozen=True)
class Route:
    topics: tuple[Topic, ...]
    tables: tuple[str, ...]

    @property
    def matched(self) -> bool:
        return bool(self.topics)


def load_catalog(path: Path) -> Catalog:
    if not path.is_file():
        raise ConfigError(f"Routing map not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError("Routing map must be a mapping.")
    topics_raw = raw.get("topics")
    tables_raw = raw.get("tables") or {}
    if not isinstance(topics_raw, list) or not topics_raw:
        raise ConfigError("Routing map needs at least one topic.")
    if not isinstance(tables_raw, dict):
        raise ConfigError("Routing map tables section must be a mapping.")

    topics: list[Topic] = []
    seen: set[str] = set()
    for entry in topics_raw:
        if not isinstance(entry, dict):
            raise ConfigError("Each topic must be a mapping.")
        topic_id = entry.get("id")
        title = entry.get("title")
        tables = entry.get("tables")
        synonyms = entry.get("synonyms")
        if not isinstance(topic_id, str) or not topic_id:
            raise ConfigError("Each topic needs an id.")
        if topic_id in seen:
            raise ConfigError(f"Duplicate topic id: {topic_id}")
        seen.add(topic_id)
        if not isinstance(title, str) or not title:
            raise ConfigError(f"Topic {topic_id} needs a title.")
        if not isinstance(tables, list) or not tables or not all(isinstance(t, str) for t in tables):
            raise ConfigError(f"Topic {topic_id} needs table names.")
        if (
            not isinstance(synonyms, list)
            or not synonyms
            or not all(isinstance(s, str) and s.strip() for s in synonyms)
        ):
            raise ConfigError(f"Topic {topic_id} needs synonyms.")
        topics.append(
            Topic(
                id=topic_id,
                title=title,
                tables=tuple(tables),
                synonyms=tuple(s.strip() for s in synonyms),
            )
        )

    descriptions: dict[str, str] = {}
    for name, spec in tables_raw.items():
        if isinstance(spec, dict) and isinstance(spec.get("description"), str):
            descriptions[str(name)] = spec["description"].strip()
        elif isinstance(spec, str):
            descriptions[str(name)] = spec.strip()
    return Catalog(topics=tuple(topics), descriptions=descriptions)


def _matches(question: str, synonym: str) -> bool:
    if any(ord(char) > 127 for char in synonym):
        return synonym.casefold() in question.casefold()
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(synonym)}(?![A-Za-z0-9_])"
    return re.search(pattern, question, flags=re.IGNORECASE) is not None


def route_question(question: str, catalog: Catalog) -> Route:
    """Return every topic whose synonyms appear in the question."""
    scored: list[tuple[int, Topic]] = []
    for topic in catalog.topics:
        score = 0
        for synonym in topic.synonyms:
            if _matches(question, synonym):
                score += max(1, len(synonym))
        if score:
            scored.append((score, topic))
    scored.sort(key=lambda item: item[0], reverse=True)
    topics = tuple(topic for _, topic in scored)
    tables: list[str] = []
    for topic in topics:
        for table in topic.tables:
            if table not in tables:
                tables.append(table)
    return Route(topics=topics, tables=tuple(tables))
