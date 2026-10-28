"""Metric catalogue. Matching is deterministic and does not call a model."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields
from datetime import date, datetime
from pathlib import Path

import yaml

from src.config import ROOT, ConfigError
from src.routing import _matches

_FIELDS = (
    "id",
    "title",
    "synonyms",
    "table",
    "grain",
    "additive_over",
    "definition",
    "owner",
    "effective_from",
    "supersedes",
    "exceptions",
)

# Fields a catalogue entry may carry but does not have to. ``measure`` is the
# column an alert sums; a metric without one is still answerable by a question,
# because a question can be answered in prose, and an alert cannot.
_OPTIONAL_FIELDS = ("measure",)

# A measure has to be a plain column name, because it is interpolated into the
# one template SQL statement an alert runs. Anything else is not a name.
_MEASURE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

DEFAULT_METRICS = ROOT / "config" / "metrics.yaml"


@dataclass(frozen=True)
class Metric:
    id: str
    title: str
    synonyms: tuple[str, ...]
    table: str
    grain: tuple[str, ...]
    additive_over: tuple[str, ...]
    definition: str
    owner: str
    effective_from: date
    supersedes: str | None
    exceptions: str
    # The column a value for this metric is summed from. Optional, because a
    # question can be answered without one and an alert cannot: a metric with
    # no measure is refused when an alert definition names it.
    measure: str | None = None


def load_metrics(path: Path | None = None) -> list[Metric]:
    catalogue = Path(path) if path is not None else DEFAULT_METRICS
    if not catalogue.is_file():
        raise ConfigError(f"Metric catalogue not found: {catalogue}")
    raw = yaml.safe_load(catalogue.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not raw:
        raise ConfigError("Metric catalogue must be a list of metrics.")
    metrics: list[Metric] = []
    seen: set[str] = set()
    for entry in raw:
        metrics.append(_parse(entry, seen))
    _validate_supersedes(metrics)
    return metrics


def _parse(entry: object, seen: set[str]) -> Metric:
    if not isinstance(entry, dict):
        raise ConfigError("Each metric must be a mapping.")
    unknown = sorted(set(entry) - set(_FIELDS) - set(_OPTIONAL_FIELDS))
    if unknown:
        raise ConfigError(f"Unknown metric fields: {', '.join(unknown)}.")
    missing = [name for name in _FIELDS if name not in entry]
    if missing:
        raise ConfigError(f"Metric is missing fields: {', '.join(missing)}.")

    metric_id = _text(entry["id"], "id")
    if metric_id in seen:
        raise ConfigError(f"Duplicate metric id: {metric_id}")
    seen.add(metric_id)

    supersedes = entry["supersedes"]
    if supersedes is not None:
        supersedes = _text(supersedes, "supersedes")

    measure = entry.get("measure")
    if measure is not None:
        measure = _text(measure, "measure", allow_empty=True) or None

    return Metric(
        id=metric_id,
        title=_text(entry["title"], "title"),
        synonyms=_strings(entry["synonyms"], "synonyms", allow_empty=False),
        table=_text(entry["table"], "table"),
        grain=_strings(entry["grain"], "grain", allow_empty=False),
        additive_over=_strings(entry["additive_over"], "additive_over", allow_empty=True),
        definition=_text(entry["definition"], "definition"),
        owner=_text(entry["owner"], "owner"),
        effective_from=_as_date(entry["effective_from"]),
        supersedes=supersedes,
        exceptions=_text(entry["exceptions"], "exceptions", allow_empty=True),
        measure=measure,
    )


def _text(value: object, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"Metric field {field} must be a string.")
    cleaned = value.strip()
    if not cleaned and not allow_empty:
        raise ConfigError(f"Metric field {field} must not be empty.")
    return cleaned


def _strings(value: object, field: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ConfigError(f"Metric field {field} must be a list of strings.")
    if not value and not allow_empty:
        raise ConfigError(f"Metric field {field} must not be empty.")
    return tuple(item.strip() for item in value)


def _as_date(value: object) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ConfigError("Metric field effective_from must be YYYY-MM-DD.") from exc
    raise ConfigError("Metric field effective_from must be a date.")


def _validate_supersedes(metrics: list[Metric]) -> None:
    """Reject dangling targets, cross-table links, and cycles. Dates are not involved."""
    by_id = {metric.id: metric for metric in metrics}
    for metric in metrics:
        if metric.supersedes is None:
            continue
        target = by_id.get(metric.supersedes)
        if target is None:
            raise ConfigError(
                f"Metric {metric.id} supersedes {metric.supersedes}, which is not in the catalogue."
            )
        if target.table != metric.table:
            raise ConfigError(
                f"Metric {metric.id} ({metric.table}) cannot supersede {target.id} ({target.table})."
            )
    for start in metrics:
        seen: list[str] = []
        current = start
        while current.supersedes is not None:
            if current.id in seen:
                loop = seen[seen.index(current.id) :] + [current.id]
                raise ConfigError(f"Metric supersede cycle: {' -> '.join(loop)}.")
            seen.append(current.id)
            current = by_id[current.supersedes]


def active_metrics(metrics: list[Metric], today: date | None = None) -> list[Metric]:
    """Metrics whose effective date has arrived and that no already-effective metric replaces."""
    current = today or date.today()
    replaced = {
        metric.supersedes
        for metric in metrics
        if metric.supersedes and metric.effective_from <= current
    }
    chosen = [
        metric
        for metric in metrics
        if metric.effective_from <= current and metric.id not in replaced
    ]
    chosen.sort(key=lambda metric: metric.id)
    return chosen


def match_metrics(
    question: str,
    metrics: list[Metric] | None = None,
    *,
    today: date | None = None,
) -> list[Metric]:
    """Return every active metric whose synonyms appear in the question.

    ASCII synonyms use a word-boundary match. Synonyms with non-ASCII
    characters use a case-folded substring match. The same question always
    returns the same ids, sorted by id.
    """
    catalogue = metrics if metrics is not None else load_metrics(DEFAULT_METRICS)
    matched = [
        metric
        for metric in active_metrics(catalogue, today)
        if any(_matches(question, synonym) for synonym in metric.synonyms)
    ]
    matched.sort(key=lambda metric: metric.id)
    return matched


def definition_hash(metric: Metric) -> str:
    """First 12 hex characters of the sha256 of the definition text."""
    return hashlib.sha256(metric.definition.encode("utf-8")).hexdigest()[:12]


# The convention the catalogue has carried since it was written: an entry no
# business owner has confirmed says PLACEHOLDER in its definition text and
# names `placeholder` as its owner. Both markers mean "nobody signed this off".
PLACEHOLDER_MARKER = "PLACEHOLDER"
PLACEHOLDER_OWNER = "placeholder"


def is_placeholder(metric: Metric) -> bool:
    """True when this metric definition has not been confirmed by a business owner.

    The test is deterministic and reads data only, never a model: the
    definition text contains ``PLACEHOLDER`` (in any case), or the owner is
    literally ``placeholder``. Either marker alone is enough, because a
    definition that still says PLACEHOLDER is unconfirmed whoever is named as
    its owner, and an owner called ``placeholder`` has not accepted anything.

    The catalogue carries both markers together, so the shipped file has
    exactly three placeholders and one confirmed metric. A YAML comment is not
    data: a ``# PLACEHOLDER`` note on a confirmed-looking line is invisible
    here, which is why the markers are part of the values, not of the comments.
    """
    text = (metric.definition or "").upper()
    owner = (metric.owner or "").strip().casefold()
    return PLACEHOLDER_MARKER in text or owner == PLACEHOLDER_OWNER


def measure_column(metric: Metric) -> str | None:
    """The column this metric's value is summed from, or None when it has none.

    A catalogue entry that names no measure, or names something that is not a
    plain column name, cannot be summed. An alert definition that names such a
    metric is refused when it is written, rather than stored and found
    unresolvable by a worker at three in the morning.
    """
    raw = metric.measure
    if not isinstance(raw, str):
        return None
    name = raw.strip()
    return name if _MEASURE_NAME.fullmatch(name) else None


def _cache_value(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, tuple):
        return [_cache_value(item) for item in value]
    if isinstance(value, list):
        return [_cache_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _cache_value(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def metric_cache_key(
    metric: Metric,
    *,
    model: str,
    prompt_version: str,
    source_id: str | None = None,
    source_sha256: str | None = None,
    data_window: str | None = None,
) -> str:
    """12 hex chars covering the metric, the model id, and the prompt version.

    Fields are read from the dataclass, so a field added later is part of the
    key without a hand-written list. A declared source also binds ``source_id``
    and its file sha256, so replacing that file misses the previous answer. The
    demo warehouse is rebuilt on a moving date window, so ``data_window`` binds
    the newest date the rows actually cover; omitting every optional field
    leaves the key unchanged.
    """
    record = {item.name: _cache_value(getattr(metric, item.name)) for item in fields(metric)}
    document: dict[str, object] = {"metric": record, "model": model, "prompt_version": prompt_version}
    if source_id is not None or source_sha256 is not None:
        document["source_id"] = source_id
        document["source_sha256"] = source_sha256
    if data_window is not None:
        document["data_window"] = data_window
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]
