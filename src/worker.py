"""The background worker: one tick, every due alert definition, once.

``python -m src.worker`` runs one tick and exits. Cron or systemd starts it,
so nothing in this module needs the web app, a browser session, a language
model, the network, or an operator: the definition is data, the SQL is a
template, the comparison is arithmetic (ADR 0003).

What one tick does, for each definition that is live or paused:

1. Resolve the window from the definition's cadence and local time.
2. Claim the fire key in the instance's alert database. If the claim already
   belongs to somebody, this window has been evaluated and the tick records a
   duplicate and moves on.
3. Refuse the run if the definition's owner may no longer read its metric, and
   say so in the audit row. The permission gate runs before any SQL.
4. Sum the metric's measure over the window through the read-only adapter, so
   the statement passes the same SELECT allowlist as a asked question.
5. Compare the sum with the constant, record the fire, and write one audit row.

Every definition considered produces exactly one audit event, whatever
happened: fired, did not fire, too little data, duplicate, skipped because
paused, refused, or failed. A paused definition is considered — it is audited
as skipped — and is never evaluated.

A tick writes audit rows and fire rows. It does not send anything: a
``FireOutcome`` with ``should_notify`` true is the input the notification
capability (ticket #21) consumes, and it carries the definition, the fire key,
the window, the value, the previous value and the verdict so that consumer
never has to re-derive one.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Callable

from src.alert_eval import (
    FIRE,
    INSUFFICIENT_DATA,
    NO_FIRE,
    Window,
    evaluate,
    fire_key,
    window_for,
)
from src.alerts import CONFIRMED, PAUSED, AlertDefinition, AlertService
from src.audit import AuditLog
from src.auth import user_named
from src.capabilities import ALERT, authorize
from src.config import Settings, load_settings
from src.db.factory import build_adapter
from src.fires import FireStore
from src.metrics import Metric, definition_hash, measure_column
from src.models import User
from src.routing import Catalog, load_catalog

# The actor every worker-written audit row names. A fire is not a person's
# action, and naming the definition's owner here would read as if it were.
WORKER_USERNAME = "worker"
WORKER_ROLE = "system"

# Outcomes of one considered definition. Every one of them is audited.
OUTCOME_FIRED = "fired"
OUTCOME_NOT_FIRED = "not_fired"
OUTCOME_INSUFFICIENT = "insufficient_data"
OUTCOME_DUPLICATE = "duplicate"
OUTCOME_SKIPPED = "skipped"
OUTCOME_REFUSED = "refused"
OUTCOME_FAILED = "failed"
OUTCOMES = (
    OUTCOME_FIRED,
    OUTCOME_NOT_FIRED,
    OUTCOME_INSUFFICIENT,
    OUTCOME_DUPLICATE,
    OUTCOME_SKIPPED,
    OUTCOME_REFUSED,
    OUTCOME_FAILED,
)

# The outcomes an operator has to do something about, and the exit code that
# says so. A cron job that fails quietly is worse than one that mails.
_ATTENTION = frozenset({OUTCOME_REFUSED, OUTCOME_FAILED})

# Audit event types. The capability is always ``alert``; the event type says
# which outcome this run was, so one grep answers "what did the worker do".
EVENT_FIRED = "alert_fired"
EVENT_NOT_FIRED = "alert_not_fired"
EVENT_INSUFFICIENT = "alert_insufficient_data"
EVENT_DUPLICATE = "alert_duplicate"
EVENT_SKIPPED = "alert_skipped"
EVENT_REFUSED = "alert_run_refused"
EVENT_FAILED = "alert_failed"

_EVENT_FOR = {
    OUTCOME_FIRED: EVENT_FIRED,
    OUTCOME_NOT_FIRED: EVENT_NOT_FIRED,
    OUTCOME_INSUFFICIENT: EVENT_INSUFFICIENT,
    OUTCOME_DUPLICATE: EVENT_DUPLICATE,
    OUTCOME_SKIPPED: EVENT_SKIPPED,
    OUTCOME_REFUSED: EVENT_REFUSED,
    OUTCOME_FAILED: EVENT_FAILED,
}

_STATUS_FOR = {
    OUTCOME_FIRED: "ok",
    OUTCOME_NOT_FIRED: "ok",
    OUTCOME_INSUFFICIENT: "ok",
    OUTCOME_DUPLICATE: "ok",
    OUTCOME_SKIPPED: "skipped",
    OUTCOME_REFUSED: "denied",
    OUTCOME_FAILED: "failed",
}

_OUTCOME_FOR_VERDICT = {
    FIRE: OUTCOME_FIRED,
    NO_FIRE: OUTCOME_NOT_FIRED,
    INSUFFICIENT_DATA: OUTCOME_INSUFFICIENT,
}

# The day a window is measured on. Every table the catalogue binds records one
# row per event_date, so a window is a date range on that column.
EVENT_DATE = "event_date"
VALUE_ALIAS = "value"

DEFAULT_INTERVAL_SECONDS = 300

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _ident(name: str) -> str:
    """Quote a column or table name. A name that is not one is not quoted.

    The measure and the table come from configuration, and configuration is
    not SQL: it is checked here so a stray quote in a catalogue entry cannot
    reach the statement that the allowlist then reads.
    """
    if not isinstance(name, str) or not _IDENT.fullmatch(name):
        raise ValueError(f"{name!r} is not a column or table name.")
    return f'"{name}"'


def sum_sql(metric: Metric, measure: str, window: Window) -> str:
    """The one statement a fire runs: the measure summed over the window."""
    return (
        f"SELECT SUM({_ident(measure)}) AS {VALUE_ALIAS} "
        f"FROM {_ident(metric.table)} "
        f"WHERE {_ident(EVENT_DATE)} >= '{window.start.isoformat()}' "
        f"AND {_ident(EVENT_DATE)} <= '{window.end.isoformat()}'"
    )


@dataclass(frozen=True)
class FireOutcome:
    """What one considered definition produced, in full.

    This is the hand-off to the notification capability: it carries the
    definition (metric, comparison, constant, recipients, owner), the fire key,
    the window, the value, the previous value the comparison used, and the
    verdict. Nothing here needs a database to read, and nothing here has been
    sent to anybody.

    ``outcome`` is the run's result (``fired``, ``duplicate``, ``skipped``…);
    ``verdict`` is the comparison's, and is present only when a comparison was
    actually made.
    """

    definition: AlertDefinition
    outcome: str
    fire_key: str
    window_start: date
    window_end: date
    value: float | None = None
    previous: float | None = None
    verdict: str | None = None
    previous_window_end: date | None = None
    metric_title: str | None = None
    message: str = ""
    error: str | None = None
    audited: bool = True

    @property
    def should_notify(self) -> bool:
        """True only for a fire whose comparison triggered. No other outcome sends."""
        return self.outcome == OUTCOME_FIRED

    @property
    def recipients(self) -> tuple[str, ...]:
        return self.definition.recipients

    @property
    def alert_id(self) -> int:
        return self.definition.id


@dataclass(frozen=True)
class _Evaluation:
    value: float | None
    previous: float | None
    previous_window_end: date | None
    verdict: str
    sql: str | None


class _RunRefused(Exception):
    """The run never reached a comparison. Carries the stable reason code."""

    def __init__(self, reason: str, message: str, *, status: str):
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.status = status


def _topic_titles(catalog: Catalog) -> dict[str, str]:
    """Map each warehouse table to the topic title a person knows it by.

    The same mapping the definition writer passes to ``authorize``, so a
    refusal here reads the way it read when the definition was written.
    """
    titles: dict[str, str] = {}
    for topic in catalog.topics:
        for table in topic.tables:
            titles.setdefault(table, topic.title)
    return titles


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Worker:
    """Evaluate every due, live alert definition for one instance, once."""

    def __init__(
        self,
        *,
        service: AlertService,
        adapter: object,
        fires: FireStore,
        titles: dict[str, str] | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.service = service
        self.adapter = adapter
        self.fires = fires
        self._titles = dict(titles or {})
        # The one clock. Tests pass a fixed time; nothing here sleeps.
        self._clock = clock or _utc_now

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        audit: AuditLog | None = None,
        catalog: Catalog | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> Worker:
        """Build the worker the way a deployment does: everything from settings."""
        log = audit if audit is not None else AuditLog(settings.audit_path)
        routes = catalog if catalog is not None else load_catalog(settings.routing_path)
        return cls(
            service=AlertService.from_settings(settings, audit=log, catalog=routes),
            adapter=build_adapter(settings),
            fires=FireStore(settings.alerts_path),
            titles=_topic_titles(routes),
            clock=clock,
        )

    # -- one tick ---------------------------------------------------------

    def tick(self) -> list[FireOutcome]:
        """Consider every live or paused definition, once, and return the outcomes.

        A draft is not scheduled and a superseded definition has been retired,
        so neither is considered and neither is audited: an event per tick for
        a definition that will not run would bury the events that matter.
        """
        now = self._clock()
        outcomes: list[FireOutcome] = []
        for definition in self.service.definitions():
            if definition.state not in (CONFIRMED, PAUSED):
                continue
            outcomes.append(self._consider(definition, now))
        return outcomes

    def _consider(self, definition: AlertDefinition, now: datetime) -> FireOutcome:
        window = window_for(now, definition.local_time, definition.window_days)
        key = fire_key(definition.id, window.end)
        metric = self._metric(definition.metric_id)

        # A paused definition is still ticked: its skip is audited, so the log
        # says the worker saw it and did nothing on purpose. It is never
        # claimed, never resolved and never evaluated.
        if definition.state == PAUSED:
            return self._record(
                definition,
                OUTCOME_SKIPPED,
                window,
                key,
                metric=metric,
                message=(
                    f"Alert definition #{definition.id} is paused, so the window "
                    f"{window.start} to {window.end} was not evaluated."
                ),
            )

        claimed = self.fires.claim(
            fire_key=key,
            alert_id=definition.id,
            window_start=window.start,
            window_end=window.end,
            at=_stamp(now),
        )
        if not claimed:
            return self._record(
                definition,
                OUTCOME_DUPLICATE,
                window,
                key,
                metric=metric,
                message=(
                    f"The window {window.start} to {window.end} of alert definition "
                    f"#{definition.id} has already been evaluated."
                ),
            )

        try:
            evaluation = self._evaluate(definition, metric, window)
        except _RunRefused as refusal:
            # Nothing was compared, so the claim is given back and the next
            # tick may try the same window again.
            self.fires.release(key)
            return self._record(
                definition,
                OUTCOME_FAILED if refusal.status == "failed" else OUTCOME_REFUSED,
                window,
                key,
                metric=metric,
                message=refusal.message,
                error=f"{refusal.reason}: {refusal.message}",
                status=refusal.status,
            )
        except Exception as exc:  # one broken definition must not stop the tick
            self.fires.release(key)
            return self._record(
                definition,
                OUTCOME_FAILED,
                window,
                key,
                metric=metric,
                message=(
                    f"The window {window.start} to {window.end} of alert definition "
                    f"#{definition.id} could not be evaluated: {exc}"
                ),
                error=f"evaluation_failed: {exc}",
                status="failed",
            )

        self.fires.complete(
            key,
            value=evaluation.value,
            previous=evaluation.previous,
            verdict=evaluation.verdict,
        )
        return self._record(
            definition,
            _OUTCOME_FOR_VERDICT[evaluation.verdict],
            window,
            key,
            metric=metric,
            message=self._message(definition, window, evaluation),
            value=evaluation.value,
            previous=evaluation.previous,
            verdict=evaluation.verdict,
            previous_window_end=evaluation.previous_window_end,
            sql=evaluation.sql,
        )

    # -- resolving and evaluating ----------------------------------------

    def _evaluate(
        self, definition: AlertDefinition, metric: Metric | None, window: Window
    ) -> _Evaluation:
        """Resolve the window's value and compare it. Raises ``_RunRefused``."""
        if metric is None:
            raise _RunRefused(
                "metric_unknown",
                f"The metric {definition.metric_id!r} is no longer in the metric catalogue.",
                status="failed",
            )
        measure = measure_column(metric)
        if measure is None:
            raise _RunRefused(
                "metric_no_measure",
                f"The metric {metric.title} names no measure to sum.",
                status="failed",
            )

        # The permission gate, before any SQL. The owner is the person who
        # confirmed the definition, and a role can change under a stored
        # definition; a run that its owner may no longer make is refused
        # rather than executed on their behalf.
        owner = user_named(definition.owner, self.service.users_path)
        if owner is None:
            raise _RunRefused(
                "owner_unknown",
                f"The owner {definition.owner} is no longer in the user directory.",
                status="failed",
            )
        decision = authorize(owner, ALERT, (metric.table,), display=self._titles)
        if not decision.allowed:
            raise _RunRefused(
                decision.reason or "not_allowed",
                f"The alert definition cannot run. {decision.message}",
                status="denied",
            )

        sql = sum_sql(metric, measure, window)
        result = self.adapter.execute_select(sql, allowed_tables={metric.table}, max_rows=1)
        value = result.rows[0].get(VALUE_ALIAS) if result.rows else None
        if value is not None:
            value = float(value)

        earlier = self.fires.previous_value(definition.id, before=window.end)
        previous, previous_end = earlier if earlier is not None else (None, None)
        verdict = evaluate(value, previous, definition.comparison, definition.constant)
        return _Evaluation(
            value=value,
            previous=previous,
            previous_window_end=previous_end,
            verdict=verdict,
            sql=sql,
        )

    def _metric(self, metric_id: str) -> Metric | None:
        for metric in self.service.metrics:
            if metric.id == metric_id:
                return metric
        return None

    @staticmethod
    def _message(definition: AlertDefinition, window: Window, evaluation: _Evaluation) -> str:
        value = "no rows" if evaluation.value is None else f"{evaluation.value:,.2f}"
        if evaluation.verdict == INSUFFICIENT_DATA:
            return (
                f"Alert definition #{definition.id} has too little data for "
                f"{window.start} to {window.end}: the comparison needs a value and a "
                "previous value, and one of them is missing."
            )
        if evaluation.verdict == FIRE:
            head = "met"
        else:
            head = "was not met"
        return (
            f"Alert definition #{definition.id} {head}: {value} over {window.start} to "
            f"{window.end} against {definition.comparison} {definition.constant:g}."
        )

    # -- audit ------------------------------------------------------------

    def _record(
        self,
        definition: AlertDefinition,
        outcome: str,
        window: Window,
        key: str,
        *,
        metric: Metric | None,
        message: str,
        value: float | None = None,
        previous: float | None = None,
        verdict: str | None = None,
        previous_window_end: date | None = None,
        error: str | None = None,
        status: str | None = None,
        sql: str | None = None,
    ) -> FireOutcome:
        """Write exactly one audit event for this definition, and return the outcome."""
        audited = self._audit(
            definition,
            outcome,
            window,
            key,
            metric=metric,
            message=message,
            error=error,
            status=status or _STATUS_FOR[outcome],
            sql=sql,
        )
        return FireOutcome(
            definition=definition,
            outcome=outcome,
            fire_key=key,
            window_start=window.start,
            window_end=window.end,
            value=value,
            previous=previous,
            verdict=verdict,
            previous_window_end=previous_window_end,
            metric_title=None if metric is None else " ".join(metric.title.split()),
            message=message if audited else f"{message} The usage log could not be written.",
            error=error,
            audited=audited,
        )

    def _audit(
        self,
        definition: AlertDefinition,
        outcome: str,
        window: Window,
        key: str,
        *,
        metric: Metric | None,
        message: str,
        error: str | None,
        status: str,
        sql: str | None,
    ) -> bool:
        """One row per considered definition, through the shared writer."""
        question = (
            f"{outcome} alert definition #{definition.id} "
            f"window {window.start} to {window.end} "
            f"fire_key {key} "
            f"({definition.comparison} {definition.constant:g}, "
            f"owner {definition.owner})"
        )
        try:
            self.service.audit.record_event(
                username=WORKER_USERNAME,
                role=WORKER_ROLE,
                status=status,
                event_type=_EVENT_FOR[outcome],
                capability=ALERT,
                question=question,
                tables=(metric.table,) if metric is not None else (),
                sql=sql,
                row_count=None,
                error=error or (message if outcome in _ATTENTION else None),
                metric_id=None if metric is None else metric.id,
                definition_hash=None if metric is None else definition_hash(metric),
            )
            return True
        except Exception:
            return False


# --- the command ----------------------------------------------------------


def _report(outcomes: list[FireOutcome]) -> int:
    """Print one line per definition and return the exit code for the tick."""
    for outcome in outcomes:
        value = "" if outcome.value is None else f" value={outcome.value:.2f}"
        previous = "" if outcome.previous is None else f" previous={outcome.previous:.2f}"
        print(
            f"{outcome.outcome:<17} alert #{outcome.alert_id:<4} "
            f"{outcome.window_start}..{outcome.window_end}"
            f"{value}{previous} {outcome.fire_key}"
        )
    if not outcomes:
        print("0 alert definitions were due")
    return 1 if any(outcome.outcome in _ATTENTION for outcome in outcomes) else 0


def main(argv: list[str] | None = None) -> int:
    """Run one tick, or keep running ticks with ``--loop``.

    One tick is the cron and systemd form:

        */15 * * * *  cd /srv/day1 && .venv/bin/python -m src.worker

    A tick is cheap when nothing is due, and a repeated tick is harmless: the
    fire key makes a second evaluation of the same window impossible.
    """
    parser = argparse.ArgumentParser(
        prog="python -m src.worker",
        description="Evaluate every due, live alert definition for one instance.",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="keep ticking instead of running one tick and exiting",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        metavar="SECONDS",
        help=f"seconds to wait between ticks in loop mode (default {DEFAULT_INTERVAL_SECONDS})",
    )
    args = parser.parse_args(argv)
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")

    settings = load_settings()
    worker = Worker.from_settings(
        settings,
        audit=AuditLog(settings.audit_path),
        catalog=load_catalog(settings.routing_path),
    )

    if not args.loop:
        return _report(worker.tick())

    try:
        while True:
            _report(worker.tick())
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
