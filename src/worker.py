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
6. If the comparison triggered, deliver the notification through
   ``src.notify``: each recipient is re-resolved and re-authorized *now*, the
   permitted ones receive one email, and the blocked ones are skipped and named
   in an audit row of their own (see ``src/notify.py`` and ticket #21).

Every definition considered produces exactly one outcome audit event, whatever
happened: fired, did not fire, too little data, duplicate, skipped because
paused, refused, suppressed, or failed. A per-recipient refusal is an
additional event, because it names a person rather than the definition. A
paused definition is considered — it is audited as skipped — and is never
evaluated.

A tick writes audit rows, fire rows, and at most one email per triggering fire.
An all-blocked fire is ``suppressed``: nothing was sent, and that is recorded as
its own outcome rather than as a success. A delivery that fails three times
stops, is recorded as ``failed`` with a terminal event, and tells the
definition's owner once.

The scheduled command refuses to run when no mail transport is configured. A
cron job that ticks and quietly delivers nothing is the worst outcome, so a
missing ``SMTP_HOST`` is an audited refusal with a non-zero exit code.

The worker also keeps the instance's own account of itself, in the settings
database (issue #28). One row per delivery attempt records the timestamp, the
outcome and the redacted reason, so ``src.delivery_health`` can answer "is
delivery alive?" from stored state alone. And the identity written at first
configuration — one UUID, the host, the path — is checked before anything is
sent: a process that is not that instance refuses to deliver, names both hosts,
and says how an operator confirms a move that was intended.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass, replace
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
from src.capabilities import ADMIN, ALERT, authorize
from src.config import ConfigError, Settings, load_settings
from src.crypto import SecretKeyError
from src.instance import InstanceState
from src.mail_settings import resolve_mail_settings
from src.db.factory import build_adapter
from src.fires import FireStore
from src.metrics import Metric, definition_hash, measure_column
from src.models import User
from src.notify import (
    DELIVERY_DELIVERED,
    DELIVERY_FAILED,
    DELIVERY_SUPPRESSED,
    Delivery,
    MailSender,
    Notifier,
    build_sender,
    missing_smtp,
)
from src.redaction import redact_transport_error
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
# The comparison triggered, but nobody who was named may still read the metric,
# so no notification was sent. Not a success: a breach reported to no one.
OUTCOME_SUPPRESSED = "suppressed"
OUTCOMES = (
    OUTCOME_FIRED,
    OUTCOME_NOT_FIRED,
    OUTCOME_INSUFFICIENT,
    OUTCOME_DUPLICATE,
    OUTCOME_SKIPPED,
    OUTCOME_REFUSED,
    OUTCOME_FAILED,
    OUTCOME_SUPPRESSED,
)

# The outcomes an operator has to do something about, and the exit code that
# says so. A cron job that fails quietly is worse than one that mails. A
# suppressed fire belongs here: it fired and reached nobody, which is exactly
# the silence this feature exists to prevent.
_ATTENTION = frozenset({OUTCOME_REFUSED, OUTCOME_FAILED, OUTCOME_SUPPRESSED})

# Audit event types. The capability is always ``alert``; the event type says
# which outcome this run was, so one grep answers "what did the worker do".
EVENT_FIRED = "alert_fired"
EVENT_NOT_FIRED = "alert_not_fired"
EVENT_INSUFFICIENT = "alert_insufficient_data"
EVENT_DUPLICATE = "alert_duplicate"
EVENT_SKIPPED = "alert_skipped"
EVENT_REFUSED = "alert_run_refused"
EVENT_FAILED = "alert_failed"
EVENT_SUPPRESSED = "alert_suppressed"
# Delivery events. A blocked recipient is its own event because it names one
# person; a delivery that never got through is the terminal failure event.
EVENT_RECIPIENT_BLOCKED = "alert_recipient_blocked"
EVENT_DELIVERY_FAILED = "alert_delivery_failed"
# The scheduled command refused to start because it had no mail transport.
EVENT_DELIVERY_UNCONFIGURED = "alert_delivery_unconfigured"
# The instance this database belongs to is not the instance this process is.
# One event says a delivery was refused, the other records a confirmed move.
EVENT_IDENTITY_MISMATCH = "instance_identity_mismatch"
EVENT_IDENTITY_MOVED = "instance_identity_moved"

_EVENT_FOR = {
    OUTCOME_FIRED: EVENT_FIRED,
    OUTCOME_NOT_FIRED: EVENT_NOT_FIRED,
    OUTCOME_INSUFFICIENT: EVENT_INSUFFICIENT,
    OUTCOME_DUPLICATE: EVENT_DUPLICATE,
    OUTCOME_SKIPPED: EVENT_SKIPPED,
    OUTCOME_REFUSED: EVENT_REFUSED,
    OUTCOME_FAILED: EVENT_FAILED,
    OUTCOME_SUPPRESSED: EVENT_SUPPRESSED,
}

_STATUS_FOR = {
    OUTCOME_FIRED: "ok",
    OUTCOME_NOT_FIRED: "ok",
    OUTCOME_INSUFFICIENT: "ok",
    OUTCOME_DUPLICATE: "ok",
    OUTCOME_SKIPPED: "skipped",
    OUTCOME_REFUSED: "denied",
    OUTCOME_FAILED: "failed",
    # Neither ok nor failed: the fire was real and the audience was empty.
    OUTCOME_SUPPRESSED: "suppressed",
}

_OUTCOME_FOR_VERDICT = {
    FIRE: OUTCOME_FIRED,
    NO_FIRE: OUTCOME_NOT_FIRED,
    INSUFFICIENT_DATA: OUTCOME_INSUFFICIENT,
}


def _event_type(outcome: str, delivery: Delivery | None) -> str:
    """The audit event type for one outcome, naming a delivery failure as one."""
    if outcome == OUTCOME_FAILED and delivery is not None and delivery.status == DELIVERY_FAILED:
        return EVENT_DELIVERY_FAILED
    return _EVENT_FOR[outcome]


# The day a window is measured on. Every table the catalogue binds records one
# row per event_date, so a window is a date range on that column.
EVENT_DATE = "event_date"
VALUE_ALIAS = "value"

DEFAULT_INTERVAL_SECONDS = 300

# The exit code when the command refuses to start because it could not deliver a
# fire. 1 is "a definition was refused or failed"; 2 is "the worker itself is
# not fit to run", which is a different thing for whoever reads the alert mail.
# 3 is "this process is not the instance that is configured to send": a moved or
# copied directory, which is an operator decision and not a retry.
EXIT_UNCONFIGURED = 2
EXIT_IDENTITY = 3

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

    This is the record of one fire: it carries the definition (metric,
    comparison, constant, recipients, owner), the fire key, the window, the
    value, the previous value the comparison used, the verdict, and — when the
    comparison triggered — what happened to the notification (``delivery``).

    ``outcome`` is the run's result (``fired``, ``duplicate``, ``skipped``,
    ``suppressed``…); ``verdict`` is the comparison's, and is present only when
    a comparison was actually made.
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
    # Absent when the comparison did not trigger, when the definition was never
    # evaluated, or when the worker has no sender wired at all.
    delivery: Delivery | None = None

    @property
    def should_notify(self) -> bool:
        """True only for a fire whose comparison triggered. No other outcome sends."""
        return self.outcome == OUTCOME_FIRED

    @property
    def recipients(self) -> tuple[str, ...]:
        return self.definition.recipients

    @property
    def notification_recipients(self) -> tuple[str, ...]:
        """Who the notification actually reached. Empty when nothing was sent."""
        return () if self.delivery is None else self.delivery.recipients

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
        notifier: Notifier | None = None,
        state: InstanceState | None = None,
        confirm_instance_move: bool = False,
    ):
        self.service = service
        self.adapter = adapter
        self.fires = fires
        self._titles = dict(titles or {})
        # The one clock. Tests pass a fixed time; nothing here sleeps.
        self._clock = clock or _utc_now
        # The delivery seam. None means this worker has no mail transport at
        # all: it evaluates and audits, and sends nothing. The scheduled
        # command never runs in that state (see ``main``), so the only way to
        # get here is a library call or a test.
        self.notifier = notifier
        # The instance's own record: its identity and its delivery health, in
        # the settings database. None is the pre-#28 worker a test builds by
        # hand; ``from_settings`` always wires it, so a deployment records an
        # attempt and refuses a moved instance without being asked to.
        self.state = state
        self.confirm_instance_move = confirm_instance_move
        # Resolved once per tick, so one tick asks the identity question once
        # and every fire in it gets the same answer.
        self._identity_resolved = False
        self._identity_refusal_reason: str | None = None

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        audit: AuditLog | None = None,
        catalog: Catalog | None = None,
        clock: Callable[[], datetime] | None = None,
        sender: MailSender | None = None,
        sleep: Callable[[float], None] | None = None,
        state: InstanceState | None = None,
    ) -> Worker:
        """Build the worker the way a deployment does: everything from settings.

        ``sender`` overrides the transport the settings describe, which is what
        a test injects. Without an override the sender comes from the one mail
        store: the encrypted settings database, then ``SMTP_*``. When neither
        names a host there is no sender, and the notifier reports that rather
        than pretending a notification was sent. A stored secret that cannot
        be decrypted raises; it is not replaced with the environment password.
        ``sleep`` is the pause between delivery attempts, injected so no test
        waits. ``state`` overrides the instance record, which is otherwise the
        settings database itself.
        """
        settings = resolve_mail_settings(settings)
        log = audit if audit is not None else AuditLog(settings.audit_path)
        routes = catalog if catalog is not None else load_catalog(settings.routing_path)
        titles = _topic_titles(routes)
        transport = sender if sender is not None else build_sender(settings)
        return cls(
            service=AlertService.from_settings(settings, audit=log, catalog=routes),
            adapter=build_adapter(settings),
            fires=FireStore(settings.alerts_path),
            titles=titles,
            clock=clock,
            # Built through the guarded constructor, not directly: that is what
            # gives the notifier the delivery guard's storage, so a password the
            # mail server has rejected three times still stops the fourth tick.
            notifier=Notifier.from_settings(
                settings,
                sender=transport,
                titles=titles,
                sleep=sleep,
                clock=clock,
            ),
            state=(
                state
                if state is not None
                else InstanceState(
                    settings.settings_path, hostname=settings.instance_hostname
                )
            ),
            confirm_instance_move=settings.confirm_instance_move,
        )

    # -- the instance this worker is ---------------------------------------

    def identity_refusal(self, *, confirm: bool | None = None) -> str | None:
        """Why this process may not deliver, or None. Asked once per tick.

        The identity row was written when the instance was first configured:
        one UUID, the host it was set up on, and the path of its settings
        database. A process whose host or path differs is not that instance —
        it is a copy — and delivering from it would present the instance's
        stored credential to real recipients as though nothing had happened. So
        nothing is sent, and the refusal names both hosts.

        ``confirm`` is the operator saying "I moved it": ``--confirm-instance-move``
        or ``DAY1_CONFIRM_INSTANCE_MOVE=1``. It re-binds the identity to this
        host and path and writes ``instance_identity_moved`` with where the
        instance came from. Without it the record is never re-pointed, so a
        copied directory cannot adopt itself by being started.
        """
        if self._identity_resolved:
            return self._identity_refusal_reason
        self._identity_resolved = True
        self._identity_refusal_reason = None
        if self.state is None:
            return None
        confirmed = self.confirm_instance_move if confirm is None else confirm
        check = self.state.check(confirm=confirmed)
        if check.adopted and check.moved_reason:
            self._audit_identity(EVENT_IDENTITY_MOVED, check.moved_reason, status="ok")
        if check.refused and check.reason:
            self._identity_refusal_reason = check.reason
            self._audit_identity(EVENT_IDENTITY_MISMATCH, check.reason, status="denied")
        return self._identity_refusal_reason

    def _audit_identity(self, event_type: str, text: str, *, status: str) -> None:
        """One audit row for an instance-identity decision.

        It carries ``capability=admin`` because the only remedy (confirm the
        move, or put the database back where it belongs) is an operator's act.
        A failure to write the row does not change the decision.
        """
        try:
            self.service.audit.record_event(
                username=WORKER_USERNAME,
                role=WORKER_ROLE,
                status=status,
                event_type=event_type,
                capability=ADMIN,
                question=text,
                tables=(),
                sql=None,
                row_count=None,
                error=None if status == "ok" else text,
            )
        except Exception:
            return

    # -- one tick ---------------------------------------------------------

    def tick(self, only: set[int] | None = None) -> list[FireOutcome]:
        """Consider every live or paused definition, once, and return the outcomes.

        ``only`` restricts the pass to the given definition ids. The operator
        command uses it for ``run-now``; a scheduled tick passes nothing and
        therefore considers everything.

        A draft is not scheduled and a superseded definition has been retired,
        so neither is considered and neither is audited: an event per tick for
        a definition that will not run would bury the events that matter.
        """
        now = self._clock()
        # One tick, one answer to "is this process the instance that is
        # configured to send". A mismatch is audited here once and then
        # refuses every notification in the pass.
        self._identity_resolved = False
        self.identity_refusal()
        outcomes: list[FireOutcome] = []
        for definition in self.service.definitions():
            if definition.state not in (CONFIRMED, PAUSED):
                continue
            if only is not None and definition.id not in only:
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
        outcome = _OUTCOME_FOR_VERDICT[evaluation.verdict]
        message = self._message(definition, window, evaluation)
        delivery: Delivery | None = None
        if outcome == OUTCOME_FIRED:
            delivery = self._deliver(definition, metric, window, key, evaluation)
            outcome, message, error, status = self._apply_delivery(outcome, message, delivery)
            if delivery is not None:
                # One row per finished notification, in the instance's own
                # database: last success, last failure and its reason, the
                # consecutive-failure streak, and this attempt's timestamp.
                self._record_delivery_health(definition, key, delivery, now)
                for skipped in delivery.blocked:
                    self._record_blocked(definition, metric, window, key, skipped)
        else:
            error, status = None, None
        return self._record(
            definition,
            outcome,
            window,
            key,
            metric=metric,
            message=message,
            value=evaluation.value,
            previous=evaluation.previous,
            verdict=evaluation.verdict,
            previous_window_end=evaluation.previous_window_end,
            error=error,
            status=status,
            sql=evaluation.sql,
            delivery=delivery,
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

    # -- delivery ---------------------------------------------------------

    def _deliver(
        self,
        definition: AlertDefinition,
        metric: Metric | None,
        window: Window,
        key: str,
        evaluation: _Evaluation,
    ) -> Delivery | None:
        """Hand this fire to the notifier, when the worker has one wired.

        The hand-off is the outcome itself, built here without an audit row so
        the delivery can be part of it: the notifier never re-reads the
        warehouse, the comparison, or the definition.

        A metric cannot be missing at this point — a fire without one is
        refused before any SQL — but the guard keeps the type honest rather than
        asserting a thing a reader cannot check.
        """
        if self.notifier is None or metric is None:
            return None
        # Nothing is composed, and nothing is sent, from an instance whose
        # database says it is somebody else. This is the second net: ``main``
        # refuses a whole tick for the same reason, and this one covers a
        # library caller and ``alert-cli run-now``.
        refusal = self.identity_refusal()
        if refusal:
            return Delivery(
                status=DELIVERY_FAILED,
                fire_key=key,
                error=f"instance_identity_mismatch: {refusal}",
                message=f"No notification was sent. {refusal}",
            )
        if self.state is not None:
            # The first delivery of a headless (``.env``) instance pins it here:
            # that address plus that account is a sender, and a copy of it must
            # not become a second one.
            self.state.pin()
        handoff = FireOutcome(
            definition=definition,
            outcome=OUTCOME_FIRED,
            fire_key=key,
            window_start=window.start,
            window_end=window.end,
            value=evaluation.value,
            previous=evaluation.previous,
            verdict=evaluation.verdict,
            previous_window_end=evaluation.previous_window_end,
            metric_title=" ".join(metric.title.split()),
        )
        try:
            return self.notifier.deliver(handoff, metric)
        except Exception as exc:
            # A notification that cannot even be prepared is this definition's
            # failure, not the tick's. Every other definition still runs, which
            # is the same rule the evaluation path follows. The text is
            # redacted before it reaches an audit row: this path can wrap a
            # transport error, and a transport error can quote the AUTH line.
            detail = redact_transport_error(
                exc, sender=getattr(self.notifier, "sender", None)
            )
            return Delivery(
                status=DELIVERY_FAILED,
                fire_key=key,
                error=f"notification_failed: {detail}",
                message=f"The notification could not be prepared: {detail}.",
            )

    @staticmethod
    def _apply_delivery(
        outcome: str,
        message: str,
        delivery: Delivery | None,
    ) -> tuple[str, str, str | None, str | None]:
        """Turn a delivery result into the fire's outcome, message and audit error.

        Delivered keeps the fire a fire. An empty audience makes it
        ``suppressed`` — the comparison triggered and nobody was told, which is
        not a success and must not read like one. Three failed attempts make it
        ``failed``, with the transport's own words in the audit row.
        """
        if delivery is None:
            return outcome, message, None, None
        if delivery.status == DELIVERY_DELIVERED:
            return OUTCOME_FIRED, f"{message} {delivery.message}", None, None
        if delivery.status == DELIVERY_SUPPRESSED:
            return (
                OUTCOME_SUPPRESSED,
                f"{message} {delivery.message}",
                f"all_recipients_blocked: {delivery.message}",
                "suppressed",
            )
        if delivery.status == DELIVERY_FAILED:
            return OUTCOME_FAILED, f"{message} {delivery.message}", delivery.error, "failed"
        # Not wired, or not a fire: the comparison's outcome stands, and the
        # message says why nothing was sent.
        return outcome, f"{message} {delivery.message}", None, None

    def _record_delivery_health(
        self,
        definition: AlertDefinition,
        key: str,
        delivery: Delivery,
        now: datetime,
    ) -> None:
        """Record one finished notification in the instance's attempt log.

        Delivered, suppressed and failed all land here, because all three say
        something different about whether delivery is alive: a success proves
        it, a failure disproves it, and a suppression is a fire that reached
        nobody. A status with no health meaning — no sender wired, nothing to
        send — is not recorded at all: the log holds attempts, not ticks.

        A failure to write this row must not undo a delivery that happened, so
        it is swallowed. The audit row is the governance record; this is the
        operational one.
        """
        if self.state is None:
            return
        try:
            self.state.record_delivery(
                status=delivery.status,
                at=now,
                alert_id=definition.id,
                fire_key=key,
                recipients=len(delivery.recipients),
                error=delivery.error,
                sender=getattr(self.notifier, "sender", None),
            )
        except Exception:
            return

    def _record_blocked(
        self,
        definition: AlertDefinition,
        metric: Metric | None,
        window: Window,
        key: str,
        blocked: object,
    ) -> None:
        """One audit event per recipient this fire could not reach.

        It names the person, the definition and the fire key, so the question
        "why did Alex not get the revenue alert?" is one grep rather than an
        argument. A refusal here is per-recipient: the others still received
        the email, and this row says who did not.
        """
        username = getattr(blocked, "username", "")
        reason = getattr(blocked, "reason", "not_allowed")
        detail = getattr(blocked, "message", "")
        try:
            self.service.audit.record_event(
                username=WORKER_USERNAME,
                role=WORKER_ROLE,
                status="denied",
                event_type=EVENT_RECIPIENT_BLOCKED,
                capability=ALERT,
                question=(
                    f"blocked alert recipient {username} for definition #{definition.id} "
                    f"window {window.start} to {window.end} fire_key {key} ({reason})"
                ),
                tables=(metric.table,) if metric is not None else (),
                sql=None,
                row_count=None,
                error=f"{reason}: {detail}",
                metric_id=None if metric is None else metric.id,
                definition_hash=None if metric is None else definition_hash(metric),
            )
        except Exception:
            # A failed audit write must not stop the other recipients' email.
            return

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
        delivery: Delivery | None = None,
    ) -> FireOutcome:
        """Write exactly one outcome audit event for this definition, and return it."""
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
            delivery=delivery,
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
            delivery=delivery,
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
        delivery: Delivery | None = None,
    ) -> bool:
        """One outcome row per considered definition, through the shared writer.

        A fire that reached somebody says so in the same row, so the audit trail
        answers "was it sent, and to whom" without a second table. A delivery
        that never got through writes the terminal failure event
        (``alert_delivery_failed``) instead of ``alert_failed``, because the
        difference between "the sum failed" and "the email failed" is the whole
        of what an operator has to fix.
        """
        question = (
            f"{outcome} alert definition #{definition.id} "
            f"window {window.start} to {window.end} "
            f"fire_key {key} "
            f"({definition.comparison} {definition.constant:g}, "
            f"owner {definition.owner})"
        )
        if delivery is not None:
            question += f" notify {delivery.status}"
            if delivery.recipients:
                question += f":{','.join(delivery.recipients)}"
            if delivery.blocked:
                question += f" skipped:{','.join(item.username for item in delivery.blocked)}"
        try:
            self.service.audit.record_event(
                username=WORKER_USERNAME,
                role=WORKER_ROLE,
                status=status,
                event_type=_event_type(outcome, delivery),
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
        delivery = ""
        if outcome.delivery is not None:
            delivery = f" notify={outcome.delivery.status}"
            if outcome.delivery.recipients:
                delivery += f":{','.join(outcome.delivery.recipients)}"
            if outcome.delivery.blocked:
                delivery += f" skipped:{','.join(item.username for item in outcome.delivery.blocked)}"
        print(
            f"{outcome.outcome:<17} alert #{outcome.alert_id:<4} "
            f"{outcome.window_start}..{outcome.window_end}"
            f"{value}{previous}{delivery} {outcome.fire_key}"
        )
    if not outcomes:
        print("0 alert definitions were due")
    return 1 if any(outcome.outcome in _ATTENTION for outcome in outcomes) else 0


def _refuse_unconfigured(settings: Settings, audit: AuditLog) -> int:
    """Refuse to tick when there is no way to deliver a fire, and say why.

    A worker that evaluates fires and drops the notification is worse than a
    worker that does not start: the first looks healthy from cron, and the
    breach it found is lost. So this is a refusal, audited like any other, with
    a non-zero exit code that systemd and cron both surface.
    """
    missing = missing_smtp(settings)
    reason = (
        f"smtp_unconfigured: the alert worker cannot deliver notifications, "
        f"because {missing} is not set"
    )
    print(f"refused: {reason}", file=sys.stderr)
    try:
        audit.record_event(
            username=WORKER_USERNAME,
            role=WORKER_ROLE,
            status="denied",
            event_type=EVENT_DELIVERY_UNCONFIGURED,
            capability=ALERT,
            question="refused to run the alert worker: no notification sender is configured",
            tables=(),
            sql=None,
            row_count=None,
            error=reason,
        )
    except Exception:
        # The refusal still stands, and it still exits non-zero.
        pass
    return EXIT_UNCONFIGURED


def main(argv: list[str] | None = None, *, sender: MailSender | None = None) -> int:
    """Run one tick, or keep running ticks with ``--loop``.

    One tick is the cron and systemd form:

        */15 * * * *  cd /srv/day1 && .venv/bin/python -m src.worker

    A tick is cheap when nothing is due, and a repeated tick is harmless: the
    fire key makes a second evaluation of the same window impossible.

    The sender comes from the instance mail store: encrypted database, then
    ``SMTP_*``. When neither names a host the command refuses to run rather
    than tick and deliver nothing. A key that cannot decrypt a stored password
    is the same kind of refusal: loud, and not a fallback to ``.env``.
    ``sender`` overrides the transport, which is how a test drives the whole
    command without a mail server.
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
    parser.add_argument(
        "--confirm-instance-move",
        action="store_true",
        help=(
            "deliver from a host or path this instance's recorded identity does not "
            "name, and record the move (the instance was moved or restored on purpose)"
        ),
    )
    args = parser.parse_args(argv)
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")

    settings = load_settings()
    if args.confirm_instance_move:
        settings = replace(settings, confirm_instance_move=True)
    try:
        settings = resolve_mail_settings(settings)
    except (SecretKeyError, ConfigError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_UNCONFIGURED
    audit = AuditLog(settings.audit_path)
    transport = sender if sender is not None else build_sender(settings)
    if transport is None:
        return _refuse_unconfigured(settings, audit)

    worker = Worker.from_settings(
        settings,
        audit=audit,
        catalog=load_catalog(settings.routing_path),
        sender=transport,
    )

    # Asked before the tick, so a moved or copied instance stops here with its
    # own exit code instead of reporting "0 alert definitions were due".
    refusal = worker.identity_refusal()
    if refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return EXIT_IDENTITY

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
