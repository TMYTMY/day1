"""Delivery of one fire's notification: compose it, re-check who may read, send it.

A fire whose comparison triggered becomes a notification (GLOSSARY.md). This
module is the whole of that step and nothing else:

* :func:`compose` writes the plain-text body. It reads the outcome the worker
  already produced — the metric title, the value, the window, the condition and
  constant, the metric definition in force with its owner and effective date,
  and the fire key — so nothing is re-derived and nothing needs a database.
* :class:`Notifier` decides *who* receives it. The recipient set is re-read from
  the user directory and re-checked through :func:`src.capabilities.authorize`
  at fire time, because a role can change between the day a definition was
  written and the morning it fires. A recipient who may no longer read the
  metric is skipped and named in the returned :class:`Delivery`; the others
  still receive the email. When nobody may read it, the delivery is
  ``suppressed``: no email is sent, and the caller records that outcome instead
  of a success.
* :class:`SmtpSender` is the only code that opens a socket, and it does so in
  ``send`` and nowhere else — constructing it touches nothing, which is what
  lets the tests build the real object and never reach a mail server.
  :class:`RecordingSender` is the in-memory seam the tests inject instead.

A failed delivery is retried at most :data:`MAX_ATTEMPTS` times with a pause
between attempts; the pause comes from an injected ``sleep`` so a test never
waits. After the last attempt the notifier stops, and the definition's owner is
notified exactly once that their alert could not be delivered.

No model call and no network happen anywhere in this module except inside
``SmtpSender.send`` (see docs/adr/0003-model-authors-definitions-not-execution.md).
"""

from __future__ import annotations

import smtplib
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from src.alerts import AlertDefinition
from src.alert_eval import BELOW_ABSOLUTE, CHANGE_PCT_DOWN, CHANGE_PCT_UP
from src.auth import user_named
from src.capabilities import ALERT, authorize, join_names
from src.config import ConfigError, Settings
from src.metrics import Metric
from src.models import User

if TYPE_CHECKING:  # the worker imports this module; this keeps that one-way
    from src.worker import FireOutcome

# The most attempts one notification gets. Three is the ticket's number: enough
# to ride out a mail server that is restarting, few enough that a broken relay
# does not turn into an unbounded retry inside a scheduled tick.
MAX_ATTEMPTS = 3

# The pause between attempts, in seconds. Injected into the notifier, so this
# tuple is a default for a deployment and never a wait a test has to sit through.
BACKOFF_SECONDS: tuple[float, ...] = (1.0, 5.0)

# The status of one delivery attempt, as the audit trail records it. These are
# deliberately distinct from the fire's own outcomes: a fire's outcome says what
# the comparison did, a delivery status says what happened to the email.
DELIVERY_DELIVERED = "delivered"
DELIVERY_SUPPRESSED = "suppressed"
DELIVERY_FAILED = "failed"
# Nobody to deliver through: no sender is wired at all. The scheduled command
# refuses to run in this state (see ``src.worker.main``), so this status only
# appears for an unwired worker in a library or a test.
DELIVERY_NOT_WIRED = "not_wired"
# The outcome was not a triggering fire, so there was nothing to deliver.
DELIVERY_NOT_A_FIRE = "not_a_fire"

DELIVERY_STATUSES = (
    DELIVERY_DELIVERED,
    DELIVERY_SUPPRESSED,
    DELIVERY_FAILED,
    DELIVERY_NOT_WIRED,
    DELIVERY_NOT_A_FIRE,
)

# Why a recipient did not receive the email. The first two are the capability
# reasons; the third is a person the directory no longer knows.
RECIPIENT_UNKNOWN = "recipient_unknown"

# Human words for the comparisons, so the body reads as a sentence and the raw
# comparison kind is still there beside it for anyone diffing two emails.
_CONDITION_WORDS = {
    BELOW_ABSOLUTE: "below",
    "above_absolute": "above",
    CHANGE_PCT_DOWN: "down by",
    CHANGE_PCT_UP: "up by",
}


# --- the message and the seam ---------------------------------------------


@dataclass(frozen=True)
class MailMessage:
    """One plain-text email: who, what, and which fire it is about."""

    to: tuple[str, ...]
    subject: str
    body: str
    # The fire key, so a sender can log what it sent and a test can assert that
    # the email belongs to the fire that produced it.
    fire_key: str = ""


class MailSender(Protocol):
    """The one method the delivery path needs from a mail transport.

    A sender either accepts the message or raises. Everything the notifier does
    with a failure — the retries, the audit event, the owner notification — is
    its own business, so a transport stays a transport.
    """

    def send(self, message: MailMessage) -> None: ...


@dataclass
class RecordingSender:
    """An in-memory sender: the seam the tests replace SMTP with.

    Nothing here opens a socket, so a test can exercise composition, the
    recipient re-check and the retry loop while proving the network is never
    reached. ``fail_times`` makes the first sends raise, which is how a test
    drives the retry path without a mail server to break.
    """

    messages: list[MailMessage] = field(default_factory=list)
    fail_times: int = 0
    error: Exception = field(default_factory=lambda: RuntimeError("the mail server is unavailable"))
    attempts: int = 0

    def send(self, message: MailMessage) -> None:
        self.attempts += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise self.error
        self.messages.append(message)

    @property
    def recipients(self) -> list[str]:
        """Every address any recorded message was sent to, in order."""
        return [address for message in self.messages for address in message.to]


@dataclass(frozen=True)
class SmtpSender:
    """SMTP, standard library only. Constructing it connects to nothing."""

    host: str
    port: int = 587
    sender: str = "day1-alerts@localhost"
    user: str | None = None
    password: str | None = None
    starttls: bool = True
    timeout: float = 30.0

    @classmethod
    def from_settings(cls, settings: Settings) -> SmtpSender:
        """Build the transport a deployment uses, or refuse to invent one."""
        if not settings.smtp_host:
            raise ConfigError(
                "SMTP_HOST is not set, so no notification can be delivered. "
                "The worker refuses to run rather than drop an alert silently."
            )
        return cls(
            host=settings.smtp_host,
            port=int(settings.smtp_port),
            sender=settings.smtp_from,
            user=settings.smtp_user,
            password=settings.smtp_password,
            starttls=bool(settings.smtp_starttls),
        )

    def message_for(self, message: MailMessage) -> EmailMessage:
        """The MIME message this sender would put on the wire.

        Separated from :meth:`send` so the composed email can be inspected
        without a server: the body stays plain text, which is what a person
        reading an alert in a terminal or a watch wants.
        """
        mail = EmailMessage()
        mail["From"] = self.sender
        mail["To"] = ", ".join(message.to)
        mail["Subject"] = message.subject
        mail.set_content(message.body)
        return mail

    def send(self, message: MailMessage) -> None:
        """Open one connection, deliver one message, close it.

        This is the only network call in the alert path. Nothing is cached, so
        a failure is a failure for this attempt and the notifier decides what
        to do about it.
        """
        mail = self.message_for(message)
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
            if self.starttls:
                smtp.starttls()
            if self.user:
                smtp.login(self.user, self.password or "")
            smtp.send_message(mail)


def build_sender(settings: Settings) -> SmtpSender | None:
    """The configured sender, or None when this instance has no mail transport.

    Returning None rather than raising keeps ``Settings`` usable in a test or a
    read-only tool; the scheduled command treats None as a refusal, so a cron
    job cannot quietly deliver nothing.
    """
    if not settings.smtp_host:
        return None
    return SmtpSender.from_settings(settings)


def missing_smtp(settings: Settings) -> str:
    """What a deployment still has to set before a fire can be delivered."""
    missing = [
        name
        for name, value in (("SMTP_HOST", settings.smtp_host), ("SMTP_FROM", settings.smtp_from))
        if not value
    ]
    return ", ".join(missing) or "SMTP_HOST"


def address_for(user: User) -> str:
    """The address a notification is sent to for one person.

    A directory entry may carry an ``email``; without one the username is the
    address, which is what a small instance whose mail relay resolves usernames
    expects.
    """
    return (getattr(user, "email", None) or user.username).strip()


# --- who may still read the metric ----------------------------------------


@dataclass(frozen=True)
class Blocked:
    """One recipient who was skipped, and why. Named so the audit can name them."""

    username: str
    reason: str
    message: str


@dataclass(frozen=True)
class Delivery:
    """What one fire's notification did: delivered, suppressed, or failed."""

    status: str
    fire_key: str = ""
    # The usernames the email was addressed to. Empty when suppressed or failed.
    recipients: tuple[str, ...] = ()
    blocked: tuple[Blocked, ...] = ()
    attempts: int = 0
    error: str | None = None
    owner_notified: bool = False
    owner_error: str | None = None
    message: str = ""

    @property
    def delivered(self) -> bool:
        return self.status == DELIVERY_DELIVERED

    @property
    def suppressed(self) -> bool:
        """True when every recipient was refused. Not a success, and not an error."""
        return self.status == DELIVERY_SUPPRESSED


# --- composition -----------------------------------------------------------


@dataclass(frozen=True)
class Notification:
    """A composed email, before it has recipients."""

    subject: str
    body: str


def condition_phrase(comparison: str, constant: float) -> str:
    """The condition in words, with the raw kind and constant kept beside it."""
    word = _CONDITION_WORDS.get(comparison, comparison)
    if comparison in (CHANGE_PCT_DOWN, CHANGE_PCT_UP):
        return f"{word} {constant:g}% or more on the previous window"
    return f"{word} {constant:g}"


def _number(value: float | None) -> str:
    return "no rows" if value is None else f"{value:,.2f}"


def compose(outcome: FireOutcome, metric: Metric) -> Notification:
    """The email one triggering fire produces, as plain text.

    Every number in it was decided before this call: the value the comparison
    used, the window it covered, the condition and constant it was compared
    with, and the metric definition that was in force. The fire key is the
    audit reference, so a recipient holding the email can find the run.
    """
    definition = outcome.definition
    title = " ".join((outcome.metric_title or metric.title).split())
    window = (
        f"{outcome.window_start.isoformat()} to {outcome.window_end.isoformat()} "
        f"({definition.window_days} day{'s' if definition.window_days != 1 else ''}), "
        f"ending {outcome.window_end.isoformat()}"
    )
    lines = [
        f"Alert: {title}",
        f"Definition: #{definition.id} (owner {definition.owner}, "
        f"cadence {definition.cadence} at {definition.local_time} local time)",
        "",
        f"Value: {_number(outcome.value)}",
        f"Window: {window}",
        f"Condition: {definition.comparison} {definition.constant:g} "
        f"(value {condition_phrase(definition.comparison, definition.constant)})",
    ]
    if outcome.previous is not None:
        earlier = (
            f"Previous window ending {outcome.previous_window_end.isoformat()}"
            if outcome.previous_window_end is not None
            else "Previous window"
        )
        lines.append(f"{earlier}: {_number(outcome.previous)}")
    lines += [
        "",
        f"Metric definition in force ({metric.id}, effective from "
        f"{metric.effective_from.isoformat()}):",
        f"  {metric.definition}",
        f"  Owner: {metric.owner}",
        "",
        f"Fire key: {outcome.fire_key}",
        "Audit reference: search the usage log for this fire key to find the "
        "evaluation, the statement it ran, and the recipients this notification "
        "reached.",
        "",
        "You receive this because you hold the alert capability and may read this "
        "metric's table. Both were checked when this fire ran.",
    ]
    subject = (
        f"[Day 1] {title} fired: {_number(outcome.value)} over "
        f"{outcome.window_start.isoformat()} to {outcome.window_end.isoformat()}"
    )
    return Notification(subject=subject, body="\n".join(lines) + "\n")


def compose_failure(
    *,
    definition: AlertDefinition,
    metric_title: str,
    delivery: Delivery,
    window_start: date,
    window_end: date,
) -> Notification:
    """The single email a definition's owner gets when delivery never happened.

    It says what was missed and why, in the terms the owner can act on: their
    alert fired, nobody was told, and the mail transport failed this many times.
    """
    title = " ".join(metric_title.split())
    subject = f"[Day 1] Delivering your alert #{definition.id} failed: {title}"
    blocked = (
        "Blocked recipients: " + join_names([item.username for item in delivery.blocked])
        if delivery.blocked
        else "No recipient was blocked."
    )
    body = "\n".join(
        [
            f"The alert definition #{definition.id} fired, and its notification could not be delivered.",
            "",
            f"Metric: {title}",
            f"Window: {window_start.isoformat()} to {window_end.isoformat()}",
            f"Recipients it was meant for: {join_names(list(delivery.recipients)) or 'nobody'}",
            f"Fire key: {delivery.fire_key}",
            "",
            f"Delivery failed {delivery.attempts} time(s). The last error was:",
            f"  {delivery.error or 'unknown'}",
            blocked,
            "",
            "The fire is recorded in the alert log and the usage log under that fire "
            "key. Nothing was sent to the recipients, so treat this window as "
            "unreported until you fix the mail transport.",
            "",
            f"Definition owner: {definition.owner}",
            "",
        ]
    )
    return Notification(subject=subject, body=body)


# --- the notifier ----------------------------------------------------------


class Notifier:
    """Deliver one fire's notification to the people who may still read it.

    Construct it with the sender, the user directory the recipient check reads,
    and the topic-title map the refusal messages use — the same map the worker
    and the definition writer pass to ``authorize``, so a skip reads the way a
    refusal read when the definition was written.

    ``sleep`` is injected so the retry pauses are a test's business and never a
    real wait; a test passes a recorder (or ``lambda seconds: None``).
    """

    def __init__(
        self,
        *,
        sender: MailSender | None,
        users_path: Path,
        titles: Mapping[str, str] | None = None,
        sleep: Callable[[float], None] | None = None,
        attempts: int = MAX_ATTEMPTS,
        backoff: Sequence[float] = BACKOFF_SECONDS,
    ):
        self.sender = sender
        self.users_path = Path(users_path)
        self._titles = dict(titles or {})
        self._sleep = sleep or time.sleep
        self._attempts = max(1, int(attempts))
        self._backoff = tuple(float(seconds) for seconds in backoff)

    def deliver(self, outcome: FireOutcome, metric: Metric) -> Delivery:
        """Compose, re-check, send, retry, and report. Never raises for a send."""
        definition = outcome.definition
        fire_key = outcome.fire_key
        if not getattr(outcome, "should_notify", False):
            return Delivery(
                status=DELIVERY_NOT_A_FIRE,
                fire_key=fire_key,
                message="The fire did not trigger, so there is nothing to deliver.",
            )
        if self.sender is None:
            return Delivery(
                status=DELIVERY_NOT_WIRED,
                fire_key=fire_key,
                message="No mail sender is configured, so no notification was sent.",
            )

        permitted, blocked = self._permitted(definition, metric)
        if not permitted:
            return Delivery(
                status=DELIVERY_SUPPRESSED,
                fire_key=fire_key,
                blocked=blocked,
                recipients=(),
                message=self._suppressed_message(definition, metric, blocked),
            )

        notification = compose(outcome, metric)
        message = MailMessage(
            to=tuple(address_for(user) for user in permitted),
            subject=notification.subject,
            body=notification.body,
            fire_key=fire_key,
        )

        error: str | None = None
        attempts = 0
        for attempt in range(1, self._attempts + 1):
            attempts = attempt
            try:
                self.sender.send(message)
            except Exception as exc:  # a transport failure is data, not a crash
                error = f"attempt {attempt} of {self._attempts} failed: {exc}"
                if attempt < self._attempts:
                    self._sleep(self._backoff[min(attempt - 1, len(self._backoff) - 1)])
                continue
            return Delivery(
                status=DELIVERY_DELIVERED,
                fire_key=fire_key,
                recipients=tuple(user.username for user in permitted),
                blocked=blocked,
                attempts=attempts,
                message=(
                    f"Notified {join_names([user.username for user in permitted])}"
                    + (
                        f"; skipped {join_names([item.username for item in blocked])}."
                        if blocked
                        else "."
                    )
                ),
            )

        owner_notified, owner_error = self._notify_owner(
            definition=definition,
            metric_title=metric.title,
            delivery=Delivery(
                status=DELIVERY_FAILED,
                fire_key=fire_key,
                recipients=tuple(user.username for user in permitted),
                blocked=blocked,
                attempts=attempts,
                error=error,
            ),
            window_start=outcome.window_start,
            window_end=outcome.window_end,
        )
        return Delivery(
            status=DELIVERY_FAILED,
            fire_key=fire_key,
            recipients=(),
            blocked=blocked,
            attempts=attempts,
            error=error,
            owner_notified=owner_notified,
            owner_error=owner_error,
            message=(
                f"Delivery failed after {attempts} attempt(s): {error}. "
                + (
                    f"The owner {definition.owner} was notified."
                    if owner_notified
                    else f"The owner {definition.owner} could not be notified"
                    + (f" ({owner_error})." if owner_error else ".")
                )
            ),
        )

    # -- the recipient check ------------------------------------------------

    def _permitted(
        self, definition: AlertDefinition, metric: Metric
    ) -> tuple[tuple[User, ...], tuple[Blocked, ...]]:
        """Resolve each recipient now, and check them now.

        The definition stored a recipient *name*. What that name may read is
        decided by the directory as it stands at fire time, through the same
        ``authorize`` boundary the rest of the app uses: the alert capability
        and the metric's table, both, for each person separately. One person's
        lost grant does not silence the others.
        """
        permitted: list[User] = []
        blocked: list[Blocked] = []
        for username in definition.recipients:
            user = user_named(username, self.users_path)
            if user is None:
                blocked.append(
                    Blocked(
                        username=username,
                        reason=RECIPIENT_UNKNOWN,
                        message=f"{username} is no longer in the user directory.",
                    )
                )
                continue
            decision = authorize(user, ALERT, (metric.table,), display=self._titles or None)
            if not decision.allowed:
                blocked.append(
                    Blocked(
                        username=user.username,
                        reason=decision.reason or "not_allowed",
                        message=decision.message or f"{user.username} may not receive this notification.",
                    )
                )
                continue
            permitted.append(user)
        return tuple(permitted), tuple(blocked)

    @staticmethod
    def _suppressed_message(
        definition: AlertDefinition, metric: Metric, blocked: tuple[Blocked, ...]
    ) -> str:
        if not blocked:
            return (
                f"Alert definition #{definition.id} names no recipients, so the fire "
                "was suppressed and nothing was sent."
            )
        names = join_names([item.username for item in blocked])
        return (
            f"Nobody who was named may read {metric.title} any more: {names}. "
            "The fire was suppressed and nothing was sent."
        )

    # -- the owner ----------------------------------------------------------

    def _notify_owner(
        self,
        *,
        definition: AlertDefinition,
        metric_title: str,
        delivery: Delivery,
        window_start: date,
        window_end: date,
    ) -> tuple[bool, str | None]:
        """Tell the owner once. Not a retry loop, and not a second attempt.

        The owner is the person who confirmed the definition, so they are the
        one who can fix a transport or rewrite an unreachable recipient set. If
        this send also fails there is nothing left to try: the failure is
        returned and the caller audits it.
        """
        owner = user_named(definition.owner, self.users_path)
        if owner is None:
            return False, f"the owner {definition.owner} is no longer in the user directory"
        notification = compose_failure(
            definition=definition,
            metric_title=metric_title,
            delivery=delivery,
            window_start=window_start,
            window_end=window_end,
        )
        message = MailMessage(
            to=(address_for(owner),),
            subject=notification.subject,
            body=notification.body,
            fire_key=delivery.fire_key,
        )
        try:
            assert self.sender is not None  # deliver() checked this already
            self.sender.send(message)
        except Exception as exc:
            return False, f"sending it also failed: {exc}"
        return True, None
