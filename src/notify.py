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

**An authentication failure is not retried.** A wrong password is a different
kind of failure from a relay that is restarting: Microsoft 365 and Google lock
an account after a run of rejected logins, and the mailbox may be a person's
only one. So a rejected login ends the delivery on the spot, and
:class:`src.send_safety.DeliveryGuard` counts the streak in the instance's alert
database. At :data:`src.send_safety.AUTH_FAILURE_LIMIT` consecutive failures the
definition is marked failing, later deliveries are refused before the transport
is touched, and the owner is told once — not once per attempt, and not once per
tick. A delivered message clears the streak. The guard is injected: a caller
with no store gets the stop *within* a delivery (no retry) but no memory across
ticks, and the notice it sends says so.

No model call and no network happen anywhere in this module except inside
``SmtpSender.send`` (see docs/adr/0003-model-authors-definitions-not-execution.md).
"""

from __future__ import annotations

import smtplib
import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from src.alerts import AlertDefinition
from src.alert_eval import BELOW_ABSOLUTE, CHANGE_PCT_DOWN, CHANGE_PCT_UP
from src.auth import user_named
from src.capabilities import ALERT, QUERY, authorize, join_names
from src.config import ConfigError, Settings
from src.metrics import Metric
from src.models import User
from src.redaction import redact_exception, redact_transport_error
from src.send_safety import AUTH_FAILURE_LIMIT, DeliveryGuard, Refusal

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

# The SMTP codes a provider answers with when the credential is wrong. 535 is
# "authentication failed"; 534 is "application-specific password required" (an
# app password is needed); 530 and 538 are the "authentication required" pair a
# tenant sends instead of 535 when it has disabled SMTP AUTH. They are listed
# because treating one of them as a retryable relay error is how an account
# gets locked.
AUTH_CODES = frozenset({530, 534, 535, 538})

# Words a wrapped or re-raised login failure keeps. A transport that raises a
# plain OSError around the server's reply has no code left, so the text is the
# only evidence; it is read here and nowhere else.
_AUTH_WORDS = (
    "authentication failed",
    "authentication required",
    "authenticate",
    "invalid login",
    "username and password not accepted",
    "auth failed",
    "bad credentials",
    "application-specific password",
)


def is_auth_failure(exc: BaseException) -> bool:
    """Whether this failure is the mail server rejecting the credential.

    Only a rejected *credential* counts. A relay that is down, a port that is
    wrong, a certificate that does not verify and a timeout are all retryable
    conditions and none of them can lock an account; a rejected login is the one
    failure where trying again is the harm.
    """
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return True
    code = getattr(exc, "smtp_code", None)
    if isinstance(code, int) and code in AUTH_CODES:
        return True
    text = str(exc).lower()
    return any(word in text for word in _AUTH_WORDS)


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


def _header_value(value: str, field: str) -> str:
    """A header value with no line break in it.

    ``EmailMessage`` also refuses one, but it refuses at the moment the message
    is composed, which is after the recipient list has been assembled from the
    directory and after a retry may already have been attempted. Checking here
    names the field instead.
    """
    text = str(value)
    if "\n" in text or "\r" in text:
        raise ConfigError(
            f"The {field} header must not contain a line break. "
            "A newline in a header value is how a second header gets written."
        )
    return text


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
    ssl: bool = False
    ca_bundle: str | None = None
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
            ssl=bool(settings.smtp_ssl),
            ca_bundle=settings.smtp_ca_bundle,
        )

    def message_for(self, message: MailMessage) -> EmailMessage:
        """The MIME message this sender would put on the wire.

        Separated from :meth:`send` so the composed email can be inspected
        without a server: the body stays plain text, which is what a person
        reading an alert in a terminal or a watch wants.

        Every header value is checked for a line break first. A newline inside
        ``From``, ``To`` or ``Subject`` is not a formatting problem: it is how
        an extra header (``Bcc:``, ``Content-Type:``) gets written by a value
        that was supposed to be data.
        """
        mail = EmailMessage()
        mail["From"] = _header_value(self.sender, "From")
        mail["To"] = ", ".join(_header_value(address, "To") for address in message.to)
        mail["Subject"] = _header_value(message.subject, "Subject")
        mail.set_content(message.body)
        return mail

    def send(self, message: MailMessage) -> None:
        """Open one connection, deliver one message, close it.

        This is the only network call in the alert path. Nothing is cached, so
        a failure is a failure for this attempt and the notifier decides what
        to do about it. The failure is redacted in place before it leaves this
        method: a server reply can quote the ``AUTH`` line, and that line is
        the credential.
        """
        try:
            self._deliver(message)
        except Exception as exc:
            redact_exception(exc, password=self.password, user=self.user)
            raise

    def _deliver(self, message: MailMessage) -> None:
        mail = self.message_for(message)
        # Certificates are verified, and there is deliberately no way to turn that
        # off. smtplib's default context does NOT verify (ssl._create_stdlib_context
        # leaves verify_mode=CERT_NONE and check_hostname=False), so passing no
        # context is the same as trusting any server that answers. A company with a
        # private relay supplies SMTP_CA_BUNDLE rather than weakening the check.
        context = ssl.create_default_context(cafile=self.ca_bundle)
        # 465 speaks TLS from the first byte; 587 starts plain and upgrades. The
        # settings layer guarantees the two flags are never both true.
        if self.ssl:
            with smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=context) as smtp:
                if self.user:
                    smtp.login(self.user, self.password or "")
                smtp.send_message(mail)
            return
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
            if self.starttls:
                smtp.starttls(context=context)
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
    # True when the mail server rejected the credential. The status stays
    # ``failed`` — the worker already turns that into a failed run and a
    # non-zero exit code — and this flag is what says *which* failure, so a
    # caller does not have to read the error text.
    auth_failed: bool = False
    # True when the delivery was never attempted because the definition is
    # already marked failing. ``attempts`` is 0 in that case.
    stopped: bool = False

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
        return f"{word} {_constant(constant)}% or more on the previous window"
    return f"{word} {_constant(constant)}"


def _number(value: float | None) -> str:
    return "no rows" if value is None else f"{value:,.2f}"


def _constant(value: float) -> str:
    """A threshold, written the way a person writes it: 100,000, not 1e+05."""
    rounded = round(float(value), 2)
    if rounded == int(rounded):
        return f"{int(rounded):,}"
    return f"{rounded:,.2f}".rstrip("0").rstrip(".")


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
        f"Condition: {definition.comparison} {_constant(definition.constant)} "
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
        "You receive this because you may read this metric. That read grant was "
        "checked when this fire ran, not when the alert was set.",
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


def compose_auth_failure(
    *,
    definition: AlertDefinition,
    metric_title: str,
    consecutive: int,
    limit: int,
    first_at: datetime,
    error: str | None,
    fire_key: str,
    window_start: date,
    window_end: date,
    marked_failing: bool,
) -> Notification:
    """The single email a definition's owner gets when the password is rejected.

    It is written for the person who can fix it, and it says three things: the
    mailbox refused the credential this many times in a row, delivery has
    stopped so the account is not locked, and the fix is one settings screen
    away. It is not a per-attempt report — the caller sends it once per streak,
    because a rejection notice for every attempt is itself a run of logins.
    """
    title = " ".join(metric_title.split())
    subject = f"[Day 1] Mail authentication is failing for alert #{definition.id}: {title}"
    state = (
        f"Delivery for this definition is now stopped: {consecutive} authentication "
        f"failures in a row (the limit is {limit}) since {first_at.strftime('%Y-%m-%dT%H:%M:%SZ')}. "
        "Nothing more will be sent for it until the password works or the window "
        "passes, so this mailbox is not driven into a provider lockout by our retries."
        if marked_failing
        else "Delivery for this fire was stopped on the first rejection rather than "
        "retried, because repeating a rejected login is what locks an account."
    )
    body = "\n".join(
        [
            f"The mail server rejected the instance's mailbox password while delivering "
            f"alert definition #{definition.id}.",
            "",
            f"Metric: {title}",
            f"Window: {window_start.isoformat()} to {window_end.isoformat()}",
            f"Recipients it was meant for: "
            f"{join_names(list(definition.recipients)) or 'nobody'}",
            f"Fire key: {fire_key}",
            "",
            state,
            "",
            "The server said:",
            f"  {error or 'no detail was recorded'}",
            "",
            "How to fix it:",
            "  1. Open Settings, then Mail settings, on this instance.",
            "  2. Enter the mailbox password again. Most providers need an app "
            "password here: Gmail wants a 16-character App Password with 2-Step "
            "Verification on, and Microsoft 365 needs an app password — or SMTP AUTH "
            "enabled for the mailbox — which the tenant may have turned off.",
            "  3. Save, then send a test message to your own address. A test message "
            "that arrives means the next scheduled run will deliver.",
            "",
            "Do not save the same password again to \"try it\": each attempt is another "
            "rejected login against the account.",
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
        guard: DeliveryGuard | None = None,
        auth_limit: int = AUTH_FAILURE_LIMIT,
        clock: Callable[[], datetime] | None = None,
    ):
        self.sender = sender
        self.users_path = Path(users_path)
        self._titles = dict(titles or {})
        self._sleep = sleep or time.sleep
        self._attempts = max(1, int(attempts))
        self._backoff = tuple(float(seconds) for seconds in backoff)
        # The store that remembers rejected logins per definition. None means
        # this caller has no store, which is a supported state (a library call,
        # a test, a worker built before the guard existed): the stop then holds
        # inside one delivery, and the notice says it is the only one.
        self._guard = guard
        self._auth_limit = max(1, int(auth_limit))
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        sender: MailSender | None,
        titles: Mapping[str, str] | None = None,
        sleep: Callable[[float], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> Notifier:
        """Build the notifier a deployment uses, with its guard wired to the instance.

        The guard belongs beside the fire log in the instance's alert database,
        because that is the only place a fact about delivery outlives the
        process that learned it. Building ``Notifier`` directly is still legal
        and is what the tests do; it just has no memory across ticks.
        """
        return cls(
            sender=sender,
            users_path=settings.users_path,
            titles=titles,
            sleep=sleep,
            guard=DeliveryGuard(settings.alerts_path),
            clock=clock,
        )

    @property
    def guard(self) -> DeliveryGuard | None:
        return self._guard

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

        # Before composing or addressing anything: has this definition already
        # been marked failing? A refusal here is the whole point of the guard —
        # the transport is not touched, so no credential is presented again.
        stopped = self._stopped(definition)
        if stopped is not None:
            return Delivery(
                status=DELIVERY_FAILED,
                fire_key=fire_key,
                error=f"{stopped.reason}: {stopped.message}",
                message=stopped.message,
                auth_failed=True,
                stopped=True,
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
        while attempts < self._attempts:
            attempts += 1
            try:
                self.sender.send(message)
            except Exception as exc:  # a transport failure is data, not a crash
                # The server's own words, minus the credential. A reply can
                # quote the AUTH line, and this string goes into an audit row,
                # the owner's email and the fire's message.
                detail = redact_transport_error(exc, sender=self.sender)
                if is_auth_failure(exc):
                    # A rejected password is the one failure where the retry is
                    # the harm: providers count them, and the account may be a
                    # person's only mailbox.
                    return self._auth_failure(
                        definition=definition,
                        metric=metric,
                        blocked=blocked,
                        outcome=outcome,
                        attempt=attempts,
                        detail=detail,
                    )
                error = f"attempt {attempts} of {self._attempts} failed: {detail}"
                if attempts < self._attempts:
                    self._sleep(self._backoff[min(attempts - 1, len(self._backoff) - 1)])
                continue
            self._record_success(definition)
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

        self._record_failure(definition, error)
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

    # -- the authentication stop --------------------------------------------

    def _stopped(self, definition: AlertDefinition) -> Refusal | None:
        """The guard's answer for this definition, or None when it may send.

        A store that cannot be read answers None. Refusing every delivery
        because a table is missing would silence the alerts this guard exists to
        protect, and the transport's own failure is still recorded and reported
        below, so the honest failure is the one a person can see.
        """
        if self._guard is None:
            return None
        try:
            return self._guard.refusal(definition.id, now=self._clock())
        except Exception:  # noqa: BLE001 - a broken store must not stop delivery
            return None

    def _record_success(self, definition: AlertDefinition) -> None:
        """Clear this definition's streak, because a message just got through."""
        if self._guard is None:
            return
        try:
            self._guard.record_success(definition.id, at=self._clock())
        except Exception:  # noqa: BLE001 - the email is what matters, not the note
            return

    def _record_failure(self, definition: AlertDefinition, error: str | None) -> None:
        """Record a non-authentication failure, so the health line can count it."""
        if self._guard is None:
            return
        try:
            self._guard.record_failure(definition.id, at=self._clock(), error=error)
        except Exception:  # noqa: BLE001
            return

    def _auth_failure(
        self,
        *,
        definition: AlertDefinition,
        metric: Metric,
        blocked: tuple[Blocked, ...],
        outcome: FireOutcome,
        attempt: int,
        detail: str,
    ) -> Delivery:
        """Stop on a rejected credential: no retry, one notice, a recorded streak.

        The one thing this must not do is try again: a rejected login is exactly
        the failure a provider counts towards a lockout. The streak is recorded
        in the guard so the *next* fire — another process, hours later — knows
        about it, and the owner is told once per streak.

        The notice is marked as sent even when sending it failed, because that
        send is itself another login attempt against a mailbox that is already
        rejecting them. Trying the notice again every tick is the retry loop
        this function exists to remove.
        """
        error = (
            "authentication_failed: the mail server rejected the password "
            f"(attempt {attempt}; a rejected login is not retried, because repeating "
            f"it is what locks a mailbox): {detail}"
        )
        stop = None
        if self._guard is not None:
            try:
                stop = self._guard.record_auth_failure(
                    definition.id, at=self._clock(), error=error
                )
            except Exception:  # noqa: BLE001 - the failure is still reported below
                stop = None
        consecutive = stop.consecutive if stop is not None else 1
        limit = stop.limit if stop is not None else self._auth_limit
        first_at = stop.first_at if stop is not None else self._clock()
        marked = bool(stop.marked_failing) if stop is not None else False
        should_notify = bool(stop.should_notify) if stop is not None else True

        owner_notified, owner_error = (False, None)
        if should_notify:
            owner_notified, owner_error = self._notify_owner_auth(
                definition=definition,
                metric_title=metric.title,
                consecutive=consecutive,
                limit=limit,
                first_at=first_at,
                error=error,
                fire_key=outcome.fire_key,
                window_start=outcome.window_start,
                window_end=outcome.window_end,
                marked_failing=marked,
            )
            if self._guard is not None:
                try:
                    self._guard.mark_notified(definition.id, at=self._clock())
                except Exception:  # noqa: BLE001
                    pass

        if stop is None:
            persistence = (
                "This instance has no delivery-health store wired, so this notice "
                "covers this fire only: the next fire will try the mailbox again."
            )
        elif marked:
            persistence = (
                f"Delivery for this definition is stopped at {limit} consecutive "
                "authentication failures; it resumes when the password works or the "
                "window passes."
            )
        else:
            persistence = (
                f"{consecutive} of {limit} consecutive authentication failures recorded "
                "for this definition."
            )
        if owner_notified:
            notice = (
                f"The owner {definition.owner} was notified once and will not be told "
                "again for this streak."
            )
        else:
            notice = f"The owner {definition.owner} could not be notified" + (
                f" ({owner_error})." if owner_error else "."
            )
        return Delivery(
            status=DELIVERY_FAILED,
            fire_key=outcome.fire_key,
            recipients=(),
            blocked=blocked,
            attempts=attempt,
            error=error,
            owner_notified=owner_notified,
            owner_error=owner_error,
            auth_failed=True,
            message=(
                f"Delivery failed: the mail server rejected the password on attempt "
                f"{attempt}, and nothing was retried. {persistence} {notice}"
            ),
        )

    def _notify_owner_auth(
        self,
        *,
        definition: AlertDefinition,
        metric_title: str,
        consecutive: int,
        limit: int,
        first_at: datetime,
        error: str,
        fire_key: str,
        window_start: date,
        window_end: date,
        marked_failing: bool,
    ) -> tuple[bool, str | None]:
        """Send the one notice about a rejected password. Not a retry loop."""
        owner = user_named(definition.owner, self.users_path)
        if owner is None:
            return False, f"the owner {definition.owner} is no longer in the user directory"
        notification = compose_auth_failure(
            definition=definition,
            metric_title=metric_title,
            consecutive=consecutive,
            limit=limit,
            first_at=first_at,
            error=error,
            fire_key=fire_key,
            window_start=window_start,
            window_end=window_end,
            marked_failing=marked_failing,
        )
        message = MailMessage(
            to=(address_for(owner),),
            subject=notification.subject,
            body=notification.body,
            fire_key=fire_key,
        )
        try:
            assert self.sender is not None  # deliver() checked this already
            self.sender.send(message)
        except Exception as exc:
            return False, (
                "sending it also failed: " + redact_transport_error(exc, sender=self.sender)
            )
        return True, None

    # -- the recipient check ------------------------------------------------

    def _permitted(
        self, definition: AlertDefinition, metric: Metric
    ) -> tuple[tuple[User, ...], tuple[Blocked, ...]]:
        """Resolve each recipient now, and check them now.

        The definition stored a recipient *name*. What that name may read is
        decided by the directory as it stands at fire time, through the same
        ``authorize`` boundary the rest of the app uses. Receiving a number is
        a READ, so the check is the query capability plus the metric's table —
        not the alert capability, which governs who may create a definition.
        One person's lost grant does not silence the others.
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
            decision = authorize(user, QUERY, (metric.table,), display=self._titles or None)
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
            return False, (
                "sending it also failed: " + redact_transport_error(exc, sender=self.sender)
            )
        return True, None
