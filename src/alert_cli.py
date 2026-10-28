"""One operator command per instance: draft, confirm, list, show, stop, resume.

An operator runs this on the machine that holds the instance, from a checkout
that has no web server in it::

    python -m src.alert_cli draft --as analyst --metric revenue_by_product \\
        --comparison below_absolute --constant 5000 --window 7 --recipient analyst
    python -m src.alert_cli confirm 1 --as analyst
    python -m src.alert_cli list
    python -m src.alert_cli show 1
    python -m src.alert_cli deactivate 1 --as analyst
    python -m src.alert_cli resume 1 --as analyst

Every path, metric, recipient and window maximum comes from the instance's own
settings (``src.config.load_settings``), so two instances on one machine are two
environment blocks and never two hardcoded paths. Nothing here imports
Streamlit, calls a model, sends mail or starts a scheduler: the command reads
and writes the alert database in ``Settings.alerts_path`` and stops.

Two rules this module keeps:

1. **The command surface never decides anything itself.** Drafting, confirming,
   pausing and resuming go through :class:`src.alerts.AlertService`, so a
   refusal is the service's own wording and its own ``alert_refused`` audit row.
   This module prints that refusal with the offending field and the stable
   reason code, and exits non-zero. It does not re-word a refusal, and it does
   not pre-validate a value the service would have refused: the store stays the
   only authority on what a definition may contain.
2. **A usage error is not a refusal.** A missing or unknown argument is rejected
   by the parser (exit 2) before settings are read, so a typo never creates an
   alert database, writes an audit row, or touches an existing definition.

Exit codes: ``0`` the command did what it was asked, ``1`` a refusal (printed
with its field and reason), ``2`` the command line itself was wrong.

Writes are made as a named actor who proves the demo password: ``--as``, plus a
password from ``DAY1_CLI_PASSWORD`` or an interactive prompt. Reads (``list``,
``show``) take no actor, exactly as reading the instance's database file with
``sqlite3`` would: the permission boundary there is filesystem access.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys

from src.alerts import (
    ABOVE_ABSOLUTE,
    ALERT_UNKNOWN,
    BELOW_ABSOLUTE,
    CADENCES,
    CHANGE_PCT_DOWN,
    CHANGE_PCT_UP,
    COMPARISONS,
    DEFAULT_CADENCE,
    DEFAULT_LOCAL_TIME,
    AlertDefinition,
    AlertResult,
    AlertService,
)
from src.audit import AuditLog
from src.auth import authenticate
from src.config import ConfigError, Settings, load_settings
from src.crypto import SecretKeyError
from src.models import User
from src.routing import load_catalog

# Where a script puts the actor's password. A command-line flag would be a
# secret in the shell history and in `ps`, so there is deliberately none.
PASSWORD_ENV = "DAY1_CLI_PASSWORD"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

PROGRAM = "python -m src.alert_cli"


class CliRefusal(Exception):
    """A refusal to print and exit non-zero on.

    ``field`` and ``reason`` mirror :class:`src.alerts.AlertResult`, so a
    refusal raised here reads the same way as one the service returned.
    """

    def __init__(self, message: str, *, field: str, reason: str):
        super().__init__(message)
        self.message = message
        self.field = field
        self.reason = reason


# --- formatting -----------------------------------------------------------


def _number(value: float) -> str:
    """Print 5000.0 as ``5,000`` and 4999.5 as ``4,999.50``."""
    if float(value).is_integer():
        return f"{int(value):,}"
    return f"{value:,.2f}"


def condition(definition: AlertDefinition) -> str:
    """The comparison as a person reads it: ``below 5,000`` / ``drops 5%``."""
    value = _number(definition.constant)
    if definition.comparison == BELOW_ABSOLUTE:
        return f"below {value}"
    if definition.comparison == ABOVE_ABSOLUTE:
        return f"above {value}"
    if definition.comparison == CHANGE_PCT_DOWN:
        return f"drops {value}%"
    if definition.comparison == CHANGE_PCT_UP:
        return f"rises {value}%"
    # A kind written by a later version. Print it rather than hide it.
    return f"{definition.comparison} {value}"


def window(definition: AlertDefinition) -> str:
    return f"{definition.window_days} day" + ("" if definition.window_days == 1 else "s")


def resolution(definition: AlertDefinition) -> str:
    """The confirmation date, or a dash while the definition is still a draft."""
    if not definition.confirmed_at:
        return "-"
    return definition.confirmed_at.split("T")[0]


def _line(label: str, value: str) -> str:
    return f"{label + ':':<16} {value}"


def _table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    """Columns wide enough for their longest cell, two spaces apart."""
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(headers, widths)).rstrip()]
    for row in rows:
        lines.append("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip())
    return "\n".join(lines)


# --- the instance ---------------------------------------------------------


def _service(settings: Settings) -> AlertService:
    """Build the service from the instance's own settings, the way the app does."""
    return AlertService.from_settings(
        settings,
        audit=AuditLog(settings.audit_path),
        catalog=load_catalog(settings.routing_path),
    )


def _sign_in(name: str, settings: Settings) -> User:
    """Authenticate the named actor, or refuse without saying which half failed."""
    password = os.environ.get(PASSWORD_ENV, "")
    if not password:
        if not sys.stdin.isatty():
            raise CliRefusal(
                f"No password for {name}. Set {PASSWORD_ENV}, or run the command in a terminal.",
                field="actor",
                reason="password_missing",
            )
        password = getpass.getpass(f"Password for {name}: ")
    user = authenticate(name, password, settings.users_path)
    if user is None:
        raise CliRefusal(
            f"The actor {name} is not in the user directory, or the password does not match.",
            field="actor",
            reason="actor_not_authenticated",
        )
    return user


def _require(result: AlertResult) -> AlertResult:
    """Turn a service refusal into the refusal this command prints and exits on."""
    if not result.ok:
        raise CliRefusal(
            result.message,
            field=result.field or "definition",
            reason=result.reason or "refused",
        )
    return result


def _title(service: AlertService, metric_id: str) -> str:
    for metric in service.metrics:
        if metric.id == metric_id:
            return metric.title
    return "(not in the catalogue)"


def _require_definition(service: AlertService, alert_id: int) -> AlertDefinition:
    """Read one definition, refusing an id this instance does not hold."""
    definition = service.definition(alert_id)
    if definition is None:
        raise CliRefusal(
            f"Alert definition #{alert_id} does not exist.",
            field="alert",
            reason=ALERT_UNKNOWN,
        )
    return definition


# --- commands -------------------------------------------------------------


def _draft(args: argparse.Namespace, *, settings: Settings, service: AlertService) -> int:
    owner = _sign_in(args.actor, settings)
    result = _require(
        service.draft(
            owner,
            metric_id=args.metric_id,
            comparison=args.comparison,
            constant=args.constant,
            window_days=args.window_days,
            cadence=args.cadence,
            local_time=args.local_time,
            recipients=tuple(args.recipients),
            supersedes=args.supersedes,
        )
    )
    definition = result.definition
    if definition is not None:
        # The id is what every other command takes, so print it on its own line.
        print(f"id: {definition.id}")
    print(result.message)
    return EXIT_OK


def _confirm(args: argparse.Namespace, *, settings: Settings, service: AlertService) -> int:
    actor = _sign_in(args.actor, settings)
    result = _require(service.confirm(args.alert_id, actor))
    print(result.message)
    return EXIT_OK


def _deactivate(args: argparse.Namespace, *, settings: Settings, service: AlertService) -> int:
    actor = _sign_in(args.actor, settings)
    result = _require(service.pause(args.alert_id, actor))
    print(result.message)
    return EXIT_OK


def _run_now(args: argparse.Namespace, *, settings: Settings, service: AlertService) -> int:
    """Evaluate one definition the way the worker would, and say what happened."""
    from src.worker import OUTCOME_FAILED, OUTCOME_REFUSED, Worker

    actor = _sign_in(args.actor, settings)
    record = service.definition(args.alert_id)
    if record is None:
        raise CliRefusal(
            f"Alert definition #{args.alert_id} does not exist.", field="alert", reason=ALERT_UNKNOWN
        )
    if record.owner != actor.username:
        raise CliRefusal(
            "Only the owner of an alert definition can run it. "
            f"The owner is {record.owner}.",
            field="owner",
            reason="not_owner",
        )

    outcomes = Worker.from_settings(settings).tick(only={args.alert_id})
    if not outcomes:
        raise CliRefusal(
            f"Alert definition #{args.alert_id} is {record.state}, so it is not scheduled.",
            field="state",
            reason="state_not_run",
        )

    outcome = outcomes[0]
    print(f"outcome: {outcome.outcome}")
    print(f"fire key: {outcome.fire_key}")
    if outcome.value is not None:
        print(f"value: {outcome.value}")
    print(outcome.message)
    if outcome.outcome in (OUTCOME_REFUSED, OUTCOME_FAILED):
        return EXIT_REFUSED
    return EXIT_OK


def _resume(args: argparse.Namespace, *, settings: Settings, service: AlertService) -> int:
    actor = _sign_in(args.actor, settings)
    result = _require(service.resume(args.alert_id, actor))
    print(result.message)
    return EXIT_OK


def _list(args: argparse.Namespace, *, settings: Settings, service: AlertService) -> int:
    definitions = service.definitions()
    if not definitions:
        print("No alert definitions on this instance.")
        return EXIT_OK
    rows = [
        (
            str(definition.id),
            definition.state,
            definition.metric_id,
            condition(definition),
            window(definition),
            ", ".join(definition.recipients) or "-",
            definition.owner,
            resolution(definition),
        )
        for definition in definitions
    ]
    print(
        _table(
            ("ID", "STATE", "METRIC", "CONDITION", "WINDOW", "RECIPIENTS", "OWNER", "CONFIRMED"),
            rows,
        )
    )
    return EXIT_OK


def _show(args: argparse.Namespace, *, settings: Settings, service: AlertService) -> int:
    definition = _require_definition(service, args.alert_id)
    lines = [
        _line("id", str(definition.id)),
        _line("state", definition.state),
        _line("live", "yes" if definition.is_live else "no"),
        _line("metric", f"{definition.metric_id} ({_title(service, definition.metric_id)})"),
        _line("condition", condition(definition)),
        _line("constant", _number(definition.constant)),
        _line("comparison", definition.comparison),
        _line("window", window(definition)),
        _line("cadence", f"{definition.cadence} at {definition.local_time}"),
        _line("recipients", ", ".join(definition.recipients)),
        _line("owner", f"{definition.owner} ({definition.owner_role})"),
        _line("created", definition.created_at),
        _line("confirmed", definition.confirmed_at or "-"),
        _line("confirmed by", definition.confirmed_by or "-"),
        _line("effective from", definition.effective_from.isoformat() if definition.effective_from else "-"),
        _line("supersedes", "-" if definition.supersedes is None else f"#{definition.supersedes}"),
        _line(
            "superseded by",
            "-" if definition.superseded_by is None else f"#{definition.superseded_by}",
        ),
    ]
    print("\n".join(lines))
    return EXIT_OK


COMMANDS = ("draft", "confirm", "list", "show", "deactivate", "resume")


# --- command line ---------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Operate one instance's alert definitions without the web app. "
            "Paths and the window maximum come from the environment."
        ),
        epilog=(
            "Exit codes: 0 done, 1 refused (the reason and the offending field are "
            f"printed), 2 the command line was wrong. Writes take --as and read the "
            f"password from {PASSWORD_ENV} or a prompt."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    draft = subparsers.add_parser(
        "draft",
        help="record a draft, which does not run until its owner confirms it",
        description=(
            "Record a draft as the named actor. The draft is checked against the "
            "metric catalogue, the instance window maximum and every recipient's "
            "grants before it is stored, so a refusal leaves nothing behind."
        ),
    )
    draft.add_argument("--as", dest="actor", required=True, metavar="USERNAME")
    draft.add_argument("--metric", dest="metric_id", required=True, metavar="METRIC_ID")
    draft.add_argument(
        "--comparison",
        required=True,
        metavar="KIND",
        help=f"one of: {', '.join(COMPARISONS)}",
    )
    draft.add_argument("--constant", required=True, type=float, metavar="NUMBER")
    draft.add_argument("--window", dest="window_days", required=True, type=int, metavar="DAYS")
    draft.add_argument(
        "--cadence",
        default=DEFAULT_CADENCE,
        metavar="NAME",
        help=f"one of: {', '.join(CADENCES)} (default: {DEFAULT_CADENCE})",
    )
    draft.add_argument(
        "--local-time",
        dest="local_time",
        default=DEFAULT_LOCAL_TIME,
        metavar="HH:MM",
        help=f"24-hour local time the cadence runs at (default: {DEFAULT_LOCAL_TIME})",
    )
    draft.add_argument(
        "--recipient",
        dest="recipients",
        action="append",
        default=[],
        metavar="USERNAME",
        help="may be repeated; at least one is required",
    )
    draft.add_argument(
        "--supersedes",
        type=int,
        default=None,
        metavar="ID",
        help="a live definition this draft will replace once confirmed",
    )
    draft.set_defaults(handler=_draft)

    confirm = subparsers.add_parser(
        "confirm",
        help="activate a draft as its owner",
        description=(
            "Activate a draft. Only its owner may confirm it, and only while it is "
            "still a draft."
        ),
    )
    confirm.add_argument("alert_id", type=int, metavar="ID")
    confirm.add_argument("--as", dest="actor", required=True, metavar="USERNAME")
    confirm.set_defaults(handler=_confirm)

    listing = subparsers.add_parser(
        "list",
        help="every definition on this instance, with its state and confirmation date",
    )
    listing.set_defaults(handler=_list)

    show = subparsers.add_parser("show", help="one definition in full")
    show.add_argument("alert_id", type=int, metavar="ID")
    show.set_defaults(handler=_show)

    deactivate = subparsers.add_parser(
        "deactivate",
        help="stop evaluating a live definition (the API calls this pause)",
        description=(
            "Stop evaluating a live definition. Its history stays in the store, and "
            "it can be resumed."
        ),
    )
    deactivate.add_argument("alert_id", type=int, metavar="ID")
    deactivate.add_argument("--as", dest="actor", required=True, metavar="USERNAME")
    deactivate.set_defaults(handler=_deactivate)

    run_now = subparsers.add_parser(
        "run-now",
        help="evaluate one definition immediately, as its owner",
        description=(
            "Evaluate one definition now, exactly as the scheduled worker would. "
            "At most one fire happens per window: running a window that has already "
            "been evaluated reports a duplicate instead of sending twice."
        ),
    )
    run_now.add_argument("alert_id", type=int, metavar="ID")
    run_now.add_argument("--as", dest="actor", required=True, metavar="USERNAME")
    run_now.set_defaults(handler=_run_now)

    resume = subparsers.add_parser("resume", help="make a deactivated definition live again")
    resume.add_argument("alert_id", type=int, metavar="ID")
    resume.add_argument("--as", dest="actor", required=True, metavar="USERNAME")
    resume.set_defaults(handler=_resume)

    return parser


def _report(refusal: CliRefusal) -> int:
    """Print a refusal with the field and the reason it is refused for."""
    print(f"refused: {refusal.message}", file=sys.stderr)
    print(f"  field: {refusal.field}", file=sys.stderr)
    print(f"  reason: {refusal.reason}", file=sys.stderr)
    return EXIT_REFUSED


def main(argv: list[str] | None = None) -> int:
    """Run one command and return its exit code. Never starts a server."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_request:
        # argparse has already printed the usage message. A bad command line is
        # rejected here, before any settings are read or any store is opened.
        code = exit_request.code
        return EXIT_USAGE if code is None else int(code)

    try:
        settings = load_settings()
        service = _service(settings)
    except (ConfigError, sqlite3.Error) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    try:
        return int(args.handler(args, settings=settings, service=service))
    except CliRefusal as refusal:
        return _report(refusal)
    except SecretKeyError as exc:
        # run-now builds the worker, which reads the mail store. A key that
        # cannot decrypt a stored password is a configuration error, named,
        # and not a traceback and not a fallback to .env.
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
