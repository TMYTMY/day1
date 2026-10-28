"""Set up and verify the SMTP connection Day 1 uses to deliver alerts.

Why this exists: everything before this point decides *what* to send, and the
worker refuses to run without a transport. This module is how a human, once per
instance, turns a mail provider into that transport — a preset per provider, a
guided prompt, a written `.env`, and a real test send whose failure explains
itself. The password is asked for, never echoed, and the wizard stores it
only in the instance's own `.env` (mode 600). The Settings page stores an
encrypted copy in the instance database; ``--check`` resolves that database
first and this file second, which is the same order the worker uses.

Nothing here sends mail at alert time. The delivery path is
:class:`src.notify.SmtpSender`. ``--init-key`` writes ``DAY1_SECRET_KEY`` when
the file does not already hold one, does not rewrite any other line, and
refuses when the settings database already holds ciphertext: a key minted on
top of stored secrets can never read them.
"""

from __future__ import annotations

import argparse
import getpass
import os
import socket
import smtplib
import ssl
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from src.config import ROOT, ConfigError, Settings, load_settings
from src.crypto import SecretKeyError, generate_key
from src.mail_settings import resolve_mail_settings, stored_ciphertext_fields
from src.notify import MailMessage, SmtpSender
from src.redaction import redact_mail_error

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

ENV_FILE = ROOT / ".env"

COMMENT = "# SMTP transport for alert delivery (added by src.mail_setup)"
SECRET_KEY_NAME = "DAY1_SECRET_KEY"

SMTP_KEYS = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "SMTP_FROM",
    "SMTP_STARTTLS",
    "SMTP_SSL",
)


@dataclass(frozen=True)
class Preset:
    """One provider's connection facts, so nobody has to know their port."""

    name: str
    host: str
    port: int
    starttls: bool
    ssl: bool
    note: str


PRESETS: dict[str, Preset] = {
    "gmail": Preset(
        "gmail", "smtp.gmail.com", 587, True, False,
        "Gmail needs a 16-character App Password (2-Step Verification must be on); "
        "your normal Google password is refused.",
    ),
    "outlook": Preset(
        "outlook", "smtp-mail.outlook.com", 587, True, False,
        "Microsoft 365 / Outlook may require an app password, and a tenant can "
        "block SMTP AUTH entirely — check with whoever runs the tenant.",
    ),
    "yahoo": Preset(
        "yahoo", "smtp.mail.yahoo.com", 587, True, False,
        "Yahoo also requires an app password.",
    ),
    "qq": Preset("qq", "smtp.qq.com", 587, True, False, "QQ Mail uses an authorisation code, not the login password."),
    "163": Preset("163", "smtp.163.com", 465, False, True, "163 uses implicit TLS on 465 and a client authorisation code."),
    "custom": Preset("custom", "", 587, True, False, "Your own relay: give the host and port."),
}


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    detail: str
    hint: str = ""


def _hint_for(exc: BaseException) -> str:
    """Turn a mail failure into something a person can act on."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return (
            "The server accepted the connection but refused the login. Almost always "
            "this is a normal password where an app password is required, or 2-Step "
            "Verification is off. For Gmail: myaccount.google.com/apppasswords."
        )
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return (
            "The server does not offer the authentication or STARTTLS this instance "
            "asked for. Try the provider preset again, or try the other TLS mode."
        )
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return (
            "The connection dropped mid-conversation. Usually the wrong TLS mode for "
            "the port: 587 wants STARTTLS, 465 wants implicit SSL."
        )
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "The server refused the recipient address."
    if isinstance(exc, smtplib.SMTPConnectError):
        return "The server answered but rejected the connection. Check the port."
    if isinstance(exc, (socket.gaierror, socket.herror)):
        return "The host name does not resolve. Check for a typo in SMTP_HOST."
    if isinstance(exc, (ConnectionRefusedError, OSError)) and "timed out" not in str(exc).lower():
        return (
            "Nothing is listening at that host and port, or a firewall dropped the "
            "connection. Check the port: 587 (STARTTLS) or 465 (SSL)."
        )
    if isinstance(exc, (TimeoutError, ssl.SSLError)):
        return "The connection timed out or TLS negotiation failed. Check the port and the TLS mode."
    return ""


def verify(settings: Settings, to: str, *, timeout: float = 30.0) -> CheckResult:
    """Send one real message and report what happened, in words."""
    if not settings.smtp_host:
        return CheckResult(False, "SMTP_HOST is not set, so there is nothing to test.", "Run the setup first.")
    if not to:
        return CheckResult(False, "No destination address was given.", "Pass --to you@example.com.")
    sender = SmtpSender(
        host=settings.smtp_host,
        port=int(settings.smtp_port),
        sender=settings.smtp_from,
        user=settings.smtp_user,
        password=settings.smtp_password,
        starttls=bool(settings.smtp_starttls),
        ssl=bool(settings.smtp_ssl),
        timeout=timeout,
    )
    message = MailMessage(
        to=(to,),
        subject="[Day 1] SMTP test — this instance can deliver alerts",
        body=(
            "This is a test message from Day 1.\n\n"
            "If you are reading it, the instance's SMTP connection works: an alert "
            "that fires will arrive the same way.\n\n"
            f"Host: {settings.smtp_host}:{settings.smtp_port} "
            f"({'SSL' if settings.smtp_ssl else 'STARTTLS' if settings.smtp_starttls else 'no TLS'})\n"
            f"From: {settings.smtp_from}\n"
        ),
        fire_key="smtp-test",
    )
    try:
        sender.send(message)
    except smtplib.SMTPAuthenticationError as exc:
        return CheckResult(False, f"The server refused the login (code {exc.smtp_code}).", _hint_for(exc))
    except Exception as exc:  # noqa: BLE001 - every failure has to be explained, not raised
        detail = redact_mail_error(
            f"{type(exc).__name__}: {exc}".strip(),
            password=settings.smtp_password,
            user=settings.smtp_user,
        )
        return CheckResult(False, detail, _hint_for(exc))
    return CheckResult(True, f"Delivered to {to} through {settings.smtp_host}:{settings.smtp_port}.")


def render_env(values: dict[str, str], existing: str = "") -> str:
    """Merge SMTP keys into a `.env`, leaving every other line untouched."""
    kept: list[str] = []
    for line in existing.splitlines():
        if line.startswith(COMMENT):
            continue
        key = line.split("=", 1)[0].strip()
        if key in SMTP_KEYS:
            continue
        kept.append(line)
    while kept and not kept[-1].strip():
        kept.pop()
    block = ["", COMMENT]
    block += [f"{key}={values[key]}" for key in SMTP_KEYS if key in values]
    return "\n".join(kept + block) + "\n"


def write_env(values: dict[str, str], path: Path = ENV_FILE) -> Path:
    """Write the SMTP keys into the instance's `.env`, readable by its owner only."""
    existing = path.read_text() if path.exists() else ""
    path.write_text(render_env(values, existing))
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600: it holds a password
    return path


def settings_database(path: Path | None = None) -> Path:
    """The instance settings database, resolved the way ``load_settings`` resolves it."""
    if path is not None:
        return Path(path)
    try:
        return load_settings().settings_path
    except ConfigError:  # pragma: no cover - a broken env still has a default store
        return ROOT / "data" / "instance.db"


def init_secret_key(path: Path = ENV_FILE, *, settings_path: Path | None = None) -> bool:
    """Create ``DAY1_SECRET_KEY`` when the file does not already hold one.

    Returns True when a key was written. A line that already has a value is
    left untouched, including its mode. An empty assignment is filled in place.
    Every other line stays as it was. A file this function writes is mode 600.

    It refuses outright when the settings database already holds ciphertext.
    A key minted on top of stored secrets cannot read them: ``data/`` restored
    without ``.env`` would silently orphan every value, and nothing would say
    so until the next alert failed to authenticate. Naming the recovery step is
    the whole point of the refusal, so the message names both of them.
    """
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = existing.splitlines()
    for line in lines:
        body = line.split("#", 1)[0].strip()
        name, sep, value = body.partition("=")
        if name.strip() == SECRET_KEY_NAME and sep and value.strip():
            return False
    database = settings_database(settings_path)
    stored = stored_ciphertext_fields(database)
    if stored:
        raise SecretKeyError(
            f"Refusing to create {SECRET_KEY_NAME}: {database} already holds an encrypted "
            f"{', '.join(stored)}. A new key cannot read it, so creating one here would "
            "orphan the stored secret in place. Restore the key that wrote it (the .env of "
            "the instance this data came from, or your secret manager) and run "
            f"python -m src.mail_setup --check --to you@example.com to confirm it reads. "
            "If that key is lost, clear the stored mail settings first — Settings, Mail "
            "settings, 'Clear stored mail settings', which needs no key — then run "
            "--init-key and enter the mail password again."
        )
    key = generate_key()
    replaced = False
    new_lines: list[str] = []
    for line in lines:
        body = line.split("#", 1)[0].strip()
        name, sep, value = body.partition("=")
        if name.strip() == SECRET_KEY_NAME and sep and not value.strip() and not replaced:
            comment = ""
            marker = line.find("#")
            if marker != -1:
                comment = " " + line[marker:]
            new_lines.append(f"{SECRET_KEY_NAME}={key}{comment}")
            replaced = True
            continue
        new_lines.append(line)
    if not replaced:
        new_lines.append(f"{SECRET_KEY_NAME}={key}")
    text = "\n".join(new_lines)
    if text and not text.endswith("\n"):
        text += "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return True


def values_for(preset: Preset, *, host: str, port: int, user: str, password: str, sender: str) -> dict[str, str]:
    return {
        "SMTP_HOST": host,
        "SMTP_PORT": str(port),
        "SMTP_USER": user,
        "SMTP_PASSWORD": password,
        "SMTP_FROM": sender or user,
        "SMTP_STARTTLS": "true" if preset.starttls else "false",
        "SMTP_SSL": "true" if preset.ssl else "false",
    }


def _ask(question: str, default: str = "", *, ask=input) -> str:
    prompt = f"{question}" + (f" [{default}]" if default else "") + ": "
    answer = ask(prompt).strip()
    return answer or default


def interactive(*, env_path: Path = ENV_FILE, ask=input, secret=getpass.getpass) -> int:
    """Walk a human through it once. The only step an agent cannot do for them."""
    print("Day 1 — SMTP setup")
    print("This writes the instance's .env and then sends one real test message.")
    print("Nothing is printed back; the password is stored only in .env (mode 600).\n")
    print("Providers: " + ", ".join(PRESETS))
    choice = _ask("Provider", "gmail", ask=ask).lower()
    if choice not in PRESETS:
        print(f"Unknown provider {choice!r}. Choose one of: {', '.join(PRESETS)}", file=sys.stderr)
        return EXIT_USAGE
    preset = PRESETS[choice]
    print(f"  {preset.note}")

    if preset.name == "custom":
        host = _ask("SMTP host", ask=ask)
        port_text = _ask("Port", "587", ask=ask)
    else:
        host = _ask("SMTP host", preset.host, ask=ask)
        port_text = _ask("Port", str(preset.port), ask=ask)
    try:
        port = int(port_text)
    except ValueError:
        print(f"Port must be a number, not {port_text!r}.", file=sys.stderr)
        return EXIT_USAGE

    user = _ask("Username (the full email address usually)", ask=ask)
    password = secret("Password / app password (not shown): ")
    sender = _ask("From address", user, ask=ask)
    destination = _ask("Send the test message to", user, ask=ask)

    values = values_for(preset, host=host, port=port, user=user, password=password, sender=sender)
    written = write_env(values, env_path)
    print(f"\nWrote {written} (mode 600, SMTP keys only).")

    os.environ.update({key: value for key, value in values.items()})
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"The written settings do not load: {exc}", file=sys.stderr)
        return EXIT_FAILED

    print(f"Sending a test message to {destination} …")
    result = verify(settings, destination)
    print(("OK: " if result.ok else "FAILED: ") + result.detail)
    if result.hint:
        print(f"How to fix: {result.hint}")
    return EXIT_OK if result.ok else EXIT_FAILED


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.mail_setup",
        description="Set up and verify the SMTP connection alert delivery uses.",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="do not prompt: test the mail settings already in place and exit",
    )
    parser.add_argument("--to", dest="destination", default="", help="test recipient for --check")
    parser.add_argument(
        "--init-key", action="store_true",
        help="create DAY1_SECRET_KEY in .env if it is absent, without changing other lines",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.init_key:
        try:
            created = init_secret_key(ENV_FILE)
        except SecretKeyError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_FAILED
        if created:
            print(f"Wrote {SECRET_KEY_NAME} to {ENV_FILE} (mode 600).")
        else:
            print(f"{SECRET_KEY_NAME} is already present in {ENV_FILE}; left it untouched.")
        if not args.check:
            return EXIT_OK

    if args.check:
        try:
            settings = resolve_mail_settings(load_settings())
        except (ConfigError, SecretKeyError) as exc:
            print(f"Settings do not load: {exc}", file=sys.stderr)
            return EXIT_FAILED
        result = verify(settings, args.destination)
        print(("OK: " if result.ok else "FAILED: ") + result.detail)
        if result.hint:
            print(f"How to fix: {result.hint}")
        return EXIT_OK if result.ok else EXIT_FAILED

    return interactive()


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
