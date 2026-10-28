"""The SMTP connector: presets, the written .env, the hints, and a real send."""

from __future__ import annotations

import asyncio
import smtplib
import stat
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from src.config import load_settings
from src.mail_setup import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_USAGE,
    PRESETS,
    _hint_for,
    interactive,
    main,
    render_env,
    verify,
    write_env,
)

# --- a real SMTP server, on a real socket, so the send path is exercised ----


class _Relay:
    """The smallest SMTP server that can accept one message."""

    def __init__(self) -> None:
        self.messages: list[str] = []
        self.port = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 test ESMTP\r\n")
        await writer.drain()
        body: list[str] = []
        while True:
            line = await reader.readline()
            if not line:
                break
            command = line.decode("utf-8", "replace").strip()
            upper = command.upper()
            if upper.startswith(("EHLO", "HELO")):
                writer.write(b"250-test\r\n250 OK\r\n")
            elif upper.startswith(("MAIL", "RCPT")):
                writer.write(b"250 OK\r\n")
            elif upper.startswith("DATA"):
                writer.write(b"354 End with a line containing a single dot\r\n")
                await writer.drain()
                while True:
                    chunk = await reader.readline()
                    if chunk.strip() == b".":
                        break
                    body.append(chunk.decode("utf-8", "replace"))
                self.messages.append("".join(body))
                writer.write(b"250 Queued\r\n")
            elif upper.startswith("QUIT"):
                writer.write(b"221 Bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 OK\r\n")
            await writer.drain()
        writer.close()

    async def _serve(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        async with self._server:
            await self._server.serve_forever()

    def __enter__(self) -> _Relay:
        self._loop = asyncio.new_event_loop()
        def _run() -> None:
            try:
                self._loop.run_until_complete(self._serve())
            except (asyncio.CancelledError, RuntimeError):
                pass  # the test closed the relay on purpose

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        assert self._ready.wait(10), "the test relay never started"
        return self

    def __exit__(self, *exc: object) -> None:
        if self._server is not None:
            self._server.close()
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)


def _settings_pointing_at(relay: _Relay):
    settings = load_settings()
    return replace(
        settings,
        smtp_host="127.0.0.1",
        smtp_port=relay.port,
        smtp_user=None,
        smtp_password=None,
        smtp_from="day1@example.test",
        smtp_starttls=False,
        smtp_ssl=False,
    )


def test_a_real_message_reaches_the_server():
    with _Relay() as relay:
        result = verify(_settings_pointing_at(relay), "someone@example.test")
        assert result.ok is True, result.detail
        assert relay.messages, "the server saw no message"
        body = relay.messages[0].replace("=\r\n", "")  # unfold the wire form
        flat = " ".join(body.split())
        assert "Subject: [Day 1] SMTP test" in flat
        assert "someone@example.test" in flat
        assert "an alert that fires will arrive the same way" in flat


def test_a_refused_connection_explains_itself():
    settings = replace(load_settings(), smtp_host="127.0.0.1", smtp_port=9, smtp_from="a@b.test")
    result = verify(settings, "someone@example.test", timeout=2)
    assert result.ok is False
    assert result.detail
    assert result.hint


def test_without_a_host_there_is_nothing_to_test():
    result = verify(replace(load_settings(), smtp_host=None), "someone@example.test")
    assert result.ok is False
    assert "SMTP_HOST" in result.detail


# --- presets ---------------------------------------------------------------


def test_each_preset_names_its_transport():
    assert PRESETS["gmail"].port == 587 and PRESETS["gmail"].starttls is True
    assert PRESETS["163"].port == 465 and PRESETS["163"].ssl is True
    assert PRESETS["custom"].starttls is True
    for preset in PRESETS.values():
        assert preset.note, f"{preset.name} must explain itself"


# --- hints -----------------------------------------------------------------


def test_an_authentication_failure_points_at_app_passwords():
    hint = _hint_for(smtplib.SMTPAuthenticationError(535, b"bad credentials"))
    assert "app password" in hint.lower()


def test_a_dropped_connection_points_at_the_tls_mode():
    hint = _hint_for(smtplib.SMTPServerDisconnected("Connection unexpectedly closed"))
    assert "587" in hint and "465" in hint


# --- the written file ------------------------------------------------------


def test_writing_the_env_keeps_every_other_line(tmp_path):
    env = tmp_path / ".env"
    env.write_text("DEEPSEEK_API_KEY=keepme\nSMTP_HOST=old.example.com\nTELEGRAM_BOT_TOKEN=alsokeep\n")
    values = {
        "SMTP_HOST": "smtp.gmail.com",
        "SMTP_PORT": "587",
        "SMTP_USER": "me@gmail.com",
        "SMTP_PASSWORD": "app-password",
        "SMTP_FROM": "me@gmail.com",
        "SMTP_STARTTLS": "true",
        "SMTP_SSL": "false",
    }
    written = write_env(values, env)
    text = written.read_text()
    assert "DEEPSEEK_API_KEY=keepme" in text
    assert "TELEGRAM_BOT_TOKEN=alsokeep" in text
    assert "SMTP_HOST=smtp.gmail.com" in text
    assert "SMTP_HOST=old.example.com" not in text
    assert oct(stat.S_IMODE(written.stat().st_mode)) == oct(0o600)


def test_the_block_is_idempotent():
    values = {"SMTP_HOST": "h", "SMTP_PORT": "587"}
    once = render_env(values, "A=1\n")
    twice = render_env(values, once)
    assert once == twice


# --- the guided path -------------------------------------------------------


def test_the_wizard_writes_the_env_and_reports_the_test(monkeypatch, tmp_path, capsys):
    answers = iter(["gmail", "smtp.gmail.com", "587", "me@gmail.com", "me@gmail.com", "someone@example.test"])
    env_path = tmp_path / ".env"

    import src.mail_setup as mail_setup

    monkeypatch.setattr(
        mail_setup, "verify",
        lambda settings, to: mail_setup.CheckResult(True, f"Delivered to {to}."),
    )
    monkeypatch.setattr(
        mail_setup, "load_settings",
        lambda: replace(load_settings(), smtp_host="smtp.gmail.com"),
    )

    code = interactive(env_path=env_path, ask=lambda q, d="": next(answers), secret=lambda q: "app-password")
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "OK: Delivered to someone@example.test." in out
    text = env_path.read_text()
    assert "SMTP_PASSWORD=app-password" in text
    assert "SMTP_SSL=false" in text


def test_the_wizard_refuses_an_unknown_provider(tmp_path, capsys):
    code = interactive(env_path=tmp_path / ".env", ask=lambda q, d="": "nope", secret=lambda q: "x")
    assert code == EXIT_USAGE
    assert "Unknown provider" in capsys.readouterr().err


def test_check_mode_reports_a_failure_without_prompting(monkeypatch, capsys):
    monkeypatch.setenv("SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("SMTP_PORT", "9")
    monkeypatch.setenv("SMTP_FROM", "a@b.test")
    monkeypatch.setenv("SMTP_STARTTLS", "false")
    code = main(["--check", "--to", "someone@example.test"])
    out = capsys.readouterr().out
    assert code == EXIT_FAILED
    assert "FAILED:" in out
    assert "How to fix:" in out
