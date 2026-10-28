"""The operator command surface for alert definitions, driven the way a person does.

Each test calls ``src.alert_cli.main(argv)`` with the instance's paths in the
environment, the way an operator's shell would carry them, and reads what the
command printed and the code it exited with. Two subprocess tests prove the
module entry point works from a clean shell and that importing the command does
not drag the Streamlit app in.
"""

from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml

from src.alert_cli import PASSWORD_ENV, main
from src.config import ROOT

ROUTING = ROOT / "config" / "routing.yaml"

# A temporary instance. alex may read both warehouse tables; rita may read
# revenue only; dina may read daily active users only. alex, rita and dina hold
# the alert capability; finn (finance) and gus (growth) hold query only, so both
# halves of the permission gate can be refused from the command line.
_USERS = """
roles:
  analyst:
    tables: [revenue, dau]
    capabilities: [query, alert]
  revonly:
    tables: [revenue]
    capabilities: [query, alert]
  dauonly:
    tables: [dau]
    capabilities: [query, alert]
  finance:
    tables: [revenue]
    capabilities: [query]
  growth:
    tables: [dau]
    capabilities: [query]

users:
  - username: alex
    password: alex
    role: analyst
  - username: rita
    password: rita
    role: revonly
  - username: dina
    password: dina
    role: dauonly
  - username: finn
    password: finn
    role: finance
  - username: gus
    password: gus
    role: growth
"""

_METRICS = [
    {
        "id": "revenue_confirmed",
        "title": "Revenue by product",
        "synonyms": ["revenue"],
        "table": "revenue",
        "grain": ["event_date", "product", "region", "channel"],
        "additive_over": ["event_date", "product", "region"],
        "definition": "Recognised revenue in USD, net of cancellations.",
        "owner": "finance-reporting",
        "effective_from": "2026-06-15",
        "supersedes": None,
        "exceptions": "Excludes internal test accounts.",
    },
    {
        "id": "dau_confirmed",
        "title": "DAU by platform",
        "synonyms": ["daily active users"],
        "table": "dau",
        "grain": ["event_date", "platform", "country"],
        "additive_over": ["event_date", "platform"],
        "definition": "Distinct users with at least one session that day.",
        "owner": "growth-lead",
        "effective_from": "2026-06-15",
        "supersedes": None,
        "exceptions": "Excludes internal test accounts.",
    },
]

WINDOW_MAXIMUM = 30


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def instance(tmp_path, monkeypatch):
    """One instance whose paths, catalogue and window maximum come from the env."""
    metrics_path = _write(
        tmp_path, "metrics.yaml", yaml.safe_dump(_METRICS, allow_unicode=True, sort_keys=False)
    )
    users_path = _write(tmp_path, "users.yaml", _USERS)
    monkeypatch.setenv("ALERTS_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("METRICS_PATH", str(metrics_path))
    monkeypatch.setenv("USERS_PATH", str(users_path))
    monkeypatch.setenv("ROUTING_PATH", str(ROUTING))
    monkeypatch.setenv("MAX_ALERT_WINDOW_DAYS", str(WINDOW_MAXIMUM))
    monkeypatch.setenv(PASSWORD_ENV, "alex")

    def run(capsys, *argv, password=None):
        """Run one command and return its exit code, stdout and stderr."""
        if password is not None:
            monkeypatch.setenv(PASSWORD_ENV, password)
        code = main([str(part) for part in argv])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return SimpleNamespace(
        tmp_path=tmp_path,
        alerts_path=tmp_path / "alerts.db",
        audit_path=tmp_path / "audit.db",
        users_path=users_path,
        run=run,
        sign_in=monkeypatch.setenv,
    )


def _draft_args(*extra, actor="alex", metric="revenue_confirmed", window=7, recipient="alex"):
    """The happy-path draft, with only what a test cares about overridden."""
    return (
        "draft",
        "--as",
        actor,
        "--metric",
        metric,
        "--comparison",
        "below_absolute",
        "--constant",
        "5000",
        "--window",
        window,
        "--recipient",
        recipient,
        *extra,
    )


def _columns(line: str) -> list[str]:
    """Split one printed row into cells. Cells are separated by two spaces."""
    return re.split(r"\s{2,}", line.strip())


def _audit_events(path):
    if not path.exists():
        return []
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    finally:
        conn.close()


# --- the six commands -----------------------------------------------------


def test_draft_prints_the_new_id_and_exits_zero(instance, capsys):
    code, out, err = instance.run(capsys, *_draft_args())
    assert code == 0, err
    assert "id: 1" in out
    assert "is a draft" in out
    assert err == ""


def test_confirm_activates_the_draft_as_its_owner(instance, capsys):
    instance.run(capsys, *_draft_args())
    code, out, err = instance.run(capsys, "confirm", 1, "--as", "alex")
    assert code == 0, err
    assert "confirmed and live" in out
    code, out, _ = instance.run(capsys, "show", 1)
    assert "state:           confirmed" in out
    assert "live:            yes" in out


def test_list_shows_state_metric_condition_window_recipients_owner_and_date(instance, capsys):
    instance.run(capsys, *_draft_args("--recipient", "rita"))
    instance.run(capsys, "confirm", 1, "--as", "alex")

    code, out, err = instance.run(capsys, "list")

    assert code == 0, err
    header, row = out.splitlines()[0], out.splitlines()[1]
    assert _columns(header) == [
        "ID",
        "STATE",
        "METRIC",
        "CONDITION",
        "WINDOW",
        "RECIPIENTS",
        "OWNER",
        "CONFIRMED",
    ]
    # One row per definition: status, metric, condition, window, recipients,
    # owner and the confirmation date, all readable in a terminal.
    cells = _columns(row)
    assert cells[:6] == [
        "1",
        "confirmed",
        "revenue_confirmed",
        "below 5,000",
        "7 days",
        "alex, rita",
    ]
    assert cells[6] == "alex"
    assert cells[7][:4] == "2026"


def test_a_draft_lists_a_dash_in_place_of_a_confirmation_date(instance, capsys):
    instance.run(capsys, *_draft_args())
    code, out, _ = instance.run(capsys, "list")
    assert code == 0
    assert out.splitlines()[1].split()[-1] == "-"


def test_list_on_an_instance_with_no_definitions_says_so(instance, capsys):
    code, out, err = instance.run(capsys, "list")
    assert code == 0, err
    assert "No alert definitions on this instance." in out


def test_show_prints_one_definition_in_full(instance, capsys):
    instance.run(capsys, *_draft_args())
    instance.run(capsys, "confirm", 1, "--as", "alex")

    code, out, err = instance.run(capsys, "show", 1)

    assert code == 0, err
    for expected in (
        "metric:          revenue_confirmed (Revenue by product)",
        "condition:       below 5,000",
        "comparison:      below_absolute",
        "window:          7 days",
        "cadence:         daily at 09:00",
        "recipients:      alex",
        "owner:           alex (analyst)",
        "confirmed by:    alex",
        "effective from:  2026",
        "supersedes:      -",
    ):
        assert expected in out


def test_deactivate_pauses_a_live_definition_and_resume_brings_it_back(instance, capsys):
    instance.run(capsys, *_draft_args())
    instance.run(capsys, "confirm", 1, "--as", "alex")

    code, out, err = instance.run(capsys, "deactivate", 1, "--as", "alex")
    assert code == 0, err
    assert "paused" in out
    code, out, _ = instance.run(capsys, "list")
    assert out.splitlines()[1].split()[1] == "paused"

    code, out, err = instance.run(capsys, "resume", 1, "--as", "alex")
    assert code == 0, err
    assert "live again" in out
    code, out, _ = instance.run(capsys, "list")
    assert out.splitlines()[1].split()[1] == "confirmed"


def test_a_draft_can_replace_a_live_definition_through_the_command_line(instance, capsys):
    instance.run(capsys, *_draft_args())
    instance.run(capsys, "confirm", 1, "--as", "alex")

    code, out, err = instance.run(capsys, *_draft_args("--supersedes", 1, window=14))
    assert code == 0, err
    assert "id: 2" in out
    code, out, err = instance.run(capsys, "confirm", 2, "--as", "alex")
    assert code == 0, err
    assert "superseded" in out

    code, out, _ = instance.run(capsys, "show", 1)
    assert "state:           superseded" in out
    assert "superseded by:   #2" in out


# --- refusals: printed with the reason, and non-zero ----------------------


def test_a_window_beyond_the_instance_maximum_is_refused_and_exits_non_zero(instance, capsys):
    code, out, err = instance.run(capsys, *_draft_args(window=WINDOW_MAXIMUM + 10))
    assert code == 1
    assert out == ""
    assert "The window is 40 days, beyond the instance maximum of 30 days." in err
    assert "field: window" in err
    assert "reason: window_too_long" in err
    # A refused draft leaves nothing behind that a later reader could confirm.
    code, out, _ = instance.run(capsys, "list")
    assert "No alert definitions on this instance." in out


def test_a_role_without_the_alert_capability_is_refused_naming_the_capability(instance, capsys):
    code, _, err = instance.run(capsys, *_draft_args(actor="finn"), password="finn")
    assert code == 1
    assert "The alert capability is not granted to the finance role." in err
    assert "field: capability" in err
    assert "reason: capability_not_granted" in err


def test_a_metric_the_actor_cannot_read_is_refused_naming_the_topic(instance, capsys):
    code, _, err = instance.run(
        capsys, *_draft_args(actor="rita", metric="dau_confirmed"), password="rita"
    )
    assert code == 1
    assert "Daily active users is outside the revonly role." in err
    assert "field: metric" in err


def test_a_recipient_without_the_alert_capability_is_refused_by_name(instance, capsys):
    code, _, err = instance.run(capsys, *_draft_args(recipient="gus"))
    assert code == 1
    assert "The recipient gus does not hold the alert capability." in err
    assert "field: recipient" in err
    assert "reason: recipient_no_capability" in err


def test_a_recipient_who_cannot_read_the_metric_is_refused_by_name(instance, capsys):
    code, _, err = instance.run(capsys, *_draft_args(recipient="dina"))
    assert code == 1
    assert "The recipient dina cannot read the alert's metric." in err
    assert "field: recipient" in err
    assert "reason: recipient_not_readable" in err


def test_an_unknown_recipient_is_refused_by_name(instance, capsys):
    code, _, err = instance.run(capsys, *_draft_args(recipient="nobody"))
    assert code == 1
    assert "The recipient nobody is not in the user directory." in err
    assert "field: recipient" in err


def test_an_empty_recipient_list_is_refused_naming_the_field(instance, capsys):
    code, _, err = instance.run(
        capsys,
        "draft",
        "--as",
        "alex",
        "--metric",
        "revenue_confirmed",
        "--comparison",
        "below_absolute",
        "--constant",
        "5000",
        "--window",
        "7",
    )
    assert code == 1
    assert "The recipients list is empty." in err
    assert "field: recipients" in err


def test_an_unknown_comparison_is_refused_by_the_store_naming_the_field(instance, capsys):
    code, _, err = instance.run(capsys, *_draft_args("--comparison", "sideways"))
    assert code == 1
    assert "The comparison 'sideways' is not one of below_absolute" in err
    assert "reason: comparison_unknown" in err


def test_confirming_as_somebody_else_is_refused_naming_the_owner(instance, capsys):
    instance.run(capsys, *_draft_args())
    code, _, err = instance.run(capsys, "confirm", 1, "--as", "rita", password="rita")
    assert code == 1
    assert "Only the owner of an alert definition can confirm it. The owner is alex." in err
    assert "field: owner" in err
    assert "reason: not_owner" in err


def test_confirming_twice_is_refused_naming_the_state(instance, capsys):
    instance.run(capsys, *_draft_args())
    instance.run(capsys, "confirm", 1, "--as", "alex")
    code, _, err = instance.run(capsys, "confirm", 1, "--as", "alex")
    assert code == 1
    assert "is confirmed, not a draft" in err
    assert "field: state" in err


def test_deactivating_a_draft_is_refused_not_silently_accepted(instance, capsys):
    instance.run(capsys, *_draft_args())
    code, _, err = instance.run(capsys, "deactivate", 1, "--as", "alex")
    assert code == 1
    assert "is draft, so there is nothing to pause." in err
    assert "field: state" in err


def test_showing_an_unknown_definition_is_refused(instance, capsys):
    code, out, err = instance.run(capsys, "show", 99)
    assert code == 1
    assert out == ""
    assert "Alert definition #99 does not exist." in err
    assert "field: alert" in err
    assert "reason: alert_unknown" in err


def test_a_wrong_password_is_refused_without_saying_which_half_failed(instance, capsys):
    code, _, err = instance.run(capsys, *_draft_args(), password="wrong")
    assert code == 1
    assert "not in the user directory, or the password does not match" in err
    assert "field: actor" in err


def test_a_refusal_goes_through_the_service_so_it_is_audited(instance, capsys):
    instance.run(capsys, *_draft_args(window=WINDOW_MAXIMUM + 1))
    rows = _audit_events(instance.audit_path)
    refused = [row for row in rows if row["event_type"] == "alert_refused"]
    assert len(refused) == 1
    assert refused[0]["capability"] == "alert"
    assert refused[0]["status"] == "denied"
    assert refused[0]["error"].startswith("window_too_long: ")


# --- the command line itself ----------------------------------------------


def test_a_missing_required_argument_exits_two_without_touching_the_store(
    instance, capsys, tmp_path
):
    alerts_path = tmp_path / "untouched" / "alerts.db"
    instance.sign_in("ALERTS_PATH", str(alerts_path))
    instance.sign_in("AUDIT_PATH", str(tmp_path / "untouched" / "audit.db"))

    code, _, err = instance.run(capsys, "draft", "--as", "alex", "--metric", "revenue_confirmed")

    assert code == 2
    assert "the following arguments are required" in err
    assert not alerts_path.exists()
    assert not (tmp_path / "untouched" / "audit.db").exists()


def test_an_unknown_command_exits_two(instance, capsys):
    code, _, err = instance.run(capsys, "conspire")
    assert code == 2
    assert "invalid choice: 'conspire'" in err


def test_an_unknown_option_exits_two(instance, capsys):
    code, _, err = instance.run(capsys, "list", "--all")
    assert code == 2
    assert "unrecognized arguments: --all" in err


def test_a_non_numeric_definition_id_exits_two(instance, capsys):
    code, _, err = instance.run(capsys, "show", "one")
    assert code == 2
    assert "invalid int value: 'one'" in err


def test_every_command_is_listed_in_the_top_level_help(instance, capsys):
    code, out, err = instance.run(capsys, "--help")
    assert code == 0, err
    for command in ("draft", "confirm", "list", "show", "deactivate", "resume"):
        assert command in out


# --- one command per instance, no web app ---------------------------------


def test_two_instances_read_their_own_alert_database(instance, capsys, tmp_path, monkeypatch):
    instance.run(capsys, *_draft_args())
    other = tmp_path / "company-b"
    monkeypatch.setenv("ALERTS_PATH", str(other / "alerts.db"))
    monkeypatch.setenv("AUDIT_PATH", str(other / "audit.db"))

    code, out, err = instance.run(capsys, "list")

    assert code == 0, err
    assert "No alert definitions on this instance." in out


def test_the_command_runs_from_a_clean_shell(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "src.alert_cli", "--help"],
        cwd=ROOT,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "Operate one instance's alert definitions without the web app." in result.stdout


def test_the_module_entry_point_reads_the_instance_paths(tmp_path):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "PYTHONPATH": str(ROOT),
        "ALERTS_PATH": str(tmp_path / "alerts.db"),
        "AUDIT_PATH": str(tmp_path / "audit.db"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "src.alert_cli", "list"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "No alert definitions on this instance." in result.stdout
    assert (tmp_path / "alerts.db").exists()


def test_importing_the_command_does_not_import_the_web_app(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, src.alert_cli; print('streamlit' in sys.modules)",
        ],
        cwd=ROOT,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
