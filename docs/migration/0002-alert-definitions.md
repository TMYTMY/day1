# 0002. Alert definitions, their database, and the `alert` capability

## What changed

An alert definition is stored data: one metric, one comparison, one constant,
one window, one cadence with a local time, a recipient set, an owner, and the
lifecycle fields `state`, `effective_from`, `supersedes`, `confirmed_at` and
`confirmed_by`. A new record starts as a **draft** and never runs. Only its
owner can confirm it into a live definition.

Three things a deployment now reads from the environment:

| Setting | Environment variable | Default |
| --- | --- | --- |
| `alerts_path` | `ALERTS_PATH` | `data/alerts.db` |
| `max_alert_window_days` | `MAX_ALERT_WINDOW_DAYS` | `365` |
| capability grant | `config/users.yaml` | see below |

`data/alerts.db` is the instance's own alert database. It holds
`alert_definitions` today and will hold the job table and the delivery log, so
the file is named for the data rather than for one table in it. It is separate
from the warehouse database and from `audit.db`: an alert definition is not a
warehouse table, and nothing in `src/sql_guard.py` or the read-only adapter
applies to it.

## Do I have to edit my files?

- **`config/users.yaml` — yes, if you want anybody to define an alert.** The
  shipped file grants `alert` to `analyst` only, and leaves `finance` and
  `growth` with `query`. Add the grant to a role that should be able to draft
  and confirm:

  ```yaml
  roles:
    finance:
      tables: [revenue]
      capabilities: [query, alert]
  ```

  A role holding `alert` but not the metric's table still cannot alert on that
  metric: both grants must pass, exactly as for a question.

- **Nothing else.** `data/alerts.db` is created on first use with its one
  table, so an existing instance starts with no alert definitions and needs no
  migration step. An existing `audit.db` gains no column: alert refusals and
  confirmations reuse `event_type` and `capability`, which arrived in
  `docs/migration/0001-capability-grants.md`.

## What a refusal looks like

Refusals happen when the draft is written, not when it is evaluated. Each one
names the offending field, is returned to the caller, and writes one audit row
with `event_type = alert_refused` and `capability = alert`:

| Field | Example message |
| --- | --- |
| `metric` | `The metric DAU by platform still has a placeholder definition, so no alert definition can be built on it.` |
| `window` | `The window is 400 days, beyond the instance maximum of 365 days.` |
| `metric` | `The metric cannot be alerted on. Daily active users is outside the finance role.` |
| `recipient` | `The recipient growth cannot read the alert's metric. Revenue is outside the growth role.` |
| `owner` | `Only the owner of an alert definition can confirm it. The owner is analyst.` |

A window beyond the maximum is **refused, never clamped**: shortening it
silently would answer a question the definer did not ask.

## Operating a definition without the web app

`python -m src.alert_cli` is the operator surface for one instance. It reads the
same `ALERTS_PATH`, `METRICS_PATH`, `USERS_PATH`, `ROUTING_PATH`, `AUDIT_PATH`
and `MAX_ALERT_WINDOW_DAYS` the app reads, so one environment block is one
instance, and nothing here needs Streamlit running (or installed).

| Command | What it does |
| --- | --- |
| `python -m src.alert_cli draft --as analyst --metric revenue_by_product --comparison below_absolute --constant 5000 --window 7 --recipient analyst` | records a draft; prints `id: N` |
| `python -m src.alert_cli confirm 1 --as analyst` | activates draft `#1` as its owner |
| `python -m src.alert_cli list` | one row per definition: id, state, metric, condition, window, recipients, owner, confirmation date |
| `python -m src.alert_cli show 1` | definition `#1` in full, including `supersedes` / `superseded by` |
| `python -m src.alert_cli deactivate 1 --as analyst` | stops evaluating a live definition (the API calls this `pause`) |
| `python -m src.alert_cli resume 1 --as analyst` | makes a deactivated definition live again |

`draft` also takes `--cadence daily`, `--local-time HH:MM` (default `09:00`) and
`--supersedes <id>`; `--recipient` may be repeated.

**A write is made as a named actor.** `--as` names them and the password comes
from `DAY1_CLI_PASSWORD`, or from a prompt when the command is run in a
terminal. There is no `--password` flag on purpose: a flag would put the secret
in the shell history and in `ps`. `list` and `show` take no actor — they read
the instance's own database file, exactly as `sqlite3` on `data/alerts.db`
would, so the boundary there is filesystem access.

**Exit codes are the contract for a script:**

| Code | Meaning |
| --- | --- |
| `0` | the command did what it was asked |
| `1` | refused: the reason is printed with the offending `field` and the stable `reason` code (see the table above) |
| `2` | the command line itself was wrong — a missing or unknown argument, or an id that is not a number |

A refusal from this command is the same refusal the app shows, written by the
same code: it names the offending field, writes one `alert_refused` audit row,
and leaves no definition behind. A usage error (exit `2`) is rejected before the
settings are read, so a typo creates no alert database and no audit row.

## Superseding

`draft(..., supersedes=<id>)` records a new draft that must be confirmed again.
The previous version stays live and confirmed while the replacement waits, and
becomes `superseded` (with `superseded_by` set) at the moment the replacement
is confirmed. Two drafts cannot both replace the same version: the second
confirmation is refused.
