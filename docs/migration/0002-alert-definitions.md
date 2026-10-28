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

## Superseding

`draft(..., supersedes=<id>)` records a new draft that must be confirmed again.
The previous version stays live and confirmed while the replacement waits, and
becomes `superseded` (with `superseded_by` set) at the moment the replacement
is confirmed. Two drafts cannot both replace the same version: the second
confirmation is refused.
