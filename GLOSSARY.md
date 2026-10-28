# Glossary

Day 1's domain language. One meaning per term. If a word is overloaded, this file is the tiebreaker — use a different word rather than stretching one of these.

## People and permissions

**Role** — a named set of readable warehouse tables, defined in configuration (e.g. `analyst`, `finance`). Role names are not hardcoded; a company may invent its own. A role says *what a person may read*, nothing about what they may do.

**Capability** — a named action the product can take on a person's behalf. `query` (ask a question, get a governed answer), `alert` (receive a scheduled notification about a metric), and `admin` (configure the instance: mail settings and the alert list) are implemented. `recipe` (run a saved, parameterised report) is planned. A capability is the unit that permissions attach to. `admin` does not grant table access; the owner role that holds it has an empty table list.

**Capability grant** — the binding of one capability to one role, in configuration. Both a capability grant and a table grant must pass for any action: a role that may read `dau` but holds no `alert` grant cannot create an alert on it.

**Level** — a *display* grouping of capability grants, used when talking to users (Level 1 = `query`, Level 2 = `recipe`, Level 3 = `alert`). A level is not stored, not checked, and not a permission of its own. Never write code that branches on a level.

## Metrics and meaning

**Metric** — a catalogue entry that binds a title and a set of synonyms to exactly one table grain. Matching a question to a metric is deterministic; the question must match exactly one.

**Metric definition** — the `definition` text of a metric, plus `owner`, `effective_from` and `supersedes`. Carries the authority of whoever confirmed it. A metric whose definition is a placeholder has no authority, and no number may be reported under it.

**Placeholder** — a metric definition that has not been confirmed by a business owner. Reporting a number under a placeholder is a defect, not a fast answer.

**Confirmation** — the human act of accepting a definition (a metric's or an alert's) as authoritative, recorded with who and when. The agent may *propose* a definition; it may never confirm one, including its own.

## Answers and actions

**Capability run** — one execution of one capability for one actor, whether asked or scheduled. Every capability run writes exactly one audit event, whatever the outcome (`ok`, `clarify`, `denied`, `blocked`, `failed`).

**Query** — a capability run answering a question through routing, metric matching, generation, the SELECT allowlist, and a read-only connection.

**Alert definition** — the stored data that makes scheduled notification possible: one metric, one comparison, one schedule, one recipient set, an owner, and lifecycle fields. It is data, not prose, and not prompt text.

**Activation** — the transition of an alert definition from draft to live. Activation requires confirmation; an unconfirmed draft never fires.

**Fire** — one scheduled evaluation of a live alert definition for one period, regardless of whether the comparison triggered. A fire that does not trigger writes an audit event and sends nothing.

**Period** — the span of data an alert evaluates, resolved from the schedule (the evaluation cadence is daily today).

**Window** — the length of data the comparison looks at, chosen by whoever defines the alert (yesterday, the last N days, or month to date). Window is part of the definition, not a product default: the person defining the alert knows whether they care about one noisy day or a smoothed week. A window is bounded by an instance maximum, and a definition naming a longer one is refused rather than silently clamped.

**Fire** — one scheduled evaluation of a live alert definition, regardless of whether the comparison triggered. A fire that does not trigger writes an audit event and sends nothing.

**Notification** — the email produced by a fire whose comparison triggered. **One notification per triggering fire** — a sustained breach notifies every evaluation, because a silent second day reads as recovery. The fire key, not the notification policy, is what prevents duplicate mail: one period is evaluated once, so a repeated notification always means a new evaluation.

**Delivery** — the act of putting a notification into the mail transport. A delivery is `delivered`, `suppressed`, or `failed`, and it is recorded beside the fire rather than instead of it: a fire can happen and a delivery not. The notification reaches only recipients who may read the metric **when the fire runs**; a recipient set stored on a definition is a claim about who should be told, never a claim about who may still read.

**Suppressed** — a fire whose comparison triggered but where no named recipient may still read the metric. Nothing is sent, and the outcome is its own word: suppressed is neither a success nor an error, because the evaluation was right and the audience was empty.

**Fire key** — the uniqueness key of a fire, built from the alert definition's identity plus the resolved window end. It exists so a restart, a double launch, or an overlapping tick cannot deliver the same period twice.

**State change** — the transition of a comparison from not-triggered to triggered, or back. Recorded for audit and for the notification body, and deliberately **not** used to suppress notifications: a breach that persists is still news.


## Data sources

**Warehouse table** — a table in the instance's own database, seeded or migrated by the instance owner.

**Declared source** — a table that entered the instance through a human running the on-ramp command against a CSV or Excel file. A declared source is answerable only when it also has a routing topic, a role grant, and at least one confirmed metric binding.

**Instance** — one company's Day 1: one directory, one database, one configuration set, one worker. Two instances on one machine share no data and no catalogue. (A single deployment serving several companies is out of scope and is not called an instance.)
