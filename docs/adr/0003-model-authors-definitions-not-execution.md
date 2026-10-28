# 0003. A model may author a definition, never its execution

## Context

Day 1 answers questions by sending a prompt to a language model and executing the SQL that comes back. That is acceptable for a one-off question: the answer is read immediately, and the model's contribution is bounded by the SELECT allowlist and the read-only connection.

Scheduled alerts change the economics. An alert runs unattended, many times, forever, and its output is pushed to somebody's inbox rather than shown inside the app. Under those conditions a per-run model call has three problems:

1. **Cost becomes recurring and invisible.** A daily alert costs something every single day, for as long as the company exists, with nobody watching the bill.
2. **The same definition can produce different output on different days.** A temperature-0 model is stable in practice but not guaranteed to be, and "the alert said 3,878,018.67 yesterday and 3,878,020.14 today for the same period" destroys the audit trail's meaning.
3. **Prompt injection becomes a scheduled event.** A question containing an instruction is one interaction; a stored definition that carries unexpected prose is a payload that re-executes on a timer.

The repository already has the opposite pattern in two places: metric definitions are stored data with `owner` and `effective_from`, and retrieval labels are certified by a human before any number is quoted. Both establish that Day 1 treats *authority* as something a person grants, not something a model asserts.

## Decision

A language model may be used **only when a definition is being authored or edited**. It interviews the human, proposes a precise definition, and writes it down as structured data. Once a human confirms the definition, execution is deterministic: fixed template SQL derived from the metric binding, no model call, no free-form prose in the execution path.

Concretely:

- The interview may ask, interpret, and propose. It may not activate anything.
- An alert definition stores data — metric id, comparison kind, constant, schedule, recipients — never prompt text.
- The executed SQL comes from the metric's template, then passes the same SELECT allowlist, the same read-only connection, and the same row and time limits as any asked question.
- Every run writes one audit event, so an automated answer is as traceable as a asked one.

## Consequences

- Zero marginal model cost per alert per day, which is what makes a per-company price possible at all.
- Identical inputs produce identical outputs, so an audit event can be replayed and the number can be defended months later.
- A stored definition cannot carry an injection payload into execution.
- The vocabulary gains a sharp line — *authoring* versus *execution* — that every future capability must respect. A capability that needs a model at run time has to justify itself against this decision.
- Flexibility is reduced: an alert cannot answer a question nobody anticipated. That is the intended trade. Novel questions stay in the `query` capability, where a model belongs.

## Alternatives rejected

- **Model at fire time.** Rejected for the three reasons in Context; the recurring cost and the unstable audit trail are the disqualifying ones.
- **Model at fire time, with the output cached per period.** Rejected as a half-measure: it hides the cost rather than removing it, and it makes the first run of a period behave differently from a retry.
- **Template SQL authored by the model and stored as SQL text.** Rejected: it puts generated code in the execution path with no reviewable definition behind it, and a schema change would silently break it.
