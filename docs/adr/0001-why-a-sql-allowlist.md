# 0001. Why a SQL allowlist

## Context

Day 1 lets a person ask a business question and get a table back. The SQL is written by a language model, or by a local planner when no key is set. Either writer can be pointed at the wrong table, at more than one statement, or at a function that reads a file. A read-only database role stops some of that after the statement arrives. It does not decide which table the question was supposed to use, and it does not tell the caller why the statement was refused.

## Decision

Two checks run, and neither replaces the other.

The allowlist in `src/sql_guard.py` parses the statement and rejects anything that is not one read-only `SELECT` or `WITH ... SELECT` against the single table routing already permitted. That is the intent check: the wrong table, a second statement, a write, or a banned function never gets a connection.

The SQLite adapter then opens the file with `mode=ro` and sets `PRAGMA query_only`. That is the consequence check: a statement that got past the parser still cannot write.

Database permissions alone are not enough. The parser is what keeps the query on the table the role was allowed to ask about. The read-only connection is what still holds if the parser is wrong.

## Consequences

- A blocked query returns a status and a short message before any rows are read.
- Adding a table means updating the routing map, the role file, and the allowlist's set of permitted names. A new grant in the database does not by itself expose the table.
- The guard is a SQL parser, so a dialect it misreads is a hole. The read-only connection is the backstop, not a reason to skip the parser.
- The same order is fixed: route, then permission, then SQL, then the guard, then the read-only execute.

## Alternatives rejected

- **Rely on the database role only.** A read-only role stops a write. It does not stop a `SELECT` against a table the question was not routed to, and it does not stop a `UNION` that smuggles that table in. The parser has to refuse the intent. The connection has to refuse the effect. Dropping either one leaves the other hole open.
- **Rely on the parser only.** A bug or an unhandled syntax form would then run with a writable connection. `mode=ro` and `PRAGMA query_only` are what make that bug fail closed.
- **Ask the model to police its own SQL.** The model is the component an uploaded note can try to redirect. The check has to sit outside the model.
