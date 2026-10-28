# 0001. Capability grants in `config/users.yaml`

## What changed

Each role in `config/users.yaml` can carry a `capabilities` list beside the
`tables` list it already had:

```yaml
roles:
  finance:
    tables: [revenue]
    capabilities: [query]
```

The table grants are unchanged. A capability grant is additive: it says which
actions a role may run, while the table grant says which tables an action may
read. Both have to pass (`src/capabilities.py`).

## Do I have to edit my file?

No. A role with no `capabilities` key implies `[query]`, which is what every
role could do before this change. An existing `users.yaml` keeps answering
questions without an edit.

```yaml
roles:
  finance:
    tables: [revenue]      # same as: capabilities: [query]
```

The implied grant is a migration default, not a permanent rule. Add the key
explicitly when you copy the file for a new deployment, so the grant is
visible to whoever reviews it.

## Differences worth knowing

- `capabilities: []` is not the same as leaving the key out. An explicit empty
  list withholds every capability: the role can sign in and nothing else. Use
  it to park an account without deleting it.
- A capability name the code does not implement is refused when the file is
  loaded, not at question time, so a typo such as `querry` fails at startup
  instead of quietly granting nothing. The names that are implemented live in
  `KNOWN_CAPABILITIES` in `src/capabilities.py`.
- Duplicate names are collapsed; order does not matter.

## Audit database

`audit_events` gains two nullable columns, `event_type` and `capability`. An
existing audit file is altered on open, the same way the metric and source
columns were added. Old rows keep reading with those columns empty; new rows
record `event_type` (`question` for a question, `capability_refusal` when the
permission gate refused the run) and `capability` (`query`).

Nothing has to be migrated by hand and no rows are rewritten.
