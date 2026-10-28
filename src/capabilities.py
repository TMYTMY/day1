"""One permission boundary for every capability a role may run.

A capability is an action the app can take on a person's behalf: ``query``
answers a question, ``alert`` drafts and confirms an alert definition. A role
holds a list of capability grants in ``config/users.yaml``, beside the table
grants it already had.

Every capability asks the same two questions at the same place:

1. May this role use this capability at all?
2. May this role read the tables the action is about?

Both answers are returned as one ``Decision``. A refusal carries a message that
names the capability or the tables and the role, so the caller never has to
build its own wording and cannot forget to check one half. The capability
grant is checked first: a role without the grant learns nothing about tables.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from src.models import User

# The capability that answers a question. Add a name here only when the code
# that runs it also ships, so a typo in users.yaml is refused at load time.
QUERY = "query"
# The capability that drafts and confirms an alert definition, and that its
# recipients must hold for a notification to reach them.
ALERT = "alert"
# The capability that configures the instance: mail settings and the alert
# list. It is not a grant to read warehouse tables.
ADMIN = "admin"
KNOWN_CAPABILITIES = frozenset({QUERY, ALERT, ADMIN})

# Reasons a decision can be refused. They are also what the audit row records
# in its error column, so keep them stable.
CAPABILITY_NOT_GRANTED = "capability_not_granted"
TABLE_NOT_ALLOWED = "table_not_allowed"


def join_names(names: list[str]) -> str:
    """Join names the way the refusal messages read them."""
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"


@dataclass(frozen=True)
class Decision:
    """The permission answer for one capability run.

    ``tables`` holds the tables this decision refused: empty when the run was
    permitted, and empty when the refusal was about the capability rather than
    about a table.
    """

    allowed: bool
    capability: str
    reason: str | None = None
    tables: tuple[str, ...] = ()
    message: str | None = None

    def __bool__(self) -> bool:
        return self.allowed


def authorize(
    user: User,
    capability: str,
    tables: Iterable[str] = (),
    display: Mapping[str, str] | None = None,
) -> Decision:
    """Decide one capability run for one user.

    Both grants must pass. A capability refusal names the capability and the
    role; a table refusal names the tables and the role. Callers pass the whole
    set of tables the action would read and read ``decision.tables`` to learn
    which ones were refused.

    ``display`` maps a table to the name a person knows it by (its topic title).
    When every refused table has one, the refusal reads the way it did before
    capabilities existed — "Daily active users is outside the finance role" —
    because a business user should not be handed a warehouse table id. Tables
    with no friendly name keep the explicit "Table ..." wording, so the two
    cases stay distinguishable.
    """
    if capability not in KNOWN_CAPABILITIES:
        raise ValueError(f"Unknown capability: {capability}")

    if capability not in user.capabilities:
        return Decision(
            allowed=False,
            capability=capability,
            reason=CAPABILITY_NOT_GRANTED,
            message=f"The {capability} capability is not granted to the {user.role} role.",
        )

    allowed_tables = set(user.allowed_tables)
    refused = tuple(dict.fromkeys(table for table in tables if table not in allowed_tables))
    if refused:
        verb = "is" if len(refused) == 1 else "are"
        friendly = display is not None and all(table in display for table in refused)
        if friendly:
            names = [display[table] for table in refused]  # type: ignore[index]
            noun = ""
        else:
            names = list(refused)
            noun = "Table " if len(refused) == 1 else "Tables "
        return Decision(
            allowed=False,
            capability=capability,
            reason=TABLE_NOT_ALLOWED,
            tables=refused,
            message=f"{noun}{join_names(names)} {verb} outside the {user.role} role.",
        )

    return Decision(allowed=True, capability=capability)
