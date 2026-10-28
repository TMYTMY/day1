"""Password stand-in for SSO.

Replace `authenticate` with the company identity provider. Callers only need
a User(username, role, allowed_tables, capabilities). Passwords in
config/users.yaml are demo credentials for the local sample database.

A role holds two grants: the tables it may read and the capabilities it may
run. A role with no `capabilities` key implies the query capability, which is
how every role behaved before capabilities existed (see
docs/migration/0001-capability-grants.md).

One account has no password in this file: the operator account, which holds
``admin``. It proves itself with the secret ``python -m src.operator_secret
--init`` generates on the host and keeps only as a salted hash in the instance
settings database. A credential that grants ``admin`` and ships in the
repository is a decorative gate; one that exists only on the box is not.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path

import yaml

from src.capabilities import KNOWN_CAPABILITIES, QUERY
from src.config import ConfigError
from src.models import User

# What a role could do before capabilities existed: ask a question.
IMPLIED_CAPABILITIES: tuple[str, ...] = (QUERY,)

# How an account proves who it is. ``password`` is the demo stand-in that
# ships in this file; ``operator_secret`` is the host-generated secret whose
# hash lives in the instance settings database, and it never ships at all.
PASSWORD_CREDENTIAL = "password"
OPERATOR_CREDENTIAL = "operator_secret"
CREDENTIALS = (PASSWORD_CREDENTIAL, OPERATOR_CREDENTIAL)


@dataclass(frozen=True)
class _Account:
    username: str
    password: str
    role: str
    email: str | None = None
    credential: str = PASSWORD_CREDENTIAL


@dataclass(frozen=True)
class Directory:
    roles: dict[str, tuple[str, ...]]
    capabilities: dict[str, tuple[str, ...]]
    accounts: dict[str, _Account]


def _role_capabilities(role: str, spec: dict) -> tuple[str, ...]:
    """Read the capability grants for one role.

    An absent key means the implied query grant. An explicit empty list means
    both grants are withheld on purpose, so the role can run nothing.
    """
    raw = spec.get("capabilities")
    if raw is None:
        return IMPLIED_CAPABILITIES
    if not isinstance(raw, list) or not all(isinstance(item, str) and item for item in raw):
        raise ConfigError(f"Role {role} capabilities must be a list of capability names.")
    unknown = sorted({item for item in raw if item not in KNOWN_CAPABILITIES})
    if unknown:
        raise ConfigError(f"Role {role} grants unknown capabilities: {', '.join(unknown)}")
    return tuple(dict.fromkeys(raw))


def load_directory(path: Path) -> Directory:
    if not path.is_file():
        raise ConfigError(f"User directory not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError("User directory must be a mapping.")
    roles_raw = raw.get("roles")
    users_raw = raw.get("users")
    if not isinstance(roles_raw, dict) or not roles_raw:
        raise ConfigError("User directory needs a roles map.")
    if not isinstance(users_raw, list) or not users_raw:
        raise ConfigError("User directory needs a users list.")

    roles: dict[str, tuple[str, ...]] = {}
    capabilities: dict[str, tuple[str, ...]] = {}
    for role, spec in roles_raw.items():
        if not isinstance(role, str) or not isinstance(spec, dict):
            raise ConfigError("Each role needs a tables list.")
        tables = spec.get("tables")
        # An empty list is legal. The owner role uses one: administering the
        # instance is not a grant to read its warehouse tables. A missing list,
        # or a list that is not names, is still a broken file.
        if not isinstance(tables, list) or not all(isinstance(item, str) and item for item in tables):
            raise ConfigError(f"Role {role} needs a list of table names.")
        roles[role] = tuple(tables)
        capabilities[role] = _role_capabilities(role, spec)

    accounts: dict[str, _Account] = {}
    for entry in users_raw:
        if not isinstance(entry, dict):
            raise ConfigError("Each user entry must be a mapping.")
        username = entry.get("username")
        password = entry.get("password")
        role = entry.get("role")
        credential = entry.get("credential", PASSWORD_CREDENTIAL)
        if not isinstance(credential, str) or credential not in CREDENTIALS:
            raise ConfigError(
                f"User {username} has an unknown credential {credential!r}. "
                f"Use one of {', '.join(CREDENTIALS)}."
            )
        if credential == OPERATOR_CREDENTIAL:
            # No password in the file: the secret is generated on the host and
            # only its hash is stored. A password beside it would be a second
            # way in, which is the thing this account exists to remove.
            if password:
                raise ConfigError(
                    f"User {username} has both a password and the operator secret, "
                    "which would be two ways in. Remove the password."
                )
            password = ""
            required = (username, role)
        else:
            required = (username, password, role)
        if not all(isinstance(value, str) and value for value in required):
            raise ConfigError("Each user needs a username, a password, and a role.")
        if role not in roles:
            raise ConfigError(f"User {username} references unknown role {role}.")
        email = entry.get("email")
        if email is not None and (not isinstance(email, str) or "@" not in email):
            raise ConfigError(f"User {username} has an email that is not an address.")
        assert isinstance(username, str) and isinstance(password, str)
        accounts[username] = _Account(
            username=username,
            password=password,
            role=role,
            email=email.strip() if isinstance(email, str) else None,
            credential=credential,
        )
    return Directory(roles=roles, capabilities=capabilities, accounts=accounts)


def authenticate(
    username: str,
    password: str,
    path: Path,
    *,
    settings_path: Path | None = None,
) -> User | None:
    """Return the user when the credential matches, otherwise None.

    A demo account compares its password here. The operator account has no
    password: it proves itself with the instance's operator secret, checked
    against the salted hash in the settings database, so ``settings_path`` is
    required for it. Without one that account is refused rather than guessed
    at — an unverifiable credential is not a credential.
    """
    directory = load_directory(path)
    account = directory.accounts.get((username or "").strip())
    if account is None:
        # Compare even when the account is missing so the branch is less obvious.
        hmac.compare_digest("invalid-password", password or "")
        return None
    if account.credential == OPERATOR_CREDENTIAL:
        if settings_path is None:
            return None
        from src.operator_secret import verify_secret

        matched = verify_secret(settings_path, password or "")
    else:
        matched = hmac.compare_digest(account.password, password or "")
    if not matched:
        return None
    return User(
        username=account.username,
        role=account.role,
        allowed_tables=directory.roles[account.role],
        capabilities=directory.capabilities[account.role],
        email=account.email,
    )


def user_named(username: str, path: Path) -> User | None:
    """Return the user a directory knows by that name, with no password check.

    A recipient of an alert definition is identified, not authenticated: the
    owner names them, and the definition only needs their grants to decide
    whether a notification may reach them. An unknown name returns None, so the
    caller refuses it rather than inventing a person.
    """
    directory = load_directory(path)
    account = directory.accounts.get((username or "").strip())
    if account is None:
        return None
    return User(
        username=account.username,
        role=account.role,
        allowed_tables=directory.roles[account.role],
        capabilities=directory.capabilities[account.role],
        email=account.email,
    )
