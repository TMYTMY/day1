"""Password stand-in for SSO.

Replace `authenticate` with the company identity provider. Callers only need
a User(username, role, allowed_tables). Passwords in config/users.yaml are
demo credentials for the local sample database.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path

import yaml

from src.config import ConfigError
from src.models import User


@dataclass(frozen=True)
class _Account:
    username: str
    password: str
    role: str


@dataclass(frozen=True)
class Directory:
    roles: dict[str, tuple[str, ...]]
    accounts: dict[str, _Account]


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
    for role, spec in roles_raw.items():
        if not isinstance(role, str) or not isinstance(spec, dict):
            raise ConfigError("Each role needs a tables list.")
        tables = spec.get("tables")
        if not isinstance(tables, list) or not tables or not all(isinstance(t, str) for t in tables):
            raise ConfigError(f"Role {role} needs a list of table names.")
        roles[role] = tuple(tables)

    accounts: dict[str, _Account] = {}
    for entry in users_raw:
        if not isinstance(entry, dict):
            raise ConfigError("Each user entry must be a mapping.")
        username = entry.get("username")
        password = entry.get("password")
        role = entry.get("role")
        if not all(isinstance(value, str) and value for value in (username, password, role)):
            raise ConfigError("Each user needs a username, password, and role.")
        if role not in roles:
            raise ConfigError(f"User {username} references unknown role {role}.")
        accounts[username] = _Account(username=username, password=password, role=role)
    return Directory(roles=roles, accounts=accounts)


def authenticate(username: str, password: str, path: Path) -> User | None:
    """Return the user when the demo password matches, otherwise None."""
    directory = load_directory(path)
    account = directory.accounts.get(username.strip())
    # Compare even when the account is missing so the branch is less obvious.
    candidate = account.password if account else "invalid-password"
    if not hmac.compare_digest(candidate, password):
        return None
    if account is None:
        return None
    return User(
        username=account.username,
        role=account.role,
        allowed_tables=directory.roles[account.role],
    )


def demo_accounts(path: Path) -> list[dict[str, str]]:
    directory = load_directory(path)
    rows = []
    for account in directory.accounts.values():
        tables = ", ".join(directory.roles[account.role])
        rows.append(
            {
                "username": account.username,
                "password": account.password,
                "role": account.role,
                "tables": tables,
            }
        )
    return rows
