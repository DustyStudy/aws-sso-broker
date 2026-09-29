"""Load and validate the account/org registry (orgs.yaml).

orgs.yaml is intentionally simple — it just maps human-friendly aliases to
AWS account IDs and the roles available on each, plus the Identity Center
start URL/region to log in against. It never contains secrets.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .paths import home_dir


class ConfigError(RuntimeError):
    pass


@dataclass
class Account:
    alias: str
    account_id: str
    roles: list[str] = field(default_factory=list)
    default_role: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class OrgConfig:
    name: str
    sso_start_url: str
    sso_region: str
    default_region: str
    accounts: dict[str, Account]
    max_session_hours: float = 8.0
    cloudwatch_log_group: str | None = None


def default_config_path() -> Path:
    return Path(os.environ.get("SSOBROKER_CONFIG", home_dir() / "orgs.yaml"))


def load(path: Path | None = None) -> OrgConfig:
    path = path or default_config_path()
    if not path.exists():
        raise ConfigError(
            f"No config found at {path}.\n"
            f"Run `ssobroker init` to create one from the example, or copy "
            f"config/orgs.example.yaml there and edit it."
        )
    raw = yaml.safe_load(path.read_text()) or {}

    required = {"name", "sso_start_url", "sso_region", "accounts"}
    missing = required - raw.keys()
    if missing:
        raise ConfigError(f"orgs.yaml is missing required field(s): {sorted(missing)}")

    accounts: dict[str, Account] = {}
    for alias, a in raw["accounts"].items():
        if "account_id" not in a:
            raise ConfigError(f"Account '{alias}' is missing 'account_id'")
        accounts[alias] = Account(
            alias=alias,
            account_id=str(a["account_id"]),
            roles=list(a.get("roles", [])),
            default_role=a.get("default_role"),
            tags=list(a.get("tags", [])),
        )

    return OrgConfig(
        name=raw["name"],
        sso_start_url=raw["sso_start_url"],
        sso_region=raw["sso_region"],
        default_region=raw.get("default_region", raw["sso_region"]),
        accounts=accounts,
        max_session_hours=float(raw.get("max_session_hours", 8.0)),
        cloudwatch_log_group=raw.get("cloudwatch_log_group"),
    )


def resolve_account(cfg: OrgConfig, alias_or_id: str) -> Account:
    if alias_or_id in cfg.accounts:
        return cfg.accounts[alias_or_id]
    for acct in cfg.accounts.values():
        if acct.account_id == alias_or_id:
            return acct
    raise ConfigError(f"Unknown account '{alias_or_id}'. Known aliases: {sorted(cfg.accounts)}")


def accounts_by_tag(cfg: OrgConfig, tag: str | None) -> list[Account]:
    """Return accounts matching `tag`, or all accounts if tag is None."""
    if not tag:
        return list(cfg.accounts.values())
    return [a for a in cfg.accounts.values() if tag in a.tags]


def resolve_role(account: Account, role: str | None) -> str:
    if role:
        if account.roles and role not in account.roles:
            raise ConfigError(
                f"Role '{role}' is not listed for account '{account.alias}' "
                f"(known roles: {account.roles})"
            )
        return role
    if account.default_role:
        return account.default_role
    if len(account.roles) == 1:
        return account.roles[0]
    raise ConfigError(
        f"No role specified and no unambiguous default for '{account.alias}' "
        f"(known roles: {account.roles}). Pass --role explicitly."
    )
