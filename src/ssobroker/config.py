"""Load and validate the account/org registry (orgs.yaml).

orgs.yaml is intentionally simple — it just maps human-friendly aliases to
AWS account IDs and the roles available on each, plus the Identity Center
start URL/region to log in against. It never contains secrets.

If an admin-managed policy is present (see policy.py), it is applied here:
it can pin the allowed start URLs and tighten session and cache settings,
never loosen them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from . import policy
from .paths import home_dir

LOGIN_FLOWS = ("auth_code", "device_code")
AUDIT_FORWARDERS = ("syslog", "eventlog", "cloudwatch")


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
    # Account alias/ID and role in this registry whose credentials are used
    # to write audit entries to CloudWatch. Unset = ambient credentials.
    cloudwatch_account: str | None = None
    cloudwatch_role: str | None = None
    login_flow: str = "auth_code"
    allow_device_code: bool = True
    role_credential_cache: str = "file"
    audit_redact_flags: list[str] = field(default_factory=list)
    audit_forward: list[str] = field(default_factory=list)
    ca_bundle: str | None = None
    https_proxy: str | None = None
    use_fips_endpoint: bool = False


def default_config_path() -> Path:
    override = policy.env_override("SSOBROKER_CONFIG")
    return Path(override) if override else home_dir() / "orgs.yaml"


def _validate_start_url(url: str, pol: policy.ManagedPolicy) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ConfigError(f"sso_start_url must be an https:// URL, got {url!r}")
    if pol.allowed_sso_start_urls and (
        policy.normalize_start_url(url) not in pol.allowed_sso_start_urls
    ):
        raise ConfigError(
            f"sso_start_url {url!r} is not allowed by the managed policy at {pol.path}. "
            f"Allowed: {list(pol.allowed_sso_start_urls)}"
        )


def _choice(raw: dict, key: str, default: str, allowed: tuple[str, ...] | list[str]) -> str:
    value = raw.get(key, default)
    if value not in allowed:
        raise ConfigError(f"'{key}' must be one of {list(allowed)}, got {value!r}")
    return value


def _merged_list(user: list[str], managed: tuple[str, ...]) -> list[str]:
    return list(dict.fromkeys([*user, *managed]))


def load(path: Path | None = None) -> OrgConfig:
    try:
        pol = policy.load()
    except policy.PolicyError as e:
        raise ConfigError(str(e)) from e

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

    _validate_start_url(raw["sso_start_url"], pol)

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

    max_hours = float(raw.get("max_session_hours", 8.0))
    if pol.max_session_hours is not None:
        max_hours = min(max_hours, pol.max_session_hours)

    login_flow = _choice(raw, "login_flow", "auth_code", LOGIN_FLOWS)
    if login_flow == "device_code" and not pol.allow_device_code:
        raise ConfigError(
            f"login_flow 'device_code' is disabled by the managed policy at {pol.path}."
        )

    role_cache = policy.stricter_role_cache(
        _choice(raw, "role_credential_cache", "file", policy.ROLE_CACHE_STRICTNESS),
        pol.role_credential_cache,
    )

    audit_forward = _merged_list(list(raw.get("audit_forward", [])), pol.audit_forward)
    bad = [f for f in audit_forward if f not in AUDIT_FORWARDERS]
    if bad:
        raise ConfigError(f"Unknown audit_forward target(s) {bad}; use {list(AUDIT_FORWARDERS)}")

    cfg = OrgConfig(
        name=raw["name"],
        sso_start_url=raw["sso_start_url"],
        sso_region=raw["sso_region"],
        default_region=raw.get("default_region", raw["sso_region"]),
        accounts=accounts,
        max_session_hours=max_hours,
        cloudwatch_log_group=pol.cloudwatch_log_group or raw.get("cloudwatch_log_group"),
        cloudwatch_account=pol.cloudwatch_account or _opt_str(raw.get("cloudwatch_account")),
        cloudwatch_role=pol.cloudwatch_role or raw.get("cloudwatch_role"),
        login_flow=login_flow,
        allow_device_code=pol.allow_device_code,
        role_credential_cache=role_cache,
        audit_redact_flags=_merged_list(
            list(raw.get("audit_redact_flags", [])), pol.audit_redact_flags
        ),
        audit_forward=audit_forward,
        ca_bundle=raw.get("ca_bundle"),
        https_proxy=raw.get("https_proxy"),
        use_fips_endpoint=bool(raw.get("use_fips_endpoint", False)),
    )

    if "cloudwatch" in cfg.audit_forward and not cfg.cloudwatch_log_group:
        raise ConfigError("audit_forward includes 'cloudwatch' but cloudwatch_log_group is unset")
    if bool(cfg.cloudwatch_account) != bool(cfg.cloudwatch_role):
        raise ConfigError("Set both cloudwatch_account and cloudwatch_role, or neither")
    if cfg.cloudwatch_account:
        logging_account_id(cfg)  # fail at load time, not on the first audit write
    return cfg


def logging_account_id(cfg: OrgConfig) -> str:
    """Account ID for the CloudWatch logging role: a registry alias/ID, or a
    bare 12-digit account ID (so a managed policy can name an account that
    isn't in every user's registry)."""
    value = cfg.cloudwatch_account or ""
    if value.isdigit() and len(value) == 12:
        return value
    return resolve_account(cfg, value).account_id


def _opt_str(value: object) -> str | None:
    return str(value) if value else None


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
