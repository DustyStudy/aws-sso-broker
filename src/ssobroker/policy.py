"""Admin-managed policy (optional).

A machine-wide `policy.yaml` that an administrator pushes to endpoints (MDM,
Intune, Jamf, config management). It lives outside the user's home directory,
so a user or a process running as the user can't edit it:

- Linux/macOS: /etc/ssobroker/policy.yaml
- Windows:     %ProgramData%\\ssobroker\\policy.yaml

The policy can only make ssobroker *stricter* than the user's own orgs.yaml
and guardrails.yaml: it adds guardrails, lowers session limits, pins which
Identity Center start URLs may be used, and turns off environment-variable
overrides. It never supplies a start URL or loosens anything, so a policy file
planted by an attacker can at worst lock the user out, not redirect them.

The one setting that sends data somewhere is `audit_forward` with CloudWatch.
On POSIX the file (and its directory) must be owned by root and not writable
by group/other, or it is rejected. On Windows, deploy the folder with an ACL
that only Administrators/SYSTEM can write (see docs/ENTERPRISE.md).

No environment variable can point ssobroker at a different policy file —
that would defeat the point of it.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

# Strictest last: a policy value only ever moves the effective setting right.
ROLE_CACHE_STRICTNESS = ["file", "keyring", "none"]

_KNOWN_KEYS = {
    "allowed_sso_start_urls",
    "max_session_hours",
    "ignore_env_overrides",
    "allow_device_code",
    "strict_protected_accounts",
    "protected_account_ids",
    "deny_patterns",
    "require_confirmation_patterns",
    "role_credential_cache",
    "audit_redact_flags",
    "audit_forward",
    "cloudwatch_log_group",
    "cloudwatch_account",
    "cloudwatch_role",
}


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManagedPolicy:
    path: Path | None = None
    allowed_sso_start_urls: tuple[str, ...] = ()
    max_session_hours: float | None = None
    ignore_env_overrides: bool = False
    allow_device_code: bool = True
    strict_protected_accounts: bool = False
    protected_account_ids: tuple[str, ...] = ()
    deny_patterns: tuple[str, ...] = ()
    require_confirmation_patterns: tuple[str, ...] = ()
    role_credential_cache: str | None = None
    audit_redact_flags: tuple[str, ...] = ()
    audit_forward: tuple[str, ...] = ()
    cloudwatch_log_group: str | None = None
    cloudwatch_account: str | None = None
    cloudwatch_role: str | None = None

    @property
    def active(self) -> bool:
        return self.path is not None


def managed_policy_path() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "ssobroker" / "policy.yaml"
    return Path("/etc/ssobroker/policy.yaml")


def normalize_start_url(url: str) -> str:
    return url.strip().rstrip("/").lower()


def _check_trusted(path: Path) -> None:
    """POSIX only: refuse a policy file a non-root user could have written."""
    if os.name != "posix":
        return
    for p in (path, path.parent):
        st = p.stat()
        if st.st_uid != 0:
            raise PolicyError(f"Refusing managed policy: {p} is not owned by root.")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyError(f"Refusing managed policy: {p} is writable by group or other.")


def _str_tuple(raw: dict, key: str) -> tuple[str, ...]:
    value = raw.get(key) or []
    if not isinstance(value, list):
        raise PolicyError(f"Managed policy field '{key}' must be a list.")
    return tuple(str(v) for v in value)


def parse(raw: dict, path: Path | None) -> ManagedPolicy:
    if not isinstance(raw, dict):
        raise PolicyError("Managed policy must be a YAML mapping.")
    unknown = set(raw) - _KNOWN_KEYS
    if unknown:
        # Fail closed: a typo in a security setting must not be silently ignored.
        raise PolicyError(f"Unknown field(s) in managed policy: {sorted(unknown)}")

    role_cache = raw.get("role_credential_cache")
    if role_cache is not None and role_cache not in ROLE_CACHE_STRICTNESS:
        raise PolicyError(
            f"role_credential_cache must be one of {ROLE_CACHE_STRICTNESS}, got {role_cache!r}"
        )
    max_hours = raw.get("max_session_hours")
    return ManagedPolicy(
        path=path,
        allowed_sso_start_urls=tuple(
            normalize_start_url(u) for u in _str_tuple(raw, "allowed_sso_start_urls")
        ),
        max_session_hours=float(max_hours) if max_hours is not None else None,
        ignore_env_overrides=bool(raw.get("ignore_env_overrides", False)),
        allow_device_code=bool(raw.get("allow_device_code", True)),
        strict_protected_accounts=bool(raw.get("strict_protected_accounts", False)),
        protected_account_ids=_str_tuple(raw, "protected_account_ids"),
        deny_patterns=_str_tuple(raw, "deny_patterns"),
        require_confirmation_patterns=_str_tuple(raw, "require_confirmation_patterns"),
        role_credential_cache=role_cache,
        audit_redact_flags=_str_tuple(raw, "audit_redact_flags"),
        audit_forward=_str_tuple(raw, "audit_forward"),
        cloudwatch_log_group=raw.get("cloudwatch_log_group"),
        cloudwatch_account=(
            str(raw["cloudwatch_account"]) if raw.get("cloudwatch_account") else None
        ),
        cloudwatch_role=raw.get("cloudwatch_role"),
    )


@cache
def load() -> ManagedPolicy:
    """Load the machine-wide policy once per process. No file = no policy."""
    path = managed_policy_path()
    if not path.exists():
        return ManagedPolicy()
    _check_trusted(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise PolicyError(f"Managed policy {path} is not valid YAML: {e}") from e
    return parse(raw, path)


def stricter_role_cache(user_value: str, policy_value: str | None) -> str:
    if policy_value is None:
        return user_value
    return max(user_value, policy_value, key=ROLE_CACHE_STRICTNESS.index)


def env_override(name: str) -> str | None:
    """Read an SSOBROKER_* path override, unless the managed policy forbids them."""
    if load().ignore_env_overrides:
        return None
    return os.environ.get(name) or None
