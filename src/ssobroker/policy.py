"""Machine-wide policy (optional).

A `policy.yaml` installed as root/Administrator. It lives outside the user's home directory,
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
by group/other, or it is rejected. On Windows the file and folder must be owned
by, and only writable by, Administrators/SYSTEM (see docs/HARDENING.md), or it
is rejected.

No environment variable can point ssobroker at a different policy file —
that would defeat the point of it.
"""

from __future__ import annotations

import os
import re
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
        return Path(_program_data()) / "ssobroker" / "policy.yaml"
    return Path("/etc/ssobroker/policy.yaml")


if sys.platform == "win32":

    def _program_data() -> str:
        """The real ProgramData folder from the shell. %ProgramData% is set per
        process, so a user could point it at an empty folder and drop the policy."""
        import ctypes
        import uuid

        folder_id = ctypes.create_string_buffer(
            uuid.UUID("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97").bytes_le  # FOLDERID_ProgramData
        )
        out = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(folder_id, 0, None, ctypes.byref(out)):
            raise PolicyError("Could not locate the ProgramData folder for the managed policy.")
        try:
            return str(out.value)
        finally:
            ctypes.windll.ole32.CoTaskMemFree(out)


def normalize_start_url(url: str) -> str:
    # One pass over trailing slashes and spaces together, so "x /" and "x" agree.
    return re.sub(r"[\s/]+$", "", url.strip()).lower()


# Principals allowed to own or write the Windows policy: SYSTEM, Administrators, TrustedInstaller.
_WIN_TRUSTED_SIDS = {
    "SY",
    "BA",
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
}
# SDDL rights that let a principal change, replace or delete the policy file or folder.
_SDDL_RIGHT_BITS = {
    "GA": 0x10000000,
    "GW": 0x40000000,
    "FA": 0x1F01FF,
    "FW": 0x120116,
    "SD": 0x10000,
    "WD": 0x40000,
    "WO": 0x80000,
    "DC": 0x2,
    "LC": 0x4,
    "DT": 0x40,
}
# write/add file, append/add subfolder, delete child, DELETE, WRITE_DAC, WRITE_OWNER, generic.
_WIN_WRITE_MASK = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000


def _sddl_rights(rights: str) -> int:
    if rights.lower().startswith("0x"):
        return int(rights, 16)
    return sum(_SDDL_RIGHT_BITS.get(rights[i : i + 2], 0) for i in range(0, len(rights), 2))


def untrusted_writers(sddl: str) -> list[str]:
    """Principals other than SYSTEM/Administrators/TrustedInstaller that own,
    or are allowed to write, the object `sddl` (with O: and D: parts) describes."""
    found = []
    owner = re.match(r"O:(S-[\d-]+|[A-Z]{2})", sddl)
    if not owner or owner.group(1) not in _WIN_TRUSTED_SIDS:
        found.append(f"owner {owner.group(1) if owner else '?'}")
    if "D:" not in sddl or "NO_ACCESS_CONTROL" in sddl:
        found.append("everyone (no access control list)")  # a null DACL allows all access
    for ace in re.findall(r"\(([^)]*)\)", sddl):
        kind, flags, rights, *_rest, sid = ace.split(";")
        # Deny ACEs grant nothing and inherit-only ACEs don't apply here. Any
        # other kind is counted, so an ACE this can't parse fails closed.
        if kind in ("D", "OD", "XD") or "IO" in flags or sid in _WIN_TRUSTED_SIDS:
            continue
        if _sddl_rights(rights) & _WIN_WRITE_MASK:
            found.append(sid)
    return found


def _check_trusted(path: Path) -> None:
    """Refuse a policy file a non-admin user could have written."""
    if sys.platform == "win32":
        from .cache import _dacl_sddl

        for p in (path, path.parent):
            if bad := untrusted_writers(_dacl_sddl(p, owner=True)):
                raise PolicyError(
                    f"Refusing managed policy: {p} can be changed by {', '.join(bad)}. "
                    "See docs/HARDENING.md for the ACL to set."
                )
        return
    if os.name != "posix":
        return
    for p in (path, path.parent):
        st = p.stat()
        if st.st_uid != 0:
            raise PolicyError(f"Refusing managed policy: {p} is not owned by root.")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyError(f"Refusing managed policy: {p} is writable by group or other.")


def account_id(value: object) -> str:
    """An AWS account ID as 12-digit text, or ValueError. Unquoted YAML turns
    012345670123 into an octal int, which would silently stop matching."""
    text = str(value)
    if isinstance(value, bool) or not (len(text) == 12 and text.isascii() and text.isdigit()):
        raise ValueError(f"account ID {value!r} is not 12 digits; quote it in YAML")
    return text


def _bool(raw: dict, key: str, default: bool) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        # Fail closed: bool("false") is True.
        raise PolicyError(f"Managed policy field '{key}' must be true or false, got {value!r}")
    return value


def _str_tuple(raw: dict, key: str) -> tuple[str, ...]:
    value = raw.get(key)
    if value is None:
        value = []
    if not isinstance(value, list):
        raise PolicyError(f"Managed policy field '{key}' must be a list.")
    return tuple(str(v) for v in value)


def _account_ids(raw: dict, key: str) -> tuple[str, ...]:
    value = raw.get(key)
    if value is None:
        value = []
    if not isinstance(value, list):
        raise PolicyError(f"Managed policy field '{key}' must be a list.")
    try:
        return tuple(account_id(v) for v in value)
    except ValueError as e:
        raise PolicyError(f"Managed policy field '{key}': {e}") from e


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
        ignore_env_overrides=_bool(raw, "ignore_env_overrides", False),
        allow_device_code=_bool(raw, "allow_device_code", True),
        strict_protected_accounts=_bool(raw, "strict_protected_accounts", False),
        protected_account_ids=_account_ids(raw, "protected_account_ids"),
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
