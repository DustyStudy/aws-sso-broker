"""Lightweight, config-driven guardrails.

Not a substitute for IAM permission boundaries or SCPs — this is a local,
last-line speed bump that catches an operator (or an agent driving this CLI)
about to run an obviously destructive command against the wrong account,
before it ever reaches AWS. Real enforcement always belongs in IAM/SCPs;
this just adds friction and an audit trail on the client side.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import policy
from .paths import home_dir


class GuardrailBlocked(RuntimeError):
    def __init__(self, reason: str, rule: str):
        super().__init__(reason)
        self.reason = reason
        self.rule = rule


@dataclass
class GuardrailConfig:
    deny_patterns: list[str] = field(default_factory=list)
    protected_account_ids: list[str] = field(default_factory=list)
    require_confirmation_patterns: list[str] = field(default_factory=list)
    # When true, protected accounts are also refused by `export-env` and
    # `creds-process`, not just `exec`/`shell`. The managed policy can turn
    # this on; a user file can't turn it back off.
    strict_protected_accounts: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> GuardrailConfig:
        """Load the user's guardrails.yaml (if any), then add the managed
        policy's guardrails on top. Policy entries are always added, never
        replaced by the user's file."""
        override = policy.env_override("SSOBROKER_GUARDRAILS")
        path = path or (Path(override) if override else home_dir() / "guardrails.yaml")
        raw = (yaml.safe_load(path.read_text()) or {}) if path.exists() else {}
        pol = policy.load()
        return cls(
            deny_patterns=_merge(raw.get("deny_patterns", []), pol.deny_patterns),
            protected_account_ids=_merge(
                [str(a) for a in raw.get("protected_account_ids", [])],
                pol.protected_account_ids,
            ),
            require_confirmation_patterns=_merge(
                raw.get("require_confirmation_patterns", []),
                pol.require_confirmation_patterns,
            ),
            strict_protected_accounts=bool(raw.get("strict_protected_accounts", False))
            or pol.strict_protected_accounts,
        )


def _merge(user: list[str], managed: tuple[str, ...]) -> list[str]:
    return list(dict.fromkeys([*user, *managed]))


# Sensible built-in defaults on top of whatever the user configures —
# these catch the classic "wrong terminal tab" disasters. Each pattern uses
# "aws*<service> <verb>" rather than "aws <service> <verb>" so a global flag
# between "aws" and the service (e.g. "aws --profile x s3 rb ... --force")
# still matches instead of slipping through the gap.
_BUILTIN_DENY = [
    "aws*iam delete-account-alias*",
    "aws*organizations leave-organization*",
    "aws*organizations close-account*",
    "aws*s3 rm*--recursive*",
    "aws*s3 rb*--force*",
]


def check_protected_account(account_id: str, cfg: GuardrailConfig) -> str | None:
    """Return a block reason if account_id is marked protected, else None.

    Split out from check_command() so callers with no single "command" to
    pattern-match against — spawn_shell(), which opens an interactive
    session rather than running one command — can still enforce the
    protected-account list, which guardrails.yaml documents as covering
    both `exec` and `shell`.
    """
    if account_id in cfg.protected_account_ids:
        return (
            f"Account {account_id} is marked protected in guardrails.yaml — "
            f"remove it there if this command is intentional."
        )
    return None


def check_command(command: list[str], account_id: str, cfg: GuardrailConfig) -> str | None:
    """Return a block reason string if the command should be denied, else None."""
    protected_reason = check_protected_account(account_id, cfg)
    if protected_reason:
        return protected_reason

    joined = " ".join(command)
    for pattern in _BUILTIN_DENY + cfg.deny_patterns:
        if fnmatch.fnmatch(joined, pattern):
            return f"Command matches deny pattern: '{pattern}'"

    return None


def needs_confirmation(command: list[str], cfg: GuardrailConfig) -> str | None:
    joined = " ".join(command)
    for pattern in cfg.require_confirmation_patterns:
        if fnmatch.fnmatch(joined, pattern):
            return pattern
    return None
