"""Write `credential_process` profile blocks into ~/.aws/config for every
account (and optionally every role) in the local orgs.yaml registry.

The file is edited as text, not parsed and re-serialized: anything this tool
didn't write — other profiles, comments, blank lines, key casing, line
endings — is preserved byte-for-byte. Every section this tool writes carries
a per-section marker key (`_ssobroker_managed`). On a re-run, a section is only
ever overwritten if that marker is already present; if a profile name
collides with a section that exists but wasn't created by this tool, it's
left alone and reported back as a conflict instead of being silently mutated.
"""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path
from typing import NamedTuple

from .config import Account, ConfigError, OrgConfig

# Written into every section this tool creates so a later run can tell
# "I made this, safe to overwrite" apart from "this collides with a
# profile the user already had".
_MANAGED_KEY = "_ssobroker_managed"
# Marker written before the tool was renamed from orgctl. Sections carrying
# it are still treated as ours, and get rewritten with the new marker.
_LEGACY_MANAGED_KEY = "_orgctl_managed"

# AWS config headers start in column 0; an indented "[x]" is a continuation line.
_SECTION_RE = re.compile(r"^\[([^\]]+)\]")
_MANAGED_RE = re.compile(rf"^(?:{_MANAGED_KEY}|{_LEGACY_MANAGED_KEY})\s*=")
_BLANK_OR_COMMENT_RE = re.compile(r"^\s*($|[#;])")


class SyncResult(NamedTuple):
    written: list[str]
    skipped: list[str]
    conflicts: list[str]
    path: Path
    backup: Path | None


def aws_config_path() -> Path:
    return Path.home() / ".aws" / "config"


def _profile_name(prefix: str, account: Account, role: str, *, all_roles: bool) -> str:
    base = f"{prefix}-{account.alias}" if prefix else account.alias
    return f"{base}-{role}" if all_roles else base


def _managed_profiles_for(
    cfg: OrgConfig, prefix: str, all_roles: bool
) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Build the set of profile-name -> settings this tool would write.

    Returns (profiles, skipped_aliases) — an account is skipped only in
    single-role mode when it has multiple roles and no configured
    `default_role`, since there'd be no unambiguous choice.

    Raises ConfigError if two different account/role pairs map to the same
    profile name, rather than silently keeping only the last one.
    """
    profiles: dict[str, dict[str, str]] = {}
    owners: dict[str, str] = {}
    skipped: list[str] = []
    for account in cfg.accounts.values():
        if all_roles and account.roles:
            roles: list[str] = account.roles
        else:
            single = account.default_role or (account.roles[0] if len(account.roles) == 1 else None)
            if not single:
                skipped.append(account.alias)
                continue
            roles = [single]

        for role in roles:
            name = _profile_name(prefix, account, role, all_roles=all_roles)
            owner = f"{account.alias}/{role}"
            if name in owners:
                raise ConfigError(
                    f"Profile name '{name}' would be written for both {owners[name]} and "
                    f"{owner}. Use --prefix and/or --all-roles to make profile names unique."
                )
            owners[name] = owner
            profiles[name] = {
                "credential_process": (
                    f"ssobroker creds-process --account {account.alias} --role {role}"
                ),
                "region": cfg.default_region,
            }
    return profiles, skipped


class _Section:
    def __init__(self, name: str, lines: list[str]):
        self.name = name
        self.lines = lines

    @property
    def managed(self) -> bool:
        return any(_MANAGED_RE.match(line) for line in self.lines)


def _parse(text: str) -> tuple[list[str], list[_Section]]:
    """Split text into (preamble lines, sections), keeping every line verbatim."""
    preamble: list[str] = []
    sections: list[_Section] = []
    for line in text.splitlines(keepends=True):
        m = _SECTION_RE.match(line)
        if m:
            sections.append(_Section(" ".join(m.group(1).split()), [line]))
        elif sections:
            sections[-1].lines.append(line)
        else:
            preamble.append(line)
    return preamble, sections


def _render(section_name: str, settings: dict[str, str], eol: str) -> list[str]:
    lines = [f"[{section_name}]"]
    lines += [f"{key} = {value}" for key, value in settings.items()]
    lines.append(f"{_MANAGED_KEY} = true")
    return [line + eol for line in lines]


def _trailing_gap(lines: list[str]) -> list[str]:
    """Trailing blank/comment lines of a section — they read as belonging to
    whatever follows it, so a rewrite must keep them."""
    i = len(lines)
    while i > 1 and _BLANK_OR_COMMENT_RE.match(lines[i - 1]):
        i -= 1
    return lines[i:]


def _backup(path: Path) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    candidate = path.with_name(f"{path.name}.bak-{stamp}")
    n = 1
    while candidate.exists():
        n += 1
        candidate = path.with_name(f"{path.name}.bak-{stamp}-{n}")
    shutil.copy2(path, candidate)
    return candidate


def sync(
    cfg: OrgConfig,
    *,
    prefix: str = "",
    all_roles: bool = False,
    dry_run: bool = False,
) -> SyncResult:
    """Write/update profiles in ~/.aws/config for every account/role.

    Returns a SyncResult: profile names written, skipped account aliases,
    conflicting profile names, the config path, and the path of the backup
    made (None if nothing was backed up).

    A profile name is a "conflict" (and left completely untouched) when a
    section of that name already exists in ~/.aws/config but doesn't carry
    this tool's managed-section marker — i.e. it predates ssobroker or was
    hand-edited, not something ssobroker itself wrote on an earlier run.

    Nothing is written — and no backup is made — when the file would come out
    identical. When an existing file is changed, it is first copied to a new
    timestamped `config.bak-<stamp>` file; earlier backups are never overwritten.
    """
    path = aws_config_path()
    desired, skipped = _managed_profiles_for(cfg, prefix, all_roles)

    original = ""
    if path.exists():
        with path.open(encoding="utf-8", newline="") as f:
            original = f.read()
    eol = "\r\n" if "\r\n" in original else "\n"
    preamble, sections = _parse(original)

    written: list[str] = []
    conflicts: list[str] = []
    new_blocks: list[list[str]] = []
    for name, settings in desired.items():
        section_name = f"profile {name}"
        existing = [s for s in sections if s.name == section_name]
        if any(not s.managed for s in existing):
            # Pre-existing, not ours — never touch it.
            conflicts.append(name)
            continue
        block = _render(section_name, settings, eol)
        if existing:
            target = existing[0]
            target.lines = block + _trailing_gap(target.lines)
        else:
            new_blocks.append(block)
        written.append(name)

    out = list(preamble)
    for section in sections:
        out.extend(section.lines)
    for block in new_blocks:
        if out and not out[-1].endswith(("\n", "\r")):
            out[-1] += eol
        if out and out[-1].strip():
            out.append(eol)
        out.extend(block)
    updated = "".join(out)

    backup: Path | None = None
    if not dry_run and updated != original:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = _backup(path)
        with path.open("w", encoding="utf-8", newline="") as f:
            f.write(updated)

    return SyncResult(written, skipped, conflicts, path, backup)
