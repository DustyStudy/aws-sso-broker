"""Find AWS credentials left on disk outside ssobroker, where infostealers look.

Infostealer malware (Lumma, RedLine, Vidar) collects the standard AWS CLI files:
`~/.aws/credentials`, `~/.aws/sso/cache/` and `~/.aws/cli/cache/` (see
https://www.wiz.io/blog/infostealer-incursion-cloud-ai-credentials). ssobroker
keeps its own tokens in the OS keychain or a 0600 file, but none of that helps
if the same laptop still has a long-lived access key in `~/.aws/credentials`
or a refresh-capable SSO token from `aws sso login` in `~/.aws/sso/cache/`.
A stolen SSO token can mint role credentials for every account its user can
reach until the Identity Center session ends.

This module only reads metadata: profile names, counts and expiry times. It
never returns or prints a key, token or secret.
"""

from __future__ import annotations

import configparser
import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

# A credentials or cache file bigger than this is not something the AWS CLI wrote.
_MAX_FILE_BYTES = 1_000_000
_MAX_CACHE_FILES = 500


@dataclass(frozen=True)
class Finding:
    level: str  # "WARN" (a live secret is on disk) or "NOTE" (worth knowing, not live)
    message: str


def _aws_dir() -> Path:
    return Path.home() / ".aws"


def _credentials_file() -> Path:
    override = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
    return Path(override).expanduser() if override else _aws_dir() / "credentials"


def _parse_time(value: object) -> float | None:
    """Epoch seconds from the timestamp formats the AWS CLI writes, else None."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    # Older CLI versions wrote "2026-10-02T18:00:00UTC"; newer ones use "Z" or an offset.
    if text.endswith("UTC"):
        text = text[:-3] + "+00:00"
    elif text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _read_small(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _when(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")


def check_shared_credentials(path: Path | None = None) -> list[Finding]:
    path = path or _credentials_file()
    text = _read_small(path)
    if text is None:
        return []
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text, source=str(path))
    except configparser.Error:
        return [Finding("NOTE", f"{path} could not be parsed; check it by hand for access keys")]
    long_lived: list[str] = []
    temporary: list[str] = []
    for section in parser.sections():
        if not parser.get(section, "aws_access_key_id", fallback="").strip():
            continue
        if parser.get(section, "aws_session_token", fallback="").strip():
            temporary.append(section)
        else:
            long_lived.append(section)
    findings = []
    if long_lived:
        findings.append(
            Finding(
                "WARN",
                f"{path} holds a long-lived access key in profile(s) "
                f"{', '.join(sorted(long_lived))}. Infostealers collect this file. "
                "Deactivate the key in IAM and delete it here; ssobroker never needs one.",
            )
        )
    if temporary:
        findings.append(
            Finding(
                "NOTE",
                f"{path} holds temporary credentials in profile(s) "
                f"{', '.join(sorted(temporary))}. Remove them once they are no longer needed.",
            )
        )
    return findings


def _json_files(directory: Path) -> list[Path]:
    try:
        return sorted(directory.glob("*.json"))[:_MAX_CACHE_FILES]
    except OSError:
        return []


def check_cli_sso_cache(directory: Path | None = None, now: float | None = None) -> list[Finding]:
    directory = directory or _aws_dir() / "sso" / "cache"
    now = time.time() if now is None else now
    live = 0
    refreshable = 0
    latest = 0.0
    for path in _json_files(directory):
        text = _read_small(path)
        try:
            entry = json.loads(text) if text else None
        except ValueError:
            continue
        if not isinstance(entry, dict) or not entry.get("accessToken"):
            continue  # client registrations and other files carry no token
        expires = _parse_time(entry.get("expiresAt"))
        has_refresh = bool(entry.get("refreshToken"))
        if has_refresh:
            refreshable += 1
        elif expires is not None and expires > now:
            live += 1
        else:
            continue
        latest = max(latest, expires or 0.0)
    if not live and not refreshable:
        return []
    detail = []
    if refreshable:
        detail.append(f"{refreshable} can be refreshed until the Identity Center session ends")
    if live:
        detail.append(f"{live} unexpired")
    expiry = f"; latest access-token expiry {_when(latest)}" if latest else ""
    return [
        Finding(
            "WARN",
            f"AWS CLI SSO tokens in {directory}: {', '.join(detail)}{expiry}. A stolen token "
            "mints role credentials for every account you can reach. Run `aws sso logout` "
            "when you are done, or sign in through ssobroker only.",
        )
    ]


def check_cli_role_cache(directory: Path | None = None, now: float | None = None) -> list[Finding]:
    directory = directory or _aws_dir() / "cli" / "cache"
    now = time.time() if now is None else now
    live = 0
    for path in _json_files(directory):
        text = _read_small(path)
        try:
            entry = json.loads(text) if text else None
        except ValueError:
            continue
        creds = entry.get("Credentials") if isinstance(entry, dict) else None
        if not isinstance(creds, dict) or not creds.get("AccessKeyId"):
            continue
        expires = _parse_time(creds.get("Expiration"))
        if expires is not None and expires > now:
            live += 1
    if not live:
        return []
    return [
        Finding(
            "NOTE",
            f"{live} unexpired role credential set(s) cached by the AWS CLI in {directory}. "
            "They expire on their own; delete the files to end them early on this machine.",
        )
    ]


def scan(now: float | None = None) -> list[Finding]:
    """All findings for the current user's AWS CLI files, WARN first."""
    findings = [
        *check_shared_credentials(),
        *check_cli_sso_cache(now=now),
        *check_cli_role_cache(now=now),
    ]
    return sorted(findings, key=lambda f: f.level != "WARN")
