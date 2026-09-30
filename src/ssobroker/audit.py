"""Local audit trail, with optional forwarding.

Every exec/shell/export-env invocation (and every fresh creds-process fetch)
appends one JSON line to ~/.ssobroker/audit.log. Arguments that look like
secrets are redacted before anything is written. Each entry carries the
short-lived AccessKeyId it used, so it can be joined to CloudTrail events.

By default nothing leaves the machine. `audit_forward` in orgs.yaml (or the
managed policy) also sends each entry to syslog, the Windows Event Log,
and/or CloudWatch Logs. Forwarding failures are reported on stderr and never
stop the command.
"""

from __future__ import annotations

import calendar
import fnmatch
import getpass
import json
import logging
import logging.handlers
import os
import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .paths import home_dir

if TYPE_CHECKING:
    from mypy_boto3_logs.type_defs import InputLogEventTypeDef

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REDACTED = "***REDACTED***"

# Matched (fnmatch, case-insensitive) against a flag name with its leading
# dashes removed, and against the name in NAME=value arguments.
DEFAULT_REDACT_PATTERNS = [
    "*secret*",
    "*password*",
    "*passwd*",
    "*token*",
    "*private-key*",
    "*private_key*",
    "*api-key*",
    "*api_key*",
    "*apikey*",
    "*credential*",
]

_SYSLOG_FACILITY = logging.handlers.SysLogHandler.LOG_AUTH

# CloudWatch PutLogEvents takes at most 10,000 events / ~1 MB per call.
_CLOUDWATCH_BATCH = 1000

CredentialsProvider = Callable[[], dict]


@dataclass
class AuditSettings:
    redact_patterns: list[str] = field(default_factory=list)
    forward: list[str] = field(default_factory=list)
    cloudwatch_log_group: str | None = None
    cloudwatch_region: str | None = None
    # Returns credentials for the CloudWatch logging role; None = ambient.
    cloudwatch_credentials: CredentialsProvider | None = None


_settings = AuditSettings()


def configure(settings: AuditSettings) -> None:
    global _settings
    _settings = settings


def log_path() -> Path:
    base = home_dir()
    base.mkdir(parents=True, exist_ok=True)
    return base / "audit.log"


def _cursor_path() -> Path:
    return log_path().with_name("audit.cloudwatch-cursor")


def _is_secret_name(name: str, patterns: list[str]) -> bool:
    name = name.lower()
    return any(fnmatch.fnmatchcase(name, p.lower()) for p in patterns)


def redact_command(command: list[str], extra_patterns: list[str] | None = None) -> list[str]:
    """Replace values of secret-looking flags and NAME=value arguments.

    Handles `--flag value`, `--flag=value` and `NAME=value`. The flag name is
    kept so the log still shows what was run."""
    patterns = DEFAULT_REDACT_PATTERNS + list(extra_patterns or [])
    out: list[str] = []
    redact_next = False
    for arg in command:
        if redact_next:
            out.append(REDACTED)
            redact_next = False
            continue
        if arg.startswith("-"):
            name, sep, _value = arg.partition("=")
            if _is_secret_name(name.lstrip("-"), patterns):
                if sep:
                    out.append(f"{name}={REDACTED}")
                else:
                    out.append(arg)
                    redact_next = True
                continue
        elif "=" in arg:
            name, _, _value = arg.partition("=")
            if name and _is_secret_name(name, patterns):
                out.append(f"{name}={REDACTED}")
                continue
        out.append(arg)
    return out


def record(
    *,
    action: str,
    account_id: str,
    role: str,
    command: list[str] | None = None,
    result: str = "ok",
    detail: str | None = None,
    reason: str | None = None,
    access_key_id: str | None = None,
) -> dict:
    """Append one entry to the local audit log, then forward it if configured.

    `reason` is a free-text justification (e.g. a ticket number) the caller
    can pass with `--reason`. It's NOT an STS session tag: the AWS SSO
    GetRoleCredentials API this tool uses has no session-tagging parameter.

    `access_key_id` is the temporary AccessKeyId issued for this action (not
    a secret on its own); CloudTrail records it on every API call made with
    those credentials, so it's the join key between this log and CloudTrail.
    """
    entry = {
        "ts": time.strftime(_TS_FORMAT, time.gmtime()),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "action": action,
        "account_id": account_id,
        "role": role,
        "command": redact_command(command or [], _settings.redact_patterns),
        "result": result,
        "detail": detail,
        "reason": reason,
        "access_key_id": access_key_id,
    }
    with log_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    _forward(entry)
    return entry


def _warn(msg: str) -> None:
    print(f"ssobroker: audit forwarding: {msg}", file=sys.stderr)


def _forward(entry: dict) -> None:
    for target in _settings.forward:
        try:
            if target == "syslog":
                _send_syslog(entry)
            elif target == "eventlog":
                _send_eventlog(entry)
            elif target == "cloudwatch":
                if _settings.cloudwatch_log_group and _settings.cloudwatch_region:
                    push_to_cloudwatch(
                        _settings.cloudwatch_log_group,
                        _settings.cloudwatch_region,
                        credentials=(
                            _settings.cloudwatch_credentials()
                            if _settings.cloudwatch_credentials
                            else None
                        ),
                    )
        except Exception as e:  # noqa: BLE001 — forwarding must never break the command
            _warn(f"{target} failed: {e}")


def _syslog_address() -> str | tuple[str, int]:
    for candidate in ("/dev/log", "/var/run/syslog"):
        if os.path.exists(candidate):
            return candidate
    return ("localhost", logging.handlers.SYSLOG_UDP_PORT)


def _emit(handler: logging.Handler, entry: dict) -> None:
    logger = logging.getLogger(f"ssobroker.audit.{type(handler).__name__}")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        level = logging.WARNING if entry.get("result") == "blocked" else logging.INFO
        logger.log(level, "ssobroker: %s", json.dumps(entry))
    finally:
        logger.removeHandler(handler)
        handler.close()


def _send_syslog(entry: dict) -> None:
    if sys.platform == "win32":
        raise RuntimeError("syslog isn't available on Windows; use 'eventlog' instead")
    handler = logging.handlers.SysLogHandler(address=_syslog_address(), facility=_SYSLOG_FACILITY)
    _emit(handler, entry)


def _send_eventlog(entry: dict) -> None:
    if sys.platform != "win32":
        raise RuntimeError("the Windows Event Log is only available on Windows")
    # Needs pywin32 (the `windows` extra). Registering the "ssobroker" event
    # source needs admin once; see docs/ENTERPRISE.md.
    _emit(logging.handlers.NTEventLogHandler("ssobroker"), entry)


def _read_cursor(total_lines: int) -> int:
    try:
        cursor = int(_cursor_path().read_text().strip())
    except (OSError, ValueError):
        return 0
    # The log shrank (rotated or truncated): start over rather than skip.
    return cursor if 0 <= cursor <= total_lines else 0


def push_to_cloudwatch(log_group: str, region: str, *, credentials: dict | None = None) -> int:
    """Push audit-log entries not yet sent to CloudWatch Logs.

    A cursor file next to the log (`audit.cloudwatch-cursor`) remembers how
    many lines were already sent, so each entry is pushed once. Delivery is
    at-least-once: two ssobroker processes pushing at the same moment can
    both send the same new lines.

    `credentials` (a dict with AccessKeyId/SecretAccessKey/SessionToken) is
    used when given, e.g. for a dedicated logging role from the registry;
    otherwise boto3's ambient credential chain is used. The log group must
    already exist; this only creates the log stream.
    Returns the number of entries pushed.
    """
    import boto3

    path = log_path()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    start = _read_cursor(len(lines))
    pending = lines[start:]
    if not pending:
        return 0

    now_ms = int(time.time() * 1000)
    events: list[InputLogEventTypeDef] = []
    for line in pending:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        events.append({"timestamp": _entry_timestamp_ms(entry, now_ms), "message": line})
    events.sort(key=lambda ev: ev["timestamp"])

    if credentials:
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )
        client = session.client("logs")
    else:
        client = boto3.client("logs", region_name=region)
    stream_name = f"{socket.gethostname()}-{getpass.getuser()}"

    try:
        client.create_log_stream(logGroupName=log_group, logStreamName=stream_name)
    except client.exceptions.ResourceAlreadyExistsException:
        pass

    for i in range(0, len(events), _CLOUDWATCH_BATCH):
        client.put_log_events(
            logGroupName=log_group,
            logStreamName=stream_name,
            logEvents=events[i : i + _CLOUDWATCH_BATCH],
        )
    _cursor_path().write_text(str(len(lines)))
    return len(events)


def _entry_timestamp_ms(entry: dict, fallback_ms: int) -> int:
    """The entry's own recorded time, as epoch milliseconds — not the time
    it happens to be pushed. Falls back to `fallback_ms` (the push time) for
    an entry with no/unparseable `ts`, e.g. hand-edited log lines."""
    ts = entry.get("ts")
    if not ts:
        return fallback_ms
    try:
        return calendar.timegm(time.strptime(ts, _TS_FORMAT)) * 1000
    except ValueError:
        return fallback_ms


def tail(n: int = 20) -> list[dict]:
    p = log_path()
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").splitlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
