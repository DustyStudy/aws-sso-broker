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
import contextlib
import fnmatch
import getpass
import json
import logging
import logging.handlers
import os
import re
import socket
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .paths import home_dir

if TYPE_CHECKING:
    from mypy_boto3_logs.type_defs import InputLogEventTypeDef, RejectedLogEventsInfoTypeDef

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
    "cli-input-*",  # --cli-input-json/--cli-input-yaml carry whole request bodies
]
# HTTP headers that carry credentials, e.g. curl -H "Authorization: Bearer ...".
_SECRET_HEADER_RE = re.compile(
    r"((?:proxy-)?authorization|cookie|x-api-key|x-auth-token|x-amz-security-token)(\s*:\s*).+",
    re.IGNORECASE,
)

_SYSLOG_FACILITY = logging.handlers.SysLogHandler.LOG_AUTH

# CloudWatch PutLogEvents takes at most 10,000 events / ~1 MB per call.
_CLOUDWATCH_BATCH = 1000
# PutLogEvents limits: request size (each event counts 26 bytes extra) and
# the time span one request may cover.
_CLOUDWATCH_MAX_BYTES = 1_048_576
_CLOUDWATCH_MAX_SPAN_MS = 24 * 3600 * 1000 - 1
# Set while pushing to CloudWatch, and inherited by any credential_process the
# push starts, so an entry recorded on the way doesn't start another push.
_FORWARDING_ENV = "SSOBROKER_AUDIT_FORWARDING"

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

    Handles `--flag value`, `--flag=value` and `NAME=value`, credential HTTP
    headers (`Authorization: ...`), and inline JSON/YAML documents that mention
    a secret-looking key. The flag name is kept so the log still shows what was
    run. This is pattern matching, not a guarantee: a secret in an argument
    that looks like none of these is logged as typed."""
    patterns = DEFAULT_REDACT_PATTERNS + list(extra_patterns or [])
    out: list[str] = []
    redact_next = False
    for arg in command:
        if redact_next:
            out.append(REDACTED)
            redact_next = False
            continue
        header = _SECRET_HEADER_RE.sub(rf"\1\2{REDACTED}", arg)
        if header != arg:
            out.append(header)
            continue
        flag, sep, value = arg.partition("=") if arg.startswith("-") else ("", "", arg)
        if value.lstrip().startswith(("{", "[")) and _is_secret_name(value, patterns):
            out.append(f"{flag}{sep}{REDACTED}")
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

    `reason` is a free-text note (e.g. why the command was run) the caller
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
                # Already inside a push: the entry is in the local log and the
                # next push sends it.
                if os.environ.get(_FORWARDING_ENV):
                    continue
                if _settings.cloudwatch_log_group and _settings.cloudwatch_region:
                    with _forwarding():
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


@contextlib.contextmanager
def _forwarding() -> Iterator[None]:
    if os.environ.get(_FORWARDING_ENV):
        yield
        return
    os.environ[_FORWARDING_ENV] = "1"
    try:
        yield
    finally:
        os.environ.pop(_FORWARDING_ENV, None)


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
    # source needs admin once; see docs/HARDENING.md.
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
    with _forwarding():
        return _push_pending(log_group, region, credentials)


def _push_pending(log_group: str, region: str, credentials: dict | None) -> int:
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
    too_large = [ev for ev in events if _event_size(ev) > _CLOUDWATCH_MAX_BYTES]
    if too_large:
        # One such event would fail every request it is in, forever.
        _warn(
            f"{len(too_large)} audit entries are too large for CloudWatch; they stay in the local log"
        )
        events = [ev for ev in events if _event_size(ev) <= _CLOUDWATCH_MAX_BYTES]

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

    rejected = 0
    for batch in _batches(events):
        resp = client.put_log_events(
            logGroupName=log_group, logStreamName=stream_name, logEvents=batch
        )
        rejected += _rejected_count(resp.get("rejectedLogEventsInfo") or {}, len(batch))
    if rejected:
        # Too old/expired, or stamped over 2 hours ahead by a skewed clock.
        # The cursor moves past them either way; they stay in the local log.
        _warn(f"CloudWatch rejected {rejected} audit entries; they stay in the local log")
    _cursor_path().write_text(str(len(lines)))
    return len(events) - rejected


def _event_size(ev: InputLogEventTypeDef) -> int:
    return len(ev["message"].encode("utf-8")) + 26


def _batches(events: list[InputLogEventTypeDef]) -> list[list[InputLogEventTypeDef]]:
    """Split time-sorted events into PutLogEvents requests within the count,
    size and 24-hour span limits."""
    batches: list[list[InputLogEventTypeDef]] = []
    batch: list[InputLogEventTypeDef] = []
    size = 0
    for ev in events:
        ev_size = _event_size(ev)
        if batch and (
            len(batch) >= _CLOUDWATCH_BATCH
            or size + ev_size > _CLOUDWATCH_MAX_BYTES
            or ev["timestamp"] - batch[0]["timestamp"] > _CLOUDWATCH_MAX_SPAN_MS
        ):
            batches.append(batch)
            batch, size = [], 0
        batch.append(ev)
        size += ev_size
    if batch:
        batches.append(batch)
    return batches


def _rejected_count(info: RejectedLogEventsInfoTypeDef, batch_len: int) -> int:
    """How many events of one request CloudWatch rejected. Old/expired end
    indexes are exclusive, the too-new start index inclusive."""
    too_old = max(info.get("tooOldLogEventEndIndex", 0), info.get("expiredLogEventEndIndex", 0))
    too_new = info.get("tooNewLogEventStartIndex", batch_len)
    return min(batch_len, too_old + (batch_len - max(too_new, too_old)))


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
