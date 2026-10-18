"""Tests for audit.push_to_cloudwatch() using moto's mocked CloudWatch Logs.

Note: push_to_cloudwatch does not create the log group itself (only the log
stream) — per the README, `cloudwatch_log_group` is expected to already exist
(e.g. provisioned via CloudFormation/Terraform ahead of time) and the
credentials used only need logs:PutLogEvents / logs:CreateLogStream, not
logs:CreateLogGroup. These tests reflect that expectation.
"""

from __future__ import annotations

import calendar
import json
import os
import time

import boto3
import pytest
from moto import mock_aws

from ssobroker import audit

REGION = "us-east-1"
LOG_GROUP = "/ssobroker/audit"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def logs_client():
    with mock_aws():
        client = boto3.client("logs", region_name=REGION)
        client.create_log_group(logGroupName=LOG_GROUP)
        yield client


def _get_events(client) -> list[dict]:
    streams = client.describe_log_streams(logGroupName=LOG_GROUP)["logStreams"]
    if not streams:
        return []
    events = []
    for stream in streams:
        resp = client.get_log_events(
            logGroupName=LOG_GROUP, logStreamName=stream["logStreamName"], startFromHead=True
        )
        events.extend(resp["events"])
    return events


def test_push_with_no_local_entries_pushes_nothing(logs_client):
    n = audit.push_to_cloudwatch(LOG_GROUP, REGION)
    assert n == 0
    assert _get_events(logs_client) == []


def test_push_sends_all_recorded_entries(logs_client):
    audit.record(
        action="exec", account_id="111111111111", role="admin", command=["aws", "s3", "ls"]
    )
    audit.record(action="shell", account_id="222222222222", role="read-only", reason="JIRA-42")

    n = audit.push_to_cloudwatch(LOG_GROUP, REGION)
    assert n == 2

    events = _get_events(logs_client)
    assert len(events) == 2
    messages = [json.loads(e["message"]) for e in events]
    actions = {m["action"] for m in messages}
    assert actions == {"exec", "shell"}


def test_push_sends_only_entries_not_yet_pushed(logs_client):
    """A cursor file remembers how many lines were already sent, so a second
    push sends only what was recorded since (exactly-once for one process)."""
    audit.record(action="exec", account_id="111", role="admin")
    assert audit.push_to_cloudwatch(LOG_GROUP, REGION) == 1

    audit.record(action="exec", account_id="222", role="admin")
    assert audit.push_to_cloudwatch(LOG_GROUP, REGION) == 1
    assert audit.push_to_cloudwatch(LOG_GROUP, REGION) == 0

    streams = logs_client.describe_log_streams(logGroupName=LOG_GROUP)["logStreams"]
    assert len(streams) == 1  # one stream reused, not recreated

    account_ids = [json.loads(e["message"])["account_id"] for e in _get_events(logs_client)]
    assert sorted(account_ids) == ["111", "222"]


def test_push_starts_over_if_log_was_truncated(logs_client):
    for i in range(3):
        audit.record(action="exec", account_id=str(i), role="r")
    assert audit.push_to_cloudwatch(LOG_GROUP, REGION) == 3

    # Log rotated: fewer lines than the cursor says were sent.
    audit.log_path().write_text("")
    audit.record(action="exec", account_id="new", role="r")
    assert audit.push_to_cloudwatch(LOG_GROUP, REGION) == 1


def test_push_uses_explicit_credentials_when_given(logs_client, monkeypatch):
    seen = {}
    real_session = boto3.Session

    def _session(**kwargs):
        seen.update(kwargs)
        return real_session(region_name=kwargs["region_name"])

    monkeypatch.setattr(boto3, "Session", _session)
    audit.record(action="exec", account_id="111", role="admin")
    creds = {"AccessKeyId": "AKIALOG", "SecretAccessKey": "s", "SessionToken": "t"}
    assert audit.push_to_cloudwatch(LOG_GROUP, REGION, credentials=creds) == 1
    assert seen["aws_access_key_id"] == "AKIALOG"


def test_record_forwards_to_cloudwatch_when_configured(logs_client):
    audit.configure(
        audit.AuditSettings(
            forward=["cloudwatch"], cloudwatch_log_group=LOG_GROUP, cloudwatch_region=REGION
        )
    )
    audit.record(action="exec", account_id="111", role="admin")
    assert len(_get_events(logs_client)) == 1


def test_forwarding_failure_warns_but_still_writes_local_log(capsys):
    with mock_aws():
        audit.configure(
            audit.AuditSettings(
                forward=["cloudwatch"],
                cloudwatch_log_group="/does/not/exist",
                cloudwatch_region=REGION,
            )
        )
        audit.record(action="exec", account_id="111", role="admin")
    assert audit.tail(1)[0]["account_id"] == "111"
    assert "cloudwatch failed" in capsys.readouterr().err


def test_push_uses_each_entrys_own_timestamp_not_push_time(logs_client):
    # Regression: every event was stamped with time.time() at push time, so
    # CloudWatch showed all events bunched at push time instead of when they
    # actually happened, defeating the point of an audit trail.
    #
    # An hour ago, not further back: CloudWatch rejects/drops PutLogEvents
    # older than 14 days, so this stays well within that window while still
    # being clearly distinct from "now" (push time).
    an_hour_ago = time.gmtime(time.time() - 3600)
    old_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", an_hour_ago)
    expected_ms = int(calendar.timegm(an_hour_ago)) * 1000
    entry = {
        "ts": old_ts,
        "user": "u",
        "host": "h",
        "action": "exec",
        "account_id": "111111111111",
        "role": "r",
        "command": [],
        "result": "ok",
        "detail": None,
        "reason": None,
    }
    with audit.log_path().open("a") as f:
        f.write(json.dumps(entry) + "\n")

    n = audit.push_to_cloudwatch(LOG_GROUP, REGION)
    assert n == 1

    events = _get_events(logs_client)
    assert len(events) == 1
    assert events[0]["timestamp"] == expected_ms


def test_push_falls_back_to_push_time_for_entry_with_no_ts(logs_client):
    entry = {"user": "u", "host": "h", "action": "exec", "account_id": "111111111111", "role": "r"}
    with audit.log_path().open("a") as f:
        f.write(json.dumps(entry) + "\n")

    before_ms = int(time.time() * 1000)
    n = audit.push_to_cloudwatch(LOG_GROUP, REGION)
    after_ms = int(time.time() * 1000)
    assert n == 1

    events = _get_events(logs_client)
    assert before_ms <= events[0]["timestamp"] <= after_ms


def test_push_fails_loudly_if_log_group_does_not_exist():
    # No log group created here — push_to_cloudwatch does not create one
    # itself, so this should surface AWS's real error rather than silently
    # doing nothing.
    with mock_aws():
        audit.record(action="exec", account_id="111", role="admin")
        with pytest.raises(Exception, match="ResourceNotFoundException|does not exist"):
            audit.push_to_cloudwatch("/does/not/exist", REGION)


def test_forwarding_does_not_recurse_through_a_credential_process(monkeypatch):
    # An ambient AWS profile backed by `ssobroker creds-process` records a new
    # entry while push_to_cloudwatch is getting credentials. That entry must
    # not start another push, in this process or in the child it spawns.
    calls = []

    def _push(*a, **k):
        calls.append(os.environ.get("SSOBROKER_AUDIT_FORWARDING"))
        audit.record(action="creds-process", account_id="111", role="admin")

    monkeypatch.setattr(audit, "push_to_cloudwatch", _push)
    audit.configure(
        audit.AuditSettings(
            forward=["cloudwatch"], cloudwatch_log_group=LOG_GROUP, cloudwatch_region=REGION
        )
    )
    audit.record(action="exec", account_id="111", role="admin")
    assert calls == ["1"]
    assert "SSOBROKER_AUDIT_FORWARDING" not in os.environ
    assert len(audit.tail(5)) == 2  # the nested entry is still logged locally


class _FakeLogs:
    class exceptions:  # noqa: N801 — mirrors botocore's client.exceptions
        class ResourceAlreadyExistsException(Exception):
            pass

    def __init__(self, response=None):
        self.batches: list[list[dict]] = []
        self.response = response or {}

    def create_log_stream(self, **kwargs):
        pass

    def put_log_events(self, **kwargs):
        self.batches.append(kwargs["logEvents"])
        return self.response


def _write_log(entries: list[dict]) -> None:
    audit.log_path().write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")


def _ts(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def test_backfill_batches_never_span_more_than_24_hours(monkeypatch):
    fake = _FakeLogs()
    monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)
    start = time.time() - 3 * 86400
    _write_log([{"ts": _ts(start + h * 3600), "action": "exec"} for h in range(72)])

    assert audit.push_to_cloudwatch(LOG_GROUP, REGION) == 72
    assert len(fake.batches) >= 3
    for batch in fake.batches:
        assert batch[-1]["timestamp"] - batch[0]["timestamp"] < 24 * 3600 * 1000


def test_backfill_batches_stay_under_the_request_size_limit(monkeypatch):
    fake = _FakeLogs()
    monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)
    now = _ts(time.time())
    _write_log([{"ts": now, "detail": "x" * 200_000} for _ in range(8)])

    assert audit.push_to_cloudwatch(LOG_GROUP, REGION) == 8
    assert len(fake.batches) >= 2
    for batch in fake.batches:
        assert sum(len(e["message"].encode()) + 26 for e in batch) <= 1_048_576


def test_events_rejected_by_cloudwatch_are_reported(monkeypatch, capsys):
    fake = _FakeLogs({"rejectedLogEventsInfo": {"expiredLogEventEndIndex": 1}})
    monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)
    _write_log([{"ts": _ts(time.time()), "action": "exec"} for _ in range(3)])

    audit.push_to_cloudwatch(LOG_GROUP, REGION)
    assert "2 audit entries were rejected" in capsys.readouterr().err


def test_direct_push_also_marks_forwarding_for_credential_processes(monkeypatch):
    # `audit-log --push-cloudwatch` calls push_to_cloudwatch directly; a
    # credential_process it starts must still see the marker.
    seen = []
    fake = _FakeLogs()
    fake.create_log_stream = lambda **k: seen.append(os.environ.get("SSOBROKER_AUDIT_FORWARDING"))
    monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)
    _write_log([{"ts": _ts(time.time()), "action": "exec"}])
    audit.push_to_cloudwatch(LOG_GROUP, REGION)
    assert seen == ["1"]
    assert "SSOBROKER_AUDIT_FORWARDING" not in os.environ
