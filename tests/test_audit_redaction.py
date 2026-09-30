"""Secret-looking arguments must never reach the audit log (or anything it
is forwarded to), and every entry must carry its AccessKeyId."""

from __future__ import annotations

import sys

import pytest

from ssobroker import audit

R = audit.REDACTED


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            ["aws", "secretsmanager", "put-secret-value", "--secret-string", "hunter2"],
            ["aws", "secretsmanager", "put-secret-value", "--secret-string", R],
        ),
        (["mysql", "--password=hunter2"], ["mysql", f"--password={R}"]),
        (["env", "DB_PASSWORD=hunter2", "app"], ["env", f"DB_PASSWORD={R}", "app"]),
        (["tool", "--API-Key", "abc"], ["tool", "--API-Key", R]),
        (["aws", "s3", "cp", "a", "s3://b/key"], ["aws", "s3", "cp", "a", "s3://b/key"]),
        (
            ["aws", "s3api", "get-object", "--key", "x"],
            ["aws", "s3api", "get-object", "--key", "x"],
        ),
        (["tool", "--token"], ["tool", "--token"]),
    ],
)
def test_redact_command(command, expected):
    assert audit.redact_command(command) == expected


def test_extra_patterns_from_config():
    assert audit.redact_command(["app", "--pin", "1234"], ["pin"]) == ["app", "--pin", R]


def test_record_redacts_and_keeps_access_key_id():
    audit.record(
        action="exec",
        account_id="111",
        role="admin",
        command=["mysql", "--password", "hunter2"],
        access_key_id="ASIAEXAMPLE",
    )
    raw = audit.log_path().read_text()
    assert "hunter2" not in raw
    entry = audit.tail(1)[0]
    assert entry["access_key_id"] == "ASIAEXAMPLE"


@pytest.mark.skipif(sys.platform == "win32", reason="syslog is POSIX only")
def test_syslog_forwarding_emits_entry(monkeypatch):
    sent = []

    class _Handler(audit.logging.Handler):
        def emit(self, record):
            sent.append(record.getMessage())

    monkeypatch.setattr(audit.logging.handlers, "SysLogHandler", lambda **k: _Handler())
    audit.configure(audit.AuditSettings(forward=["syslog"]))
    audit.record(action="exec", account_id="111", role="admin", result="blocked")
    assert len(sent) == 1 and '"account_id": "111"' in sent[0]


def test_forwarding_to_unsupported_target_warns_without_failing(capsys):
    target = "syslog" if sys.platform == "win32" else "eventlog"
    audit.configure(audit.AuditSettings(forward=[target]))
    audit.record(action="exec", account_id="111", role="admin")
    assert audit.tail(1)[0]["account_id"] == "111"
    assert f"{target} failed" in capsys.readouterr().err
