from ssobroker import audit


def test_record_and_tail(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    audit.record(
        action="exec", account_id="123456789012", role="admin", command=["aws", "s3", "ls"]
    )
    entries = audit.tail(5)
    assert len(entries) == 1
    assert entries[0]["action"] == "exec"
    assert entries[0]["account_id"] == "123456789012"
    assert entries[0]["command"] == ["aws", "s3", "ls"]
    assert entries[0]["reason"] is None


def test_record_with_reason(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    audit.record(action="shell", account_id="999", role="read-only", reason="rotate-keys")
    entries = audit.tail(5)
    assert entries[0]["reason"] == "rotate-keys"


def test_tail_returns_empty_when_no_log(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    assert audit.tail(10) == []


def test_tail_respects_n(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    for i in range(5):
        audit.record(action="exec", account_id=str(i), role="r")
    entries = audit.tail(2)
    assert len(entries) == 2
    assert entries[-1]["account_id"] == "4"


def test_entry_timestamp_ms_parses_the_entrys_own_ts():
    assert audit._entry_timestamp_ms({"ts": "2020-01-01T00:00:00Z"}, fallback_ms=0) == 1577836800000


def test_entry_timestamp_ms_falls_back_when_ts_missing():
    assert audit._entry_timestamp_ms({}, fallback_ms=123) == 123


def test_entry_timestamp_ms_falls_back_when_ts_unparseable():
    assert audit._entry_timestamp_ms({"ts": "not a timestamp"}, fallback_ms=456) == 456


def test_large_log_is_rotated_and_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    monkeypatch.setattr(audit, "_MAX_LOG_BYTES", 400)
    for _ in range(3):
        audit.record(action="exec", account_id="1", role="r")
    rotated = list(tmp_path.glob("audit.log.*"))
    assert len(rotated) == 1
    assert len(audit.tail(10)) == 1  # the active log started over
    assert rotated[0].read_text().count("\n") == 2


def test_rotation_waits_for_entries_not_yet_in_cloudwatch(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    monkeypatch.setattr(audit, "_MAX_LOG_BYTES", 400)
    monkeypatch.setattr(audit, "_forward", lambda entry: None)  # pushes "fail"
    audit.configure(audit.AuditSettings(forward=["cloudwatch"]))
    for _ in range(3):
        audit.record(action="exec", account_id="1", role="r")
    assert not list(tmp_path.glob("audit.log.*"))

    audit._cursor_path().write_text("3")  # a push sent them all
    audit.record(action="exec", account_id="1", role="r")
    assert len(list(tmp_path.glob("audit.log.*"))) == 1
    assert not audit._cursor_path().exists()  # the new log is counted from zero
