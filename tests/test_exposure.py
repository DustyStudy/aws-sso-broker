"""Tests for exposure.py: finding AWS credentials other tools left on disk.

Every file here is fake and lives under tmp_path (conftest points the module
away from the real ~/.aws). Values are placeholders built at runtime, so no
secret-shaped literal appears in the repository.
"""

from __future__ import annotations

import json
import time

import pytest
from click.testing import CliRunner

from ssobroker import cli, exposure
from ssobroker.config import OrgConfig

NOW = 1_790_000_000.0  # fixed clock: 2026-09-21
SECRET = "placeholder-" + "s" * 8


def _aws(tmp_path):
    root = tmp_path / "aws-home"
    root.mkdir(exist_ok=True)
    return root


def _write_creds(tmp_path, text: str):
    path = _aws(tmp_path) / "credentials"
    path.write_text(text, encoding="utf-8")
    return path


def _sso_cache(tmp_path, name: str, entry: dict):
    d = _aws(tmp_path) / "sso" / "cache"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps(entry), encoding="utf-8")


def _iso(epoch: float, suffix: str = "Z") -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch)) + suffix


# --- ~/.aws/credentials -------------------------------------------------------


def test_long_lived_key_is_a_warning_and_never_echoes_the_secret(tmp_path):
    _write_creds(
        tmp_path,
        f"[default]\naws_access_key_id = fake-id\naws_secret_access_key = {SECRET}\n"
        f"[ci]\naws_access_key_id = fake-id-2\naws_secret_access_key = {SECRET}\n",
    )
    findings = exposure.check_shared_credentials()
    assert [f.level for f in findings] == ["WARN"]
    assert "ci, default" in findings[0].message
    assert SECRET not in findings[0].message and "fake-id" not in findings[0].message


def test_temporary_credentials_are_only_a_note(tmp_path):
    _write_creds(
        tmp_path,
        "[tmp]\naws_access_key_id = fake-id\naws_secret_access_key = x\naws_session_token = t\n",
    )
    assert [f.level for f in exposure.check_shared_credentials()] == ["NOTE"]


def test_profiles_without_keys_and_missing_file_are_clean(tmp_path):
    assert exposure.check_shared_credentials() == []
    _write_creds(tmp_path, "[sso]\nregion = us-east-1\n[blank]\naws_access_key_id =\n")
    assert exposure.check_shared_credentials() == []


def test_shared_credentials_file_env_override_is_honoured(tmp_path, monkeypatch):
    other = tmp_path / "elsewhere"
    other.write_text("[x]\naws_access_key_id = fake-id\n", encoding="utf-8")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(other))
    findings = exposure.check_shared_credentials()
    assert findings and str(other) in findings[0].message


def test_unparseable_credentials_file_is_a_note_not_a_crash(tmp_path):
    _write_creds(tmp_path, "aws_access_key_id = no-section-header\n")
    assert [f.level for f in exposure.check_shared_credentials()] == ["NOTE"]


def test_oversized_credentials_file_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(exposure, "_MAX_FILE_BYTES", 10)
    _write_creds(tmp_path, "[x]\naws_access_key_id = fake-id\n")
    assert exposure.check_shared_credentials() == []


# --- ~/.aws/sso/cache ---------------------------------------------------------


def test_refreshable_sso_token_is_a_warning_even_after_the_access_token_expires(tmp_path):
    _sso_cache(
        tmp_path,
        "a",
        {"accessToken": "t", "refreshToken": "r", "expiresAt": _iso(NOW - 60)},
    )
    findings = exposure.check_cli_sso_cache(now=NOW)
    assert [f.level for f in findings] == ["WARN"]
    assert "1 can be refreshed" in findings[0].message
    assert "aws sso logout" in findings[0].message


def test_unexpired_sso_token_in_legacy_utc_format_is_a_warning(tmp_path):
    _sso_cache(tmp_path, "a", {"accessToken": "t", "expiresAt": _iso(NOW + 3600, "UTC")})
    findings = exposure.check_cli_sso_cache(now=NOW)
    assert "1 unexpired" in findings[0].message


def test_expired_tokens_registrations_and_junk_are_ignored(tmp_path):
    _sso_cache(tmp_path, "expired", {"accessToken": "t", "expiresAt": _iso(NOW - 1)})
    _sso_cache(tmp_path, "client", {"clientId": "c", "clientSecret": "s", "expiresAt": 0})
    _sso_cache(tmp_path, "list", [1, 2, 3])  # type: ignore[arg-type]
    _sso_cache(tmp_path, "badtime", {"accessToken": "t", "expiresAt": "not a time"})
    (_aws(tmp_path) / "sso" / "cache" / "broken.json").write_text("{", encoding="utf-8")
    assert exposure.check_cli_sso_cache(now=NOW) == []


# --- ~/.aws/cli/cache ---------------------------------------------------------


def test_unexpired_cli_role_credentials_are_a_note(tmp_path):
    d = _aws(tmp_path) / "cli" / "cache"
    d.mkdir(parents=True)
    live = {"Credentials": {"AccessKeyId": "fake-id", "Expiration": _iso(NOW + 900, "+00:00")}}
    dead = {"Credentials": {"AccessKeyId": "fake-id", "Expiration": _iso(NOW - 900)}}
    (d / "live.json").write_text(json.dumps(live), encoding="utf-8")
    (d / "dead.json").write_text(json.dumps(dead), encoding="utf-8")
    (d / "other.json").write_text(json.dumps({"Credentials": "nope"}), encoding="utf-8")
    findings = exposure.check_cli_role_cache(now=NOW)
    assert [f.level for f in findings] == ["NOTE"] and findings[0].message.startswith("1 ")


def test_parse_time_formats():
    assert exposure._parse_time("2026-10-02T00:00:00Z") == exposure._parse_time(
        "2026-10-02T00:00:00UTC"
    )
    assert exposure._parse_time("2026-10-02T00:00:00") == exposure._parse_time(
        "2026-10-02T00:00:00+00:00"
    )
    assert exposure._parse_time(5) == 5.0
    for bad in [None, True, "", "  ", "yesterday", {}]:
        assert exposure._parse_time(bad) is None


def test_scan_orders_warnings_first(tmp_path):
    _write_creds(tmp_path, "[t]\naws_access_key_id = k\naws_session_token = t\n")
    _sso_cache(tmp_path, "a", {"accessToken": "t", "refreshToken": "r", "expiresAt": 0})
    assert [f.level for f in exposure.scan(now=NOW)] == ["WARN", "NOTE"]


# --- doctor -------------------------------------------------------------------


@pytest.fixture
def _doctor_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path / "ssobroker"))
    cfg = OrgConfig(
        name="test",
        sso_start_url="https://example.awsapps.com/start",
        sso_region="us-east-1",
        default_region="us-east-1",
        accounts={},
    )
    monkeypatch.setattr(cli.config, "load", lambda: cfg)


def test_doctor_warns_but_passes_by_default_and_fails_with_strict(tmp_path, _doctor_env):
    _write_creds(tmp_path, "[default]\naws_access_key_id = fake-id\n")
    runner = CliRunner()
    result = runner.invoke(cli.main, ["doctor"])
    assert "WARN" in result.output and "long-lived access key" in result.output
    assert result.exit_code == 0
    strict = runner.invoke(cli.main, ["doctor", "--strict"])
    assert strict.exit_code == 1


def test_doctor_reports_ok_when_nothing_is_left_on_disk(_doctor_env):
    result = CliRunner().invoke(cli.main, ["doctor", "--strict"])
    assert "no AWS CLI credentials or SSO tokens left on disk" in result.output
    assert result.exit_code == 0


def test_doctor_escapes_rich_markup_in_paths(tmp_path, monkeypatch, _doctor_env):
    odd = tmp_path / "[red]creds"
    odd.write_text("[p]\naws_access_key_id = fake-id\n", encoding="utf-8")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(odd))
    result = CliRunner().invoke(cli.main, ["doctor"])
    # rich wraps long lines; compare without whitespace
    assert "[red]creds" in "".join(result.output.split())
