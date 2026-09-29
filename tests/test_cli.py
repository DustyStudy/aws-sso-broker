"""Tests for cli.py's error handling: an unknown account/role or a rejected/
expired SSO token must produce a clean one-line message and exit(1), not a
raw traceback. AWS itself (SSO, STS, IAM) is always faked — these tests are
about what the CLI does with the outcome, not about talking to AWS.
"""

from __future__ import annotations

import time

import pytest
from click.testing import CliRunner

from ssobroker import cli, exec_cmd
from ssobroker.config import Account, OrgConfig
from ssobroker.sso import SsoToken, SsoTokenExpiredError

FAKE_CFG = OrgConfig(
    name="test",
    sso_start_url="https://example.awsapps.com/start",
    sso_region="us-east-1",
    default_region="us-east-1",
    accounts={
        "prod": Account(alias="prod", account_id="111111111111", roles=["ro"], default_role="ro"),
    },
)

FAKE_TOKEN = SsoToken(
    access_token="tok",
    expires_at=time.time() + 3600,
    region="us-east-1",
    start_url="https://example.awsapps.com/start",
)

FAKE_CREDS = {
    "AccessKeyId": "AKIAFAKE",
    "SecretAccessKey": "fake-secret",
    "SessionToken": "fake-token",
    "Expiration": 9999999999000,
}

EXPIRED = SsoTokenExpiredError("Your cached SSO session was rejected by AWS. Run login again.")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    monkeypatch.setattr(cli.config, "load", lambda: FAKE_CFG)
    monkeypatch.setattr(cli.sso, "login", lambda *a, **k: FAKE_TOKEN)
    return tmp_path


def _clean_exit(result, exit_code: int = 1) -> None:
    """Assert the command exited via its own sys.exit(exit_code) — printing
    a message on the way — rather than letting an exception (ConfigError,
    SsoTokenExpiredError, ...) escape unhandled up through Click. Checking
    exit_code alone would not catch a regression here: CliRunner reports
    exit_code 1 with empty output for an unhandled exception too."""
    assert isinstance(result.exception, SystemExit), (
        f"expected a clean sys.exit, got {result.exception!r} (output: {result.output!r})"
    )
    assert result.exit_code == exit_code
    assert result.output.strip(), "expected an error message to be printed"


def invoke(*args: str):
    return CliRunner().invoke(cli.main, list(args))


# --- whoami -----------------------------------------------------------------


def test_whoami_unknown_account_is_a_clean_error_not_a_traceback():
    result = invoke("whoami", "-a", "doesnotexist")
    _clean_exit(result)
    assert "doesnotexist" in result.output


def test_whoami_expired_token_is_a_clean_error_not_a_traceback(monkeypatch):
    monkeypatch.setattr(
        cli.sso, "get_role_credentials", lambda *a, **k: (_ for _ in ()).throw(EXPIRED)
    )
    result = invoke("whoami", "-a", "prod")
    _clean_exit(result)
    assert "Run" in result.output or "login" in result.output.lower()


# --- check-policy -------------------------------------------------------------


def test_check_policy_unknown_account_is_a_clean_error_not_a_traceback():
    result = invoke("check-policy", "-a", "doesnotexist", "--action", "s3:GetObject")
    _clean_exit(result)
    assert "doesnotexist" in result.output


def test_check_policy_expired_token_is_a_clean_error_not_a_traceback(monkeypatch):
    monkeypatch.setattr(
        cli.sso, "get_role_credentials", lambda *a, **k: (_ for _ in ()).throw(EXPIRED)
    )
    result = invoke("check-policy", "-a", "prod", "--action", "s3:GetObject")
    _clean_exit(result)


# --- list-remote --------------------------------------------------------------


def test_list_remote_expired_token_is_a_clean_error_not_a_traceback(monkeypatch):
    monkeypatch.setattr(cli.sso, "list_accounts", lambda *a, **k: (_ for _ in ()).throw(EXPIRED))
    result = invoke("list-remote")
    _clean_exit(result)


# --- exec ---------------------------------------------------------------------


def test_exec_unknown_account_is_a_clean_error_not_a_traceback():
    result = invoke("exec", "-a", "doesnotexist", "--", "aws", "sts", "get-caller-identity")
    _clean_exit(result)
    assert "doesnotexist" in result.output


def test_exec_expired_token_is_a_clean_error_not_a_traceback(monkeypatch):
    monkeypatch.setattr(
        exec_cmd, "get_role_credentials", lambda *a, **k: (_ for _ in ()).throw(EXPIRED)
    )
    result = invoke("exec", "-a", "prod", "--", "aws", "sts", "get-caller-identity")
    _clean_exit(result)


# --- shell ---------------------------------------------------------------------


def test_shell_expired_token_is_a_clean_error_not_a_traceback(monkeypatch):
    monkeypatch.setattr(
        exec_cmd, "get_role_credentials", lambda *a, **k: (_ for _ in ()).throw(EXPIRED)
    )
    result = invoke("shell", "-a", "prod")
    _clean_exit(result)


# --- export-env ------------------------------------------------------------------


def test_export_env_expired_token_is_a_clean_error_not_a_traceback(monkeypatch):
    monkeypatch.setattr(
        exec_cmd, "get_role_credentials", lambda *a, **k: (_ for _ in ()).throw(EXPIRED)
    )
    result = invoke("export-env", "-a", "prod")
    _clean_exit(result)


# --- creds-process -----------------------------------------------------------------


def test_creds_process_unknown_account_is_a_clean_stderr_error():
    result = invoke("creds-process", "-a", "doesnotexist")
    _clean_exit(result)
    assert "doesnotexist" in result.output


def test_creds_process_expired_token_is_a_clean_stderr_error(monkeypatch):
    monkeypatch.setattr(
        cli.sso, "get_role_credentials", lambda *a, **k: (_ for _ in ()).throw(EXPIRED)
    )
    result = invoke("creds-process", "-a", "prod")
    _clean_exit(result)


def test_creds_process_success_prints_only_json_to_stdout(monkeypatch):
    monkeypatch.setattr(cli.sso, "get_role_credentials", lambda *a, **k: dict(FAKE_CREDS))
    result = invoke("creds-process", "-a", "prod")
    assert result.exit_code == 0
    assert result.output.strip().startswith("{")
    assert "AKIAFAKE" in result.output


# --- doctor --------------------------------------------------------------------------


def test_doctor_reports_ok_when_cache_dir_is_writable():
    result = invoke("doctor")
    assert result.exit_code == 0
    assert "cache dir writable" in result.output
    assert "FAIL" not in result.output


def test_doctor_reports_failure_when_cache_dir_is_not_writable(monkeypatch):
    # Regression: doctor printed "OK cache dir writable" unconditionally,
    # without ever testing that a write actually succeeds.
    monkeypatch.setattr(cli, "_cache_dir_writable_error", lambda cdir: "Permission denied")
    result = invoke("doctor")
    assert result.exit_code == 1
    assert "FAIL" in result.output
    assert "not writable" in result.output
