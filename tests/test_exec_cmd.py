"""Tests for exec_cmd.run()'s guardrail branching: block / confirm / proceed.

Credentials and the actual subprocess are faked throughout — these tests are
about which branch `run()` takes and what it records to the audit log, not
about SSO or process execution themselves (those are covered by test_sso.py
equivalents / manual testing, same rationale as test_policy_check.py).
"""

from __future__ import annotations

import json

import pytest

from ssobroker import exec_cmd, guardrails
from ssobroker.config import Account, OrgConfig

FAKE_CREDS = {
    "AccessKeyId": "AKIAFAKE",
    "SecretAccessKey": "fake-secret",
    "SessionToken": "fake-token",
    "Expiration": 9999999999000,
}


@pytest.fixture
def cfg():
    return OrgConfig(
        name="test",
        sso_start_url="https://example.awsapps.com/start",
        sso_region="us-east-1",
        default_region="us-east-1",
        accounts={
            "prod": Account(alias="prod", account_id="111111111111", roles=["admin"]),
        },
    )


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    # Route the audit log to a temp dir instead of the real ~/.ssobroker.
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def fake_get_creds(monkeypatch):
    calls = []

    def _fake(sso_token, account_id, role_name):
        calls.append((account_id, role_name))
        return dict(FAKE_CREDS)

    monkeypatch.setattr(exec_cmd, "get_role_credentials", _fake)
    return calls


@pytest.fixture
def fake_subprocess(monkeypatch):
    calls = []

    class _FakeCompletedProcess:
        returncode = 0

    def _fake_run(command, env):
        calls.append((command, env))
        return _FakeCompletedProcess()

    monkeypatch.setattr(exec_cmd.subprocess, "run", _fake_run)
    return calls


def _last_audit_entry(tmp_path) -> dict:
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    return json.loads(lines[-1])


def test_blocked_command_never_fetches_creds_or_runs(
    cfg, fake_get_creds, fake_subprocess, tmp_path
):
    gcfg = guardrails.GuardrailConfig(deny_patterns=["aws s3 rb*"])
    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "s3", "rb", "s3://important-bucket"],
        gcfg=gcfg,
    )

    assert rc == 2
    assert fake_get_creds == []  # never even tried to get credentials
    assert fake_subprocess == []  # and definitely never ran the command

    entry = _last_audit_entry(tmp_path)
    assert entry["result"] == "blocked"
    assert "deny pattern" in entry["detail"]


def test_protected_account_id_blocks_regardless_of_command(cfg, fake_get_creds, fake_subprocess):
    gcfg = guardrails.GuardrailConfig(protected_account_ids=["111111111111"])
    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "s3", "ls"],  # innocuous command, but account is protected
        gcfg=gcfg,
    )

    assert rc == 2
    assert fake_get_creds == []


def test_confirmation_declined_stops_before_running(
    cfg, fake_get_creds, fake_subprocess, monkeypatch, tmp_path
):
    gcfg = guardrails.GuardrailConfig(
        require_confirmation_patterns=["aws ec2 terminate-instances*"]
    )
    monkeypatch.setattr("builtins.input", lambda _: "n")

    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "ec2", "terminate-instances", "--instance-ids", "i-123"],
        gcfg=gcfg,
    )

    assert rc == 1
    assert fake_get_creds == []
    assert fake_subprocess == []
    assert _last_audit_entry(tmp_path)["result"] == "cancelled"


def test_confirmation_accepted_via_prompt_proceeds(
    cfg, fake_get_creds, fake_subprocess, monkeypatch
):
    gcfg = guardrails.GuardrailConfig(
        require_confirmation_patterns=["aws ec2 terminate-instances*"]
    )
    monkeypatch.setattr("builtins.input", lambda _: "y")

    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "ec2", "terminate-instances", "--instance-ids", "i-123"],
        gcfg=gcfg,
    )

    assert rc == 0
    assert fake_get_creds == [("111111111111", "admin")]
    assert len(fake_subprocess) == 1


def test_assume_yes_skips_prompt_entirely(cfg, fake_get_creds, fake_subprocess, monkeypatch):
    gcfg = guardrails.GuardrailConfig(
        require_confirmation_patterns=["aws ec2 terminate-instances*"]
    )

    def _fail_if_called(_):
        raise AssertionError("input() should never be called when assume_yes=True")

    monkeypatch.setattr("builtins.input", _fail_if_called)

    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "ec2", "terminate-instances", "--instance-ids", "i-123"],
        gcfg=gcfg,
        assume_yes=True,
    )

    assert rc == 0
    assert len(fake_subprocess) == 1


def test_ordinary_command_runs_with_no_guardrail_config(cfg, fake_get_creds, fake_subprocess):
    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "sts", "get-caller-identity"],
        gcfg=guardrails.GuardrailConfig(),
    )

    assert rc == 0
    assert fake_get_creds == [("111111111111", "admin")]
    ((ran_command, env),) = fake_subprocess
    assert ran_command == ["aws", "sts", "get-caller-identity"]


def test_credentials_placed_in_child_env_and_profile_stripped(
    cfg, fake_get_creds, fake_subprocess, monkeypatch
):
    monkeypatch.setenv("AWS_PROFILE", "some-other-profile")

    exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "sts", "get-caller-identity"],
        gcfg=guardrails.GuardrailConfig(),
    )

    ((_, env),) = fake_subprocess
    assert env["AWS_ACCESS_KEY_ID"] == FAKE_CREDS["AccessKeyId"]
    assert env["AWS_SECRET_ACCESS_KEY"] == FAKE_CREDS["SecretAccessKey"]
    assert env["AWS_SESSION_TOKEN"] == FAKE_CREDS["SessionToken"]
    assert env["AWS_DEFAULT_REGION"] == "us-east-1"
    # A long-lived profile from the parent shell must never leak into a
    # child process that's supposed to be running under short-lived SSO creds.
    assert "AWS_PROFILE" not in env


def test_exit_code_from_child_process_is_propagated(cfg, fake_get_creds, monkeypatch):
    class _FailingCompletedProcess:
        returncode = 137

    monkeypatch.setattr(exec_cmd.subprocess, "run", lambda command, env: _FailingCompletedProcess())

    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "sts", "get-caller-identity"],
        gcfg=guardrails.GuardrailConfig(),
    )

    assert rc == 137


def test_policy_precheck_warns_but_does_not_block_on_denial(
    cfg, fake_get_creds, fake_subprocess, monkeypatch, capsys
):
    """check_action is advisory-only per the module's own docstring — a
    predicted deny must print a warning but still let the real command run.
    """
    from ssobroker import policy_check

    monkeypatch.setattr(
        policy_check,
        "resolve_role_arn",
        lambda creds, region: "arn:aws:iam::111111111111:role/admin",
    )
    seen = {}

    def _simulate(creds, role_arn, action, resource, region):
        seen.update(creds=creds, region=region)
        return policy_check.PolicyCheckResult(
            action=action, resource=resource, decision="explicitDeny", matched_statements=[]
        )

    monkeypatch.setattr(policy_check, "simulate", _simulate)

    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "s3", "rm", "s3://bucket/key"],
        gcfg=guardrails.GuardrailConfig(),
        check_action="s3:DeleteObject",
    )

    assert rc == 0  # advisory only — proceeds regardless
    assert len(fake_subprocess) == 1
    assert "would be explicitDeny" in capsys.readouterr().err
    # The simulator must be called with the role's credentials, not ambient ones.
    assert seen["creds"] == FAKE_CREDS
    assert seen["region"] == "us-east-1"


def test_policy_precheck_failure_warns_but_does_not_crash(
    cfg, fake_get_creds, fake_subprocess, monkeypatch, capsys
):
    from ssobroker import policy_check

    def _boom(creds, region):
        raise RuntimeError("no IAM permission to simulate")

    monkeypatch.setattr(policy_check, "resolve_role_arn", _boom)

    rc = exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "s3", "ls"],
        gcfg=guardrails.GuardrailConfig(),
        check_action="s3:ListBucket",
    )

    assert rc == 0
    assert len(fake_subprocess) == 1
    assert "policy pre-check failed to run" in capsys.readouterr().err


def test_spawn_shell_blocks_protected_account(
    cfg, fake_get_creds, fake_subprocess, tmp_path, capsys
):
    # Regression: guardrails.yaml documents protected_account_ids as
    # blocking "ANY command via `ssobroker exec`/`shell`", but spawn_shell()
    # never called into guardrails at all — there's no single "command" to
    # pattern-match against for an interactive session, but the
    # protected-account list should still apply.
    gcfg = guardrails.GuardrailConfig(protected_account_ids=["111111111111"])

    rc = exec_cmd.spawn_shell(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        gcfg=gcfg,
    )

    assert rc == 2
    assert fake_get_creds == []
    assert fake_subprocess == []
    assert "BLOCKED by guardrails" in capsys.readouterr().err
    assert _last_audit_entry(tmp_path)["result"] == "blocked"


def test_spawn_shell_proceeds_when_account_not_protected(cfg, fake_get_creds, fake_subprocess):
    gcfg = guardrails.GuardrailConfig(protected_account_ids=["999999999999"])

    rc = exec_cmd.spawn_shell(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        gcfg=gcfg,
    )

    assert rc == 0
    assert fake_get_creds == [("111111111111", "admin")]
    assert len(fake_subprocess) == 1


def test_other_ambient_credential_sources_are_stripped(
    cfg, fake_get_creds, fake_subprocess, monkeypatch
):
    for name in exec_cmd._STRIP_ENV:
        monkeypatch.setenv(name, "from-parent")

    exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "sts", "get-caller-identity"],
        gcfg=guardrails.GuardrailConfig(),
    )

    ((_, env),) = fake_subprocess
    assert not any(name in env for name in exec_cmd._STRIP_ENV)


def test_exec_audit_entry_carries_access_key_id(cfg, fake_get_creds, fake_subprocess, tmp_path):
    exec_cmd.run(
        cfg,
        sso_token=None,
        account_alias_or_id="prod",
        role="admin",
        command=["aws", "s3", "ls"],
        gcfg=guardrails.GuardrailConfig(),
    )
    assert _last_audit_entry(tmp_path)["access_key_id"] == "AKIAFAKE"


def test_default_shell_honours_override():
    assert exec_cmd._default_shell({"SSOBROKER_SHELL": "/bin/zsh"}) == "/bin/zsh"


def test_default_shell_on_windows_prefers_pwsh_then_comspec(monkeypatch):
    monkeypatch.setattr(exec_cmd.os, "name", "nt")
    monkeypatch.setattr(exec_cmd.shutil, "which", lambda n: "C:/pwsh.exe" if n == "pwsh" else None)
    assert exec_cmd._default_shell({}) == "C:/pwsh.exe"
    monkeypatch.setattr(exec_cmd.shutil, "which", lambda n: None)
    assert exec_cmd._default_shell({"COMSPEC": "C:/cmd.exe"}) == "C:/cmd.exe"


def test_credential_process_payload_shape(cfg, monkeypatch):
    monkeypatch.setattr(
        exec_cmd, "fetch_role_credentials", lambda *a, **k: (dict(FAKE_CREDS), False)
    )
    payload = exec_cmd.credential_process_payload(
        cfg, None, "prod", "admin", gcfg=guardrails.GuardrailConfig()
    )
    assert payload["Version"] == 1
    assert payload["AccessKeyId"] == "AKIAFAKE"
    assert payload["Expiration"].endswith("Z")


def test_protected_account_allowed_for_creds_process_unless_strict(cfg, monkeypatch):
    monkeypatch.setattr(
        exec_cmd, "fetch_role_credentials", lambda *a, **k: (dict(FAKE_CREDS), True)
    )
    loose = guardrails.GuardrailConfig(protected_account_ids=["111111111111"])
    assert exec_cmd.credential_process_payload(cfg, None, "prod", "admin", gcfg=loose)

    strict = guardrails.GuardrailConfig(
        protected_account_ids=["111111111111"], strict_protected_accounts=True
    )
    with pytest.raises(guardrails.GuardrailBlocked):
        exec_cmd.credential_process_payload(cfg, None, "prod", "admin", gcfg=strict)
