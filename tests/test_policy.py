"""Tests for the admin-managed policy and how it tightens user config."""

from __future__ import annotations

import os
import sys
import textwrap

import pytest
from conftest import write_policy

from ssobroker import config, guardrails, paths, policy
from ssobroker.config import ConfigError

ORGS = textwrap.dedent(
    """\
    name: test
    sso_start_url: https://example.awsapps.com/start
    sso_region: us-east-1
    max_session_hours: 8
    accounts:
      prod:
        account_id: "111111111111"
        roles: [ro]
      logging:
        account_id: "222222222222"
        roles: [log-writer]
    """
)


@pytest.fixture
def orgs(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("SSOBROKER_HOME", str(home))

    def _write(extra: str = "") -> config.OrgConfig:
        (home / "orgs.yaml").write_text(ORGS + extra)
        return config.load()

    return _write


def test_no_policy_file_means_inactive_policy():
    assert policy.load().active is False


def test_unknown_policy_field_fails_closed(tmp_path, monkeypatch):
    write_policy(monkeypatch, tmp_path, "alowed_sso_start_urls: []\n")
    with pytest.raises(policy.PolicyError, match="Unknown field"):
        policy.load()


def test_invalid_role_cache_value_is_rejected(tmp_path, monkeypatch):
    write_policy(monkeypatch, tmp_path, "role_credential_cache: disk\n")
    with pytest.raises(policy.PolicyError):
        policy.load()


def test_start_url_must_be_https(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    (tmp_path / "orgs.yaml").write_text(ORGS.replace("https://example", "http://example"))
    with pytest.raises(ConfigError, match="https"):
        config.load()


def test_start_url_allowlist_rejects_other_urls(orgs, tmp_path, monkeypatch):
    write_policy(
        monkeypatch, tmp_path, "allowed_sso_start_urls: [https://corp.awsapps.com/start]\n"
    )
    with pytest.raises(ConfigError, match="not allowed"):
        orgs()


def test_start_url_allowlist_match_ignores_case_and_trailing_slash(orgs, tmp_path, monkeypatch):
    write_policy(
        monkeypatch, tmp_path, "allowed_sso_start_urls: [HTTPS://Example.awsapps.com/start/]\n"
    )
    assert orgs().sso_start_url == "https://example.awsapps.com/start"


def test_policy_caps_max_session_hours(orgs, tmp_path, monkeypatch):
    write_policy(monkeypatch, tmp_path, "max_session_hours: 2\n")
    assert orgs().max_session_hours == 2


def test_policy_never_raises_max_session_hours(orgs, tmp_path, monkeypatch):
    write_policy(monkeypatch, tmp_path, "max_session_hours: 24\n")
    assert orgs().max_session_hours == 8


@pytest.mark.parametrize(
    ("user", "managed", "expected"),
    [
        ("file", "keyring", "keyring"),
        ("none", "keyring", "none"),
        ("keyring", "file", "keyring"),
        ("file", None, "file"),
    ],
)
def test_role_cache_takes_the_stricter_setting(user, managed, expected):
    assert policy.stricter_role_cache(user, managed) == expected


def test_policy_can_disable_device_code(orgs, tmp_path, monkeypatch):
    write_policy(monkeypatch, tmp_path, "allow_device_code: false\n")
    with pytest.raises(ConfigError, match="disabled"):
        orgs("login_flow: device_code\n")
    assert orgs().allow_device_code is False


def test_policy_adds_redaction_and_forwarding(orgs, tmp_path, monkeypatch):
    write_policy(
        monkeypatch,
        tmp_path,
        "audit_redact_flags: ['*ssn*']\naudit_forward: [syslog]\n",
    )
    cfg = orgs("audit_redact_flags: ['*pin*']\n")
    assert cfg.audit_redact_flags == ["*pin*", "*ssn*"]
    assert cfg.audit_forward == ["syslog"]


def test_policy_cloudwatch_settings_win(orgs, tmp_path, monkeypatch):
    write_policy(
        monkeypatch,
        tmp_path,
        "cloudwatch_log_group: /corp/ssobroker\n"
        "cloudwatch_account: logging\ncloudwatch_role: log-writer\n",
    )
    cfg = orgs("cloudwatch_log_group: /mine\n")
    assert cfg.cloudwatch_log_group == "/corp/ssobroker"
    assert (cfg.cloudwatch_account, cfg.cloudwatch_role) == ("logging", "log-writer")


def test_cloudwatch_forwarding_needs_a_log_group(orgs):
    with pytest.raises(ConfigError, match="cloudwatch_log_group"):
        orgs("audit_forward: [cloudwatch]\n")


def test_cloudwatch_role_needs_account_too(orgs):
    with pytest.raises(ConfigError, match="both"):
        orgs("cloudwatch_role: log-writer\n")


def test_unknown_audit_forward_target_is_rejected(orgs):
    with pytest.raises(ConfigError, match="audit_forward"):
        orgs("audit_forward: [splunk]\n")


def test_guardrails_merge_policy_on_top_of_user_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    (tmp_path / "guardrails.yaml").write_text(
        "deny_patterns: ['aws iam delete-role*']\nstrict_protected_accounts: false\n"
    )
    write_policy(
        monkeypatch,
        tmp_path,
        "deny_patterns: ['aws kms schedule-key-deletion*']\n"
        "protected_account_ids: ['999999999999']\n"
        "strict_protected_accounts: true\n",
    )
    g = guardrails.GuardrailConfig.load()
    assert g.deny_patterns == ["aws iam delete-role*", "aws kms schedule-key-deletion*"]
    assert g.protected_account_ids == ["999999999999"]
    assert g.strict_protected_accounts is True  # user file can't turn it off


def test_env_overrides_ignored_when_policy_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("SSOBROKER_GUARDRAILS", str(tmp_path / "empty.yaml"))
    monkeypatch.setattr(paths.Path, "home", lambda: tmp_path)
    write_policy(monkeypatch, tmp_path, "ignore_env_overrides: true\n")
    assert paths.home_dir() == tmp_path / ".ssobroker"
    assert policy.env_override("SSOBROKER_GUARDRAILS") is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership check")
def test_policy_not_owned_by_root_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    path.write_text("max_session_hours: 1\n")
    monkeypatch.setattr(policy, "managed_policy_path", lambda: path)
    policy.load.cache_clear()
    if os.geteuid() == 0:
        pytest.skip("running as root")
    with pytest.raises(policy.PolicyError, match="not owned by root"):
        policy.load()


def test_cloudwatch_account_can_be_a_bare_account_id(orgs):
    cfg = orgs("cloudwatch_account: '444444444444'\ncloudwatch_role: AuditLogWriter\n")
    assert config.logging_account_id(cfg) == "444444444444"


def test_cloudwatch_account_alias_must_exist(orgs):
    with pytest.raises(ConfigError, match="Unknown account"):
        orgs("cloudwatch_account: nope\ncloudwatch_role: AuditLogWriter\n")


def test_example_policy_file_parses():
    import pathlib

    import yaml

    root = pathlib.Path(__file__).resolve().parents[1]
    raw = yaml.safe_load((root / "config" / "policy.example.yaml").read_text())
    assert policy.parse(raw, None).allow_device_code is False
