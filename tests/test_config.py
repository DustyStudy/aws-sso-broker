import textwrap

import pytest

from ssobroker import config


def write_orgs_yaml(tmp_path, content):
    p = tmp_path / "orgs.yaml"
    p.write_text(textwrap.dedent(content))
    return p


def test_load_valid_config(tmp_path):
    p = write_orgs_yaml(
        tmp_path,
        """
        name: test-org
        sso_start_url: https://example.awsapps.com/start
        sso_region: us-east-1
        accounts:
          prod:
            account_id: "123456789012"
            roles: [read-only, admin]
            default_role: read-only
        """,
    )
    cfg = config.load(p)
    assert cfg.name == "test-org"
    assert "prod" in cfg.accounts
    assert cfg.accounts["prod"].account_id == "123456789012"
    assert cfg.default_region == "us-east-1"  # falls back to sso_region


def test_missing_file_raises(tmp_path):
    with pytest.raises(config.ConfigError):
        config.load(tmp_path / "does-not-exist.yaml")


def test_missing_required_field(tmp_path):
    p = write_orgs_yaml(
        tmp_path,
        """
        name: test-org
        accounts: {}
        """,
    )
    with pytest.raises(config.ConfigError):
        config.load(p)


def test_account_missing_id(tmp_path):
    p = write_orgs_yaml(
        tmp_path,
        """
        name: test-org
        sso_start_url: https://example.awsapps.com/start
        sso_region: us-east-1
        accounts:
          prod:
            roles: [read-only]
        """,
    )
    with pytest.raises(config.ConfigError):
        config.load(p)


def test_resolve_account_by_alias_and_id(tmp_path):
    p = write_orgs_yaml(
        tmp_path,
        """
        name: test-org
        sso_start_url: https://example.awsapps.com/start
        sso_region: us-east-1
        accounts:
          prod:
            account_id: "123456789012"
            roles: [read-only]
        """,
    )
    cfg = config.load(p)
    assert config.resolve_account(cfg, "prod").account_id == "123456789012"
    assert config.resolve_account(cfg, "123456789012").alias == "prod"
    with pytest.raises(config.ConfigError):
        config.resolve_account(cfg, "nope")


def test_optional_fields_and_defaults(tmp_path):
    p = write_orgs_yaml(
        tmp_path,
        """
        name: test-org
        sso_start_url: https://example.awsapps.com/start
        sso_region: us-east-1
        accounts:
          prod:
            account_id: "123456789012"
            roles: [read-only]
        """,
    )
    cfg = config.load(p)
    assert cfg.max_session_hours == 8.0
    assert cfg.cloudwatch_log_group is None


def test_optional_fields_explicit(tmp_path):
    p = write_orgs_yaml(
        tmp_path,
        """
        name: test-org
        sso_start_url: https://example.awsapps.com/start
        sso_region: us-east-1
        max_session_hours: 2
        cloudwatch_log_group: /ssobroker/audit
        accounts:
          prod:
            account_id: "123456789012"
            roles: [read-only]
        """,
    )
    cfg = config.load(p)
    assert cfg.max_session_hours == 2.0
    assert cfg.cloudwatch_log_group == "/ssobroker/audit"


def test_accounts_by_tag(tmp_path):
    p = write_orgs_yaml(
        tmp_path,
        """
        name: test-org
        sso_start_url: https://example.awsapps.com/start
        sso_region: us-east-1
        accounts:
          prod:
            account_id: "111111111111"
            roles: [read-only]
            tags: [prod, critical]
          dev:
            account_id: "222222222222"
            roles: [PowerUserAccess]
            tags: [dev]
        """,
    )
    cfg = config.load(p)
    assert {a.alias for a in config.accounts_by_tag(cfg, "prod")} == {"prod"}
    assert {a.alias for a in config.accounts_by_tag(cfg, None)} == {"prod", "dev"}
    assert config.accounts_by_tag(cfg, "nonexistent") == []


def test_resolve_role_defaults_and_ambiguity(tmp_path):
    p = write_orgs_yaml(
        tmp_path,
        """
        name: test-org
        sso_start_url: https://example.awsapps.com/start
        sso_region: us-east-1
        accounts:
          single-role:
            account_id: "111111111111"
            roles: [read-only]
          multi-role-with-default:
            account_id: "222222222222"
            roles: [read-only, admin]
            default_role: read-only
          multi-role-no-default:
            account_id: "333333333333"
            roles: [read-only, admin]
        """,
    )
    cfg = config.load(p)

    assert config.resolve_role(cfg.accounts["single-role"], None) == "read-only"
    assert config.resolve_role(cfg.accounts["multi-role-with-default"], None) == "read-only"
    assert config.resolve_role(cfg.accounts["multi-role-with-default"], "admin") == "admin"

    with pytest.raises(config.ConfigError):
        config.resolve_role(cfg.accounts["multi-role-no-default"], None)

    with pytest.raises(config.ConfigError):
        config.resolve_role(cfg.accounts["single-role"], "not-a-real-role")
