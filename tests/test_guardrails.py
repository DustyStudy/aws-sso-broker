import pytest

from ssobroker import guardrails


def test_protected_account_blocks_everything():
    cfg = guardrails.GuardrailConfig(protected_account_ids=["111111111111"])
    reason = guardrails.check_command(["aws", "s3", "ls"], "111111111111", cfg)
    assert reason is not None
    assert "protected" in reason.lower()


def test_check_protected_account_directly():
    cfg = guardrails.GuardrailConfig(protected_account_ids=["111111111111"])
    reason = guardrails.check_protected_account("111111111111", cfg)
    assert reason is not None
    assert "protected" in reason.lower()


def test_check_protected_account_none_for_unprotected_account():
    cfg = guardrails.GuardrailConfig(protected_account_ids=["111111111111"])
    assert guardrails.check_protected_account("222222222222", cfg) is None


def test_builtin_deny_blocks_leave_organization():
    cfg = guardrails.GuardrailConfig()
    reason = guardrails.check_command(
        ["aws", "organizations", "leave-organization"], "222222222222", cfg
    )
    assert reason is not None


def test_custom_deny_pattern():
    cfg = guardrails.GuardrailConfig(deny_patterns=["aws iam delete-role*"])
    reason = guardrails.check_command(
        ["aws", "iam", "delete-role", "--role-name", "foo"], "333333333333", cfg
    )
    assert reason is not None


def test_safe_command_not_blocked():
    cfg = guardrails.GuardrailConfig()
    reason = guardrails.check_command(["aws", "s3", "ls"], "444444444444", cfg)
    assert reason is None


def test_confirmation_pattern_detected():
    cfg = guardrails.GuardrailConfig(require_confirmation_patterns=["aws s3 rm*"])
    match = guardrails.needs_confirmation(["aws", "s3", "rm", "s3://bucket/key"], cfg)
    assert match == "aws s3 rm*"


def test_no_confirmation_needed_when_no_match():
    cfg = guardrails.GuardrailConfig(require_confirmation_patterns=["aws s3 rm*"])
    match = guardrails.needs_confirmation(["aws", "s3", "ls"], cfg)
    assert match is None


@pytest.mark.parametrize(
    "command",
    [
        ["aws", "s3", "rm", "s3://bucket", "--recursive"],
        ["aws", "s3", "rm", "--recursive", "s3://bucket/prefix/"],
        ["aws", "--profile", "prod", "s3", "rm", "s3://bucket", "--recursive"],
        ["aws", "s3", "rb", "s3://bucket", "--force"],
        ["aws", "organizations", "leave-organization"],
        ["aws", "organizations", "close-account", "--account-id", "123456789012"],
        ["aws", "iam", "delete-account-alias", "--account-alias", "x"],
    ],
)
def test_builtin_deny_blocks_documented_destructive_commands(command):
    # Regression: the recursive `s3 rm` built-in required "--recursive" to appear
    # *before* "s3", which no real invocation does, so it never matched.
    reason = guardrails.check_command(command, "222222222222", guardrails.GuardrailConfig())
    assert reason is not None
    assert "deny pattern" in reason


@pytest.mark.parametrize(
    "command",
    [
        ["aws", "s3", "rm", "s3://bucket/key"],  # single object, not recursive
        ["aws", "s3", "ls", "--recursive"],
        ["aws", "s3", "cp", "--recursive", "./dir", "s3://bucket/dir"],
        ["aws", "s3", "sync", ".", "s3://bucket"],
    ],
)
def test_builtin_deny_does_not_block_benign_s3_commands(command):
    reason = guardrails.check_command(command, "222222222222", guardrails.GuardrailConfig())
    assert reason is None


@pytest.mark.parametrize(
    "command",
    [
        ["aws", "--profile", "prod", "organizations", "leave-organization"],
        ["aws", "--region", "us-east-1", "organizations", "close-account", "--account-id", "1"],
        ["aws", "--profile", "prod", "iam", "delete-account-alias", "--account-alias", "x"],
        ["aws", "--profile", "prod", "s3", "rb", "s3://bucket", "--force"],
    ],
)
def test_builtin_deny_blocks_destructive_commands_with_global_flags_before_service(command):
    # Regression: every built-in pattern except the recursive-s3-rm one still
    # required "aws" to be immediately followed by the service name, so a
    # global flag in between (as real `aws` CLI usage often has) slipped past.
    reason = guardrails.check_command(command, "222222222222", guardrails.GuardrailConfig())
    assert reason is not None
    assert "deny pattern" in reason
