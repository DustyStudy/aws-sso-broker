"""Tests for exec_cmd.export_env_lines(): the lines it prints are meant to be
eval'd directly into the caller's shell, so a value containing a shell
metacharacter must not let that value break out of its assignment.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from ssobroker import exec_cmd
from ssobroker.config import Account, OrgConfig
from ssobroker.sso import SsoToken

CFG = OrgConfig(
    name="test",
    sso_start_url="https://example.awsapps.com/start",
    sso_region="us-east-1",
    default_region="us-east-1",
    accounts={
        "prod": Account(alias="prod", account_id="111111111111", roles=["admin"]),
    },
)

TOKEN = SsoToken(access_token="tok", expires_at=0, region="us-east-1", start_url=CFG.sso_start_url)


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))


def _fake_creds(monkeypatch, **overrides):
    creds = {
        "AccessKeyId": "AKIAFAKE",
        "SecretAccessKey": "fake-secret",
        "SessionToken": "fake-token",
        "Expiration": 9999999999000,
        **overrides,
    }
    monkeypatch.setattr(exec_cmd, "get_role_credentials", lambda *a, **k: creds)
    return creds


def test_posix_lines_have_ordinary_values_unquoted(monkeypatch):
    _fake_creds(monkeypatch)
    lines = exec_cmd.export_env_lines(CFG, TOKEN, "prod", "admin")
    assert "export AWS_ACCESS_KEY_ID=AKIAFAKE" in lines
    assert "export AWS_SECRET_ACCESS_KEY=fake-secret" in lines
    assert "export AWS_REGION=us-east-1" in lines


def test_powershell_lines_have_ordinary_values_double_quoted(monkeypatch):
    _fake_creds(monkeypatch)
    lines = exec_cmd.export_env_lines(CFG, TOKEN, "prod", "admin", powershell=True)
    assert '$env:AWS_ACCESS_KEY_ID = "AKIAFAKE"' in lines
    assert '$env:AWS_REGION = "us-east-1"' in lines


@pytest.mark.parametrize(
    "malicious_token",
    [
        "abc$(rm -rf ~)def",
        "abc`rm -rf ~`def",
        "abc'; rm -rf ~; echo 'def",
        'abc"; rm -rf ~; echo "def',
    ],
)
def test_posix_export_line_is_safe_to_eval_even_with_shell_metacharacters(
    monkeypatch, malicious_token
):
    # Regression: values were interpolated into `export KEY="value"` with no
    # quoting/escaping. AWS credentials never actually contain these
    # characters, but the values still come from an external API response,
    # so the interpolation itself should not be a foot-gun. Prove it by
    # actually eval-ing the generated line in a POSIX shell and checking the
    # metacharacters were neutralized rather than executed.
    if sys.platform == "win32":
        pytest.skip("needs a POSIX shell to eval against")
    _fake_creds(monkeypatch, SessionToken=malicious_token)
    lines = exec_cmd.export_env_lines(CFG, TOKEN, "prod", "admin")

    result = subprocess.run(
        ["sh", "-c", f'{lines}\nprintf "%s" "$AWS_SESSION_TOKEN"'],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == malicious_token


def test_powershell_double_quotes_in_value_do_not_end_the_string(monkeypatch):
    _fake_creds(monkeypatch, SessionToken='abc"; Remove-Item -Recurse C:\\; "def')
    lines = exec_cmd.export_env_lines(CFG, TOKEN, "prod", "admin", powershell=True)
    line = next(line_ for line_ in lines.splitlines() if "AWS_SESSION_TOKEN" in line_)
    # The whole value stays inside one quoted string: exactly two unescaped
    # (non-backtick-preceded) double quotes delimit it, at the very ends.
    assert line.startswith('$env:AWS_SESSION_TOKEN = "')
    assert line.endswith('"')
    body = line[len('$env:AWS_SESSION_TOKEN = "') : -1]
    assert '`"' in body  # the embedded quotes were escaped, not left bare


@pytest.mark.parametrize("quote", ["\u201c", "\u201d", "\u201e"])
def test_powershell_typographic_quotes_are_escaped(monkeypatch, quote):
    # Found by Hypothesis: PowerShell ends a double-quoted string at these too.
    _fake_creds(monkeypatch, SessionToken=f"abc{quote}; Remove-Item C:\; {quote}def")
    lines = exec_cmd.export_env_lines(CFG, TOKEN, "prod", "admin", powershell=True)
    line = next(line_ for line_ in lines.splitlines() if "AWS_SESSION_TOKEN" in line_)
    assert f"`{quote}" in line
    assert line.count(quote) == line.count(f"`{quote}")
