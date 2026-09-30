"""Property-based (fuzz) tests with Hypothesis.

These cover the code that turns untrusted text into something that gets
written, eval'd or matched: audit redaction, shell quoting for export-env,
the ~/.aws/config editor, guardrail patterns and the managed-policy parser.
Each test states a property that must hold for every input Hypothesis can
generate, not just the handful of cases in the example-based tests.
"""

from __future__ import annotations

import shlex
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ssobroker import audit, aws_config_sync, exec_cmd, guardrails, policy
from ssobroker.config import Account, OrgConfig

SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# Any text a shell or config file could receive (no NUL, no lone surrogates).
any_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00")
)
# Plain arguments that are neither flags nor NAME=value pairs.
plain_arg = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789/:._", min_size=1)
secret_word = st.sampled_from(["secret", "password", "passwd", "token", "api-key", "credential"])
affix = st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", max_size=8)


# --- audit redaction ----------------------------------------------------------


@SETTINGS
@given(
    before=st.lists(plain_arg, max_size=4),
    after=st.lists(plain_arg, max_size=4),
    prefix=affix,
    word=secret_word,
    suffix=affix,
    value=any_text.filter(lambda v: v != ""),
    form=st.sampled_from(["separate", "equals", "env"]),
)
def test_secret_values_never_survive_redaction(before, after, prefix, word, suffix, value, form):
    name = f"{prefix}{word}{suffix}".strip("-") or word
    env_name = name.upper().replace("-", "_")
    if form == "separate":
        secret_args, expected = [f"--{name}", value], [f"--{name}", audit.REDACTED]
    elif form == "equals":
        secret_args, expected = [f"--{name}={value}"], [f"--{name}={audit.REDACTED}"]
    else:
        secret_args, expected = [f"{env_name}={value}"], [f"{env_name}={audit.REDACTED}"]
    command = ["tool", *before, *secret_args, *after]

    out = audit.redact_command(command)

    assert len(out) == len(command)
    assert out[1 + len(before) : 1 + len(before) + len(secret_args)] == expected
    # Everything around the secret is left exactly as it was.
    assert out[: 1 + len(before)] == command[: 1 + len(before)]
    assert out[len(out) - len(after) :] == command[len(command) - len(after) :]


@SETTINGS
@given(st.lists(plain_arg, max_size=8))
def test_redaction_leaves_ordinary_commands_alone(args):
    command = ["aws", *args]
    assert audit.redact_command(command) == command


# --- export-env quoting ---------------------------------------------------------


CFG = OrgConfig(
    name="t",
    sso_start_url="https://example.awsapps.com/start",
    sso_region="us-east-1",
    default_region="us-east-1",
    accounts={"prod": Account(alias="prod", account_id="111111111111", roles=["admin"])},
)


def _export_lines(value: str, powershell: bool) -> str:
    creds = {
        "AccessKeyId": "AKIAFAKE",
        "SecretAccessKey": "s",
        "SessionToken": value,
        "Expiration": 9999999999000,
    }
    with (
        tempfile.TemporaryDirectory() as home,
        mock.patch.dict("os.environ", {"SSOBROKER_HOME": home}),
        mock.patch.object(exec_cmd, "get_role_credentials", lambda *a, **k: creds),
    ):
        return exec_cmd.export_env_lines(
            CFG, None, "prod", "admin", powershell=powershell, gcfg=guardrails.GuardrailConfig()
        )


@SETTINGS
@given(any_text)
def test_posix_export_line_parses_back_to_the_exact_value(value):
    """`eval "$(ssobroker export-env ...)"` must assign exactly the value
    and nothing else, whatever characters it contains."""
    words = shlex.split(_export_lines(value, powershell=False))
    # Five `export NAME=value` statements, and the token comes back intact.
    assert words[0::2] == ["export"] * 5
    assert f"AWS_SESSION_TOKEN={value}" in words[1::2]


# PowerShell ends a double-quoted string at ", and also at the typographic
# double quotes below. ` escapes the next character; an unescaped $ expands.
_PS_QUOTES = {'"', "“", "”", "„"}


def _parse_powershell_double_quoted(literal: str) -> str:
    assert literal[0] == '"' and literal[-1] == '"'
    body, out, i = literal[1:-1], [], 0
    while i < len(body):
        ch = body[i]
        if ch == "`":
            assert i + 1 < len(body), "dangling escape"
            out.append(body[i + 1])
            i += 2
            continue
        assert ch not in _PS_QUOTES, f"unescaped quote {ch!r} would end the string"
        assert ch != "$", "unescaped $ would expand a variable"
        out.append(ch)
        i += 1
    return "".join(out)


@SETTINGS
@given(any_text.filter(lambda v: "\n" not in v and "\r" not in v))
def test_powershell_export_line_parses_back_to_the_exact_value(value):
    lines = _export_lines(value, powershell=True).split("\n")
    line = next(li for li in lines if li.startswith("$env:AWS_SESSION_TOKEN = "))
    literal = line[len("$env:AWS_SESSION_TOKEN = ") :]
    assert _parse_powershell_double_quoted(literal) == value


# --- ~/.aws/config editing ---------------------------------------------------------

profile_name = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=12)
config_value = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc", "Zl", "Zp"), blacklist_characters="[]"
    ),
    max_size=20,
)
user_section = st.tuples(
    profile_name.map(lambda n: f"user-{n}"),
    st.dictionaries(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=10),
        config_value,
        max_size=3,
    ),
)


@SETTINGS
@given(
    sections=st.lists(user_section, max_size=5, unique_by=lambda s: s[0]),
    aliases=st.lists(profile_name, min_size=1, max_size=4, unique=True),
    eol=st.sampled_from(["\n", "\r\n"]),
)
def test_sync_preserves_user_sections_and_is_idempotent(sections, aliases, eol):
    original = ""
    for name, keys in sections:
        original += f"[profile {name}]{eol}"
        original += "".join(f"{k} = {v}{eol}" for k, v in keys.items())
        original += eol
    cfg = OrgConfig(
        name="t",
        sso_start_url="https://example.awsapps.com/start",
        sso_region="us-east-1",
        default_region="us-east-1",
        accounts={a: Account(alias=a, account_id="111111111111", roles=["ro"]) for a in aliases},
    )
    with tempfile.TemporaryDirectory() as home, mock.patch.object(Path, "home", lambda: Path(home)):
        path = Path(home) / ".aws" / "config"
        path.parent.mkdir()
        path.write_bytes(original.encode("utf-8"))

        first = aws_config_sync.sync(cfg)
        after_first = path.read_bytes().decode("utf-8")
        second = aws_config_sync.sync(cfg)

        # Everything the user wrote is still there, byte for byte, in order.
        assert after_first.startswith(original)
        assert sorted(first.written) == sorted(aliases)
        # A second run changes nothing and makes no backup.
        assert path.read_bytes().decode("utf-8") == after_first
        assert second.backup is None


# --- guardrails ---------------------------------------------------------------------

global_flag = st.sampled_from(
    ["--debug", "--no-cli-pager", "--profile x", "--region us-east-1", "--output json"]
)


@SETTINGS
@given(
    flags=st.lists(global_flag, max_size=4),
    bucket=plain_arg,
    trailing=st.lists(global_flag, max_size=2),
)
def test_builtin_deny_catches_recursive_s3_rm_whatever_the_global_flags(flags, bucket, trailing):
    command = ["aws", *" ".join(flags).split(), "s3", "rm", f"s3://{bucket}", "--recursive"]
    command += " ".join(trailing).split()
    assert guardrails.check_command(command, "123456789012", guardrails.GuardrailConfig())


# --- managed policy ------------------------------------------------------------------


@SETTINGS
@given(
    key=st.text(min_size=1, max_size=30).filter(lambda k: k not in policy._KNOWN_KEYS),
    value=st.one_of(st.booleans(), st.integers(), any_text),
)
def test_policy_with_any_unknown_key_fails_closed(key, value):
    with pytest.raises(policy.PolicyError, match="Unknown field"):
        policy.parse({"max_session_hours": 4, key: value}, None)


@SETTINGS
@given(st.text(max_size=60))
def test_start_url_normalization_is_idempotent(url):
    once = policy.normalize_start_url(url)
    assert policy.normalize_start_url(once) == once
