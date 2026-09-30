"""Run a command (or a subshell) with short-lived, exported credentials for
one account/role — and nowhere else. Credentials live only in the child
process's environment; they are never written to disk unencrypted outside
the cache, and never printed.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import time

from . import audit, guardrails
from .config import Account, OrgConfig, resolve_account, resolve_role
from .sso import SsoToken, fetch_role_credentials, get_role_credentials

# Other ways an AWS SDK could pick up credentials or a role from the parent
# shell. The explicit keys set below normally win, but removing these makes
# sure nothing else is mixed in.
_STRIP_ENV = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CREDENTIAL_EXPIRATION",
)


def _creds_to_env(creds: dict, region: str) -> dict:
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
    env["AWS_SESSION_TOKEN"] = creds["SessionToken"]
    env["AWS_DEFAULT_REGION"] = region
    env["AWS_REGION"] = region
    # Never inherit a long-lived profile/key from the parent shell by accident.
    for name in _STRIP_ENV:
        env.pop(name, None)
    return env


def _default_shell(env: dict) -> str:
    """SSOBROKER_SHELL if set; otherwise $SHELL on POSIX, and PowerShell 7
    (then Windows PowerShell, then %COMSPEC%) on Windows."""
    if env.get("SSOBROKER_SHELL"):
        return env["SSOBROKER_SHELL"]
    if os.name != "nt":
        return env.get("SHELL", "/bin/bash")
    return shutil.which("pwsh") or shutil.which("powershell") or env.get("COMSPEC", "cmd.exe")


def enforce_strict_protected(
    account: Account,
    resolved_role: str,
    gcfg: guardrails.GuardrailConfig,
    *,
    action: str,
    reason: str | None = None,
) -> None:
    """Refuse a protected account on paths that aren't `exec`/`shell` when
    `strict_protected_accounts` is on. Raises GuardrailBlocked."""
    if not gcfg.strict_protected_accounts:
        return
    block_reason = guardrails.check_protected_account(account.account_id, gcfg)
    if block_reason:
        audit.record(
            action=action,
            account_id=account.account_id,
            role=resolved_role,
            result="blocked",
            detail=block_reason,
            reason=reason,
        )
        raise guardrails.GuardrailBlocked(block_reason, "protected_account_ids")


def run(
    cfg: OrgConfig,
    sso_token: SsoToken,
    account_alias_or_id: str,
    role: str | None,
    command: list[str],
    region: str | None = None,
    *,
    gcfg: guardrails.GuardrailConfig | None = None,
    assume_yes: bool = False,
    reason: str | None = None,
    check_action: str | None = None,
    check_resource: str = "*",
) -> int:
    account: Account = resolve_account(cfg, account_alias_or_id)
    resolved_role = resolve_role(account, role)
    gcfg = gcfg or guardrails.GuardrailConfig.load()

    block_reason = guardrails.check_command(command, account.account_id, gcfg)
    if block_reason:
        audit.record(
            action="exec",
            account_id=account.account_id,
            role=resolved_role,
            command=command,
            result="blocked",
            detail=block_reason,
            reason=reason,
        )
        print(f"BLOCKED by guardrails: {block_reason}", file=sys.stderr)
        return 2

    confirm_pattern = guardrails.needs_confirmation(command, gcfg)
    if confirm_pattern and not assume_yes:
        joined = " ".join(command)
        print(
            f"This command matches a require-confirmation pattern "
            f"('{confirm_pattern}'):\n  {joined}\nagainst account "
            f"{account.alias} ({account.account_id}) as {resolved_role}.",
        )
        answer = input("Continue? [y/N] ").strip().lower()
        if answer != "y":
            audit.record(
                action="exec",
                account_id=account.account_id,
                role=resolved_role,
                command=command,
                result="cancelled",
                reason=reason,
            )
            return 1

    creds = get_role_credentials(sso_token, account.account_id, resolved_role)

    if check_action:
        from . import policy_check

        try:
            check_region = region or cfg.default_region
            role_arn = policy_check.resolve_role_arn(creds, check_region)
            result = policy_check.simulate(
                creds, role_arn, check_action, check_resource, check_region
            )
        except Exception as e:  # noqa: BLE001 — surface any failure as a warning, don't crash the real command
            print(f"WARNING: policy pre-check failed to run: {e}", file=sys.stderr)
        else:
            if not result.allowed:
                print(
                    f"WARNING: identity-based policy pre-check says "
                    f"'{check_action}' on '{check_resource}' would be "
                    f"{result.decision} for this role. This does NOT check "
                    f"SCPs or resource policies — proceeding anyway since "
                    f"this is advisory only.",
                    file=sys.stderr,
                )

    env = _creds_to_env(creds, region or cfg.default_region)

    audit.record(
        action="exec",
        account_id=account.account_id,
        role=resolved_role,
        command=command,
        reason=reason,
        access_key_id=creds["AccessKeyId"],
    )

    proc = subprocess.run(command, env=env)
    return proc.returncode


def spawn_shell(
    cfg: OrgConfig,
    sso_token: SsoToken,
    account_alias_or_id: str,
    role: str | None,
    region: str | None = None,
    *,
    gcfg: guardrails.GuardrailConfig | None = None,
    reason: str | None = None,
) -> int:
    account = resolve_account(cfg, account_alias_or_id)
    resolved_role = resolve_role(account, role)
    gcfg = gcfg or guardrails.GuardrailConfig.load()

    # There's no single "command" here to pattern-match against (this opens
    # an interactive session), but the protected-account list is documented
    # as covering both `exec` and `shell` — enforce that part of it.
    block_reason = guardrails.check_protected_account(account.account_id, gcfg)
    if block_reason:
        audit.record(
            action="shell",
            account_id=account.account_id,
            role=resolved_role,
            result="blocked",
            detail=block_reason,
            reason=reason,
        )
        print(f"BLOCKED by guardrails: {block_reason}", file=sys.stderr)
        return 2

    creds = get_role_credentials(sso_token, account.account_id, resolved_role)
    env = _creds_to_env(creds, region or cfg.default_region)

    shell = _default_shell(env)
    prompt_tag = f"[{account.alias}:{resolved_role}]"
    env["SSOBROKER_ACTIVE_CONTEXT"] = prompt_tag
    if os.name != "nt":
        env.setdefault("PS1", f"{prompt_tag} $ ")

    audit.record(
        action="shell",
        account_id=account.account_id,
        role=resolved_role,
        reason=reason,
        access_key_id=creds["AccessKeyId"],
    )

    minutes_left = (creds["Expiration"] / 1000.0 - time.time()) / 60.0
    print(f"Spawning subshell as {prompt_tag} — type 'exit' to return.")
    print(f"Credentials expire in ~{minutes_left:.0f} min.", file=sys.stderr)
    if minutes_left < 15:
        print(
            "WARNING: these credentials expire soon. A long session may outlive "
            "them — if AWS calls start failing with an expired-token error, exit "
            "and run `ssobroker shell` again to get a fresh set.",
            file=sys.stderr,
        )

    proc = subprocess.run([shell], env=env)
    return proc.returncode


def export_env_lines(
    cfg: OrgConfig,
    sso_token: SsoToken,
    account_alias_or_id: str,
    role: str | None,
    region: str | None = None,
    *,
    gcfg: guardrails.GuardrailConfig | None = None,
    powershell: bool = False,
    reason: str | None = None,
) -> str:
    """Return shell commands that export credentials for account/role into
    *the calling shell* — for `eval "$(ssobroker export-env -a prod -r admin)"`
    where spawning a subshell (see spawn_shell) isn't what you want, e.g.
    inside a script or CI step that needs to keep running in the same shell.
    """
    account = resolve_account(cfg, account_alias_or_id)
    resolved_role = resolve_role(account, role)
    gcfg = gcfg or guardrails.GuardrailConfig.load()
    enforce_strict_protected(account, resolved_role, gcfg, action="export-env", reason=reason)
    creds = get_role_credentials(sso_token, account.account_id, resolved_role)
    resolved_region = region or cfg.default_region

    audit.record(
        action="export-env",
        account_id=account.account_id,
        role=resolved_role,
        reason=reason,
        access_key_id=creds["AccessKeyId"],
    )

    pairs = [
        ("AWS_ACCESS_KEY_ID", creds["AccessKeyId"]),
        ("AWS_SECRET_ACCESS_KEY", creds["SecretAccessKey"]),
        ("AWS_SESSION_TOKEN", creds["SessionToken"]),
        ("AWS_DEFAULT_REGION", resolved_region),
        ("AWS_REGION", resolved_region),
    ]
    if powershell:
        return "\n".join(f"$env:{k} = {_powershell_quote(v)}" for k, v in pairs)
    return "\n".join(f"export {k}={shlex.quote(v)}" for k, v in pairs)


def _powershell_quote(value: str) -> str:
    """Quote `value` for interpolation into a PowerShell double-quoted
    string. AWS credentials/regions never actually contain these characters,
    but the values still come from an external API response, so this is
    defensive rather than provably unnecessary — same reasoning as using
    shlex.quote() for the POSIX side above."""
    escaped = value.replace("`", "``").replace('"', '`"').replace("$", "`$")
    return f'"{escaped}"'


def credential_process_payload(
    cfg: OrgConfig,
    sso_token: SsoToken,
    account_alias_or_id: str,
    role: str | None,
    *,
    gcfg: guardrails.GuardrailConfig | None = None,
) -> dict:
    """The JSON document the AWS `credential_process` protocol expects.

    Writes an audit entry only when AWS issued new credentials, not on a
    cache hit, so wiring this into ~/.aws/config doesn't flood the log."""
    import datetime

    account = resolve_account(cfg, account_alias_or_id)
    resolved_role = resolve_role(account, role)
    gcfg = gcfg or guardrails.GuardrailConfig.load()
    enforce_strict_protected(account, resolved_role, gcfg, action="creds-process")
    creds, fresh = fetch_role_credentials(sso_token, account.account_id, resolved_role)
    if fresh:
        audit.record(
            action="creds-process",
            account_id=account.account_id,
            role=resolved_role,
            access_key_id=creds["AccessKeyId"],
        )
    expiration = datetime.datetime.fromtimestamp(creds["Expiration"] / 1000.0, tz=datetime.UTC)
    return {
        "Version": 1,
        "AccessKeyId": creds["AccessKeyId"],
        "SecretAccessKey": creds["SecretAccessKey"],
        "SessionToken": creds["SessionToken"],
        "Expiration": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
