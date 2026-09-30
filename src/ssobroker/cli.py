from __future__ import annotations

import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import click
from rich.console import Console
from rich.table import Table

from . import audit, aws_config_sync, cache, config, exec_cmd, guardrails, network, policy, sso
from .config import ConfigError
from .paths import home_dir

console = Console()

T = TypeVar("T")


def _sso_login(cfg: config.OrgConfig, flow: str | None = None) -> sso.SsoToken:
    return sso.login(
        cfg.sso_start_url,
        cfg.sso_region,
        max_session_hours=cfg.max_session_hours,
        flow=flow or cfg.login_flow,
        allow_device_code=cfg.allow_device_code,
        role_credential_cache=cfg.role_credential_cache,
    )


def _logging_role_credentials(cfg: config.OrgConfig) -> Callable[[], dict] | None:
    """Credentials provider for the CloudWatch logging role, if one is set."""
    if not (cfg.cloudwatch_account and cfg.cloudwatch_role):
        return None
    account_id = config.logging_account_id(cfg)
    role = cfg.cloudwatch_role
    return lambda: sso.get_role_credentials(_sso_login(cfg), account_id, role)


def _prepare(cfg: config.OrgConfig) -> config.OrgConfig:
    """Apply network settings and audit settings from a loaded config."""
    network.apply(cfg)
    audit.configure(
        audit.AuditSettings(
            redact_patterns=cfg.audit_redact_flags,
            forward=cfg.audit_forward,
            cloudwatch_log_group=cfg.cloudwatch_log_group,
            cloudwatch_region=cfg.default_region,
            cloudwatch_credentials=_logging_role_credentials(cfg),
        )
    )
    return cfg


def _load_config_or_exit() -> config.OrgConfig:
    try:
        return _prepare(config.load())
    except ConfigError as e:
        console.print(f"[red]Config error:[/red] {e}")
        sys.exit(1)


def _login_or_exit(cfg: config.OrgConfig, flow: str | None = None) -> sso.SsoToken:
    try:
        return _sso_login(cfg, flow)
    except sso.SsoLoginError as e:
        console.print(f"[red]Login failed:[/red] {e}")
        sys.exit(1)


def _guard(fn: Callable[..., T], *args: object, **kwargs: object) -> T:
    """Call fn, turning an unknown account/role (ConfigError) or a rejected/
    expired SSO token (SsoLoginError) into a clean one-line message and
    exit(1), instead of the raw traceback these used to produce in every
    command below `login`/`_load_config_or_exit`."""
    try:
        return fn(*args, **kwargs)
    except (ConfigError, sso.SsoLoginError) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except guardrails.GuardrailBlocked as e:
        console.print(f"[red]BLOCKED by guardrails:[/red] {e}")
        sys.exit(2)


def _resolve_and_get_creds(
    cfg: config.OrgConfig, token: sso.SsoToken, account: str, role: str | None
) -> tuple[config.Account, str, dict]:
    acct = config.resolve_account(cfg, account)
    resolved_role = config.resolve_role(acct, role)
    creds = sso.get_role_credentials(token, acct.account_id, resolved_role)
    return acct, resolved_role, creds


def _fetch_remote_accounts(
    token: sso.SsoToken,
) -> tuple[list[str], list[str], list[list[str]]]:
    accts = sso.list_accounts(token)
    account_ids: list[str] = []
    account_names: list[str] = []
    roles_by_account: list[list[str]] = []
    for a in accts:
        account_ids.append(a["accountId"])
        account_names.append(a["accountName"] or "-")
        roles_by_account.append(sso.list_account_roles(token, a["accountId"]))
    return account_ids, account_names, roles_by_account


def _cache_dir_writable_error(cdir: Path) -> str | None:
    """Actually exercise the cache directory with a real write+delete,
    rather than assuming a successful cache_dir() (which only creates the
    directory) means later writes will succeed too. Returns an error
    message, or None if the probe write succeeded."""
    import os

    probe = cdir / f".ssobroker_doctor_probe_{os.getpid()}"
    try:
        probe.write_text("ok")
        probe.unlink()
    except OSError as e:
        return str(e)
    return None


@click.group()
@click.version_option(package_name="aws-sso-broker")
def main():
    """ssobroker — ephemeral AWS multi-account credential manager (IAM Identity Center)."""
    try:
        policy.load()
    except policy.PolicyError as e:
        print(f"ssobroker: {e}", file=sys.stderr)
        sys.exit(1)


@main.command()
def init():
    """Create ~/.ssobroker/orgs.yaml from the bundled example, if it doesn't exist yet."""
    dest = config.default_config_path()
    if dest.exists():
        console.print(f"[yellow]Already exists:[/yellow] {dest}")
        return
    example = Path(__file__).parent / "examples" / "orgs.example.yaml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(example, dest)
    console.print(f"[green]Created[/green] {dest} — edit it with your SSO start URL and accounts.")


@main.command()
@click.option(
    "--use-device-code",
    is_flag=True,
    help="Use the device-code flow (for machines with no local browser). "
    "Only approve a sign-in request you started yourself.",
)
def login(use_device_code: bool):
    """Log in via IAM Identity Center (opens a browser to sign in)."""
    cfg = _load_config_or_exit()
    token = _login_or_exit(cfg, "device_code" if use_device_code else None)
    console.print(f"[green]Logged in[/green] to '{cfg.name}' — token cached until expiry.")
    _ = token


@main.command("sync-aws-config")
@click.option(
    "--prefix",
    default="",
    help="Prefix prepended to every profile name (<prefix>-<alias>[-<role>]); "
    "default: none, so profiles are named after the account alias",
)
@click.option(
    "--all-roles",
    is_flag=True,
    help="Write one profile per role instead of just each account's default role "
    "(profiles named <alias>-<role>)",
)
@click.option(
    "--dry-run", is_flag=True, help="Show what would be written without touching the file"
)
def sync_aws_config(prefix: str, all_roles: bool, dry_run: bool):
    """Write credential_process profiles into ~/.aws/config for every account
    (and role, with --all-roles) in your registry.

    Existing profiles you didn't create with this tool, and any comments or
    formatting in the file, are left untouched. If the file changes, the
    previous version is first saved to a new timestamped ~/.aws/config.bak-*
    file (earlier backups are never overwritten).
    """
    cfg = _load_config_or_exit()
    try:
        written, skipped, conflicts, path, backup = aws_config_sync.sync(
            cfg, prefix=prefix, all_roles=all_roles, dry_run=dry_run
        )
    except ConfigError as e:
        console.print(f"[red]Config error:[/red] {e}")
        sys.exit(1)
    verb = "Would write" if dry_run else "Wrote"
    console.print(
        f"[green]{verb} {len(written)} profile(s)[/green] to {path}: {', '.join(sorted(written))}"
    )
    if skipped:
        console.print(
            f"[yellow]Skipped {len(skipped)} account(s) with multiple roles and no "
            f"default_role set:[/yellow] {', '.join(skipped)} (set default_role in orgs.yaml, "
            f"or pass --all-roles)"
        )
    if conflicts:
        console.print(
            f"[red]Left {len(conflicts)} profile(s) untouched — a section with that name "
            f"already exists and wasn't created by ssobroker:[/red] {', '.join(sorted(conflicts))} "
            f"(use --prefix to pick different profile names, or rename/remove the existing "
            f"section yourself first)"
        )
    if backup:
        console.print(f"[dim]Backup saved to {backup}[/dim]")


@main.command()
@click.option(
    "--local-only",
    is_flag=True,
    help="Only clear the local cache; don't sign the SSO session out at AWS.",
)
def logout(local_only: bool):
    """Sign out of Identity Center and clear all cached tokens and credentials.

    Role credentials issued earlier stay valid at AWS until they expire."""
    errors: list[str] = []
    if local_only:
        n = cache.clear()
    else:
        try:
            _prepare(config.load())
        except ConfigError:
            pass  # network settings are optional here; logout must still work
        n, errors = sso.logout()
    console.print(f"Cleared {n} cached entr{'y' if n == 1 else 'ies'}.")
    for err in errors:
        console.print(f"[yellow]Server-side sign-out failed ({err}); local cache cleared.[/yellow]")


@main.command()
def doctor():
    """Sanity-check config, cache dir, and guardrails file."""
    problems = []
    pol = policy.load()
    if pol.active:
        console.print(f"[green]OK[/green] managed policy applied: {pol.path}")
    else:
        console.print(f"[dim]NOTE no managed policy at {policy.managed_policy_path()}[/dim]")
    try:
        cfg = config.load()
        console.print(f"[green]OK[/green] config loaded: {cfg.name} ({len(cfg.accounts)} accounts)")
        console.print(
            f"[green]OK[/green] login flow: {cfg.login_flow}; role credential cache: "
            f"{cfg.role_credential_cache}; audit forwarding: "
            f"{', '.join(cfg.audit_forward) or 'off'}"
        )
    except ConfigError as e:
        problems.append(str(e))
        console.print(f"[red]FAIL[/red] config: {e}")

    cdir = cache.cache_dir()
    write_error = _cache_dir_writable_error(cdir)
    if write_error:
        problems.append(f"cache dir not writable: {write_error}")
        console.print(f"[red]FAIL[/red] cache dir not writable: {cdir} ({write_error})")
    else:
        console.print(f"[green]OK[/green] cache dir writable: {cdir}")

    gcfg_path = home_dir() / "guardrails.yaml"
    if gcfg_path.exists():
        console.print(f"[green]OK[/green] guardrails file present: {gcfg_path}")
    else:
        console.print("[yellow]NOTE[/yellow] no guardrails.yaml — using built-in defaults only")

    if problems:
        sys.exit(1)


@main.command()
@click.option("--tag", default=None, help="Only show accounts with this tag")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table")
def accounts(tag: str | None, as_json: bool):
    """List accounts from your local registry (orgs.yaml)."""
    cfg = _load_config_or_exit()
    matched = config.accounts_by_tag(cfg, tag)

    if as_json:
        import json

        print(
            json.dumps(
                [
                    {
                        "alias": a.alias,
                        "account_id": a.account_id,
                        "roles": a.roles,
                        "default_role": a.default_role,
                        "tags": a.tags,
                    }
                    for a in matched
                ],
                indent=2,
            )
        )
        return

    title = f"Accounts — {cfg.name}" + (f" (tag: {tag})" if tag else "")
    table = Table(title=title)
    table.add_column("Alias")
    table.add_column("Account ID")
    table.add_column("Roles")
    table.add_column("Default role")
    table.add_column("Tags")
    for acct in matched:
        table.add_row(
            acct.alias,
            acct.account_id,
            ", ".join(acct.roles) or "-",
            acct.default_role or "-",
            ", ".join(acct.tags) or "-",
        )
    console.print(table)
    if tag and not matched:
        console.print(f"[yellow]No accounts tagged '{tag}'.[/yellow]")


@main.command("list-remote")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table")
def list_remote(as_json: bool):
    """List accounts/roles actually granted to you right now via Identity Center."""
    cfg = _load_config_or_exit()
    token = _login_or_exit(cfg)
    account_ids, account_names, roles_by_account = _guard(_fetch_remote_accounts, token)

    if as_json:
        import json

        print(
            json.dumps(
                [
                    {"account_id": aid, "account_name": name, "roles": roles}
                    for aid, name, roles in zip(
                        account_ids, account_names, roles_by_account, strict=True
                    )
                ],
                indent=2,
            )
        )
        return

    table = Table(title="Accounts granted via Identity Center")
    table.add_column("Account ID")
    table.add_column("Account Name")
    table.add_column("Roles")
    for aid, name, roles in zip(account_ids, account_names, roles_by_account, strict=True):
        table.add_row(aid, name, ", ".join(roles))
    console.print(table)


@main.command("exec")
@click.option("--account", "-a", required=True, help="Account alias or ID from orgs.yaml")
@click.option("--role", "-r", default=None, help="Role name (falls back to account default)")
@click.option("--region", default=None, help="Override default region for this command")
@click.option("--yes", "-y", is_flag=True, help="Skip require-confirmation prompts")
@click.option(
    "--reason",
    default=None,
    help="Free-text justification (e.g. ticket #) recorded in the local audit log. "
    "NOT an AWS-side STS session tag — SSO's credential API doesn't support those.",
)
@click.option(
    "--check-action",
    default=None,
    help="Optional: IAM action (e.g. s3:DeleteObject) to pre-check against the role's "
    "identity-based policies before running. Advisory only — does not check SCPs.",
)
@click.option("--check-resource", default="*", help="Resource ARN for --check-action (default: *)")
@click.argument("command", nargs=-1, required=True)
def exec_command(
    account: str,
    role: str | None,
    region: str | None,
    yes: bool,
    reason: str | None,
    check_action: str | None,
    check_resource: str,
    command: tuple[str, ...],
):
    """Run COMMAND with short-lived credentials for --account/--role.

    \b
    Example:
      ssobroker exec -a prod -r read-only -- aws s3 ls
    """
    cfg = _load_config_or_exit()
    token = _login_or_exit(cfg)
    code = _guard(
        exec_cmd.run,
        cfg,
        token,
        account,
        role,
        list(command),
        region,
        assume_yes=yes,
        reason=reason,
        check_action=check_action,
        check_resource=check_resource,
    )
    sys.exit(code)


@main.command()
@click.option("--account", "-a", required=True, help="Account alias or ID from orgs.yaml")
@click.option("--role", "-r", default=None, help="Role name (falls back to account default)")
@click.option("--region", default=None, help="Override default region for this session")
@click.option(
    "--reason",
    default=None,
    help="Free-text justification recorded in the local audit log for this session.",
)
def shell(account: str, role: str | None, region: str | None, reason: str | None):
    """Spawn a subshell with credentials for --account/--role exported."""
    cfg = _load_config_or_exit()
    token = _login_or_exit(cfg)
    code = _guard(exec_cmd.spawn_shell, cfg, token, account, role, region, reason=reason)
    sys.exit(code)


@main.command("export-env")
@click.option("--account", "-a", required=True, help="Account alias or ID from orgs.yaml")
@click.option("--role", "-r", default=None, help="Role name (falls back to account default)")
@click.option("--region", default=None, help="Override default region")
@click.option("--powershell", is_flag=True, help="Emit $env: syntax instead of POSIX export")
@click.option(
    "--reason",
    default=None,
    help="Free-text justification recorded in the local audit log.",
)
def export_env(
    account: str, role: str | None, region: str | None, powershell: bool, reason: str | None
):
    """Print export statements for --account/--role, for use in your CURRENT
    shell — as opposed to `ssobroker shell`, which spawns a new one.

    \b
    Example:
      eval "$(ssobroker export-env -a prod -r admin)"
      # or, in PowerShell:
      ssobroker export-env -a prod -r admin --powershell | Invoke-Expression

    Useful inside scripts or CI steps that need the credentials in the shell
    they're already running in, rather than a child subshell.
    """
    cfg = _load_config_or_exit()
    token = _login_or_exit(cfg)
    lines = _guard(
        exec_cmd.export_env_lines,
        cfg,
        token,
        account,
        role,
        region,
        powershell=powershell,
        reason=reason,
    )
    print(lines)


@main.command("creds-process")
@click.option("--account", "-a", required=True, help="Account alias or ID from orgs.yaml")
@click.option("--role", "-r", default=None, help="Role name (falls back to account default)")
def creds_process(account: str, role: str | None):
    """AWS `credential_process` provider — emits clean JSON on stdout only.

    Wire this into ~/.aws/config so `aws`/`terraform`/boto3 work natively
    with --profile, no `ssobroker exec` wrapper needed:

    \b
      [profile prod]
      credential_process = ssobroker creds-process --account prod --role read-only

    All human-readable output (errors, the login URL if a fresh browser
    approval is needed) goes to stderr; stdout carries only the JSON
    document AWS tooling expects.
    """
    import json

    try:
        cfg = _prepare(config.load())
    except ConfigError as e:
        print(f"ssobroker config error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        token = _sso_login(cfg)
    except sso.SsoLoginError as e:
        print(f"ssobroker login failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        payload = exec_cmd.credential_process_payload(cfg, token, account, role)
    except (ConfigError, sso.SsoLoginError) as e:
        print(f"ssobroker error: {e}", file=sys.stderr)
        sys.exit(1)
    except guardrails.GuardrailBlocked as e:
        print(f"ssobroker: BLOCKED by guardrails: {e}", file=sys.stderr)
        sys.exit(2)

    # Writing the credentials to stdout is the credential_process protocol:
    # the calling AWS SDK/CLI reads them from this pipe. Nothing else is printed.
    print(json.dumps(payload))


@main.command()
@click.option("--account", "-a", required=True, help="Account alias or ID from orgs.yaml")
@click.option("--role", "-r", default=None, help="Role name (falls back to account default)")
def whoami(account: str, role: str | None):
    """Show the STS identity you'd get for --account/--role right now."""
    cfg = _load_config_or_exit()
    token = _login_or_exit(cfg)
    acct, resolved_role, creds = _guard(_resolve_and_get_creds, cfg, token, account, role)

    import boto3

    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=cfg.default_region,
    )
    identity = session.client("sts").get_caller_identity()
    table = Table(title=f"Identity — {acct.alias} ({resolved_role})")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Account", identity["Account"])
    table.add_row("Arn", identity["Arn"])
    table.add_row("UserId", identity["UserId"])
    console.print(table)


@main.command("check-policy")
@click.option("--account", "-a", required=True, help="Account alias or ID from orgs.yaml")
@click.option("--role", "-r", default=None, help="Role name (falls back to account default)")
@click.option("--action", required=True, help="IAM action to check, e.g. s3:DeleteObject")
@click.option("--resource", default="*", help="Resource ARN to check against (default: *)")
def check_policy(account: str, role: str | None, action: str, resource: str):
    """Ask the IAM policy simulator whether --role could perform --action.

    Identity-based policies only — this does NOT evaluate SCPs or
    resource-based policies, since AWS exposes no simulator API for those.
    Treat a pass here as necessary, not sufficient.
    """
    from . import policy_check

    cfg = _load_config_or_exit()
    token = _login_or_exit(cfg)
    _acct, _resolved_role, creds = _guard(_resolve_and_get_creds, cfg, token, account, role)

    try:
        role_arn = policy_check.resolve_role_arn(creds, cfg.default_region)
        result = policy_check.simulate(creds, role_arn, action, resource, cfg.default_region)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Check failed:[/red] {e}")
        sys.exit(1)

    color = "green" if result.allowed else "red"
    console.print(f"[{color}]{result.decision}[/{color}] — {action} on {resource}")
    if result.matched_statements:
        console.print(f"Matched policies: {', '.join(result.matched_statements)}")
    console.print(
        "[dim]Note: identity-based policies only — SCPs and resource policies "
        "are not evaluated by this check.[/dim]"
    )
    sys.exit(0 if result.allowed else 3)


@main.command()
@click.argument("shell_name", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell_name: str):
    """Print the shell-completion setup line for bash/zsh/fish."""
    var = f"_SSOBROKER_COMPLETE={shell_name}_source"
    console.print("Add this to your shell profile:\n")
    console.print(f'  eval "$({var} ssobroker)"')


@main.command("audit-log")
@click.option("-n", default=20, help="Number of recent entries to show")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table")
@click.option(
    "--push-cloudwatch",
    is_flag=True,
    help="Also push entries not yet sent to the CloudWatch Logs group set as "
    "'cloudwatch_log_group' in orgs.yaml, using the cloudwatch_account/cloudwatch_role "
    "logging role if set, else whatever credentials are active in this shell.",
)
def audit_log(n: int, as_json: bool, push_cloudwatch: bool):
    """Show recent entries from the local audit log."""
    entries = audit.tail(n)

    if as_json:
        import json

        print(json.dumps(entries, indent=2))
    elif not entries:
        console.print("No audit entries yet.")
    else:
        table = Table(title="Recent activity")
        table.add_column("Time (UTC)")
        table.add_column("Action")
        table.add_column("Account")
        table.add_column("Role")
        table.add_column("Result")
        table.add_column("Reason")
        table.add_column("Command")
        for e in entries:
            table.add_row(
                e.get("ts", "-"),
                e.get("action", "-"),
                e.get("account_id", "-"),
                e.get("role", "-"),
                e.get("result", "-"),
                e.get("reason") or "-",
                " ".join(e.get("command") or []),
            )
        console.print(table)

    if push_cloudwatch:
        cfg = _load_config_or_exit()
        if not cfg.cloudwatch_log_group:
            console.print(
                "[red]No 'cloudwatch_log_group' set in orgs.yaml — nothing to push to.[/red]"
            )
            sys.exit(1)
        try:
            provider = _logging_role_credentials(cfg)
            pushed = audit.push_to_cloudwatch(
                cfg.cloudwatch_log_group,
                cfg.default_region,
                credentials=provider() if provider else None,
            )
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]CloudWatch push failed:[/red] {e}")
            sys.exit(1)
        console.print(f"[green]Pushed {pushed} new entries[/green] to {cfg.cloudwatch_log_group}")


if __name__ == "__main__":
    main()
