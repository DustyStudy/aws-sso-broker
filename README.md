# orgctl

[![CI](https://github.com/DustyStudy/aws-orgctl/actions/workflows/ci.yml/badge.svg)](https://github.com/DustyStudy/aws-orgctl/actions/workflows/ci.yml)
[![CodeQL](https://github.com/DustyStudy/aws-orgctl/actions/workflows/codeql.yml/badge.svg)](https://github.com/DustyStudy/aws-orgctl/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/DustyStudy/aws-orgctl/badge)](https://securityscorecards.dev/viewer/?uri=github.com/DustyStudy/aws-orgctl)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Ephemeral AWS multi-account credential manager, built on IAM Identity Center (SSO).**

No long-lived access keys. No static credentials sitting in `~/.aws/credentials`.
Log in once via your org's Identity Center portal, then run commands or open a
shell against any account/role you're granted, with short-lived, auto-expiring
credentials and a local audit trail.

## Why

Most teams either hand out long-lived IAM user keys (bad) or make people
click through the AWS SSO web console and copy-paste temporary credentials
by hand every hour (annoying). `orgctl` automates the second option: it
drives the same Identity Center device-authorization flow the console uses,
caches the resulting short-lived credentials locally, and exposes a simple
CLI (`exec`, `shell`) for using them.

## Features

- **SSO-only.** Uses the AWS SSO OIDC device-authorization grant, the same
  flow the `aws sso login` CLI command uses. There is no code path that
  accepts or stores a long-lived access key.
- **Account/role registry** (`orgs.yaml`): give your accounts human-friendly
  aliases instead of memorizing 12-digit IDs.
- **`orgctl exec -a <account> -r <role> -- <command>`**: run a one-off AWS
  CLI (or any) command with the right credentials exported into that
  process's environment only.
- **`orgctl shell -a <account> -r <role>`**: drop into a subshell with
  credentials exported, prompt tagged with the active account/role so you
  always know where you are.
- **Local guardrails** (`guardrails.yaml`): optional deny-patterns and
  "protected account" list to stop an obviously wrong command (or a
  fat-fingered wrong terminal tab) before it reaches AWS. This is a client-side
  speed bump, not a replacement for IAM permission boundaries or SCPs.
- **Local audit log** (`~/.orgctl/audit.log`): every `exec`/`shell` invocation
  is appended as a JSON line: who, when, which account/role, what command.
  Never uploaded anywhere; it's for your own review.
- **Nothing persisted insecurely.** Cached tokens/credentials live under
  `~/.orgctl/cache` with owner-only permissions and their own expiry check on
  every read.
- **Native `credential_process` support** (`orgctl creds-process`): wire it
  into `~/.aws/config` and `aws`/`terraform`/boto3 work with plain
  `--profile`, no wrapper needed.
- **Configurable session cap** (`max_session_hours`): force re-auth sooner
  than the SSO token's own expiry, independent of what your org issues.
- **Advisory IAM policy pre-check** (`orgctl check-policy`, `--check-action`
  on `exec`): ask the IAM policy simulator whether a role's identity-based
  policies allow an action before you rely on it. Does not evaluate SCPs or
  resource policies (AWS exposes no simulator API for those).
- **Shell completion**: `orgctl completion bash|zsh|fish`.
- **`orgctl whoami`**: quick STS identity check for an account/role.
- **CI on every push/PR**: ruff lint + format check, mypy, pytest across
  Python 3.11/3.12.
- **Typed**: ships a `py.typed` marker; mypy-checked in CI.
- **`orgctl sync-aws-config`**: writes a `credential_process` profile into
  `~/.aws/config` for every account (or every account/role with
  `--all-roles`) in your registry. Backs up the existing file before
  changing it and never touches profiles (or comments) it didn't create.
- **OS keychain for SSO tokens**: with the `keyring` extra installed and a
  working backend (macOS Keychain, Windows Credential Manager, Secret
  Service/KWallet), the SSO token itself is stored there instead of a plain
  file. Falls back to the existing 0600-file cache automatically when no
  backend is available.
- **`--json` output** on `accounts`, `list-remote`, and `audit-log`: for
  piping into `jq` or other tooling.
- **`orgctl export-env`**: prints `export AWS_...` (or `--powershell`
  `$env:...`) lines for `eval "$(orgctl export-env -a prod -r admin)"` in
  your *current* shell, as an alternative to `orgctl shell`'s subshell,
  useful in scripts and CI steps.
- **Session-expiry heads-up**: `orgctl shell` prints how long the
  credentials have left, and a warning if it's under 15 minutes.

## Install

```bash
git clone https://github.com/DustyStudy/aws-orgctl.git
cd aws-orgctl
python3 -m pip install -e .
```

### pipx (recommended for CLI-only use)

If you just want the `orgctl` command available globally without managing a
virtualenv yourself:

```bash
pipx install git+https://github.com/DustyStudy/aws-orgctl.git
```

### Homebrew

A formula isn't published yet; once there's a tagged release, a
`Formula/orgctl.rb` pulling from the release tarball can be added to a
personal tap (`brew tap DustyStudy/aws-orgctl && brew install orgctl`). Tracked as a
follow-up; pipx is the easiest path in the meantime.

### OS keychain for SSO tokens (optional)

```bash
python3 -m pip install -e ".[keyring]"
```

With this installed and a working backend (macOS Keychain, Windows
Credential Manager, Secret Service/KWallet on Linux), the SSO token is
stored there instead of a plain file under `~/.orgctl/cache`. If no backend
is available (common on headless Linux), `orgctl` automatically falls back
to the existing file-based cache; nothing else changes.

### Shell completion

```bash
orgctl completion bash   # or zsh / fish
```

prints the line to add to your shell profile (built on Click's native
completion support; no extra dependency).

## Quick start

```bash
# 1. Create your local account registry from the example
orgctl init
$EDITOR ~/.orgctl/orgs.yaml   # add your SSO start URL + account IDs/roles

# 2. Sanity-check everything
orgctl doctor

# 3. Log in (opens your browser for Identity Center approval)
orgctl login

# 4. See what's in your registry
orgctl accounts

# 5. See what Identity Center actually grants you right now
orgctl list-remote

# 6. Run something
orgctl exec -a prod -r read-only -- aws s3 ls

# 7. Or work interactively
orgctl shell -a prod -r read-only
```

## More commands

```bash
# Use as a native AWS credential provider, no `orgctl exec` wrapper needed.
# Add to ~/.aws/config:
#   [profile prod]
#   credential_process = orgctl creds-process --account prod --role read-only
orgctl creds-process -a prod -r read-only

# Quick "who am I right now" check for an account/role
orgctl whoami -a prod -r read-only

# Filter your registry by tag
orgctl accounts --tag security

# Attach a justification to a command or session (recorded in the local
# audit log only; see note below on why this isn't an AWS-side session tag)
orgctl exec -a prod -r admin --reason "JIRA-1234" -- terraform apply
orgctl shell -a prod -r admin --reason "JIRA-1234"

# Advisory pre-check: would this role's identity-based policies allow an
# action, before you actually run something relying on it
orgctl exec -a prod -r deploy --check-action s3:DeleteObject --check-resource "arn:aws:s3:::my-bucket/*" -- ./destroy.sh
orgctl check-policy -a prod -r deploy --action s3:DeleteObject --resource "arn:aws:s3:::my-bucket/*"

# Push recent audit-log entries to CloudWatch Logs (requires
# cloudwatch_log_group set in orgs.yaml and logs:PutLogEvents on whatever
# credentials are active in this shell)
orgctl audit-log --push-cloudwatch

# One-time setup: write a credential_process profile into ~/.aws/config
# for every account (one per account by default; --all-roles for one
# profile per account/role instead). Then just use --profile like normal.
orgctl sync-aws-config
aws --profile prod s3 ls

# Get credentials into your CURRENT shell instead of spawning a subshell,
# handy in scripts/CI steps that need to keep running in the same process
eval "$(orgctl export-env -a prod -r admin)"
# PowerShell:
orgctl export-env -a prod -r admin --powershell | Invoke-Expression

# JSON output for scripting
orgctl accounts --json | jq '.[] | .alias'
orgctl audit-log --json -n 50 | jq '.[] | select(.result == "blocked")'
```

**On `--reason`:** recorded in your local audit log only. AWS SSO's
`GetRoleCredentials` API (what this tool uses to fetch short-lived
credentials) has no session-tagging parameter; real STS session tags
require a direct `sts:AssumeRole` call against a role ARN instead. So this
is a local justification trail, not an AWS-side session tag.

**On `--check-action`/`check-policy`:** calls `iam:SimulatePrincipalPolicy`
against the role's identity-based policies only. AWS exposes no API that
simulates Service Control Policies or resource-based policies, so a passing
result here is necessary but not sufficient; a real SCP can still deny the
call. Treat it as a fast local sanity check, not a guarantee.

**On `sync-aws-config`:** each section it writes is tagged internally so a
later run can tell "orgctl created this" apart from "this profile name
already existed." If a profile name from your registry collides with a
section you already had (from `aws configure`, hand-editing, etc.), that
section is left completely alone and reported back as a conflict; nothing
about it is overwritten. The file is edited in place as text, so comments,
formatting, and every other profile are preserved exactly as you wrote them.
If a run changes the file, the previous version is first saved as a new
timestamped `~/.aws/config.bak-<stamp>` (earlier backups are never
overwritten); a re-run that changes nothing writes nothing. `--prefix corp`
names profiles `corp-<alias>` (`corp-<alias>-<role>` with `--all-roles`), and
two registry entries that would map to the same profile name are rejected
rather than one silently winning. Orgctl doesn't delete profiles it wrote
earlier, so if you change `--prefix`/`--all-roles`, remove the old
orgctl-managed sections yourself. Re-run it any time your `orgs.yaml` changes.

## Configuration

### `~/.orgctl/orgs.yaml`

See [`config/orgs.example.yaml`](config/orgs.example.yaml). No secrets live
here: just your Identity Center start URL/region and a map of aliases to
account IDs and role names. Two optional top-level fields:

- `max_session_hours` (default 8): force a fresh browser login after this
  many hours, independent of the SSO token's own server-side expiry.
- `cloudwatch_log_group`: set this to enable `orgctl audit-log --push-cloudwatch`.
  Each push resends the last `n` local entries with no "since last push"
  tracking, so calling it repeatedly with overlapping history produces
  duplicate CloudWatch events: push right after each command, or dedupe
  downstream, if that matters for your use case.

### `~/.orgctl/guardrails.yaml` (optional)

See [`config/guardrails.example.yaml`](config/guardrails.example.yaml). Lets
you mark accounts as protected (block all ad-hoc commands) and add
deny/require-confirmation glob patterns on top of the built-in defaults
(blocks things like `organizations leave-organization`, `close-account`,
recursive `s3 rm`, etc.).

## Security model

- Credentials are always short-lived (from AWS SSO's `GetRoleCredentials`),
  scoped to exactly the account/role requested, and expire on their own.
- `exec` and `shell` never touch the parent shell's own environment:
  credentials exist only in the memory of the one child process/subshell
  spawned for that command. `export-env` and `creds-process` are the
  deliberate exceptions: printing credentials to stdout (for `eval` into
  your *current* shell, or for AWS tooling's `credential_process` protocol)
  is their whole point, not a leak; see the notes on them above.
- `orgctl logout` clears every cached token/credential immediately.
- Guardrails and the audit log are local-only conveniences, not a substitute
  for IAM permission boundaries, SCPs, or CloudTrail.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full breakdown:
assets, trust boundaries, per-scenario mitigations and residual risk, and
what's explicitly out of scope.

## Proof

Run for real against a real IAM Identity Center instance: login, both
guardrail types, audit logging, `sync-aws-config`, and `logout` all
verified against AWS's own responses. Unlike this tool's earlier fix
rounds, this pass found nothing broken. See [`docs/PROOF.md`](docs/PROOF.md).

## Development

```bash
python3 -m pip install -e ".[dev]"
ruff check src tests
ruff format src tests
mypy src
pytest -v --cov=orgctl --cov-report=term-missing
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow (including
optional `pre-commit` hooks) and [SECURITY.md](.github/SECURITY.md) for
the vulnerability-reporting process and which areas get the most scrutiny.

## License

MIT, see [LICENSE](LICENSE).
