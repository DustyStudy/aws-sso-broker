# Usage reference

Everything the [README](../README.md) leaves out: the full feature list,
the other install options, every command and the configuration files.

## Features

- **SSO-only sign-in that resists device-code phishing.** Uses the AWS SSO
  OIDC authorization-code grant with PKCE and a `127.0.0.1` redirect, the same
  flow `aws sso login` uses in AWS CLI v2.22+. Only a browser on the same
  machine can finish the sign-in, so a sign-in link sent to someone else gets
  an attacker nothing. Whether the sign-in itself is phishing-resistant in the
  OMB M-22-09 sense (FIDO2/WebAuthn or PIV) depends on the MFA your identity
  provider requires, not on ssobroker. The device-code flow is still there for
  headless machines (`login --use-device-code`) and can be turned off by an
  admin. There is no code path that accepts or stores a long-lived access key.
- **Account/role registry** (`orgs.yaml`): give your accounts human-friendly
  aliases instead of memorizing 12-digit IDs.
- **`ssobroker exec -a <account> -r <role> -- <command>`**: run a one-off AWS
  CLI (or any) command with the right credentials exported into that
  process's environment only.
- **`ssobroker shell -a <account> -r <role>`**: drop into a subshell with
  credentials exported. `SSOBROKER_ACTIVE_CONTEXT` holds `[alias:role]` so
  your prompt can show it. On Linux/macOS, `PS1` is set to that tag too when
  the parent shell didn't export one, but a shell that sets its own prompt in
  its startup file (most `.bashrc`/`.zshrc` do) replaces it. Windows shells get
  only the variable. To always see it, add it to your prompt, e.g.
  `PS1='${SSOBROKER_ACTIVE_CONTEXT:+$SSOBROKER_ACTIVE_CONTEXT }'"$PS1"` in
  `.bashrc`, or in your PowerShell `$PROFILE`
  `function prompt { "$env:SSOBROKER_ACTIVE_CONTEXT PS $PWD> " }`.
- **Local guardrails** (`guardrails.yaml`): optional deny-patterns and
  "protected account" list to stop an obviously wrong command (or a
  fat-fingered wrong terminal tab) before it reaches AWS. This is a client-side
  speed bump, not a replacement for IAM permission boundaries or SCPs.
  Deny and confirm patterns are checked by `exec` only, since it is the one
  command that sees the command line. Profiles that use `creds-process`
  (`aws --profile ...`, Terraform) get the protected-account check alone, and
  only with `strict_protected_accounts: true`.
- **Audit log** (`~/.ssobroker/audit.log`): every `exec`/`shell`/`export-env`
  invocation, and every `creds-process` call that gets new credentials, is
  appended as a JSON line: who, when, which account/role, what command, and
  the temporary `AccessKeyId` (the join key to CloudTrail). Secret-looking
  arguments (`--secret-string`, `--password=...`, `DB_PASSWORD=...`) are
  redacted first. Local-only by default; `audit_forward` also sends each
  entry to syslog, the Windows Event Log, or CloudWatch Logs.
- **Nothing persisted insecurely.** Cached tokens/credentials live under
  `~/.ssobroker/cache` with owner-only permissions and their own expiry check on
  every read. Cached role credentials are tied to the SSO session that
  fetched them, are refreshed when under 5 minutes remain, and can be kept in
  the OS keychain or not cached at all (`role_credential_cache`).
- **Finds credentials infostealers look for** (`ssobroker doctor`): warns
  about long-lived access keys in `~/.aws/credentials` and unexpired or
  refresh-capable AWS CLI SSO tokens in `~/.aws/sso/cache/`, the files
  commodity infostealers copy. Prints names, counts and expiry only;
  `--strict` fails the check. See threat scenario 9 in
  [THREAT_MODEL.md](THREAT_MODEL.md).
- **Machine policy** (`/etc/ssobroker/policy.yaml`,
  `%ProgramData%\ssobroker\policy.yaml`): pin the allowed Identity Center
  start URLs, cap session length, add guardrails, turn off device-code sign-in
  and environment-variable overrides. It can only tighten a user's settings.
  See [docs/HARDENING.md](HARDENING.md).
- **Proxies and FIPS endpoints**: `ca_bundle`, `https_proxy` and `use_fips_endpoint`
  in `orgs.yaml`.
- **Native `credential_process` support** (`ssobroker creds-process`): wire it
  into `~/.aws/config` and `aws`/`terraform`/boto3 work with plain
  `--profile`, no wrapper needed.
- **Configurable session cap** (`max_session_hours`): force re-auth sooner
  than the SSO token's own expiry, independent of what your org issues.
- **Advisory IAM policy pre-check** (`ssobroker check-policy`, `--check-action`
  on `exec`): ask the IAM policy simulator whether a role's identity-based
  policies allow an action before you rely on it. Does not evaluate SCPs or
  resource policies (AWS exposes no simulator API for those).
- **Shell completion**: `ssobroker completion bash|zsh|fish`.
- **`ssobroker whoami`**: quick STS identity check for an account/role.
- **CI on every push/PR**: ruff lint + format check, mypy, pytest on
  Linux, Windows and macOS across Python 3.11-3.13.
- **Verifiable releases**: every release attaches the wheel, sdist, a
  hash-locked `runtime-requirements.txt` and a CycloneDX SBOM, each with a
  signed build-provenance attestation (`gh attestation verify`).
- **Typed**: ships a `py.typed` marker; mypy-checked in CI.
- **`ssobroker sync-aws-config`**: writes a `credential_process` profile into
  `~/.aws/config` for every account (or every account/role with
  `--all-roles`) in your registry. Backs up the existing file before
  changing it and never touches profiles (or comments) it didn't create.
- **OS keychain for SSO tokens**: with the `keyring` extra installed and a
  working backend (macOS Keychain, Windows Credential Manager, Secret
  Service/KWallet), the SSO token itself is stored there instead of a plain
  file. Falls back to the existing 0600-file cache automatically when no
  backend is available. `role_credential_cache: keyring` puts role
  credentials there too (and caches nothing if no keychain is available).
- **`--json` output** on `accounts`, `list-remote`, and `audit-log`: for
  piping into `jq` or other tooling.
- **`ssobroker export-env`**: prints `export AWS_...` (or `--powershell`
  `$env:...`) lines for `eval "$(ssobroker export-env -a prod -r admin)"` in
  your *current* shell, as an alternative to `ssobroker shell`'s subshell,
  useful in scripts and CI steps.
- **Session-expiry heads-up**: `ssobroker shell` prints how long the
  credentials have left, and a warning if it's under 15 minutes.
  `ssobroker shell --refresh` keeps them fresh instead (see below).

## Install options

The README covers the verified release and pipx.

### From source

```bash
git clone https://github.com/DustyStudy/aws-sso-broker.git
cd aws-sso-broker
python3 -m pip install -e .
```

### Homebrew

A formula isn't published yet; once there's a tagged release, a
`Formula/ssobroker.rb` pulling from the release tarball can be added to a
personal tap (`brew tap DustyStudy/aws-sso-broker && brew install ssobroker`). Tracked as a
follow-up; pipx is the easiest path in the meantime.

### OS keychain for SSO tokens (optional)

```bash
python3 -m pip install -e ".[keyring]"
```

With this installed and a working backend (macOS Keychain, Windows
Credential Manager, Secret Service/KWallet on Linux), the SSO token is
stored there instead of a plain file under `~/.ssobroker/cache`. If no backend
is available (common on headless Linux), `ssobroker` automatically falls back
to the existing file-based cache; nothing else changes.

### Shell completion

```bash
ssobroker completion bash   # or zsh / fish
```

prints the line to add to your shell profile (built on Click's native
completion support; no extra dependency).

### Upgrading from orgctl

This project was previously named `orgctl`. After reinstalling, the command
is `ssobroker`. An existing `~/.orgctl` directory keeps being used until a
`~/.ssobroker` directory exists, so your registry, guardrails and audit log
carry over. Environment overrides are now `SSOBROKER_HOME`,
`SSOBROKER_CONFIG` and `SSOBROKER_GUARDRAILS`. Run `ssobroker login` once
(the keychain entry is stored under the new name), then re-run
`ssobroker sync-aws-config`: profiles written by orgctl are recognised and
rewritten to call `ssobroker`.

This compatibility is deprecated and will be removed in a future release.
Move `~/.orgctl` to `~/.ssobroker` and re-run `sync-aws-config` now;
`ssobroker doctor` reports it while the old folder is still in use.

## Commands

```bash
# Use as a native AWS credential provider, no `ssobroker exec` wrapper needed.
# Add to ~/.aws/config:
#   [profile prod]
#   credential_process = ssobroker creds-process --account prod --role read-only
ssobroker creds-process -a prod -r read-only

# Quick "who am I right now" check for an account/role
ssobroker whoami -a prod -r read-only

# Filter your registry by tag
ssobroker accounts --tag security

# Attach a justification to a command or session (recorded in the local
# audit log only; see note below on why this isn't an AWS-side session tag)
ssobroker exec -a prod -r admin --reason "rotate KMS key" -- terraform apply
ssobroker shell -a prod -r admin --reason "check billing alarm"

# Advisory pre-check: would this role's identity-based policies allow an
# action, before you actually run something relying on it
ssobroker exec -a prod -r deploy --check-action s3:DeleteObject --check-resource "arn:aws:s3:::my-bucket/*" -- ./destroy.sh
ssobroker check-policy -a prod -r deploy --action s3:DeleteObject --resource "arn:aws:s3:::my-bucket/*"

# Push audit-log entries not yet sent to CloudWatch Logs (requires
# cloudwatch_log_group in orgs.yaml; uses the cloudwatch_account/role logging
# role if set, else whatever credentials are active in this shell)
ssobroker audit-log --push-cloudwatch

# Sign out at AWS and clear every cached token and credential
ssobroker logout

# One-time setup: write a credential_process profile into ~/.aws/config
# for every account (one per account by default; --all-roles for one
# profile per account/role instead). Then just use --profile like normal.
ssobroker sync-aws-config
aws --profile prod s3 ls

# Get credentials into your CURRENT shell instead of spawning a subshell,
# handy in scripts/CI steps that need to keep running in the same process
eval "$(ssobroker export-env -a prod -r admin)"
# PowerShell:
ssobroker export-env -a prod -r admin --powershell | Invoke-Expression

# JSON output for scripting
ssobroker accounts --json | jq '.[] | .alias'
ssobroker audit-log --json -n 50 | jq '.[] | select(.result == "blocked")'
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
later run can tell "ssobroker created this" apart from "this profile name
already existed." If a profile name from your registry collides with a
section you already had (from `aws configure`, hand-editing, etc.), that
section is left completely alone and reported back as a conflict; nothing
about it is overwritten. The file is edited in place as text, so comments,
formatting, and every other profile are preserved exactly as you wrote them.
If a run changes the file, the previous version is first saved as a new
timestamped `~/.aws/config.bak-<stamp>` (earlier backups are never
overwritten); a re-run that changes nothing writes nothing. `--prefix sso`
names profiles `sso-<alias>` (`sso-<alias>-<role>` with `--all-roles`), and
two registry entries that would map to the same profile name are rejected
rather than one silently winning. ssobroker doesn't delete profiles it wrote
earlier unless you pass `--prune`, which removes every ssobroker-written
profile this run would not write: accounts dropped from `orgs.yaml`, or
profiles from an earlier `--prefix`/`--all-roles` choice. Combine it with
`--dry-run` to see the list first. Re-run it any time your `orgs.yaml` changes.

`--python-launcher` writes `"<this python>" -m ssobroker creds-process ...`
instead of `ssobroker creds-process ...`. Use it where the `ssobroker`
launcher is blocked (Windows Smart App Control) or not on the `PATH` that
`aws`/`terraform` see.

**On `shell --refresh`:** by default `shell` exports one set of credentials,
which stop working when they expire. With `--refresh`, the subshell instead
gets a temporary AWS config with one profile whose `credential_process` is
`ssobroker creds-process`, and `AWS_PROFILE` pointing at it. The AWS CLI, the
SDKs and Terraform then fetch new credentials themselves as the old ones run
out. Tools that only read `AWS_ACCESS_KEY_ID` from the environment get no
credentials in that mode, and your own `~/.aws/config` profiles aren't
visible inside it. The temporary file holds no secret and is deleted when
the shell exits.

**On `export-env`:** it prints the same environment `exec` gives its child:
it first unsets `AWS_PROFILE`, `AWS_ROLE_ARN` and the other variables that
could mix in a different identity, then sets the keys, the region and
`AWS_CREDENTIAL_EXPIRATION`.

**On the audit log:** `exec`, `shell`, `export-env`, `whoami`, `check-policy`,
`creds-process` (when it gets new credentials) and the CloudWatch logging
role (`audit-forward`, when it gets new credentials) each write an entry.
Commands typed inside a `shell` are not logged one by one; CloudTrail has
those. Past 10 MB the log is renamed to `audit.log.<UTC timestamp>.<pid>`
and a new one started. Rotated files are kept. With CloudWatch forwarding
on, the log is only rotated once every entry in it has been sent.

## Configuration

### `~/.ssobroker/orgs.yaml`

See [`src/ssobroker/examples/orgs.example.yaml`](../src/ssobroker/examples/orgs.example.yaml). No secrets live
here: just your Identity Center start URL/region and a map of aliases to
account IDs and role names. Two optional top-level fields:

- `max_session_hours` (default 8): force a fresh browser login after this
  many hours, independent of the SSO token's own server-side expiry.
- `cloudwatch_log_group`: set this to enable `ssobroker audit-log --push-cloudwatch`
  and `audit_forward: [cloudwatch]`. A cursor file next to the log remembers
  what was already sent, so each entry is pushed once (two processes pushing
  at the same moment can still both send an entry).

Other optional settings, all shown in the example file: `login_flow`,
`role_credential_cache`, `audit_redact_flags`, `audit_forward`,
`cloudwatch_account`/`cloudwatch_role`, `ca_bundle`, `https_proxy` and
`use_fips_endpoint`.

### `~/.ssobroker/guardrails.yaml` (optional)

See [`config/guardrails.example.yaml`](../config/guardrails.example.yaml). Lets
you mark accounts as protected (block all ad-hoc commands) and add
deny/require-confirmation glob patterns on top of the built-in defaults
(blocks things like `organizations leave-organization`, `close-account`,
recursive `s3 rm`, etc.).

### Machine policy (optional)

See [`config/policy.example.yaml`](../config/policy.example.yaml) and
[docs/HARDENING.md](HARDENING.md).
