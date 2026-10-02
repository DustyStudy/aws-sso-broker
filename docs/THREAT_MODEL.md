# Threat model

This document walks through what `ssobroker` protects, who the relevant actors
are, and — for each threat scenario considered — what mitigates it and what
residual risk is left over. It's meant to complement, not repeat,
[`SECURITY.md`](../.github/SECURITY.md) (vulnerability reporting, code areas
under review, CI/CD supply-chain hardening) and the README's "Security
model" section (the one-paragraph summary). This is the longer version: the
reasoning behind that summary, spelled out scenario by scenario.

Threat modeling is only useful if it's kept honest, so this document is
written from the position that `ssobroker` is a **convenience and friction
layer on top of AWS SSO**, not a security boundary in itself. Every
mitigation described below assumes IAM, SCPs, and Identity Center's own
controls are doing the actual enforcement — `ssobroker` just tries not to make
things worse, and to add friction/visibility on top.

## Assets

What this tool has custody of, at some point, and what protecting it means:

| Asset | Where it lives | What "protected" means |
|---|---|---|
| SSO access token and refresh token | OS keychain (preferred) or `~/.ssobroker/` cache file (fallback) | Not written to disk in plaintext when a keychain is available; 0600 permissions and expiry-checked reads when it isn't |
| Short-lived role credentials (`AccessKeyId`/`SecretAccessKey`/`SessionToken`) | Same cache, keyed per account+role | Same as above, plus never exported outside the one child process/shell that requested them — except via `export-env`/`creds-process`, whose whole purpose is printing them to stdout for the caller's own use (see scenario 4) |
| `orgs.yaml` (account registry) | `~/.ssobroker/orgs.yaml` (or `SSOBROKER_CONFIG`) | Contains account IDs and role names only — no secrets — but is still the map an attacker would want to see, and its contents drive which guardrails apply |
| `guardrails.yaml` | `~/.ssobroker/guardrails.yaml` (or `SSOBROKER_GUARDRAILS`) | Governs which commands get blocked/confirmed — its integrity matters more than its confidentiality |
| `policy.yaml` (admin-managed, optional) | `/etc/ssobroker/` or `%ProgramData%\ssobroker\` | Written only by root/Administrators; can only tighten user settings, never loosen them or supply a start URL |
| Local audit log | `~/.ssobroker/audit.log` (or `SSOBROKER_HOME`) | A record of what was run against which account, for the operator's own review; append-only in practice, not append-only *enforced* (see below) |
| `~/.aws/config` profiles written by `sync-aws-config` | Standard AWS config location | Must not silently absorb or overwrite a profile the tool didn't create |

## Actors and trust boundaries

- **The operator** (you, running the CLI) — fully trusted. `ssobroker` assumes
  whoever is running it on the local machine is authorized to act as
  themselves; it does no local authentication of its own beyond what the OS
  session already provides.
- **AWS IAM Identity Center** — trusted as the source of truth for
  identity and for issuing credentials. `ssobroker` never second-guesses an
  Identity Center authorization decision; it only adds *pre*-AWS friction
  (guardrails) and *post*-hoc local logging (audit log).
- **Anyone else with access to the same machine/account** (a second local
  user, malware, another process running as the same OS user) — explicitly
  **not** trusted, and is the actor most of the scenarios below are about.
- **A person who can modify this repository's source or its published
  package** (a compromised maintainer account, a malicious PR that gets
  merged, a compromised PyPI upload if this is ever published there) —
  covered separately by `SECURITY.md`'s CI/CD supply-chain section
  (SHA-pinned actions, harden-runner, branch protection); not duplicated
  here.

## Threat scenarios

### 1. Laptop is lost, stolen, or accessed by someone else while unlocked

**Threat:** an attacker with filesystem access wants long-lived or
long-enough-to-matter AWS access.

**Mitigation:** there is no long-lived credential to steal in the first
place — every credential `ssobroker` handles comes from `GetRoleCredentials`
and expires on its own (typically ~1 hour for role credentials, up to
`max_session_hours` for the SSO token itself). When a keychain backend is
available, the SSO token isn't even on disk in a form the attacker can
read without also compromising the OS-level keychain protections (e.g. the
user's login password, on most desktop keychains). When it isn't (headless
Linux with no keychain, `keyring` extra not installed), the fallback cache
file is created 0600 and every read checks expiry before trusting it.

**Residual risk:** if the attacker gets the disk *and* an unlocked session
(or the keychain unlock secret) within the credential's remaining lifetime,
they get exactly what the legitimate operator could have gotten — same
account, same role, until expiry. This is inherent to any tool that caches
credentials locally at all, not something a config change in `ssobroker`
fixes; it's why `max_session_hours` exists (force re-auth sooner than AWS's
own token expiry) and why `ssobroker logout` clearing the cache immediately is
part of the documented incident-response step. The cached refresh token
only works until `max_session_hours` after the original sign-in and while
the Identity Center session is valid. `logout` also calls the SSO
portal's `Logout` API, so the stolen SSO access and refresh tokens stop
working at AWS, not just locally. Role credentials already issued stay valid until they expire;
`role_credential_cache: keyring` (or `none`) keeps them off disk, and cached
ones are only reused under the SSO session that fetched them.

### 2. A malicious or careless command is run against the wrong account

**Threat:** the classic "wrong terminal tab" incident — an operator (or an
agent/script driving this CLI) runs a destructive command intending one
account and hits another, or runs something destructive on purpose without
realizing the blast radius.

**Mitigation:** `guardrails.py`'s deny-patterns, protected-account-ids, and
require-confirmation-patterns catch the known-bad shapes (leaving an org,
closing an account, recursive `s3 rm`, etc.) before the command ever
reaches AWS, and the optional `--check-action`/`check-policy` pre-check can
flag when a command would be denied by the role's own identity-based
policy anyway.

**Residual risk — and this is the important one:** guardrails are
pattern-matched (`fnmatch` globs) against the literal command string. They
are trivially bypassed by rephrasing the same command (a different flag
order, an alias, a wrapper script, `aws s3api` instead of `aws s3`). This
is **by design, not an oversight** — see "Explicitly out of scope" below —
but it means guardrails should be read as "catches the accidental case,"
not "prevents the determined case." The actual enforcement boundary for
"this role cannot do X" has to be an IAM permission boundary or SCP, full
stop. The code, the README, and `SECURITY.md` all say this in three
different words; this document is the fourth.

### 3. `orgs.yaml` or `guardrails.yaml` is tampered with

**Threat:** a second local process, a malicious dependency in an unrelated
project the operator also runs, or a synced-dotfiles mistake modifies
either config file — e.g. removing a `protected_account_ids` entry, adding
a deny-pattern that's actually a decoy, or pointing `sso_start_url` at an
attacker-controlled Identity Center instance.

**Mitigation:** both files are loaded fresh on every command (no
in-memory trust carried across invocations), and `yaml.safe_load` is used
throughout — no arbitrary object construction or code execution via a
crafted YAML file, unlike `yaml.load` with the default loader.
`sso_start_url` must be `https://`. When an admin deploys the managed
policy (`policy.yaml`, writable only by root/Administrators),
`allowed_sso_start_urls` pins which Identity Center instances may be used,
its guardrails are added on top of the user's file and can't be removed
from it, and `ignore_env_overrides` stops `SSOBROKER_GUARDRAILS` /
`SSOBROKER_CONFIG` / `SSOBROKER_HOME` from pointing ssobroker at
attacker-chosen files. On POSIX a policy file not owned by root, or
writable by group/other, is refused.

**Residual risk:** neither file is integrity-checked (no signature, no
checksum pinned elsewhere) — if an attacker can write to
`~/.ssobroker/*.yaml`, they can silently change guardrail behavior or, more
seriously, redirect `sso_start_url`/`sso_region` to an attacker-controlled
endpoint and phish the operator's next sign-in. This
requires local write access to the operator's home directory already,
which is a fairly high bar (roughly equivalent to "attacker already has
code execution as this user"), but it's worth naming explicitly rather
than leaving implicit. Without a managed policy this still holds. Anyone deploying `ssobroker`
fleet-wide should deploy `policy.yaml` with `allowed_sso_start_urls` and
`ignore_env_overrides` (see [ENTERPRISE.md](ENTERPRISE.md)). On Windows the
policy's protection depends on the folder ACL the admin sets.

### 4. Credentials leak out of the intended child process

**Threat:** short-lived role credentials end up somewhere they shouldn't —
shell history, a subprocess the operator didn't intend to grant them to,
or the parent shell's own environment.

**Mitigation:** for `exec`/`shell`, `exec_cmd._creds_to_env()` builds a
**copy** of the environment (`os.environ.copy()`), so the parent shell's
own `os.environ` is never mutated — credentials exist only in the memory of
the one `subprocess.run()` child. `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, web-identity and container-credential
variables are explicitly stripped from that copy so no other credential
source configured in the parent shell can get picked up by mistake
alongside the short-lived creds. `subprocess.run()` is
called with a list (`command`), never `shell=True` with a joined string —
so there's no shell-injection surface from account aliases, role names, or
arguments containing shell metacharacters.

`export-env` and `creds-process` are a deliberate exception to "stays in
one child process" — printing credentials to stdout is their entire
purpose (`eval`-ing into the *current* shell, or feeding AWS tooling's
`credential_process` protocol), not a leak. What they still guard against:
`export_env_lines()` quotes every value before interpolating it into the
printed `export KEY=value` / `$env:KEY = "value"` line (`shlex.quote()` on
POSIX; on PowerShell, backtick-escaping of the backtick, `$`, `"` and the
typographic quotes `“ ” „`, which PowerShell also treats as string
delimiters. Hypothesis property tests in `tests/test_properties.py`
check both for arbitrary input), so a value containing a
shell metacharacter can't break out of its assignment when the caller
`eval`s the output; `creds-process` writes human-readable errors and the
login URL to stderr only, keeping stdout clean JSON for the AWS SDK/CLI to
parse.

**Residual risk:** once credentials are in a child process's environment,
`ssobroker` has no control over what that child process (or anything *it*
spawns) does with them — a command that itself echoes `$AWS_SECRET_ACCESS_KEY`
to a log file, or a `ssobroker shell` session where the operator runs
something that dumps `env`, is the operator's own action at that point, not
something this tool can prevent from inside `exec_cmd.py`. `spawn_shell`'s
subshell prompt tag (`[account:role]`) is a mitigation for the *adjacent*
risk — forgetting *which* context you're in — not for env-leakage itself.

### 5. `sync-aws-config` overwrites a profile it didn't create

**Threat:** a profile name collision between `orgs.yaml` and something the
operator already had in `~/.aws/config` (hand-written, from `aws
configure`, from another tool) results in silent data loss or, worse, a
`credential_process` pointing somewhere unexpected.

**Mitigation:** fixed as of the per-section managed-marker change (see
`aws_config_sync.py`) — a name collision with a section that doesn't carry
ssobroker's own marker is left completely untouched and reported back as a
conflict, never silently mutated. The file is edited as text rather than
parsed and re-serialized, so comments and formatting in everything ssobroker
didn't write survive byte-for-byte. Before changing an existing file, the
previous version is copied to a new timestamped `config.bak-<stamp>`;
backups are never overwritten, so the original survives repeated runs. A
run that would change nothing writes nothing and makes no backup. Two
registry entries that map to the same profile name are rejected outright.

**Residual risk:** ssobroker-managed sections are overwritten wholesale on
re-run, so hand edits made *inside* a section ssobroker wrote are lost (the
timestamped backup is the recovery path). ssobroker never deletes sections it
wrote earlier, so profiles from a previous `--prefix`/`--all-roles`
choice linger until removed by hand. Beyond that, the general "back up
your own dotfiles" hygiene applies to any tool that writes to
`~/.aws/config`.

### 6. Audit log data pushed to CloudWatch is read or tampered with

**Threat:** `ssobroker audit-log --push-cloudwatch` sends recent local audit
entries (account IDs, roles, commands run, free-text `--reason` values) to
a CloudWatch Logs group. Anyone who can read that log group sees an
operator's command history; anyone who can write to it could inject
forged entries.

**Mitigation:** this is opt-in (`cloudwatch_log_group` must be explicitly
set, and `audit_forward: [cloudwatch]` or `--push-cloudwatch` used). It
writes with a dedicated logging role (`cloudwatch_account` /
`cloudwatch_role`) when one is set, else the credentials active in the
calling shell, so the operator controls exactly which role has
`logs:PutLogEvents`/`logs:CreateLogStream` on that group. Values of
secret-looking arguments are redacted before an entry is written or sent.
Only the managed policy (root/Administrators-writable) or the user's own
orgs.yaml can turn forwarding on.

**Residual risk:** this is entirely a function of how the operator
provisions and secures the destination log group (encryption at rest, log
group resource policy, who has `logs:GetLogEvents` on it) — outside this
tool's control by design. `ssobroker` does not create the log group and does
not set access policy on it. Worth calling out explicitly: the
`--reason` field is free text the operator types, not validated against a
ticketing system, so treat it as a note-to-self / good-faith annotation,
not a tamper-evident justification.

### 7. The local audit log itself is edited or deleted after the fact

**Threat:** an operator (or something running as them) wants to remove
evidence of a command that was run.

**Mitigation:** none, and this is intentional — see "Explicitly out of
scope."

**Residual risk:** total. `~/.ssobroker/audit.log` is a plain, appendable text
file with no protection against an operator (or anything running with
their OS privileges) editing or truncating it. This is fine for its stated
purpose — "what did I run against prod last Tuesday," a convenience for
the operator's own recall — and actively wrong to rely on for anything
resembling non-repudiation or compliance evidence. **CloudTrail is the
actual tamper-evident record of what happened in AWS**, independent of
anything this CLI does locally. If you need a defensible audit trail,
that's what to point an auditor at.

### 8. Sign-in phishing (device-code phishing)

**Threat:** an attacker starts a device-authorization sign-in against the
victim's Identity Center, then sends the victim the real AWS approval link
("verify your session"). The page is genuine, so the victim approves, and the
attacker's poller receives the SSO token.

**Mitigation:** `ssobroker login` defaults to the authorization-code grant
with PKCE and a `127.0.0.1` loopback redirect. The authorization code is
delivered only to the listener on the machine that started the sign-in, the
`state` value is checked, and the code is useless without the PKCE verifier
that never leaves the process. The device-code flow is still available for
headless machines, prints a warning to approve only requests you started,
and can be disabled fleet-wide with `allow_device_code: false`.

**Residual risk:** the managed policy doesn't stop an attacker from running
their own device-code sign-in against your Identity Center with some other
tool; it only removes the flow from `ssobroker`. Require MFA and user
awareness in Identity Center itself.

### 9. Infostealer harvests AWS CLI files left beside ssobroker

**Threat:** commodity infostealers (Lumma, RedLine, Vidar) copy
`~/.aws/credentials`, `~/.aws/sso/cache/` and `~/.aws/cli/cache/` from
developer machines. [Wiz (2026-09-25)](https://www.wiz.io/blog/infostealer-incursion-cloud-ai-credentials)
found AWS secrets were 46% of the cloud credentials in infostealer logs, and
that SSO cache tokens can stay usable for up to 90 days unless revoked. A
stolen refresh-capable SSO token mints role credentials for every account its
user can reach. ssobroker's own cache does not help if the same machine still
has a long-lived access key or an `aws sso login` token from before.

**Mitigation:** `ssobroker doctor` scans those three locations (and
`AWS_SHARED_CREDENTIALS_FILE`) and prints a WARN for any long-lived access key
and any AWS CLI SSO token that is unexpired or refresh-capable, plus a NOTE for
cached temporary credentials. It reads only profile names, counts and expiry
times and never prints a key or token. `ssobroker doctor --strict` exits 1 on
a WARN, so a fleet check or login script can enforce it.

**Residual risk:** `doctor` reports; it does not delete. The operator still has
to deactivate the key in IAM and run `aws sso logout`. It does not see other
tools' credential stores (Granted, aws-vault, IDE plugins, exported shell
variables). Malware already running as the user can read ssobroker's own cache
too (see "Explicitly out of scope"); keep `max_session_hours` short and revoke
the user's Identity Center sessions after a suspected compromise.

## Explicitly out of scope

Naming these directly, rather than leaving them as an implied gap:

- **A determined operator bypassing their own guardrails.** Guardrails are
  a speed bump for the *accidental* case, not an access-control mechanism.
  Anyone with legitimate `ssobroker`/AWS access who wants to run a
  guardrail-matched command already has a dozen ways around client-side
  pattern matching (see scenario 2). The correct control for "this
  identity must never be able to do X" is IAM/SCPs, which don't care what
  CLI or wrapper script the request came through.
- **Malware or a compromised process already running as the operator's OS
  user.** If an attacker already has arbitrary code execution as the
  logged-in user, they can read anything that user's session can read —
  including an unlocked keychain, environment variables of processes they
  spawn, and (per scenario 3) the config files that drive guardrail
  behavior. No client-side tool can fully defend against this; it's the
  same trust boundary every local CLI (including the AWS CLI itself)
  operates within.
- **A compromised or malicious Identity Center administrator.** `ssobroker`
  trusts Identity Center's authorization decisions completely — it has no
  mechanism to detect or resist a case where Identity Center itself has
  been misconfigured or its admin access compromised. That's an identity
  provider's own security posture, not something a client tool layered on
  top of it can compensate for.
- **Network-level attacks against the SSO OIDC sign-in flows**
  (e.g. an attacker intercepting the verification URL before the operator
  approves it). This is AWS SSO OIDC's own protocol design, not something
  `ssobroker` implements or could add mitigations to beyond what the protocol
  already provides (short-lived device codes, user-driven approval in a
  separate, trusted browser context).
- **Auditability/non-repudiation of the local audit log** — see scenario 7.

## Recommended compensating controls (for whoever deploys this)

Start with [ENTERPRISE.md](ENTERPRISE.md): a managed `policy.yaml` pinning
`allowed_sso_start_urls`, turning off device-code sign-in and environment
overrides, and forwarding the audit log.

None of these are things `ssobroker` does for you — they're the actual
enforcement layer this tool assumes exists around it:

- IAM permission boundaries and/or SCPs on every role `ssobroker` can assume,
  scoped to least privilege for that role's actual job.
- CloudTrail enabled org-wide, as the real (tamper-evident, AWS-side)
  record of API activity — not the local audit log.
- MFA required at the Identity Center level for the sign-in
  flow itself.
- If using `--push-cloudwatch`: encryption at rest on the destination log
  group, a resource policy restricting who can read it, and a retention
  policy appropriate for your compliance requirements.
- Session policies / `max_session_hours` tuned to your organization's risk
  tolerance for "how long should a stolen laptop's cached token remain
  useful," independent of AWS's own token expiry.

## Status

This is a living document — if you find a scenario it doesn't cover, or a
mitigation described here that doesn't hold up, please open an issue (or,
for anything that looks like an actual exploitable gap rather than a
documentation gap, follow the private reporting process in
[`SECURITY.md`](../.github/SECURITY.md) instead of a public issue).
