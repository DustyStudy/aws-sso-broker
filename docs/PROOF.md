# Proof that ssobroker works

Two live runs against a real AWS Organization's real IAM Identity Center
instance. Account IDs, the SSO user and access keys are masked in the text
and in the evidence files under [`proof/`](proof/).

- [Run 2 (2026-09-30)](#run-2-2026-09-30-corporate-hardening): the corporate
  hardening from PR #9: PKCE sign-in, server-side logout, managed policy,
  audit redaction and forwarding, CloudTrail join. **Found one real problem**
  (hourly re-login) and fixed it in the same PR as this proof.
- [Run 1 (2026-09-23)](#run-1-2026-09-23-core-behavior): core behavior:
  credentials, guardrails, audit log, `sync-aws-config`, logout. Found nothing.

## Run 2 (2026-09-30): corporate hardening

Run from `main` at `b0db996` (PR #9) plus the refresh-token fix on this
branch, on Windows 11 with Python 3.12. `SSOBROKER_HOME` pointed at a
throwaway directory. `ProgramData` pointed at another throwaway directory, so
the managed policy was read through its real Windows code path
(`%ProgramData%\ssobroker\policy.yaml`) without writing to the machine.

| | |
|---|---|
| **Identity Center** | Real instance in us-east-2, signed in through the browser with MFA (three times: first run, after the fix, and for cleanup) |
| **Accounts** | Management account (marked protected, `strict_protected_accounts: true`) and one member ("dev") account, `AdministratorAccess` on both |
| **Evidence** | [`2026-09-30-hardening-checks.json`](proof/2026-09-30-hardening-checks.json), [`2026-09-30-audit-log.json`](proof/2026-09-30-audit-log.json) (the full local audit log from the run) |

### Claims and evidence

| # | Claim | Result | How it was checked |
|---|---|---|---|
| 1 | `login` signs in with the authorization-code grant + PKCE on a `127.0.0.1` redirect | **Proven** | Authorize URL used `code_challenge_method=S256` and `redirect_uri=http://127.0.0.1:<port>/oauth/callback`; AWS's `CreateToken` accepted the verifier and returned a token |
| 2 | The OIDC client registration is cached, not repeated on every login | **Proven** | `sso-client_…_auth_code.json` written with a ~90-day lifetime |
| 3 | An expired access token is refreshed without a browser, but the session cap still counts from the original sign-in | **Proven (after fix)** | Access token marked expired on disk; `whoami` then succeeded with a different access token, no browser, `issuedAt` unchanged |
| 4 | `logout` signs the session out at AWS, not just locally | **Proven** | The saved access token listed 3 accounts before logout and got `UnauthorizedException: Session token not found or invalid` after; the saved refresh token got `InvalidGrantException` |
| 5 | `creds-process` is audited when it gets new credentials, and only then | **Proven** | Two calls: one audit entry (fresh), none for the cache hit |
| 6 | `strict_protected_accounts` blocks `creds-process` and `export-env`, not just `exec`/`shell` | **Proven** | All three exited 2 against the management account and were audited as `blocked`; no credentials printed |
| 7 | Secret-looking arguments are redacted before they're written | **Proven** | `env DB_PASSWORD=not-a-real-secret …` logged as `DB_PASSWORD=***REDACTED***`; a managed-policy pattern (`*user-name*`) redacted `--user-name` |
| 8 | The audit log's `access_key_id` finds the matching CloudTrail events | **Proven** | `aws cloudtrail lookup-events` by that key returned exactly the calls made with it (`GetCallerIdentity`, `GetAccountSummary`, `GetCallerIdentity`) |
| 9 | CloudWatch forwarding sends every entry once, and a forwarding failure never blocks the command | **Proven** | Before the log group existed: stderr warning, command still ran. After: 13 local lines = 13 CloudWatch events, all unique; two `--push-cloudwatch` runs pushed 0 new entries |
| 10 | The managed policy pins start URLs, fails closed on unknown keys, and turns off device code | **Proven** | Wrong URL: config error. Same URL with different case and trailing slash: accepted. `alow_device_code` typo: exit 1. `login --use-device-code`: refused |
| 11 | The managed policy can switch off `SSOBROKER_*` overrides | **Proven** | With `ignore_env_overrides: true`, `doctor` ignored `SSOBROKER_HOME` and read the real `~/.ssobroker/orgs.yaml` instead (read-only) |
| 12 | Policy settings only tighten | **Proven** | `max_session_hours` 8 (user) / 4 (policy) became 4; policy `deny_patterns` blocked `aws iam create-user`; `role_credential_cache: none` left 0 role-credential files on disk |

### What running it for real found

**Users would have had to sign in every hour.** With the authorization-code
grant, Identity Center issues a 1-hour access token plus a refresh token
(the device-code grant ssobroker used before got one token lasting about
8 hours). PR #9 deliberately dropped the refresh token, so every
command after the first hour would have opened a browser. The unit tests
couldn't catch this because the fake returned whatever lifetime it was given.

Fixed in the same PR as this proof: the refresh token is stored with the
access token (OS keychain when available, 0600 file otherwise). An expired
access token is refreshed silently, but only until `max_session_hours` after
the original sign-in, and only while the Identity Center session is still
valid. Claims 3 and 4 were run after the fix, including proof that `logout`
revokes the refresh token too.

Also worth knowing, but not bugs:

- `result: "ok"` in the audit log means "allowed and started", not "the
  command succeeded". The run's first `aws logs create-log-group` failed
  inside the AWS CLI and is still logged `ok`. Use CloudTrail for what
  actually happened in AWS.
- On Windows, Git Bash rewrites arguments that look like POSIX paths
  (`/ssobroker/proof` became `C:/Program Files/Git/ssobroker/proof`), which
  is visible in one audit entry. That is Git Bash, not ssobroker; set
  `MSYS_NO_PATHCONV=1` or use PowerShell.

### What this run does not prove

- **The OS keychain backend.** The `keyring` extra wasn't installed, so
  tokens used the 0600-file cache. It was skipped deliberately: the keychain
  entry name is shared with any real ssobroker install on the same machine.
- **syslog and Windows Event Log forwarding.** Only CloudWatch was run live.
- **The POSIX root-ownership check on `/etc/ssobroker/policy.yaml`.** This run
  was on Windows; the check is covered by unit tests on Linux and macOS CI.
- **A real Windows folder ACL on `%ProgramData%\ssobroker`.** The policy was
  read from a redirected `ProgramData`.
- **`ca_bundle`, `https_proxy`, `use_fips_endpoint`** against a real proxy or
  FIPS endpoint.
- **Refresh up to the session cap in real time.** Expiry was forced by editing
  the cached expiry time, not by waiting an hour.

### Follow-up: first attested release (v0.2.2)

After this run was merged, release-please published v0.2.2 and the new
release job attached four files. Each one verified against its signed
build-provenance attestation, and a hash-locked install from them worked:

```text
$ gh attestation verify <file> --repo DustyStudy/aws-sso-broker
aws-sso-broker.cdx.json                 verified  release-please.yml  refs/heads/main  afb6b53
aws_sso_broker-0.2.2-py3-none-any.whl   verified  release-please.yml  refs/heads/main  afb6b53
aws_sso_broker-0.2.2.tar.gz             verified  release-please.yml  refs/heads/main  afb6b53
runtime-requirements.txt                verified  release-please.yml  refs/heads/main  afb6b53

$ pip install --require-hashes -r runtime-requirements.txt
$ pip install --no-deps aws_sso_broker-0.2.2-py3-none-any.whl
$ ssobroker --version
ssobroker, version 0.2.2
```

### Follow-up: property-based fuzzing found a PowerShell quoting bug

Hypothesis property tests (`tests/test_properties.py`) generate arbitrary
values and check that `export-env --powershell` output parses back to exactly
that value. They found that PowerShell also ends a double-quoted string at
the typographic quotes `“ ” „` (U+201C, U+201D, U+201E), which weren't
escaped. Checked in real PowerShell 7 with the value
`abc“; Write-Output INJECTED; “def`:

| Quoting | Result |
|---|---|
| Before the fix | Variable got only `abc`; `Write-Output INJECTED` ran |
| After the fix | Variable holds all 33 characters; nothing ran |

AWS never returns credentials containing these characters, so no real
credentials were at risk, but the quoting now holds for any value as the
threat model says.

### Reproduce it

1. Install from a clone: `pip install -e .`.
2. Point `SSOBROKER_HOME` at an empty directory and write an `orgs.yaml` with
   your start URL and two accounts; add a `guardrails.yaml` with one account
   in `protected_account_ids` and `strict_protected_accounts: true`.
3. `ssobroker login`: approve in the browser. Check that `cache/` has an
   `sso-client_…_auth_code.json` and that the token entry has a
   `refreshToken`.
4. `ssobroker creds-process -a <dev>` twice, then `ssobroker audit-log`: one
   entry. Try `creds-process`, `export-env` and `exec` against the protected
   account: exit 2 each time.
5. `ssobroker exec -a <dev> -- env DB_PASSWORD=x aws sts get-caller-identity`,
   then look at `audit.log`.
6. After ~5-15 minutes, `aws cloudtrail lookup-events --lookup-attributes
   AttributeKey=AccessKeyId,AttributeValue=<access_key_id from audit.log>`.
7. Managed policy: on Windows set `ProgramData` to a scratch directory (or
   use the real `%ProgramData%\ssobroker\policy.yaml` / `/etc/ssobroker/policy.yaml`)
   and try the settings in [`config/policy.example.yaml`](../config/policy.example.yaml).
8. CloudWatch: create a log group, set `audit_forward: [cloudwatch]` and
   `cloudwatch_log_group`, run a few commands, and compare
   `aws logs filter-log-events` with `audit.log`.
9. Save the cached access token, run `ssobroker logout`, then
   `aws sso list-accounts --access-token <saved token>`: expect
   `UnauthorizedException`.

## Run 1 (2026-09-23): core behavior

Run for real on **2026-09-23** against a real AWS Organization's real IAM
Identity Center instance - two real accounts, real device-authorization
logins, real ephemeral STS credentials, and every guardrail outcome
(allowed, blocked by protected-account, blocked by deny-pattern, cancelled
at a confirmation prompt) exercised for real, not mocked. Verified against
AWS's own responses (`aws sts get-caller-identity` via both `ssobroker` and
plain `aws --profile`) and the tool's own on-disk audit log, not just its
CLI output. Account IDs are masked below and in the evidence files.

The tool was named `orgctl` when this run happened, so the raw evidence
files under `docs/proof/` use that name and the `~/.orgctl` paths.

Unlike this session's other proofs, **nothing broke.** Every command tested
did what its `--help` text and README said it would, on the first try. That
is itself worth recording plainly rather than manufacturing a "found and
fixed" narrative where there wasn't one - ssobroker has already been through
several rounds of real fixes (see `CHANGELOG.md` and the merged `fix/*`
PRs), and this run didn't surface a new one.

### What was tested

| | |
|---|---|
| **Org** | The same real AWS Organization used in this session's other proofs: management account and one member ("dev") account |
| **Identity Center** | Real `sso_start_url`, real device-authorization grant, approved via an already-authenticated browser session from earlier in the session |
| **Config** | `~/.ssobroker/orgs.yaml` with both real accounts; `~/.ssobroker/guardrails.yaml` with the management account marked `protected_account_ids`, a `deny_patterns` entry, and a `require_confirmation_patterns` entry |

### 1. Claims and evidence

| # | Claim | Result | Evidence |
|---|---|---|---|
| 1 | `login` completes a real SSO device-authorization grant and caches a token | **Proven** | Real device-authorization URL issued against the real `sso_start_url`; `whoami` succeeded immediately after |
| 2 | `whoami`/`exec` produce real, correctly-scoped STS credentials per account/role | **Proven** | [`end-to-end-checks.json`](proof/end-to-end-checks.json): both accounts' ARNs match exactly what direct `aws sts get-caller-identity` under the equivalent SSO profile returns |
| 3 | `protected_account_ids` blocks `exec` *and* `shell` against the management account, before any credentials are requested | **Proven** | [`audit-log-excerpt.json`](proof/audit-log-excerpt.json): both blocked, both audit-logged, with the specific reason recorded |
| 4 | `deny_patterns` blocks a matching command regardless of account | **Proven** | Same file: `aws iam delete-role*` blocked before reaching AWS |
| 5 | `require_confirmation_patterns` actually gates execution, not just warns | **Proven** | Same file: declining the prompt recorded `cancelled` and made no AWS call; `--yes` on the identical command recorded `ok` and made a real call (which failed with `NoSuchBucket` against an intentionally nonexistent target - proof it really reached AWS this time, not just that the tool claimed success) |
| 6 | Every action type is audited, not just `exec` | **Proven** | Same file: `export-env` and `shell` both produced audit entries too |
| 7 | `list-remote` reflects live Identity Center grants, not just the local registry | **Proven** | Returned a third account never added to `orgs.yaml` |
| 8 | `check-policy` evaluates identity-based policy only, as documented | **Proven** | [`end-to-end-checks.json`](proof/end-to-end-checks.json): correctly returned "allowed" for an action AdministratorAccess's identity policy does technically permit, demonstrating its own stated SCP-blindness rather than overclaiming |
| 9 | `sync-aws-config` never touches profiles it didn't create, and backs up first | **Proven** | Same file: 3 pre-existing `[profile]`/`[sso-session]` blocks untouched; new backup file created automatically |
| 10 | A `sync-aws-config`-written `credential_process` profile works with plain `aws` CLI, no `ssobroker` wrapper needed | **Proven** | `aws sts get-caller-identity --profile dev` / `--profile management` both succeeded, matching `ssobroker whoami`'s output exactly |
| 11 | `logout` actually clears cached credentials, not just claims to | **Proven** | Cache directory empty after; next command transparently re-triggered a fresh device-authorization login rather than silently reusing anything |

### 2. What running it for real found

Nothing. No bug, no gap between documented and actual behavior, across 11
claims spanning credential issuance, all three guardrail mechanisms, audit
logging, config sync, and logout/re-auth. This is not "nothing was tested
hard enough" - see the specific failure-mode checks in claims 3-5 and 9,
each of which is exactly the kind of thing that tends to silently not work
(a guardrail that logs but doesn't block, a confirmation prompt that's
cosmetic, a config sync that clobbers what it shouldn't).

### 3. What this does not prove

- **The OS keychain backend for SSO tokens** (the `keyring` extra). This run used the default file-based cache (0600 permissions), not a real macOS Keychain/Windows Credential Manager/Secret Service backend.
- **Multiple AWS Organizations from one registry.** Tested with one org, two accounts.
- **GovCloud.** Not exercised.
- **`ssobroker completion`** was not installed into a real shell and exercised interactively.
- **`audit-log --push-cloudwatch`.** `cloudwatch_log_group` was left unset in `orgs.yaml`; the local-only audit path was tested, not the CloudWatch export.
- **Concurrent/multi-user use of the same cache directory.** Single user, single machine.
- **The session-expiry warning and `max_session_hours` cap.** Not exercised - would need a session actually approaching either limit, which a short test run doesn't reach.
- **Attempting to bypass guardrails deliberately** (e.g. constructing a command that's semantically equivalent to a denied pattern but doesn't match the glob). The guardrails file's own header says this is a speed bump, not a security boundary, and this run didn't try to defeat it - only confirmed it works for the straightforward case.

### 4. Reproduce it

Prerequisites: an AWS Organization with IAM Identity Center, at least one
member account you have a permission set on, and a management account you
can mark protected.

1. `pip install -e .` from a clone of this repo, or `pipx install .`.
2. `ssobroker init`, then edit `~/.ssobroker/orgs.yaml` with your real
   `sso_start_url`, `sso_region`, and accounts.
3. `ssobroker doctor` - confirms config/cache/guardrails are all readable.
4. `ssobroker login` - approve the device code in your browser.
5. `ssobroker whoami -a <alias> -r <role>` for each account; compare the ARN
   against `aws sts get-caller-identity --profile <equivalent-sso-profile>`.
6. Add a `guardrails.yaml` with one account under `protected_account_ids`
   and try `ssobroker exec -a <that account> -- aws sts get-caller-identity` -
   expect a block, not a prompt.
7. Try a `deny_patterns` entry and a `require_confirmation_patterns` entry
   the same way; for the latter, confirm declining doesn't run the command
   and `--yes` does.
8. `ssobroker audit-log` (or read `~/.ssobroker/audit.log` directly) to see every
   attempt above recorded with its actual outcome.
9. `ssobroker sync-aws-config`, then `aws sts get-caller-identity --profile
   <alias>` with no `ssobroker` involved at all.
10. `ssobroker logout`, then confirm `~/.ssobroker/cache/` is empty and the next
    command re-triggers login.

`docs/proof/` holds the machine-readable evidence from the run above.
