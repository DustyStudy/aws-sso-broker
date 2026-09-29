# Proof that ssobroker works

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

## What was tested

| | |
|---|---|
| **Org** | The same real AWS Organization used in this session's other proofs: management account and one member ("dev") account |
| **Identity Center** | Real `sso_start_url`, real device-authorization grant, approved via an already-authenticated browser session from earlier in the session |
| **Config** | `~/.ssobroker/orgs.yaml` with both real accounts; `~/.ssobroker/guardrails.yaml` with the management account marked `protected_account_ids`, a `deny_patterns` entry, and a `require_confirmation_patterns` entry |

## 1. Claims and evidence

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

## 2. What running it for real found

Nothing. No bug, no gap between documented and actual behavior, across 11
claims spanning credential issuance, all three guardrail mechanisms, audit
logging, config sync, and logout/re-auth. This is not "nothing was tested
hard enough" - see the specific failure-mode checks in claims 3-5 and 9,
each of which is exactly the kind of thing that tends to silently not work
(a guardrail that logs but doesn't block, a confirmation prompt that's
cosmetic, a config sync that clobbers what it shouldn't).

## 3. What this does not prove

- **The OS keychain backend for SSO tokens** (the `keyring` extra). This run used the default file-based cache (0600 permissions), not a real macOS Keychain/Windows Credential Manager/Secret Service backend.
- **Multiple AWS Organizations from one registry.** Tested with one org, two accounts.
- **GovCloud.** Not exercised.
- **`ssobroker completion`** was not installed into a real shell and exercised interactively.
- **`audit-log --push-cloudwatch`.** `cloudwatch_log_group` was left unset in `orgs.yaml`; the local-only audit path was tested, not the CloudWatch export.
- **Concurrent/multi-user use of the same cache directory.** Single user, single machine.
- **The session-expiry warning and `max_session_hours` cap.** Not exercised - would need a session actually approaching either limit, which a short test run doesn't reach.
- **Attempting to bypass guardrails deliberately** (e.g. constructing a command that's semantically equivalent to a denied pattern but doesn't match the glob). The guardrails file's own header says this is a speed bump, not a security boundary, and this run didn't try to defeat it - only confirmed it works for the straightforward case.

## 4. Reproduce it

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
