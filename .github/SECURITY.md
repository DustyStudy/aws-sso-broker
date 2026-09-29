# Security Policy

For the full threat model — assets, trust boundaries, per-scenario
mitigations, residual risk, and explicit non-goals — see
[`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md). This document covers
vulnerability reporting and CI/CD supply-chain hardening specifically.

## Reporting a vulnerability

If you find a security issue in `ssobroker`, please open a private report via
[GitHub private vulnerability reporting](https://github.com/DustyStudy/aws-sso-broker/security/advisories/new)
rather than a public issue. If that's unavailable, open an issue with minimal detail
asking for a private channel and it'll be picked up from there.

## Scope

`ssobroker` handles short-lived AWS credentials. Areas that get the most
scrutiny for security review:

- `src/ssobroker/sso.py` — the device-authorization flow and token handling
- `src/ssobroker/cache.py` — where tokens and role credentials are persisted
  (OS keychain when available, 0600 local files otherwise)
- `src/ssobroker/exec_cmd.py` — how credentials are exported into child
  processes
- `src/ssobroker/guardrails.py` — the local deny/confirm-pattern checks

## Design notes relevant to security review

- No code path accepts, stores, or exports a long-lived IAM access key —
  everything comes from AWS SSO's `GetRoleCredentials`, which is inherently
  short-lived.
- Cached credentials live in the OS keychain (SSO tokens, when the
  `keyring` extra is installed and a backend is available) or in
  owner-only (0600) local files, with expiry checked on every read.
- Guardrails (`guardrails.yaml`) and the IAM policy pre-check
  (`check-policy`, `--check-action`) are explicitly **not** a security
  boundary — they're local, best-effort speed bumps. Real enforcement
  belongs in IAM permission boundaries and Service Control Policies. Both
  the code and the README say so; please flag it if you find a place where
  the tool implies otherwise.
- The local audit log (`~/.ssobroker/audit.log`) and any `--reason` text are
  never transmitted anywhere by this tool except when you explicitly run
  `ssobroker audit-log --push-cloudwatch`.

## CI/CD supply-chain hardening

Every workflow under `.github/workflows/` follows the same baseline:

- **Least-privilege `permissions`** declared at the workflow level
  (`contents: read` by default), with any broader permission (e.g.
  `security-events: write` for SARIF uploads, `id-token: write` for
  Scorecard's Sigstore signing) scoped to only the specific job that needs
  it — never at the workflow level.
- **`step-security/harden-runner`** as the first step of every job. It
  monitors and can restrict network egress and file/process activity on
  the runner, which is how real incidents like the `tj-actions/changed-files`
  supply-chain compromise (CVE-2025-30066) get caught in practice. Currently
  running in `audit` (log-only) mode while the egress allowlist is
  characterized; the plan is to move to `block` mode with an explicit
  allowlist once a few weeks of audit logs confirm nothing legitimate gets
  blocked.
- **`persist-credentials: false`** on every `actions/checkout` step, so the
  ephemeral `GITHUB_TOKEN` isn't left sitting in the local git config for
  the rest of the job.
- **Explicit `timeout-minutes`** on every job, so a hung or runaway step
  can't tie up compute (or a compromised dependency) indefinitely.
- **`concurrency` groups**, so superseded runs on the same ref get
  cancelled instead of piling up.

**Action pinning policy:** every action, first-party or third-party, is
pinned to a full commit SHA with the version in a trailing comment. A tag
like `@v4` can be moved by the maintainer, or by an attacker who
compromises the maintainer's account, without any signal to consumers; a
SHA cannot.

Dependabot (`.github/dependabot.yml`) keeps the pinned SHAs current
automatically.

## Supported versions

Pre-1.0 — only the latest `main` is supported. Once there's a first
tagged release, this section will be updated with a version table.
