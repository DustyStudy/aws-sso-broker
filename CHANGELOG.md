# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); once tagged
releases start, versioning follows [SemVer](https://semver.org/).

Entries below `[Unreleased]` are managed automatically by
[release-please](https://github.com/googleapis/release-please) once that
workflow is active (see `.github/workflows/release-please.yml`) — it opens
a PR that moves these into a versioned section on each release. Until the
first tag exists, this file is maintained by hand.

## [0.1.7](https://github.com/DustyStudy/aws-sso-broker/compare/orgctl-v0.1.6...orgctl-v0.1.7) (2026-09-29)


### Documentation

* **threat-model:** remove link to a repo that is no longer public ([#29](https://github.com/DustyStudy/aws-sso-broker/issues/29)) ([e074aa4](https://github.com/DustyStudy/aws-sso-broker/commit/e074aa44effc3f5e53bc22add9e08f54f98b3e94))

## [0.1.6](https://github.com/DustyStudy/aws-sso-broker/compare/orgctl-v0.1.5...orgctl-v0.1.6) (2026-09-23)


### Documentation

* **proof:** orgctl tested against a real IAM Identity Center org ([#24](https://github.com/DustyStudy/aws-sso-broker/issues/24)) ([44224b5](https://github.com/DustyStudy/aws-sso-broker/commit/44224b5edd7ce488660737a31cb05f13bfefe107))

## [0.1.5](https://github.com/DustyStudy/aws-sso-broker/compare/orgctl-v0.1.4...orgctl-v0.1.5) (2026-09-22)


### Bug Fixes

* cache file permission window, export-env quoting, shell guardrail gap ([#22](https://github.com/DustyStudy/aws-sso-broker/issues/22)) ([ee94b9d](https://github.com/DustyStudy/aws-sso-broker/commit/ee94b9d0e0a0b26d22fdd47bfda9ac36a8d36e08))

## [0.1.4](https://github.com/DustyStudy/aws-sso-broker/compare/orgctl-v0.1.3...orgctl-v0.1.4) (2026-09-22)


### Bug Fixes

* clean errors for expired tokens/bad accounts, guardrail bypass, audit timestamps ([#20](https://github.com/DustyStudy/aws-sso-broker/issues/20)) ([ed28272](https://github.com/DustyStudy/aws-sso-broker/commit/ed28272300f657215e8de3b550ba40a4f700398a))

## [0.1.3](https://github.com/DustyStudy/aws-sso-broker/compare/orgctl-v0.1.2...orgctl-v0.1.3) (2026-09-22)


### Bug Fixes

* token cache key, policy simulator creds, s3 rm guardrail, sync-aws-config ([#18](https://github.com/DustyStudy/aws-sso-broker/issues/18)) ([22eeeed](https://github.com/DustyStudy/aws-sso-broker/commit/22eeeedd19329d14a40db6d3e765ff899ebc3ed1))

## [0.1.2](https://github.com/DustyStudy/aws-sso-broker/compare/orgctl-v0.1.1...orgctl-v0.1.2) (2026-09-18)


### Documentation

* remove stale badge-visibility note from README ([#15](https://github.com/DustyStudy/aws-sso-broker/issues/15)) ([2484952](https://github.com/DustyStudy/aws-sso-broker/commit/248495219670da10f9e99df7d2f88e1b0f99a14e))

## [0.1.1](https://github.com/DustyStudy/aws-sso-broker/compare/orgctl-v0.1.0...orgctl-v0.1.1) (2026-09-06)


### Bug Fixes

* satisfy ruff format line-length on test_aws_config_sync.py ([#5](https://github.com/DustyStudy/aws-sso-broker/issues/5)) ([89e0072](https://github.com/DustyStudy/aws-sso-broker/commit/89e00720d3e8241cf90b231aebd578002e85bcb2))

## [Unreleased]

### Added
- Initial `orgctl` CLI: `init`, `login`, `logout`, `doctor`, `accounts`,
  `list-remote`, `exec`, `shell`, `creds-process`, `whoami`, `check-policy`,
  `completion`, `audit-log`.
- IAM Identity Center (AWS SSO) device-authorization login flow.
- Local account/role registry (`orgs.yaml`).
- Local guardrails (`guardrails.yaml`) — deny-patterns, protected accounts,
  require-confirmation patterns, with sensible built-in defaults.
- Local JSONL audit log, with optional `--reason` justification and
  optional CloudWatch Logs export (`audit-log --push-cloudwatch`).
- Native `credential_process` support (`creds-process`) for use with plain
  `--profile` in the AWS CLI/SDKs/Terraform.
- `sync-aws-config` — writes/updates `credential_process` profiles in
  `~/.aws/config` for every account (or account/role with `--all-roles`)
  in the registry, without touching unrelated profiles.
- Advisory IAM policy pre-check (`check-policy`, `--check-action` on
  `exec`) via `iam:SimulatePrincipalPolicy` (identity-based policies only —
  does not evaluate SCPs or resource policies).
- Configurable local session cap (`max_session_hours`) independent of the
  SSO token's own server-side expiry.
- OS-keychain storage for SSO tokens via the optional `keyring` extra, with
  automatic fallback to the existing 0600 file-based cache.
- `--json` output on `accounts`, `list-remote`, and `audit-log`.
- `export-env` — prints export/`$env:` lines for the current shell, as an
  alternative to spawning a subshell via `shell`.
- Session-expiry heads-up in `shell` when credentials have under 15
  minutes left.
- CI: ruff lint + format, mypy, pytest (Python 3.11/3.12).
- Dependabot (pip + GitHub Actions), pre-commit config, CODEOWNERS,
  CONTRIBUTING.md, SECURITY.md.
