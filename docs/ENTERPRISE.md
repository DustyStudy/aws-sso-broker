# Deploying ssobroker in an organization

This guide is for the team that rolls `ssobroker` out to many machines. It
covers the admin-managed policy, audit forwarding, network settings, and how
to verify the package you install. Individual users don't need any of it.

`ssobroker` is still a client-side tool. Enforcement belongs in IAM, SCPs,
permission boundaries and Identity Center itself; see
[THREAT_MODEL.md](THREAT_MODEL.md). What this guide adds is a way to make
every endpoint behave the same and to get its activity into your SIEM.

## 1. Install a verified build

Each GitHub release has these files attached:

| File | What it is |
|---|---|
| `aws_sso_broker-X.Y.Z-py3-none-any.whl` | The package |
| `aws_sso_broker-X.Y.Z.tar.gz` | Source distribution |
| `runtime-requirements.txt` | Hash-locked runtime dependencies (including the `keyring` and `windows` extras) |
| `aws-sso-broker.cdx.json` | CycloneDX SBOM of those dependencies |

All four carry a signed build-provenance attestation. Check the wheel before
you mirror it:

```bash
gh attestation verify aws_sso_broker-X.Y.Z-py3-none-any.whl --repo DustyStudy/aws-sso-broker
```

Install with every dependency pinned by hash:

```bash
python3 -m venv /opt/ssobroker
/opt/ssobroker/bin/pip install --require-hashes -r runtime-requirements.txt
/opt/ssobroker/bin/pip install --no-deps aws_sso_broker-X.Y.Z-py3-none-any.whl
```

If the release is also on PyPI (`pipx install aws-sso-broker`), it was
uploaded with trusted publishing from the same workflow, and PyPI shows that
publisher attestation on the file page.

## 2. The managed policy

Put a `policy.yaml` where users can't write:

| OS | Path | Protection |
|---|---|---|
| Linux, macOS | `/etc/ssobroker/policy.yaml` | File and directory owned by root and not group/world-writable. Otherwise `ssobroker` refuses to run. |
| Windows | `%ProgramData%\ssobroker\policy.yaml` | Create the folder with an ACL that only Administrators and SYSTEM can write. Users get read. |

On Windows, set the ACL when you create the folder. By default a standard
user can create new folders under `%ProgramData%`:

```powershell
$dir = "$env:ProgramData\ssobroker"
New-Item -ItemType Directory -Force $dir | Out-Null
icacls $dir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX"
```

[`config/policy.example.yaml`](../config/policy.example.yaml) lists every
setting. The rules that make it safe to deploy:

- **It only tightens.** It can pin the allowed start URLs, lower
  `max_session_hours`, add guardrails, require a stricter role-credential
  cache, and add redaction patterns and forwarding. It never supplies a start
  URL and can't loosen a user's settings.
- **Unknown keys are an error.** A typo in a security setting stops the tool
  instead of being silently ignored.
- **No environment variable can point at a different policy file.**
- `ssobroker doctor` shows whether a policy was applied.

The settings most organizations want:

```yaml
allowed_sso_start_urls: [https://corp.awsapps.com/start]
ignore_env_overrides: true      # SSOBROKER_GUARDRAILS=/dev/null no longer disables guardrails
allow_device_code: false        # removes the device-code phishing path
strict_protected_accounts: true # protected accounts blocked in creds-process/export-env too
role_credential_cache: keyring
max_session_hours: 8
```

With `allow_device_code: false`, machines with no local browser can't sign
in. Leave it on for those machines, or give them a separate policy.

## 3. Sign-in flow

`ssobroker login` uses the OAuth 2.0 authorization-code grant with PKCE,
the same flow AWS CLI v2.22+ uses. It listens on a random `127.0.0.1` port
and only a browser on the same machine can finish the sign-in. The device-code
flow (`--use-device-code`) prints a URL that can be approved from any device,
and attackers abuse that by sending victims real Identity Center approval
links. Turn it off with the policy wherever you can.

Also require MFA in Identity Center. `ssobroker` can't enforce it.

`ssobroker logout` calls the SSO portal's `Logout` API, so the session stops
working at AWS as well as locally. Role credentials issued earlier stay valid
until they expire (usually 1 hour; up to the permission set's session
duration). To cut those off too, add an inline policy to the permission set
that denies everything with `aws:TokenIssueTime` before the incident time
(AWS documents this as revoking IAM role sessions created by permission sets).

## 4. Audit forwarding

Every `exec`, `shell` and `export-env`, and every `creds-process` call that
got new credentials, writes one JSON line to `~/.ssobroker/audit.log`.
Values of secret-looking arguments (`--secret-string`, `--password=...`,
`DB_PASSWORD=...`, and more; add your own with `audit_redact_flags`) are
replaced with `***REDACTED***` first.

Each entry includes `access_key_id`, the temporary key used for that action.
CloudTrail records the same key on every API call made with it
(`userIdentity.accessKeyId`), so you can join a local entry to exactly the
AWS activity it caused:

```sql
-- CloudTrail Lake / Athena
SELECT eventTime, eventName, eventSource
FROM cloudtrail
WHERE userIdentity.accessKeyId = 'ASIA...'
```

Forwarding targets (`audit_forward`):

| Target | Where | Notes |
|---|---|---|
| `syslog` | Local syslog, facility `auth` | Linux/macOS. Ship with your existing agent. |
| `eventlog` | Windows Application log, source `ssobroker` | Install with the `windows` extra. Register the event source once as admin: `New-EventLog -LogName Application -Source ssobroker`. |
| `cloudwatch` | `cloudwatch_log_group` | Pushes unsent entries after each write. A cursor file avoids duplicates; two processes at the same moment can still both send one entry. |

For CloudWatch, set `cloudwatch_account` and `cloudwatch_role` to a
dedicated role that can only write to the group:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "arn:aws:logs:*:444444444444:log-group:/corp/ssobroker/audit:*"
  }]
}
```

Encrypt the log group with KMS and restrict who can read it: entries include
command lines.

Forwarding never blocks a command. A failure is printed to stderr and the
entry stays in the local log. The local log is still not tamper-evident;
CloudTrail is your record of what happened in AWS.

## 5. Network settings

For TLS-inspecting proxies, proxies and FIPS endpoints, set these in
`orgs.yaml` (or the matching environment variables, which win):

```yaml
ca_bundle: /etc/pki/corp-root-ca.pem   # AWS_CA_BUNDLE
https_proxy: http://proxy.corp:8080    # HTTPS_PROXY
use_fips_endpoint: true                # AWS_USE_FIPS_ENDPOINT
```

They're exported to commands run by `exec` and `shell` as well. With
`use_fips_endpoint`, check that the SSO and SSO OIDC FIPS endpoints exist in
your Identity Center region first.

GovCloud works like any other region: set `sso_region` to your Identity
Center's GovCloud region. The sign-in URL is built from the SSO OIDC endpoint
for that region.

## 6. Checklist

- [ ] Wheel verified with `gh attestation verify` and mirrored internally
- [ ] `policy.yaml` deployed, root/Administrators-only write, `ssobroker doctor` shows it
- [ ] `ssobroker doctor --strict` passes on every machine: no long-lived keys in `~/.aws/credentials`, no AWS CLI SSO tokens left in `~/.aws/sso/cache`
- [ ] `allowed_sso_start_urls` set
- [ ] `allow_device_code: false` (except on headless machines)
- [ ] MFA required in Identity Center
- [ ] Audit forwarding on, and the destination encrypted and access-controlled
- [ ] SCPs / permission boundaries in place for every role users can reach
