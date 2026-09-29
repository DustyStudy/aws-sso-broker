"""IAM Identity Center (AWS SSO) device-authorization login and role
credential retrieval.

Flow (standard AWS SSO OIDC device grant):
  1. Register this CLI as an OIDC client with the SSO OIDC service.
  2. Start device authorization -> get a verification URL + user code.
  3. User opens the URL in a browser and approves.
  4. Poll for the access token until approved/expired.
  5. Cache the token (short-lived, typically ~8h) locally.
  6. Use the token with the `sso` service to list accounts/roles and to
     fetch short-lived STS-style role credentials — never a long-lived key.
"""

from __future__ import annotations

import hashlib
import sys
import time
import webbrowser
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

from . import cache

CLIENT_NAME = "ssobroker"
CLIENT_TYPE = "public"

# Default cap on how long a cached SSO token is trusted, independent of its
# server-side expiry. Some orgs issue tokens valid for 8+ hours; you may want
# to force re-auth sooner than that regardless. Overridden by
# OrgConfig.max_session_hours (see config.py).
DEFAULT_MAX_SESSION_HOURS = 8


class SsoLoginError(RuntimeError):
    pass


class SsoTokenExpiredError(SsoLoginError):
    """The cached SSO access token was rejected by AWS — expired, or revoked
    server-side (e.g. by an admin) independent of our own local expiry
    tracking. The cached token has already been cleared by the time this is
    raised; the caller just needs to run `ssobroker login` again."""


# AWS SSO's error codes for "this access token is no longer good" — as
# opposed to e.g. AccessDeniedException, which means the token is fine but
# the identity it represents isn't allowed to do the specific thing asked.
_TOKEN_INVALID_CODES = {"UnauthorizedException", "ForbiddenException"}


@dataclass
class SsoToken:
    access_token: str
    expires_at: float
    region: str
    start_url: str


def _token_cache_key(start_url: str, region: str) -> str:
    # Must be stable across processes — the builtin hash() is randomized per
    # interpreter run (PYTHONHASHSEED), which made every invocation miss the cache.
    digest = hashlib.sha256(start_url.encode("utf-8")).hexdigest()[:16]
    return f"sso-token_{region}_{digest}"


def login(
    start_url: str,
    region: str,
    *,
    open_browser: bool = True,
    max_session_hours: float = DEFAULT_MAX_SESSION_HOURS,
) -> SsoToken:
    """Run the device-authorization flow and return a cached access token.

    All diagnostic output (the verification URL, prompts) goes to stderr —
    never stdout — so this function is safe to call from a command whose
    stdout must be clean machine-readable output (see `creds-process`).
    """
    cache_key = _token_cache_key(start_url, region)
    cached = cache.get(cache_key)
    if cached:
        issued_at = cached.get("issuedAt", 0)
        age_hours = (time.time() - issued_at) / 3600.0
        if age_hours <= max_session_hours:
            return SsoToken(
                access_token=cached["accessToken"],
                expires_at=cached["expiresAt"],
                region=region,
                start_url=start_url,
            )
        # Cached token is still server-side valid but older than our local
        # policy allows — drop it and force a fresh device-auth flow.
        cache.clear(cache_key)

    oidc = boto3.client("sso-oidc", region_name=region)

    reg = oidc.register_client(clientName=CLIENT_NAME, clientType=CLIENT_TYPE)
    client_id, client_secret = reg["clientId"], reg["clientSecret"]

    auth = oidc.start_device_authorization(
        clientId=client_id,
        clientSecret=client_secret,
        startUrl=start_url,
    )

    verification_uri = auth["verificationUriComplete"]
    print("\nOpen this URL to sign in (or scan it if shown in your terminal):\n", file=sys.stderr)
    print(f"  {verification_uri}\n", file=sys.stderr)
    if open_browser:
        try:
            webbrowser.open(verification_uri)
        except Exception:
            pass  # headless environment — the printed URL is enough

    interval = auth.get("interval", 5)
    deadline = time.time() + auth.get("expiresIn", 600)

    while time.time() < deadline:
        try:
            token = oidc.create_token(
                clientId=client_id,
                clientSecret=client_secret,
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=auth["deviceCode"],
            )
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AuthorizationPendingException":
                time.sleep(interval)
                continue
            if code == "SlowDownException":
                interval += 5
                time.sleep(interval)
                continue
            if code == "ExpiredTokenException":
                raise SsoLoginError("Device code expired before approval — run login again.") from e
            raise SsoLoginError(f"SSO login failed: {code}") from e
    else:
        raise SsoLoginError("Timed out waiting for browser approval.")

    expires_at = time.time() + token.get("expiresIn", 28800)
    cache.put(
        cache_key,
        {
            "accessToken": token["accessToken"],
            "expiresAt": expires_at,
            "issuedAt": time.time(),
        },
    )
    return SsoToken(
        access_token=token["accessToken"],
        expires_at=expires_at,
        region=region,
        start_url=start_url,
    )


def _invalidate_if_token_rejected(sso_token: SsoToken, e: ClientError) -> None:
    """If `e` means AWS rejected the access token itself (not just denied the
    specific action), clear it from the cache and raise a clear error instead
    of letting the raw ClientError propagate. Otherwise, re-raise as-is.
    """
    code = e.response.get("Error", {}).get("Code")
    if code in _TOKEN_INVALID_CODES:
        cache.clear(_token_cache_key(sso_token.start_url, sso_token.region))
        raise SsoTokenExpiredError(
            "Your cached SSO session was rejected by AWS (it may have expired "
            "or been revoked). The cached token has been cleared — run "
            "`ssobroker login` again."
        ) from e
    raise


def list_accounts(sso_token: SsoToken) -> list[dict[str, str]]:
    client = boto3.client("sso", region_name=sso_token.region)
    accounts: list[dict[str, str]] = []
    try:
        paginator = client.get_paginator("list_accounts")
        for page in paginator.paginate(accessToken=sso_token.access_token):
            for item in page.get("accountList", []):
                accounts.append(
                    {
                        "accountId": item.get("accountId", ""),
                        "accountName": item.get("accountName", ""),
                    }
                )
    except ClientError as e:
        _invalidate_if_token_rejected(sso_token, e)
    return accounts


def list_account_roles(sso_token: SsoToken, account_id: str) -> list[str]:
    client = boto3.client("sso", region_name=sso_token.region)
    roles: list[str] = []
    try:
        paginator = client.get_paginator("list_account_roles")
        for page in paginator.paginate(accessToken=sso_token.access_token, accountId=account_id):
            roles.extend(r["roleName"] for r in page.get("roleList", []))
    except ClientError as e:
        _invalidate_if_token_rejected(sso_token, e)
    return roles


def get_role_credentials(sso_token: SsoToken, account_id: str, role_name: str) -> dict:
    """Return short-lived STS-style credentials for account_id/role_name.

    Cached under a key scoped to (account, role) so a re-run within the
    credential lifetime (~1h) reuses them instead of re-prompting AWS.
    """
    cache_key = f"role-creds_{account_id}_{role_name}"
    cached = cache.get(cache_key)
    if cached:
        return cached["credentials"]

    client = boto3.client("sso", region_name=sso_token.region)
    try:
        resp = client.get_role_credentials(
            roleName=role_name,
            accountId=account_id,
            accessToken=sso_token.access_token,
        )
    except ClientError as e:
        _invalidate_if_token_rejected(sso_token, e)
        raise  # unreachable: the helper above always raises or re-raises
    creds = resp["roleCredentials"]
    normalized = {
        "AccessKeyId": creds["accessKeyId"],
        "SecretAccessKey": creds["secretAccessKey"],
        "SessionToken": creds["sessionToken"],
        "Expiration": creds["expiration"],  # epoch ms
    }
    cache.put(
        cache_key,
        {"credentials": normalized, "expiresAt": creds["expiration"] / 1000.0},
    )
    return normalized
