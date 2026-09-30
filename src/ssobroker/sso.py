"""IAM Identity Center (AWS SSO) login and role credential retrieval.

Two login flows, both standard AWS SSO OIDC grants:

- Authorization code with PKCE (default, same as AWS CLI v2.22+). ssobroker
  listens on a random 127.0.0.1 port, opens the Identity Center authorize
  page, and receives the code on the loopback redirect. Only the browser on
  this machine can complete it, so a phished link can't be approved from
  somewhere else.
- Device authorization (`login_flow: device_code` or `login --use-device-code`)
  for headless machines with no local browser. The approval URL can be opened
  on any device, which is exactly what device-code phishing abuses, so an
  admin can turn it off with the managed policy.

Either way the result is an SSO access token (cached, short-lived) that is
exchanged for short-lived role credentials — never a long-lived key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import boto3
from botocore.exceptions import ClientError

from . import cache

CLIENT_NAME = "ssobroker"
CLIENT_TYPE = "public"
SSO_SCOPES = ["sso:account:access"]
# Registered once; any loopback port is accepted at authorize time (RFC 8252).
_REGISTERED_REDIRECT_URI = "http://127.0.0.1/oauth/callback"
_CALLBACK_PATH = "/oauth/callback"

# Default cap on how long a cached SSO token is trusted, independent of its
# server-side expiry. Overridden by OrgConfig.max_session_hours (see config.py).
DEFAULT_MAX_SESSION_HOURS = 8

# Cached role credentials with less than this left are refreshed instead of
# being handed to a command that may outlive them.
ROLE_CREDS_REFRESH_MARGIN_SECONDS = 300

# Re-register the OIDC client this long before its secret actually expires.
_CLIENT_REGISTRATION_MARGIN_SECONDS = 3600

_LOGIN_TIMEOUT_SECONDS = 600


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
    # Where role credentials fetched with this token are cached: "file",
    # "keyring", or "none" (see role_credential_cache in orgs.yaml).
    role_credential_cache: str = "file"


def _digest(value: str, n: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:n]


def _token_cache_key(start_url: str, region: str) -> str:
    # Must be stable across processes — the builtin hash() is randomized per
    # interpreter run (PYTHONHASHSEED), which made every invocation miss the cache.
    return f"sso-token_{region}_{_digest(start_url)}"


def _client_cache_key(start_url: str, region: str, flow: str) -> str:
    return f"sso-client_{region}_{_digest(start_url)}_{flow}"


def _role_creds_cache_key(sso_token: SsoToken, account_id: str, role_name: str) -> str:
    return f"role-creds_{_digest(sso_token.start_url)}_{account_id}_{role_name}"


def _token_fingerprint(sso_token: SsoToken) -> str:
    return _digest(sso_token.access_token, 32)


def login(
    start_url: str,
    region: str,
    *,
    open_browser: bool = True,
    max_session_hours: float = DEFAULT_MAX_SESSION_HOURS,
    flow: str = "auth_code",
    allow_device_code: bool = True,
    role_credential_cache: str = "file",
) -> SsoToken:
    """Return a cached SSO token, or run a login flow to get a new one.

    All diagnostic output (the sign-in URL, prompts) goes to stderr — never
    stdout — so this function is safe to call from a command whose stdout
    must be clean machine-readable output (see `creds-process`).
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
                role_credential_cache=role_credential_cache,
            )
        # Cached token is still server-side valid but older than our local
        # policy allows — drop it and force a fresh login.
        cache.clear(cache_key)

    if flow == "device_code" and not allow_device_code:
        raise SsoLoginError("Device-code login is disabled by the managed policy.")

    oidc = boto3.client("sso-oidc", region_name=region)
    if flow == "device_code":
        token = _device_code_flow(oidc, start_url, region, open_browser)
    elif flow == "auth_code":
        token = _auth_code_flow(oidc, start_url, region, open_browser)
    else:
        raise SsoLoginError(f"Unknown login flow {flow!r}")

    # Only the access token is kept. A refresh token, if AWS returned one, is
    # deliberately dropped: re-auth after max_session_hours is the point.
    now = time.time()
    expires_at = now + token.get("expiresIn", 28800)
    cache.put(
        cache_key,
        {
            "accessToken": token["accessToken"],
            "expiresAt": expires_at,
            "issuedAt": now,
            "region": region,
        },
    )
    return SsoToken(
        access_token=token["accessToken"],
        expires_at=expires_at,
        region=region,
        start_url=start_url,
        role_credential_cache=role_credential_cache,
    )


def _registered_client(oidc, start_url: str, region: str, flow: str) -> tuple[str, str]:
    """Reuse a cached OIDC client registration (valid ~90 days) instead of
    calling RegisterClient on every login."""
    key = _client_cache_key(start_url, region, flow)
    cached = cache.get(key)
    if cached:
        return cached["clientId"], cached["clientSecret"]

    kwargs: dict = {"clientName": CLIENT_NAME, "clientType": CLIENT_TYPE}
    if flow == "auth_code":
        kwargs.update(
            grantTypes=["authorization_code", "refresh_token"],
            redirectUris=[_REGISTERED_REDIRECT_URI],
            issuerUrl=start_url,
            scopes=SSO_SCOPES,
        )
    reg = oidc.register_client(**kwargs)
    expires_at = reg.get("clientSecretExpiresAt")
    if expires_at:
        cache.put(
            key,
            {
                "clientId": reg["clientId"],
                "clientSecret": reg["clientSecret"],
                "expiresAt": expires_at - _CLIENT_REGISTRATION_MARGIN_SECONDS,
            },
            keyring=False,
        )
    return reg["clientId"], reg["clientSecret"]


def _show_url(url: str, open_browser: bool, what: str) -> None:
    print(f"\n{what}\n", file=sys.stderr)
    print(f"  {url}\n", file=sys.stderr)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass  # headless environment — the printed URL is enough


def _device_code_flow(oidc, start_url: str, region: str, open_browser: bool) -> dict:
    client_id, client_secret = _registered_client(oidc, start_url, region, "device_code")
    auth = oidc.start_device_authorization(
        clientId=client_id,
        clientSecret=client_secret,
        startUrl=start_url,
    )
    _show_url(
        auth["verificationUriComplete"],
        open_browser,
        "Open this URL to sign in. Only approve a request you started yourself:",
    )

    interval = auth.get("interval", 5)
    deadline = time.time() + auth.get("expiresIn", _LOGIN_TIMEOUT_SECONDS)

    while time.time() < deadline:
        try:
            return oidc.create_token(
                clientId=client_id,
                clientSecret=client_secret,
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=auth["deviceCode"],
            )
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
            if code == "InvalidClientException":
                cache.clear(_client_cache_key(start_url, region, "device_code"))
            raise SsoLoginError(f"SSO login failed: {code}") from e
    raise SsoLoginError("Timed out waiting for browser approval.")


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.rstrip(b"=").decode()


class _CallbackResult:
    def __init__(self) -> None:
        self.params: dict[str, str] | None = None
        self.done = threading.Event()


def _make_handler(result: _CallbackResult):
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — http.server naming
            parsed = urlparse(self.path)
            if parsed.path != _CALLBACK_PATH:
                self.send_response(404)
                self.end_headers()
                return
            query = parse_qs(parsed.query)
            result.params = {k: v[0] for k, v in query.items()}
            ok = "code" in result.params
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            msg = "Signed in. You can close this tab." if ok else "Sign-in failed."
            self.wfile.write(f"<!doctype html><title>ssobroker</title><p>{msg}</p>".encode())
            result.done.set()

        def log_message(self, format: str, *args: object) -> None:
            pass  # keep the code out of stderr

    return _Handler


def _auth_code_flow(
    oidc, start_url: str, region: str, open_browser: bool, timeout: float = _LOGIN_TIMEOUT_SECONDS
) -> dict:
    client_id, client_secret = _registered_client(oidc, start_url, region, "auth_code")
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)

    result = _CallbackResult()
    server = HTTPServer(("127.0.0.1", 0), _make_handler(result))
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}{_CALLBACK_PATH}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        query = urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge_method": "S256",
                "scopes": " ".join(SSO_SCOPES),
                "code_challenge": challenge,
            }
        )
        _show_url(
            f"{oidc.meta.endpoint_url}/authorize?{query}",
            open_browser,
            "Opening your browser to sign in. If it doesn't open, visit this URL on this machine:",
        )
        if not result.done.wait(timeout):
            raise SsoLoginError(
                "Timed out waiting for browser sign-in. On a machine with no local "
                "browser, use `ssobroker login --use-device-code`."
            )
    finally:
        server.shutdown()
        server.server_close()

    params = result.params or {}
    if not hmac.compare_digest(params.get("state", ""), state):
        raise SsoLoginError("Sign-in response had the wrong state parameter; ignoring it.")
    if "error" in params:
        raise SsoLoginError(f"SSO sign-in failed: {params['error']}")
    if "code" not in params:
        raise SsoLoginError("SSO sign-in returned no authorization code.")

    try:
        return oidc.create_token(
            clientId=client_id,
            clientSecret=client_secret,
            grantType="authorization_code",
            code=params["code"],
            codeVerifier=verifier,
            redirectUri=redirect_uri,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidClientException":
            cache.clear(_client_cache_key(start_url, region, "auth_code"))
        raise SsoLoginError(f"SSO login failed: {code}") from e


def logout() -> tuple[int, list[str]]:
    """Sign every cached SSO token out server-side, then clear the local cache.

    Returns (entries cleared, errors). A token AWS already considers invalid
    is not an error. Role credentials that were already issued stay valid at
    AWS until they expire; this can't revoke those.
    """
    errors: list[str] = []
    for key in cache.keys("sso-token_"):
        data = cache.get(key)
        if not data:
            continue
        region = data.get("region") or key.split("_")[1]
        try:
            boto3.client("sso", region_name=region).logout(accessToken=data["accessToken"])
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code not in _TOKEN_INVALID_CODES:
                errors.append(f"{region}: {code}")
        except Exception as e:  # noqa: BLE001 — offline etc.; still clear locally
            errors.append(f"{region}: {e}")
    return cache.clear(), errors


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


def fetch_role_credentials(
    sso_token: SsoToken, account_id: str, role_name: str
) -> tuple[dict, bool]:
    """Return (credentials, fresh) for account_id/role_name.

    `fresh` is True when the credentials were just issued by AWS rather than
    read from the cache. A cached entry is only reused when it was issued
    under this same SSO token (so a re-login, a logout, or a different
    Identity Center instance never gets someone else's credentials back) and
    has more than ROLE_CREDS_REFRESH_MARGIN_SECONDS left.
    """
    storage = sso_token.role_credential_cache
    if storage == "keyring" and not cache.keyring_available():
        storage = "none"  # never fall back to a plaintext file when keyring was asked for
    use_keyring = storage == "keyring"
    cache_key = _role_creds_cache_key(sso_token, account_id, role_name)
    fingerprint = _token_fingerprint(sso_token)

    if storage != "none":
        cached = cache.get(cache_key, keyring=use_keyring)
        if (
            cached
            and cached.get("tokenFingerprint") == fingerprint
            and cached["expiresAt"] - time.time() > ROLE_CREDS_REFRESH_MARGIN_SECONDS
        ):
            return cached["credentials"], False

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
    if storage != "none":
        cache.put(
            cache_key,
            {
                "credentials": normalized,
                "expiresAt": creds["expiration"] / 1000.0,
                "tokenFingerprint": fingerprint,
            },
            keyring=use_keyring,
        )
    return normalized, True


def get_role_credentials(sso_token: SsoToken, account_id: str, role_name: str) -> dict:
    """Return short-lived STS-style credentials for account_id/role_name."""
    return fetch_role_credentials(sso_token, account_id, role_name)[0]
