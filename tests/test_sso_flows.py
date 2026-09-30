"""Tests for the login flows, client-registration caching, server-side
logout, and how cached role credentials are bound to the SSO token."""

from __future__ import annotations

import base64
import hashlib
import threading
import time
import urllib.request
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from botocore.exceptions import ClientError

from ssobroker import cache, sso

START_URL = "https://example.awsapps.com/start"
REGION = "us-east-1"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))


class _Meta:
    endpoint_url = "https://oidc.us-east-1.amazonaws.com"


class FakeOidc:
    meta = _Meta()

    def __init__(self):
        self.register_calls: list[dict] = []
        self.create_token_calls: list[dict] = []

    def register_client(self, **kwargs):
        self.register_calls.append(kwargs)
        return {
            "clientId": "cid",
            "clientSecret": "csecret",
            "clientSecretExpiresAt": int(time.time()) + 90 * 86400,
        }

    def start_device_authorization(self, **kwargs):
        return {
            "verificationUriComplete": "https://device.sso/verify?code=ABCD",
            "deviceCode": "dev",
            "interval": 0,
            "expiresIn": 5,
        }

    def create_token(self, **kwargs):
        self.create_token_calls.append(kwargs)
        return {"accessToken": "new-token", "expiresIn": 3600, "refreshToken": "rt"}


def _browser(respond):
    """Stand-in for webbrowser.open: parse the authorize URL and call the
    loopback redirect the way Identity Center would after sign-in."""
    seen: dict = {}

    def _open(url):
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        seen.update(q)
        params = respond(q)
        target = f"{q['redirect_uri']}?{urlencode(params)}"
        threading.Thread(target=lambda: urllib.request.urlopen(target).read(), daemon=True).start()
        return True

    return _open, seen


def test_auth_code_flow_uses_pkce_and_loopback(monkeypatch):
    oidc = FakeOidc()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: oidc)
    opener, seen = _browser(lambda q: {"code": "the-code", "state": q["state"]})
    monkeypatch.setattr(sso.webbrowser, "open", opener)

    token = sso.login(START_URL, REGION)

    assert token.access_token == "new-token"
    assert seen["code_challenge_method"] == "S256"
    assert seen["redirect_uri"].startswith("http://127.0.0.1:")
    (reg,) = oidc.register_calls
    assert reg["grantTypes"] == ["authorization_code", "refresh_token"]
    assert reg["redirectUris"] == ["http://127.0.0.1/oauth/callback"]
    (call,) = oidc.create_token_calls
    assert call["grantType"] == "authorization_code"
    assert call["code"] == "the-code"
    assert call["redirectUri"] == seen["redirect_uri"]
    # The verifier sent to CreateToken must hash to the challenge in the URL.
    digest = hashlib.sha256(call["codeVerifier"].encode()).digest()
    assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == seen["code_challenge"]
    # The refresh token is never cached.
    stored = cache.get(sso._token_cache_key(START_URL, REGION))
    assert "refreshToken" not in stored


def test_auth_code_flow_rejects_wrong_state(monkeypatch):
    oidc = FakeOidc()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: oidc)
    opener, _ = _browser(lambda q: {"code": "the-code", "state": "forged"})
    monkeypatch.setattr(sso.webbrowser, "open", opener)

    with pytest.raises(sso.SsoLoginError, match="state"):
        sso.login(START_URL, REGION)
    assert oidc.create_token_calls == []


def test_auth_code_flow_surfaces_idp_error(monkeypatch):
    oidc = FakeOidc()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: oidc)
    opener, _ = _browser(lambda q: {"error": "access_denied", "state": q["state"]})
    monkeypatch.setattr(sso.webbrowser, "open", opener)

    with pytest.raises(sso.SsoLoginError, match="access_denied"):
        sso.login(START_URL, REGION)


def test_auth_code_flow_times_out_cleanly(monkeypatch):
    oidc = FakeOidc()
    with pytest.raises(sso.SsoLoginError, match="--use-device-code"):
        sso._auth_code_flow(oidc, START_URL, REGION, open_browser=False, timeout=0.1)


def test_device_code_flow_still_works(monkeypatch):
    oidc = FakeOidc()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: oidc)
    token = sso.login(START_URL, REGION, open_browser=False, flow="device_code")
    assert token.access_token == "new-token"
    assert oidc.create_token_calls[0]["grantType"].endswith("device_code")


def test_device_code_refused_when_policy_disallows(monkeypatch):
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: pytest.fail("called AWS"))
    with pytest.raises(sso.SsoLoginError, match="disabled"):
        sso.login(START_URL, REGION, flow="device_code", allow_device_code=False)


def test_client_registration_is_cached(monkeypatch):
    oidc = FakeOidc()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: oidc)
    sso.login(START_URL, REGION, open_browser=False, flow="device_code")
    cache.clear(sso._token_cache_key(START_URL, REGION))
    sso.login(START_URL, REGION, open_browser=False, flow="device_code")
    assert len(oidc.register_calls) == 1


# --- logout ----------------------------------------------------------------------


class FakePortal:
    def __init__(self, error: str | None = None):
        self.logged_out: list[str] = []
        self.error = error

    def logout(self, accessToken):
        if self.error:
            raise ClientError({"Error": {"Code": self.error, "Message": "x"}}, "Logout")
        self.logged_out.append(accessToken)


def _cache_token(access_token="tok"):
    now = time.time()
    cache.put(
        sso._token_cache_key(START_URL, REGION),
        {"accessToken": access_token, "expiresAt": now + 3600, "issuedAt": now, "region": REGION},
    )


def test_logout_signs_out_at_aws_then_clears(monkeypatch):
    portal = FakePortal()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: portal)
    _cache_token()
    cleared, errors = sso.logout()
    assert portal.logged_out == ["tok"]
    assert cleared == 1 and errors == []
    assert cache.get(sso._token_cache_key(START_URL, REGION)) is None


def test_logout_treats_already_invalid_token_as_success(monkeypatch):
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: FakePortal("UnauthorizedException"))
    _cache_token()
    _, errors = sso.logout()
    assert errors == []


def test_logout_clears_locally_even_if_aws_unreachable(monkeypatch):
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: FakePortal("InternalServerError"))
    _cache_token()
    cleared, errors = sso.logout()
    assert cleared == 1
    assert errors and "InternalServerError" in errors[0]


# --- role credential cache --------------------------------------------------------


class FakeSso:
    def __init__(self):
        self.calls = 0

    def get_role_credentials(self, **kwargs):
        self.calls += 1
        return {
            "roleCredentials": {
                "accessKeyId": f"AKIA{self.calls}",
                "secretAccessKey": "s",
                "sessionToken": "t",
                "expiration": int((time.time() + 3600) * 1000),
            }
        }


def _token(access_token="tok", start_url=START_URL, storage="file"):
    return sso.SsoToken(access_token, time.time() + 3600, REGION, start_url, storage)


def test_role_credentials_reused_under_same_token(monkeypatch):
    fake = FakeSso()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake)
    first, fresh1 = sso.fetch_role_credentials(_token(), "111", "ro")
    second, fresh2 = sso.fetch_role_credentials(_token(), "111", "ro")
    assert (fresh1, fresh2) == (True, False)
    assert first == second and fake.calls == 1


def test_role_credentials_not_reused_after_relogin(monkeypatch):
    fake = FakeSso()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake)
    sso.fetch_role_credentials(_token("old"), "111", "ro")
    _, fresh = sso.fetch_role_credentials(_token("new"), "111", "ro")
    assert fresh and fake.calls == 2


def test_role_credentials_not_shared_across_identity_center_instances(monkeypatch):
    fake = FakeSso()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake)
    sso.fetch_role_credentials(_token(start_url="https://a.awsapps.com/start"), "111", "ro")
    sso.fetch_role_credentials(_token(start_url="https://b.awsapps.com/start"), "111", "ro")
    assert fake.calls == 2


def test_role_credentials_refreshed_when_nearly_expired(monkeypatch):
    fake = FakeSso()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake)
    token = _token()
    key = sso._role_creds_cache_key(token, "111", "ro")
    cache.put(
        key,
        {
            "credentials": {"AccessKeyId": "STALE"},
            "expiresAt": time.time() + 60,
            "tokenFingerprint": sso._token_fingerprint(token),
        },
    )
    creds, fresh = sso.fetch_role_credentials(token, "111", "ro")
    assert fresh and creds["AccessKeyId"] != "STALE"


def test_role_credentials_never_cached_with_storage_none(monkeypatch):
    fake = FakeSso()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake)
    sso.fetch_role_credentials(_token(storage="none"), "111", "ro")
    sso.fetch_role_credentials(_token(storage="none"), "111", "ro")
    assert fake.calls == 2
    assert cache.keys("role-creds_") == []


def test_keyring_storage_without_keyring_does_not_write_a_file(monkeypatch):
    fake = FakeSso()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake)
    monkeypatch.setattr(cache, "keyring_available", lambda: False)
    sso.fetch_role_credentials(_token(storage="keyring"), "111", "ro")
    assert cache.keys("role-creds_") == []


class FakeKeyring:
    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service, key):
        return self.store.get((service, key))

    def set_password(self, service, key, value):
        self.store[(service, key)] = value

    def delete_password(self, service, key):
        self.store.pop((service, key), None)


def test_keyring_storage_keeps_role_credentials_out_of_files(monkeypatch):
    fake = FakeSso()
    kr = FakeKeyring()
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake)
    monkeypatch.setattr(cache, "_keyring_module", lambda: kr)

    sso.fetch_role_credentials(_token(storage="keyring"), "111", "ro")
    _, fresh = sso.fetch_role_credentials(_token(storage="keyring"), "111", "ro")

    assert not fresh and fake.calls == 1
    assert not list(cache.cache_dir().glob("role-creds_*.json"))
    assert len(kr.store) == 1
    assert cache.clear() == 1
    assert kr.store == {}
