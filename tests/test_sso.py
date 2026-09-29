import os
import subprocess
import sys
import time

import pytest
from botocore.exceptions import ClientError

from ssobroker import cache, sso

START_URL = "https://example.awsapps.com/start"
REGION = "us-east-1"


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "GetRoleCredentials")


class _FakePaginator:
    def __init__(self, error: ClientError | None, pages: list[dict]):
        self._error = error
        self._pages = pages

    def paginate(self, **kwargs):
        if self._error:
            raise self._error
        yield from self._pages


class _FakeSsoClient:
    def __init__(self, error: ClientError | None = None, pages: list[dict] | None = None):
        self._error = error
        self._pages = pages or []
        self.get_role_credentials_error = error

    def get_paginator(self, name):
        return _FakePaginator(self._error, self._pages)

    def get_role_credentials(self, **kwargs):
        if self.get_role_credentials_error:
            raise self.get_role_credentials_error
        raise AssertionError("not stubbed for this test")


def _token(tmp_path, monkeypatch) -> sso.SsoToken:
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    return sso.SsoToken(
        access_token="tok", expires_at=time.time() + 3600, region=REGION, start_url=START_URL
    )


def _key_in_subprocess(hash_seed: str) -> str:
    code = f"from ssobroker import sso; print(sso._token_cache_key({START_URL!r}, {REGION!r}))"
    env = {**os.environ, "PYTHONHASHSEED": hash_seed}
    out = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def test_token_cache_key_is_stable_across_processes():
    # Regression: the key used the builtin hash(), which is randomized per
    # process, so a token cached by one invocation was never found by the next.
    keys = {_key_in_subprocess(seed) for seed in ("1", "2", "3")}
    assert len(keys) == 1


def test_token_cache_key_differs_per_start_url_and_region():
    a = sso._token_cache_key("https://a.awsapps.com/start", REGION)
    b = sso._token_cache_key("https://b.awsapps.com/start", REGION)
    c = sso._token_cache_key("https://a.awsapps.com/start", "eu-west-1")
    assert len({a, b, c}) == 3


def test_token_cache_key_is_filename_safe():
    key = sso._token_cache_key(START_URL, REGION)
    assert all(ch.isalnum() or ch in "-_" for ch in key)


def test_login_reuses_cached_token_without_calling_aws(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    now = time.time()
    cache.put(
        sso._token_cache_key(START_URL, REGION),
        {"accessToken": "cached-token", "expiresAt": now + 3600, "issuedAt": now},
    )

    def _no_aws(*args, **kwargs):
        raise AssertionError("login() should have used the cached token, not called AWS")

    monkeypatch.setattr(sso.boto3, "client", _no_aws)

    token = sso.login(START_URL, REGION, open_browser=False)
    assert token.access_token == "cached-token"


def test_login_ignores_cached_token_older_than_max_session(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    now = time.time()
    key = sso._token_cache_key(START_URL, REGION)
    cache.put(
        key,
        {"accessToken": "old", "expiresAt": now + 3600, "issuedAt": now - 10 * 3600},
    )

    class _StopHere(Exception):
        pass

    def _fresh_login_attempted(*args, **kwargs):
        raise _StopHere

    monkeypatch.setattr(sso.boto3, "client", _fresh_login_attempted)

    with pytest.raises(_StopHere):
        sso.login(START_URL, REGION, open_browser=False, max_session_hours=8)
    assert cache.get(key) is None


@pytest.mark.parametrize("code", ["UnauthorizedException", "ForbiddenException"])
def test_get_role_credentials_clears_token_and_raises_clean_error(tmp_path, monkeypatch, code):
    # Regression: a revoked/expired SSO token made get_role_credentials raise
    # a raw botocore ClientError, and the (now-useless) cached token was never
    # cleared, so the caller was stuck until they knew to run `ssobroker logout`.
    token = _token(tmp_path, monkeypatch)
    cache.put(
        sso._token_cache_key(START_URL, REGION),
        {"accessToken": "tok", "expiresAt": time.time() + 3600, "issuedAt": time.time()},
    )

    fake_client = _FakeSsoClient(error=_client_error(code))
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake_client)

    with pytest.raises(sso.SsoTokenExpiredError):
        sso.get_role_credentials(token, "111111111111", "ro")

    assert cache.get(sso._token_cache_key(START_URL, REGION)) is None


def test_list_accounts_clears_token_and_raises_clean_error(tmp_path, monkeypatch):
    token = _token(tmp_path, monkeypatch)
    cache.put(
        sso._token_cache_key(START_URL, REGION),
        {"accessToken": "tok", "expiresAt": time.time() + 3600, "issuedAt": time.time()},
    )

    fake_client = _FakeSsoClient(error=_client_error("UnauthorizedException"))
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake_client)

    with pytest.raises(sso.SsoTokenExpiredError):
        sso.list_accounts(token)

    assert cache.get(sso._token_cache_key(START_URL, REGION)) is None


def test_list_account_roles_clears_token_and_raises_clean_error(tmp_path, monkeypatch):
    token = _token(tmp_path, monkeypatch)
    cache.put(
        sso._token_cache_key(START_URL, REGION),
        {"accessToken": "tok", "expiresAt": time.time() + 3600, "issuedAt": time.time()},
    )

    fake_client = _FakeSsoClient(error=_client_error("UnauthorizedException"))
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake_client)

    with pytest.raises(sso.SsoTokenExpiredError):
        sso.list_account_roles(token, "111111111111")

    assert cache.get(sso._token_cache_key(START_URL, REGION)) is None


def test_get_role_credentials_other_client_errors_pass_through_unaltered(tmp_path, monkeypatch):
    # A denial that has nothing to do with the token itself (e.g. the role
    # legitimately cannot do this) must NOT be swallowed/reinterpreted, and
    # must not nuke a perfectly good cached token.
    token = _token(tmp_path, monkeypatch)
    cache.put(
        sso._token_cache_key(START_URL, REGION),
        {"accessToken": "tok", "expiresAt": time.time() + 3600, "issuedAt": time.time()},
    )

    fake_client = _FakeSsoClient(error=_client_error("AccessDeniedException"))
    monkeypatch.setattr(sso.boto3, "client", lambda *a, **k: fake_client)

    with pytest.raises(ClientError):
        sso.get_role_credentials(token, "111111111111", "ro")

    assert cache.get(sso._token_cache_key(START_URL, REGION)) is not None
