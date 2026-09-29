import os
import stat
import sys
import time

import pytest

from ssobroker import cache


def test_put_and_get_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("mykey", {"value": 42, "expiresAt": time.time() + 60})
    result = cache.get("mykey")
    assert result is not None
    assert result["value"] == 42


def test_expired_entry_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("expired", {"value": 1, "expiresAt": time.time() - 10})
    assert cache.get("expired") is None


def test_missing_key_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    assert cache.get("does-not-exist") is None


def test_clear_single_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("a", {"value": 1, "expiresAt": time.time() + 60})
    cache.put("b", {"value": 2, "expiresAt": time.time() + 60})
    removed = cache.clear("a")
    assert removed == 1
    assert cache.get("a") is None
    assert cache.get("b") is not None


def test_clear_all(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("a", {"value": 1, "expiresAt": time.time() + 60})
    cache.put("b", {"value": 2, "expiresAt": time.time() + 60})
    removed = cache.clear()
    assert removed == 2
    assert cache.get("a") is None
    assert cache.get("b") is None


def test_sso_token_key_roundtrips_without_keyring(tmp_path, monkeypatch):
    """sso-token_* keys attempt the OS keychain first, but must still work
    correctly (via the file-based fallback) on a system with no keyring
    backend available — e.g. this test environment, and most CI runners."""
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("sso-token_us-east-1_123", {"accessToken": "abc", "expiresAt": time.time() + 60})
    result = cache.get("sso-token_us-east-1_123")
    assert result is not None
    assert result["accessToken"] == "abc"


def test_sso_token_key_respects_expiry(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("sso-token_expired", {"accessToken": "x", "expiresAt": time.time() - 10})
    assert cache.get("sso-token_expired") is None


def test_put_creates_new_files_with_owner_only_mode_atomically(tmp_path, monkeypatch):
    # Regression: the old implementation wrote with Path.write_text() (mode
    # dictated by the process umask, often world-readable) and only
    # restricted access with chmod() afterward — a real window during which
    # a brand-new token/credentials file was readable by anyone. os.open()
    # with O_CREAT and an explicit mode sets the permissions atomically at
    # creation time instead.
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    calls = []
    real_open = os.open

    def _spy_open(path, flags, mode=0o777):
        calls.append((flags, mode))
        return real_open(path, flags, mode)

    monkeypatch.setattr(cache.os, "open", _spy_open)
    cache.put("mykey", {"value": 1, "expiresAt": time.time() + 60})

    assert calls, "expected cache.put() to create the file via os.open()"
    flags, mode = calls[-1]
    assert flags & os.O_CREAT
    assert flags & os.O_WRONLY
    assert mode == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits don't apply on Windows")
def test_put_file_has_owner_only_permissions_on_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("mykey", {"value": 1, "expiresAt": time.time() + 60})
    path = cache.cache_dir() / "mykey.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
