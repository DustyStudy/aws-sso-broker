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


def test_keys_differing_only_in_replaced_characters_do_not_collide(tmp_path, monkeypatch):
    # Ops+Admin and Ops_Admin are different permission sets.
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("role-creds_x_111111111111_Ops+Admin", {"role": "plus"})
    cache.put("role-creds_x_111111111111_Ops_Admin", {"role": "underscore"})
    assert cache.get("role-creds_x_111111111111_Ops+Admin") == {"role": "plus"}


class _BrokenKeyring:
    def set_password(self, *a):
        raise RuntimeError("locked")

    def get_password(self, *a):
        return "{}"

    def delete_password(self, *a):
        raise RuntimeError("locked")


def test_explicit_keyring_never_falls_back_to_a_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    monkeypatch.setattr(cache, "_keyring_module", lambda: _BrokenKeyring())
    cache.put("role-creds_k", {"secret": "x"}, keyring=True)
    assert not list(cache.cache_dir().glob("role-creds_*.json"))


def test_failed_keyring_delete_stays_indexed(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    monkeypatch.setattr(cache, "_keyring_module", lambda: _BrokenKeyring())
    cache._keyring_index_add("sso-token_us-east-1_abc")
    cache.clear()
    assert cache.keys("sso-token_") == ["sso-token_us-east-1_abc"]


def test_explicit_keyring_without_a_keychain_writes_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    monkeypatch.setattr(cache, "_keyring_module", lambda: None)
    cache.put("role-creds_k", {"secret": "x"}, keyring=True)
    assert not list(cache.cache_dir().glob("role-creds_*.json"))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")
def test_windows_state_folder_gets_a_private_acl(tmp_path, monkeypatch):
    import subprocess

    def icacls(*args):
        return subprocess.run(["icacls", *args], capture_output=True, text=True, check=True).stdout

    home = tmp_path / "home"
    (home / "cache").mkdir(parents=True)
    (home / "audit.log").write_text("from before the ACL")
    (home / "explicit.txt").write_text("x")
    icacls(str(home / "explicit.txt"), "/grant", "*S-1-1-0:R")  # explicit Everyone
    (home / "protected.txt").write_text("x")
    icacls(str(home / "protected.txt"), "/inheritance:d")  # keeps a copy, blocks inheritance
    monkeypatch.setenv("SSOBROKER_HOME", str(home))

    def assert_private():
        acl = icacls(str(home), "/T")
        assert "audit.log" in acl and "protected.txt" in acl
        for broad in ("Everyone", "BUILTIN\\Users", "Authenticated Users"):
            assert broad not in acl

    cache.put("mykey", {"value": 1})
    assert_private()
    # Loosened later (e.g. restored from a copy): the next run puts it back.
    icacls(str(home), "/grant", "*S-1-1-0:(OI)(CI)R")
    cache.cache_dir()
    assert_private()
    # Only a file loosened, folder still right: the file is fixed too.
    icacls(str(home / "audit.log"), "/grant", "*S-1-1-0:R")
    cache.cache_dir()
    assert_private()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need admin on Windows")
def test_put_never_writes_through_a_planted_symlink(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path / "home"))
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    (cache.cache_dir() / "mykey.json").symlink_to(victim)
    cache.put("mykey", {"value": 1})
    assert victim.read_text() == "keep me"
    assert cache.get("mykey") == {"value": 1}


def test_concurrent_keyring_index_adds_keep_every_entry(tmp_path, monkeypatch):
    import threading

    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    keys = [f"sso-token_r_{i}" for i in range(20)]
    threads = [threading.Thread(target=cache._keyring_index_add, args=(k,)) for k in keys]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert cache.keys("sso-token_") == sorted(keys)
