"""Local cache for SSO tokens and assumed-role credentials.

SSO tokens (the most sensitive entries — they're bearer credentials valid
for hours) are stored in the OS keychain via the optional `keyring` package
when it's installed and a working backend is available (macOS Keychain,
Windows Credential Manager, Secret Service/KWallet on Linux). Everything
else, and the token fallback when no keychain is available, lives under
~/.ssobroker/cache as 0600 files. Nothing here is ever transmitted anywhere
except back to AWS SSO/STS endpoints. Every read checks expiry before
handing anything back.

Install the `keyring` extra to enable OS-keychain storage:
    pip install "aws-sso-broker[keyring]"
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

from .paths import home_dir

KEYRING_SERVICE = "ssobroker"
# SSO tokens go through the OS keychain by default. Role credentials only do
# when the caller asks (role_credential_cache: keyring in orgs.yaml).
_KEYRING_ELIGIBLE_PREFIX = "sso-token_"


def _keyring_module():
    """Lazily import keyring and confirm it has a usable backend. Returns
    the module, or None if unavailable/unusable — callers fall back to the
    file cache in either case."""
    try:
        import keyring
        import keyring.errors

        # get_keyring() raises if only the no-op "fail" backend is available
        # (e.g. headless Linux with no Secret Service/KWallet running).
        backend = keyring.get_keyring()
        if backend.__class__.__module__.endswith("fail.Keyring"):
            return None
        return keyring
    except Exception:
        return None


def keyring_available() -> bool:
    return _keyring_module() is not None


def cache_dir() -> Path:
    base = home_dir()
    d = base / "cache"
    d.mkdir(parents=True, exist_ok=True)
    _lock_down(base)
    _lock_down(d)
    return d


def _lock_down(path: Path) -> None:
    """Best-effort: restrict to owner-only (0700 dirs / 0600 files)."""
    try:
        if path.is_dir():
            os.chmod(path, stat.S_IRWXU)
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # e.g. Windows — best effort only


def _write_locked_down(path: Path, data: str) -> None:
    """Create/overwrite `path` with owner-only permissions in place, rather
    than writing with the default (often world-readable) mode and chmod'ing
    afterward — which leaves a brief window where a brand-new cache file,
    containing a live token or credentials, is readable by anyone. Still
    best-effort on Windows, where os.open()'s mode argument doesn't map onto
    real ACLs (see _lock_down above) — the final _lock_down call here mainly
    matters for the case the file already existed with looser permissions.
    """
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
    finally:
        _lock_down(path)


def _path_for(key: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)
    return cache_dir() / f"{safe}.json"


def _keyring_index_path() -> Path:
    return cache_dir() / ".keyring_index.json"


def _keyring_index() -> set[str]:
    p = _keyring_index_path()
    if not p.exists():
        return set()
    try:
        return set(json.loads(p.read_text()))
    except (json.JSONDecodeError, OSError):
        return set()


def _keyring_index_add(key: str) -> None:
    idx = _keyring_index()
    idx.add(key)
    _write_locked_down(_keyring_index_path(), json.dumps(sorted(idx)))


def _keyring_index_remove(key: str) -> None:
    idx = _keyring_index()
    if key not in idx:
        return
    idx.discard(key)
    _write_locked_down(_keyring_index_path(), json.dumps(sorted(idx)))


def _use_keyring_for(key: str, keyring: bool | None) -> bool:
    if keyring is not None:
        return keyring
    return key.startswith(_KEYRING_ELIGIBLE_PREFIX)


def keys(prefix: str) -> list[str]:
    """Every cached key starting with `prefix`, file-based or in the keychain."""
    found = {p.stem for p in cache_dir().glob(f"{prefix}*.json")}
    found |= {k for k in _keyring_index() if k.startswith(prefix)}
    return sorted(found)


def get(key: str, *, keyring: bool | None = None) -> dict | None:
    """Return the cached value for `key`, or None if missing or expired.

    `keyring` picks the OS keychain (True) or the file cache only (False);
    None means the default for that key (keychain for SSO tokens)."""
    if _use_keyring_for(key, keyring):
        kr = _keyring_module()
        if kr is not None:
            try:
                raw = kr.get_password(KEYRING_SERVICE, key)
            except Exception:
                raw = None
            if raw is not None:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = None
                if data is not None:
                    expires_at = data.get("expiresAt")
                    if expires_at is not None and time.time() >= expires_at:
                        _keyring_delete(key)
                        return None
                    return data
        # Fall through to file cache — covers both "keyring unavailable"
        # and "nothing found under this key in the keychain yet".

    p = _path_for(key)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    expires_at = data.get("expiresAt")
    if expires_at is not None and time.time() >= expires_at:
        try:
            p.unlink()
        except OSError:
            pass
        return None
    return data


def put(key: str, value: dict, *, keyring: bool | None = None) -> None:
    if _use_keyring_for(key, keyring):
        kr = _keyring_module()
        if kr is not None:
            try:
                kr.set_password(KEYRING_SERVICE, key, json.dumps(value))
                _keyring_index_add(key)
                # Make sure a stale file-based copy from a previous run
                # (e.g. keyring became available after being unavailable)
                # doesn't shadow the keychain entry.
                p = _path_for(key)
                if p.exists():
                    p.unlink()
                return
            except Exception:
                pass  # fall back to file cache below

    p = _path_for(key)
    _write_locked_down(p, json.dumps(value))


def _keyring_delete(key: str) -> None:
    kr = _keyring_module()
    if kr is not None:
        try:
            kr.delete_password(KEYRING_SERVICE, key)
        except Exception:
            pass
    _keyring_index_remove(key)


def clear(key: str | None = None) -> int:
    """Remove one cache entry, or every entry if key is None. Returns count removed."""
    removed = 0

    if key:
        if key in _keyring_index():
            _keyring_delete(key)
            removed += 1
        p = _path_for(key)
        if p.exists():
            p.unlink()
            removed += 1
        return removed

    # Clear everything: file-based entries...
    d = cache_dir()
    for p in d.glob("*.json"):
        if p.name == ".keyring_index.json":
            continue
        p.unlink()
        removed += 1

    # ...and every keychain entry we've ever recorded in the index.
    for indexed_key in list(_keyring_index()):
        _keyring_delete(indexed_key)
        removed += 1

    idx_path = _keyring_index_path()
    if idx_path.exists():
        idx_path.unlink()

    return removed
