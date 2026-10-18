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

import contextlib
import functools
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
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
    if sys.platform == "win32":
        _ensure_private_acl(base)
    return d


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _SE_FILE_OBJECT = 1
    _DACL_INFO = 0x4
    _PROTECTED_DACL = 0x80000000
    _UNPROTECTED_DACL = 0x20000000
    _SDDL_REVISION_1 = 1
    _DRIVE_REMOTE = 4
    _ACE_RE = re.compile(r"\(([^)]*)\)")

    @functools.cache
    def _current_user_sid() -> str:
        out = subprocess.run(
            [
                os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "whoami.exe"),
                "/user",
                "/fo",
                "csv",
                "/nh",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return out.strip().split(",")[-1].strip('"')

    def _dacl_sddl(path: Path) -> str:
        sd = ctypes.c_void_p()
        err = _advapi32.GetNamedSecurityInfoW(
            str(path), _SE_FILE_OBJECT, _DACL_INFO, None, None, None, None, ctypes.byref(sd)
        )
        if err:
            raise ctypes.WinError(err)
        try:
            text = ctypes.c_wchar_p()
            if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, _SDDL_REVISION_1, _DACL_INFO, ctypes.byref(text), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return str(text.value)
            finally:
                _kernel32.LocalFree(text)
        finally:
            _kernel32.LocalFree(sd)

    def _set_dacl(path: Path, sddl: str, flags: int) -> None:
        """Replace the DACL of `path` in one call, so it is never briefly empty."""
        sd = ctypes.c_void_p()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(sd), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            dacl = ctypes.c_void_p()
            if not _advapi32.GetSecurityDescriptorDacl(
                sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            err = _advapi32.SetNamedSecurityInfoW(
                str(path), _SE_FILE_OBJECT, _DACL_INFO | flags, None, None, dacl, None
            )
            if err:
                raise ctypes.WinError(err)
        finally:
            _kernel32.LocalFree(sd)

    def _on_network_drive(path: Path) -> bool:
        drive = os.path.splitdrive(os.path.abspath(path))[0]
        return drive.startswith("\\\\") or (_kernel32.GetDriveTypeW(drive + "\\") == _DRIVE_REMOTE)

    def _ensure_private_acl(base: Path) -> None:
        """chmod can't restrict readers on Windows. Give the state folder an
        exact, non-inherited ACL (this user and SYSTEM, full control) and make
        everything in it inherit only that. Checked on every run, so a copy or
        restore that loosened it gets fixed. Skipped on network drives, where
        the share may know this user under another identity and the ACL could
        lock them out."""
        try:
            if _on_network_drive(base):
                return
            sid = _current_user_sid()
            want = sorted([f"A;OICI;FA;;;{sid}", "A;OICI;FA;;;SY"])
            current = _dacl_sddl(base)
            if not (current.startswith("D:P") and sorted(_ACE_RE.findall(current)) == want):
                _set_dacl(base, "D:P" + "".join(f"({ace})" for ace in want), _PROTECTED_DACL)
            # Files with their own explicit or protected ACL don't take the base
            # one by inheritance alone: reset any such file to "inherit only".
            for root, dirs, files in os.walk(base):
                for name in [*dirs, *files]:
                    path = Path(root) / name
                    sddl = _dacl_sddl(path)
                    aces = _ACE_RE.findall(sddl)
                    if sddl.startswith("D:P") or any("ID" not in a.split(";")[1] for a in aces):
                        _set_dacl(path, "D:AI", _UNPROTECTED_DACL)
        except (OSError, subprocess.CalledProcessError) as e:
            print(f"ssobroker: could not restrict access to {base}: {e}", file=sys.stderr)


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
    """Write `path` with owner-only permissions from the moment it exists,
    rather than writing with the default (often world-readable) mode and
    chmod'ing afterward. The data goes to a new temp file (O_EXCL, so never
    through a planted symlink) that then replaces `path`, so a reader never
    sees half a file. On Windows the folder ACL does the restricting (see
    _ensure_private_acl)."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
        _replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _replace(src: Path, dst: Path) -> None:
    for attempt in range(10):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            # Windows refuses while another process has dst open for a moment.
            if os.name != "nt" or attempt == 9:
                raise
            time.sleep(0.05)


@contextlib.contextmanager
def _index_lock() -> Iterator[None]:
    """Hold an exclusive lock while reading and rewriting the keyring index,
    so two processes logging in at once don't drop each other's entries."""
    with open(cache_dir() / ".keyring_index.lock", "a+b") as f:
        if sys.platform == "win32":
            import msvcrt

            # LK_LOCK retries only once a second, so poll the non-blocking lock instead.
            deadline = time.monotonic() + 10
            while True:
                f.seek(0)
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.02)
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


def _path_for(key: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)
    if safe != key:
        # Keep keys apart that differ only in replaced characters (Ops+Admin vs Ops_Admin).
        safe += "_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
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
    with _index_lock():
        idx = _keyring_index()
        idx.add(key)
        _write_locked_down(_keyring_index_path(), json.dumps(sorted(idx)))


def _keyring_index_remove(key: str) -> None:
    with _index_lock():
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


def get(key: str, *, keyring: bool | None = None, include_expired: bool = False) -> dict | None:
    """Return the cached value for `key`, or None if missing or expired.

    `keyring` picks the OS keychain (True) or the file cache only (False);
    None means the default for that key (keychain for SSO tokens).
    `include_expired` returns an expired entry as-is instead of deleting it."""
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
                    if not include_expired and expires_at is not None and time.time() >= expires_at:
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
    if not include_expired and expires_at is not None and time.time() >= expires_at:
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
                pass
        if keyring:
            return  # keychain was asked for explicitly: don't cache rather than write a file

    p = _path_for(key)
    _write_locked_down(p, json.dumps(value))


def _keyring_delete(key: str) -> bool:
    """Delete one keychain entry. True if it is gone."""
    kr = _keyring_module()
    if kr is None:
        return False  # keep the index entry so a later clear can still remove it
    try:
        kr.delete_password(KEYRING_SERVICE, key)
    except Exception:
        try:
            still_there = kr.get_password(KEYRING_SERVICE, key) is not None
        except Exception:
            still_there = True
        if still_there:
            return False  # keep it indexed so a later logout finds it again
    _keyring_index_remove(key)
    return True


def keyring_leftovers() -> int:
    """Keychain entries a clear could not remove (still in the index)."""
    return len(_keyring_index())


def clear(key: str | None = None) -> int:
    """Remove one cache entry, or every entry if key is None. Returns count removed."""
    removed = 0

    if key:
        if key in _keyring_index() and _keyring_delete(key):
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
        removed += _keyring_delete(indexed_key)

    return removed
