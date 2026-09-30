"""Where ssobroker keeps its local state (config, cache, audit log).

Defaults to ~/.ssobroker, overridable with SSOBROKER_HOME (unless the managed
policy sets `ignore_env_overrides`). Installs from before the rename (when the
tool was called orgctl) used ~/.orgctl; if that directory exists and
~/.ssobroker doesn't, it keeps being used so an existing registry, guardrails
file and audit log carry over untouched.
"""

from __future__ import annotations

from pathlib import Path

from . import policy

_LEGACY_DIRNAME = ".orgctl"


def home_dir() -> Path:
    override = policy.env_override("SSOBROKER_HOME")
    if override:
        return Path(override)
    current = Path.home() / ".ssobroker"
    legacy = Path.home() / _LEGACY_DIRNAME
    if not current.exists() and legacy.is_dir():
        return legacy
    return current
