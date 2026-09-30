"""Shared test isolation: no test may see a real machine-wide policy file or
inherit audit settings from another test."""

from __future__ import annotations

import pytest

from ssobroker import audit, policy


@pytest.fixture(autouse=True)
def _no_managed_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "managed_policy_path", lambda: tmp_path / "no-policy.yaml")
    policy.load.cache_clear()
    audit.configure(audit.AuditSettings())
    yield
    policy.load.cache_clear()
    audit.configure(audit.AuditSettings())


def write_policy(monkeypatch, tmp_path, text: str):
    """Install `text` as the managed policy for one test."""
    path = tmp_path / "managed" / "policy.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text)
    monkeypatch.setattr(policy, "managed_policy_path", lambda: path)
    monkeypatch.setattr(policy, "_check_trusted", lambda p: None)
    policy.load.cache_clear()
    return path
