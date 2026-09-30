from __future__ import annotations

import time

import ssobroker
from ssobroker import cache, network
from ssobroker.config import OrgConfig


def _cfg(**kw) -> OrgConfig:
    return OrgConfig(
        name="t",
        sso_start_url="https://x.awsapps.com/start",
        sso_region="us-east-1",
        default_region="us-east-1",
        accounts={},
        **kw,
    )


def test_network_settings_applied_to_environment(monkeypatch):
    for name in ("AWS_CA_BUNDLE", "HTTPS_PROXY", "AWS_USE_FIPS_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)
    network.apply(
        _cfg(ca_bundle="/etc/corp-ca.pem", https_proxy="http://proxy:8080", use_fips_endpoint=True)
    )
    import os

    assert os.environ["AWS_CA_BUNDLE"] == "/etc/corp-ca.pem"
    assert os.environ["HTTPS_PROXY"] == "http://proxy:8080"
    assert os.environ["AWS_USE_FIPS_ENDPOINT"] == "true"


def test_existing_environment_wins(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://mine:3128")
    network.apply(_cfg(https_proxy="http://proxy:8080"))
    import os

    assert os.environ["HTTPS_PROXY"] == "http://mine:3128"


def test_cache_keys_lists_by_prefix(tmp_path, monkeypatch):
    monkeypatch.setenv("SSOBROKER_HOME", str(tmp_path))
    cache.put("sso-token_us-east-1_a", {"expiresAt": time.time() + 60}, keyring=False)
    cache.put("role-creds_x", {"expiresAt": time.time() + 60})
    assert cache.keys("sso-token_") == ["sso-token_us-east-1_a"]


def test_version_comes_from_package_metadata():
    from importlib.metadata import version

    assert ssobroker.__version__ == version("aws-sso-broker")
