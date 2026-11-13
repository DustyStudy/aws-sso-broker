"""Network settings: CA bundle, HTTPS proxy, FIPS endpoints.

boto3 and the AWS CLI already read AWS_CA_BUNDLE, HTTPS_PROXY and
AWS_USE_FIPS_ENDPOINT from the environment. orgs.yaml can set them so they
apply without editing shell profiles; there a value already set in the
environment wins. The managed policy can set them too, and its values win
over both, so an organization can require FIPS endpoints or its proxy.
Because they are set in this process's environment, commands started by
`exec`/`shell` inherit them too.
"""

from __future__ import annotations

import os

from . import policy
from .config import OrgConfig


def apply(cfg: OrgConfig) -> None:
    pol = policy.load()
    _set("AWS_CA_BUNDLE", pol.ca_bundle, cfg.ca_bundle and os.path.expanduser(cfg.ca_bundle))
    _set("HTTPS_PROXY", pol.https_proxy, cfg.https_proxy)
    if pol.https_proxy:
        # Lowercase https_proxy wins over HTTPS_PROXY, and NO_PROXY skips the
        # proxy entirely: neither may route around a proxy the policy requires.
        os.environ["https_proxy"] = pol.https_proxy
        for name in ("NO_PROXY", "no_proxy"):
            os.environ.pop(name, None)
    _set(
        "AWS_USE_FIPS_ENDPOINT",
        "true" if pol.use_fips_endpoint else None,
        "true" if cfg.use_fips_endpoint else None,
    )


def _set(name: str, forced: str | None, default: str | None) -> None:
    if forced:
        os.environ[name] = forced
    elif default:
        os.environ.setdefault(name, default)
