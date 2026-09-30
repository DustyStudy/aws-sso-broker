"""Corporate network settings: CA bundle, HTTPS proxy, FIPS endpoints.

boto3 and the AWS CLI already read AWS_CA_BUNDLE, HTTPS_PROXY and
AWS_USE_FIPS_ENDPOINT from the environment. orgs.yaml can set them so every
machine gets the same values without editing shell profiles. A value already
set in the environment wins. Because they are set in this process's
environment, commands started by `exec`/`shell` inherit them too.
"""

from __future__ import annotations

import os

from .config import OrgConfig


def apply(cfg: OrgConfig) -> None:
    if cfg.ca_bundle:
        os.environ.setdefault("AWS_CA_BUNDLE", os.path.expanduser(cfg.ca_bundle))
    if cfg.https_proxy:
        os.environ.setdefault("HTTPS_PROXY", cfg.https_proxy)
    if cfg.use_fips_endpoint:
        os.environ.setdefault("AWS_USE_FIPS_ENDPOINT", "true")
