"""ssobroker — ephemeral AWS multi-account credential manager.

Built on IAM Identity Center (AWS SSO). Never stores long-lived access keys;
all credentials are short-lived, cached locally with an expiry, and scoped to
the account/role/session the user explicitly requests.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aws-sso-broker")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"
