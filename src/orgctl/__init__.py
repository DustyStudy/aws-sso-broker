"""orgctl — ephemeral AWS multi-account credential manager.

Built on IAM Identity Center (AWS SSO). Never stores long-lived access keys;
all credentials are short-lived, cached locally with an expiry, and scoped to
the account/role/session the user explicitly requests.
"""

__version__ = "0.1.7"
