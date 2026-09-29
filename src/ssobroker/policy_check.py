"""Optional pre-flight check against the IAM policy simulator.

This does NOT parse arbitrary shell commands into IAM actions — that mapping
is too fragile to guess reliably (e.g. "aws s3 rm" could be s3:DeleteObject
or s3:DeleteObjects depending on flags, versioning, etc.). Instead this is an
explicit, opt-in check: you tell it the IAM action (and optionally a
resource ARN) you're about to rely on, and it asks IAM whether the assumed
role's *identity-based* policies would allow it.

Important limitation: `iam:SimulatePrincipalPolicy` evaluates the principal's
own attached/inline policies. It does NOT evaluate Service Control Policies,
resource-based policies, or permission boundaries — AWS does not expose an
API that simulates SCPs directly. So a "would allow" result here is
necessary but not sufficient; a real SCP deny can still block the call.
Treat this as a fast local sanity check, not a guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass

import boto3


@dataclass
class PolicyCheckResult:
    action: str
    resource: str
    decision: str  # "allowed" | "explicitDeny" | "implicitDeny"
    matched_statements: list[str]

    @property
    def allowed(self) -> bool:
        return self.decision == "allowed"


def resolve_role_arn(creds: dict, region: str) -> str:
    """Best-effort: turn the short-lived credentials for an Identity Center
    permission set into the underlying IAM role's full ARN, so it can be
    passed as PolicySourceArn to simulate().

    SSO permission-set roles live under the path
    /aws-reserved/sso.amazonaws.com/... but STS's assumed-role ARN drops the
    path, so we have to look the role up by name via iam:ListRoles using the
    same credentials. If that lookup fails (e.g. the role lacks
    iam:ListRoles), raise with a clear message rather than guessing.
    """
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    sts = session.client("sts")
    identity_arn = sts.get_caller_identity()["Arn"]

    # e.g. arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_ReadOnly_abc123/session
    if ":assumed-role/" not in identity_arn:
        return identity_arn  # already a role/user ARN, nothing to resolve

    role_name = identity_arn.split(":assumed-role/")[1].split("/")[0]

    iam = session.client("iam")
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate(PathPrefix="/aws-reserved/sso.amazonaws.com/"):
        for role in page.get("Roles", []):
            if role["RoleName"] == role_name:
                return role["Arn"]

    raise RuntimeError(
        f"Could not resolve IAM role ARN for '{role_name}' via iam:ListRoles "
        f"(the role may lack that permission)."
    )


def simulate(
    creds: dict,
    role_arn: str,
    action: str,
    resource: str = "*",
    region: str | None = None,
) -> PolicyCheckResult:
    """Ask IAM's policy simulator whether `role_arn` can perform `action` on
    `resource`, based on its identity-based policies only (see module
    docstring for the SCP/resource-policy caveat).

    The simulator call is made with `creds` (the short-lived credentials for
    the role's account) — never with whatever ambient credentials happen to
    be in the environment, which may belong to a different account entirely.
    """
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    client = session.client("iam")
    if resource == "*":
        resp = client.simulate_principal_policy(PolicySourceArn=role_arn, ActionNames=[action])
    else:
        resp = client.simulate_principal_policy(
            PolicySourceArn=role_arn, ActionNames=[action], ResourceArns=[resource]
        )
    results = resp.get("EvaluationResults", [])
    if not results:
        return PolicyCheckResult(action, resource, "implicitDeny", [])

    r = results[0]
    matched = [s.get("SourcePolicyId", "?") for s in r.get("MatchedStatements", [])]
    return PolicyCheckResult(
        action=action,
        resource=resource,
        decision=r["EvalDecision"],
        matched_statements=matched,
    )
