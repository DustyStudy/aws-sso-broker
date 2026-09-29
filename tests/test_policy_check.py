from ssobroker import policy_check
from ssobroker.policy_check import PolicyCheckResult

CREDS = {
    "AccessKeyId": "AKIAFAKE",
    "SecretAccessKey": "fake-secret",
    "SessionToken": "fake-token",
}
ROLE_ARN = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_x"


class _FakeIam:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def simulate_principal_policy(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def _install_fake_session(monkeypatch, response):
    """Replace boto3.Session so we can see which credentials build the client."""
    iam = _FakeIam(response)
    sessions = []

    class _FakeSession:
        def __init__(self, **kwargs):
            sessions.append(kwargs)

        def client(self, name):
            assert name == "iam"
            return iam

    def _ambient(*args, **kwargs):
        raise AssertionError("must not build a client from ambient credentials")

    monkeypatch.setattr(policy_check.boto3, "Session", _FakeSession)
    monkeypatch.setattr(policy_check.boto3, "client", _ambient)
    return iam, sessions


def test_allowed_property_true_on_allowed():
    r = PolicyCheckResult(
        action="s3:GetObject", resource="*", decision="allowed", matched_statements=["p1"]
    )
    assert r.allowed is True


def test_allowed_property_false_on_explicit_deny():
    r = PolicyCheckResult(
        action="s3:DeleteObject", resource="*", decision="explicitDeny", matched_statements=[]
    )
    assert r.allowed is False


def test_allowed_property_false_on_implicit_deny():
    r = PolicyCheckResult(
        action="iam:DeleteRole", resource="*", decision="implicitDeny", matched_statements=[]
    )
    assert r.allowed is False


def test_simulate_uses_role_credentials_not_ambient(monkeypatch):
    # Regression: simulate() used to build its IAM client from the default
    # credential chain, so it ran as whatever identity the shell happened to
    # have (possibly the wrong account) instead of the role being checked.
    iam, sessions = _install_fake_session(
        monkeypatch,
        {"EvaluationResults": [{"EvalDecision": "allowed", "MatchedStatements": []}]},
    )

    result = policy_check.simulate(CREDS, ROLE_ARN, "s3:GetObject", region="us-east-1")

    assert sessions == [
        {
            "aws_access_key_id": "AKIAFAKE",
            "aws_secret_access_key": "fake-secret",
            "aws_session_token": "fake-token",
            "region_name": "us-east-1",
        }
    ]
    assert result.allowed is True
    assert iam.calls == [{"PolicySourceArn": ROLE_ARN, "ActionNames": ["s3:GetObject"]}]


def test_simulate_passes_resource_arn_when_given(monkeypatch):
    iam, _ = _install_fake_session(
        monkeypatch,
        {
            "EvaluationResults": [
                {
                    "EvalDecision": "explicitDeny",
                    "MatchedStatements": [{"SourcePolicyId": "deny-policy"}],
                }
            ]
        },
    )

    result = policy_check.simulate(CREDS, ROLE_ARN, "s3:DeleteObject", "arn:aws:s3:::b/*")

    assert iam.calls[0]["ResourceArns"] == ["arn:aws:s3:::b/*"]
    assert result.decision == "explicitDeny"
    assert result.matched_statements == ["deny-policy"]


def test_simulate_no_results_is_implicit_deny(monkeypatch):
    _install_fake_session(monkeypatch, {"EvaluationResults": []})
    result = policy_check.simulate(CREDS, ROLE_ARN, "iam:DeleteRole")
    assert result.decision == "implicitDeny"
    assert result.allowed is False
