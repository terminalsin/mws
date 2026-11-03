"""STS through boto3."""

import json
import uuid

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def test_caller_identity(endpoint, session_for):
    sts = session_for().client("sts", endpoint_url=endpoint)
    me = sts.get_caller_identity()
    assert me["Arn"] == f"arn:aws:iam::{ACCOUNT}:root"
    assert me["Account"] == ACCOUNT


def test_assume_role_and_use_session(iam, endpoint, session_for):
    role = unique("role")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": ACCOUNT}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust), MaxSessionDuration=7200)
    iam.attach_role_policy(RoleName=role, PolicyArn="arn:aws:iam::aws:policy/IAMReadOnlyAccess")

    user = unique("caller")
    iam.create_user(UserName=user)
    iam.put_user_policy(
        UserName=user,
        PolicyName="assume",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]}),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    sts = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client("sts", endpoint_url=endpoint)

    out = sts.assume_role(RoleArn=f"arn:aws:iam::{ACCOUNT}:role/{role}", RoleSessionName="py", DurationSeconds=7200)
    creds = out["Credentials"]
    assert creds["AccessKeyId"].startswith("ASIA")
    assert out["AssumedRoleUser"]["Arn"] == f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/py"

    session = session_for(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])
    assert session.client("sts", endpoint_url=endpoint).get_caller_identity()["Arn"] == out["AssumedRoleUser"]["Arn"]
    role_iam = session.client("iam", endpoint_url=endpoint)
    role_iam.list_roles()
    with pytest.raises(ClientError) as e:
        role_iam.create_user(UserName=unique("x"))
    assert e.value.response["Error"]["Code"] == "AccessDenied"

    # Tampering with the session token is rejected.
    bad = session_for(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"] + "x")
    with pytest.raises(ClientError) as e:
        bad.client("sts", endpoint_url=endpoint).get_caller_identity()
    assert e.value.response["Error"]["Code"] == "InvalidClientTokenId"
