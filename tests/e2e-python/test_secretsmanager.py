"""Secrets Manager through boto3: versions, KMS, policies, rotation through
a real Lambda function, and replication."""

import io
import json
import time
import uuid
import zipfile

import pytest
from botocore.exceptions import ClientError

TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

ROTATOR = """
import json, boto3

def handler(event, context):
    arn, token, step = event["SecretId"], event["ClientRequestToken"], event["Step"]
    sm = boto3.client("secretsmanager")
    meta = sm.describe_secret(SecretId=arn)
    versions = meta["VersionIdsToStages"]
    if token not in versions:
        raise ValueError("no such version")
    if "AWSCURRENT" in versions[token]:
        return
    if step == "createSecret":
        try:
            sm.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except sm.exceptions.ResourceNotFoundException:
            password = sm.get_random_password(PasswordLength=20)["RandomPassword"]
            sm.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=password, VersionStages=["AWSPENDING"])
    elif step == "finishSecret":
        old = next(v for v, s in versions.items() if "AWSCURRENT" in s)
        sm.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=old)
"""


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def code(err):
    return err.value.response["Error"]["Code"]


@pytest.fixture
def sm(endpoint, session_for):
    return session_for().client("secretsmanager", endpoint_url=endpoint)


def test_versions_labels_and_listing(sm):
    name = unique("app/db")
    created = sm.create_secret(Name=name, SecretString="one", Description="db creds", Tags=[{"Key": "k", "Value": "v"}])
    v1 = created["VersionId"]
    assert created["ARN"].startswith(f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{name}-")
    with pytest.raises(ClientError) as e:
        sm.create_secret(Name=name, SecretString="again")
    assert code(e) == "ResourceExistsException"

    v2 = sm.put_secret_value(SecretId=name, SecretString="two")["VersionId"]
    assert sm.get_secret_value(SecretId=name)["SecretString"] == "two"
    assert sm.get_secret_value(SecretId=name, VersionStage="AWSPREVIOUS")["VersionId"] == v1
    v3 = sm.put_secret_value(SecretId=name, SecretString="three", VersionStages=["beta"])["VersionId"]
    sm.update_secret_version_stage(SecretId=name, VersionStage="AWSCURRENT", MoveToVersionId=v3, RemoveFromVersionId=v2)
    stages = sm.describe_secret(SecretId=name)["VersionIdsToStages"]
    assert stages[v3] == ["beta", "AWSCURRENT"]
    assert stages[v2] == ["AWSPREVIOUS"]
    assert v1 not in stages

    versions = sm.list_secret_version_ids(SecretId=name, IncludeDeprecated=True)["Versions"]
    assert {v["VersionId"] for v in versions} == {v1, v2, v3}
    assert sm.update_secret(SecretId=name, Description="changed", SecretString="four")["VersionId"]
    assert sm.get_secret_value(SecretId=name)["SecretString"] == "four"

    sm.tag_resource(SecretId=name, Tags=[{"Key": "env", "Value": "test"}])
    sm.untag_resource(SecretId=name, TagKeys=["k"])
    assert sm.describe_secret(SecretId=name)["Tags"] == [{"Key": "env", "Value": "test"}]
    listed = sm.list_secrets(Filters=[{"Key": "name", "Values": [name]}])["SecretList"]
    assert [s["Name"] for s in listed] == [name]
    assert listed[0]["Description"] == "changed"

    batch = sm.batch_get_secret_value(SecretIdList=[name, "missing-" + name])
    assert [v["SecretString"] for v in batch["SecretValues"]] == ["four"]
    assert batch["Errors"][0]["ErrorCode"] == "ResourceNotFoundException"

    deleted = sm.delete_secret(SecretId=name, RecoveryWindowInDays=10)
    assert "DeletionDate" in deleted
    with pytest.raises(ClientError) as e:
        sm.get_secret_value(SecretId=name)
    assert code(e) == "InvalidRequestException"
    sm.restore_secret(SecretId=name)
    sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    with pytest.raises(ClientError) as e:
        sm.describe_secret(SecretId=name)
    assert code(e) == "ResourceNotFoundException"


def test_binary_secrets_and_passwords(sm):
    name = unique("bin")
    sm.create_secret(Name=name, SecretBinary=b"\x00\xff")
    assert sm.get_secret_value(SecretId=name)["SecretBinary"] == b"\x00\xff"
    pw = sm.get_random_password(PasswordLength=40, ExcludeNumbers=True, IncludeSpace=True)["RandomPassword"]
    assert len(pw) == 40 and not any(c.isdigit() for c in pw)


def test_customer_keys_and_resource_policies(endpoint, session_for, sm, iam):
    kms = session_for().client("kms", endpoint_url=endpoint)
    key = kms.create_key()["KeyMetadata"]["Arn"]
    name = unique("cmk")
    sm.create_secret(Name=name, SecretString="s3cret", KmsKeyId=key)
    assert sm.describe_secret(SecretId=name)["KmsKeyId"] == key

    user = unique("reader")
    iam.create_user(UserName=user)
    iam.put_user_policy(
        UserName=user,
        PolicyName="read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}],
            }
        ),
    )
    k = iam.create_access_key(UserName=user)["AccessKey"]
    reader = session_for(k["AccessKeyId"], k["SecretAccessKey"]).client("secretsmanager", endpoint_url=endpoint)
    with pytest.raises(ClientError) as e:
        reader.get_secret_value(SecretId=sm.describe_secret(SecretId=name)["ARN"])
    assert code(e) == "AccessDeniedException"
    assert e.value.response["Error"]["Message"] == "Access to KMS is not allowed"

    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
            ],
        }
    )
    result = sm.validate_resource_policy(SecretId=name, ResourcePolicy=policy)
    assert result["PolicyValidationPassed"] is False
    with pytest.raises(ClientError) as e:
        sm.put_resource_policy(SecretId=name, ResourcePolicy=policy, BlockPublicPolicy=True)
    assert code(e) == "PublicPolicyException"
    sm.put_resource_policy(SecretId=name, ResourcePolicy=policy)
    assert json.loads(sm.get_resource_policy(SecretId=name)["ResourcePolicy"]) == json.loads(policy)
    sm.delete_resource_policy(SecretId=name)
    assert "ResourcePolicy" not in sm.get_resource_policy(SecretId=name)


def package(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_rotation_invokes_the_function(endpoint, session_for, sm, iam):
    lam = session_for().client("lambda", endpoint_url=endpoint)
    role_name = unique("rotator")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="secrets",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "secretsmanager:*", "Resource": "*"}]}
        ),
    )
    fn = lam.create_function(
        FunctionName=role_name,
        Runtime="python3.12",
        Role=role,
        Handler="app.handler",
        Timeout=30,
        Code={"ZipFile": package({"app.py": ROTATOR})},
    )["FunctionArn"]
    lam.get_waiter("function_active_v2").wait(FunctionName=role_name)
    lam.add_permission(
        FunctionName=role_name,
        StatementId="sm",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
    )
    name = unique("rotated")
    sm.create_secret(Name=name, SecretString="before")
    token = sm.rotate_secret(
        SecretId=name, RotationLambdaARN=fn, RotationRules={"ScheduleExpression": "rate(7 days)"}
    )["VersionId"]
    for _ in range(300):
        meta = sm.describe_secret(SecretId=name)
        if meta["VersionIdsToStages"].get(token) == ["AWSCURRENT"]:
            break
        time.sleep(0.1)
    else:
        pytest.fail("rotation did not finish")
    assert meta["RotationEnabled"] is True
    assert meta["RotationRules"]["AutomaticallyAfterDays"] == 7
    assert "LastRotatedDate" in meta and "NextRotationDate" in meta
    value = sm.get_secret_value(SecretId=name)["SecretString"]
    assert value != "before" and len(value) == 20
    assert sm.get_secret_value(SecretId=name, VersionStage="AWSPREVIOUS")["SecretString"] == "before"

    cancelled = sm.cancel_rotate_secret(SecretId=name)
    assert cancelled["Name"] == name
    assert sm.describe_secret(SecretId=name)["RotationEnabled"] is False


def test_replication(endpoint, session_for, sm):
    west = session_for().client("secretsmanager", endpoint_url=endpoint, region_name="us-west-2")
    name = unique("multi")
    sm.create_secret(Name=name, SecretString="v1")
    out = sm.replicate_secret_to_regions(SecretId=name, AddReplicaRegions=[{"Region": "us-west-2"}])
    assert out["ReplicationStatus"][0]["Status"] == "InSync"
    assert west.get_secret_value(SecretId=name)["SecretString"] == "v1"
    sm.put_secret_value(SecretId=name, SecretString="v2")
    assert west.get_secret_value(SecretId=name)["SecretString"] == "v2"
    assert west.describe_secret(SecretId=name)["PrimaryRegion"] == "us-east-1"
    with pytest.raises(ClientError) as e:
        west.update_secret(SecretId=name, Description="no")
    assert code(e) == "InvalidRequestException"
    west.stop_replication_to_replica(SecretId=name)
    assert "PrimaryRegion" not in west.describe_secret(SecretId=name)
    sm.replicate_secret_to_regions(SecretId=name, AddReplicaRegions=[{"Region": "eu-central-1"}])
    removed = sm.remove_regions_from_replication(SecretId=name, RemoveReplicaRegions=["eu-central-1"])
    assert removed["ReplicationStatus"] == []


def test_errors_and_idempotency_match_aws(endpoint, session_for, sm, iam):
    # Model constraints are ValidationException.
    with pytest.raises(ClientError) as e:
        sm.list_secrets(MaxResults=101)
    assert code(e) == "ValidationException"

    # Unauthorized callers are denied before the lookup.
    user = unique("nobody")
    iam.create_user(UserName=user)
    k = iam.create_access_key(UserName=user)["AccessKey"]
    nobody = session_for(k["AccessKeyId"], k["SecretAccessKey"]).client("secretsmanager", endpoint_url=endpoint)
    with pytest.raises(ClientError) as e:
        nobody.describe_secret(SecretId=unique("missing"))
    assert code(e) == "AccessDeniedException"

    # A retried CreateSecret is ignored; a forced delete of nothing succeeds.
    name, token = unique("retried"), str(uuid.uuid4())
    first = sm.create_secret(Name=name, ClientRequestToken=token, SecretString="v")
    again = sm.create_secret(Name=name, ClientRequestToken=token, SecretString="v")
    assert again["ARN"] == first["ARN"] and again["VersionId"] == token
    gone = sm.delete_secret(SecretId=unique("never"), ForceDeleteWithoutRecovery=True)
    assert "DeletionDate" in gone

    # Another Region's ARN finds nothing.
    west = session_for().client("secretsmanager", endpoint_url=endpoint, region_name="us-west-2")
    with pytest.raises(ClientError) as e:
        west.get_secret_value(SecretId=first["ARN"])
    assert code(e) == "ResourceNotFoundException"
