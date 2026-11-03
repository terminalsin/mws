"""S3 Control access points and S3 Object Lambda through boto3.

SDKs put the account id (S3 Control) or the access point name and account
(access point ARNs) in front of the endpoint's host, so these tests resolve
any `*.127.0.0.1` host to 127.0.0.1, as wildcard DNS would.
"""

import io
import json
import socket
import uuid
import zipfile

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"

_real_getaddrinfo = socket.getaddrinfo


def _getaddrinfo(host, *args, **kwargs):
    if isinstance(host, str) and (host.endswith(".127.0.0.1") or host.endswith(".localhost")):
        host = "127.0.0.1"
    return _real_getaddrinfo(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def wildcard_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)


@pytest.fixture
def s3control(endpoint, session_for):
    return session_for().client("s3control", endpoint_url=endpoint)


@pytest.fixture
def s3(endpoint, session_for):
    return session_for().client("s3", endpoint_url=endpoint, config=Config(s3={"addressing_style": "path"}))


@pytest.fixture
def lam(endpoint, session_for):
    return session_for().client("lambda", endpoint_url=endpoint)


@pytest.fixture
def bucket(s3):
    name = f"olap-{uuid.uuid4().hex[:12]}"
    s3.create_bucket(Bucket=name)
    s3.put_object(Bucket=name, Key="greeting.txt", Body=b"hello object lambda", ContentType="text/plain")
    return name


def code(err):
    return err.value.response["Error"]["Code"]


def test_access_points(s3control, s3, bucket):
    name = f"ap-{uuid.uuid4().hex[:8]}"
    created = s3control.create_access_point(AccountId=ACCOUNT, Name=name, Bucket=bucket)
    arn = created["AccessPointArn"]
    alias = created["Alias"]
    assert arn == f"arn:aws:s3:us-east-1:{ACCOUNT}:accesspoint/{name}"
    assert alias.startswith(f"{name}-") and alias.endswith("-s3alias")

    got = s3control.get_access_point(AccountId=ACCOUNT, Name=name)
    assert got["Bucket"] == bucket
    assert got["NetworkOrigin"] == "Internet"
    assert got["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is True
    listed = s3control.list_access_points(AccountId=ACCOUNT, Bucket=bucket)["AccessPointList"]
    assert [a["Name"] for a in listed] == [name]

    with pytest.raises(ClientError) as e:
        s3control.create_access_point(AccountId=ACCOUNT, Name=name, Bucket=bucket)
    assert code(e) == "AccessPointAlreadyOwnedByYou"
    with pytest.raises(ClientError) as e:
        s3control.get_access_point(AccountId=ACCOUNT, Name="no-such-ap")
    assert code(e) == "NoSuchAccessPoint"

    # Data through the access point: by ARN (host-style) and by alias.
    assert s3.get_object(Bucket=arn, Key="greeting.txt")["Body"].read() == b"hello object lambda"
    s3.put_object(Bucket=alias, Key="via-alias.txt", Body=b"x")
    assert s3.get_object(Bucket=bucket, Key="via-alias.txt")["Body"].read() == b"x"
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=alias)["Contents"]]
    assert keys == ["greeting.txt", "via-alias.txt"]

    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject", "Resource": f"{arn}/object/secret/*"}
            ],
        }
    )
    s3control.put_access_point_policy(AccountId=ACCOUNT, Name=name, Policy=policy)
    assert json.loads(s3control.get_access_point_policy(AccountId=ACCOUNT, Name=name)["Policy"]) == json.loads(policy)
    assert s3control.get_access_point_policy_status(AccountId=ACCOUNT, Name=name)["PolicyStatus"]["IsPublic"] is False
    s3.put_object(Bucket=bucket, Key="secret/a", Body=b"s")
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=alias, Key="secret/a")
    assert code(e) == "AccessDenied"
    assert s3.get_object(Bucket=bucket, Key="secret/a")["Body"].read() == b"s"

    public = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"{arn}/object/*"}],
        }
    )
    with pytest.raises(ClientError) as e:
        s3control.put_access_point_policy(AccountId=ACCOUNT, Name=name, Policy=public)
    assert code(e) == "AccessDenied"

    s3control.delete_access_point(AccountId=ACCOUNT, Name=name)
    with pytest.raises(ClientError) as e:
        s3control.get_access_point(AccountId=ACCOUNT, Name=name)
    assert code(e) == "NoSuchAccessPoint"


def test_account_public_access_block(s3control):
    with pytest.raises(ClientError) as e:
        s3control.get_public_access_block(AccountId=ACCOUNT)
    assert code(e) == "NoSuchPublicAccessBlockConfiguration"
    config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": False,
    }
    s3control.put_public_access_block(AccountId=ACCOUNT, PublicAccessBlockConfiguration=config)
    try:
        got = s3control.get_public_access_block(AccountId=ACCOUNT)["PublicAccessBlockConfiguration"]
        assert got == config
    finally:
        s3control.delete_public_access_block(AccountId=ACCOUNT)


TRANSFORM = """
import boto3, urllib.request

def handler(event, context):
    ctx = event["getObjectContext"]
    assert "X-Amz-Signature=" in ctx["inputS3Url"] and "X-Amz-Security-Token=" in ctx["inputS3Url"]
    original = urllib.request.urlopen(ctx["inputS3Url"]).read()
    payload = event["configuration"]["payload"]
    if payload == "fail":
        boto3.client("s3").write_get_object_response(
            RequestRoute=ctx["outputRoute"], RequestToken=ctx["outputToken"],
            StatusCode=403, ErrorCode="NoTransform", ErrorMessage="refused")
        return
    if payload == "silent":
        return {"status_code": 200}
    boto3.client("s3").write_get_object_response(
        RequestRoute=ctx["outputRoute"],
        RequestToken=ctx["outputToken"],
        Body=original.upper() + b" " + event["userIdentity"]["type"].encode(),
        ContentType="text/plain",
        Metadata={"transformed": "yes"},
    )
    return {"status_code": 200}
"""


@pytest.fixture
def transform_function(lam, iam):
    role = f"olap-{uuid.uuid4().hex[:8]}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role,
        PolicyName="wgor",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3-object-lambda:WriteGetObjectResponse", "Resource": "*"}
                ],
            }
        ),
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", TRANSFORM)
    name = f"upper-{uuid.uuid4().hex[:8]}"
    return lam.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="app.handler",
        Code={"ZipFile": buf.getvalue()},
        Timeout=30,
    )["FunctionArn"]


def make_olap(s3control, bucket, function_arn, payload=""):
    ap = f"sup-{uuid.uuid4().hex[:8]}"
    ap_arn = s3control.create_access_point(AccountId=ACCOUNT, Name=ap, Bucket=bucket)["AccessPointArn"]
    name = f"ol-{uuid.uuid4().hex[:8]}"
    created = s3control.create_access_point_for_object_lambda(
        AccountId=ACCOUNT,
        Name=name,
        Configuration={
            "SupportingAccessPoint": ap_arn,
            "TransformationConfigurations": [
                {
                    "Actions": ["GetObject"],
                    "ContentTransformation": {
                        "AwsLambda": {"FunctionArn": function_arn, "FunctionPayload": payload}
                    },
                }
            ],
        },
    )
    return name, created


def test_object_lambda_get_object(s3control, s3, bucket, transform_function):
    name, created = make_olap(s3control, bucket, transform_function)
    arn = created["ObjectLambdaAccessPointArn"]
    alias = created["Alias"]["Value"]
    assert arn == f"arn:aws:s3-object-lambda:us-east-1:{ACCOUNT}:accesspoint/{name}"
    assert alias.endswith("--ol-s3")
    assert created["Alias"]["Status"] == "READY"

    conf = s3control.get_access_point_configuration_for_object_lambda(AccountId=ACCOUNT, Name=name)["Configuration"]
    assert conf["TransformationConfigurations"][0]["Actions"] == ["GetObject"]
    listed = s3control.list_access_points_for_object_lambda(AccountId=ACCOUNT)["ObjectLambdaAccessPointList"]
    assert name in [o["Name"] for o in listed]

    for target in (arn, alias):
        got = s3.get_object(Bucket=target, Key="greeting.txt")
        assert got["Body"].read() == b"HELLO OBJECT LAMBDA Root"
        assert got["ContentType"] == "text/plain"
        assert got["Metadata"] == {"transformed": "yes"}

    # Untransformed operations go to the supporting access point.
    head = s3.head_object(Bucket=alias, Key="greeting.txt")
    assert head["ContentLength"] == len(b"hello object lambda")

    s3control.delete_access_point_for_object_lambda(AccountId=ACCOUNT, Name=name)
    with pytest.raises(ClientError) as e:
        s3control.get_access_point_for_object_lambda(AccountId=ACCOUNT, Name=name)
    assert code(e) == "NoSuchAccessPoint"


def test_object_lambda_errors(s3control, s3, bucket, transform_function):
    _, failing = make_olap(s3control, bucket, transform_function, payload="fail")
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=failing["Alias"]["Value"], Key="greeting.txt")
    assert code(e) == "NoTransform"
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403

    _, silent = make_olap(s3control, bucket, transform_function, payload="silent")
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=silent["Alias"]["Value"], Key="greeting.txt")
    assert code(e) == "LambdaResponseNotReceived"

    missing = transform_function.rsplit(":", 1)[0] + ":does-not-exist"
    _, gone = make_olap(s3control, bucket, missing)
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=gone["Alias"]["Value"], Key="greeting.txt")
    assert code(e) == "LambdaNotFound"

    with pytest.raises(ClientError) as e:
        s3.write_get_object_response(RequestRoute="io-x", RequestToken="nope", Body=b"")
    assert code(e) == "InvalidToken"
