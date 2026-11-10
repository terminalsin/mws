"""Lambda through boto3: functions really run on the local Python runtime."""

import base64
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


def package(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


@pytest.fixture
def lam(endpoint, session_for):
    return session_for().client("lambda", endpoint_url=endpoint)


@pytest.fixture
def role(iam):
    name = f"fn-{uuid.uuid4().hex[:8]}"
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="all",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )
    return arn


def code(err):
    return err.value.response["Error"]["Code"]


HANDLER = """
import json, os

def handler(event, context):
    print("got", json.dumps(event))
    if event.get("fail"):
        raise ValueError("boom")
    return {
        "echo": event,
        "name": context.function_name,
        "version": context.function_version,
        "memory": context.memory_limit_in_mb,
        "region": os.environ["AWS_REGION"],
        "greeting": os.environ.get("GREETING"),
        "has_creds": bool(os.environ.get("AWS_SESSION_TOKEN")),
    }
"""


def create(lam, role, name=None, **kw):
    name = name or f"fn-{uuid.uuid4().hex[:8]}"
    lam.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Role=role,
        Handler="app.handler",
        Code={"ZipFile": package({"app.py": HANDLER})},
        **kw,
    )
    # A new function is Pending for a moment, as on AWS.
    lam.get_waiter("function_active_v2").wait(FunctionName=name)
    return name


def test_create_invoke_and_errors(lam, role):
    name = create(lam, role, Environment={"Variables": {"GREETING": "hi"}}, MemorySize=256)
    conf = lam.get_function_configuration(FunctionName=name)
    assert conf["Runtime"] == "python3.12"
    assert conf["MemorySize"] == 256
    assert conf["State"] == "Active"
    assert conf["Environment"]["Variables"] == {"GREETING": "hi"}

    out = lam.invoke(FunctionName=name, Payload=json.dumps({"a": 1}), LogType="Tail")
    assert out["StatusCode"] == 200
    assert "FunctionError" not in out
    body = json.loads(out["Payload"].read())
    assert body["echo"] == {"a": 1}
    assert body["name"] == name
    assert body["version"] == "$LATEST"
    assert body["memory"] == "256"
    assert body["greeting"] == "hi"
    assert body["has_creds"] is True
    logs = base64.b64decode(out["LogResult"]).decode()
    assert 'got {"a": 1}' in logs
    assert "REPORT RequestId:" in logs

    failed = lam.invoke(FunctionName=name, Payload=json.dumps({"fail": True}))
    assert failed["FunctionError"] == "Unhandled"
    err = json.loads(failed["Payload"].read())
    assert err["errorType"] == "ValueError"
    assert err["errorMessage"] == "boom"

    assert lam.invoke(FunctionName=name, InvocationType="DryRun")["StatusCode"] == 204
    assert lam.invoke(FunctionName=name, InvocationType="Event", Payload=b"{}")["StatusCode"] == 202

    with pytest.raises(ClientError) as e:
        lam.invoke(FunctionName="missing-function")
    assert code(e) == "ResourceNotFoundException"
    with pytest.raises(ClientError) as e:
        create(lam, role, name=name)
    assert code(e) == "ResourceConflictException"


def test_versions_aliases_and_code_updates(lam, role):
    name = create(lam, role)
    v1 = lam.publish_version(FunctionName=name)["Version"]
    assert v1 == "1"
    lam.update_function_code(
        FunctionName=name, ZipFile=package({"app.py": "def handler(e, c):\n    return 'v2'\n"})
    )
    lam.get_waiter("function_updated_v2").wait(FunctionName=name)
    assert json.loads(lam.invoke(FunctionName=name)["Payload"].read()) == "v2"
    assert json.loads(lam.invoke(FunctionName=name, Qualifier="1", Payload=b"{}")["Payload"].read())["version"] == "1"

    alias = lam.create_alias(FunctionName=name, Name="live", FunctionVersion="1")
    assert alias["AliasArn"].endswith(f":{name}:live")
    out = lam.invoke(FunctionName=f"{name}:live", Payload=b"{}")
    assert out["ExecutedVersion"] == "1"
    assert [v["Version"] for v in lam.list_versions_by_function(FunctionName=name)["Versions"]] == ["$LATEST", "1"]
    with pytest.raises(ClientError) as e:
        lam.delete_function(FunctionName=name, Qualifier="1")
    assert code(e) == "ResourceConflictException"
    lam.delete_alias(FunctionName=name, Name="live")
    lam.delete_function(FunctionName=name)
    with pytest.raises(ClientError) as e:
        lam.get_function(FunctionName=name)
    assert code(e) == "ResourceNotFoundException"


def test_function_uses_aws_from_inside(lam, role, endpoint, session_for):
    """The function's SDK reaches MWS with the execution role's credentials."""
    src = """
import boto3

def handler(event, context):
    return boto3.client("sts").get_caller_identity()["Arn"]
"""
    name = f"fn-{uuid.uuid4().hex[:8]}"
    lam.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Role=role,
        Handler="app.handler",
        Code={"ZipFile": package({"app.py": src})},
        Timeout=30,
    )
    lam.get_waiter("function_active_v2").wait(FunctionName=name)
    out = lam.invoke(FunctionName=name)
    assert "FunctionError" not in out, out["Payload"].read()
    arn = json.loads(out["Payload"].read())
    role_name = role.rsplit("/", 1)[1]
    assert arn.startswith(f"arn:aws:sts::") and f":assumed-role/{role_name}/{name}" in arn


def test_permissions_and_cross_principal_invoke(lam, role, iam, session_for, endpoint):
    name = create(lam, role)
    user = f"u-{uuid.uuid4().hex[:8]}"
    iam.create_user(UserName=user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    other = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client("lambda", endpoint_url=endpoint)
    for _ in range(50):
        try:
            other.invoke(FunctionName=name, InvocationType="DryRun")
        except ClientError as e:
            if code_of(e) == "AccessDeniedException":
                break
            if code_of(e) != "UnrecognizedClientException":
                raise
        time.sleep(0.05)
    with pytest.raises(ClientError) as e:
        other.invoke(FunctionName=name, InvocationType="DryRun")
    assert code(e) == "AccessDeniedException"

    user_arn = iam.get_user(UserName=user)["User"]["Arn"]
    stmt = json.loads(
        lam.add_permission(
            FunctionName=name, StatementId="u", Action="lambda:InvokeFunction", Principal=user_arn
        )["Statement"]
    )
    assert stmt["Principal"] == {"AWS": user_arn}
    assert other.invoke(FunctionName=name, InvocationType="DryRun")["StatusCode"] == 204
    policy = json.loads(lam.get_policy(FunctionName=name)["Policy"])
    assert [s["Sid"] for s in policy["Statement"]] == ["u"]
    with pytest.raises(ClientError) as e:
        lam.add_permission(FunctionName=name, StatementId="u", Action="lambda:InvokeFunction", Principal="*")
    assert code(e) == "ResourceConflictException"
    lam.remove_permission(FunctionName=name, StatementId="u")
    with pytest.raises(ClientError) as e:
        lam.get_policy(FunctionName=name)
    assert code(e) == "ResourceNotFoundException"


def code_of(e):
    return e.response["Error"]["Code"]


def test_settings(lam, role):
    name = create(lam, role, Tags={"team": "a"})
    arn = lam.get_function(FunctionName=name)["Configuration"]["FunctionArn"]
    assert lam.list_tags(Resource=arn)["Tags"] == {"team": "a"}
    lam.tag_resource(Resource=arn, Tags={"env": "dev"})
    lam.untag_resource(Resource=arn, TagKeys=["team"])
    assert lam.list_tags(Resource=arn)["Tags"] == {"env": "dev"}

    lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=5)
    assert lam.get_function_concurrency(FunctionName=name)["ReservedConcurrentExecutions"] == 5
    with pytest.raises(ClientError) as e:
        lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=950)
    assert code(e) == "InvalidParameterValueException"
    lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=0)
    with pytest.raises(ClientError) as e:
        lam.invoke(FunctionName=name)
    assert code(e) == "TooManyRequestsException"
    lam.delete_function_concurrency(FunctionName=name)

    cfg = lam.put_function_event_invoke_config(FunctionName=name, MaximumRetryAttempts=0)
    assert cfg["MaximumRetryAttempts"] == 0
    url = lam.create_function_url_config(FunctionName=name, AuthType="AWS_IAM")
    assert url["FunctionUrl"].startswith("https://") and ".lambda-url.us-east-1.on.aws/" in url["FunctionUrl"]
    settings = lam.get_account_settings()
    assert settings["AccountLimit"]["ConcurrentExecutions"] == 1000

    layer = lam.publish_layer_version(
        LayerName=f"l-{uuid.uuid4().hex[:6]}",
        Content={"ZipFile": package({"python/helper.py": "VALUE = 42\n"})},
        CompatibleRuntimes=["python3.12"],
    )
    assert layer["Version"] == 1
    lam.update_function_configuration(FunctionName=name, Layers=[layer["LayerVersionArn"]])
    lam.get_waiter("function_updated_v2").wait(FunctionName=name)
    lam.update_function_code(
        FunctionName=name, ZipFile=package({"app.py": "import helper\n\ndef handler(e, c):\n    return helper.VALUE\n"})
    )
    lam.get_waiter("function_updated_v2").wait(FunctionName=name)
    assert json.loads(lam.invoke(FunctionName=name)["Payload"].read()) == 42
