"""Lambda function URLs through boto3 and plain HTTP: requests invoke the
function with the payload format 2.0 event, as Lambda does."""

import json
import urllib.error
import urllib.request
import uuid

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from test_lambda import TRUST, package

ECHO = """
import base64, json

def handler(event, context):
    if event["rawPath"] == "/plain":
        return {"plain": True}
    body = event.get("body")
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()
    return {
        "statusCode": 201,
        "headers": {"Content-Type": "application/json", "X-Echo": "yes"},
        "cookies": ["session=abc"],
        "body": json.dumps({
            "method": event["requestContext"]["http"]["method"],
            "path": event["rawPath"],
            "query": event.get("queryStringParameters"),
            "body": body,
            "version": event["version"],
            "iam": event["requestContext"].get("authorizer", {}).get("iam"),
            "cookies": event.get("cookies"),
        }),
    }
"""


def call(method, url, body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def make_function(iam, lam):
    name = f"url-{uuid.uuid4().hex[:8]}"
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
    lam.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Role=role,
        Handler="app.handler",
        Code={"ZipFile": package({"app.py": ECHO})},
    )
    lam.get_waiter("function_active_v2").wait(FunctionName=name)
    return name


def test_public_function_url(endpoint, iam, session_for):
    lam = session_for().client("lambda", endpoint_url=endpoint)
    name = make_function(iam, lam)
    url = lam.create_function_url_config(FunctionName=name, AuthType="NONE")["FunctionUrl"]
    url_id = url.split("//")[1].split(".")[0]
    host = url.split("//")[1].rstrip("/")

    # Without a resource policy granting `*`, Lambda refuses the call.
    status, headers, body = call("GET", f"{endpoint}/hello", headers={"Host": host})
    assert status == 403
    assert json.loads(body) == {"Message": "Forbidden"}

    lam.add_permission(
        FunctionName=name,
        StatementId="url",
        Action="lambda:InvokeFunctionUrl",
        Principal="*",
        FunctionUrlAuthType="NONE",
    )
    lam.add_permission(
        FunctionName=name,
        StatementId="invoke",
        Action="lambda:InvokeFunction",
        Principal="*",
        InvokedViaFunctionUrl=True,
    )

    status, headers, body = call(
        "POST",
        f"{endpoint}/hello/world?a=1&b=2",
        body=b'{"x": 1}',
        headers={"Host": host, "Content-Type": "application/json", "Cookie": "c1=v1; c2=v2"},
    )
    assert status == 201, body
    assert headers["X-Echo"] == "yes"
    assert headers["Set-Cookie"] == "session=abc"
    echoed = json.loads(body)
    assert echoed["method"] == "POST"
    assert echoed["path"] == "/hello/world"
    assert echoed["query"] == {"a": "1", "b": "2"}
    assert echoed["body"] == '{"x": 1}'
    assert echoed["version"] == "2.0"
    assert echoed["iam"] is None
    assert echoed["cookies"] == ["c1=v1", "c2=v2"]

    # Binary bodies arrive base64-encoded; the path form needs no Host.
    status, _, body = call(
        "PUT",
        f"{endpoint}/_aws/lambda-url/{url_id}/bin",
        body=b"raw bytes",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert status == 201
    assert json.loads(body)["body"] == "raw bytes"

    # A result without statusCode is the JSON body of a 200.
    status, headers, body = call("GET", f"{endpoint}/_aws/lambda-url/{url_id}/plain")
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body) == {"plain": True}


def test_iam_function_url(endpoint, iam, session_for):
    lam = session_for().client("lambda", endpoint_url=endpoint)
    name = make_function(iam, lam)
    url = lam.create_function_url_config(FunctionName=name, AuthType="AWS_IAM")["FunctionUrl"]
    url_id = url.split("//")[1].split(".")[0]
    target = f"{endpoint}/_aws/lambda-url/{url_id}/whoami"

    status, _, body = call("GET", target)
    assert status == 403
    assert json.loads(body) == {"Message": "Forbidden"}

    # The account's root user is allowed by its identity; the request must
    # be SigV4-signed for `lambda`.
    creds = session_for().get_credentials()
    req = AWSRequest(method="GET", url=target)
    SigV4Auth(creds, "lambda", "us-east-1").add_auth(req)
    status, _, body = call("GET", target, headers=dict(req.headers))
    assert status == 201, body
    who = json.loads(body)["iam"]
    assert len(who["accountId"]) == 12
    assert who["userArn"].endswith(":root")

    # A user without lambda:InvokeFunctionUrl is refused.
    user = f"u-{uuid.uuid4().hex[:6]}"
    iam.create_user(UserName=user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    other = session_for(key["AccessKeyId"], key["SecretAccessKey"]).get_credentials()
    req = AWSRequest(method="GET", url=target)
    SigV4Auth(other, "lambda", "us-east-1").add_auth(req)
    status, _, body = call("GET", target, headers=dict(req.headers))
    assert status == 403
