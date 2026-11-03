"""IAM through boto3, unmodified apart from endpoint_url."""

import uuid

import pytest
from botocore.exceptions import ClientError


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def test_root_get_user(iam):
    user = iam.get_user()["User"]
    assert user["Arn"] == "arn:aws:iam::123456789012:root"


def test_user_and_key_lifecycle(iam, endpoint, session_for):
    name = unique("carol")
    user = iam.create_user(UserName=name, Path="/qa/", Tags=[{"Key": "k", "Value": "v"}])["User"]
    assert user["Arn"] == f"arn:aws:iam::123456789012:user/qa/{name}"
    assert user["Tags"] == [{"Key": "k", "Value": "v"}]

    iam.attach_user_policy(UserName=name, PolicyArn="arn:aws:iam::aws:policy/IAMReadOnlyAccess")
    key = iam.create_access_key(UserName=name)["AccessKey"]
    carol = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client("iam", endpoint_url=endpoint)
    assert carol.get_user()["User"]["UserName"] == name

    keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
    assert [k["AccessKeyId"] for k in keys] == [key["AccessKeyId"]]

    with pytest.raises(iam.exceptions.DeleteConflictException):
        iam.delete_user(UserName=name)
    iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
    iam.detach_user_policy(UserName=name, PolicyArn="arn:aws:iam::aws:policy/IAMReadOnlyAccess")
    iam.delete_user(UserName=name)

    with pytest.raises(iam.exceptions.NoSuchEntityException) as e:
        iam.get_user(UserName=name)
    assert e.value.response["Error"]["Message"] == f"The user with name {name} cannot be found."
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404


def test_paginator(iam):
    prefix = f"/{unique('page')}/"
    names = sorted(unique("u") for _ in range(5))
    for n in names:
        iam.create_user(UserName=n, Path=prefix)
    pages = list(iam.get_paginator("list_users").paginate(PathPrefix=prefix, PaginationConfig={"PageSize": 2}))
    assert len(pages) == 3
    assert [u["UserName"] for p in pages for u in p["Users"]] == names


def test_validation_error(iam):
    with pytest.raises(ClientError) as e:
        iam.create_user(UserName="bad name")
    err = e.value.response["Error"]
    assert err["Code"] == "ValidationError"
    assert "Member must satisfy regular expression pattern" in err["Message"]


def test_wrong_secret(endpoint, session_for):
    client = session_for(secret="wrong").client("iam", endpoint_url=endpoint)
    with pytest.raises(ClientError) as e:
        client.get_user()
    assert e.value.response["Error"]["Code"] == "SignatureDoesNotMatch"


def test_policy_documents_round_trip(iam):
    """boto3 URL-decodes and parses IAM policy documents, as with real AWS."""
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:List*", "Resource": "*"}]}
    import json

    name = unique("p")
    arn = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
    version = iam.get_policy_version(PolicyArn=arn, VersionId="v1")["PolicyVersion"]
    assert version["Document"] == doc
    assert version["IsDefaultVersion"] is True


def test_access_denied_for_unprivileged_user(iam, endpoint, session_for):
    name = unique("nobody")
    iam.create_user(UserName=name)
    key = iam.create_access_key(UserName=name)["AccessKey"]
    client = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client("iam", endpoint_url=endpoint)
    with pytest.raises(ClientError) as e:
        client.list_users()
    assert e.value.response["Error"]["Code"] == "AccessDenied"
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403
