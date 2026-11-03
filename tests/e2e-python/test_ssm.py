"""SSM Parameter Store through boto3."""

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


@pytest.fixture
def ssm(endpoint, session_for):
    return session_for().client("ssm", endpoint_url=endpoint)


@pytest.fixture
def prefix():
    return f"/py/{uuid.uuid4().hex[:8]}"


def code(exc):
    return exc.value.response["Error"]["Code"]


def test_put_get_versions_and_labels(ssm, prefix):
    name = f"{prefix}/db/host"
    out = ssm.put_parameter(Name=name, Value="db1", Type="String", Description="host")
    assert out["Version"] == 1 and out["Tier"] == "Standard"
    p = ssm.get_parameter(Name=name)["Parameter"]
    assert p["Value"] == "db1" and p["Type"] == "String" and p["DataType"] == "text"
    assert p["ARN"] == f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter{name}"
    assert isinstance(p["LastModifiedDate"], datetime)

    with pytest.raises(ClientError) as e:
        ssm.put_parameter(Name=name, Value="x")
    assert code(e) == "ParameterAlreadyExists"
    assert ssm.put_parameter(Name=name, Value="db2", Overwrite=True)["Version"] == 2
    assert ssm.get_parameter(Name=f"{name}:1")["Parameter"]["Value"] == "db1"

    out = ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=["blue", "9nine"])
    assert out["InvalidLabels"] == ["9nine"] and out["ParameterVersion"] == 1
    assert ssm.get_parameter(Name=f"{name}:blue")["Parameter"]["Selector"] == ":blue"
    out = ssm.unlabel_parameter_version(Name=name, ParameterVersion=1, Labels=["blue", "green"])
    assert out["RemovedLabels"] == ["blue"] and out["InvalidLabels"] == ["green"]

    history = ssm.get_parameter_history(Name=name)["Parameters"]
    assert [h["Version"] for h in history] == [1, 2]
    assert history[1]["Description"] == "host"

    got = ssm.get_parameters(Names=[name, f"{prefix}/missing"])
    assert [p["Name"] for p in got["Parameters"]] == [name]
    assert got["InvalidParameters"] == [f"{prefix}/missing"]

    with pytest.raises(ClientError) as e:
        ssm.get_parameter(Name=f"{name}:7")
    assert code(e) == "ParameterVersionNotFound"
    with pytest.raises(ClientError) as e:
        ssm.put_parameter(Name="/aws/mine", Value="x", Type="String")
    assert code(e) == "AccessDeniedException"
    with pytest.raises(ClientError) as e:
        ssm.put_parameter(Name="ssmthing", Value="x", Type="String")
    assert code(e) == "ValidationException"

    ssm.delete_parameter(Name=name)
    with pytest.raises(ClientError) as e:
        ssm.get_parameter(Name=name)
    assert code(e) == "ParameterNotFound"
    ssm.put_parameter(Name=f"{prefix}/x", Value="x", Type="String")
    out = ssm.delete_parameters(Names=[f"{prefix}/x", f"{prefix}/y"])
    assert out["DeletedParameters"] == [f"{prefix}/x"]
    assert out["InvalidParameters"] == [f"{prefix}/y"]


def test_secure_strings(ssm, prefix, endpoint, session_for):
    name = f"{prefix}/password"
    ssm.put_parameter(Name=name, Value="hunter2", Type="SecureString")
    raw = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    assert raw != "hunter2"
    assert ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"] == "hunter2"
    kms = session_for().client("kms", endpoint_url=endpoint)
    context = {"PARAMETER_ARN": f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter{name}"}
    # alias/aws/ssm can only be used through Parameter Store.
    with pytest.raises(ClientError) as e:
        kms.decrypt(CiphertextBlob=base64.b64decode(raw), EncryptionContext=context)
    assert code(e) == "AccessDeniedException"

    key = kms.create_key()["KeyMetadata"]["KeyId"]
    cmk = f"{prefix}/cmk"
    ssm.put_parameter(Name=cmk, Value="direct", Type="SecureString", KeyId=key)
    blob = base64.b64decode(ssm.get_parameter(Name=cmk)["Parameter"]["Value"])
    context = {"PARAMETER_ARN": f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter{cmk}"}
    assert kms.decrypt(CiphertextBlob=blob, EncryptionContext=context)["Plaintext"] == b"direct"
    adv = f"{prefix}/advanced"
    out = ssm.put_parameter(Name=adv, Value="x" * 6000, Type="SecureString", KeyId=key, Tier="Advanced")
    assert out["Tier"] == "Advanced"
    assert ssm.get_parameter(Name=adv, WithDecryption=True)["Parameter"]["Value"] == "x" * 6000
    meta = ssm.describe_parameters(ParameterFilters=[{"Key": "KeyId", "Values": [key]}])["Parameters"]
    assert sorted(m["Name"] for m in meta) == [adv, cmk]

    with pytest.raises(ClientError) as e:
        ssm.put_parameter(Name=f"{prefix}/bad", Value="v", Type="SecureString", KeyId="alias/nope")
    assert code(e) == "InvalidKeyId"


def test_paths_filters_and_pagination(ssm, prefix):
    for n in ["a", "b", "c/d", "c/e/f"]:
        ssm.put_parameter(Name=f"{prefix}/{n}", Value=n, Type="String")
    ssm.put_parameter(Name=f"{prefix}/list", Value="1,2", Type="StringList")
    one = ssm.get_parameters_by_path(Path=prefix)["Parameters"]
    assert [p["Name"] for p in one] == [f"{prefix}/a", f"{prefix}/b", f"{prefix}/list"]
    paginator = ssm.get_paginator("get_parameters_by_path")
    names = [p["Name"] for page in paginator.paginate(Path=prefix, Recursive=True, PaginationConfig={"PageSize": 2}) for p in page["Parameters"]]
    assert len(names) == 5
    lists = ssm.get_parameters_by_path(Path=prefix, Recursive=True, ParameterFilters=[{"Key": "Type", "Values": ["StringList"]}])
    assert [p["Value"] for p in lists["Parameters"]] == ["1,2"]

    paginator = ssm.get_paginator("describe_parameters")
    found = [
        p["Name"]
        for page in paginator.paginate(
            ParameterFilters=[{"Key": "Path", "Option": "Recursive", "Values": [prefix]}], PaginationConfig={"PageSize": 2}
        )
        for p in page["Parameters"]
    ]
    assert sorted(found) == sorted(f"{prefix}/{n}" for n in ["a", "b", "c/d", "c/e/f", "list"])
    contains = ssm.describe_parameters(ParameterFilters=[{"Key": "Name", "Option": "Contains", "Values": [f"{prefix[4:]}/c/e"]}])
    assert [p["Name"] for p in contains["Parameters"]] == [f"{prefix}/c/e/f"]
    with pytest.raises(ClientError) as e:
        ssm.describe_parameters(ParameterFilters=[{"Key": "Path", "Option": "Deep", "Values": [prefix]}])
    assert code(e) == "InvalidFilterOption"
    with pytest.raises(ClientError) as e:
        ssm.get_parameters_by_path(Path=prefix, ParameterFilters=[{"Key": "Tier", "Values": ["Standard"]}])
    assert code(e) == "InvalidFilterKey"


def test_tags_tiers_and_policies(ssm, prefix):
    name = f"{prefix}/tagged"
    ssm.put_parameter(Name=name, Value="v", Type="String", Tags=[{"Key": "team", "Value": "py"}])
    ssm.add_tags_to_resource(ResourceType="Parameter", ResourceId=name, Tags=[{"Key": "env", "Value": "test"}])
    tags = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)["TagList"]
    assert tags == [{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "py"}]
    ssm.remove_tags_from_resource(ResourceType="Parameter", ResourceId=name, TagKeys=["team"])
    assert len(ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)["TagList"]) == 1
    with pytest.raises(ClientError) as e:
        ssm.add_tags_to_resource(ResourceType="Document", ResourceId="nope", Tags=[{"Key": "k", "Value": "v"}])
    assert code(e) == "InvalidResourceId"

    out = ssm.put_parameter(Name=f"{prefix}/it", Value="small", Type="String", Tier="Intelligent-Tiering")
    assert out["Tier"] == "Standard"
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    policies = json.dumps(
        [
            {"Type": "Expiration", "Version": "1.0", "Attributes": {"Timestamp": expires}},
            {"Type": "NoChangeNotification", "Version": "1.0", "Attributes": {"After": "20", "Unit": "Days"}},
        ]
    )
    out = ssm.put_parameter(Name=f"{prefix}/it", Value="small", Overwrite=True, Tier="Intelligent-Tiering", Policies=policies)
    assert out["Tier"] == "Advanced"
    meta = ssm.describe_parameters(ParameterFilters=[{"Key": "Name", "Values": [f"{prefix}/it"]}])["Parameters"][0]
    assert {p["PolicyType"] for p in meta["Policies"]} == {"Expiration", "NoChangeNotification"}
    with pytest.raises(ClientError) as e:
        ssm.put_parameter(Name=f"{prefix}/it", Value="v", Overwrite=True, Policies=json.dumps([{"Type": "Expiration", "Version": "1.0", "Attributes": {"Timestamp": "2001-01-01T00:00:00Z"}}]))
    assert code(e) == "InvalidPolicyAttributeException"
    with pytest.raises(ClientError) as e:
        ssm.put_parameter(Name=f"{prefix}/it", Value="v", Overwrite=True, Policies=json.dumps([{"Type": "Expiration", "Version": "1.0", "Attributes": {"Timestamp": expires}}] * 2))
    assert code(e) == "IncompatiblePolicyException"


def test_service_settings(ssm):
    tier = "/ssm/parameter-store/default-parameter-tier"
    setting = ssm.get_service_setting(SettingId=tier)["ServiceSetting"]
    assert setting["SettingValue"] == "Standard" and setting["Status"] == "Default"
    ssm.update_service_setting(SettingId=tier, SettingValue="Intelligent-Tiering")
    try:
        assert ssm.get_service_setting(SettingId=tier)["ServiceSetting"]["SettingValue"] == "Intelligent-Tiering"
    finally:
        reset = ssm.reset_service_setting(SettingId=tier)["ServiceSetting"]
    assert reset["SettingValue"] == "Standard"
    with pytest.raises(ClientError) as e:
        ssm.get_service_setting(SettingId="/ssm/unknown")
    assert code(e) == "ServiceSettingNotFound"


def test_resource_policies(ssm, prefix):
    name = f"{prefix}/shared"
    ssm.put_parameter(Name=name, Value="v", Type="String", Tier="Advanced")
    arn = f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter{name}"
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Action": "ssm:GetParameter", "Resource": arn}],
        }
    )
    put = ssm.put_resource_policy(ResourceArn=arn, Policy=doc)
    listed = ssm.get_resource_policies(ResourceArn=arn)["Policies"]
    assert listed[0]["PolicyId"] == put["PolicyId"] and json.loads(listed[0]["Policy"]) == json.loads(doc)
    updated = ssm.put_resource_policy(ResourceArn=arn, Policy=doc, PolicyId=put["PolicyId"], PolicyHash=put["PolicyHash"])
    assert updated["PolicyId"] == put["PolicyId"]
    ssm.delete_resource_policy(ResourceArn=arn, PolicyId=put["PolicyId"], PolicyHash=updated["PolicyHash"])
    assert ssm.get_resource_policies(ResourceArn=arn)["Policies"] == []


def test_secrets_manager_reference_needs_decryption(ssm):
    with pytest.raises(ClientError) as e:
        ssm.get_parameter(Name="/aws/reference/secretsmanager/nope")
    assert code(e) == "ValidationException"
    with pytest.raises(ClientError) as e:
        ssm.get_parameter(Name="/aws/reference/secretsmanager/nope", WithDecryption=True)
    assert code(e) == "ParameterNotFound"
