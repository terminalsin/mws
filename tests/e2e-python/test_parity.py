"""Cross-service behaviour boto3 users rely on: how each protocol names
authentication failures, S3's own validation errors, and SSM public
parameters. Expected values are what AWS returns."""

import uuid

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

NO_RETRY = Config(retries={"max_attempts": 1}, s3={"addressing_style": "path"})


def client(session_for, endpoint, service, **creds):
    return session_for(**creds).client(service, endpoint_url=endpoint, config=NO_RETRY)


@pytest.mark.parametrize(
    "service,call,unknown_key,bad_signature,status",
    [
        ("kms", "list_keys", "UnrecognizedClientException", "InvalidSignatureException", 400),
        ("logs", "describe_log_groups", "UnrecognizedClientException", "InvalidSignatureException", 400),
        ("ssm", "describe_parameters", "UnrecognizedClientException", "InvalidSignatureException", 400),
        ("lambda", "list_functions", "UnrecognizedClientException", "InvalidSignatureException", 403),
        ("sqs", "list_queues", "InvalidClientTokenId", "SignatureDoesNotMatch", 403),
        ("sts", "get_caller_identity", "InvalidClientTokenId", "SignatureDoesNotMatch", 403),
        ("s3", "list_buckets", "InvalidAccessKeyId", "SignatureDoesNotMatch", 403),
    ],
)
def test_auth_errors_per_protocol(session_for, endpoint, service, call, unknown_key, bad_signature, status):
    bad = client(session_for, endpoint, service, key="AKIAAAAAAAAAAAAAAAAA", secret="x")
    with pytest.raises(ClientError) as e:
        getattr(bad, call)()
    assert e.value.response["Error"]["Code"] == unknown_key
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == status
    wrong = client(session_for, endpoint, service, secret="wrong-secret-wrong-secret-wrong-secret00")
    with pytest.raises(ClientError) as e:
        getattr(wrong, call)()
    assert e.value.response["Error"]["Code"] == bad_signature


def test_s3_validation_codes(session_for, endpoint):
    s3 = client(session_for, endpoint, "s3")
    bucket = f"parity-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="k", Body=b"x", StorageClass="FOO")
    assert e.value.response["Error"]["Code"] == "InvalidStorageClass"
    with pytest.raises(ClientError) as e:
        s3.create_bucket(Bucket=bucket + "-x", CreateBucketConfiguration={"LocationConstraint": "us-east-1"})
    assert e.value.response["Error"]["Code"] == "InvalidLocationConstraint"


def test_ssm_public_parameters(session_for, endpoint):
    ssm = client(session_for, endpoint, "ssm")
    p = ssm.get_parameter(Name="/aws/service/global-infrastructure/regions/eu-west-1/longName")["Parameter"]
    assert p["Value"] == "Europe (Ireland)"
    assert p["ARN"] == "arn:aws:ssm:us-east-1::parameter/aws/service/global-infrastructure/regions/eu-west-1/longName"
    ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    assert ami["Parameter"]["Value"].startswith("ami-")
    assert ami["Parameter"]["DataType"] == "aws:ec2:image"
    pages = ssm.get_paginator("get_parameters_by_path").paginate(Path="/aws/service/global-infrastructure/regions")
    regions = {p["Value"] for page in pages for p in page["Parameters"]}
    assert {"us-east-1", "eu-west-1", "ap-southeast-2"} <= regions
