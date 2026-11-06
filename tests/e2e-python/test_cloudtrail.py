"""CloudTrail through boto3.

botocore names CloudTrail's JSON target with the namespace-qualified prefix
(`com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetTrail`), unlike
the Smithy-based SDKs; AWS accepts both.
"""

import uuid

import pytest
from botocore.exceptions import ClientError


def test_trail_lifecycle_with_qualified_target(endpoint, session_for):
    session = session_for()
    s3 = session.client("s3", endpoint_url=endpoint, region_name="us-east-1")
    ct = session.client("cloudtrail", endpoint_url=endpoint, region_name="us-east-1")
    bucket = f"trail-{uuid.uuid4().hex[:8]}"
    name = f"trail-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=bucket)
    policy = (
        '{"Version":"2012-10-17","Statement":['
        '{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl",'
        f'"Resource":"arn:aws:s3:::{bucket}"}},'
        '{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject",'
        f'"Resource":"arn:aws:s3:::{bucket}/*"}}]}}'
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=policy)

    with pytest.raises(ClientError) as e:
        ct.get_trail(Name=name)
    assert e.value.response["Error"]["Code"] == "TrailNotFoundException"

    ct.create_trail(Name=name, S3BucketName=bucket)
    assert ct.get_trail(Name=name)["Trail"]["Name"] == name
    assert ct.get_trail_status(Name=name)["IsLogging"] is False
    ct.delete_trail(Name=name)
