"""S3 through boto3."""

import hashlib
import json
import urllib.error
import urllib.request
import uuid

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError


@pytest.fixture
def s3(endpoint, session_for):
    return session_for().client("s3", endpoint_url=endpoint, config=Config(s3={"addressing_style": "path"}))


@pytest.fixture
def bucket(s3):
    name = f"boto-{uuid.uuid4().hex[:12]}"
    s3.create_bucket(Bucket=name)
    return name


def code(err):
    return err.value.response["Error"]["Code"]


def test_objects_round_trip(s3, bucket):
    put = s3.put_object(Bucket=bucket, Key="a/b.txt", Body=b"hello", Metadata={"k": "v"}, ContentType="text/plain")
    assert put["ETag"] == '"' + hashlib.md5(b"hello").hexdigest() + '"'
    got = s3.get_object(Bucket=bucket, Key="a/b.txt")
    assert got["Body"].read() == b"hello"
    assert got["Metadata"] == {"k": "v"}
    assert got["ContentType"] == "text/plain"
    assert s3.get_object(Bucket=bucket, Key="a/b.txt", Range="bytes=1-3")["Body"].read() == b"ell"
    head = s3.head_object(Bucket=bucket, Key="a/b.txt")
    assert head["ContentLength"] == 5

    with pytest.raises(ClientError) as err:
        s3.get_object(Bucket=bucket, Key="missing")
    assert code(err) == "NoSuchKey"
    with pytest.raises(ClientError) as err:
        s3.head_object(Bucket=bucket, Key="missing")
    assert err.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404


def test_upload_fileobj_uses_multipart(s3, bucket):
    import io

    from boto3.s3.transfer import TransferConfig

    data = bytes(range(256)) * (6 * 1024 * 1024 // 256 * 2)
    config = TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024)
    s3.upload_fileobj(io.BytesIO(data), bucket, "big.bin", Config=config)
    head = s3.head_object(Bucket=bucket, Key="big.bin")
    assert head["ContentLength"] == len(data)
    assert head["ETag"].endswith('-3"')
    out = io.BytesIO()
    s3.download_fileobj(bucket, "big.bin", out)
    assert out.getvalue() == data


def test_listing_and_batch_delete(s3, bucket):
    for key in ["x/1", "x/2", "y", "z"]:
        s3.put_object(Bucket=bucket, Key=key, Body=b"")
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, PaginationConfig={"PageSize": 2})
    keys = [o["Key"] for page in pages for o in page.get("Contents", [])]
    assert keys == ["x/1", "x/2", "y", "z"]
    out = s3.list_objects_v2(Bucket=bucket, Delimiter="/")
    assert [p["Prefix"] for p in out["CommonPrefixes"]] == ["x/"]
    deleted = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": "x/1"}, {"Key": "y"}]})
    assert sorted(d["Key"] for d in deleted["Deleted"]) == ["x/1", "y"]
    assert s3.list_objects_v2(Bucket=bucket)["KeyCount"] == 2


def test_versioning(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    v1 = s3.put_object(Bucket=bucket, Key="k", Body=b"1")["VersionId"]
    s3.put_object(Bucket=bucket, Key="k", Body=b"2")
    marker = s3.delete_object(Bucket=bucket, Key="k")
    assert marker["DeleteMarker"] is True
    with pytest.raises(ClientError) as err:
        s3.get_object(Bucket=bucket, Key="k")
    assert code(err) == "NoSuchKey"
    assert s3.get_object(Bucket=bucket, Key="k", VersionId=v1)["Body"].read() == b"1"
    versions = s3.list_object_versions(Bucket=bucket)
    assert len(versions["Versions"]) == 2
    assert len(versions["DeleteMarkers"]) == 1


def test_bucket_configuration_round_trips(s3, bucket):
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "team", "Value": "core"}]})
    assert s3.get_bucket_tagging(Bucket=bucket)["TagSet"] == [{"Key": "team", "Value": "core"}]
    s3.put_bucket_cors(
        Bucket=bucket,
        CORSConfiguration={"CORSRules": [{"AllowedMethods": ["GET"], "AllowedOrigins": ["https://example.com"]}]},
    )
    assert s3.get_bucket_cors(Bucket=bucket)["CORSRules"][0]["AllowedMethods"] == ["GET"]
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={
            "Rules": [{"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 1}}]
        },
    )
    assert s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"][0]["ID"] == "expire"
    enc = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]
    assert enc["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
    assert s3.get_bucket_location(Bucket=bucket).get("LocationConstraint") is None
    with pytest.raises(ClientError) as err:
        s3.get_bucket_website(Bucket=bucket)
    assert code(err) == "NoSuchWebsiteConfiguration"


def test_bucket_policy_enforced_for_iam_users(s3, bucket, endpoint, session_for):
    iam = session_for().client("iam", endpoint_url=endpoint)
    user = f"s3user-{uuid.uuid4().hex[:8]}"
    iam.create_user(UserName=user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    other = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client(
        "s3", endpoint_url=endpoint, config=Config(s3={"addressing_style": "path"})
    )
    s3.put_object(Bucket=bucket, Key="doc", Body=b"data")
    with pytest.raises(ClientError) as err:
        other.get_object(Bucket=bucket, Key="doc")
    assert code(err) == "AccessDenied"
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::123456789012:user/{user}"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    }
                ],
            }
        ),
    )
    assert other.get_object(Bucket=bucket, Key="doc")["Body"].read() == b"data"


def test_presigned_url(endpoint, session_for, bucket):
    s3 = session_for().client(
        "s3", endpoint_url=endpoint, config=Config(signature_version="s3v4", s3={"addressing_style": "path"})
    )
    s3.put_object(Bucket=bucket, Key="p", Body=b"presigned")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "p"}, ExpiresIn=60)
    with urllib.request.urlopen(url) as resp:
        assert resp.read() == b"presigned"
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(url.replace("X-Amz-Signature=", "X-Amz-Signature=0"))
    assert err.value.code == 403


def test_signature_v2_is_refused(s3, bucket):
    # boto3 still presigns with Signature Version 2 unless told otherwise;
    # S3 refuses it for buckets created since 2020.
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "p"}, ExpiresIn=60)
    assert "AWSAccessKeyId=" in url
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(url)
    assert err.value.code == 400
    assert b"<Code>InvalidRequest</Code>" in err.value.read()


def test_virtual_hosted_style(endpoint, session_for, bucket):
    # boto3's default addressing puts the bucket in the Host header.
    s3 = session_for().client("s3", endpoint_url=endpoint.replace("127.0.0.1", "s3.localhost"))
    try:
        s3.put_object(Bucket=bucket, Key="vh", Body=b"v")
    except Exception:  # pragma: no cover - needs *.localhost to resolve
        pytest.skip("*.s3.localhost does not resolve here")
    assert s3.get_object(Bucket=bucket, Key="vh")["Body"].read() == b"v"


def test_resource_api(endpoint, session_for, bucket):
    s3 = session_for().resource("s3", endpoint_url=endpoint, config=Config(s3={"addressing_style": "path"}))
    b = s3.Bucket(bucket)
    b.put_object(Key="r1", Body=b"1")
    b.put_object(Key="r2", Body=b"2")
    assert sorted(o.key for o in b.objects.all()) == ["r1", "r2"]
    b.objects.all().delete()
    assert list(b.objects.all()) == []
    b.delete()
    assert bucket not in [x.name for x in s3.buckets.all()]

