"""S3 Inventory reports through boto3, read back with pyarrow and gzip."""

import gzip
import hashlib
import io
import json
import urllib.request
import uuid

import pytest
from botocore.config import Config

ACCOUNT = "123456789012"


def clock(endpoint, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{endpoint}/_mws/clock", data=data, method="POST" if data else "GET")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


@pytest.fixture
def next_day(endpoint):
    """Move the emulated clock a day on, and put it back afterwards."""
    before = clock(endpoint)["offsetSeconds"]
    yield lambda: clock(endpoint, {"advanceSeconds": 86400})
    clock(endpoint, {"offsetSeconds": before})


@pytest.fixture
def s3(endpoint, session_for):
    return session_for().client("s3", endpoint_url=endpoint, config=Config(s3={"addressing_style": "path"}))


def setup(s3, fmt):
    source, dest = f"inv-src-{uuid.uuid4().hex[:8]}", f"inv-dst-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=source)
    s3.create_bucket(Bucket=dest)
    s3.put_bucket_policy(
        Bucket=dest,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "s3.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{dest}/*",
                        "Condition": {
                            "ArnLike": {"aws:SourceArn": f"arn:aws:s3:::{source}"},
                            "StringEquals": {"aws:SourceAccount": ACCOUNT},
                        },
                    }
                ],
            }
        ),
    )
    s3.put_object(Bucket=source, Key="a.txt", Body=b"hello")
    s3.put_object(Bucket=source, Key="dir/b c.bin", Body=b"\x00" * 10)
    s3.put_bucket_inventory_configuration(
        Bucket=source,
        Id="weekly",
        InventoryConfiguration={
            "Id": "weekly",
            "IsEnabled": True,
            "IncludedObjectVersions": "Current",
            "OptionalFields": ["Size", "LastModifiedDate", "IsMultipartUploaded"],
            "Schedule": {"Frequency": "Weekly"},
            "Destination": {"S3BucketDestination": {"Bucket": f"arn:aws:s3:::{dest}", "Format": fmt}},
        },
    )
    return source, dest


def manifest(s3, dest, source):
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=dest).get("Contents", [])]
    m = next(k for k in keys if k.endswith("manifest.json"))
    assert m.startswith(f"{source}/weekly/")
    body = s3.get_object(Bucket=dest, Key=m)["Body"].read()
    checksum = s3.get_object(Bucket=dest, Key=m.replace("manifest.json", "manifest.checksum"))["Body"].read()
    assert checksum.decode() == hashlib.md5(body).hexdigest()
    return json.loads(body)


def test_csv_inventory(s3, next_day):
    source, dest = setup(s3, "CSV")
    assert "Contents" not in s3.list_objects_v2(Bucket=dest)
    next_day()
    m = manifest(s3, dest, source)
    assert m["fileSchema"] == "Bucket, Key, Size, LastModifiedDate, IsMultipartUploaded"
    data = s3.get_object(Bucket=dest, Key=m["files"][0]["key"])["Body"].read()
    assert hashlib.md5(data).hexdigest() == m["files"][0]["MD5checksum"]
    rows = [line.split('","') for line in gzip.decompress(data).decode().splitlines()]
    assert [r[1] for r in rows] == ["a.txt", "dir%2Fb+c.bin"]
    assert rows[0][2] == "5" and rows[1][4] == 'false"'


def test_parquet_inventory_reads_with_pyarrow(s3, next_day):
    pq = pytest.importorskip("pyarrow.parquet")
    source, dest = setup(s3, "Parquet")
    next_day()
    m = manifest(s3, dest, source)
    assert m["fileFormat"] == "Parquet"
    data = s3.get_object(Bucket=dest, Key=m["files"][0]["key"])["Body"].read()
    table = pq.read_table(io.BytesIO(data))
    assert table.column_names == ["bucket", "key", "size", "last_modified_date", "is_multipart_uploaded"]
    rows = table.to_pylist()
    assert [r["key"] for r in rows] == ["a.txt", "dir/b c.bin"]
    assert [r["size"] for r in rows] == [5, 10]
    assert rows[0]["bucket"] == source
    assert rows[0]["is_multipart_uploaded"] is False
    assert rows[0]["last_modified_date"].year >= 2024
