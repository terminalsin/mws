"""S3 bucket and object configuration through boto3: every setting round
trips, deletes take effect, and objects honour their ACLs, locks and
storage classes."""

import datetime
import hashlib
import json
import time
import uuid

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


@pytest.fixture
def s3(endpoint, session_for):
    return session_for().client("s3", endpoint_url=endpoint, config=Config(s3={"addressing_style": "path"}))


@pytest.fixture
def bucket(s3):
    name = f"cov-{uuid.uuid4().hex[:12]}"
    s3.create_bucket(Bucket=name)
    return name


def code(err):
    return err.value.response["Error"]["Code"]


def test_bucket_settings_round_trip_and_delete(s3, bucket):
    s3.put_bucket_cors(
        Bucket=bucket, CORSConfiguration={"CORSRules": [{"AllowedMethods": ["GET"], "AllowedOrigins": ["*"]}]}
    )
    s3.delete_bucket_cors(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.get_bucket_cors(Bucket=bucket)
    assert code(e) == "NoSuchCORSConfiguration"

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}]
        },
    )
    rule = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"
    assert rule["BucketKeyEnabled"] is True
    s3.delete_bucket_encryption(Bucket=bucket)
    # Buckets always encrypt with SSE-S3 by default.
    rule = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"

    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={
            "Rules": [{"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 1}}]
        },
    )
    s3.delete_bucket_lifecycle(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    assert code(e) == "NoSuchLifecycleConfiguration"

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "a", "Value": "1"}]})
    s3.delete_bucket_tagging(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.get_bucket_tagging(Bucket=bucket)
    assert code(e) == "NoSuchTagSet"

    s3.put_bucket_website(
        Bucket=bucket,
        WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}, "ErrorDocument": {"Key": "error.html"}},
    )
    site = s3.get_bucket_website(Bucket=bucket)
    assert site["IndexDocument"]["Suffix"] == "index.html"
    assert site["ErrorDocument"]["Key"] == "error.html"
    s3.delete_bucket_website(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.get_bucket_website(Bucket=bucket)
    assert code(e) == "NoSuchWebsiteConfiguration"

    s3.put_bucket_accelerate_configuration(Bucket=bucket, AccelerateConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_accelerate_configuration(Bucket=bucket)["Status"] == "Enabled"
    s3.put_bucket_request_payment(Bucket=bucket, RequestPaymentConfiguration={"Payer": "Requester"})
    assert s3.get_bucket_request_payment(Bucket=bucket)["Payer"] == "Requester"
    s3.put_bucket_request_payment(Bucket=bucket, RequestPaymentConfiguration={"Payer": "BucketOwner"})

    assert s3.get_bucket_abac(Bucket=bucket)["AbacStatus"]["Status"] == "Disabled"


def test_ownership_acls_and_public_access_block(s3, bucket):
    # New buckets enforce bucket ownership, which disables ACLs.
    controls = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]
    assert controls["Rules"][0]["ObjectOwnership"] == "BucketOwnerEnforced"
    with pytest.raises(ClientError) as e:
        s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    assert code(e) == "AccessControlListNotSupported"

    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    acl = s3.get_bucket_acl(Bucket=bucket)
    owner = acl["Owner"]["ID"]
    assert [g["Permission"] for g in acl["Grants"]] == ["FULL_CONTROL"]

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    assert s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
    with pytest.raises(ClientError) as e:
        s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    assert code(e) == "AccessDenied"
    s3.delete_public_access_block(Bucket=bucket)

    s3.put_bucket_acl(
        Bucket=bucket,
        AccessControlPolicy={
            "Owner": {"ID": owner},
            "Grants": [
                {"Grantee": {"Type": "CanonicalUser", "ID": owner}, "Permission": "FULL_CONTROL"},
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "WRITE",
                },
            ],
        },
    )
    perms = sorted(g["Permission"] for g in s3.get_bucket_acl(Bucket=bucket)["Grants"])
    assert perms == ["FULL_CONTROL", "WRITE"]

    s3.put_object(Bucket=bucket, Key="doc", Body=b"x")
    s3.put_object_acl(Bucket=bucket, Key="doc", ACL="public-read")
    grants = s3.get_object_acl(Bucket=bucket, Key="doc")["Grants"]
    assert any(g["Grantee"].get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers" for g in grants)

    s3.delete_bucket_ownership_controls(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.get_bucket_ownership_controls(Bucket=bucket)
    assert code(e) == "OwnershipControlsNotFoundError"


def test_policy_logging_notifications_and_replication(s3, bucket, endpoint, session_for):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    assert json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"]) == policy

    logs = f"cov-logs-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=logs)
    s3.put_bucket_logging(
        Bucket=bucket, BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": logs, "TargetPrefix": "access/"}}
    )
    enabled = s3.get_bucket_logging(Bucket=bucket)["LoggingEnabled"]
    assert (enabled["TargetBucket"], enabled["TargetPrefix"]) == (logs, "access/")
    s3.put_bucket_logging(Bucket=bucket, BucketLoggingStatus={})
    assert "LoggingEnabled" not in s3.get_bucket_logging(Bucket=bucket)

    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "Id": "new-objects",
                    "QueueArn": f"arn:aws:sqs:us-east-1:{ACCOUNT}:events",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ]
        },
        SkipDestinationValidation=True,
    )
    queues = s3.get_bucket_notification_configuration(Bucket=bucket)["QueueConfigurations"]
    assert queues[0]["Id"] == "new-objects" and queues[0]["Events"] == ["s3:ObjectCreated:*"]
    s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration={})
    assert "QueueConfigurations" not in s3.get_bucket_notification_configuration(Bucket=bucket)

    dest = f"cov-dest-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=dest)
    replication = {
        "Role": f"arn:aws:iam::{ACCOUNT}:role/replication",
        "Rules": [
            {
                "ID": "all",
                "Status": "Enabled",
                "Priority": 1,
                "Filter": {},
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Destination": {"Bucket": f"arn:aws:s3:::{dest}"},
            }
        ],
    }
    with pytest.raises(ClientError) as e:
        s3.put_bucket_replication(Bucket=bucket, ReplicationConfiguration=replication)
    assert code(e) == "InvalidRequest"
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=dest, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_replication(Bucket=bucket, ReplicationConfiguration=replication)
    got = s3.get_bucket_replication(Bucket=bucket)["ReplicationConfiguration"]
    assert got["Rules"][0]["Destination"]["Bucket"] == f"arn:aws:s3:::{dest}"
    s3.delete_bucket_replication(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.get_bucket_replication(Bucket=bucket)
    assert code(e) == "ReplicationConfigurationNotFoundError"


def test_analytics_metrics_inventory_and_tiering(s3, bucket):
    dest = f"arn:aws:s3:::{bucket}"
    s3.put_bucket_analytics_configuration(
        Bucket=bucket,
        Id="a1",
        AnalyticsConfiguration={
            "Id": "a1",
            "Filter": {"Prefix": "logs/"},
            "StorageClassAnalysis": {
                "DataExport": {
                    "OutputSchemaVersion": "V_1",
                    "Destination": {"S3BucketDestination": {"Format": "CSV", "Bucket": dest}},
                }
            },
        },
    )
    assert s3.get_bucket_analytics_configuration(Bucket=bucket, Id="a1")["AnalyticsConfiguration"]["Id"] == "a1"
    listed = s3.list_bucket_analytics_configurations(Bucket=bucket)["AnalyticsConfigurationList"]
    assert [c["Id"] for c in listed] == ["a1"]
    s3.delete_bucket_analytics_configuration(Bucket=bucket, Id="a1")
    with pytest.raises(ClientError) as e:
        s3.get_bucket_analytics_configuration(Bucket=bucket, Id="a1")
    assert code(e) == "NoSuchConfiguration"

    s3.put_bucket_metrics_configuration(
        Bucket=bucket, Id="m1", MetricsConfiguration={"Id": "m1", "Filter": {"Prefix": "img/"}}
    )
    got = s3.get_bucket_metrics_configuration(Bucket=bucket, Id="m1")["MetricsConfiguration"]
    assert got["Filter"]["Prefix"] == "img/"
    assert [c["Id"] for c in s3.list_bucket_metrics_configurations(Bucket=bucket)["MetricsConfigurationList"]] == ["m1"]
    s3.delete_bucket_metrics_configuration(Bucket=bucket, Id="m1")
    assert "MetricsConfigurationList" not in s3.list_bucket_metrics_configurations(Bucket=bucket)

    s3.put_bucket_inventory_configuration(
        Bucket=bucket,
        Id="i1",
        InventoryConfiguration={
            "Id": "i1",
            "IsEnabled": True,
            "IncludedObjectVersions": "Current",
            "Schedule": {"Frequency": "Daily"},
            "Destination": {"S3BucketDestination": {"Bucket": dest, "Format": "CSV"}},
            "OptionalFields": ["Size", "ETag"],
        },
    )
    inv = s3.get_bucket_inventory_configuration(Bucket=bucket, Id="i1")["InventoryConfiguration"]
    assert inv["Schedule"]["Frequency"] == "Daily" and inv["OptionalFields"] == ["Size", "ETag"]
    listed = s3.list_bucket_inventory_configurations(Bucket=bucket)["InventoryConfigurationList"]
    assert [c["Id"] for c in listed] == ["i1"]
    s3.delete_bucket_inventory_configuration(Bucket=bucket, Id="i1")
    with pytest.raises(ClientError) as e:
        s3.get_bucket_inventory_configuration(Bucket=bucket, Id="i1")
    assert code(e) == "NoSuchConfiguration"

    s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket,
        Id="t1",
        IntelligentTieringConfiguration={
            "Id": "t1",
            "Status": "Enabled",
            "Tierings": [{"Days": 90, "AccessTier": "ARCHIVE_ACCESS"}],
        },
    )
    tier = s3.get_bucket_intelligent_tiering_configuration(Bucket=bucket, Id="t1")["IntelligentTieringConfiguration"]
    assert tier["Tierings"] == [{"Days": 90, "AccessTier": "ARCHIVE_ACCESS"}]
    listed = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket)["IntelligentTieringConfigurationList"]
    assert [c["Id"] for c in listed] == ["t1"]
    s3.delete_bucket_intelligent_tiering_configuration(Bucket=bucket, Id="t1")
    with pytest.raises(ClientError) as e:
        s3.get_bucket_intelligent_tiering_configuration(Bucket=bucket, Id="t1")
    assert code(e) == "NoSuchConfiguration"


def test_object_lock_retention_and_legal_hold(s3):
    bucket = f"cov-lock-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    assert s3.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]["ObjectLockEnabled"] == "Enabled"
    s3.put_object_lock_configuration(
        Bucket=bucket,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
        },
    )
    rule = s3.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]["Rule"]
    assert rule["DefaultRetention"] == {"Mode": "GOVERNANCE", "Days": 1}

    version = s3.put_object(Bucket=bucket, Key="ledger", Body=b"v1")["VersionId"]
    retention = s3.get_object_retention(Bucket=bucket, Key="ledger")["Retention"]
    assert retention["Mode"] == "GOVERNANCE"
    with pytest.raises(ClientError) as e:
        s3.delete_object(Bucket=bucket, Key="ledger", VersionId=version)
    assert code(e) == "AccessDenied"

    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)
    s3.put_object_retention(
        Bucket=bucket, Key="ledger", Retention={"Mode": "GOVERNANCE", "RetainUntilDate": later}
    )
    until = s3.get_object_retention(Bucket=bucket, Key="ledger")["Retention"]["RetainUntilDate"]
    assert abs((until - later).total_seconds()) < 1

    s3.put_object_legal_hold(Bucket=bucket, Key="ledger", LegalHold={"Status": "ON"})
    assert s3.get_object_legal_hold(Bucket=bucket, Key="ledger")["LegalHold"]["Status"] == "ON"
    # A legal hold blocks deletion even when governance retention is bypassed.
    with pytest.raises(ClientError) as e:
        s3.delete_object(Bucket=bucket, Key="ledger", VersionId=version, BypassGovernanceRetention=True)
    assert code(e) == "AccessDenied"
    s3.put_object_legal_hold(Bucket=bucket, Key="ledger", LegalHold={"Status": "OFF"})
    s3.delete_object(Bucket=bucket, Key="ledger", VersionId=version, BypassGovernanceRetention=True)

    plain = f"cov-plain-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=plain)
    with pytest.raises(ClientError) as e:
        s3.get_object_lock_configuration(Bucket=plain)
    assert code(e) == "ObjectLockConfigurationNotFoundError"


def test_object_attributes_tagging_copy_parts_restore_and_encryption(s3, bucket, endpoint, session_for):
    body = b"0123456789" * 600_000
    s3.put_object(Bucket=bucket, Key="big", Body=body, ChecksumAlgorithm="SHA256", Tagging="a=1&b=2")
    attrs = s3.get_object_attributes(
        Bucket=bucket, Key="big", ObjectAttributes=["ETag", "Checksum", "ObjectSize", "StorageClass"]
    )
    assert attrs["ObjectSize"] == len(body)
    assert attrs["ETag"] == hashlib.md5(body).hexdigest()
    assert attrs["StorageClass"] == "STANDARD"
    assert "ChecksumSHA256" in attrs["Checksum"]

    s3.delete_object_tagging(Bucket=bucket, Key="big")
    assert s3.get_object_tagging(Bucket=bucket, Key="big")["TagSet"] == []

    upload = s3.create_multipart_upload(Bucket=bucket, Key="copied")["UploadId"]
    first = s3.upload_part_copy(
        Bucket=bucket, Key="copied", UploadId=upload, PartNumber=1, CopySource={"Bucket": bucket, "Key": "big"},
        CopySourceRange="bytes=0-5242879",
    )["CopyPartResult"]["ETag"]
    second = s3.upload_part_copy(
        Bucket=bucket, Key="copied", UploadId=upload, PartNumber=2, CopySource={"Bucket": bucket, "Key": "big"},
        CopySourceRange=f"bytes=5242880-{len(body) - 1}",
    )["CopyPartResult"]["ETag"]
    s3.complete_multipart_upload(
        Bucket=bucket,
        Key="copied",
        UploadId=upload,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": first}, {"PartNumber": 2, "ETag": second}]},
    )
    assert s3.get_object(Bucket=bucket, Key="copied")["Body"].read() == body
    parts = s3.get_object_attributes(Bucket=bucket, Key="copied", ObjectAttributes=["ObjectParts"])
    assert parts["ObjectParts"]["TotalPartsCount"] == 2

    s3.put_object(Bucket=bucket, Key="cold", Body=b"frozen", StorageClass="GLACIER")
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="cold")
    assert code(e) == "InvalidObjectState"
    with pytest.raises(ClientError) as e:
        s3.restore_object(Bucket=bucket, Key="big", RestoreRequest={"Days": 1})
    assert code(e) == "InvalidObjectState"
    s3.restore_object(Bucket=bucket, Key="cold", RestoreRequest={"Days": 2})
    # Restores finish in the background, as on AWS.
    for _ in range(100):
        if 'ongoing-request="false"' in s3.head_object(Bucket=bucket, Key="cold").get("Restore", ""):
            break
        time.sleep(0.1)
    assert s3.get_object(Bucket=bucket, Key="cold")["Body"].read() == b"frozen"
    assert 'ongoing-request="false"' in s3.head_object(Bucket=bucket, Key="cold")["Restore"]

    kms = session_for().client("kms", endpoint_url=endpoint, region_name="us-east-1")
    key_arn = kms.create_key()["KeyMetadata"]["Arn"]
    s3.update_object_encryption(
        Bucket=bucket, Key="big", ObjectEncryption={"SSEKMS": {"KMSKeyArn": key_arn, "BucketKeyEnabled": False}}
    )
    head = s3.head_object(Bucket=bucket, Key="big")
    assert head["ServerSideEncryption"] == "aws:kms"
    assert head["SSEKMSKeyId"] == key_arn
    assert s3.get_object(Bucket=bucket, Key="big")["Body"].read() == body


def test_metadata_table_configurations(s3, bucket):
    table_bucket = f"arn:aws:s3tables:us-east-1:{ACCOUNT}:bucket/metadata"
    s3.create_bucket_metadata_table_configuration(
        Bucket=bucket,
        MetadataTableConfiguration={"S3TablesDestination": {"TableBucketArn": table_bucket, "TableName": "journal"}},
    )
    got = s3.get_bucket_metadata_table_configuration(Bucket=bucket)["GetBucketMetadataTableConfigurationResult"]
    dest = got["MetadataTableConfigurationResult"]["S3TablesDestinationResult"]
    assert (dest["TableBucketArn"], dest["TableName"]) == (table_bucket, "journal")
    assert got["Status"] in ("CREATING", "ACTIVE")
    with pytest.raises(ClientError) as e:
        s3.create_bucket_metadata_table_configuration(
            Bucket=bucket,
            MetadataTableConfiguration={"S3TablesDestination": {"TableBucketArn": table_bucket, "TableName": "again"}},
        )
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 409
    s3.delete_bucket_metadata_table_configuration(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.get_bucket_metadata_table_configuration(Bucket=bucket)
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404

    s3.create_bucket_metadata_configuration(
        Bucket=bucket,
        MetadataConfiguration={
            "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "ENABLED", "Days": 30}},
            "InventoryTableConfiguration": {"ConfigurationState": "DISABLED"},
        },
    )
    s3.update_bucket_metadata_journal_table_configuration(
        Bucket=bucket, JournalTableConfiguration={"RecordExpiration": {"Expiration": "ENABLED", "Days": 60}}
    )
    s3.update_bucket_metadata_inventory_table_configuration(
        Bucket=bucket, InventoryTableConfiguration={"ConfigurationState": "ENABLED"}
    )
    result = s3.get_bucket_metadata_configuration(Bucket=bucket)["GetBucketMetadataConfigurationResult"][
        "MetadataConfigurationResult"
    ]
    assert result["JournalTableConfigurationResult"]["RecordExpiration"] == {"Expiration": "ENABLED", "Days": 60}
    assert result["InventoryTableConfigurationResult"]["ConfigurationState"] == "ENABLED"
    s3.update_bucket_metadata_annotation_table_configuration(
        Bucket=bucket, AnnotationTableConfiguration={"ConfigurationState": "ENABLED"}
    )
    result = s3.get_bucket_metadata_configuration(Bucket=bucket)["GetBucketMetadataConfigurationResult"][
        "MetadataConfigurationResult"
    ]
    assert result["AnnotationTableConfigurationResult"]["ConfigurationState"] == "ENABLED"
    with pytest.raises(ClientError) as e:
        s3.update_bucket_metadata_annotation_table_configuration(
            Bucket=bucket, AnnotationTableConfiguration={"ConfigurationState": "SOMETIMES"}
        )
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
