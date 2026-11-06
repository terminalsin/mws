import json

from ..dsl import aws_error, aws_ok, scenario

S3_DOC = "S3 API reference / error responses"


@scenario("s3", "bucket and object basics")
def _(s):
    s.call("create_bucket", Bucket="${name}")
    s.call("head_bucket", Bucket="${name}")
    s.call("get_bucket_location", Bucket="${name}", expect=aws_ok({"LocationConstraint": None}, source="us-east-1 buckets report a null LocationConstraint"))
    s.call(
        "put_object",
        Bucket="${name}",
        Key="dir/hello.txt",
        Body=b"hello parity",
        ContentType="text/plain",
        Metadata={"owner": "parity"},
        expect=aws_ok({"ETag": '"ef2a02275b08a52915d74cba1e1f4e3e"'}, source="ETag of a single-part upload is the MD5 of the body"),
    )
    s.call("head_object", Bucket="${name}", Key="dir/hello.txt")
    s.call("get_object", Bucket="${name}", Key="dir/hello.txt")
    s.call("get_object", Bucket="${name}", Key="dir/hello.txt", Range="bytes=0-4", expect=aws_ok(status=206))
    s.call("copy_object", Bucket="${name}", Key="copy.txt", CopySource={"Bucket": "${name}", "Key": "dir/hello.txt"})
    s.call("list_objects_v2", Bucket="${name}")
    s.call("list_objects_v2", Bucket="${name}", Prefix="dir/", Delimiter="/")
    s.call("list_objects", Bucket="${name}", Delimiter="/")
    s.call("put_object_tagging", Bucket="${name}", Key="copy.txt", Tagging={"TagSet": [{"Key": "a", "Value": "b"}]})
    s.call("get_object_tagging", Bucket="${name}", Key="copy.txt")
    s.call("get_object", Bucket="${name}", Key="missing", expect=aws_error("NoSuchKey", 404, source=S3_DOC))
    s.call("head_object", Bucket="${name}", Key="missing", expect=aws_error("404", 404, source="HEAD errors have no body"))
    s.call("get_object", Bucket="${name}-nope", Key="x", expect=aws_error("NoSuchBucket", 404, source=S3_DOC))
    s.call(
        "create_bucket",
        Bucket="${name}",
        expect=aws_ok(status=200, source="S3 CreateBucket: in us-east-1 re-creating a bucket you own succeeds (legacy behaviour)"),
    )
    s.call("create_bucket", Bucket="Invalid_Bucket", expect=aws_error("InvalidBucketName", 400, source=S3_DOC))
    s.call("delete_bucket", Bucket="${name}", expect=aws_error("BucketNotEmpty", 409, source=S3_DOC))
    s.call(
        "delete_objects",
        Bucket="${name}",
        Delete={"Objects": [{"Key": "dir/hello.txt"}, {"Key": "copy.txt"}, {"Key": "never-existed"}]},
    )
    s.cleanup("delete_bucket", Bucket="${name}")


@scenario("s3", "bucket configuration")
def _(s):
    s.call("create_bucket", Bucket="${name}")
    s.call("put_bucket_versioning", Bucket="${name}", VersioningConfiguration={"Status": "Enabled"})
    s.call("get_bucket_versioning", Bucket="${name}")
    s.call("put_bucket_tagging", Bucket="${name}", Tagging={"TagSet": [{"Key": "team", "Value": "parity"}]})
    s.call("get_bucket_tagging", Bucket="${name}")
    s.call("delete_bucket_tagging", Bucket="${name}", expect=aws_ok(status=204))
    s.call("get_bucket_tagging", Bucket="${name}", expect=aws_error("NoSuchTagSet", 404, source=S3_DOC))
    s.call(
        "put_bucket_policy",
        Bucket="${name}",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::${account}:root"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::${name}/*",
                    }
                ],
            }
        ),
    )
    s.call("get_bucket_policy", Bucket="${name}")
    s.call("get_bucket_policy_status", Bucket="${name}")
    s.call("delete_bucket_policy", Bucket="${name}")
    s.call("get_bucket_policy", Bucket="${name}", expect=aws_error("NoSuchBucketPolicy", 404, source=S3_DOC))
    s.call(
        "put_bucket_cors",
        Bucket="${name}",
        CORSConfiguration={"CORSRules": [{"AllowedMethods": ["GET"], "AllowedOrigins": ["*"], "MaxAgeSeconds": 300}]},
    )
    s.call("get_bucket_cors", Bucket="${name}")
    s.call(
        "put_bucket_lifecycle_configuration",
        Bucket="${name}",
        LifecycleConfiguration={
            "Rules": [{"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 7}}]
        },
    )
    s.call("get_bucket_lifecycle_configuration", Bucket="${name}")
    s.call("get_bucket_encryption", Bucket="${name}")
    s.call(
        "put_public_access_block",
        Bucket="${name}",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s.call("get_public_access_block", Bucket="${name}")
    s.call("get_bucket_acl", Bucket="${name}")
    s.call("get_bucket_ownership_controls", Bucket="${name}")
    s.call("get_bucket_website", Bucket="${name}", expect=aws_error("NoSuchWebsiteConfiguration", 404, source=S3_DOC))
    s.call("put_object", Bucket="${name}", Key="v.txt", Body=b"v1")
    s.call("put_object", Bucket="${name}", Key="v.txt", Body=b"v2")
    s.call("list_object_versions", Bucket="${name}")
    s.call("delete_object", Bucket="${name}", Key="v.txt")
    s.call("list_object_versions", Bucket="${name}", save={"versions": "[Versions[].{Key: Key, VersionId: VersionId}, DeleteMarkers[].{Key: Key, VersionId: VersionId}][]"})
    s.cleanup("delete_objects", Bucket="${name}", Delete={"Objects": "${versions}"})
    s.cleanup("delete_bucket", Bucket="${name}")


@scenario("s3", "multipart upload")
def _(s):
    s.call("create_bucket", Bucket="${name}")
    s.call("create_multipart_upload", Bucket="${name}", Key="big.bin", save={"upload": "UploadId"})
    s.call("upload_part", Bucket="${name}", Key="big.bin", UploadId="${upload}", PartNumber=1, Body=b"a" * (5 * 1024 * 1024), save={"etag1": "ETag"})
    s.call("upload_part", Bucket="${name}", Key="big.bin", UploadId="${upload}", PartNumber=2, Body=b"tail", save={"etag2": "ETag"})
    s.call("list_parts", Bucket="${name}", Key="big.bin", UploadId="${upload}")
    s.call("list_multipart_uploads", Bucket="${name}")
    s.call(
        "complete_multipart_upload",
        Bucket="${name}",
        Key="big.bin",
        UploadId="${upload}",
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": "${etag1}"}, {"PartNumber": 2, "ETag": "${etag2}"}]},
        expect=aws_ok({"ETag": 're:"[0-9a-f]{32}-2"'}, source="multipart ETag is MD5-of-MD5s plus -<parts>"),
    )
    s.call("head_object", Bucket="${name}", Key="big.bin")
    s.call(
        "complete_multipart_upload",
        Bucket="${name}",
        Key="big.bin",
        UploadId="nope",
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": "${etag1}"}]},
        expect=aws_error("NoSuchUpload", 404, source=S3_DOC),
    )
    s.call("create_multipart_upload", Bucket="${name}", Key="aborted", save={"upload2": "UploadId"})
    s.call("abort_multipart_upload", Bucket="${name}", Key="aborted", UploadId="${upload2}", expect=aws_ok(status=204))
    s.cleanup("delete_object", Bucket="${name}", Key="big.bin")
    s.cleanup("delete_bucket", Bucket="${name}")


@scenario("s3", "list buckets")
def _(s):
    s.call("list_buckets", _shape_only=True, _note="other buckets differ between emulators; shape only")


@scenario("s3control", "account public access block", needs=("s3control",))
def _(s):
    s.call("get_public_access_block", AccountId="${account}", _note="fresh accounts have none")
    s.call(
        "put_public_access_block",
        AccountId="${account}",
        PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
    )
    s.call("get_public_access_block", AccountId="${account}")
    s.cleanup("delete_public_access_block", AccountId="${account}")


@scenario("s3control", "access points")
def _(s):
    s.call("create_bucket", service="s3", Bucket="${name}")
    s.call("create_access_point", AccountId="${account}", Name="${name}-ap", Bucket="${name}")
    s.call("get_access_point", AccountId="${account}", Name="${name}-ap")
    s.call("list_access_points", AccountId="${account}", Bucket="${name}")
    s.call("get_access_point", AccountId="${account}", Name="${name}-none", expect=aws_error("NoSuchAccessPoint", 404))
    s.cleanup("delete_access_point", AccountId="${account}", Name="${name}-ap")
    s.cleanup("delete_bucket", service="s3", Bucket="${name}")
