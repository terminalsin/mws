//! S3, observed through the official Rust SDK.

use std::time::Duration;

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    BucketVersioningStatus, ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier, Tag,
    Tagging, VersioningConfiguration,
};
use mws_e2e::{user_with_policy, Mws};

async fn root(mws: &Mws) -> aws_sdk_s3::Client {
    Mws::s3(&mws.root_sdk_config().await)
}

async fn body(out: aws_sdk_s3::operation::get_object::GetObjectOutput) -> Vec<u8> {
    out.body.collect().await.unwrap().into_bytes().to_vec()
}

#[tokio::test]
async fn buckets_create_list_and_delete() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("alpha").send().await.unwrap();
    s3.create_bucket().bucket("beta").send().await.unwrap();
    // us-east-1 keeps its legacy answer: re-creating your own bucket succeeds.
    s3.create_bucket().bucket("alpha").send().await.unwrap();
    let err = s3.create_bucket().bucket("Bad_Name").send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidBucketName"));

    let list = s3.list_buckets().send().await.unwrap();
    let names: Vec<_> = list.buckets().iter().filter_map(|b| b.name()).collect();
    assert_eq!(names, ["alpha", "beta"]);
    assert!(list.owner().and_then(|o| o.id()).is_some());

    s3.head_bucket().bucket("alpha").send().await.unwrap();
    let err = s3.head_bucket().bucket("missing").send().await.unwrap_err();
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 404);

    s3.put_object().bucket("alpha").key("k").body(ByteStream::from_static(b"x")).send().await.unwrap();
    let err = s3.delete_bucket().bucket("alpha").send().await.unwrap_err();
    assert_eq!(err.code(), Some("BucketNotEmpty"));
    assert_eq!(err.message(), Some("The bucket you tried to delete is not empty"));
    s3.delete_object().bucket("alpha").key("k").send().await.unwrap();
    s3.delete_bucket().bucket("alpha").send().await.unwrap();
    let err = s3.get_bucket_location().bucket("alpha").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchBucket"));
}

#[tokio::test]
async fn objects_round_trip_with_metadata_ranges_and_conditions() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("data").send().await.unwrap();
    let put = s3
        .put_object()
        .bucket("data")
        .key("dir/hello world.txt")
        .body(ByteStream::from_static(b"hello, world"))
        .content_type("text/plain")
        .metadata("colour", "blue")
        .send()
        .await
        .unwrap();
    let etag = put.e_tag().unwrap().to_string();
    assert_eq!(etag, "\"e4d7f1b4ed2e42d15898f4b27b019da4\"");

    let got = s3.get_object().bucket("data").key("dir/hello world.txt").send().await.unwrap();
    assert_eq!(got.content_type(), Some("text/plain"));
    assert_eq!(got.metadata().unwrap().get("colour").map(String::as_str), Some("blue"));
    assert_eq!(got.content_length(), Some(12));
    assert_eq!(body(got).await, b"hello, world");

    let ranged = s3.get_object().bucket("data").key("dir/hello world.txt").range("bytes=7-").send().await.unwrap();
    assert_eq!(ranged.content_range(), Some("bytes 7-11/12"));
    assert_eq!(body(ranged).await, b"world");

    let err = s3.get_object().bucket("data").key("dir/hello world.txt").if_match("\"nope\"").send().await.unwrap_err();
    assert_eq!(err.code(), Some("PreconditionFailed"));
    let err = s3.head_object().bucket("data").key("dir/hello world.txt").if_none_match(&etag).send().await.unwrap_err();
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 304);

    // Conditional create.
    let err = s3
        .put_object()
        .bucket("data")
        .key("dir/hello world.txt")
        .if_none_match("*")
        .body(ByteStream::from_static(b"again"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("PreconditionFailed"));

    let err = s3.get_object().bucket("data").key("missing").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchKey"));
    assert_eq!(err.message(), Some("The specified key does not exist."));
}

#[tokio::test]
async fn checksums_are_computed_and_verified() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("sums").send().await.unwrap();
    let put = s3
        .put_object()
        .bucket("sums")
        .key("a")
        .checksum_algorithm(ChecksumAlgorithm::Sha256)
        .body(ByteStream::from_static(b"abc"))
        .send()
        .await
        .unwrap();
    assert_eq!(put.checksum_sha256(), Some("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="));
    let head = s3
        .head_object()
        .bucket("sums")
        .key("a")
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(head.checksum_sha256(), Some("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="));

    // The SDK's default CRC32 checksum travels in an aws-chunked trailer.
    let put = s3.put_object().bucket("sums").key("b").body(ByteStream::from_static(b"hello")).send().await.unwrap();
    assert_eq!(put.checksum_crc32(), Some("NhCmhg=="));
    let got = s3.get_object().bucket("sums").key("b").send().await.unwrap();
    assert_eq!(body(got).await, b"hello");

    let err = s3
        .put_object()
        .bucket("sums")
        .key("c")
        .checksum_sha256("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")
        .body(ByteStream::from_static(b"abd"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("BadDigest"));
}

#[tokio::test]
async fn multipart_upload() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("big").send().await.unwrap();
    let up = s3.create_multipart_upload().bucket("big").key("file").send().await.unwrap();
    let id = up.upload_id().unwrap();
    let part1 = vec![b'a'; 5 * 1024 * 1024];
    let part2 = b"tail".to_vec();
    let mut parts = Vec::new();
    for (n, data) in [(1, part1.clone()), (2, part2.clone())] {
        let out = s3
            .upload_part()
            .bucket("big")
            .key("file")
            .upload_id(id)
            .part_number(n)
            .body(ByteStream::from(data))
            .send()
            .await
            .unwrap();
        parts.push(CompletedPart::builder().part_number(n).e_tag(out.e_tag().unwrap()).build());
    }
    let listed = s3.list_parts().bucket("big").key("file").upload_id(id).send().await.unwrap();
    assert_eq!(listed.parts().len(), 2);
    let uploads = s3.list_multipart_uploads().bucket("big").send().await.unwrap();
    assert_eq!(uploads.uploads().len(), 1);

    let done = s3
        .complete_multipart_upload()
        .bucket("big")
        .key("file")
        .upload_id(id)
        .multipart_upload(CompletedMultipartUpload::builder().set_parts(Some(parts)).build())
        .send()
        .await
        .unwrap();
    assert!(done.e_tag().unwrap().ends_with("-2\""));
    let got = s3.get_object().bucket("big").key("file").send().await.unwrap();
    assert_eq!(got.content_length(), Some(5 * 1024 * 1024 + 4));
    let data = body(got).await;
    assert_eq!(&data[data.len() - 4..], b"tail");

    let part = s3.get_object().bucket("big").key("file").part_number(2).send().await.unwrap();
    assert_eq!(part.parts_count(), Some(2));
    assert_eq!(body(part).await, b"tail");

    // Small non-final parts are refused at completion.
    let up = s3.create_multipart_upload().bucket("big").key("small").send().await.unwrap();
    let id = up.upload_id().unwrap();
    let mut parts = Vec::new();
    for n in 1..=2 {
        let out = s3
            .upload_part()
            .bucket("big")
            .key("small")
            .upload_id(id)
            .part_number(n)
            .body(ByteStream::from_static(b"tiny"))
            .send()
            .await
            .unwrap();
        parts.push(CompletedPart::builder().part_number(n).e_tag(out.e_tag().unwrap()).build());
    }
    let err = s3
        .complete_multipart_upload()
        .bucket("big")
        .key("small")
        .upload_id(id)
        .multipart_upload(CompletedMultipartUpload::builder().set_parts(Some(parts)).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("EntityTooSmall"));
    s3.abort_multipart_upload().bucket("big").key("small").upload_id(id).send().await.unwrap();
    let err = s3.list_parts().bucket("big").key("small").upload_id(id).send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchUpload"));
}

#[tokio::test]
async fn versioning_and_delete_markers() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("ver").send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("ver")
        .versioning_configuration(VersioningConfiguration::builder().status(BucketVersioningStatus::Enabled).build())
        .send()
        .await
        .unwrap();
    let v1 = s3.put_object().bucket("ver").key("k").body(ByteStream::from_static(b"one")).send().await.unwrap();
    let v2 = s3.put_object().bucket("ver").key("k").body(ByteStream::from_static(b"two")).send().await.unwrap();
    let v1 = v1.version_id().unwrap().to_string();
    assert_ne!(Some(v1.as_str()), v2.version_id());

    let del = s3.delete_object().bucket("ver").key("k").send().await.unwrap();
    assert_eq!(del.delete_marker(), Some(true));
    let err = s3.get_object().bucket("ver").key("k").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchKey"));
    let old = s3.get_object().bucket("ver").key("k").version_id(&v1).send().await.unwrap();
    assert_eq!(body(old).await, b"one");

    let versions = s3.list_object_versions().bucket("ver").send().await.unwrap();
    assert_eq!(versions.versions().len(), 2);
    assert_eq!(versions.delete_markers().len(), 1);
    assert_eq!(versions.delete_markers()[0].is_latest(), Some(true));

    // Removing the marker brings the previous version back.
    s3.delete_object().bucket("ver").key("k").version_id(del.version_id().unwrap()).send().await.unwrap();
    let got = s3.get_object().bucket("ver").key("k").send().await.unwrap();
    assert_eq!(body(got).await, b"two");
    let status = s3.get_bucket_versioning().bucket("ver").send().await.unwrap();
    assert_eq!(status.status(), Some(&BucketVersioningStatus::Enabled));
}

#[tokio::test]
async fn listing_with_prefixes_delimiters_and_pages() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("list").send().await.unwrap();
    for key in ["a/1", "a/2", "b/1", "c", "d"] {
        s3.put_object().bucket("list").key(key).body(ByteStream::from_static(b"x")).send().await.unwrap();
    }
    let out = s3.list_objects_v2().bucket("list").delimiter("/").send().await.unwrap();
    let prefixes: Vec<_> = out.common_prefixes().iter().filter_map(|p| p.prefix()).collect();
    let keys: Vec<_> = out.contents().iter().filter_map(|o| o.key()).collect();
    assert_eq!(prefixes, ["a/", "b/"]);
    assert_eq!(keys, ["c", "d"]);

    let page = s3.list_objects_v2().bucket("list").max_keys(2).send().await.unwrap();
    assert_eq!(page.key_count(), Some(2));
    assert_eq!(page.is_truncated(), Some(true));
    let rest = s3
        .list_objects_v2()
        .bucket("list")
        .continuation_token(page.next_continuation_token().unwrap())
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = rest.contents().iter().filter_map(|o| o.key()).collect();
    assert_eq!(keys, ["b/1", "c", "d"]);

    let v1 = s3.list_objects().bucket("list").prefix("a/").send().await.unwrap();
    assert_eq!(v1.contents().len(), 2);

    let deleted = s3
        .delete_objects()
        .bucket("list")
        .delete(
            Delete::builder()
                .objects(ObjectIdentifier::builder().key("a/1").build().unwrap())
                .objects(ObjectIdentifier::builder().key("c").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.deleted().len(), 2);
    let out = s3.list_objects_v2().bucket("list").send().await.unwrap();
    assert_eq!(out.key_count(), Some(3));
}

#[tokio::test]
async fn copy_and_tagging() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("src").send().await.unwrap();
    s3.create_bucket().bucket("dst").send().await.unwrap();
    s3.put_object()
        .bucket("src")
        .key("orig")
        .tagging("team=core")
        .body(ByteStream::from_static(b"payload"))
        .send()
        .await
        .unwrap();
    s3.copy_object().bucket("dst").key("copy").copy_source("src/orig").send().await.unwrap();
    let got = s3.get_object().bucket("dst").key("copy").send().await.unwrap();
    assert_eq!(body(got).await, b"payload");
    let tags = s3.get_object_tagging().bucket("dst").key("copy").send().await.unwrap();
    assert_eq!(tags.tag_set()[0].key(), "team");

    s3.put_object_tagging()
        .bucket("dst")
        .key("copy")
        .tagging(Tagging::builder().tag_set(Tag::builder().key("env").value("dev").build().unwrap()).build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = s3.get_object_tagging().bucket("dst").key("copy").send().await.unwrap();
    assert_eq!(tags.tag_set().len(), 1);
    assert_eq!(tags.tag_set()[0].value(), "dev");
}

#[tokio::test]
async fn bucket_policies_and_iam_are_enforced() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("guarded").send().await.unwrap();
    s3.put_object().bucket("guarded").key("doc").body(ByteStream::from_static(b"secret")).send().await.unwrap();

    let (_, alice_cfg) = user_with_policy(&mws, "alice", None).await;
    let alice = Mws::s3(&alice_cfg);
    let err = alice.get_object().bucket("guarded").key("doc").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 403);

    // A bucket policy grants alice read access.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"AWS":"arn:aws:iam::123456789012:user/alice"},
        "Action":"s3:GetObject","Resource":"arn:aws:s3:::guarded/*"}]}"#;
    s3.put_bucket_policy().bucket("guarded").policy(policy).send().await.unwrap();
    let got = alice.get_object().bucket("guarded").key("doc").send().await.unwrap();
    assert_eq!(body(got).await, b"secret");
    let err =
        alice.put_object().bucket("guarded").key("x").body(ByteStream::from_static(b"no")).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // An explicit deny in the bucket policy beats the identity policy.
    let (_, bob_cfg) = user_with_policy(
        &mws,
        "bob",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#),
    )
    .await;
    let bob = Mws::s3(&bob_cfg);
    bob.get_object().bucket("guarded").key("doc").send().await.unwrap();
    let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny",
        "Principal":{"AWS":"arn:aws:iam::123456789012:user/bob"},
        "Action":"s3:*","Resource":["arn:aws:s3:::guarded","arn:aws:s3:::guarded/*"]}]}"#;
    s3.put_bucket_policy().bucket("guarded").policy(deny).send().await.unwrap();
    let err = bob.get_object().bucket("guarded").key("doc").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    let err = s3.put_bucket_policy().bucket("guarded").policy("{").send().await.unwrap_err();
    assert_eq!(err.code(), Some("MalformedPolicy"));
}

#[tokio::test]
async fn anonymous_access_needs_a_public_policy() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("site").send().await.unwrap();
    s3.put_object()
        .bucket("site")
        .key("index.html")
        .body(ByteStream::from_static(b"<h1>hi</h1>"))
        .send()
        .await
        .unwrap();
    let (status, _, body) = mws.raw("GET", "/site/index.html", &[], b"").await;
    assert_eq!(status, 403);
    assert!(String::from_utf8_lossy(&body).contains("<Code>AccessDenied</Code>"));

    let public = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
        "Action":"s3:GetObject","Resource":"arn:aws:s3:::site/*"}]}"#;
    // Block Public Access is on by default.
    let err = s3.put_bucket_policy().bucket("site").policy(public).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    s3.delete_public_access_block().bucket("site").send().await.unwrap();
    s3.put_bucket_policy().bucket("site").policy(public).send().await.unwrap();
    let (status, _, body) = mws.raw("GET", "/site/index.html", &[], b"").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"<h1>hi</h1>");
    let status = s3.get_bucket_policy_status().bucket("site").send().await.unwrap();
    assert_eq!(status.policy_status().and_then(|p| p.is_public()), Some(true));
}

#[tokio::test]
async fn presigned_urls() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("pre").send().await.unwrap();
    let presign = PresigningConfig::expires_in(Duration::from_secs(300)).unwrap();
    let put = s3.put_object().bucket("pre").key("up.txt").presigned(presign.clone()).await.unwrap();
    let headers: Vec<(&str, &str)> = put.headers().collect();
    let (status, _, _) = mws.raw("PUT", put.uri(), &headers, b"via presign").await;
    assert_eq!(status, 200);
    let get = s3.get_object().bucket("pre").key("up.txt").presigned(presign).await.unwrap();
    let (status, _, body) = mws.raw("GET", get.uri(), &[], b"").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"via presign");

    // A tampered signature is refused.
    let bad = get.uri().replace("X-Amz-Signature=", "X-Amz-Signature=0");
    let (status, _, body) = mws.raw("GET", &bad, &[], b"").await;
    assert_eq!(status, 403);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));
}

#[tokio::test]
async fn sse_kms_uses_kms_with_the_callers_permissions() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    let kms = aws_sdk_kms::Client::new(&mws.root_sdk_config().await);
    let key = kms.create_key().send().await.unwrap();
    let key_arn = key.key_metadata().unwrap().arn().unwrap().to_string();
    let key_id = key.key_metadata().unwrap().key_id().to_string();
    s3.create_bucket().bucket("enc").send().await.unwrap();

    let put = s3
        .put_object()
        .bucket("enc")
        .key("a")
        .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms)
        .ssekms_key_id(&key_id)
        .body(ByteStream::from_static(b"sealed"))
        .send()
        .await
        .unwrap();
    assert_eq!(put.ssekms_key_id(), Some(key_arn.as_str()));
    let got = s3.get_object().bucket("enc").key("a").send().await.unwrap();
    assert_eq!(got.server_side_encryption(), Some(&aws_sdk_s3::types::ServerSideEncryption::AwsKms));
    assert_eq!(body(got).await, b"sealed");

    // Without a key id S3 uses (and creates) the AWS managed key aws/s3.
    let put = s3
        .put_object()
        .bucket("enc")
        .key("b")
        .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms)
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap();
    let aliases = kms.list_aliases().send().await.unwrap();
    let managed = aliases.aliases().iter().find(|a| a.alias_name() == Some("alias/aws/s3")).unwrap();
    assert!(put.ssekms_key_id().unwrap().ends_with(managed.target_key_id().unwrap()));

    // A user allowed S3 but not KMS can neither write nor read SSE-KMS objects.
    let (_, cfg) = user_with_policy(
        &mws,
        "s3only",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#),
    )
    .await;
    let user = Mws::s3(&cfg);
    let err = user
        .put_object()
        .bucket("enc")
        .key("c")
        .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms)
        .ssekms_key_id(&key_arn)
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(err.message().unwrap().contains("kms:GenerateDataKey"), "{:?}", err.message());
    let err = user.get_object().bucket("enc").key("a").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(err.message().unwrap().contains("kms:Decrypt"));
    // The AWS managed key lets any principal in the account use it through S3.
    let got = user.get_object().bucket("enc").key("b").send().await.unwrap();
    assert_eq!(body(got).await, b"x");

    kms.disable_key().key_id(&key_id).send().await.unwrap();
    let err = s3.get_object().bucket("enc").key("a").send().await.unwrap_err();
    assert_eq!(err.code(), Some("KMS.DisabledException"));
}

#[tokio::test]
async fn cross_account_access_needs_both_bucket_and_identity_policies() {
    let mws = Mws::start().await;
    let orgs = aws_sdk_organizations::Client::new(&mws.root_sdk_config().await);
    orgs.create_organization().send().await.unwrap();
    let created = orgs.create_account().email("data@example.com").account_name("data").send().await.unwrap();
    let request_id = created.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let member = status.create_account_status().unwrap().account_id().unwrap().to_string();

    let admin_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    let (_, admin_cfg) = user_with_policy(&mws, "admin", Some(admin_policy)).await;
    let (_, bob_cfg) = user_with_policy(&mws, "bob", None).await;
    let creds = aws_sdk_sts::Client::new(&admin_cfg)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{member}:role/OrganizationAccountAccessRole"))
        .role_session_name("s3")
        .send()
        .await
        .unwrap();
    let member_s3 = Mws::s3(&mws_e2e::sts_config(&mws, creds.credentials().unwrap()).await);
    let admin = Mws::s3(&admin_cfg);
    let bob = Mws::s3(&bob_cfg);

    member_s3.create_bucket().bucket("member-data").send().await.unwrap();
    member_s3.put_object().bucket("member-data").key("k").body(ByteStream::from_static(b"m")).send().await.unwrap();
    // Each account lists only its own buckets; names are global.
    let mine = member_s3.list_buckets().send().await.unwrap();
    assert_eq!(mine.buckets().len(), 1);
    assert!(root(&mws).await.list_buckets().send().await.unwrap().buckets().is_empty());
    let err = admin.create_bucket().bucket("member-data").send().await.unwrap_err();
    assert_eq!(err.code(), Some("BucketAlreadyExists"));
    let err = admin.head_bucket().bucket("member-data").expected_bucket_owner("123456789012").send().await.unwrap_err();
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 403);

    // The management account's admin may do anything at home, but not in
    // another account's bucket until its policy allows it.
    let err = admin.get_object().bucket("member-data").key("k").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"AWS":["arn:aws:iam::123456789012:root","arn:aws:iam::123456789012:user/bob"]},
        "Action":"s3:GetObject","Resource":"arn:aws:s3:::member-data/*"}]}"#;
    member_s3.put_bucket_policy().bucket("member-data").policy(policy).send().await.unwrap();
    let got = admin.get_object().bucket("member-data").key("k").send().await.unwrap();
    assert_eq!(body(got).await, b"m");
    // Bob is named by the bucket policy, but his own account grants him
    // nothing: cross-account access needs both.
    let err = bob.get_object().bucket("member-data").key("k").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
}
