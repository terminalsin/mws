//! S3 authorization details: SSE-KMS multipart uploads needing
//! kms:Decrypt, the encryption context S3 always sends, the bucket owner's
//! hold on its bucket policy, and VPC-only access points.

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, ServerSideEncryption};
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

#[tokio::test]
async fn sse_kms_multipart_uploads_need_kms_decrypt() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let key = kms.create_key().send().await.unwrap().key_metadata.unwrap().arn.unwrap();
    s3.create_bucket().bucket("mpu-kms").send().await.unwrap();
    let policy = |actions: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[
            {{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::mpu-kms/*"}},
            {{"Effect":"Allow","Action":{actions},"Resource":"{key}"}}]}}"#
        )
    };
    let (_, user) = user_with_policy(&mws, "uploader", Some(&policy(r#"["kms:GenerateDataKey"]"#))).await;
    let user = Mws::s3(&user);
    let upload = user
        .create_multipart_upload()
        .bucket("mpu-kms")
        .key("big")
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .ssekms_key_id(&key)
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let part = || user.upload_part().bucket("mpu-kms").key("big").upload_id(id).part_number(1);
    let err = part().body(ByteStream::from_static(b"part one")).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(err.message().unwrap().contains("kms:Decrypt"), "{:?}", err.message());

    let both = policy(r#"["kms:GenerateDataKey","kms:Decrypt"]"#);
    iam.put_user_policy().user_name("uploader").policy_name("inline").policy_document(both).send().await.unwrap();
    let etag = part().body(ByteStream::from_static(b"part one")).send().await.unwrap().e_tag.unwrap();
    let complete = || {
        user.complete_multipart_upload()
            .bucket("mpu-kms")
            .key("big")
            .upload_id(id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .parts(CompletedPart::builder().part_number(1).e_tag(&etag).build())
                    .build(),
            )
            .send()
    };
    // Completing needs kms:Decrypt too.
    iam.put_user_policy()
        .user_name("uploader")
        .policy_name("inline")
        .policy_document(policy(r#"["kms:GenerateDataKey"]"#))
        .send()
        .await
        .unwrap();
    let err = complete().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    iam.put_user_policy()
        .user_name("uploader")
        .policy_name("inline")
        .policy_document(policy(r#"["kms:GenerateDataKey","kms:Decrypt"]"#))
        .send()
        .await
        .unwrap();
    let done = complete().await.unwrap();
    assert_eq!(done.ssekms_key_id(), Some(key.as_str()));
}

#[tokio::test]
async fn caller_encryption_context_is_added_to_the_object_arn() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    // The key only serves this bucket's objects, by the context S3 sends.
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": format!("arn:aws:iam::{ACCOUNT}:root")}, "Action": "kms:*", "Resource": "*"},
            {"Effect": "Deny", "Principal": "*", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "*",
             "Condition": {"StringNotLike": {"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::ctx-bucket/*"}}}
        ]
    });
    let key = kms.create_key().policy(policy.to_string()).send().await.unwrap().key_metadata.unwrap().arn.unwrap();
    s3.create_bucket().bucket("ctx-bucket").send().await.unwrap();
    let context = base64::engine::general_purpose::STANDARD.encode(r#"{"team":"red"}"#);
    s3.put_object()
        .bucket("ctx-bucket")
        .key("doc")
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .ssekms_key_id(&key)
        .ssekms_encryption_context(&context)
        .body(ByteStream::from_static(b"classified"))
        .send()
        .await
        .unwrap();
    let got = s3.get_object().bucket("ctx-bucket").key("doc").send().await.unwrap();
    assert_eq!(got.body.collect().await.unwrap().into_bytes().as_ref(), b"classified");
}

#[tokio::test]
async fn the_bucket_owner_root_user_can_always_manage_the_bucket_policy() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("locked-out").send().await.unwrap();
    let deny_all = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
        "Resource":["arn:aws:s3:::locked-out","arn:aws:s3:::locked-out/*"]}]}"#;
    s3.put_bucket_policy().bucket("locked-out").policy(deny_all).send().await.unwrap();

    // The policy denies everyone everything, root included...
    let err = s3.list_objects_v2().bucket("locked-out").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let (_, admin) = user_with_policy(
        &mws,
        "admin",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#),
    )
    .await;
    let err = Mws::s3(&admin).get_bucket_policy().bucket("locked-out").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // ...except the owner's root user managing the policy itself.
    let got = s3.get_bucket_policy().bucket("locked-out").send().await.unwrap();
    assert!(got.policy().unwrap().contains("Deny"));
    s3.put_bucket_policy().bucket("locked-out").policy(deny_all).send().await.unwrap();
    s3.delete_bucket_policy().bucket("locked-out").send().await.unwrap();
    s3.list_objects_v2().bucket("locked-out").send().await.unwrap();
}

#[tokio::test]
async fn vpc_only_access_points_refuse_requests_from_outside_the_vpc() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let control = aws_sdk_s3control::Client::new(&cfg);
    s3.create_bucket().bucket("vpc-data").send().await.unwrap();
    s3.put_object().bucket("vpc-data").key("k").body(ByteStream::from_static(b"v")).send().await.unwrap();
    let open = control.create_access_point().account_id(ACCOUNT).name("open").bucket("vpc-data").send().await.unwrap();
    let inside = control
        .create_access_point()
        .account_id(ACCOUNT)
        .name("inside")
        .bucket("vpc-data")
        .vpc_configuration(aws_sdk_s3control::types::VpcConfiguration::builder().vpc_id("vpc-0abc").build().unwrap())
        .send()
        .await
        .unwrap();
    // Access point ARNs are addressed host-style.
    let host_style = aws_sdk_s3::Client::new(&cfg);
    let got = host_style.get_object().bucket(open.access_point_arn().unwrap()).key("k").send().await.unwrap();
    assert_eq!(got.body.collect().await.unwrap().into_bytes().as_ref(), b"v");
    let err = host_style.get_object().bucket(inside.access_point_arn().unwrap()).key("k").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let err = s3.list_objects_v2().bucket(inside.alias().unwrap()).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
}

#[tokio::test]
async fn mfa_delete_and_lifecycle_minimums_are_enforced() {
    use aws_sdk_s3::types::{
        BucketLifecycleConfiguration, BucketVersioningStatus, ExpirationStatus, LifecycleRule, LifecycleRuleFilter,
        MfaDelete, Transition, TransitionStorageClass, VersioningConfiguration,
    };
    let mws = Mws::start().await;
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    s3.create_bucket().bucket("mfa-guarded").send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("mfa-guarded")
        .mfa("arn:aws:iam::123456789012:mfa/root 123456")
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .mfa_delete(MfaDelete::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let put = s3.put_object().bucket("mfa-guarded").key("k").body(ByteStream::from_static(b"x")).send().await.unwrap();
    let version = put.version_id().unwrap();
    // Without the MFA header a permanent delete is refused.
    let err = s3.delete_object().bucket("mfa-guarded").key("k").version_id(version).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert_eq!(err.message(), Some("Mfa Authentication must be used for this request"));
    // A delete marker needs no MFA.
    s3.delete_object().bucket("mfa-guarded").key("k").send().await.unwrap();

    // Infrequent Access transitions need at least 30 days.
    let rule = LifecycleRule::builder()
        .id("ia")
        .status(ExpirationStatus::Enabled)
        .filter(LifecycleRuleFilter::builder().prefix("").build())
        .transitions(Transition::builder().days(7).storage_class(TransitionStorageClass::StandardIa).build())
        .build()
        .unwrap();
    let err = s3
        .put_bucket_lifecycle_configuration()
        .bucket("mfa-guarded")
        .lifecycle_configuration(BucketLifecycleConfiguration::builder().rules(rule).build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidArgument"));
    assert_eq!(
        err.message(),
        Some("'Days' in Transition action must be greater than or equal to 30 for storageClass 'STANDARD_IA'")
    );
}
