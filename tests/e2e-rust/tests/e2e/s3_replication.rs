//! S3 replication as AWS does it: asynchronous, as the configuration's
//! role, with SSE-KMS objects re-encrypted under the replica key, and
//! PutBucketReplication checking the caller before the configuration.

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    BucketVersioningStatus, DeleteMarkerReplication, DeleteMarkerReplicationStatus, Destination,
    EncryptionConfiguration, Event, NotificationConfiguration, QueueConfiguration, ReplicationConfiguration,
    ReplicationRule, ReplicationRuleFilter, ReplicationRuleStatus, ReplicationStatus, ServerSideEncryption,
    SourceSelectionCriteria, SseKmsEncryptedObjects, SseKmsEncryptedObjectsStatus, VersioningConfiguration,
};
use mws_e2e::{user_with_policy, Mws};

use crate::s3::replication_settled;
use crate::s3_events::{collect, open_queue};

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

async fn versioned_buckets(s3: &aws_sdk_s3::Client, names: &[&str]) {
    for b in names {
        s3.create_bucket().bucket(*b).send().await.unwrap();
        s3.put_bucket_versioning()
            .bucket(*b)
            .versioning_configuration(
                VersioningConfiguration::builder().status(BucketVersioningStatus::Enabled).build(),
            )
            .send()
            .await
            .unwrap();
    }
}

async fn role(iam: &aws_sdk_iam::Client, name: &str, permissions: &str) -> String {
    let role = iam.create_role().role_name(name).assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy().role_name(name).policy_name("p").policy_document(permissions).send().await.unwrap();
    role.role().unwrap().arn().to_string()
}

fn config(role: &str, rule: ReplicationRule) -> ReplicationConfiguration {
    ReplicationConfiguration::builder().role(role).rules(rule).build().unwrap()
}

fn rule(dest: &str) -> aws_sdk_s3::types::builders::ReplicationRuleBuilder {
    ReplicationRule::builder()
        .id("all")
        .priority(1)
        .status(ReplicationRuleStatus::Enabled)
        .filter(ReplicationRuleFilter::builder().prefix("").build())
        .delete_marker_replication(
            DeleteMarkerReplication::builder().status(DeleteMarkerReplicationStatus::Disabled).build(),
        )
        .destination(Destination::builder().bucket(format!("arn:aws:s3:::{dest}")).build().unwrap())
}

#[tokio::test]
async fn replication_is_asynchronous_and_reports_failures() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let role_arn = role(
        &iam,
        "replicator",
        r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"s3:GetObjectVersionForReplication","Resource":"arn:aws:s3:::async-src/*"},
        {"Effect":"Allow","Action":"s3:ReplicateObject","Resource":"arn:aws:s3:::async-dst/*"}]}"#,
    )
    .await;
    versioned_buckets(&s3, &["async-src", "async-dst"]).await;
    s3.put_bucket_replication()
        .bucket("async-src")
        .replication_configuration(config(&role_arn, rule("async-dst").build().unwrap()))
        .send()
        .await
        .unwrap();
    let (url, arn) = open_queue(&sqs, "replication").await;
    s3.put_bucket_notification_configuration()
        .bucket("async-src")
        .notification_configuration(
            NotificationConfiguration::builder()
                .queue_configurations(
                    QueueConfiguration::builder()
                        .queue_arn(&arn)
                        .events(Event::from("s3:Replication:*"))
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    // Right after the write the source is PENDING and the replica does not
    // exist yet.
    let put = s3.put_object().bucket("async-src").key("a").body(ByteStream::from_static(b"one")).send().await.unwrap();
    let head = s3.head_object().bucket("async-src").key("a").send().await.unwrap();
    assert_eq!(head.replication_status(), Some(&ReplicationStatus::Pending));
    let err = s3.head_object().bucket("async-dst").key("a").send().await.unwrap_err();
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 404);
    assert_eq!(replication_settled(&s3, "async-src", "a").await, ReplicationStatus::Completed);
    let replica = s3.get_object().bucket("async-dst").key("a").send().await.unwrap();
    assert_eq!(replica.replication_status(), Some(&ReplicationStatus::Replica));
    assert_eq!(replica.version_id(), put.version_id());

    // A replication the role may not make fails, and S3 says so on its own.
    iam.delete_role_policy().role_name("replicator").policy_name("p").send().await.unwrap();
    s3.put_object().bucket("async-src").key("b").body(ByteStream::from_static(b"two")).send().await.unwrap();
    let got = collect(&sqs, &url, 1, |m| m.get("Records").is_some()).await;
    let record = &got.first().expect("a replication event")["Records"][0];
    assert_eq!(record["eventName"], "Replication:OperationFailedReplication");
    assert_eq!(record["eventVersion"], "2.2");
    assert_eq!(record["s3"]["object"]["key"], "b");
    let data = &record["replicationEventData"];
    assert_eq!(data["replicationRuleId"], "all");
    assert_eq!(data["destinationBucket"], "arn:aws:s3:::async-dst");
    assert_eq!(data["s3Operation"], "OBJECT_PUT");
    assert_eq!(data["failureReason"], "SrcGetObjectNotPermitted");
    let head = s3.head_object().bucket("async-src").key("b").send().await.unwrap();
    assert_eq!(head.replication_status(), Some(&ReplicationStatus::Failed));
    let err = s3.head_object().bucket("async-dst").key("b").send().await.unwrap_err();
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 404);

    // Versioning stays on while replication is configured.
    let err = s3
        .put_bucket_versioning()
        .bucket("async-src")
        .versioning_configuration(VersioningConfiguration::builder().status(BucketVersioningStatus::Suspended).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidBucketState"));
    assert_eq!(
        err.message(),
        Some("A replication configuration is present on this bucket, so the versioning state cannot be changed.")
    );
}

#[tokio::test]
async fn put_bucket_replication_authorizes_and_needs_pass_role() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role_arn = role(
        &iam,
        "replicator",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
    )
    .await;
    versioned_buckets(&s3, &["guarded-src", "guarded-dst"]).await;

    // Without s3:PutReplicationConfiguration nothing about the destination
    // is revealed.
    let (_, nobody) = user_with_policy(&mws, "nobody", None).await;
    let err = Mws::s3(&nobody)
        .put_bucket_replication()
        .bucket("guarded-src")
        .replication_configuration(config(&role_arn, rule("no-such-bucket").build().unwrap()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // With it, the caller still needs iam:PassRole on the role.
    let put_only = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"s3:PutReplicationConfiguration","Resource":"arn:aws:s3:::guarded-src"}]}"#;
    let (_, alice) = user_with_policy(&mws, "alice", Some(put_only)).await;
    let alice = Mws::s3(&alice);
    let err = alice
        .put_bucket_replication()
        .bucket("guarded-src")
        .replication_configuration(config(&role_arn, rule("guarded-dst").build().unwrap()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(err.message().unwrap().contains("iam:PassRole"), "{:?}", err.message());

    let with_pass = format!(
        r#"{{"Version":"2012-10-17","Statement":[
        {{"Effect":"Allow","Action":"s3:PutReplicationConfiguration","Resource":"arn:aws:s3:::guarded-src"}},
        {{"Effect":"Allow","Action":"iam:PassRole","Resource":"{role_arn}",
          "Condition":{{"StringEquals":{{"iam:PassedToService":"s3.amazonaws.com"}}}}}}]}}"#
    );
    iam.put_user_policy().user_name("alice").policy_name("inline").policy_document(with_pass).send().await.unwrap();
    let err = alice
        .put_bucket_replication()
        .bucket("guarded-src")
        .replication_configuration(config(&role_arn, rule("no-such-bucket").build().unwrap()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidRequest"));
    assert_eq!(err.message(), Some("Destination bucket must exist."));
    alice
        .put_bucket_replication()
        .bucket("guarded-src")
        .replication_configuration(config(&role_arn, rule("guarded-dst").build().unwrap()))
        .send()
        .await
        .unwrap();

    // SSE-KMS objects need a replica key.
    let kms_rule = rule("guarded-dst")
        .source_selection_criteria(
            SourceSelectionCriteria::builder()
                .sse_kms_encrypted_objects(
                    SseKmsEncryptedObjects::builder().status(SseKmsEncryptedObjectsStatus::Enabled).build().unwrap(),
                )
                .build(),
        )
        .build()
        .unwrap();
    let err = s3
        .put_bucket_replication()
        .bucket("guarded-src")
        .replication_configuration(config(&role_arn, kms_rule))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidRequest"));
    assert_eq!(err.message(), Some("ReplicaKmsKeyID must be specified if SseKmsEncryptedObjects tag is present."));
}

#[tokio::test]
async fn sse_kms_objects_are_reencrypted_under_the_replica_key() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let source_key = kms.create_key().send().await.unwrap().key_metadata.unwrap().arn.unwrap();
    let replica_key = kms.create_key().send().await.unwrap().key_metadata.unwrap().arn.unwrap();
    versioned_buckets(&s3, &["kms-src", "kms-dst"]).await;
    let s3_part = r#"{"Effect":"Allow","Action":["s3:GetObjectVersionForReplication","s3:ReplicateObject"],"Resource":["arn:aws:s3:::kms-src/*","arn:aws:s3:::kms-dst/*"]}"#;
    let decrypt_only = format!(
        r#"{{"Version":"2012-10-17","Statement":[{s3_part},
        {{"Effect":"Allow","Action":"kms:Decrypt","Resource":"{source_key}"}}]}}"#
    );
    let role_arn = role(&iam, "kms-replicator", &decrypt_only).await;
    let kms_rule = rule("kms-dst")
        .source_selection_criteria(
            SourceSelectionCriteria::builder()
                .sse_kms_encrypted_objects(
                    SseKmsEncryptedObjects::builder().status(SseKmsEncryptedObjectsStatus::Enabled).build().unwrap(),
                )
                .build(),
        )
        .destination(
            Destination::builder()
                .bucket("arn:aws:s3:::kms-dst")
                .encryption_configuration(EncryptionConfiguration::builder().replica_kms_key_id(&replica_key).build())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    s3.put_bucket_replication()
        .bucket("kms-src")
        .replication_configuration(config(&role_arn, kms_rule))
        .send()
        .await
        .unwrap();
    let put = |key: &'static str| {
        s3.put_object()
            .bucket("kms-src")
            .key(key)
            .server_side_encryption(ServerSideEncryption::AwsKms)
            .ssekms_key_id(&source_key)
            .body(ByteStream::from_static(b"secret"))
            .send()
    };

    // Without kms:Encrypt on the replica key the replication fails.
    put("first").await.unwrap();
    assert_eq!(replication_settled(&s3, "kms-src", "first").await, ReplicationStatus::Failed);

    let both = format!(
        r#"{{"Version":"2012-10-17","Statement":[{s3_part},
        {{"Effect":"Allow","Action":"kms:Decrypt","Resource":"{source_key}"}},
        {{"Effect":"Allow","Action":"kms:Encrypt","Resource":"{replica_key}"}}]}}"#
    );
    iam.put_role_policy().role_name("kms-replicator").policy_name("p").policy_document(both).send().await.unwrap();
    put("second").await.unwrap();
    assert_eq!(replication_settled(&s3, "kms-src", "second").await, ReplicationStatus::Completed);
    let replica = s3.get_object().bucket("kms-dst").key("second").send().await.unwrap();
    assert_eq!(replica.ssekms_key_id(), Some(replica_key.as_str()));
    assert_eq!(replica.body.collect().await.unwrap().into_bytes().as_ref(), b"secret");
    let source = s3.head_object().bucket("kms-src").key("second").send().await.unwrap();
    assert_eq!(source.ssekms_key_id(), Some(source_key.as_str()));
}

#[tokio::test]
async fn replication_assumes_the_role_and_validates_v2_rules() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    versioned_buckets(&s3, &["trust-src", "trust-dst"]).await;
    // A role that does not trust S3: S3 cannot assume it, so replication
    // fails although the role's permissions would allow it.
    let lambda_trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let arn = iam
        .create_role()
        .role_name("not-for-s3")
        .assume_role_policy_document(lambda_trust)
        .send()
        .await
        .unwrap()
        .role()
        .unwrap()
        .arn()
        .to_string();
    iam.put_role_policy()
        .role_name("not-for-s3")
        .policy_name("p")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    s3.put_bucket_replication()
        .bucket("trust-src")
        .replication_configuration(config(&arn, rule("trust-dst").build().unwrap()))
        .send()
        .await
        .unwrap();
    s3.put_object().bucket("trust-src").key("k").body(ByteStream::from_static(b"x")).send().await.unwrap();
    assert_eq!(replication_settled(&s3, "trust-src", "k").await, ReplicationStatus::Failed);

    // V2 rules (with a Filter) must name a priority and the delete marker
    // setting.
    let no_priority = ReplicationRule::builder()
        .id("r")
        .status(ReplicationRuleStatus::Enabled)
        .filter(ReplicationRuleFilter::builder().prefix("").build())
        .delete_marker_replication(
            DeleteMarkerReplication::builder().status(DeleteMarkerReplicationStatus::Disabled).build(),
        )
        .destination(Destination::builder().bucket("arn:aws:s3:::trust-dst").build().unwrap())
        .build()
        .unwrap();
    let err = s3
        .put_bucket_replication()
        .bucket("trust-src")
        .replication_configuration(config(&arn, no_priority))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidRequest"));
    assert!(err.message().unwrap().starts_with("Priority must be specified"));
    let no_marker = ReplicationRule::builder()
        .id("r")
        .priority(1)
        .status(ReplicationRuleStatus::Enabled)
        .filter(ReplicationRuleFilter::builder().prefix("").build())
        .destination(Destination::builder().bucket("arn:aws:s3:::trust-dst").build().unwrap())
        .build()
        .unwrap();
    let err = s3
        .put_bucket_replication()
        .bucket("trust-src")
        .replication_configuration(config(&arn, no_marker))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidRequest"));
    assert!(err.message().unwrap().starts_with("DeleteMarkerReplication must be specified"));
}
