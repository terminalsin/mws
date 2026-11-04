//! S3 server access logging through the official Rust SDK: records are
//! written into the target bucket by `logging.s3.amazonaws.com`, which the
//! target bucket's policy must allow.

use aws_sdk_s3::types::{BucketLoggingStatus, LoggingEnabled};
use mws_e2e::Mws;

async fn log_lines(s3: &aws_sdk_s3::Client, bucket: &str, prefix: &str) -> Vec<String> {
    let listed = s3.list_objects_v2().bucket(bucket).prefix(prefix).send().await.unwrap();
    let mut lines = Vec::new();
    for o in listed.contents() {
        let body = s3.get_object().bucket(bucket).key(o.key().unwrap()).send().await.unwrap().body.collect().await;
        lines.extend(String::from_utf8(body.unwrap().to_vec()).unwrap().lines().map(str::to_string));
    }
    lines
}

#[tokio::test]
async fn access_logs_reach_the_target_bucket() {
    let mws = Mws::start().await;
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    s3.create_bucket().bucket("data").send().await.unwrap();
    s3.create_bucket().bucket("logs").send().await.unwrap();
    let logging = BucketLoggingStatus::builder()
        .logging_enabled(LoggingEnabled::builder().target_bucket("logs").target_prefix("access/").build().unwrap())
        .build();
    s3.put_bucket_logging().bucket("data").bucket_logging_status(logging).send().await.unwrap();

    // No bucket policy for the logging service yet: records are dropped.
    s3.put_object().bucket("data").key("early.txt").body(b"x".to_vec().into()).send().await.unwrap();
    assert!(log_lines(&s3, "logs", "access/").await.is_empty());

    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::logs/access/*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::data"},"StringEquals":{"aws:SourceAccount":"123456789012"}}}]}"#;
    s3.put_bucket_policy().bucket("logs").policy(policy).send().await.unwrap();

    s3.put_object().bucket("data").key("report.csv").body(b"a,b\n1,2\n".to_vec().into()).send().await.unwrap();
    s3.get_object().bucket("data").key("report.csv").send().await.unwrap();
    s3.get_object().bucket("data").key("missing").send().await.unwrap_err();

    let lines = log_lines(&s3, "logs", "access/").await;
    assert_eq!(lines.len(), 3, "{lines:#?}");
    let put = lines.iter().find(|l| l.contains(" REST.PUT.OBJECT ")).expect("PUT record");
    let fields: Vec<&str> = put.split(' ').collect();
    assert_eq!(fields[1], "data");
    assert!(fields[2].starts_with('['));
    assert!(put.contains(" arn:aws:iam::123456789012:root "), "{put}");
    assert!(put.contains(" report.csv \"PUT /data/report.csv"), "{put}");
    assert!(put.contains(" 200 - "), "{put}");
    assert!(put.contains(" SigV4 - AuthHeader "), "{put}");
    let get = lines.iter().find(|l| l.contains(" REST.GET.OBJECT report.csv ")).expect("GET record");
    assert!(get.contains(" 200 - 8 8 "), "{get}");
    let missing = lines.iter().find(|l| l.contains(" REST.GET.OBJECT missing ")).expect("404 record");
    assert!(missing.contains(" 404 NoSuchKey "), "{missing}");

    // The target bucket must belong to the same account, and exist.
    let e = s3
        .put_bucket_logging()
        .bucket("data")
        .bucket_logging_status(
            BucketLoggingStatus::builder()
                .logging_enabled(LoggingEnabled::builder().target_bucket("nope").target_prefix("x/").build().unwrap())
                .build(),
        )
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(aws_sdk_s3::error::ProvideErrorMetadata::code(&e), Some("InvalidTargetBucketForLogging"));
    mws.stop().await;
}
