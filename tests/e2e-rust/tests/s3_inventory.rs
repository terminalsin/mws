//! S3 Inventory through the official Rust SDK: reports land in the
//! destination bucket at midnight on the emulated clock, written by
//! `s3.amazonaws.com` (which the destination bucket policy must allow), in
//! AWS's layout: data files, `manifest.json`, `manifest.checksum` and a Hive
//! `symlink.txt`.

use std::io::Read;

use aws_sdk_s3::types::{
    InventoryConfiguration, InventoryDestination, InventoryEncryption, InventoryFilter, InventoryFormat,
    InventoryFrequency, InventoryIncludedObjectVersions, InventoryOptionalField, InventoryS3BucketDestination,
    InventorySchedule, Ssekms,
};
use mws_e2e::Mws;
use serde_json::json;

async fn advance_days(mws: &Mws, days: i64) {
    let body = json!({"advanceSeconds": days * 86400}).to_string();
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

async fn keys(s3: &aws_sdk_s3::Client, bucket: &str, prefix: &str) -> Vec<String> {
    let listed = s3.list_objects_v2().bucket(bucket).prefix(prefix).send().await.unwrap();
    listed.contents().iter().map(|o| o.key().unwrap().to_string()).collect()
}

async fn get(s3: &aws_sdk_s3::Client, bucket: &str, key: &str) -> Vec<u8> {
    s3.get_object().bucket(bucket).key(key).send().await.unwrap().body.collect().await.unwrap().to_vec()
}

fn destination_policy(bucket: &str) -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "InventoryPolicy",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": format!("arn:aws:s3:::{bucket}/*"),
            "Condition": {
                "ArnLike": {"aws:SourceArn": "arn:aws:s3:::source"},
                "StringEquals": {"aws:SourceAccount": "123456789012", "s3:x-amz-acl": "bucket-owner-full-control"}
            }
        }]
    })
    .to_string()
}

fn config(
    id: &str,
    format: InventoryFormat,
    versions: InventoryIncludedObjectVersions,
    encryption: Option<InventoryEncryption>,
) -> InventoryConfiguration {
    InventoryConfiguration::builder()
        .id(id)
        .is_enabled(true)
        .included_object_versions(versions)
        .filter(InventoryFilter::builder().prefix("docs/").build().unwrap())
        .optional_fields(InventoryOptionalField::Size)
        .optional_fields(InventoryOptionalField::ETag)
        .optional_fields(InventoryOptionalField::LastModifiedDate)
        .optional_fields(InventoryOptionalField::StorageClass)
        .optional_fields(InventoryOptionalField::EncryptionStatus)
        .schedule(InventorySchedule::builder().frequency(InventoryFrequency::Daily).build().unwrap())
        .destination(
            InventoryDestination::builder()
                .s3_bucket_destination(
                    InventoryS3BucketDestination::builder()
                        .bucket("arn:aws:s3:::reports")
                        .account_id("123456789012")
                        .format(format)
                        .prefix("inv")
                        .set_encryption(encryption)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn csv_inventory_is_delivered_on_schedule() {
    let mws = Mws::start().await;
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    s3.create_bucket().bucket("source").send().await.unwrap();
    s3.create_bucket().bucket("reports").send().await.unwrap();
    for (key, body) in [("docs/a.txt", "hello"), ("docs/b c.txt", "hi"), ("other/x", "nope")] {
        s3.put_object().bucket("source").key(key).body(body.as_bytes().to_vec().into()).send().await.unwrap();
    }
    s3.put_bucket_inventory_configuration()
        .bucket("source")
        .id("daily")
        .inventory_configuration(config("daily", InventoryFormat::Csv, InventoryIncludedObjectVersions::Current, None))
        .send()
        .await
        .unwrap();

    // Nothing before the first midnight.
    assert!(keys(&s3, "reports", "").await.is_empty());

    // Without a bucket policy for s3.amazonaws.com the report is lost.
    advance_days(&mws, 1).await;
    assert!(keys(&s3, "reports", "").await.is_empty());

    s3.put_bucket_policy().bucket("reports").policy(destination_policy("reports")).send().await.unwrap();
    advance_days(&mws, 1).await;
    let all = keys(&s3, "reports", "inv/source/daily/").await;
    assert_eq!(all.len(), 4, "{all:#?}");
    let manifest_key = all.iter().find(|k| k.ends_with("/manifest.json")).expect("manifest.json");
    let checksum_key = all.iter().find(|k| k.ends_with("/manifest.checksum")).expect("manifest.checksum");
    let symlink_key = all.iter().find(|k| k.ends_with("/symlink.txt")).expect("symlink.txt");
    assert!(symlink_key.starts_with("inv/source/daily/hive/dt="), "{symlink_key}");
    assert!(manifest_key.ends_with("T00-00Z/manifest.json"), "{manifest_key}");

    let manifest_bytes = get(&s3, "reports", manifest_key).await;
    let checksum = String::from_utf8(get(&s3, "reports", checksum_key).await).unwrap();
    assert_eq!(checksum, md5_hex(&manifest_bytes));
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["sourceBucket"], "source");
    assert_eq!(manifest["destinationBucket"], "arn:aws:s3:::reports");
    assert_eq!(manifest["version"], "2016-11-30");
    assert_eq!(manifest["fileFormat"], "CSV");
    assert_eq!(manifest["fileSchema"], "Bucket, Key, Size, LastModifiedDate, ETag, StorageClass, EncryptionStatus");
    let file = &manifest["files"][0];
    let data_key = file["key"].as_str().unwrap();
    assert!(data_key.starts_with("inv/source/daily/data/") && data_key.ends_with(".csv.gz"), "{data_key}");

    let gz = get(&s3, "reports", data_key).await;
    assert_eq!(file["size"], gz.len());
    assert_eq!(file["MD5checksum"], md5_hex(&gz));
    let mut csv = String::new();
    flate2::read::GzDecoder::new(&gz[..]).read_to_string(&mut csv).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 2, "{csv}");
    assert!(lines[0].starts_with(r#""source","docs%2Fa.txt","5","20"#), "{csv}");
    assert!(lines[0].ends_with(r#"","5d41402abc4b2a76b9719d911017c592","STANDARD","SSE-S3""#), "{csv}");
    assert!(lines[1].starts_with(r#""source","docs%2Fb+c.txt","2","#), "{csv}");

    let symlink = String::from_utf8(get(&s3, "reports", symlink_key).await).unwrap();
    assert_eq!(symlink.trim(), format!("s3://reports/{data_key}"));

    // Daily: the next report comes a day later, and a disabled
    // configuration delivers nothing.
    advance_days(&mws, 1).await;
    let manifests =
        keys(&s3, "reports", "inv/source/daily/").await.into_iter().filter(|k| k.ends_with("manifest.json"));
    assert_eq!(manifests.count(), 2);
    let mut disabled = config("daily", InventoryFormat::Csv, InventoryIncludedObjectVersions::Current, None);
    disabled.is_enabled = false;
    s3.put_bucket_inventory_configuration()
        .bucket("source")
        .id("daily")
        .inventory_configuration(disabled)
        .send()
        .await
        .unwrap();
    advance_days(&mws, 1).await;
    let manifests =
        keys(&s3, "reports", "inv/source/daily/").await.into_iter().filter(|k| k.ends_with("manifest.json"));
    assert_eq!(manifests.count(), 2);
    mws.stop().await;
}

#[tokio::test]
async fn versioned_parquet_and_sse_kms_inventory() {
    let mws = Mws::start().await;
    let config_root = mws.root_sdk_config().await;
    let s3 = Mws::s3(&config_root);
    let kms = aws_sdk_kms::Client::new(&config_root);
    s3.create_bucket().bucket("source").send().await.unwrap();
    s3.create_bucket().bucket("reports").send().await.unwrap();
    s3.put_bucket_policy().bucket("reports").policy(destination_policy("reports")).send().await.unwrap();
    s3.put_bucket_versioning()
        .bucket("source")
        .versioning_configuration(
            aws_sdk_s3::types::VersioningConfiguration::builder()
                .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    s3.put_object().bucket("source").key("docs/a").body(b"one".to_vec().into()).send().await.unwrap();
    s3.put_object().bucket("source").key("docs/a").body(b"two!".to_vec().into()).send().await.unwrap();
    s3.delete_object().bucket("source").key("docs/a").send().await.unwrap();

    // A key whose policy lets S3 generate data keys for this bucket.
    let key_policy = json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"},
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "kms:GenerateDataKey", "Resource": "*",
             "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}}}
        ]
    });
    let key = kms.create_key().policy(key_policy.to_string()).send().await.unwrap();
    let key_arn = key.key_metadata().unwrap().arn().unwrap().to_string();

    let encryption = InventoryEncryption::builder().ssekms(Ssekms::builder().key_id(&key_arn).build().unwrap()).build();
    let c = config("versions", InventoryFormat::Parquet, InventoryIncludedObjectVersions::All, Some(encryption));
    s3.put_bucket_inventory_configuration()
        .bucket("source")
        .id("versions")
        .inventory_configuration(c)
        .send()
        .await
        .unwrap();
    advance_days(&mws, 1).await;

    let all = keys(&s3, "reports", "inv/source/versions/").await;
    let manifest_key = all.iter().find(|k| k.ends_with("/manifest.json")).expect("manifest.json");
    let manifest: serde_json::Value = serde_json::from_slice(&get(&s3, "reports", manifest_key).await).unwrap();
    assert_eq!(manifest["fileFormat"], "Parquet");
    let schema = manifest["fileSchema"].as_str().unwrap();
    assert!(schema.starts_with("message s3.inventory { required binary bucket (STRING); required binary key (STRING); optional binary version_id (STRING); optional boolean is_latest; optional boolean is_delete_marker; optional int64 size;"), "{schema}");
    let data_key = manifest["files"][0]["key"].as_str().unwrap();
    assert!(data_key.ends_with(".parquet"), "{data_key}");

    let head = s3.head_object().bucket("reports").key(data_key).send().await.unwrap();
    assert_eq!(head.server_side_encryption().map(|s| s.as_str()), Some("aws:kms"));
    assert_eq!(head.ssekms_key_id(), Some(key_arn.as_str()));
    let parquet = get(&s3, "reports", data_key).await;
    assert!(parquet.starts_with(b"PAR1") && parquet.ends_with(b"PAR1"));
    // Two versions and the delete marker, newest first.
    let text = String::from_utf8_lossy(&parquet);
    assert_eq!(text.matches("docs/a").count(), 3, "{text}");
    mws.stop().await;
}

fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    md5::Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}
