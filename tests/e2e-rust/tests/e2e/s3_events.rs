//! S3 events that S3 itself causes: lifecycle expirations and transitions
//! and restores finishing, delivered to notification destinations and to
//! EventBridge, through the official Rust SDK.

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    BucketLifecycleConfiguration, BucketVersioningStatus, Event, EventBridgeConfiguration, ExpirationStatus,
    GlacierJobParameters, LifecycleExpiration, LifecycleRule, LifecycleRuleFilter, NotificationConfiguration,
    QueueConfiguration, RestoreRequest, Tier, Transition, TransitionStorageClass, VersioningConfiguration,
};
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

/// A queue that S3 and EventBridge may send to.
pub(crate) async fn open_queue(sqs: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url.unwrap();
    let arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:{name}");
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": ["s3.amazonaws.com", "events.amazonaws.com"]},
            "Action": "sqs:SendMessage",
            "Resource": arn,
        }]
    });
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    (url, arn)
}

/// Receive (and delete) messages until `n` match `keep`, or give up after
/// about ten seconds. Bodies are parsed as JSON.
pub(crate) async fn collect(
    sqs: &aws_sdk_sqs::Client,
    url: &str,
    n: usize,
    keep: impl Fn(&serde_json::Value) -> bool,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for _ in 0..10 {
        let got =
            sqs.receive_message().queue_url(url).max_number_of_messages(10).wait_time_seconds(1).send().await.unwrap();
        for m in got.messages() {
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
            let body: serde_json::Value = serde_json::from_str(m.body().unwrap()).unwrap();
            if keep(&body) {
                out.push(body);
            }
        }
        if out.len() >= n {
            break;
        }
    }
    out
}

fn records(messages: &[serde_json::Value]) -> Vec<serde_json::Value> {
    messages.iter().filter_map(|m| m["Records"].get(0).cloned()).collect()
}

fn find<'a>(records: &'a [serde_json::Value], name: &str, key: &str) -> &'a serde_json::Value {
    records
        .iter()
        .find(|r| r["eventName"] == name && r["s3"]["object"]["key"] == key)
        .unwrap_or_else(|| panic!("no {name} event for {key} in {records:#?}"))
}

async fn advance_days(mws: &Mws, days: i64) {
    let body = format!(r#"{{"advanceSeconds":{}}}"#, days * 86400);
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn lifecycle_actions_and_finished_restores_send_events() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let (url, arn) = open_queue(&sqs, "lifecycle").await;
    let (eb_url, eb_arn) = open_queue(&sqs, "from-eventbridge").await;
    eb.put_rule().name("s3").event_pattern(r#"{"source":["aws.s3"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("s3")
        .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(&eb_arn).build().unwrap())
        .send()
        .await
        .unwrap();

    let rule = |id: &str, prefix: &str| {
        LifecycleRule::builder()
            .id(id)
            .status(ExpirationStatus::Enabled)
            .filter(LifecycleRuleFilter::builder().prefix(prefix).build())
    };
    let config = BucketLifecycleConfiguration::builder()
        .rules(rule("tmp", "tmp/").expiration(LifecycleExpiration::builder().days(1).build()).build().unwrap())
        .rules(
            rule("cold", "cold/")
                .transitions(Transition::builder().days(1).storage_class(TransitionStorageClass::Glacier).build())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let notifications = NotificationConfiguration::builder()
        .queue_configurations(
            QueueConfiguration::builder()
                .queue_arn(&arn)
                .events(Event::from("s3:LifecycleExpiration:*"))
                .events(Event::from("s3:LifecycleTransition"))
                .events(Event::from("s3:ObjectRestore:*"))
                .build()
                .unwrap(),
        )
        .event_bridge_configuration(EventBridgeConfiguration::builder().build())
        .build();
    for b in ["aging", "aging-versioned"] {
        s3.create_bucket().bucket(b).send().await.unwrap();
        s3.put_bucket_lifecycle_configuration().bucket(b).lifecycle_configuration(config.clone()).send().await.unwrap();
        s3.put_bucket_notification_configuration()
            .bucket(b)
            .notification_configuration(notifications.clone())
            .send()
            .await
            .unwrap();
    }
    s3.put_bucket_versioning()
        .bucket("aging-versioned")
        .versioning_configuration(VersioningConfiguration::builder().status(BucketVersioningStatus::Enabled).build())
        .send()
        .await
        .unwrap();
    s3.put_object().bucket("aging").key("tmp/a").body(ByteStream::from_static(b"gone")).send().await.unwrap();
    s3.put_object().bucket("aging").key("cold/b").body(ByteStream::from_static(b"frozen")).send().await.unwrap();
    s3.put_object().bucket("aging-versioned").key("tmp/v").body(ByteStream::from_static(b"v")).send().await.unwrap();
    // The configurations' test events.
    collect(&sqs, &url, 2, |m| m["Event"] == "s3:TestEvent").await;

    advance_days(&mws, 2).await;
    s3.list_objects_v2().bucket("aging").send().await.unwrap();
    let got = records(&collect(&sqs, &url, 3, |m| m.get("Records").is_some()).await);
    let expired = find(&got, "LifecycleExpiration:Delete", "tmp/a");
    assert_eq!(expired["eventVersion"], "2.3");
    assert_eq!(expired["userIdentity"]["principalId"], "s3.amazonaws.com");
    assert_eq!(expired["requestParameters"]["sourceIPAddress"], "s3.amazonaws.com");
    assert_eq!(expired["s3"]["bucket"]["name"], "aging");
    let moved = find(&got, "LifecycleTransition", "cold/b");
    assert_eq!(moved["lifecycleEventData"]["transitionEventData"]["destinationStorageClass"], "GLACIER");
    assert_eq!(moved["s3"]["object"]["size"], 6);
    let marker = find(&got, "LifecycleExpiration:DeleteMarkerCreated", "tmp/v");
    assert_eq!(marker["s3"]["bucket"]["name"], "aging-versioned");
    assert!(marker["s3"]["object"]["versionId"].is_string());

    let events = collect(&sqs, &eb_url, 3, |e| e["source"] == "aws.s3").await;
    let deleted = events
        .iter()
        .find(|e| e["detail-type"] == "Object Deleted" && e["detail"]["object"]["key"] == "tmp/a")
        .expect("Object Deleted for tmp/a");
    assert_eq!(deleted["detail"]["reason"], "Lifecycle Expiration");
    assert_eq!(deleted["detail"]["deletion-type"], "Permanently Deleted");
    assert_eq!(deleted["detail"]["requester"], "s3.amazonaws.com");
    let created_marker = events
        .iter()
        .find(|e| e["detail-type"] == "Object Deleted" && e["detail"]["object"]["key"] == "tmp/v")
        .expect("Object Deleted for tmp/v");
    assert_eq!(created_marker["detail"]["deletion-type"], "Delete Marker Created");
    let class = events.iter().find(|e| e["detail-type"] == "Object Storage Class Changed").expect("class change");
    assert_eq!(class["detail"]["destination-storage-class"], "GLACIER");

    // A restore runs in the background: in progress first, then the copy
    // is readable and S3 says the restore completed.
    let head = s3.head_object().bucket("aging").key("cold/b").send().await.unwrap();
    assert_eq!(head.storage_class(), Some(&aws_sdk_s3::types::StorageClass::Glacier));
    let request = RestoreRequest::builder()
        .days(1)
        .glacier_job_parameters(GlacierJobParameters::builder().tier(Tier::Standard).build().unwrap())
        .build();
    s3.restore_object().bucket("aging").key("cold/b").restore_request(request.clone()).send().await.unwrap();
    let head = s3.head_object().bucket("aging").key("cold/b").send().await.unwrap();
    assert_eq!(head.restore(), Some("ongoing-request=\"true\""));
    let err = s3.get_object().bucket("aging").key("cold/b").send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidObjectState"));
    let err = s3.restore_object().bucket("aging").key("cold/b").restore_request(request).send().await.unwrap_err();
    assert_eq!(err.code(), Some("RestoreAlreadyInProgress"));
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 409);

    // The Completed event arrives without anyone asking S3 again.
    let got = records(&collect(&sqs, &url, 2, |m| m.get("Records").is_some()).await);
    find(&got, "ObjectRestore:Post", "cold/b");
    let done = find(&got, "ObjectRestore:Completed", "cold/b");
    assert_eq!(done["userIdentity"]["principalId"], "s3.amazonaws.com");
    let restore = &done["glacierEventData"]["restoreEventData"];
    assert_eq!(restore["lifecycleRestoreStorageClass"], "GLACIER");
    assert!(restore["lifecycleRestorationExpiryTime"].is_string());
    let events = collect(&sqs, &eb_url, 2, |e| e["source"] == "aws.s3").await;
    let completed =
        events.iter().find(|e| e["detail-type"] == "Object Restore Completed").expect("Object Restore Completed");
    assert_eq!(completed["detail"]["source-storage-class"], "GLACIER");
    assert!(completed["detail"]["restore-expiry-time"].is_string());

    let head = s3.head_object().bucket("aging").key("cold/b").send().await.unwrap();
    assert!(head.restore().unwrap().starts_with("ongoing-request=\"false\", expiry-date="), "{:?}", head.restore());
    let got = s3.get_object().bucket("aging").key("cold/b").send().await.unwrap();
    assert_eq!(got.body.collect().await.unwrap().into_bytes().as_ref(), b"frozen");
}
