//! SNS FIFO message archiving and replay through the official Rust SDK.

use aws_sdk_sns::error::ProvideErrorMetadata;
use aws_sdk_sns::Client;
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;
use serde_json::json;

async fn fifo_queue(sqs: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let url = sqs
        .create_queue()
        .queue_name(name)
        .attributes(QueueAttributeName::FifoQueue, "true")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let arn = format!("arn:aws:sqs:us-east-1:123456789012:{name}");
    let policy = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": arn
    }]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    (url, arn)
}

async fn drain(sqs: &aws_sdk_sqs::Client, url: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    loop {
        let got =
            sqs.receive_message().queue_url(url).max_number_of_messages(10).wait_time_seconds(1).send().await.unwrap();
        if got.messages().is_empty() {
            return out;
        }
        for m in got.messages() {
            out.push(serde_json::from_str(m.body().unwrap()).unwrap());
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
    }
}

#[tokio::test]
async fn archived_messages_replay_to_new_subscriptions() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);

    // Archiving is for FIFO topics only.
    let e = sns
        .create_topic()
        .name("plain")
        .attributes("ArchivePolicy", r#"{"MessageRetentionPeriod":"7"}"#)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("InvalidParameter"));

    let topic = sns
        .create_topic()
        .name("orders.fifo")
        .attributes("FifoTopic", "true")
        .attributes("ContentBasedDeduplication", "true")
        .attributes("ArchivePolicy", r#"{"MessageRetentionPeriod":"7"}"#)
        .send()
        .await
        .unwrap()
        .topic_arn()
        .unwrap()
        .to_string();
    let begin = |attrs: &aws_sdk_sns::operation::get_topic_attributes::GetTopicAttributesOutput| {
        attrs.attributes().unwrap()["BeginningArchiveTime"].clone()
    };
    let first = begin(&sns.get_topic_attributes().topic_arn(&topic).send().await.unwrap());
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(begin(&sns.get_topic_attributes().topic_arn(&topic).send().await.unwrap()), first);

    let before = chrono::Utc::now() - chrono::Duration::seconds(5);
    let mut ids = Vec::new();
    for (i, kind) in ["order", "refund", "order"].iter().enumerate() {
        let out = sns
            .publish()
            .topic_arn(&topic)
            .message(format!("m{i}"))
            .message_group_id("g")
            .message_attributes(
                "kind",
                aws_sdk_sns::types::MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value(*kind)
                    .build()
                    .unwrap(),
            )
            .send()
            .await
            .unwrap();
        ids.push(out.message_id().unwrap().to_string());
    }

    // A new subscription replays the archive through its filter policy.
    let (url, arn) = fifo_queue(&sqs, "replay.fifo").await;
    let replay = json!({"PointType": "Timestamp", "StartingPoint": before.to_rfc3339()}).to_string();
    let sub = sns
        .subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(&arn)
        .attributes("ReplayPolicy", &replay)
        .attributes("FilterPolicy", r#"{"kind":["order"]}"#)
        .send()
        .await
        .unwrap()
        .subscription_arn()
        .unwrap()
        .to_string();
    let got = drain(&sqs, &url).await;
    assert_eq!(got.len(), 2, "{got:#?}");
    assert_eq!(got[0]["MessageId"], ids[0].as_str());
    assert_eq!(got[0]["Message"], "m0");
    assert_eq!(got[0]["Replayed"], true);
    assert_eq!(got[1]["Message"], "m2");
    let attrs = sns.get_subscription_attributes().subscription_arn(&sub).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["ReplayStatus"], "Completed");

    // Without an EndingPoint, new messages keep coming (not replayed).
    sns.publish().topic_arn(&topic).message("m3").message_group_id("g").send().await.unwrap();
    // No `kind` attribute: filtered out. Publish a matching one too.
    sns.publish()
        .topic_arn(&topic)
        .message("m4")
        .message_group_id("g")
        .message_attributes(
            "kind",
            aws_sdk_sns::types::MessageAttributeValue::builder()
                .data_type("String")
                .string_value("order")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let got = drain(&sqs, &url).await;
    assert_eq!(got.len(), 1, "{got:#?}");
    assert_eq!(got[0]["Message"], "m4");
    assert!(got[0].get("Replayed").is_none());

    // An EndingPoint pauses the subscription.
    let window = json!({
        "PointType": "Timestamp",
        "StartingPoint": before.to_rfc3339(),
        "EndingPoint": (chrono::Utc::now() + chrono::Duration::seconds(1)).to_rfc3339(),
    });
    let (paused_url, paused_arn) = fifo_queue(&sqs, "paused.fifo").await;
    let paused = sns
        .subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(&paused_arn)
        .send()
        .await
        .unwrap()
        .subscription_arn()
        .unwrap()
        .to_string();
    sns.set_subscription_attributes()
        .subscription_arn(&paused)
        .attribute_name("ReplayPolicy")
        .attribute_value(window.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(drain(&sqs, &paused_url).await.len(), 5);
    sns.publish().topic_arn(&topic).message("m5").message_group_id("g").send().await.unwrap();
    assert!(drain(&sqs, &paused_url).await.is_empty());

    // Bad policies and topics that do not archive.
    let e = sns
        .set_subscription_attributes()
        .subscription_arn(&paused)
        .attribute_name("ReplayPolicy")
        .attribute_value(r#"{"PointType":"Sequence","StartingPoint":"1"}"#)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("InvalidParameter"));
    let unarchived = sns
        .create_topic()
        .name("noarchive.fifo")
        .attributes("FifoTopic", "true")
        .send()
        .await
        .unwrap()
        .topic_arn()
        .unwrap()
        .to_string();
    let (_, other_arn) = fifo_queue(&sqs, "other.fifo").await;
    let e = sns
        .subscribe()
        .topic_arn(&unarchived)
        .protocol("sqs")
        .endpoint(&other_arn)
        .attributes("ReplayPolicy", &replay)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("InvalidParameter"));
    mws.stop().await;
}
