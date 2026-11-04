//! SNS parity fixes through the official Rust SDKs: Firehose
//! subscriptions, message data protection policies, MessageGroupId on
//! standard topics (SQS fair queues), FIFO deduplication scope, and which
//! queues a topic may have.

use std::time::Duration;

use aws_sdk_sns::error::ProvideErrorMetadata;
use aws_sdk_sqs::types::{MessageSystemAttributeName, QueueAttributeName};
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

fn trust(service: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
    )
}

async fn role(iam: &aws_sdk_iam::Client, name: &str, service: &str, actions: &str) -> String {
    let created = iam.create_role().role_name(name).assume_role_policy_document(trust(service)).send().await.unwrap();
    let policy =
        format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":"*"}}]}}"#);
    iam.put_role_policy().role_name(name).policy_name("p").policy_document(policy).send().await.unwrap();
    created.role().unwrap().arn().to_string()
}

/// A queue SNS topics in the account may send to; returns (url, arn).
async fn open_queue(sqs: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let mut create = sqs.create_queue().queue_name(name);
    if name.ends_with(".fifo") {
        create = create.attributes(QueueAttributeName::FifoQueue, "true");
    }
    let url = create.send().await.unwrap().queue_url.unwrap();
    let arn = sqs
        .get_queue_attributes()
        .queue_url(&url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes
        .unwrap()[&QueueAttributeName::QueueArn]
        .clone();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"sns.amazonaws.com"}},"Action":"sqs:SendMessage","Resource":"{arn}"}}]}}"#
    );
    sqs.set_queue_attributes().queue_url(&url).attributes(QueueAttributeName::Policy, policy).send().await.unwrap();
    (url, arn)
}

/// The bodies (and message group ids) of up to `n` messages on a queue.
async fn receive(sqs: &aws_sdk_sqs::Client, url: &str, n: usize) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for _ in 0..20 {
        let got = sqs
            .receive_message()
            .queue_url(url)
            .max_number_of_messages(10)
            .message_system_attribute_names(MessageSystemAttributeName::MessageGroupId)
            .wait_time_seconds(1)
            .send()
            .await
            .unwrap();
        for m in got.messages() {
            let group = m.attributes().and_then(|a| a.get(&MessageSystemAttributeName::MessageGroupId)).cloned();
            out.push((m.body().unwrap_or_default().to_string(), group));
        }
        if out.len() >= n {
            break;
        }
    }
    out
}

fn notification(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap()
}

#[tokio::test]
async fn firehose_subscriptions_deliver_records() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);
    let firehose = aws_sdk_firehose::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);

    s3.create_bucket().bucket("archive").send().await.unwrap();
    let delivery = role(&iam, "delivery", "firehose.amazonaws.com", r#"["s3:PutObject"]"#).await;
    let subscription = role(&iam, "sns-to-firehose", "sns.amazonaws.com", r#"["firehose:PutRecord"]"#).await;
    for (name, prefix) in [("envelopes", "env/"), ("raw", "raw/")] {
        let config = aws_sdk_firehose::types::ExtendedS3DestinationConfiguration::builder()
            .role_arn(&delivery)
            .bucket_arn("arn:aws:s3:::archive")
            .prefix(prefix)
            .buffering_hints(
                aws_sdk_firehose::types::BufferingHints::builder().interval_in_seconds(0).size_in_mbs(1).build(),
            )
            .build()
            .unwrap();
        firehose
            .create_delivery_stream()
            .delivery_stream_name(name)
            .extended_s3_destination_configuration(config)
            .send()
            .await
            .unwrap();
    }
    for _ in 0..100 {
        let d = firehose.describe_delivery_stream().delivery_stream_name("raw").send().await.unwrap();
        if d.delivery_stream_description().unwrap().delivery_stream_status()
            == &aws_sdk_firehose::types::DeliveryStreamStatus::Active
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let topic = sns.create_topic().name("events").send().await.unwrap().topic_arn.unwrap();
    let env_sub = sns
        .subscribe()
        .topic_arn(&topic)
        .protocol("firehose")
        .endpoint(format!("arn:aws:firehose:us-east-1:{ACCOUNT}:deliverystream/envelopes"))
        .attributes("SubscriptionRoleArn", &subscription)
        .send()
        .await
        .unwrap()
        .subscription_arn
        .unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("firehose")
        .endpoint(format!("arn:aws:firehose:us-east-1:{ACCOUNT}:deliverystream/raw"))
        .attributes("SubscriptionRoleArn", &subscription)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();

    let id = sns
        .publish()
        .topic_arn(&topic)
        .subject("Hello")
        .message("first body")
        .message_attributes(
            "kind",
            aws_sdk_sns::types::MessageAttributeValue::builder().data_type("String").string_value("a").build().unwrap(),
        )
        .send()
        .await
        .unwrap()
        .message_id
        .unwrap();

    let objects = |prefix: &'static str| {
        let s3 = s3.clone();
        let firehose = firehose.clone();
        async move {
            for _ in 0..100 {
                let _ = firehose.list_delivery_streams().send().await;
                let listed = s3.list_objects_v2().bucket("archive").prefix(prefix).send().await.unwrap();
                if let Some(o) = listed.contents().first() {
                    let body = s3.get_object().bucket("archive").key(o.key().unwrap()).send().await.unwrap();
                    return String::from_utf8(body.body.collect().await.unwrap().into_bytes().to_vec()).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!("nothing delivered under {prefix}");
        }
    };
    let env = objects("env/").await;
    assert!(env.ends_with('\n'), "{env:?}");
    let doc = notification(env.trim_end());
    assert_eq!(doc["Type"], "Notification");
    assert_eq!(doc["MessageId"], id.as_str());
    assert_eq!(doc["TopicArn"], topic.as_str());
    assert_eq!(doc["Subject"], "Hello");
    assert_eq!(doc["Message"], "first body");
    assert_eq!(doc["MessageAttributes"]["kind"]["Value"], "a");
    let unsubscribe = doc["UnsubscribeURL"].as_str().unwrap();
    assert!(unsubscribe.contains(&env_sub.replace(':', "%3A")), "{unsubscribe}");
    // Firehose records are not signed.
    assert!(doc.get("Signature").is_none() && doc.get("SigningCertURL").is_none(), "{doc}");
    assert_eq!(objects("raw/").await, "first body\n");
    mws.stop().await;
}

const SSN: &str = "arn:aws:dataprotection::aws:data-identifier/Ssn-US";
const EMAIL: &str = "arn:aws:dataprotection::aws:data-identifier/EmailAddress";

#[tokio::test]
async fn data_protection_policies_act_on_messages() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = aws_sdk_sns::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let topic = sns.create_topic().name("pii").send().await.unwrap().topic_arn.unwrap();
    let (masked_url, masked_arn) = open_queue(&sqs, "masked").await;
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(&masked_arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();

    // A user who subscribes a queue; outbound statements name them.
    let (_, user_cfg) = user_with_policy(
        &mws,
        "auditor",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:*","Resource":"*"}]}"#),
    )
    .await;
    let auditor = aws_sdk_sns::Client::new(&user_cfg);
    let (blocked_url, blocked_arn) = open_queue(&sqs, "blocked").await;
    let sub = auditor
        .subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(&blocked_arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap()
        .subscription_arn
        .unwrap();
    let attrs = sns.get_subscription_attributes().subscription_arn(&sub).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["SubscriptionPrincipal"], format!("arn:aws:iam::{ACCOUNT}:user/auditor"));

    logs.create_log_group().log_group_name("/aws/vendedlogs/sns-audit").send().await.unwrap();
    let policy = serde_json::json!({
        "Name": "pii", "Version": "2021-06-01",
        "Statement": [
            {"Sid": "audit", "DataDirection": "Inbound", "Principal": ["*"], "DataIdentifier": [SSN, EMAIL],
             "Operation": {"Audit": {"SampleRate": 99,
                "FindingsDestination": {"CloudWatchLogs": {"LogGroup": "/aws/vendedlogs/sns-audit"}}}}},
            {"Sid": "mask", "DataDirection": "Inbound", "Principal": ["*"], "DataIdentifier": [SSN],
             "Operation": {"Deidentify": {"MaskConfig": {"MaskWithCharacter": "#"}}}},
            {"Sid": "deny-email", "DataDirection": "Inbound", "Principal": [format!("arn:aws:iam::{ACCOUNT}:user/auditor")],
             "DataIdentifier": [EMAIL], "Operation": {"Deny": {}}},
            {"Sid": "deny-out", "DataDirection": "Outbound", "Principal": [format!("arn:aws:iam::{ACCOUNT}:user/auditor")],
             "DataIdentifier": [EMAIL], "Operation": {"Deny": {}}}
        ]
    });
    sns.put_data_protection_policy()
        .resource_arn(&topic)
        .data_protection_policy(policy.to_string())
        .send()
        .await
        .unwrap();

    // Bad policies are refused.
    let mut bad = policy.clone();
    bad["Statement"][0]["DataDirection"] = "Outbound".into();
    let err = sns
        .put_data_protection_policy()
        .resource_arn(&topic)
        .data_protection_policy(bad.to_string())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("InvalidParameter"));

    // Inbound: masked for everyone; e-mail addresses denied for the auditor.
    let id = sns.publish().topic_arn(&topic).message("ssn: 123-45-6789 mail: a@example.com").send().await.unwrap();
    let err = auditor
        .publish()
        .topic_arn(&topic)
        .message("mail: a@example.com")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("AuthorizationError"));
    // A message that is nothing but sensitive data is refused.
    let err = sns.publish().topic_arn(&topic).message("123-45-6789").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("AuthorizationError"));
    sns.publish().topic_arn(&topic).message("plain").send().await.unwrap();

    let got = receive(&sqs, &masked_url, 2).await;
    let bodies: Vec<&str> = got.iter().map(|(b, _)| b.as_str()).collect();
    assert!(bodies.contains(&"ssn: ########### mail: a@example.com"), "{bodies:?}");
    assert!(bodies.contains(&"plain"), "{bodies:?}");
    // Outbound: the auditor's queue never gets the message with an e-mail.
    let got = receive(&sqs, &blocked_url, 1).await;
    let bodies: Vec<&str> = got.iter().map(|(b, _)| b.as_str()).collect();
    assert_eq!(bodies, vec!["plain"]);

    // Audit findings for the sampled message with findings.
    let mut findings = Vec::new();
    for _ in 0..40 {
        if let Ok(found) = logs.filter_log_events().log_group_name("/aws/vendedlogs/sns-audit").send().await {
            findings = found
                .events()
                .iter()
                .filter_map(|e| serde_json::from_str::<serde_json::Value>(e.message()?).ok())
                .collect();
        }
        if !findings.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mine: Vec<&serde_json::Value> =
        findings.iter().filter(|f| f["messageId"] == id.message_id().unwrap()).collect();
    // A 99% sample rate can skip a message; when it is written, check it.
    if let Some(f) = mine.first() {
        assert_eq!(f["resourceArn"], topic.as_str());
        assert_eq!(f["callerPrincipal"], format!("arn:aws:iam::{ACCOUNT}:root"));
        let names: Vec<&str> =
            f["dataIdentifiers"].as_array().unwrap().iter().filter_map(|d| d["name"].as_str()).collect();
        assert!(names.contains(&"Ssn-US") && names.contains(&"EmailAddress"), "{f}");
        assert_eq!(f["dataIdentifiers"][0]["count"], 1);
    }
    mws.stop().await;
}

#[tokio::test]
async fn message_groups_and_fifo_rules() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = aws_sdk_sns::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);

    // Standard topics pass MessageGroupId on to standard queues (fair
    // queues), and cannot have FIFO queues.
    let topic = sns.create_topic().name("standard").send().await.unwrap().topic_arn.unwrap();
    let (url, arn) = open_queue(&sqs, "fair").await;
    sns.subscribe().topic_arn(&topic).protocol("sqs").endpoint(&arn).send().await.unwrap();
    sns.publish().topic_arn(&topic).message("m").message_group_id("tenant-1").send().await.unwrap();
    let got = receive(&sqs, &url, 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1.as_deref(), Some("tenant-1"));
    assert_eq!(notification(&got[0].0)["Message"], "m");
    let (_, fifo_arn) = open_queue(&sqs, "ordered.fifo").await;
    let err = sns
        .subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(&fifo_arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("InvalidParameter"));
    assert!(err.message().unwrap().contains("FIFO SQS Queues can not be subscribed to standard SNS topics"));

    // Deduplication covers the whole topic, or each message group with
    // FifoThroughputScope = MessageGroup.
    for (name, scope, distinct) in [("topic.fifo", "Topic", false), ("groups.fifo", "MessageGroup", true)] {
        let fifo = sns
            .create_topic()
            .name(name)
            .attributes("FifoTopic", "true")
            .attributes("FifoThroughputScope", scope)
            .send()
            .await
            .unwrap()
            .topic_arn
            .unwrap();
        let mut ids = Vec::new();
        for group in ["a", "b"] {
            let out = sns
                .publish()
                .topic_arn(&fifo)
                .message("same")
                .message_group_id(group)
                .message_deduplication_id("d-1")
                .send()
                .await
                .unwrap();
            ids.push(out.message_id.unwrap());
        }
        assert_eq!(ids[0] != ids[1], distinct, "{scope}: {ids:?}");
    }
    mws.stop().await;
}
