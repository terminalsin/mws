//! SNS delivery status logging to CloudWatch Logs through the official
//! Rust SDKs: records written as the topic's feedback role.

use std::time::Duration;

use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

async fn records(logs: &aws_sdk_cloudwatchlogs::Client, group: &str) -> Vec<serde_json::Value> {
    for _ in 0..40 {
        if let Ok(found) = logs.filter_log_events().log_group_name(group).send().await {
            let events: Vec<serde_json::Value> =
                found.events().iter().filter_map(|e| serde_json::from_str(e.message()?).ok()).collect();
            if !events.is_empty() {
                return events;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Vec::new()
}

#[tokio::test]
async fn sqs_deliveries_are_logged_as_the_feedback_role() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);

    let role = iam.create_role().role_name("sns-feedback").assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy()
        .role_name("sns-feedback")
        .policy_name("logs")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    let topic = sns.create_topic().name("orders").send().await.unwrap().topic_arn.unwrap();
    for (k, v) in [
        ("SQSSuccessFeedbackRoleArn", role_arn.as_str()),
        ("SQSFailureFeedbackRoleArn", role_arn.as_str()),
        ("SQSSuccessFeedbackSampleRate", "100"),
    ] {
        sns.set_topic_attributes().topic_arn(&topic).attribute_name(k).attribute_value(v).send().await.unwrap();
    }

    let arn_of = |url: String| {
        let sqs = sqs.clone();
        async move {
            sqs.get_queue_attributes()
                .queue_url(url)
                .attribute_names(QueueAttributeName::QueueArn)
                .send()
                .await
                .unwrap()
                .attributes
                .unwrap()[&QueueAttributeName::QueueArn]
                .clone()
        }
    };
    let ok_url = sqs.create_queue().queue_name("ok").send().await.unwrap().queue_url.unwrap();
    let ok_arn = arn_of(ok_url.clone()).await;
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"sns.amazonaws.com"}},"Action":"sqs:SendMessage","Resource":"{ok_arn}","Condition":{{"ArnEquals":{{"aws:SourceArn":"{topic}"}}}}}}]}}"#
    );
    sqs.set_queue_attributes().queue_url(&ok_url).attributes(QueueAttributeName::Policy, policy).send().await.unwrap();
    let closed_url = sqs.create_queue().queue_name("closed").send().await.unwrap().queue_url.unwrap();
    let closed_arn = arn_of(closed_url).await;
    for q in [&ok_arn, &closed_arn] {
        sns.subscribe().topic_arn(&topic).protocol("sqs").endpoint(q).send().await.unwrap();
    }

    let id = sns.publish().topic_arn(&topic).message("hello").send().await.unwrap().message_id.unwrap();

    let ok = records(&logs, "sns/us-east-1/123456789012/orders").await;
    assert_eq!(ok.len(), 1, "{ok:?}");
    assert_eq!(ok[0]["status"], "SUCCESS");
    assert_eq!(ok[0]["notification"]["messageId"], id.as_str());
    assert_eq!(ok[0]["notification"]["topicArn"], topic.as_str());
    assert_eq!(ok[0]["notification"]["messageMD5Sum"], "5d41402abc4b2a76b9719d911017c592");
    assert_eq!(ok[0]["delivery"]["destination"], ok_arn.as_str());
    assert_eq!(ok[0]["delivery"]["statusCode"], 200);
    let provider: serde_json::Value =
        serde_json::from_str(ok[0]["delivery"]["providerResponse"].as_str().unwrap()).unwrap();
    assert!(provider["sqsMessageId"].is_string());

    let failed = records(&logs, "sns/us-east-1/123456789012/orders/Failure").await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["status"], "FAILURE");
    assert_eq!(failed[0]["delivery"]["destination"], closed_arn.as_str());
    mws.stop().await;
}
