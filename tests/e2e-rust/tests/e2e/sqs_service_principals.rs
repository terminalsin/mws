//! AWS services sending to SQS call `SendMessage` as their service
//! principal, and the queue policy alone decides, with the condition keys
//! AWS sets for service principals (`aws:SourceArn`, `aws:SourceAccount`,
//! `aws:SourceOrgID`).

use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

async fn queue_with_policy(sqs: &aws_sdk_sqs::Client, name: &str, statements: serde_json::Value) -> (String, String) {
    let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url().unwrap().to_string();
    let arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:{name}");
    let policy = serde_json::json!({ "Version": "2012-10-17", "Statement": statements });
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::Policy, policy.to_string().replace("QUEUE", &arn))
        .send()
        .await
        .unwrap();
    (url, arn)
}

async fn bodies(sqs: &aws_sdk_sqs::Client, url: &str) -> Vec<(String, String)> {
    let got = sqs
        .receive_message()
        .queue_url(url)
        .max_number_of_messages(10)
        .message_system_attribute_names(aws_sdk_sqs::types::MessageSystemAttributeName::SenderId)
        .wait_time_seconds(1)
        .send()
        .await
        .unwrap();
    got.messages()
        .iter()
        .map(|m| {
            let sender = m
                .attributes()
                .and_then(|a| a.get(&aws_sdk_sqs::types::MessageSystemAttributeName::SenderId))
                .cloned()
                .unwrap_or_default();
            (sender, m.body().unwrap_or_default().to_string())
        })
        .collect()
}

#[tokio::test]
async fn queue_policies_judge_service_principals_by_source_org_arn_and_explicit_denies() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let orgs = aws_sdk_organizations::Client::new(&cfg);
    let org = orgs.create_organization().send().await.unwrap();
    let org_id = org.organization().unwrap().id().unwrap().to_string();
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);
    let events = aws_sdk_eventbridge::Client::new(&cfg);

    // Allowed for services acting for an account of the organization.
    let (org_url, org_arn) = queue_with_policy(
        &sqs,
        "org-only",
        serde_json::json!([{
            "Effect": "Allow",
            "Principal": {"Service": ["sns.amazonaws.com", "events.amazonaws.com"]},
            "Action": "sqs:SendMessage",
            "Resource": "QUEUE",
            "Condition": {"StringEquals": {"aws:SourceOrgID": org_id}}
        }]),
    )
    .await;
    // Allowed for SNS, but one topic is denied explicitly.
    let blocked_topic = format!("arn:aws:sns:us-east-1:{ACCOUNT}:blocked");
    let (deny_url, deny_arn) = queue_with_policy(
        &sqs,
        "deny-one-topic",
        serde_json::json!([
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": "QUEUE"
            },
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "sqs:SendMessage",
                "Resource": "QUEUE",
                "Condition": {"ArnEquals": {"aws:SourceArn": blocked_topic}}
            }
        ]),
    )
    .await;
    // Principals other than services are not let in by a service grant.
    let (other_url, other_arn) = queue_with_policy(
        &sqs,
        "lambda-only",
        serde_json::json!([{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": "QUEUE"
        }]),
    )
    .await;

    let open = sns.create_topic().name("open").send().await.unwrap().topic_arn().unwrap().to_string();
    let blocked = sns.create_topic().name("blocked").send().await.unwrap().topic_arn().unwrap().to_string();
    assert_eq!(blocked, blocked_topic);
    for (topic, queue) in [(&open, &org_arn), (&open, &deny_arn), (&blocked, &deny_arn), (&open, &other_arn)] {
        sns.subscribe()
            .topic_arn(topic)
            .protocol("sqs")
            .endpoint(queue)
            .attributes("RawMessageDelivery", "true")
            .send()
            .await
            .unwrap();
    }
    sns.publish().topic_arn(&open).message("from-open").send().await.unwrap();
    sns.publish().topic_arn(&blocked).message("from-blocked").send().await.unwrap();

    // SNS's messages carry its principal as the sender.
    assert_eq!(bodies(&sqs, &org_url).await, vec![("sns.amazonaws.com".to_string(), "from-open".to_string())]);
    assert_eq!(bodies(&sqs, &deny_url).await, vec![("sns.amazonaws.com".to_string(), "from-open".to_string())]);
    assert!(bodies(&sqs, &other_url).await.is_empty());

    // EventBridge targets go through the same check.
    events.put_rule().name("orders").event_pattern(r#"{"source":["app.orders"]}"#).send().await.unwrap();
    let target = |id: &str, arn: &str| aws_sdk_eventbridge::types::Target::builder().id(id).arn(arn).build().unwrap();
    events
        .put_targets()
        .rule("orders")
        .targets(target("org", &org_arn))
        .targets(target("other", &other_arn))
        .send()
        .await
        .unwrap();
    let entry = aws_sdk_eventbridge::types::PutEventsRequestEntry::builder()
        .source("app.orders")
        .detail_type("Order Placed")
        .detail(r#"{"id":7}"#)
        .build();
    let put = events.put_events().entries(entry).send().await.unwrap();
    assert_eq!(put.failed_entry_count(), 0);
    let mut got = Vec::new();
    for _ in 0..10 {
        got.extend(bodies(&sqs, &org_url).await);
        if !got.is_empty() {
            break;
        }
    }
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].0, "events.amazonaws.com");
    let event: serde_json::Value = serde_json::from_str(&got[0].1).unwrap();
    assert_eq!(event["detail"]["id"], 7);
    assert!(bodies(&sqs, &other_url).await.is_empty());
}
