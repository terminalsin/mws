//! EventBridge targets that cannot be reached, through the official Rust
//! SDK: a target in a service MWS does not emulate (Step Functions here) is
//! a failed invocation that, like a missing target resource on AWS, is not
//! retried: it is counted in `FailedInvocations` and sent to the dead-letter
//! queue at once. It is never
//! reported as a success.

use std::time::Duration;

use aws_sdk_cloudwatch::types::{Dimension, Statistic};
use aws_sdk_eventbridge::types::{DeadLetterConfig, PutEventsRequestEntry, RetryPolicy, Target};
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

fn dim(name: &str, value: &str) -> Dimension {
    Dimension::builder().name(name).value(value).build()
}

async fn sum_now(cw: &aws_sdk_cloudwatch::Client, name: &str, rule: &str) -> f64 {
    let now = std::time::SystemTime::now();
    let out = cw
        .get_metric_statistics()
        .namespace("AWS/Events")
        .metric_name(name)
        .dimensions(dim("RuleName", rule))
        .start_time((now - Duration::from_secs(3600)).into())
        .end_time((now + Duration::from_secs(600)).into())
        .period(3600)
        .statistics(Statistic::Sum)
        .send()
        .await
        .unwrap();
    out.datapoints().iter().filter_map(|d| d.sum()).sum()
}

/// Waits until the metric reaches `want`, and returns its last value.
async fn sum(cw: &aws_sdk_cloudwatch::Client, name: &str, rule: &str, want: f64) -> f64 {
    let mut last = 0.0;
    for _ in 0..100 {
        last = sum_now(cw, name, rule).await;
        if last >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    last
}

#[tokio::test]
async fn unreachable_targets_fail_and_go_straight_to_the_dead_letter_queue() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);

    let dlq_url = sqs.create_queue().queue_name("rule-dlq").send().await.unwrap().queue_url.unwrap();
    let dlq_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:rule-dlq");
    let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},
        "Action":"sqs:SendMessage","Resource":dlq_arn}]});
    sqs.set_queue_attributes()
        .queue_url(&dlq_url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();

    let machine = format!("arn:aws:states:us-east-1:{ACCOUNT}:stateMachine:orders");
    eb.put_rule().name("to-sfn").event_pattern(r#"{"source":["shop"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("to-sfn")
        .targets(
            Target::builder()
                .id("sfn")
                .arn(&machine)
                .role_arn(format!("arn:aws:iam::{ACCOUNT}:role/events-sfn"))
                .retry_policy(RetryPolicy::builder().maximum_retry_attempts(1).build())
                .dead_letter_config(DeadLetterConfig::builder().arn(&dlq_arn).build())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let put = eb
        .put_events()
        .entries(PutEventsRequestEntry::builder().source("shop").detail_type("Order").detail(r#"{"n":7}"#).build())
        .send()
        .await
        .unwrap();
    assert_eq!(put.failed_entry_count(), 0);
    let event_id = put.entries()[0].event_id().unwrap().to_string();

    // The dead-letter message arrives without retries; long-poll for it.
    let mut message = None;
    for _ in 0..10 {
        let r = sqs
            .receive_message()
            .queue_url(&dlq_url)
            .message_attribute_names("All")
            .wait_time_seconds(2)
            .send()
            .await
            .unwrap();
        if let Some(m) = r.messages.unwrap_or_default().into_iter().next() {
            message = Some(m);
            break;
        }
    }
    let m = message.expect("the event reached the dead-letter queue");
    let body: serde_json::Value = serde_json::from_str(m.body().unwrap()).unwrap();
    assert_eq!(body["id"], event_id.as_str());
    assert_eq!(body["detail"]["n"], 7);
    let attrs = m.message_attributes.unwrap();
    let attr = |k: &str| attrs[k].string_value.clone().unwrap();
    assert_eq!(attr("RULE_ARN"), format!("arn:aws:events:us-east-1:{ACCOUNT}:rule/to-sfn"));
    assert_eq!(attr("TARGET_ARN"), machine);
    assert_eq!(attr("ERROR_CODE"), "ResourceNotFoundException");
    assert!(attr("ERROR_MESSAGE").contains(&machine), "{}", attr("ERROR_MESSAGE"));
    assert_eq!(attr("EXHAUSTED_RETRY_CONDITION"), "RetriesExhausted");
    assert_eq!(attr("RETRY_ATTEMPTS"), "0");

    assert_eq!(sum(&cw, "InvocationsSentToDlq", "to-sfn", 1.0).await, 1.0);
    assert_eq!(sum(&cw, "FailedInvocations", "to-sfn", 1.0).await, 1.0);
    assert_eq!(sum(&cw, "Invocations", "to-sfn", 1.0).await, 1.0);
    assert_eq!(sum(&cw, "InvocationAttempts", "to-sfn", 1.0).await, 1.0);
    assert_eq!(sum_now(&cw, "RetryInvocationAttempts", "to-sfn").await, 0.0);
    // Nothing reports the delivery as a success.
    assert_eq!(sum_now(&cw, "SuccessfulInvocationAttempts", "to-sfn").await, 0.0);
    assert_eq!(sum_now(&cw, "IngestionToInvocationSuccessLatency", "to-sfn").await, 0.0);
    mws.stop().await;
}

#[tokio::test]
async fn unreachable_targets_without_a_dead_letter_queue_still_fail() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    eb.put_rule().name("to-build").event_pattern(r#"{"source":["ci"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("to-build")
        .targets(
            Target::builder()
                .id("build")
                .arn(format!("arn:aws:codebuild:us-east-1:{ACCOUNT}:project/app"))
                .role_arn(format!("arn:aws:iam::{ACCOUNT}:role/events-build"))
                .retry_policy(RetryPolicy::builder().maximum_retry_attempts(0).build())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    eb.put_events()
        .entries(PutEventsRequestEntry::builder().source("ci").detail_type("Push").detail("{}").build())
        .send()
        .await
        .unwrap();
    assert_eq!(sum(&cw, "FailedInvocations", "to-build", 1.0).await, 1.0);
    assert_eq!(sum(&cw, "InvocationAttempts", "to-build", 1.0).await, 1.0);
    assert_eq!(sum_now(&cw, "SuccessfulInvocationAttempts", "to-build").await, 0.0);
    assert_eq!(sum_now(&cw, "InvocationsSentToDlq", "to-build").await, 0.0);
    mws.stop().await;
}
