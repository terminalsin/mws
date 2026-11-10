//! The metrics AWS services publish into CloudWatch, and what CloudWatch
//! alarms do to other services, through the official Rust SDK: `AWS/Lambda`
//! per invocation, `AWS/SNS` per publish and delivery, `AWS/Events` per
//! rule, and EC2 alarm actions that stop an instance.

use std::time::Duration;

use aws_sdk_cloudwatch::types::{Dimension, StateValue, Statistic};
use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, Runtime};
use mws_e2e::Mws;

use crate::lambda::zip;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

fn dim(name: &str, value: &str) -> Dimension {
    Dimension::builder().name(name).value(value).build()
}

/// The `Sum` of a metric over the last hour (and the next few minutes),
/// waiting until it reaches `want`.
async fn sum(cw: &aws_sdk_cloudwatch::Client, ns: &str, name: &str, dims: &[Dimension], want: f64) -> f64 {
    let mut last = 0.0;
    for _ in 0..100 {
        let now = std::time::SystemTime::now();
        let mut req = cw
            .get_metric_statistics()
            .namespace(ns)
            .metric_name(name)
            .start_time((now - Duration::from_secs(3600)).into())
            .end_time((now + Duration::from_secs(600)).into())
            .period(3600)
            .statistics(Statistic::Sum);
        for d in dims {
            req = req.dimensions(d.clone());
        }
        let out = req.send().await.unwrap();
        last = out.datapoints().iter().filter_map(|d| d.sum()).sum();
        if last >= want {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    last
}

#[tokio::test]
async fn lambda_invocations_publish_aws_lambda_metrics() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    let role = iam.create_role().role_name("fn").assume_role_policy_document(TRUST).send().await.unwrap();
    let code =
        "def handler(event, context):\n    if event.get('fail'):\n        raise ValueError('no')\n    return 1\n";
    lambda
        .create_function()
        .function_name("metered")
        .runtime(Runtime::Python312)
        .handler("app.handler")
        .role(role.role().unwrap().arn())
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", code)]))).build())
        .send()
        .await
        .unwrap();
    lambda.invoke().function_name("metered").payload(Blob::new(b"{}".to_vec())).send().await.unwrap();
    let failed =
        lambda.invoke().function_name("metered").payload(Blob::new(br#"{"fail":true}"#.to_vec())).send().await.unwrap();
    assert_eq!(failed.function_error(), Some("Unhandled"));

    let by_name = [dim("FunctionName", "metered")];
    assert_eq!(sum(&cw, "AWS/Lambda", "Invocations", &by_name, 2.0).await, 2.0);
    assert_eq!(sum(&cw, "AWS/Lambda", "Errors", &by_name, 1.0).await, 1.0);
    // Every function together, without dimensions.
    assert_eq!(sum(&cw, "AWS/Lambda", "Invocations", &[], 2.0).await, 2.0);
    let now = std::time::SystemTime::now();
    let duration = cw
        .get_metric_statistics()
        .namespace("AWS/Lambda")
        .metric_name("Duration")
        .dimensions(dim("FunctionName", "metered"))
        .start_time((now - Duration::from_secs(3600)).into())
        .end_time((now + Duration::from_secs(600)).into())
        .period(3600)
        .statistics(Statistic::SampleCount)
        .statistics(Statistic::Maximum)
        .send()
        .await
        .unwrap();
    let point = &duration.datapoints()[0];
    assert_eq!(point.sample_count(), Some(2.0));
    assert!(point.maximum().unwrap() > 0.0);
    assert_eq!(point.unit().map(|u| u.as_str()), Some("Milliseconds"));

    let listed = cw.list_metrics().namespace("AWS/Lambda").send().await.unwrap();
    let names: Vec<&str> = listed.metrics().iter().filter_map(|m| m.metric_name()).collect();
    for n in ["Invocations", "Errors", "Duration", "ConcurrentExecutions"] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
}

#[tokio::test]
async fn sns_publishes_and_deliveries_publish_aws_sns_metrics() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = aws_sdk_sns::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    let topic = sns.create_topic().name("orders").send().await.unwrap().topic_arn.unwrap();
    let url = sqs.create_queue().queue_name("orders-q").send().await.unwrap().queue_url.unwrap();
    let queue_arn = "arn:aws:sqs:us-east-1:123456789012:orders-q";
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"sns.amazonaws.com"}},"Action":"sqs:SendMessage","Resource":"{queue_arn}"}}]}}"#
    );
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy)
        .send()
        .await
        .unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(queue_arn)
        .attributes("FilterPolicy", r#"{"kind":["paid"]}"#)
        .send()
        .await
        .unwrap();
    let attr = |v: &str| {
        aws_sdk_sns::types::MessageAttributeValue::builder().data_type("String").string_value(v).build().unwrap()
    };
    sns.publish().topic_arn(&topic).message("one").message_attributes("kind", attr("paid")).send().await.unwrap();
    sns.publish().topic_arn(&topic).message("two").message_attributes("kind", attr("free")).send().await.unwrap();

    let by_topic = [dim("TopicName", "orders")];
    assert_eq!(sum(&cw, "AWS/SNS", "NumberOfMessagesPublished", &by_topic, 2.0).await, 2.0);
    assert_eq!(sum(&cw, "AWS/SNS", "NumberOfNotificationsDelivered", &by_topic, 1.0).await, 1.0);
    assert_eq!(sum(&cw, "AWS/SNS", "NumberOfNotificationsFilteredOut", &by_topic, 1.0).await, 1.0);
    assert_eq!(sum(&cw, "AWS/SNS", "PublishSize", &by_topic, 6.0).await, 6.0);
}

#[tokio::test]
async fn eventbridge_rules_publish_aws_events_metrics() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    sqs.create_queue().queue_name("sink").send().await.unwrap();
    eb.put_rule().name("orders").event_pattern(r#"{"source":["shop"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("orders")
        .targets(
            aws_sdk_eventbridge::types::Target::builder()
                .id("q")
                .arn("arn:aws:sqs:us-east-1:123456789012:sink")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let entry =
        aws_sdk_eventbridge::types::PutEventsRequestEntry::builder().source("shop").detail_type("Order").detail("{}");
    eb.put_events().entries(entry.clone().build()).entries(entry.build()).send().await.unwrap();

    let by_rule = [dim("RuleName", "orders")];
    assert_eq!(sum(&cw, "AWS/Events", "TriggeredRules", &by_rule, 2.0).await, 2.0);
    // The queue policy does not let EventBridge send: both deliveries fail.
    assert_eq!(sum(&cw, "AWS/Events", "Invocations", &by_rule, 2.0).await, 2.0);
    assert_eq!(sum(&cw, "AWS/Events", "FailedInvocations", &by_rule, 2.0).await, 2.0);
    let by_bus = [dim("EventBusName", "default"), dim("RuleName", "orders")];
    assert_eq!(sum(&cw, "AWS/Events", "TriggeredRules", &by_bus, 2.0).await, 2.0);
}

#[tokio::test]
async fn ec2_alarm_actions_stop_the_instance() {
    let mws =
        Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    let images = ec2.describe_images().owners("amazon").send().await.unwrap();
    let image = images.images()[0].image_id().unwrap().to_string();
    let id = ec2.run_instances().image_id(image).min_count(1).max_count(1).send().await.unwrap().instances()[0]
        .instance_id()
        .unwrap()
        .to_string();
    let state = |ec2: aws_sdk_ec2::Client, id: String| async move {
        let d = ec2.describe_instances().instance_ids(id).send().await.unwrap();
        d.reservations()[0].instances()[0].state().and_then(|s| s.name()).map(|n| n.as_str().to_string())
    };
    for _ in 0..100 {
        if state(ec2.clone(), id.clone()).await.as_deref() == Some("running") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    cw.put_metric_alarm()
        .alarm_name("idle")
        .namespace("AWS/EC2")
        .metric_name("CPUUtilization")
        .dimensions(dim("InstanceId", &id))
        .statistic(Statistic::Average)
        .period(300)
        .evaluation_periods(1)
        .threshold(5.0)
        .comparison_operator(aws_sdk_cloudwatch::types::ComparisonOperator::LessThanThreshold)
        .alarm_actions("arn:aws:automate:us-east-1:ec2:stop")
        .send()
        .await
        .unwrap();
    cw.set_alarm_state().alarm_name("idle").state_value(StateValue::Alarm).state_reason("idle").send().await.unwrap();
    for _ in 0..100 {
        if matches!(state(ec2.clone(), id.clone()).await.as_deref(), Some("stopping" | "stopped")) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the alarm action did not stop {id}");
}
