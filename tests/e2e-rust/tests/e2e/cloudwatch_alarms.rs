//! CloudWatch alarm evaluation details through the official Rust SDK: the
//! look-back over the evaluation range before `TreatMissingData` applies,
//! Systems Manager OpsItem actions, and the `cloudwatch:AlarmActions`
//! condition key.

use std::time::Duration;

use aws_sdk_cloudwatch::error::ProvideErrorMetadata;
use aws_sdk_cloudwatch::primitives::DateTime;
use aws_sdk_cloudwatch::types::{ComparisonOperator, MetricDatum, StateValue, Statistic};
use aws_sdk_cloudwatch::Client;
use mws_e2e::{user_with_policy, Mws};

use crate::cloudwatch_anomaly::clock_now;

async fn wait_for(cw: &Client, alarm: &str, state: StateValue) -> aws_sdk_cloudwatch::types::MetricAlarm {
    for _ in 0..100 {
        let out = cw.describe_alarms().alarm_names(alarm).send().await.unwrap();
        if let Some(a) = out.metric_alarms().first().filter(|a| a.state_value() == Some(&state)) {
            return a.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("alarm {alarm} never reached {state:?}");
}

async fn put(cw: &Client, metric: &str, points: &[(i64, f64)]) {
    for (t, v) in points {
        cw.put_metric_data()
            .namespace("Sparse")
            .metric_data(
                MetricDatum::builder().metric_name(metric).value(*v).timestamp(DateTime::from_secs(*t)).build(),
            )
            .send()
            .await
            .unwrap();
    }
}

async fn alarm(cw: &Client, name: &str, metric: &str, missing: &str) {
    cw.put_metric_alarm()
        .alarm_name(name)
        .namespace("Sparse")
        .metric_name(metric)
        .statistic(Statistic::Maximum)
        .period(60)
        .evaluation_periods(2)
        .datapoints_to_alarm(2)
        .threshold(5.0)
        .comparison_operator(ComparisonOperator::GreaterThanThreshold)
        .treat_missing_data(missing)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn missing_data_looks_back_over_the_evaluation_range() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    let now = clock_now(&mws).await;
    let m = now - now.rem_euclid(60);
    // Breaching, nothing, breaching in the last three minutes: the two most
    // recent real datapoints breach, so the gap is not treated at all.
    put(&cw, "Gappy", &[(m - 240, 1.0), (m - 180, 9.0), (m - 60, 9.0)]).await;
    alarm(&cw, "gappy", "Gappy", "notBreaching").await;
    let a = wait_for(&cw, "gappy", StateValue::Alarm).await;
    assert!(a.state_reason().unwrap().starts_with("Threshold Crossed: 2 out of the last 2 datapoints [9.0 ("), "{a:?}");

    // Not breaching, nothing, breaching: the most recent real datapoints
    // are 1.0 and 9.0, so a missing one is not counted as breaching.
    put(&cw, "Recovering", &[(m - 240, 9.0), (m - 180, 1.0), (m - 60, 9.0)]).await;
    alarm(&cw, "recovering", "Recovering", "breaching").await;
    wait_for(&cw, "recovering", StateValue::Ok).await;

    // With fewer real datapoints than EvaluationPeriods in the range, the
    // missing ones are treated as TreatMissingData says.
    put(&cw, "Lonely", &[(m - 60, 9.0)]).await;
    alarm(&cw, "lonely", "Lonely", "breaching").await;
    wait_for(&cw, "lonely", StateValue::Alarm).await;
}

#[tokio::test]
async fn alarm_actions_create_ops_items() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let cw = Client::new(&cfg);
    let ssm = aws_sdk_ssm::Client::new(&cfg);
    let ops = "arn:aws:ssm:us-east-1:123456789012:opsitem:2#CATEGORY=Availability";
    let incident = "arn:aws:ssm-incidents::123456789012:response-plan/oncall";
    cw.put_metric_alarm()
        .alarm_name("disk-full")
        .alarm_description("The disk is full")
        .namespace("Host")
        .metric_name("DiskUsed")
        .statistic(Statistic::Maximum)
        .period(60)
        .evaluation_periods(1)
        .threshold(90.0)
        .comparison_operator(ComparisonOperator::GreaterThanThreshold)
        .alarm_actions(ops)
        .alarm_actions(incident)
        .send()
        .await
        .unwrap();
    for _ in 0..2 {
        cw.set_alarm_state()
            .alarm_name("disk-full")
            .state_value(StateValue::Ok)
            .state_reason("ok")
            .send()
            .await
            .unwrap();
        cw.set_alarm_state()
            .alarm_name("disk-full")
            .state_value(StateValue::Alarm)
            .state_reason("the disk filled up")
            .send()
            .await
            .unwrap();
    }
    let items = ssm.describe_ops_items().send().await.unwrap();
    // The second ALARM finds the first OpsItem still open.
    assert_eq!(items.ops_item_summaries().len(), 1, "{items:?}");
    let id = items.ops_item_summaries()[0].ops_item_id().unwrap();
    let item = ssm.get_ops_item().ops_item_id(id).send().await.unwrap();
    let item = item.ops_item().unwrap();
    assert_eq!(item.title(), Some("CloudWatch alarm - 'disk-full' is in ALARM state"));
    assert_eq!(item.severity(), Some("2"));
    assert_eq!(item.category(), Some("Availability"));
    assert_eq!(item.status(), Some(&aws_sdk_ssm::types::OpsItemStatus::Open));
    assert!(item.description().unwrap().contains("the disk filled up"), "{item:?}");
    let resources = item.operational_data().unwrap()["/aws/resources"].value().unwrap();
    assert!(resources.contains("arn:aws:cloudwatch:us-east-1:123456789012:alarm:disk-full"), "{resources}");

    // Incident Manager is not emulated: that action fails, in the history.
    let history = cw
        .describe_alarm_history()
        .alarm_name("disk-full")
        .history_item_type(aws_sdk_cloudwatch::types::HistoryItemType::Action)
        .send()
        .await
        .unwrap();
    let summaries: Vec<&str> = history.alarm_history_items().iter().filter_map(|h| h.history_summary()).collect();
    assert!(summaries.iter().any(|s| s.starts_with(&format!("Successfully executed action {ops}"))), "{summaries:?}");
    assert!(summaries.iter().any(|s| s.starts_with(&format!("Failed to execute action {incident}"))), "{summaries:?}");
}

#[tokio::test]
async fn alarm_actions_condition_key_limits_targets() {
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudwatch:PutMetricAlarm","cloudwatch:PutCompositeAlarm"],"Resource":"*","Condition":{"ForAllValues:ArnLike":{"cloudwatch:AlarmActions":"arn:aws:sns:*:*:team-*"}}}]}"#;
    let (_, cfg) = user_with_policy(&mws, "alarmist", Some(policy)).await;
    let cw = Client::new(&cfg);
    let base = |name: &str| {
        cw.put_metric_alarm()
            .alarm_name(name)
            .namespace("App")
            .metric_name("Errors")
            .statistic(Statistic::Sum)
            .period(60)
            .evaluation_periods(1)
            .threshold(1.0)
            .comparison_operator(ComparisonOperator::GreaterThanThreshold)
    };
    base("allowed").alarm_actions("arn:aws:sns:us-east-1:123456789012:team-pager").send().await.unwrap();
    let err = base("denied")
        .alarm_actions("arn:aws:sns:us-east-1:123456789012:team-pager")
        .ok_actions("arn:aws:lambda:us-east-1:123456789012:function:other")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("AccessDenied"), "{err:?}");
    let err = cw
        .put_composite_alarm()
        .alarm_name("composite")
        .alarm_rule("ALARM(allowed)")
        .alarm_actions("arn:aws:sns:us-east-1:123456789012:elsewhere")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("AccessDenied"), "{err:?}");
    cw.put_composite_alarm()
        .alarm_name("composite")
        .alarm_rule("ALARM(allowed)")
        .alarm_actions("arn:aws:sns:us-east-1:123456789012:team-ops")
        .send()
        .await
        .unwrap();
}
