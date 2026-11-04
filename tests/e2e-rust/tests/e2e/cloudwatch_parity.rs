//! CloudWatch behaviours from the parity audit, through the official Rust
//! SDK: when alarms evaluate (a state set with `SetAlarmState` holds until
//! the next period), `EvaluateLowSampleCountPercentile`, the children and
//! parents of composite alarms, which alarms `DescribeAlarmHistory` and
//! `DescribeAlarmsForMetric` return, partial `DeleteAlarms` and
//! `DeleteDashboards`, `ListMetrics` across accounts, and the statistics
//! rules for statistic sets, negative values and retention.

use std::time::Duration;

use aws_sdk_cloudwatch::error::ProvideErrorMetadata;
use aws_sdk_cloudwatch::primitives::DateTime;
use aws_sdk_cloudwatch::types::{
    AlarmType, ComparisonOperator, Dimension, HistoryItemType, Metric, MetricDataQuery, MetricDatum, MetricStat,
    StateValue, Statistic, StatisticSet,
};
use aws_sdk_cloudwatch::Client;
use mws_e2e::Mws;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

async fn state_of(cw: &Client, alarm: &str) -> Option<StateValue> {
    let out = cw.describe_alarms().alarm_names(alarm).send().await.unwrap();
    out.metric_alarms().first().and_then(|a| a.state_value().cloned())
}

async fn wait_for(cw: &Client, alarm: &str, state: StateValue) {
    for _ in 0..150 {
        if state_of(cw, alarm).await.as_ref() == Some(&state) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("alarm {alarm} never reached {state:?}");
}

async fn simple_alarm(cw: &Client, name: &str, metric: &str) {
    cw.put_metric_alarm()
        .alarm_name(name)
        .namespace("Parity")
        .metric_name(metric)
        .statistic(Statistic::Maximum)
        .period(60)
        .evaluation_periods(1)
        .threshold(10.0)
        .comparison_operator(ComparisonOperator::GreaterThanThreshold)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn set_alarm_state_holds_until_the_next_evaluation() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    simple_alarm(&cw, "manual", "Latency").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(state_of(&cw, "manual").await, Some(StateValue::InsufficientData));

    cw.set_alarm_state()
        .alarm_name("manual")
        .state_value(StateValue::Alarm)
        .state_reason("testing notifications")
        .send()
        .await
        .unwrap();
    // CloudWatch evaluates a 60-second alarm once a minute: the state set
    // by hand is still there seconds later.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let out = cw.describe_alarms().alarm_names("manual").send().await.unwrap();
    let a = &out.metric_alarms()[0];
    assert_eq!(a.state_value(), Some(&StateValue::Alarm));
    assert_eq!(a.state_reason(), Some("testing notifications"));

    // At the next period the alarm evaluates its (missing) data again.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 61}"#)).await;
    assert_eq!(status, 200);
    wait_for(&cw, "manual", StateValue::InsufficientData).await;

    // New data is evaluated straight away.
    cw.put_metric_data()
        .namespace("Parity")
        .metric_data(MetricDatum::builder().metric_name("Latency").value(50.0).build())
        .send()
        .await
        .unwrap();
    wait_for(&cw, "manual", StateValue::Alarm).await;
}

#[tokio::test]
async fn low_sample_count_percentiles_can_be_ignored() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    // Five samples: p90 needs 10 / (1 - 0.9) = 100 to be significant.
    cw.put_metric_data()
        .namespace("Parity")
        .metric_data(
            MetricDatum::builder()
                .metric_name("Duration")
                .set_values(Some(vec![100.0, 200.0, 300.0, 400.0, 500.0]))
                .build(),
        )
        .send()
        .await
        .unwrap();
    for (name, mode) in [("p90-evaluate", "evaluate"), ("p90-ignore", "ignore")] {
        cw.put_metric_alarm()
            .alarm_name(name)
            .namespace("Parity")
            .metric_name("Duration")
            .extended_statistic("p90")
            .period(60)
            .evaluation_periods(1)
            .threshold(250.0)
            .comparison_operator(ComparisonOperator::GreaterThanThreshold)
            .evaluate_low_sample_count_percentile(mode)
            .send()
            .await
            .unwrap();
    }
    wait_for(&cw, "p90-evaluate", StateValue::Alarm).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(state_of(&cw, "p90-ignore").await, Some(StateValue::InsufficientData));
}

#[tokio::test]
async fn composite_family_history_and_alarms_for_metric() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    simple_alarm(&cw, "cpu", "Cpu").await;
    cw.put_composite_alarm().alarm_name("inner").alarm_rule("ALARM(cpu)").send().await.unwrap();
    cw.put_composite_alarm().alarm_name("outer").alarm_rule("ALARM(cpu) OR ALARM(inner)").send().await.unwrap();
    // A metric math alarm that reads the same metric.
    let m1 = MetricDataQuery::builder()
        .id("m1")
        .return_data(false)
        .metric_stat(
            MetricStat::builder()
                .metric(Metric::builder().namespace("Parity").metric_name("Cpu").build())
                .period(60)
                .stat("Maximum")
                .build(),
        )
        .build();
    let e1 = MetricDataQuery::builder().id("e1").expression("m1 * 2").build();
    cw.put_metric_alarm()
        .alarm_name("cpu-math")
        .metrics(m1)
        .metrics(e1)
        .evaluation_periods(1)
        .threshold(10.0)
        .comparison_operator(ComparisonOperator::GreaterThanThreshold)
        .send()
        .await
        .unwrap();

    // Children are metric and composite alarms; parents are composites.
    let children = cw.describe_alarms().children_of_alarm_name("outer").send().await.unwrap();
    assert_eq!(children.metric_alarms().len(), 1);
    assert_eq!(children.composite_alarms().len(), 1);
    assert_eq!(children.composite_alarms()[0].alarm_name(), Some("inner"));
    let parents = cw.describe_alarms().parents_of_alarm_name("cpu").send().await.unwrap();
    let mut names: Vec<&str> = parents.composite_alarms().iter().filter_map(|a| a.alarm_name()).collect();
    names.sort();
    assert_eq!(names, ["inner", "outer"]);
    let err = cw
        .describe_alarms()
        .parents_of_alarm_name("cpu")
        .alarm_types(AlarmType::CompositeAlarm)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");

    // History defaults to metric alarms.
    let history = cw.describe_alarm_history().send().await.unwrap();
    assert!(!history.alarm_history_items().is_empty());
    assert!(history.alarm_history_items().iter().all(|h| h.alarm_type() == Some(&AlarmType::MetricAlarm)));
    let composite = cw
        .describe_alarm_history()
        .alarm_types(AlarmType::CompositeAlarm)
        .history_item_type(HistoryItemType::ConfigurationUpdate)
        .send()
        .await
        .unwrap();
    assert_eq!(composite.alarm_history_items().len(), 2);

    // Alarms for a metric leave out metric math alarms.
    let for_metric = cw.describe_alarms_for_metric().namespace("Parity").metric_name("Cpu").send().await.unwrap();
    let names: Vec<&str> = for_metric.metric_alarms().iter().filter_map(|a| a.alarm_name()).collect();
    assert_eq!(names, ["cpu"]);
}

#[tokio::test]
async fn partial_deletes_delete_what_exists() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    simple_alarm(&cw, "a", "A").await;
    simple_alarm(&cw, "b", "B").await;
    let err = cw.delete_alarms().alarm_names("a").alarm_names("nope").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceNotFound");
    let left = cw.describe_alarms().send().await.unwrap();
    let names: Vec<&str> = left.metric_alarms().iter().filter_map(|a| a.alarm_name()).collect();
    assert_eq!(names, ["b"]);

    cw.put_composite_alarm().alarm_name("c1").alarm_rule("ALARM(b)").send().await.unwrap();
    cw.put_composite_alarm().alarm_name("c2").alarm_rule("ALARM(b)").send().await.unwrap();
    let err = cw.delete_alarms().alarm_names("c1").alarm_names("c2").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ValidationError");
    let composites = cw.describe_alarms().alarm_types(AlarmType::CompositeAlarm).send().await.unwrap();
    assert_eq!(composites.composite_alarms().len(), 2);

    let body = r#"{"widgets":[]}"#;
    cw.put_dashboard().dashboard_name("one").dashboard_body(body).send().await.unwrap();
    let err = cw
        .delete_dashboards()
        .dashboard_names("one")
        .dashboard_names("two")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ResourceNotFound");
    let dashboards = cw.list_dashboards().send().await.unwrap();
    assert!(dashboards.dashboard_entries().is_empty());
}

#[tokio::test]
async fn statistics_follow_cloudwatch_rules() {
    let mws = Mws::start().await;
    let cw = Client::new(&mws.root_sdk_config().await);
    let now = now_secs();
    let minute = now - now.rem_euclid(60);
    let dim = Dimension::builder().name("Host").value("h1").build();
    cw.put_metric_data()
        .namespace("Parity")
        .metric_data(
            // A statistic set of equal values still has percentiles.
            MetricDatum::builder()
                .metric_name("Set")
                .dimensions(dim.clone())
                .statistic_values(StatisticSet::builder().sample_count(4.0).sum(20.0).minimum(5.0).maximum(5.0).build())
                .timestamp(DateTime::from_secs(minute))
                .build(),
        )
        .metric_data(
            // Percentiles are not available over negative values.
            MetricDatum::builder()
                .metric_name("Signed")
                .dimensions(dim.clone())
                .set_values(Some(vec![-1.0, 2.0, 3.0]))
                .timestamp(DateTime::from_secs(minute))
                .build(),
        )
        .metric_data(
            // High-resolution data from four hours ago.
            MetricDatum::builder()
                .metric_name("Old")
                .dimensions(dim.clone())
                .value(7.0)
                .storage_resolution(1)
                .timestamp(DateTime::from_secs(now - 4 * 3600))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let p50 = |name: &'static str| {
        cw.get_metric_statistics()
            .namespace("Parity")
            .metric_name(name)
            .dimensions(dim.clone())
            .start_time(DateTime::from_secs(minute))
            .end_time(DateTime::from_secs(minute + 60))
            .period(60)
            .extended_statistics("p50")
            .send()
    };
    let set = p50("Set").await.unwrap();
    assert_eq!(set.datapoints()[0].extended_statistics().unwrap()["p50"], 5.0);
    let signed = p50("Signed").await.unwrap();
    assert!(signed.datapoints().iter().all(|d| d.extended_statistics().is_none_or(|e| e.is_empty())));

    // Sub-minute periods only reach three hours back; a minute still works.
    let old = |period: i32| {
        cw.get_metric_statistics()
            .namespace("Parity")
            .metric_name("Old")
            .dimensions(dim.clone())
            .start_time(DateTime::from_secs(now - 5 * 3600))
            .end_time(DateTime::from_secs(now - 3 * 3600))
            .period(period)
            .statistics(Statistic::Maximum)
            .send()
    };
    assert!(old(10).await.unwrap().datapoints().is_empty());
    assert_eq!(old(60).await.unwrap().datapoints().len(), 1);

    // Without cross-account observability another account lists nothing.
    let mine = cw.list_metrics().namespace("Parity").send().await.unwrap();
    assert_eq!(mine.metrics().len(), 3);
    let theirs = cw.list_metrics().namespace("Parity").owning_account("210987654321").send().await.unwrap();
    assert!(theirs.metrics().is_empty());
}
