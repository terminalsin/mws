//! CloudWatch through the official Rust SDK (Smithy RPC v2 CBOR, with
//! gzip-compressed PutMetricData): metrics and statistics, GetMetricData
//! with metric math and SEARCH, alarms that really evaluate and act (SNS to
//! SQS, Lambda, EventBridge), composite alarms, mute rules, log alarms,
//! Logs metric filters publishing metrics, Contributor Insights over real
//! log events, dashboards, anomaly detectors, metric streams, tags, OTel
//! enrichment, resource metrics configurations, the dataset KMS key and
//! widget images.

use std::io::Write;
use std::time::Duration;

use aws_sdk_cloudwatch::error::ProvideErrorMetadata;
use aws_sdk_cloudwatch::primitives::DateTime;
use aws_sdk_cloudwatch::types::{
    ComparisonOperator, Dimension, DimensionFilter, ManagedRule, Metric, MetricDataQuery, MetricDatum, MetricStat,
    MetricStreamFilter, MetricStreamOutputFormat, MuteTargets, OTelEnrichmentMetricSelector, ResourceMetricSelection,
    Rule, Schedule, ScheduleConfiguration, ScheduledQueryConfiguration, SingleMetricAnomalyDetector, StandardUnit,
    StateValue, Statistic, StatisticSet, Tag,
};
use aws_sdk_cloudwatch::Client;
use mws_e2e::{user_with_policy, Mws};

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message<E: ProvideErrorMetadata>(e: &E) -> String {
    e.message().unwrap_or_default().to_string()
}

fn dim(name: &str, value: &str) -> Dimension {
    Dimension::builder().name(name).value(value).build()
}

fn tag(k: &str, v: &str) -> Tag {
    Tag::builder().key(k).value(v).build()
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn at(secs: i64) -> DateTime {
    DateTime::from_secs(secs)
}

fn datum(name: &str, value: f64, t: i64) -> MetricDatum {
    MetricDatum::builder()
        .metric_name(name)
        .dimensions(dim("Service", "checkout"))
        .value(value)
        .unit(StandardUnit::Count)
        .timestamp(at(t))
        .build()
}

fn stat_query(id: &str, ns: &str, name: &str, dims: &[Dimension], stat: &str, period: i32) -> MetricDataQuery {
    let mut metric = Metric::builder().namespace(ns).metric_name(name);
    for d in dims {
        metric = metric.dimensions(d.clone());
    }
    MetricDataQuery::builder()
        .id(id)
        .metric_stat(MetricStat::builder().metric(metric.build()).period(period).stat(stat).build())
        .build()
}

async fn wait_for_state(cw: &Client, alarm: &str, state: StateValue, composite: bool) {
    for _ in 0..150 {
        let mut req = cw.describe_alarms().alarm_names(alarm);
        if composite {
            req = req.alarm_types(aws_sdk_cloudwatch::types::AlarmType::CompositeAlarm);
        }
        let out = req.send().await.unwrap();
        let current = if composite {
            out.composite_alarms().first().and_then(|a| a.state_value().cloned())
        } else {
            out.metric_alarms().first().and_then(|a| a.state_value().cloned())
        };
        if current.as_ref() == Some(&state) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("alarm {alarm} never reached {state:?}");
}

#[tokio::test]
async fn metric_data_statistics_and_listing() {
    let mws = Mws::start().await;
    // Compress every PutMetricData, as SDKs do for large batches.
    let conf = aws_sdk_cloudwatch::config::Builder::from(&mws.root_sdk_config().await)
        .request_min_compression_size_bytes(1)
        .build();
    let cw = Client::from_conf(conf);
    let t = (now_secs() / 60) * 60 - 300;
    cw.put_metric_data()
        .namespace("Shop")
        .metric_data(datum("Orders", 10.0, t))
        .metric_data(datum("Orders", 20.0, t + 10))
        .metric_data(
            MetricDatum::builder()
                .metric_name("Orders")
                .dimensions(dim("Service", "checkout"))
                .values(1.0)
                .values(2.0)
                .counts(3.0)
                .counts(1.0)
                .unit(StandardUnit::Count)
                .timestamp(at(t + 60))
                .build(),
        )
        .metric_data(
            MetricDatum::builder()
                .metric_name("Latency")
                .dimensions(dim("Service", "checkout"))
                .statistic_values(
                    StatisticSet::builder().sample_count(4.0).sum(400.0).minimum(50.0).maximum(200.0).build(),
                )
                .unit(StandardUnit::Milliseconds)
                .timestamp(at(t))
                .build(),
        )
        .send()
        .await
        .unwrap();

    let stats = cw
        .get_metric_statistics()
        .namespace("Shop")
        .metric_name("Orders")
        .dimensions(dim("Service", "checkout"))
        .start_time(at(t - 60))
        .end_time(at(t + 120))
        .period(60)
        .statistics(Statistic::Sum)
        .statistics(Statistic::SampleCount)
        .statistics(Statistic::Maximum)
        .send()
        .await
        .unwrap();
    assert_eq!(stats.label(), Some("Orders"));
    let mut points = stats.datapoints().to_vec();
    points.sort_by_key(|p| p.timestamp().unwrap().secs());
    assert_eq!(points.len(), 2, "{points:?}");
    assert_eq!(points[0].sum(), Some(30.0));
    assert_eq!(points[0].sample_count(), Some(2.0));
    assert_eq!(points[0].maximum(), Some(20.0));
    assert_eq!(points[0].unit(), Some(&StandardUnit::Count));
    // Values/Counts: 1 three times and 2 once.
    assert_eq!(points[1].sum(), Some(5.0));
    assert_eq!(points[1].sample_count(), Some(4.0));
    let p50 = cw
        .get_metric_statistics()
        .namespace("Shop")
        .metric_name("Orders")
        .dimensions(dim("Service", "checkout"))
        .start_time(at(t + 60))
        .end_time(at(t + 120))
        .period(60)
        .extended_statistics("p50")
        .send()
        .await
        .unwrap();
    assert_eq!(p50.datapoints()[0].extended_statistics().unwrap().get("p50"), Some(&1.0));
    let err = cw
        .get_metric_statistics()
        .namespace("Shop")
        .metric_name("Orders")
        .start_time(at(t))
        .end_time(at(t + 60))
        .period(60)
        .statistics(Statistic::Sum)
        .extended_statistics("p50")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidParameterCombination");

    let err = cw
        .get_metric_statistics()
        .namespace("Shop")
        .metric_name("Orders")
        .start_time(at(t - 86400 * 2))
        .end_time(at(t))
        .period(60)
        .statistics(Statistic::Sum)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidParameterCombination");

    let listed = cw.list_metrics().namespace("Shop").send().await.unwrap();
    let mut names: Vec<&str> = listed.metrics().iter().filter_map(|m| m.metric_name()).collect();
    names.sort();
    assert_eq!(names, ["Latency", "Orders"]);
    let filtered = cw
        .list_metrics()
        .namespace("Shop")
        .dimensions(DimensionFilter::builder().name("Service").value("checkout").build())
        .metric_name("Latency")
        .send()
        .await
        .unwrap();
    assert_eq!(filtered.metrics().len(), 1);

    // Validation follows the model and AWS's wording.
    let err = cw.put_metric_data().namespace("AWS/EC2").metric_data(datum("X", 1.0, t)).send().await.unwrap_err();
    let err = err.into_service_error();
    assert_eq!(code(&err), "InvalidParameterValue");
    assert!(message(&err).contains("AWS/"), "{}", message(&err));
}

#[tokio::test]
async fn get_metric_data_runs_metric_math_and_search() {
    let mws = Mws::start().await;
    let cw = client(&mws).await;
    let t = (now_secs() / 60) * 60 - 600;
    for (i, svc) in ["a", "b"].iter().enumerate() {
        let mut req = cw.put_metric_data().namespace("App");
        for k in 0..5 {
            req = req.metric_data(
                MetricDatum::builder()
                    .metric_name("Errors")
                    .dimensions(dim("Service", svc))
                    .value((k + 1) as f64 * (i + 1) as f64)
                    .timestamp(at(t + k * 60))
                    .build(),
            );
        }
        req.send().await.unwrap();
    }
    let out = cw
        .get_metric_data()
        .start_time(at(t))
        .end_time(at(t + 300))
        .metric_data_queries({
            let mut q = stat_query("a", "App", "Errors", &[dim("Service", "a")], "Sum", 60);
            q.return_data = Some(false);
            q
        })
        .metric_data_queries({
            let mut q = stat_query("b", "App", "Errors", &[dim("Service", "b")], "Sum", 60);
            q.return_data = Some(false);
            q
        })
        .metric_data_queries(MetricDataQuery::builder().id("total").expression("a + b").label("Total").build())
        .metric_data_queries(
            MetricDataQuery::builder()
                .id("all")
                .expression("SEARCH('{App,Service} MetricName=\"Errors\"', 'Sum', 60)")
                .build(),
        )
        .metric_data_queries(MetricDataQuery::builder().id("peak").expression("MAX(total)").build())
        .send()
        .await
        .unwrap();
    let results = out.metric_data_results();
    let total = results.iter().find(|r| r.id() == Some("total")).unwrap();
    assert_eq!(total.label(), Some("Total"));
    assert_eq!(total.status_code().map(|s| s.as_str()), Some("Complete"));
    let mut pairs: Vec<(i64, f64)> =
        total.timestamps().iter().map(|t| t.secs()).zip(total.values().iter().copied()).collect();
    pairs.sort_by_key(|p| p.0);
    assert_eq!(pairs.iter().map(|p| p.1).collect::<Vec<_>>(), [3.0, 6.0, 9.0, 12.0, 15.0]);
    let searched: Vec<_> = results.iter().filter(|r| r.id().is_some_and(|i| i.starts_with("all"))).collect();
    assert_eq!(searched.len(), 2, "{results:?}");
    let peak = results.iter().find(|r| r.id() == Some("peak")).unwrap();
    assert!(peak.values().iter().all(|v| *v == 15.0), "{peak:?}");

    let err = cw
        .get_metric_data()
        .start_time(at(t))
        .end_time(at(t + 300))
        .metric_data_queries(MetricDataQuery::builder().id("x").expression("nope(").build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");
}

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const RECORDER: &str = r#"
import json, os

def handler(event, context):
    with open(os.environ["OUT"], "a") as f:
        f.write(json.dumps(event) + "\n")
    return {}
"#;

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        for (name, body) in files {
            z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            z.write_all(body.as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

async fn wait_for_lines(path: &std::path::Path, n: usize) -> Vec<serde_json::Value> {
    for _ in 0..300 {
        if let Ok(text) = std::fs::read_to_string(path) {
            let lines: Vec<serde_json::Value> =
                text.lines().filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
            if lines.len() >= n {
                return lines;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{} never got {n} lines", path.display());
}

#[tokio::test]
async fn metric_alarms_evaluate_and_notify_sns_and_lambda() {
    use aws_sdk_lambda::primitives::Blob;
    use aws_sdk_lambda::types::{Environment, FunctionCode, Runtime};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let cw = Client::new(&cfg);

    // SNS topic (default policy) delivering to an SQS queue.
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let queue = sqs.create_queue().queue_name("alarms").send().await.unwrap().queue_url().unwrap().to_string();
    let queue_arn = sqs
        .get_queue_attributes()
        .queue_url(&queue)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .unwrap()[&aws_sdk_sqs::types::QueueAttributeName::QueueArn]
        .clone();
    let sns = aws_sdk_sns::Client::new(&cfg);
    let topic = sns.create_topic().name("alarms").send().await.unwrap().topic_arn().unwrap().to_string();
    let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":queue_arn,"Condition":{"ArnEquals":{"aws:SourceArn":topic}}}]});
    sqs.set_queue_attributes()
        .queue_url(&queue)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(&queue_arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();

    // A Lambda function CloudWatch alarms may invoke.
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role = iam.create_role().role_name("alarm-fn").assume_role_policy_document(TRUST).send().await.unwrap();
    let out = std::env::temp_dir().join(format!("mws-cw-{}-{}.jsonl", std::process::id(), now_secs()));
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let f = lambda
        .create_function()
        .function_name("on-alarm")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .environment(Environment::builder().variables("OUT", out.to_string_lossy()).build())
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", RECORDER)]))).build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, "on-alarm").await;
    let fn_arn = f.function_arn().unwrap().to_string();
    let alarm_arn = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:high-errors";
    lambda
        .add_permission()
        .function_name("on-alarm")
        .statement_id("alarms")
        .action("lambda:InvokeFunction")
        .principal("lambda.alarms.cloudwatch.amazonaws.com")
        .source_arn(alarm_arn)
        .send()
        .await
        .unwrap();

    // Validation.
    let err = cw
        .put_metric_alarm()
        .alarm_name("bad")
        .namespace("Shop")
        .metric_name("Errors")
        .statistic(Statistic::Sum)
        .period(300)
        .evaluation_periods(300)
        .threshold(1.0)
        .comparison_operator(ComparisonOperator::GreaterThanThreshold)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");
    assert_eq!(
        message(&err),
        "Metrics cannot be checked across more than a day (EvaluationPeriods * Period must be <= 86400)"
    );

    cw.put_metric_alarm()
        .alarm_name("high-errors")
        .alarm_description("Too many errors")
        .namespace("Shop")
        .metric_name("Errors")
        .dimensions(dim("Service", "checkout"))
        .statistic(Statistic::Sum)
        .period(60)
        .evaluation_periods(1)
        .threshold(5.0)
        .comparison_operator(ComparisonOperator::GreaterThanThreshold)
        .treat_missing_data("notBreaching")
        .alarm_actions(&topic)
        .alarm_actions(&fn_arn)
        .ok_actions(&topic)
        .tags(tag("team", "checkout"))
        .send()
        .await
        .unwrap();
    // Missing data is not breaching: OK.
    wait_for_state(&cw, "high-errors", StateValue::Ok, false).await;
    let ok = sqs.receive_message().queue_url(&queue).wait_time_seconds(5).send().await.unwrap();
    let ok_msg: serde_json::Value = serde_json::from_str(ok.messages()[0].body().unwrap()).unwrap();
    assert_eq!(ok_msg["NewStateValue"], "OK");
    assert_eq!(ok_msg["OldStateValue"], "INSUFFICIENT_DATA");
    sqs.delete_message()
        .queue_url(&queue)
        .receipt_handle(ok.messages()[0].receipt_handle().unwrap())
        .send()
        .await
        .unwrap();

    let t = now_secs();
    cw.put_metric_data()
        .namespace("Shop")
        .metric_data(
            MetricDatum::builder()
                .metric_name("Errors")
                .dimensions(dim("Service", "checkout"))
                .value(9.0)
                .timestamp(at(t))
                .build(),
        )
        .send()
        .await
        .unwrap();
    // Alarms evaluate completed periods, about once a minute: let the
    // minute of the datapoint end.
    crate::cloudwatch_anomaly::finish_minute(&mws, t).await;
    wait_for_state(&cw, "high-errors", StateValue::Alarm, false).await;

    let msg = sqs.receive_message().queue_url(&queue).wait_time_seconds(5).send().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(msg.messages()[0].body().unwrap()).unwrap();
    assert_eq!(body["AlarmName"], "high-errors");
    assert_eq!(body["AlarmDescription"], "Too many errors");
    assert_eq!(body["NewStateValue"], "ALARM");
    assert_eq!(body["OldStateValue"], "OK");
    assert_eq!(body["AlarmArn"], alarm_arn);
    assert_eq!(body["Trigger"]["MetricName"], "Errors");
    assert_eq!(body["Trigger"]["Threshold"], 5.0);
    assert!(
        body["NewStateReason"].as_str().unwrap().starts_with("Threshold Crossed: 1 out of the last 1 datapoint [9.0 ("),
        "{body}"
    );
    assert!(body["NewStateReason"].as_str().unwrap().contains("was greater than the threshold (5.0)"), "{body}");

    let events = wait_for_lines(&out, 1).await;
    let _ = std::fs::remove_file(&out);
    assert_eq!(events[0]["source"], "aws.cloudwatch");
    assert_eq!(events[0]["alarmArn"], alarm_arn);
    assert_eq!(events[0]["alarmData"]["state"]["value"], "ALARM");
    assert_eq!(events[0]["alarmData"]["previousState"]["value"], "OK");

    let alarms = cw.describe_alarms().alarm_name_prefix("high").send().await.unwrap();
    let a = &alarms.metric_alarms()[0];
    assert_eq!(a.alarm_arn(), Some(alarm_arn));
    assert_eq!(a.state_value(), Some(&StateValue::Alarm));
    assert_eq!(a.alarm_actions().len(), 2);
    let for_metric = cw
        .describe_alarms_for_metric()
        .namespace("Shop")
        .metric_name("Errors")
        .dimensions(dim("Service", "checkout"))
        .send()
        .await
        .unwrap();
    assert_eq!(for_metric.metric_alarms().len(), 1);

    let history = cw.describe_alarm_history().alarm_name("high-errors").send().await.unwrap();
    let kinds: Vec<&str> =
        history.alarm_history_items().iter().filter_map(|h| h.history_item_type()).map(|t| t.as_str()).collect();
    assert!(kinds.contains(&"ConfigurationUpdate"), "{kinds:?}");
    assert!(kinds.contains(&"StateUpdate"), "{kinds:?}");
    assert!(kinds.contains(&"Action"), "{kinds:?}");

    // Disabled actions: state changes but nothing is sent.
    cw.disable_alarm_actions().alarm_names("high-errors").send().await.unwrap();
    cw.set_alarm_state()
        .alarm_name("high-errors")
        .state_value(StateValue::Ok)
        .state_reason("testing")
        .send()
        .await
        .unwrap();
    let a = cw.describe_alarms().alarm_names("high-errors").send().await.unwrap();
    assert_eq!(a.metric_alarms()[0].actions_enabled(), Some(false));
    cw.enable_alarm_actions().alarm_names("high-errors").send().await.unwrap();
    let err = cw
        .set_alarm_state()
        .alarm_name("high-errors")
        .state_value(StateValue::Alarm)
        .state_reason("x")
        .state_reason_data("{not json")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidFormat");

    let contributors = cw.describe_alarm_contributors().alarm_name("high-errors").send().await.unwrap();
    assert!(contributors.alarm_contributors().is_empty());

    cw.delete_alarms().alarm_names("high-errors").send().await.unwrap();
    let err = cw.delete_alarms().alarm_names("high-errors").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceNotFound");
}

#[tokio::test]
async fn composite_alarms_and_mute_rules() {
    let mws = Mws::start().await;
    let cw = client(&mws).await;
    for name in ["cpu", "mem"] {
        cw.put_metric_alarm()
            .alarm_name(name)
            .namespace("Host")
            .metric_name(name)
            .statistic(Statistic::Average)
            .period(60)
            .evaluation_periods(1)
            .threshold(90.0)
            .comparison_operator(ComparisonOperator::GreaterThanOrEqualToThreshold)
            .send()
            .await
            .unwrap();
    }
    let err = cw
        .put_composite_alarm()
        .alarm_name("host")
        .alarm_rule("ALARM(cpu) AND ALARM(disk)")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");
    cw.put_composite_alarm().alarm_name("host").alarm_rule("ALARM(cpu) AND ALARM(\"mem\")").send().await.unwrap();
    cw.set_alarm_state().alarm_name("cpu").state_value(StateValue::Alarm).state_reason("x").send().await.unwrap();
    cw.set_alarm_state().alarm_name("mem").state_value(StateValue::Alarm).state_reason("x").send().await.unwrap();
    wait_for_state(&cw, "host", StateValue::Alarm, true).await;
    let children = cw.describe_alarms().children_of_alarm_name("host").send().await.unwrap();
    assert_eq!(children.metric_alarms().len(), 2);
    let err = cw.delete_alarms().alarm_names("cpu").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceConflict");

    cw.put_alarm_mute_rule()
        .name("maintenance")
        .description("weekly window")
        .rule(
            Rule::builder()
                .schedule(Schedule::builder().expression("cron(0 2 ? * SUN *)").duration("PT2H").build())
                .build(),
        )
        .mute_targets(MuteTargets::builder().alarm_names("cpu").build())
        .send()
        .await
        .unwrap();
    let rule = cw.get_alarm_mute_rule().alarm_mute_rule_name("maintenance").send().await.unwrap();
    assert_eq!(rule.name(), Some("maintenance"));
    assert_eq!(rule.mute_type(), Some("RECURRING"));
    assert!(rule.alarm_mute_rule_arn().unwrap().ends_with(":alarm-mute-rule:maintenance"));
    let listed = cw.list_alarm_mute_rules().send().await.unwrap();
    assert_eq!(listed.alarm_mute_rule_summaries().len(), 1);
    cw.delete_alarm_mute_rule().alarm_mute_rule_name("maintenance").send().await.unwrap();
    let err =
        cw.get_alarm_mute_rule().alarm_mute_rule_name("maintenance").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceNotFoundException");
}

#[tokio::test]
async fn logs_metric_filters_publish_metrics_and_feed_alarms_and_insights() {
    use aws_sdk_cloudwatchlogs::types::{InputLogEvent, MetricTransformation};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let cw = Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    logs.create_log_group().log_group_name("/app").send().await.unwrap();
    logs.create_log_stream().log_group_name("/app").log_stream_name("s").send().await.unwrap();
    logs.put_metric_filter()
        .log_group_name("/app")
        .filter_name("latency")
        .filter_pattern("{ $.latency = * }")
        .metric_transformations(
            MetricTransformation::builder()
                .metric_namespace("App")
                .metric_name("Latency")
                .metric_value("$.latency")
                .dimensions("Route", "$.route")
                .unit(aws_sdk_cloudwatchlogs::types::StandardUnit::Milliseconds)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let lines = [("/a", 10), ("/a", 30), ("/b", 5), ("/a", 20)];
    let mut req = logs.put_log_events().log_group_name("/app").log_stream_name("s");
    for (i, (route, latency)) in lines.iter().enumerate() {
        req = req.log_events(
            InputLogEvent::builder()
                .timestamp(now_ms + i as i64)
                .message(serde_json::json!({"route": route, "latency": latency}).to_string())
                .build()
                .unwrap(),
        );
    }
    req.send().await.unwrap();

    let t = now_ms / 1000;
    let stats = cw
        .get_metric_statistics()
        .namespace("App")
        .metric_name("Latency")
        .dimensions(dim("Route", "/a"))
        .start_time(at(t - 120))
        .end_time(at(t + 120))
        .period(300)
        .statistics(Statistic::Sum)
        .statistics(Statistic::SampleCount)
        .send()
        .await
        .unwrap();
    let p = &stats.datapoints()[0];
    assert_eq!(p.sum(), Some(60.0));
    assert_eq!(p.sample_count(), Some(3.0));
    assert_eq!(p.unit(), Some(&StandardUnit::Milliseconds));

    // Contributor Insights over the same events.
    let rule = serde_json::json!({
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": ["/app"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.route"], "ValueOf": "$.latency", "Filters": [{"Match": "$.latency", "GreaterThan": 0}]},
        "AggregateOn": "Sum"
    });
    cw.put_insight_rule()
        .rule_name("by-route")
        .rule_definition(rule.to_string())
        .tags(tag("team", "web"))
        .send()
        .await
        .unwrap();
    let err =
        cw.put_insight_rule().rule_name("bad").rule_definition("{}").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "InvalidParameterValue");
    let described = cw.describe_insight_rules().send().await.unwrap();
    assert_eq!(described.insight_rules().len(), 1);
    assert_eq!(described.insight_rules()[0].state(), Some("ENABLED"));
    let report = cw
        .get_insight_rule_report()
        .rule_name("by-route")
        .start_time(at(t - 300))
        .end_time(at(t + 300))
        .period(60)
        .metrics("UniqueContributors")
        .metrics("Sum")
        .send()
        .await
        .unwrap();
    assert_eq!(report.key_labels(), ["$.route"]);
    assert_eq!(report.aggregation_statistic(), Some("Sum"));
    assert_eq!(report.approximate_unique_count(), Some(2));
    let top = &report.contributors()[0];
    assert_eq!(top.keys(), ["/a"]);
    assert_eq!(top.approximate_aggregate_value(), Some(60.0));
    assert!(!report.metric_datapoints().is_empty());

    // INSIGHT_RULE_METRIC in metric math.
    let gmd = cw
        .get_metric_data()
        .start_time(at(t - 300))
        .end_time(at(t + 300))
        .metric_data_queries(
            MetricDataQuery::builder()
                .id("u")
                .expression("INSIGHT_RULE_METRIC('by-route', 'UniqueContributors')")
                .period(600)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(gmd.metric_data_results()[0].values(), [2.0]);

    let disabled = cw.disable_insight_rules().rule_names("by-route").rule_names("nope").send().await.unwrap();
    assert_eq!(disabled.failures().len(), 1);
    assert_eq!(disabled.failures()[0].failure_resource(), Some("nope"));
    cw.enable_insight_rules().rule_names("by-route").send().await.unwrap();

    let resource = "arn:aws:dynamodb:us-east-1:123456789012:table/orders";
    let put = cw
        .put_managed_insight_rules()
        .managed_rules(
            ManagedRule::builder().template_name("DynamoDBContributorInsights-PKC").resource_arn(resource).build(),
        )
        .send()
        .await
        .unwrap();
    assert!(put.failures().is_empty());
    let managed = cw.list_managed_insight_rules().resource_arn(resource).send().await.unwrap();
    assert_eq!(managed.managed_rules().len(), 1);
    assert_eq!(managed.managed_rules()[0].template_name(), Some("DynamoDBContributorInsights-PKC"));

    let deleted = cw.delete_insight_rules().rule_names("by-route").send().await.unwrap();
    assert!(deleted.failures().is_empty());

    // A log alarm counting the events on a schedule.
    cw.put_log_alarm()
        .alarm_name("slow")
        .scheduled_query_configuration(
            ScheduledQueryConfiguration::builder()
                .query_string("fields @message | filter latency > 15")
                .log_group_identifiers("/app")
                .scheduled_query_role_arn("arn:aws:iam::123456789012:role/query")
                .aggregation_expression("count(*)")
                .schedule_configuration(
                    ScheduleConfiguration::builder()
                        .schedule_expression("rate(1 minute)")
                        .start_time_offset(900)
                        .build(),
                )
                .build(),
        )
        .query_results_to_evaluate(1)
        .query_results_to_alarm(1)
        .threshold(1.0)
        .comparison_operator(ComparisonOperator::GreaterThanThreshold)
        .send()
        .await
        .unwrap();
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 61}"#)).await;
    assert_eq!(status, 200);
    let mut state = None;
    for _ in 0..150 {
        let out = cw
            .describe_alarms()
            .alarm_names("slow")
            .alarm_types(aws_sdk_cloudwatch::types::AlarmType::LogAlarm)
            .send()
            .await
            .unwrap();
        state = out.log_alarms().first().and_then(|a| a.state_value().cloned());
        if state == Some(StateValue::Alarm) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(state, Some(StateValue::Alarm));
}

#[tokio::test]
async fn dashboards_detectors_streams_and_tags() {
    let mws = Mws::start().await;
    let cw = client(&mws).await;
    let body = r#"{"widgets":[{"type":"metric","x":0,"y":0,"width":6,"height":6,"properties":{"metrics":[["Shop","Orders"]],"region":"us-east-1","period":300}}]}"#;
    let put = cw.put_dashboard().dashboard_name("main").dashboard_body(body).send().await.unwrap();
    assert!(put.dashboard_validation_messages().is_empty());
    let err =
        cw.put_dashboard().dashboard_name("bad").dashboard_body("{nope").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "InvalidParameterInput");
    let got = cw.get_dashboard().dashboard_name("main").send().await.unwrap();
    assert_eq!(got.dashboard_body(), Some(body));
    let dashboard_arn = got.dashboard_arn().unwrap().to_string();
    assert_eq!(dashboard_arn, "arn:aws:cloudwatch::123456789012:dashboard/main");
    let listed = cw.list_dashboards().send().await.unwrap();
    assert_eq!(listed.dashboard_entries().len(), 1);
    assert!(listed.dashboard_entries()[0].size().unwrap() > 0);

    // Tags on dashboards.
    cw.tag_resource()
        .resource_arn(&dashboard_arn)
        .tags(tag("env", "prod"))
        .tags(tag("team", "web"))
        .send()
        .await
        .unwrap();
    cw.untag_resource().resource_arn(&dashboard_arn).tag_keys("team").send().await.unwrap();
    let tags = cw.list_tags_for_resource().resource_arn(&dashboard_arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert_eq!(tags.tags()[0].key(), Some("env"));
    let err = cw
        .list_tags_for_resource()
        .resource_arn("arn:aws:cloudwatch:us-east-1:123456789012:alarm:nope")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ResourceNotFoundException");
    cw.delete_dashboards().dashboard_names("main").send().await.unwrap();
    let err = cw.get_dashboard().dashboard_name("main").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceNotFound");

    // Anomaly detectors.
    let detector = SingleMetricAnomalyDetector::builder()
        .namespace("Shop")
        .metric_name("Orders")
        .dimensions(dim("Service", "checkout"))
        .stat("Average")
        .build();
    cw.put_anomaly_detector().single_metric_anomaly_detector(detector.clone()).send().await.unwrap();
    let described = cw.describe_anomaly_detectors().namespace("Shop").send().await.unwrap();
    assert_eq!(described.anomaly_detectors().len(), 1);
    assert_eq!(described.anomaly_detectors()[0].state_value().map(|s| s.as_str()), Some("PENDING_TRAINING"));
    cw.delete_anomaly_detector().single_metric_anomaly_detector(detector.clone()).send().await.unwrap();
    let err = cw
        .delete_anomaly_detector()
        .single_metric_anomaly_detector(detector)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ResourceNotFoundException");

    // Metric streams.
    let stream = cw
        .put_metric_stream()
        .name("to-firehose")
        .firehose_arn("arn:aws:firehose:us-east-1:123456789012:deliverystream/metrics")
        .role_arn("arn:aws:iam::123456789012:role/streams")
        .output_format(MetricStreamOutputFormat::Json)
        .include_filters(MetricStreamFilter::builder().namespace("Shop").build())
        .send()
        .await
        .unwrap();
    let stream_arn = stream.arn().unwrap().to_string();
    assert_eq!(stream_arn, "arn:aws:cloudwatch:us-east-1:123456789012:metric-stream/to-firehose");
    let err = cw
        .put_metric_stream()
        .name("bad")
        .firehose_arn("nope")
        .role_arn("arn:aws:iam::123456789012:role/streams")
        .output_format(MetricStreamOutputFormat::Json)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidParameterValue");
    cw.stop_metric_streams().names("to-firehose").send().await.unwrap();
    let got = cw.get_metric_stream().name("to-firehose").send().await.unwrap();
    assert_eq!(got.state(), Some("stopped"));
    assert_eq!(got.include_filters().len(), 1);
    cw.start_metric_streams().names("to-firehose").send().await.unwrap();
    let listed = cw.list_metric_streams().send().await.unwrap();
    assert_eq!(listed.entries()[0].state(), Some("running"));
    cw.tag_resource().resource_arn(&stream_arn).tags(tag("k", "v")).send().await.unwrap();
    cw.delete_metric_stream().name("to-firehose").send().await.unwrap();
    let err = cw.get_metric_stream().name("to-firehose").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceNotFoundException");
}

#[tokio::test]
async fn otel_enrichment_resource_metrics_datasets_and_widgets() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let cw = Client::new(&cfg);

    assert_eq!(cw.get_o_tel_enrichment().send().await.unwrap().status().map(|s| s.as_str()), Some("Stopped"));
    cw.start_o_tel_enrichment()
        .include_filters(OTelEnrichmentMetricSelector::builder().namespace("AWS/EC2").build())
        .send()
        .await
        .unwrap();
    let got = cw.get_o_tel_enrichment().send().await.unwrap();
    assert_eq!(got.status().map(|s| s.as_str()), Some("Running"));
    assert_eq!(got.include_filters().len(), 1);
    cw.update_o_tel_enrichment()
        .include_filters(OTelEnrichmentMetricSelector::builder().namespace("AWS/Lambda").metric_names("Errors").build())
        .send()
        .await
        .unwrap();
    assert_eq!(cw.get_o_tel_enrichment().send().await.unwrap().include_filters()[0].namespace(), Some("AWS/Lambda"));
    cw.stop_o_tel_enrichment().send().await.unwrap();
    assert_eq!(cw.get_o_tel_enrichment().send().await.unwrap().status().map(|s| s.as_str()), Some("Stopped"));

    let table = "arn:aws:dynamodb:us-east-1:123456789012:table/orders";
    let created = cw
        .create_resource_metrics_configuration()
        .resource_arn(table)
        .metric_selections(ResourceMetricSelection::builder().include_metrics("ConsumedReadCapacityUnits").build())
        .send()
        .await
        .unwrap();
    assert_eq!(created.resource_metrics_configuration().unwrap().resource_arn(), Some(table));
    let err =
        cw.create_resource_metrics_configuration().resource_arn(table).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ConflictException");
    cw.update_resource_metrics_configuration()
        .resource_arn(table)
        .metric_selections(ResourceMetricSelection::builder().include_metrics("ThrottledRequests").build())
        .send()
        .await
        .unwrap();
    let got = cw.get_resource_metrics_configuration().resource_arn(table).send().await.unwrap();
    assert_eq!(
        got.resource_metrics_configuration().unwrap().metric_selections()[0].include_metrics(),
        ["ThrottledRequests"]
    );
    cw.delete_resource_metrics_configuration().resource_arn(table).send().await.unwrap();
    let err =
        cw.get_resource_metrics_configuration().resource_arn(table).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceNotFoundException");

    // The default dataset and its KMS key.
    let ds = cw.get_dataset().dataset_identifier("default").send().await.unwrap();
    assert_eq!(ds.dataset_id(), Some("default"));
    assert_eq!(ds.arn(), Some("arn:aws:cloudwatch:us-east-1:123456789012:dataset/default"));
    assert!(ds.kms_key_arn().is_none());
    let kms = aws_sdk_kms::Client::new(&cfg);
    let key = kms.create_key().send().await.unwrap().key_metadata().unwrap().arn().unwrap().to_string();
    cw.associate_dataset_kms_key().dataset_identifier("default").kms_key_arn(&key).send().await.unwrap();
    assert_eq!(cw.get_dataset().dataset_identifier("default").send().await.unwrap().kms_key_arn(), Some(key.as_str()));
    let missing = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000";
    let err =
        cw.associate_dataset_kms_key().dataset_identifier("default").kms_key_arn(missing).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "KmsKeyNotFoundException");
    cw.disassociate_dataset_kms_key().dataset_identifier("default").send().await.unwrap();
    assert!(cw.get_dataset().dataset_identifier("default").send().await.unwrap().kms_key_arn().is_none());
    // The model's pattern admits only the default dataset.
    let err = cw.get_dataset().dataset_identifier("other").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ValidationError");

    // Widget images are real PNGs.
    let t = now_secs();
    cw.put_metric_data()
        .namespace("Shop")
        .metric_data(datum("Orders", 3.0, t - 120))
        .metric_data(datum("Orders", 7.0, t - 60))
        .send()
        .await
        .unwrap();
    let widget = r#"{"metrics":[["Shop","Orders","Service","checkout"]],"start":"-PT1H","width":320,"height":200,"stat":"Sum","period":60}"#;
    let image = cw.get_metric_widget_image().metric_widget(widget).send().await.unwrap();
    let png = image.metric_widget_image().unwrap().as_ref();
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), 320);
    assert_eq!(u32::from_be_bytes(png[20..24].try_into().unwrap()), 200);
}

#[tokio::test]
async fn iam_policies_gate_cloudwatch_actions() {
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudwatch:PutMetricData","cloudwatch:ListMetrics"],"Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "metrics-writer", Some(policy)).await;
    let cw = Client::new(&cfg);
    cw.put_metric_data().namespace("Shop").metric_data(datum("Orders", 1.0, now_secs())).send().await.unwrap();
    cw.list_metrics().send().await.unwrap();
    let err = cw.describe_alarms().send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "AccessDenied");
    let err = cw.put_dashboard().dashboard_name("d").dashboard_body("{\"widgets\":[]}").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "AccessDenied");
}

#[tokio::test]
async fn metric_streams_deliver_json_records_to_firehose() {
    use aws_sdk_firehose::types::{BufferingHints, ExtendedS3DestinationConfiguration};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let cw = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let trust = |svc: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{svc}"}},"Action":"sts:AssumeRole"}}]}}"#
        )
    };
    let allow = |actions: &str| {
        format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":"*"}}]}}"#)
    };
    let delivery = iam
        .create_role()
        .role_name("delivery")
        .assume_role_policy_document(trust("firehose.amazonaws.com"))
        .send()
        .await
        .unwrap();
    iam.put_role_policy()
        .role_name("delivery")
        .policy_name("p")
        .policy_document(allow(r#"["s3:*"]"#))
        .send()
        .await
        .unwrap();
    let streams = iam
        .create_role()
        .role_name("metric-streams")
        .assume_role_policy_document(trust("streams.metrics.cloudwatch.amazonaws.com"))
        .send()
        .await
        .unwrap();
    iam.put_role_policy()
        .role_name("metric-streams")
        .policy_name("p")
        .policy_document(allow(r#"["firehose:PutRecord","firehose:PutRecordBatch"]"#))
        .send()
        .await
        .unwrap();
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("metrics").send().await.unwrap();
    let fh = aws_sdk_firehose::Client::new(&cfg);
    fh.create_delivery_stream()
        .delivery_stream_name("metrics")
        .extended_s3_destination_configuration(
            ExtendedS3DestinationConfiguration::builder()
                .role_arn(delivery.role().unwrap().arn())
                .bucket_arn("arn:aws:s3:::metrics")
                .buffering_hints(BufferingHints::builder().interval_in_seconds(0).size_in_mbs(1).build())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    for _ in 0..100 {
        let d = fh.describe_delivery_stream().delivery_stream_name("metrics").send().await.unwrap();
        if d.delivery_stream_description().unwrap().delivery_stream_status().as_str() == "ACTIVE" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    cw.put_metric_stream()
        .name("all")
        .firehose_arn("arn:aws:firehose:us-east-1:123456789012:deliverystream/metrics")
        .role_arn(streams.role().unwrap().arn())
        .output_format(MetricStreamOutputFormat::Json)
        .include_filters(MetricStreamFilter::builder().namespace("Shop").build())
        .send()
        .await
        .unwrap();
    cw.put_metric_data()
        .namespace("Shop")
        .metric_data(datum("Orders", 4.0, now_secs()))
        .metric_data(datum("Orders", 6.0, now_secs()))
        .send()
        .await
        .unwrap();
    cw.put_metric_data().namespace("Other").metric_data(datum("Ignored", 1.0, now_secs())).send().await.unwrap();
    // The minute ends; the next minute's tick streams it.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 61}"#)).await;
    assert_eq!(status, 200);
    cw.list_metric_streams().send().await.unwrap();
    let mut body = String::new();
    for _ in 0..100 {
        let _ = fh.list_delivery_streams().send().await;
        let listed = s3.list_objects_v2().bucket("metrics").send().await.unwrap();
        if let Some(o) = listed.contents().first() {
            let got = s3.get_object().bucket("metrics").key(o.key().unwrap()).send().await.unwrap();
            body = String::from_utf8(got.body.collect().await.unwrap().into_bytes().to_vec()).unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let lines: Vec<serde_json::Value> = body.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 1, "{body}");
    let r = &lines[0];
    assert_eq!(r["metric_stream_name"], "all");
    assert_eq!(r["namespace"], "Shop");
    assert_eq!(r["metric_name"], "Orders");
    assert_eq!(r["dimensions"]["Service"], "checkout");
    assert_eq!(r["value"]["sum"], 10.0);
    assert_eq!(r["value"]["count"], 2.0);
    assert_eq!(r["unit"], "Count");
}
