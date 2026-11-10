//! What EC2 reports on its own, through the official Rust SDK (metadata
//! backend): `EC2 Instance State-change Notification` events on the
//! default bus, `AWS/EC2` metrics on the emulated clock, and instance
//! transitions that take time, so code has to wait as it does on AWS.

use std::time::{Duration, SystemTime};

use aws_sdk_cloudwatch::types::{ComparisonOperator, Dimension, Metric, MetricDataQuery, MetricStat, StateValue};
use aws_sdk_ec2::client::Waiters;
use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{InstanceStateName, RunInstancesMonitoringEnabled};
use aws_sdk_eventbridge::types::Target;
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

async fn start() -> Mws {
    Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await
}

async fn image(ec2: &aws_sdk_ec2::Client) -> String {
    let images = ec2.describe_images().owners("amazon").send().await.unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

async fn launch(ec2: &aws_sdk_ec2::Client, detailed: bool) -> String {
    let image = image(ec2).await;
    let out = ec2
        .run_instances()
        .image_id(image)
        .min_count(1)
        .max_count(1)
        .monitoring(RunInstancesMonitoringEnabled::builder().enabled(detailed).build())
        .send()
        .await
        .unwrap();
    out.instances()[0].instance_id().unwrap().to_string()
}

async fn state(ec2: &aws_sdk_ec2::Client, id: &str) -> InstanceStateName {
    let d = ec2.describe_instances().instance_ids(id).send().await.unwrap();
    d.reservations()[0].instances()[0].state().unwrap().name().unwrap().clone()
}

async fn wait_for(ec2: &aws_sdk_ec2::Client, id: &str, want: InstanceStateName) {
    for _ in 0..100 {
        if state(ec2, id).await == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{id} never became {want:?}");
}

#[tokio::test]
async fn transitions_take_time_and_reach_eventbridge() {
    let mws = start().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);

    let url = sqs.create_queue().queue_name("ec2-states").send().await.unwrap().queue_url.unwrap();
    let queue_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:ec2-states");
    let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},
        "Action":"sqs:SendMessage","Resource":queue_arn}]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    eb.put_rule()
        .name("instance-states")
        .event_pattern(r#"{"source":["aws.ec2"],"detail-type":["EC2 Instance State-change Notification"]}"#)
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("instance-states")
        .targets(Target::builder().id("q").arn(&queue_arn).build().unwrap())
        .send()
        .await
        .unwrap();

    let id = launch(&ec2, false).await;
    assert_eq!(state(&ec2, &id).await, InstanceStateName::Pending);
    // A pending instance cannot be stopped yet.
    let err = ec2.stop_instances().instance_ids(&id).send().await.unwrap_err();
    assert_eq!(err.code(), Some("IncorrectInstanceState"));
    assert_eq!(
        err.message(),
        Some(format!("This instance '{id}' is not in a state from which it can be stopped.").as_str())
    );
    wait_for(&ec2, &id, InstanceStateName::Running).await;

    let out = ec2.stop_instances().instance_ids(&id).send().await.unwrap();
    assert_eq!(out.stopping_instances()[0].current_state().unwrap().name(), Some(&InstanceStateName::Stopping));
    // Starting a stopping instance fails until it has stopped.
    let err = ec2.start_instances().instance_ids(&id).send().await.unwrap_err();
    assert_eq!(err.code(), Some("IncorrectInstanceState"));
    assert_eq!(
        err.message(),
        Some(format!("The instance '{id}' is not in a state from which it can be started.").as_str())
    );
    // The SDK's waiter sees it stop.
    ec2.wait_until_instance_stopped().instance_ids(&id).wait(Duration::from_secs(60)).await.unwrap();
    ec2.start_instances().instance_ids(&id).send().await.unwrap();
    wait_for(&ec2, &id, InstanceStateName::Running).await;
    ec2.terminate_instances().instance_ids(&id).send().await.unwrap();
    assert_eq!(state(&ec2, &id).await, InstanceStateName::ShuttingDown);
    wait_for(&ec2, &id, InstanceStateName::Terminated).await;

    let want = ["pending", "running", "stopping", "stopped", "pending", "running", "shutting-down", "terminated"];
    let mut seen: Vec<serde_json::Value> = Vec::new();
    for _ in 0..100 {
        let r = sqs.receive_message().queue_url(&url).max_number_of_messages(10).send().await.unwrap();
        for m in r.messages() {
            seen.push(serde_json::from_str(m.body().unwrap()).unwrap());
            sqs.delete_message().queue_url(&url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
        if seen.len() >= want.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // SQS does not keep order; event times do.
    seen.sort_by(|a, b| a["time"].as_str().cmp(&b["time"].as_str()));
    let states: Vec<&str> = seen.iter().map(|e| e["detail"]["state"].as_str().unwrap()).collect();
    let mut sorted_states = states.clone();
    sorted_states.sort();
    let mut sorted_want = want.to_vec();
    sorted_want.sort();
    assert_eq!(sorted_states, sorted_want, "{seen:#?}");
    for e in &seen {
        assert_eq!(e["source"], "aws.ec2");
        assert_eq!(e["detail-type"], "EC2 Instance State-change Notification");
        assert_eq!(e["account"], ACCOUNT);
        assert_eq!(e["region"], "us-east-1");
        assert_eq!(e["detail"]["instance-id"], id.as_str());
        assert_eq!(e["resources"][0], format!("arn:aws:ec2:us-east-1:{ACCOUNT}:instance/{id}"));
    }
}

fn dim(name: &str, value: &str) -> Dimension {
    Dimension::builder().name(name).value(value).build()
}

/// The data points of an `AWS/EC2` metric over the last two hours (and the
/// next hour, since the emulated clock runs ahead), polled until there are
/// some.
async fn points(
    cw: &aws_sdk_cloudwatch::Client,
    name: &str,
    dims: &[Dimension],
    period: i32,
    stat: &str,
) -> Vec<(i64, f64)> {
    for _ in 0..100 {
        // Datapoints are aligned to the start time, so start on an hour
        // boundary (as AWS recommends) to get period-aligned timestamps.
        let secs = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(secs - secs % 3600);
        let mut metric = Metric::builder().namespace("AWS/EC2").metric_name(name);
        for d in dims {
            metric = metric.dimensions(d.clone());
        }
        let out = cw
            .get_metric_data()
            .metric_data_queries(
                MetricDataQuery::builder()
                    .id("m")
                    .metric_stat(MetricStat::builder().metric(metric.build()).period(period).stat(stat).build())
                    .build(),
            )
            .start_time((now - Duration::from_secs(7200)).into())
            .end_time((now + Duration::from_secs(7200)).into())
            .send()
            .await
            .unwrap();
        let r = &out.metric_data_results()[0];
        let got: Vec<(i64, f64)> = r.timestamps().iter().map(|t| t.secs()).zip(r.values().iter().copied()).collect();
        if !got.is_empty() {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Vec::new()
}

#[tokio::test]
async fn metrics_follow_the_emulated_clock_and_drive_alarms() {
    let mws = start().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    let asg = aws_sdk_autoscaling::Client::new(&cfg);

    // A basic-monitoring instance with its CPU set high, and a detailed
    // one left idle.
    let busy = launch(&ec2, false).await;
    let idle = launch(&ec2, true).await;
    wait_for(&ec2, &busy, InstanceStateName::Running).await;
    wait_for(&ec2, &idle, InstanceStateName::Running).await;
    let (status, body) =
        mws.control("POST", &format!("/_aws/ec2/metrics/{busy}"), Some(r#"{"CPUUtilization": 85}"#)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["metrics"]["CPUUtilization"], 85.0);
    let (status, _) = mws.control("POST", "/_aws/ec2/metrics/i-0123456789abcdef0", Some("{}")).await;
    assert_eq!(status, 404);
    let (status, _) = mws.control("POST", &format!("/_aws/ec2/metrics/{busy}"), Some(r#"{"Bogus": 1}"#)).await;
    assert_eq!(status, 400);

    // An Auto Scaling group's instances report under its name too.
    let template = ec2
        .create_launch_template()
        .launch_template_name("web")
        .launch_template_data(
            aws_sdk_ec2::types::RequestLaunchTemplateData::builder().image_id(image(&ec2).await).build(),
        )
        .send()
        .await
        .unwrap();
    let template_id = template.launch_template().unwrap().launch_template_id().unwrap().to_string();
    asg.create_auto_scaling_group()
        .auto_scaling_group_name("web")
        .min_size(1)
        .max_size(1)
        .launch_template(
            aws_sdk_autoscaling::types::LaunchTemplateSpecification::builder()
                .launch_template_id(&template_id)
                .version("$Latest")
                .build(),
        )
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap();
    let mut member = None;
    for _ in 0..200 {
        let g = asg.describe_auto_scaling_groups().auto_scaling_group_names("web").send().await.unwrap();
        member = g.auto_scaling_groups()[0]
            .instances()
            .iter()
            .find(|i| i.lifecycle_state().map(|s| s.as_str()) == Some("InService"))
            .and_then(|i| i.instance_id().map(str::to_string));
        if member.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let member = member.expect("the group's instance never went InService");
    wait_for(&ec2, &member, InstanceStateName::Running).await;

    // Nothing is published before a period ends.
    cw.put_metric_alarm()
        .alarm_name("hot")
        .namespace("AWS/EC2")
        .metric_name("CPUUtilization")
        .dimensions(dim("InstanceId", &busy))
        .statistic(aws_sdk_cloudwatch::types::Statistic::Average)
        .period(300)
        .evaluation_periods(1)
        .threshold(70.0)
        .comparison_operator(ComparisonOperator::GreaterThanThreshold)
        .send()
        .await
        .unwrap();

    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 900}"#)).await;
    assert_eq!(status, 200);
    // Any signed call tells EC2 the time.
    ec2.describe_instances().send().await.unwrap();

    let busy_cpu = points(&cw, "CPUUtilization", &[dim("InstanceId", &busy)], 300, "Average").await;
    assert!(!busy_cpu.is_empty(), "no CPUUtilization for {busy}");
    assert!(busy_cpu.iter().all(|(t, v)| *v == 85.0 && t % 300 == 0), "{busy_cpu:?}");
    // Basic monitoring: one point per 5 minutes.
    let per_minute = points(&cw, "CPUUtilization", &[dim("InstanceId", &busy)], 60, "SampleCount").await;
    assert!(per_minute.iter().all(|(t, _)| t % 300 == 0), "{per_minute:?}");

    // Detailed monitoring: every minute, and by image and type too.
    let idle_cpu = points(&cw, "CPUUtilization", &[dim("InstanceId", &idle)], 60, "Average").await;
    assert!(idle_cpu.len() >= 10, "{idle_cpu:?}");
    assert!(idle_cpu.iter().all(|(_, v)| (0.5..=3.0).contains(v)), "{idle_cpu:?}");
    let d = ec2.describe_instances().instance_ids(&idle).send().await.unwrap();
    let ty = d.reservations()[0].instances()[0].instance_type().unwrap().as_str().to_string();
    let by_type_any = points(&cw, "CPUUtilization", &[dim("InstanceType", &ty)], 60, "Average").await;
    assert!(!by_type_any.is_empty());

    // Network and status checks (every minute even with basic monitoring).
    let net = points(&cw, "NetworkIn", &[dim("InstanceId", &busy)], 300, "Sum").await;
    assert!(net.iter().all(|(_, v)| *v == 0.0) && !net.is_empty(), "{net:?}");
    let checks = points(&cw, "StatusCheckFailed", &[dim("InstanceId", &busy)], 60, "Maximum").await;
    assert!(checks.len() >= 10 && checks.iter().all(|(_, v)| *v == 0.0), "{checks:?}");

    // The group aggregate target tracking reads.
    let group = points(&cw, "CPUUtilization", &[dim("AutoScalingGroupName", "web")], 300, "Average").await;
    assert!(!group.is_empty(), "no CPUUtilization for the group");
    let listed = cw
        .list_metrics()
        .namespace("AWS/EC2")
        .metric_name("CPUUtilization")
        .dimensions(aws_sdk_cloudwatch::types::DimensionFilter::builder().name("AutoScalingGroupName").build())
        .send()
        .await
        .unwrap();
    assert_eq!(listed.metrics().len(), 1);

    // The alarm on the busy instance fires.
    for _ in 0..100 {
        let a = cw.describe_alarms().alarm_names("hot").send().await.unwrap();
        if a.metric_alarms()[0].state_value() == Some(&StateValue::Alarm) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("the CPU alarm never fired");
}
