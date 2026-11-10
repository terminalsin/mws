//! EC2 Auto Scaling with Elastic Load Balancing through the official Rust
//! SDKs: ELB health checks replace failing instances once the grace period
//! is over, scale-in waits for the target group's deregistration delay,
//! attachments are checked when made, and metric math target tracking
//! creates metric math alarms.

use std::time::Duration;

use aws_sdk_autoscaling::error::ProvideErrorMetadata;
use aws_sdk_autoscaling::types::{
    CustomizedMetricSpecification, LaunchTemplateSpecification, TargetTrackingConfiguration,
    TargetTrackingMetricDataQuery, TargetTrackingMetricStat,
};
use aws_sdk_autoscaling::Client;
use aws_sdk_ec2::types::{Filter, InstanceStateName, InstanceType, RequestLaunchTemplateData};
use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, ProtocolEnum, TargetHealthStateEnum, TargetTypeEnum,
};
use mws_e2e::Mws;

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

async fn launch_template(ec2: &aws_sdk_ec2::Client) -> LaunchTemplateSpecification {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let lt = ec2
        .create_launch_template()
        .launch_template_name("served")
        .launch_template_data(
            RequestLaunchTemplateData::builder().image_id(&ami).instance_type(InstanceType::T3Micro).build(),
        )
        .send()
        .await
        .unwrap();
    let id = lt.launch_template().unwrap().launch_template_id().unwrap().to_string();
    LaunchTemplateSpecification::builder().launch_template_id(id).version("$Latest").build()
}

/// `(instance id, lifecycle state, health status)` of each group member.
async fn members(asg: &Client, name: &str) -> Vec<(String, String, String)> {
    let out = asg.describe_auto_scaling_groups().auto_scaling_group_names(name).send().await.unwrap();
    out.auto_scaling_groups()[0]
        .instances()
        .iter()
        .map(|i| {
            (
                i.instance_id().unwrap_or_default().to_string(),
                i.lifecycle_state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                i.health_status().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

async fn wait_for<F, Fut>(what: &str, secs: u64, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..secs * 4 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("never: {what}");
}

async fn ec2_state(ec2: &aws_sdk_ec2::Client, id: &str) -> Option<InstanceStateName> {
    let d = ec2
        .describe_instances()
        .filters(Filter::builder().name("instance-id").values(id).build())
        .send()
        .await
        .unwrap();
    d.reservations().first().and_then(|r| r.instances().first()).and_then(|i| i.state()).and_then(|s| s.name().cloned())
}

#[tokio::test]
async fn elb_health_checks_replace_instances_after_draining() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let asg = Client::new(&config);
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&config);
    let (vpc, subnets) = crate::elbv2::default_network(&mws).await;
    let lb = elb.create_load_balancer().name("front").set_subnets(Some(subnets.clone())).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    // Nothing listens on the instances, so their health checks fail.
    let tg = elb
        .create_target_group()
        .name("app")
        .protocol(ProtocolEnum::Http)
        .port(80)
        .vpc_id(&vpc)
        .target_type(TargetTypeEnum::Instance)
        .health_check_interval_seconds(5)
        .health_check_timeout_seconds(2)
        .unhealthy_threshold_count(2)
        .healthy_threshold_count(2)
        .send()
        .await
        .unwrap();
    let tg_arn = tg.target_groups()[0].target_group_arn().unwrap().to_string();
    elb.create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(Action::builder().r#type(ActionTypeEnum::Forward).target_group_arn(&tg_arn).build())
        .send()
        .await
        .unwrap();

    asg.create_auto_scaling_group()
        .auto_scaling_group_name("checked")
        .min_size(1)
        .max_size(2)
        .launch_template(launch_template(&ec2).await)
        .vpc_zone_identifier(&subnets[0])
        .target_group_arns(&tg_arn)
        .health_check_type("ELB")
        .health_check_grace_period(0)
        .send()
        .await
        .unwrap();
    let mut first = None;
    for _ in 0..160 {
        first = members(&asg, "checked").await.into_iter().find(|m| m.1 == "InService").map(|m| m.0);
        if first.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let first = first.expect("an InService instance");

    // The target fails its checks; Auto Scaling marks the instance
    // unhealthy and starts replacing it.
    wait_for("the target to turn unhealthy", 60, || {
        let elb = elb.clone();
        let (tg_arn, first) = (tg_arn.clone(), first.clone());
        async move {
            let h = elb.describe_target_health().target_group_arn(&tg_arn).send().await.unwrap();
            h.target_health_descriptions().iter().any(|d| {
                d.target().and_then(|t| t.id()) == Some(first.as_str())
                    && d.target_health().and_then(|t| t.state()) == Some(&TargetHealthStateEnum::Unhealthy)
            })
        }
    })
    .await;
    wait_for("the instance to be replaced", 30, || {
        let asg = asg.clone();
        let first = first.clone();
        async move {
            let m = members(&asg, "checked").await;
            m.iter().any(|m| m.0 == first && m.1 == "Terminating" && m.2 == "Unhealthy")
                && m.iter().any(|m| m.0 != first)
        }
    })
    .await;
    let acts = asg.describe_scaling_activities().auto_scaling_group_name("checked").send().await.unwrap();
    assert!(
        acts.activities().iter().any(|a| a.description() == Some(&format!("Terminating EC2 instance: {first}"))
            && a.cause()
                .unwrap_or_default()
                .contains("an instance was taken out of service in response to an ELB system health check failure.")),
        "{:#?}",
        acts.activities().iter().map(|a| a.cause()).collect::<Vec<_>>()
    );

    // Deregistration takes the target group's delay (300 s): the instance
    // stays Terminating and running until it is over.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(members(&asg, "checked").await.iter().any(|m| m.0 == first && m.1 == "Terminating"));
    assert_eq!(ec2_state(&ec2, &first).await, Some(InstanceStateName::Running));
    let h = elb.describe_target_health().target_group_arn(&tg_arn).send().await.unwrap();
    assert!(h.target_health_descriptions().iter().any(|d| d.target().and_then(|t| t.id()) == Some(first.as_str())
        && d.target_health().and_then(|t| t.state()) == Some(&TargetHealthStateEnum::Draining)));
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 301}"#)).await;
    assert_eq!(status, 200);
    wait_for("the drained instance to terminate", 40, || {
        let (asg, ec2, first) = (asg.clone(), ec2.clone(), first.clone());
        async move {
            !members(&asg, "checked").await.iter().any(|m| m.0 == first)
                && matches!(
                    ec2_state(&ec2, &first).await,
                    Some(InstanceStateName::ShuttingDown | InstanceStateName::Terminated)
                )
        }
    })
    .await;
}

#[tokio::test]
async fn attachments_are_checked() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let asg = Client::new(&config);
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&config);
    let (vpc, subnets) = crate::elbv2::default_network(&mws).await;
    let template = launch_template(&ec2).await;
    let tg = |name: &'static str, vpc: String, ty: TargetTypeEnum| {
        let elb = elb.clone();
        async move {
            let out = elb
                .create_target_group()
                .name(name)
                .protocol(ProtocolEnum::Http)
                .port(80)
                .vpc_id(vpc)
                .target_type(ty)
                .send()
                .await
                .unwrap();
            out.target_groups()[0].target_group_arn().unwrap().to_string()
        }
    };
    let good = tg("good", vpc.clone(), TargetTypeEnum::Instance).await;
    let ips = tg("ips", vpc.clone(), TargetTypeEnum::Ip).await;
    let other_vpc = ec2.create_vpc().cidr_block("10.9.0.0/16").send().await.unwrap();
    let other_vpc = other_vpc.vpc().unwrap().vpc_id().unwrap().to_string();
    let elsewhere = tg("elsewhere", other_vpc, TargetTypeEnum::Instance).await;
    let missing = good.replace("/good/", "/missing/");

    let tg_message = "Provided Target Groups may not be valid. Please ensure they exist and try again.";
    let err = asg
        .create_auto_scaling_group()
        .auto_scaling_group_name("checked")
        .min_size(0)
        .max_size(1)
        .launch_template(template.clone())
        .vpc_zone_identifier(&subnets[0])
        .target_group_arns(&missing)
        .send()
        .await
        .unwrap_err();
    assert_eq!((code(&err).as_str(), message(&err).as_str()), ("ValidationError", tg_message));
    assert!(asg
        .describe_auto_scaling_groups()
        .auto_scaling_group_names("checked")
        .send()
        .await
        .unwrap()
        .auto_scaling_groups()
        .is_empty());

    asg.create_auto_scaling_group()
        .auto_scaling_group_name("checked")
        .min_size(0)
        .max_size(1)
        .launch_template(template)
        .vpc_zone_identifier(&subnets[0])
        .target_group_arns(&good)
        .send()
        .await
        .unwrap();
    for bad in [&ips, &elsewhere, &missing] {
        let err = asg
            .attach_load_balancer_target_groups()
            .auto_scaling_group_name("checked")
            .target_group_arns(bad)
            .send()
            .await
            .unwrap_err();
        assert_eq!((code(&err).as_str(), message(&err).as_str()), ("ValidationError", tg_message), "{bad}");
    }
    let err = asg
        .attach_load_balancers()
        .auto_scaling_group_name("checked")
        .load_balancer_names("ghost")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ValidationError");
    assert_eq!(message(&err), "Provided Load Balancers may not be valid. Please ensure they exist and try again.");
    let tgs = asg.describe_load_balancer_target_groups().auto_scaling_group_name("checked").send().await.unwrap();
    assert_eq!(tgs.load_balancer_target_groups().len(), 1);
}

#[tokio::test]
async fn metric_math_target_tracking_scales() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let asg = Client::new(&config);
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let cw = aws_sdk_cloudwatch::Client::new(&config);
    asg.create_auto_scaling_group()
        .auto_scaling_group_name("workers")
        .min_size(1)
        .max_size(10)
        .launch_template(launch_template(&ec2).await)
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap();
    // Backlog per instance: queue depth over the group's in-service
    // instances, as AWS's own example does.
    let backlog = |id: &str, ns: &str, name: &str, dim: Option<(&str, &str)>| {
        let mut metric = aws_sdk_autoscaling::types::Metric::builder().namespace(ns).metric_name(name);
        if let Some((n, v)) = dim {
            metric = metric.dimensions(aws_sdk_autoscaling::types::MetricDimension::builder().name(n).value(v).build());
        }
        TargetTrackingMetricDataQuery::builder()
            .id(id)
            .metric_stat(TargetTrackingMetricStat::builder().metric(metric.build()).stat("Sum").build())
            .return_data(false)
            .build()
    };
    let spec = CustomizedMetricSpecification::builder()
        .metrics(backlog("m1", "App", "QueueDepth", None))
        .metrics(TargetTrackingMetricDataQuery::builder().id("e1").expression("m1 / 2").return_data(true).build());
    let out = asg
        .put_scaling_policy()
        .auto_scaling_group_name("workers")
        .policy_name("backlog")
        .policy_type("TargetTrackingScaling")
        .target_tracking_configuration(
            TargetTrackingConfiguration::builder()
                .customized_metric_specification(spec.build())
                .target_value(10.0)
                .disable_scale_in(true)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(out.alarms().len(), 1);
    let alarms = cw.describe_alarms().alarm_name_prefix("TargetTracking-workers-").send().await.unwrap();
    let high = &alarms.metric_alarms()[0];
    assert_eq!(high.metrics().len(), 2);
    assert_eq!(high.metric_name(), None);
    assert_eq!(high.threshold(), Some(10.0));
    let described = asg.describe_policies().auto_scaling_group_name("workers").send().await.unwrap();
    let cms = described.scaling_policies()[0]
        .target_tracking_configuration()
        .and_then(|c| c.customized_metric_specification())
        .unwrap();
    assert_eq!(cms.metrics().len(), 2);

    // Two queries cannot both return data.
    let err = asg
        .put_scaling_policy()
        .auto_scaling_group_name("workers")
        .policy_name("bad")
        .policy_type("TargetTrackingScaling")
        .target_tracking_configuration(
            TargetTrackingConfiguration::builder()
                .customized_metric_specification(
                    CustomizedMetricSpecification::builder()
                        .metrics(
                            TargetTrackingMetricDataQuery::builder().id("a").expression("1").return_data(true).build(),
                        )
                        .metrics(
                            TargetTrackingMetricDataQuery::builder().id("b").expression("2").return_data(true).build(),
                        )
                        .build(),
                )
                .target_value(10.0)
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ValidationError");

    // A backlog of 100 (50 per the expression) breaches the target of 10:
    // the alarm fires and the group scales out.
    let now = std::time::SystemTime::now();
    for minutes in 0..4u64 {
        cw.put_metric_data()
            .namespace("App")
            .metric_data(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("QueueDepth")
                    .value(100.0)
                    .timestamp(aws_sdk_cloudwatch::primitives::DateTime::from(now - Duration::from_secs(minutes * 60)))
                    .build(),
            )
            .send()
            .await
            .unwrap();
    }
    wait_for("the math alarm to scale the group out", 60, || {
        let asg = asg.clone();
        async move {
            let g = asg.describe_auto_scaling_groups().auto_scaling_group_names("workers").send().await.unwrap();
            g.auto_scaling_groups()[0].desired_capacity().unwrap_or_default() > 1
        }
    })
    .await;
}
