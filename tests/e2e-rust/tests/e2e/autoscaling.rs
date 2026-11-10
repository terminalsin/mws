//! EC2 Auto Scaling through the official Rust SDK: groups launch real MWS
//! EC2 instances (metadata backend), replace unhealthy ones, run lifecycle
//! hooks, scale on policies and alarms, follow schedules, refresh
//! instances, keep warm pools and register instances with load balancers.

use std::time::Duration;

use aws_sdk_autoscaling::error::ProvideErrorMetadata;
use aws_sdk_autoscaling::primitives::DateTime;
use aws_sdk_autoscaling::types::{
    AutoScalingGroup, DesiredConfiguration, Filter as AsgFilter, LaunchTemplateSpecification,
    LifecycleHookSpecification, MetricDimension, PredefinedMetricSpecification, PredictiveScalingConfiguration,
    PredictiveScalingMetricSpecification, PredictiveScalingPredefinedMetricPair, RefreshPreferences,
    ScheduledUpdateGroupActionRequest, StepAdjustment, Tag, TargetTrackingConfiguration, TrafficSourceIdentifier,
};
use aws_sdk_autoscaling::Client;
use aws_sdk_ec2::types::{Filter, InstanceStateName, InstanceType, RequestLaunchTemplateData};
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

struct Env {
    mws: Mws,
    asg: Client,
    ec2: aws_sdk_ec2::Client,
    template_id: String,
}

async fn alpine_ami(ec2: &aws_sdk_ec2::Client) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

async fn env() -> Env {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let asg = Client::new(&config);
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let ami = alpine_ami(&ec2).await;
    let lt = ec2
        .create_launch_template()
        .launch_template_name("web")
        .launch_template_data(
            RequestLaunchTemplateData::builder().image_id(&ami).instance_type(InstanceType::T3Micro).build(),
        )
        .send()
        .await
        .unwrap();
    let template_id = lt.launch_template().unwrap().launch_template_id().unwrap().to_string();
    Env { mws, asg, ec2, template_id }
}

fn template(id: &str, version: &str) -> LaunchTemplateSpecification {
    LaunchTemplateSpecification::builder().launch_template_id(id).version(version).build()
}

async fn group(asg: &Client, name: &str) -> AutoScalingGroup {
    let out = asg.describe_auto_scaling_groups().auto_scaling_group_names(name).send().await.unwrap();
    out.auto_scaling_groups().first().cloned().unwrap_or_else(|| panic!("no group {name}"))
}

/// Poll the group until `ok` holds (the reconciliation loop runs every
/// second).
async fn wait_group(asg: &Client, name: &str, what: &str, ok: impl Fn(&AutoScalingGroup) -> bool) -> AutoScalingGroup {
    let mut last = None;
    for _ in 0..160 {
        let g = group(asg, name).await;
        if ok(&g) {
            return g;
        }
        last = Some(g);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let acts = asg.describe_scaling_activities().auto_scaling_group_name(name).send().await.unwrap();
    let acts: Vec<_> = acts
        .activities()
        .iter()
        .map(|a| {
            (
                a.status_code().map(|s| s.as_str().to_string()),
                a.description().map(String::from),
                a.cause().map(String::from),
            )
        })
        .collect();
    let last = last.map(|g| {
        g.instances()
            .iter()
            .map(|i| (i.instance_id().map(String::from), i.lifecycle_state().map(|s| s.as_str().to_string())))
            .collect::<Vec<_>>()
    });
    panic!("group {name} never reached: {what}; instances {last:?}; activities {acts:#?}");
}

fn in_service(g: &AutoScalingGroup) -> usize {
    g.instances().iter().filter(|i| i.lifecycle_state().map(|s| s.as_str()) == Some("InService")).count()
}

fn ids(g: &AutoScalingGroup) -> Vec<String> {
    g.instances().iter().filter_map(|i| i.instance_id().map(String::from)).collect()
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

async fn wait_ec2(ec2: &aws_sdk_ec2::Client, id: &str, want: InstanceStateName) {
    for _ in 0..120 {
        if ec2_state(ec2, id).await.as_ref() == Some(&want) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("instance {id} never reached {want:?}");
}

#[tokio::test]
async fn groups_launch_replace_and_terminate_instances() {
    let Env { mws: _mws, asg, ec2, template_id } = env().await;

    // Validation in Auto Scaling's words.
    let err = asg
        .create_auto_scaling_group()
        .auto_scaling_group_name("web")
        .min_size(3)
        .max_size(2)
        .launch_template(template(&template_id, "$Latest"))
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ValidationError");
    assert_eq!(message(&err), "Max bound, 2, must be greater than or equal to min bound, 3");
    let err = asg
        .create_auto_scaling_group()
        .auto_scaling_group_name("web")
        .min_size(1)
        .max_size(4)
        .desired_capacity(5)
        .launch_template(template(&template_id, "$Latest"))
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err), "Desired capacity:5 must be between the specified min size:1 and max size:4");
    let err = asg
        .create_auto_scaling_group()
        .auto_scaling_group_name("web")
        .min_size(1)
        .max_size(4)
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(&err),
        "Valid requests must contain either LaunchTemplate, LaunchConfigurationName, InstanceId or MixedInstancesPolicy parameter."
    );
    let err = asg
        .create_auto_scaling_group()
        .auto_scaling_group_name("web")
        .min_size(1)
        .max_size(4)
        .launch_template(template(&template_id, "$Latest"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err), "At least one Availability Zone or VPC Subnet is required.");
    let err = asg
        .create_auto_scaling_group()
        .auto_scaling_group_name("web")
        .min_size(1)
        .max_size(4)
        .launch_template(template("lt-0123456789abcdef0", "$Latest"))
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap_err();
    assert!(message(&err).starts_with("You must use a valid fully-formed launch template."), "{}", message(&err));

    asg.create_auto_scaling_group()
        .auto_scaling_group_name("web")
        .min_size(1)
        .max_size(4)
        .desired_capacity(2)
        .launch_template(template(&template_id, "$Latest"))
        .availability_zones("us-east-1a")
        .availability_zones("us-east-1b")
        .tags(Tag::builder().key("Team").value("web").propagate_at_launch(true).build())
        .tags(Tag::builder().key("Internal").value("x").propagate_at_launch(false).build())
        .send()
        .await
        .unwrap();
    let err = asg
        .create_auto_scaling_group()
        .auto_scaling_group_name("web")
        .min_size(1)
        .max_size(4)
        .launch_template(template(&template_id, "$Latest"))
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "AlreadyExists");
    assert_eq!(
        message(&err),
        "AutoScalingGroup by this name already exists - A group with the name web already exists"
    );

    let g = wait_group(&asg, "web", "2 InService", |g| in_service(g) == 2).await;
    assert!(g
        .auto_scaling_group_arn()
        .unwrap()
        .starts_with(&format!("arn:aws:autoscaling:us-east-1:{ACCOUNT}:autoScalingGroup:")));
    assert_eq!(g.health_check_type(), Some("EC2"));
    assert_eq!(g.default_cooldown(), Some(300));
    assert_eq!(
        g.service_linked_role_arn(),
        Some(
            format!(
                "arn:aws:iam::{ACCOUNT}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            )
            .as_str()
        )
    );
    // One instance per zone, launched from the template's latest version.
    let mut zones: Vec<_> = g.instances().iter().filter_map(|i| i.availability_zone()).collect();
    zones.sort();
    assert_eq!(zones, ["us-east-1a", "us-east-1b"]);
    let lt = g.instances()[0].launch_template().unwrap();
    assert_eq!(lt.launch_template_id(), Some(template_id.as_str()));
    assert_eq!(lt.launch_template_name(), Some("web"));
    assert_eq!(lt.version(), Some("1"));
    assert_eq!(g.instances()[0].health_status(), Some("Healthy"));

    // The instances are real EC2 instances, tagged by the group.
    let first = ids(&g)[0].clone();
    let d = ec2.describe_instances().instance_ids(&first).send().await.unwrap();
    let i = &d.reservations()[0].instances()[0];
    assert_eq!(i.state().unwrap().name(), Some(&InstanceStateName::Running));
    let tag = |k: &str| i.tags().iter().find(|t| t.key() == Some(k)).and_then(|t| t.value()).map(String::from);
    assert_eq!(tag("aws:autoscaling:groupName").as_deref(), Some("web"));
    assert_eq!(tag("Team").as_deref(), Some("web"));
    assert_eq!(tag("Internal"), None);
    assert_eq!(tag("aws:ec2launchtemplate:id").as_deref(), Some(template_id.as_str()));

    let inst = asg.describe_auto_scaling_instances().instance_ids(&first).send().await.unwrap();
    let d = &inst.auto_scaling_instances()[0];
    assert_eq!(d.auto_scaling_group_name(), Some("web"));
    assert_eq!(d.lifecycle_state(), Some("InService"));
    assert_eq!(d.health_status(), Some("HEALTHY"));

    let acts = asg.describe_scaling_activities().auto_scaling_group_name("web").send().await.unwrap();
    assert_eq!(acts.activities().len(), 2);
    let a = &acts.activities()[0];
    assert_eq!(a.status_code().map(|s| s.as_str()), Some("Successful"));
    assert!(a.description().unwrap().starts_with("Launching a new EC2 instance: i-"), "{:?}", a.description());
    assert!(
        a.cause().unwrap().contains(
            "an instance was started in response to a difference between desired and actual capacity, increasing the capacity from 0 to 2."
        ),
        "{:?}",
        a.cause()
    );

    // Desired capacity.
    let err = asg.set_desired_capacity().auto_scaling_group_name("web").desired_capacity(9).send().await.unwrap_err();
    assert_eq!(message(&err), "New SetDesiredCapacity value 9 is above max value 4 for the AutoScalingGroup.");
    asg.set_desired_capacity().auto_scaling_group_name("web").desired_capacity(3).send().await.unwrap();
    let g = wait_group(&asg, "web", "3 InService", |g| in_service(g) == 3).await;

    // An instance terminated behind the group's back is replaced.
    let victim = ids(&g)[0].clone();
    ec2.terminate_instances().instance_ids(&victim).send().await.unwrap();
    let g = wait_group(&asg, "web", "replacement", |g| in_service(g) == 3 && !ids(g).contains(&victim)).await;

    // So is one marked unhealthy.
    let sick = ids(&g)[0].clone();
    asg.set_instance_health()
        .instance_id(&sick)
        .health_status("Unhealthy")
        .should_respect_grace_period(false)
        .send()
        .await
        .unwrap();
    let g = wait_group(&asg, "web", "unhealthy replaced", |g| in_service(g) == 3 && !ids(g).contains(&sick)).await;
    wait_ec2(&ec2, &sick, InstanceStateName::Terminated).await;
    let acts = asg.describe_scaling_activities().auto_scaling_group_name("web").send().await.unwrap();
    assert!(acts
        .activities()
        .iter()
        .any(|a| a.cause().unwrap_or_default().contains("in response to a user health-check.")));

    // Scale-in protection keeps an instance through a scale in.
    let keep = ids(&g)[0].clone();
    asg.set_instance_protection()
        .auto_scaling_group_name("web")
        .instance_ids(&keep)
        .protected_from_scale_in(true)
        .send()
        .await
        .unwrap();
    asg.update_auto_scaling_group().auto_scaling_group_name("web").desired_capacity(1).send().await.unwrap();
    let g = wait_group(&asg, "web", "1 instance", |g| g.instances().len() == 1).await;
    assert_eq!(ids(&g), std::slice::from_ref(&keep));
    assert!(g.instances()[0].protected_from_scale_in().unwrap());

    // TerminateInstanceInAutoScalingGroup: replaced unless the capacity
    // drops with it.
    let err = asg
        .terminate_instance_in_auto_scaling_group()
        .instance_id(&keep)
        .should_decrement_desired_capacity(true)
        .send()
        .await
        .unwrap_err();
    assert!(message(&err).starts_with("Currently, desiredSize equals minSize (1)."), "{}", message(&err));
    let out = asg
        .terminate_instance_in_auto_scaling_group()
        .instance_id(&keep)
        .should_decrement_desired_capacity(false)
        .send()
        .await
        .unwrap();
    let a = out.activity().unwrap();
    assert_eq!(a.description(), Some(format!("Terminating EC2 instance: {keep}").as_str()));
    let g = wait_group(&asg, "web", "replaced", |g| in_service(g) == 1 && !ids(g).contains(&keep)).await;
    let err = asg
        .terminate_instance_in_auto_scaling_group()
        .instance_id("i-00000000000000000")
        .should_decrement_desired_capacity(false)
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err), "Instance Id not found - No managed instance found for instance ID: i-00000000000000000");

    // Deleting needs an empty group, or ForceDelete.
    let err = asg.delete_auto_scaling_group().auto_scaling_group_name("web").send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceInUse");
    let last = ids(&g)[0].clone();
    asg.delete_auto_scaling_group().auto_scaling_group_name("web").force_delete(true).send().await.unwrap();
    let out = asg.describe_auto_scaling_groups().auto_scaling_group_names("web").send().await.unwrap();
    assert!(out.auto_scaling_groups().is_empty());
    wait_ec2(&ec2, &last, InstanceStateName::Terminated).await;
    let err = asg.delete_auto_scaling_group().auto_scaling_group_name("web").send().await.unwrap_err();
    assert_eq!(message(&err), "AutoScalingGroup name not found - AutoScalingGroup web not found");
    let acts = asg.describe_scaling_activities().auto_scaling_group_name("web").send().await.unwrap();
    assert!(acts.activities().is_empty());
    let acts = asg
        .describe_scaling_activities()
        .auto_scaling_group_name("web")
        .include_deleted_groups(true)
        .send()
        .await
        .unwrap();
    assert!(!acts.activities().is_empty());
    assert_eq!(acts.activities()[0].auto_scaling_group_state(), Some("Deleted"));
}

#[tokio::test]
async fn launch_configurations_tags_and_catalogues() {
    let Env { mws: _mws, asg, ec2, .. } = env().await;
    let ami = alpine_ami(&ec2).await;
    let err = asg
        .create_launch_configuration()
        .launch_configuration_name("old")
        .image_id("ami-00000000000000000")
        .instance_type("t3.micro")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ValidationError");
    asg.create_launch_configuration()
        .launch_configuration_name("old")
        .image_id(&ami)
        .instance_type("t3.micro")
        .user_data("IyEvYmluL3NoCmVjaG8gaGk=")
        .send()
        .await
        .unwrap();
    let err = asg
        .create_launch_configuration()
        .launch_configuration_name("old")
        .image_id(&ami)
        .instance_type("t3.micro")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "AlreadyExists");
    let lcs = asg.describe_launch_configurations().launch_configuration_names("old").send().await.unwrap();
    let lc = &lcs.launch_configurations()[0];
    assert_eq!(lc.image_id(), Some(ami.as_str()));
    assert!(lc.launch_configuration_arn().unwrap().contains(":launchConfiguration:"));
    assert_eq!(lc.instance_monitoring().unwrap().enabled(), Some(true));

    asg.create_auto_scaling_group()
        .auto_scaling_group_name("legacy")
        .launch_configuration_name("old")
        .min_size(1)
        .max_size(2)
        .availability_zones("us-east-1c")
        .send()
        .await
        .unwrap();
    let g = wait_group(&asg, "legacy", "1 InService", |g| in_service(g) == 1).await;
    assert_eq!(g.launch_configuration_name(), Some("old"));
    assert_eq!(g.instances()[0].launch_configuration_name(), Some("old"));
    let err = asg.delete_launch_configuration().launch_configuration_name("old").send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceInUse");
    assert_eq!(
        message(&err),
        "Cannot delete launch configuration old because it is attached to AutoScalingGroup legacy"
    );

    // Tags.
    asg.create_or_update_tags()
        .tags(
            Tag::builder()
                .resource_id("legacy")
                .resource_type("auto-scaling-group")
                .key("env")
                .value("prod")
                .propagate_at_launch(true)
                .build(),
        )
        .tags(Tag::builder().resource_id("legacy").resource_type("auto-scaling-group").key("tier").value("1").build())
        .send()
        .await
        .unwrap();
    let tags = asg
        .describe_tags()
        .filters(AsgFilter::builder().name("auto-scaling-group").values("legacy").build())
        .filters(AsgFilter::builder().name("key").values("env").build())
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert_eq!(tags.tags()[0].value(), Some("prod"));
    assert_eq!(tags.tags()[0].propagate_at_launch(), Some(true));
    let err = asg
        .create_or_update_tags()
        .tags(Tag::builder().resource_id("legacy").resource_type("auto-scaling-group").key("aws:x").value("1").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ValidationError");
    asg.delete_tags()
        .tags(Tag::builder().resource_id("legacy").resource_type("auto-scaling-group").key("tier").build())
        .send()
        .await
        .unwrap();
    let g = group(&asg, "legacy").await;
    assert_eq!(g.tags().iter().filter_map(|t| t.key()).collect::<Vec<_>>(), ["env"]);
    let by_tag = asg
        .describe_auto_scaling_groups()
        .filters(AsgFilter::builder().name("tag:env").values("prod").build())
        .send()
        .await
        .unwrap();
    assert_eq!(by_tag.auto_scaling_groups().len(), 1);

    // Catalogues.
    let limits = asg.describe_account_limits().send().await.unwrap();
    assert_eq!(limits.max_number_of_auto_scaling_groups(), Some(500));
    assert_eq!(limits.number_of_auto_scaling_groups(), Some(1));
    assert_eq!(limits.number_of_launch_configurations(), Some(1));
    let adj = asg.describe_adjustment_types().send().await.unwrap();
    assert_eq!(adj.adjustment_types().len(), 3);
    let procs = asg.describe_scaling_process_types().send().await.unwrap();
    assert!(procs.processes().iter().any(|p| p.process_name() == Some("AZRebalance")));
    let metrics = asg.describe_metric_collection_types().send().await.unwrap();
    assert!(metrics.metrics().iter().any(|m| m.metric() == Some("GroupInServiceInstances")));
    assert_eq!(metrics.granularities()[0].granularity(), Some("1Minute"));
    let tp = asg.describe_termination_policy_types().send().await.unwrap();
    assert!(tp.termination_policy_types().iter().any(|p| p == "OldestInstance"));
    let nt = asg.describe_auto_scaling_notification_types().send().await.unwrap();
    assert!(nt.auto_scaling_notification_types().iter().any(|p| p == "autoscaling:EC2_INSTANCE_LAUNCH"));
    let ht = asg.describe_lifecycle_hook_types().send().await.unwrap();
    assert_eq!(
        ht.lifecycle_hook_types(),
        ["autoscaling:EC2_INSTANCE_LAUNCHING", "autoscaling:EC2_INSTANCE_TERMINATING"]
    );
    asg.put_account_setting().name("default-instance-warmup").value("enabled").send().await.unwrap();
    let settings = asg.describe_account_settings().send().await.unwrap();
    assert_eq!(settings.settings()[0].value(), Some("enabled"));

    asg.update_auto_scaling_group()
        .auto_scaling_group_name("legacy")
        .min_size(0)
        .desired_capacity(0)
        .send()
        .await
        .unwrap();
    wait_group(&asg, "legacy", "empty", |g| g.instances().is_empty()).await;
    asg.delete_auto_scaling_group().auto_scaling_group_name("legacy").send().await.unwrap();
    asg.delete_launch_configuration().launch_configuration_name("old").send().await.unwrap();
    let lcs = asg.describe_launch_configurations().send().await.unwrap();
    assert!(lcs.launch_configurations().is_empty());
}

#[tokio::test]
async fn lifecycle_hooks_hold_instances_and_notify() {
    let Env { mws, asg, ec2: _ec2, template_id } = env().await;
    let config = mws.root_sdk_config().await;
    let sqs = aws_sdk_sqs::Client::new(&config);
    let sns = aws_sdk_sns::Client::new(&config);
    let q = sqs.create_queue().queue_name("hooks").send().await.unwrap();
    let url = q.queue_url().unwrap().to_string();
    let queue_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:hooks");
    let role = format!("arn:aws:iam::{ACCOUNT}:role/hooks");

    asg.create_auto_scaling_group()
        .auto_scaling_group_name("hooked")
        .min_size(0)
        .max_size(3)
        .desired_capacity(0)
        .launch_template(template(&template_id, "$Default"))
        .availability_zones("us-east-1a")
        .lifecycle_hook_specification_list(
            LifecycleHookSpecification::builder()
                .lifecycle_hook_name("boot")
                .lifecycle_transition("autoscaling:EC2_INSTANCE_LAUNCHING")
                .notification_target_arn(&queue_arn)
                .role_arn(&role)
                .notification_metadata("hello")
                .heartbeat_timeout(300)
                .build(),
        )
        .send()
        .await
        .unwrap();
    asg.put_lifecycle_hook()
        .auto_scaling_group_name("hooked")
        .lifecycle_hook_name("drain")
        .lifecycle_transition("autoscaling:EC2_INSTANCE_TERMINATING")
        .heartbeat_timeout(600)
        .default_result("CONTINUE")
        .send()
        .await
        .unwrap();
    let err = asg
        .put_lifecycle_hook()
        .auto_scaling_group_name("hooked")
        .lifecycle_hook_name("bad")
        .lifecycle_transition("autoscaling:EC2_INSTANCE_LAUNCHING")
        .heartbeat_timeout(10)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ValidationError");
    let hooks = asg.describe_lifecycle_hooks().auto_scaling_group_name("hooked").send().await.unwrap();
    assert_eq!(hooks.lifecycle_hooks().len(), 2);
    let boot = hooks.lifecycle_hooks().iter().find(|h| h.lifecycle_hook_name() == Some("boot")).unwrap();
    assert_eq!(boot.global_timeout(), Some(30000));
    assert_eq!(boot.default_result(), Some("ABANDON"));

    // A topic for group notifications, delivered to a queue.
    let topic = sns.create_topic().name("asg-events").send().await.unwrap().topic_arn().unwrap().to_string();
    let notes = sqs.create_queue().queue_name("asg-events").send().await.unwrap().queue_url().unwrap().to_string();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": format!("arn:aws:sqs:us-east-1:{ACCOUNT}:asg-events"),
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}},
        }],
    });
    sqs.set_queue_attributes()
        .queue_url(&notes)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(format!("arn:aws:sqs:us-east-1:{ACCOUNT}:asg-events"))
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();
    asg.put_notification_configuration()
        .auto_scaling_group_name("hooked")
        .topic_arn(&topic)
        .notification_types("autoscaling:EC2_INSTANCE_LAUNCH")
        .notification_types("autoscaling:EC2_INSTANCE_TERMINATE")
        .send()
        .await
        .unwrap();
    let nc = asg.describe_notification_configurations().auto_scaling_group_names("hooked").send().await.unwrap();
    assert_eq!(nc.notification_configurations().len(), 2);

    let receive = |url: String| {
        let sqs = sqs.clone();
        async move {
            let mut out = Vec::new();
            for _ in 0..40 {
                let r = sqs.receive_message().queue_url(&url).max_number_of_messages(10).send().await.unwrap();
                for m in r.messages() {
                    sqs.delete_message()
                        .queue_url(&url)
                        .receipt_handle(m.receipt_handle().unwrap())
                        .send()
                        .await
                        .unwrap();
                    out.push(serde_json::from_str::<serde_json::Value>(m.body().unwrap()).unwrap());
                }
                if !out.is_empty() {
                    return out;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            out
        }
    };
    // Putting the hook (and the notification configuration) sends a test
    // notification.
    let test = receive(url.clone()).await;
    assert_eq!(test[0]["Event"], "autoscaling:TEST_NOTIFICATION");
    let test = receive(notes.clone()).await;
    assert_eq!(test[0]["Event"], "autoscaling:TEST_NOTIFICATION");
    assert_eq!(test[0]["AutoScalingGroupName"], "hooked");

    asg.set_desired_capacity().auto_scaling_group_name("hooked").desired_capacity(1).send().await.unwrap();
    let g = wait_group(&asg, "hooked", "Pending:Wait", |g| {
        g.instances().first().and_then(|i| i.lifecycle_state()).map(|s| s.as_str()) == Some("Pending:Wait")
    })
    .await;
    let id = ids(&g)[0].clone();
    let msg = receive(url.clone()).await;
    let m = &msg[0];
    assert_eq!(m["LifecycleTransition"], "autoscaling:EC2_INSTANCE_LAUNCHING");
    assert_eq!(m["LifecycleHookName"], "boot");
    assert_eq!(m["EC2InstanceId"], id.as_str());
    assert_eq!(m["NotificationMetadata"], "hello");
    assert_eq!(m["Origin"], "EC2");
    assert_eq!(m["Destination"], "AutoScalingGroup");
    let token = m["LifecycleActionToken"].as_str().unwrap().to_string();
    // The activity waits on the hook.
    let acts = asg.describe_scaling_activities().auto_scaling_group_name("hooked").send().await.unwrap();
    assert_eq!(acts.activities()[0].status_code().map(|s| s.as_str()), Some("MidLifecycleAction"));

    asg.record_lifecycle_action_heartbeat()
        .auto_scaling_group_name("hooked")
        .lifecycle_hook_name("boot")
        .lifecycle_action_token(&token)
        .send()
        .await
        .unwrap();
    let err = asg
        .complete_lifecycle_action()
        .auto_scaling_group_name("hooked")
        .lifecycle_hook_name("boot")
        .instance_id("i-00000000000000000")
        .lifecycle_action_result("CONTINUE")
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err), "No active Lifecycle Action found with instance ID i-00000000000000000");
    asg.complete_lifecycle_action()
        .auto_scaling_group_name("hooked")
        .lifecycle_hook_name("boot")
        .lifecycle_action_token(&token)
        .lifecycle_action_result("CONTINUE")
        .send()
        .await
        .unwrap();
    wait_group(&asg, "hooked", "InService", |g| in_service(g) == 1).await;
    let launch = receive(notes.clone()).await;
    assert_eq!(launch[0]["Event"], "autoscaling:EC2_INSTANCE_LAUNCH");
    assert_eq!(launch[0]["EC2InstanceId"], id.as_str());

    // Scale in: the terminate hook holds the instance in Terminating:Wait.
    asg.set_desired_capacity().auto_scaling_group_name("hooked").desired_capacity(0).send().await.unwrap();
    wait_group(&asg, "hooked", "Terminating:Wait", |g| {
        g.instances().first().and_then(|i| i.lifecycle_state()).map(|s| s.as_str()) == Some("Terminating:Wait")
    })
    .await;
    asg.complete_lifecycle_action()
        .auto_scaling_group_name("hooked")
        .lifecycle_hook_name("drain")
        .instance_id(&id)
        .lifecycle_action_result("CONTINUE")
        .send()
        .await
        .unwrap();
    wait_group(&asg, "hooked", "empty", |g| g.instances().is_empty()).await;
    let term = receive(notes.clone()).await;
    assert_eq!(term[0]["Event"], "autoscaling:EC2_INSTANCE_TERMINATE");

    // Abandoning a launch hook terminates the instance.
    asg.set_desired_capacity().auto_scaling_group_name("hooked").desired_capacity(1).send().await.unwrap();
    let g = wait_group(&asg, "hooked", "Pending:Wait", |g| {
        g.instances().first().and_then(|i| i.lifecycle_state()).map(|s| s.as_str()) == Some("Pending:Wait")
    })
    .await;
    let abandoned = ids(&g)[0].clone();
    asg.complete_lifecycle_action()
        .auto_scaling_group_name("hooked")
        .lifecycle_hook_name("boot")
        .instance_id(&abandoned)
        .lifecycle_action_result("ABANDON")
        .send()
        .await
        .unwrap();
    wait_group(&asg, "hooked", "abandoned instance gone", |g| !ids(g).contains(&abandoned)).await;

    asg.delete_lifecycle_hook().auto_scaling_group_name("hooked").lifecycle_hook_name("boot").send().await.unwrap();
    asg.delete_lifecycle_hook().auto_scaling_group_name("hooked").lifecycle_hook_name("drain").send().await.unwrap();
    asg.delete_notification_configuration().auto_scaling_group_name("hooked").topic_arn(&topic).send().await.unwrap();
    let nc = asg.describe_notification_configurations().send().await.unwrap();
    assert!(nc.notification_configurations().is_empty());
    wait_group(&asg, "hooked", "InService without hooks", |g| in_service(g) == 1).await;
}

#[tokio::test]
async fn processes_standby_detach_attach_and_metrics() {
    let Env { mws, asg, ec2, template_id } = env().await;
    asg.create_auto_scaling_group()
        .auto_scaling_group_name("ops")
        .min_size(0)
        .max_size(5)
        .desired_capacity(2)
        .launch_template(template(&template_id, "$Latest"))
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap();
    wait_group(&asg, "ops", "2 InService", |g| in_service(g) == 2).await;

    // Suspended Launch: no scale out until resumed.
    asg.suspend_processes().auto_scaling_group_name("ops").scaling_processes("Launch").send().await.unwrap();
    let err =
        asg.suspend_processes().auto_scaling_group_name("ops").scaling_processes("Nope").send().await.unwrap_err();
    assert_eq!(code(&err), "ValidationError");
    asg.set_desired_capacity().auto_scaling_group_name("ops").desired_capacity(3).send().await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let g2 = group(&asg, "ops").await;
    assert_eq!(g2.instances().len(), 2);
    assert_eq!(g2.suspended_processes()[0].process_name(), Some("Launch"));
    assert!(g2.suspended_processes()[0].suspension_reason().unwrap().starts_with("User suspended at "));
    asg.resume_processes().auto_scaling_group_name("ops").send().await.unwrap();
    let g = wait_group(&asg, "ops", "3 InService", |g| in_service(g) == 3).await;
    assert!(g.suspended_processes().is_empty());

    // Standby: out of service without a replacement when decremented.
    let parked = ids(&g)[0].clone();
    let out = asg
        .enter_standby()
        .auto_scaling_group_name("ops")
        .instance_ids(&parked)
        .should_decrement_desired_capacity(true)
        .send()
        .await
        .unwrap();
    assert_eq!(out.activities()[0].description(), Some(format!("Moving EC2 instance to Standby: {parked}").as_str()));
    let g = group(&asg, "ops").await;
    assert_eq!(g.desired_capacity(), Some(2));
    let state = |g: &AutoScalingGroup, id: &str| {
        g.instances()
            .iter()
            .find(|i| i.instance_id() == Some(id))
            .and_then(|i| i.lifecycle_state())
            .map(|s| s.as_str().to_string())
    };
    assert_eq!(state(&g, &parked).as_deref(), Some("Standby"));
    let err = asg
        .enter_standby()
        .auto_scaling_group_name("ops")
        .instance_ids(&parked)
        .should_decrement_desired_capacity(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err), format!("The instance {parked} is not in InService."));
    asg.exit_standby().auto_scaling_group_name("ops").instance_ids(&parked).send().await.unwrap();
    let g = wait_group(&asg, "ops", "back in service", |g| in_service(g) == 3).await;
    assert_eq!(g.desired_capacity(), Some(3));

    // Detach: the instance keeps running outside the group.
    let out = asg
        .detach_instances()
        .auto_scaling_group_name("ops")
        .instance_ids(&parked)
        .should_decrement_desired_capacity(true)
        .send()
        .await
        .unwrap();
    assert_eq!(out.activities()[0].description(), Some(format!("Detaching EC2 instance: {parked}").as_str()));
    let g = group(&asg, "ops").await;
    assert!(!ids(&g).contains(&parked));
    assert_eq!(g.desired_capacity(), Some(2));
    assert_eq!(ec2_state(&ec2, &parked).await, Some(InstanceStateName::Running));
    let d = ec2.describe_instances().instance_ids(&parked).send().await.unwrap();
    assert!(!d.reservations()[0].instances()[0].tags().iter().any(|t| t.key() == Some("aws:autoscaling:groupName")));

    // Attach it again.
    asg.attach_instances().auto_scaling_group_name("ops").instance_ids(&parked).send().await.unwrap();
    let g = wait_group(&asg, "ops", "attached", |g| in_service(g) == 3 && ids(g).contains(&parked)).await;
    assert_eq!(g.desired_capacity(), Some(3));
    let err = asg.attach_instances().auto_scaling_group_name("ops").instance_ids(&parked).send().await.unwrap_err();
    assert_eq!(message(&err), format!("The instance {parked} is already part of the Auto Scaling group ops"));
    let d = ec2.describe_instances().instance_ids(&parked).send().await.unwrap();
    assert!(d.reservations()[0].instances()[0].tags().iter().any(|t| t.key() == Some("aws:autoscaling:groupName")));

    // Group metrics go to CloudWatch.
    asg.enable_metrics_collection().auto_scaling_group_name("ops").granularity("1Minute").send().await.unwrap();
    let g = group(&asg, "ops").await;
    assert_eq!(g.enabled_metrics().len(), 20);
    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    let mut found = false;
    for _ in 0..40 {
        let m =
            cw.list_metrics().namespace("AWS/AutoScaling").metric_name("GroupInServiceInstances").send().await.unwrap();
        if !m.metrics().is_empty() {
            assert_eq!(m.metrics()[0].dimensions()[0].name(), Some("AutoScalingGroupName"));
            assert_eq!(m.metrics()[0].dimensions()[0].value(), Some("ops"));
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(found, "no AWS/AutoScaling metrics");
    asg.disable_metrics_collection().auto_scaling_group_name("ops").send().await.unwrap();
    assert!(group(&asg, "ops").await.enabled_metrics().is_empty());

    // LaunchInstances launches synchronously and is idempotent.
    let out = asg
        .launch_instances()
        .auto_scaling_group_name("ops")
        .requested_capacity(1)
        .client_token("burst-1")
        .send()
        .await
        .unwrap();
    let launched: Vec<String> = out.instances().iter().flat_map(|c| c.instance_ids().iter().cloned()).collect();
    assert_eq!(launched.len(), 1, "{out:?}");
    let again = asg
        .launch_instances()
        .auto_scaling_group_name("ops")
        .requested_capacity(1)
        .client_token("burst-1")
        .send()
        .await
        .unwrap();
    assert_eq!(again.instances()[0].instance_ids(), launched.as_slice());
    let g = wait_group(&asg, "ops", "4 InService", |g| in_service(g) == 4).await;
    assert_eq!(g.desired_capacity(), Some(4));
}

#[tokio::test]
async fn policies_scale_on_executions_and_alarms() {
    let Env { mws, asg, ec2: _ec2, template_id } = env().await;
    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    asg.create_auto_scaling_group()
        .auto_scaling_group_name("scaled")
        .min_size(1)
        .max_size(10)
        .desired_capacity(2)
        .launch_template(template(&template_id, "$Latest"))
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap();
    let simple = asg
        .put_scaling_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("add-two")
        .adjustment_type("ChangeInCapacity")
        .scaling_adjustment(2)
        .cooldown(600)
        .send()
        .await
        .unwrap();
    let simple_arn = simple.policy_arn().unwrap().to_string();
    assert!(
        simple_arn.contains(":scalingPolicy:")
            && simple_arn.ends_with(":autoScalingGroupName/scaled:policyName/add-two")
    );
    asg.execute_policy().auto_scaling_group_name("scaled").policy_name("add-two").send().await.unwrap();
    assert_eq!(group(&asg, "scaled").await.desired_capacity(), Some(4));
    let err = asg
        .execute_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("add-two")
        .honor_cooldown(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ScalingActivityInProgress");

    asg.put_scaling_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("steps")
        .policy_type("StepScaling")
        .adjustment_type("PercentChangeInCapacity")
        .step_adjustments(
            StepAdjustment::builder()
                .metric_interval_lower_bound(0.0)
                .metric_interval_upper_bound(10.0)
                .scaling_adjustment(10)
                .build(),
        )
        .step_adjustments(StepAdjustment::builder().metric_interval_lower_bound(10.0).scaling_adjustment(50).build())
        .send()
        .await
        .unwrap();
    // 4 + 50% = 6.
    asg.execute_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("steps")
        .metric_value(95.0)
        .breach_threshold(70.0)
        .send()
        .await
        .unwrap();
    assert_eq!(group(&asg, "scaled").await.desired_capacity(), Some(6));
    // 6 + 10% rounds to at least one instance.
    asg.execute_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("steps")
        .metric_value(75.0)
        .breach_threshold(70.0)
        .send()
        .await
        .unwrap();
    assert_eq!(group(&asg, "scaled").await.desired_capacity(), Some(7));
    let err = asg
        .put_scaling_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("gappy")
        .policy_type("StepScaling")
        .adjustment_type("ChangeInCapacity")
        .step_adjustments(
            StepAdjustment::builder()
                .metric_interval_lower_bound(0.0)
                .metric_interval_upper_bound(10.0)
                .scaling_adjustment(1)
                .build(),
        )
        .step_adjustments(StepAdjustment::builder().metric_interval_lower_bound(20.0).scaling_adjustment(2).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ValidationError");

    // An alarm naming a policy scales the group when it goes to ALARM, once
    // add-two's cooldown is over.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 660}"#)).await;
    assert_eq!(status, 200);
    asg.put_scaling_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("shrink")
        .adjustment_type("ExactCapacity")
        .scaling_adjustment(3)
        .send()
        .await
        .unwrap();
    let shrink_arn = asg
        .describe_policies()
        .auto_scaling_group_name("scaled")
        .policy_names("shrink")
        .send()
        .await
        .unwrap()
        .scaling_policies()[0]
        .policy_arn()
        .unwrap()
        .to_string();
    cw.put_metric_alarm()
        .alarm_name("quiet")
        .namespace("App")
        .metric_name("Load")
        .statistic(aws_sdk_cloudwatch::types::Statistic::Average)
        .period(60)
        .evaluation_periods(1)
        .threshold(1.0)
        .comparison_operator(aws_sdk_cloudwatch::types::ComparisonOperator::LessThanThreshold)
        .alarm_actions(&shrink_arn)
        .send()
        .await
        .unwrap();
    cw.set_alarm_state()
        .alarm_name("quiet")
        .state_value(aws_sdk_cloudwatch::types::StateValue::Alarm)
        .state_reason("testing")
        .send()
        .await
        .unwrap();
    wait_group(&asg, "scaled", "desired 3", |g| g.desired_capacity() == Some(3)).await;
    let acts = asg.describe_scaling_activities().auto_scaling_group_name("scaled").send().await.unwrap();
    let g = wait_group(&asg, "scaled", "3 instances", |g| in_service(g) == 3 && g.instances().len() == 3).await;
    let _ = g;
    let acts2 = asg.describe_scaling_activities().auto_scaling_group_name("scaled").send().await.unwrap();
    assert!(
        acts.activities().iter().chain(acts2.activities()).any(|a| a.cause().unwrap_or_default().contains(
            "a monitor alarm quiet in state ALARM triggered policy shrink changing the desired capacity from 7 to 3."
        )),
        "{:#?}",
        acts2.activities().iter().map(|a| a.cause()).collect::<Vec<_>>()
    );

    // Target tracking owns two CloudWatch alarms.
    let tt = asg
        .put_scaling_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("cpu50")
        .policy_type("TargetTrackingScaling")
        .target_tracking_configuration(
            TargetTrackingConfiguration::builder()
                .predefined_metric_specification(
                    PredefinedMetricSpecification::builder()
                        .predefined_metric_type("ASGAverageCPUUtilization".into())
                        .build(),
                )
                .target_value(50.0)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(tt.alarms().len(), 2);
    let high = tt.alarms().iter().find(|a| a.alarm_name().unwrap().contains("-AlarmHigh-")).unwrap();
    assert!(high.alarm_name().unwrap().starts_with("TargetTracking-scaled-AlarmHigh-"));
    let alarms = cw.describe_alarms().alarm_name_prefix("TargetTracking-scaled-").send().await.unwrap();
    assert_eq!(alarms.metric_alarms().len(), 2);
    let h = alarms.metric_alarms().iter().find(|a| a.alarm_name().unwrap().contains("High")).unwrap();
    assert_eq!(h.namespace(), Some("AWS/EC2"));
    assert_eq!(h.metric_name(), Some("CPUUtilization"));
    assert_eq!(h.threshold(), Some(50.0));
    assert_eq!(h.dimensions()[0].value(), Some("scaled"));
    let err = asg.execute_policy().auto_scaling_group_name("scaled").policy_name("cpu50").send().await.unwrap_err();
    assert_eq!(code(&err), "ValidationError");

    // Custom metric target tracking, and predictive scaling forecasts.
    asg.put_scaling_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("queue")
        .policy_type("TargetTrackingScaling")
        .target_tracking_configuration(
            TargetTrackingConfiguration::builder()
                .customized_metric_specification(
                    aws_sdk_autoscaling::types::CustomizedMetricSpecification::builder()
                        .namespace("App")
                        .metric_name("Backlog")
                        .dimensions(MetricDimension::builder().name("Queue").value("jobs").build())
                        .statistic("Average".into())
                        .build(),
                )
                .target_value(100.0)
                .disable_scale_in(true)
                .build(),
        )
        .send()
        .await
        .unwrap();
    asg.put_scaling_policy()
        .auto_scaling_group_name("scaled")
        .policy_name("predict")
        .policy_type("PredictiveScaling")
        .predictive_scaling_configuration(
            PredictiveScalingConfiguration::builder()
                .metric_specifications(
                    PredictiveScalingMetricSpecification::builder()
                        .target_value(40.0)
                        .predefined_metric_pair_specification(
                            PredictiveScalingPredefinedMetricPair::builder()
                                .predefined_metric_type("ASGCPUUtilization".into())
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let forecast = asg
        .get_predictive_scaling_forecast()
        .auto_scaling_group_name("scaled")
        .policy_name("predict")
        .start_time(DateTime::from_secs(now))
        .end_time(DateTime::from_secs(now + 6 * 3600))
        .send()
        .await
        .unwrap();
    assert!(forecast.capacity_forecast().unwrap().timestamps().len() >= 6);
    assert_eq!(forecast.load_forecast().len(), 1);

    let policies = asg.describe_policies().auto_scaling_group_name("scaled").send().await.unwrap();
    assert_eq!(policies.scaling_policies().len(), 6);
    let tts = asg
        .describe_policies()
        .auto_scaling_group_name("scaled")
        .policy_types("TargetTrackingScaling")
        .send()
        .await
        .unwrap();
    assert_eq!(tts.scaling_policies().len(), 2);
    asg.delete_policy().auto_scaling_group_name("scaled").policy_name("cpu50").send().await.unwrap();
    let alarms = cw.describe_alarms().alarm_name_prefix("TargetTracking-scaled-AlarmHigh-").send().await.unwrap();
    assert_eq!(alarms.metric_alarms().len(), 1, "the custom policy's alarm remains");
    let err = asg.delete_policy().auto_scaling_group_name("scaled").policy_name("cpu50").send().await.unwrap_err();
    assert_eq!(code(&err), "ValidationError");
}

#[tokio::test]
async fn schedules_refreshes_and_warm_pools() {
    let Env { mws, asg, ec2, template_id } = env().await;
    asg.create_auto_scaling_group()
        .auto_scaling_group_name("fleet")
        .min_size(1)
        .max_size(6)
        .desired_capacity(2)
        .launch_template(template(&template_id, "$Latest"))
        .availability_zones("us-east-1a")
        .availability_zones("us-east-1b")
        .send()
        .await
        .unwrap();
    let g = wait_group(&asg, "fleet", "2 InService", |g| in_service(g) == 2).await;
    let before = ids(&g);

    // A scheduled action on the emulated clock.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let err = asg
        .put_scheduled_update_group_action()
        .auto_scaling_group_name("fleet")
        .scheduled_action_name("past")
        .start_time(DateTime::from_secs(now - 3600))
        .desired_capacity(3)
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err), "Given start time is in the past");
    asg.put_scheduled_update_group_action()
        .auto_scaling_group_name("fleet")
        .scheduled_action_name("morning")
        .start_time(DateTime::from_secs(now + 600))
        .desired_capacity(3)
        .send()
        .await
        .unwrap();
    let out = asg
        .batch_put_scheduled_update_group_action()
        .auto_scaling_group_name("fleet")
        .scheduled_update_group_actions(
            ScheduledUpdateGroupActionRequest::builder()
                .scheduled_action_name("weekdays")
                .recurrence("0 9 * * 1-5")
                .min_size(1)
                .build(),
        )
        .scheduled_update_group_actions(
            ScheduledUpdateGroupActionRequest::builder()
                .scheduled_action_name("broken")
                .recurrence("not cron")
                .min_size(1)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(out.failed_scheduled_update_group_actions().len(), 1);
    assert_eq!(out.failed_scheduled_update_group_actions()[0].scheduled_action_name(), Some("broken"));
    let sched = asg.describe_scheduled_actions().auto_scaling_group_name("fleet").send().await.unwrap();
    assert_eq!(sched.scheduled_update_group_actions().len(), 2);
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 660}"#)).await;
    assert_eq!(status, 200);
    let g = wait_group(&asg, "fleet", "scheduled desired 3", |g| g.desired_capacity() == Some(3)).await;
    let _ = g;
    let sched = asg.describe_scheduled_actions().auto_scaling_group_name("fleet").send().await.unwrap();
    let names: Vec<_> =
        sched.scheduled_update_group_actions().iter().filter_map(|a| a.scheduled_action_name()).collect();
    assert_eq!(names, ["weekdays"], "one-time actions go once run");
    let acts = asg.describe_scaling_activities().auto_scaling_group_name("fleet").send().await.unwrap();
    let g = wait_group(&asg, "fleet", "3 InService", |g| in_service(g) == 3).await;
    let _ = (acts, g);
    let out = asg
        .batch_delete_scheduled_action()
        .auto_scaling_group_name("fleet")
        .scheduled_action_names("weekdays")
        .scheduled_action_names("missing")
        .send()
        .await
        .unwrap();
    assert_eq!(out.failed_scheduled_actions().len(), 1);
    asg.put_scheduled_update_group_action()
        .auto_scaling_group_name("fleet")
        .scheduled_action_name("nightly")
        .recurrence("0 2 * * *")
        .desired_capacity(1)
        .send()
        .await
        .unwrap();
    asg.delete_scheduled_action()
        .auto_scaling_group_name("fleet")
        .scheduled_action_name("nightly")
        .send()
        .await
        .unwrap();

    // Instance refresh to a new template version.
    let ami = alpine_ami(&ec2).await;
    ec2.create_launch_template_version()
        .launch_template_id(&template_id)
        .launch_template_data(
            RequestLaunchTemplateData::builder().image_id(&ami).instance_type(InstanceType::T3Small).build(),
        )
        .send()
        .await
        .unwrap();
    let err = asg.cancel_instance_refresh().auto_scaling_group_name("fleet").send().await.unwrap_err();
    assert_eq!(code(&err), "ActiveInstanceRefreshNotFound");
    let started = asg
        .start_instance_refresh()
        .auto_scaling_group_name("fleet")
        .desired_configuration(DesiredConfiguration::builder().launch_template(template(&template_id, "2")).build())
        .preferences(RefreshPreferences::builder().min_healthy_percentage(50).skip_matching(true).build())
        .send()
        .await
        .unwrap();
    let refresh_id = started.instance_refresh_id().unwrap().to_string();
    let err = asg.start_instance_refresh().auto_scaling_group_name("fleet").send().await.unwrap_err();
    assert_eq!(code(&err), "InstanceRefreshInProgress");
    let mut done = None;
    for _ in 0..200 {
        let r = asg.describe_instance_refreshes().auto_scaling_group_name("fleet").send().await.unwrap();
        let r = r.instance_refreshes()[0].clone();
        if r.status().map(|s| s.as_str()) == Some("Successful") {
            done = Some(r);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let done = done.expect("the refresh never finished");
    assert_eq!(done.instance_refresh_id(), Some(refresh_id.as_str()));
    assert_eq!(done.percentage_complete(), Some(100));
    let g = wait_group(&asg, "fleet", "refreshed", |g| {
        in_service(g) == 3 && g.instances().iter().all(|i| i.launch_template().and_then(|l| l.version()) == Some("2"))
    })
    .await;
    assert!(before.iter().all(|id| !ids(&g).contains(id)));
    assert_eq!(g.launch_template().unwrap().version(), Some("2"));
    assert!(g.instances().iter().all(|i| i.instance_type() == Some("t3.small")));

    // A refresh can be cancelled, and one without a desired configuration
    // can't be rolled back.
    asg.start_instance_refresh()
        .auto_scaling_group_name("fleet")
        .preferences(RefreshPreferences::builder().instance_warmup(300).build())
        .send()
        .await
        .unwrap();
    let err = asg.rollback_instance_refresh().auto_scaling_group_name("fleet").send().await.unwrap_err();
    assert_eq!(code(&err), "IrreversibleInstanceRefresh");
    let cancelled = asg.cancel_instance_refresh().auto_scaling_group_name("fleet").send().await.unwrap();
    assert!(cancelled.instance_refresh_id().is_some());
    let mut status = String::new();
    for _ in 0..80 {
        let r = asg.describe_instance_refreshes().auto_scaling_group_name("fleet").send().await.unwrap();
        status = r.instance_refreshes()[0].status().unwrap().as_str().to_string();
        if status == "Cancelled" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(status, "Cancelled");
    wait_group(&asg, "fleet", "3 InService after cancel", |g| in_service(g) == 3).await;

    // A warm pool of stopped instances; scale out takes from it.
    asg.put_warm_pool()
        .auto_scaling_group_name("fleet")
        .min_size(1)
        .max_group_prepared_capacity(4)
        .send()
        .await
        .unwrap();
    let mut warm = Vec::new();
    for _ in 0..120 {
        let wp = asg.describe_warm_pool().auto_scaling_group_name("fleet").send().await.unwrap();
        if wp.instances().len() == 1
            && wp.instances()[0].lifecycle_state().map(|s| s.as_str()) == Some("Warmed:Stopped")
        {
            assert_eq!(wp.warm_pool_configuration().unwrap().pool_state().map(|s| s.as_str()), Some("Stopped"));
            warm = wp.instances().iter().filter_map(|i| i.instance_id().map(String::from)).collect();
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(warm.len(), 1, "the warm pool never filled");
    wait_ec2(&ec2, &warm[0], InstanceStateName::Stopped).await;
    assert_eq!(group(&asg, "fleet").await.warm_pool_size(), Some(1));
    asg.set_desired_capacity().auto_scaling_group_name("fleet").desired_capacity(4).send().await.unwrap();
    let g = wait_group(&asg, "fleet", "warm instance in service", |g| in_service(g) == 4 && ids(g).contains(&warm[0]))
        .await;
    let _ = g;
    wait_ec2(&ec2, &warm[0], InstanceStateName::Running).await;
    asg.delete_warm_pool().auto_scaling_group_name("fleet").force_delete(true).send().await.unwrap();
    let wp = asg.describe_warm_pool().auto_scaling_group_name("fleet").send().await.unwrap();
    assert!(wp.warm_pool_configuration().is_none());
}

#[tokio::test]
async fn load_balancers_get_the_group_instances() {
    use aws_sdk_elasticloadbalancingv2::types::{ProtocolEnum, TargetTypeEnum};
    let Env { mws, asg, ec2, template_id } = env().await;
    let config = mws.root_sdk_config().await;
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&config);
    let classic = aws_sdk_elasticloadbalancing::Client::new(&config);
    let vpc = ec2
        .describe_vpcs()
        .filters(Filter::builder().name("isDefault").values("true").build())
        .send()
        .await
        .unwrap()
        .vpcs()[0]
        .vpc_id()
        .unwrap()
        .to_string();
    let tg = elb
        .create_target_group()
        .name("web")
        .protocol(ProtocolEnum::Http)
        .port(80)
        .vpc_id(&vpc)
        .target_type(TargetTypeEnum::Instance)
        .send()
        .await
        .unwrap();
    let tg_arn = tg.target_groups()[0].target_group_arn().unwrap().to_string();
    classic
        .create_load_balancer()
        .load_balancer_name("legacy")
        .availability_zones("us-east-1a")
        .listeners(
            aws_sdk_elasticloadbalancing::types::Listener::builder()
                .protocol("HTTP")
                .load_balancer_port(8080)
                .instance_port(80)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    asg.create_auto_scaling_group()
        .auto_scaling_group_name("served")
        .min_size(2)
        .max_size(3)
        .launch_template(template(&template_id, "$Latest"))
        .availability_zones("us-east-1a")
        .target_group_arns(&tg_arn)
        .send()
        .await
        .unwrap();
    let g = wait_group(&asg, "served", "2 InService", |g| in_service(g) == 2).await;
    assert_eq!(g.target_group_arns(), std::slice::from_ref(&tg_arn));
    let registered = |elb: aws_sdk_elasticloadbalancingv2::Client, arn: String| async move {
        let h = elb.describe_target_health().target_group_arn(&arn).send().await.unwrap();
        let mut v: Vec<String> = h
            .target_health_descriptions()
            .iter()
            .filter_map(|d| d.target().and_then(|t| t.id()).map(String::from))
            .collect();
        v.sort();
        v
    };
    let mut want = ids(&g);
    want.sort();
    let mut got = Vec::new();
    for _ in 0..40 {
        got = registered(elb.clone(), tg_arn.clone()).await;
        if got == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(got, want);
    let tgs = asg.describe_load_balancer_target_groups().auto_scaling_group_name("served").send().await.unwrap();
    assert_eq!(tgs.load_balancer_target_groups()[0].state(), Some("Added"));

    asg.attach_load_balancers().auto_scaling_group_name("served").load_balancer_names("legacy").send().await.unwrap();
    let lbs = asg.describe_load_balancers().auto_scaling_group_name("served").send().await.unwrap();
    assert_eq!(lbs.load_balancers()[0].load_balancer_name(), Some("legacy"));
    let mut classic_ids = Vec::new();
    for _ in 0..40 {
        let d = classic.describe_load_balancers().load_balancer_names("legacy").send().await.unwrap();
        classic_ids = d.load_balancer_descriptions()[0]
            .instances()
            .iter()
            .filter_map(|i| i.instance_id().map(String::from))
            .collect();
        classic_ids.sort();
        if classic_ids == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(classic_ids, want);

    let sources = asg.describe_traffic_sources().auto_scaling_group_name("served").send().await.unwrap();
    assert_eq!(sources.traffic_sources().len(), 2);
    asg.detach_load_balancers().auto_scaling_group_name("served").load_balancer_names("legacy").send().await.unwrap();
    asg.detach_load_balancer_target_groups()
        .auto_scaling_group_name("served")
        .target_group_arns(&tg_arn)
        .send()
        .await
        .unwrap();
    for _ in 0..40 {
        if registered(elb.clone(), tg_arn.clone()).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(registered(elb.clone(), tg_arn.clone()).await.is_empty());

    // The traffic source APIs cover the same attachments.
    asg.attach_traffic_sources()
        .auto_scaling_group_name("served")
        .traffic_sources(TrafficSourceIdentifier::builder().identifier(&tg_arn).r#type("elbv2").build())
        .send()
        .await
        .unwrap();
    let g = group(&asg, "served").await;
    assert_eq!(g.target_group_arns(), std::slice::from_ref(&tg_arn));
    for _ in 0..40 {
        if registered(elb.clone(), tg_arn.clone()).await == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(registered(elb.clone(), tg_arn.clone()).await, want);
    asg.detach_traffic_sources()
        .auto_scaling_group_name("served")
        .traffic_sources(TrafficSourceIdentifier::builder().identifier(&tg_arn).build())
        .send()
        .await
        .unwrap();
    let sources = asg.describe_traffic_sources().auto_scaling_group_name("served").send().await.unwrap();
    assert!(sources.traffic_sources().is_empty());
}

#[tokio::test]
async fn mixed_instances_policies_launch_spot_instances() {
    use aws_sdk_autoscaling::types::{
        InstancesDistribution, LaunchTemplate, LaunchTemplateOverrides, MixedInstancesPolicy,
    };
    let Env { mws: _mws, asg, ec2, template_id } = env().await;

    // One on-demand instance as base capacity, then half of the rest
    // on-demand (rounded up) and the remainder Spot.
    asg.create_auto_scaling_group()
        .auto_scaling_group_name("mixed")
        .min_size(0)
        .max_size(6)
        .desired_capacity(4)
        .availability_zones("us-east-1a")
        .mixed_instances_policy(
            MixedInstancesPolicy::builder()
                .launch_template(
                    LaunchTemplate::builder()
                        .launch_template_specification(template(&template_id, "$Latest"))
                        .overrides(LaunchTemplateOverrides::builder().instance_type("t3.micro").build())
                        .overrides(LaunchTemplateOverrides::builder().instance_type("t3.small").build())
                        .build(),
                )
                .instances_distribution(
                    InstancesDistribution::builder()
                        .on_demand_base_capacity(1)
                        .on_demand_percentage_above_base_capacity(50)
                        .spot_allocation_strategy("price-capacity-optimized")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let g = wait_group(&asg, "mixed", "4 in service", |g| in_service(g) == 4).await;
    let out = ec2.describe_instances().set_instance_ids(Some(ids(&g))).send().await.unwrap();
    let instances: Vec<_> = out.reservations().iter().flat_map(|r| r.instances().to_vec()).collect();
    let spot: Vec<_> = instances
        .iter()
        .filter(|i| i.instance_lifecycle() == Some(&aws_sdk_ec2::types::InstanceLifecycleType::Spot))
        .collect();
    assert_eq!((instances.len(), spot.len()), (4, 1));
    assert!(spot[0].spot_instance_request_id().unwrap().starts_with("sir-"));

    // EC2 filters by lifecycle.
    let filtered = ec2
        .describe_instances()
        .filters(Filter::builder().name("instance-lifecycle").values("spot").build())
        .filters(Filter::builder().name("instance-state-name").values("pending").values("running").build())
        .send()
        .await
        .unwrap();
    let filtered: Vec<_> = filtered.reservations().iter().flat_map(|r| r.instances().to_vec()).collect();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].instance_id(), spot[0].instance_id());

    // An all-Spot distribution launches only Spot.
    asg.update_auto_scaling_group()
        .auto_scaling_group_name("mixed")
        .mixed_instances_policy(
            MixedInstancesPolicy::builder()
                .launch_template(
                    LaunchTemplate::builder()
                        .launch_template_specification(template(&template_id, "$Latest"))
                        .overrides(LaunchTemplateOverrides::builder().instance_type("t3.micro").build())
                        .build(),
                )
                .instances_distribution(
                    InstancesDistribution::builder()
                        .on_demand_base_capacity(0)
                        .on_demand_percentage_above_base_capacity(0)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    asg.set_desired_capacity().auto_scaling_group_name("mixed").desired_capacity(6).send().await.unwrap();
    let g = wait_group(&asg, "mixed", "6 in service", |g| in_service(g) == 6).await;
    let out = ec2.describe_instances().set_instance_ids(Some(ids(&g))).send().await.unwrap();
    let spot = out
        .reservations()
        .iter()
        .flat_map(|r| r.instances().to_vec())
        .filter(|i| i.instance_lifecycle() == Some(&aws_sdk_ec2::types::InstanceLifecycleType::Spot))
        .count();
    assert_eq!(spot, 3);

    // A RunInstances request on the Spot market.
    let ami = alpine_ami(&ec2).await;
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .instance_market_options(
            aws_sdk_ec2::types::InstanceMarketOptionsRequest::builder()
                .market_type(aws_sdk_ec2::types::MarketType::Spot)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(run.instances()[0].instance_lifecycle(), Some(&aws_sdk_ec2::types::InstanceLifecycleType::Spot));
}
