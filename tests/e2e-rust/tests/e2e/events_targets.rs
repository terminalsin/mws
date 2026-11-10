//! EventBridge targets that run work in other services, through the
//! official Rust SDK: ECS clusters (each event runs a task) and Systems
//! Manager documents (each event sends a Run Command).

use std::time::Duration;

use aws_sdk_ec2::types::{IamInstanceProfileSpecification, InstanceStateName, ResourceType, TagSpecification};
use aws_sdk_ecs::types::{Compatibility, ContainerDefinition, NetworkMode};
use aws_sdk_eventbridge::types::{
    AwsVpcConfiguration, EcsParameters, LaunchType, NetworkConfiguration, PutEventsRequestEntry, RunCommandParameters,
    RunCommandTarget, Target,
};
use mws_e2e::Mws;

const EVENTS_TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

async fn events_role(cfg: &aws_config::SdkConfig, name: &str, actions: &str) -> String {
    let iam = aws_sdk_iam::Client::new(cfg);
    let r = iam.create_role().role_name(name).assume_role_policy_document(EVENTS_TRUST).send().await.unwrap();
    let policy =
        format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":"*"}}]}}"#);
    iam.put_role_policy().role_name(name).policy_name("p").policy_document(policy).send().await.unwrap();
    r.role().unwrap().arn().to_string()
}

fn order_event() -> PutEventsRequestEntry {
    PutEventsRequestEntry::builder().source("shop").detail_type("Order placed").detail(r#"{"id":"o-1"}"#).build()
}

#[tokio::test]
async fn ecs_targets_run_a_task_per_event() {
    let mws = Mws::start_with(mws::Config {
        ec2_backend: mws_ec2::BackendChoice::Metadata,
        ecs_backend: mws_ecs::BackendChoice::Metadata,
        ..Default::default()
    })
    .await;
    let cfg = mws.root_sdk_config().await;
    let ecs = aws_sdk_ecs::Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let subnets = ec2.describe_subnets().send().await.unwrap();
    let subnet = subnets.subnets()[0].subnet_id().unwrap().to_string();
    let cluster = ecs.create_cluster().cluster_name("jobs").send().await.unwrap();
    let cluster_arn = cluster.cluster().unwrap().cluster_arn().unwrap().to_string();
    let td = ecs
        .register_task_definition()
        .family("report")
        .network_mode(NetworkMode::Awsvpc)
        .requires_compatibilities(Compatibility::Fargate)
        .cpu("256")
        .memory("512")
        .container_definitions(ContainerDefinition::builder().name("report").image("busybox").build())
        .send()
        .await
        .unwrap();
    let td_arn = td.task_definition().unwrap().task_definition_arn().unwrap().to_string();
    let role = events_role(&cfg, "run-tasks", r#"["ecs:RunTask","iam:PassRole"]"#).await;

    eb.put_rule().name("nightly-report").event_pattern(r#"{"source":["shop"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("nightly-report")
        .targets(
            Target::builder()
                .id("task")
                .arn(&cluster_arn)
                .role_arn(&role)
                .input(r#"{"containerOverrides":[{"name":"report","command":["echo","hi"]}]}"#)
                .ecs_parameters(
                    EcsParameters::builder()
                        .task_definition_arn(&td_arn)
                        .task_count(1)
                        .launch_type(LaunchType::Fargate)
                        .network_configuration(
                            NetworkConfiguration::builder()
                                .awsvpc_configuration(AwsVpcConfiguration::builder().subnets(&subnet).build().unwrap())
                                .build(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    eb.put_events().entries(order_event()).send().await.unwrap();

    for _ in 0..200 {
        let listed = ecs.list_tasks().cluster("jobs").started_by("events-rule/nightly-report").send().await.unwrap();
        if let Some(arn) = listed.task_arns().first() {
            let d = ecs.describe_tasks().cluster("jobs").tasks(arn).send().await.unwrap();
            let task = &d.tasks()[0];
            assert_eq!(task.task_definition_arn(), Some(td_arn.as_str()));
            let overrides = task.overrides().unwrap();
            assert_eq!(overrides.container_overrides()[0].command(), ["echo", "hi"]);
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no task was started by the rule");
}

#[tokio::test]
async fn ssm_document_targets_send_run_commands() {
    let mws =
        Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = aws_sdk_ssm::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    iam.create_role().role_name("node").assume_role_policy_document(trust).send().await.unwrap();
    iam.create_instance_profile().instance_profile_name("node").send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name("node").role_name("node").send().await.unwrap();
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(aws_sdk_ec2::types::Filter::builder().name("name").values("al2023-ami-*").build())
        .send()
        .await
        .unwrap();
    let image = images.images()[0].image_id().unwrap().to_string();
    let instance = ec2
        .run_instances()
        .image_id(image)
        .min_count(1)
        .max_count(1)
        .iam_instance_profile(IamInstanceProfileSpecification::builder().name("node").build())
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Instance)
                .tags(aws_sdk_ec2::types::Tag::builder().key("Role").value("web").build())
                .build(),
        )
        .send()
        .await
        .unwrap()
        .instances()[0]
        .instance_id()
        .unwrap()
        .to_string();
    for _ in 0..200 {
        let d = ec2.describe_instances().instance_ids(&instance).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().and_then(|s| s.name()) == Some(&InstanceStateName::Running) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let role = events_role(&cfg, "send-commands", r#"["ssm:SendCommand"]"#).await;
    eb.put_rule().name("on-order").event_pattern(r#"{"source":["shop"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("on-order")
        .targets(
            Target::builder()
                .id("cmd")
                .arn("arn:aws:ssm:us-east-1::document/AWS-RunShellScript")
                .role_arn(&role)
                .input(r#"{"commands":["echo order"]}"#)
                .run_command_parameters(
                    RunCommandParameters::builder()
                        .run_command_targets(RunCommandTarget::builder().key("tag:Role").values("web").build().unwrap())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    eb.put_events().entries(order_event()).send().await.unwrap();

    for _ in 0..200 {
        let listed = ssm.list_commands().send().await.unwrap();
        if let Some(c) = listed.commands().first() {
            assert_eq!(c.document_name(), Some("AWS-RunShellScript"));
            assert_eq!(c.parameters().unwrap()["commands"], ["echo order"]);
            assert_eq!(c.target_count(), 1);
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the rule sent no command");
}
