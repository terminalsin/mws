//! Systems Manager fidelity, through the official Rust SDK: `iam:PassRole`
//! on roles handed to Systems Manager, invocations that appear a moment
//! after `SendCommand`, Run Command plugins and schema 2.2 control flow,
//! command output in S3, and SSM's EventBridge events.

use std::time::Duration;

use aws_sdk_ec2::types::{Filter, IamInstanceProfileSpecification, InstanceStateName};
use aws_sdk_ssm::error::ProvideErrorMetadata;
use aws_sdk_ssm::types::{CommandInvocationStatus, DocumentType};
use aws_sdk_ssm::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn metadata_mws() -> Mws {
    Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await
}

/// A managed node whose instance profile role may write to S3.
async fn node(mws: &Mws) -> String {
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    iam.create_role().role_name("node").assume_role_policy_document(trust).send().await.unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:*","ssmmessages:*","ec2messages:*","s3:*","logs:*"],"Resource":"*"}]}"#;
    iam.put_role_policy().role_name("node").policy_name("core").policy_document(policy).send().await.unwrap();
    iam.create_instance_profile().instance_profile_name("node").send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name("node").role_name("node").send().await.unwrap();
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("al2023-ami-2023*-x86_64").build())
        .send()
        .await
        .unwrap();
    let image = images.images()[0].image_id().unwrap().to_string();
    let run = ec2
        .run_instances()
        .image_id(image)
        .min_count(1)
        .max_count(1)
        .iam_instance_profile(IamInstanceProfileSpecification::builder().name("node").build())
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().and_then(|s| s.name()) == Some(&InstanceStateName::Running) {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("instance {id} never ran");
}

async fn finished(
    ssm: &Client,
    command: &str,
    instance: &str,
    plugin: Option<&str>,
) -> aws_sdk_ssm::operation::get_command_invocation::GetCommandInvocationOutput {
    for _ in 0..240 {
        let r = ssm
            .get_command_invocation()
            .command_id(command)
            .instance_id(instance)
            .set_plugin_name(plugin.map(str::to_string))
            .send()
            .await;
        if let Ok(out) = r {
            if !matches!(out.status(), Some(CommandInvocationStatus::Pending | CommandInvocationStatus::InProgress)) {
                return out;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("command {command} never finished");
}

#[tokio::test]
async fn pass_role_is_required_for_roles_handed_to_ssm() {
    let mws = Mws::start().await;
    let root = Client::new(&mws.root_sdk_config().await);
    let role = format!("arn:aws:iam::{ACCOUNT}:role/automation");
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:*","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "operator", Some(policy)).await;
    let ssm = Client::new(&cfg);
    let e = ssm
        .start_automation_execution()
        .document_name("AWS-StopEC2Instance")
        .parameters("InstanceId", vec!["i-1234567890abcdef0".into()])
        .parameters("AutomationAssumeRole", vec![role.clone()])
        .send()
        .await
        .unwrap_err();
    let e = e.into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"));
    assert!(e.message().unwrap().contains("iam:PassRole"), "{:?}", e.message());

    let window = root
        .create_maintenance_window()
        .name("window")
        .schedule("rate(1 day)")
        .duration(2)
        .cutoff(1)
        .allow_unassociated_targets(true)
        .send()
        .await
        .unwrap();
    let e = ssm
        .register_task_with_maintenance_window()
        .window_id(window.window_id().unwrap())
        .task_arn("AWS-StopEC2Instance")
        .task_type(aws_sdk_ssm::types::MaintenanceWindowTaskType::Automation)
        .service_role_arn(&role)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "AccessDeniedException");

    // With iam:PassRole for ssm.amazonaws.com the execution starts.
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"ssm:*","Resource":"*"}},{{"Effect":"Allow","Action":"iam:PassRole","Resource":"{role}","Condition":{{"StringEquals":{{"iam:PassedToService":"ssm.amazonaws.com"}}}}}}]}}"#
    );
    let (_, cfg) = user_with_policy(&mws, "passer", Some(&policy)).await;
    Client::new(&cfg)
        .start_automation_execution()
        .document_name("AWS-StopEC2Instance")
        .parameters("InstanceId", vec!["i-1234567890abcdef0".into()])
        .parameters("AutomationAssumeRole", vec![role])
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn plugins_control_flow_output_and_events() {
    let mws = metadata_mws().await;
    let cfg = mws.root_sdk_config().await;
    let ssm = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let instance = node(&mws).await;

    // Command status events reach EventBridge.
    let url = sqs.create_queue().queue_name("ssm-events").send().await.unwrap().queue_url.unwrap();
    let queue = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:ssm-events");
    let qpolicy = serde_json::json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":queue}]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, qpolicy.to_string())
        .send()
        .await
        .unwrap();
    eb.put_rule()
        .name("commands")
        .event_pattern(r#"{"source":["aws.ssm"],"detail-type":["EC2 Command Status-change Notification"]}"#)
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("commands")
        .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(&queue).build().unwrap())
        .send()
        .await
        .unwrap();

    s3.create_bucket().bucket("command-output").send().await.unwrap();
    let doc = r#"{
      "schemaVersion": "2.2",
      "description": "control flow",
      "mainSteps": [
        {"action": "aws:runPowerShellScript", "name": "windowsOnly", "inputs": {"runCommand": ["dir"]}},
        {"action": "aws:downloadContent", "name": "fetch", "inputs": {"sourceType": "SSMDocument", "sourceInfo": "{\"name\": \"AWS-RunShellScript\"}"}},
        {"action": "aws:configurePackage", "name": "install", "inputs": {"name": "NoSuchPackage", "action": "Install", "onFailure": "exit"}},
        {"action": "aws:runShellScript", "name": "never", "inputs": {"runCommand": ["echo no"]}},
        {"action": "aws:runShellScript", "name": "cleanup", "inputs": {"runCommand": ["echo bye"], "finallyStep": true}}
      ]
    }"#;
    ssm.create_document().name("Flow").document_type(DocumentType::Command).content(doc).send().await.unwrap();
    let sent = ssm
        .send_command()
        .document_name("Flow")
        .instance_ids(&instance)
        .output_s3_bucket_name("command-output")
        .output_s3_key_prefix("runs")
        .send()
        .await
        .unwrap();
    let id = sent.command().unwrap().command_id().unwrap().to_string();

    // The invocation is not there for the first moment.
    let e = ssm.get_command_invocation().command_id(&id).instance_id(&instance).plugin_name("fetch").send().await;
    assert_eq!(code(e.unwrap_err().into_service_error()), "InvocationDoesNotExist");

    let fetch = finished(&ssm, &id, &instance, Some("fetch")).await;
    assert_eq!(fetch.status(), Some(&CommandInvocationStatus::Success));
    assert!(fetch.standard_output_content().unwrap().contains("Content downloaded to"));
    let key = format!("runs/{id}/{instance}/awsdownloadContent/fetch/stdout");
    assert!(fetch.standard_output_url().unwrap().ends_with(&key), "{:?}", fetch.standard_output_url());
    let windows = finished(&ssm, &id, &instance, Some("windowsOnly")).await;
    assert_eq!(windows.status().map(|s| s.as_str()), Some("Skipped"));
    let install = finished(&ssm, &id, &instance, Some("install")).await;
    assert_eq!(install.status(), Some(&CommandInvocationStatus::Failed));
    let never = finished(&ssm, &id, &instance, Some("never")).await;
    assert_eq!(never.status().map(|s| s.as_str()), Some("Skipped"));
    let cleanup = finished(&ssm, &id, &instance, Some("cleanup")).await;
    assert_eq!(cleanup.status(), Some(&CommandInvocationStatus::Success));
    let command = ssm.list_commands().command_id(&id).send().await.unwrap();
    assert_eq!(command.commands()[0].status().map(|s| s.as_str()), Some("Failed"));
    s3.get_object().bucket("command-output").key(&key).send().await.unwrap();

    // Pending, InProgress and Failed each reach the queue.
    let mut statuses = Vec::new();
    for _ in 0..60 {
        let r = sqs.receive_message().queue_url(&url).max_number_of_messages(10).send().await.unwrap();
        for m in r.messages() {
            let v: serde_json::Value = serde_json::from_str(m.body().unwrap()).unwrap();
            assert_eq!(v["detail"]["command-id"], id.as_str());
            statuses.push(v["detail"]["status"].as_str().unwrap().to_string());
        }
        if statuses.iter().any(|s| s == "Failed") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(statuses.contains(&"Failed".to_string()), "{statuses:?}");
    assert!(statuses.contains(&"InProgress".to_string()), "{statuses:?}");
}
