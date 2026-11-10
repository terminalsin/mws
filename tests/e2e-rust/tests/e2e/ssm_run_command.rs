//! Systems Manager beyond Parameter Store, through the official Rust SDK:
//! documents, managed nodes and Run Command, maintenance windows that run
//! on the emulated clock, and patch baselines.

use std::time::Duration;

use aws_sdk_ec2::types::{Filter, IamInstanceProfileSpecification, InstanceStateName, ResourceType, TagSpecification};
use aws_sdk_ssm::error::ProvideErrorMetadata;
use aws_sdk_ssm::types::{
    CommandInvocationStatus, DocumentFilter, DocumentFilterKey, DocumentFormat, DocumentKeyValuesFilter,
    DocumentPermissionType, MaintenanceWindowExecutionStatus, MaintenanceWindowResourceType, MaintenanceWindowTaskType,
    OperatingSystem, PatchFilter, PatchFilterGroup, PatchFilterKey, PatchRule, PatchRuleGroup, ResourceTypeForTagging,
    Tag, Target,
};
use aws_sdk_ssm::Client;
use mws_e2e::Mws;

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn metadata_mws() -> Mws {
    Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await
}

/// An instance profile whose role EC2 may assume.
async fn profile(mws: &Mws, name: &str) {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    // The agent registers only when the role may call ssm:UpdateInstanceInformation.
    let core = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:UpdateInstanceInformation","ssmmessages:*","ec2messages:*"],"Resource":"*"}]}"#;
    iam.put_role_policy().role_name(name).policy_name("ssm-core").policy_document(core).send().await.unwrap();
    iam.create_instance_profile().instance_profile_name(name).send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name(name).role_name(name).send().await.unwrap();
}

async fn ami(ec2: &aws_sdk_ec2::Client, pattern: &str) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values(pattern).build())
        .send()
        .await
        .unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

async fn launch(ec2: &aws_sdk_ec2::Client, image: &str, profile: Option<&str>, role_tag: &str) -> String {
    let mut run = ec2.run_instances().image_id(image).min_count(1).max_count(1).tag_specifications(
        TagSpecification::builder()
            .resource_type(ResourceType::Instance)
            .tags(aws_sdk_ec2::types::Tag::builder().key("Role").value(role_tag).build())
            .build(),
    );
    if let Some(p) = profile {
        run = run.iam_instance_profile(IamInstanceProfileSpecification::builder().name(p).build());
    }
    let id = run.send().await.unwrap().instances()[0].instance_id().unwrap().to_string();
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().and_then(|s| s.name()) == Some(&InstanceStateName::Running) {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("instance {id} never ran");
}

/// Wait for a command invocation to finish; its final state.
async fn finished(
    ssm: &Client,
    command: &str,
    instance: &str,
) -> aws_sdk_ssm::operation::get_command_invocation::GetCommandInvocationOutput {
    for _ in 0..240 {
        // Invocations appear a moment after SendCommand, as in AWS.
        let out = match ssm.get_command_invocation().command_id(command).instance_id(instance).send().await {
            Ok(out) => out,
            Err(e) if e.as_service_error().is_some_and(|s| s.is_invocation_does_not_exist()) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            Err(e) => panic!("{e:?}"),
        };
        if !matches!(
            out.status(),
            Some(
                CommandInvocationStatus::Pending
                    | CommandInvocationStatus::InProgress
                    | CommandInvocationStatus::Delayed
            )
        ) {
            return out;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("command {command} never finished on {instance}");
}

#[tokio::test]
async fn documents_versions_and_sharing() {
    let mws = Mws::start().await;
    let ssm = Client::new(&mws.root_sdk_config().await);
    let yaml = "schemaVersion: '2.2'\ndescription: Say hello\nparameters:\n  who:\n    type: String\n    default: world\nmainSteps:\n- action: aws:runShellScript\n  name: hello\n  inputs:\n    runCommand:\n    - echo hello {{ who }}\n";
    let created = ssm
        .create_document()
        .name("Hello")
        .content(yaml)
        .document_format(DocumentFormat::Yaml)
        .version_name("first")
        .tags(Tag::builder().key("team").value("ops").build().unwrap())
        .send()
        .await
        .unwrap();
    let d = created.document_description().unwrap();
    assert_eq!(d.document_version(), Some("1"));
    assert_eq!(d.platform_types().len(), 2, "aws:runShellScript runs on Linux and macOS");
    assert_eq!(d.parameters()[0].default_value(), Some("world"));
    let e = ssm
        .create_document()
        .name("Hello")
        .content(yaml)
        .document_format(DocumentFormat::Yaml)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "DocumentAlreadyExists");
    let e = ssm.create_document().name("Broken").content("{").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidDocumentContent");

    // JSON on request.
    let got = ssm.get_document().name("Hello").document_format(DocumentFormat::Json).send().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(got.content().unwrap()).unwrap();
    assert_eq!(json["mainSteps"][0]["name"], "hello");

    let e = ssm
        .update_document()
        .name("Hello")
        .content(yaml)
        .document_format(DocumentFormat::Yaml)
        .document_version("$LATEST")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "DuplicateDocumentContent");
    let v2 = yaml.replace("hello {{ who }}", "hi {{ who }}");
    let updated = ssm
        .update_document()
        .name("Hello")
        .content(&v2)
        .document_format(DocumentFormat::Yaml)
        .document_version("$LATEST")
        .send()
        .await
        .unwrap();
    assert_eq!(updated.document_description().unwrap().latest_version(), Some("2"));
    assert_eq!(updated.document_description().unwrap().default_version(), Some("1"));
    ssm.update_document_default_version().name("Hello").document_version("2").send().await.unwrap();
    let versions = ssm.list_document_versions().name("Hello").send().await.unwrap();
    assert_eq!(versions.document_versions().len(), 2);
    assert!(versions.document_versions().iter().any(|v| v.document_version() == Some("2") && v.is_default_version()));
    let e = ssm.delete_document().name("Hello").document_version("2").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidDocumentOperation");
    ssm.delete_document().name("Hello").version_name("first").send().await.unwrap();

    // Mine, and AWS's.
    let mine = ssm
        .list_documents()
        .filters(DocumentKeyValuesFilter::builder().key("Owner").values("Self").build())
        .send()
        .await
        .unwrap();
    assert_eq!(mine.document_identifiers().len(), 1);
    let amazon = ssm
        .list_documents()
        .document_filter_list(
            DocumentFilter::builder().key(DocumentFilterKey::Name).value("AWS-RunShellScript").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(amazon.document_identifiers()[0].owner(), Some("Amazon"));
    let shell = ssm.describe_document().name("AWS-RunShellScript").send().await.unwrap();
    assert_eq!(shell.document().unwrap().schema_version(), Some("1.2"));
    let e = ssm.update_document().name("AWS-RunShellScript").content("{}").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidDocumentOperation");

    ssm.modify_document_permission()
        .name("Hello")
        .permission_type(DocumentPermissionType::Share)
        .account_ids_to_add("210987654321")
        .send()
        .await
        .unwrap();
    let perms = ssm
        .describe_document_permission()
        .name("Hello")
        .permission_type(DocumentPermissionType::Share)
        .send()
        .await
        .unwrap();
    assert_eq!(perms.account_ids(), ["210987654321"]);

    let tags = ssm
        .list_tags_for_resource()
        .resource_type(ResourceTypeForTagging::Document)
        .resource_id("Hello")
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tag_list()[0].key(), "team");
    ssm.delete_document().name("Hello").send().await.unwrap();
    let e = ssm.describe_document().name("Hello").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidDocument");
}

#[tokio::test]
async fn run_command_on_managed_instances() {
    let mws = metadata_mws().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    profile(&mws, "ssm-node").await;
    let image = ami(&ec2, "al2023-ami-2023*-x86_64").await;
    let managed = launch(&ec2, &image, Some("ssm-node"), "web").await;
    let unmanaged = launch(&ec2, &image, None, "web").await;
    // A role that may not call ssm:UpdateInstanceInformation: the agent
    // never registers.
    let iam = aws_sdk_iam::Client::new(&cfg);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    iam.create_role().role_name("bare").assume_role_policy_document(trust).send().await.unwrap();
    iam.create_instance_profile().instance_profile_name("bare").send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name("bare").role_name("bare").send().await.unwrap();
    let unregistered = launch(&ec2, &image, Some("bare"), "db").await;

    // Only instances whose instance profile lets the agent register are
    // managed nodes.
    let info = ssm.describe_instance_information().send().await.unwrap();
    let nodes = info.instance_information_list();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].instance_id(), Some(managed.as_str()));
    assert_eq!(nodes[0].ping_status().map(|p| p.as_str()), Some("Online"));
    assert_eq!(nodes[0].platform_name(), Some("Amazon Linux"));
    assert_eq!(nodes[0].platform_version(), Some("2023"));
    assert_eq!(nodes[0].iam_role(), Some("ssm-node"));

    let e = ssm
        .send_command()
        .document_name("AWS-RunShellScript")
        .instance_ids(&unmanaged)
        .parameters("commands", vec!["true".into()])
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidInstanceId");
    let e = ssm
        .send_command()
        .document_name("AWS-RunShellScript")
        .instance_ids(&unregistered)
        .parameters("commands", vec!["true".into()])
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidInstanceId");
    let e = ssm.send_command().document_name("AWS-RunShellScript").instance_ids(&managed).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidParameters", "commands is required");

    // Targets by tag reach the managed node only.
    let sent = ssm
        .send_command()
        .document_name("AWS-RunShellScript")
        .targets(Target::builder().key("tag:Role").values("web").build())
        .parameters("commands", vec!["echo hi".into()])
        .comment("hello")
        .send()
        .await
        .unwrap();
    let command = sent.command().unwrap();
    let id = command.command_id().unwrap().to_string();
    assert_eq!(command.target_count(), 1);
    let out = finished(&ssm, &id, &managed).await;
    assert_eq!(out.status(), Some(&CommandInvocationStatus::Success));
    assert_eq!(out.response_code(), 0);
    assert_eq!(out.plugin_name(), Some("aws:runShellScript"));

    let listed = ssm.list_commands().command_id(&id).send().await.unwrap();
    assert_eq!(listed.commands()[0].comment(), Some("hello"));
    assert_eq!(listed.commands()[0].completed_count(), 1);
    let invocations = ssm.list_command_invocations().command_id(&id).details(true).send().await.unwrap();
    assert_eq!(invocations.command_invocations()[0].command_plugins().len(), 1);
    let e = ssm.get_command_invocation().command_id(&id).instance_id(&unmanaged).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvocationDoesNotExist");

    // A stopped node loses its connection.
    ec2.stop_instances().instance_ids(&managed).send().await.unwrap();
    for _ in 0..240 {
        let info = ssm.describe_instance_information().send().await.unwrap();
        if info.instance_information_list()[0].ping_status().map(|p| p.as_str()) == Some("ConnectionLost") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the stopped node stayed online");
}

#[tokio::test]
async fn maintenance_windows_run_on_the_clock() {
    let mws = metadata_mws().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    profile(&mws, "patcher").await;
    let image = ami(&ec2, "al2023-ami-2023*-x86_64").await;
    let node = launch(&ec2, &image, Some("patcher"), "db").await;

    let e = ssm
        .create_maintenance_window()
        .name("bad")
        .schedule("rate(1 hour)")
        .duration(2)
        .cutoff(2)
        .allow_unassociated_targets(false)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    let window = ssm
        .create_maintenance_window()
        .name("nightly")
        .schedule("rate(1 hour)")
        .duration(2)
        .cutoff(1)
        .allow_unassociated_targets(false)
        .send()
        .await
        .unwrap()
        .window_id
        .unwrap();
    assert!(window.starts_with("mw-"));
    let target = ssm
        .register_target_with_maintenance_window()
        .window_id(&window)
        .resource_type(MaintenanceWindowResourceType::Instance)
        .targets(Target::builder().key("tag:Role").values("db").build())
        .owner_information("dba")
        .send()
        .await
        .unwrap()
        .window_target_id
        .unwrap();
    let task = ssm
        .register_task_with_maintenance_window()
        .window_id(&window)
        .task_arn("AWS-RunShellScript")
        .task_type(MaintenanceWindowTaskType::RunCommand)
        .targets(Target::builder().key("WindowTargetIds").values(&target).build())
        .task_invocation_parameters(
            aws_sdk_ssm::types::MaintenanceWindowTaskInvocationParameters::builder()
                .run_command(
                    aws_sdk_ssm::types::MaintenanceWindowRunCommandParameters::builder()
                        .parameters("commands", vec!["echo {{RESOURCE_ID}}".into()])
                        .build(),
                )
                .build(),
        )
        .max_concurrency("1")
        .max_errors("0")
        .send()
        .await
        .unwrap()
        .window_task_id
        .unwrap();
    let e = ssm
        .deregister_target_from_maintenance_window()
        .window_id(&window)
        .window_target_id(&target)
        .safe(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "TargetInUseException");

    let schedule = ssm.describe_maintenance_window_schedule().window_id(&window).max_results(2).send().await.unwrap();
    assert_eq!(schedule.scheduled_window_executions().len(), 2);
    let got = ssm.get_maintenance_window().window_id(&window).send().await.unwrap();
    assert!(got.next_execution_time().is_some());
    let found = ssm
        .describe_maintenance_windows_for_target()
        .targets(Target::builder().key("tag:Role").values("db").build())
        .resource_type(MaintenanceWindowResourceType::Instance)
        .send()
        .await
        .unwrap();
    assert_eq!(found.window_identities()[0].window_id(), Some(window.as_str()));

    // An hour later the window runs its task on the node.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 3700}"#)).await;
    assert_eq!(status, 200);
    let mut execution = None;
    for _ in 0..120 {
        let ex = ssm.describe_maintenance_window_executions().window_id(&window).send().await.unwrap();
        if let Some(e) = ex.window_executions().first() {
            if e.status() == Some(&MaintenanceWindowExecutionStatus::Success) {
                execution = e.window_execution_id().map(str::to_string);
                break;
            }
            assert_ne!(e.status(), Some(&MaintenanceWindowExecutionStatus::Failed), "{:?}", e.status_details());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let execution = execution.expect("the window ran");
    let tasks = ssm.describe_maintenance_window_execution_tasks().window_execution_id(&execution).send().await.unwrap();
    let task_execution = tasks.window_execution_task_identities()[0].task_execution_id().unwrap().to_string();
    let invocations = ssm
        .describe_maintenance_window_execution_task_invocations()
        .window_execution_id(&execution)
        .task_id(&task_execution)
        .send()
        .await
        .unwrap();
    let inv = &invocations.window_execution_task_invocation_identities()[0];
    assert_eq!(inv.owner_information(), Some("dba"));
    assert!(inv.parameters().unwrap().contains(&format!("echo {node}")), "{{{{RESOURCE_ID}}}} is the instance id");
    let command = inv.execution_id().unwrap();
    let out = finished(&ssm, command, &node).await;
    assert_eq!(out.status(), Some(&CommandInvocationStatus::Success));

    ssm.deregister_task_from_maintenance_window().window_id(&window).window_task_id(&task).send().await.unwrap();
    ssm.delete_maintenance_window().window_id(&window).send().await.unwrap();
    let e = ssm.get_maintenance_window().window_id(&window).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "DoesNotExistException");
}

#[tokio::test]
async fn patch_baselines_and_groups() {
    let mws = Mws::start().await;
    let ssm = Client::new(&mws.root_sdk_config().await);
    let aws = ssm
        .describe_patch_baselines()
        .filters(aws_sdk_ssm::types::PatchOrchestratorFilter::builder().key("OWNER").values("AWS").build())
        .send()
        .await
        .unwrap();
    assert!(aws
        .baseline_identities()
        .iter()
        .any(|b| b.baseline_name() == Some("AWS-AmazonLinux2023DefaultPatchBaseline") && b.default_baseline()));
    let default =
        ssm.get_default_patch_baseline().operating_system(OperatingSystem::AmazonLinux2023).send().await.unwrap();
    assert!(default.baseline_id().unwrap().contains(":patchbaseline/pb-"));

    let rules = PatchRuleGroup::builder()
        .patch_rules(
            PatchRule::builder()
                .patch_filter_group(
                    PatchFilterGroup::builder()
                        .patch_filters(
                            PatchFilter::builder()
                                .key(PatchFilterKey::Classification)
                                .values("Security")
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .approve_after_days(3)
                .build(),
        )
        .build()
        .unwrap();
    let id = ssm
        .create_patch_baseline()
        .name("strict")
        .operating_system(OperatingSystem::AmazonLinux2023)
        .approval_rules(rules)
        .send()
        .await
        .unwrap()
        .baseline_id
        .unwrap();
    ssm.register_default_patch_baseline().baseline_id(&id).send().await.unwrap();
    let default =
        ssm.get_default_patch_baseline().operating_system(OperatingSystem::AmazonLinux2023).send().await.unwrap();
    assert_eq!(default.baseline_id(), Some(id.as_str()));
    ssm.register_patch_baseline_for_patch_group().baseline_id(&id).patch_group("prod").send().await.unwrap();
    let e =
        ssm.register_patch_baseline_for_patch_group().baseline_id(&id).patch_group("prod").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "AlreadyExistsException");
    let groups = ssm.describe_patch_groups().send().await.unwrap();
    assert_eq!(groups.mappings()[0].patch_group(), Some("prod"));
    let got = ssm.get_patch_baseline().baseline_id(&id).send().await.unwrap();
    assert_eq!(got.patch_groups(), ["prod"]);
    let for_group = ssm
        .get_patch_baseline_for_patch_group()
        .patch_group("prod")
        .operating_system(OperatingSystem::AmazonLinux2023)
        .send()
        .await
        .unwrap();
    assert_eq!(for_group.baseline_id(), Some(id.as_str()));

    let e = ssm.delete_patch_baseline().baseline_id(&id).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ResourceInUseException");
    ssm.deregister_patch_baseline_for_patch_group().baseline_id(&id).patch_group("prod").send().await.unwrap();
    let aws_default = aws
        .baseline_identities()
        .iter()
        .find(|b| b.baseline_name() == Some("AWS-AmazonLinux2023DefaultPatchBaseline"))
        .and_then(|b| b.baseline_id())
        .unwrap()
        .to_string();
    ssm.register_default_patch_baseline().baseline_id(&aws_default).send().await.unwrap();
    ssm.delete_patch_baseline().baseline_id(&id).send().await.unwrap();
    let e = ssm.get_patch_baseline().baseline_id(&id).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "DoesNotExistException");
}

#[tokio::test]
async fn commands_really_run_in_docker_instances() {
    let docker = std::process::Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !docker {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { ec2_backend: mws_ec2::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    profile(&mws, "runner").await;
    let image = ami(&ec2, "mws-alpine-*").await;
    let node = launch(&ec2, &image, Some("runner"), "app").await;

    let sent = ssm
        .send_command()
        .document_name("AWS-RunShellScript")
        .instance_ids(&node)
        .parameters("commands", vec!["echo hello from $(pwd)".into(), "uname -s".into()])
        .parameters("workingDirectory", vec!["/tmp".into()])
        .send()
        .await
        .unwrap();
    let id = sent.command().unwrap().command_id().unwrap().to_string();
    let out = finished(&ssm, &id, &node).await;
    assert_eq!(out.status(), Some(&CommandInvocationStatus::Success), "{:?}", out.standard_error_content());
    assert_eq!(out.standard_output_content(), Some("hello from /tmp\nLinux\n"));

    let failing = ssm
        .send_command()
        .document_name("AWS-RunShellScript")
        .instance_ids(&node)
        .parameters("commands", vec!["echo oops >&2".into(), "exit 3".into()])
        .send()
        .await
        .unwrap();
    let id = failing.command().unwrap().command_id().unwrap().to_string();
    let out = finished(&ssm, &id, &node).await;
    assert_eq!(out.status(), Some(&CommandInvocationStatus::Failed));
    assert_eq!(out.response_code(), 3);
    assert!(out.standard_error_content().unwrap().starts_with("oops\n"));
    ec2.terminate_instances().instance_ids(&node).send().await.unwrap();
}
