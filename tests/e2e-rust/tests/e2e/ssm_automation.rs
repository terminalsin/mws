//! Systems Manager Automation, Change Manager and OpsCenter through the
//! official Rust SDK: runbooks that call other services, branch, wait on
//! the emulated clock, run scripts, wait for approval and fan out over
//! targets; change requests; OpsItems from the API and from EventBridge.

use std::time::Duration;

use aws_sdk_ec2::types::{Filter, InstanceStateName, ResourceType, TagSpecification};
use aws_sdk_ssm::error::ProvideErrorMetadata;
use aws_sdk_ssm::types::{
    AutomationExecution, AutomationExecutionFilter, AutomationExecutionFilterKey, AutomationExecutionStatus,
    DocumentType, OpsFilter, OpsItemDataType, OpsItemDataValue, OpsItemFilter, OpsItemFilterKey, OpsItemFilterOperator,
    OpsItemStatus, Runbook, SignalType, Target,
};
use aws_sdk_ssm::Client;
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn metadata_mws() -> Mws {
    Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await
}

async fn launch(ec2: &aws_sdk_ec2::Client, env: &str) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("al2023-ami-*").build())
        .send()
        .await
        .unwrap();
    let image = images.images()[0].image_id().unwrap().to_string();
    let out = ec2
        .run_instances()
        .image_id(image)
        .min_count(1)
        .max_count(1)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Instance)
                .tags(aws_sdk_ec2::types::Tag::builder().key("Env").value(env).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let id = out.instances()[0].instance_id().unwrap().to_string();
    wait_state(ec2, &id, InstanceStateName::Running).await;
    id
}

async fn wait_state(ec2: &aws_sdk_ec2::Client, id: &str, want: InstanceStateName) {
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().and_then(|s| s.name()) == Some(&want) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("instance {id} never reached {want:?}");
}

/// Poll an execution until `done` says so.
async fn wait_for(ssm: &Client, id: &str, done: impl Fn(&AutomationExecution) -> bool) -> AutomationExecution {
    for _ in 0..300 {
        let e = ssm.get_automation_execution().automation_execution_id(id).send().await.unwrap();
        let e = e.automation_execution().unwrap().clone();
        if done(&e) {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let e = ssm.get_automation_execution().automation_execution_id(id).send().await.unwrap();
    panic!("execution {id} never got there: {:#?}", e.automation_execution());
}

fn finished(e: &AutomationExecution) -> bool {
    matches!(
        e.automation_execution_status(),
        Some(
            AutomationExecutionStatus::Success
                | AutomationExecutionStatus::Failed
                | AutomationExecutionStatus::Cancelled
                | AutomationExecutionStatus::Timedout
                | AutomationExecutionStatus::Rejected
        )
    )
}

fn waiting(e: &AutomationExecution) -> bool {
    e.automation_execution_status() == Some(&AutomationExecutionStatus::Waiting)
}

async fn create_runbook(ssm: &Client, name: &str, content: &str) {
    ssm.create_document().name(name).document_type(DocumentType::Automation).content(content).send().await.unwrap();
}

/// A role Systems Manager may assume, allowed `actions`.
async fn automation_role(cfg: &aws_config::SdkConfig, name: &str, actions: &str) -> String {
    let iam = aws_sdk_iam::Client::new(cfg);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ssm.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    let policy =
        format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":"*"}}]}}"#);
    iam.put_role_policy().role_name(name).policy_name("p").policy_document(policy).send().await.unwrap();
    role.role().unwrap().arn().to_string()
}

const RUNBOOK: &str = r#"
schemaVersion: '0.3'
description: Inspect an instance, wait, compute and report.
parameters:
  InstanceId:
    type: String
  Greeting:
    type: String
    default: hello
outputs:
  - describe.State
  - compute.Sum
  - report.Message
variables:
  Attempts:
    type: Integer
    default: 0
mainSteps:
  - name: describe
    action: aws:executeAwsApi
    inputs:
      Service: ec2
      Api: DescribeInstances
      InstanceIds:
        - '{{ InstanceId }}'
    outputs:
      - Name: State
        Selector: $.Reservations[0].Instances[0].State.Name
        Type: String
      - Name: Ids
        Selector: $.Reservations[*].Instances[*].InstanceId
        Type: StringList
  - name: check
    action: aws:branch
    inputs:
      Choices:
        - NextStep: running
          Variable: '{{ describe.State }}'
          StringEquals: running
      Default: notRunning
  - name: notRunning
    action: aws:executeAwsApi
    isEnd: true
    inputs:
      Service: ec2
      Api: DescribeInstances
  - name: running
    action: aws:assertAwsResourceProperty
    inputs:
      Service: ec2
      Api: DescribeInstances
      InstanceIds:
        - '{{ InstanceId }}'
      PropertySelector: $.Reservations[0].Instances[0].State.Name
      DesiredValues:
        - running
  - name: nap
    action: aws:sleep
    inputs:
      Duration: PT30M
  - name: count
    action: aws:updateVariable
    inputs:
      Name: variable:Attempts
      Value: 1
  - name: compute
    action: aws:executeScript
    inputs:
      Runtime: python3.11
      Handler: handler
      InputPayload:
        a: 2
        b: 40
        ids: '{{ describe.Ids }}'
      Script: |-
        def handler(events, context):
            return {"sum": events["a"] + events["b"], "count": len(events["ids"])}
    outputs:
      - Name: Sum
        Selector: $.Payload.sum
        Type: Integer
  - name: report
    action: aws:executeAwsApi
    inputs:
      Service: ssm
      Api: PutParameter
      Name: /automation/{{ automation:EXECUTION_ID }}
      Value: '{{ Greeting }} {{ compute.Sum }} {{ global:ACCOUNT_ID }}'
      Type: String
    outputs:
      - Name: Message
        Selector: $.Version
        Type: Integer
"#;

#[tokio::test]
async fn runbooks_call_services_branch_sleep_and_run_scripts() {
    let mws = metadata_mws().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    let instance = launch(&ec2, "dev").await;
    ssm.create_document()
        .name("inspect")
        .document_type(DocumentType::Automation)
        .document_format(aws_sdk_ssm::types::DocumentFormat::Yaml)
        .content(RUNBOOK)
        .send()
        .await
        .unwrap();

    let missing = ssm.start_automation_execution().document_name("inspect").send().await.unwrap_err();
    assert_eq!(code(missing), "InvalidAutomationExecutionParametersException");
    let unknown = ssm.start_automation_execution().document_name("nope").send().await.unwrap_err();
    assert_eq!(code(unknown), "AutomationDefinitionNotFoundException");

    let id = ssm
        .start_automation_execution()
        .document_name("inspect")
        .parameters("InstanceId", vec![instance.clone()])
        .send()
        .await
        .unwrap()
        .automation_execution_id()
        .unwrap()
        .to_string();
    // The run sleeps for 30 minutes on the emulated clock.
    let e = wait_for(&ssm, &id, |e| e.current_step_name() == Some("nap")).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Inprogress));
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 1900}"#)).await;
    assert_eq!(status, 200);
    let e = wait_for(&ssm, &id, finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Success), "{e:#?}");
    let outputs = e.outputs().unwrap();
    assert_eq!(outputs["describe.State"], vec!["running".to_string()]);
    assert_eq!(outputs["compute.Sum"], vec!["42".to_string()]);
    assert_eq!(outputs["report.Message"], vec!["1".to_string()]);
    assert_eq!(e.variables().unwrap()["Attempts"], vec!["1".to_string()]);
    assert_eq!(e.executed_by(), Some(format!("arn:aws:iam::{ACCOUNT}:root").as_str()));
    let steps = e.step_executions();
    let status_of = |n: &str| steps.iter().find(|s| s.step_name() == Some(n)).and_then(|s| s.step_status()).cloned();
    assert_eq!(status_of("notRunning"), Some(AutomationExecutionStatus::Pending));
    assert_eq!(status_of("running"), Some(AutomationExecutionStatus::Success));
    let check = steps.iter().find(|s| s.step_name() == Some("check")).unwrap();
    assert_eq!(check.valid_next_steps(), ["running", "notRunning"]);
    let p = ssm.get_parameter().name(format!("/automation/{id}")).send().await.unwrap();
    assert_eq!(p.parameter().unwrap().value(), Some(format!("hello 42 {ACCOUNT}").as_str()));

    let step_list = ssm
        .describe_automation_step_executions()
        .automation_execution_id(&id)
        .filters(
            aws_sdk_ssm::types::StepExecutionFilter::builder()
                .key(aws_sdk_ssm::types::StepExecutionFilterKey::Action)
                .values("aws:executeAwsApi")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(step_list.step_executions().len(), 3);
    let listed = ssm
        .describe_automation_executions()
        .filters(
            AutomationExecutionFilter::builder()
                .key(AutomationExecutionFilterKey::DocumentNamePrefix)
                .values("insp")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(listed.automation_execution_metadata_list().len(), 1);

    // An API error fails the step, and onFailure Abort fails the run.
    create_runbook(
        &ssm,
        "broken",
        r#"{"schemaVersion":"0.3","mainSteps":[{"name":"bad","action":"aws:executeAwsApi","inputs":{"Service":"ec2","Api":"DescribeInstances","InstanceIds":["i-0000000000000dead"]}}]}"#,
    )
    .await;
    let id = ssm.start_automation_execution().document_name("broken").send().await.unwrap();
    let e = wait_for(&ssm, id.automation_execution_id().unwrap(), finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Failed));
    let step = &e.step_executions()[0];
    assert!(step.failure_message().unwrap().contains("InvalidInstanceID.NotFound"), "{step:?}");
    assert!(e.failure_message().unwrap().contains("InvalidInstanceID.NotFound"));
}

#[tokio::test]
async fn assume_roles_approvals_pauses_cancel_and_rate_control() {
    let mws = metadata_mws().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    let a = launch(&ec2, "dev").await;
    let b = launch(&ec2, "dev").await;
    let c = launch(&ec2, "prod").await;
    let role = automation_role(&cfg, "automation", r#"["ec2:*"]"#).await;

    // AWS's own runbook, as an assume role.
    let id = ssm
        .start_automation_execution()
        .document_name("AWS-StopEC2Instance")
        .parameters("InstanceId", vec![a.clone()])
        .parameters("AutomationAssumeRole", vec![role.clone()])
        .send()
        .await
        .unwrap();
    let e = wait_for(&ssm, id.automation_execution_id().unwrap(), finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Success), "{e:#?}");
    wait_state(&ec2, &a, InstanceStateName::Stopped).await;

    // A role without the permission fails the step; one Systems Manager
    // may not assume fails the run.
    let weak = automation_role(&cfg, "weak", r#"["ec2:DescribeInstances"]"#).await;
    let id = ssm
        .start_automation_execution()
        .document_name("AWS-StartEC2Instance")
        .parameters("InstanceId", vec![a.clone()])
        .parameters("AutomationAssumeRole", vec![weak])
        .send()
        .await
        .unwrap();
    let e = wait_for(&ssm, id.automation_execution_id().unwrap(), finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Failed));
    assert!(e.step_executions()[0].failure_message().unwrap().contains("UnauthorizedOperation"), "{e:#?}");
    let id = ssm
        .start_automation_execution()
        .document_name("AWS-StartEC2Instance")
        .parameters("InstanceId", vec![a.clone()])
        .parameters("AutomationAssumeRole", vec![format!("arn:aws:iam::{ACCOUNT}:role/missing")])
        .send()
        .await
        .unwrap();
    let e = wait_for(&ssm, id.automation_execution_id().unwrap(), finished).await;
    assert_eq!(e.failure_message(), Some("The defined assume role is unable to be assumed."));

    // Approvals and pauses wait for signals.
    create_runbook(
        &ssm,
        "gated",
        &format!(
            r#"{{"schemaVersion":"0.3","mainSteps":[
              {{"name":"approve","action":"aws:approve","inputs":{{"Approvers":["arn:aws:iam::{ACCOUNT}:root"],"MinRequiredApprovals":1,"Message":"ok?"}}}},
              {{"name":"hold","action":"aws:pause","inputs":{{}}}},
              {{"name":"start","action":"aws:changeInstanceState","inputs":{{"InstanceIds":["{a}"],"DesiredState":"running"}}}}]}}"#
        ),
    )
    .await;
    let id = ssm.start_automation_execution().document_name("gated").send().await.unwrap();
    let id = id.automation_execution_id().unwrap().to_string();
    wait_for(&ssm, &id, |e| waiting(e) && e.current_action() == Some("aws:approve")).await;
    let early = ssm.send_automation_signal().automation_execution_id(&id).signal_type(SignalType::Resume).send().await;
    assert_eq!(code(early.unwrap_err()), "InvalidAutomationSignalException");
    ssm.send_automation_signal()
        .automation_execution_id(&id)
        .signal_type(SignalType::Approve)
        .payload("Comment", vec!["looks good".into()])
        .send()
        .await
        .unwrap();
    wait_for(&ssm, &id, |e| waiting(e) && e.current_action() == Some("aws:pause")).await;
    ssm.send_automation_signal().automation_execution_id(&id).signal_type(SignalType::Resume).send().await.unwrap();
    let e = wait_for(&ssm, &id, finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Success), "{e:#?}");
    assert_eq!(e.step_executions()[0].outputs().unwrap()["ApprovalStatus"], vec!["Approved".to_string()]);
    wait_state(&ec2, &a, InstanceStateName::Running).await;

    let id = ssm.start_automation_execution().document_name("gated").send().await.unwrap();
    let id = id.automation_execution_id().unwrap().to_string();
    wait_for(&ssm, &id, waiting).await;
    ssm.send_automation_signal().automation_execution_id(&id).signal_type(SignalType::Reject).send().await.unwrap();
    let e = wait_for(&ssm, &id, finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Failed));

    let id = ssm.start_automation_execution().document_name("gated").send().await.unwrap();
    let id = id.automation_execution_id().unwrap().to_string();
    wait_for(&ssm, &id, waiting).await;
    ssm.stop_automation_execution().automation_execution_id(&id).send().await.unwrap();
    let e = wait_for(&ssm, &id, finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Cancelled));
    let again = ssm.stop_automation_execution().automation_execution_id(&id).send().await.unwrap_err();
    assert_eq!(code(again), "InvalidAutomationStatusUpdateException");

    // Rate control: one child execution per tagged instance.
    let parent = ssm
        .start_automation_execution()
        .document_name("AWS-StopEC2Instance")
        .target_parameter_name("InstanceId")
        .targets(Target::builder().key("tag:Env").values("dev").build())
        .max_concurrency("1")
        .max_errors("0")
        .send()
        .await
        .unwrap();
    let parent = parent.automation_execution_id().unwrap().to_string();
    let e = wait_for(&ssm, &parent, finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Success), "{e:#?}");
    let mut resolved = e.resolved_targets().unwrap().parameter_values().to_vec();
    resolved.sort();
    let mut want = vec![a.clone(), b.clone()];
    want.sort();
    assert_eq!(resolved, want);
    let children = ssm
        .describe_automation_executions()
        .filters(
            AutomationExecutionFilter::builder()
                .key(AutomationExecutionFilterKey::ParentExecutionId)
                .values(&parent)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(children.automation_execution_metadata_list().len(), 2);
    wait_state(&ec2, &b, InstanceStateName::Stopped).await;
    let prod = ec2.describe_instances().instance_ids(&c).send().await.unwrap();
    assert_eq!(prod.reservations()[0].instances()[0].state().and_then(|s| s.name()), Some(&InstanceStateName::Running));

    let preview = ssm
        .start_execution_preview()
        .document_name("AWS-RestartEC2Instance")
        .execution_inputs(aws_sdk_ssm::types::ExecutionInputs::Automation(
            aws_sdk_ssm::types::AutomationExecutionInputs::builder()
                .target_parameter_name("InstanceId")
                .targets(Target::builder().key("ParameterValues").values(&a).values(&b).build())
                .build(),
        ))
        .send()
        .await
        .unwrap();
    let got =
        ssm.get_execution_preview().execution_preview_id(preview.execution_preview_id().unwrap()).send().await.unwrap();
    assert_eq!(got.status().map(|s| s.as_str()), Some("Success"));
    let aws_sdk_ssm::types::ExecutionPreview::Automation(p) = got.execution_preview().unwrap() else { panic!() };
    assert_eq!(p.step_previews().unwrap()[&aws_sdk_ssm::types::ImpactType::Mutating], 2);
    assert_eq!(p.target_previews()[0].count(), 2);
}

#[tokio::test]
async fn change_requests_and_opscenter() {
    let mws = metadata_mws().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    let instance = launch(&ec2, "dev").await;
    ec2.stop_instances().instance_ids(&instance).send().await.unwrap();
    wait_state(&ec2, &instance, InstanceStateName::Stopped).await;
    let template = format!(
        r#"{{"schemaVersion":"0.3","description":"Restart change","templateInformation":"Start a stopped instance","emergencyChange":false,"autoApprovable":false,
          "executableRunBooks":[{{"name":"AWS-StartEC2Instance","version":"1"}}],
          "mainSteps":[{{"name":"ApproveChange","action":"aws:approve","timeoutSeconds":3600,"inputs":{{"Message":"Approve the change","EnhancedApprovals":{{"Approvers":[{{"approver":"arn:aws:iam::{ACCOUNT}:root","type":"IamUser","minRequiredApprovals":1}}]}},"Approvers":[{{"approver":"arn:aws:iam::{ACCOUNT}:root","type":"IamUser","minRequiredApprovals":1}}]}}}}]}}"#
    );
    ssm.create_document()
        .name("restart-change")
        .document_type(DocumentType::ChangeTemplate)
        .content(template)
        .send()
        .await
        .unwrap();
    let auto = ssm
        .start_change_request_execution()
        .document_name("restart-change")
        .auto_approve(true)
        .runbooks(
            Runbook::builder()
                .document_name("AWS-StartEC2Instance")
                .parameters("InstanceId", vec![instance.clone()])
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(auto), "InvalidAutomationExecutionParametersException");
    let id = ssm
        .start_change_request_execution()
        .document_name("restart-change")
        .change_request_name("Start the dev box")
        .runbooks(
            Runbook::builder()
                .document_name("AWS-StartEC2Instance")
                .parameters("InstanceId", vec![instance.clone()])
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let id = id.automation_execution_id().unwrap().to_string();
    let e = wait_for(&ssm, &id, |e| {
        e.automation_execution_status() == Some(&AutomationExecutionStatus::PendingApproval)
            && e.ops_item_id().is_some()
    })
    .await;
    assert_eq!(e.automation_subtype().map(|s| s.as_str()), Some("ChangeRequest"));
    let ops_item = e.ops_item_id().unwrap().to_string();
    let item = ssm.get_ops_item().ops_item_id(&ops_item).send().await.unwrap();
    let item = item.ops_item().unwrap();
    assert_eq!(item.ops_item_type(), Some("/aws/changerequest"));
    assert_eq!(item.title(), Some("Start the dev box"));
    assert_eq!(item.status(), Some(&OpsItemStatus::PendingApproval));
    ssm.send_automation_signal().automation_execution_id(&id).signal_type(SignalType::Approve).send().await.unwrap();
    let e = wait_for(&ssm, &id, finished).await;
    assert_eq!(e.automation_execution_status(), Some(&AutomationExecutionStatus::Success), "{e:#?}");
    wait_state(&ec2, &instance, InstanceStateName::Running).await;
    let item = ssm.get_ops_item().ops_item_id(&ops_item).send().await.unwrap();
    assert_eq!(item.ops_item().unwrap().status(), Some(&OpsItemStatus::CompletedWithSuccess));

    // OpsItems from the API.
    let created = ssm
        .create_ops_item()
        .title("Disk almost full")
        .description("The root volume of the web server is at 95%")
        .source("monitoring")
        .priority(2)
        .severity("2")
        .category("Performance")
        .operational_data(
            "/aws/dedup",
            OpsItemDataValue::builder()
                .value(r#"{"dedupString":"disk-web-1"}"#)
                .r#type(OpsItemDataType::SearchableString)
                .build(),
        )
        .operational_data(
            "host",
            OpsItemDataValue::builder().value("web-1").r#type(OpsItemDataType::SearchableString).build(),
        )
        .send()
        .await
        .unwrap();
    let oi = created.ops_item_id().unwrap().to_string();
    assert!(oi.starts_with("oi-"));
    let dup = ssm
        .create_ops_item()
        .title("Disk almost full again")
        .description("x")
        .source("monitoring")
        .operational_data(
            "/aws/dedup",
            OpsItemDataValue::builder()
                .value(r#"{"dedupString":"disk-web-1"}"#)
                .r#type(OpsItemDataType::SearchableString)
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(dup), "OpsItemAlreadyExistsException");
    let bad = ssm.create_ops_item().title("t").description("d").source("aws.custom").send().await.unwrap_err();
    assert_eq!(code(bad), "OpsItemInvalidParameterException");
    ssm.update_ops_item().ops_item_id(&oi).status(OpsItemStatus::InProgress).send().await.unwrap();
    let wrong = ssm.update_ops_item().ops_item_id(&oi).status(OpsItemStatus::Approved).send().await.unwrap_err();
    assert_eq!(code(wrong), "OpsItemInvalidParameterException");
    let found = ssm
        .describe_ops_items()
        .ops_item_filters(
            OpsItemFilter::builder()
                .key(OpsItemFilterKey::Status)
                .values("InProgress")
                .operator(OpsItemFilterOperator::Equal)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(found.ops_item_summaries().len(), 1);
    assert_eq!(found.ops_item_summaries()[0].ops_item_id(), Some(oi.as_str()));
    let assoc = ssm
        .associate_ops_item_related_item()
        .ops_item_id(&oi)
        .association_type("RelatesTo")
        .resource_type("AWS::SSM::Document")
        .resource_uri(format!("arn:aws:ssm:us-east-1:{ACCOUNT}:document/restart-change"))
        .send()
        .await
        .unwrap();
    let related = ssm.list_ops_item_related_items().ops_item_id(&oi).send().await.unwrap();
    assert_eq!(related.summaries().len(), 1);
    ssm.disassociate_ops_item_related_item()
        .ops_item_id(&oi)
        .association_id(assoc.association_id().unwrap())
        .send()
        .await
        .unwrap();
    let summary = ssm
        .get_ops_summary()
        .filters(
            OpsFilter::builder()
                .key("AWS:OpsItem.Status")
                .values("InProgress")
                .r#type(aws_sdk_ssm::types::OpsFilterOperatorType::Equal)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(summary.entities().len(), 1);
    assert_eq!(summary.entities()[0].id(), Some(oi.as_str()));

    // OpsItems from EventBridge.
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    eb.put_rule().name("ops").event_pattern(r#"{"source":["custom.app"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("ops")
        .targets(
            aws_sdk_eventbridge::types::Target::builder()
                .id("ops")
                .arn(format!("arn:aws:ssm:us-east-1:{ACCOUNT}:opsitem"))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    eb.put_events()
        .entries(
            aws_sdk_eventbridge::types::PutEventsRequestEntry::builder()
                .source("custom.app")
                .detail_type("Checkout failures")
                .detail(r#"{"rate":0.2}"#)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let mut events = Vec::new();
    for _ in 0..100 {
        events = ssm.list_ops_item_events().send().await.unwrap().summaries().to_vec();
        if !events.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(events[0].detail_type(), Some("Checkout failures"));
    let from_event = ssm.get_ops_item().ops_item_id(events[0].ops_item_id().unwrap()).send().await.unwrap();
    assert_eq!(from_event.ops_item().unwrap().source(), Some("custom.app"));

    ssm.delete_ops_item().ops_item_id(&oi).send().await.unwrap();
    let gone = ssm.get_ops_item().ops_item_id(&oi).send().await.unwrap_err();
    assert_eq!(code(gone), "OpsItemNotFoundException");

    // Application Manager metadata.
    let arn = ssm
        .create_ops_metadata()
        .resource_id("/aws/ssm/web/appmanager")
        .metadata("owner", aws_sdk_ssm::types::MetadataValue::builder().value("team-web").build())
        .send()
        .await
        .unwrap()
        .ops_metadata_arn()
        .unwrap()
        .to_string();
    assert_eq!(arn, format!("arn:aws:ssm:us-east-1:{ACCOUNT}:opsmetadata/aws/ssm/web/appmanager"));
    ssm.update_ops_metadata()
        .ops_metadata_arn(&arn)
        .metadata_to_update("tier", aws_sdk_ssm::types::MetadataValue::builder().value("gold").build())
        .send()
        .await
        .unwrap();
    let got = ssm.get_ops_metadata().ops_metadata_arn(&arn).send().await.unwrap();
    assert_eq!(got.metadata().unwrap()["tier"].value(), Some("gold"));
    assert_eq!(ssm.list_ops_metadata().send().await.unwrap().ops_metadata_list().len(), 1);
    ssm.delete_ops_metadata().ops_metadata_arn(&arn).send().await.unwrap();
    let gone = ssm.get_ops_metadata().ops_metadata_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(gone), "OpsMetadataNotFoundException");
}
