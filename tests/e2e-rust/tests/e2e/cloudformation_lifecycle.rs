//! CloudFormation stack lifecycle semantics through the official Rust SDK:
//! deletion policies on rollback, capabilities, asynchronous change sets,
//! custom-named replacements, rollback triggers, snapshots and transforms.

use std::time::Duration;

use aws_sdk_cloudformation::client::Waiters;
use aws_sdk_cloudformation::error::ProvideErrorMetadata;
use aws_sdk_cloudformation::types::{
    Capability, ChangeSetStatus, ChangeSetType, ExecutionStatus, Parameter, RollbackConfiguration, RollbackTrigger,
    StackStatus, TemplateStage,
};
use aws_sdk_cloudformation::Client;
use mws_e2e::Mws;

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn message<E: ProvideErrorMetadata>(e: &E) -> String {
    e.message().unwrap_or_default().to_string()
}

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn settle(cfn: &Client, stack: &str) -> aws_sdk_cloudformation::types::Stack {
    for _ in 0..600 {
        let out = cfn.describe_stacks().stack_name(stack).send().await.unwrap();
        let s = out.stacks()[0].clone();
        if !s.stack_status().unwrap().as_str().ends_with("_IN_PROGRESS") {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("stack {stack} did not settle");
}

async fn settle_change_set(
    cfn: &Client,
    id: &str,
) -> aws_sdk_cloudformation::operation::describe_change_set::DescribeChangeSetOutput {
    for _ in 0..300 {
        let d = cfn.describe_change_set().change_set_name(id).send().await.unwrap();
        if !matches!(d.status(), Some(ChangeSetStatus::CreatePending) | Some(ChangeSetStatus::CreateInProgress)) {
            return d;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("change set {id} did not settle");
}

async fn events(cfn: &Client, stack: &str) -> Vec<(String, String, String)> {
    let out = cfn.describe_stack_events().stack_name(stack).send().await.unwrap();
    out.stack_events()
        .iter()
        .map(|e| {
            (
                e.logical_resource_id().unwrap_or_default().to_string(),
                e.resource_status().map(|s| s.as_str().to_string()).unwrap_or_default(),
                e.resource_status_reason().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn output(s: &aws_sdk_cloudformation::types::Stack, key: &str) -> String {
    s.outputs().iter().find(|o| o.output_key() == Some(key)).and_then(|o| o.output_value()).unwrap_or_default().into()
}

async fn queue_exists(sqs: &aws_sdk_sqs::Client, name: &str) -> bool {
    sqs.get_queue_url().queue_name(name).send().await.is_ok()
}

#[tokio::test]
async fn rollbacks_honour_deletion_policies() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let sqs = aws_sdk_sqs::Client::new(&mws.root_sdk_config().await);

    // A failed create deletes RetainExceptOnCreate resources and keeps
    // Retain ones.
    let failing = r#"{"Resources": {
        "Keep": {"Type": "AWS::SQS::Queue", "DeletionPolicy": "Retain", "Properties": {"QueueName": "lc-keep"}},
        "Temp": {"Type": "AWS::SQS::Queue", "DeletionPolicy": "RetainExceptOnCreate", "Properties": {"QueueName": "lc-temp"}},
        "Bad": {"Type": "AWS::SQS::Queue", "DependsOn": ["Keep", "Temp"], "Properties": {"VisibilityTimeout": 999999}}}}"#;
    cfn.create_stack().stack_name("roll").template_body(failing).send().await.unwrap();
    let s = settle(&cfn, "roll").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::RollbackComplete));
    assert!(queue_exists(&sqs, "lc-keep").await);
    assert!(!queue_exists(&sqs, "lc-temp").await);
    let ev = events(&cfn, "roll").await;
    assert!(ev.iter().any(|(l, st, _)| l == "Keep" && st == "DELETE_SKIPPED"));
    assert!(ev.iter().any(|(l, st, _)| l == "Temp" && st == "DELETE_COMPLETE"));

    // A ROLLBACK_COMPLETE stack can be neither updated nor changed by a
    // change set.
    let id = s.stack_id().unwrap().to_string();
    let want = format!("Stack:{id} is in ROLLBACK_COMPLETE state and can not be updated.");
    let e = cfn.update_stack().stack_name("roll").template_body(failing).send().await.unwrap_err();
    assert_eq!(message(&e), want);
    let e = cfn
        .create_change_set()
        .stack_name("roll")
        .change_set_name("again")
        .template_body(failing)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "ValidationError");
    assert_eq!(message(&e), want);

    // Stack-level RetainExceptOnCreate deletes even Retain resources the
    // failed create made.
    let failing2 = failing.replace("lc-keep", "lc-keep2").replace("lc-temp", "lc-temp2");
    cfn.create_stack().stack_name("roll2").template_body(&failing2).retain_except_on_create(true).send().await.unwrap();
    assert_eq!(settle(&cfn, "roll2").await.stack_status(), Some(&StackStatus::RollbackComplete));
    assert!(!queue_exists(&sqs, "lc-keep2").await);

    // A failed update keeps the Retain resources it added.
    cfn.create_stack()
        .stack_name("upd")
        .template_body(
            r#"{"Resources": {"Base": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": "lc-base"}}}}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "upd").await.stack_status(), Some(&StackStatus::CreateComplete));
    let update = r#"{"Resources": {
        "Base": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": "lc-base"}},
        "Added": {"Type": "AWS::SQS::Queue", "DeletionPolicy": "Retain", "Properties": {"QueueName": "lc-added"}},
        "AddedTemp": {"Type": "AWS::SQS::Queue", "DeletionPolicy": "RetainExceptOnCreate", "Properties": {"QueueName": "lc-added-temp"}},
        "Bad": {"Type": "AWS::SQS::Queue", "DependsOn": ["Added", "AddedTemp"], "Properties": {"VisibilityTimeout": 999999}}}}"#;
    cfn.update_stack().stack_name("upd").template_body(update).send().await.unwrap();
    assert_eq!(settle(&cfn, "upd").await.stack_status(), Some(&StackStatus::UpdateRollbackComplete));
    assert!(queue_exists(&sqs, "lc-added").await);
    assert!(!queue_exists(&sqs, "lc-added-temp").await);
    let ev = events(&cfn, "upd").await;
    assert!(ev.iter().any(|(l, st, _)| l == "Added" && st == "DELETE_SKIPPED"));
    let resources = cfn.describe_stack_resources().stack_name("upd").send().await.unwrap();
    let names: Vec<_> = resources.stack_resources().iter().filter_map(|r| r.logical_resource_id()).collect();
    assert_eq!(names, ["Base"]);
}

#[tokio::test]
async fn capabilities_follow_aws_rules() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let config = mws.root_sdk_config().await;

    // NAMED_IAM covers unnamed IAM resources.
    let role = r#"{"Resources": {"R": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument":
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}}}}}"#;
    cfn.create_stack()
        .stack_name("named")
        .template_body(role)
        .capabilities(Capability::CapabilityNamedIam)
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "named").await.stack_status(), Some(&StackStatus::CreateComplete));

    // Transforms need AUTO_EXPAND on CreateStack, but not in a change set.
    let le = r#"{"Transform": "AWS::LanguageExtensions", "Resources": {"Q": {"Type": "AWS::SQS::Queue"}}}"#;
    let e = cfn.create_stack().stack_name("le").template_body(le).send().await.unwrap_err();
    assert_eq!(code(&e), "InsufficientCapabilitiesException");
    assert_eq!(message(&e), "Requires capabilities : [CAPABILITY_AUTO_EXPAND]");
    let cs = cfn
        .create_change_set()
        .stack_name("le")
        .change_set_name("c")
        .change_set_type(ChangeSetType::Create)
        .template_body(le)
        .send()
        .await
        .unwrap();
    let d = settle_change_set(&cfn, cs.id().unwrap()).await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::CreateComplete), "{:?}", d.status_reason());
    let v = cfn.validate_template().template_body(le).send().await.unwrap();
    assert_eq!(v.capabilities(), [Capability::CapabilityAutoExpand]);

    // Nested stacks need AUTO_EXPAND, and run with the root's capabilities.
    let s3 = Mws::s3(&config);
    s3.create_bucket().bucket("lc-templates").send().await.unwrap();
    s3.put_object().bucket("lc-templates").key("role.json").body(role.as_bytes().to_vec().into()).send().await.unwrap();
    let parent = r#"{"Resources": {"Child": {"Type": "AWS::CloudFormation::Stack",
        "Properties": {"TemplateURL": "https://lc-templates.s3.amazonaws.com/role.json"}}}}"#;
    let e = cfn.create_stack().stack_name("parent").template_body(parent).send().await.unwrap_err();
    assert_eq!(message(&e), "Requires capabilities : [CAPABILITY_AUTO_EXPAND]");
    cfn.create_stack()
        .stack_name("parent")
        .template_body(parent)
        .capabilities(Capability::CapabilityAutoExpand)
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "parent").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::RollbackComplete));
    let ev = events(&cfn, "parent").await;
    assert!(
        ev.iter().any(|(l, _, r)| l == "Child" && r.contains("Requires capabilities : [CAPABILITY_IAM]")),
        "{ev:?}"
    );
    cfn.create_stack()
        .stack_name("parent2")
        .template_body(parent)
        .capabilities(Capability::CapabilityAutoExpand)
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "parent2").await.stack_status(), Some(&StackStatus::CreateComplete));
}

#[tokio::test]
async fn change_sets_are_created_and_executed_asynchronously() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let template = r#"{"Resources": {
        "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        "Wait": {"Type": "AWS::CloudFormation::WaitCondition", "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "60"}}}}"#;
    let cs = cfn
        .create_change_set()
        .stack_name("async")
        .change_set_name("first")
        .change_set_type(ChangeSetType::Create)
        .template_body(template)
        .send()
        .await
        .unwrap();
    let id = cs.id().unwrap().to_string();
    let first = cfn.describe_change_set().change_set_name(&id).send().await.unwrap();
    assert!(matches!(
        first.status(),
        Some(ChangeSetStatus::CreatePending | ChangeSetStatus::CreateInProgress | ChangeSetStatus::CreateComplete)
    ));
    if first.status() != Some(&ChangeSetStatus::CreateComplete) {
        assert_eq!(first.execution_status(), Some(&ExecutionStatus::Unavailable));
    }
    let d = settle_change_set(&cfn, &id).await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::CreateComplete));
    assert_eq!(d.execution_status(), Some(&ExecutionStatus::Available));
    // The SDK waiter agrees (its first check is immediate).
    cfn.wait_until_change_set_create_complete().change_set_name(&id).wait(Duration::from_secs(10)).await.unwrap();

    cfn.execute_change_set().change_set_name(&id).send().await.unwrap();
    let d = cfn.describe_change_set().change_set_name(&id).send().await.unwrap();
    assert_eq!(d.execution_status(), Some(&ExecutionStatus::ExecuteInProgress));
    // Executing again while it runs is refused.
    let e = cfn.execute_change_set().change_set_name(&id).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidChangeSetStatus");
    // Release the wait condition.
    let mut handle = None;
    for _ in 0..200 {
        let r = cfn.describe_stack_resource().stack_name("async").logical_resource_id("Handle").send().await;
        if let Some(p) = r.ok().and_then(|r| r.stack_resource_detail()?.physical_resource_id().map(str::to_string)) {
            handle = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let handle = handle.expect("handle");
    let path = &handle[handle.find("/_aws/").unwrap()..];
    mws.control("PUT", path, Some(r#"{"Status": "SUCCESS", "UniqueId": "a", "Data": "x", "Reason": "ok"}"#)).await;
    assert_eq!(settle(&cfn, "async").await.stack_status(), Some(&StackStatus::CreateComplete));
    let d = cfn.describe_change_set().change_set_name(&id).send().await.unwrap();
    assert_eq!(d.execution_status(), Some(&ExecutionStatus::ExecuteComplete));

    // A change set whose execution rolls back ends EXECUTE_FAILED.
    let broken = r#"{"Resources": {
        "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        "Bad": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 999999}}}}"#;
    let cs = cfn
        .create_change_set()
        .stack_name("async")
        .change_set_name("broken")
        .template_body(broken)
        .send()
        .await
        .unwrap();
    let id = cs.id().unwrap().to_string();
    assert_eq!(settle_change_set(&cfn, &id).await.status(), Some(&ChangeSetStatus::CreateComplete));
    cfn.execute_change_set().change_set_name(&id).send().await.unwrap();
    assert_eq!(settle(&cfn, "async").await.stack_status(), Some(&StackStatus::UpdateRollbackComplete));
    let d = cfn.describe_change_set().change_set_name(&id).send().await.unwrap();
    assert_eq!(d.execution_status(), Some(&ExecutionStatus::ExecuteFailed));
}

#[tokio::test]
async fn replacing_custom_named_resources_is_refused_and_firehose_updates_in_place() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let group = |class: &str| {
        format!(
            r#"{{"Resources": {{"Logs": {{"Type": "AWS::Logs::LogGroup", "Properties": {{"LogGroupName": "lc-logs", "LogGroupClass": "{class}"}}}}}}}}"#
        )
    };
    cfn.create_stack().stack_name("named").template_body(group("STANDARD")).send().await.unwrap();
    assert_eq!(settle(&cfn, "named").await.stack_status(), Some(&StackStatus::CreateComplete));
    cfn.update_stack().stack_name("named").template_body(group("INFREQUENT_ACCESS")).send().await.unwrap();
    assert_eq!(settle(&cfn, "named").await.stack_status(), Some(&StackStatus::UpdateRollbackComplete));
    let ev = events(&cfn, "named").await;
    assert!(ev.iter().any(|(l, st, r)| l == "Logs"
        && st == "UPDATE_FAILED"
        && r == "CloudFormation cannot update a stack when a custom-named resource requires replacing. Rename lc-logs and update the stack again."),
        "{ev:?}");

    // Firehose buffering hints change in place.
    let config = mws.root_sdk_config().await;
    let s3 = Mws::s3(&config);
    s3.create_bucket().bucket("lc-firehose").send().await.unwrap();
    let stream = |interval: u32| {
        format!(
            r#"{{"Resources": {{
              "Role": {{"Type": "AWS::IAM::Role", "Properties": {{"AssumeRolePolicyDocument": {{"Version": "2012-10-17",
                "Statement": [{{"Effect": "Allow", "Principal": {{"Service": "firehose.amazonaws.com"}}, "Action": "sts:AssumeRole"}}]}}}}}},
              "Stream": {{"Type": "AWS::KinesisFirehose::DeliveryStream", "Properties": {{
                "DeliveryStreamName": "lc-stream", "DeliveryStreamType": "DirectPut",
                "ExtendedS3DestinationConfiguration": {{"BucketARN": "arn:aws:s3:::lc-firehose", "RoleARN": {{"Fn::GetAtt": ["Role", "Arn"]}},
                  "BufferingHints": {{"IntervalInSeconds": {interval}, "SizeInMBs": 5}}}}}}}}}},
              "Outputs": {{"Arn": {{"Value": {{"Fn::GetAtt": ["Stream", "Arn"]}}}}}}}}"#
        )
    };
    cfn.create_stack()
        .stack_name("hose")
        .template_body(stream(300))
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "hose").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", events(&cfn, "hose").await);
    cfn.update_stack()
        .stack_name("hose")
        .template_body(stream(60))
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "hose").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::UpdateComplete), "{:?}", events(&cfn, "hose").await);
    let firehose = aws_sdk_firehose::Client::new(&config);
    let d = firehose.describe_delivery_stream().delivery_stream_name("lc-stream").send().await.unwrap();
    let dest = &d.delivery_stream_description().unwrap().destinations()[0];
    let hints = dest.extended_s3_destination_description().unwrap().buffering_hints().unwrap();
    assert_eq!(hints.interval_in_seconds(), Some(60));
}

#[tokio::test]
async fn rollback_triggers_roll_back_on_alarms() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    let sqs = aws_sdk_sqs::Client::new(&mws.root_sdk_config().await);
    for name in ["lc-alarm", "lc-later"] {
        cw.put_metric_alarm()
            .alarm_name(name)
            .metric_name("Errors")
            .namespace("App")
            .statistic(aws_sdk_cloudwatch::types::Statistic::Sum)
            .period(60)
            .evaluation_periods(1)
            .threshold(1.0)
            .comparison_operator(aws_sdk_cloudwatch::types::ComparisonOperator::GreaterThanThreshold)
            .send()
            .await
            .unwrap();
    }
    let arn = |n: &str| format!("arn:aws:cloudwatch:us-east-1:123456789012:alarm:{n}");
    let trigger = |n: &str| RollbackTrigger::builder().arn(arn(n)).r#type("AWS::CloudWatch::Alarm").build();
    cw.set_alarm_state()
        .alarm_name("lc-alarm")
        .state_value(aws_sdk_cloudwatch::types::StateValue::Alarm)
        .state_reason("test")
        .send()
        .await
        .unwrap();
    let template = |q: &str| {
        format!(r#"{{"Resources": {{"Q": {{"Type": "AWS::SQS::Queue", "Properties": {{"QueueName": "{q}"}}}}}}}}"#)
    };
    cfn.create_stack()
        .stack_name("trig")
        .template_body(template("lc-trig"))
        .rollback_configuration(RollbackConfiguration::builder().rollback_triggers(trigger("lc-alarm")).build())
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "trig").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::RollbackComplete));
    let rc = s.rollback_configuration().unwrap();
    assert_eq!(rc.rollback_triggers()[0].arn(), Some(arn("lc-alarm").as_str()));
    assert!(!queue_exists(&sqs, "lc-trig").await);

    // An alarm firing during the monitoring window rolls the stack back.
    cfn.create_stack()
        .stack_name("watch")
        .template_body(template("lc-watch"))
        .rollback_configuration(
            RollbackConfiguration::builder()
                .rollback_triggers(trigger("lc-later"))
                .monitoring_time_in_minutes(5)
                .build(),
        )
        .send()
        .await
        .unwrap();
    for _ in 0..100 {
        if queue_exists(&sqs, "lc-watch").await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let s = cfn.describe_stacks().stack_name("watch").send().await.unwrap();
    assert_eq!(s.stacks()[0].stack_status(), Some(&StackStatus::CreateInProgress));
    assert_eq!(s.stacks()[0].rollback_configuration().unwrap().monitoring_time_in_minutes(), Some(5));
    cw.set_alarm_state()
        .alarm_name("lc-later")
        .state_value(aws_sdk_cloudwatch::types::StateValue::Alarm)
        .state_reason("test")
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "watch").await.stack_status(), Some(&StackStatus::RollbackComplete));

    // The monitoring window runs on the emulated clock.
    cfn.create_stack()
        .stack_name("calm")
        .template_body(template("lc-calm"))
        .rollback_configuration(
            RollbackConfiguration::builder()
                .rollback_triggers(trigger("lc-quiet"))
                .monitoring_time_in_minutes(30)
                .build(),
        )
        .send()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let s = cfn.describe_stacks().stack_name("calm").send().await.unwrap();
    assert_eq!(s.stacks()[0].stack_status(), Some(&StackStatus::CreateInProgress));
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 1900}"#)).await;
    assert_eq!(status, 200);
    assert_eq!(settle(&cfn, "calm").await.stack_status(), Some(&StackStatus::CreateComplete));
}

#[tokio::test]
async fn snapshot_policy_snapshots_volumes_before_deleting_them() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let ec2 = aws_sdk_ec2::Client::new(&mws.root_sdk_config().await);
    let template = r#"{"Resources": {
        "Vol": {"Type": "AWS::EC2::Volume", "DeletionPolicy": "Snapshot", "Properties": {"AvailabilityZone": "us-east-1a", "Size": 8}},
        "Q": {"Type": "AWS::SQS::Queue", "DeletionPolicy": "Snapshot"}}}"#;
    cfn.create_stack().stack_name("snap").template_body(template).send().await.unwrap();
    let s = settle(&cfn, "snap").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", events(&cfn, "snap").await);
    let r = cfn.describe_stack_resource().stack_name("snap").logical_resource_id("Vol").send().await.unwrap();
    let volume = r.stack_resource_detail().unwrap().physical_resource_id().unwrap().to_string();
    cfn.delete_stack().stack_name("snap").send().await.unwrap();
    assert_eq!(settle(&cfn, s.stack_id().unwrap()).await.stack_status(), Some(&StackStatus::DeleteComplete));
    let snaps = ec2
        .describe_snapshots()
        .owner_ids("self")
        .filters(aws_sdk_ec2::types::Filter::builder().name("volume-id").values(&volume).build())
        .send()
        .await
        .unwrap();
    assert_eq!(snaps.snapshots().len(), 1);
    let vols = ec2.describe_volumes().send().await.unwrap();
    assert!(vols.volumes().iter().all(|v| v.volume_id() != Some(volume.as_str())));
}

#[tokio::test]
async fn language_extensions_and_include_expand_templates() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let config = mws.root_sdk_config().await;
    let sqs = aws_sdk_sqs::Client::new(&config);
    let s3 = Mws::s3(&config);
    s3.create_bucket().bucket("lc-snippets").send().await.unwrap();
    s3.put_object()
        .bucket("lc-snippets")
        .key("topic.yaml")
        .body(b"Alerts:\n  Type: AWS::SNS::Topic\n  Properties:\n    TopicName: lc-alerts\n".to_vec().into())
        .send()
        .await
        .unwrap();
    let template = r#"
Transform: AWS::LanguageExtensions
Parameters:
  Names:
    Type: CommaDelimitedList
    Default: "alpha,beta-two"
Resources:
  Fn::ForEach::Queues:
    - Name
    - !Ref Names
    - "Queue&{Name}":
        Type: AWS::SQS::Queue
        Properties:
          QueueName: !Sub "lc-${Name}"
  Fn::Transform:
    Name: AWS::Include
    Parameters:
      Location: s3://lc-snippets/topic.yaml
Outputs:
  Fn::ForEach::Urls:
    - Name
    - !Ref Names
    - "Url&{Name}":
        Value: !Ref "Queue&{Name}"
  Count:
    Value: !Join [",", !Ref Names]
"#;
    let e = cfn.create_stack().stack_name("le").template_body(template).send().await.unwrap_err();
    assert_eq!(message(&e), "Requires capabilities : [CAPABILITY_AUTO_EXPAND]");
    cfn.create_stack()
        .stack_name("le")
        .template_body(template)
        .capabilities(Capability::CapabilityAutoExpand)
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "le").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    assert!(queue_exists(&sqs, "lc-alpha").await);
    assert!(queue_exists(&sqs, "lc-beta-two").await);
    assert!(output(&s, "Urlbetatwo").ends_with("/lc-beta-two"));
    let sns = aws_sdk_sns::Client::new(&config);
    let topics = sns.list_topics().send().await.unwrap();
    assert!(topics.topics().iter().any(|t| t.topic_arn().unwrap().ends_with(":lc-alerts")));
    // GetTemplate returns the template as submitted, or as processed.
    let original = cfn.get_template().stack_name("le").send().await.unwrap();
    assert!(original.template_body().unwrap().contains("Fn::ForEach::Queues"));
    let processed = cfn.get_template().stack_name("le").template_stage(TemplateStage::Processed).send().await.unwrap();
    let body = processed.template_body().unwrap();
    assert!(body.contains("Queuealpha") && !body.contains("Fn::ForEach"), "{body}");

    // Updating with new parameter values re-runs the loop.
    cfn.update_stack()
        .stack_name("le")
        .use_previous_template(true)
        .parameters(Parameter::builder().parameter_key("Names").parameter_value("alpha").build())
        .capabilities(Capability::CapabilityAutoExpand)
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "le").await.stack_status(), Some(&StackStatus::UpdateComplete));
    assert!(!queue_exists(&sqs, "lc-beta-two").await);
}

const MACRO_STACK: &str = r#"
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt Role.Arn
      Code:
        ZipFile: |
          def handler(event, context):
              fragment = event["fragment"]
              suffix = event["templateParameterValues"]["Suffix"]
              fragment["Resources"]["Added"] = {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": "lc-macro-" + suffix}}
              return {"requestId": event["requestId"], "status": "success", "fragment": fragment}
  Macro:
    Type: AWS::CloudFormation::Macro
    Properties:
      Name: AddQueue
      FunctionName: !GetAtt Fn.Arn
"#;

#[tokio::test]
async fn macros_and_sam_run_server_side() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let sqs = aws_sdk_sqs::Client::new(&mws.root_sdk_config().await);
    cfn.create_stack()
        .stack_name("macro")
        .template_body(MACRO_STACK)
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "macro").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", events(&cfn, "macro").await);

    let uses = r#"{"Transform": "AddQueue", "Parameters": {"Suffix": {"Type": "String"}},
        "Resources": {"Base": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": "lc-base"}}}}"#;
    cfn.create_stack()
        .stack_name("uses")
        .template_body(uses)
        .parameters(Parameter::builder().parameter_key("Suffix").parameter_value("x").build())
        .capabilities(Capability::CapabilityAutoExpand)
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "uses").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", events(&cfn, "uses").await);
    assert!(queue_exists(&sqs, "lc-macro-x").await);

    // A change set whose transform fails is FAILED, naming the macro.
    let failing = r#"{"Resources": {"Base": {"Type": "AWS::SQS::Queue",
        "Properties": {"Fn::Transform": {"Name": "Nope"}}}}}"#;
    let cs = cfn
        .create_change_set()
        .stack_name("bad-macro")
        .change_set_name("c")
        .change_set_type(ChangeSetType::Create)
        .template_body(failing)
        .send()
        .await
        .unwrap();
    let d = settle_change_set(&cfn, cs.id().unwrap()).await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::Failed));
    assert_eq!(d.status_reason(), Some("No transform named 123456789012::Nope found."));

    // SAM functions with event sources deploy through a change set.
    let sam = r#"
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    Runtime: python3.12
    Timeout: 10
Resources:
  Jobs:
    Type: AWS::SQS::Queue
  Worker:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      InlineCode: "def handler(event, context):\n    return 'ok'\n"
      Policies:
        - SQSSendMessagePolicy:
            QueueName: !GetAtt Jobs.QueueName
      Events:
        Queue:
          Type: SQS
          Properties:
            Queue: !GetAtt Jobs.Arn
            BatchSize: 5
        Tick:
          Type: Schedule
          Properties:
            Schedule: rate(5 minutes)
Outputs:
  RoleArn:
    Value: !GetAtt WorkerRole.Arn
"#;
    let cs = cfn
        .create_change_set()
        .stack_name("sam")
        .change_set_name("deploy")
        .change_set_type(ChangeSetType::Create)
        .template_body(sam)
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    let d = settle_change_set(&cfn, cs.id().unwrap()).await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::CreateComplete), "{:?}", d.status_reason());
    cfn.execute_change_set().change_set_name(cs.id().unwrap()).send().await.unwrap();
    let s = settle(&cfn, "sam").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", events(&cfn, "sam").await);
    assert!(output(&s, "RoleArn").contains(":role/"));
    let resources = cfn.describe_stack_resources().stack_name("sam").send().await.unwrap();
    let mut types: Vec<(String, String)> = resources
        .stack_resources()
        .iter()
        .map(|r| (r.logical_resource_id().unwrap().to_string(), r.resource_type().unwrap().to_string()))
        .collect();
    types.sort();
    assert_eq!(
        types,
        [
            ("Jobs", "AWS::SQS::Queue"),
            ("Worker", "AWS::Lambda::Function"),
            ("WorkerQueue", "AWS::Lambda::EventSourceMapping"),
            ("WorkerRole", "AWS::IAM::Role"),
            ("WorkerTick", "AWS::Events::Rule"),
            ("WorkerTickPermission", "AWS::Lambda::Permission"),
        ]
        .map(|(a, b)| (a.to_string(), b.to_string()))
    );
    let lambda = aws_sdk_lambda::Client::new(&mws.root_sdk_config().await);
    let maps = lambda.list_event_source_mappings().send().await.unwrap();
    assert_eq!(maps.event_source_mappings().len(), 1);
}
