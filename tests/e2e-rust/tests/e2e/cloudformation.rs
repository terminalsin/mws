//! CloudFormation through the official Rust SDK: stacks that create real
//! resources in the other emulated services.

use std::time::Duration;

use aws_sdk_cloudformation::client::Waiters;
use aws_sdk_cloudformation::error::ProvideErrorMetadata;
use aws_sdk_cloudformation::types::{
    Capability, ChangeSetStatus, ChangeSetType, OnFailure, Parameter, ResourceStatus, StackDriftDetectionStatus,
    StackDriftStatus, StackResourceDriftStatus, StackStatus, Tag,
};
use aws_sdk_cloudformation::Client;
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message<E: ProvideErrorMetadata>(e: &E) -> String {
    e.message().unwrap_or_default().to_string()
}

fn param(k: &str, v: &str) -> Parameter {
    Parameter::builder().parameter_key(k).parameter_value(v).build()
}

/// Poll until the stack leaves its `*_IN_PROGRESS` state; the SDK waiters
/// wait 30 seconds between attempts, which is too slow for a test.
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
    stack: &str,
    name: &str,
) -> aws_sdk_cloudformation::operation::describe_change_set::DescribeChangeSetOutput {
    for _ in 0..300 {
        let d = cfn.describe_change_set().stack_name(stack).change_set_name(name).send().await.unwrap();
        if !matches!(d.status(), Some(ChangeSetStatus::CreatePending) | Some(ChangeSetStatus::CreateInProgress)) {
            return d;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("change set {name} did not settle");
}

fn output(s: &aws_sdk_cloudformation::types::Stack, key: &str) -> String {
    s.outputs()
        .iter()
        .find(|o| o.output_key() == Some(key))
        .and_then(|o| o.output_value())
        .unwrap_or_else(|| panic!("no output {key}"))
        .to_string()
}

/// Every failure reason in the stack's events, for assertion messages.
async fn failures(cfn: &Client, stack: &str) -> Vec<String> {
    let events = cfn.describe_stack_events().stack_name(stack).send().await.unwrap();
    events
        .stack_events()
        .iter()
        .filter(|e| e.resource_status().is_some_and(|s| s.as_str().ends_with("FAILED")))
        .map(|e| {
            format!(
                "{}: {}",
                e.logical_resource_id().unwrap_or_default(),
                e.resource_status_reason().unwrap_or_default()
            )
        })
        .collect()
}

async fn physical_id(cfn: &Client, stack: &str, logical: &str) -> String {
    let r = cfn.describe_stack_resource().stack_name(stack).logical_resource_id(logical).send().await.unwrap();
    r.stack_resource_detail().unwrap().physical_resource_id().unwrap().to_string()
}

const APP: &str = r#"
AWSTemplateFormatVersion: "2010-09-09"
Description: Queues, a topic and parameters
Parameters:
  Env:
    Type: String
    AllowedValues: [dev, prod]
    Default: dev
  Retention:
    Type: Number
    Default: 345600
    MinValue: 60
Mappings:
  Sizes:
    dev: {Timeout: 30}
    prod: {Timeout: 120}
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  DeadLetters:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: !Ref Retention
  Work:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: !FindInMap [Sizes, !Ref Env, Timeout]
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt DeadLetters.Arn
        maxReceiveCount: 3
      Tags:
        - Key: env
          Value: !Ref Env
  Alerts:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Sub "${AWS::StackName}-alerts"
  AlertsToWork:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref Alerts
      Protocol: sqs
      Endpoint: !GetAtt Work.Arn
      RawMessageDelivery: true
  WorkPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref Work]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: sns.amazonaws.com}
            Action: sqs:SendMessage
            Resource: !GetAtt Work.Arn
            Condition:
              ArnEquals: {aws:SourceArn: !Ref Alerts}
  QueueUrlParameter:
    Type: AWS::SSM::Parameter
    Properties:
      Name: !Sub "/${AWS::StackName}/queue-url"
      Type: String
      Value: !Ref Work
  ProdOnly:
    Type: AWS::SQS::Queue
    Condition: IsProd
Outputs:
  QueueUrl:
    Value: !Ref Work
    Export:
      Name: !Sub "${AWS::StackName}-QueueUrl"
  QueueArn:
    Value: !GetAtt Work.Arn
  Region:
    Value: !Join [":", [!Ref "AWS::Region", !Ref "AWS::AccountId", !Select [1, !Split ["-", !Ref Env]]]]
    Condition: IsProd
  TopicName:
    Value: !GetAtt Alerts.TopicName
"#;

#[tokio::test]
async fn stack_creates_real_resources_with_intrinsics_outputs_and_exports() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let config = mws.root_sdk_config().await;
    let sqs = aws_sdk_sqs::Client::new(&config);
    let sns = aws_sdk_sns::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);

    let created = cfn
        .create_stack()
        .stack_name("app")
        .template_body(APP)
        .parameters(param("Env", "dev"))
        .tags(Tag::builder().key("team").value("core").build())
        .send()
        .await
        .unwrap();
    let stack_id = created.stack_id().unwrap().to_string();
    assert!(stack_id.starts_with(&format!("arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/app/")));
    let s = settle(&cfn, "app").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    // The SDK waiter agrees (its first check is immediate).
    cfn.wait_until_stack_create_complete().stack_name("app").wait(Duration::from_secs(5)).await.unwrap();
    assert_eq!(s.description(), Some("Queues, a topic and parameters"));
    assert_eq!(s.tags().len(), 1);
    // Parameters with defaults are reported; the condition left ProdOnly
    // and the Region output out.
    let params: Vec<_> =
        s.parameters().iter().map(|p| (p.parameter_key().unwrap(), p.parameter_value().unwrap())).collect();
    assert!(params.contains(&("Env", "dev")) && params.contains(&("Retention", "345600")));
    assert!(s.outputs().iter().all(|o| o.output_key() != Some("Region")));
    assert_eq!(output(&s, "TopicName"), "app-alerts");

    // The queue exists, with the mapped timeout, the redrive policy and the
    // stack's tags.
    let url = output(&s, "QueueUrl");
    let attrs = sqs
        .get_queue_attributes()
        .queue_url(&url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::All)
        .send()
        .await
        .unwrap();
    let a = attrs.attributes().unwrap();
    assert_eq!(a[&aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout], "30");
    assert!(a[&aws_sdk_sqs::types::QueueAttributeName::RedrivePolicy].contains("maxReceiveCount"));
    assert_eq!(output(&s, "QueueArn"), a[&aws_sdk_sqs::types::QueueAttributeName::QueueArn]);
    let tags = sqs.list_queue_tags().queue_url(&url).send().await.unwrap();
    assert_eq!(tags.tags().unwrap()["env"], "dev");
    assert_eq!(tags.tags().unwrap()["team"], "core");
    // Generated names follow <stack>-<logical id>-<suffix>.
    assert!(url.rsplit('/').next().unwrap().starts_with("app-Work-"), "{url}");

    // SNS -> SQS works through the stack's subscription and queue policy.
    let topic = physical_id(&cfn, "app", "Alerts").await;
    sns.publish().topic_arn(&topic).message("hello").send().await.unwrap();
    let mut got = None;
    for _ in 0..50 {
        let r = sqs.receive_message().queue_url(&url).send().await.unwrap();
        if let Some(m) = r.messages().first() {
            got = m.body().map(str::to_string);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(got.as_deref(), Some("hello"));

    let p = ssm.get_parameter().name("/app/queue-url").send().await.unwrap();
    assert_eq!(p.parameter().unwrap().value(), Some(url.as_str()));

    // Resources, events, template and summaries.
    let resources = cfn.describe_stack_resources().stack_name("app").send().await.unwrap();
    assert_eq!(resources.stack_resources().len(), 6);
    assert!(resources.stack_resources().iter().all(|r| r.resource_status() == Some(&ResourceStatus::CreateComplete)));
    let listed = cfn.list_stack_resources().stack_name("app").send().await.unwrap();
    assert_eq!(listed.stack_resource_summaries().len(), 6);
    let events = cfn.describe_stack_events().stack_name("app").send().await.unwrap();
    let first = events.stack_events().last().unwrap();
    assert_eq!(first.resource_status(), Some(&ResourceStatus::CreateInProgress));
    assert_eq!(first.resource_type(), Some("AWS::CloudFormation::Stack"));
    assert_eq!(events.stack_events()[0].resource_status(), Some(&ResourceStatus::CreateComplete));
    assert_eq!(events.stack_events()[0].logical_resource_id(), Some("app"));
    let t = cfn.get_template().stack_name("app").send().await.unwrap();
    assert_eq!(t.template_body(), Some(APP));
    let listed = cfn.list_stacks().send().await.unwrap();
    assert!(listed.stack_summaries().iter().any(|s| s.stack_name() == Some("app")));

    // Exports, and a stack that imports one.
    let exports = cfn.list_exports().send().await.unwrap();
    assert_eq!(exports.exports().len(), 1);
    assert_eq!(exports.exports()[0].name(), Some("app-QueueUrl"));
    assert_eq!(exports.exports()[0].value(), Some(url.as_str()));
    let consumer = r#"{
      "Resources": {
        "Ref": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": {"Fn::ImportValue": "app-QueueUrl"}}}
      }
    }"#;
    cfn.create_stack().stack_name("consumer").template_body(consumer).send().await.unwrap();
    assert_eq!(settle(&cfn, "consumer").await.stack_status(), Some(&StackStatus::CreateComplete));
    let imports = cfn.list_imports().export_name("app-QueueUrl").send().await.unwrap();
    assert_eq!(imports.imports(), ["consumer"]);
    // An export in use blocks deleting the stack.
    cfn.delete_stack().stack_name("app").send().await.unwrap();
    let s = settle(&cfn, "app").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::DeleteFailed));
    assert_eq!(s.stack_status_reason(), Some("Export app-QueueUrl cannot be deleted as it is in use by consumer"));

    cfn.delete_stack().stack_name("consumer").send().await.unwrap();
    cfn.delete_stack().stack_name("app").send().await.unwrap();
    let deleted = settle(&cfn, &stack_id).await;
    assert_eq!(deleted.stack_status(), Some(&StackStatus::DeleteComplete));
    // Deleted stacks are found by id only, and their resources are gone.
    let e = cfn.describe_stacks().stack_name("app").send().await.unwrap_err();
    assert_eq!(message(&e.into_service_error()), "Stack with id app does not exist");
    assert!(sqs.get_queue_url().queue_name(url.rsplit('/').next().unwrap()).send().await.is_err());
    assert!(ssm.get_parameter().name("/app/queue-url").send().await.is_err());
}

#[tokio::test]
async fn template_and_parameter_errors_use_aws_wording() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;

    let e = cfn.create_stack().stack_name("bad").template_body("{").send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "ValidationError");
    assert!(message(&e).starts_with("Template format error:"), "{}", message(&e));

    let e = cfn
        .create_stack()
        .stack_name("bad")
        .template_body(APP)
        .parameters(param("Env", "qa"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&e.into_service_error()), "Parameter 'Env' must be one of AllowedValues");
    let e = cfn
        .create_stack()
        .stack_name("bad")
        .template_body(APP)
        .parameters(param("Nope", "x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&e.into_service_error()), "Parameters: [Nope] do not exist in the template");

    let missing =
        r#"{"Resources": {"Q": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": {"Ref": "Missing"}}}}}"#;
    let e = cfn.create_stack().stack_name("bad").template_body(missing).send().await.unwrap_err();
    assert_eq!(
        message(&e.into_service_error()),
        "Template format error: Unresolved resource dependencies [Missing] in the Resources block of the template"
    );

    let cycle = r#"{"Resources": {
      "A": {"Type": "AWS::SQS::Queue", "DependsOn": "B"},
      "B": {"Type": "AWS::SQS::Queue", "DependsOn": "A"}}}"#;
    let e = cfn.create_stack().stack_name("bad").template_body(cycle).send().await.unwrap_err();
    assert_eq!(message(&e.into_service_error()), "Circular dependency between resources: [A, B]");

    let unknown = r#"{"Resources": {"A": {"Type": "AWS::Nope::Thing"}}}"#;
    let e = cfn.create_stack().stack_name("bad").template_body(unknown).send().await.unwrap_err();
    assert_eq!(
        message(&e.into_service_error()),
        "Template format error: Unrecognized resource types: [AWS::Nope::Thing]"
    );

    let iam = r#"{"Resources": {"R": {"Type": "AWS::IAM::Role", "Properties": {"RoleName": "named",
      "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}}}}}"#;
    let e = cfn.create_stack().stack_name("iam").template_body(iam).send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "InsufficientCapabilitiesException");
    assert_eq!(message(&e), "Requires capabilities : [CAPABILITY_NAMED_IAM]");
    let e = cfn
        .create_stack()
        .stack_name("iam")
        .template_body(iam)
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&e.into_service_error()), "Requires capabilities : [CAPABILITY_NAMED_IAM]");
    cfn.create_stack()
        .stack_name("iam")
        .template_body(iam)
        .capabilities(Capability::CapabilityNamedIam)
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "iam").await.stack_status(), Some(&StackStatus::CreateComplete));
    let e = cfn.create_stack().stack_name("iam").template_body(iam).send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "AlreadyExistsException");
    assert_eq!(message(&e), "Stack [iam] already exists");

    // Validation and summaries.
    let v = cfn.validate_template().template_body(APP).send().await.unwrap();
    assert_eq!(v.description(), Some("Queues, a topic and parameters"));
    let keys: Vec<_> = v.parameters().iter().map(|p| p.parameter_key().unwrap()).collect();
    assert_eq!(keys, ["Env", "Retention"]);
    let v = cfn.validate_template().template_body(iam).send().await.unwrap();
    assert_eq!(v.capabilities(), [Capability::CapabilityNamedIam]);
    let summary = cfn.get_template_summary().template_body(APP).send().await.unwrap();
    assert!(summary.resource_types().contains(&"AWS::SNS::Topic".to_string()));
    let summary = cfn.get_template_summary().stack_name("iam").send().await.unwrap();
    assert_eq!(summary.resource_types(), ["AWS::IAM::Role"]);
    let cost = cfn.estimate_template_cost().template_body(APP).send().await.unwrap();
    assert!(cost.url().unwrap().starts_with("https://calculator.aws"));
    let limits = cfn.describe_account_limits().send().await.unwrap();
    assert!(limits.account_limits().iter().any(|l| l.name() == Some("StackLimit")));
}

#[tokio::test]
async fn updates_replace_resources_and_failures_roll_back() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let sqs = aws_sdk_sqs::Client::new(&mws.root_sdk_config().await);
    let template = |name: &str, timeout: &str| {
        format!(
            r#"{{"Parameters": {{"Retention": {{"Type": "Number", "Default": 345600}}}},
              "Resources": {{"Q": {{"Type": "AWS::SQS::Queue", "Properties": {{"QueueName": "{name}", "VisibilityTimeout": {timeout},
                "MessageRetentionPeriod": {{"Ref": "Retention"}}}}}}}},
              "Outputs": {{"Url": {{"Value": {{"Ref": "Q"}}}}}}}}"#
        )
    };
    cfn.create_stack().stack_name("upd").template_body(template("first", "30")).send().await.unwrap();
    let s = settle(&cfn, "upd").await;
    let first = output(&s, "Url");

    // An updatable property changes in place.
    cfn.update_stack().stack_name("upd").template_body(template("first", "45")).send().await.unwrap();
    let s = settle(&cfn, "upd").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::UpdateComplete));
    assert_eq!(output(&s, "Url"), first);
    let a = sqs
        .get_queue_attributes()
        .queue_url(&first)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout)
        .send()
        .await
        .unwrap();
    assert_eq!(a.attributes().unwrap()[&aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout], "45");

    // Nothing changed.
    let e = cfn.update_stack().stack_name("upd").template_body(template("first", "45")).send().await.unwrap_err();
    assert_eq!(message(&e.into_service_error()), "No updates are to be performed.");
    // UsePreviousTemplate with a new parameter value is a change.
    cfn.update_stack()
        .stack_name("upd")
        .use_previous_template(true)
        .parameters(param("Retention", "600"))
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "upd").await.stack_status(), Some(&StackStatus::UpdateComplete));

    // A create-only property replaces the queue: new first, old deleted in
    // cleanup.
    cfn.update_stack().stack_name("upd").template_body(template("second", "45")).send().await.unwrap();
    let s = settle(&cfn, "upd").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::UpdateComplete));
    let second = output(&s, "Url");
    assert!(second.ends_with("/second"));
    assert!(sqs.get_queue_url().queue_name("first").send().await.is_err());
    let events = cfn.describe_stack_events().stack_name("upd").send().await.unwrap();
    assert!(events
        .stack_events()
        .iter()
        .any(|e| e.resource_status().map(|s| s.as_str()) == Some("UPDATE_COMPLETE_CLEANUP_IN_PROGRESS")));
    assert!(events.stack_events().iter().any(|e| e.resource_status_reason()
        == Some("Requested update requires the creation of a new physical resource; hence creating one.")));

    // A failing update rolls back to the previous properties.
    cfn.update_stack().stack_name("upd").template_body(template("second", "999999")).send().await.unwrap();
    let s = settle(&cfn, "upd").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::UpdateRollbackComplete));
    let events = cfn.describe_stack_events().stack_name("upd").send().await.unwrap();
    let failed =
        events.stack_events().iter().find(|e| e.resource_status() == Some(&ResourceStatus::UpdateFailed)).unwrap();
    assert_eq!(failed.logical_resource_id(), Some("Q"));
    assert!(failed.resource_status_reason().unwrap().contains("Resource handler returned message"), "{failed:?}");
    assert_eq!(output(&s, "Url"), second);

    // A failing create rolls back and deletes what was created.
    let broken = r#"{"Resources": {
      "Good": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": "good"}},
      "Bad": {"Type": "AWS::SQS::Queue", "DependsOn": "Good", "Properties": {"QueueName": "bad", "DelaySeconds": 9999}}}}"#;
    cfn.create_stack().stack_name("broken").template_body(broken).send().await.unwrap();
    let s = settle(&cfn, "broken").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::RollbackComplete));
    let events = cfn.describe_stack_events().stack_name("broken").send().await.unwrap();
    assert!(events.stack_events().iter().any(|e| e.resource_status_reason()
        == Some("The following resource(s) failed to create: [Bad]. Rollback requested by user.")));
    assert!(sqs.get_queue_url().queue_name("good").send().await.is_err());
    // A ROLLBACK_COMPLETE stack cannot be updated, only deleted.
    let e = cfn.update_stack().stack_name("broken").template_body(broken).send().await.unwrap_err();
    assert!(message(&e.into_service_error()).contains("is in ROLLBACK_COMPLETE state and can not be updated"));
    cfn.delete_stack().stack_name("broken").send().await.unwrap();

    // DO_NOTHING keeps what was created.
    cfn.create_stack()
        .stack_name("kept")
        .template_body(broken.replace("good", "kept-good").replace("\"bad\"", "\"kept-bad\""))
        .on_failure(OnFailure::DoNothing)
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "kept").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateFailed));
    assert!(sqs.get_queue_url().queue_name("kept-good").send().await.is_ok());
    // RollbackStack rolls it back on request.
    cfn.rollback_stack().stack_name("kept").send().await.unwrap();
    assert_eq!(settle(&cfn, "kept").await.stack_status(), Some(&StackStatus::RollbackComplete));
    assert!(sqs.get_queue_url().queue_name("kept-good").send().await.is_err());
}

#[tokio::test]
async fn change_sets_preview_and_apply_changes() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let v1 = r#"{"Resources": {
      "Q": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}},
      "T": {"Type": "AWS::SNS::Topic"}}}"#;
    let created = cfn
        .create_change_set()
        .stack_name("cs")
        .change_set_name("initial")
        .change_set_type(ChangeSetType::Create)
        .template_body(v1)
        .send()
        .await
        .unwrap();
    assert!(created.id().unwrap().contains(":changeSet/initial/"));
    // The stack waits for review.
    let s = cfn.describe_stacks().stack_name("cs").send().await.unwrap();
    assert_eq!(s.stacks()[0].stack_status(), Some(&StackStatus::ReviewInProgress));
    let d = settle_change_set(&cfn, "cs", "initial").await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::CreateComplete));
    assert_eq!(d.execution_status().map(|e| e.as_str()), Some("AVAILABLE"));
    let actions: Vec<_> = d
        .changes()
        .iter()
        .map(|c| {
            let r = c.resource_change().unwrap();
            (r.logical_resource_id().unwrap().to_string(), r.action().unwrap().as_str().to_string())
        })
        .collect();
    assert_eq!(actions, [("Q".to_string(), "Add".to_string()), ("T".to_string(), "Add".to_string())]);
    cfn.execute_change_set().stack_name("cs").change_set_name("initial").send().await.unwrap();
    assert_eq!(settle(&cfn, "cs").await.stack_status(), Some(&StackStatus::CreateComplete));

    // An update: modify in place, replace, add and remove.
    let v2 = r#"{"Resources": {
      "Q": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 60, "FifoQueue": true}},
      "P": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": {"Ref": "Q"}}}}}"#;
    cfn.create_change_set().stack_name("cs").change_set_name("second").template_body(v2).send().await.unwrap();
    let d = settle_change_set(&cfn, "cs", "second").await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::CreateComplete), "{:?}", d.status_reason());
    let change = |id: &str| {
        d.changes()
            .iter()
            .find_map(|c| c.resource_change().filter(|r| r.logical_resource_id() == Some(id)).cloned())
            .unwrap()
    };
    assert_eq!(change("Q").action().unwrap().as_str(), "Modify");
    assert_eq!(change("Q").replacement().unwrap().as_str(), "True");
    assert_eq!(change("P").action().unwrap().as_str(), "Add");
    assert_eq!(change("T").action().unwrap().as_str(), "Remove");
    let listed = cfn.list_change_sets().stack_name("cs").send().await.unwrap();
    // The executed change set stays; executing removed none here.
    assert_eq!(listed.summaries().len(), 2);
    let hooks = cfn.describe_change_set_hooks().stack_name("cs").change_set_name("second").send().await.unwrap();
    assert!(hooks.hooks().is_empty());
    cfn.execute_change_set().stack_name("cs").change_set_name("second").send().await.unwrap();
    let s = settle(&cfn, "cs").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::UpdateComplete));
    let q = physical_id(&cfn, "cs", "Q").await;
    assert!(q.ends_with(".fifo"), "{q}");

    // A change set without changes fails, with AWS's reason.
    cfn.create_change_set().stack_name("cs").change_set_name("same").template_body(v2).send().await.unwrap();
    let d = settle_change_set(&cfn, "cs", "same").await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::Failed));
    assert_eq!(
        d.status_reason(),
        Some("The submitted information didn't contain changes. Submit different information to create a change set.")
    );
    cfn.delete_change_set().stack_name("cs").change_set_name("same").send().await.unwrap();
    let e = cfn.describe_change_set().stack_name("cs").change_set_name("same").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ChangeSetNotFound");
}

#[tokio::test]
async fn drift_stack_policies_and_termination_protection() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let sqs = aws_sdk_sqs::Client::new(&mws.root_sdk_config().await);
    let t = |timeout: u32| {
        format!(
            r#"{{"Resources": {{"Q": {{"Type": "AWS::SQS::Queue", "Properties": {{"VisibilityTimeout": {timeout}}}}},
              "Other": {{"Type": "AWS::SQS::Queue", "Properties": {{"DelaySeconds": {}}}}}}}}}"#,
            timeout / 10
        )
    };
    cfn.create_stack()
        .stack_name("drifty")
        .template_body(t(30))
        .enable_termination_protection(true)
        .send()
        .await
        .unwrap();
    settle(&cfn, "drifty").await;
    let url = physical_id(&cfn, "drifty", "Q").await;

    // Out-of-band change, then drift detection.
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout, "99")
        .send()
        .await
        .unwrap();
    let id = cfn
        .detect_stack_drift()
        .stack_name("drifty")
        .send()
        .await
        .unwrap()
        .stack_drift_detection_id()
        .unwrap()
        .to_string();
    let mut status = None;
    for _ in 0..100 {
        let d = cfn.describe_stack_drift_detection_status().stack_drift_detection_id(&id).send().await.unwrap();
        if d.detection_status() != Some(&StackDriftDetectionStatus::DetectionInProgress) {
            status = Some(d);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = status.unwrap();
    assert_eq!(status.detection_status(), Some(&StackDriftDetectionStatus::DetectionComplete));
    assert_eq!(status.stack_drift_status(), Some(&StackDriftStatus::Drifted));
    assert_eq!(status.drifted_stack_resource_count(), Some(1));
    let drifts = cfn.describe_stack_resource_drifts().stack_name("drifty").send().await.unwrap();
    let q = drifts.stack_resource_drifts().iter().find(|d| d.logical_resource_id() == Some("Q")).unwrap();
    assert_eq!(q.stack_resource_drift_status(), Some(&StackResourceDriftStatus::Modified));
    let diff = &q.property_differences()[0];
    assert_eq!(diff.property_path(), Some("/VisibilityTimeout"));
    assert_eq!(diff.expected_value(), Some("30"));
    assert_eq!(diff.actual_value(), Some("99"));
    let one = cfn.detect_stack_resource_drift().stack_name("drifty").logical_resource_id("Other").send().await.unwrap();
    assert_eq!(
        one.stack_resource_drift().unwrap().stack_resource_drift_status(),
        Some(&StackResourceDriftStatus::InSync)
    );
    let s = cfn.describe_stacks().stack_name("drifty").send().await.unwrap();
    assert_eq!(s.stacks()[0].drift_information().unwrap().stack_drift_status(), Some(&StackDriftStatus::Drifted));

    // A stack policy that protects Q fails an update that touches it.
    let policy = r#"{"Statement": [
      {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
      {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "LogicalResourceId/Q"}]}"#;
    cfn.set_stack_policy().stack_name("drifty").stack_policy_body(policy).send().await.unwrap();
    let got = cfn.get_stack_policy().stack_name("drifty").send().await.unwrap();
    assert_eq!(got.stack_policy_body(), Some(policy));
    cfn.update_stack().stack_name("drifty").template_body(t(40)).send().await.unwrap();
    let s = settle(&cfn, "drifty").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::UpdateRollbackComplete));
    let events = cfn.describe_stack_events().stack_name("drifty").send().await.unwrap();
    assert!(events
        .stack_events()
        .iter()
        .any(|e| e.resource_status_reason().is_some_and(|r| r.starts_with("Action denied by stack policy"))));
    // A temporary override lets it through.
    cfn.update_stack()
        .stack_name("drifty")
        .template_body(t(40))
        .stack_policy_during_update_body(
            r#"{"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "drifty").await.stack_status(), Some(&StackStatus::UpdateComplete));

    // Termination protection.
    let e = cfn.delete_stack().stack_name("drifty").send().await.unwrap_err();
    assert_eq!(
        message(&e.into_service_error()),
        "Stack [drifty] cannot be deleted while TerminationProtection is enabled"
    );
    cfn.update_termination_protection().stack_name("drifty").enable_termination_protection(false).send().await.unwrap();
    // Retain the protected queue on delete.
    cfn.delete_stack().stack_name("drifty").retain_resources("Q").send().await.unwrap_err();
    cfn.delete_stack().stack_name("drifty").send().await.unwrap();
    assert_eq!(settle(&cfn, s.stack_id().unwrap()).await.stack_status(), Some(&StackStatus::DeleteComplete));
}

#[tokio::test]
async fn custom_resources_run_lambda_and_wait_conditions_wait_for_signals() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let template = r#"
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
  Adder:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt Role.Arn
      Timeout: 30
      Code:
        ZipFile: |
          import cfnresponse
          def handler(event, context):
              props = event["ResourceProperties"]
              if event["RequestType"] == "Delete":
                  cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
                  return
              total = int(props["A"]) + int(props["B"])
              cfnresponse.send(event, context, cfnresponse.SUCCESS, {"Sum": str(total)}, "sum-" + str(total))
  Sum:
    Type: Custom::Adder
    Properties:
      ServiceToken: !GetAtt Adder.Arn
      A: 2
      B: 40
  Handle:
    Type: AWS::CloudFormation::WaitConditionHandle
  Wait:
    Type: AWS::CloudFormation::WaitCondition
    Properties:
      Handle: !Ref Handle
      Timeout: "60"
Outputs:
  Sum:
    Value: !GetAtt Sum.Sum
  Physical:
    Value: !Ref Sum
  HandleUrl:
    Value: !Ref Handle
  Data:
    Value: !GetAtt Wait.Data
"#;
    cfn.create_stack()
        .stack_name("custom")
        .template_body(template)
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    // Wait for the handle, then signal it the way cfn-signal does.
    let mut handle = None;
    for _ in 0..600 {
        if let Ok(r) = cfn.describe_stack_resource().stack_name("custom").logical_resource_id("Handle").send().await {
            if let Some(id) = r.stack_resource_detail().and_then(|d| d.physical_resource_id()) {
                handle = Some(id.to_string());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let handle = handle.expect("wait condition handle");
    let path = &handle[handle.find("/_aws/").unwrap()..];
    let (status, _) = mws
        .control("PUT", path, Some(r#"{"Status": "SUCCESS", "UniqueId": "box1", "Data": "ready", "Reason": "done"}"#))
        .await;
    assert_eq!(status, 200);
    let s = settle(&cfn, "custom").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    assert_eq!(output(&s, "Sum"), "42");
    assert_eq!(output(&s, "Physical"), "sum-42");
    assert_eq!(output(&s, "Data"), r#"{"box1":"ready"}"#);

    // SignalResource on a resource without a creation policy is rejected.
    let e = cfn
        .signal_resource()
        .stack_name("custom")
        .logical_resource_id("Sum")
        .unique_id("i-1")
        .status(aws_sdk_cloudformation::types::ResourceSignalStatus::Success)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ValidationError");

    cfn.delete_stack().stack_name("custom").send().await.unwrap();
    assert_eq!(settle(&cfn, s.stack_id().unwrap()).await.stack_status(), Some(&StackStatus::DeleteComplete));
}

#[tokio::test]
async fn nested_stacks_read_child_outputs() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let config = mws.root_sdk_config().await;
    let s3 = Mws::s3(&config);
    s3.create_bucket().bucket("templates").send().await.unwrap();
    let child = r#"{"Parameters": {"Prefix": {"Type": "String"}},
      "Resources": {"Q": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Fn::Sub": "${Prefix}-child"}}}},
      "Outputs": {"Url": {"Value": {"Ref": "Q"}}}}"#;
    s3.put_object().bucket("templates").key("child.json").body(child.as_bytes().to_vec().into()).send().await.unwrap();
    let parent = r#"{"Resources": {"Child": {"Type": "AWS::CloudFormation::Stack", "Properties": {
        "TemplateURL": "https://templates.s3.amazonaws.com/child.json", "Parameters": {"Prefix": "nested"}}}},
      "Outputs": {"ChildUrl": {"Value": {"Fn::GetAtt": ["Child", "Outputs.Url"]}}}}"#;
    // Nested stacks need CAPABILITY_AUTO_EXPAND, as on AWS.
    cfn.create_stack()
        .stack_name("parent")
        .template_body(parent)
        .capabilities(Capability::CapabilityAutoExpand)
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "parent").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    assert!(output(&s, "ChildUrl").ends_with("/nested-child"));
    let child_id = physical_id(&cfn, "parent", "Child").await;
    let c = cfn.describe_stacks().stack_name(&child_id).send().await.unwrap();
    let c = &c.stacks()[0];
    assert!(c.stack_name().unwrap().starts_with("parent-Child-"));
    assert_eq!(c.parent_id(), s.stack_id());
    assert_eq!(c.root_id(), s.stack_id());

    // Templates from S3 work for top-level stacks too.
    cfn.create_stack()
        .stack_name("from-s3")
        .template_url("https://templates.s3.amazonaws.com/child.json")
        .parameters(param("Prefix", "direct"))
        .send()
        .await
        .unwrap();
    assert_eq!(settle(&cfn, "from-s3").await.stack_status(), Some(&StackStatus::CreateComplete));

    cfn.delete_stack().stack_name("parent").send().await.unwrap();
    assert_eq!(settle(&cfn, s.stack_id().unwrap()).await.stack_status(), Some(&StackStatus::DeleteComplete));
    let c = cfn.describe_stacks().stack_name(&child_id).send().await.unwrap();
    assert_eq!(c.stacks()[0].stack_status(), Some(&StackStatus::DeleteComplete));
}

#[tokio::test]
async fn service_roles_decide_what_a_stack_may_create() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&root);
    let trust = r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
      "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("cfn-deployer").assume_role_policy_document(trust).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    iam.put_role_policy()
        .role_name("cfn-deployer")
        .policy_name("sqs")
        .policy_document(
            r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:*", "Resource": "*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    // A user who may use CloudFormation and pass the role, nothing else.
    let (_, user) = mws_e2e::user_with_policy(
        &mws,
        "deployer",
        Some(&format!(
            r#"{{"Version": "2012-10-17", "Statement": [
              {{"Effect": "Allow", "Action": "cloudformation:*", "Resource": "*"}},
              {{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "{role_arn}"}}]}}"#
        )),
    )
    .await;
    let cfn = Client::new(&user);
    let queue = r#"{"Resources": {"Q": {"Type": "AWS::SQS::Queue"}}}"#;

    // Without a role the stack acts as the user, who cannot create queues.
    cfn.create_stack().stack_name("as-user").template_body(queue).send().await.unwrap();
    let s = settle(&cfn, "as-user").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::RollbackComplete));
    let events = cfn.describe_stack_events().stack_name("as-user").send().await.unwrap();
    let failed =
        events.stack_events().iter().find(|e| e.resource_status() == Some(&ResourceStatus::CreateFailed)).unwrap();
    assert!(failed.resource_status_reason().unwrap().contains("HandlerErrorCode: AccessDenied"), "{failed:?}");

    // With the role it succeeds.
    cfn.create_stack().stack_name("as-role").template_body(queue).role_arn(&role_arn).send().await.unwrap();
    let s = settle(&cfn, "as-role").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    assert_eq!(s.role_arn(), Some(role_arn.as_str()));

    // A role CloudFormation cannot assume is rejected up front.
    let e = cfn
        .create_stack()
        .stack_name("bad-role")
        .template_body(queue)
        .role_arn(format!("arn:aws:iam::{ACCOUNT}:role/missing"))
        .send()
        .await
        .unwrap_err();
    // The PassRole check comes first.
    let e = e.into_service_error();
    assert_eq!(code(&e), "AccessDenied");
    assert!(message(&e).contains("iam:PassRole"), "{}", message(&e));
}

#[tokio::test]
async fn networking_dns_and_monitoring_resources() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let config = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let template = r#"
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.20.0.0/16
      EnableDnsHostnames: true
      Tags: [{Key: Name, Value: cfn-vpc}]
  Subnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !Select [0, !Cidr [!GetAtt Vpc.CidrBlock, 4, 8]]
      AvailabilityZone: !Select [0, !GetAZs ""]
      MapPublicIpOnLaunch: true
  Igw:
    Type: AWS::EC2::InternetGateway
  Attach:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties: {VpcId: !Ref Vpc, InternetGatewayId: !Ref Igw}
  Routes:
    Type: AWS::EC2::RouteTable
    Properties: {VpcId: !Ref Vpc}
  DefaultRoute:
    Type: AWS::EC2::Route
    DependsOn: Attach
    Properties: {RouteTableId: !Ref Routes, DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref Igw}
  Assoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: {SubnetId: !Ref Subnet, RouteTableId: !Ref Routes}
  Web:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0}
  Zone:
    Type: AWS::Route53::HostedZone
    Properties: {Name: cfn.example.com}
  Www:
    Type: AWS::Route53::RecordSet
    Properties:
      HostedZoneId: !Ref Zone
      Name: www.cfn.example.com
      Type: A
      TTL: "60"
      ResourceRecords: [192.0.2.10]
  Logs:
    Type: AWS::Logs::LogGroup
    Properties: {RetentionInDays: 7}
  Errors:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref Logs
      FilterPattern: ERROR
      MetricTransformations: [{MetricName: Errors, MetricNamespace: App, MetricValue: "1"}]
  Alarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      Namespace: App
      MetricName: Errors
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
  Key:
    Type: AWS::KMS::Key
  KeyAlias:
    Type: AWS::KMS::Alias
    Properties: {AliasName: alias/cfn-key, TargetKeyId: !Ref Key}
  Stream:
    Type: AWS::Kinesis::Stream
    Properties: {ShardCount: 2}
  Bus:
    Type: AWS::Events::EventBus
    Properties: {Name: cfn-bus}
  Rule:
    Type: AWS::Events::Rule
    Properties:
      EventBusName: !Ref Bus
      EventPattern: {source: [app]}
      Targets: [{Id: logs, Arn: !GetAtt Logs.Arn}]
  Secret:
    Type: AWS::SecretsManager::Secret
    Properties:
      GenerateSecretString: {PasswordLength: 24, ExcludePunctuation: true}
  PasswordCopy:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /infra/password-copy
      Type: String
      Value: !Sub "{{resolve:secretsmanager:${Secret}:SecretString}}"
Outputs:
  VpcId: {Value: !Ref Vpc}
  SubnetCidr: {Value: !GetAtt Subnet.CidrBlock}
  DefaultSg: {Value: !GetAtt Vpc.DefaultSecurityGroup}
  NameServers: {Value: !Join [",", !GetAtt Zone.NameServers]}
  KeyArn: {Value: !GetAtt Key.Arn}
  StreamArn: {Value: !GetAtt Stream.Arn}
"#;
    cfn.create_stack().stack_name("infra").template_body(template).send().await.unwrap();
    let s = settle(&cfn, "infra").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", failures(&cfn, "infra").await);
    assert_eq!(output(&s, "SubnetCidr"), "10.20.0.0/24");
    // The dynamic reference resolved to the generated password.
    let ssm = aws_sdk_ssm::Client::new(&config);
    let copy = ssm.get_parameter().name("/infra/password-copy").send().await.unwrap();
    assert_eq!(copy.parameter().unwrap().value().unwrap().len(), 24);
    assert!(output(&s, "NameServers").contains(','));

    let vpc = output(&s, "VpcId");
    let vpcs = ec2.describe_vpcs().vpc_ids(&vpc).send().await.unwrap();
    assert_eq!(vpcs.vpcs()[0].cidr_block(), Some("10.20.0.0/16"));
    assert!(vpcs.vpcs()[0].tags().iter().any(|t| t.key() == Some("Name") && t.value() == Some("cfn-vpc")));
    let sg = physical_id(&cfn, "infra", "Web").await;
    let groups = ec2.describe_security_groups().group_ids(&sg).send().await.unwrap();
    let perms = groups.security_groups()[0].ip_permissions();
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].from_port(), Some(443));
    assert!(output(&s, "DefaultSg").starts_with("sg-"));
    let rt = physical_id(&cfn, "infra", "Routes").await;
    let tables = ec2.describe_route_tables().route_table_ids(&rt).send().await.unwrap();
    assert!(tables.route_tables()[0].routes().iter().any(|r| r.destination_cidr_block() == Some("0.0.0.0/0")));

    let r53 = aws_sdk_route53::Client::new(&config);
    let zone = physical_id(&cfn, "infra", "Zone").await;
    let records = r53.list_resource_record_sets().hosted_zone_id(&zone).send().await.unwrap();
    assert!(records.resource_record_sets().iter().any(|r| r.name() == "www.cfn.example.com."));

    let kms = aws_sdk_kms::Client::new(&config);
    let key = kms.describe_key().key_id("alias/cfn-key").send().await.unwrap();
    assert_eq!(key.key_metadata().unwrap().arn(), Some(output(&s, "KeyArn").as_str()));
    let kinesis = aws_sdk_kinesis::Client::new(&config);
    let stream = kinesis.describe_stream_summary().stream_arn(output(&s, "StreamArn")).send().await.unwrap();
    assert_eq!(stream.stream_description_summary().unwrap().open_shard_count(), 2);
    let cw = aws_sdk_cloudwatch::Client::new(&config);
    let alarm = physical_id(&cfn, "infra", "Alarm").await;
    let alarms = cw.describe_alarms().alarm_names(&alarm).send().await.unwrap();
    assert_eq!(alarms.metric_alarms()[0].threshold(), Some(1.0));

    // Resource types are listed in the registry.
    let types = cfn
        .list_types()
        .visibility(aws_sdk_cloudformation::types::Visibility::Public)
        .r#type(aws_sdk_cloudformation::types::RegistryType::Resource)
        .send()
        .await
        .unwrap();
    assert!(types.type_summaries().iter().any(|t| t.type_name() == Some("AWS::EC2::VPC")));
    let described = cfn
        .describe_type()
        .r#type(aws_sdk_cloudformation::types::RegistryType::Resource)
        .type_name("AWS::SQS::Queue")
        .send()
        .await
        .unwrap();
    assert!(described.schema().unwrap().contains("QueueName"));

    cfn.delete_stack().stack_name("infra").send().await.unwrap();
    let s = settle(&cfn, s.stack_id().unwrap()).await;
    assert_eq!(s.stack_status(), Some(&StackStatus::DeleteComplete), "{:?}", s.stack_status_reason());
    assert!(ec2.describe_vpcs().vpc_ids(&vpc).send().await.is_err());
}

#[tokio::test]
async fn cancelling_an_update_rolls_it_back() {
    let mws = Mws::start().await;
    let cfn = client(&mws).await;
    let sqs = aws_sdk_sqs::Client::new(&mws.root_sdk_config().await);
    let v1 = r#"{"Resources": {"Q": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": "keep"}}}}"#;
    cfn.create_stack().stack_name("cancel").template_body(v1).send().await.unwrap();
    settle(&cfn, "cancel").await;
    // Neither call applies to a stack that is not updating or failed.
    let e = cfn.cancel_update_stack().stack_name("cancel").send().await.unwrap_err();
    assert_eq!(message(&e.into_service_error()), "CancelUpdateStack cannot be called from current stack status");
    let e = cfn.continue_update_rollback().stack_name("cancel").send().await.unwrap_err();
    assert_eq!(message(&e.into_service_error()), "ContinueUpdateRollback cannot be called from current stack status");

    // An update that waits on a signal, cancelled while it waits.
    let v2 = r#"{"Resources": {
      "Q": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": "keep"}},
      "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
      "Wait": {"Type": "AWS::CloudFormation::WaitCondition", "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "60"}},
      "Later": {"Type": "AWS::SQS::Queue", "DependsOn": "Wait", "Properties": {"QueueName": "later"}}}}"#;
    cfn.update_stack().stack_name("cancel").template_body(v2).send().await.unwrap();
    let mut handle = None;
    for _ in 0..300 {
        let r = cfn.describe_stack_resources().stack_name("cancel").logical_resource_id("Handle").send().await.unwrap();
        if let Some(id) = r.stack_resources().first().and_then(|r| r.physical_resource_id()) {
            handle = Some(id.to_string());
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let handle = handle.expect("handle created");
    cfn.cancel_update_stack().stack_name("cancel").send().await.unwrap();
    let path = &handle[handle.find("/_aws/").unwrap()..];
    mws.control("PUT", path, Some(r#"{"Status": "SUCCESS", "UniqueId": "1", "Data": "x", "Reason": "r"}"#)).await;
    let s = settle(&cfn, "cancel").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::UpdateRollbackComplete), "{:?}", failures(&cfn, "cancel").await);
    assert!(sqs.get_queue_url().queue_name("later").send().await.is_err());
    assert!(sqs.get_queue_url().queue_name("keep").send().await.is_ok());
    let r = cfn.list_stack_resources().stack_name("cancel").send().await.unwrap();
    assert_eq!(r.stack_resource_summaries().len(), 1);
}
