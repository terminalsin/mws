//! The CloudFormation registry through the official Rust SDK: private
//! resource types whose handlers really run, modules, hooks, type
//! configuration, testing, publishing and activation.

use std::time::Duration;

use aws_sdk_cloudformation::error::ProvideErrorMetadata;
use aws_sdk_cloudformation::types::{
    Category, HandlerErrorCode, HookStatus, HookTargetType, ListHookResultsTargetType, OperationStatus,
    RegistrationStatus, RegistryType, StackStatus, TypeConfigurationIdentifier, TypeFilters, TypeTestsStatus,
    Visibility,
};
use aws_sdk_cloudformation::Client;
use mws_e2e::Mws;

use crate::lambda::zip;

const ACCOUNT: &str = "123456789012";

const COUNTER_SCHEMA: &str = r#"{
  "typeName": "Mws::Test::Counter",
  "description": "A counter its handler keeps in a file",
  "properties": {
    "Name": {"type": "string"},
    "Value": {"type": "integer"},
    "TokenFile": {"type": "string"},
    "Id": {"type": "string"},
    "Arn": {"type": "string"},
    "Label": {"type": "string"}
  },
  "required": ["Name"],
  "primaryIdentifier": ["/properties/Id"],
  "readOnlyProperties": ["/properties/Id", "/properties/Arn", "/properties/Label"],
  "createOnlyProperties": ["/properties/Name"],
  "additionalProperties": false,
  "typeConfiguration": {"properties": {"Prefix": {"type": "string"}}, "additionalProperties": false},
  "handlers": {
    "create": {"permissions": []},
    "read": {"permissions": []},
    "update": {"permissions": []},
    "delete": {"permissions": []}
  }
}"#;

/// A resource handler speaking the CloudFormation CLI protocol directly.
const COUNTER_HANDLER: &str = r#"
import json, os, tempfile, uuid

DIR = os.path.join(tempfile.gettempdir(), "mws-cfn-counter")
os.makedirs(DIR, exist_ok=True)

def path(model):
    return os.path.join(DIR, model["Id"] + ".json")

def not_found(model):
    return {"status": "FAILED", "errorCode": "NotFound", "message": "Counter %s not found" % model.get("Id")}

def resource(event, context):
    action = event["action"]
    model = dict(event["requestData"]["resourceProperties"] or {})
    callback = event.get("callbackContext") or {}
    config = event["requestData"].get("typeConfiguration") or {}
    if action == "CREATE":
        if model.get("Value") == 13:
            return {"status": "FAILED", "errorCode": "InvalidRequest", "message": "13 is unlucky"}
        if model.get("TokenFile") and not callback:
            with open(model["TokenFile"], "w") as f:
                f.write(event["bearerToken"])
            return {"status": "IN_PROGRESS", "callbackContext": {"waiting": True}, "callbackDelaySeconds": 600, "resourceModel": model}
        if not callback.get("stage"):
            return {"status": "IN_PROGRESS", "callbackContext": {"stage": 1}, "callbackDelaySeconds": 0, "resourceModel": model}
        model["Id"] = uuid.uuid4().hex[:12]
        model["Arn"] = "arn:aws:mws-counter:%s:%s:counter/%s" % (event["region"], event["awsAccountId"], model["Id"])
        model["Label"] = config.get("Prefix", "") + model["Name"]
        with open(path(model), "w") as f:
            json.dump(model, f)
        return {"status": "SUCCESS", "resourceModel": model}
    if not model.get("Id") or not os.path.exists(path(model)):
        return not_found(model)
    with open(path(model)) as f:
        stored = json.load(f)
    if action == "READ":
        return {"status": "SUCCESS", "resourceModel": stored}
    if action == "UPDATE":
        stored.update({k: v for k, v in model.items() if k not in ("Id", "Arn", "Label")})
        with open(path(model), "w") as f:
            json.dump(stored, f)
        return {"status": "SUCCESS", "resourceModel": stored}
    if action == "DELETE":
        os.remove(path(model))
        return {"status": "SUCCESS"}
    return {"status": "FAILED", "errorCode": "InvalidRequest", "message": "unsupported " + action}
"#;

const HOOK_SCHEMA: &str = r#"{
  "typeName": "Mws::Test::QueueNames",
  "description": "Rejects queues whose names contain a forbidden word",
  "typeConfiguration": {"properties": {"Forbidden": {"type": "string"}}, "additionalProperties": false},
  "handlers": {
    "preCreate": {"targetNames": ["AWS::SQS::Queue"], "permissions": []},
    "preUpdate": {"targetNames": ["AWS::SQS::Queue"], "permissions": []}
  },
  "additionalProperties": false
}"#;

const HOOK_HANDLER: &str = r#"
def hook(event, context):
    props = event["requestData"]["targetModel"]["resourceProperties"]
    forbidden = (event.get("hookModel") or {}).get("Forbidden", "public")
    if forbidden in str(props.get("QueueName", "")):
        return {"status": "FAILED", "errorCode": "NonCompliant", "message": "Queue names must not contain " + forbidden}
    return {"status": "SUCCESS", "message": "Queue name is compliant"}
"#;

const FRAGMENT: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A queue with its dead-letter queue",
  "Parameters": {"Retention": {"Type": "String", "Default": "345600"}},
  "Resources": {
    "Dlq": {"Type": "AWS::SQS::Queue", "Properties": {"MessageRetentionPeriod": {"Ref": "Retention"}}},
    "Queue": {
      "Type": "AWS::SQS::Queue",
      "Properties": {"RedrivePolicy": {"deadLetterTargetArn": {"Fn::GetAtt": ["Dlq", "Arn"]}, "maxReceiveCount": 3}}
    }
  }
}"#;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn upload(s3: &aws_sdk_s3::Client, key: &str, body: Vec<u8>) -> String {
    s3.put_object().bucket("packages").key(key).body(body.into()).send().await.unwrap();
    format!("s3://packages/{key}")
}

async fn register(cfn: &Client, kind: RegistryType, name: &str, package: &str) -> String {
    let token = cfn
        .register_type()
        .r#type(kind)
        .type_name(name)
        .schema_handler_package(package)
        .send()
        .await
        .unwrap()
        .registration_token()
        .unwrap()
        .to_string();
    for _ in 0..200 {
        let d = cfn.describe_type_registration().registration_token(&token).send().await.unwrap();
        match d.progress_status() {
            Some(RegistrationStatus::InProgress) => tokio::time::sleep(Duration::from_millis(50)).await,
            Some(RegistrationStatus::Complete) => return d.type_version_arn().unwrap().to_string(),
            other => panic!("registration of {name} ended {other:?}: {:?}", d.description()),
        }
    }
    panic!("registration of {name} did not finish");
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

fn output(s: &aws_sdk_cloudformation::types::Stack, key: &str) -> String {
    s.outputs().iter().find(|o| o.output_key() == Some(key)).unwrap().output_value().unwrap().to_string()
}

fn counter_package(schema: &str) -> Vec<u8> {
    zip(&[
        ("schema.json", schema),
        (
            ".rpdk-config",
            r#"{"typeName":"Mws::Test::Counter","language":"python312","runtime":"python3.12","entrypoint":"handler.resource"}"#,
        ),
        ("handler.py", COUNTER_HANDLER),
        ("inputs/inputs_1_create.json", r#"{"Name":"contract","Value":1}"#),
        ("inputs/inputs_1_update.json", r#"{"Name":"contract","Value":2}"#),
    ])
}

#[tokio::test]
async fn private_resource_types_run_their_handlers() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let s3 = Mws::s3(&config);
    s3.create_bucket().bucket("packages").send().await.unwrap();

    // Registration checks the name and the schema.
    let reserved = cfn
        .register_type()
        .type_name("AWS::Test::Counter")
        .schema_handler_package("s3://packages/x.zip")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&reserved), "CFNRegistryException");
    let bad = upload(&s3, "bad.zip", zip(&[("schema.json", r#"{"typeName":"Mws::Test::Counter"}"#)])).await;
    let token = cfn
        .register_type()
        .type_name("Mws::Test::Counter")
        .schema_handler_package(&bad)
        .send()
        .await
        .unwrap()
        .registration_token()
        .unwrap()
        .to_string();
    let mut failed = None;
    for _ in 0..100 {
        let d = cfn.describe_type_registration().registration_token(&token).send().await.unwrap();
        if d.progress_status() != Some(&RegistrationStatus::InProgress) {
            failed = Some(d);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let failed = failed.unwrap();
    assert_eq!(failed.progress_status(), Some(&RegistrationStatus::Failed));
    assert!(failed.description().unwrap().contains("description"), "{:?}", failed.description());

    let package = upload(&s3, "counter.zip", counter_package(COUNTER_SCHEMA)).await;
    let v1 = register(&cfn, RegistryType::Resource, "Mws::Test::Counter", &package).await;
    let type_arn = format!("arn:aws:cloudformation:us-east-1:{ACCOUNT}:type/resource/Mws-Test-Counter");
    assert_eq!(v1, format!("{type_arn}/00000001"));
    let regs = cfn
        .list_type_registrations()
        .type_name("Mws::Test::Counter")
        .r#type(RegistryType::Resource)
        .send()
        .await
        .unwrap();
    assert_eq!(regs.registration_token_list().len(), 2);
    let complete = cfn
        .list_type_registrations()
        .type_arn(&type_arn)
        .registration_status_filter(RegistrationStatus::Complete)
        .send()
        .await
        .unwrap();
    assert_eq!(complete.registration_token_list().len(), 1);
    let d = cfn.describe_type().r#type(RegistryType::Resource).type_name("Mws::Test::Counter").send().await.unwrap();
    assert_eq!(d.arn(), Some(type_arn.as_str()));
    assert_eq!(d.visibility(), Some(&Visibility::Private));
    assert_eq!(d.default_version_id(), Some("00000001"));
    assert_eq!(d.type_tests_status(), Some(&TypeTestsStatus::NotTested));
    assert_eq!(d.provisioning_type().unwrap().as_str(), "FULLY_MUTABLE");
    let private = cfn.list_types().visibility(Visibility::Private).send().await.unwrap();
    assert_eq!(private.type_summaries().len(), 1);
    assert_eq!(private.type_summaries()[0].type_name(), Some("Mws::Test::Counter"));

    // Configuration reaches the handler.
    let set =
        cfn.set_type_configuration().type_arn(&type_arn).configuration(r#"{"Prefix":"cfg-"}"#).send().await.unwrap();
    assert_eq!(
        set.configuration_arn(),
        Some(
            format!("arn:aws:cloudformation:us-east-1:{ACCOUNT}:type-configuration/resource/Mws-Test-Counter/default")
                .as_str()
        )
    );
    let configs = cfn
        .batch_describe_type_configurations()
        .type_configuration_identifiers(TypeConfigurationIdentifier::builder().type_arn(&type_arn).build())
        .type_configuration_identifiers(
            TypeConfigurationIdentifier::builder()
                .r#type(aws_sdk_cloudformation::types::ThirdPartyType::Resource)
                .type_name("Mws::Missing::Thing")
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(configs.type_configurations().len(), 1);
    assert_eq!(configs.type_configurations()[0].configuration(), Some(r#"{"Prefix":"cfg-"}"#));
    assert_eq!(configs.type_configurations()[0].is_default_configuration(), Some(true));
    assert_eq!(configs.errors().len(), 1);

    // A stack creates, reads (drift), updates and deletes through the
    // handlers.
    let template = r#"
Resources:
  Counter:
    Type: Mws::Test::Counter
    Properties:
      Name: visits
      Value: 1
Outputs:
  Id:
    Value: !Ref Counter
  Arn:
    Value: !GetAtt Counter.Arn
  Label:
    Value: !GetAtt Counter.Label
"#;
    cfn.create_stack().stack_name("counters").template_body(template).send().await.unwrap();
    let s = settle(&cfn, "counters").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    let id = output(&s, "Id");
    assert_eq!(id.len(), 12);
    assert_eq!(output(&s, "Arn"), format!("arn:aws:mws-counter:us-east-1:{ACCOUNT}:counter/{id}"));
    assert_eq!(output(&s, "Label"), "cfg-visits");
    let file = std::env::temp_dir().join("mws-cfn-counter").join(format!("{id}.json"));
    let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(stored["Value"], 1);
    cfn.update_stack()
        .stack_name("counters")
        .template_body(template.replace("Value: 1", "Value: 5"))
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "counters").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::UpdateComplete), "{:?}", s.stack_status_reason());
    let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(stored["Value"], 5);
    // Out-of-band change, seen by drift detection through READ.
    let mut changed = stored.clone();
    changed["Value"] = serde_json::json!(9);
    std::fs::write(&file, changed.to_string()).unwrap();
    let det = cfn.detect_stack_drift().stack_name("counters").send().await.unwrap();
    let st = cfn
        .describe_stack_drift_detection_status()
        .stack_drift_detection_id(det.stack_drift_detection_id().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(st.stack_drift_status().unwrap().as_str(), "DRIFTED");
    cfn.delete_stack().stack_name("counters").send().await.unwrap();
    let gone = cfn.describe_stacks().stack_name(s.stack_id().unwrap()).send().await.unwrap();
    let _ = gone;
    for _ in 0..100 {
        if !file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!file.exists(), "DELETE did not run");

    // Handler failures are reported with their error code.
    cfn.create_stack()
        .stack_name("unlucky")
        .template_body(template.replace("Value: 1", "Value: 13"))
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "unlucky").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::RollbackComplete));
    let events = cfn.describe_stack_events().stack_name("unlucky").send().await.unwrap();
    let reason = events
        .stack_events()
        .iter()
        .find(|e| e.resource_status().is_some_and(|s| s.as_str() == "CREATE_FAILED"))
        .and_then(|e| e.resource_status_reason())
        .unwrap()
        .to_string();
    assert!(reason.contains("13 is unlucky") && reason.contains("HandlerErrorCode: InvalidRequest"), "{reason}");

    // A long-running handler reports completion with RecordHandlerProgress.
    let token_file = std::env::temp_dir().join(format!("mws-cfn-token-{}", uuid_like()));
    let waiting = format!(
        "Resources:\n  Counter:\n    Type: Mws::Test::Counter\n    Properties:\n      Name: slow\n      TokenFile: {}\n",
        token_file.display()
    );
    cfn.create_stack().stack_name("slow").template_body(waiting).send().await.unwrap();
    let mut bearer = String::new();
    for _ in 0..200 {
        if let Ok(t) = std::fs::read_to_string(&token_file) {
            if !t.is_empty() {
                bearer = t;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!bearer.is_empty(), "the handler did not start");
    let wrong = cfn
        .record_handler_progress()
        .bearer_token(&bearer)
        .operation_status(OperationStatus::Success)
        .current_operation_status(OperationStatus::Failed)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&wrong), "ConditionalCheckFailed");
    cfn.record_handler_progress()
        .bearer_token(&bearer)
        .operation_status(OperationStatus::Success)
        .resource_model(r#"{"Name":"slow","Id":"reported0001","Arn":"arn:reported","Label":"slow"}"#)
        .client_request_token("progress-1")
        .send()
        .await
        .unwrap();
    let s = settle(&cfn, "slow").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    let r = cfn.describe_stack_resource().stack_name("slow").logical_resource_id("Counter").send().await.unwrap();
    assert_eq!(r.stack_resource_detail().unwrap().physical_resource_id(), Some("reported0001"));
    let late = cfn
        .record_handler_progress()
        .bearer_token(&bearer)
        .operation_status(OperationStatus::Failed)
        .error_code(HandlerErrorCode::InternalFailure)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&late), "InvalidStateTransition");
    let _ = std::fs::remove_file(&token_file);

    // Versions: a second registration becomes version 2.
    let v2 = register(&cfn, RegistryType::Resource, "Mws::Test::Counter", &package).await;
    assert_eq!(v2, format!("{type_arn}/00000002"));
    let versions = cfn.list_type_versions().arn(&type_arn).send().await.unwrap();
    assert_eq!(versions.type_version_summaries().len(), 2);
    assert_eq!(versions.type_version_summaries()[0].is_default_version(), Some(true));
    let default_err = cfn.deregister_type().arn(&v1).send().await.unwrap_err();
    assert_eq!(code(&default_err), "CFNRegistryException");
    cfn.set_type_default_version().arn(&v2).send().await.unwrap();
    cfn.deregister_type().arn(&v1).send().await.unwrap();
    let live = cfn.list_type_versions().arn(&type_arn).send().await.unwrap();
    assert_eq!(live.type_version_summaries().len(), 1);
    assert_eq!(live.type_version_summaries()[0].version_id(), Some("00000002"));
    let deprecated = cfn
        .list_type_versions()
        .arn(&type_arn)
        .deprecated_status(aws_sdk_cloudformation::types::DeprecatedStatus::Deprecated)
        .send()
        .await
        .unwrap();
    assert_eq!(deprecated.type_version_summaries()[0].version_id(), Some("00000001"));

    // Testing, publishing and activation.
    let tested = cfn.test_type().arn(&type_arn).log_delivery_bucket("packages").send().await.unwrap();
    assert_eq!(tested.type_version_arn(), Some(v2.as_str()));
    let mut status = None;
    for _ in 0..300 {
        let d = cfn.describe_type().arn(&v2).send().await.unwrap();
        if d.type_tests_status() != Some(&TypeTestsStatus::InProgress) {
            status = Some(d);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = status.unwrap();
    assert_eq!(
        status.type_tests_status(),
        Some(&TypeTestsStatus::Passed),
        "{:?}",
        status.type_tests_status_description()
    );
    let logs = s3.list_objects_v2().bucket("packages").prefix("Mws-Test-Counter/").send().await.unwrap();
    assert_eq!(logs.contents().len(), 1);

    let unregistered = cfn.publish_type().arn(&type_arn).send().await.unwrap_err();
    assert_eq!(code(&unregistered), "CFNRegistryException");
    let no_terms = cfn.register_publisher().send().await.unwrap_err();
    assert_eq!(code(&no_terms), "ValidationError");
    let publisher = cfn.register_publisher().accept_terms_and_conditions(true).send().await.unwrap();
    let publisher = publisher.publisher_id().unwrap().to_string();
    let me = cfn.describe_publisher().send().await.unwrap();
    assert_eq!(me.publisher_id(), Some(publisher.as_str()));
    assert_eq!(me.publisher_status().unwrap().as_str(), "VERIFIED");
    let published = cfn.publish_type().arn(&type_arn).public_version_number("1.0.0").send().await.unwrap();
    let public_arn = published.public_type_arn().unwrap().to_string();
    assert_eq!(public_arn, format!("arn:aws:cloudformation:us-east-1::type/resource/{publisher}/Mws-Test-Counter"));
    let older = cfn.publish_type().arn(&type_arn).public_version_number("0.9.0").send().await.unwrap_err();
    assert_eq!(code(&older), "CFNRegistryException");
    let third_party = cfn
        .list_types()
        .visibility(Visibility::Public)
        .filters(TypeFilters::builder().category(Category::ThirdParty).build())
        .send()
        .await
        .unwrap();
    assert_eq!(third_party.type_summaries().len(), 1);
    assert_eq!(third_party.type_summaries()[0].latest_public_version(), Some("1.0.0"));
    let public = cfn.describe_type().arn(&public_arn).send().await.unwrap();
    assert_eq!(public.visibility(), Some(&Visibility::Public));
    assert_eq!(public.publisher_id(), Some(publisher.as_str()));
    let public_versions = cfn
        .list_type_versions()
        .r#type(RegistryType::Resource)
        .type_name("Mws::Test::Counter")
        .publisher_id("0000000000000000000000000000000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&public_versions), "TypeNotFoundException");

    let activated = cfn
        .activate_type()
        .public_type_arn(&public_arn)
        .type_name_alias("Mws::Shared::Counter")
        .auto_update(true)
        .send()
        .await
        .unwrap();
    let activated_arn = activated.arn().unwrap().to_string();
    assert_eq!(activated_arn, format!("arn:aws:cloudformation:us-east-1:{ACCOUNT}:type/resource/Mws-Shared-Counter"));
    let listed = cfn
        .list_types()
        .visibility(Visibility::Private)
        .filters(TypeFilters::builder().category(Category::Activated).build())
        .send()
        .await
        .unwrap();
    assert_eq!(listed.type_summaries().len(), 1);
    assert_eq!(listed.type_summaries()[0].original_type_name(), Some("Mws::Test::Counter"));
    assert_eq!(listed.type_summaries()[0].is_activated(), Some(true));
    let alias_stack = "Resources:\n  C:\n    Type: Mws::Shared::Counter\n    Properties:\n      Name: shared\n";
    cfn.create_stack().stack_name("shared").template_body(alias_stack).send().await.unwrap();
    let s = settle(&cfn, "shared").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    let in_use = cfn.deactivate_type().arn(&activated_arn).send().await.unwrap_err();
    assert_eq!(code(&in_use), "CFNRegistryException");
    cfn.delete_stack().stack_name("shared").send().await.unwrap();
    for _ in 0..100 {
        let d = cfn.describe_stacks().stack_name(s.stack_id().unwrap()).send().await.unwrap();
        if d.stacks()[0].stack_status() == Some(&StackStatus::DeleteComplete) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    cfn.deactivate_type().arn(&activated_arn).send().await.unwrap();
    let missing = cfn.describe_type().arn(&activated_arn).send().await.unwrap_err();
    assert_eq!(code(&missing), "TypeNotFoundException");

    // Deregistering the last version removes the type from use.
    cfn.deregister_type().r#type(RegistryType::Resource).type_name("Mws::Test::Counter").send().await.unwrap();
    let unknown = cfn.validate_template().template_body(template).send().await.unwrap_err();
    assert!(unknown.message().unwrap().contains("Unrecognized resource types: [Mws::Test::Counter]"));
}

fn uuid_like() -> String {
    format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())
}

#[tokio::test]
async fn modules_expand_and_hooks_guard_provisioning() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let s3 = Mws::s3(&config);
    let sqs = aws_sdk_sqs::Client::new(&config);
    s3.create_bucket().bucket("packages").send().await.unwrap();

    // A module: a queue with a dead-letter queue.
    let module = upload(&s3, "module.zip", zip(&[("fragments/queues.json", FRAGMENT)])).await;
    register(&cfn, RegistryType::Module, "Mws::Test::Queues::MODULE", &module).await;
    let d =
        cfn.describe_type().r#type(RegistryType::Module).type_name("Mws::Test::Queues::MODULE").send().await.unwrap();
    assert!(d.schema().unwrap().contains("Retention"));
    let template = r#"
Resources:
  Work:
    Type: Mws::Test::Queues::MODULE
    Properties:
      Retention: "600"
Outputs:
  QueueUrl:
    Value: !Ref Work.Queue
  DlqArn:
    Value: !GetAtt Work.Dlq.Arn
"#;
    cfn.create_stack().stack_name("work").template_body(template).send().await.unwrap();
    let s = settle(&cfn, "work").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    let resources = cfn.describe_stack_resources().stack_name("work").send().await.unwrap();
    let mut ids: Vec<&str> = resources.stack_resources().iter().filter_map(|r| r.logical_resource_id()).collect();
    ids.sort();
    assert_eq!(ids, ["WorkDlq", "WorkQueue"]);
    let attrs = sqs
        .get_queue_attributes()
        .queue_url(output(&s, "QueueUrl"))
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::All)
        .send()
        .await
        .unwrap();
    let redrive = &attrs.attributes().unwrap()[&aws_sdk_sqs::types::QueueAttributeName::RedrivePolicy];
    assert!(redrive.contains(&output(&s, "DlqArn")), "{redrive}");
    let dlq_url =
        sqs.get_queue_url().queue_name(output(&s, "DlqArn").rsplit(':').next().unwrap()).send().await.unwrap();
    let dlq = sqs
        .get_queue_attributes()
        .queue_url(dlq_url.queue_url().unwrap())
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::MessageRetentionPeriod)
        .send()
        .await
        .unwrap();
    assert_eq!(dlq.attributes().unwrap()[&aws_sdk_sqs::types::QueueAttributeName::MessageRetentionPeriod], "600");
    let missing_param = cfn
        .validate_template()
        .template_body("Resources:\n  M:\n    Type: Mws::Test::Queues::MODULE\n    Properties:\n      Nope: x\n")
        .send()
        .await
        .unwrap_err();
    assert!(missing_param.message().unwrap().contains("has no parameter Nope"));

    // A hook that rejects queue names containing "public".
    let hook = upload(
        &s3,
        "hook.zip",
        zip(&[
            ("schema.json", HOOK_SCHEMA),
            (".rpdk-config", r#"{"typeName":"Mws::Test::QueueNames","runtime":"python3.12","entrypoint":"hook.hook"}"#),
            ("hook.py", HOOK_HANDLER),
        ]),
    )
    .await;
    let hook_version = register(&cfn, RegistryType::Hook, "Mws::Test::QueueNames", &hook).await;
    let hook_arn = hook_version.rsplit_once('/').unwrap().0.to_string();
    let bad_config = cfn
        .set_type_configuration()
        .type_arn(&hook_arn)
        .configuration(r#"{"CloudFormationConfiguration":{"HookConfiguration":{"HookInvocationStatus":"MAYBE"}}}"#)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_config), "ValidationError");
    cfn.set_type_configuration()
        .type_arn(&hook_arn)
        .configuration(
            r#"{"CloudFormationConfiguration":{"HookConfiguration":{"HookInvocationStatus":"ENABLED","FailureMode":"FAIL","TargetStacks":"ALL","Properties":{"Forbidden":"public"}}}}"#,
        )
        .send()
        .await
        .unwrap();
    let blocked = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n    Properties:\n      QueueName: public-orders\n";
    cfn.create_stack().stack_name("blocked").template_body(blocked).send().await.unwrap();
    let s = settle(&cfn, "blocked").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::RollbackComplete));
    let events = cfn.describe_stack_events().stack_name("blocked").send().await.unwrap();
    let hook_events: Vec<_> = events.stack_events().iter().filter(|e| e.hook_type().is_some()).collect();
    assert_eq!(hook_events.len(), 2, "{hook_events:?}");
    assert!(hook_events.iter().any(|e| e.hook_status() == Some(&HookStatus::HookCompleteFailed)
        && e.hook_status_reason() == Some("Queue names must not contain public")));
    let failure = events
        .stack_events()
        .iter()
        .find(|e| e.resource_status().is_some_and(|s| s.as_str() == "CREATE_FAILED"))
        .unwrap();
    assert!(failure
        .resource_status_reason()
        .unwrap()
        .contains("The following hook(s) failed: [Mws::Test::QueueNames]"));
    assert!(sqs.get_queue_url().queue_name("public-orders").send().await.is_err());

    let results = cfn
        .list_hook_results()
        .target_type(ListHookResultsTargetType::Stack)
        .target_id(s.stack_id().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(results.hook_results().len(), 1);
    let result_id = results.hook_results()[0].hook_result_id().unwrap().to_string();
    let result = cfn.get_hook_result().hook_result_id(&result_id).send().await.unwrap();
    assert_eq!(result.type_name(), Some("Mws::Test::QueueNames"));
    assert_eq!(result.status(), Some(&HookStatus::HookCompleteFailed));
    let target = result.target().unwrap();
    assert_eq!(target.target_type(), Some(&HookTargetType::Resource));
    assert_eq!(target.target_type_name(), Some("AWS::SQS::Queue"));
    assert_eq!(target.target_id(), Some("Q"));
    let by_type = cfn.list_hook_results().type_arn(&hook_arn).send().await.unwrap();
    assert!(!by_type.hook_results().is_empty());
    let invalid = cfn.get_hook_result().hook_result_id("nope").send().await.unwrap_err();
    assert_eq!(code(&invalid), "ValidationError");
    let none = cfn.get_hook_result().hook_result_id("00000000-0000-4000-8000-000000000000").send().await.unwrap_err();
    assert_eq!(code(&none), "HookResultNotFound");

    // Compliant names pass, and the hook's success is recorded.
    let fine = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n    Properties:\n      QueueName: private-orders\n";
    cfn.create_stack().stack_name("fine").template_body(fine).send().await.unwrap();
    let s = settle(&cfn, "fine").await;
    assert_eq!(s.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", s.stack_status_reason());
    let ok =
        cfn.list_hook_results().target_type(ListHookResultsTargetType::Stack).target_id("fine").send().await.unwrap();
    assert_eq!(ok.hook_results()[0].status(), Some(&HookStatus::HookCompleteSucceeded));
}
