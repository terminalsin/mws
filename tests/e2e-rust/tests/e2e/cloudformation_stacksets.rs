//! CloudFormation StackSets through the official Rust SDK: stack instances
//! deployed across Regions and accounts with the administration and
//! execution roles (self-managed) or Organizations (service-managed).

use std::time::Duration;

use aws_sdk_cloudformation::error::ProvideErrorMetadata;
use aws_sdk_cloudformation::types::{
    AutoDeployment, CallAs, DeploymentTargets, Parameter, PermissionModels, StackInstanceDetailedStatus,
    StackInstanceFilter, StackInstanceFilterName, StackInstanceStatus, StackResourceDriftStatus, StackSetDriftStatus,
    StackSetOperationPreferences, StackSetOperationResultStatus, StackSetOperationStatus, StackSetStatus,
};
use aws_sdk_cloudformation::Client;
use mws_e2e::{sts_config, Mws};

const ACCOUNT: &str = "123456789012";

const QUEUES: &str = r#"
AWSTemplateFormatVersion: "2010-09-09"
Description: A queue per account and Region
Parameters:
  Visibility:
    Type: Number
    Default: "30"
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: !Ref Visibility
Outputs:
  Url:
    Value: !Ref Queue
"#;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message<E: ProvideErrorMetadata>(e: &E) -> String {
    e.message().unwrap_or_default().to_string()
}

fn param(k: &str, v: &str) -> Parameter {
    Parameter::builder().parameter_key(k).parameter_value(v).build()
}

fn in_region(config: &aws_config::SdkConfig, region: &str) -> aws_config::SdkConfig {
    config.to_builder().region(aws_config::Region::new(region.to_string())).build()
}

/// Wait for a stack set operation to finish.
async fn finish(cfn: &Client, set: &str, op: &str, call_as: Option<CallAs>) -> StackSetOperationStatus {
    for _ in 0..600 {
        let d = cfn
            .describe_stack_set_operation()
            .stack_set_name(set)
            .operation_id(op)
            .set_call_as(call_as.clone())
            .send()
            .await
            .unwrap();
        let s = d.stack_set_operation().unwrap().status().unwrap().clone();
        if !matches!(
            s,
            StackSetOperationStatus::Running | StackSetOperationStatus::Queued | StackSetOperationStatus::Stopping
        ) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("operation {op} did not finish");
}

async fn results(cfn: &Client, set: &str, op: &str) -> Vec<(String, String, String, String)> {
    let r = cfn.list_stack_set_operation_results().stack_set_name(set).operation_id(op).send().await.unwrap();
    r.summaries()
        .iter()
        .map(|s| {
            (
                s.account().unwrap_or_default().to_string(),
                s.region().unwrap_or_default().to_string(),
                s.status().unwrap().as_str().to_string(),
                s.status_reason().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// The self-managed permission setup from the AWS documentation: the
/// administration role CloudFormation assumes, and the execution role it
/// assumes in turn in each target account.
async fn self_managed_roles(iam: &aws_sdk_iam::Client, admin_account: &str) {
    iam.create_role()
        .role_name("AWSCloudFormationStackSetAdministrationRole")
        .assume_role_policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudformation.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#,
        )
        .send()
        .await
        .unwrap();
    iam.put_role_policy()
        .role_name("AWSCloudFormationStackSetAdministrationRole")
        .policy_name("AssumeExecution")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:*:iam::*:role/AWSCloudFormationStackSetExecutionRole"}]}"#,
        )
        .send()
        .await
        .unwrap();
    iam.create_role()
        .role_name("AWSCloudFormationStackSetExecutionRole")
        .assume_role_policy_document(format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{admin_account}:role/AWSCloudFormationStackSetAdministrationRole"}},"Action":"sts:AssumeRole"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    iam.put_role_policy()
        .role_name("AWSCloudFormationStackSetExecutionRole")
        .policy_name("Admin")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
}

async fn visibility(sqs: &aws_sdk_sqs::Client, url: &str) -> String {
    let a = sqs
        .get_queue_attributes()
        .queue_url(url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout)
        .send()
        .await
        .unwrap();
    a.attributes().unwrap()[&aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout].clone()
}

async fn instance_queue(
    cfn: &Client,
    config: &aws_config::SdkConfig,
    set: &str,
    account: &str,
    region: &str,
) -> String {
    let i = cfn
        .describe_stack_instance()
        .stack_set_name(set)
        .stack_instance_account(account)
        .stack_instance_region(region)
        .send()
        .await
        .unwrap();
    let stack_id = i.stack_instance().unwrap().stack_id().unwrap().to_string();
    let regional = Client::new(&in_region(config, region));
    let s = regional.describe_stacks().stack_name(&stack_id).send().await.unwrap();
    s.stacks()[0].outputs().iter().find(|o| o.output_key() == Some("Url")).unwrap().output_value().unwrap().to_string()
}

#[tokio::test]
async fn self_managed_stack_sets_deploy_instances_across_regions() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let iam = aws_sdk_iam::Client::new(&config);

    // Without the administration role, instances cannot deploy.
    cfn.create_stack_set().stack_set_name("queues").template_body(QUEUES).send().await.unwrap();
    let dup = cfn.create_stack_set().stack_set_name("queues").template_body(QUEUES).send().await.unwrap_err();
    assert_eq!(code(&dup), "NameAlreadyExistsException");
    assert_eq!(message(&dup), "StackSet queues already exists");
    let op = cfn
        .create_stack_instances()
        .stack_set_name("queues")
        .accounts(ACCOUNT)
        .regions("us-east-1")
        .send()
        .await
        .unwrap()
        .operation_id()
        .unwrap()
        .to_string();
    assert_eq!(finish(&cfn, "queues", &op, None).await, StackSetOperationStatus::Failed);
    let r = results(&cfn, "queues", &op).await;
    assert!(r[0].3.contains("AWSCloudFormationStackSetAdministrationRole"), "{r:?}");
    let failed = cfn
        .describe_stack_instance()
        .stack_set_name("queues")
        .stack_instance_account(ACCOUNT)
        .stack_instance_region("us-east-1")
        .send()
        .await
        .unwrap();
    let failed = failed.stack_instance().unwrap();
    assert_eq!(failed.status(), Some(&StackInstanceStatus::Outdated));
    assert_eq!(failed.stack_instance_status().unwrap().detailed_status(), Some(&StackInstanceDetailedStatus::Failed));

    self_managed_roles(&iam, ACCOUNT).await;
    let d = cfn.describe_stack_set().stack_set_name("queues").send().await.unwrap();
    let set = d.stack_set().unwrap();
    assert_eq!(set.status(), Some(&StackSetStatus::Active));
    assert_eq!(set.permission_model(), Some(&PermissionModels::SelfManaged));
    assert_eq!(set.description(), Some("A queue per account and Region"));
    assert!(set
        .stack_set_arn()
        .unwrap()
        .starts_with(&format!("arn:aws:cloudformation:us-east-1:{ACCOUNT}:stackset/queues:")));
    assert_eq!(
        set.administration_role_arn(),
        Some(format!("arn:aws:iam::{ACCOUNT}:role/AWSCloudFormationStackSetAdministrationRole").as_str())
    );
    assert_eq!(set.execution_role_name(), Some("AWSCloudFormationStackSetExecutionRole"));
    let listed = cfn.list_stack_sets().status(StackSetStatus::Active).send().await.unwrap();
    assert_eq!(listed.summaries().len(), 1);

    // Two Regions, both at once; the failed us-east-1 instance is retried.
    let prefs = StackSetOperationPreferences::builder()
        .max_concurrent_count(2)
        .failure_tolerance_count(1)
        .region_order("eu-west-1")
        .build();
    cfn.create_stack_instances()
        .stack_set_name("queues")
        .accounts(ACCOUNT)
        .regions("us-east-1")
        .regions("eu-west-1")
        .operation_preferences(prefs)
        .operation_id("deploy-1")
        .send()
        .await
        .unwrap();
    assert_eq!(finish(&cfn, "queues", "deploy-1", None).await, StackSetOperationStatus::Succeeded);
    let r = results(&cfn, "queues", "deploy-1").await;
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|x| x.2 == "SUCCEEDED"), "{r:?}");
    let gate =
        cfn.list_stack_set_operation_results().stack_set_name("queues").operation_id("deploy-1").send().await.unwrap();
    assert_eq!(gate.summaries()[0].account_gate_result().unwrap().status().unwrap().as_str(), "SKIPPED");
    let again = cfn
        .create_stack_instances()
        .stack_set_name("queues")
        .accounts(ACCOUNT)
        .regions("us-east-1")
        .operation_id("deploy-1")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&again), "OperationIdAlreadyExistsException");

    let instances = cfn.list_stack_instances().stack_set_name("queues").send().await.unwrap();
    assert_eq!(instances.summaries().len(), 2);
    assert!(instances.summaries().iter().all(|i| i.status() == Some(&StackInstanceStatus::Current)));
    let eu_sqs = aws_sdk_sqs::Client::new(&in_region(&config, "eu-west-1"));
    let eu_url = instance_queue(&cfn, &config, "queues", ACCOUNT, "eu-west-1").await;
    assert_eq!(visibility(&eu_sqs, &eu_url).await, "30");

    // A parameter override for one Region only.
    let op = cfn
        .update_stack_instances()
        .stack_set_name("queues")
        .accounts(ACCOUNT)
        .regions("eu-west-1")
        .parameter_overrides(param("Visibility", "45"))
        .send()
        .await;
    // Overrides are allowed only for parameters the stack set specifies.
    assert_eq!(code(&op.unwrap_err()), "ValidationError");
    let op = cfn
        .update_stack_set()
        .stack_set_name("queues")
        .use_previous_template(true)
        .parameters(param("Visibility", "30"))
        .send()
        .await
        .unwrap();
    assert_eq!(finish(&cfn, "queues", op.operation_id().unwrap(), None).await, StackSetOperationStatus::Succeeded);
    let op = cfn
        .update_stack_instances()
        .stack_set_name("queues")
        .accounts(ACCOUNT)
        .regions("eu-west-1")
        .parameter_overrides(param("Visibility", "45"))
        .send()
        .await
        .unwrap();
    assert_eq!(finish(&cfn, "queues", op.operation_id().unwrap(), None).await, StackSetOperationStatus::Succeeded);
    assert_eq!(visibility(&eu_sqs, &eu_url).await, "45");
    let us_sqs = aws_sdk_sqs::Client::new(&config);
    let us_url = instance_queue(&cfn, &config, "queues", ACCOUNT, "us-east-1").await;
    assert_eq!(visibility(&us_sqs, &us_url).await, "30");

    // Drift: an out-of-band change shows up per instance and resource.
    us_sqs
        .set_queue_attributes()
        .queue_url(&us_url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout, "99")
        .send()
        .await
        .unwrap();
    let drift = cfn.detect_stack_set_drift().stack_set_name("queues").send().await.unwrap();
    let drift_op = drift.operation_id().unwrap().to_string();
    assert_eq!(finish(&cfn, "queues", &drift_op, None).await, StackSetOperationStatus::Succeeded);
    let d = cfn.describe_stack_set().stack_set_name("queues").send().await.unwrap();
    let details = d.stack_set().unwrap().stack_set_drift_detection_details().unwrap();
    assert_eq!(details.drift_status(), Some(&StackSetDriftStatus::Drifted));
    assert_eq!(details.drifted_stack_instances_count(), Some(1));
    assert_eq!(details.in_sync_stack_instances_count(), Some(1));
    let drifts = cfn
        .list_stack_instance_resource_drifts()
        .stack_set_name("queues")
        .operation_id(&drift_op)
        .stack_instance_account(ACCOUNT)
        .stack_instance_region("us-east-1")
        .stack_instance_resource_drift_statuses(StackResourceDriftStatus::Modified)
        .send()
        .await
        .unwrap();
    assert_eq!(drifts.summaries().len(), 1);
    let diff = &drifts.summaries()[0].property_differences()[0];
    assert_eq!(diff.property_path(), Some("/VisibilityTimeout"));
    assert_eq!(diff.actual_value(), Some("99"));
    let drifted = cfn
        .list_stack_instances()
        .stack_set_name("queues")
        .filters(StackInstanceFilter::builder().name(StackInstanceFilterName::DriftStatus).values("DRIFTED").build())
        .send()
        .await
        .unwrap();
    assert_eq!(drifted.summaries().len(), 1);
    assert_eq!(drifted.summaries()[0].region(), Some("us-east-1"));

    // Finished operations cannot be stopped.
    let stop =
        cfn.stop_stack_set_operation().stack_set_name("queues").operation_id(&drift_op).send().await.unwrap_err();
    assert_eq!(code(&stop), "InvalidOperationException");
    let ops = cfn.list_stack_set_operations().stack_set_name("queues").send().await.unwrap();
    assert_eq!(ops.summaries().len(), 5);
    assert_eq!(ops.summaries()[0].operation_id(), Some(drift_op.as_str()));
    assert_eq!(ops.summaries()[0].action().unwrap().as_str(), "DETECT_DRIFT");

    // An existing stack joins the stack set.
    let west = Client::new(&in_region(&config, "us-west-2"));
    let legacy = west.create_stack().stack_name("legacy").template_body(QUEUES).send().await.unwrap();
    let legacy_id = legacy.stack_id().unwrap().to_string();
    for _ in 0..100 {
        let s = west.describe_stacks().stack_name("legacy").send().await.unwrap();
        if !s.stacks()[0].stack_status().unwrap().as_str().ends_with("IN_PROGRESS") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let import = cfn.import_stacks_to_stack_set().stack_set_name("queues").stack_ids(&legacy_id).send().await.unwrap();
    assert_eq!(finish(&cfn, "queues", import.operation_id().unwrap(), None).await, StackSetOperationStatus::Succeeded);
    let i = cfn
        .describe_stack_instance()
        .stack_set_name("queues")
        .stack_instance_account(ACCOUNT)
        .stack_instance_region("us-west-2")
        .send()
        .await
        .unwrap();
    assert_eq!(i.stack_instance().unwrap().stack_id(), Some(legacy_id.as_str()));
    assert_eq!(i.stack_instance().unwrap().status(), Some(&StackInstanceStatus::Current));

    // A stack set with instances cannot be deleted.
    let not_empty = cfn.delete_stack_set().stack_set_name("queues").send().await.unwrap_err();
    assert_eq!(code(&not_empty), "StackSetNotEmptyException");
    // Retained stacks stay; the others are deleted with their queues.
    let op = cfn
        .delete_stack_instances()
        .stack_set_name("queues")
        .accounts(ACCOUNT)
        .regions("us-west-2")
        .retain_stacks(true)
        .send()
        .await
        .unwrap();
    assert_eq!(finish(&cfn, "queues", op.operation_id().unwrap(), None).await, StackSetOperationStatus::Succeeded);
    let s = west.describe_stacks().stack_name("legacy").send().await.unwrap();
    assert_eq!(s.stacks()[0].stack_status().unwrap().as_str(), "CREATE_COMPLETE");
    let op = cfn
        .delete_stack_instances()
        .stack_set_name("queues")
        .accounts(ACCOUNT)
        .regions("us-east-1")
        .regions("eu-west-1")
        .retain_stacks(false)
        .send()
        .await
        .unwrap();
    assert_eq!(finish(&cfn, "queues", op.operation_id().unwrap(), None).await, StackSetOperationStatus::Succeeded);
    let gone = eu_sqs.get_queue_attributes().queue_url(&eu_url).send().await.unwrap_err();
    assert!(gone.to_string().contains("NonExistentQueue") || format!("{gone:?}").contains("NonExistentQueue"));
    let empty = cfn.list_stack_instances().stack_set_name("queues").send().await.unwrap();
    assert!(empty.summaries().is_empty());
    let r = cfn
        .list_stack_set_operation_results()
        .stack_set_name("queues")
        .operation_id(op.operation_id().unwrap())
        .send()
        .await
        .unwrap();
    assert!(r.summaries().iter().all(|s| s.status() == Some(&StackSetOperationResultStatus::Succeeded)));

    cfn.delete_stack_set().stack_set_name("queues").send().await.unwrap();
    let missing = cfn.describe_stack_set().stack_set_name("queues").send().await.unwrap_err();
    assert_eq!(code(&missing), "StackSetNotFoundException");
    assert_eq!(message(&missing), "StackSet queues not found");
    let deleted = cfn.list_stack_sets().status(StackSetStatus::Deleted).send().await.unwrap();
    assert_eq!(deleted.summaries().len(), 1);
}

#[tokio::test]
async fn service_managed_stack_sets_follow_organizational_units() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let orgs = aws_sdk_organizations::Client::new(&config);
    orgs.create_organization().send().await.unwrap();
    let root = orgs.list_roots().send().await.unwrap().roots()[0].id().unwrap().to_string();
    let ou = orgs.create_organizational_unit().parent_id(&root).name("workloads").send().await.unwrap();
    let ou = ou.organizational_unit().unwrap().id().unwrap().to_string();
    let create_account = |name: &'static str| {
        let orgs = orgs.clone();
        async move {
            let out =
                orgs.create_account().email(format!("{name}@example.com")).account_name(name).send().await.unwrap();
            let id = out.create_account_status().unwrap().id().unwrap().to_string();
            let s = orgs.describe_create_account_status().create_account_request_id(id).send().await.unwrap();
            s.create_account_status().unwrap().account_id().unwrap().to_string()
        }
    };
    let first = create_account("first").await;
    orgs.move_account().account_id(&first).source_parent_id(&root).destination_parent_id(&ou).send().await.unwrap();

    // Service-managed stack sets need trusted access first.
    let auto = AutoDeployment::builder().enabled(true).retain_stacks_on_account_removal(false).build();
    let denied = cfn
        .create_stack_set()
        .stack_set_name("baseline")
        .template_body(QUEUES)
        .permission_model(PermissionModels::ServiceManaged)
        .auto_deployment(auto.clone())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "ValidationError");
    let status = cfn.describe_organizations_access().send().await.unwrap();
    assert_eq!(status.status().unwrap().as_str(), "DISABLED");
    cfn.activate_organizations_access().send().await.unwrap();
    let status = cfn.describe_organizations_access().send().await.unwrap();
    assert_eq!(status.status().unwrap().as_str(), "ENABLED");
    let principals = orgs.list_aws_service_access_for_organization().send().await.unwrap();
    assert!(principals
        .enabled_service_principals()
        .iter()
        .any(|p| p.service_principal() == Some("member.org.stacksets.cloudformation.amazonaws.com")));

    cfn.create_stack_set()
        .stack_set_name("baseline")
        .template_body(QUEUES)
        .permission_model(PermissionModels::ServiceManaged)
        .auto_deployment(auto)
        .send()
        .await
        .unwrap();
    let op = cfn
        .create_stack_instances()
        .stack_set_name("baseline")
        .deployment_targets(DeploymentTargets::builder().organizational_unit_ids(&ou).build())
        .regions("us-east-1")
        .send()
        .await
        .unwrap();
    assert_eq!(finish(&cfn, "baseline", op.operation_id().unwrap(), None).await, StackSetOperationStatus::Succeeded);
    let instances = cfn.list_stack_instances().stack_set_name("baseline").send().await.unwrap();
    assert_eq!(instances.summaries().len(), 1);
    assert_eq!(instances.summaries()[0].account(), Some(first.as_str()));
    assert_eq!(instances.summaries()[0].organizational_unit_id(), Some(ou.as_str()));
    let targets = cfn.list_stack_set_auto_deployment_targets().stack_set_name("baseline").send().await.unwrap();
    assert_eq!(targets.summaries()[0].organizational_unit_id(), Some(ou.as_str()));
    assert_eq!(targets.summaries()[0].regions(), ["us-east-1"]);

    // The queue is real, in the member account.
    let (_, admin) = mws_e2e::user_with_policy(
        &mws,
        "admin",
        Some(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#),
    )
    .await;
    let sts = aws_sdk_sts::Client::new(&admin);
    let creds = sts
        .assume_role()
        .role_arn(format!("arn:aws:iam::{first}:role/OrganizationAccountAccessRole"))
        .role_session_name("check")
        .send()
        .await
        .unwrap();
    let member = sts_config(&mws, creds.credentials().unwrap()).await;
    let queues = aws_sdk_sqs::Client::new(&member).list_queues().send().await.unwrap();
    assert_eq!(queues.queue_urls().len(), 1, "{queues:?}");
    assert!(queues.queue_urls()[0].contains(&first));
    let member_roles = aws_sdk_iam::Client::new(&member).list_roles().send().await.unwrap();
    assert!(member_roles.roles().iter().any(|r| r.role_name().starts_with("stacksets-exec-")));

    // Auto-deployment: a new account in the OU gets an instance.
    let second = create_account("second").await;
    orgs.move_account().account_id(&second).source_parent_id(&root).destination_parent_id(&ou).send().await.unwrap();
    let mut deployed = false;
    for _ in 0..100 {
        let i = cfn.list_stack_instances().stack_set_name("baseline").send().await.unwrap();
        if i.summaries().len() == 2 && i.summaries().iter().all(|s| s.status() == Some(&StackInstanceStatus::Current)) {
            deployed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(deployed, "the second account did not get a stack instance");

    // A delegated administrator manages the stack set from a member account.
    orgs.register_delegated_administrator()
        .account_id(&first)
        .service_principal("member.org.stacksets.cloudformation.amazonaws.com")
        .send()
        .await
        .unwrap();
    let delegated = Client::new(&member);
    let as_self = delegated.list_stack_sets().send().await.unwrap();
    assert!(as_self.summaries().is_empty());
    let as_admin = delegated.list_stack_sets().call_as(CallAs::DelegatedAdmin).send().await.unwrap();
    assert_eq!(as_admin.summaries().len(), 1);
    assert_eq!(as_admin.summaries()[0].stack_set_name(), Some("baseline"));

    // Leaving the OU removes the instance and its stack.
    orgs.move_account().account_id(&second).source_parent_id(&ou).destination_parent_id(&root).send().await.unwrap();
    let mut removed = false;
    for _ in 0..100 {
        let i = cfn.list_stack_instances().stack_set_name("baseline").send().await.unwrap();
        if i.summaries().len() == 1 {
            removed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(removed, "the second account kept its stack instance");

    let op = cfn
        .delete_stack_instances()
        .stack_set_name("baseline")
        .call_as(CallAs::SelfValue)
        .deployment_targets(DeploymentTargets::builder().organizational_unit_ids(&ou).build())
        .regions("us-east-1")
        .retain_stacks(false)
        .send()
        .await
        .unwrap();
    assert_eq!(finish(&cfn, "baseline", op.operation_id().unwrap(), None).await, StackSetOperationStatus::Succeeded);
    let queues = aws_sdk_sqs::Client::new(&member).list_queues().send().await.unwrap();
    assert!(queues.queue_urls().is_empty());
    cfn.delete_stack_set().stack_set_name("baseline").send().await.unwrap();
    orgs.deregister_delegated_administrator()
        .account_id(&first)
        .service_principal("member.org.stacksets.cloudformation.amazonaws.com")
        .send()
        .await
        .unwrap();
    cfn.deactivate_organizations_access().send().await.unwrap();
    let status = cfn.describe_organizations_access().send().await.unwrap();
    assert_eq!(status.status().unwrap().as_str(), "DISABLED");
}
