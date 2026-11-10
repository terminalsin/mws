//! The CloudFormation IaC generator through the official Rust SDK: scan
//! existing resources, generate a template from them, and import them
//! into a stack with an IMPORT change set.

use std::collections::HashMap;
use std::time::Duration;

use aws_sdk_cloudformation::error::ProvideErrorMetadata;
use aws_sdk_cloudformation::types::{
    ChangeSetStatus, ChangeSetType, GeneratedTemplateStatus, ResourceDefinition, ResourceScanStatus, ResourceToImport,
    ScanFilter, ScannedResourceIdentifier, StackStatus, TemplateConfiguration, TemplateFormat,
};
use aws_sdk_cloudformation::Client;
use mws_e2e::Mws;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn ident(k: &str, v: &str) -> HashMap<String, String> {
    [(k.to_string(), v.to_string())].into_iter().collect()
}

/// Describe a change set once AWS has finished creating it (creation is
/// asynchronous: `CREATE_PENDING`, `CREATE_IN_PROGRESS`).
async fn created_change_set(
    cfn: &Client,
    id: &str,
) -> aws_sdk_cloudformation::operation::describe_change_set::DescribeChangeSetOutput {
    for _ in 0..200 {
        let d = cfn.describe_change_set().change_set_name(id).send().await.unwrap();
        let pending = d.status().is_some_and(|s| matches!(s.as_str(), "CREATE_PENDING" | "CREATE_IN_PROGRESS"));
        if !pending {
            return d;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("change set {id} was not created");
}

async fn scan(cfn: &Client, filter: Option<ScanFilter>) -> String {
    let id = cfn.start_resource_scan().set_scan_filters(filter.map(|f| vec![f])).send().await.unwrap();
    let id = id.resource_scan_id().unwrap().to_string();
    for _ in 0..200 {
        let d = cfn.describe_resource_scan().resource_scan_id(&id).send().await.unwrap();
        if d.status() != Some(&ResourceScanStatus::InProgress) {
            assert_eq!(d.status(), Some(&ResourceScanStatus::Complete), "{:?}", d.status_reason());
            return id;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("scan did not finish");
}

async fn generated(
    cfn: &Client,
    name: &str,
) -> aws_sdk_cloudformation::operation::describe_generated_template::DescribeGeneratedTemplateOutput {
    for _ in 0..200 {
        let d = cfn.describe_generated_template().generated_template_name(name).send().await.unwrap();
        if matches!(d.status(), Some(GeneratedTemplateStatus::Complete) | Some(GeneratedTemplateStatus::Failed)) {
            return d;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("template {name} was not generated");
}

#[tokio::test]
async fn scans_generate_templates_that_import_existing_resources() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let sqs = aws_sdk_sqs::Client::new(&config);
    let s3 = Mws::s3(&config);

    // Resources made outside CloudFormation.
    s3.create_bucket().bucket("legacy-assets").send().await.unwrap();
    let dlq = sqs.create_queue().queue_name("legacy-dlq").send().await.unwrap();
    let dlq_arn = sqs
        .get_queue_attributes()
        .queue_url(dlq.queue_url().unwrap())
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .unwrap()[&aws_sdk_sqs::types::QueueAttributeName::QueueArn]
        .clone();
    let queue = sqs
        .create_queue()
        .queue_name("legacy-orders")
        .attributes(aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout, "45")
        .attributes(
            aws_sdk_sqs::types::QueueAttributeName::RedrivePolicy,
            format!(r#"{{"deadLetterTargetArn":"{dlq_arn}","maxReceiveCount":"5"}}"#),
        )
        .tags("team", "orders")
        .send()
        .await
        .unwrap();
    let queue_url = queue.queue_url().unwrap().to_string();

    let missing = cfn
        .describe_resource_scan()
        .resource_scan_id("arn:aws:cloudformation:us-east-1:123456789012:resourceScan/nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&missing), "ResourceScanNotFound");

    // A full scan finds them.
    let full = scan(&cfn, None).await;
    let d = cfn.describe_resource_scan().resource_scan_id(&full).send().await.unwrap();
    assert!(d.resource_types().contains(&"AWS::SQS::Queue".to_string()));
    assert!(d.resources_scanned().unwrap() >= 3);
    let queues = cfn
        .list_resource_scan_resources()
        .resource_scan_id(&full)
        .resource_type_prefix("AWS::SQS::")
        .send()
        .await
        .unwrap();
    assert_eq!(queues.resources().len(), 2);
    assert!(queues.resources().iter().all(|r| r.managed_by_stack() == Some(false)));
    let tagged = cfn
        .list_resource_scan_resources()
        .resource_scan_id(&full)
        .tag_key("team")
        .tag_value("orders")
        .send()
        .await
        .unwrap();
    assert_eq!(tagged.resources().len(), 1);
    assert_eq!(tagged.resources()[0].resource_identifier().unwrap()["QueueUrl"], queue_url);
    let related = cfn
        .list_resource_scan_related_resources()
        .resource_scan_id(&full)
        .resources(
            ScannedResourceIdentifier::builder()
                .resource_type("AWS::SQS::Queue")
                .set_resource_identifier(Some(ident("QueueUrl", &queue_url)))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(related.related_resources().len(), 1, "{related:?}");
    assert_eq!(related.related_resources()[0].resource_identifier().unwrap()["QueueUrl"], dlq.queue_url().unwrap());

    // A partial scan of one service.
    let partial = scan(&cfn, Some(ScanFilter::builder().types("AWS::S3::*").build())).await;
    let scans = cfn.list_resource_scans().send().await.unwrap();
    assert_eq!(scans.resource_scan_summaries().len(), 2);
    assert_eq!(scans.resource_scan_summaries()[0].resource_scan_id(), Some(partial.as_str()));
    assert_eq!(scans.resource_scan_summaries()[0].scan_type().unwrap().as_str(), "PARTIAL");
    let buckets = cfn.list_resource_scan_resources().resource_scan_id(&partial).send().await.unwrap();
    assert_eq!(buckets.resources().len(), 1);
    assert_eq!(buckets.resources()[0].resource_type(), Some("AWS::S3::Bucket"));

    // Generate a template from the scanned resources.
    let def = |ty: &str, logical: &str, k: &str, v: &str| {
        ResourceDefinition::builder()
            .resource_type(ty)
            .logical_resource_id(logical)
            .set_resource_identifier(Some(ident(k, v)))
            .build()
    };
    let created = cfn
        .create_generated_template()
        .generated_template_name("legacy")
        .resources(def("AWS::SQS::Queue", "Orders", "QueueUrl", &queue_url))
        .resources(def("AWS::SQS::Queue", "DeadLetters", "QueueUrl", dlq.queue_url().unwrap()))
        .template_configuration(TemplateConfiguration::builder().deletion_policy("RETAIN".into()).build())
        .send()
        .await
        .unwrap();
    let template_id = created.generated_template_id().unwrap().to_string();
    assert!(template_id.starts_with("arn:aws:cloudformation:us-east-1:123456789012:generatedtemplate/"));
    let dup = cfn.create_generated_template().generated_template_name("legacy").send().await.unwrap_err();
    assert_eq!(code(&dup), "AlreadyExistsException");
    let d = generated(&cfn, "legacy").await;
    assert_eq!(d.status(), Some(&GeneratedTemplateStatus::Complete), "{:?}", d.status_reason());
    assert_eq!(d.progress().unwrap().resources_succeeded(), Some(2));
    let body = cfn.get_generated_template().generated_template_name("legacy").send().await.unwrap();
    let t: serde_json::Value = serde_json::from_str(body.template_body().unwrap()).unwrap();
    assert_eq!(t["Resources"]["Orders"]["DeletionPolicy"], "Retain");
    assert_eq!(t["Resources"]["Orders"]["Properties"]["QueueName"], "legacy-orders");
    assert_eq!(t["Resources"]["Orders"]["Properties"]["VisibilityTimeout"], 45);
    // The dead-letter queue is referred to, not hard-coded.
    assert_eq!(
        t["Resources"]["Orders"]["Properties"]["RedrivePolicy"]["deadLetterTargetArn"],
        serde_json::json!({"Fn::GetAtt": ["DeadLetters", "Arn"]})
    );
    let yaml = cfn
        .get_generated_template()
        .generated_template_name(&template_id)
        .format(TemplateFormat::Yaml)
        .send()
        .await
        .unwrap();
    assert!(yaml.template_body().unwrap().contains("legacy-orders"));

    // Add the bucket, rename the template.
    cfn.update_generated_template()
        .generated_template_name("legacy")
        .new_generated_template_name("legacy-app")
        .add_resources(def("AWS::S3::Bucket", "Assets", "BucketName", "legacy-assets"))
        .send()
        .await
        .unwrap();
    let d = generated(&cfn, "legacy-app").await;
    assert_eq!(d.resources().len(), 3);
    let listed = cfn.list_generated_templates().send().await.unwrap();
    assert_eq!(listed.summaries().len(), 1);
    assert_eq!(listed.summaries()[0].number_of_resources(), Some(3));
    let gone = cfn.describe_generated_template().generated_template_name("legacy").send().await.unwrap_err();
    assert_eq!(code(&gone), "GeneratedTemplateNotFound");
    let body = cfn.get_generated_template().generated_template_name("legacy-app").send().await.unwrap();
    let body = body.template_body().unwrap().to_string();

    // Import everything into a new stack.
    let import = |logical: &str, ty: &str, k: &str, v: &str| {
        ResourceToImport::builder()
            .resource_type(ty)
            .logical_resource_id(logical)
            .set_resource_identifier(Some(ident(k, v)))
            .build()
    };
    let bad = cfn
        .create_change_set()
        .stack_name("legacy")
        .change_set_name("missing")
        .change_set_type(ChangeSetType::Import)
        .template_body(r#"{"Resources":{"Q":{"Type":"AWS::SQS::Queue","DeletionPolicy":"Retain","Properties":{"QueueName":"nope"}}}}"#)
        .resources_to_import(import("Q", "AWS::SQS::Queue", "QueueUrl", "http://nope"))
        .send()
        .await
        .unwrap();
    let cs = created_change_set(&cfn, bad.id().unwrap()).await;
    assert_eq!(cs.status(), Some(&ChangeSetStatus::Failed));
    assert!(cs.status_reason().unwrap().contains("[Q]"), "{:?}", cs.status_reason());
    let no_policy = cfn
        .create_change_set()
        .stack_name("legacy")
        .change_set_name("no-policy")
        .change_set_type(ChangeSetType::Import)
        .template_body(r#"{"Resources":{"Q":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"legacy-orders"}}}}"#)
        .resources_to_import(import("Q", "AWS::SQS::Queue", "QueueUrl", &queue_url))
        .send()
        .await
        .unwrap_err();
    assert!(no_policy.message().unwrap().contains("must have DeletionPolicy"));

    let cs = cfn
        .create_change_set()
        .stack_name("legacy")
        .change_set_name("adopt")
        .change_set_type(ChangeSetType::Import)
        .template_body(&body)
        .resources_to_import(import("Orders", "AWS::SQS::Queue", "QueueUrl", &queue_url))
        .resources_to_import(import("DeadLetters", "AWS::SQS::Queue", "QueueUrl", dlq.queue_url().unwrap()))
        .resources_to_import(import("Assets", "AWS::S3::Bucket", "BucketName", "legacy-assets"))
        .send()
        .await
        .unwrap();
    let d = created_change_set(&cfn, cs.id().unwrap()).await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::CreateComplete), "{:?}", d.status_reason());
    assert_eq!(d.changes().len(), 3);
    assert!(d.changes().iter().all(|c| c.resource_change().unwrap().action().unwrap().as_str() == "Import"));
    cfn.execute_change_set().change_set_name(cs.id().unwrap()).send().await.unwrap();
    let mut status = None;
    for _ in 0..200 {
        let s = cfn.describe_stacks().stack_name("legacy").send().await.unwrap();
        let st = s.stacks()[0].stack_status().cloned();
        if !st.as_ref().is_some_and(|x| x.as_str().ends_with("_IN_PROGRESS")) {
            status = st;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status, Some(StackStatus::ImportComplete));
    let r = cfn.describe_stack_resource().stack_name("legacy").logical_resource_id("Orders").send().await.unwrap();
    let r = r.stack_resource_detail().unwrap();
    assert_eq!(r.physical_resource_id(), Some(queue_url.as_str()));
    assert_eq!(r.resource_status().unwrap().as_str(), "IMPORT_COMPLETE");

    // A new scan sees them as managed, and importing them again fails.
    let after = scan(&cfn, Some(ScanFilter::builder().types("AWS::SQS::Queue").build())).await;
    let managed = cfn.list_resource_scan_resources().resource_scan_id(&after).send().await.unwrap();
    assert!(managed.resources().iter().all(|r| r.managed_by_stack() == Some(true)));
    let twice = cfn
        .create_change_set()
        .stack_name("other")
        .change_set_name("steal")
        .change_set_type(ChangeSetType::Import)
        .template_body(r#"{"Resources":{"Q":{"Type":"AWS::SQS::Queue","DeletionPolicy":"Retain","Properties":{"QueueName":"legacy-orders"}}}}"#)
        .resources_to_import(import("Q", "AWS::SQS::Queue", "QueueUrl", &queue_url))
        .send()
        .await
        .unwrap();
    let d = created_change_set(&cfn, twice.id().unwrap()).await;
    assert_eq!(d.status(), Some(&ChangeSetStatus::Failed));
    assert!(d.status_reason().unwrap().contains("already exists in stack legacy"));

    // Deleting the stack keeps the retained resources.
    cfn.delete_stack().stack_name("legacy").send().await.unwrap();
    for _ in 0..100 {
        let s = cfn.list_stacks().send().await.unwrap();
        if s.stack_summaries()
            .iter()
            .any(|x| x.stack_name() == Some("legacy") && x.stack_status() == Some(&StackStatus::DeleteComplete))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(sqs.get_queue_url().queue_name("legacy-orders").send().await.is_ok());

    cfn.delete_generated_template().generated_template_name("legacy-app").send().await.unwrap();
    assert!(cfn.list_generated_templates().send().await.unwrap().summaries().is_empty());
}

async fn settled(cfn: &Client, stack: &str) -> StackStatus {
    for _ in 0..200 {
        let s = cfn.describe_stacks().stack_name(stack).send().await.unwrap();
        let st = s.stacks()[0].stack_status().cloned().unwrap();
        if !st.as_str().ends_with("_IN_PROGRESS") {
            return st;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("stack {stack} did not settle");
}

async fn refactor_done(
    cfn: &Client,
    id: &str,
) -> aws_sdk_cloudformation::operation::describe_stack_refactor::DescribeStackRefactorOutput {
    for _ in 0..200 {
        let d = cfn.describe_stack_refactor().stack_refactor_id(id).send().await.unwrap();
        let busy = d.status().is_some_and(|s| s.as_str().ends_with("_IN_PROGRESS"))
            || d.execution_status().is_some_and(|s| s.as_str().ends_with("_IN_PROGRESS"));
        if !busy {
            return d;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("refactor {id} did not finish");
}

#[tokio::test]
async fn refactors_move_resources_between_stacks_and_events_group_by_operation() {
    use aws_sdk_cloudformation::types::{EventFilter, ResourceLocation, ResourceMapping, StackDefinition};
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let sqs = aws_sdk_sqs::Client::new(&config);

    let app = r#"{"Resources":{
        "Jobs":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"refactor-jobs"}},
        "Alerts":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":"refactor-alerts"}}},
      "Outputs":{"JobsUrl":{"Value":{"Ref":"Jobs"}}}}"#;
    let created = cfn.create_stack().stack_name("app").template_body(app).send().await.unwrap();
    assert_eq!(settled(&cfn, "app").await, StackStatus::CreateComplete);
    let queue_url =
        sqs.get_queue_url().queue_name("refactor-jobs").send().await.unwrap().queue_url().unwrap().to_string();

    // DescribeEvents groups the stack's events by operation.
    let events = cfn.describe_events().stack_name("app").send().await.unwrap();
    let events = events.operation_events();
    assert!(events.len() >= 6, "{events:?}");
    assert!(events.iter().all(|e| e.operation_id() == created.operation_id()));
    assert!(events.iter().all(|e| e.operation_type().unwrap().as_str() == "CREATE_STACK"));
    assert!(events.iter().all(|e| e.operation_status().unwrap().as_str() == "SUCCEEDED"));
    let stack_events: Vec<_> = events.iter().filter(|e| e.event_type().unwrap().as_str() == "STACK_EVENT").collect();
    assert_eq!(stack_events.len(), 2);
    assert!(stack_events[0].end_time().is_some() && stack_events[0].start_time().is_some());
    let by_op = cfn.describe_events().operation_id(created.operation_id().unwrap()).send().await.unwrap();
    assert_eq!(by_op.operation_events().len(), events.len());
    let none_failed = cfn
        .describe_events()
        .stack_name("app")
        .filters(EventFilter::builder().failed_events(true).build())
        .send()
        .await
        .unwrap();
    assert!(none_failed.operation_events().is_empty());
    let neither = cfn.describe_events().send().await.unwrap_err();
    assert_eq!(code(&neither), "ValidationError");

    // A failed update shows up as a provisioning error under its own operation.
    let broken = r#"{"Resources":{
        "Jobs":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"refactor-jobs"}},
        "Alerts":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":"refactor-alerts"}},
        "Bad":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"bad","VisibilityTimeout":999999}}},
      "Outputs":{"JobsUrl":{"Value":{"Ref":"Jobs"}}}}"#;
    let cs =
        cfn.create_change_set().stack_name("app").change_set_name("break").template_body(broken).send().await.unwrap();
    for _ in 0..100 {
        let d = cfn.describe_change_set().change_set_name(cs.id().unwrap()).send().await.unwrap();
        if d.status() == Some(&ChangeSetStatus::CreateComplete) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let pending = cfn.describe_events().change_set_name(cs.id().unwrap()).send().await.unwrap();
    assert_eq!(pending.operation_events().len(), 1);
    assert_eq!(pending.operation_events()[0].operation_type().unwrap().as_str(), "CREATE_CHANGESET");
    assert_eq!(pending.operation_events()[0].operation_status().unwrap().as_str(), "SUCCEEDED");
    cfn.execute_change_set().change_set_name(cs.id().unwrap()).send().await.unwrap();
    assert_eq!(settled(&cfn, "app").await, StackStatus::UpdateRollbackComplete);
    let executed = cfn.describe_events().change_set_name(cs.id().unwrap()).send().await.unwrap();
    let update: Vec<_> =
        executed.operation_events().iter().filter(|e| e.operation_type().unwrap().as_str() == "UPDATE_STACK").collect();
    assert!(!update.is_empty());
    assert!(update.iter().all(|e| e.operation_status().unwrap().as_str() == "FAILED"));
    let failed = cfn
        .describe_events()
        .stack_name("app")
        .operation_id(update[0].operation_id().unwrap())
        .filters(EventFilter::builder().failed_events(true).build())
        .send()
        .await
        .unwrap();
    assert!(!failed.operation_events().is_empty());
    assert!(failed
        .operation_events()
        .iter()
        .any(|e| e.event_type().unwrap().as_str() == "PROVISIONING_ERROR" && e.logical_resource_id() == Some("Bad")));

    // A refactor can't delete or add resources.
    let def = |name: &str, body: &str| StackDefinition::builder().stack_name(name).template_body(body).build();
    let lossy = cfn
        .create_stack_refactor()
        .stack_definitions(def(
            "app",
            r#"{"Resources":{"Alerts":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":"refactor-alerts"}}}}"#,
        ))
        .send()
        .await
        .unwrap();
    let d = refactor_done(&cfn, lossy.stack_refactor_id().unwrap()).await;
    assert_eq!(d.status().unwrap().as_str(), "CREATE_FAILED");
    assert_eq!(d.execution_status().unwrap().as_str(), "UNAVAILABLE");
    assert!(d.status_reason().unwrap().contains("app/Jobs"), "{:?}", d.status_reason());
    let no_stack = cfn
        .create_stack_refactor()
        .stack_definitions(def(
            "app",
            r#"{"Resources":{"Alerts":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":"refactor-alerts"}}}}"#,
        ))
        .stack_definitions(def(
            "workers",
            r#"{"Resources":{"Jobs":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"refactor-jobs"}}}}"#,
        ))
        .send()
        .await
        .unwrap();
    let d = refactor_done(&cfn, no_stack.stack_refactor_id().unwrap()).await;
    assert_eq!(d.status().unwrap().as_str(), "CREATE_FAILED");
    assert!(d.status_reason().unwrap().contains("EnableStackCreation"));

    // Move Jobs into a new stack (detected) and rename Alerts (mapped).
    let refactor = cfn
        .create_stack_refactor()
        .description("split workers out")
        .enable_stack_creation(true)
        .stack_definitions(def("app", r#"{"Resources":{"Notifications":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":"refactor-alerts"}}},"Outputs":{"Topic":{"Value":{"Ref":"Notifications"}}}}"#))
        .stack_definitions(def("workers", r#"{"Resources":{"Jobs":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"refactor-jobs"}}},"Outputs":{"JobsUrl":{"Value":{"Ref":"Jobs"},"Export":{"Name":"jobs-url"}}}}"#))
        .resource_mappings(
            ResourceMapping::builder()
                .source(ResourceLocation::builder().stack_name("app").logical_resource_id("Alerts").build())
                .destination(ResourceLocation::builder().stack_name("app").logical_resource_id("Notifications").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let id = refactor.stack_refactor_id().unwrap().to_string();
    let d = refactor_done(&cfn, &id).await;
    assert_eq!(d.status().unwrap().as_str(), "CREATE_COMPLETE", "{:?}", d.status_reason());
    assert_eq!(d.execution_status().unwrap().as_str(), "AVAILABLE");
    assert_eq!(d.stack_ids().len(), 2);
    let actions = cfn.list_stack_refactor_actions().stack_refactor_id(&id).send().await.unwrap();
    let actions = actions.stack_refactor_actions();
    assert_eq!(actions.len(), 3, "{actions:?}");
    assert!(actions
        .iter()
        .any(|a| a.action().unwrap().as_str() == "CREATE" && a.entity().unwrap().as_str() == "STACK"));
    let jobs = actions
        .iter()
        .find(|a| a.resource_mapping().is_some_and(|m| m.source().unwrap().logical_resource_id() == Some("Jobs")))
        .unwrap();
    assert_eq!(jobs.detection().unwrap().as_str(), "AUTO");
    assert_eq!(jobs.physical_resource_id(), Some(queue_url.as_str()));
    assert_eq!(jobs.resource_mapping().unwrap().destination().unwrap().stack_name(), Some("workers"));
    let alerts = actions
        .iter()
        .find(|a| a.resource_mapping().is_some_and(|m| m.source().unwrap().logical_resource_id() == Some("Alerts")))
        .unwrap();
    assert_eq!(alerts.detection().unwrap().as_str(), "MANUAL");

    let listed = cfn.list_stack_refactors().send().await.unwrap();
    assert_eq!(listed.stack_refactor_summaries().len(), 3);
    let available = cfn
        .list_stack_refactors()
        .execution_status_filter(aws_sdk_cloudformation::types::StackRefactorExecutionStatus::Available)
        .send()
        .await
        .unwrap();
    assert_eq!(available.stack_refactor_summaries().len(), 1);
    assert_eq!(available.stack_refactor_summaries()[0].description(), Some("split workers out"));
    let cant =
        cfn.execute_stack_refactor().stack_refactor_id(lossy.stack_refactor_id().unwrap()).send().await.unwrap_err();
    assert_eq!(code(&cant), "ValidationError");
    let missing = cfn
        .describe_stack_refactor()
        .stack_refactor_id(
            "arn:aws:cloudformation:us-east-1:123456789012:stackRefactor/00000000-0000-0000-0000-000000000000",
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&missing), "StackRefactorNotFoundException");

    cfn.execute_stack_refactor().stack_refactor_id(&id).send().await.unwrap();
    let d = refactor_done(&cfn, &id).await;
    assert_eq!(d.execution_status().unwrap().as_str(), "EXECUTE_COMPLETE", "{:?}", d.execution_status_reason());
    assert_eq!(settled(&cfn, "app").await, StackStatus::UpdateComplete);
    assert_eq!(settled(&cfn, "workers").await, StackStatus::CreateComplete);
    let workers = cfn.describe_stack_resource().stack_name("workers").logical_resource_id("Jobs").send().await.unwrap();
    assert_eq!(workers.stack_resource_detail().unwrap().physical_resource_id(), Some(queue_url.as_str()));
    let app_resources = cfn.describe_stack_resources().stack_name("app").send().await.unwrap();
    let names: Vec<_> = app_resources.stack_resources().iter().map(|r| r.logical_resource_id().unwrap()).collect();
    assert_eq!(names, ["Notifications"]);
    let exports = cfn.list_exports().send().await.unwrap();
    assert!(exports.exports().iter().any(|e| e.name() == Some("jobs-url") && e.value() == Some(queue_url.as_str())));
    // The resources themselves were never touched.
    assert!(sqs.get_queue_url().queue_name("refactor-jobs").send().await.is_ok());

    // Executed refactors are done; an update since then makes others obsolete.
    let again = cfn.execute_stack_refactor().stack_refactor_id(&id).send().await.unwrap_err();
    assert_eq!(code(&again), "ValidationError");
    let stale = cfn
        .create_stack_refactor()
        .stack_definitions(def("workers", r#"{"Resources":{"Work":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"refactor-jobs"}}},"Outputs":{"JobsUrl":{"Value":{"Ref":"Work"},"Export":{"Name":"jobs-url"}}}}"#))
        .resource_mappings(
            ResourceMapping::builder()
                .source(ResourceLocation::builder().stack_name("workers").logical_resource_id("Jobs").build())
                .destination(ResourceLocation::builder().stack_name("workers").logical_resource_id("Work").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        refactor_done(&cfn, stale.stack_refactor_id().unwrap()).await.execution_status().unwrap().as_str(),
        "AVAILABLE"
    );
    cfn.update_termination_protection().stack_name("workers").enable_termination_protection(true).send().await.unwrap();
    cfn.update_stack()
        .stack_name("workers")
        .template_body(r#"{"Resources":{"Jobs":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"refactor-jobs","VisibilityTimeout":60}}},"Outputs":{"JobsUrl":{"Value":{"Ref":"Jobs"},"Export":{"Name":"jobs-url"}}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(settled(&cfn, "workers").await, StackStatus::UpdateComplete);
    let d = refactor_done(&cfn, stale.stack_refactor_id().unwrap()).await;
    assert_eq!(d.execution_status().unwrap().as_str(), "OBSOLETE");
}
