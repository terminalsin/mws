//! Systems Manager State Manager, inventory, compliance, patching, node
//! views, change calendars, document reviews and resource data syncs,
//! through the official Rust SDK.

use std::time::Duration;

use aws_sdk_ec2::types::{Filter, IamInstanceProfileSpecification, InstanceStateName, ResourceType, TagSpecification};
use aws_sdk_ssm::error::ProvideErrorMetadata;
use aws_sdk_ssm::primitives::DateTime;
use aws_sdk_ssm::types::{
    AssociationFilter, AssociationFilterKey, CalendarState, ComplianceExecutionSummary, ComplianceItemEntry,
    ComplianceSeverity, ComplianceStatus, ComplianceStringFilter, CreateAssociationBatchRequestEntry, DocumentFormat,
    DocumentReviewAction, DocumentReviews, DocumentType, InventoryFilter, InventoryItem, InventoryQueryOperatorType,
    NodeAggregator, NodeAggregatorType, NodeAttributeName, NodeTypeName, ResourceDataSyncS3Destination,
    ResourceDataSyncS3Format, Target,
};
use aws_sdk_ssm::Client;
use mws_e2e::Mws;

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn profile(cfg: &aws_config::SdkConfig, name: &str) {
    let iam = aws_sdk_iam::Client::new(cfg);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    // The agent registers only when the role may call ssm:UpdateInstanceInformation.
    let core = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:UpdateInstanceInformation","ssmmessages:*","ec2messages:*"],"Resource":"*"}]}"#;
    iam.put_role_policy().role_name(name).policy_name("ssm-core").policy_document(core).send().await.unwrap();
    iam.create_instance_profile().instance_profile_name(name).send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name(name).role_name(name).send().await.unwrap();
}

async fn launch(ec2: &aws_sdk_ec2::Client, image: &str, tags: &[(&str, &str)]) -> String {
    let mut spec = TagSpecification::builder().resource_type(ResourceType::Instance);
    for (k, v) in tags {
        spec = spec.tags(aws_sdk_ec2::types::Tag::builder().key(*k).value(*v).build());
    }
    let out = ec2
        .run_instances()
        .image_id(image)
        .min_count(1)
        .max_count(1)
        .iam_instance_profile(IamInstanceProfileSpecification::builder().name("node").build())
        .tag_specifications(spec.build())
        .send()
        .await
        .unwrap();
    let id = out.instances()[0].instance_id().unwrap().to_string();
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().and_then(|s| s.name()) == Some(&InstanceStateName::Running) {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("instance {id} never ran");
}

async fn image(ec2: &aws_sdk_ec2::Client, pattern: &str) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values(pattern).build())
        .send()
        .await
        .unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

/// Wait until an association has `n` executions that all finished.
async fn executions(ssm: &Client, id: &str, n: usize) -> Vec<aws_sdk_ssm::types::AssociationExecution> {
    for _ in 0..200 {
        let out = ssm.describe_association_executions().association_id(id).send().await.unwrap();
        let list = out.association_executions().to_vec();
        if list.len() >= n && list.iter().all(|e| matches!(e.status(), Some("Success" | "Failed"))) {
            return list;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("association {id} never reached {n} finished executions");
}

#[tokio::test]
async fn associations_apply_on_create_update_schedule_and_new_nodes() {
    let mws =
        Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    profile(&cfg, "node").await;
    let ami = image(&ec2, "al2023-ami-*").await;
    let first = launch(&ec2, &ami, &[("Role", "web")]).await;

    let created = ssm
        .create_association()
        .name("AWS-RunShellScript")
        .association_name("say-hello")
        .targets(Target::builder().key("tag:Role").values("web").build())
        .parameters("commands", vec!["echo hello".into()])
        .schedule_expression("rate(30 minutes)")
        .compliance_severity(aws_sdk_ssm::types::AssociationComplianceSeverity::High)
        .send()
        .await
        .unwrap();
    let a = created.association_description().unwrap();
    let id = a.association_id().unwrap().to_string();
    assert_eq!(a.association_version(), Some("1"));

    let runs = executions(&ssm, &id, 1).await;
    assert_eq!(runs[0].status(), Some("Success"));
    let execution = runs[0].execution_id().unwrap();
    let targets =
        ssm.describe_association_execution_targets().association_id(&id).execution_id(execution).send().await.unwrap();
    let target = &targets.association_execution_targets()[0];
    assert_eq!(target.resource_id(), Some(first.as_str()));
    assert_eq!(target.status(), Some("Success"));
    assert_eq!(target.output_source().unwrap().output_source_type(), Some("RunCommand"));
    let described = ssm.describe_association().association_id(&id).send().await.unwrap();
    let overview = described.association_description().unwrap().overview().unwrap();
    assert_eq!(overview.status(), Some("Success"));
    let status = ssm.describe_instance_associations_status().instance_id(&first).send().await.unwrap();
    assert_eq!(status.instance_association_status_infos()[0].status(), Some("Success"));
    let effective = ssm.describe_effective_instance_associations().instance_id(&first).send().await.unwrap();
    assert!(effective.associations()[0].content().unwrap().contains("aws:runShellScript"));

    // Association compliance follows the run.
    let items = ssm
        .list_compliance_items()
        .resource_ids(&first)
        .resource_types("ManagedInstance")
        .filters(ComplianceStringFilter::builder().key("ComplianceType").values("Association").build())
        .send()
        .await
        .unwrap();
    assert_eq!(items.compliance_items()[0].status(), Some(&ComplianceStatus::Compliant));
    assert_eq!(items.compliance_items()[0].severity(), Some(&ComplianceSeverity::High));

    // An update is a new version, applied at once.
    let updated = ssm
        .update_association()
        .association_id(&id)
        .association_version("1")
        .parameters("commands", vec!["echo again".into()])
        .send()
        .await
        .unwrap();
    assert_eq!(updated.association_description().unwrap().association_version(), Some("2"));
    let stale = ssm.update_association().association_id(&id).association_version("1").send().await.unwrap_err();
    assert_eq!(code(stale), "InvalidAssociationVersion");
    executions(&ssm, &id, 2).await;
    let versions = ssm.list_association_versions().association_id(&id).send().await.unwrap();
    assert_eq!(versions.association_versions().len(), 2);

    // A node that starts matching the targets gets the association.
    let second = launch(&ec2, &ami, &[("Role", "web")]).await;
    let mut applied = false;
    for _ in 0..100 {
        let s = ssm.describe_instance_associations_status().instance_id(&second).send().await.unwrap();
        if s.instance_association_status_infos().first().and_then(|i| i.status()) == Some("Success") {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(applied, "the association never reached {second}");
    let before = ssm.describe_association_executions().association_id(&id).send().await.unwrap();
    let count = before.association_executions().len();

    // The schedule comes due on the emulated clock.
    let (code_, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 1900}"#)).await;
    assert_eq!(code_, 200);
    ssm.list_associations().send().await.unwrap();
    executions(&ssm, &id, count + 1).await;

    ssm.start_associations_once().association_ids(&id).send().await.unwrap();
    executions(&ssm, &id, count + 2).await;

    let listed = ssm
        .list_associations()
        .association_filter_list(
            AssociationFilter::builder().key(AssociationFilterKey::Name).value("AWS-RunShellScript").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(listed.associations().len(), 1);
    assert_eq!(listed.associations()[0].association_name(), Some("say-hello"));

    let batch = ssm
        .create_association_batch()
        .entries(
            CreateAssociationBatchRequestEntry::builder()
                .name("AWS-RunShellScript")
                .instance_id(&first)
                .parameters("commands", vec!["true".into()])
                .build()
                .unwrap(),
        )
        .entries(
            CreateAssociationBatchRequestEntry::builder().name("NoSuchDocument").instance_id(&first).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(batch.successful().len(), 1);
    assert_eq!(batch.failed().len(), 1);

    let props = ssm.describe_instance_properties().send().await.unwrap();
    let p = props.instance_properties().iter().find(|p| p.instance_id() == Some(first.as_str())).unwrap();
    assert!(p.last_association_execution_date().is_some());

    ssm.delete_association().association_id(&id).send().await.unwrap();
    let gone = ssm.describe_association().association_id(&id).send().await.unwrap_err();
    assert_eq!(code(gone), "AssociationDoesNotExist");
}

#[tokio::test]
async fn inventory_compliance_patching_and_data_sync() {
    let mws =
        Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    profile(&cfg, "node").await;
    let ami = image(&ec2, "al2023-ami-*").await;
    let node = launch(&ec2, &ami, &[("Role", "db"), ("Patch Group", "prod")]).await;

    // Every managed node reports AWS:InstanceInformation.
    let inv = ssm
        .get_inventory()
        .filters(
            InventoryFilter::builder()
                .key("AWS:InstanceInformation.InstanceId")
                .values(&node)
                .r#type(InventoryQueryOperatorType::Equal)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(inv.entities().len(), 1);
    let info = &inv.entities()[0].data().unwrap()["AWS:InstanceInformation"];
    assert_eq!(info.content()[0]["PlatformType"], "Linux");

    let now = DateTime::from_secs(1_800_000_000).fmt(aws_smithy_types::date_time::Format::DateTime).unwrap();
    ssm.put_inventory()
        .instance_id(&node)
        .items(
            InventoryItem::builder()
                .type_name("Custom:RackInfo")
                .schema_version("1.0")
                .capture_time(&now)
                .content([("RackLocation".to_string(), "Bay B/Row C".to_string())].into_iter().collect())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let entries = ssm.list_inventory_entries().instance_id(&node).type_name("Custom:RackInfo").send().await.unwrap();
    assert_eq!(entries.entries()[0]["RackLocation"], "Bay B/Row C");
    let schema = ssm.get_inventory_schema().type_name("Custom:RackInfo").send().await.unwrap();
    assert_eq!(schema.schemas()[0].attributes()[0].name(), "RackLocation");
    let agg = ssm
        .get_inventory()
        .aggregators(
            aws_sdk_ssm::types::InventoryAggregator::builder()
                .expression("AWS:InstanceInformation.PlatformType")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let counts = &agg.entities()[0].data().unwrap()["AWS:InstanceInformation"];
    assert_eq!(counts.content()[0]["Count"], "1");

    // Custom compliance.
    ssm.put_compliance_items()
        .resource_id(&node)
        .resource_type("ManagedInstance")
        .compliance_type("Custom:Antivirus")
        .execution_summary(
            ComplianceExecutionSummary::builder().execution_time(DateTime::from_secs(1_800_000_000)).build().unwrap(),
        )
        .items(
            ComplianceItemEntry::builder()
                .id("av-1")
                .title("Definitions out of date")
                .severity(ComplianceSeverity::Critical)
                .status(ComplianceStatus::NonCompliant)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let summaries = ssm.list_resource_compliance_summaries().send().await.unwrap();
    let av = summaries
        .resource_compliance_summary_items()
        .iter()
        .find(|s| s.compliance_type() == Some("Custom:Antivirus"))
        .unwrap();
    assert_eq!(av.status(), Some(&ComplianceStatus::NonCompliant));
    assert_eq!(av.overall_severity(), Some(&ComplianceSeverity::Critical));

    // A patch scan records the node's patch state against its group.
    let sent = ssm
        .send_command()
        .document_name("AWS-RunPatchBaseline")
        .instance_ids(&node)
        .parameters("Operation", vec!["Scan".into()])
        .send()
        .await
        .unwrap();
    let command = sent.command().unwrap().command_id().unwrap().to_string();
    let mut state = None;
    for _ in 0..100 {
        let s = ssm.describe_instance_patch_states().instance_ids(&node).send().await.unwrap();
        if let Some(p) = s.instance_patch_states().first() {
            state = Some(p.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let state = state.expect("no patch state recorded");
    assert_eq!(state.patch_group(), "prod");
    assert_eq!(state.operation(), &aws_sdk_ssm::types::PatchOperationType::Scan);
    assert!(state.baseline_id().starts_with("pb-"), "{}", state.baseline_id());
    let group = ssm.describe_instance_patch_states_for_patch_group().patch_group("prod").send().await.unwrap();
    assert_eq!(group.instance_patch_states().len(), 1);
    let done = ssm.get_command_invocation().command_id(&command).instance_id(&node).send().await.unwrap();
    assert!(done.standard_output_content().unwrap().contains("Patch baseline Scan completed"));
    let types = ssm.list_compliance_summaries().send().await.unwrap();
    let kinds: Vec<&str> = types.compliance_summary_items().iter().filter_map(|s| s.compliance_type()).collect();
    assert!(kinds.contains(&"Patch"), "{kinds:?}");

    // Resource data syncs write the inventory into S3.
    s3.create_bucket().bucket("inventory-sync").send().await.unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ssm.amazonaws.com"},"Action":["s3:PutObject","s3:GetBucketAcl"],"Resource":["arn:aws:s3:::inventory-sync","arn:aws:s3:::inventory-sync/*"]}]}"#;
    s3.put_bucket_policy().bucket("inventory-sync").policy(policy).send().await.unwrap();
    ssm.create_resource_data_sync()
        .sync_name("all")
        .s3_destination(
            ResourceDataSyncS3Destination::builder()
                .bucket_name("inventory-sync")
                .prefix("ssm")
                .sync_format(ResourceDataSyncS3Format::JsonSerde)
                .region("us-east-1")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let key = format!(
        "ssm/Custom:RackInfo/accountid=123456789012/region=us-east-1/resourcetype=ManagedInstanceInventory/{node}.json"
    );
    let mut body = None;
    for _ in 0..100 {
        if let Ok(o) = s3.get_object().bucket("inventory-sync").key(&key).send().await {
            body = Some(String::from_utf8(o.body.collect().await.unwrap().to_vec()).unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let body = body.expect("the sync wrote nothing");
    let line: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    assert_eq!(line["rackLocation"], "Bay B/Row C");
    assert_eq!(line["resourceId"], node.as_str());
    let syncs = ssm.list_resource_data_sync().send().await.unwrap();
    assert_eq!(syncs.resource_data_sync_items()[0].last_status().map(|s| s.as_str()), Some("Successful"));
    s3.create_bucket().bucket("closed").send().await.unwrap();
    let denied = ssm
        .create_resource_data_sync()
        .sync_name("denied")
        .s3_destination(
            ResourceDataSyncS3Destination::builder()
                .bucket_name("closed")
                .sync_format(ResourceDataSyncS3Format::JsonSerde)
                .region("us-east-1")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(denied), "ResourceDataSyncInvalidConfigurationException");

    let deleted = ssm
        .delete_inventory()
        .type_name("Custom:RackInfo")
        .schema_delete_option(aws_sdk_ssm::types::InventorySchemaDeleteOption::DeleteSchema)
        .send()
        .await
        .unwrap();
    let deletions =
        ssm.describe_inventory_deletions().deletion_id(deleted.deletion_id().unwrap()).send().await.unwrap();
    assert_eq!(deletions.inventory_deletions()[0].last_status().map(|s| s.as_str()), Some("Complete"));

    // Node views.
    let nodes = ssm.list_nodes().send().await.unwrap();
    assert_eq!(nodes.nodes()[0].id(), Some(node.as_str()));
    let summary = ssm
        .list_nodes_summary()
        .aggregators(
            NodeAggregator::builder()
                .aggregator_type(NodeAggregatorType::Count)
                .type_name(NodeTypeName::Instance)
                .attribute_name(NodeAttributeName::PlatformType)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(summary.summary()[0]["Count"], "1");
}

#[tokio::test]
async fn change_calendars_and_document_reviews() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ssm = Client::new(&cfg);
    let calendar = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//AWS//Change Calendar 1.0//EN\r\nX-CALENDAR-TYPE:DEFAULT_OPEN\r\nBEGIN:VEVENT\r\nUID:freeze\r\nDTSTART:20000101T000000Z\r\nDTEND:21000101T000000Z\r\nSUMMARY:Freeze\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    ssm.create_document()
        .name("freeze")
        .document_type(DocumentType::ChangeCalendar)
        .document_format(DocumentFormat::Text)
        .content(calendar)
        .send()
        .await
        .unwrap();
    let state = ssm.get_calendar_state().calendar_names("freeze").send().await.unwrap();
    assert_eq!(state.state(), Some(&CalendarState::Closed));
    assert_eq!(state.next_transition_time(), Some("2100-01-01T00:00:00Z"));
    let later = ssm.get_calendar_state().calendar_names("freeze").at_time("2100-06-01T00:00:00Z").send().await.unwrap();
    assert_eq!(later.state(), Some(&CalendarState::Open));

    let content = r#"{"schemaVersion":"2.2","description":"hi","mainSteps":[{"action":"aws:runShellScript","name":"run","inputs":{"runCommand":["echo hi"]}}]}"#;
    ssm.create_document().name("reviewed").document_type(DocumentType::Command).content(content).send().await.unwrap();
    ssm.update_document_metadata()
        .name("reviewed")
        .document_reviews(DocumentReviews::builder().action(DocumentReviewAction::SendForReview).build().unwrap())
        .send()
        .await
        .unwrap();
    ssm.update_document_metadata()
        .name("reviewed")
        .document_reviews(DocumentReviews::builder().action(DocumentReviewAction::Approve).build().unwrap())
        .send()
        .await
        .unwrap();
    let history = ssm
        .list_document_metadata_history()
        .name("reviewed")
        .metadata(aws_sdk_ssm::types::DocumentMetadataEnum::DocumentReviews)
        .send()
        .await
        .unwrap();
    let responses = history.metadata().unwrap().reviewer_response();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].review_status().map(|s| s.as_str()), Some("APPROVED"));
}
