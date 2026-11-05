//! AWS Security Hub through the official SDK: the hub, standards and
//! controls, ASFF findings (import, filters, workflow, history, insights,
//! automation rules), EventBridge findings events, administrator/member
//! accounts through invitations and through AWS Organizations (delegated
//! administrator, central configuration policies), and the V2 API (OCSF
//! findings, resources, software, exports to S3, connectors).

use std::time::Duration;

use aws_sdk_securityhub::error::ProvideErrorMetadata;
use aws_sdk_securityhub::types::*;
use aws_sdk_securityhub::Client;
use mws_e2e::{sts_config, user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";
const REGION: &str = "us-east-1";
const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;

fn default_product(account: &str) -> String {
    format!("arn:aws:securityhub:{REGION}:{account}:product/{account}/default")
}

fn ts(offset_minutes: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::minutes(offset_minutes))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// An ASFF finding from the account's own default product.
fn finding(id: &str, account: &str, label: SeverityLabel, bucket: &str) -> AwsSecurityFinding {
    AwsSecurityFinding::builder()
        .schema_version("2018-10-08")
        .id(id)
        .product_arn(default_product(account))
        .generator_id("mws-e2e-scanner")
        .aws_account_id(account)
        .types("Software and Configuration Checks/Vulnerabilities/CVE")
        .created_at(ts(-60))
        .updated_at(ts(-1))
        .severity(Severity::builder().label(label).original("custom").build())
        .title(format!("Finding {id}"))
        .description("A finding imported by the e2e suite")
        .resources(
            Resource::builder()
                .r#type("AwsS3Bucket")
                .id(format!("arn:aws:s3:::{bucket}"))
                .partition(Partition::Aws)
                .region(REGION)
                .tags("team", "payments")
                .build(),
        )
        .vulnerabilities(
            Vulnerability::builder()
                .id("CVE-2024-0001")
                .vulnerable_packages(
                    SoftwarePackage::builder().name("openssl").version("1.1.1k").package_manager("OS").build(),
                )
                .build(),
        )
        .build()
}

/// An OCSF finding from the V2 API as JSON.
fn doc_json(d: &aws_smithy_types::Document) -> serde_json::Value {
    use aws_smithy_types::{Document, Number};
    match d {
        Document::Object(m) => serde_json::Value::Object(m.iter().map(|(k, v)| (k.clone(), doc_json(v))).collect()),
        Document::Array(a) => a.iter().map(doc_json).collect(),
        Document::Number(Number::PosInt(n)) => (*n).into(),
        Document::Number(Number::NegInt(n)) => (*n).into(),
        Document::Number(Number::Float(f)) => serde_json::json!(f),
        Document::String(s) => s.clone().into(),
        Document::Bool(b) => (*b).into(),
        Document::Null => serde_json::Value::Null,
    }
}

fn eq(v: &str) -> StringFilter {
    StringFilter::builder().value(v).comparison(StringFilterComparison::Equals).build()
}

fn ident(id: &str, account: &str) -> AwsSecurityFindingIdentifier {
    AwsSecurityFindingIdentifier::builder().id(id).product_arn(default_product(account)).build()
}

/// Run a test on a thread with a large stack: the SDK's debug-build
/// deserializers for ASFF findings (resource details have hundreds of
/// members) overflow a default test thread's stack.
fn big_stack<F: std::future::Future<Output = ()> + Send + 'static>(test: F) {
    let thread = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test))
        .unwrap();
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

async fn hub(mws: &Mws) -> Client {
    let sh = Client::new(&mws.root_sdk_config().await);
    sh.enable_security_hub().enable_default_standards(true).tags("env", "test").send().await.unwrap();
    sh
}

async fn hub_lifecycle_products_action_targets_and_tags_body() {
    let mws = Mws::start().await;
    let sh = Client::new(&mws.root_sdk_config().await);

    let err = sh.describe_hub().send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidAccessException"));
    assert!(err.message().unwrap().contains("not subscribed to AWS Security Hub"), "{err:?}");

    sh.enable_security_hub()
        .enable_default_standards(true)
        .control_finding_generator(ControlFindingGenerator::SecurityControl)
        .tags("env", "test")
        .send()
        .await
        .unwrap();
    let again = sh.enable_security_hub().send().await.unwrap_err();
    assert_eq!(again.code(), Some("ResourceConflictException"));

    let d = sh.describe_hub().send().await.unwrap();
    let hub_arn = d.hub_arn().unwrap().to_string();
    assert_eq!(hub_arn, format!("arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default"));
    assert_eq!(d.auto_enable_controls(), Some(true));
    assert_eq!(d.control_finding_generator(), Some(&ControlFindingGenerator::SecurityControl));
    assert!(d.subscribed_at().is_some());

    sh.update_security_hub_configuration()
        .auto_enable_controls(false)
        .control_finding_generator(ControlFindingGenerator::StandardControl)
        .send()
        .await
        .unwrap();
    let d = sh.describe_hub().hub_arn(&hub_arn).send().await.unwrap();
    assert_eq!(d.auto_enable_controls(), Some(false));
    assert_eq!(d.control_finding_generator(), Some(&ControlFindingGenerator::StandardControl));

    // Products: AWS integrations are enabled with the hub; partner ones are not.
    let products = sh.describe_products().max_results(100).send().await.unwrap();
    let names: Vec<_> = products.products().iter().filter_map(|p| p.product_name()).collect();
    assert!(names.contains(&"GuardDuty"), "{names:?}");
    let falcon = products
        .products()
        .iter()
        .find(|p| p.product_name() == Some("CrowdStrike Falcon"))
        .unwrap()
        .product_arn()
        .unwrap()
        .to_string();
    let enabled = sh.list_enabled_products_for_import().send().await.unwrap();
    assert!(enabled.product_subscriptions().iter().any(|s| s.ends_with("product-subscription/aws/guardduty")));
    let sub = sh.enable_import_findings_for_product().product_arn(&falcon).send().await.unwrap();
    let sub_arn = sub.product_subscription_arn().unwrap().to_string();
    assert_eq!(
        sub_arn,
        format!("arn:aws:securityhub:{REGION}:{ACCOUNT}:product-subscription/crowdstrike/crowdstrike-falcon")
    );
    let dup = sh.enable_import_findings_for_product().product_arn(&falcon).send().await.unwrap_err();
    assert_eq!(dup.code(), Some("ResourceConflictException"));
    sh.disable_import_findings_for_product().product_subscription_arn(&sub_arn).send().await.unwrap();
    let enabled = sh.list_enabled_products_for_import().send().await.unwrap();
    assert!(!enabled.product_subscriptions().contains(&sub_arn));

    // Custom actions.
    let target = sh
        .create_action_target()
        .name("Send to SOC")
        .description("Escalate to the SOC")
        .id("SendToSOC")
        .send()
        .await
        .unwrap();
    let target_arn = target.action_target_arn().unwrap().to_string();
    assert_eq!(target_arn, format!("arn:aws:securityhub:{REGION}:{ACCOUNT}:action/custom/SendToSOC"));
    sh.update_action_target().action_target_arn(&target_arn).description("Escalate now").send().await.unwrap();
    let targets = sh.describe_action_targets().action_target_arns(&target_arn).send().await.unwrap();
    assert_eq!(targets.action_targets()[0].description(), Some("Escalate now"));
    sh.delete_action_target().action_target_arn(&target_arn).send().await.unwrap();
    let gone = sh.describe_action_targets().action_target_arns(&target_arn).send().await.unwrap_err();
    assert_eq!(gone.code(), Some("ResourceNotFoundException"));

    // Tags on the hub.
    let tags = sh.list_tags_for_resource().resource_arn(&hub_arn).send().await.unwrap();
    assert_eq!(tags.tags().unwrap().get("env").map(String::as_str), Some("test"));
    sh.tag_resource().resource_arn(&hub_arn).tags("owner", "secops").send().await.unwrap();
    sh.untag_resource().resource_arn(&hub_arn).tag_keys("env").send().await.unwrap();
    let tags = sh.list_tags_for_resource().resource_arn(&hub_arn).send().await.unwrap();
    let tags = tags.tags().unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags.get("owner").map(String::as_str), Some("secops"));
    let reserved = sh.tag_resource().resource_arn(&hub_arn).tags("aws:x", "y").send().await.unwrap_err();
    assert_eq!(reserved.code(), Some("InvalidInputException"));

    // Cross-Region aggregation.
    let agg = sh
        .create_finding_aggregator()
        .region_linking_mode("SPECIFIED_REGIONS")
        .regions("us-west-2")
        .regions("eu-west-1")
        .send()
        .await
        .unwrap();
    let agg_arn = agg.finding_aggregator_arn().unwrap().to_string();
    assert_eq!(agg.finding_aggregation_region(), Some(REGION));
    let dup = sh.create_finding_aggregator().region_linking_mode("ALL_REGIONS").send().await.unwrap_err();
    assert!(dup.code().is_some(), "{dup:?}");
    sh.update_finding_aggregator()
        .finding_aggregator_arn(&agg_arn)
        .region_linking_mode("ALL_REGIONS")
        .send()
        .await
        .unwrap();
    let got = sh.get_finding_aggregator().finding_aggregator_arn(&agg_arn).send().await.unwrap();
    assert_eq!(got.region_linking_mode(), Some("ALL_REGIONS"));
    let listed = sh.list_finding_aggregators().send().await.unwrap();
    assert_eq!(listed.finding_aggregators().len(), 1);
    sh.delete_finding_aggregator().finding_aggregator_arn(&agg_arn).send().await.unwrap();
    assert!(sh.list_finding_aggregators().send().await.unwrap().finding_aggregators().is_empty());

    sh.disable_security_hub().send().await.unwrap();
    let err = sh.describe_hub().send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidAccessException"));
}

async fn standards_and_controls_body() {
    let mws = Mws::start().await;
    let sh = hub(&mws).await;

    let standards = sh.describe_standards().send().await.unwrap();
    let arns: Vec<_> = standards.standards().iter().filter_map(|s| s.standards_arn()).collect();
    let fsbp = format!("arn:aws:securityhub:{REGION}::standards/aws-foundational-security-best-practices/v/1.0.0");
    let cis12 = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0".to_string();
    let nist = format!("arn:aws:securityhub:{REGION}::standards/nist-800-53/v/5.0.0");
    assert!(
        arns.contains(&fsbp.as_str()) && arns.contains(&cis12.as_str()) && arns.contains(&nist.as_str()),
        "{arns:?}"
    );

    // Default standards are FSBP and CIS 1.2.0.
    let enabled = sh.get_enabled_standards().send().await.unwrap();
    let mut on: Vec<_> = enabled.standards_subscriptions().iter().filter_map(|s| s.standards_arn()).collect();
    on.sort();
    let mut want = vec![fsbp.as_str(), cis12.as_str()];
    want.sort();
    assert_eq!(on, want);

    let nist_sub = sh
        .batch_enable_standards()
        .standards_subscription_requests(StandardsSubscriptionRequest::builder().standards_arn(&nist).build())
        .send()
        .await
        .unwrap();
    let nist_sub_arn = nist_sub.standards_subscriptions()[0].standards_subscription_arn().unwrap().to_string();
    assert_eq!(nist_sub_arn, format!("arn:aws:securityhub:{REGION}:{ACCOUNT}:subscription/nist-800-53/v/5.0.0"));
    // Subscribing is asynchronous: PENDING, then READY.
    assert_eq!(nist_sub.standards_subscriptions()[0].standards_status(), Some(&StandardsStatus::Pending));
    let enabled = sh.get_enabled_standards().standards_subscription_arns(&nist_sub_arn).send().await.unwrap();
    assert_eq!(enabled.standards_subscriptions()[0].standards_status(), Some(&StandardsStatus::Ready));

    // Per-standard controls (the original API).
    let controls = sh.describe_standards_controls().standards_subscription_arn(&nist_sub_arn).send().await.unwrap();
    let acm1 = controls.controls().iter().find(|c| c.control_id() == Some("ACM.1")).unwrap();
    assert_eq!(acm1.control_status(), Some(&ControlStatus::Enabled));
    let acm1_arn = acm1.standards_control_arn().unwrap().to_string();
    assert_eq!(acm1_arn, format!("arn:aws:securityhub:{REGION}:{ACCOUNT}:control/nist-800-53/v/5.0.0/ACM.1"));
    let no_reason = sh
        .update_standards_control()
        .standards_control_arn(&acm1_arn)
        .control_status(ControlStatus::Disabled)
        .send()
        .await
        .unwrap_err();
    assert_eq!(no_reason.code(), Some("InvalidInputException"));
    sh.update_standards_control()
        .standards_control_arn(&acm1_arn)
        .control_status(ControlStatus::Disabled)
        .disabled_reason("Not applicable")
        .send()
        .await
        .unwrap();

    // Consolidated controls.
    let defs = sh.list_security_control_definitions().standards_arn(&nist).max_results(100).send().await.unwrap();
    assert!(defs.security_control_definitions().iter().any(|d| d.security_control_id() == Some("ACM.1")));
    let def = sh.get_security_control_definition().security_control_id("ACM.1").send().await.unwrap();
    let def = def.security_control_definition().unwrap();
    assert_eq!(def.severity_rating(), Some(&SeverityRating::Medium));
    assert!(def.parameter_definitions().unwrap().contains_key("daysToExpiration"));

    let got = sh
        .batch_get_security_controls()
        .security_control_ids("ACM.1")
        .security_control_ids("Nope.99")
        .send()
        .await
        .unwrap();
    assert_eq!(got.security_controls().len(), 1);
    assert_eq!(got.unprocessed_ids()[0].security_control_id(), Some("Nope.99"));

    let mut params = std::collections::HashMap::new();
    params.insert(
        "daysToExpiration".to_string(),
        ParameterConfiguration::builder()
            .value_type(ParameterValueType::Custom)
            .value(ParameterValue::Integer(45))
            .build(),
    );
    sh.update_security_control()
        .security_control_id("ACM.1")
        .set_parameters(Some(params.clone()))
        .last_update_reason("Longer renewal window")
        .send()
        .await
        .unwrap();
    let got = sh.batch_get_security_controls().security_control_ids("ACM.1").send().await.unwrap();
    let ctl = &got.security_controls()[0];
    assert_eq!(ctl.last_update_reason(), Some("Longer renewal window"));
    let p = ctl.parameters().unwrap().get("daysToExpiration").unwrap();
    assert_eq!(p.value(), Some(&ParameterValue::Integer(45)));
    params.insert(
        "daysToExpiration".to_string(),
        ParameterConfiguration::builder()
            .value_type(ParameterValueType::Custom)
            .value(ParameterValue::Integer(1000))
            .build(),
    );
    let out_of_range = sh
        .update_security_control()
        .security_control_id("ACM.1")
        .set_parameters(Some(params))
        .send()
        .await
        .unwrap_err();
    assert_eq!(out_of_range.code(), Some("InvalidInputException"));

    let assoc = sh.list_standards_control_associations().security_control_id("ACM.1").send().await.unwrap();
    let nist_assoc = assoc
        .standards_control_association_summaries()
        .iter()
        .find(|a| a.standards_arn() == Some(nist.as_str()))
        .unwrap();
    assert_eq!(nist_assoc.association_status(), Some(&AssociationStatus::Disabled));
    sh.batch_update_standards_control_associations()
        .standards_control_association_updates(
            StandardsControlAssociationUpdate::builder()
                .standards_arn(&nist)
                .security_control_id("ACM.1")
                .association_status(AssociationStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let details = sh
        .batch_get_standards_control_associations()
        .standards_control_association_ids(
            StandardsControlAssociationId::builder().standards_arn(&nist).security_control_id("ACM.1").build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        details.standards_control_association_details()[0].association_status(),
        Some(&AssociationStatus::Enabled)
    );

    sh.batch_disable_standards().standards_subscription_arns(&nist_sub_arn).send().await.unwrap();
    let enabled = sh.get_enabled_standards().send().await.unwrap();
    assert!(enabled.standards_subscriptions().iter().all(|s| s.standards_arn() != Some(nist.as_str())));
}

/// A queue receiving the default bus's Security Hub events.
async fn events_queue(mws: &Mws, pattern: &str) -> (aws_sdk_sqs::Client, String) {
    let cfg = mws.root_sdk_config().await;
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let url = sqs.create_queue().queue_name("securityhub-events").send().await.unwrap().queue_url.unwrap();
    let arn = format!("arn:aws:sqs:{REGION}:{ACCOUNT}:securityhub-events");
    let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":arn}]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    eb.put_rule().name("securityhub").event_pattern(pattern).send().await.unwrap();
    eb.put_targets()
        .rule("securityhub")
        .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(&arn).build().unwrap())
        .send()
        .await
        .unwrap();
    (sqs, url)
}

async fn receive_events(sqs: &aws_sdk_sqs::Client, url: &str, n: usize) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for _ in 0..20 {
        let r = sqs.receive_message().queue_url(url).max_number_of_messages(10).send().await.unwrap();
        for m in r.messages() {
            out.push(serde_json::from_str(m.body().unwrap()).unwrap());
        }
        if out.len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    out
}

async fn findings_import_filters_workflow_history_and_events_body() {
    let mws = Mws::start().await;
    let sh = hub(&mws).await;
    let (sqs, url) = events_queue(&mws, r#"{"source":["aws.securityhub"]}"#).await;

    // A finding for another account is refused on its own.
    let mut foreign = finding("f-3", ACCOUNT, SeverityLabel::Critical, "other");
    foreign.aws_account_id = Some("999999999999".into());
    let imported = sh
        .batch_import_findings()
        .findings(finding("f-1", ACCOUNT, SeverityLabel::High, "payments-data"))
        .findings(finding("f-2", ACCOUNT, SeverityLabel::Low, "public-assets"))
        .findings(foreign)
        .send()
        .await
        .unwrap();
    assert_eq!(imported.success_count(), Some(2));
    assert_eq!(imported.failed_count(), Some(1));
    let failed = &imported.failed_findings()[0];
    assert_eq!(failed.id(), Some("f-3"));
    assert!(failed.error_code().is_some());

    let events = receive_events(&sqs, &url, 1).await;
    let imported_event = events.iter().find(|e| e["detail-type"] == "Security Hub Findings - Imported").expect("event");
    assert_eq!(imported_event["source"], "aws.securityhub");
    assert_eq!(imported_event["account"], ACCOUNT);
    let ids: Vec<_> = events
        .iter()
        .flat_map(|e| e["detail"]["findings"].as_array().unwrap().iter().map(|f| f["Id"].clone()))
        .collect();
    assert!(ids.contains(&serde_json::json!("f-1")) && ids.contains(&serde_json::json!("f-2")), "{ids:?}");

    // Filters, sorting and paging.
    let high = sh
        .get_findings()
        .filters(AwsSecurityFindingFilters::builder().severity_label(eq("HIGH")).build())
        .send()
        .await
        .unwrap();
    assert_eq!(high.findings().len(), 1);
    let f1 = &high.findings()[0];
    assert_eq!(f1.id(), Some("f-1"));
    assert_eq!(f1.product_name(), Some("Default"));
    assert_eq!(f1.company_name(), Some("Personal"));
    assert_eq!(f1.region(), Some(REGION));
    assert_eq!(f1.record_state(), Some(&RecordState::Active));
    assert_eq!(f1.workflow().unwrap().status(), Some(&WorkflowStatus::New));
    assert_eq!(f1.severity().unwrap().normalized(), Some(70));
    assert!(f1.processed_at().is_some());

    let prefix = StringFilter::builder().value("arn:aws:s3:::pay").comparison(StringFilterComparison::Prefix).build();
    let by_resource = sh
        .get_findings()
        .filters(AwsSecurityFindingFilters::builder().resource_id(prefix).build())
        .send()
        .await
        .unwrap();
    assert_eq!(by_resource.findings().len(), 1);
    let tagged = sh
        .get_findings()
        .filters(
            AwsSecurityFindingFilters::builder()
                .resource_tags(
                    MapFilter::builder().key("team").value("payments").comparison(MapFilterComparison::Equals).build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(tagged.findings().len(), 2);

    let page = sh
        .get_findings()
        .sort_criteria(SortCriterion::builder().field("SeverityNormalized").sort_order(SortOrder::Ascending).build())
        .max_results(1)
        .send()
        .await
        .unwrap();
    assert_eq!(page.findings()[0].id(), Some("f-2"));
    let next = sh
        .get_findings()
        .sort_criteria(SortCriterion::builder().field("SeverityNormalized").sort_order(SortOrder::Ascending).build())
        .max_results(1)
        .next_token(page.next_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(next.findings()[0].id(), Some("f-1"));

    // BatchUpdateFindings: customer fields win over later provider imports.
    let updated = sh
        .batch_update_findings()
        .finding_identifiers(ident("f-1", ACCOUNT))
        .finding_identifiers(ident("missing", ACCOUNT))
        .workflow(WorkflowUpdate::builder().status(WorkflowStatus::Notified).build())
        .note(NoteUpdate::builder().text("Paged the bucket owner").updated_by("analyst").build())
        .severity(SeverityUpdate::builder().label(SeverityLabel::Critical).build())
        .user_defined_fields("ticket", "SEC-1")
        .send()
        .await
        .unwrap();
    assert_eq!(updated.processed_findings().len(), 1);
    assert_eq!(updated.unprocessed_findings()[0].error_code(), Some("FindingNotFound"));

    let mut again = finding("f-1", ACCOUNT, SeverityLabel::Low, "payments-data");
    again.updated_at = Some(ts(0));
    again.title = Some("Finding f-1 (rescanned)".into());
    sh.batch_import_findings().findings(again).send().await.unwrap();
    let got =
        sh.get_findings().filters(AwsSecurityFindingFilters::builder().id(eq("f-1")).build()).send().await.unwrap();
    let f1 = &got.findings()[0];
    assert_eq!(f1.title(), Some("Finding f-1 (rescanned)"));
    assert_eq!(f1.severity().unwrap().label(), Some(&SeverityLabel::Critical));
    assert_eq!(f1.workflow().unwrap().status(), Some(&WorkflowStatus::Notified));
    assert_eq!(f1.note().unwrap().text(), Some("Paged the bucket owner"));
    assert_eq!(f1.user_defined_fields().unwrap().get("ticket").map(String::as_str), Some("SEC-1"));

    let history = sh.get_finding_history().finding_identifier(ident("f-1", ACCOUNT)).send().await.unwrap();
    let records = history.records();
    assert!(records.len() >= 3, "{records:?}");
    assert_eq!(records.iter().filter(|r| r.finding_created() == Some(true)).count(), 1);
    assert!(records
        .iter()
        .any(|r| r.update_source().and_then(|s| s.r#type())
            == Some(&FindingHistoryUpdateSourceType::BatchUpdateFindings)));

    // The deprecated UpdateFindings archives by filter.
    sh.update_findings()
        .filters(AwsSecurityFindingFilters::builder().id(eq("f-2")).build())
        .record_state(RecordState::Archived)
        .note(NoteUpdate::builder().text("Accepted risk").updated_by("analyst").build())
        .send()
        .await
        .unwrap();
    let archived = sh
        .get_findings()
        .filters(AwsSecurityFindingFilters::builder().record_state(eq("ARCHIVED")).build())
        .send()
        .await
        .unwrap();
    assert_eq!(archived.findings().len(), 1);
    assert_eq!(archived.findings()[0].id(), Some("f-2"));

    // A passing control check resolves the finding; failing again reopens it.
    let mut passed = finding("f-1", ACCOUNT, SeverityLabel::Low, "payments-data");
    passed.updated_at = Some(ts(1));
    passed.compliance = Some(Compliance::builder().status(ComplianceStatus::Passed).build());
    sh.batch_import_findings().findings(passed).send().await.unwrap();
    let got =
        sh.get_findings().filters(AwsSecurityFindingFilters::builder().id(eq("f-1")).build()).send().await.unwrap();
    assert_eq!(got.findings()[0].workflow().unwrap().status(), Some(&WorkflowStatus::Resolved));
    let mut reopen = finding("f-1", ACCOUNT, SeverityLabel::Low, "payments-data");
    reopen.updated_at = Some(ts(2));
    reopen.compliance = Some(Compliance::builder().status(ComplianceStatus::Failed).build());
    sh.batch_import_findings().findings(reopen).send().await.unwrap();
    let got =
        sh.get_findings().filters(AwsSecurityFindingFilters::builder().id(eq("f-1")).build()).send().await.unwrap();
    assert_eq!(got.findings()[0].workflow().unwrap().status(), Some(&WorkflowStatus::New));

    let invalid = sh
        .batch_import_findings()
        .findings(AwsSecurityFinding::builder().id("x").aws_account_id(ACCOUNT).build())
        .send()
        .await;
    match invalid {
        Ok(out) => assert_eq!(out.failed_count(), Some(1)),
        Err(e) => assert_eq!(e.code(), Some("InvalidInputException")),
    }
}

async fn insights_and_automation_rules_body() {
    let mws = Mws::start().await;
    let sh = hub(&mws).await;

    // A rule suppresses low findings on public buckets and tags them.
    let rule = sh
        .create_automation_rule()
        .rule_name("suppress-public-assets")
        .rule_order(1)
        .description("Public assets are expected to be public")
        .rule_status(RuleStatus::Enabled)
        .is_terminal(true)
        .criteria(
            AutomationRulesFindingFilters::builder()
                .resource_id(
                    StringFilter::builder().value("public").comparison(StringFilterComparison::Contains).build(),
                )
                .build(),
        )
        .actions(
            AutomationRulesAction::builder()
                .r#type(AutomationRulesActionType::FindingFieldsUpdate)
                .finding_fields_update(
                    AutomationRulesFindingFieldsUpdate::builder()
                        .workflow(WorkflowUpdate::builder().status(WorkflowStatus::Suppressed).build())
                        .user_defined_fields("reason", "public-by-design")
                        .build(),
                )
                .build(),
        )
        .tags("team", "secops")
        .send()
        .await
        .unwrap();
    let rule_arn = rule.rule_arn().unwrap().to_string();
    assert!(rule_arn.starts_with(&format!("arn:aws:securityhub:{REGION}:{ACCOUNT}:automation-rule/")));

    let listed = sh.list_automation_rules().send().await.unwrap();
    assert_eq!(listed.automation_rules_metadata().len(), 1);
    assert_eq!(listed.automation_rules_metadata()[0].rule_name(), Some("suppress-public-assets"));
    let got = sh
        .batch_get_automation_rules()
        .automation_rules_arns(&rule_arn)
        .automation_rules_arns(format!("{rule_arn}x"))
        .send()
        .await
        .unwrap();
    assert_eq!(got.rules().len(), 1);
    assert_eq!(got.unprocessed_automation_rules().len(), 1);

    sh.batch_import_findings()
        .findings(finding("pub-1", ACCOUNT, SeverityLabel::Low, "public-assets"))
        .findings(finding("priv-1", ACCOUNT, SeverityLabel::High, "payroll"))
        .send()
        .await
        .unwrap();
    let all = sh.get_findings().send().await.unwrap();
    let public = all.findings().iter().find(|f| f.id() == Some("pub-1")).unwrap();
    assert_eq!(public.workflow().unwrap().status(), Some(&WorkflowStatus::Suppressed));
    assert_eq!(public.user_defined_fields().unwrap().get("reason").map(String::as_str), Some("public-by-design"));
    let private = all.findings().iter().find(|f| f.id() == Some("priv-1")).unwrap();
    assert_eq!(private.workflow().unwrap().status(), Some(&WorkflowStatus::New));

    sh.batch_update_automation_rules()
        .update_automation_rules_request_items(
            UpdateAutomationRulesRequestItem::builder().rule_arn(&rule_arn).rule_status(RuleStatus::Disabled).build(),
        )
        .send()
        .await
        .unwrap();
    let got = sh.batch_get_automation_rules().automation_rules_arns(&rule_arn).send().await.unwrap();
    assert_eq!(got.rules()[0].rule_status(), Some(&RuleStatus::Disabled));
    let deleted = sh.batch_delete_automation_rules().automation_rules_arns(&rule_arn).send().await.unwrap();
    assert_eq!(deleted.processed_automation_rules(), std::slice::from_ref(&rule_arn));
    assert!(sh.list_automation_rules().send().await.unwrap().automation_rules_metadata().is_empty());

    // Insights.
    let insight = sh
        .create_insight()
        .name("Findings by bucket")
        .group_by_attribute("ResourceId")
        .filters(AwsSecurityFindingFilters::builder().workflow_status(eq("NEW")).build())
        .send()
        .await
        .unwrap();
    let insight_arn = insight.insight_arn().unwrap().to_string();
    let results = sh.get_insight_results().insight_arn(&insight_arn).send().await.unwrap();
    let results = results.insight_results().unwrap();
    assert_eq!(results.group_by_attribute(), Some("ResourceId"));
    assert_eq!(results.result_values().len(), 1);
    assert_eq!(results.result_values()[0].group_by_attribute_value(), Some("arn:aws:s3:::payroll"));
    assert_eq!(results.result_values()[0].count(), Some(1));

    sh.update_insight().insight_arn(&insight_arn).name("New findings by bucket").send().await.unwrap();
    let got = sh.get_insights().insight_arns(&insight_arn).send().await.unwrap();
    assert_eq!(got.insights()[0].name(), Some("New findings by bucket"));
    // Without ARNs only custom insights are listed; managed ones are read by ARN.
    let custom = sh.get_insights().send().await.unwrap();
    assert_eq!(custom.insights().len(), 1);
    let managed_arn = "arn:aws:securityhub:::insight/securityhub/default/1";
    let managed = sh.get_insights().insight_arns(managed_arn).send().await.unwrap();
    assert!(managed.insights()[0].name().is_some());
    let managed_results = sh.get_insight_results().insight_arn(managed_arn).send().await.unwrap();
    assert!(managed_results.insight_results().is_some());
    let bad_group = sh
        .create_insight()
        .name("bad")
        .group_by_attribute("NotAField")
        .filters(AwsSecurityFindingFilters::builder().build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(bad_group.code(), Some("InvalidInputException"));
    sh.delete_insight().insight_arn(&insight_arn).send().await.unwrap();
    let gone = sh.get_insights().insight_arns(&insight_arn).send().await.unwrap_err();
    assert_eq!(gone.code(), Some("ResourceNotFoundException"));
}

struct Org {
    mws: Mws,
    orgs: aws_sdk_organizations::Client,
    admin: aws_config::SdkConfig,
}

async fn org() -> Org {
    let mws = Mws::start().await;
    let orgs = aws_sdk_organizations::Client::new(&mws.root_sdk_config().await);
    orgs.create_organization().send().await.unwrap();
    let (_, admin) = user_with_policy(&mws, "admin", Some(ADMIN)).await;
    Org { mws, orgs, admin }
}

impl Org {
    async fn create_account(&self, name: &str) -> String {
        let out =
            self.orgs.create_account().email(format!("{name}@example.com")).account_name(name).send().await.unwrap();
        let request_id = out.create_account_status().unwrap().id().unwrap();
        let status =
            self.orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
        status.create_account_status().unwrap().account_id().unwrap().to_string()
    }

    async fn client_for(&self, account: &str) -> Client {
        let sts = aws_sdk_sts::Client::new(&self.admin);
        let creds = sts
            .assume_role()
            .role_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
            .role_session_name("secops")
            .send()
            .await
            .unwrap();
        Client::new(&sts_config(&self.mws, creds.credentials().unwrap()).await)
    }
}

#[allow(deprecated)] // AcceptInvitation and the master-account calls
async fn members_through_invitations_body() {
    let o = org().await;
    let admin = Client::new(&o.mws.root_sdk_config().await);
    admin.enable_security_hub().send().await.unwrap();
    let member_id = o.create_account("workload").await;
    let other_id = o.create_account("sandbox").await;
    let member = o.client_for(&member_id).await;
    let other = o.client_for(&other_id).await;
    member.enable_security_hub().send().await.unwrap();
    other.enable_security_hub().send().await.unwrap();

    let created = admin
        .create_members()
        .account_details(AccountDetails::builder().account_id(&member_id).email("workload@example.com").build())
        .account_details(AccountDetails::builder().account_id(&other_id).email("sandbox@example.com").build())
        .account_details(AccountDetails::builder().account_id("bad").build())
        .send()
        .await
        .unwrap();
    assert_eq!(created.unprocessed_accounts().len(), 1);
    let members = admin.list_members().only_associated(false).send().await.unwrap();
    assert_eq!(members.members().len(), 2);
    assert!(members.members().iter().all(|m| m.member_status() == Some("Created")));

    admin.invite_members().account_ids(&member_id).account_ids(&other_id).send().await.unwrap();
    let count = member.get_invitations_count().send().await.unwrap();
    assert_eq!(count.invitations_count(), Some(1));
    let invitations = member.list_invitations().send().await.unwrap();
    let inv = &invitations.invitations()[0];
    assert_eq!(inv.account_id(), Some(ACCOUNT));
    assert_eq!(inv.member_status(), Some("Pending"));
    let invitation_id = inv.invitation_id().unwrap().to_string();

    member
        .accept_administrator_invitation()
        .administrator_id(ACCOUNT)
        .invitation_id(&invitation_id)
        .send()
        .await
        .unwrap();
    let administrator = member.get_administrator_account().send().await.unwrap();
    assert_eq!(administrator.administrator().unwrap().account_id(), Some(ACCOUNT));
    assert_eq!(administrator.administrator().unwrap().member_status(), Some("Enabled"));
    let master = member.get_master_account().send().await.unwrap();
    assert_eq!(master.master().unwrap().account_id(), Some(ACCOUNT));

    // The administrator sees member findings.
    member
        .batch_import_findings()
        .findings(finding("member-1", &member_id, SeverityLabel::Medium, "member-bucket"))
        .send()
        .await
        .unwrap();
    let seen = admin
        .get_findings()
        .filters(AwsSecurityFindingFilters::builder().aws_account_id(eq(&member_id)).build())
        .send()
        .await
        .unwrap();
    assert_eq!(seen.findings().len(), 1);
    let got = admin.get_members().account_ids(&member_id).account_ids("000000000000").send().await.unwrap();
    assert_eq!(got.members()[0].member_status(), Some("Enabled"));
    assert_eq!(got.unprocessed_accounts()[0].account_id(), Some("000000000000"));
    let listed = admin.list_members().send().await.unwrap();
    assert_eq!(listed.members().len(), 1, "only associated members by default");

    // The other account declines; invited again, it deletes the invitation.
    let declined = other.decline_invitations().account_ids(ACCOUNT).send().await.unwrap();
    assert!(declined.unprocessed_accounts().is_empty());
    assert_eq!(other.get_invitations_count().send().await.unwrap().invitations_count(), Some(0));
    let nothing = other.decline_invitations().account_ids(ACCOUNT).send().await.unwrap();
    assert_eq!(nothing.unprocessed_accounts().len(), 1);
    admin
        .create_members()
        .account_details(AccountDetails::builder().account_id(&other_id).build())
        .send()
        .await
        .unwrap();
    admin.invite_members().account_ids(&other_id).send().await.unwrap();
    assert_eq!(other.get_invitations_count().send().await.unwrap().invitations_count(), Some(1));
    let deleted = other.delete_invitations().account_ids(ACCOUNT).send().await.unwrap();
    assert!(deleted.unprocessed_accounts().is_empty(), "{:?}", deleted.unprocessed_accounts());
    assert_eq!(other.get_invitations_count().send().await.unwrap().invitations_count(), Some(0));

    // The member leaves; the administrator re-invites, the member accepts
    // through the old API, and the administrator removes the member.
    member.disassociate_from_administrator_account().send().await.unwrap();
    let members = admin.get_members().account_ids(&member_id).send().await.unwrap();
    assert_eq!(members.members()[0].member_status(), Some("Resigned"));
    let no_admin = member.get_administrator_account().send().await.unwrap();
    assert!(no_admin.administrator().is_none());

    admin
        .create_members()
        .account_details(AccountDetails::builder().account_id(&member_id).build())
        .send()
        .await
        .unwrap();
    admin.invite_members().account_ids(&member_id).send().await.unwrap();
    let inv = member.list_invitations().send().await.unwrap();
    let invitation_id = inv.invitations()[0].invitation_id().unwrap().to_string();
    member.accept_invitation().master_id(ACCOUNT).invitation_id(&invitation_id).send().await.unwrap();
    member.disassociate_from_master_account().send().await.unwrap();
    admin
        .create_members()
        .account_details(AccountDetails::builder().account_id(&member_id).build())
        .send()
        .await
        .unwrap();
    admin.invite_members().account_ids(&member_id).send().await.unwrap();
    let inv = member.list_invitations().send().await.unwrap();
    let invitation_id = inv.invitations()[0].invitation_id().unwrap().to_string();
    member
        .accept_administrator_invitation()
        .administrator_id(ACCOUNT)
        .invitation_id(&invitation_id)
        .send()
        .await
        .unwrap();

    admin.disassociate_members().account_ids(&member_id).send().await.unwrap();
    let members = admin.get_members().account_ids(&member_id).send().await.unwrap();
    assert_eq!(members.members()[0].member_status(), Some("Removed"));
    let deleted = admin.delete_members().account_ids(&member_id).account_ids(&other_id).send().await.unwrap();
    assert!(deleted.unprocessed_accounts().is_empty(), "{:?}", deleted.unprocessed_accounts());
    assert!(admin.list_members().only_associated(false).send().await.unwrap().members().is_empty());
}

async fn organization_admin_and_central_configuration_body() {
    let o = org().await;
    let mgmt = Client::new(&o.mws.root_sdk_config().await);
    mgmt.enable_security_hub().send().await.unwrap();
    let secops_id = o.create_account("secops").await;
    let workload_id = o.create_account("workload").await;
    let secops = o.client_for(&secops_id).await;

    let not_member =
        mgmt.enable_organization_admin_account().admin_account_id("111111111111").send().await.unwrap_err();
    assert_eq!(not_member.code(), Some("InvalidInputException"), "{not_member:?}");
    mgmt.enable_organization_admin_account().admin_account_id(&secops_id).send().await.unwrap();
    let admins = mgmt.list_organization_admin_accounts().send().await.unwrap();
    assert_eq!(admins.admin_accounts()[0].account_id(), Some(secops_id.as_str()));
    assert_eq!(admins.admin_accounts()[0].status(), Some(&AdminStatus::Enabled));

    // Organizations sees the delegated administrator.
    let delegated =
        o.orgs.list_delegated_administrators().service_principal("securityhub.amazonaws.com").send().await.unwrap();
    assert_eq!(delegated.delegated_administrators()[0].id(), Some(secops_id.as_str()));

    // The delegated administrator auto-enables new organization accounts.
    let cfg = secops.describe_organization_configuration().send().await.unwrap();
    assert_eq!(cfg.auto_enable(), Some(false));
    secops
        .update_organization_configuration()
        .auto_enable(true)
        .auto_enable_standards(AutoEnableStandards::Default)
        .send()
        .await
        .unwrap();
    let created = secops
        .create_members()
        .account_details(AccountDetails::builder().account_id(&workload_id).build())
        .send()
        .await
        .unwrap();
    assert!(created.unprocessed_accounts().is_empty());
    let members = secops.list_members().send().await.unwrap();
    let workload = members.members().iter().find(|m| m.account_id() == Some(workload_id.as_str())).unwrap();
    assert_eq!(workload.member_status(), Some("Enabled"));
    let workload_client = o.client_for(&workload_id).await;
    workload_client.describe_hub().send().await.unwrap();

    // Central configuration needs a home Region aggregator.
    let central = OrganizationConfiguration::builder()
        .configuration_type(OrganizationConfigurationConfigurationType::Central)
        .build();
    let no_home = secops
        .update_organization_configuration()
        .auto_enable(false)
        .auto_enable_standards(AutoEnableStandards::None)
        .organization_configuration(central.clone())
        .send()
        .await
        .unwrap_err();
    assert_eq!(no_home.code(), Some("InvalidInputException"));
    secops.create_finding_aggregator().region_linking_mode("ALL_REGIONS").send().await.unwrap();
    secops
        .update_organization_configuration()
        .auto_enable(false)
        .auto_enable_standards(AutoEnableStandards::None)
        .organization_configuration(central)
        .send()
        .await
        .unwrap();
    let cfg = secops.describe_organization_configuration().send().await.unwrap();
    assert_eq!(
        cfg.organization_configuration().unwrap().configuration_type(),
        Some(&OrganizationConfigurationConfigurationType::Central)
    );

    let nist = format!("arn:aws:securityhub:{REGION}::standards/nist-800-53/v/5.0.0");
    let policy = Policy::SecurityHub(
        SecurityHubPolicy::builder()
            .service_enabled(true)
            .enabled_standard_identifiers(&nist)
            .security_controls_configuration(
                SecurityControlsConfiguration::builder().disabled_security_control_identifiers("ACM.1").build(),
            )
            .build(),
    );
    let created = secops
        .create_configuration_policy()
        .name("baseline")
        .description("NIST everywhere")
        .configuration_policy(policy.clone())
        .send()
        .await
        .unwrap();
    let policy_id = created.id().unwrap().to_string();
    let policy_arn = created.arn().unwrap().to_string();
    assert!(policy_arn.contains(":configuration-policy/"));
    secops
        .update_configuration_policy()
        .identifier(&policy_id)
        .description("NIST 800-53 everywhere")
        .send()
        .await
        .unwrap();
    let got = secops.get_configuration_policy().identifier(&policy_arn).send().await.unwrap();
    assert_eq!(got.description(), Some("NIST 800-53 everywhere"));
    let listed = secops.list_configuration_policies().send().await.unwrap();
    assert_eq!(listed.configuration_policy_summaries().len(), 1);

    let assoc = secops
        .start_configuration_policy_association()
        .configuration_policy_identifier(&policy_id)
        .target(Target::AccountId(workload_id.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(assoc.association_status(), Some(&ConfigurationPolicyAssociationStatus::Success));
    let got = secops
        .get_configuration_policy_association()
        .target(Target::AccountId(workload_id.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(got.configuration_policy_id(), Some(policy_id.as_str()));
    assert_eq!(got.association_type(), Some(&AssociationType::Applied));
    let batch = secops
        .batch_get_configuration_policy_associations()
        .configuration_policy_association_identifiers(
            ConfigurationPolicyAssociation::builder().target(Target::AccountId(workload_id.clone())).build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(batch.configuration_policy_associations().len(), 1);
    let listed = secops.list_configuration_policy_associations().send().await.unwrap();
    assert!(listed.configuration_policy_association_summaries().iter().any(|a| a.target_id()
        == Some(workload_id.as_str())
        && a.configuration_policy_id() == Some(policy_id.as_str())));

    // The policy took effect in the workload account.
    let enabled = workload_client.get_enabled_standards().send().await.unwrap();
    let on: Vec<_> = enabled.standards_subscriptions().iter().filter_map(|s| s.standards_arn()).collect();
    assert_eq!(on, [nist.as_str()]);

    let in_use = secops.delete_configuration_policy().identifier(&policy_id).send().await.unwrap_err();
    assert!(in_use.code().is_some());
    secops
        .start_configuration_policy_disassociation()
        .configuration_policy_identifier(&policy_id)
        .target(Target::AccountId(workload_id.clone()))
        .send()
        .await
        .unwrap();
    secops.delete_configuration_policy().identifier(&policy_id).send().await.unwrap();

    mgmt.disable_organization_admin_account().admin_account_id(&secops_id).send().await.unwrap();
    assert!(mgmt.list_organization_admin_accounts().send().await.unwrap().admin_accounts().is_empty());
}

async fn v2_findings_resources_software_and_exports_body() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sh = hub(&mws).await;

    let not_v2 = sh.describe_security_hub_v2().send().await.unwrap_err();
    assert_eq!(not_v2.code(), Some("ResourceNotFoundException"));
    let enabled = sh.enable_security_hub_v2().tags("env", "test").send().await.unwrap();
    let hub_v2_arn = enabled.hub_v2_arn().unwrap().to_string();
    assert_eq!(hub_v2_arn, format!("arn:aws:securityhub:{REGION}:{ACCOUNT}:hubv2/default"));
    sh.enable_security_hub_feature_v2().feature_name(FeatureName::NetworkScanning).send().await.unwrap();
    let d = sh.describe_security_hub_v2().send().await.unwrap();
    assert_eq!(d.hub_v2_arn(), Some(hub_v2_arn.as_str()));
    assert!(d.subscribed_at().is_some());
    sh.disable_security_hub_feature_v2().feature_name(FeatureName::NetworkScanning).send().await.unwrap();

    let trials = sh.list_free_trial_statuses_v2().send().await.unwrap();
    let trial = &trials.account_free_trial_statuses()[0];
    assert_eq!(trial.account_id(), Some(ACCOUNT));
    assert_eq!(trial.free_trial_statuses()[0].status(), Some(&FreeTrialStatusValue::Active));
    let products = sh.describe_products_v2().send().await.unwrap();
    assert!(products.products_v2().iter().any(|p| p.product_v2_name() == Some("GuardDuty")));

    sh.batch_import_findings()
        .findings(finding("v2-1", ACCOUNT, SeverityLabel::High, "payments-data"))
        .findings(finding("v2-2", ACCOUNT, SeverityLabel::Low, "public-assets"))
        .send()
        .await
        .unwrap();

    // OCSF findings.
    let high = OcsfFindingFilters::builder()
        .composite_filters(
            CompositeFilter::builder()
                .string_filters(
                    OcsfStringFilter::builder()
                        .field_name(OcsfStringField::FindingInfoTitle)
                        .filter(eq("Finding v2-1"))
                        .build(),
                )
                .build(),
        )
        .build();
    let found = sh.get_findings_v2().filters(high.clone()).send().await.unwrap();
    assert_eq!(found.findings().len(), 1);
    let doc: serde_json::Value = doc_json(&found.findings()[0]);
    assert_eq!(doc["finding_info"]["uid"], "v2-1");
    assert_eq!(doc["cloud"]["account"]["uid"], ACCOUNT);
    assert_eq!(doc["severity"], "High");
    let metadata_uid = doc["metadata"]["uid"].as_str().unwrap().to_string();

    let updated = sh
        .batch_update_findings_v2()
        .metadata_uids(&metadata_uid)
        .metadata_uids("nope")
        .finding_identifiers(
            OcsfFindingIdentifier::builder()
                .cloud_account_uid(ACCOUNT)
                .finding_info_uid("v2-2")
                .metadata_product_uid(default_product(ACCOUNT))
                .build(),
        )
        .status_id(2)
        .comment("Investigating")
        .send()
        .await
        .unwrap();
    assert_eq!(updated.processed_findings().len(), 2);
    assert_eq!(updated.unprocessed_findings().len(), 1);
    let found = sh.get_findings_v2().filters(high).send().await.unwrap();
    let doc: serde_json::Value = doc_json(&found.findings()[0]);
    assert_eq!(doc["status_id"], 2);
    assert_eq!(doc["comment"], "Investigating");

    let stats = sh
        .get_finding_statistics_v2()
        .group_by_rules(GroupByRule::builder().group_by_field(GroupByField::Severity).build())
        .send()
        .await
        .unwrap();
    let values = stats.group_by_results()[0].group_by_values();
    assert_eq!(values.len(), 2);
    assert!(values.iter().all(|v| v.count() == Some(1)));

    let now = aws_sdk_securityhub::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() + 60);
    let week_ago = aws_sdk_securityhub::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() - 7 * 86400);
    let trends = sh.get_findings_trends_v2().start_time(week_ago).end_time(now).send().await.unwrap();
    assert_eq!(trends.granularity(), Some(&GranularityField::Daily));
    let last = trends.trends_metrics().last().unwrap();
    let sev = last.trends_values().unwrap().severity_trends().unwrap();
    assert_eq!((sev.high(), sev.low()), (Some(1), Some(1)));

    // Resources and software derived from the findings.
    let resources = sh.get_resources_v2().send().await.unwrap();
    assert_eq!(resources.resources().len(), 2);
    let bucket = resources.resources().iter().find(|r| r.resource_id() == Some("arn:aws:s3:::payments-data")).unwrap();
    assert_eq!(bucket.resource_type(), Some("AwsS3Bucket"));
    assert_eq!(bucket.findings_summary()[0].total_findings(), Some(1));
    let by_type = sh
        .get_resources_statistics_v2()
        .group_by_rules(ResourceGroupByRule::builder().group_by_field(ResourceGroupByField::ResourceType).build())
        .send()
        .await
        .unwrap();
    assert_eq!(by_type.group_by_results()[0].group_by_values()[0].count(), Some(2));
    let rtrends = sh.get_resources_trends_v2().start_time(week_ago).end_time(now).send().await.unwrap();
    assert_eq!(
        rtrends.trends_metrics().last().unwrap().trends_values().unwrap().resources_count().unwrap().all_resources(),
        Some(2)
    );

    let software = sh.get_software_v2().send().await.unwrap();
    assert_eq!(software.software()[0].package_name(), Some("openssl"));
    assert_eq!(software.software()[0].resource_count(), Some(2));
    let on = sh.get_software_resources_v2().package_name("openssl").package_type("OS").send().await.unwrap();
    assert_eq!(on.software_resources().len(), 2);
    let sstats = sh
        .get_software_statistics_v2()
        .group_by_rules(SoftwareGroupByRule::builder().group_by_field(SoftwareGroupByField::PackageVersion).build())
        .send()
        .await
        .unwrap();
    assert_eq!(sstats.group_by_results()[0].group_by_values()[0].field_value(), Some("1.1.1k"));

    // Remediation analysis has nothing for these findings.
    let rem = sh.get_remediations_v2().send().await.unwrap();
    assert!(rem.items().is_empty());
    let exposures = sh.list_exposures_by_remediation_v2().target_uid("nothing").send().await.unwrap_err();
    assert_eq!(exposures.code(), Some("ResourceNotFoundException"));
    sh.generate_recommended_policy_v2().metadata_uid(&metadata_uid).send().await.unwrap();
    let rec = sh.get_recommended_policy_v2().metadata_uid(&metadata_uid).send().await.unwrap();
    assert_eq!(rec.status(), Some(&RecommendationStatus::Failed));

    // Exports to S3, encrypted with a KMS key Security Hub may use.
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("sh-exports").send().await.unwrap();
    let bucket_policy = serde_json::json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"Service":"securityhub.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::sh-exports/*"}]});
    s3.put_bucket_policy().bucket("sh-exports").policy(bucket_policy.to_string()).send().await.unwrap();
    let kms = aws_sdk_kms::Client::new(&cfg);
    let key = kms.create_key().send().await.unwrap().key_metadata.unwrap().arn.unwrap();
    let key_policy = serde_json::json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:root")},"Action":"kms:*","Resource":"*"},
        {"Effect":"Allow","Principal":{"Service":"securityhub.amazonaws.com"},"Action":"kms:GenerateDataKey","Resource":"*"}]});
    kms.put_key_policy().key_id(&key).policy(key_policy.to_string()).send().await.unwrap();

    let job = sh
        .start_export_job_v2()
        .name("weekly")
        .destination(ExportDestination::S3(
            S3ExportDestination::builder()
                .bucket_arn("arn:aws:s3:::sh-exports")
                .kms_key_arn(&key)
                .object_prefix("exports")
                .build(),
        ))
        .output_configuration(ExportOutput::Findings(
            FindingsOutput::builder().format(FindingsExportFormat::OcsfJson).build(),
        ))
        .send()
        .await
        .unwrap();
    let job_id = job.export_job_id().unwrap().to_string();
    let got = sh.get_export_job_v2().export_job_id(&job_id).send().await.unwrap();
    assert_eq!(got.status(), Some(&ExportStatus::Succeeded), "{got:?}");
    let objects = s3.list_objects_v2().bucket("sh-exports").prefix("exports/").send().await.unwrap();
    let key_name = objects.contents()[0].key().unwrap().to_string();
    let object = s3.get_object().bucket("sh-exports").key(&key_name).send().await.unwrap();
    assert_eq!(object.server_side_encryption(), Some(&aws_sdk_s3::types::ServerSideEncryption::AwsKms));
    let body: serde_json::Value = serde_json::from_slice(&object.body.collect().await.unwrap().into_bytes()).unwrap();
    assert_eq!(body.as_array().unwrap().len(), 2);

    let failed = sh
        .start_export_job_v2()
        .destination(ExportDestination::S3(
            S3ExportDestination::builder().bucket_arn("arn:aws:s3:::no-such-bucket").kms_key_arn(&key).build(),
        ))
        .output_configuration(ExportOutput::Findings(
            FindingsOutput::builder().format(FindingsExportFormat::OcsfJson).build(),
        ))
        .send()
        .await
        .unwrap();
    let got = sh.get_export_job_v2().export_job_id(failed.export_job_id().unwrap()).send().await.unwrap();
    assert_eq!(got.status(), Some(&ExportStatus::Failed));
    let jobs = sh.list_export_jobs_v2().send().await.unwrap();
    assert_eq!(jobs.items().len(), 2);
    let done = sh.cancel_export_job_v2().export_job_id(&job_id).send().await.unwrap_err();
    assert_eq!(done.code(), Some("ConflictException"));

    sh.disable_security_hub_v2().send().await.unwrap();
    let gone = sh.get_findings_v2().send().await.unwrap_err();
    assert_eq!(gone.code(), Some("AccessDeniedException"));
}

async fn v2_aggregators_automation_rules_and_connectors_body() {
    let mws = Mws::start().await;
    let sh = hub(&mws).await;
    sh.enable_security_hub_v2().send().await.unwrap();

    let agg = sh
        .create_aggregator_v2()
        .region_linking_mode("SPECIFIED_REGIONS")
        .linked_regions("us-west-2")
        .send()
        .await
        .unwrap();
    let agg_arn = agg.aggregator_v2_arn().unwrap().to_string();
    assert!(agg_arn.contains(":aggregatorv2/"));
    sh.update_aggregator_v2().aggregator_v2_arn(&agg_arn).region_linking_mode("ALL_REGIONS").send().await.unwrap();
    let got = sh.get_aggregator_v2().aggregator_v2_arn(&agg_arn).send().await.unwrap();
    assert_eq!(got.region_linking_mode(), Some("ALL_REGIONS"));
    assert_eq!(sh.list_aggregators_v2().send().await.unwrap().aggregators_v2().len(), 1);
    sh.delete_aggregator_v2().aggregator_v2_arn(&agg_arn).send().await.unwrap();
    assert!(sh.list_aggregators_v2().send().await.unwrap().aggregators_v2().is_empty());

    // A V2 rule lowers the severity of findings on public buckets.
    let criteria = Criteria::OcsfFindingCriteria(
        OcsfFindingFilters::builder()
            .composite_filters(
                CompositeFilter::builder()
                    .string_filters(
                        OcsfStringFilter::builder()
                            .field_name(OcsfStringField::ResourcesUid)
                            .filter(
                                StringFilter::builder()
                                    .value("public")
                                    .comparison(StringFilterComparison::Contains)
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .build(),
    );
    let rule = sh
        .create_automation_rule_v2()
        .rule_name("lower-public")
        .description("Public buckets are expected")
        .rule_order(1.0)
        .criteria(criteria)
        .actions(
            AutomationRulesActionV2::builder()
                .r#type(AutomationRulesActionTypeV2::FindingFieldsUpdate)
                .finding_fields_update(
                    AutomationRulesFindingFieldsUpdateV2::builder().severity_id(1).comment("expected").build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let rule_id = rule.rule_id().unwrap().to_string();
    sh.update_automation_rule_v2()
        .identifier(&rule_id)
        .description("Public buckets are by design")
        .send()
        .await
        .unwrap();
    let got = sh.get_automation_rule_v2().identifier(&rule_id).send().await.unwrap();
    assert_eq!(got.description(), Some("Public buckets are by design"));
    assert_eq!(sh.list_automation_rules_v2().send().await.unwrap().rules().len(), 1);

    sh.batch_import_findings()
        .findings(finding("pub", ACCOUNT, SeverityLabel::High, "public-site"))
        .send()
        .await
        .unwrap();
    let found = sh.get_findings_v2().send().await.unwrap();
    let doc: serde_json::Value = doc_json(&found.findings()[0]);
    assert_eq!(doc["severity_id"], 1);
    let metadata_uid = doc["metadata"]["uid"].as_str().unwrap().to_string();
    sh.delete_automation_rule_v2().identifier(&rule_id).send().await.unwrap();
    assert!(sh.list_automation_rules_v2().send().await.unwrap().rules().is_empty());

    // Jira Cloud connectors authorize through OAuth, then create tickets.
    let jira = sh
        .create_connector_v2()
        .name("jira")
        .description("Security tickets")
        .provider(ProviderConfiguration::JiraCloud(
            JiraCloudProviderConfiguration::builder().project_key("SEC").build(),
        ))
        .send()
        .await
        .unwrap();
    let jira_id = jira.connector_id().unwrap().to_string();
    let auth_url = jira.auth_url().unwrap();
    let state = auth_url.split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let not_yet =
        sh.create_ticket_v2().connector_id(&jira_id).finding_metadata_uid(&metadata_uid).send().await.unwrap_err();
    assert_eq!(not_yet.code(), Some("ConflictException"));
    let registered =
        sh.register_connector_v2().auth_code("code-from-atlassian").auth_state(&state).send().await.unwrap();
    assert_eq!(registered.connector_id(), Some(jira_id.as_str()));
    let ticket = sh.create_ticket_v2().connector_id(&jira_id).finding_metadata_uid(&metadata_uid).send().await.unwrap();
    assert!(ticket.ticket_id().unwrap().starts_with("SEC-"));
    sh.update_connector_v2().connector_id(&jira_id).description("SecOps tickets").send().await.unwrap();
    let got = sh.get_connector_v2().connector_id(&jira_id).send().await.unwrap();
    assert_eq!(got.description(), Some("SecOps tickets"));
    assert_eq!(sh.list_connectors_v2().send().await.unwrap().connectors().len(), 1);
    sh.delete_connector_v2().connector_id(&jira_id).send().await.unwrap();
    let gone = sh.get_connector_v2().connector_id(&jira_id).send().await.unwrap_err();
    assert_eq!(gone.code(), Some("ResourceNotFoundException"));

    // CSPM connectors to Azure (the V1 connector API).
    let azure = AzureProviderConfiguration::builder()
        .aws_config_connector_arn(format!("arn:aws:config:{REGION}:{ACCOUNT}:connector/azure-1"))
        .scope_configuration(
            AzureScopeConfiguration::builder().scope_type(ScopeType::Subscription).scope_values("sub-1").build(),
        )
        .azure_regions("eastus")
        .build();
    let created =
        sh.create_connector().name("azure").provider(CspmProviderConfiguration::Azure(azure)).send().await.unwrap();
    let azure_id = created.connector_id().unwrap().to_string();
    sh.update_connector().connector_id(&azure_id).description("Azure subscriptions").send().await.unwrap();
    let got = sh.get_connector().connector_id(&azure_id).send().await.unwrap();
    assert_eq!(got.description(), Some("Azure subscriptions"));
    assert_eq!(sh.list_connectors().send().await.unwrap().connectors().len(), 1);
    sh.delete_connector().connector_id(&azure_id).send().await.unwrap();
    assert!(sh.list_connectors().send().await.unwrap().connectors().is_empty());
}

#[test]
fn hub_lifecycle_products_action_targets_and_tags() {
    big_stack(hub_lifecycle_products_action_targets_and_tags_body());
}

#[test]
fn standards_and_controls() {
    big_stack(standards_and_controls_body());
}

#[test]
fn findings_import_filters_workflow_history_and_events() {
    big_stack(findings_import_filters_workflow_history_and_events_body());
}

#[test]
fn insights_and_automation_rules() {
    big_stack(insights_and_automation_rules_body());
}

#[test]
fn members_through_invitations() {
    big_stack(members_through_invitations_body());
}

#[test]
fn organization_admin_and_central_configuration() {
    big_stack(organization_admin_and_central_configuration_body());
}

#[test]
fn v2_findings_resources_software_and_exports() {
    big_stack(v2_findings_resources_software_and_exports_body());
}

#[test]
fn v2_aggregators_automation_rules_and_connectors() {
    big_stack(v2_aggregators_automation_rules_and_connectors_body());
}
