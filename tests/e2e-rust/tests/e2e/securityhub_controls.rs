//! Security Hub's security controls through the official Rust SDK: the
//! full control catalogue, the service-linked role `EnableSecurityHub`
//! creates, and control findings that evaluate the emulated services and
//! follow the resources as they change.

use aws_sdk_securityhub::error::ProvideErrorMetadata;
use aws_sdk_securityhub::types::*;
use aws_sdk_securityhub::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";
const CIS12: &str = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0";

/// Run a test on a thread with a large stack: the SDK's `AwsSecurityFinding`
/// deserializer needs more than a test thread's 2 MiB in debug builds.
fn on_big_stack<F: std::future::Future<Output = ()> + 'static>(test: fn() -> F) {
    let thread = std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test()))
        .unwrap();
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

fn eq(v: &str) -> StringFilter {
    StringFilter::builder().value(v).comparison(StringFilterComparison::Equals).build()
}

async fn control_findings(sh: &Client, control: &str, resource: Option<&str>) -> Vec<AwsSecurityFinding> {
    let mut f = AwsSecurityFindingFilters::builder()
        .generator_id(eq(&format!("security-control/{control}")))
        .record_state(eq("ACTIVE"));
    if let Some(r) = resource {
        f = f.resource_id(eq(r));
    }
    sh.get_findings().filters(f.build()).send().await.unwrap().findings().to_vec()
}

#[test]
fn catalogue_lists_the_real_controls() {
    on_big_stack(catalogue_lists_the_real_controls_test)
}

async fn catalogue_lists_the_real_controls_test() {
    let mws = Mws::start().await;
    let sh = Client::new(&mws.root_sdk_config().await);
    sh.enable_security_hub().enable_default_standards(false).send().await.unwrap();

    let got = sh
        .batch_get_security_controls()
        .security_control_ids("S3.2")
        .security_control_ids("EC2.3")
        .security_control_ids("RDS.2")
        .security_control_ids("DynamoDB.1")
        .send()
        .await
        .unwrap();
    assert!(got.unprocessed_ids().is_empty(), "{:?}", got.unprocessed_ids());
    let by_id = |id: &str| got.security_controls().iter().find(|c| c.security_control_id() == Some(id)).unwrap();
    assert_eq!(by_id("S3.2").title(), Some("S3 general purpose buckets should block public read access"));
    assert_eq!(by_id("S3.2").severity_rating(), Some(&SeverityRating::Critical));
    assert_eq!(
        by_id("S3.2").remediation_url(),
        Some("https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2")
    );
    assert_eq!(by_id("EC2.3").title(), Some("Attached Amazon EBS volumes should be encrypted at-rest"));
    assert_eq!(by_id("RDS.2").severity_rating(), Some(&SeverityRating::Critical));
    assert_eq!(by_id("DynamoDB.1").title(), Some("DynamoDB tables should automatically scale capacity with demand"));
    assert_eq!(
        by_id("DynamoDB.1").remediation_url(),
        Some("https://docs.aws.amazon.com/securityhub/latest/userguide/dynamodb-controls.html#dynamodb-1")
    );

    // FSBP in full: every page of its controls.
    let fsbp = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0";
    let mut ids = Vec::new();
    let mut token = None;
    loop {
        let page =
            sh.list_security_control_definitions().standards_arn(fsbp).set_next_token(token).send().await.unwrap();
        ids.extend(
            page.security_control_definitions().iter().map(|d| d.security_control_id().unwrap_or_default().to_string()),
        );
        token = page.next_token().map(str::to_string);
        if token.is_none() {
            break;
        }
    }
    assert!(ids.len() >= 250, "{} FSBP controls", ids.len());
    for id in ["S3.2", "EC2.3", "RDS.2", "DynamoDB.1", "Lambda.1", "GuardDuty.1"] {
        assert!(ids.iter().any(|x| x == id), "{id} missing from FSBP");
    }
    let def = sh.get_security_control_definition().security_control_id("EC2.19").send().await.unwrap();
    assert_eq!(def.security_control_definition().unwrap().severity_rating(), Some(&SeverityRating::Critical));
}

#[test]
fn enabling_creates_the_service_linked_role() {
    on_big_stack(enabling_creates_the_service_linked_role_test)
}

async fn enabling_creates_the_service_linked_role_test() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&root);
    let only_hub =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"securityhub:*","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "hub-only", Some(only_hub)).await;
    let sh = Client::new(&cfg);

    // Without iam:CreateServiceLinkedRole, enabling is refused.
    let err = sh.enable_security_hub().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"), "{err:?}");
    assert!(err.message().unwrap_or_default().contains("iam:CreateServiceLinkedRole"), "{err:?}");
    assert!(iam.get_role().role_name("AWSServiceRoleForSecurityHub").send().await.is_err());
    assert_eq!(
        sh.describe_hub().send().await.unwrap_err().code(),
        Some("InvalidAccessException"),
        "nothing was enabled"
    );

    // With it, the role is created.
    let allowed = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"securityhub:*","Resource":"*"},
        {"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"*",
         "Condition":{"StringEquals":{"iam:AWSServiceName":"securityhub.amazonaws.com"}}}]}"#;
    let (_, cfg) = user_with_policy(&mws, "hub-admin", Some(allowed)).await;
    Client::new(&cfg).enable_security_hub().enable_default_standards(false).send().await.unwrap();
    let role = iam.get_role().role_name("AWSServiceRoleForSecurityHub").send().await.unwrap();
    let role = role.role().unwrap();
    assert_eq!(role.path(), "/aws-service-role/securityhub.amazonaws.com/");
    assert_eq!(
        role.arn(),
        format!("arn:aws:iam::{ACCOUNT}:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub")
    );

    // Once the role exists, securityhub:* is enough.
    sh.disable_security_hub().send().await.unwrap();
    sh.enable_security_hub().enable_default_standards(false).send().await.unwrap();
}

#[test]
fn control_findings_follow_the_resources() {
    on_big_stack(control_findings_follow_the_resources_test)
}

async fn control_findings_follow_the_resources_test() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sh = Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let key_arn = kms.create_key().send().await.unwrap().key_metadata().unwrap().arn().unwrap().to_string();

    // Default standards: FSBP and CIS 1.2.0. KMS.4 (CIS 2.8) checks the key.
    sh.enable_security_hub().send().await.unwrap();
    let found = control_findings(&sh, "KMS.4", Some(&key_arn)).await;
    assert_eq!(found.len(), 1, "{found:?}");
    let f = &found[0];
    assert_eq!(f.product_name(), Some("Security Hub"));
    assert_eq!(f.company_name(), Some("AWS"));
    assert_eq!(f.product_arn(), Some("arn:aws:securityhub:us-east-1::product/aws/securityhub"));
    assert!(f
        .id()
        .unwrap()
        .starts_with(&format!("arn:aws:securityhub:us-east-1:{ACCOUNT}:security-control/KMS.4/finding/")));
    assert_eq!(f.title(), Some("AWS KMS key rotation should be enabled"));
    assert_eq!(f.resources()[0].r#type(), Some("AwsKmsKey"));
    let compliance = f.compliance().unwrap();
    assert_eq!(compliance.status(), Some(&ComplianceStatus::Failed));
    assert_eq!(compliance.security_control_id(), Some("KMS.4"));
    assert!(compliance
        .associated_standards()
        .iter()
        .any(|s| s.standards_id() == Some("ruleset/cis-aws-foundations-benchmark/v/1.2.0")));
    assert!(compliance.related_requirements().iter().any(|r| r == "CIS AWS Foundations 2.8"));
    assert_eq!(f.severity().unwrap().label(), Some(&SeverityLabel::Medium));
    let pf = f.product_fields().unwrap();
    assert_eq!(pf.get("RelatedAWSResources:0/type").map(String::as_str), Some("AWS::Config::ConfigRule"));
    assert!(pf.get("aws/securityhub/FindingId").is_some());
    let finding_id = f.id().unwrap().to_string();

    // Account-level checks: no CloudTrail trail.
    let trail = control_findings(&sh, "CloudTrail.1", Some(&format!("AWS::::Account:{ACCOUNT}"))).await;
    assert_eq!(trail[0].compliance().unwrap().status(), Some(&ComplianceStatus::Failed));

    // Filtering by compliance status.
    let failed = sh
        .get_findings()
        .filters(
            AwsSecurityFindingFilters::builder()
                .compliance_status(eq("FAILED"))
                .compliance_security_control_id(eq("KMS.4"))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(failed.findings().len(), 1);

    // Fix the key: the same finding passes (and is resolved).
    kms.enable_key_rotation().key_id(&key_arn).send().await.unwrap();
    let found = control_findings(&sh, "KMS.4", Some(&key_arn)).await;
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!(f.id(), Some(finding_id.as_str()));
    assert_eq!(f.compliance().unwrap().status(), Some(&ComplianceStatus::Passed));
    assert_eq!(f.severity().unwrap().label(), Some(&SeverityLabel::Informational));
    assert_eq!(f.severity().unwrap().original(), Some("MEDIUM"));
    assert_eq!(f.workflow().unwrap().status(), Some(&WorkflowStatus::Resolved));

    // Disabling the control in the only standard that has it archives its findings.
    let out = sh
        .batch_update_standards_control_associations()
        .standards_control_association_updates(
            StandardsControlAssociationUpdate::builder()
                .standards_arn(CIS12)
                .security_control_id("KMS.4")
                .association_status(AssociationStatus::Disabled)
                .updated_reason("not used here")
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(out.unprocessed_association_updates().is_empty());
    assert!(control_findings(&sh, "KMS.4", None).await.is_empty());
    let archived = sh
        .get_findings()
        .filters(AwsSecurityFindingFilters::builder().id(eq(&finding_id)).record_state(eq("ARCHIVED")).build())
        .send()
        .await
        .unwrap();
    assert_eq!(archived.findings().len(), 1);

    // With per-standard findings (the older generator), IDs follow the standard.
    sh.update_security_hub_configuration()
        .control_finding_generator(ControlFindingGenerator::StandardControl)
        .send()
        .await
        .unwrap();
    let legacy = sh
        .get_findings()
        .filters(
            AwsSecurityFindingFilters::builder()
                .generator_id(eq(&format!("{CIS12}/rule/2.1")))
                .record_state(eq("ACTIVE"))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(legacy.findings().len(), 1, "CloudTrail.1 as CIS 2.1");
    assert_eq!(legacy.findings()[0].title(), Some("2.1 CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events"));
    assert!(control_findings(&sh, "CloudTrail.1", None).await.is_empty(), "consolidated findings archived");
}

#[test]
fn checks_rerun_periodically_and_on_changes() {
    on_big_stack(checks_rerun_periodically_and_on_changes_test)
}

async fn checks_rerun_periodically_and_on_changes_test() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sh = Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    sh.enable_security_hub().send().await.unwrap();
    let url = sqs
        .create_queue()
        .queue_name("plain")
        .attributes(aws_sdk_sqs::types::QueueAttributeName::SqsManagedSseEnabled, "false")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:plain");
    let found = control_findings(&sh, "SQS.1", Some(&arn)).await;
    assert_eq!(found[0].compliance().unwrap().status(), Some(&ComplianceStatus::Failed));
    let updated = found[0].updated_at().unwrap().to_string();

    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::SqsManagedSseEnabled, "true")
        .send()
        .await
        .unwrap();
    let found = control_findings(&sh, "SQS.1", Some(&arn)).await;
    assert_eq!(found[0].compliance().unwrap().status(), Some(&ComplianceStatus::Passed));

    // Unchanged results are refreshed by the periodic check (12 hours).
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 43300}"#)).await;
    assert_eq!(status, 200);
    let found = control_findings(&sh, "SQS.1", Some(&arn)).await;
    assert_ne!(found[0].updated_at().unwrap(), updated);
    assert_eq!(found[0].compliance().unwrap().status(), Some(&ComplianceStatus::Passed));
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"offsetSeconds": 0}"#)).await;
    assert_eq!(status, 200);

    // Deleting the queue archives its finding.
    sqs.delete_queue().queue_url(&url).send().await.unwrap();
    assert!(control_findings(&sh, "SQS.1", Some(&arn)).await.is_empty());
}
