#![allow(deprecated)]
//! Amazon GuardDuty through the official Rust SDK: detectors and features,
//! sample findings (queried with finding criteria, archived, suppressed by
//! filters) delivered to EventBridge and exported to S3 under KMS, threat
//! lists, member accounts by invitation and through an Organizations
//! delegated administrator, malware protection, custom detection rules,
//! investigations and IAM enforcement.

use std::time::{Duration, Instant};

use aws_sdk_guardduty::error::ProvideErrorMetadata;
use aws_sdk_guardduty::types::{
    AccountDetail, AutoEnableMembers, Condition, CoverageStatisticsType, CreateProtectedResource,
    CreateS3BucketResource, DataSourceConfigurations, DestinationProperties, DestinationType, DetectorFeature,
    DetectorFeatureConfiguration, FeatureStatus, Feedback, FilterAction, FindingCriteria, FindingStatisticType,
    GroupByType, IpSetFormat, OrderBy, OrgFeature, OrgFeatureStatus, OrganizationFeatureConfiguration,
    S3LogsConfiguration, S3ObjectForSendObjectMalwareScan, SortCriteria, ThreatEntitySetFormat, ThreatIntelSetFormat,
    TrustedEntitySetFormat, UsageCriteria, UsageStatisticType,
};
use aws_sdk_guardduty::Client;
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::{sts_config, user_with_policy, Mws};
use serde_json::{json, Value};

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message<E: ProvideErrorMetadata>(e: &E) -> String {
    e.message().unwrap_or_default().to_string()
}

async fn detector(gd: &Client) -> String {
    gd.create_detector().enable(true).send().await.unwrap().detector_id().unwrap().to_string()
}

fn eq(key: &str, values: &[&str]) -> FindingCriteria {
    let mut c = Condition::builder();
    for v in values {
        c = c.equals(*v);
    }
    FindingCriteria::builder().criterion(key, c.build()).build()
}

/// `aws.guardduty` events from the default bus, delivered to SQS.
struct Inbox {
    sqs: aws_sdk_sqs::Client,
    url: String,
}

impl Inbox {
    async fn new(cfg: &aws_config::SdkConfig, name: &str) -> Self {
        let eb = aws_sdk_eventbridge::Client::new(cfg);
        let sqs = aws_sdk_sqs::Client::new(cfg);
        let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url.unwrap();
        let attrs = sqs
            .get_queue_attributes()
            .queue_url(&url)
            .attribute_names(QueueAttributeName::QueueArn)
            .send()
            .await
            .unwrap();
        let arn = attrs.attributes().unwrap()[&QueueAttributeName::QueueArn].clone();
        let policy = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":arn}]});
        sqs.set_queue_attributes()
            .queue_url(&url)
            .attributes(QueueAttributeName::Policy, policy.to_string())
            .send()
            .await
            .unwrap();
        eb.put_rule().name(name).event_pattern(r#"{"source":["aws.guardduty"]}"#).send().await.unwrap();
        eb.put_targets()
            .rule(name)
            .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(&arn).build().unwrap())
            .send()
            .await
            .unwrap();
        Inbox { sqs, url }
    }

    /// Every event that arrives within `wait`.
    async fn drain(&self, wait: Duration) -> Vec<Value> {
        let deadline = Instant::now() + wait;
        let mut out = Vec::new();
        while Instant::now() < deadline {
            let r = self.sqs.receive_message().queue_url(&self.url).max_number_of_messages(10).send().await.unwrap();
            if r.messages().is_empty() {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            for m in r.messages() {
                self.sqs
                    .delete_message()
                    .queue_url(&self.url)
                    .receipt_handle(m.receipt_handle().unwrap())
                    .send()
                    .await
                    .unwrap();
                out.push(serde_json::from_str(m.body().unwrap()).unwrap());
            }
        }
        out
    }
}

#[tokio::test]
async fn detector_lifecycle_features_and_tags() {
    let mws = Mws::start().await;
    let gd = Client::new(&mws.root_sdk_config().await);

    let id = gd
        .create_detector()
        .enable(true)
        .finding_publishing_frequency(aws_sdk_guardduty::types::FindingPublishingFrequency::FifteenMinutes)
        .features(
            DetectorFeatureConfiguration::builder()
                .name(DetectorFeature::RuntimeMonitoring)
                .status(FeatureStatus::Enabled)
                .build(),
        )
        .tags("team", "sec")
        .send()
        .await
        .unwrap()
        .detector_id()
        .unwrap()
        .to_string();
    assert_eq!(id.len(), 32);
    let again = gd.create_detector().enable(true).send().await.unwrap_err();
    assert_eq!(code(&again), "BadRequestException");
    assert_eq!(message(&again), "The request is rejected because a detector already exists for the current account.");
    let both = gd
        .create_detector()
        .enable(true)
        .data_sources(
            DataSourceConfigurations::builder().s3_logs(S3LogsConfiguration::builder().enable(true).build()).build(),
        )
        .features(DetectorFeatureConfiguration::builder().name(DetectorFeature::S3DataEvents).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&both), "BadRequestException");

    let d = gd.get_detector().detector_id(&id).send().await.unwrap();
    assert_eq!(d.status().unwrap().as_str(), "ENABLED");
    assert_eq!(d.finding_publishing_frequency().unwrap().as_str(), "FIFTEEN_MINUTES");
    assert!(d
        .service_role()
        .unwrap()
        .ends_with("role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"));
    assert_eq!(d.tags().unwrap()["team"], "sec");
    let feature = |d: &aws_sdk_guardduty::operation::get_detector::GetDetectorOutput, n: &str| {
        d.features()
            .iter()
            .find(|f| f.name().map(|x| x.as_str()) == Some(n))
            .unwrap()
            .status()
            .unwrap()
            .as_str()
            .to_string()
    };
    assert_eq!(feature(&d, "RUNTIME_MONITORING"), "ENABLED");
    assert_eq!(feature(&d, "CLOUD_TRAIL"), "ENABLED");
    assert_eq!(feature(&d, "S3_DATA_EVENTS"), "ENABLED");
    assert_eq!(feature(&d, "EKS_RUNTIME_MONITORING"), "DISABLED");
    assert_eq!(d.data_sources().unwrap().s3_logs().unwrap().status().unwrap().as_str(), "ENABLED");

    let missing = gd.get_detector().detector_id("0123456789abcdef0123456789abcdef").send().await.unwrap_err();
    assert_eq!(code(&missing), "BadRequestException");
    assert_eq!(
        message(&missing),
        "The request is rejected because the input detectorId is not owned by the current account."
    );

    gd.update_detector()
        .detector_id(&id)
        .data_sources(
            DataSourceConfigurations::builder().s3_logs(S3LogsConfiguration::builder().enable(false).build()).build(),
        )
        .send()
        .await
        .unwrap();
    let d = gd.get_detector().detector_id(&id).send().await.unwrap();
    assert_eq!(feature(&d, "S3_DATA_EVENTS"), "DISABLED");
    gd.update_detector().detector_id(&id).enable(false).send().await.unwrap();
    let d = gd.get_detector().detector_id(&id).send().await.unwrap();
    assert_eq!(d.status().unwrap().as_str(), "DISABLED");
    assert_eq!(d.data_sources().unwrap().cloud_trail().unwrap().status().unwrap().as_str(), "DISABLED");

    assert_eq!(gd.list_detectors().send().await.unwrap().detector_ids(), [id.as_str()]);

    let s = gd.get_malware_scan_settings().detector_id(&id).send().await.unwrap();
    assert_eq!(s.ebs_snapshot_preservation().unwrap().as_str(), "NO_RETENTION");
    gd.update_malware_scan_settings()
        .detector_id(&id)
        .ebs_snapshot_preservation(aws_sdk_guardduty::types::EbsSnapshotPreservation::RetentionWithFinding)
        .send()
        .await
        .unwrap();
    let s = gd.get_malware_scan_settings().detector_id(&id).send().await.unwrap();
    assert_eq!(s.ebs_snapshot_preservation().unwrap().as_str(), "RETENTION_WITH_FINDING");

    let usage = gd
        .get_usage_statistics()
        .detector_id(&id)
        .usage_statistic_type(UsageStatisticType::SumByAccount)
        .usage_criteria(UsageCriteria::builder().build())
        .send()
        .await
        .unwrap();
    let by_account = usage.usage_statistics().unwrap().sum_by_account();
    assert_eq!(by_account[0].account_id(), Some("123456789012"));
    assert_eq!(by_account[0].total().unwrap().amount(), Some("0"));
    let trial = gd.get_remaining_free_trial_days().detector_id(&id).account_ids("123456789012").send().await.unwrap();
    assert_eq!(
        trial.accounts()[0].data_sources().unwrap().cloud_trail().unwrap().free_trial_days_remaining(),
        Some(30)
    );
    assert!(gd.list_coverage().detector_id(&id).send().await.unwrap().resources().is_empty());
    let cov = gd
        .get_coverage_statistics()
        .detector_id(&id)
        .statistics_type(CoverageStatisticsType::CountByCoverageStatus)
        .send()
        .await
        .unwrap();
    assert!(cov.coverage_statistics().unwrap().count_by_coverage_status().unwrap().is_empty());

    let arn = format!("arn:aws:guardduty:us-east-1:123456789012:detector/{id}");
    gd.tag_resource().resource_arn(&arn).tags("env", "test").send().await.unwrap();
    let tags = gd.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().unwrap().len(), 2);
    gd.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let tags = gd.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().unwrap().keys().collect::<Vec<_>>(), ["env"]);

    gd.delete_detector().detector_id(&id).send().await.unwrap();
    assert!(gd.list_detectors().send().await.unwrap().detector_ids().is_empty());
}

#[tokio::test]
async fn sample_findings_reach_eventbridge_and_filters_suppress_them() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let gd = Client::new(&cfg);
    let inbox = Inbox::new(&cfg, "gd-events").await;
    let id = detector(&gd).await;

    let bad = gd.create_sample_findings().detector_id(&id).finding_types("Nope:EC2/Nothing").send().await.unwrap_err();
    assert_eq!(code(&bad), "BadRequestException");

    gd.create_sample_findings()
        .detector_id(&id)
        .finding_types("Backdoor:EC2/C&CActivity.B")
        .finding_types("Recon:IAMUser/MaliciousIPCaller")
        .send()
        .await
        .unwrap();
    let events = inbox.drain(Duration::from_secs(3)).await;
    assert_eq!(events.len(), 2, "{events:?}");
    let backdoor = events.iter().find(|e| e["detail"]["type"] == "Backdoor:EC2/C&CActivity.B").unwrap();
    assert_eq!(backdoor["source"], "aws.guardduty");
    assert_eq!(backdoor["detail-type"], "GuardDuty Finding");
    assert_eq!(backdoor["detail"]["service"]["additionalInfo"]["sample"], true);
    assert_eq!(backdoor["detail"]["resource"]["instanceDetails"]["instanceId"], "i-99999999");
    assert_eq!(backdoor["detail"]["severity"], 8.0);
    assert!(backdoor["detail"]["title"].as_str().unwrap().starts_with("[SAMPLE]"));

    let all = gd.list_findings().detector_id(&id).send().await.unwrap();
    assert_eq!(all.finding_ids().len(), 2);
    let iam = gd
        .list_findings()
        .detector_id(&id)
        .finding_criteria(eq("resource.resourceType", &["AccessKey"]))
        .send()
        .await
        .unwrap();
    assert_eq!(iam.finding_ids().len(), 1);
    let high = gd
        .list_findings()
        .detector_id(&id)
        .finding_criteria(
            FindingCriteria::builder()
                .criterion("severity", Condition::builder().greater_than_or_equal(7).build())
                .build(),
        )
        .sort_criteria(SortCriteria::builder().attribute_name("severity").order_by(OrderBy::Desc).build())
        .send()
        .await
        .unwrap();
    assert_eq!(high.finding_ids().len(), 1);
    let found =
        gd.get_findings().detector_id(&id).set_finding_ids(Some(all.finding_ids().to_vec())).send().await.unwrap();
    let f = found.findings().iter().find(|f| f.r#type() == Some("Backdoor:EC2/C&CActivity.B")).unwrap();
    assert_eq!(f.account_id(), Some("123456789012"));
    assert!(f.arn().unwrap().starts_with(&format!("arn:aws:guardduty:us-east-1:123456789012:detector/{id}/finding/")));
    assert_eq!(f.resource().unwrap().resource_type(), Some("Instance"));
    let svc = f.service().unwrap();
    assert_eq!(svc.count(), Some(1));
    assert_eq!(svc.action().unwrap().action_type(), Some("NETWORK_CONNECTION"));
    let info: Value = serde_json::from_str(svc.additional_info().unwrap().value().unwrap()).unwrap();
    assert_eq!(
        info,
        json!({"sample":true,"threatListName":"GeneratedFindingThreatListName","threatName":"GeneratedFindingThreatName"})
    );

    // Generating the same sample again updates it.
    gd.create_sample_findings().detector_id(&id).finding_types("Backdoor:EC2/C&CActivity.B").send().await.unwrap();
    let again = gd.get_findings().detector_id(&id).finding_ids(f.id().unwrap()).send().await.unwrap();
    assert_eq!(again.findings()[0].service().unwrap().count(), Some(2));
    assert_eq!(inbox.drain(Duration::from_secs(2)).await.len(), 1);

    let stats = gd
        .get_findings_statistics()
        .detector_id(&id)
        .finding_statistic_types(FindingStatisticType::CountBySeverity)
        .send()
        .await
        .unwrap();
    assert_eq!(stats.finding_statistics().unwrap().count_by_severity().unwrap()["8.0"], 1);
    let grouped =
        gd.get_findings_statistics().detector_id(&id).group_by(GroupByType::FindingType).send().await.unwrap();
    assert_eq!(grouped.finding_statistics().unwrap().grouped_by_finding_type().len(), 2);

    gd.archive_findings().detector_id(&id).finding_ids(f.id().unwrap()).send().await.unwrap();
    let archived =
        gd.list_findings().detector_id(&id).finding_criteria(eq("service.archived", &["true"])).send().await.unwrap();
    assert_eq!(archived.finding_ids(), [f.id().unwrap().to_string()]);
    gd.unarchive_findings().detector_id(&id).finding_ids(f.id().unwrap()).send().await.unwrap();
    gd.update_findings_feedback()
        .detector_id(&id)
        .finding_ids(f.id().unwrap())
        .feedback(Feedback::Useful)
        .send()
        .await
        .unwrap();
    let fb = gd.get_findings().detector_id(&id).finding_ids(f.id().unwrap()).send().await.unwrap();
    let svc = fb.findings()[0].service().unwrap();
    assert_eq!(svc.archived(), Some(false));
    assert_eq!(svc.user_feedback(), Some("USEFUL"));

    // A suppression rule archives matching new findings, which are not sent.
    gd.create_filter()
        .detector_id(&id)
        .name("suppress-portscans")
        .action(FilterAction::Archive)
        .finding_criteria(eq("type", &["Recon:EC2/Portscan"]))
        .send()
        .await
        .unwrap();
    gd.create_filter()
        .detector_id(&id)
        .name("noop")
        .finding_criteria(eq("severity", &["2"]))
        .rank(1)
        .send()
        .await
        .unwrap();
    let dup = gd
        .create_filter()
        .detector_id(&id)
        .name("noop")
        .finding_criteria(eq("severity", &["2"]))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "BadRequestException");
    let names = gd.list_filters().detector_id(&id).send().await.unwrap();
    assert_eq!(names.filter_names(), ["noop", "suppress-portscans"]);
    gd.create_sample_findings()
        .detector_id(&id)
        .finding_types("Recon:EC2/Portscan")
        .finding_types("Policy:S3/BucketBlockPublicAccessDisabled")
        .send()
        .await
        .unwrap();
    let sent = inbox.drain(Duration::from_secs(2)).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["detail"]["type"], "Policy:S3/BucketBlockPublicAccessDisabled");
    let suppressed =
        gd.list_findings().detector_id(&id).finding_criteria(eq("type", &["Recon:EC2/Portscan"])).send().await.unwrap();
    let s = gd.get_findings().detector_id(&id).finding_ids(&suppressed.finding_ids()[0]).send().await.unwrap();
    assert_eq!(s.findings()[0].service().unwrap().archived(), Some(true));

    let filter = gd.get_filter().detector_id(&id).filter_name("suppress-portscans").send().await.unwrap();
    assert_eq!(filter.action().unwrap().as_str(), "ARCHIVE");
    assert_eq!(filter.rank(), Some(2));
    gd.update_filter()
        .detector_id(&id)
        .filter_name("suppress-portscans")
        .action(FilterAction::Noop)
        .rank(1)
        .send()
        .await
        .unwrap();
    let filter = gd.get_filter().detector_id(&id).filter_name("suppress-portscans").send().await.unwrap();
    assert_eq!((filter.action().unwrap().as_str(), filter.rank(), filter.version()), ("NOOP", Some(1), Some(2)));
    gd.delete_filter().detector_id(&id).filter_name("noop").send().await.unwrap();
    let gone = gd.get_filter().detector_id(&id).filter_name("noop").send().await.unwrap_err();
    assert_eq!(message(&gone), "The request is rejected since no such resource found.");

    // Every finding type has a sample.
    gd.create_sample_findings().detector_id(&id).send().await.unwrap();
    let total = gd
        .get_findings_statistics()
        .detector_id(&id)
        .group_by(GroupByType::FindingType)
        .max_results(100)
        .send()
        .await
        .unwrap();
    assert!(total.finding_statistics().unwrap().grouped_by_finding_type().len() >= 100);
}

#[tokio::test]
async fn threat_lists_and_s3_publishing_destination() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let gd = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let id = detector(&gd).await;

    let ip = gd
        .create_ip_set()
        .detector_id(&id)
        .name("office")
        .format(IpSetFormat::Txt)
        .location("https://s3.amazonaws.com/lists/office.txt")
        .activate(true)
        .send()
        .await
        .unwrap()
        .ip_set_id()
        .unwrap()
        .to_string();
    let second = gd
        .create_ip_set()
        .detector_id(&id)
        .name("vpn")
        .format(IpSetFormat::Txt)
        .location("s3://lists/vpn.txt")
        .activate(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&second), "BadRequestException");
    let got = gd.get_ip_set().detector_id(&id).ip_set_id(&ip).send().await.unwrap();
    assert_eq!((got.name(), got.status().unwrap().as_str()), (Some("office"), "ACTIVE"));
    gd.update_ip_set().detector_id(&id).ip_set_id(&ip).activate(false).name("hq").send().await.unwrap();
    let got = gd.get_ip_set().detector_id(&id).ip_set_id(&ip).send().await.unwrap();
    assert_eq!((got.name(), got.status().unwrap().as_str()), (Some("hq"), "INACTIVE"));
    assert_eq!(gd.list_ip_sets().detector_id(&id).send().await.unwrap().ip_set_ids(), [ip.as_str()]);
    gd.delete_ip_set().detector_id(&id).ip_set_id(&ip).send().await.unwrap();
    assert!(gd.list_ip_sets().detector_id(&id).send().await.unwrap().ip_set_ids().is_empty());

    let ti = gd
        .create_threat_intel_set()
        .detector_id(&id)
        .name("bad-ips")
        .format(ThreatIntelSetFormat::Stix)
        .location("s3://lists/bad.xml")
        .activate(true)
        .tags("k", "v")
        .send()
        .await
        .unwrap()
        .threat_intel_set_id()
        .unwrap()
        .to_string();
    gd.update_threat_intel_set()
        .detector_id(&id)
        .threat_intel_set_id(&ti)
        .location("s3://lists/bad2.xml")
        .send()
        .await
        .unwrap();
    let got = gd.get_threat_intel_set().detector_id(&id).threat_intel_set_id(&ti).send().await.unwrap();
    assert_eq!(got.location(), Some("s3://lists/bad2.xml"));
    assert_eq!(got.tags().unwrap()["k"], "v");
    assert_eq!(gd.list_threat_intel_sets().detector_id(&id).send().await.unwrap().threat_intel_set_ids().len(), 1);
    gd.delete_threat_intel_set().detector_id(&id).threat_intel_set_id(&ti).send().await.unwrap();

    let te = gd
        .create_threat_entity_set()
        .detector_id(&id)
        .name("bad-domains")
        .format(ThreatEntitySetFormat::Txt)
        .location("s3://lists/domains.txt")
        .activate(false)
        .send()
        .await
        .unwrap()
        .threat_entity_set_id()
        .unwrap()
        .to_string();
    gd.update_threat_entity_set().detector_id(&id).threat_entity_set_id(&te).activate(true).send().await.unwrap();
    let got = gd.get_threat_entity_set().detector_id(&id).threat_entity_set_id(&te).send().await.unwrap();
    assert_eq!(got.status().unwrap().as_str(), "ACTIVE");
    assert!(got.created_at().is_some());
    assert_eq!(
        gd.list_threat_entity_sets().detector_id(&id).send().await.unwrap().threat_entity_set_ids(),
        [te.as_str()]
    );
    gd.delete_threat_entity_set().detector_id(&id).threat_entity_set_id(&te).send().await.unwrap();

    let tr = gd
        .create_trusted_entity_set()
        .detector_id(&id)
        .name("partners")
        .format(TrustedEntitySetFormat::Txt)
        .location("s3://lists/partners.txt")
        .activate(true)
        .send()
        .await
        .unwrap()
        .trusted_entity_set_id()
        .unwrap()
        .to_string();
    gd.update_trusted_entity_set().detector_id(&id).trusted_entity_set_id(&tr).name("vendors").send().await.unwrap();
    let got = gd.get_trusted_entity_set().detector_id(&id).trusted_entity_set_id(&tr).send().await.unwrap();
    assert_eq!(got.name(), Some("vendors"));
    assert_eq!(gd.list_trusted_entity_sets().detector_id(&id).send().await.unwrap().trusted_entity_set_ids().len(), 1);
    gd.delete_trusted_entity_set().detector_id(&id).trusted_entity_set_id(&tr).send().await.unwrap();
    let bad = gd
        .create_trusted_entity_set()
        .detector_id(&id)
        .name("x")
        .format(TrustedEntitySetFormat::Txt)
        .location("ftp://nowhere")
        .activate(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad), "BadRequestException");

    // Findings exported to S3, SSE-KMS under the destination's key.
    s3.create_bucket().bucket("gd-findings").send().await.unwrap();
    let bucket_policy = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"Service":"guardduty.amazonaws.com"},"Action":["s3:PutObject","s3:GetBucketLocation"],
        "Resource":["arn:aws:s3:::gd-findings","arn:aws:s3:::gd-findings/*"]}]});
    s3.put_bucket_policy().bucket("gd-findings").policy(bucket_policy.to_string()).send().await.unwrap();
    let key_policy = json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"},
        {"Effect":"Allow","Principal":{"Service":"guardduty.amazonaws.com"},"Action":"kms:GenerateDataKey","Resource":"*",
         "Condition":{"StringEquals":{"aws:SourceAccount":"123456789012"}}}]});
    let key = kms.create_key().policy(key_policy.to_string()).send().await.unwrap();
    let key_arn = key.key_metadata().unwrap().arn().unwrap().to_string();
    let dest = gd
        .create_publishing_destination()
        .detector_id(&id)
        .destination_type(DestinationType::S3)
        .destination_properties(
            DestinationProperties::builder()
                .destination_arn("arn:aws:s3:::gd-findings/exports")
                .kms_key_arn(&key_arn)
                .build(),
        )
        .send()
        .await
        .unwrap()
        .destination_id()
        .unwrap()
        .to_string();
    gd.create_sample_findings().detector_id(&id).finding_types("Trojan:EC2/DropPoint").send().await.unwrap();
    let objects = s3.list_objects_v2().bucket("gd-findings").send().await.unwrap();
    let obj = &objects.contents()[0];
    let key_name = obj.key().unwrap().to_string();
    assert!(key_name.starts_with("exports/AWSLogs/123456789012/GuardDuty/us-east-1/"), "{key_name}");
    assert!(key_name.ends_with(".jsonl.gz"));
    let got = s3.get_object().bucket("gd-findings").key(&key_name).send().await.unwrap();
    assert_eq!(got.server_side_encryption().unwrap().as_str(), "aws:kms");
    let body = got.body.collect().await.unwrap().into_bytes();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&body[..]), &mut text).unwrap();
    let line: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(line["type"], "Trojan:EC2/DropPoint");

    let described = gd.describe_publishing_destination().detector_id(&id).destination_id(&dest).send().await.unwrap();
    assert_eq!(described.status().unwrap().as_str(), "PUBLISHING");
    assert_eq!(described.publishing_failure_start_timestamp(), Some(0));
    // A destination that cannot be written reports it.
    gd.update_publishing_destination()
        .detector_id(&id)
        .destination_id(&dest)
        .destination_properties(
            DestinationProperties::builder()
                .destination_arn("arn:aws:s3:::no-such-bucket")
                .kms_key_arn(&key_arn)
                .build(),
        )
        .send()
        .await
        .unwrap();
    gd.create_sample_findings().detector_id(&id).finding_types("Trojan:EC2/DropPoint!DNS").send().await.unwrap();
    let described = gd.describe_publishing_destination().detector_id(&id).destination_id(&dest).send().await.unwrap();
    assert_eq!(described.status().unwrap().as_str(), "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY");
    assert!(described.publishing_failure_start_timestamp().unwrap() > 0);
    let listed = gd.list_publishing_destinations().detector_id(&id).send().await.unwrap();
    assert_eq!(listed.destinations()[0].destination_id(), Some(dest.as_str()));
    gd.delete_publishing_destination().detector_id(&id).destination_id(&dest).send().await.unwrap();
    assert!(gd.list_publishing_destinations().detector_id(&id).send().await.unwrap().destinations().is_empty());
}

const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

struct Org {
    mws: Mws,
    orgs: aws_sdk_organizations::Client,
    admin: aws_config::SdkConfig,
}

impl Org {
    async fn new() -> Self {
        let mws = Mws::start().await;
        let orgs = aws_sdk_organizations::Client::new(&mws.root_sdk_config().await);
        orgs.create_organization().send().await.unwrap();
        let (_, admin) = user_with_policy(&mws, "admin", Some(ADMIN)).await;
        Org { mws, orgs, admin }
    }

    async fn account(&self, name: &str) -> (String, aws_config::SdkConfig) {
        let out =
            self.orgs.create_account().email(format!("{name}@example.com")).account_name(name).send().await.unwrap();
        let req = out.create_account_status().unwrap().id().unwrap();
        let st = self.orgs.describe_create_account_status().create_account_request_id(req).send().await.unwrap();
        let account = st.create_account_status().unwrap().account_id().unwrap().to_string();
        let sts = aws_sdk_sts::Client::new(&self.admin);
        let creds = sts
            .assume_role()
            .role_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
            .role_session_name("ops")
            .send()
            .await
            .unwrap();
        (account.clone(), sts_config(&self.mws, creds.credentials().unwrap()).await)
    }
}

#[tokio::test]
async fn members_by_invitation() {
    let org = Org::new().await;
    let admin = Client::new(&org.admin);
    let (member_id, member_cfg) = org.account("member").await;
    let member = Client::new(&member_cfg);
    let admin_det = detector(&admin).await;
    let member_det = detector(&member).await;

    let created = admin
        .create_members()
        .detector_id(&admin_det)
        .account_details(AccountDetail::builder().account_id(&member_id).email("member@example.com").build())
        .account_details(AccountDetail::builder().account_id("123456789012").email("me@example.com").build())
        .send()
        .await
        .unwrap();
    assert_eq!(created.unprocessed_accounts().len(), 1);
    let m = admin.get_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    assert_eq!(m.members()[0].relationship_status(), Some("Created"));
    assert!(admin.list_members().detector_id(&admin_det).send().await.unwrap().members().is_empty());
    let all = admin.list_members().detector_id(&admin_det).only_associated("false").send().await.unwrap();
    assert_eq!(all.members().len(), 1);

    admin.invite_members().detector_id(&admin_det).account_ids(&member_id).message("join").send().await.unwrap();
    assert_eq!(member.get_invitations_count().send().await.unwrap().invitations_count(), Some(1));
    let inv = member.list_invitations().send().await.unwrap();
    let invitation = inv.invitations()[0].clone();
    assert_eq!(invitation.account_id(), Some("123456789012"));
    let wrong = member
        .accept_administrator_invitation()
        .detector_id(&member_det)
        .administrator_id("123456789012")
        .invitation_id("0000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&wrong), "The request is rejected because the input invitationId is invalid.");
    member
        .accept_administrator_invitation()
        .detector_id(&member_det)
        .administrator_id("123456789012")
        .invitation_id(invitation.invitation_id().unwrap())
        .send()
        .await
        .unwrap();
    let a = member.get_administrator_account().detector_id(&member_det).send().await.unwrap();
    let a = a.administrator().unwrap();
    assert_eq!((a.account_id(), a.relationship_status()), (Some("123456789012"), Some("Enabled")));
    let master = member.get_master_account().detector_id(&member_det).send().await.unwrap();
    assert_eq!(master.master().unwrap().account_id(), Some("123456789012"));
    let listed = admin.list_members().detector_id(&admin_det).send().await.unwrap();
    assert_eq!(listed.members()[0].detector_id(), Some(member_det.as_str()));

    // The administrator sees and manages the member's findings and detector.
    member
        .create_sample_findings()
        .detector_id(&member_det)
        .finding_types("CryptoCurrency:EC2/BitcoinTool.B")
        .send()
        .await
        .unwrap();
    let seen = admin
        .list_findings()
        .detector_id(&admin_det)
        .finding_criteria(eq("accountId", &[&member_id]))
        .send()
        .await
        .unwrap();
    assert_eq!(seen.finding_ids().len(), 1);
    let blocked = member
        .archive_findings()
        .detector_id(&member_det)
        .finding_ids(&seen.finding_ids()[0])
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&blocked), "BadRequestException");
    admin.archive_findings().detector_id(&admin_det).finding_ids(&seen.finding_ids()[0]).send().await.unwrap();
    admin
        .update_member_detectors()
        .detector_id(&admin_det)
        .account_ids(&member_id)
        .features(
            aws_sdk_guardduty::types::MemberFeaturesConfiguration::builder()
                .name(OrgFeature::EksAuditLogs)
                .status(FeatureStatus::Disabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let md = admin.get_member_detectors().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    let cfg = &md.member_data_source_configurations()[0];
    assert_eq!(
        cfg.data_sources().unwrap().kubernetes().unwrap().audit_logs().unwrap().status().unwrap().as_str(),
        "DISABLED"
    );

    admin.stop_monitoring_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    let m = admin.get_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    assert_eq!(m.members()[0].relationship_status(), Some("Disabled"));
    admin.start_monitoring_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();

    member.disassociate_from_administrator_account().detector_id(&member_det).send().await.unwrap();
    let m = admin.get_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    assert_eq!(m.members()[0].relationship_status(), Some("Resigned"));

    // Decline, then delete, then the deprecated accept and disassociate.
    admin.invite_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    member.decline_invitations().account_ids("123456789012").send().await.unwrap();
    assert_eq!(member.get_invitations_count().send().await.unwrap().invitations_count(), Some(0));
    admin.invite_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    member.delete_invitations().account_ids("123456789012").send().await.unwrap();
    let none = member.delete_invitations().account_ids("123456789012").send().await.unwrap();
    assert_eq!(none.unprocessed_accounts().len(), 1);
    admin.invite_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    let inv = member.list_invitations().send().await.unwrap();
    member
        .accept_invitation()
        .detector_id(&member_det)
        .master_id("123456789012")
        .invitation_id(inv.invitations()[0].invitation_id().unwrap())
        .send()
        .await
        .unwrap();
    member.disassociate_from_master_account().detector_id(&member_det).send().await.unwrap();
    admin.invite_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    let inv = member.list_invitations().send().await.unwrap();
    member
        .accept_administrator_invitation()
        .detector_id(&member_det)
        .administrator_id("123456789012")
        .invitation_id(inv.invitations()[0].invitation_id().unwrap())
        .send()
        .await
        .unwrap();
    admin.disassociate_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    let m = admin.get_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    assert_eq!(m.members()[0].relationship_status(), Some("Removed"));
    let a = member.get_administrator_account().detector_id(&member_det).send().await.unwrap();
    assert!(a.administrator().unwrap().account_id().is_none());
    admin.delete_members().detector_id(&admin_det).account_ids(&member_id).send().await.unwrap();
    let all = admin.list_members().detector_id(&admin_det).only_associated("false").send().await.unwrap();
    assert!(all.members().is_empty());
}

#[tokio::test]
async fn organization_delegated_administrator() {
    let org = Org::new().await;
    let mgmt = Client::new(&org.admin);
    let (sec_id, sec_cfg) = org.account("security").await;
    let (app_id, app_cfg) = org.account("app").await;
    let sec = Client::new(&sec_cfg);
    let app = Client::new(&app_cfg);

    let not_admin = sec.list_organization_admin_accounts().send().await.unwrap_err();
    assert_eq!(code(&not_admin), "BadRequestException");
    mgmt.enable_organization_admin_account().admin_account_id(&sec_id).send().await.unwrap();
    let admins = mgmt.list_organization_admin_accounts().send().await.unwrap();
    let a = &admins.admin_accounts()[0];
    assert_eq!((a.admin_account_id(), a.admin_status().unwrap().as_str()), (Some(sec_id.as_str()), "ENABLED"));
    // Organizations knows GuardDuty's delegated administrator.
    let delegated =
        org.orgs.list_delegated_administrators().service_principal("guardduty.amazonaws.com").send().await.unwrap();
    assert_eq!(delegated.delegated_administrators()[0].id(), Some(sec_id.as_str()));
    let services = org.orgs.list_aws_service_access_for_organization().send().await.unwrap();
    assert!(services
        .enabled_service_principals()
        .iter()
        .any(|s| s.service_principal() == Some("guardduty.amazonaws.com")));

    // The delegated administrator got a detector and manages the org.
    let sec_det = sec.list_detectors().send().await.unwrap().detector_ids()[0].clone();
    sec.update_organization_configuration()
        .detector_id(&sec_det)
        .auto_enable_organization_members(AutoEnableMembers::All)
        .features(
            OrganizationFeatureConfiguration::builder()
                .name(OrgFeature::RuntimeMonitoring)
                .auto_enable(OrgFeatureStatus::All)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let conf = sec.describe_organization_configuration().detector_id(&sec_det).send().await.unwrap();
    assert_eq!(conf.auto_enable_organization_members().unwrap().as_str(), "ALL");
    assert_eq!(conf.auto_enable(), Some(true));
    let members = sec.list_members().detector_id(&sec_det).send().await.unwrap();
    let mut ids: Vec<&str> = members.members().iter().map(|m| m.account_id().unwrap()).collect();
    ids.sort();
    let mut want = vec![app_id.as_str(), "123456789012"];
    want.sort();
    assert_eq!(ids, want);
    assert!(members.members().iter().all(|m| m.relationship_status() == Some("Enabled")));

    let app_det = app.list_detectors().send().await.unwrap().detector_ids()[0].clone();
    let a = app.get_administrator_account().detector_id(&app_det).send().await.unwrap();
    assert_eq!(a.administrator().unwrap().account_id(), Some(sec_id.as_str()));
    let d = app.get_detector().detector_id(&app_det).send().await.unwrap();
    let rm = d.features().iter().find(|f| f.name().map(|n| n.as_str()) == Some("RUNTIME_MONITORING")).unwrap();
    assert_eq!(rm.status().unwrap().as_str(), "ENABLED");
    let leave = app.disassociate_from_administrator_account().detector_id(&app_det).send().await.unwrap_err();
    assert_eq!(code(&leave), "BadRequestException");

    // Members' findings go to the administrator's bus too.
    let inbox = Inbox::new(&sec_cfg, "sec-findings").await;
    app.create_sample_findings()
        .detector_id(&app_det)
        .finding_types("UnauthorizedAccess:EC2/SSHBruteForce")
        .send()
        .await
        .unwrap();
    let events = inbox.drain(Duration::from_secs(3)).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["account"], sec_id);
    assert_eq!(events[0]["detail"]["accountId"], app_id);

    let stats = sec.get_organization_statistics().send().await.unwrap();
    let s = stats.organization_details().unwrap().organization_statistics().unwrap();
    assert_eq!(s.total_accounts_count(), Some(3));
    assert_eq!(s.member_accounts_count(), Some(2));

    // Organization-wide custom detection rule configuration.
    let rules = sec.list_custom_detection_rules().send().await.unwrap();
    let rule = rules.rules()[0].rule_id().unwrap().to_string();
    sec.create_custom_detection_rule_org_configuration()
        .rule_id(&rule)
        .mode(aws_sdk_guardduty::types::AssociationMode::Live)
        .exclude_account_ids(&app_id)
        .send()
        .await
        .unwrap();
    let denied = app
        .create_custom_detection_rule_org_configuration()
        .rule_id(&rule)
        .mode(aws_sdk_guardduty::types::AssociationMode::Live)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "AccessDeniedException");
    sec.update_custom_detection_rule_org_configuration()
        .rule_id(&rule)
        .mode(aws_sdk_guardduty::types::AssociationMode::Live)
        .include_account_ids("123456789012")
        .send()
        .await
        .unwrap();
    let c = sec
        .get_custom_detection_rule_org_configuration()
        .rule_id(&rule)
        .mode(aws_sdk_guardduty::types::AssociationMode::Live)
        .send()
        .await
        .unwrap();
    assert_eq!(c.configuration().unwrap().include_account_ids(), ["123456789012"]);
    assert_eq!(sec.list_custom_detection_rule_org_configurations().send().await.unwrap().configurations().len(), 1);
    sec.delete_custom_detection_rule_org_configuration()
        .rule_id(&rule)
        .mode(aws_sdk_guardduty::types::AssociationMode::Live)
        .send()
        .await
        .unwrap();

    mgmt.disable_organization_admin_account().admin_account_id(&sec_id).send().await.unwrap();
    assert!(mgmt.list_organization_admin_accounts().send().await.unwrap().admin_accounts().is_empty());
    let delegated =
        org.orgs.list_delegated_administrators().service_principal("guardduty.amazonaws.com").send().await.unwrap();
    assert!(delegated.delegated_administrators().is_empty());
    let a = app.get_administrator_account().detector_id(&app_det).send().await.unwrap();
    assert!(a.administrator().unwrap().account_id().is_none());
}

#[tokio::test]
async fn malware_protection_rules_and_investigations() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let gd = Client::new(&cfg);
    let id = detector(&gd).await;
    let inbox = Inbox::new(&cfg, "malware").await;

    let plan = gd
        .create_malware_protection_plan()
        .role("arn:aws:iam::123456789012:role/gd-malware")
        .protected_resource(
            CreateProtectedResource::builder()
                .s3_bucket(CreateS3BucketResource::builder().bucket_name("uploads").object_prefixes("in/").build())
                .build(),
        )
        .tags("app", "uploads")
        .send()
        .await
        .unwrap()
        .malware_protection_plan_id()
        .unwrap()
        .to_string();
    let dup = gd
        .create_malware_protection_plan()
        .role("arn:aws:iam::123456789012:role/gd-malware")
        .protected_resource(
            CreateProtectedResource::builder()
                .s3_bucket(CreateS3BucketResource::builder().bucket_name("uploads").build())
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "ConflictException");
    let p = gd.get_malware_protection_plan().malware_protection_plan_id(&plan).send().await.unwrap();
    assert_eq!(p.status().unwrap().as_str(), "ACTIVE");
    assert_eq!(p.arn().unwrap(), format!("arn:aws:guardduty:us-east-1:123456789012:malware-protection-plan/{plan}"));
    gd.update_malware_protection_plan()
        .malware_protection_plan_id(&plan)
        .role("arn:aws:iam::123456789012:role/gd-malware-2")
        .send()
        .await
        .unwrap();
    let p = gd.get_malware_protection_plan().malware_protection_plan_id(&plan).send().await.unwrap();
    assert_eq!(p.role(), Some("arn:aws:iam::123456789012:role/gd-malware-2"));
    assert_eq!(gd.list_malware_protection_plans().send().await.unwrap().malware_protection_plans().len(), 1);

    gd.send_object_malware_scan()
        .s3_object(S3ObjectForSendObjectMalwareScan::builder().bucket("uploads").key("in/a.pdf").build())
        .send()
        .await
        .unwrap();
    let outside = gd
        .send_object_malware_scan()
        .s3_object(S3ObjectForSendObjectMalwareScan::builder().bucket("uploads").key("out/a.pdf").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&outside), "BadRequestException");
    let events = inbox.drain(Duration::from_secs(2)).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["detail-type"], "GuardDuty Malware Protection Object Scan Result");
    assert_eq!(events[0]["detail"]["scanResultDetails"]["scanResultStatus"], "NO_THREATS_FOUND");
    gd.delete_malware_protection_plan().malware_protection_plan_id(&plan).send().await.unwrap();
    let gone = gd.get_malware_protection_plan().malware_protection_plan_id(&plan).send().await.unwrap_err();
    assert_eq!(code(&gone), "ResourceNotFoundException");

    let instance = "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0";
    let scan = gd.start_malware_scan().resource_arn(instance).send().await.unwrap().scan_id().unwrap().to_string();
    let s = gd.get_malware_scan().scan_id(&scan).send().await.unwrap();
    assert_eq!(s.scan_status().unwrap().as_str(), "COMPLETED");
    assert_eq!(s.resource_type().unwrap().as_str(), "EC2_INSTANCE");
    assert_eq!(s.scan_result_details().unwrap().scan_result_status().unwrap().as_str(), "NO_THREATS_FOUND");
    assert_eq!(gd.list_malware_scans().send().await.unwrap().scans()[0].scan_id(), Some(scan.as_str()));
    let described = gd.describe_malware_scans().detector_id(&id).send().await.unwrap();
    assert_eq!(described.scans()[0].resource_details().unwrap().instance_arn(), Some(instance));
    let missing = gd.get_malware_scan().scan_id("nope").send().await.unwrap_err();
    assert_eq!(code(&missing), "ResourceNotFoundException");

    let rules = gd.list_custom_detection_rules().send().await.unwrap();
    assert!(!rules.rules().is_empty());
    let rule_id = rules.rules()[0].rule_id().unwrap().to_string();
    let rule = gd.get_custom_detection_rule().rule_id(&rule_id).send().await.unwrap();
    assert!(rule.rule().unwrap().definition().unwrap().expression().unwrap().contains("cloudtrail"));
    let unknown = gd.get_custom_detection_rule().rule_id("no-such-rule").send().await.unwrap_err();
    assert_eq!(code(&unknown), "ResourceNotFoundException");
    let assoc = gd
        .create_custom_detection_rule_association()
        .rule_id(&rule_id)
        .mode(aws_sdk_guardduty::types::AssociationMode::DryRun)
        .tags("k", "v")
        .send()
        .await
        .unwrap();
    let assoc = assoc.rule_association().unwrap();
    assert!(assoc.expires_at().is_some());
    let assoc_id = assoc.association_id().unwrap().to_string();
    gd.update_custom_detection_rule_association()
        .rule_id(&rule_id)
        .association_id(&assoc_id)
        .mode(aws_sdk_guardduty::types::AssociationMode::Live)
        .send()
        .await
        .unwrap();
    let got =
        gd.get_custom_detection_rule_association().rule_id(&rule_id).association_id(&assoc_id).send().await.unwrap();
    assert_eq!(got.rule_association().unwrap().mode().unwrap().as_str(), "LIVE");
    assert!(got.rule_association().unwrap().expires_at().is_none());
    assert_eq!(gd.list_custom_detection_rule_associations().send().await.unwrap().rule_associations().len(), 1);
    gd.delete_custom_detection_rule_association().rule_id(&rule_id).association_id(&assoc_id).send().await.unwrap();
    assert!(gd.list_custom_detection_rule_associations().send().await.unwrap().rule_associations().is_empty());

    let inv = gd
        .create_investigation()
        .detector_id(&id)
        .trigger_prompt("Was any access key used from Tor last week?")
        .send()
        .await
        .unwrap()
        .investigation_id()
        .unwrap()
        .to_string();
    let got = gd.get_investigation().detector_id(&id).investigation_id(&inv).send().await.unwrap();
    assert_eq!(got.investigation().unwrap().status().unwrap().as_str(), "COMPLETED");
    assert_eq!(gd.list_investigations().detector_id(&id).send().await.unwrap().investigations().len(), 1);
}

#[tokio::test]
async fn iam_is_enforced() {
    let mws = Mws::start().await;
    let gd_root = Client::new(&mws.root_sdk_config().await);
    let id = detector(&gd_root).await;
    let policy = json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":["guardduty:GetDetector","guardduty:ListDetectors"],"Resource":"*"},
        {"Effect":"Deny","Action":"guardduty:GetDetector","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/locked":"yes"}}}]});
    let (_, cfg) = user_with_policy(&mws, "reader", Some(&policy.to_string())).await;
    let gd = Client::new(&cfg);
    assert_eq!(gd.list_detectors().send().await.unwrap().detector_ids(), [id.as_str()]);
    gd.get_detector().detector_id(&id).send().await.unwrap();
    let denied = gd.create_sample_findings().detector_id(&id).send().await.unwrap_err();
    assert_eq!(code(&denied), "AccessDeniedException");
    gd_root
        .tag_resource()
        .resource_arn(format!("arn:aws:guardduty:us-east-1:123456789012:detector/{id}"))
        .tags("locked", "yes")
        .send()
        .await
        .unwrap();
    let denied = gd.get_detector().detector_id(&id).send().await.unwrap_err();
    assert_eq!(code(&denied), "AccessDeniedException");
    let _ = gd_root.get_organization_statistics().send().await.unwrap_err();
}

#[tokio::test]
async fn findings_are_imported_into_security_hub() {
    use aws_sdk_securityhub::types::{AwsSecurityFindingFilters, StringFilter, StringFilterComparison};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let gd = Client::new(&cfg);
    let sh = aws_sdk_securityhub::Client::new(&cfg);
    let id = detector(&gd).await;
    // Nothing is imported before Security Hub is enabled.
    gd.create_sample_findings()
        .detector_id(&id)
        .finding_types("Recon:EC2/PortProbeUnprotectedPort")
        .send()
        .await
        .unwrap();
    sh.enable_security_hub().send().await.unwrap();
    gd.create_sample_findings()
        .detector_id(&id)
        .finding_types("Backdoor:EC2/C&CActivity.B")
        .finding_types("UnauthorizedAccess:IAMUser/MaliciousIPCaller")
        .send()
        .await
        .unwrap();
    let product = StringFilter::builder()
        .value("arn:aws:securityhub:us-east-1::product/aws/guardduty")
        .comparison(StringFilterComparison::Equals)
        .build();
    let found = sh
        .get_findings()
        .filters(AwsSecurityFindingFilters::builder().product_arn(product).build())
        .send()
        .await
        .unwrap();
    assert_eq!(found.findings().len(), 2);
    let backdoor = found
        .findings()
        .iter()
        .find(|f| f.types().iter().any(|t| t == "TTPs/Command and Control/Backdoor:EC2-C&CActivity.B"))
        .unwrap();
    assert_eq!(backdoor.product_name(), Some("GuardDuty"));
    assert_eq!(backdoor.company_name(), Some("Amazon"));
    assert_eq!(backdoor.severity().unwrap().label().unwrap().as_str(), "HIGH");
    assert!(backdoor.title().unwrap().starts_with("[SAMPLE]"));
    assert_eq!(
        backdoor.generator_id(),
        Some(format!("arn:aws:guardduty:us-east-1:123456789012:detector/{id}").as_str())
    );
    let r = &backdoor.resources()[0];
    assert_eq!(r.r#type(), Some("AwsEc2Instance"));
    assert_eq!(r.id(), Some("arn:aws:ec2:us-east-1:123456789012:instance/i-99999999"));
    assert_eq!(backdoor.product_fields().unwrap()["aws/guardduty/service/count"], "1");
    let key = found.findings().iter().find(|f| f.resources()[0].r#type() == Some("AwsIamAccessKey"));
    assert!(key.is_some());
}
