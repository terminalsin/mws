//! The rest of CloudTrail through the official Rust SDKs: trail updates,
//! Insights selectors and the Insights events they produce, event
//! configuration, Lake imports, channel ingestion through CloudTrail Data
//! (`PutAuditEvents`), dashboards, queries, federation and delegated
//! administrators.

use std::io::Write;
use std::time::Duration;

use aws_sdk_cloudtrail::types::{
    AdvancedEventSelector, AdvancedFieldSelector, Destination, DestinationType, ImportSource, InsightSelector,
    InsightType, LookupAttribute, LookupAttributeKey, S3ImportSource, Tag,
};
use mws_e2e::Mws;
use serde_json::{json, Value};
use sha2_010::Digest;

const ACCOUNT: &str = "123456789012";

fn code<E: aws_sdk_cloudtrail::error::ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn trail_bucket(s3: &aws_sdk_s3::Client, bucket: &str) {
    s3.create_bucket().bucket(bucket).send().await.unwrap();
    let policy = json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl",
         "Resource":format!("arn:aws:s3:::{bucket}")},
        {"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject",
         "Resource":format!("arn:aws:s3:::{bucket}/*")}]});
    s3.put_bucket_policy().bucket(bucket).policy(policy.to_string()).send().await.unwrap();
}

async fn advance(mws: &Mws, seconds: i64) {
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&format!(r#"{{"advanceSeconds": {seconds}}}"#))).await;
    assert_eq!(status, 200);
}

/// Wall-clock time back to what it was, for the other suites.
async fn reset_clock(mws: &Mws) {
    let _ = mws.control("POST", "/_mws/clock", Some(r#"{"offsetSeconds": 0}"#)).await;
}

fn activity_selector() -> AdvancedEventSelector {
    AdvancedEventSelector::builder()
        .name("integration")
        .field_selectors(
            AdvancedFieldSelector::builder().field("eventCategory").equals("ActivityAuditLog").build().unwrap(),
        )
        .build()
        .unwrap()
}

/// Run a Lake query and wait for its rows (queries run in the background).
async fn rows(ct: &aws_sdk_cloudtrail::Client, sql: String) -> Vec<Vec<(String, String)>> {
    let id = ct.start_query().query_statement(sql).send().await.unwrap().query_id.unwrap();
    let mut out = ct.get_query_results().query_id(&id).send().await.unwrap();
    for _ in 0..40 {
        if !matches!(out.query_status().map(|s| s.as_str()), Some("QUEUED") | Some("RUNNING")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        out = ct.get_query_results().query_id(&id).send().await.unwrap();
    }
    assert_eq!(out.query_status().map(|s| s.as_str()), Some("FINISHED"));
    assert_eq!(out.error_message(), None);
    out.query_result_rows()
        .iter()
        .map(|r| r.iter().flat_map(|c| c.iter().map(|(k, v)| (k.clone(), v.clone()))).collect())
        .collect()
}

#[tokio::test]
async fn trails_update_list_tag_and_configure() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    trail_bucket(&s3, "cfg-trail").await;
    trail_bucket(&s3, "cfg-trail-2").await;
    let arn = ct.create_trail().name("cfg").s3_bucket_name("cfg-trail").send().await.unwrap().trail_arn.unwrap();

    let updated = ct
        .update_trail()
        .name("cfg")
        .s3_bucket_name("cfg-trail-2")
        .s3_key_prefix("audit")
        .is_multi_region_trail(true)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.s3_bucket_name(), Some("cfg-trail-2"));
    assert_eq!(updated.s3_key_prefix(), Some("audit"));
    assert_eq!(updated.is_multi_region_trail(), Some(true));
    let missing = ct.update_trail().name("nope").s3_bucket_name("cfg-trail").send().await.unwrap_err();
    assert_eq!(code(missing.into_service_error()), "TrailNotFoundException");

    let listed = ct.list_trails().send().await.unwrap();
    assert_eq!(listed.trails().len(), 1);
    assert_eq!(listed.trails()[0].trail_arn(), Some(arn.as_str()));
    assert_eq!(listed.trails()[0].home_region(), Some("us-east-1"));

    ct.add_tags()
        .resource_id(&arn)
        .tags_list(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = ct.list_tags().resource_id_list(&arn).send().await.unwrap();
    assert_eq!(tags.resource_tag_list()[0].tags_list()[0].value(), Some("prod"));
    let reserved = ct.add_tags().resource_id(&arn).tags_list(Tag::builder().key("aws:x").build().unwrap()).send().await;
    assert_eq!(code(reserved.unwrap_err().into_service_error()), "InvalidTagParameterException");

    let no_insights = ct.get_insight_selectors().trail_name("cfg").send().await.unwrap_err();
    assert_eq!(code(no_insights.into_service_error()), "InsightNotEnabledException");
    let put = ct
        .put_insight_selectors()
        .trail_name("cfg")
        .insight_selectors(InsightSelector::builder().insight_type(InsightType::ApiCallRateInsight).build())
        .send()
        .await
        .unwrap();
    assert_eq!(put.trail_arn(), Some(arn.as_str()));
    let got = ct.get_insight_selectors().trail_name("cfg").send().await.unwrap();
    assert_eq!(got.insight_selectors()[0].insight_type(), Some(&InsightType::ApiCallRateInsight));

    let config = ct.get_event_configuration().trail_name("cfg").send().await.unwrap();
    assert_eq!(config.max_event_size().map(|s| s.as_str()), Some("Standard"));
    ct.put_event_configuration()
        .trail_name("cfg")
        .max_event_size(aws_sdk_cloudtrail::types::MaxEventSize::Large)
        .send()
        .await
        .unwrap();
    let config = ct.get_event_configuration().trail_name("cfg").send().await.unwrap();
    assert_eq!(config.max_event_size().map(|s| s.as_str()), Some("Large"));
    let both = ct.get_event_configuration().send().await.unwrap_err();
    assert_eq!(code(both.into_service_error()), "InvalidParameterCombinationException");
    mws.stop().await;
}

#[tokio::test]
async fn insights_events_follow_unusual_call_rates() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    trail_bucket(&s3, "insights-trail").await;
    let arn =
        ct.create_trail().name("insights").s3_bucket_name("insights-trail").send().await.unwrap().trail_arn.unwrap();
    ct.put_insight_selectors()
        .trail_name("insights")
        .insight_selectors(InsightSelector::builder().insight_type(InsightType::ApiCallRateInsight).build())
        .send()
        .await
        .unwrap();
    ct.start_logging().name("insights").send().await.unwrap();

    // A quiet minute for the baseline, then a burst.
    iam.create_group().group_name("g0").send().await.unwrap();
    advance(&mws, 60).await;
    for i in 1..=30 {
        iam.create_group().group_name(format!("g{i}")).send().await.unwrap();
    }
    advance(&mws, 120).await;
    iam.list_groups().send().await.unwrap();

    let insight = LookupAttribute::builder()
        .attribute_key(LookupAttributeKey::EventName)
        .attribute_value("CreateGroup")
        .build()
        .unwrap();
    let mut found = Vec::new();
    for _ in 0..40 {
        let out = ct
            .lookup_events()
            .event_category(aws_sdk_cloudtrail::types::EventCategory::Insight)
            .lookup_attributes(insight.clone())
            .send()
            .await
            .unwrap();
        found = out.events().to_vec();
        if found.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let records: Vec<Value> =
        found.iter().map(|e| serde_json::from_str(e.cloud_trail_event().unwrap()).unwrap()).collect();
    let start = records.iter().find(|r| r["insightDetails"]["state"] == "Start").expect("a Start Insights event");
    assert_eq!(start["eventType"], "AwsCloudTrailInsight");
    assert_eq!(start["insightDetails"]["eventSource"], "iam.amazonaws.com");
    assert_eq!(start["insightDetails"]["insightType"], "ApiCallRateInsight");
    let end = records.iter().find(|r| r["insightDetails"]["state"] == "End").expect("an End Insights event");
    assert_eq!(start["sharedEventID"], end["sharedEventID"]);

    let data = ct
        .list_insights_data()
        .insight_source(&arn)
        .data_type(aws_sdk_cloudtrail::types::ListInsightsDataType::InsightsEvents)
        .dimensions(aws_sdk_cloudtrail::types::ListInsightsDataDimensionKey::EventName, "CreateGroup")
        .send()
        .await
        .unwrap();
    assert_eq!(data.events().len(), 2);

    let metrics = ct
        .list_insights_metric_data()
        .event_source("iam.amazonaws.com")
        .event_name("CreateGroup")
        .insight_type(InsightType::ApiCallRateInsight)
        .period(60)
        .data_type(aws_sdk_cloudtrail::types::InsightsMetricDataType::NonZeroData)
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.values().iter().sum::<f64>(), 31.0);

    // Insights log files come with the trail's next batch of log files.
    advance(&mws, 301).await;
    let mut keys = Vec::new();
    for _ in 0..40 {
        let out = s3
            .list_objects_v2()
            .bucket("insights-trail")
            .prefix(format!("AWSLogs/{ACCOUNT}/CloudTrail-Insight/us-east-1/"))
            .send()
            .await
            .unwrap();
        keys = out.contents().iter().filter_map(|o| o.key().map(str::to_string)).collect();
        if !keys.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(!keys.is_empty(), "no Insights log file");
    reset_clock(&mws).await;
    mws.stop().await;
}

#[tokio::test]
async fn imports_read_trail_log_files_back_from_s3() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);

    s3.create_bucket().bucket("old-logs").send().await.unwrap();
    let records = json!({"Records": [
        {"eventVersion":"1.11","eventTime":"2025-01-02T03:04:05Z","eventSource":"s3.amazonaws.com",
         "eventName":"DeleteBucket","awsRegion":"us-east-1","eventID":"11111111-1111-1111-1111-111111111111",
         "eventCategory":"Management","managementEvent":true,"readOnly":false,
         "userIdentity":{"type":"Root","accountId":ACCOUNT}}]});
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(records.to_string().as_bytes()).unwrap();
    let key = format!("AWSLogs/{ACCOUNT}/CloudTrail/us-east-1/2025/01/02/{ACCOUNT}_CloudTrail_us-east-1_x.json.gz");
    s3.put_object().bucket("old-logs").key(&key).body(gz.finish().unwrap().into()).send().await.unwrap();
    let bad = format!("AWSLogs/{ACCOUNT}/CloudTrail/us-east-1/2025/01/02/broken.json.gz");
    s3.put_object().bucket("old-logs").key(&bad).body(b"not gzip".to_vec().into()).send().await.unwrap();

    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("importer").assume_role_policy_document(trust).send().await.unwrap();
    iam.put_role_policy()
        .role_name("importer")
        .policy_name("read")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListBucket","s3:GetObject"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    let eds = ct.create_event_data_store().name("history").send().await.unwrap().event_data_store_arn.unwrap();
    let source = ImportSource::builder()
        .s3(S3ImportSource::builder()
            .s3_location_uri("s3://old-logs/AWSLogs/")
            .s3_bucket_region("us-east-1")
            .s3_bucket_access_role_arn(role.role().unwrap().arn())
            .build()
            .unwrap())
        .build();
    let started = ct.start_import().destinations(&eds).import_source(source).send().await.unwrap();
    let import_id = started.import_id().unwrap().to_string();

    let got = ct.get_import().import_id(&import_id).send().await.unwrap();
    assert_eq!(got.import_status().map(|s| s.as_str()), Some("COMPLETED"));
    let stats = got.import_statistics().unwrap();
    assert_eq!(stats.events_completed(), Some(1));
    assert_eq!(stats.files_completed(), Some(1));
    assert_eq!(stats.failed_entries(), Some(1));
    let listed = ct.list_imports().destination(&eds).send().await.unwrap();
    assert_eq!(listed.imports().len(), 1);
    let failures = ct.list_import_failures().import_id(&import_id).send().await.unwrap();
    assert_eq!(failures.failures().len(), 1);
    assert!(failures.failures()[0].location().unwrap().ends_with("broken.json.gz"));
    let stopped = ct.stop_import().import_id(&import_id).send().await.unwrap();
    assert_eq!(stopped.import_status().map(|s| s.as_str()), Some("COMPLETED"));
    let unknown = ct.get_import().import_id("00000000-0000-0000-0000-000000000000").send().await.unwrap_err();
    assert_eq!(code(unknown.into_service_error()), "ImportNotFoundException");

    let id = eds.rsplit('/').next().unwrap();
    let found = rows(&ct, format!("SELECT eventName FROM {id} WHERE eventName = 'DeleteBucket'")).await;
    assert_eq!(found, vec![vec![("eventName".to_string(), "DeleteBucket".to_string())]]);
    mws.stop().await;
}

#[tokio::test]
async fn channels_take_audit_events_from_cloudtrail_data() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let data = aws_sdk_cloudtraildata::Client::new(&cfg);

    let eds = ct
        .create_event_data_store()
        .name("partner-events")
        .advanced_event_selectors(activity_selector())
        .send()
        .await
        .unwrap()
        .event_data_store_arn
        .unwrap();
    let dest = Destination::builder().r#type(DestinationType::EventDataStore).location(&eds).build().unwrap();
    let channel = ct.create_channel().name("app").source("Custom").destinations(dest).send().await.unwrap();
    let channel_arn = channel.channel_arn().unwrap().to_string();
    let renamed = ct.update_channel().channel(&channel_arn).name("app-events").send().await.unwrap();
    assert_eq!(renamed.name(), Some("app-events"));

    let event = json!({"version":"1.0","userIdentity":{"type":"CustomUser","principalId":"alice"},
        "eventSource":"myapp.example.com","eventName":"Login","eventTime":"2026-11-05T10:00:00Z",
        "UID":"u-1","additionalEventData":{"ok":true}})
    .to_string();
    let checksum = hex::encode(sha2_010::Sha256::digest(event.as_bytes()));
    let put = data
        .put_audit_events()
        .channel_arn(&channel_arn)
        .audit_events(
            aws_sdk_cloudtraildata::types::AuditEvent::builder()
                .id("e1")
                .event_data(&event)
                .event_data_checksum(checksum)
                .build()
                .unwrap(),
        )
        .audit_events(
            aws_sdk_cloudtraildata::types::AuditEvent::builder()
                .id("e2")
                .event_data(r#"{"version":"1.0"}"#)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.successful().len(), 1);
    assert_eq!(put.successful()[0].id(), "e1");
    assert_eq!(put.failed().len(), 1);
    assert_eq!(put.failed()[0].id(), "e2");

    let missing = data
        .put_audit_events()
        .channel_arn(format!("arn:aws:cloudtrail:us-east-1:{ACCOUNT}:channel/00000000-0000-0000-0000-000000000000"))
        .audit_events(aws_sdk_cloudtraildata::types::AuditEvent::builder().id("x").event_data("{}").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        aws_sdk_cloudtraildata::error::ProvideErrorMetadata::code(&missing.into_service_error()),
        Some("ChannelNotFound")
    );

    let id = eds.rsplit('/').next().unwrap();
    let found = rows(&ct, format!("SELECT eventData.eventName, eventData.userIdentity.principalId FROM {id}")).await;
    assert_eq!(found.len(), 1);
    assert!(found[0].iter().any(|(_, v)| v == "Login"), "{found:?}");
    assert!(found[0].iter().any(|(_, v)| v == "alice"), "{found:?}");
    mws.stop().await;
}

#[tokio::test]
async fn dashboards_queries_and_federation() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let eds = ct.create_event_data_store().name("dash").send().await.unwrap().event_data_store_arn.unwrap();
    let id = eds.rsplit('/').next().unwrap().to_string();

    let dashboard = ct.create_dashboard().name("ops").send().await.unwrap().dashboard_arn.unwrap();
    let widget = aws_sdk_cloudtrail::types::RequestWidget::builder()
        .query_statement(format!("SELECT eventName, COUNT(*) AS n FROM {id} GROUP BY eventName"))
        .view_properties("View", "Table")
        .build()
        .unwrap();
    let updated = ct
        .update_dashboard()
        .dashboard_id(&dashboard)
        .widgets(widget)
        .termination_protection_enabled(true)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.widgets().len(), 1);
    assert_eq!(updated.termination_protection_enabled(), Some(true));
    let protected = ct.delete_dashboard().dashboard_id(&dashboard).send().await.unwrap_err();
    assert_eq!(code(protected.into_service_error()), "ConflictException");

    // Queries run in the background: one still queued can be cancelled,
    // once.
    let q = ct.start_query().query_statement(format!("SELECT eventName FROM {id}")).send().await.unwrap();
    let cancelled = ct.cancel_query().query_id(q.query_id().unwrap()).send().await.unwrap();
    assert_eq!(cancelled.query_status().as_str(), "CANCELLED");
    let done = ct.cancel_query().query_id(q.query_id().unwrap()).send().await.unwrap_err();
    assert_eq!(code(done.into_service_error()), "InactiveQueryException");

    let generated =
        ct.generate_query().event_data_stores(&eds).prompt("Show me failed CreateUser calls").send().await.unwrap();
    let sql = generated.query_statement().unwrap();
    assert!(sql.contains("errorCode IS NOT NULL") && sql.contains("CreateUser"), "{sql}");
    ct.start_query().query_statement(sql).send().await.unwrap();

    let samples = ct.search_sample_queries().search_phrase("access denied").send().await.unwrap();
    assert!(!samples.search_results().is_empty());

    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("federation").assume_role_policy_document(trust).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    let enabled = ct.enable_federation().event_data_store(&eds).federation_role_arn(&role_arn).send().await.unwrap();
    assert_eq!(enabled.federation_status().map(|s| s.as_str()), Some("ENABLED"));
    let got = ct.get_event_data_store().event_data_store(&eds).send().await.unwrap();
    assert_eq!(got.federation_role_arn(), Some(role_arn.as_str()));
    ct.update_event_data_store().event_data_store(&eds).termination_protection_enabled(false).send().await.unwrap();
    let blocked = ct.delete_event_data_store().event_data_store(&eds).send().await.unwrap_err();
    assert_eq!(code(blocked.into_service_error()), "EventDataStoreFederationEnabledException");
    let disabled = ct.disable_federation().event_data_store(&eds).send().await.unwrap();
    assert_eq!(disabled.federation_status().map(|s| s.as_str()), Some("DISABLED"));
    ct.delete_event_data_store().event_data_store(&eds).send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn organization_delegated_administrators() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let orgs = aws_sdk_organizations::Client::new(&cfg);

    let none = ct.register_organization_delegated_admin().member_account_id("111122223333").send().await.unwrap_err();
    assert_eq!(code(none.into_service_error()), "OrganizationsNotInUseException");

    orgs.create_organization().send().await.unwrap();
    let out = orgs.create_account().email("audit@example.com").account_name("audit").send().await.unwrap();
    let request = out.create_account_status().unwrap().id().unwrap().to_string();
    let status = orgs.describe_create_account_status().create_account_request_id(request).send().await.unwrap();
    let member = status.create_account_status().unwrap().account_id().unwrap().to_string();

    let own = ct.register_organization_delegated_admin().member_account_id(ACCOUNT).send().await.unwrap_err();
    assert_eq!(code(own.into_service_error()), "CannotDelegateManagementAccountException");
    ct.register_organization_delegated_admin().member_account_id(&member).send().await.unwrap();
    let again = ct.register_organization_delegated_admin().member_account_id(&member).send().await.unwrap_err();
    assert_eq!(code(again.into_service_error()), "AccountRegisteredException");
    ct.deregister_organization_delegated_admin().delegated_admin_account_id(&member).send().await.unwrap();
    let gone =
        ct.deregister_organization_delegated_admin().delegated_admin_account_id(&member).send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "AccountNotRegisteredException");
    mws.stop().await;
}
