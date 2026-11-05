//! CloudTrail through the official Rust SDKs: trails that deliver real log
//! files (and signed digests) to S3, CloudWatch Logs and EventBridge, the
//! event history, and CloudTrail Lake queries.

use std::io::Read;
use std::time::Duration;

use aws_sdk_cloudtrail::types::{LookupAttribute, LookupAttributeKey, ReadWriteType, Tag};
use mws_e2e::Mws;
use serde_json::{json, Value};

const ACCOUNT: &str = "123456789012";

fn bucket_policy(bucket: &str) -> String {
    json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl",
         "Resource":format!("arn:aws:s3:::{bucket}")},
        {"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject",
         "Resource":format!("arn:aws:s3:::{bucket}/AWSLogs/{ACCOUNT}/*"),
         "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}]})
    .to_string()
}

async fn trail_bucket(s3: &aws_sdk_s3::Client, bucket: &str) {
    s3.create_bucket().bucket(bucket).send().await.unwrap();
    s3.put_bucket_policy().bucket(bucket).policy(bucket_policy(bucket)).send().await.unwrap();
}

/// Keys under `prefix`, waiting until at least one is there.
async fn keys(s3: &aws_sdk_s3::Client, bucket: &str, prefix: &str) -> Vec<String> {
    for _ in 0..60 {
        let out = s3.list_objects_v2().bucket(bucket).prefix(prefix).send().await.unwrap();
        let keys: Vec<String> = out.contents().iter().filter_map(|o| o.key().map(str::to_string)).collect();
        if !keys.is_empty() {
            return keys;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Vec::new()
}

async fn records(s3: &aws_sdk_s3::Client, bucket: &str, key: &str) -> Vec<Value> {
    let body = s3.get_object().bucket(bucket).key(key).send().await.unwrap().body.collect().await.unwrap();
    let mut plain = String::new();
    flate2::read::GzDecoder::new(&body.into_bytes()[..]).read_to_string(&mut plain).unwrap();
    let file: Value = serde_json::from_str(&plain).unwrap();
    file["Records"].as_array().unwrap().clone()
}

/// Every record delivered under the trail's log prefix so far.
async fn all_records(s3: &aws_sdk_s3::Client, bucket: &str, want: &str) -> Vec<Value> {
    let prefix = format!("AWSLogs/{ACCOUNT}/CloudTrail/us-east-1/");
    for _ in 0..60 {
        let mut all = Vec::new();
        for key in keys(s3, bucket, &prefix).await {
            all.extend(records(s3, bucket, &key).await);
        }
        if all.iter().any(|r| r["eventName"] == want) {
            return all;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("no {want} record was delivered to s3://{bucket}/{prefix}");
}

#[tokio::test]
async fn trails_deliver_log_files_and_digests_to_s3() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);

    // Without a bucket policy CloudTrail cannot write.
    s3.create_bucket().bucket("no-policy").send().await.unwrap();
    let err = ct.create_trail().name("trail").s3_bucket_name("no-policy").send().await.unwrap_err();
    let err = err.into_service_error();
    assert_eq!(err.meta().code(), Some("InsufficientS3BucketPolicyException"), "{err:?}");
    let err = ct.create_trail().name("trail").s3_bucket_name("missing-bucket").send().await.unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("S3BucketDoesNotExistException"));
    let err = ct.create_trail().name("-bad").s3_bucket_name("no-policy").send().await.unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("InvalidTrailNameException"));

    trail_bucket(&s3, "trail-logs").await;
    let created = ct
        .create_trail()
        .name("main")
        .s3_bucket_name("trail-logs")
        .is_multi_region_trail(true)
        .enable_log_file_validation(true)
        .tags_list(Tag::builder().key("team").value("sec").build().unwrap())
        .send()
        .await
        .unwrap();
    let trail_arn = created.trail_arn().unwrap().to_string();
    assert_eq!(trail_arn, format!("arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/main"));
    assert_eq!(created.is_multi_region_trail(), Some(true));
    assert_eq!(created.log_file_validation_enabled(), Some(true));
    let dup = ct.create_trail().name("main").s3_bucket_name("trail-logs").send().await.unwrap_err();
    assert_eq!(dup.into_service_error().meta().code(), Some("TrailAlreadyExistsException"));

    let status = ct.get_trail_status().name("main").send().await.unwrap();
    assert_eq!(status.is_logging(), Some(false));
    ct.start_logging().name(&trail_arn).send().await.unwrap();
    assert_eq!(ct.get_trail_status().name("main").send().await.unwrap().is_logging(), Some(true));

    iam.create_user().user_name("audited").send().await.unwrap();
    let records = all_records(&s3, "trail-logs", "CreateUser").await;
    let create = records.iter().find(|r| r["eventName"] == "CreateUser").unwrap();
    assert_eq!(create["eventSource"], "iam.amazonaws.com");
    assert_eq!(create["eventVersion"], "1.11");
    assert_eq!(create["requestParameters"]["userName"], "audited");
    assert_eq!(create["responseElements"]["user"]["userName"], "audited");
    assert_eq!(create["userIdentity"]["type"], "Root");
    assert_eq!(create["userIdentity"]["accountId"], ACCOUNT);
    assert_eq!(create["readOnly"], false);
    assert_eq!(create["managementEvent"], true);
    assert_eq!(create["recipientAccountId"], ACCOUNT);
    assert_eq!(create["eventType"], "AwsApiCall");

    // Failed calls carry their error.
    let missing = iam.get_user().user_name("nobody").send().await.unwrap_err();
    assert!(missing.into_service_error().is_no_such_entity_exception());
    iam.delete_user().user_name("nobody").send().await.unwrap_err();
    let records = all_records(&s3, "trail-logs", "DeleteUser").await;
    let failed = records.iter().find(|r| r["eventName"] == "DeleteUser").unwrap();
    assert_eq!(failed["errorCode"], "NoSuchEntityException");
    assert!(failed["errorMessage"].as_str().unwrap().contains("nobody"), "{failed}");

    // Digest files chain the log files and are signed with a key that
    // ListPublicKeys returns.
    let digests = keys(&s3, "trail-logs", &format!("AWSLogs/{ACCOUNT}/CloudTrail-Digest/us-east-1/")).await;
    assert!(!digests.is_empty(), "no digest files");
    let head = s3.head_object().bucket("trail-logs").key(&digests[0]).send().await.unwrap();
    let meta = head.metadata().unwrap();
    assert_eq!(meta.get("signature-algorithm").map(String::as_str), Some("SHA256withRSA"));
    assert!(meta.contains_key("signature"));
    let keys = ct.list_public_keys().send().await.unwrap();
    assert!(!keys.public_key_list().is_empty());

    let described = ct.describe_trails().trail_name_list("main").send().await.unwrap();
    assert_eq!(described.trail_list()[0].s3_bucket_name(), Some("trail-logs"));
    let tags = ct.list_tags().resource_id_list(&trail_arn).send().await.unwrap();
    assert_eq!(tags.resource_tag_list()[0].tags_list()[0].key(), "team");
    ct.remove_tags()
        .resource_id(&trail_arn)
        .tags_list(Tag::builder().key("team").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = ct.list_tags().resource_id_list(&trail_arn).send().await.unwrap();
    assert!(tags.resource_tag_list()[0].tags_list().is_empty());

    // Write-only management events leave reads out.
    let sel = aws_sdk_cloudtrail::types::EventSelector::builder()
        .read_write_type(ReadWriteType::WriteOnly)
        .include_management_events(true)
        .build();
    ct.put_event_selectors().trail_name("main").event_selectors(sel).send().await.unwrap();
    let got = ct.get_event_selectors().trail_name("main").send().await.unwrap();
    assert_eq!(got.event_selectors()[0].read_write_type(), Some(&ReadWriteType::WriteOnly));

    ct.stop_logging().name("main").send().await.unwrap();
    ct.delete_trail().name("main").send().await.unwrap();
    let gone = ct.get_trail().name("main").send().await.unwrap_err();
    assert_eq!(gone.into_service_error().meta().code(), Some("TrailNotFoundException"));
    mws.stop().await;
}

#[tokio::test]
async fn lookup_events_searches_the_event_history() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);

    // The event history needs no trail.
    for name in ["alice", "bob", "carol"] {
        iam.create_user().user_name(name).send().await.unwrap();
    }
    let by_name = |name: &str| {
        LookupAttribute::builder().attribute_key(LookupAttributeKey::EventName).attribute_value(name).build().unwrap()
    };
    let found = ct.lookup_events().lookup_attributes(by_name("CreateUser")).send().await.unwrap();
    assert_eq!(found.events().len(), 3);
    // Newest first.
    let first: Value = serde_json::from_str(found.events()[0].cloud_trail_event().unwrap()).unwrap();
    assert_eq!(first["requestParameters"]["userName"], "carol");
    assert_eq!(found.events()[0].event_source(), Some("iam.amazonaws.com"));
    assert_eq!(found.events()[0].read_only(), Some("false"));
    assert!(found.events()[0].resources().iter().any(|r| r.resource_name() == Some("carol")));

    let page = ct.lookup_events().lookup_attributes(by_name("CreateUser")).max_results(2).send().await.unwrap();
    assert_eq!(page.events().len(), 2);
    let rest = ct
        .lookup_events()
        .lookup_attributes(by_name("CreateUser"))
        .max_results(2)
        .next_token(page.next_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(rest.events().len(), 1);
    assert_eq!(rest.next_token(), None);

    let by_resource = LookupAttribute::builder()
        .attribute_key(LookupAttributeKey::ResourceName)
        .attribute_value("bob")
        .build()
        .unwrap();
    let bob = ct.lookup_events().lookup_attributes(by_resource).send().await.unwrap();
    assert_eq!(bob.events().len(), 1);

    let two = ct.lookup_events().lookup_attributes(by_name("A")).lookup_attributes(by_name("B")).send().await;
    assert_eq!(two.unwrap_err().into_service_error().meta().code(), Some("InvalidLookupAttributesException"));
    // The model's range constraint answers first.
    let big = ct.lookup_events().max_results(51).send().await.unwrap_err();
    assert_eq!(big.into_service_error().meta().code(), Some("ValidationException"));
    mws.stop().await;
}

#[tokio::test]
async fn api_calls_reach_eventbridge_and_cloudwatch_logs() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);

    let url = sqs.create_queue().queue_name("api-calls").send().await.unwrap().queue_url.unwrap();
    let queue_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:api-calls");
    let policy = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":queue_arn}]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    let pattern =
        r#"{"source":["aws.iam"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventName":["CreateRole"]}}"#;
    eb.put_rule().name("roles").event_pattern(pattern).send().await.unwrap();
    eb.put_targets()
        .rule("roles")
        .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(&queue_arn).build().unwrap())
        .send()
        .await
        .unwrap();

    // CloudTrail writes to the log group as the trail's role.
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("trail-logs").assume_role_policy_document(trust).send().await.unwrap();
    iam.put_role_policy()
        .role_name("trail-logs")
        .policy_name("logs")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    logs.create_log_group().log_group_name("trail").send().await.unwrap();
    let group_arn = format!("arn:aws:logs:us-east-1:{ACCOUNT}:log-group:trail:*");
    trail_bucket(&s3, "eb-trail").await;
    ct.create_trail()
        .name("to-logs")
        .s3_bucket_name("eb-trail")
        .cloud_watch_logs_log_group_arn(&group_arn)
        .cloud_watch_logs_role_arn(role.role().unwrap().arn())
        .send()
        .await
        .unwrap();
    ct.start_logging().name("to-logs").send().await.unwrap();

    iam.create_role().role_name("watched").assume_role_policy_document(trust).send().await.unwrap();

    let mut event = None;
    for _ in 0..60 {
        let got = sqs.receive_message().queue_url(&url).wait_time_seconds(1).send().await.unwrap();
        if let Some(m) = got.messages().first() {
            event = Some(serde_json::from_str::<Value>(m.body().unwrap()).unwrap());
            break;
        }
    }
    let event = event.expect("no CreateRole event reached the queue");
    assert_eq!(event["source"], "aws.iam");
    assert_eq!(event["detail-type"], "AWS API Call via CloudTrail");
    assert_eq!(event["detail"]["eventName"], "CreateRole");
    assert_eq!(event["detail"]["requestParameters"]["roleName"], "watched");

    let stream = format!("{ACCOUNT}_CloudTrail_us-east-1");
    let mut found = Vec::new();
    for _ in 0..60 {
        if let Ok(out) = logs.filter_log_events().log_group_name("trail").log_stream_names(&stream).send().await {
            found = out.events().iter().filter_map(|e| serde_json::from_str::<Value>(e.message()?).ok()).collect();
            if found.iter().any(|r| r["eventName"] == "CreateRole") {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(found.iter().any(|r| r["eventName"] == "CreateRole"), "{found:?}");
    let status = ct.get_trail_status().name("to-logs").send().await.unwrap();
    assert!(status.latest_cloud_watch_logs_delivery_time().is_some());
    mws.stop().await;
}

#[tokio::test]
async fn lake_event_data_stores_answer_sql_queries() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);

    let eds = ct.create_event_data_store().name("audit").send().await.unwrap();
    let arn = eds.event_data_store_arn().unwrap().to_string();
    assert_eq!(eds.retention_period(), Some(366));
    assert_eq!(eds.termination_protection_enabled(), Some(true));
    assert_eq!(eds.multi_region_enabled(), Some(true));
    let id = arn.rsplit('/').next().unwrap().to_string();
    let dup = ct.create_event_data_store().name("audit").send().await.unwrap_err();
    assert_eq!(dup.into_service_error().meta().code(), Some("EventDataStoreAlreadyExistsException"));

    for name in ["dave", "erin"] {
        iam.create_user().user_name(name).send().await.unwrap();
    }
    iam.list_users().send().await.unwrap();

    let q = ct
        .start_query()
        .query_statement(format!(
            "SELECT eventName, element_at(requestParameters, 'userName') AS userName FROM {id} \
             WHERE eventSource = 'iam.amazonaws.com' AND readOnly = false ORDER BY eventTime"
        ))
        .send()
        .await
        .unwrap();
    let query_id = q.query_id().unwrap().to_string();
    let results = ct.get_query_results().query_id(&query_id).send().await.unwrap();
    assert_eq!(results.query_status().map(|s| s.as_str()), Some("FINISHED"));
    let rows: Vec<(String, String)> = results
        .query_result_rows()
        .iter()
        .map(|row| {
            let get = |col: &str| row.iter().find_map(|c| c.get(col).cloned()).unwrap_or_default();
            (get("eventName"), get("userName"))
        })
        .collect();
    assert_eq!(rows, vec![("CreateUser".into(), "dave".into()), ("CreateUser".into(), "erin".into())]);

    let counts = ct
        .start_query()
        .query_statement(format!("SELECT eventName, COUNT(*) AS n FROM {arn} WHERE eventSource = 'iam.amazonaws.com' GROUP BY eventName ORDER BY n DESC"))
        .send()
        .await
        .unwrap();
    let results = ct.get_query_results().query_id(counts.query_id().unwrap()).send().await.unwrap();
    let top = &results.query_result_rows()[0];
    assert!(top.iter().any(|c| c.get("eventName").map(String::as_str) == Some("CreateUser")), "{top:?}");
    assert!(top.iter().any(|c| c.get("n").map(String::as_str) == Some("2")), "{top:?}");

    let described = ct.describe_query().query_id(&query_id).send().await.unwrap();
    assert_eq!(described.query_statistics().unwrap().events_matched(), Some(2));
    let listed = ct.list_queries().event_data_store(&arn).send().await.unwrap();
    assert_eq!(listed.queries().len(), 2);

    let bad = ct.start_query().query_statement("DELETE FROM x").send().await.unwrap_err();
    assert_eq!(bad.into_service_error().meta().code(), Some("InvalidQueryStatementException"));
    let unknown = ct
        .start_query()
        .query_statement("SELECT eventName FROM 00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(unknown.into_service_error().meta().code(), Some("EventDataStoreNotFoundException"));

    // Stopped ingestion keeps new events out.
    ct.stop_event_data_store_ingestion().event_data_store(&arn).send().await.unwrap();
    let got = ct.get_event_data_store().event_data_store(&arn).send().await.unwrap();
    assert_eq!(got.status().map(|s| s.as_str()), Some("STOPPED_INGESTION"));
    iam.create_user().user_name("frank").send().await.unwrap();
    ct.start_event_data_store_ingestion().event_data_store(&arn).send().await.unwrap();

    // Termination protection, then deletion and restore.
    let protected = ct.delete_event_data_store().event_data_store(&arn).send().await.unwrap_err();
    assert_eq!(protected.into_service_error().meta().code(), Some("EventDataStoreTerminationProtectedException"));
    ct.update_event_data_store().event_data_store(&arn).termination_protection_enabled(false).send().await.unwrap();
    ct.delete_event_data_store().event_data_store(&arn).send().await.unwrap();
    let got = ct.get_event_data_store().event_data_store(&arn).send().await.unwrap();
    assert_eq!(got.status().map(|s| s.as_str()), Some("PENDING_DELETION"));
    ct.restore_event_data_store().event_data_store(&arn).send().await.unwrap();
    let listed = ct.list_event_data_stores().send().await.unwrap();
    assert_eq!(listed.event_data_stores().len(), 1);
    let got = ct.get_event_data_store().event_data_store(&arn).send().await.unwrap();
    assert_eq!(got.status().map(|s| s.as_str()), Some("ENABLED"));
    mws.stop().await;
}

#[tokio::test]
async fn channels_dashboards_and_resource_policies() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);

    // Channels deliver to event data stores of integration events.
    let selector = aws_sdk_cloudtrail::types::AdvancedEventSelector::builder()
        .name("integration")
        .field_selectors(
            aws_sdk_cloudtrail::types::AdvancedFieldSelector::builder()
                .field("eventCategory")
                .equals("ActivityAuditLog")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let eds = ct.create_event_data_store().name("partners").advanced_event_selectors(selector).send().await.unwrap();
    let eds_arn = eds.event_data_store_arn().unwrap().to_string();
    let dest = aws_sdk_cloudtrail::types::Destination::builder()
        .r#type(aws_sdk_cloudtrail::types::DestinationType::EventDataStore)
        .location(&eds_arn)
        .build()
        .unwrap();
    let channel = ct.create_channel().name("partner").source("Custom").destinations(dest).send().await.unwrap();
    let channel_arn = channel.channel_arn().unwrap().to_string();
    let got = ct.get_channel().channel(&channel_arn).send().await.unwrap();
    assert_eq!(got.name(), Some("partner"));
    assert_eq!(ct.list_channels().send().await.unwrap().channels().len(), 1);

    let in_use =
        ct.update_event_data_store().event_data_store(&eds_arn).termination_protection_enabled(false).send().await;
    in_use.unwrap();
    let blocked = ct.delete_event_data_store().event_data_store(&eds_arn).send().await.unwrap_err();
    assert_eq!(blocked.into_service_error().meta().code(), Some("ChannelExistsForEDSException"));

    let policy = json!({"Version":"2012-10-17","Statement":[{"Sid":"partner","Effect":"Allow",
        "Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"cloudtrail-data:PutAuditEvents",
        "Resource":channel_arn}]})
    .to_string();
    ct.put_resource_policy().resource_arn(&channel_arn).resource_policy(&policy).send().await.unwrap();
    let got = ct.get_resource_policy().resource_arn(&channel_arn).send().await.unwrap();
    assert_eq!(got.resource_policy(), Some(policy.as_str()));
    ct.delete_resource_policy().resource_arn(&channel_arn).send().await.unwrap();
    let gone = ct.get_resource_policy().resource_arn(&channel_arn).send().await.unwrap_err();
    assert_eq!(gone.into_service_error().meta().code(), Some("ResourcePolicyNotFoundException"));
    ct.delete_channel().channel(&channel_arn).send().await.unwrap();

    let dashboard = ct.create_dashboard().name("overview").send().await.unwrap();
    let dashboard_arn = dashboard.dashboard_arn().unwrap().to_string();
    let got = ct.get_dashboard().dashboard_id(&dashboard_arn).send().await.unwrap();
    assert_eq!(got.r#type().map(|t| t.as_str()), Some("CUSTOM"));
    let refresh = ct.start_dashboard_refresh().dashboard_id(&dashboard_arn).send().await.unwrap();
    assert!(refresh.refresh_id().is_some());
    assert_eq!(ct.list_dashboards().send().await.unwrap().dashboards().len(), 1);
    ct.delete_dashboard().dashboard_id(&dashboard_arn).send().await.unwrap();
    assert!(ct.list_dashboards().send().await.unwrap().dashboards().is_empty());
    mws.stop().await;
}

#[tokio::test]
async fn cloudtrail_actions_need_permission() {
    let mws = Mws::start().await;
    let (_, cfg) = mws_e2e::user_with_policy(
        &mws,
        "reader",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudtrail:Describe*","cloudtrail:LookupEvents"],"Resource":"*"}]}"#),
    )
    .await;
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    ct.describe_trails().send().await.unwrap();
    ct.lookup_events().send().await.unwrap();
    let denied = ct.create_trail().name("x").s3_bucket_name("y").send().await.unwrap_err();
    assert_eq!(denied.into_service_error().meta().code(), Some("AccessDeniedException"));
    mws.stop().await;
}
