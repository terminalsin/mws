//! CloudWatch Logs work that runs after the call returns (Logs Insights
//! queries, export and import tasks), data protection at every way out,
//! the newer Logs Insights commands and the `AWS/Logs` vended metrics,
//! through the official Rust SDKs.

use std::time::Duration;

use aws_sdk_cloudwatchlogs::error::ProvideErrorMetadata;
use aws_sdk_cloudwatchlogs::types::{ExportTaskStatusCode, ImportStatus, InputLogEvent, QueryStatus};
use aws_sdk_cloudwatchlogs::Client;
use mws_e2e::{user_with_policy, Mws};

use crate::logs::{wait_export, wait_query};

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

async fn group_with_events(logs: &Client, group: &str, messages: &[&str]) -> i64 {
    logs.create_log_group().log_group_name(group).send().await.unwrap();
    logs.create_log_stream().log_group_name(group).log_stream_name("s").send().await.unwrap();
    put(logs, group, messages).await
}

async fn put(logs: &Client, group: &str, messages: &[&str]) -> i64 {
    let t = now_ms() - 5000;
    let mut put = logs.put_log_events().log_group_name(group).log_stream_name("s");
    for (i, m) in messages.iter().enumerate() {
        put = put.log_events(InputLogEvent::builder().timestamp(t + i as i64).message(*m).build().unwrap());
    }
    put.send().await.unwrap();
    t
}

async fn start(logs: &Client, group: &str, query: &str) -> String {
    let t = now_ms() / 1000;
    logs.start_query()
        .log_group_name(group)
        .start_time(t - 3600)
        .end_time(t + 60)
        .query_string(query)
        .send()
        .await
        .unwrap()
        .query_id
        .unwrap()
}

/// The rows of a finished query, as `field=value` strings.
async fn rows(logs: &Client, id: &str) -> Vec<Vec<String>> {
    let out = wait_query(logs, id).await;
    assert_eq!(out.status(), Some(&QueryStatus::Complete), "{out:?}");
    out.results()
        .iter()
        .map(|r| {
            r.iter()
                .filter(|f| f.field() != Some("@ptr"))
                .map(|f| format!("{}={}", f.field().unwrap(), f.value().unwrap()))
                .collect()
        })
        .collect()
}

const DATA_PROTECTION: &str = r#"{
  "Name": "mask-emails",
  "Version": "2021-06-01",
  "Statement": [
    {"Sid": "audit", "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
     "Operation": {"Audit": {"FindingsDestination": {}}}},
    {"Sid": "redact", "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
     "Operation": {"Deidentify": {"MaskConfig": {}}}}
  ]
}"#;

/// `@message` of the protected event, as readers without unmask see it.
const MASKED: &str = "@message=login by ***************";

async fn protected_group(logs: &Client, group: &str) {
    logs.create_log_group().log_group_name(group).send().await.unwrap();
    logs.create_log_stream().log_group_name(group).log_stream_name("s").send().await.unwrap();
    logs.put_data_protection_policy()
        .log_group_identifier(group)
        .policy_document(DATA_PROTECTION)
        .send()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    put(logs, group, &["login by ann@example.com"]).await;
}

#[tokio::test]
async fn queries_run_in_the_background() {
    let mws = Mws::start().await;
    let logs = Client::new(&mws.root_sdk_config().await);
    group_with_events(&logs, "/bg", &["one", "two"]).await;

    // Scheduled (or Running) first, Complete shortly after, over the
    // events as they were when the query started.
    let id = start(&logs, "/bg", "stats count(*) as n").await;
    let first = logs.get_query_results().query_id(&id).send().await.unwrap();
    assert!(matches!(first.status(), Some(QueryStatus::Scheduled | QueryStatus::Running)), "{first:?}");
    assert!(first.results().is_empty());
    put(&logs, "/bg", &["three"]).await;
    assert_eq!(rows(&logs, &id).await, vec![vec!["n=2"]]);

    // StopQuery cancels a query that has not finished, and only such.
    let id = start(&logs, "/bg", "fields @message").await;
    let stopped = logs.stop_query().query_id(&id).send().await.unwrap();
    assert!(stopped.success());
    let out = wait_query(&logs, &id).await;
    assert_eq!(out.status(), Some(&QueryStatus::Cancelled));
    let again = logs.stop_query().query_id(&id).send().await.unwrap_err();
    assert_eq!(again.into_service_error().code(), Some("InvalidParameterException"));

    // 30 queries at a time per account.
    let mut ids = Vec::new();
    for _ in 0..30 {
        ids.push(start(&logs, "/bg", "fields @message").await);
    }
    let t = now_ms() / 1000;
    let e = logs
        .start_query()
        .log_group_name("/bg")
        .start_time(t - 60)
        .end_time(t)
        .query_string("fields @message")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("LimitExceededException"));
    assert_eq!(e.message(), Some("Account maximum query concurrency limit of [30] reached."));
    for id in &ids {
        let _ = logs.stop_query().query_id(id).send().await;
    }
    let running = logs.describe_queries().status(QueryStatus::Running).send().await.unwrap();
    assert!(running.queries().is_empty());

    // Queries time out after 60 minutes on the emulated clock.
    let id = start(&logs, "/bg", "fields @message").await;
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 3700}"#)).await;
    assert_eq!(status, 200);
    logs.describe_log_groups().send().await.unwrap();
    assert_eq!(wait_query(&logs, &id).await.status(), Some(&QueryStatus::Timeout));
}

#[tokio::test]
async fn insights_masks_and_unmask_needs_permission() {
    let mws = Mws::start().await;
    let logs = Client::new(&mws.root_sdk_config().await);
    protected_group(&logs, "/pii").await;

    let masked = rows(&logs, &start(&logs, "/pii", "fields @message").await).await;
    assert_eq!(masked, vec![vec![MASKED]]);
    let clear = rows(&logs, &start(&logs, "/pii", "fields @message | unmask(@message)").await).await;
    assert_eq!(clear, vec![vec!["@message=login by ann@example.com"]]);
    // OpenSearch SQL results are masked too.
    let t = now_ms() / 1000;
    let sql = logs
        .start_query()
        .query_language(aws_sdk_cloudwatchlogs::types::QueryLanguage::Sql)
        .start_time(t - 3600)
        .end_time(t + 60)
        .query_string("SELECT `@message` FROM `/pii`")
        .send()
        .await
        .unwrap();
    assert_eq!(rows(&logs, sql.query_id().unwrap()).await, vec![vec![MASKED]]);

    // Without logs:Unmask the unmask command is refused.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:StartQuery","logs:GetQueryResults"],"Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "analyst", Some(policy)).await;
    let analyst = Client::new(&cfg);
    let masked = rows(&analyst, &start(&analyst, "/pii", "fields @message").await).await;
    assert_eq!(masked, vec![vec![MASKED]]);
    let e = analyst
        .start_query()
        .log_group_name("/pii")
        .start_time(t - 3600)
        .end_time(t + 60)
        .query_string("fields @message | unmask(@message)")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"));
    assert!(e.message().unwrap().contains("logs:Unmask"), "{e:?}");
}

#[tokio::test]
async fn export_tasks_run_in_the_background_one_at_a_time() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let logs = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    protected_group(&logs, "/exp").await;
    s3.create_bucket().bucket("archive").send().await.unwrap();
    let principal = serde_json::json!({"Service": "logs.us-east-1.amazonaws.com"});
    let policy = serde_json::json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": principal, "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::archive"},
        {"Effect": "Allow", "Principal": principal, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::archive/*"}
    ]});
    s3.put_bucket_policy().bucket("archive").policy(policy.to_string()).send().await.unwrap();
    let (from, to) = (now_ms() - 3_600_000, now_ms() + 60_000);
    let create = || logs.create_export_task().log_group_name("/exp").from(from).to(to).destination("archive");

    let first = create().send().await.unwrap().task_id.unwrap();
    let described = logs.describe_export_tasks().task_id(&first).send().await.unwrap();
    assert_eq!(described.export_tasks()[0].status().unwrap().code(), Some(&ExportTaskStatusCode::Pending));
    // One active export task per account.
    let e = create().send().await.unwrap_err().into_service_error();
    assert_eq!(e.code(), Some("LimitExceededException"));
    assert_eq!(e.message(), Some("Resource limit exceeded."));
    logs.cancel_export_task().task_id(&first).send().await.unwrap();
    let cancelled = wait_export(&logs, &first).await;
    assert_eq!(cancelled.status().unwrap().code(), Some(&ExportTaskStatusCode::Cancelled));

    let second = create().send().await.unwrap().task_id.unwrap();
    let done = wait_export(&logs, &second).await;
    assert_eq!(done.status().unwrap().code(), Some(&ExportTaskStatusCode::Completed), "{done:?}");
    assert!(done.execution_info().unwrap().completion_time().is_some());
    let obj = s3.get_object().bucket("archive").key(format!("exportedlogs/{second}/s/000000.gz")).send().await.unwrap();
    let gz = obj.body.collect().await.unwrap().into_bytes();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut text).unwrap();
    // Exports are masked like every other way out.
    assert!(text.trim_end().ends_with(&MASKED["@message=".len()..]), "{text}");
    let nothing = s3.list_objects_v2().bucket("archive").prefix(format!("exportedlogs/{first}/")).send().await.unwrap();
    assert!(nothing.contents().is_empty());
}

#[tokio::test]
async fn insights_pattern_diff_anomaly_unnest_lookup_source_filter_index() {
    let mws = Mws::start().await;
    let logs = Client::new(&mws.root_sdk_config().await);
    group_with_events(
        &logs,
        "/svc/api",
        &[
            "ERROR request 17 failed after 120 ms",
            "ERROR request 18 failed after 80 ms",
            "ERROR request 19 failed after 95 ms",
            "INFO user alice logged in",
            r#"{"user":"bob","tags":["a","b"]}"#,
        ],
    )
    .await;
    group_with_events(&logs, "/svc/worker", &["INFO job done"]).await;
    group_with_events(&logs, "/other", &["INFO elsewhere"]).await;

    let patterns =
        rows(&logs, &start(&logs, "/svc/api", "filter @message like /request/ | pattern @message").await).await;
    assert_eq!(patterns.len(), 1, "{patterns:?}");
    let p = &patterns[0];
    assert_eq!(p[0], "@pattern=ERROR request <*> failed after <*> ms");
    assert_eq!(p[1], "@ratio=1");
    assert_eq!(p[2], "@sampleCount=3");
    assert_eq!(p[3], "@severityLabel=ERROR");
    assert!(p[4].starts_with("@visualization=["), "{p:?}");

    // filterIndex filters like filter.
    let indexed = rows(&logs, &start(&logs, "/svc/api", "filterIndex user = \"bob\" | fields user").await).await;
    assert_eq!(indexed, vec![vec!["user=bob"]]);

    // unnest spreads an array over records.
    let tags = rows(
        &logs,
        &start(&logs, "/svc/api", "filter ispresent(user) | unnest tags into tag | fields tag | sort tag asc").await,
    )
    .await;
    assert_eq!(tags, vec![vec!["tag=a"], vec!["tag=b"]]);

    // lookup joins a lookup table.
    logs.create_lookup_table().lookup_table_name("users").table_body("user,team\nbob,core\n").send().await.unwrap();
    let joined = rows(
        &logs,
        &start(&logs, "/svc/api", "filter ispresent(user) | lookup users user OUTPUT team | fields user, team").await,
    )
    .await;
    assert_eq!(joined, vec![vec!["user=bob", "team=core"]]);

    // SOURCE picks the log groups by prefix, with none in the request.
    let t = now_ms() / 1000;
    let q = logs
        .start_query()
        .start_time(t - 3600)
        .end_time(t + 60)
        .query_string(
            "SOURCE logGroups(namePrefix: ['/svc'], class: 'STANDARD') | stats count(*) as n by @log | sort @log asc",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        rows(&logs, q.query_id().unwrap()).await,
        vec![vec!["@log=123456789012:/svc/api", "n=5"], vec!["@log=123456789012:/svc/worker", "n=1"]]
    );

    // diff compares with the period before: these patterns are all new.
    let diff =
        rows(&logs, &start(&logs, "/svc/api", "filter @message like /request/ | pattern @message | diff").await).await;
    assert_eq!(
        diff,
        vec![vec![
            "@pattern=ERROR request <*> failed after <*> ms",
            "@sampleCount=3",
            "@previousSampleCount=0",
            "@changeInSampleCount=3",
            "@diffType=NEW"
        ]]
    );
    // anomaly keeps the patterns whose count spikes.
    let anomalies = rows(&logs, &start(&logs, "/svc/api", "pattern @message | anomaly").await).await;
    assert!(anomalies.iter().any(|r| r[0] == "@pattern=ERROR request <*> failed after <*> ms"), "{anomalies:?}");

    let e = logs
        .start_query()
        .log_group_name("/svc/api")
        .start_time(t - 60)
        .end_time(t)
        .query_string("fields @message | anomaly")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("MalformedQueryException"));
}

#[tokio::test]
async fn vended_metrics_and_masked_subscription_deliveries() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let logs = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let kinesis = aws_sdk_kinesis::Client::new(&cfg);
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);

    kinesis.create_stream().stream_name("sink").shard_count(1).send().await.unwrap();
    // Subscriptions test-deliver to the stream, which must be ACTIVE.
    crate::kinesis::wait_active(&kinesis, "sink").await;
    let stream_arn = kinesis
        .describe_stream_summary()
        .stream_name("sink")
        .send()
        .await
        .unwrap()
        .stream_description_summary
        .unwrap()
        .stream_arn;
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logs.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("cwl").assume_role_policy_document(trust).send().await.unwrap();
    iam.put_role_policy()
        .role_name("cwl")
        .policy_name("put")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kinesis:PutRecord","Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    logs.create_log_group().log_group_name("/sub").send().await.unwrap();
    logs.create_log_stream().log_group_name("/sub").log_stream_name("s").send().await.unwrap();
    logs.put_data_protection_policy()
        .log_group_identifier("/sub")
        .policy_document(DATA_PROTECTION)
        .send()
        .await
        .unwrap();
    logs.put_subscription_filter()
        .log_group_name("/sub")
        .filter_name("all")
        .filter_pattern("")
        .destination_arn(&stream_arn)
        .role_arn(role.role().unwrap().arn())
        .send()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    put(&logs, "/sub", &["mail carol@example.com", "plain"]).await;

    // The delivered DATA_MESSAGE is masked.
    let shard = kinesis.list_shards().stream_name("sink").send().await.unwrap().shards()[0].shard_id().to_string();
    let it = kinesis
        .get_shard_iterator()
        .stream_name("sink")
        .shard_id(shard)
        .shard_iterator_type(aws_sdk_kinesis::types::ShardIteratorType::TrimHorizon)
        .send()
        .await
        .unwrap()
        .shard_iterator
        .unwrap();
    let records = kinesis.get_records().shard_iterator(it).send().await.unwrap();
    let data: Vec<serde_json::Value> = records
        .records()
        .iter()
        .map(|r| {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(r.data().as_ref()), &mut text).unwrap();
            serde_json::from_str(&text).unwrap()
        })
        .collect();
    let message = data.iter().find(|d| d["messageType"] == "DATA_MESSAGE").expect("a data message");
    assert_eq!(message["logEvents"][0]["message"], format!("mail {}", "*".repeat("carol@example.com".len())));

    // AWS/Logs metrics: incoming per log group and for the account, and
    // forwarded per subscription filter.
    let mut names = Vec::new();
    for _ in 0..50 {
        let listed = cw.list_metrics().namespace("AWS/Logs").send().await.unwrap();
        names = listed
            .metrics()
            .iter()
            .map(|m| {
                let dims: Vec<String> =
                    m.dimensions().iter().map(|d| format!("{}={}", d.name().unwrap(), d.value().unwrap())).collect();
                format!("{} {}", m.metric_name().unwrap(), dims.join(","))
            })
            .collect();
        if names.iter().any(|n| n.starts_with("ForwardedLogEvents")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for want in ["IncomingBytes LogGroupName=/sub", "IncomingLogEvents LogGroupName=/sub", "IncomingLogEvents "] {
        assert!(names.iter().any(|n| n == want), "{want} not in {names:?}");
    }
    assert!(
        names.iter().any(|n| n.starts_with("ForwardedLogEvents")
            && n.contains("FilterName=all")
            && n.contains("DestinationType=Kinesis")
            && n.contains("LogGroupName=/sub")),
        "{names:?}"
    );
    let end = aws_sdk_cloudwatch::primitives::DateTime::from_millis(now_ms() + 60_000);
    let begin = aws_sdk_cloudwatch::primitives::DateTime::from_millis(now_ms() - 600_000);
    let stats = cw
        .get_metric_statistics()
        .namespace("AWS/Logs")
        .metric_name("IncomingLogEvents")
        .dimensions(aws_sdk_cloudwatch::types::Dimension::builder().name("LogGroupName").value("/sub").build())
        .start_time(begin)
        .end_time(end)
        .period(3600)
        .statistics(aws_sdk_cloudwatch::types::Statistic::Sum)
        .send()
        .await
        .unwrap();
    assert_eq!(stats.datapoints().iter().filter_map(|d| d.sum()).sum::<f64>(), 2.0);
}

#[tokio::test]
async fn imports_copy_cloudtrail_lake_events() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let logs = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let eds = ct.create_event_data_store().name("audit").send().await.unwrap();
    let eds_arn = eds.event_data_store_arn().unwrap().to_string();
    let eds_id = eds_arn.rsplit('/').next().unwrap().to_string();
    iam.create_user().user_name("imported-user").send().await.unwrap();

    // The role must trust CloudTrail and may read the store.
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("import").assume_role_policy_document(trust).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    let import = || logs.create_import_task().import_source_arn(&eds_arn).import_role_arn(&role_arn);
    let e = import().send().await.unwrap_err().into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"), "{e:?}");
    iam.put_role_policy()
        .role_name("import")
        .policy_name("read")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudtrail:GetEventDataStoreData","logs:CreateLogGroup","logs:CreateLogStream","logs:PutResourcePolicy"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    let started = import().send().await.unwrap();
    let id = started.import_id().unwrap().to_string();
    let group = format!("/aws/cloudtrail/{eds_id}");
    assert_eq!(
        started.import_destination_arn(),
        Some(format!("arn:aws:logs:us-east-1:123456789012:log-group:{group}").as_str())
    );
    let mut task = None;
    for _ in 0..100 {
        let d = logs.describe_import_tasks().import_id(&id).send().await.unwrap();
        let t = d.imports()[0].clone();
        if t.import_status() != Some(&ImportStatus::InProgress) {
            task = Some(t);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let task = task.expect("import finished");
    assert_eq!(task.import_status(), Some(&ImportStatus::Completed), "{task:?}");
    assert!(task.import_statistics().unwrap().bytes_imported().unwrap() > 0);
    let batches = logs.describe_import_task_batches().import_id(&id).send().await.unwrap();
    assert!(!batches.import_batches().is_empty());
    assert!(batches.import_batches().iter().all(|b| b.status() == &ImportStatus::Completed));

    let events = logs.filter_log_events().log_group_name(&group).filter_pattern("imported-user").send().await.unwrap();
    assert!(!events.events().is_empty(), "no imported CreateUser event");
    let streams = logs.describe_log_streams().log_group_name(&group).send().await.unwrap();
    assert_eq!(streams.log_streams()[0].log_stream_name(), Some("123456789012_CloudTrail_us-east-1"));

    // A finished import cannot be cancelled.
    let e = logs.cancel_import_task().import_id(&id).send().await.unwrap_err().into_service_error();
    assert_eq!(e.code(), Some("InvalidOperationException"));
}
