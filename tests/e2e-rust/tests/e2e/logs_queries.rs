//! CloudWatch Logs queries in OpenSearch SQL and PPL, and scheduled
//! queries that run and deliver their results, through the official Rust
//! SDK.

use std::time::Duration;

use aws_sdk_cloudwatchlogs::error::ProvideErrorMetadata;
use aws_sdk_cloudwatchlogs::types::{
    DestinationConfiguration, ExecutionStatus, InputLogEvent, LookupTableConfiguration, QueryLanguage, S3Configuration,
};
use aws_sdk_cloudwatchlogs::Client;
use mws_e2e::Mws;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

async fn group_with_events(logs: &Client, group: &str, messages: &[&str]) {
    logs.create_log_group().log_group_name(group).send().await.unwrap();
    logs.create_log_stream().log_group_name(group).log_stream_name("s").send().await.unwrap();
    let t = now_ms() - 5000;
    let mut put = logs.put_log_events().log_group_name(group).log_stream_name("s");
    for (i, m) in messages.iter().enumerate() {
        put = put.log_events(InputLogEvent::builder().timestamp(t + i as i64).message(*m).build().unwrap());
    }
    put.send().await.unwrap();
}

/// The rows of a finished query, as `field=value` strings.
async fn rows(logs: &Client, id: &str) -> Vec<Vec<String>> {
    let out = logs.get_query_results().query_id(id).send().await.unwrap();
    out.results()
        .iter()
        .map(|r| r.iter().map(|f| format!("{}={}", f.field().unwrap(), f.value().unwrap())).collect())
        .collect()
}

const EVENTS: &[&str] = &[
    r#"{"path":"/a","status":200,"ms":12}"#,
    r#"{"path":"/b","status":500,"ms":90}"#,
    r#"{"path":"/b","status":200,"ms":30}"#,
    r#"{"path":"/c","status":404,"ms":5}"#,
];

#[tokio::test]
async fn sql_and_ppl_queries() {
    let mws = Mws::start().await;
    let logs = Client::new(&mws.root_sdk_config().await);
    group_with_events(&logs, "/web", EVENTS).await;
    let (start, end) = (now_ms() / 1000 - 3600, now_ms() / 1000 + 60);

    // SQL names its log groups in FROM.
    let sql = logs
        .start_query()
        .query_language(QueryLanguage::Sql)
        .query_string(
            "SELECT path, COUNT(*) AS hits, MAX(ms) AS slowest FROM `logGroups(logGroupIdentifier: ['/web'])` \
             WHERE status BETWEEN 200 AND 599 GROUP BY path HAVING COUNT(*) > 1 ORDER BY hits DESC",
        )
        .start_time(start)
        .end_time(end)
        .send()
        .await
        .unwrap();
    assert_eq!(rows(&logs, sql.query_id().unwrap()).await, vec![vec!["path=/b", "hits=2", "slowest=90"]]);
    let got = logs.get_query_results().query_id(sql.query_id().unwrap()).send().await.unwrap();
    assert_eq!(got.query_language(), Some(&QueryLanguage::Sql));

    let filtered = logs
        .start_query()
        .query_language(QueryLanguage::Sql)
        .query_string("SELECT path, status FROM `/web` WHERE path LIKE '/b%' AND status <> 500")
        .start_time(start)
        .end_time(end)
        .send()
        .await
        .unwrap();
    assert_eq!(rows(&logs, filtered.query_id().unwrap()).await, vec![vec!["path=/b", "status=200"]]);

    let no_from = logs
        .start_query()
        .query_language(QueryLanguage::Sql)
        .query_string("SELECT path")
        .start_time(start)
        .end_time(end)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(no_from.code(), Some("MalformedQueryException"));

    // PPL runs on the log groups the request names.
    let ppl = logs
        .start_query()
        .query_language(QueryLanguage::Ppl)
        .log_group_identifiers("/web")
        .query_string("where status != 404 | stats avg(ms) as avg_ms, count() as n by path | sort - n | head 1")
        .start_time(start)
        .end_time(end)
        .send()
        .await
        .unwrap();
    assert_eq!(rows(&logs, ppl.query_id().unwrap()).await, vec![vec!["path=/b", "avg_ms=60", "n=2"]]);
    let top = logs
        .start_query()
        .query_language(QueryLanguage::Ppl)
        .log_group_identifiers("/web")
        .query_string("eval slow = ms > 20 | where slow | fields path, ms | sort ms")
        .start_time(start)
        .end_time(end)
        .send()
        .await
        .unwrap();
    assert_eq!(rows(&logs, top.query_id().unwrap()).await, vec![vec!["path=/b", "ms=30"], vec!["path=/b", "ms=90"]]);
    let bad = logs
        .start_query()
        .query_language(QueryLanguage::Ppl)
        .log_group_identifiers("/web")
        .query_string("frobnicate path")
        .start_time(start)
        .end_time(end)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(bad.code(), Some("MalformedQueryException"));
    let no_groups = logs
        .start_query()
        .query_language(QueryLanguage::Ppl)
        .query_string("fields path")
        .start_time(start)
        .end_time(end)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(no_groups.code(), Some("InvalidParameterException"));

    // Log group names starting with aws/ are reserved.
    let reserved = logs.create_log_group().log_group_name("aws/mine").send().await.unwrap_err().into_service_error();
    assert_eq!(reserved.code(), Some("InvalidParameterException"));
}

const LOGS_TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logs.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

#[tokio::test]
async fn scheduled_queries_run_and_deliver() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let logs = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    group_with_events(&logs, "/web", EVENTS).await;
    s3.create_bucket().bucket("query-results").send().await.unwrap();

    let role = iam.create_role().role_name("sq").assume_role_policy_document(LOGS_TRUST).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["logs:StartQuery", "logs:GetQueryResults", "logs:CreateLookupTable", "logs:UpdateLookupTable"], "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::query-results/*"}
        ]
    });
    iam.put_role_policy().role_name("sq").policy_name("run").policy_document(policy.to_string()).send().await.unwrap();
    // A role CloudWatch Logs may not assume.
    let untrusted = iam
        .create_role()
        .role_name("other")
        .assume_role_policy_document(LOGS_TRUST.replace("logs.amazonaws.com", "lambda.amazonaws.com"))
        .send()
        .await
        .unwrap();

    let created = logs
        .create_scheduled_query()
        .name("errors-by-path")
        .query_language(QueryLanguage::Cwli)
        .query_string("stats count(*) as n by path | sort path")
        .log_group_identifiers("/web")
        .schedule_expression("cron(* * * * ? *)")
        .start_time_offset(3600)
        .execution_role_arn(&role_arn)
        .destination_configuration(
            DestinationConfiguration::builder()
                .s3_configuration(
                    S3Configuration::builder()
                        .destination_identifier("s3://query-results/daily")
                        .role_arn(&role_arn)
                        .build()
                        .unwrap(),
                )
                .lookup_table_configuration(
                    LookupTableConfiguration::builder().table_name("paths").role_arn(&role_arn).build().unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let arn = created.scheduled_query_arn().unwrap().to_string();
    logs.create_scheduled_query()
        .name("cannot-run")
        .query_language(QueryLanguage::Sql)
        .query_string("SELECT COUNT(*) AS n FROM `/web`")
        .schedule_expression("cron(* * * * ? *)")
        .start_time_offset(3600)
        .execution_role_arn(untrusted.role().unwrap().arn())
        .send()
        .await
        .unwrap();
    let bad_sql = logs
        .create_scheduled_query()
        .name("bad")
        .query_language(QueryLanguage::Sql)
        .query_string("SELECT FROM WHERE")
        .schedule_expression("cron(* * * * ? *)")
        .execution_role_arn(&role_arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(bad_sql.code(), Some("ValidationException"));

    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 61}"#)).await;
    assert_eq!(status, 200);
    let mut history = Vec::new();
    for _ in 0..100 {
        // Any call lets the service see the moved clock.
        let out = logs
            .get_scheduled_query_history()
            .identifier(&arn)
            .start_time(0)
            .end_time(i64::MAX / 2)
            .send()
            .await
            .unwrap();
        history = out.trigger_history().to_vec();
        if !history.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let run = history.first().expect("the scheduled query ran");
    assert_eq!(run.execution_status(), Some(&ExecutionStatus::Complete), "{run:?}");
    let dests = run.destinations();
    assert_eq!(dests.len(), 2);
    assert!(dests.iter().all(|d| d.status().map(|s| s.as_str()) == Some("COMPLETE")), "{dests:?}");
    let query_id = run.query_id().unwrap();
    assert_eq!(
        rows(&logs, query_id).await,
        vec![vec!["path=/a", "n=1"], vec!["path=/b", "n=2"], vec!["path=/c", "n=1"]]
    );

    let key = format!("daily/{query_id}.json");
    assert_eq!(dests[0].processed_identifier(), Some(format!("s3://query-results/{key}").as_str()));
    let obj = s3.get_object().bucket("query-results").key(&key).send().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&obj.body.collect().await.unwrap().into_bytes()).unwrap();
    assert_eq!(body[1], serde_json::json!({"path": "/b", "n": "2"}));

    let tables = logs.describe_lookup_tables().send().await.unwrap();
    let table = tables.lookup_tables().iter().find(|t| t.lookup_table_name() == Some("paths")).unwrap();
    let got = logs.get_lookup_table().lookup_table_arn(table.lookup_table_arn().unwrap()).send().await.unwrap();
    assert_eq!(got.table_body(), Some("path,n\n/a,1\n/b,2\n/c,1"));

    let sq = logs.get_scheduled_query().identifier(&arn).send().await.unwrap();
    assert_eq!(sq.last_execution_status(), Some(&ExecutionStatus::Complete));
    assert!(sq.last_triggered_time().is_some());

    // The run whose role CloudWatch Logs cannot assume fails.
    let mut failed = Vec::new();
    for _ in 0..50 {
        let out = logs
            .get_scheduled_query_history()
            .identifier("cannot-run")
            .start_time(0)
            .end_time(i64::MAX / 2)
            .send()
            .await
            .unwrap();
        failed = out.trigger_history().to_vec();
        if !failed.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(failed[0].execution_status(), Some(&ExecutionStatus::Failed));
    assert!(failed[0].error_message().unwrap().contains("assume"));
}
