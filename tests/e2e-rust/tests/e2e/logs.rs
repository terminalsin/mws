//! CloudWatch Logs through the official Rust SDK.

use aws_sdk_cloudwatchlogs::error::ProvideErrorMetadata;
use aws_sdk_cloudwatchlogs::types::{InputLogEvent, OrderBy, QueryStatus};
use aws_sdk_cloudwatchlogs::Client;
use mws_e2e::{user_with_policy, Mws};

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn event(ts: i64, msg: &str) -> InputLogEvent {
    InputLogEvent::builder().timestamp(ts).message(msg).build().unwrap()
}

/// The results of a query once it has finished: queries run in the
/// background, `Scheduled` then `Running` then `Complete`.
pub(crate) async fn wait_query(
    logs: &Client,
    id: &str,
) -> aws_sdk_cloudwatchlogs::operation::get_query_results::GetQueryResultsOutput {
    for _ in 0..100 {
        let out = logs.get_query_results().query_id(id).send().await.unwrap();
        if !matches!(out.status(), Some(QueryStatus::Scheduled | QueryStatus::Running)) {
            return out;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("query {id} did not finish");
}

/// An export task once it has left `PENDING` and `RUNNING`.
pub(crate) async fn wait_export(logs: &Client, id: &str) -> aws_sdk_cloudwatchlogs::types::ExportTask {
    use aws_sdk_cloudwatchlogs::types::ExportTaskStatusCode as C;
    for _ in 0..100 {
        let out = logs.describe_export_tasks().task_id(id).send().await.unwrap();
        let task = out.export_tasks()[0].clone();
        if !matches!(task.status().and_then(|s| s.code()), Some(C::Pending | C::Running)) {
            return task;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("export task {id} did not finish");
}

async fn group_with_events(logs: &Client, group: &str, stream: &str, messages: &[(i64, &str)]) {
    logs.create_log_group().log_group_name(group).send().await.unwrap();
    logs.create_log_stream().log_group_name(group).log_stream_name(stream).send().await.unwrap();
    let mut put = logs.put_log_events().log_group_name(group).log_stream_name(stream);
    for (ts, m) in messages {
        put = put.log_events(event(*ts, m));
    }
    put.send().await.unwrap();
}

#[tokio::test]
#[allow(deprecated)] // the log-group tagging operations are still part of the API
async fn log_groups_streams_and_events() {
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    logs.create_log_group().log_group_name("/app/web").tags("team", "web").send().await.unwrap();
    let dup = logs.create_log_group().log_group_name("/app/web").send().await.unwrap_err();
    assert_eq!(code(dup.into_service_error()), "ResourceAlreadyExistsException");
    logs.create_log_group().log_group_name("/app/worker").send().await.unwrap();

    let groups = logs.describe_log_groups().log_group_name_prefix("/app/").send().await.unwrap();
    let names: Vec<_> = groups.log_groups().iter().filter_map(|g| g.log_group_name()).collect();
    assert_eq!(names, ["/app/web", "/app/worker"]);
    let web = &groups.log_groups()[0];
    assert_eq!(web.arn(), Some("arn:aws:logs:us-east-1:123456789012:log-group:/app/web:*"));
    assert_eq!(web.log_group_arn(), Some("arn:aws:logs:us-east-1:123456789012:log-group:/app/web"));
    assert_eq!(web.stored_bytes(), Some(0));
    let page = logs.describe_log_groups().limit(1).send().await.unwrap();
    assert_eq!(page.log_groups().len(), 1);
    let rest = logs.describe_log_groups().next_token(page.next_token().unwrap()).send().await.unwrap();
    assert_eq!(rest.log_groups()[0].log_group_name(), Some("/app/worker"));
    let listed = logs.list_log_groups().log_group_name_pattern("work").send().await.unwrap();
    assert_eq!(listed.log_groups().len(), 1);
    assert_eq!(listed.log_groups()[0].log_group_name(), Some("/app/worker"));
    let summaries = logs
        .list_aggregate_log_group_summaries()
        .group_by(aws_sdk_cloudwatchlogs::types::ListAggregateLogGroupSummariesGroupBy::DataSourceNameAndType)
        .send()
        .await
        .unwrap();
    assert!(!summaries.aggregate_log_group_summaries().is_empty());

    logs.create_log_stream().log_group_name("/app/web").log_stream_name("i-1").send().await.unwrap();
    logs.create_log_stream().log_group_name("/app/web").log_stream_name("i-2").send().await.unwrap();
    let missing = logs.create_log_stream().log_group_name("/nope").log_stream_name("s").send().await.unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");

    let t = now_ms() - 10_000;
    let put = logs
        .put_log_events()
        .log_group_name("/app/web")
        .log_stream_name("i-1")
        .log_events(event(t, "GET /index 200 12ms"))
        .log_events(event(t + 1, "GET /missing 404 3ms"))
        .log_events(event(t + 2, r#"{"level":"ERROR","latency":250}"#))
        .send()
        .await
        .unwrap();
    assert!(put.next_sequence_token().is_some());
    assert!(put.rejected_log_events_info().is_none());
    let unordered = logs
        .put_log_events()
        .log_group_name("/app/web")
        .log_stream_name("i-2")
        .log_events(event(t + 5, "b"))
        .log_events(event(t, "a"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(unordered.into_service_error()), "InvalidParameterException");
    let old = logs
        .put_log_events()
        .log_group_name("/app/web")
        .log_stream_name("i-2")
        .log_events(event(now_ms() - 15 * 86_400_000, "too old"))
        .send()
        .await
        .unwrap();
    assert_eq!(old.rejected_log_events_info().unwrap().too_old_log_event_end_index(), Some(0));
    logs.put_log_events()
        .log_group_name("/app/web")
        .log_stream_name("i-2")
        .log_events(event(t + 3, "ok"))
        .send()
        .await
        .unwrap();

    let got = logs
        .get_log_events()
        .log_group_name("/app/web")
        .log_stream_name("i-1")
        .start_from_head(true)
        .send()
        .await
        .unwrap();
    let messages: Vec<_> = got.events().iter().filter_map(|e| e.message()).collect();
    assert_eq!(messages, ["GET /index 200 12ms", "GET /missing 404 3ms", r#"{"level":"ERROR","latency":250}"#]);
    let paged = logs
        .get_log_events()
        .log_group_name("/app/web")
        .log_stream_name("i-1")
        .start_from_head(true)
        .limit(2)
        .send()
        .await
        .unwrap();
    assert_eq!(paged.events().len(), 2);
    let next = logs
        .get_log_events()
        .log_group_name("/app/web")
        .log_stream_name("i-1")
        .next_token(paged.next_forward_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(next.events().len(), 1);

    let filtered = logs.filter_log_events().log_group_name("/app/web").filter_pattern("404").send().await.unwrap();
    assert_eq!(filtered.events().len(), 1);
    assert_eq!(filtered.events()[0].log_stream_name(), Some("i-1"));
    let json =
        logs.filter_log_events().log_group_name("/app/web").filter_pattern("{ $.latency > 100 }").send().await.unwrap();
    assert_eq!(json.events().len(), 1);
    let delimited = logs
        .filter_log_events()
        .log_group_name("/app/web")
        .filter_pattern("[method, path, status=2*, ...]")
        .send()
        .await
        .unwrap();
    assert_eq!(delimited.events().len(), 1);
    let either = logs.filter_log_events().log_group_name("/app/web").filter_pattern("?404 ?ok").send().await.unwrap();
    assert_eq!(either.events().len(), 2);

    let streams = logs
        .describe_log_streams()
        .log_group_name("/app/web")
        .order_by(OrderBy::LastEventTime)
        .descending(true)
        .send()
        .await
        .unwrap();
    assert_eq!(streams.log_streams().len(), 2);
    let s1 = streams.log_streams().iter().find(|s| s.log_stream_name() == Some("i-1")).unwrap();
    assert_eq!(s1.first_event_timestamp(), Some(t));
    assert_eq!(s1.last_event_timestamp(), Some(t + 2));
    assert_eq!(s1.arn(), Some("arn:aws:logs:us-east-1:123456789012:log-group:/app/web:log-stream:i-1"));

    // Retention against the event timestamps.
    logs.put_retention_policy().log_group_name("/app/web").retention_in_days(7).send().await.unwrap();
    let bad = logs.put_retention_policy().log_group_name("/app/web").retention_in_days(8).send().await.unwrap_err();
    assert_eq!(code(bad.into_service_error()), "InvalidParameterException");
    let g = logs.describe_log_groups().log_group_name_prefix("/app/web").send().await.unwrap();
    assert_eq!(g.log_groups()[0].retention_in_days(), Some(7));
    logs.delete_retention_policy().log_group_name("/app/web").send().await.unwrap();

    // Tags, by name and by ARN.
    logs.tag_log_group().log_group_name("/app/web").tags("env", "prod").send().await.unwrap();
    logs.untag_log_group().log_group_name("/app/web").tags("team").send().await.unwrap();
    let tags = logs.list_tags_log_group().log_group_name("/app/web").send().await.unwrap();
    assert_eq!(tags.tags().unwrap().get("env").map(String::as_str), Some("prod"));
    assert!(!tags.tags().unwrap().contains_key("team"));
    let arn = "arn:aws:logs:us-east-1:123456789012:log-group:/app/web";
    logs.tag_resource().resource_arn(arn).tags("cost", "1").send().await.unwrap();
    logs.untag_resource().resource_arn(arn).tag_keys("env").send().await.unwrap();
    let tags = logs.list_tags_for_resource().resource_arn(arn).send().await.unwrap();
    assert_eq!(tags.tags().unwrap().len(), 1);
    assert_eq!(tags.tags().unwrap().get("cost").map(String::as_str), Some("1"));

    // Deletion protection.
    logs.put_log_group_deletion_protection()
        .log_group_identifier("/app/worker")
        .deletion_protection_enabled(true)
        .send()
        .await
        .unwrap();
    let protected = logs.delete_log_group().log_group_name("/app/worker").send().await.unwrap_err();
    assert_eq!(code(protected.into_service_error()), "ValidationException");
    logs.put_log_group_deletion_protection()
        .log_group_identifier("/app/worker")
        .deletion_protection_enabled(false)
        .send()
        .await
        .unwrap();
    logs.put_bearer_token_authentication()
        .log_group_identifier("/app/worker")
        .bearer_token_authentication_enabled(true)
        .send()
        .await
        .unwrap();
    let g = logs.describe_log_groups().log_group_name_prefix("/app/worker").send().await.unwrap();
    assert_eq!(g.log_groups()[0].bearer_token_authentication_enabled(), Some(true));

    logs.delete_log_stream().log_group_name("/app/web").log_stream_name("i-2").send().await.unwrap();
    let gone = logs.get_log_events().log_group_name("/app/web").log_stream_name("i-2").send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");
    logs.delete_log_group().log_group_name("/app/worker").send().await.unwrap();
    let gone = logs.delete_log_group().log_group_name("/app/worker").send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");
}

#[tokio::test]
async fn kms_keys_must_allow_cloudwatch_logs() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let logs = Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let plain = kms.create_key().send().await.unwrap();
    let plain_arn = plain.key_metadata().unwrap().arn().unwrap().to_string();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"},
            {"Effect": "Allow", "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
             "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:GenerateDataKey*", "kms:Describe*"], "Resource": "*"}
        ]
    });
    let allowed = kms.create_key().policy(policy.to_string()).send().await.unwrap();
    let allowed_arn = allowed.key_metadata().unwrap().arn().unwrap().to_string();

    let denied = logs.create_log_group().log_group_name("enc").kms_key_id(&plain_arn).send().await.unwrap_err();
    assert_eq!(code(denied.into_service_error()), "AccessDeniedException");
    logs.create_log_group().log_group_name("enc").kms_key_id(&allowed_arn).send().await.unwrap();
    logs.disassociate_kms_key().log_group_name("enc").send().await.unwrap();
    let g = logs.describe_log_groups().log_group_name_prefix("enc").send().await.unwrap();
    assert_eq!(g.log_groups()[0].kms_key_id(), None);
    logs.associate_kms_key().log_group_name("enc").kms_key_id(&allowed_arn).send().await.unwrap();
    let g = logs.describe_log_groups().log_group_name_prefix("enc").send().await.unwrap();
    assert_eq!(g.log_groups()[0].kms_key_id(), Some(allowed_arn.as_str()));
    let missing = logs
        .associate_kms_key()
        .log_group_name("enc")
        .kms_key_id("arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(missing.into_service_error()), "AccessDeniedException");
}

#[tokio::test]
async fn insights_queries_and_definitions() {
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    let t = now_ms() - 60_000;
    group_with_events(
        &logs,
        "/q/api",
        "s",
        &[
            (t, r#"{"path":"/a","ms":10,"status":200}"#),
            (t + 1000, r#"{"path":"/b","ms":30,"status":500}"#),
            (t + 2000, r#"{"path":"/a","ms":20,"status":200}"#),
        ],
    )
    .await;
    let started = logs
        .start_query()
        .log_group_name("/q/api")
        .start_time(t / 1000 - 60)
        .end_time(t / 1000 + 60)
        .query_string("filter status = 200 | stats count(*) as n, avg(ms) as avg_ms by path | sort n desc")
        .send()
        .await
        .unwrap();
    let id = started.query_id().unwrap().to_string();
    let results = wait_query(&logs, &id).await;
    assert_eq!(results.status(), Some(&QueryStatus::Complete));
    let rows = results.results();
    assert_eq!(rows.len(), 1);
    let field = |row: &[aws_sdk_cloudwatchlogs::types::ResultField], name: &str| {
        row.iter().find(|f| f.field() == Some(name)).and_then(|f| f.value()).map(str::to_string)
    };
    assert_eq!(field(&rows[0], "path").as_deref(), Some("/a"));
    assert_eq!(field(&rows[0], "n").as_deref(), Some("2"));
    assert_eq!(field(&rows[0], "avg_ms").as_deref(), Some("15"));
    assert_eq!(results.statistics().unwrap().records_matched(), 2.0);

    let raw = logs
        .start_query()
        .log_group_name("/q/api")
        .start_time(t / 1000 - 60)
        .end_time(t / 1000 + 60)
        .query_string("fields @timestamp, @message, @ptr | sort @timestamp asc | limit 1")
        .send()
        .await
        .unwrap();
    let raw = wait_query(&logs, raw.query_id().unwrap()).await;
    let ptr = field(&raw.results()[0], "@ptr").unwrap();
    let record = logs.get_log_record().log_record_pointer(&ptr).send().await.unwrap();
    assert_eq!(
        record.log_record().unwrap().get("@message").map(String::as_str),
        Some(r#"{"path":"/a","ms":10,"status":200}"#)
    );
    let fields = logs.get_log_group_fields().log_group_name("/q/api").send().await.unwrap();
    let names: Vec<_> = fields.log_group_fields().iter().filter_map(|f| f.name()).collect();
    assert!(names.contains(&"@message") && names.contains(&"path"), "{names:?}");

    let bad = logs
        .start_query()
        .log_group_name("/q/api")
        .start_time(0)
        .end_time(1)
        .query_string("fields @message | nonsense")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(bad.into_service_error()), "MalformedQueryException");

    let for_query = logs.list_log_groups_for_query().query_id(&id).send().await.unwrap();
    assert_eq!(for_query.log_group_identifiers(), ["arn:aws:logs:us-east-1:123456789012:log-group:/q/api"]);
    let described = logs.describe_queries().log_group_name("/q/api").send().await.unwrap();
    assert_eq!(described.queries().len(), 2);
    let stopped = logs.stop_query().query_id(&id).send().await.unwrap_err();
    assert_eq!(code(stopped.into_service_error()), "InvalidParameterException");

    let def = logs
        .put_query_definition()
        .name("errors/by-path")
        .query_string("filter status >= 500 | stats count(*) by path")
        .log_group_names("/q/api")
        .send()
        .await
        .unwrap();
    let def_id = def.query_definition_id().unwrap().to_string();
    logs.put_query_definition()
        .name("errors/by-path")
        .query_definition_id(&def_id)
        .query_string("filter status >= 400 | stats count(*) by path")
        .send()
        .await
        .unwrap();
    let defs = logs.describe_query_definitions().query_definition_name_prefix("errors/").send().await.unwrap();
    assert_eq!(defs.query_definitions().len(), 1);
    assert_eq!(defs.query_definitions()[0].query_string(), Some("filter status >= 400 | stats count(*) by path"));
    let deleted = logs.delete_query_definition().query_definition_id(&def_id).send().await.unwrap();
    assert!(deleted.success());
}

#[tokio::test]
async fn iam_policies_and_resource_tags_are_enforced() {
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    logs.create_log_group().log_group_name("/team/a").tags("team", "a").send().await.unwrap();
    logs.create_log_group().log_group_name("/team/b").tags("team", "b").send().await.unwrap();
    for g in ["/team/a", "/team/b"] {
        logs.create_log_stream().log_group_name(g).log_stream_name("s").send().await.unwrap();
    }
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["logs:PutLogEvents", "logs:GetLogEvents"],
             "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:*",
             "Condition": {"StringEquals": {"aws:ResourceTag/team": "a"}}},
            {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": "*"}
        ]
    });
    let (_, cfg) = user_with_policy(&mws, "writer", Some(&policy.to_string())).await;
    let user = Client::new(&cfg);
    user.put_log_events()
        .log_group_name("/team/a")
        .log_stream_name("s")
        .log_events(event(now_ms(), "hi"))
        .send()
        .await
        .unwrap();
    let denied = user
        .put_log_events()
        .log_group_name("/team/b")
        .log_stream_name("s")
        .log_events(event(now_ms(), "hi"))
        .send()
        .await
        .unwrap_err();
    let denied = denied.into_service_error();
    assert_eq!(denied.code(), Some("AccessDeniedException"));
    assert!(denied.message().unwrap().contains("logs:PutLogEvents"), "{denied:?}");
    let create = user.create_log_group().log_group_name("/team/c").send().await.unwrap_err();
    assert_eq!(code(create.into_service_error()), "AccessDeniedException");
    let groups = user.describe_log_groups().send().await.unwrap();
    assert_eq!(groups.log_groups().len(), 2);
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

#[tokio::test]
async fn resource_account_data_protection_and_index_policies() {
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    let t = now_ms() - 1000;
    group_with_events(&logs, "/pii", "s", &[(t, r#"{"user":"ann@example.com","requestId":"r-1"}"#)]).await;

    // Resource policies, account-wide and scoped to one log group.
    let doc = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "route53.amazonaws.com"},
                       "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}]
    })
    .to_string();
    let put = logs.put_resource_policy().policy_name("route53").policy_document(&doc).send().await.unwrap();
    let rev = put.revision_id().unwrap().to_string();
    let stale = logs
        .put_resource_policy()
        .policy_name("route53")
        .policy_document(&doc)
        .expected_revision_id("nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(stale.into_service_error()), "OperationAbortedException");
    logs.put_resource_policy()
        .policy_name("route53")
        .policy_document(&doc)
        .expected_revision_id(&rev)
        .send()
        .await
        .unwrap();
    let group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:/pii";
    logs.put_resource_policy().resource_arn(group_arn).policy_document(&doc).send().await.unwrap();
    let all = logs.describe_resource_policies().send().await.unwrap();
    assert_eq!(all.resource_policies().len(), 1);
    let scoped = logs.describe_resource_policies().resource_arn(group_arn).send().await.unwrap();
    assert_eq!(scoped.resource_policies().len(), 1);
    logs.delete_resource_policy().policy_name("route53").send().await.unwrap();
    logs.delete_resource_policy().resource_arn(group_arn).send().await.unwrap();
    let gone = logs.delete_resource_policy().policy_name("route53").send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");

    // Data protection masks what readers see of events ingested from then
    // on, unless they may unmask.
    logs.put_data_protection_policy()
        .log_group_identifier("/pii")
        .policy_document(DATA_PROTECTION)
        .send()
        .await
        .unwrap();
    let before = logs.get_log_events().log_group_name("/pii").log_stream_name("s").send().await.unwrap();
    assert!(before.events()[0].message().unwrap().contains("ann@example.com"));
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    logs.put_log_events()
        .log_group_name("/pii")
        .log_stream_name("s")
        .log_events(event(t + 1, r#"{"user":"ann@example.com","requestId":"r-1"}"#))
        .send()
        .await
        .unwrap();
    let got = logs.get_data_protection_policy().log_group_identifier("/pii").send().await.unwrap();
    assert!(got.policy_document().unwrap().contains("mask-emails"));
    let masked = logs.get_log_events().log_group_name("/pii").log_stream_name("s").send().await.unwrap();
    assert_eq!(masked.events()[1].message(), Some(r#"{"user":"***************","requestId":"r-1"}"#));
    let clear = logs.get_log_events().log_group_name("/pii").log_stream_name("s").unmask(true).send().await.unwrap();
    assert_eq!(clear.events()[1].message(), Some(r#"{"user":"ann@example.com","requestId":"r-1"}"#));
    let filtered = logs.filter_log_events().log_group_name("/pii").filter_pattern("r-1").send().await.unwrap();
    assert!(filtered.events()[1].message().unwrap().contains("****"));
    let bad =
        logs.put_data_protection_policy().log_group_identifier("/pii").policy_document("{}").send().await.unwrap_err();
    assert_eq!(code(bad.into_service_error()), "InvalidParameterException");
    logs.delete_data_protection_policy().log_group_identifier("/pii").send().await.unwrap();
    let plain = logs.get_log_events().log_group_name("/pii").log_stream_name("s").send().await.unwrap();
    assert!(plain.events()[1].message().unwrap().contains("ann@example.com"));

    // Account policies.
    let retention = logs
        .put_account_policy()
        .policy_name("keep")
        .policy_type(aws_sdk_cloudwatchlogs::types::PolicyType::FieldIndexPolicy)
        .policy_document(r#"{"Fields":["requestId"]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(retention.account_policy().unwrap().policy_name(), Some("keep"));
    let described = logs
        .describe_account_policies()
        .policy_type(aws_sdk_cloudwatchlogs::types::PolicyType::FieldIndexPolicy)
        .send()
        .await
        .unwrap();
    assert_eq!(described.account_policies().len(), 1);

    // Index policies: the account policy applies until the group has its own.
    let indexes = logs.describe_index_policies().log_group_identifiers("/pii").send().await.unwrap();
    assert_eq!(indexes.index_policies()[0].source(), Some(&aws_sdk_cloudwatchlogs::types::IndexSource::Account));
    logs.put_index_policy()
        .log_group_identifier("/pii")
        .policy_document(r#"{"Fields":["user"]}"#)
        .send()
        .await
        .unwrap();
    let indexes = logs.describe_index_policies().log_group_identifiers("/pii").send().await.unwrap();
    assert_eq!(indexes.index_policies()[0].source(), Some(&aws_sdk_cloudwatchlogs::types::IndexSource::LogGroup));
    let fields = logs.describe_field_indexes().log_group_identifiers("/pii").send().await.unwrap();
    assert_eq!(fields.field_indexes()[0].field_index_name(), Some("user"));
    assert_eq!(fields.field_indexes()[0].first_event_time(), Some(t));
    logs.delete_index_policy().log_group_identifier("/pii").send().await.unwrap();
    logs.delete_account_policy()
        .policy_name("keep")
        .policy_type(aws_sdk_cloudwatchlogs::types::PolicyType::FieldIndexPolicy)
        .send()
        .await
        .unwrap();
    let described = logs
        .describe_account_policies()
        .policy_type(aws_sdk_cloudwatchlogs::types::PolicyType::FieldIndexPolicy)
        .send()
        .await
        .unwrap();
    assert!(described.account_policies().is_empty());
}

#[tokio::test]
async fn metric_filters_subscriptions_and_destinations() {
    use aws_sdk_cloudwatchlogs::types::MetricTransformation;
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    logs.create_log_group().log_group_name("/m").send().await.unwrap();

    let tested = logs
        .test_metric_filter()
        .filter_pattern("[ip, user, status = 5*, bytes]")
        .log_event_messages("10.0.0.1 alice 500 1024")
        .log_event_messages("10.0.0.2 bob 200 99")
        .send()
        .await
        .unwrap();
    assert_eq!(tested.matches().len(), 1);
    let m = &tested.matches()[0];
    assert_eq!(m.event_number(), 1);
    assert_eq!(m.extracted_values().unwrap().get("$status").map(String::as_str), Some("500"));

    let transformation = MetricTransformation::builder()
        .metric_name("Errors")
        .metric_namespace("App")
        .metric_value("1")
        .build()
        .unwrap();
    logs.put_metric_filter()
        .log_group_name("/m")
        .filter_name("errors")
        .filter_pattern("ERROR")
        .metric_transformations(transformation.clone())
        .send()
        .await
        .unwrap();
    let bad = logs
        .put_metric_filter()
        .log_group_name("/m")
        .filter_name("bad")
        .filter_pattern("{ $.x = ")
        .metric_transformations(transformation)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(bad.into_service_error()), "InvalidParameterException");
    let filters = logs.describe_metric_filters().metric_namespace("App").metric_name("Errors").send().await.unwrap();
    assert_eq!(filters.metric_filters()[0].filter_name(), Some("errors"));
    logs.delete_metric_filter().log_group_name("/m").filter_name("errors").send().await.unwrap();
    assert!(logs.describe_metric_filters().log_group_name("/m").send().await.unwrap().metric_filters().is_empty());

    // A destination in this account, then a subscription filter to it.
    let dest = logs
        .put_destination()
        .destination_name("central")
        .target_arn("arn:aws:kinesis:us-east-1:123456789012:stream/central")
        .role_arn("arn:aws:iam::123456789012:role/cwl-to-kinesis")
        .send()
        .await
        .unwrap();
    let dest_arn = dest.destination().unwrap().arn().unwrap().to_string();
    assert_eq!(dest_arn, "arn:aws:logs:us-east-1:123456789012:destination:central");
    let access = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"},
                       "Action": "logs:PutSubscriptionFilter", "Resource": dest_arn}]
    });
    logs.put_destination_policy().destination_name("central").access_policy(access.to_string()).send().await.unwrap();
    let dests = logs.describe_destinations().destination_name_prefix("cen").send().await.unwrap();
    assert!(dests.destinations()[0].access_policy().unwrap().contains("111122223333"));
    logs.put_subscription_filter()
        .log_group_name("/m")
        .filter_name("ship")
        .filter_pattern("")
        .destination_arn(&dest_arn)
        .send()
        .await
        .unwrap();
    let missing = logs
        .put_subscription_filter()
        .log_group_name("/m")
        .filter_name("ship2")
        .filter_pattern("")
        .destination_arn("arn:aws:logs:us-east-1:123456789012:destination:nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");
    let subs = logs.describe_subscription_filters().log_group_name("/m").send().await.unwrap();
    assert_eq!(subs.subscription_filters()[0].destination_arn(), Some(dest_arn.as_str()));
    assert_eq!(
        subs.subscription_filters()[0].distribution(),
        Some(&aws_sdk_cloudwatchlogs::types::Distribution::ByLogStream)
    );
    logs.delete_subscription_filter().log_group_name("/m").filter_name("ship").send().await.unwrap();
    logs.delete_destination().destination_name("central").send().await.unwrap();
    assert!(logs.describe_destinations().send().await.unwrap().destinations().is_empty());
}

#[tokio::test]
async fn transformers_rewrite_events() {
    use aws_sdk_cloudwatchlogs::types::{AddKeyEntry, AddKeys, ParseJson, Processor};
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    logs.create_log_group().log_group_name("/t").send().await.unwrap();
    let config = vec![
        Processor::builder().parse_json(ParseJson::builder().build()).build(),
        Processor::builder()
            .add_keys(
                AddKeys::builder()
                    .entries(AddKeyEntry::builder().key("env").value("prod").build().unwrap())
                    .build()
                    .unwrap(),
            )
            .build(),
    ];
    let tested = logs
        .test_transformer()
        .set_transformer_config(Some(config.clone()))
        .log_event_messages(r#"{"a":1}"#)
        .send()
        .await
        .unwrap();
    let out: serde_json::Value =
        serde_json::from_str(tested.transformed_logs()[0].transformed_event_message().unwrap()).unwrap();
    assert_eq!(out, serde_json::json!({"a": 1, "env": "prod"}));
    let not_parser = logs
        .put_transformer()
        .log_group_identifier("/t")
        .transformer_config(config[1].clone())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(not_parser.into_service_error()), "InvalidParameterException");
    logs.put_transformer().log_group_identifier("/t").set_transformer_config(Some(config)).send().await.unwrap();
    let got = logs.get_transformer().log_group_identifier("/t").send().await.unwrap();
    assert_eq!(got.transformer_config().len(), 2);
    assert_eq!(got.log_group_identifier(), Some("/t"));
    logs.delete_transformer().log_group_identifier("/t").send().await.unwrap();
    let gone = logs.get_transformer().log_group_identifier("/t").send().await.unwrap();
    assert!(gone.transformer_config().is_empty());
}

#[tokio::test]
async fn vended_log_deliveries() {
    use aws_sdk_cloudwatchlogs::types::{DeliveryDestinationConfiguration, S3DeliveryConfiguration};
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    logs.create_log_group().log_group_name("/vended").send().await.unwrap();
    let source = logs
        .put_delivery_source()
        .name("cf")
        .resource_arn("arn:aws:cloudfront::123456789012:distribution/E1ABCDEF")
        .log_type("ACCESS_LOGS")
        .tags("k", "v")
        .send()
        .await
        .unwrap();
    assert_eq!(source.delivery_source().unwrap().service(), Some("cloudfront"));
    let changed = logs
        .put_delivery_source()
        .name("cf")
        .resource_arn("arn:aws:cloudfront::123456789012:distribution/E1ABCDEF")
        .log_type("CONNECTION_LOGS")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(changed.into_service_error()), "ConflictException");
    assert_eq!(
        logs.get_delivery_source().name("cf").send().await.unwrap().delivery_source().unwrap().log_type(),
        Some("ACCESS_LOGS")
    );
    assert_eq!(logs.describe_delivery_sources().send().await.unwrap().delivery_sources().len(), 1);

    let dest = logs
        .put_delivery_destination()
        .name("to-cwl")
        .delivery_destination_configuration(
            DeliveryDestinationConfiguration::builder()
                .destination_resource_arn("arn:aws:logs:us-east-1:123456789012:log-group:/vended")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let dest_arn = dest.delivery_destination().unwrap().arn().unwrap().to_string();
    assert_eq!(
        dest.delivery_destination().unwrap().delivery_destination_type(),
        Some(&aws_sdk_cloudwatchlogs::types::DeliveryDestinationType::Cwl)
    );
    let s3_dest = logs
        .put_delivery_destination()
        .name("to-s3")
        .delivery_destination_configuration(
            DeliveryDestinationConfiguration::builder()
                .destination_resource_arn("arn:aws:s3:::vended-logs")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let s3_arn = s3_dest.delivery_destination().unwrap().arn().unwrap().to_string();
    assert_eq!(
        logs.get_delivery_destination().name("to-cwl").send().await.unwrap().delivery_destination().unwrap().arn(),
        Some(dest_arn.as_str())
    );
    assert_eq!(logs.describe_delivery_destinations().send().await.unwrap().delivery_destinations().len(), 2);
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Action": "logs:CreateDelivery", "Resource": dest_arn}]
    });
    logs.put_delivery_destination_policy()
        .delivery_destination_name("to-cwl")
        .delivery_destination_policy(policy.to_string())
        .send()
        .await
        .unwrap();
    let got = logs.get_delivery_destination_policy().delivery_destination_name("to-cwl").send().await.unwrap();
    assert!(got.policy().unwrap().delivery_destination_policy().unwrap().contains("111122223333"));
    logs.delete_delivery_destination_policy().delivery_destination_name("to-cwl").send().await.unwrap();

    let delivery =
        logs.create_delivery().delivery_source_name("cf").delivery_destination_arn(&dest_arn).send().await.unwrap();
    let id = delivery.delivery().unwrap().id().unwrap().to_string();
    let again =
        logs.create_delivery().delivery_source_name("cf").delivery_destination_arn(&dest_arn).send().await.unwrap_err();
    assert_eq!(code(again.into_service_error()), "ConflictException");
    let to_s3 =
        logs.create_delivery().delivery_source_name("cf").delivery_destination_arn(&s3_arn).send().await.unwrap();
    let s3_id = to_s3.delivery().unwrap().id().unwrap().to_string();
    logs.update_delivery_configuration()
        .id(&s3_id)
        .record_fields("timestamp")
        .s3_delivery_configuration(S3DeliveryConfiguration::builder().enable_hive_compatible_path(true).build())
        .send()
        .await
        .unwrap();
    let got = logs.get_delivery().id(&s3_id).send().await.unwrap();
    assert_eq!(got.delivery().unwrap().record_fields(), ["timestamp"]);
    assert_eq!(got.delivery().unwrap().s3_delivery_configuration().unwrap().enable_hive_compatible_path(), Some(true));
    let s3_only = logs
        .update_delivery_configuration()
        .id(&id)
        .s3_delivery_configuration(S3DeliveryConfiguration::builder().build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(s3_only.into_service_error()), "ValidationException");
    assert_eq!(logs.describe_deliveries().send().await.unwrap().deliveries().len(), 2);
    let templates = logs.describe_configuration_templates().service("cloudfront").send().await.unwrap();
    assert!(!templates.configuration_templates().is_empty());

    let in_use = logs.delete_delivery_source().name("cf").send().await.unwrap_err();
    assert_eq!(code(in_use.into_service_error()), "ConflictException");
    logs.delete_delivery().id(&id).send().await.unwrap();
    logs.delete_delivery().id(&s3_id).send().await.unwrap();
    logs.delete_delivery_destination().name("to-cwl").send().await.unwrap();
    logs.delete_delivery_destination().name("to-s3").send().await.unwrap();
    logs.delete_delivery_source().name("cf").send().await.unwrap();
    assert!(logs.describe_delivery_sources().send().await.unwrap().delivery_sources().is_empty());
}

#[tokio::test]
async fn export_tasks_write_to_s3_and_imports_need_cloudtrail_lake() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let logs = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let t = now_ms() - 5000;
    group_with_events(&logs, "/export", "web-1", &[(t, "first line"), (t + 1, "second line")]).await;
    s3.create_bucket().bucket("log-archive").send().await.unwrap();

    // Without a bucket policy CloudWatch Logs may not write.
    let denied = logs
        .create_export_task()
        .log_group_name("/export")
        .from(t - 1000)
        .to(t + 1000)
        .destination("log-archive")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(denied.into_service_error()), "InvalidParameterException");
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::log-archive",
             "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}}},
            {"Effect": "Allow", "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": "arn:aws:s3:::log-archive/*",
             "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}
        ]
    });
    s3.put_bucket_policy().bucket("log-archive").policy(policy.to_string()).send().await.unwrap();
    let task = logs
        .create_export_task()
        .task_name("nightly")
        .log_group_name("/export")
        .from(t - 1000)
        .to(t + 1000)
        .destination("log-archive")
        .destination_prefix("cwl")
        .send()
        .await
        .unwrap();
    let task_id = task.task_id().unwrap().to_string();
    wait_export(&logs, &task_id).await;
    let key = format!("cwl/{task_id}/web-1/000000.gz");
    let obj = s3.get_object().bucket("log-archive").key(&key).send().await.unwrap();
    let gz = obj.body.collect().await.unwrap().into_bytes();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut text).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].ends_with(" first line"), "{text}");
    s3.head_object().bucket("log-archive").key("cwl/aws-logs-write-test").send().await.unwrap();

    let tasks = logs.describe_export_tasks().task_id(&task_id).send().await.unwrap();
    let described = &tasks.export_tasks()[0];
    assert_eq!(described.task_name(), Some("nightly"));
    assert_eq!(
        described.status().unwrap().code(),
        Some(&aws_sdk_cloudwatchlogs::types::ExportTaskStatusCode::Completed)
    );
    let finished = logs.cancel_export_task().task_id(&task_id).send().await.unwrap_err();
    assert_eq!(code(finished.into_service_error()), "InvalidOperationException");

    // No such event data store in CloudTrail Lake.
    let import = logs
        .create_import_task()
        .import_source_arn(
            "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/EXAMPLE-f852-4e8f-8bd1-bcf6cEXAMPLE",
        )
        .import_role_arn("arn:aws:iam::123456789012:role/import")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(import.into_service_error()), "ResourceNotFoundException");
    assert!(logs.describe_import_tasks().send().await.unwrap().imports().is_empty());
    let batches = logs.describe_import_task_batches().import_id("nope").send().await.unwrap_err();
    assert_eq!(code(batches.into_service_error()), "ResourceNotFoundException");
    let cancel = logs.cancel_import_task().import_id("nope").send().await.unwrap_err();
    assert_eq!(code(cancel.into_service_error()), "ResourceNotFoundException");
}

#[tokio::test]
async fn anomaly_detectors_lookup_tables_and_scheduled_queries() {
    use aws_sdk_cloudwatchlogs::types::{EvaluationFrequency, ScheduledQueryState};
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    let t = now_ms() - 5000;
    group_with_events(
        &logs,
        "/svc",
        "s",
        &[(t, r#"{"code":"E1","msg":"disk full"}"#), (t + 1, r#"{"code":"E2","msg":"oom"}"#)],
    )
    .await;
    let group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:/svc";

    let det = logs
        .create_log_anomaly_detector()
        .log_group_arn_list(group_arn)
        .detector_name("svc")
        .evaluation_frequency(EvaluationFrequency::FiveMin)
        .tags("k", "v")
        .send()
        .await
        .unwrap();
    let det_arn = det.anomaly_detector_arn().unwrap().to_string();
    let missing = logs
        .create_log_anomaly_detector()
        .log_group_arn_list("arn:aws:logs:us-east-1:123456789012:log-group:/nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");
    let got = logs.get_log_anomaly_detector().anomaly_detector_arn(&det_arn).send().await.unwrap();
    assert_eq!(got.detector_name(), Some("svc"));
    assert_eq!(got.anomaly_visibility_time(), Some(21));
    logs.update_log_anomaly_detector()
        .anomaly_detector_arn(&det_arn)
        .enabled(false)
        .evaluation_frequency(EvaluationFrequency::OneHour)
        .send()
        .await
        .unwrap();
    let got = logs.get_log_anomaly_detector().anomaly_detector_arn(&det_arn).send().await.unwrap();
    assert_eq!(got.evaluation_frequency(), Some(&EvaluationFrequency::OneHour));
    assert_eq!(got.anomaly_detector_status(), Some(&aws_sdk_cloudwatchlogs::types::AnomalyDetectorStatus::Paused));
    let listed = logs.list_log_anomaly_detectors().filter_log_group_arn(group_arn).send().await.unwrap();
    assert_eq!(listed.anomaly_detectors().len(), 1);
    assert!(logs.list_anomalies().anomaly_detector_arn(&det_arn).send().await.unwrap().anomalies().is_empty());
    let unknown = logs
        .update_anomaly()
        .anomaly_detector_arn(&det_arn)
        .anomaly_id("00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(unknown.into_service_error()), "ResourceNotFoundException");
    let tags = logs.list_tags_for_resource().resource_arn(&det_arn).send().await.unwrap();
    assert_eq!(tags.tags().unwrap().get("k").map(String::as_str), Some("v"));
    logs.delete_log_anomaly_detector().anomaly_detector_arn(&det_arn).send().await.unwrap();

    // Lookup tables, from CSV or from a query's results.
    let table = logs
        .create_lookup_table()
        .lookup_table_name("codes")
        .description("error codes")
        .table_body("code,owner\nE1,storage\nE2,runtime\n")
        .send()
        .await
        .unwrap();
    let table_arn = table.lookup_table_arn().unwrap().to_string();
    let got = logs.get_lookup_table().lookup_table_arn(&table_arn).send().await.unwrap();
    assert_eq!(got.table_body(), Some("code,owner\nE1,storage\nE2,runtime\n"));
    let q = logs
        .start_query()
        .log_group_name("/svc")
        .start_time(t / 1000 - 60)
        .end_time(t / 1000 + 60)
        .query_string("fields code, msg | sort code asc")
        .send()
        .await
        .unwrap();
    wait_query(&logs, q.query_id().unwrap()).await;
    logs.update_lookup_table().lookup_table_arn(&table_arn).query_id(q.query_id().unwrap()).send().await.unwrap();
    let described = logs.describe_lookup_tables().lookup_table_name_prefix("co").send().await.unwrap();
    let t0 = &described.lookup_tables()[0];
    assert_eq!(t0.table_fields(), ["code", "msg"]);
    assert_eq!(t0.records_count(), Some(2));
    logs.delete_lookup_table().lookup_table_arn(&table_arn).send().await.unwrap();
    let gone = logs.get_lookup_table().lookup_table_arn(&table_arn).send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");

    // Scheduled queries are stored and described; MWS does not run them.
    let created = logs
        .create_scheduled_query()
        .name("hourly-errors")
        .query_language(aws_sdk_cloudwatchlogs::types::QueryLanguage::Cwli)
        .query_string("stats count(*) by code")
        .log_group_identifiers(group_arn)
        .schedule_expression("rate(1 hour)")
        .execution_role_arn("arn:aws:iam::123456789012:role/sq")
        .send()
        .await
        .unwrap();
    let sq_arn = created.scheduled_query_arn().unwrap().to_string();
    let bad = logs
        .create_scheduled_query()
        .name("bad")
        .query_language(aws_sdk_cloudwatchlogs::types::QueryLanguage::Cwli)
        .query_string("stats count(*)")
        .schedule_expression("every hour")
        .execution_role_arn("arn:aws:iam::123456789012:role/sq")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(bad.into_service_error()), "ValidationException");
    logs.update_scheduled_query()
        .identifier(&sq_arn)
        .query_language(aws_sdk_cloudwatchlogs::types::QueryLanguage::Cwli)
        .query_string("stats count(*) by msg")
        .schedule_expression("cron(0 * * * ? *)")
        .execution_role_arn("arn:aws:iam::123456789012:role/sq")
        .state(ScheduledQueryState::Disabled)
        .send()
        .await
        .unwrap();
    let got = logs.get_scheduled_query().identifier("hourly-errors").send().await.unwrap();
    assert_eq!(got.schedule_expression(), Some("cron(0 * * * ? *)"));
    assert_eq!(got.state(), Some(&ScheduledQueryState::Disabled));
    let listed = logs.list_scheduled_queries().state(ScheduledQueryState::Disabled).send().await.unwrap();
    assert_eq!(listed.scheduled_queries().len(), 1);
    let history =
        logs.get_scheduled_query_history().identifier(&sq_arn).start_time(0).end_time(now_ms()).send().await.unwrap();
    assert!(history.trigger_history().is_empty());
    logs.delete_scheduled_query().identifier(&sq_arn).send().await.unwrap();
    assert!(logs.list_scheduled_queries().send().await.unwrap().scheduled_queries().is_empty());
}

#[tokio::test]
async fn integrations_storage_tier_syslog_and_fields() {
    use aws_sdk_cloudwatchlogs::types::{
        DataSource, IntegrationType, OpenSearchResourceConfig, ResourceConfig, StorageTier,
    };
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    logs.create_log_group().log_group_name("/sys").send().await.unwrap();

    let config = ResourceConfig::OpenSearchResourceConfig(
        OpenSearchResourceConfig::builder()
            .data_source_role_arn("arn:aws:iam::123456789012:role/os")
            .dashboard_viewer_principals("arn:aws:iam::123456789012:root")
            .retention_days(30)
            .build()
            .unwrap(),
    );
    let put = logs
        .put_integration()
        .integration_name("os")
        .integration_type(IntegrationType::Opensearch)
        .resource_config(config.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put.integration_status(), Some(&aws_sdk_cloudwatchlogs::types::IntegrationStatus::Active));
    let dup = logs
        .put_integration()
        .integration_name("os")
        .integration_type(IntegrationType::Opensearch)
        .resource_config(config)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(dup.into_service_error()), "ValidationException");
    let got = logs.get_integration().integration_name("os").send().await.unwrap();
    assert!(got.integration_details().is_some());
    assert_eq!(
        logs.list_integrations().integration_name_prefix("o").send().await.unwrap().integration_summaries().len(),
        1
    );
    logs.delete_integration().integration_name("os").send().await.unwrap();
    assert!(logs.list_integrations().send().await.unwrap().integration_summaries().is_empty());

    let s3_integration = "arn:aws:logs:us-east-1:123456789012:integration:s3tables";
    let source = DataSource::builder().name("vpc_flow").r#type("aws_vpc").build().unwrap();
    let assoc = logs
        .associate_source_to_s3_table_integration()
        .integration_arn(s3_integration)
        .data_source(source)
        .send()
        .await
        .unwrap();
    let source_id = assoc.identifier().unwrap().to_string();
    let sources = logs.list_sources_for_s3_table_integration().integration_arn(s3_integration).send().await.unwrap();
    assert_eq!(sources.sources().len(), 1);
    logs.disassociate_source_from_s3_table_integration().identifier(&source_id).send().await.unwrap();
    let sources = logs.list_sources_for_s3_table_integration().integration_arn(s3_integration).send().await.unwrap();
    assert!(sources.sources().is_empty());

    assert_eq!(logs.get_storage_tier_policy().send().await.unwrap().storage_tier(), Some(&StorageTier::Standard));
    logs.put_storage_tier_policy().storage_tier(StorageTier::IntelligentTiering).send().await.unwrap();
    assert_eq!(
        logs.get_storage_tier_policy().send().await.unwrap().storage_tier(),
        Some(&StorageTier::IntelligentTiering)
    );

    logs.put_syslog_configuration()
        .log_group_identifier("/sys")
        .vpc_endpoint_id("vpce-0123456789abcdef0")
        .send()
        .await
        .unwrap();
    let listed = logs.list_syslog_configurations().log_group_identifier("/sys").send().await.unwrap();
    assert_eq!(listed.syslog_configurations()[0].vpc_endpoint_id(), Some("vpce-0123456789abcdef0"));
    logs.delete_syslog_configuration()
        .log_group_identifier("/sys")
        .vpc_endpoint_id("vpce-0123456789abcdef0")
        .send()
        .await
        .unwrap();
    assert!(logs.list_syslog_configurations().send().await.unwrap().syslog_configurations().is_empty());

    let fields = logs.get_log_fields().data_source_name("aws_vpc").data_source_type("flow").send().await.unwrap();
    assert!(fields.log_fields().iter().any(|f| f.log_field_name() == Some("@timestamp")));
}

#[tokio::test]
async fn live_tail_streams_new_events() {
    use aws_sdk_cloudwatchlogs::types::StartLiveTailResponseStream;
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    logs.create_log_group().log_group_name("/tail").send().await.unwrap();
    logs.create_log_stream().log_group_name("/tail").log_stream_name("app").send().await.unwrap();
    let mut tail = logs
        .start_live_tail()
        .log_group_identifiers("arn:aws:logs:us-east-1:123456789012:log-group:/tail")
        .log_event_filter_pattern("ERROR")
        .send()
        .await
        .unwrap();
    match tail.response_stream.recv().await.unwrap() {
        Some(StartLiveTailResponseStream::SessionStart(s)) => {
            assert_eq!(s.log_group_identifiers(), ["arn:aws:logs:us-east-1:123456789012:log-group:/tail"]);
            assert_eq!(s.log_event_filter_pattern(), Some("ERROR"));
        }
        other => panic!("expected sessionStart, got {other:?}"),
    }
    logs.put_log_events()
        .log_group_name("/tail")
        .log_stream_name("app")
        .log_events(event(now_ms(), "INFO fine"))
        .log_events(event(now_ms() + 1, "ERROR broken"))
        .send()
        .await
        .unwrap();
    let results = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match tail.response_stream.recv().await.unwrap() {
                Some(StartLiveTailResponseStream::SessionUpdate(u)) if !u.session_results().is_empty() => {
                    break u.session_results().to_vec();
                }
                Some(_) => continue,
                None => panic!("stream ended"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].message(), Some("ERROR broken"));
    assert_eq!(results[0].log_stream_name(), Some("app"));
    assert_eq!(results[0].log_group_identifier(), Some("arn:aws:logs:us-east-1:123456789012:log-group:/tail"));

    let missing = logs
        .start_live_tail()
        .log_group_identifiers("arn:aws:logs:us-east-1:123456789012:log-group:/nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");
}

#[tokio::test]
async fn log_objects_stream_large_events() {
    use aws_sdk_cloudwatchlogs::types::GetLogObjectResponseStream;
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    let big = "x".repeat(150_000);
    let t = now_ms() - 1000;
    group_with_events(&logs, "/obj", "s", &[(t, &big)]).await;
    let q = logs
        .start_query()
        .log_group_name("/obj")
        .start_time(t / 1000 - 60)
        .end_time(t / 1000 + 60)
        .query_string("fields @ptr")
        .send()
        .await
        .unwrap();
    let res = wait_query(&logs, q.query_id().unwrap()).await;
    let ptr = res.results()[0].iter().find(|f| f.field() == Some("@ptr")).unwrap().value().unwrap().to_string();
    let mut out = logs.get_log_object().log_object_pointer(&ptr).send().await.unwrap();
    let mut data = Vec::new();
    let mut chunks = 0;
    while let Some(ev) = out.field_stream.recv().await.unwrap() {
        if let GetLogObjectResponseStream::Fields(f) = ev {
            data.extend_from_slice(f.data().unwrap().as_ref());
            chunks += 1;
        }
    }
    assert_eq!(chunks, 3);
    assert_eq!(data.len(), big.len());
    let bad = logs.get_log_object().log_object_pointer("bm90LWEtcG9pbnRlcg==").send().await.unwrap_err();
    assert_eq!(code(bad.into_service_error()), "InvalidParameterException");
}

const LAMBDA_TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        for (name, body) in files {
            z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            z.write_all(body.as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

/// Function logs land in `/aws/lambda/<name>`, written as the execution
/// role: a role without logging permissions loses them, as in AWS.
#[tokio::test]
async fn lambda_function_logs_go_to_cloudwatch_logs() {
    use aws_sdk_lambda::primitives::Blob;
    use aws_sdk_lambda::types::{FunctionCode, Runtime};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let logs = Client::new(&cfg);
    let code_zip = zip(&[(
        "app.py",
        "def handler(event, context):\n    print('hello from', context.function_name)\n    return 1\n",
    )]);
    let basic = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}]
    });
    for (role, may_log) in [("logging-role", true), ("silent-role", false)] {
        let r = iam.create_role().role_name(role).assume_role_policy_document(LAMBDA_TRUST).send().await.unwrap();
        if may_log {
            iam.put_role_policy()
                .role_name(role)
                .policy_name("logs")
                .policy_document(basic.to_string())
                .send()
                .await
                .unwrap();
        }
        let name = format!("fn-{role}");
        lambda
            .create_function()
            .function_name(&name)
            .runtime(Runtime::Python312)
            .role(r.role().unwrap().arn())
            .handler("app.handler")
            .code(FunctionCode::builder().zip_file(Blob::new(code_zip.clone())).build())
            .send()
            .await
            .unwrap();
        let out = lambda.invoke().function_name(&name).send().await.unwrap();
        assert_eq!(out.function_error(), None);
    }

    let group = "/aws/lambda/fn-logging-role";
    let streams = logs.describe_log_streams().log_group_name(group).send().await.unwrap();
    let stream = streams.log_streams()[0].log_stream_name().unwrap().to_string();
    assert!(stream.contains("[$LATEST]"), "{stream}");
    let events = logs.filter_log_events().log_group_name(group).send().await.unwrap();
    let text: Vec<_> = events.events().iter().filter_map(|e| e.message()).collect();
    assert!(text.iter().any(|m| m.starts_with("START RequestId:")), "{text:?}");
    assert!(text.iter().any(|m| m.contains("hello from fn-logging-role")), "{text:?}");
    assert!(text.iter().any(|m| m.starts_with("REPORT RequestId:")), "{text:?}");

    let silent = logs.describe_log_groups().log_group_name_prefix("/aws/lambda/fn-silent-role").send().await.unwrap();
    assert!(silent.log_groups().is_empty());
}

/// The DNS responder writes Route 53 query logs into the configured group.
#[tokio::test]
async fn route53_query_logs_go_to_cloudwatch_logs() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let r53 = aws_sdk_route53::Client::new(&cfg);
    let logs = Client::new(&cfg);
    let zone = r53.create_hosted_zone().name("q.test").caller_reference("q").send().await.unwrap();
    let zone_id = zone.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    logs.create_log_group().log_group_name("/aws/route53/q.test").send().await.unwrap();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "route53.amazonaws.com"},
                       "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}]
    });
    logs.put_resource_policy().policy_name("r53").policy_document(policy.to_string()).send().await.unwrap();
    r53.create_query_logging_config()
        .hosted_zone_id(&zone_id)
        .cloud_watch_logs_log_group_arn("arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/q.test:*")
        .send()
        .await
        .unwrap();

    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(mws_route53::serve_dns(mws.route53.clone(), server));
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["missing", "q", "test"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    client.send_to(&q, addr).await.unwrap();
    let mut buf = [0u8; 512];
    tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf)).await.unwrap().unwrap();

    let events = logs.filter_log_events().log_group_name("/aws/route53/q.test").send().await.unwrap();
    assert_eq!(events.events().len(), 1);
    let e = &events.events()[0];
    assert_eq!(e.log_stream_name(), Some(format!("{zone_id}/MWS1").as_str()));
    let fields: Vec<_> = e.message().unwrap().split(' ').collect();
    assert_eq!(fields[0], "1.0");
    assert_eq!(&fields[2..7], [zone_id.as_str(), "missing.q.test", "A", "NXDOMAIN", "UDP"]);
    assert_eq!(fields[8], "127.0.0.1");
}

/// Log groups and events survive a state export and import.
#[tokio::test]
async fn state_round_trips() {
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    group_with_events(&logs, "/keep", "s", &[(now_ms() - 10, "persist me")]).await;
    let (status, state) = mws.control("GET", "/_mws/state", None).await;
    assert_eq!(status, 200);
    let (status, _) = mws.control("POST", "/_mws/reset?to=empty", None).await;
    assert_eq!(status, 200);
    assert!(logs.describe_log_groups().send().await.unwrap().log_groups().is_empty());
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&state.to_string())).await;
    assert_eq!(status, 200);
    let got = logs.get_log_events().log_group_name("/keep").log_stream_name("s").send().await.unwrap();
    assert_eq!(got.events()[0].message(), Some("persist me"));
}

#[tokio::test]
async fn transformers_apply_at_ingestion() {
    use aws_sdk_cloudwatchlogs::types::{AddKeyEntry, AddKeys, ParseJson, Processor};
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    let t = now_ms() - 60_000;
    group_with_events(&logs, "/ingest", "s", &[(t, r#"{"user":"before"}"#)]).await;
    let config = vec![
        Processor::builder().parse_json(ParseJson::builder().build()).build(),
        Processor::builder()
            .add_keys(
                AddKeys::builder()
                    .entries(AddKeyEntry::builder().key("env").value("prod").build().unwrap())
                    .build()
                    .unwrap(),
            )
            .build(),
    ];
    logs.put_transformer().log_group_identifier("/ingest").set_transformer_config(Some(config)).send().await.unwrap();
    logs.put_log_events()
        .log_group_name("/ingest")
        .log_stream_name("s")
        .log_events(event(t + 1000, r#"{"user":"after"}"#))
        .send()
        .await
        .unwrap();

    // GetLogEvents and FilterLogEvents give back the originals.
    let got = logs.get_log_events().log_group_name("/ingest").log_stream_name("s").send().await.unwrap();
    let messages: Vec<&str> = got.events().iter().filter_map(|e| e.message()).collect();
    assert_eq!(messages, [r#"{"user":"before"}"#, r#"{"user":"after"}"#]);
    let filtered = logs.filter_log_events().log_group_name("/ingest").filter_pattern("prod").send().await.unwrap();
    assert!(filtered.events().is_empty());

    // Logs Insights sees the transformed events; earlier events were not
    // transformed.
    let q = logs
        .start_query()
        .log_group_name("/ingest")
        .start_time(t / 1000 - 60)
        .end_time(t / 1000 + 60)
        .query_string("filter env = \"prod\" | fields user, env, @message")
        .send()
        .await
        .unwrap();
    let res = wait_query(&logs, q.query_id().unwrap()).await;
    assert_eq!(res.results().len(), 1, "{res:?}");
    let field = |name: &str| {
        res.results()[0].iter().find(|f| f.field() == Some(name)).and_then(|f| f.value()).map(str::to_string)
    };
    assert_eq!(field("user").as_deref(), Some("after"));
    assert_eq!(field("env").as_deref(), Some("prod"));

    // An account-level transformer policy covers groups it selects.
    let policy = serde_json::json!({"transformerConfig": [
        {"parseJSON": {}},
        {"addKeys": {"entries": [{"key": "tier", "value": "gold"}]}}
    ]});
    logs.put_account_policy()
        .policy_name("tx")
        .policy_type(aws_sdk_cloudwatchlogs::types::PolicyType::TransformerPolicy)
        .policy_document(policy.to_string())
        .selection_criteria("LogGroupNamePrefix IN [\"/acct\"]")
        .send()
        .await
        .unwrap();
    group_with_events(&logs, "/acct/app", "s", &[(t, r#"{"n":1}"#)]).await;
    let q = logs
        .start_query()
        .log_group_name("/acct/app")
        .start_time(t / 1000 - 60)
        .end_time(t / 1000 + 60)
        .query_string("fields tier")
        .send()
        .await
        .unwrap();
    let res = wait_query(&logs, q.query_id().unwrap()).await;
    let tier = res.results()[0].iter().find(|f| f.field() == Some("tier")).and_then(|f| f.value());
    assert_eq!(tier, Some("gold"));
}

/// The vended-delivery operations declare `ValidationException` rather
/// than Logs' usual `InvalidParameterException`, and validate with it.
#[tokio::test]
async fn delivery_operations_validate_with_validation_exception() {
    let mws = Mws::start().await;
    let logs = client(&mws).await;
    let e = logs.get_delivery().id("not-an-id!").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    let e = logs.delete_delivery_source().name("").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    // Older operations keep InvalidParameterException.
    let e = logs.describe_log_groups().limit(0).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidParameterException");
    mws.stop().await;
}
