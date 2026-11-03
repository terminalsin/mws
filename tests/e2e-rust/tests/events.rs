//! EventBridge through the official Rust SDK: rules really match events
//! and targets really receive them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_sdk_eventbridge::error::ProvideErrorMetadata;
use aws_sdk_eventbridge::types::{
    ApiDestinationHttpMethod, Condition, ConnectionAuthorizationType, ConnectionHeaderParameter,
    ConnectionHttpParameters, CreateConnectionApiKeyAuthRequestParameters, CreateConnectionAuthRequestParameters,
    CreateConnectionOAuthClientRequestParameters, CreateConnectionOAuthRequestParameters, EndpointEventBus,
    FailoverConfig, HttpParameters, InputTransformer, Primary, PutEventsRequestEntry, ReplayDestination,
    ReplicationConfig, ReplicationState, RetryPolicy, RoutingConfig, RuleState, Secondary, Tag, Target,
    UpdateConnectionAuthRequestParameters, UpdateConnectionBasicAuthRequestParameters,
};
use aws_sdk_eventbridge::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn entry(source: &str, detail_type: &str, detail: serde_json::Value) -> PutEventsRequestEntry {
    PutEventsRequestEntry::builder().source(source).detail_type(detail_type).detail(detail.to_string()).build()
}

fn target(id: &str, arn: &str) -> Target {
    Target::builder().id(id).arn(arn).build().unwrap()
}

/// Poll `f` until it returns `Some`, for up to `secs` seconds.
async fn eventually<T, F, Fut>(secs: u64, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(std::time::Instant::now() < deadline, "timed out waiting");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A log group EventBridge may write to, through a Logs resource policy.
async fn log_group(logs: &aws_sdk_cloudwatchlogs::Client, name: &str) -> String {
    logs.create_log_group().log_group_name(name).send().await.unwrap();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": ["events.amazonaws.com", "delivery.logs.amazonaws.com"]},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": format!("arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{name}:*"),
        }],
    });
    let policy_name = format!("events-{}", name.replace('/', "-"));
    logs.put_resource_policy().policy_name(policy_name).policy_document(policy.to_string()).send().await.unwrap();
    format!("arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{name}")
}

/// Every message in a log group.
async fn messages(logs: &aws_sdk_cloudwatchlogs::Client, group: &str) -> Vec<String> {
    match logs.filter_log_events().log_group_name(group).send().await {
        Ok(out) => out.events().iter().filter_map(|e| e.message().map(str::to_string)).collect(),
        Err(_) => Vec::new(),
    }
}

async fn wait_for_messages(logs: &aws_sdk_cloudwatchlogs::Client, group: &str, n: usize) -> Vec<serde_json::Value> {
    eventually(15, || async {
        let m = messages(logs, group).await;
        (m.len() >= n).then(|| {
            m.iter().map(|s| serde_json::from_str(s).unwrap_or(serde_json::Value::String(s.clone()))).collect()
        })
    })
    .await
}

#[tokio::test]
async fn buses_rules_targets_and_tags() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);

    let created = eb
        .create_event_bus()
        .name("orders")
        .description("order events")
        .tags(Tag::builder().key("team").value("shop").build().unwrap())
        .send()
        .await
        .unwrap();
    let bus_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:event-bus/orders");
    assert_eq!(created.event_bus_arn(), Some(bus_arn.as_str()));
    let dup = eb.create_event_bus().name("orders").send().await.unwrap_err();
    assert_eq!(code(dup.into_service_error()), "ResourceAlreadyExistsException");

    let buses = eb.list_event_buses().send().await.unwrap();
    let names: Vec<_> = buses.event_buses().iter().filter_map(|b| b.name()).collect();
    assert_eq!(names, ["default", "orders"]);
    let prefixed = eb.list_event_buses().name_prefix("ord").limit(1).send().await.unwrap();
    assert_eq!(prefixed.event_buses().len(), 1);
    eb.update_event_bus().name("orders").description("all order events").send().await.unwrap();
    let described = eb.describe_event_bus().name("orders").send().await.unwrap();
    assert_eq!(described.description(), Some("all order events"));
    assert_eq!(described.arn(), Some(bus_arn.as_str()));
    let missing = eb.describe_event_bus().name("nope").send().await.unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");
    let default = eb.describe_event_bus().send().await.unwrap();
    assert_eq!(default.name(), Some("default"));

    let pattern = r#"{"source":["shop.orders"],"detail":{"total":[{"numeric":[">",100]}]}}"#;
    let rule = eb.put_rule().name("big-orders").event_bus_name("orders").event_pattern(pattern).send().await.unwrap();
    let rule_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:rule/orders/big-orders");
    assert_eq!(rule.rule_arn(), Some(rule_arn.as_str()));
    let bad = eb.put_rule().name("bad").event_pattern(r#"{"source":"x"}"#).send().await.unwrap_err();
    let bad = bad.into_service_error();
    assert_eq!(bad.code(), Some("InvalidEventPatternException"));
    assert!(bad.message().unwrap().starts_with("Event pattern is not valid. Reason:"), "{bad:?}");
    let neither = eb.put_rule().name("bad").send().await.unwrap_err();
    assert_eq!(code(neither.into_service_error()), "ValidationException");
    let sched = eb
        .put_rule()
        .name("s")
        .event_bus_name("orders")
        .schedule_expression("rate(5 minutes)")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(sched.into_service_error()), "ValidationException");
    let no_bus = eb.put_rule().name("r").event_bus_name("nope").event_pattern(pattern).send().await.unwrap_err();
    assert_eq!(code(no_bus.into_service_error()), "ResourceNotFoundException");

    let d = eb.describe_rule().name("big-orders").event_bus_name("orders").send().await.unwrap();
    assert_eq!(d.event_pattern(), Some(pattern));
    assert_eq!(d.state(), Some(&RuleState::Enabled));
    assert_eq!(d.created_by(), Some(ACCOUNT));
    let gone = eb.describe_rule().name("nope").send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");
    eb.disable_rule().name("big-orders").event_bus_name("orders").send().await.unwrap();
    let rules = eb.list_rules().event_bus_name("orders").send().await.unwrap();
    assert_eq!(rules.rules()[0].state(), Some(&RuleState::Disabled));
    eb.enable_rule().name("big-orders").event_bus_name("orders").send().await.unwrap();
    let rules = eb.list_rules().event_bus_name("orders").name_prefix("big").send().await.unwrap();
    assert_eq!(rules.rules()[0].state(), Some(&RuleState::Enabled));

    let fn_arn = format!("arn:aws:lambda:us-east-1:{ACCOUNT}:function:handler");
    let put = eb
        .put_targets()
        .rule("big-orders")
        .event_bus_name("orders")
        .targets(target("t1", &fn_arn))
        .targets(Target::builder().id("t2").arn(&fn_arn).input_path("$.detail").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(put.failed_entry_count(), 0);
    let both = Target::builder().id("t3").arn(&fn_arn).input("{}").input_path("$").build().unwrap();
    let both = eb.put_targets().rule("big-orders").event_bus_name("orders").targets(both).send().await.unwrap_err();
    assert_eq!(code(both.into_service_error()), "ValidationException");
    let listed = eb.list_targets_by_rule().rule("big-orders").event_bus_name("orders").send().await.unwrap();
    assert_eq!(listed.targets().iter().map(|t| t.id()).collect::<Vec<_>>(), ["t1", "t2"]);
    assert_eq!(listed.targets()[1].input_path(), Some("$.detail"));
    let by_target = eb.list_rule_names_by_target().target_arn(&fn_arn).event_bus_name("orders").send().await.unwrap();
    assert_eq!(by_target.rule_names(), ["big-orders"]);
    let has_targets = eb.delete_rule().name("big-orders").event_bus_name("orders").send().await.unwrap_err();
    assert_eq!(code(has_targets.into_service_error()), "ValidationException");

    eb.tag_resource()
        .resource_arn(&rule_arn)
        .tags(Tag::builder().key("env").value("test").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = eb.list_tags_for_resource().resource_arn(&rule_arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert_eq!(tags.tags()[0].key(), "env");
    let bus_tags = eb.list_tags_for_resource().resource_arn(&bus_arn).send().await.unwrap();
    assert_eq!(bus_tags.tags()[0].value(), "shop");
    eb.untag_resource().resource_arn(&rule_arn).tag_keys("env").send().await.unwrap();
    let tags = eb.list_tags_for_resource().resource_arn(&rule_arn).send().await.unwrap();
    assert!(tags.tags().is_empty());

    let removed =
        eb.remove_targets().rule("big-orders").event_bus_name("orders").ids("t1").ids("t2").send().await.unwrap();
    assert_eq!(removed.failed_entry_count(), 0);
    eb.delete_rule().name("big-orders").event_bus_name("orders").send().await.unwrap();
    assert!(eb.list_rules().event_bus_name("orders").send().await.unwrap().rules().is_empty());

    eb.put_permission()
        .event_bus_name("orders")
        .action("events:PutEvents")
        .principal("111122223333")
        .statement_id("partner")
        .send()
        .await
        .unwrap();
    eb.put_permission()
        .event_bus_name("orders")
        .action("events:PutEvents")
        .principal("*")
        .statement_id("org")
        .condition(
            Condition::builder().r#type("StringEquals").key("aws:PrincipalOrgID").value("o-abc").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let policy = eb.describe_event_bus().name("orders").send().await.unwrap();
    let policy: serde_json::Value = serde_json::from_str(policy.policy().unwrap()).unwrap();
    assert_eq!(policy["Statement"][0]["Principal"]["AWS"], "arn:aws:iam::111122223333:root");
    assert_eq!(policy["Statement"][1]["Condition"]["StringEquals"]["aws:PrincipalOrgID"], "o-abc");
    eb.remove_permission().event_bus_name("orders").statement_id("partner").send().await.unwrap();
    let missing = eb.remove_permission().event_bus_name("orders").statement_id("partner").send().await.unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");
    eb.remove_permission().event_bus_name("orders").remove_all_permissions(true).send().await.unwrap();
    assert!(eb.describe_event_bus().name("orders").send().await.unwrap().policy().is_none());

    let no_default = eb.delete_event_bus().name("default").send().await.unwrap_err();
    assert_eq!(code(no_default.into_service_error()), "ValidationException");
    eb.delete_event_bus().name("orders").send().await.unwrap();
    assert_eq!(eb.list_event_buses().send().await.unwrap().event_buses().len(), 1);
    mws.stop().await;
}

#[tokio::test]
async fn test_event_pattern_covers_the_pattern_language() {
    let mws = Mws::start().await;
    let eb = Client::new(&mws.root_sdk_config().await);
    let event = serde_json::json!({
        "id": "1", "account": ACCOUNT, "source": "com.example", "time": "2026-01-01T00:00:00Z",
        "region": "us-east-1", "resources": ["arn:aws:s3:::bucket/key.png"], "detail-type": "Upload",
        "detail": {"size": 2048, "ip": "10.0.0.7", "name": "Report-Final.PNG", "tags": ["a", "b"], "meta": null},
    })
    .to_string();
    let cases = [
        (r#"{"source":["com.example"]}"#, true),
        (r#"{"source":["other"]}"#, false),
        (r#"{"detail":{"size":[{"numeric":[">=",1024,"<",4096]}]}}"#, true),
        (r#"{"detail":{"ip":[{"cidr":"10.0.0.0/24"}]}}"#, true),
        (r#"{"detail":{"name":[{"prefix":{"equals-ignore-case":"report"}}]}}"#, true),
        (r#"{"detail":{"name":[{"suffix":".PNG"}]}}"#, true),
        (r#"{"detail":{"name":[{"wildcard":"Report-*.PNG"}]}}"#, true),
        (r#"{"detail":{"name":[{"equals-ignore-case":"report-final.png"}]}}"#, true),
        (r#"{"detail":{"tags":["b"]}}"#, true),
        (r#"{"detail":{"tags":[{"anything-but":["a","b"]}]}}"#, false),
        (r#"{"detail":{"meta":[null]}}"#, true),
        (r#"{"detail":{"missing":[{"exists":false}]}}"#, true),
        (r#"{"detail":{"size":[{"exists":true}]}}"#, true),
        (r#"{"resources":[{"suffix":".png"}]}"#, true),
        (r#"{"$or":[{"detail":{"size":[1]}},{"detail-type":["Upload"]}]}"#, true),
    ];
    for (pattern, expected) in cases {
        let r = eb.test_event_pattern().event_pattern(pattern).event(&event).send().await.unwrap();
        assert_eq!(r.result(), expected, "{pattern}");
    }
    let invalid =
        eb.test_event_pattern().event_pattern(r#"{"a":[{"bogus":1}]}"#).event(&event).send().await.unwrap_err();
    assert_eq!(code(invalid.into_service_error()), "InvalidEventPatternException");
    let bad_event = eb.test_event_pattern().event_pattern(r#"{"source":["x"]}"#).event("{}").send().await.unwrap_err();
    assert_eq!(code(bad_event.into_service_error()), "ValidationException");
    mws.stop().await;
}

#[tokio::test]
async fn events_reach_logs_and_other_buses_with_transforms() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);

    let raw = log_group(&logs, "/events/raw").await;
    let shaped = log_group(&logs, "/events/shaped").await;
    let forwarded = log_group(&logs, "/events/forwarded").await;

    eb.put_rule()
        .name("to-logs")
        .event_pattern(r#"{"source":["app"],"detail":{"kind":["order"]}}"#)
        .send()
        .await
        .unwrap();
    let transformer = InputTransformer::builder()
        .input_paths_map("id", "$.detail.id")
        .input_paths_map("time", "$.time")
        .input_template(r#"{"timestamp": <time>, "message": "order <id> at <time>"}"#)
        .build()
        .unwrap();
    eb.put_targets()
        .rule("to-logs")
        .targets(target("raw", &raw))
        .targets(Target::builder().id("shaped").arn(&shaped).input_transformer(transformer).build().unwrap())
        .send()
        .await
        .unwrap();

    // Bus to bus in the same account goes through a role.
    eb.create_event_bus().name("audit").send().await.unwrap();
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("eb-forward").assume_role_policy_document(trust).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    iam.put_role_policy()
        .role_name("eb-forward")
        .policy_name("put")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"events:PutEvents","Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let audit_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:event-bus/audit");
    eb.put_rule().name("forward").event_pattern(r#"{"source":["app"]}"#).send().await.unwrap();
    let no_role = eb.put_targets().rule("forward").targets(target("bus", &audit_arn)).send().await.unwrap_err();
    assert_eq!(code(no_role.into_service_error()), "ValidationException");
    eb.put_targets()
        .rule("forward")
        .targets(Target::builder().id("bus").arn(&audit_arn).role_arn(&role_arn).build().unwrap())
        .send()
        .await
        .unwrap();
    eb.put_rule()
        .name("audit-log")
        .event_bus_name("audit")
        .event_pattern(r#"{"source":["app"]}"#)
        .send()
        .await
        .unwrap();
    eb.put_targets().rule("audit-log").event_bus_name("audit").targets(target("log", &forwarded)).send().await.unwrap();

    let out = eb
        .put_events()
        .entries(entry("app", "Order Placed", serde_json::json!({"kind": "order", "id": "o-1"})))
        .entries(entry("app", "Order Placed", serde_json::json!({"kind": "refund", "id": "r-1"})))
        .entries(PutEventsRequestEntry::builder().source("app").detail_type("x").build())
        .entries(PutEventsRequestEntry::builder().source("app").detail_type("x").detail("[1]").build())
        .entries(entry("aws.s3", "Object Created", serde_json::json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(out.failed_entry_count(), 3);
    let results = out.entries();
    assert!(results[0].event_id().is_some());
    assert_eq!(results[2].error_code(), Some("InvalidArgument"));
    assert_eq!(results[3].error_code(), Some("MalformedDetail"));
    assert_eq!(results[4].error_code(), Some("NotAuthorizedForSourceException"));
    let order_id = results[0].event_id().unwrap().to_string();

    let raw_events = wait_for_messages(&logs, "/events/raw", 1).await;
    assert_eq!(raw_events.len(), 1, "only the order matches: {raw_events:?}");
    let e = &raw_events[0];
    assert_eq!(e["id"], order_id.as_str());
    assert_eq!(e["source"], "app");
    assert_eq!(e["detail-type"], "Order Placed");
    assert_eq!(e["account"], ACCOUNT);
    assert_eq!(e["region"], "us-east-1");
    assert_eq!(e["detail"]["id"], "o-1");
    // CloudWatch Logs targets get one log stream per event, named by its id.
    let streams = logs.describe_log_streams().log_group_name("/events/raw").send().await.unwrap();
    assert_eq!(streams.log_streams()[0].log_stream_name(), Some(order_id.as_str()));

    let shaped_events = eventually(15, || async {
        let m = messages(&logs, "/events/shaped").await;
        (!m.is_empty()).then_some(m)
    })
    .await;
    assert!(shaped_events[0].starts_with("order o-1 at "), "{shaped_events:?}");

    let forwarded_events = wait_for_messages(&logs, "/events/forwarded", 2).await;
    assert_eq!(forwarded_events.len(), 2);
    assert!(forwarded_events.iter().any(|e| e["id"] == order_id.as_str()));

    // Without a resource policy, CloudWatch Logs refuses EventBridge.
    logs.create_log_group().log_group_name("/locked").send().await.unwrap();
    let locked_rule = eb.put_rule().name("locked").event_pattern(r#"{"source":["locked"]}"#).send().await.unwrap();
    assert!(locked_rule.rule_arn().is_some());
    let locked_arn = format!("arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/locked");
    eb.put_targets()
        .rule("locked")
        .targets(
            Target::builder()
                .id("l")
                .arn(&locked_arn)
                .retry_policy(RetryPolicy::builder().maximum_retry_attempts(0).build())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    eb.put_events().entries(entry("locked", "x", serde_json::json!({}))).send().await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(messages(&logs, "/locked").await.is_empty());
    mws.stop().await;
}

const TRUST_LAMBDA: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const HANDLER: &str = r#"
import json

def handler(event, context):
    print("EVENT " + json.dumps(event))
    return {}
"#;

#[tokio::test]
async fn rules_invoke_lambda_functions_allowed_by_their_policy() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let role = iam.create_role().role_name("fn").assume_role_policy_document(TRUST_LAMBDA).send().await.unwrap();
    iam.put_role_policy()
        .role_name("fn")
        .policy_name("logs")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:*","Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let zip = {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut z = zip::ZipWriter::new(&mut buf);
        z.start_file("app.py", zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(HANDLER.as_bytes()).unwrap();
        z.finish().unwrap();
        buf.into_inner()
    };
    let f = lambda
        .create_function()
        .function_name("on-event")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder().zip_file(aws_sdk_lambda::primitives::Blob::new(zip)).build(),
        )
        .send()
        .await
        .unwrap();
    let fn_arn = f.function_arn().unwrap().to_string();
    let rule = eb.put_rule().name("to-fn").event_pattern(r#"{"source":["app"]}"#).send().await.unwrap();
    eb.put_targets().rule("to-fn").targets(target("fn", &fn_arn)).send().await.unwrap();

    // Without a resource policy that lets EventBridge in, nothing runs.
    eb.put_events().entries(entry("app", "first", serde_json::json!({"n": 1}))).send().await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let events = |logs: aws_sdk_cloudwatchlogs::Client| async move {
        let out = logs.filter_log_events().log_group_name("/aws/lambda/on-event").filter_pattern("EVENT").send().await;
        out.map(|o| o.events().iter().filter_map(|e| e.message().map(str::to_string)).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    assert!(events(logs.clone()).await.is_empty());

    lambda
        .add_permission()
        .function_name("on-event")
        .statement_id("events")
        .action("lambda:InvokeFunction")
        .principal("events.amazonaws.com")
        .source_arn(rule.rule_arn().unwrap())
        .send()
        .await
        .unwrap();
    eb.put_events().entries(entry("app", "second", serde_json::json!({"n": 2}))).send().await.unwrap();
    let seen = eventually(30, || {
        let logs = logs.clone();
        async move {
            let e = events(logs).await;
            (!e.is_empty()).then_some(e)
        }
    })
    .await;
    assert_eq!(seen.len(), 1, "{seen:?}");
    let body: serde_json::Value = serde_json::from_str(seen[0].trim().trim_start_matches("EVENT ")).unwrap();
    assert_eq!(body["detail-type"], "second");
    assert_eq!(body["detail"]["n"], 2);
    mws.stop().await;
}

#[tokio::test]
async fn archives_and_replays() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let group = log_group(&logs, "/replayed").await;
    let bus_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:event-bus/default");

    let a = eb
        .create_archive()
        .archive_name("orders")
        .event_source_arn(&bus_arn)
        .event_pattern(r#"{"source":["shop"]}"#)
        .retention_days(7)
        .send()
        .await
        .unwrap();
    let archive_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:archive/orders");
    assert_eq!(a.archive_arn(), Some(archive_arn.as_str()));
    let dup = eb.create_archive().archive_name("orders").event_source_arn(&bus_arn).send().await.unwrap_err();
    assert_eq!(code(dup.into_service_error()), "ResourceAlreadyExistsException");
    // EventBridge manages a rule for the archive.
    let rules = eb.list_rules().send().await.unwrap();
    let managed = rules.rules().iter().find(|r| r.name() == Some("Events-Archive-orders")).unwrap();
    assert_eq!(managed.managed_by(), Some("events.amazonaws.com"));
    let cannot = eb.delete_rule().name("Events-Archive-orders").send().await.unwrap_err();
    assert_eq!(code(cannot.into_service_error()), "ManagedRuleException");

    let start = aws_sdk_eventbridge::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() - 60);
    eb.put_events()
        .entries(entry("shop", "Order", serde_json::json!({"n": 1})))
        .entries(entry("shop", "Order", serde_json::json!({"n": 2})))
        .entries(entry("other", "Noise", serde_json::json!({})))
        .send()
        .await
        .unwrap();
    let d = eb.describe_archive().archive_name("orders").send().await.unwrap();
    assert_eq!(d.event_count(), 2);
    assert!(d.size_bytes() > 0);
    assert_eq!(d.retention_days(), Some(7));
    eb.update_archive().archive_name("orders").description("all orders").retention_days(30).send().await.unwrap();
    let listed = eb.list_archives().event_source_arn(&bus_arn).send().await.unwrap();
    assert_eq!(listed.archives()[0].retention_days(), Some(30));

    // Only rules created for replays see the replayed events.
    eb.put_rule().name("replays").event_pattern(r#"{"replay-name":[{"exists":true}]}"#).send().await.unwrap();
    eb.put_targets().rule("replays").targets(target("log", &group)).send().await.unwrap();
    let end = aws_sdk_eventbridge::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() + 60);
    let r = eb
        .start_replay()
        .replay_name("again")
        .event_source_arn(&archive_arn)
        .event_start_time(start)
        .event_end_time(end)
        .destination(ReplayDestination::builder().arn(&bus_arn).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.state().map(|s| s.as_str()), Some("STARTING"));
    let backwards = eb
        .start_replay()
        .replay_name("bad")
        .event_source_arn(&archive_arn)
        .event_start_time(end)
        .event_end_time(start)
        .destination(ReplayDestination::builder().arn(&bus_arn).build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(backwards.into_service_error()), "ValidationException");
    eventually(15, || async {
        let d = eb.describe_replay().replay_name("again").send().await.unwrap();
        (d.state().map(|s| s.as_str()) == Some("COMPLETED")).then_some(())
    })
    .await;
    let replayed = wait_for_messages(&logs, "/replayed", 2).await;
    assert_eq!(replayed.len(), 2);
    assert!(replayed.iter().all(|e| e["replay-name"] == "again"));
    let replays = eb.list_replays().event_source_arn(&archive_arn).send().await.unwrap();
    assert_eq!(replays.replays()[0].replay_name(), Some("again"));
    let done = eb.cancel_replay().replay_name("again").send().await.unwrap_err();
    assert_eq!(code(done.into_service_error()), "IllegalStatusException");
    // Replayed events are not archived again.
    assert_eq!(eb.describe_archive().archive_name("orders").send().await.unwrap().event_count(), 2);

    eb.delete_archive().archive_name("orders").send().await.unwrap();
    let gone = eb.describe_archive().archive_name("orders").send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");
    assert!(eb.list_rules().name_prefix("Events-Archive").send().await.unwrap().rules().is_empty());
    mws.stop().await;
}

/// A local HTTP server that records requests and answers OAuth token
/// requests.
async fn recorder() -> (String, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let log = log.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if body.len() >= len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&raw).to_string();
                let body = if text.starts_with("POST /token") {
                    r#"{"access_token":"tok-123","token_type":"bearer"}"#
                } else {
                    "{}"
                };
                log.lock().unwrap().push(text);
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            });
        }
    });
    (url, seen)
}

#[tokio::test]
async fn api_destinations_call_http_endpoints_with_connection_auth() {
    let mws = Mws::start().await;
    let eb = Client::new(&mws.root_sdk_config().await);
    let (url, seen) = recorder().await;

    let conn = eb
        .create_connection()
        .name("hooks")
        .authorization_type(ConnectionAuthorizationType::ApiKey)
        .auth_parameters(
            CreateConnectionAuthRequestParameters::builder()
                .api_key_auth_parameters(
                    CreateConnectionApiKeyAuthRequestParameters::builder()
                        .api_key_name("x-api-key")
                        .api_key_value("s3cret")
                        .build()
                        .unwrap(),
                )
                .invocation_http_parameters(
                    ConnectionHttpParameters::builder()
                        .header_parameters(
                            ConnectionHeaderParameter::builder()
                                .key("x-tenant")
                                .value("acme")
                                .is_value_secret(false)
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let conn_arn = conn.connection_arn().unwrap().to_string();
    assert!(conn_arn.starts_with(&format!("arn:aws:events:us-east-1:{ACCOUNT}:connection/hooks/")));
    assert_eq!(conn.connection_state().map(|s| s.as_str()), Some("AUTHORIZED"));
    let d = eb.describe_connection().name("hooks").send().await.unwrap();
    let auth = d.auth_parameters().unwrap();
    assert_eq!(auth.api_key_auth_parameters().unwrap().api_key_name(), Some("x-api-key"));
    assert!(d.secret_arn().unwrap().contains(":secret:events!connection/hooks/"));
    let missing = eb.describe_connection().name("nope").send().await.unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");
    assert_eq!(eb.list_connections().send().await.unwrap().connections().len(), 1);

    let dest = eb
        .create_api_destination()
        .name("hook")
        .connection_arn(&conn_arn)
        .invocation_endpoint(format!("{url}/hooks/*"))
        .http_method(ApiDestinationHttpMethod::Post)
        .invocation_rate_limit_per_second(10)
        .send()
        .await
        .unwrap();
    let dest_arn = dest.api_destination_arn().unwrap().to_string();
    let described = eb.describe_api_destination().name("hook").send().await.unwrap();
    assert_eq!(described.invocation_rate_limit_per_second(), Some(10));
    eb.update_api_destination().name("hook").description("webhook").send().await.unwrap();
    let listed = eb.list_api_destinations().connection_arn(&conn_arn).send().await.unwrap();
    assert_eq!(listed.api_destinations()[0].name(), Some("hook"));

    eb.put_rule().name("hook").event_pattern(r#"{"source":["app"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("hook")
        .targets(
            Target::builder()
                .id("api")
                .arn(&dest_arn)
                .http_parameters(
                    HttpParameters::builder().path_parameter_values("orders").query_string_parameters("v", "2").build(),
                )
                .input_path("$.detail")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    eb.put_events().entries(entry("app", "Hook", serde_json::json!({"order": 42}))).send().await.unwrap();
    let request = eventually(15, || async { seen.lock().unwrap().first().cloned() }).await;
    assert!(request.starts_with("POST /hooks/orders?v=2 HTTP/1.1"), "{request}");
    let lower = request.to_ascii_lowercase();
    assert!(lower.contains("x-api-key: s3cret"), "{request}");
    assert!(lower.contains("x-tenant: acme"), "{request}");
    assert!(request.ends_with(r#"{"order":42}"#), "{request}");

    // Basic auth, then OAuth client credentials with a token endpoint.
    eb.update_connection()
        .name("hooks")
        .authorization_type(ConnectionAuthorizationType::Basic)
        .auth_parameters(
            UpdateConnectionAuthRequestParameters::builder()
                .basic_auth_parameters(
                    UpdateConnectionBasicAuthRequestParameters::builder().username("u").password("p").build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    eb.put_events().entries(entry("app", "Hook", serde_json::json!({"order": 43}))).send().await.unwrap();
    let basic = eventually(15, || async { seen.lock().unwrap().get(1).cloned() }).await;
    assert!(basic.contains("Basic dTpw"), "{basic}");

    let oauth = eb
        .create_connection()
        .name("oauth")
        .authorization_type(ConnectionAuthorizationType::OauthClientCredentials)
        .auth_parameters(
            CreateConnectionAuthRequestParameters::builder()
                .o_auth_parameters(
                    CreateConnectionOAuthRequestParameters::builder()
                        .client_parameters(
                            CreateConnectionOAuthClientRequestParameters::builder()
                                .client_id("id")
                                .client_secret("secret")
                                .build()
                                .unwrap(),
                        )
                        .authorization_endpoint(format!("{url}/token"))
                        .http_method("POST".into())
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(oauth.connection_state().map(|s| s.as_str()), Some("AUTHORIZING"));
    eventually(15, || async {
        let d = eb.describe_connection().name("oauth").send().await.unwrap();
        (d.connection_state().map(|s| s.as_str()) == Some("AUTHORIZED")).then_some(())
    })
    .await;
    eb.update_api_destination().name("hook").connection_arn(oauth.connection_arn().unwrap()).send().await.unwrap();
    eb.put_events().entries(entry("app", "Hook", serde_json::json!({"order": 44}))).send().await.unwrap();
    let bearer =
        eventually(15, || async { seen.lock().unwrap().iter().find(|r| r.contains("Bearer tok-123")).cloned() }).await;
    assert!(bearer.starts_with("POST /hooks/orders"), "{bearer}");

    let de = eb.deauthorize_connection().name("hooks").send().await.unwrap();
    assert_eq!(de.connection_state().map(|s| s.as_str()), Some("DEAUTHORIZING"));
    eb.remove_targets().rule("hook").ids("api").send().await.unwrap();
    eb.delete_api_destination().name("hook").send().await.unwrap();
    let gone = eb.describe_api_destination().name("hook").send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");
    let deleted = eb.delete_connection().name("hooks").send().await.unwrap();
    assert_eq!(deleted.connection_state().map(|s| s.as_str()), Some("DELETING"));
    eb.delete_connection().name("oauth").send().await.unwrap();
    assert!(eb.list_connections().send().await.unwrap().connections().is_empty());
    mws.stop().await;
}

#[tokio::test]
async fn global_endpoints() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);
    let west = Client::from_conf(
        aws_sdk_eventbridge::config::Builder::from(&cfg).region(aws_config::Region::new("us-west-2")).build(),
    );
    eb.create_event_bus().name("global").send().await.unwrap();
    west.create_event_bus().name("global").send().await.unwrap();
    let buses = [
        EndpointEventBus::builder()
            .event_bus_arn(format!("arn:aws:events:us-east-1:{ACCOUNT}:event-bus/global"))
            .build()
            .unwrap(),
        EndpointEventBus::builder()
            .event_bus_arn(format!("arn:aws:events:us-west-2:{ACCOUNT}:event-bus/global"))
            .build()
            .unwrap(),
    ];
    let routing = RoutingConfig::builder()
        .failover_config(
            FailoverConfig::builder()
                .primary(Primary::builder().health_check("arn:aws:route53:::healthcheck/abc").build().unwrap())
                .secondary(Secondary::builder().route("us-west-2").build().unwrap())
                .build(),
        )
        .build();
    let created = eb
        .create_endpoint()
        .name("ge")
        .routing_config(routing.clone())
        .replication_config(ReplicationConfig::builder().state(ReplicationState::Disabled).build())
        .set_event_buses(Some(buses.to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(created.arn(), Some(format!("arn:aws:events:us-east-1:{ACCOUNT}:endpoint/ge").as_str()));
    let one_bus = eb
        .create_endpoint()
        .name("bad")
        .routing_config(routing)
        .event_buses(buses[0].clone())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(one_bus.into_service_error()), "ValidationException");
    let d = eb.describe_endpoint().name("ge").send().await.unwrap();
    assert_eq!(d.state().map(|s| s.as_str()), Some("ACTIVE"));
    assert!(d.endpoint_url().unwrap().ends_with(".endpoint.events.amazonaws.com"));
    assert!(d.endpoint_id().is_some());
    eb.update_endpoint().name("ge").description("failover").send().await.unwrap();
    let listed = eb.list_endpoints().name_prefix("g").send().await.unwrap();
    assert_eq!(listed.endpoints()[0].description(), Some("failover"));
    eb.delete_endpoint().name("ge").send().await.unwrap();
    let gone = eb.describe_endpoint().name("ge").send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");
    mws.stop().await;
}

#[tokio::test]
async fn partner_event_sources_and_buses() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let name = "aws.partner/example.com/tenant1/orders";
    let created = eb.create_partner_event_source().name(name).account(ACCOUNT).send().await.unwrap();
    assert_eq!(created.event_source_arn(), Some(format!("arn:aws:events:us-east-1::event-source/{name}").as_str()));
    let partner = eb.describe_partner_event_source().name(name).send().await.unwrap();
    assert_eq!(partner.name(), Some(name));
    let sources = eb.list_partner_event_sources().name_prefix("aws.partner/example.com/").send().await.unwrap();
    assert_eq!(sources.partner_event_sources().len(), 1);
    let accounts = eb.list_partner_event_source_accounts().event_source_name(name).send().await.unwrap();
    assert_eq!(accounts.partner_event_source_accounts()[0].account(), Some(ACCOUNT));
    assert_eq!(accounts.partner_event_source_accounts()[0].state().map(|s| s.as_str()), Some("PENDING"));

    let source = eb.describe_event_source().name(name).send().await.unwrap();
    assert_eq!(source.created_by(), Some(ACCOUNT));
    assert_eq!(eb.list_event_sources().name_prefix("aws.partner/").send().await.unwrap().event_sources().len(), 1);
    eb.create_event_bus().name(name).event_source_name(name).send().await.unwrap();
    assert_eq!(eb.describe_event_source().name(name).send().await.unwrap().state().map(|s| s.as_str()), Some("ACTIVE"));
    eb.deactivate_event_source().name(name).send().await.unwrap();
    assert_eq!(
        eb.describe_event_source().name(name).send().await.unwrap().state().map(|s| s.as_str()),
        Some("PENDING")
    );
    eb.activate_event_source().name(name).send().await.unwrap();

    let group = log_group(&logs, "/partner").await;
    eb.put_rule()
        .name("all")
        .event_bus_name(name)
        .event_pattern(format!(r#"{{"source":["{name}"]}}"#))
        .send()
        .await
        .unwrap();
    eb.put_targets().rule("all").event_bus_name(name).targets(target("log", &group)).send().await.unwrap();
    let put = eb
        .put_partner_events()
        .entries(
            aws_sdk_eventbridge::types::PutPartnerEventsRequestEntry::builder()
                .source(name)
                .detail_type("Order")
                .detail(r#"{"id":"p1"}"#)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put.failed_entry_count(), 0);
    let seen = wait_for_messages(&logs, "/partner", 1).await;
    assert_eq!(seen[0]["detail"]["id"], "p1");

    eb.delete_partner_event_source().name(name).account(ACCOUNT).send().await.unwrap();
    assert_eq!(
        eb.describe_event_source().name(name).send().await.unwrap().state().map(|s| s.as_str()),
        Some("DELETED")
    );
    let deleted = eb.activate_event_source().name(name).send().await.unwrap_err();
    assert_eq!(code(deleted.into_service_error()), "InvalidStateException");
    mws.stop().await;
}

#[tokio::test]
async fn scheduled_rules_fire_on_the_emulated_clock() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let group = log_group(&logs, "/scheduled").await;
    eb.put_rule().name("tick").schedule_expression("rate(1 hour)").send().await.unwrap();
    eb.put_targets().rule("tick").targets(target("log", &group)).send().await.unwrap();
    let bad = eb.put_rule().name("bad").schedule_expression("rate(1 hours)").send().await.unwrap_err();
    assert_eq!(code(bad.into_service_error()), "ValidationException");
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 3700}"#)).await;
    assert_eq!(status, 200);
    // EventBridge sees the clock move on its next request.
    eb.list_rules().send().await.unwrap();
    let seen = wait_for_messages(&logs, "/scheduled", 1).await;
    assert_eq!(seen[0]["detail-type"], "Scheduled Event");
    assert_eq!(seen[0]["source"], "aws.events");
    assert_eq!(seen[0]["resources"][0], format!("arn:aws:events:us-east-1:{ACCOUNT}:rule/tick"));
    mws.stop().await;
}

#[tokio::test]
async fn iam_controls_event_bridge() {
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"events:PutEvents","Resource":"*","Condition":{"StringEquals":{"events:source":"allowed"}}}]}"#;
    let (_, cfg) = user_with_policy(&mws, "producer", Some(policy)).await;
    let eb = Client::new(&cfg);
    let denied = eb.list_event_buses().send().await.unwrap_err();
    assert_eq!(code(denied.into_service_error()), "AccessDeniedException");
    let out = eb
        .put_events()
        .entries(entry("allowed", "x", serde_json::json!({})))
        .entries(entry("forbidden", "x", serde_json::json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(out.failed_entry_count(), 1);
    assert_eq!(out.entries()[1].error_code(), Some("AccessDeniedException"));
    let all_denied = eb.put_events().entries(entry("forbidden", "x", serde_json::json!({}))).send().await.unwrap_err();
    assert_eq!(code(all_denied.into_service_error()), "AccessDeniedException");
    mws.stop().await;
}

#[tokio::test]
async fn sqs_targets_and_dead_letter_queues() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let queue = |name: &'static str, open: bool| {
        let sqs = sqs.clone();
        async move {
            let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url.unwrap();
            let arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:{name}");
            if open {
                let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{
                    "Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},
                    "Action":"sqs:SendMessage","Resource":arn}]});
                sqs.set_queue_attributes()
                    .queue_url(&url)
                    .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
                    .send()
                    .await
                    .unwrap();
            }
            (url, arn)
        }
    };
    let (ok_url, ok_arn) = queue("ok", true).await;
    let (_, locked_arn) = queue("locked", false).await;
    let (dlq_url, dlq_arn) = queue("dlq", true).await;

    eb.put_rule().name("to-sqs").event_pattern(r#"{"source":["app"]}"#).send().await.unwrap();
    let locked = Target::builder()
        .id("locked")
        .arn(&locked_arn)
        .dead_letter_config(aws_sdk_eventbridge::types::DeadLetterConfig::builder().arn(&dlq_arn).build())
        .build()
        .unwrap();
    eb.put_targets().rule("to-sqs").targets(target("ok", &ok_arn)).targets(locked).send().await.unwrap();
    eb.put_events().entries(entry("app", "Thing", serde_json::json!({"n": 1}))).send().await.unwrap();

    let receive = |url: String| {
        let sqs = sqs.clone();
        async move {
            eventually(10, || {
                let (sqs, url) = (sqs.clone(), url.clone());
                async move {
                    let r = sqs.receive_message().queue_url(url).message_attribute_names("All").send().await.unwrap();
                    r.messages.unwrap_or_default().into_iter().next()
                }
            })
            .await
        }
    };
    let m = receive(ok_url).await;
    let body: serde_json::Value = serde_json::from_str(m.body().unwrap()).unwrap();
    assert_eq!(body["source"], "app");
    assert_eq!(body["detail"]["n"], 1);

    let m = receive(dlq_url).await;
    let body: serde_json::Value = serde_json::from_str(m.body().unwrap()).unwrap();
    assert_eq!(body["detail-type"], "Thing");
    let attrs = m.message_attributes.unwrap();
    let attr = |k: &str| attrs[k].string_value.clone().unwrap();
    assert_eq!(attr("RULE_ARN"), format!("arn:aws:events:us-east-1:{ACCOUNT}:rule/to-sqs"));
    assert_eq!(attr("TARGET_ARN"), locked_arn);
    assert_eq!(attr("ERROR_CODE"), "AccessDeniedException");
    mws.stop().await;
}

/// A queue EventBridge and SNS may send to; returns its URL and ARN.
async fn open_queue(sqs: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url.unwrap();
    let arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:{name}");
    let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Principal":{"Service":["events.amazonaws.com","sns.amazonaws.com"]},
        "Action":"sqs:SendMessage","Resource":arn}]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    (url, arn)
}

async fn receive_one(sqs: &aws_sdk_sqs::Client, url: &str) -> serde_json::Value {
    eventually(10, || async {
        let r = sqs.receive_message().queue_url(url).send().await.unwrap();
        r.messages.unwrap_or_default().into_iter().next().map(|m| serde_json::from_str(m.body().unwrap()).unwrap())
    })
    .await
}

#[tokio::test]
async fn sns_targets_and_s3_events() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let eb = Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);

    // SNS: the topic policy must let EventBridge publish.
    let (sns_url, sns_queue) = open_queue(&sqs, "from-sns").await;
    let topic = sns.create_topic().name("events").send().await.unwrap().topic_arn.unwrap();
    sns.subscribe().topic_arn(&topic).protocol("sqs").endpoint(&sns_queue).send().await.unwrap();
    eb.put_rule().name("to-sns").event_pattern(r#"{"source":["app"]}"#).send().await.unwrap();
    eb.put_targets().rule("to-sns").targets(target("t", &topic)).send().await.unwrap();
    eb.put_events().entries(entry("app", "Before", serde_json::json!({}))).send().await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r = sqs.receive_message().queue_url(&sns_url).send().await.unwrap();
    assert!(r.messages.unwrap_or_default().is_empty(), "the default topic policy only allows the owner");
    let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sns:Publish","Resource":topic}]});
    sns.set_topic_attributes()
        .topic_arn(&topic)
        .attribute_name("Policy")
        .attribute_value(policy.to_string())
        .send()
        .await
        .unwrap();
    eb.put_events().entries(entry("app", "After", serde_json::json!({"k": "v"}))).send().await.unwrap();
    let note = receive_one(&sqs, &sns_url).await;
    assert_eq!(note["Type"], "Notification");
    let event: serde_json::Value = serde_json::from_str(note["Message"].as_str().unwrap()).unwrap();
    assert_eq!(event["detail-type"], "After");
    assert_eq!(event["detail"]["k"], "v");

    // S3: buckets with EventBridge turned on put object events on the
    // default bus.
    let (s3_url, s3_queue) = open_queue(&sqs, "from-s3").await;
    eb.put_rule()
        .name("s3")
        .event_pattern(r#"{"source":["aws.s3"],"detail":{"bucket":{"name":["watched"]}}}"#)
        .send()
        .await
        .unwrap();
    eb.put_targets().rule("s3").targets(target("q", &s3_queue)).send().await.unwrap();
    for b in ["watched", "quiet"] {
        s3.create_bucket().bucket(b).send().await.unwrap();
    }
    s3.put_bucket_notification_configuration()
        .bucket("watched")
        .notification_configuration(
            aws_sdk_s3::types::NotificationConfiguration::builder()
                .event_bridge_configuration(aws_sdk_s3::types::EventBridgeConfiguration::builder().build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    s3.put_object().bucket("quiet").key("a").body(b"x".to_vec().into()).send().await.unwrap();
    s3.put_object().bucket("watched").key("docs/a.txt").body(b"hello".to_vec().into()).send().await.unwrap();
    let event = receive_one(&sqs, &s3_url).await;
    assert_eq!(event["source"], "aws.s3");
    assert_eq!(event["detail-type"], "Object Created");
    assert_eq!(event["account"], ACCOUNT);
    assert_eq!(event["resources"][0], "arn:aws:s3:::watched");
    assert_eq!(event["detail"]["bucket"]["name"], "watched");
    assert_eq!(event["detail"]["object"]["key"], "docs/a.txt");
    assert_eq!(event["detail"]["object"]["size"], 5);
    assert_eq!(event["detail"]["reason"], "PutObject");
    s3.delete_object().bucket("watched").key("docs/a.txt").send().await.unwrap();
    let event = receive_one(&sqs, &s3_url).await;
    assert_eq!(event["detail-type"], "Object Deleted");
    assert_eq!(event["detail"]["deletion-type"], "Permanently Deleted");
    mws.stop().await;
}
