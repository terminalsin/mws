//! How SQS event source mappings scale, through the official Rust SDK: a
//! mapping runs several batches at once (AWS starts with five), no more
//! than `ScalingConfig.MaximumConcurrency`, and a FIFO queue's message
//! groups stay in order.

use aws_sdk_lambda::client::Waiters;
use std::time::Duration;

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, Runtime, ScalingConfig};
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Records when each batch started and ended, and what it held.
const HANDLER: &str = r#"
import json, time, boto3

sqs = boto3.client("sqs")

def handler(event, context):
    start = time.time()
    time.sleep(1.0)
    out = sqs.get_queue_url(QueueName="spans")["QueueUrl"]
    sqs.send_message(QueueUrl=out, MessageBody=json.dumps({
        "fn": context.function_name,
        "start": start,
        "end": time.time(),
        "bodies": [r["body"] for r in event["Records"]],
        "groups": [r["attributes"].get("MessageGroupId") for r in event["Records"]],
    }))
"#;

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

async fn queue(sqs: &aws_sdk_sqs::Client, name: &str, attrs: &[(QueueAttributeName, &str)]) -> (String, String) {
    let mut req = sqs.create_queue().queue_name(name);
    for (k, v) in attrs {
        req = req.attributes(k.clone(), *v);
    }
    let url = req.send().await.unwrap().queue_url.unwrap();
    let arn = sqs
        .get_queue_attributes()
        .queue_url(&url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes
        .unwrap()[&QueueAttributeName::QueueArn]
        .clone();
    (url, arn)
}

/// The spans the functions reported, once `want` have arrived.
async fn spans(sqs: &aws_sdk_sqs::Client, url: &str, want: usize) -> Vec<serde_json::Value> {
    let mut got = Vec::new();
    for _ in 0..240 {
        let out = sqs.receive_message().queue_url(url).max_number_of_messages(10).send().await.unwrap();
        for m in out.messages() {
            got.push(serde_json::from_str(m.body().unwrap()).unwrap());
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
        if got.len() >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    got
}

/// The most spans that overlapped at one time.
fn max_overlap(spans: &[serde_json::Value]) -> usize {
    let mut edges: Vec<(f64, i32)> =
        spans.iter().flat_map(|s| [(s["start"].as_f64().unwrap(), 1), (s["end"].as_f64().unwrap(), -1)]).collect();
    edges.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().then(a.1.cmp(&b.1)));
    let (mut now, mut most) = (0i32, 0i32);
    for (_, d) in edges {
        now += d;
        most = most.max(now);
    }
    most as usize
}

async fn function(lambda: &aws_sdk_lambda::Client, name: &str, role: &str) {
    lambda
        .create_function()
        .function_name(name)
        .runtime(Runtime::Python312)
        .role(role)
        .handler("app.handler")
        .timeout(10)
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", HANDLER)]))).build())
        .send()
        .await
        .unwrap();
    lambda.wait_until_function_active_v2().function_name(name).wait(Duration::from_secs(60)).await.unwrap();
}

#[tokio::test]
async fn sqs_mappings_run_batches_concurrently_within_maximum_concurrency() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);

    let role = iam.create_role().role_name("poller").assume_role_policy_document(TRUST).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    iam.put_role_policy()
        .role_name("poller")
        .policy_name("sqs")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:*","logs:*"],"Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let vis = [(QueueAttributeName::VisibilityTimeout, "30")];
    let (wide_url, wide_arn) = queue(&sqs, "wide", &vis).await;
    let (narrow_url, narrow_arn) = queue(&sqs, "narrow", &vis).await;
    let (spans_url, _) = queue(&sqs, "spans", &[]).await;
    function(&lambda, "wide", &role_arn).await;
    function(&lambda, "narrow", &role_arn).await;

    for i in 0..15 {
        for url in [&wide_url, &narrow_url] {
            sqs.send_message().queue_url(url).message_body(format!("m{i}")).send().await.unwrap();
        }
    }
    let wide = lambda
        .create_event_source_mapping()
        .function_name("wide")
        .event_source_arn(&wide_arn)
        .batch_size(1)
        .send()
        .await
        .unwrap();
    assert_eq!(wide.scaling_config(), None);
    let narrow = lambda
        .create_event_source_mapping()
        .function_name("narrow")
        .event_source_arn(&narrow_arn)
        .batch_size(1)
        .scaling_config(ScalingConfig::builder().maximum_concurrency(2).build())
        .send()
        .await
        .unwrap();
    assert_eq!(narrow.scaling_config().and_then(|s| s.maximum_concurrency()), Some(2));

    let all = spans(&sqs, &spans_url, 30).await;
    let of = |name: &str| all.iter().filter(|s| s["fn"] == name).cloned().collect::<Vec<_>>();
    let (wide, narrow) = (of("wide"), of("narrow"));
    assert_eq!(wide.len(), 15, "{all:?}");
    assert_eq!(narrow.len(), 15, "{all:?}");
    // A standard queue's batches run side by side, five at first.
    assert!(max_overlap(&wide) >= 4, "wide ran at most {} at once", max_overlap(&wide));
    // MaximumConcurrency caps them.
    assert_eq!(max_overlap(&narrow), 2, "{narrow:?}");
}

#[tokio::test]
async fn fifo_mappings_keep_each_message_group_in_order() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);

    let role = iam.create_role().role_name("poller").assume_role_policy_document(TRUST).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    iam.put_role_policy()
        .role_name("poller")
        .policy_name("sqs")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:*","logs:*"],"Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let (url, arn) = queue(
        &sqs,
        "orders.fifo",
        &[
            (QueueAttributeName::FifoQueue, "true"),
            (QueueAttributeName::ContentBasedDeduplication, "true"),
            (QueueAttributeName::VisibilityTimeout, "30"),
        ],
    )
    .await;
    let (spans_url, _) = queue(&sqs, "spans", &[]).await;
    function(&lambda, "orders", &role_arn).await;
    for i in 0..4 {
        for g in ["a", "b", "c"] {
            sqs.send_message()
                .queue_url(&url)
                .message_group_id(g)
                .message_body(format!("{g}{i}"))
                .send()
                .await
                .unwrap();
        }
    }
    lambda
        .create_event_source_mapping()
        .function_name("orders")
        .event_source_arn(&arn)
        .batch_size(1)
        .send()
        .await
        .unwrap();

    let mut got = spans(&sqs, &spans_url, 12).await;
    assert_eq!(got.len(), 12, "{got:?}");
    got.sort_by(|a, b| a["start"].as_f64().partial_cmp(&b["start"].as_f64()).unwrap());
    for g in ["a", "b", "c"] {
        let group: Vec<&serde_json::Value> = got.iter().filter(|s| s["groups"][0] == g).collect();
        let bodies: Vec<&str> = group.iter().map(|s| s["bodies"][0].as_str().unwrap()).collect();
        assert_eq!(bodies, (0..4).map(|i| format!("{g}{i}")).collect::<Vec<_>>(), "{got:?}");
        // One batch per group at a time.
        let owned: Vec<serde_json::Value> = group.into_iter().cloned().collect();
        assert_eq!(max_overlap(&owned), 1, "{owned:?}");
    }
    // The groups themselves run side by side.
    assert!(max_overlap(&got) >= 2, "{got:?}");
}
