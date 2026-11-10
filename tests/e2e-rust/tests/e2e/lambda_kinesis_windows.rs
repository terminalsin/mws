//! Kinesis event source mappings with `ParallelizationFactor` and
//! `TumblingWindowInSeconds`, through the official Rust SDK: batches from
//! one shard run concurrently while each partition key stays in order, and
//! tumbling windows carry the function's state from one invocation to the
//! next until a final invocation at the window's end.

use aws_sdk_lambda::client::Waiters;
use std::time::Duration;

use aws_sdk_kinesis::types::StreamStatus;
use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{EventSourcePosition, FunctionCode, Runtime};
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";
const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Reports each batch's records and timing, slowly.
const PARALLEL: &str = r#"
import base64, json, time, boto3

sqs = boto3.client("sqs")

def handler(event, context):
    start = time.time()
    time.sleep(0.8)
    out = sqs.get_queue_url(QueueName="out")["QueueUrl"]
    sqs.send_message(QueueUrl=out, MessageBody=json.dumps({
        "start": start,
        "end": time.time(),
        "records": [[r["kinesis"]["partitionKey"], base64.b64decode(r["kinesis"]["data"]).decode()]
                    for r in event["Records"]],
    }))
"#;

/// Sums the records of each window in its state and reports every
/// invocation.
const WINDOWED: &str = r#"
import base64, json, boto3

sqs = boto3.client("sqs")

def handler(event, context):
    out = sqs.get_queue_url(QueueName="out")["QueueUrl"]
    state = event["state"] or {}
    total = int(state.get("total", "0"))
    for r in event["Records"]:
        total += int(base64.b64decode(r["kinesis"]["data"]).decode())
    report = {k: event.get(k) for k in ["window", "state", "shardId", "eventSourceARN",
                                         "isFinalInvokeForWindow", "isWindowTerminatedEarly"]}
    report["count"] = len(event["Records"])
    sqs.send_message(QueueUrl=out, MessageBody=json.dumps(report))
    return {"state": {"total": str(total)}, "batchItemFailures": []}
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

struct Setup {
    _mws: Mws,
    k: aws_sdk_kinesis::Client,
    sqs: aws_sdk_sqs::Client,
    lambda: aws_sdk_lambda::Client,
    out: String,
    stream_arn: String,
}

async fn setup(code: &str) -> Setup {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let k = aws_sdk_kinesis::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = iam.create_role().role_name("reader").assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy()
        .role_name("reader")
        .policy_name("p")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:*","kinesis:*","logs:*"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    k.create_stream().stream_name("events").shard_count(1).send().await.unwrap();
    for _ in 0..50 {
        let s = k.describe_stream_summary().stream_name("events").send().await.unwrap();
        if s.stream_description_summary().unwrap().stream_status() == &StreamStatus::Active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let out = sqs
        .create_queue()
        .queue_name("out")
        .attributes(QueueAttributeName::VisibilityTimeout, "30")
        .send()
        .await
        .unwrap()
        .queue_url
        .unwrap();
    lambda
        .create_function()
        .function_name("consumer")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .timeout(10)
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", code)]))).build())
        .send()
        .await
        .unwrap();
    lambda.wait_until_function_active_v2().function_name("consumer").wait(Duration::from_secs(60)).await.unwrap();
    Setup { _mws: mws, k, sqs, lambda, out, stream_arn: format!("arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/events") }
}

/// What the function reported, until `done` holds or time runs out.
async fn reports(s: &Setup, done: impl Fn(&[serde_json::Value]) -> bool) -> Vec<serde_json::Value> {
    let mut got = Vec::new();
    for _ in 0..160 {
        let out = s.sqs.receive_message().queue_url(&s.out).max_number_of_messages(10).send().await.unwrap();
        for m in out.messages() {
            got.push(serde_json::from_str(m.body().unwrap()).unwrap());
            s.sqs.delete_message().queue_url(&s.out).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
        if done(&got) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    got
}

async fn put(s: &Setup, key: &str, data: &str) {
    s.k.put_record()
        .stream_name("events")
        .partition_key(key)
        .data(aws_sdk_kinesis::primitives::Blob::new(data))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn kinesis_parallelization_factor_runs_lanes_concurrently_in_key_order() {
    let s = setup(PARALLEL).await;
    for i in 0..3 {
        for key in 0..10 {
            put(&s, &format!("key-{key}"), &i.to_string()).await;
        }
    }
    let mapping = s
        .lambda
        .create_event_source_mapping()
        .function_name("consumer")
        .event_source_arn(&s.stream_arn)
        .starting_position(EventSourcePosition::TrimHorizon)
        .batch_size(1)
        .parallelization_factor(10)
        .send()
        .await
        .unwrap();
    assert_eq!(mapping.parallelization_factor(), Some(10));

    // BatchSize is checked on update as on create.
    let e = s
        .lambda
        .update_event_source_mapping()
        .uuid(mapping.uuid().unwrap())
        .batch_size(10_001)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(matches!(e.meta().code(), Some("InvalidParameterValueException" | "ValidationException")), "{e:?}");

    let got = reports(&s, |g| g.len() >= 30).await;
    assert_eq!(got.len(), 30, "{got:?}");
    let mut spans: Vec<(f64, f64, String, String)> = got
        .iter()
        .map(|r| {
            let rec = &r["records"][0];
            (
                r["start"].as_f64().unwrap(),
                r["end"].as_f64().unwrap(),
                rec[0].as_str().unwrap().to_string(),
                rec[1].as_str().unwrap().to_string(),
            )
        })
        .collect();
    spans.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    // Each partition key's records arrive in order, one batch at a time.
    for key in 0..10 {
        let key = format!("key-{key}");
        let mine: Vec<&(f64, f64, String, String)> = spans.iter().filter(|s| s.2 == key).collect();
        let order: Vec<&str> = mine.iter().map(|s| s.3.as_str()).collect();
        assert_eq!(order, ["0", "1", "2"], "{key}: {spans:?}");
        assert!(mine.windows(2).all(|w| w[1].0 >= w[0].1), "{key} overlapped: {mine:?}");
    }
    // Different lanes overlap.
    let overlapping = spans.windows(2).any(|w| w[1].0 < w[0].1);
    assert!(overlapping, "batches ran one at a time: {spans:?}");
}

#[tokio::test]
async fn kinesis_tumbling_windows_carry_state_to_a_final_invocation() {
    let s = setup(WINDOWED).await;
    const WINDOW: i64 = 4;
    let mapping = s
        .lambda
        .create_event_source_mapping()
        .function_name("consumer")
        .event_source_arn(&s.stream_arn)
        .starting_position(EventSourcePosition::TrimHorizon)
        .batch_size(2)
        .tumbling_window_in_seconds(WINDOW as i32)
        .send()
        .await
        .unwrap();
    assert_eq!(mapping.tumbling_window_in_seconds(), Some(WINDOW as i32));
    // Start just after a window boundary, so every record lands in one
    // window.
    loop {
        let now = chrono::Utc::now();
        if now.timestamp() % WINDOW == 0 && now.timestamp_subsec_millis() < 300 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for n in 1..=5 {
        put(&s, "k", &n.to_string()).await;
    }
    let got = reports(&s, |g| g.iter().any(|r| r["isFinalInvokeForWindow"] == true)).await;
    let (finals, partial): (Vec<_>, Vec<_>) = got.iter().partition(|r| r["isFinalInvokeForWindow"] == true);
    assert_eq!(finals.len(), 1, "{got:?}");
    let last = finals[0];
    assert_eq!(last["state"], serde_json::json!({"total": "15"}), "{got:?}");
    assert_eq!(last["count"], 0);
    assert_eq!(last["isWindowTerminatedEarly"], false);
    assert_eq!(last["shardId"], "shardId-000000000000");
    assert_eq!(last["eventSourceARN"], s.stream_arn.as_str());
    let start = chrono::DateTime::parse_from_rfc3339(last["window"]["start"].as_str().unwrap()).unwrap();
    let end = chrono::DateTime::parse_from_rfc3339(last["window"]["end"].as_str().unwrap()).unwrap();
    assert_eq!((end - start).num_seconds(), WINDOW);
    // The records came in batches of at most two, each starting from the
    // state the one before returned.
    assert_eq!(partial.iter().map(|r| r["count"].as_i64().unwrap()).sum::<i64>(), 5, "{got:?}");
    assert!(partial.len() >= 3, "{got:?}");
    assert!(partial.iter().all(|r| r["window"] == last["window"]), "{got:?}");
    let fresh = partial.iter().filter(|r| r["state"] == serde_json::json!({})).count();
    assert_eq!(fresh, 1, "{got:?}");
    assert!(partial.iter().all(|r| r["state"] == serde_json::json!({}) || r["state"]["total"].is_string()), "{got:?}");
}
