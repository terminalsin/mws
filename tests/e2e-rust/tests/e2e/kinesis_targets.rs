//! Kinesis Data Streams and Firehose as destinations of other services,
//! through the official Rust SDKs: CloudWatch Logs subscription filters,
//! EventBridge targets and Lambda event source mappings.

use std::io::Read;
use std::time::Duration;

use aws_sdk_cloudwatchlogs::types::InputLogEvent;
use aws_sdk_eventbridge::types::{KinesisParameters, PutEventsRequestEntry, Target};
use aws_sdk_firehose::types::{BufferingHints, ExtendedS3DestinationConfiguration};
use aws_sdk_kinesis::types::{ShardIteratorType, StreamStatus};
use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{EventSourcePosition, Filter, FilterCriteria, FunctionCode, Runtime};
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

fn trust(service: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
    )
}

async fn role(cfg: &aws_config::SdkConfig, name: &str, service: &str, actions: &str) -> String {
    let iam = aws_sdk_iam::Client::new(cfg);
    let r = iam.create_role().role_name(name).assume_role_policy_document(trust(service)).send().await.unwrap();
    let policy =
        format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":"*"}}]}}"#);
    iam.put_role_policy().role_name(name).policy_name("p").policy_document(policy).send().await.unwrap();
    r.role().unwrap().arn().to_string()
}

async fn stream(k: &aws_sdk_kinesis::Client, name: &str) -> String {
    k.create_stream().stream_name(name).shard_count(1).send().await.unwrap();
    for _ in 0..50 {
        let s = k.describe_stream_summary().stream_name(name).send().await.unwrap();
        if s.stream_description_summary().unwrap().stream_status() == &StreamStatus::Active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    format!("arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/{name}")
}

/// Every record in the stream's single shard, waiting until there are `n`.
async fn records(k: &aws_sdk_kinesis::Client, name: &str, n: usize) -> Vec<aws_sdk_kinesis::types::Record> {
    for _ in 0..50 {
        let it = k
            .get_shard_iterator()
            .stream_name(name)
            .shard_id("shardId-000000000000")
            .shard_iterator_type(ShardIteratorType::TrimHorizon)
            .send()
            .await
            .unwrap();
        let out = k.get_records().shard_iterator(it.shard_iterator().unwrap()).send().await.unwrap();
        if out.records().len() >= n {
            return out.records().to_vec();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{name} never got {n} records");
}

fn gunzip(data: &[u8]) -> serde_json::Value {
    let mut out = String::new();
    flate2::read::GzDecoder::new(data).read_to_string(&mut out).unwrap();
    serde_json::from_str(&out).unwrap()
}

#[tokio::test]
async fn logs_subscriptions_write_to_kinesis_and_firehose() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let k = aws_sdk_kinesis::Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let arn = stream(&k, "logs").await;
    logs.create_log_group().log_group_name("/setup").send().await.unwrap();

    // Without a role CloudWatch Logs cannot write to the stream.
    let e = logs
        .put_subscription_filter()
        .log_group_name("/setup")
        .filter_name("all")
        .filter_pattern("")
        .destination_arn(&arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(e.is_invalid_parameter_exception(), "{e:?}");
    let to_kinesis = role(&cfg, "cwl-kinesis", "logs.amazonaws.com", r#"["kinesis:PutRecord"]"#).await;

    // Deliveries go straight to the stream, or through a Logs destination.
    logs.put_destination().destination_name("central").target_arn(&arn).role_arn(&to_kinesis).send().await.unwrap();
    logs.delete_log_group().log_group_name("/setup").send().await.unwrap();
    logs.create_log_group().log_group_name("/app").send().await.unwrap();
    logs.create_log_stream().log_group_name("/app").log_stream_name("web-1").send().await.unwrap();
    logs.put_subscription_filter()
        .log_group_name("/app")
        .filter_name("errors")
        .filter_pattern("ERROR")
        .destination_arn(&arn)
        .role_arn(&to_kinesis)
        .send()
        .await
        .unwrap();
    // The new subscription's test message is in the stream.
    let control = records(&k, "logs", 1).await;
    let msg = gunzip(control[0].data().as_ref());
    assert_eq!(msg["messageType"], "CONTROL_MESSAGE");
    assert_eq!(msg["logEvents"][0]["message"], "CWL CONTROL MESSAGE: Checking health of destination Kinesis stream.");

    let now = chrono::Utc::now().timestamp_millis();
    logs.put_log_events()
        .log_group_name("/app")
        .log_stream_name("web-1")
        .log_events(InputLogEvent::builder().timestamp(now).message("INFO ok").build().unwrap())
        .log_events(InputLogEvent::builder().timestamp(now + 1).message("ERROR disk full").build().unwrap())
        .send()
        .await
        .unwrap();
    let got = records(&k, "logs", 2).await;
    assert_eq!(got[1].partition_key(), Some("web-1"));
    let data = gunzip(got[1].data().as_ref());
    assert_eq!(data["messageType"], "DATA_MESSAGE");
    assert_eq!(data["owner"], ACCOUNT);
    assert_eq!(data["logGroup"], "/app");
    assert_eq!(data["subscriptionFilters"], serde_json::json!(["errors"]));
    assert_eq!(data["logEvents"].as_array().unwrap().len(), 1);
    assert_eq!(data["logEvents"][0]["message"], "ERROR disk full");

    // Through the destination: its target and role are used.
    logs.create_log_group().log_group_name("/other").send().await.unwrap();
    logs.create_log_stream().log_group_name("/other").log_stream_name("s").send().await.unwrap();
    logs.put_subscription_filter()
        .log_group_name("/other")
        .filter_name("all")
        .filter_pattern("")
        .destination_arn(format!("arn:aws:logs:us-east-1:{ACCOUNT}:destination:central"))
        .distribution(aws_sdk_cloudwatchlogs::types::Distribution::Random)
        .send()
        .await
        .unwrap();
    logs.put_log_events()
        .log_group_name("/other")
        .log_stream_name("s")
        .log_events(InputLogEvent::builder().timestamp(now).message("hello").build().unwrap())
        .send()
        .await
        .unwrap();
    let got = records(&k, "logs", 3).await;
    let data = gunzip(got[2].data().as_ref());
    assert_eq!(data["logGroup"], "/other");
    assert_ne!(got[2].partition_key(), Some("s"));

    // Firehose: the gzipped messages land in S3.
    let f = aws_sdk_firehose::Client::new(&cfg);
    let delivery = role(&cfg, "delivery", "firehose.amazonaws.com", r#"["s3:PutObject"]"#).await;
    Mws::s3(&cfg).create_bucket().bucket("archive").send().await.unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("archive")
        .extended_s3_destination_configuration(
            ExtendedS3DestinationConfiguration::builder()
                .role_arn(&delivery)
                .bucket_arn("arn:aws:s3:::archive")
                .buffering_hints(BufferingHints::builder().interval_in_seconds(0).size_in_mbs(1).build())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    for _ in 0..50 {
        let d = f.describe_delivery_stream().delivery_stream_name("archive").send().await.unwrap();
        if d.delivery_stream_description().unwrap().delivery_stream_status().as_str() == "ACTIVE" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let to_firehose = role(&cfg, "cwl-firehose", "logs.amazonaws.com", r#"["firehose:PutRecord"]"#).await;
    logs.create_log_group().log_group_name("/fh").send().await.unwrap();
    logs.create_log_stream().log_group_name("/fh").log_stream_name("s").send().await.unwrap();
    logs.put_subscription_filter()
        .log_group_name("/fh")
        .filter_name("all")
        .filter_pattern("")
        .destination_arn(format!("arn:aws:firehose:us-east-1:{ACCOUNT}:deliverystream/archive"))
        .role_arn(&to_firehose)
        .send()
        .await
        .unwrap();
    logs.put_log_events()
        .log_group_name("/fh")
        .log_stream_name("s")
        .log_events(InputLogEvent::builder().timestamp(now).message("to firehose").build().unwrap())
        .send()
        .await
        .unwrap();
    let s3 = Mws::s3(&cfg);
    let mut messages = Vec::new();
    for _ in 0..100 {
        let _ = f.list_delivery_streams().send().await;
        messages.clear();
        for o in s3.list_objects_v2().bucket("archive").send().await.unwrap().contents() {
            let body = s3.get_object().bucket("archive").key(o.key().unwrap()).send().await.unwrap();
            let bytes = body.body.collect().await.unwrap().into_bytes();
            // Each record is its own gzip member.
            let mut text = String::new();
            flate2::read::MultiGzDecoder::new(&bytes[..]).read_to_string(&mut text).unwrap();
            let mut stream = serde_json::Deserializer::from_str(&text).into_iter::<serde_json::Value>();
            while let Some(Ok(v)) = stream.next() {
                messages.push(v);
            }
        }
        if messages.iter().any(|m| m["messageType"] == "DATA_MESSAGE") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(messages.iter().any(|m| m["messageType"] == "CONTROL_MESSAGE"), "{messages:?}");
    let data = messages.iter().find(|m| m["messageType"] == "DATA_MESSAGE").expect("no data message delivered");
    assert_eq!(data["logEvents"][0]["message"], "to firehose");
}

#[tokio::test]
async fn eventbridge_targets_kinesis_and_firehose() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let k = aws_sdk_kinesis::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let arn = stream(&k, "orders").await;
    let role_arn =
        role(&cfg, "eb-targets", "events.amazonaws.com", r#"["kinesis:PutRecord","firehose:PutRecord"]"#).await;
    eb.put_rule().name("orders").event_pattern(r#"{"source":["shop"]}"#).send().await.unwrap();

    // Kinesis targets need a role.
    let missing = eb
        .put_targets()
        .rule("orders")
        .targets(Target::builder().id("k").arn(&arn).build().unwrap())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(missing.meta().code(), Some("ValidationException"));
    assert_eq!(missing.meta().message(), Some("Parameter(s) RoleArn must be specified for target: k."));

    let f = aws_sdk_firehose::Client::new(&cfg);
    let delivery = role(&cfg, "delivery", "firehose.amazonaws.com", r#"["s3:PutObject"]"#).await;
    Mws::s3(&cfg).create_bucket().bucket("events").send().await.unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("events")
        .extended_s3_destination_configuration(
            ExtendedS3DestinationConfiguration::builder()
                .role_arn(&delivery)
                .bucket_arn("arn:aws:s3:::events")
                .buffering_hints(BufferingHints::builder().interval_in_seconds(0).size_in_mbs(1).build())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("orders")
        .targets(
            Target::builder()
                .id("k")
                .arn(&arn)
                .role_arn(&role_arn)
                .kinesis_parameters(
                    KinesisParameters::builder().partition_key_path("$.detail.customer").build().unwrap(),
                )
                .build()
                .unwrap(),
        )
        .targets(
            Target::builder()
                .id("f")
                .arn(format!("arn:aws:firehose:us-east-1:{ACCOUNT}:deliverystream/events"))
                .role_arn(&role_arn)
                .input_path("$.detail")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    eb.put_events()
        .entries(
            PutEventsRequestEntry::builder()
                .source("shop")
                .detail_type("OrderPlaced")
                .detail(r#"{"customer":"c-42","total":10}"#)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let got = records(&k, "orders", 1).await;
    assert_eq!(got[0].partition_key(), Some("c-42"));
    let event: serde_json::Value = serde_json::from_slice(got[0].data().as_ref()).unwrap();
    assert_eq!(event["detail-type"], "OrderPlaced");
    assert_eq!(event["detail"]["total"], 10);

    let s3 = Mws::s3(&cfg);
    let mut body = None;
    for _ in 0..100 {
        let _ = f.list_delivery_streams().send().await;
        let listed = s3.list_objects_v2().bucket("events").send().await.unwrap();
        if let Some(o) = listed.contents().first() {
            let got = s3.get_object().bucket("events").key(o.key().unwrap()).send().await.unwrap();
            body = Some(got.body.collect().await.unwrap().into_bytes().to_vec());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let body: serde_json::Value = serde_json::from_slice(&body.expect("nothing delivered to S3")).unwrap();
    assert_eq!(body, serde_json::json!({"customer": "c-42", "total": 10}));
}

const RECORDER: &str = r#"
import base64, json

def handler(event, context):
    for r in event["Records"]:
        data = base64.b64decode(r["kinesis"]["data"]).decode()
        print("GOT " + json.dumps({"data": data, "source": r["eventSource"], "id": r["eventID"],
                                   "name": r["eventName"], "arn": r["eventSourceARN"],
                                   "identity": r["invokeIdentityArn"], "key": r["kinesis"]["partitionKey"]}))
        if data == "poison":
            return {"batchItemFailures": [{"itemIdentifier": r["kinesis"]["sequenceNumber"]}]}
    return {"batchItemFailures": []}
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

#[tokio::test]
async fn lambda_event_source_mappings_read_kinesis() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let k = aws_sdk_kinesis::Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let arn = stream(&k, "clicks").await;
    k.put_record()
        .stream_name("clicks")
        .partition_key("early")
        .data(aws_sdk_kinesis::primitives::Blob::new("before the mapping"))
        .send()
        .await
        .unwrap();

    let no_read = role(&cfg, "no-read", "lambda.amazonaws.com", r#"["logs:*"]"#).await;
    let can_read = role(&cfg, "reader", "lambda.amazonaws.com", r#"["logs:*","kinesis:*"]"#).await;
    let create = |name: &'static str, role: String| {
        let lambda = lambda.clone();
        async move {
            lambda
                .create_function()
                .function_name(name)
                .runtime(Runtime::Python312)
                .role(role)
                .handler("app.handler")
                .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", RECORDER)]))).build())
                .send()
                .await
                .unwrap()
        }
    };
    create("blocked", no_read).await;
    create("reader", can_read.clone()).await;

    let denied = lambda
        .create_event_source_mapping()
        .function_name("blocked")
        .event_source_arn(&arn)
        .starting_position(EventSourcePosition::TrimHorizon)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(denied.meta().code(), Some("InvalidParameterValueException"));
    assert_eq!(
        denied.meta().message(),
        Some("The provided execution role does not have permissions to call DescribeStream on Kinesis")
    );
    let no_position = lambda
        .create_event_source_mapping()
        .function_name("reader")
        .event_source_arn(&arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(no_position.meta().code(), Some("InvalidParameterValueException"));

    // LATEST: only what arrives after the mapping exists. Records whose
    // JSON data does not match the filter are skipped.
    let mapping = lambda
        .create_event_source_mapping()
        .function_name("reader")
        .event_source_arn(&arn)
        .starting_position(EventSourcePosition::Latest)
        .batch_size(10)
        .function_response_types(aws_sdk_lambda::types::FunctionResponseType::ReportBatchItemFailures)
        .maximum_retry_attempts(1)
        .filter_criteria(
            FilterCriteria::builder()
                .filters(Filter::builder().pattern(r#"{"kinesis":{"data":{"keep":[false]}}}"#).build())
                .filters(Filter::builder().pattern(r#"{"kinesis":{"partitionKey":["plain"]}}"#).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(mapping.starting_position(), Some(&EventSourcePosition::Latest));
    assert_eq!(mapping.batch_size(), Some(10));
    for (key, data) in
        [("plain", "hello"), ("json", r#"{"keep":true}"#), ("json", r#"{"keep":false}"#), ("plain", "poison")]
    {
        k.put_record()
            .stream_name("clicks")
            .partition_key(key)
            .data(aws_sdk_kinesis::primitives::Blob::new(data))
            .send()
            .await
            .unwrap();
    }
    let mut lines: Vec<serde_json::Value> = Vec::new();
    for _ in 0..80 {
        let found = logs.filter_log_events().log_group_name("/aws/lambda/reader").filter_pattern("GOT").send().await;
        lines = found
            .map(|f| {
                f.events()
                    .iter()
                    .filter_map(|e| e.message())
                    .filter_map(|m| m.trim().strip_prefix("GOT ").and_then(|j| serde_json::from_str(j).ok()))
                    .collect()
            })
            .unwrap_or_default();
        // The poison record is retried once, then skipped.
        if lines.iter().filter(|l| l["data"] == "poison").count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let data: Vec<&str> = lines.iter().map(|l| l["data"].as_str().unwrap()).collect();
    assert!(!data.contains(&"before the mapping"), "{data:?}");
    assert!(!data.contains(&r#"{"keep":true}"#), "{data:?}");
    assert!(data.contains(&"hello") && data.contains(&r#"{"keep":false}"#), "{data:?}");
    assert_eq!(data.iter().filter(|d| **d == "poison").count(), 2, "{data:?}");
    // "hello" is processed once: the retry starts at the failed record.
    assert_eq!(data.iter().filter(|d| **d == "hello").count(), 1, "{data:?}");
    let first = &lines[0];
    assert_eq!(first["source"], "aws:kinesis");
    assert_eq!(first["name"], "aws:kinesis:record");
    assert_eq!(first["arn"], arn);
    assert_eq!(first["identity"], can_read);
    assert!(first["id"].as_str().unwrap().starts_with("shardId-000000000000:"));
}
