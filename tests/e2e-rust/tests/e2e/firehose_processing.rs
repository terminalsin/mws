//! Firehose Lambda transformations through the official Rust SDK: the
//! processor buffers records (`BufferSizeInMBs`, `BufferIntervalInSeconds`)
//! and invokes the function once per buffer, retries failed invocations
//! `NumberOfRetries` times, then writes the records to the
//! `processing-failed` error output, and publishes the `ExecuteProcessing`
//! metrics.

use aws_sdk_lambda::client::Waiters;
use std::time::Duration;

use aws_sdk_firehose::primitives::Blob;
use aws_sdk_firehose::types::{
    BufferingHints, DeliveryStreamStatus, ExtendedS3DestinationConfiguration, ProcessingConfiguration, Processor,
    ProcessorParameter, ProcessorParameterName, ProcessorType, Record,
};
use aws_sdk_firehose::Client;
use mws_e2e::Mws;

use crate::firehose::{objects, role_and_bucket, wait_status, zip};

/// Each record becomes the number of records its invocation carried.
const COUNTER: &str = r#"
import base64

def handler(event, context):
    n = len(event["records"])
    data = base64.b64encode(f"{n}\n".encode()).decode()
    return {"records": [{"recordId": r["recordId"], "result": "Ok", "data": data} for r in event["records"]]}
"#;

const FAILING: &str = r#"
def handler(event, context):
    raise Exception("boom")
"#;

async fn function(mws: &Mws, name: &str, code: &str) -> String {
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role =
        iam.create_role().role_name(format!("{name}-fn")).assume_role_policy_document(trust).send().await.unwrap();
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let created = lambda
        .create_function()
        .function_name(name)
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(aws_sdk_lambda::primitives::Blob::new(zip(&[("app.py", code)])))
                .build(),
        )
        .send()
        .await
        .unwrap();
    lambda.wait_until_function_active_v2().function_name(name).wait(Duration::from_secs(60)).await.unwrap();
    created.function_arn().unwrap().to_string()
}

fn parameter(name: ProcessorParameterName, value: &str) -> ProcessorParameter {
    ProcessorParameter::builder().parameter_name(name).parameter_value(value).build().unwrap()
}

async fn delivery_stream(f: &Client, name: &str, role: &str, parameters: Vec<ProcessorParameter>) {
    let config = ExtendedS3DestinationConfiguration::builder()
        .role_arn(role)
        .bucket_arn("arn:aws:s3:::landing")
        .prefix("out/")
        .buffering_hints(BufferingHints::builder().interval_in_seconds(0).size_in_mbs(5).build())
        .processing_configuration(
            ProcessingConfiguration::builder()
                .enabled(true)
                .processors(
                    Processor::builder()
                        .r#type(ProcessorType::Lambda)
                        .set_parameters(Some(parameters))
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .build()
        .unwrap();
    f.create_delivery_stream()
        .delivery_stream_name(name)
        .extended_s3_destination_configuration(config)
        .send()
        .await
        .unwrap();
    wait_status(f, name, DeliveryStreamStatus::Active).await;
}

/// Move the emulated clock past the processor's 60 s buffer interval.
async fn past_processor_interval(mws: &Mws) {
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 61}"#)).await;
    assert_eq!(status, 200);
}

async fn metric(
    cw: &aws_sdk_cloudwatch::Client,
    name: &str,
    stream: &str,
    stat: aws_sdk_cloudwatch::types::Statistic,
) -> Vec<f64> {
    let now = chrono::Utc::now().timestamp();
    let mut out = Vec::new();
    for _ in 0..50 {
        let stats = cw
            .get_metric_statistics()
            .namespace("AWS/Firehose")
            .metric_name(name)
            .dimensions(
                aws_sdk_cloudwatch::types::Dimension::builder().name("DeliveryStreamName").value(stream).build(),
            )
            .start_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(now - 3600))
            .end_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(now + 3600))
            .period(7200)
            .statistics(stat.clone())
            .send()
            .await
            .unwrap();
        out = stats
            .datapoints()
            .iter()
            .filter_map(|p| match stat {
                aws_sdk_cloudwatch::types::Statistic::SampleCount => p.sample_count(),
                aws_sdk_cloudwatch::types::Statistic::Average => p.average(),
                _ => p.sum(),
            })
            .collect();
        if !out.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    out
}

#[tokio::test]
async fn invocations_follow_the_processor_buffer_size() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let f = Client::new(&cfg);
    let role = role_and_bucket(&mws, "delivery", "landing", r#"["s3:PutObject","lambda:InvokeFunction"]"#).await;
    let arn = function(&mws, "counter", COUNTER).await;
    // 0.2 MB (209,715 bytes) per invocation: two 100 KiB records each.
    delivery_stream(
        &f,
        "split",
        &role,
        vec![
            parameter(ProcessorParameterName::LambdaArn, &arn),
            parameter(ProcessorParameterName::BufferSizeInMb, "0.2"),
        ],
    )
    .await;
    let mut batch = f.put_record_batch().delivery_stream_name("split");
    for _ in 0..4 {
        batch = batch.records(Record::builder().data(Blob::new(vec![b'x'; 100 * 1024])).build().unwrap());
    }
    batch.send().await.unwrap();
    // Nothing is transformed before the processor's 60 s interval.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let s3 = Mws::s3(&cfg);
    let listed = s3.list_objects_v2().bucket("landing").prefix("out/").send().await.unwrap();
    assert!(listed.contents().is_empty(), "delivered before the processor buffer interval");
    past_processor_interval(&mws).await;
    let out = objects(&mws, &f, "landing", "out/", 1).await;
    assert_eq!(String::from_utf8_lossy(&out[0].1), "2\n2\n2\n2\n");
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    let durations =
        metric(&cw, "ExecuteProcessing.Duration", "split", aws_sdk_cloudwatch::types::Statistic::SampleCount).await;
    assert_eq!(durations.iter().sum::<f64>(), 2.0, "two invocations");
    let success =
        metric(&cw, "ExecuteProcessing.Success", "split", aws_sdk_cloudwatch::types::Statistic::Average).await;
    assert_eq!(success, vec![1.0]);
    mws.stop().await;
}

#[tokio::test]
async fn failed_invocations_are_retried_then_written_to_processing_failed() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let f = Client::new(&cfg);
    let role = role_and_bucket(&mws, "delivery", "landing", r#"["s3:PutObject","lambda:InvokeFunction"]"#).await;
    let arn = function(&mws, "failing", FAILING).await;
    delivery_stream(
        &f,
        "retries",
        &role,
        vec![
            parameter(ProcessorParameterName::LambdaArn, &arn),
            parameter(ProcessorParameterName::LambdaNumberOfRetries, "2"),
        ],
    )
    .await;
    f.put_record()
        .delivery_stream_name("retries")
        .record(Record::builder().data(Blob::new("hello")).build().unwrap())
        .send()
        .await
        .unwrap();
    past_processor_interval(&mws).await;
    let failed = objects(&mws, &f, "landing", "processing-failed/", 1).await;
    let line: serde_json::Value = serde_json::from_slice(failed[0].1.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["errorCode"], "Lambda.FunctionError");
    assert!(line["errorMessage"]
        .as_str()
        .unwrap()
        .starts_with("The Lambda function was successfully invoked but it returned an error result."));
    // The first invocation and two retries.
    assert_eq!(line["attemptsMade"], 3);
    assert_eq!(line["lambdaArn"], arn.as_str());
    assert_eq!(line["rawData"], "aGVsbG8=");
    assert!(line["arrivalTimestamp"].is_i64() && line["attemptEndingTimestamp"].is_i64());
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    let durations =
        metric(&cw, "ExecuteProcessing.Duration", "retries", aws_sdk_cloudwatch::types::Statistic::SampleCount).await;
    assert_eq!(durations.iter().sum::<f64>(), 3.0);
    let success =
        metric(&cw, "ExecuteProcessing.Success", "retries", aws_sdk_cloudwatch::types::Statistic::Average).await;
    assert_eq!(success, vec![0.0]);
    mws.stop().await;
}
