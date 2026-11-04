//! CloudWatch Logs subscription filters delivering matching events to a
//! Lambda function, through the official Rust SDKs.

use std::time::Duration;

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, Runtime};
use mws_e2e::Mws;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Decodes the `awslogs` payload and logs it, so the test can read it back
/// from the function's own log group.
const SINK: &str = r#"
import base64, gzip, json

def handler(event, context):
    data = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    print("DECODED " + json.dumps(data))
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
async fn subscription_filters_invoke_lambda() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);

    let role = iam.create_role().role_name("sink").assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy()
        .role_name("sink")
        .policy_name("logs")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:*","Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let function_arn = lambda
        .create_function()
        .function_name("sink")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", SINK)]))).build())
        .send()
        .await
        .unwrap()
        .function_arn
        .unwrap();
    logs.create_log_group().log_group_name("/app").send().await.unwrap();
    logs.create_log_stream().log_group_name("/app").log_stream_name("web-1").send().await.unwrap();

    // CloudWatch Logs must be allowed to invoke the function.
    let e = logs
        .put_subscription_filter()
        .log_group_name("/app")
        .filter_name("errors")
        .filter_pattern("ERROR")
        .destination_arn(&function_arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(e.is_invalid_parameter_exception());
    assert_eq!(
        e.meta().message(),
        Some("Could not execute the lambda function. Make sure you have given CloudWatch Logs permission to execute your function.")
    );
    lambda
        .add_permission()
        .function_name("sink")
        .statement_id("logs")
        .action("lambda:InvokeFunction")
        .principal("logs.amazonaws.com")
        .source_arn("arn:aws:logs:us-east-1:123456789012:log-group:/app:*")
        .send()
        .await
        .unwrap();
    logs.put_subscription_filter()
        .log_group_name("/app")
        .filter_name("errors")
        .filter_pattern("ERROR")
        .destination_arn(&function_arn)
        .send()
        .await
        .unwrap();

    let now = chrono::Utc::now().timestamp_millis();
    logs.put_log_events()
        .log_group_name("/app")
        .log_stream_name("web-1")
        .log_events(
            aws_sdk_cloudwatchlogs::types::InputLogEvent::builder()
                .timestamp(now)
                .message("INFO all good")
                .build()
                .unwrap(),
        )
        .log_events(
            aws_sdk_cloudwatchlogs::types::InputLogEvent::builder()
                .timestamp(now + 1)
                .message("ERROR disk full")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let mut decoded = None;
    for _ in 0..60 {
        let found = logs.filter_log_events().log_group_name("/aws/lambda/sink").filter_pattern("DECODED").send().await;
        if let Some(line) = found.ok().and_then(|f| f.events().first().and_then(|e| e.message().map(str::to_string))) {
            decoded = Some(line);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let line = decoded.expect("the function was not invoked");
    let data: serde_json::Value = serde_json::from_str(line.trim().strip_prefix("DECODED ").unwrap()).unwrap();
    assert_eq!(data["messageType"], "DATA_MESSAGE");
    assert_eq!(data["owner"], "123456789012");
    assert_eq!(data["logGroup"], "/app");
    assert_eq!(data["logStream"], "web-1");
    assert_eq!(data["subscriptionFilters"], serde_json::json!(["errors"]));
    let events = data["logEvents"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["message"], "ERROR disk full");
    assert_eq!(events[0]["timestamp"], now + 1);
    assert_eq!(events[0]["id"].as_str().unwrap().len(), 56);
    mws.stop().await;
}
