//! Recursive loop detection, through the official Rust SDK with boto3 in
//! the functions: the SDK in a function sends the X-Ray header Lambda gave
//! it, SQS keeps it as `AWSTraceHeader` and SNS carries it on, and Lambda
//! stops a Lambda-SQS or Lambda-SNS loop after 16 invocations unless the
//! function's `RecursiveLoop` is `Allow`.

use aws_sdk_lambda::client::Waiters;
use std::time::Duration;

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{DestinationConfig, FunctionCode, OnFailure, RecursiveLoop, Runtime};
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Notes each invocation in `seen`, then sends the event round again: to
/// the queue it reads (SQS records) or the topic it is subscribed to (SNS
/// records).
const LOOPER: &str = r#"
import json, os, boto3

sqs = boto3.client("sqs")
sns = boto3.client("sns")

def handler(event, context):
    seen = sqs.get_queue_url(QueueName="seen")["QueueUrl"]
    for r in event["Records"]:
        sqs.send_message(QueueUrl=seen, MessageBody=json.dumps({
            "fn": context.function_name,
            "env": os.environ.get("_X_AMZN_TRACE_ID"),
            "trace": r.get("attributes", {}).get("AWSTraceHeader"),
        }))
        if "Sns" in r:
            sns.publish(TopicArn=r["Sns"]["TopicArn"], Message="again")
        else:
            loop = sqs.get_queue_url(QueueName=os.environ["LOOP"])["QueueUrl"]
            sqs.send_message(QueueUrl=loop, MessageBody="again")
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

async fn queue(sqs: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let url = sqs
        .create_queue()
        .queue_name(name)
        .attributes(QueueAttributeName::VisibilityTimeout, "30")
        .send()
        .await
        .unwrap()
        .queue_url
        .unwrap();
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

async fn function(lambda: &aws_sdk_lambda::Client, name: &str, role: &str, loop_queue: &str) -> String {
    let out = lambda
        .create_function()
        .function_name(name)
        .runtime(Runtime::Python312)
        .role(role)
        .handler("app.handler")
        .timeout(10)
        .environment(aws_sdk_lambda::types::Environment::builder().variables("LOOP", loop_queue).build())
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", LOOPER)]))).build())
        .send()
        .await
        .unwrap();
    lambda.wait_until_function_active_v2().function_name(name).wait(Duration::from_secs(60)).await.unwrap();
    out.function_arn().unwrap().to_string()
}

/// Every message in `url` so far, waiting until no more arrive for a few
/// seconds (or `enough` have).
async fn settle(sqs: &aws_sdk_sqs::Client, url: &str, enough: usize) -> Vec<serde_json::Value> {
    let mut got = Vec::new();
    let mut quiet = 0;
    for _ in 0..240 {
        let out = sqs.receive_message().queue_url(url).max_number_of_messages(10).send().await.unwrap();
        quiet = if out.messages().is_empty() { quiet + 1 } else { 0 };
        for m in out.messages() {
            got.push(serde_json::from_str(m.body().unwrap()).unwrap());
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
        if quiet >= 16 || got.len() >= enough {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    got
}

async fn setup(mws: &Mws) -> (aws_sdk_sqs::Client, aws_sdk_lambda::Client, String) {
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role = iam.create_role().role_name("looper").assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy()
        .role_name("looper")
        .policy_name("p")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:*","sns:*","logs:*"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    (aws_sdk_sqs::Client::new(&cfg), aws_sdk_lambda::Client::new(&cfg), role.role().unwrap().arn().to_string())
}

#[tokio::test]
async fn lambda_stops_a_loop_through_sqs_after_16_invocations() {
    let mws = Mws::start().await;
    let (sqs, lambda, role) = setup(&mws).await;
    let (seen_url, _) = queue(&sqs, "seen").await;
    let (loop_url, loop_arn) = queue(&sqs, "loop").await;
    function(&lambda, "looper", &role, "loop").await;
    let config = lambda.get_function_recursion_config().function_name("looper").send().await.unwrap();
    assert_eq!(config.recursive_loop(), Some(&RecursiveLoop::Terminate));
    lambda.create_event_source_mapping().function_name("looper").event_source_arn(&loop_arn).send().await.unwrap();

    sqs.send_message().queue_url(&loop_url).message_body("start").send().await.unwrap();
    let seen = settle(&sqs, &seen_url, 40).await;
    assert_eq!(seen.len(), 16, "{seen:?}");
    // The function runs with an X-Ray header, which boto3 passes on and
    // SQS keeps as the message's AWSTraceHeader.
    let first = seen.iter().find(|s| s["trace"].is_null()).expect("the first message had no trace header");
    let root = first["env"].as_str().unwrap().split(';').next().unwrap().to_string();
    assert!(root.starts_with("Root=1-"), "{first:?}");
    assert!(first["env"].as_str().unwrap().contains("Lineage="), "{first:?}");
    let traced: Vec<&serde_json::Value> = seen.iter().filter(|s| !s["trace"].is_null()).collect();
    assert_eq!(traced.len(), 15, "{seen:?}");
    assert!(traced.iter().all(|s| s["trace"].as_str().unwrap().starts_with(&root)), "{seen:?}");
    assert!(seen.iter().all(|s| s["env"].as_str().unwrap().starts_with(&root)), "{seen:?}");
}

#[tokio::test]
async fn recursive_loop_allow_lets_the_loop_run() {
    let mws = Mws::start().await;
    let (sqs, lambda, role) = setup(&mws).await;
    let (seen_url, _) = queue(&sqs, "seen").await;
    let (loop_url, loop_arn) = queue(&sqs, "loop").await;
    function(&lambda, "spinner", &role, "loop").await;
    let put = lambda
        .put_function_recursion_config()
        .function_name("spinner")
        .recursive_loop(RecursiveLoop::Allow)
        .send()
        .await
        .unwrap();
    assert_eq!(put.recursive_loop(), Some(&RecursiveLoop::Allow));
    let mapping =
        lambda.create_event_source_mapping().function_name("spinner").event_source_arn(&loop_arn).send().await.unwrap();
    sqs.send_message().queue_url(&loop_url).message_body("start").send().await.unwrap();
    let seen = settle(&sqs, &seen_url, 20).await;
    assert!(seen.len() >= 20, "the loop stopped at {}", seen.len());
    lambda.delete_event_source_mapping().uuid(mapping.uuid().unwrap()).send().await.unwrap();
}

#[tokio::test]
async fn lambda_stops_a_loop_through_sns_and_sends_the_event_on() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let (sqs, lambda, role) = setup(&mws).await;
    let sns = aws_sdk_sns::Client::new(&cfg);
    let (seen_url, _) = queue(&sqs, "seen").await;
    let (failed_url, failed_arn) = queue(&sqs, "failed").await;
    let arn = function(&lambda, "echo", &role, "unused").await;
    lambda
        .put_function_event_invoke_config()
        .function_name("echo")
        .destination_config(
            DestinationConfig::builder().on_failure(OnFailure::builder().destination(&failed_arn).build()).build(),
        )
        .send()
        .await
        .unwrap();
    let topic = sns.create_topic().name("echoes").send().await.unwrap().topic_arn.unwrap();
    lambda
        .add_permission()
        .function_name("echo")
        .statement_id("sns")
        .action("lambda:InvokeFunction")
        .principal("sns.amazonaws.com")
        .source_arn(&topic)
        .send()
        .await
        .unwrap();
    sns.subscribe().topic_arn(&topic).protocol("lambda").endpoint(&arn).send().await.unwrap();

    sns.publish().topic_arn(&topic).message("start").send().await.unwrap();
    let seen = settle(&sqs, &seen_url, 40).await;
    assert_eq!(seen.len(), 16, "{seen:?}");
    let failed = settle(&sqs, &failed_url, 1).await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    let record = &failed[0];
    assert_eq!(record["requestContext"]["functionArn"], format!("{arn}:$LATEST"));
    assert_eq!(record["responsePayload"]["errorType"], "RecursiveInvocationException");
    assert_eq!(record["requestPayload"]["Records"][0]["Sns"]["Message"], "again");
}
