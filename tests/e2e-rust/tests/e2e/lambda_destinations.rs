//! Where Lambda sends invocation records, through the official Rust SDK:
//! asynchronous invocation destinations on SQS and EventBridge, a
//! function's dead-letter queue, and a Kinesis mapping's on-failure
//! destination. Also the event source mapping rules AWS enforces: no
//! duplicate mappings, and mappings outlive their function.

use std::time::Duration;

use aws_sdk_lambda::operation::RequestId;
use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{
    DeadLetterConfig, DestinationConfig, EventSourcePosition, FunctionCode, InvocationType, OnFailure, OnSuccess,
    Runtime,
};
use aws_sdk_sqs::types::{MessageSystemAttributeName, QueueAttributeName};
use mws_e2e::Mws;

use crate::lambda::zip;

const ACCOUNT: &str = "123456789012";
const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const HANDLER: &str = r#"
def handler(event, context):
    if event.get("fail"):
        raise ValueError("bad order " + str(event.get("id")))
    return {"ok": event.get("id")}
"#;

async fn role(cfg: &aws_config::SdkConfig, name: &str, actions: &str) -> String {
    let iam = aws_sdk_iam::Client::new(cfg);
    let r = iam.create_role().role_name(name).assume_role_policy_document(TRUST).send().await.unwrap();
    let policy =
        format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":"*"}}]}}"#);
    iam.put_role_policy().role_name(name).policy_name("p").policy_document(policy).send().await.unwrap();
    r.role().unwrap().arn().to_string()
}

async fn queue(sqs: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url.unwrap();
    (url, format!("arn:aws:sqs:us-east-1:{ACCOUNT}:{name}"))
}

/// The first message on a queue, waiting for it.
async fn next_message(sqs: &aws_sdk_sqs::Client, url: &str) -> aws_sdk_sqs::types::Message {
    for _ in 0..120 {
        let out = sqs
            .receive_message()
            .queue_url(url)
            .message_attribute_names("All")
            .message_system_attribute_names(MessageSystemAttributeName::All)
            .send()
            .await
            .unwrap();
        if let Some(m) = out.messages().first() {
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
            return m.clone();
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("nothing arrived on {url}");
}

fn body(m: &aws_sdk_sqs::types::Message) -> serde_json::Value {
    serde_json::from_str(m.body().unwrap()).unwrap()
}

#[tokio::test]
async fn async_invocations_reach_their_destinations_and_dead_letter_queue() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let role_arn = role(&cfg, "orders-role", r#"["sqs:SendMessage","events:PutEvents","logs:*"]"#).await;
    let (ok_url, ok_arn) = queue(&sqs, "succeeded").await;
    let (failed_url, failed_arn) = queue(&sqs, "failed").await;
    let (dlq_url, dlq_arn) = queue(&sqs, "orders-dlq").await;

    let fn_arn = lambda
        .create_function()
        .function_name("orders")
        .runtime(Runtime::Python312)
        .role(&role_arn)
        .handler("app.handler")
        .dead_letter_config(DeadLetterConfig::builder().target_arn(&dlq_arn).build())
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", HANDLER)]))).build())
        .send()
        .await
        .unwrap()
        .function_arn
        .unwrap();
    lambda
        .put_function_event_invoke_config()
        .function_name("orders")
        .maximum_retry_attempts(0)
        .destination_config(
            DestinationConfig::builder()
                .on_success(OnSuccess::builder().destination(&ok_arn).build())
                .on_failure(OnFailure::builder().destination(&failed_arn).build())
                .build(),
        )
        .send()
        .await
        .unwrap();

    let queued = lambda
        .invoke()
        .function_name("orders")
        .invocation_type(InvocationType::Event)
        .payload(Blob::new(br#"{"id":1}"#.to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(queued.status_code(), 202);
    let record = body(&next_message(&sqs, &ok_url).await);
    assert_eq!(record["version"], "1.0");
    assert_eq!(record["requestContext"]["condition"], "Success");
    assert_eq!(record["requestContext"]["functionArn"], format!("{fn_arn}:$LATEST"));
    assert_eq!(record["requestContext"]["approximateInvokeCount"], 1);
    assert_eq!(record["requestPayload"], serde_json::json!({"id": 1}));
    assert_eq!(record["responseContext"], serde_json::json!({"statusCode": 200, "executedVersion": "$LATEST"}));
    assert_eq!(record["responsePayload"], serde_json::json!({"ok": 1}));

    // A failure goes to the on-failure destination and the dead-letter
    // queue, which gets the event itself.
    let failing = lambda
        .invoke()
        .function_name("orders")
        .invocation_type(InvocationType::Event)
        .payload(Blob::new(br#"{"id":2,"fail":true}"#.to_vec()))
        .send()
        .await
        .unwrap();
    let request_id = failing.request_id().map(str::to_string);
    let record = body(&next_message(&sqs, &failed_url).await);
    assert_eq!(record["requestContext"]["condition"], "RetriesExhausted");
    assert_eq!(record["responseContext"]["functionError"], "Unhandled");
    assert_eq!(record["responsePayload"]["errorType"], "ValueError");
    assert_eq!(record["requestPayload"], serde_json::json!({"id": 2, "fail": true}));
    let dead = next_message(&sqs, &dlq_url).await;
    assert_eq!(body(&dead), serde_json::json!({"id": 2, "fail": true}));
    let attrs = dead.message_attributes().unwrap();
    assert_eq!(attrs["ErrorMessage"].string_value(), Some("bad order 2"));
    assert_eq!(attrs["ErrorCode"].data_type(), "Number");
    assert_eq!(attrs["ErrorCode"].string_value(), Some("200"));
    if let Some(id) = request_id {
        assert_eq!(attrs["RequestID"].string_value(), Some(id.as_str()));
        assert_eq!(record["requestContext"]["requestId"], id);
    }

    // An event bus destination gets a "Lambda Function Invocation Result"
    // event from source "lambda".
    let (bus_url, bus_queue_arn) = queue(&sqs, "from-bus").await;
    let queue_policy = serde_json::json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage", "Resource": bus_queue_arn,
    }]});
    sqs.set_queue_attributes()
        .queue_url(&bus_url)
        .attributes(QueueAttributeName::Policy, queue_policy.to_string())
        .send()
        .await
        .unwrap();
    eb.put_rule().name("lambda-results").event_pattern(r#"{"source":["lambda"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("lambda-results")
        .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(&bus_queue_arn).build().unwrap())
        .send()
        .await
        .unwrap();
    let bus_arn = format!("arn:aws:events:us-east-1:{ACCOUNT}:event-bus/default");
    lambda
        .update_function_event_invoke_config()
        .function_name("orders")
        .destination_config(
            DestinationConfig::builder().on_success(OnSuccess::builder().destination(&bus_arn).build()).build(),
        )
        .send()
        .await
        .unwrap();
    lambda
        .invoke()
        .function_name("orders")
        .invocation_type(InvocationType::Event)
        .payload(Blob::new(br#"{"id":3}"#.to_vec()))
        .send()
        .await
        .unwrap();
    let event = body(&next_message(&sqs, &bus_url).await);
    assert_eq!(event["source"], "lambda");
    assert_eq!(event["detail-type"], "Lambda Function Invocation Result - Success");
    assert_eq!(event["detail"]["requestContext"]["condition"], "Success");
    assert_eq!(event["detail"]["responsePayload"], serde_json::json!({"ok": 3}));
    assert!(event["resources"].as_array().unwrap().iter().any(|r| r == &format!("{fn_arn}:$LATEST")));
    mws.stop().await;
}

const ALWAYS_FAILS: &str = r#"
def handler(event, context):
    raise RuntimeError("cannot process")
"#;

#[tokio::test]
async fn kinesis_mapping_failures_reach_the_on_failure_destination() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let k = aws_sdk_kinesis::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role_arn = role(&cfg, "stream-role", r#"["kinesis:*","sqs:SendMessage","logs:*"]"#).await;
    let (failed_url, failed_arn) = queue(&sqs, "stream-failures").await;
    k.create_stream().stream_name("events").shard_count(1).send().await.unwrap();
    for _ in 0..50 {
        let s = k.describe_stream_summary().stream_name("events").send().await.unwrap();
        if s.stream_description_summary().unwrap().stream_status() == &aws_sdk_kinesis::types::StreamStatus::Active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stream_arn = format!("arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/events");
    lambda
        .create_function()
        .function_name("consumer")
        .runtime(Runtime::Python312)
        .role(&role_arn)
        .handler("app.handler")
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", ALWAYS_FAILS)]))).build())
        .send()
        .await
        .unwrap();
    let mapping = lambda
        .create_event_source_mapping()
        .function_name("consumer")
        .event_source_arn(&stream_arn)
        .starting_position(EventSourcePosition::TrimHorizon)
        .maximum_retry_attempts(0)
        .destination_config(
            DestinationConfig::builder().on_failure(OnFailure::builder().destination(&failed_arn).build()).build(),
        )
        .send()
        .await
        .unwrap();
    let put = k
        .put_record()
        .stream_name("events")
        .partition_key("p")
        .data(aws_sdk_kinesis::primitives::Blob::new("poison"))
        .send()
        .await
        .unwrap();

    let record = body(&next_message(&sqs, &failed_url).await);
    assert_eq!(record["requestContext"]["condition"], "RetryAttemptsExhausted");
    assert_eq!(record["requestContext"]["approximateInvokeCount"], 1);
    assert_eq!(record["responseContext"]["functionError"], "Unhandled");
    let info = &record["KinesisBatchInfo"];
    assert_eq!(info["shardId"], "shardId-000000000000");
    assert_eq!(info["startSequenceNumber"], put.sequence_number());
    assert_eq!(info["endSequenceNumber"], put.sequence_number());
    assert_eq!(info["batchSize"], 1);
    assert_eq!(info["streamArn"], stream_arn);

    // One mapping per source and function.
    let dup = lambda
        .create_event_source_mapping()
        .function_name("consumer")
        .event_source_arn(&stream_arn)
        .starting_position(EventSourcePosition::Latest)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(dup.is_resource_conflict_exception(), "{dup:?}");
    let uuid = mapping.uuid().unwrap();
    assert_eq!(
        dup.meta().message(),
        Some(
            format!(
                "The event source arn (\" {stream_arn} \") and function (\" consumer \") provided mapping already exists. Please update or delete the existing mapping with UUID {uuid}"
            )
            .as_str()
        )
    );

    // Deleting the function leaves its mappings, as in AWS.
    lambda.delete_function().function_name("consumer").send().await.unwrap();
    let still = lambda.get_event_source_mapping().uuid(uuid).send().await.unwrap();
    assert_eq!(still.event_source_arn(), Some(stream_arn.as_str()));
    lambda.delete_event_source_mapping().uuid(uuid).send().await.unwrap();
    mws.stop().await;
}
