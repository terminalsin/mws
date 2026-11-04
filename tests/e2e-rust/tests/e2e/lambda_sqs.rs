//! Lambda event source mappings polling SQS, through the official Rust SDK:
//! the checks AWS makes when a mapping is created, batches delivered as
//! `aws:sqs` records, partial batch responses, and failed messages going to
//! the queue's dead-letter queue.

use std::time::Duration;

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, FunctionResponseType, Runtime};
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Forwards every record to the `out` queue and reports records whose body
/// is `fail` as failed.
const HANDLER: &str = r#"
import json, os, boto3

def handler(event, context):
    sqs = boto3.client("sqs")
    out = sqs.get_queue_url(QueueName="out")["QueueUrl"]
    failures = []
    for r in event["Records"]:
        if r["body"] == "fail":
            failures.append({"itemIdentifier": r["messageId"]})
            continue
        sqs.send_message(QueueUrl=out, MessageBody=json.dumps({
            "body": r["body"],
            "eventSource": r["eventSource"],
            "eventSourceARN": r["eventSourceARN"],
            "awsRegion": r["awsRegion"],
            "receiveCount": r["attributes"]["ApproximateReceiveCount"],
            "attr": r["messageAttributes"].get("color", {}).get("stringValue"),
            "md5": r["md5OfBody"],
        }))
    return {"batchItemFailures": failures}
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

async fn drain(sqs: &aws_sdk_sqs::Client, url: &str, want: usize) -> Vec<String> {
    let mut got = Vec::new();
    for _ in 0..60 {
        let out = sqs.receive_message().queue_url(url).max_number_of_messages(10).send().await.unwrap();
        for m in out.messages() {
            got.push(m.body().unwrap().to_string());
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
        if got.len() >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    got
}

#[tokio::test]
async fn sqs_event_source_mapping_delivers_batches() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);

    let role = iam.create_role().role_name("poller").assume_role_policy_document(TRUST).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    let (_, dlq_arn) = queue(&sqs, "jobs-dlq", &[]).await;
    let redrive = format!(r#"{{"deadLetterTargetArn":"{dlq_arn}","maxReceiveCount":"1"}}"#);
    let (jobs_url, jobs_arn) = queue(
        &sqs,
        "jobs",
        &[(QueueAttributeName::VisibilityTimeout, "3"), (QueueAttributeName::RedrivePolicy, redrive.as_str())],
    )
    .await;
    let (_, short_arn) = queue(&sqs, "short", &[(QueueAttributeName::VisibilityTimeout, "2")]).await;
    let (out_url, _) = queue(&sqs, "out", &[]).await;

    lambda
        .create_function()
        .function_name("worker")
        .runtime(Runtime::Python312)
        .role(&role_arn)
        .handler("app.handler")
        .timeout(3)
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", HANDLER)]))).build())
        .send()
        .await
        .unwrap();

    // The role may not read the queue yet.
    let e = lambda
        .create_event_source_mapping()
        .function_name("worker")
        .event_source_arn(&jobs_arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(e.is_invalid_parameter_value_exception());
    assert_eq!(
        e.to_string(),
        "InvalidParameterValueException: The provided execution role does not have permissions to call ReceiveMessage on SQS"
    );

    iam.put_role_policy()
        .role_name("poller")
        .policy_name("sqs")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();

    let e = lambda
        .create_event_source_mapping()
        .function_name("worker")
        .event_source_arn(&short_arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(
        e.to_string(),
        "InvalidParameterValueException: Queue visibility timeout: 2 seconds is less than Function timeout: 3 seconds"
    );
    let e = lambda
        .create_event_source_mapping()
        .function_name("worker")
        .event_source_arn(&jobs_arn)
        .batch_size(50)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(e.is_invalid_parameter_value_exception());

    let mapping = lambda
        .create_event_source_mapping()
        .function_name("worker")
        .event_source_arn(&jobs_arn)
        .function_response_types(FunctionResponseType::ReportBatchItemFailures)
        .send()
        .await
        .unwrap();
    assert_eq!(mapping.state(), Some("Creating"));
    assert_eq!(mapping.batch_size(), Some(10));

    for body in ["one", "two", "fail"] {
        sqs.send_message()
            .queue_url(&jobs_url)
            .message_body(body)
            .message_attributes(
                "color",
                aws_sdk_sqs::types::MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value("blue")
                    .build()
                    .unwrap(),
            )
            .send()
            .await
            .unwrap();
    }

    let mut seen: Vec<serde_json::Value> =
        drain(&sqs, &out_url, 2).await.iter().map(|b| serde_json::from_str(b).unwrap()).collect();
    seen.sort_by_key(|v| v["body"].as_str().unwrap().to_string());
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0]["body"], "one");
    assert_eq!(seen[1]["body"], "two");
    assert_eq!(seen[0]["eventSource"], "aws:sqs");
    assert_eq!(seen[0]["eventSourceARN"], jobs_arn.as_str());
    assert_eq!(seen[0]["awsRegion"], "us-east-1");
    assert_eq!(seen[0]["receiveCount"], "1");
    assert_eq!(seen[0]["attr"], "blue");
    assert_eq!(seen[0]["md5"], "f97c5d29941bfb1b2fdab0874906ab82");

    // The failed record is retried once its visibility timeout ends, then
    // the redrive policy moves it to the dead-letter queue.
    let dlq_url = sqs.get_queue_url().queue_name("jobs-dlq").send().await.unwrap().queue_url.unwrap();
    let dead = drain(&sqs, &dlq_url, 1).await;
    assert_eq!(dead, vec!["fail".to_string()]);
    let left = sqs
        .get_queue_attributes()
        .queue_url(&jobs_url)
        .attribute_names(QueueAttributeName::All)
        .send()
        .await
        .unwrap()
        .attributes
        .unwrap();
    assert_eq!(left[&QueueAttributeName::ApproximateNumberOfMessages], "0");
    assert_eq!(left[&QueueAttributeName::ApproximateNumberOfMessagesNotVisible], "0");

    // A disabled mapping stops polling.
    lambda.update_event_source_mapping().uuid(mapping.uuid().unwrap()).enabled(false).send().await.unwrap();
    sqs.send_message().queue_url(&jobs_url).message_body("later").send().await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let waiting = sqs
        .get_queue_attributes()
        .queue_url(&jobs_url)
        .attribute_names(QueueAttributeName::ApproximateNumberOfMessages)
        .send()
        .await
        .unwrap()
        .attributes
        .unwrap();
    assert_eq!(waiting[&QueueAttributeName::ApproximateNumberOfMessages], "1");
    mws.stop().await;
}

#[tokio::test]
async fn filter_criteria_drop_records_that_do_not_match() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = iam.create_role().role_name("poller").assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy()
        .role_name("poller")
        .policy_name("sqs")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    let (jobs_url, jobs_arn) = queue(&sqs, "jobs", &[]).await;
    let (out_url, _) = queue(&sqs, "out", &[]).await;
    lambda
        .create_function()
        .function_name("worker")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", HANDLER)]))).build())
        .send()
        .await
        .unwrap();

    let criteria = |pattern: &str| {
        aws_sdk_lambda::types::FilterCriteria::builder()
            .filters(aws_sdk_lambda::types::Filter::builder().pattern(pattern).build())
            .build()
    };
    let e = lambda
        .create_event_source_mapping()
        .function_name("worker")
        .event_source_arn(&jobs_arn)
        .filter_criteria(criteria("{not json"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.to_string(), "InvalidParameterValueException: Invalid filter pattern definition.");

    lambda
        .create_event_source_mapping()
        .function_name("worker")
        .event_source_arn(&jobs_arn)
        .filter_criteria(criteria(r#"{"body":{"kind":["order"]}}"#))
        .send()
        .await
        .unwrap();
    for body in [r#"{"kind":"refund"}"#, "plain text", r#"{"kind":"order","id":7}"#] {
        sqs.send_message().queue_url(&jobs_url).message_body(body).send().await.unwrap();
    }
    let seen = drain(&sqs, &out_url, 1).await;
    assert_eq!(seen.len(), 1, "{seen:?}");
    let v: serde_json::Value = serde_json::from_str(&seen[0]).unwrap();
    assert_eq!(v["body"], r#"{"kind":"order","id":7}"#);
    // Filtered-out messages are deleted, not left for later.
    for _ in 0..20 {
        let attrs = sqs
            .get_queue_attributes()
            .queue_url(&jobs_url)
            .attribute_names(QueueAttributeName::All)
            .send()
            .await
            .unwrap()
            .attributes
            .unwrap();
        if attrs[&QueueAttributeName::ApproximateNumberOfMessages] == "0"
            && attrs[&QueueAttributeName::ApproximateNumberOfMessagesNotVisible] == "0"
        {
            mws.stop().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("filtered messages were not deleted");
}
