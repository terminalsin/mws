//! Lambda's function lifecycle and concurrency through the official Rust
//! SDK: `Pending` and `InProgress` conflicts, ABAC on function tags,
//! reserved concurrency, throttled asynchronous events, and event source
//! mappings that poll however they were created.

use std::time::Duration;

use aws_sdk_lambda::error::ProvideErrorMetadata;
use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{
    DestinationConfig, Environment, FunctionCode, InvocationType, LastUpdateStatus, OnFailure, OnSuccess, Runtime,
    State,
};
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const HANDLER: &str = r#"
import os

def handler(event, context):
    return {"greeting": os.environ.get("GREETING", "none")}
"#;

/// Forwards every SQS record's body to the `out` queue.
const FORWARDER: &str = r#"
import boto3

def handler(event, context):
    sqs = boto3.client("sqs")
    out = sqs.get_queue_url(QueueName="out")["QueueUrl"]
    for r in event["Records"]:
        sqs.send_message(QueueUrl=out, MessageBody=r["body"])
    return {}
"#;

fn zip(body: &str) -> Blob {
    Blob::new(crate::lambda::zip(&[("app.py", body)]))
}

async fn role(iam: &aws_sdk_iam::Client, name: &str) -> String {
    let role = iam.create_role().role_name(name).assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy()
        .role_name(name)
        .policy_name("sqs")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    role.role().unwrap().arn().to_string()
}

async fn create(lambda: &aws_sdk_lambda::Client, name: &str, role: &str, body: &str) {
    lambda
        .create_function()
        .function_name(name)
        .runtime(Runtime::Python312)
        .role(role)
        .handler("app.handler")
        .timeout(5)
        .code(FunctionCode::builder().zip_file(zip(body)).build())
        .environment(Environment::builder().variables("GREETING", "v1").build())
        .send()
        .await
        .unwrap();
}

async fn greeting(lambda: &aws_sdk_lambda::Client, name: &str) -> String {
    let out = lambda.invoke().function_name(name).send().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(out.payload().unwrap().as_ref()).unwrap();
    body["greeting"].as_str().unwrap().to_string()
}

async fn queue(sqs: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url.unwrap();
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

/// Bodies received from `url` within `within`, stopping at `want`.
async fn receive(sqs: &aws_sdk_sqs::Client, url: &str, want: usize, within: Duration) -> Vec<String> {
    let started = std::time::Instant::now();
    let mut got = Vec::new();
    while got.len() < want && started.elapsed() < within {
        let out = sqs.receive_message().queue_url(url).max_number_of_messages(10).send().await.unwrap();
        for m in out.messages() {
            got.push(m.body().unwrap().to_string());
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    got
}

#[tokio::test]
async fn pending_and_in_progress_functions_refuse_what_aws_refuses() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = role(&iam, "fn").await;
    let arn = "arn:aws:lambda:us-east-1:123456789012:function:states";

    create(&lambda, "states", &role, HANDLER).await;
    // A new function is Pending: GetFunction says so, and Invoke and updates
    // are refused.
    let got = lambda.get_function_configuration().function_name("states").send().await.unwrap();
    assert_eq!(got.state(), Some(&State::Pending));
    assert_eq!(got.state_reason_code().map(|c| c.as_str()), Some("Creating"));
    let e = lambda.invoke().function_name("states").send().await.unwrap_err().into_service_error();
    assert!(e.is_resource_conflict_exception(), "{e:?}");
    assert_eq!(
        e.message(),
        Some(
            "The operation cannot be performed at this time. The function is currently in the following state: Pending"
        )
    );
    let e = lambda
        .update_function_configuration()
        .function_name("states")
        .timeout(10)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(e.is_resource_conflict_exception(), "{e:?}");
    assert_eq!(
        e.message().map(str::to_string),
        Some(format!("The operation cannot be performed at this time. An update is in progress for resource: {arn}"))
    );

    mws_e2e::function_active(&lambda, "states").await;
    let got = lambda.get_function_configuration().function_name("states").send().await.unwrap();
    assert_eq!(got.state(), Some(&State::Active));
    assert_eq!(got.last_update_status(), Some(&LastUpdateStatus::Successful));
    assert_eq!(greeting(&lambda, "states").await, "v1");

    // An update stays InProgress for a moment: another update or a publish
    // is refused, while invocations still run the previous configuration.
    let updated = lambda
        .update_function_configuration()
        .function_name("states")
        .environment(Environment::builder().variables("GREETING", "v2").build())
        .send()
        .await
        .unwrap();
    assert_eq!(updated.last_update_status(), Some(&LastUpdateStatus::InProgress));
    let got = lambda.get_function_configuration().function_name("states").send().await.unwrap();
    assert_eq!(got.last_update_status(), Some(&LastUpdateStatus::InProgress));
    let e = lambda
        .update_function_code()
        .function_name("states")
        .zip_file(zip(HANDLER))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(e.is_resource_conflict_exception(), "{e:?}");
    assert_eq!(
        e.message().map(str::to_string),
        Some(format!("The operation cannot be performed at this time. An update is in progress for resource: {arn}"))
    );
    let e = lambda.publish_version().function_name("states").send().await.unwrap_err().into_service_error();
    assert!(e.is_resource_conflict_exception(), "{e:?}");
    assert_eq!(greeting(&lambda, "states").await, "v1");

    mws_e2e::function_updated(&lambda, "states").await;
    let got = lambda.get_function_configuration().function_name("states").send().await.unwrap();
    assert_eq!(got.last_update_status(), Some(&LastUpdateStatus::Successful));
    assert_eq!(greeting(&lambda, "states").await, "v2");
    lambda.update_function_code().function_name("states").zip_file(zip(HANDLER)).send().await.unwrap();
    mws_e2e::function_updated(&lambda, "states").await;
    assert_eq!(lambda.publish_version().function_name("states").send().await.unwrap().version(), Some("1"));
    mws.stop().await;
}

#[tokio::test]
async fn function_tags_are_resource_tag_condition_keys() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = role(&iam, "fn").await;
    for (name, team) in [("blue-fn", "blue"), ("red-fn", "red")] {
        lambda
            .create_function()
            .function_name(name)
            .runtime(Runtime::Python312)
            .role(&role)
            .handler("app.handler")
            .code(FunctionCode::builder().zip_file(zip(HANDLER)).build())
            .tags("team", team)
            .send()
            .await
            .unwrap();
        mws_e2e::function_active(&lambda, name).await;
    }

    // An Allow conditioned on the function's tag.
    let allow = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:InvokeFunction","lambda:GetFunction"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"blue"}}}]}"#;
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "blue-dev", Some(allow)).await;
    let blue = aws_sdk_lambda::Client::new(&user_cfg);
    let ok = blue.invoke().function_name("blue-fn").invocation_type(InvocationType::DryRun).send().await.unwrap();
    assert_eq!(ok.status_code(), 204);
    blue.get_function().function_name("blue-fn").send().await.unwrap();
    let e = blue.invoke().function_name("red-fn").send().await.unwrap_err().into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"));
    let e = blue.get_function().function_name("red-fn").send().await.unwrap_err().into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"));

    // A Deny conditioned on the function's tag beats a broad Allow.
    let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":"*"},{"Effect":"Deny","Action":["lambda:UpdateFunctionConfiguration","lambda:InvokeFunction"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"red"}}}]}"#;
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "not-red", Some(deny)).await;
    let not_red = aws_sdk_lambda::Client::new(&user_cfg);
    let e = not_red.invoke().function_name("red-fn").send().await.unwrap_err().into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"));
    let e = not_red
        .update_function_configuration()
        .function_name("red-fn")
        .timeout(9)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"));
    not_red.invoke().function_name("blue-fn").invocation_type(InvocationType::DryRun).send().await.unwrap();
    not_red.update_function_configuration().function_name("blue-fn").timeout(9).send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn reserved_concurrency_zero_throttles_a_warm_function() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = role(&iam, "fn").await;
    create(&lambda, "warm", &role, HANDLER).await;
    mws_e2e::function_active(&lambda, "warm").await;
    // Warm an execution environment.
    assert_eq!(greeting(&lambda, "warm").await, "v1");
    assert_eq!(greeting(&lambda, "warm").await, "v1");

    lambda.put_function_concurrency().function_name("warm").reserved_concurrent_executions(0).send().await.unwrap();
    let e = lambda.invoke().function_name("warm").send().await.unwrap_err().into_service_error();
    assert!(e.is_too_many_requests_exception(), "{e:?}");
    let aws_sdk_lambda::operation::invoke::InvokeError::TooManyRequestsException(t) = &e else { unreachable!() };
    assert_eq!(t.reason().map(|r| r.as_str()), Some("ReservedFunctionConcurrentInvocationLimitExceeded"));

    lambda.delete_function_concurrency().function_name("warm").send().await.unwrap();
    assert_eq!(greeting(&lambda, "warm").await, "v1");
    mws.stop().await;
}

#[tokio::test]
async fn throttled_events_wait_instead_of_failing() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = role(&iam, "fn").await;
    let (ok_url, ok_arn) = queue(&sqs, "succeeded").await;
    let (failed_url, failed_arn) = queue(&sqs, "failed").await;
    create(&lambda, "throttled", &role, HANDLER).await;
    mws_e2e::function_active(&lambda, "throttled").await;
    lambda
        .put_function_event_invoke_config()
        .function_name("throttled")
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
    lambda
        .put_function_concurrency()
        .function_name("throttled")
        .reserved_concurrent_executions(0)
        .send()
        .await
        .unwrap();

    let queued =
        lambda.invoke().function_name("throttled").invocation_type(InvocationType::Event).send().await.unwrap();
    assert_eq!(queued.status_code(), 202);
    // Throttles do not use up MaximumRetryAttempts (0 here): the event is
    // kept, not sent to the on-failure destination.
    assert!(receive(&sqs, &failed_url, 1, Duration::from_secs(4)).await.is_empty());

    lambda.delete_function_concurrency().function_name("throttled").send().await.unwrap();
    let records = receive(&sqs, &ok_url, 1, Duration::from_secs(30)).await;
    assert_eq!(records.len(), 1, "the throttled event runs once concurrency allows");
    let record: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
    assert_eq!(record["requestContext"]["condition"], "Success");
    assert_eq!(record["responsePayload"], serde_json::json!({"greeting": "v1"}));
    assert!(receive(&sqs, &failed_url, 1, Duration::from_millis(500)).await.is_empty());
    mws.stop().await;
}

const STACK: &str = r#"
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: sqs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: sqs:*
                Resource: "*"
  Jobs:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: jobs
  Out:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: out
  Worker:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt Role.Arn
      Timeout: 10
      Code:
        ZipFile: |
          import boto3
          def handler(event, context):
              sqs = boto3.client("sqs")
              out = sqs.get_queue_url(QueueName="out")["QueueUrl"]
              for r in event["Records"]:
                  sqs.send_message(QueueUrl=out, MessageBody=r["body"])
              return {}
  Trigger:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref Worker
      EventSourceArn: !GetAtt Jobs.Arn
"#;

#[tokio::test]
async fn mappings_from_cloudformation_poll_without_lambda_requests() {
    use aws_sdk_cloudformation::types::{Capability, StackStatus};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let cfn = aws_sdk_cloudformation::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    cfn.create_stack()
        .stack_name("esm")
        .template_body(STACK)
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    let mut status = None;
    for _ in 0..600 {
        let s = cfn.describe_stacks().stack_name("esm").send().await.unwrap().stacks()[0].clone();
        if !s.stack_status().unwrap().as_str().ends_with("_IN_PROGRESS") {
            status = Some((s.stack_status().cloned(), s.stack_status_reason().map(str::to_string)));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (status, reason) = status.expect("stack settles");
    assert_eq!(status, Some(StackStatus::CreateComplete), "{reason:?}");

    // Nothing has called the Lambda API directly: the mapping polls anyway.
    let jobs = sqs.get_queue_url().queue_name("jobs").send().await.unwrap().queue_url.unwrap();
    let out = sqs.get_queue_url().queue_name("out").send().await.unwrap().queue_url.unwrap();
    sqs.send_message().queue_url(&jobs).message_body("from-cfn").send().await.unwrap();
    assert_eq!(receive(&sqs, &out, 1, Duration::from_secs(30)).await, vec!["from-cfn".to_string()]);
    mws.stop().await;
}

#[tokio::test]
async fn restored_mappings_poll_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("mws-e2e-{}-lambda-restart", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config = mws::Config { db: Some(dir.join("state.db")), ..Default::default() };

    let mws = Mws::start_with(config.clone()).await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = role(&iam, "poller").await;
    let (_, jobs_arn) = queue(&sqs, "jobs").await;
    queue(&sqs, "out").await;
    create(&lambda, "forward", &role, FORWARDER).await;
    mws_e2e::function_active(&lambda, "forward").await;
    lambda.create_event_source_mapping().function_name("forward").event_source_arn(&jobs_arn).send().await.unwrap();
    mws.stop().await;

    // After the restart only SQS is called: the restored mapping polls.
    let mws = Mws::start_with(config).await;
    let cfg = mws.root_sdk_config().await;
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let jobs = sqs.get_queue_url().queue_name("jobs").send().await.unwrap().queue_url.unwrap();
    let out = sqs.get_queue_url().queue_name("out").send().await.unwrap().queue_url.unwrap();
    sqs.send_message().queue_url(&jobs).message_body("after-restart").send().await.unwrap();
    assert_eq!(receive(&sqs, &out, 1, Duration::from_secs(30)).await, vec!["after-restart".to_string()]);
    mws.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}
