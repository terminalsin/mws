//! Lambda through the official Rust SDK: functions really run.

use std::io::Write;

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, InvocationType, LogType, Runtime};
use base64::Engine;
use mws_e2e::Mws;

pub fn zip(files: &[(&str, &str)]) -> Vec<u8> {
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

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const HANDLER: &str = r#"
import json, os

def handler(event, context):
    print("event", json.dumps(event))
    if event.get("fail"):
        raise RuntimeError("asked to fail")
    return {"echo": event, "fn": context.function_name, "region": os.environ["AWS_REGION"]}
"#;

#[tokio::test]
async fn create_and_invoke_a_python_function() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role = iam.create_role().role_name("fn-role").assume_role_policy_document(TRUST).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    let lambda = aws_sdk_lambda::Client::new(&cfg);

    let created = lambda
        .create_function()
        .function_name("echo")
        .runtime(Runtime::Python312)
        .role(&role_arn)
        .handler("app.handler")
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", HANDLER)]))).build())
        .send()
        .await
        .unwrap();
    assert_eq!(created.function_arn(), Some("arn:aws:lambda:us-east-1:123456789012:function:echo"));
    assert_eq!(created.handler(), Some("app.handler"));

    let out = lambda
        .invoke()
        .function_name("echo")
        .payload(Blob::new(br#"{"n":7}"#.to_vec()))
        .log_type(LogType::Tail)
        .send()
        .await
        .unwrap();
    assert_eq!(out.status_code(), 200);
    assert_eq!(out.function_error(), None);
    assert_eq!(out.executed_version(), Some("$LATEST"));
    let body: serde_json::Value = serde_json::from_slice(out.payload().unwrap().as_ref()).unwrap();
    assert_eq!(body, serde_json::json!({"echo": {"n": 7}, "fn": "echo", "region": "us-east-1"}));
    let logs = base64::engine::general_purpose::STANDARD.decode(out.log_result().unwrap()).unwrap();
    let logs = String::from_utf8(logs).unwrap();
    assert!(logs.contains(r#"event {"n": 7}"#), "{logs}");

    let failed =
        lambda.invoke().function_name("echo").payload(Blob::new(br#"{"fail":true}"#.to_vec())).send().await.unwrap();
    assert_eq!(failed.function_error(), Some("Unhandled"));
    let err: serde_json::Value = serde_json::from_slice(failed.payload().unwrap().as_ref()).unwrap();
    assert_eq!(err["errorType"], "RuntimeError");
    assert_eq!(err["errorMessage"], "asked to fail");

    let queued = lambda.invoke().function_name("echo").invocation_type(InvocationType::Event).send().await.unwrap();
    assert_eq!(queued.status_code(), 202);

    let missing = lambda.invoke().function_name("nope").send().await.unwrap_err();
    assert!(missing.as_service_error().unwrap().is_resource_not_found_exception());

    let v = lambda.publish_version().function_name("echo").send().await.unwrap();
    assert_eq!(v.version(), Some("1"));
    lambda.create_alias().function_name("echo").name("prod").function_version("1").send().await.unwrap();
    let via_alias = lambda.invoke().function_name("echo:prod").send().await.unwrap();
    assert_eq!(via_alias.executed_version(), Some("1"));

    let listed = lambda.list_functions().send().await.unwrap();
    assert_eq!(listed.functions().iter().filter_map(|f| f.function_name()).collect::<Vec<_>>(), vec!["echo"]);
    lambda.delete_function().function_name("echo").send().await.unwrap();
    let gone = lambda.get_function().function_name("echo").send().await.unwrap_err();
    assert!(gone.as_service_error().unwrap().is_resource_not_found_exception());
    mws.stop().await;
}

#[tokio::test]
async fn invoke_needs_permission() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role = iam.create_role().role_name("r").assume_role_policy_document(TRUST).send().await.unwrap();
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    lambda
        .create_function()
        .function_name("private")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", HANDLER)]))).build())
        .send()
        .await
        .unwrap();
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "dev", None).await;
    let as_user = aws_sdk_lambda::Client::new(&user_cfg);
    let denied = as_user.invoke().function_name("private").send().await.unwrap_err();
    let denied = denied.into_service_error();
    assert_eq!(denied.meta().code(), Some("AccessDeniedException"));

    lambda
        .add_permission()
        .function_name("private")
        .statement_id("dev")
        .action("lambda:InvokeFunction")
        .principal("arn:aws:iam::123456789012:user/dev")
        .send()
        .await
        .unwrap();
    let ok = as_user.invoke().function_name("private").invocation_type(InvocationType::DryRun).send().await.unwrap();
    assert_eq!(ok.status_code(), 204);
    mws.stop().await;
}
