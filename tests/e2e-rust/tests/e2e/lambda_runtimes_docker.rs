//! Lambda functions of managed runtimes in AWS's own base images
//! (`public.ecr.aws/lambda/<lang>:<version>`), through the official Rust
//! SDK. Skipped when no Docker daemon answers.

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, Runtime};
use mws_e2e::Mws;

use crate::ecr::docker_available;
use crate::lambda::zip;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const NODE_HANDLER: &str = r#"
import { existsSync, readFileSync } from "node:fs";

export const handler = async (event) => {
  if (event.fail) throw new TypeError("asked to fail");
  const health = await fetch(`${process.env.AWS_ENDPOINT_URL}/_mws/health`);
  return {
    node: process.version,
    taskRoot: process.env.LAMBDA_TASK_ROOT,
    cwd: process.cwd(),
    handler: process.env._HANDLER,
    runtimeClient: existsSync("/var/runtime/bootstrap"),
    layer: readFileSync("/opt/data/greeting.txt", "utf8").trim(),
    health: health.status,
    event,
  };
};
"#;

const PYTHON_HANDLER: &str = r#"
import os, sys, urllib.request

def handler(event, context):
    with urllib.request.urlopen(os.environ["AWS_ENDPOINT_URL"] + "/_mws/health") as r:
        health = r.status
    return {
        "python": "%d.%d" % sys.version_info[:2],
        "taskRoot": os.environ["LAMBDA_TASK_ROOT"],
        "cwd": os.getcwd(),
        "fn": context.function_name,
        "runtimeClient": os.path.exists("/var/runtime/bootstrap"),
        "health": health,
        "event": event,
    }
"#;

/// The images of running containers of `function_arn`.
fn container_images(function_arn: &str) -> Vec<String> {
    let out = std::process::Command::new("docker")
        .args(["ps", "--filter", &format!("label=mws.lambda.function={function_arn}"), "--format", "{{.Image}}"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect()
}

async fn invoke(lambda: &aws_sdk_lambda::Client, name: &str, payload: &str) -> (Option<String>, serde_json::Value) {
    let out = lambda.invoke().function_name(name).payload(Blob::new(payload)).send().await.unwrap();
    let body = serde_json::from_slice(out.payload().unwrap().as_ref()).unwrap();
    (out.function_error().map(str::to_string), body)
}

#[tokio::test]
async fn managed_runtimes_run_in_aws_base_images_docker() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { lambda_runtime_executor: mws::LambdaRuntimeExecutor::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = iam.create_role().role_name("base-image-fn").assume_role_policy_document(TRUST).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();

    // Node.js 22, with a layer (mounted at /opt).
    let layer = lambda
        .publish_layer_version()
        .layer_name("greeting")
        .content(
            aws_sdk_lambda::types::LayerVersionContentInput::builder()
                .zip_file(Blob::new(zip(&[("data/greeting.txt", "hello from a layer\n")])))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let node = lambda
        .create_function()
        .function_name("node22")
        .runtime(Runtime::Nodejs22x)
        .handler("index.handler")
        .role(&role_arn)
        .layers(layer.layer_version_arn().unwrap())
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("index.mjs", NODE_HANDLER)]))).build())
        .send()
        .await
        .unwrap();
    let (error, body) = invoke(&lambda, "node22", r#"{"n":1}"#).await;
    assert_eq!(error, None, "{body}");
    assert!(body["node"].as_str().unwrap().starts_with("v22."), "{body}");
    assert_eq!(body["taskRoot"], "/var/task");
    assert_eq!(body["cwd"], "/var/task");
    assert_eq!(body["handler"], "index.handler");
    assert_eq!(body["runtimeClient"], true);
    assert_eq!(body["layer"], "hello from a layer");
    assert_eq!(body["health"], 200);
    assert_eq!(body["event"]["n"], 1);
    // The environment is a warm container of the base image.
    assert_eq!(container_images(node.function_arn().unwrap()), ["public.ecr.aws/lambda/nodejs:22"]);

    // Errors come back in the runtime's own shape.
    let (error, body) = invoke(&lambda, "node22", r#"{"fail":true}"#).await;
    assert_eq!(error.as_deref(), Some("Unhandled"));
    assert_eq!(body["errorType"], "TypeError", "{body}");
    assert_eq!(body["errorMessage"], "asked to fail");

    // Python 3.13.
    lambda
        .create_function()
        .function_name("py313")
        .runtime(Runtime::Python313)
        .handler("app.handler")
        .role(&role_arn)
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", PYTHON_HANDLER)]))).build())
        .send()
        .await
        .unwrap();
    let (error, body) = invoke(&lambda, "py313", r#"{"n":2}"#).await;
    assert_eq!(error, None, "{body}");
    assert_eq!(body["python"], "3.13");
    assert_eq!(body["taskRoot"], "/var/task");
    assert_eq!(body["cwd"], "/var/task");
    assert_eq!(body["fn"], "py313");
    assert_eq!(body["runtimeClient"], true);
    assert_eq!(body["health"], 200);

    // Deleting the function stops its containers.
    lambda.delete_function().function_name("node22").send().await.unwrap();
    for _ in 0..50 {
        if container_images(node.function_arn().unwrap()).is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(container_images(node.function_arn().unwrap()).is_empty());
    mws.stop().await;
}
