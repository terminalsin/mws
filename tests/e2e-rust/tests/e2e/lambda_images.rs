//! Lambda container image functions through the official Rust SDK: images
//! resolve against ECR when code is set, and run in Docker.

use aws_sdk_lambda::error::ProvideErrorMetadata;
use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{Architecture, FunctionCode, ImageConfig, LogType, PackageType};
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};

use crate::ecr::{digest, docker, docker_available, push, run_docker};

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

async fn role(mws: &Mws, name: &str) -> String {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let role = iam.create_role().role_name(name).assume_role_policy_document(TRUST).send().await.unwrap();
    role.role().unwrap().arn().to_string()
}

fn image_code(uri: &str) -> FunctionCode {
    FunctionCode::builder().image_uri(uri).build()
}

fn message<E: ProvideErrorMetadata>(e: &E) -> (String, String) {
    (e.code().unwrap_or_default().to_string(), e.message().unwrap_or_default().to_string())
}

#[tokio::test]
async fn image_uris_resolve_against_ecr() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ecr = aws_sdk_ecr::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role_arn = role(&mws, "image-role").await;

    let repo = ecr.create_repository().repository_name("fns/app").send().await.unwrap();
    let repo_uri = repo.repository().unwrap().repository_uri().unwrap().to_string();
    assert_eq!(repo_uri, "123456789012.dkr.ecr.us-east-1.amazonaws.com/fns/app");
    let d1 = push(&ecr, "fns/app", "v1", "one").await;
    let d2 = push(&ecr, "fns/app", "v2", "two").await;

    // Images must exist, and URIs must name an ECR repository.
    for (uri, wording) in [
        (format!("{repo_uri}:nope"), "does not exist"),
        ("123456789012.dkr.ecr.us-east-1.amazonaws.com/missing:v1".to_string(), "does not exist"),
        ("docker.io/library/python:3.12".to_string(), "is not valid"),
    ] {
        let err = lambda
            .create_function()
            .function_name("img")
            .package_type(PackageType::Image)
            .role(&role_arn)
            .code(image_code(&uri))
            .send()
            .await
            .unwrap_err();
        let (code, msg) = message(&err);
        assert_eq!(code, "InvalidParameterValueException", "{uri}");
        assert_eq!(msg, format!("Source image {uri} {wording}. Provide a valid source image."));
    }

    let created = lambda
        .create_function()
        .function_name("img")
        .package_type(PackageType::Image)
        .role(&role_arn)
        .code(image_code(&format!("{repo_uri}:v1")))
        .image_config(ImageConfig::builder().command("app.handler").working_directory("/srv").build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, "img").await;
    assert_eq!(created.package_type(), Some(&PackageType::Image));
    assert_eq!(created.code_size(), 0);
    assert_eq!(created.code_sha256(), Some(d1.trim_start_matches("sha256:")));
    let got = lambda.get_function().function_name("img").send().await.unwrap();
    let code = got.code().unwrap();
    assert_eq!(code.repository_type(), Some("ECR"));
    assert_eq!(code.image_uri(), Some(format!("{repo_uri}:v1").as_str()));
    assert_eq!(code.resolved_image_uri(), Some(format!("{repo_uri}@{d1}").as_str()));
    let image_config = got.configuration().unwrap().image_config_response().unwrap().image_config().unwrap();
    assert_eq!(image_config.command(), ["app.handler"]);
    assert_eq!(image_config.working_directory(), Some("/srv"));

    // Lambda's pull is recorded on the image.
    let described = ecr
        .describe_images()
        .repository_name("fns/app")
        .image_ids(aws_sdk_ecr::types::ImageIdentifier::builder().image_tag("v1").build())
        .send()
        .await
        .unwrap();
    assert!(described.image_details()[0].last_recorded_pull_time().is_some());

    // New code resolves again; digests work as references too.
    let updated =
        lambda.update_function_code().function_name("img").image_uri(format!("{repo_uri}@{d2}")).send().await.unwrap();
    mws_e2e::function_updated(&lambda, "img").await;
    assert_eq!(updated.code_sha256(), Some(d2.trim_start_matches("sha256:")));
    let got = lambda.get_function().function_name("img").send().await.unwrap();
    assert_eq!(got.code().unwrap().resolved_image_uri(), Some(format!("{repo_uri}@{d2}").as_str()));
    let err = lambda
        .update_function_code()
        .function_name("img")
        .image_uri(format!("{repo_uri}:gone"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err).0, "InvalidParameterValueException");

    // An index picks the manifest for the function's architecture.
    let manifest = |d: &str| {
        let m = ecr
            .batch_get_image()
            .repository_name("fns/app")
            .image_ids(aws_sdk_ecr::types::ImageIdentifier::builder().image_digest(d).build());
        async move { m.send().await.unwrap().images()[0].image_manifest().unwrap().to_string() }
    };
    let m1 = manifest(&d1).await;
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [{
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": d1, "size": m1.len(),
            "platform": {"architecture": "amd64", "os": "linux"},
        }],
    })
    .to_string();
    let put =
        ecr.put_image().repository_name("fns/app").image_tag("multi").image_manifest(&index).send().await.unwrap();
    let index_digest = put.image().unwrap().image_id().unwrap().image_digest().unwrap().to_string();
    assert_eq!(index_digest, digest(index.as_bytes()));
    let multi = lambda
        .create_function()
        .function_name("multi")
        .package_type(PackageType::Image)
        .role(&role_arn)
        .code(image_code(&format!("{repo_uri}:multi")))
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, "multi").await;
    assert_eq!(multi.code_sha256(), Some(index_digest.trim_start_matches("sha256:")));
    let err = lambda
        .create_function()
        .function_name("multi-arm")
        .package_type(PackageType::Image)
        .architectures(Architecture::Arm64)
        .role(&role_arn)
        .code(image_code(&format!("{repo_uri}:multi")))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(&err),
        (
            "InvalidParameterValueException".to_string(),
            format!(
                "The image manifest, config or layer media type for the source image {repo_uri}:multi is not supported."
            )
        )
    );

    // Setting code is a pull by the caller: without ECR permissions there
    // is no function.
    let policy = serde_json::json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["lambda:*", "iam:PassRole"], "Resource": "*"},
    ]})
    .to_string();
    let (_, user_cfg) = user_with_policy(&mws, "deployer", Some(&policy)).await;
    let as_user = aws_sdk_lambda::Client::new(&user_cfg);
    let err = as_user
        .create_function()
        .function_name("denied")
        .package_type(PackageType::Image)
        .role(&role_arn)
        .code(image_code(&format!("{repo_uri}:v1")))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(&err),
        (
            "AccessDeniedException".to_string(),
            "Lambda does not have permission to access the ECR image. Check the ECR permissions.".to_string()
        )
    );
    // A repository policy may grant the pull instead.
    let repo_policy = serde_json::json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:user/deployer"},
        "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
    }]})
    .to_string();
    ecr.set_repository_policy().repository_name("fns/app").policy_text(repo_policy).send().await.unwrap();
    as_user
        .create_function()
        .function_name("allowed")
        .package_type(PackageType::Image)
        .role(&role_arn)
        .code(image_code(&format!("{repo_uri}:v1")))
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&as_user, "allowed").await;

    // Zip functions take no image, and image functions need one.
    let err = lambda
        .create_function()
        .function_name("no-uri")
        .package_type(PackageType::Image)
        .role(&role_arn)
        .code(FunctionCode::builder().build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err).1, "Please provide ImageUri when creating functions with PackageType Image.");
}

/// A Lambda custom runtime with nothing but std, compiled statically so the
/// image can be `FROM scratch` (no base image to pull). It reports how it
/// was started, and fails when the event asks it to.
const RUNTIME: &str = r##"
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

fn call(api: &str, method: &str, path: &str, body: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
    let mut s = TcpStream::connect(api).expect("runtime API");
    write!(s, "{method} {path} HTTP/1.1\r\nHost: {api}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    s.write_all(body).unwrap();
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let mut headers = Vec::new();
    loop {
        line.clear();
        r.read_line(&mut line).unwrap();
        let l = line.trim_end();
        if l.is_empty() { break; }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let mut body = Vec::new();
    r.read_to_end(&mut body).unwrap();
    (headers, body)
}

fn quote(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn var(k: &str) -> String {
    std::env::var(k).map(|v| quote(&v)).unwrap_or_else(|_| "null".into())
}

fn main() {
    let api = std::env::var("AWS_LAMBDA_RUNTIME_API").expect("AWS_LAMBDA_RUNTIME_API");
    let args: Vec<String> = std::env::args().map(|a| quote(&a)).collect();
    loop {
        let (headers, event) = call(&api, "GET", "/2018-06-01/runtime/invocation/next", b"");
        let id = headers.iter().find(|(k, _)| k == "lambda-runtime-aws-request-id").map(|(_, v)| v.clone()).unwrap();
        let event = String::from_utf8_lossy(&event).to_string();
        println!("handling {id}");
        if event.contains("\"fail\"") {
            let body = br#"{"errorType":"Custom","errorMessage":"failed on purpose"}"#;
            call(&api, "POST", &format!("/2018-06-01/runtime/invocation/{id}/error"), body);
            continue;
        }
        let cwd = std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default();
        let tmp = std::fs::write("/tmp/probe", b"x").is_ok();
        let root = std::fs::write("/probe", b"x").is_ok();
        let body = format!(
            "{{\"args\":[{}],\"cwd\":{},\"event\":{},\"function\":{},\"task_root\":{},\"greeting\":{},\"image_version\":{},\"handler\":{},\"has_credentials\":{},\"tmp_writable\":{tmp},\"root_writable\":{root}}}",
            args.join(","),
            quote(&cwd),
            event,
            var("AWS_LAMBDA_FUNCTION_NAME"),
            var("LAMBDA_TASK_ROOT"),
            var("GREETING"),
            var("IMAGE_VERSION"),
            var("_HANDLER"),
            std::env::var("AWS_ACCESS_KEY_ID").is_ok(),
        );
        call(&api, "POST", &format!("/2018-06-01/runtime/invocation/{id}/response"), body.as_bytes());
    }
}
"##;

/// Build the runtime and an image `tag` around it; `false` when this
/// machine cannot compile it statically.
fn build_runtime_image(host: &str, tag: &str, version: &str) -> bool {
    let dir = std::env::temp_dir().join(format!("mws-lambda-image-{}-{version}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bootstrap.rs"), RUNTIME).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let built = std::process::Command::new(rustc)
        .args(["--edition", "2021", "-O", "-C", "target-feature=+crt-static", "-C", "strip=symbols", "-o"])
        .arg(dir.join("bootstrap"))
        .arg(dir.join("bootstrap.rs"))
        .output();
    match built {
        Ok(o) if o.status.success() => {}
        other => {
            eprintln!("skipping: cannot build a static runtime: {other:?}");
            return false;
        }
    }
    std::fs::write(
        dir.join("Dockerfile"),
        format!(
            "FROM scratch\nCOPY bootstrap /var/runtime/bootstrap\nENV GREETING=hello IMAGE_VERSION={version}\n\
             WORKDIR /var/task\nENTRYPOINT [\"/var/runtime/bootstrap\"]\nCMD [\"app.handler\"]\n"
        ),
    )
    .unwrap();
    let out = docker(host, &["build", "-q", "-t", tag, dir.to_str().unwrap()], None);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "docker build: {}", String::from_utf8_lossy(&out.stderr));
    true
}

async fn invoke(
    lambda: &aws_sdk_lambda::Client,
    name: &str,
    payload: &str,
) -> (Option<String>, serde_json::Value, String) {
    let out = lambda
        .invoke()
        .function_name(name)
        .payload(Blob::new(payload.as_bytes().to_vec()))
        .log_type(LogType::Tail)
        .send()
        .await
        .unwrap();
    let body = serde_json::from_slice(out.payload().unwrap().as_ref()).unwrap();
    let logs = base64::engine::general_purpose::STANDARD.decode(out.log_result().unwrap_or_default()).unwrap();
    (out.function_error().map(str::to_string), body, String::from_utf8(logs).unwrap())
}

// Docker runs blocking, so the server needs a thread of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn container_image_functions_run_in_docker() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ecr = aws_sdk_ecr::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role_arn = role(&mws, "container-role").await;
    let host = mws.endpoint.trim_start_matches("http://").to_string();

    // Build two versions of the image and `docker push` them to ECR.
    let repo = ecr.create_repository().repository_name("fns/runtime").send().await.unwrap();
    let repo_uri = repo.repository().unwrap().repository_uri().unwrap().to_string();
    let token = ecr.get_authorization_token().send().await.unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.authorization_data()[0].authorization_token().unwrap())
        .unwrap();
    let password = String::from_utf8(decoded).unwrap()["AWS:".len()..].to_string();
    run_docker(&host, &["login", "-u", "AWS", "--password-stdin", &host], Some(&password));
    for version in ["1", "2"] {
        let local = format!("{host}/fns/runtime:v{version}");
        if !build_runtime_image(&host, &local, version) {
            return;
        }
        run_docker(&host, &["push", &local], None);
        run_docker(&host, &["rmi", &local], None);
    }

    // ImageConfig overrides the image's command and working directory.
    lambda
        .create_function()
        .function_name("container")
        .package_type(PackageType::Image)
        .role(&role_arn)
        .code(image_code(&format!("{repo_uri}:v1")))
        .image_config(ImageConfig::builder().command("custom.handler").working_directory("/tmp").build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, "container").await;
    let (error, body, logs) = invoke(&lambda, "container", r#"{"n":1}"#).await;
    assert_eq!(error, None, "{body}");
    assert_eq!(body["args"], serde_json::json!(["/var/runtime/bootstrap", "custom.handler"]));
    assert_eq!(body["cwd"], "/tmp");
    assert_eq!(body["event"], serde_json::json!({"n": 1}));
    assert_eq!(body["function"], "container");
    assert_eq!(body["task_root"], "/var/task");
    assert_eq!(body["greeting"], "hello");
    assert_eq!(body["image_version"], "1");
    // Images name their handler themselves.
    assert_eq!(body["handler"], serde_json::Value::Null);
    assert_eq!(body["has_credentials"], true);
    // As in Lambda, only /tmp is writable.
    assert_eq!(body["tmp_writable"], true);
    assert_eq!(body["root_writable"], false);
    assert!(logs.contains("handling "), "{logs}");
    assert!(logs.contains("REPORT RequestId:"), "{logs}");

    // The environment stays warm and reports function errors.
    let (error, body, _) = invoke(&lambda, "container", r#"{"fail":true}"#).await;
    assert_eq!(error.as_deref(), Some("Unhandled"));
    assert_eq!(body, serde_json::json!({"errorType": "Custom", "errorMessage": "failed on purpose"}));

    // New code runs the new image.
    lambda.update_function_code().function_name("container").image_uri(format!("{repo_uri}:v2")).send().await.unwrap();
    mws_e2e::function_updated(&lambda, "container").await;
    let (_, body, _) = invoke(&lambda, "container", "{}").await;
    assert_eq!(body["image_version"], "2");
    assert_eq!(body["args"], serde_json::json!(["/var/runtime/bootstrap", "custom.handler"]));

    // An entry point override keeps the image's command.
    lambda
        .update_function_configuration()
        .function_name("container")
        .image_config(ImageConfig::builder().entry_point("/var/runtime/bootstrap").entry_point("--flag").build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_updated(&lambda, "container").await;
    let (_, body, _) = invoke(&lambda, "container", "{}").await;
    assert_eq!(body["args"], serde_json::json!(["/var/runtime/bootstrap", "--flag", "app.handler"]));
    assert_eq!(body["cwd"], "/var/task");

    // An entry point that does not exist cannot start.
    lambda
        .update_function_configuration()
        .function_name("container")
        .image_config(ImageConfig::builder().entry_point("/nope").build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_updated(&lambda, "container").await;
    let (error, body, _) = invoke(&lambda, "container", "{}").await;
    assert_eq!(error.as_deref(), Some("Unhandled"));
    assert_eq!(body["errorType"], "Runtime.InvalidEntrypoint", "{body}");

    run_docker(&host, &["logout", &host], None);
}
