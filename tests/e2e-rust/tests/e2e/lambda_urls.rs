//! Lambda function URLs: HTTP requests invoke the function with the payload
//! format 2.0 event, and its result becomes the HTTP response.

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, FunctionUrlAuthType, Runtime};
use mws_e2e::Mws;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const APP: &str = r#"
import json

def handler(event, context):
    return {
        "statusCode": 202,
        "headers": {"content-type": "text/plain"},
        "body": event["requestContext"]["http"]["method"] + " " + event["rawPath"] + "?" + event["rawQueryString"],
    }
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
async fn function_urls_serve_requests() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);

    let role = iam.create_role().role_name("web").assume_role_policy_document(TRUST).send().await.unwrap();
    lambda
        .create_function()
        .function_name("web")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", APP)]))).build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, "web").await;
    let url = lambda
        .create_function_url_config()
        .function_name("web")
        .auth_type(FunctionUrlAuthType::None)
        .send()
        .await
        .unwrap()
        .function_url;
    let host = url.trim_start_matches("https://").trim_end_matches('/').to_string();
    assert!(host.ends_with(".lambda-url.us-east-1.on.aws"), "{host}");

    // No resource policy lets `*` call it yet.
    let (status, _, body) = mws.raw("GET", "/items", &[("Host", &host)], b"").await;
    assert_eq!(status, 403);
    assert_eq!(body, br#"{"Message":"Forbidden"}"#);

    lambda
        .add_permission()
        .function_name("web")
        .statement_id("url")
        .action("lambda:InvokeFunctionUrl")
        .principal("*")
        .function_url_auth_type(FunctionUrlAuthType::None)
        .send()
        .await
        .unwrap();
    lambda
        .add_permission()
        .function_name("web")
        .statement_id("invoke")
        .action("lambda:InvokeFunction")
        .principal("*")
        .invoked_via_function_url(true)
        .send()
        .await
        .unwrap();

    let (status, headers, body) = mws.raw("DELETE", "/items/7?force=true", &[("Host", &host)], b"").await;
    assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
    assert!(headers.iter().any(|(k, v)| k == "content-type" && v == "text/plain"));
    assert_eq!(String::from_utf8(body).unwrap(), "DELETE /items/7?force=true");

    // Removing the URL config stops serving it.
    lambda.delete_function_url_config().function_name("web").send().await.unwrap();
    let (status, _, _) = mws.raw("GET", "/items", &[("Host", &host)], b"").await;
    assert_eq!(status, 403);
    mws.stop().await;
}
