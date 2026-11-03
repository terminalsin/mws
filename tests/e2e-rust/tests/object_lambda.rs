//! S3 Control access points and S3 Object Lambda through the official Rust
//! SDKs: GetObject through an Object Lambda access point runs the function,
//! which answers with WriteGetObjectResponse.

use std::io::Write;

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FunctionCode, Runtime};
use aws_sdk_s3control::types::{
    AwsLambdaTransformation, ObjectLambdaConfiguration, ObjectLambdaContentTransformation,
    ObjectLambdaTransformationConfiguration, ObjectLambdaTransformationConfigurationAction,
};
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
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
const WGOR_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3-object-lambda:WriteGetObjectResponse","Resource":"*"}]}"#;

const REDACT: &str = r#"
import boto3, urllib.request

def handler(event, context):
    ctx = event["getObjectContext"]
    assert "X-Amz-Signature=" in ctx["inputS3Url"] and "X-Amz-Security-Token=" in ctx["inputS3Url"]
    text = urllib.request.urlopen(ctx["inputS3Url"]).read().decode()
    secret = event["configuration"]["payload"]
    boto3.client("s3").write_get_object_response(
        RequestRoute=ctx["outputRoute"],
        RequestToken=ctx["outputToken"],
        Body=text.replace(secret, "*" * len(secret)).encode(),
        ContentType="text/plain",
    )
    return {"status_code": 200}
"#;

#[tokio::test]
async fn access_points_and_object_lambda() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let control = aws_sdk_s3control::Client::new(&cfg);
    s3.create_bucket().bucket("docs").send().await.unwrap();
    s3.put_object()
        .bucket("docs")
        .key("memo.txt")
        .body(b"the password is hunter2".to_vec().into())
        .send()
        .await
        .unwrap();

    // A plain access point, addressed by ARN (host-style) and by alias.
    let ap = control.create_access_point().account_id(ACCOUNT).name("docs-ap").bucket("docs").send().await.unwrap();
    let ap_arn = ap.access_point_arn().unwrap().to_string();
    assert_eq!(ap_arn, "arn:aws:s3:us-east-1:123456789012:accesspoint/docs-ap");
    let alias = ap.alias().unwrap().to_string();
    assert!(alias.ends_with("-s3alias"), "{alias}");
    let got = control.get_access_point().account_id(ACCOUNT).name("docs-ap").send().await.unwrap();
    assert_eq!(got.bucket(), Some("docs"));
    assert_eq!(got.network_origin(), Some(&aws_sdk_s3control::types::NetworkOrigin::Internet));
    let listed = control.list_access_points().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(listed.access_point_list().len(), 1);
    let dup =
        control.create_access_point().account_id(ACCOUNT).name("docs-ap").bucket("docs").send().await.unwrap_err();
    assert_eq!(dup.into_service_error().meta().code(), Some("AccessPointAlreadyOwnedByYou"));

    let host_style = aws_sdk_s3::Client::new(&cfg);
    let body = host_style.get_object().bucket(&ap_arn).key("memo.txt").send().await.unwrap();
    assert_eq!(body.body.collect().await.unwrap().into_bytes().as_ref(), b"the password is hunter2");
    let body = s3.get_object().bucket(&alias).key("memo.txt").send().await.unwrap();
    assert_eq!(body.body.collect().await.unwrap().into_bytes().as_ref(), b"the password is hunter2");

    // The transforming function.
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role = iam.create_role().role_name("redactor").assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy().role_name("redactor").policy_name("wgor").policy_document(WGOR_POLICY).send().await.unwrap();
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let function = lambda
        .create_function()
        .function_name("redact")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .timeout(30)
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", REDACT)]))).build())
        .send()
        .await
        .unwrap();

    let olap = control
        .create_access_point_for_object_lambda()
        .account_id(ACCOUNT)
        .name("redacted")
        .configuration(
            ObjectLambdaConfiguration::builder()
                .supporting_access_point(&ap_arn)
                .transformation_configurations(
                    ObjectLambdaTransformationConfiguration::builder()
                        .actions(ObjectLambdaTransformationConfigurationAction::GetObject)
                        .content_transformation(ObjectLambdaContentTransformation::AwsLambda(
                            AwsLambdaTransformation::builder()
                                .function_arn(function.function_arn().unwrap())
                                .function_payload("hunter2")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let olap_arn = olap.object_lambda_access_point_arn().unwrap().to_string();
    assert_eq!(olap_arn, "arn:aws:s3-object-lambda:us-east-1:123456789012:accesspoint/redacted");
    let olap_alias = olap.alias().unwrap().value().unwrap().to_string();
    assert!(olap_alias.ends_with("--ol-s3"), "{olap_alias}");

    for (client, target) in [(&host_style, &olap_arn), (&s3, &olap_alias)] {
        let out = client.get_object().bucket(target).key("memo.txt").send().await.unwrap();
        assert_eq!(out.content_type(), Some("text/plain"));
        assert_eq!(out.body.collect().await.unwrap().into_bytes().as_ref(), b"the password is *******");
    }

    // The caller needs lambda:InvokeFunction and the Object Lambda
    // permissions, not just S3 ones.
    let (_, reader_cfg) = mws_e2e::user_with_policy(
        &mws,
        "reader",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3-object-lambda:GetObject"],"Resource":"*"}]}"#),
    )
    .await;
    let reader = Mws::s3(&reader_cfg);
    let denied = reader.get_object().bucket(&olap_alias).key("memo.txt").send().await.unwrap_err();
    assert_eq!(denied.into_service_error().meta().code(), Some("LambdaPermissionError"));

    // Unknown tokens are refused.
    let bad = s3.write_get_object_response().request_route("io-x").request_token("bogus").send().await.unwrap_err();
    assert_eq!(bad.into_service_error().meta().code(), Some("InvalidToken"));

    control.delete_access_point_for_object_lambda().account_id(ACCOUNT).name("redacted").send().await.unwrap();
    let gone = s3.get_object().bucket(&olap_alias).key("memo.txt").send().await.unwrap_err();
    assert_eq!(gone.into_service_error().meta().code(), Some("NoSuchBucket"));
    mws.stop().await;
}
