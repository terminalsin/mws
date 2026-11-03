//! Behaviour AWS shows across services that SDK users rely on: how each
//! protocol names authentication failures, S3's own validation errors, and
//! public SSM parameters. Expected values are what AWS returns.

use aws_sdk_s3::error::ProvideErrorMetadata;
use mws_e2e::Mws;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

const BAD_KEY: &str = "AKIAAAAAAAAAAAAAAAAA";

#[tokio::test]
async fn auth_errors_follow_each_protocol() {
    let mws = Mws::start().await;
    let iam = &mws.config.iam;
    let unknown = mws.sdk_config(BAD_KEY, "x", None).await;
    let wrong_secret = mws.sdk_config(&iam.root_access_key_id, "wrong-secret-wrong-secret-wrong-secret00", None).await;

    // awsJson: Coral's names, status 400.
    for (config, want) in [(&unknown, "UnrecognizedClientException"), (&wrong_secret, "InvalidSignatureException")] {
        let e = aws_sdk_kms::Client::new(config).list_keys().send().await.unwrap_err();
        assert_eq!(e.raw_response().unwrap().status().as_u16(), 400);
        assert_eq!(code(&e.into_service_error()), want);
        let e = aws_sdk_cloudwatchlogs::Client::new(config).describe_log_groups().send().await.unwrap_err();
        assert_eq!(code(&e.into_service_error()), want);
        let e = aws_sdk_secretsmanager::Client::new(config).list_secrets().send().await.unwrap_err();
        assert_eq!(code(&e.into_service_error()), want);
    }
    let e = aws_sdk_kms::Client::new(&unknown).list_keys().send().await.unwrap_err();
    assert_eq!(e.into_service_error().message(), Some("The security token included in the request is invalid."));

    // restJson (Lambda): the same names, status 403.
    let e = aws_sdk_lambda::Client::new(&unknown).list_functions().send().await.unwrap_err();
    assert_eq!(e.raw_response().unwrap().status().as_u16(), 403);
    assert_eq!(code(&e.into_service_error()), "UnrecognizedClientException");
    let e = aws_sdk_lambda::Client::new(&wrong_secret).list_functions().send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidSignatureException");

    // awsQuery and awsQueryCompatible keep the awsQuery codes.
    let e = aws_sdk_sts::Client::new(&unknown).get_caller_identity().send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidClientTokenId");
    let e = aws_sdk_sqs::Client::new(&unknown).list_queues().send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidClientTokenId");
    let e = aws_sdk_sqs::Client::new(&wrong_secret).list_queues().send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "SignatureDoesNotMatch");

    // S3 words them its own way.
    let e = Mws::s3(&unknown).list_buckets().send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "InvalidAccessKeyId");
    assert_eq!(e.message(), Some("The AWS Access Key Id you provided does not exist in our records."));
    let e = Mws::s3(&wrong_secret).list_buckets().send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "SignatureDoesNotMatch");
    assert_eq!(
        e.message(),
        Some(
            "The request signature we calculated does not match the signature you provided. Check your key and signing method."
        )
    );
    mws.stop().await;
}

#[tokio::test]
async fn unsigned_requests_are_refused_in_the_services_protocol() {
    let mws = Mws::start().await;
    let (status, headers, body) = mws
        .raw(
            "POST",
            "/",
            &[("X-Amz-Target", "TrentService.ListKeys"), ("Content-Type", "application/x-amz-json-1.1")],
            b"{}",
        )
        .await;
    assert_eq!(status, 400);
    assert!(headers.iter().any(|(k, v)| k == "x-amzn-errortype" && v == "MissingAuthenticationTokenException"));
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["message"], "Missing Authentication Token");

    let (status, headers, _) = mws.raw("GET", "/2015-03-31/functions/", &[], b"").await;
    assert_eq!(status, 403);
    assert!(headers.iter().any(|(k, v)| k == "x-amzn-errortype" && v == "MissingAuthenticationTokenException"));
    mws.stop().await;
}

#[tokio::test]
async fn s3_validation_errors_use_s3_codes() {
    let mws = Mws::start().await;
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    s3.create_bucket().bucket("parity").send().await.unwrap();

    let e = s3
        .put_object()
        .bucket("parity")
        .key("k")
        .storage_class("FOO".into())
        .body(b"x".to_vec().into())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidStorageClass");
    assert_eq!(e.message(), Some("The storage class you specified is not valid"));

    // `us-east-1` is never a location constraint.
    let e = s3
        .create_bucket()
        .bucket("parity-2")
        .create_bucket_configuration(
            aws_sdk_s3::types::CreateBucketConfiguration::builder().location_constraint("us-east-1".into()).build(),
        )
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidLocationConstraint");

    let e = s3
        .put_bucket_versioning()
        .bucket("parity")
        .versioning_configuration(
            aws_sdk_s3::types::VersioningConfiguration::builder().status("Sometimes".into()).build(),
        )
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "MalformedXML");
    mws.stop().await;
}

#[tokio::test]
async fn ssm_public_parameters() {
    let mws = Mws::start().await;
    let ssm = aws_sdk_ssm::Client::new(&mws.root_sdk_config().await);

    let p = ssm
        .get_parameter()
        .name("/aws/service/global-infrastructure/regions/us-east-1/longName")
        .send()
        .await
        .unwrap()
        .parameter
        .unwrap();
    assert_eq!(p.value(), Some("US East (N. Virginia)"));
    assert_eq!(
        p.arn(),
        Some("arn:aws:ssm:us-east-1::parameter/aws/service/global-infrastructure/regions/us-east-1/longName")
    );

    let name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64";
    let ami = ssm.get_parameter().name(name).send().await.unwrap().parameter.unwrap();
    assert!(ami.value().unwrap().starts_with("ami-"));
    assert_eq!(ami.value().unwrap().len(), 21);
    assert_eq!(ami.data_type(), Some("aws:ec2:image"));
    let by_arn =
        ssm.get_parameter().name(format!("arn:aws:ssm:us-east-1::parameter{name}")).send().await.unwrap().parameter;
    assert_eq!(by_arn.unwrap().value(), ami.value());

    let regions: Vec<String> = ssm
        .get_parameters_by_path()
        .path("/aws/service/global-infrastructure/regions")
        .into_paginator()
        .send()
        .collect::<Result<Vec<_>, _>>()
        .await
        .unwrap()
        .into_iter()
        .flat_map(|page| page.parameters.unwrap_or_default())
        .filter_map(|p| p.value)
        .collect();
    assert!(regions.contains(&"eu-west-1".to_string()));
    assert!(regions.contains(&"us-east-1".to_string()));

    let e = ssm.get_parameter().name("/aws/service/no/such/thing").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ParameterNotFound");

    // They are AWS's, not the caller's: not listed, not writable.
    let listed = ssm.describe_parameters().send().await.unwrap();
    assert!(listed.parameters().is_empty());
    let e = ssm
        .put_parameter()
        .name(name)
        .value("ami-0")
        .r#type(aws_sdk_ssm::types::ParameterType::String)
        .overwrite(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AccessDeniedException");
    mws.stop().await;
}
