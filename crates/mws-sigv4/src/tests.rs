//! Cross-checks against the official `aws-sigv4` signer, so MWS accepts
//! exactly what the AWS SDKs produce.

use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SignatureLocation as AwsLoc, SigningSettings};
use aws_sigv4::sign::v4;
use chrono::{DateTime, Utc};

use super::*;

const AKID: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

#[allow(clippy::too_many_arguments)]
fn signed(
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
    service: &str,
    location: AwsLoc,
    token: Option<&str>,
    at: SystemTime,
) -> http::Request<Vec<u8>> {
    let creds = Credentials::new(AKID, SECRET, token.map(str::to_string), None, "test");
    let identity = creds.into();
    let mut settings = SigningSettings::default();
    settings.signature_location = location;
    if location == AwsLoc::QueryParams {
        settings.expires_in = Some(Duration::from_secs(900));
    }
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name(service)
        .time(at)
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let signable =
        SignableRequest::new(method, uri, headers.iter().copied(), SignableBody::Bytes(body.as_bytes())).unwrap();
    let (instructions, _) = sign(signable, &params).unwrap().into_parts();
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let mut req = builder.body(body.as_bytes().to_vec()).unwrap();
    instructions.apply_to_request_http1x(&mut req);
    req
}

fn now() -> (SystemTime, DateTime<Utc>) {
    let t = SystemTime::now();
    (t, DateTime::<Utc>::from(t))
}

#[test]
fn header_signature_from_sdk_verifies() {
    let (t, now) = now();
    let req = signed(
        "POST",
        "http://localhost:4566/",
        &[("host", "localhost:4566"), ("content-type", "application/x-www-form-urlencoded")],
        "Action=GetUser&Version=2010-05-08",
        "iam",
        AwsLoc::Headers,
        None,
        t,
    );
    let parsed = parse(&req).unwrap();
    assert_eq!(parsed.scope.access_key_id, AKID);
    assert_eq!(parsed.scope.service, "iam");
    assert_eq!(parsed.location, SignatureLocation::Header);
    verify(&req, &parsed, SECRET, now, VerifyOptions::default()).unwrap();
}

#[test]
fn wrong_secret_is_rejected() {
    let (t, now) = now();
    let req = signed("POST", "http://localhost/", &[("host", "localhost")], "x", "iam", AwsLoc::Headers, None, t);
    let parsed = parse(&req).unwrap();
    assert_eq!(verify(&req, &parsed, "nope", now, VerifyOptions::default()), Err(SigV4Error::Mismatch));
}

#[test]
fn tampered_body_is_rejected() {
    let (t, now) = now();
    let mut req = signed("POST", "http://localhost/", &[("host", "localhost")], "a=1", "iam", AwsLoc::Headers, None, t);
    *req.body_mut() = b"a=2".to_vec();
    let parsed = parse(&req).unwrap();
    assert_eq!(verify(&req, &parsed, SECRET, now, VerifyOptions::default()), Err(SigV4Error::Mismatch));
}

#[test]
fn rest_path_with_query_and_encoded_segments_verifies() {
    let (t, now) = now();
    let req = signed(
        "GET",
        "http://localhost:4566/2013-04-01/hostedzone/Z1%2FX/rrset?maxitems=10&name=a%20b.example.com.&type=A",
        &[("host", "localhost:4566")],
        "",
        "route53",
        AwsLoc::Headers,
        Some("session-token/with+chars="),
        t,
    );
    let parsed = parse(&req).unwrap();
    assert_eq!(parsed.session_token.as_deref(), Some("session-token/with+chars="));
    verify(&req, &parsed, SECRET, now, VerifyOptions::default()).unwrap();
}

#[test]
fn presigned_query_signature_verifies() {
    let (t, now) = now();
    let req = signed(
        "GET",
        "http://localhost:4566/?Action=GetCallerIdentity&Version=2011-06-15",
        &[("host", "localhost:4566")],
        "",
        "sts",
        AwsLoc::QueryParams,
        Some("tok"),
        t,
    );
    let parsed = parse(&req).unwrap();
    assert_eq!(parsed.location, SignatureLocation::Query);
    assert_eq!(parsed.expires_in, Some(900));
    verify(&req, &parsed, SECRET, now, VerifyOptions::default()).unwrap();
    // Expired a second after its lifetime.
    let later = now + TimeDelta::seconds(901);
    assert_eq!(verify(&req, &parsed, SECRET, later, VerifyOptions::default()), Err(SigV4Error::PresignExpired));
}

#[test]
fn clock_skew_is_enforced() {
    let (t, _) = now();
    let old = t - Duration::from_secs(16 * 60);
    let req = signed("POST", "http://localhost/", &[("host", "localhost")], "", "iam", AwsLoc::Headers, None, old);
    let parsed = parse(&req).unwrap();
    let err = verify(&req, &parsed, SECRET, DateTime::<Utc>::from(t), VerifyOptions::default()).unwrap_err();
    assert!(matches!(err, SigV4Error::Expired { .. }), "{err:?}");
}

#[test]
fn unsigned_request_is_missing() {
    let req = http::Request::builder().uri("http://localhost/").body(Vec::<u8>::new()).unwrap();
    assert_eq!(parse(&req), Err(SigV4Error::Missing));
}

#[test]
fn malformed_header_is_incomplete() {
    let req = http::Request::builder()
        .uri("http://localhost/")
        .header("authorization", "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/iam/aws4_request")
        .header("x-amz-date", "20240101T000000Z")
        .body(Vec::<u8>::new())
        .unwrap();
    assert!(matches!(parse(&req), Err(SigV4Error::Incomplete(_))));
}

#[test]
fn presigned_urls_verify() {
    let now = chrono::Utc::now();
    let url = presign_url(&PresignParams {
        method: "GET",
        url: "http://127.0.0.1:4566/my-ap-abc-s3alias/a%20b.txt?versionId=1",
        region: "us-east-1",
        service: "s3",
        access_key_id: "AKIDEXAMPLE",
        secret_access_key: "secret",
        session_token: Some("tok/en+"),
        now,
        expires_in: 60,
    })
    .unwrap();
    let uri: http::Uri = url.parse().unwrap();
    let request = http::Request::builder()
        .uri(uri.path_and_query().unwrap().as_str())
        .header("host", "127.0.0.1:4566")
        .body(Vec::<u8>::new())
        .unwrap();
    let parsed = parse(&request).unwrap();
    assert_eq!(parsed.session_token.as_deref(), Some("tok/en+"));
    verify(&request, &parsed, "secret", now, VerifyOptions { double_encode_path: false }).unwrap();
    assert!(verify(&request, &parsed, "other", now, VerifyOptions { double_encode_path: false }).is_err());
}

fn signed_v4a(region_set: &str, body: &str, at: SystemTime) -> http::Request<Vec<u8>> {
    let creds = Credentials::new(AKID, SECRET, None, None, "test");
    let identity = creds.into();
    let params = aws_sigv4::sign::v4a::SigningParams::builder()
        .identity(&identity)
        .region_set(region_set)
        .name("events")
        .time(at)
        .settings(SigningSettings::default())
        .build()
        .unwrap()
        .into();
    let headers = [("host", "abcde.xyz.endpoint.events.amazonaws.com"), ("x-amz-target", "AWSEvents.PutEvents")];
    let uri = "https://abcde.xyz.endpoint.events.amazonaws.com/";
    let signable =
        SignableRequest::new("POST", uri, headers.iter().copied(), SignableBody::Bytes(body.as_bytes())).unwrap();
    let (instructions, _) = sign(signable, &params).unwrap().into_parts();
    let mut builder = http::Request::builder().method("POST").uri(uri);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    let mut req = builder.body(body.as_bytes().to_vec()).unwrap();
    instructions.apply_to_request_http1x(&mut req);
    req
}

#[test]
fn sigv4a_signature_from_sdk_verifies() {
    let (t, now) = now();
    let req = signed_v4a("*", r#"{"Entries":[]}"#, t);
    let parsed = parse(&req).unwrap();
    assert_eq!(parsed.algorithm, Algorithm::EcdsaP256Sha256);
    assert_eq!(parsed.scope.service, "events");
    assert_eq!(parsed.scope.region, "");
    verify(&req, &parsed, SECRET, now, VerifyOptions::default()).unwrap();
    assert_eq!(verify(&req, &parsed, "wrong", now, VerifyOptions::default()), Err(SigV4Error::Mismatch));

    let req = signed_v4a("eu-west-1,us-*", "{}", t);
    let parsed = parse(&req).unwrap();
    assert_eq!(parsed.scope.region, "eu-west-1");
    verify(&req, &parsed, SECRET, now, VerifyOptions::default()).unwrap();

    // A changed body no longer verifies.
    let (parts, _) = req.into_parts();
    let tampered = http::Request::from_parts(parts, b"{\"x\":1}".to_vec());
    assert!(verify(&tampered, &parsed, SECRET, now, VerifyOptions::default()).is_err());
}
