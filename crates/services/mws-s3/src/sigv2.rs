//! Signatures S3 accepts besides SigV4: Signature Version 2
//! (`Authorization: AWS <key>:<signature>` and presigned URLs with
//! `AWSAccessKeyId`/`Signature`/`Expires`), and the signed policies of
//! browser form uploads (`POST` with `multipart/form-data`, signed with
//! either version).
//!
//! The gateway resolves the access key and calls back with its secret
//! ([`mws_core::AlternateSignature`]). Version 2 signatures are verified
//! like AWS does, but S3 then refuses them for any bucket created after 24
//! June 2020 (every MWS bucket) with `InvalidRequest`.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{AlternateSignature, ErrorValue, HttpRequest, ServiceError};

use crate::post;

/// Subresources that are part of a V2 `CanonicalizedResource`.
const SUBRESOURCES: &[&str] = &[
    "accelerate",
    "acl",
    "analytics",
    "cors",
    "delete",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "legal-hold",
    "lifecycle",
    "location",
    "logging",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "partNumber",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
    "response-content-language",
    "response-content-type",
    "response-expires",
    "restore",
    "retention",
    "select",
    "select-type",
    "tagging",
    "torrent",
    "uploadId",
    "uploads",
    "versionId",
    "versioning",
    "versions",
    "website",
];

/// Requests may be signed up to 15 minutes either side of the server's time.
const MAX_SKEW_SECS: i64 = 15 * 60;

fn signature_does_not_match() -> ServiceError {
    ServiceError::client(
        "SignatureDoesNotMatch",
        403,
        "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
    )
}

fn hmac_sha1(secret: &str, data: &[u8]) -> String {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::hmac::sign(&key, data).as_ref())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn decode(v: &str) -> String {
    percent_encoding::percent_decode_str(&v.replace('+', "%20")).decode_utf8_lossy().into_owned()
}

fn query_params(request: &HttpRequest) -> Vec<(String, String)> {
    request
        .uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

/// The signature a request carries, if it is one of S3's own.
pub(crate) fn alternate(request: &HttpRequest) -> Option<Result<AlternateSignature, ServiceError>> {
    if let Some(auth) = request.headers().get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let rest = auth.strip_prefix("AWS ")?;
        return Some(header_v2(request, rest));
    }
    let params = query_params(request);
    let get = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    if let (Some(key), Some(signature)) = (get("AWSAccessKeyId"), get("Signature")) {
        return Some(query_v2(request, &params, key, signature, get("Expires")));
    }
    if post::is_form_upload(request) {
        return post_policy(request);
    }
    None
}

fn header_v2(request: &HttpRequest, rest: &str) -> Result<AlternateSignature, ServiceError> {
    let Some((key, signature)) = rest.rsplit_once(':') else {
        return Err(ServiceError::client(
            "InvalidArgument",
            400,
            "AWS authorization header is invalid.  Expected AwsAccessKeyId:signature",
        )
        .with_field("ArgumentName", ErrorValue::String("Authorization".into()))
        .with_field("ArgumentValue", ErrorValue::String(format!("AWS {rest}"))));
    };
    let header = |name: &str| request.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let amz_date = header("x-amz-date");
    let date = header("date");
    let when = amz_date.as_deref().or(date.as_deref()).map(str::to_string);
    let string_to_sign =
        string_to_sign(request, &[], if amz_date.is_some() { "" } else { date.as_deref().unwrap_or("") });
    let (key, signature) = (key.to_string(), signature.to_string());
    Ok(AlternateSignature {
        access_key_id: key,
        session_token: header("x-amz-security-token"),
        region: None,
        verify: Box::new(move |secret, now| {
            let Some(when) = when.as_deref().and_then(parse_http_date) else {
                return Err(ServiceError::client(
                    "AccessDenied",
                    403,
                    "AWS authentication requires a valid Date or x-amz-date header",
                ));
            };
            if (now - when).num_seconds().abs() > MAX_SKEW_SECS {
                return Err(ServiceError::client(
                    "RequestTimeTooSkewed",
                    403,
                    "The difference between the request time and the current time is too large.",
                )
                .with_field("RequestTime", ErrorValue::String(when.to_rfc2822()))
                .with_field("ServerTime", ErrorValue::String(now.format("%Y-%m-%dT%H:%M:%SZ").to_string()))
                .with_field("MaxAllowedSkewMilliseconds", ErrorValue::String("900000".into())));
            }
            check(secret, &string_to_sign, &signature)
        }),
    })
}

fn query_v2(
    request: &HttpRequest,
    params: &[(String, String)],
    key: String,
    signature: String,
    expires: Option<String>,
) -> Result<AlternateSignature, ServiceError> {
    let Some(expires) = expires else {
        return Err(ServiceError::client(
            "AccessDenied",
            403,
            "Query-string authentication requires the Signature, Expires and AWSAccessKeyId parameters",
        ));
    };
    let string_to_sign = string_to_sign(request, params, &expires);
    let token = params.iter().find(|(k, _)| k == "x-amz-security-token").map(|(_, v)| v.clone());
    Ok(AlternateSignature {
        access_key_id: key,
        session_token: token,
        region: None,
        verify: Box::new(move |secret, now| {
            let at = expires.parse::<i64>().ok().and_then(|e| DateTime::<Utc>::from_timestamp(e, 0));
            match at {
                Some(at) if at >= now => check(secret, &string_to_sign, &signature),
                Some(_) => Err(ServiceError::client("AccessDenied", 403, "Request has expired")
                    .with_field("Expires", ErrorValue::String(expires.clone()))
                    .with_field("ServerTime", ErrorValue::String(now.format("%Y-%m-%dT%H:%M:%SZ").to_string()))),
                None => Err(ServiceError::client(
                    "AccessDenied",
                    403,
                    "Invalid date (should be seconds since epoch): ".to_string() + &expires,
                )),
            }
        }),
    })
}

fn check(secret: &str, string_to_sign: &str, signature: &str) -> Result<(), ServiceError> {
    let expected = hmac_sha1(secret, string_to_sign.as_bytes());
    if constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        return Ok(());
    }
    // A bucket's own resource is `/bucket/` as well as `/bucket` (botocore
    // signs the former for path-style requests).
    let (head, resource) = string_to_sign.rsplit_once('\n').unwrap_or(("", string_to_sign));
    let (path, query) = resource.split_once('?').map_or((resource, None), |(p, q)| (p, Some(q)));
    let bucket_only = path.len() > 1 && !path[1..].contains('/');
    let alternate = format!("{head}\n{path}/{}", query.map(|q| format!("?{q}")).unwrap_or_default());
    if bucket_only && constant_time_eq(hmac_sha1(secret, alternate.as_bytes()).as_bytes(), signature.as_bytes()) {
        Ok(())
    } else {
        tracing::debug!(%string_to_sign, "Signature Version 2 verification failed");
        Err(signature_does_not_match())
    }
}

fn parse_http_date(v: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(v)
        .ok()
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| chrono::NaiveDateTime::parse_from_str(v, "%Y%m%dT%H%M%SZ").ok().map(|d| d.and_utc()))
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(v.trim_end_matches(" GMT"), "%a, %d %b %Y %H:%M:%S")
                .ok()
                .map(|d| d.and_utc())
        })
}

/// The V2 string to sign. For presigned URLs, `x-amz-*` (and Content-Type /
/// Content-MD5) query parameters count as headers, and `date` is the
/// `Expires` value.
fn string_to_sign(request: &HttpRequest, params: &[(String, String)], date: &str) -> String {
    let mut amz: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut content_md5 = String::new();
    let mut content_type = String::new();
    for (name, value) in request.headers() {
        let name = name.as_str().to_ascii_lowercase();
        let value = value.to_str().unwrap_or_default().trim().to_string();
        match name.as_str() {
            "content-md5" => content_md5 = value,
            "content-type" => content_type = value,
            n if n.starts_with("x-amz-") => amz.entry(name).or_default().push(value),
            _ => {}
        }
    }
    for (name, value) in params {
        let name = name.to_ascii_lowercase();
        match name.as_str() {
            "content-md5" => content_md5 = value.clone(),
            "content-type" => content_type = value.clone(),
            n if n.starts_with("x-amz-") => amz.entry(name).or_default().push(value.clone()),
            _ => {}
        }
    }
    let mut s = format!("{}\n{content_md5}\n{content_type}\n{date}\n", request.method());
    for (name, values) in amz {
        s.push_str(&format!("{name}:{}\n", values.join(",")));
    }
    s.push_str(&canonical_resource(request));
    s
}

fn canonical_resource(request: &HttpRequest) -> String {
    let host = request.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let path = request.uri().path();
    let mut resource = match crate::virtual_host_bucket(host) {
        Some(bucket) => format!("/{bucket}{path}"),
        None => path.to_string(),
    };
    let mut sub: Vec<(String, Option<String>)> = request
        .uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|p| {
            let (k, v) = match p.split_once('=') {
                Some((k, v)) => (k, Some(decode(v))),
                None => (p, None),
            };
            SUBRESOURCES.contains(&k).then(|| (k.to_string(), v))
        })
        .collect();
    sub.sort_by(|a, b| a.0.cmp(&b.0));
    if !sub.is_empty() {
        resource.push('?');
        let parts: Vec<String> = sub
            .into_iter()
            .map(|(k, v)| match v {
                Some(v) => format!("{k}={v}"),
                None => k,
            })
            .collect();
        resource.push_str(&parts.join("&"));
    }
    resource
}

/// A form upload signed with a POST policy, in either signature version.
fn post_policy(request: &HttpRequest) -> Option<Result<AlternateSignature, ServiceError>> {
    let form = match post::Form::parse(request) {
        Ok(f) => f,
        Err(e) => return Some(Err(e)),
    };
    let field = |name: &str| form.field(name).map(str::to_string);
    let token = field("x-amz-security-token");
    if let Some(credential) = field("x-amz-credential") {
        let Some(policy) = field("policy") else { return Some(Err(post::missing_field("Policy"))) };
        let Some(signature) = field("x-amz-signature") else {
            return Some(Err(post::missing_field("X-Amz-Signature")));
        };
        if field("x-amz-algorithm").as_deref() != Some("AWS4-HMAC-SHA256") {
            return Some(Err(ServiceError::client(
                "InvalidArgument",
                400,
                "Unsupported value for x-amz-algorithm, must be AWS4-HMAC-SHA256",
            )));
        }
        let parts: Vec<&str> = credential.split('/').collect();
        let [key, date, region, service, "aws4_request"] = parts[..] else {
            return Some(Err(ServiceError::client(
                "InvalidArgument",
                400,
                format!("Invalid credential: {credential}"),
            )));
        };
        let scope = mws_sigv4::CredentialScope {
            access_key_id: key.to_string(),
            date: date.to_string(),
            region: region.to_string(),
            service: service.to_string(),
        };
        return Some(Ok(AlternateSignature {
            access_key_id: key.to_string(),
            session_token: token,
            region: Some(region.to_string()),
            verify: Box::new(move |secret, _| {
                let expected = mws_sigv4::sign_string(secret, &scope, &policy);
                if constant_time_eq(expected.as_bytes(), signature.to_ascii_lowercase().as_bytes()) {
                    Ok(())
                } else {
                    Err(signature_does_not_match())
                }
            }),
        }));
    }
    let key = field("awsaccesskeyid")?;
    let Some(policy) = field("policy") else { return Some(Err(post::missing_field("Policy"))) };
    let Some(signature) = field("signature") else { return Some(Err(post::missing_field("Signature"))) };
    Some(Ok(AlternateSignature {
        access_key_id: key,
        session_token: token,
        region: None,
        verify: Box::new(move |secret, _| check(secret, &policy, &signature)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_documented_example() {
        // From the S3 Signature Version 2 documentation (GET object).
        let request = http::Request::builder()
            .method("GET")
            .uri("/photos/puppy.jpg")
            .header("host", "awsexamplebucket1.s3.us-west-1.amazonaws.com")
            .header("date", "Tue, 27 Mar 2007 19:36:42 +0000")
            .body(bytes::Bytes::new())
            .unwrap();
        let sts = string_to_sign(&request, &[], "Tue, 27 Mar 2007 19:36:42 +0000");
        assert_eq!(sts, "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/awsexamplebucket1/photos/puppy.jpg");
        assert_eq!(
            hmac_sha1("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sts.as_bytes()),
            "qgk2+6Sv9/oM7G3qLEjTH1a1l1g="
        );
    }
}
