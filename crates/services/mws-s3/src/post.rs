//! Browser-based uploads: `POST /<bucket>` with a `multipart/form-data`
//! body whose fields describe the object and whose `file` field holds it,
//! optionally signed with a POST policy that constrains the other fields
//! (what `generate_presigned_post` and `createPresignedPost` produce).
//!
//! The upload is authorized and stored as a `PutObject` by whoever signed
//! the policy (or anonymously), and notifies as `s3:ObjectCreated:Post`.

use base64::Engine;
use bytes::Bytes;
use http::Method;
use mws_core::{ErrorValue, HttpRequest, HttpResponse, RequestContext, ServiceError};

use crate::{generated, Call};

const KEY_ENCODE: &percent_encoding::AsciiSet =
    &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~').remove(b'/');

/// Whether `request` is a form upload to a bucket (path-style by now).
pub(crate) fn is_form_upload(request: &HttpRequest) -> bool {
    request.method() == Method::POST
        && request.uri().query().is_none_or(|q| q.is_empty())
        && request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().starts_with("multipart/form-data"))
}

pub(crate) fn missing_field(name: &str) -> ServiceError {
    invalid_argument(
        format!("Bucket POST must contain a field named '{name}'.  If it is specified, please check the order of the fields."),
        name,
        "",
    )
}

fn invalid_argument(message: impl Into<String>, name: &str, value: &str) -> ServiceError {
    ServiceError::client("InvalidArgument", 400, message)
        .with_field("ArgumentName", ErrorValue::String(name.into()))
        .with_field("ArgumentValue", ErrorValue::String(value.into()))
}

fn policy_denied(why: impl Into<String>) -> ServiceError {
    ServiceError::client("AccessDenied", 403, format!("Invalid according to Policy: {}", why.into()))
}

fn malformed_post() -> ServiceError {
    ServiceError::client(
        "MalformedPOSTRequest",
        400,
        "The body of your POST request is not well-formed multipart/form-data.",
    )
}

/// The parsed form: fields in order (names as sent), and the file.
pub(crate) struct Form {
    fields: Vec<(String, String)>,
    file: Option<(Option<String>, Bytes)>,
}

impl Form {
    pub(crate) fn parse(request: &HttpRequest) -> Result<Form, ServiceError> {
        let content_type =
            request.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
        let boundary = content_type
            .split(';')
            .map(str::trim)
            .find_map(|p| {
                let (k, v) = p.split_once('=')?;
                k.eq_ignore_ascii_case("boundary").then(|| v.trim_matches('"').to_string())
            })
            .ok_or_else(malformed_post)?;
        let body = request.body();
        let delimiter = format!("--{boundary}");
        let mut fields = Vec::new();
        let mut file = None;
        let mut rest: &[u8] = body;
        let Some(start) = find(rest, delimiter.as_bytes()) else { return Err(malformed_post()) };
        rest = &rest[start + delimiter.len()..];
        loop {
            if rest.starts_with(b"--") {
                break;
            }
            rest = rest.strip_prefix(b"\r\n").ok_or_else(malformed_post)?;
            let head_end = find(rest, b"\r\n\r\n").ok_or_else(malformed_post)?;
            let head = String::from_utf8_lossy(&rest[..head_end]).into_owned();
            rest = &rest[head_end + 4..];
            let end_marker = format!("\r\n{delimiter}");
            let end = find(rest, end_marker.as_bytes()).ok_or_else(malformed_post)?;
            let value = &rest[..end];
            rest = &rest[end + end_marker.len()..];
            let (mut name, mut filename) = (None, None);
            for line in head.split("\r\n") {
                let Some((h, v)) = line.split_once(':') else { continue };
                if !h.trim().eq_ignore_ascii_case("content-disposition") {
                    continue;
                }
                for param in v.split(';').map(str::trim) {
                    if let Some((k, v)) = param.split_once('=') {
                        let v = v.trim().trim_matches('"').to_string();
                        match k.trim().to_ascii_lowercase().as_str() {
                            "name" => name = Some(v),
                            "filename" => filename = Some(v),
                            _ => {}
                        }
                    }
                }
            }
            let Some(name) = name else { return Err(malformed_post()) };
            if name.eq_ignore_ascii_case("file") {
                // S3 ignores fields after the file.
                file = Some((filename, Bytes::copy_from_slice(value)));
                break;
            }
            fields.push((name, String::from_utf8_lossy(value).into_owned()));
        }
        Ok(Form { fields, file })
    }

    /// A field by name, case-insensitively.
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Fields that sign the upload rather than describe it: no policy condition
/// needs to cover them.
fn exempt(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(n.as_str(), "policy" | "signature" | "awsaccesskeyid" | "x-amz-signature" | "file")
        || n.starts_with("x-ignore-")
}

/// Check the form against its policy's expiration and conditions.
fn check_policy(
    form: &Form,
    bucket: &str,
    size: usize,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), ServiceError> {
    let Some(policy) = form.field("policy") else { return Ok(()) };
    let invalid = |why: &str| ServiceError::client("InvalidPolicyDocument", 400, format!("Invalid Policy: {why}"));
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(policy.trim())
        .map_err(|_| invalid("Invalid 'Policy': Policy could not be decoded."))?;
    let doc: serde_json::Value = serde_json::from_slice(&decoded).map_err(|_| invalid("Invalid JSON."))?;
    let expiration =
        doc.get("expiration").and_then(|e| e.as_str()).ok_or_else(|| invalid("Policy missing expiration."))?;
    let expiration = chrono::DateTime::parse_from_rfc3339(expiration)
        .map_err(|_| invalid(&format!("Invalid 'expiration' value: '{expiration}'")))?;
    if expiration < now {
        return Err(policy_denied("Policy expired."));
    }
    let conditions =
        doc.get("conditions").and_then(|c| c.as_array()).ok_or_else(|| invalid("Policy missing conditions."))?;
    let value_of = |name: &str| -> String {
        let name = name.trim_start_matches('$');
        if name.eq_ignore_ascii_case("bucket") {
            return form.field("bucket").unwrap_or(bucket).to_string();
        }
        form.field(name).unwrap_or_default().to_string()
    };
    let mut covered: Vec<String> = Vec::new();
    for c in conditions {
        let failed = || policy_denied(format!("Policy Condition failed: {c}"));
        match c {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    covered.push(k.to_ascii_lowercase());
                    let want = v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
                    if value_of(k) != want {
                        return Err(failed());
                    }
                }
            }
            serde_json::Value::Array(a) => {
                let op = a.first().and_then(|v| v.as_str()).unwrap_or_default().to_ascii_lowercase();
                match op.as_str() {
                    "content-length-range" => {
                        let min = a
                            .get(1)
                            .and_then(|v| v.as_u64())
                            .ok_or_else(|| invalid("Invalid content-length-range."))?;
                        let max = a
                            .get(2)
                            .and_then(|v| v.as_u64())
                            .ok_or_else(|| invalid("Invalid content-length-range."))?;
                        if (size as u64) > max {
                            return Err(crate::errors::entity_too_large(size as i64, max as i64));
                        }
                        if (size as u64) < min {
                            return Err(ServiceError::client(
                                "EntityTooSmall",
                                400,
                                "Your proposed upload is smaller than the minimum allowed size",
                            )
                            .with_field("ProposedSize", ErrorValue::String(size.to_string()))
                            .with_field("MinSizeAllowed", ErrorValue::String(min.to_string())));
                        }
                    }
                    "eq" | "starts-with" => {
                        let (Some(field), Some(want)) =
                            (a.get(1).and_then(|v| v.as_str()), a.get(2).and_then(|v| v.as_str()))
                        else {
                            return Err(invalid(&format!("Invalid condition: {c}")));
                        };
                        if !field.starts_with('$') {
                            return Err(invalid(&format!("Invalid condition: {c}")));
                        }
                        covered.push(field.trim_start_matches('$').to_ascii_lowercase());
                        let got = value_of(field);
                        let ok = if op == "eq" { got == want } else { got.starts_with(want) };
                        if !ok {
                            return Err(failed());
                        }
                    }
                    _ => return Err(invalid(&format!("Invalid condition: {c}"))),
                }
            }
            _ => return Err(invalid(&format!("Invalid condition: {c}"))),
        }
    }
    let extra: Vec<&str> = form
        .fields
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| !exempt(k) && !k.eq_ignore_ascii_case("bucket") && !covered.contains(&k.to_ascii_lowercase()))
        .collect();
    if let Some(first) = extra.first() {
        return Err(policy_denied(format!("Extra input fields: {first}")));
    }
    Ok(())
}

/// A `tagging` field (`<Tagging><TagSet><Tag>...`) as a header value.
fn tagging_header(xml: &str) -> Result<String, ServiceError> {
    let text = |tag: &str, s: &str| -> Option<String> {
        let open = format!("<{tag}>");
        let (_, rest) = s.split_once(&open)?;
        let (v, _) = rest.split_once(&format!("</{tag}>"))?;
        Some(v.to_string())
    };
    let mut pairs = form_urlencoded::Serializer::new(String::new());
    for chunk in xml.split("<Tag>").skip(1) {
        let (Some(k), Some(v)) = (text("Key", chunk), text("Value", chunk)) else {
            return Err(crate::errors::malformed_xml());
        };
        pairs.append_pair(&k, &v);
    }
    Ok(pairs.finish())
}

impl Call {
    /// Serve a form upload to `bucket`.
    pub(crate) async fn post_object(
        &mut self,
        ctx: &RequestContext,
        request: &HttpRequest,
    ) -> Result<HttpResponse, ServiceError> {
        let path = request.uri().path().trim_start_matches('/');
        let bucket = path.split('/').next().unwrap_or_default().to_string();
        let form = Form::parse(request)?;
        let Some((filename, data)) = &form.file else {
            return Err(invalid_argument("POST requires exactly one file upload per request.", "file", "0"));
        };
        let signed = form.field("x-amz-credential").is_some() || form.field("awsaccesskeyid").is_some();
        if signed {
            check_policy(&form, &bucket, data.len(), ctx.received_at)?;
        }
        let Some(key) = form.field("key") else { return Err(missing_field("key")) };
        let key = key.replace("${filename}", filename.as_deref().unwrap_or_default());
        if key.is_empty() {
            return Err(invalid_argument("User key must have a length greater than 0.", "key", ""));
        }

        let encoded_key = percent_encoding::utf8_percent_encode(&key, KEY_ENCODE).to_string();
        let mut put = http::Request::builder().method(Method::PUT).uri(format!("/{bucket}/{encoded_key}"));
        for (name, value) in &form.fields {
            let lower = name.to_ascii_lowercase();
            let header = match lower.as_str() {
                "acl" => "x-amz-acl".to_string(),
                "tagging" => {
                    put = put.header("x-amz-tagging", tagging_header(value)?);
                    continue;
                }
                "cache-control"
                | "content-type"
                | "content-disposition"
                | "content-encoding"
                | "expires"
                | "content-md5"
                | "content-language" => lower.clone(),
                "x-amz-algorithm" | "x-amz-credential" | "x-amz-date" | "x-amz-signature" | "x-amz-security-token" => {
                    continue
                }
                n if n.starts_with("x-amz-") => lower.clone(),
                _ => continue,
            };
            put = put.header(header, value.as_str());
        }
        put = put.header(http::header::CONTENT_LENGTH, data.len());
        let put = put.body(data.clone()).map_err(|_| malformed_post())?;

        self.form_post = true;
        let response = generated::route(self, ctx, &put).await?;
        if !response.status().is_success() {
            return Ok(response);
        }
        let etag =
            response.headers().get(http::header::ETAG).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let base = ctx.endpoint.clone().unwrap_or_default();
        let location = format!("{base}/{bucket}/{encoded_key}");
        let mut out = http::Response::builder();
        for name in
            ["x-amz-version-id", "x-amz-server-side-encryption", "x-amz-server-side-encryption-aws-kms-key-id", "etag"]
        {
            if let Some(v) = response.headers().get(name) {
                out = out.header(name, v.clone());
            }
        }
        out = out.header(http::header::LOCATION, location.as_str());
        let redirect = form.field("success_action_redirect").or_else(|| form.field("redirect"));
        if let Some(url) = redirect.filter(|u| u.starts_with("http://") || u.starts_with("https://")) {
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("bucket", &bucket)
                .append_pair("key", &key)
                .append_pair("etag", &etag)
                .finish();
            let sep = if url.contains('?') { '&' } else { '?' };
            return out
                .status(303)
                .header(http::header::LOCATION, format!("{url}{sep}{query}"))
                .body(Bytes::new())
                .map_err(|_| malformed_post());
        }
        let status = match form.field("success_action_status") {
            Some("200") => 200,
            Some("201") => 201,
            _ => 204,
        };
        let body = if status == 201 {
            let esc =
                |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
            out = out.header(http::header::CONTENT_TYPE, "application/xml");
            Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PostResponse><Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></PostResponse>",
                esc(&location),
                esc(&bucket),
                esc(&key),
                esc(&etag)
            ))
        } else {
            Bytes::new()
        };
        out.status(status).body(body).map_err(|_| malformed_post())
    }
}
