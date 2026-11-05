//! The URLs custom resources answer on (`ResponseURL`) and wait condition
//! handles signal. AWS hands out presigned S3 URLs; MWS serves them
//! itself, unsigned, as those URLs need no credentials either.

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse};
use serde_json::Value;

use crate::CloudFormation;

pub const PREFIX: &str = "/_aws/cloudformation/signal/";

/// The URL for signal key `token`.
pub fn url(endpoint: Option<&str>, token: &str) -> String {
    let base = endpoint.unwrap_or("http://localhost:4566").trim_end_matches('/');
    format!("{base}{PREFIX}{token}")
}

/// The token of a URL [`url`] made.
pub fn token_of(url: &str) -> Option<String> {
    let pos = url.find(PREFIX)?;
    let t = &url[pos + PREFIX.len()..];
    let t = t.split(['?', '#']).next().unwrap_or_default();
    (!t.is_empty()).then(|| t.to_string())
}

pub fn handle(cfn: &CloudFormation, request: &HttpRequest) -> HttpResponse {
    let token = request.uri().path()[PREFIX.len()..].to_string();
    let respond = |status: u16, body: &str| {
        http::Response::builder()
            .status(status)
            .header("content-type", "application/xml")
            .body(Bytes::from(body.to_string()))
            .expect("valid response")
    };
    if request.method() != http::Method::PUT && request.method() != http::Method::POST {
        return respond(405, "");
    }
    let body: Value = match serde_json::from_slice(request.body()) {
        Ok(v) => v,
        Err(_) => return respond(400, "<Error><Code>MalformedJSON</Code><Message>The response body is not valid JSON</Message></Error>"),
    };
    cfn.signal(&token, body);
    respond(200, "")
}
