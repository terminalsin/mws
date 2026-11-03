//! Runtime support for the `awsQuery` protocol.
//!
//! Requests are form-encoded `Action=...&Version=...&Param.member.1=...`
//! bodies (or query strings); responses are XML wrapped in
//! `<{Op}Response><{Op}Result>`. Generated service code (see `mws-codegen`)
//! calls into this crate; it knows nothing about any particular service.
//!
//! Spec: <https://smithy.io/2.0/aws/protocols/aws-query-protocol.html>

mod decode;

pub use decode::{Decoder, Params};
pub use mws_core::render_list;
pub use mws_xml::{format_timestamp, XmlWriter};

use bytes::Bytes;
use mws_core::{ErrorFault, HttpRequest, HttpResponse, ServiceError};

/// Re-exports used by generated code, so service crates need not depend on
/// these directly.
#[doc(hidden)]
pub mod __private {
    pub use async_trait::async_trait;
    pub use chrono;
    pub use regex;
}

/// Static facts about a query service, emitted by codegen.
#[derive(Debug, Clone, Copy)]
pub struct ServiceInfo {
    pub xml_namespace: &'static str,
    pub version: &'static str,
}

/// Collect request parameters from the query string and, for form posts,
/// the body. Body values win on conflict.
pub fn read_params(request: &HttpRequest) -> Params {
    let mut params = Params::new();
    if let Some(q) = request.uri().query() {
        params.extend_from_urlencoded(q.as_bytes());
    }
    let is_form = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(!request.body().is_empty());
    if is_form {
        params.extend_from_urlencoded(request.body());
    }
    params
}

/// The XML body of a successful response. `write_result` writes the members
/// of the output structure; pass `None` for operations without output.
pub fn success_body(
    info: &ServiceInfo,
    operation: &str,
    request_id: &str,
    write_result: Option<&dyn Fn(&mut XmlWriter)>,
) -> String {
    let mut w = XmlWriter::new();
    let response = format!("{operation}Response");
    w.open_with_ns(&response, info.xml_namespace);
    if let Some(write) = write_result {
        let result = format!("{operation}Result");
        w.open(&result);
        write(&mut w);
        w.close(&result);
    }
    w.open("ResponseMetadata");
    w.leaf("RequestId", request_id);
    w.close("ResponseMetadata");
    w.close(&response);
    w.finish()
}

pub fn error_body(info: &ServiceInfo, request_id: &str, error: &ServiceError) -> String {
    let mut w = XmlWriter::new();
    w.open_with_ns("ErrorResponse", info.xml_namespace);
    w.open("Error");
    w.leaf(
        "Type",
        match error.fault {
            ErrorFault::Client => "Sender",
            ErrorFault::Server => "Receiver",
        },
    );
    w.leaf("Code", &error.code);
    w.leaf("Message", &error.message);
    mws_xml::write_error_fields(&mut w, error);
    w.close("Error");
    w.leaf("RequestId", request_id);
    w.close("ErrorResponse");
    w.finish()
}

pub fn xml_response(status: u16, request_id: &str, body: String) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/xml")
        .header("x-amzn-RequestId", request_id)
        .body(Bytes::from(body))
        .expect("static response parts are valid")
}

pub fn error_response(info: &ServiceInfo, request_id: &str, error: &ServiceError) -> HttpResponse {
    xml_response(error.status, request_id, error_body(info, request_id, error))
}
