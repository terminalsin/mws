//! Runtime support for the `restXml` protocol.
//!
//! Operations are routed by HTTP method and URI pattern. Input members are
//! bound to URI labels, query parameters, headers, or the XML body; output
//! members to headers, the status code, or the XML body. Generated service
//! code (see `mws-codegen`) calls into this crate; it knows nothing about any
//! particular service.
//!
//! Spec: <https://smithy.io/2.0/aws/protocols/aws-restxml-protocol.html>

mod decode;
pub use mws_core::eventstream;
mod route;

pub use decode::{attr, child, children, elements, prefix_headers, Decoder};
pub use mws_xml::{format_timestamp, roxmltree, XmlWriter};
pub use route::{hint_matches, match_uri, Labels, Query};

use bytes::Bytes;
use mws_core::{ErrorFault, HttpResponse, ServiceError};

/// Re-exports used by generated code, so service crates need not depend on
/// these directly.
#[doc(hidden)]
pub mod __private {
    pub use async_trait::async_trait;
    pub use chrono;
    pub use regex;
}

/// Static facts about a restXml service, emitted by codegen.
#[derive(Debug, Clone, Copy)]
pub struct ServiceInfo {
    pub xml_namespace: &'static str,
    /// Error code for constraint violations (Route 53: `InvalidInput`).
    pub validation_error: &'static str,
    /// Whether errors are wrapped in `<ErrorResponse>` (the restXml default)
    /// or written as a bare `<Error>` (`noErrorWrapping`).
    pub error_wrapping: bool,
    /// The response header that carries the request id.
    pub request_id_header: &'static str,
}

/// A response body.
#[derive(Debug, Clone)]
pub enum Body {
    None,
    /// An XML document (`text/xml`).
    Xml(String),
    /// A string payload (`text/plain` unless a header says otherwise).
    Text(String),
    /// A blob payload (`application/octet-stream` unless a header says
    /// otherwise).
    Raw(Bytes),
}

/// Parse a request body as XML. An empty body yields `None`.
pub fn parse_body(body: &[u8]) -> Result<Option<roxmltree::Document<'_>>, ServiceError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let text = std::str::from_utf8(body).map_err(|_| malformed())?;
    roxmltree::Document::parse(text).map(Some).map_err(|_| malformed())
}

fn malformed() -> ServiceError {
    ServiceError::client("MalformedXML", 400, "The XML you provided was not well-formed or did not validate.")
}

/// No operation matches the method and path.
pub fn unknown_operation(method: &str, path: &str) -> ServiceError {
    ServiceError::client("UnknownOperationException", 404, format!("No operation matches {method} {path}"))
}

/// A response with a body and extra headers. A `Content-Type` among
/// `headers` wins over the body's default.
pub fn response(
    info: &ServiceInfo,
    status: u16,
    request_id: &str,
    headers: Vec<(String, String)>,
    body: Body,
) -> HttpResponse {
    let mut b = http::Response::builder().status(status).header(info.request_id_header, request_id);
    let has_type = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    for (k, v) in headers {
        b = b.header(k, v);
    }
    let (default_type, body) = match body {
        Body::None => (None, Bytes::new()),
        Body::Xml(s) => (Some("text/xml"), Bytes::from(s)),
        Body::Text(s) => (Some("text/plain"), Bytes::from(s)),
        Body::Raw(b) => (Some("application/octet-stream"), b),
    };
    if let (Some(t), false) = (default_type, has_type) {
        b = b.header(http::header::CONTENT_TYPE, t);
    }
    b.body(body).unwrap_or_else(|_| {
        http::Response::builder().status(500).body(Bytes::new()).expect("static response parts are valid")
    })
}

/// `<ErrorResponse><Error><Type/><Code/><Message/>...</Error><RequestId/></ErrorResponse>`,
/// or with `noErrorWrapping`, `<Error><Code/><Message/>...<RequestId/></Error>`.
pub fn error_body(info: &ServiceInfo, request_id: &str, error: &ServiceError) -> String {
    let mut w = XmlWriter::new();
    if !info.error_wrapping {
        w.open("Error");
        w.leaf("Code", &error.code);
        w.leaf("Message", &error.message);
        mws_xml::write_error_fields(&mut w, error);
        w.leaf("RequestId", request_id);
        w.close("Error");
        return format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", w.finish());
    }
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

pub fn error_response(info: &ServiceInfo, request_id: &str, error: &ServiceError) -> HttpResponse {
    response(info, error.status, request_id, Vec::new(), Body::Xml(error_body(info, request_id, error)))
}
