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
mod route;

pub use decode::{child, children, elements, Decoder};
pub use mws_xml::{format_timestamp, roxmltree, XmlWriter};
pub use route::{match_uri, Labels, Query};

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

/// A response with optional XML body and extra headers.
pub fn response(
    status: u16,
    request_id: &str,
    headers: Vec<(&'static str, String)>,
    body: Option<String>,
) -> HttpResponse {
    let mut b = http::Response::builder().status(status).header("x-amzn-RequestId", request_id);
    for (k, v) in headers {
        b = b.header(k, v);
    }
    let body = match body {
        Some(body) => {
            b = b.header(http::header::CONTENT_TYPE, "text/xml");
            Bytes::from(body)
        }
        None => Bytes::new(),
    };
    b.body(body).unwrap_or_else(|_| {
        http::Response::builder().status(500).body(Bytes::new()).expect("static response parts are valid")
    })
}

/// `<ErrorResponse><Error><Type/><Code/><Message/>...</Error><RequestId/></ErrorResponse>`
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

pub fn error_response(info: &ServiceInfo, request_id: &str, error: &ServiceError) -> HttpResponse {
    response(error.status, request_id, Vec::new(), Some(error_body(info, request_id, error)))
}
