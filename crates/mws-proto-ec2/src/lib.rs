//! Runtime support for the `ec2Query` protocol.
//!
//! Requests are form-encoded like awsQuery, but keys come from
//! `ec2QueryName` and lists are always flattened (`Filter.1.Value.1`).
//! Responses are `<{Op}Response><requestId>..</requestId>members..` with no
//! `Result` wrapper, and errors are `<Response><Errors><Error>..`.
//! Generated service code (see `mws-codegen`) calls into this crate; it
//! knows nothing about any particular service.
//!
//! Spec: <https://smithy.io/2.0/aws/protocols/aws-ec2-query-protocol.html>

use bytes::Bytes;
use chrono::{DateTime, NaiveDateTime, Utc};
use mws_core::{HttpRequest, HttpResponse, ServiceError};

pub use mws_proto_query::Params;
pub use mws_xml::XmlWriter;

#[doc(hidden)]
pub mod __private {
    pub use async_trait::async_trait;
    pub use chrono;
}

/// Static facts about an ec2Query service, emitted by codegen.
#[derive(Debug, Clone, Copy)]
pub struct ServiceInfo {
    pub xml_namespace: &'static str,
    pub version: &'static str,
}

/// Request parameters from the query string and form body.
pub fn read_params(request: &HttpRequest) -> Params {
    mws_proto_query::read_params(request)
}

pub fn missing_action() -> ServiceError {
    ServiceError::client("MissingAction", 400, "The request must contain the parameter Action")
}

pub fn invalid_action(action: &str) -> ServiceError {
    ServiceError::client("InvalidAction", 400, format!("The action {action} is not valid for this web service."))
}

/// Decodes typed values out of [`Params`]. EC2 does not report Smithy
/// validation messages: the first problem becomes `MissingParameter` or
/// `InvalidParameterValue`, worded as EC2 words them.
#[derive(Debug)]
pub struct Decoder<'a> {
    pub params: &'a Params,
    error: Option<ServiceError>,
}

impl<'a> Decoder<'a> {
    pub fn new(params: &'a Params) -> Self {
        Self { params, error: None }
    }

    pub fn finish(self) -> Result<(), ServiceError> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn fail(&mut self, e: ServiceError) {
        if self.error.is_none() {
            self.error = Some(e);
        }
    }

    pub fn has_prefix(&self, key: &str) -> bool {
        self.params.has_prefix(key)
    }

    pub fn indexes(&self, prefix: &str) -> Vec<usize> {
        self.params.indexes(prefix)
    }

    pub fn required<T>(&mut self, value: &Option<T>, key: &str) {
        if value.is_none() {
            self.fail(ServiceError::client(
                "MissingParameter",
                400,
                format!("The request must contain the parameter {key}"),
            ));
        }
    }

    fn invalid(&mut self, key: &str, raw: &str) {
        self.fail(ServiceError::client("InvalidParameterValue", 400, format!("Invalid value '{raw}' for {key}")));
    }

    pub fn string(&mut self, key: &str) -> Option<String> {
        self.params.get(key).map(str::to_string)
    }

    pub fn boolean(&mut self, key: &str) -> Option<bool> {
        let raw = self.params.get(key)?;
        match raw.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => {
                self.invalid(key, raw);
                None
            }
        }
    }

    pub fn number<T: std::str::FromStr>(&mut self, key: &str) -> Option<T> {
        let raw = self.params.get(key)?;
        match raw.trim().parse::<T>() {
            Ok(v) => Some(v),
            Err(_) => {
                self.invalid(key, raw);
                None
            }
        }
    }

    pub fn timestamp(&mut self, key: &str) -> Option<DateTime<Utc>> {
        let raw = self.params.get(key)?;
        if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
            return Some(t.with_timezone(&Utc));
        }
        if let Ok(t) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
            return Some(t.and_utc());
        }
        if let Ok(secs) = raw.parse::<f64>() {
            if let Some(t) = DateTime::from_timestamp_millis((secs * 1000.0) as i64) {
                return Some(t);
            }
        }
        self.invalid(key, raw);
        None
    }

    pub fn blob(&mut self, key: &str) -> Option<Vec<u8>> {
        use base64::Engine;
        let raw = self.params.get(key)?;
        match base64::engine::general_purpose::STANDARD.decode(raw) {
            Ok(v) => Some(v),
            Err(_) => {
                self.invalid(key, raw);
                None
            }
        }
    }
}

/// The XML body of a successful response.
pub fn success_body(
    info: &ServiceInfo,
    operation: &str,
    request_id: &str,
    write_result: Option<&dyn Fn(&mut XmlWriter)>,
) -> String {
    let mut w = XmlWriter::new();
    let response = format!("{operation}Response");
    w.open_with_ns(&response, info.xml_namespace);
    w.leaf("requestId", request_id);
    if let Some(write) = write_result {
        write(&mut w);
    }
    w.close(&response);
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", w.finish())
}

/// `<Response><Errors><Error><Code>..</Code><Message>..</Message></Error></Errors><RequestID>..`.
pub fn error_body(request_id: &str, error: &ServiceError) -> String {
    let mut w = XmlWriter::new();
    w.open("Response");
    w.open("Errors");
    w.open("Error");
    w.leaf("Code", &error.code);
    w.leaf("Message", &error.message);
    mws_xml::write_error_fields(&mut w, error);
    w.close("Error");
    w.close("Errors");
    w.leaf("RequestID", request_id);
    w.close("Response");
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", w.finish())
}

pub fn xml_response(status: u16, request_id: &str, body: String) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/xml;charset=UTF-8")
        .header("x-amzn-RequestId", request_id)
        .body(Bytes::from(body))
        .expect("static response parts are valid")
}

pub fn error_response(request_id: &str, error: &ServiceError) -> HttpResponse {
    xml_response(error.status, request_id, error_body(request_id, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattened_lists_and_missing_parameters() {
        let mut p = Params::new();
        p.extend_from_urlencoded(b"Action=X&Filter.1.Name=a&Filter.1.Value.1=b&Filter.2.Name=c");
        let mut d = Decoder::new(&p);
        assert_eq!(d.indexes("Filter"), vec![1, 2]);
        d.required::<String>(&None, "ImageId");
        let e = d.finish().unwrap_err();
        assert_eq!(e.code, "MissingParameter");
        assert_eq!(e.message, "The request must contain the parameter ImageId");
    }

    #[test]
    fn errors_use_the_ec2_envelope() {
        let e = ServiceError::client("InvalidVpcID.NotFound", 400, "The vpc ID 'vpc-1' does not exist");
        let body = error_body("rid", &e);
        assert!(body.contains("<Response><Errors><Error><Code>InvalidVpcID.NotFound</Code>"));
        assert!(body.ends_with("<RequestID>rid</RequestID></Response>"));
    }
}
