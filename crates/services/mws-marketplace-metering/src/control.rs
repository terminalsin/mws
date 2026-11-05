//! What Metering accepted, served unsigned at `/_aws/marketplace-metering/`
//! so tests can check what a seller would be paid for:
//!
//! * `GET /_aws/marketplace-metering/records[?productCode=&customerAWSAccountId=&customerIdentifier=&dimension=]`
//! * `DELETE /_aws/marketplace-metering/records`: forget them
//! * `GET /_aws/marketplace-metering/registrations[?productCode=]`: RegisterUsage calls
//! * `GET /_aws/marketplace-metering/public-key`: the PEM key that verifies
//!   RegisterUsage signatures (public key version 1)

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse};
use serde_json::json;

use crate::Metering;

pub const PREFIX: &str = "/_aws/marketplace-metering/";

fn respond(status: u16, content_type: &str, body: String) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(Bytes::from(body))
        .expect("static response parts are valid")
}

fn query(request: &HttpRequest, name: &str) -> Option<String> {
    let q = request.uri().query()?;
    form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

impl Metering {
    pub(crate) fn serve_control(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let rest = request.uri().path().strip_prefix(PREFIX)?;
        let method = request.method().clone();
        let json_ok = |v: serde_json::Value| respond(200, "application/json", v.to_string());
        Some(match (method, rest.trim_end_matches('/')) {
            (http::Method::GET, "records") => {
                let product = query(request, "productCode");
                let account = query(request, "customerAWSAccountId");
                let customer = query(request, "customerIdentifier");
                let dimension = query(request, "dimension");
                let st = self.lock();
                let list: Vec<_> = st
                    .records
                    .iter()
                    .filter(|r| product.as_ref().is_none_or(|p| &r.product_code == p))
                    .filter(|r| account.as_ref().is_none_or(|a| &r.customer_aws_account_id == a))
                    .filter(|r| customer.as_ref().is_none_or(|c| r.customer_identifier.as_ref() == Some(c)))
                    .filter(|r| dimension.as_ref().is_none_or(|d| &r.dimension == d))
                    .collect();
                json_ok(json!({ "records": list }))
            }
            (http::Method::DELETE, "records") => {
                let mut st = self.lock();
                st.records.clear();
                st.client_tokens.clear();
                json_ok(json!({}))
            }
            (http::Method::GET, "registrations") => {
                let product = query(request, "productCode");
                let st = self.lock();
                let list: Vec<_> =
                    st.registrations.iter().filter(|r| product.as_ref().is_none_or(|p| &r.product_code == p)).collect();
                json_ok(json!({ "registrations": list }))
            }
            (http::Method::GET, "public-key") => match crate::signing::public_key_pem(&mut self.lock()) {
                Ok(pem) => respond(200, "application/x-pem-file", pem),
                Err(e) => respond(500, "application/json", json!({ "message": e.message }).to_string()),
            },
            _ => respond(404, "application/json", json!({ "message": "not found" }).to_string()),
        })
    }
}
