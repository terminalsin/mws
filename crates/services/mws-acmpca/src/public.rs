//! The unsigned OCSP responder.

use base64::Engine;
use bytes::Bytes;
use http::{Method, StatusCode};
use mws_core::{HttpRequest, HttpResponse};

use crate::revocation;
use crate::PrivateCa;

const OCSP_REQUEST: &str = "application/ocsp-request";
const OCSP_RESPONSE: &str = "application/ocsp-response";

fn response(status: StatusCode, content_type: &str, body: Vec<u8>, head: bool) -> HttpResponse {
    let len = body.len();
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, len)
        .body(if head { Bytes::new() } else { Bytes::from(body) })
        .expect("valid response")
}

fn is_ocsp_post(request: &HttpRequest) -> bool {
    request.method() == Method::POST
        && request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case(OCSP_REQUEST))
}

/// The DER OCSP request in a GET's last path segment (RFC 6960 A.1).
fn ocsp_get_body(request: &HttpRequest) -> Option<Vec<u8>> {
    if request.method() != Method::GET {
        return None;
    }
    let segment = request.uri().path().rsplit('/').next()?;
    if segment.is_empty() {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(segment).decode_utf8().ok()?;
    let der = base64::engine::general_purpose::STANDARD.decode(decoded.as_bytes()).ok()?;
    revocation::parse_request(&der).is_some().then_some(der)
}

impl PrivateCa {
    pub(crate) fn is_public_request(&self, request: &HttpRequest) -> bool {
        if is_ocsp_post(request) {
            return true;
        }
        ocsp_get_body(request).is_some()
    }

    pub(crate) fn public_response(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let der = if is_ocsp_post(request) { request.body().to_vec() } else { ocsp_get_body(request)? };
        Some(response(StatusCode::OK, OCSP_RESPONSE, self.ocsp(&der), false))
    }

    fn ocsp(&self, der: &[u8]) -> Vec<u8> {
        use revocation::status;
        let Some(req) = revocation::parse_request(der) else {
            return revocation::error_response(status::MALFORMED_REQUEST);
        };
        let st = self.lock();
        let first = &req.cert_ids[0];
        let issuer = st.cas.values().find_map(|ca| {
            let ids = revocation::issuer_ids(ca.cert_pem.as_deref()?)?;
            revocation::matches(first, &ids).then_some((ca, ids))
        });
        let Some((ca, ids)) = issuer else { return revocation::error_response(status::UNAUTHORIZED) };
        if revocation::ocsp_config(ca).is_none() || ca.status == "DELETED" {
            return revocation::error_response(status::UNAUTHORIZED);
        }
        revocation::respond(ca, &req, &ids).unwrap_or_else(|_| revocation::error_response(status::INTERNAL_ERROR))
    }
}
