//! Unsigned HTTP endpoints: CRL and audit report downloads, and OCSP.

use base64::Engine;
use bytes::Bytes;
use http::{Method, StatusCode};
use mws_core::{HttpRequest, HttpResponse};

use crate::revocation::{self, ca_id};
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

enum Download {
    Crl(String),
    AuditReport { ca_id: String, report_id: String },
}

fn download(path: &str) -> Option<Download> {
    let mut parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let file = parts.pop()?;
    if let Some(id) = file.strip_suffix(".crl") {
        return Some(Download::Crl(id.to_string()));
    }
    let report_id = file.strip_suffix(".json").or_else(|| file.strip_suffix(".csv"))?;
    let ca = parts.pop()?;
    (parts.pop()? == "audit-report")
        .then(|| Download::AuditReport { ca_id: ca.to_string(), report_id: report_id.to_string() })
}

impl PrivateCa {
    pub(crate) fn is_public_request(&self, request: &HttpRequest) -> bool {
        if is_ocsp_post(request) {
            return true;
        }
        if matches!(*request.method(), Method::GET | Method::HEAD) {
            let st = self.lock();
            let known = |id: &str| st.cas.keys().any(|arn| ca_id(arn) == id);
            match download(request.uri().path()) {
                Some(Download::Crl(id)) if known(&id) => return true,
                Some(Download::AuditReport { ca_id, .. }) if known(&ca_id) => return true,
                _ => {}
            }
        }
        ocsp_get_body(request).is_some()
    }

    pub(crate) fn public_response(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let head = request.method() == Method::HEAD;
        if matches!(*request.method(), Method::GET | Method::HEAD) {
            if let Some(d) = download(request.uri().path()) {
                let mut st = self.lock();
                let found = match &d {
                    Download::Crl(id) => st.cas.iter_mut().find(|(arn, _)| ca_id(arn) == id).map(|(_, ca)| {
                        // ACM PCA reissues a CRL before the current one lapses.
                        if ca.crl.as_ref().is_some_and(|c| c.next_update <= chrono::Utc::now()) {
                            let _ = revocation::refresh_crl(ca);
                        }
                        ca.crl.as_ref().map(|c| (c.der.clone(), "application/pkix-crl"))
                    }),
                    Download::AuditReport { ca_id: id, report_id } => {
                        st.cas.iter().find(|(arn, _)| ca_id(arn) == id).map(|(_, ca)| {
                            ca.audit_reports.get(report_id).map(|r| (r.body.clone(), r.content_type.as_str()))
                        })
                    }
                };
                match found {
                    Some(Some((body, ct))) => return Some(response(StatusCode::OK, ct, body, head)),
                    Some(None) => {
                        return Some(response(StatusCode::NOT_FOUND, "text/plain", b"Not Found".to_vec(), head))
                    }
                    None => {}
                }
            }
        }
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
