//! The SCEP (RFC 8894) endpoint of each connector:
//! `GET|POST /_aws/pca-connector-scep/<id>[/pkiclient.exe]?operation=...`.

use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Duration};
use http::{Method, StatusCode};
use mws_acmpca::{ServiceIssue, ServiceIssueError};
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use x509_parser::prelude::*;

use crate::cms::{self, CmsError, PkiMessage, Reply};
use crate::state::Connector;
use crate::{ScepConnector, SERVICE_PRINCIPAL};

pub const PATH_PREFIX: &str = "/_aws/pca-connector-scep/";

const CA_CAPS: &str = "AES\nPOSTPKIOperation\nSCEPStandard\nSHA-1\nSHA-256\nSHA-512\n";
const PKI_MESSAGE: &str = "application/x-pki-message";
/// SCEP message types.
const PKCS_REQ: &str = "19";
const GET_CERT_INITIAL: &str = "20";
/// failInfo values.
const BAD_REQUEST: u8 = 2;
const BAD_CERT_ID: u8 = 4;

pub fn is_scep_path(path: &str) -> bool {
    path.starts_with(PATH_PREFIX)
}

fn response(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> HttpResponse {
    let body = body.into();
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(body)
        .expect("valid response")
}

/// An error as AWS's SCEP endpoint reports it: a JSON body naming the
/// exception.
fn error(status: StatusCode, code: &str, message: impl Into<String>) -> HttpResponse {
    let body = serde_json::json!({ "__type": code, "message": message.into() }).to_string();
    let mut r = response(status, "application/json", body);
    if let Ok(v) = http::HeaderValue::from_str(code) {
        r.headers_mut().insert("x-amzn-errortype", v);
    }
    r
}

fn validation(message: impl Into<String>) -> HttpResponse {
    error(StatusCode::BAD_REQUEST, "ValidationException", message)
}

/// A `CertRep` failure, sent with HTTP 400 as AWS does for request errors
/// it can still answer in SCEP.
fn failure_rep(c: &Connector, req: &PkiMessage, info: u8, now: DateTime<chrono::Utc>) -> HttpResponse {
    match cms::cert_rep(req, &Reply::Failure(info), &c.ra_key, &c.ra_cert, now) {
        Ok(body) => response(StatusCode::BAD_REQUEST, PKI_MESSAGE, body),
        Err(e) => validation(e.message()),
    }
}

fn query_param(request: &HttpRequest, name: &str) -> Option<String> {
    let q = request.uri().query()?;
    form_pairs(q).into_iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

fn form_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let dec =
                |s: &str| percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned();
            (dec(k), dec(v))
        })
        .collect()
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> =
        b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).expect("base64 is ASCII")).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

impl ScepConnector {
    pub(crate) fn serve_scep(&self, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
        let path = request.uri().path();
        let id = path[PATH_PREFIX.len()..].split('/').next().unwrap_or_default();
        let connector = self.lock().connectors.values().find(|c| c.id == id).cloned();
        let Some(connector) = connector else {
            let url = format!("{}{path}", ctx.endpoint.clone().unwrap_or_default());
            return error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("A connector with endpoint {url} doesn't exist."),
            );
        };
        let Some(operation) = query_param(request, "operation") else {
            return validation("The request URI is invalid.");
        };
        if connector.status != "ACTIVE" {
            return validation("The connector is not active.");
        }
        let Some(ca) = self.pca.ca_info(&connector.ca_arn) else {
            return error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                "The certificate authority does not exist.",
            );
        };
        if ca.status != "ACTIVE" {
            return validation("The certificate authority is not active.");
        }
        match operation.as_str() {
            "GetCACaps" => response(StatusCode::OK, "text/plain", CA_CAPS),
            "GetCACert" => {
                // The RA certificate first, then the CA and its chain.
                let mut certs = vec![connector.ra_cert.clone()];
                for p in [ca.certificate_pem.as_deref(), ca.chain_pem.as_deref()].into_iter().flatten() {
                    for pem in Pem::iter_from_buffer(p.as_bytes()).flatten() {
                        certs.push(pem.contents);
                    }
                }
                response(StatusCode::OK, "application/x-x509-ca-ra-cert", cms::certs_only(&certs))
            }
            "PKIOperation" => {
                let raw = if request.method() == Method::POST {
                    request.body().to_vec()
                } else {
                    let Some(message) = query_param(request, "message") else {
                        return validation("The request URI is invalid.");
                    };
                    match base64::engine::general_purpose::STANDARD.decode(message.trim()) {
                        Ok(b) => b,
                        Err(_) => return validation("The request must contain base64."),
                    }
                };
                self.pki_operation(ctx, &connector, &raw)
            }
            _ => validation("The request URI is invalid."),
        }
    }

    fn pki_operation(&self, ctx: &RequestContext, connector: &Connector, raw: &[u8]) -> HttpResponse {
        let now = ctx.received_at;
        let req = match cms::read_pki_message(raw, now) {
            Ok(r) => r,
            Err(e) => return validation(e.message()),
        };
        match req.message_type.as_str() {
            PKCS_REQ => self.enroll(ctx, connector, &req),
            GET_CERT_INITIAL => {
                let issued =
                    self.lock().connectors.get(&connector.arn).and_then(|c| c.issued.get(&req.transaction_id).cloned());
                match issued {
                    Some(cert) => self.success(connector, &req, cert, now),
                    None => failure_rep(connector, &req, BAD_CERT_ID, now),
                }
            }
            other => error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                format!("Unsupported PkiOperation messageType: {other}."),
            ),
        }
    }

    fn success(
        &self,
        connector: &Connector,
        req: &PkiMessage,
        cert: Vec<u8>,
        now: DateTime<chrono::Utc>,
    ) -> HttpResponse {
        let built = cms::envelope_for(&cms::certs_only(&[cert]), &req.signer_cert, &self.content_alg(connector, req))
            .and_then(|env| cms::cert_rep(req, &Reply::Success(env), &connector.ra_key, &connector.ra_cert, now));
        match built {
            Ok(body) => response(StatusCode::OK, PKI_MESSAGE, body),
            Err(e) => validation(e.message()),
        }
    }

    /// Reply with the cipher the request used.
    fn content_alg(&self, connector: &Connector, req: &PkiMessage) -> String {
        cms::open_envelope(&req.envelope, &connector.ra_key).map(|(_, alg)| alg).unwrap_or_default()
    }

    fn enroll(&self, ctx: &RequestContext, connector: &Connector, req: &PkiMessage) -> HttpResponse {
        let now = ctx.received_at;
        let csr_der = match cms::open_envelope(&req.envelope, &connector.ra_key) {
            Ok((plain, _)) => plain,
            Err(e @ CmsError::UnsupportedAlgorithm(_)) => return validation(e.message()),
            Err(e) => return validation(e.message()),
        };
        let Ok((_, csr)) = X509CertificationRequest::from_der(&csr_der) else {
            return validation(CmsError::Undecodable.message());
        };
        let passwords: Vec<String> = csr
            .certification_request_info
            .iter_attributes()
            .filter_map(|a| match a.parsed_attribute() {
                ParsedCriAttribute::ChallengePassword(p) => Some(p.0.clone()),
                _ => None,
            })
            .collect();
        if connector.ty == "INTUNE" {
            // Intune connectors validate requests with Microsoft Intune,
            // which MWS can't reach.
            return error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "The connector does not have access to Azure.",
            );
        }
        if passwords.len() != 1 {
            return error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Exactly one challenge password is required in the certificate signing request.",
            );
        }
        let valid =
            self.lock().challenges.values().any(|c| c.connector_arn == connector.arn && c.password == passwords[0]);
        if !valid {
            let mut r = failure_rep(connector, req, BAD_REQUEST, now);
            r.headers_mut().insert("x-amzn-errortype", http::HeaderValue::from_static("BadRequestException"));
            return r;
        }
        let key_ok = match csr.certification_request_info.subject_pki.parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(k)) => k.key_size() <= 16384,
            Ok(x509_parser::public_key::PublicKey::EC(p)) => p.key_size() <= 521,
            _ => false,
        };
        if !key_ok {
            return error(StatusCode::BAD_REQUEST, "BadRequestException", "Key algorithm or length is not supported.");
        }
        // Without an extended key usage, AWS adds client authentication.
        let has_eku = csr
            .requested_extensions()
            .is_some_and(|mut e| e.any(|x| matches!(x, ParsedExtension::ExtendedKeyUsage(_))));
        let passthrough = (!has_eku).then(|| mws_acmpca::ApiPassthrough {
            extensions: Some(mws_acmpca::generated::types::Extensions {
                extended_key_usage: Some(vec![mws_acmpca::generated::types::ExtendedKeyUsage {
                    extended_key_usage_type: Some("CLIENT_AUTH".into()),
                    extended_key_usage_object_identifier: None,
                }]),
                ..Default::default()
            }),
            ..Default::default()
        });
        let ca_end = self.pca.ca_info(&connector.ca_arn).and_then(|c| c.not_after);
        let mut not_after = now + Duration::days(365);
        if let Some(end) = ca_end {
            not_after = not_after.min(end);
        }
        let template = crate::ops::TEMPLATE.replace("arn:aws:", &format!("arn:{}:", ctx.partition));
        let issued = self.pca.issue_as_service(ServiceIssue {
            service_principal: SERVICE_PRINCIPAL,
            source_account: &connector.owner,
            source_arn: &connector.arn,
            ca_arn: &connector.ca_arn,
            csr: pem("CERTIFICATE REQUEST", &csr_der).as_bytes(),
            template_arn: &template,
            not_after,
            api_passthrough: passthrough,
            now,
        });
        let cert = match issued {
            Ok(i) => match x509_parser::pem::parse_x509_pem(i.certificate_pem.as_bytes()) {
                Ok((_, p)) => p.contents,
                Err(_) => {
                    return error(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerException", "Issuance failed.")
                }
            },
            Err(ServiceIssueError::AccessDenied) => {
                return error(
                    StatusCode::UNAUTHORIZED,
                    "AccessDeniedException",
                    "The connector does not have access to the certificate authority.",
                )
            }
            Err(ServiceIssueError::NotFound) => {
                return error(
                    StatusCode::NOT_FOUND,
                    "ResourceNotFoundException",
                    "The certificate authority does not exist.",
                )
            }
            Err(ServiceIssueError::Refused(e)) => return validation(e.message),
        };
        if let Some(c) = self.lock().connectors.get_mut(&connector.arn) {
            c.issued.insert(req.transaction_id.clone(), cert.clone());
        }
        self.success(connector, req, cert, now)
    }
}
