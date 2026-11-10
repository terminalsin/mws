//! External key stores: KMS's client for the XKS Proxy API (v1). Requests
//! are SigV4-signed (service `kms-xks-proxy`) with the store's proxy
//! authentication credential and sent over HTTPS to the store's proxy
//! URI; keys in the store are double encrypted, first with KMS key
//! material and then by the proxy's external key.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::{digest, hmac};
use base64::Engine as _;
use chrono::Utc;
use serde_json::{json, Value};

const TIMEOUT: Duration = Duration::from_secs(3);
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// How MWS reaches XKS proxies. AWS requires `https://<host>` on port
/// 443; locally a proxy usually listens elsewhere with a private CA.
#[derive(Debug, Clone, Default)]
pub struct XksTransport {
    /// Connect to `address` (`host:port`) whenever a proxy URI names
    /// `host`, as `curl --connect-to` does.
    pub connect_to: BTreeMap<String, String>,
    /// Extra trusted root certificates (PEM), on top of the platform's.
    pub ca_pem: Option<String>,
}

/// One proxy, as a store's configuration names it.
#[derive(Debug, Clone)]
pub(crate) struct Proxy {
    pub endpoint: String,
    pub path: String,
    pub access_key_id: String,
    pub secret: String,
    pub region: String,
}

/// What the proxy (or reaching it) said.
#[derive(Debug, Clone)]
pub(crate) enum XksError {
    /// No answer: connection refused, TLS failure, timeout.
    Unreachable(String),
    TimedOut,
    InvalidTls(String),
    /// An XKS error (`errorName`, `errorMessage`) with its HTTP status.
    Proxy {
        status: u16,
        name: String,
        message: String,
    },
    /// An answer that isn't an XKS response.
    InvalidResponse(String),
}

impl XksError {
    /// The custom key store connection error code for this failure.
    pub fn connection_error_code(&self) -> &'static str {
        match self {
            XksError::Unreachable(_) => "XKS_PROXY_NOT_REACHABLE",
            XksError::TimedOut => "XKS_PROXY_TIMED_OUT",
            XksError::InvalidTls(_) => "XKS_PROXY_INVALID_TLS_CONFIGURATION",
            XksError::Proxy { name, .. } if name == "AuthenticationFailedException" => "INVALID_CREDENTIALS",
            XksError::Proxy { name, .. } if name == "AccessDeniedException" => "XKS_PROXY_ACCESS_DENIED",
            XksError::Proxy { status: 404, .. } => "XKS_PROXY_INVALID_CONFIGURATION",
            XksError::Proxy { .. } | XksError::InvalidResponse(_) => "XKS_PROXY_INVALID_RESPONSE",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            XksError::Unreachable(e) => format!("the external key store proxy is not reachable: {e}"),
            XksError::TimedOut => "the external key store proxy did not respond in time".into(),
            XksError::InvalidTls(e) => format!("the external key store proxy's TLS configuration is not valid: {e}"),
            XksError::Proxy { name, message, .. } => {
                format!("the external key store proxy rejected the request: {name}: {message}")
            }
            XksError::InvalidResponse(e) => format!("the external key store proxy's response is not valid: {e}"),
        }
    }
}

/// Who asks and why, for the request metadata the proxy logs and may
/// authorize on.
#[derive(Debug, Clone, Default)]
pub(crate) struct Meta {
    pub principal: String,
    pub operation: String,
    pub request_id: String,
    pub key_arn: Option<String>,
}

impl Meta {
    fn json(&self) -> Value {
        let mut m = json!({
            "awsPrincipalArn": self.principal,
            "kmsOperation": self.operation,
            "kmsRequestId": self.request_id,
        });
        if let Some(k) = &self.key_arn {
            m["kmsKeyArn"] = json!(k);
        }
        m
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_hex(b: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, b).as_ref())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data).as_ref().to_vec()
}

/// SigV4 headers for a POST of `body` to `path` on `host`.
fn sign(proxy: &Proxy, host: &str, path: &str, body: &[u8]) -> Vec<(String, String)> {
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let payload = sha256_hex(body);
    let signed = "content-type;host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "POST\n{path}\n\ncontent-type:application/json\nhost:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{amz_date}\n\n{signed}\n{payload}"
    );
    let scope = format!("{date}/{}/kms-xks-proxy/aws4_request", proxy.region);
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let mut k = hmac_sha256(format!("AWS4{}", proxy.secret).as_bytes(), date.as_bytes());
    for part in [proxy.region.as_str(), "kms-xks-proxy", "aws4_request"] {
        k = hmac_sha256(&k, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&k, to_sign.as_bytes()));
    vec![
        ("Content-Type".into(), "application/json".into()),
        ("X-Amz-Date".into(), amz_date),
        ("X-Amz-Content-Sha256".into(), payload),
        (
            "Authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
                proxy.access_key_id
            ),
        ),
    ]
}

fn tls_config(transport: &XksTransport) -> Result<Arc<rustls::ClientConfig>, XksError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(pem) = &transport.ca_pem {
        use rustls_pki_types::pem::PemObject;
        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()).filter_map(Result::ok) {
            let _ = roots.add(cert);
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| XksError::InvalidTls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn io_error(e: std::io::Error) -> XksError {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => XksError::TimedOut,
        std::io::ErrorKind::InvalidData => XksError::InvalidTls(e.to_string()),
        _ => XksError::Unreachable(e.to_string()),
    }
}

/// POST `body` to `{path}{rel}` on the proxy; the response JSON.
pub(crate) fn post(transport: &XksTransport, proxy: &Proxy, rel: &str, body: Value) -> Result<Value, XksError> {
    let host = proxy.endpoint.strip_prefix("https://").unwrap_or(&proxy.endpoint).to_string();
    let path = format!("{}{rel}", proxy.path);
    let body = body.to_string().into_bytes();
    let address = transport.connect_to.get(&host).cloned().unwrap_or_else(|| format!("{host}:443"));
    let addr = address
        .to_socket_addrs()
        .map_err(|e| XksError::Unreachable(format!("{address}: {e}")))?
        .next()
        .ok_or_else(|| XksError::Unreachable(format!("{address} has no address")))?;
    let tcp = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(io_error)?;
    tcp.set_read_timeout(Some(TIMEOUT)).map_err(io_error)?;
    tcp.set_write_timeout(Some(TIMEOUT)).map_err(io_error)?;
    let name = rustls_pki_types::ServerName::try_from(host.clone())
        .map_err(|e| XksError::InvalidTls(format!("{host}: {e}")))?;
    let conn =
        rustls::ClientConnection::new(tls_config(transport)?, name).map_err(|e| XksError::InvalidTls(e.to_string()))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut head =
        format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in sign(proxy, &host, &path, &body) {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    tls.write_all(head.as_bytes()).map_err(io_error)?;
    tls.write_all(&body).map_err(io_error)?;
    tls.flush().map_err(io_error)?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if complete(&raw) {
                    break;
                }
            }
            // Proxies that close without close_notify.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(io_error(e)),
        }
        if raw.len() > 1024 * 1024 {
            return Err(XksError::InvalidResponse("the response is too large".into()));
        }
    }
    let (status, body) = parse(&raw).ok_or_else(|| XksError::InvalidResponse("not an HTTP response".into()))?;
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(XksError::Proxy {
            status,
            name: v["errorName"].as_str().unwrap_or("UnknownError").into(),
            message: v["errorMessage"].as_str().unwrap_or_default().into(),
        });
    }
    if !v.is_object() {
        return Err(XksError::InvalidResponse("the body is not a JSON object".into()));
    }
    Ok(v)
}

fn split(raw: &[u8]) -> Option<(usize, &[u8])> {
    let i = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((i, &raw[i + 4..]))
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse().ok())?
    })
}

fn complete(raw: &[u8]) -> bool {
    let Some((i, body)) = split(raw) else { return false };
    let head = String::from_utf8_lossy(&raw[..i]);
    content_length(&head).is_some_and(|n| body.len() >= n)
}

fn parse(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
    let (i, body) = split(raw)?;
    let head = String::from_utf8_lossy(&raw[..i]).to_string();
    let status = head.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
    let body = match content_length(&head) {
        Some(n) => body.get(..n)?.to_vec(),
        None if head.to_ascii_lowercase().contains("transfer-encoding: chunked") => dechunk(body),
        None => body.to_vec(),
    };
    Some((status, body))
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(i) = data.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(String::from_utf8_lossy(&data[..i]).trim(), 16).unwrap_or(0);
        if size == 0 || data.len() < i + 2 + size {
            break;
        }
        out.extend_from_slice(&data[i + 2..i + 2 + size]);
        data = &data[(i + 4 + size).min(data.len())..];
    }
    out
}

/// `GetHealthStatus`: whether the proxy answers and has an active key
/// manager.
pub(crate) fn health(transport: &XksTransport, proxy: &Proxy, meta: &Meta) -> Result<(), XksError> {
    let v = post(transport, proxy, "/health", json!({ "requestMetadata": meta.json() }))?;
    let fleet = v["ekmFleetDetails"].as_array().cloned().unwrap_or_default();
    if fleet.is_empty() {
        return Err(XksError::InvalidResponse("ekmFleetDetails is missing".into()));
    }
    if !fleet.iter().any(|f| matches!(f["healthStatus"].as_str(), Some("ACTIVE" | "DEGRADED"))) {
        return Err(XksError::InvalidResponse("no external key manager is active".into()));
    }
    Ok(())
}

/// `GetKeyMetadata`: the external key's spec, usages and status.
pub(crate) fn key_metadata(transport: &XksTransport, proxy: &Proxy, key: &str, meta: &Meta) -> Result<Value, XksError> {
    post(transport, proxy, &format!("/keys/{key}/metadata"), json!({ "requestMetadata": meta.json() }))
}

/// The outer layer of a double-encrypted ciphertext.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Outer {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
}

const OUTER_MAGIC: &[u8] = b"XKS1";

impl Outer {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = OUTER_MAGIC.to_vec();
        for part in [&self.iv, &self.tag, self.metadata.as_ref().unwrap_or(&Vec::new()), &self.ciphertext] {
            out.extend((part.len() as u32).to_be_bytes());
            out.extend(part);
        }
        out
    }

    pub fn decode(mut b: &[u8]) -> Option<Self> {
        b = b.strip_prefix(OUTER_MAGIC)?;
        let mut parts = Vec::new();
        for _ in 0..4 {
            let len = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
            parts.push(b.get(4..4 + len)?.to_vec());
            b = &b[4 + len..];
        }
        let ciphertext = parts.pop()?;
        let metadata = parts.pop().filter(|m| !m.is_empty());
        let tag = parts.pop()?;
        let iv = parts.pop()?;
        Some(Self { ciphertext, iv, tag, metadata })
    }
}

/// `Encrypt` with the external key: the outer layer over `plaintext`
/// (the KMS-encrypted inner ciphertext), bound to `aad`.
pub(crate) fn encrypt(
    transport: &XksTransport,
    proxy: &Proxy,
    key: &str,
    meta: &Meta,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Outer, XksError> {
    let v = post(
        transport,
        proxy,
        &format!("/keys/{key}/encrypt"),
        json!({
            "requestMetadata": meta.json(),
            "plaintext": B64.encode(plaintext),
            "encryptionAlgorithm": "AES_GCM",
            "additionalAuthenticatedData": B64.encode(aad),
        }),
    )?;
    let field = |k: &str| -> Result<Vec<u8>, XksError> {
        v[k].as_str()
            .and_then(|s| B64.decode(s).ok())
            .ok_or_else(|| XksError::InvalidResponse(format!("{k} is missing")))
    };
    Ok(Outer {
        ciphertext: field("ciphertext")?,
        iv: field("initializationVector")?,
        tag: field("authenticationTag")?,
        metadata: v["ciphertextMetadata"].as_str().and_then(|s| B64.decode(s).ok()),
    })
}

/// `Decrypt` with the external key: the inner ciphertext.
pub(crate) fn decrypt(
    transport: &XksTransport,
    proxy: &Proxy,
    key: &str,
    meta: &Meta,
    outer: &Outer,
    aad: &[u8],
) -> Result<Vec<u8>, XksError> {
    let mut body = json!({
        "requestMetadata": meta.json(),
        "ciphertext": B64.encode(&outer.ciphertext),
        "encryptionAlgorithm": "AES_GCM",
        "initializationVector": B64.encode(&outer.iv),
        "authenticationTag": B64.encode(&outer.tag),
        "additionalAuthenticatedData": B64.encode(aad),
    });
    if let Some(m) = &outer.metadata {
        body["ciphertextMetadata"] = json!(B64.encode(m));
    }
    let v = post(transport, proxy, &format!("/keys/{key}/decrypt"), body)?;
    v["plaintext"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .ok_or_else(|| XksError::InvalidResponse("plaintext is missing".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_layers_round_trip() {
        let o = Outer { ciphertext: vec![1, 2, 3], iv: vec![4; 12], tag: vec![5; 16], metadata: Some(vec![9]) };
        assert_eq!(Outer::decode(&o.encode()), Some(o));
        let o = Outer { metadata: None, ..Default::default() };
        assert_eq!(Outer::decode(&o.encode()), Some(o));
    }

    #[test]
    fn responses_parse() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert!(complete(raw));
        assert_eq!(parse(raw), Some((200, b"{}".to_vec())));
        let raw = b"HTTP/1.1 400 Bad\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(parse(raw), Some((400, b"{}".to_vec())));
    }
}
