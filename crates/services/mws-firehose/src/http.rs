//! A minimal HTTP/1.1 client for HTTP endpoint, Splunk and OpenSearch
//! destinations: one request per connection, `http://` or `https://` (with
//! the platform's trusted roots).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

pub async fn send(req: Request<'_>) -> Result<Response, String> {
    tokio::time::timeout(TIMEOUT, send_inner(req)).await.map_err(|_| "the request timed out".to_string())?
}

async fn send_inner(req: Request<'_>) -> Result<Response, String> {
    let (tls, rest) = if let Some(r) = req.url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = req.url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("{} is not an HTTP URL", req.url));
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (h, p.parse::<u16>().map_err(|_| format!("bad port in {}", req.url))?),
        _ => (authority, default_port),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut head = format!("{} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n", req.method);
    for (k, v) in &req.headers {
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    let body = req.body.unwrap_or_default();
    if !body.is_empty() || matches!(req.method, "POST" | "PUT" | "PATCH") {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&body);
    let tcp = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| format!("connecting to {host}: {e}"))?;
    let raw = if tls {
        let config = tls_config()?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let stream = connector.connect(name, tcp).await.map_err(|e| format!("TLS with {host}: {e}"))?;
        exchange(stream, &bytes).await?
    } else {
        exchange(tcp, &bytes).await?
    };
    parse(&raw)
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, request: &[u8]) -> Result<Vec<u8>, String> {
    s.write_all(request).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_RESPONSE {
                    break;
                }
                if complete(&raw) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(raw)
}

/// Whether a response with `Content-Length` has fully arrived (servers
/// may keep the connection open despite `Connection: close`).
fn complete(raw: &[u8]) -> bool {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let len = head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()));
    match len {
        Some(n) => raw.len() >= split + 4 + n,
        None => {
            head.lines().any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"))
                && raw.ends_with(b"0\r\n\r\n")
        }
    }
}

fn parse(raw: &[u8]) -> Result<Response, String> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head.split(' ').nth(1).and_then(|s| s.parse().ok()).ok_or("malformed HTTP status line")?;
    let body = &raw[split + 4..];
    let lower = head.to_ascii_lowercase();
    let chunked = lower.lines().any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
    let len =
        lower.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()));
    let body = if chunked { dechunk(body) } else { body[..len.unwrap_or(body.len()).min(body.len())].to_vec() };
    Ok(Response { status, body })
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(end) = data.windows(2).position(|w| w == b"\r\n") {
        let size = std::str::from_utf8(&data[..end])
            .ok()
            .and_then(|s| usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16).ok())
            .unwrap_or(0);
        if size == 0 || data.len() < end + 2 + size {
            break;
        }
        out.extend_from_slice(&data[end + 2..end + 2 + size]);
        data = &data[(end + 4 + size).min(data.len())..];
    }
    out
}

fn tls_config() -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth())
}
