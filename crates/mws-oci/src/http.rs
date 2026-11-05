//! A minimal HTTP/1.1 client: one request per connection, `http://` or
//! `https://` (with the platform's trusted roots).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(300);
/// Layers are held in memory; a local emulator caps them.
const MAX_RESPONSE: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
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
    let tcp = match proxy_for(host, tls) {
        Some(proxy) => tunnel(&proxy, host, port).await?,
        None => tokio::net::TcpStream::connect((host, port)).await.map_err(|e| format!("connecting to {host}: {e}"))?,
    };
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

/// The `HTTPS_PROXY` to reach `host` through, unless `NO_PROXY` exempts
/// it (plain HTTP goes direct).
fn proxy_for(host: &str, tls: bool) -> Option<String> {
    if !tls {
        return None;
    }
    let env = |k: &str| {
        std::env::var(k).ok().or_else(|| std::env::var(k.to_ascii_lowercase()).ok()).filter(|v| !v.is_empty())
    };
    let proxy = env("HTTPS_PROXY")?;
    let exempt = env("NO_PROXY").unwrap_or_default();
    let host = host.to_ascii_lowercase();
    let skip = exempt.split(',').map(|e| e.trim().trim_start_matches('*').to_ascii_lowercase()).any(|e| {
        !e.is_empty() && (e == host || (e.starts_with('.') && host.ends_with(&e)) || host.ends_with(&format!(".{e}")))
    });
    (!skip && host != "localhost" && !host.starts_with("127.")).then_some(proxy)
}

/// A TCP stream to `host:port` through an HTTP proxy's `CONNECT`.
async fn tunnel(proxy: &str, host: &str, port: u16) -> Result<tokio::net::TcpStream, String> {
    let authority = proxy.split_once("://").map(|(_, r)| r).unwrap_or(proxy).trim_end_matches('/');
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);
    let mut tcp = tokio::net::TcpStream::connect(authority)
        .await
        .map_err(|e| format!("connecting to the proxy {authority}: {e}"))?;
    let connect = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    tcp.write_all(connect.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tcp.read(&mut byte).await.map_err(|e| e.to_string())? == 0 || head.len() > 16 * 1024 {
            return Err("the proxy closed the connection".into());
        }
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head).split(' ').nth(1).unwrap_or("").to_string();
    if status != "200" {
        return Err(format!("the proxy refused to connect to {host}: {status}"));
    }
    Ok(tcp)
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
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Ok(Response { status, headers, body })
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
