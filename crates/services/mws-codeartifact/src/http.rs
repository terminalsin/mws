//! A minimal HTTP/1.1 client for external connections: one request per
//! connection, `http://` or `https://` (with the platform's trusted
//! roots), following redirects.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: usize = 256 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// GET `url`, following redirects.
pub async fn get(url: &str, headers: &[(&str, &str)]) -> Result<Response, String> {
    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let r = tokio::time::timeout(TIMEOUT, send(&url, headers))
            .await
            .map_err(|_| "the request timed out".to_string())??;
        if matches!(r.status, 301 | 302 | 303 | 307 | 308) {
            if let Some(loc) = r.header("location") {
                url = resolve(&url, loc);
                continue;
            }
        }
        return Ok(r);
    }
    Err(format!("too many redirects fetching {url}"))
}

fn resolve(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    let scheme_end = base.find("://").map_or(0, |i| i + 3);
    let host_end = base[scheme_end..].find('/').map_or(base.len(), |i| scheme_end + i);
    if location.starts_with('/') {
        format!("{}{location}", &base[..host_end])
    } else {
        let dir = base.rfind('/').filter(|i| *i >= host_end).map_or(base.len(), |i| i + 1);
        format!("{}{}{location}", &base[..dir], if dir == base.len() { "/" } else { "" })
    }
}

async fn send(url: &str, headers: &[(&str, &str)]) -> Result<Response, String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("{url} is not an HTTP URL"));
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (h, p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?),
        _ => (authority, default_port),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut head = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: mws-codeartifact\r\nAccept-Encoding: identity\r\n"
    );
    for (k, v) in headers {
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let tcp = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| format!("connecting to {host}: {e}"))?;
    let raw = if tls {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config()?));
        let name = rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let stream = connector.connect(name, tcp).await.map_err(|e| format!("TLS with {host}: {e}"))?;
        exchange(stream, head.as_bytes()).await?
    } else {
        exchange(tcp, head.as_bytes()).await?
    };
    parse(&raw)
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, request: &[u8]) -> Result<Vec<u8>, String> {
    s.write_all(request).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_RESPONSE || complete(&raw) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(raw)
}

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
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("malformed HTTP status line")?;
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    let body = &raw[split + 4..];
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());
    let body = if chunked { dechunk(body) } else { body[..len.unwrap_or(body.len()).min(body.len())].to_vec() };
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

#[cfg(test)]
mod tests {
    #[test]
    fn redirects_resolve() {
        assert_eq!(super::resolve("https://a.b/x/y", "/z"), "https://a.b/z");
        assert_eq!(super::resolve("https://a.b/x/y", "z"), "https://a.b/x/z");
        assert_eq!(super::resolve("https://a.b/x", "https://c.d/e"), "https://c.d/e");
    }
}
