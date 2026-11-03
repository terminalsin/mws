//! A minimal HTTP/1.1 client for HTTP/HTTPS subscriptions.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How long SNS waits for an endpoint to answer.
const TIMEOUT: Duration = Duration::from_secs(15);

/// POST `body` to `url`, returning the response status.
pub async fn post(url: &str, headers: &[(String, String)], content_type: &str, body: &[u8]) -> Result<u16, String> {
    tokio::time::timeout(TIMEOUT, post_inner(url, headers, content_type, body))
        .await
        .map_err(|_| format!("timed out posting to {url}"))?
}

async fn post_inner(url: &str, headers: &[(String, String)], content_type: &str, body: &[u8]) -> Result<u16, String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("{url} is not an HTTP URL"));
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest[i..].starts_with('/') => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    // Drop any userinfo.
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (h, p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?),
        _ => (host_port, if tls { 443 } else { 80 }),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nUser-Agent: Amazon Simple Notification Service Agent\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    let tcp = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| format!("connecting to {host}: {e}"))?;
    if tls {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config()?));
        let name = rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let stream = connector.connect(name, tcp).await.map_err(|e| format!("TLS with {host}: {e}"))?;
        exchange(stream, request.as_bytes(), body).await
    } else {
        exchange(tcp, request.as_bytes(), body).await
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, head: &[u8], body: &[u8]) -> Result<u16, String> {
    s.write_all(head).await.map_err(|e| e.to_string())?;
    s.write_all(body).await.map_err(|e| e.to_string())?;
    s.flush().await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    let line = String::from_utf8_lossy(&raw);
    line.split(' ').nth(1).and_then(|s| s.parse().ok()).ok_or_else(|| "malformed HTTP response".to_string())
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
