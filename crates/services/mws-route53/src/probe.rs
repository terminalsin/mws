//! Health checkers. Endpoint health checks (HTTP, HTTPS, the string
//! matching variants and TCP) are probed for real, from the first second
//! and then every `RequestInterval` seconds, with Route 53's timeouts; a
//! check turns unhealthy after `FailureThreshold` consecutive failures and
//! healthy again after as many successes. Calculated checks follow their
//! children. DNS answers and `GetHealthCheckStatus` read the result.
//!
//! MWS probes from one place, so every checker region reports the same
//! observation. CloudWatch alarm and Application Recovery Controller checks
//! report their `InsufficientDataHealthStatus` (healthy by default).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::generated::types;
use crate::Route53;

/// What one probe saw.
#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub success: bool,
    pub report: String,
    pub at: DateTime<Utc>,
}

/// The running state of one health check.
#[derive(Debug, Clone)]
pub(crate) struct Run {
    /// Healthy before `Inverted` and `Disabled` apply.
    pub healthy: bool,
    successes: u32,
    failures: u32,
    pub last: Option<Observation>,
    pub last_failure: Option<Observation>,
    next_due: Instant,
    in_flight: bool,
    /// The configuration version this run was started for.
    version: i64,
}

impl Run {
    fn new(version: i64) -> Self {
        // Route 53 considers a new health check healthy until checkers
        // report otherwise.
        Run {
            healthy: true,
            successes: 0,
            failures: 0,
            last: None,
            last_failure: None,
            next_due: Instant::now(),
            in_flight: false,
            version,
        }
    }
}

/// Health check runs by health check id.
pub(crate) type Runs = HashMap<String, Run>;

const FIREWALL: &str = "The endpoint or the internet connection is down, or requests are being blocked by your firewall. See https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-router-firewall-rules.html";

pub(crate) fn is_endpoint(ty: &str) -> bool {
    matches!(ty, "HTTP" | "HTTPS" | "HTTP_STR_MATCH" | "HTTPS_STR_MATCH" | "TCP")
}

impl Route53 {
    /// Start the checkers once, on the current Tokio runtime. Called when a
    /// health check is created or state is loaded; without a runtime the
    /// checks keep their initial status.
    pub(crate) fn ensure_prober(&self) {
        if self.prober_started.load(Ordering::Relaxed) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        if self.prober_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let weak = Arc::downgrade(&self.state);
        let this = self.clone();
        handle.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tick.tick().await;
                // Stop once every handle to this Route 53 is gone.
                if weak.strong_count() <= 1 {
                    return;
                }
                this.probe_due();
            }
        });
    }

    /// Start a probe for every endpoint check that is due.
    fn probe_due(&self) {
        let checks: Vec<(String, types::HealthCheck)> = {
            let all = self.lock_all();
            all.accounts
                .values()
                .flat_map(|s| s.health_checks.iter().map(|(id, h)| (id.clone(), h.check.clone())))
                .collect()
        };
        let now = Instant::now();
        let mut due = Vec::new();
        {
            let mut runs = self.health.lock().expect("health runs lock");
            runs.retain(|id, _| checks.iter().any(|(c, _)| c == id));
            for (id, check) in &checks {
                let run = runs.entry(id.clone()).or_insert_with(|| Run::new(check.health_check_version));
                if run.version != check.health_check_version {
                    // An update starts the checkers over.
                    run.version = check.health_check_version;
                    run.next_due = now;
                }
                let config = &check.health_check_config;
                if !is_endpoint(&config.r#type) || run.in_flight || run.next_due > now {
                    continue;
                }
                run.in_flight = true;
                let interval = config.request_interval.unwrap_or(30).max(1) as u64;
                run.next_due = now + Duration::from_secs(interval);
                due.push((id.clone(), config.clone()));
            }
        }
        for (id, config) in due {
            let this = self.clone();
            tokio::spawn(async move {
                let observation = probe(&config).await;
                this.record(&id, &config, observation);
            });
        }
    }

    fn record(&self, id: &str, config: &types::HealthCheckConfig, observation: Observation) {
        let threshold = config.failure_threshold.unwrap_or(3).max(1) as u32;
        let mut runs = self.health.lock().expect("health runs lock");
        let Some(run) = runs.get_mut(id) else { return };
        run.in_flight = false;
        if observation.success {
            run.successes += 1;
            run.failures = 0;
            if !run.healthy && run.successes >= threshold {
                run.healthy = true;
            }
        } else {
            run.failures += 1;
            run.successes = 0;
            if run.healthy && run.failures >= threshold {
                run.healthy = false;
            }
            run.last_failure = Some(observation.clone());
        }
        run.last = Some(observation);
    }

    /// The last observation and last failure of health check `id`.
    pub(crate) fn observations(&self, id: &str) -> (Option<Observation>, Option<Observation>) {
        let runs = self.health.lock().expect("health runs lock");
        runs.get(id).map(|r| (r.last.clone(), r.last_failure.clone())).unwrap_or_default()
    }

    /// Whether health check `id` is healthy, as DNS answers see it: after
    /// `Inverted` and `Disabled`, and for calculated checks from their
    /// children. Unknown ids count as healthy.
    pub(crate) fn is_healthy(&self, checks: &HashMap<String, types::HealthCheckConfig>, id: &str) -> bool {
        let runs = self.health.lock().expect("health runs lock");
        healthy_in(&runs, checks, id, 0)
    }
}

fn healthy_in(runs: &Runs, checks: &HashMap<String, types::HealthCheckConfig>, id: &str, depth: usize) -> bool {
    let Some(config) = checks.get(id) else { return true };
    if config.disabled == Some(true) {
        // Route 53 considers disabled health checks healthy.
        return true;
    }
    let raw = match config.r#type.as_str() {
        "CALCULATED" if depth < 4 => {
            let children = config.child_health_checks.clone().unwrap_or_default();
            let healthy = children.iter().filter(|c| healthy_in(runs, checks, c, depth + 1)).count();
            let threshold = config.health_threshold.unwrap_or(children.len() as i32).max(0) as usize;
            healthy >= threshold
        }
        "CLOUDWATCH_METRIC" => config.insufficient_data_health_status.as_deref() != Some("Unhealthy"),
        t if is_endpoint(t) => runs.get(id).is_none_or(|r| r.healthy),
        _ => true,
    };
    raw != config.inverted.unwrap_or(false)
}

/// Probe one endpoint the way a Route 53 health checker does.
async fn probe(config: &types::HealthCheckConfig) -> Observation {
    let (success, report) = probe_inner(config).await;
    Observation { success, report, at: Utc::now() }
}

async fn probe_inner(config: &types::HealthCheckConfig) -> (bool, String) {
    let https = config.r#type.starts_with("HTTPS");
    let port = config.port.unwrap_or(if https { 443 } else { 80 }) as u16;
    let host = config.ip_address.clone().or_else(|| config.fully_qualified_domain_name.clone()).unwrap_or_default();
    let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let connect_timeout = Duration::from_secs(if config.r#type == "TCP" { 10 } else { 4 });
    let stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(&target)).await {
        Err(_) => return (false, format!("Failure: Connection timed out. {FIREWALL}")),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return (false, format!("Failure: Connection refused. {FIREWALL}"))
        }
        Ok(Err(_)) => return (false, format!("Failure: Could not connect to the endpoint. {FIREWALL}")),
        Ok(Ok(s)) => s,
    };
    let resolved = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    if config.r#type == "TCP" {
        return (true, "Success: TCP connection established".into());
    }
    let host_header = config.fully_qualified_domain_name.clone().unwrap_or_else(|| host.clone());
    let path = config.resource_path.clone().unwrap_or_else(|| "/".into());
    let path = if path.starts_with('/') { path } else { format!("/{path}") };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Amazon-Route53-Health-Check-Service (ref {}; report http://amzn.to/1vsZADi)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        uuid::Uuid::new_v4()
    );
    // Route 53 waits two seconds for the response after connecting.
    let exchange = async {
        if https {
            let sni = if config.enable_sni.unwrap_or(true) { host_header.clone() } else { host.clone() };
            let mut tls = tls_connect(stream, &sni).await?;
            exchange(&mut tls, &request).await
        } else {
            let mut stream = stream;
            exchange(&mut stream, &request).await
        }
    };
    let response = match tokio::time::timeout(Duration::from_secs(2), exchange).await {
        Err(_) => return (false, format!("Failure: Response timed out. Resolved IP: {resolved}")),
        Ok(Err(e)) => return (false, format!("Failure: {e}. Resolved IP: {resolved}")),
        Ok(Ok(r)) => r,
    };
    let (status, reason, body) = parse_response(&response);
    let Some(status) = status else {
        return (false, format!("Failure: The response is not a valid HTTP response. Resolved IP: {resolved}"));
    };
    if !(200..400).contains(&status) {
        return (false, format!("Failure: HTTP Status Code {status}, {reason}. Resolved IP: {resolved}"));
    }
    if config.r#type.ends_with("STR_MATCH") {
        let wanted = config.search_string.clone().unwrap_or_default();
        // Route 53 searches the first 5,120 bytes of the body.
        let head = &body[..body.len().min(5120)];
        if !String::from_utf8_lossy(head).contains(&wanted) {
            return (
                false,
                format!("Failure: HTTP Status Code {status}, {reason}. Failed to find the specified string in the response body. Resolved IP: {resolved}"),
            );
        }
    }
    (true, format!("Success: HTTP Status Code {status}, {reason}"))
}

async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    request: &str,
) -> Result<Vec<u8>, String> {
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                // Headers and the searched part of the body are enough.
                if out.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) if !out.is_empty() => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(out)
}

fn parse_response(raw: &[u8]) -> (Option<u16>, String, Vec<u8>) {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&raw[..i], raw[i + 4..].to_vec()),
        None => (raw, Vec::new()),
    };
    let head = String::from_utf8_lossy(head);
    let status_line = head.lines().next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return (None, String::new(), body);
    }
    let status = parts.next().and_then(|s| s.parse().ok());
    let reason = parts.next().unwrap_or_default().trim().to_string();
    (status, reason, body)
}

/// Route 53 health checkers do not validate certificates.
#[derive(Debug)]
struct AcceptAnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn tls_connect(
    stream: TcpStream,
    server_name: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
        .with_no_client_auth();
    let name = rustls_pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| "Failure: The endpoint name is not valid for TLS".to_string())?;
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_lines() {
        let (status, reason, body) = parse_response(b"HTTP/1.1 503 Service Unavailable\r\nX: y\r\n\r\nbody");
        assert_eq!((status, reason.as_str(), body.as_slice()), (Some(503), "Service Unavailable", &b"body"[..]));
        assert_eq!(parse_response(b"garbage").0, None);
    }

    #[test]
    fn calculated_checks_follow_children() {
        let mut runs = Runs::new();
        let endpoint = |ty: &str| types::HealthCheckConfig { r#type: ty.into(), ..Default::default() };
        let mut checks = HashMap::new();
        checks.insert("a".to_string(), endpoint("HTTP"));
        checks.insert("b".to_string(), endpoint("HTTP"));
        checks.insert(
            "calc".to_string(),
            types::HealthCheckConfig {
                r#type: "CALCULATED".into(),
                child_health_checks: Some(vec!["a".into(), "b".into()]),
                health_threshold: Some(2),
                ..Default::default()
            },
        );
        assert!(healthy_in(&runs, &checks, "calc", 0));
        let mut down = Run::new(1);
        down.healthy = false;
        runs.insert("b".into(), down);
        assert!(!healthy_in(&runs, &checks, "calc", 0));
        checks.get_mut("b").unwrap().inverted = Some(true);
        assert!(healthy_in(&runs, &checks, "calc", 0));
    }
}
