//! The layer 7 proxy: Application Load Balancer listeners (rules, actions,
//! transforms, weighted target groups, stickiness, routing algorithms)
//! and Classic HTTP/HTTPS listeners.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::Rng;

use super::tls::{TlsInfo, TlsSettings};
use super::FrontSpec;
use crate::health;
use crate::logs::{self, Stream};
use crate::metrics::{dims, Batch};
use crate::names;
use crate::state::{RegionState, RegisteredTarget, TargetGroupRecord};
use crate::v2::types as t;
use crate::Elb;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type Body = BoxBody<Bytes, BoxError>;

pub(crate) fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

/// Serve a listener socket.
pub(crate) async fn serve(elb: Elb, spec: FrontSpec, listener: tokio::net::TcpListener) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else { continue };
        if !elb.front_allows(&spec, peer) {
            continue;
        }
        let elb = elb.clone();
        let spec = spec.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let conn_id = conn_trace_id();
            if spec.protocol == "HTTPS" {
                let settings = elb.tls_settings(&spec);
                let Some(config) = super::tls::server_config(&elb, &settings) else { return };
                let begun = Instant::now();
                let accepted = tokio_rustls::TlsAcceptor::from(config).accept(stream).await;
                let latency = begun.elapsed();
                match accepted {
                    Ok(tls) => {
                        let mut info = super::tls::info(tls.get_ref().1);
                        info.certificate = settings.certificates.first().cloned();
                        connection_log(&elb, &spec, peer, latency, Ok(&info), &conn_id);
                        serve_conn(elb, spec, TokioIo::new(tls), peer, Some(info), conn_id).await;
                    }
                    Err(e) => connection_log(&elb, &spec, peer, latency, Err(&e), &conn_id),
                }
            } else {
                serve_conn(elb, spec, TokioIo::new(stream), peer, None, conn_id).await;
            }
        });
    }
}

/// `TID_` and 32 hex digits: the id tying a connection log entry to its
/// requests' access log entries.
pub(crate) fn conn_trace_id() -> String {
    format!("TID_{}", names::hex_id(32))
}

/// An Application Load Balancer connection log entry for one TLS
/// handshake.
fn connection_log(
    elb: &Elb,
    spec: &FrontSpec,
    peer: SocketAddr,
    latency: Duration,
    outcome: Result<&TlsInfo, &std::io::Error>,
    conn_id: &str,
) {
    if spec.classic.is_some() {
        return;
    }
    let Some(dest) = elb.log_destination(spec, Stream::Connection) else { return };
    let (proto, cipher, subject, validity, serial, status) = match outcome {
        Ok(info) => {
            let leaf = info.client_chain.first().and_then(|der| {
                let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
                let v = cert.validity();
                let stamp = |t: &x509_parser::time::ASN1Time| {
                    chrono::DateTime::from_timestamp(t.timestamp(), 0)
                        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                        .unwrap_or_default()
                };
                Some((
                    logs::quoted(&cert.subject().to_string()),
                    format!("NotAfter={};NotBefore={}", stamp(&v.not_after), stamp(&v.not_before)),
                    hex::encode_upper(cert.raw_serial()),
                ))
            });
            let (subject, validity, serial) = leaf.unwrap_or_else(|| ("-".into(), "-".into(), "-".into()));
            (info.version.clone(), info.cipher.clone(), subject, validity, serial, "Success".to_string())
        }
        Err(e) => {
            let reason = e
                .get_ref()
                .and_then(|i| i.downcast_ref::<rustls::Error>())
                .map(|r| match r {
                    rustls::Error::InvalidCertificate(c) => match c {
                        rustls::CertificateError::Expired => "ClientCertExpired",
                        rustls::CertificateError::NotValidYet => "ClientCertNotYetValid",
                        rustls::CertificateError::Revoked => "ClientCertRevoked",
                        rustls::CertificateError::UnknownIssuer => "ClientCertUntrusted",
                        _ => "ClientCertInvalid",
                    },
                    _ => "UnmappedConnectionError",
                })
                .unwrap_or("UnmappedConnectionError");
            ("-".into(), "-".into(), "-".into(), "-".into(), "-".into(), format!("Failed:{reason}"))
        }
    };
    let line = format!(
        "{} {} {} {} {} {} {:.3} {} {} {} {} {}",
        logs::micros(elb.now()),
        peer.ip(),
        peer.port(),
        spec.port,
        logs::dash(&proto),
        logs::dash(&cipher),
        latency.as_secs_f64() * 1000.0,
        subject,
        validity,
        serial,
        status,
        conn_id,
    );
    elb.record_log(spec, Stream::Connection, dest, line);
}

async fn serve_conn<I>(elb: Elb, spec: FrontSpec, io: I, peer: SocketAddr, tls: Option<TlsInfo>, conn_id: String)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let elb = elb.clone();
        let spec = spec.clone();
        let tls = tls.clone();
        let conn_id = conn_id.clone();
        async move {
            let req = req.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed());
            Ok::<_, Infallible>(handle(elb, spec, req, peer, tls, &conn_id).await)
        }
    });
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
}

/// Where a request goes.
#[derive(Debug, Clone)]
pub(crate) enum Upstream {
    Http { addr: SocketAddr, tls: bool, h2: bool },
    Lambda { function: String, multi_value: bool },
}

pub(crate) struct Forward {
    pub(crate) tg_arn: Option<String>,
    pub(crate) target: (String, i32),
    pub(crate) upstream: Upstream,
    pub(crate) set_cookies: Vec<String>,
    pub(crate) timeout: Duration,
    pub(crate) preserve_host_port: bool,
    pub(crate) tls_headers: bool,
    pub(crate) xff_mode: String,
    pub(crate) xff_port: bool,
}

pub(crate) enum Decision {
    Respond { status: u16, headers: Vec<(String, String)>, body: Bytes },
    Forward(Box<Forward>),
}

/// ELB's own error page for `status`.
pub(crate) fn error_page(status: u16) -> Bytes {
    let Decision::Respond { body, .. } = elb_error(status) else { return Bytes::new() };
    body
}

pub(crate) fn elb_error(status: u16) -> Decision {
    // The phrases ELB's own error pages use.
    let reason = match status {
        503 => "Service Temporarily Unavailable",
        504 => "Gateway Time-out",
        413 => "Request Entity Too Large",
        561 => "Unauthorized",
        _ => StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason()).unwrap_or("Error"),
    };
    let body = format!(
        "<html>\r\n<head><title>{status} {reason}</title></head>\r\n<body>\r\n<center><h1>{status} {reason}</h1></center>\r\n</body>\r\n</html>\r\n"
    );
    Decision::Respond { status, headers: vec![("content-type".into(), "text/html".into())], body: Bytes::from(body) }
}

/// What the request looks like to rule conditions.
struct Seen<'a> {
    method: &'a str,
    host: String,
    path: String,
    query: Vec<(String, String)>,
    headers: &'a HeaderMap,
    client: SocketAddr,
}

/// ALB wildcards: `*` matches any run of characters, `?` one character.
pub(crate) fn wildcard(pattern: &str, value: &str, case_insensitive: bool) -> bool {
    let (p, v): (Vec<char>, Vec<char>) = if case_insensitive {
        (pattern.to_lowercase().chars().collect(), value.to_lowercase().chars().collect())
    } else {
        (pattern.chars().collect(), value.chars().collect())
    };
    let (mut pi, mut vi, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = vi;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            vi = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn regex_any(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| regex::Regex::new(p).is_ok_and(|r| r.is_match(value)))
}

fn condition_matches(c: &t::RuleCondition, seen: &Seen<'_>) -> bool {
    match c.field.as_deref().unwrap_or_default() {
        "host-header" => {
            let cfg = c.host_header_config.clone().unwrap_or_default();
            let host = seen.host.split(':').next().unwrap_or_default().to_string();
            cfg.values.iter().flatten().any(|v| wildcard(v, &host, true))
                || regex_any(cfg.regex_values.as_deref().unwrap_or_default(), &host)
        }
        "path-pattern" => {
            let cfg = c.path_pattern_config.clone().unwrap_or_default();
            cfg.values.iter().flatten().any(|v| wildcard(v, &seen.path, false))
                || regex_any(cfg.regex_values.as_deref().unwrap_or_default(), &seen.path)
        }
        "http-header" => {
            let cfg = c.http_header_config.clone().unwrap_or_default();
            let name = cfg.http_header_name.unwrap_or_default();
            seen.headers.get_all(name.as_str()).iter().filter_map(|v| v.to_str().ok()).any(|h| {
                cfg.values.iter().flatten().any(|v| wildcard(v, h, true))
                    || regex_any(cfg.regex_values.as_deref().unwrap_or_default(), h)
            })
        }
        "http-request-method" => {
            c.http_request_method_config.iter().flat_map(|m| m.values.iter().flatten()).any(|m| m == seen.method)
        }
        "query-string" => c.query_string_config.iter().flat_map(|q| q.values.iter().flatten()).any(|kv| {
            seen.query.iter().any(|(k, v)| {
                kv.key.as_deref().is_none_or(|want| wildcard(want, k, true))
                    && kv.value.as_deref().is_some_and(|want| wildcard(want, v, true))
            })
        }),
        "source-ip" => {
            let ip = seen.client.ip().to_string();
            c.source_ip_config.iter().flat_map(|s| s.values.iter().flatten()).any(|cidr| names::ip_in_cidr(&ip, cidr))
        }
        _ => false,
    }
}

fn parse_query(q: Option<&str>) -> Vec<(String, String)> {
    q.map(form_pairs).unwrap_or_default()
}

fn form_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (decode(k), decode(v))
        })
        .collect()
}

fn decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(http::header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(
        |c| {
            let (k, v) = c.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        },
    )
}

fn sticky_value(id: &str, port: i32) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{id}|{port}"))
}

fn sticky_target(v: &str) -> Option<(String, i32)> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (id, port) = s.rsplit_once('|')?;
    Some((id.to_string(), port.parse().ok()?))
}

fn expires(seconds: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(seconds)).format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Targets a target group may send to: healthy ones, or every target in
/// service when none is healthy (ELB fails open).
pub(crate) fn routable(
    elb: &Elb,
    r: &RegionState,
    account: &str,
    region: &str,
    tg: &TargetGroupRecord,
) -> Vec<RegisteredTarget> {
    let mut healthy = Vec::new();
    let mut fallback = Vec::new();
    for target in &tg.targets {
        let s = health::classify(elb, r, account, region, tg, target);
        match s.state {
            "healthy" | "unavailable" => healthy.push(target.clone()),
            "initial" | "unhealthy" => fallback.push(target.clone()),
            _ => {}
        }
    }
    if healthy.is_empty() {
        fallback
    } else {
        healthy
    }
}

/// Where traffic for a target goes.
pub(crate) fn upstream_for(
    elb: &Elb,
    account: &str,
    region: &str,
    tg: &TargetGroupRecord,
    target: &RegisteredTarget,
) -> Option<Upstream> {
    let tls = tg.protocol() == "HTTPS" || tg.protocol() == "TLS";
    let h2 = matches!(tg.tg.protocol_version.as_deref(), Some("HTTP2" | "GRPC"));
    match tg.target_type() {
        "lambda" => Some(Upstream::Lambda {
            function: target.id.clone(),
            multi_value: tg.attr("lambda.multi_value_headers.enabled") == Some("true"),
        }),
        "instance" => {
            let (_, ip, _) = health::instance_state(elb, account, region, &target.id)?;
            Some(Upstream::Http { addr: SocketAddr::new(ip?.parse().ok()?, target.port as u16), tls, h2 })
        }
        "alb" => Some(Upstream::Http {
            addr: elb.inner.data.address_of_lb_port(&target.id, target.port)?,
            tls: false,
            h2: false,
        }),
        _ => Some(Upstream::Http { addr: SocketAddr::new(target.id.parse().ok()?, target.port as u16), tls, h2 }),
    }
}

/// Pick a target with the group's algorithm and stickiness.
fn pick_target(
    elb: &Elb,
    tg: &TargetGroupRecord,
    candidates: &[RegisteredTarget],
    headers: &HeaderMap,
    set_cookies: &mut Vec<String>,
    secure: bool,
) -> Option<RegisteredTarget> {
    if candidates.is_empty() {
        return None;
    }
    let sticky = tg.attr("stickiness.enabled") == Some("true");
    let sticky_type = tg.attr("stickiness.type").unwrap_or("lb_cookie");
    let cookie_name = match sticky_type {
        "app_cookie" => "AWSALBAPP-0",
        _ => "AWSALB",
    };
    if sticky {
        if let Some((id, port)) = cookie(headers, cookie_name).as_deref().and_then(sticky_target) {
            if let Some(t) = candidates.iter().find(|c| c.id == id && c.port == port) {
                return Some(t.clone());
            }
        }
    }
    let chosen = match tg.attr("load_balancing.algorithm.type").unwrap_or("round_robin") {
        "least_outstanding_requests" => {
            let out = elb.inner.data.outstanding.lock().expect("lock");
            candidates
                .iter()
                .min_by_key(|c| out.get(&format!("{}|{}|{}", tg.arn(), c.id, c.port)).copied().unwrap_or(0))
                .cloned()
        }
        "weighted_random" => Some(candidates[rand::thread_rng().gen_range(0..candidates.len())].clone()),
        _ => {
            let mut counters = elb.inner.data.counters.lock().expect("lock");
            let n = counters.entry(tg.arn().to_string()).or_insert(0);
            let t = candidates[*n % candidates.len()].clone();
            *n = n.wrapping_add(1);
            Some(t)
        }
    }?;
    if sticky && tg.target_type() != "lambda" {
        let duration: i64 = tg
            .attr(if sticky_type == "app_cookie" {
                "stickiness.app_cookie.duration_seconds"
            } else {
                "stickiness.lb_cookie.duration_seconds"
            })
            .and_then(|v| v.parse().ok())
            .unwrap_or(86_400);
        let value = sticky_value(&chosen.id, chosen.port);
        let exp = expires(duration);
        set_cookies.push(format!("{cookie_name}={value}; Expires={exp}; Path=/"));
        if cookie_name == "AWSALB" {
            let secure_attr = if secure { "; Secure" } else { "" };
            set_cookies.push(format!("AWSALBCORS={value}; Expires={exp}; Path=/; SameSite=None{secure_attr}"));
        }
    }
    Some(chosen)
}

/// Fill `#{...}` placeholders in a redirect component.
fn placeholders(template: &str, protocol: &str, host: &str, port: &str, path: &str, query: &str) -> String {
    template
        .replace("#{protocol}", &protocol.to_ascii_lowercase())
        .replace("#{host}", host)
        .replace("#{port}", port)
        .replace("#{path}", path.trim_start_matches('/'))
        .replace("#{query}", query)
}

fn redirect(c: &t::RedirectActionConfig, spec: &FrontSpec, host: &str, path: &str, query: Option<&str>) -> Decision {
    let protocol = placeholders(
        c.protocol.as_deref().unwrap_or("#{protocol}"),
        &spec.protocol,
        host,
        &spec.port.to_string(),
        path,
        query.unwrap_or(""),
    );
    let host_out = placeholders(
        c.host.as_deref().unwrap_or("#{host}"),
        &spec.protocol,
        host,
        &spec.port.to_string(),
        path,
        query.unwrap_or(""),
    );
    let port = placeholders(
        c.port.as_deref().unwrap_or("#{port}"),
        &spec.protocol,
        host,
        &spec.port.to_string(),
        path,
        query.unwrap_or(""),
    );
    let path_out = placeholders(
        c.path.as_deref().unwrap_or("/#{path}"),
        &spec.protocol,
        host,
        &spec.port.to_string(),
        path,
        query.unwrap_or(""),
    );
    let query_out = placeholders(
        c.query.as_deref().unwrap_or("#{query}"),
        &spec.protocol,
        host,
        &spec.port.to_string(),
        path,
        query.unwrap_or(""),
    );
    // ELB always writes the port, default or not.
    let scheme = protocol.to_ascii_lowercase();
    let mut location = format!("{scheme}://{host_out}:{port}");
    location.push_str(&path_out);
    if !query_out.is_empty() {
        location.push('?');
        location.push_str(&query_out);
    }
    let status = if c.status_code == "HTTP_301" { 301 } else { 302 };
    Decision::Respond {
        status,
        headers: vec![("location".into(), location), ("content-type".into(), "text/html".into())],
        body: Bytes::new(),
    }
}

/// Apply a rule's transforms to the request target and host.
fn transform(transforms: &[t::RuleTransform], host: &mut String, path_and_query: &mut String) {
    for tr in transforms {
        let (rewrites, value): (&[t::RewriteConfig], &mut String) = match tr.r#type.as_str() {
            "host-header-rewrite" => {
                (tr.host_header_rewrite_config.as_ref().and_then(|c| c.rewrites.as_deref()).unwrap_or_default(), host)
            }
            "url-rewrite" => {
                (tr.url_rewrite_config.as_ref().and_then(|c| c.rewrites.as_deref()).unwrap_or_default(), path_and_query)
            }
            _ => continue,
        };
        for rw in rewrites {
            if let Ok(re) = regex::Regex::new(&rw.regex) {
                // `$1` names a capture group; `${1}` keeps it apart from what follows.
                let template = dollar_group().replace_all(&rw.replace, "$${$1}");
                let replaced = re.replace(value, template.as_ref()).into_owned();
                *value = replaced;
            }
        }
    }
}

struct V2Route {
    decision: Decision,
    /// Authentication actions to run first, in order.
    auth: Vec<t::Action>,
    host: String,
    path_and_query: String,
    /// The matched rule's priority (0 for the default rule) and the action
    /// types run, for access logs.
    priority: Option<i64>,
    executed: Vec<String>,
}

fn decide_v2(elb: &Elb, spec: &FrontSpec, parts: &http::request::Parts, client: SocketAddr, secure: bool) -> V2Route {
    let host = parts.headers.get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let mut path_and_query = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let mut out_host = host.clone();
    let st = elb.lock();
    let mut auth: Vec<t::Action> = Vec::new();
    let log: std::cell::RefCell<(Option<i64>, Vec<String>)> = Default::default();
    let result = |decision: Decision, auth: Vec<t::Action>, h: String, pq: String| {
        let (priority, executed) = log.borrow().clone();
        V2Route { decision, auth, host: h, path_and_query: pq, priority, executed }
    };
    let Some(r) = st.regions.get(&spec.region_key) else {
        return result(elb_error(503), std::mem::take(&mut auth), out_host, path_and_query);
    };
    let Some(listener) = r.listeners.get(&spec.key) else {
        return result(elb_error(503), std::mem::take(&mut auth), out_host, path_and_query);
    };
    let lb_attrs = r.load_balancers.get(listener.lb_arn()).map(|l| l.attributes.clone()).unwrap_or_default();
    let seen = Seen {
        method: parts.method.as_str(),
        host: host.clone(),
        path: parts.uri.path().to_string(),
        query: parse_query(parts.uri.query()),
        headers: &parts.headers,
        client,
    };
    let _ = lb_attrs;
    let rules = crate::ops::rules_of(r, &spec.key);
    let matched = rules
        .iter()
        .find(|rule| rule.is_default() || rule.rule.conditions.iter().flatten().all(|c| condition_matches(c, &seen)));
    let Some(rule) = matched else {
        return result(elb_error(503), std::mem::take(&mut auth), out_host, path_and_query);
    };
    log.borrow_mut().0 = Some(if rule.is_default() { 0 } else { rule.priority() });
    if let Some(trs) = &rule.rule.transforms {
        transform(trs, &mut out_host, &mut path_and_query);
    }
    let mut actions: Vec<t::Action> = rule.rule.actions.clone().unwrap_or_default();
    actions.sort_by_key(|a| a.order.unwrap_or(0));
    for a in &actions {
        {
            let executed = &mut log.borrow_mut().1;
            let name = match a.r#type.as_str() {
                "authenticate-oidc" | "authenticate-cognito" => "authenticate",
                other => other,
            };
            if executed.last().map(String::as_str) != Some(name) {
                executed.push(name.to_string());
            }
        }
        match a.r#type.as_str() {
            "authenticate-oidc" | "authenticate-cognito" | "jwt-validation" => auth.push(a.clone()),
            "fixed-response" => {
                let c = a.fixed_response_config.clone().unwrap_or_default();
                return result(
                    Decision::Respond {
                        status: c.status_code.parse().unwrap_or(200),
                        headers: c.content_type.map(|ct| vec![("content-type".to_string(), ct)]).unwrap_or_default(),
                        body: Bytes::from(c.message_body.unwrap_or_default()),
                    },
                    std::mem::take(&mut auth),
                    out_host,
                    path_and_query,
                );
            }
            "redirect" => {
                let c = a.redirect_config.clone().unwrap_or_default();
                let (path, query) = match path_and_query.split_once('?') {
                    Some((p, q)) => (p.to_string(), Some(q.to_string())),
                    None => (path_and_query.clone(), None),
                };
                let h = out_host.split(':').next().unwrap_or_default().to_string();
                return result(
                    redirect(&c, spec, &h, &path, query.as_deref()),
                    std::mem::take(&mut auth),
                    out_host,
                    path_and_query,
                );
            }
            "forward" => {
                let groups: Vec<t::TargetGroupTuple> =
                    a.forward_config.as_ref().and_then(|f| f.target_groups.clone()).unwrap_or_default();
                let stick = a
                    .forward_config
                    .as_ref()
                    .and_then(|f| f.target_group_stickiness_config.clone())
                    .unwrap_or_default();
                let mut set_cookies = Vec::new();
                let mut chosen: Option<String> = None;
                if stick.enabled == Some(true) {
                    if let Some(v) = cookie(&parts.headers, "AWSALBTG").and_then(|v| sticky_target(&v)) {
                        if groups.iter().any(|g| g.target_group_arn.as_deref() == Some(v.0.as_str())) {
                            chosen = Some(v.0);
                        }
                    }
                }
                if chosen.is_none() {
                    let total: i32 = groups.iter().map(|g| g.weight.unwrap_or(1)).sum();
                    if total > 0 {
                        let mut roll = rand::thread_rng().gen_range(0..total);
                        for g in &groups {
                            let w = g.weight.unwrap_or(1);
                            if roll < w {
                                chosen = g.target_group_arn.clone();
                                break;
                            }
                            roll -= w;
                        }
                    }
                }
                let Some(tg_arn) = chosen else {
                    return result(elb_error(503), std::mem::take(&mut auth), out_host, path_and_query);
                };
                if stick.enabled == Some(true) {
                    let d = stick.duration_seconds.unwrap_or(3600) as i64;
                    let v = sticky_value(&tg_arn, 0);
                    set_cookies.push(format!("AWSALBTG={v}; Expires={}; Path=/", expires(d)));
                    set_cookies
                        .push(format!("AWSALBTGCORS={v}; Expires={}; Path=/; SameSite=None; Secure", expires(d)));
                }
                let Some(tg) = r.target_groups.get(&tg_arn) else {
                    return result(elb_error(503), std::mem::take(&mut auth), out_host, path_and_query);
                };
                let candidates = routable(elb, r, spec.account(), spec.region(), tg);
                let Some(target) = pick_target(elb, tg, &candidates, &parts.headers, &mut set_cookies, secure) else {
                    return result(elb_error(503), std::mem::take(&mut auth), out_host, path_and_query);
                };
                let Some(upstream) = upstream_for(elb, spec.account(), spec.region(), tg, &target) else {
                    return result(elb_error(502), std::mem::take(&mut auth), out_host, path_and_query);
                };
                let timeout = r
                    .load_balancers
                    .get(listener.lb_arn())
                    .and_then(|l| l.attributes.get("idle_timeout.timeout_seconds"))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60u64);
                let lb = r.load_balancers.get(listener.lb_arn());
                let attr = |k: &str| lb.and_then(|l| l.attributes.get(k)).cloned().unwrap_or_default();
                let forward = Forward {
                    tg_arn: Some(tg_arn.clone()),
                    target: (target.id.clone(), target.port),
                    upstream,
                    set_cookies,
                    timeout: Duration::from_secs(timeout),
                    preserve_host_port: attr("routing.http.preserve_host_header.enabled") == "true",
                    tls_headers: attr("routing.http.x_amzn_tls_version_and_cipher_suite.enabled") == "true",
                    xff_mode: attr("routing.http.xff_header_processing.mode"),
                    xff_port: attr("routing.http.xff_client_port.enabled") == "true",
                };
                return result(
                    Decision::Forward(Box::new(forward)),
                    std::mem::take(&mut auth),
                    out_host,
                    path_and_query,
                );
            }
            _ => {}
        }
    }
    result(elb_error(503), std::mem::take(&mut auth), out_host, path_and_query)
}

/// Run the rule's authentication actions: each either adds request
/// headers or answers the request itself (a login redirect, 401, 561).
async fn authenticate(elb: &Elb, spec: &FrontSpec, parts: &mut http::request::Parts, route: &mut V2Route) {
    let host = parts.headers.get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let mut actions = std::mem::take(&mut route.auth);
    // The IdP's redirect back is finished by the action that sent the user
    // to it, whichever rule the callback path matches.
    if parts.uri.path() == super::auth::CALLBACK
        && !actions.iter().any(|a| a.r#type == "authenticate-oidc")
        && elb.inner.data.auth.has_pending(parts.uri.query().unwrap_or(""))
    {
        actions.insert(
            0,
            t::Action {
                r#type: "authenticate-oidc".into(),
                authenticate_oidc_config: Some(Default::default()),
                ..Default::default()
            },
        );
    }
    for a in &actions {
        if a.r#type == "authenticate-oidc" {
            for h in ["x-amzn-oidc-accesstoken", "x-amzn-oidc-identity", "x-amzn-oidc-data"] {
                parts.headers.remove(h);
            }
        }
        match super::auth::run(elb, spec, a, parts, &host, &route.path_and_query).await {
            super::auth::Outcome::Continue(headers) => {
                for (k, v) in headers {
                    if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
                        parts.headers.insert(k, v);
                    }
                }
            }
            super::auth::Outcome::Respond { status, headers, body } => {
                route.decision = Decision::Respond { status, headers, body };
                // The actions after this one never ran.
                let kind = if a.r#type == "jwt-validation" { "jwt-validation" } else { "authenticate" };
                if let Some(i) = route.executed.iter().position(|e| e == kind) {
                    route.executed.truncate(i + 1);
                }
                return;
            }
        }
    }
}

/// Handle one request on a listener.
pub(crate) async fn handle(
    elb: Elb,
    spec: FrontSpec,
    req: Request<Body>,
    client: SocketAddr,
    tls: Option<TlsInfo>,
    conn_id: &str,
) -> Response<Body> {
    let started = Instant::now();
    let created = elb.now();
    let secure = tls.is_some() || spec.protocol == "HTTPS";
    let (mut parts, body) = req.into_parts();
    // The trace id is fixed here so the access log and the target see the
    // same one.
    if !parts.headers.get("x-amzn-trace-id").and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("Root=")) {
        let trace = format!("Root=1-{:08x}-{}", created.timestamp(), names::hex_id(24));
        if let Ok(v) = HeaderValue::from_str(&trace) {
            parts.headers.insert("x-amzn-trace-id", v);
        }
    }
    let log = elb.log_destination(&spec, Stream::Access).map(|d| (d, RequestLog::new(&parts, &spec, secure)));
    let route = if spec.classic.is_some() {
        let (decision, host, pq) = crate::classic::decide(&elb, &spec, &parts, secure);
        V2Route { decision, auth: Vec::new(), host, path_and_query: pq, priority: None, executed: Vec::new() }
    } else {
        decide_v2(&elb, &spec, &parts, client, secure)
    };
    let mut route = route;
    if !route.auth.is_empty() || parts.uri.path() == super::auth::CALLBACK {
        authenticate(&elb, &spec, &mut parts, &mut route).await;
    }
    let lb_dim = names::lb_dimension(&spec.lb_arn);
    let ns = crate::metrics::namespace(&spec.lb_type);
    let classic_dims = vec![dims(&[("LoadBalancerName", spec.classic.as_deref().unwrap_or_default())])];
    let lb_dims = if spec.classic.is_some() { classic_dims.clone() } else { vec![dims(&[("LoadBalancer", &lb_dim)])] };
    let mut batch = Batch::new(spec.account(), spec.region(), ns);
    batch.add("RequestCount", "Count", 1.0, &lb_dims);
    let mut dispatch = Dispatch::default();
    let ran = (route.priority, std::mem::take(&mut route.executed));
    let response = match route.decision {
        Decision::Respond { status, headers, body } => {
            if spec.classic.is_none() {
                let class = format!("HTTPCode_ELB_{}XX_Count", status / 100);
                if (400..600).contains(&status) {
                    batch.add(leak(class), "Count", 1.0, &lb_dims);
                    if matches!(status, 500..=504) {
                        batch.add(leak(format!("HTTPCode_ELB_{status}_Count")), "Count", 1.0, &lb_dims);
                    }
                } else if (300..400).contains(&status) && headers.iter().any(|(k, _)| k == "location") {
                    batch.add("HTTPCode_ELB_3XX_Count", "Count", 1.0, &lb_dims);
                } else {
                    batch.add("HTTPCode_ELB_2XX_Count", "Count", 1.0, &lb_dims);
                }
            } else if status >= 500 {
                batch.add(leak(format!("HTTPCode_ELB_{}XX", status / 100)), "Count", 1.0, &lb_dims);
            }
            if ran.1.last().map(String::as_str) == Some("redirect") {
                dispatch.redirect =
                    headers.iter().find(|(k, _)| k == "location").map(|(_, v)| v.clone()).unwrap_or_default();
            }
            let mut b = Response::builder().status(status).header("server", "awselb/2.0");
            for (k, v) in &headers {
                b = b.header(k.as_str(), v.as_str());
            }
            b.header("content-length", body.len())
                .body(full(body))
                .unwrap_or_else(|_| Response::new(full(Bytes::new())))
        }
        Decision::Forward(f) => {
            let tg_dims = match &f.tg_arn {
                Some(tg) => vec![
                    dims(&[("TargetGroup", &names::tg_dimension(tg)), ("LoadBalancer", &lb_dim)]),
                    dims(&[("TargetGroup", &names::tg_dimension(tg))]),
                ],
                None => classic_dims.clone(),
            };
            if f.tg_arn.is_some() {
                batch.add("RequestCountPerTarget", "Count", 1.0, &tg_dims[1..]);
                batch.add("RequestCount", "Count", 1.0, &tg_dims[..1]);
            }
            dispatch.tg_arn = f.tg_arn.clone().unwrap_or_default();
            dispatch.request_time = Some(started.elapsed().as_secs_f64());
            if let Upstream::Http { addr, .. } = &f.upstream {
                dispatch.target = addr.to_string();
            }
            let outstanding_key = format!("{}|{}|{}", f.tg_arn.clone().unwrap_or_default(), f.target.0, f.target.1);
            *elb.inner.data.outstanding.lock().expect("lock").entry(outstanding_key.clone()).or_insert(0) += 1;
            parts.headers.remove(http::header::HOST);
            let result = match &f.upstream {
                Upstream::Lambda { function, multi_value } => {
                    super::lambda::invoke(
                        &elb,
                        &spec,
                        f.tg_arn.as_deref().unwrap_or_default(),
                        function,
                        *multi_value,
                        &parts,
                        &route.host,
                        &route.path_and_query,
                        body,
                        client,
                        secure,
                    )
                    .await
                }
                Upstream::Http { addr, tls: up_tls, h2 } => {
                    let host = if f.preserve_host_port {
                        route.host.clone()
                    } else {
                        host_with_listener_port(&route.host, spec.port)
                    };
                    let mut req = Request::from_parts(parts, body);
                    *req.uri_mut() = route.path_and_query.parse().unwrap_or_else(|_| http::Uri::from_static("/"));
                    prepare_headers(req.headers_mut(), &host, client, &spec, &f, tls.as_ref());
                    send(*addr, *up_tls, *h2, req, f.timeout).await
                }
            };
            if let Some(n) = elb.inner.data.outstanding.lock().expect("lock").get_mut(&outstanding_key) {
                *n = n.saturating_sub(1);
            }
            let elapsed = started.elapsed().as_secs_f64();
            match result {
                Ok(mut resp) => {
                    let code = resp.status().as_u16();
                    dispatch.target_status = code.to_string();
                    dispatch.target_time = Some(elapsed);
                    if spec.classic.is_some() {
                        batch.add(leak(format!("HTTPCode_Backend_{}XX", code / 100)), "Count", 1.0, &lb_dims);
                        batch.add("Latency", "Seconds", elapsed, &lb_dims);
                    } else {
                        let class = leak(format!("HTTPCode_Target_{}XX_Count", code / 100));
                        batch.add(class, "Count", 1.0, &lb_dims);
                        batch.add(class, "Count", 1.0, &tg_dims[..1]);
                        batch.add("TargetResponseTime", "Seconds", elapsed, &lb_dims);
                        batch.add("TargetResponseTime", "Seconds", elapsed, &tg_dims[..1]);
                    }
                    for c in &f.set_cookies {
                        if let Ok(v) = HeaderValue::from_str(c) {
                            resp.headers_mut().append(http::header::SET_COOKIE, v);
                        }
                    }
                    resp
                }
                Err(status) => {
                    if spec.classic.is_some() {
                        batch.add("BackendConnectionErrors", "Count", 1.0, &lb_dims);
                        batch.add("HTTPCode_ELB_5XX", "Count", 1.0, &lb_dims);
                    } else {
                        batch.add("HTTPCode_ELB_5XX_Count", "Count", 1.0, &lb_dims);
                        batch.add(leak(format!("HTTPCode_ELB_{status}_Count")), "Count", 1.0, &lb_dims);
                        if status == 502 || status == 504 {
                            batch.add("TargetConnectionErrorCount", "Count", 1.0, &lb_dims);
                        }
                    }
                    let Decision::Respond { status, headers, body } = elb_error(status) else { unreachable!() };
                    let mut b = Response::builder().status(status).header("server", "awselb/2.0");
                    for (k, v) in &headers {
                        b = b.header(k.as_str(), v.as_str());
                    }
                    b.body(full(body)).unwrap_or_else(|_| Response::new(full(Bytes::new())))
                }
            }
        }
    };
    batch.send(elb.metrics());
    if let Some((dest, req)) = log {
        let line = req.line(&elb, &spec, &ran, &dispatch, &response, client, tls.as_ref(), created, conn_id);
        elb.record_log(&spec, Stream::Access, dest, line);
    }
    response
}

/// What happened past the load balancer, for the access log.
#[derive(Default)]
struct Dispatch {
    tg_arn: String,
    target: String,
    target_status: String,
    request_time: Option<f64>,
    target_time: Option<f64>,
    redirect: String,
}

/// The request as the access log records it, taken before the request is
/// forwarded.
struct RequestLog {
    kind: &'static str,
    request: String,
    user_agent: String,
    trace: String,
    received: u64,
}

impl RequestLog {
    fn new(parts: &http::request::Parts, spec: &FrontSpec, secure: bool) -> Self {
        let header = |n: &str| parts.headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or_default();
        let upgrade = header("upgrade").eq_ignore_ascii_case("websocket");
        let kind = match (secure, parts.version == http::Version::HTTP_2, upgrade) {
            (_, _, true) if secure => "wss",
            (_, _, true) => "ws",
            (true, true, _) if header("content-type").starts_with("application/grpc") => "grpcs",
            (true, true, _) => "h2",
            (true, false, _) => "https",
            _ => "http",
        };
        let host = header("host");
        let host = host.rsplit_once(':').filter(|(_, p)| p.parse::<u16>().is_ok()).map(|(h, _)| h).unwrap_or(host);
        let version = match parts.version {
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_2 => "HTTP/2.0",
            _ => "HTTP/1.1",
        };
        let scheme = if secure { "https" } else { "http" };
        let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let request = format!("{} {scheme}://{host}:{}{pq} {version}", parts.method, spec.port);
        let head: usize = parts.headers.iter().map(|(k, v)| k.as_str().len() + v.len() + 4).sum();
        let body: u64 = header("content-length").parse().unwrap_or(0);
        let received = (request.len() + head + 2) as u64 + body;
        Self {
            kind,
            request,
            user_agent: header("user-agent").to_string(),
            trace: header("x-amzn-trace-id").to_string(),
            received,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn line(
        &self,
        elb: &Elb,
        spec: &FrontSpec,
        ran: &(Option<i64>, Vec<String>),
        d: &Dispatch,
        response: &Response<Body>,
        client: SocketAddr,
        tls: Option<&TlsInfo>,
        created: chrono::DateTime<chrono::Utc>,
        conn_id: &str,
    ) -> String {
        use hyper::body::Body as _;
        let status = response.status().as_u16();
        let head: usize = response.headers().iter().map(|(k, v)| k.as_str().len() + v.len() + 4).sum();
        let sent = response.body().size_hint().exact().unwrap_or(0) + (head + 17) as u64;
        let now = elb.now();
        let target = logs::dash(&d.target);
        let target_status = logs::dash(&d.target_status);
        let (cipher, proto) = tls.map(|t| (t.cipher.as_str(), t.version.as_str())).unwrap_or(("-", "-"));
        if let Some(name) = &spec.classic {
            let t = |v: Option<f64>| v.map(|v| format!("{v:.6}")).unwrap_or_else(|| "-1".into());
            return format!(
                "{} {name} {client} {target} {} {} {} {status} {target_status} {} {sent} {} {} {} {}",
                logs::micros(now),
                t(d.request_time),
                t(d.target_time),
                t(d.target_time.map(|_| 0.000_02)),
                self.received,
                logs::quoted(&self.request),
                logs::quoted(&self.user_agent),
                logs::dash(cipher),
                logs::dash(proto),
            );
        }
        let t = |v: Option<f64>| v.map(|v| format!("{v:.3}")).unwrap_or_else(|| "-1".into());
        let (target_list, status_list) = if d.target.is_empty() {
            (String::new(), String::new())
        } else {
            (d.target.clone(), d.target_status.clone())
        };
        let executed = ran.1.join(",");
        format!(
            "{kind} {time} {elb} {client} {target} {req_t} {target_t} {resp_t} {status} {target_status} {received} {sent} {request} {ua} {cipher} {proto} {tg} {trace} {domain} {cert} {priority} {created} {actions} {redirect} {error} {targets} {codes} \"-\" \"-\" {conn_id}",
            kind = self.kind,
            time = logs::micros(now),
            elb = names::lb_dimension(&spec.lb_arn),
            req_t = t(d.request_time),
            target_t = t(d.target_time),
            resp_t = t(d.target_time.map(|_| 0.0)),
            received = self.received,
            request = logs::quoted(&self.request),
            ua = logs::quoted(&self.user_agent),
            cipher = logs::dash(cipher),
            proto = logs::dash(proto),
            tg = logs::dash(&d.tg_arn),
            trace = logs::quoted(&self.trace),
            domain = logs::quoted(tls.and_then(|t| t.sni.as_deref()).unwrap_or_default()),
            cert = logs::quoted(tls.and_then(|t| t.certificate.as_deref()).unwrap_or_default()),
            priority = ran.0.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            created = logs::micros(created),
            actions = logs::quoted(&executed),
            redirect = logs::quoted(&d.redirect),
            error = logs::quoted(""),
            targets = logs::quoted(&target_list),
            codes = logs::quoted(&status_list),
        )
    }
}

fn dollar_group() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\$(\d+)").expect("regex"))
}

/// Without `routing.http.preserve_host_header.enabled`, the Host header's
/// port becomes the listener's (and is left out for 80 and 443).
fn host_with_listener_port(host: &str, port: i32) -> String {
    let name = match host.rsplit_once(':') {
        Some((n, p)) if p.chars().all(|c| c.is_ascii_digit()) && (n.ends_with(']') || !n.contains(':')) => n,
        _ => host,
    };
    if port == 80 || port == 443 {
        name.to_string()
    } else {
        format!("{name}:{port}")
    }
}

/// Metric names are static strings; the few dynamic ones are interned.
fn leak(s: String) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static NAMES: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let set = NAMES.get_or_init(Default::default);
    let mut set = set.lock().expect("metric names");
    if let Some(found) = set.get(s.as_str()) {
        return found;
    }
    let leaked: &'static str = Box::leak(s.into_boxed_str());
    set.insert(leaked);
    leaked
}

const HOP_BY_HOP: &[&str] =
    &["connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"];

fn prepare_headers(
    h: &mut HeaderMap,
    host: &str,
    client: SocketAddr,
    spec: &FrontSpec,
    f: &Forward,
    tls: Option<&TlsInfo>,
) {
    for name in HOP_BY_HOP {
        h.remove(*name);
    }
    if let Ok(v) = HeaderValue::from_str(host) {
        h.insert(http::header::HOST, v);
    }
    let client_entry = if f.xff_port { client.to_string() } else { client.ip().to_string() };
    match f.xff_mode.as_str() {
        "remove" => {
            h.remove("x-forwarded-for");
        }
        "preserve" => {}
        _ => {
            let xff = match h.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                Some(prev) if !prev.is_empty() => format!("{prev}, {client_entry}"),
                _ => client_entry,
            };
            if let Ok(v) = HeaderValue::from_str(&xff) {
                h.insert("x-forwarded-for", v);
            }
        }
    }
    let proto = if spec.protocol == "HTTPS" { "https" } else { "http" };
    h.insert("x-forwarded-proto", HeaderValue::from_static(proto));
    if let Ok(v) = HeaderValue::from_str(&spec.port.to_string()) {
        h.insert("x-forwarded-port", v);
    }
    let trace = match h.get("x-amzn-trace-id").and_then(|v| v.to_str().ok()) {
        Some(existing) if existing.contains("Root=") => existing.to_string(),
        _ => format!("Root=1-{:08x}-{}", chrono::Utc::now().timestamp(), names::hex_id(24)),
    };
    if let Ok(v) = HeaderValue::from_str(&trace) {
        h.insert("x-amzn-trace-id", v);
    }
    if let Some(info) = tls {
        if f.tls_headers {
            for (name, v) in [("x-amzn-tls-version", &info.version), ("x-amzn-tls-cipher-suite", &info.cipher)] {
                if let Ok(v) = HeaderValue::from_str(v) {
                    h.insert(HeaderName::from_static(name), v);
                }
            }
        }
        if !info.client_chain.is_empty() {
            if let Some(leaf) = info.client_chain.first() {
                if let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf) {
                    let set = |h: &mut HeaderMap, name: &'static str, v: String| {
                        if let Ok(v) = HeaderValue::from_str(&v) {
                            h.insert(HeaderName::from_static(name), v);
                        }
                    };
                    set(h, "x-amzn-mtls-clientcert-serial-number", hex::encode_upper(cert.raw_serial()));
                    set(h, "x-amzn-mtls-clientcert-issuer", cert.issuer().to_string());
                    set(h, "x-amzn-mtls-clientcert-subject", cert.subject().to_string());
                    set(
                        h,
                        "x-amzn-mtls-clientcert-validity",
                        format!(
                            "NotBefore={};NotAfter={}",
                            cert.validity().not_before.to_rfc2822().unwrap_or_default(),
                            cert.validity().not_after.to_rfc2822().unwrap_or_default()
                        ),
                    );
                }
                let pem = pem_encode(leaf);
                set_encoded(h, "x-amzn-mtls-clientcert-leaf", &pem);
                let chain: String = info.client_chain.iter().map(|c| pem_encode(c)).collect();
                set_encoded(h, "x-amzn-mtls-clientcert", &chain);
            }
        }
    }
}

fn set_encoded(h: &mut HeaderMap, name: &'static str, pem: &str) {
    let enc: String = pem
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    if let Ok(v) = HeaderValue::from_str(&enc) {
        h.insert(HeaderName::from_static(name), v);
    }
}

fn pem_encode(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Send `req` to a target. Errors are the status ELB answers with.
pub(crate) async fn send(
    addr: SocketAddr,
    tls: bool,
    h2: bool,
    req: Request<Body>,
    timeout: Duration,
) -> Result<Response<Body>, u16> {
    let connect = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr)).await;
    let stream = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(502),
        Err(_) => return Err(504),
    };
    let _ = stream.set_nodelay(true);
    let fut = async move {
        if tls {
            let alpn = if h2 { vec![b"h2".to_vec()] } else { vec![b"http/1.1".to_vec()] };
            let s = super::tls::connect_insecure_alpn(stream, addr, alpn).await.map_err(|_| 502u16)?;
            exchange(TokioIo::new(s), h2, req).await
        } else {
            exchange(TokioIo::new(stream), h2, req).await
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(504),
    }
}

async fn exchange<I>(io: I, h2: bool, req: Request<Body>) -> Result<Response<Body>, u16>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let resp = if h2 {
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await.map_err(|_| 502u16)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut req = req;
        *req.version_mut() = http::Version::HTTP_2;
        sender.send_request(req).await.map_err(|_| 502u16)?
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|_| 502u16)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut req = req;
        *req.version_mut() = http::Version::HTTP_11;
        sender.send_request(req).await.map_err(|_| 502u16)?
    };
    let (mut parts, body) = resp.into_parts();
    for name in HOP_BY_HOP {
        parts.headers.remove(*name);
    }
    Ok(Response::from_parts(parts, body.map_err(|e| Box::new(e) as BoxError).boxed()))
}

impl Elb {
    /// TLS settings of a listener, read from the state.
    pub(crate) fn tls_settings(&self, spec: &FrontSpec) -> TlsSettings {
        let st = self.lock();
        let Some(r) = st.regions.get(&spec.region_key) else { return TlsSettings::default() };
        if let Some(name) = &spec.classic {
            return crate::classic::tls_settings(r, name, spec.port);
        }
        let Some(l) = r.listeners.get(&spec.key) else { return TlsSettings::default() };
        let mut certificates: Vec<String> = l.default_certificate().map(str::to_string).into_iter().collect();
        certificates.extend(l.extra_certificates.iter().cloned());
        let http2 = r
            .load_balancers
            .get(l.lb_arn())
            .and_then(|lb| lb.attributes.get("routing.http2.enabled"))
            .map(String::as_str)
            != Some("false");
        let alpn = match l.protocol() {
            "HTTPS" if http2 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "HTTPS" => vec![b"http/1.1".to_vec()],
            _ => match l.listener.alpn_policy.as_ref().and_then(|a| a.first()).map(String::as_str) {
                Some("HTTP1Only") => vec![b"http/1.1".to_vec()],
                Some("HTTP2Only") => vec![b"h2".to_vec()],
                Some("HTTP2Optional") => vec![b"http/1.1".to_vec(), b"h2".to_vec()],
                Some("HTTP2Preferred") => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                _ => Vec::new(),
            },
        };
        let mutual = l.listener.mutual_authentication.as_ref().and_then(|m| {
            let mode = m.mode.clone()?;
            match mode.as_str() {
                "verify" => {
                    let ts = r.trust_stores.get(m.trust_store_arn.as_deref()?)?;
                    let crls: Vec<Vec<u8>> = ts.revocations.iter().map(|r| r.crl.clone()).collect();
                    Some((mode, ts.bundle_pem.clone(), crls, m.ignore_client_certificate_expiry == Some(true)))
                }
                "passthrough" => Some((mode, String::new(), Vec::new(), false)),
                _ => None,
            }
        });
        TlsSettings { certificates, policy: l.listener.ssl_policy.clone(), alpn, mutual }
    }
}
