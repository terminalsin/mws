//! The data plane: a local socket per listener, kept in step with the
//! control-plane state by [`reconcile`]. HTTP and HTTPS listeners run the
//! layer 7 proxy ([`l7`]); TCP, TLS, UDP and TCP_UDP listeners and Classic
//! TCP/SSL listeners run the layer 4 proxy ([`l4`]).
//!
//! HTTP(S) listeners also answer on MWS's own endpoint when a request's
//! `Host` is the load balancer's DNS name (`<dns>:<port>` picks the
//! listener; without a port, port 80, then 443, then the only HTTP(S)
//! listener). `GET /_aws/elb/listeners` lists where every listener is
//! served.

pub(crate) mod l4;
pub(crate) mod l7;
mod lambda;
pub(crate) mod tls;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext};

use crate::state::State;
use crate::Elb;

/// Where a listener is served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerAddress {
    /// The listener's ARN; for a Classic Load Balancer
    /// `<load balancer ARN>:<port>`.
    pub listener: String,
    pub load_balancer: String,
    pub dns_name: String,
    pub protocol: String,
    pub port: i32,
    /// The local socket (TCP; UDP-only listeners report their UDP socket).
    pub address: SocketAddr,
}

/// A listener the data plane should serve.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FrontSpec {
    pub key: String,
    pub region_key: String,
    pub lb_arn: String,
    pub lb_type: String,
    pub dns: String,
    pub protocol: String,
    pub port: i32,
    /// For Classic Load Balancers: the load balancer name.
    pub classic: Option<String>,
}

impl FrontSpec {
    pub fn account(&self) -> &str {
        self.region_key.split_once('|').map(|(a, _)| a).unwrap_or_default()
    }
    pub fn region(&self) -> &str {
        self.region_key.split_once('|').map(|(_, r)| r).unwrap_or_default()
    }
    fn layer7(&self) -> bool {
        matches!(self.protocol.as_str(), "HTTP" | "HTTPS")
    }
    fn udp(&self) -> bool {
        matches!(self.protocol.as_str(), "UDP" | "TCP_UDP" | "QUIC" | "TCP_QUIC")
    }
    fn tcp(&self) -> bool {
        !matches!(self.protocol.as_str(), "UDP" | "QUIC")
    }
}

struct Bound {
    spec: FrontSpec,
    tcp: Option<SocketAddr>,
    udp: Option<SocketAddr>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Bound {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[derive(Default)]
pub(crate) struct Runtime {
    bound: Mutex<HashMap<String, Bound>>,
    /// Round-robin positions and outstanding requests per target group.
    pub(crate) counters: Mutex<HashMap<String, usize>>,
    pub(crate) outstanding: Mutex<HashMap<String, usize>>,
}

impl Runtime {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Bound>> {
        self.bound.lock().expect("ELB data plane lock poisoned")
    }

    pub fn addresses(&self) -> Vec<ListenerAddress> {
        let mut v: Vec<ListenerAddress> = self
            .lock()
            .values()
            .filter_map(|b| {
                Some(ListenerAddress {
                    listener: b.spec.key.clone(),
                    load_balancer: b.spec.lb_arn.clone(),
                    dns_name: b.spec.dns.clone(),
                    protocol: b.spec.protocol.clone(),
                    port: b.spec.port,
                    address: b.tcp.or(b.udp)?,
                })
            })
            .collect();
        v.sort_by(|a, b| a.listener.cmp(&b.listener));
        v
    }

    /// The local TCP address of `lb_arn`'s listener on `port` (NLB `alb`
    /// targets forward there).
    pub fn address_of_lb_port(&self, lb_arn: &str, port: i32) -> Option<SocketAddr> {
        self.lock().values().find(|b| b.spec.lb_arn == lb_arn && b.spec.port == port).and_then(|b| b.tcp)
    }

    pub fn spec(&self, key: &str) -> Option<FrontSpec> {
        self.lock().get(key).map(|b| b.spec.clone())
    }
}

/// Every listener the state describes.
fn desired(st: &State) -> Vec<FrontSpec> {
    let mut out = Vec::new();
    for (region_key, r) in &st.regions {
        for l in r.listeners.values() {
            let Some(lb) = r.load_balancers.get(l.lb_arn()) else { continue };
            if lb.ty() == "gateway" {
                continue;
            }
            out.push(FrontSpec {
                key: l.arn().to_string(),
                region_key: region_key.clone(),
                lb_arn: lb.arn().to_string(),
                lb_type: lb.ty().to_string(),
                dns: lb.lb.dns_name.clone().unwrap_or_default(),
                protocol: l.protocol().to_string(),
                port: l.port(),
                classic: None,
            });
        }
        for c in r.classic.values() {
            let arn = crate::classic::lb_arn(region_key, c.name());
            for ld in c.description.listener_descriptions.iter().flatten() {
                let Some(listener) = &ld.listener else { continue };
                let protocol = match listener.protocol.to_ascii_uppercase().as_str() {
                    "HTTP" => "HTTP",
                    "HTTPS" => "HTTPS",
                    "SSL" => "TLS",
                    _ => "TCP",
                };
                out.push(FrontSpec {
                    key: format!("{arn}:{}", listener.load_balancer_port),
                    region_key: region_key.clone(),
                    lb_arn: arn.clone(),
                    lb_type: "classic".into(),
                    dns: c.description.dns_name.clone().unwrap_or_default(),
                    protocol: protocol.into(),
                    port: listener.load_balancer_port,
                    classic: Some(c.name().to_string()),
                });
            }
        }
    }
    out
}

/// Bind sockets for new listeners and close removed ones.
pub(crate) fn reconcile(elb: &Elb) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
    let wanted = desired(&elb.lock());
    let mut bound = elb.inner.data.lock();
    bound.retain(|k, b| wanted.iter().any(|w| &w.key == k && w.port == b.spec.port && w.protocol == b.spec.protocol));
    for spec in wanted {
        if bound.contains_key(&spec.key) {
            continue;
        }
        match bind(elb, &handle, &spec) {
            Ok(b) => {
                tracing::info!(listener = %spec.key, protocol = %spec.protocol, address = ?b.tcp.or(b.udp), "ELB listener serving");
                bound.insert(spec.key.clone(), b);
            }
            Err(e) => tracing::warn!(listener = %spec.key, "cannot bind ELB listener: {e}"),
        }
    }
}

fn bind_tcp(host: &str, port: u16) -> std::io::Result<std::net::TcpListener> {
    let l = std::net::TcpListener::bind((host, port))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

fn bind(elb: &Elb, handle: &tokio::runtime::Handle, spec: &FrontSpec) -> std::io::Result<Bound> {
    let host = elb.inner.config.bind_host.clone();
    let preferred = if elb.inner.config.use_listener_ports { spec.port as u16 } else { 0 };
    let mut tasks = Vec::new();
    let mut tcp_addr = None;
    let mut udp_addr = None;
    let _guard = handle.enter();
    if spec.tcp() {
        let std_listener = bind_tcp(&host, preferred).or_else(|_| bind_tcp(&host, 0))?;
        let listener = tokio::net::TcpListener::from_std(std_listener)?;
        tcp_addr = Some(listener.local_addr()?);
        let elb2 = elb.clone();
        let spec2 = spec.clone();
        tasks.push(handle.spawn(async move {
            if spec2.layer7() {
                l7::serve(elb2, spec2, listener).await
            } else {
                l4::serve_tcp(elb2, spec2, listener).await
            }
        }));
    }
    if spec.udp() {
        let port = tcp_addr.map(|a| a.port()).unwrap_or(preferred);
        let socket = std::net::UdpSocket::bind((host.as_str(), port))
            .or_else(|_| std::net::UdpSocket::bind((host.as_str(), 0)))?;
        socket.set_nonblocking(true)?;
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        udp_addr = Some(socket.local_addr()?);
        let elb2 = elb.clone();
        let spec2 = spec.clone();
        tasks.push(handle.spawn(async move { l4::serve_udp(elb2, spec2, socket).await }));
    }
    Ok(Bound { spec: spec.clone(), tcp: tcp_addr, udp: udp_addr, tasks })
}

/// A request to MWS's endpoint that a load balancer should serve.
pub(crate) enum HostRoute {
    Listener(String),
    /// `/_aws/elb/...` pages.
    Control(String),
}

pub(crate) fn host_route(elb: &Elb, request: &HttpRequest) -> Option<HostRoute> {
    if let Some(rest) = request.uri().path().strip_prefix("/_aws/elb/") {
        return Some(HostRoute::Control(rest.to_string()));
    }
    let host = request.headers().get(http::header::HOST).and_then(|v| v.to_str().ok())?.to_ascii_lowercase();
    if !host.contains(".elb.") {
        return None;
    }
    let (name, port) = match host.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<i32>().ok()),
        None => (host.clone(), None),
    };
    let bound = elb.inner.data.lock();
    let candidates: Vec<&FrontSpec> =
        bound.values().map(|b| &b.spec).filter(|s| s.layer7() && s.dns.eq_ignore_ascii_case(&name)).collect();
    let pick = match port {
        Some(p) => candidates.iter().find(|s| s.port == p),
        None => candidates
            .iter()
            .find(|s| s.port == 80)
            .or_else(|| candidates.iter().find(|s| s.port == 443))
            .or_else(|| if candidates.len() == 1 { candidates.first() } else { None }),
    };
    pick.map(|s| HostRoute::Listener(s.key.clone()))
}

pub(crate) async fn serve_host_routed(
    elb: &Elb,
    ctx: &RequestContext,
    route: HostRoute,
    request: HttpRequest,
) -> HttpResponse {
    use http_body_util::BodyExt;
    match route {
        HostRoute::Control(path) => control(elb, ctx, &path),
        HostRoute::Listener(key) => {
            let Some(spec) = elb.inner.data.spec(&key) else {
                return plain(503, "text/plain", Bytes::from_static(b"Service Unavailable"));
            };
            let peer: SocketAddr = ctx
                .source_ip
                .as_deref()
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, 0))
                .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
            let request = request.map(|b| http_body_util::Full::new(b).map_err(|never| match never {}).boxed());
            let response = l7::handle(elb.clone(), spec, request, peer, None).await;
            let (parts, body) = response.into_parts();
            let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
            http::Response::from_parts(parts, bytes)
        }
    }
}

fn plain(status: u16, content_type: &str, body: Bytes) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(body)
        .unwrap_or_else(|_| http::Response::new(Bytes::new()))
}

fn control(elb: &Elb, _ctx: &RequestContext, path: &str) -> HttpResponse {
    if path == "listeners" || path == "listeners/" {
        let list: Vec<serde_json::Value> = elb
            .listener_addresses()
            .into_iter()
            .map(|a| {
                serde_json::json!({
                    "listener": a.listener,
                    "loadBalancer": a.load_balancer,
                    "dnsName": a.dns_name,
                    "protocol": a.protocol,
                    "port": a.port,
                    "address": a.address.to_string(),
                })
            })
            .collect();
        return plain(200, "application/json", Bytes::from(serde_json::Value::Array(list).to_string()));
    }
    // trust-stores/<account>/<region>/<arn>/bundle | revocations/<id>
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 5 && parts[0] == "trust-stores" {
        let arn = percent_decode(parts[3]);
        let key = State::key(parts[1], parts[2]);
        let st = elb.lock();
        let store = st.regions.get(&key).and_then(|r| r.trust_stores.get(&arn));
        match (store, parts[4]) {
            (Some(s), "bundle") => return plain(200, "application/x-pem-file", Bytes::from(s.bundle_pem.clone())),
            (Some(s), "revocations") => {
                let id: i64 = parts.get(5).and_then(|p| p.parse().ok()).unwrap_or(0);
                if let Some(rev) = s.revocations.iter().find(|r| r.id == id) {
                    return plain(200, "text/plain", Bytes::from(rev.serials.join("\n")));
                }
            }
            _ => {}
        }
    }
    plain(404, "text/plain", Bytes::from_static(b"Not Found"))
}

fn percent_decode(s: &str) -> String {
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
