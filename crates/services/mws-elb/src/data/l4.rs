//! The layer 4 proxy: Network Load Balancer TCP, TLS, UDP and TCP_UDP
//! listeners (with source IP stickiness and proxy protocol v2) and Classic
//! TCP/SSL listeners. Each connection (or UDP flow) is pinned to one
//! target.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::FrontSpec;
use crate::metrics::{dims, Batch};
use crate::names;
use crate::Elb;

/// Where one flow goes.
pub(crate) struct L4Target {
    pub addr: SocketAddr,
    pub tls: bool,
    pub proxy_protocol: bool,
    pub tg_arn: Option<String>,
}

fn hash_ip(ip: &std::net::IpAddr) -> usize {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut h);
    h.finish() as usize
}

/// Pick the target for a new flow from `client`.
pub(crate) fn decide(elb: &Elb, spec: &FrontSpec, client: SocketAddr, udp: bool) -> Option<L4Target> {
    if let Some(name) = &spec.classic {
        return crate::classic::decide_l4(elb, spec, name);
    }
    let st = elb.lock();
    let r = st.regions.get(&spec.region_key)?;
    let listener = r.listeners.get(&spec.key)?;
    let actions = listener.listener.default_actions.clone().unwrap_or_default();
    let groups = crate::ops::forwarded_target_groups(actions.iter());
    let tg_arn = groups.into_iter().find(|g| {
        r.target_groups.get(g).is_some_and(|tg| match (spec.protocol.as_str(), udp) {
            ("TCP_UDP", _) => true,
            (_, true) => matches!(tg.protocol(), "UDP" | "TCP_UDP"),
            _ => true,
        })
    })?;
    let tg = r.target_groups.get(&tg_arn)?;
    let candidates = super::l7::routable(elb, r, spec.account(), spec.region(), tg);
    if candidates.is_empty() {
        return None;
    }
    let sticky = tg.attr("stickiness.enabled") == Some("true");
    let index = if sticky {
        hash_ip(&client.ip()) % candidates.len()
    } else {
        let mut counters = elb.inner.data.counters.lock().expect("lock");
        let n = counters.entry(tg_arn.clone()).or_insert(0);
        let i = *n % candidates.len();
        *n = n.wrapping_add(1);
        i
    };
    let target = &candidates[index];
    let upstream = super::l7::upstream_for(elb, spec.account(), spec.region(), tg, target)?;
    let super::l7::Upstream::Http { addr, .. } = upstream else { return None };
    Some(L4Target {
        addr,
        tls: tg.protocol() == "TLS",
        proxy_protocol: tg.attr("proxy_protocol_v2.enabled") == Some("true"),
        tg_arn: Some(tg_arn),
    })
}

/// A proxy protocol v2 header for a TCP flow.
fn proxy_v2_header(client: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let mut h = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    h.push(0x21);
    match (client, local) {
        (SocketAddr::V4(c), SocketAddr::V4(l)) => {
            h.push(0x11);
            h.extend_from_slice(&12u16.to_be_bytes());
            h.extend_from_slice(&c.ip().octets());
            h.extend_from_slice(&l.ip().octets());
            h.extend_from_slice(&c.port().to_be_bytes());
            h.extend_from_slice(&l.port().to_be_bytes());
        }
        (c, l) => {
            let v6 = |a: SocketAddr| match a {
                SocketAddr::V6(x) => x.ip().octets(),
                SocketAddr::V4(x) => x.ip().to_ipv6_mapped().octets(),
            };
            h.push(0x21);
            h.extend_from_slice(&36u16.to_be_bytes());
            h.extend_from_slice(&v6(c));
            h.extend_from_slice(&v6(l));
            h.extend_from_slice(&c.port().to_be_bytes());
            h.extend_from_slice(&l.port().to_be_bytes());
        }
    }
    h
}

fn flow_metrics(spec: &FrontSpec, tg: Option<&str>, bytes: f64, rejected: bool) -> Batch {
    let ns = crate::metrics::namespace(&spec.lb_type);
    let mut b = Batch::new(spec.account(), spec.region(), ns);
    if spec.classic.is_some() {
        let d = vec![dims(&[("LoadBalancerName", spec.classic.as_deref().unwrap_or_default())])];
        b.add("RequestCount", "Count", 1.0, &d);
        if rejected {
            b.add("BackendConnectionErrors", "Count", 1.0, &d);
        }
        return b;
    }
    let lb = names::lb_dimension(&spec.lb_arn);
    let d = vec![dims(&[("LoadBalancer", &lb)])];
    let proto = match spec.protocol.as_str() {
        "TLS" => "TLS",
        "UDP" => "UDP",
        _ => "TCP",
    };
    b.add("NewFlowCount", "Count", 1.0, &d);
    b.add(crate::data::l4::leak_flow(proto), "Count", 1.0, &d);
    b.add("ProcessedBytes", "Bytes", bytes, &d);
    if rejected {
        b.add("TCP_ELB_Reset_Count", "Count", 1.0, &d);
    } else if let Some(tg) = tg {
        b.add(
            "NewFlowCount",
            "Count",
            1.0,
            &[dims(&[("TargetGroup", &names::tg_dimension(tg)), ("LoadBalancer", &lb)])],
        );
    }
    b
}

fn leak_flow(proto: &str) -> &'static str {
    match proto {
        "TLS" => "NewFlowCount_TLS",
        "UDP" => "NewFlowCount_UDP",
        _ => "NewFlowCount_TCP",
    }
}

pub(crate) async fn serve_tcp(elb: Elb, spec: FrontSpec, listener: tokio::net::TcpListener) {
    loop {
        let Ok((stream, client)) = listener.accept().await else { continue };
        let local = stream.local_addr().unwrap_or(client);
        let elb = elb.clone();
        let spec = spec.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            if spec.protocol == "TLS" || spec.protocol == "HTTPS" {
                let settings = elb.tls_settings(&spec);
                let Some(config) = super::tls::server_config(&elb, &settings) else { return };
                let Ok(tls) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await else { return };
                relay(elb, spec, tls, client, local).await;
            } else {
                relay(elb, spec, stream, client, local).await;
            }
        });
    }
}

async fn relay<S>(elb: Elb, spec: FrontSpec, mut inbound: S, client: SocketAddr, local: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Some(target) = decide(&elb, &spec, client, false) else {
        flow_metrics(&spec, None, 0.0, true).send(elb.metrics());
        return;
    };
    let Ok(Ok(upstream)) = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target.addr)).await else {
        flow_metrics(&spec, target.tg_arn.as_deref(), 0.0, true).send(elb.metrics());
        return;
    };
    let _ = upstream.set_nodelay(true);
    let bytes = if target.tls {
        let Ok(mut up) = super::tls::connect_insecure(upstream, target.addr).await else { return };
        if target.proxy_protocol {
            let _ = up.write_all(&proxy_v2_header(client, local)).await;
        }
        tokio::io::copy_bidirectional(&mut inbound, &mut up).await
    } else {
        let mut up = upstream;
        if target.proxy_protocol {
            let _ = up.write_all(&proxy_v2_header(client, local)).await;
        }
        tokio::io::copy_bidirectional(&mut inbound, &mut up).await
    };
    let total = bytes.map(|(a, b)| (a + b) as f64).unwrap_or(0.0);
    flow_metrics(&spec, target.tg_arn.as_deref(), total, false).send(elb.metrics());
}

struct Flow {
    socket: Arc<UdpSocket>,
    last: Instant,
}

/// UDP: one upstream socket per client address, closed after 120 idle
/// seconds (NLB's UDP flow timeout).
pub(crate) async fn serve_udp(elb: Elb, spec: FrontSpec, socket: UdpSocket) {
    let socket = Arc::new(socket);
    let flows: Arc<Mutex<HashMap<SocketAddr, Flow>>> = Arc::default();
    let mut buf = vec![0u8; 65_536];
    loop {
        let Ok((n, client)) = socket.recv_from(&mut buf).await else { continue };
        let existing = {
            let mut f = flows.lock().expect("udp flows");
            f.retain(|_, flow| flow.last.elapsed() < Duration::from_secs(120));
            f.get_mut(&client).map(|flow| {
                flow.last = Instant::now();
                flow.socket.clone()
            })
        };
        let up = match existing {
            Some(up) => up,
            None => {
                let Some(target) = decide(&elb, &spec, client, true) else { continue };
                let bind: SocketAddr =
                    if target.addr.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { "[::]:0".parse().expect("addr") };
                let Ok(up) = UdpSocket::bind(bind).await else { continue };
                if up.connect(target.addr).await.is_err() {
                    continue;
                }
                let up = Arc::new(up);
                flows.lock().expect("udp flows").insert(client, Flow { socket: up.clone(), last: Instant::now() });
                flow_metrics(&spec, target.tg_arn.as_deref(), n as f64, false).send(elb.metrics());
                let reply_to = socket.clone();
                let reader = up.clone();
                let flows2 = flows.clone();
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; 65_536];
                    loop {
                        match tokio::time::timeout(Duration::from_secs(120), reader.recv(&mut rbuf)).await {
                            Ok(Ok(m)) => {
                                let _ = reply_to.send_to(&rbuf[..m], client).await;
                            }
                            _ => {
                                flows2.lock().expect("udp flows").remove(&client);
                                return;
                            }
                        }
                    }
                });
                up
            }
        };
        let _ = up.send(&buf[..n]).await;
    }
}
