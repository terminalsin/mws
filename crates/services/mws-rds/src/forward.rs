//! RDS Proxy's data plane: a TCP listener per proxy endpoint that passes
//! each client connection through to the database the proxy's target
//! group points at (looked up per connection, so failovers and new
//! targets apply at once). Clients authenticate to the database itself.
//!
//! RDS Proxy endpoints are host names clients reach on the engine's
//! standard port (5432, 3306). On Linux every `127.0.0.0/8` address is
//! local, so each endpoint gets its own loopback address (`127.77.x.y`)
//! listening on that port, and RDS reports the address as the endpoint.
//! Where that does not work, the listener takes any free port on
//! `127.0.0.1` and RDS reports the AWS-style host name;
//! `GET /_aws/rds/proxy-endpoints` lists where each endpoint listens.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Where to send a new connection: a database's host and port.
pub(crate) type Resolve = Arc<dyn Fn() -> Option<(String, u16)> + Send + Sync>;

struct Listener {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

/// The listeners, by proxy endpoint ARN.
#[derive(Default)]
pub(crate) struct Forwarders {
    listeners: Mutex<BTreeMap<String, Listener>>,
    next: AtomicU32,
}

impl Forwarders {
    /// Listen for endpoint `key` on the engine's `port`, on a loopback
    /// address of its own if possible. Returns where it listens and whether
    /// that is a dedicated address (clients use the standard port).
    pub(crate) async fn start(&self, key: &str, port: u16, resolve: Resolve) -> Option<(SocketAddr, bool)> {
        if let Some(l) = self.listeners.lock().expect("forwarders lock").get(key) {
            return Some((l.addr, l.addr.port() == port));
        }
        let mut bound = None;
        for _ in 0..16 {
            let n = self.next.fetch_add(1, Ordering::Relaxed) + 1;
            let addr: SocketAddr = (std::net::Ipv4Addr::new(127, 77, (n >> 8) as u8, n as u8), port).into();
            if let Ok(l) = TcpListener::bind(addr).await {
                bound = Some((l, true));
                break;
            }
        }
        if bound.is_none() {
            bound = TcpListener::bind(("127.0.0.1", 0)).await.ok().map(|l| (l, false));
        }
        let (listener, dedicated) = bound?;
        let addr = listener.local_addr().ok()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else { continue };
                let resolve = resolve.clone();
                tokio::spawn(async move {
                    let Some((host, port)) = resolve() else { return };
                    let Ok(mut server) = TcpStream::connect((host.as_str(), port)).await else { return };
                    let mut client = client;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                });
            }
        });
        self.listeners.lock().expect("forwarders lock").insert(key.to_string(), Listener { addr, task });
        Some((addr, dedicated))
    }

    pub(crate) fn stop(&self, key: &str) {
        if let Some(l) = self.listeners.lock().expect("forwarders lock").remove(key) {
            l.task.abort();
        }
    }

    /// Where each endpoint listens.
    pub(crate) fn addresses(&self) -> BTreeMap<String, SocketAddr> {
        self.listeners.lock().expect("forwarders lock").iter().map(|(k, l)| (k.clone(), l.addr)).collect()
    }

    pub(crate) fn stop_all(&self) {
        for (_, l) in std::mem::take(&mut *self.listeners.lock().expect("forwarders lock")) {
            l.task.abort();
        }
    }
}
