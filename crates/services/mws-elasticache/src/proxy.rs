//! Endpoint proxies: the stable addresses ElastiCache hands out for a
//! replication group (primary endpoint, reader endpoint, configuration
//! endpoint). AWS moves a DNS name on failover; MWS listens on a port and
//! forwards each new connection to whichever node currently holds the role.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::net::{TcpListener, TcpStream};

type Targets = Arc<RwLock<Vec<(String, u16)>>>;

struct Proxy {
    targets: Targets,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
pub struct Proxies {
    map: Mutex<HashMap<String, Proxy>>,
}

/// A free TCP port on `bind`.
pub fn free_port(bind: &str) -> u16 {
    std::net::TcpListener::bind((bind, 0)).and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

impl Proxies {
    /// Listen on `bind:port` (0 for any free port) for `key`, forwarding
    /// to the targets set later. Returns the port.
    pub fn open(&self, key: &str, bind: &str, port: u16) -> std::io::Result<u16> {
        self.close(key);
        let std_listener = std::net::TcpListener::bind((bind, port))?;
        std_listener.set_nonblocking(true)?;
        let port = std_listener.local_addr()?.port();
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return Ok(port);
        };
        let listener = {
            let _guard = rt.enter();
            TcpListener::from_std(std_listener)?
        };
        let targets: Targets = Arc::default();
        let next = Arc::new(AtomicUsize::new(0));
        let t = targets.clone();
        let task = rt.spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else { continue };
                let list = t.read().map(|l| l.clone()).unwrap_or_default();
                if list.is_empty() {
                    drop(inbound);
                    continue;
                }
                let i = next.fetch_add(1, Ordering::Relaxed) % list.len();
                let (host, port) = list[i].clone();
                tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect((host.as_str(), port)).await {
                        let _ = inbound.set_nodelay(true);
                        let _ = outbound.set_nodelay(true);
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        self.map.lock().expect("proxy lock").insert(key.to_string(), Proxy { targets, task });
        Ok(port)
    }

    /// Keep `task` (a listener of its own) under `key`, aborting it when
    /// the key is closed.
    pub fn insert_task(&self, key: &str, task: tokio::task::JoinHandle<()>) {
        self.close(key);
        self.map.lock().expect("proxy lock").insert(key.to_string(), Proxy { targets: Arc::default(), task });
    }

    pub fn set_targets(&self, key: &str, targets: Vec<(String, u16)>) {
        if let Some(p) = self.map.lock().expect("proxy lock").get(key) {
            if let Ok(mut t) = p.targets.write() {
                *t = targets;
            }
        }
    }

    pub fn close(&self, key: &str) {
        if let Some(p) = self.map.lock().expect("proxy lock").remove(key) {
            p.task.abort();
        }
    }

    pub fn close_prefix(&self, prefix: &str) {
        let mut map = self.map.lock().expect("proxy lock");
        let keys: Vec<String> = map.keys().filter(|k| k.starts_with(prefix)).cloned().collect();
        for k in keys {
            if let Some(p) = map.remove(&k) {
                p.task.abort();
            }
        }
    }

    pub fn close_all(&self) {
        for (_, p) in self.map.lock().expect("proxy lock").drain() {
            p.task.abort();
        }
    }
}
