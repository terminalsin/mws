//! Memcached auto discovery: a Memcached cluster's configuration endpoint
//! answers `config get cluster` with the cluster's current nodes, the way
//! ElastiCache's nodes do, and passes every other command through to a
//! node. Clients such as the ElastiCache Cluster Client poll it to follow
//! nodes being added and removed.

use std::sync::{Arc, Weak};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::resp::Stream;
use crate::{ElastiCache, Inner};

/// The `config get cluster` answer for `nodes` (host, port).
pub(crate) fn config_response(version: u64, nodes: &[(String, u16)]) -> String {
    let list: Vec<String> = nodes.iter().map(|(h, p)| format!("{h}|{h}|{p}")).collect();
    let body = format!("{version}\n{}\n", list.join(" "));
    format!("CONFIG cluster 0 {}\r\n{body}\r\nEND\r\n", body.len())
}

/// Storage commands carry a data block of the size their 5th word names.
fn data_block_len(line: &str) -> Option<usize> {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.first().copied()? {
        "set" | "add" | "replace" | "append" | "prepend" | "cas" => words.get(4)?.parse().ok(),
        _ => None,
    }
}

impl ElastiCache {
    fn from_weak(w: &Weak<Inner>) -> Option<ElastiCache> {
        w.upgrade().map(|inner| ElastiCache { inner })
    }

    /// The configuration version and the running nodes of a Memcached
    /// cluster.
    fn discovery(&self, key: &str, cluster: &str) -> Option<(u64, Vec<(String, u16)>)> {
        let host = self.options().advertise_host.clone();
        self.with_existing(key, |r| {
            let c = r.clusters.get(cluster)?;
            let ids: Vec<u64> = c.nodes.keys().filter_map(|n| n.parse().ok()).collect();
            let max = ids.iter().copied().max().unwrap_or(0);
            // Each node added or removed is a new configuration.
            let version = max + (max - ids.len() as u64);
            let nodes = c.nodes.values().filter(|n| n.handle.is_some()).map(|n| (host.clone(), n.port)).collect();
            Some((version.max(1), nodes))
        })
        .flatten()
    }

    /// Serve a Memcached cluster's configuration endpoint on `port`.
    pub(crate) fn open_discovery(&self, key: &str, cluster: &str, port: u16, tls: bool) {
        if !self.runs_engines() {
            return;
        }
        let proxy_key = format!("{key}/memcached/{cluster}");
        self.proxies().close(&proxy_key);
        let Ok(std_listener) = std::net::TcpListener::bind((self.options().bind_address.as_str(), port)) else {
            tracing::warn!("ElastiCache: port {port} for {cluster}'s configuration endpoint is taken");
            return;
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        let _ = std_listener.set_nonblocking(true);
        let listener = {
            let _guard = rt.enter();
            match TcpListener::from_std(std_listener) {
                Ok(l) => l,
                Err(_) => return,
            }
        };
        let acceptor =
            tls.then(|| crate::tls::server_config(&self.pki()).ok()).flatten().map(tokio_rustls::TlsAcceptor::from);
        let weak = Arc::downgrade(&self.inner);
        let (key, cluster) = (key.to_string(), cluster.to_string());
        let task = rt.spawn(async move {
            loop {
                let Ok((inbound, _)) = listener.accept().await else { continue };
                let _ = inbound.set_nodelay(true);
                let (weak, key, cluster, acceptor) = (weak.clone(), key.clone(), cluster.clone(), acceptor.clone());
                tokio::spawn(async move {
                    match acceptor {
                        Some(a) => {
                            if let Ok(s) = a.accept(inbound).await {
                                serve(s, weak, key, cluster).await;
                            }
                        }
                        None => serve(inbound, weak, key, cluster).await,
                    }
                });
            }
        });
        self.proxies().insert_task(&proxy_key, task);
    }

    pub(crate) fn close_discovery(&self, key: &str, cluster: &str) {
        self.proxies().close(&format!("{key}/memcached/{cluster}"));
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    client: S,
    weak: Weak<Inner>,
    key: String,
    cluster: String,
) {
    let (read, write) = tokio::io::split(client);
    let write = Arc::new(Mutex::new(write));
    let mut read = BufReader::new(read);
    let mut upstream: Option<tokio::io::WriteHalf<Box<dyn Stream>>> = None;
    let mut pump: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        // The binary protocol has no `config` command: pass it through.
        let mut line = String::new();
        match read.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.trim_end() == "config get cluster" {
            let Some(svc) = ElastiCache::from_weak(&weak) else { break };
            let (version, nodes) = svc.discovery(&key, &cluster).unwrap_or((1, vec![]));
            let mut w = write.lock().await;
            if w.write_all(config_response(version, &nodes).as_bytes()).await.is_err() {
                break;
            }
            continue;
        }
        if upstream.is_none() {
            let Some(svc) = ElastiCache::from_weak(&weak) else { break };
            let target = svc.discovery(&key, &cluster).and_then(|(_, n)| n.into_iter().next());
            let Some((_, port)) = target else {
                let mut w = write.lock().await;
                let _ = w.write_all(b"SERVER_ERROR no cache nodes are available\r\n").await;
                continue;
            };
            let Ok(stream) = crate::engine::raw_connect(&svc, port).await else { break };
            let (mut up_read, up_write) = tokio::io::split(stream);
            let w = write.clone();
            pump = Some(tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match up_read.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if w.lock().await.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = w.lock().await.shutdown().await;
            }));
            upstream = Some(up_write);
        }
        let Some(up) = upstream.as_mut() else { break };
        if up.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        if let Some(n) = data_block_len(&line) {
            let mut block = vec![0u8; n + 2];
            if read.read_exact(&mut block).await.is_err() || up.write_all(&block).await.is_err() {
                break;
            }
        }
    }
    if let Some(p) = pump {
        p.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_cluster_config() {
        let r = config_response(2, &[("127.0.0.1".into(), 11211), ("127.0.0.1".into(), 11212)]);
        assert_eq!(r, "CONFIG cluster 0 54\r\n2\n127.0.0.1|127.0.0.1|11211 127.0.0.1|127.0.0.1|11212\n\r\nEND\r\n");
        assert_eq!(data_block_len("set k 0 0 5\r\n"), Some(5));
        assert_eq!(data_block_len("get k\r\n"), None);
    }
}
