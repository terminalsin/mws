//! A small Redis protocol (RESP2) client: what MWS needs to drive the
//! engines it runs (replication, cluster setup, ACLs, failover, snapshots).

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// A plain or TLS connection.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resp {
    Simple(String),
    Error(String),
    Int(i64),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<Resp>>),
}

impl Resp {
    pub fn as_text(&self) -> Option<String> {
        match self {
            Resp::Simple(s) => Some(s.clone()),
            Resp::Bulk(Some(b)) => Some(String::from_utf8_lossy(b).into_owned()),
            Resp::Int(i) => Some(i.to_string()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Resp::Bulk(Some(b)) => Some(b.clone()),
            Resp::Simple(s) => Some(s.as_bytes().to_vec()),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Resp::Int(i) => Some(*i),
            other => other.as_text()?.parse().ok(),
        }
    }

    pub fn items(&self) -> &[Resp] {
        match self {
            Resp::Array(Some(v)) => v,
            _ => &[],
        }
    }
}

#[derive(Debug, Clone)]
pub struct RespError(pub String);

impl std::fmt::Display for RespError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<std::io::Error> for RespError {
    fn from(e: std::io::Error) -> Self {
        RespError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, RespError>;

async fn tcp(host: &str, port: u16) -> Result<TcpStream> {
    let stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect((host, port)))
        .await
        .map_err(|_| RespError(format!("connecting to {host}:{port} timed out")))??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

pub struct Client {
    stream: BufReader<Box<dyn Stream>>,
    /// Commands the node knows under other names (`rename-command`).
    renames: Option<(&'static [&'static str], String)>,
}

const TIMEOUT: Duration = Duration::from_secs(30);

impl Client {
    pub async fn connect(host: &str, port: u16) -> Result<Self> {
        let stream = tcp(host, port).await?;
        Ok(Self { stream: BufReader::new(Box::new(stream)), renames: None })
    }

    /// Connect over TLS, trusting `config`'s roots (encryption in transit).
    pub async fn connect_tls(host: &str, port: u16, config: std::sync::Arc<rustls::ClientConfig>) -> Result<Self> {
        let stream = tcp(host, port).await?;
        let name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| RespError(format!("invalid server name {host}: {e}")))?;
        let tls = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_rustls::TlsConnector::from(config).connect(name, stream),
        )
        .await
        .map_err(|_| RespError(format!("TLS handshake with {host}:{port} timed out")))??;
        Ok(Self { stream: BufReader::new(Box::new(tls)), renames: None })
    }

    /// Connect (over TLS when `tls` is set) and authenticate.
    pub async fn connect_with(
        host: &str,
        port: u16,
        tls: Option<std::sync::Arc<rustls::ClientConfig>>,
        auth: &Auth,
    ) -> Result<Self> {
        let mut c = match tls {
            Some(config) => Self::connect_tls(host, port, config).await?,
            None => Self::connect(host, port).await?,
        };
        c.authenticate(auth).await?;
        Ok(c)
    }

    async fn authenticate(&mut self, auth: &Auth) -> Result<()> {
        match auth {
            Auth::None => {}
            Auth::Password(p) => {
                self.ok(&["AUTH", p]).await?;
            }
            Auth::User(u, p) => {
                self.ok(&["AUTH", u, p]).await?;
            }
        }
        Ok(())
    }

    /// Connect and authenticate (as `default` with the AUTH token, or as
    /// `user`).
    pub async fn connect_auth(host: &str, port: u16, auth: &Auth) -> Result<Self> {
        let mut c = Self::connect(host, port).await?;
        c.authenticate(auth).await?;
        Ok(c)
    }

    pub async fn cmd(&mut self, args: &[&str]) -> Result<Resp> {
        let args: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
        self.cmd_bytes(&args).await
    }

    /// Send `commands` as `<COMMAND>-<suffix>`, the names a node started
    /// with `rename-command` knows them by.
    pub fn renamed(mut self, commands: &'static [&'static str], suffix: &str) -> Self {
        self.renames = Some((commands, suffix.to_string()));
        self
    }

    pub async fn cmd_bytes(&mut self, args: &[&[u8]]) -> Result<Resp> {
        let renamed = match (&self.renames, args.first()) {
            (Some((commands, suffix)), Some(first)) => {
                let name = String::from_utf8_lossy(first).to_ascii_uppercase();
                commands.contains(&name.as_str()).then(|| format!("{name}-{suffix}").into_bytes())
            }
            _ => None,
        };
        let mut args = args.to_vec();
        if let Some(r) = &renamed {
            args[0] = r;
        }
        let mut out = format!("*{}\r\n", args.len()).into_bytes();
        for a in args {
            out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            out.extend_from_slice(a);
            out.extend_from_slice(b"\r\n");
        }
        tokio::time::timeout(TIMEOUT, async {
            self.stream.get_mut().write_all(&out).await?;
            self.read().await
        })
        .await
        .map_err(|_| RespError("timed out waiting for the engine".into()))?
    }

    /// Run a command, turning an error reply into an error.
    pub async fn ok(&mut self, args: &[&str]) -> Result<Resp> {
        match self.cmd(args).await? {
            Resp::Error(e) => Err(RespError(e)),
            r => Ok(r),
        }
    }

    async fn line(&mut self) -> Result<String> {
        let mut line = String::new();
        if self.stream.read_line(&mut line).await? == 0 {
            return Err(RespError("connection closed".into()));
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }

    fn read(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Resp>> + Send + '_>> {
        Box::pin(async move {
            let line = self.line().await?;
            let (kind, rest) = line.split_at(line.len().min(1));
            match kind {
                "+" => Ok(Resp::Simple(rest.to_string())),
                "-" => Ok(Resp::Error(rest.to_string())),
                ":" => Ok(Resp::Int(rest.parse().map_err(|_| RespError(format!("bad integer {rest}")))?)),
                "$" => {
                    let n: i64 = rest.parse().map_err(|_| RespError(format!("bad length {rest}")))?;
                    if n < 0 {
                        return Ok(Resp::Bulk(None));
                    }
                    let mut buf = vec![0u8; n as usize + 2];
                    self.stream.read_exact(&mut buf).await?;
                    buf.truncate(n as usize);
                    Ok(Resp::Bulk(Some(buf)))
                }
                "*" => {
                    let n: i64 = rest.parse().map_err(|_| RespError(format!("bad length {rest}")))?;
                    if n < 0 {
                        return Ok(Resp::Array(None));
                    }
                    let mut items = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        items.push(self.read().await?);
                    }
                    Ok(Resp::Array(Some(items)))
                }
                _ => Err(RespError(format!("unexpected reply {line:?}"))),
            }
        })
    }
}

/// How MWS authenticates to an engine it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    None,
    Password(String),
    User(String, String),
}

/// `INFO <section>` as key/value pairs.
pub async fn info(c: &mut Client, section: &str) -> Result<Vec<(String, String)>> {
    let text = c.ok(&["INFO", section]).await?.as_text().unwrap_or_default();
    Ok(text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.trim().to_string()))
        .collect())
}

/// The CRC16 (XMODEM) Redis Cluster hashes keys with.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// The cluster slot a key belongs to (honouring `{hash tags}`).
pub fn key_slot(key: &[u8]) -> u16 {
    let k = match key.iter().position(|&b| b == b'{') {
        Some(s) => match key[s + 1..].iter().position(|&b| b == b'}') {
            Some(0) | None => key,
            Some(e) => &key[s + 1..s + 1 + e],
        },
        None => key,
    };
    crc16(k) % 16384
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_match_redis() {
        assert_eq!(key_slot(b"foo"), 12182);
        assert_eq!(key_slot(b"{user1000}.following"), key_slot(b"user1000"));
        assert_eq!(key_slot(b"123456789"), 0x31C3);
    }
}
