//! Helpers to start MWS on a random port and build SDK configs for it.

use std::sync::Arc;

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_credential_types::Credentials;

pub struct Mws {
    pub endpoint: String,
    pub config: mws::Config,
    pub route53: mws_route53::Route53,
    shutdown: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<()>,
}

impl Mws {
    pub async fn start() -> Self {
        let config = mws::Config::default();
        let built = mws::build(config.clone());
        Self::serve(config, built).await
    }

    /// Start the way the binary does: open `config.db`, restore saved state
    /// or run `config.scenario`.
    pub async fn start_with(config: mws::Config) -> Self {
        let built = mws::start(config.clone()).await.expect("MWS starts");
        Self::serve(config, built).await
    }

    async fn serve(config: mws::Config, built: mws::Mws) -> Self {
        let route53 = built.route53;
        let gateway = Arc::new(built.gateway);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(mws_server::serve(listener, gateway, async {
            let _ = rx.await;
        }));
        Self { endpoint, config, route53, shutdown: tx, server }
    }

    /// Shut down gracefully (state is flushed to the database, if any).
    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        self.server.await.unwrap();
    }

    /// Call the MWS control API: `(status, JSON body)`.
    pub async fn control(&self, method: &str, path: &str, body: Option<&str>) -> (u16, serde_json::Value) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = self.endpoint.trim_start_matches("http://");
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = body.unwrap_or("");
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8(raw).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        let body = if body.is_empty() { serde_json::Value::Null } else { serde_json::from_str(body).unwrap() };
        (status, body)
    }

    /// Send a raw HTTP/1.1 request (anonymous or presigned): `(status,
    /// headers, body)`. `target` is the path and query.
    pub async fn raw(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = target.strip_prefix(&self.endpoint).unwrap_or(target);
        let addr = self.endpoint.trim_start_matches("http://");
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut request = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
        for (k, v) in headers {
            request.push_str(&format!("{k}: {v}\r\n"));
        }
        request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let mut body = raw[split + 4..].to_vec();
        if headers.iter().any(|(k, v)| k == "transfer-encoding" && v.contains("chunked")) {
            body = dechunk(&body);
        }
        (status, headers, body)
    }

    /// An S3 client (path-style addressing) for `config`.
    pub fn s3(config: &SdkConfig) -> aws_sdk_s3::Client {
        let conf = aws_sdk_s3::config::Builder::from(config).force_path_style(true).build();
        aws_sdk_s3::Client::from_conf(conf)
    }

    /// SDK config signed with the account root keys.
    pub async fn root_sdk_config(&self) -> SdkConfig {
        let iam = &self.config.iam;
        self.sdk_config(&iam.root_access_key_id, &iam.root_secret_access_key, None).await
    }

    pub async fn sdk_config(&self, akid: &str, secret: &str, token: Option<&str>) -> SdkConfig {
        aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(&self.endpoint)
            .credentials_provider(Credentials::new(akid, secret, token.map(str::to_string), None, "mws-e2e"))
            .load()
            .await
    }
}

/// Create a user with the given inline policy and return a client signed
/// with that user's own new access key.
pub async fn user_with_policy(mws: &Mws, name: &str, policy: Option<&str>) -> (aws_sdk_iam::Client, SdkConfig) {
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    root.create_user().user_name(name).send().await.unwrap();
    if let Some(doc) = policy {
        root.put_user_policy().user_name(name).policy_name("inline").policy_document(doc).send().await.unwrap();
    }
    let key = root.create_access_key().user_name(name).send().await.unwrap();
    let key = key.access_key().unwrap();
    let cfg = mws.sdk_config(key.access_key_id(), key.secret_access_key(), None).await;
    (aws_sdk_iam::Client::new(&cfg), cfg)
}

/// SDK config for a set of STS temporary credentials.
pub async fn sts_config(mws: &Mws, creds: &aws_sdk_sts::types::Credentials) -> SdkConfig {
    mws.sdk_config(creds.access_key_id(), creds.secret_access_key(), Some(creds.session_token())).await
}

/// An unsigned-looking OIDC ID token: header.payload.signature.
pub fn jwt(claims: serde_json::Value) -> String {
    use base64::Engine;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{}.{}.{}", e.encode(br#"{"alg":"RS256","typ":"JWT"}"#), e.encode(claims.to_string()), e.encode(b"sig"))
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(end) = data.windows(2).position(|w| w == b"\r\n") else { return out };
        let size =
            usize::from_str_radix(std::str::from_utf8(&data[..end]).unwrap().split(';').next().unwrap(), 16).unwrap();
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&data[end + 2..end + 2 + size]);
        data = &data[end + 4 + size..];
    }
}
