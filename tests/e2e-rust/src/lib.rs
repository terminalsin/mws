//! Helpers to start MWS on a random port and build SDK configs for it.

use std::sync::Arc;

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_credential_types::Credentials;

pub struct Mws {
    pub endpoint: String,
    pub config: mws::Config,
    pub route53: mws_route53::Route53,
    pub ses: mws_ses::Ses,
    pub codeartifact: mws_codeartifact::CodeArtifact,
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

    /// Start listening on every interface (for clients outside this host's
    /// loopback, such as EC2 instances in containers); clients here still
    /// use 127.0.0.1.
    pub async fn start_on_all_interfaces(config: mws::Config) -> Self {
        let built = mws::build(config.clone());
        Self::serve_on(config, built, "0.0.0.0:0").await
    }

    async fn serve(config: mws::Config, built: mws::Mws) -> Self {
        Self::serve_on(config, built, "127.0.0.1:0").await
    }

    async fn serve_on(config: mws::Config, built: mws::Mws, addr: &str) -> Self {
        let route53 = built.route53;
        let ses = built.ses;
        let codeartifact = built.codeartifact;
        let lambda = built.lambda;
        let gateway = Arc::new(built.gateway);
        // As the binary does: Lambda's background work learns the endpoint.
        let weak = Arc::downgrade(&gateway);
        lambda.set_endpoint_source(Arc::new(move || weak.upgrade().and_then(|g| g.endpoint().map(str::to_string))));
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(mws_server::serve(listener, gateway, async {
            let _ = rx.await;
        }));
        Self { endpoint, config, route53, ses, codeartifact, shutdown: tx, server }
    }

    /// Start the SES SMTP listener on a free loopback port: its address.
    pub async fn start_smtp(&self) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(mws_ses::serve_smtp(self.ses.clone(), listener));
        addr
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
        let mut request = format!("{method} {target} HTTP/1.1\r\nConnection: close\r\n");
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            request.push_str(&format!("Host: {addr}\r\n"));
        }
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

    /// Send a SigV4-signed request for `service` with the root keys (MWS's
    /// own signed endpoints): `(status, headers, body)`.
    pub async fn signed(
        &self,
        service: &str,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let iam = &self.config.iam;
        self.signed_as(&iam.root_access_key_id, &iam.root_secret_access_key, service, method, target, body).await
    }

    /// [`Mws::signed`] with other keys.
    pub async fn signed_as(
        &self,
        akid: &str,
        secret: &str,
        service: &str,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
        let identity = Credentials::new(akid, secret, None, None, "mws-e2e").into();
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region("us-east-1")
            .name(service)
            .time(std::time::SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .unwrap()
            .into();
        let host = self.endpoint.trim_start_matches("http://").to_string();
        let url = format!("{}{target}", self.endpoint);
        let signable =
            SignableRequest::new(method, &url, [("host", host.as_str())].into_iter(), SignableBody::Bytes(body))
                .unwrap();
        let (instructions, _) = sign(signable, &params).unwrap().into_parts();
        let mut request = http::Request::builder().method(method).uri(&url).body(()).unwrap();
        instructions.apply_to_request_http1x(&mut request);
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
            .chain([("host".to_string(), host.clone())])
            .collect();
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let path = request.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
        self.raw(method, &path, &refs, body).await
    }

    pub async fn sdk_config(&self, akid: &str, secret: &str, token: Option<&str>) -> SdkConfig {
        aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .http_client(loopback_http_client())
            .endpoint_url(&self.endpoint)
            .credentials_provider(Credentials::new(akid, secret, token.map(str::to_string), None, "mws-e2e"))
            .load()
            .await
    }
}

/// Resolves every name to 127.0.0.1, like wildcard DNS for the endpoint:
/// SDKs put the account id (S3 Control) or `{access point}-{account}` (S3
/// access point ARNs) in front of the endpoint's host.
#[derive(Debug, Clone)]
struct Loopback;

impl aws_smithy_runtime_api::client::dns::ResolveDns for Loopback {
    fn resolve_dns<'a>(&'a self, _name: &'a str) -> aws_smithy_runtime_api::client::dns::DnsFuture<'a> {
        aws_smithy_runtime_api::client::dns::DnsFuture::ready(Ok(vec![std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )]))
    }
}

fn loopback_http_client() -> aws_smithy_runtime_api::client::http::SharedHttpClient {
    use aws_smithy_http_client::tls;
    aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::AwsLc))
        .build_with_resolver(Loopback)
}

/// Create a user with the given inline policy and return a client signed
/// with that user's own new access key.
/// Wait, with the SDK's `function_active_v2` waiter, until a new function
/// is `Active` (Lambda keeps it `Pending` for a moment, as on AWS).
pub async fn function_active(lambda: &aws_sdk_lambda::Client, name: &str) {
    use aws_sdk_lambda::client::Waiters;
    lambda
        .wait_until_function_active_v2()
        .function_name(name)
        .wait(std::time::Duration::from_secs(60))
        .await
        .expect("function becomes Active");
}

/// Wait, with the SDK's `function_updated_v2` waiter, until a function's
/// last update is `Successful`.
pub async fn function_updated(lambda: &aws_sdk_lambda::Client, name: &str) {
    use aws_sdk_lambda::client::Waiters;
    lambda
        .wait_until_function_updated_v2()
        .function_name(name)
        .wait(std::time::Duration::from_secs(60))
        .await
        .expect("function update completes");
}

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

/// An OIDC ID token with a fake signature: header.payload.signature. MWS
/// rejects it unless signature verification is turned off.
pub fn jwt(claims: serde_json::Value) -> String {
    use base64::Engine;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{}.{}.{}", e.encode(br#"{"alg":"RS256","typ":"JWT"}"#), e.encode(claims.to_string()), e.encode(b"sig"))
}

/// A local OpenID Connect identity provider: serves discovery and a JWKS
/// over HTTPS with a self-signed certificate, and signs ID tokens with its
/// RSA key, so `AssumeRoleWithWebIdentity` can verify them as AWS does.
pub struct Idp {
    /// `https://localhost:<port>`.
    pub issuer: String,
    /// Hex SHA-1 thumbprint of the server certificate, for the IAM OIDC
    /// provider.
    pub thumbprint: String,
    key: aws_lc_rs::rsa::KeyPair,
    _server: tokio::task::JoinHandle<()>,
}

impl Idp {
    pub async fn start() -> Self {
        use aws_lc_rs::signature::KeyPair as _;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let components: aws_lc_rs::signature::RsaPublicKeyComponents<Vec<u8>> = key.public_key().into();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("https://localhost:{}", listener.local_addr().unwrap().port());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let thumbprint = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &cert_der)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(cert_der)],
                rustls_pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let discovery = serde_json::json!({"issuer": issuer, "jwks_uri": format!("{issuer}/keys")}).to_string();
        let jwks = serde_json::json!({"keys": [{
            "kty": "RSA", "kid": "idp-key", "alg": "RS256", "use": "sig",
            "n": b64.encode(&components.n), "e": b64.encode(&components.e)
        }]})
        .to_string();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let (discovery, jwks) = (discovery.clone(), jwks.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let mut buf = vec![0u8; 4096];
                    let n = tls.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = request.split(' ').nth(1).unwrap_or("/");
                    let (status, body) = match path {
                        "/.well-known/openid-configuration" => ("200 OK", discovery),
                        "/keys" => ("200 OK", jwks),
                        _ => ("404 Not Found", String::new()),
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(response.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self { issuer, thumbprint, key, _server: server }
    }

    /// The provider URL as IAM stores it (without the scheme), which is
    /// also the prefix of its condition keys.
    pub fn host(&self) -> &str {
        self.issuer.trim_start_matches("https://")
    }

    /// An RS256 ID token with these claims (`iss` is filled in).
    pub fn token(&self, mut claims: serde_json::Value) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        claims["iss"] = serde_json::Value::from(self.issuer.clone());
        let signing_input = format!(
            "{}.{}",
            b64.encode(r#"{"alg":"RS256","typ":"JWT","kid":"idp-key"}"#),
            b64.encode(claims.to_string())
        );
        let mut sig = vec![0; self.key.public_modulus_len()];
        self.key
            .sign(
                &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                signing_input.as_bytes(),
                &mut sig,
            )
            .unwrap();
        format!("{signing_input}.{}", b64.encode(sig))
    }
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
