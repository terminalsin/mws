//! TLS for HTTPS and TLS listeners: certificates come from ACM (chosen by
//! SNI among the listener's default and added certificates), protocol
//! versions from the listener's security policy, and client certificates
//! are checked against the listener's trust store for mutual TLS.

use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpStream;

use crate::Elb;

/// What a listener serves TLS with.
#[derive(Clone, Default)]
pub(crate) struct TlsSettings {
    pub certificates: Vec<String>,
    pub policy: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    /// `verify` or `passthrough` mutual TLS, with the trust store's PEM
    /// bundle and revoked serials for `verify`.
    pub mutual: Option<(String, String, Vec<Vec<u8>>, bool)>,
}

/// Negotiated details the data plane passes on as headers.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsInfo {
    pub version: String,
    pub cipher: String,
    pub client_chain: Vec<Vec<u8>>,
    /// The SNI name the client sent.
    pub sni: Option<String>,
    /// The listener's default certificate.
    pub certificate: Option<String>,
}

struct Candidate {
    names: Vec<String>,
    key: Arc<CertifiedKey>,
}

#[derive(Debug)]
struct SniResolver {
    candidates: Vec<(Vec<String>, Arc<CertifiedKey>)>,
}

impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate").field("names", &self.names).finish()
    }
}

fn name_matches(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.split_once('.').is_some_and(|(_, rest)| rest == suffix),
        None => pattern == host,
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = hello.server_name() {
            if let Some((_, key)) = self.candidates.iter().find(|(names, _)| names.iter().any(|n| name_matches(n, sni)))
            {
                return Some(key.clone());
            }
        }
        // ELB falls back to the listener's default certificate.
        self.candidates.first().map(|(_, k)| k.clone())
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn load(elb: &Elb, arn: &str) -> Option<Candidate> {
    let c = elb.acm()?.server_certificate(arn)?;
    let mut chain: Vec<CertificateDer<'static>> = Vec::new();
    for pem in [c.certificate_pem.as_deref(), c.chain_pem.as_deref()].into_iter().flatten() {
        chain.extend(CertificateDer::pem_slice_iter(pem.as_bytes()).filter_map(Result::ok));
    }
    let key: PrivateKeyDer<'static> = match c.key? {
        mws_acm::ServerKey::Pkcs8Der(der) => PrivateKeyDer::Pkcs8(der.into()),
        mws_acm::ServerKey::Pem(pem) => PrivateKeyDer::from_pem_slice(&pem).ok()?,
    };
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).ok()?;
    let mut names = vec![c.domain_name.clone()];
    names.extend(c.subject_alternative_names);
    Some(Candidate { names, key: Arc::new(CertifiedKey::new(chain, signing)) })
}

/// A server config for `settings`, or `None` if no certificate loads.
pub(crate) fn server_config(elb: &Elb, settings: &TlsSettings) -> Option<Arc<rustls::ServerConfig>> {
    let candidates: Vec<_> =
        settings.certificates.iter().filter_map(|a| load(elb, a)).map(|c| (c.names, c.key)).collect();
    if candidates.is_empty() {
        return None;
    }
    let protocols = settings
        .policy
        .as_deref()
        .and_then(crate::catalog::ssl_policy)
        .map(|(_, p, _)| p)
        .unwrap_or_else(|| vec!["TLSv1.2", "TLSv1.3"]);
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
    if protocols.contains(&"TLSv1.3") {
        versions.push(&rustls::version::TLS13);
    }
    if protocols.iter().any(|p| matches!(*p, "TLSv1.2" | "TLSv1.1" | "TLSv1")) {
        versions.push(&rustls::version::TLS12);
    }
    let builder = rustls::ServerConfig::builder_with_provider(provider()).with_protocol_versions(&versions).ok()?;
    let resolver = Arc::new(SniResolver { candidates });
    let mut config = match &settings.mutual {
        Some((mode, bundle, crls, _)) if mode == "verify" => {
            let mut roots = rustls::RootCertStore::empty();
            for c in CertificateDer::pem_slice_iter(bundle.as_bytes()).filter_map(Result::ok) {
                let _ = roots.add(c);
            }
            let crls: Vec<rustls_pki_types::CertificateRevocationListDer<'static>> =
                crls.iter().map(|d| d.clone().into()).collect();
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                .with_crls(crls)
                .allow_unknown_revocation_status()
                .build()
                .ok()?;
            builder.with_client_cert_verifier(verifier).with_cert_resolver(resolver)
        }
        Some((mode, _, _, _)) if mode == "passthrough" => {
            builder.with_client_cert_verifier(Arc::new(AcceptAnyClient(provider()))).with_cert_resolver(resolver)
        }
        _ => builder.with_no_client_auth().with_cert_resolver(resolver),
    };
    config.alpn_protocols = settings.alpn.clone();
    Some(Arc::new(config))
}

/// Accepts any client certificate (mTLS passthrough: targets decide).
#[derive(Debug)]
struct AcceptAnyClient(Arc<rustls::crypto::CryptoProvider>);

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClient {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Load balancers do not validate target certificates.
#[derive(Debug)]
struct AcceptAnyServer(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS to a target, without checking its certificate.
pub(crate) async fn connect_insecure(
    stream: TcpStream,
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    connect_insecure_alpn(stream, addr, Vec::new()).await
}

pub(crate) async fn connect_insecure_alpn(
    stream: TcpStream,
    addr: std::net::SocketAddr,
    alpn: Vec<Vec<u8>>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let p = provider();
    let mut config = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer(p)))
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    let name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
    tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream).await
}

/// TLS to `host` (SNI), without verifying its certificate: identity
/// providers that load balancers call (token, user info and JWKS
/// endpoints), which locally are usually self-signed.
pub(crate) async fn connect_insecure_named(
    stream: TcpStream,
    host: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let p = provider();
    let mut config = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer(p)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls_pki_types::ServerName::try_from(host.to_string()).map_err(std::io::Error::other)?;
    tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream).await
}

/// What a finished handshake negotiated.
pub(crate) fn info(conn: &rustls::ServerConnection) -> TlsInfo {
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "",
    };
    let cipher = conn.negotiated_cipher_suite().map(|c| openssl_cipher_name(c.suite())).unwrap_or_default();
    TlsInfo {
        version: version.into(),
        cipher,
        client_chain: conn.peer_certificates().map(|c| c.iter().map(|d| d.to_vec()).collect()).unwrap_or_default(),
        sni: conn.server_name().map(str::to_string),
        certificate: None,
    }
}

fn openssl_cipher_name(s: rustls::CipherSuite) -> String {
    use rustls::CipherSuite as C;
    match s {
        C::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        C::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        C::TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "ECDHE-ECDSA-AES128-GCM-SHA256",
        C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "ECDHE-RSA-AES128-GCM-SHA256",
        C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "ECDHE-ECDSA-AES256-GCM-SHA384",
        C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "ECDHE-RSA-AES256-GCM-SHA384",
        C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-RSA-CHACHA20-POLY1305",
        other => return format!("{other:?}"),
    }
    .to_string()
}
