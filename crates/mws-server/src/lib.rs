//! The MWS front door.
//!
//! [`Gateway`] receives every HTTP request, verifies its SigV4 signature
//! against the registered [`CredentialStore`]s, builds a
//! [`RequestContext`], and hands the request to the [`Service`] whose signing
//! name matches the credential scope. It does not know any service by name.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use mws_core::{
    Authorizer, Caller, CredentialError, CredentialStore, Environment, HttpRequest, HttpResponse, RequestContext,
    ResolvedCredential, Service, ServiceError,
};
use mws_sigv4::{SigV4Error, VerifyOptions};
use tokio::net::TcpListener;

/// Largest request body MWS accepts.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Routes authenticated requests to services.
pub struct Gateway {
    services: BTreeMap<&'static str, Arc<dyn Service>>,
    /// Renders errors for requests we cannot attribute to a service.
    fallback: Option<Arc<dyn Service>>,
    credentials: Vec<Arc<dyn CredentialStore>>,
    authorizer: Arc<dyn Authorizer>,
    env: Environment,
}

pub struct GatewayBuilder {
    gateway: Gateway,
}

impl GatewayBuilder {
    /// Register a service under its signing name. The first service
    /// registered also renders errors for requests that name no service.
    pub fn service(mut self, service: Arc<dyn Service>) -> Self {
        if self.gateway.fallback.is_none() {
            self.gateway.fallback = Some(service.clone());
        }
        self.gateway.services.insert(service.signing_name(), service);
        self
    }

    /// Add a credential store. Stores are asked in registration order.
    pub fn credentials(mut self, store: Arc<dyn CredentialStore>) -> Self {
        self.gateway.credentials.push(store);
        self
    }

    pub fn authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.gateway.authorizer = authorizer;
        self
    }

    pub fn environment(mut self, env: Environment) -> Self {
        self.gateway.env = env;
        self
    }

    pub fn build(self) -> Gateway {
        self.gateway
    }
}

impl Gateway {
    pub fn builder() -> GatewayBuilder {
        GatewayBuilder {
            gateway: Gateway {
                services: BTreeMap::new(),
                fallback: None,
                credentials: Vec::new(),
                authorizer: Arc::new(mws_core::AllowAll),
                env: Environment::default(),
            },
        }
    }

    pub fn service_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.services.keys().copied()
    }

    /// Handle one request whose body has already been read.
    pub async fn handle(&self, request: HttpRequest, remote: Option<SocketAddr>) -> HttpResponse {
        let request_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        if request.uri().path() == "/_mws/health" {
            return self.health();
        }

        let parsed = match mws_sigv4::parse(&request) {
            Ok(p) => p,
            Err(SigV4Error::Missing) => {
                let unsigned = self.services.values().find(|s| s.accepts_unsigned(&request)).cloned();
                return match unsigned {
                    Some(service) => {
                        let ctx =
                            self.context(request_id, self.env.default_region.clone(), Caller::anonymous(), remote, now);
                        service.handle(ctx, request).await
                    }
                    None => self.fallback_error(&request_id, &ServiceError::missing_authentication_token()),
                };
            }
            Err(e) => return self.fallback_error(&request_id, &sigv4_error(e)),
        };

        let Some(service) = self.services.get(parsed.scope.service.as_str()).cloned() else {
            let err = ServiceError::client(
                "UnknownService",
                400,
                format!("MWS does not emulate the service '{}'.", parsed.scope.service),
            );
            return self.fallback_error(&request_id, &err);
        };

        let resolved = match self.resolve(&parsed.scope.access_key_id, parsed.session_token.as_deref(), now) {
            Ok(r) => r,
            Err(e) => return service.render_error(&request_id, &e.into_service_error()),
        };

        if let Err(e) = mws_sigv4::verify(&request, &parsed, &resolved.secret_access_key, now, VerifyOptions::default())
        {
            tracing::debug!(
                canonical_request = %mws_sigv4::canonical_request(&request, &parsed, VerifyOptions::default()),
                "signature verification failed: {e}"
            );
            return service.render_error(&request_id, &sigv4_error(e));
        }

        let ctx = self.context(request_id, parsed.scope.region.clone(), resolved.caller, remote, now);
        service.handle(ctx, request).await
    }

    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: chrono::DateTime<Utc>,
    ) -> Result<ResolvedCredential, CredentialError> {
        for store in &self.credentials {
            if let Some(found) = store.resolve(access_key_id, session_token, now)? {
                return Ok(found);
            }
        }
        Err(CredentialError::UnknownAccessKey)
    }

    fn context(
        &self,
        request_id: String,
        region: String,
        caller: Caller,
        remote: Option<SocketAddr>,
        now: chrono::DateTime<Utc>,
    ) -> RequestContext {
        RequestContext {
            request_id,
            region,
            partition: self.env.partition.clone(),
            received_at: now,
            caller,
            source_ip: remote.map(|a| a.ip().to_string()),
            secure_transport: false,
            authorizer: self.authorizer.clone(),
        }
    }

    fn fallback_error(&self, request_id: &str, err: &ServiceError) -> HttpResponse {
        match &self.fallback {
            Some(s) => s.render_error(request_id, err),
            None => {
                http::Response::builder().status(err.status).body(Bytes::from(err.to_string())).expect("valid response")
            }
        }
    }

    fn health(&self) -> HttpResponse {
        let services: Vec<String> = self.services.keys().map(|s| format!("\"{s}\"")).collect();
        http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(format!("{{\"status\":\"ok\",\"services\":[{}]}}", services.join(","))))
            .expect("valid response")
    }
}

fn sigv4_error(e: SigV4Error) -> ServiceError {
    match e {
        SigV4Error::Missing => ServiceError::missing_authentication_token(),
        SigV4Error::Incomplete(msg) => ServiceError::incomplete_signature(msg),
        SigV4Error::UnsupportedAlgorithm(a) => {
            ServiceError::incomplete_signature(format!("Unsupported AWS 'algorithm': '{a}'"))
        }
        e @ SigV4Error::Expired { .. } => ServiceError::client("SignatureDoesNotMatch", 403, e.to_string()),
        SigV4Error::PresignExpired => ServiceError::client("AccessDenied", 403, "Request has expired"),
        SigV4Error::Mismatch => ServiceError::signature_does_not_match(),
    }
}

/// Serve `gateway` on `listener` until `shutdown` resolves.
pub async fn serve(listener: TcpListener, gateway: Arc<Gateway>, shutdown: impl Future<Output = ()>) {
    tokio::pin!(shutdown);
    loop {
        let (stream, remote) = tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    continue;
                }
            },
        };
        let gateway = gateway.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: http::Request<Incoming>| {
                let gateway = gateway.clone();
                async move { Ok::<_, std::convert::Infallible>(handle_incoming(&gateway, req, remote).await) }
            });
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                tracing::debug!("connection from {remote} ended: {e}");
            }
        });
    }
}

async fn handle_incoming(
    gateway: &Gateway,
    req: http::Request<Incoming>,
    remote: SocketAddr,
) -> http::Response<Full<Bytes>> {
    let started = Instant::now();
    let (parts, body) = req.into_parts();
    let body = match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return http::Response::builder()
                .status(413)
                .body(Full::new(Bytes::from(format!("request body rejected: {e}"))))
                .expect("valid response");
        }
    };
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let response = gateway.handle(http::Request::from_parts(parts, body), Some(remote)).await;
    tracing::info!(
        %method,
        %path,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "request"
    );
    response.map(Full::new)
}
