//! The MWS front door.
//!
//! [`Gateway`] receives every HTTP request, verifies its SigV4 signature
//! against the registered [`CredentialStore`]s, builds a
//! [`RequestContext`], and hands the request to the [`Service`] whose signing
//! name matches the credential scope. It does not know any service by name.
//!
//! It also serves the MWS control API under `/_mws/` (see [`admin`]):
//! export, import, reset and snapshot the whole emulator's state, and run
//! [`scenario`] files. With a [`Store`] attached, state is saved to disk
//! shortly after every change and restored at startup.

mod admin;
pub mod scenario;
mod state;

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use mws_core::{
    ApiCall, ApiCallObserver, Authorizer, Caller, CredentialError, CredentialStore, Environment, HttpRequest,
    HttpResponse, RecordingAuthorizer, RequestContext, RequestObserver, ResolvedCredential, Service, ServiceError,
    StreamingBody,
};
use mws_sigv4::{SigV4Error, VerifyOptions};
pub use mws_store::Store;
pub use scenario::Scenario;
pub use state::{ScenarioError, SnapshotInfo, STATE_FORMAT};
use tokio::net::TcpListener;

/// Largest request body MWS accepts: S3's 5 GiB single-request limit.
const MAX_BODY_BYTES: usize = 5 << 30;

/// Routes authenticated requests to services.
pub struct Gateway {
    /// Services by signing name, in registration order.
    services: BTreeMap<&'static str, Vec<Arc<dyn Service>>>,
    /// Services by [`Service::name`], for state and scenarios.
    named: BTreeMap<&'static str, Arc<dyn Service>>,
    /// Further signing names, by the service they belong to.
    aliases: BTreeMap<&'static str, &'static str>,
    /// Renders errors for requests we cannot attribute to a service.
    fallback: Option<Arc<dyn Service>>,
    credentials: Vec<Arc<dyn CredentialStore>>,
    authorizer: Arc<dyn Authorizer>,
    env: Environment,
    state: state::StateHub,
    /// How far the emulated clock runs ahead of the wall clock, in
    /// milliseconds (`/_mws/clock`). Services see it in
    /// `RequestContext::received_at`; signature checks use the wall clock,
    /// since SDKs sign with it.
    clock_offset_ms: std::sync::atomic::AtomicI64,
    /// Where [`serve`] listens, as a URL.
    endpoint: std::sync::OnceLock<String>,
    /// Told about every signed request routed to a service, with the
    /// actions it authorized (Service Quotas, Cost Explorer).
    request_observers: Vec<Arc<dyn RequestObserver>>,
    /// Told about every API call a service handled (CloudTrail).
    observers: Vec<Arc<dyn ApiCallObserver>>,
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
        for alias in service.signing_aliases() {
            self.gateway.aliases.insert(alias, service.signing_name());
        }
        self.gateway.named.insert(service.name(), service.clone());
        self.gateway.services.entry(service.signing_name()).or_default().push(service);
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

    /// Tell `observer` about every signed request once it is answered.
    pub fn request_observer(mut self, observer: Arc<dyn RequestObserver>) -> Self {
        self.gateway.request_observers.push(observer);
        self
    }

    /// Tell `observer` about every API call services handle.
    pub fn observer(mut self, observer: Arc<dyn ApiCallObserver>) -> Self {
        self.gateway.observers.push(observer);
        self
    }

    pub fn environment(mut self, env: Environment) -> Self {
        self.gateway.env = env;
        self
    }

    /// Persist state in `store` and restore it at startup.
    pub fn store(mut self, store: Arc<Store>) -> Self {
        self.gateway.state.store = Some(store);
        self
    }

    /// How long to wait after a change before writing state to the store.
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.gateway.state.flush_interval = interval;
        self
    }

    /// The access key whose identity runs scenario steps that do not name
    /// one (normally the account root's).
    pub fn scenario_principal(mut self, access_key_id: impl Into<String>) -> Self {
        self.gateway.state.scenario_access_key = Some(access_key_id.into());
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
                named: BTreeMap::new(),
                aliases: BTreeMap::new(),
                fallback: None,
                credentials: Vec::new(),
                authorizer: Arc::new(mws_core::AllowAll),
                env: Environment::default(),
                state: state::StateHub::default(),
                clock_offset_ms: std::sync::atomic::AtomicI64::new(0),
                endpoint: std::sync::OnceLock::new(),
                request_observers: Vec::new(),
                observers: Vec::new(),
            },
        }
    }

    pub fn service_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.named.keys().copied()
    }

    /// Handle one request whose body has already been read.
    pub async fn handle(&self, request: HttpRequest, remote: Option<SocketAddr>) -> HttpResponse {
        let request_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        if request.uri().path().starts_with(admin::PREFIX) {
            return self.admin(request).await;
        }
        let _gate = self.state.gate.read().await;
        let trace = mws_core::trace_header::of(&request);
        let work =
            mws_core::trace_header::scope(trace, self.handle_service_request(request_id.clone(), request, remote, now));
        // A panic in a handler answers 500 InternalFailure, as AWS would,
        // instead of resetting the connection (which SDKs retry).
        let response = match (CatchUnwind { inner: Box::pin(work) }).await {
            Ok(r) => r,
            Err(()) => {
                tracing::error!(%request_id, "a handler panicked");
                self.fallback_error(
                    &request_id,
                    &ServiceError::internal("We encountered an internal error. Please try again."),
                )
            }
        };
        self.mark_dirty();
        response
    }

    async fn handle_service_request(
        &self,
        request_id: String,
        request: HttpRequest,
        remote: Option<SocketAddr>,
        now: chrono::DateTime<Utc>,
    ) -> HttpResponse {
        if let Some(service) = self.services.values().flatten().find(|s| s.serves_unauthenticated(&request)).cloned() {
            let ctx = self.context(request_id, self.env.default_region.clone(), Caller::anonymous(), remote, now);
            return service.handle(ctx, request).await;
        }
        for service in self.services.values().flatten() {
            let Some(alternate) = service.alternate_signature(&request) else { continue };
            let service = service.clone();
            let alternate = match alternate {
                Ok(a) => a,
                Err(e) => return service.render_error(&request_id, &e),
            };
            let resolved = match self.resolve(&alternate.access_key_id, alternate.session_token.as_deref(), now) {
                Ok(r) => r,
                Err(e) => return service.render_error(&request_id, &e.into_service_error()),
            };
            if let Err(e) = (alternate.verify)(&resolved.secret_access_key, now) {
                return service.render_error(&request_id, &e);
            }
            let region = alternate.region.unwrap_or_else(|| self.env.default_region.clone());
            let ctx = self.context(request_id, region, resolved.caller, remote, now);
            return self.dispatch(&service, ctx, request).await;
        }
        let parsed = match mws_sigv4::parse(&request) {
            Ok(p) => p,
            Err(SigV4Error::Missing) => {
                // A request that names its service (an `X-Amz-Target`, a
                // dated REST path) is that service's to accept or refuse.
                let recognized = self.services.values().flatten().find(|s| s.recognizes(&request)).cloned();
                let unsigned = match &recognized {
                    Some(s) => s.accepts_unsigned(&request).then(|| s.clone()),
                    None => self.services.values().flatten().find(|s| s.accepts_unsigned(&request)).cloned(),
                };
                return match (unsigned, recognized) {
                    (Some(service), _) => {
                        let ctx =
                            self.context(request_id, self.env.default_region.clone(), Caller::anonymous(), remote, now);
                        self.dispatch(&service, ctx, request).await
                    }
                    (None, Some(service)) => {
                        service.render_error(&request_id, &ServiceError::missing_authentication_token())
                    }
                    (None, None) => self.fallback_error(&request_id, &ServiceError::missing_authentication_token()),
                };
            }
            Err(e) => {
                // Services with their own credentials (CodeArtifact
                // repository endpoints take `Bearer` and `Basic` tokens)
                // check a non-SigV4 `Authorization` header themselves.
                if let Some(service) =
                    self.services.values().flatten().find(|s| s.recognizes(&request) && s.accepts_unsigned(&request))
                {
                    let ctx =
                        self.context(request_id, self.env.default_region.clone(), Caller::anonymous(), remote, now);
                    return service.handle(ctx, request).await;
                }
                let err = sigv4_error(e);
                return match self.services.values().flatten().find(|s| s.recognizes(&request)) {
                    // An `Authorization` header of the service's own that
                    // names no caller (a registry's anonymous bearer token).
                    Some(service) if service.anonymous_credentials(&request) => {
                        let ctx =
                            self.context(request_id, self.env.default_region.clone(), Caller::anonymous(), remote, now);
                        service.handle(ctx, request).await
                    }
                    Some(service) => service.render_error(&request_id, &err),
                    None => self.fallback_error(&request_id, &err),
                };
            }
        };

        let name = parsed.scope.service.as_str();
        let name = self.aliases.get(name).copied().unwrap_or(name);
        let candidates = self.services.get(name);
        let service = candidates.and_then(|c| c.iter().find(|s| s.claims(&request)).or_else(|| c.first())).cloned();
        let Some(service) = service else {
            let err = ServiceError::client(
                "UnknownService",
                400,
                format!("MWS does not emulate the service '{}'.", parsed.scope.service),
            );
            return self.fallback_error(&request_id, &err);
        };

        let session_token = parsed.session_token.clone().or_else(|| service.session_token(&request));
        let resolved = match self.resolve(&parsed.scope.access_key_id, session_token.as_deref(), now) {
            Ok(r) => r,
            Err(e) => return service.render_error(&request_id, &e.into_service_error()),
        };

        let options = VerifyOptions { double_encode_path: !service.signs_raw_path() };
        if let Err(e) = mws_sigv4::verify(&request, &parsed, &resolved.secret_access_key, now, options) {
            tracing::debug!(
                canonical_request = %mws_sigv4::canonical_request(&request, &parsed, options),
                "signature verification failed: {e}"
            );
            return service.render_error(&request_id, &sigv4_error(e));
        }
        let request = match mws_sigv4::check_payload(&request, &parsed, &resolved.secret_access_key) {
            Ok(None) => request,
            Ok(Some(decoded)) => replace_chunked_body(request, decoded),
            Err(e) => return service.render_error(&request_id, &sigv4_error(e)),
        };

        // A SigV4a request valid in every Region (`X-Amz-Region-Set: *`)
        // runs in the default Region.
        let region = match parsed.scope.region.as_str() {
            "" => self.env.default_region.clone(),
            r => r.to_string(),
        };
        let ctx = self.context(request_id, region, resolved.caller, remote, now);
        self.dispatch(&service, ctx, request).await
    }

    /// Hand a signed request to its service, recording the actions it
    /// authorizes for the request observers and telling the API call
    /// observers about the call it made.
    async fn dispatch(&self, service: &Arc<dyn Service>, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        // Deliveries the handler deferred run before the response goes out.
        mws_core::deferred::run(self.dispatch_now(service, ctx, request)).await
    }

    async fn dispatch_now(
        &self,
        service: &Arc<dyn Service>,
        mut ctx: RequestContext,
        request: HttpRequest,
    ) -> HttpResponse {
        if self.observers.is_empty() && self.request_observers.is_empty() {
            return service.handle(ctx, request).await;
        }
        let recorder = (!self.request_observers.is_empty()).then(|| {
            let recorder = Arc::new(RecordingAuthorizer::new(ctx.authorizer.clone()));
            ctx.authorizer = recorder.clone();
            recorder
        });
        let request_call = ApiCall {
            request_id: ctx.request_id.clone(),
            service: service.signing_name(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            at: ctx.received_at,
            actions: Vec::new(),
            status: 0,
        };
        let response = if self.observers.is_empty() {
            service.handle(ctx, request).await
        } else {
            let header = |name: http::header::HeaderName| {
                request.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
            };
            let mut facts = mws_core::trail::HttpFacts {
                user_agent: header(http::header::USER_AGENT),
                host: header(http::header::HOST),
                status: 0,
            };
            let (response, call) = mws_core::trail::watch(service.handle(ctx.clone(), request)).await;
            if let Some(call) = call {
                facts.status = response.status().as_u16();
                for o in &self.observers {
                    o.observe(&ctx, &call, &facts);
                }
            }
            response
        };
        if let Some(recorder) = recorder {
            let call = ApiCall { actions: recorder.actions(), status: response.status().as_u16(), ..request_call };
            for observer in &self.request_observers {
                observer.observe(&call);
            }
        }
        response
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
            received_at: self.emulated_time(now),
            caller,
            source_ip: remote.map(|a| a.ip().to_string()),
            secure_transport: false,
            authorizer: self.authorizer.clone(),
            endpoint: self.endpoint.get().cloned(),
        }
    }

    /// The emulated time for a wall-clock instant.
    pub fn emulated_time(&self, wall: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
        wall + chrono::Duration::milliseconds(self.clock_offset_ms.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Move the emulated clock: it then runs `offset` ahead of the wall
    /// clock (never behind).
    pub fn set_clock_offset(&self, offset: chrono::Duration) {
        let ms = offset.num_milliseconds().max(0);
        self.clock_offset_ms.store(ms, std::sync::atomic::Ordering::Relaxed);
    }

    /// The URL MWS serves on, once [`serve`] has started (or
    /// [`Gateway::set_endpoint`] was called).
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.get().map(String::as_str)
    }

    /// Record the URL MWS is reachable at. The first call wins.
    pub fn set_endpoint(&self, url: impl Into<String>) {
        let _ = self.endpoint.set(url.into());
    }

    pub fn clock_offset(&self) -> chrono::Duration {
        chrono::Duration::milliseconds(self.clock_offset_ms.load(std::sync::atomic::Ordering::Relaxed))
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
        let services: Vec<String> = self.named.keys().map(|s| format!("\"{s}\"")).collect();
        http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(format!("{{\"status\":\"ok\",\"services\":[{}]}}", services.join(","))))
            .expect("valid response")
    }
}

/// Swap an `aws-chunked` body for its decoded content, as if the client had
/// sent it plainly: trailers become headers and `aws-chunked` leaves
/// `Content-Encoding`.
fn replace_chunked_body(request: HttpRequest, decoded: mws_sigv4::DecodedChunks) -> HttpRequest {
    let (mut parts, _) = request.into_parts();
    for (k, v) in decoded.trailers {
        if let (Ok(k), Ok(v)) = (http::HeaderName::try_from(k), http::HeaderValue::try_from(v)) {
            parts.headers.insert(k, v);
        }
    }
    let encoding = parts.headers.get(http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).map(|v| {
        v.split(',').map(str::trim).filter(|e| !e.eq_ignore_ascii_case("aws-chunked")).collect::<Vec<_>>().join(",")
    });
    match encoding {
        Some(e) if !e.is_empty() => {
            if let Ok(v) = http::HeaderValue::try_from(e) {
                parts.headers.insert(http::header::CONTENT_ENCODING, v);
            }
        }
        _ => {
            parts.headers.remove(http::header::CONTENT_ENCODING);
        }
    }
    parts.headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(decoded.body.len()));
    http::Request::from_parts(parts, Bytes::from(decoded.body))
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
        e @ SigV4Error::ContentSha256Mismatch => ServiceError::client("XAmzContentSHA256Mismatch", 400, e.to_string()),
        SigV4Error::MalformedChunks(m) => ServiceError::client("IncompleteBody", 400, m),
    }
}

/// Serve `gateway` on `listener` until `shutdown` resolves. With a store
/// attached, state is written in the background while serving and once more
/// on the way out.
pub async fn serve(listener: TcpListener, gateway: Arc<Gateway>, shutdown: impl Future<Output = ()>) {
    if let Ok(addr) = listener.local_addr() {
        let ip = if addr.ip().is_unspecified() { "127.0.0.1".to_string() } else { addr.ip().to_string() };
        let host = if ip.contains(':') { format!("[{ip}]") } else { ip };
        gateway.set_endpoint(format!("http://{host}:{}", addr.port()));
    }
    let persist = gateway.state.store.is_some().then(|| tokio::spawn(gateway.clone().persist_loop()));
    serve_until(listener, gateway.clone(), shutdown).await;
    if let Some(task) = persist {
        task.abort();
        gateway.flush().await;
    }
}

async fn serve_until(listener: TcpListener, gateway: Arc<Gateway>, shutdown: impl Future<Output = ()>) {
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

/// A response body: the bytes in the response, then, for a
/// [`StreamingBody`] response, whatever its sender produces.
enum ResponseBody {
    Full(Full<Bytes>),
    Streaming { head: Option<Bytes>, rest: tokio::sync::mpsc::Receiver<Bytes> },
}

impl hyper::body::Body for ResponseBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        match self.get_mut() {
            ResponseBody::Full(b) => std::pin::Pin::new(b).poll_frame(cx),
            ResponseBody::Streaming { head, rest } => {
                if let Some(h) = head.take().filter(|h| !h.is_empty()) {
                    return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(h))));
                }
                rest.poll_recv(cx).map(|c| c.map(|c| Ok(hyper::body::Frame::data(c))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ResponseBody::Full(b) => b.is_end_stream(),
            ResponseBody::Streaming { .. } => false,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            ResponseBody::Full(b) => b.size_hint(),
            ResponseBody::Streaming { .. } => hyper::body::SizeHint::default(),
        }
    }
}

async fn handle_incoming(
    gateway: &Gateway,
    req: http::Request<Incoming>,
    remote: SocketAddr,
) -> http::Response<ResponseBody> {
    let started = Instant::now();
    let (parts, body) = req.into_parts();
    let body = match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return http::Response::builder()
                .status(413)
                .body(ResponseBody::Full(Full::new(Bytes::from(format!("request body rejected: {e}")))))
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
    let streaming = response.extensions().get::<StreamingBody>().and_then(StreamingBody::take);
    match streaming {
        Some(rest) => response.map(|head| ResponseBody::Streaming { head: Some(head), rest }),
        None => response.map(|b| ResponseBody::Full(Full::new(b))),
    }
}

/// Polls `inner`, turning a panic into `Err(())`.
struct CatchUnwind<'a, T> {
    inner: std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>,
}

impl<T> std::future::Future for CatchUnwind<'_, T> {
    type Output = Result<T, ()>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let inner = self.inner.as_mut();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx))) {
            Ok(std::task::Poll::Ready(v)) => std::task::Poll::Ready(Ok(v)),
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Err(_) => std::task::Poll::Ready(Err(())),
        }
    }
}
