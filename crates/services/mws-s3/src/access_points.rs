//! Access points and S3 Object Lambda on the data plane.
//!
//! S3 Control owns access points and Object Lambda access points; it
//! publishes them to S3 through [`AccessPointDirectory`]. Requests can name
//! an access point by host (`{name}-{account}.{endpoint}`, as SDKs address
//! access point ARNs) or by alias as the bucket (`{name}-{suffix}-s3alias`,
//! `{name}-{suffix}--ol-s3`). Requests through an access point are
//! authorized against the access point (identity policies plus its policy)
//! and the bucket (its policy), as S3 does.
//!
//! An Object Lambda access point runs a Lambda function for the operations
//! it transforms. For `GetObject` the function receives a `getObjectContext`
//! with a presigned `inputS3Url` for the original object and answers with
//! `WriteGetObjectResponse`, which S3 returns to the waiting caller. Lambda
//! runs the function through [`ObjectLambdaInvoker`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use mws_core::{CallerKind, ConditionContext, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use serde_json::{json, Value};

use crate::generated::types;
use crate::{Call, S3};

/// An access point, as S3 Control describes it to S3.
#[derive(Debug, Clone, Default)]
pub struct AccessPoint {
    pub name: String,
    pub arn: String,
    pub account_id: String,
    pub bucket: String,
    pub alias: String,
    /// `Internet` or `VPC`.
    pub network_origin: String,
    pub policy: Option<String>,
    /// The access point's own Block Public Access settings.
    pub restrict_public_buckets: bool,
}

/// A transformation of an Object Lambda access point.
#[derive(Debug, Clone, Default)]
pub struct Transformation {
    /// `GetObject`, `HeadObject`, `ListObjects`, `ListObjectsV2`.
    pub actions: Vec<String>,
    pub function_arn: String,
    pub payload: Option<String>,
}

/// An Object Lambda access point.
#[derive(Debug, Clone, Default)]
pub struct ObjectLambdaAccessPoint {
    pub name: String,
    pub arn: String,
    pub account_id: String,
    pub alias: String,
    pub supporting_access_point: String,
    /// `GetObject-Range`, `GetObject-PartNumber`, `HeadObject-Range`,
    /// `HeadObject-PartNumber`.
    pub allowed_features: Vec<String>,
    pub transformations: Vec<Transformation>,
    pub policy: Option<String>,
}

/// Account-level Block Public Access (`s3control:PutPublicAccessBlock`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountPublicAccessBlock {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

/// What S3 Control tells S3 about access points.
pub trait AccessPointDirectory: Send + Sync {
    fn access_point(&self, account_id: &str, name: &str) -> Option<AccessPoint>;
    fn access_point_by_alias(&self, alias: &str) -> Option<AccessPoint>;
    fn object_lambda(&self, account_id: &str, name: &str) -> Option<ObjectLambdaAccessPoint>;
    fn object_lambda_by_alias(&self, alias: &str) -> Option<ObjectLambdaAccessPoint>;
    fn account_public_access_block(&self, account_id: &str) -> Option<AccountPublicAccessBlock>;
}

/// The result of running a function synchronously.
#[derive(Debug, Clone, Default)]
pub struct LambdaInvocation {
    pub payload: Vec<u8>,
    /// `Unhandled` or the error type, when the function failed.
    pub function_error: Option<String>,
}

/// Runs Object Lambda functions (implemented by Lambda).
#[async_trait::async_trait]
pub trait ObjectLambdaInvoker: Send + Sync {
    /// Invoke `function_arn` synchronously with `event`, authorized as the
    /// caller in `ctx` (`lambda:InvokeFunction`). Errors carry Lambda's
    /// error codes.
    async fn invoke(
        &self,
        ctx: &RequestContext,
        function_arn: &str,
        event: Vec<u8>,
    ) -> Result<LambdaInvocation, ServiceError>;
}

/// A `GetObject` waiting for its `WriteGetObjectResponse`.
struct Pending {
    route: String,
    reply: tokio::sync::oneshot::Sender<HttpResponse>,
}

/// Temporary credentials S3 Object Lambda signs an `inputS3Url` with:
/// they act as the caller of the original request.
#[derive(Clone)]
struct InputSession {
    secret: String,
    token: String,
    caller: mws_core::Caller,
    expires: chrono::DateTime<chrono::Utc>,
}

/// Resolves the credentials `inputS3Url`s are signed with.
struct InputSessionStore(Arc<Mutex<HashMap<String, InputSession>>>);

impl mws_core::CredentialStore for InputSessionStore {
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<mws_core::ResolvedCredential>, mws_core::CredentialError> {
        let Ok(mut sessions) = self.0.lock() else { return Ok(None) };
        sessions.retain(|_, s| s.expires + chrono::Duration::minutes(1) > now);
        let Some(s) = sessions.get(access_key_id) else { return Ok(None) };
        if session_token != Some(s.token.as_str()) {
            return Err(mws_core::CredentialError::Invalid);
        }
        if s.expires <= now {
            return Err(mws_core::CredentialError::Expired);
        }
        let mut caller = s.caller.clone();
        caller.access_key_id = access_key_id.to_string();
        Ok(Some(mws_core::ResolvedCredential { secret_access_key: s.secret.clone(), caller }))
    }
}

/// How S3 reaches S3 Control and Lambda, and Object Lambda requests in
/// flight.
#[derive(Default)]
pub(crate) struct Links {
    directory: OnceLock<Arc<dyn AccessPointDirectory>>,
    invoker: OnceLock<Arc<dyn ObjectLambdaInvoker>>,
    pub(crate) quotas: OnceLock<mws_servicequotas::ServiceQuotas>,
    pending: Mutex<HashMap<String, Pending>>,
    input_sessions: Arc<Mutex<HashMap<String, InputSession>>>,
}

/// How long an `inputS3Url` stays valid.
const INPUT_URL_TTL_SECS: i64 = 3660;
const CALLED_VIA: &str = "s3-object-lambda.amazonaws.com";

impl S3 {
    /// Look access points up in S3 Control.
    pub fn set_access_points(&self, directory: Arc<dyn AccessPointDirectory>) {
        let _ = self.links.directory.set(directory);
    }

    /// Run Object Lambda functions through Lambda.
    pub fn set_object_lambda_invoker(&self, invoker: Arc<dyn ObjectLambdaInvoker>) {
        let _ = self.links.invoker.set(invoker);
    }

    pub(crate) fn directory(&self) -> Option<&Arc<dyn AccessPointDirectory>> {
        self.links.directory.get()
    }

    /// The account-level Block Public Access settings for `account`.
    pub(crate) fn account_pab(&self, account: &str) -> AccountPublicAccessBlock {
        self.directory().and_then(|d| d.account_public_access_block(account)).unwrap_or_default()
    }
}

/// The access point an S3 request addresses, after resolution.
pub(crate) enum Target {
    /// A plain bucket request (the request is unchanged).
    Bucket(HttpRequest),
    AccessPoint(HttpRequest, AccessPoint),
    ObjectLambda(HttpRequest, ObjectLambdaAccessPoint),
}

fn host_of(request: &HttpRequest) -> Option<String> {
    request
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| request.uri().authority().map(|a| a.to_string()))
}

/// `(name, account)` when the first host label is `{name}-{12 digits}`.
fn access_point_host(host: &str) -> Option<(String, String)> {
    let label = host.split('.').next()?;
    if !host.contains('.') {
        return None;
    }
    let (name, account) = label.rsplit_once('-')?;
    (account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit()) && !name.is_empty())
        .then(|| (name.to_ascii_lowercase(), account.to_string()))
}

/// The SigV4 service the request was signed for.
fn signing_service(request: &HttpRequest) -> Option<String> {
    let scope = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.split("Credential=").nth(1))
        .map(|c| c.split([',', ' ']).next().unwrap_or("").to_string())
        .or_else(|| crate::form_urlencoded_get(request.uri().query().unwrap_or(""), "X-Amz-Credential"))?;
    scope.split('/').nth(3).map(str::to_string)
}

/// Replace the request path with `/{bucket}{rest}`, keeping the query.
fn with_path(request: HttpRequest, bucket: &str, rest: &str) -> HttpRequest {
    let (mut parts, body) = request.into_parts();
    let mut new = format!("/{bucket}{}", if rest == "/" { "" } else { rest });
    if let Some(q) = parts.uri.query() {
        new.push('?');
        new.push_str(q);
    }
    if let Ok(uri) = new.parse() {
        parts.uri = uri;
    }
    // Drop the host so the virtual-host rewrite leaves the path alone.
    parts.headers.remove(http::header::HOST);
    http::Request::from_parts(parts, body)
}

fn split_first_segment(path: &str) -> (&str, &str) {
    let p = path.strip_prefix('/').unwrap_or(path);
    match p.find('/') {
        Some(i) => (&p[..i], &p[i..]),
        None => (p, "/"),
    }
}

impl S3 {
    /// Work out which bucket, access point or Object Lambda access point a
    /// request addresses.
    pub(crate) fn resolve_target(&self, request: HttpRequest) -> Target {
        let Some(dir) = self.directory().cloned() else { return Target::Bucket(crate::to_path_style(request)) };
        if let Some((name, account)) = host_of(&request).as_deref().and_then(access_point_host) {
            let object_lambda = signing_service(&request).as_deref() == Some("s3-object-lambda");
            if object_lambda {
                if let Some(olap) = dir.object_lambda(&account, &name) {
                    let path = request.uri().path().to_string();
                    return Target::ObjectLambda(with_path(request, &olap.alias, &path), olap);
                }
            } else if let Some(ap) = dir.access_point(&account, &name) {
                let path = request.uri().path().to_string();
                let bucket = ap.bucket.clone();
                return Target::AccessPoint(with_path(request, &bucket, &path), ap);
            }
        }
        let request = crate::to_path_style(request);
        let path = request.uri().path().to_string();
        let (first, rest) = split_first_segment(&path);
        if first.ends_with("--ol-s3") {
            if let Some(olap) = dir.object_lambda_by_alias(first) {
                return Target::ObjectLambda(request, olap);
            }
        } else if first.ends_with("-s3alias") {
            if let Some(ap) = dir.access_point_by_alias(first) {
                let bucket = ap.bucket.clone();
                let rest = rest.to_string();
                return Target::AccessPoint(with_path(request, &bucket, &rest), ap);
            }
        }
        Target::Bucket(request)
    }

    /// The service a request was made through on the caller's behalf: S3
    /// Object Lambda, for requests signed with an `inputS3Url`'s
    /// credentials.
    pub(crate) fn called_via(&self, ctx: &RequestContext) -> Option<&'static str> {
        let sessions = self.links.input_sessions.lock().ok()?;
        sessions.contains_key(&ctx.caller.access_key_id).then_some(CALLED_VIA)
    }

    /// The credential store for the temporary credentials `inputS3Url`s
    /// are signed with; register it with the gateway.
    pub fn object_lambda_credential_store(&self) -> Arc<dyn mws_core::CredentialStore> {
        Arc::new(InputSessionStore(self.links.input_sessions.clone()))
    }
}

/// Condition keys for a request through `ap`.
pub(crate) fn access_point_context(ap: &AccessPoint) -> ConditionContext {
    let mut c = ConditionContext::new();
    c.insert("s3:DataAccessPointArn".into(), vec![ap.arn.clone()]);
    c.insert("s3:DataAccessPointAccount".into(), vec![ap.account_id.clone()]);
    c.insert("s3:AccessPointNetworkOrigin".into(), vec![ap.network_origin.clone()]);
    c
}

pub(crate) fn called_via_context(c: &mut ConditionContext, via: &str) {
    c.insert("aws:CalledVia".into(), vec![via.to_string()]);
    c.insert("aws:CalledViaFirst".into(), vec![via.to_string()]);
    c.insert("aws:CalledViaLast".into(), vec![via.to_string()]);
    c.insert("aws:ViaAWSService".into(), vec!["true".into()]);
}

// ---- Object Lambda ---------------------------------------------------------

/// Which operation an Object Lambda request is.
fn olap_operation(request: &HttpRequest, key: &str) -> Option<&'static str> {
    let query = request.uri().query().unwrap_or("");
    let names: Vec<&str> =
        query.split('&').filter(|p| !p.is_empty()).map(|p| p.split('=').next().unwrap_or("")).collect();
    let object_params = |n: &&str| {
        matches!(*n, "versionId" | "partNumber" | "x-id") || n.starts_with("response-") || n.starts_with("X-Amz-")
    };
    match (request.method().clone(), key.is_empty()) {
        (http::Method::GET, false) if names.iter().all(object_params) => Some("GetObject"),
        (http::Method::HEAD, false) if names.iter().all(object_params) => Some("HeadObject"),
        (http::Method::GET, true) => {
            let list_params = |n: &&str| {
                matches!(
                    *n,
                    "list-type"
                        | "prefix"
                        | "delimiter"
                        | "max-keys"
                        | "marker"
                        | "continuation-token"
                        | "start-after"
                        | "fetch-owner"
                        | "encoding-type"
                        | "x-id"
                ) || n.starts_with("X-Amz-")
            };
            if !names.iter().all(list_params) {
                return None;
            }
            Some(if names.contains(&"list-type") { "ListObjectsV2" } else { "ListObjects" })
        }
        _ => None,
    }
}

fn user_identity(ctx: &RequestContext) -> Value {
    let c = &ctx.caller;
    let kind = match &c.kind {
        CallerKind::Root => "Root",
        CallerKind::User { .. } => "IAMUser",
        CallerKind::AssumedRole { .. } => "AssumedRole",
        CallerKind::FederatedUser { .. } => "FederatedUser",
        _ => "AWSAccount",
    };
    let mut v = json!({
        "type": kind,
        "principalId": c.user_id,
        "arn": c.arn,
        "accountId": c.account_id,
        "accessKeyId": c.access_key_id,
    });
    if let CallerKind::AssumedRole { role_name, .. } = &c.kind {
        let role_arn = format!("arn:{}:iam::{}:role/{role_name}", ctx.partition, c.account_id);
        v["sessionContext"] = json!({
            "attributes": { "creationDate": ctx.received_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(), "mfaAuthenticated": "false" },
            "sessionIssuer": {
                "type": "Role",
                "principalId": c.user_id.split(':').next().unwrap_or_default(),
                "arn": role_arn,
                "accountId": c.account_id,
                "userName": role_name,
            }
        });
    }
    v
}

fn olap_error(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    if status >= 500 {
        ServiceError::server(code, status, message)
    } else {
        ServiceError::client(code, status, message)
    }
}

/// Map a failure to invoke the function to the error S3 returns.
fn invoke_error(e: ServiceError) -> ServiceError {
    match e.code.as_ref() {
        "ResourceNotFoundException" => olap_error("LambdaNotFound", 404, "The AWS Lambda function was not found."),
        "AccessDeniedException" | "AccessDenied" => {
            olap_error("LambdaPermissionError", 403, "The caller is not authorized to invoke the AWS Lambda function.")
        }
        "TooManyRequestsException" => olap_error("LambdaThrottledError", 429, "The AWS Lambda function was throttled."),
        "InvalidRequestContentException" | "RequestTooLargeException" => {
            olap_error("LambdaInvalidRequest", 400, "The request to the AWS Lambda function was invalid.")
        }
        _ => olap_error("LambdaRuntimeError", 500, format!("The AWS Lambda function failed: {}", e.message)),
    }
}

fn function_failed(out: &LambdaInvocation) -> ServiceError {
    if out.function_error.as_deref().is_some_and(|e| e.contains("Timedout"))
        || String::from_utf8_lossy(&out.payload).contains("Sandbox.Timedout")
    {
        return olap_error("LambdaTimeout", 500, "The AWS Lambda function timed out.");
    }
    olap_error("LambdaRuntimeError", 500, "The AWS Lambda function failed with an unhandled error.")
}

fn path_encode(key: &str) -> String {
    const SET: &percent_encoding::AsciiSet =
        &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~').remove(b'/');
    percent_encoding::utf8_percent_encode(key, SET).to_string()
}

impl S3 {
    /// Serve a request to an Object Lambda access point.
    pub(crate) async fn serve_object_lambda(
        &self,
        ctx: &RequestContext,
        request: HttpRequest,
        olap: ObjectLambdaAccessPoint,
    ) -> HttpResponse {
        let path = request.uri().path().to_string();
        let (_, rest) = split_first_segment(&path);
        let key = percent_encoding::percent_decode_str(rest.strip_prefix('/').unwrap_or(rest))
            .decode_utf8_lossy()
            .into_owned();
        let Some(op) = olap_operation(&request, &key) else {
            return self.render_error(
                &ctx.request_id,
                &ServiceError::client("NotImplemented", 501, "This operation is not supported by S3 Object Lambda."),
            );
        };
        let action = if op.starts_with("List") { "s3-object-lambda:ListBucket" } else { "s3-object-lambda:GetObject" };
        let mut c = ConditionContext::new();
        c.insert("aws:ResourceAccount".into(), vec![olap.account_id.clone()]);
        if let Err(e) = ctx.authorize_with_resource_policy(action, &olap.arn, olap.policy.as_deref(), c) {
            return self.render_error(&ctx.request_id, &e);
        }
        let Some(supporting) = self.supporting_access_point(&olap) else {
            return self.render_error(
                &ctx.request_id,
                &ServiceError::client("NoSuchAccessPoint", 404, "The specified accesspoint does not exist"),
            );
        };
        let transformation = olap.transformations.iter().find(|t| t.actions.iter().any(|a| a == op)).cloned();
        let Some(transformation) = transformation else {
            // Not transformed: served by the supporting access point.
            let bucket = supporting.bucket.clone();
            let request = with_path(request, &bucket, rest);
            return self.serve(ctx.clone(), request, Some(supporting), Some(CALLED_VIA)).await;
        };
        let feature = |f: &str| olap.allowed_features.iter().any(|x| x == f);
        let base = if op.starts_with("Get") { "GetObject" } else { "HeadObject" };
        if request.headers().contains_key(http::header::RANGE)
            && !op.starts_with("List")
            && !feature(&format!("{base}-Range"))
        {
            return self.render_error(
                &ctx.request_id,
                &ServiceError::client(
                    "NotImplemented",
                    501,
                    "A header you provided implies functionality that is not implemented",
                ),
            );
        }
        if crate::form_urlencoded_get(request.uri().query().unwrap_or(""), "partNumber").is_some()
            && !feature(&format!("{base}-PartNumber"))
        {
            return self.render_error(
                &ctx.request_id,
                &ServiceError::client(
                    "NotImplemented",
                    501,
                    "A header you provided implies functionality that is not implemented",
                ),
            );
        }
        match self.transform(ctx, &request, &olap, &supporting, &transformation, op, &key).await {
            Ok(response) => response,
            Err(e) => self.render_error(&ctx.request_id, &e),
        }
    }

    fn supporting_access_point(&self, olap: &ObjectLambdaAccessPoint) -> Option<AccessPoint> {
        let arn = &olap.supporting_access_point;
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        let (account, resource) = (parts.get(4)?, parts.get(5)?);
        let name = resource.strip_prefix("accesspoint/")?;
        self.directory()?.access_point(account, name)
    }

    /// Mint an `inputS3Url` for the supporting access point, acting as the
    /// caller.
    /// Presign an `inputS3Url` for the supporting access point with
    /// temporary credentials that act as the caller, as S3 Object Lambda
    /// does.
    fn input_url(
        &self,
        ctx: &RequestContext,
        request: &HttpRequest,
        supporting: &AccessPoint,
        key: &str,
        method: &str,
    ) -> Result<String, ServiceError> {
        use rand::Rng;
        let alnum = |n: usize, upper: bool| -> String {
            let chars: &[u8] = if upper {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            } else {
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            };
            let mut rng = rand::thread_rng();
            (0..n).map(|_| chars[rng.gen_range(0..chars.len())] as char).collect()
        };
        let access_key_id = format!("ASIA{}", alnum(16, true));
        let secret = alnum(40, false);
        let token = alnum(96, false);
        let now = chrono::Utc::now();
        if let Ok(mut m) = self.links.input_sessions.lock() {
            m.retain(|_, v| v.expires > now);
            m.insert(
                access_key_id.clone(),
                InputSession {
                    secret: secret.clone(),
                    token: token.clone(),
                    caller: ctx.caller.clone(),
                    expires: now + chrono::Duration::seconds(INPUT_URL_TTL_SECS),
                },
            );
        }
        let base = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
        let query: Vec<&str> = request
            .uri()
            .query()
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty() && !p.starts_with("X-Amz-") && !p.starts_with("x-id"))
            .collect();
        let path = if key.is_empty() { String::new() } else { format!("/{}", path_encode(key)) };
        let mut url = format!("{base}/{}{path}", supporting.alias);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }
        mws_sigv4::presign_url(&mws_sigv4::PresignParams {
            method,
            url: &url,
            region: &ctx.region,
            service: "s3",
            access_key_id: &access_key_id,
            secret_access_key: &secret,
            session_token: Some(&token),
            now,
            expires_in: INPUT_URL_TTL_SECS,
        })
        .map_err(|e| olap_error("InternalError", 500, format!("Presigning the input URL failed: {e:?}")))
    }

    fn user_request(ctx: &RequestContext, request: &HttpRequest) -> Value {
        let mut headers = serde_json::Map::new();
        for (name, value) in request.headers() {
            if name == http::header::AUTHORIZATION {
                continue;
            }
            let pretty: String = name
                .as_str()
                .split('-')
                .map(|w| {
                    let mut c = w.chars();
                    c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join("-");
            headers.insert(pretty, Value::String(value.to_str().unwrap_or_default().to_string()));
        }
        let host = host_of(request).unwrap_or_else(|| "localhost".into());
        let scheme = if ctx.secure_transport { "https" } else { "http" };
        json!({ "url": format!("{scheme}://{host}{}", request.uri()), "headers": headers })
    }

    #[allow(clippy::too_many_arguments)]
    async fn transform(
        &self,
        ctx: &RequestContext,
        request: &HttpRequest,
        olap: &ObjectLambdaAccessPoint,
        supporting: &AccessPoint,
        t: &Transformation,
        op: &str,
        key: &str,
    ) -> Result<HttpResponse, ServiceError> {
        let Some(invoker) = self.links.invoker.get().cloned() else {
            return Err(olap_error("LambdaNotFound", 404, "The AWS Lambda function was not found."));
        };
        let input_url =
            self.input_url(ctx, request, supporting, key, if op == "HeadObject" { "HEAD" } else { "GET" })?;
        let mut event = json!({
            "xAmzRequestId": ctx.request_id,
            "configuration": {
                "accessPointArn": olap.arn,
                "supportingAccessPointArn": supporting.arn,
                "payload": t.payload.clone().unwrap_or_default(),
            },
            "userRequest": Self::user_request(ctx, request),
            "userIdentity": user_identity(ctx),
            "protocolVersion": "1.00",
        });
        let context_name = match op {
            "GetObject" => "getObjectContext",
            "HeadObject" => "headObjectContext",
            "ListObjects" => "listObjectsContext",
            _ => "listObjectsV2Context",
        };
        if op != "GetObject" {
            event[context_name] = json!({ "inputS3Url": input_url });
            let out =
                invoker.invoke(ctx, &t.function_arn, event.to_string().into_bytes()).await.map_err(invoke_error)?;
            if out.function_error.is_some() {
                return Err(function_failed(&out));
            }
            return self.payload_response(ctx, op, &out.payload);
        }
        let token = uuid::Uuid::new_v4().simple().to_string() + &uuid::Uuid::new_v4().simple().to_string();
        let route = format!("io-{}-{}", ctx.region.replace('-', ""), &token[..8]);
        event[context_name] = json!({ "inputS3Url": input_url, "outputRoute": route, "outputToken": token });
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        if let Ok(mut m) = self.links.pending.lock() {
            m.insert(token.clone(), Pending { route: route.clone(), reply: tx });
        }
        let task = {
            let ctx = ctx.clone();
            let function = t.function_arn.clone();
            let body = event.to_string().into_bytes();
            tokio::spawn(async move { invoker.invoke(&ctx, &function, body).await })
        };
        let result = tokio::select! {
            r = &mut rx => r.map_err(|_| olap_error("LambdaResponseNotReceived", 500, "The AWS Lambda function did not send a response.")),
            done = task => {
                match rx.try_recv() {
                    Ok(response) => Ok(response),
                    Err(_) => Err(match done {
                        Ok(Ok(out)) if out.function_error.is_some() => function_failed(&out),
                        Ok(Ok(_)) => olap_error(
                            "LambdaResponseNotReceived",
                            500,
                            "The Lambda function exited without successfully calling WriteGetObjectResponse.",
                        ),
                        Ok(Err(e)) => invoke_error(e),
                        Err(_) => olap_error("LambdaRuntimeError", 500, "The AWS Lambda function failed."),
                    }),
                }
            }
        };
        if let Ok(mut m) = self.links.pending.lock() {
            m.remove(&token);
        }
        result
    }

    /// The response to a `HeadObject` or `ListObjects*` transformation,
    /// which the function returns as its result.
    fn payload_response(&self, ctx: &RequestContext, op: &str, payload: &[u8]) -> Result<HttpResponse, ServiceError> {
        let v: Value = serde_json::from_slice(payload).map_err(|_| {
            olap_error("LambdaInvalidResponse", 500, "The AWS Lambda function returned an invalid response.")
        })?;
        let status = v.get("statusCode").and_then(Value::as_u64).unwrap_or(200) as u16;
        if let Some(code) = v.get("errorCode").and_then(Value::as_str) {
            let message = v.get("errorMessage").and_then(Value::as_str).unwrap_or_default();
            let status = if status == 200 { 403 } else { status };
            return Ok(self
                .render_error(&ctx.request_id, &ServiceError::client(code.to_string(), status, message.to_string())));
        }
        let mut builder = http::Response::builder().status(status);
        let body = if op == "HeadObject" {
            if let Some(h) = v.get("headers").and_then(Value::as_object) {
                for (k, val) in h {
                    if let Some(s) = val.as_str().map(str::to_string).or_else(|| val.as_i64().map(|n| n.to_string())) {
                        builder = builder.header(k.as_str(), s);
                    }
                }
            }
            if let Some(m) = v.get("metadata").and_then(Value::as_object) {
                for (k, val) in m {
                    if let Some(s) = val.as_str() {
                        builder = builder.header(format!("x-amz-meta-{k}"), s);
                    }
                }
            }
            Bytes::new()
        } else {
            let xml = v.get("listResultXml").and_then(Value::as_str).ok_or_else(|| {
                olap_error("LambdaInvalidResponse", 500, "The AWS Lambda function returned an invalid response.")
            })?;
            builder = builder.header(http::header::CONTENT_TYPE, "application/xml");
            Bytes::from(xml.to_string())
        };
        builder.header("x-amz-request-id", ctx.request_id.as_str()).body(body).map_err(|_| {
            olap_error("LambdaInvalidResponse", 500, "The AWS Lambda function returned an invalid response.")
        })
    }
}

impl Call {
    /// `WriteGetObjectResponse`: answer the `GetObject` waiting on
    /// `RequestToken`.
    pub fn write_get_object_response(
        &self,
        ctx: &RequestContext,
        input: types::WriteGetObjectResponseRequest,
    ) -> Result<(), ServiceError> {
        ctx.authorize("s3-object-lambda:WriteGetObjectResponse", "*", ConditionContext::new())?;
        let pending = self.links.pending.lock().ok().and_then(|mut m| {
            let matches = m.get(&input.request_token).is_some_and(|p| p.route == input.request_route);
            if matches {
                m.remove(&input.request_token)
            } else {
                None
            }
        });
        let Some(pending) = pending else {
            return Err(ServiceError::client(
                "InvalidToken",
                400,
                "The provided token is malformed or otherwise invalid.",
            ));
        };
        let status = input.status_code.unwrap_or(200) as u16;
        let response = if let Some(code) = input.error_code.clone() {
            let status = if status < 300 { 400 } else { status };
            let e = ServiceError::client(code, status, input.error_message.clone().unwrap_or_default());
            self.render_error(&ctx.request_id, &e)
        } else {
            wgor_response(&input, status)
        };
        let _ = pending.reply.send(response);
        Ok(())
    }
}

fn wgor_response(i: &types::WriteGetObjectResponseRequest, status: u16) -> HttpResponse {
    let fmt_date = |d: &chrono::DateTime<chrono::Utc>| d.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let mut h: Vec<(String, Option<String>)> = vec![
        ("accept-ranges".into(), i.accept_ranges.clone()),
        ("cache-control".into(), i.cache_control.clone()),
        ("content-disposition".into(), i.content_disposition.clone()),
        ("content-encoding".into(), i.content_encoding.clone()),
        ("content-language".into(), i.content_language.clone()),
        ("content-range".into(), i.content_range.clone()),
        ("content-type".into(), i.content_type.clone()),
        ("x-amz-checksum-crc32".into(), i.checksum_crc32.clone()),
        ("x-amz-checksum-crc32c".into(), i.checksum_crc32_c.clone()),
        ("x-amz-checksum-crc64nvme".into(), i.checksum_crc64_nvme.clone()),
        ("x-amz-checksum-sha1".into(), i.checksum_sha1.clone()),
        ("x-amz-checksum-sha256".into(), i.checksum_sha256.clone()),
        ("x-amz-delete-marker".into(), i.delete_marker.map(|v| v.to_string())),
        ("etag".into(), i.e_tag.clone()),
        ("expires".into(), i.expires.clone()),
        ("x-amz-expiration".into(), i.expiration.clone()),
        ("last-modified".into(), i.last_modified.as_ref().map(fmt_date)),
        ("x-amz-missing-meta".into(), i.missing_meta.map(|v| v.to_string())),
        ("x-amz-object-lock-mode".into(), i.object_lock_mode.clone()),
        ("x-amz-object-lock-legal-hold".into(), i.object_lock_legal_hold_status.clone()),
        (
            "x-amz-object-lock-retain-until-date".into(),
            i.object_lock_retain_until_date.as_ref().map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
        ),
        ("x-amz-mp-parts-count".into(), i.parts_count.map(|v| v.to_string())),
        ("x-amz-replication-status".into(), i.replication_status.clone()),
        ("x-amz-request-charged".into(), i.request_charged.clone()),
        ("x-amz-restore".into(), i.restore.clone()),
        ("x-amz-server-side-encryption".into(), i.server_side_encryption.clone()),
        ("x-amz-server-side-encryption-customer-algorithm".into(), i.sse_customer_algorithm.clone()),
        ("x-amz-server-side-encryption-aws-kms-key-id".into(), i.ssekms_key_id.clone()),
        ("x-amz-server-side-encryption-customer-key-md5".into(), i.sse_customer_key_md5.clone()),
        ("x-amz-storage-class".into(), i.storage_class.clone()),
        ("x-amz-tagging-count".into(), i.tag_count.map(|v| v.to_string())),
        ("x-amz-version-id".into(), i.version_id.clone()),
        ("x-amz-server-side-encryption-bucket-key-enabled".into(), i.bucket_key_enabled.map(|v| v.to_string())),
    ];
    for (k, v) in i.metadata.iter().flatten() {
        h.push((format!("x-amz-meta-{k}"), Some(v.clone())));
    }
    let mut b = http::Response::builder().status(status);
    for (k, v) in h {
        if let Some(v) = v {
            b = b.header(k, v);
        }
    }
    b.body(Bytes::from(i.body.clone()))
        .unwrap_or_else(|_| http::Response::builder().status(500).body(Bytes::new()).expect("valid response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_point_hosts() {
        assert_eq!(
            access_point_host("my-ap-123456789012.localhost:4566"),
            Some(("my-ap".into(), "123456789012".into()))
        );
        assert_eq!(
            access_point_host("ap-123456789012.s3-accesspoint.us-east-1.amazonaws.com"),
            Some(("ap".into(), "123456789012".into()))
        );
        assert_eq!(access_point_host("bucket.localhost"), None);
        assert_eq!(access_point_host("localhost:4566"), None);
    }

    #[test]
    fn keys_are_path_encoded() {
        assert_eq!(path_encode("a b/c+d.txt"), "a%20b/c%2Bd.txt");
    }
}
