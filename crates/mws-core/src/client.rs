//! Services calling each other's APIs, as AWS services do.
//!
//! In AWS an integration is an API call: S3 delivers an event notification
//! by calling `sqs:SendMessage` as `s3.amazonaws.com`, a Lambda event
//! source mapping polls with `sqs:ReceiveMessage` as the function's
//! execution role. [`ServiceClient`] makes those calls in-process through
//! the target's own operations ([`Service::invoke`]), so the target
//! validates and authorizes them exactly as it would an SDK request, and
//! audit logs see them as calls of their own.
//!
//! Callers name the service and operation, never the other crate's types,
//! so an integration needs no crate dependency on the service it calls.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde_json::Value;

use crate::trail::{self, ApiCallObserver, HttpFacts};
use crate::{Authorizer, Caller, RequestContext, Service, ServiceError};

#[derive(Default)]
pub(crate) struct Registry {
    pub services: HashMap<&'static str, Arc<dyn Service>>,
    pub observers: Vec<Arc<dyn ApiCallObserver>>,
    pub authorizer: Option<Arc<dyn Authorizer>>,
}

/// Calls any registered service's operations by name. Cheap to clone; all
/// clones share one registry, which the composition root fills once every
/// service exists.
#[derive(Clone, Default)]
pub struct ServiceClient {
    pub(crate) registry: Arc<RwLock<Registry>>,
    pub(crate) outbox: Arc<Outbox>,
}

/// Calls queued for retry (see [`crate::outbox`]).
#[derive(Default)]
pub(crate) struct Outbox {
    pub deliveries: std::sync::Mutex<Vec<crate::outbox::Delivery>>,
    /// How far the emulated clock runs ahead, as last seen.
    pub clock_offset_ms: std::sync::atomic::AtomicI64,
    pub retrying: std::sync::atomic::AtomicBool,
    pub endpoint: std::sync::Mutex<Option<String>>,
}

impl std::fmt::Debug for ServiceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.registry.read().map(|r| r.services.keys().copied().collect()).unwrap_or_default();
        f.debug_struct("ServiceClient").field("services", &names).finish()
    }
}

impl ServiceClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make `service` reachable under its [`Service::name`]. The first
    /// service registered under a name keeps it.
    pub fn register(&self, service: Arc<dyn Service>) {
        if let Ok(mut r) = self.registry.write() {
            r.services.entry(service.name()).or_insert(service);
        }
    }

    /// Tell `observer` (an audit log) about every call made through this
    /// client.
    pub fn observe_with(&self, observer: Arc<dyn ApiCallObserver>) {
        if let Ok(mut r) = self.registry.write() {
            r.observers.push(observer);
        }
    }

    /// The authorizer that judges calls made as an AWS service principal.
    /// Such calls are always judged by it, whatever authorizer the
    /// request that caused them carried: a context built for a
    /// service-linked role may allow everything, but a service principal
    /// is never exempt from the target's resource policy.
    pub fn set_authorizer(&self, authorizer: Arc<dyn Authorizer>) {
        if let Ok(mut r) = self.registry.write() {
            r.authorizer = Some(authorizer);
        }
    }

    /// Whether a service is registered under `name`.
    pub fn knows(&self, name: &str) -> bool {
        self.registry.read().is_ok_and(|r| r.services.contains_key(name))
    }

    /// Run `operation` of `service` as `ctx`'s caller, with its input and
    /// output as JSON keyed by Smithy member names. The target validates and
    /// authorizes the call itself. Never call this while holding a lock the
    /// target or the IAM authorizer may need.
    pub async fn call(
        &self,
        ctx: &RequestContext,
        service: &str,
        operation: &str,
        input: Value,
    ) -> Result<Value, ServiceError> {
        let (target, observers, authorizer) = {
            let r = self.registry.read().map_err(|_| ServiceError::internal("service registry poisoned"))?;
            (r.services.get(service).cloned(), r.observers.clone(), r.authorizer.clone())
        };
        if ctx.endpoint.is_some() {
            if let Ok(mut e) = self.outbox.endpoint.lock() {
                e.clone_from(&ctx.endpoint);
            }
        }
        let mut ctx = ctx.clone();
        if let (Some(a), Some(_)) = (authorizer, ctx.caller.service_principal()) {
            ctx.authorizer = a;
        }
        let ctx = &ctx;
        let Some(target) = target else {
            return Err(ServiceError::internal(format!("no service named {service} is registered")));
        };
        // What the target defers (its own deliveries) runs before this
        // call returns, as it would before its response went out.
        let invoke = crate::deferred::run(target.invoke(ctx.clone(), operation, input));
        if observers.is_empty() {
            return invoke.await;
        }
        let (result, call) = trail::watch(invoke).await;
        if let Some(call) = call {
            let facts = HttpFacts {
                user_agent: Some(internal_agent(&ctx.caller)),
                host: None,
                status: match &result {
                    Ok(_) => 200,
                    Err(e) => e.status,
                },
            };
            for o in &observers {
                o.observe(ctx, &call, &facts);
            }
        }
        result
    }
}

impl ServiceClient {
    /// The emulator's URL, as the last call that knew it saw it.
    pub(crate) fn endpoint(&self) -> Option<String> {
        self.outbox.endpoint.lock().ok().and_then(|e| e.clone())
    }
}

/// The user agent audit logs show for a call one service makes to another:
/// the service principal itself, or `AWS Internal` for calls made with a
/// role's credentials.
fn internal_agent(caller: &Caller) -> String {
    caller.service_principal().map_or_else(|| "AWS Internal".to_string(), str::to_string)
}

impl RequestContext {
    /// This request's caller, acting through a service on its behalf after
    /// its own request was authorized (a forward access session): only
    /// explicit denies and policies that must name the principal (KMS key
    /// policies) still refuse.
    pub fn on_behalf(&self) -> RequestContext {
        RequestContext { authorizer: crate::ServiceLinkedRoleAuthorizer::wrap(self.authorizer.clone()), ..self.clone() }
    }

    /// This request's context, with the AWS service `principal` as the
    /// caller, acting for `source_account` on behalf of `source_arn`.
    /// Authorization then evaluates resource policies only.
    pub fn as_service(&self, principal: &str, source_account: &str, source_arn: Option<&str>) -> RequestContext {
        RequestContext {
            request_id: crate::ids::request_id(),
            caller: Caller::service(principal, source_account, source_arn),
            source_ip: None,
            secure_transport: true,
            ..self.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllowAll, AuthzDecision, AuthzRequest, HttpRequest, HttpResponse};

    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorize(&self, _: &AuthzRequest<'_>) -> AuthzDecision {
            AuthzDecision::Deny { reason: String::new(), explicit: false }
        }
    }

    /// A service whose one operation only authorizes.
    struct Guarded;
    #[async_trait::async_trait]
    impl Service for Guarded {
        fn signing_name(&self) -> &'static str {
            "guarded"
        }
        async fn handle(&self, _: RequestContext, _: HttpRequest) -> HttpResponse {
            unreachable!()
        }
        fn render_error(&self, _: &str, _: &ServiceError) -> HttpResponse {
            unreachable!()
        }
        async fn invoke(&self, ctx: RequestContext, _: &str, _: Value) -> Result<Value, ServiceError> {
            ctx.authorize("guarded:Do", "*", Default::default())?;
            Ok(Value::Null)
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            request_id: "r".into(),
            region: "us-east-1".into(),
            partition: "aws".into(),
            received_at: chrono::Utc::now(),
            caller: Caller::anonymous(),
            source_ip: None,
            secure_transport: true,
            authorizer: Arc::new(AllowAll),
            endpoint: None,
        }
    }

    #[tokio::test]
    async fn service_principals_are_judged_by_the_real_authorizer() {
        let client = ServiceClient::new();
        client.register(Arc::new(Guarded));
        client.set_authorizer(Arc::new(DenyAll));
        // A context built for a service-linked role allows everything...
        let template = ctx();
        assert!(client.call(&template, "guarded", "Do", Value::Null).await.is_ok());
        // ...but a service principal acting from it is still judged.
        let as_service = template.as_service("s3.amazonaws.com", "123456789012", None);
        let err = client.call(&as_service, "guarded", "Do", Value::Null).await.unwrap_err();
        assert_eq!(err.code, "AccessDenied");
        let err = client.call(&template, "missing", "Do", Value::Null).await.unwrap_err();
        assert_eq!(err.status, 500);
    }
}
