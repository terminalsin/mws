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
use crate::{Caller, RequestContext, Service, ServiceError};

#[derive(Default)]
struct Registry {
    services: HashMap<&'static str, Arc<dyn Service>>,
    observers: Vec<Arc<dyn ApiCallObserver>>,
}

/// Calls any registered service's operations by name. Cheap to clone; all
/// clones share one registry, which the composition root fills once every
/// service exists.
#[derive(Clone, Default)]
pub struct ServiceClient {
    registry: Arc<RwLock<Registry>>,
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
        let (target, observers) = {
            let r = self.registry.read().map_err(|_| ServiceError::internal("service registry poisoned"))?;
            let target = r.services.get(service).cloned();
            (target, r.observers.clone())
        };
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

/// The user agent audit logs show for a call one service makes to another:
/// the service principal itself, or `AWS Internal` for calls made with a
/// role's credentials.
fn internal_agent(caller: &Caller) -> String {
    caller.service_principal().map_or_else(|| "AWS Internal".to_string(), str::to_string)
}

impl RequestContext {
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
