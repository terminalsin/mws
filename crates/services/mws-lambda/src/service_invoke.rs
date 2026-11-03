//! AWS services invoking functions on their own behalf (EventBridge rule
//! targets, ...): asynchronous invocations allowed by the function's
//! resource policy alone, as for service principals in AWS.

use std::fmt;

use mws_core::RequestContext;
use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::{names, Lambda};

/// A service principal invoking a function asynchronously.
#[derive(Debug, Clone)]
pub struct ServiceInvoke<'a> {
    /// The function ARN, optionally qualified with a version or alias.
    pub function_arn: &'a str,
    /// e.g. `events.amazonaws.com`.
    pub service_principal: &'a str,
    /// `aws:SourceAccount` and `aws:SourceArn` for the resource policy.
    pub source_account: &'a str,
    pub source_arn: &'a str,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceInvokeError {
    NoSuchFunction,
    /// The function's resource policy does not allow the service.
    AccessDenied,
    Invalid(String),
}

impl fmt::Display for ServiceInvokeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceInvokeError::NoSuchFunction => write!(f, "Function not found"),
            ServiceInvokeError::AccessDenied => {
                write!(f, "The resource policy of the function does not allow the service to invoke it")
            }
            ServiceInvokeError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ServiceInvokeError {}

impl Lambda {
    /// Queue an asynchronous invocation by a service principal, after
    /// checking the function's resource policy. `ctx` supplies the
    /// endpoint and clock the function runs with.
    pub fn invoke_as_service(&self, ctx: &RequestContext, s: ServiceInvoke<'_>) -> Result<(), ServiceInvokeError> {
        let f = names::parse_function(ctx, s.function_arn, None)
            .map_err(|e| ServiceInvokeError::Invalid(e.message.clone()))?;
        let policy = {
            let st = self.read();
            let func = Self::function(&st, &f).map_err(|_| ServiceInvokeError::NoSuchFunction)?;
            if func.version_for(f.qualifier.as_deref()).is_none() {
                return Err(ServiceInvokeError::NoSuchFunction);
            }
            Self::policy_document(func, f.qualifier.as_deref())
        };
        let policy = policy.and_then(|d| Policy::parse(&d, PolicyKind::Resource).ok());
        let principal = PrincipalInfo { service: Some(s.service_principal.to_string()), ..Default::default() };
        let mut context = ConditionContext::new();
        context.insert("aws:SourceAccount", vec![s.source_account.to_string()]);
        context.insert("aws:SourceArn", vec![s.source_arn.to_string()]);
        context.insert("aws:PrincipalServiceName", vec![s.service_principal.to_string()]);
        context.insert("aws:PrincipalIsAWSService", vec!["true".to_string()]);
        let resource = f.qualified_arn();
        let allowed = policy.as_ref().is_some_and(|p| {
            let e = p.evaluate(&Request {
                action: "lambda:InvokeFunction",
                resource: &resource,
                principal: &principal,
                context: &context,
            });
            e.allowed() && !e.denied()
        });
        if !allowed {
            return Err(ServiceInvokeError::AccessDenied);
        }
        self.enqueue(ctx, &f, s.payload);
        Ok(())
    }
}
