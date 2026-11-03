//! Invocations made by AWS services as their service principal (Secrets
//! Manager rotation, ...). As in AWS, the function's resource policy alone
//! decides: it must allow the service principal `lambda:InvokeFunction`,
//! usually with `aws:SourceAccount`/`aws:SourceArn` conditions.

use mws_core::{RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind, PrincipalInfo, Request};

use crate::names;
use crate::Lambda;

/// A synchronous invocation by a service principal.
#[derive(Debug, Clone)]
pub struct ServiceInvocation<'a> {
    /// The function's name or ARN, optionally qualified.
    pub function: &'a str,
    /// The service principal, e.g. `secretsmanager.amazonaws.com`.
    pub service_principal: &'a str,
    /// `aws:SourceAccount`: the account of the resource the call is for.
    pub source_account: Option<&'a str>,
    /// `aws:SourceArn`: the resource the call is for.
    pub source_arn: Option<&'a str>,
    pub payload: Vec<u8>,
}

/// What a service invocation returned.
#[derive(Debug, Clone)]
pub struct ServiceInvocationResult {
    pub payload: Vec<u8>,
    /// `Unhandled` or `Handled` when the function failed.
    pub function_error: Option<String>,
    pub executed_version: String,
}

/// Why a service could not invoke a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceInvokeError {
    /// The function (or qualifier) does not exist.
    NotFound,
    /// The function policy does not allow the service principal.
    AccessDenied,
    /// The function exists but could not run.
    Failed(String),
}

impl Lambda {
    /// Whether `inv`'s service principal may invoke the function, without
    /// running it.
    pub fn check_service_invoke(
        &self,
        ctx: &RequestContext,
        inv: &ServiceInvocation<'_>,
    ) -> Result<names::FunctionRef, ServiceInvokeError> {
        let f = names::parse_function(ctx, inv.function, None).map_err(|_| ServiceInvokeError::NotFound)?;
        let policy = {
            let st = self.read();
            let func = st.functions.get(&f.arn()).ok_or(ServiceInvokeError::NotFound)?;
            if func.version_for(f.qualifier.as_deref()).is_none() {
                return Err(ServiceInvokeError::NotFound);
            }
            Self::policy_document(func, f.qualifier.as_deref())
        };
        let Some(policy) = policy else { return Err(ServiceInvokeError::AccessDenied) };
        let policy = Policy::parse(&policy, PolicyKind::Resource).map_err(|_| ServiceInvokeError::AccessDenied)?;
        let principal = PrincipalInfo { service: Some(inv.service_principal.to_string()), ..Default::default() };
        let mut context = mws_iam_policy::ConditionContext::new();
        context.insert("aws:PrincipalIsAWSService", vec!["true".into()]);
        context.insert("aws:PrincipalServiceName", vec![inv.service_principal.to_string()]);
        context.insert("aws:CurrentTime", vec![ctx.received_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()]);
        if let Some(a) = inv.source_account {
            context.insert("aws:SourceAccount", vec![a.to_string()]);
        }
        if let Some(a) = inv.source_arn {
            context.insert("aws:SourceArn", vec![a.to_string()]);
        }
        let resource = f.qualified_arn();
        let e = policy.evaluate(&Request {
            action: "lambda:InvokeFunction",
            resource: &resource,
            principal: &principal,
            context: &context,
        });
        if e.denied() || !e.allowed() {
            return Err(ServiceInvokeError::AccessDenied);
        }
        Ok(f)
    }

    /// Run a function synchronously for a service principal, after checking
    /// its resource policy. `ctx` supplies the Region, clock and endpoint.
    pub async fn invoke_as_service(
        &self,
        ctx: &RequestContext,
        inv: ServiceInvocation<'_>,
    ) -> Result<ServiceInvocationResult, ServiceInvokeError> {
        let f = self.check_service_invoke(ctx, &inv)?;
        let ran = self
            .run(ctx, &f, inv.payload, None)
            .await
            .map_err(|e: ServiceError| ServiceInvokeError::Failed(format!("{}: {}", e.code, e.message)))?;
        Ok(ServiceInvocationResult {
            payload: ran.outcome.payload,
            function_error: ran.outcome.function_error,
            executed_version: ran.executed_version,
        })
    }
}

impl std::fmt::Display for ServiceInvokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceInvokeError::NotFound => write!(f, "Function not found"),
            ServiceInvokeError::AccessDenied => write!(f, "The function policy does not allow lambda:InvokeFunction"),
            ServiceInvokeError::Failed(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ServiceInvokeError {}

impl Lambda {
    /// Queue an asynchronous (`Event`) invocation as the service principal
    /// (SNS subscriptions, S3 event notifications), after checking the
    /// function policy. `ctx` is the request that caused it (for the
    /// emulator's endpoint and clock); its caller is not consulted.
    pub fn invoke_event_as_service(
        &self,
        ctx: &RequestContext,
        inv: ServiceInvocation<'_>,
    ) -> Result<(), ServiceInvokeError> {
        let f = self.check_service_invoke(ctx, &inv)?;
        if inv.payload.len() > crate::invoke::MAX_ASYNC_PAYLOAD {
            return Err(ServiceInvokeError::Failed(
                "The event is larger than Lambda's asynchronous payload limit".into(),
            ));
        }
        let ctx = RequestContext { region: f.region.clone(), ..ctx.clone() };
        self.enqueue(&ctx, &f, inv.payload);
        Ok(())
    }
}

const S3_PRINCIPAL: &str = "s3.amazonaws.com";

/// S3 event notifications invoke functions as `s3.amazonaws.com`.
impl mws_s3::NotificationDestination for Lambda {
    fn service(&self) -> &'static str {
        "lambda"
    }

    fn check(&self, ctx: &RequestContext, arn: &str, source: &mws_s3::NotificationSource<'_>) -> Result<(), String> {
        let inv = ServiceInvocation {
            function: arn,
            service_principal: S3_PRINCIPAL,
            source_account: Some(source.bucket_owner),
            source_arn: Some(source.bucket_arn),
            payload: Vec::new(),
        };
        self.check_service_invoke(ctx, &inv).map(|_| ()).map_err(|e| match e {
            ServiceInvokeError::NotFound => "The destination function does not exist".to_string(),
            _ => "Permissions on the destination function do not allow S3 to invoke it".to_string(),
        })
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &mws_s3::NotificationSource<'_>, message: String) {
        let inv = ServiceInvocation {
            function: arn,
            service_principal: S3_PRINCIPAL,
            source_account: Some(source.bucket_owner),
            source_arn: Some(source.bucket_arn),
            payload: message.into_bytes(),
        };
        if let Err(e) = self.invoke_event_as_service(ctx, inv) {
            tracing::warn!(function = arn, "S3 could not invoke a notification function: {e}");
        }
    }
}
