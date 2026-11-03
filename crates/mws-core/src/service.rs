use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};

use crate::{Authorizer, AuthzDecision, AuthzRequest, Caller, ConditionContext, ServiceError};

pub type HttpRequest = http::Request<Bytes>;
pub type HttpResponse = http::Response<Bytes>;

/// Everything a service needs to know about the request beyond its body.
#[derive(Clone)]
pub struct RequestContext {
    pub request_id: String,
    /// Region from the SigV4 credential scope.
    pub region: String,
    pub partition: String,
    pub received_at: DateTime<Utc>,
    pub caller: Caller,
    pub source_ip: Option<String>,
    /// Whether the request arrived over TLS (`aws:SecureTransport`).
    pub secure_transport: bool,
    pub authorizer: Arc<dyn Authorizer>,
}

impl RequestContext {
    /// Global condition keys AWS adds to every request.
    pub fn global_condition_context(&self) -> ConditionContext {
        let mut ctx = ConditionContext::new();
        let c = &self.caller;
        ctx.insert("aws:PrincipalArn".into(), vec![principal_arn_for_conditions(c)]);
        ctx.insert("aws:PrincipalAccount".into(), vec![c.account_id.clone()]);
        ctx.insert("aws:userid".into(), vec![c.user_id.clone()]);
        if let crate::CallerKind::User { name } = &c.kind {
            ctx.insert("aws:username".into(), vec![name.clone()]);
        }
        ctx.insert("aws:CurrentTime".into(), vec![self.received_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()]);
        ctx.insert("aws:EpochTime".into(), vec![self.received_at.timestamp().to_string()]);
        ctx.insert("aws:SecureTransport".into(), vec![self.secure_transport.to_string()]);
        ctx.insert("aws:RequestedRegion".into(), vec![self.region.clone()]);
        if let Some(ip) = &self.source_ip {
            ctx.insert("aws:SourceIp".into(), vec![ip.clone()]);
        }
        ctx
    }

    /// Ask the authorizer whether the caller may perform `action` on
    /// `resource`, and turn a denial into the standard AccessDenied error.
    pub fn authorize(&self, action: &str, resource: &str, extra_context: ConditionContext) -> Result<(), ServiceError> {
        let mut context = self.global_condition_context();
        context.extend(extra_context);
        let req = AuthzRequest { caller: &self.caller, action, resource, resource_policy: None, context };
        match self.authorizer.authorize(&req) {
            AuthzDecision::Allow => Ok(()),
            AuthzDecision::Deny { reason } => Err(ServiceError::client(
                "AccessDenied",
                403,
                format!(
                    "User: {} is not authorized to perform: {} on resource: {} {}",
                    self.caller.arn, action, resource, reason
                ),
            )),
        }
    }
}

/// For an assumed-role session, `aws:PrincipalArn` is the role ARN, not the
/// session ARN.
fn principal_arn_for_conditions(c: &Caller) -> String {
    match &c.kind {
        crate::CallerKind::AssumedRole { role_name, .. } => {
            let partition = c.arn.split(':').nth(1).unwrap_or("aws");
            format!("arn:{partition}:iam::{}:role/{role_name}", c.account_id)
        }
        _ => c.arn.clone(),
    }
}

/// One AWS service, reachable through the shared HTTP front door.
#[async_trait::async_trait]
pub trait Service: Send + Sync {
    /// The SigV4 signing name, e.g. `iam`, `sts`, `route53`, `acm-pca`.
    fn signing_name(&self) -> &'static str;

    /// Handle an authenticated request.
    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse;

    /// Render an error raised before the request reached [`Service::handle`]
    /// (authentication failures) in this service's wire protocol.
    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse;

    /// Whether this service will accept the given unsigned request. Some STS
    /// operations (e.g. `AssumeRoleWithWebIdentity`) need no signature.
    fn accepts_unsigned(&self, _request: &HttpRequest) -> bool {
        false
    }
}
