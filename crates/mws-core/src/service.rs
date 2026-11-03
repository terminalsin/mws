use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};

use crate::{Authorizer, AuthzDecision, AuthzRequest, Caller, ConditionContext, ResourcePolicyMode, ServiceError};

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
        let principal_type = match &c.kind {
            crate::CallerKind::Root => "Account",
            crate::CallerKind::User { .. } => "User",
            crate::CallerKind::AssumedRole { .. } => "AssumedRole",
            crate::CallerKind::FederatedUser { .. } => "FederatedUser",
            crate::CallerKind::Anonymous => "Anonymous",
        };
        ctx.insert("aws:PrincipalType".into(), vec![principal_type.into()]);
        let mfa = c.session.as_ref().is_some_and(|s| s.mfa_authenticated);
        ctx.insert("aws:MultiFactorAuthPresent".into(), vec![mfa.to_string()]);
        if let Some(s) = &c.session {
            ctx.insert("aws:TokenIssueTime".into(), vec![s.issued_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()]);
            if let Some(si) = &s.source_identity {
                ctx.insert("aws:SourceIdentity".into(), vec![si.clone()]);
            }
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
        self.authorize_inner(action, resource, None, ResourcePolicyMode::Optional, extra_context)
    }

    /// Like [`RequestContext::authorize`], also evaluating the resource's
    /// own policy (a bucket policy, a CA policy, ...).
    pub fn authorize_with_resource_policy(
        &self,
        action: &str,
        resource: &str,
        resource_policy: Option<&str>,
        extra_context: ConditionContext,
    ) -> Result<(), ServiceError> {
        self.authorize_inner(action, resource, resource_policy, ResourcePolicyMode::Optional, extra_context)
    }

    /// Like [`RequestContext::authorize_with_resource_policy`], but the
    /// resource policy must allow the caller (directly, or through its
    /// account together with identity policies), as KMS key policies do.
    pub fn authorize_with_required_resource_policy(
        &self,
        action: &str,
        resource: &str,
        resource_policy: &str,
        extra_context: ConditionContext,
    ) -> Result<(), ServiceError> {
        self.authorize_inner(action, resource, Some(resource_policy), ResourcePolicyMode::Required, extra_context)
    }

    /// Ask the authorizer without turning a denial into an error.
    pub fn check(
        &self,
        action: &str,
        resource: &str,
        resource_policy: Option<&str>,
        resource_policy_mode: ResourcePolicyMode,
        extra_context: ConditionContext,
    ) -> AuthzDecision {
        let mut context = self.global_condition_context();
        context.extend(extra_context);
        let req =
            AuthzRequest { caller: &self.caller, action, resource, resource_policy, resource_policy_mode, context };
        self.authorizer.authorize(&req)
    }

    /// Authorize against a role trust policy: the trust policy must allow the
    /// caller, and identity policies must too unless it names them directly.
    pub fn authorize_against_trust_policy(
        &self,
        action: &str,
        role_arn: &str,
        trust_policy: &str,
        extra_context: ConditionContext,
    ) -> Result<(), ServiceError> {
        self.authorize_inner(action, role_arn, Some(trust_policy), ResourcePolicyMode::Trust, extra_context)
    }

    fn authorize_inner(
        &self,
        action: &str,
        resource: &str,
        resource_policy: Option<&str>,
        resource_policy_mode: ResourcePolicyMode,
        extra_context: ConditionContext,
    ) -> Result<(), ServiceError> {
        match self.check(action, resource, resource_policy, resource_policy_mode, extra_context) {
            AuthzDecision::Allow => Ok(()),
            AuthzDecision::Deny { reason, .. } => {
                let reason = if reason.is_empty() { String::new() } else { format!(" {reason}") };
                Err(ServiceError::client(
                    "AccessDenied",
                    403,
                    format!(
                        "User: {} is not authorized to perform: {} on resource: {}{reason}",
                        self.caller.arn, action, resource
                    ),
                ))
            }
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

    /// Further signing names this service answers to (S3 directory bucket
    /// requests are signed for `s3express`).
    fn signing_aliases(&self) -> &'static [&'static str] {
        &[]
    }

    /// A session token the request carries outside `X-Amz-Security-Token`,
    /// in a header or query parameter of this service's own.
    fn session_token(&self, _request: &HttpRequest) -> Option<String> {
        None
    }

    /// Handle an authenticated request.
    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse;

    /// Render an error raised before the request reached [`Service::handle`]
    /// (authentication failures) in this service's wire protocol.
    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse;

    /// Whether SigV4 signs this service's URI path as sent, without
    /// normalizing or encoding it again (S3).
    fn signs_raw_path(&self) -> bool {
        false
    }

    /// Whether this service will accept the given unsigned request. Some STS
    /// operations (e.g. `AssumeRoleWithWebIdentity`) need no signature.
    fn accepts_unsigned(&self, _request: &HttpRequest) -> bool {
        false
    }

    /// Run `operation` with its input as JSON keyed by Smithy member names
    /// (the shape `aws ... --cli-input-json` takes) and return its output
    /// the same way. MWS uses this to apply scenario files; the input is
    /// validated and authorized exactly like a wire request.
    async fn invoke(
        &self,
        _ctx: RequestContext,
        operation: &str,
        _input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        Err(ServiceError::unknown_operation(operation))
    }

    /// This service's whole state as JSON, for persistence and snapshots.
    /// `None` for services that keep no state.
    fn export_state(&self) -> Option<serde_json::Value> {
        None
    }

    /// Replace this service's whole state with one [`Service::export_state`]
    /// produced. On error the state is left unchanged.
    fn import_state(&self, _state: serde_json::Value) -> Result<(), String> {
        Ok(())
    }

    /// Return to the state of a freshly started service.
    fn reset_state(&self) {}
}
