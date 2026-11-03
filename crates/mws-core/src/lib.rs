//! Service-agnostic contracts for MWS.
//!
//! This crate deliberately knows nothing about any particular AWS service. It
//! defines the seams between the HTTP front door (`mws-server`), the services
//! (`mws-iam`, ...), and whichever crate decides who may do what (an
//! [`Authorizer`]) or who a caller is (a [`CredentialStore`]).

mod auth;
mod error;
mod service;
mod validate;

pub use auth::{
    AllowAll, Authorizer, AuthzDecision, AuthzRequest, Caller, CallerKind, ConditionContext, CredentialError,
    CredentialStore, ResolvedCredential, ResourcePolicyMode, SessionInfo, SessionKind,
};
pub use error::{ErrorFault, ErrorField, ErrorValue, ServiceError};
pub use service::{HttpRequest, HttpResponse, RequestContext, Service};
pub use validate::{render_list, Validator};

/// Settings that describe the simulated AWS partition and account.
#[derive(Debug, Clone)]
pub struct Environment {
    /// Partition used when building ARNs, normally `aws`.
    pub partition: String,
    /// Default region reported to callers that do not sign with one.
    pub default_region: String,
}

impl Default for Environment {
    fn default() -> Self {
        Self { partition: "aws".into(), default_region: "us-east-1".into() }
    }
}
