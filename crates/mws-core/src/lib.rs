//! Service-agnostic contracts for MWS.
//!
//! This crate deliberately knows nothing about any particular AWS service. It
//! defines the seams between the HTTP front door (`mws-server`), the services
//! (`mws-iam`, ...), and whichever crate decides who may do what (an
//! [`Authorizer`]) or who a caller is (a [`CredentialStore`]).

mod auth;
mod error;
pub mod eventstream;
pub mod ids;
pub mod metrics;
mod observe;
mod service;
pub mod shell;
pub mod trail;
mod validate;

pub use auth::{
    AllowAll, Authorizer, AuthzDecision, AuthzRequest, Caller, CallerKind, ConditionContext, CredentialError,
    CredentialStore, ResolvedCredential, ResourcePolicyMode, SessionInfo, SessionKind,
};
pub use error::{ErrorFault, ErrorField, ErrorValue, ServiceError};
pub use observe::{ApiCall, RecordingAuthorizer, RequestObserver};
pub use service::{AlternateSignature, HttpRequest, HttpResponse, RequestContext, Service, StreamingBody};
pub use trail::ApiCallObserver;
pub use validate::{render_list, Validator};

/// Re-exports used by generated code.
#[doc(hidden)]
pub mod __private {
    pub use fancy_regex;
}

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
