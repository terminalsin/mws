//! Trusted context assertions (`ProvidedContexts` on `AssumeRole`): a
//! context provider such as IAM Identity Center has STS seal the identity of
//! a user into an opaque assertion, and a role session created with it
//! carries that identity as condition keys (an identity-enhanced session).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use mws_core::{RequestContext, ServiceError};

use crate::generated::types::ProvidedContext;
use crate::ops::validation;
use crate::Sts;

/// The context provider of IAM Identity Center.
pub const IDENTITY_CENTER_CONTEXT_PROVIDER: &str = "arn:aws:iam::aws:contextProvider/IdentityCenter";

/// What a context assertion stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityContext {
    /// The provider ARN the assertion must be presented with.
    pub provider_arn: String,
    /// The condition keys the session gets, e.g. `identitystore:UserId`.
    pub keys: BTreeMap<String, Vec<String>>,
    pub expires_at: DateTime<Utc>,
}

impl Sts {
    /// Seal `context` into an assertion for `ProvidedContexts`.
    pub fn issue_context_assertion(&self, context: IdentityContext) -> String {
        use base64::Engine;
        let mut bytes = [0u8; 48];
        aws_lc_rs::rand::fill(&mut bytes).expect("system randomness");
        let assertion = base64::engine::general_purpose::STANDARD.encode(bytes);
        let mut contexts = self.inner.contexts.lock().unwrap_or_else(|e| e.into_inner());
        // Expiry is judged on the emulated clock, which only requests know
        // (see `provided_context`). Here, drop only what expired long before
        // the new assertion expires, so wall time never decides.
        let horizon = context.expires_at - chrono::Duration::days(1);
        contexts.retain(|_, c| c.expires_at > horizon);
        contexts.insert(assertion.clone(), context);
        assertion
    }

    /// The context behind `assertion`, pruning those that expired over an
    /// hour before `now` (the request's emulated time).
    pub(crate) fn context_for(&self, assertion: &str, now: DateTime<Utc>) -> Option<IdentityContext> {
        let mut contexts = self.inner.contexts.lock().unwrap_or_else(|e| e.into_inner());
        contexts.retain(|_, c| c.expires_at > now - chrono::Duration::hours(1));
        contexts.get(assertion).cloned()
    }
}

impl Sts {
    /// The condition keys `ProvidedContexts` give a new session.
    pub(crate) fn provided_context(
        &self,
        ctx: &RequestContext,
        contexts: Option<&[ProvidedContext]>,
    ) -> Result<BTreeMap<String, Vec<String>>, ServiceError> {
        let mut keys = BTreeMap::new();
        for c in contexts.unwrap_or_default() {
            let provider = c.provider_arn.as_deref().unwrap_or_default();
            let assertion = c.context_assertion.as_deref().unwrap_or_default();
            if provider != IDENTITY_CENTER_CONTEXT_PROVIDER {
                return Err(validation(format!("{provider} is not a valid context provider ARN.")));
            }
            let found = self
                .context_for(assertion, ctx.received_at)
                .filter(|x| x.provider_arn == provider)
                .ok_or_else(|| validation("The provided context assertion is invalid."))?;
            if found.expires_at <= ctx.received_at {
                return Err(ServiceError::client(
                    "ExpiredTokenException",
                    400,
                    "The provided context assertion has expired.",
                ));
            }
            keys.extend(found.keys);
        }
        Ok(keys)
    }
}
