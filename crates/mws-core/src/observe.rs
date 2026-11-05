//! Seeing API calls after they are answered.
//!
//! AWS meters API calls in several places (`AWS/Usage` `CallCount`
//! metrics, request charges on the bill). The gateway reports every signed
//! request it routed to a service, with the IAM actions the handler asked
//! to authorize, to the [`RequestObserver`]s registered with it.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::{Authorizer, AuthzDecision, AuthzRequest};

/// One answered API call.
#[derive(Debug, Clone)]
pub struct ApiCall {
    pub request_id: String,
    /// The SigV4 signing name of the service that handled it.
    pub service: &'static str,
    /// The calling account.
    pub account: String,
    pub region: String,
    /// When the call was received, on the emulated clock.
    pub at: DateTime<Utc>,
    /// The IAM actions the handler authorized (`kms:Encrypt`), in order and
    /// without repeats. The first names the operation for nearly every
    /// handler.
    pub actions: Vec<String>,
    /// The HTTP status of the response.
    pub status: u16,
}

impl ApiCall {
    /// The operation, as the first authorized action's name (`Encrypt`).
    pub fn operation(&self) -> Option<&str> {
        self.actions.first().and_then(|a| a.split_once(':')).map(|(_, op)| op)
    }

    pub fn succeeded(&self) -> bool {
        self.status < 400
    }
}

/// Told about every API call the gateway answered. Called after the
/// response is ready, outside any service's locks.
pub trait RequestObserver: Send + Sync {
    fn observe(&self, call: &ApiCall);
}

/// Wraps the real authorizer for one request and remembers the actions it
/// was asked about.
pub struct RecordingAuthorizer {
    inner: Arc<dyn Authorizer>,
    actions: Mutex<Vec<String>>,
}

/// Most actions one request may record (background work can hold on to a
/// request's context).
const MAX_ACTIONS: usize = 16;

impl RecordingAuthorizer {
    pub fn new(inner: Arc<dyn Authorizer>) -> Self {
        Self { inner, actions: Mutex::new(Vec::new()) }
    }

    pub fn actions(&self) -> Vec<String> {
        self.actions.lock().expect("recording authorizer lock poisoned").clone()
    }
}

impl Authorizer for RecordingAuthorizer {
    fn authorize(&self, request: &AuthzRequest<'_>) -> AuthzDecision {
        {
            let mut actions = self.actions.lock().expect("recording authorizer lock poisoned");
            if actions.len() < MAX_ACTIONS && !actions.iter().any(|a| a == request.action) {
                actions.push(request.action.to_string());
            }
        }
        self.inner.authorize(request)
    }
}
