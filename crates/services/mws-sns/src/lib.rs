//! Amazon Simple Notification Service for MWS.
//!
//! Topics, subscriptions, platform applications and SMS settings behave as
//! in SNS, and messages are really delivered: to Lambda functions (invoked
//! asynchronously as `sns.amazonaws.com`, judged by the function policy),
//! to HTTP/HTTPS endpoints (signed `SubscriptionConfirmation` and
//! `Notification` POSTs with a real signing certificate), and to SQS queues
//! once the queue service is wired in. Messages SNS would send to people or
//! devices (email, SMS, mobile push) are kept in an outbox that tests read
//! at `/_aws/sns/...`.
//!
//! AWS couples SNS to Lambda (function subscriptions) and S3 (bucket event
//! notifications publish to topics), so this crate uses their public APIs.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/sns_generated.rs"));
}

mod delivery;
mod errors;
mod filter;
mod handler;
mod names;
mod outbox;
mod platform;
mod public;
mod publish;
mod s3;
mod signing;
mod sms;
mod state;
mod status_log;
mod subscriptions;
mod topics;
mod webhook;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use public::{QueueDelivery, QueueMessage, QueueMessageAttribute, ServicePublish, ServicePublishError};
use state::State;

pub(crate) struct Inner {
    state: Mutex<State>,
    lambda: OnceLock<mws_lambda::Lambda>,
    queues: OnceLock<Arc<dyn QueueDelivery>>,
    /// Where delivery status logs go, and how feedback roles are assumed.
    status_logs: OnceLock<(mws_logs::Logs, mws_sts::Sts)>,
    signer: signing::Signer,
}

/// The SNS service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Sns {
    inner: Arc<Inner>,
}

impl Default for Sns {
    fn default() -> Self {
        Self::new()
    }
}

impl Sns {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                lambda: OnceLock::new(),
                queues: OnceLock::new(),
                status_logs: OnceLock::new(),
                signer: signing::Signer::default(),
            }),
        }
    }

    /// Deliver to `lambda` subscriptions through Lambda.
    pub fn with_lambda(self, lambda: mws_lambda::Lambda) -> Self {
        let _ = self.inner.lambda.set(lambda);
        self
    }

    /// Deliver to `sqs` subscriptions (and redrive policies) through the
    /// queue service.
    pub fn set_queues(&self, queues: Arc<dyn QueueDelivery>) {
        let _ = self.inner.queues.set(queues);
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("SNS state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for Sns {
    fn signing_name(&self) -> &'static str {
        "sns"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Some(response) = self.serve_side_channel(&ctx, &request) {
            return response;
        }
        let params = mws_proto_query::read_params(&request);
        generated::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&generated::SERVICE_INFO, request_id, &errors::sns_error(error.clone()))
    }

    /// The links SNS puts in messages work without a signature, as in AWS:
    /// `SubscribeURL` (ConfirmSubscription), `UnsubscribeURL`
    /// (Unsubscribe) and `SigningCertURL`; so do MWS's outbox pages.
    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        if request.uri().path().starts_with(outbox::PREFIX) {
            return true;
        }
        if request.method() != http::Method::GET {
            return false;
        }
        let params = mws_proto_query::read_params(request);
        matches!(params.get("Action"), Some("ConfirmSubscription" | "Unsubscribe"))
            && (params.get("TopicArn").is_some_and(|a| a.contains(":sns:"))
                || params.get("SubscriptionArn").is_some_and(|a| a.contains(":sns:")))
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        Some(serde_json::to_value(&*self.lock()).expect("SNS state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid SNS state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
