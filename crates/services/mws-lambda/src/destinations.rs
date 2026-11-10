//! Where Lambda sends records about invocations it gave up on or finished:
//! asynchronous invocation destinations (`OnSuccess`/`OnFailure`), a
//! function's dead-letter queue, and the on-failure destination of stream
//! event source mappings. As in AWS, Lambda sends them with the function's
//! execution role, so the role needs `sqs:SendMessage`, `sns:Publish`,
//! `events:PutEvents` or `lambda:InvokeFunction` on the destination.
//!
//! Lambda functions are reached directly; the other services are
//! [`DestinationSink`]s the `mws` crate registers, so this crate does not
//! depend on them.

use std::sync::Arc;

use mws_core::{RequestContext, ServiceError};

use crate::names;
use crate::Lambda;

/// A record for a destination.
#[derive(Debug, Clone, Default)]
pub struct DestinationMessage {
    /// The message: an invocation record, or for dead-letter queues the
    /// event itself.
    pub body: String,
    /// String message attributes (`RequestID`, `ErrorMessage`, ...).
    pub string_attributes: Vec<(String, String)>,
    /// Number message attributes (`ErrorCode`).
    pub number_attributes: Vec<(String, String)>,
    /// The EventBridge `detail-type`, for event bus destinations.
    pub detail_type: String,
    /// The function (qualified with the version that ran), for event
    /// `resources`.
    pub function_arn: String,
    /// The object key for S3 bucket destinations; `None` for the
    /// asynchronous invocation key (`aws/lambda/async/<function>/...`).
    pub s3_key: Option<String>,
}

/// The time part of the keys Lambda writes S3 destination records under:
/// `YYYY/MM/DD/YYYY-MM-DDTHH.MM.SS-<uuid>`.
pub(crate) fn s3_key_suffix(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("{}-{}", now.format("%Y/%m/%d/%Y-%m-%dT%H.%M.%S"), uuid::Uuid::new_v4())
}

/// A service Lambda can send destination records to.
#[async_trait::async_trait]
pub trait DestinationSink: Send + Sync {
    /// The ARN service this sink takes (`sqs`, `sns`, `events`, ...).
    fn service(&self) -> &'static str;
    /// Send `message` to `arn` as `ctx.caller` (the execution role).
    async fn send(&self, ctx: &RequestContext, arn: &str, message: &DestinationMessage) -> Result<(), ServiceError>;
}

/// Registered sinks by ARN service.
#[derive(Default)]
pub(crate) struct Sinks(std::sync::RwLock<Vec<Arc<dyn DestinationSink>>>);

impl Sinks {
    fn get(&self, service: &str) -> Option<Arc<dyn DestinationSink>> {
        self.0.read().expect("sink lock poisoned").iter().find(|s| s.service() == service).cloned()
    }
}

impl Lambda {
    /// Send destination records whose ARN names `sink.service()` through
    /// `sink`.
    pub fn add_destination_sink(&self, sink: Arc<dyn DestinationSink>) {
        self.inner.destinations.0.write().expect("sink lock poisoned").push(sink);
    }

    /// Send `message` to `destination` as the execution role of
    /// `function_arn`. Failures are logged and dropped, as Lambda drops
    /// records it cannot deliver.
    pub(crate) async fn send_to_destination(
        &self,
        ctx: &RequestContext,
        function_arn: &str,
        destination: &str,
        message: &DestinationMessage,
    ) {
        if let Err(e) = self.try_send_to_destination(ctx, function_arn, destination, message).await {
            tracing::warn!(%destination, function = %function_arn, "destination record not delivered: {}", e.message);
        }
    }

    async fn try_send_to_destination(
        &self,
        ctx: &RequestContext,
        function_arn: &str,
        destination: &str,
        message: &DestinationMessage,
    ) -> Result<(), ServiceError> {
        let role_ctx = self.role_context(ctx, function_arn)?;
        let service = destination.split(':').nth(2).unwrap_or_default();
        if service == "lambda" {
            let target = names::parse_function(ctx, destination, None)?;
            // The execution role invokes the destination asynchronously.
            self.authorize_function(&role_ctx, "lambda:InvokeFunction", &target, Default::default())?;
            {
                let st = self.read();
                let func = Self::function(&st, &target)?;
                if func.version_for(target.qualifier.as_deref()).is_none() {
                    return Err(target.not_found());
                }
            }
            self.enqueue(&role_ctx, &target, message.body.clone().into_bytes());
            return Ok(());
        }
        if service == "s3" {
            return self.send_to_bucket(&role_ctx, function_arn, destination, message);
        }
        let Some(sink) = self.inner.destinations.get(service) else {
            return Err(crate::generated::errors::service(format!(
                "MWS cannot deliver to {service} destinations: {destination}"
            )));
        };
        sink.send(&role_ctx, destination, message).await
    }

    /// Write a record to an S3 bucket destination as the execution role
    /// (which needs `s3:PutObject`), under Lambda's key layout.
    fn send_to_bucket(
        &self,
        role_ctx: &RequestContext,
        function_arn: &str,
        destination: &str,
        message: &DestinationMessage,
    ) -> Result<(), ServiceError> {
        let Some(s3) = &self.inner.s3 else {
            return Err(crate::generated::errors::service("S3 is not available."));
        };
        let bucket = destination.splitn(6, ':').nth(5).unwrap_or_default().split('/').next().unwrap_or_default();
        let key = match &message.s3_key {
            Some(k) => k.clone(),
            None => {
                let name = function_arn.split(':').nth(6).unwrap_or(function_arn);
                format!("aws/lambda/async/{name}/{}", s3_key_suffix(role_ctx.received_at))
            }
        };
        let body = message.body.clone().into_bytes();
        s3.put_object_as_caller(
            role_ctx,
            mws_s3::generated::types::PutObjectRequest {
                bucket: bucket.to_string(),
                key,
                content_length: Some(body.len() as i64),
                content_type: Some("application/json".into()),
                body,
                ..Default::default()
            },
        )
        .map(|_| ())
    }
}
