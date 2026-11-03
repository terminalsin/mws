//! Glue between services whose crates cannot depend on each other (the
//! dependency would run in a cycle), wired where AWS couples them.

use mws_core::RequestContext;
use mws_s3::{NotificationDestination, NotificationSource};
use mws_sns::{QueueDelivery, QueueMessage};
use mws_sqs::{ServiceMessage, ServiceMessageAttribute, ServiceSendError, Sqs};

/// SNS delivering to `sqs` subscriptions and dead-letter queues.
pub(crate) struct SnsToSqs(pub Sqs);

impl QueueDelivery for SnsToSqs {
    fn send(&self, m: QueueMessage) -> Result<String, String> {
        let attributes = m
            .message_attributes
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    ServiceMessageAttribute {
                        data_type: v.data_type,
                        string_value: v.string_value,
                        binary_value: v.binary_value,
                    },
                )
            })
            .collect();
        self.0
            .send_message_as_service(ServiceMessage {
                queue_arn: &m.queue_arn,
                service_principal: &m.service_principal,
                source_arn: &m.source_arn,
                source_account: &m.source_account,
                body: m.body,
                message_attributes: attributes,
                message_group_id: m.message_group_id,
                message_deduplication_id: m.message_deduplication_id,
                now: m.now,
            })
            .map_err(|e| e.to_string())
    }
}

/// S3 event notifications sent to queues as `s3.amazonaws.com`.
pub(crate) struct S3ToSqs(pub Sqs);

const S3_PRINCIPAL: &str = "s3.amazonaws.com";

impl NotificationDestination for S3ToSqs {
    fn service(&self) -> &'static str {
        "sqs"
    }

    fn check(&self, _ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>) -> Result<(), String> {
        if arn.ends_with(".fifo") {
            return Err("FIFO SQS queues are not supported as notification destinations".to_string());
        }
        self.0.check_service_access(arn, S3_PRINCIPAL, source.bucket_arn, source.bucket_owner).map_err(|e| match e {
            ServiceSendError::NoSuchQueue => "The destination queue does not exist".to_string(),
            _ => "Permissions on the destination queue do not allow S3 to publish notifications from this bucket"
                .to_string(),
        })
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>, message: String) {
        let sent = self.0.send_message_as_service(ServiceMessage {
            queue_arn: arn,
            service_principal: S3_PRINCIPAL,
            source_arn: source.bucket_arn,
            source_account: source.bucket_owner,
            body: message,
            message_attributes: Default::default(),
            message_group_id: None,
            message_deduplication_id: None,
            now: ctx.received_at,
        });
        if let Err(e) = sent {
            tracing::warn!(queue = arn, "S3 could not send a notification: {e}");
        }
    }
}

/// Lambda's event source pollers reading SQS queues as the function's
/// execution role, through SQS's own operations.
pub(crate) struct LambdaFromSqs(pub Sqs);

fn queue_url(ctx: &RequestContext, arn: &str) -> Result<String, mws_core::ServiceError> {
    Sqs::queue_url_for(ctx, arn).ok_or_else(|| {
        mws_core::ServiceError::client(
            "AWS.SimpleQueueService.NonExistentQueue",
            400,
            "The specified queue does not exist.",
        )
    })
}

#[async_trait::async_trait]
impl mws_lambda::QueueSource for LambdaFromSqs {
    fn facts(&self, ctx: &RequestContext, queue_arn: &str) -> Result<mws_lambda::QueueFacts, mws_core::ServiceError> {
        let out = self.0.get_queue_attributes(
            ctx,
            mws_sqs::generated::types::GetQueueAttributesRequest {
                queue_url: queue_url(ctx, queue_arn)?,
                attribute_names: Some(vec!["VisibilityTimeout".into(), "FifoQueue".into()]),
            },
        )?;
        let attrs = out.attributes.unwrap_or_default();
        Ok(mws_lambda::QueueFacts {
            visibility_timeout: attrs.get("VisibilityTimeout").and_then(|v| v.parse().ok()).unwrap_or(30),
            fifo: attrs.get("FifoQueue").is_some_and(|v| v == "true"),
        })
    }

    fn authorize(&self, ctx: &RequestContext, queue_arn: &str, action: &str) -> Result<(), mws_core::ServiceError> {
        self.0.authorize_caller(ctx, queue_arn, action)
    }

    async fn receive(
        &self,
        ctx: &RequestContext,
        queue_arn: &str,
        max: i32,
    ) -> Result<Vec<mws_lambda::QueueMessage>, mws_core::ServiceError> {
        let out = self
            .0
            .receive_message(
                ctx,
                mws_sqs::generated::types::ReceiveMessageRequest {
                    queue_url: queue_url(ctx, queue_arn)?,
                    max_number_of_messages: Some(max.clamp(1, 10)),
                    wait_time_seconds: Some(0),
                    message_system_attribute_names: Some(vec!["All".into()]),
                    message_attribute_names: Some(vec!["All".into()]),
                    ..Default::default()
                },
            )
            .await?;
        Ok(out
            .messages
            .unwrap_or_default()
            .into_iter()
            .map(|m| mws_lambda::QueueMessage {
                message_id: m.message_id.unwrap_or_default(),
                receipt_handle: m.receipt_handle.unwrap_or_default(),
                body: m.body.unwrap_or_default(),
                md5_of_body: m.md5_of_body.unwrap_or_default(),
                md5_of_message_attributes: m.md5_of_message_attributes,
                attributes: m.attributes.unwrap_or_default(),
                message_attributes: m
                    .message_attributes
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            mws_lambda::QueueMessageAttribute {
                                data_type: v.data_type,
                                string_value: v.string_value,
                                binary_value: v.binary_value,
                            },
                        )
                    })
                    .collect(),
            })
            .collect())
    }

    fn delete(
        &self,
        ctx: &RequestContext,
        queue_arn: &str,
        receipt_handles: &[String],
    ) -> Result<(), mws_core::ServiceError> {
        let url = queue_url(ctx, queue_arn)?;
        for chunk in receipt_handles.chunks(10) {
            self.0.delete_message_batch(
                ctx,
                mws_sqs::generated::types::DeleteMessageBatchRequest {
                    queue_url: url.clone(),
                    entries: chunk
                        .iter()
                        .enumerate()
                        .map(|(i, h)| mws_sqs::generated::types::DeleteMessageBatchRequestEntry {
                            id: i.to_string(),
                            receipt_handle: h.clone(),
                        })
                        .collect(),
                },
            )?;
        }
        Ok(())
    }
}

/// CloudWatch Logs subscription filters invoking Lambda functions, as
/// `logs.amazonaws.com` (or its Regional form), asynchronously.
pub(crate) struct LogsToLambda(pub mws_lambda::Lambda);

const LOGS_PERMISSION: &str =
    "Could not execute the lambda function. Make sure you have given CloudWatch Logs permission to execute your function.";

impl LogsToLambda {
    fn principals(region: &str) -> [String; 2] {
        ["logs.amazonaws.com".to_string(), format!("logs.{region}.amazonaws.com")]
    }
}

impl mws_logs::SubscriptionTarget for LogsToLambda {
    fn service(&self) -> &'static str {
        "lambda"
    }

    fn check(&self, ctx: &RequestContext, arn: &str, source: &mws_logs::SubscriptionSource<'_>) -> Result<(), String> {
        let allowed = Self::principals(&ctx.region).iter().any(|p| {
            let inv = mws_lambda::ServiceInvocation {
                function: arn,
                service_principal: p,
                source_account: Some(source.account),
                source_arn: Some(source.log_group_arn),
                payload: Vec::new(),
            };
            self.0.check_service_invoke(ctx, &inv).is_ok()
        });
        if allowed {
            Ok(())
        } else {
            Err(LOGS_PERMISSION.to_string())
        }
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &mws_logs::SubscriptionSource<'_>, payload: Vec<u8>) {
        for p in Self::principals(&ctx.region) {
            let inv = mws_lambda::ServiceInvocation {
                function: arn,
                service_principal: &p,
                source_account: Some(source.account),
                source_arn: Some(source.log_group_arn),
                payload: payload.clone(),
            };
            match self.0.invoke_event_as_service(ctx, inv) {
                Ok(()) => return,
                Err(mws_lambda::ServiceInvokeError::AccessDenied) => continue,
                Err(e) => {
                    tracing::debug!(function = arn, "subscription delivery failed: {e:?}");
                    return;
                }
            }
        }
    }
}
