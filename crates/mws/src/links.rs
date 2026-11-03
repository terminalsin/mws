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
