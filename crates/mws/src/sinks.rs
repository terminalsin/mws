//! Adapters that let one service deliver to another where AWS couples
//! them, kept here so the service crates stay independent.

use std::collections::BTreeMap;

use mws_events::{TargetError, TargetInvocation, TargetSink};
use mws_sqs::{ServiceMessage, ServiceMessageAttribute, ServiceSendError, Sqs};

/// EventBridge targets and dead-letter queues that are SQS queues.
pub struct SqsTarget(pub Sqs);

#[async_trait::async_trait]
impl TargetSink for SqsTarget {
    async fn deliver(&self, inv: TargetInvocation<'_>) -> Result<(), TargetError> {
        let fifo = inv.target_arn.ends_with(".fifo");
        let message_attributes: BTreeMap<String, ServiceMessageAttribute> = inv
            .message_attributes
            .iter()
            .map(|(k, v)| {
                let attr = ServiceMessageAttribute {
                    data_type: "String".into(),
                    string_value: Some(v.clone()),
                    binary_value: None,
                };
                (k.clone(), attr)
            })
            .collect();
        let message = ServiceMessage {
            queue_arn: inv.target_arn,
            service_principal: inv.service_principal,
            source_arn: inv.source_arn,
            source_account: inv.source_account,
            body: inv.payload.to_string(),
            message_attributes,
            message_group_id: inv.message_group_id.map(str::to_string),
            message_deduplication_id: fifo.then(|| uuid::Uuid::new_v4().to_string()),
            now: inv.ctx.received_at,
        };
        match self.0.send_message_as_service(message) {
            Ok(_) => Ok(()),
            Err(ServiceSendError::NoSuchQueue) => Err(TargetError::permanent(
                "ResourceNotFoundException",
                format!("The queue {} does not exist.", inv.target_arn),
            )),
            Err(ServiceSendError::AccessDenied { reason }) => {
                Err(TargetError::permanent("AccessDeniedException", reason))
            }
            Err(ServiceSendError::Rejected(m)) => Err(TargetError::permanent("SQSException", m)),
        }
    }
}
