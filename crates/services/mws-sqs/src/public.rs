//! What other MWS services may do to SQS directly, where AWS couples them:
//! AWS service principals (SNS topics, S3 event notifications, ...)
//! sending messages to a customer's queue. Access is decided by the queue
//! policy alone, with `aws:SourceArn` and `aws:SourceAccount`, as for
//! service principals in AWS; queues encrypted with a customer managed KMS
//! key also need its key policy to let the service use the key.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::messages::{check_outgoing, enqueue, Outgoing};
use crate::names::parse_queue_arn;
use crate::state::{Attr, Queue};
use crate::Sqs;

/// A message attribute a service attaches (SNS raw delivery passes the
/// publisher's attributes through).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceMessageAttribute {
    pub data_type: String,
    pub string_value: Option<String>,
    pub binary_value: Option<Vec<u8>>,
}

/// One message a service sends.
#[derive(Debug, Clone)]
pub struct ServiceMessage<'a> {
    pub queue_arn: &'a str,
    /// e.g. `sns.amazonaws.com`, `s3.amazonaws.com`.
    pub service_principal: &'a str,
    /// The topic, bucket, ... on whose behalf the service sends.
    pub source_arn: &'a str,
    pub source_account: &'a str,
    pub body: String,
    pub message_attributes: BTreeMap<String, ServiceMessageAttribute>,
    /// Required for FIFO queues.
    pub message_group_id: Option<String>,
    pub message_deduplication_id: Option<String>,
    /// Emulated time of the send.
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceSendError {
    NoSuchQueue,
    /// The queue policy (or the queue's KMS key policy) does not let the
    /// service principal send.
    AccessDenied {
        reason: String,
    },
    /// SQS refused the message (size, FIFO parameters, ...).
    Rejected(String),
}

impl fmt::Display for ServiceSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceSendError::NoSuchQueue => write!(f, "The specified queue does not exist."),
            ServiceSendError::AccessDenied { reason } => write!(f, "Access denied: {reason}"),
            ServiceSendError::Rejected(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ServiceSendError {}

fn service_allowed(q: &Queue, principal: &str, source_arn: &str, source_account: &str) -> bool {
    let Some(policy) = q.policy().and_then(|p| Policy::parse(p, PolicyKind::Resource).ok()) else { return false };
    let who = PrincipalInfo { service: Some(principal.to_string()), ..Default::default() };
    let mut context = ConditionContext::new();
    context.insert("aws:SourceArn", vec![source_arn.to_string()]);
    context.insert("aws:SourceAccount", vec![source_account.to_string()]);
    context.insert("aws:PrincipalServiceName", vec![principal.to_string()]);
    context.insert("aws:PrincipalIsAWSService", vec!["true".to_string()]);
    context.insert("aws:ResourceAccount", vec![q.account.clone()]);
    for (k, v) in &q.tags {
        context.insert(format!("aws:ResourceTag/{k}"), vec![v.clone()]);
    }
    let e =
        policy.evaluate(&Request { action: "sqs:SendMessage", resource: &q.arn, principal: &who, context: &context });
    e.allowed() && !e.denied()
}

impl Sqs {
    /// Check that the queue exists and lets `service_principal` send to it
    /// on behalf of `source_arn` (the checks S3 and SNS make when a queue
    /// is configured as a destination).
    pub fn check_service_access(
        &self,
        queue_arn: &str,
        service_principal: &str,
        source_arn: &str,
        source_account: &str,
    ) -> Result<(), ServiceSendError> {
        let st = self.lock();
        let q = st.queues.get(queue_arn).ok_or(ServiceSendError::NoSuchQueue)?;
        if !service_allowed(q, service_principal, source_arn, source_account) {
            return Err(ServiceSendError::AccessDenied {
                reason: format!(
                    "{service_principal} is not authorized to perform: sqs:SendMessage on resource: {queue_arn}"
                ),
            });
        }
        let key = q.attr("KmsMasterKeyId").map(str::to_string);
        let (region, account) = (q.region.clone(), q.account.clone());
        let partition = queue_arn.split(':').nth(1).unwrap_or("aws").to_string();
        drop(st);
        if let (Some(kms), Some(key)) = (&self.kms, key) {
            let key = if key.starts_with("arn:") {
                key
            } else if key.starts_with("alias/") {
                format!("arn:{partition}:kms:{region}:{account}:{key}")
            } else {
                format!("arn:{partition}:kms:{region}:{account}:key/{key}")
            };
            let mut conditions = mws_core::ConditionContext::new();
            conditions.insert("aws:SourceArn".into(), vec![source_arn.to_string()]);
            conditions.insert("aws:SourceAccount".into(), vec![source_account.to_string()]);
            kms.key_for_service(&key, service_principal, &["kms:GenerateDataKey", "kms:Decrypt"], &conditions)
                .map_err(|e| ServiceSendError::AccessDenied { reason: e.message })?;
        }
        Ok(())
    }

    /// Send a message as an AWS service principal. Returns the message id.
    pub fn send_message_as_service(&self, m: ServiceMessage<'_>) -> Result<String, ServiceSendError> {
        if parse_queue_arn(m.queue_arn).is_none() {
            return Err(ServiceSendError::NoSuchQueue);
        }
        self.check_service_access(m.queue_arn, m.service_principal, m.source_arn, m.source_account)?;
        let out = Outgoing {
            body: m.body,
            attributes: m
                .message_attributes
                .into_iter()
                .map(|(k, v)| {
                    (k, Attr { data_type: v.data_type, string_value: v.string_value, binary_value: v.binary_value })
                })
                .collect(),
            // The X-Ray header of the request that caused the delivery.
            trace_header: mws_core::trace_header::current(),
            delay: None,
            group_id: m.message_group_id,
            dedup_id: m.message_deduplication_id,
        };
        let now = m.now.timestamp_millis();
        let mut st = self.lock();
        let q = st.queues.get_mut(m.queue_arn).ok_or(ServiceSendError::NoSuchQueue)?;
        check_outgoing(q, &out).map_err(|e| ServiceSendError::Rejected(e.message))?;
        // AWS reports the service principal as the sender.
        let sent = enqueue(q, out, &service_sender_id(m.service_principal), now, None);
        self.meter.count(m.queue_arn, now, |c| crate::metrics::count_send(c, sent.size, sent.duplicate));
        drop(st);
        self.arrivals.notify_waiters();
        Ok(sent.message_id)
    }
}

/// The `SenderId` messages from a service principal carry.
fn service_sender_id(principal: &str) -> String {
    principal.to_string()
}

impl Sqs {
    /// The URL of the queue `queue_arn` names, as `ctx` sees it. Services
    /// that act on a queue as a caller (Lambda's event source pollers, with
    /// the function's execution role) use it to call SQS's own operations.
    pub fn queue_url_for(ctx: &mws_core::RequestContext, queue_arn: &str) -> Option<String> {
        let (_, account, name) = parse_queue_arn(queue_arn)?;
        Some(crate::names::queue_url(ctx, account, name))
    }

    /// Whether `ctx`'s caller may perform `action` on the queue: its
    /// identity policies or the queue policy must allow it.
    pub fn authorize_caller(
        &self,
        ctx: &mws_core::RequestContext,
        queue_arn: &str,
        action: &str,
    ) -> Result<(), mws_core::ServiceError> {
        let st = self.lock();
        let q = st.queue(queue_arn)?;
        crate::names::authorize_queue(ctx, action, q)
    }
}
