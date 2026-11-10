//! What other MWS services may ask SQS directly, where AWS couples them:
//! whether an AWS service principal (an SNS topic, an S3 event
//! notification, ...) may send to a customer's queue, which those services
//! check when a notification is configured. The messages themselves go
//! through SQS's own `SendMessage`, called with `RequestContext::as_service`.
//! Access is decided by the queue policy alone, with `aws:SourceArn` and
//! `aws:SourceAccount`, as for service principals in AWS; queues encrypted
//! with a customer managed KMS key also need its key policy to let the
//! service use the key.

use std::fmt;

use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::names::parse_queue_arn;
use crate::state::Queue;
use crate::Sqs;

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
