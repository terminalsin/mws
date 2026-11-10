//! What other MWS services do with SNS directly, where AWS couples them:
//! AWS service principals (S3 event notifications, EventBridge targets, ...)
//! publishing to a customer's topic, judged by the topic's access policy
//! alone; and the queue service SNS delivers `sqs` subscriptions to.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::generated::types::MessageAttributeValue;
use crate::{names, publish, Sns};

/// A message SNS sends to a queue as `sns.amazonaws.com`.
#[derive(Debug, Clone)]
pub struct QueueMessage {
    pub queue_arn: String,
    pub service_principal: String,
    /// The topic (`aws:SourceArn`) and its account (`aws:SourceAccount`).
    pub source_arn: String,
    pub source_account: String,
    pub body: String,
    pub message_attributes: BTreeMap<String, QueueMessageAttribute>,
    pub message_group_id: Option<String>,
    pub message_deduplication_id: Option<String>,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueMessageAttribute {
    pub data_type: String,
    pub string_value: Option<String>,
    pub binary_value: Option<Vec<u8>>,
}

/// Where `sqs` subscriptions go (implemented over the queue service).
#[async_trait::async_trait]
pub trait QueueDelivery: Send + Sync {
    /// Send a message as the service principal, judged by the queue policy.
    /// `ctx` is the request the delivery comes from. Returns the message id.
    async fn send(&self, ctx: &mws_core::RequestContext, message: QueueMessage) -> Result<String, String>;
}

/// A service principal publishing to a topic.
#[derive(Debug, Clone)]
pub struct ServicePublish<'a> {
    pub topic_arn: &'a str,
    /// e.g. `s3.amazonaws.com`.
    pub service_principal: &'a str,
    /// `aws:SourceArn` and `aws:SourceAccount` for the topic policy.
    pub source_arn: &'a str,
    pub source_account: &'a str,
    pub message: String,
    pub subject: Option<String>,
    /// `(data type, string value)` message attributes.
    pub attributes: BTreeMap<String, (String, String)>,
    pub message_group_id: Option<String>,
    pub message_deduplication_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicePublishError {
    NoSuchTopic,
    /// The topic policy does not let the service principal publish.
    AccessDenied,
    /// SNS refused the message.
    Rejected(String),
}

impl fmt::Display for ServicePublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServicePublishError::NoSuchTopic => write!(f, "Topic does not exist"),
            ServicePublishError::AccessDenied => write!(f, "The topic policy does not allow SNS:Publish"),
            ServicePublishError::Rejected(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ServicePublishError {}

impl Sns {
    /// Whether `p`'s service principal may publish to the topic, as S3
    /// checks when a notification configuration is put.
    pub fn check_service_publish(&self, p: &ServicePublish<'_>) -> Result<(), ServicePublishError> {
        let policy = {
            let st = self.lock();
            let topic = st.topics.get(p.topic_arn).ok_or(ServicePublishError::NoSuchTopic)?;
            topic.policy().map(str::to_string)
        };
        let policy = policy.and_then(|d| Policy::parse(&d, PolicyKind::Resource).ok());
        let principal = PrincipalInfo { service: Some(p.service_principal.to_string()), ..Default::default() };
        let mut context = ConditionContext::new();
        context.insert("aws:SourceAccount", vec![p.source_account.to_string()]);
        context.insert("aws:SourceArn", vec![p.source_arn.to_string()]);
        // CloudWatch alarms publish with the legacy `aws:SourceOwner` key
        // (the alarm's account), which the default topic policy admits, so
        // alarms reach their owner's topics without a policy change. SES
        // notifications and event destinations do the same. Other services
        // (EventBridge, S3) need the topic policy to allow them.
        if matches!(p.service_principal, "cloudwatch.amazonaws.com" | "ses.amazonaws.com") {
            context.insert("aws:SourceOwner", vec![p.source_account.to_string()]);
        }
        context.insert("aws:PrincipalServiceName", vec![p.service_principal.to_string()]);
        context.insert("aws:PrincipalIsAWSService", vec!["true".to_string()]);
        let allowed = policy.is_some_and(|policy| {
            let e = policy.evaluate(&Request {
                action: "sns:Publish",
                resource: p.topic_arn,
                principal: &principal,
                context: &context,
            });
            e.allowed() && !e.denied()
        });
        if allowed {
            Ok(())
        } else {
            Err(ServicePublishError::AccessDenied)
        }
    }

    /// Publish as a service principal. `ctx` is the request that caused
    /// it (for the emulator's endpoint and clock); its caller is not
    /// consulted.
    pub fn publish_as_service(
        &self,
        ctx: &RequestContext,
        p: &ServicePublish<'_>,
    ) -> Result<String, ServicePublishError> {
        self.check_service_publish(p)?;
        let topic = self.lock().topics.get(p.topic_arn).cloned().ok_or(ServicePublishError::NoSuchTopic)?;
        // Encrypted topics need the key policy to let the service principal
        // use the key; otherwise the message is lost, as in AWS.
        self.seal_for_service(&topic, p.service_principal, p.source_arn, p.source_account)
            .map_err(|e| ServicePublishError::Rejected(format!("{}: {}", e.code, e.message)))?;
        let parsed = names::parse_sns_arn(p.topic_arn).ok_or(ServicePublishError::NoSuchTopic)?;
        let ctx = RequestContext { region: parsed.region, ..ctx.clone() };
        let attributes: BTreeMap<String, MessageAttributeValue> = p
            .attributes
            .iter()
            .map(|(k, (t, v))| {
                (
                    k.clone(),
                    MessageAttributeValue { data_type: t.clone(), string_value: Some(v.clone()), binary_value: None },
                )
            })
            .collect();
        let r = publish::Request {
            message: &p.message,
            subject: p.subject.as_deref(),
            structure: None,
            attributes: Some(&attributes),
            group_id: p.message_group_id.as_deref(),
            dedup_id: p.message_deduplication_id.as_deref(),
        };
        let rejected = |e: ServiceError| ServicePublishError::Rejected(e.message);
        let structure = publish::check_message(&r).map_err(rejected)?;
        let out = self.publish_to_topic(&ctx, p.topic_arn, p.service_principal, &r, structure).map_err(|e| {
            if e.code == "NotFound" {
                ServicePublishError::NoSuchTopic
            } else {
                rejected(e)
            }
        })?;
        Ok(out.message_id.unwrap_or_default())
    }
}
