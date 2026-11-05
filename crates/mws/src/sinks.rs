//! Adapters that let one service deliver to another where AWS couples
//! them, kept here so the service crates stay independent.

use std::collections::BTreeMap;

use mws_core::RequestContext;
use mws_events::{Events, ServiceEvent, TargetError, TargetInvocation, TargetSink};
use mws_s3::{EventBridgeSink, ObjectEvent};
use mws_sns::{ServicePublish, ServicePublishError, Sns};
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

/// EventBridge targets that are SNS topics.
pub struct SnsTarget(pub Sns);

#[async_trait::async_trait]
impl TargetSink for SnsTarget {
    async fn deliver(&self, inv: TargetInvocation<'_>) -> Result<(), TargetError> {
        let fifo = inv.target_arn.ends_with(".fifo");
        let publish = ServicePublish {
            topic_arn: inv.target_arn,
            service_principal: inv.service_principal,
            source_arn: inv.source_arn,
            source_account: inv.source_account,
            message: inv.payload.to_string(),
            subject: None,
            attributes: inv.message_attributes.iter().map(|(k, v)| (k.clone(), ("String".into(), v.clone()))).collect(),
            message_group_id: inv.message_group_id.map(str::to_string),
            message_deduplication_id: fifo.then(|| uuid::Uuid::new_v4().to_string()),
        };
        match self.0.publish_as_service(inv.ctx, &publish) {
            Ok(_) => Ok(()),
            Err(ServicePublishError::NoSuchTopic) => Err(TargetError::permanent(
                "ResourceNotFoundException",
                format!("The topic {} does not exist.", inv.target_arn),
            )),
            Err(ServicePublishError::AccessDenied) => Err(TargetError::permanent(
                "AccessDeniedException",
                format!(
                    "events.amazonaws.com is not authorized to perform: SNS:Publish on resource: {}",
                    inv.target_arn
                ),
            )),
            Err(ServicePublishError::Rejected(m)) => Err(TargetError::permanent("SNSException", m)),
        }
    }
}

/// S3 buses with EventBridge notifications turned on put their object
/// events on the bucket owner's default bus, in S3's EventBridge format.
pub struct S3ToEvents(pub Events);

/// The EventBridge `detail-type` for an S3 notification event, if S3
/// sends that event to EventBridge.
fn s3_detail_type(event_name: &str) -> Option<&'static str> {
    let (group, kind) = event_name.split_once(':').unwrap_or((event_name, ""));
    Some(match (group, kind) {
        ("ObjectCreated", _) => "Object Created",
        ("ObjectRemoved", _) | ("LifecycleExpiration", _) => "Object Deleted",
        ("ObjectRestore", "Post") => "Object Restore Initiated",
        ("ObjectRestore", "Completed") => "Object Restore Completed",
        ("ObjectRestore", "Delete") => "Object Restore Expired",
        ("ObjectTagging", "Put") => "Object Tags Added",
        ("ObjectTagging", "Delete") => "Object Tags Deleted",
        ("ObjectAcl", "Put") => "Object ACL Updated",
        ("LifecycleTransition", _) => "Object Storage Class Changed",
        ("IntelligentTiering", _) => "Object Access Tier Changed",
        _ => return None,
    })
}

impl EventBridgeSink for S3ToEvents {
    fn object_event(&self, ctx: &RequestContext, e: &ObjectEvent) {
        let Some(detail_type) = s3_detail_type(&e.event_name) else { return };
        let mut object = serde_json::json!({ "key": e.key, "sequencer": e.sequencer });
        if detail_type == "Object Created" {
            object["size"] = serde_json::json!(e.size.unwrap_or(0));
            if let Some(etag) = &e.etag {
                object["etag"] = serde_json::json!(etag.trim_matches('"'));
            }
        }
        if let Some(v) = &e.version_id {
            object["version-id"] = serde_json::json!(v);
        }
        let reason = if e.event_name.starts_with("LifecycleExpiration") {
            "Lifecycle Expiration".to_string()
        } else {
            e.reason.clone()
        };
        let mut detail = serde_json::json!({
            "version": "0",
            "bucket": { "name": e.bucket },
            "object": object,
            "request-id": e.request_id,
            "requester": e.requester,
            "source-ip-address": e.source_ip,
            "reason": reason,
        });
        if let Some(d) = &e.deletion_type {
            detail["deletion-type"] = serde_json::json!(d);
        }
        self.0.put_service_event(
            ctx,
            ServiceEvent {
                partition: e.partition.clone(),
                account: e.bucket_owner.clone(),
                region: e.region.clone(),
                source: "aws.s3".into(),
                detail_type: detail_type.into(),
                resources: vec![format!("arn:{}:s3:::{}", e.partition, e.bucket)],
                detail,
                time: e.time,
            },
        );
    }
}

/// SSM parameter policies' "Parameter Store Policy Action" events, put on
/// the parameter's account's default bus as the emulated clock reaches them.
pub struct SsmPolicyEvents {
    pub ssm: mws_ssm::Ssm,
    pub partition: String,
}

impl mws_events::ClockSource for SsmPolicyEvents {
    fn due_events(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<ServiceEvent> {
        self.ssm
            .take_policy_events(now)
            .into_iter()
            .map(|e| {
                let name = e.name.strip_prefix('/').unwrap_or(&e.name).to_string();
                ServiceEvent {
                    resources: vec![format!("arn:{}:ssm:{}:{}:parameter/{name}", self.partition, e.region, e.account)],
                    partition: self.partition.clone(),
                    account: e.account,
                    region: e.region,
                    source: "aws.ssm".into(),
                    detail_type: "Parameter Store Policy Action".into(),
                    detail: serde_json::json!({
                        "parameter-name": e.name,
                        "parameter-type": e.parameter_type,
                        "policy-type": e.policy_type,
                        "action-status": e.action_status,
                        "action-reason": e.action_reason,
                    }),
                    time: e.time,
                }
            })
            .collect()
    }
}

/// Parameter Store's "Parameter Store Change" events (create, update,
/// delete, label), put on the parameter's account's default bus.
pub struct SsmChangeEvents(pub Events);

impl mws_ssm::ParameterChangeSink for SsmChangeEvents {
    fn parameter_changed(&self, ctx: &RequestContext, c: mws_ssm::ParameterChange) {
        let mut detail = serde_json::json!({
            "operation": c.operation,
            "name": c.name,
            "type": c.parameter_type,
        });
        if let Some(d) = c.description {
            detail["description"] = serde_json::json!(d);
        }
        self.0.put_service_event(
            ctx,
            ServiceEvent {
                partition: c.partition,
                account: c.account,
                region: c.region,
                source: "aws.ssm".into(),
                detail_type: "Parameter Store Change".into(),
                resources: vec![c.arn],
                detail,
                time: c.time,
            },
        );
    }
}

/// ACM's EventBridge events (certificate available, expired, renewal
/// action required, approaching expiration) and its daily `DaysToExpiry`
/// metric, both on the emulated clock.
pub struct AcmEvents {
    pub acm: mws_acm::Acm,
    pub cloudwatch: mws_cloudwatch::CloudWatch,
    pub partition: String,
}

impl mws_events::ClockSource for AcmEvents {
    fn due_events(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<ServiceEvent> {
        let events = self.acm.take_events(now);
        for m in self.acm.take_days_to_expiry(now) {
            self.cloudwatch.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: m.account,
                region: m.region,
                namespace: "AWS/CertificateManager".into(),
                metric_name: "DaysToExpiry".into(),
                dimensions: vec![("CertificateArn".into(), m.certificate_arn)],
                unit: None,
                timestamp: m.time,
                values: vec![(m.days, 1.0)],
            });
        }
        events
            .into_iter()
            .map(|e| ServiceEvent {
                partition: self.partition.clone(),
                account: e.account,
                region: e.region,
                source: "aws.acm".into(),
                detail_type: e.detail_type,
                resources: e.resources,
                detail: e.detail,
                time: e.time,
            })
            .collect()
    }
}

/// EventBridge targets that are Kinesis data streams, written as the
/// target's role.
pub struct KinesisTarget(pub mws_kinesis::Kinesis);

fn target_error(e: mws_core::ServiceError) -> TargetError {
    TargetError {
        code: e.code.to_string(),
        message: e.message.to_string(),
        retryable: e.status >= 500 || e.code.contains("Throughput"),
    }
}

#[async_trait::async_trait]
impl TargetSink for KinesisTarget {
    async fn deliver(&self, inv: TargetInvocation<'_>) -> Result<(), TargetError> {
        let ctx = inv.role_context()?;
        let partition_key = inv.partition_key.map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.0
            .put_record(
                &ctx,
                mws_kinesis::generated::types::PutRecordInput {
                    stream_arn: Some(inv.target_arn.to_string()),
                    partition_key: Some(partition_key),
                    data: inv.payload.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .map(|_| ())
            .map_err(target_error)
    }
}

/// EventBridge targets that are Firehose streams, written as the target's
/// role.
pub struct FirehoseTarget(pub mws_firehose::Firehose);

#[async_trait::async_trait]
impl TargetSink for FirehoseTarget {
    async fn deliver(&self, inv: TargetInvocation<'_>) -> Result<(), TargetError> {
        let ctx = inv.role_context()?;
        let name = inv.target_arn.rsplit_once("deliverystream/").map(|(_, n)| n).unwrap_or(inv.target_arn);
        self.0
            .put_record(
                &ctx,
                mws_firehose::generated::types::PutRecordInput {
                    delivery_stream_name: name.to_string(),
                    record: mws_firehose::generated::types::Record { data: inv.payload.as_bytes().to_vec() },
                },
            )
            .map(|_| ())
            .map_err(target_error)
    }
}

/// Route 53 health checks for EventBridge global endpoint failover.
pub struct Route53HealthChecks(pub mws_route53::Route53);

impl mws_events::HealthChecks for Route53HealthChecks {
    fn healthy(&self, health_check_arn: &str) -> Option<bool> {
        self.0.health_check_healthy(health_check_arn)
    }
}

/// GuardDuty's findings and scan results on the account's default bus.
pub struct GuardDutyToEvents(pub Events);

impl mws_guardduty::EventSink for GuardDutyToEvents {
    fn put_event(&self, ctx: &RequestContext, e: mws_guardduty::GuardDutyEvent) {
        self.0.put_service_event(
            ctx,
            ServiceEvent {
                partition: e.partition,
                account: e.account,
                region: e.region,
                source: "aws.guardduty".into(),
                detail_type: e.detail_type,
                resources: Vec::new(),
                detail: e.detail,
                time: e.time,
            },
        );
    }
}

/// EC2 Image Builder image state changes, as the EventBridge event
/// "EC2 Image Builder Image State Change".
pub struct ImageBuilderEvents(pub Events);

impl mws_imagebuilder::ImageEvents for ImageBuilderEvents {
    fn image_state_changed(&self, ctx: &RequestContext, c: &mws_imagebuilder::ImageStateChange) {
        let mut detail = serde_json::json!({ "state": { "status": c.status } });
        if let Some(prev) = &c.previous_status {
            detail["previous-state"] = serde_json::json!({ "status": prev });
        }
        if let Some(reason) = &c.reason {
            detail["state"]["reason"] = serde_json::json!(reason);
        }
        let ctx = RequestContext { region: c.region.clone(), ..ctx.clone() };
        self.0.put_service_event(
            &ctx,
            ServiceEvent {
                partition: c.partition.clone(),
                account: c.account.clone(),
                region: c.region.clone(),
                source: "aws.imagebuilder".into(),
                detail_type: "EC2 Image Builder Image State Change".into(),
                resources: vec![c.image_build_version_arn.clone()],
                detail,
                time: c.time,
            },
        );
    }
}
