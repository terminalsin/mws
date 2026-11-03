//! Delivering events to targets, with the target's retry policy and
//! dead-letter queue.

use std::collections::BTreeMap;
use std::time::Duration;

use mws_core::{ConditionContext, RequestContext};
use mws_iam_policy::{Policy, PolicyKind, PrincipalInfo, Request};
use serde_json::Value;

use crate::generated::types;
use crate::ingest::timestamp;
use crate::names::{self, BusRef};
use crate::state::Rule;
use crate::transform::{self, Reserved};
use crate::Events;

pub(crate) const SERVICE_PRINCIPAL: &str = "events.amazonaws.com";

/// An event on its way to a target that another MWS service owns.
pub struct TargetInvocation<'a> {
    /// The context deliveries run in: its endpoint, authorizer and clock.
    pub ctx: &'a RequestContext,
    pub target_arn: &'a str,
    /// The role the target names, if any.
    pub role_arn: Option<&'a str>,
    /// What the target receives, after input transformation.
    pub payload: &'a str,
    /// `events.amazonaws.com`.
    pub service_principal: &'a str,
    /// The rule's ARN and account, for `aws:SourceArn` / `aws:SourceAccount`.
    pub source_arn: &'a str,
    pub source_account: &'a str,
    /// `SqsParameters.MessageGroupId` for FIFO queues.
    pub message_group_id: Option<&'a str>,
    /// Message attributes, set for dead-letter messages.
    pub message_attributes: &'a BTreeMap<String, String>,
}

/// Why a delivery failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetError {
    pub code: String,
    pub message: String,
    /// Whether EventBridge should try again.
    pub retryable: bool,
}

impl TargetError {
    pub fn permanent(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into(), retryable: false }
    }

    pub fn retryable(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into(), retryable: true }
    }
}

/// Delivers to targets of one service; see [`Events::register_target_sink`].
#[async_trait::async_trait]
pub trait TargetSink: Send + Sync {
    async fn deliver(&self, invocation: TargetInvocation<'_>) -> Result<(), TargetError>;
}

#[derive(Clone)]
pub(crate) struct Delivery {
    pub ctx: RequestContext,
    pub bus: BusRef,
    pub rule_arn: String,
    pub rule_name: String,
    pub target: types::Target,
    pub event: Value,
    pub ingested: chrono::DateTime<chrono::Utc>,
    /// How many buses this event has already been forwarded through.
    pub hops: u8,
}

const MAX_HOPS: u8 = 2;

impl Events {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_delivery(
        &self,
        ctx: &RequestContext,
        bus: &BusRef,
        rule: &Rule,
        target: types::Target,
        event: Value,
        ingested: chrono::DateTime<chrono::Utc>,
        hops: u8,
    ) {
        let d = Delivery {
            ctx: ctx.clone(),
            bus: bus.clone(),
            rule_arn: rule.arn.clone(),
            rule_name: rule.name.clone(),
            target,
            event,
            ingested,
            hops,
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move { me.deliver_with_retries(d).await });
    }

    async fn deliver_with_retries(&self, d: Delivery) {
        let retry = d.target.retry_policy.clone().unwrap_or_default();
        let max_retries = retry.maximum_retry_attempts.unwrap_or(185).max(0) as u32;
        let max_age = Duration::from_secs(retry.maximum_event_age_in_seconds.unwrap_or(86_400).max(0) as u64);
        let started = std::time::Instant::now();
        let mut attempt = 0u32;
        let (error, condition) = loop {
            match self.deliver_once(&d).await {
                Ok(()) => return,
                Err(e) if !e.retryable => break (e, "RetriesExhausted"),
                Err(e) => {
                    if attempt >= max_retries {
                        break (e, "MaximumRetryAttemptsExceeded");
                    }
                    let delay = Duration::from_millis(500u64 << attempt.min(6)).min(Duration::from_secs(30));
                    if started.elapsed() + delay > max_age {
                        break (e, "MaximumEventAgeExceeded");
                    }
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                }
            }
        };
        tracing::info!(
            rule = %d.rule_arn, target = %d.target.arn, code = %error.code,
            "EventBridge could not deliver an event: {}", error.message
        );
        self.dead_letter(&d, &error, condition, attempt).await;
    }

    /// Send a failed event to the target's dead-letter queue, with the
    /// attributes EventBridge adds.
    async fn dead_letter(&self, d: &Delivery, error: &TargetError, condition: &str, attempts: u32) {
        let Some(queue) = d.target.dead_letter_config.as_ref().and_then(|c| c.arn.clone()) else { return };
        let Some(sink) = self.sink("sqs") else { return };
        let attributes: BTreeMap<String, String> = [
            ("RULE_ARN", d.rule_arn.clone()),
            ("TARGET_ARN", d.target.arn.clone()),
            ("ERROR_CODE", error.code.clone()),
            ("ERROR_MESSAGE", error.message.clone()),
            ("EXHAUSTED_RETRY_CONDITION", condition.to_string()),
            ("RETRY_ATTEMPTS", attempts.to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let payload = d.event.to_string();
        let ctx = self.delivery_ctx(&d.ctx);
        let result = sink
            .deliver(TargetInvocation {
                ctx: &ctx,
                target_arn: &queue,
                role_arn: None,
                payload: &payload,
                service_principal: SERVICE_PRINCIPAL,
                source_arn: &d.rule_arn,
                source_account: &d.bus.account,
                message_group_id: None,
                message_attributes: &attributes,
            })
            .await;
        if let Err(e) = result {
            tracing::info!(queue = %queue, "EventBridge could not send to the dead-letter queue: {}", e.message);
        }
    }

    pub(crate) fn delivery_ctx(&self, ctx: &RequestContext) -> RequestContext {
        RequestContext {
            received_at: self.now().max(ctx.received_at),
            request_id: uuid::Uuid::new_v4().to_string(),
            ..ctx.clone()
        }
    }

    async fn deliver_once(&self, d: &Delivery) -> Result<(), TargetError> {
        let ingestion_time = timestamp(d.ingested);
        let payload = transform::payload(
            &d.target,
            &d.event,
            &Reserved { rule_arn: &d.rule_arn, rule_name: &d.rule_name, ingestion_time: &ingestion_time },
        );
        let ctx = self.delivery_ctx(&d.ctx);
        let Some((_, service, _, _, resource)) = names::split_arn(&d.target.arn) else {
            return Err(TargetError::permanent("InvalidTarget", "The target ARN is not valid."));
        };
        match service {
            "lambda" => self.deliver_lambda(&ctx, d, payload),
            "logs" => self.deliver_logs(&ctx, d, &payload),
            "events" if resource.starts_with("event-bus/") => self.deliver_bus(&ctx, d),
            "events" if resource.starts_with("api-destination/") => {
                self.deliver_api_destination(&ctx, d, &payload).await
            }
            other => match self.sink(other) {
                Some(sink) => {
                    let attributes = BTreeMap::new();
                    sink.deliver(TargetInvocation {
                        ctx: &ctx,
                        target_arn: &d.target.arn,
                        role_arn: d.target.role_arn.as_deref(),
                        payload: &payload,
                        service_principal: SERVICE_PRINCIPAL,
                        source_arn: &d.rule_arn,
                        source_account: &d.bus.account,
                        message_group_id: d.target.sqs_parameters.as_ref().and_then(|p| p.message_group_id.as_deref()),
                        message_attributes: &attributes,
                    })
                    .await
                }
                None => {
                    tracing::info!(target = %d.target.arn, "MWS does not emulate this EventBridge target; event dropped");
                    Ok(())
                }
            },
        }
    }

    fn deliver_lambda(&self, ctx: &RequestContext, d: &Delivery, payload: String) -> Result<(), TargetError> {
        let Some(lambda) = self.inner.lambda.get() else {
            return Err(TargetError::permanent("ResourceNotFoundException", "Lambda is not available."));
        };
        lambda
            .invoke_as_service(
                ctx,
                mws_lambda::ServiceInvoke {
                    function_arn: &d.target.arn,
                    service_principal: SERVICE_PRINCIPAL,
                    source_account: &d.bus.account,
                    source_arn: &d.rule_arn,
                    payload: payload.into_bytes(),
                },
            )
            .map_err(|e| match e {
                mws_lambda::ServiceInvokeError::NoSuchFunction => {
                    TargetError::permanent("ResourceNotFoundException", format!("Function not found: {}", d.target.arn))
                }
                mws_lambda::ServiceInvokeError::AccessDenied => TargetError::permanent(
                    "AccessDeniedException",
                    format!("EventBridge is not authorized to invoke {}", d.target.arn),
                ),
                mws_lambda::ServiceInvokeError::Invalid(m) => {
                    TargetError::permanent("InvalidParameterValueException", m)
                }
            })
    }

    fn deliver_logs(&self, ctx: &RequestContext, d: &Delivery, payload: &str) -> Result<(), TargetError> {
        let Some(logs) = self.inner.logs.get() else {
            return Err(TargetError::permanent("ResourceNotFoundException", "CloudWatch Logs is not available."));
        };
        let Some((partition, _, region, account, resource)) = names::split_arn(&d.target.arn) else {
            return Err(TargetError::permanent("InvalidTarget", "The target ARN is not valid."));
        };
        let group = resource.strip_prefix("log-group:").unwrap_or(resource);
        let group = group.strip_suffix(":*").unwrap_or(group);
        let event_time = d
            .event
            .get("time")
            .and_then(Value::as_str)
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.timestamp_millis())
            .unwrap_or_else(|| ctx.received_at.timestamp_millis());
        // An input transformer for a log group target produces
        // `{"timestamp": ..., "message": ...}`.
        let (timestamp, message) = match serde_json::from_str::<Value>(payload) {
            Ok(Value::Object(m)) if m.len() == 2 && m.contains_key("timestamp") && m.contains_key("message") => {
                let ts = m.get("timestamp").and_then(Value::as_i64).unwrap_or(event_time);
                let msg = match m.get("message") {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => String::new(),
                };
                (ts, msg)
            }
            _ => (event_time, payload.to_string()),
        };
        let stream = d.event.get("id").and_then(Value::as_str).unwrap_or("events").to_string();
        let now = ctx.received_at.timestamp_millis();
        let mut last = None;
        for principal in [SERVICE_PRINCIPAL, "delivery.logs.amazonaws.com"] {
            let w = mws_logs::ServiceLogWriter {
                partition,
                account,
                region,
                log_group: group,
                service_principal: principal,
                source_account: &d.bus.account,
                source_arn: &d.rule_arn,
            };
            let events = vec![mws_logs::ServiceLogEvent { timestamp, message: message.clone() }];
            match logs.put_log_events_as_service(&w, &stream, events, now) {
                Ok(()) => return Ok(()),
                Err(mws_logs::ServiceLogError::AccessDenied { action }) => last = Some(action),
                Err(mws_logs::ServiceLogError::NoSuchLogGroup) => {
                    return Err(TargetError::permanent(
                        "ResourceNotFoundException",
                        "The specified log group does not exist.",
                    ))
                }
                Err(mws_logs::ServiceLogError::Rejected(m)) => {
                    return Err(TargetError::permanent("InvalidParameterException", m))
                }
            }
        }
        Err(TargetError::permanent(
            "AccessDeniedException",
            format!("EventBridge is not authorized to perform {} on {}", last.unwrap_or_default(), d.target.arn),
        ))
    }

    /// A role's identity, as EventBridge gets it by assuming the role.
    pub(crate) fn role_caller(
        &self,
        ctx: &RequestContext,
        role: &str,
        source_arn: &str,
        source_account: &str,
    ) -> Result<mws_core::Caller, TargetError> {
        let Some(sts) = self.inner.sts.get() else {
            return Err(TargetError::permanent("AccessDeniedException", "STS is not available."));
        };
        let creds = sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: role,
                service_principal: SERVICE_PRINCIPAL,
                session_name: "EventBridge",
                duration_seconds: 3600,
                source_account: Some(source_account),
                source_arn: Some(source_arn),
                now: ctx.received_at,
            })
            .map_err(|_| {
                TargetError::permanent("AccessDeniedException", format!("EventBridge cannot assume the role {role}."))
            })?;
        match sts.credential_store().resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at) {
            Ok(Some(r)) => Ok(r.caller),
            _ => Err(TargetError::permanent(
                "AccessDeniedException",
                format!("EventBridge cannot assume the role {role}."),
            )),
        }
    }

    fn deliver_bus(&self, ctx: &RequestContext, d: &Delivery) -> Result<(), TargetError> {
        if d.hops >= MAX_HOPS {
            return Err(TargetError::permanent("ValidationException", "The event has been forwarded too many times."));
        }
        let Some(target) = BusRef::from_arn(&d.target.arn) else {
            return Err(TargetError::permanent("InvalidTarget", "The target ARN is not valid."));
        };
        let source = d.event.get("source").and_then(Value::as_str).unwrap_or_default().to_string();
        let detail_type = d.event.get("detail-type").and_then(Value::as_str).unwrap_or_default().to_string();
        if let Some(role) = &d.target.role_arn {
            let caller = self.role_caller(ctx, role, &d.rule_arn, &d.bus.account)?;
            let rctx = RequestContext { caller, region: target.region.clone(), ..ctx.clone() };
            let mut extra = ConditionContext::new();
            extra.insert("events:source".into(), vec![source]);
            extra.insert("events:detail-type".into(), vec![detail_type]);
            self.authorize_on_bus(&rctx, "events:PutEvents", &target, &target.arn(), extra)
                .map_err(|e| TargetError::permanent("AccessDeniedException", e.message))?;
        } else {
            // Without a role, the receiving bus's policy must let the
            // sending account put events.
            let policy = {
                let st = self.lock();
                st.region(&target.account, &target.region)
                    .and_then(|r| r.buses.get(&target.name))
                    .and_then(|b| b.policy.clone())
            };
            let principal = PrincipalInfo {
                account_id: d.bus.account.clone(),
                arns: vec![format!("arn:{}:iam::{}:root", d.bus.partition, d.bus.account)],
                ..Default::default()
            };
            let mut context = mws_iam_policy::ConditionContext::new();
            context.insert("aws:PrincipalAccount", vec![d.bus.account.clone()]);
            context.insert("events:source", vec![source]);
            context.insert("events:detail-type", vec![detail_type]);
            let resource = target.arn();
            let allowed = policy.and_then(|p| Policy::parse(&p, PolicyKind::Resource).ok()).is_some_and(|p| {
                let e = p.evaluate(&Request {
                    action: "events:PutEvents",
                    resource: &resource,
                    principal: &principal,
                    context: &context,
                });
                e.allowed() && !e.denied()
            });
            if !allowed {
                return Err(TargetError::permanent(
                    "AccessDeniedException",
                    format!("Account {} is not authorized to put events on {resource}.", d.bus.account),
                ));
            }
        }
        if !self.bus_exists(ctx, &target) {
            return Err(TargetError::permanent(
                "ResourceNotFoundException",
                format!("Event bus {} does not exist.", target.name),
            ));
        }
        self.ingest_hops(ctx, &target, &d.event, None, d.hops + 1);
        Ok(())
    }
}
