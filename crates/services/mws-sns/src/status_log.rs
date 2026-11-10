//! Delivery status logging: with `<Protocol>SuccessFeedbackRoleArn` /
//! `<Protocol>FailureFeedbackRoleArn` set on a topic (Lambda, SQS, HTTP,
//! Application, Firehose), SNS writes a record of each delivery to
//! CloudWatch Logs as that role: `sns/<region>/<account>/<topic>` for
//! successes (sampled by `<Protocol>SuccessFeedbackSampleRate`, a
//! percentage, none when unset) and `.../Failure` for failures. The role
//! must trust `sns.amazonaws.com` and may need `logs:CreateLogGroup`,
//! `logs:CreateLogStream` and `logs:PutLogEvents`; as in AWS, a record the
//! role cannot write is lost silently.

use md5::{Digest, Md5};
use mws_core::RequestContext;
use serde_json::json;

use crate::publish::Outgoing;
use crate::Sns;

/// One delivery attempt's outcome.
pub(crate) struct Attempt<'a> {
    pub topic_arn: &'a str,
    pub protocol: &'a str,
    pub destination: &'a str,
    pub success: bool,
    pub status_code: u16,
    pub provider_response: String,
    pub attempts: u32,
}

fn attribute_prefix(protocol: &str) -> Option<&'static str> {
    Some(match protocol {
        "lambda" => "Lambda",
        "sqs" => "SQS",
        "http" | "https" => "HTTP",
        "application" => "Application",
        "firehose" => "Firehose",
        _ => return None,
    })
}

/// A request context acting as `role`, assumed by `sns.amazonaws.com` for
/// the topic `topic_arn` (in the topic's region).
pub(crate) fn role_context(
    sts: &mws_sts::Sts,
    ctx: &RequestContext,
    role: &str,
    topic_arn: &str,
    session_name: &str,
) -> Result<RequestContext, String> {
    let parsed = crate::names::parse_sns_arn(topic_arn).ok_or_else(|| format!("{topic_arn} is not a topic ARN"))?;
    let creds = sts
        .assume_role_as_service(&mws_sts::ServiceAssume {
            role_arn: role,
            service_principal: "sns.amazonaws.com",
            session_name,
            duration_seconds: 900,
            source_account: Some(&parsed.account),
            source_arn: Some(topic_arn),
            now: ctx.received_at,
        })
        .map_err(|e| format!("SNS could not assume {role}: {e:?}"))?;
    let resolved = sts
        .credential_store()
        .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
        .map_err(|e| format!("{e:?}"))?
        .ok_or_else(|| "the role session could not be resolved".to_string())?;
    Ok(RequestContext { caller: resolved.caller, region: parsed.region, source_ip: None, ..ctx.clone() })
}

impl Sns {
    /// The STS service, for acting as roles.
    pub(crate) fn sts(&self) -> Option<&mws_sts::Sts> {
        self.inner.status_logs.get().map(|(_, sts)| sts)
    }

    /// Write delivery status logs to `logs`, assuming feedback roles
    /// through `sts`.
    pub fn set_delivery_status_logs(&self, logs: mws_logs::Logs, sts: mws_sts::Sts) {
        let _ = self.inner.status_logs.set((logs, sts));
    }

    pub(crate) fn log_delivery(&self, ctx: &RequestContext, msg: &Outgoing, a: Attempt<'_>) {
        let metric = if a.success { "NumberOfNotificationsDelivered" } else { "NumberOfNotificationsFailed" };
        self.topic_metric(ctx, a.topic_arn, metric, "Count", 1.0);
        let Some((logs, sts)) = self.inner.status_logs.get() else { return };
        let Some(prefix) = attribute_prefix(a.protocol) else { return };
        let attributes = {
            let st = self.lock();
            let Some(t) = st.topics.get(a.topic_arn) else { return };
            t.attributes.clone()
        };
        let kind = if a.success { "Success" } else { "Failure" };
        let Some(role) = attributes.get(&format!("{prefix}{kind}FeedbackRoleArn")).filter(|r| !r.is_empty()) else {
            return;
        };
        if a.success {
            let rate: u32 =
                attributes.get(&format!("{prefix}SuccessFeedbackSampleRate")).and_then(|r| r.parse().ok()).unwrap_or(0);
            if rate == 0 || (rate < 100 && rand::random::<u32>() % 100 >= rate) {
                return;
            }
        }
        let mut parts = a.topic_arn.splitn(6, ':');
        let (Some(_), Some(_), Some(_), Some(region), Some(account), Some(name)) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return;
        };
        let Ok(role_ctx) = role_context(sts, ctx, role, a.topic_arn, "SNSDeliveryStatusLogging") else { return };
        let body = msg.message_for(a.protocol);
        let md5: String = Md5::digest(body.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        let now = ctx.received_at;
        let record = json!({
            "notification": {
                "messageMD5Sum": md5,
                "messageId": msg.message_id,
                "topicArn": a.topic_arn,
                "timestamp": msg.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            },
            "delivery": {
                "deliveryId": uuid::Uuid::new_v4().to_string(),
                "destination": a.destination,
                "providerResponse": a.provider_response,
                "dwellTimeMs": (now - msg.timestamp).num_milliseconds().max(0),
                "attempts": a.attempts,
                "statusCode": a.status_code,
            },
            "status": if a.success { "SUCCESS" } else { "FAILURE" },
        });
        let group = if a.success {
            format!("sns/{region}/{account}/{name}")
        } else {
            format!("sns/{region}/{account}/{name}/Failure")
        };
        let stream = uuid::Uuid::new_v4().to_string();
        let event = mws_logs::ServiceLogEvent { timestamp: now.timestamp_millis(), message: record.to_string() };
        if let Err(e) = logs.put_log_events_as_caller(&role_ctx, &group, &stream, vec![event]) {
            tracing::debug!(topic = a.topic_arn, "delivery status not logged: {}", e.message);
        }
    }
}
