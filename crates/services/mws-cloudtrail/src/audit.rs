//! Events from outside AWS, sent through a channel (the CloudTrail Data
//! service's `PutAuditEvents`) into the channel's event data stores.

use mws_core::{ConditionContext, RequestContext};
use serde_json::{json, Value};
use sha2::Digest;

use crate::record::time_string;
use crate::state::EDS_EVENT_LIMIT;
use crate::CloudTrail;

/// One event as `PutAuditEvents` sends it.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub id: String,
    pub event_data: String,
    pub event_data_checksum: Option<String>,
}

/// Why a whole `PutAuditEvents` request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    InvalidChannelArn(String),
    ChannelNotFound(String),
    InsufficientPermission(String),
    DuplicatedId(String),
    /// Authorization failed with this error.
    Denied(mws_core::ServiceError),
}

/// What happened to each event.
#[derive(Debug, Clone, Default)]
pub struct AuditResult {
    /// `(id, eventID)`.
    pub successful: Vec<(String, String)>,
    /// `(id, errorCode, errorMessage)`.
    pub failed: Vec<(String, String, String)>,
}

/// The `eventData` fields the integration event schema requires.
fn check_event_data(v: &Value) -> Result<(), String> {
    let obj = v.as_object().ok_or("eventData must be a JSON object.")?;
    for field in ["version", "userIdentity", "eventSource", "eventName", "eventTime", "UID"] {
        if !obj.contains_key(field) {
            return Err(format!("eventData is missing the required field {field}."));
        }
    }
    let identity = obj["userIdentity"].as_object().ok_or("userIdentity must be an object.")?;
    for field in ["type", "principalId"] {
        if !identity.get(field).is_some_and(Value::is_string) {
            return Err(format!("userIdentity is missing the required field {field}."));
        }
    }
    let time = obj["eventTime"].as_str().ok_or("eventTime must be a string.")?;
    chrono::DateTime::parse_from_rfc3339(time).map_err(|_| format!("eventTime {time} is not a valid timestamp."))?;
    Ok(())
}

impl CloudTrail {
    /// Ingest events through `channel_arn` as the caller.
    pub fn put_audit_events(
        &self,
        ctx: &RequestContext,
        channel_arn: &str,
        external_id: Option<&str>,
        events: Vec<AuditEvent>,
    ) -> Result<AuditResult, AuditError> {
        let parsed = crate::names::parse_arn(channel_arn)
            .filter(|a| a.kind == "channel")
            .ok_or_else(|| AuditError::InvalidChannelArn(format!("Channel ARN {channel_arn} is not valid.")))?;
        let (channel, policy) = {
            let st = self.lock();
            let account = st.accounts.get(&parsed.account);
            let channel = account
                .and_then(|a| a.channels.get(channel_arn))
                .cloned()
                .ok_or_else(|| AuditError::ChannelNotFound(format!("Channel {channel_arn} was not found.")))?;
            (channel, account.and_then(|a| a.resource_policies.get(channel_arn)).cloned())
        };
        let mut keys = ConditionContext::new();
        if let Some(e) = external_id {
            keys.insert("cloudtrail:ExternalId".into(), vec![e.to_string()]);
        }
        let allowed = if parsed.account == ctx.caller.account_id {
            ctx.authorize_with_resource_policy("cloudtrail-data:PutAuditEvents", channel_arn, policy.as_deref(), keys)
        } else {
            match &policy {
                Some(p) => {
                    ctx.authorize_with_required_resource_policy("cloudtrail-data:PutAuditEvents", channel_arn, p, keys)
                }
                None => {
                    return Err(AuditError::InsufficientPermission(format!(
                        "The caller does not have permission to put audit events into channel {channel_arn}."
                    )))
                }
            }
        };
        if let Err(e) = allowed {
            return Err(if e.code == "AccessDenied" || e.code == "AccessDeniedException" {
                AuditError::InsufficientPermission(format!(
                    "The caller does not have permission to put audit events into channel {channel_arn}."
                ))
            } else {
                AuditError::Denied(e)
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for e in &events {
            if !seen.insert(e.id.as_str()) {
                return Err(AuditError::DuplicatedId(format!(
                    "Two or more entries in the request have the same event ID {}.",
                    e.id
                )));
            }
        }
        let mut out = AuditResult::default();
        let mut records = Vec::new();
        for e in events {
            if let Some(sum) = &e.event_data_checksum {
                if *sum != hex::encode(sha2::Sha256::digest(e.event_data.as_bytes())) {
                    out.failed.push((
                        e.id,
                        "InvalidChecksum".into(),
                        "The eventDataChecksum does not match the eventData.".into(),
                    ));
                    continue;
                }
            }
            let data = match serde_json::from_str::<Value>(&e.event_data) {
                Ok(v) => v,
                Err(_) => {
                    out.failed.push((e.id, "InvalidEventData".into(), "eventData is not valid JSON.".into()));
                    continue;
                }
            };
            if let Err(m) = check_event_data(&data) {
                out.failed.push((e.id, "InvalidEventData".into(), m));
                continue;
            }
            let event_id = uuid::Uuid::new_v4().to_string();
            records.push(json!({
                "eventVersion": "1.0",
                "eventCategory": "ActivityAuditLog",
                "eventType": "ActivityLog",
                "eventID": event_id,
                "eventTime": data["eventTime"],
                "awsRegion": parsed.region,
                "recipientAccountId": parsed.account,
                "eventData": data,
                "metadata": {
                    "ingestionTime": time_string(ctx.received_at),
                    "channelARN": channel_arn,
                },
            }));
            out.successful.push((e.id, event_id));
        }
        let mut st = self.lock();
        if let Some(account) = st.accounts.get_mut(&parsed.account) {
            for d in channel.destinations.iter().filter(|d| d.r#type == "EVENT_DATA_STORE") {
                if let Some(eds) = account.event_data_stores.get_mut(&d.location).filter(|e| e.ingesting()) {
                    eds.events.extend(records.iter().cloned());
                    let excess = eds.events.len().saturating_sub(EDS_EVENT_LIMIT);
                    eds.events.drain(..excess);
                }
            }
        }
        Ok(out)
    }
}
