//! Events entering buses: `PutEvents`, `PutPartnerEvents`, events from
//! other services, schedules and replays all end in [`Events::ingest`],
//! which archives the event and hands it to every matching rule's targets.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Value};

use crate::generated::types;
use crate::names::{validation, BusRef};
use crate::pattern::Pattern;
use crate::state::ArchivedEvent;
use crate::Events;

/// What a replay sends an event to.
#[derive(Debug, Clone)]
pub(crate) struct ReplayInfo {
    pub name: String,
    /// Rule ARNs the replay is limited to, if any.
    pub rules: Option<Vec<String>>,
}

pub(crate) fn timestamp(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// An event in EventBridge's envelope.
#[allow(clippy::too_many_arguments)]
pub(crate) fn envelope(
    id: &str,
    detail_type: &str,
    source: &str,
    account: &str,
    time: chrono::DateTime<chrono::Utc>,
    region: &str,
    resources: &[String],
    detail: Value,
) -> Value {
    json!({
        "version": "0",
        "id": id,
        "detail-type": detail_type,
        "source": source,
        "account": account,
        "time": timestamp(time),
        "region": region,
        "resources": resources,
        "detail": detail,
    })
}

const MAX_REQUEST: usize = 256 * 1024;

fn entry_size(e: &types::PutEventsRequestEntry) -> usize {
    let mut n = 14; // the time stamp
    for s in [&e.source, &e.detail_type, &e.detail].into_iter().flatten() {
        n += s.len();
    }
    n + e.resources.iter().flatten().map(String::len).sum::<usize>()
}

fn entry_error(code: &str, message: impl Into<String>) -> types::PutEventsResultEntry {
    types::PutEventsResultEntry { event_id: None, error_code: Some(code.into()), error_message: Some(message.into()) }
}

/// Check an entry's fields and parse its detail.
fn check_entry(
    source: Option<&str>,
    detail_type: Option<&str>,
    detail: Option<&str>,
) -> Result<Value, types::PutEventsResultEntry> {
    let required = |name: &str| {
        entry_error("InvalidArgument", format!("Parameter {name} is not valid. Reason: {name} is a required argument."))
    };
    source.filter(|s| !s.is_empty()).ok_or_else(|| required("Source"))?;
    detail_type.filter(|s| !s.is_empty()).ok_or_else(|| required("DetailType"))?;
    let detail = detail.filter(|s| !s.is_empty()).ok_or_else(|| required("Detail"))?;
    match serde_json::from_str::<Value>(detail) {
        Ok(v @ Value::Object(_)) => Ok(v),
        _ => Err(entry_error("MalformedDetail", "Detail is malformed.")),
    }
}

impl Events {
    pub fn put_events(
        &self,
        ctx: &RequestContext,
        input: types::PutEventsRequest,
    ) -> Result<types::PutEventsResponse, ServiceError> {
        if input.entries.iter().map(entry_size).sum::<usize>() > MAX_REQUEST {
            return Err(validation("Total size of the entries in the request is over the limit."));
        }
        let endpoint_bus = match &input.endpoint_id {
            Some(id) => Some(self.endpoint_primary_bus(ctx, id)?),
            None => None,
        };
        let mut results = Vec::new();
        let mut failed = 0;
        let mut denials = Vec::new();
        for entry in &input.entries {
            match self.put_entry(ctx, entry, endpoint_bus.as_ref()) {
                Ok(id) => results.push(types::PutEventsResultEntry { event_id: Some(id), ..Default::default() }),
                Err(EntryFailure::Entry(e)) => {
                    failed += 1;
                    results.push(e);
                }
                Err(EntryFailure::Denied(e)) => {
                    failed += 1;
                    results.push(entry_error("AccessDeniedException", e.message.clone()));
                    denials.push(e);
                }
            }
        }
        // A caller that may put none of the events is refused outright.
        if !denials.is_empty() && denials.len() == input.entries.len() {
            return Err(denials.remove(0));
        }
        Ok(types::PutEventsResponse { failed_entry_count: failed, entries: Some(results) })
    }

    fn put_entry(
        &self,
        ctx: &RequestContext,
        entry: &types::PutEventsRequestEntry,
        endpoint_bus: Option<&BusRef>,
    ) -> Result<String, EntryFailure> {
        let detail = check_entry(entry.source.as_deref(), entry.detail_type.as_deref(), entry.detail.as_deref())
            .map_err(EntryFailure::Entry)?;
        let source = entry.source.clone().unwrap_or_default();
        let detail_type = entry.detail_type.clone().unwrap_or_default();
        if source.starts_with("aws.") {
            return Err(EntryFailure::Entry(entry_error(
                "NotAuthorizedForSourceException",
                "Not authorized for the source.",
            )));
        }
        let bus = match (endpoint_bus, entry.event_bus_name.as_deref()) {
            (Some(b), None) => b.clone(),
            (Some(b), Some(name)) if !name.starts_with("arn:") => BusRef { name: name.to_string(), ..b.clone() },
            (_, name) => {
                BusRef::parse(ctx, name).map_err(|e| EntryFailure::Entry(entry_error("InvalidArgument", e.message)))?
            }
        };
        let mut extra = ConditionContext::new();
        extra.insert("events:source".into(), vec![source.clone()]);
        extra.insert("events:detail-type".into(), vec![detail_type.clone()]);
        self.authorize_on_bus(ctx, "events:PutEvents", &bus, &bus.arn(), extra).map_err(EntryFailure::Denied)?;
        if !self.bus_exists(ctx, &bus) {
            return Err(EntryFailure::Entry(entry_error(
                "ResourceNotFoundException",
                format!("Event bus {} does not exist.", bus.name),
            )));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let event = envelope(
            &id,
            &detail_type,
            &source,
            &ctx.caller.account_id,
            entry.time.unwrap_or(ctx.received_at),
            &bus.region,
            entry.resources.as_deref().unwrap_or_default(),
            detail,
        );
        self.ingest(ctx, &bus, &event, None);
        Ok(id)
    }

    pub fn put_partner_events(
        &self,
        ctx: &RequestContext,
        input: types::PutPartnerEventsRequest,
    ) -> Result<types::PutPartnerEventsResponse, ServiceError> {
        ctx.authorize("events:PutPartnerEvents", "*", ConditionContext::new())?;
        let mut results = Vec::new();
        let mut failed = 0;
        for entry in &input.entries {
            let result = check_entry(entry.source.as_deref(), entry.detail_type.as_deref(), entry.detail.as_deref())
                .and_then(|detail| {
                    let source = entry.source.clone().unwrap_or_default();
                    let accounts = self.partner_accounts(ctx, &source);
                    if accounts.is_none() {
                        return Err(entry_error(
                            "InvalidArgument",
                            format!("Parameter Source is not valid. Reason: Event source {source} does not exist."),
                        ));
                    }
                    let id = uuid::Uuid::new_v4().to_string();
                    for account in accounts.unwrap_or_default() {
                        let bus = BusRef {
                            partition: ctx.partition.clone(),
                            account: account.clone(),
                            region: ctx.region.clone(),
                            name: source.clone(),
                        };
                        if !self.partner_source_active(&bus) {
                            continue;
                        }
                        let event = envelope(
                            &id,
                            entry.detail_type.as_deref().unwrap_or_default(),
                            &source,
                            &account,
                            entry.time.unwrap_or(ctx.received_at),
                            &ctx.region,
                            entry.resources.as_deref().unwrap_or_default(),
                            detail.clone(),
                        );
                        self.ingest(ctx, &bus, &event, None);
                    }
                    Ok(id)
                });
            match result {
                Ok(id) => results.push(types::PutPartnerEventsResultEntry { event_id: Some(id), ..Default::default() }),
                Err(e) => {
                    failed += 1;
                    results.push(types::PutPartnerEventsResultEntry {
                        event_id: None,
                        error_code: e.error_code,
                        error_message: e.error_message,
                    });
                }
            }
        }
        Ok(types::PutPartnerEventsResponse { failed_entry_count: failed, entries: Some(results) })
    }

    /// Put an event on a bus: archive it and send it to every matching
    /// rule's targets. Missing buses drop the event.
    pub(crate) fn ingest(&self, ctx: &RequestContext, bus: &BusRef, event: &Value, replay: Option<&ReplayInfo>) {
        self.ingest_hops(ctx, bus, event, replay, 0)
    }

    /// [`Events::ingest`] for an event that other buses forwarded `hops`
    /// times already.
    pub(crate) fn ingest_hops(
        &self,
        ctx: &RequestContext,
        bus: &BusRef,
        event: &Value,
        replay: Option<&ReplayInfo>,
        hops: u8,
    ) {
        let now = self.now().max(ctx.received_at);
        let mut event = event.clone();
        if let Some(r) = replay {
            event["replay-name"] = Value::String(r.name.clone());
        }
        let matched = {
            let mut st = self.lock();
            let region = st.region_mut(&bus.partition, &bus.account, &bus.region, now);
            let Some(b) = region.buses.get(&bus.name) else { return };
            let bus_arn = b.arn.clone();
            let matched: Vec<_> = b
                .rules
                .values()
                .filter(|r| r.enabled() && !r.targets.is_empty())
                .filter(|r| replay.and_then(|x| x.rules.as_ref()).is_none_or(|only| only.contains(&r.arn)))
                .filter(|r| {
                    r.event_pattern.as_deref().and_then(|p| Pattern::parse(p).ok()).is_some_and(|p| p.matches(&event))
                })
                .cloned()
                .collect();
            if replay.is_none() {
                let text = event.to_string();
                let time = event
                    .get("time")
                    .and_then(Value::as_str)
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                    .map(|t| t.with_timezone(&chrono::Utc));
                for a in region.archives.values_mut() {
                    if a.event_source_arn != bus_arn || a.state != "ENABLED" {
                        continue;
                    }
                    if a.retention_days > 0 {
                        let cutoff = now - chrono::Duration::days(a.retention_days as i64);
                        a.events.retain(|e| e.ingested.is_none_or(|t| t >= cutoff));
                    }
                    let hit = match &a.event_pattern {
                        Some(p) => Pattern::parse(p).is_ok_and(|p| p.matches(&event)),
                        None => true,
                    };
                    if hit {
                        a.events.push(ArchivedEvent { time, ingested: Some(now), event: text.clone() });
                    }
                }
            }
            matched
        };
        for rule in matched {
            for target in &rule.targets {
                self.spawn_delivery(ctx, bus, &rule, target.clone(), event.clone(), now, hops);
            }
        }
    }
}

enum EntryFailure {
    Entry(types::PutEventsResultEntry),
    Denied(ServiceError),
}
