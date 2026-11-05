//! Event history: `LookupEvents`, and the Insights metrics computed from
//! it.

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::HistoryEvent;
use crate::CloudTrail;

fn matches(h: &HistoryEvent, key: &str, value: &str) -> bool {
    match key {
        "EventId" => h.event_id == value,
        "EventName" => h.event_name == value,
        "ReadOnly" => h.read_only.to_string() == value,
        "Username" => h.username.as_deref() == Some(value),
        "ResourceType" => h.resources.iter().any(|(t, _)| t == value),
        "ResourceName" => h.resources.iter().any(|(_, n)| n == value),
        "EventSource" => h.event_source == value,
        "AccessKeyId" => h.access_key_id.as_deref() == Some(value),
        _ => false,
    }
}

fn event(h: &HistoryEvent) -> types::Event {
    types::Event {
        event_id: Some(h.event_id.clone()),
        event_name: Some(h.event_name.clone()),
        read_only: Some(h.read_only.to_string()),
        access_key_id: h.access_key_id.clone(),
        event_time: Some(h.event_time),
        event_source: Some(h.event_source.clone()),
        username: h.username.clone(),
        resources: Some(
            h.resources
                .iter()
                .map(|(t, n)| types::Resource { resource_type: Some(t.clone()), resource_name: Some(n.clone()) })
                .collect(),
        ),
        cloud_trail_event: Some(h.record.clone()),
    }
}

impl CloudTrail {
    pub(crate) fn lookup_events(
        &self,
        ctx: &RequestContext,
        input: types::LookupEventsRequest,
    ) -> Result<types::LookupEventsResponse, ServiceError> {
        ctx.authorize("cloudtrail:LookupEvents", "*", ConditionContext::new())?;
        let attributes = input.lookup_attributes.unwrap_or_default();
        if attributes.len() > 1 {
            return Err(errors::invalid_lookup_attributes("You cannot specify more than one lookup attribute."));
        }
        if let Some(c) = &input.event_category {
            if c != "insight" {
                return Err(errors::invalid_event_category(format!("Event category {c} is not valid.")));
            }
        }
        let max = input.max_results.unwrap_or(50);
        if !(1..=50).contains(&max) {
            return Err(errors::invalid_max_results("MaxResults must be between 1 and 50."));
        }
        let now = ctx.received_at;
        let end = input.end_time.unwrap_or(now);
        let start = input.start_time.unwrap_or(now - Duration::days(90));
        if start > end {
            return Err(errors::invalid_time_range("Start time must be before end time."));
        }
        let st = self.lock();
        // Insights events are not generated, so their history is empty.
        let history: &[HistoryEvent] = if input.event_category.is_some() {
            &[]
        } else {
            st.accounts
                .get(&ctx.caller.account_id)
                .and_then(|a| a.history.get(&ctx.region))
                .map(Vec::as_slice)
                .unwrap_or(&[])
        };
        // Newest first; the token is the id of the next event to return.
        let mut found = history
            .iter()
            .rev()
            .filter(|h| h.event_time >= start && h.event_time <= end)
            .filter(|h| attributes.iter().all(|a| matches(h, &a.attribute_key, &a.attribute_value)));
        if let Some(token) = input.next_token.as_deref().filter(|t| !t.is_empty()) {
            let id = token.strip_prefix("mws-").unwrap_or_default();
            let mut skipped = false;
            for h in found.by_ref() {
                if h.event_id == id {
                    skipped = true;
                    break;
                }
            }
            if !skipped {
                return Err(errors::invalid_next_token("Invalid NextToken."));
            }
        }
        let mut page: Vec<&HistoryEvent> = found.by_ref().take(max as usize).collect();
        let next = found.next().and(page.last()).map(|h| format!("mws-{}", h.event_id));
        let events = page.drain(..).map(event).collect();
        Ok(types::LookupEventsResponse { events: Some(events), next_token: next })
    }

    pub(crate) fn list_insights_metric_data(
        &self,
        ctx: &RequestContext,
        input: types::ListInsightsMetricDataRequest,
    ) -> Result<types::ListInsightsMetricDataResponse, ServiceError> {
        ctx.authorize("cloudtrail:ListInsightsMetricData", "*", ConditionContext::new())?;
        if input.insight_type == "ApiCallRateInsight" && input.error_code.is_some() {
            return Err(errors::invalid_parameter("ErrorCode can only be specified for ApiErrorRateInsight."));
        }
        let period = i64::from(input.period.unwrap_or(3600));
        if ![60, 300, 3600].contains(&period) {
            return Err(errors::invalid_parameter("Period must be 60, 300 or 3600 seconds."));
        }
        let now = ctx.received_at;
        let end = input.end_time.unwrap_or(now);
        let start = input.start_time.unwrap_or(end - Duration::days(90));
        let align = |t: DateTime<Utc>| t.timestamp() - t.timestamp().rem_euclid(period);
        let st = self.lock();
        let history: Vec<&HistoryEvent> = st
            .accounts
            .get(&ctx.caller.account_id)
            .and_then(|a| a.history.get(&ctx.region))
            .into_iter()
            .flatten()
            .filter(|h| h.event_source == input.event_source && h.event_name == input.event_name)
            .filter(|h| h.event_time >= start && h.event_time <= end)
            .collect();
        let mut buckets: std::collections::BTreeMap<i64, f64> = std::collections::BTreeMap::new();
        for h in history {
            let counted = match input.insight_type.as_str() {
                "ApiErrorRateInsight" => {
                    let code = serde_json::from_str::<serde_json::Value>(&h.record)
                        .ok()
                        .and_then(|r| r.get("errorCode").and_then(|c| c.as_str()).map(str::to_string));
                    match (&input.error_code, code) {
                        (Some(want), Some(c)) => *want == c,
                        (None, Some(_)) => true,
                        _ => false,
                    }
                }
                _ => true,
            };
            if counted {
                *buckets.entry(align(h.event_time)).or_default() += 1.0;
            }
        }
        if input.data_type.as_deref() != Some("NonZeroData") {
            let mut t = align(start);
            while t <= end.timestamp() && buckets.len() < 10_000 {
                buckets.entry(t).or_insert(0.0);
                t += period;
            }
        }
        let max = input.max_results.unwrap_or(21_600).max(1) as usize;
        let skip = input.next_token.as_deref().and_then(|t| t.parse::<usize>().ok()).unwrap_or(0);
        let all: Vec<(i64, f64)> = buckets.into_iter().collect();
        let page: Vec<(i64, f64)> = all.iter().skip(skip).take(max).copied().collect();
        let next = (skip + page.len() < all.len()).then(|| (skip + page.len()).to_string());
        let trail_arn = match &input.trail_name {
            Some(n) => Some(self.find_trail(&st, ctx, n)?.1),
            None => None,
        };
        Ok(types::ListInsightsMetricDataResponse {
            trail_arn,
            event_source: Some(input.event_source),
            event_name: Some(input.event_name),
            insight_type: Some(input.insight_type),
            error_code: input.error_code,
            timestamps: Some(page.iter().filter_map(|(t, _)| DateTime::from_timestamp(*t, 0)).collect()),
            values: Some(page.iter().map(|(_, v)| *v).collect()),
            next_token: next,
        })
    }

    pub(crate) fn list_insights_data(
        &self,
        ctx: &RequestContext,
        input: types::ListInsightsDataRequest,
    ) -> Result<types::ListInsightsDataResponse, ServiceError> {
        ctx.authorize("cloudtrail:ListInsightsData", &input.insight_source, ConditionContext::new())?;
        // Insights events are not generated.
        Ok(types::ListInsightsDataResponse { events: Some(Vec::new()), next_token: None })
    }
}
