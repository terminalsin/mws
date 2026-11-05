//! CloudTrail Insights: unusual API call and error rates.
//!
//! While a trail (or an event data store) has Insights selectors, the
//! account's write management calls (`ApiCallRateInsight`) and failed
//! management calls (`ApiErrorRateInsight`, per error code) are counted per
//! minute. When a minute's count rises above the baseline (the mean of the
//! earlier minutes since counting began, up to 7 days, plus three standard
//! deviations) and is at least [`MIN_CALLS`], an Insights event with state
//! `Start` is logged; the
//! first minute back at or under the baseline logs the matching `End`.
//! Events go to the trails' `CloudTrail-Insight` log files, the Insights
//! event history (`LookupEvents` with `EventCategory=insight`,
//! `ListInsightsData`), event data stores' Insights destinations and
//! EventBridge ("AWS Insight via CloudTrail").

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::record::{time_string, Recorded};
use crate::state::{Account, HistoryEvent, OpenInsight, Rate, State, EDS_EVENT_LIMIT, HISTORY_LIMIT};
use crate::CloudTrail;

/// The fewest calls in a minute that can be unusual.
pub const MIN_CALLS: u32 = 10;
const BASELINE_MINUTES: i64 = 7 * 24 * 60;
/// How far back evaluation catches up after the clock jumps.
const CATCH_UP_MINUTES: i64 = 60;
const MAX_INSIGHT_EVENTS: usize = 10_000;

fn minute(t: DateTime<Utc>) -> i64 {
    t.timestamp().div_euclid(60)
}

fn wants(selectors: &[crate::generated::types::InsightSelector], kind: &str) -> bool {
    selectors.iter().any(|s| s.insight_type.as_deref() == Some(kind))
}

/// The Insight types the account's trails and event data stores ask for in
/// `region`.
fn wanted(account: &Account, region: &str) -> (bool, bool) {
    let mut out = (false, false);
    for t in account.trails.values() {
        if t.is_logging && (t.is_multi_region_trail || t.home_region == region) {
            out.0 |= wants(&t.insight_selectors, "ApiCallRateInsight");
            out.1 |= wants(&t.insight_selectors, "ApiErrorRateInsight");
        }
    }
    for e in account.event_data_stores.values() {
        if e.ingesting() && (e.multi_region_enabled || e.home_region == region) {
            out.0 |= wants(&e.insight_selectors, "ApiCallRateInsight");
            out.1 |= wants(&e.insight_selectors, "ApiErrorRateInsight");
        }
    }
    out
}

/// Count a management event where Insights watch for it.
pub(crate) fn count(st: &mut State, e: &Recorded) {
    if !e.management {
        return;
    }
    let account = st.account(&e.account);
    let (calls, errors) = wanted(account, &e.region);
    let error = e.record.get("errorCode").and_then(Value::as_str);
    let mut bump = |kind: &str, code: &str| {
        let key = format!("{}|{}|{}|{kind}|{code}", e.region, e.event_source, e.event_name);
        let rate =
            account.rates.entry(key).or_insert_with(|| Rate { evaluated: minute(e.time) - 1, ..Rate::default() });
        *rate.counts.entry(minute(e.time)).or_default() += 1;
    };
    if calls && !e.read_only {
        bump("ApiCallRateInsight", "");
    }
    if let (true, Some(code)) = (errors, error) {
        bump("ApiErrorRateInsight", code);
    }
}

struct Detected {
    region: String,
    source: String,
    name: String,
    kind: String,
    error_code: String,
    state: &'static str,
    shared_event_id: String,
    at: DateTime<Utc>,
    baseline: f64,
    baseline_minutes: i64,
    insight: f64,
    duration: i64,
}

fn evaluate(rate: &mut Rate, now_minute: i64, out: &mut Vec<(i64, &'static str, OpenInsight, f64, i64)>) {
    let from = (rate.evaluated + 1).max(now_minute - CATCH_UP_MINUTES);
    for m in from..now_minute {
        let c = rate.counts.get(&m).copied().unwrap_or(0);
        let first = rate.counts.keys().next().copied().unwrap_or(m).max(m - BASELINE_MINUTES);
        // Minutes of an open Insight stay out of its baseline.
        let window: Vec<u32> = (first..m)
            .filter(|x| rate.open.as_ref().is_none_or(|o| *x < o.start_minute))
            .map(|x| rate.counts.get(&x).copied().unwrap_or(0))
            .collect();
        let n = window.len().max(1) as f64;
        let mean = window.iter().map(|c| f64::from(*c)).sum::<f64>() / n;
        let var = window.iter().map(|c| (f64::from(*c) - mean).powi(2)).sum::<f64>() / n;
        let threshold = mean + 3.0 * var.sqrt();
        match &mut rate.open {
            // A minute with no earlier minutes has no baseline.
            None if !window.is_empty() && c >= MIN_CALLS && f64::from(c) > threshold => {
                let o = OpenInsight {
                    shared_event_id: uuid::Uuid::new_v4().to_string(),
                    start_minute: m,
                    baseline: mean,
                    baseline_minutes: window.len() as i64,
                    total: u64::from(c),
                };
                out.push((m, "Start", o.clone(), f64::from(c), 1));
                rate.open = Some(o);
            }
            Some(o) if f64::from(c) > o.baseline + 3.0 * var.sqrt() && c >= MIN_CALLS => o.total += u64::from(c),
            Some(o) => {
                let duration = (m - o.start_minute).max(1);
                let average = o.total as f64 / duration as f64;
                out.push((m, "End", o.clone(), average, duration));
                rate.open = None;
            }
            None => {}
        }
        rate.evaluated = m;
    }
    rate.counts.retain(|m, _| *m >= now_minute - BASELINE_MINUTES);
}

fn record(account: &str, d: &Detected) -> Value {
    let mut details = json!({
        "state": d.state,
        "eventSource": d.source,
        "eventName": d.name,
        "insightType": d.kind,
        "insightContext": {
            "statistics": {
                "baseline": { "average": d.baseline },
                "insight": { "average": d.insight },
                "insightDuration": d.duration,
                "baselineDuration": d.baseline_minutes,
            },
            "attributions": [],
        },
    });
    if !d.error_code.is_empty() {
        details["errorCode"] = json!(d.error_code);
    }
    json!({
        "eventVersion": "1.08",
        "eventTime": time_string(d.at),
        "awsRegion": d.region,
        "eventID": uuid::Uuid::new_v4().to_string(),
        "eventType": "AwsCloudTrailInsight",
        "recipientAccountId": account,
        "sharedEventID": d.shared_event_id,
        "insightDetails": details,
        "eventCategory": "Insight",
    })
}

fn history_event(d: &Detected, r: &Value) -> HistoryEvent {
    HistoryEvent {
        event_id: r["eventID"].as_str().unwrap_or_default().to_string(),
        event_name: d.name.clone(),
        event_source: d.source.clone(),
        event_time: d.at,
        read_only: false,
        access_key_id: None,
        username: None,
        resources: Vec::new(),
        record: r.to_string(),
    }
}

impl CloudTrail {
    /// Evaluate the minutes that ended since the last tick and log the
    /// Insights events they start or end.
    pub(crate) fn evaluate_insights(&self, ctx: &RequestContext) {
        let now_minute = minute(ctx.received_at);
        let mut bus = Vec::new();
        {
            let mut st = self.lock();
            for (account_id, account) in st.accounts.iter_mut() {
                let mut detected = Vec::new();
                for (key, rate) in account.rates.iter_mut() {
                    let mut found = Vec::new();
                    evaluate(rate, now_minute, &mut found);
                    let parts: Vec<&str> = key.splitn(5, '|').collect();
                    let [region, source, name, kind, code] = parts[..] else { continue };
                    for (m, state, o, insight, duration) in found {
                        detected.push(Detected {
                            region: region.into(),
                            source: source.into(),
                            name: name.into(),
                            kind: kind.into(),
                            error_code: code.into(),
                            state,
                            shared_event_id: o.shared_event_id,
                            at: DateTime::from_timestamp(m * 60, 0).unwrap_or(ctx.received_at),
                            baseline: o.baseline,
                            baseline_minutes: o.baseline_minutes,
                            insight,
                            duration,
                        });
                    }
                }
                account.rates.retain(|_, r| !r.counts.is_empty() || r.open.is_some());
                for d in detected {
                    let r = record(account_id, &d);
                    let h = history_event(&d, &r);
                    let history = account.insights.entry(d.region.clone()).or_default();
                    history.push(h.clone());
                    let cutoff = d.at - Duration::days(90);
                    let drop = history.iter().take_while(|x| x.event_time < cutoff).count();
                    history.drain(..drop.max(history.len().saturating_sub(HISTORY_LIMIT)));
                    for t in account.trails.values_mut() {
                        if t.is_logging
                            && (t.is_multi_region_trail || t.home_region == d.region)
                            && wants(&t.insight_selectors, &d.kind)
                        {
                            t.insight_pending.push(r.clone());
                            t.insight_events.push(h.clone());
                            let excess = t.insight_events.len().saturating_sub(MAX_INSIGHT_EVENTS);
                            t.insight_events.drain(..excess);
                        }
                    }
                    let destinations: Vec<String> = account
                        .event_data_stores
                        .values()
                        .filter(|e| e.ingesting() && wants(&e.insight_selectors, &d.kind))
                        .filter_map(|e| e.insights_destination.clone())
                        .collect();
                    for dest in destinations {
                        if let Some(e) = account.event_data_stores.get_mut(&dest) {
                            e.events.push(r.clone());
                            let excess = e.events.len().saturating_sub(EDS_EVENT_LIMIT);
                            e.events.drain(..excess);
                        }
                    }
                    bus.push((account_id.clone(), d, r));
                }
            }
        }
        if self.inner.events.get().is_some() {
            for (account, d, r) in bus {
                let source = d.source.trim_end_matches(".amazonaws.com").to_string();
                let event = mws_events::ServiceEvent {
                    partition: ctx.partition.clone(),
                    account: account.clone(),
                    region: d.region.clone(),
                    source: format!("aws.{source}"),
                    detail_type: "AWS Insight via CloudTrail".into(),
                    resources: Vec::new(),
                    detail: r,
                    time: d.at,
                };
                let mut ctx = ctx.clone();
                ctx.region = d.region.clone();
                ctx.caller.account_id = account;
                self.inner.bus.lock().expect("bus lock poisoned").push((ctx, event));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_starts_and_ends_an_insight() {
        let mut rate = Rate { evaluated: 99, ..Rate::default() };
        for m in 100..110 {
            rate.counts.insert(m, 1);
        }
        rate.counts.insert(110, 40);
        let mut out = Vec::new();
        evaluate(&mut rate, 111, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1, "Start");
        assert!((out[0].2.baseline - 1.0).abs() < 1e-9);
        evaluate(&mut rate, 113, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].1, "End");
        assert!(rate.open.is_none());
    }

    #[test]
    fn steady_traffic_is_not_unusual() {
        let mut rate = Rate { evaluated: 99, ..Rate::default() };
        for m in 100..200 {
            rate.counts.insert(m, 30);
        }
        let mut out = Vec::new();
        evaluate(&mut rate, 200, &mut out);
        assert!(out.is_empty());
    }
}
