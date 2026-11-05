//! Alarm evaluation and actions.
//!
//! A scheduler evaluates every alarm each second against the emulated
//! clock: metric alarms over their last `EvaluationPeriods` periods
//! (`DatapointsToAlarm` of them must breach, `TreatMissingData` deciding
//! what gaps mean), metric math and anomaly detection band alarms through
//! the metric math engine, log alarms by running their Logs Insights query
//! on schedule, and composite alarms from their children. State changes go
//! into the alarm history, to EventBridge as `CloudWatch Alarm State
//! Change` events, and, when actions are enabled and no mute rule or
//! suppressor holds them, to the state's actions: SNS topics (published as
//! `cloudwatch.amazonaws.com`) and Lambda functions (invoked as
//! `lambda.alarms.cloudwatch.amazonaws.com`).

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::alarms::{history_ts, push_history};
use crate::generated::types;
use crate::math::{Engine, Val};
use crate::metrics::align;
use crate::names::region_display_name;
use crate::rule::Rule;
use crate::state::{Alarm, MetricKey, Region};
use crate::CloudWatch;

/// A state change, and what it should set off.
#[derive(Debug, Clone)]
pub struct Transition {
    pub account: String,
    pub region: String,
    pub alarm: Alarm,
    pub old_value: String,
    pub old_reason: String,
    pub old_reason_data: Option<String>,
    pub old_timestamp: DateTime<Utc>,
    /// The actions to run (empty when disabled, muted or suppressed).
    pub actions: Vec<String>,
}

/// Whether a mute rule holds `alarm`'s actions at `now`.
pub fn muted_by(region: &Region, alarm: &str, now: DateTime<Utc>) -> Option<String> {
    region.mute_rules.values().find_map(|r| {
        let targets = r.config.mute_targets.as_ref().map(|t| t.alarm_names.clone()).unwrap_or_default();
        (targets.iter().any(|t| t == alarm) && crate::mute::status(r, now) == "ACTIVE").then(|| r.arn.clone())
    })
}

/// Move alarm `name` to `value`. `None` when it is already there.
#[allow(clippy::too_many_arguments)]
pub fn transition(
    region: &mut Region,
    account: &str,
    region_name: &str,
    name: &str,
    value: &str,
    reason: &str,
    reason_data: Option<String>,
    now: DateTime<Utc>,
) -> Option<Transition> {
    let muted = muted_by(region, name, now);
    let a = region.alarms.get_mut(name)?;
    if a.state_value == value {
        return None;
    }
    let old = (a.state_value.clone(), a.state_reason.clone(), a.state_reason_data.clone(), a.state_updated);
    a.state_value = value.to_string();
    a.state_reason = reason.chars().take(1023).collect();
    a.state_reason_data = reason_data.clone();
    a.state_updated = now;
    a.state_transitioned = now;
    let enabled = a.actions_enabled();
    let suppressed = a.actions_suppressed_by.is_some();
    let snapshot = a.clone();
    let mut new_state = json!({"stateValue": value, "stateReason": snapshot.state_reason});
    if let Some(d) = reason_data.as_deref().and_then(|d| serde_json::from_str::<Value>(d).ok()) {
        new_state["stateReasonData"] = d;
    }
    push_history(
        region,
        types::AlarmHistoryItem {
            alarm_name: Some(name.to_string()),
            alarm_type: Some(snapshot.alarm_type.clone()),
            timestamp: Some(now),
            history_item_type: Some("StateUpdate".into()),
            history_summary: Some(format!("Alarm updated from {} to {value}", old.0)),
            history_data: Some(
                json!({"version": "1.0", "oldState": {"stateValue": old.0, "stateReason": old.1}, "newState": new_state})
                    .to_string(),
            ),
            ..Default::default()
        },
    );
    let actions = if enabled && !suppressed && muted.is_none() { snapshot.actions_for(value) } else { Vec::new() };
    if let Some(rule) = muted {
        push_history(
            region,
            types::AlarmHistoryItem {
                alarm_name: Some(name.to_string()),
                alarm_type: Some(snapshot.alarm_type.clone()),
                timestamp: Some(now),
                history_item_type: Some("Action".into()),
                history_summary: Some(format!("Actions muted by alarm mute rule {rule}")),
                history_data: Some(json!({"actionState": "Muted", "muteRuleArn": rule}).to_string()),
                ..Default::default()
            },
        );
    }
    Some(Transition {
        account: account.to_string(),
        region: region_name.to_string(),
        alarm: snapshot,
        old_value: old.0,
        old_reason: old.1,
        old_reason_data: old.2,
        old_timestamp: old.3,
        actions,
    })
}

fn long_time(t: DateTime<Utc>) -> String {
    t.format("%A %d %B, %Y %H:%M:%S UTC").to_string()
}

/// Bring composite alarms in line with their children, repeatedly, since
/// composites can name composites.
pub fn cascade_composites(
    region: &mut Region,
    account: &str,
    region_name: &str,
    now: DateTime<Utc>,
) -> Vec<Transition> {
    let mut out = Vec::new();
    for _ in 0..10 {
        let mut changed = false;
        let composites: Vec<(String, types::PutCompositeAlarmInput)> =
            region.alarms.values().filter_map(|a| a.composite.clone().map(|c| (a.name().to_string(), c))).collect();
        for (name, c) in composites {
            update_suppression(region, &name, &c, now);
            let Ok(rule) = Rule::parse(&c.alarm_rule) else { continue };
            let states: BTreeMap<String, (String, String, DateTime<Utc>)> = region
                .alarms
                .values()
                .map(|a| (a.name().to_string(), (a.state_value.clone(), a.arn.clone(), a.state_transitioned)))
                .collect();
            let holds = rule.eval(&|n| states.get(n).map(|s| s.0.clone()));
            let want = if holds { "ALARM" } else { "OK" };
            if region.alarms.get(&name).is_some_and(|a| a.state_value == want) {
                continue;
            }
            // The child whose latest transition decided it.
            let trigger = rule.alarms().into_iter().filter_map(|n| states.get(&n).cloned()).max_by_key(|s| s.2);
            let (reason, data) = match &trigger {
                Some((state, arn, at)) => (
                    format!("{arn} transitioned to {state} at {}", long_time(*at)),
                    json!({"triggeringAlarms": [{"arn": arn, "state": {"value": state, "timestamp": history_ts(*at)}}]}).to_string(),
                ),
                None => ("Rule evaluated".to_string(), json!({"triggeringAlarms": []}).to_string()),
            };
            if let Some(t) = transition(region, account, region_name, &name, want, &reason, Some(data), now) {
                out.push(t);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    out
}

/// Set `ActionsSuppressedBy` from the composite's suppressor alarm.
fn update_suppression(region: &mut Region, name: &str, c: &types::PutCompositeAlarmInput, now: DateTime<Utc>) {
    let Some(sup) = &c.actions_suppressor else { return };
    let sup_name = sup.rsplit(":alarm:").next().unwrap_or(sup).to_string();
    let Some((sup_state, sup_changed)) =
        region.alarms.get(&sup_name).map(|a| (a.state_value.clone(), a.state_transitioned))
    else {
        return;
    };
    let wait = Duration::seconds(c.actions_suppressor_wait_period.unwrap_or(0) as i64);
    let extension = Duration::seconds(c.actions_suppressor_extension_period.unwrap_or(0) as i64);
    let Some(a) = region.alarms.get_mut(name) else { return };
    let (by, reason) = if sup_state == "ALARM" {
        (Some("Alarm"), Some(format!("Alarm {sup_name} is in ALARM state")))
    } else if now < sup_changed + extension && a.actions_suppressed_by.is_some() {
        (Some("ExtensionPeriod"), Some(format!("Extension period of {}s is active", extension.num_seconds())))
    } else if wait > Duration::zero() && now < a.state_transitioned + wait && a.state_value == "ALARM" {
        (Some("WaitPeriod"), Some(format!("Wait period of {}s is active", wait.num_seconds())))
    } else {
        (None, None)
    };
    a.actions_suppressed_by = by.map(str::to_string);
    a.actions_suppressed_reason = reason;
}

/// Java's `Double.toString` for the values in state reasons.
pub fn java_double(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e7 {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

fn breaches(op: &str, v: f64, threshold: f64, band: Option<(f64, f64)>) -> bool {
    match (op, band) {
        ("GreaterThanOrEqualToThreshold", _) => v >= threshold,
        ("GreaterThanThreshold", _) => v > threshold,
        ("LessThanThreshold", _) => v < threshold,
        ("LessThanOrEqualToThreshold", _) => v <= threshold,
        ("LessThanLowerOrGreaterThanUpperThreshold", Some((lo, hi))) => v < lo || v > hi,
        ("LessThanLowerThreshold", Some((lo, _))) => v < lo,
        ("GreaterThanUpperThreshold", Some((_, hi))) => v > hi,
        _ => false,
    }
}

fn op_words(op: &str) -> &'static str {
    match op {
        "GreaterThanOrEqualToThreshold" => "greater than or equal to",
        "GreaterThanThreshold" => "greater than",
        "LessThanThreshold" => "less than",
        "LessThanOrEqualToThreshold" => "less than or equal to",
        "LessThanLowerOrGreaterThanUpperThreshold" => "outside the band",
        "LessThanLowerThreshold" => "less than the lower band",
        _ => "greater than the upper band",
    }
}

/// The period a metric alarm evaluates (of its returned query for metric
/// math alarms).
fn alarm_period(m: &types::PutMetricAlarmInput) -> i64 {
    m.period
        .or_else(|| {
            let qs = m.metrics.as_ref()?;
            let returning =
                qs.iter().find(|q| q.return_data != Some(false) && Some(&q.id) != m.threshold_metric_id.as_ref())?;
            returning
                .metric_stat
                .as_ref()
                .map(|s| s.period)
                .or(returning.period)
                .or_else(|| qs.iter().find_map(|q| q.metric_stat.as_ref().map(|s| s.period)))
        })
        .unwrap_or(60) as i64
}

/// Whether a metric alarm evaluates now. CloudWatch evaluates an alarm
/// once per period (every minute at most, every 10 or 30 seconds for
/// high-resolution alarms), so a state set by `SetAlarmState` holds until
/// the next evaluation. MWS also evaluates as soon as new data arrives,
/// and right after the alarm is created or updated.
fn due(region: &Region, a: &Alarm, now: DateTime<Utc>) -> bool {
    let Some(last) = a.last_evaluated else { return true };
    if region.puts != a.seen_puts {
        return true;
    }
    let interval = a.metric.as_ref().map(alarm_period).unwrap_or(60).clamp(1, 60);
    now.timestamp().div_euclid(interval) != last.timestamp().div_euclid(interval)
}

/// The new state of a metric alarm, with its reason and reason data, or
/// `None` to leave it as it is.
pub fn evaluate_metric_alarm(region: &Region, a: &Alarm, now: DateTime<Utc>) -> Option<(String, String, String)> {
    let m = a.metric.as_ref()?;
    if m.evaluation_criteria.is_some() {
        return None;
    }
    let n = m.evaluation_periods? as i64;
    let mdp = m.datapoints_to_alarm.map(i64::from).unwrap_or(n);
    let op = m.comparison_operator.as_deref()?;
    let period = alarm_period(m);
    let end = align(now, period) + Duration::seconds(period);
    let start = end - Duration::seconds(period * n);
    #[allow(clippy::type_complexity)]
    let (points, band, stat_label): (BTreeMap<i64, f64>, BTreeMap<i64, (f64, f64)>, String) =
        match (&m.metric_name, &m.metrics) {
            (Some(name), _) => {
                let key = MetricKey::new(m.namespace.as_deref().unwrap_or_default(), name, m.dimensions.as_deref());
                let stat = m.statistic.clone().or(m.extended_statistic.clone()).unwrap_or_else(|| "Average".into());
                let engine = Engine::new(Some(region), &[], start, end);
                let points = engine.metric_series(&key, &stat, period, m.unit.as_deref()).points;
                // `EvaluateLowSampleCountPercentile: ignore`: a percentile
                // over too few samples (10 / (1 - p)) to be statistically
                // significant leaves the state as it is.
                if m.evaluate_low_sample_count_percentile.as_deref() == Some("ignore") {
                    if let Some(crate::stats::Stat::Percentile(p)) = crate::stats::Stat::parse(&stat) {
                        let needed = if p < 100.0 { 10.0 / (1.0 - p / 100.0) } else { 0.0 };
                        let counts = engine.metric_series(&key, "SampleCount", period, m.unit.as_deref()).points;
                        if points.keys().any(|t| counts.get(t).is_some_and(|c| *c < needed)) {
                            return None;
                        }
                    }
                }
                (points, BTreeMap::new(), stat)
            }
            (None, Some(qs)) => {
                let engine = Engine::new(Some(region), qs, start, end);
                let id = qs
                    .iter()
                    .find(|q| q.return_data != Some(false) && Some(&q.id) != m.threshold_metric_id.as_ref())?
                    .id
                    .clone();
                let points = match engine.eval(&id).ok()? {
                    Val::Series(ts) => ts.points,
                    Val::Scalar(s) => [(align(now, period).timestamp(), s)].into_iter().collect(),
                    _ => return None,
                };
                let band = match m.threshold_metric_id.as_ref().map(|t| engine.eval(t)) {
                    Some(Ok(Val::Array(a))) if a.len() == 2 => a[0]
                        .points
                        .iter()
                        .filter_map(|(t, lo)| a[1].points.get(t).map(|hi| (*t, (lo.min(*hi), lo.max(*hi)))))
                        .collect(),
                    _ => BTreeMap::new(),
                };
                (points, band, "Metrics".into())
            }
            _ => return None,
        };
    let threshold = m.threshold.unwrap_or(0.0);
    let tmd = m.treat_missing_data.as_deref().unwrap_or("missing");
    let slots: Vec<i64> = (0..n).map(|k| (start + Duration::seconds(period * k)).timestamp()).collect();
    let present: Vec<(i64, f64)> = slots.iter().filter_map(|t| points.get(t).map(|v| (*t, *v))).collect();
    let missing = n - present.len() as i64;
    let breaching_present = present
        .iter()
        .filter(|(t, v)| {
            let b = band.get(t).copied();
            if m.threshold_metric_id.is_some() && b.is_none() {
                return false;
            }
            breaches(op, *v, threshold, b)
        })
        .count() as i64;
    let breaching = breaching_present + if tmd == "breaching" { missing } else { 0 };
    let fmt_points = |pts: &[(i64, f64)]| -> String {
        pts.iter()
            .rev()
            .map(|(t, v)| {
                let d = DateTime::from_timestamp(*t, 0).unwrap_or_default();
                format!("{} ({})", java_double(*v), d.format("%d/%m/%y %H:%M:%S"))
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let data = json!({
        "version": "1.0",
        "queryDate": history_ts(now),
        "startDate": history_ts(start),
        "statistic": stat_label,
        "period": period,
        "recentDatapoints": present.iter().map(|(_, v)| *v).collect::<Vec<_>>(),
        "threshold": threshold,
        "evaluatedDatapoints": present.iter().rev().map(|(t, v)| json!({
            "timestamp": history_ts(DateTime::from_timestamp(*t, 0).unwrap_or_default()),
            "value": v,
        })).collect::<Vec<_>>(),
    })
    .to_string();
    let plural = |k: i64| if k == 1 { "datapoint" } else { "datapoints" };
    if present.is_empty() {
        return match tmd {
            "ignore" => None,
            "notBreaching" => Some((
                "OK".into(),
                format!("Threshold Crossed: no datapoints were received for {n} period{} and {n} missing datapoint{} {} treated as [NonBreaching].", if n == 1 { "" } else { "s" }, if n == 1 { " was" } else { "s were" }, ""),
                data,
            )),
            "breaching" if breaching >= mdp => Some((
                "ALARM".into(),
                format!("Threshold Crossed: no datapoints were received for {n} period{} and {n} missing datapoint{} treated as [Breaching].", if n == 1 { "" } else { "s" }, if n == 1 { " was" } else { "s were" }),
                data,
            )),
            _ => Some((
                "INSUFFICIENT_DATA".into(),
                format!("Insufficient Data: {n} {} {} unknown.", plural(n), if n == 1 { "was" } else { "were" }),
                data,
            )),
        };
    }
    let thr = if m.threshold_metric_id.is_some() {
        "the band".to_string()
    } else {
        format!("the threshold ({})", java_double(threshold))
    };
    if breaching >= mdp {
        let from = a.state_value.as_str();
        Some((
            "ALARM".into(),
            format!(
                "Threshold Crossed: {breaching} out of the last {n} {} [{}] {} {} {thr} (minimum {mdp} {} for {from} -> ALARM transition).",
                plural(n),
                fmt_points(&present),
                if breaching == 1 { "was" } else { "were" },
                op_words(op),
                plural(mdp),
            ),
            data,
        ))
    } else {
        let from = a.state_value.as_str();
        let not = n - breaching;
        Some((
            "OK".into(),
            format!(
                "Threshold Crossed: {not} out of the last {n} {} [{}] {} not {} {thr} (minimum 1 datapoint for {from} -> OK transition).",
                plural(n),
                fmt_points(&present),
                if not == 1 { "was" } else { "were" },
                op_words(op),
            ),
            data,
        ))
    }
}

/// A new state, its reason and its reason data.
type Decision = (String, String, String);

/// Evaluate every metric alarm of a Region, then its composites.
pub fn evaluate_region(region: &mut Region, account: &str, region_name: &str, now: DateTime<Utc>) -> Vec<Transition> {
    let evaluated: Vec<(String, Option<Decision>)> = region
        .alarms
        .values()
        .filter(|a| a.alarm_type == "MetricAlarm" && due(region, a, now))
        .map(|a| (a.name().to_string(), evaluate_metric_alarm(region, a, now)))
        .collect();
    let puts = region.puts;
    let mut out = Vec::new();
    for (name, decision) in evaluated {
        if let Some(a) = region.alarms.get_mut(&name) {
            a.last_evaluated = Some(now);
            a.seen_puts = puts;
        }
        let Some((value, reason, data)) = decision else { continue };
        if let Some(t) = transition(region, account, region_name, &name, &value, &reason, Some(data), now) {
            out.push(t);
        }
    }
    out.extend(cascade_composites(region, account, region_name, now));
    out
}

/// A log alarm due to run its query: `(account, region, name, config)`.
type DueLogAlarm = (String, String, String, types::PutLogAlarmInput);

impl CloudWatch {
    /// Start the evaluator (once), and learn the emulated clock's offset.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = (ctx.received_at - Utc::now()).num_milliseconds();
        self.inner.clock_offset_ms.store(offset.max(0), Ordering::Relaxed);
        *self.inner.template.lock().expect("template lock poisoned") = Some(ctx.clone());
        if tokio::runtime::Handle::try_current().is_ok() && !self.inner.scheduler.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(StdDuration::from_secs(1)).await;
                    me.tick();
                }
            });
        }
    }

    /// The emulated clock's current time.
    pub(crate) fn clock_now(&self) -> DateTime<Utc> {
        Utc::now() + Duration::milliseconds(self.inner.clock_offset_ms.load(Ordering::Relaxed))
    }

    /// Evaluate every alarm now.
    pub fn tick(&self) {
        let Some(template) = self.inner.template.lock().expect("template lock poisoned").clone() else { return };
        let now = self.clock_now();
        let (mut transitions, due, batches) = {
            let mut st = self.lock();
            let mut out = Vec::new();
            let mut due: Vec<DueLogAlarm> = Vec::new();
            let mut batches = Vec::new();
            for (key, region) in st.regions.iter_mut() {
                let Some((account, region_name)) = key.split_once('/') else { continue };
                out.extend(evaluate_region(region, account, region_name, now));
                batches.extend(crate::streams::due_batches(region, account, region_name, now));
                for a in region.alarms.values_mut() {
                    let Some(l) = &a.log else { continue };
                    if crate::logalarm::due(l, a.last_evaluated, a.config_updated, now) {
                        a.last_evaluated = Some(now);
                        due.push((account.to_string(), region_name.to_string(), a.name().to_string(), l.clone()));
                    }
                }
            }
            (out, due, batches)
        };
        self.deliver_batches(batches);
        for (account, region_name, name, config) in due {
            let decision = crate::logalarm::evaluate(self, &template, &account, &region_name, &config, now);
            let mut st = self.lock();
            let region = st.region(&account, &region_name);
            if let Some((value, reason, data)) = decision {
                if let Some(t) = transition(region, &account, &region_name, &name, &value, &reason, Some(data), now) {
                    transitions.push(t);
                }
                transitions.extend(cascade_composites(region, &account, &region_name, now));
            }
        }
        let ctx = RequestContext { received_at: now, ..template };
        self.run_transitions(&ctx, transitions);
    }

    /// Send state changes to EventBridge and run their actions.
    pub(crate) fn run_transitions(&self, ctx: &RequestContext, transitions: Vec<Transition>) {
        for t in transitions {
            let ctx = RequestContext { region: t.region.clone(), ..ctx.clone() };
            self.state_change_event(&ctx, &t);
            for action in &t.actions {
                let result = self.run_action(&ctx, &t, action);
                let (state, summary) = match &result {
                    Ok(()) => ("Succeeded", format!("Successfully executed action {action}")),
                    Err(e) => ("Failed", format!("Failed to execute action {action}. Received error: \"{e}\"")),
                };
                let mut st = self.lock();
                push_history(
                    st.region(&t.account, &t.region),
                    types::AlarmHistoryItem {
                        alarm_name: Some(t.alarm.name().to_string()),
                        alarm_type: Some(t.alarm.alarm_type.clone()),
                        timestamp: Some(ctx.received_at),
                        history_item_type: Some("Action".into()),
                        history_summary: Some(summary.chars().take(255).collect()),
                        history_data: Some(
                            json!({
                                "actionState": state,
                                "stateUpdateTimestamp": t.alarm.state_updated.timestamp_millis(),
                                "notificationResource": action,
                                "error": result.err(),
                            })
                            .to_string(),
                        ),
                        ..Default::default()
                    },
                );
            }
        }
    }

    fn run_action(&self, ctx: &RequestContext, t: &Transition, action: &str) -> Result<(), String> {
        let service = action.split(':').nth(2).unwrap_or_default();
        match service {
            "sns" => {
                let sns = self.inner.sns.get().ok_or("SNS is not available")?;
                let message = sns_message(t, &ctx.region);
                let subject: String =
                    format!("{}: \"{}\" in {}", t.alarm.state_value, t.alarm.name(), region_display_name(&t.region))
                        .chars()
                        .take(100)
                        .collect();
                sns.publish_as_service(
                    ctx,
                    &mws_sns::ServicePublish {
                        topic_arn: action,
                        service_principal: "cloudwatch.amazonaws.com",
                        source_arn: &t.alarm.arn,
                        source_account: &t.account,
                        message: message.to_string(),
                        subject: Some(subject),
                        attributes: Default::default(),
                        message_group_id: action.ends_with(".fifo").then(|| t.alarm.name().to_string()),
                        message_deduplication_id: action
                            .ends_with(".fifo")
                            .then(|| format!("{}-{}", t.alarm.name(), t.alarm.state_updated.timestamp_millis())),
                    },
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            }
            "lambda" => {
                let lambda = self.inner.lambda.get().ok_or("Lambda is not available")?;
                let payload = lambda_event(t);
                lambda
                    .invoke_event_as_service(
                        ctx,
                        mws_lambda::ServiceInvocation {
                            function: action,
                            service_principal: "lambda.alarms.cloudwatch.amazonaws.com",
                            source_account: Some(&t.account),
                            source_arn: Some(&t.alarm.arn),
                            payload: payload.to_string().into_bytes(),
                        },
                    )
                    .map_err(|e| match e {
                        mws_lambda::ServiceInvokeError::NotFound => "Function not found".to_string(),
                        mws_lambda::ServiceInvokeError::AccessDenied => {
                            "CloudWatch Alarms is not authorized to perform: lambda:InvokeFunction on the resource"
                                .to_string()
                        }
                        mws_lambda::ServiceInvokeError::Failed(m) => m,
                    })
            }
            other => {
                let target = self.inner.action_targets.lock().expect("action targets lock poisoned").get(other).cloned();
                let Some(target) = target else {
                    return Err(format!("Actions of type {other} are not supported by MWS"));
                };
                let metric_value = t
                    .alarm
                    .state_reason_data
                    .as_deref()
                    .and_then(|d| serde_json::from_str::<Value>(d).ok())
                    .and_then(|d| d["recentDatapoints"].as_array().and_then(|a| a.last().and_then(Value::as_f64)));
                target.run(
                    ctx,
                    crate::AlarmAction {
                        action_arn: action.to_string(),
                        alarm_name: t.alarm.name().to_string(),
                        alarm_arn: t.alarm.arn.clone(),
                        account: t.account.clone(),
                        region: t.region.clone(),
                        state: t.alarm.state_value.clone(),
                        threshold: t.alarm.metric.as_ref().and_then(|m| m.threshold),
                        metric_value,
                    },
                )
            }
        }
    }

    fn state_change_event(&self, ctx: &RequestContext, t: &Transition) {
        let Some(events) = self.inner.events.get() else { return };
        let detail = alarm_data(t);
        events.put_service_event(
            ctx,
            mws_events::ServiceEvent {
                partition: ctx.partition.clone(),
                account: t.account.clone(),
                region: t.region.clone(),
                source: "aws.cloudwatch".into(),
                detail_type: "CloudWatch Alarm State Change".into(),
                resources: vec![t.alarm.arn.clone()],
                detail,
                time: ctx.received_at,
            },
        );
    }
}

fn state_json(value: &str, reason: &str, data: Option<&str>, at: DateTime<Utc>) -> Value {
    let mut s = json!({"value": value, "reason": reason, "timestamp": history_ts(at)});
    if let Some(d) = data {
        s["reasonData"] = Value::String(d.to_string());
    }
    s
}

fn configuration(a: &Alarm) -> Value {
    if let Some(c) = &a.composite {
        return json!({"alarmRule": c.alarm_rule, "description": c.alarm_description});
    }
    let mut metrics = Vec::new();
    if let Some(m) = &a.metric {
        match (&m.metric_name, &m.metrics) {
            (Some(name), _) => {
                let dims: serde_json::Map<String, Value> =
                    m.dimensions.iter().flatten().map(|d| (d.name.clone(), Value::String(d.value.clone()))).collect();
                metrics.push(json!({
                    "id": "m1",
                    "metricStat": {
                        "metric": {"namespace": m.namespace, "name": name, "dimensions": dims},
                        "period": m.period,
                        "stat": m.statistic.clone().or(m.extended_statistic.clone()),
                    },
                    "returnData": true,
                }));
            }
            (None, Some(qs)) => {
                for q in qs {
                    let mut v = json!({"id": q.id, "returnData": q.return_data.unwrap_or(true)});
                    if let Some(e) = &q.expression {
                        v["expression"] = json!(e);
                        v["label"] = json!(q.label);
                    }
                    if let Some(ms) = &q.metric_stat {
                        let dims: serde_json::Map<String, Value> = ms
                            .metric
                            .dimensions
                            .iter()
                            .flatten()
                            .map(|d| (d.name.clone(), Value::String(d.value.clone())))
                            .collect();
                        v["metricStat"] = json!({
                            "metric": {"namespace": ms.metric.namespace, "name": ms.metric.metric_name, "dimensions": dims},
                            "period": ms.period,
                            "stat": ms.stat,
                        });
                    }
                    metrics.push(v);
                }
            }
            _ => {}
        }
    }
    json!({"description": a.description(), "metrics": metrics})
}

/// The `detail` of state change events, and `alarmData` of Lambda actions.
fn alarm_data(t: &Transition) -> Value {
    json!({
        "alarmName": t.alarm.name(),
        "state": state_json(&t.alarm.state_value, &t.alarm.state_reason, t.alarm.state_reason_data.as_deref(), t.alarm.state_updated),
        "previousState": state_json(&t.old_value, &t.old_reason, t.old_reason_data.as_deref(), t.old_timestamp),
        "configuration": configuration(&t.alarm),
    })
}

fn lambda_event(t: &Transition) -> Value {
    json!({
        "source": "aws.cloudwatch",
        "alarmArn": t.alarm.arn,
        "accountId": t.account,
        "time": history_ts(t.alarm.state_updated),
        "region": t.region,
        "alarmData": alarm_data(t),
    })
}

fn sns_message(t: &Transition, region: &str) -> Value {
    let a = &t.alarm;
    let (ok, alarm, insufficient) = a.actions();
    let mut msg = json!({
        "AlarmName": a.name(),
        "AlarmDescription": a.description(),
        "AWSAccountId": t.account,
        "AlarmConfigurationUpdatedTimestamp": history_ts(a.config_updated),
        "NewStateValue": a.state_value,
        "NewStateReason": a.state_reason,
        "StateChangeTime": history_ts(a.state_updated),
        "Region": region_display_name(region),
        "AlarmArn": a.arn,
        "OldStateValue": t.old_value,
        "OKActions": ok,
        "AlarmActions": alarm,
        "InsufficientDataActions": insufficient,
    });
    if let Some(m) = &a.metric {
        let mut trigger = json!({
            "Period": m.period,
            "EvaluationPeriods": m.evaluation_periods,
            "DatapointsToAlarm": m.datapoints_to_alarm,
            "ComparisonOperator": m.comparison_operator,
            "Threshold": m.threshold,
            "TreatMissingData": m.treat_missing_data.clone().unwrap_or_default(),
            "EvaluateLowSampleCountPercentile": m.evaluate_low_sample_count_percentile.clone().unwrap_or_default(),
        });
        if let Some(name) = &m.metric_name {
            trigger["MetricName"] = json!(name);
            trigger["Namespace"] = json!(m.namespace);
            match (&m.statistic, &m.extended_statistic) {
                (Some(s), _) => {
                    trigger["StatisticType"] = json!("Statistic");
                    trigger["Statistic"] = json!(s.to_ascii_uppercase());
                }
                (_, Some(e)) => {
                    trigger["StatisticType"] = json!("ExtendedStatistic");
                    trigger["ExtendedStatistic"] = json!(e);
                }
                _ => {}
            }
            trigger["Unit"] = json!(m.unit);
            trigger["Dimensions"] = Value::Array(
                m.dimensions.iter().flatten().map(|d| json!({"value": d.value, "name": d.name})).collect(),
            );
        } else if let Some(qs) = &m.metrics {
            trigger["Metrics"] = configuration(a)["metrics"].clone();
            let _ = qs;
        }
        msg["Trigger"] = trigger;
    }
    if let Some(c) = &a.composite {
        msg["AlarmRule"] = json!(c.alarm_rule);
    }
    msg
}
