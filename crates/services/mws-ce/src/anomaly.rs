//! Cost Anomaly Detection: monitors, subscriptions, anomalies found in the
//! ledger, feedback, and alerts to SNS subscribers.
//!
//! A day's spend for one monitored value (a service, or an account for
//! `LINKED_ACCOUNT` monitors) is anomalous when it exceeds the mean of the
//! previous 14 days (at least 7 of history) by more than three standard
//! deviations, 20% of the mean and $1. Consecutive anomalous days form
//! one anomaly.

use std::collections::{BTreeMap, BTreeSet};

use mws_core::{RequestContext, ServiceError};

use crate::costs::{auth, page};
use crate::generated::types as t;
use crate::query::{check_expression, date_str, from_ms, ms, parse_time, validation, View};
use crate::settings::{arn, tag_map};
use crate::state::{Monitor, Subscription};
use crate::CostExplorer;

const DAY: i64 = 86_400_000;

/// (service, region, account, usage type).
type Cause = (String, String, String, String);
/// A run of anomalous days: first day, last day, (actual, expected) per day.
type Run = (i64, i64, Vec<(f64, f64)>);

fn unknown_monitor() -> ServiceError {
    ServiceError::client("UnknownMonitorException", 404, "Cost anomaly monitor does not exist for the account")
}

fn unknown_subscription() -> ServiceError {
    ServiceError::client(
        "UnknownSubscriptionException",
        404,
        "Cost anomaly subscription does not exist for the account",
    )
}

/// A stable id for an anomaly.
fn anomaly_id(parts: &[&str]) -> String {
    let mut a: u64 = 0xcbf29ce484222325;
    let mut b: u64 = 0x84222325cbf29ce4;
    for p in parts {
        for byte in p.bytes().chain(std::iter::once(0)) {
            a = (a ^ byte as u64).wrapping_mul(0x100000001b3);
            b = (b ^ byte as u64).wrapping_mul(0x1000193).rotate_left(7);
        }
    }
    uuid::Uuid::from_u128(((a as u128) << 64) | b as u128).to_string()
}

fn monitor_view(m: &Monitor, dimensional_value_count: i32) -> t::AnomalyMonitor {
    let mut spec: t::AnomalyMonitor = serde_json::from_value(m.spec.clone()).unwrap_or_default();
    spec.monitor_arn = Some(m.arn.clone());
    spec.creation_date = Some(m.created.clone());
    spec.last_updated_date = Some(m.updated.clone());
    spec.dimensional_value_count = dimensional_value_count;
    spec
}

/// The value a record is monitored under.
fn monitored_value(view: &View<'_>, spec: &t::AnomalyMonitor, r: &crate::state::CostRecord) -> Option<String> {
    if spec.monitor_type == "CUSTOM" {
        if let Some(e) = &spec.monitor_specification {
            if !view.matches(r, e, 0) {
                return None;
            }
        }
        return r.dimension("SERVICE").map(str::to_string);
    }
    match spec.monitor_dimension.as_deref() {
        Some("LINKED_ACCOUNT") => Some(r.account.clone()),
        _ => r.dimension("SERVICE").map(str::to_string),
    }
}

/// Anomalies a monitor finds in what `view` sees.
pub(crate) fn detect(view: &View<'_>, m: &Monitor) -> Vec<t::Anomaly> {
    let spec: t::AnomalyMonitor = serde_json::from_value(m.spec.clone()).unwrap_or_default();
    let mut series: BTreeMap<String, BTreeMap<i64, f64>> = BTreeMap::new();
    let mut by_cause: BTreeMap<(String, i64), BTreeMap<Cause, f64>> = BTreeMap::new();
    for r in &view.records {
        if r.dimension("RECORD_TYPE").is_some_and(|t| t != "Usage") {
            continue;
        }
        let Some(value) = monitored_value(view, &spec, r) else { continue };
        let day = r.start.div_euclid(DAY);
        *series.entry(value.clone()).or_default().entry(day).or_default() += r.unblended_cost;
        let cause = (
            r.dimension("SERVICE").unwrap_or_default().to_string(),
            r.dimension("REGION").unwrap_or_default().to_string(),
            r.account.clone(),
            r.dimension("USAGE_TYPE").unwrap_or_default().to_string(),
        );
        *by_cause.entry((value, day)).or_default().entry(cause).or_default() += r.unblended_cost;
    }
    let today = view.now.div_euclid(DAY);
    let mut out = Vec::new();
    for (value, days) in &series {
        let Some(&first) = days.keys().next() else { continue };
        let at = |d: i64| days.get(&d).copied().unwrap_or(0.0);
        // Runs of anomalous days: (start, end, impacts, expected sums).
        let mut runs: Vec<Run> = Vec::new();
        for d in (first + 7)..=today.min(*days.keys().last().unwrap_or(&first)) {
            let window: Vec<f64> = ((d - 14).max(first)..d).map(at).collect();
            let n = window.len() as f64;
            let mean = window.iter().sum::<f64>() / n;
            let sd = (window.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n).sqrt();
            let actual = at(d);
            let excess = actual - mean;
            if excess > 3.0 * sd && excess > 0.2 * mean && excess >= 1.0 {
                match runs.last_mut() {
                    Some(run) if run.1 == d - 1 => {
                        run.1 = d;
                        run.2.push((actual, mean));
                    }
                    _ => runs.push((d, d, vec![(actual, mean)])),
                }
            }
        }
        for (start, end, points) in runs {
            let actual: f64 = points.iter().map(|p| p.0).sum();
            let expected: f64 = points.iter().map(|p| p.1).sum();
            let total = actual - expected;
            let max = points.iter().map(|p| p.0 - p.1).fold(0.0, f64::max);
            let score = (total / actual.max(1.0)).clamp(0.0, 1.0);
            let mut causes: BTreeMap<Cause, f64> = BTreeMap::new();
            for d in start..=end {
                for (k, v) in by_cause.get(&(value.clone(), d)).into_iter().flatten() {
                    *causes.entry(k.clone()).or_default() += v;
                }
            }
            let mut causes: Vec<_> = causes.into_iter().collect();
            causes.sort_by(|a, b| b.1.total_cmp(&a.1));
            causes.truncate(10);
            let id = anomaly_id(&[&m.arn, value, &start.to_string()]);
            out.push(t::Anomaly {
                anomaly_id: id.clone(),
                anomaly_start_date: Some(date_str(from_ms(start * DAY))),
                anomaly_end_date: Some(date_str(from_ms(end * DAY))),
                dimension_value: Some(value.clone()),
                root_causes: Some(
                    causes
                        .into_iter()
                        .map(|((service, region, account, usage_type), cost)| t::RootCause {
                            linked_account_name: view.names.get(&account).cloned(),
                            service: Some(service),
                            region: Some(region),
                            linked_account: Some(account),
                            usage_type: Some(usage_type),
                            impact: Some(t::RootCauseImpact { contribution: round(cost) }),
                        })
                        .collect(),
                ),
                anomaly_score: t::AnomalyScore { max_score: round(score), current_score: round(score) },
                impact: t::Impact {
                    max_impact: round(max),
                    total_impact: round(total),
                    total_actual_spend: Some(round(actual)),
                    total_expected_spend: Some(round(expected)),
                    total_impact_percentage: (expected > 0.0).then(|| round(total / expected * 100.0)),
                },
                monitor_arn: m.arn.clone(),
                feedback: view.account.feedback.get(&id).cloned(),
            });
        }
    }
    out
}

fn round(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Whether an anomaly passes a subscription's threshold.
fn passes(sub: &t::AnomalySubscription, a: &t::Anomaly) -> bool {
    fn eval(e: &t::Expression, a: &t::Anomaly) -> bool {
        if let Some(and) = &e.and {
            return and.iter().all(|x| eval(x, a));
        }
        if let Some(or) = &e.or {
            return or.iter().any(|x| eval(x, a));
        }
        if let Some(not) = &e.not {
            return !eval(not, a);
        }
        let Some(d) = &e.dimensions else { return true };
        let actual = match d.key.as_deref() {
            Some("ANOMALY_TOTAL_IMPACT_PERCENTAGE") => a.impact.total_impact_percentage.unwrap_or(0.0),
            _ => a.impact.total_impact,
        };
        d.values.iter().flatten().filter_map(|v| v.parse::<f64>().ok()).any(|v| actual >= v)
    }
    match (&sub.threshold_expression, sub.threshold) {
        (Some(e), _) => eval(e, a),
        (None, Some(th)) => a.impact.total_impact >= th,
        _ => true,
    }
}

fn check_subscribers(frequency: &str, subscribers: &[t::Subscriber]) -> Result<(), ServiceError> {
    if subscribers.is_empty() {
        return Err(validation("Subscribers must contain at least one subscriber."));
    }
    for s in subscribers {
        match (s.r#type.as_deref(), frequency) {
            (Some("SNS"), "IMMEDIATE") | (Some("EMAIL"), "DAILY" | "WEEKLY") => {}
            (Some("SNS"), _) => return Err(validation("SNS subscribers are only supported for IMMEDIATE frequency.")),
            (Some("EMAIL"), _) => {
                return Err(validation("Email subscribers are only supported for DAILY and WEEKLY frequency."))
            }
            _ => return Err(validation("Subscriber type must be EMAIL or SNS.")),
        }
    }
    Ok(())
}

impl CostExplorer {
    pub(crate) fn create_anomaly_monitor_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateAnomalyMonitorRequest,
    ) -> Result<t::CreateAnomalyMonitorResponse, ServiceError> {
        auth(ctx, "CreateAnomalyMonitor")?;
        let mut spec = input.anomaly_monitor;
        match spec.monitor_type.as_str() {
            "DIMENSIONAL" => {
                if spec.monitor_dimension.is_none() {
                    return Err(validation("MonitorDimension is required for DIMENSIONAL monitors."));
                }
            }
            _ => match &spec.monitor_specification {
                Some(e) => check_expression(e)?,
                None => return Err(validation("MonitorSpecification is required for CUSTOM monitors.")),
            },
        }
        let tags = tag_map(input.resource_tags.as_deref())?;
        let arn = arn(ctx, "anomalymonitor");
        let today = date_str(ctx.received_at);
        spec.monitor_arn = None;
        self.with_account(ctx, |acct| {
            if spec.monitor_type == "DIMENSIONAL"
                && spec.monitor_dimension.as_deref() == Some("SERVICE")
                && acct.monitors.values().any(|m| {
                    m.spec.get("MonitorDimension").and_then(|v| v.as_str()) == Some("SERVICE")
                        || serde_json::from_value::<t::AnomalyMonitor>(m.spec.clone())
                            .is_ok_and(|s| s.monitor_dimension.as_deref() == Some("SERVICE"))
                })
            {
                return Err(ServiceError::client(
                    "LimitExceededException",
                    400,
                    "You can create only one AWS services monitor per account.",
                ));
            }
            acct.monitors.insert(
                arn.clone(),
                Monitor {
                    arn: arn.clone(),
                    spec: serde_json::to_value(&spec).expect("monitor serializes"),
                    created: today.clone(),
                    updated: today.clone(),
                    tags,
                },
            );
            Ok(())
        })?;
        Ok(t::CreateAnomalyMonitorResponse { monitor_arn: arn })
    }

    pub(crate) fn get_anomaly_monitors_op(
        &self,
        ctx: &RequestContext,
        input: t::GetAnomalyMonitorsRequest,
    ) -> Result<t::GetAnomalyMonitorsResponse, ServiceError> {
        auth(ctx, "GetAnomalyMonitors")?;
        let wanted = input.monitor_arn_list.clone().unwrap_or_default();
        let monitors = self.with_view(ctx, |view| {
            let monitors: Vec<&Monitor> =
                view.account.monitors.values().filter(|m| wanted.is_empty() || wanted.contains(&m.arn)).collect();
            if monitors.len() < wanted.len() {
                return Err(unknown_monitor());
            }
            Ok(monitors
                .into_iter()
                .map(|m| {
                    let spec: t::AnomalyMonitor = serde_json::from_value(m.spec.clone()).unwrap_or_default();
                    let values: BTreeSet<String> =
                        view.records.iter().filter_map(|r| monitored_value(view, &spec, r)).collect();
                    monitor_view(m, values.len() as i32)
                })
                .collect::<Vec<_>>())
        })?;
        let (anomaly_monitors, next_page_token) =
            page(monitors, input.next_page_token.as_deref(), input.max_results, 100)?;
        Ok(t::GetAnomalyMonitorsResponse { anomaly_monitors, next_page_token })
    }

    pub(crate) fn update_anomaly_monitor_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateAnomalyMonitorRequest,
    ) -> Result<t::UpdateAnomalyMonitorResponse, ServiceError> {
        ctx.authorize("ce:UpdateAnomalyMonitor", &input.monitor_arn, Default::default())?;
        let today = date_str(ctx.received_at);
        self.with_account(ctx, |acct| {
            let m = acct.monitors.get_mut(&input.monitor_arn).ok_or_else(unknown_monitor)?;
            if let Some(name) = &input.monitor_name {
                let mut spec: t::AnomalyMonitor = serde_json::from_value(m.spec.clone()).unwrap_or_default();
                spec.monitor_name = name.clone();
                m.spec = serde_json::to_value(&spec).expect("monitor serializes");
            }
            m.updated = today;
            Ok::<_, ServiceError>(())
        })?;
        Ok(t::UpdateAnomalyMonitorResponse { monitor_arn: input.monitor_arn })
    }

    pub(crate) fn delete_anomaly_monitor_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteAnomalyMonitorRequest,
    ) -> Result<t::DeleteAnomalyMonitorResponse, ServiceError> {
        ctx.authorize("ce:DeleteAnomalyMonitor", &input.monitor_arn, Default::default())?;
        self.with_account(ctx, |acct| acct.monitors.remove(&input.monitor_arn)).ok_or_else(unknown_monitor)?;
        Ok(t::DeleteAnomalyMonitorResponse {})
    }

    pub(crate) fn create_anomaly_subscription_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateAnomalySubscriptionRequest,
    ) -> Result<t::CreateAnomalySubscriptionResponse, ServiceError> {
        auth(ctx, "CreateAnomalySubscription")?;
        let mut spec = input.anomaly_subscription;
        check_subscribers(&spec.frequency, &spec.subscribers)?;
        if spec.threshold.is_none() && spec.threshold_expression.is_none() {
            return Err(validation("Either Threshold or ThresholdExpression is required."));
        }
        let tags = tag_map(input.resource_tags.as_deref())?;
        let arn = arn(ctx, "anomalysubscription");
        spec.subscription_arn = None;
        spec.account_id = Some(ctx.caller.account_id.clone());
        for s in &mut spec.subscribers {
            s.status.get_or_insert_with(|| "CONFIRMED".into());
        }
        self.with_account(ctx, |acct| {
            if spec.monitor_arn_list.is_empty() || spec.monitor_arn_list.iter().any(|m| !acct.monitors.contains_key(m))
            {
                return Err(unknown_monitor());
            }
            acct.subscriptions.insert(
                arn.clone(),
                Subscription {
                    arn: arn.clone(),
                    spec: serde_json::to_value(&spec).expect("subscription serializes"),
                    tags,
                },
            );
            Ok(())
        })?;
        Ok(t::CreateAnomalySubscriptionResponse { subscription_arn: arn })
    }

    pub(crate) fn get_anomaly_subscriptions_op(
        &self,
        ctx: &RequestContext,
        input: t::GetAnomalySubscriptionsRequest,
    ) -> Result<t::GetAnomalySubscriptionsResponse, ServiceError> {
        auth(ctx, "GetAnomalySubscriptions")?;
        let wanted = input.subscription_arn_list.clone().unwrap_or_default();
        let subs = self.with_account(ctx, |acct| {
            let subs: Vec<t::AnomalySubscription> = acct
                .subscriptions
                .values()
                .filter(|s| wanted.is_empty() || wanted.contains(&s.arn))
                .map(|s| {
                    let mut spec: t::AnomalySubscription = serde_json::from_value(s.spec.clone()).unwrap_or_default();
                    spec.subscription_arn = Some(s.arn.clone());
                    spec
                })
                .filter(|s| input.monitor_arn.as_ref().is_none_or(|m| s.monitor_arn_list.contains(m)))
                .collect();
            if subs.len() < wanted.len() {
                return Err(unknown_subscription());
            }
            Ok(subs)
        })?;
        let (anomaly_subscriptions, next_page_token) =
            page(subs, input.next_page_token.as_deref(), input.max_results, 100)?;
        Ok(t::GetAnomalySubscriptionsResponse { anomaly_subscriptions, next_page_token })
    }

    pub(crate) fn update_anomaly_subscription_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateAnomalySubscriptionRequest,
    ) -> Result<t::UpdateAnomalySubscriptionResponse, ServiceError> {
        ctx.authorize("ce:UpdateAnomalySubscription", &input.subscription_arn, Default::default())?;
        self.with_account(ctx, |acct| {
            let monitors: BTreeSet<String> = acct.monitors.keys().cloned().collect();
            let s = acct.subscriptions.get_mut(&input.subscription_arn).ok_or_else(unknown_subscription)?;
            let mut spec: t::AnomalySubscription = serde_json::from_value(s.spec.clone()).unwrap_or_default();
            if let Some(v) = input.threshold {
                spec.threshold = Some(v);
            }
            if let Some(v) = &input.frequency {
                spec.frequency = v.clone();
            }
            if let Some(v) = &input.monitor_arn_list {
                if v.iter().any(|m| !monitors.contains(m)) {
                    return Err(unknown_monitor());
                }
                spec.monitor_arn_list = v.clone();
            }
            if let Some(v) = &input.subscribers {
                spec.subscribers = v.clone();
            }
            if let Some(v) = &input.subscription_name {
                spec.subscription_name = v.clone();
            }
            if let Some(v) = &input.threshold_expression {
                check_expression(v)?;
                spec.threshold_expression = Some(v.clone());
            }
            check_subscribers(&spec.frequency, &spec.subscribers)?;
            s.spec = serde_json::to_value(&spec).expect("subscription serializes");
            Ok(())
        })?;
        Ok(t::UpdateAnomalySubscriptionResponse { subscription_arn: input.subscription_arn })
    }

    pub(crate) fn delete_anomaly_subscription_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteAnomalySubscriptionRequest,
    ) -> Result<t::DeleteAnomalySubscriptionResponse, ServiceError> {
        ctx.authorize("ce:DeleteAnomalySubscription", &input.subscription_arn, Default::default())?;
        self.with_account(ctx, |acct| acct.subscriptions.remove(&input.subscription_arn))
            .ok_or_else(unknown_subscription)?;
        Ok(t::DeleteAnomalySubscriptionResponse {})
    }

    pub(crate) fn get_anomalies_op(
        &self,
        ctx: &RequestContext,
        input: t::GetAnomaliesRequest,
    ) -> Result<t::GetAnomaliesResponse, ServiceError> {
        auth(ctx, "GetAnomalies")?;
        let start = ms(parse_time(&input.date_interval.start_date)?);
        let end = match &input.date_interval.end_date {
            Some(e) => ms(parse_time(e)?),
            None => ms(ctx.received_at),
        };
        let mut anomalies = self.with_view(ctx, |view| {
            if let Some(m) = &input.monitor_arn {
                if !view.account.monitors.contains_key(m) {
                    return Err(unknown_monitor());
                }
            }
            Ok(view
                .account
                .monitors
                .values()
                .filter(|m| input.monitor_arn.as_ref().is_none_or(|a| a == &m.arn))
                .flat_map(|m| detect(view, m))
                .collect::<Vec<_>>())
        })?;
        anomalies.retain(|a| {
            let s = a.anomaly_start_date.as_deref().and_then(|d| parse_time(d).ok()).map(ms).unwrap_or(0);
            s >= start
                && s <= end
                && input.feedback.as_ref().is_none_or(|f| a.feedback.as_ref() == Some(f))
                && input.total_impact.as_ref().is_none_or(|f| {
                    let v = a.impact.total_impact;
                    match f.numeric_operator.as_str() {
                        "EQUAL" => v == f.start_value,
                        "GREATER_THAN_OR_EQUAL" => v >= f.start_value,
                        "LESS_THAN_OR_EQUAL" => v <= f.start_value,
                        "GREATER_THAN" => v > f.start_value,
                        "LESS_THAN" => v < f.start_value,
                        _ => v >= f.start_value && v <= f.end_value,
                    }
                })
        });
        anomalies.sort_by(|a, b| b.anomaly_start_date.cmp(&a.anomaly_start_date).then(a.anomaly_id.cmp(&b.anomaly_id)));
        let (anomalies, next_page_token) = page(anomalies, input.next_page_token.as_deref(), input.max_results, 100)?;
        Ok(t::GetAnomaliesResponse { anomalies, next_page_token })
    }

    pub(crate) fn provide_anomaly_feedback_op(
        &self,
        ctx: &RequestContext,
        input: t::ProvideAnomalyFeedbackRequest,
    ) -> Result<t::ProvideAnomalyFeedbackResponse, ServiceError> {
        auth(ctx, "ProvideAnomalyFeedback")?;
        self.with_account(ctx, |acct| acct.feedback.insert(input.anomaly_id.clone(), input.feedback.clone()));
        Ok(t::ProvideAnomalyFeedbackResponse { anomaly_id: input.anomaly_id })
    }

    /// Send anomalies not yet alerted to immediate SNS subscribers.
    pub(crate) fn alert_new_anomalies(&self, ctx: &RequestContext) {
        let Some(notifier) = self.inner.notifier.get().cloned() else { return };
        let accounts: Vec<String> = self
            .lock()
            .accounts
            .iter()
            .filter(|(_, a)| a.subscriptions.values().any(|s| s.spec.to_string().contains("IMMEDIATE")))
            .map(|(k, _)| k.clone())
            .collect();
        let now = ms(ctx.received_at);
        for account in accounts {
            let alerts: Vec<(String, crate::AnomalyAlert)> = self.with_view_of(&account, now, |view| {
                let mut out = Vec::new();
                for s in view.account.subscriptions.values() {
                    let spec: t::AnomalySubscription = serde_json::from_value(s.spec.clone()).unwrap_or_default();
                    if spec.frequency != "IMMEDIATE" {
                        continue;
                    }
                    for m in spec.monitor_arn_list.iter().filter_map(|a| view.account.monitors.get(a)) {
                        for a in detect(view, m) {
                            let key = format!("{}|{}", s.arn, a.anomaly_id);
                            if view.account.notified.contains(&key) || !passes(&spec, &a) {
                                continue;
                            }
                            let message = serde_json::json!({
                                "accountId": account,
                                "anomalyDetailsLink": format!("https://console.aws.amazon.com/cost-management/home#/anomaly-detection/monitors/{}/anomalies/{}", m.arn.rsplit('/').next().unwrap_or_default(), a.anomaly_id),
                                "anomalyEndDate": a.anomaly_end_date,
                                "anomalyId": a.anomaly_id,
                                "anomalyScore": {"currentScore": a.anomaly_score.current_score, "maxScore": a.anomaly_score.max_score},
                                "anomalyStartDate": a.anomaly_start_date,
                                "dimensionalValue": a.dimension_value,
                                "impact": {
                                    "maxImpact": a.impact.max_impact,
                                    "totalActualSpend": a.impact.total_actual_spend,
                                    "totalExpectedSpend": a.impact.total_expected_spend,
                                    "totalImpact": a.impact.total_impact,
                                    "totalImpactPercentage": a.impact.total_impact_percentage,
                                },
                                "monitorArn": m.arn,
                                "rootCauses": a.root_causes.iter().flatten().map(|c| serde_json::json!({
                                    "linkedAccount": c.linked_account,
                                    "linkedAccountName": c.linked_account_name,
                                    "region": c.region,
                                    "service": c.service,
                                    "usageType": c.usage_type,
                                })).collect::<Vec<_>>(),
                                "subscriptionId": s.arn.rsplit('/').next().unwrap_or_default(),
                                "subscriptionName": spec.subscription_name,
                            })
                            .to_string();
                            for sub in spec.subscribers.iter().filter(|x| x.r#type.as_deref() == Some("SNS")) {
                                if let Some(topic) = &sub.address {
                                    out.push((
                                        key.clone(),
                                        crate::AnomalyAlert {
                                            topic_arn: topic.clone(),
                                            subject: format!("AWS Cost Anomaly Detection Alert: {}", spec.subscription_name),
                                            message: message.clone(),
                                            account: account.clone(),
                                            subscription_arn: s.arn.clone(),
                                        },
                                    ));
                                }
                            }
                        }
                    }
                }
                out
            });
            for (key, alert) in alerts {
                let topic = alert.topic_arn.clone();
                if let Err(e) = notifier.notify(ctx, alert) {
                    tracing::warn!(topic, "anomaly alert not delivered: {e}");
                }
                let mut st = self.lock();
                let acct = st.accounts.entry(account.clone()).or_default();
                if !acct.notified.contains(&key) {
                    acct.notified.push(key);
                }
            }
        }
    }
}
