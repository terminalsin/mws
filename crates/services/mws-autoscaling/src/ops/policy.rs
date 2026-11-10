//! Scaling policies: simple, step, target tracking (with the CloudWatch
//! alarms it owns) and predictive, plus `ExecutePolicy` and alarm actions.

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::authorized_group;
use crate::generated::types as t;
use crate::state::{Group, State};
use crate::util::{at, authorize, limit_exceeded, paginate, policy_arn, scaling_in_progress, validation};
use crate::{account_of, AlarmQuery, AlarmQueryMetric, AlarmTrigger, AutoScaling, ManagedAlarm};

const ADJUSTMENT_TYPES: &[&str] = &["ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity"];
const POLICY_TYPES: &[&str] = &["SimpleScaling", "StepScaling", "TargetTrackingScaling", "PredictiveScaling"];

fn policy_not_found(name: &str) -> ServiceError {
    validation(format!("Policy name not found - Policy {name} not found"))
}

/// The capacity an adjustment asks for (before min/max).
pub(crate) fn adjusted(current: i32, adjustment_type: &str, adjustment: i32, min_magnitude: Option<i32>) -> i32 {
    match adjustment_type {
        "ExactCapacity" => adjustment,
        "PercentChangeInCapacity" => {
            let raw = current as f64 * adjustment as f64 / 100.0;
            let mut delta = if raw.abs() > 0.0 && raw.abs() < 1.0 { raw.signum() as i32 } else { raw.trunc() as i32 };
            if let Some(m) = min_magnitude.filter(|m| *m > 0) {
                if delta != 0 && delta.abs() < m {
                    delta = m * delta.signum();
                }
            }
            current + delta
        }
        _ => current + adjustment,
    }
}

/// The step whose interval holds `metric - threshold`.
fn step_for(steps: &[t::StepAdjustment], diff: f64) -> Option<&t::StepAdjustment> {
    steps.iter().find(|s| {
        let lower = s.metric_interval_lower_bound.unwrap_or(f64::NEG_INFINITY);
        let upper = s.metric_interval_upper_bound.unwrap_or(f64::INFINITY);
        if diff >= 0.0 {
            diff >= lower && diff < upper
        } else {
            diff > lower && diff <= upper
        }
    })
}

fn check_steps(steps: &[t::StepAdjustment]) -> Result<(), ServiceError> {
    if steps.is_empty() {
        return Err(validation("StepAdjustments must be specified for a StepScaling policy."));
    }
    let mut sorted: Vec<&t::StepAdjustment> = steps.iter().collect();
    sorted.sort_by(|a, b| {
        a.metric_interval_lower_bound
            .unwrap_or(f64::NEG_INFINITY)
            .partial_cmp(&b.metric_interval_lower_bound.unwrap_or(f64::NEG_INFINITY))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for s in &sorted {
        if let (Some(l), Some(u)) = (s.metric_interval_lower_bound, s.metric_interval_upper_bound) {
            if u <= l {
                return Err(validation("The upper bound of a step adjustment must be greater than its lower bound."));
            }
        }
    }
    for w in sorted.windows(2) {
        if w[0].metric_interval_upper_bound != w[1].metric_interval_lower_bound {
            return Err(validation("Step adjustment intervals must not overlap or have gaps."));
        }
    }
    let nulls_low = sorted.iter().filter(|s| s.metric_interval_lower_bound.is_none()).count();
    let nulls_high = sorted.iter().filter(|s| s.metric_interval_upper_bound.is_none()).count();
    if nulls_low > 1 || nulls_high > 1 {
        return Err(validation("Only one step adjustment can have a null bound on each side."));
    }
    Ok(())
}

/// The metric a target tracking policy follows: namespace, name,
/// dimensions, statistic, unit.
type TrackedMetric = (String, String, Vec<(String, String)>, String, Option<String>);

fn tracked_metric(group: &str, cfg: &t::TargetTrackingConfiguration) -> Result<TrackedMetric, ServiceError> {
    if let Some(p) = &cfg.predefined_metric_specification {
        let dims = vec![("AutoScalingGroupName".to_string(), group.to_string())];
        return Ok(match p.predefined_metric_type.as_str() {
            "ASGAverageCPUUtilization" => ("AWS/EC2".into(), "CPUUtilization".into(), dims, "Average".into(), None),
            "ASGAverageNetworkIn" => ("AWS/EC2".into(), "NetworkIn".into(), dims, "Average".into(), None),
            "ASGAverageNetworkOut" => ("AWS/EC2".into(), "NetworkOut".into(), dims, "Average".into(), None),
            "ALBRequestCountPerTarget" => {
                let label = p.resource_label.clone().ok_or_else(|| {
                    validation(
                        "ResourceLabel must be specified for the predefined metric type ALBRequestCountPerTarget.",
                    )
                })?;
                let tg = label.split('/').skip(3).collect::<Vec<_>>().join("/");
                (
                    "AWS/ApplicationELB".into(),
                    "RequestCountPerTarget".into(),
                    vec![("TargetGroup".into(), tg)],
                    "Sum".into(),
                    None,
                )
            }
            other => return Err(validation(format!("Unsupported predefined metric type: {other}"))),
        });
    }
    if let Some(c) = &cfg.customized_metric_specification {
        if c.metrics.as_ref().is_some_and(|m| !m.is_empty()) {
            if c.metric_name.is_some() || c.namespace.is_some() || c.dimensions.is_some() || c.statistic.is_some() {
                return Err(validation(
                    "A customized metric specification can specify either Metrics or MetricName, Namespace, Dimensions and Statistic, not both.",
                ));
            }
            // A metric math policy: its alarms evaluate the queries.
            return Ok((String::new(), String::new(), Vec::new(), String::new(), None));
        }
        let name =
            c.metric_name.clone().ok_or_else(|| validation("MetricName must be specified for a customized metric."))?;
        let ns =
            c.namespace.clone().ok_or_else(|| validation("Namespace must be specified for a customized metric."))?;
        return Ok((
            ns,
            name,
            c.dimensions.iter().flatten().map(|d| (d.name.clone(), d.value.clone())).collect(),
            c.statistic.clone().unwrap_or_else(|| "Average".into()),
            c.unit.clone(),
        ));
    }
    Err(validation("Either PredefinedMetricSpecification or CustomizedMetricSpecification must be specified."))
}

/// The metric math queries of a target tracking policy
/// (`CustomizedMetricSpecification.Metrics`), checked as AWS does: every
/// query has an expression or a metric, and exactly one returns data.
fn math_queries(cfg: &t::TargetTrackingConfiguration) -> Result<Vec<AlarmQuery>, ServiceError> {
    let Some(list) = cfg.customized_metric_specification.as_ref().and_then(|c| c.metrics.as_ref()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for q in list {
        if q.expression.is_some() == q.metric_stat.is_some() {
            return Err(validation(format!(
                "Metric data query {} must specify exactly one of Expression and MetricStat.",
                q.id
            )));
        }
        out.push(AlarmQuery {
            id: q.id.clone(),
            expression: q.expression.clone(),
            label: q.label.clone(),
            return_data: q.return_data,
            metric: q.metric_stat.as_ref().map(|m| AlarmQueryMetric {
                namespace: m.metric.namespace.clone(),
                metric_name: m.metric.metric_name.clone(),
                dimensions: m.metric.dimensions.iter().flatten().map(|d| (d.name.clone(), d.value.clone())).collect(),
                stat: m.stat.clone(),
                unit: m.unit.clone(),
                period: m.period.or(q.period).unwrap_or(60),
            }),
        });
    }
    // ReturnData defaults to true for a single query.
    let returning = out.iter().filter(|q| q.return_data.unwrap_or(out.len() == 1)).count();
    if returning != 1 {
        return Err(validation("Exactly one metric data query must have ReturnData set to true."));
    }
    if out.len() == 1 {
        out[0].return_data = Some(true);
    }
    Ok(out)
}

/// Apply a capacity change to a group: clamp, record the cause, start the
/// cooldown. Returns whether the desired capacity changed.
fn apply(g: &mut Group, new: i32, cause: String, cooldown: Option<i64>, now: DateTime<Utc>) -> bool {
    let new = new.clamp(g.cfg.min_size, g.cfg.max_size.max(g.cfg.min_size));
    let before = g.cfg.desired_capacity;
    if new == before {
        return false;
    }
    g.cfg.desired_capacity = new;
    g.pending_cause = Some(format!("{cause} changing the desired capacity from {before} to {new}."));
    if let Some(c) = cooldown {
        g.cooldown_until = Some(now + Duration::seconds(c));
    }
    true
}

impl AutoScaling {
    pub(crate) async fn put_scaling_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::PutScalingPolicyType,
    ) -> Result<t::PolicyARNType, ServiceError> {
        let account = account_of(ctx);
        let kind = input.policy_type.clone().unwrap_or_else(|| "SimpleScaling".into());
        if !POLICY_TYPES.contains(&kind.as_str()) {
            return Err(validation(format!("Invalid policy type: {kind}")));
        }
        if let Some(a) = &input.adjustment_type {
            if !ADJUSTMENT_TYPES.contains(&a.as_str()) {
                return Err(validation(format!("Invalid adjustment type: {a}")));
            }
        }
        match kind.as_str() {
            "SimpleScaling" => {
                if input.adjustment_type.is_none() {
                    return Err(validation("AdjustmentType must be specified for a SimpleScaling policy."));
                }
                if input.scaling_adjustment.is_none() {
                    return Err(validation("ScalingAdjustment must be specified for a SimpleScaling policy."));
                }
            }
            "StepScaling" => {
                if input.adjustment_type.is_none() {
                    return Err(validation("AdjustmentType must be specified for a StepScaling policy."));
                }
                check_steps(input.step_adjustments.as_deref().unwrap_or_default())?;
                if let Some(a) = &input.metric_aggregation_type {
                    if !matches!(a.as_str(), "Minimum" | "Maximum" | "Average") {
                        return Err(validation(format!("Invalid metric aggregation type: {a}")));
                    }
                }
            }
            "TargetTrackingScaling" => {
                let cfg = input.target_tracking_configuration.as_ref().ok_or_else(|| {
                    validation("TargetTrackingConfiguration must be specified for a TargetTrackingScaling policy.")
                })?;
                tracked_metric(&input.auto_scaling_group_name, cfg)?;
                math_queries(cfg)?;
            }
            _ => {
                let cfg = input.predictive_scaling_configuration.as_ref().ok_or_else(|| {
                    validation("PredictiveScalingConfiguration must be specified for a PredictiveScaling policy.")
                })?;
                if cfg.metric_specifications.is_empty() {
                    return Err(validation("PredictiveScalingConfiguration must have one metric specification."));
                }
            }
        }
        let (policy, old_alarms) = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "PutScalingPolicy", &input.auto_scaling_group_name)?;
            let existing = g.policies.get(&input.policy_name).cloned();
            if existing.is_none() && g.policies.len() >= 50 {
                return Err(limit_exceeded(
                    "You have reached the limit of 50 scaling policies for the Auto Scaling group.",
                ));
            }
            if existing.as_ref().is_some_and(|e| e.policy_type.as_deref() != Some(kind.as_str())) {
                return Err(validation("You can't change the type of an existing scaling policy."));
            }
            let arn = existing
                .as_ref()
                .and_then(|e| e.policy_arn.clone())
                .unwrap_or_else(|| policy_arn(ctx, &account, &input.auto_scaling_group_name, &input.policy_name));
            let mut policy = t::ScalingPolicy {
                auto_scaling_group_name: Some(input.auto_scaling_group_name.clone()),
                policy_name: Some(input.policy_name.clone()),
                policy_arn: Some(arn),
                policy_type: Some(kind.clone()),
                adjustment_type: input.adjustment_type.clone(),
                min_adjustment_step: input.min_adjustment_step,
                min_adjustment_magnitude: input.min_adjustment_magnitude,
                scaling_adjustment: input.scaling_adjustment,
                cooldown: input.cooldown,
                step_adjustments: input.step_adjustments.clone(),
                metric_aggregation_type: input.metric_aggregation_type.clone(),
                estimated_instance_warmup: input.estimated_instance_warmup,
                alarms: Some(existing.as_ref().and_then(|e| e.alarms.clone()).unwrap_or_default()),
                target_tracking_configuration: input.target_tracking_configuration.clone().map(|mut c| {
                    c.disable_scale_in.get_or_insert(false);
                    c
                }),
                enabled: Some(input.enabled.unwrap_or(true)),
                predictive_scaling_configuration: input.predictive_scaling_configuration.clone().map(|mut c| {
                    c.mode.get_or_insert_with(|| "ForecastOnly".into());
                    c.max_capacity_breach_behavior.get_or_insert_with(|| "HonorMaxCapacity".into());
                    c
                }),
            };
            if kind == "StepScaling" {
                policy.metric_aggregation_type.get_or_insert_with(|| "Average".into());
            }
            let old = if kind == "TargetTrackingScaling" { g.policy_alarms.remove(&input.policy_name) } else { None };
            g.policies.insert(input.policy_name.clone(), policy.clone());
            Ok((policy, old.unwrap_or_default()))
        })?;
        let mut alarms_out = Vec::new();
        if kind == "TargetTrackingScaling" {
            let sctx = self.service_ctx(ctx, &account, &ctx.region);
            let mgr = self.alarms().cloned();
            if let Some(mgr) = &mgr {
                if !old_alarms.is_empty() {
                    mgr.delete_alarms(&sctx, &old_alarms).await;
                }
            }
            let cfg = policy.target_tracking_configuration.clone().expect("checked");
            let (namespace, metric_name, dimensions, statistic, unit) =
                tracked_metric(&input.auto_scaling_group_name, &cfg)?;
            let metrics = math_queries(&cfg)?;
            let arn = policy.policy_arn.clone().unwrap_or_default();
            let id = uuid::Uuid::new_v4().to_string();
            let mut wanted = vec![ManagedAlarm {
                name: format!("TargetTracking-{}-AlarmHigh-{id}", input.auto_scaling_group_name),
                description: format!("DO NOT EDIT OR DELETE. For TargetTrackingScaling policy {arn}."),
                namespace: namespace.clone(),
                metric_name: metric_name.clone(),
                dimensions: dimensions.clone(),
                statistic: statistic.clone(),
                unit: unit.clone(),
                period: 60,
                evaluation_periods: 3,
                datapoints_to_alarm: 3,
                threshold: cfg.target_value,
                comparison_operator: "GreaterThanThreshold".into(),
                alarm_actions: vec![arn.clone()],
                metrics: metrics.clone(),
            }];
            if !cfg.disable_scale_in.unwrap_or(false) {
                wanted.push(ManagedAlarm {
                    name: format!("TargetTracking-{}-AlarmLow-{}", input.auto_scaling_group_name, uuid::Uuid::new_v4()),
                    description: format!("DO NOT EDIT OR DELETE. For TargetTrackingScaling policy {arn}."),
                    namespace,
                    metric_name,
                    dimensions,
                    statistic,
                    unit,
                    period: 60,
                    evaluation_periods: 15,
                    datapoints_to_alarm: 15,
                    threshold: cfg.target_value * 0.9,
                    comparison_operator: "LessThanThreshold".into(),
                    alarm_actions: vec![arn.clone()],
                    metrics,
                });
            }
            let mut names = Vec::new();
            for a in &wanted {
                let alarm_arn = match &mgr {
                    Some(m) => m
                        .put_alarm(&sctx, a)
                        .await
                        .map_err(|e| validation(format!("Could not create the target tracking alarm: {e}")))?,
                    None => format!("arn:{}:cloudwatch:{}:{account}:alarm:{}", ctx.partition, ctx.region, a.name),
                };
                names.push(a.name.clone());
                alarms_out.push(t::Alarm { alarm_name: Some(a.name.clone()), alarm_arn: Some(alarm_arn) });
            }
            self.with_region(ctx, |r| {
                if let Some(g) = r.groups.get_mut(&input.auto_scaling_group_name) {
                    g.policy_alarms.insert(input.policy_name.clone(), names);
                    if let Some(p) = g.policies.get_mut(&input.policy_name) {
                        p.alarms = Some(alarms_out.clone());
                    }
                }
            });
        }
        Ok(t::PolicyARNType { policy_arn: policy.policy_arn, alarms: Some(alarms_out) })
    }

    pub(crate) fn describe_policies_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribePoliciesType,
    ) -> Result<t::PoliciesType, ServiceError> {
        authorize(ctx, "DescribePolicies", "*", None, ConditionContext::new())?;
        let names = input.policy_names.clone().unwrap_or_default();
        let kinds = input.policy_types.clone().unwrap_or_default();
        let list: Vec<t::ScalingPolicy> = self.with_region(ctx, |r| {
            if let Some(g) = &input.auto_scaling_group_name {
                if !r.groups.contains_key(g) {
                    return Err(crate::util::group_not_found(g));
                }
            }
            Ok(r.groups
                .values()
                .filter(|g| input.auto_scaling_group_name.as_ref().is_none_or(|n| n == g.name()))
                .flat_map(|g| g.policies.values().cloned())
                .filter(|p| {
                    names.is_empty()
                        || names.iter().any(|n| Some(n) == p.policy_name.as_ref() || Some(n) == p.policy_arn.as_ref())
                })
                .filter(|p| kinds.is_empty() || p.policy_type.as_ref().is_some_and(|k| kinds.contains(k)))
                .collect())
        })?;
        let (page, next_token) = paginate(list, input.max_records, &input.next_token, 100)?;
        Ok(t::PoliciesType { scaling_policies: Some(page), next_token })
    }

    /// The group and policy `name` (a name or ARN) belongs to.
    fn locate_policy(r: &crate::state::RegionState, group: &Option<String>, name: &str) -> Option<(String, String)> {
        r.groups.values().filter(|g| group.as_ref().is_none_or(|n| n == g.name())).find_map(|g| {
            g.policies
                .values()
                .find(|p| p.policy_name.as_deref() == Some(name) || p.policy_arn.as_deref() == Some(name))
                .map(|p| (g.name().to_string(), p.policy_name.clone().unwrap_or_default()))
        })
    }

    pub(crate) async fn delete_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::DeletePolicyType,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let alarms = self.with_region(ctx, |r| {
            let (group, policy) = match Self::locate_policy(r, &input.auto_scaling_group_name, &input.policy_name) {
                Some(found) => found,
                None => {
                    if let Some(g) = &input.auto_scaling_group_name {
                        authorized_group(ctx, r, "DeletePolicy", g)?;
                    } else {
                        authorize(ctx, "DeletePolicy", "*", None, ConditionContext::new())?;
                    }
                    return Err(policy_not_found(&input.policy_name));
                }
            };
            let g = authorized_group(ctx, r, "DeletePolicy", &group)?;
            g.policies.remove(&policy);
            Ok(g.policy_alarms.remove(&policy).unwrap_or_default())
        })?;
        if let (Some(mgr), false) = (self.alarms(), alarms.is_empty()) {
            mgr.delete_alarms(&self.service_ctx(ctx, &account, &ctx.region), &alarms).await;
        }
        Ok(())
    }

    /// Run a policy: compute the new capacity and apply it.
    #[allow(clippy::too_many_arguments)]
    fn run_policy(
        g: &mut Group,
        policy: &t::ScalingPolicy,
        metric: Option<f64>,
        threshold: Option<f64>,
        cause: String,
        honor_cooldown: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, ServiceError> {
        let kind = policy.policy_type.as_deref().unwrap_or("SimpleScaling");
        let current = g.cfg.desired_capacity;
        let adjustment_type = policy.adjustment_type.as_deref().unwrap_or("ChangeInCapacity");
        let magnitude = policy.min_adjustment_magnitude.or(policy.min_adjustment_step);
        match kind {
            "SimpleScaling" => {
                if honor_cooldown && g.cooldown_until.is_some_and(|c| now < c) {
                    return Err(scaling_in_progress("Scaling activity is in progress and blocks this action."));
                }
                let new = adjusted(current, adjustment_type, policy.scaling_adjustment.unwrap_or(0), magnitude);
                let cooldown = policy.cooldown.unwrap_or(g.cfg.default_cooldown) as i64;
                Ok(apply(g, new, cause, Some(cooldown), now))
            }
            "StepScaling" => {
                let (Some(metric), Some(threshold)) = (metric, threshold) else {
                    return Err(validation(
                        "MetricValue and BreachThreshold are required for executing a StepScaling policy.",
                    ));
                };
                let steps = policy.step_adjustments.clone().unwrap_or_default();
                let Some(step) = step_for(&steps, metric - threshold) else {
                    return Err(validation(format!(
                        "The metric value {metric} does not fall into any of the step adjustments of policy {}.",
                        policy.policy_name.clone().unwrap_or_default()
                    )));
                };
                let new = adjusted(current, adjustment_type, step.scaling_adjustment, magnitude);
                Ok(apply(g, new, cause, None, now))
            }
            "TargetTrackingScaling" => {
                let cfg = policy.target_tracking_configuration.clone().unwrap_or_default();
                let Some(metric) = metric else { return Ok(false) };
                if cfg.target_value <= 0.0 {
                    return Ok(false);
                }
                let base = current.max(1) as f64;
                let mut new = (base * metric / cfg.target_value).ceil() as i32;
                if current == 0 && metric > cfg.target_value {
                    new = new.max(1);
                }
                if new < current && cfg.disable_scale_in.unwrap_or(false) {
                    return Ok(false);
                }
                // Scale in gently: one step toward the target at a time.
                if new < current {
                    new = new.max(current - (current / 10).max(1));
                }
                Ok(apply(g, new, cause, None, now))
            }
            _ => Err(validation("A PredictiveScaling policy can't be executed.")),
        }
    }

    pub(crate) fn execute_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::ExecutePolicyType,
    ) -> Result<(), ServiceError> {
        let now = self.now();
        self.with_region(ctx, |r| {
            let (group, policy) = match Self::locate_policy(r, &input.auto_scaling_group_name, &input.policy_name) {
                Some(found) => found,
                None => {
                    if let Some(g) = &input.auto_scaling_group_name {
                        authorized_group(ctx, r, "ExecutePolicy", g)?;
                    } else {
                        authorize(ctx, "ExecutePolicy", "*", None, ConditionContext::new())?;
                    }
                    return Err(policy_not_found(&input.policy_name));
                }
            };
            let g = authorized_group(ctx, r, "ExecutePolicy", &group)?;
            let p = g.policies.get(&policy).cloned().expect("policy");
            match p.policy_type.as_deref() {
                Some("TargetTrackingScaling") => {
                    return Err(validation("ExecutePolicy is not supported for target tracking scaling policies."))
                }
                Some("PredictiveScaling") => {
                    return Err(validation("ExecutePolicy is not supported for predictive scaling policies."))
                }
                Some("StepScaling") if input.honor_cooldown.is_some() => {
                    return Err(validation("HonorCooldown is not supported for step scaling policies."))
                }
                _ => {}
            }
            let cause = format!("{} a user request executed policy {policy}", at(now));
            Self::run_policy(
                g,
                &p,
                input.metric_value,
                input.breach_threshold,
                cause,
                input.honor_cooldown.unwrap_or(false),
                now,
            )
            .map(drop)
        })
    }

    /// A CloudWatch alarm action naming one of the policies.
    pub(crate) async fn run_alarm_policy(&self, trigger: AlarmTrigger) -> Result<(), String> {
        let now = self.now();
        let changed = {
            let mut st = self.lock();
            let Some(r) = st.regions.get_mut(&State::key(&trigger.account, &trigger.region)) else {
                return Err(format!("No scaling policy {} exists.", trigger.policy_arn));
            };
            let Some((group, policy)) = Self::locate_policy(r, &None, &trigger.policy_arn) else {
                return Err(format!("No scaling policy {} exists.", trigger.policy_arn));
            };
            let g = r.groups.get_mut(&group).expect("group");
            if g.suspended("AlarmNotification") || g.deleting {
                return Ok(());
            }
            let p = g.policies.get(&policy).cloned().expect("policy");
            if p.enabled == Some(false) {
                return Ok(());
            }
            // Simple policies wait out their cooldown.
            if p.policy_type.as_deref().unwrap_or("SimpleScaling") == "SimpleScaling"
                && g.cooldown_until.is_some_and(|c| now < c)
            {
                return Ok(());
            }
            let cause =
                format!("{} a monitor alarm {} in state ALARM triggered policy {policy}", at(now), trigger.alarm_name);
            Self::run_policy(g, &p, trigger.metric_value, trigger.threshold, cause, false, now)
                .map_err(|e| e.message)?
        };
        if changed {
            self.kick();
        }
        Ok(())
    }

    pub(crate) fn get_predictive_scaling_forecast_op(
        &self,
        ctx: &RequestContext,
        input: t::GetPredictiveScalingForecastType,
    ) -> Result<t::GetPredictiveScalingForecastAnswer, ServiceError> {
        if input.end_time <= input.start_time {
            return Err(validation("EndTime must be after StartTime."));
        }
        if input.end_time - input.start_time > Duration::days(30) {
            return Err(validation("The time range between StartTime and EndTime can't exceed 30 days."));
        }
        let now = self.now();
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "GetPredictiveScalingForecast", &input.auto_scaling_group_name)?;
            let p = g
                .policies
                .get(&input.policy_name)
                .filter(|p| p.policy_type.as_deref() == Some("PredictiveScaling"))
                .ok_or_else(|| policy_not_found(&input.policy_name))?;
            let cfg = p.predictive_scaling_configuration.clone().unwrap_or_default();
            let mut timestamps = Vec::new();
            let mut t0 = input.start_time - Duration::seconds(input.start_time.timestamp().rem_euclid(3600));
            while t0 < input.end_time {
                timestamps.push(t0);
                t0 += Duration::hours(1);
            }
            let desired = g.cfg.desired_capacity as f64;
            // A flat forecast: today's load, and the capacity it needs.
            let loads = cfg
                .metric_specifications
                .iter()
                .map(|m| t::LoadForecast {
                    timestamps: timestamps.clone(),
                    values: vec![m.target_value * desired.max(1.0); timestamps.len()],
                    metric_specification: m.clone(),
                })
                .collect();
            Ok(t::GetPredictiveScalingForecastAnswer {
                load_forecast: loads,
                capacity_forecast: t::CapacityForecast {
                    timestamps: timestamps.clone(),
                    values: vec![desired; timestamps.len()],
                },
                update_time: now,
            })
        })
    }
}
