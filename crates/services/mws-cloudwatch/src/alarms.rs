//! Alarm configuration: `PutMetricAlarm`, `PutCompositeAlarm`,
//! `PutLogAlarm`, `DescribeAlarms`, `DescribeAlarmsForMetric`,
//! `DeleteAlarms`, `EnableAlarmActions`, `DisableAlarmActions`,
//! `SetAlarmState`, `DescribeAlarmHistory` and
//! `DescribeAlarmContributors`. Evaluation lives in [`crate::evaluate`].

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::json;

use crate::evaluate::Transition;
use crate::generated::{errors, types};
use crate::metrics::valid_period;
use crate::names::{self, alarm_arn, history_time, now, request_tag_conditions, resource_tag_conditions};
use crate::rule::Rule;
use crate::state::{Alarm, Region};
use crate::CloudWatch;

const STATES: &[&str] = &["OK", "ALARM", "INSUFFICIENT_DATA"];
const TREAT_MISSING: &[&str] = &["breaching", "notBreaching", "ignore", "missing"];
const MAX_HISTORY: usize = 10_000;
const MAX_ACTIONS: usize = 5;

pub(crate) fn push_history(region: &mut Region, item: types::AlarmHistoryItem) {
    region.history.push(item);
    if region.history.len() > MAX_HISTORY {
        let drop = region.history.len() - MAX_HISTORY;
        region.history.drain(..drop);
    }
}

pub(crate) fn config_history(
    alarm: &Alarm,
    kind: &str,
    now: DateTime<Utc>,
    data: serde_json::Value,
) -> types::AlarmHistoryItem {
    types::AlarmHistoryItem {
        alarm_name: Some(alarm.name().to_string()),
        alarm_type: Some(alarm.alarm_type.clone()),
        timestamp: Some(now),
        history_item_type: Some("ConfigurationUpdate".into()),
        history_summary: Some(format!("Alarm \"{}\" {kind}", alarm.name())),
        history_data: Some(data.to_string()),
        ..Default::default()
    }
}

fn validate_actions(actions: &[Option<Vec<String>>]) -> Result<(), ServiceError> {
    for list in actions.iter().flatten() {
        if list.len() > MAX_ACTIONS {
            return Err(errors::validation(format!(
                "The collection of actions must not have a size greater than {MAX_ACTIONS}."
            )));
        }
        for a in list {
            let parts: Vec<&str> = a.splitn(6, ':').collect();
            if parts.len() < 6 || parts[0] != "arn" {
                return Err(errors::validation(format!("Invalid arn syntax: {a}")));
            }
            let ok = matches!(
                parts[2],
                "sns" | "lambda" | "autoscaling" | "automate" | "ssm" | "ssm-incidents" | "swf" | "ec2" | "sqs"
            );
            if !ok {
                return Err(errors::validation(format!("Invalid action: {a}")));
            }
        }
    }
    Ok(())
}

fn validate_tags(tags: &[types::Tag]) -> Result<(), ServiceError> {
    if tags.len() > 50 {
        return Err(errors::invalid_parameter_value("The number of tags must not exceed 50."));
    }
    if let Some(t) = tags.iter().find(|t| t.key.starts_with("aws:")) {
        return Err(errors::invalid_parameter_value(format!(
            "Invalid tag key: {}. Tag keys cannot start with the reserved prefix aws:.",
            t.key
        )));
    }
    Ok(())
}

fn validate_comparison(op: &str, band: bool) -> Result<(), ServiceError> {
    let band_ops = ["LessThanLowerOrGreaterThanUpperThreshold", "LessThanLowerThreshold", "GreaterThanUpperThreshold"];
    if band != band_ops.contains(&op) {
        return Err(errors::validation(if band {
            format!("Comparison operator {op} is not supported for anomaly detection alarms.")
        } else {
            format!("Comparison operator {op} is only supported for anomaly detection alarms.")
        }));
    }
    Ok(())
}

impl CloudWatch {
    /// The caller's alarm `name`, authorized for `action` with its tags.
    pub(crate) fn authorize_alarm(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: &str,
        mut extra: ConditionContext,
    ) -> Result<String, ServiceError> {
        let arn = alarm_arn(ctx, name);
        let tags = self.lock().region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.tags.get(&arn).cloned());
        extra.extend(resource_tag_conditions(tags.as_ref()));
        ctx.authorize(&format!("cloudwatch:{action}"), &arn, extra)?;
        Ok(arn)
    }

    /// Store a new or updated alarm. Tags only apply when it is new.
    fn save_alarm(
        &self,
        ctx: &RequestContext,
        name: &str,
        alarm_type: &str,
        tags: Vec<types::Tag>,
        set: impl FnOnce(&mut Alarm),
    ) -> Result<(), ServiceError> {
        let now = now(ctx);
        let arn = alarm_arn(ctx, name);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(existing) = region.alarms.get(name) {
            if existing.alarm_type != alarm_type {
                return Err(errors::resource_conflict(format!(
                    "An alarm of another type with the name {name} already exists."
                )));
            }
        }
        let created = !region.alarms.contains_key(name);
        let alarm = region.alarms.entry(name.to_string()).or_insert_with(|| Alarm {
            arn: arn.clone(),
            alarm_type: alarm_type.to_string(),
            state_value: "INSUFFICIENT_DATA".into(),
            state_reason: "Unchecked: Initial alarm creation".into(),
            state_updated: now,
            state_transitioned: now,
            ..Alarm::default()
        });
        set(alarm);
        alarm.config_updated = now;
        alarm.last_evaluated = None;
        let snapshot = alarm.clone();
        let data = json!({"version": "1.0", "type": if created { "Create" } else { "Update" }, "createdAlarm": self.alarm_json(&snapshot)});
        push_history(region, config_history(&snapshot, if created { "created" } else { "updated" }, now, data));
        if created && !tags.is_empty() {
            region.tags.insert(arn, tags.into_iter().map(|t| (t.key, t.value)).collect());
        }
        Ok(())
    }

    pub(crate) fn alarm_json(&self, a: &Alarm) -> serde_json::Value {
        let v = match a.alarm_type.as_str() {
            "CompositeAlarm" => serde_json::to_value(composite_out(a)),
            "LogAlarm" => serde_json::to_value(log_out(a)),
            _ => serde_json::to_value(metric_out(a)),
        };
        v.unwrap_or_default()
    }

    pub(crate) fn put_metric_alarm(
        &self,
        ctx: &RequestContext,
        mut input: types::PutMetricAlarmInput,
    ) -> Result<(), ServiceError> {
        let tags = input.tags.take().unwrap_or_default();
        self.authorize_alarm(ctx, "PutMetricAlarm", &input.alarm_name, request_tag_conditions(&tags))?;
        self.observe(ctx);
        validate_tags(&tags)?;
        validate_actions(&[
            input.ok_actions.clone(),
            input.alarm_actions.clone(),
            input.insufficient_data_actions.clone(),
        ])?;
        let promql = input.evaluation_criteria.is_some();
        match (&input.metric_name, &input.metrics) {
            (Some(_), Some(_)) => {
                return Err(errors::invalid_parameter_combination(
                    "The parameters MetricName and Metrics are mutually exclusive and you have specified both.",
                ))
            }
            (None, None) if !promql => {
                return Err(errors::validation("One of MetricName, Metrics or EvaluationCriteria must be specified."))
            }
            (Some(_), None) => {
                if input.namespace.is_none() {
                    return Err(errors::missing_required_parameter("The parameter Namespace is required."));
                }
                match (&input.statistic, &input.extended_statistic) {
                    (Some(_), Some(_)) => {
                        return Err(errors::invalid_parameter_combination(
                            "The parameters Statistic and ExtendedStatistic are mutually exclusive and you have specified both.",
                        ))
                    }
                    (None, None) => {
                        return Err(errors::missing_required_parameter(
                            "One of the parameters Statistic or ExtendedStatistic must be specified.",
                        ))
                    }
                    (None, Some(e)) if crate::stats::Stat::parse(e).is_none() || crate::stats::Stat::is_basic(e) => {
                        return Err(errors::invalid_parameter_value(format!(
                            "The value {e} for parameter ExtendedStatistic is not supported."
                        )));
                    }
                    _ => {}
                }
                let period = input
                    .period
                    .ok_or_else(|| errors::missing_required_parameter("The parameter Period is required."))?;
                if !valid_period(period as i64) || matches!(period, 1 | 5) {
                    return Err(errors::validation(format!(
                        "The value {period} for parameter Period is not supported. Valid values are 10, 20, 30 or any multiple of 60."
                    )));
                }
            }
            (None, Some(metrics)) => {
                crate::math::validate_queries(metrics, "Metrics")?;
                let returning = metrics.iter().filter(|q| q.return_data != Some(false)).count();
                if input.threshold_metric_id.is_none() && returning != 1 {
                    return Err(errors::validation("Exactly one element of the metrics list should return data."));
                }
                if input.statistic.is_some()
                    || input.extended_statistic.is_some()
                    || input.namespace.is_some()
                    || input.period.is_some()
                {
                    return Err(errors::invalid_parameter_combination(
                        "The parameters Statistic, ExtendedStatistic, Namespace, Period and Dimensions cannot be specified with Metrics.",
                    ));
                }
                if let Some(t) = &input.threshold_metric_id {
                    if !metrics.iter().any(|q| &q.id == t) {
                        return Err(errors::validation(format!("ThresholdMetricId {t} is not in the Metrics list.")));
                    }
                }
            }
            _ => {}
        }
        if !promql {
            let op = input
                .comparison_operator
                .as_deref()
                .ok_or_else(|| errors::missing_required_parameter("The parameter ComparisonOperator is required."))?;
            validate_comparison(op, input.threshold_metric_id.is_some())?;
            if input.threshold_metric_id.is_none() && input.threshold.is_none() {
                return Err(errors::missing_required_parameter("The parameter Threshold is required."));
            }
            if input.threshold_metric_id.is_some() && input.threshold.is_some() {
                return Err(errors::invalid_parameter_combination(
                    "The parameters Threshold and ThresholdMetricId are mutually exclusive and you have specified both.",
                ));
            }
            let periods = input
                .evaluation_periods
                .ok_or_else(|| errors::missing_required_parameter("The parameter EvaluationPeriods is required."))?;
            if let Some(d) = input.datapoints_to_alarm {
                if d > periods {
                    return Err(errors::validation(
                        "DatapointsToAlarm must be less than or equal to EvaluationPeriods.",
                    ));
                }
            }
            let period = input.period.or_else(|| {
                input.metrics.iter().flatten().find_map(|q| q.metric_stat.as_ref().map(|m| m.period).or(q.period))
            });
            if let Some(p) = period {
                let limit = if p >= 3600 { 7 * 86400 } else { 86400 };
                if p as i64 * periods as i64 > limit {
                    return Err(errors::validation(if limit == 86400 {
                        "Metrics cannot be checked across more than a day (EvaluationPeriods * Period must be <= 86400)"
                            .to_string()
                    } else {
                        "Metrics cannot be checked across more than a week (EvaluationPeriods * Period must be <= 604800)".to_string()
                    }));
                }
            }
        }
        if let Some(t) = &input.treat_missing_data {
            if !TREAT_MISSING.contains(&t.as_str()) {
                return Err(errors::validation(format!(
                    "The value {t} for parameter TreatMissingData is not supported. Valid values are breaching, notBreaching, ignore and missing."
                )));
            }
        }
        if let Some(e) = &input.evaluate_low_sample_count_percentile {
            if e != "evaluate" && e != "ignore" {
                return Err(errors::validation(format!(
                    "The value {e} for parameter EvaluateLowSampleCountPercentile is not supported."
                )));
            }
        }
        let name = input.alarm_name.clone();
        self.save_alarm(ctx, &name, "MetricAlarm", tags, |a| a.metric = Some(input))
    }

    pub(crate) fn put_composite_alarm(
        &self,
        ctx: &RequestContext,
        mut input: types::PutCompositeAlarmInput,
    ) -> Result<(), ServiceError> {
        let tags = input.tags.take().unwrap_or_default();
        self.authorize_alarm(ctx, "PutCompositeAlarm", &input.alarm_name, request_tag_conditions(&tags))?;
        self.observe(ctx);
        validate_tags(&tags)?;
        validate_actions(&[
            input.ok_actions.clone(),
            input.alarm_actions.clone(),
            input.insufficient_data_actions.clone(),
        ])?;
        let rule = Rule::parse(&input.alarm_rule).map_err(errors::validation)?;
        {
            let st = self.lock();
            let region = st.region_ref(&ctx.caller.account_id, &ctx.region);
            let missing: Vec<String> = rule
                .alarms()
                .into_iter()
                .filter(|n| region.is_none_or(|r| !r.alarms.contains_key(n.as_str())))
                .collect();
            if !missing.is_empty() {
                return Err(errors::validation(format!(
                    "Could not save the composite alarm as alarms [{}] in the alarm rule do not exist",
                    missing.join(", ")
                )));
            }
            if let Some(r) = region {
                if crate::rule::creates_cycle(r, &input.alarm_name, &rule) {
                    return Err(errors::validation(
                        "Could not save the composite alarm as the alarm rule would create a cycle of composite alarms",
                    ));
                }
            }
        }
        if let Some(s) = &input.actions_suppressor {
            let suppressor = s.rsplit(":alarm:").next().unwrap_or(s);
            let st = self.lock();
            if st.region_ref(&ctx.caller.account_id, &ctx.region).is_none_or(|r| !r.alarms.contains_key(suppressor)) {
                return Err(errors::validation(format!(
                    "Could not save the composite alarm as the actions suppressor {s} does not exist"
                )));
            }
        } else if input.actions_suppressor_wait_period.is_some() || input.actions_suppressor_extension_period.is_some()
        {
            return Err(errors::validation(
                "ActionsSuppressorWaitPeriod and ActionsSuppressorExtensionPeriod require ActionsSuppressor.",
            ));
        }
        let name = input.alarm_name.clone();
        self.save_alarm(ctx, &name, "CompositeAlarm", tags, |a| a.composite = Some(input))
    }

    pub(crate) fn put_log_alarm(
        &self,
        ctx: &RequestContext,
        mut input: types::PutLogAlarmInput,
    ) -> Result<(), ServiceError> {
        let tags = input.tags.take().unwrap_or_default();
        self.authorize_alarm(ctx, "PutLogAlarm", &input.alarm_name, request_tag_conditions(&tags))?;
        self.observe(ctx);
        validate_tags(&tags)?;
        validate_actions(&[
            input.ok_actions.clone(),
            input.alarm_actions.clone(),
            input.insufficient_data_actions.clone(),
        ])?;
        validate_comparison(&input.comparison_operator, false)?;
        if input.query_results_to_alarm > input.query_results_to_evaluate {
            return Err(errors::validation(
                "QueryResultsToAlarm must be less than or equal to QueryResultsToEvaluate.",
            ));
        }
        let q = &input.scheduled_query_configuration;
        if mws_events::schedule::Schedule::parse(&q.schedule_configuration.schedule_expression).is_none() {
            return Err(errors::validation(format!(
                "Invalid schedule expression: {}",
                q.schedule_configuration.schedule_expression
            )));
        }
        if mws_logs::insights::parse(&q.query_string).is_err() {
            return Err(errors::validation("The query string of the scheduled query is not valid."));
        }
        if let Some(t) = &input.treat_missing_data {
            if !TREAT_MISSING.contains(&t.as_str()) {
                return Err(errors::validation(format!(
                    "The value {t} for parameter TreatMissingData is not supported."
                )));
            }
        }
        let name = input.alarm_name.clone();
        self.save_alarm(ctx, &name, "LogAlarm", tags, |a| a.log = Some(input))
    }

    pub(crate) fn describe_alarms(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAlarmsInput,
    ) -> Result<types::DescribeAlarmsOutput, ServiceError> {
        ctx.authorize("cloudwatch:DescribeAlarms", &alarm_arn(ctx, "*"), ConditionContext::new())?;
        self.observe(ctx);
        if input.alarm_names.is_some() && input.alarm_name_prefix.is_some() {
            return Err(errors::invalid_parameter_combination(
                "The parameters AlarmNames and AlarmNamePrefix are mutually exclusive and you have specified both.",
            ));
        }
        if input.children_of_alarm_name.is_some() && input.parents_of_alarm_name.is_some() {
            return Err(errors::invalid_parameter_combination(
                "The parameters ChildrenOfAlarmName and ParentsOfAlarmName are mutually exclusive and you have specified both.",
            ));
        }
        let family = input.children_of_alarm_name.is_some() || input.parents_of_alarm_name.is_some();
        if family
            && (input.alarm_names.is_some()
                || input.alarm_name_prefix.is_some()
                || input.state_value.is_some()
                || input.action_prefix.is_some())
        {
            let which =
                if input.children_of_alarm_name.is_some() { "ChildrenOfAlarmName" } else { "ParentsOfAlarmName" };
            return Err(errors::validation(format!(
                "If {which} is specified, no other parameters except MaxRecords and NextToken can be specified."
            )));
        }
        // Children are metric and composite alarms, parents composite
        // alarms, whatever AlarmTypes would default to. (AlarmTypes is
        // tolerated here, as SDK callers commonly pass it.)
        let types_wanted = if family && input.alarm_types.is_none() {
            vec!["MetricAlarm".to_string(), "CompositeAlarm".to_string()]
        } else {
            input.alarm_types.clone().unwrap_or_else(|| vec!["MetricAlarm".to_string()])
        };
        let st = self.lock();
        let mut found: Vec<Alarm> = Vec::new();
        if let Some(r) = st.region_ref(&ctx.caller.account_id, &ctx.region) {
            let children: Option<Vec<String>> = input.children_of_alarm_name.as_ref().map(|n| {
                r.alarms
                    .get(n)
                    .and_then(|a| a.composite.as_ref())
                    .and_then(|c| Rule::parse(&c.alarm_rule).ok())
                    .map(|rule| rule.alarms())
                    .unwrap_or_default()
            });
            for a in r.alarms.values() {
                if !types_wanted.contains(&a.alarm_type) {
                    continue;
                }
                let name = a.name();
                if input.alarm_names.as_ref().is_some_and(|ns| !ns.iter().any(|n| n == name))
                    || input.alarm_name_prefix.as_ref().is_some_and(|p| !name.starts_with(p.as_str()))
                    || input.state_value.as_ref().is_some_and(|s| s != &a.state_value)
                {
                    continue;
                }
                if let Some(prefix) = &input.action_prefix {
                    let (ok, alarm, ins) = a.actions();
                    if !ok.iter().chain(&alarm).chain(&ins).any(|x| x.starts_with(prefix.as_str())) {
                        continue;
                    }
                }
                if let Some(c) = &children {
                    if !c.iter().any(|x| x == name) {
                        continue;
                    }
                }
                if let Some(child) = &input.parents_of_alarm_name {
                    let parent = a
                        .composite
                        .as_ref()
                        .and_then(|c| Rule::parse(&c.alarm_rule).ok())
                        .is_some_and(|rule| rule.alarms().iter().any(|x| x == child));
                    if !parent {
                        continue;
                    }
                }
                found.push(a.clone());
            }
        }
        drop(st);
        let size = input.max_records.unwrap_or(50).clamp(1, 100) as usize;
        let (page, next_token) = names::page(found, input.next_token.as_deref(), size)?;
        let mut out = types::DescribeAlarmsOutput { next_token, ..Default::default() };
        let (mut metric, mut composite, mut log) = (Vec::new(), Vec::new(), Vec::new());
        for a in &page {
            match a.alarm_type.as_str() {
                "CompositeAlarm" => composite.push(composite_out(a)),
                "LogAlarm" => log.push(log_out(a)),
                _ => metric.push(metric_out(a)),
            }
        }
        out.metric_alarms = Some(metric);
        out.composite_alarms = Some(composite);
        if types_wanted.iter().any(|t| t == "LogAlarm") {
            out.log_alarms = Some(log);
        }
        Ok(out)
    }

    pub(crate) fn describe_alarms_for_metric(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAlarmsForMetricInput,
    ) -> Result<types::DescribeAlarmsForMetricOutput, ServiceError> {
        ctx.authorize("cloudwatch:DescribeAlarmsForMetric", &names::any(ctx), ConditionContext::new())?;
        let want = crate::state::MetricKey::new(&input.namespace, &input.metric_name, input.dimensions.as_deref());
        let st = self.lock();
        let mut out = Vec::new();
        if let Some(r) = st.region_ref(&ctx.caller.account_id, &ctx.region) {
            for a in r.alarms.values() {
                let Some(m) = &a.metric else { continue };
                #[allow(clippy::type_complexity)]
                let keys: Vec<(crate::state::MetricKey, Option<String>, Option<i32>, Option<String>)> =
                    match (&m.metric_name, &m.metrics) {
                        (Some(n), _) => vec![(
                            crate::state::MetricKey::new(
                                m.namespace.as_deref().unwrap_or_default(),
                                n,
                                m.dimensions.as_deref(),
                            ),
                            m.statistic.clone().or(m.extended_statistic.clone()),
                            m.period,
                            m.unit.clone(),
                        )],
                        // Not alarms on metric math that uses the metric.
                        _ => Vec::new(),
                    };
                let hit = keys.iter().any(|(k, stat, period, unit)| {
                    k == &want
                        && input.statistic.as_ref().is_none_or(|s| stat.as_ref() == Some(s))
                        && input.extended_statistic.as_ref().is_none_or(|s| stat.as_ref() == Some(s))
                        && input.period.is_none_or(|p| *period == Some(p))
                        && input.unit.as_ref().is_none_or(|u| unit.as_ref() == Some(u))
                });
                if hit {
                    out.push(metric_out(a));
                }
            }
        }
        Ok(types::DescribeAlarmsForMetricOutput { metric_alarms: Some(out) })
    }

    pub(crate) fn delete_alarms(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAlarmsInput,
    ) -> Result<(), ServiceError> {
        for n in &input.alarm_names {
            self.authorize_alarm(ctx, "DeleteAlarms", n, ConditionContext::new())?;
        }
        if input.alarm_names.len() > 100 {
            return Err(errors::validation("The collection AlarmNames must not have a size greater than 100."));
        }
        let now = now(ctx);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let kind = |n: &String| region.alarms.get(n.as_str()).map(|a| a.alarm_type.as_str());
        if input.alarm_names.iter().filter(|n| kind(n) == Some("CompositeAlarm")).count() > 1 {
            return Err(errors::validation("You can delete at most one composite alarm in one DeleteAlarms call."));
        }
        if input.alarm_names.len() > 1 && input.alarm_names.iter().any(|n| kind(n) == Some("LogAlarm")) {
            return Err(errors::validation("Log alarms cannot be deleted in a batch. Delete one log alarm per call."));
        }
        // Incorrect names do not stop the correct ones from being deleted.
        let missing: Vec<String> =
            input.alarm_names.iter().filter(|n| !region.alarms.contains_key(n.as_str())).cloned().collect();
        // An alarm a remaining composite alarm's rule names cannot go.
        for n in &input.alarm_names {
            let parent = region.alarms.values().find(|a| {
                !input.alarm_names.iter().any(|d| d == a.name())
                    && a.composite
                        .as_ref()
                        .and_then(|c| Rule::parse(&c.alarm_rule).ok())
                        .is_some_and(|r| r.alarms().contains(n))
            });
            if let Some(p) = parent {
                return Err(errors::resource_conflict(format!(
                    "Alarm {n} cannot be deleted because it is used in the rule of composite alarm {}.",
                    p.name()
                )));
            }
        }
        for n in &input.alarm_names {
            if let Some(a) = region.alarms.remove(n) {
                region.tags.remove(&a.arn);
                let data = json!({"version": "1.0", "type": "Delete", "deletedAlarm": self.alarm_json(&a)});
                push_history(region, config_history(&a, "deleted", now, data));
            }
        }
        if !missing.is_empty() {
            return Err(errors::resource_not_found(format!(
                "{} alarm{} not found: [{}]",
                missing.len(),
                if missing.len() == 1 { "" } else { "s" },
                missing.join(", ")
            )));
        }
        Ok(())
    }

    fn set_actions(
        &self,
        ctx: &RequestContext,
        action: &str,
        names: &[String],
        enabled: bool,
    ) -> Result<(), ServiceError> {
        for n in names {
            self.authorize_alarm(ctx, action, n, ConditionContext::new())?;
        }
        let now = now(ctx);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        for n in names {
            if let Some(a) = region.alarms.get_mut(n) {
                if a.actions_enabled() == enabled {
                    continue;
                }
                a.set_actions_enabled(enabled);
                a.config_updated = now;
                let snapshot = a.clone();
                let data = json!({"version": "1.0", "type": "Update", "updatedAlarm": self.alarm_json(&snapshot)});
                push_history(region, config_history(&snapshot, "updated", now, data));
            }
        }
        Ok(())
    }

    pub(crate) fn enable_alarm_actions(
        &self,
        ctx: &RequestContext,
        input: types::EnableAlarmActionsInput,
    ) -> Result<(), ServiceError> {
        self.set_actions(ctx, "EnableAlarmActions", &input.alarm_names, true)
    }

    pub(crate) fn disable_alarm_actions(
        &self,
        ctx: &RequestContext,
        input: types::DisableAlarmActionsInput,
    ) -> Result<(), ServiceError> {
        self.set_actions(ctx, "DisableAlarmActions", &input.alarm_names, false)
    }

    pub(crate) fn set_alarm_state(
        &self,
        ctx: &RequestContext,
        input: types::SetAlarmStateInput,
    ) -> Result<(), ServiceError> {
        self.authorize_alarm(ctx, "SetAlarmState", &input.alarm_name, ConditionContext::new())?;
        self.observe(ctx);
        if !STATES.contains(&input.state_value.as_str()) {
            return Err(errors::validation(format!(
                "The value {} for parameter StateValue is not valid.",
                input.state_value
            )));
        }
        if let Some(d) = &input.state_reason_data {
            if serde_json::from_str::<serde_json::Value>(d).map(|v| !v.is_object()).unwrap_or(true) {
                return Err(errors::invalid_format_fault("The value of StateReasonData must be valid JSON."));
            }
        }
        let now = now(ctx);
        let transitions: Vec<Transition> = {
            let mut st = self.lock();
            let region = st.region(&ctx.caller.account_id, &ctx.region);
            if !region.alarms.contains_key(&input.alarm_name) {
                return Err(errors::resource_not_found(format!("Alarm {} not found", input.alarm_name)));
            }
            // The state holds until the alarm's next evaluation.
            let puts = region.puts;
            if let Some(a) = region.alarms.get_mut(&input.alarm_name) {
                if a.alarm_type == "MetricAlarm" {
                    a.last_evaluated = Some(now);
                    a.seen_puts = puts;
                }
            }
            let mut out = Vec::new();
            if let Some(t) = crate::evaluate::transition(
                region,
                &ctx.caller.account_id,
                &ctx.region,
                &input.alarm_name,
                &input.state_value,
                &input.state_reason,
                input.state_reason_data.clone(),
                now,
            ) {
                out.push(t);
            }
            out.extend(crate::evaluate::cascade_composites(region, &ctx.caller.account_id, &ctx.region, now));
            out
        };
        self.run_transitions(ctx, transitions);
        Ok(())
    }

    pub(crate) fn describe_alarm_history(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAlarmHistoryInput,
    ) -> Result<types::DescribeAlarmHistoryOutput, ServiceError> {
        let resource = alarm_arn(ctx, input.alarm_name.as_deref().unwrap_or("*"));
        ctx.authorize("cloudwatch:DescribeAlarmHistory", &resource, ConditionContext::new())?;
        let st = self.lock();
        let mut items: Vec<types::AlarmHistoryItem> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.history
                    .iter()
                    .filter(|h| {
                        input.alarm_name.as_ref().is_none_or(|n| h.alarm_name.as_ref() == Some(n))
                            && input
                                .alarm_contributor_id
                                .as_ref()
                                .is_none_or(|c| h.alarm_contributor_id.as_ref() == Some(c))
                            && input.history_item_type.as_ref().is_none_or(|t| h.history_item_type.as_ref() == Some(t))
                            && h.alarm_type.as_ref().is_some_and(|t| match &input.alarm_types {
                                Some(ts) => ts.contains(t),
                                // Metric alarms only, unless AlarmTypes asks.
                                None => t == "MetricAlarm",
                            })
                            && input.start_date.is_none_or(|s| h.timestamp.is_some_and(|t| t >= s))
                            && input.end_date.is_none_or(|e| h.timestamp.is_some_and(|t| t <= e))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        drop(st);
        if input.scan_by.as_deref() != Some("TimestampAscending") {
            items.reverse();
        }
        let size = input.max_records.unwrap_or(100).clamp(1, 100) as usize;
        let (page, next_token) = names::page(items, input.next_token.as_deref(), size)?;
        Ok(types::DescribeAlarmHistoryOutput { alarm_history_items: Some(page), next_token })
    }

    pub(crate) fn describe_alarm_contributors(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAlarmContributorsInput,
    ) -> Result<types::DescribeAlarmContributorsOutput, ServiceError> {
        self.authorize_alarm(ctx, "DescribeAlarmContributors", &input.alarm_name, ConditionContext::new())?;
        let st = self.lock();
        let a = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.alarms.get(&input.alarm_name))
            .ok_or_else(|| errors::resource_not_found_exception(format!("Alarm {} not found", input.alarm_name)))?;
        let all: Vec<types::AlarmContributor> = a
            .contributors
            .iter()
            .filter(|(_, c)| c.state_value == "ALARM")
            .map(|(id, c)| types::AlarmContributor {
                contributor_id: id.clone(),
                contributor_attributes: c.attributes.clone(),
                state_reason: c.state_reason.clone(),
                state_transitioned_timestamp: c.transitioned,
            })
            .collect();
        drop(st);
        let (page, next_token) = names::page(all, input.next_token.as_deref(), 100)?;
        Ok(types::DescribeAlarmContributorsOutput { alarm_contributors: page, next_token })
    }
}

pub(crate) fn metric_out(a: &Alarm) -> types::MetricAlarm {
    let m = a.metric.clone().unwrap_or_default();
    types::MetricAlarm {
        alarm_name: Some(m.alarm_name),
        alarm_arn: Some(a.arn.clone()),
        alarm_description: m.alarm_description,
        alarm_configuration_updated_timestamp: Some(a.config_updated),
        actions_enabled: Some(m.actions_enabled.unwrap_or(true)),
        ok_actions: Some(m.ok_actions.unwrap_or_default()),
        alarm_actions: Some(m.alarm_actions.unwrap_or_default()),
        insufficient_data_actions: Some(m.insufficient_data_actions.unwrap_or_default()),
        state_value: Some(a.state_value.clone()),
        state_reason: Some(a.state_reason.clone()),
        state_reason_data: a.state_reason_data.clone(),
        state_updated_timestamp: Some(a.state_updated),
        metric_name: m.metric_name,
        namespace: m.namespace,
        statistic: m.statistic,
        extended_statistic: m.extended_statistic,
        dimensions: Some(m.dimensions.unwrap_or_default()),
        period: m.period,
        unit: m.unit,
        evaluation_periods: m.evaluation_periods,
        datapoints_to_alarm: m.datapoints_to_alarm,
        threshold: m.threshold,
        comparison_operator: m.comparison_operator,
        treat_missing_data: m.treat_missing_data,
        evaluate_low_sample_count_percentile: m.evaluate_low_sample_count_percentile,
        metrics: m.metrics,
        threshold_metric_id: m.threshold_metric_id,
        evaluation_state: a.evaluation_state.clone(),
        state_transitioned_timestamp: Some(a.state_transitioned),
        evaluation_window: m.evaluation_window,
        warm_up_configuration: m.warm_up_configuration,
        evaluation_criteria: m.evaluation_criteria,
        evaluation_interval: m.evaluation_interval,
        action_configuration: m.action_configuration,
    }
}

pub(crate) fn composite_out(a: &Alarm) -> types::CompositeAlarm {
    let c = a.composite.clone().unwrap_or_default();
    types::CompositeAlarm {
        actions_enabled: Some(c.actions_enabled.unwrap_or(true)),
        alarm_actions: Some(c.alarm_actions.unwrap_or_default()),
        alarm_arn: Some(a.arn.clone()),
        alarm_configuration_updated_timestamp: Some(a.config_updated),
        alarm_description: c.alarm_description,
        alarm_name: Some(c.alarm_name),
        alarm_rule: Some(c.alarm_rule),
        insufficient_data_actions: Some(c.insufficient_data_actions.unwrap_or_default()),
        ok_actions: Some(c.ok_actions.unwrap_or_default()),
        state_reason: Some(a.state_reason.clone()),
        state_reason_data: a.state_reason_data.clone(),
        state_updated_timestamp: Some(a.state_updated),
        state_value: Some(a.state_value.clone()),
        state_transitioned_timestamp: Some(a.state_transitioned),
        actions_suppressed_by: a.actions_suppressed_by.clone(),
        actions_suppressed_reason: a.actions_suppressed_reason.clone(),
        actions_suppressor: c.actions_suppressor,
        actions_suppressor_wait_period: c.actions_suppressor_wait_period,
        actions_suppressor_extension_period: c.actions_suppressor_extension_period,
        action_configuration: c.action_configuration,
    }
}

pub(crate) fn log_out(a: &Alarm) -> types::LogAlarm {
    let l = a.log.clone().unwrap_or_default();
    types::LogAlarm {
        alarm_name: Some(l.alarm_name),
        alarm_arn: Some(a.arn.clone()),
        alarm_description: l.alarm_description,
        alarm_configuration_updated_timestamp: Some(a.config_updated),
        actions_enabled: Some(l.actions_enabled.unwrap_or(true)),
        ok_actions: Some(l.ok_actions.unwrap_or_default()),
        alarm_actions: Some(l.alarm_actions.unwrap_or_default()),
        insufficient_data_actions: Some(l.insufficient_data_actions.unwrap_or_default()),
        state_value: Some(a.state_value.clone()),
        state_reason: Some(a.state_reason.clone()),
        state_reason_data: a.state_reason_data.clone(),
        state_updated_timestamp: Some(a.state_updated),
        scheduled_query_configuration: Some(l.scheduled_query_configuration),
        query_results_to_evaluate: Some(l.query_results_to_evaluate),
        query_results_to_alarm: Some(l.query_results_to_alarm),
        threshold: Some(l.threshold),
        comparison_operator: Some(l.comparison_operator),
        treat_missing_data: l.treat_missing_data,
        state_transitioned_timestamp: Some(a.state_transitioned),
        evaluation_state: a.evaluation_state.clone(),
        action_log_line_count: l.action_log_line_count,
        action_log_line_role_arn: l.action_log_line_role_arn,
        warm_up_configuration: l.warm_up_configuration,
        action_configuration: l.action_configuration,
    }
}

pub(crate) fn history_ts(t: DateTime<Utc>) -> String {
    history_time(t)
}
