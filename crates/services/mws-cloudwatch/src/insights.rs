//! Contributor Insights: rules over log groups (`PutInsightRule`,
//! `DescribeInsightRules`, `EnableInsightRules`, `DisableInsightRules`,
//! `DeleteInsightRules`, managed rules) and `GetInsightRuleReport`, which
//! really analyses the log events: JSON or CLF events are filtered, keyed
//! by the rule's `Contribution.Keys`, and counted or summed per contributor
//! and period. Metric math's `INSIGHT_RULE_METRIC` reads the same numbers.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::generated::{errors, types};
use crate::math::Engine;
use crate::names::{self, insight_rule_arn, request_tag_conditions};
use crate::state::{InsightRule, Region};
use crate::CloudWatch;

const SCHEMA: &str = "CloudWatchLogRule/1";
const MAX_RULES: usize = 100;

#[derive(Debug, Clone)]
struct Filter {
    selector: String,
    test: Value,
}

#[derive(Debug, Clone)]
pub struct Definition {
    log_groups: Vec<String>,
    clf: bool,
    fields: BTreeMap<usize, String>,
    keys: Vec<String>,
    value_of: Option<String>,
    filters: Vec<Filter>,
    sum: bool,
}

fn bad(m: impl Into<String>) -> ServiceError {
    errors::invalid_parameter_value(m)
}

pub fn parse_definition(s: &str) -> Result<Definition, ServiceError> {
    let v: Value = serde_json::from_str(s).map_err(|_| bad("The rule definition is not valid JSON."))?;
    let schema = v.get("Schema").ok_or_else(|| bad("The rule definition must have a Schema."))?;
    if schema.get("Name").and_then(Value::as_str) != Some("CloudWatchLogRule") {
        return Err(bad("The rule definition Schema.Name must be CloudWatchLogRule."));
    }
    if schema.get("Version").and_then(Value::as_i64) != Some(1) {
        return Err(bad("The rule definition Schema.Version must be 1."));
    }
    let strings = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let mut log_groups = strings("LogGroupNames");
    log_groups.extend(strings("LogGroupARNs"));
    if log_groups.is_empty() {
        return Err(bad("The rule definition must name LogGroupNames or LogGroupARNs."));
    }
    let clf = match v.get("LogFormat").and_then(Value::as_str) {
        Some("JSON") => false,
        Some("CLF") => true,
        _ => return Err(bad("The rule definition LogFormat must be JSON or CLF.")),
    };
    let mut fields = BTreeMap::new();
    if let Some(f) = v.get("Fields").and_then(Value::as_object) {
        for (k, name) in f {
            let i: usize = k.parse().map_err(|_| bad(format!("Invalid field position {k} in the rule definition.")))?;
            fields.insert(i, name.as_str().unwrap_or_default().to_string());
        }
    }
    let c = v.get("Contribution").ok_or_else(|| bad("The rule definition must have a Contribution."))?;
    let keys: Vec<String> = c
        .get("Keys")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if keys.is_empty() || keys.len() > 4 {
        return Err(bad("The rule definition must have between 1 and 4 Contribution.Keys."));
    }
    let value_of = c.get("ValueOf").and_then(Value::as_str).map(str::to_string);
    let filters = c
        .get("Filters")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|f| {
                    let o = f.as_object()?;
                    let selector = o.get("Match")?.as_str()?.to_string();
                    let test = o.iter().find(|(k, _)| k.as_str() != "Match").map(|(k, v)| serde_json::json!({k: v}))?;
                    Some(Filter { selector, test })
                })
                .collect()
        })
        .unwrap_or_default();
    let sum = match v.get("AggregateOn").and_then(Value::as_str) {
        Some("Sum") => true,
        Some("Count") | None => false,
        Some(o) => return Err(bad(format!("Invalid AggregateOn value {o} in the rule definition."))),
    };
    if sum && value_of.is_none() {
        return Err(bad("A rule that aggregates on Sum must set Contribution.ValueOf."));
    }
    Ok(Definition { log_groups, clf, fields, keys, value_of, filters, sum })
}

fn select(def: &Definition, doc: &Value, clf_fields: &[String], selector: &str) -> Option<Value> {
    if def.clf {
        let pos = def.fields.iter().find(|(_, n)| n.as_str() == selector).map(|(i, _)| *i)?;
        return clf_fields.get(pos.checked_sub(1)?).map(|s| Value::String(s.clone()));
    }
    mws_logs::filter::select(doc, selector)
}

fn as_f64(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn passes(f: &Filter, v: Option<&Value>) -> bool {
    let Some((op, arg)) = f.test.as_object().and_then(|o| o.iter().next()) else { return true };
    let list = || arg.as_array().cloned().unwrap_or_else(|| vec![arg.clone()]);
    match op.as_str() {
        "IsPresent" => v.is_some() == arg.as_bool().unwrap_or(true),
        _ => {
            let Some(v) = v else { return false };
            match op.as_str() {
                "In" => list().iter().any(|x| as_text(x) == as_text(v)),
                "NotIn" => !list().iter().any(|x| as_text(x) == as_text(v)),
                "StartsWith" => list().iter().any(|x| as_text(v).starts_with(&as_text(x))),
                "EqualTo" => as_f64(v).zip(as_f64(arg)).is_some_and(|(a, b)| a == b),
                "NotEqualTo" => as_f64(v).zip(as_f64(arg)).is_some_and(|(a, b)| a != b),
                "GreaterThan" => as_f64(v).zip(as_f64(arg)).is_some_and(|(a, b)| a > b),
                "GreaterThanOrEqualTo" => as_f64(v).zip(as_f64(arg)).is_some_and(|(a, b)| a >= b),
                "LessThan" => as_f64(v).zip(as_f64(arg)).is_some_and(|(a, b)| a < b),
                "LessThanOrEqualTo" => as_f64(v).zip(as_f64(arg)).is_some_and(|(a, b)| a <= b),
                _ => false,
            }
        }
    }
}

/// One contributor's numbers.
#[derive(Debug, Clone, Default)]
pub struct ContributorData {
    pub total: f64,
    pub per_period: BTreeMap<i64, f64>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub contributors: BTreeMap<Vec<String>, ContributorData>,
    /// Per period: each event's value.
    pub samples: BTreeMap<i64, Vec<f64>>,
}

/// Analyse `events` (`(timestamp ms, message)`).
pub fn analyse(def: &Definition, events: &[(i64, String)], start: DateTime<Utc>, period: i64) -> Report {
    let mut r = Report::default();
    let origin = start.timestamp();
    for (ts, message) in events {
        let doc: Value = if def.clf { Value::Null } else { serde_json::from_str(message).unwrap_or(Value::Null) };
        if !def.clf && !doc.is_object() {
            continue;
        }
        let clf_fields = if def.clf { mws_logs::filter::split_fields(message) } else { Vec::new() };
        if !def.filters.iter().all(|f| passes(f, select(def, &doc, &clf_fields, &f.selector).as_ref())) {
            continue;
        }
        let keys: Option<Vec<String>> =
            def.keys.iter().map(|k| select(def, &doc, &clf_fields, k).map(|v| as_text(&v))).collect();
        let Some(keys) = keys else { continue };
        let value = match (&def.value_of, def.sum) {
            (Some(v), true) => match select(def, &doc, &clf_fields, v).as_ref().and_then(as_f64) {
                Some(x) => x,
                None => continue,
            },
            _ => 1.0,
        };
        let secs = ts.div_euclid(1000);
        let bucket = origin + (secs - origin).div_euclid(period.max(1)) * period.max(1);
        let c = r.contributors.entry(keys).or_default();
        c.total += value;
        *c.per_period.entry(bucket).or_default() += value;
        r.samples.entry(bucket).or_default().push(value);
    }
    r
}

impl Report {
    /// A rule metric (`UniqueContributors`, `MaxContributorValue`,
    /// `SampleCount`, `Sum`, `Minimum`, `Maximum`, `Average`) per period.
    pub fn metric(&self, name: &str) -> BTreeMap<i64, f64> {
        let mut out = BTreeMap::new();
        for (t, vals) in &self.samples {
            let v = match name {
                "UniqueContributors" => {
                    self.contributors.values().filter(|c| c.per_period.contains_key(t)).count() as f64
                }
                "MaxContributorValue" => self
                    .contributors
                    .values()
                    .filter_map(|c| c.per_period.get(t))
                    .copied()
                    .fold(f64::NEG_INFINITY, f64::max),
                "SampleCount" => vals.len() as f64,
                "Sum" => vals.iter().sum(),
                "Minimum" => vals.iter().copied().fold(f64::INFINITY, f64::min),
                "Maximum" => vals.iter().copied().fold(f64::NEG_INFINITY, f64::max),
                "Average" => vals.iter().sum::<f64>() / vals.len() as f64,
                _ => continue,
            };
            out.insert(*t, v);
        }
        out
    }
}

/// `INSIGHT_RULE_METRIC(rule, metric)` for metric math.
pub fn rule_metric(engine: &Engine<'_>, rule: &str, metric: &str, period: i64) -> BTreeMap<i64, f64> {
    let Some(r) = engine.region.and_then(|r| r.insight_rules.get(rule)) else { return BTreeMap::new() };
    let Some((logs, account, region)) = engine.logs else { return BTreeMap::new() };
    let Ok(def) = parse_definition(&r.definition) else { return BTreeMap::new() };
    let events: Vec<(i64, String)> = logs
        .events_as_service(
            account,
            region,
            &def.log_groups,
            engine.start.timestamp_millis(),
            engine.end.timestamp_millis() - 1,
        )
        .into_iter()
        .map(|(_, _, t, m)| (t, m))
        .collect();
    analyse(&def, &events, crate::metrics::align(engine.start, period), period).metric(metric)
}

fn failure(name: &str, description: &str) -> types::PartialFailure {
    types::PartialFailure {
        failure_resource: Some(name.to_string()),
        exception_type: Some("ResourceNotFoundException".into()),
        failure_code: Some("404".into()),
        failure_description: Some(description.to_string()),
    }
}

impl CloudWatch {
    pub(crate) fn put_insight_rule(
        &self,
        ctx: &RequestContext,
        input: types::PutInsightRuleInput,
    ) -> Result<types::PutInsightRuleOutput, ServiceError> {
        let arn = insight_rule_arn(ctx, &input.rule_name);
        let tags = input.tags.clone().unwrap_or_default();
        ctx.authorize("cloudwatch:PutInsightRule", &arn, request_tag_conditions(&tags))?;
        let state = input.rule_state.clone().unwrap_or_else(|| "ENABLED".into());
        if state != "ENABLED" && state != "DISABLED" {
            return Err(bad(format!("The value {state} for parameter RuleState is not valid.")));
        }
        if !input.rule_name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
            return Err(bad(format!("The value {} for parameter RuleName is not valid.", input.rule_name)));
        }
        parse_definition(&input.rule_definition)?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let created = !region.insight_rules.contains_key(&input.rule_name);
        if created && region.insight_rules.values().filter(|r| !r.managed).count() >= MAX_RULES {
            return Err(errors::limit_exceeded("The maximum number of Contributor Insights rules has been reached."));
        }
        if region.insight_rules.get(&input.rule_name).is_some_and(|r| r.managed) {
            return Err(bad(format!("The rule {} is a managed rule and cannot be modified.", input.rule_name)));
        }
        region.insight_rules.insert(
            input.rule_name.clone(),
            InsightRule {
                arn: arn.clone(),
                state,
                definition: input.rule_definition,
                managed: false,
                apply_on_transformed_logs: input.apply_on_transformed_logs,
                template_name: None,
                resource_arn: None,
            },
        );
        if created && !tags.is_empty() {
            region.tags.insert(arn, tags.into_iter().map(|t| (t.key, t.value)).collect());
        }
        Ok(types::PutInsightRuleOutput {})
    }

    pub(crate) fn describe_insight_rules(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInsightRulesInput,
    ) -> Result<types::DescribeInsightRulesOutput, ServiceError> {
        ctx.authorize("cloudwatch:DescribeInsightRules", &insight_rule_arn(ctx, "*"), ConditionContext::new())?;
        let st = self.lock();
        let rules: Vec<types::InsightRule> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.insight_rules
                    .iter()
                    .map(|(n, r)| types::InsightRule {
                        name: n.clone(),
                        state: r.state.clone(),
                        schema: SCHEMA.into(),
                        definition: r.definition.clone(),
                        managed_rule: Some(r.managed),
                        apply_on_transformed_logs: r.apply_on_transformed_logs,
                    })
                    .collect()
            })
            .unwrap_or_default();
        drop(st);
        let size = input.max_results.unwrap_or(500).clamp(1, 500) as usize;
        let (page, next_token) = names::page(rules, input.next_token.as_deref(), size)?;
        Ok(types::DescribeInsightRulesOutput { next_token, insight_rules: Some(page) })
    }

    fn change_rules(
        &self,
        ctx: &RequestContext,
        action: &str,
        names: &[String],
        change: impl Fn(&mut Region, &str) -> bool,
    ) -> Result<Vec<types::PartialFailure>, ServiceError> {
        for n in names {
            ctx.authorize(&format!("cloudwatch:{action}"), &insight_rule_arn(ctx, n), ConditionContext::new())?;
        }
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let mut failures = Vec::new();
        for n in names {
            if !change(region, n) {
                failures.push(failure(n, &format!("Rule {n} does not exist")));
            }
        }
        Ok(failures)
    }

    pub(crate) fn delete_insight_rules(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInsightRulesInput,
    ) -> Result<types::DeleteInsightRulesOutput, ServiceError> {
        let failures =
            self.change_rules(ctx, "DeleteInsightRules", &input.rule_names, |r, n| match r.insight_rules.remove(n) {
                Some(rule) => {
                    r.tags.remove(&rule.arn);
                    true
                }
                None => false,
            })?;
        Ok(types::DeleteInsightRulesOutput { failures: Some(failures) })
    }

    pub(crate) fn enable_insight_rules(
        &self,
        ctx: &RequestContext,
        input: types::EnableInsightRulesInput,
    ) -> Result<types::EnableInsightRulesOutput, ServiceError> {
        let failures = self.change_rules(ctx, "EnableInsightRules", &input.rule_names, |r, n| {
            r.insight_rules.get_mut(n).map(|x| x.state = "ENABLED".into()).is_some()
        })?;
        Ok(types::EnableInsightRulesOutput { failures: Some(failures) })
    }

    pub(crate) fn disable_insight_rules(
        &self,
        ctx: &RequestContext,
        input: types::DisableInsightRulesInput,
    ) -> Result<types::DisableInsightRulesOutput, ServiceError> {
        let failures = self.change_rules(ctx, "DisableInsightRules", &input.rule_names, |r, n| {
            r.insight_rules.get_mut(n).map(|x| x.state = "DISABLED".into()).is_some()
        })?;
        Ok(types::DisableInsightRulesOutput { failures: Some(failures) })
    }

    pub(crate) fn get_insight_rule_report(
        &self,
        ctx: &RequestContext,
        input: types::GetInsightRuleReportInput,
    ) -> Result<types::GetInsightRuleReportOutput, ServiceError> {
        ctx.authorize(
            "cloudwatch:GetInsightRuleReport",
            &insight_rule_arn(ctx, &input.rule_name),
            ConditionContext::new(),
        )?;
        if input.start_time >= input.end_time {
            return Err(bad("The parameter StartTime must be less than the parameter EndTime."));
        }
        let period = input.period as i64;
        if !crate::metrics::valid_period(period) {
            return Err(bad("The parameter Period must be a multiple of 60."));
        }
        const METRICS: &[&str] =
            &["UniqueContributors", "MaxContributorValue", "SampleCount", "Sum", "Minimum", "Maximum", "Average"];
        for m in input.metrics.iter().flatten() {
            if !METRICS.contains(&m.as_str()) {
                return Err(bad(format!("The value {m} for parameter Metrics is not valid.")));
            }
        }
        let order_by = input.order_by.clone().unwrap_or_else(|| "Sum".into());
        if order_by != "Sum" && order_by != "Maximum" {
            return Err(bad(format!("The value {order_by} for parameter OrderBy is not valid.")));
        }
        let def = {
            let st = self.lock();
            let r = st
                .region_ref(&ctx.caller.account_id, &ctx.region)
                .and_then(|r| r.insight_rules.get(&input.rule_name))
                .ok_or_else(|| {
                    errors::resource_not_found_exception(format!("Rule {} does not exist", input.rule_name))
                })?;
            parse_definition(&r.definition)?
        };
        let events: Vec<(i64, String)> = match self.inner.logs.get() {
            Some(logs) => logs
                .events_as_service(
                    &ctx.caller.account_id,
                    &ctx.region,
                    &def.log_groups,
                    input.start_time.timestamp_millis(),
                    input.end_time.timestamp_millis() - 1,
                )
                .into_iter()
                .map(|(_, _, t, m)| (t, m))
                .collect(),
            None => Vec::new(),
        };
        let start = crate::metrics::align(input.start_time, period);
        let report = analyse(&def, &events, start, period);
        let mut contributors: Vec<(&Vec<String>, &ContributorData)> = report.contributors.iter().collect();
        let max_of = |c: &ContributorData| c.per_period.values().copied().fold(f64::NEG_INFINITY, f64::max);
        if order_by == "Maximum" {
            contributors.sort_by(|a, b| max_of(b.1).total_cmp(&max_of(a.1)));
        } else {
            contributors.sort_by(|a, b| b.1.total.total_cmp(&a.1.total));
        }
        let limit = input.max_contributor_count.unwrap_or(10).clamp(1, 100) as usize;
        let out_contributors = contributors
            .iter()
            .take(limit)
            .map(|(keys, c)| types::InsightRuleContributor {
                keys: (*keys).clone(),
                approximate_aggregate_value: c.total,
                datapoints: c
                    .per_period
                    .iter()
                    .map(|(t, v)| types::InsightRuleContributorDatapoint {
                        timestamp: DateTime::from_timestamp(*t, 0).unwrap_or_default(),
                        approximate_value: *v,
                    })
                    .collect(),
            })
            .collect();
        let wanted = input.metrics.clone().unwrap_or_default();
        let metric_datapoints = (!wanted.is_empty()).then(|| {
            let per: BTreeMap<&str, BTreeMap<i64, f64>> =
                wanted.iter().map(|m| (m.as_str(), report.metric(m))).collect();
            report
                .samples
                .keys()
                .map(|t| {
                    let g = |name: &str| per.get(name).and_then(|m| m.get(t)).copied();
                    types::InsightRuleMetricDatapoint {
                        timestamp: DateTime::from_timestamp(*t, 0).unwrap_or_default(),
                        unique_contributors: g("UniqueContributors"),
                        max_contributor_value: g("MaxContributorValue"),
                        sample_count: g("SampleCount"),
                        average: g("Average"),
                        sum: g("Sum"),
                        minimum: g("Minimum"),
                        maximum: g("Maximum"),
                    }
                })
                .collect()
        });
        let _ = Duration::zero();
        Ok(types::GetInsightRuleReportOutput {
            key_labels: Some(def.keys.clone()),
            aggregation_statistic: Some(if def.sum { "Sum" } else { "Count" }.into()),
            aggregate_value: Some(report.contributors.values().map(|c| c.total).sum()),
            approximate_unique_count: Some(report.contributors.len() as i64),
            contributors: Some(out_contributors),
            metric_datapoints,
        })
    }

    pub(crate) fn put_managed_insight_rules(
        &self,
        ctx: &RequestContext,
        input: types::PutManagedInsightRulesInput,
    ) -> Result<types::PutManagedInsightRulesOutput, ServiceError> {
        for r in &input.managed_rules {
            let tags = r.tags.clone().unwrap_or_default();
            ctx.authorize(
                "cloudwatch:PutManagedInsightRules",
                &insight_rule_arn(ctx, "*"),
                request_tag_conditions(&tags),
            )?;
        }
        let mut failures = Vec::new();
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        for r in input.managed_rules {
            let Some(resource) = r.resource_arn.rsplit(['/', ':']).next().filter(|s| !s.is_empty()) else {
                failures.push(types::PartialFailure {
                    failure_resource: Some(r.resource_arn.clone()),
                    exception_type: Some("InvalidParameterValueException".into()),
                    failure_code: Some("400".into()),
                    failure_description: Some("The resource ARN is not valid.".into()),
                });
                continue;
            };
            let name = format!("{}-{resource}", r.template_name);
            let arn = insight_rule_arn(ctx, &name);
            let definition = serde_json::json!({
                "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
                "LogGroupNames": [format!("/aws/managed/{}", r.template_name)],
                "LogFormat": "JSON",
                "Contribution": {"Keys": ["$.key"]},
                "AggregateOn": "Count",
            })
            .to_string();
            region.insight_rules.insert(
                name,
                InsightRule {
                    arn: arn.clone(),
                    state: "ENABLED".into(),
                    definition,
                    managed: true,
                    apply_on_transformed_logs: None,
                    template_name: Some(r.template_name),
                    resource_arn: Some(r.resource_arn),
                },
            );
            if let Some(tags) = r.tags.filter(|t| !t.is_empty()) {
                region.tags.insert(arn, tags.into_iter().map(|t| (t.key, t.value)).collect());
            }
        }
        Ok(types::PutManagedInsightRulesOutput { failures: Some(failures) })
    }

    pub(crate) fn list_managed_insight_rules(
        &self,
        ctx: &RequestContext,
        input: types::ListManagedInsightRulesInput,
    ) -> Result<types::ListManagedInsightRulesOutput, ServiceError> {
        ctx.authorize("cloudwatch:ListManagedInsightRules", &input.resource_arn, ConditionContext::new())?;
        let st = self.lock();
        let rules: Vec<types::ManagedRuleDescription> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.insight_rules
                    .iter()
                    .filter(|(_, x)| x.managed && x.resource_arn.as_deref() == Some(input.resource_arn.as_str()))
                    .map(|(n, x)| types::ManagedRuleDescription {
                        template_name: x.template_name.clone(),
                        resource_arn: x.resource_arn.clone(),
                        rule_state: Some(types::ManagedRuleState { rule_name: n.clone(), state: x.state.clone() }),
                    })
                    .collect()
            })
            .unwrap_or_default();
        drop(st);
        let size = input.max_results.unwrap_or(100).clamp(1, 500) as usize;
        let (page, next_token) = names::page(rules, input.next_token.as_deref(), size)?;
        Ok(types::ListManagedInsightRulesOutput { managed_rules: Some(page), next_token })
    }
}
