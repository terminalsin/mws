//! `PutMetricData`, `ListMetrics` and `GetMetricStatistics`, and the
//! period bucketing the other read paths (metric math, alarms) share.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{self, now};
use crate::state::{MetricKey, Region, Sample, Series, StatSet};
use crate::stats::{Agg, Stat};
use crate::CloudWatch;

const MAX_DIMENSIONS: usize = 30;
const MAX_VALUES: usize = 150;
const MAX_DATAPOINTS: i64 = 1440;
/// Values CloudWatch accepts: magnitudes in (2^-260, 2^360), or zero.
const MAX_MAGNITUDE: f64 = 2.348_542_582_773_833_3e108;
const MIN_MAGNITUDE: f64 = 5.397_605_346_934_028e-79;
/// Raw data is kept for 15 months.
const RETENTION_DAYS: i64 = 455;

fn valid_value(v: f64) -> bool {
    v.is_finite() && (v == 0.0 || (v.abs() < MAX_MAGNITUDE && v.abs() > MIN_MAGNITUDE))
}

fn fmt_value(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else {
        format!("{v}")
    }
}

/// Validate one datum and turn it into a stored sample.
fn sample(d: &types::MetricDatum, at: &str, now: DateTime<Utc>) -> Result<Sample, ServiceError> {
    if d.value.is_some() && d.statistic_values.is_some() {
        return Err(errors::invalid_parameter_combination(format!(
            "The parameters {at}.Value and {at}.StatisticValues are mutually exclusive and you have specified both."
        )));
    }
    if d.value.is_some() && d.values.is_some() {
        return Err(errors::invalid_parameter_combination(format!(
            "The parameters {at}.Value and {at}.Values are mutually exclusive and you have specified both."
        )));
    }
    if d.statistic_values.is_some() && d.values.is_some() {
        return Err(errors::invalid_parameter_combination(format!(
            "The parameters {at}.StatisticValues and {at}.Values are mutually exclusive and you have specified both."
        )));
    }
    if d.counts.is_some() && d.values.is_none() {
        return Err(errors::invalid_parameter_combination(format!(
            "The parameter {at}.Counts must be specified with {at}.Values."
        )));
    }
    if d.dimensions.as_ref().is_some_and(|ds| ds.len() > MAX_DIMENSIONS) {
        return Err(errors::invalid_parameter_value(format!(
            "The collection {at}.Dimensions must not have a size greater than {MAX_DIMENSIONS}."
        )));
    }
    let resolution = d.storage_resolution.unwrap_or(60);
    if resolution != 1 && resolution != 60 {
        return Err(errors::invalid_parameter_value(format!(
            "The value {resolution} for parameter {at}.StorageResolution is invalid."
        )));
    }
    let t = d.timestamp.unwrap_or(now);
    if t < now - Duration::days(14) {
        return Err(errors::invalid_parameter_value(format!(
            "The parameter {at}.Timestamp must specify a time within the past two weeks."
        )));
    }
    if t > now + Duration::hours(2) {
        return Err(errors::invalid_parameter_value(format!(
            "The parameter {at}.Timestamp must specify a time no more than two hours in the future."
        )));
    }
    let unit = d.unit.clone().unwrap_or_else(|| "None".into());
    let mut s = Sample { t, unit, resolution, values: Vec::new(), stats: None };
    if let Some(v) = d.value {
        if !valid_value(v) {
            return Err(errors::invalid_parameter_value(format!(
                "The value {} for parameter {at}.Value is invalid.",
                fmt_value(v)
            )));
        }
        s.values.push((v, 1.0));
    } else if let Some(st) = &d.statistic_values {
        for (name, v) in
            [("SampleCount", st.sample_count), ("Sum", st.sum), ("Minimum", st.minimum), ("Maximum", st.maximum)]
        {
            if !valid_value(v) {
                return Err(errors::invalid_parameter_value(format!(
                    "The value {} for parameter {at}.StatisticValues.{name} is invalid.",
                    fmt_value(v)
                )));
            }
        }
        if st.sample_count <= 0.0 {
            return Err(errors::invalid_parameter_value(format!(
                "The value {} for parameter {at}.StatisticValues.SampleCount is invalid.",
                fmt_value(st.sample_count)
            )));
        }
        if st.minimum > st.maximum {
            return Err(errors::invalid_parameter_combination(format!(
                "The parameter {at}.StatisticValues.Maximum must be greater than {at}.StatisticValues.Minimum."
            )));
        }
        s.stats = Some(StatSet { count: st.sample_count, sum: st.sum, min: st.minimum, max: st.maximum });
    } else if let Some(values) = &d.values {
        if values.len() > MAX_VALUES {
            return Err(errors::invalid_parameter_value(format!(
                "The collection {at}.Values must not have a size greater than {MAX_VALUES}."
            )));
        }
        let counts = match &d.counts {
            Some(c) if c.len() != values.len() => {
                return Err(errors::invalid_parameter_value(format!(
                    "The parameters {at}.Values and {at}.Counts must be of the same size."
                )));
            }
            Some(c) => c.clone(),
            None => vec![1.0; values.len()],
        };
        for (i, (v, c)) in values.iter().zip(&counts).enumerate() {
            if !valid_value(*v) {
                return Err(errors::invalid_parameter_value(format!(
                    "The value {} for parameter {at}.Values.member.{} is invalid.",
                    fmt_value(*v),
                    i + 1
                )));
            }
            if !c.is_finite() || *c < 0.0 {
                return Err(errors::invalid_parameter_value(format!(
                    "The value {} for parameter {at}.Counts.member.{} is invalid.",
                    fmt_value(*c),
                    i + 1
                )));
            }
            if *c > 0.0 {
                s.values.push((*v, *c));
            }
        }
    } else {
        return Err(errors::invalid_parameter_combination(format!(
            "At least one of the parameters {at}.Value, {at}.StatisticValues, or {at}.Values must be specified."
        )));
    }
    Ok(s)
}

/// Store samples for `key`.
pub(crate) fn record(region: &mut Region, key: MetricKey, samples: Vec<Sample>, now: DateTime<Utc>) {
    let series = region.metrics.entry(key.key()).or_insert_with(|| Series { key, ..Series::default() });
    for s in samples {
        let at = series.samples.partition_point(|x| x.t <= s.t);
        series.samples.insert(at, s);
    }
    let cutoff = now - Duration::days(RETENTION_DAYS);
    let old = series.samples.partition_point(|x| x.t < cutoff);
    series.samples.drain(..old);
    series.last_put = Some(now);
}

fn validate_namespace(ns: &str, service: bool) -> Result<(), ServiceError> {
    if !service && ns.starts_with("AWS/") {
        return Err(errors::invalid_parameter_value(format!("The value {ns} for parameter Namespace is invalid.")));
    }
    if ns.starts_with(':') || !ns.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Err(errors::invalid_parameter_value(format!("The value {ns} for parameter Namespace is invalid.")));
    }
    Ok(())
}

/// The first period start at or before `t` for `period` seconds: whole
/// minutes for periods of a minute or more, whole periods below.
pub fn align(t: DateTime<Utc>, period: i64) -> DateTime<Utc> {
    let g = if period >= 60 { 60 } else { period.max(1) };
    let s = t.timestamp().div_euclid(g) * g;
    DateTime::from_timestamp(s, 0).unwrap_or(t)
}

/// Period starts from `start` (aligned) up to `end`.
pub fn buckets(start: DateTime<Utc>, end: DateTime<Utc>, period: i64) -> Vec<DateTime<Utc>> {
    let mut out = Vec::new();
    let mut t = align(start, period);
    let step = Duration::seconds(period.max(1));
    while t < end && out.len() < 100_100 {
        out.push(t);
        t += step;
    }
    out
}

/// A series's samples in `[from, to)`, of `unit` when given.
pub fn samples_in<'a>(
    series: &'a Series,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    unit: Option<&'a str>,
) -> impl Iterator<Item = &'a Sample> + 'a {
    let lo = series.samples.partition_point(|s| s.t < from);
    let hi = series.samples.partition_point(|s| s.t < to);
    series.samples[lo..hi].iter().filter(move |s| unit.is_none_or(|u| s.unit == u))
}

/// The aggregate of each period of `series` with data.
pub fn aggregates(
    series: &Series,
    starts: &[DateTime<Utc>],
    period: i64,
    unit: Option<&str>,
) -> Vec<(DateTime<Utc>, Agg)> {
    let step = Duration::seconds(period);
    starts.iter().filter_map(|b| Agg::of(samples_in(series, *b, *b + step, unit)).map(|a| (*b, a))).collect()
}

pub fn valid_period(period: i64) -> bool {
    matches!(period, 1 | 5 | 10 | 20 | 30) || (period > 0 && period % 60 == 0)
}

impl CloudWatch {
    pub(crate) fn put_metric_data(
        &self,
        ctx: &RequestContext,
        input: types::PutMetricDataInput,
    ) -> Result<(), ServiceError> {
        let mut cond = ConditionContext::new();
        cond.insert("cloudwatch:namespace".into(), vec![input.namespace.clone()]);
        ctx.authorize("cloudwatch:PutMetricData", &names::any(ctx), cond)?;
        self.observe(ctx);
        validate_namespace(&input.namespace, false)?;
        let now = now(ctx);
        let data = input.metric_data.unwrap_or_default();
        let entity = input.entity_metric_data.unwrap_or_default();
        if data.is_empty() && entity.is_empty() {
            return Err(errors::missing_required_parameter(
                "At least one of the parameters MetricData or EntityMetricData must be specified.",
            ));
        }
        if data.len() > 1000 {
            return Err(errors::invalid_parameter_value(
                "The collection MetricData must not have a size greater than 1000.",
            ));
        }
        let mut batch = Vec::new();
        for (i, d) in data.iter().enumerate() {
            let s = sample(d, &format!("MetricData.member.{}", i + 1), now)?;
            batch.push((MetricKey::new(&input.namespace, &d.metric_name, d.dimensions.as_deref()), s));
        }
        for (i, e) in entity.iter().enumerate() {
            if input.strict_entity_validation == Some(true) {
                let has_keys =
                    e.entity.as_ref().and_then(|x| x.key_attributes.as_ref()).is_some_and(|k| k.contains_key("Type"));
                if !has_keys {
                    return Err(errors::invalid_parameter_value(format!(
                        "The parameter EntityMetricData.member.{}.Entity.KeyAttributes must contain the key Type.",
                        i + 1
                    )));
                }
            }
            for (j, d) in e.metric_data.iter().flatten().enumerate() {
                let s = sample(d, &format!("EntityMetricData.member.{}.MetricData.member.{}", i + 1, j + 1), now)?;
                batch.push((MetricKey::new(&input.namespace, &d.metric_name, d.dimensions.as_deref()), s));
            }
        }
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        for (k, s) in batch {
            record(region, k, vec![s], now);
        }
        Ok(())
    }

    pub(crate) fn list_metrics(
        &self,
        ctx: &RequestContext,
        input: types::ListMetricsInput,
    ) -> Result<types::ListMetricsOutput, ServiceError> {
        ctx.authorize("cloudwatch:ListMetrics", &names::any(ctx), ConditionContext::new())?;
        self.observe(ctx);
        let now = now(ctx);
        let filters = input.dimensions.unwrap_or_default();
        let recent = match input.recently_active.as_deref() {
            Some("PT3H") => Some(now - Duration::hours(3)),
            _ => None,
        };
        let account = input.owning_account.clone().unwrap_or_else(|| ctx.caller.account_id.clone());
        let st = self.lock();
        let mut out: Vec<types::Metric> = Vec::new();
        if let Some(r) = st.region_ref(&account, &ctx.region) {
            for s in r.metrics.values() {
                let k = &s.key;
                if input.namespace.as_ref().is_some_and(|n| n != &k.namespace)
                    || input.metric_name.as_ref().is_some_and(|n| n != &k.name)
                {
                    continue;
                }
                let dims_match = filters.iter().all(|f| {
                    k.dimensions.iter().any(|(n, v)| n == &f.name && f.value.as_ref().is_none_or(|fv| fv == v))
                });
                if !dims_match {
                    continue;
                }
                let latest = s.samples.last().map(|x| x.t).or(s.last_put);
                if latest.is_none_or(|t| t < now - Duration::days(14)) {
                    continue;
                }
                if let Some(since) = recent {
                    if s.last_put.is_none_or(|t| t < since) {
                        continue;
                    }
                }
                out.push(k.to_metric());
            }
        }
        drop(st);
        let (metrics, next_token) = names::page(out, input.next_token.as_deref(), 500)?;
        let owning_accounts =
            (input.include_linked_accounts == Some(true)).then(|| vec![account.clone(); metrics.len()]);
        Ok(types::ListMetricsOutput { metrics: Some(metrics), next_token, owning_accounts })
    }

    pub(crate) fn get_metric_statistics(
        &self,
        ctx: &RequestContext,
        input: types::GetMetricStatisticsInput,
    ) -> Result<types::GetMetricStatisticsOutput, ServiceError> {
        ctx.authorize("cloudwatch:GetMetricStatistics", &names::any(ctx), ConditionContext::new())?;
        self.observe(ctx);
        let statistics = input.statistics.clone().unwrap_or_default();
        let extended = input.extended_statistics.clone().unwrap_or_default();
        if statistics.is_empty() && extended.is_empty() {
            return Err(errors::invalid_parameter_combination("Must specify either Statistics or ExtendedStatistics"));
        }
        if !statistics.is_empty() && !extended.is_empty() {
            return Err(errors::invalid_parameter_combination(
                "Statistics and ExtendedStatistics are mutually exclusive",
            ));
        }
        if extended.len() > 10 {
            return Err(errors::invalid_parameter_value(
                "The collection ExtendedStatistics must not have a size greater than 10.",
            ));
        }
        for (i, e) in extended.iter().enumerate() {
            match Stat::parse(e) {
                Some(s) if !Stat::is_basic(e) && !matches!(s, Stat::SampleCount) => {}
                _ => {
                    return Err(errors::invalid_parameter_value(format!(
                        "The value {e} for parameter ExtendedStatistics.member.{} is not supported.",
                        i + 1
                    )));
                }
            }
        }
        let period = input.period as i64;
        if !valid_period(period) {
            return Err(errors::invalid_parameter_value("The parameter Period must be a multiple of 60."));
        }
        if input.start_time >= input.end_time {
            return Err(errors::invalid_parameter_value(
                "The parameter StartTime must be less than the parameter EndTime.",
            ));
        }
        let starts = buckets(input.start_time, input.end_time, period);
        let requested = starts.len() as i64 * (statistics.len() + extended.len()) as i64;
        if requested > MAX_DATAPOINTS {
            return Err(errors::invalid_parameter_combination(format!(
                "You have requested up to {} datapoints, which exceeds the limit of 1,440. You may reduce the datapoints requested by increasing Period, or decreasing the time range.",
                thousands(requested)
            )));
        }
        let key = MetricKey::new(&input.namespace, &input.metric_name, input.dimensions.as_deref());
        let st = self.lock();
        let series = st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.metrics.get(&key.key()));
        let mut datapoints = Vec::new();
        if let Some(series) = series {
            for (t, agg) in aggregates(series, &starts, period, input.unit.as_deref()) {
                let mut dp = types::Datapoint {
                    timestamp: Some(t),
                    unit: Some(input.unit.clone().or(agg.unit.clone()).unwrap_or_else(|| "None".into())),
                    ..Default::default()
                };
                for s in &statistics {
                    let v = agg.stat(s);
                    match s.as_str() {
                        "SampleCount" => dp.sample_count = v,
                        "Average" => dp.average = v,
                        "Sum" => dp.sum = v,
                        "Minimum" => dp.minimum = v,
                        "Maximum" => dp.maximum = v,
                        _ => {}
                    }
                }
                if !extended.is_empty() {
                    let mut m = BTreeMap::new();
                    for e in &extended {
                        if let Some(v) = agg.stat(e) {
                            m.insert(e.clone(), v);
                        }
                    }
                    dp.extended_statistics = Some(m);
                }
                datapoints.push(dp);
            }
        }
        Ok(types::GetMetricStatisticsOutput { label: Some(input.metric_name), datapoints: Some(datapoints) })
    }
}

fn thousands(n: i64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A metric another service publishes (CloudWatch Logs metric filters).
#[derive(Debug, Clone)]
pub struct ServiceMetric {
    pub account: String,
    pub region: String,
    pub namespace: String,
    pub metric_name: String,
    pub dimensions: Vec<(String, String)>,
    pub unit: Option<String>,
    pub timestamp: DateTime<Utc>,
    /// `(value, count)` pairs.
    pub values: Vec<(f64, f64)>,
}

impl CloudWatch {
    /// Store data an AWS service publishes into a customer's account (no
    /// caller to authorize). `AWS/` namespaces are allowed.
    pub fn put_metric_as_service(&self, m: ServiceMetric) {
        if m.values.is_empty() || validate_namespace(&m.namespace, true).is_err() {
            return;
        }
        let dims: Vec<types::Dimension> =
            m.dimensions.iter().map(|(n, v)| types::Dimension { name: n.clone(), value: v.clone() }).collect();
        let key = MetricKey::new(&m.namespace, &m.metric_name, Some(&dims));
        let s = Sample {
            t: m.timestamp,
            unit: m.unit.unwrap_or_else(|| "None".into()),
            resolution: 60,
            values: m.values.into_iter().filter(|(v, c)| valid_value(*v) && *c > 0.0).collect(),
            stats: None,
        };
        if s.values.is_empty() {
            return;
        }
        let now = self.clock_now();
        let mut st = self.lock();
        record(st.region(&m.account, &m.region), key, vec![s], now);
    }
}
