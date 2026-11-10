//! Anomaly detection models (`PutAnomalyDetector`,
//! `DescribeAnomalyDetectors`, `DeleteAnomalyDetector`). The model itself
//! ([`crate::model`]) trains on the metric's history whenever
//! `ANOMALY_DETECTION_BAND` needs a band, with the detector's excluded time
//! ranges and time zone; a detector's `StateValue` follows how much history
//! there is to train on.

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::math::{Engine, Val};
use crate::names;
use crate::state::{MetricKey, Region};
use crate::stats::Stat;
use crate::CloudWatch;

const MAX_DETECTORS: usize = 500;

/// The detector a request names, in its `SingleMetricAnomalyDetector` /
/// `MetricMathAnomalyDetector` form.
fn normalize(
    namespace: Option<String>,
    metric_name: Option<String>,
    dimensions: Option<Vec<types::Dimension>>,
    stat: Option<String>,
    single: Option<types::SingleMetricAnomalyDetector>,
    math: Option<types::MetricMathAnomalyDetector>,
) -> Result<(Option<types::SingleMetricAnomalyDetector>, Option<types::MetricMathAnomalyDetector>), ServiceError> {
    let legacy = namespace.is_some() || metric_name.is_some() || dimensions.is_some() || stat.is_some();
    match (legacy, single, math) {
        (true, None, None) => Ok((
            Some(types::SingleMetricAnomalyDetector {
                account_id: None,
                namespace,
                metric_name,
                dimensions: Some(dimensions.unwrap_or_default()),
                stat,
            }),
            None,
        )),
        (false, Some(s), None) => Ok((Some(s), None)),
        (false, None, Some(m)) => Ok((None, Some(m))),
        (false, None, None) => Err(errors::missing_required_parameter(
            "One of SingleMetricAnomalyDetector or MetricMathAnomalyDetector must be specified.",
        )),
        _ => Err(errors::invalid_parameter_combination(
            "Exactly one of SingleMetricAnomalyDetector, MetricMathAnomalyDetector, or the legacy Namespace, MetricName, Dimensions and Stat parameters may be specified.",
        )),
    }
}

fn validate_single(s: &types::SingleMetricAnomalyDetector) -> Result<(), ServiceError> {
    let missing = |p: &str| errors::missing_required_parameter(format!("The parameter {p} is required."));
    let ns = s.namespace.as_deref().ok_or_else(|| missing("Namespace"))?;
    s.metric_name.as_deref().ok_or_else(|| missing("MetricName"))?;
    let stat = s.stat.as_deref().ok_or_else(|| missing("Stat"))?;
    if ns.is_empty() {
        return Err(errors::invalid_parameter_value("The parameter Namespace must not be empty."));
    }
    if Stat::parse(stat).is_none() {
        return Err(errors::invalid_parameter_value(format!("The value {stat} for parameter Stat is not valid.")));
    }
    if s.dimensions.as_ref().is_some_and(|d| d.len() > 30) {
        return Err(errors::invalid_parameter_value("The collection Dimensions must not have a size greater than 30."));
    }
    Ok(())
}

fn same_dimensions(a: Option<&[types::Dimension]>, b: Option<&[types::Dimension]>) -> bool {
    let norm = |d: Option<&[types::Dimension]>| MetricKey::new("", "", d).dimensions;
    norm(a) == norm(b)
}

pub(crate) fn same_single(a: &types::SingleMetricAnomalyDetector, b: &types::SingleMetricAnomalyDetector) -> bool {
    a.namespace == b.namespace
        && a.metric_name == b.metric_name
        && a.stat == b.stat
        && a.account_id == b.account_id
        && same_dimensions(a.dimensions.as_deref(), b.dimensions.as_deref())
}

fn matches(
    d: &types::AnomalyDetector,
    single: &Option<types::SingleMetricAnomalyDetector>,
    math: &Option<types::MetricMathAnomalyDetector>,
) -> bool {
    match (single, math, &d.single_metric_anomaly_detector, &d.metric_math_anomaly_detector) {
        (Some(a), None, Some(b), _) => same_single(a, b),
        (None, Some(a), _, Some(b)) => a == b,
        _ => false,
    }
}

/// How far a detector has trained, from the history a model would train
/// on now (two weeks, less the excluded time ranges, by minute):
/// `PENDING_TRAINING` without enough of it to train
/// ([`crate::model::MIN_TRAINING_POINTS`] datapoints), then
/// `TRAINED_INSUFFICIENT_DATA` while it covers less than a day, then
/// `TRAINED`.
fn state_value(region: Option<&Region>, d: &types::AnomalyDetector, now: DateTime<Utc>) -> String {
    let period = 60;
    let end = crate::metrics::align(now, period);
    let start = end - Duration::days(crate::model::TRAINING_DAYS);
    let points = match (&d.single_metric_anomaly_detector, &d.metric_math_anomaly_detector) {
        (Some(s), _) => {
            let key = MetricKey::new(
                s.namespace.as_deref().unwrap_or_default(),
                s.metric_name.as_deref().unwrap_or_default(),
                s.dimensions.as_deref(),
            );
            Engine::new(region, &[], start, end)
                .metric_series(&key, s.stat.as_deref().unwrap_or("Average"), period, None)
                .points
        }
        (None, Some(m)) => {
            let queries = m.metric_data_queries.clone().unwrap_or_default();
            let engine = Engine::new(region, &queries, start, end);
            match queries.iter().find(|q| q.return_data != Some(false)).map(|q| engine.eval(&q.id)) {
                Some(Ok(Val::Series(ts))) => ts.points,
                _ => Default::default(),
            }
        }
        _ => Default::default(),
    };
    let training = crate::model::Training::from_config(d.configuration.as_ref());
    let kept: Vec<i64> =
        points.keys().copied().filter(|t| !training.excluded.iter().any(|(s, e)| *t < *e && t + period > *s)).collect();
    match (kept.first(), kept.last()) {
        _ if kept.len() < crate::model::MIN_TRAINING_POINTS => "PENDING_TRAINING".into(),
        (Some(first), Some(last)) if last - first + period < 86_400 => "TRAINED_INSUFFICIENT_DATA".into(),
        _ => "TRAINED".into(),
    }
}

/// Create the single-metric detectors an `ANOMALY_DETECTION_BAND` used
/// without one, as CloudWatch does for alarms and graphs.
pub(crate) fn auto_create(region: &mut Region, wanted: Vec<types::SingleMetricAnomalyDetector>) {
    for s in wanted {
        let exists = region
            .anomaly_detectors
            .iter()
            .any(|d| d.single_metric_anomaly_detector.as_ref().is_some_and(|x| same_single(x, &s)));
        if exists || region.anomaly_detectors.len() >= MAX_DETECTORS {
            continue;
        }
        region.anomaly_detectors.push(types::AnomalyDetector {
            anomaly_detector_id: Some(uuid::Uuid::new_v4().to_string()),
            namespace: s.namespace.clone(),
            metric_name: s.metric_name.clone(),
            dimensions: s.dimensions.clone(),
            stat: s.stat.clone(),
            single_metric_anomaly_detector: Some(s),
            ..Default::default()
        });
    }
}

/// IANA time zone names (`America/New_York`, `UTC`, `Etc/GMT+5`).
fn valid_timezone(tz: &str) -> bool {
    tz.parse::<chrono_tz::Tz>().is_ok()
}

impl CloudWatch {
    pub(crate) fn put_anomaly_detector(
        &self,
        ctx: &RequestContext,
        input: types::PutAnomalyDetectorInput,
    ) -> Result<types::PutAnomalyDetectorOutput, ServiceError> {
        ctx.authorize("cloudwatch:PutAnomalyDetector", &names::any(ctx), ConditionContext::new())?;
        let (single, math) = normalize(
            input.namespace,
            input.metric_name,
            input.dimensions,
            input.stat,
            input.single_metric_anomaly_detector,
            input.metric_math_anomaly_detector,
        )?;
        if let Some(s) = &single {
            validate_single(s)?;
        }
        if let Some(m) = &math {
            let queries = m.metric_data_queries.clone().unwrap_or_default();
            crate::math::validate_queries(&queries, "MetricMathAnomalyDetector.MetricDataQueries")?;
            if queries.iter().filter(|q| q.return_data.unwrap_or(true)).count() != 1 {
                return Err(errors::invalid_parameter_value(
                    "Exactly one element of the MetricDataQueries list should return data.",
                ));
            }
        }
        if let Some(c) = &input.configuration {
            for r in c.excluded_time_ranges.iter().flatten() {
                if r.start_time >= r.end_time {
                    return Err(errors::invalid_parameter_value(
                        "The start time of an excluded time range must be before its end time.",
                    ));
                }
            }
            if let Some(tz) = &c.metric_timezone {
                if !valid_timezone(tz) {
                    return Err(errors::invalid_parameter_value(format!(
                        "The value {tz} for parameter MetricTimezone is not valid."
                    )));
                }
            }
        }
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(d) = region.anomaly_detectors.iter_mut().find(|d| matches(d, &single, &math)) {
            d.configuration = input.configuration;
            d.metric_characteristics = input.metric_characteristics;
            return Ok(types::PutAnomalyDetectorOutput { anomaly_detector_id: d.anomaly_detector_id.clone() });
        }
        if region.anomaly_detectors.len() >= MAX_DETECTORS {
            return Err(errors::limit_exceeded("The maximum number of anomaly detection models has been reached."));
        }
        let legacy = single.clone().unwrap_or_default();
        let id = uuid::Uuid::new_v4().to_string();
        region.anomaly_detectors.push(types::AnomalyDetector {
            anomaly_detector_id: Some(id.clone()),
            namespace: legacy.namespace.clone(),
            metric_name: legacy.metric_name.clone(),
            dimensions: single.as_ref().map(|_| legacy.dimensions.clone().unwrap_or_default()),
            stat: legacy.stat.clone(),
            configuration: input.configuration,
            state_value: None,
            metric_characteristics: input.metric_characteristics,
            single_metric_anomaly_detector: single,
            metric_math_anomaly_detector: math,
        });
        Ok(types::PutAnomalyDetectorOutput { anomaly_detector_id: Some(id) })
    }

    pub(crate) fn describe_anomaly_detectors(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAnomalyDetectorsInput,
    ) -> Result<types::DescribeAnomalyDetectorsOutput, ServiceError> {
        ctx.authorize("cloudwatch:DescribeAnomalyDetectors", &names::any(ctx), ConditionContext::new())?;
        let types_wanted = input.anomaly_detector_types.clone().unwrap_or_default();
        for t in &types_wanted {
            if t != "SINGLE_METRIC" && t != "METRIC_MATH" {
                return Err(errors::invalid_parameter_value(format!(
                    "The value {t} for parameter AnomalyDetectorTypes is not valid."
                )));
            }
        }
        let now = names::now(ctx);
        let st = self.lock();
        let region = st.region_ref(&ctx.caller.account_id, &ctx.region);
        let detectors: Vec<types::AnomalyDetector> = region
            .map(|r| r.anomaly_detectors.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|d| {
                let kind = if d.metric_math_anomaly_detector.is_some() { "METRIC_MATH" } else { "SINGLE_METRIC" };
                if !types_wanted.is_empty() && !types_wanted.iter().any(|t| t == kind) {
                    return false;
                }
                if let Some(ids) = &input.anomaly_detector_ids {
                    if !ids.iter().any(|i| d.anomaly_detector_id.as_ref() == Some(i)) {
                        return false;
                    }
                }
                let s = d.single_metric_anomaly_detector.as_ref();
                if input.namespace.is_some() && s.and_then(|s| s.namespace.as_ref()) != input.namespace.as_ref() {
                    return false;
                }
                if input.metric_name.is_some() && s.and_then(|s| s.metric_name.as_ref()) != input.metric_name.as_ref() {
                    return false;
                }
                if let Some(want) = &input.dimensions {
                    let have = s.and_then(|s| s.dimensions.clone()).unwrap_or_default();
                    if !want.iter().all(|w| have.iter().any(|h| h.name == w.name && h.value == w.value)) {
                        return false;
                    }
                }
                true
            })
            .map(|mut d| {
                d.state_value = Some(state_value(region, &d, now));
                d
            })
            .collect();
        drop(st);
        let size = input.max_results.unwrap_or(100).clamp(1, 100) as usize;
        let (page, next_token) = names::page(detectors, input.next_token.as_deref(), size)?;
        Ok(types::DescribeAnomalyDetectorsOutput { anomaly_detectors: Some(page), next_token })
    }

    pub(crate) fn delete_anomaly_detector(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAnomalyDetectorInput,
    ) -> Result<types::DeleteAnomalyDetectorOutput, ServiceError> {
        ctx.authorize("cloudwatch:DeleteAnomalyDetector", &names::any(ctx), ConditionContext::new())?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let before = region.anomaly_detectors.len();
        if let Some(id) = &input.anomaly_detector_id {
            region.anomaly_detectors.retain(|d| d.anomaly_detector_id.as_ref() != Some(id));
        } else {
            let (single, math) = normalize(
                input.namespace,
                input.metric_name,
                input.dimensions,
                input.stat,
                input.single_metric_anomaly_detector,
                input.metric_math_anomaly_detector,
            )?;
            region.anomaly_detectors.retain(|d| !matches(d, &single, &math));
        }
        if region.anomaly_detectors.len() == before {
            return Err(errors::resource_not_found_exception("The anomaly detection model does not exist."));
        }
        Ok(types::DeleteAnomalyDetectorOutput {})
    }
}
