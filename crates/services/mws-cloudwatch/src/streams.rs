//! Metric streams. A running stream really streams: every minute the
//! evaluator turns the previous minute of each matching metric into a
//! record (`json` output format: one JSON object per metric and minute,
//! newline-delimited, with `max`, `min`, `sum`, `count` and any additional
//! statistics) and hands the batch to the Firehose delivery stream through
//! [`MetricStreamDelivery`], as the stream's IAM role.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::json;

use crate::generated::{errors, types};
use crate::names::{self, metric_stream_arn, request_tag_conditions, resource_tag_conditions};
use crate::state::{MetricStream, Region, Series};
use crate::stats::Agg;
use crate::CloudWatch;

const FORMATS: &[&str] = &["json", "opentelemetry0.7", "opentelemetry1.0"];

/// Where metric stream records go: Kinesis Data Firehose.
pub trait MetricStreamDelivery: Send + Sync {
    /// Put `records` into the delivery stream `firehose_arn`, assuming
    /// `role_arn` as `streams.metrics.cloudwatch.amazonaws.com` for the
    /// metric stream `stream_arn`. `ctx` is in the stream's account and
    /// Region (for the endpoint and the emulated clock); its caller is not
    /// consulted.
    fn deliver(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        firehose_arn: &str,
        role_arn: &str,
        records: Vec<Vec<u8>>,
    ) -> Result<(), String>;
}

/// One stream's batch, ready to hand over.
pub(crate) struct Batch {
    account: String,
    region: String,
    stream_arn: String,
    firehose_arn: String,
    role_arn: String,
    records: Vec<Vec<u8>>,
}

fn bad(m: impl Into<String>) -> ServiceError {
    errors::invalid_parameter_value(m)
}

fn validate_filters(filters: &[types::MetricStreamFilter], field: &str) -> Result<(), ServiceError> {
    for (i, f) in filters.iter().enumerate() {
        if f.namespace.as_deref().is_none_or(str::is_empty) && f.metric_names.as_ref().is_some_and(|m| !m.is_empty()) {
            return Err(bad(format!("{field}.member.{} must specify a Namespace to filter by MetricNames.", i + 1)));
        }
    }
    Ok(())
}

fn arn_service(arn: &str) -> Option<(&str, &str)> {
    let mut p = arn.splitn(6, ':');
    if p.next() != Some("arn") {
        return None;
    }
    let _partition = p.next()?;
    let service = p.next()?;
    let _region = p.next()?;
    let _account = p.next()?;
    Some((service, p.next()?))
}

fn filter_matches(f: &types::MetricStreamFilter, namespace: &str, name: &str) -> bool {
    f.namespace.as_deref().is_none_or(|n| n == namespace)
        && f.metric_names.as_ref().is_none_or(|m| m.is_empty() || m.iter().any(|x| x == name))
}

/// Whether a stream includes a metric.
pub fn includes(c: &types::PutMetricStreamInput, namespace: &str, name: &str) -> bool {
    let include = c.include_filters.as_deref().unwrap_or_default();
    let exclude = c.exclude_filters.as_deref().unwrap_or_default();
    (include.is_empty() || include.iter().any(|f| filter_matches(f, namespace, name)))
        && !exclude.iter().any(|f| filter_matches(f, namespace, name))
}

fn record(
    stream: &MetricStream,
    account: &str,
    region: &str,
    series: &Series,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Option<Vec<u8>> {
    let agg = Agg::of(crate::metrics::samples_in(series, from, to, None))?;
    let mut value = json!({"max": agg.max, "min": agg.min, "sum": agg.sum, "count": agg.count});
    for sc in stream.config.statistics_configurations.iter().flatten() {
        if sc.include_metrics.iter().any(|m| m.namespace == series.key.namespace && m.metric_name == series.key.name) {
            for s in &sc.additional_statistics {
                if let Some(v) = agg.stat(s) {
                    value[s.as_str()] = json!(v);
                }
            }
        }
    }
    let dims: serde_json::Map<String, serde_json::Value> =
        series.key.dimensions.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    let mut line = serde_json::to_vec(&json!({
        "metric_stream_name": stream.config.name,
        "account_id": account,
        "region": region,
        "namespace": series.key.namespace,
        "metric_name": series.key.name,
        "dimensions": dims,
        "timestamp": from.timestamp_millis(),
        "value": value,
        "unit": agg.unit.clone().unwrap_or_else(|| "None".into()),
    }))
    .ok()?;
    line.push(b'\n');
    Some(line)
}

/// Collect the minutes each running stream in `region` has not delivered
/// yet, up to the start of the current minute.
pub(crate) fn due_batches(region: &mut Region, account: &str, region_name: &str, now: DateTime<Utc>) -> Vec<Batch> {
    let minute = crate::metrics::align(now, 60);
    let mut out = Vec::new();
    let Region { metrics, metric_streams, .. } = region;
    for stream in metric_streams.values_mut() {
        if stream.state != "running" {
            continue;
        }
        let from = stream.delivered_until.unwrap_or(crate::metrics::align(stream.updated, 60));
        if from >= minute {
            continue;
        }
        // Deliver at most an hour of backlog, as Firehose would buffer.
        let from = from.max(minute - Duration::hours(1));
        let mut records = Vec::new();
        if stream.config.output_format == "json" {
            let mut t = from;
            while t < minute {
                for s in metrics.values() {
                    if includes(&stream.config, &s.key.namespace, &s.key.name) {
                        records.extend(record(stream, account, region_name, s, t, t + Duration::minutes(1)));
                    }
                }
                t += Duration::minutes(1);
            }
        }
        stream.delivered_until = Some(minute);
        if !records.is_empty() {
            out.push(Batch {
                account: account.to_string(),
                region: region_name.to_string(),
                stream_arn: stream.arn.clone(),
                firehose_arn: stream.config.firehose_arn.clone(),
                role_arn: stream.config.role_arn.clone(),
                records,
            });
        }
    }
    out
}

impl CloudWatch {
    pub(crate) fn deliver_batches(&self, batches: Vec<Batch>) {
        if batches.is_empty() {
            return;
        }
        let Some(sink) = self.inner.streams.get().cloned() else { return };
        let Some(template) = self.inner.template.lock().expect("template lock poisoned").clone() else { return };
        for b in batches {
            let mut ctx =
                RequestContext { region: b.region.clone(), received_at: self.clock_now(), ..template.clone() };
            ctx.caller.account_id = b.account.clone();
            if let Err(e) = sink.deliver(&ctx, &b.stream_arn, &b.firehose_arn, &b.role_arn, b.records) {
                tracing::debug!(firehose = %b.firehose_arn, error = %e, "metric stream delivery failed");
            }
        }
    }

    /// Where running metric streams deliver.
    pub fn set_metric_stream_delivery(&self, sink: Arc<dyn MetricStreamDelivery>) {
        let _ = self.inner.streams.set(sink);
    }

    fn stream_tags(&self, ctx: &RequestContext, arn: &str) -> ConditionContext {
        let st = self.lock();
        resource_tag_conditions(st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.tags.get(arn)))
    }

    pub(crate) fn put_metric_stream(
        &self,
        ctx: &RequestContext,
        input: types::PutMetricStreamInput,
    ) -> Result<types::PutMetricStreamOutput, ServiceError> {
        let arn = metric_stream_arn(ctx, &input.name);
        let tags = input.tags.clone().unwrap_or_default();
        let mut conds = request_tag_conditions(&tags);
        conds.extend(self.stream_tags(ctx, &arn));
        ctx.authorize("cloudwatch:PutMetricStream", &arn, conds)?;
        if !input.name.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)) {
            return Err(bad(format!("The value {} for parameter Name is not valid.", input.name)));
        }
        if !FORMATS.contains(&input.output_format.as_str()) {
            return Err(bad(format!("The value {} for parameter OutputFormat is not valid.", input.output_format)));
        }
        if !matches!(arn_service(&input.firehose_arn), Some(("firehose", r)) if r.starts_with("deliverystream/")) {
            return Err(bad(format!("The value {} for parameter FirehoseArn is not valid.", input.firehose_arn)));
        }
        if !matches!(arn_service(&input.role_arn), Some(("iam", r)) if r.starts_with("role/")) {
            return Err(bad(format!("The value {} for parameter RoleArn is not valid.", input.role_arn)));
        }
        // The stream hands CloudWatch the role, which needs iam:PassRole.
        let mut pass = ConditionContext::new();
        pass.insert("iam:PassedToService".into(), vec!["streams.metrics.cloudwatch.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", &input.role_arn, pass)?;
        let include = input.include_filters.as_deref().unwrap_or_default();
        let exclude = input.exclude_filters.as_deref().unwrap_or_default();
        if !include.is_empty() && !exclude.is_empty() {
            return Err(errors::invalid_parameter_combination(
                "IncludeFilters and ExcludeFilters cannot both be specified.",
            ));
        }
        validate_filters(include, "IncludeFilters")?;
        validate_filters(exclude, "ExcludeFilters")?;
        for (i, sc) in input.statistics_configurations.iter().flatten().enumerate() {
            for s in &sc.additional_statistics {
                if crate::stats::Stat::is_basic(s) || crate::stats::Stat::parse(s).is_none() {
                    return Err(bad(format!(
                        "The value {s} for parameter StatisticsConfigurations.member.{}.AdditionalStatistics is not valid.",
                        i + 1
                    )));
                }
            }
        }
        let now = names::now(ctx);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let created = !region.metric_streams.contains_key(&input.name);
        let mut config = input;
        config.tags = None;
        match region.metric_streams.get_mut(&config.name) {
            Some(s) => {
                s.config = config;
                s.updated = now;
            }
            None => {
                region.metric_streams.insert(
                    config.name.clone(),
                    MetricStream {
                        arn: arn.clone(),
                        config,
                        state: "running".into(),
                        created: now,
                        updated: now,
                        delivered_until: None,
                    },
                );
            }
        }
        if created && !tags.is_empty() {
            region.tags.insert(arn.clone(), tags.into_iter().map(|t| (t.key, t.value)).collect());
        }
        drop(st);
        self.observe(ctx);
        Ok(types::PutMetricStreamOutput { arn: Some(arn) })
    }

    pub(crate) fn get_metric_stream(
        &self,
        ctx: &RequestContext,
        input: types::GetMetricStreamInput,
    ) -> Result<types::GetMetricStreamOutput, ServiceError> {
        let arn = metric_stream_arn(ctx, &input.name);
        ctx.authorize("cloudwatch:GetMetricStream", &arn, self.stream_tags(ctx, &arn))?;
        let st = self.lock();
        let s = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.metric_streams.get(&input.name))
            .ok_or_else(|| {
                errors::resource_not_found_exception(format!("The metric stream {} does not exist.", input.name))
            })?;
        Ok(types::GetMetricStreamOutput {
            arn: Some(s.arn.clone()),
            name: Some(s.config.name.clone()),
            include_filters: Some(s.config.include_filters.clone().unwrap_or_default()),
            exclude_filters: Some(s.config.exclude_filters.clone().unwrap_or_default()),
            firehose_arn: Some(s.config.firehose_arn.clone()),
            role_arn: Some(s.config.role_arn.clone()),
            state: Some(s.state.clone()),
            creation_date: Some(s.created),
            last_update_date: Some(s.updated),
            output_format: Some(s.config.output_format.clone()),
            statistics_configurations: Some(s.config.statistics_configurations.clone().unwrap_or_default()),
            include_linked_accounts_metrics: Some(s.config.include_linked_accounts_metrics.unwrap_or(false)),
        })
    }

    pub(crate) fn list_metric_streams(
        &self,
        ctx: &RequestContext,
        input: types::ListMetricStreamsInput,
    ) -> Result<types::ListMetricStreamsOutput, ServiceError> {
        ctx.authorize("cloudwatch:ListMetricStreams", &names::any(ctx), ConditionContext::new())?;
        let st = self.lock();
        let entries: Vec<types::MetricStreamEntry> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.metric_streams
                    .values()
                    .map(|s| types::MetricStreamEntry {
                        arn: Some(s.arn.clone()),
                        creation_date: Some(s.created),
                        last_update_date: Some(s.updated),
                        name: Some(s.config.name.clone()),
                        firehose_arn: Some(s.config.firehose_arn.clone()),
                        state: Some(s.state.clone()),
                        output_format: Some(s.config.output_format.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        drop(st);
        let size = input.max_results.unwrap_or(500).clamp(1, 500) as usize;
        let (page, next_token) = names::page(entries, input.next_token.as_deref(), size)?;
        Ok(types::ListMetricStreamsOutput { next_token, entries: Some(page) })
    }

    pub(crate) fn delete_metric_stream(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMetricStreamInput,
    ) -> Result<types::DeleteMetricStreamOutput, ServiceError> {
        let arn = metric_stream_arn(ctx, &input.name);
        ctx.authorize("cloudwatch:DeleteMetricStream", &arn, self.stream_tags(ctx, &arn))?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        // Deleting a stream that does not exist succeeds, as in AWS.
        if region.metric_streams.remove(&input.name).is_some() {
            region.tags.remove(&arn);
        }
        Ok(types::DeleteMetricStreamOutput {})
    }

    fn set_stream_state(
        &self,
        ctx: &RequestContext,
        action: &str,
        names: &[String],
        running: bool,
    ) -> Result<(), ServiceError> {
        for n in names {
            let arn = metric_stream_arn(ctx, n);
            ctx.authorize(&format!("cloudwatch:{action}"), &arn, self.stream_tags(ctx, &arn))?;
        }
        let now = names::now(ctx);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(missing) = names.iter().find(|n| !region.metric_streams.contains_key(*n)) {
            return Err(errors::resource_not_found_exception(format!("The metric stream {missing} does not exist.")));
        }
        let state = if running { "running" } else { "stopped" };
        for n in names {
            let s = region.metric_streams.get_mut(n).expect("checked above");
            if s.state != state {
                s.state = state.into();
                s.updated = now;
                s.delivered_until = None;
            }
        }
        drop(st);
        if running {
            self.observe(ctx);
        }
        Ok(())
    }

    pub(crate) fn start_metric_streams(
        &self,
        ctx: &RequestContext,
        input: types::StartMetricStreamsInput,
    ) -> Result<types::StartMetricStreamsOutput, ServiceError> {
        self.set_stream_state(ctx, "StartMetricStreams", &input.names, true)?;
        Ok(types::StartMetricStreamsOutput {})
    }

    pub(crate) fn stop_metric_streams(
        &self,
        ctx: &RequestContext,
        input: types::StopMetricStreamsInput,
    ) -> Result<types::StopMetricStreamsOutput, ServiceError> {
        self.set_stream_state(ctx, "StopMetricStreams", &input.names, false)?;
        Ok(types::StopMetricStreamsOutput {})
    }
}
