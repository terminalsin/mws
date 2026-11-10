//! The `AWS/Lambda` CloudWatch metrics: one data point per invocation for
//! `Invocations`, `Errors`, `Throttles` and `Duration`, and the
//! `ConcurrentExecutions` gauge, published by function name, by
//! `Resource` (the qualified name) and `ExecutedVersion` for qualified
//! invocations, and across all functions.

use mws_core::metrics::MetricDatum;
use mws_core::RequestContext;

use crate::names::FunctionRef;
use crate::Lambda;

/// What one invocation did, for its metrics.
pub(crate) enum Result {
    /// The function ran (`error` when it failed) for `duration_ms`.
    Ran {
        executed_version: String,
        error: bool,
        duration_ms: f64,
    },
    Throttled,
    /// Lambda could not start the function.
    Failed,
}

impl Lambda {
    pub(crate) fn publish_invocation_metrics(&self, ctx: &RequestContext, f: &FunctionRef, result: Result) {
        if !self.inner.metrics.connected() {
            return;
        }
        let account = f.account.clone();
        let now = ctx.received_at.max(chrono::Utc::now() + self.clock_skew());
        let mut dimension_sets: Vec<Vec<(String, String)>> =
            vec![Vec::new(), vec![("FunctionName".into(), f.name.clone())]];
        if let Some(q) = &f.qualifier {
            dimension_sets
                .push(vec![("FunctionName".into(), f.name.clone()), ("Resource".into(), format!("{}:{q}", f.name))]);
        }
        let executed = match &result {
            Result::Ran { executed_version, .. } if f.qualifier.is_some() => Some(executed_version.clone()),
            _ => None,
        };
        let mut data = Vec::new();
        let mut put = |name: &'static str, unit: &'static str, value: f64, by_version: bool| {
            for dims in &dimension_sets {
                data.push(MetricDatum::new(&account, &ctx.region, "AWS/Lambda", name, dims.clone(), unit, now, value));
            }
            if let (true, Some(v)) = (by_version, &executed) {
                let dims = vec![("FunctionName".into(), f.name.clone()), ("ExecutedVersion".into(), v.clone())];
                data.push(MetricDatum::new(&account, &ctx.region, "AWS/Lambda", name, dims, unit, now, value));
            }
        };
        match result {
            Result::Ran { error, duration_ms, .. } => {
                put("Invocations", "Count", 1.0, true);
                put("Errors", "Count", if error { 1.0 } else { 0.0 }, true);
                put("Duration", "Milliseconds", duration_ms, true);
            }
            Result::Throttled => {
                put("Throttles", "Count", 1.0, false);
            }
            Result::Failed => {
                put("Invocations", "Count", 1.0, false);
                put("Errors", "Count", 1.0, false);
            }
        }
        // Lambda counts the invocation that just finished as running.
        let running = self.inner.runtimes.concurrent(Some(&f.arn())) as f64 + 1.0;
        let all = self.inner.runtimes.concurrent(None) as f64 + 1.0;
        data.push(MetricDatum::new(
            &account,
            &ctx.region,
            "AWS/Lambda",
            "ConcurrentExecutions",
            vec![("FunctionName".into(), f.name.clone())],
            "Count",
            now,
            running,
        ));
        data.push(MetricDatum::new(
            &account,
            &ctx.region,
            "AWS/Lambda",
            "ConcurrentExecutions",
            Vec::new(),
            "Count",
            now,
            all,
        ));
        self.inner.metrics.publish(data);
    }

    /// Publish one data point for a stream event source mapping (its
    /// `IteratorAge`) or an asynchronous invocation (`AsyncEventAge`, ...).
    pub(crate) fn publish_function_metric(
        &self,
        ctx: &RequestContext,
        f: &FunctionRef,
        name: &'static str,
        unit: &'static str,
        value: f64,
    ) {
        if !self.inner.metrics.connected() {
            return;
        }
        let now = ctx.received_at.max(chrono::Utc::now() + self.clock_skew());
        let data = [Vec::new(), vec![("FunctionName".to_string(), f.name.clone())]]
            .into_iter()
            .map(|dims| MetricDatum::new(&f.account, &ctx.region, "AWS/Lambda", name, dims, unit, now, value))
            .collect();
        self.inner.metrics.publish(data);
    }
}

/// The `Duration` a REPORT log line states, in milliseconds.
pub(crate) fn reported_duration(logs: &str) -> Option<f64> {
    let line = logs.lines().rev().find(|l| l.starts_with("REPORT "))?;
    let rest = line.split("\tDuration: ").nth(1).or_else(|| line.split(" Duration: ").nth(1))?;
    rest.split(" ms").next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn duration_from_report() {
        let logs = "START RequestId: x Version: $LATEST\nEND RequestId: x\nREPORT RequestId: x\tDuration: 12.34 ms\tBilled Duration: 13 ms\tMemory Size: 128 MB\n";
        assert_eq!(super::reported_duration(logs), Some(12.34));
        assert_eq!(super::reported_duration("nothing"), None);
    }
}
