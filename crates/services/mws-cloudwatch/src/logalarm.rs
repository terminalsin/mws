//! Log alarms: a Logs Insights query run on a schedule over a time window
//! (`StartTimeOffset`/`EndTimeOffset` seconds before the run). Each run
//! reduces its rows to one value: the sum of the column named by
//! `AggregationExpression` when the results have one, else the number of
//! rows. The alarm goes to `ALARM` when `QueryResultsToAlarm` of the last
//! `QueryResultsToEvaluate` values breach the threshold.

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;
use mws_events::schedule::Schedule;
use serde_json::json;

use crate::alarms::history_ts;
use crate::evaluate::java_double;
use crate::generated::types;
use crate::CloudWatch;

/// Whether the alarm's schedule fired since it last ran.
pub fn due(
    l: &types::PutLogAlarmInput,
    last: Option<DateTime<Utc>>,
    created: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    let Some(s) = Schedule::parse(&l.scheduled_query_configuration.schedule_configuration.schedule_expression) else {
        return false;
    };
    !s.fires_between(created, last.unwrap_or(created), now, 1).is_empty()
}

fn breaches(op: &str, v: f64, t: f64) -> bool {
    match op {
        "GreaterThanOrEqualToThreshold" => v >= t,
        "GreaterThanThreshold" => v > t,
        "LessThanThreshold" => v < t,
        "LessThanOrEqualToThreshold" => v <= t,
        _ => false,
    }
}

/// Run the query and decide the state: `(value, reason, reason data)`.
pub fn evaluate(
    cw: &CloudWatch,
    template: &RequestContext,
    account: &str,
    region: &str,
    l: &types::PutLogAlarmInput,
    now: DateTime<Utc>,
) -> Option<(String, String, String)> {
    let q = &l.scheduled_query_configuration;
    let logs = cw.inner.logs.get()?;
    let start = now - Duration::seconds(q.schedule_configuration.start_time_offset);
    let end = now - Duration::seconds(q.schedule_configuration.end_time_offset.unwrap_or(0));
    let groups = q.log_group_identifiers.clone().unwrap_or_default();
    let _ = template;
    let rows = logs
        .query_as_service(account, region, &groups, &q.query_string, start.timestamp_millis(), end.timestamp_millis())
        .ok()?;
    let column = q.aggregation_expression.trim();
    let has_column = rows.iter().any(|r| r.iter().any(|(f, _)| f == column));
    let value = if has_column {
        let vals: Vec<f64> = rows
            .iter()
            .filter_map(|r| r.iter().find(|(f, _)| f == column).and_then(|(_, v)| v.parse::<f64>().ok()))
            .collect();
        (!vals.is_empty()).then(|| vals.iter().sum())
    } else {
        Some(rows.len() as f64)
    };
    let (results, prev_state) = {
        let mut st = cw.lock();
        let a = st.region(account, region).alarms.get_mut(&l.alarm_name)?;
        a.log_results.push(value);
        let keep = l.query_results_to_evaluate.max(1) as usize;
        if a.log_results.len() > keep {
            let drop = a.log_results.len() - keep;
            a.log_results.drain(..drop);
        }
        (a.log_results.clone(), a.state_value.clone())
    };
    let n = l.query_results_to_evaluate.max(1) as usize;
    let m = l.query_results_to_alarm.max(1) as usize;
    let tmd = l.treat_missing_data.as_deref().unwrap_or("missing");
    let present: Vec<f64> = results.iter().flatten().copied().collect();
    let missing = n.saturating_sub(present.len());
    let breaching = present.iter().filter(|v| breaches(&l.comparison_operator, **v, l.threshold)).count()
        + if tmd == "breaching" { missing } else { 0 };
    let data = json!({
        "version": "1.0",
        "queryDate": history_ts(now),
        "startDate": history_ts(start),
        "endDate": history_ts(end),
        "threshold": l.threshold,
        "recentQueryResults": results,
    })
    .to_string();
    let listed = present.iter().rev().map(|v| java_double(*v)).collect::<Vec<_>>().join(", ");
    if present.is_empty() && tmd != "breaching" {
        return match tmd {
            "ignore" => None,
            "notBreaching" => {
                Some(("OK".into(), "Threshold Crossed: no query results were treated as [NonBreaching].".into(), data))
            }
            _ => {
                Some(("INSUFFICIENT_DATA".into(), format!("Insufficient Data: {n} query results were unknown."), data))
            }
        };
    }
    if breaching >= m {
        Some((
            "ALARM".into(),
            format!(
                "Threshold Crossed: {breaching} out of the last {n} query results [{listed}] breached the threshold ({}) (minimum {m} for {prev_state} -> ALARM transition).",
                java_double(l.threshold)
            ),
            data,
        ))
    } else {
        Some((
            "OK".into(),
            format!(
                "Threshold Crossed: {} out of the last {n} query results [{listed}] did not breach the threshold ({}).",
                n - breaching.min(n),
                java_double(l.threshold)
            ),
            data,
        ))
    }
}
