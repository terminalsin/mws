//! Scheduled queries that run: every second the runner looks for
//! enabled scheduled queries whose schedule fired on the emulated clock,
//! assumes the execution role as `logs.amazonaws.com`, runs the query
//! over `[fired - startTimeOffset, fired - endTimeOffset]` and delivers
//! the results: a JSON file in S3 (as the S3 configuration's role) and/or
//! a lookup table refreshed from the query. Each run is recorded in the
//! trigger history (`GetScheduledQueryHistory`), with the query id that
//! `GetQueryResults` answers for.

use std::sync::atomic::Ordering;

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use serde_json::{json, Map, Value};

use crate::generated::types;
use crate::Logs;

const SERVICE_PRINCIPAL: &str = "logs.amazonaws.com";

/// A firing to run: where, which query, and when it fired.
struct Due {
    account: String,
    region: String,
    arn: String,
    fired: i64,
    record: types::GetScheduledQueryResponse,
}

/// AWS documents these as epoch time; accept seconds or milliseconds.
fn epoch_ms(t: i64) -> i64 {
    if t.abs() < 100_000_000_000 {
        t * 1000
    } else {
        t
    }
}

fn ms_time(ms: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

/// `s3://bucket/prefix` → `(bucket, prefix)`.
fn s3_target(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("s3://")?;
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    Some((bucket.to_string(), prefix.trim_matches('/').to_string()))
}

impl Logs {
    /// Start the runner once, from inside the runtime.
    pub(crate) fn start_scheduler(&self) {
        if tokio::runtime::Handle::try_current().is_err() || self.scheduler.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                me.run_scheduled_queries().await;
            }
        });
    }

    /// Run every scheduled query whose schedule fired since it was last
    /// looked at. A query that missed several firings (the clock jumped)
    /// runs once, for the latest.
    pub(crate) async fn run_scheduled_queries(&self) {
        let Some((template, offset)) = self.template.lock().expect("Logs template lock poisoned").clone() else {
            return;
        };
        let now = Utc::now() + offset;
        let now_ms = now.timestamp_millis();
        let mut due = Vec::new();
        {
            let mut st = self.lock();
            for (key, region) in st.regions.iter_mut() {
                let Some((account, region_name)) = key.split_once('/') else { continue };
                for (arn, q) in region.scheduled_queries.iter_mut() {
                    let after = q.evaluated_until.unwrap_or(now_ms);
                    q.evaluated_until = Some(now_ms);
                    let r = &q.record;
                    if r.state.as_deref() != Some("ENABLED") {
                        continue;
                    }
                    let Some(schedule) = r.schedule_expression.as_deref().and_then(mws_schedule::Schedule::parse)
                    else {
                        continue;
                    };
                    let after = after.max(r.schedule_start_time.map(epoch_ms).unwrap_or(i64::MIN).saturating_sub(1));
                    let until = now_ms.min(r.schedule_end_time.map(epoch_ms).unwrap_or(i64::MAX));
                    if until <= after {
                        continue;
                    }
                    let anchor = ms_time(r.creation_time.unwrap_or(after));
                    let fired = schedule.fires_between(anchor, ms_time(after), ms_time(until), 1000);
                    if let Some(t) = fired.last() {
                        due.push(Due {
                            account: account.to_string(),
                            region: region_name.to_string(),
                            arn: arn.clone(),
                            fired: t.timestamp_millis(),
                            record: r.clone(),
                        });
                    }
                }
            }
        }
        for d in due {
            let mut ctx = template.clone();
            ctx.region = d.region.clone();
            ctx.caller.account_id = d.account.clone();
            ctx.received_at = now;
            let entry = self.run_one(&ctx, &d).await;
            let mut st = self.lock();
            if let Some(q) = st.region(&d.account, &d.region).scheduled_queries.get_mut(&d.arn) {
                q.record.last_triggered_time = Some(d.fired);
                q.record.last_execution_status = entry.execution_status.clone();
                q.history.push(entry);
                // Keep the history bounded.
                if q.history.len() > 1000 {
                    q.history.remove(0);
                }
            }
        }
    }

    /// The role's identity, as CloudWatch Logs gets it by assuming it.
    fn scheduled_role_context(
        &self,
        ctx: &RequestContext,
        role: &str,
        source_arn: &str,
    ) -> Result<RequestContext, String> {
        let cannot = || format!("Unable to assume role {role}. Make sure its trust policy allows {SERVICE_PRINCIPAL}.");
        let sts = self.sts.as_ref().ok_or_else(cannot)?;
        let creds = sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: role,
                service_principal: SERVICE_PRINCIPAL,
                session_name: "CWLScheduledQuery",
                duration_seconds: 3600,
                source_account: Some(&ctx.caller.account_id),
                source_arn: Some(source_arn),
                now: ctx.received_at,
            })
            .map_err(|_| cannot())?;
        let resolved = sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .ok()
            .flatten()
            .ok_or_else(cannot)?;
        Ok(RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() })
    }

    async fn run_one(&self, ctx: &RequestContext, d: &Due) -> types::TriggerHistoryRecord {
        let r = &d.record;
        let mut entry = types::TriggerHistoryRecord { triggered_timestamp: Some(d.fired), ..Default::default() };
        let fail = |mut e: types::TriggerHistoryRecord, status: &str, message: String| {
            e.execution_status = Some(status.into());
            e.error_message = Some(message);
            e
        };
        let role = r.execution_role_arn.clone().unwrap_or_default();
        let rctx = match self.scheduled_role_context(ctx, &role, &d.arn) {
            Ok(c) => c,
            Err(m) => return fail(entry, "Failed", m),
        };
        let start = d.fired - r.start_time_offset.unwrap_or(0).max(0) * 1000;
        let end = d.fired - r.end_time_offset.unwrap_or(0).max(0) * 1000;
        let language = r.query_language.clone().unwrap_or_else(|| "CWLI".into());
        let query_id = match self.run_query(
            &rctx,
            &language,
            r.query_string.as_deref().unwrap_or_default(),
            r.log_group_identifiers.clone().unwrap_or_default(),
            (start, end),
            None,
        ) {
            Ok(id) => id,
            Err(e) if e.code == "MalformedQueryException" => return fail(entry, "InvalidQuery", e.message),
            Err(e) => return fail(entry, "Failed", e.message),
        };
        entry.query_id = Some(query_id.clone());
        entry.execution_status = Some("Complete".into());
        let mut destinations = Vec::new();
        let config = r.destination_configuration.clone().unwrap_or_default();
        if let Some(s3) = &config.s3_configuration {
            destinations.push(self.deliver_to_s3(ctx, d, &query_id, s3).await);
        }
        if let Some(t) = &config.lookup_table_configuration {
            destinations.push(self.deliver_to_lookup_table(ctx, d, &query_id, t));
        }
        if destinations.iter().any(|x| x.status.as_deref() != Some("COMPLETE")) {
            entry.execution_status = Some("Failed".into());
            entry.error_message = destinations.iter().find_map(|x| x.error_message.clone());
        }
        if !destinations.is_empty() {
            entry.destinations = Some(destinations);
        }
        entry
    }

    /// The query's rows as JSON objects, in result order.
    fn result_rows(&self, ctx: &RequestContext, query_id: &str) -> Vec<Value> {
        let st = self.lock();
        let Some(q) = st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.queries.get(query_id)) else {
            return Vec::new();
        };
        q.results
            .iter()
            .map(|row| {
                let obj: Map<String, Value> = row
                    .iter()
                    .filter_map(|f| Some((f.field.clone()?, Value::String(f.value.clone().unwrap_or_default()))))
                    .collect();
                Value::Object(obj)
            })
            .collect()
    }

    async fn deliver_to_s3(
        &self,
        ctx: &RequestContext,
        d: &Due,
        query_id: &str,
        c: &types::S3Configuration,
    ) -> types::ScheduledQueryDestination {
        let mut out = types::ScheduledQueryDestination {
            destination_type: Some("S3".into()),
            destination_identifier: Some(c.destination_identifier.clone()),
            ..Default::default()
        };
        let result: Result<String, String> = async {
            let (bucket, prefix) = s3_target(&c.destination_identifier)
                .ok_or_else(|| format!("Invalid S3 destination {}", c.destination_identifier))?;
            let key = if prefix.is_empty() { format!("{query_id}.json") } else { format!("{prefix}/{query_id}.json") };
            let s3 = self.s3.as_ref().ok_or("S3 is not available.")?;
            let rctx = self.scheduled_role_context(ctx, &c.role_arn, &d.arn)?;
            let body = serde_json::to_vec(&self.result_rows(ctx, query_id)).expect("rows serialize");
            let mut request = json!({
                "Bucket": bucket,
                "Key": key,
                "Body": base64::engine::general_purpose::STANDARD.encode(body),
                "ContentType": "application/json",
            });
            if let Some(owner) = &c.owner_account_id {
                request["ExpectedBucketOwner"] = json!(owner);
            }
            if let Some(k) = &c.kms_key_id {
                request["ServerSideEncryption"] = json!("aws:kms");
                request["SSEKMSKeyId"] = json!(k);
            }
            mws_core::Service::invoke(s3, rctx, "PutObject", request)
                .await
                .map_err(|e: ServiceError| format!("{}: {}", e.code, e.message))?;
            Ok(format!("s3://{bucket}/{key}"))
        }
        .await;
        match result {
            Ok(id) => {
                out.status = Some("COMPLETE".into());
                out.processed_identifier = Some(id);
            }
            Err(m) => {
                out.status = Some(if m.contains("AccessDenied") { "CLIENT_ERROR" } else { "FAILED" }.into());
                out.error_message = Some(m);
            }
        }
        out
    }

    fn deliver_to_lookup_table(
        &self,
        ctx: &RequestContext,
        d: &Due,
        query_id: &str,
        c: &types::LookupTableConfiguration,
    ) -> types::ScheduledQueryDestination {
        let mut out = types::ScheduledQueryDestination {
            destination_type: Some("LOOKUP_TABLE".into()),
            destination_identifier: Some(c.table_name.clone()),
            ..Default::default()
        };
        let result = self.scheduled_role_context(ctx, &c.role_arn, &d.arn).and_then(|rctx| {
            let existing = self
                .lock()
                .region_ref(&ctx.caller.account_id, &ctx.region)
                .and_then(|r| r.lookup_tables.get(&c.table_name).map(|t| t.arn.clone()));
            let arn = match existing {
                Some(arn) => self
                    .update_lookup_table(
                        &rctx,
                        types::UpdateLookupTableRequest {
                            lookup_table_arn: arn.clone(),
                            description: c.description.clone(),
                            query_id: Some(query_id.to_string()),
                            kms_key_id: c.kms_key_id.clone(),
                            ..Default::default()
                        },
                    )
                    .map(|_| arn),
                None => self
                    .create_lookup_table(
                        &rctx,
                        types::CreateLookupTableRequest {
                            lookup_table_name: c.table_name.clone(),
                            description: c.description.clone(),
                            query_id: Some(query_id.to_string()),
                            kms_key_id: c.kms_key_id.clone(),
                            tags: c.tags.clone(),
                            ..Default::default()
                        },
                    )
                    .map(|r| r.lookup_table_arn.unwrap_or_default()),
            };
            arn.map_err(|e| format!("{}: {}", e.code, e.message))
        });
        match result {
            Ok(arn) => {
                out.status = Some("COMPLETE".into());
                out.processed_identifier = Some(arn);
            }
            Err(m) => {
                out.status = Some(if m.contains("AccessDenied") { "CLIENT_ERROR" } else { "FAILED" }.into());
                out.error_message = Some(m);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(s3_target("s3://b/x/y/"), Some(("b".into(), "x/y".into())));
        assert_eq!(s3_target("s3://b"), Some(("b".into(), String::new())));
        assert_eq!(s3_target("b/x"), None);
        assert_eq!(epoch_ms(1_700_000_000), 1_700_000_000_000);
        assert_eq!(epoch_ms(1_700_000_000_000), 1_700_000_000_000);
    }
}
