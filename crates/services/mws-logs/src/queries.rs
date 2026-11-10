//! Logs Insights queries and query definitions, log group fields, and
//! reading single records back through `@ptr`.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::events::cutoff;
use crate::generated::{errors, types};
use crate::groups::name_or_identifier;
use crate::insights::{self, Record, V};
use crate::names::{arn, now_ms, page, uuid, GroupRef};
use crate::state::{Event, LogGroup, Query, State};
use crate::Logs;

/// `@ptr`: where an event lives.
pub fn pointer(g: &GroupRef, stream: &str, seq: u64) -> String {
    let raw = format!("{}\u{1f}{}\u{1f}{}\u{1f}{stream}\u{1f}{seq}", g.account, g.region, g.name);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

fn resolve_pointer(p: &str) -> Option<(GroupRef, String, u64)> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).ok()?;
    let raw = String::from_utf8(raw).ok()?;
    let parts: Vec<&str> = raw.split('\u{1f}').collect();
    let [account, region, name, stream, seq] = parts.as_slice() else { return None };
    Some((
        GroupRef {
            partition: "aws".into(),
            account: account.to_string(),
            region: region.to_string(),
            name: name.to_string(),
        },
        stream.to_string(),
        seq.parse().ok()?,
    ))
}

/// The record Logs Insights sees for one event.
pub fn record(g: &GroupRef, stream: &str, e: &Event) -> Record {
    let mut r = Record::new();
    // Logs Insights queries the transformed version of an event.
    let message = e.message_for(true);
    insights::discover_json(message, &mut r);
    r.insert("@timestamp".into(), V::Time(e.timestamp));
    r.insert("@ingestionTime".into(), V::Time(e.ingestion_time));
    r.insert("@message".into(), V::Str(message.to_string()));
    r.insert("@logStream".into(), V::Str(stream.to_string()));
    r.insert("@log".into(), V::Str(format!("{}:{}", g.account, g.name)));
    r.insert("@ptr".into(), V::Str(pointer(g, stream, e.seq)));
    r
}

fn find_event<'a>(st: &'a State, g: &GroupRef, stream: &str, seq: u64) -> Option<(&'a LogGroup, &'a Event)> {
    let group = st.group(g).ok()?;
    let e = group.streams.get(stream)?.events.iter().find(|e| e.seq == seq)?;
    Some((group, e))
}

impl Logs {
    pub(crate) fn start_query(
        &self,
        ctx: &RequestContext,
        input: types::StartQueryRequest,
    ) -> Result<types::StartQueryResponse, ServiceError> {
        let language = input.query_language.clone().unwrap_or_else(|| "CWLI".into());
        let ids: Vec<String> = match (&input.log_group_name, &input.log_group_names, &input.log_group_identifiers) {
            (Some(n), None, None) => vec![n.clone()],
            (None, Some(ns), None) => ns.clone(),
            (None, None, Some(ids)) => ids.clone(),
            (None, None, None) if language == "SQL" => Vec::new(),
            (None, None, None) if language == "PPL" && input.query_string.trim_start().starts_with("source") => {
                Vec::new()
            }
            (None, None, None) => {
                return Err(errors::invalid_parameter(
                    "Either logGroupName, logGroupNames or logGroupIdentifiers must be specified",
                ))
            }
            _ => {
                return Err(errors::invalid_parameter(
                    "logGroupName, logGroupNames and logGroupIdentifiers are mutually exclusive parameters.",
                ))
            }
        };
        if input.end_time < input.start_time {
            return Err(errors::invalid_parameter("End time should not be before the start time"));
        }
        let id = self.run_query(
            ctx,
            &language,
            &input.query_string,
            ids,
            (input.start_time.saturating_mul(1000), input.end_time.saturating_mul(1000) + 999),
            input.limit,
        )?;
        Ok(types::StartQueryResponse { query_id: Some(id) })
    }

    /// Compile and run a query in any of the three languages over the
    /// events in `[from, to]` (epoch ms), keeping the results for
    /// `GetQueryResults`. Returns the query id.
    pub(crate) fn run_query(
        &self,
        ctx: &RequestContext,
        language: &str,
        query_string: &str,
        ids: Vec<String>,
        (from, to): (i64, i64),
        limit: Option<i32>,
    ) -> Result<String, ServiceError> {
        let now = now_ms(ctx);
        // Joins and subqueries load their log groups while compiling.
        let mut fetched: Vec<GroupRef> = Vec::new();
        let mut fetch_error: Option<ServiceError> = None;
        let mut scanned_bytes = 0i64;
        let mut scanned = 0usize;
        let compiled = {
            let mut fetch = |ids: &[String]| -> Result<Vec<insights::Record>, String> {
                let mut load = || -> Result<Vec<insights::Record>, ServiceError> {
                    let groups: Vec<GroupRef> = ids.iter().map(|i| GroupRef::parse(ctx, i)).collect::<Result<_, _>>()?;
                    let (records, bytes) = self.load_records(ctx, &groups, now, (from, to))?;
                    scanned_bytes += bytes;
                    scanned += records.len();
                    for g in groups {
                        if !fetched.iter().any(|f| f.arn() == g.arn()) {
                            fetched.push(g);
                        }
                    }
                    Ok(records)
                };
                load().map_err(|e| {
                    let m = e.message.clone();
                    fetch_error = Some(e);
                    m
                })
            };
            crate::sqlppl::compile_with(language, query_string, &mut fetch)
        };
        if let Some(e) = fetch_error {
            return Err(e);
        }
        let compiled = compiled.map_err(errors::malformed_query)?;
        // SQL names its log groups in FROM; the request may not add more.
        let ids = match (language, compiled.log_groups.is_empty()) {
            ("SQL", true) if compiled.rows.is_none() => {
                return Err(errors::malformed_query(
                    "Syntax error: missing FROM clause; name the log group to query in FROM",
                ))
            }
            ("SQL", _) if !ids.is_empty() => {
                return Err(errors::invalid_parameter(
                    "For SQL queries, specify log groups in the FROM clause of the query, not in the request.",
                ))
            }
            (_, false) => compiled.log_groups.clone(),
            _ => ids,
        };
        let query = compiled.query;
        let started = std::time::Instant::now();
        let (records, groups) = match compiled.rows {
            Some(rows) => (rows, fetched),
            None => {
                let groups: Vec<GroupRef> = ids.iter().map(|i| GroupRef::parse(ctx, i)).collect::<Result<_, _>>()?;
                let (records, bytes) = self.load_records(ctx, &groups, now, (from, to))?;
                scanned_bytes += bytes;
                scanned += records.len();
                for g in groups {
                    if !fetched.iter().any(|f| f.arn() == g.arn()) {
                        fetched.push(g);
                    }
                }
                (records, fetched)
            }
        };
        let limit = limit.map_or(10_000, |l| l.clamp(1, 10_000) as usize);
        let out = insights::execute(&query, records, limit);
        // `@ptr` is a Logs Insights language field.
        let ptr = language == "CWLI";
        let results: Vec<Vec<types::ResultField>> = out
            .rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .filter(|(f, _)| ptr || f != "@ptr")
                    .map(|(f, v)| types::ResultField { field: Some(f), value: Some(v) })
                    .collect()
            })
            .collect();
        let id = uuid();
        let stats = types::QueryStatistics {
            records_matched: out.records_matched as f64,
            records_scanned: scanned as f64,
            bytes_scanned: scanned_bytes as f64,
            log_groups_scanned: groups.len() as f64,
            result_count: results.len() as f64,
            ..Default::default()
        };
        let q = Query {
            id: id.clone(),
            language: language.to_string(),
            query_string: query_string.to_string(),
            status: "Complete".into(),
            create_time: now,
            log_groups: groups.iter().map(GroupRef::arn).collect(),
            results,
            statistics: stats,
            duration_ms: started.elapsed().as_millis() as i64,
        };
        self.lock().region(&ctx.caller.account_id, &ctx.region).queries.insert(id.clone(), q);
        Ok(id)
    }

    /// The events of `groups` in `[from, to]` as query records, after
    /// authorizing `StartQuery` on each; and the bytes scanned.
    fn load_records(
        &self,
        ctx: &RequestContext,
        groups: &[GroupRef],
        now: i64,
        (from, to): (i64, i64),
    ) -> Result<(Vec<insights::Record>, i64), ServiceError> {
        for g in groups {
            self.authorize_group(ctx, "StartQuery", g, None, ConditionContext::new())?;
        }
        let mut records = Vec::new();
        let mut bytes = 0i64;
        let st = self.lock();
        for g in groups {
            let group = st.group(g).map_err(|_| {
                errors::resource_not_found(format!("Log group '{}' does not exist for account ID '{}'", g.name, g.account))
            })?;
            let floor = cutoff(group, now).max(from);
            for s in group.streams.values() {
                for e in s.events.iter().filter(|e| e.timestamp >= floor && e.timestamp <= to) {
                    bytes += e.size();
                    records.push(record(g, &s.name, e));
                }
            }
        }
        Ok((records, bytes))
    }

    fn query(&self, ctx: &RequestContext, id: &str) -> Result<Query, ServiceError> {
        let st = self.lock();
        st.region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.queries.get(id))
            .cloned()
            .ok_or_else(|| errors::resource_not_found(format!("Query does not exist: {id}")))
    }

    pub(crate) fn get_query_results(
        &self,
        ctx: &RequestContext,
        input: types::GetQueryResultsRequest,
    ) -> Result<types::GetQueryResultsResponse, ServiceError> {
        self.authorize(ctx, "GetQueryResults", &arn(ctx, "log-group:*"), ConditionContext::new())?;
        let q = self.query(ctx, &input.query_id)?;
        let kms =
            self.lock().region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.query_result_kms_key.clone());
        let (results, next_token) = match input.max_items {
            Some(n) => page(q.results, input.next_token.as_deref(), n.max(1) as usize)?,
            None => (q.results, None),
        };
        Ok(types::GetQueryResultsResponse {
            query_language: Some(q.language),
            results: Some(results),
            statistics: Some(q.statistics),
            status: Some(q.status),
            encryption_key: kms,
            next_token,
        })
    }

    pub(crate) fn stop_query(
        &self,
        ctx: &RequestContext,
        input: types::StopQueryRequest,
    ) -> Result<types::StopQueryResponse, ServiceError> {
        self.authorize(ctx, "StopQuery", &arn(ctx, "log-group:*"), ConditionContext::new())?;
        let mut st = self.lock();
        let q = st
            .region(&ctx.caller.account_id, &ctx.region)
            .queries
            .get_mut(&input.query_id)
            .ok_or_else(|| errors::resource_not_found(format!("Query does not exist: {}", input.query_id)))?;
        // AWS answers a query that has already ended with an error.
        if !matches!(q.status.as_str(), "Running" | "Scheduled") {
            return Err(errors::invalid_parameter(format!("Query {} is not running.", input.query_id)));
        }
        q.status = "Cancelled".into();
        Ok(types::StopQueryResponse { success: true })
    }

    pub(crate) fn describe_queries(
        &self,
        ctx: &RequestContext,
        input: types::DescribeQueriesRequest,
    ) -> Result<types::DescribeQueriesResponse, ServiceError> {
        self.authorize(ctx, "DescribeQueries", &arn(ctx, "log-group:*"), ConditionContext::new())?;
        let st = self.lock();
        let mut out: Vec<&Query> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| r.queries.values().collect())
            .unwrap_or_default();
        out.sort_by_key(|q| std::cmp::Reverse(q.create_time));
        let wanted_group = input.log_group_name.as_ref().map(|n| GroupRef::own(ctx, n).arn());
        let out: Vec<types::QueryInfo> = out
            .into_iter()
            .filter(|q| input.status.as_ref().is_none_or(|s| s == &q.status))
            .filter(|q| input.query_language.as_ref().is_none_or(|l| l == &q.language))
            .filter(|q| wanted_group.as_ref().is_none_or(|g| q.log_groups.contains(g)))
            .map(|q| types::QueryInfo {
                query_language: Some(q.language.clone()),
                query_id: Some(q.id.clone()),
                query_string: Some(q.query_string.clone()),
                status: Some(q.status.clone()),
                create_time: Some(q.create_time),
                log_group_name: q.log_groups.first().and_then(|a| a.rsplit(':').next()).map(str::to_string),
                query_duration: Some(q.duration_ms),
                bytes_scanned: Some(q.statistics.bytes_scanned),
                user_identity: None,
            })
            .collect();
        let (queries, next_token) =
            page(out, input.next_token.as_deref(), input.max_results.unwrap_or(1000).clamp(1, 1000) as usize)?;
        Ok(types::DescribeQueriesResponse { queries: Some(queries), next_token })
    }

    pub(crate) fn list_log_groups_for_query(
        &self,
        ctx: &RequestContext,
        input: types::ListLogGroupsForQueryRequest,
    ) -> Result<types::ListLogGroupsForQueryResponse, ServiceError> {
        self.authorize(ctx, "ListLogGroupsForQuery", &arn(ctx, "log-group:*"), ConditionContext::new())?;
        let q = self.query(ctx, &input.query_id)?;
        let (ids, next_token) =
            page(q.log_groups, input.next_token.as_deref(), input.max_results.unwrap_or(50).clamp(1, 500) as usize)?;
        Ok(types::ListLogGroupsForQueryResponse { log_group_identifiers: Some(ids), next_token })
    }

    // ---- query definitions ---------------------------------------------------

    pub(crate) fn put_query_definition(
        &self,
        ctx: &RequestContext,
        input: types::PutQueryDefinitionRequest,
    ) -> Result<types::PutQueryDefinitionResponse, ServiceError> {
        self.authorize(ctx, "PutQueryDefinition", "*", ConditionContext::new())?;
        let language = input.query_language.unwrap_or_else(|| "CWLI".into());
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let id = match input.query_definition_id {
            Some(id) => {
                if !region.query_definitions.contains_key(&id) {
                    return Err(errors::resource_not_found(format!("Query definition does not exist: {id}")));
                }
                id
            }
            None => uuid(),
        };
        region.query_definitions.insert(
            id.clone(),
            types::QueryDefinition {
                query_language: Some(language),
                query_definition_id: Some(id.clone()),
                name: Some(input.name),
                query_string: Some(input.query_string),
                last_modified: Some(now_ms(ctx)),
                log_group_names: input.log_group_names,
                parameters: input.parameters,
            },
        );
        Ok(types::PutQueryDefinitionResponse { query_definition_id: Some(id) })
    }

    pub(crate) fn describe_query_definitions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeQueryDefinitionsRequest,
    ) -> Result<types::DescribeQueryDefinitionsResponse, ServiceError> {
        self.authorize(ctx, "DescribeQueryDefinitions", "*", ConditionContext::new())?;
        let st = self.lock();
        let mut defs: Vec<types::QueryDefinition> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| r.query_definitions.values().cloned().collect())
            .unwrap_or_default();
        defs.retain(|d| {
            input
                .query_definition_name_prefix
                .as_ref()
                .is_none_or(|p| d.name.as_deref().unwrap_or("").starts_with(p.as_str()))
                && input.query_language.as_ref().is_none_or(|l| d.query_language.as_ref() == Some(l))
        });
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        let (defs, next_token) =
            page(defs, input.next_token.as_deref(), input.max_results.unwrap_or(1000).clamp(1, 1000) as usize)?;
        Ok(types::DescribeQueryDefinitionsResponse { query_definitions: Some(defs), next_token })
    }

    pub(crate) fn delete_query_definition(
        &self,
        ctx: &RequestContext,
        input: types::DeleteQueryDefinitionRequest,
    ) -> Result<types::DeleteQueryDefinitionResponse, ServiceError> {
        self.authorize(ctx, "DeleteQueryDefinition", "*", ConditionContext::new())?;
        let mut st = self.lock();
        st.region(&ctx.caller.account_id, &ctx.region)
            .query_definitions
            .remove(&input.query_definition_id)
            .ok_or_else(|| {
                errors::resource_not_found(format!("Query definition does not exist: {}", input.query_definition_id))
            })?;
        Ok(types::DeleteQueryDefinitionResponse { success: true })
    }

    // ---- fields and records -------------------------------------------------

    pub(crate) fn get_log_group_fields(
        &self,
        ctx: &RequestContext,
        input: types::GetLogGroupFieldsRequest,
    ) -> Result<types::GetLogGroupFieldsResponse, ServiceError> {
        let g = name_or_identifier(ctx, input.log_group_name.as_deref(), input.log_group_identifier.as_deref())?;
        self.authorize_group(ctx, "GetLogGroupFields", &g, None, ConditionContext::new())?;
        let end = input.time.map_or(now_ms(ctx), |t| t * 1000);
        let start = end - 15 * 60_000;
        let st = self.lock();
        let group = st.group(&g)?;
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut total = 0usize;
        for s in group.streams.values() {
            for e in s.events.iter().filter(|e| e.timestamp >= start && e.timestamp <= end) {
                total += 1;
                for k in record(&g, &s.name, e).keys() {
                    if k != "@ptr" {
                        *counts.entry(k.clone()).or_default() += 1;
                    }
                }
            }
        }
        let fields = counts
            .into_iter()
            .map(|(name, n)| types::LogGroupField { name: Some(name), percent: (n * 100 / total.max(1)) as i32 })
            .collect();
        Ok(types::GetLogGroupFieldsResponse { log_group_fields: Some(fields) })
    }

    pub(crate) fn get_log_record(
        &self,
        ctx: &RequestContext,
        input: types::GetLogRecordRequest,
    ) -> Result<types::GetLogRecordResponse, ServiceError> {
        let not_found = || errors::resource_not_found("The specified log record does not exist.");
        let (mut g, stream, seq) = resolve_pointer(&input.log_record_pointer)
            .ok_or_else(|| errors::invalid_parameter("The specified logRecordPointer is not valid."))?;
        g.partition = ctx.partition.clone();
        self.authorize_group(ctx, "GetLogRecord", &g, Some(&stream), ConditionContext::new())?;
        if input.unmask {
            self.authorize_group(ctx, "Unmask", &g, None, ConditionContext::new())?;
        }
        let st = self.lock();
        let (_, e) = find_event(&st, &g, &stream, seq).ok_or_else(not_found)?;
        let mask = if input.unmask { Vec::new() } else { crate::policies::masks_for(&st, &g) };
        let mut out = BTreeMap::new();
        for (k, v) in record(&g, &stream, e) {
            if k == "@ptr" {
                continue;
            }
            let text = match v {
                V::Time(t) => t.to_string(),
                other => other.display().unwrap_or_default(),
            };
            out.insert(k, crate::policies::mask(&mask, e.ingestion_time, &text));
        }
        Ok(types::GetLogRecordResponse { log_record: Some(out) })
    }

    /// `GetLogObject`: the event behind a pointer, as `fields` events of
    /// at most 64 KiB each.
    pub(crate) fn get_log_object(
        &self,
        ctx: &RequestContext,
        input: types::GetLogObjectRequest,
    ) -> Result<types::GetLogObjectResponse, ServiceError> {
        let (mut g, stream, seq) = resolve_pointer(&input.log_object_pointer)
            .ok_or_else(|| errors::invalid_parameter("The specified logObjectPointer is not valid."))?;
        g.partition = ctx.partition.clone();
        self.authorize_group(ctx, "GetLogObject", &g, Some(&stream), ConditionContext::new())?;
        if input.unmask {
            self.authorize_group(ctx, "Unmask", &g, None, ConditionContext::new())?;
        }
        let st = self.lock();
        let (_, e) = find_event(&st, &g, &stream, seq)
            .ok_or_else(|| errors::resource_not_found("The specified log object does not exist."))?;
        let mask = if input.unmask { Vec::new() } else { crate::policies::masks_for(&st, &g) };
        let data = crate::policies::mask(&mask, e.ingestion_time, &e.message).into_bytes();
        let field_stream = data
            .chunks(64 * 1024)
            .map(|c| types::GetLogObjectResponseStream::Fields(types::FieldsData { data: Some(c.to_vec()) }))
            .collect();
        Ok(types::GetLogObjectResponse { field_stream })
    }

    /// `GetLogFields`: the fields of a data source's log events. MWS knows
    /// the standard fields every log event has.
    pub(crate) fn get_log_fields(
        &self,
        ctx: &RequestContext,
        input: types::GetLogFieldsRequest,
    ) -> Result<types::GetLogFieldsResponse, ServiceError> {
        self.authorize(ctx, "GetLogFields", "*", ConditionContext::new())?;
        let _ = input;
        let field = |name: &str, ty: &str| types::LogFieldsListItem {
            log_field_name: Some(name.to_string()),
            log_field_type: Some(types::LogFieldType { r#type: Some(ty.to_string()), element: None, fields: None }),
        };
        Ok(types::GetLogFieldsResponse {
            log_fields: Some(vec![
                field("@timestamp", "timestamp"),
                field("@message", "string"),
                field("@logStream", "string"),
                field("@log", "string"),
                field("@ingestionTime", "timestamp"),
            ]),
        })
    }
}
