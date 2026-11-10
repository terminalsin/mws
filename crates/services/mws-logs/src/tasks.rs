//! Export tasks (log events into S3) and import tasks (CloudTrail Lake
//! event data store events into a managed log group). Both run in the
//! background (see [`crate::background`]).

use std::io::Write;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_s3::{ServicePutError, ServicePutObject};

use crate::events::cutoff;
use crate::generated::{errors, types};
use crate::names::{arn, now_ms, page, uuid, GroupRef};
use crate::state::{Event, ExportSpec, ImportTask, LogGroup, LogStream};

/// Imports an account may have `IN_PROGRESS` at a time.
const MAX_ACTIVE_IMPORTS: usize = 3;
use crate::Logs;

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).expect("writing to a Vec cannot fail");
    e.finish().expect("writing to a Vec cannot fail")
}

fn iso8601(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

fn status(code: &str, message: &str) -> types::ExportTaskStatus {
    types::ExportTaskStatus { code: Some(code.into()), message: Some(message.into()) }
}

/// Whether the account has an export task `PENDING` or `RUNNING`: it may
/// have only one at a time.
fn active_export(r: &crate::state::Region) -> bool {
    r.export_tasks
        .values()
        .any(|t| matches!(t.status.as_ref().and_then(|s| s.code.as_deref()), Some("PENDING" | "RUNNING")))
}

fn export_limit() -> ServiceError {
    errors::limit_exceeded("Resource limit exceeded.")
}

fn put_failed(e: ServicePutError, call: &str) -> ServiceError {
    match e {
        ServicePutError::NoSuchBucket => {
            errors::invalid_parameter("The given bucket does not exist. Please make sure the bucket is valid.")
        }
        _ => errors::invalid_parameter(format!(
            "{call} call on the given bucket failed. Please check if CloudWatch Logs has been granted permission to perform this operation."
        )),
    }
}

impl Logs {
    pub(crate) fn create_export_task(
        &self,
        ctx: &RequestContext,
        input: types::CreateExportTaskRequest,
    ) -> Result<types::CreateExportTaskResponse, ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "CreateExportTask", &g, None, ConditionContext::new())?;
        if input.from > input.to {
            return Err(errors::invalid_parameter("The from time must be before the to time."));
        }
        {
            let st = self.lock();
            if st.region_ref(&ctx.caller.account_id, &ctx.region).is_some_and(active_export) {
                return Err(export_limit());
            }
            st.group(&g)?;
        }
        let prefix = input.destination_prefix.clone().unwrap_or_else(|| "exportedlogs".into());
        let now = now_ms(ctx);
        let s3 = self.s3.as_ref().ok_or_else(|| {
            errors::invalid_parameter("The given bucket does not exist. Please make sure the bucket is valid.")
        })?;
        // CloudWatch Logs checks the bucket before it accepts the task.
        let principal = format!("logs.{}.amazonaws.com", ctx.region);
        let source_arn = format!("{}:*", g.arn());
        let test_key = format!("{prefix}/aws-logs-write-test");
        let probe = ServicePutObject {
            bucket: &input.destination,
            key: &test_key,
            body: Vec::new(),
            content_type: "text/plain",
            service_principal: &principal,
            source_account: &ctx.caller.account_id,
            source_arn: &source_arn,
            acl: Some("bucket-owner-full-control"),
            partition: &ctx.partition,
        };
        s3.check_service_access(&probe, &["s3:GetBucketAcl"]).map_err(|e| put_failed(e, "GetBucketAcl"))?;
        s3.put_object_as_service(ServicePutObject { body: b"Permission Check Successful".to_vec(), ..probe })
            .map_err(|e| put_failed(e, "PutObject"))?;
        let task_id = uuid();
        let task = types::ExportTask {
            task_id: Some(task_id.clone()),
            task_name: input.task_name,
            log_group_name: Some(g.name.clone()),
            from: Some(input.from),
            to: Some(input.to),
            destination: Some(input.destination),
            destination_prefix: Some(prefix),
            status: Some(status("PENDING", "Pending")),
            execution_info: Some(types::ExportTaskExecutionInfo { creation_time: Some(now), completion_time: None }),
        };
        {
            let mut st = self.lock();
            let region = st.region(&ctx.caller.account_id, &ctx.region);
            if active_export(region) {
                return Err(export_limit());
            }
            region.export_tasks.insert(task_id.clone(), task);
            region.export_specs.insert(
                task_id.clone(),
                ExportSpec { partition: ctx.partition.clone(), log_stream_name_prefix: input.log_stream_name_prefix },
            );
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            self.spawn_export(ctx.caller.account_id.clone(), ctx.region.clone(), task_id.clone());
        } else if self.start_export(&ctx.caller.account_id, &ctx.region, &task_id) {
            self.finish_export(&ctx.caller.account_id, &ctx.region, &task_id);
        }
        Ok(types::CreateExportTaskResponse { task_id: Some(task_id) })
    }

    /// `PENDING` → `RUNNING`; false when the task is no longer pending
    /// (cancelled).
    pub(crate) fn start_export(&self, account: &str, region: &str, id: &str) -> bool {
        let mut st = self.lock();
        let Some(t) = st.region(account, region).export_tasks.get_mut(id) else { return false };
        if t.status.as_ref().and_then(|s| s.code.as_deref()) != Some("PENDING") {
            return false;
        }
        t.status = Some(status("RUNNING", "Started successfully"));
        true
    }

    /// A task found `RUNNING` in loaded state runs again from the start.
    pub(crate) fn reset_export(&self, account: &str, region: &str, id: &str) {
        let mut st = self.lock();
        if let Some(t) = st.region(account, region).export_tasks.get_mut(id) {
            t.status = Some(status("PENDING", "Pending"));
        }
    }

    /// Write a running task's events into S3 (one gzipped object per log
    /// stream, masked by the data protection policies) and complete it.
    pub(crate) fn finish_export(&self, account: &str, region: &str, id: &str) {
        let now = self.emulated_now_ms();
        let found = {
            let mut st = self.lock();
            let r = st.region(account, region);
            let spec = r.export_specs.get(id).cloned().unwrap_or_default();
            r.export_tasks.get(id).cloned().map(|t| (t, spec))
        };
        let Some((task, spec)) = found else { return };
        if task.status.as_ref().and_then(|s| s.code.as_deref()) != Some("RUNNING") {
            return;
        }
        let g = GroupRef {
            partition: if spec.partition.is_empty() { "aws".into() } else { spec.partition.clone() },
            account: account.to_string(),
            region: region.to_string(),
            name: task.log_group_name.clone().unwrap_or_default(),
        };
        let (from, to) = (task.from.unwrap_or(0), task.to.unwrap_or(0));
        let collected: Result<Vec<(String, Vec<u8>)>, String> = {
            let st = self.lock();
            match st.group(&g) {
                Err(_) => Err("The specified log group does not exist.".into()),
                Ok(group) => {
                    let masks = crate::policies::masks_for(&st, &g);
                    let floor = cutoff(group, now).max(from);
                    Ok(group
                        .streams
                        .values()
                        .filter(|s| spec.log_stream_name_prefix.as_ref().is_none_or(|p| s.name.starts_with(p.as_str())))
                        .filter_map(|s| {
                            let mut text = String::new();
                            for e in s.events.iter().filter(|e| e.timestamp >= floor && e.timestamp <= to) {
                                text.push_str(&iso8601(e.timestamp));
                                text.push(' ');
                                text.push_str(&crate::policies::mask(&masks, e.ingestion_time, &e.message));
                                text.push('\n');
                            }
                            (!text.is_empty()).then(|| (s.name.clone(), gzip(text.as_bytes())))
                        })
                        .collect())
                }
            }
        };
        let written = collected.and_then(|exports| {
            let s3 =
                self.s3.as_ref().ok_or("The given bucket does not exist. Please make sure the bucket is valid.")?;
            let principal = format!("logs.{region}.amazonaws.com");
            let source_arn = format!("{}:*", g.arn());
            let prefix = task.destination_prefix.clone().unwrap_or_default();
            let bucket = task.destination.clone().unwrap_or_default();
            for (stream, body) in exports {
                let key = format!("{prefix}/{id}/{stream}/000000.gz");
                s3.put_object_as_service(ServicePutObject {
                    bucket: &bucket,
                    key: &key,
                    body,
                    content_type: "application/gzip",
                    service_principal: &principal,
                    source_account: account,
                    source_arn: &source_arn,
                    acl: Some("bucket-owner-full-control"),
                    partition: &g.partition,
                })
                .map_err(|e| put_failed(e, "PutObject").message)?;
            }
            Ok(())
        });
        let mut st = self.lock();
        let r = st.region(account, region);
        r.export_specs.remove(id);
        let Some(t) = r.export_tasks.get_mut(id) else { return };
        // Cancelled while it ran: stays cancelled.
        if t.status.as_ref().and_then(|s| s.code.as_deref()) != Some("RUNNING") {
            return;
        }
        t.status = Some(match written {
            Ok(()) => status("COMPLETED", "Completed successfully"),
            Err(m) => status("FAILED", &m),
        });
        if let Some(info) = t.execution_info.as_mut() {
            info.completion_time = Some(now);
        }
    }

    pub(crate) fn describe_export_tasks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeExportTasksRequest,
    ) -> Result<types::DescribeExportTasksResponse, ServiceError> {
        self.authorize(ctx, "DescribeExportTasks", "*", ConditionContext::new())?;
        let st = self.lock();
        let mut out: Vec<types::ExportTask> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| r.export_tasks.values().cloned().collect())
            .unwrap_or_default();
        out.retain(|t| {
            input.task_id.as_ref().is_none_or(|id| t.task_id.as_ref() == Some(id))
                && input.status_code.as_ref().is_none_or(|c| t.status.as_ref().and_then(|s| s.code.as_ref()) == Some(c))
        });
        out.sort_by_key(|t| std::cmp::Reverse(t.execution_info.as_ref().and_then(|e| e.creation_time)));
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeExportTasksResponse { export_tasks: Some(out), next_token })
    }

    pub(crate) fn cancel_export_task(
        &self,
        ctx: &RequestContext,
        input: types::CancelExportTaskRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "CancelExportTask", "*", ConditionContext::new())?;
        let mut st = self.lock();
        let t = st
            .region(&ctx.caller.account_id, &ctx.region)
            .export_tasks
            .get_mut(&input.task_id)
            .ok_or_else(|| errors::resource_not_found("The specified export task does not exist."))?;
        let code = t.status.as_ref().and_then(|s| s.code.clone()).unwrap_or_default();
        if !matches!(code.as_str(), "PENDING" | "RUNNING") {
            return Err(errors::invalid_operation("The specified export task has already finished."));
        }
        t.status = Some(status("CANCELLED", "Cancelled by user"));
        if let Some(info) = t.execution_info.as_mut() {
            info.completion_time = Some(now_ms(ctx));
        }
        st.region(&ctx.caller.account_id, &ctx.region).export_specs.remove(&input.task_id);
        Ok(())
    }

    // ---- import tasks ------------------------------------------------------------

    fn no_import(id: &str) -> ServiceError {
        errors::resource_not_found(format!("Import task {id} does not exist."))
    }

    pub(crate) fn create_import_task(
        &self,
        ctx: &RequestContext,
        input: types::CreateImportTaskRequest,
    ) -> Result<types::CreateImportTaskResponse, ServiceError> {
        self.authorize(ctx, "CreateImportTask", &arn(ctx, "log-group:*"), ConditionContext::new())?;
        let parts: Vec<&str> = input.import_source_arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[2] != "cloudtrail" || !parts[5].starts_with("eventdatastore/") {
            return Err(errors::invalid_parameter(format!(
                "Invalid importSourceArn: {}. It must be a CloudTrail Lake event data store ARN.",
                input.import_source_arn
            )));
        }
        if !input.import_role_arn.starts_with("arn:") {
            return Err(errors::invalid_parameter(format!("Invalid importRoleArn: {}", input.import_role_arn)));
        }
        let filter = input.import_filter.clone();
        if let Some(f) = &filter {
            if let (Some(a), Some(b)) = (f.start_event_time, f.end_event_time) {
                if a > b {
                    return Err(errors::invalid_parameter(
                        "The startEventTime must be less than or equal to endEventTime.",
                    ));
                }
            }
        }
        let not_found =
            || errors::resource_not_found(format!("The event data store {} does not exist.", input.import_source_arn));
        let lake = self.lake.read().expect("Logs lake lock poisoned").clone().ok_or_else(not_found)?;
        let data = lake.read(&input.import_source_arn).ok_or_else(not_found)?;
        if data.status != "ENABLED" {
            return Err(errors::invalid_operation(format!(
                "The event data store {} is not in an ACTIVE state.",
                input.import_source_arn
            )));
        }
        let store_id = parts[5].trim_start_matches("eventdatastore/").to_string();
        let g = GroupRef::own(ctx, &format!("/aws/cloudtrail/{store_id}"));
        // The caller must be able to read the source and pass the role.
        let mut pass = ConditionContext::new();
        pass.insert("iam:AssociatedResourceARN".into(), vec![format!("{}:*", g.arn())]);
        pass.insert("iam:PassedToService".into(), vec!["cloudtrail.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", &input.import_role_arn, pass)?;
        ctx.authorize("cloudtrail:GetEventDataStoreData", &input.import_source_arn, ConditionContext::new())?;
        // The role must trust cloudtrail.amazonaws.com and read the store.
        if let Some(sts) = &self.sts {
            let cannot = || {
                errors::access_denied(format!(
                    "Unable to assume role {}. Make sure its trust policy allows cloudtrail.amazonaws.com.",
                    input.import_role_arn
                ))
            };
            let creds = sts
                .assume_role_as_service(&mws_sts::ServiceAssume {
                    role_arn: &input.import_role_arn,
                    service_principal: "cloudtrail.amazonaws.com",
                    session_name: "CWLImportTask",
                    duration_seconds: 3600,
                    source_account: Some(&ctx.caller.account_id),
                    source_arn: Some(&input.import_source_arn),
                    now: ctx.received_at,
                })
                .map_err(|_| cannot())?;
            let resolved = sts
                .credential_store()
                .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
                .ok()
                .flatten()
                .ok_or_else(cannot)?;
            let rctx = RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() };
            rctx.authorize("cloudtrail:GetEventDataStoreData", &input.import_source_arn, ConditionContext::new())?;
            for action in ["logs:CreateLogGroup", "logs:CreateLogStream"] {
                rctx.authorize(action, &g.resource(None), ConditionContext::new())?;
            }
        }
        let now = now_ms(ctx);
        let id = uuid();
        let destination = g.arn();
        {
            let mut st = self.lock();
            let region = st.region(&ctx.caller.account_id, &ctx.region);
            let active = region
                .import_tasks
                .values()
                .filter(|t| t.record.import_status.as_deref() == Some("IN_PROGRESS"))
                .count();
            if active >= MAX_ACTIVE_IMPORTS {
                return Err(errors::invalid_operation(
                    "There can be no more than 3 active imports per account at a given time.",
                ));
            }
            region.log_groups.entry(g.name.clone()).or_insert_with(|| LogGroup {
                name: g.name.clone(),
                creation_time: now,
                class: "STANDARD".into(),
                ..LogGroup::default()
            });
            region.import_tasks.insert(
                id.clone(),
                ImportTask {
                    record: types::Import {
                        import_id: Some(id.clone()),
                        import_source_arn: Some(input.import_source_arn.clone()),
                        import_status: Some("IN_PROGRESS".into()),
                        import_destination_arn: Some(destination.clone()),
                        import_statistics: Some(types::ImportStatistics { bytes_imported: Some(0) }),
                        import_filter: filter,
                        creation_time: Some(now),
                        last_updated_time: Some(now),
                        error_message: None,
                    },
                    batches: Vec::new(),
                    log_group: g.name.clone(),
                    partition: ctx.partition.clone(),
                },
            );
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            self.spawn_import(ctx.caller.account_id.clone(), ctx.region.clone(), id.clone());
        } else {
            self.run_import(&ctx.caller.account_id, &ctx.region, &id);
        }
        Ok(types::CreateImportTaskResponse {
            import_id: Some(id),
            import_destination_arn: Some(destination),
            creation_time: Some(now),
        })
    }

    /// Copy an import's events into its managed log group, one batch per
    /// hour of `eventTime`, each into the stream
    /// `<account>_CloudTrail_<region>` of the event. Stops between batches
    /// when the import is cancelled.
    pub(crate) fn run_import(&self, account: &str, region: &str, id: &str) {
        let task = {
            let st = self.lock();
            st.region_ref(account, region).and_then(|r| r.import_tasks.get(id)).cloned()
        };
        let Some(task) = task else { return };
        if task.record.import_status.as_deref() != Some("IN_PROGRESS") {
            return;
        }
        let g = GroupRef {
            partition: if task.partition.is_empty() { "aws".into() } else { task.partition.clone() },
            account: account.to_string(),
            region: region.to_string(),
            name: task.log_group.clone(),
        };
        let lake = self.lake.read().expect("Logs lake lock poisoned").clone();
        let source = task.record.import_source_arn.clone().unwrap_or_default();
        let finish = |status: &str, error: Option<String>| {
            let now = self.emulated_now_ms();
            let mut st = self.lock();
            if let Some(t) = st.region(account, region).import_tasks.get_mut(id) {
                if t.record.import_status.as_deref() == Some("IN_PROGRESS") {
                    t.record.import_status = Some(status.into());
                    t.record.error_message = error;
                    t.record.last_updated_time = Some(now);
                }
            }
        };
        let Some(data) = lake.and_then(|l| l.read(&source)) else {
            return finish("FAILED", Some(format!("The event data store {source} does not exist.")));
        };
        let filter = task.record.import_filter.clone().unwrap_or_default();
        let mut batches: std::collections::BTreeMap<i64, Vec<crate::lake::LakeEvent>> = Default::default();
        for e in data.events {
            if filter.start_event_time.is_some_and(|s| e.event_time < s)
                || filter.end_event_time.is_some_and(|x| e.event_time > x)
            {
                continue;
            }
            batches.entry(e.event_time.div_euclid(3_600_000)).or_default().push(e);
        }
        for (_, events) in batches {
            let now = self.emulated_now_ms();
            let batch_id = uuid();
            let mut written: Vec<(String, Vec<Event>)> = Vec::new();
            let bytes: i64 = events.iter().map(|e| e.json.len() as i64).sum();
            {
                let mut st = self.lock();
                let cancelled = st
                    .region_ref(account, region)
                    .and_then(|r| r.import_tasks.get(id))
                    .is_none_or(|t| t.record.import_status.as_deref() != Some("IN_PROGRESS"));
                if cancelled {
                    return;
                }
                let mut seq = st.next_seq;
                let outcome = match st.group_mut(&g) {
                    Err(_) => Err("The specified log group does not exist.".to_string()),
                    Ok(group) => {
                        for e in events {
                            let name = format!("{}_CloudTrail_{}", e.account, e.region);
                            let stream = group.streams.entry(name.clone()).or_insert_with(|| LogStream {
                                name: name.clone(),
                                creation_time: now,
                                ..LogStream::default()
                            });
                            let ev = Event {
                                timestamp: e.event_time,
                                ingestion_time: now,
                                message: e.json,
                                seq,
                                transformed: None,
                            };
                            seq += 1;
                            stream.first_event_timestamp =
                                Some(stream.first_event_timestamp.map_or(ev.timestamp, |t| t.min(ev.timestamp)));
                            stream.last_event_timestamp =
                                Some(stream.last_event_timestamp.map_or(ev.timestamp, |t| t.max(ev.timestamp)));
                            stream.last_ingestion_time = Some(now);
                            match written.iter_mut().find(|(n, _)| *n == name) {
                                Some((_, list)) => list.push(ev.clone()),
                                None => written.push((name.clone(), vec![ev.clone()])),
                            }
                            stream.insert(ev);
                        }
                        Ok(())
                    }
                };
                st.next_seq = seq;
                let t = st.region(account, region).import_tasks.get_mut(id).expect("checked above");
                match &outcome {
                    Ok(()) => {
                        t.batches.push(types::ImportBatch {
                            batch_id,
                            status: "COMPLETED".into(),
                            error_message: None,
                        });
                        let stats = t.record.import_statistics.get_or_insert_with(Default::default);
                        stats.bytes_imported = Some(stats.bytes_imported.unwrap_or(0) + bytes);
                        t.record.last_updated_time = Some(now);
                    }
                    Err(m) => {
                        t.batches.push(types::ImportBatch {
                            batch_id,
                            status: "FAILED".into(),
                            error_message: Some(m.clone()),
                        });
                    }
                }
                if let Err(m) = outcome {
                    drop(st);
                    return finish("FAILED", Some(m));
                }
            }
            for (stream, events) in written {
                self.after_store(None, &g, &stream, &events, now);
            }
        }
        finish("COMPLETED", None);
    }

    pub(crate) fn describe_import_tasks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImportTasksRequest,
    ) -> Result<types::DescribeImportTasksResponse, ServiceError> {
        self.authorize(ctx, "DescribeImportTasks", "*", ConditionContext::new())?;
        let st = self.lock();
        let out: Vec<types::Import> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.import_tasks
                    .values()
                    .map(|t| t.record.clone())
                    .filter(|t| input.import_id.as_ref().is_none_or(|i| t.import_id.as_ref() == Some(i)))
                    .filter(|t| input.import_status.as_ref().is_none_or(|s| t.import_status.as_ref() == Some(s)))
                    .filter(|t| {
                        input.import_source_arn.as_ref().is_none_or(|a| t.import_source_arn.as_ref() == Some(a))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(id) = &input.import_id {
            if out.is_empty() {
                return Err(Self::no_import(id));
            }
        }
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeImportTasksResponse { imports: Some(out), next_token })
    }

    pub(crate) fn describe_import_task_batches(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImportTaskBatchesRequest,
    ) -> Result<types::DescribeImportTaskBatchesResponse, ServiceError> {
        self.authorize(ctx, "DescribeImportTaskBatches", "*", ConditionContext::new())?;
        let st = self.lock();
        let t = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.import_tasks.get(&input.import_id))
            .ok_or_else(|| Self::no_import(&input.import_id))?;
        let batches: Vec<_> = t
            .batches
            .iter()
            .filter(|b| input.batch_import_status.as_ref().is_none_or(|s| s.contains(&b.status)))
            .cloned()
            .collect();
        let (batches, next_token) =
            page(batches, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeImportTaskBatchesResponse {
            import_source_arn: t.record.import_source_arn.clone(),
            import_id: Some(input.import_id),
            import_batches: Some(batches),
            next_token,
        })
    }

    pub(crate) fn cancel_import_task(
        &self,
        ctx: &RequestContext,
        input: types::CancelImportTaskRequest,
    ) -> Result<types::CancelImportTaskResponse, ServiceError> {
        self.authorize(ctx, "CancelImportTask", "*", ConditionContext::new())?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let t = st
            .region(&ctx.caller.account_id, &ctx.region)
            .import_tasks
            .get_mut(&input.import_id)
            .ok_or_else(|| Self::no_import(&input.import_id))?;
        if t.record.import_status.as_deref() != Some("IN_PROGRESS") {
            return Err(errors::invalid_operation("The import task is not in progress."));
        }
        t.record.import_status = Some("CANCELLED".into());
        t.record.last_updated_time = Some(now);
        Ok(types::CancelImportTaskResponse {
            import_id: t.record.import_id.clone(),
            import_statistics: t.record.import_statistics.clone(),
            import_status: t.record.import_status.clone(),
            creation_time: t.record.creation_time,
            last_updated_time: Some(now),
        })
    }
}
