//! Export tasks (log events into S3) and import tasks (from CloudTrail
//! Lake, which MWS does not emulate).

use std::io::Write;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_s3::{ServicePutError, ServicePutObject};

use crate::events::cutoff;
use crate::generated::{errors, types};
use crate::names::{arn, now_ms, page, uuid, GroupRef};
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
        let prefix = input.destination_prefix.clone().unwrap_or_else(|| "exportedlogs".into());
        let now = now_ms(ctx);
        // Collect what to export before touching S3.
        let exports: Vec<(String, Vec<u8>)> = {
            let st = self.lock();
            let group = st.group(&g)?;
            let floor = cutoff(group, now).max(input.from);
            group
                .streams
                .values()
                .filter(|s| input.log_stream_name_prefix.as_ref().is_none_or(|p| s.name.starts_with(p.as_str())))
                .filter_map(|s| {
                    let mut text = String::new();
                    for e in s.events.iter().filter(|e| e.timestamp >= floor && e.timestamp <= input.to) {
                        text.push_str(&iso8601(e.timestamp));
                        text.push(' ');
                        text.push_str(&e.message);
                        text.push('\n');
                    }
                    (!text.is_empty()).then(|| (s.name.clone(), gzip(text.as_bytes())))
                })
                .collect()
        };
        let s3 = self.s3.as_ref().ok_or_else(|| {
            errors::invalid_parameter("The given bucket does not exist. Please make sure the bucket is valid.")
        })?;
        let task_id = uuid();
        let principal = format!("logs.{}.amazonaws.com", ctx.region);
        let source_arn = format!("{}:*", g.arn());
        let base = ServicePutObject {
            bucket: &input.destination,
            key: "",
            body: Vec::new(),
            content_type: "application/gzip",
            service_principal: &principal,
            source_account: &ctx.caller.account_id,
            source_arn: &source_arn,
            acl: Some("bucket-owner-full-control"),
            partition: &ctx.partition,
        };
        let failed = |e: ServicePutError, call: &str| {
            match e {
            ServicePutError::NoSuchBucket => {
                errors::invalid_parameter("The given bucket does not exist. Please make sure the bucket is valid.")
            }
            _ => errors::invalid_parameter(format!(
                "{call} call on the given bucket failed. Please check if CloudWatch Logs has been granted permission to perform this operation."
            )),
        }
        };
        let test_key = format!("{prefix}/aws-logs-write-test");
        let probe = ServicePutObject { key: &test_key, content_type: "text/plain", ..base.clone() };
        s3.check_service_access(&probe, &["s3:GetBucketAcl"]).map_err(|e| failed(e, "GetBucketAcl"))?;
        s3.put_object_as_service(ServicePutObject { body: b"Permission Check Successful".to_vec(), ..probe })
            .map_err(|e| failed(e, "PutObject"))?;
        for (stream, body) in exports {
            let key = format!("{prefix}/{task_id}/{stream}/000000.gz");
            s3.put_object_as_service(ServicePutObject { key: &key, body, ..base.clone() })
                .map_err(|e| failed(e, "PutObject"))?;
        }
        let task = types::ExportTask {
            task_id: Some(task_id.clone()),
            task_name: input.task_name,
            log_group_name: Some(g.name.clone()),
            from: Some(input.from),
            to: Some(input.to),
            destination: Some(input.destination),
            destination_prefix: Some(prefix),
            status: Some(types::ExportTaskStatus {
                code: Some("COMPLETED".into()),
                message: Some("Completed successfully".into()),
            }),
            execution_info: Some(types::ExportTaskExecutionInfo {
                creation_time: Some(now),
                completion_time: Some(now_ms(ctx)),
            }),
        };
        self.lock().region(&ctx.caller.account_id, &ctx.region).export_tasks.insert(task_id.clone(), task);
        Ok(types::CreateExportTaskResponse { task_id: Some(task_id) })
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
        t.status =
            Some(types::ExportTaskStatus { code: Some("CANCELLED".into()), message: Some("Cancelled by user".into()) });
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
        // CloudTrail Lake is not emulated, so no event data store exists.
        Err(errors::resource_not_found(format!("The event data store {} does not exist.", input.import_source_arn)))
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
