//! Exports of snapshots and clusters to S3, as Apache Parquet.
//!
//! The export reads every table out of the source's data (the backend
//! starts a throwaway copy of it), writes one Parquet file per table under
//! `<prefix>/<export id>/<database>/<schema>.<table>/1/`, then
//! `export_info_<id>.json` and `export_tables_info_<id>_from_1_to_<n>.json`,
//! all as the export's IAM role with SSE-KMS under the export's key.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_parquet::{Column, Kind as PqKind, Value};
use serde_json::json;

use super::authorize;
use crate::backend::{DatabaseSpec, TableData};
use crate::catalog;
use crate::generated::{errors, types as t};
use crate::util::{account_of, arn, identifier, invalid_parameter, opt, paginate, parse_arn, resource_id, Filters};
use crate::Rds;

const DONE: &[&str] = &["COMPLETE", "FAILED", "CANCELED"];

fn not_found(id: &str) -> ServiceError {
    errors::export_task_not_found_fault(format!("The export task with the ID {id} can't be found."))
}

/// What an export reads from.
#[derive(Clone)]
enum Source {
    /// A backend snapshot that already holds the data.
    Snapshot { backend: Option<String>, spec: Option<DatabaseSpec> },
    /// A live cluster, copied when the export starts.
    Cluster { backend: Option<String>, spec: Option<DatabaseSpec> },
}

/// S3 bucket naming rules, as RDS checks them before starting.
fn check_bucket(name: &str) -> Result<(), ServiceError> {
    let ok = (3..=63).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(errors::invalid_s3_bucket_fault(format!("The S3 bucket {name} is not valid.")))
    }
}

/// `ExportOnly` entries: `database`, `database.schema` or
/// `database.schema.table` (PostgreSQL), `database` or `database.table`
/// (MySQL).
fn check_export_only(list: &[String]) -> Result<(), ServiceError> {
    for e in list {
        let parts = e.split('.').count();
        if e.is_empty() || parts > 3 || e.split('.').any(str::is_empty) {
            return Err(errors::invalid_export_only_fault(format!("The ExportOnly parameter value {e} is not valid.")));
        }
    }
    Ok(())
}

fn included(only: &[String], t: &TableData) -> bool {
    if only.is_empty() {
        return true;
    }
    let mut names = vec![t.database.clone()];
    match &t.schema {
        Some(s) => {
            names.push(format!("{}.{s}", t.database));
            names.push(format!("{}.{s}.{}", t.database, t.table));
        }
        None => names.push(format!("{}.{}", t.database, t.table)),
    }
    only.iter().any(|o| names.contains(o))
}

fn column_kind(sql: &str) -> PqKind {
    let sql = sql.to_ascii_lowercase();
    match sql.as_str() {
        "smallint" | "integer" | "bigint" | "int" | "tinyint" | "mediumint" => PqKind::Int,
        "real" | "double precision" | "double" | "float" => PqKind::Double,
        "boolean" => PqKind::Bool,
        _ => PqKind::Str,
    }
}

fn exported_type(kind: PqKind) -> &'static str {
    match kind {
        PqKind::Int => "int64",
        PqKind::Double => "double",
        PqKind::Bool => "boolean",
        PqKind::Str | PqKind::Time => "string",
    }
}

fn cell(kind: PqKind, v: Option<&serde_json::Value>) -> Value {
    use serde_json::Value as J;
    match v {
        None | Some(J::Null) => Value::Null,
        Some(J::Bool(b)) => match kind {
            PqKind::Bool => Value::Bool(*b),
            PqKind::Int => Value::Int(i64::from(*b)),
            _ => Value::Str(b.to_string()),
        },
        Some(J::Number(n)) => match kind {
            PqKind::Int => n.as_i64().map(Value::Int).unwrap_or_else(|| Value::Str(n.to_string())),
            PqKind::Double => n.as_f64().map(Value::Double).unwrap_or(Value::Null),
            PqKind::Bool => Value::Bool(n.as_i64() != Some(0)),
            _ => Value::Str(n.to_string()),
        },
        Some(J::String(s)) => match kind {
            PqKind::Int => s.parse().map(Value::Int).unwrap_or_else(|_| Value::Str(s.clone())),
            PqKind::Double => s.parse().map(Value::Double).unwrap_or(Value::Null),
            PqKind::Bool => Value::Bool(matches!(s.as_str(), "t" | "true" | "1")),
            _ => Value::Str(s.clone()),
        },
        Some(other) => Value::Str(other.to_string()),
    }
}

/// A table's Parquet file.
fn parquet(t: &TableData) -> Vec<u8> {
    let cols: Vec<Column> =
        t.columns.iter().map(|(name, sql)| Column::new(name.clone(), column_kind(sql), false)).collect();
    let rows: Vec<Vec<Value>> =
        t.rows.iter().map(|row| cols.iter().map(|c| cell(c.kind, row.get(&c.name))).collect()).collect();
    mws_parquet::write(&cols, &rows, "MWS RDS export")
}

fn target(t: &TableData) -> String {
    match &t.schema {
        Some(s) => format!("{}.{s}.{}", t.database, t.table),
        None => format!("{}.{}", t.database, t.table),
    }
}

fn prefix_of(task: &t::ExportTask) -> String {
    let id = task.export_task_identifier.clone().unwrap_or_default();
    match task.s3_prefix.as_deref().map(|p| p.trim_matches('/')).filter(|p| !p.is_empty()) {
        Some(p) => format!("{p}/{id}"),
        None => id,
    }
}

impl Rds {
    fn export_task(&self, ctx: &RequestContext, id: &str) -> Option<t::ExportTask> {
        self.with_region(ctx, |r| r.export_tasks.get(id).cloned())
    }

    fn update_export(
        &self,
        ctx: &RequestContext,
        id: &str,
        f: impl FnOnce(&mut t::ExportTask),
    ) -> Option<t::ExportTask> {
        self.with_region(ctx, |r| {
            let task = r.export_tasks.get_mut(id)?;
            f(task);
            Some(task.clone())
        })
    }

    pub(crate) async fn start_export_task_op(
        &self,
        ctx: &RequestContext,
        input: t::StartExportTaskMessage,
    ) -> Result<t::ExportTask, ServiceError> {
        let id = identifier("ExportTaskIdentifier", &input.export_task_identifier, 60)?;
        let only = input.export_only.clone().unwrap_or_default();
        check_export_only(&only)?;
        check_bucket(&input.s3_bucket_name)?;
        if input.iam_role_arn.is_empty() {
            return Err(invalid_parameter("IamRoleArn is required."));
        }
        let (_, src_account, kind, name) = parse_arn(&input.source_arn)
            .ok_or_else(|| invalid_parameter(format!("The source ARN {} is not valid.", input.source_arn)))?;
        if src_account != account_of(ctx) {
            return Err(invalid_parameter(format!("The source ARN {} is not valid.", input.source_arn)));
        }
        authorize(ctx, "StartExportTask", &input.source_arn, ConditionContext::new())?;
        ctx.authorize("iam:PassRole", &input.iam_role_arn, ConditionContext::new())?;
        let runs = self.backend().runs_databases();
        let tmp_name = || format!("export-{}", resource_id("").to_ascii_lowercase());
        let (source, source_type, snapshot_time) = match kind.as_str() {
            "snapshot" => {
                let s = self
                    .with_region(ctx, |r| r.snapshots.get(&name).cloned())
                    .ok_or_else(|| errors::db_snapshot_not_found_fault(format!("DBSnapshot {name} not found.")))?;
                if s.snapshot.status.as_deref() != Some("available") {
                    return Err(errors::invalid_export_source_state_fault(format!(
                        "The snapshot {name} must be available to export."
                    )));
                }
                let spec = catalog::engine(s.snapshot.engine.as_deref().unwrap_or_default()).map(|e| DatabaseSpec {
                    name: tmp_name(),
                    account_id: account_of(ctx),
                    region: ctx.region.clone(),
                    identifier: name.clone(),
                    engine: e.name.to_string(),
                    kind: e.kind,
                    image: s.image.clone(),
                    master_username: s.snapshot.master_username.clone().unwrap_or_default(),
                    master_password: s.master_password.clone(),
                    database_name: s.db_name.clone(),
                    parameters: Vec::new(),
                    memory_mib: 1024,
                });
                (
                    Source::Snapshot { backend: (runs && s.has_data).then(|| s.backend_name.clone()), spec },
                    "SNAPSHOT",
                    s.snapshot.snapshot_create_time,
                )
            }
            "cluster-snapshot" => {
                let s = self.with_region(ctx, |r| r.cluster_snapshots.get(&name).cloned()).ok_or_else(|| {
                    errors::db_cluster_snapshot_not_found_fault(format!("DBClusterSnapshot {name} not found."))
                })?;
                if s.snapshot.status.as_deref() != Some("available") {
                    return Err(errors::invalid_export_source_state_fault(format!(
                        "The snapshot {name} must be available to export."
                    )));
                }
                let spec = catalog::engine(s.snapshot.engine.as_deref().unwrap_or_default()).map(|e| DatabaseSpec {
                    name: tmp_name(),
                    account_id: account_of(ctx),
                    region: ctx.region.clone(),
                    identifier: name.clone(),
                    engine: e.name.to_string(),
                    kind: e.kind,
                    image: s.image.clone(),
                    master_username: s.snapshot.master_username.clone().unwrap_or_default(),
                    master_password: s.master_password.clone(),
                    database_name: s.database_name.clone(),
                    parameters: Vec::new(),
                    memory_mib: 1024,
                });
                (
                    Source::Snapshot { backend: (runs && s.has_data).then(|| s.backend_name.clone()), spec },
                    "SNAPSHOT",
                    s.snapshot.snapshot_create_time,
                )
            }
            "cluster" => {
                let (status, spec) = self
                    .with_region(ctx, |r| {
                        r.clusters.get(&name).map(|c| (c.cluster.status.clone(), self.cluster_spec(r, c, ctx)))
                    })
                    .ok_or_else(|| errors::db_cluster_not_found_fault(format!("DBCluster {name} not found.")))?;
                if status.as_deref() != Some("available") {
                    return Err(errors::invalid_export_source_state_fault(format!(
                        "The DB cluster {name} must be available to export."
                    )));
                }
                let backend = runs.then(|| spec.name.clone());
                let spec = DatabaseSpec { name: tmp_name(), ..spec };
                (Source::Cluster { backend, spec: Some(spec) }, "CLUSTER", Some(ctx.received_at))
            }
            _ => return Err(invalid_parameter(format!("The source ARN {} is not valid.", input.source_arn))),
        };
        let key = self.storage_key(ctx, Some(&input.kms_key_id), &id)?;
        let store = self.export_store().cloned();
        if let Some(store) = &store {
            store.assume(ctx, &input.iam_role_arn, &input.source_arn).map_err(|_| {
                errors::iam_role_not_found_fault(format!("The IAM role {} is not valid.", input.iam_role_arn))
            })?;
        }
        let task = t::ExportTask {
            export_task_identifier: Some(id.clone()),
            source_arn: Some(input.source_arn.clone()),
            export_only: (!only.is_empty()).then(|| only.clone()),
            snapshot_time,
            task_start_time: Some(ctx.received_at),
            task_end_time: None,
            s3_bucket: Some(input.s3_bucket_name.clone()),
            s3_prefix: input.s3_prefix.clone(),
            iam_role_arn: Some(input.iam_role_arn.clone()),
            kms_key_id: Some(key.clone()),
            status: Some("STARTING".into()),
            percent_progress: Some(0),
            total_extracted_data_in_gb: Some(0),
            failure_cause: None,
            warning_message: None,
            source_type: Some(source_type.into()),
        };
        self.with_region(ctx, |r| {
            if r.export_tasks.contains_key(&id) {
                return Err(errors::export_task_already_exists_fault(format!(
                    "The export task with the ID {id} already exists."
                )));
            }
            r.export_tasks.insert(id.clone(), task.clone());
            Ok(())
        })?;
        let this = self.clone();
        let tctx = ctx.clone();
        let tid = id.clone();
        self.run_task(async move {
            this.run_export(&tctx, &tid, source, store, &key, &only).await;
        })
        .await;
        Ok(self.export_task(ctx, &id).unwrap_or(task))
    }

    /// Read, write and record the export's outcome.
    async fn run_export(
        &self,
        ctx: &RequestContext,
        id: &str,
        source: Source,
        store: Option<std::sync::Arc<dyn crate::ExportStore>>,
        key: &str,
        only: &[String],
    ) {
        let Some(task) = self.update_export(ctx, id, |t| {
            if t.status.as_deref() == Some("STARTING") {
                t.status = Some("IN_PROGRESS".into());
            }
        }) else {
            return;
        };
        let result = self.export_data(ctx, id, &task, source, store, key, only).await;
        let now = self.now().max(ctx.received_at);
        let source_arn = task.source_arn.clone().unwrap_or_default();
        let (_, _, kind, name) = parse_arn(&source_arn).unwrap_or_default();
        let source_type = if kind == "snapshot" { "db-snapshot" } else { "db-cluster-snapshot" };
        match result {
            Ok(Some(bytes)) => {
                self.update_export(ctx, id, |t| {
                    t.status = Some("COMPLETE".into());
                    t.percent_progress = Some(100);
                    t.total_extracted_data_in_gb = Some((bytes / (1 << 30)) as i32);
                    t.task_end_time = Some(now);
                });
                self.emit(
                    ctx,
                    source_type,
                    &name,
                    &source_arn,
                    &["notification"],
                    "DB snapshot export task completed.",
                    "RDS-EVENT-0161",
                );
            }
            Ok(None) => {
                self.update_export(ctx, id, |t| {
                    t.status = Some("CANCELED".into());
                    t.task_end_time = Some(now);
                });
                self.emit(
                    ctx,
                    source_type,
                    &name,
                    &source_arn,
                    &["notification"],
                    "DB snapshot export task canceled.",
                    "RDS-EVENT-0160",
                );
            }
            Err(cause) => {
                self.update_export(ctx, id, |t| {
                    t.status = Some("FAILED".into());
                    t.failure_cause = Some(cause);
                    t.task_end_time = Some(now);
                });
                self.emit(
                    ctx,
                    source_type,
                    &name,
                    &source_arn,
                    &["notification"],
                    "DB snapshot export task failed.",
                    "RDS-EVENT-0159",
                );
            }
        }
    }

    fn export_canceled(&self, ctx: &RequestContext, id: &str) -> bool {
        self.export_task(ctx, id).is_none_or(|t| t.status.as_deref() == Some("CANCELING"))
    }

    /// Write the export; `Ok(None)` when it was canceled.
    #[allow(clippy::too_many_arguments)]
    async fn export_data(
        &self,
        ctx: &RequestContext,
        id: &str,
        task: &t::ExportTask,
        source: Source,
        store: Option<std::sync::Arc<dyn crate::ExportStore>>,
        key: &str,
        only: &[String],
    ) -> Result<Option<u64>, String> {
        let Some(store) = store else { return Err("S3 is not available.".into()) };
        let role_arn = task.iam_role_arn.clone().unwrap_or_default();
        let source_arn = task.source_arn.clone().unwrap_or_default();
        let role = store
            .assume(ctx, &role_arn, &source_arn)
            .map_err(|_| format!("The IAM role {role_arn} could not be assumed by export.rds.amazonaws.com."))?;
        let started = self.now().max(ctx.received_at);
        let tables = match source {
            Source::Snapshot { backend: Some(b), spec: Some(spec) } => {
                self.backend().export_tables(&spec, &b).await.map_err(|e| format!("Reading the data failed: {e}"))?
            }
            Source::Cluster { backend: Some(b), spec: Some(spec) } => {
                let tmp = format!("{}-src", spec.name);
                self.backend().snapshot(&b, &tmp).await.map_err(|e| format!("Copying the cluster failed: {e}"))?;
                let r = self.backend().export_tables(&spec, &tmp).await;
                let _ = self.backend().delete_snapshot(&tmp).await;
                r.map_err(|e| format!("Reading the data failed: {e}"))?
            }
            _ => Vec::new(),
        };
        let tables: Vec<TableData> = tables.into_iter().filter(|t| included(only, t)).collect();
        let bucket = task.s3_bucket.clone().unwrap_or_default();
        let prefix = prefix_of(task);
        let mut bytes = 0u64;
        let mut per_table = Vec::new();
        let total = tables.len().max(1);
        for (i, table) in tables.iter().enumerate() {
            if self.export_canceled(ctx, id) {
                return Ok(None);
            }
            let body = parquet(table);
            bytes += body.len() as u64;
            let dir = match &table.schema {
                Some(s) => format!("{}/{s}.{}", table.database, table.table),
                None => format!("{}/{}.{}", table.database, table.database, table.table),
            };
            let file = format!("{prefix}/{dir}/1/part-00000-{}.c000.parquet", uuid::Uuid::new_v4());
            store
                .put_object(&role, &bucket, &file, body, key)
                .await
                .map_err(|e| format!("Writing to S3 failed: {e}"))?;
            let now = self.now().max(ctx.received_at);
            per_table.push(json!({
                "tableStatistics": {
                    "extractionStartTime": started.to_rfc3339(),
                    "extractionEndTime": now.to_rfc3339(),
                    "partitioningInfo": {"numberOfPartitions": 1, "numberOfCompletedPartitions": 1},
                },
                "schemaMetadata": {
                    "originalTypeMappings": table.columns.iter().map(|(n, sql)| json!({
                        "columnName": n,
                        "originalType": sql,
                        "expectedExportedType": exported_type(column_kind(sql)),
                    })).collect::<Vec<_>>(),
                },
                "status": "COMPLETE",
                "sizeGB": 0.0,
                "target": target(table),
            }));
            let pct = ((i + 1) * 100 / total) as i32;
            self.update_export(ctx, id, |t| t.percent_progress = Some(pct.min(99)));
        }
        if self.export_canceled(ctx, id) {
            return Ok(None);
        }
        let n = per_table.len();
        let tables_info = json!({ "perTableStatus": per_table });
        store
            .put_object(
                &role,
                &bucket,
                &format!("{prefix}/export_tables_info_{id}_from_1_to_{n}.json"),
                serde_json::to_vec_pretty(&tables_info).unwrap_or_default(),
                key,
            )
            .await
            .map_err(|e| format!("Writing to S3 failed: {e}"))?;
        let now = self.now().max(ctx.received_at);
        let info = json!({
            "exportTaskIdentifier": id,
            "sourceArn": source_arn,
            "exportOnly": only,
            "snapshotTime": task.snapshot_time.map(|t| t.to_rfc3339()),
            "taskStartTime": task.task_start_time.map(|t| t.to_rfc3339()),
            "taskEndTime": now.to_rfc3339(),
            "s3Bucket": bucket,
            "s3Prefix": task.s3_prefix.clone().unwrap_or_default(),
            "exportedFilesPath": format!("{prefix}/"),
            "iamRoleArn": role_arn,
            "kmsKeyId": key,
            "status": "COMPLETE",
            "percentProgress": 100,
            "totalExportedDataInGB": bytes as f64 / f64::from(1u32 << 30),
        });
        store
            .put_object(
                &role,
                &bucket,
                &format!("{prefix}/export_info_{id}.json"),
                serde_json::to_vec_pretty(&info).unwrap_or_default(),
                key,
            )
            .await
            .map_err(|e| format!("Writing to S3 failed: {e}"))?;
        Ok(Some(bytes))
    }

    pub(crate) fn cancel_export_task_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelExportTaskMessage,
    ) -> Result<t::ExportTask, ServiceError> {
        let id = input.export_task_identifier;
        let task = self.export_task(ctx, &id).ok_or_else(|| not_found(&id))?;
        authorize(ctx, "CancelExportTask", task.source_arn.as_deref().unwrap_or("*"), ConditionContext::new())?;
        let status = task.status.clone().unwrap_or_default();
        if DONE.contains(&status.as_str()) || status == "CANCELING" {
            return Err(errors::invalid_export_task_state_fault(format!(
                "The export task with the ID {id} can't be canceled because its status is {status}."
            )));
        }
        Ok(self
            .update_export(ctx, &id, |t| {
                t.status = Some("CANCELING".into());
            })
            .unwrap_or(task))
    }

    pub(crate) fn describe_export_tasks_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeExportTasksMessage,
    ) -> Result<t::ExportTasksMessage, ServiceError> {
        let f = Filters::new(&input.filters, &["export-task-identifier", "s3-bucket", "source-arn", "status"])?;
        authorize(ctx, "DescribeExportTasks", &arn(ctx, "*", "*"), ConditionContext::new())?;
        if let Some(s) = &input.source_type {
            if !matches!(s.as_str(), "SNAPSHOT" | "CLUSTER") {
                return Err(invalid_parameter(format!("Invalid SourceType: {s}")));
            }
        }
        let all: Vec<t::ExportTask> = self.with_region(ctx, |r| r.export_tasks.values().cloned().collect());
        let all: Vec<t::ExportTask> = all
            .into_iter()
            .filter(|t| {
                input.export_task_identifier.as_ref().is_none_or(|i| t.export_task_identifier.as_ref() == Some(i))
                    && input.source_arn.as_ref().is_none_or(|a| t.source_arn.as_ref() == Some(a))
                    && input.source_type.as_ref().is_none_or(|s| t.source_type.as_ref() == Some(s))
                    && f.matches(|name| match name {
                        "export-task-identifier" => opt(&t.export_task_identifier),
                        "s3-bucket" => opt(&t.s3_bucket),
                        "source-arn" => opt(&t.source_arn),
                        "status" => {
                            let s = t.status.clone().unwrap_or_default();
                            vec![s.clone(), s.to_ascii_lowercase()]
                        }
                        _ => Vec::new(),
                    })
            })
            .collect();
        if let Some(id) = &input.export_task_identifier {
            if all.is_empty() {
                return Err(not_found(id));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::ExportTasksMessage { marker, export_tasks: Some(page) })
    }
}
