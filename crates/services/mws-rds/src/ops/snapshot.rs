//! Snapshots and backups: manual and automated DB and cluster snapshots,
//! sharing, copies, restores (from a snapshot and to a point in time) and
//! automated backups. With a backend that runs databases, a snapshot is a
//! copy of the database's data volume.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::instance::{certificate, check_class, engine_of, param_family_mismatch, NewInstance};
use super::pitr::Recovery;
use super::{authorize, cluster_arn, cond, db_arn};
use crate::backend::LogSource;
use crate::catalog;
use crate::generated::{errors, types as t};
use crate::state::{ClusterRecord, ClusterSnapshotRecord, InstanceRecord, SnapshotRecord};
use crate::util::{
    account_of, arn, backup_window, identifier, invalid_combination, invalid_parameter, maintenance_window, merge_tags,
    name_of, opt, paginate, parse_arn, request_tag_context, resource_id, resource_tag_context, stable_token, tags_from,
    Filters,
};
use crate::Rds;

fn snapshot_not_found(id: &str) -> ServiceError {
    errors::db_snapshot_not_found_fault(format!("DBSnapshot {id} not found."))
}

fn cluster_snapshot_not_found(id: &str) -> ServiceError {
    errors::db_cluster_snapshot_not_found_fault(format!("DBClusterSnapshot {id} not found."))
}

/// The backend's name for a snapshot's data.
/// The backend's name for a new snapshot's data. It is unique per
/// creation, so emulators sharing one Docker host (or a snapshot recreated
/// under an old name) never share a volume.
pub(crate) fn backend_snapshot_name(snapshot_arn: &str) -> String {
    let unique = format!("{snapshot_arn}/{}", uuid::Uuid::new_v4());
    format!("snap-{}", stable_token(&unique, 24))
}

fn automated_name(id: &str, at: DateTime<Utc>) -> String {
    format!("rds:{id}-{}", at.format("%Y-%m-%d-%H-%M"))
}

pub(crate) fn automated_backup(ctx: &RequestContext, rec: &InstanceRecord) -> t::DBInstanceAutomatedBackup {
    let db = &rec.db;
    let resource = db.dbi_resource_id.clone().unwrap_or_default();
    t::DBInstanceAutomatedBackup {
        db_instance_arn: db.db_instance_arn.clone(),
        dbi_resource_id: Some(resource.clone()),
        region: Some(ctx.region.clone()),
        db_instance_identifier: db.db_instance_identifier.clone(),
        restore_window: Some(t::RestoreWindow {
            earliest_time: db.instance_create_time,
            latest_time: db.latest_restorable_time,
        }),
        allocated_storage: db.allocated_storage,
        status: Some("active".into()),
        port: Some(rec.port),
        availability_zone: db.availability_zone.clone(),
        vpc_id: db.db_subnet_group.as_ref().and_then(|g| g.vpc_id.clone()),
        instance_create_time: db.instance_create_time,
        master_username: db.master_username.clone(),
        engine: db.engine.clone(),
        engine_version: db.engine_version.clone(),
        license_model: db.license_model.clone(),
        iops: db.iops,
        storage_throughput: db.storage_throughput,
        option_group_name: db
            .option_group_memberships
            .as_ref()
            .and_then(|o| o.first())
            .and_then(|o| o.option_group_name.clone()),
        encrypted: db.storage_encrypted,
        storage_type: db.storage_type.clone(),
        kms_key_id: db.kms_key_id.clone(),
        timezone: db.timezone.clone(),
        iam_database_authentication_enabled: db.iam_database_authentication_enabled,
        backup_retention_period: db.backup_retention_period,
        preferred_backup_window: db.preferred_backup_window.clone(),
        db_instance_automated_backups_arn: Some(arn(
            ctx,
            "auto-backup",
            &format!("ab-{}", stable_token(&resource, 26)),
        )),
        db_instance_automated_backups_replications: Some(
            db.db_instance_automated_backups_replications.clone().unwrap_or_default(),
        ),
        backup_target: db.backup_target.clone(),
        multi_tenant: Some(false),
        tag_list: db.tag_list.clone(),
        dedicated_log_volume: db.dedicated_log_volume,
        ..Default::default()
    }
}

pub(crate) fn cluster_automated_backup(ctx: &RequestContext, rec: &ClusterRecord) -> t::DBClusterAutomatedBackup {
    let c = &rec.cluster;
    let resource = c.db_cluster_resource_id.clone().unwrap_or_default();
    t::DBClusterAutomatedBackup {
        engine: c.engine.clone(),
        db_cluster_automated_backups_arn: Some(arn(
            ctx,
            "cluster-auto-backup",
            &format!("cab-{}", stable_token(&resource, 26)),
        )),
        db_cluster_identifier: c.db_cluster_identifier.clone(),
        restore_window: Some(t::RestoreWindow {
            earliest_time: c.earliest_restorable_time,
            latest_time: c.latest_restorable_time,
        }),
        master_username: c.master_username.clone(),
        db_cluster_resource_id: Some(resource),
        region: Some(ctx.region.clone()),
        license_model: Some(
            if c.engine.as_deref().is_some_and(|e| e.contains("mysql")) {
                "general-public-license"
            } else {
                "postgresql-license"
            }
            .into(),
        ),
        status: Some("active".into()),
        iam_database_authentication_enabled: c.iam_database_authentication_enabled,
        cluster_create_time: c.cluster_create_time,
        storage_encrypted: c.storage_encrypted,
        allocated_storage: c.allocated_storage,
        engine_version: c.engine_version.clone(),
        db_cluster_arn: c.db_cluster_arn.clone(),
        backup_retention_period: c.backup_retention_period,
        preferred_backup_window: c.preferred_backup_window.clone(),
        engine_mode: c.engine_mode.clone(),
        availability_zones: c.availability_zones.clone(),
        port: c.port,
        kms_key_id: c.kms_key_id.clone(),
        storage_type: c.storage_type.clone(),
        iops: c.iops,
        tag_list: c.tag_list.clone(),
        ..Default::default()
    }
}

fn snapshot_filter(s: &t::DBSnapshot, name: &str) -> Vec<String> {
    match name {
        "db-instance-id" => {
            let mut v = opt(&s.db_instance_identifier);
            v.extend(s.db_snapshot_arn.as_ref().map(|a| {
                a.replace(
                    &format!(":snapshot:{}", s.db_snapshot_identifier.clone().unwrap_or_default()),
                    &format!(":db:{}", s.db_instance_identifier.clone().unwrap_or_default()),
                )
            }));
            v
        }
        "db-snapshot-id" => {
            let mut v = opt(&s.db_snapshot_identifier);
            v.extend(opt(&s.db_snapshot_arn));
            v
        }
        "dbi-resource-id" => opt(&s.dbi_resource_id),
        "snapshot-type" => opt(&s.snapshot_type),
        "engine" => opt(&s.engine),
        _ => Vec::new(),
    }
}

fn cluster_snapshot_filter(s: &t::DBClusterSnapshot, name: &str) -> Vec<String> {
    match name {
        "db-cluster-id" => opt(&s.db_cluster_identifier),
        "db-cluster-snapshot-id" => {
            let mut v = opt(&s.db_cluster_snapshot_identifier);
            v.extend(opt(&s.db_cluster_snapshot_arn));
            v
        }
        "snapshot-type" => opt(&s.snapshot_type),
        "engine" => opt(&s.engine),
        _ => Vec::new(),
    }
}

/// Settings a restore may override, common to the restore operations.
#[derive(Default)]
struct RestoreOptions {
    class: Option<String>,
    port: Option<i32>,
    availability_zone: Option<String>,
    subnet_group: Option<String>,
    multi_az: Option<bool>,
    publicly_accessible: Option<bool>,
    auto_minor_version_upgrade: Option<bool>,
    db_name: Option<String>,
    iops: Option<i32>,
    storage_type: Option<String>,
    option_group: Option<String>,
    tags: Vec<t::Tag>,
    vpc_security_group_ids: Option<Vec<String>>,
    copy_tags_to_snapshot: Option<bool>,
    iam_auth: Option<bool>,
    logs: Option<Vec<String>>,
    parameter_group: Option<String>,
    deletion_protection: Option<bool>,
    allocated_storage: Option<i32>,
    backup_retention_period: Option<i32>,
    preferred_backup_window: Option<String>,
    ca_certificate_identifier: Option<String>,
    manage_master_user_password: Option<bool>,
    master_user_secret_kms_key_id: Option<String>,
    /// Roll the data forward before the restore starts.
    recovery: Option<Recovery>,
    /// The snapshot is a temporary copy, dropped once restored.
    drop_snapshot: bool,
}

/// What a recovery needs to know of a database that no longer runs.
fn recovery_spec(
    ctx: &RequestContext,
    engine: &catalog::Engine,
    image: &str,
    s: &t::DBSnapshot,
    password: &str,
) -> crate::backend::DatabaseSpec {
    crate::backend::DatabaseSpec {
        name: String::new(),
        account_id: account_of(ctx),
        region: ctx.region.clone(),
        identifier: s.db_instance_identifier.clone().unwrap_or_default(),
        engine: engine.name.to_string(),
        kind: engine.kind,
        image: image.to_string(),
        master_username: s.master_username.clone().unwrap_or_default(),
        master_password: password.to_string(),
        database_name: None,
        parameters: Vec::new(),
        memory_mib: 1024,
    }
}

impl Rds {
    /// A DB snapshot by identifier or ARN; an ARN may name a snapshot
    /// another account shared with the caller.
    fn find_snapshot(&self, ctx: &RequestContext, id: &str) -> Result<SnapshotRecord, ServiceError> {
        let caller = account_of(ctx);
        if let Some((region, account, _, name)) = parse_arn(id) {
            let rec = self
                .with_region_of(&account, &region, |r| r.snapshots.get(&name).cloned())
                .ok_or_else(|| snapshot_not_found(&name))?;
            if account != caller && !rec.restore.iter().any(|a| a == &caller || a == "all") {
                return Err(snapshot_not_found(&name));
            }
            return Ok(rec);
        }
        let name = id.to_ascii_lowercase();
        self.with_region(ctx, |r| r.snapshots.get(&name).cloned()).ok_or_else(|| snapshot_not_found(&name))
    }

    fn find_cluster_snapshot(&self, ctx: &RequestContext, id: &str) -> Result<ClusterSnapshotRecord, ServiceError> {
        let caller = account_of(ctx);
        if let Some((region, account, _, name)) = parse_arn(id) {
            let rec = self
                .with_region_of(&account, &region, |r| r.cluster_snapshots.get(&name).cloned())
                .ok_or_else(|| cluster_snapshot_not_found(&name))?;
            if account != caller && !rec.restore.iter().any(|a| a == &caller || a == "all") {
                return Err(cluster_snapshot_not_found(&name));
            }
            return Ok(rec);
        }
        let name = id.to_ascii_lowercase();
        self.with_region(ctx, |r| r.cluster_snapshots.get(&name).cloned())
            .ok_or_else(|| cluster_snapshot_not_found(&name))
    }

    /// Snapshot an instance (or, for cluster members, refuse). Waits for the
    /// data copy, so a delete that follows sees a complete snapshot.
    pub(crate) async fn snapshot_instance(
        &self,
        ctx: &RequestContext,
        id: &str,
        snapshot_id: &str,
        kind: &str,
        tags: Vec<t::Tag>,
    ) -> Result<t::DBSnapshot, ServiceError> {
        let rec = self.instance(ctx, id)?;
        let db = &rec.db;
        if db.db_cluster_identifier.is_some() {
            return Err(errors::invalid_db_instance_state_fault(
                "The specified instance is a member of a cluster and a snapshot cannot be created directly. Please use the CreateDBClusterSnapshot API instead.",
            ));
        }
        let sarn = arn(ctx, "snapshot", snapshot_id);
        let mut tags = tags;
        if db.copy_tags_to_snapshot == Some(true) && tags.is_empty() {
            tags = db.tag_list.clone().unwrap_or_default();
        }
        let now = ctx.received_at;
        let snapshot = t::DBSnapshot {
            db_snapshot_identifier: Some(snapshot_id.to_string()),
            db_instance_identifier: db.db_instance_identifier.clone(),
            snapshot_create_time: Some(now),
            engine: db.engine.clone(),
            allocated_storage: db.allocated_storage,
            status: Some("creating".into()),
            port: Some(rec.port),
            availability_zone: db.availability_zone.clone(),
            vpc_id: db.db_subnet_group.as_ref().and_then(|g| g.vpc_id.clone()),
            instance_create_time: db.instance_create_time,
            master_username: db.master_username.clone(),
            engine_version: db.engine_version.clone(),
            license_model: db.license_model.clone(),
            snapshot_type: Some(kind.to_string()),
            iops: db.iops,
            storage_throughput: db.storage_throughput,
            option_group_name: db
                .option_group_memberships
                .as_ref()
                .and_then(|o| o.first())
                .and_then(|o| o.option_group_name.clone()),
            percent_progress: Some(0),
            storage_type: db.storage_type.clone(),
            encrypted: db.storage_encrypted,
            kms_key_id: db.kms_key_id.clone(),
            db_snapshot_arn: Some(sarn.clone()),
            timezone: db.timezone.clone(),
            iam_database_authentication_enabled: db.iam_database_authentication_enabled,
            processor_features: Some(Vec::new()),
            dbi_resource_id: db.dbi_resource_id.clone(),
            tag_list: Some(tags),
            snapshot_target: Some("region".into()),
            original_snapshot_create_time: Some(now),
            snapshot_database_time: Some(now),
            multi_tenant: Some(false),
            dedicated_log_volume: db.dedicated_log_volume,
            ..Default::default()
        };
        let backend_name = backend_snapshot_name(&sarn);
        let record = SnapshotRecord {
            snapshot: snapshot.clone(),
            master_password: rec.master_password.clone(),
            db_name: db.db_name.clone(),
            image: rec.image.clone(),
            db_instance_class: db.db_instance_class.clone().unwrap_or_default(),
            restore: Vec::new(),
            has_data: false,
            backend_name: backend_name.clone(),
            data_time: None,
        };
        let max = self.quota(ctx, crate::quotas::MANUAL_SNAPSHOTS);
        self.with_region(ctx, |r| {
            if r.snapshots.contains_key(snapshot_id) {
                return Err(errors::db_snapshot_already_exists_fault(format!(
                    "Cannot create the snapshot because a snapshot with the identifier {snapshot_id} already exists."
                )));
            }
            if r.snapshots.values().filter(|s| s.snapshot.snapshot_type.as_deref() == Some("manual")).count() as i64
                >= max
                && kind == "manual"
            {
                return Err(errors::snapshot_quota_exceeded_fault(format!(
                    "Cannot create more than {max} manual snapshots."
                )));
            }
            r.snapshots.insert(snapshot_id.to_string(), record);
            Ok(())
        })?;
        self.emit(ctx, "db-snapshot", snapshot_id, &sarn, &["creation"], "Creating manual snapshot", "RDS-EVENT-0040");
        let wall = chrono::Utc::now();
        let has_data = if self.backend().runs_databases() && rec.listen.is_some() {
            match self.backend().snapshot(&rec.backend_name, &backend_name).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(db = %id, "snapshot failed: {e}");
                    false
                }
            }
        } else {
            false
        };
        let done = self.with_region(ctx, |r| {
            let s = r.snapshots.get_mut(snapshot_id)?;
            s.has_data = has_data;
            s.data_time = has_data.then_some(wall);
            s.snapshot.status = Some("available".into());
            s.snapshot.percent_progress = Some(100);
            Some(s.snapshot.clone())
        });
        self.emit(ctx, "db-snapshot", snapshot_id, &sarn, &["creation"], "Manual snapshot created", "RDS-EVENT-0042");
        Ok(done.unwrap_or(snapshot))
    }

    /// Take an instance's automated snapshot (at creation).
    pub(crate) async fn automated_snapshot(&self, ctx: &RequestContext, id: &str) {
        let name = automated_name(id, self.now());
        if let Err(e) = self.snapshot_instance(ctx, id, &name, "automated", Vec::new()).await {
            tracing::debug!(db = %id, "automated snapshot skipped: {}", e.message);
        }
    }

    /// Take a cluster's automated snapshot.
    pub(crate) async fn automated_cluster_snapshot(&self, ctx: &RequestContext, id: &str) {
        let name = automated_name(id, self.now());
        if let Err(e) = self.snapshot_cluster(ctx, id, &name, "automated", Vec::new()).await {
            tracing::debug!(cluster = %id, "automated snapshot skipped: {}", e.message);
        }
    }

    pub(crate) async fn snapshot_cluster(
        &self,
        ctx: &RequestContext,
        id: &str,
        snapshot_id: &str,
        kind: &str,
        tags: Vec<t::Tag>,
    ) -> Result<t::DBClusterSnapshot, ServiceError> {
        let rec = self.cluster(ctx, id)?;
        let c = &rec.cluster;
        let sarn = arn(ctx, "cluster-snapshot", snapshot_id);
        let mut tags = tags;
        if c.copy_tags_to_snapshot == Some(true) && tags.is_empty() {
            tags = c.tag_list.clone().unwrap_or_default();
        }
        let now = ctx.received_at;
        let vpc = self.subnet_group(ctx, c.db_subnet_group.as_deref().unwrap_or("default")).ok().and_then(|g| g.vpc_id);
        let snapshot = t::DBClusterSnapshot {
            availability_zones: c.availability_zones.clone(),
            db_cluster_snapshot_identifier: Some(snapshot_id.to_string()),
            db_cluster_identifier: c.db_cluster_identifier.clone(),
            snapshot_create_time: Some(now),
            engine: c.engine.clone(),
            engine_mode: c.engine_mode.clone(),
            allocated_storage: c.allocated_storage,
            status: Some("creating".into()),
            port: c.port,
            vpc_id: vpc,
            cluster_create_time: c.cluster_create_time,
            master_username: c.master_username.clone(),
            engine_version: c.engine_version.clone(),
            license_model: Some(
                engine_of(c.engine.as_deref().unwrap_or_default())
                    .map(|e| e.license)
                    .unwrap_or("postgresql-license")
                    .into(),
            ),
            snapshot_type: Some(kind.to_string()),
            percent_progress: Some(0),
            storage_encrypted: c.storage_encrypted,
            kms_key_id: c.kms_key_id.clone(),
            db_cluster_snapshot_arn: Some(sarn.clone()),
            iam_database_authentication_enabled: c.iam_database_authentication_enabled,
            tag_list: Some(tags),
            storage_type: c.storage_type.clone(),
            db_cluster_resource_id: c.db_cluster_resource_id.clone(),
            ..Default::default()
        };
        let backend_name = backend_snapshot_name(&sarn);
        self.with_region(ctx, |r| {
            if r.cluster_snapshots.contains_key(snapshot_id) {
                return Err(errors::db_cluster_snapshot_already_exists_fault(format!(
                    "Cannot create the cluster snapshot because one with the identifier {snapshot_id} already exists."
                )));
            }
            r.cluster_snapshots.insert(
                snapshot_id.to_string(),
                ClusterSnapshotRecord {
                    snapshot: snapshot.clone(),
                    master_password: rec.master_password.clone(),
                    database_name: c.database_name.clone(),
                    image: rec.image.clone(),
                    restore: Vec::new(),
                    has_data: false,
                    backend_name: backend_name.clone(),
                    data_time: None,
                },
            );
            Ok(())
        })?;
        let wall = chrono::Utc::now();
        let has_data = self.backend().runs_databases()
            && rec.listen.is_some()
            && self.backend().snapshot(&rec.backend_name, &backend_name).await.is_ok();
        let done = self.with_region(ctx, |r| {
            let s = r.cluster_snapshots.get_mut(snapshot_id)?;
            s.has_data = has_data;
            s.data_time = has_data.then_some(wall);
            s.snapshot.status = Some("available".into());
            s.snapshot.percent_progress = Some(100);
            Some(s.snapshot.clone())
        });
        self.emit(
            ctx,
            "db-cluster-snapshot",
            snapshot_id,
            &sarn,
            &["backup"],
            "Manual cluster snapshot created",
            "RDS-EVENT-0075",
        );
        Ok(done.unwrap_or(snapshot))
    }

    pub(crate) async fn create_db_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBSnapshotMessage,
    ) -> Result<t::CreateDBSnapshotResult, ServiceError> {
        let snap = identifier("DBSnapshotIdentifier", &input.db_snapshot_identifier, 255)?;
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let tags = tags_from(&input.tags)?;
        let sarn = arn(ctx, "snapshot", &snap);
        authorize(ctx, "CreateDBSnapshot", &sarn, request_tag_context(&tags))?;
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "CreateDBSnapshot", &db_arn(ctx, &id), resource_tag_context("db", &rec.db.tag_list))?;
        let status = rec.db.db_instance_status.clone().unwrap_or_default();
        if status != "available" && status != "stopped" {
            return Err(super::invalid_instance_state(&id, &status));
        }
        let s = self.snapshot_instance(ctx, &id, &snap, "manual", tags).await?;
        Ok(t::CreateDBSnapshotResult { db_snapshot: Some(s) })
    }

    pub(crate) fn describe_db_snapshots_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBSnapshotsMessage,
    ) -> Result<t::DBSnapshotMessage, ServiceError> {
        authorize(
            ctx,
            "DescribeDBSnapshots",
            &arn(ctx, "snapshot", input.db_snapshot_identifier.as_deref().map(name_of).as_deref().unwrap_or("*")),
            ConditionContext::new(),
        )?;
        let f = Filters::new(
            &input.filters,
            &["db-instance-id", "db-snapshot-id", "dbi-resource-id", "snapshot-type", "engine"],
        )?;
        let caller = account_of(ctx);
        let wanted = input.db_snapshot_identifier.as_deref().map(|s| name_of(s).to_ascii_lowercase());
        let instance = input.db_instance_identifier.as_deref().map(|s| name_of(s).to_ascii_lowercase());
        let kind = input.snapshot_type.clone();
        let include_shared = input.include_shared.unwrap_or(false) || kind.as_deref() == Some("shared");
        let include_public = input.include_public.unwrap_or(false) || kind.as_deref() == Some("public");
        let mut all: Vec<t::DBSnapshot> = Vec::new();
        {
            let st = self.lock();
            for (key, r) in &st.regions {
                let Some((account, region)) = key.split_once('/') else { continue };
                if region != ctx.region {
                    continue;
                }
                let own = account == caller;
                for s in r.snapshots.values() {
                    let shared = s.restore.iter().any(|a| a == &caller);
                    let public = s.restore.iter().any(|a| a == "all");
                    let visible = own || (include_shared && shared) || (include_public && public);
                    if !visible {
                        continue;
                    }
                    let mut snap = s.snapshot.clone();
                    if !own {
                        snap.snapshot_type = Some(if shared { "shared" } else { "public" }.into());
                        snap.db_snapshot_identifier = snap.db_snapshot_arn.clone();
                    }
                    all.push(snap);
                }
            }
        }
        if let Some(w) = &wanted {
            all.retain(|s| {
                s.db_snapshot_identifier.as_ref() == Some(w)
                    || s.db_snapshot_arn
                        .as_ref()
                        .is_some_and(|a| name_of(a) == *w && input.db_snapshot_identifier.as_deref() == Some(a))
            });
            if all.is_empty() {
                return Err(snapshot_not_found(w));
            }
        }
        let all: Vec<t::DBSnapshot> = all
            .into_iter()
            .filter(|s| instance.as_ref().is_none_or(|i| s.db_instance_identifier.as_ref() == Some(i)))
            .filter(|s| match kind.as_deref() {
                None => true,
                Some("shared") | Some("public") => s.snapshot_type == kind,
                Some(k) => s.snapshot_type.as_deref() == Some(k),
            })
            .filter(|s| input.dbi_resource_id.as_ref().is_none_or(|d| s.dbi_resource_id.as_ref() == Some(d)))
            .filter(|s| f.matches(|n| snapshot_filter(s, n)))
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBSnapshotMessage { marker, db_snapshots: Some(page) })
    }

    pub(crate) async fn delete_db_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBSnapshotMessage,
    ) -> Result<t::DeleteDBSnapshotResult, ServiceError> {
        let id = name_of(&input.db_snapshot_identifier).to_ascii_lowercase();
        let rec = self.with_region(ctx, |r| r.snapshots.get(&id).cloned()).ok_or_else(|| snapshot_not_found(&id))?;
        authorize(
            ctx,
            "DeleteDBSnapshot",
            &arn(ctx, "snapshot", &id),
            resource_tag_context("snapshot", &rec.snapshot.tag_list),
        )?;
        if rec.snapshot.snapshot_type.as_deref() == Some("automated") {
            return Err(errors::invalid_db_snapshot_state_fault("Only manual snapshots may be deleted."));
        }
        if rec.snapshot.status.as_deref() != Some("available") {
            return Err(errors::invalid_db_snapshot_state_fault(
                "Cannot delete the snapshot because it is not in available state.",
            ));
        }
        self.with_region(ctx, |r| r.snapshots.remove(&id));
        if rec.has_data {
            let _ = self.backend().delete_snapshot(&rec.backend_name).await;
        }
        let mut s = rec.snapshot;
        s.status = Some("deleted".into());
        Ok(t::DeleteDBSnapshotResult { db_snapshot: Some(s) })
    }

    pub(crate) async fn copy_db_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::CopyDBSnapshotMessage,
    ) -> Result<t::CopyDBSnapshotResult, ServiceError> {
        let target = identifier("TargetDBSnapshotIdentifier", &input.target_db_snapshot_identifier, 255)?;
        let source = self.find_snapshot(ctx, &input.source_db_snapshot_identifier)?;
        let tarn = arn(ctx, "snapshot", &target);
        let mut tags = tags_from(&input.tags)?;
        authorize(ctx, "CopyDBSnapshot", &tarn, request_tag_context(&tags))?;
        authorize(
            ctx,
            "CopyDBSnapshot",
            source.snapshot.db_snapshot_arn.as_deref().unwrap_or_default(),
            ConditionContext::new(),
        )?;
        if source.snapshot.status.as_deref() != Some("available") {
            return Err(errors::invalid_db_snapshot_state_fault("The source snapshot is not in available state."));
        }
        if input.copy_tags == Some(true) {
            let mut base = source.snapshot.tag_list.clone().unwrap_or_default();
            merge_tags(&mut base, &tags);
            tags = base;
        }
        let encrypted = source.snapshot.encrypted.unwrap_or(false);
        let source_region =
            parse_arn(source.snapshot.db_snapshot_arn.as_deref().unwrap_or_default()).map(|p| p.0).unwrap_or_default();
        let kms_key = match (&input.kms_key_id, encrypted) {
            (Some(k), _) => {
                Some(self.storage_key(ctx, Some(k), &source.snapshot.dbi_resource_id.clone().unwrap_or_default())?)
            }
            (None, true) if source_region != ctx.region => {
                return Err(invalid_parameter(
                    "KmsKeyId must be specified when copying an encrypted snapshot to another Region.",
                ))
            }
            (None, true) => source.snapshot.kms_key_id.clone(),
            (None, false) => None,
        };
        let now = ctx.received_at;
        let mut snap = source.snapshot.clone();
        snap.db_snapshot_identifier = Some(target.clone());
        snap.db_snapshot_arn = Some(tarn.clone());
        snap.snapshot_type = Some("manual".into());
        snap.snapshot_create_time = Some(now);
        snap.source_db_snapshot_identifier = source.snapshot.db_snapshot_arn.clone();
        snap.source_region = (source_region != ctx.region).then_some(source_region);
        snap.encrypted = Some(encrypted || kms_key.is_some());
        snap.kms_key_id = kms_key;
        snap.tag_list = Some(tags);
        snap.status = Some("available".into());
        if let Some(og) = &input.option_group_name {
            snap.option_group_name = Some(self.option_group(ctx, og)?.option_group_name.unwrap_or_default());
        }
        let backend_name = backend_snapshot_name(&tarn);
        let has_data =
            source.has_data && self.backend().copy_snapshot(&source.backend_name, &backend_name).await.is_ok();
        self.with_region(ctx, |r| {
            if r.snapshots.contains_key(&target) {
                return Err(errors::db_snapshot_already_exists_fault(format!(
                    "Cannot copy the snapshot because a snapshot with the identifier {target} already exists."
                )));
            }
            r.snapshots.insert(
                target.clone(),
                SnapshotRecord {
                    snapshot: snap.clone(),
                    restore: Vec::new(),
                    has_data,
                    backend_name,
                    ..source.clone()
                },
            );
            Ok(())
        })?;
        Ok(t::CopyDBSnapshotResult { db_snapshot: Some(snap) })
    }

    pub(crate) fn modify_db_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBSnapshotMessage,
    ) -> Result<t::ModifyDBSnapshotResult, ServiceError> {
        let id = name_of(&input.db_snapshot_identifier).to_ascii_lowercase();
        let rec = self.with_region(ctx, |r| r.snapshots.get(&id).cloned()).ok_or_else(|| snapshot_not_found(&id))?;
        authorize(
            ctx,
            "ModifyDBSnapshot",
            &arn(ctx, "snapshot", &id),
            resource_tag_context("snapshot", &rec.snapshot.tag_list),
        )?;
        let engine = engine_of(rec.snapshot.engine.as_deref().unwrap_or_default())?;
        let mut image = None;
        let version = match &input.engine_version {
            Some(v) => {
                let target = engine
                    .version(v)
                    .ok_or_else(|| invalid_combination(format!("Cannot find version {v} for {}", engine.name)))?;
                let current = engine.version(rec.snapshot.engine_version.as_deref().unwrap_or_default());
                if current.is_some_and(|c| {
                    engine.versions.iter().position(|x| x.version == c.version)
                        > engine.versions.iter().position(|x| x.version == target.version)
                }) {
                    return Err(invalid_parameter(format!(
                        "Cannot upgrade snapshot from {} to {}",
                        current.map(|c| c.version).unwrap_or_default(),
                        target.version
                    )));
                }
                if current.map(|c| c.major) == Some(target.major) {
                    image = Some(target.image.to_string());
                }
                Some(target.version.to_string())
            }
            None => None,
        };
        let og = match &input.option_group_name {
            Some(n) => Some(self.option_group(ctx, n)?.option_group_name.unwrap_or_default()),
            None => None,
        };
        let s = self.with_region(ctx, |r| {
            let s = r.snapshots.get_mut(&id).expect("looked up above");
            if let Some(v) = version {
                s.snapshot.engine_version = Some(v);
            }
            if let Some(i) = image {
                s.image = i;
            }
            if let Some(o) = og {
                s.snapshot.option_group_name = Some(o);
            }
            s.snapshot.clone()
        });
        Ok(t::ModifyDBSnapshotResult { db_snapshot: Some(s) })
    }

    pub(crate) fn describe_db_snapshot_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBSnapshotAttributesMessage,
    ) -> Result<t::DescribeDBSnapshotAttributesResult, ServiceError> {
        let id = name_of(&input.db_snapshot_identifier).to_ascii_lowercase();
        let rec = self.with_region(ctx, |r| r.snapshots.get(&id).cloned()).ok_or_else(|| snapshot_not_found(&id))?;
        authorize(
            ctx,
            "DescribeDBSnapshotAttributes",
            &arn(ctx, "snapshot", &id),
            resource_tag_context("snapshot", &rec.snapshot.tag_list),
        )?;
        Ok(t::DescribeDBSnapshotAttributesResult {
            db_snapshot_attributes_result: Some(t::DBSnapshotAttributesResult {
                db_snapshot_identifier: Some(id),
                db_snapshot_attributes: Some(vec![t::DBSnapshotAttribute {
                    attribute_name: Some("restore".into()),
                    attribute_values: Some(rec.restore),
                }]),
            }),
        })
    }

    pub(crate) fn modify_db_snapshot_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBSnapshotAttributeMessage,
    ) -> Result<t::ModifyDBSnapshotAttributeResult, ServiceError> {
        let id = name_of(&input.db_snapshot_identifier).to_ascii_lowercase();
        let rec = self.with_region(ctx, |r| r.snapshots.get(&id).cloned()).ok_or_else(|| snapshot_not_found(&id))?;
        authorize(
            ctx,
            "ModifyDBSnapshotAttribute",
            &arn(ctx, "snapshot", &id),
            resource_tag_context("snapshot", &rec.snapshot.tag_list),
        )?;
        let restore = share(
            &input.attribute_name,
            &rec.restore,
            &input.values_to_add,
            &input.values_to_remove,
            rec.snapshot.snapshot_type.as_deref(),
            rec.snapshot.encrypted == Some(true),
            rec.snapshot.kms_key_id.as_deref(),
        )?;
        self.with_region(ctx, |r| {
            if let Some(s) = r.snapshots.get_mut(&id) {
                s.restore = restore.clone();
            }
        });
        Ok(t::ModifyDBSnapshotAttributeResult {
            db_snapshot_attributes_result: Some(t::DBSnapshotAttributesResult {
                db_snapshot_identifier: Some(id),
                db_snapshot_attributes: Some(vec![t::DBSnapshotAttribute {
                    attribute_name: Some("restore".into()),
                    attribute_values: Some(restore),
                }]),
            }),
        })
    }

    async fn restore_instance(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        source: SnapshotRecord,
        o: RestoreOptions,
    ) -> Result<t::DBInstance, ServiceError> {
        let id = identifier("DBInstanceIdentifier", id, 63)?;
        let iarn = db_arn(ctx, &id);
        let mut c = request_tag_context(&o.tags);
        c.extend(cond(&[("rds:DatabaseClass", o.class.clone())]));
        authorize(ctx, action, &iarn, c)?;
        if self.with_region(ctx, |r| r.instances.contains_key(&id)) {
            return Err(errors::db_instance_already_exists_fault("DB instance already exists"));
        }
        let s = &source.snapshot;
        let engine = engine_of(s.engine.as_deref().unwrap_or_default())?;
        if engine.aurora {
            return Err(invalid_parameter("Aurora DB instances are restored with RestoreDBClusterFromSnapshot."));
        }
        let version =
            engine.version(s.engine_version.as_deref().unwrap_or_default()).unwrap_or(engine.default_version());
        let class = o.class.clone().unwrap_or(source.db_instance_class.clone());
        check_class(engine, version, &class)?;
        let resource = resource_id("db-");
        let subnet_group = self.subnet_group(ctx, o.subnet_group.as_deref().unwrap_or("default"))?;
        let zones: Vec<String> = subnet_group
            .subnets
            .iter()
            .flatten()
            .filter_map(|s| s.subnet_availability_zone.as_ref().and_then(|a| a.name.clone()))
            .collect();
        let vpc = subnet_group.vpc_id.clone().unwrap_or_default();
        let sgs = self.security_groups(ctx, &o.vpc_security_group_ids, &vpc)?;
        let pg = self.param_group(
            ctx,
            o.parameter_group.as_deref().unwrap_or(&engine.default_parameter_group(version)),
            false,
        )?;
        if pg.family != version.family {
            return Err(param_family_mismatch(&pg.name, &pg.family, version.family));
        }
        let og = self.option_group(
            ctx,
            o.option_group
                .as_deref()
                .or(s.option_group_name.as_deref())
                .unwrap_or(&engine.default_option_group(version)),
        )?;
        let encrypted = s.encrypted.unwrap_or(false);
        let kms_key = if encrypted { Some(self.storage_key(ctx, s.kms_key_id.as_deref(), &resource)?) } else { None };
        let manage = o.manage_master_user_password.unwrap_or(false);
        let mut password = source.master_password.clone();
        let username = s.master_username.clone().unwrap_or_default();
        let secret = if manage {
            password = super::generate_password();
            Some(self.create_master_secret(
                ctx,
                "db",
                &iarn,
                &username,
                &password,
                o.master_user_secret_kms_key_id.clone(),
            )?)
        } else {
            None
        };
        let retention = o.backup_retention_period.unwrap_or(1);
        let multi_az = o.multi_az.unwrap_or(false);
        let az = o.availability_zone.clone().or(zones.first().cloned()).unwrap_or_default();
        let db = t::DBInstance {
            db_instance_identifier: Some(id.clone()),
            db_instance_class: Some(class),
            engine: s.engine.clone(),
            db_instance_status: Some("creating".into()),
            master_username: Some(username),
            db_name: o.db_name.clone().or(source.db_name.clone()),
            allocated_storage: Some(o.allocated_storage.unwrap_or(s.allocated_storage.unwrap_or(20))),
            instance_create_time: Some(ctx.received_at),
            preferred_backup_window: Some(
                o.preferred_backup_window.clone().unwrap_or_else(|| backup_window(&resource)),
            ),
            backup_retention_period: Some(retention),
            db_security_groups: Some(Vec::new()),
            vpc_security_groups: Some(sgs),
            db_parameter_groups: Some(vec![t::DBParameterGroupStatus {
                db_parameter_group_name: Some(pg.name),
                parameter_apply_status: Some("in-sync".into()),
            }]),
            availability_zone: Some(az.clone()),
            db_subnet_group: Some(subnet_group),
            preferred_maintenance_window: Some(maintenance_window(&resource)),
            pending_modified_values: Some(t::PendingModifiedValues::default()),
            multi_az: Some(multi_az),
            secondary_availability_zone: multi_az.then(|| zones.iter().find(|z| **z != az).cloned()).flatten(),
            engine_version: s.engine_version.clone(),
            auto_minor_version_upgrade: Some(o.auto_minor_version_upgrade.unwrap_or(true)),
            read_replica_db_instance_identifiers: Some(Vec::new()),
            license_model: s.license_model.clone(),
            iops: o.iops.or(s.iops),
            storage_throughput: s.storage_throughput,
            option_group_memberships: Some(vec![t::OptionGroupMembership {
                option_group_name: og.option_group_name,
                status: Some("in-sync".into()),
            }]),
            publicly_accessible: Some(o.publicly_accessible.unwrap_or(false)),
            storage_type: o.storage_type.clone().or(s.storage_type.clone()),
            db_instance_port: Some(0),
            storage_encrypted: Some(encrypted),
            kms_key_id: kms_key,
            dbi_resource_id: Some(resource.clone()),
            ca_certificate_identifier: Some(
                o.ca_certificate_identifier.clone().unwrap_or_else(|| self.default_certificate(ctx)),
            ),
            certificate_details: certificate(Some(
                &o.ca_certificate_identifier.clone().unwrap_or_else(|| self.default_certificate(ctx)),
            )),
            domain_memberships: Some(Vec::new()),
            copy_tags_to_snapshot: Some(o.copy_tags_to_snapshot.unwrap_or(false)),
            monitoring_interval: Some(0),
            db_instance_arn: Some(iarn),
            timezone: s.timezone.clone(),
            iam_database_authentication_enabled: Some(o.iam_auth.unwrap_or(false)),
            database_insights_mode: Some("standard".into()),
            performance_insights_enabled: Some(false),
            enabled_cloudwatch_logs_exports: o.logs.clone(),
            deletion_protection: Some(o.deletion_protection.unwrap_or(false)),
            associated_roles: Some(Vec::new()),
            tag_list: Some(o.tags.clone()),
            customer_owned_ip_enabled: Some(false),
            network_type: Some("IPV4".into()),
            activity_stream_status: Some("stopped".into()),
            backup_target: Some("region".into()),
            master_user_secret: secret,
            dedicated_log_volume: Some(false),
            is_storage_config_upgrade_available: Some(false),
            engine_lifecycle_support: Some("open-source-rds-extended-support".into()),
            ..Default::default()
        };
        let restart_password = manage && source.has_data;
        let old_password = source.master_password.clone();
        let view = self
            .launch_instance(
                ctx,
                NewInstance {
                    db,
                    master_password: if restart_password { old_password.clone() } else { password.clone() },
                    port: o.port.unwrap_or(s.port.unwrap_or(engine.default_port)),
                    image: source.image.clone(),
                    from_snapshot: source.has_data.then(|| source.backend_name.clone()),
                    first_backup: retention > 0,
                    recovery: o.recovery,
                    drop_snapshot: o.drop_snapshot,
                },
            )
            .await?;
        if restart_password {
            // The restored data still has the snapshot's password.
            self.with_region(ctx, |r| {
                if let Some(i) = r.instances.get_mut(&id) {
                    i.master_password = password.clone();
                }
            });
            self.apply_password(ctx, Some(id.clone()), None, old_password);
        }
        Ok(view)
    }

    pub(crate) async fn restore_db_instance_from_db_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreDBInstanceFromDBSnapshotMessage,
    ) -> Result<t::RestoreDBInstanceFromDBSnapshotResult, ServiceError> {
        let snap = match (&input.db_snapshot_identifier, &input.db_cluster_snapshot_identifier) {
            (Some(s), None) => s.clone(),
            (None, Some(_)) => {
                return Err(invalid_parameter(
                    "Restoring a DB instance from a Multi-AZ DB cluster snapshot isn't supported by MWS.",
                ))
            }
            _ => {
                return Err(invalid_combination("Specify either DBSnapshotIdentifier or DBClusterSnapshotIdentifier."))
            }
        };
        let source = self.find_snapshot(ctx, &snap)?;
        authorize(
            ctx,
            "RestoreDBInstanceFromDBSnapshot",
            source.snapshot.db_snapshot_arn.as_deref().unwrap_or_default(),
            ConditionContext::new(),
        )?;
        if source.snapshot.status.as_deref() != Some("available") {
            return Err(errors::invalid_db_snapshot_state_fault("The snapshot is not in available state."));
        }
        let o = RestoreOptions {
            class: input.db_instance_class,
            port: input.port,
            availability_zone: input.availability_zone,
            subnet_group: input.db_subnet_group_name,
            multi_az: input.multi_az,
            publicly_accessible: input.publicly_accessible,
            auto_minor_version_upgrade: input.auto_minor_version_upgrade,
            db_name: input.db_name,
            iops: input.iops,
            storage_type: input.storage_type,
            option_group: input.option_group_name,
            tags: tags_from(&input.tags)?,
            vpc_security_group_ids: input.vpc_security_group_ids,
            copy_tags_to_snapshot: input.copy_tags_to_snapshot,
            iam_auth: input.enable_iam_database_authentication,
            logs: input.enable_cloudwatch_logs_exports,
            parameter_group: input.db_parameter_group_name,
            deletion_protection: input.deletion_protection,
            allocated_storage: input.allocated_storage,
            backup_retention_period: input.backup_retention_period,
            preferred_backup_window: input.preferred_backup_window,
            ca_certificate_identifier: input.ca_certificate_identifier,
            manage_master_user_password: input.manage_master_user_password,
            master_user_secret_kms_key_id: input.master_user_secret_kms_key_id,
            ..Default::default()
        };
        let db = self
            .restore_instance(ctx, "RestoreDBInstanceFromDBSnapshot", &input.db_instance_identifier, source, o)
            .await?;
        Ok(t::RestoreDBInstanceFromDBSnapshotResult { db_instance: Some(db) })
    }

    /// The point a point-in-time restore may go back to, checked against the
    /// source's restorable window.
    fn check_restore_time(
        &self,
        earliest: Option<DateTime<Utc>>,
        latest: Option<DateTime<Utc>>,
        restore_time: Option<DateTime<Utc>>,
        use_latest: Option<bool>,
    ) -> Result<(), ServiceError> {
        match (restore_time, use_latest.unwrap_or(false)) {
            (Some(_), true) => Err(invalid_combination("Cannot specify both RestoreTime and UseLatestRestorableTime.")),
            (None, false) => {
                Err(invalid_combination("Either RestoreTime or UseLatestRestorableTime must be specified."))
            }
            (Some(t), false) => {
                let latest = latest.unwrap_or_else(|| self.now());
                if earliest.is_some_and(|e| t < e) || t > latest {
                    Err(errors::point_in_time_restore_not_enabled_fault(format!(
                        "Restore time {} is outside the restorable window.",
                        t.to_rfc3339()
                    )))
                } else {
                    Ok(())
                }
            }
            (None, true) => Ok(()),
        }
    }

    pub(crate) async fn restore_db_instance_to_point_in_time_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreDBInstanceToPointInTimeMessage,
    ) -> Result<t::RestoreDBInstanceToPointInTimeResult, ServiceError> {
        // The source: a live instance, or a retained (or replicated)
        // automated backup.
        let resource = match (&input.source_db_instance_identifier, &input.source_dbi_resource_id) {
            (Some(src), _) => self.instance(ctx, src)?.db.dbi_resource_id.unwrap_or_default(),
            (None, Some(res)) => res.clone(),
            (None, None) => {
                let a = input.source_db_instance_automated_backups_arn.clone().ok_or_else(|| {
                    invalid_combination(
                        "Specify SourceDBInstanceIdentifier, SourceDbiResourceId or SourceDBInstanceAutomatedBackupsArn.",
                    )
                })?;
                self.with_region(ctx, |r| {
                    r.retained_backups
                        .values()
                        .find(|b| b.db_instance_automated_backups_arn.as_ref() == Some(&a))
                        .and_then(|b| b.dbi_resource_id.clone())
                })
                .ok_or_else(|| {
                    errors::db_instance_automated_backup_not_found_fault(format!("Automated backup {a} not found."))
                })?
            }
        };
        let live = self.with_region(ctx, |r| {
            r.instances.values().find(|i| i.db.dbi_resource_id.as_deref() == Some(resource.as_str())).cloned()
        });
        let o = pitr_options(&input)?;
        let latest_snapshot = |this: &Self| {
            this.with_region(ctx, |r| {
                r.snapshots
                    .values()
                    .filter(|s| s.snapshot.dbi_resource_id.as_deref() == Some(resource.as_str()))
                    .max_by_key(|s| s.snapshot.snapshot_create_time)
                    .cloned()
            })
        };
        let (template, created, latest, log) = match &live {
            Some(rec) => {
                let id = rec.db.db_instance_identifier.clone().unwrap_or_default();
                authorize(
                    ctx,
                    "RestoreDBInstanceToPointInTime",
                    &db_arn(ctx, &id),
                    resource_tag_context("db", &rec.db.tag_list),
                )?;
                if rec.db.backup_retention_period.unwrap_or(0) == 0 {
                    return Err(errors::point_in_time_restore_not_enabled_fault(format!(
                        "Point-in-time restore is not enabled for DB instance {id}."
                    )));
                }
                let template = SnapshotRecord {
                    snapshot: t::DBSnapshot {
                        engine: rec.db.engine.clone(),
                        engine_version: rec.db.engine_version.clone(),
                        master_username: rec.db.master_username.clone(),
                        allocated_storage: rec.db.allocated_storage,
                        port: Some(rec.port),
                        license_model: rec.db.license_model.clone(),
                        iops: rec.db.iops,
                        storage_throughput: rec.db.storage_throughput,
                        storage_type: rec.db.storage_type.clone(),
                        encrypted: rec.db.storage_encrypted,
                        kms_key_id: rec.db.kms_key_id.clone(),
                        timezone: rec.db.timezone.clone(),
                        dbi_resource_id: rec.db.dbi_resource_id.clone(),
                        option_group_name: rec
                            .db
                            .option_group_memberships
                            .as_ref()
                            .and_then(|o| o.first())
                            .and_then(|o| o.option_group_name.clone()),
                        ..Default::default()
                    },
                    master_password: rec.master_password.clone(),
                    db_name: rec.db.db_name.clone(),
                    image: rec.image.clone(),
                    db_instance_class: rec.db.db_instance_class.clone().unwrap_or_default(),
                    ..Default::default()
                };
                (template, rec.db.instance_create_time, ctx.received_at, None)
            }
            None => {
                let b = self.with_region(ctx, |r| r.retained_backups.get(&resource).cloned()).ok_or_else(|| {
                    errors::db_instance_automated_backup_not_found_fault(format!(
                        "Automated backup for {resource} not found."
                    ))
                })?;
                authorize(
                    ctx,
                    "RestoreDBInstanceToPointInTime",
                    b.db_instance_automated_backups_arn.as_deref().unwrap_or_default(),
                    ConditionContext::new(),
                )?;
                let Some(snap) = latest_snapshot(self) else {
                    return Err(errors::db_instance_automated_backup_not_found_fault(format!(
                        "No restorable backup exists for {}.",
                        b.db_instance_identifier.unwrap_or_default()
                    )));
                };
                let log = self.with_region(ctx, |r| r.retained_logs.get(&resource).cloned());
                let latest = b.restore_window.as_ref().and_then(|w| w.latest_time).unwrap_or(ctx.received_at);
                (snap, b.instance_create_time, latest, log)
            }
        };
        let earliest = self.earliest_restorable(ctx, &resource, false, created);
        self.check_restore_time(earliest, Some(latest), input.restore_time, input.use_latest_restorable_time)?;
        let until = input.restore_time.unwrap_or(latest);
        let tmp_arn = arn(ctx, "snapshot", &format!("pitr-{}", resource_id("")));
        let target = backend_snapshot_name(&tmp_arn);
        let mut o = o;
        let mut source = SnapshotRecord { backend_name: target.clone(), has_data: false, ..template.clone() };
        if self.backend().runs_databases() {
            match &live {
                Some(rec) if rec.listen.is_some() => {
                    let spec = self.with_region(ctx, |r| self.instance_spec(r, rec, ctx));
                    if let Err(e) = self.backend().seal_log(&spec).await {
                        tracing::warn!(db = %rec.backend_name, "archiving the transaction log failed: {e}");
                    }
                    let sealed = chrono::Utc::now();
                    let until_wall = self.wall_time(until);
                    if until_wall >= sealed - chrono::Duration::seconds(1) {
                        // Nothing to replay: the restore is a copy of now.
                        source.has_data = self.backend().snapshot(&rec.backend_name, &target).await.is_ok();
                    } else {
                        let bases = self.recovery_bases(ctx, &resource, false, until_wall);
                        if bases.is_empty() {
                            tracing::warn!(db = %rec.backend_name, "no backup with data before the restore time");
                            source.has_data = self.backend().snapshot(&rec.backend_name, &target).await.is_ok();
                        } else {
                            source.has_data = true;
                            o.recovery = Some(Recovery {
                                spec,
                                bases,
                                log: LogSource::Database(rec.backend_name.clone()),
                                until: until_wall,
                            });
                        }
                    }
                    o.drop_snapshot = source.has_data;
                }
                Some(_) => {}
                None => {
                    // A deleted instance: its last data and log were kept.
                    let until_wall = self.wall_time(until);
                    match log {
                        Some(l) if l.data_time.is_some_and(|t| until_wall >= t) => {
                            source.has_data = self.backend().copy_snapshot(&l.backend_name, &target).await.is_ok();
                            o.drop_snapshot = source.has_data;
                        }
                        Some(l) => {
                            let bases = self.recovery_bases(ctx, &resource, false, until_wall);
                            if !bases.is_empty() {
                                let engine = engine_of(template.snapshot.engine.as_deref().unwrap_or_default())?;
                                source.has_data = true;
                                o.drop_snapshot = true;
                                o.recovery = Some(Recovery {
                                    spec: recovery_spec(
                                        ctx,
                                        engine,
                                        &template.image,
                                        &template.snapshot,
                                        &template.master_password,
                                    ),
                                    bases,
                                    log: LogSource::Snapshot(l.backend_name),
                                    until: until_wall,
                                });
                            }
                        }
                        None => {
                            // No log: the newest snapshot's data.
                            if template.has_data {
                                source.has_data =
                                    self.backend().copy_snapshot(&template.backend_name, &target).await.is_ok();
                                o.drop_snapshot = source.has_data;
                            }
                        }
                    }
                }
            }
        }
        let db = self
            .restore_instance(ctx, "RestoreDBInstanceToPointInTime", &input.target_db_instance_identifier, source, o)
            .await;
        if db.is_err() && self.backend().runs_databases() {
            let _ = self.backend().delete_snapshot(&target).await;
        }
        Ok(t::RestoreDBInstanceToPointInTimeResult { db_instance: Some(db?) })
    }

    pub(crate) fn describe_db_instance_automated_backups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBInstanceAutomatedBackupsMessage,
    ) -> Result<t::DBInstanceAutomatedBackupMessage, ServiceError> {
        authorize(ctx, "DescribeDBInstanceAutomatedBackups", &arn(ctx, "auto-backup", "*"), ConditionContext::new())?;
        let f = Filters::new(&input.filters, &["status", "db-instance-id", "dbi-resource-id"])?;
        let mut all: Vec<t::DBInstanceAutomatedBackup> = self.with_region(ctx, |r| {
            let mut v: Vec<_> = r
                .instances
                .values()
                .filter(|i| i.db.backup_retention_period.unwrap_or(0) > 0 && i.db.db_cluster_identifier.is_none())
                .map(|i| automated_backup(ctx, i))
                .collect();
            v.extend(r.retained_backups.values().cloned());
            v.extend(r.replicated_backups.values().cloned());
            v
        });
        let id = input.db_instance_identifier.as_deref().map(|i| name_of(i).to_ascii_lowercase());
        all.retain(|b| {
            id.as_ref().is_none_or(|i| b.db_instance_identifier.as_ref() == Some(i))
                && input.dbi_resource_id.as_ref().is_none_or(|d| b.dbi_resource_id.as_ref() == Some(d))
                && input
                    .db_instance_automated_backups_arn
                    .as_ref()
                    .is_none_or(|a| b.db_instance_automated_backups_arn.as_ref() == Some(a))
                && f.matches(|n| match n {
                    "status" => opt(&b.status),
                    "db-instance-id" => opt(&b.db_instance_identifier),
                    "dbi-resource-id" => opt(&b.dbi_resource_id),
                    _ => Vec::new(),
                })
        });
        if all.is_empty() && (input.dbi_resource_id.is_some() || id.is_some()) {
            return Err(errors::db_instance_automated_backup_not_found_fault("No automated backup found."));
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBInstanceAutomatedBackupMessage { marker, db_instance_automated_backups: Some(page) })
    }

    pub(crate) async fn delete_db_instance_automated_backup_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBInstanceAutomatedBackupMessage,
    ) -> Result<t::DeleteDBInstanceAutomatedBackupResult, ServiceError> {
        authorize(ctx, "DeleteDBInstanceAutomatedBackup", &arn(ctx, "auto-backup", "*"), ConditionContext::new())?;
        let resource = match (&input.dbi_resource_id, &input.db_instance_automated_backups_arn) {
            (Some(r), _) => r.clone(),
            (None, Some(a)) => self
                .with_region(ctx, |r| {
                    r.retained_backups
                        .values()
                        .find(|b| b.db_instance_automated_backups_arn.as_ref() == Some(a))
                        .and_then(|b| b.dbi_resource_id.clone())
                })
                .ok_or_else(|| {
                    errors::db_instance_automated_backup_not_found_fault(format!("Automated backup {a} not found."))
                })?,
            (None, None) => return Err(invalid_parameter("Specify DbiResourceId or DBInstanceAutomatedBackupsArn.")),
        };
        if self.with_region(ctx, |r| r.instances.values().any(|i| i.db.dbi_resource_id.as_ref() == Some(&resource))) {
            return Err(errors::invalid_db_instance_automated_backup_state_fault(
                "The automated backup is in use by a DB instance. Delete the DB instance first.",
            ));
        }
        let (b, snaps) = self.with_region(ctx, |r| {
            let b = r.retained_backups.remove(&resource);
            let keys: Vec<String> = r
                .snapshots
                .iter()
                .filter(|(_, s)| {
                    s.snapshot.snapshot_type.as_deref() == Some("automated")
                        && s.snapshot.dbi_resource_id.as_ref() == Some(&resource)
                })
                .map(|(k, _)| k.clone())
                .collect();
            let mut snaps: Vec<String> = keys
                .iter()
                .filter_map(|k| r.snapshots.remove(k))
                .filter(|s| s.has_data)
                .map(|s| s.backend_name)
                .collect();
            snaps.extend(r.retained_logs.remove(&resource).map(|l| l.backend_name));
            (b, snaps)
        });
        let mut b = b.ok_or_else(|| {
            errors::db_instance_automated_backup_not_found_fault(format!("Automated backup for {resource} not found."))
        })?;
        for s in snaps {
            let _ = self.backend().delete_snapshot(&s).await;
        }
        b.status = Some("deleting".into());
        Ok(t::DeleteDBInstanceAutomatedBackupResult { db_instance_automated_backup: Some(b) })
    }

    // Cluster snapshots.

    pub(crate) async fn create_db_cluster_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBClusterSnapshotMessage,
    ) -> Result<t::CreateDBClusterSnapshotResult, ServiceError> {
        let snap = identifier("DBClusterSnapshotIdentifier", &input.db_cluster_snapshot_identifier, 255)?;
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let tags = tags_from(&input.tags)?;
        authorize(ctx, "CreateDBClusterSnapshot", &arn(ctx, "cluster-snapshot", &snap), request_tag_context(&tags))?;
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "CreateDBClusterSnapshot",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        let status = rec.cluster.status.clone().unwrap_or_default();
        if status != "available" {
            return Err(super::invalid_cluster_state(&id, &status));
        }
        let s = self.snapshot_cluster(ctx, &id, &snap, "manual", tags).await?;
        Ok(t::CreateDBClusterSnapshotResult { db_cluster_snapshot: Some(s) })
    }

    pub(crate) fn describe_db_cluster_snapshots_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBClusterSnapshotsMessage,
    ) -> Result<t::DBClusterSnapshotMessage, ServiceError> {
        authorize(
            ctx,
            "DescribeDBClusterSnapshots",
            &arn(
                ctx,
                "cluster-snapshot",
                input.db_cluster_snapshot_identifier.as_deref().map(name_of).as_deref().unwrap_or("*"),
            ),
            ConditionContext::new(),
        )?;
        let f = Filters::new(&input.filters, &["db-cluster-id", "db-cluster-snapshot-id", "snapshot-type", "engine"])?;
        let caller = account_of(ctx);
        let wanted = input.db_cluster_snapshot_identifier.as_deref().map(|s| name_of(s).to_ascii_lowercase());
        let cluster = input.db_cluster_identifier.as_deref().map(|s| name_of(s).to_ascii_lowercase());
        let kind = input.snapshot_type.clone();
        let include_shared = input.include_shared.unwrap_or(false) || kind.as_deref() == Some("shared");
        let include_public = input.include_public.unwrap_or(false) || kind.as_deref() == Some("public");
        let mut all = Vec::new();
        {
            let st = self.lock();
            for (key, r) in &st.regions {
                let Some((account, region)) = key.split_once('/') else { continue };
                if region != ctx.region {
                    continue;
                }
                let own = account == caller;
                for s in r.cluster_snapshots.values() {
                    let shared = s.restore.iter().any(|a| a == &caller);
                    let public = s.restore.iter().any(|a| a == "all");
                    if !(own || (include_shared && shared) || (include_public && public)) {
                        continue;
                    }
                    let mut snap = s.snapshot.clone();
                    if !own {
                        snap.snapshot_type = Some(if shared { "shared" } else { "public" }.into());
                        snap.db_cluster_snapshot_identifier = snap.db_cluster_snapshot_arn.clone();
                    }
                    all.push(snap);
                }
            }
        }
        if let Some(w) = &wanted {
            all.retain(|s: &t::DBClusterSnapshot| {
                s.db_cluster_snapshot_identifier.as_ref() == Some(w)
                    || s.db_cluster_snapshot_arn.as_deref() == input.db_cluster_snapshot_identifier.as_deref()
            });
            if all.is_empty() {
                return Err(cluster_snapshot_not_found(w));
            }
        }
        let all: Vec<t::DBClusterSnapshot> = all
            .into_iter()
            .filter(|s| cluster.as_ref().is_none_or(|c| s.db_cluster_identifier.as_ref() == Some(c)))
            .filter(|s| kind.as_ref().is_none_or(|k| s.snapshot_type.as_ref() == Some(k)))
            .filter(|s| {
                input.db_cluster_resource_id.as_ref().is_none_or(|d| s.db_cluster_resource_id.as_ref() == Some(d))
            })
            .filter(|s| f.matches(|n| cluster_snapshot_filter(s, n)))
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBClusterSnapshotMessage { marker, db_cluster_snapshots: Some(page) })
    }

    pub(crate) async fn delete_db_cluster_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBClusterSnapshotMessage,
    ) -> Result<t::DeleteDBClusterSnapshotResult, ServiceError> {
        let id = name_of(&input.db_cluster_snapshot_identifier).to_ascii_lowercase();
        let rec = self
            .with_region(ctx, |r| r.cluster_snapshots.get(&id).cloned())
            .ok_or_else(|| cluster_snapshot_not_found(&id))?;
        authorize(
            ctx,
            "DeleteDBClusterSnapshot",
            &arn(ctx, "cluster-snapshot", &id),
            resource_tag_context("cluster-snapshot", &rec.snapshot.tag_list),
        )?;
        if rec.snapshot.snapshot_type.as_deref() == Some("automated") {
            return Err(errors::invalid_db_cluster_snapshot_state_fault("Only manual snapshots may be deleted."));
        }
        self.with_region(ctx, |r| r.cluster_snapshots.remove(&id));
        if rec.has_data {
            let _ = self.backend().delete_snapshot(&rec.backend_name).await;
        }
        let mut s = rec.snapshot;
        s.status = Some("deleted".into());
        Ok(t::DeleteDBClusterSnapshotResult { db_cluster_snapshot: Some(s) })
    }

    pub(crate) async fn copy_db_cluster_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::CopyDBClusterSnapshotMessage,
    ) -> Result<t::CopyDBClusterSnapshotResult, ServiceError> {
        let target =
            identifier("TargetDBClusterSnapshotIdentifier", &input.target_db_cluster_snapshot_identifier, 255)?;
        let source = self.find_cluster_snapshot(ctx, &input.source_db_cluster_snapshot_identifier)?;
        let tarn = arn(ctx, "cluster-snapshot", &target);
        let mut tags = tags_from(&input.tags)?;
        authorize(ctx, "CopyDBClusterSnapshot", &tarn, request_tag_context(&tags))?;
        authorize(
            ctx,
            "CopyDBClusterSnapshot",
            source.snapshot.db_cluster_snapshot_arn.as_deref().unwrap_or_default(),
            ConditionContext::new(),
        )?;
        if input.copy_tags == Some(true) {
            let mut base = source.snapshot.tag_list.clone().unwrap_or_default();
            merge_tags(&mut base, &tags);
            tags = base;
        }
        let encrypted = source.snapshot.storage_encrypted.unwrap_or(false);
        let source_region = parse_arn(source.snapshot.db_cluster_snapshot_arn.as_deref().unwrap_or_default())
            .map(|p| p.0)
            .unwrap_or_default();
        let kms_key = match (&input.kms_key_id, encrypted) {
            (Some(k), _) => Some(self.storage_key(
                ctx,
                Some(k),
                &source.snapshot.db_cluster_resource_id.clone().unwrap_or_default(),
            )?),
            (None, true) if source_region != ctx.region => {
                return Err(invalid_parameter(
                    "KmsKeyId must be specified when copying an encrypted snapshot to another Region.",
                ))
            }
            (None, true) => source.snapshot.kms_key_id.clone(),
            (None, false) => None,
        };
        let mut snap = source.snapshot.clone();
        snap.db_cluster_snapshot_identifier = Some(target.clone());
        snap.db_cluster_snapshot_arn = Some(tarn.clone());
        snap.snapshot_type = Some("manual".into());
        snap.snapshot_create_time = Some(ctx.received_at);
        snap.source_db_cluster_snapshot_arn = source.snapshot.db_cluster_snapshot_arn.clone();
        snap.storage_encrypted = Some(encrypted || kms_key.is_some());
        snap.kms_key_id = kms_key;
        snap.tag_list = Some(tags);
        snap.status = Some("available".into());
        let backend_name = backend_snapshot_name(&tarn);
        let has_data =
            source.has_data && self.backend().copy_snapshot(&source.backend_name, &backend_name).await.is_ok();
        self.with_region(ctx, |r| {
            if r.cluster_snapshots.contains_key(&target) {
                return Err(errors::db_cluster_snapshot_already_exists_fault(format!(
                    "Cannot copy the cluster snapshot because one with the identifier {target} already exists."
                )));
            }
            r.cluster_snapshots.insert(
                target.clone(),
                ClusterSnapshotRecord {
                    snapshot: snap.clone(),
                    restore: Vec::new(),
                    has_data,
                    backend_name,
                    ..source.clone()
                },
            );
            Ok(())
        })?;
        Ok(t::CopyDBClusterSnapshotResult { db_cluster_snapshot: Some(snap) })
    }

    pub(crate) fn describe_db_cluster_snapshot_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBClusterSnapshotAttributesMessage,
    ) -> Result<t::DescribeDBClusterSnapshotAttributesResult, ServiceError> {
        let id = name_of(&input.db_cluster_snapshot_identifier).to_ascii_lowercase();
        let rec = self
            .with_region(ctx, |r| r.cluster_snapshots.get(&id).cloned())
            .ok_or_else(|| cluster_snapshot_not_found(&id))?;
        authorize(
            ctx,
            "DescribeDBClusterSnapshotAttributes",
            &arn(ctx, "cluster-snapshot", &id),
            resource_tag_context("cluster-snapshot", &rec.snapshot.tag_list),
        )?;
        Ok(t::DescribeDBClusterSnapshotAttributesResult {
            db_cluster_snapshot_attributes_result: Some(t::DBClusterSnapshotAttributesResult {
                db_cluster_snapshot_identifier: Some(id),
                db_cluster_snapshot_attributes: Some(vec![t::DBClusterSnapshotAttribute {
                    attribute_name: Some("restore".into()),
                    attribute_values: Some(rec.restore),
                }]),
            }),
        })
    }

    pub(crate) fn modify_db_cluster_snapshot_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBClusterSnapshotAttributeMessage,
    ) -> Result<t::ModifyDBClusterSnapshotAttributeResult, ServiceError> {
        let id = name_of(&input.db_cluster_snapshot_identifier).to_ascii_lowercase();
        let rec = self
            .with_region(ctx, |r| r.cluster_snapshots.get(&id).cloned())
            .ok_or_else(|| cluster_snapshot_not_found(&id))?;
        authorize(
            ctx,
            "ModifyDBClusterSnapshotAttribute",
            &arn(ctx, "cluster-snapshot", &id),
            resource_tag_context("cluster-snapshot", &rec.snapshot.tag_list),
        )?;
        let restore = share(
            &input.attribute_name,
            &rec.restore,
            &input.values_to_add,
            &input.values_to_remove,
            rec.snapshot.snapshot_type.as_deref(),
            rec.snapshot.storage_encrypted == Some(true),
            rec.snapshot.kms_key_id.as_deref(),
        )?;
        self.with_region(ctx, |r| {
            if let Some(s) = r.cluster_snapshots.get_mut(&id) {
                s.restore = restore.clone();
            }
        });
        Ok(t::ModifyDBClusterSnapshotAttributeResult {
            db_cluster_snapshot_attributes_result: Some(t::DBClusterSnapshotAttributesResult {
                db_cluster_snapshot_identifier: Some(id),
                db_cluster_snapshot_attributes: Some(vec![t::DBClusterSnapshotAttribute {
                    attribute_name: Some("restore".into()),
                    attribute_values: Some(restore),
                }]),
            }),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn restore_cluster(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        source: ClusterSnapshotRecord,
        engine_version: Option<String>,
        o: ClusterRestore,
    ) -> Result<t::DBCluster, ServiceError> {
        let id = identifier("DBClusterIdentifier", id, 63)?;
        let carn = cluster_arn(ctx, &id);
        authorize(ctx, action, &carn, request_tag_context(&o.tags))?;
        if self.with_region(ctx, |r| r.clusters.contains_key(&id)) {
            return Err(errors::db_cluster_already_exists_fault("DB Cluster already exists"));
        }
        let s = &source.snapshot;
        let engine = engine_of(s.engine.as_deref().unwrap_or_default())?;
        let mut image = source.image.clone();
        let version = match &engine_version {
            Some(v) => {
                let target = engine
                    .version(v)
                    .ok_or_else(|| invalid_combination(format!("Cannot find version {v} for {}", engine.name)))?;
                if engine.version(s.engine_version.as_deref().unwrap_or_default()).map(|c| c.major)
                    == Some(target.major)
                {
                    image = target.image.to_string();
                }
                target
            }
            None => engine.version(s.engine_version.as_deref().unwrap_or_default()).unwrap_or(engine.default_version()),
        };
        let resource = resource_id("cluster-");
        let subnet_group = self.subnet_group(ctx, o.subnet_group.as_deref().unwrap_or("default"))?;
        let vpc = subnet_group.vpc_id.clone().unwrap_or_default();
        let sgs = self.security_groups(ctx, &o.vpc_security_group_ids, &vpc)?;
        let pg = self.param_group(
            ctx,
            o.parameter_group.as_deref().unwrap_or(&engine.default_parameter_group(version)),
            true,
        )?;
        let encrypted = s.storage_encrypted.unwrap_or(false) || o.kms_key_id.is_some();
        let kms_key = if encrypted {
            Some(self.storage_key(ctx, o.kms_key_id.as_deref().or(s.kms_key_id.as_deref()), &resource)?)
        } else {
            None
        };
        let mut zones: Vec<String> = subnet_group
            .subnets
            .iter()
            .flatten()
            .filter_map(|s| s.subnet_availability_zone.as_ref().and_then(|a| a.name.clone()))
            .collect();
        zones.sort();
        zones.dedup();
        zones.truncate(3);
        let cluster = t::DBCluster {
            allocated_storage: s.allocated_storage,
            availability_zones: Some(o.availability_zones.clone().unwrap_or(zones)),
            backup_retention_period: Some(o.backup_retention_period.unwrap_or(1)),
            database_name: o.database_name.clone().or(source.database_name.clone()),
            db_cluster_identifier: Some(id.clone()),
            db_cluster_parameter_group: Some(pg.name),
            db_subnet_group: subnet_group.db_subnet_group_name.clone(),
            status: Some("creating".into()),
            multi_az: Some(!engine.aurora),
            engine: s.engine.clone(),
            engine_version: Some(version.version.into()),
            port: Some(o.port.or(s.port).unwrap_or(engine.default_port)),
            master_username: s.master_username.clone(),
            db_cluster_option_group_memberships: Some(Vec::new()),
            preferred_backup_window: Some(
                o.preferred_backup_window.clone().unwrap_or_else(|| backup_window(&resource)),
            ),
            preferred_maintenance_window: Some(maintenance_window(&resource)),
            read_replica_identifiers: Some(Vec::new()),
            db_cluster_members: Some(Vec::new()),
            vpc_security_groups: Some(sgs),
            storage_encrypted: Some(encrypted),
            kms_key_id: kms_key,
            db_cluster_resource_id: Some(resource.clone()),
            db_cluster_arn: Some(carn),
            associated_roles: Some(Vec::new()),
            iam_database_authentication_enabled: Some(o.iam_auth.unwrap_or(false)),
            clone_group_id: o.clone_group_id.clone(),
            cluster_create_time: Some(ctx.received_at),
            enabled_cloudwatch_logs_exports: o.logs.clone(),
            engine_mode: Some("provisioned".into()),
            pending_modified_values: Some(t::ClusterPendingModifiedValues::default()),
            db_cluster_instance_class: o.db_cluster_instance_class.clone(),
            storage_type: o.storage_type.clone().or(s.storage_type.clone()).or(Some("aurora".into())),
            auto_minor_version_upgrade: Some(true),
            deletion_protection: Some(o.deletion_protection.unwrap_or(false)),
            http_endpoint_enabled: Some(false),
            activity_stream_status: Some("stopped".into()),
            copy_tags_to_snapshot: Some(o.copy_tags_to_snapshot.unwrap_or(false)),
            cross_account_clone: Some(false),
            domain_memberships: Some(Vec::new()),
            tag_list: Some(o.tags.clone()),
            network_type: Some("IPV4".into()),
            serverless_v2_scaling_configuration: o.serverless_v2_scaling_configuration.as_ref().map(|s| {
                t::ServerlessV2ScalingConfigurationInfo {
                    min_capacity: s.min_capacity,
                    max_capacity: s.max_capacity,
                    seconds_until_auto_pause: s.seconds_until_auto_pause,
                }
            }),
            monitoring_interval: Some(0),
            database_insights_mode: Some("standard".into()),
            performance_insights_enabled: Some(false),
            engine_lifecycle_support: Some("open-source-rds-extended-support".into()),
            ..Default::default()
        };
        let rec = ClusterRecord {
            cluster,
            master_password: source.master_password.clone(),
            backend_name: resource.to_ascii_lowercase(),
            listen: None,
            generation: 1,
            image,
            pending_reboot: false,
        };
        let launch = super::cluster::Launch {
            from_snapshot: source.has_data.then(|| source.backend_name.clone()),
            recovery: o.recovery,
            drop_snapshot: o.drop_snapshot,
        };
        self.launch_cluster(ctx, rec, launch).await
    }

    pub(crate) async fn restore_db_cluster_from_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreDBClusterFromSnapshotMessage,
    ) -> Result<t::RestoreDBClusterFromSnapshotResult, ServiceError> {
        let source = match self.find_cluster_snapshot(ctx, &input.snapshot_identifier) {
            Ok(s) => s,
            Err(e) => {
                if self.find_snapshot(ctx, &input.snapshot_identifier).is_ok() {
                    return Err(invalid_parameter(
                        "Restoring an Aurora DB cluster from a DB instance snapshot isn't supported by MWS.",
                    ));
                }
                return Err(e);
            }
        };
        authorize(
            ctx,
            "RestoreDBClusterFromSnapshot",
            source.snapshot.db_cluster_snapshot_arn.as_deref().unwrap_or_default(),
            ConditionContext::new(),
        )?;
        let wanted = engine_of(&input.engine)?;
        if Some(wanted.name) != source.snapshot.engine.as_deref() {
            return Err(invalid_parameter(format!(
                "The engine {} doesn't match the snapshot's engine {}.",
                wanted.name,
                source.snapshot.engine.clone().unwrap_or_default()
            )));
        }
        let o = ClusterRestore {
            availability_zones: input.availability_zones,
            port: input.port,
            subnet_group: input.db_subnet_group_name,
            database_name: input.database_name,
            vpc_security_group_ids: input.vpc_security_group_ids,
            tags: tags_from(&input.tags)?,
            kms_key_id: input.kms_key_id,
            iam_auth: input.enable_iam_database_authentication,
            logs: input.enable_cloudwatch_logs_exports,
            parameter_group: input.db_cluster_parameter_group_name,
            deletion_protection: input.deletion_protection,
            copy_tags_to_snapshot: input.copy_tags_to_snapshot,
            db_cluster_instance_class: input.db_cluster_instance_class,
            storage_type: input.storage_type,
            serverless_v2_scaling_configuration: input.serverless_v2_scaling_configuration,
            backup_retention_period: input.backup_retention_period,
            preferred_backup_window: input.preferred_backup_window,
            clone_group_id: None,
            ..Default::default()
        };
        let c = self
            .restore_cluster(
                ctx,
                "RestoreDBClusterFromSnapshot",
                &input.db_cluster_identifier,
                source,
                input.engine_version,
                o,
            )
            .await?;
        Ok(t::RestoreDBClusterFromSnapshotResult { db_cluster: Some(c) })
    }

    pub(crate) async fn restore_db_cluster_to_point_in_time_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreDBClusterToPointInTimeMessage,
    ) -> Result<t::RestoreDBClusterToPointInTimeResult, ServiceError> {
        let src = match (&input.source_db_cluster_identifier, &input.source_db_cluster_resource_id) {
            (Some(s), _) => self.cluster(ctx, s)?,
            (None, Some(res)) => self
                .with_region(ctx, |r| {
                    r.clusters.values().find(|c| c.cluster.db_cluster_resource_id.as_ref() == Some(res)).cloned()
                })
                .ok_or_else(|| super::cluster_not_found(res))?,
            (None, None) => {
                return Err(invalid_parameter("Specify SourceDBClusterIdentifier or SourceDbClusterResourceId."))
            }
        };
        let sid = src.cluster.db_cluster_identifier.clone().unwrap_or_default();
        authorize(
            ctx,
            "RestoreDBClusterToPointInTime",
            &cluster_arn(ctx, &sid),
            resource_tag_context("cluster", &src.cluster.tag_list),
        )?;
        let copy_on_write = match input.restore_type.as_deref() {
            None | Some("full-copy") => false,
            Some("copy-on-write") => true,
            Some(other) => return Err(invalid_parameter(format!("Invalid RestoreType: {other}"))),
        };
        if copy_on_write && input.restore_to_time.is_some() {
            return Err(invalid_combination("You can't specify RestoreToTime when RestoreType is copy-on-write."));
        }
        if !copy_on_write || input.restore_to_time.is_some() || input.use_latest_restorable_time.is_some() {
            self.check_restore_time(
                self.earliest_restorable(
                    ctx,
                    src.cluster.db_cluster_resource_id.as_deref().unwrap_or_default(),
                    true,
                    src.cluster.earliest_restorable_time,
                ),
                Some(ctx.received_at),
                input.restore_to_time,
                input.use_latest_restorable_time.or(copy_on_write.then_some(true)),
            )?;
        }
        let tmp_arn = arn(ctx, "cluster-snapshot", &format!("pitr-{}", resource_id("")));
        let target = backend_snapshot_name(&tmp_arn);
        let mut recovery = None;
        let mut has_data = false;
        if self.backend().runs_databases() && src.listen.is_some() {
            let spec = self.with_region(ctx, |r| self.cluster_spec(r, &src, ctx));
            if let Err(e) = self.backend().seal_log(&spec).await {
                tracing::warn!(cluster = %sid, "archiving the transaction log failed: {e}");
            }
            let sealed = chrono::Utc::now();
            let until_wall = input.restore_to_time.map(|t| self.wall_time(t));
            let resource = src.cluster.db_cluster_resource_id.clone().unwrap_or_default();
            let bases = until_wall
                .filter(|u| *u < sealed - chrono::Duration::seconds(1))
                .map(|u| self.recovery_bases(ctx, &resource, true, u))
                .unwrap_or_default();
            match until_wall {
                Some(u) if !bases.is_empty() => {
                    has_data = true;
                    recovery =
                        Some(Recovery { spec, bases, log: LogSource::Database(src.backend_name.clone()), until: u });
                }
                _ => has_data = self.backend().snapshot(&src.backend_name, &target).await.is_ok(),
            }
        }
        let source = ClusterSnapshotRecord {
            snapshot: t::DBClusterSnapshot {
                engine: src.cluster.engine.clone(),
                engine_version: src.cluster.engine_version.clone(),
                master_username: src.cluster.master_username.clone(),
                allocated_storage: src.cluster.allocated_storage,
                port: src.cluster.port,
                storage_encrypted: src.cluster.storage_encrypted,
                kms_key_id: src.cluster.kms_key_id.clone(),
                storage_type: src.cluster.storage_type.clone(),
                ..Default::default()
            },
            master_password: src.master_password.clone(),
            database_name: src.cluster.database_name.clone(),
            image: src.image.clone(),
            restore: Vec::new(),
            has_data,
            backend_name: target.clone(),
            data_time: None,
        };
        let clone_group = copy_on_write
            .then(|| src.cluster.clone_group_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()));
        if let Some(g) = &clone_group {
            self.with_region(ctx, |r| {
                if let Some(c) = r.clusters.get_mut(&sid) {
                    c.cluster.clone_group_id = Some(g.clone());
                }
            });
        }
        let o = ClusterRestore {
            availability_zones: None,
            port: input.port,
            subnet_group: input.db_subnet_group_name.or(src.cluster.db_subnet_group.clone()),
            database_name: None,
            vpc_security_group_ids: input.vpc_security_group_ids,
            tags: tags_from(&input.tags)?,
            kms_key_id: input.kms_key_id,
            iam_auth: input.enable_iam_database_authentication,
            logs: input.enable_cloudwatch_logs_exports,
            parameter_group: input.db_cluster_parameter_group_name,
            deletion_protection: input.deletion_protection,
            copy_tags_to_snapshot: input.copy_tags_to_snapshot,
            db_cluster_instance_class: input.db_cluster_instance_class,
            storage_type: input.storage_type,
            serverless_v2_scaling_configuration: input.serverless_v2_scaling_configuration,
            backup_retention_period: input.backup_retention_period,
            preferred_backup_window: input.preferred_backup_window,
            clone_group_id: clone_group,
            recovery,
            drop_snapshot: has_data,
        };
        let result = self
            .restore_cluster(ctx, "RestoreDBClusterToPointInTime", &input.db_cluster_identifier, source, None, o)
            .await;
        if result.is_err() && has_data {
            let _ = self.backend().delete_snapshot(&target).await;
        }
        Ok(t::RestoreDBClusterToPointInTimeResult { db_cluster: Some(result?) })
    }

    pub(crate) fn describe_db_cluster_automated_backups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBClusterAutomatedBackupsMessage,
    ) -> Result<t::DBClusterAutomatedBackupMessage, ServiceError> {
        authorize(
            ctx,
            "DescribeDBClusterAutomatedBackups",
            &arn(ctx, "cluster-auto-backup", "*"),
            ConditionContext::new(),
        )?;
        let f = Filters::new(&input.filters, &["status", "db-cluster-id", "db-cluster-resource-id"])?;
        let mut all: Vec<t::DBClusterAutomatedBackup> =
            self.with_region(ctx, |r| r.retained_cluster_backups.values().cloned().collect());
        let id = input.db_cluster_identifier.as_deref().map(|i| name_of(i).to_ascii_lowercase());
        all.retain(|b| {
            id.as_ref().is_none_or(|i| b.db_cluster_identifier.as_ref() == Some(i))
                && input.db_cluster_resource_id.as_ref().is_none_or(|d| b.db_cluster_resource_id.as_ref() == Some(d))
                && f.matches(|n| match n {
                    "status" => opt(&b.status),
                    "db-cluster-id" => opt(&b.db_cluster_identifier),
                    "db-cluster-resource-id" => opt(&b.db_cluster_resource_id),
                    _ => Vec::new(),
                })
        });
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBClusterAutomatedBackupMessage { marker, db_cluster_automated_backups: Some(page) })
    }

    pub(crate) async fn delete_db_cluster_automated_backup_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBClusterAutomatedBackupMessage,
    ) -> Result<t::DeleteDBClusterAutomatedBackupResult, ServiceError> {
        authorize(
            ctx,
            "DeleteDBClusterAutomatedBackup",
            &arn(ctx, "cluster-auto-backup", "*"),
            ConditionContext::new(),
        )?;
        let resource = input.db_cluster_resource_id.clone();
        let (b, snaps) = self.with_region(ctx, |r| {
            let b = r.retained_cluster_backups.remove(&resource);
            let keys: Vec<String> = r
                .cluster_snapshots
                .iter()
                .filter(|(_, s)| {
                    s.snapshot.snapshot_type.as_deref() == Some("automated")
                        && s.snapshot.db_cluster_resource_id.as_ref() == Some(&resource)
                })
                .map(|(k, _)| k.clone())
                .collect();
            let snaps: Vec<String> = keys
                .iter()
                .filter_map(|k| r.cluster_snapshots.remove(k))
                .filter(|s| s.has_data)
                .map(|s| s.backend_name)
                .collect();
            (b, snaps)
        });
        let mut b = b.ok_or_else(|| {
            errors::db_cluster_automated_backup_not_found_fault(format!("Automated backup for {resource} not found."))
        })?;
        for s in snaps {
            let _ = self.backend().delete_snapshot(&s).await;
        }
        b.status = Some("deleting".into());
        Ok(t::DeleteDBClusterAutomatedBackupResult { db_cluster_automated_backup: Some(b) })
    }
}

#[derive(Default)]
struct ClusterRestore {
    availability_zones: Option<Vec<String>>,
    port: Option<i32>,
    subnet_group: Option<String>,
    database_name: Option<String>,
    vpc_security_group_ids: Option<Vec<String>>,
    tags: Vec<t::Tag>,
    kms_key_id: Option<String>,
    iam_auth: Option<bool>,
    logs: Option<Vec<String>>,
    parameter_group: Option<String>,
    deletion_protection: Option<bool>,
    copy_tags_to_snapshot: Option<bool>,
    db_cluster_instance_class: Option<String>,
    storage_type: Option<String>,
    serverless_v2_scaling_configuration: Option<t::ServerlessV2ScalingConfiguration>,
    backup_retention_period: Option<i32>,
    preferred_backup_window: Option<String>,
    clone_group_id: Option<String>,
    recovery: Option<Recovery>,
    drop_snapshot: bool,
}

fn pitr_options(input: &t::RestoreDBInstanceToPointInTimeMessage) -> Result<RestoreOptions, ServiceError> {
    Ok(RestoreOptions {
        class: input.db_instance_class.clone(),
        port: input.port,
        availability_zone: input.availability_zone.clone(),
        subnet_group: input.db_subnet_group_name.clone(),
        multi_az: input.multi_az,
        publicly_accessible: input.publicly_accessible,
        auto_minor_version_upgrade: input.auto_minor_version_upgrade,
        db_name: input.db_name.clone(),
        iops: input.iops,
        storage_type: input.storage_type.clone(),
        option_group: input.option_group_name.clone(),
        tags: tags_from(&input.tags)?,
        vpc_security_group_ids: input.vpc_security_group_ids.clone(),
        copy_tags_to_snapshot: input.copy_tags_to_snapshot,
        iam_auth: input.enable_iam_database_authentication,
        logs: input.enable_cloudwatch_logs_exports.clone(),
        parameter_group: input.db_parameter_group_name.clone(),
        deletion_protection: input.deletion_protection,
        allocated_storage: input.allocated_storage,
        backup_retention_period: input.backup_retention_period,
        preferred_backup_window: input.preferred_backup_window.clone(),
        ca_certificate_identifier: input.ca_certificate_identifier.clone(),
        manage_master_user_password: input.manage_master_user_password,
        master_user_secret_kms_key_id: input.master_user_secret_kms_key_id.clone(),
        ..Default::default()
    })
}

/// Apply a `restore` attribute change: account ids, or `all` for public.
fn share(
    attribute: &str,
    current: &[String],
    add: &Option<Vec<String>>,
    remove: &Option<Vec<String>>,
    snapshot_type: Option<&str>,
    encrypted: bool,
    kms_key: Option<&str>,
) -> Result<Vec<String>, ServiceError> {
    if attribute != "restore" {
        return Err(invalid_parameter(format!("Invalid snapshot attribute name: {attribute}")));
    }
    if snapshot_type == Some("automated") {
        return Err(errors::invalid_db_snapshot_state_fault(
            "You can't share an automated snapshot. Copy it to a manual snapshot first.",
        ));
    }
    let mut out = current.to_vec();
    for a in add.iter().flatten() {
        if a != "all" && (a.len() != 12 || !a.chars().all(|c| c.is_ascii_digit())) {
            return Err(invalid_parameter(format!("Invalid account identifier: {a}")));
        }
        if a == "all" && encrypted {
            return Err(invalid_parameter("Encrypted snapshots can't be made public."));
        }
        if encrypted && kms_key.is_some_and(|k| k.contains(":alias/aws/") || k.ends_with("alias/aws/rds")) {
            return Err(invalid_parameter("Snapshots encrypted with the AWS managed key can't be shared."));
        }
        if !out.contains(a) {
            out.push(a.clone());
        }
    }
    out.retain(|a| !remove.iter().flatten().any(|r| r == a));
    if out.len() > 20 {
        return Err(errors::shared_snapshot_quota_exceeded_fault("A snapshot can be shared with at most 20 accounts."));
    }
    Ok(out)
}

impl Rds {
    /// A new cluster `new_id` holding a copy of cluster `source_id`'s data
    /// as of now (Blue/Green deployments' green cluster).
    pub(crate) async fn clone_cluster(
        &self,
        ctx: &RequestContext,
        source_id: &str,
        new_id: &str,
        parameter_group: Option<String>,
        engine_version: Option<String>,
        tags: Vec<t::Tag>,
    ) -> Result<t::DBCluster, ServiceError> {
        let src = self.cluster(ctx, source_id)?;
        let tmp_arn = arn(ctx, "cluster-snapshot", &format!("bg-{}", resource_id("")));
        let target = backend_snapshot_name(&tmp_arn);
        let has_data = self.backend().runs_databases()
            && src.listen.is_some()
            && self.backend().snapshot(&src.backend_name, &target).await.is_ok();
        let source = ClusterSnapshotRecord {
            snapshot: t::DBClusterSnapshot {
                engine: src.cluster.engine.clone(),
                engine_version: src.cluster.engine_version.clone(),
                master_username: src.cluster.master_username.clone(),
                allocated_storage: src.cluster.allocated_storage,
                port: src.cluster.port,
                storage_encrypted: src.cluster.storage_encrypted,
                kms_key_id: src.cluster.kms_key_id.clone(),
                storage_type: src.cluster.storage_type.clone(),
                ..Default::default()
            },
            master_password: src.master_password.clone(),
            database_name: src.cluster.database_name.clone(),
            image: src.image.clone(),
            restore: Vec::new(),
            has_data,
            backend_name: target.clone(),
            data_time: None,
        };
        let o = ClusterRestore {
            subnet_group: src.cluster.db_subnet_group.clone(),
            vpc_security_group_ids: src
                .cluster
                .vpc_security_groups
                .as_ref()
                .map(|g| g.iter().filter_map(|g| g.vpc_security_group_id.clone()).collect()),
            tags,
            parameter_group: parameter_group.or(src.cluster.db_cluster_parameter_group.clone()),
            serverless_v2_scaling_configuration: src.cluster.serverless_v2_scaling_configuration.as_ref().map(|s| {
                t::ServerlessV2ScalingConfiguration {
                    min_capacity: s.min_capacity,
                    max_capacity: s.max_capacity,
                    seconds_until_auto_pause: s.seconds_until_auto_pause,
                }
            }),
            backup_retention_period: src.cluster.backup_retention_period,
            drop_snapshot: has_data,
            ..Default::default()
        };
        let r = self.restore_cluster(ctx, "CreateBlueGreenDeployment", new_id, source, engine_version, o).await;
        if r.is_err() && has_data {
            let _ = self.backend().delete_snapshot(&target).await;
        }
        r
    }
}
