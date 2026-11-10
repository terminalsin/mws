//! DB instances: create, describe, modify, delete, start, stop, reboot,
//! read replicas and IAM roles.

use std::collections::BTreeMap;

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::maintenance::operational;
use super::pitr::Recovery;
use super::{
    authorize, check_db_name, check_password, check_username, cond, db_arn, instance_host, instance_not_found,
    invalid_instance_state,
};
use crate::catalog::{self, Engine, Version};
use crate::generated::{errors, types as t};
use crate::state::{InstanceRecord, Listen, RetainedLog};
use crate::util::{
    account_of, backup_window, check_backup_window, check_maintenance_window, identifier, invalid_combination,
    invalid_parameter, maintenance_window, missing, name_of, opt, paginate, request_tag_context, resource_id,
    resource_tag_context, tags_from, Filters,
};
use crate::Rds;

/// What a new instance needs beyond the request: used by create, restore
/// and read replicas.
pub(crate) struct NewInstance {
    pub db: t::DBInstance,
    pub master_password: String,
    pub port: i32,
    pub image: String,
    /// Restore the backend data from this snapshot.
    pub from_snapshot: Option<String>,
    /// Make an automated backup once available.
    pub first_backup: bool,
    /// Build `from_snapshot` by rolling a backup forward first.
    pub recovery: Option<Recovery>,
    /// `from_snapshot` is a temporary copy, dropped once restored.
    pub drop_snapshot: bool,
}

pub(crate) fn resolve_version(
    engine: &'static Engine,
    wanted: &Option<String>,
) -> Result<&'static Version, ServiceError> {
    match wanted {
        None => Ok(engine.default_version()),
        Some(v) => {
            engine.version(v).ok_or_else(|| invalid_combination(format!("Cannot find version {v} for {}", engine.name)))
        }
    }
}

pub(crate) fn engine_of(name: &str) -> Result<&'static Engine, ServiceError> {
    catalog::engine(&name.to_ascii_lowercase()).ok_or_else(|| invalid_parameter(format!("Invalid DB engine: {name}")))
}

pub(crate) fn check_class(engine: &Engine, version: &Version, class: &str) -> Result<(), ServiceError> {
    if catalog::class_supported(engine, class) {
        Ok(())
    } else {
        Err(invalid_combination(format!(
            "RDS does not support creating a DB instance with the following combination: DBInstanceClass={class}, Engine={}, EngineVersion={}, LicenseModel={}. For supported combinations of instance class and database engine version, see the documentation.",
            engine.name, version.version, engine.license
        )))
    }
}

/// Storage settings of a standalone instance: (type, allocated, iops,
/// throughput).
pub(crate) fn storage(
    engine: &Engine,
    storage_type: &Option<String>,
    allocated: Option<i32>,
    iops: Option<i32>,
    throughput: Option<i32>,
) -> Result<(String, i32, Option<i32>, Option<i32>), ServiceError> {
    let st = storage_type.clone().unwrap_or_else(|| if iops.is_some() { "io1".into() } else { "gp3".into() });
    if !["gp2", "gp3", "io1", "io2", "standard"].contains(&st.as_str()) {
        return Err(invalid_parameter(format!("Invalid storage type: {st}")));
    }
    let size = allocated.unwrap_or(0);
    let (min, max) = catalog::storage_range(engine, &st);
    if !(min..=max).contains(&size) {
        return Err(invalid_parameter(format!(
            "Invalid storage size for engine name {} and storage type {st}: {size}",
            engine.name
        )));
    }
    let (iops, throughput) = match st.as_str() {
        "io1" | "io2" => {
            let i = iops.ok_or_else(|| invalid_combination(format!("You must specify IOPS for storage type {st}")))?;
            (Some(i), None)
        }
        "gp3" => {
            if size < 400 && (iops.is_some() || throughput.is_some()) {
                return Err(invalid_combination(
                    "You can't specify IOPS or storage throughput for engine postgres and a storage size less than 400.",
                ));
            }
            (Some(iops.unwrap_or(3000)), Some(throughput.unwrap_or(125)))
        }
        _ => {
            if iops.is_some() {
                return Err(invalid_combination(format!("IOPS isn't supported for storage type {st}.")));
            }
            (None, None)
        }
    };
    Ok((st, size, iops, throughput))
}

pub(crate) fn instance_filter(db: &t::DBInstance, name: &str) -> Vec<String> {
    match name {
        "db-cluster-id" => {
            let mut v = opt(&db.db_cluster_identifier);
            if let Some(c) = &db.db_cluster_identifier {
                if let Some(a) = &db.db_instance_arn {
                    v.push(a.replace(
                        &format!(":db:{}", db.db_instance_identifier.clone().unwrap_or_default()),
                        &format!(":cluster:{c}"),
                    ));
                }
            }
            v
        }
        "db-instance-id" => {
            let mut v = opt(&db.db_instance_identifier);
            v.extend(opt(&db.db_instance_arn));
            v
        }
        "dbi-resource-id" => opt(&db.dbi_resource_id),
        "domain" => db.domain_memberships.iter().flatten().filter_map(|d| d.domain.clone()).collect(),
        "engine" => opt(&db.engine),
        _ => Vec::new(),
    }
}

impl Rds {
    /// Look up an instance by identifier or ARN.
    pub(crate) fn instance(&self, ctx: &RequestContext, id: &str) -> Result<InstanceRecord, ServiceError> {
        let id = name_of(id).to_ascii_lowercase();
        self.with_region(ctx, |r| r.instances.get(&id).cloned()).ok_or_else(|| instance_not_found(&id))
    }

    /// The instance as `Describe*` shows it.
    pub(crate) fn instance_view(&self, ctx: &RequestContext, rec: &InstanceRecord) -> t::DBInstance {
        let mut db = rec.db.clone();
        let status = db.db_instance_status.clone().unwrap_or_default();
        if matches!(status.as_str(), "creating" | "deleting" | "failed") && rec.listen.is_none() {
            db.endpoint = None;
        } else {
            let id = db.db_instance_identifier.clone().unwrap_or_default();
            let listen = match &db.db_cluster_identifier {
                Some(c) => self.with_region(ctx, |r| r.clusters.get(c).and_then(|c| c.listen.clone())),
                None => rec.listen.clone(),
            };
            db.endpoint = Some(self.endpoint_for(ctx, &instance_host(ctx, &id), rec.port, &listen));
        }
        // The log is archived continuously: restorable up to now.
        if operational(&status) && db.backup_retention_period.unwrap_or(0) > 0 && db.db_cluster_identifier.is_none() {
            db.latest_restorable_time = Some(ctx.received_at);
        }
        db
    }

    /// Store a new instance and start it.
    pub(crate) async fn launch_instance(
        &self,
        ctx: &RequestContext,
        new: NewInstance,
    ) -> Result<t::DBInstance, ServiceError> {
        let id = new.db.db_instance_identifier.clone().unwrap_or_default();
        let resource = new.db.dbi_resource_id.clone().unwrap_or_default();
        let in_cluster = new.db.db_cluster_identifier.clone();
        let rec = InstanceRecord {
            db: new.db,
            master_password: new.master_password,
            backend_name: resource.to_ascii_lowercase(),
            listen: None,
            generation: 1,
            port: new.port,
            image: new.image,
            pending_reboot: false,
            ..Default::default()
        };
        let max = self.quota(ctx, crate::quotas::DB_INSTANCES);
        let count = self.with_region(ctx, |r| r.instances.len()) as i64;
        if count >= max {
            return Err(errors::instance_quota_exceeded_fault(format!("Cannot create more than {max} DB instances.")));
        }
        self.with_region(ctx, |r| {
            if r.instances.contains_key(&id) {
                return Err(errors::db_instance_already_exists_fault("DB instance already exists"));
            }
            r.instances.insert(id.clone(), rec.clone());
            if let Some(c) = in_cluster.as_ref().and_then(|c| r.clusters.get_mut(c)) {
                let members = c.cluster.db_cluster_members.get_or_insert_with(Vec::new);
                let writer = !members.iter().any(|m| m.is_cluster_writer == Some(true));
                members.push(t::DBClusterMember {
                    db_instance_identifier: Some(id.clone()),
                    is_cluster_writer: Some(writer),
                    db_cluster_parameter_group_status: Some("in-sync".into()),
                    promotion_tier: rec.db.promotion_tier,
                });
            }
            Ok(())
        })?;
        let view = self.instance_view(ctx, &rec);
        let arn = db_arn(ctx, &id);
        self.emit(ctx, "db-instance", &id, &arn, &["creation"], "DB instance created", "RDS-EVENT-0005");
        match in_cluster {
            Some(cluster) => {
                // Cluster members run on the cluster's database.
                let available = self
                    .with_region(ctx, |r| {
                        r.clusters.get(&cluster).map(|c| c.cluster.status.as_deref() == Some("available"))
                    })
                    .unwrap_or(false);
                if available {
                    self.set_instance_status(ctx, &id, 1, "available", None);
                }
            }
            None => {
                let this = self.clone();
                let ctx2 = ctx.clone();
                let (from, first_backup) = (new.from_snapshot, new.first_backup);
                let (recovery, drop_snapshot) = (new.recovery, new.drop_snapshot);
                self.run_task(async move {
                    let spec =
                        this.with_region(&ctx2, |r| r.instances.get(&id).map(|rec| this.instance_spec(r, rec, &ctx2)));
                    let Some(spec) = spec else { return };
                    if let (Some(rc), Some(target)) = (&recovery, &from) {
                        if let Err(e) = this.recover_into(rc, target).await {
                            tracing::warn!(db = %id, "point-in-time recovery failed: {e}");
                            this.set_instance_status(&ctx2, &id, 1, "incompatible-restore", None);
                            this.emit(
                                &ctx2,
                                "db-instance",
                                &id,
                                &db_arn(&ctx2, &id),
                                &["failure"],
                                &format!("Point-in-time recovery failed: {e}"),
                                "RDS-EVENT-0035",
                            );
                            return;
                        }
                    }
                    let created = this.backend().create(&spec, from.as_deref()).await;
                    if drop_snapshot {
                        if let Some(f) = &from {
                            let _ = this.backend().delete_snapshot(f).await;
                        }
                    }
                    match created {
                        Ok(l) => {
                            let listen = Listen { host: l.host, port: l.port };
                            // creating -> backing-up (the first automated
                            // backup) -> available.
                            if first_backup {
                                if this.set_instance_status(&ctx2, &id, 1, "backing-up", Some(listen)) {
                                    this.automated_snapshot(&ctx2, &id).await;
                                    this.set_instance_status(&ctx2, &id, 1, "available", None);
                                }
                            } else {
                                this.set_instance_status(&ctx2, &id, 1, "available", Some(listen));
                            }
                        }
                        Err(e) => {
                            tracing::warn!(db = %id, "creating the database failed: {e}");
                            this.set_instance_status(&ctx2, &id, 1, "failed", None);
                            this.emit(
                                &ctx2,
                                "db-instance",
                                &id,
                                &db_arn(&ctx2, &id),
                                &["failure"],
                                &format!("DB instance could not be created: {e}"),
                                "RDS-EVENT-0031",
                            );
                        }
                    }
                })
                .await;
            }
        }
        Ok(view)
    }

    /// Keep a deleted instance's last data and transaction log for
    /// point-in-time restores of its retained automated backup.
    pub(crate) async fn keep_log(&self, ctx: &RequestContext, rec: &InstanceRecord) -> Option<RetainedLog> {
        let spec = self.with_region(ctx, |r| self.instance_spec(r, rec, ctx));
        let _ = self.backend().seal_log(&spec).await;
        let name = format!("log-{}", rec.backend_name);
        let wall = chrono::Utc::now();
        match self.backend().snapshot(&rec.backend_name, &name).await {
            Ok(()) => Some(RetainedLog { backend_name: name, data_time: Some(wall) }),
            Err(e) => {
                tracing::warn!(db = %rec.backend_name, "keeping the transaction log failed: {e}");
                None
            }
        }
    }

    /// Move an instance to `status` if no newer change happened since
    /// `generation`. Returns whether it did.
    pub(crate) fn set_instance_status(
        &self,
        ctx: &RequestContext,
        id: &str,
        generation: u64,
        status: &str,
        listen: Option<Listen>,
    ) -> bool {
        let now = self.now();
        self.with_region(ctx, |r| {
            let Some(rec) = r.instances.get_mut(id) else { return false };
            if rec.generation != generation {
                return false;
            }
            // Back up after a storage change: optimization goes on.
            let status = match status {
                "available" if rec.storage_optimized_until.is_some_and(|u| u > now) => "storage-optimization",
                s => s,
            };
            rec.db.db_instance_status = Some(status.to_string());
            if listen.is_some() {
                rec.listen = listen;
            }
            if operational(status) {
                if let Some(p) = rec.db.pending_modified_values.as_mut() {
                    p.master_user_password = None;
                }
                if rec.db.backup_retention_period.unwrap_or(0) > 0 {
                    rec.db.latest_restorable_time = Some(now);
                }
            }
            true
        })
    }

    /// Bump an instance's generation and set a transitional status.
    pub(crate) fn begin_instance(&self, ctx: &RequestContext, id: &str, status: &str) -> u64 {
        self.with_region(ctx, |r| {
            let rec = r.instances.get_mut(id).expect("checked by the caller");
            rec.generation += 1;
            rec.db.db_instance_status = Some(status.to_string());
            rec.generation
        })
    }

    /// (Re)start an instance's database with its current settings, then
    /// make it available.
    pub(crate) async fn restart_instance(
        &self,
        ctx: &RequestContext,
        id: &str,
        generation: u64,
        event: (&'static str, &'static str),
    ) {
        let this = self.clone();
        let ctx = ctx.clone();
        let id = id.to_string();
        self.run_task(async move {
            let spec = this.with_region(&ctx, |r| {
                let rec = r.instances.get(&id)?;
                match rec.db.db_cluster_identifier.as_ref().and_then(|c| r.clusters.get(c)) {
                    Some(c) => Some(this.cluster_spec(r, c, &ctx)),
                    None => Some(this.instance_spec(r, rec, &ctx)),
                }
            });
            let Some(spec) = spec else { return };
            match this.backend().start(&spec).await {
                Ok(l) => {
                    let listen = Some(Listen { host: l.host, port: l.port });
                    if this.set_instance_status(&ctx, &id, generation, "available", listen.clone()) {
                        this.with_region(&ctx, |r| {
                            if let Some(rec) = r.instances.get_mut(&id) {
                                rec.pending_reboot = false;
                                for g in rec.db.db_parameter_groups.iter_mut().flatten() {
                                    g.parameter_apply_status = Some("in-sync".into());
                                }
                                if let Some(c) =
                                    rec.db.db_cluster_identifier.clone().and_then(|c| r.clusters.get_mut(&c))
                                {
                                    c.listen = listen;
                                }
                            }
                        });
                        this.emit(&ctx, "db-instance", &id, &db_arn(&ctx, &id), &["availability"], event.0, event.1);
                    }
                }
                Err(e) => {
                    tracing::warn!(db = %id, "starting the database failed: {e}");
                    this.set_instance_status(&ctx, &id, generation, "incompatible-restore", None);
                }
            }
        })
        .await;
    }

    pub(crate) async fn create_db_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBInstanceMessage,
    ) -> Result<t::CreateDBInstanceResult, ServiceError> {
        let id = identifier("DBInstanceIdentifier", &input.db_instance_identifier, 63)?;
        let engine = engine_of(&input.engine)?;
        let tags = tags_from(&input.tags)?;
        let arn = db_arn(ctx, &id);
        let mut c = request_tag_context(&tags);
        c.extend(cond(&[
            ("rds:DatabaseEngine", Some(engine.name.to_string())),
            ("rds:DatabaseClass", Some(input.db_instance_class.clone())),
            ("rds:DatabaseName", input.db_name.clone()),
            ("rds:StorageEncrypted", Some(input.storage_encrypted.unwrap_or(false).to_string())),
            ("rds:MultiAz", Some(input.multi_az.unwrap_or(false).to_string())),
            ("rds:StorageSize", input.allocated_storage.map(|s| s.to_string())),
            ("rds:Piops", input.iops.map(|s| s.to_string())),
            ("rds:Vpc", Some("true".into())),
            ("rds:ManageMasterUserPassword", input.manage_master_user_password.map(|b| b.to_string())),
        ]));
        authorize(ctx, "CreateDBInstance", &arn, c.clone())?;
        if !tags.is_empty() {
            authorize(ctx, "AddTagsToResource", &arn, c)?;
        }
        if self.with_region(ctx, |r| r.instances.contains_key(&id)) {
            return Err(errors::db_instance_already_exists_fault("DB instance already exists"));
        }
        self.check_monitoring(ctx, input.monitoring_interval, input.monitoring_role_arn.as_deref(), &arn)?;
        let class = input.db_instance_class.clone();
        let manage = input.manage_master_user_password.unwrap_or(false);
        let cluster = match &input.db_cluster_identifier {
            Some(cid) => {
                let cid = cid.to_ascii_lowercase();
                Some(
                    self.with_region(ctx, |r| r.clusters.get(&cid).cloned())
                        .ok_or_else(|| super::cluster_not_found(&cid))?,
                )
            }
            None => None,
        };
        if engine.aurora && cluster.is_none() {
            return Err(invalid_parameter(format!(
                "The parameter DBClusterIdentifier must be provided when creating an {} DB instance.",
                engine.name
            )));
        }
        let resource = resource_id("db-");
        let now = ctx.received_at;
        let new = if let Some(cl) = &cluster {
            let cc = &cl.cluster;
            if cc.engine.as_deref() != Some(engine.name) {
                return Err(invalid_combination(format!(
                    "The engine name requested for your DB instance ({}) doesn't match the engine name of your DB cluster ({}).",
                    engine.name,
                    cc.engine.clone().unwrap_or_default()
                )));
            }
            if input.master_user_password.is_some() || input.master_username.is_some() || manage {
                return Err(invalid_combination(
                    "The requested DB Instance will be a member of a DB Cluster. Set master user password for the DB Cluster.",
                ));
            }
            if input.db_name.is_some() {
                return Err(invalid_combination(
                    "The requested DB Instance will be a member of a DB Cluster. Set database name for the DB Cluster.",
                ));
            }
            if input.storage_encrypted.is_some() || input.kms_key_id.is_some() {
                return Err(invalid_combination(
                    "The requested DB Instance will be a member of a DB Cluster. Set storage encryption for the DB Cluster.",
                ));
            }
            let version =
                engine.version(cc.engine_version.as_deref().unwrap_or_default()).unwrap_or(engine.default_version());
            check_class(engine, version, &class)?;
            if class == "db.serverless" && cc.serverless_v2_scaling_configuration.is_none() {
                return Err(invalid_combination(
                    "Set the Serverless v2 scaling configuration on the parent DB cluster before creating a Serverless v2 DB instance.",
                ));
            }
            let pg = self.param_group(
                ctx,
                input.db_parameter_group_name.as_deref().unwrap_or(&engine.default_parameter_group(version)),
                false,
            )?;
            if pg.family != version.family {
                return Err(param_family_mismatch(&pg.name, &pg.family, version.family));
            }
            let zones = cc.availability_zones.clone().unwrap_or_default();
            let used = cc.db_cluster_members.as_ref().map(|m| m.len()).unwrap_or(0);
            let az = input
                .availability_zone
                .clone()
                .unwrap_or_else(|| zones.get(used % zones.len().max(1)).cloned().unwrap_or_default());
            let subnet_group = self.subnet_group(ctx, cc.db_subnet_group.as_deref().unwrap_or("default"))?;
            let og = self.option_group(ctx, &engine.default_option_group(version))?;
            NewInstance {
                db: t::DBInstance {
                    db_instance_identifier: Some(id.clone()),
                    db_instance_class: Some(class.clone()),
                    engine: Some(engine.name.into()),
                    db_instance_status: Some("creating".into()),
                    master_username: cc.master_username.clone(),
                    db_name: cc.database_name.clone(),
                    allocated_storage: Some(1),
                    instance_create_time: Some(now),
                    preferred_backup_window: cc.preferred_backup_window.clone(),
                    backup_retention_period: cc.backup_retention_period,
                    db_security_groups: Some(Vec::new()),
                    vpc_security_groups: cc.vpc_security_groups.clone(),
                    db_parameter_groups: Some(vec![t::DBParameterGroupStatus {
                        db_parameter_group_name: Some(pg.name.clone()),
                        parameter_apply_status: Some("in-sync".into()),
                    }]),
                    availability_zone: Some(az),
                    db_subnet_group: Some(subnet_group),
                    preferred_maintenance_window: Some(match &input.preferred_maintenance_window {
                        Some(w) => check_maintenance_window(w)?,
                        None => maintenance_window(&resource),
                    }),
                    pending_modified_values: Some(t::PendingModifiedValues::default()),
                    multi_az: Some(false),
                    engine_version: cc.engine_version.clone(),
                    auto_minor_version_upgrade: Some(input.auto_minor_version_upgrade.unwrap_or(true)),
                    read_replica_db_instance_identifiers: Some(Vec::new()),
                    license_model: Some(engine.license.into()),
                    option_group_memberships: Some(vec![t::OptionGroupMembership {
                        option_group_name: og.option_group_name.clone(),
                        status: Some("in-sync".into()),
                    }]),
                    publicly_accessible: Some(input.publicly_accessible.unwrap_or(false)),
                    storage_type: Some(cc.storage_type.clone().unwrap_or_else(|| "aurora".into())),
                    db_instance_port: Some(0),
                    db_cluster_identifier: cc.db_cluster_identifier.clone(),
                    storage_encrypted: cc.storage_encrypted,
                    kms_key_id: cc.kms_key_id.clone(),
                    dbi_resource_id: Some(resource.clone()),
                    ca_certificate_identifier: Some(
                        input.ca_certificate_identifier.clone().unwrap_or_else(|| self.default_certificate(ctx)),
                    ),
                    copy_tags_to_snapshot: Some(input.copy_tags_to_snapshot.unwrap_or(false)),
                    monitoring_interval: Some(input.monitoring_interval.unwrap_or(0)),
                    monitoring_role_arn: input.monitoring_role_arn.clone(),
                    promotion_tier: Some(input.promotion_tier.unwrap_or(1)),
                    db_instance_arn: Some(arn.clone()),
                    iam_database_authentication_enabled: cc.iam_database_authentication_enabled,
                    performance_insights_enabled: Some(input.enable_performance_insights.unwrap_or(false)),
                    deletion_protection: Some(false),
                    associated_roles: Some(Vec::new()),
                    tag_list: Some(tags.clone()),
                    customer_owned_ip_enabled: Some(false),
                    network_type: Some("IPV4".into()),
                    backup_target: Some("region".into()),
                    certificate_details: certificate(Some(
                        &input.ca_certificate_identifier.clone().unwrap_or_else(|| self.default_certificate(ctx)),
                    )),
                    dedicated_log_volume: Some(false),
                    is_storage_config_upgrade_available: Some(false),
                    engine_lifecycle_support: Some("open-source-rds-extended-support".into()),
                    enabled_cloudwatch_logs_exports: input.enable_cloudwatch_logs_exports.clone(),
                    ..Default::default()
                },
                master_password: cl.master_password.clone(),
                port: cc.port.unwrap_or(engine.default_port),
                image: cl.image.clone(),
                from_snapshot: None,
                first_backup: false,
                recovery: None,
                drop_snapshot: false,
            }
        } else {
            let version = resolve_version(engine, &input.engine_version)?;
            check_class(engine, version, &class)?;
            let username = input.master_username.clone().ok_or_else(|| missing("MasterUsername"))?;
            check_username(engine, &username)?;
            let password = match (&input.master_user_password, manage) {
                (Some(_), true) => {
                    return Err(invalid_combination(
                        "You can't specify MasterUserPassword and ManageMasterUserPassword at the same time.",
                    ))
                }
                (Some(p), false) => {
                    check_password(engine, p)?;
                    p.clone()
                }
                (None, true) => super::generate_password(),
                (None, false) => return Err(missing("MasterUserPassword")),
            };
            if input.master_user_secret_kms_key_id.is_some() && !manage {
                return Err(invalid_combination(
                    "You can't specify MasterUserSecretKmsKeyId unless ManageMasterUserPassword is turned on.",
                ));
            }
            if let Some(n) = &input.db_name {
                check_db_name(engine, n)?;
            }
            let (storage_type, allocated, iops, throughput) =
                storage(engine, &input.storage_type, input.allocated_storage, input.iops, input.storage_throughput)?;
            if let Some(m) = input.max_allocated_storage {
                if m < allocated {
                    return Err(invalid_parameter(
                        "Max allocated storage must be greater than or equal to the allocated storage.",
                    ));
                }
            }
            let retention = input.backup_retention_period.unwrap_or(1);
            if !(0..=35).contains(&retention) {
                return Err(invalid_parameter(format!(
                    "Invalid backup retention period: {retention}. Must be between 0 and 35."
                )));
            }
            if let Some(w) = &input.preferred_backup_window {
                check_backup_window(w)?;
            }
            let port = input.port.unwrap_or(engine.default_port);
            if !(1150..=65535).contains(&port) {
                return Err(invalid_parameter(format!(
                    "Invalid port {port}. The port must be between 1150 and 65535."
                )));
            }
            let subnet_group = self.subnet_group(ctx, input.db_subnet_group_name.as_deref().unwrap_or("default"))?;
            let zones: Vec<String> = {
                let mut z: Vec<String> = subnet_group
                    .subnets
                    .iter()
                    .flatten()
                    .filter_map(|s| s.subnet_availability_zone.as_ref().and_then(|a| a.name.clone()))
                    .collect();
                z.sort();
                z.dedup();
                z
            };
            let multi_az = input.multi_az.unwrap_or(false);
            let az = match &input.availability_zone {
                Some(a) if multi_az => {
                    return Err(invalid_parameter(format!(
                        "Requesting a specific availability zone ({a}) is not valid for Multi-AZ instances."
                    )))
                }
                Some(a) if !zones.contains(a) => {
                    return Err(invalid_combination(format!(
                        "No subnets in the DB subnet group are in the availability zone {a}."
                    )))
                }
                Some(a) => a.clone(),
                None => zones.first().cloned().unwrap_or_default(),
            };
            let vpc = subnet_group.vpc_id.clone().unwrap_or_default();
            let sgs = self.security_groups(ctx, &input.vpc_security_group_ids, &vpc)?;
            let pg = self.param_group(
                ctx,
                input.db_parameter_group_name.as_deref().unwrap_or(&engine.default_parameter_group(version)),
                false,
            )?;
            if pg.family != version.family {
                return Err(param_family_mismatch(&pg.name, &pg.family, version.family));
            }
            let og = self.option_group(
                ctx,
                input.option_group_name.as_deref().unwrap_or(&engine.default_option_group(version)),
            )?;
            if og.engine_name.as_deref() != Some(engine.name)
                || og.major_engine_version.as_deref() != Some(version.major)
            {
                return Err(invalid_parameter(format!(
                    "The option group {} isn't compatible with engine {} version {}.",
                    og.option_group_name.clone().unwrap_or_default(),
                    engine.name,
                    version.version
                )));
            }
            if let Some(logs) = &input.enable_cloudwatch_logs_exports {
                check_log_types(engine, logs)?;
            }
            let encrypted = input.storage_encrypted.unwrap_or(false);
            if input.kms_key_id.is_some() && !encrypted {
                return Err(invalid_combination(
                    "You must set StorageEncrypted to true when you specify a KMS key for the DB instance.",
                ));
            }
            let kms_key =
                if encrypted { Some(self.storage_key(ctx, input.kms_key_id.as_deref(), &resource)?) } else { None };
            let secret = if manage {
                Some(self.create_master_secret(
                    ctx,
                    "db",
                    &arn,
                    &username,
                    &password,
                    input.master_user_secret_kms_key_id.clone(),
                )?)
            } else {
                None
            };
            let mut pending = t::PendingModifiedValues::default();
            if !manage {
                pending.master_user_password = Some("****".into());
            }
            NewInstance {
                db: t::DBInstance {
                    db_instance_identifier: Some(id.clone()),
                    db_instance_class: Some(class.clone()),
                    engine: Some(engine.name.into()),
                    db_instance_status: Some("creating".into()),
                    master_username: Some(username),
                    db_name: input.db_name.clone(),
                    allocated_storage: Some(allocated),
                    instance_create_time: Some(now),
                    preferred_backup_window: Some(
                        input.preferred_backup_window.clone().unwrap_or_else(|| backup_window(&resource)),
                    ),
                    backup_retention_period: Some(retention),
                    db_security_groups: Some(Vec::new()),
                    vpc_security_groups: Some(sgs),
                    db_parameter_groups: Some(vec![t::DBParameterGroupStatus {
                        db_parameter_group_name: Some(pg.name.clone()),
                        parameter_apply_status: Some("in-sync".into()),
                    }]),
                    availability_zone: Some(az.clone()),
                    db_subnet_group: Some(subnet_group),
                    preferred_maintenance_window: Some(match &input.preferred_maintenance_window {
                        Some(w) => check_maintenance_window(w)?,
                        None => maintenance_window(&resource),
                    }),
                    pending_modified_values: Some(pending),
                    multi_az: Some(multi_az),
                    secondary_availability_zone: multi_az.then(|| zones.iter().find(|z| **z != az).cloned()).flatten(),
                    engine_version: Some(version.version.into()),
                    auto_minor_version_upgrade: Some(input.auto_minor_version_upgrade.unwrap_or(true)),
                    read_replica_db_instance_identifiers: Some(Vec::new()),
                    license_model: Some(input.license_model.clone().unwrap_or_else(|| engine.license.into())),
                    iops,
                    storage_throughput: throughput,
                    option_group_memberships: Some(vec![t::OptionGroupMembership {
                        option_group_name: og.option_group_name.clone(),
                        status: Some("in-sync".into()),
                    }]),
                    character_set_name: input.character_set_name.clone(),
                    publicly_accessible: Some(input.publicly_accessible.unwrap_or(false)),
                    storage_type: Some(storage_type),
                    db_instance_port: Some(0),
                    storage_encrypted: Some(encrypted),
                    kms_key_id: kms_key,
                    dbi_resource_id: Some(resource.clone()),
                    ca_certificate_identifier: Some(
                        input.ca_certificate_identifier.clone().unwrap_or_else(|| self.default_certificate(ctx)),
                    ),
                    domain_memberships: Some(Vec::new()),
                    copy_tags_to_snapshot: Some(input.copy_tags_to_snapshot.unwrap_or(false)),
                    monitoring_interval: Some(input.monitoring_interval.unwrap_or(0)),
                    monitoring_role_arn: input.monitoring_role_arn.clone(),
                    db_instance_arn: Some(arn.clone()),
                    timezone: input.timezone.clone(),
                    iam_database_authentication_enabled: Some(
                        input.enable_iam_database_authentication.unwrap_or(false),
                    ),
                    database_insights_mode: Some(
                        input.database_insights_mode.clone().unwrap_or_else(|| "standard".into()),
                    ),
                    performance_insights_enabled: Some(input.enable_performance_insights.unwrap_or(false)),
                    performance_insights_retention_period: input
                        .enable_performance_insights
                        .filter(|b| *b)
                        .map(|_| input.performance_insights_retention_period.unwrap_or(7)),
                    enabled_cloudwatch_logs_exports: input.enable_cloudwatch_logs_exports.clone(),
                    deletion_protection: Some(input.deletion_protection.unwrap_or(false)),
                    associated_roles: Some(Vec::new()),
                    max_allocated_storage: input.max_allocated_storage,
                    tag_list: Some(tags),
                    customer_owned_ip_enabled: Some(false),
                    network_type: Some(input.network_type.clone().unwrap_or_else(|| "IPV4".into())),
                    activity_stream_status: Some("stopped".into()),
                    backup_target: Some("region".into()),
                    certificate_details: certificate(Some(
                        &input.ca_certificate_identifier.clone().unwrap_or_else(|| self.default_certificate(ctx)),
                    )),
                    master_user_secret: secret,
                    dedicated_log_volume: Some(false),
                    is_storage_config_upgrade_available: Some(false),
                    engine_lifecycle_support: Some(
                        input
                            .engine_lifecycle_support
                            .clone()
                            .unwrap_or_else(|| "open-source-rds-extended-support".into()),
                    ),
                    ..Default::default()
                },
                master_password: password,
                port,
                image: version.image.into(),
                from_snapshot: None,
                first_backup: retention > 0,
                recovery: None,
                drop_snapshot: false,
            }
        };
        let view = self.launch_instance(ctx, new).await?;
        Ok(t::CreateDBInstanceResult { db_instance: Some(view) })
    }

    /// Resolve and check a storage encryption key; returns its ARN.
    pub(crate) fn storage_key(
        &self,
        ctx: &RequestContext,
        key: Option<&str>,
        resource: &str,
    ) -> Result<String, ServiceError> {
        let key = match key {
            Some(k) => k.to_string(),
            None => self.kms().aws_managed_key(ctx, "rds"),
        };
        let mut context = BTreeMap::new();
        context.insert("aws:rds:db-id".to_string(), resource.to_string());
        match self.kms().generate_data_key_via(ctx, "rds", &key, &context, 32) {
            Ok(dk) => Ok(dk.key_arn),
            Err(e) => Err(errors::kms_key_not_accessible_fault(format!(
                "The specified KMS key [{key}] does not exist, is not enabled or you do not have permissions to access it. ({})",
                e.message
            ))),
        }
    }

    pub(crate) fn describe_db_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBInstancesMessage,
    ) -> Result<t::DBInstanceMessage, ServiceError> {
        let wanted = input.db_instance_identifier.as_deref().map(|i| name_of(i).to_ascii_lowercase());
        authorize(ctx, "DescribeDBInstances", &db_arn(ctx, wanted.as_deref().unwrap_or("*")), ConditionContext::new())?;
        let f =
            Filters::new(&input.filters, &["db-cluster-id", "db-instance-id", "dbi-resource-id", "domain", "engine"])?;
        let recs: Vec<InstanceRecord> = self.with_region(ctx, |r| r.instances.values().cloned().collect());
        if let Some(w) = &wanted {
            if !recs.iter().any(|r| r.db.db_instance_identifier.as_deref() == Some(w)) {
                return Err(instance_not_found(w));
            }
        }
        let all: Vec<t::DBInstance> = recs
            .iter()
            .filter(|r| wanted.as_ref().is_none_or(|w| r.db.db_instance_identifier.as_ref() == Some(w)))
            .filter(|r| f.matches(|n| instance_filter(&r.db, n)))
            .map(|r| self.instance_view(ctx, r))
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBInstanceMessage { marker, db_instances: Some(page) })
    }

    pub(crate) async fn modify_db_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBInstanceMessage,
    ) -> Result<t::ModifyDBInstanceResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let arn = db_arn(ctx, &id);
        let rec = self.instance(ctx, &id)?;
        let mut c = resource_tag_context("db", &rec.db.tag_list);
        c.extend(cond(&[
            ("rds:DatabaseClass", input.db_instance_class.clone()),
            ("rds:StorageSize", input.allocated_storage.map(|s| s.to_string())),
            ("rds:MultiAz", input.multi_az.map(|s| s.to_string())),
            ("rds:Piops", input.iops.map(|s| s.to_string())),
            ("rds:ManageMasterUserPassword", input.manage_master_user_password.map(|b| b.to_string())),
        ]));
        authorize(ctx, "ModifyDBInstance", &arn, c)?;
        let status = rec.db.db_instance_status.clone().unwrap_or_default();
        if !operational(&status) {
            return Err(invalid_instance_state(&id, &status));
        }
        let engine = engine_of(rec.db.engine.as_deref().unwrap_or_default())?;
        let in_cluster = rec.db.db_cluster_identifier.is_some();
        let immediate = input.apply_immediately.unwrap_or(false);
        let mut db = rec.db.clone();
        let mut pending = db.pending_modified_values.clone().unwrap_or_default();
        let mut new_password: Option<String> = None;
        let version =
            engine.version(db.engine_version.as_deref().unwrap_or_default()).unwrap_or(engine.default_version());

        if let Some(class) = &input.db_instance_class {
            check_class(engine, version, class)?;
            // Applied by `apply_instance_changes`: at once with
            // ApplyImmediately (the response still shows the old class),
            // in the maintenance window otherwise.
            if Some(class) != db.db_instance_class.as_ref() {
                pending.db_instance_class = Some(class.clone());
            } else {
                pending.db_instance_class = None;
            }
        }
        if !in_cluster
            && (input.allocated_storage.is_some()
                || input.storage_type.is_some()
                || input.iops.is_some()
                || input.storage_throughput.is_some())
        {
            let size = input.allocated_storage.or(db.allocated_storage);
            if size < db.allocated_storage {
                return Err(invalid_parameter(format!(
                    "Invalid storage size for engine name {} and storage type {}: {}",
                    engine.name,
                    db.storage_type.clone().unwrap_or_default(),
                    size.unwrap_or(0)
                )));
            }
            let st = input.storage_type.clone().or(db.storage_type.clone());
            let (st, size, iops, throughput) = storage(
                engine,
                &st,
                size,
                input.iops.or(if input.storage_type.is_some() { None } else { db.iops }),
                input.storage_throughput.or(if input.storage_type.is_some() { None } else { db.storage_throughput }),
            )
            .or_else(|e| match input.iops {
                None if st.as_deref() == Some("gp3") => storage(engine, &st, size, None, None),
                _ => Err(e),
            })?;
            let changed = Some(&st) != db.storage_type.as_ref()
                || Some(size) != db.allocated_storage
                || iops != db.iops
                || throughput != db.storage_throughput;
            if changed {
                let current = db.allocated_storage.unwrap_or(0);
                // Increases must be at least 10%.
                if size > current && (size as i64) * 10 < (current as i64) * 11 {
                    return Err(invalid_combination(format!(
                        "Invalid storage size for engine name {} and storage type {st}: {size}",
                        engine.name
                    )));
                }
                if rec.storage_optimized_until.is_some_and(|u| u > ctx.received_at) || status == "storage-optimization"
                {
                    return Err(super::maintenance::storage_being_optimized());
                }
                pending.storage_type = Some(st);
                pending.allocated_storage = Some(size);
                pending.iops = iops;
                pending.storage_throughput = throughput;
            }
        }
        if let Some(m) = input.max_allocated_storage {
            db.max_allocated_storage = Some(m).filter(|m| *m > 0);
        }
        if let Some(pw) = &input.master_user_password {
            if in_cluster {
                return Err(invalid_combination(
                    "The requested DB Instance is a member of a DB Cluster. Set master user password for the DB Cluster.",
                ));
            }
            if db.master_user_secret.is_some() && input.manage_master_user_password != Some(false) {
                return Err(invalid_combination(
                    "You can't specify MasterUserPassword for an instance with ManageMasterUserPassword turned on.",
                ));
            }
            check_password(engine, pw)?;
            new_password = Some(pw.clone());
        }
        match input.manage_master_user_password {
            Some(true) if db.master_user_secret.is_none() => {
                if in_cluster {
                    return Err(invalid_combination(
                        "The requested DB Instance is a member of a DB Cluster. Manage the master user password for the DB Cluster.",
                    ));
                }
                let pw = super::generate_password();
                db.master_user_secret = Some(self.create_master_secret(
                    ctx,
                    "db",
                    &arn,
                    db.master_username.as_deref().unwrap_or_default(),
                    &pw,
                    input.master_user_secret_kms_key_id.clone(),
                )?);
                new_password = Some(pw);
            }
            Some(false) if db.master_user_secret.is_some() => {
                if input.master_user_password.is_none() {
                    return Err(invalid_combination(
                        "You must specify MasterUserPassword when you turn off ManageMasterUserPassword.",
                    ));
                }
                self.delete_master_secret(&db.master_user_secret);
                db.master_user_secret = None;
            }
            _ => {}
        }
        if input.rotate_master_user_password == Some(true) {
            if !immediate {
                return Err(invalid_combination(
                    "You must specify ApplyImmediately when rotating the master user password.",
                ));
            }
            let arn = db.master_user_secret.as_ref().and_then(|s| s.secret_arn.clone()).ok_or_else(|| {
                invalid_combination(
                    "You can't rotate the master user password because it isn't managed in Secrets Manager.",
                )
            })?;
            self.rotate_master_secret(ctx, &arn)?;
            db.master_user_secret = self.instance(ctx, &id)?.db.master_user_secret;
        }
        if let Some(pg_name) = &input.db_parameter_group_name {
            let pg = self.param_group(ctx, pg_name, false)?;
            if pg.family != version.family {
                return Err(param_family_mismatch(&pg.name, &pg.family, version.family));
            }
            db.db_parameter_groups = Some(vec![t::DBParameterGroupStatus {
                db_parameter_group_name: Some(pg.name),
                parameter_apply_status: Some("pending-reboot".into()),
            }]);
        }
        if let Some(og_name) = &input.option_group_name {
            let og = self.option_group(ctx, og_name)?;
            db.option_group_memberships = Some(vec![t::OptionGroupMembership {
                option_group_name: og.option_group_name,
                status: Some(if immediate { "in-sync" } else { "pending-apply" }.into()),
            }]);
        }
        if let Some(sgs) = &input.vpc_security_group_ids {
            let vpc = db.db_subnet_group.as_ref().and_then(|g| g.vpc_id.clone()).unwrap_or_default();
            db.vpc_security_groups = Some(self.security_groups(ctx, &Some(sgs.clone()), &vpc)?);
        }
        if let Some(n) = input.backup_retention_period {
            if in_cluster {
                return Err(invalid_combination(
                    "The requested DB Instance is a member of a DB Cluster. Set backup retention period for the DB Cluster.",
                ));
            }
            if !(0..=35).contains(&n) {
                return Err(invalid_parameter(format!(
                    "Invalid backup retention period: {n}. Must be between 0 and 35."
                )));
            }
            db.backup_retention_period = Some(n);
        }
        if let Some(w) = &input.preferred_backup_window {
            check_backup_window(w)?;
            db.preferred_backup_window = Some(w.clone());
        }
        if let Some(w) = &input.preferred_maintenance_window {
            db.preferred_maintenance_window = Some(check_maintenance_window(w)?);
        }
        if let Some(m) = input.multi_az {
            if in_cluster {
                return Err(invalid_combination("Multi-AZ is set at the DB cluster level for Aurora instances."));
            }
            pending.multi_az = (Some(m) != db.multi_az).then_some(m);
        }
        if let Some(v) = &input.engine_version {
            if in_cluster {
                return Err(invalid_combination(
                    "The requested DB Instance is a member of a DB Cluster. Upgrade the engine version of the DB Cluster.",
                ));
            }
            let target = engine
                .version(v)
                .ok_or_else(|| invalid_combination(format!("Cannot find version {v} for {}", engine.name)))?;
            if target.version != version.version {
                let index = |x: &Version| engine.versions.iter().position(|y| y.version == x.version);
                if index(target) < index(version) {
                    return Err(invalid_combination(format!(
                        "Cannot upgrade {} from {} to {}",
                        engine.name, version.version, target.version
                    )));
                }
                if target.major != version.major && input.allow_major_version_upgrade != Some(true) {
                    return Err(invalid_combination(
                        "The AllowMajorVersionUpgrade flag must be present when upgrading to a new major version.",
                    ));
                }
                if target.major != version.major && input.db_parameter_group_name.is_none() {
                    let pg = self.param_group(ctx, &engine.default_parameter_group(target), false)?;
                    db.db_parameter_groups = Some(vec![t::DBParameterGroupStatus {
                        db_parameter_group_name: Some(pg.name),
                        parameter_apply_status: Some("in-sync".into()),
                    }]);
                }
                pending.engine_version = Some(target.version.into());
            }
        }
        if let Some(b) = input.auto_minor_version_upgrade {
            db.auto_minor_version_upgrade = Some(b);
        }
        if let Some(b) = input.copy_tags_to_snapshot {
            db.copy_tags_to_snapshot = Some(b);
        }
        if let Some(b) = input.deletion_protection {
            db.deletion_protection = Some(b);
        }
        if let Some(b) = input.publicly_accessible {
            db.publicly_accessible = Some(b);
        }
        if input.monitoring_interval.is_some() || input.monitoring_role_arn.is_some() {
            let interval = input.monitoring_interval.or(db.monitoring_interval);
            let role = input.monitoring_role_arn.clone().or(db.monitoring_role_arn.clone());
            self.check_monitoring(ctx, interval, role.as_deref().filter(|r| !r.is_empty()), &arn)?;
            db.monitoring_interval = interval;
            db.monitoring_role_arn = role.filter(|r| !r.is_empty());
        }
        if let Some(n) = input.promotion_tier {
            if !(0..=15).contains(&n) {
                return Err(invalid_parameter("PromotionTier must be between 0 and 15."));
            }
            db.promotion_tier = Some(n);
        }
        if let Some(b) = input.enable_iam_database_authentication {
            db.iam_database_authentication_enabled = Some(b);
        }
        if let Some(b) = input.enable_performance_insights {
            db.performance_insights_enabled = Some(b);
            db.performance_insights_retention_period =
                b.then(|| input.performance_insights_retention_period.unwrap_or(7));
        }
        if let Some(m) = &input.database_insights_mode {
            db.database_insights_mode = Some(m.clone());
        }
        if let Some(ca) = &input.ca_certificate_identifier {
            if !catalog::CERTIFICATES.iter().any(|c| c.0 == ca) {
                return Err(errors::certificate_not_found_fault(format!("Certificate {ca} not found.")));
            }
            db.ca_certificate_identifier = Some(ca.clone());
            db.certificate_details = certificate(Some(ca));
        }
        if let Some(cfg) = &input.cloudwatch_logs_export_configuration {
            let enable = cfg.enable_log_types.clone().unwrap_or_default();
            check_log_types(engine, &enable)?;
            let mut logs = db.enabled_cloudwatch_logs_exports.clone().unwrap_or_default();
            for l in enable {
                if !logs.contains(&l) {
                    logs.push(l);
                }
            }
            logs.retain(|l| !cfg.disable_log_types.iter().flatten().any(|d| d == l));
            db.enabled_cloudwatch_logs_exports = Some(logs).filter(|l| !l.is_empty());
        }
        if let Some(p) = input.db_port_number {
            if !(1150..=65535).contains(&p) {
                return Err(invalid_parameter(format!("Invalid port {p}. The port must be between 1150 and 65535.")));
            }
        }
        if let Some(n) = &input.network_type {
            db.network_type = Some(n.clone());
        }
        let new_id = match &input.new_db_instance_identifier {
            Some(n) => {
                let n = identifier("NewDBInstanceIdentifier", n, 63)?;
                if n != id && self.with_region(ctx, |r| r.instances.contains_key(&n)) {
                    return Err(errors::db_instance_already_exists_fault("DB instance already exists"));
                }
                if immediate {
                    Some(n)
                } else {
                    pending.db_instance_identifier = Some(n);
                    None
                }
            }
            None => None,
        };
        if new_password.is_some()
            && !(input.manage_master_user_password == Some(true) && rec.db.master_user_secret.is_none())
        {
            pending.master_user_password = Some("****".into());
        }
        let deferred = super::maintenance::instance_has_deferred(&pending);
        let apply_now = immediate && deferred;
        db.pending_modified_values = Some(pending);
        let port_change = input.db_port_number.filter(|p| *p != rec.port);
        let old_password = rec.master_password.clone();
        self.with_region(ctx, |r| {
            let rec = r.instances.get_mut(&id).expect("looked up above");
            rec.db = db.clone();
            if let Some(pw) = &new_password {
                rec.master_password = pw.clone();
            }
            if let Some(p) = port_change {
                rec.port = p;
            }
            rec.generation += 1;
            if deferred {
                rec.pending_since.get_or_insert(ctx.received_at);
            } else {
                rec.pending_since = None;
            }
            if apply_now {
                rec.db.db_instance_status = Some("modifying".into());
            }
        });
        let mut id = id;
        if let Some(n) = new_id {
            self.rename_instance(ctx, &id, &n);
            id = n;
        }
        let view = self.instance_view(ctx, &self.instance(ctx, &id)?);
        if new_password.is_some() {
            self.apply_password(ctx, Some(id.clone()), None, old_password);
            let ctx2 = ctx.clone();
            let id2 = id.clone();
            let this = self.clone();
            self.run_task(async move {
                this.with_region(&ctx2, |r| {
                    if let Some(p) = r.instances.get_mut(&id2).and_then(|i| i.db.pending_modified_values.as_mut()) {
                        p.master_user_password = None;
                    }
                });
            })
            .await;
        }
        if apply_now {
            self.apply_instance_changes(ctx, &id, super::maintenance::Scope::All).await;
        }
        Ok(t::ModifyDBInstanceResult { db_instance: Some(view) })
    }

    pub(crate) fn rename_instance(&self, ctx: &RequestContext, old: &str, new: &str) {
        let arn = db_arn(ctx, new);
        self.with_region(ctx, |r| {
            if let Some(mut rec) = r.instances.remove(old) {
                rec.db.db_instance_identifier = Some(new.to_string());
                rec.db.db_instance_arn = Some(arn);
                for other in r.instances.values_mut() {
                    for x in other.db.read_replica_db_instance_identifiers.iter_mut().flatten() {
                        if x == old {
                            *x = new.to_string();
                        }
                    }
                    if other.db.read_replica_source_db_instance_identifier.as_deref() == Some(old) {
                        other.db.read_replica_source_db_instance_identifier = Some(new.to_string());
                    }
                }
                if let Some(c) = rec.db.db_cluster_identifier.as_ref().and_then(|c| r.clusters.get_mut(c)) {
                    for m in c.cluster.db_cluster_members.iter_mut().flatten() {
                        if m.db_instance_identifier.as_deref() == Some(old) {
                            m.db_instance_identifier = Some(new.to_string());
                        }
                    }
                }
                r.instances.insert(new.to_string(), rec);
            }
        });
    }

    pub(crate) async fn delete_db_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBInstanceMessage,
    ) -> Result<t::DeleteDBInstanceResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "DeleteDBInstance", &db_arn(ctx, &id), resource_tag_context("db", &rec.db.tag_list))?;
        let status = rec.db.db_instance_status.clone().unwrap_or_default();
        if status == "deleting" {
            return Err(errors::invalid_db_instance_state_fault(format!("Instance {id} is already being deleted.")));
        }
        if rec.db.deletion_protection == Some(true) {
            return Err(invalid_combination(
                "Cannot delete protected DB Instance, please disable deletion protection and try again.",
            ));
        }
        let skip = input.skip_final_snapshot.unwrap_or(false);
        let in_cluster = rec.db.db_cluster_identifier.is_some();
        let is_replica = rec.db.read_replica_source_db_instance_identifier.is_some();
        let final_snapshot = match (&input.final_db_snapshot_identifier, skip) {
            (Some(_), true) => {
                return Err(invalid_combination(
                    "Cannot specify a FinalDBSnapshotIdentifier when SkipFinalSnapshot is true.",
                ))
            }
            (Some(s), false) if in_cluster || is_replica => {
                let _ = s;
                return Err(invalid_combination(
                    "FinalDBSnapshotIdentifier can not be specified when deleting a cluster instance or a read replica.",
                ));
            }
            (Some(s), false) => Some(identifier("FinalDBSnapshotIdentifier", s, 255)?),
            (None, false) if !in_cluster && !is_replica => {
                return Err(invalid_combination(
                    "FinalDBSnapshotIdentifier is required unless SkipFinalSnapshot is specified.",
                ))
            }
            (None, _) => None,
        };
        if let Some(s) = &final_snapshot {
            if self.with_region(ctx, |r| r.snapshots.contains_key(s)) {
                return Err(errors::db_snapshot_already_exists_fault(format!(
                    "Cannot create the snapshot because a snapshot with the identifier {s} already exists."
                )));
            }
            if !operational(&status) && status != "stopped" {
                return Err(invalid_instance_state(&id, &status));
            }
        }
        let generation = self.begin_instance(ctx, &id, "deleting");
        let view = self.instance_view(ctx, &self.instance(ctx, &id)?);
        let retain = !input.delete_automated_backups.unwrap_or(true);
        let this = self.clone();
        let ctx2 = ctx.clone();
        if let Some(s) = &final_snapshot {
            self.snapshot_instance(ctx, &id, s, "manual", Vec::new()).await?;
        }
        self.run_task(async move {
            let rec = this.with_region(&ctx2, |r| r.instances.get(&id).cloned());
            let Some(rec) = rec else { return };
            if rec.generation != generation {
                return;
            }
            let keep_log = retain
                && rec.db.backup_retention_period.unwrap_or(0) > 0
                && rec.db.db_cluster_identifier.is_none()
                && rec.listen.is_some()
                && this.backend().runs_databases();
            let retained_log = if keep_log { this.keep_log(&ctx2, &rec).await } else { None };
            if rec.db.db_cluster_identifier.is_none() {
                if let Err(e) = this.backend().delete(&rec.backend_name).await {
                    tracing::warn!(db = %id, "deleting the database failed: {e}");
                }
            }
            this.delete_master_secret(&rec.db.master_user_secret);
            let automated: Vec<String> = this.with_region(&ctx2, |r| {
                r.instances.remove(&id);
                Rds::forget_proxy_targets(r, Some(&id), None);
                for other in r.instances.values_mut() {
                    if let Some(list) = other.db.read_replica_db_instance_identifiers.as_mut() {
                        list.retain(|x| x != &id);
                    }
                    if other.db.read_replica_source_db_instance_identifier.as_deref() == Some(id.as_str()) {
                        other.db.read_replica_source_db_instance_identifier = None;
                    }
                }
                if let Some(c) = rec.db.db_cluster_identifier.as_ref().and_then(|c| r.clusters.get_mut(c)) {
                    let members = c.cluster.db_cluster_members.get_or_insert_with(Vec::new);
                    let was_writer = members.iter().any(|m| {
                        m.db_instance_identifier.as_deref() == Some(id.as_str()) && m.is_cluster_writer == Some(true)
                    });
                    members.retain(|m| m.db_instance_identifier.as_deref() != Some(id.as_str()));
                    if was_writer {
                        if let Some(m) = members.iter_mut().min_by_key(|m| m.promotion_tier.unwrap_or(1)) {
                            m.is_cluster_writer = Some(true);
                        }
                    }
                }
                if retain && rec.db.backup_retention_period.unwrap_or(0) > 0 {
                    let mut b = crate::ops::snapshot::automated_backup(&ctx2, &rec);
                    b.status = Some("retained".into());
                    if let Some(w) = b.restore_window.as_mut() {
                        w.latest_time = Some(this.now());
                    }
                    let resource = rec.db.dbi_resource_id.clone().unwrap_or_default();
                    if let Some(l) = retained_log.clone() {
                        r.retained_logs.insert(resource.clone(), l);
                    }
                    r.retained_backups.insert(resource, b);
                }
                let automated: Vec<String> = r
                    .snapshots
                    .iter()
                    .filter(|(_, s)| {
                        s.snapshot.snapshot_type.as_deref() == Some("automated")
                            && s.snapshot.db_instance_identifier.as_deref() == Some(id.as_str())
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                if retain {
                    return Vec::new();
                }
                automated
                    .iter()
                    .filter_map(|k| r.snapshots.remove(k))
                    .filter(|s| s.has_data)
                    .map(|s| s.backend_name)
                    .collect()
            });
            for s in automated {
                let _ = this.backend().delete_snapshot(&s).await;
            }
            this.emit(
                &ctx2,
                "db-instance",
                &id,
                &db_arn(&ctx2, &id),
                &["deletion"],
                "DB instance deleted",
                "RDS-EVENT-0003",
            );
        })
        .await;
        Ok(t::DeleteDBInstanceResult { db_instance: Some(view) })
    }

    pub(crate) async fn stop_db_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::StopDBInstanceMessage,
    ) -> Result<t::StopDBInstanceResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "StopDBInstance", &db_arn(ctx, &id), resource_tag_context("db", &rec.db.tag_list))?;
        if rec.db.db_cluster_identifier.is_some() {
            return Err(invalid_combination("The DB instance is part of a DB cluster. Stop the DB cluster instead."));
        }
        if rec.db.read_replica_source_db_instance_identifier.is_some()
            || rec.db.read_replica_db_instance_identifiers.as_ref().is_some_and(|r| !r.is_empty())
        {
            return Err(errors::invalid_db_instance_state_fault(
                "Cannot stop or start a Read-Replica instance, or an instance that has Read-Replicas.",
            ));
        }
        let status = rec.db.db_instance_status.clone().unwrap_or_default();
        if !operational(&status) {
            return Err(invalid_instance_state(&id, &status));
        }
        if let Some(s) = &input.db_snapshot_identifier {
            let s = identifier("DBSnapshotIdentifier", s, 255)?;
            self.snapshot_instance(ctx, &id, &s, "manual", Vec::new()).await?;
        }
        let generation = self.begin_instance(ctx, &id, "stopping");
        let restart_at = ctx.received_at + Duration::days(7);
        self.with_region(ctx, |r| {
            if let Some(i) = r.instances.get_mut(&id) {
                i.db.automatic_restart_time = Some(restart_at);
            }
        });
        let view = self.instance_view(ctx, &self.instance(ctx, &id)?);
        let this = self.clone();
        let ctx2 = ctx.clone();
        let name = rec.backend_name.clone();
        self.run_task(async move {
            if let Err(e) = this.backend().stop(&name).await {
                tracing::warn!(db = %id, "stopping the database failed: {e}");
            }
            if this.set_instance_status(&ctx2, &id, generation, "stopped", None) {
                this.emit(
                    &ctx2,
                    "db-instance",
                    &id,
                    &db_arn(&ctx2, &id),
                    &["notification"],
                    "DB instance stopped",
                    "RDS-EVENT-0087",
                );
            }
        })
        .await;
        Ok(t::StopDBInstanceResult { db_instance: Some(view) })
    }

    pub(crate) async fn start_db_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::StartDBInstanceMessage,
    ) -> Result<t::StartDBInstanceResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "StartDBInstance", &db_arn(ctx, &id), resource_tag_context("db", &rec.db.tag_list))?;
        if rec.db.db_cluster_identifier.is_some() {
            return Err(invalid_combination("The DB instance is part of a DB cluster. Start the DB cluster instead."));
        }
        let status = rec.db.db_instance_status.clone().unwrap_or_default();
        if status != "stopped" {
            return Err(errors::invalid_db_instance_state_fault(format!(
                "Instance {id} cannot be started as it is not in stopped state. Its state is {status}."
            )));
        }
        let generation = self.begin_instance(ctx, &id, "starting");
        self.with_region(ctx, |r| {
            if let Some(i) = r.instances.get_mut(&id) {
                i.db.automatic_restart_time = None;
            }
        });
        let view = self.instance_view(ctx, &self.instance(ctx, &id)?);
        self.restart_instance(ctx, &id, generation, ("DB instance started", "RDS-EVENT-0088")).await;
        Ok(t::StartDBInstanceResult { db_instance: Some(view) })
    }

    pub(crate) async fn reboot_db_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::RebootDBInstanceMessage,
    ) -> Result<t::RebootDBInstanceResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "RebootDBInstance", &db_arn(ctx, &id), resource_tag_context("db", &rec.db.tag_list))?;
        let status = rec.db.db_instance_status.clone().unwrap_or_default();
        if !operational(&status) {
            return Err(invalid_instance_state(&id, &status));
        }
        if input.force_failover == Some(true) && rec.db.multi_az != Some(true) {
            return Err(invalid_combination("Cannot force a failover when the instance is not Multi-AZ."));
        }
        let generation = self.begin_instance(ctx, &id, "rebooting");
        if input.force_failover == Some(true) {
            self.with_region(ctx, |r| {
                if let Some(i) = r.instances.get_mut(&id) {
                    let primary = i.db.availability_zone.clone();
                    i.db.availability_zone = i.db.secondary_availability_zone.clone();
                    i.db.secondary_availability_zone = primary;
                }
            });
        }
        let view = self.instance_view(ctx, &self.instance(ctx, &id)?);
        self.restart_instance(ctx, &id, generation, ("DB instance restarted", "RDS-EVENT-0006")).await;
        Ok(t::RebootDBInstanceResult { db_instance: Some(view) })
    }

    pub(crate) async fn create_db_instance_read_replica_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBInstanceReadReplicaMessage,
    ) -> Result<t::CreateDBInstanceReadReplicaResult, ServiceError> {
        let id = identifier("DBInstanceIdentifier", &input.db_instance_identifier, 63)?;
        let source_id =
            input.source_db_instance_identifier.clone().ok_or_else(|| missing("SourceDBInstanceIdentifier"))?;
        let source = self.instance(ctx, &source_id)?;
        let tags = tags_from(&input.tags)?;
        let arn = db_arn(ctx, &id);
        let mut c = request_tag_context(&tags);
        c.extend(cond(&[("rds:DatabaseClass", input.db_instance_class.clone())]));
        authorize(ctx, "CreateDBInstanceReadReplica", &arn, c)?;
        let src = &source.db;
        let source_name = src.db_instance_identifier.clone().unwrap_or_default();
        let engine = engine_of(src.engine.as_deref().unwrap_or_default())?;
        if engine.aurora || src.db_cluster_identifier.is_some() {
            return Err(invalid_combination(
                "Read replicas of Aurora DB instances are created by adding DB instances to the DB cluster.",
            ));
        }
        if !operational(src.db_instance_status.as_deref().unwrap_or_default()) {
            return Err(invalid_instance_state(&source_name, src.db_instance_status.as_deref().unwrap_or_default()));
        }
        if src.backup_retention_period.unwrap_or(0) == 0 {
            return Err(errors::invalid_db_instance_state_fault(
                "Automated backups are not enabled for this database instance. To enable automated backups, use ModifyDBInstance to set the backup retention period to a non-zero value.",
            ));
        }
        if self.with_region(ctx, |r| r.instances.contains_key(&id)) {
            return Err(errors::db_instance_already_exists_fault("DB instance already exists"));
        }
        let version =
            engine.version(src.engine_version.as_deref().unwrap_or_default()).unwrap_or(engine.default_version());
        let class = input.db_instance_class.clone().or(src.db_instance_class.clone()).unwrap_or_default();
        check_class(engine, version, &class)?;
        let resource = resource_id("db-");
        let encrypted = src.storage_encrypted.unwrap_or(false);
        let kms_key = if encrypted {
            Some(self.storage_key(ctx, input.kms_key_id.as_deref().or(src.kms_key_id.as_deref()), &resource)?)
        } else {
            None
        };
        // The replica starts as a copy of the source's data.
        let seed = format!("replica-seed-{}", resource.to_ascii_lowercase());
        if self.backend().runs_databases() {
            self.backend().snapshot(&source.backend_name, &seed).await.map_err(|e| {
                errors::invalid_db_instance_state_fault(format!("Could not copy the source instance: {e}"))
            })?;
        }
        let subnet_group = match &input.db_subnet_group_name {
            Some(n) => self.subnet_group(ctx, n)?,
            None => src.db_subnet_group.clone().unwrap_or_default(),
        };
        let vpc = subnet_group.vpc_id.clone().unwrap_or_default();
        let sgs = match &input.vpc_security_group_ids {
            Some(_) => Some(self.security_groups(ctx, &input.vpc_security_group_ids, &vpc)?),
            None => src.vpc_security_groups.clone(),
        };
        let pg = match &input.db_parameter_group_name {
            Some(n) => {
                let pg = self.param_group(ctx, n, false)?;
                if pg.family != version.family {
                    return Err(param_family_mismatch(&pg.name, &pg.family, version.family));
                }
                Some(vec![t::DBParameterGroupStatus {
                    db_parameter_group_name: Some(pg.name),
                    parameter_apply_status: Some("in-sync".into()),
                }])
            }
            None => src.db_parameter_groups.clone(),
        };
        let db = t::DBInstance {
            db_instance_identifier: Some(id.clone()),
            db_instance_class: Some(class),
            db_instance_status: Some("creating".into()),
            instance_create_time: Some(ctx.received_at),
            backup_retention_period: Some(0),
            vpc_security_groups: sgs,
            db_parameter_groups: pg,
            availability_zone: Some(
                input.availability_zone.clone().or(src.availability_zone.clone()).unwrap_or_default(),
            ),
            db_subnet_group: Some(subnet_group),
            pending_modified_values: Some(t::PendingModifiedValues::default()),
            multi_az: Some(input.multi_az.unwrap_or(false)),
            read_replica_source_db_instance_identifier: Some(source_name.clone()),
            read_replica_db_instance_identifiers: Some(Vec::new()),
            replica_mode: input.replica_mode.clone(),
            publicly_accessible: Some(input.publicly_accessible.unwrap_or(false)),
            status_infos: Some(vec![t::DBInstanceStatusInfo {
                status_type: Some("read replication".into()),
                normal: Some(true),
                status: Some("replicating".into()),
                message: None,
            }]),
            storage_type: input.storage_type.clone().or(src.storage_type.clone()),
            storage_encrypted: Some(encrypted),
            kms_key_id: kms_key,
            dbi_resource_id: Some(resource.clone()),
            db_instance_arn: Some(arn.clone()),
            deletion_protection: Some(input.deletion_protection.unwrap_or(false)),
            tag_list: Some(tags),
            master_user_secret: None,
            copy_tags_to_snapshot: Some(input.copy_tags_to_snapshot.unwrap_or(false)),
            ..src.clone()
        };
        let view = self
            .launch_instance(
                ctx,
                NewInstance {
                    db,
                    master_password: source.master_password.clone(),
                    port: input.port.unwrap_or(source.port),
                    image: source.image.clone(),
                    from_snapshot: self.backend().runs_databases().then(|| seed.clone()),
                    first_backup: false,
                    recovery: None,
                    drop_snapshot: true,
                },
            )
            .await?;
        self.with_region(ctx, |r| {
            if let Some(s) = r.instances.get_mut(&source_name) {
                s.db.read_replica_db_instance_identifiers.get_or_insert_with(Vec::new).push(id.clone());
            }
        });
        Ok(t::CreateDBInstanceReadReplicaResult { db_instance: Some(view) })
    }

    pub(crate) async fn promote_read_replica_op(
        &self,
        ctx: &RequestContext,
        input: t::PromoteReadReplicaMessage,
    ) -> Result<t::PromoteReadReplicaResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "PromoteReadReplica", &db_arn(ctx, &id), resource_tag_context("db", &rec.db.tag_list))?;
        let Some(source) = rec.db.read_replica_source_db_instance_identifier.clone() else {
            return Err(errors::invalid_db_instance_state_fault(format!("DB Instance {id} is not a read replica.")));
        };
        let status = rec.db.db_instance_status.clone().unwrap_or_default();
        if !operational(&status) {
            return Err(invalid_instance_state(&id, &status));
        }
        let retention = input.backup_retention_period.unwrap_or(1);
        let generation = self.with_region(ctx, |r| {
            if let Some(s) = r.instances.get_mut(&source) {
                if let Some(l) = s.db.read_replica_db_instance_identifiers.as_mut() {
                    l.retain(|x| x != &id);
                }
            }
            let rec = r.instances.get_mut(&id).expect("looked up above");
            rec.db.read_replica_source_db_instance_identifier = None;
            rec.db.status_infos = None;
            rec.db.backup_retention_period = Some(retention);
            if let Some(w) = &input.preferred_backup_window {
                rec.db.preferred_backup_window = Some(w.clone());
            }
            rec.db.db_instance_status = Some("modifying".into());
            rec.generation += 1;
            rec.generation
        });
        let view = self.instance_view(ctx, &self.instance(ctx, &id)?);
        self.restart_instance(ctx, &id, generation, ("Read replica promoted", "RDS-EVENT-0062")).await;
        Ok(t::PromoteReadReplicaResult { db_instance: Some(view) })
    }

    pub(crate) fn add_role_to_db_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::AddRoleToDBInstanceMessage,
    ) -> Result<(), ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "AddRoleToDBInstance", &db_arn(ctx, &id), resource_tag_context("db", &rec.db.tag_list))?;
        ctx.authorize("iam:PassRole", &input.role_arn, ConditionContext::new())?;
        if !input.role_arn.starts_with("arn:") || !input.role_arn.contains(":role/") {
            return Err(invalid_parameter(format!("Invalid role ARN: {}", input.role_arn)));
        }
        self.with_region(ctx, |r| {
            let rec = r.instances.get_mut(&id).expect("looked up above");
            let roles = rec.db.associated_roles.get_or_insert_with(Vec::new);
            if roles.iter().any(|x| x.role_arn.as_ref() == Some(&input.role_arn)) {
                return Err(errors::db_instance_role_already_exists_fault(format!(
                    "Role ARN {} is already associated with DB Instance {id}",
                    input.role_arn
                )));
            }
            if roles.iter().any(|x| x.feature_name.as_ref() == Some(&input.feature_name)) {
                return Err(errors::db_instance_role_already_exists_fault(format!(
                    "Feature {} already has a role associated with DB Instance {id}",
                    input.feature_name
                )));
            }
            roles.push(t::DBInstanceRole {
                role_arn: Some(input.role_arn.clone()),
                feature_name: Some(input.feature_name.clone()),
                status: Some("ACTIVE".into()),
            });
            Ok(())
        })
    }

    pub(crate) fn remove_role_from_db_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::RemoveRoleFromDBInstanceMessage,
    ) -> Result<(), ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "RemoveRoleFromDBInstance", &db_arn(ctx, &id), resource_tag_context("db", &rec.db.tag_list))?;
        self.with_region(ctx, |r| {
            let rec = r.instances.get_mut(&id).expect("looked up above");
            let roles = rec.db.associated_roles.get_or_insert_with(Vec::new);
            let before = roles.len();
            roles.retain(|x| {
                !(x.role_arn.as_ref() == Some(&input.role_arn) && x.feature_name.as_ref() == Some(&input.feature_name))
            });
            if roles.len() == before {
                return Err(errors::db_instance_role_not_found_fault(format!(
                    "Role ARN {} cannot be found for DB Instance {id}",
                    input.role_arn
                )));
            }
            Ok(())
        })
    }

    pub(crate) fn describe_valid_db_instance_modifications_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeValidDBInstanceModificationsMessage,
    ) -> Result<t::DescribeValidDBInstanceModificationsResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "DescribeValidDBInstanceModifications", &db_arn(ctx, &id), ConditionContext::new())?;
        let engine = engine_of(rec.db.engine.as_deref().unwrap_or_default())?;
        let current = rec.db.allocated_storage.unwrap_or(20);
        let range = |from: i32, to: i32| t::Range { from: Some(from), to: Some(to), step: Some(1) };
        let storage: Vec<t::ValidStorageOptions> = if engine.aurora {
            Vec::new()
        } else {
            ["gp2", "gp3", "io1", "io2", "standard"]
                .iter()
                .map(|st| {
                    let (min, max) = catalog::storage_range(engine, st);
                    t::ValidStorageOptions {
                        storage_type: Some(st.to_string()),
                        storage_size: Some(vec![range(min.max(current), max)]),
                        provisioned_iops: matches!(*st, "io1" | "io2" | "gp3").then(|| vec![range(1000, 256000)]),
                        supports_storage_autoscaling: Some(true),
                        ..Default::default()
                    }
                })
                .collect()
        };
        Ok(t::DescribeValidDBInstanceModificationsResult {
            valid_db_instance_modifications_message: Some(t::ValidDBInstanceModificationsMessage {
                storage: Some(storage),
                valid_processor_features: Some(Vec::new()),
                supports_dedicated_log_volume: Some(false),
                ..Default::default()
            }),
        })
    }
}

pub(crate) fn param_family_mismatch(name: &str, family: &str, wanted: &str) -> ServiceError {
    invalid_combination(format!(
        "The parameter group {name} with DBParameterGroupFamily {family} can't be used for this instance. Use a parameter group with DBParameterGroupFamily {wanted}."
    ))
}

pub(crate) fn check_log_types(engine: &Engine, logs: &[String]) -> Result<(), ServiceError> {
    for l in logs {
        if !engine.log_types.contains(&l.as_str()) {
            return Err(invalid_parameter(format!(
                "You cannot use the log type {l} with engine {}. Valid log types are: {}",
                engine.name,
                engine.log_types.join(", ")
            )));
        }
    }
    Ok(())
}

pub(crate) fn certificate(id: Option<&str>) -> Option<t::CertificateDetails> {
    let id = id.unwrap_or(catalog::DEFAULT_CERTIFICATE);
    Some(t::CertificateDetails { ca_identifier: Some(id.to_string()), valid_till: catalog::certificate_valid_till(id) })
}

#[allow(dead_code)]
pub(crate) fn account(ctx: &RequestContext) -> String {
    account_of(ctx)
}
