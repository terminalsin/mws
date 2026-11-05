//! DB clusters: Aurora clusters (the cluster owns the database; its
//! instances are compute that share it) and Multi-AZ DB clusters (three
//! instances created with the cluster).

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::instance::{certificate, check_class, check_log_types, engine_of, resolve_version, NewInstance};
use super::{
    authorize, check_db_name, check_password, check_username, cluster_arn, cluster_host, cluster_not_found, cond,
    db_arn, invalid_cluster_state,
};
use crate::catalog;
use crate::generated::{errors, types as t};
use crate::state::{ClusterRecord, Listen};
use crate::util::{
    backup_window, check_backup_window, check_maintenance_window, hosted_zone_id, identifier, invalid_combination,
    invalid_parameter, maintenance_window, missing, name_of, opt, paginate, request_tag_context, resource_id,
    resource_tag_context, tags_from, zones, Filters,
};
use crate::Rds;

fn check_scaling(
    s: &Option<t::ServerlessV2ScalingConfiguration>,
) -> Result<Option<t::ServerlessV2ScalingConfigurationInfo>, ServiceError> {
    let Some(s) = s else { return Ok(None) };
    let min = s.min_capacity.unwrap_or(0.5);
    let max = s.max_capacity.unwrap_or(min.max(1.0));
    let half = |v: f64| (v * 2.0).fract() == 0.0;
    if !(0.0..=256.0).contains(&min) || !(1.0..=256.0).contains(&max) || !half(min) || !half(max) {
        return Err(invalid_parameter(
            "Serverless v2 capacity must be between 0 and 256 ACUs, in increments of 0.5 ACU.",
        ));
    }
    if max < min {
        return Err(invalid_parameter(
            "The maximum capacity for Serverless v2 must be greater than or equal to the minimum capacity.",
        ));
    }
    Ok(Some(t::ServerlessV2ScalingConfigurationInfo {
        min_capacity: Some(min),
        max_capacity: Some(max),
        seconds_until_auto_pause: (min == 0.0).then(|| s.seconds_until_auto_pause.unwrap_or(300)),
    }))
}

pub(crate) fn cluster_filter(c: &t::DBCluster, name: &str) -> Vec<String> {
    match name {
        "db-cluster-id" => {
            let mut v = opt(&c.db_cluster_identifier);
            v.extend(opt(&c.db_cluster_arn));
            v
        }
        "clone-group-id" => opt(&c.clone_group_id),
        "domain" => c.domain_memberships.iter().flatten().filter_map(|d| d.domain.clone()).collect(),
        "engine" => opt(&c.engine),
        _ => Vec::new(),
    }
}

/// How a new cluster's data starts.
#[derive(Default)]
pub(crate) struct Launch {
    /// A copy of this backend snapshot.
    pub from_snapshot: Option<String>,
    /// Built by rolling a backup forward first.
    pub recovery: Option<super::pitr::Recovery>,
    /// `from_snapshot` is a temporary copy, dropped once restored.
    pub drop_snapshot: bool,
}

impl Rds {
    pub(crate) fn cluster(&self, ctx: &RequestContext, id: &str) -> Result<ClusterRecord, ServiceError> {
        let id = name_of(id).to_ascii_lowercase();
        self.with_region(ctx, |r| r.clusters.get(&id).cloned()).ok_or_else(|| cluster_not_found(&id))
    }

    /// The cluster as `Describe*` shows it.
    pub(crate) fn cluster_view(&self, ctx: &RequestContext, rec: &ClusterRecord) -> t::DBCluster {
        let mut c = rec.cluster.clone();
        let id = c.db_cluster_identifier.clone().unwrap_or_default();
        let port = c.port.unwrap_or_default();
        let writer = self.endpoint_for(ctx, &cluster_host(ctx, &id, "cluster"), port, &rec.listen);
        let reader = self.endpoint_for(ctx, &cluster_host(ctx, &id, "cluster-ro"), port, &rec.listen);
        c.endpoint = writer.address;
        c.reader_endpoint = reader.address;
        c.port = writer.port;
        c.hosted_zone_id = Some(hosted_zone_id(&ctx.region).into());
        if c.status.as_deref() == Some("available") {
            c.latest_restorable_time = Some(ctx.received_at);
        }
        if let Some(w) = c.backtrack_window.filter(|w| *w > 0) {
            let created = c.cluster_create_time.unwrap_or(ctx.received_at);
            c.earliest_backtrack_time = Some(created.max(ctx.received_at - chrono::Duration::seconds(w)));
            c.backtrack_consumed_change_records = Some(c.backtrack_consumed_change_records.unwrap_or(0));
        }
        c.earliest_restorable_time = self.earliest_restorable(
            ctx,
            c.db_cluster_resource_id.as_deref().unwrap_or_default(),
            true,
            c.earliest_restorable_time,
        );
        c.custom_endpoints = Some(self.with_region(ctx, |r| {
            r.cluster_endpoints
                .values()
                .filter(|e| e.item.db_cluster_identifier.as_deref() == Some(id.as_str()))
                .filter_map(|e| e.item.endpoint.clone())
                .collect()
        }));
        c
    }

    /// Move a cluster (and its instances) to `status` if nothing newer
    /// happened since `generation`.
    pub(crate) fn set_cluster_status(
        &self,
        ctx: &RequestContext,
        id: &str,
        generation: u64,
        status: &str,
        listen: Option<Listen>,
    ) -> bool {
        let now = self.now();
        self.with_region(ctx, |r| {
            let Some(rec) = r.clusters.get_mut(id) else { return false };
            if rec.generation != generation {
                return false;
            }
            rec.cluster.status = Some(status.to_string());
            if listen.is_some() {
                rec.listen = listen;
            }
            if status == "available" {
                rec.cluster.latest_restorable_time = Some(now);
                rec.cluster.earliest_restorable_time.get_or_insert(now);
                if let Some(p) = rec.cluster.pending_modified_values.as_mut() {
                    p.master_user_password = None;
                }
            }
            let members: Vec<String> = rec
                .cluster
                .db_cluster_members
                .iter()
                .flatten()
                .filter_map(|m| m.db_instance_identifier.clone())
                .collect();
            for m in members {
                if let Some(i) = r.instances.get_mut(&m) {
                    if i.db.db_instance_status.as_deref() != Some("deleting") {
                        i.db.db_instance_status = Some(status.to_string());
                    }
                }
            }
            true
        })
    }

    pub(crate) fn begin_cluster(&self, ctx: &RequestContext, id: &str, status: &str) -> u64 {
        self.with_region(ctx, |r| {
            let rec = r.clusters.get_mut(id).expect("checked by the caller");
            rec.generation += 1;
            rec.cluster.status = Some(status.to_string());
            for m in rec.cluster.db_cluster_members.iter().flatten() {
                if let Some(i) = r.instances.get_mut(m.db_instance_identifier.as_deref().unwrap_or_default()) {
                    i.db.db_instance_status = Some(status.to_string());
                }
            }
            rec.generation
        })
    }

    /// Store a new cluster and create its database.
    pub(crate) async fn launch_cluster(
        &self,
        ctx: &RequestContext,
        rec: ClusterRecord,
        launch: Launch,
    ) -> Result<t::DBCluster, ServiceError> {
        let Launch { from_snapshot, recovery, drop_snapshot } = launch;
        let id = rec.cluster.db_cluster_identifier.clone().unwrap_or_default();
        let max = self.quota(ctx, crate::quotas::DB_CLUSTERS);
        self.with_region(ctx, |r| {
            if r.clusters.len() as i64 >= max {
                return Err(errors::db_cluster_quota_exceeded_fault(format!(
                    "Cannot create more than {max} DB clusters."
                )));
            }
            if r.clusters.contains_key(&id) {
                return Err(errors::db_cluster_already_exists_fault("DB Cluster already exists"));
            }
            r.clusters.insert(id.clone(), rec.clone());
            Ok(())
        })?;
        let view = self.cluster_view(ctx, &rec);
        let arn = cluster_arn(ctx, &id);
        self.emit(ctx, "db-cluster", &id, &arn, &["creation"], "DB cluster created", "RDS-EVENT-0170");
        let this = self.clone();
        let ctx2 = ctx.clone();
        self.run_task(async move {
            let spec = this.with_region(&ctx2, |r| r.clusters.get(&id).map(|c| this.cluster_spec(r, c, &ctx2)));
            let Some(spec) = spec else { return };
            if let (Some(rc), Some(target)) = (&recovery, &from_snapshot) {
                if let Err(e) = this.recover_into(rc, target).await {
                    tracing::warn!(cluster = %id, "point-in-time recovery failed: {e}");
                    let gen = this.with_region(&ctx2, |r| r.clusters.get(&id).map(|c| c.generation)).unwrap_or(0);
                    this.set_cluster_status(&ctx2, &id, gen, "inaccessible-encryption-credentials-recoverable", None);
                    this.emit(
                        &ctx2,
                        "db-cluster",
                        &id,
                        &cluster_arn(&ctx2, &id),
                        &["failure"],
                        &format!("Point-in-time recovery failed: {e}"),
                        "RDS-EVENT-0081",
                    );
                    return;
                }
            }
            let created = this.backend().create(&spec, from_snapshot.as_deref()).await;
            if drop_snapshot {
                if let Some(f) = &from_snapshot {
                    let _ = this.backend().delete_snapshot(f).await;
                }
            }
            match created {
                Ok(l) => {
                    let gen = this.with_region(&ctx2, |r| r.clusters.get(&id).map(|c| c.generation)).unwrap_or(0);
                    let first = this.set_cluster_status(
                        &ctx2,
                        &id,
                        gen,
                        "available",
                        Some(Listen { host: l.host, port: l.port }),
                    );
                    if first {
                        this.automated_cluster_snapshot(&ctx2, &id).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(cluster = %id, "creating the database failed: {e}");
                    let gen = this.with_region(&ctx2, |r| r.clusters.get(&id).map(|c| c.generation)).unwrap_or(0);
                    this.set_cluster_status(&ctx2, &id, gen, "inaccessible-encryption-credentials-recoverable", None);
                }
            }
        })
        .await;
        Ok(view)
    }

    /// (Re)start a cluster's database.
    pub(crate) async fn restart_cluster(
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
            let spec = this.with_region(&ctx, |r| r.clusters.get(&id).map(|c| this.cluster_spec(r, c, &ctx)));
            let Some(spec) = spec else { return };
            match this.backend().start(&spec).await {
                Ok(l) => {
                    if this.set_cluster_status(
                        &ctx,
                        &id,
                        generation,
                        "available",
                        Some(Listen { host: l.host, port: l.port }),
                    ) {
                        this.with_region(&ctx, |r| {
                            if let Some(c) = r.clusters.get_mut(&id) {
                                c.pending_reboot = false;
                                for m in c.cluster.db_cluster_members.iter_mut().flatten() {
                                    m.db_cluster_parameter_group_status = Some("in-sync".into());
                                }
                            }
                        });
                        this.emit(
                            &ctx,
                            "db-cluster",
                            &id,
                            &cluster_arn(&ctx, &id),
                            &["notification"],
                            event.0,
                            event.1,
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(cluster = %id, "starting the database failed: {e}");
                    this.set_cluster_status(&ctx, &id, generation, "incompatible-parameters", None);
                }
            }
        })
        .await;
    }

    pub(crate) async fn create_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBClusterMessage,
    ) -> Result<t::CreateDBClusterResult, ServiceError> {
        let id = identifier("DBClusterIdentifier", &input.db_cluster_identifier, 63)?;
        let engine = engine_of(&input.engine)?;
        let tags = tags_from(&input.tags)?;
        let arn = cluster_arn(ctx, &id);
        let mut c = request_tag_context(&tags);
        c.extend(cond(&[
            ("rds:DatabaseEngine", Some(engine.name.to_string())),
            ("rds:DatabaseName", input.database_name.clone()),
            ("rds:StorageEncrypted", Some(input.storage_encrypted.unwrap_or(false).to_string())),
            ("rds:ManageMasterUserPassword", input.manage_master_user_password.map(|b| b.to_string())),
        ]));
        authorize(ctx, "CreateDBCluster", &arn, c.clone())?;
        if !tags.is_empty() {
            authorize(ctx, "AddTagsToResource", &arn, c)?;
        }
        if self.with_region(ctx, |r| r.clusters.contains_key(&id)) {
            return Err(errors::db_cluster_already_exists_fault("DB Cluster already exists"));
        }
        let multi_az = !engine.aurora;
        if multi_az && input.db_cluster_instance_class.is_none() {
            return Err(invalid_parameter(format!(
                "The engine {} isn't supported for DB clusters without DBClusterInstanceClass. Use an Aurora engine, or specify DBClusterInstanceClass to create a Multi-AZ DB cluster.",
                engine.name
            )));
        }
        let mode = input.engine_mode.clone().unwrap_or_else(|| "provisioned".into());
        if mode != "provisioned" {
            return Err(invalid_parameter(format!("The engine mode {mode} you requested is currently unavailable.")));
        }
        let version = resolve_version(engine, &input.engine_version)?;
        if let Some(class) = &input.db_cluster_instance_class {
            check_class(engine, version, class)?;
        }
        let backtrack_window = super::backtrack::window(engine.name, input.backtrack_window)?;
        let scalability = match input.cluster_scalability_type.as_deref() {
            None | Some("standard") => None,
            Some("limitless") if engine.name == "aurora-postgresql" => Some("limitless".to_string()),
            Some("limitless") => {
                return Err(invalid_combination(format!(
                    "Aurora Limitless Database isn't supported for engine {}.",
                    engine.name
                )))
            }
            Some(other) => return Err(invalid_parameter(format!("Invalid ClusterScalabilityType: {other}"))),
        };
        let global = match &input.global_cluster_identifier {
            Some(g) => Some(self.global(ctx, g)?),
            None => None,
        };
        let secondary =
            global.as_ref().is_some_and(|g| g.global_cluster_members.as_ref().is_some_and(|m| !m.is_empty()));
        let manage = input.manage_master_user_password.unwrap_or(false);
        let (username, password) = if secondary {
            if input.master_username.is_some() || input.master_user_password.is_some() {
                return Err(invalid_combination(
                    "Cannot specify MasterUsername or MasterUserPassword for a secondary cluster in a global database.",
                ));
            }
            let primary = self.global_primary(ctx, global.as_ref().unwrap());
            (
                primary.as_ref().and_then(|p| p.cluster.master_username.clone()).unwrap_or_default(),
                primary.map(|p| p.master_password).unwrap_or_default(),
            )
        } else {
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
            (username, password)
        };
        if let Some(n) = &input.database_name {
            check_db_name(engine, n)?;
        }
        let retention = input.backup_retention_period.unwrap_or(1);
        if !(1..=35).contains(&retention) {
            return Err(invalid_parameter(format!(
                "Invalid backup retention period: {retention}. Must be between 1 and 35."
            )));
        }
        if let Some(w) = &input.preferred_backup_window {
            check_backup_window(w)?;
        }
        let port = input.port.unwrap_or(engine.default_port);
        if !(1150..=65535).contains(&port) {
            return Err(invalid_parameter(format!("Invalid port {port}. The port must be between 1150 and 65535.")));
        }
        let subnet_group = self.subnet_group(ctx, input.db_subnet_group_name.as_deref().unwrap_or("default"))?;
        let mut group_zones: Vec<String> = subnet_group
            .subnets
            .iter()
            .flatten()
            .filter_map(|s| s.subnet_availability_zone.as_ref().and_then(|a| a.name.clone()))
            .collect();
        group_zones.sort();
        group_zones.dedup();
        let azs = match &input.availability_zones {
            Some(a) if !a.is_empty() => {
                for z in a {
                    if !zones(&ctx.region).contains(z) {
                        return Err(invalid_parameter(format!("Invalid availability zone: {z}")));
                    }
                }
                a.clone()
            }
            _ => group_zones.iter().take(3).cloned().collect(),
        };
        let vpc = subnet_group.vpc_id.clone().unwrap_or_default();
        let sgs = self.security_groups(ctx, &input.vpc_security_group_ids, &vpc)?;
        let pg = self.param_group(
            ctx,
            input.db_cluster_parameter_group_name.as_deref().unwrap_or(&engine.default_parameter_group(version)),
            true,
        )?;
        if pg.family != version.family {
            return Err(invalid_combination(format!(
                "The parameter group {} with DBParameterGroupFamily {} can't be used for this DB cluster. Use a parameter group with DBParameterGroupFamily {}.",
                pg.name, pg.family, version.family
            )));
        }
        if let Some(logs) = &input.enable_cloudwatch_logs_exports {
            check_log_types(engine, logs)?;
        }
        let scaling = check_scaling(&input.serverless_v2_scaling_configuration)?;
        let resource = resource_id("cluster-");
        let encrypted =
            input.storage_encrypted.unwrap_or(global.as_ref().and_then(|g| g.storage_encrypted).unwrap_or(false));
        if input.kms_key_id.is_some() && !encrypted {
            return Err(invalid_combination(
                "You must set StorageEncrypted to true when you specify a KMS key for the DB cluster.",
            ));
        }
        let kms_key =
            if encrypted { Some(self.storage_key(ctx, input.kms_key_id.as_deref(), &resource)?) } else { None };
        if input.master_user_secret_kms_key_id.is_some() && !manage {
            return Err(invalid_combination(
                "You can't specify MasterUserSecretKmsKeyId unless ManageMasterUserPassword is turned on.",
            ));
        }
        let secret = if manage {
            Some(self.create_master_secret(
                ctx,
                "cluster",
                &arn,
                &username,
                &password,
                input.master_user_secret_kms_key_id.clone(),
            )?)
        } else {
            None
        };
        let storage_type = match (&input.storage_type, multi_az) {
            (Some(s), false) if s == "aurora" || s == "aurora-iopt1" => s.clone(),
            (None, false) => "aurora".into(),
            (Some(s), true) if ["io1", "io2", "gp3"].contains(&s.as_str()) => s.clone(),
            (None, true) => return Err(missing("StorageType")),
            (Some(s), _) => return Err(invalid_parameter(format!("Invalid storage type: {s}"))),
        };
        if multi_az && input.allocated_storage.is_none() {
            return Err(missing("AllocatedStorage"));
        }
        let now = ctx.received_at;
        let mut pending = t::ClusterPendingModifiedValues::default();
        if !manage && !secondary {
            pending.master_user_password = Some("****".into());
        }
        let cluster = t::DBCluster {
            allocated_storage: Some(input.allocated_storage.unwrap_or(1)),
            availability_zones: Some(azs),
            backup_retention_period: Some(retention),
            character_set_name: input.character_set_name.clone(),
            database_name: input.database_name.clone(),
            db_cluster_identifier: Some(id.clone()),
            db_cluster_parameter_group: Some(pg.name.clone()),
            db_subnet_group: subnet_group.db_subnet_group_name.clone(),
            status: Some("creating".into()),
            multi_az: Some(multi_az),
            engine: Some(engine.name.into()),
            engine_version: Some(version.version.into()),
            port: Some(port),
            master_username: Some(username),
            db_cluster_option_group_memberships: Some(Vec::new()),
            preferred_backup_window: Some(
                input.preferred_backup_window.clone().unwrap_or_else(|| backup_window(&resource)),
            ),
            preferred_maintenance_window: Some(match &input.preferred_maintenance_window {
                Some(w) => check_maintenance_window(w)?,
                None => maintenance_window(&resource),
            }),
            read_replica_identifiers: Some(Vec::new()),
            db_cluster_members: Some(Vec::new()),
            vpc_security_groups: Some(sgs),
            storage_encrypted: Some(encrypted),
            kms_key_id: kms_key,
            db_cluster_resource_id: Some(resource.clone()),
            db_cluster_arn: Some(arn.clone()),
            associated_roles: Some(Vec::new()),
            iam_database_authentication_enabled: Some(input.enable_iam_database_authentication.unwrap_or(false)),
            cluster_create_time: Some(now),
            enabled_cloudwatch_logs_exports: input.enable_cloudwatch_logs_exports.clone(),
            engine_mode: Some(mode),
            pending_modified_values: Some(pending),
            db_cluster_instance_class: input.db_cluster_instance_class.clone(),
            storage_type: Some(storage_type),
            iops: input.iops,
            publicly_accessible: multi_az.then(|| input.publicly_accessible.unwrap_or(false)),
            auto_minor_version_upgrade: Some(input.auto_minor_version_upgrade.unwrap_or(true)),
            deletion_protection: Some(input.deletion_protection.unwrap_or(false)),
            http_endpoint_enabled: Some(input.enable_http_endpoint.unwrap_or(false)),
            activity_stream_status: Some("stopped".into()),
            backtrack_window,
            limitless_database: scalability
                .as_ref()
                .map(|_| t::LimitlessDatabase { status: Some("not-in-use".into()), min_required_acu: Some(16.0) }),
            cluster_scalability_type: scalability,
            copy_tags_to_snapshot: Some(input.copy_tags_to_snapshot.unwrap_or(false)),
            cross_account_clone: Some(false),
            domain_memberships: Some(Vec::new()),
            tag_list: Some(tags),
            global_cluster_identifier: global.as_ref().and_then(|g| g.global_cluster_identifier.clone()),
            global_write_forwarding_requested: input.enable_global_write_forwarding,
            network_type: Some(input.network_type.clone().unwrap_or_else(|| "IPV4".into())),
            serverless_v2_scaling_configuration: scaling,
            monitoring_interval: Some(input.monitoring_interval.unwrap_or(0)),
            monitoring_role_arn: input.monitoring_role_arn.clone(),
            database_insights_mode: Some(input.database_insights_mode.clone().unwrap_or_else(|| "standard".into())),
            performance_insights_enabled: Some(input.enable_performance_insights.unwrap_or(false)),
            master_user_secret: secret,
            local_write_forwarding_status: input
                .enable_local_write_forwarding
                .map(|b| if b { "enabled" } else { "disabled" }.into()),
            certificate_details: multi_az.then(|| certificate(input.ca_certificate_identifier.as_deref())).flatten(),
            engine_lifecycle_support: Some(
                input.engine_lifecycle_support.clone().unwrap_or_else(|| "open-source-rds-extended-support".into()),
            ),
            ..Default::default()
        };
        let rec = ClusterRecord {
            cluster,
            master_password: password,
            backend_name: resource.to_ascii_lowercase(),
            listen: None,
            generation: 1,
            image: version.image.into(),
            pending_reboot: false,
        };
        let mut view = self.launch_cluster(ctx, rec, Launch::default()).await?;
        if let Some(g) = &global {
            self.join_global(ctx, g.global_cluster_identifier.as_deref().unwrap_or_default(), &arn, !secondary);
        }
        if multi_az {
            // A Multi-AZ DB cluster comes with a writer and two readers.
            let class = input.db_cluster_instance_class.clone().unwrap_or_default();
            for n in 1..=3 {
                let member = format!("{id}-instance-{n}");
                self.cluster_instance(ctx, &id, &member, &class, n == 1).await?;
            }
            view = self.cluster_view(ctx, &self.cluster(ctx, &id)?);
        }
        Ok(t::CreateDBClusterResult { db_cluster: Some(view) })
    }

    /// Add an instance to a cluster (Multi-AZ DB cluster members).
    async fn cluster_instance(
        &self,
        ctx: &RequestContext,
        cluster: &str,
        id: &str,
        class: &str,
        _writer: bool,
    ) -> Result<(), ServiceError> {
        let rec = self.cluster(ctx, cluster)?;
        let cc = &rec.cluster;
        let engine = engine_of(cc.engine.as_deref().unwrap_or_default())?;
        let version =
            engine.version(cc.engine_version.as_deref().unwrap_or_default()).unwrap_or(engine.default_version());
        let resource = resource_id("db-");
        let zones = cc.availability_zones.clone().unwrap_or_default();
        let used = cc.db_cluster_members.as_ref().map(|m| m.len()).unwrap_or(0);
        let pg = self.param_group(ctx, &engine.default_parameter_group(version), false)?;
        let db = t::DBInstance {
            db_instance_identifier: Some(id.to_string()),
            db_instance_class: Some(class.to_string()),
            engine: cc.engine.clone(),
            db_instance_status: Some("creating".into()),
            master_username: cc.master_username.clone(),
            db_name: cc.database_name.clone(),
            allocated_storage: cc.allocated_storage,
            instance_create_time: Some(ctx.received_at),
            preferred_backup_window: cc.preferred_backup_window.clone(),
            backup_retention_period: cc.backup_retention_period,
            vpc_security_groups: cc.vpc_security_groups.clone(),
            db_parameter_groups: Some(vec![t::DBParameterGroupStatus {
                db_parameter_group_name: Some(pg.name),
                parameter_apply_status: Some("in-sync".into()),
            }]),
            availability_zone: zones.get(used % zones.len().max(1)).cloned(),
            db_subnet_group: Some(self.subnet_group(ctx, cc.db_subnet_group.as_deref().unwrap_or("default"))?),
            preferred_maintenance_window: cc.preferred_maintenance_window.clone(),
            pending_modified_values: Some(t::PendingModifiedValues::default()),
            multi_az: Some(false),
            engine_version: cc.engine_version.clone(),
            auto_minor_version_upgrade: cc.auto_minor_version_upgrade,
            read_replica_db_instance_identifiers: Some(Vec::new()),
            license_model: Some(engine.license.into()),
            iops: cc.iops,
            publicly_accessible: cc.publicly_accessible,
            storage_type: cc.storage_type.clone(),
            db_instance_port: Some(0),
            db_cluster_identifier: Some(cluster.to_string()),
            storage_encrypted: cc.storage_encrypted,
            kms_key_id: cc.kms_key_id.clone(),
            dbi_resource_id: Some(resource),
            ca_certificate_identifier: Some(self.default_certificate(ctx)),
            certificate_details: certificate(Some(&self.default_certificate(ctx))),
            db_instance_arn: Some(db_arn(ctx, id)),
            promotion_tier: Some(1),
            deletion_protection: Some(false),
            associated_roles: Some(Vec::new()),
            tag_list: Some(Vec::new()),
            network_type: cc.network_type.clone(),
            ..Default::default()
        };
        self.launch_instance(
            ctx,
            NewInstance {
                db,
                master_password: rec.master_password.clone(),
                port: cc.port.unwrap_or(engine.default_port),
                image: rec.image.clone(),
                from_snapshot: None,
                first_backup: false,
                recovery: None,
                drop_snapshot: false,
            },
        )
        .await?;
        Ok(())
    }

    pub(crate) fn describe_db_clusters_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBClustersMessage,
    ) -> Result<t::DBClusterMessage, ServiceError> {
        let wanted = input.db_cluster_identifier.as_deref().map(|i| name_of(i).to_ascii_lowercase());
        authorize(
            ctx,
            "DescribeDBClusters",
            &cluster_arn(ctx, wanted.as_deref().unwrap_or("*")),
            ConditionContext::new(),
        )?;
        let f = Filters::new(
            &input.filters,
            &["clone-group-id", "db-cluster-id", "db-cluster-resource-id", "domain", "engine"],
        )?;
        let recs: Vec<ClusterRecord> = self.with_region(ctx, |r| r.clusters.values().cloned().collect());
        if let Some(w) = &wanted {
            if !recs.iter().any(|r| r.cluster.db_cluster_identifier.as_deref() == Some(w)) {
                return Err(cluster_not_found(w));
            }
        }
        let all: Vec<t::DBCluster> = recs
            .iter()
            .filter(|r| wanted.as_ref().is_none_or(|w| r.cluster.db_cluster_identifier.as_ref() == Some(w)))
            .filter(|r| {
                f.matches(|n| match n {
                    "db-cluster-resource-id" => opt(&r.cluster.db_cluster_resource_id),
                    n => cluster_filter(&r.cluster, n),
                })
            })
            .map(|r| self.cluster_view(ctx, r))
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBClusterMessage { marker, db_clusters: Some(page) })
    }

    pub(crate) async fn modify_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBClusterMessage,
    ) -> Result<t::ModifyDBClusterResult, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let arn = cluster_arn(ctx, &id);
        let rec = self.cluster(ctx, &id)?;
        let mut cc = resource_tag_context("cluster", &rec.cluster.tag_list);
        cc.extend(cond(&[("rds:ManageMasterUserPassword", input.manage_master_user_password.map(|b| b.to_string()))]));
        authorize(ctx, "ModifyDBCluster", &arn, cc)?;
        let status = rec.cluster.status.clone().unwrap_or_default();
        if status != "available" {
            return Err(invalid_cluster_state(&id, &status));
        }
        let engine = engine_of(rec.cluster.engine.as_deref().unwrap_or_default())?;
        let version = engine
            .version(rec.cluster.engine_version.as_deref().unwrap_or_default())
            .unwrap_or(engine.default_version());
        let immediate = input.apply_immediately.unwrap_or(false);
        let mut c = rec.cluster.clone();
        let mut pending = c.pending_modified_values.clone().unwrap_or_default();
        let mut new_password: Option<String> = None;
        let mut restart = false;
        if let Some(pw) = &input.master_user_password {
            if c.master_user_secret.is_some() && input.manage_master_user_password != Some(false) {
                return Err(invalid_combination(
                    "You can't specify MasterUserPassword for a cluster with ManageMasterUserPassword turned on.",
                ));
            }
            check_password(engine, pw)?;
            new_password = Some(pw.clone());
            pending.master_user_password = Some("****".into());
        }
        match input.manage_master_user_password {
            Some(true) if c.master_user_secret.is_none() => {
                let pw = super::generate_password();
                c.master_user_secret = Some(self.create_master_secret(
                    ctx,
                    "cluster",
                    &arn,
                    c.master_username.as_deref().unwrap_or_default(),
                    &pw,
                    input.master_user_secret_kms_key_id.clone(),
                )?);
                new_password = Some(pw);
            }
            Some(false) if c.master_user_secret.is_some() => {
                if input.master_user_password.is_none() {
                    return Err(invalid_combination(
                        "You must specify MasterUserPassword when you turn off ManageMasterUserPassword.",
                    ));
                }
                self.delete_master_secret(&c.master_user_secret);
                c.master_user_secret = None;
            }
            _ => {}
        }
        if input.rotate_master_user_password == Some(true) {
            if !immediate {
                return Err(invalid_combination(
                    "You must specify ApplyImmediately when rotating the master user password.",
                ));
            }
            let secret = c.master_user_secret.as_ref().and_then(|s| s.secret_arn.clone()).ok_or_else(|| {
                invalid_combination(
                    "You can't rotate the master user password because it isn't managed in Secrets Manager.",
                )
            })?;
            self.rotate_master_secret(ctx, &secret)?;
        }
        if let Some(n) = input.backup_retention_period {
            if !(1..=35).contains(&n) {
                return Err(invalid_parameter(format!(
                    "Invalid backup retention period: {n}. Must be between 1 and 35."
                )));
            }
            c.backup_retention_period = Some(n);
        }
        if let Some(w) = &input.preferred_backup_window {
            check_backup_window(w)?;
            c.preferred_backup_window = Some(w.clone());
        }
        if let Some(w) = &input.preferred_maintenance_window {
            c.preferred_maintenance_window = Some(check_maintenance_window(w)?);
        }
        if let Some(n) = &input.db_cluster_parameter_group_name {
            let pg = self.param_group(ctx, n, true)?;
            if pg.family != version.family {
                return Err(invalid_combination(format!(
                    "The parameter group {} with DBParameterGroupFamily {} can't be used for this DB cluster. Use a parameter group with DBParameterGroupFamily {}.",
                    pg.name, pg.family, version.family
                )));
            }
            c.db_cluster_parameter_group = Some(pg.name);
            for m in c.db_cluster_members.iter_mut().flatten() {
                m.db_cluster_parameter_group_status = Some("pending-reboot".into());
            }
        }
        if let Some(sgs) = &input.vpc_security_group_ids {
            let vpc =
                self.subnet_group(ctx, c.db_subnet_group.as_deref().unwrap_or("default"))?.vpc_id.unwrap_or_default();
            c.vpc_security_groups = Some(self.security_groups(ctx, &Some(sgs.clone()), &vpc)?);
        }
        if let Some(p) = input.port {
            if !(1150..=65535).contains(&p) {
                return Err(invalid_parameter(format!("Invalid port {p}. The port must be between 1150 and 65535.")));
            }
            c.port = Some(p);
        }
        if let Some(b) = input.enable_iam_database_authentication {
            c.iam_database_authentication_enabled = Some(b);
        }
        if let Some(b) = input.deletion_protection {
            c.deletion_protection = Some(b);
        }
        if let Some(b) = input.copy_tags_to_snapshot {
            c.copy_tags_to_snapshot = Some(b);
        }
        if let Some(b) = input.auto_minor_version_upgrade {
            c.auto_minor_version_upgrade = Some(b);
        }
        if let Some(b) = input.enable_http_endpoint {
            c.http_endpoint_enabled = Some(b);
        }
        if let Some(b) = input.enable_performance_insights {
            c.performance_insights_enabled = Some(b);
        }
        if let Some(m) = &input.database_insights_mode {
            c.database_insights_mode = Some(m.clone());
        }
        if let Some(n) = input.monitoring_interval {
            c.monitoring_interval = Some(n);
        }
        if let Some(r) = &input.monitoring_role_arn {
            c.monitoring_role_arn = Some(r.clone());
        }
        if let Some(n) = &input.network_type {
            c.network_type = Some(n.clone());
        }
        if let Some(b) = input.enable_local_write_forwarding {
            c.local_write_forwarding_status = Some(if b { "enabled" } else { "disabled" }.into());
        }
        if let Some(b) = input.enable_global_write_forwarding {
            c.global_write_forwarding_requested = Some(b);
        }
        if input.serverless_v2_scaling_configuration.is_some() {
            c.serverless_v2_scaling_configuration = check_scaling(&input.serverless_v2_scaling_configuration)?;
        }
        if let Some(st) = &input.storage_type {
            if engine.aurora && st != "aurora" && st != "aurora-iopt1" {
                return Err(invalid_parameter(format!("Invalid storage type: {st}")));
            }
            c.storage_type = Some(st.clone());
        }
        if let Some(a) = input.allocated_storage {
            c.allocated_storage = Some(a);
        }
        if let Some(i) = input.iops {
            c.iops = Some(i);
        }
        if let Some(class) = &input.db_cluster_instance_class {
            check_class(engine, version, class)?;
            c.db_cluster_instance_class = Some(class.clone());
        }
        if let Some(cfg) = &input.cloudwatch_logs_export_configuration {
            let enable = cfg.enable_log_types.clone().unwrap_or_default();
            check_log_types(engine, &enable)?;
            let mut logs = c.enabled_cloudwatch_logs_exports.clone().unwrap_or_default();
            for l in enable {
                if !logs.contains(&l) {
                    logs.push(l);
                }
            }
            logs.retain(|l| !cfg.disable_log_types.iter().flatten().any(|d| d == l));
            c.enabled_cloudwatch_logs_exports = Some(logs).filter(|l| !l.is_empty());
        }
        if let Some(ca) = &input.ca_certificate_identifier {
            if !catalog::CERTIFICATES.iter().any(|x| x.0 == ca) {
                return Err(errors::certificate_not_found_fault(format!("Certificate {ca} not found.")));
            }
            c.certificate_details = certificate(Some(ca));
        }
        if input.backtrack_window.is_some() {
            if c.backtrack_window.unwrap_or(0) == 0 && input.backtrack_window != Some(0) {
                return Err(invalid_combination(
                    "Backtrack can only be turned on when the DB cluster is created or restored.",
                ));
            }
            c.backtrack_window = super::backtrack::window(engine.name, input.backtrack_window)?;
        }
        if let Some(v) = &input.engine_version {
            let target = engine
                .version(v)
                .ok_or_else(|| invalid_combination(format!("Cannot find version {v} for {}", engine.name)))?;
            if target.version != version.version {
                let index = |x: &catalog::Version| engine.versions.iter().position(|y| y.version == x.version);
                if index(target) < index(version) {
                    return Err(invalid_parameter(format!(
                        "Cannot upgrade {} from {} to {}",
                        engine.name, version.version, target.version
                    )));
                }
                if target.major != version.major {
                    if input.allow_major_version_upgrade != Some(true) {
                        return Err(invalid_parameter(
                            "The AllowMajorVersionUpgrade flag must be present when upgrading to a new major version.",
                        ));
                    }
                    if input.db_cluster_parameter_group_name.is_none() {
                        c.db_cluster_parameter_group =
                            Some(self.param_group(ctx, &engine.default_parameter_group(target), true)?.name);
                    }
                }
                if immediate {
                    c.engine_version = Some(target.version.into());
                    restart = true;
                } else {
                    pending.engine_version = Some(target.version.into());
                }
            }
        }
        let new_id = match &input.new_db_cluster_identifier {
            Some(n) => {
                let n = identifier("NewDBClusterIdentifier", n, 63)?;
                if n != id && self.with_region(ctx, |r| r.clusters.contains_key(&n)) {
                    return Err(errors::db_cluster_already_exists_fault("DB Cluster already exists"));
                }
                (n != id).then_some(n)
            }
            None => None,
        };
        c.pending_modified_values = Some(pending);
        let old_password = rec.master_password.clone();
        let version_change = c.engine_version != rec.cluster.engine_version;
        let generation = self.with_region(ctx, |r| {
            let rec = r.clusters.get_mut(&id).expect("looked up above");
            rec.cluster = c.clone();
            if let Some(pw) = &new_password {
                rec.master_password = pw.clone();
            }
            rec.generation += 1;
            if version_change {
                rec.cluster.status = Some("upgrading".into());
            }
            for m in rec.cluster.db_cluster_members.iter().flatten() {
                if let Some(i) = r.instances.get_mut(m.db_instance_identifier.as_deref().unwrap_or_default()) {
                    i.master_password = rec.master_password.clone();
                    i.db.engine_version = rec.cluster.engine_version.clone();
                    i.db.iam_database_authentication_enabled = rec.cluster.iam_database_authentication_enabled;
                    i.db.backup_retention_period = rec.cluster.backup_retention_period;
                    i.db.vpc_security_groups = rec.cluster.vpc_security_groups.clone();
                }
            }
            rec.generation
        });
        let mut id = id;
        if let Some(n) = new_id {
            self.rename_cluster(ctx, &id, &n);
            id = n;
        }
        if new_password.is_some() {
            self.apply_password(ctx, None, Some(id.clone()), old_password);
            self.with_region(ctx, |r| {
                if let Some(p) = r.clusters.get_mut(&id).and_then(|c| c.cluster.pending_modified_values.as_mut()) {
                    p.master_user_password = None;
                }
            });
        }
        let view = self.cluster_view(ctx, &self.cluster(ctx, &id)?);
        if restart {
            if version_change && self.backend().runs_databases() {
                // A new engine version needs a new image; the data stays.
                let image =
                    engine.version(c.engine_version.as_deref().unwrap_or_default()).map(|v| v.image.to_string());
                if let Some(image) = image {
                    let major_change =
                        engine.version(rec.cluster.engine_version.as_deref().unwrap_or_default()).map(|v| v.major)
                            != engine.version(c.engine_version.as_deref().unwrap_or_default()).map(|v| v.major);
                    if !major_change {
                        self.with_region(ctx, |r| {
                            if let Some(rec) = r.clusters.get_mut(&id) {
                                rec.image = image;
                            }
                        });
                    }
                }
            }
            self.restart_cluster(ctx, &id, generation, ("Database cluster engine version upgraded", "RDS-EVENT-0172"))
                .await;
        } else {
            self.emit(
                ctx,
                "db-cluster",
                &id,
                &cluster_arn(ctx, &id),
                &["configuration change"],
                "DB cluster modified",
                "RDS-EVENT-0016",
            );
        }
        Ok(t::ModifyDBClusterResult { db_cluster: Some(view) })
    }

    pub(crate) fn rename_cluster(&self, ctx: &RequestContext, old: &str, new: &str) {
        let arn = cluster_arn(ctx, new);
        self.with_region(ctx, |r| {
            if let Some(mut rec) = r.clusters.remove(old) {
                rec.cluster.db_cluster_identifier = Some(new.to_string());
                rec.cluster.db_cluster_arn = Some(arn);
                for m in rec.cluster.db_cluster_members.iter().flatten() {
                    if let Some(i) = r.instances.get_mut(m.db_instance_identifier.as_deref().unwrap_or_default()) {
                        i.db.db_cluster_identifier = Some(new.to_string());
                    }
                }
                for e in r.cluster_endpoints.values_mut() {
                    if e.item.db_cluster_identifier.as_deref() == Some(old) {
                        e.item.db_cluster_identifier = Some(new.to_string());
                    }
                }
                r.clusters.insert(new.to_string(), rec);
            }
        });
    }

    pub(crate) async fn delete_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBClusterMessage,
    ) -> Result<t::DeleteDBClusterResult, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "DeleteDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        let status = rec.cluster.status.clone().unwrap_or_default();
        if rec.cluster.deletion_protection == Some(true) {
            return Err(invalid_parameter(
                "Cannot delete protected Cluster, please disable deletion protection and try again.",
            ));
        }
        if rec.cluster.global_cluster_identifier.is_some() {
            return Err(errors::invalid_db_cluster_state_fault(
                "This cluster is a part of a global cluster, please remove it from globalcluster first",
            ));
        }
        let members: Vec<String> =
            rec.cluster.db_cluster_members.iter().flatten().filter_map(|m| m.db_instance_identifier.clone()).collect();
        let multi_az =
            rec.cluster.multi_az == Some(true) && !engine_of(rec.cluster.engine.as_deref().unwrap_or_default())?.aurora;
        if !members.is_empty() && !multi_az {
            return Err(errors::invalid_db_cluster_state_fault(
                "Cluster cannot be deleted, it still contains DB instances in non-deleting state.",
            ));
        }
        if status == "deleting" {
            return Err(invalid_cluster_state(&id, &status));
        }
        if self.with_region(ctx, |r| {
            r.shard_groups.values().any(|g| g.db_cluster_identifier.as_deref() == Some(id.as_str()))
        }) {
            return Err(errors::invalid_db_cluster_state_fault(format!(
                "The DB cluster {id} has a DB shard group. Delete the DB shard group first."
            )));
        }
        let skip = input.skip_final_snapshot.unwrap_or(false);
        let final_snapshot = match (&input.final_db_snapshot_identifier, skip) {
            (Some(_), true) => {
                return Err(invalid_parameter(
                    "FinalDBSnapshotIdentifier can not be specified when SkipFinalSnapshot is enabled.",
                ))
            }
            (Some(s), false) => Some(identifier("FinalDBSnapshotIdentifier", s, 255)?),
            (None, false) => {
                return Err(invalid_parameter(
                    "FinalDBSnapshotIdentifier is required unless SkipFinalSnapshot is specified.",
                ))
            }
            (None, true) => None,
        };
        if let Some(s) = &final_snapshot {
            self.snapshot_cluster(ctx, &id, s, "manual", Vec::new()).await?;
        }
        let generation = self.begin_cluster(ctx, &id, "deleting");
        let view = self.cluster_view(ctx, &self.cluster(ctx, &id)?);
        let retain = !input.delete_automated_backups.unwrap_or(true);
        let this = self.clone();
        let ctx2 = ctx.clone();
        self.run_task(async move {
            let rec = this.with_region(&ctx2, |r| r.clusters.get(&id).cloned());
            let Some(rec) = rec else { return };
            if rec.generation != generation {
                return;
            }
            if let Err(e) = this.backend().delete(&rec.backend_name).await {
                tracing::warn!(cluster = %id, "deleting the database failed: {e}");
            }
            this.delete_master_secret(&rec.cluster.master_user_secret);
            let snaps: Vec<String> = this.with_region(&ctx2, |r| {
                r.clusters.remove(&id);
                Rds::forget_proxy_targets(r, None, Some(&id));
                for m in &members {
                    r.instances.remove(m);
                }
                r.cluster_endpoints.retain(|_, e| e.item.db_cluster_identifier.as_deref() != Some(id.as_str()));
                let automated: Vec<String> = r
                    .cluster_snapshots
                    .iter()
                    .filter(|(_, s)| {
                        s.snapshot.snapshot_type.as_deref() == Some("automated")
                            && s.snapshot.db_cluster_identifier.as_deref() == Some(id.as_str())
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                if retain {
                    let mut b = crate::ops::snapshot::cluster_automated_backup(&ctx2, &rec);
                    b.status = Some("retained".into());
                    r.retained_cluster_backups
                        .insert(rec.cluster.db_cluster_resource_id.clone().unwrap_or_default(), b);
                    return Vec::new();
                }
                automated
                    .iter()
                    .filter_map(|k| r.cluster_snapshots.remove(k))
                    .filter(|s| s.has_data)
                    .map(|s| s.backend_name)
                    .collect()
            });
            for s in snaps {
                let _ = this.backend().delete_snapshot(&s).await;
            }
            this.emit(
                &ctx2,
                "db-cluster",
                &id,
                &cluster_arn(&ctx2, &id),
                &["deletion"],
                "DB cluster deleted",
                "RDS-EVENT-0171",
            );
        })
        .await;
        Ok(t::DeleteDBClusterResult { db_cluster: Some(view) })
    }

    pub(crate) async fn stop_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::StopDBClusterMessage,
    ) -> Result<t::StopDBClusterResult, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "StopDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        let status = rec.cluster.status.clone().unwrap_or_default();
        if status != "available" {
            return Err(invalid_cluster_state(&id, &status));
        }
        if rec.cluster.global_cluster_identifier.is_some() {
            return Err(errors::invalid_db_cluster_state_fault(
                "Stopping a cluster that is part of a global database isn't supported.",
            ));
        }
        let generation = self.begin_cluster(ctx, &id, "stopping");
        let restart = ctx.received_at + chrono::Duration::days(7);
        self.with_region(ctx, |r| {
            if let Some(c) = r.clusters.get_mut(&id) {
                c.cluster.automatic_restart_time = Some(restart);
            }
        });
        let view = self.cluster_view(ctx, &self.cluster(ctx, &id)?);
        let this = self.clone();
        let ctx2 = ctx.clone();
        let name = rec.backend_name.clone();
        self.run_task(async move {
            if let Err(e) = this.backend().stop(&name).await {
                tracing::warn!(cluster = %id, "stopping the database failed: {e}");
            }
            if this.set_cluster_status(&ctx2, &id, generation, "stopped", None) {
                this.emit(
                    &ctx2,
                    "db-cluster",
                    &id,
                    &cluster_arn(&ctx2, &id),
                    &["notification"],
                    "DB cluster stopped",
                    "RDS-EVENT-0150",
                );
            }
        })
        .await;
        Ok(t::StopDBClusterResult { db_cluster: Some(view) })
    }

    pub(crate) async fn start_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::StartDBClusterMessage,
    ) -> Result<t::StartDBClusterResult, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "StartDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        let status = rec.cluster.status.clone().unwrap_or_default();
        if status != "stopped" {
            return Err(errors::invalid_db_cluster_state_fault(format!("DbCluster {id} is not in stopped state.")));
        }
        let generation = self.begin_cluster(ctx, &id, "starting");
        self.with_region(ctx, |r| {
            if let Some(c) = r.clusters.get_mut(&id) {
                c.cluster.automatic_restart_time = None;
            }
        });
        let view = self.cluster_view(ctx, &self.cluster(ctx, &id)?);
        self.restart_cluster(ctx, &id, generation, ("DB cluster started", "RDS-EVENT-0151")).await;
        Ok(t::StartDBClusterResult { db_cluster: Some(view) })
    }

    pub(crate) async fn reboot_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::RebootDBClusterMessage,
    ) -> Result<t::RebootDBClusterResult, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "RebootDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        let status = rec.cluster.status.clone().unwrap_or_default();
        if status != "available" {
            return Err(invalid_cluster_state(&id, &status));
        }
        let generation = self.begin_cluster(ctx, &id, "rebooting");
        let view = self.cluster_view(ctx, &self.cluster(ctx, &id)?);
        self.restart_cluster(ctx, &id, generation, ("DB cluster rebooted", "RDS-EVENT-0006")).await;
        Ok(t::RebootDBClusterResult { db_cluster: Some(view) })
    }

    pub(crate) fn failover_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::FailoverDBClusterMessage,
    ) -> Result<t::FailoverDBClusterResult, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "FailoverDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        let status = rec.cluster.status.clone().unwrap_or_default();
        if status != "available" {
            return Err(invalid_cluster_state(&id, &status));
        }
        let members = rec.cluster.db_cluster_members.clone().unwrap_or_default();
        let target = match &input.target_db_instance_identifier {
            Some(t) => {
                let t = name_of(t).to_ascii_lowercase();
                if !members.iter().any(|m| m.db_instance_identifier.as_deref() == Some(t.as_str())) {
                    return Err(super::instance_not_found(&t));
                }
                t
            }
            None => members
                .iter()
                .filter(|m| m.is_cluster_writer != Some(true))
                .min_by_key(|m| m.promotion_tier.unwrap_or(1))
                .and_then(|m| m.db_instance_identifier.clone())
                .ok_or_else(|| {
                    errors::invalid_db_cluster_state_fault("Cannot failover a DB cluster that has no reader instances.")
                })?,
        };
        self.with_region(ctx, |r| {
            if let Some(c) = r.clusters.get_mut(&id) {
                for m in c.cluster.db_cluster_members.iter_mut().flatten() {
                    m.is_cluster_writer = Some(m.db_instance_identifier.as_deref() == Some(target.as_str()));
                }
            }
        });
        self.emit(
            ctx,
            "db-cluster",
            &id,
            &cluster_arn(ctx, &id),
            &["failover"],
            &format!("Completed failover to DB instance: {target}"),
            "RDS-EVENT-0071",
        );
        Ok(t::FailoverDBClusterResult { db_cluster: Some(self.cluster_view(ctx, &self.cluster(ctx, &id)?)) })
    }

    pub(crate) fn add_role_to_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::AddRoleToDBClusterMessage,
    ) -> Result<(), ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "AddRoleToDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        ctx.authorize("iam:PassRole", &input.role_arn, ConditionContext::new())?;
        if !input.role_arn.starts_with("arn:") || !input.role_arn.contains(":role/") {
            return Err(invalid_parameter(format!("Invalid role ARN: {}", input.role_arn)));
        }
        self.with_region(ctx, |r| {
            let rec = r.clusters.get_mut(&id).expect("looked up above");
            let roles = rec.cluster.associated_roles.get_or_insert_with(Vec::new);
            if roles.iter().any(|x| x.role_arn.as_ref() == Some(&input.role_arn)) {
                return Err(errors::db_cluster_role_already_exists_fault(format!(
                    "Role ARN {} is already associated with DB Cluster {id}",
                    input.role_arn
                )));
            }
            roles.push(t::DBClusterRole {
                role_arn: Some(input.role_arn.clone()),
                status: Some("ACTIVE".into()),
                feature_name: input.feature_name.clone(),
            });
            Ok(())
        })
    }

    pub(crate) fn remove_role_from_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::RemoveRoleFromDBClusterMessage,
    ) -> Result<(), ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "RemoveRoleFromDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        self.with_region(ctx, |r| {
            let rec = r.clusters.get_mut(&id).expect("looked up above");
            let roles = rec.cluster.associated_roles.get_or_insert_with(Vec::new);
            let before = roles.len();
            roles.retain(|x| x.role_arn.as_ref() != Some(&input.role_arn));
            if roles.len() == before {
                return Err(errors::db_cluster_role_not_found_fault(format!(
                    "Role ARN {} cannot be found for DB Cluster {id}",
                    input.role_arn
                )));
            }
            Ok(())
        })
    }

    fn set_http_endpoint(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource_arn: &str,
        on: bool,
    ) -> Result<t::EnableHttpEndpointResponse, ServiceError> {
        let rec = self.cluster(ctx, resource_arn)?;
        let id = rec.cluster.db_cluster_identifier.clone().unwrap_or_default();
        authorize(ctx, action, &cluster_arn(ctx, &id), resource_tag_context("cluster", &rec.cluster.tag_list))?;
        if !engine_of(rec.cluster.engine.as_deref().unwrap_or_default())?.aurora {
            return Err(errors::invalid_resource_state_fault(
                "The HTTP endpoint is only available for Aurora DB clusters.",
            ));
        }
        self.with_region(ctx, |r| {
            if let Some(c) = r.clusters.get_mut(&id) {
                c.cluster.http_endpoint_enabled = Some(on);
            }
        });
        Ok(t::EnableHttpEndpointResponse { resource_arn: Some(cluster_arn(ctx, &id)), http_endpoint_enabled: Some(on) })
    }

    pub(crate) fn enable_http_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableHttpEndpointRequest,
    ) -> Result<t::EnableHttpEndpointResponse, ServiceError> {
        self.set_http_endpoint(ctx, "EnableHttpEndpoint", &input.resource_arn, true)
    }

    pub(crate) fn disable_http_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableHttpEndpointRequest,
    ) -> Result<t::DisableHttpEndpointResponse, ServiceError> {
        let r = self.set_http_endpoint(ctx, "DisableHttpEndpoint", &input.resource_arn, false)?;
        Ok(t::DisableHttpEndpointResponse {
            resource_arn: r.resource_arn,
            http_endpoint_enabled: r.http_endpoint_enabled,
        })
    }
}
