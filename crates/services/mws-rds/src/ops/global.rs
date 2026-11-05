//! Aurora global databases: a global cluster groups one writer cluster and
//! read-only secondary clusters in other Regions.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::instance::{engine_of, resolve_version};
use super::{authorize, cluster_not_found};
use crate::generated::{errors, types as t};
use crate::state::{ClusterRecord, GlobalRecord, State};
use crate::util::{
    account_of, identifier, invalid_combination, invalid_parameter, name_of, opt, paginate, parse_arn,
    request_tag_context, resource_id, stable_token, tags_from, Filters,
};
use crate::Rds;

fn global_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:rds::{}:global-cluster:{id}", ctx.partition, account_of(ctx))
}

fn not_found(id: &str) -> ServiceError {
    errors::global_cluster_not_found_fault(format!("Global cluster {id} not found."))
}

impl Rds {
    pub(crate) fn global(&self, ctx: &RequestContext, id: &str) -> Result<t::GlobalCluster, ServiceError> {
        let id = name_of(id);
        let key = State::key(&account_of(ctx), &id);
        self.lock().global_clusters.get(&key).map(|g| g.global.clone()).ok_or_else(|| not_found(&id))
    }

    fn update_global<R>(
        &self,
        ctx: &RequestContext,
        id: &str,
        f: impl FnOnce(&mut t::GlobalCluster) -> R,
    ) -> Result<R, ServiceError> {
        let key = State::key(&account_of(ctx), id);
        let mut st = self.lock();
        let g = st.global_clusters.get_mut(&key).ok_or_else(|| not_found(id))?;
        Ok(f(&mut g.global))
    }

    /// A member cluster, by ARN, in whichever Region it lives.
    fn cluster_by_arn(&self, arn: &str) -> Option<ClusterRecord> {
        let (region, account, _, name) = parse_arn(arn)?;
        self.with_region_of(&account, &region, |r| r.clusters.get(&name).cloned())
    }

    fn with_cluster_arn(&self, arn: &str, f: impl FnOnce(&mut ClusterRecord)) {
        if let Some((region, account, _, name)) = parse_arn(arn) {
            self.with_region_of(&account, &region, |r| {
                if let Some(c) = r.clusters.get_mut(&name) {
                    f(c)
                }
            });
        }
    }

    pub(crate) fn global_primary(&self, _ctx: &RequestContext, g: &t::GlobalCluster) -> Option<ClusterRecord> {
        let writer = g.global_cluster_members.iter().flatten().find(|m| m.is_writer == Some(true))?;
        self.cluster_by_arn(writer.db_cluster_arn.as_deref()?)
    }

    /// Record a cluster as a member of a global cluster.
    pub(crate) fn join_global(&self, ctx: &RequestContext, id: &str, cluster_arn: &str, writer: bool) {
        let primary = self
            .global(ctx, id)
            .ok()
            .and_then(|g| g.global_cluster_members)
            .and_then(|m| m.into_iter().find(|m| m.is_writer == Some(true)).and_then(|m| m.db_cluster_arn));
        let _ = self.update_global(ctx, id, |g| {
            let members = g.global_cluster_members.get_or_insert_with(Vec::new);
            members.push(t::GlobalClusterMember {
                db_cluster_arn: Some(cluster_arn.to_string()),
                readers: Some(Vec::new()),
                is_writer: Some(writer),
                global_write_forwarding_status: (!writer).then(|| "disabled".into()),
                synchronization_status: (!writer).then(|| "connected".into()),
            });
            if !writer {
                if let Some(p) = members.iter_mut().find(|m| m.is_writer == Some(true)) {
                    p.readers.get_or_insert_with(Vec::new).push(cluster_arn.to_string());
                }
            }
        });
        if let Some(p) = primary.filter(|_| !writer) {
            let arn = cluster_arn.to_string();
            self.with_cluster_arn(&p, |c| c.cluster.read_replica_identifiers.get_or_insert_with(Vec::new).push(arn));
            let p2 = p.clone();
            self.with_cluster_arn(cluster_arn, |c| c.cluster.replication_source_identifier = Some(p2));
        }
    }

    pub(crate) fn create_global_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateGlobalClusterMessage,
    ) -> Result<t::CreateGlobalClusterResult, ServiceError> {
        let id = identifier("GlobalClusterIdentifier", &input.global_cluster_identifier, 255)?;
        let arn = global_arn(ctx, &id);
        let tags = tags_from(&input.tags)?;
        authorize(ctx, "CreateGlobalCluster", &arn, request_tag_context(&tags))?;
        if self.global(ctx, &id).is_ok() {
            return Err(errors::global_cluster_already_exists_fault(format!("Global cluster {id} already exists.")));
        }
        let source = match &input.source_db_cluster_identifier {
            Some(s) => {
                let rec = if s.starts_with("arn:") {
                    self.cluster_by_arn(s).ok_or_else(|| cluster_not_found(&name_of(s)))?
                } else {
                    self.cluster(ctx, s)?
                };
                authorize(
                    ctx,
                    "CreateGlobalCluster",
                    rec.cluster.db_cluster_arn.as_deref().unwrap_or_default(),
                    ConditionContext::new(),
                )?;
                if rec.cluster.global_cluster_identifier.is_some() {
                    return Err(errors::invalid_db_cluster_state_fault(
                        "The source cluster is already a member of a global cluster.",
                    ));
                }
                Some(rec)
            }
            None => None,
        };
        let (engine, version, encrypted, db_name) = match &source {
            Some(s) => {
                if input.engine.is_some()
                    || input.engine_version.is_some()
                    || input.storage_encrypted.is_some()
                    || input.database_name.is_some()
                {
                    return Err(invalid_parameter(
                        "When you specify SourceDBClusterIdentifier you can't specify Engine, EngineVersion, StorageEncrypted or DatabaseName.",
                    ));
                }
                (
                    s.cluster.engine.clone().unwrap_or_default(),
                    s.cluster.engine_version.clone().unwrap_or_default(),
                    s.cluster.storage_encrypted.unwrap_or(false),
                    s.cluster.database_name.clone(),
                )
            }
            None => {
                let name = input.engine.clone().ok_or_else(|| {
                    invalid_parameter(
                        "The parameter Engine must be provided unless SourceDBClusterIdentifier is specified.",
                    )
                })?;
                let engine = engine_of(&name)?;
                if !engine.aurora {
                    return Err(invalid_parameter(format!("Global clusters aren't supported for engine {name}.")));
                }
                let v = resolve_version(engine, &input.engine_version)?;
                (
                    engine.name.to_string(),
                    v.version.to_string(),
                    input.storage_encrypted.unwrap_or(false),
                    input.database_name.clone(),
                )
            }
        };
        let global = t::GlobalCluster {
            global_cluster_identifier: Some(id.clone()),
            global_cluster_resource_id: Some(format!("cluster-{}", &stable_token(&resource_id("g"), 26)[..26])),
            global_cluster_arn: Some(arn.clone()),
            status: Some("available".into()),
            engine: Some(engine),
            engine_version: Some(version),
            engine_lifecycle_support: Some(
                input.engine_lifecycle_support.clone().unwrap_or_else(|| "open-source-rds-extended-support".into()),
            ),
            database_name: db_name,
            storage_encrypted: Some(encrypted),
            deletion_protection: Some(input.deletion_protection.unwrap_or(false)),
            global_cluster_members: Some(Vec::new()),
            endpoint: Some(format!("{id}.global-{}.global.rds.amazonaws.com", &stable_token(&arn, 12)[..12])),
            tag_list: Some(tags),
            ..Default::default()
        };
        self.lock().global_clusters.insert(State::key(&account_of(ctx), &id), GlobalRecord { global });
        if let Some(s) = &source {
            let carn = s.cluster.db_cluster_arn.clone().unwrap_or_default();
            self.with_cluster_arn(&carn, |c| c.cluster.global_cluster_identifier = Some(id.clone()));
            self.join_global(ctx, &id, &carn, true);
        }
        Ok(t::CreateGlobalClusterResult { global_cluster: Some(self.global(ctx, &id)?) })
    }

    pub(crate) fn describe_global_clusters_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeGlobalClustersMessage,
    ) -> Result<t::GlobalClustersMessage, ServiceError> {
        let wanted = input.global_cluster_identifier.as_deref().map(name_of);
        authorize(
            ctx,
            "DescribeGlobalClusters",
            &global_arn(ctx, wanted.as_deref().unwrap_or("*")),
            ConditionContext::new(),
        )?;
        let f = Filters::new(&input.filters, &["db-cluster-id", "engine", "global-cluster-id"])?;
        let prefix = format!("{}/", account_of(ctx));
        let all: Vec<t::GlobalCluster> = self
            .lock()
            .global_clusters
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, g)| g.global.clone())
            .collect();
        if let Some(w) = &wanted {
            if !all.iter().any(|g| g.global_cluster_identifier.as_ref() == Some(w)) {
                return Err(not_found(w));
            }
        }
        let all: Vec<t::GlobalCluster> = all
            .into_iter()
            .filter(|g| wanted.as_ref().is_none_or(|w| g.global_cluster_identifier.as_ref() == Some(w)))
            .filter(|g| {
                f.matches(|n| match n {
                    "global-cluster-id" => opt(&g.global_cluster_identifier),
                    "engine" => opt(&g.engine),
                    "db-cluster-id" => {
                        g.global_cluster_members.iter().flatten().filter_map(|m| m.db_cluster_arn.clone()).collect()
                    }
                    _ => Vec::new(),
                })
            })
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::GlobalClustersMessage { marker, global_clusters: Some(page) })
    }

    pub(crate) fn modify_global_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyGlobalClusterMessage,
    ) -> Result<t::ModifyGlobalClusterResult, ServiceError> {
        let id = name_of(&input.global_cluster_identifier);
        let g = self.global(ctx, &id)?;
        authorize(ctx, "ModifyGlobalCluster", &global_arn(ctx, &id), ConditionContext::new())?;
        if let Some(v) = &input.engine_version {
            let engine = engine_of(g.engine.as_deref().unwrap_or_default())?;
            let target = engine
                .version(v)
                .ok_or_else(|| invalid_combination(format!("Cannot find version {v} for {}", engine.name)))?;
            let current = engine.version(g.engine_version.as_deref().unwrap_or_default());
            if current.map(|c| c.major) != Some(target.major) && input.allow_major_version_upgrade != Some(true) {
                return Err(invalid_parameter(
                    "The AllowMajorVersionUpgrade flag must be present when upgrading to a new major version.",
                ));
            }
            for m in g.global_cluster_members.iter().flatten() {
                let version = target.version.to_string();
                self.with_cluster_arn(m.db_cluster_arn.as_deref().unwrap_or_default(), |c| {
                    c.cluster.engine_version = Some(version)
                });
            }
        }
        let new_id = match &input.new_global_cluster_identifier {
            Some(n) => Some(identifier("NewGlobalClusterIdentifier", n, 255)?),
            None => None,
        };
        self.update_global(ctx, &id, |g| {
            if let Some(b) = input.deletion_protection {
                g.deletion_protection = Some(b);
            }
            if let Some(v) = &input.engine_version {
                g.engine_version = Some(v.clone());
            }
        })?;
        let mut id = id;
        if let Some(n) = new_id.filter(|n| *n != id) {
            if self.global(ctx, &n).is_ok() {
                return Err(errors::global_cluster_already_exists_fault(format!("Global cluster {n} already exists.")));
            }
            let mut st = self.lock();
            let account = account_of(ctx);
            if let Some(mut rec) = st.global_clusters.remove(&State::key(&account, &id)) {
                rec.global.global_cluster_identifier = Some(n.clone());
                rec.global.global_cluster_arn = Some(global_arn(ctx, &n));
                st.global_clusters.insert(State::key(&account, &n), rec);
            }
            for r in st.regions.values_mut() {
                for c in r.clusters.values_mut() {
                    if c.cluster.global_cluster_identifier.as_deref() == Some(id.as_str()) {
                        c.cluster.global_cluster_identifier = Some(n.clone());
                    }
                }
            }
            id = n;
        }
        Ok(t::ModifyGlobalClusterResult { global_cluster: Some(self.global(ctx, &id)?) })
    }

    pub(crate) fn delete_global_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteGlobalClusterMessage,
    ) -> Result<t::DeleteGlobalClusterResult, ServiceError> {
        let id = name_of(&input.global_cluster_identifier);
        let g = self.global(ctx, &id)?;
        authorize(ctx, "DeleteGlobalCluster", &global_arn(ctx, &id), ConditionContext::new())?;
        if g.deletion_protection == Some(true) {
            return Err(errors::invalid_global_cluster_state_fault(
                "Cannot delete protected Global Cluster, please disable deletion protection and try again.",
            ));
        }
        if g.global_cluster_members.as_ref().is_some_and(|m| !m.is_empty()) {
            return Err(errors::invalid_global_cluster_state_fault(format!("Global Cluster {id} is not empty")));
        }
        self.lock().global_clusters.remove(&State::key(&account_of(ctx), &id));
        let mut g = g;
        g.status = Some("deleting".into());
        Ok(t::DeleteGlobalClusterResult { global_cluster: Some(g) })
    }

    pub(crate) fn remove_from_global_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::RemoveFromGlobalClusterMessage,
    ) -> Result<t::RemoveFromGlobalClusterResult, ServiceError> {
        let id = name_of(&input.global_cluster_identifier);
        let g = self.global(ctx, &id)?;
        authorize(ctx, "RemoveFromGlobalCluster", &global_arn(ctx, &id), ConditionContext::new())?;
        let arn = if input.db_cluster_identifier.starts_with("arn:") {
            input.db_cluster_identifier.clone()
        } else {
            super::cluster_arn(ctx, &input.db_cluster_identifier.to_ascii_lowercase())
        };
        let member = g
            .global_cluster_members
            .iter()
            .flatten()
            .find(|m| m.db_cluster_arn.as_deref() == Some(arn.as_str()))
            .cloned()
            .ok_or_else(|| {
                errors::db_cluster_not_found_fault(format!("DB cluster {arn} is not a member of global cluster {id}."))
            })?;
        let others = g.global_cluster_members.iter().flatten().count() > 1;
        if member.is_writer == Some(true) && others {
            return Err(errors::invalid_global_cluster_state_fault(
                "The primary cluster can't be removed while the global cluster has secondary clusters.",
            ));
        }
        self.update_global(ctx, &id, |g| {
            if let Some(m) = g.global_cluster_members.as_mut() {
                m.retain(|m| m.db_cluster_arn.as_deref() != Some(arn.as_str()));
                for x in m.iter_mut() {
                    if let Some(r) = x.readers.as_mut() {
                        r.retain(|r| r != &arn);
                    }
                }
            }
        })?;
        let primary = g
            .global_cluster_members
            .iter()
            .flatten()
            .find(|m| m.is_writer == Some(true))
            .and_then(|m| m.db_cluster_arn.clone());
        self.with_cluster_arn(&arn, |c| {
            c.cluster.global_cluster_identifier = None;
            c.cluster.replication_source_identifier = None;
        });
        if let Some(p) = primary {
            self.with_cluster_arn(&p, |c| {
                if let Some(r) = c.cluster.read_replica_identifiers.as_mut() {
                    r.retain(|r| r != &arn);
                }
            });
        }
        Ok(t::RemoveFromGlobalClusterResult { global_cluster: Some(self.global(ctx, &id)?) })
    }

    fn move_writer(
        &self,
        ctx: &RequestContext,
        id: &str,
        target: &str,
        data_loss: bool,
        switchover: bool,
    ) -> Result<t::GlobalCluster, ServiceError> {
        let g = self.global(ctx, id)?;
        let target_arn = if target.starts_with("arn:") {
            target.to_string()
        } else {
            super::cluster_arn(ctx, &target.to_ascii_lowercase())
        };
        let members = g.global_cluster_members.clone().unwrap_or_default();
        if !members.iter().any(|m| m.db_cluster_arn.as_deref() == Some(target_arn.as_str())) {
            return Err(errors::db_cluster_not_found_fault(format!(
                "DB cluster {target_arn} is not a member of global cluster {id}."
            )));
        }
        let from = members
            .iter()
            .find(|m| m.is_writer == Some(true))
            .and_then(|m| m.db_cluster_arn.clone())
            .unwrap_or_default();
        if from == target_arn {
            return Err(errors::invalid_global_cluster_state_fault(format!(
                "The cluster {target_arn} is already the primary cluster of global cluster {id}."
            )));
        }
        let all: Vec<String> = members.iter().filter_map(|m| m.db_cluster_arn.clone()).collect();
        let readers: Vec<String> = all.iter().filter(|a| **a != target_arn).cloned().collect();
        self.update_global(ctx, id, |g| {
            for m in g.global_cluster_members.iter_mut().flatten() {
                let writer = m.db_cluster_arn.as_deref() == Some(target_arn.as_str());
                m.is_writer = Some(writer);
                m.readers = Some(if writer { readers.clone() } else { Vec::new() });
                m.synchronization_status = (!writer).then(|| "connected".into());
                m.global_write_forwarding_status = (!writer).then(|| "disabled".into());
            }
            g.failover_state = Some(t::FailoverState {
                status: Some("pending".into()),
                from_db_cluster_arn: Some(from.clone()),
                to_db_cluster_arn: Some(target_arn.clone()),
                is_data_loss_allowed: Some(data_loss && !switchover),
            });
        })?;
        for a in &all {
            let writer = *a == target_arn;
            let (target, readers) = (target_arn.clone(), readers.clone());
            self.with_cluster_arn(a, |c| {
                c.cluster.replication_source_identifier = (!writer).then_some(target);
                c.cluster.read_replica_identifiers = Some(if writer { readers } else { Vec::new() });
            });
        }
        // The move completes at once.
        self.update_global(ctx, id, |g| g.failover_state = None)?;
        let mut g = self.global(ctx, id)?;
        g.failover_state = Some(t::FailoverState {
            status: Some("pending".into()),
            from_db_cluster_arn: Some(from),
            to_db_cluster_arn: Some(target_arn),
            is_data_loss_allowed: Some(data_loss && !switchover),
        });
        Ok(g)
    }

    pub(crate) fn failover_global_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::FailoverGlobalClusterMessage,
    ) -> Result<t::FailoverGlobalClusterResult, ServiceError> {
        let id = name_of(&input.global_cluster_identifier);
        self.global(ctx, &id)?;
        authorize(ctx, "FailoverGlobalCluster", &global_arn(ctx, &id), ConditionContext::new())?;
        if input.allow_data_loss == Some(true) && input.switchover == Some(true) {
            return Err(invalid_combination("You can't specify both AllowDataLoss and Switchover."));
        }
        let g = self.move_writer(
            ctx,
            &id,
            &input.target_db_cluster_identifier,
            input.allow_data_loss.unwrap_or(false),
            input.switchover.unwrap_or(false),
        )?;
        Ok(t::FailoverGlobalClusterResult { global_cluster: Some(g) })
    }

    pub(crate) fn switchover_global_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::SwitchoverGlobalClusterMessage,
    ) -> Result<t::SwitchoverGlobalClusterResult, ServiceError> {
        let id = name_of(&input.global_cluster_identifier);
        self.global(ctx, &id)?;
        authorize(ctx, "SwitchoverGlobalCluster", &global_arn(ctx, &id), ConditionContext::new())?;
        let g = self.move_writer(ctx, &id, &input.target_db_cluster_identifier, false, true)?;
        Ok(t::SwitchoverGlobalClusterResult { global_cluster: Some(g) })
    }
}
