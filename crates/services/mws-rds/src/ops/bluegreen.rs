//! Blue/Green deployments: a green copy of a DB instance or Aurora cluster
//! (optionally on a newer engine version, other parameter group or
//! instance class) that takes over the blue one's names at switchover.
//!
//! The green copy is a read replica of the blue database (for clusters, a
//! clone with the same instances). At switchover RDS brings green up to
//! date with blue's data as it is then, renames blue to `<name>-old1` and
//! gives green blue's names, so clients keep their configuration.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, cluster_arn, db_arn};
use crate::generated::{errors, types as t};
use crate::state::Listen;
use crate::util::{
    invalid_combination, invalid_parameter, paginate, parse_arn, request_tag_context, resource_id, tags_from, Filters,
};
use crate::Rds;

fn not_found(id: &str) -> ServiceError {
    errors::blue_green_deployment_not_found_fault(format!("BlueGreenDeployment {id} not found."))
}

fn suffix() -> String {
    resource_id("").to_ascii_lowercase()[..6].to_string()
}

fn task(name: &str, status: &str) -> t::BlueGreenDeploymentTask {
    t::BlueGreenDeploymentTask { name: Some(name.into()), status: Some(status.into()) }
}

impl Rds {
    fn blue_green(&self, ctx: &RequestContext, id: &str) -> Result<t::BlueGreenDeployment, ServiceError> {
        let id = id.to_ascii_lowercase();
        self.with_region(ctx, |r| r.blue_green.get(&id).cloned()).ok_or_else(|| not_found(&id))
    }

    /// A deployment as RDS reports it now: provisioning until every green
    /// member is available.
    fn refresh_blue_green(&self, ctx: &RequestContext, mut bg: t::BlueGreenDeployment) -> t::BlueGreenDeployment {
        if bg.status.as_deref() == Some("PROVISIONING") {
            let ready = bg.switchover_details.iter().flatten().all(|d| {
                let Some((_, _, kind, name)) = d.target_member.as_deref().and_then(parse_arn) else { return false };
                self.with_region(ctx, |r| match kind.as_str() {
                    "cluster" => {
                        r.clusters.get(&name).is_some_and(|c| c.cluster.status.as_deref() == Some("available"))
                    }
                    _ => r.instances.get(&name).is_some_and(|i| {
                        super::maintenance::operational(i.db.db_instance_status.as_deref().unwrap_or_default())
                    }),
                })
            });
            if ready {
                bg.status = Some("AVAILABLE".into());
                for t in bg.tasks.iter_mut().flatten() {
                    t.status = Some("COMPLETED".into());
                }
                for d in bg.switchover_details.iter_mut().flatten() {
                    d.status = Some("AVAILABLE".into());
                }
                let id = bg.blue_green_deployment_identifier.clone().unwrap_or_default();
                let stored = bg.clone();
                self.with_region(ctx, |r| r.blue_green.insert(id, stored));
            }
        }
        bg
    }

    pub(crate) async fn create_blue_green_deployment_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateBlueGreenDeploymentRequest,
    ) -> Result<t::CreateBlueGreenDeploymentResponse, ServiceError> {
        let name = input.blue_green_deployment_name.clone();
        if name.is_empty() || name.len() > 60 {
            return Err(invalid_parameter("BlueGreenDeploymentName must be 1 to 60 characters."));
        }
        let id = format!("bgd-{}", &resource_id("").to_ascii_lowercase()[..16]);
        let tags = tags_from(&input.tags)?;
        let bg_arn = crate::util::arn(ctx, "deployment", &id);
        authorize(ctx, "CreateBlueGreenDeployment", &bg_arn, request_tag_context(&tags))?;
        let Some((_, _, kind, source)) = parse_arn(&input.source) else {
            return Err(invalid_parameter(format!("Invalid source ARN: {}", input.source)));
        };
        authorize(ctx, "CreateBlueGreenDeployment", &input.source, ConditionContext::new())?;
        let in_use = self.with_region(ctx, |r| {
            r.blue_green.values().any(|b| {
                b.source.as_deref() == Some(input.source.as_str())
                    && !matches!(b.status.as_deref(), Some("SWITCHOVER_COMPLETED") | Some("DELETING"))
            })
        });
        if in_use {
            return Err(errors::blue_green_deployment_already_exists_fault(format!(
                "A blue/green deployment already exists for source {}.",
                input.source
            )));
        }
        let green_suffix = suffix();
        let mut details = Vec::new();
        let mut tasks = vec![task("CREATING_READ_REPLICA_OF_SOURCE", "IN_PROGRESS")];
        if input.target_engine_version.is_some() {
            tasks.push(task("DB_ENGINE_VERSION_UPGRADE", "PENDING"));
        }
        tasks.push(task("CONFIGURE_BACKUPS", "PENDING"));
        tasks.push(task("CREATING_TOPOLOGY_OF_SOURCE", "PENDING"));
        let target = match kind.as_str() {
            "db" => {
                let blue = self.instance(ctx, &source)?;
                if blue.db.db_cluster_identifier.is_some() {
                    return Err(invalid_parameter(
                        "The source DB instance is a member of a DB cluster. Specify the cluster as the source.",
                    ));
                }
                if blue.db.read_replica_source_db_instance_identifier.is_some() {
                    return Err(invalid_parameter("The source can't be a read replica."));
                }
                let green = format!("{}-green-{green_suffix}", truncate(&source, 63 - 13));
                self.create_db_instance_read_replica_op(
                    ctx,
                    t::CreateDBInstanceReadReplicaMessage {
                        db_instance_identifier: green.clone(),
                        source_db_instance_identifier: Some(source.clone()),
                        db_instance_class: input.target_db_instance_class.clone(),
                        db_parameter_group_name: input.target_db_parameter_group_name.clone(),
                        storage_type: input.target_storage_type.clone(),
                        tags: blue.db.tag_list.clone(),
                        ..Default::default()
                    },
                )
                .await?;
                self.green_settings(ctx, &green, &input)?;
                details.push(t::SwitchoverDetail {
                    source_member: Some(input.source.clone()),
                    target_member: Some(db_arn(ctx, &green)),
                    status: Some("PROVISIONING".into()),
                });
                db_arn(ctx, &green)
            }
            "cluster" => {
                let blue = self.cluster(ctx, &source)?;
                let green = format!("{}-green-{green_suffix}", truncate(&source, 63 - 13));
                self.clone_cluster(
                    ctx,
                    &source,
                    &green,
                    input.target_db_cluster_parameter_group_name.clone(),
                    input.target_engine_version.clone(),
                    blue.cluster.tag_list.clone().unwrap_or_default(),
                )
                .await?;
                details.push(t::SwitchoverDetail {
                    source_member: Some(input.source.clone()),
                    target_member: Some(cluster_arn(ctx, &green)),
                    status: Some("PROVISIONING".into()),
                });
                for m in blue.cluster.db_cluster_members.iter().flatten() {
                    let member = m.db_instance_identifier.clone().unwrap_or_default();
                    let Ok(i) = self.instance(ctx, &member) else { continue };
                    let green_member = format!("{}-green-{green_suffix}", truncate(&member, 63 - 13));
                    self.create_db_instance_op(
                        ctx,
                        t::CreateDBInstanceMessage {
                            db_instance_identifier: green_member.clone(),
                            db_cluster_identifier: Some(green.clone()),
                            engine: i.db.engine.clone().unwrap_or_default(),
                            db_instance_class: input
                                .target_db_instance_class
                                .clone()
                                .or(i.db.db_instance_class.clone())
                                .unwrap_or_default(),
                            promotion_tier: m.promotion_tier,
                            tags: i.db.tag_list.clone(),
                            ..Default::default()
                        },
                    )
                    .await?;
                    details.push(t::SwitchoverDetail {
                        source_member: Some(db_arn(ctx, &member)),
                        target_member: Some(db_arn(ctx, &green_member)),
                        status: Some("PROVISIONING".into()),
                    });
                }
                cluster_arn(ctx, &green)
            }
            _ => return Err(invalid_parameter(format!("Invalid source ARN: {}", input.source))),
        };
        let bg = t::BlueGreenDeployment {
            blue_green_deployment_identifier: Some(id.clone()),
            blue_green_deployment_name: Some(name),
            source: Some(input.source.clone()),
            target: Some(target),
            switchover_details: Some(details),
            tasks: Some(tasks),
            status: Some("PROVISIONING".into()),
            status_details: None,
            create_time: Some(ctx.received_at),
            delete_time: None,
            tag_list: Some(tags),
        };
        self.with_region(ctx, |r| r.blue_green.insert(id.clone(), bg.clone()));
        Ok(t::CreateBlueGreenDeploymentResponse { blue_green_deployment: Some(bg) })
    }

    /// The green instance's engine version and storage, as asked.
    fn green_settings(
        &self,
        ctx: &RequestContext,
        green: &str,
        input: &t::CreateBlueGreenDeploymentRequest,
    ) -> Result<(), ServiceError> {
        let rec = self.instance(ctx, green)?;
        let engine = super::instance::engine_of(rec.db.engine.as_deref().unwrap_or_default())?;
        let version = match &input.target_engine_version {
            Some(v) => {
                let target = engine
                    .version(v)
                    .ok_or_else(|| invalid_combination(format!("Cannot find version {v} for {}", engine.name)))?;
                let current = engine.version(rec.db.engine_version.as_deref().unwrap_or_default());
                if current.is_some_and(|c| c.version > target.version && c.major >= target.major) {
                    return Err(invalid_parameter(format!(
                        "The target engine version {v} is older than the source's engine version."
                    )));
                }
                Some(target)
            }
            None => None,
        };
        self.with_region(ctx, |r| {
            if let Some(i) = r.instances.get_mut(green) {
                if let Some(v) = version {
                    i.db.engine_version = Some(v.version.to_string());
                    i.image = v.image.to_string();
                }
                if let Some(s) = input.target_allocated_storage {
                    i.db.allocated_storage = Some(s);
                }
                if let Some(s) = input.target_iops {
                    i.db.iops = Some(s);
                }
                if let Some(s) = input.target_storage_throughput {
                    i.db.storage_throughput = Some(s);
                }
            }
        });
        Ok(())
    }

    pub(crate) fn describe_blue_green_deployments_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeBlueGreenDeploymentsRequest,
    ) -> Result<t::DescribeBlueGreenDeploymentsResponse, ServiceError> {
        authorize(
            ctx,
            "DescribeBlueGreenDeployments",
            &crate::util::arn(ctx, "deployment", "*"),
            ConditionContext::new(),
        )?;
        let f = Filters::new(
            &input.filters,
            &["blue-green-deployment-identifier", "blue-green-deployment-name", "source", "target"],
        )?;
        let all: Vec<t::BlueGreenDeployment> = match &input.blue_green_deployment_identifier {
            Some(id) => vec![self.blue_green(ctx, id)?],
            None => self.with_region(ctx, |r| r.blue_green.values().cloned().collect()),
        };
        let all: Vec<_> = all
            .into_iter()
            .map(|b| self.refresh_blue_green(ctx, b))
            .filter(|b| {
                f.matches(|n| match n {
                    "blue-green-deployment-identifier" => b.blue_green_deployment_identifier.iter().cloned().collect(),
                    "blue-green-deployment-name" => b.blue_green_deployment_name.iter().cloned().collect(),
                    "source" => b.source.iter().cloned().collect(),
                    "target" => b.target.iter().cloned().collect(),
                    _ => Vec::new(),
                })
            })
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DescribeBlueGreenDeploymentsResponse { blue_green_deployments: Some(page), marker })
    }

    /// Bring green's data up to blue's as of now.
    async fn sync_green(&self, ctx: &RequestContext, blue_backend: &str, green: &str, cluster: bool) -> Option<Listen> {
        if !self.backend().runs_databases() {
            return None;
        }
        let tmp = format!("bg-sync-{}", resource_id("").to_ascii_lowercase());
        if let Err(e) = self.backend().snapshot(blue_backend, &tmp).await {
            tracing::warn!(green = %green, "copying blue's data failed: {e}");
            return None;
        }
        let spec = self.with_region(ctx, |r| {
            if cluster {
                r.clusters.get(green).map(|c| self.cluster_spec(r, c, ctx))
            } else {
                r.instances.get(green).map(|i| self.instance_spec(r, i, ctx))
            }
        })?;
        let _ = self.backend().delete(&spec.name).await;
        let created = self.backend().create(&spec, Some(&tmp)).await;
        let _ = self.backend().delete_snapshot(&tmp).await;
        match created {
            Ok(l) => Some(Listen { host: l.host, port: l.port }),
            Err(e) => {
                tracing::warn!(green = %green, "restarting green failed: {e}");
                None
            }
        }
    }

    pub(crate) async fn switchover_blue_green_deployment_op(
        &self,
        ctx: &RequestContext,
        input: t::SwitchoverBlueGreenDeploymentRequest,
    ) -> Result<t::SwitchoverBlueGreenDeploymentResponse, ServiceError> {
        let bg = self.blue_green(ctx, &input.blue_green_deployment_identifier)?;
        let bg = self.refresh_blue_green(ctx, bg);
        let id = bg.blue_green_deployment_identifier.clone().unwrap_or_default();
        authorize(
            ctx,
            "SwitchoverBlueGreenDeployment",
            &crate::util::arn(ctx, "deployment", &id),
            ConditionContext::new(),
        )?;
        if let Some(t) = input.switchover_timeout {
            if t < 30 {
                return Err(invalid_parameter("SwitchoverTimeout must be at least 30 seconds."));
            }
        }
        if bg.status.as_deref() != Some("AVAILABLE") {
            return Err(errors::invalid_blue_green_deployment_state_fault(format!(
                "The blue/green deployment {id} is in {} state. Switchover requires AVAILABLE.",
                bg.status.clone().unwrap_or_default()
            )));
        }
        let pairs: Vec<(String, String, String)> = bg
            .switchover_details
            .iter()
            .flatten()
            .filter_map(|d| {
                let (_, _, kind, blue) = parse_arn(d.source_member.as_deref()?)?;
                let (_, _, _, green) = parse_arn(d.target_member.as_deref()?)?;
                Some((kind, blue, green))
            })
            .collect();
        // Green catches up with blue, then takes blue's names.
        for (kind, blue, green) in &pairs {
            let cluster = kind == "cluster";
            if !cluster && self.instance(ctx, green).is_ok_and(|g| g.db.db_cluster_identifier.is_some()) {
                continue;
            }
            let blue_backend = self.with_region(ctx, |r| {
                if cluster {
                    r.clusters.get(blue).map(|c| c.backend_name.clone())
                } else {
                    r.instances.get(blue).map(|i| i.backend_name.clone())
                }
            });
            let Some(blue_backend) = blue_backend else {
                return Err(errors::invalid_blue_green_deployment_state_fault(format!(
                    "The blue database {blue} no longer exists."
                )));
            };
            // Green becomes writable, with blue's credentials.
            self.with_region(ctx, |r| {
                if cluster {
                    let (password, secret) = r
                        .clusters
                        .get(blue)
                        .map(|c| (c.master_password.clone(), c.cluster.master_user_secret.clone()))
                        .unwrap_or_default();
                    if let Some(g) = r.clusters.get_mut(green) {
                        g.master_password = password;
                        g.cluster.master_user_secret = secret;
                    }
                } else {
                    let (password, secret, retention) = r
                        .instances
                        .get(blue)
                        .map(|i| {
                            (i.master_password.clone(), i.db.master_user_secret.clone(), i.db.backup_retention_period)
                        })
                        .unwrap_or_default();
                    if let Some(s) = r.instances.get_mut(blue) {
                        if let Some(l) = s.db.read_replica_db_instance_identifiers.as_mut() {
                            l.retain(|x| x != green);
                        }
                    }
                    if let Some(g) = r.instances.get_mut(green) {
                        g.master_password = password;
                        g.db.master_user_secret = secret;
                        g.db.read_replica_source_db_instance_identifier = None;
                        g.db.status_infos = None;
                        g.db.backup_retention_period = retention.or(Some(1));
                    }
                }
            });
            let listen = self.sync_green(ctx, &blue_backend, green, cluster).await;
            if let Some(l) = listen {
                self.with_region(ctx, |r| {
                    if cluster {
                        if let Some(g) = r.clusters.get_mut(green) {
                            g.listen = Some(l);
                        }
                    } else if let Some(g) = r.instances.get_mut(green) {
                        g.listen = Some(l);
                    }
                });
            }
        }
        let mut details = Vec::new();
        for (kind, blue, green) in &pairs {
            let old = format!("{}-old1", truncate(blue, 58));
            if kind == "cluster" {
                self.rename_cluster(ctx, blue, &old);
                self.rename_cluster(ctx, green, blue);
                details.push(t::SwitchoverDetail {
                    source_member: Some(cluster_arn(ctx, &old)),
                    target_member: Some(cluster_arn(ctx, blue)),
                    status: Some("SWITCHOVER_COMPLETED".into()),
                });
            } else {
                self.rename_instance(ctx, blue, &old);
                self.rename_instance(ctx, green, blue);
                details.push(t::SwitchoverDetail {
                    source_member: Some(db_arn(ctx, &old)),
                    target_member: Some(db_arn(ctx, blue)),
                    status: Some("SWITCHOVER_COMPLETED".into()),
                });
            }
            self.emit(
                ctx,
                if kind == "cluster" { "db-cluster" } else { "db-instance" },
                blue,
                &if kind == "cluster" { cluster_arn(ctx, blue) } else { db_arn(ctx, blue) },
                &["notification"],
                "Blue/green deployment switchover completed.",
                "RDS-EVENT-0245",
            );
        }
        let bg = self.with_region(ctx, |r| {
            let b = r.blue_green.get_mut(&id).expect("looked up above");
            b.status = Some("SWITCHOVER_COMPLETED".into());
            b.source = details.first().and_then(|d| d.source_member.clone());
            b.target = details.first().and_then(|d| d.target_member.clone());
            b.switchover_details = Some(details);
            b.clone()
        });
        Ok(t::SwitchoverBlueGreenDeploymentResponse { blue_green_deployment: Some(bg) })
    }

    pub(crate) async fn delete_blue_green_deployment_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteBlueGreenDeploymentRequest,
    ) -> Result<t::DeleteBlueGreenDeploymentResponse, ServiceError> {
        let bg = self.blue_green(ctx, &input.blue_green_deployment_identifier)?;
        let id = bg.blue_green_deployment_identifier.clone().unwrap_or_default();
        authorize(
            ctx,
            "DeleteBlueGreenDeployment",
            &crate::util::arn(ctx, "deployment", &id),
            ConditionContext::new(),
        )?;
        let switched = bg.status.as_deref() == Some("SWITCHOVER_COMPLETED");
        let delete_target = input.delete_target.unwrap_or(false);
        if switched && delete_target {
            return Err(invalid_combination(
                "You can't delete the target resources of a blue/green deployment after switchover.",
            ));
        }
        if delete_target {
            // Instances first, then the green cluster.
            let mut members: Vec<(String, String)> = bg
                .switchover_details
                .iter()
                .flatten()
                .filter_map(|d| parse_arn(d.target_member.as_deref()?).map(|(_, _, k, n)| (k, n)))
                .collect();
            members.sort_by_key(|(k, _)| k == "cluster");
            for (kind, name) in members {
                if kind == "cluster" {
                    let _ = self
                        .delete_db_cluster_op(
                            ctx,
                            t::DeleteDBClusterMessage {
                                db_cluster_identifier: name,
                                skip_final_snapshot: Some(true),
                                ..Default::default()
                            },
                        )
                        .await;
                } else {
                    let _ = self
                        .delete_db_instance_op(
                            ctx,
                            t::DeleteDBInstanceMessage {
                                db_instance_identifier: name,
                                skip_final_snapshot: Some(true),
                                ..Default::default()
                            },
                        )
                        .await;
                }
            }
        } else if !switched {
            // Green stays as a database of its own.
            for d in bg.switchover_details.iter().flatten() {
                if let Some((_, _, kind, name)) = d.target_member.as_deref().and_then(parse_arn) {
                    if kind == "db" {
                        let source = self.with_region(ctx, |r| {
                            r.instances.get(&name).and_then(|i| i.db.read_replica_source_db_instance_identifier.clone())
                        });
                        if source.is_some() {
                            let _ = self
                                .promote_read_replica_op(
                                    ctx,
                                    t::PromoteReadReplicaMessage { db_instance_identifier: name, ..Default::default() },
                                )
                                .await;
                        }
                    }
                }
            }
        }
        let mut bg = bg;
        bg.status = Some("DELETING".into());
        bg.delete_time = Some(ctx.received_at);
        self.with_region(ctx, |r| r.blue_green.remove(&id));
        Ok(t::DeleteBlueGreenDeploymentResponse { blue_green_deployment: Some(bg) })
    }
}

fn truncate(s: &str, n: usize) -> &str {
    &s[..s.len().min(n)]
}
