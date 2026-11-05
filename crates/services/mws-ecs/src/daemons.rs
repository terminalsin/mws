//! Daemons and daemon task definitions: one daemon task per instance of a
//! Managed Instances capacity provider. MWS keeps their definitions,
//! revisions and deployments; deployments complete at once.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types as t};
use crate::names::{
    authorize, check_tags, client, cluster_name, failure, invalid, numeric_id, paginate, request_tags, resource_tags,
    split_arn, Cond, Scope,
};
use crate::state::{DaemonRecord, Region};
use crate::{clusters, tags, taskdefs, Ecs};

fn parse_dtd(reference: &str) -> (String, Option<i32>) {
    let body = match split_arn(reference) {
        Some((_, _, res)) => res.strip_prefix("daemon-task-definition/").unwrap_or(res),
        None => reference,
    };
    match body.rsplit_once(':').and_then(|(f, r)| Some((f, r.parse::<i32>().ok()?))) {
        Some((f, r)) => (f.to_string(), Some(r)),
        None => (body.to_string(), None),
    }
}

fn resolve_dtd<'a>(r: &'a Region, reference: &str) -> Option<&'a t::DaemonTaskDefinition> {
    let (family, rev) = parse_dtd(reference);
    let revs = r.daemon_task_definitions.get(&family)?;
    match rev {
        Some(n) => revs.iter().find(|d| d.revision == n),
        None => revs.iter().rev().find(|d| d.status.as_deref() == Some("ACTIVE")),
    }
}

fn daemon_not_found() -> ServiceError {
    errors::daemon_not_found("The specified daemon does not exist.")
}

impl Ecs {
    pub(crate) fn register_daemon_task_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::RegisterDaemonTaskDefinitionRequest,
    ) -> Result<t::RegisterDaemonTaskDefinitionResponse, ServiceError> {
        if !taskdefs::valid_family(&input.family) {
            return Err(client(
                "Family contains invalid characters. Up to 255 letters (uppercase and lowercase), numbers, hyphens, and underscores are allowed.",
            ));
        }
        if input.container_definitions.is_empty() {
            return Err(client("Container list cannot be empty."));
        }
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let scope = Scope::of(ctx);
        authorize(
            ctx,
            "RegisterDaemonTaskDefinition",
            &scope.arn(&format!("daemon-task-definition/{}:*", input.family)),
            Cond::new().extend(request_tags(input.tags.as_ref())),
        )?;
        let mut names = Vec::new();
        for c in &input.container_definitions {
            let name = c.name.clone().unwrap_or_default();
            if names.contains(&name) {
                return Err(client(format!("Duplicate container name found: '{name}'.")));
            }
            if c.image.is_empty() {
                return Err(client("Container.image should not be null or empty."));
            }
            names.push(name);
        }
        self.with_region(ctx, |r, scope| {
            let revs = r.daemon_task_definitions.entry(input.family.clone()).or_default();
            let revision = revs.len() as i32 + 1;
            let arn = scope.arn(&format!("daemon-task-definition/{}:{revision}", input.family));
            revs.push(t::DaemonTaskDefinition {
                daemon_task_definition_arn: Some(arn.clone()),
                family: Some(input.family.clone()),
                revision,
                task_role_arn: input.task_role_arn.clone(),
                execution_role_arn: input.execution_role_arn.clone(),
                container_definitions: Some(
                    input
                        .container_definitions
                        .iter()
                        .cloned()
                        .map(|mut c| {
                            c.essential.get_or_insert(true);
                            c
                        })
                        .collect(),
                ),
                volumes: Some(input.volumes.clone().unwrap_or_default()),
                cpu: input.cpu.clone(),
                memory: input.memory.clone(),
                status: Some("ACTIVE".into()),
                registered_at: Some(ctx.received_at),
                delete_requested_at: None,
                registered_by: Some(ctx.caller.arn.clone()),
                pid_mode: input.pid_mode.clone(),
                ipc_mode: input.ipc_mode.clone(),
            });
            tags::store(r, &arn, input.tags.as_ref());
            Ok(t::RegisterDaemonTaskDefinitionResponse { daemon_task_definition_arn: Some(arn) })
        })
    }

    pub(crate) fn describe_daemon_task_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDaemonTaskDefinitionRequest,
    ) -> Result<t::DescribeDaemonTaskDefinitionResponse, ServiceError> {
        let found = self.with_region(ctx, |r, _| resolve_dtd(r, &input.daemon_task_definition).cloned());
        let arn = found.as_ref().and_then(|d| d.daemon_task_definition_arn.clone()).unwrap_or_else(|| "*".into());
        authorize(ctx, "DescribeDaemonTaskDefinition", &arn, Cond::new())?;
        let d = found.ok_or_else(|| client("Unable to describe daemon task definition."))?;
        Ok(t::DescribeDaemonTaskDefinitionResponse { daemon_task_definition: Some(d) })
    }

    pub(crate) fn list_daemon_task_definitions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListDaemonTaskDefinitionsRequest,
    ) -> Result<t::ListDaemonTaskDefinitionsResponse, ServiceError> {
        authorize(ctx, "ListDaemonTaskDefinitions", "*", Cond::new())?;
        let status = input.status.clone().unwrap_or_else(|| "ACTIVE".into());
        self.with_region(ctx, |r, _| {
            let mut out: Vec<t::DaemonTaskDefinitionSummary> = Vec::new();
            for (family, revs) in &r.daemon_task_definitions {
                if input.family.as_ref().is_some_and(|f| f != family)
                    || input.family_prefix.as_ref().is_some_and(|p| !family.starts_with(p.as_str()))
                {
                    continue;
                }
                let mut chosen: Vec<&t::DaemonTaskDefinition> =
                    revs.iter().filter(|d| status == "ALL" || d.status.as_deref() == Some(status.as_str())).collect();
                if input.revision.as_deref() == Some("LAST_REGISTERED") {
                    chosen = chosen.into_iter().last().into_iter().collect();
                }
                out.extend(chosen.into_iter().map(|d| t::DaemonTaskDefinitionSummary {
                    arn: d.daemon_task_definition_arn.clone(),
                    registered_at: d.registered_at,
                    registered_by: d.registered_by.clone(),
                    delete_requested_at: d.delete_requested_at,
                    status: d.status.clone(),
                }));
            }
            if input.sort.as_deref() == Some("DESC") {
                out.reverse();
            }
            let (page, next_token) = paginate(&out, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListDaemonTaskDefinitionsResponse { daemon_task_definitions: Some(page), next_token })
        })
    }

    pub(crate) fn delete_daemon_task_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDaemonTaskDefinitionRequest,
    ) -> Result<t::DeleteDaemonTaskDefinitionResponse, ServiceError> {
        let (family, rev) = parse_dtd(&input.daemon_task_definition);
        let Some(rev) = rev else {
            return Err(client("A daemon task definition revision must be specified."));
        };
        let scope = Scope::of(ctx);
        let arn = scope.arn(&format!("daemon-task-definition/{family}:{rev}"));
        let t_ = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(ctx, "DeleteDaemonTaskDefinition", &arn, Cond::new().extend(resource_tags(t_.as_ref())))?;
        self.with_region(ctx, |r, _| {
            if r.daemons.values().any(|d| {
                d.status == "ACTIVE"
                    && r.daemon_revisions.get(&d.revision_arn).and_then(|x| x.daemon_task_definition_arn.as_deref())
                        == Some(arn.as_str())
            }) {
                return Err(client("The daemon task definition is in use by a daemon."));
            }
            let d = r
                .daemon_task_definitions
                .get_mut(&family)
                .and_then(|revs| revs.iter_mut().find(|d| d.revision == rev))
                .ok_or_else(|| client("The specified daemon task definition does not exist."))?;
            d.status = Some("DELETE_IN_PROGRESS".into());
            d.delete_requested_at = Some(ctx.received_at);
            Ok(t::DeleteDaemonTaskDefinitionResponse { daemon_task_definition_arn: Some(arn.clone()) })
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn daemon_revision(
        r: &mut Region,
        scope: &Scope,
        cluster: &str,
        name: &str,
        daemon_arn: &str,
        dtd: &str,
        input_flags: (Option<String>, bool, bool, Option<bool>),
        now: chrono::DateTime<chrono::Utc>,
    ) -> String {
        let arn = scope.arn(&format!("daemon-revision/{cluster}/{name}/{}", numeric_id()));
        let images = resolve_dtd(r, dtd)
            .map(|d| {
                d.container_definitions
                    .iter()
                    .flatten()
                    .map(|c| t::DaemonContainerImage {
                        container_name: c.name.clone(),
                        image: Some(c.image.clone()),
                        image_digest: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        r.daemon_revisions.insert(
            arn.clone(),
            t::DaemonRevision {
                daemon_revision_arn: Some(arn.clone()),
                cluster_arn: Some(scope.cluster_arn(cluster)),
                daemon_arn: Some(daemon_arn.to_string()),
                daemon_task_definition_arn: Some(dtd.to_string()),
                created_at: Some(now),
                container_images: Some(images),
                propagate_tags: input_flags.0,
                enable_ecs_managed_tags: Some(input_flags.1),
                enable_execute_command: Some(input_flags.2),
                critical: input_flags.3,
            },
        );
        arn
    }

    #[allow(clippy::too_many_arguments)]
    fn daemon_deployment(
        r: &mut Region,
        scope: &Scope,
        cluster: &str,
        name: &str,
        target: &str,
        source: Option<&str>,
        config: Option<t::DaemonDeploymentConfiguration>,
        providers: &[String],
        now: chrono::DateTime<chrono::Utc>,
    ) -> String {
        let arn = scope.arn(&format!("daemon-deployment/{cluster}/{name}/{}", crate::names::short_id()));
        let detail = |rev: &str| t::DaemonDeploymentRevisionDetail {
            arn: Some(rev.to_string()),
            capacity_providers: Some(
                providers
                    .iter()
                    .map(|p| t::DaemonDeploymentCapacityProvider {
                        arn: Some(p.clone()),
                        running_instance_count: Some(0),
                        without_daemon_instance_count: Some(0),
                        draining_instance_count: Some(0),
                    })
                    .collect(),
            ),
            total_running_instance_count: Some(0),
            total_without_daemon_instance_count: Some(0),
            total_draining_instance_count: Some(0),
        };
        r.daemon_deployments.insert(
            arn.clone(),
            t::DaemonDeployment {
                daemon_deployment_arn: Some(arn.clone()),
                cluster_arn: Some(scope.cluster_arn(cluster)),
                status: Some("SUCCESSFUL".into()),
                status_reason: None,
                target_daemon_revision: Some(detail(target)),
                source_daemon_revisions: Some(source.map(detail).into_iter().collect()),
                circuit_breaker: Some(t::DaemonCircuitBreaker {
                    failure_count: 0,
                    status: Some("MONITORING_COMPLETE".into()),
                    threshold: 3,
                }),
                alarms: Some(t::DaemonDeploymentAlarms { status: Some("DISABLED".into()), ..Default::default() }),
                rollback: None,
                deployment_configuration: config,
                created_at: Some(now),
                started_at: Some(now),
                stopped_at: None,
                finished_at: Some(now),
            },
        );
        arn
    }

    pub(crate) fn create_daemon_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDaemonRequest,
    ) -> Result<t::CreateDaemonResponse, ServiceError> {
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        if input.capacity_provider_arns.is_empty() {
            return Err(invalid("capacityProviderArns must contain at least one capacity provider."));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster_arn.as_deref());
        let arn = scope.arn(&format!("daemon/{cluster}/{}", input.daemon_name));
        authorize(
            ctx,
            "CreateDaemon",
            &arn,
            Cond::new()
                .cluster(&scope, &cluster)
                .with("ecs:daemon-task-definition", input.daemon_task_definition_arn.clone())
                .extend(request_tags(input.tags.as_ref())),
        )?;
        self.authorize_create_tags(ctx, &arn, "CreateDaemon", input.tags.as_ref())?;
        let now = ctx.received_at;
        self.with_region(ctx, |r, scope| {
            clusters::active(r, Some(&cluster))?;
            if r.daemons.get(&arn).is_some_and(|d| d.status == "ACTIVE") {
                return Err(invalid("A daemon with this name already exists in the cluster."));
            }
            let dtd = resolve_dtd(r, &input.daemon_task_definition_arn)
                .and_then(|d| d.daemon_task_definition_arn.clone())
                .ok_or_else(|| client("The specified daemon task definition does not exist."))?;
            for p in &input.capacity_provider_arns {
                if crate::capacity::find(r, scope, p).is_none() {
                    return Err(invalid(format!("The specified capacity provider '{p}' does not exist.")));
                }
            }
            let flags = (
                input.propagate_tags.clone(),
                input.enable_ecs_managed_tags,
                input.enable_execute_command,
                input.critical,
            );
            let rev = Self::daemon_revision(r, scope, &cluster, &input.daemon_name, &arn, &dtd, flags, now);
            let dep = Self::daemon_deployment(
                r,
                scope,
                &cluster,
                &input.daemon_name,
                &rev,
                None,
                input.deployment_configuration.clone(),
                &input.capacity_provider_arns,
                now,
            );
            r.daemons.insert(
                arn.clone(),
                DaemonRecord {
                    arn: arn.clone(),
                    name: input.daemon_name.clone(),
                    cluster_arn: scope.cluster_arn(&cluster),
                    status: "ACTIVE".into(),
                    revision_arn: rev,
                    deployment_arn: dep.clone(),
                    capacity_provider_arns: input.capacity_provider_arns.clone(),
                    created_at: Some(now),
                    updated_at: Some(now),
                },
            );
            tags::store(r, &arn, input.tags.as_ref());
            Ok(t::CreateDaemonResponse {
                daemon_arn: Some(arn.clone()),
                status: Some("ACTIVE".into()),
                created_at: Some(now),
                deployment_arn: Some(dep),
            })
        })
    }

    fn daemon_by_arn(&self, ctx: &RequestContext, action: &str, arn: &str) -> Result<DaemonRecord, ServiceError> {
        let (rec, tags) = self.with_region(ctx, |r, _| (r.daemons.get(arn).cloned(), r.tags.get(arn).cloned()));
        authorize(ctx, action, arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        rec.ok_or_else(daemon_not_found)
    }

    pub(crate) fn describe_daemon_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDaemonRequest,
    ) -> Result<t::DescribeDaemonResponse, ServiceError> {
        let d = self.daemon_by_arn(ctx, "DescribeDaemon", &input.daemon_arn)?;
        Ok(t::DescribeDaemonResponse {
            daemon: Some(t::DaemonDetail {
                daemon_arn: Some(d.arn.clone()),
                cluster_arn: Some(d.cluster_arn.clone()),
                status: Some(d.status.clone()),
                current_revisions: Some(vec![t::DaemonRevisionDetail {
                    arn: Some(d.revision_arn.clone()),
                    capacity_providers: Some(
                        d.capacity_provider_arns
                            .iter()
                            .map(|p| t::DaemonCapacityProvider {
                                arn: Some(p.clone()),
                                running_count: 0,
                                without_daemon_count: 0,
                            })
                            .collect(),
                    ),
                    total_running_count: 0,
                    total_without_daemon_count: 0,
                }]),
                deployment_arn: Some(d.deployment_arn.clone()),
                created_at: d.created_at,
                updated_at: d.updated_at,
            }),
        })
    }

    pub(crate) fn list_daemons_op(
        &self,
        ctx: &RequestContext,
        input: t::ListDaemonsRequest,
    ) -> Result<t::ListDaemonsResponse, ServiceError> {
        authorize(ctx, "ListDaemons", "*", Cond::new())?;
        let scope = Scope::of(ctx);
        let cluster = input.cluster_arn.as_deref().map(|c| scope.cluster_arn(&cluster_name(Some(c))));
        self.with_region(ctx, |r, _| {
            let out: Vec<t::DaemonSummary> = r
                .daemons
                .values()
                .filter(|d| cluster.as_ref().is_none_or(|c| &d.cluster_arn == c))
                .filter(|d| {
                    input
                        .capacity_provider_arns
                        .as_ref()
                        .is_none_or(|ps| ps.iter().any(|p| d.capacity_provider_arns.contains(p)))
                })
                .map(|d| t::DaemonSummary {
                    daemon_arn: Some(d.arn.clone()),
                    status: Some(d.status.clone()),
                    created_at: d.created_at,
                    updated_at: d.updated_at,
                })
                .collect();
            let (page, next_token) = paginate(&out, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListDaemonsResponse { daemon_summaries_list: Some(page), next_token })
        })
    }

    pub(crate) fn update_daemon_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateDaemonRequest,
    ) -> Result<t::UpdateDaemonResponse, ServiceError> {
        let d = self.daemon_by_arn(ctx, "UpdateDaemon", &input.daemon_arn)?;
        if d.status != "ACTIVE" {
            return Err(errors::daemon_not_active("The daemon is not ACTIVE."));
        }
        let now = ctx.received_at;
        let cluster = crate::names::last_segment(&d.cluster_arn).to_string();
        self.with_region(ctx, |r, scope| {
            let dtd = resolve_dtd(r, &input.daemon_task_definition_arn)
                .and_then(|d| d.daemon_task_definition_arn.clone())
                .ok_or_else(|| client("The specified daemon task definition does not exist."))?;
            let flags = (
                input.propagate_tags.clone(),
                input.enable_ecs_managed_tags,
                input.enable_execute_command,
                input.critical,
            );
            let rev = Self::daemon_revision(r, scope, &cluster, &d.name, &d.arn, &dtd, flags, now);
            let dep = Self::daemon_deployment(
                r,
                scope,
                &cluster,
                &d.name,
                &rev,
                Some(&d.revision_arn),
                input.deployment_configuration.clone(),
                &input.capacity_provider_arns,
                now,
            );
            let rec = r.daemons.get_mut(&d.arn).ok_or_else(daemon_not_found)?;
            rec.revision_arn = rev;
            rec.deployment_arn = dep.clone();
            rec.capacity_provider_arns = input.capacity_provider_arns.clone();
            rec.updated_at = Some(now);
            Ok(t::UpdateDaemonResponse {
                daemon_arn: Some(d.arn.clone()),
                status: Some("ACTIVE".into()),
                created_at: d.created_at,
                updated_at: Some(now),
                deployment_arn: Some(dep),
            })
        })
    }

    pub(crate) fn delete_daemon_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDaemonRequest,
    ) -> Result<t::DeleteDaemonResponse, ServiceError> {
        let d = self.daemon_by_arn(ctx, "DeleteDaemon", &input.daemon_arn)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r, _| {
            let rec = r.daemons.get_mut(&d.arn).ok_or_else(daemon_not_found)?;
            rec.status = "DELETE_IN_PROGRESS".into();
            rec.updated_at = Some(now);
            Ok(t::DeleteDaemonResponse {
                daemon_arn: Some(d.arn.clone()),
                status: Some("DELETE_IN_PROGRESS".into()),
                created_at: d.created_at,
                updated_at: Some(now),
                deployment_arn: Some(d.deployment_arn.clone()),
            })
        })
    }

    pub(crate) fn describe_daemon_deployments_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDaemonDeploymentsRequest,
    ) -> Result<t::DescribeDaemonDeploymentsResponse, ServiceError> {
        let mut out = Vec::new();
        let mut failures = Vec::new();
        for arn in &input.daemon_deployment_arns {
            authorize(ctx, "DescribeDaemonDeployments", arn, Cond::new())?;
            match self.with_region(ctx, |r, _| r.daemon_deployments.get(arn).cloned()) {
                Some(d) => out.push(d),
                None => failures.push(failure(arn.clone(), "MISSING")),
            }
        }
        Ok(t::DescribeDaemonDeploymentsResponse { failures: Some(failures), daemon_deployments: Some(out) })
    }

    pub(crate) fn list_daemon_deployments_op(
        &self,
        ctx: &RequestContext,
        input: t::ListDaemonDeploymentsRequest,
    ) -> Result<t::ListDaemonDeploymentsResponse, ServiceError> {
        let d = self.daemon_by_arn(ctx, "ListDaemonDeployments", &input.daemon_arn)?;
        let prefix = d.arn.replacen(":daemon/", ":daemon-deployment/", 1) + "/";
        self.with_region(ctx, |r, _| {
            let mut deps: Vec<&t::DaemonDeployment> = r
                .daemon_deployments
                .iter()
                .filter(|(a, _)| a.starts_with(&prefix))
                .map(|(_, d)| d)
                .filter(|x| input.status.as_ref().is_none_or(|s| s.contains(&x.status.clone().unwrap_or_default())))
                .collect();
            deps.sort_by_key(|d| std::cmp::Reverse(d.created_at));
            let out: Vec<t::DaemonDeploymentSummary> = deps
                .into_iter()
                .map(|x| t::DaemonDeploymentSummary {
                    daemon_deployment_arn: x.daemon_deployment_arn.clone(),
                    daemon_arn: Some(d.arn.clone()),
                    cluster_arn: x.cluster_arn.clone(),
                    status: x.status.clone(),
                    status_reason: x.status_reason.clone(),
                    target_daemon_revision_arn: x.target_daemon_revision.as_ref().and_then(|t| t.arn.clone()),
                    created_at: x.created_at,
                    started_at: x.started_at,
                    stopped_at: x.stopped_at,
                    finished_at: x.finished_at,
                })
                .collect();
            let (page, next_token) = paginate(&out, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListDaemonDeploymentsResponse { next_token, daemon_deployments: Some(page) })
        })
    }

    pub(crate) fn describe_daemon_revisions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDaemonRevisionsRequest,
    ) -> Result<t::DescribeDaemonRevisionsResponse, ServiceError> {
        let mut out = Vec::new();
        let mut failures = Vec::new();
        for arn in &input.daemon_revision_arns {
            authorize(ctx, "DescribeDaemonRevisions", arn, Cond::new())?;
            match self.with_region(ctx, |r, _| r.daemon_revisions.get(arn).cloned()) {
                Some(d) => out.push(d),
                None => failures.push(failure(arn.clone(), "MISSING")),
            }
        }
        Ok(t::DescribeDaemonRevisionsResponse { daemon_revisions: Some(out), failures: Some(failures) })
    }
}
