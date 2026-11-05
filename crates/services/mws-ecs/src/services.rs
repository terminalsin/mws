//! Services: CreateService, UpdateService (with new deployments when the
//! task configuration changes), DeleteService, service deployments and
//! revisions, and task sets for the EXTERNAL deployment controller. The
//! scheduler (see `scheduler.rs`) keeps them at their desired count.

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types as t};
use crate::names::{
    authorize, check_tags, cluster_name, failure, invalid, last_segment, numeric_id, paginate, request_tags,
    resource_tags, service_not_found, short_id, split_arn, Cond, Scope,
};
use crate::state::{Region, ServiceRecord};
use crate::{capacity, clusters, taskdefs, tasks, Ecs};

pub fn service_arn(scope: &Scope, cluster: &str, name: &str) -> String {
    scope.arn(&format!("service/{cluster}/{name}"))
}

/// Settle deleted services whose tasks are all gone.
pub fn settle(r: &mut Region, now: DateTime<Utc>) {
    let live: Vec<String> = r
        .tasks
        .values()
        .filter(|t| t.task.last_status.as_deref() != Some("STOPPED"))
        .filter_map(|t| t.service_arn.clone())
        .collect();
    for (arn, s) in r.services.iter_mut() {
        if s.service.status.as_deref() == Some("DRAINING") && !live.contains(arn) {
            s.service.status = Some("INACTIVE".into());
            s.inactive_at = Some(now);
            for d in s.service.deployments.iter_mut().flatten() {
                d.status = Some("INACTIVE".into());
            }
            s.service.deployments = Some(Vec::new());
        }
    }
}

fn default_deployment_configuration(c: Option<t::DeploymentConfiguration>, daemon: bool) -> t::DeploymentConfiguration {
    let mut c = c.unwrap_or_default();
    c.maximum_percent.get_or_insert(if daemon { 100 } else { 200 });
    c.minimum_healthy_percent.get_or_insert(if daemon { 0 } else { 100 });
    c.deployment_circuit_breaker.get_or_insert(t::DeploymentCircuitBreaker {
        enable: false,
        rollback: false,
        ..Default::default()
    });
    c.strategy.get_or_insert_with(|| "ROLLING".into());
    c
}

/// The circuit breaker's failure threshold for a desired count.
pub fn breaker_threshold(desired: i32) -> i32 {
    ((desired + 1) / 2).clamp(3, 200)
}

fn ev(message: String, now: DateTime<Utc>) -> t::ServiceEvent {
    t::ServiceEvent { id: Some(uuid::Uuid::new_v4().to_string()), created_at: Some(now), message: Some(message) }
}

/// Add a service event (newest first, at most 100, no immediate repeats).
pub fn push_event(s: &mut t::Service, message: String, now: DateTime<Utc>) {
    let events = s.events.get_or_insert_with(Vec::new);
    if events.first().and_then(|e| e.message.as_deref()) == Some(message.as_str()) {
        return;
    }
    events.insert(0, ev(message, now));
    events.truncate(100);
}

/// What a service deployment's configuration looks like: the parts of a
/// service that make up a revision.
#[derive(Debug, Clone, Default)]
pub struct RevisionConfig {
    pub task_definition: String,
    pub launch_type: Option<String>,
    pub capacity_provider_strategy: Vec<t::CapacityProviderStrategyItem>,
    pub platform_version: Option<String>,
    pub network_configuration: Option<t::NetworkConfiguration>,
    pub load_balancers: Vec<t::LoadBalancer>,
    pub service_registries: Vec<t::ServiceRegistry>,
    pub service_connect_configuration: Option<t::ServiceConnectConfiguration>,
    pub volume_configurations: Option<Vec<t::ServiceVolumeConfiguration>>,
    pub vpc_lattice_configurations: Option<Vec<t::VpcLatticeConfiguration>>,
    pub gateway_connectors: Option<Vec<t::GatewayConnector>>,
    pub monitoring: Option<t::MonitoringConfiguration>,
}

impl Ecs {
    /// Start a new deployment of `config`: a service revision, a PRIMARY
    /// deployment, and a service deployment tracking the rollout.
    pub(crate) fn new_deployment(
        &self,
        r: &mut Region,
        scope: &Scope,
        rec_arn: &str,
        config: RevisionConfig,
        now: DateTime<Utc>,
        rollback_of: Option<String>,
    ) {
        let def = taskdefs::resolve(r, &config.task_definition).cloned();
        let Some(rec) = r.services.get(rec_arn) else { return };
        let cluster = rec.cluster.clone();
        let name = rec.service.service_name.clone().unwrap_or_default();
        let fargate = config.launch_type.as_deref() == Some("FARGATE")
            || config
                .capacity_provider_strategy
                .iter()
                .any(|i| capacity::BUILT_IN.contains(&i.capacity_provider.as_str()));
        let platform_version = fargate.then(|| config.platform_version.clone().unwrap_or_else(|| "LATEST".into()));
        let revision_arn = scope.arn(&format!("service-revision/{cluster}/{name}/{}", numeric_id()));
        let revision = t::ServiceRevision {
            service_revision_arn: Some(revision_arn.clone()),
            service_arn: Some(rec_arn.to_string()),
            cluster_arn: Some(scope.cluster_arn(&cluster)),
            task_definition: Some(config.task_definition.clone()),
            capacity_provider_strategy: (!config.capacity_provider_strategy.is_empty())
                .then(|| config.capacity_provider_strategy.clone()),
            launch_type: config.launch_type.clone(),
            platform_version: platform_version.clone(),
            platform_family: fargate.then(|| "Linux".into()),
            load_balancers: Some(config.load_balancers.clone()),
            service_registries: Some(config.service_registries.clone()),
            network_configuration: config.network_configuration.clone(),
            container_images: Some(
                def.iter()
                    .flat_map(|d| d.container_definitions.iter().flatten())
                    .map(|c| t::ContainerImage {
                        container_name: c.name.clone(),
                        image: c.image.clone(),
                        image_digest: None,
                    })
                    .collect(),
            ),
            guard_duty_enabled: false,
            service_connect_configuration: config.service_connect_configuration.clone(),
            volume_configurations: config.volume_configurations.clone(),
            created_at: Some(now),
            vpc_lattice_configurations: config.vpc_lattice_configurations.clone(),
            gateway_connectors: config.gateway_connectors.clone(),
            monitoring: config.monitoring.clone(),
            ..Default::default()
        };
        r.service_revisions.insert(revision_arn.clone(), revision);
        let rec = r.services.get_mut(rec_arn).expect("checked above");
        let deployment_id = format!("ecs-svc/{}", numeric_id());
        let desired = rec.service.desired_count;
        let source_revisions: Vec<t::ServiceRevisionSummary> = rec
            .service
            .deployments
            .iter()
            .flatten()
            .filter_map(|d| {
                Some(t::ServiceRevisionSummary {
                    arn: rec.deployment_revisions.get(d.id.as_ref()?).cloned(),
                    requested_task_count: d.desired_count,
                    running_task_count: d.running_count,
                    pending_task_count: d.pending_count,
                    ..Default::default()
                })
            })
            .collect();
        let deployments = rec.service.deployments.get_or_insert_with(Vec::new);
        for d in deployments.iter_mut() {
            if d.status.as_deref() == Some("PRIMARY") {
                d.status = Some("ACTIVE".into());
                d.updated_at = Some(now);
            }
        }
        deployments.insert(
            0,
            t::Deployment {
                id: Some(deployment_id.clone()),
                status: Some("PRIMARY".into()),
                task_definition: Some(config.task_definition.clone()),
                desired_count: desired,
                pending_count: 0,
                running_count: 0,
                failed_tasks: 0,
                created_at: Some(now),
                updated_at: Some(now),
                capacity_provider_strategy: (!config.capacity_provider_strategy.is_empty())
                    .then(|| config.capacity_provider_strategy.clone()),
                launch_type: config.launch_type.clone(),
                platform_version: platform_version.clone(),
                platform_family: fargate.then(|| "Linux".into()),
                network_configuration: config.network_configuration.clone(),
                rollout_state: Some("IN_PROGRESS".into()),
                rollout_state_reason: Some(format!("ECS deployment {deployment_id} in progress.")),
                service_connect_configuration: config.service_connect_configuration.clone(),
                volume_configurations: config.volume_configurations.clone(),
                vpc_lattice_configurations: config.vpc_lattice_configurations.clone(),
                ..Default::default()
            },
        );
        rec.deployment_revisions.insert(deployment_id.clone(), revision_arn.clone());
        rec.failed_launches = 0;
        rec.service.task_definition = Some(config.task_definition.clone());
        rec.service.launch_type = config.launch_type.clone();
        rec.service.capacity_provider_strategy =
            (!config.capacity_provider_strategy.is_empty()).then(|| config.capacity_provider_strategy.clone());
        rec.service.platform_version = platform_version;
        rec.service.platform_family = fargate.then(|| "Linux".into());
        rec.service.network_configuration = config.network_configuration.clone();
        rec.service.load_balancers = Some(config.load_balancers.clone());
        rec.service.service_registries = Some(config.service_registries.clone());
        let conf = rec.service.deployment_configuration.clone().unwrap_or_default();
        let breaker = conf.deployment_circuit_breaker.clone().unwrap_or_default();
        // A rollback continues the current service deployment.
        if let Some(reason) = rollback_of {
            if let Some(sd) = rec.current_deployment_arn.clone().and_then(|a| r.service_deployments.get_mut(&a)) {
                sd.status = Some("ROLLBACK_IN_PROGRESS".into());
                sd.updated_at = Some(now);
                sd.rollback = Some(t::Rollback {
                    reason: Some(reason),
                    started_at: Some(now),
                    service_revision_arn: Some(revision_arn.clone()),
                });
            }
            return;
        }
        // The previous deployment finishes as superseded.
        if let Some(prev) = rec.current_deployment_arn.clone() {
            if let Some(sd) = r.service_deployments.get_mut(&prev) {
                if matches!(sd.status.as_deref(), Some("PENDING" | "IN_PROGRESS")) {
                    sd.status = Some("STOPPED".into());
                    sd.status_reason = Some("Service deployment was superseded by a new deployment.".into());
                    sd.stopped_at = Some(now);
                    sd.updated_at = Some(now);
                }
            }
        }
        let sd_arn = scope.arn(&format!("service-deployment/{cluster}/{name}/{}", short_id()));
        let sd = t::ServiceDeployment {
            service_deployment_arn: Some(sd_arn.clone()),
            service_arn: Some(rec_arn.to_string()),
            cluster_arn: Some(scope.cluster_arn(&cluster)),
            created_at: Some(now),
            started_at: Some(now),
            updated_at: Some(now),
            source_service_revisions: Some(source_revisions),
            target_service_revision: Some(t::ServiceRevisionSummary {
                arn: Some(revision_arn.clone()),
                requested_task_count: desired,
                ..Default::default()
            }),
            status: Some("IN_PROGRESS".into()),
            status_reason: None,
            lifecycle_stage: Some("RECONCILE_SERVICE".into()),
            deployment_configuration: Some(conf.clone()),
            deployment_circuit_breaker: Some(t::ServiceDeploymentCircuitBreaker {
                status: Some(if breaker.enable { "MONITORING" } else { "DISABLED" }.into()),
                failure_count: 0,
                threshold: breaker_threshold(desired),
            }),
            alarms: Some(t::ServiceDeploymentAlarms {
                status: Some(
                    if conf.alarms.as_ref().is_some_and(|a| a.enable) { "MONITORING" } else { "DISABLED" }.into(),
                ),
                alarm_names: conf.alarms.as_ref().map(|a| a.alarm_names.clone()),
                triggered_alarm_names: Some(Vec::new()),
            }),
            ..Default::default()
        };
        r.service_deployments.insert(sd_arn.clone(), sd);
        let rec = r.services.get_mut(rec_arn).expect("checked above");
        rec.current_deployment_arn = Some(sd_arn.clone());
        rec.service.current_service_deployment = Some(sd_arn);
    }

    /// Resolve and check the capacity, task definition and network parts
    /// of a service request against the cluster.
    #[allow(clippy::too_many_arguments)]
    fn check_service_capacity(
        &self,
        r: &Region,
        scope: &Scope,
        cluster: &t::Cluster,
        def: Option<&t::TaskDefinition>,
        launch_type: Option<&str>,
        strategy: Option<&[t::CapacityProviderStrategyItem]>,
        network: Option<&t::NetworkConfiguration>,
    ) -> Result<(Option<String>, Vec<t::CapacityProviderStrategyItem>), ServiceError> {
        let (lt, strategy) = tasks::resolve_capacity(r, scope, cluster, launch_type, strategy)?;
        if let Some(def) = def {
            match &lt {
                Some(lt) => tasks::check_launch(def, lt, network)?,
                None => {
                    for item in &strategy {
                        let lt =
                            tasks::launch_type_of_provider(r, scope, &capacity::provider_name(&item.capacity_provider));
                        tasks::check_launch(def, &lt, network)?;
                    }
                }
            }
        }
        Ok((lt, strategy))
    }

    pub(crate) fn create_service_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateServiceRequest,
    ) -> Result<t::CreateServiceResponse, ServiceError> {
        let name = input.service_name.clone();
        if name.is_empty()
            || name.len() > 255
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(invalid(
                "Service name can only contain letters (uppercase and lowercase), numbers, hyphens (-), and underscores (_).",
            ));
        }
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let arn = service_arn(&scope, &cluster, &name);
        let controller = input.deployment_controller.as_ref().map(|c| c.r#type.clone()).unwrap_or_else(|| "ECS".into());
        let daemon = input.scheduling_strategy.as_deref() == Some("DAEMON");
        let (def, cluster_obj) = self.with_region(ctx, |r, _| {
            let c = clusters::active(r, input.cluster.as_deref())?.clone();
            let d = match input.task_definition.as_deref() {
                Some(td) => Some(
                    taskdefs::resolve(r, td)
                        .filter(|d| d.status.as_deref() != Some("DELETE_IN_PROGRESS"))
                        .cloned()
                        .ok_or_else(|| crate::names::client("TaskDefinition not found."))?,
                ),
                None => None,
            };
            Ok::<_, ServiceError>((d, c))
        })?;
        let providers: Vec<String> = input
            .capacity_provider_strategy
            .iter()
            .flatten()
            .map(|i| capacity::provider_name(&i.capacity_provider))
            .collect();
        let awsvpc = input.network_configuration.as_ref().and_then(|n| n.awsvpc_configuration.as_ref());
        authorize(
            ctx,
            "CreateService",
            &arn,
            Cond::new()
                .cluster(&scope, &cluster)
                .with_opt("ecs:task-definition", def.as_ref().and_then(|d| d.task_definition_arn.as_deref()))
                .with_opt("ecs:task-cpu", def.as_ref().and_then(|d| d.cpu.as_deref()))
                .with_opt("ecs:task-memory", def.as_ref().and_then(|d| d.memory.as_deref()))
                .with_list("ecs:capacity-provider", providers)
                .with("ecs:enable-execute-command", input.enable_execute_command.to_string())
                .with("ecs:enable-ecs-managed-tags", input.enable_ecs_managed_tags.to_string())
                .with_opt("ecs:propagate-tags", input.propagate_tags.as_deref())
                .with_list("ecs:subnet", awsvpc.map(|a| a.subnets.clone()).unwrap_or_default())
                .with_opt("ecs:auto-assign-public-ip", awsvpc.and_then(|a| a.assign_public_ip.as_deref()))
                .with(
                    "ecs:enable-service-connect",
                    input.service_connect_configuration.as_ref().is_some_and(|s| s.enabled).to_string(),
                )
                .extend(request_tags(input.tags.as_ref())),
        )?;
        if let Some(role) = &input.role {
            ctx.authorize("iam:PassRole", role, mws_core::ConditionContext::new()).map_err(crate::names::ecs_denial)?;
        }
        self.authorize_create_tags(ctx, &arn, "CreateService", input.tags.as_ref())?;
        if controller != "EXTERNAL" && def.is_none() {
            return Err(invalid("TaskDefinition must be specified."));
        }
        if !daemon && controller == "ECS" && input.desired_count.is_none() {
            return Err(invalid(
                "The desiredCount parameter is required for services using the REPLICA scheduling strategy.",
            ));
        }
        if daemon && input.desired_count.is_some_and(|d| d != 0) && input.desired_count.is_some() {
            return Err(invalid("Desired count is not supported with scheduling strategy DAEMON."));
        }
        if daemon && controller != "ECS" {
            return Err(invalid(
                "The daemon scheduling strategy is only supported with the ECS deployment controller.",
            ));
        }
        if input.desired_count.is_some_and(|d| d < 0) {
            return Err(invalid("desiredCount must be greater than or equal to 0."));
        }
        if let Some(c) = &input.deployment_configuration {
            if let (Some(max), Some(min)) = (c.maximum_percent, c.minimum_healthy_percent) {
                if max <= min && !(daemon && max == 100) {
                    return Err(invalid("maximumPercent must be greater than minimumHealthyPercent."));
                }
            }
        }
        if input.launch_type.as_deref() == Some("FARGATE") && daemon {
            return Err(invalid("The daemon scheduling strategy is not supported for the FARGATE launch type."));
        }
        let now = ctx.received_at;
        let me = self.clone();
        let out = self.with_region(ctx, |r, scope| {
            if let Some(existing) = r.services.get(&arn) {
                match existing.service.status.as_deref() {
                    Some("ACTIVE") => {
                        if input.client_token.is_some() && existing.client_token == input.client_token {
                            return Ok(render(r, existing, false));
                        }
                        return Err(invalid("Creation of service was not idempotent."));
                    }
                    Some("DRAINING") => return Err(invalid("Unable to Start a service that is still Draining.")),
                    _ => {}
                }
            }
            let (lt, strategy) =
                if def.is_some() || input.launch_type.is_some() || input.capacity_provider_strategy.is_some() {
                    me.check_service_capacity(
                        r,
                        scope,
                        &cluster_obj,
                        def.as_ref(),
                        input.launch_type.as_deref(),
                        input.capacity_provider_strategy.as_deref(),
                        input.network_configuration.as_ref(),
                    )?
                } else {
                    (None, Vec::new())
                };
            let deployment_configuration =
                default_deployment_configuration(input.deployment_configuration.clone(), daemon);
            let service = t::Service {
                service_arn: Some(arn.clone()),
                service_name: Some(name.clone()),
                cluster_arn: Some(scope.cluster_arn(&cluster)),
                load_balancers: Some(input.load_balancers.clone().unwrap_or_default()),
                service_registries: Some(input.service_registries.clone().unwrap_or_default()),
                status: Some("ACTIVE".into()),
                desired_count: input.desired_count.unwrap_or(0),
                running_count: 0,
                pending_count: 0,
                launch_type: lt.clone(),
                capacity_provider_strategy: (!strategy.is_empty()).then(|| strategy.clone()),
                task_definition: def.as_ref().and_then(|d| d.task_definition_arn.clone()),
                deployment_configuration: Some(deployment_configuration),
                task_sets: (controller != "ECS").then(Vec::new),
                deployments: Some(Vec::new()),
                role_arn: input.role.clone(),
                events: Some(Vec::new()),
                created_at: Some(now),
                placement_constraints: Some(input.placement_constraints.clone().unwrap_or_default()),
                placement_strategy: Some(input.placement_strategy.clone().unwrap_or_default()),
                network_configuration: input.network_configuration.clone(),
                health_check_grace_period_seconds: input.health_check_grace_period_seconds,
                scheduling_strategy: Some(if daemon { "DAEMON" } else { "REPLICA" }.into()),
                deployment_controller: Some(t::DeploymentController { r#type: controller.clone() }),
                created_by: Some(crate::settings::caller_principal(ctx, scope)),
                enable_ecs_managed_tags: input.enable_ecs_managed_tags,
                propagate_tags: Some(input.propagate_tags.clone().unwrap_or_else(|| "NONE".into())),
                enable_execute_command: input.enable_execute_command,
                availability_zone_rebalancing: Some(
                    input.availability_zone_rebalancing.clone().unwrap_or_else(|| "ENABLED".into()),
                ),
                resource_management_type: Some("CUSTOMER".into()),
                ..Default::default()
            };
            r.tags.remove(&arn);
            crate::tags::store(r, &arn, input.tags.as_ref());
            r.services.insert(
                arn.clone(),
                ServiceRecord {
                    service,
                    cluster: cluster.clone(),
                    client_token: input.client_token.clone(),
                    ..Default::default()
                },
            );
            match controller.as_str() {
                "ECS" => {
                    let config = RevisionConfig {
                        task_definition: def.as_ref().and_then(|d| d.task_definition_arn.clone()).unwrap_or_default(),
                        launch_type: lt,
                        capacity_provider_strategy: strategy,
                        platform_version: input.platform_version.clone(),
                        network_configuration: input.network_configuration.clone(),
                        load_balancers: input.load_balancers.clone().unwrap_or_default(),
                        service_registries: input.service_registries.clone().unwrap_or_default(),
                        service_connect_configuration: input.service_connect_configuration.clone(),
                        volume_configurations: input.volume_configurations.clone(),
                        vpc_lattice_configurations: input.vpc_lattice_configurations.clone(),
                        gateway_connectors: input.gateway_connectors.clone(),
                        monitoring: input.monitoring.clone(),
                    };
                    me.new_deployment(r, scope, &arn, config, now, None);
                }
                "CODE_DEPLOY" => {
                    // CodeDeploy services start with one primary task set.
                    let set = new_task_set(
                        r,
                        scope,
                        &arn,
                        TaskSetInput {
                            external_id: None,
                            task_definition: def
                                .as_ref()
                                .and_then(|d| d.task_definition_arn.clone())
                                .unwrap_or_default(),
                            network_configuration: input.network_configuration.clone(),
                            load_balancers: input.load_balancers.clone(),
                            service_registries: input.service_registries.clone(),
                            launch_type: lt,
                            capacity_provider_strategy: (!strategy.is_empty()).then_some(strategy),
                            platform_version: input.platform_version.clone(),
                            scale: None,
                            started_by: Some("CodeDeploy".into()),
                        },
                        now,
                    );
                    let s = r.services.get_mut(&arn).expect("just inserted");
                    for ts in s.service.task_sets.iter_mut().flatten() {
                        if ts.id == set.id {
                            ts.status = Some("PRIMARY".into());
                        }
                    }
                }
                _ => {}
            }
            Ok(render(r, &r.services[&arn], false))
        })?;
        self.kick();
        Ok(t::CreateServiceResponse { service: Some(out) })
    }

    pub(crate) fn describe_services_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeServicesRequest,
    ) -> Result<t::DescribeServicesResponse, ServiceError> {
        if input.services.is_empty() || input.services.len() > 10 {
            return Err(invalid("services must contain between 1 and 10 services."));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        self.with_region(ctx, |r, _| clusters::active(r, input.cluster.as_deref()).map(drop))?;
        let with_tags = input.include.iter().flatten().any(|i| i == "TAGS");
        let mut out = Vec::new();
        let mut failures = Vec::new();
        for reference in &input.services {
            let arn = service_arn(&scope, &cluster, last_segment(reference));
            let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
            authorize(
                ctx,
                "DescribeServices",
                &arn,
                Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())),
            )?;
            self.with_region(ctx, |r, _| match r.services.get(&arn) {
                Some(s) => out.push(render(r, s, with_tags)),
                None => failures.push(failure(arn.clone(), "MISSING")),
            });
        }
        Ok(t::DescribeServicesResponse { services: Some(out), failures: Some(failures) })
    }

    pub(crate) fn list_services_op(
        &self,
        ctx: &RequestContext,
        input: t::ListServicesRequest,
    ) -> Result<t::ListServicesResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        authorize(ctx, "ListServices", "*", Cond::new().cluster(&scope, &cluster))?;
        self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            let arns: Vec<String> = r
                .services
                .values()
                .filter(|s| s.cluster == cluster && s.service.status.as_deref() != Some("INACTIVE"))
                .filter(|s| input.launch_type.as_deref().is_none_or(|l| s.service.launch_type.as_deref() == Some(l)))
                .filter(|s| {
                    input
                        .scheduling_strategy
                        .as_deref()
                        .is_none_or(|st| s.service.scheduling_strategy.as_deref() == Some(st))
                })
                .filter(|s| {
                    input
                        .resource_management_type
                        .as_deref()
                        .is_none_or(|m| s.service.resource_management_type.as_deref() == Some(m))
                })
                .filter_map(|s| s.service.service_arn.clone())
                .collect();
            let (page, next_token) = paginate(&arns, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListServicesResponse { service_arns: Some(page), next_token })
        })
    }

    pub(crate) fn list_services_by_namespace_op(
        &self,
        ctx: &RequestContext,
        input: t::ListServicesByNamespaceRequest,
    ) -> Result<t::ListServicesByNamespaceResponse, ServiceError> {
        authorize(ctx, "ListServicesByNamespace", "*", Cond::new().with("ecs:namespace", input.namespace.clone()))?;
        self.with_region(ctx, |r, _| {
            let wanted = |ns: &str| ns == input.namespace || last_segment(ns) == last_segment(&input.namespace);
            let arns: Vec<String> = r
                .services
                .values()
                .filter(|s| s.service.status.as_deref() == Some("ACTIVE"))
                .filter(|s| {
                    s.service.deployments.iter().flatten().any(|d| {
                        d.service_connect_configuration
                            .as_ref()
                            .is_some_and(|c| c.enabled && c.namespace.as_deref().is_some_and(wanted))
                    }) || r.clusters.get(&s.cluster).is_some_and(|c| {
                        c.service_connect_defaults.as_ref().and_then(|d| d.namespace.as_deref()).is_some_and(wanted)
                            && s.service.deployments.iter().flatten().any(|d| {
                                d.service_connect_configuration
                                    .as_ref()
                                    .is_some_and(|c| c.enabled && c.namespace.is_none())
                            })
                    })
                })
                .filter_map(|s| s.service.service_arn.clone())
                .collect();
            let (page, next_token) = paginate(&arns, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListServicesByNamespaceResponse { service_arns: Some(page), next_token })
        })
    }

    pub(crate) fn update_service_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateServiceRequest,
    ) -> Result<t::UpdateServiceResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let arn = service_arn(&scope, &cluster, last_segment(&input.service));
        let (tags, new_def, cluster_obj) = self.with_region(ctx, |r, _| {
            let c = clusters::active(r, input.cluster.as_deref())?.clone();
            let d = match input.task_definition.as_deref() {
                Some(td) => Some(
                    taskdefs::resolve(r, td)
                        .filter(|d| d.status.as_deref() != Some("DELETE_IN_PROGRESS"))
                        .cloned()
                        .ok_or_else(|| crate::names::client("TaskDefinition not found."))?,
                ),
                None => None,
            };
            Ok::<_, ServiceError>((r.tags.get(&arn).cloned(), d, c))
        })?;
        let awsvpc = input.network_configuration.as_ref().and_then(|n| n.awsvpc_configuration.as_ref());
        authorize(
            ctx,
            "UpdateService",
            &arn,
            Cond::new()
                .cluster(&scope, &cluster)
                .with_opt("ecs:task-definition", new_def.as_ref().and_then(|d| d.task_definition_arn.as_deref()))
                .with_list(
                    "ecs:capacity-provider",
                    input
                        .capacity_provider_strategy
                        .iter()
                        .flatten()
                        .map(|i| capacity::provider_name(&i.capacity_provider))
                        .collect(),
                )
                .with_opt("ecs:enable-execute-command", input.enable_execute_command.map(|b| b.to_string()).as_deref())
                .with_list("ecs:subnet", awsvpc.map(|a| a.subnets.clone()).unwrap_or_default())
                .extend(resource_tags(tags.as_ref())),
        )?;
        let now = ctx.received_at;
        let me = self.clone();
        let out = self.with_region(ctx, |r, scope| {
            let rec = r.services.get(&arn).ok_or_else(service_not_found)?;
            if rec.service.status.as_deref() != Some("ACTIVE") {
                return Err(errors::service_not_active("Service was not ACTIVE."));
            }
            let controller = rec.service.deployment_controller.as_ref().map(|c| c.r#type.clone()).unwrap_or_else(|| "ECS".into());
            let daemon = rec.service.scheduling_strategy.as_deref() == Some("DAEMON");
            if controller == "CODE_DEPLOY" && (input.task_definition.is_some() || input.network_configuration.is_some()) {
                return Err(invalid(
                    "Unable to update task definition on services with a CODE_DEPLOY deployment controller. Use AWS CodeDeploy to trigger a new deployment.",
                ));
            }
            if daemon && input.desired_count.is_some() {
                return Err(invalid("Desired count is not supported with scheduling strategy DAEMON."));
            }
            if input.desired_count.is_some_and(|d| d < 0) {
                return Err(invalid("desiredCount must be greater than or equal to 0."));
            }
            let primary = rec.service.deployments.iter().flatten().find(|d| d.status.as_deref() == Some("PRIMARY")).cloned();
            let current_def = taskdefs::resolve(r, rec.service.task_definition.as_deref().unwrap_or_default()).cloned();
            let def_for_checks = new_def.clone().or(current_def);
            let changes_capacity = input.capacity_provider_strategy.is_some();
            let (lt, strategy) = if changes_capacity || input.network_configuration.is_some() || new_def.is_some() {
                let lt = if changes_capacity { None } else { rec.service.launch_type.clone() };
                let strategy = if changes_capacity {
                    input.capacity_provider_strategy.clone()
                } else {
                    rec.service.capacity_provider_strategy.clone()
                };
                let network = input.network_configuration.clone().or(rec.service.network_configuration.clone());
                me.check_service_capacity(r, scope, &cluster_obj, def_for_checks.as_ref(), lt.as_deref(), strategy.as_deref(), network.as_ref())?
            } else {
                (rec.service.launch_type.clone(), rec.service.capacity_provider_strategy.clone().unwrap_or_default())
            };
            let new_deployment = controller == "ECS"
                && (input.force_new_deployment
                    || new_def.as_ref().is_some_and(|d| d.task_definition_arn != rec.service.task_definition)
                    || input.network_configuration.is_some()
                    || changes_capacity
                    || input.platform_version.is_some()
                    || input.load_balancers.is_some()
                    || input.service_registries.is_some()
                    || input.service_connect_configuration.is_some()
                    || input.volume_configurations.is_some()
                    || input.vpc_lattice_configurations.is_some()
                    || input.enable_execute_command.is_some_and(|e| e != rec.service.enable_execute_command));
            let rec = r.services.get_mut(&arn).expect("checked above");
            let s = &mut rec.service;
            if let Some(d) = input.desired_count {
                s.desired_count = d;
                for dep in s.deployments.iter_mut().flatten() {
                    if dep.status.as_deref() == Some("PRIMARY") {
                        dep.desired_count = d;
                        dep.updated_at = Some(now);
                    }
                }
            }
            if let Some(c) = input.deployment_configuration.clone() {
                let mut merged = s.deployment_configuration.clone().unwrap_or_default();
                if c.maximum_percent.is_some() {
                    merged.maximum_percent = c.maximum_percent;
                }
                if c.minimum_healthy_percent.is_some() {
                    merged.minimum_healthy_percent = c.minimum_healthy_percent;
                }
                if c.deployment_circuit_breaker.is_some() {
                    merged.deployment_circuit_breaker = c.deployment_circuit_breaker;
                }
                if c.alarms.is_some() {
                    merged.alarms = c.alarms;
                }
                if c.strategy.is_some() {
                    merged.strategy = c.strategy;
                }
                if c.bake_time_in_minutes.is_some() {
                    merged.bake_time_in_minutes = c.bake_time_in_minutes;
                }
                if c.lifecycle_hooks.is_some() {
                    merged.lifecycle_hooks = c.lifecycle_hooks;
                }
                if c.linear_configuration.is_some() {
                    merged.linear_configuration = c.linear_configuration;
                }
                if c.canary_configuration.is_some() {
                    merged.canary_configuration = c.canary_configuration;
                }
                if c.early_success_criteria.is_some() {
                    merged.early_success_criteria = c.early_success_criteria;
                }
                s.deployment_configuration = Some(merged);
            }
            if let Some(p) = input.placement_constraints.clone() {
                s.placement_constraints = Some(p);
            }
            if let Some(p) = input.placement_strategy.clone() {
                s.placement_strategy = Some(p);
            }
            if input.health_check_grace_period_seconds.is_some() {
                s.health_check_grace_period_seconds = input.health_check_grace_period_seconds;
            }
            if let Some(e) = input.enable_execute_command {
                s.enable_execute_command = e;
            }
            if let Some(e) = input.enable_ecs_managed_tags {
                s.enable_ecs_managed_tags = e;
            }
            if let Some(p) = input.propagate_tags.clone() {
                s.propagate_tags = Some(p);
            }
            if let Some(az) = input.availability_zone_rebalancing.clone() {
                s.availability_zone_rebalancing = Some(az);
            }
            if new_deployment {
                let primary = primary.unwrap_or_default();
                let config = RevisionConfig {
                    task_definition: new_def
                        .as_ref()
                        .and_then(|d| d.task_definition_arn.clone())
                        .or(s.task_definition.clone())
                        .unwrap_or_default(),
                    launch_type: lt,
                    capacity_provider_strategy: strategy,
                    platform_version: input.platform_version.clone().or(primary.platform_version.clone()),
                    network_configuration: input.network_configuration.clone().or(s.network_configuration.clone()),
                    load_balancers: input.load_balancers.clone().or(s.load_balancers.clone()).unwrap_or_default(),
                    service_registries: input.service_registries.clone().or(s.service_registries.clone()).unwrap_or_default(),
                    service_connect_configuration: input
                        .service_connect_configuration
                        .clone()
                        .or(primary.service_connect_configuration.clone()),
                    volume_configurations: input.volume_configurations.clone().or(primary.volume_configurations.clone()),
                    vpc_lattice_configurations: input
                        .vpc_lattice_configurations
                        .clone()
                        .or(primary.vpc_lattice_configurations.clone()),
                    gateway_connectors: input.gateway_connectors.clone(),
                    monitoring: input.monitoring.clone(),
                };
                me.new_deployment(r, scope, &arn, config, now, None);
            }
            Ok(render(r, &r.services[&arn], false))
        })?;
        self.kick();
        Ok(t::UpdateServiceResponse { service: Some(out) })
    }

    pub(crate) fn delete_service_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteServiceRequest,
    ) -> Result<t::DeleteServiceResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let arn = service_arn(&scope, &cluster, last_segment(&input.service));
        let tags = self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            Ok::<_, ServiceError>(r.tags.get(&arn).cloned())
        })?;
        authorize(
            ctx,
            "DeleteService",
            &arn,
            Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())),
        )?;
        let now = ctx.received_at;
        let out = self.with_region(ctx, |r, _| {
            let rec = r.services.get_mut(&arn).ok_or_else(service_not_found)?;
            if rec.service.status.as_deref() == Some("INACTIVE") {
                return Err(errors::service_not_active("Service was not ACTIVE."));
            }
            let daemon = rec.service.scheduling_strategy.as_deref() == Some("DAEMON");
            if !daemon && rec.service.desired_count > 0 && input.force != Some(true) {
                return Err(invalid("The service cannot be stopped while it is scaled above 0."));
            }
            rec.service.status = Some("DRAINING".into());
            rec.service.desired_count = 0;
            for d in rec.service.deployments.iter_mut().flatten() {
                d.desired_count = 0;
                d.updated_at = Some(now);
            }
            Ok(render(r, &r.services[&arn], false))
        })?;
        self.kick();
        Ok(t::DeleteServiceResponse { service: Some(out) })
    }

    pub(crate) fn list_service_deployments_op(
        &self,
        ctx: &RequestContext,
        input: t::ListServiceDeploymentsRequest,
    ) -> Result<t::ListServiceDeploymentsResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let arn = service_arn(&scope, &cluster, last_segment(&input.service));
        let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(
            ctx,
            "ListServiceDeployments",
            &arn,
            Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())),
        )?;
        self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            if !r.services.contains_key(&arn) {
                return Err(service_not_found());
            }
            let mut deps: Vec<&t::ServiceDeployment> = r
                .service_deployments
                .values()
                .filter(|d| d.service_arn.as_deref() == Some(arn.as_str()))
                .filter(|d| {
                    input
                        .status
                        .as_ref()
                        .is_none_or(|s| s.is_empty() || s.contains(&d.status.clone().unwrap_or_default()))
                })
                .filter(|d| {
                    input.created_at.as_ref().is_none_or(|c| {
                        c.before.is_none_or(|b| d.created_at.is_some_and(|x| x < b))
                            && c.after.is_none_or(|a| d.created_at.is_some_and(|x| x > a))
                    })
                })
                .collect();
            deps.sort_by_key(|d| std::cmp::Reverse(d.created_at));
            let briefs: Vec<t::ServiceDeploymentBrief> = deps
                .into_iter()
                .map(|d| t::ServiceDeploymentBrief {
                    service_deployment_arn: d.service_deployment_arn.clone(),
                    service_arn: d.service_arn.clone(),
                    cluster_arn: d.cluster_arn.clone(),
                    started_at: d.started_at,
                    created_at: d.created_at,
                    finished_at: d.finished_at,
                    target_service_revision_arn: d.target_service_revision.as_ref().and_then(|t| t.arn.clone()),
                    status: d.status.clone(),
                    status_reason: d.status_reason.clone(),
                })
                .collect();
            let (page, next_token) = paginate(&briefs, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListServiceDeploymentsResponse { service_deployments: Some(page), next_token })
        })
    }

    pub(crate) fn describe_service_deployments_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeServiceDeploymentsRequest,
    ) -> Result<t::DescribeServiceDeploymentsResponse, ServiceError> {
        if input.service_deployment_arns.is_empty() || input.service_deployment_arns.len() > 20 {
            return Err(invalid("serviceDeploymentArns must contain between 1 and 20 ARNs."));
        }
        let mut out = Vec::new();
        let mut failures = Vec::new();
        for arn in &input.service_deployment_arns {
            let found = self.with_region(ctx, |r, _| r.service_deployments.get(arn).cloned());
            let service = found.as_ref().and_then(|d| d.service_arn.clone()).unwrap_or_else(|| arn.clone());
            authorize(ctx, "DescribeServiceDeployments", arn, Cond::new().with("ecs:service", service))?;
            match found {
                Some(d) => out.push(d),
                None => failures.push(failure(arn.clone(), "MISSING")),
            }
        }
        Ok(t::DescribeServiceDeploymentsResponse { service_deployments: Some(out), failures: Some(failures) })
    }

    pub(crate) fn describe_service_revisions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeServiceRevisionsRequest,
    ) -> Result<t::DescribeServiceRevisionsResponse, ServiceError> {
        if input.service_revision_arns.is_empty() || input.service_revision_arns.len() > 20 {
            return Err(invalid("serviceRevisionArns must contain between 1 and 20 ARNs."));
        }
        let mut out = Vec::new();
        let mut failures = Vec::new();
        for arn in &input.service_revision_arns {
            let found = self.with_region(ctx, |r, _| r.service_revisions.get(arn).cloned());
            authorize(ctx, "DescribeServiceRevisions", arn, Cond::new())?;
            match found {
                Some(d) => out.push(d),
                None => failures.push(failure(arn.clone(), "MISSING")),
            }
        }
        Ok(t::DescribeServiceRevisionsResponse { service_revisions: Some(out), failures: Some(failures) })
    }

    pub(crate) fn stop_service_deployment_op(
        &self,
        ctx: &RequestContext,
        input: t::StopServiceDeploymentRequest,
    ) -> Result<t::StopServiceDeploymentResponse, ServiceError> {
        authorize(ctx, "StopServiceDeployment", &input.service_deployment_arn, Cond::new())?;
        let now = ctx.received_at;
        let me = self.clone();
        self.with_region(ctx, |r, scope| {
            let sd = r
                .service_deployments
                .get(&input.service_deployment_arn)
                .cloned()
                .ok_or_else(|| errors::service_deployment_not_found("The service deployment does not exist."))?;
            if !matches!(sd.status.as_deref(), Some("PENDING" | "IN_PROGRESS")) {
                return Err(errors::conflict("The service deployment is not in progress and cannot be stopped."));
            }
            let service = sd.service_arn.clone().unwrap_or_default();
            let stop_type = input.stop_type.clone().unwrap_or_else(|| "ROLLBACK".into());
            let source = sd.source_service_revisions.iter().flatten().next().and_then(|s| s.arn.clone());
            match (stop_type.as_str(), source.and_then(|a| r.service_revisions.get(&a).cloned())) {
                ("ROLLBACK", Some(rev)) => {
                    if let Some(d) = r.service_deployments.get_mut(&input.service_deployment_arn) {
                        d.status = Some("STOP_REQUESTED".into());
                        d.updated_at = Some(now);
                    }
                    let config = revision_config(&rev);
                    me.new_deployment(
                        r,
                        scope,
                        &service,
                        config,
                        now,
                        Some("Service deployment rolled back because a stop was requested.".into()),
                    );
                }
                _ => {
                    if let Some(d) = r.service_deployments.get_mut(&input.service_deployment_arn) {
                        d.status = Some("STOPPED".into());
                        d.stopped_at = Some(now);
                        d.updated_at = Some(now);
                        d.status_reason = Some("Service deployment stopped by user.".into());
                    }
                }
            }
            Ok(())
        })?;
        self.kick();
        Ok(t::StopServiceDeploymentResponse { service_deployment_arn: Some(input.service_deployment_arn) })
    }

    pub(crate) fn continue_service_deployment_op(
        &self,
        ctx: &RequestContext,
        input: t::ContinueServiceDeploymentRequest,
    ) -> Result<t::ContinueServiceDeploymentResponse, ServiceError> {
        authorize(ctx, "ContinueServiceDeployment", &input.service_deployment_arn, Cond::new())?;
        self.with_region(ctx, |r, _| {
            let sd = r
                .service_deployments
                .get_mut(&input.service_deployment_arn)
                .ok_or_else(|| errors::service_deployment_not_found("The service deployment does not exist."))?;
            let hook = sd
                .lifecycle_hook_details
                .iter_mut()
                .flatten()
                .find(|h| h.hook_id.as_deref() == Some(input.hook_id.as_str()))
                .ok_or_else(|| {
                    invalid(format!("The lifecycle hook {} is not waiting for a response.", input.hook_id))
                })?;
            hook.status = Some(input.action.clone().unwrap_or_else(|| "CONTINUE".into()));
            Ok(t::ContinueServiceDeploymentResponse {
                service_deployment_arn: Some(input.service_deployment_arn.clone()),
            })
        })
    }

    // Task sets.

    fn task_set_service(
        &self,
        ctx: &RequestContext,
        cluster_ref: &str,
        service_ref: &str,
    ) -> Result<(String, String), ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(Some(cluster_ref));
        let arn = service_arn(&scope, &cluster, last_segment(service_ref));
        self.with_region(ctx, |r, _| {
            clusters::active(r, Some(cluster_ref))?;
            let s = r.services.get(&arn).ok_or_else(service_not_found)?;
            if s.service.status.as_deref() != Some("ACTIVE") {
                return Err(errors::service_not_active("Service was not ACTIVE."));
            }
            if s.service.deployment_controller.as_ref().map(|c| c.r#type.as_str()) != Some("EXTERNAL") {
                return Err(invalid(
                    "Amazon ECS only supports task set management on services configured to use the external deployment controller.",
                ));
            }
            Ok((cluster, arn))
        })
    }

    pub(crate) fn create_task_set_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTaskSetRequest,
    ) -> Result<t::CreateTaskSetResponse, ServiceError> {
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let (cluster, service) = self.task_set_service(ctx, &input.cluster, &input.service)?;
        let scope = Scope::of(ctx);
        let probe = scope.arn(&format!("task-set/{cluster}/{}/*", last_segment(&service)));
        authorize(
            ctx,
            "CreateTaskSet",
            &probe,
            Cond::new()
                .cluster(&scope, &cluster)
                .with("ecs:service", service.clone())
                .extend(request_tags(input.tags.as_ref())),
        )?;
        self.authorize_create_tags(ctx, &probe, "CreateTaskSet", input.tags.as_ref())?;
        let now = ctx.received_at;
        let me = self.clone();
        let out = self.with_region(ctx, |r, scope| {
            if let Some(token) = &input.client_token {
                if let Some((_, existing)) = r.client_tokens.get(&format!("taskset:{token}")) {
                    let found = r.services[&service]
                        .service
                        .task_sets
                        .iter()
                        .flatten()
                        .find(|t| t.task_set_arn.as_ref() == Some(existing))
                        .cloned();
                    if let Some(ts) = found {
                        return Ok(ts);
                    }
                }
            }
            let def = taskdefs::resolve(r, &input.task_definition)
                .cloned()
                .ok_or_else(|| crate::names::client("TaskDefinition not found."))?;
            let cluster_obj = clusters::active(r, Some(&cluster))?.clone();
            let (lt, strategy) = me.check_service_capacity(
                r,
                scope,
                &cluster_obj,
                Some(&def),
                input.launch_type.as_deref(),
                input.capacity_provider_strategy.as_deref(),
                input.network_configuration.as_ref(),
            )?;
            let ts = new_task_set(
                r,
                scope,
                &service,
                TaskSetInput {
                    external_id: input.external_id.clone(),
                    task_definition: def.task_definition_arn.clone().unwrap_or_default(),
                    network_configuration: input.network_configuration.clone(),
                    load_balancers: input.load_balancers.clone(),
                    service_registries: input.service_registries.clone(),
                    launch_type: lt,
                    capacity_provider_strategy: (!strategy.is_empty()).then_some(strategy),
                    platform_version: input.platform_version.clone(),
                    scale: input.scale.clone(),
                    started_by: None,
                },
                now,
            );
            let ts_arn = ts.task_set_arn.clone().unwrap_or_default();
            crate::tags::store(r, &ts_arn, input.tags.as_ref());
            if let Some(token) = &input.client_token {
                r.client_tokens.insert(format!("taskset:{token}"), ("task-set".into(), ts_arn));
            }
            Ok(ts)
        })?;
        self.kick();
        Ok(t::CreateTaskSetResponse { task_set: Some(out) })
    }

    pub(crate) fn describe_task_sets_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTaskSetsRequest,
    ) -> Result<t::DescribeTaskSetsResponse, ServiceError> {
        let (cluster, service) = self.task_set_service(ctx, &input.cluster, &input.service)?;
        let scope = Scope::of(ctx);
        authorize(
            ctx,
            "DescribeTaskSets",
            &scope.arn(&format!("task-set/{cluster}/{}/*", last_segment(&service))),
            Cond::new().cluster(&scope, &cluster).with("ecs:service", service.clone()),
        )?;
        let with_tags = input.include.iter().flatten().any(|i| i == "TAGS");
        self.with_region(ctx, |r, _| {
            let sets: Vec<t::TaskSet> = r.services[&service].service.task_sets.clone().unwrap_or_default();
            let mut out = Vec::new();
            let mut failures = Vec::new();
            let pick = |ts: &t::TaskSet| {
                let mut ts = ts.clone();
                ts.tags = with_tags
                    .then(|| r.tags.get(ts.task_set_arn.as_deref().unwrap_or_default()).cloned().unwrap_or_default());
                ts
            };
            match &input.task_sets {
                Some(refs) => {
                    for reference in refs {
                        match sets.iter().find(|ts| {
                            ts.task_set_arn.as_deref() == Some(reference.as_str())
                                || ts.id.as_deref() == Some(reference.as_str())
                        }) {
                            Some(ts) => out.push(pick(ts)),
                            None => failures.push(failure(reference.clone(), "MISSING")),
                        }
                    }
                }
                None => out.extend(sets.iter().map(pick)),
            }
            Ok(t::DescribeTaskSetsResponse { task_sets: Some(out), failures: Some(failures) })
        })
    }

    pub(crate) fn update_task_set_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateTaskSetRequest,
    ) -> Result<t::UpdateTaskSetResponse, ServiceError> {
        let (cluster, service) = self.task_set_service(ctx, &input.cluster, &input.service)?;
        let scope = Scope::of(ctx);
        authorize(
            ctx,
            "UpdateTaskSet",
            &task_set_arn_of(&scope, &cluster, &service, &input.task_set),
            Cond::new().cluster(&scope, &cluster),
        )?;
        check_scale(&input.scale)?;
        let now = ctx.received_at;
        let out = self.with_region(ctx, |r, _| {
            let rec = r.services.get_mut(&service).expect("checked");
            let desired = rec.service.desired_count;
            let ts = rec
                .service
                .task_sets
                .iter_mut()
                .flatten()
                .find(|ts| matches_task_set(ts, &input.task_set))
                .ok_or_else(|| errors::task_set_not_found("The specified task set does not exist."))?;
            ts.scale = Some(input.scale.clone());
            ts.computed_desired_count = computed(desired, &input.scale);
            ts.stability_status = Some("STABILIZING".into());
            ts.stability_status_at = Some(now);
            ts.updated_at = Some(now);
            Ok(ts.clone())
        })?;
        self.kick();
        Ok(t::UpdateTaskSetResponse { task_set: Some(out) })
    }

    pub(crate) fn delete_task_set_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTaskSetRequest,
    ) -> Result<t::DeleteTaskSetResponse, ServiceError> {
        let (cluster, service) = self.task_set_service(ctx, &input.cluster, &input.service)?;
        let scope = Scope::of(ctx);
        authorize(
            ctx,
            "DeleteTaskSet",
            &task_set_arn_of(&scope, &cluster, &service, &input.task_set),
            Cond::new().cluster(&scope, &cluster),
        )?;
        let now = ctx.received_at;
        let out = self.with_region(ctx, |r, _| {
            let rec = r.services.get_mut(&service).expect("checked");
            let ts = rec
                .service
                .task_sets
                .iter_mut()
                .flatten()
                .find(|ts| matches_task_set(ts, &input.task_set))
                .ok_or_else(|| errors::task_set_not_found("The specified task set does not exist."))?;
            if ts.status.as_deref() == Some("PRIMARY") && input.force != Some(true) {
                return Err(invalid("Cannot delete the primary task set of a service. Use the force parameter."));
            }
            if ts.scale.as_ref().is_some_and(|s| s.value > 0.0) && input.force != Some(true) {
                return Err(invalid(
                    "The task set cannot be deleted while it is scaled above 0. Use the force parameter.",
                ));
            }
            ts.status = Some("DRAINING".into());
            ts.computed_desired_count = 0;
            ts.updated_at = Some(now);
            Ok(ts.clone())
        })?;
        self.kick();
        Ok(t::DeleteTaskSetResponse { task_set: Some(out) })
    }

    pub(crate) fn update_service_primary_task_set_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateServicePrimaryTaskSetRequest,
    ) -> Result<t::UpdateServicePrimaryTaskSetResponse, ServiceError> {
        let (cluster, service) = self.task_set_service(ctx, &input.cluster, &input.service)?;
        let scope = Scope::of(ctx);
        authorize(ctx, "UpdateServicePrimaryTaskSet", &service, Cond::new().cluster(&scope, &cluster))?;
        let now = ctx.received_at;
        self.with_region(ctx, |r, _| {
            let rec = r.services.get_mut(&service).expect("checked");
            if !rec.service.task_sets.iter().flatten().any(|ts| matches_task_set(ts, &input.primary_task_set)) {
                return Err(errors::task_set_not_found("The specified task set does not exist."));
            }
            let mut primary = None;
            for ts in rec.service.task_sets.iter_mut().flatten() {
                if matches_task_set(ts, &input.primary_task_set) {
                    if ts.status.as_deref() == Some("DRAINING") {
                        return Err(invalid("A draining task set cannot be made primary."));
                    }
                    ts.status = Some("PRIMARY".into());
                    ts.updated_at = Some(now);
                    primary = Some(ts.clone());
                } else if ts.status.as_deref() == Some("PRIMARY") {
                    ts.status = Some("ACTIVE".into());
                    ts.updated_at = Some(now);
                }
            }
            let primary = primary.expect("checked above");
            rec.service.task_definition = primary.task_definition.clone();
            rec.service.launch_type = primary.launch_type.clone();
            rec.service.capacity_provider_strategy = primary.capacity_provider_strategy.clone();
            rec.service.network_configuration = primary.network_configuration.clone();
            rec.service.load_balancers = primary.load_balancers.clone();
            Ok(t::UpdateServicePrimaryTaskSetResponse { task_set: Some(primary) })
        })
    }
}

/// A service as DescribeServices shows it, with counts.
pub fn render(r: &Region, rec: &ServiceRecord, with_tags: bool) -> t::Service {
    let mut s = rec.service.clone();
    let arn = s.service_arn.clone().unwrap_or_default();
    let live: Vec<_> = r
        .tasks
        .values()
        .filter(|t| t.service_arn.as_deref() == Some(arn.as_str()))
        .filter(|t| t.task.last_status.as_deref() != Some("STOPPED"))
        .collect();
    let running = |dep: Option<&str>| {
        live.iter()
            .filter(|t| dep.is_none_or(|d| t.deployment_id.as_deref() == Some(d)))
            .filter(|t| t.task.last_status.as_deref() == Some("RUNNING"))
            .count() as i32
    };
    let pending = |dep: Option<&str>| {
        live.iter()
            .filter(|t| dep.is_none_or(|d| t.deployment_id.as_deref() == Some(d)))
            .filter(|t| t.task.last_status.as_deref() != Some("RUNNING"))
            .filter(|t| t.task.desired_status.as_deref() != Some("STOPPED"))
            .count() as i32
    };
    s.running_count = running(None);
    s.pending_count = pending(None);
    for d in s.deployments.iter_mut().flatten() {
        d.running_count = running(d.id.as_deref());
        d.pending_count = pending(d.id.as_deref());
    }
    for ts in s.task_sets.iter_mut().flatten() {
        ts.running_count = running(ts.id.as_deref());
        ts.pending_count = pending(ts.id.as_deref());
    }
    s.current_service_revisions = Some(
        s.deployments
            .iter()
            .flatten()
            .filter_map(|d| {
                Some(t::ServiceCurrentRevisionSummary {
                    arn: rec.deployment_revisions.get(d.id.as_ref()?).cloned(),
                    requested_task_count: d.desired_count,
                    running_task_count: d.running_count,
                    pending_task_count: d.pending_count,
                })
            })
            .collect(),
    );
    s.tags = with_tags.then(|| r.tags.get(&arn).cloned().unwrap_or_default());
    s
}

pub fn revision_config(rev: &t::ServiceRevision) -> RevisionConfig {
    RevisionConfig {
        task_definition: rev.task_definition.clone().unwrap_or_default(),
        launch_type: rev.launch_type.clone(),
        capacity_provider_strategy: rev.capacity_provider_strategy.clone().unwrap_or_default(),
        platform_version: rev.platform_version.clone(),
        network_configuration: rev.network_configuration.clone(),
        load_balancers: rev.load_balancers.clone().unwrap_or_default(),
        service_registries: rev.service_registries.clone().unwrap_or_default(),
        service_connect_configuration: rev.service_connect_configuration.clone(),
        volume_configurations: rev.volume_configurations.clone(),
        vpc_lattice_configurations: rev.vpc_lattice_configurations.clone(),
        gateway_connectors: rev.gateway_connectors.clone(),
        monitoring: rev.monitoring.clone(),
    }
}

struct TaskSetInput {
    external_id: Option<String>,
    task_definition: String,
    network_configuration: Option<t::NetworkConfiguration>,
    load_balancers: Option<Vec<t::LoadBalancer>>,
    service_registries: Option<Vec<t::ServiceRegistry>>,
    launch_type: Option<String>,
    capacity_provider_strategy: Option<Vec<t::CapacityProviderStrategyItem>>,
    platform_version: Option<String>,
    scale: Option<t::Scale>,
    started_by: Option<String>,
}

fn computed(desired: i32, scale: &t::Scale) -> i32 {
    (desired as f64 * scale.value / 100.0).ceil() as i32
}

fn check_scale(scale: &t::Scale) -> Result<(), ServiceError> {
    if !(0.0..=100.0).contains(&scale.value) {
        return Err(invalid("The scale value must be between 0 and 100."));
    }
    Ok(())
}

fn matches_task_set(ts: &t::TaskSet, reference: &str) -> bool {
    ts.task_set_arn.as_deref() == Some(reference) || ts.id.as_deref() == Some(reference)
}

fn task_set_arn_of(scope: &Scope, cluster: &str, service_arn: &str, reference: &str) -> String {
    if split_arn(reference).is_some() {
        reference.to_string()
    } else {
        scope.arn(&format!("task-set/{cluster}/{}/{reference}", last_segment(service_arn)))
    }
}

fn new_task_set(
    r: &mut Region,
    scope: &Scope,
    service_arn: &str,
    input: TaskSetInput,
    now: DateTime<Utc>,
) -> t::TaskSet {
    let rec = r.services.get_mut(service_arn).expect("service exists");
    let id = format!("ecs-svc/{}", numeric_id());
    let cluster = rec.cluster.clone();
    let name = rec.service.service_name.clone().unwrap_or_default();
    let scale = input.scale.unwrap_or(t::Scale { value: 100.0, unit: Some("PERCENT".into()) });
    let fargate = input.launch_type.as_deref() == Some("FARGATE");
    let ts = t::TaskSet {
        id: Some(id.clone()),
        task_set_arn: Some(scope.arn(&format!("task-set/{cluster}/{name}/{id}"))),
        service_arn: Some(service_arn.to_string()),
        cluster_arn: Some(scope.cluster_arn(&cluster)),
        started_by: input.started_by,
        external_id: input.external_id,
        status: Some("ACTIVE".into()),
        task_definition: Some(input.task_definition),
        computed_desired_count: computed(rec.service.desired_count, &scale),
        pending_count: 0,
        running_count: 0,
        created_at: Some(now),
        updated_at: Some(now),
        launch_type: input.launch_type,
        capacity_provider_strategy: input.capacity_provider_strategy,
        platform_version: fargate.then(|| input.platform_version.unwrap_or_else(|| "1.4.0".into())),
        platform_family: fargate.then(|| "Linux".into()),
        network_configuration: input.network_configuration,
        load_balancers: Some(input.load_balancers.unwrap_or_default()),
        service_registries: Some(input.service_registries.unwrap_or_default()),
        scale: Some(scale),
        stability_status: Some("STABILIZING".into()),
        stability_status_at: Some(now),
        tags: None,
        fargate_ephemeral_storage: None,
    };
    rec.service.task_sets.get_or_insert_with(Vec::new).push(ts.clone());
    ts
}
