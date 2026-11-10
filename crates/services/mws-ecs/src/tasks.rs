//! Tasks: RunTask and StartTask (with launch type and capacity provider
//! resolution, Fargate checks and container instance placement),
//! StopTask, DescribeTasks, ListTasks, task protection, ExecuteCommand and
//! the agent's state change calls.

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::generated::types as t;
use crate::names::{
    authorize, check_tags, cluster_name, ecs_denial, failure, hex_id, invalid, last_segment, paginate, request_tags,
    resource_tags, Cond, Scope,
};
use crate::platform::TaskInterface;
use crate::state::{Protection, Region, TaskRecord};
use crate::{capacity, clusters, instances, taskdefs, Ecs};

/// How long a stopped task stays visible.
pub(crate) const STOPPED_RETENTION_MINUTES: i64 = 60;

/// Drop stopped tasks past their retention.
pub fn expire(r: &mut Region, now: DateTime<Utc>) {
    r.tasks.retain(|_, t| t.expires_at.is_none_or(|e| e > now));
    for t in r.tasks.values_mut() {
        if let Some(p) = t.protection.as_mut() {
            if p.enabled && p.expires_at.is_some_and(|e| e <= now) {
                p.enabled = false;
                p.expires_at = None;
            }
        }
    }
}

pub fn task_arn(scope: &Scope, cluster: &str, id: &str) -> String {
    scope.arn(&format!("task/{cluster}/{id}"))
}

/// The fixed host ports a task definition's containers take.
fn host_ports(def: &t::TaskDefinition) -> Vec<i32> {
    def.container_definitions
        .iter()
        .flatten()
        .flat_map(|c| c.port_mappings.iter().flatten())
        .filter_map(|m| m.host_port.filter(|p| *p > 0))
        .collect()
}

/// Where a task runs, once resolved.
#[derive(Debug, Clone, Default)]
pub struct Placement {
    pub launch_type: String,
    pub capacity_provider: Option<String>,
    pub container_instance_arn: Option<String>,
}

/// Everything needed to start one task.
#[derive(Debug, Clone, Default)]
pub struct Launch {
    pub cluster: String,
    pub definition: t::TaskDefinition,
    pub placement: Placement,
    pub network: Option<t::NetworkConfiguration>,
    pub overrides: Option<t::TaskOverride>,
    pub group: Option<String>,
    pub started_by: Option<String>,
    pub tags: Vec<t::Tag>,
    pub enable_execute_command: bool,
    pub platform_version: Option<String>,
    pub service_arn: Option<String>,
    pub deployment_id: Option<String>,
}

/// The CPU units and MiB of memory a task reserves.
pub fn task_resources(def: &t::TaskDefinition) -> (i64, i64) {
    let containers = def.container_definitions.as_deref().unwrap_or_default();
    let cpu = def
        .cpu
        .as_deref()
        .and_then(|c| c.parse::<i64>().ok())
        .unwrap_or_else(|| containers.iter().map(|c| c.cpu as i64).sum());
    let memory = def
        .memory
        .as_deref()
        .and_then(|m| m.parse::<i64>().ok())
        .unwrap_or_else(|| containers.iter().map(|c| c.memory.or(c.memory_reservation).unwrap_or(0) as i64).sum());
    (cpu, memory)
}

/// Resolve the launch type and capacity provider of a task or service.
pub fn resolve_capacity(
    r: &Region,
    scope: &Scope,
    cluster: &t::Cluster,
    launch_type: Option<&str>,
    strategy: Option<&[t::CapacityProviderStrategyItem]>,
) -> Result<(Option<String>, Vec<t::CapacityProviderStrategyItem>), ServiceError> {
    let strategy = strategy.filter(|s| !s.is_empty());
    match (launch_type, strategy) {
        (Some(_), Some(_)) => Err(invalid(
            "Specifying both a launch type and capacity provider strategy is not supported. Remove one and try again.",
        )),
        (Some(lt), None) => Ok((Some(lt.to_string()), Vec::new())),
        (None, Some(s)) => {
            capacity::check_strategy(s)?;
            for item in s {
                let name = capacity::provider_name(&item.capacity_provider);
                if capacity::find(r, scope, &name).is_none() {
                    return Err(invalid(format!(
                        "The specified capacity provider '{name}' does not exist. Specify a valid name or ARN and try again."
                    )));
                }
                if !cluster.capacity_providers.iter().flatten().any(|p| capacity::provider_name(p) == name) {
                    return Err(invalid(
                        "The specified capacity provider strategy cannot contain a capacity provider that is not associated with the cluster. Associate the capacity provider with the cluster or specify a valid capacity provider and try again.",
                    ));
                }
            }
            Ok((None, s.to_vec()))
        }
        (None, None) => match cluster.default_capacity_provider_strategy.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => Ok((None, s.to_vec())),
            None => Ok((Some("EC2".into()), Vec::new())),
        },
    }
}

/// The launch type tasks on a capacity provider get.
pub fn launch_type_of_provider(r: &Region, scope: &Scope, provider: &str) -> String {
    match provider {
        "FARGATE" | "FARGATE_SPOT" => "FARGATE".into(),
        p => match capacity::find(r, scope, p).and_then(|c| c.r#type) {
            Some(ty) if ty == "MANAGED_INSTANCES" => "MANAGED_INSTANCES".into(),
            _ => "EC2".into(),
        },
    }
}

/// The checks a task definition and network configuration must pass for a
/// launch type.
pub fn check_launch(
    def: &t::TaskDefinition,
    launch_type: &str,
    network: Option<&t::NetworkConfiguration>,
) -> Result<(), ServiceError> {
    let compat = def.compatibilities.as_deref().unwrap_or_default();
    if launch_type != "EC2" && !compat.iter().any(|c| c == launch_type) {
        return Err(invalid(format!("Task definition does not support launch_type {launch_type}.")));
    }
    let awsvpc = def.network_mode.as_deref() == Some("awsvpc");
    match network.and_then(|n| n.awsvpc_configuration.as_ref()) {
        None if awsvpc => {
            return Err(invalid("Network Configuration must be provided when networkMode 'awsvpc' is specified."));
        }
        Some(_) if !awsvpc => {
            return Err(invalid(
                "Network Configuration is not valid for the given networkMode of this task definition.",
            ));
        }
        Some(c) => {
            if c.subnets.is_empty() {
                return Err(invalid("subnets can not be empty."));
            }
            if c.subnets.len() > 16 {
                return Err(invalid("subnets can have at most 16 items."));
            }
            if c.security_groups.as_ref().is_some_and(|g| g.len() > 5) {
                return Err(invalid("securityGroups can have at most 5 items."));
            }
            if c.assign_public_ip.as_deref() == Some("ENABLED") && launch_type == "EC2" {
                return Err(invalid("Assign public IP is not supported for this launch type."));
            }
        }
        None => {}
    }
    Ok(())
}

/// The (allowed) placement constraints: `distinctInstance` and `memberOf`
/// expressions on attributes (`attribute:name == value`, `in [...]`, `!=`).
pub fn constraint_ok(r: &Region, inst: &crate::state::InstanceRecord, expr: &str) -> bool {
    let expr = expr.trim();
    let Some(rest) = expr.strip_prefix("attribute:") else { return true };
    let attrs = instances::all_attributes(r, inst);
    let value_of = |name: &str| attrs.iter().find(|a| a.name == name).and_then(|a| a.value.clone());
    if let Some((name, value)) = rest.split_once("==") {
        return value_of(name.trim()).as_deref() == Some(value.trim());
    }
    if let Some((name, value)) = rest.split_once("!=") {
        return value_of(name.trim()).as_deref() != Some(value.trim());
    }
    if let Some((name, list)) = rest.split_once(" in ") {
        let values: Vec<&str> = list.trim().trim_matches(['[', ']']).split(',').map(str::trim).collect();
        return value_of(name.trim()).is_some_and(|v| values.contains(&v.as_str()));
    }
    if let Some((name, list)) = rest.split_once(" not_in ") {
        let values: Vec<&str> = list.trim().trim_matches(['[', ']']).split(',').map(str::trim).collect();
        return !value_of(name.trim()).is_some_and(|v| values.contains(&v.as_str()));
    }
    if let Some(name) = rest.strip_suffix(" exists") {
        return value_of(name.trim()).is_some();
    }
    true
}

/// Choose a container instance for a task, or say why none fits.
pub fn place_on_instance(
    r: &Region,
    cluster: &str,
    def: &t::TaskDefinition,
    capacity_provider: Option<&str>,
    constraints: &[t::PlacementConstraint],
    strategy: &[t::PlacementStrategy],
    taken: &[String],
) -> Result<String, Vec<t::Failure>> {
    let (cpu, memory) = task_resources(def);
    let mut candidates: Vec<(&String, &crate::state::InstanceRecord, i64, i64)> = Vec::new();
    let mut failures = Vec::new();
    let ports = host_ports(def);
    for (arn, inst) in r.container_instances.iter().filter(|(_, i)| i.cluster == cluster) {
        if inst.instance.status.as_deref() != Some("ACTIVE") || !inst.instance.agent_connected {
            continue;
        }
        if let Some(cp) = capacity_provider {
            if inst.instance.capacity_provider_name.as_deref().is_some_and(|n| n != cp) {
                continue;
            }
        }
        let (rem_cpu, rem_mem, used_ports) = instances::remaining(r, arn, inst);
        let distinct = constraints.iter().any(|c| c.r#type.as_deref() == Some("distinctInstance"));
        if distinct && taken.contains(arn) {
            continue;
        }
        if !constraints
            .iter()
            .filter(|c| c.r#type.as_deref() == Some("memberOf"))
            .all(|c| constraint_ok(r, inst, c.expression.as_deref().unwrap_or_default()))
        {
            failures.push(failure(arn.clone(), "MemberOf placement constraint unsatisfied."));
            continue;
        }
        if rem_cpu < cpu {
            failures.push(failure(arn.clone(), "RESOURCE:CPU"));
            continue;
        }
        if rem_mem < memory {
            failures.push(failure(arn.clone(), "RESOURCE:MEMORY"));
            continue;
        }
        if ports.iter().any(|p| used_ports.contains(p)) {
            failures.push(failure(arn.clone(), "RESOURCE:PORTS"));
            continue;
        }
        candidates.push((arn, inst, rem_cpu, rem_mem));
    }
    if candidates.is_empty() {
        return Err(failures);
    }
    match strategy.first().map(|s| (s.r#type.as_deref().unwrap_or_default(), s.field.as_deref().unwrap_or_default())) {
        Some(("binpack", field)) => {
            let key = |c: &(&String, &crate::state::InstanceRecord, i64, i64)| if field == "cpu" { c.2 } else { c.3 };
            candidates.sort_by_key(key);
        }
        Some(("random", _)) => {
            use rand::seq::SliceRandom;
            candidates.shuffle(&mut rand::thread_rng());
        }
        _ => {
            // spread (the default): the instance with the fewest tasks.
            candidates.sort_by_key(|c| {
                r.tasks
                    .values()
                    .filter(|t| t.task.container_instance_arn.as_deref() == Some(c.0.as_str()))
                    .filter(|t| t.task.last_status.as_deref() != Some("STOPPED"))
                    .count()
            });
        }
    }
    Ok(candidates[0].0.clone())
}

fn kv(name: &str, value: impl Into<String>) -> t::KeyValuePair {
    t::KeyValuePair { name: Some(name.into()), value: Some(value.into()) }
}

/// Apply task overrides to the definition the task runs.
fn overridden(def: &t::TaskDefinition, overrides: Option<&t::TaskOverride>) -> t::TaskDefinition {
    let mut d = def.clone();
    let Some(o) = overrides else { return d };
    if let Some(cpu) = &o.cpu {
        d.cpu = Some(cpu.clone());
    }
    if let Some(mem) = &o.memory {
        d.memory = Some(mem.clone());
    }
    if let Some(r) = &o.task_role_arn {
        d.task_role_arn = Some(r.clone());
    }
    if let Some(r) = &o.execution_role_arn {
        d.execution_role_arn = Some(r.clone());
    }
    if let Some(e) = &o.ephemeral_storage {
        d.ephemeral_storage = Some(e.clone());
    }
    for co in o.container_overrides.iter().flatten() {
        let Some(c) = d.container_definitions.iter_mut().flatten().find(|c| c.name.is_some() && c.name == co.name)
        else {
            continue;
        };
        if let Some(cmd) = &co.command {
            c.command = Some(cmd.clone());
        }
        if let Some(env) = &co.environment {
            let current = c.environment.get_or_insert_with(Vec::new);
            for e in env {
                current.retain(|x| x.name != e.name);
                current.push(e.clone());
            }
        }
        if let Some(files) = &co.environment_files {
            c.environment_files = Some(files.clone());
        }
        if let Some(cpu) = co.cpu {
            c.cpu = cpu;
        }
        if co.memory.is_some() {
            c.memory = co.memory;
        }
        if co.memory_reservation.is_some() {
            c.memory_reservation = co.memory_reservation;
        }
        if let Some(rr) = &co.resource_requirements {
            c.resource_requirements = Some(rr.clone());
        }
    }
    d
}

fn check_overrides(def: &t::TaskDefinition, overrides: Option<&t::TaskOverride>) -> Result<(), ServiceError> {
    let Some(o) = overrides else { return Ok(()) };
    for co in o.container_overrides.iter().flatten() {
        let name = co.name.as_deref().unwrap_or_default();
        if !def.container_definitions.iter().flatten().any(|c| c.name.as_deref() == Some(name)) {
            return Err(invalid(format!(
                "Override for container named {name} is not a container in the TaskDefinition."
            )));
        }
    }
    Ok(())
}

impl Ecs {
    /// Create a task record (and its network interface) and start running
    /// it. Returns the task as RunTask reports it.
    pub(crate) fn launch(
        &self,
        ctx: &RequestContext,
        r: &mut Region,
        scope: &Scope,
        launch: Launch,
    ) -> Result<t::Task, ServiceError> {
        let id = hex_id();
        let arn = task_arn(scope, &launch.cluster, &id);
        let def = overridden(&launch.definition, launch.overrides.as_ref());
        let fargate = launch.placement.launch_type == "FARGATE";
        let mut attachments = Vec::new();
        let mut interface: Option<TaskInterface> = None;
        let mut az = format!("{}a", scope.region);
        if def.network_mode.as_deref() == Some("awsvpc") {
            let conf = launch.network.as_ref().and_then(|n| n.awsvpc_configuration.clone()).unwrap_or_default();
            let attachment_id = uuid::Uuid::new_v4().to_string();
            let description = scope.arn(&format!("attachment/{attachment_id}"));
            let eni = match self.platform() {
                Some(p) => p.create_interface(
                    ctx,
                    &scope.account,
                    &conf.subnets,
                    conf.security_groups.as_deref().unwrap_or_default(),
                    conf.assign_public_ip.as_deref() == Some("ENABLED"),
                    &description,
                )?,
                None => made_up_interface(&conf),
            };
            if !eni.availability_zone.is_empty() {
                az = eni.availability_zone.clone();
            }
            attachments.push(t::Attachment {
                id: Some(attachment_id),
                r#type: Some("ElasticNetworkInterface".into()),
                status: Some("PRECREATED".into()),
                details: Some(vec![
                    kv("subnetId", eni.subnet_id.clone()),
                    kv("networkInterfaceId", eni.eni_id.clone()),
                    kv("macAddress", eni.mac_address.clone()),
                    kv("privateDnsName", eni.private_dns_name.clone()),
                    kv("privateIPv4Address", eni.private_ip.clone()),
                ]),
            });
            interface = Some(eni);
        } else if let Some(ci) = &launch.placement.container_instance_arn {
            if let Some(inst) = r.container_instances.get(ci) {
                if let Some(a) = instances::attribute_value(r, inst, "ecs.availability-zone") {
                    az = a;
                }
            }
        }
        let containers: Vec<t::Container> = def
            .container_definitions
            .iter()
            .flatten()
            .map(|c| t::Container {
                container_arn: Some(scope.arn(&format!("container/{}/{id}/{}", launch.cluster, uuid::Uuid::new_v4()))),
                task_arn: Some(arn.clone()),
                name: c.name.clone(),
                image: c.image.clone(),
                last_status: Some("PENDING".into()),
                network_bindings: Some(Vec::new()),
                network_interfaces: Some(
                    interface
                        .iter()
                        .map(|i| t::NetworkInterface {
                            attachment_id: attachments.first().and_then(|a: &t::Attachment| a.id.clone()),
                            private_ipv4_address: Some(i.private_ip.clone()),
                            ipv6_address: None,
                        })
                        .collect(),
                ),
                health_status: Some("UNKNOWN".into()),
                managed_agents: launch.enable_execute_command.then(|| {
                    vec![t::ManagedAgent {
                        name: Some("ExecuteCommandAgent".into()),
                        last_status: Some("PENDING".into()),
                        ..Default::default()
                    }]
                }),
                cpu: Some(c.cpu.to_string()),
                memory: c.memory.map(|m| m.to_string()),
                memory_reservation: c.memory_reservation.map(|m| m.to_string()),
                ..Default::default()
            })
            .collect();
        let (cpu, memory) = task_resources(&def);
        let family = def.family.clone().unwrap_or_default();
        let platform_version = fargate.then(|| match launch.platform_version.as_deref() {
            None | Some("LATEST") => "1.4.0".to_string(),
            Some(v) => v.to_string(),
        });
        let task = t::Task {
            attachments: Some(attachments),
            attributes: Some(vec![t::Attribute {
                name: "ecs.cpu-architecture".into(),
                value: Some(
                    def.runtime_platform
                        .as_ref()
                        .and_then(|p| p.cpu_architecture.clone())
                        .map(|a| a.to_ascii_lowercase())
                        .unwrap_or_else(|| "x86_64".into()),
                ),
                ..Default::default()
            }]),
            availability_zone: Some(az),
            capacity_provider_name: launch.placement.capacity_provider.clone(),
            cluster_arn: Some(scope.cluster_arn(&launch.cluster)),
            container_instance_arn: launch.placement.container_instance_arn.clone(),
            containers: Some(containers),
            cpu: Some(cpu.to_string()),
            created_at: Some(ctx.received_at),
            desired_status: Some("RUNNING".into()),
            enable_execute_command: launch.enable_execute_command,
            group: Some(launch.group.clone().unwrap_or_else(|| format!("family:{family}"))),
            health_status: Some("UNKNOWN".into()),
            last_status: Some(if fargate { "PROVISIONING" } else { "PENDING" }.into()),
            launch_type: Some(launch.placement.launch_type.clone()),
            memory: Some(memory.to_string()),
            overrides: Some(t::TaskOverride {
                container_overrides: Some(
                    launch.overrides.as_ref().and_then(|o| o.container_overrides.clone()).unwrap_or_default(),
                ),
                inference_accelerator_overrides: Some(Vec::new()),
                ..launch.overrides.clone().unwrap_or_default()
            }),
            platform_version,
            platform_family: fargate.then(|| {
                def.runtime_platform
                    .as_ref()
                    .and_then(|p| p.operating_system_family.clone())
                    .map(|f| if f.starts_with("WINDOWS") { "Windows".to_string() } else { "Linux".to_string() })
                    .unwrap_or_else(|| "Linux".into())
            }),
            started_by: launch.started_by.clone(),
            tags: None,
            task_arn: Some(arn.clone()),
            task_definition_arn: launch.definition.task_definition_arn.clone(),
            version: 1,
            ephemeral_storage: fargate.then(|| t::EphemeralStorage {
                size_in_gi_b: def.ephemeral_storage.as_ref().map(|e| e.size_in_gi_b).unwrap_or(20),
            }),
            fargate_ephemeral_storage: fargate.then(|| t::TaskEphemeralStorage {
                size_in_gi_b: def.ephemeral_storage.as_ref().map(|e| e.size_in_gi_b).unwrap_or(20),
                kms_key_id: None,
            }),
            ..Default::default()
        };
        if !launch.tags.is_empty() {
            r.tags.insert(arn.clone(), launch.tags.clone());
        }
        let record = TaskRecord {
            task: task.clone(),
            definition: def,
            cluster: launch.cluster.clone(),
            service_arn: launch.service_arn.clone(),
            deployment_id: launch.deployment_id.clone(),
            eni_id: interface.as_ref().map(|i| i.eni_id.clone()),
            vpc: interface
                .as_ref()
                .filter(|i| !i.vpc_id.is_empty())
                .map(|i| (i.vpc_id.clone(), i.vpc_cidr.clone(), i.private_ip.clone())),
            ..Default::default()
        };
        r.tasks.insert(arn.clone(), record);
        self.start_runner(&scope.key(), &arn);
        Ok(task)
    }

    /// Ask a task to stop. Returns whether it was running.
    pub(crate) fn request_stop(
        &self,
        r: &mut Region,
        arn: &str,
        stop_code: &str,
        reason: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(rec) = r.tasks.get_mut(arn) else { return false };
        if rec.task.desired_status.as_deref() == Some("STOPPED") {
            return false;
        }
        rec.task.desired_status = Some("STOPPED".into());
        rec.task.stopping_at = Some(now);
        rec.task.stop_code = Some(stop_code.into());
        rec.task.stopped_reason = Some(reason.into());
        rec.task.version += 1;
        let signal = self.inner.runners.lock().expect("ECS runner lock poisoned").get(arn).cloned();
        match signal {
            Some(s) => s.notify_one(),
            None => {
                // Nothing runs it (restored state): it stops at once.
                crate::runner::finish_stopped(rec, now, None);
                if let Some(eni) = rec.eni_id.clone() {
                    if let (Some(p), Some(ctx)) =
                        (self.platform(), self.background_context(&account_of_arn(arn), &region_of_arn(arn)))
                    {
                        p.delete_interface(&ctx, &account_of_arn(arn), &eni);
                    }
                }
            }
        }
        true
    }

    /// `iam:PassRole` on the task and execution roles a task will use,
    /// passed to `ecs-tasks.amazonaws.com`.
    pub(crate) fn authorize_pass_roles(
        &self,
        ctx: &RequestContext,
        def: &t::TaskDefinition,
        overrides: Option<&t::TaskOverride>,
    ) -> Result<(), ServiceError> {
        let mut roles: Vec<String> = Vec::new();
        for r in [
            overrides.and_then(|o| o.task_role_arn.clone()).or_else(|| def.task_role_arn.clone()),
            overrides.and_then(|o| o.execution_role_arn.clone()).or_else(|| def.execution_role_arn.clone()),
        ]
        .into_iter()
        .flatten()
        {
            if !roles.contains(&r) {
                roles.push(r);
            }
        }
        for role in roles {
            ctx.authorize(
                "iam:PassRole",
                &role,
                mws_core::ConditionContext::from([(
                    "iam:PassedToService".to_string(),
                    vec!["ecs-tasks.amazonaws.com".to_string()],
                )]),
            )
            .map_err(ecs_denial)?;
        }
        Ok(())
    }

    /// `iam:PassRole` on `role`, passed to `service`.
    pub(crate) fn pass_role(&self, ctx: &RequestContext, role: &str, service: &str) -> Result<(), ServiceError> {
        ctx.authorize(
            "iam:PassRole",
            role,
            mws_core::ConditionContext::from([("iam:PassedToService".to_string(), vec![service.to_string()])]),
        )
        .map_err(ecs_denial)
    }

    /// `ecs:TagResource` is needed to tag a resource on creation.
    pub(crate) fn authorize_create_tags(
        &self,
        ctx: &RequestContext,
        arn: &str,
        action: &str,
        tags: Option<&Vec<t::Tag>>,
    ) -> Result<(), ServiceError> {
        if tags.is_none_or(|t| t.is_empty()) {
            return Ok(());
        }
        authorize(ctx, "TagResource", arn, Cond::new().with("ecs:CreateAction", action).extend(request_tags(tags)))
    }

    pub(crate) fn run_task_op(
        &self,
        ctx: &RequestContext,
        input: t::RunTaskRequest,
    ) -> Result<t::RunTaskResponse, ServiceError> {
        let count = input.count.unwrap_or(1);
        if !(1..=10).contains(&count) {
            return Err(invalid("The value of count must be between 1 and 10."));
        }
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let (def, cluster_obj) = self.with_region(ctx, |r, _| {
            let c = clusters::active(r, input.cluster.as_deref())?.clone();
            let d = taskdefs::resolve(r, &input.task_definition)
                .filter(|d| d.status.as_deref() != Some("DELETE_IN_PROGRESS"))
                .cloned()
                .ok_or_else(|| crate::names::client("TaskDefinition not found."))?;
            Ok::<_, ServiceError>((d, c))
        })?;
        let def_arn = def.task_definition_arn.clone().unwrap_or_default();
        let providers: Vec<String> = input
            .capacity_provider_strategy
            .iter()
            .flatten()
            .map(|i| capacity::provider_name(&i.capacity_provider))
            .collect();
        authorize(
            ctx,
            "RunTask",
            &def_arn,
            Cond::new()
                .cluster(&scope, &cluster)
                .with("ecs:enable-execute-command", input.enable_execute_command.to_string())
                .with_list("ecs:capacity-provider", providers)
                .extend(request_tags(input.tags.as_ref())),
        )?;
        self.authorize_pass_roles(ctx, &def, input.overrides.as_ref())?;
        check_overrides(&def, input.overrides.as_ref())?;
        if def.status.as_deref() == Some("INACTIVE") {
            // AWS still runs inactive revisions named explicitly.
            if taskdefs::parse_ref(&input.task_definition).1.is_none() {
                return Err(crate::names::client("TaskDefinition is inactive"));
            }
        }
        // The probe ARN for tag-on-create authorization.
        self.authorize_create_tags(ctx, &task_arn(&scope, &cluster, "*"), "RunTask", input.tags.as_ref())?;
        if let Some(token) = input.client_token.as_deref() {
            if token.len() > 64 {
                return Err(invalid("clientToken must be at most 64 characters."));
            }
        }
        self.with_region(ctx, |r, scope| {
            let (launch_type, strategy) = resolve_capacity(
                r,
                scope,
                &cluster_obj,
                input.launch_type.as_deref(),
                input.capacity_provider_strategy.as_deref(),
            )?;
            let mut tasks = Vec::new();
            let mut failures = Vec::new();
            let mut counts = vec![0usize; strategy.len()];
            let mut taken: Vec<String> = Vec::new();
            for _ in 0..count {
                let (lt, cp) = match &launch_type {
                    Some(lt) => (lt.clone(), None),
                    None => {
                        let i = capacity::pick(&strategy, &counts);
                        counts[i] += 1;
                        let name = capacity::provider_name(&strategy[i].capacity_provider);
                        (launch_type_of_provider(r, scope, &name), Some(name))
                    }
                };
                check_launch(&def, &lt, input.network_configuration.as_ref())?;
                let mut placement =
                    Placement { launch_type: lt.clone(), capacity_provider: cp.clone(), container_instance_arn: None };
                if lt == "EC2" || lt == "EXTERNAL" || lt == "MANAGED_INSTANCES" {
                    let any = r.container_instances.values().any(|i| {
                        i.cluster == cluster && matches!(i.instance.status.as_deref(), Some("ACTIVE" | "DRAINING"))
                    });
                    if !any {
                        return Err(invalid("No Container Instances were found in your cluster."));
                    }
                    match place_on_instance(
                        r,
                        &cluster,
                        &def,
                        cp.as_deref(),
                        input.placement_constraints.as_deref().unwrap_or_default(),
                        input.placement_strategy.as_deref().unwrap_or_default(),
                        &taken,
                    ) {
                        Ok(ci) => {
                            taken.push(ci.clone());
                            placement.container_instance_arn = Some(ci);
                        }
                        Err(f) => {
                            failures.extend(f);
                            continue;
                        }
                    }
                }
                let tags = propagated_tags(r, &def, input.propagate_tags.as_deref(), input.tags.as_ref(), None);
                let task = self.launch(
                    ctx,
                    r,
                    scope,
                    Launch {
                        cluster: cluster.clone(),
                        definition: def.clone(),
                        placement,
                        network: input.network_configuration.clone(),
                        overrides: input.overrides.clone(),
                        group: input.group.clone(),
                        started_by: input.started_by.clone(),
                        tags,
                        enable_execute_command: input.enable_execute_command,
                        platform_version: input.platform_version.clone(),
                        service_arn: None,
                        deployment_id: None,
                    },
                )?;
                tasks.push(task);
            }
            Ok(t::RunTaskResponse { tasks: Some(tasks), failures: Some(failures) })
        })
    }

    pub(crate) fn start_task_op(
        &self,
        ctx: &RequestContext,
        input: t::StartTaskRequest,
    ) -> Result<t::StartTaskResponse, ServiceError> {
        if input.container_instances.is_empty() || input.container_instances.len() > 10 {
            return Err(invalid("containerInstances must contain between 1 and 10 container instances."));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let def = self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            taskdefs::resolve(r, &input.task_definition)
                .filter(|d| d.status.as_deref() != Some("DELETE_IN_PROGRESS"))
                .cloned()
                .ok_or_else(|| crate::names::client("TaskDefinition not found."))
        })?;
        let instance_arns: Vec<String> = input
            .container_instances
            .iter()
            .map(|c| scope.arn(&format!("container-instance/{cluster}/{}", last_segment(c))))
            .collect();
        authorize(
            ctx,
            "StartTask",
            def.task_definition_arn.as_deref().unwrap_or_default(),
            Cond::new()
                .cluster(&scope, &cluster)
                .with_list("ecs:container-instances", instance_arns.clone())
                .with("ecs:enable-execute-command", input.enable_execute_command.to_string())
                .extend(request_tags(input.tags.as_ref())),
        )?;
        self.authorize_pass_roles(ctx, &def, input.overrides.as_ref())?;
        check_overrides(&def, input.overrides.as_ref())?;
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        self.authorize_create_tags(ctx, &task_arn(&scope, &cluster, "*"), "StartTask", input.tags.as_ref())?;
        self.with_region(ctx, |r, scope| {
            check_launch(&def, "EC2", input.network_configuration.as_ref())?;
            let mut tasks = Vec::new();
            let mut failures = Vec::new();
            for ci in instance_arns {
                let Some(inst) = r.container_instances.get(&ci).filter(|i| i.cluster == cluster) else {
                    failures.push(failure(ci.clone(), "MISSING"));
                    continue;
                };
                if inst.instance.status.as_deref() != Some("ACTIVE") {
                    failures.push(failure(ci.clone(), "INACTIVE"));
                    continue;
                }
                let (cpu, mem) = task_resources(&def);
                let (rem_cpu, rem_mem, used_ports) = instances::remaining(r, &ci, inst);
                if rem_cpu < cpu {
                    failures.push(failure(ci.clone(), "RESOURCE:CPU"));
                    continue;
                }
                if rem_mem < mem {
                    failures.push(failure(ci.clone(), "RESOURCE:MEMORY"));
                    continue;
                }
                if host_ports(&def).iter().any(|p| used_ports.contains(p)) {
                    failures.push(failure(ci.clone(), "RESOURCE:PORTS"));
                    continue;
                }
                let lt = "EC2";
                let tags = propagated_tags(r, &def, input.propagate_tags.as_deref(), input.tags.as_ref(), None);
                let task = self.launch(
                    ctx,
                    r,
                    scope,
                    Launch {
                        cluster: cluster.clone(),
                        definition: def.clone(),
                        placement: Placement {
                            launch_type: lt.into(),
                            capacity_provider: None,
                            container_instance_arn: Some(ci.clone()),
                        },
                        network: input.network_configuration.clone(),
                        overrides: input.overrides.clone(),
                        group: input.group.clone(),
                        started_by: input.started_by.clone(),
                        tags,
                        enable_execute_command: input.enable_execute_command,
                        platform_version: None,
                        service_arn: None,
                        deployment_id: None,
                    },
                )?;
                tasks.push(task);
            }
            Ok(t::StartTaskResponse { tasks: Some(tasks), failures: Some(failures) })
        })
    }

    pub(crate) fn stop_task_op(
        &self,
        ctx: &RequestContext,
        input: t::StopTaskRequest,
    ) -> Result<t::StopTaskResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let arn = task_arn(&scope, &cluster, last_segment(&input.task));
        let tags = self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            Ok::<_, ServiceError>(r.tags.get(&arn).cloned())
        })?;
        authorize(ctx, "StopTask", &arn, Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())))?;
        if input.reason.as_ref().is_some_and(|r| r.len() > 1024) {
            return Err(invalid("reason can be at most 1024 characters."));
        }
        self.with_region(ctx, |r, _| {
            if !r.tasks.contains_key(&arn) {
                return Err(invalid("The referenced task was not found."));
            }
            let reason = input.reason.clone().unwrap_or_else(|| "Task stopped by user".into());
            self.request_stop(r, &arn, "UserInitiated", &reason, ctx.received_at);
            let rec = &r.tasks[&arn];
            Ok(t::StopTaskResponse { task: Some(render(r, rec, false)) })
        })
    }

    pub(crate) fn describe_tasks_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTasksRequest,
    ) -> Result<t::DescribeTasksResponse, ServiceError> {
        if input.tasks.is_empty() {
            return Err(invalid("Tasks cannot be empty."));
        }
        if input.tasks.len() > 100 {
            return Err(invalid("Tasks cannot have more than 100 elements"));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        self.with_region(ctx, |r, _| clusters::active(r, input.cluster.as_deref()).map(drop))?;
        let with_tags = input.include.iter().flatten().any(|i| i == "TAGS");
        let mut tasks = Vec::new();
        let mut failures = Vec::new();
        for reference in &input.tasks {
            let arn = task_arn(&scope, &cluster, last_segment(reference));
            let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
            authorize(
                ctx,
                "DescribeTasks",
                &arn,
                Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())),
            )?;
            self.with_region(ctx, |r, _| match r.tasks.get(&arn) {
                Some(rec) => tasks.push(render(r, rec, with_tags)),
                None => failures.push(failure(arn.clone(), "MISSING")),
            });
        }
        Ok(t::DescribeTasksResponse { tasks: Some(tasks), failures: Some(failures) })
    }

    pub(crate) fn list_tasks_op(
        &self,
        ctx: &RequestContext,
        input: t::ListTasksRequest,
    ) -> Result<t::ListTasksResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        authorize(
            ctx,
            "ListTasks",
            &scope.arn(&format!("container-instance/{cluster}/*")),
            Cond::new().cluster(&scope, &cluster),
        )?;
        if input.started_by.is_some() && input.service_name.is_some() {
            return Err(invalid("startedBy and serviceName cannot be specified together."));
        }
        self.with_region(ctx, |r, scope| {
            clusters::active(r, input.cluster.as_deref())?;
            let desired = input.desired_status.clone().unwrap_or_else(|| "RUNNING".into());
            let service_arn =
                input.service_name.as_deref().map(|s| scope.arn(&format!("service/{cluster}/{}", last_segment(s))));
            let instance = input
                .container_instance
                .as_deref()
                .map(|c| scope.arn(&format!("container-instance/{cluster}/{}", last_segment(c))));
            let daemon =
                input.daemon_name.as_deref().map(|d| scope.arn(&format!("daemon/{cluster}/{}", last_segment(d))));
            let mut recs: Vec<&TaskRecord> = r
                .tasks
                .values()
                .filter(|t| t.cluster == cluster)
                .filter(|t| {
                    let d = t.task.desired_status.as_deref().unwrap_or("RUNNING");
                    match desired.as_str() {
                        "STOPPED" => d == "STOPPED",
                        _ => d != "STOPPED",
                    }
                })
                .filter(|t| input.family.as_deref().is_none_or(|f| t.definition.family.as_deref() == Some(f)))
                .filter(|t| input.started_by.as_deref().is_none_or(|s| t.task.started_by.as_deref() == Some(s)))
                .filter(|t| service_arn.is_none() || t.service_arn == service_arn)
                .filter(|t| instance.is_none() || t.task.container_instance_arn == instance)
                .filter(|t| input.launch_type.as_deref().is_none_or(|l| t.task.launch_type.as_deref() == Some(l)))
                .filter(|t| daemon.is_none() || t.service_arn == daemon)
                .collect();
            recs.sort_by_key(|t| t.task.created_at);
            let arns: Vec<String> = recs.iter().filter_map(|t| t.task.task_arn.clone()).collect();
            let (page, next_token) = paginate(&arns, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListTasksResponse { task_arns: Some(page), next_token })
        })
    }

    pub(crate) fn update_task_protection_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateTaskProtectionRequest,
    ) -> Result<t::UpdateTaskProtectionResponse, ServiceError> {
        if input.tasks.is_empty() || input.tasks.len() > 10 {
            return Err(invalid("tasks must contain between 1 and 10 tasks."));
        }
        let minutes = input.expires_in_minutes.unwrap_or(120);
        if !(1..=2880).contains(&minutes) {
            return Err(invalid("expiresInMinutes must be between 1 and 2880."));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(Some(&input.cluster));
        self.with_region(ctx, |r, _| clusters::active(r, Some(&input.cluster)).map(drop))?;
        let mut protected = Vec::new();
        let mut failures = Vec::new();
        for reference in &input.tasks {
            let arn = task_arn(&scope, &cluster, last_segment(reference));
            let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
            authorize(
                ctx,
                "UpdateTaskProtection",
                &arn,
                Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())),
            )?;
            self.with_region(ctx, |r, _| {
                let Some(rec) = r.tasks.get_mut(&arn) else {
                    failures.push(failure(arn.clone(), "TASK_NOT_FOUND"));
                    return;
                };
                if rec.service_arn.is_none() {
                    failures.push(failure(arn.clone(), "TASK_NOT_VALID"));
                    return;
                }
                if rec.task.last_status.as_deref() == Some("STOPPED")
                    || rec.task.desired_status.as_deref() == Some("STOPPED")
                {
                    failures.push(failure(arn.clone(), "TASK_NOT_VALID"));
                    return;
                }
                let p = Protection {
                    enabled: input.protection_enabled,
                    expires_at: input.protection_enabled.then(|| ctx.received_at + Duration::minutes(minutes as i64)),
                };
                rec.protection = Some(p.clone());
                protected.push(t::ProtectedTask {
                    task_arn: Some(arn.clone()),
                    protection_enabled: p.enabled,
                    expiration_date: p.expires_at,
                });
            });
        }
        Ok(t::UpdateTaskProtectionResponse { protected_tasks: Some(protected), failures: Some(failures) })
    }

    pub(crate) fn get_task_protection_op(
        &self,
        ctx: &RequestContext,
        input: t::GetTaskProtectionRequest,
    ) -> Result<t::GetTaskProtectionResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(Some(&input.cluster));
        self.with_region(ctx, |r, _| clusters::active(r, Some(&input.cluster)).map(drop))?;
        let refs: Vec<String> = match &input.tasks {
            Some(t) => t.clone(),
            None => self.with_region(ctx, |r, _| {
                r.tasks
                    .values()
                    .filter(|t| t.cluster == cluster && t.service_arn.is_some())
                    .filter(|t| t.task.desired_status.as_deref() != Some("STOPPED"))
                    .filter_map(|t| t.task.task_arn.clone())
                    .collect()
            }),
        };
        let mut protected = Vec::new();
        let mut failures = Vec::new();
        for reference in refs {
            let arn = task_arn(&scope, &cluster, last_segment(&reference));
            let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
            authorize(
                ctx,
                "GetTaskProtection",
                &arn,
                Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())),
            )?;
            self.with_region(ctx, |r, _| match r.tasks.get(&arn) {
                None => failures.push(failure(arn.clone(), "TASK_NOT_FOUND")),
                Some(rec) if rec.service_arn.is_none() => failures.push(failure(arn.clone(), "TASK_NOT_VALID")),
                Some(rec) => {
                    let p = rec.protection.clone().unwrap_or_default();
                    protected.push(t::ProtectedTask {
                        task_arn: Some(arn.clone()),
                        protection_enabled: p.enabled,
                        expiration_date: p.expires_at,
                    });
                }
            });
        }
        Ok(t::GetTaskProtectionResponse { protected_tasks: Some(protected), failures: Some(failures) })
    }

    pub(crate) async fn execute_command_op(
        &self,
        ctx: &RequestContext,
        input: t::ExecuteCommandRequest,
    ) -> Result<t::ExecuteCommandResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let arn = task_arn(&scope, &cluster, last_segment(&input.task));
        let tags = self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            Ok::<_, ServiceError>(r.tags.get(&arn).cloned())
        })?;
        authorize(
            ctx,
            "ExecuteCommand",
            &arn,
            Cond::new()
                .cluster(&scope, &cluster)
                .with("ecs:task", arn.clone())
                .with_opt("ecs:container-name", input.container.as_deref())
                .extend(resource_tags(tags.as_ref())),
        )?;
        if !input.interactive {
            return Err(invalid("Interactive is the only mode supported currently."));
        }
        let (container, runtime_id, container_arn, credentials) = self.with_region(ctx, |r, _| {
            let rec = r.tasks.get(&arn).ok_or_else(|| invalid("The referenced task was not found."))?;
            if !rec.task.enable_execute_command || rec.task.last_status.as_deref() != Some("RUNNING") {
                return Err(invalid(
                    "The execute command failed because execute command was not enabled when the task was run or the execute command agent isn't running. Wait and try again or run a new task with execute command enabled and try again.",
                ));
            }
            let containers = rec.task.containers.as_deref().unwrap_or_default();
            let c = match input.container.as_deref() {
                Some(name) => containers
                    .iter()
                    .find(|c| c.name.as_deref() == Some(name))
                    .ok_or_else(|| invalid(format!("The container {name} was not found in the task.")))?,
                None if containers.len() == 1 => &containers[0],
                None => {
                    return Err(invalid(
                        "Task has more than one container, specify the container with the --container parameter.",
                    ));
                }
            };
            let name = c.name.clone().unwrap_or_default();
            Ok((name.clone(), rec.runtime_ids.get(&name).cloned(), c.container_arn.clone(), rec.credentials.clone()))
        })?;
        // The SSM agent in the task opens its Session Manager channels with
        // the task role: without `ssmmessages:*` it never connects.
        if let Some(p) = self.platform() {
            let connected = credentials
                .map(|c| crate::platform::RoleCredentials {
                    access_key_id: c.access_key_id,
                    secret_access_key: c.secret_access_key,
                    session_token: c.session_token,
                    expiration: c.expiration.unwrap_or(ctx.received_at),
                })
                .and_then(|c| p.role_context(ctx, &c))
                .is_some_and(|role| session_channels_allowed(&role));
            if !connected {
                return Err(crate::generated::errors::target_not_connected(
                    "The execute command failed due to an internal error. Try again later.",
                ));
            }
        }
        // There is no Session Manager to attach to: the command runs once
        // in the container, and the session describes where AWS would
        // stream it.
        if let Some(id) = runtime_id {
            let backend = self.backend();
            let command = input.command.clone();
            tokio::spawn(async move {
                if let Err(e) = backend.exec(&id, &command).await {
                    tracing::debug!("ExecuteCommand: {e}");
                }
            });
        }
        let session_id = format!("ecs-execute-command-{}", hex_id());
        Ok(t::ExecuteCommandResponse {
            cluster_arn: Some(scope.cluster_arn(&cluster)),
            container_arn,
            container_name: Some(container),
            interactive: true,
            session: Some(t::Session {
                session_id: Some(session_id.clone()),
                stream_url: Some(format!(
                    "wss://ssmmessages.{}.amazonaws.com/v1/data-channel/{session_id}?role=publish_subscribe&cell-number=AAEAAQ",
                    scope.region
                )),
                token_value: Some(format!("AAEAA{}", hex_id())),
            }),
            task_arn: Some(arn),
        })
    }

    pub(crate) fn submit_task_state_change_op(
        &self,
        ctx: &RequestContext,
        input: t::SubmitTaskStateChangeRequest,
    ) -> Result<t::SubmitTaskStateChangeResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        authorize(ctx, "SubmitTaskStateChange", &scope.cluster_arn(&cluster), Cond::new())?;
        self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            let Some(reference) = input.task.as_deref() else { return Ok(()) };
            let arn = task_arn(&scope, &cluster, last_segment(reference));
            let rec = r.tasks.get_mut(&arn).ok_or_else(|| invalid("The referenced task was not found."))?;
            for c in input.containers.iter().flatten() {
                if let Some(cont) = rec.task.containers.iter_mut().flatten().find(|x| x.name == c.container_name) {
                    if c.status.is_some() {
                        cont.last_status = c.status.clone();
                    }
                    if c.exit_code.is_some() {
                        cont.exit_code = c.exit_code;
                    }
                    if c.reason.is_some() {
                        cont.reason = c.reason.clone();
                    }
                    if c.runtime_id.is_some() {
                        cont.runtime_id = c.runtime_id.clone();
                    }
                    if c.image_digest.is_some() {
                        cont.image_digest = c.image_digest.clone();
                    }
                    if c.network_bindings.is_some() {
                        cont.network_bindings = c.network_bindings.clone();
                    }
                }
            }
            for a in input.attachments.iter().flatten() {
                for att in rec.task.attachments.iter_mut().flatten() {
                    if a.attachment_arn.ends_with(att.id.as_deref().unwrap_or("~")) {
                        att.status = Some(a.status.clone());
                    }
                }
            }
            if input.pull_started_at.is_some() {
                rec.task.pull_started_at = input.pull_started_at;
            }
            if input.pull_stopped_at.is_some() {
                rec.task.pull_stopped_at = input.pull_stopped_at;
            }
            if input.execution_stopped_at.is_some() {
                rec.task.execution_stopped_at = input.execution_stopped_at;
            }
            if let Some(status) = &input.status {
                match status.as_str() {
                    "RUNNING" => {
                        rec.task.last_status = Some("RUNNING".into());
                        rec.task.started_at.get_or_insert(ctx.received_at);
                        rec.reached_running = true;
                    }
                    "STOPPED" => crate::runner::finish_stopped(rec, ctx.received_at, input.reason.clone()),
                    s => rec.task.last_status = Some(s.to_string()),
                }
            }
            rec.task.version += 1;
            Ok(())
        })?;
        Ok(t::SubmitTaskStateChangeResponse { acknowledgment: Some("ACK".into()) })
    }

    pub(crate) fn submit_container_state_change_op(
        &self,
        ctx: &RequestContext,
        input: t::SubmitContainerStateChangeRequest,
    ) -> Result<t::SubmitContainerStateChangeResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        authorize(ctx, "SubmitContainerStateChange", &scope.cluster_arn(&cluster), Cond::new())?;
        self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            let Some(reference) = input.task.as_deref() else { return Ok(()) };
            let arn = task_arn(&scope, &cluster, last_segment(reference));
            let rec = r.tasks.get_mut(&arn).ok_or_else(|| invalid("The referenced task was not found."))?;
            if let Some(c) = rec.task.containers.iter_mut().flatten().find(|c| c.name == input.container_name) {
                if input.status.is_some() {
                    c.last_status = input.status.clone();
                }
                if input.exit_code.is_some() {
                    c.exit_code = input.exit_code;
                }
                if input.reason.is_some() {
                    c.reason = input.reason.clone();
                }
                if input.runtime_id.is_some() {
                    c.runtime_id = input.runtime_id.clone();
                }
                if input.network_bindings.is_some() {
                    c.network_bindings = input.network_bindings.clone();
                }
            }
            rec.task.version += 1;
            Ok(())
        })?;
        Ok(t::SubmitContainerStateChangeResponse { acknowledgment: Some("ACK".into()) })
    }

    pub(crate) fn submit_attachment_state_changes_op(
        &self,
        ctx: &RequestContext,
        input: t::SubmitAttachmentStateChangesRequest,
    ) -> Result<t::SubmitAttachmentStateChangesResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        authorize(ctx, "SubmitAttachmentStateChanges", &scope.cluster_arn(&cluster), Cond::new())?;
        self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            for a in &input.attachments {
                let id = last_segment(&a.attachment_arn).to_string();
                for rec in r.tasks.values_mut().filter(|t| t.cluster == cluster) {
                    for att in rec.task.attachments.iter_mut().flatten() {
                        if att.id.as_deref() == Some(id.as_str()) {
                            att.status = Some(a.status.clone());
                        }
                    }
                }
            }
            Ok(())
        })?;
        Ok(t::SubmitAttachmentStateChangesResponse { acknowledgment: Some("ACK".into()) })
    }
}

/// A task as DescribeTasks shows it.
pub fn render(r: &Region, rec: &TaskRecord, with_tags: bool) -> t::Task {
    let mut task = rec.task.clone();
    task.tags =
        with_tags.then(|| r.tags.get(task.task_arn.as_deref().unwrap_or_default()).cloned().unwrap_or_default());
    task
}

/// Tags a new task gets: its own, plus the service's or task definition's
/// when `propagate_tags` says so.
pub fn propagated_tags(
    r: &Region,
    def: &t::TaskDefinition,
    propagate: Option<&str>,
    tags: Option<&Vec<t::Tag>>,
    service_arn: Option<&str>,
) -> Vec<t::Tag> {
    let mut out: Vec<t::Tag> = Vec::new();
    let source = match propagate {
        Some("TASK_DEFINITION") => r.tags.get(def.task_definition_arn.as_deref().unwrap_or_default()).cloned(),
        Some("SERVICE") => service_arn.and_then(|s| r.tags.get(s).cloned()),
        _ => None,
    };
    for t in source.into_iter().flatten().chain(tags.cloned().into_iter().flatten()) {
        out.retain(|x| x.key != t.key);
        out.push(t);
    }
    out
}

/// Network details when no EC2 is wired in.
fn made_up_interface(conf: &t::AwsVpcConfiguration) -> TaskInterface {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let ip = format!("10.0.{}.{}", rng.gen_range(0..255), rng.gen_range(4..250));
    let mac: Vec<String> = (0..6).map(|i| format!("{:02x}", if i == 0 { 0x0a } else { rng.gen::<u8>() })).collect();
    TaskInterface {
        eni_id: format!("eni-{:017x}", rng.gen::<u64>()),
        private_dns_name: format!("ip-{}.ec2.internal", ip.replace('.', "-")),
        private_ip: ip,
        mac_address: mac.join(":"),
        subnet_id: conf.subnets.first().cloned().unwrap_or_default(),
        vpc_id: String::new(),
        vpc_cidr: String::new(),
        availability_zone: String::new(),
    }
}

pub fn account_of_arn(arn: &str) -> String {
    arn.split(':').nth(4).unwrap_or_default().to_string()
}

pub fn region_of_arn(arn: &str) -> String {
    arn.split(':').nth(3).unwrap_or_default().to_string()
}

/// Whether a task role session may open the Session Manager channels the
/// SSM agent needs for `ExecuteCommand`.
fn session_channels_allowed(role: &RequestContext) -> bool {
    ["CreateControlChannel", "CreateDataChannel", "OpenControlChannel", "OpenDataChannel"]
        .iter()
        .all(|a| role.authorize(&format!("ssmmessages:{a}"), "*", mws_core::ConditionContext::new()).is_ok())
}
