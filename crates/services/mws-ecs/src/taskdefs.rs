//! Task definitions: registration with ECS's validation and defaults,
//! revisions, deregistration and deletion.

use mws_core::{RequestContext, ServiceError};

use crate::generated::types as t;
use crate::names::{
    authorize, check_tags, client, failure, invalid, normalize_cpu, normalize_memory, paginate, request_tags,
    resource_tags, split_arn, Cond, Scope,
};
use crate::state::Region;
use crate::{tags, Ecs};

/// `(family, revision)` of a task definition reference: `family`,
/// `family:revision` or an ARN.
pub fn parse_ref(reference: &str) -> (String, Option<i32>) {
    let body = match split_arn(reference) {
        Some((_, _, res)) => res.strip_prefix("task-definition/").unwrap_or(res),
        None => reference,
    };
    match body.rsplit_once(':') {
        Some((family, rev)) => match rev.parse() {
            Ok(n) => (family.to_string(), Some(n)),
            Err(_) => (body.to_string(), None),
        },
        None => (body.to_string(), None),
    }
}

/// The task definition a reference names: a family alone means its latest
/// `ACTIVE` revision.
pub fn resolve<'a>(r: &'a Region, reference: &str) -> Option<&'a t::TaskDefinition> {
    let (family, rev) = parse_ref(reference);
    let revisions = r.task_definitions.get(&family)?;
    match rev {
        Some(n) => revisions.get((n - 1).max(0) as usize).filter(|d| d.revision == n),
        None => revisions.iter().rev().find(|d| d.status.as_deref() == Some("ACTIVE")),
    }
}

pub fn valid_family(f: &str) -> bool {
    !f.is_empty() && f.len() <= 255 && f.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Fargate's task size combinations.
pub fn fargate_size_ok(cpu: u64, memory: u64) -> bool {
    let range = |lo: u64, hi: u64, step: u64| memory >= lo && memory <= hi && (memory - lo).is_multiple_of(step);
    match cpu {
        256 => [512, 1024, 2048].contains(&memory),
        512 => range(1024, 4096, 1024),
        1024 => range(2048, 8192, 1024),
        2048 => range(4096, 16384, 1024),
        4096 => range(8192, 30720, 1024),
        8192 => range(16384, 61440, 4096),
        16384 => range(32768, 122880, 8192),
        _ => false,
    }
}

fn attr(name: &str) -> t::Attribute {
    t::Attribute { name: name.into(), ..Default::default() }
}

/// What a container definition looks like once ECS has filled in its
/// defaults.
fn with_defaults(mut c: t::ContainerDefinition, awsvpc: bool) -> t::ContainerDefinition {
    c.essential.get_or_insert(true);
    let mappings = c.port_mappings.get_or_insert_with(Vec::new);
    for m in mappings.iter_mut() {
        m.protocol.get_or_insert_with(|| "tcp".into());
        if awsvpc && m.host_port.is_none() && m.container_port_range.is_none() {
            m.host_port = m.container_port;
        }
    }
    c.environment.get_or_insert_with(Vec::new);
    c.mount_points.get_or_insert_with(Vec::new);
    c.volumes_from.get_or_insert_with(Vec::new);
    c.system_controls.get_or_insert_with(Vec::new);
    c
}

/// The checks RegisterTaskDefinition makes, and the attributes the
/// definition will require of container instances.
fn validate(input: &t::RegisterTaskDefinitionRequest) -> Result<(Vec<t::Attribute>, Vec<String>), ServiceError> {
    if !valid_family(&input.family) {
        return Err(client(
            "Family contains invalid characters. Up to 255 letters (uppercase and lowercase), numbers, hyphens, and underscores are allowed.",
        ));
    }
    if input.container_definitions.is_empty() {
        return Err(client("Container list cannot be empty."));
    }
    let network = input.network_mode.as_deref().unwrap_or("bridge");
    let fargate = input.requires_compatibilities.iter().flatten().any(|c| c == "FARGATE");
    let mut names = Vec::new();
    let mut required = Vec::new();
    let mut need = |a: &str| {
        if !required.contains(&a.to_string()) {
            required.push(a.to_string());
        }
    };
    need("com.amazonaws.ecs.capability.docker-remote-api.1.18");
    for c in &input.container_definitions {
        let name = c.name.as_deref().unwrap_or_default();
        if name.is_empty() {
            return Err(client("Container.name should not be null or empty."));
        }
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') || name.len() > 255 {
            return Err(client(format!(
                "Container name '{name}' is invalid. Up to 255 letters (uppercase and lowercase), numbers, hyphens, and underscores are allowed."
            )));
        }
        if names.contains(&name) {
            return Err(client(format!("Duplicate container name found: '{name}'.")));
        }
        names.push(name);
        if c.image.as_deref().unwrap_or_default().is_empty() {
            return Err(client("Container.image should not be null or empty."));
        }
        if !fargate && input.memory.is_none() && c.memory.is_none() && c.memory_reservation.is_none() {
            return Err(client(format!(
                "Invalid setting for container '{name}'. At least one of 'memory' or 'memoryReservation' must be specified."
            )));
        }
        if let (Some(m), Some(res)) = (c.memory, c.memory_reservation) {
            if m < res {
                return Err(client(format!(
                    "Invalid setting for container '{name}'. 'memory' must be greater than or equal to 'memoryReservation'."
                )));
            }
        }
        if c.memory.is_some_and(|m| m < 6) {
            return Err(client(format!(
                "Invalid 'memory' setting for container '{name}'. The minimum memory value for a container is 6 MiB."
            )));
        }
        for m in c.port_mappings.iter().flatten() {
            if network == "awsvpc" || network == "host" {
                if let (Some(h), Some(cp)) = (m.host_port, m.container_port) {
                    if h != cp {
                        return Err(client(format!(
                            "When networkMode={network}, the host ports and container ports in port mappings must match."
                        )));
                    }
                }
            }
        }
        if let Some(lc) = &c.log_configuration {
            need(&format!("com.amazonaws.ecs.capability.logging-driver.{}", lc.log_driver));
            if lc.log_driver == "awslogs" {
                need("com.amazonaws.ecs.capability.docker-remote-api.1.19");
                if input.execution_role_arn.is_some() {
                    need("ecs.capability.execution-role-awslogs");
                }
                if fargate && input.execution_role_arn.is_none() {
                    return Err(client(
                        "Fargate requires task definition to have execution role ARN to support log driver awslogs.",
                    ));
                }
            }
        }
        if c.image.as_deref().is_some_and(|i| i.contains(".dkr.ecr.")) {
            need("com.amazonaws.ecs.capability.ecr-auth");
            if input.execution_role_arn.is_some() {
                need("ecs.capability.execution-role-ecr-pull");
            }
        }
        for s in c.secrets.iter().flatten() {
            if input.execution_role_arn.is_none() {
                return Err(client(
                    "When you are specifying container secrets, you must also specify a value for 'executionRoleArn'.",
                ));
            }
            if s.value_from.contains(":secretsmanager:") {
                need("ecs.capability.secrets.asm.environment-variables");
            } else {
                need("ecs.capability.secrets.ssm.environment-variables");
            }
        }
        if c.health_check.is_some() {
            need("ecs.capability.container-health-check");
        }
        if c.depends_on.as_ref().is_some_and(|d| !d.is_empty()) {
            need("ecs.capability.container-ordering");
        }
        if c.environment_files.as_ref().is_some_and(|f| !f.is_empty()) {
            need("ecs.capability.env-files.s3");
        }
        if c.repository_credentials.is_some() {
            need("com.amazonaws.ecs.capability.private-registry-authentication.secretsmanager");
        }
    }
    for c in &input.container_definitions {
        for d in c.depends_on.iter().flatten() {
            if !names.contains(&d.container_name.as_str()) {
                return Err(client(format!(
                    "Container '{}' has a dependency on container '{}', which does not exist in the task definition.",
                    c.name.as_deref().unwrap_or_default(),
                    d.container_name
                )));
            }
        }
        for link in c.links.iter().flatten() {
            if network == "awsvpc" {
                return Err(client("Links are not supported when networkMode=awsvpc."));
            }
            let target = link.split(':').next().unwrap_or_default();
            if !names.contains(&target) {
                return Err(client(format!("Container link references unknown container '{target}'.")));
            }
        }
        let volume_names: Vec<&str> = input.volumes.iter().flatten().filter_map(|v| v.name.as_deref()).collect();
        for mp in c.mount_points.iter().flatten() {
            let src = mp.source_volume.as_deref().unwrap_or_default();
            if !volume_names.contains(&src) {
                return Err(client(format!(
                    "Invalid 'mountPoints' setting for container '{}'. Unknown volume '{src}'.",
                    c.name.as_deref().unwrap_or_default()
                )));
            }
        }
    }
    if !input.container_definitions.iter().any(|c| c.essential.unwrap_or(true)) {
        return Err(client("A task definition must have at least one essential container."));
    }
    if network == "awsvpc" {
        need("ecs.capability.task-eni");
    }
    if input.task_role_arn.is_some() {
        need("com.amazonaws.ecs.capability.task-iam-role");
        if network == "host" {
            need("com.amazonaws.ecs.capability.task-iam-role-network-host");
        }
    }
    if input.execution_role_arn.is_some() && input.container_definitions.iter().any(|c| c.secrets.is_some()) {
        need("ecs.capability.execution-role-ecr-pull");
    }
    let mut compat = vec!["EC2".to_string()];
    let fargate_ok = network == "awsvpc"
        && match (input.cpu.as_deref().and_then(normalize_cpu), input.memory.as_deref().and_then(normalize_memory)) {
            (Some(c), Some(m)) => fargate_size_ok(c.parse().unwrap_or(0), m.parse().unwrap_or(0)),
            _ => false,
        };
    if fargate {
        if network != "awsvpc" {
            return Err(client("Fargate only supports network mode 'awsvpc'."));
        }
        let (Some(cpu), Some(mem)) = (input.cpu.as_deref(), input.memory.as_deref()) else {
            return Err(client("Fargate requires that 'cpu' be defined at the task level."));
        };
        let cpu_n = normalize_cpu(cpu).and_then(|c| c.parse::<u64>().ok());
        let mem_n = normalize_memory(mem).and_then(|m| m.parse::<u64>().ok());
        if !cpu_n.zip(mem_n).is_some_and(|(c, m)| fargate_size_ok(c, m)) {
            return Err(client(format!(
                "No Fargate configuration exists for given values: {} CPU, {} memory. See the Amazon ECS documentation for the valid values.",
                cpu_n.map(|c| c.to_string()).unwrap_or_else(|| cpu.into()),
                mem_n.map(|m| m.to_string()).unwrap_or_else(|| mem.into()),
            )));
        }
        for c in &input.container_definitions {
            if c.links.as_ref().is_some_and(|l| !l.is_empty()) || c.privileged == Some(true) {
                return Err(client(format!(
                    "Task definition does not support launch_type FARGATE. Container '{}' uses settings Fargate does not support.",
                    c.name.as_deref().unwrap_or_default()
                )));
            }
        }
        for v in input.volumes.iter().flatten() {
            if v.host.as_ref().is_some_and(|h| h.source_path.is_some()) || v.docker_volume_configuration.is_some() {
                return Err(client("Fargate does not support host or Docker volumes with a source path."));
            }
        }
    }
    if fargate_ok {
        compat.push("FARGATE".into());
    }
    if matches!(network, "bridge" | "host" | "none") {
        compat.push("EXTERNAL".into());
    }
    if matches!(network, "awsvpc" | "host") {
        compat.push("MANAGED_INSTANCES".into());
    }
    for rc in input.requires_compatibilities.iter().flatten() {
        if !compat.contains(rc) {
            return Err(client(format!("Task definition does not support launch_type {rc}.")));
        }
    }
    Ok((required.into_iter().map(|a| attr(&a)).collect(), compat))
}

/// A task definition as Describe returns it, without the parts only some
/// calls include.
pub fn render(d: &t::TaskDefinition) -> t::TaskDefinition {
    d.clone()
}

impl Ecs {
    pub(crate) fn register_task_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::RegisterTaskDefinitionRequest,
    ) -> Result<t::RegisterTaskDefinitionResponse, ServiceError> {
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let scope = Scope::of(ctx);
        let family_arn = scope.arn(&format!("task-definition/{}:*", input.family));
        authorize(ctx, "RegisterTaskDefinition", &family_arn, Cond::new().extend(request_tags(input.tags.as_ref())))?;
        let (requires_attributes, compatibilities) = validate(&input)?;
        let cpu = match input.cpu.as_deref() {
            Some(c) => Some(normalize_cpu(c).ok_or_else(|| client(format!("Invalid 'cpu' setting for task: {c}.")))?),
            None => None,
        };
        let memory = match input.memory.as_deref() {
            Some(m) => {
                Some(normalize_memory(m).ok_or_else(|| client(format!("Invalid 'memory' setting for task: {m}.")))?)
            }
            None => None,
        };
        let awsvpc = input.network_mode.as_deref() == Some("awsvpc");
        self.with_region(ctx, |r, scope| {
            let revisions = r.task_definitions.entry(input.family.clone()).or_default();
            let revision = revisions.len() as i32 + 1;
            let arn = scope.arn(&format!("task-definition/{}:{revision}", input.family));
            let def = t::TaskDefinition {
                task_definition_arn: Some(arn.clone()),
                container_definitions: Some(
                    input.container_definitions.iter().cloned().map(|c| with_defaults(c, awsvpc)).collect(),
                ),
                family: Some(input.family.clone()),
                task_role_arn: input.task_role_arn.clone(),
                execution_role_arn: input.execution_role_arn.clone(),
                network_mode: input.network_mode.clone(),
                revision,
                volumes: Some(input.volumes.clone().unwrap_or_default()),
                status: Some("ACTIVE".into()),
                requires_attributes: Some(requires_attributes),
                placement_constraints: Some(input.placement_constraints.clone().unwrap_or_default()),
                compatibilities: Some(compatibilities),
                runtime_platform: input.runtime_platform.clone(),
                requires_compatibilities: input.requires_compatibilities.clone(),
                cpu,
                memory,
                inference_accelerators: input.inference_accelerators.clone(),
                pid_mode: input.pid_mode.clone(),
                ipc_mode: input.ipc_mode.clone(),
                proxy_configuration: input.proxy_configuration.clone(),
                registered_at: Some(ctx.received_at),
                deregistered_at: None,
                delete_requested_at: None,
                registered_by: Some(ctx.caller.arn.clone()),
                ephemeral_storage: input.ephemeral_storage.clone(),
                enable_fault_injection: Some(input.enable_fault_injection.unwrap_or(false)),
            };
            revisions.push(def.clone());
            tags::store(r, &arn, input.tags.as_ref());
            Ok(t::RegisterTaskDefinitionResponse {
                task_definition: Some(render(&def)),
                tags: Some(input.tags.clone().unwrap_or_default()),
            })
        })
    }

    pub(crate) fn describe_task_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTaskDefinitionRequest,
    ) -> Result<t::DescribeTaskDefinitionResponse, ServiceError> {
        authorize(ctx, "DescribeTaskDefinition", "*", Cond::new())?;
        self.with_region(ctx, |r, _| {
            let d = resolve(r, &input.task_definition)
                .filter(|d| {
                    d.status.as_deref() != Some("DELETE_IN_PROGRESS") || parse_ref(&input.task_definition).1.is_some()
                })
                .ok_or_else(|| client("Unable to describe task definition."))?;
            let with_tags = input.include.iter().flatten().any(|i| i == "TAGS");
            let tags = with_tags
                .then(|| r.tags.get(d.task_definition_arn.as_deref().unwrap_or_default()).cloned().unwrap_or_default());
            Ok(t::DescribeTaskDefinitionResponse { task_definition: Some(render(d)), tags })
        })
    }

    pub(crate) fn list_task_definitions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListTaskDefinitionsRequest,
    ) -> Result<t::ListTaskDefinitionsResponse, ServiceError> {
        authorize(ctx, "ListTaskDefinitions", "*", Cond::new())?;
        let status = input.status.clone().unwrap_or_else(|| "ACTIVE".into());
        self.with_region(ctx, |r, _| {
            let mut arns: Vec<String> = r
                .task_definitions
                .iter()
                .filter(|(family, _)| input.family_prefix.as_deref().is_none_or(|p| family.starts_with(p)))
                .flat_map(|(_, revs)| revs.iter())
                .filter(|d| d.status.as_deref() == Some(status.as_str()))
                .filter_map(|d| d.task_definition_arn.clone())
                .collect();
            if input.sort.as_deref() == Some("DESC") {
                arns.reverse();
            }
            let (page, next_token) = paginate(&arns, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListTaskDefinitionsResponse { task_definition_arns: Some(page), next_token })
        })
    }

    pub(crate) fn list_task_definition_families_op(
        &self,
        ctx: &RequestContext,
        input: t::ListTaskDefinitionFamiliesRequest,
    ) -> Result<t::ListTaskDefinitionFamiliesResponse, ServiceError> {
        authorize(ctx, "ListTaskDefinitionFamilies", "*", Cond::new())?;
        let status = input.status.clone().unwrap_or_else(|| "ALL".into());
        self.with_region(ctx, |r, _| {
            let families: Vec<String> = r
                .task_definitions
                .iter()
                .filter(|(family, _)| input.family_prefix.as_deref().is_none_or(|p| family.starts_with(p)))
                .filter(|(_, revs)| {
                    let active = revs.iter().any(|d| d.status.as_deref() == Some("ACTIVE"));
                    match status.as_str() {
                        "ACTIVE" => active,
                        "INACTIVE" => !active,
                        _ => true,
                    }
                })
                .map(|(f, _)| f.clone())
                .collect();
            let (page, next_token) = paginate(&families, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListTaskDefinitionFamiliesResponse { families: Some(page), next_token })
        })
    }

    pub(crate) fn deregister_task_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::DeregisterTaskDefinitionRequest,
    ) -> Result<t::DeregisterTaskDefinitionResponse, ServiceError> {
        let (family, rev) = parse_ref(&input.task_definition);
        let Some(rev) = rev else {
            return Err(invalid("Invalid revision number. Number: "));
        };
        let scope = Scope::of(ctx);
        let arn = scope.arn(&format!("task-definition/{family}:{rev}"));
        let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(ctx, "DeregisterTaskDefinition", "*", Cond::new().extend(resource_tags(tags.as_ref())))?;
        self.with_region(ctx, |r, _| {
            let d = r
                .task_definitions
                .get_mut(&family)
                .and_then(|revs| revs.get_mut((rev - 1).max(0) as usize))
                .filter(|d| d.revision == rev && d.status.as_deref() != Some("DELETE_IN_PROGRESS"))
                .ok_or_else(|| client("The specified task definition does not exist."))?;
            if d.status.as_deref() == Some("ACTIVE") {
                d.status = Some("INACTIVE".into());
                d.deregistered_at = Some(ctx.received_at);
            }
            Ok(t::DeregisterTaskDefinitionResponse { task_definition: Some(render(d)) })
        })
    }

    pub(crate) fn delete_task_definitions_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTaskDefinitionsRequest,
    ) -> Result<t::DeleteTaskDefinitionsResponse, ServiceError> {
        if input.task_definitions.is_empty() || input.task_definitions.len() > 10 {
            return Err(invalid("The number of task definitions must be between 1 and 10."));
        }
        let scope = Scope::of(ctx);
        let mut deleted = Vec::new();
        let mut failures = Vec::new();
        for reference in &input.task_definitions {
            let (family, rev) = parse_ref(reference);
            let Some(rev) = rev else {
                failures.push(failure(
                    reference.clone(),
                    "The specified task definition identifier is invalid. Specify a valid name or ARN and try again.",
                ));
                continue;
            };
            let arn = scope.arn(&format!("task-definition/{family}:{rev}"));
            let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
            authorize(ctx, "DeleteTaskDefinitions", &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
            self.with_region(ctx, |r, _| {
                let d = r
                    .task_definitions
                    .get_mut(&family)
                    .and_then(|revs| revs.get_mut((rev - 1).max(0) as usize))
                    .filter(|d| d.revision == rev);
                match d {
                    None => failures.push(failure(arn.clone(), "The specified task definition does not exist. Specify a valid account, family, revision and try again.")),
                    Some(d) if d.status.as_deref() == Some("ACTIVE") => failures.push(failure(
                        arn.clone(),
                        "The specified task definition is still in ACTIVE status. Please deregister the target and try again.",
                    )),
                    Some(d) if d.status.as_deref() == Some("DELETE_IN_PROGRESS") => failures.push(failure(
                        arn.clone(),
                        "The specified task definition is already in DELETE_IN_PROGRESS status.",
                    )),
                    Some(d) => {
                        d.status = Some("DELETE_IN_PROGRESS".into());
                        d.delete_requested_at = Some(ctx.received_at);
                        deleted.push(render(d));
                    }
                }
            });
        }
        Ok(t::DeleteTaskDefinitionsResponse { task_definitions: Some(deleted), failures: Some(failures) })
    }
}
