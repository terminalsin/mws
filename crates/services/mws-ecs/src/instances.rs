//! Container instances (what the ECS agent registers), their resources and
//! attributes, draining, and the agent's endpoint discovery.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types as t};
use crate::names::{
    authorize, check_tags, cluster_name, failure, hex_id, invalid, last_segment, paginate, request_tags,
    resource_tags, Cond, Scope,
};
use crate::state::{InstanceRecord, Region};
use crate::{clusters, tags, tasks, Ecs};

pub fn instance_arn(scope: &Scope, cluster: &str, id: &str) -> String {
    scope.arn(&format!("container-instance/{cluster}/{id}"))
}

fn resource_int(name: &str, v: i32) -> t::Resource {
    t::Resource { name: Some(name.into()), r#type: Some("INTEGER".into()), integer_value: v, ..Default::default() }
}

fn resource_set(name: &str, v: Vec<String>) -> t::Resource {
    t::Resource { name: Some(name.into()), r#type: Some("STRINGSET".into()), string_set_value: Some(v), ..Default::default() }
}

fn registered(inst: &t::ContainerInstance, name: &str) -> Option<t::Resource> {
    inst.registered_resources.iter().flatten().find(|r| r.name.as_deref() == Some(name)).cloned()
}

/// Remaining CPU, memory and the host ports in use on an instance.
pub fn remaining(r: &Region, arn: &str, inst: &InstanceRecord) -> (i64, i64, Vec<i32>) {
    let cpu = registered(&inst.instance, "CPU").map(|r| r.integer_value as i64).unwrap_or(0);
    let mem = registered(&inst.instance, "MEMORY").map(|r| r.integer_value as i64).unwrap_or(0);
    let mut ports: Vec<i32> = registered(&inst.instance, "PORTS")
        .and_then(|r| r.string_set_value)
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p.parse().ok())
        .collect();
    let (mut used_cpu, mut used_mem) = (0, 0);
    for task in r.tasks.values().filter(|t| t.task.container_instance_arn.as_deref() == Some(arn)) {
        if task.task.last_status.as_deref() == Some("STOPPED") {
            continue;
        }
        let (c, m) = tasks::task_resources(&task.definition);
        used_cpu += c;
        used_mem += m;
        for c in task.definition.container_definitions.iter().flatten() {
            for pm in c.port_mappings.iter().flatten() {
                if let Some(p) = pm.host_port.filter(|p| *p > 0) {
                    ports.push(p);
                }
            }
        }
    }
    (cpu - used_cpu, mem - used_mem, ports)
}

/// Built-in and custom attributes of an instance.
pub fn all_attributes(r: &Region, inst: &InstanceRecord) -> Vec<t::Attribute> {
    let mut out = inst.instance.attributes.clone().unwrap_or_default();
    let key = format!("{}|{}", inst.cluster, inst.instance.container_instance_arn.as_deref().unwrap_or_default());
    if let Some(custom) = r.attributes.get(&key) {
        for a in custom.values() {
            out.retain(|x| x.name != a.name);
            out.push(t::Attribute { name: a.name.clone(), value: a.value.clone(), target_type: None, target_id: None });
        }
    }
    out
}

pub fn attribute_value(r: &Region, inst: &InstanceRecord, name: &str) -> Option<String> {
    all_attributes(r, inst).into_iter().find(|a| a.name == name).and_then(|a| a.value)
}

fn render(r: &Region, arn: &str, inst: &InstanceRecord, with_tags: bool) -> t::ContainerInstance {
    let mut out = inst.instance.clone();
    let (cpu, mem, ports) = remaining(r, arn, inst);
    out.remaining_resources = Some(vec![
        resource_int("CPU", cpu as i32),
        resource_int("MEMORY", mem as i32),
        resource_set("PORTS", ports.iter().map(|p| p.to_string()).collect()),
        resource_set(
            "PORTS_UDP",
            registered(&inst.instance, "PORTS_UDP").and_then(|r| r.string_set_value).unwrap_or_default(),
        ),
    ]);
    let on: Vec<_> = r
        .tasks
        .values()
        .filter(|t| t.task.container_instance_arn.as_deref() == Some(arn))
        .filter(|t| t.task.last_status.as_deref() != Some("STOPPED"))
        .collect();
    out.running_tasks_count = on.iter().filter(|t| t.task.last_status.as_deref() == Some("RUNNING")).count() as i32;
    out.pending_tasks_count = on.iter().filter(|t| t.task.last_status.as_deref() != Some("RUNNING")).count() as i32;
    out.attributes = Some(all_attributes(r, inst));
    out.tags = with_tags.then(|| r.tags.get(arn).cloned().unwrap_or_default());
    out
}

/// What the instance identity document says.
fn identity(doc: Option<&str>) -> BTreeMap<String, String> {
    let Some(v) = doc.and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok()) else { return BTreeMap::new() };
    let mut out = BTreeMap::new();
    if let Some(o) = v.as_object() {
        for (k, v) in o {
            if let Some(s) = v.as_str() {
                out.insert(k.clone(), s.to_string());
            }
        }
    }
    out
}

impl Ecs {
    fn instance_ref(&self, ctx: &RequestContext, cluster_ref: Option<&str>, reference: &str) -> (String, String) {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(cluster_ref);
        let arn = instance_arn(&scope, &cluster, last_segment(reference));
        (cluster, arn)
    }

    pub(crate) fn register_container_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::RegisterContainerInstanceRequest,
    ) -> Result<t::RegisterContainerInstanceResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        authorize(
            ctx,
            "RegisterContainerInstance",
            &scope.cluster_arn(&cluster),
            Cond::new().extend(request_tags(input.tags.as_ref())),
        )?;
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let now = ctx.received_at;
        let out = self.with_region(ctx, |r, scope| {
            clusters::active(r, input.cluster.as_deref())?;
            let doc = identity(input.instance_identity_document.as_deref());
            let ec2_id = doc.get("instanceId").cloned().unwrap_or_else(|| format!("i-{}", &hex_id()[..17]));
            let arn = match &input.container_instance_arn {
                Some(a) => instance_arn(scope, &cluster, last_segment(a)),
                None => r
                    .container_instances
                    .iter()
                    .find(|(_, i)| {
                        i.cluster == cluster
                            && i.instance.ec2_instance_id.as_deref() == Some(ec2_id.as_str())
                            && i.instance.status.as_deref() != Some("INACTIVE")
                    })
                    .map(|(a, _)| a.clone())
                    .unwrap_or_else(|| instance_arn(scope, &cluster, &hex_id())),
            };
            let resources = input.total_resources.clone().unwrap_or_else(|| {
                vec![
                    resource_int("CPU", 2048),
                    resource_int("MEMORY", 3943),
                    resource_set("PORTS", ["22", "2375", "2376", "51678", "51679"].map(String::from).to_vec()),
                    resource_set("PORTS_UDP", Vec::new()),
                ]
            });
            let az = doc.get("availabilityZone").cloned().unwrap_or_else(|| format!("{}a", scope.region));
            let mut attrs = vec![
                t::Attribute { name: "ecs.os-type".into(), value: Some("linux".into()), ..Default::default() },
                t::Attribute { name: "ecs.os-family".into(), value: Some("LINUX".into()), ..Default::default() },
                t::Attribute { name: "ecs.availability-zone".into(), value: Some(az), ..Default::default() },
                t::Attribute { name: "ecs.cpu-architecture".into(), value: Some("x86_64".into()), ..Default::default() },
            ];
            if let Some(it) = doc.get("instanceType") {
                attrs.push(t::Attribute { name: "ecs.instance-type".into(), value: Some(it.clone()), ..Default::default() });
            }
            if let Some(ami) = doc.get("imageId") {
                attrs.push(t::Attribute { name: "ecs.ami-id".into(), value: Some(ami.clone()), ..Default::default() });
            }
            for a in input.attributes.iter().flatten() {
                attrs.retain(|x| x.name != a.name);
                attrs.push(t::Attribute { name: a.name.clone(), value: a.value.clone(), ..Default::default() });
            }
            let version = r.container_instances.get(&arn).map(|i| i.instance.version + 1).unwrap_or(1);
            let inst = t::ContainerInstance {
                container_instance_arn: Some(arn.clone()),
                ec2_instance_id: Some(ec2_id),
                capacity_provider_name: None,
                version,
                version_info: Some(input.version_info.clone().unwrap_or(t::VersionInfo {
                    agent_version: Some("1.89.0".into()),
                    agent_hash: Some("mws".into()),
                    docker_version: Some("DockerVersion: 25.0.6".into()),
                })),
                remaining_resources: None,
                registered_resources: Some(resources),
                status: Some("ACTIVE".into()),
                status_reason: None,
                agent_connected: true,
                running_tasks_count: 0,
                pending_tasks_count: 0,
                agent_update_status: None,
                attributes: Some(attrs),
                registered_at: Some(now),
                attachments: Some(Vec::new()),
                tags: None,
                health_status: Some(t::ContainerInstanceHealthStatus {
                    overall_status: Some("OK".into()),
                    details: Some(vec![t::InstanceHealthCheckResult {
                        r#type: Some("CONTAINER_RUNTIME".into()),
                        status: Some("OK".into()),
                        last_updated: Some(now),
                        last_status_change: Some(now),
                        status_reason: None,
                    }]),
                }),
                gpu_devices: None,
            };
            tags::store(r, &arn, input.tags.as_ref());
            r.container_instances.insert(arn.clone(), InstanceRecord { instance: inst, cluster: cluster.clone() });
            Ok(render(r, &arn, &r.container_instances[&arn], false))
        })?;
        self.kick();
        Ok(t::RegisterContainerInstanceResponse { container_instance: Some(out) })
    }

    pub(crate) fn deregister_container_instance_op(
        &self,
        ctx: &RequestContext,
        input: t::DeregisterContainerInstanceRequest,
    ) -> Result<t::DeregisterContainerInstanceResponse, ServiceError> {
        let (cluster, arn) = self.instance_ref(ctx, input.cluster.as_deref(), &input.container_instance);
        let scope = Scope::of(ctx);
        authorize(ctx, "DeregisterContainerInstance", &scope.cluster_arn(&cluster), Cond::new())?;
        let now = ctx.received_at;
        let out = self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            if !r.container_instances.get(&arn).is_some_and(|i| i.instance.status.as_deref() != Some("INACTIVE")) {
                return Err(invalid("The referenced container instance was not found."));
            }
            let on: Vec<String> = r
                .tasks
                .values()
                .filter(|t| t.task.container_instance_arn.as_deref() == Some(arn.as_str()))
                .filter(|t| t.task.desired_status.as_deref() != Some("STOPPED"))
                .filter_map(|t| t.task.task_arn.clone())
                .collect();
            if !on.is_empty() && input.force != Some(true) {
                return Err(invalid("Found running tasks on the instance."));
            }
            for task in &on {
                let service = r.tasks.get(task).and_then(|t| t.service_arn.clone());
                if service.is_some() {
                    self.request_stop(r, task, "ServiceSchedulerInitiated", "Container instance deregistration forced by user", now);
                }
            }
            let rec = r.container_instances.get_mut(&arn).expect("checked above");
            rec.instance.status = Some("INACTIVE".into());
            rec.instance.agent_connected = false;
            rec.instance.version += 1;
            let rec = rec.clone();
            Ok(render(r, &arn, &rec, false))
        })?;
        self.kick();
        Ok(t::DeregisterContainerInstanceResponse { container_instance: Some(out) })
    }

    pub(crate) fn describe_container_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeContainerInstancesRequest,
    ) -> Result<t::DescribeContainerInstancesResponse, ServiceError> {
        if input.container_instances.is_empty() || input.container_instances.len() > 100 {
            return Err(invalid("containerInstances must contain between 1 and 100 container instances."));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        self.with_region(ctx, |r, _| clusters::active(r, input.cluster.as_deref()).map(drop))?;
        let with_tags = input.include.iter().flatten().any(|i| i == "TAGS");
        let with_health = input.include.iter().flatten().any(|i| i == "CONTAINER_INSTANCE_HEALTH");
        let mut out = Vec::new();
        let mut failures = Vec::new();
        for reference in &input.container_instances {
            let arn = instance_arn(&scope, &cluster, last_segment(reference));
            let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
            authorize(ctx, "DescribeContainerInstances", &arn, Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())))?;
            self.with_region(ctx, |r, _| match r.container_instances.get(&arn).filter(|i| i.cluster == cluster) {
                Some(i) => {
                    let mut ci = render(r, &arn, i, with_tags);
                    if !with_health {
                        ci.health_status = None;
                    }
                    out.push(ci);
                }
                None => failures.push(failure(arn.clone(), "MISSING")),
            });
        }
        Ok(t::DescribeContainerInstancesResponse { container_instances: Some(out), failures: Some(failures) })
    }

    pub(crate) fn list_container_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::ListContainerInstancesRequest,
    ) -> Result<t::ListContainerInstancesResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        authorize(ctx, "ListContainerInstances", &scope.cluster_arn(&cluster), Cond::new())?;
        self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            let arns: Vec<String> = r
                .container_instances
                .iter()
                .filter(|(_, i)| i.cluster == cluster)
                .filter(|(_, i)| match input.status.as_deref() {
                    Some(s) => i.instance.status.as_deref() == Some(s),
                    None => i.instance.status.as_deref() != Some("INACTIVE"),
                })
                .filter(|(_, i)| {
                    input.filter.as_deref().is_none_or(|f| {
                        f.split("&&").all(|clause| tasks::constraint_ok(r, i, clause.trim()))
                    })
                })
                .map(|(a, _)| a.clone())
                .collect();
            let (page, next_token) = paginate(&arns, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListContainerInstancesResponse { container_instance_arns: Some(page), next_token })
        })
    }

    pub(crate) fn update_container_instances_state_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateContainerInstancesStateRequest,
    ) -> Result<t::UpdateContainerInstancesStateResponse, ServiceError> {
        if !matches!(input.status.as_str(), "ACTIVE" | "DRAINING") {
            return Err(invalid("Container instances can only be set to ACTIVE or DRAINING."));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        self.with_region(ctx, |r, _| clusters::active(r, input.cluster.as_deref()).map(drop))?;
        let now = ctx.received_at;
        let mut out = Vec::new();
        let mut failures = Vec::new();
        for reference in &input.container_instances {
            let arn = instance_arn(&scope, &cluster, last_segment(reference));
            let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
            authorize(ctx, "UpdateContainerInstancesState", &arn, Cond::new().cluster(&scope, &cluster).extend(resource_tags(tags.as_ref())))?;
            self.with_region(ctx, |r, _| {
                let Some(inst) = r.container_instances.get_mut(&arn).filter(|i| i.cluster == cluster) else {
                    failures.push(failure(arn.clone(), "MISSING"));
                    return;
                };
                if inst.instance.status.as_deref() == Some("INACTIVE") {
                    failures.push(failure(arn.clone(), "INACTIVE"));
                    return;
                }
                inst.instance.status = Some(input.status.clone());
                inst.instance.version += 1;
                if input.status == "DRAINING" {
                    // Service tasks move off a draining instance.
                    let service_tasks: Vec<String> = r
                        .tasks
                        .values()
                        .filter(|t| t.task.container_instance_arn.as_deref() == Some(arn.as_str()))
                        .filter(|t| t.service_arn.is_some() && t.task.desired_status.as_deref() != Some("STOPPED"))
                        .filter_map(|t| t.task.task_arn.clone())
                        .collect();
                    for task in service_tasks {
                        self.request_stop(r, &task, "ServiceSchedulerInitiated", "Container instance is draining", now);
                    }
                }
                let inst = r.container_instances[&arn].clone();
                out.push(render(r, &arn, &inst, false));
            });
        }
        self.kick();
        Ok(t::UpdateContainerInstancesStateResponse { container_instances: Some(out), failures: Some(failures) })
    }

    pub(crate) fn update_container_agent_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateContainerAgentRequest,
    ) -> Result<t::UpdateContainerAgentResponse, ServiceError> {
        let (cluster, arn) = self.instance_ref(ctx, input.cluster.as_deref(), &input.container_instance);
        let scope = Scope::of(ctx);
        authorize(ctx, "UpdateContainerAgent", &arn, Cond::new().cluster(&scope, &cluster))?;
        self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            if !r.container_instances.get(&arn).is_some_and(|i| i.cluster == cluster) {
                return Err(invalid("The referenced container instance was not found."));
            }
            Err(errors::no_update_available("There is no update available for your container instance's agent."))
        })
    }

    pub(crate) fn discover_poll_endpoint_op(
        &self,
        ctx: &RequestContext,
        _input: t::DiscoverPollEndpointRequest,
    ) -> Result<t::DiscoverPollEndpointResponse, ServiceError> {
        authorize(ctx, "DiscoverPollEndpoint", "*", Cond::new())?;
        let region = &ctx.region;
        Ok(t::DiscoverPollEndpointResponse {
            endpoint: Some(format!("https://ecs-a-1.{region}.amazonaws.com/")),
            telemetry_endpoint: Some(format!("https://ecs-t-1.{region}.amazonaws.com/")),
            service_connect_endpoint: Some(format!("https://ecs-sc.{region}.api.aws")),
        })
    }

    pub(crate) fn put_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::PutAttributesRequest,
    ) -> Result<t::PutAttributesResponse, ServiceError> {
        if input.attributes.is_empty() || input.attributes.len() > 10 {
            return Err(invalid("attributes must contain between 1 and 10 attributes."));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        for a in &input.attributes {
            let target = a.target_id.as_deref().unwrap_or_default();
            authorize(ctx, "PutAttributes", &instance_arn(&scope, &cluster, last_segment(target)), Cond::new().cluster(&scope, &cluster))?;
            if a.name.is_empty() || a.name.len() > 128 {
                return Err(invalid("Attribute names must be between 1 and 128 characters."));
            }
        }
        self.with_region(ctx, |r, scope| {
            clusters::active(r, input.cluster.as_deref())?;
            let mut out = Vec::new();
            for a in &input.attributes {
                let Some(target) = a.target_id.as_deref() else {
                    return Err(invalid("targetId is required for container instance attributes."));
                };
                let arn = instance_arn(scope, &cluster, last_segment(target));
                if !r.container_instances.get(&arn).is_some_and(|i| i.cluster == cluster) {
                    return Err(errors::target_not_found(format!("Could not find {target}.")));
                }
                let entry = r.attributes.entry(format!("{cluster}|{arn}")).or_default();
                if !entry.contains_key(&a.name) && entry.len() >= 10 {
                    return Err(errors::attribute_limit_exceeded("You can have a maximum of 10 custom attributes per resource."));
                }
                let stored = t::Attribute {
                    name: a.name.clone(),
                    value: a.value.clone(),
                    target_type: Some("container-instance".into()),
                    target_id: Some(arn.clone()),
                };
                entry.insert(a.name.clone(), stored.clone());
                out.push(stored);
            }
            Ok(t::PutAttributesResponse { attributes: Some(out) })
        })
    }

    pub(crate) fn delete_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteAttributesRequest,
    ) -> Result<t::DeleteAttributesResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        for a in &input.attributes {
            let target = a.target_id.as_deref().unwrap_or_default();
            authorize(ctx, "DeleteAttributes", &instance_arn(&scope, &cluster, last_segment(target)), Cond::new().cluster(&scope, &cluster))?;
        }
        self.with_region(ctx, |r, scope| {
            clusters::active(r, input.cluster.as_deref())?;
            let mut out = Vec::new();
            for a in &input.attributes {
                let Some(target) = a.target_id.as_deref() else {
                    return Err(invalid("targetId is required for container instance attributes."));
                };
                let arn = instance_arn(scope, &cluster, last_segment(target));
                if !r.container_instances.contains_key(&arn) {
                    return Err(errors::target_not_found(format!("Could not find {target}.")));
                }
                if let Some(removed) = r.attributes.get_mut(&format!("{cluster}|{arn}")).and_then(|m| m.remove(&a.name)) {
                    out.push(removed);
                }
            }
            Ok(t::DeleteAttributesResponse { attributes: Some(out) })
        })
    }

    pub(crate) fn list_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::ListAttributesRequest,
    ) -> Result<t::ListAttributesResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        authorize(ctx, "ListAttributes", &scope.cluster_arn(&cluster), Cond::new())?;
        if input.attribute_value.is_some() && input.attribute_name.is_none() {
            return Err(invalid("attributeValue can only be specified together with attributeName."));
        }
        self.with_region(ctx, |r, _| {
            clusters::active(r, input.cluster.as_deref())?;
            let mut out = Vec::new();
            for (arn, inst) in r.container_instances.iter().filter(|(_, i)| i.cluster == cluster) {
                if inst.instance.status.as_deref() == Some("INACTIVE") {
                    continue;
                }
                for a in all_attributes(r, inst) {
                    if input.attribute_name.as_deref().is_some_and(|n| n != a.name) {
                        continue;
                    }
                    if input.attribute_value.is_some() && input.attribute_value != a.value {
                        continue;
                    }
                    out.push(t::Attribute {
                        target_type: Some("container-instance".into()),
                        target_id: Some(arn.clone()),
                        ..a
                    });
                }
            }
            let (page, next_token) = paginate(&out, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListAttributesResponse { attributes: Some(page), next_token })
        })
    }
}
