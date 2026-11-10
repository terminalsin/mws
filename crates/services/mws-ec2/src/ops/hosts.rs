//! Dedicated Hosts: allocated per instance type or family, with
//! auto-placement; `RunInstances` places instances on them
//! (`Placement.HostId` or `Tenancy=host`), and capacity is what the
//! instances on a host leave over.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::pricing::{family_of, host_size};
use crate::state::RegionState;
use crate::util::{
    arn, err, invalid_parameter, missing_parameter, new_id, paginate, request_tag_context, resource_tag_context, s,
    some_tags, tags_for, Filters, Kind,
};
use crate::{account_of, Ec2};

fn unsuccessful(id: &str, code: &str, message: impl Into<String>) -> t::UnsuccessfulItem {
    t::UnsuccessfulItem {
        resource_id: Some(id.into()),
        error: Some(t::UnsuccessfulItemError { code: Some(code.into()), message: Some(message.into()) }),
    }
}

fn vcpus(instance_type: &str) -> i32 {
    crate::catalog::instance_type(instance_type).map(|i| i.vcpus as i32).unwrap_or(1)
}

/// Instances on `host_id` that hold capacity: everything not stopped or
/// terminated.
fn host_instances(r: &RegionState, host_id: &str) -> Vec<t::HostInstance> {
    r.instances
        .values()
        .filter(|i| i.instance.placement.as_ref().and_then(|p| p.host_id.as_deref()) == Some(host_id))
        .filter(|i| {
            !matches!(i.instance.state.as_ref().and_then(|s| s.name.as_deref()), Some("terminated" | "stopped"))
        })
        .map(|i| t::HostInstance {
            instance_id: i.instance.instance_id.clone(),
            instance_type: i.instance.instance_type.clone(),
            owner_id: Some(i.owner_id.clone()),
        })
        .collect()
}

/// How many more `instance_type` instances `host` takes.
fn free_slots(r: &RegionState, host: &t::Host, instance_type: &str) -> usize {
    if host.state.as_deref() != Some("available") {
        return 0;
    }
    let props = host.host_properties.clone().unwrap_or_default();
    let total = props.total_v_cpus.unwrap_or_default();
    let used: i32 = host_instances(r, host.host_id.as_deref().unwrap_or_default())
        .iter()
        .map(|i| vcpus(i.instance_type.as_deref().unwrap_or_default()))
        .sum();
    let fits = match (&props.instance_type, &props.instance_family) {
        (Some(single), _) => single == instance_type,
        (None, Some(family)) => family == family_of(instance_type),
        _ => false,
    };
    if !fits {
        return 0;
    }
    ((total - used).max(0) / vcpus(instance_type)) as usize
}

/// The hosts a launch may use: the named host, or the auto-placement hosts
/// in `zone`.
fn candidates<'a>(
    r: &'a RegionState,
    placement: &t::Placement,
    instance_type: &str,
    zone: &str,
) -> Result<Vec<&'a t::Host>, ServiceError> {
    match &placement.host_id {
        Some(id) => {
            Kind::Host.check(id)?;
            let host = r
                .hosts
                .get(id)
                .filter(|h| h.state.as_deref() != Some("released"))
                .ok_or_else(|| Kind::Host.not_found(id))?;
            if host.availability_zone.as_deref() != Some(zone) {
                return Err(invalid_parameter(format!(
                    "The Dedicated Host {id} is in {} but the instance would launch in {zone}.",
                    host.availability_zone.clone().unwrap_or_default()
                )));
            }
            if free_slots(r, host, instance_type) == 0 && host.state.as_deref() == Some("available") {
                let props = host.host_properties.clone().unwrap_or_default();
                let supported = props.instance_type.clone().or(props.instance_family.clone()).unwrap_or_default();
                if props.instance_type.as_deref().is_some_and(|t| t != instance_type)
                    || props.instance_family.as_deref().is_some_and(|f| f != family_of(instance_type))
                {
                    return Err(invalid_parameter(format!(
                        "The instance type {instance_type} is not supported by Dedicated Host {id}, which supports {supported}."
                    )));
                }
            }
            Ok(vec![host])
        }
        None => Ok(r
            .hosts
            .values()
            .filter(|h| h.auto_placement.as_deref() == Some("on") && h.availability_zone.as_deref() == Some(zone))
            .collect()),
    }
}

/// How many `instance_type` instances the hosts `placement` allows can
/// still take.
pub fn room(r: &RegionState, placement: &t::Placement, instance_type: &str, zone: &str) -> Result<usize, ServiceError> {
    Ok(candidates(r, placement, instance_type, zone)?.into_iter().map(|h| free_slots(r, h, instance_type)).sum())
}

/// The host the next instance goes on (`room` said there is one).
pub fn place(
    r: &RegionState,
    placement: &t::Placement,
    instance_type: &str,
    zone: &str,
) -> Result<String, ServiceError> {
    candidates(r, placement, instance_type, zone)?
        .into_iter()
        .find(|h| free_slots(r, h, instance_type) > 0)
        .and_then(|h| h.host_id.clone())
        .ok_or_else(|| {
            err(
                "InsufficientHostCapacity",
                format!("There is not enough capacity on the Dedicated Hosts to launch an instance of type {instance_type}."),
            )
        })
}

/// A host as `DescribeHosts` shows it: its instances and what is left.
fn render(r: &RegionState, host: &t::Host) -> t::Host {
    let mut h = host.clone();
    let id = h.host_id.clone().unwrap_or_default();
    let instances = if h.state.as_deref() == Some("released") { Vec::new() } else { host_instances(r, &id) };
    let props = h.host_properties.clone().unwrap_or_default();
    let total = props.total_v_cpus.unwrap_or_default();
    let used: i32 = instances.iter().map(|i| vcpus(i.instance_type.as_deref().unwrap_or_default())).sum();
    let types: Vec<&str> = match (&props.instance_type, &props.instance_family) {
        (Some(single), _) => vec![single.as_str()],
        (None, Some(family)) => {
            crate::catalog::INSTANCE_TYPES.iter().filter(|i| family_of(i.name) == family).map(|i| i.name).collect()
        }
        _ => Vec::new(),
    };
    h.available_capacity = Some(t::AvailableCapacity {
        available_instance_capacity: Some(
            types
                .iter()
                .map(|ty| t::InstanceCapacity {
                    instance_type: Some(ty.to_string()),
                    total_capacity: Some(total / vcpus(ty)),
                    available_capacity: Some(((total - used).max(0)) / vcpus(ty)),
                })
                .collect(),
        ),
        available_v_cpus: Some((total - used).max(0)),
    });
    h.instances = Some(instances);
    h
}

impl Ec2 {
    pub(crate) fn allocate_hosts_op(
        &self,
        ctx: &RequestContext,
        input: t::AllocateHostsRequest,
    ) -> Result<t::AllocateHostsResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "dedicated-host", &["dedicated-host"])?;
        let zone = match (&input.availability_zone, &input.availability_zone_id) {
            (Some(z), _) => z.clone(),
            (None, Some(id)) => crate::catalog::zone_name(&ctx.region, id)
                .ok_or_else(|| invalid_parameter(format!("Invalid availability zone id: [{id}]")))?,
            (None, None) => return Err(missing_parameter("AvailabilityZone")),
        };
        let zone_id = crate::catalog::zone_id(&ctx.region, &zone)
            .ok_or_else(|| invalid_parameter(format!("Invalid availability zone: [{zone}]")))?;
        let (family, single) = match (&input.instance_type, &input.instance_family) {
            (Some(_), Some(_)) => {
                return Err(err(
                    "InvalidParameterCombination",
                    "You can specify either an instance type or an instance family, but not both.",
                ))
            }
            (Some(ty), None) => {
                crate::catalog::instance_type(ty)
                    .ok_or_else(|| invalid_parameter(format!("Invalid value '{ty}' for InstanceType.")))?;
                (family_of(ty).to_string(), Some(ty.clone()))
            }
            (None, Some(f)) => (f.clone(), None),
            (None, None) => return Err(missing_parameter("InstanceType or InstanceFamily")),
        };
        let (sockets, cores, total) = host_size(&family).ok_or_else(|| {
            invalid_parameter(format!("Dedicated Hosts are not available for the instance family {family}."))
        })?;
        let quantity = input.quantity.unwrap_or(1);
        if !(1..=100).contains(&quantity) {
            return Err(invalid_parameter(format!("Value ({quantity}) for parameter quantity is invalid.")));
        }
        let check = |name: &str, v: &Option<String>, allowed: &[&str], default: &str| -> Result<String, ServiceError> {
            let v = v.clone().unwrap_or_else(|| default.into());
            if allowed.contains(&v.as_str()) {
                Ok(v)
            } else {
                Err(invalid_parameter(format!("Value ({v}) for parameter {name} is invalid.")))
            }
        };
        let auto = check("autoPlacement", &input.auto_placement, &["on", "off"], "off")?;
        let recovery = check("hostRecovery", &input.host_recovery, &["on", "off"], "off")?;
        let maintenance = check("hostMaintenance", &input.host_maintenance, &["on", "off"], "on")?;
        let account = account_of(ctx);
        self.authorize_known(
            ctx,
            "AllocateHosts",
            &[(arn(ctx, &account, "dedicated-host/*"), request_tag_context(&tags))],
            None,
        )?;
        let now = ctx.received_at;
        let fp = crate::idempotency::fingerprint(&input);
        self.with_region(ctx, |r| {
            crate::idempotency::replay(r, "AllocateHosts", input.client_token.as_deref(), &fp, |_| true)?;
            if let Some(token) = &input.client_token {
                let ids: Vec<String> = r
                    .hosts
                    .values()
                    .filter(|h| h.client_token.as_deref() == Some(token.as_str()))
                    .filter_map(|h| h.host_id.clone())
                    .collect();
                if !ids.is_empty() {
                    return Ok(t::AllocateHostsResult { host_ids: Some(ids) });
                }
            }
            let mut ids = Vec::new();
            for _ in 0..quantity {
                let id = new_id("h");
                r.hosts.insert(
                    id.clone(),
                    t::Host {
                        host_id: Some(id.clone()),
                        auto_placement: Some(auto.clone()),
                        availability_zone: Some(zone.clone()),
                        availability_zone_id: Some(zone_id.clone()),
                        client_token: input.client_token.clone(),
                        host_properties: Some(t::HostProperties {
                            cores: Some(cores),
                            sockets: Some(sockets),
                            total_v_cpus: Some(total),
                            instance_type: single.clone(),
                            instance_family: Some(family.clone()),
                        }),
                        state: Some("available".into()),
                        allocation_time: Some(now),
                        tags: some_tags(tags.clone()),
                        host_recovery: Some(recovery.clone()),
                        allows_multiple_instance_types: Some(if single.is_some() { "off" } else { "on" }.into()),
                        owner_id: Some(account.clone()),
                        member_of_service_linked_resource_group: Some(false),
                        host_maintenance: Some(maintenance.clone()),
                        ..Default::default()
                    },
                );
                ids.push(id);
            }
            crate::idempotency::remember(r, "AllocateHosts", input.client_token.as_deref(), &fp, &ids.join(","));
            Ok(t::AllocateHostsResult { host_ids: Some(ids) })
        })
    }

    pub(crate) fn describe_hosts_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeHostsRequest,
    ) -> Result<t::DescribeHostsResult, ServiceError> {
        self.authorize_known(ctx, "DescribeHosts", &[("*".into(), ConditionContext::new())], None)?;
        let ids = input.host_ids.clone().unwrap_or_default();
        if !ids.is_empty() && input.max_results.is_some() {
            return Err(err(
                "InvalidParameterCombination",
                "The parameter hostSet cannot be used with the parameter maxResults",
            ));
        }
        let filters = Filters::new(&input.filter);
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            // Released hosts stay visible for a while.
            r.hosts.retain(|_, h| {
                h.state.as_deref() != Some("released")
                    || h.release_time.is_none_or(|t| now - t < chrono::Duration::hours(1))
            });
            Kind::Host.check_all(&ids, |id| r.hosts.contains_key(id))?;
            let mut out = Vec::new();
            for h in r.hosts.values() {
                let id = h.host_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let props = h.host_properties.clone().unwrap_or_default();
                let ok = filters.matches(h.tags.as_ref(), |name| {
                    Some(match name {
                        "auto-placement" => s(&h.auto_placement),
                        "availability-zone" => s(&h.availability_zone),
                        "client-token" => s(&h.client_token),
                        "host-reservation-id" => s(&h.host_reservation_id),
                        "instance-type" => s(&props.instance_type),
                        "state" => s(&h.state),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(render(r, h));
                }
            }
            let (hosts, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeHostsResult { hosts: Some(hosts), next_token })
        })
    }

    fn host_resources(&self, ctx: &RequestContext, ids: &[String]) -> Vec<(String, ConditionContext)> {
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            ids.iter()
                .map(|id| {
                    (
                        arn(ctx, &account, &format!("dedicated-host/{id}")),
                        resource_tag_context(r.hosts.get(id).and_then(|h| h.tags.as_ref())),
                    )
                })
                .collect()
        })
    }

    pub(crate) fn modify_hosts_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyHostsRequest,
    ) -> Result<t::ModifyHostsResult, ServiceError> {
        if input.host_ids.is_empty() {
            return Err(missing_parameter("HostIds"));
        }
        if input.instance_type.is_some() && input.instance_family.is_some() {
            return Err(err(
                "InvalidParameterCombination",
                "You can specify either an instance type or an instance family, but not both.",
            ));
        }
        for (name, v) in [
            ("autoPlacement", &input.auto_placement),
            ("hostRecovery", &input.host_recovery),
            ("hostMaintenance", &input.host_maintenance),
        ] {
            if let Some(v) = v {
                if v != "on" && v != "off" {
                    return Err(invalid_parameter(format!("Value ({v}) for parameter {name} is invalid.")));
                }
            }
        }
        self.authorize_known(ctx, "ModifyHosts", &self.host_resources(ctx, &input.host_ids), None)?;
        self.with_region(ctx, |r| {
            let mut ok = Vec::new();
            let mut failed = Vec::new();
            for id in &input.host_ids {
                if Kind::Host.check(id).is_err() {
                    failed.push(unsuccessful(id, "InvalidHostID.Malformed", format!("Invalid id: \"{id}\"")));
                    continue;
                }
                let occupied = !host_instances(r, id).is_empty();
                let Some(h) = r.hosts.get_mut(id).filter(|h| h.state.as_deref() != Some("released")) else {
                    failed.push(unsuccessful(id, "InvalidHostID.NotFound", format!("The host ID '{id}' does not exist")));
                    continue;
                };
                if input.instance_type.is_some() || input.instance_family.is_some() {
                    if occupied {
                        failed.push(unsuccessful(
                            id,
                            "InvalidHost.Occupied",
                            "The instance type or family of a Dedicated Host can be changed only when it has no instances.",
                        ));
                        continue;
                    }
                    let (family, single) = match (&input.instance_type, &input.instance_family) {
                        (Some(ty), _) => (family_of(ty).to_string(), Some(ty.clone())),
                        (None, Some(f)) => (f.clone(), None),
                        _ => unreachable!(),
                    };
                    let Some((sockets, cores, total)) = host_size(&family) else {
                        failed.push(unsuccessful(
                            id,
                            "InvalidParameterValue",
                            format!("Dedicated Hosts are not available for the instance family {family}."),
                        ));
                        continue;
                    };
                    h.allows_multiple_instance_types = Some(if single.is_some() { "off" } else { "on" }.into());
                    h.host_properties = Some(t::HostProperties {
                        cores: Some(cores),
                        sockets: Some(sockets),
                        total_v_cpus: Some(total),
                        instance_type: single,
                        instance_family: Some(family),
                    });
                }
                if let Some(v) = &input.auto_placement {
                    h.auto_placement = Some(v.clone());
                }
                if let Some(v) = &input.host_recovery {
                    h.host_recovery = Some(v.clone());
                }
                if let Some(v) = &input.host_maintenance {
                    h.host_maintenance = Some(v.clone());
                }
                ok.push(id.clone());
            }
            Ok(t::ModifyHostsResult { successful: Some(ok), unsuccessful: Some(failed) })
        })
    }

    pub(crate) fn release_hosts_op(
        &self,
        ctx: &RequestContext,
        input: t::ReleaseHostsRequest,
    ) -> Result<t::ReleaseHostsResult, ServiceError> {
        if input.host_ids.is_empty() {
            return Err(missing_parameter("HostIds"));
        }
        self.authorize_known(ctx, "ReleaseHosts", &self.host_resources(ctx, &input.host_ids), None)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let mut ok = Vec::new();
            let mut failed = Vec::new();
            for id in &input.host_ids {
                if Kind::Host.check(id).is_err() {
                    failed.push(unsuccessful(id, "InvalidHostID.Malformed", format!("Invalid id: \"{id}\"")));
                    continue;
                }
                let occupied = !host_instances(r, id).is_empty();
                let Some(h) = r.hosts.get_mut(id).filter(|h| h.state.as_deref() != Some("released")) else {
                    failed.push(unsuccessful(id, "InvalidHostID.NotFound", format!("The host ID '{id}' does not exist")));
                    continue;
                };
                if occupied {
                    failed.push(unsuccessful(
                        id,
                        "Client.InvalidHost.Occupied",
                        format!("Dedicated Host {id} has instances running on it. Stop or terminate them before releasing the host."),
                    ));
                    continue;
                }
                h.state = Some("released".into());
                h.release_time = Some(now);
                ok.push(id.clone());
            }
            Ok(t::ReleaseHostsResult { successful: Some(ok), unsuccessful: Some(failed) })
        })
    }

    pub(crate) fn modify_instance_placement_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyInstancePlacementRequest,
    ) -> Result<t::ModifyInstancePlacementResult, ServiceError> {
        let id = input.instance_id.clone();
        Kind::Instance.check(&id)?;
        let account = account_of(ctx);
        let tags = self.with_region(ctx, |r| {
            r.instances.get(&id).map(|i| i.instance.tags.clone()).ok_or_else(|| Kind::Instance.not_found(&id))
        })?;
        self.authorize_known(
            ctx,
            "ModifyInstancePlacement",
            &[(arn(ctx, &account, &format!("instance/{id}")), resource_tag_context(tags.as_ref()))],
            None,
        )?;
        if let Some(t) = &input.tenancy {
            if !matches!(t.as_str(), "default" | "dedicated" | "host") {
                return Err(invalid_parameter(format!("Value ({t}) for parameter tenancy is invalid.")));
            }
        }
        if let Some(a) = &input.affinity {
            if a != "default" && a != "host" {
                return Err(invalid_parameter(format!("Value ({a}) for parameter affinity is invalid.")));
            }
        }
        self.with_region(ctx, |r| {
            let rec = &r.instances[&id];
            let state = rec.instance.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default();
            let changes_host = input.host_id.is_some() || input.tenancy.is_some() || input.affinity.is_some();
            if changes_host && state != "stopped" {
                return Err(err(
                    "IncorrectInstanceState",
                    format!("The instance '{id}' is not in the 'stopped' state."),
                ));
            }
            let instance_type = rec.instance.instance_type.clone().unwrap_or_default();
            let zone = rec.instance.placement.as_ref().and_then(|p| p.availability_zone.clone()).unwrap_or_default();
            let mut placement = rec.instance.placement.clone().unwrap_or_default();
            if let Some(host) = &input.host_id {
                let probe = t::Placement { host_id: Some(host.clone()), ..Default::default() };
                // A stopped instance holds no capacity, so `room` sees the
                // host as it would be once the instance starts there.
                if room(r, &probe, &instance_type, &zone)? == 0 {
                    return Err(err(
                        "InsufficientHostCapacity",
                        format!(
                            "Dedicated Host {host} does not have capacity for an instance of type {instance_type}."
                        ),
                    ));
                }
                placement.host_id = Some(host.clone());
                placement.tenancy = Some("host".into());
            }
            if let Some(t) = &input.tenancy {
                placement.tenancy = Some(t.clone());
                if t != "host" {
                    placement.host_id = None;
                    placement.affinity = None;
                }
            }
            if let Some(a) = &input.affinity {
                placement.affinity = Some(a.clone());
            }
            if let Some(g) = &input.group_name {
                placement.group_name = Some(g.clone());
            }
            if input.partition_number.is_some() {
                placement.partition_number = input.partition_number;
            }
            r.instances.get_mut(&id).expect("checked").instance.placement = Some(placement);
            Ok(t::ModifyInstancePlacementResult { r#return: Some(true) })
        })
    }
}
