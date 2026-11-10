//! Account defaults (credit specifications, instance metadata defaults,
//! serial console access, AMI block public access, id formats), instance
//! settings (monitoring, maintenance, CPU options, private DNS names,
//! attribute resets, status reports), AMI controls (deprecation,
//! deregistration protection, disabling), placement groups, capacity
//! reservations and network interface permissions.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::instance::state_name;
use crate::generated::types as t;
use crate::state::RegionState;
use crate::util::{
    arn, authorize, err, invalid_parameter, new_id, paginate, request_tag_context, resource_tag_context, s, some_tags,
    tags_for, Filters, Kind,
};
use crate::{account_of, Ec2};

/// Resource types whose id format DescribeIdFormat reports (all long now).
const ID_FORMAT_RESOURCES: &[&str] = &[
    "bundle",
    "conversion-task",
    "customer-gateway",
    "dhcp-options",
    "elastic-ip-allocation",
    "elastic-ip-association",
    "export-task",
    "flow-log",
    "image",
    "import-task",
    "instance",
    "internet-gateway",
    "network-acl",
    "network-acl-association",
    "network-interface",
    "network-interface-attachment",
    "prefix-list",
    "reservation",
    "route-table",
    "route-table-association",
    "security-group",
    "snapshot",
    "subnet",
    "subnet-cidr-block-association",
    "volume",
    "vpc",
    "vpc-cidr-block-association",
    "vpc-endpoint",
    "vpc-peering-connection",
    "vpn-connection",
    "vpn-gateway",
];

/// Instance families whose topology `DescribeInstanceTopology` reports.
const TOPOLOGY_FAMILIES: &[&str] =
    &["p3dn", "p4d", "p4de", "p5", "p5e", "p5en", "p6", "trn1", "trn1n", "trn2", "hpc6a", "hpc6id", "hpc7a", "hpc7g"];

fn account_resource(_ctx: &RequestContext) -> Vec<(String, ConditionContext)> {
    vec![("*".into(), ConditionContext::new())]
}

fn id_format(resource: &str) -> t::IdFormat {
    t::IdFormat { deadline: None, resource: Some(resource.into()), use_long_ids: Some(true) }
}

fn incorrect_state(id: &str, wanted: &str) -> ServiceError {
    err("IncorrectInstanceState", format!("The instance '{id}' is not in the '{wanted}' state."))
}

fn placement_group_arn(ctx: &RequestContext, account: &str, name: &str) -> String {
    arn(ctx, account, &format!("placement-group/{name}"))
}

/// Whether an instance counts against capacity (pending or running).
fn occupies(rec: &crate::state::InstanceRecord) -> bool {
    matches!(state_name(rec).as_str(), "pending" | "running")
}

/// A capacity reservation as it stands at `now`: its state (expired past
/// its end date) and available count.
pub(crate) fn reservation_view(
    r: &RegionState,
    cr: &t::CapacityReservation,
    now: DateTime<Utc>,
) -> t::CapacityReservation {
    let mut cr = cr.clone();
    if cr.state.as_deref() == Some("active")
        && cr.end_date_type.as_deref() == Some("limited")
        && cr.end_date.is_some_and(|e| e <= now)
    {
        cr.state = Some("expired".into());
    }
    let id = cr.capacity_reservation_id.clone();
    let used = r.instances.values().filter(|i| i.instance.capacity_reservation_id == id && occupies(i)).count() as i32;
    let total = cr.total_instance_count.unwrap_or(0);
    cr.available_instance_count = Some(if cr.state.as_deref() == Some("active") { (total - used).max(0) } else { 0 });
    cr
}

/// The capacity reservation a new instance uses, if any: the targeted
/// one (which must fit and have room), or with preference `open` an
/// active open reservation that matches. `Err` when a targeted
/// reservation can't take it.
pub(crate) fn pick_reservation(
    r: &RegionState,
    spec: Option<&t::CapacityReservationSpecification>,
    instance_type: &str,
    zone: &str,
    tenancy: &str,
    count: usize,
    now: DateTime<Utc>,
) -> Result<Option<String>, ServiceError> {
    let preference = spec.and_then(|s| s.capacity_reservation_preference.clone());
    if let Some(id) =
        spec.and_then(|s| s.capacity_reservation_target.as_ref()).and_then(|t| t.capacity_reservation_id.clone())
    {
        let cr = r.capacity_reservations.get(&id).ok_or_else(|| {
            err("InvalidCapacityReservationId.NotFound", format!("The capacity reservation ID '{id}' does not exist"))
        })?;
        let cr = reservation_view(r, cr, now);
        let fits = cr.instance_type.as_deref() == Some(instance_type)
            && cr.availability_zone.as_deref() == Some(zone)
            && cr.tenancy.as_deref().unwrap_or("default") == tenancy;
        if !fits || cr.state.as_deref() != Some("active") || (cr.available_instance_count.unwrap_or(0) as usize) < count
        {
            return Err(err(
                "ReservationCapacityExceeded",
                "The requested reservation does not have sufficient compatible and available capacity for this request.",
            ));
        }
        return Ok(Some(id));
    }
    match preference.as_deref() {
        Some("none") | Some("capacity-reservations-only") if preference.as_deref() == Some("none") => return Ok(None),
        _ => {}
    }
    let found = r.capacity_reservations.values().map(|cr| reservation_view(r, cr, now)).find(|cr| {
        cr.state.as_deref() == Some("active")
            && cr.instance_match_criteria.as_deref() == Some("open")
            && cr.instance_type.as_deref() == Some(instance_type)
            && cr.availability_zone.as_deref() == Some(zone)
            && cr.tenancy.as_deref().unwrap_or("default") == tenancy
            && cr.available_instance_count.unwrap_or(0) as usize >= count
    });
    if found.is_none() && preference.as_deref() == Some("capacity-reservations-only") {
        return Err(err(
            "InsufficientInstanceCapacity",
            "There is no capacity reservation with available capacity that matches this request.",
        ));
    }
    Ok(found.and_then(|cr| cr.capacity_reservation_id))
}

/// Check a launch's placement group; the partition number for each
/// instance (partition groups).
pub(crate) fn check_placement_group(
    r: &RegionState,
    placement: Option<&t::Placement>,
    zone: &str,
    count: usize,
) -> Result<Vec<Option<i32>>, ServiceError> {
    let Some(p) = placement else { return Ok(vec![None; count]) };
    let group = match (&p.group_name, &p.group_id) {
        (Some(name), _) if !name.is_empty() => {
            r.placement_groups.values().find(|g| g.group_name.as_deref() == Some(name))
        }
        (_, Some(id)) if !id.is_empty() => r.placement_groups.get(id),
        _ => return Ok(vec![None; count]),
    };
    let name = p.group_name.clone().or_else(|| p.group_id.clone()).unwrap_or_default();
    let group = group
        .filter(|g| g.state.as_deref() == Some("available"))
        .ok_or_else(|| err("InvalidPlacementGroup.Unknown", format!("The Placement Group '{name}' is unknown.")))?;
    let group_name = group.group_name.clone().unwrap_or_default();
    let members: Vec<&crate::state::InstanceRecord> = r
        .instances
        .values()
        .filter(|i| {
            occupies(i)
                && i.instance.placement.as_ref().and_then(|p| p.group_name.as_deref()) == Some(group_name.as_str())
        })
        .collect();
    match group.strategy.as_deref() {
        Some("cluster") => {
            if let Some(other) = members
                .iter()
                .filter_map(|i| i.instance.placement.as_ref().and_then(|p| p.availability_zone.clone()))
                .find(|z| z != zone)
            {
                return Err(invalid_parameter(format!(
                    "Instances in cluster placement group '{group_name}' must be in one Availability Zone ({other})."
                )));
            }
            Ok(vec![None; count])
        }
        Some("spread") => {
            let in_zone = members
                .iter()
                .filter(|i| i.instance.placement.as_ref().and_then(|p| p.availability_zone.as_deref()) == Some(zone))
                .count();
            if in_zone + count > 7 {
                return Err(err(
                    "InsufficientInstanceCapacity",
                    format!("A spread placement group can have at most 7 running instances per Availability Zone; '{group_name}' already has {in_zone} in {zone}."),
                ));
            }
            Ok(vec![None; count])
        }
        _ => {
            let partitions = group.partition_count.unwrap_or(2).max(1);
            if let Some(n) = p.partition_number {
                if n < 1 || n > partitions {
                    return Err(invalid_parameter(format!(
                        "Value ({n}) for parameter partitionNumber is invalid. Partition number must be between 1 and {partitions}."
                    )));
                }
                return Ok(vec![Some(n); count]);
            }
            // Spread instances over the partitions, fullest last.
            let mut load: Vec<usize> = (1..=partitions)
                .map(|n| {
                    members
                        .iter()
                        .filter(|i| i.instance.placement.as_ref().and_then(|p| p.partition_number) == Some(n))
                        .count()
                })
                .collect();
            Ok((0..count)
                .map(|_| {
                    let (i, _) = load.iter().enumerate().min_by_key(|(_, l)| **l).expect("partitions");
                    load[i] += 1;
                    Some(i as i32 + 1)
                })
                .collect())
        }
    }
}

impl Ec2 {
    // ---- account defaults --------------------------------------------------------------------

    pub(crate) fn get_default_credit_specification_op(
        &self,
        ctx: &RequestContext,
        input: t::GetDefaultCreditSpecificationRequest,
    ) -> Result<t::GetDefaultCreditSpecificationResult, ServiceError> {
        authorize(ctx, "GetDefaultCreditSpecification", &account_resource(ctx), input.dry_run)?;
        let fallback = match input.instance_family.as_str() {
            "t2" => "standard",
            "t3" | "t3a" | "t4g" => "unlimited",
            other => {
                return Err(invalid_parameter(format!(
                    "Value ({other}) for parameter instanceFamily is invalid. Valid values are t2, t3, t3a and t4g."
                )))
            }
        };
        let credits = self.with_region(ctx, |r| r.default_credit_specs.get(&input.instance_family).cloned());
        Ok(t::GetDefaultCreditSpecificationResult {
            instance_family_credit_specification: Some(t::InstanceFamilyCreditSpecification {
                instance_family: Some(input.instance_family.clone()),
                cpu_credits: Some(credits.unwrap_or_else(|| fallback.into())),
            }),
        })
    }

    pub(crate) fn modify_default_credit_specification_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDefaultCreditSpecificationRequest,
    ) -> Result<t::ModifyDefaultCreditSpecificationResult, ServiceError> {
        authorize(ctx, "ModifyDefaultCreditSpecification", &account_resource(ctx), input.dry_run)?;
        if !["t2", "t3", "t3a", "t4g"].contains(&input.instance_family.as_str()) {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter instanceFamily is invalid. Valid values are t2, t3, t3a and t4g.",
                input.instance_family
            )));
        }
        if !["standard", "unlimited"].contains(&input.cpu_credits.as_str()) {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter cpuCredits is invalid. Valid values are standard and unlimited.",
                input.cpu_credits
            )));
        }
        self.with_region(ctx, |r| {
            r.default_credit_specs.insert(input.instance_family.clone(), input.cpu_credits.clone())
        });
        Ok(t::ModifyDefaultCreditSpecificationResult {
            instance_family_credit_specification: Some(t::InstanceFamilyCreditSpecification {
                instance_family: Some(input.instance_family),
                cpu_credits: Some(input.cpu_credits),
            }),
        })
    }

    pub(crate) fn get_instance_metadata_defaults_op(
        &self,
        ctx: &RequestContext,
        input: t::GetInstanceMetadataDefaultsRequest,
    ) -> Result<t::GetInstanceMetadataDefaultsResult, ServiceError> {
        authorize(ctx, "GetInstanceMetadataDefaults", &account_resource(ctx), input.dry_run)?;
        let d = self.with_region(ctx, |r| r.metadata_defaults.clone());
        Ok(t::GetInstanceMetadataDefaultsResult {
            account_level: Some(t::InstanceMetadataDefaultsResponse { managed_by: Some("account".into()), ..d }),
        })
    }

    pub(crate) fn modify_instance_metadata_defaults_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyInstanceMetadataDefaultsRequest,
    ) -> Result<t::ModifyInstanceMetadataDefaultsResult, ServiceError> {
        authorize(ctx, "ModifyInstanceMetadataDefaults", &account_resource(ctx), input.dry_run)?;
        let check = |v: &Option<String>, name: &str, allowed: &[&str]| -> Result<(), ServiceError> {
            match v {
                Some(x) if !allowed.contains(&x.as_str()) => {
                    Err(invalid_parameter(format!("Value ({x}) for parameter {name} is invalid.")))
                }
                _ => Ok(()),
            }
        };
        check(&input.http_tokens, "HttpTokens", &["optional", "required", "no-preference"])?;
        check(&input.http_endpoint, "HttpEndpoint", &["enabled", "disabled", "no-preference"])?;
        check(&input.instance_metadata_tags, "InstanceMetadataTags", &["enabled", "disabled", "no-preference"])?;
        check(&input.http_tokens_enforced, "HttpTokensEnforced", &["enabled", "disabled", "no-preference"])?;
        if let Some(h) = input.http_put_response_hop_limit {
            if h != -1 && !(1..=64).contains(&h) {
                return Err(invalid_parameter(format!(
                    "Value ({h}) for parameter HttpPutResponseHopLimit is invalid."
                )));
            }
        }
        self.with_region(ctx, |r| {
            let d = &mut r.metadata_defaults;
            let set = |slot: &mut Option<String>, v: &Option<String>| {
                if let Some(v) = v {
                    *slot = (v != "no-preference").then(|| v.clone());
                }
            };
            set(&mut d.http_tokens, &input.http_tokens);
            set(&mut d.http_endpoint, &input.http_endpoint);
            set(&mut d.instance_metadata_tags, &input.instance_metadata_tags);
            set(&mut d.http_tokens_enforced, &input.http_tokens_enforced);
            if let Some(h) = input.http_put_response_hop_limit {
                d.http_put_response_hop_limit = (h != -1).then_some(h);
            }
        });
        Ok(t::ModifyInstanceMetadataDefaultsResult { r#return: Some(true) })
    }

    pub(crate) fn enable_serial_console_access_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableSerialConsoleAccessRequest,
    ) -> Result<t::EnableSerialConsoleAccessResult, ServiceError> {
        authorize(ctx, "EnableSerialConsoleAccess", &account_resource(ctx), input.dry_run)?;
        self.with_region(ctx, |r| r.serial_console_access = true);
        Ok(t::EnableSerialConsoleAccessResult { serial_console_access_enabled: Some(true) })
    }

    pub(crate) fn disable_serial_console_access_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableSerialConsoleAccessRequest,
    ) -> Result<t::DisableSerialConsoleAccessResult, ServiceError> {
        authorize(ctx, "DisableSerialConsoleAccess", &account_resource(ctx), input.dry_run)?;
        self.with_region(ctx, |r| r.serial_console_access = false);
        Ok(t::DisableSerialConsoleAccessResult { serial_console_access_enabled: Some(false) })
    }

    pub(crate) fn get_serial_console_access_status_op(
        &self,
        ctx: &RequestContext,
        input: t::GetSerialConsoleAccessStatusRequest,
    ) -> Result<t::GetSerialConsoleAccessStatusResult, ServiceError> {
        authorize(ctx, "GetSerialConsoleAccessStatus", &account_resource(ctx), input.dry_run)?;
        let on = self.with_region(ctx, |r| r.serial_console_access);
        Ok(t::GetSerialConsoleAccessStatusResult {
            serial_console_access_enabled: Some(on),
            managed_by: Some("account".into()),
        })
    }

    pub(crate) fn enable_image_block_public_access_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableImageBlockPublicAccessRequest,
    ) -> Result<t::EnableImageBlockPublicAccessResult, ServiceError> {
        authorize(ctx, "EnableImageBlockPublicAccess", &account_resource(ctx), input.dry_run)?;
        if input.image_block_public_access_state != "block-new-sharing" {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter ImageBlockPublicAccessState is invalid. Valid value: block-new-sharing.",
                input.image_block_public_access_state
            )));
        }
        self.with_region(ctx, |r| r.image_block_public_access = Some("block-new-sharing".into()));
        Ok(t::EnableImageBlockPublicAccessResult { image_block_public_access_state: Some("block-new-sharing".into()) })
    }

    pub(crate) fn disable_image_block_public_access_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableImageBlockPublicAccessRequest,
    ) -> Result<t::DisableImageBlockPublicAccessResult, ServiceError> {
        authorize(ctx, "DisableImageBlockPublicAccess", &account_resource(ctx), input.dry_run)?;
        self.with_region(ctx, |r| r.image_block_public_access = Some("unblocked".into()));
        Ok(t::DisableImageBlockPublicAccessResult { image_block_public_access_state: Some("unblocked".into()) })
    }

    pub(crate) fn get_image_block_public_access_state_op(
        &self,
        ctx: &RequestContext,
        input: t::GetImageBlockPublicAccessStateRequest,
    ) -> Result<t::GetImageBlockPublicAccessStateResult, ServiceError> {
        authorize(ctx, "GetImageBlockPublicAccessState", &account_resource(ctx), input.dry_run)?;
        // Accounts created since late 2023 block new public sharing.
        let state = self
            .with_region(ctx, |r| r.image_block_public_access.clone())
            .unwrap_or_else(|| "block-new-sharing".into());
        Ok(t::GetImageBlockPublicAccessStateResult {
            image_block_public_access_state: Some(state),
            managed_by: Some("account".into()),
        })
    }

    pub(crate) fn describe_id_format_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeIdFormatRequest,
    ) -> Result<t::DescribeIdFormatResult, ServiceError> {
        authorize(ctx, "DescribeIdFormat", &account_resource(ctx), None)?;
        let statuses = match &input.resource {
            Some(r) if !ID_FORMAT_RESOURCES.contains(&r.as_str()) => {
                return Err(invalid_parameter(format!("Invalid resource type: {r}")));
            }
            Some(r) => vec![id_format(r)],
            None => ID_FORMAT_RESOURCES.iter().map(|r| id_format(r)).collect(),
        };
        Ok(t::DescribeIdFormatResult { statuses: Some(statuses) })
    }

    pub(crate) fn describe_identity_id_format_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeIdentityIdFormatRequest,
    ) -> Result<t::DescribeIdentityIdFormatResult, ServiceError> {
        authorize(ctx, "DescribeIdentityIdFormat", &account_resource(ctx), None)?;
        let out = self.describe_id_format_op(ctx, t::DescribeIdFormatRequest { resource: input.resource })?;
        Ok(t::DescribeIdentityIdFormatResult { statuses: out.statuses })
    }

    pub(crate) fn describe_principal_id_format_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribePrincipalIdFormatRequest,
    ) -> Result<t::DescribePrincipalIdFormatResult, ServiceError> {
        authorize(ctx, "DescribePrincipalIdFormat", &account_resource(ctx), input.dry_run)?;
        let resources: Vec<String> =
            input.resources.clone().unwrap_or_else(|| ID_FORMAT_RESOURCES.iter().map(|r| r.to_string()).collect());
        let statuses: Vec<t::IdFormat> = resources.iter().map(|r| id_format(r)).collect();
        let principals = vec![t::PrincipalIdFormat {
            arn: Some(format!("arn:{}:iam::{}:root", ctx.partition, account_of(ctx))),
            statuses: Some(statuses),
        }];
        let (principals, next_token) = paginate(principals, input.max_results, &input.next_token)?;
        Ok(t::DescribePrincipalIdFormatResult { principals: Some(principals), next_token })
    }

    pub(crate) fn describe_aggregate_id_format_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeAggregateIdFormatRequest,
    ) -> Result<t::DescribeAggregateIdFormatResult, ServiceError> {
        authorize(ctx, "DescribeAggregateIdFormat", &account_resource(ctx), input.dry_run)?;
        Ok(t::DescribeAggregateIdFormatResult {
            use_long_ids_aggregated: Some(true),
            statuses: Some(ID_FORMAT_RESOURCES.iter().map(|r| id_format(r)).collect()),
        })
    }

    pub(crate) fn modify_id_format_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyIdFormatRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "ModifyIdFormat", &account_resource(ctx), None)?;
        if !ID_FORMAT_RESOURCES.contains(&input.resource.as_str()) && input.resource != "all-current" {
            return Err(invalid_parameter(format!("Invalid resource type: {}", input.resource)));
        }
        if !input.use_long_ids {
            return Err(invalid_parameter(format!("Resource type {} only supports longer IDs.", input.resource)));
        }
        Ok(())
    }

    pub(crate) fn modify_identity_id_format_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyIdentityIdFormatRequest,
    ) -> Result<(), ServiceError> {
        self.modify_id_format_op(
            ctx,
            t::ModifyIdFormatRequest { resource: input.resource, use_long_ids: input.use_long_ids },
        )
    }

    // ---- instance settings -------------------------------------------------------------------

    /// Authorize `action` on one instance and run `f` on its record.
    fn on_instance<R>(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
        f: impl FnOnce(&mut RegionState) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        self.authorize_instances(ctx, action, std::slice::from_ref(&id.to_string()), dry_run)?;
        self.with_region(ctx, f)
    }

    fn set_monitoring(
        &self,
        ctx: &RequestContext,
        action: &str,
        ids: &[String],
        dry_run: Option<bool>,
        enabled: bool,
    ) -> Result<Vec<t::InstanceMonitoring>, ServiceError> {
        self.authorize_instances(ctx, action, ids, dry_run)?;
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for id in ids {
                let rec = r.instances.get_mut(id).expect("checked");
                if state_name(rec) == "terminated" {
                    return Err(incorrect_state(id, "running"));
                }
                rec.instance.monitoring =
                    Some(t::Monitoring { state: Some(if enabled { "enabled" } else { "disabled" }.into()) });
                out.push(t::InstanceMonitoring {
                    instance_id: Some(id.clone()),
                    monitoring: Some(t::Monitoring {
                        state: Some(if enabled { "pending" } else { "disabling" }.into()),
                    }),
                });
            }
            Ok(out)
        })
    }

    pub(crate) fn monitor_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::MonitorInstancesRequest,
    ) -> Result<t::MonitorInstancesResult, ServiceError> {
        let out = self.set_monitoring(ctx, "MonitorInstances", &input.instance_ids, input.dry_run, true)?;
        Ok(t::MonitorInstancesResult { instance_monitorings: Some(out) })
    }

    pub(crate) fn unmonitor_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::UnmonitorInstancesRequest,
    ) -> Result<t::UnmonitorInstancesResult, ServiceError> {
        let out = self.set_monitoring(ctx, "UnmonitorInstances", &input.instance_ids, input.dry_run, false)?;
        Ok(t::UnmonitorInstancesResult { instance_monitorings: Some(out) })
    }

    pub(crate) fn modify_instance_maintenance_options_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyInstanceMaintenanceOptionsRequest,
    ) -> Result<t::ModifyInstanceMaintenanceOptionsResult, ServiceError> {
        for (v, name) in [(&input.auto_recovery, "AutoRecovery"), (&input.reboot_migration, "RebootMigration")] {
            if let Some(v) = v.as_deref().filter(|v| !["default", "disabled"].contains(v)) {
                return Err(invalid_parameter(format!("Value ({v}) for parameter {name} is invalid.")));
            }
        }
        let id = input.instance_id.clone();
        self.on_instance(ctx, "ModifyInstanceMaintenanceOptions", &id, input.dry_run, |r| {
            let rec = r.instances.get_mut(&id).expect("checked");
            let m = rec.instance.maintenance_options.get_or_insert_with(Default::default);
            if let Some(v) = input.auto_recovery {
                m.auto_recovery = Some(v);
            }
            if let Some(v) = input.reboot_migration {
                m.reboot_migration = Some(v);
            }
            Ok(t::ModifyInstanceMaintenanceOptionsResult {
                instance_id: Some(id.clone()),
                auto_recovery: m.auto_recovery.clone(),
                reboot_migration: m.reboot_migration.clone(),
            })
        })
    }

    pub(crate) fn modify_instance_cpu_options_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyInstanceCpuOptionsRequest,
    ) -> Result<t::ModifyInstanceCpuOptionsResult, ServiceError> {
        let id = input.instance_id.clone();
        self.on_instance(ctx, "ModifyInstanceCpuOptions", &id, input.dry_run, |r| {
            let rec = r.instances.get_mut(&id).expect("checked");
            if state_name(rec) != "stopped" {
                return Err(incorrect_state(&id, "stopped"));
            }
            let itype = rec.instance.instance_type.clone().unwrap_or_default();
            let vcpus = crate::catalog::instance_type(&itype).map(|i| i.vcpus as i32).unwrap_or(2);
            let cpu = rec.instance.cpu_options.get_or_insert_with(Default::default);
            let threads = input.threads_per_core.or(cpu.threads_per_core).unwrap_or(1);
            if !(1..=2).contains(&threads) {
                return Err(invalid_parameter(format!("Value ({threads}) for parameter threadsPerCore is invalid.")));
            }
            let cores = input.core_count.or(cpu.core_count).unwrap_or(vcpus / threads);
            if cores < 1 || cores * threads > vcpus {
                return Err(invalid_parameter(format!(
                    "The specified CPU options are not valid for instance type {itype}: {cores} cores with {threads} threads per core exceeds {vcpus} vCPUs."
                )));
            }
            cpu.core_count = Some(cores);
            cpu.threads_per_core = Some(threads);
            if let Some(n) = input.nested_virtualization {
                cpu.nested_virtualization = Some(n);
            }
            Ok(t::ModifyInstanceCpuOptionsResult {
                instance_id: Some(id.clone()),
                core_count: cpu.core_count,
                threads_per_core: cpu.threads_per_core,
                nested_virtualization: cpu.nested_virtualization.clone(),
            })
        })
    }

    pub(crate) fn modify_instance_capacity_reservation_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyInstanceCapacityReservationAttributesRequest,
    ) -> Result<t::ModifyInstanceCapacityReservationAttributesResult, ServiceError> {
        let id = input.instance_id.clone();
        let now = ctx.received_at;
        self.on_instance(ctx, "ModifyInstanceCapacityReservationAttributes", &id, input.dry_run, |r| {
            let rec = r.instances.get(&id).expect("checked");
            if state_name(rec) != "stopped" {
                return Err(incorrect_state(&id, "stopped"));
            }
            let itype = rec.instance.instance_type.clone().unwrap_or_default();
            let placement = rec.instance.placement.clone().unwrap_or_default();
            let zone = placement.availability_zone.clone().unwrap_or_default();
            let tenancy = placement.tenancy.clone().unwrap_or_else(|| "default".into());
            let spec = &input.capacity_reservation_specification;
            // A stopped instance holds no capacity, so a reservation with
            // room for one more fits.
            let target = if spec.capacity_reservation_target.is_some() {
                pick_reservation(r, Some(spec), &itype, &zone, &tenancy, 1, now)?
            } else {
                None
            };
            let rec = r.instances.get_mut(&id).expect("checked");
            rec.instance.capacity_reservation_id = target.clone();
            rec.instance.capacity_reservation_specification = Some(t::CapacityReservationSpecificationResponse {
                capacity_reservation_preference: spec
                    .capacity_reservation_preference
                    .clone()
                    .or_else(|| target.is_none().then(|| "open".into())),
                capacity_reservation_target: spec.capacity_reservation_target.as_ref().map(|t| {
                    t::CapacityReservationTargetResponse {
                        capacity_reservation_id: t.capacity_reservation_id.clone(),
                        capacity_reservation_resource_group_arn: t.capacity_reservation_resource_group_arn.clone(),
                    }
                }),
            });
            Ok(t::ModifyInstanceCapacityReservationAttributesResult { r#return: Some(true) })
        })
    }

    pub(crate) fn modify_private_dns_name_options_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyPrivateDnsNameOptionsRequest,
    ) -> Result<t::ModifyPrivateDnsNameOptionsResult, ServiceError> {
        let id = input.instance_id.clone();
        let region = ctx.region.clone();
        self.on_instance(ctx, "ModifyPrivateDnsNameOptions", &id, input.dry_run, |r| {
            let rec = r.instances.get_mut(&id).expect("checked");
            if let Some(h) = &input.private_dns_hostname_type {
                if !["ip-name", "resource-name"].contains(&h.as_str()) {
                    return Err(invalid_parameter(format!(
                        "Value ({h}) for parameter PrivateDnsHostnameType is invalid."
                    )));
                }
                if state_name(rec) != "stopped" {
                    return Err(incorrect_state(&id, "stopped"));
                }
            }
            let o = rec.instance.private_dns_name_options.get_or_insert_with(Default::default);
            if let Some(h) = input.private_dns_hostname_type.clone() {
                o.hostname_type = Some(h);
            }
            if let Some(v) = input.enable_resource_name_dns_a_record {
                o.enable_resource_name_dns_a_record = Some(v);
            }
            if let Some(v) = input.enable_resource_name_dns_aaaa_record {
                o.enable_resource_name_dns_aaaa_record = Some(v);
            }
            let resource_name = o.hostname_type.as_deref() == Some("resource-name");
            let ip = rec.instance.private_ip_address.clone().unwrap_or_default();
            rec.instance.private_dns_name = Some(if resource_name {
                if region == "us-east-1" {
                    format!("{id}.ec2.internal")
                } else {
                    format!("{id}.{region}.compute.internal")
                }
            } else {
                crate::util::private_dns(&region, &ip)
            });
            Ok(t::ModifyPrivateDnsNameOptionsResult { r#return: Some(true) })
        })
    }

    pub(crate) fn reset_instance_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ResetInstanceAttributeRequest,
    ) -> Result<(), ServiceError> {
        let id = input.instance_id.clone();
        self.on_instance(ctx, "ResetInstanceAttribute", &id, input.dry_run, |r| {
            let rec = r.instances.get_mut(&id).expect("checked");
            match input.attribute.as_str() {
                "kernel" | "ramdisk" => {
                    if state_name(rec) != "stopped" {
                        return Err(incorrect_state(&id, "stopped"));
                    }
                    if input.attribute == "kernel" {
                        rec.instance.kernel_id = None;
                    } else {
                        rec.instance.ramdisk_id = None;
                    }
                }
                "disableApiStop" => rec.disable_api_stop = false,
                "sourceDestCheck" => {
                    if let Some(eni) = super::eni::primary_eni(r, &id) {
                        if let Some(n) = r.network_interfaces.get_mut(&eni) {
                            n.source_dest_check = Some(true);
                        }
                    }
                }
                other => {
                    return Err(invalid_parameter(format!(
                        "Value ({other}) for parameter attribute is invalid. Valid values: kernel, ramdisk, sourceDestCheck, disableApiStop."
                    )))
                }
            }
            Ok(())
        })
    }

    pub(crate) fn report_instance_status_op(
        &self,
        ctx: &RequestContext,
        input: t::ReportInstanceStatusRequest,
    ) -> Result<(), ServiceError> {
        if !["ok", "impaired"].contains(&input.status.as_str()) {
            return Err(invalid_parameter(format!("Value ({}) for parameter status is invalid.", input.status)));
        }
        const CODES: &[&str] = &[
            "instance-stuck-in-state",
            "unresponsive",
            "not-accepting-credentials",
            "password-not-available",
            "performance-network",
            "performance-instance-store",
            "performance-ebs-volume",
            "performance-other",
            "other",
        ];
        if let Some(c) = input.reason_codes.iter().find(|c| !CODES.contains(&c.as_str())) {
            return Err(invalid_parameter(format!("Value ({c}) for parameter reasonCode is invalid.")));
        }
        self.authorize_instances(ctx, "ReportInstanceStatus", &input.instances, input.dry_run)
    }

    pub(crate) fn send_diagnostic_interrupt_op(
        &self,
        ctx: &RequestContext,
        input: t::SendDiagnosticInterruptRequest,
    ) -> Result<(), ServiceError> {
        let id = input.instance_id.clone();
        self.on_instance(ctx, "SendDiagnosticInterrupt", &id, input.dry_run, |r| {
            let rec = r.instances.get(&id).expect("checked");
            if state_name(rec) != "running" {
                return Err(incorrect_state(&id, "running"));
            }
            let family =
                rec.instance.instance_type.as_deref().unwrap_or_default().split('.').next().unwrap_or_default();
            if family.starts_with('t') && !family.starts_with("t3") && !family.starts_with("t4") || family == "t2" {
                return Err(err(
                    "UnsupportedOperation",
                    format!("The instance '{id}' does not support diagnostic interrupts (Nitro instances only)."),
                ));
            }
            Ok(())
        })
    }

    pub(crate) fn describe_instance_topology_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInstanceTopologyRequest,
    ) -> Result<t::DescribeInstanceTopologyResult, ServiceError> {
        authorize(ctx, "DescribeInstanceTopology", &account_resource(ctx), input.dry_run)?;
        let ids = input.instance_ids.clone().unwrap_or_default();
        let groups = input.group_names.clone().unwrap_or_default();
        let filters = Filters::new(&input.filters);
        let out = self.with_region(ctx, |r| -> Result<_, ServiceError> {
            let mut out = Vec::new();
            for rec in r.instances.values() {
                let i = &rec.instance;
                let id = i.instance_id.clone().unwrap_or_default();
                let itype = i.instance_type.clone().unwrap_or_default();
                let family = itype.split('.').next().unwrap_or_default();
                if !TOPOLOGY_FAMILIES.contains(&family) || !occupies(rec) {
                    continue;
                }
                let p = i.placement.clone().unwrap_or_default();
                let group = p.group_name.clone().filter(|g| !g.is_empty());
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                if !groups.is_empty() && !group.as_ref().is_some_and(|g| groups.contains(g)) {
                    continue;
                }
                let zone = p.availability_zone.clone().unwrap_or_default();
                let zone_id = p.availability_zone_id.clone().unwrap_or_default();
                if !filters.matches(None, |name| {
                    Some(match name {
                        "availability-zone" => vec![zone.clone()],
                        "zone-id" => vec![zone_id.clone()],
                        "instance-type" => vec![itype.clone()],
                        _ => return None,
                    })
                })? {
                    continue;
                }
                // Instances of one cluster group share their upper nodes.
                let seed = group.clone().unwrap_or_else(|| id.clone());
                let h = |level: &str| {
                    let d = aws_lc_rs::digest::digest(
                        &aws_lc_rs::digest::SHA256,
                        format!("{zone}/{level}/{seed}").as_bytes(),
                    );
                    format!("nn-{}", &d.as_ref()[..9].iter().map(|b| format!("{b:02x}")).collect::<String>()[..17])
                };
                out.push(t::InstanceTopology {
                    instance_id: Some(id.clone()),
                    instance_type: Some(itype.clone()),
                    group_name: group,
                    network_nodes: Some(vec![h("1"), h("2"), h(&format!("3/{id}"))]),
                    availability_zone: Some(zone),
                    zone_id: Some(zone_id),
                    capacity_block_id: None,
                });
            }
            Ok(out)
        })?;
        let (instances, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribeInstanceTopologyResult { instances: Some(instances), next_token })
    }

    // ---- images ------------------------------------------------------------------------------

    /// Authorize `action` on one of the caller's own images and change it.
    fn on_own_image<R>(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
        f: impl FnOnce(&mut RegionState) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        Kind::Image.check(id)?;
        let tags = self.with_region(ctx, |r| r.images.get(id).map(|i| i.image.tags.clone()));
        let Some(tags) = tags else {
            return Err(match self.find_image(ctx, id) {
                Ok(_) => err("AuthFailure", format!("Not authorized for image:{id}")),
                Err(e) => e,
            });
        };
        authorize(
            ctx,
            action,
            &[(super::image::image_arn(ctx, &ctx.region, id), resource_tag_context(tags.as_ref()))],
            dry_run,
        )?;
        self.with_region(ctx, f)
    }

    pub(crate) fn enable_image_deprecation_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableImageDeprecationRequest,
    ) -> Result<t::EnableImageDeprecationResult, ServiceError> {
        if input.deprecate_at > ctx.received_at + chrono::Duration::days(365 * 10) {
            return Err(invalid_parameter("The deprecation date can't be more than 10 years in the future."));
        }
        let id = input.image_id.clone();
        self.on_own_image(ctx, "EnableImageDeprecation", &id, input.dry_run, |r| {
            let rec = r.images.get_mut(&id).expect("checked");
            // Deprecation times are rounded down to the minute.
            let at = input.deprecate_at.format("%Y-%m-%dT%H:%M:00.000Z").to_string();
            rec.image.deprecation_time = Some(at);
            Ok(t::EnableImageDeprecationResult { r#return: Some(true) })
        })
    }

    pub(crate) fn disable_image_deprecation_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableImageDeprecationRequest,
    ) -> Result<t::DisableImageDeprecationResult, ServiceError> {
        let id = input.image_id.clone();
        self.on_own_image(ctx, "DisableImageDeprecation", &id, input.dry_run, |r| {
            r.images.get_mut(&id).expect("checked").image.deprecation_time = None;
            Ok(t::DisableImageDeprecationResult { r#return: Some(true) })
        })
    }

    pub(crate) fn enable_image_deregistration_protection_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableImageDeregistrationProtectionRequest,
    ) -> Result<t::EnableImageDeregistrationProtectionResult, ServiceError> {
        let id = input.image_id.clone();
        self.on_own_image(ctx, "EnableImageDeregistrationProtection", &id, input.dry_run, |r| {
            let v = if input.with_cooldown == Some(true) { "enabled-with-cooldown" } else { "enabled" };
            r.images.get_mut(&id).expect("checked").image.deregistration_protection = Some(v.into());
            Ok(t::EnableImageDeregistrationProtectionResult { r#return: Some(v.into()) })
        })
    }

    pub(crate) fn disable_image_deregistration_protection_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableImageDeregistrationProtectionRequest,
    ) -> Result<t::DisableImageDeregistrationProtectionResult, ServiceError> {
        let id = input.image_id.clone();
        let now = ctx.received_at;
        self.on_own_image(ctx, "DisableImageDeregistrationProtection", &id, input.dry_run, |r| {
            let rec = r.images.get_mut(&id).expect("checked");
            // With a cooldown the image stays protected for 24 hours.
            let v = match rec.image.deregistration_protection.as_deref() {
                Some("enabled-with-cooldown") => {
                    format!("disabled-until {}", (now + chrono::Duration::hours(24)).format("%Y-%m-%dT%H:%M:%S%.3fZ"))
                }
                _ => "disabled".into(),
            };
            rec.image.deregistration_protection = Some(v.clone());
            Ok(t::DisableImageDeregistrationProtectionResult { r#return: Some(v) })
        })
    }

    pub(crate) fn enable_image_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableImageRequest,
    ) -> Result<t::EnableImageResult, ServiceError> {
        let id = input.image_id.clone();
        self.on_own_image(ctx, "EnableImage", &id, input.dry_run, |r| {
            let rec = r.images.get_mut(&id).expect("checked");
            if rec.image.state.as_deref() != Some("disabled") {
                return Err(err("IncorrectState", format!("Image {id} is not disabled.")));
            }
            rec.image.state = Some("available".into());
            Ok(t::EnableImageResult { r#return: Some(true) })
        })
    }

    pub(crate) fn disable_image_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableImageRequest,
    ) -> Result<t::DisableImageResult, ServiceError> {
        let id = input.image_id.clone();
        self.on_own_image(ctx, "DisableImage", &id, input.dry_run, |r| {
            let rec = r.images.get_mut(&id).expect("checked");
            if rec.image.state.as_deref() != Some("available") {
                return Err(err("IncorrectState", format!("Image {id} is not available.")));
            }
            // A disabled image is private: its sharing is removed.
            rec.image.state = Some("disabled".into());
            rec.launch_users.clear();
            rec.launch_public = false;
            rec.image.public = Some(false);
            Ok(t::DisableImageResult { r#return: Some(true) })
        })
    }

    pub(crate) fn reset_image_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ResetImageAttributeRequest,
    ) -> Result<(), ServiceError> {
        if input.attribute != "launchPermission" {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter attribute is invalid. Only launchPermission can be reset.",
                input.attribute
            )));
        }
        let id = input.image_id.clone();
        self.on_own_image(ctx, "ResetImageAttribute", &id, input.dry_run, |r| {
            let rec = r.images.get_mut(&id).expect("checked");
            rec.launch_users.clear();
            rec.launch_public = false;
            rec.image.public = Some(false);
            Ok(())
        })
    }

    pub(crate) fn cancel_image_launch_permission_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelImageLaunchPermissionRequest,
    ) -> Result<t::CancelImageLaunchPermissionResult, ServiceError> {
        Kind::Image.check(&input.image_id)?;
        authorize(
            ctx,
            "CancelImageLaunchPermission",
            &[(super::image::image_arn(ctx, &ctx.region, &input.image_id), ConditionContext::new())],
            input.dry_run,
        )?;
        let caller = account_of(ctx);
        let found = self.find_image(ctx, &input.image_id)?;
        let Some(owner) = found.owner.filter(|o| *o != caller) else {
            return Err(invalid_parameter(format!(
                "You can't remove your own launch permission for image {}.",
                input.image_id
            )));
        };
        if !found.record.launch_users.contains(&caller) {
            return Err(invalid_parameter(format!("Image {} is not shared with your account.", input.image_id)));
        }
        let mut st = self.lock();
        if let Some(rec) = st
            .regions
            .get_mut(&crate::state::State::key(&owner, &ctx.region))
            .and_then(|r| r.images.get_mut(&input.image_id))
        {
            rec.launch_users.retain(|u| *u != caller);
        }
        Ok(t::CancelImageLaunchPermissionResult { r#return: Some(true) })
    }

    // ---- placement groups --------------------------------------------------------------------

    pub(crate) fn create_placement_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreatePlacementGroupRequest,
    ) -> Result<t::CreatePlacementGroupResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "placement-group", &["placement-group"])?;
        let name = input.group_name.clone().unwrap_or_else(|| new_id("pg"));
        authorize(
            ctx,
            "CreatePlacementGroup",
            &[(placement_group_arn(ctx, &account, &name), request_tag_context(&tags))],
            input.dry_run,
        )?;
        let strategy = input.strategy.clone().unwrap_or_else(|| "cluster".into());
        if !["cluster", "spread", "partition"].contains(&strategy.as_str()) {
            return Err(invalid_parameter(format!("Value ({strategy}) for parameter strategy is invalid.")));
        }
        match (strategy.as_str(), input.partition_count) {
            ("partition", Some(n)) if !(1..=7).contains(&n) => {
                return Err(invalid_parameter(format!(
                    "Value ({n}) for parameter partitionCount is invalid. Partition count must be between 1 and 7."
                )));
            }
            (s, Some(_)) if s != "partition" => {
                return Err(err(
                    "InvalidParameterCombination",
                    "PartitionCount can only be specified for partition placement groups.",
                ));
            }
            _ => {}
        }
        if input.spread_level.is_some() && strategy != "spread" {
            return Err(err(
                "InvalidParameterCombination",
                "SpreadLevel can only be specified for spread placement groups.",
            ));
        }
        let group = self.with_region(ctx, |r| {
            if r.placement_groups.values().any(|g| g.group_name.as_deref() == Some(name.as_str())) {
                return Err(err(
                    "InvalidPlacementGroup.Duplicate",
                    format!("The placement group '{name}' already exists."),
                ));
            }
            let id = new_id("pg");
            let group = t::PlacementGroup {
                group_name: Some(name.clone()),
                state: Some("available".into()),
                strategy: Some(strategy.clone()),
                partition_count: (strategy == "partition").then(|| input.partition_count.unwrap_or(2)),
                group_id: Some(id.clone()),
                tags: some_tags(tags.clone()),
                group_arn: Some(placement_group_arn(ctx, &account, &name)),
                spread_level: (strategy == "spread")
                    .then(|| input.spread_level.clone().unwrap_or_else(|| "rack".into())),
                ..Default::default()
            };
            r.placement_groups.insert(id, group.clone());
            Ok(group)
        })?;
        Ok(t::CreatePlacementGroupResult { placement_group: Some(group) })
    }

    pub(crate) fn describe_placement_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribePlacementGroupsRequest,
    ) -> Result<t::DescribePlacementGroupsResult, ServiceError> {
        authorize(ctx, "DescribePlacementGroups", &account_resource(ctx), input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let names = input.group_names.clone().unwrap_or_default();
        let ids = input.group_ids.clone().unwrap_or_default();
        let out = self.with_region(ctx, |r| -> Result<_, ServiceError> {
            for n in &names {
                if !r.placement_groups.values().any(|g| g.group_name.as_deref() == Some(n.as_str())) {
                    return Err(err("InvalidPlacementGroup.Unknown", format!("The Placement Group '{n}' is unknown.")));
                }
            }
            for id in &ids {
                if !r.placement_groups.contains_key(id) {
                    return Err(err(
                        "InvalidPlacementGroup.Unknown",
                        format!("The Placement Group '{id}' is unknown."),
                    ));
                }
            }
            let mut out = Vec::new();
            for g in r.placement_groups.values() {
                if !names.is_empty() && !g.group_name.as_ref().is_some_and(|n| names.contains(n)) {
                    continue;
                }
                if !ids.is_empty() && !g.group_id.as_ref().is_some_and(|i| ids.contains(i)) {
                    continue;
                }
                let ok = filters.matches(g.tags.as_ref(), |name| {
                    Some(match name {
                        "group-name" => s(&g.group_name),
                        "group-arn" => s(&g.group_arn),
                        "state" => s(&g.state),
                        "strategy" => s(&g.strategy),
                        "spread-level" => s(&g.spread_level),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(g.clone());
                }
            }
            Ok(out)
        })?;
        Ok(t::DescribePlacementGroupsResult { placement_groups: Some(out) })
    }

    pub(crate) fn delete_placement_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeletePlacementGroupRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let name = input.group_name.clone();
        let tags = self.with_region(ctx, |r| {
            r.placement_groups.values().find(|g| g.group_name.as_deref() == Some(name.as_str())).map(|g| g.tags.clone())
        });
        let Some(tags) = tags else {
            return Err(err("InvalidPlacementGroup.Unknown", format!("The Placement Group '{name}' is unknown.")));
        };
        authorize(
            ctx,
            "DeletePlacementGroup",
            &[(placement_group_arn(ctx, &account, &name), resource_tag_context(tags.as_ref()))],
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let in_use = r.instances.values().any(|i| {
                state_name(i) != "terminated"
                    && i.instance.placement.as_ref().and_then(|p| p.group_name.as_deref()) == Some(name.as_str())
            });
            if in_use {
                return Err(err("InvalidPlacementGroup.InUse", format!("Placement group {name} is in use")));
            }
            r.placement_groups.retain(|_, g| g.group_name.as_deref() != Some(name.as_str()));
            Ok(())
        })
    }

    // ---- capacity reservations ---------------------------------------------------------------

    pub(crate) fn create_capacity_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateCapacityReservationRequest,
    ) -> Result<t::CreateCapacityReservationResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "capacity-reservation", &["capacity-reservation"])?;
        let mut cond = request_tag_context(&tags);
        cond.insert("ec2:InstanceType".into(), vec![input.instance_type.clone()]);
        authorize(
            ctx,
            "CreateCapacityReservation",
            &[(arn(ctx, &account, "capacity-reservation/*"), cond)],
            input.dry_run,
        )?;
        if crate::catalog::instance_type(&input.instance_type).is_none() {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter instanceType is invalid.",
                input.instance_type
            )));
        }
        const PLATFORMS: &[&str] = &[
            "Linux/UNIX",
            "Red Hat Enterprise Linux",
            "SUSE Linux",
            "Windows",
            "Windows with SQL Server",
            "Windows with SQL Server Enterprise",
            "Windows with SQL Server Standard",
            "Windows with SQL Server Web",
            "Linux with SQL Server Standard",
            "Linux with SQL Server Web",
            "Linux with SQL Server Enterprise",
            "RHEL with SQL Server Standard",
            "RHEL with SQL Server Enterprise",
            "RHEL with SQL Server Web",
            "RHEL with HA",
            "RHEL with HA and SQL Server Standard",
            "RHEL with HA and SQL Server Enterprise",
            "Ubuntu Pro",
        ];
        if !PLATFORMS.contains(&input.instance_platform.as_str()) {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter instancePlatform is invalid.",
                input.instance_platform
            )));
        }
        if !(1..=1000).contains(&input.instance_count) {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter instanceCount is invalid.",
                input.instance_count
            )));
        }
        let end_type = input.end_date_type.clone().unwrap_or_else(|| "unlimited".into());
        match (end_type.as_str(), input.end_date) {
            ("limited", None) => {
                return Err(err("InvalidParameterCombination", "EndDate is required when EndDateType is limited."))
            }
            ("unlimited", Some(_)) => {
                return Err(err(
                    "InvalidParameterCombination",
                    "EndDate can't be specified when EndDateType is unlimited.",
                ))
            }
            ("limited", Some(e)) if e <= ctx.received_at => {
                return Err(invalid_parameter("The end date must be in the future."));
            }
            ("limited" | "unlimited", _) => {}
            (other, _) => {
                return Err(invalid_parameter(format!("Value ({other}) for parameter endDateType is invalid.")))
            }
        }
        let criteria = input.instance_match_criteria.clone().unwrap_or_else(|| "open".into());
        if !["open", "targeted"].contains(&criteria.as_str()) {
            return Err(invalid_parameter(format!(
                "Value ({criteria}) for parameter instanceMatchCriteria is invalid."
            )));
        }
        let now = ctx.received_at;
        let cr = self.with_region(ctx, |r| -> Result<_, ServiceError> {
            if let Some(token) = &input.client_token {
                if let Some(existing) =
                    r.capacity_reservation_tokens.get(token).and_then(|id| r.capacity_reservations.get(id))
                {
                    return Ok(reservation_view(r, existing, now));
                }
            }
            let (zone, zone_id) = match (&input.availability_zone, &input.availability_zone_id) {
                (Some(z), _) => {
                    let s = r.subnets.values().find(|s| s.availability_zone.as_deref() == Some(z.as_str()));
                    let s = s.ok_or_else(|| {
                        invalid_parameter(format!("Value ({z}) for parameter availabilityZone is invalid."))
                    })?;
                    (z.clone(), s.availability_zone_id.clone().unwrap_or_default())
                }
                (None, Some(id)) => {
                    let s = r.subnets.values().find(|s| s.availability_zone_id.as_deref() == Some(id.as_str()));
                    let s = s.ok_or_else(|| {
                        invalid_parameter(format!("Value ({id}) for parameter availabilityZoneId is invalid."))
                    })?;
                    (s.availability_zone.clone().unwrap_or_default(), id.clone())
                }
                (None, None) => return Err(crate::util::missing_parameter("AvailabilityZone")),
            };
            let id = new_id("cr");
            let cr = t::CapacityReservation {
                capacity_reservation_id: Some(id.clone()),
                owner_id: Some(account.clone()),
                capacity_reservation_arn: Some(arn(ctx, &account, &format!("capacity-reservation/{id}"))),
                availability_zone_id: Some(zone_id),
                instance_type: Some(input.instance_type.clone()),
                instance_platform: Some(input.instance_platform.clone()),
                availability_zone: Some(zone),
                tenancy: Some(input.tenancy.clone().unwrap_or_else(|| "default".into())),
                total_instance_count: Some(input.instance_count),
                available_instance_count: Some(input.instance_count),
                ebs_optimized: Some(input.ebs_optimized.unwrap_or(false)),
                ephemeral_storage: Some(false),
                state: Some("active".into()),
                start_date: Some(input.start_date.unwrap_or(now)),
                end_date: input.end_date,
                end_date_type: Some(end_type.clone()),
                instance_match_criteria: Some(criteria.clone()),
                create_date: Some(now),
                tags: some_tags(tags.clone()),
                placement_group_arn: input.placement_group_arn.clone(),
                capacity_allocations: Some(Vec::new()),
                reservation_type: Some("default".into()),
                delivery_preference: Some(input.delivery_preference.clone().unwrap_or_else(|| "fixed".into())),
                ..Default::default()
            };
            r.capacity_reservations.insert(id.clone(), cr.clone());
            if let Some(token) = &input.client_token {
                r.capacity_reservation_tokens.insert(token.clone(), id);
            }
            Ok(cr)
        })?;
        Ok(t::CreateCapacityReservationResult { capacity_reservation: Some(cr) })
    }

    fn reservation_resource(&self, ctx: &RequestContext, id: &str) -> Result<(String, ConditionContext), ServiceError> {
        let account = account_of(ctx);
        let tags = self.with_region(ctx, |r| r.capacity_reservations.get(id).map(|c| c.tags.clone()));
        let tags = tags.ok_or_else(|| {
            err("InvalidCapacityReservationId.NotFound", format!("The capacity reservation ID '{id}' does not exist"))
        })?;
        Ok((arn(ctx, &account, &format!("capacity-reservation/{id}")), resource_tag_context(tags.as_ref())))
    }

    pub(crate) fn describe_capacity_reservations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeCapacityReservationsRequest,
    ) -> Result<t::DescribeCapacityReservationsResult, ServiceError> {
        authorize(ctx, "DescribeCapacityReservations", &account_resource(ctx), input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.capacity_reservation_ids.clone().unwrap_or_default();
        let now = ctx.received_at;
        let out = self.with_region(ctx, |r| -> Result<_, ServiceError> {
            for id in &ids {
                if !r.capacity_reservations.contains_key(id) {
                    return Err(err(
                        "InvalidCapacityReservationId.NotFound",
                        format!("The capacity reservation ID '{id}' does not exist"),
                    ));
                }
            }
            let mut out = Vec::new();
            for cr in r.capacity_reservations.values() {
                let cr = reservation_view(r, cr, now);
                if !ids.is_empty() && !cr.capacity_reservation_id.as_ref().is_some_and(|i| ids.contains(i)) {
                    continue;
                }
                let ok = filters.matches(cr.tags.as_ref(), |name| {
                    Some(match name {
                        "instance-type" => s(&cr.instance_type),
                        "owner-id" => s(&cr.owner_id),
                        "instance-platform" => s(&cr.instance_platform),
                        "availability-zone" => s(&cr.availability_zone),
                        "tenancy" => s(&cr.tenancy),
                        "state" => s(&cr.state),
                        "end-date-type" => s(&cr.end_date_type),
                        "instance-match-criteria" => s(&cr.instance_match_criteria),
                        "placement-group-arn" => s(&cr.placement_group_arn),
                        "capacity-reservation-id" => s(&cr.capacity_reservation_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(cr);
                }
            }
            Ok(out)
        })?;
        let (capacity_reservations, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribeCapacityReservationsResult { capacity_reservations: Some(capacity_reservations), next_token })
    }

    pub(crate) fn modify_capacity_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyCapacityReservationRequest,
    ) -> Result<t::ModifyCapacityReservationResult, ServiceError> {
        let resource = self.reservation_resource(ctx, &input.capacity_reservation_id)?;
        authorize(ctx, "ModifyCapacityReservation", &[resource], input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let view = reservation_view(r, &r.capacity_reservations[&input.capacity_reservation_id], now);
            if view.state.as_deref() != Some("active") {
                return Err(err(
                    "InvalidCapacityReservationId.Malformed",
                    format!(
                        "The capacity reservation '{}' is {}.",
                        input.capacity_reservation_id,
                        view.state.unwrap_or_default()
                    ),
                ));
            }
            let cr = r.capacity_reservations.get_mut(&input.capacity_reservation_id).expect("exists");
            if let Some(n) = input.instance_count {
                if !(1..=1000).contains(&n) {
                    return Err(invalid_parameter(format!("Value ({n}) for parameter instanceCount is invalid.")));
                }
                cr.total_instance_count = Some(n);
            }
            if let Some(t) = &input.end_date_type {
                cr.end_date_type = Some(t.clone());
                if t == "unlimited" {
                    cr.end_date = None;
                }
            }
            if let Some(e) = input.end_date {
                if e <= now {
                    return Err(invalid_parameter("The end date must be in the future."));
                }
                cr.end_date = Some(e);
            }
            if cr.end_date_type.as_deref() == Some("limited") && cr.end_date.is_none() {
                return Err(err("InvalidParameterCombination", "EndDate is required when EndDateType is limited."));
            }
            if let Some(c) = &input.instance_match_criteria {
                if !["open", "targeted"].contains(&c.as_str()) {
                    return Err(invalid_parameter(format!(
                        "Value ({c}) for parameter instanceMatchCriteria is invalid."
                    )));
                }
                cr.instance_match_criteria = Some(c.clone());
            }
            Ok(t::ModifyCapacityReservationResult { r#return: Some(true), ..Default::default() })
        })
    }

    pub(crate) fn cancel_capacity_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelCapacityReservationRequest,
    ) -> Result<t::CancelCapacityReservationResult, ServiceError> {
        let resource = self.reservation_resource(ctx, &input.capacity_reservation_id)?;
        authorize(ctx, "CancelCapacityReservation", &[resource], input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let id = input.capacity_reservation_id.clone();
            let view = reservation_view(r, &r.capacity_reservations[&id], now);
            if view.state.as_deref() != Some("active") {
                return Err(err(
                    "IncorrectState",
                    format!("The capacity reservation '{id}' is {}.", view.state.unwrap_or_default()),
                ));
            }
            let cr = r.capacity_reservations.get_mut(&id).expect("exists");
            cr.state = Some("cancelled".into());
            cr.end_date = Some(now);
            // Instances keep running, outside the reservation.
            for i in r.instances.values_mut() {
                if i.instance.capacity_reservation_id.as_deref() == Some(id.as_str()) {
                    i.instance.capacity_reservation_id = None;
                }
            }
            Ok(t::CancelCapacityReservationResult { r#return: Some(true) })
        })
    }

    pub(crate) fn get_capacity_reservation_usage_op(
        &self,
        ctx: &RequestContext,
        input: t::GetCapacityReservationUsageRequest,
    ) -> Result<t::GetCapacityReservationUsageResult, ServiceError> {
        let resource = self.reservation_resource(ctx, &input.capacity_reservation_id)?;
        authorize(ctx, "GetCapacityReservationUsage", &[resource], input.dry_run)?;
        let now = ctx.received_at;
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            let cr = reservation_view(r, &r.capacity_reservations[&input.capacity_reservation_id], now);
            let used = cr.total_instance_count.unwrap_or(0) - cr.available_instance_count.unwrap_or(0);
            let usages = if used > 0 && cr.state.as_deref() == Some("active") {
                vec![t::InstanceUsage { account_id: Some(account.clone()), used_instance_count: Some(used) }]
            } else {
                Vec::new()
            };
            let (usages, next_token) = paginate(usages, input.max_results, &input.next_token)?;
            Ok(t::GetCapacityReservationUsageResult {
                next_token,
                capacity_reservation_id: cr.capacity_reservation_id.clone(),
                instance_type: cr.instance_type.clone(),
                total_instance_count: cr.total_instance_count,
                available_instance_count: cr.available_instance_count,
                state: cr.state.clone(),
                instance_usages: Some(usages),
                ..Default::default()
            })
        })
    }

    // ---- network interface permissions -------------------------------------------------------

    pub(crate) fn reset_network_interface_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ResetNetworkInterfaceAttributeRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let id = input.network_interface_id.clone();
        let tags = self.with_region(ctx, |r| {
            Kind::NetworkInterface.check_all(std::slice::from_ref(&id), |i| r.network_interfaces.contains_key(i))?;
            Ok::<_, ServiceError>(r.network_interfaces[&id].tag_set.clone())
        })?;
        authorize(
            ctx,
            "ResetNetworkInterfaceAttribute",
            &[(arn(ctx, &account, &format!("network-interface/{id}")), resource_tag_context(tags.as_ref()))],
            input.dry_run,
        )?;
        if input.source_dest_check.as_deref().is_some_and(|v| v != "sourceDestCheck") {
            return Err(invalid_parameter(
                "Value for parameter sourceDestCheck is invalid. Valid value: sourceDestCheck.",
            ));
        }
        self.with_region(ctx, |r| {
            if let Some(n) = r.network_interfaces.get_mut(&id) {
                n.source_dest_check = Some(true);
            }
        });
        Ok(())
    }

    pub(crate) fn create_network_interface_permission_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateNetworkInterfacePermissionRequest,
    ) -> Result<t::CreateNetworkInterfacePermissionResult, ServiceError> {
        let account = account_of(ctx);
        let id = input.network_interface_id.clone();
        let tags = self.with_region(ctx, |r| {
            Kind::NetworkInterface.check_all(std::slice::from_ref(&id), |i| r.network_interfaces.contains_key(i))?;
            Ok::<_, ServiceError>(r.network_interfaces[&id].tag_set.clone())
        })?;
        authorize(
            ctx,
            "CreateNetworkInterfacePermission",
            &[(arn(ctx, &account, &format!("network-interface/{id}")), resource_tag_context(tags.as_ref()))],
            input.dry_run,
        )?;
        if input.aws_account_id.is_some() == input.aws_service.is_some() {
            return Err(err(
                "InvalidParameterCombination",
                "Specify either an AWS account ID or an AWS service, but not both.",
            ));
        }
        if !["INSTANCE-ATTACH", "EIP-ASSOCIATE"].contains(&input.permission.as_str()) {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter permission is invalid.",
                input.permission
            )));
        }
        if let Some(a) = &input.aws_account_id {
            if !(a.len() == 12 && a.bytes().all(|b| b.is_ascii_digit())) {
                return Err(invalid_parameter(format!("Value ({a}) for parameter awsAccountId is invalid.")));
            }
        }
        let perm = self.with_region(ctx, |r| -> Result<_, ServiceError> {
            if r.eni_permissions.values().any(|p| {
                p.network_interface_id.as_deref() == Some(id.as_str())
                    && p.aws_account_id == input.aws_account_id
                    && p.aws_service == input.aws_service
                    && p.permission.as_deref() == Some(input.permission.as_str())
            }) {
                return Err(err(
                    "InvalidPermission.Duplicate",
                    format!("The permission {} already exists for network interface {id}.", input.permission),
                ));
            }
            let perm = t::NetworkInterfacePermission {
                network_interface_permission_id: Some(new_id("eni-perm")),
                network_interface_id: Some(id.clone()),
                aws_account_id: input.aws_account_id.clone(),
                aws_service: input.aws_service.clone(),
                permission: Some(input.permission.clone()),
                permission_state: Some(t::NetworkInterfacePermissionState {
                    state: Some("granted".into()),
                    status_message: None,
                }),
            };
            r.eni_permissions.insert(perm.network_interface_permission_id.clone().unwrap_or_default(), perm.clone());
            Ok(perm)
        })?;
        Ok(t::CreateNetworkInterfacePermissionResult { interface_permission: Some(perm) })
    }

    pub(crate) fn describe_network_interface_permissions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeNetworkInterfacePermissionsRequest,
    ) -> Result<t::DescribeNetworkInterfacePermissionsResult, ServiceError> {
        authorize(ctx, "DescribeNetworkInterfacePermissions", &account_resource(ctx), None)?;
        let filters = Filters::new(&input.filters);
        let ids = input.network_interface_permission_ids.clone().unwrap_or_default();
        let out = self.with_region(ctx, |r| -> Result<_, ServiceError> {
            for id in &ids {
                if !r.eni_permissions.contains_key(id) {
                    return Err(err(
                        "InvalidPermissionID.NotFound",
                        format!("The network interface permission ID '{id}' does not exist"),
                    ));
                }
            }
            let mut out = Vec::new();
            for p in r.eni_permissions.values() {
                if !ids.is_empty() && !p.network_interface_permission_id.as_ref().is_some_and(|i| ids.contains(i)) {
                    continue;
                }
                let ok = filters.matches(None, |name| {
                    Some(match name {
                        "network-interface-permission.network-interface-permission-id" => {
                            s(&p.network_interface_permission_id)
                        }
                        "network-interface-permission.network-interface-id" => s(&p.network_interface_id),
                        "network-interface-permission.aws-account-id" => s(&p.aws_account_id),
                        "network-interface-permission.aws-service" => s(&p.aws_service),
                        "network-interface-permission.permission" => s(&p.permission),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(p.clone());
                }
            }
            Ok(out)
        })?;
        let (perms, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribeNetworkInterfacePermissionsResult { network_interface_permissions: Some(perms), next_token })
    }

    pub(crate) fn delete_network_interface_permission_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteNetworkInterfacePermissionRequest,
    ) -> Result<t::DeleteNetworkInterfacePermissionResult, ServiceError> {
        let account = account_of(ctx);
        let id = input.network_interface_permission_id.clone();
        let eni = self.with_region(ctx, |r| r.eni_permissions.get(&id).and_then(|p| p.network_interface_id.clone()));
        let eni = eni.ok_or_else(|| {
            err("InvalidPermissionID.NotFound", format!("The network interface permission ID '{id}' does not exist"))
        })?;
        authorize(
            ctx,
            "DeleteNetworkInterfacePermission",
            &[(arn(ctx, &account, &format!("network-interface/{eni}")), ConditionContext::new())],
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            // A permission in use (the interface attached to another
            // account's instance) needs Force.
            let attached_elsewhere = r
                .network_interfaces
                .get(&eni)
                .and_then(|n| n.attachment.as_ref())
                .and_then(|a| a.instance_owner_id.clone())
                .is_some_and(|owner| owner != account);
            if attached_elsewhere && input.force != Some(true) {
                return Err(err(
                    "InvalidPermission.InUse",
                    format!("The network interface permission '{id}' is in use. Use Force to delete it."),
                ));
            }
            r.eni_permissions.remove(&id);
            Ok(t::DeleteNetworkInterfacePermissionResult { r#return: Some(true) })
        })
    }
}
