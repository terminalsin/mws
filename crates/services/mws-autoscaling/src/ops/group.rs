//! Groups: create, update, delete, describe; capacity; processes, metrics
//! and tags.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_ec2::generated::types as et;
use mws_ec2::generated::Handler as _;

use super::{authorized_group, render_group};
use crate::generated::types as t;
use crate::state::{Group, RegionState};
use crate::util::{
    already_exists, at, authorize, group_arn, group_resource, launch_configuration_arn, limit_exceeded, paginate,
    request_tags, resource_in_use, scaling_in_progress, validation, METRICS, PROCESSES, TERMINATION_POLICIES,
};
use crate::{account_of, AutoScaling};

pub(crate) const MAX_GROUPS: usize = 500;

/// Subnets with their zones, the zones, and the subnet list.
pub(crate) type Zones = (BTreeMap<String, (String, String)>, Vec<String>, Option<String>);

pub(crate) fn check_sizes(min: i32, max: i32, desired: i32) -> Result<(), ServiceError> {
    if min < 0 || max < 0 {
        return Err(validation("MinSize and MaxSize must be non-negative."));
    }
    if max < min {
        return Err(validation(format!("Max bound, {max}, must be greater than or equal to min bound, {min}")));
    }
    if desired < min || desired > max {
        return Err(validation(format!(
            "Desired capacity:{desired} must be between the specified min size:{min} and max size:{max}"
        )));
    }
    Ok(())
}

fn check_termination_policies(policies: &Option<Vec<String>>) -> Result<(), ServiceError> {
    for p in policies.iter().flatten() {
        if !TERMINATION_POLICIES.contains(&p.as_str()) && !p.starts_with("arn:") {
            return Err(validation(format!("Termination policy {p} is not supported.")));
        }
    }
    Ok(())
}

fn check_health_check_type(t: &Option<String>) -> Result<(), ServiceError> {
    if let Some(t) = t {
        for part in t.split(',') {
            if !matches!(part.trim(), "EC2" | "ELB" | "VPC_LATTICE" | "EBS") {
                return Err(validation(format!(
                    "Health check type {t} is not supported. Valid values are EC2, ELB, VPC_LATTICE and EBS."
                )));
            }
        }
    }
    Ok(())
}

fn version_specified(spec: &t::LaunchTemplateSpecification) -> bool {
    spec.version.is_some()
}

/// Tags for a new group, as `DescribeTags` shows them.
pub(crate) fn tag_descriptions(group: &str, tags: &[t::Tag]) -> Result<Vec<t::TagDescription>, ServiceError> {
    let mut out: Vec<t::TagDescription> = Vec::new();
    for tag in tags {
        if tag.key.is_empty() {
            return Err(validation("Tag key must not be empty."));
        }
        if tag.key.to_ascii_lowercase().starts_with("aws:") {
            return Err(validation("Tag keys starting with 'aws:' are reserved for internal use"));
        }
        if let Some(rt) = &tag.resource_type {
            if rt != "auto-scaling-group" {
                return Err(validation(format!("Invalid resource type: {rt}")));
            }
        }
        out.retain(|t| t.key.as_deref() != Some(tag.key.as_str()));
        out.push(t::TagDescription {
            resource_id: Some(group.to_string()),
            resource_type: Some("auto-scaling-group".into()),
            key: Some(tag.key.clone()),
            value: Some(tag.value.clone().unwrap_or_default()),
            propagate_at_launch: Some(tag.propagate_at_launch.unwrap_or(false)),
        });
    }
    if out.len() > 50 {
        return Err(limit_exceeded("The number of tags exceeds the limit of 50 tags per Auto Scaling group."));
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

impl AutoScaling {
    /// Check a launch template a group names: it exists, and the caller may
    /// launch with it.
    pub(crate) fn check_launch_template(
        &self,
        ctx: &RequestContext,
        spec: &t::LaunchTemplateSpecification,
    ) -> Result<mws_ec2::ResolvedLaunchTemplate, ServiceError> {
        if spec.launch_template_id.is_none() && spec.launch_template_name.is_none() {
            return Err(validation("Valid requests must contain either launchTemplateId or launchTemplateName."));
        }
        if spec.launch_template_id.is_some() && spec.launch_template_name.is_some() {
            return Err(validation(
                "Valid requests must contain either launchTemplateId or launchTemplateName, not both.",
            ));
        }
        if let Some(v) = &spec.version {
            if !matches!(v.as_str(), "$Latest" | "$Default") && v.parse::<i64>().is_err() {
                return Err(validation(format!(
                    "The launch template version {v} is invalid. Specify $Latest, $Default, or a version number."
                )));
            }
        }
        let resolved = self
            .ec2()
            .resolve_launch_template(
                ctx,
                &et::LaunchTemplateSpecification {
                    launch_template_id: spec.launch_template_id.clone(),
                    launch_template_name: spec.launch_template_name.clone(),
                    version: spec.version.clone(),
                },
            )
            .map_err(|e| validation(format!("You must use a valid fully-formed launch template. {}", e.message)))?;
        let arn =
            format!("arn:{}:ec2:{}:{}:launch-template/{}", ctx.partition, ctx.region, account_of(ctx), resolved.id);
        ctx.authorize("ec2:RunInstances", &arn, ConditionContext::new())
            .map_err(|_| validation(format!("You are not authorized to use launch template: {}", resolved.name)))?;
        Ok(resolved)
    }

    /// The subnets a group launches into.
    pub(crate) async fn resolve_zones(
        &self,
        sctx: &RequestContext,
        vpc_zone_identifier: Option<&str>,
        zones: Option<&[String]>,
    ) -> Result<Zones, ServiceError> {
        let subnets: Vec<String> = vpc_zone_identifier
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let mut out = BTreeMap::new();
        if !subnets.is_empty() {
            let mut vpc: Option<String> = None;
            for id in &subnets {
                let found = self
                    .ec2_subnets(sctx, std::slice::from_ref(id))
                    .await
                    .ok()
                    .and_then(|s| s.into_iter().next())
                    .ok_or_else(|| validation(format!("The subnet ID '{id}' does not exist")))?;
                let v = found.vpc_id.clone().unwrap_or_default();
                if vpc.as_ref().is_some_and(|p| *p != v) {
                    return Err(validation("The subnets specified must belong to the same VPC."));
                }
                vpc = Some(v);
                out.insert(
                    id.clone(),
                    (found.availability_zone.unwrap_or_default(), found.availability_zone_id.unwrap_or_default()),
                );
            }
            let mut azs: Vec<String> = out.values().map(|(z, _)| z.clone()).collect();
            azs.sort();
            azs.dedup();
            if let Some(requested) = zones.filter(|z| !z.is_empty()) {
                if let Some(z) = requested.iter().find(|z| !azs.contains(z)) {
                    return Err(validation(format!(
                        "The availability zone {z} is not legal for the subnets specified."
                    )));
                }
            }
            return Ok((out, azs, Some(subnets.join(","))));
        }
        let Some(zones) = zones.filter(|z| !z.is_empty()) else {
            return Err(validation("At least one Availability Zone or VPC Subnet is required."));
        };
        let known: Vec<String> = self.ec2_zones(sctx).await.into_iter().map(|(z, _)| z).collect();
        for z in zones {
            if !known.contains(z) {
                return Err(validation(format!("The availability zone '{z}' is not valid.")));
            }
        }
        let defaults = self.ec2_default_subnets(sctx, zones).await?;
        for z in zones {
            let s = defaults
                .iter()
                .find(|s| s.availability_zone.as_deref() == Some(z.as_str()))
                .ok_or_else(|| validation(format!("No default subnet for availability zone: '{z}'.")))?;
            out.insert(
                s.subnet_id.clone().unwrap_or_default(),
                (z.clone(), s.availability_zone_id.clone().unwrap_or_default()),
            );
        }
        let mut azs = zones.to_vec();
        azs.sort();
        azs.dedup();
        Ok((out, azs, None))
    }

    /// A launch configuration from a running instance (`InstanceId`).
    pub(crate) async fn configuration_from_instance(
        &self,
        ctx: &RequestContext,
        name: &str,
        instance_id: &str,
    ) -> Result<(t::LaunchConfiguration, Option<String>), ServiceError> {
        let not_found = || validation(format!("Invalid instance id: {instance_id}"));
        let out = self
            .ec2()
            .describe_instances(
                ctx,
                et::DescribeInstancesRequest {
                    instance_ids: Some(vec![instance_id.to_string()]),
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| not_found())?;
        let i = out
            .reservations
            .unwrap_or_default()
            .into_iter()
            .flat_map(|r| r.instances.unwrap_or_default())
            .next()
            .ok_or_else(not_found)?;
        let lc = t::LaunchConfiguration {
            launch_configuration_name: name.to_string(),
            launch_configuration_arn: Some(launch_configuration_arn(ctx, &account_of(ctx), name)),
            image_id: i.image_id.clone().unwrap_or_default(),
            key_name: i.key_name.clone(),
            security_groups: Some(
                i.security_groups.clone().unwrap_or_default().into_iter().filter_map(|g| g.group_id).collect(),
            ),
            instance_type: i.instance_type.clone().unwrap_or_default(),
            kernel_id: i.kernel_id.clone(),
            ramdisk_id: i.ramdisk_id.clone(),
            block_device_mappings: Some(Vec::new()),
            instance_monitoring: Some(t::InstanceMonitoring {
                enabled: Some(i.monitoring.as_ref().and_then(|m| m.state.as_deref()) == Some("enabled")),
            }),
            iam_instance_profile: i.iam_instance_profile.as_ref().and_then(|p| p.arn.clone()),
            created_time: self.now(),
            ebs_optimized: i.ebs_optimized,
            ..Default::default()
        };
        Ok((lc, i.subnet_id))
    }

    pub(crate) async fn create_auto_scaling_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateAutoScalingGroupType,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let name = input.auto_scaling_group_name.clone();
        let tags = input.tags.clone().unwrap_or_default();
        let mut cond = request_tags(&tags);
        cond.insert("autoscaling:MinSize".into(), vec![input.min_size.to_string()]);
        cond.insert("autoscaling:MaxSize".into(), vec![input.max_size.to_string()]);
        if let Some(lc) = &input.launch_configuration_name {
            cond.insert("autoscaling:LaunchConfigurationName".into(), vec![lc.clone()]);
        }
        if let Some(spec) = &input.launch_template {
            cond.insert("autoscaling:LaunchTemplateVersionSpecified".into(), vec![version_specified(spec).to_string()]);
        }
        if let Some(v) = &input.vpc_zone_identifier {
            cond.insert("autoscaling:VPCZoneIdentifiers".into(), v.split(',').map(|s| s.trim().to_string()).collect());
        }
        authorize(ctx, "CreateAutoScalingGroup", &group_resource(ctx, &account, &name), None, cond)?;
        let existing = self.with_region(ctx, |r| (r.groups.contains_key(&name), r.groups.len()));
        if existing.0 {
            return Err(already_exists(format!(
                "AutoScalingGroup by this name already exists - A group with the name {name} already exists"
            )));
        }
        if existing.1 >= MAX_GROUPS {
            return Err(limit_exceeded(format!(
                "You have reached your limit of {MAX_GROUPS} Auto Scaling groups. Delete unused groups or request a limit increase."
            )));
        }
        let desired = input.desired_capacity.unwrap_or(input.min_size);
        check_sizes(input.min_size, input.max_size, desired)?;
        check_termination_policies(&input.termination_policies)?;
        check_health_check_type(&input.health_check_type)?;
        let sources = [
            input.launch_template.is_some(),
            input.launch_configuration_name.is_some(),
            input.instance_id.is_some(),
            input.mixed_instances_policy.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if sources != 1 {
            return Err(validation(
                "Valid requests must contain either LaunchTemplate, LaunchConfigurationName, InstanceId or MixedInstancesPolicy parameter.",
            ));
        }
        if let Some(lc) = &input.launch_configuration_name {
            if !self.with_region(ctx, |r| r.launch_configurations.contains_key(lc)) {
                return Err(validation(format!(
                    "Launch configuration name not found - Launch configuration {lc} not found"
                )));
            }
        }
        if let Some(spec) = &input.launch_template {
            self.check_launch_template(ctx, spec)?;
        }
        if let Some(mip) = &input.mixed_instances_policy {
            let spec = mip
                .launch_template
                .as_ref()
                .and_then(|l| l.launch_template_specification.as_ref())
                .ok_or_else(|| validation("A mixed instances policy must specify a launch template."))?;
            self.check_launch_template(ctx, spec)?;
        }
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        let mut vpc = input.vpc_zone_identifier.clone();
        let mut launch_configuration_name = input.launch_configuration_name.clone();
        if let Some(iid) = &input.instance_id {
            let (lc, subnet) = self.configuration_from_instance(ctx, &name, iid).await?;
            if vpc.as_deref().unwrap_or_default().is_empty() && input.availability_zones.is_none() {
                vpc = subnet;
            }
            launch_configuration_name = Some(name.clone());
            self.with_region(ctx, |r| {
                r.launch_configurations.entry(name.clone()).or_insert(lc);
            });
        }
        let (subnet_zones, azs, vpc_zone_identifier) =
            self.resolve_zones(&sctx, vpc.as_deref(), input.availability_zones.as_deref()).await?;
        let tags = tag_descriptions(&name, &tags)?;
        let mut hooks = BTreeMap::new();
        for spec in input.lifecycle_hook_specification_list.clone().unwrap_or_default() {
            let hook = super::hooks::make_hook(
                &name,
                &spec.lifecycle_hook_name,
                None,
                Some(spec.lifecycle_transition.clone()),
                spec.notification_target_arn.clone(),
                spec.role_arn.clone(),
                spec.notification_metadata.clone(),
                spec.heartbeat_timeout,
                spec.default_result.clone(),
            )?;
            hooks.insert(spec.lifecycle_hook_name.clone(), hook);
        }
        let zone_ids: Vec<String> = {
            let mut v: Vec<String> =
                subnet_zones.values().map(|(_, id)| id.clone()).filter(|i| !i.is_empty()).collect();
            v.sort();
            v.dedup();
            v
        };
        let now = self.now();
        let cfg = t::AutoScalingGroup {
            auto_scaling_group_name: name.clone(),
            auto_scaling_group_arn: Some(group_arn(ctx, &account, &name)),
            launch_configuration_name,
            launch_template: input.launch_template.clone().map(|mut s| {
                if s.version.is_none() {
                    s.version = Some("$Default".into());
                }
                s
            }),
            mixed_instances_policy: input.mixed_instances_policy.clone(),
            min_size: input.min_size,
            max_size: input.max_size,
            desired_capacity: desired,
            default_cooldown: input.default_cooldown.unwrap_or(300),
            availability_zones: azs,
            availability_zone_ids: Some(zone_ids),
            health_check_type: input.health_check_type.clone().unwrap_or_else(|| "EC2".into()),
            health_check_grace_period: Some(input.health_check_grace_period.unwrap_or(0)),
            created_time: now,
            suspended_processes: Some(Vec::new()),
            placement_group: input.placement_group.clone(),
            vpc_zone_identifier,
            enabled_metrics: Some(Vec::new()),
            tags: Some(tags),
            termination_policies: Some(input.termination_policies.clone().unwrap_or_else(|| vec!["Default".into()])),
            new_instances_protected_from_scale_in: Some(input.new_instances_protected_from_scale_in.unwrap_or(false)),
            service_linked_role_arn: Some(input.service_linked_role_arn.clone().unwrap_or_else(|| {
                format!(
                    "arn:{}:iam::{account}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                    ctx.partition
                )
            })),
            max_instance_lifetime: input.max_instance_lifetime,
            capacity_rebalance: Some(input.capacity_rebalance.unwrap_or(false)),
            context: input.context.clone(),
            desired_capacity_type: input.desired_capacity_type.clone(),
            default_instance_warmup: input.default_instance_warmup,
            instance_maintenance_policy: input.instance_maintenance_policy.clone(),
            deletion_protection: Some(input.deletion_protection.clone().unwrap_or_else(|| "none".into())),
            availability_zone_distribution: Some(input.availability_zone_distribution.clone().unwrap_or(
                t::AvailabilityZoneDistribution { capacity_distribution_strategy: Some("balanced-best-effort".into()) },
            )),
            availability_zone_impairment_policy: input.availability_zone_impairment_policy.clone(),
            capacity_reservation_specification: input.capacity_reservation_specification.clone(),
            instance_lifecycle_policy: input.instance_lifecycle_policy.clone(),
            operator: input.operator.clone(),
            ..Default::default()
        };
        let mut g = Group { cfg, hooks, subnet_zones, ..Default::default() };
        let sources = input
            .load_balancer_names
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|n| t::TrafficSourceIdentifier { identifier: n, r#type: Some("elb".into()) })
            .chain(
                input
                    .target_group_ar_ns
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|n| t::TrafficSourceIdentifier { identifier: n, r#type: Some("elbv2".into()) }),
            )
            .chain(input.traffic_sources.clone().unwrap_or_default());
        for ts in sources {
            g.traffic_sources.insert(ts.identifier.clone(), super::traffic::source_state(&ts, "Added"));
        }
        self.with_region(ctx, |r| {
            if r.groups.contains_key(&name) {
                return Err(already_exists(format!(
                    "AutoScalingGroup by this name already exists - A group with the name {name} already exists"
                )));
            }
            r.groups.insert(name.clone(), g);
            Ok(())
        })
    }

    pub(crate) async fn update_auto_scaling_group_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateAutoScalingGroupType,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let name = input.auto_scaling_group_name.clone();
        let mut cond = ConditionContext::new();
        if let Some(v) = input.min_size {
            cond.insert("autoscaling:MinSize".into(), vec![v.to_string()]);
        }
        if let Some(v) = input.max_size {
            cond.insert("autoscaling:MaxSize".into(), vec![v.to_string()]);
        }
        if let Some(lc) = &input.launch_configuration_name {
            cond.insert("autoscaling:LaunchConfigurationName".into(), vec![lc.clone()]);
        }
        if let Some(spec) = &input.launch_template {
            cond.insert("autoscaling:LaunchTemplateVersionSpecified".into(), vec![version_specified(spec).to_string()]);
        }
        if let Some(v) = &input.vpc_zone_identifier {
            cond.insert("autoscaling:VPCZoneIdentifiers".into(), v.split(',').map(|s| s.trim().to_string()).collect());
        }
        self.with_region(ctx, |r| {
            super::authorized_group_with(ctx, r, "UpdateAutoScalingGroup", &name, cond).map(drop)
        })?;
        check_termination_policies(&input.termination_policies)?;
        check_health_check_type(&input.health_check_type)?;
        if let Some(lc) = &input.launch_configuration_name {
            if !self.with_region(ctx, |r| r.launch_configurations.contains_key(lc)) {
                return Err(validation(format!(
                    "Launch configuration name not found - Launch configuration {lc} not found"
                )));
            }
        }
        if let Some(spec) = &input.launch_template {
            self.check_launch_template(ctx, spec)?;
        }
        if let Some(spec) = input
            .mixed_instances_policy
            .as_ref()
            .and_then(|m| m.launch_template.as_ref())
            .and_then(|l| l.launch_template_specification.as_ref())
        {
            self.check_launch_template(ctx, spec)?;
        }
        let zones = if input.vpc_zone_identifier.is_some() || input.availability_zones.is_some() {
            let sctx = self.service_ctx(ctx, &account, &ctx.region);
            Some(
                self.resolve_zones(&sctx, input.vpc_zone_identifier.as_deref(), input.availability_zones.as_deref())
                    .await?,
            )
        } else {
            None
        };
        let now = self.now();
        self.with_region(ctx, |r| {
            let g = r.groups.get_mut(&name).ok_or_else(|| crate::util::group_not_found(&name))?;
            if g.deleting {
                return Err(scaling_in_progress(
                    "You cannot update an AutoScalingGroup while it is being deleted.".to_string(),
                ));
            }
            let c = &mut g.cfg;
            let min = input.min_size.unwrap_or(c.min_size);
            let max = input.max_size.unwrap_or(c.max_size);
            let mut desired = input.desired_capacity.unwrap_or(c.desired_capacity);
            if input.desired_capacity.is_none() {
                desired = desired.clamp(min, max.max(min));
            }
            check_sizes(min, max, desired)?;
            let before = c.desired_capacity;
            c.min_size = min;
            c.max_size = max;
            c.desired_capacity = desired;
            if before != desired {
                let fmt = |v: Option<i32>| v.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
                g.pending_cause = Some(format!(
                    "{} a user request update of AutoScalingGroup constraints to min: {}, max: {}, desired: {} changing the desired capacity from {before} to {desired}.",
                    at(now),
                    fmt(input.min_size),
                    fmt(input.max_size),
                    fmt(input.desired_capacity)
                ));
            }
            let c = &mut g.cfg;
            if let Some(lc) = &input.launch_configuration_name {
                c.launch_configuration_name = Some(lc.clone());
                c.launch_template = None;
                c.mixed_instances_policy = None;
            }
            if let Some(lt) = &input.launch_template {
                let mut lt = lt.clone();
                if lt.version.is_none() {
                    lt.version = Some("$Default".into());
                }
                c.launch_template = Some(lt);
                c.launch_configuration_name = None;
                c.mixed_instances_policy = None;
            }
            if let Some(m) = &input.mixed_instances_policy {
                if g.cfg.warm_pool_configuration.is_some() {
                    return Err(validation(
                        "You can't add a mixed instances policy to an Auto Scaling group that has a warm pool.",
                    ));
                }
                let c = &mut g.cfg;
                c.mixed_instances_policy = Some(m.clone());
                c.launch_template = None;
                c.launch_configuration_name = None;
            }
            let c = &mut g.cfg;
            macro_rules! set {
                ($field:ident) => {
                    if let Some(v) = &input.$field {
                        c.$field = Some(v.clone());
                    }
                };
            }
            if let Some(v) = input.default_cooldown {
                c.default_cooldown = v;
            }
            if let Some(v) = &input.health_check_type {
                c.health_check_type = v.clone();
            }
            set!(health_check_grace_period);
            set!(placement_group);
            set!(termination_policies);
            set!(new_instances_protected_from_scale_in);
            set!(service_linked_role_arn);
            set!(max_instance_lifetime);
            set!(capacity_rebalance);
            set!(context);
            set!(desired_capacity_type);
            set!(default_instance_warmup);
            set!(instance_maintenance_policy);
            set!(availability_zone_distribution);
            set!(availability_zone_impairment_policy);
            set!(capacity_reservation_specification);
            set!(instance_lifecycle_policy);
            set!(deletion_protection);
            if let Some((subnets, azs, vpc)) = zones {
                c.availability_zones = azs;
                let mut ids: Vec<String> = subnets.values().map(|(_, id)| id.clone()).filter(|i| !i.is_empty()).collect();
                ids.sort();
                ids.dedup();
                c.availability_zone_ids = Some(ids);
                c.vpc_zone_identifier = vpc;
                g.subnet_zones = subnets;
                // Instances outside the new zones are replaced by rebalancing.
            }
            Ok(())
        })
    }

    pub(crate) async fn delete_auto_scaling_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteAutoScalingGroupType,
    ) -> Result<(), ServiceError> {
        let name = input.auto_scaling_group_name.clone();
        let force = input.force_delete.unwrap_or(false);
        let account = account_of(ctx);
        let removed = self.with_region(ctx, |r| -> Result<Group, ServiceError> {
            let g = authorized_group(ctx, r, "DeleteAutoScalingGroup", &name)?;
            match g.cfg.deletion_protection.as_deref() {
                Some("prevent-all-deletion") => {
                    return Err(validation(format!(
                        "Deletion protection is enabled for Auto Scaling group {name}. Disable deletion protection to delete the group."
                    )))
                }
                Some("prevent-force-deletion") if force => {
                    return Err(validation(format!(
                        "Force deletion is prevented for Auto Scaling group {name} by its deletion protection setting."
                    )))
                }
                _ => {}
            }
            if !force {
                if !g.members.is_empty() {
                    return Err(resource_in_use(
                        "You cannot delete an AutoScalingGroup while there are instances or pending Spot instance request(s) still in the group.",
                    ));
                }
                let busy = r.activities.iter().any(|a| {
                    a.auto_scaling_group_name == name && !matches!(a.status_code.as_str(), "Successful" | "Failed" | "Cancelled")
                });
                if busy {
                    return Err(scaling_in_progress(
                        "You cannot delete an AutoScalingGroup while there are scaling activities in progress for that group.",
                    ));
                }
            }
            Ok(r.groups.remove(&name).expect("group exists"))
        })?;
        // Force delete: terminate everything without waiting for lifecycle
        // actions.
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        let ids: Vec<String> = removed.members.keys().cloned().collect();
        if !ids.is_empty() {
            let _ = self.ec2_terminate(&sctx, ids).await;
        }
        let alarms: Vec<String> = removed.policy_alarms.values().flatten().cloned().collect();
        if let (Some(mgr), false) = (self.alarms(), alarms.is_empty()) {
            mgr.delete_alarms(&sctx, &alarms).await;
        }
        let deregister = super::traffic::deregister_all_ops(&removed);
        for op in deregister {
            self.deliver_traffic(&sctx, op);
        }
        Ok(())
    }

    pub(crate) async fn describe_auto_scaling_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::AutoScalingGroupNamesType,
    ) -> Result<t::AutoScalingGroupsType, ServiceError> {
        authorize(ctx, "DescribeAutoScalingGroups", "*", None, ConditionContext::new())?;
        let names = input.auto_scaling_group_names.clone().unwrap_or_default();
        let filters = input.filters.clone().unwrap_or_default();
        let include_instances = input.include_instances.unwrap_or(true);
        let groups: Vec<t::AutoScalingGroup> = self.with_region(ctx, |r| {
            r.groups
                .values()
                .filter(|g| names.is_empty() || names.iter().any(|n| n == g.name()))
                .filter(|g| {
                    filters.iter().all(|f| {
                        let values = f.values.clone().unwrap_or_default();
                        let tags = g.cfg.tags.clone().unwrap_or_default();
                        match f.name.as_deref().unwrap_or_default() {
                            "tag-key" => tags.iter().any(|t| values.iter().any(|v| Some(v) == t.key.as_ref())),
                            "tag-value" => tags.iter().any(|t| values.iter().any(|v| Some(v) == t.value.as_ref())),
                            n if n.starts_with("tag:") => tags.iter().any(|t| {
                                t.key.as_deref() == Some(&n[4..]) && values.iter().any(|v| Some(v) == t.value.as_ref())
                            }),
                            _ => true,
                        }
                    })
                })
                .map(|g| {
                    let mut out = render_group(g);
                    if !include_instances {
                        out.instances = None;
                    }
                    out
                })
                .collect()
        });
        let (page, next_token) = paginate(groups, input.max_records, &input.next_token, 100)?;
        Ok(t::AutoScalingGroupsType { auto_scaling_groups: page, next_token })
    }

    pub(crate) fn set_desired_capacity_op(
        &self,
        ctx: &RequestContext,
        input: t::SetDesiredCapacityType,
    ) -> Result<(), ServiceError> {
        let now = self.now();
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "SetDesiredCapacity", &input.auto_scaling_group_name)?;
            let n = input.desired_capacity;
            if n < g.cfg.min_size {
                return Err(validation(format!(
                    "New SetDesiredCapacity value {n} is below min value {} for the AutoScalingGroup.",
                    g.cfg.min_size
                )));
            }
            if n > g.cfg.max_size {
                return Err(validation(format!(
                    "New SetDesiredCapacity value {n} is above max value {} for the AutoScalingGroup.",
                    g.cfg.max_size
                )));
            }
            if input.honor_cooldown == Some(true) && g.cooldown_until.is_some_and(|c| now < c) {
                return Err(scaling_in_progress("Scaling activity is in progress and blocks this action."));
            }
            let before = g.cfg.desired_capacity;
            g.cfg.desired_capacity = n;
            if before != n {
                g.pending_cause = Some(format!(
                    "{} a user request explicitly set group desired capacity changing the desired capacity from {before} to {n}.",
                    at(now)
                ));
                if input.honor_cooldown == Some(true) {
                    g.cooldown_until = Some(now + chrono::Duration::seconds(g.cfg.default_cooldown as i64));
                }
            }
            Ok(())
        })
    }

    fn change_processes(
        &self,
        ctx: &RequestContext,
        input: t::ScalingProcessQuery,
        suspend: bool,
    ) -> Result<(), ServiceError> {
        let action = if suspend { "SuspendProcesses" } else { "ResumeProcesses" };
        let now = self.now();
        let mut names = input.scaling_processes.clone().unwrap_or_default();
        let all = names.is_empty();
        if all {
            names = PROCESSES.iter().map(|s| s.to_string()).collect();
        }
        for n in &names {
            if !PROCESSES.contains(&n.as_str()) {
                return Err(validation(format!("Unknown process name: {n}")));
            }
        }
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, action, &input.auto_scaling_group_name)?;
            let list = g.cfg.suspended_processes.get_or_insert_with(Vec::new);
            for n in names {
                list.retain(|p| p.process_name.as_deref() != Some(n.as_str()));
                if suspend {
                    list.push(t::SuspendedProcess {
                        process_name: Some(n),
                        suspension_reason: Some(format!("User suspended at {}", now.format("%Y-%m-%dT%H:%M:%SZ"))),
                    });
                }
            }
            Ok(())
        })
    }

    pub(crate) fn suspend_processes_op(
        &self,
        ctx: &RequestContext,
        input: t::ScalingProcessQuery,
    ) -> Result<(), ServiceError> {
        self.change_processes(ctx, input, true)
    }

    pub(crate) fn resume_processes_op(
        &self,
        ctx: &RequestContext,
        input: t::ScalingProcessQuery,
    ) -> Result<(), ServiceError> {
        self.change_processes(ctx, input, false)
    }

    pub(crate) fn enable_metrics_collection_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableMetricsCollectionQuery,
    ) -> Result<(), ServiceError> {
        if input.granularity != "1Minute" {
            return Err(validation(format!(
                "Invalid granularity: {}. The only valid granularity is 1Minute.",
                input.granularity
            )));
        }
        let mut metrics = input.metrics.clone().unwrap_or_default();
        if metrics.is_empty() {
            metrics = METRICS.iter().map(|s| s.to_string()).collect();
        }
        for m in &metrics {
            if !METRICS.contains(&m.as_str()) {
                return Err(validation(format!("Invalid metric name: {m}")));
            }
        }
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "EnableMetricsCollection", &input.auto_scaling_group_name)?;
            let list = g.cfg.enabled_metrics.get_or_insert_with(Vec::new);
            for m in metrics {
                if !list.iter().any(|e| e.metric.as_deref() == Some(m.as_str())) {
                    list.push(t::EnabledMetric { metric: Some(m), granularity: Some("1Minute".into()) });
                }
            }
            Ok(())
        })
    }

    pub(crate) fn disable_metrics_collection_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableMetricsCollectionQuery,
    ) -> Result<(), ServiceError> {
        let metrics = input.metrics.clone().unwrap_or_default();
        for m in &metrics {
            if !METRICS.contains(&m.as_str()) {
                return Err(validation(format!("Invalid metric name: {m}")));
            }
        }
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "DisableMetricsCollection", &input.auto_scaling_group_name)?;
            let list = g.cfg.enabled_metrics.get_or_insert_with(Vec::new);
            if metrics.is_empty() {
                list.clear();
            } else {
                list.retain(|e| !metrics.iter().any(|m| Some(m) == e.metric.as_ref()));
            }
            Ok(())
        })
    }

    fn tagged_groups(
        ctx: &RequestContext,
        r: &mut RegionState,
        action: &str,
        tags: &[t::Tag],
    ) -> Result<Vec<String>, ServiceError> {
        let mut names = Vec::new();
        for tag in tags {
            if tag.resource_type.as_deref().unwrap_or("auto-scaling-group") != "auto-scaling-group" {
                return Err(validation(format!(
                    "Invalid resource type: {}",
                    tag.resource_type.clone().unwrap_or_default()
                )));
            }
            let name =
                tag.resource_id.clone().ok_or_else(|| validation("ResourceId must be specified for each tag."))?;
            let g = r.groups.get(&name).ok_or_else(|| crate::util::group_not_found(&name))?;
            authorize(ctx, action, &g.arn(), g.cfg.tags.as_ref(), request_tags(std::slice::from_ref(tag)))?;
            names.push(name);
        }
        Ok(names)
    }

    pub(crate) fn create_or_update_tags_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateOrUpdateTagsType,
    ) -> Result<(), ServiceError> {
        self.with_region(ctx, |r| {
            Self::tagged_groups(ctx, r, "CreateOrUpdateTags", &input.tags)?;
            for tag in &input.tags {
                let name = tag.resource_id.clone().unwrap_or_default();
                let g = r.groups.get_mut(&name).expect("checked");
                let mut current: Vec<t::Tag> = g
                    .cfg
                    .tags
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|t| t.key.as_deref() != Some(tag.key.as_str()))
                    .map(|t| t::Tag {
                        resource_id: t.resource_id,
                        resource_type: t.resource_type,
                        key: t.key.unwrap_or_default(),
                        value: t.value,
                        propagate_at_launch: t.propagate_at_launch,
                    })
                    .collect();
                current.push(tag.clone());
                g.cfg.tags = Some(tag_descriptions(&name, &current)?);
            }
            Ok(())
        })
    }

    pub(crate) fn delete_tags_op(&self, ctx: &RequestContext, input: t::DeleteTagsType) -> Result<(), ServiceError> {
        self.with_region(ctx, |r| {
            Self::tagged_groups(ctx, r, "DeleteTags", &input.tags)?;
            for tag in &input.tags {
                let name = tag.resource_id.clone().unwrap_or_default();
                let g = r.groups.get_mut(&name).expect("checked");
                if let Some(list) = g.cfg.tags.as_mut() {
                    list.retain(|t| {
                        t.key.as_deref() != Some(tag.key.as_str())
                            || tag.value.as_ref().is_some_and(|v| Some(v) != t.value.as_ref())
                    });
                }
            }
            Ok(())
        })
    }

    pub(crate) fn describe_tags_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTagsType,
    ) -> Result<t::TagsType, ServiceError> {
        authorize(ctx, "DescribeTags", "*", None, ConditionContext::new())?;
        let filters = input.filters.clone().unwrap_or_default();
        let tags: Vec<t::TagDescription> = self.with_region(ctx, |r| {
            r.groups
                .values()
                .flat_map(|g| g.cfg.tags.clone().unwrap_or_default())
                .filter(|t| {
                    filters.iter().all(|f| {
                        let values = f.values.clone().unwrap_or_default();
                        let field = match f.name.as_deref().unwrap_or_default() {
                            "auto-scaling-group" => t.resource_id.clone(),
                            "key" => t.key.clone(),
                            "value" => t.value.clone(),
                            "propagate-at-launch" => t.propagate_at_launch.map(|b| b.to_string()),
                            _ => return true,
                        };
                        values.iter().any(|v| Some(v) == field.as_ref())
                    })
                })
                .collect()
        });
        let (page, next_token) = paginate(tags, input.max_records, &input.next_token, 100)?;
        Ok(t::TagsType { tags: Some(page), next_token })
    }

    pub(crate) fn describe_scaling_activities_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeScalingActivitiesType,
    ) -> Result<t::ActivitiesType, ServiceError> {
        authorize(ctx, "DescribeScalingActivities", "*", None, ConditionContext::new())?;
        let ids = input.activity_ids.clone().unwrap_or_default();
        let include_deleted = input.include_deleted_groups.unwrap_or(false);
        let filters = input.filters.clone().unwrap_or_default();
        let list: Vec<t::Activity> = self.with_region(ctx, |r| {
            r.activities
                .iter()
                .rev()
                .filter(|a| ids.is_empty() || ids.contains(&a.activity_id))
                .filter(|a| input.auto_scaling_group_name.as_ref().is_none_or(|n| *n == a.auto_scaling_group_name))
                .filter(|a| {
                    let current = r
                        .groups
                        .get(&a.auto_scaling_group_name)
                        .is_some_and(|g| Some(g.arn()) == a.auto_scaling_group_arn);
                    current || include_deleted || !ids.is_empty()
                })
                .filter(|a| {
                    filters.iter().all(|f| match f.name.as_deref() {
                        Some("StatusCode") => f.values.iter().flatten().any(|v| *v == a.status_code),
                        _ => true,
                    })
                })
                .map(|a| {
                    let mut a = a.clone();
                    if !r
                        .groups
                        .get(&a.auto_scaling_group_name)
                        .is_some_and(|g| Some(g.arn()) == a.auto_scaling_group_arn)
                    {
                        a.auto_scaling_group_state = Some("Deleted".into());
                    }
                    a
                })
                .collect()
        });
        let (page, next_token) = paginate(list, input.max_records.or(Some(100)), &input.next_token, 100)?;
        Ok(t::ActivitiesType { activities: page, next_token })
    }

    pub(crate) fn describe_account_limits_op(
        &self,
        ctx: &RequestContext,
    ) -> Result<t::DescribeAccountLimitsAnswer, ServiceError> {
        authorize(ctx, "DescribeAccountLimits", "*", None, ConditionContext::new())?;
        let (groups, lcs) = self.with_region(ctx, |r| (r.groups.len() as i32, r.launch_configurations.len() as i32));
        Ok(t::DescribeAccountLimitsAnswer {
            max_number_of_auto_scaling_groups: Some(MAX_GROUPS as i32),
            max_number_of_launch_configurations: Some(super::launch_config::MAX_LAUNCH_CONFIGURATIONS as i32),
            number_of_auto_scaling_groups: Some(groups),
            number_of_launch_configurations: Some(lcs),
        })
    }
}
