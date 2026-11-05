//! The API operations, by area.

pub(crate) mod group;
mod hooks;
mod instances;
mod launch_config;
mod misc;
mod policy;
pub(crate) mod refresh;
mod scheduled;
pub(crate) mod traffic;
mod warm_pool;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::account_of;
use crate::generated::types as t;
use crate::state::{Group, Member, RegionState};
use crate::util::{authorize, group_not_found, group_resource};

/// The group `name`, after authorizing `action` on it (with its tags).
pub(crate) fn authorized_group<'a>(
    ctx: &RequestContext,
    r: &'a mut RegionState,
    action: &str,
    name: &str,
) -> Result<&'a mut Group, ServiceError> {
    authorized_group_with(ctx, r, action, name, ConditionContext::new())
}

pub(crate) fn authorized_group_with<'a>(
    ctx: &RequestContext,
    r: &'a mut RegionState,
    action: &str,
    name: &str,
    extra: ConditionContext,
) -> Result<&'a mut Group, ServiceError> {
    match r.groups.get(name) {
        Some(g) => authorize(ctx, action, &g.arn(), g.cfg.tags.as_ref(), extra)?,
        None => {
            authorize(ctx, action, &group_resource(ctx, &account_of(ctx), name), None, extra)?;
            return Err(group_not_found(name));
        }
    }
    Ok(r.groups.get_mut(name).expect("group checked above"))
}

pub(crate) fn render_instance(m: &Member) -> t::Instance {
    t::Instance {
        instance_id: m.instance_id.clone(),
        instance_type: Some(m.instance_type.clone()).filter(|s| !s.is_empty()),
        availability_zone: m.availability_zone.clone(),
        availability_zone_id: m.availability_zone_id.clone(),
        lifecycle_state: m.lifecycle_state.clone(),
        health_status: m.health_status.clone(),
        launch_configuration_name: m.launch_configuration_name.clone(),
        launch_template: m.launch_template.clone(),
        image_id: m.image_id.clone(),
        protected_from_scale_in: m.protected_from_scale_in,
        weighted_capacity: m.weighted_capacity.clone(),
    }
}

pub(crate) fn render_group(g: &Group) -> t::AutoScalingGroup {
    let mut cfg = g.cfg.clone();
    cfg.instances = Some(g.members.values().filter(|m| !m.warm).map(render_instance).collect());
    let of_kind = |k: &str| -> Vec<String> {
        g.traffic_sources
            .values()
            .filter(|s| s.r#type.as_deref() == Some(k))
            .filter_map(|s| s.identifier.clone())
            .collect()
    };
    cfg.load_balancer_names = Some(of_kind("elb"));
    cfg.target_group_ar_ns = Some(of_kind("elbv2"));
    cfg.traffic_sources = Some(
        g.traffic_sources
            .values()
            .map(|s| t::TrafficSourceIdentifier {
                identifier: s.identifier.clone().unwrap_or_default(),
                r#type: s.r#type.clone(),
            })
            .collect(),
    );
    if cfg.suspended_processes.is_none() {
        cfg.suspended_processes = Some(Vec::new());
    }
    if cfg.enabled_metrics.is_none() {
        cfg.enabled_metrics = Some(Vec::new());
    }
    if cfg.tags.is_none() {
        cfg.tags = Some(Vec::new());
    }
    if g.deleting {
        cfg.status = Some("Delete in progress".into());
    }
    cfg
}

/// Find the group an instance belongs to.
pub(crate) fn group_of_instance<'a>(r: &'a RegionState, instance_id: &str) -> Option<&'a Group> {
    r.groups.values().find(|g| g.members.contains_key(instance_id))
}
