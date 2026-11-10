//! Load balancers, target groups and traffic sources. Classic load
//! balancers, ELBv2 target groups and VPC Lattice target groups are all
//! traffic sources; the older load balancer APIs show the first two.
//! InService instances are registered with every attached source (unless
//! `AddToLoadBalancer` is suspended) and deregistered when they leave.

use mws_core::{RequestContext, ServiceError};

use super::authorized_group;
use crate::engine::Op;
use crate::generated::types as t;
use crate::state::Group;
use crate::util::{limit_exceeded, paginate, validation};
use crate::{AutoScaling, TrafficTarget};

/// The traffic source type an identifier names.
pub(crate) fn kind_of(identifier: &str, given: Option<&str>) -> String {
    if let Some(g) = given {
        return g.to_string();
    }
    if identifier.starts_with("arn:") && identifier.contains(":vpc-lattice:") {
        "vpc-lattice".into()
    } else if identifier.starts_with("arn:") {
        "elbv2".into()
    } else {
        "elb".into()
    }
}

pub(crate) fn source_state(ts: &t::TrafficSourceIdentifier, state: &str) -> t::TrafficSourceState {
    t::TrafficSourceState {
        traffic_source: Some(ts.identifier.clone()),
        state: Some(state.to_string()),
        identifier: Some(ts.identifier.clone()),
        r#type: Some(kind_of(&ts.identifier, ts.r#type.as_deref())),
    }
}

pub(crate) fn target_of(s: &t::TrafficSourceState) -> TrafficTarget {
    let id = s.identifier.clone().unwrap_or_default();
    match s.r#type.as_deref() {
        Some("elb") => TrafficTarget::ClassicLoadBalancer(id),
        Some("vpc-lattice") => TrafficTarget::LatticeTargetGroup(id),
        _ => TrafficTarget::TargetGroup(id),
    }
}

/// Instances that should be registered with the group's sources.
pub(crate) fn registered_members(g: &Group) -> Vec<String> {
    g.members.values().filter(|m| !m.warm && m.lifecycle_state == "InService").map(|m| m.instance_id.clone()).collect()
}

pub(crate) fn deregister_all_ops(g: &Group) -> Vec<Op> {
    let ids = registered_members(g);
    if ids.is_empty() {
        return Vec::new();
    }
    g.traffic_sources
        .values()
        .map(|s| Op::Traffic { register: false, target: target_of(s), instance_ids: ids.clone() })
        .collect()
}

/// Ops registering (or deregistering) `ids` with every source of `g`.
pub(crate) fn member_ops(g: &Group, ids: &[String], register: bool) -> Vec<Op> {
    if ids.is_empty() || (register && g.suspended("AddToLoadBalancer")) {
        return Vec::new();
    }
    g.traffic_sources
        .values()
        .map(|s| Op::Traffic { register, target: target_of(s), instance_ids: ids.to_vec() })
        .collect()
}

impl AutoScaling {
    fn attach_sources(
        &self,
        ctx: &RequestContext,
        action: &str,
        group: &str,
        sources: Vec<t::TrafficSourceIdentifier>,
    ) -> Result<(), ServiceError> {
        let account = crate::account_of(ctx);
        // Authorize and find the group's VPC first, then check the sources
        // (outside the state lock: ELB answers).
        let subnets =
            self.with_region(ctx, |r| authorized_group(ctx, r, action, group).map(|g| g.subnet_zones.clone()))?;
        let vpc = self.subnets_vpc(ctx, &subnets);
        let new: Vec<t::TrafficSourceIdentifier> =
            sources.iter().filter(|s| !s.identifier.is_empty()).cloned().collect();
        self.check_traffic_sources(ctx, vpc.as_deref(), &new)?;
        let ops = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, action, group)?;
            if g.traffic_sources.len() + sources.len() > 50 {
                return Err(limit_exceeded(
                    "You have reached the limit of 50 traffic sources for the Auto Scaling group.",
                ));
            }
            let ids = registered_members(g);
            let mut ops = Vec::new();
            for s in sources {
                if s.identifier.is_empty() {
                    return Err(validation("The traffic source identifier must not be empty."));
                }
                if g.traffic_sources.contains_key(&s.identifier) {
                    continue;
                }
                let state = source_state(&s, "Added");
                if !ids.is_empty() && !g.suspended("AddToLoadBalancer") {
                    ops.push(Op::Traffic { register: true, target: target_of(&state), instance_ids: ids.clone() });
                }
                g.traffic_sources.insert(s.identifier.clone(), state);
            }
            Ok(ops)
        })?;
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        for op in ops {
            self.deliver_traffic(&sctx, op);
        }
        Ok(())
    }

    fn detach_sources(
        &self,
        ctx: &RequestContext,
        action: &str,
        group: &str,
        ids: Vec<String>,
    ) -> Result<(), ServiceError> {
        let account = crate::account_of(ctx);
        let ops = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, action, group)?;
            let members = registered_members(g);
            let mut ops = Vec::new();
            for id in ids {
                if let Some(s) = g.traffic_sources.remove(&id) {
                    if !members.is_empty() {
                        ops.push(Op::Traffic { register: false, target: target_of(&s), instance_ids: members.clone() });
                    }
                }
            }
            Ok(ops)
        })?;
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        for op in ops {
            self.deliver_traffic(&sctx, op);
        }
        Ok(())
    }

    fn describe_sources(
        &self,
        ctx: &RequestContext,
        action: &str,
        group: &str,
        kind: Option<&str>,
    ) -> Result<Vec<t::TrafficSourceState>, ServiceError> {
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, action, group)?;
            Ok(g.traffic_sources
                .values()
                .filter(|s| kind.is_none_or(|k| s.r#type.as_deref() == Some(k)))
                .cloned()
                .collect())
        })
    }

    pub(crate) fn attach_load_balancers_op(
        &self,
        ctx: &RequestContext,
        input: t::AttachLoadBalancersType,
    ) -> Result<t::AttachLoadBalancersResultType, ServiceError> {
        let sources = input
            .load_balancer_names
            .into_iter()
            .map(|n| t::TrafficSourceIdentifier { identifier: n, r#type: Some("elb".into()) })
            .collect();
        self.attach_sources(ctx, "AttachLoadBalancers", &input.auto_scaling_group_name, sources)?;
        Ok(Default::default())
    }

    pub(crate) fn attach_load_balancer_target_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::AttachLoadBalancerTargetGroupsType,
    ) -> Result<t::AttachLoadBalancerTargetGroupsResultType, ServiceError> {
        let sources = input
            .target_group_ar_ns
            .into_iter()
            .map(|n| t::TrafficSourceIdentifier { identifier: n, r#type: Some("elbv2".into()) })
            .collect();
        self.attach_sources(ctx, "AttachLoadBalancerTargetGroups", &input.auto_scaling_group_name, sources)?;
        Ok(Default::default())
    }

    pub(crate) fn attach_traffic_sources_op(
        &self,
        ctx: &RequestContext,
        input: t::AttachTrafficSourcesType,
    ) -> Result<t::AttachTrafficSourcesResultType, ServiceError> {
        for s in &input.traffic_sources {
            if let Some(k) = &s.r#type {
                if !matches!(k.as_str(), "elb" | "elbv2" | "vpc-lattice") {
                    return Err(validation(format!("Invalid traffic source type: {k}")));
                }
            }
        }
        self.attach_sources(ctx, "AttachTrafficSources", &input.auto_scaling_group_name, input.traffic_sources)?;
        Ok(Default::default())
    }

    pub(crate) fn detach_load_balancers_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachLoadBalancersType,
    ) -> Result<t::DetachLoadBalancersResultType, ServiceError> {
        self.detach_sources(ctx, "DetachLoadBalancers", &input.auto_scaling_group_name, input.load_balancer_names)?;
        Ok(Default::default())
    }

    pub(crate) fn detach_load_balancer_target_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachLoadBalancerTargetGroupsType,
    ) -> Result<t::DetachLoadBalancerTargetGroupsResultType, ServiceError> {
        self.detach_sources(
            ctx,
            "DetachLoadBalancerTargetGroups",
            &input.auto_scaling_group_name,
            input.target_group_ar_ns,
        )?;
        Ok(Default::default())
    }

    pub(crate) fn detach_traffic_sources_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachTrafficSourcesType,
    ) -> Result<t::DetachTrafficSourcesResultType, ServiceError> {
        let ids = input.traffic_sources.into_iter().map(|s| s.identifier).collect();
        self.detach_sources(ctx, "DetachTrafficSources", &input.auto_scaling_group_name, ids)?;
        Ok(Default::default())
    }

    pub(crate) fn describe_load_balancers_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLoadBalancersRequest,
    ) -> Result<t::DescribeLoadBalancersResponse, ServiceError> {
        let list: Vec<t::LoadBalancerState> = self
            .describe_sources(ctx, "DescribeLoadBalancers", &input.auto_scaling_group_name, Some("elb"))?
            .into_iter()
            .map(|s| t::LoadBalancerState { load_balancer_name: s.identifier, state: s.state })
            .collect();
        let (page, next_token) = paginate(list, input.max_records.or(Some(100)), &input.next_token, 100)?;
        Ok(t::DescribeLoadBalancersResponse { load_balancers: Some(page), next_token })
    }

    pub(crate) fn describe_load_balancer_target_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLoadBalancerTargetGroupsRequest,
    ) -> Result<t::DescribeLoadBalancerTargetGroupsResponse, ServiceError> {
        let list: Vec<t::LoadBalancerTargetGroupState> = self
            .describe_sources(ctx, "DescribeLoadBalancerTargetGroups", &input.auto_scaling_group_name, Some("elbv2"))?
            .into_iter()
            .map(|s| t::LoadBalancerTargetGroupState { load_balancer_target_group_arn: s.identifier, state: s.state })
            .collect();
        let (page, next_token) = paginate(list, input.max_records.or(Some(100)), &input.next_token, 100)?;
        Ok(t::DescribeLoadBalancerTargetGroupsResponse { load_balancer_target_groups: Some(page), next_token })
    }

    pub(crate) fn describe_traffic_sources_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTrafficSourcesRequest,
    ) -> Result<t::DescribeTrafficSourcesResponse, ServiceError> {
        let list = self.describe_sources(
            ctx,
            "DescribeTrafficSources",
            &input.auto_scaling_group_name,
            input.traffic_source_type.as_deref(),
        )?;
        let (page, next_token) = paginate(list, input.max_records, &input.next_token, 50)?;
        Ok(t::DescribeTrafficSourcesResponse { traffic_sources: Some(page), next_token })
    }
}
