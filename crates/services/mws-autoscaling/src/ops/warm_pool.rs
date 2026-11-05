//! Warm pools: pre-initialized instances (running, stopped or hibernated)
//! the group takes from before launching new ones.

use mws_core::{RequestContext, ServiceError};

use super::{authorized_group, render_instance};
use crate::generated::types as t;
use crate::util::{paginate, validation};
use crate::{account_of, AutoScaling};

impl AutoScaling {
    pub(crate) fn put_warm_pool_op(
        &self,
        ctx: &RequestContext,
        input: t::PutWarmPoolType,
    ) -> Result<t::PutWarmPoolAnswer, ServiceError> {
        if let Some(s) = &input.pool_state {
            if !matches!(s.as_str(), "Stopped" | "Running" | "Hibernated") {
                return Err(validation(format!(
                    "The value '{s}' for parameter PoolState is invalid. Valid values are Stopped, Running and Hibernated."
                )));
            }
        }
        if input.min_size.is_some_and(|m| m < 0) {
            return Err(validation("MinSize must be greater than or equal to 0."));
        }
        if input.max_group_prepared_capacity.is_some_and(|m| m < -1) {
            return Err(validation("MaxGroupPreparedCapacity must be -1 or greater."));
        }
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "PutWarmPool", &input.auto_scaling_group_name)?;
            if g.cfg.mixed_instances_policy.is_some() {
                return Err(validation(
                    "You can't add a warm pool to an Auto Scaling group that has a mixed instances policy or a launch template or launch configuration that requests Spot Instances.",
                ));
            }
            if g.cfg.warm_pool_configuration.as_ref().is_some_and(|w| w.status.as_deref() == Some("PendingDelete")) {
                return Err(validation("The warm pool is being deleted."));
            }
            if let Some(m) = input.max_group_prepared_capacity.filter(|m| *m >= 0) {
                if m < g.cfg.min_size {
                    return Err(validation(format!(
                        "MaxGroupPreparedCapacity ({m}) must be greater than or equal to the group's minimum size ({}).",
                        g.cfg.min_size
                    )));
                }
            }
            g.cfg.warm_pool_configuration = Some(t::WarmPoolConfiguration {
                max_group_prepared_capacity: input.max_group_prepared_capacity,
                min_size: Some(input.min_size.unwrap_or(0)),
                pool_state: Some(input.pool_state.clone().unwrap_or_else(|| "Stopped".into())),
                status: None,
                instance_reuse_policy: input.instance_reuse_policy.clone(),
            });
            Ok(Default::default())
        })
    }

    pub(crate) fn describe_warm_pool_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeWarmPoolType,
    ) -> Result<t::DescribeWarmPoolAnswer, ServiceError> {
        let (cfg, instances) = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "DescribeWarmPool", &input.auto_scaling_group_name)?;
            Ok::<_, ServiceError>((
                g.cfg.warm_pool_configuration.clone(),
                g.members.values().filter(|m| m.warm).map(render_instance).collect::<Vec<_>>(),
            ))
        })?;
        let (page, next_token) = paginate(instances, input.max_records, &input.next_token, 50)?;
        Ok(t::DescribeWarmPoolAnswer { warm_pool_configuration: cfg, instances: Some(page), next_token })
    }

    pub(crate) async fn delete_warm_pool_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteWarmPoolType,
    ) -> Result<t::DeleteWarmPoolAnswer, ServiceError> {
        let force = input.force_delete.unwrap_or(false);
        let account = account_of(ctx);
        let terminate = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "DeleteWarmPool", &input.auto_scaling_group_name)?;
            let Some(wp) = g.cfg.warm_pool_configuration.as_mut() else {
                return Err(validation(format!(
                    "No warm pool found for Auto Scaling group {}.",
                    input.auto_scaling_group_name
                )));
            };
            if !force {
                wp.status = Some("PendingDelete".into());
                return Ok(Vec::new());
            }
            // Force: the pool and its instances go at once.
            let ids: Vec<String> = g.members.values().filter(|m| m.warm).map(|m| m.instance_id.clone()).collect();
            g.members.retain(|_, m| !m.warm);
            g.cfg.warm_pool_configuration = None;
            g.cfg.warm_pool_size = None;
            Ok(ids)
        })?;
        if !terminate.is_empty() {
            let sctx = self.service_ctx(ctx, &account, &ctx.region);
            let _ = self.ec2_terminate(&sctx, terminate).await;
        }
        Ok(Default::default())
    }
}
