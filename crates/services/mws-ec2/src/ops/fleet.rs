//! Spot Fleet (`RequestSpotFleet`) and EC2 Fleet (`CreateFleet`): fleets
//! launch real instances across their launch specifications or template
//! overrides until their target capacity (in weighted units) is met, Spot
//! first by the allocation strategy and the simulated Spot prices. `maintain`
//! fleets replace instances that end, `request` fleets do not, and `instant`
//! EC2 Fleets launch once and report what they launched.
//!
//! Fleets are brought up to date whenever fleets are described or changed.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::pricing::{fmt_price, on_demand_price, spot_price};
use crate::state::{FleetMember, FleetRecord, RegionState, SpotFleetRecord};
use crate::util::{
    arn, authorize, err, invalid_parameter, missing_parameter, new_id, paginate, request_tag_context,
    resource_tag_context, s, some_tags, tags_for, Filters,
};
use crate::{account_of, Ec2};

use super::spot::{launch_zone, record_fleet_request, service_ctx, PRODUCT};

/// One place a fleet can launch: a launch specification, or a template with
/// one override.
#[derive(Debug, Clone, Default)]
pub(crate) struct Pool {
    pub run: t::RunInstancesRequest,
    pub instance_type: String,
    pub weight: f64,
    pub priority: f64,
    pub max_price: Option<f64>,
    pub zone: Option<String>,
    pub template: Option<t::FleetLaunchTemplateSpecification>,
    pub overrides: Option<t::FleetLaunchTemplateOverrides>,
}

/// A pool that could not launch.
#[derive(Debug, Clone)]
pub(crate) struct PoolError {
    pub pool: usize,
    pub lifecycle: String,
    pub code: String,
    pub message: String,
}

fn uuid() -> String {
    use rand::Rng;
    let b: [u8; 16] = rand::thread_rng().gen();
    let h = hex::encode(b);
    format!("{}-{}-4{}-a{}-{}", &h[..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
}

fn unit_price(p: &Pool, spot: bool, now: chrono::DateTime<chrono::Utc>) -> f64 {
    let price = if spot {
        p.zone.as_deref().and_then(|z| spot_price(&p.instance_type, z, PRODUCT, now))
    } else {
        on_demand_price(&p.instance_type)
    };
    price.unwrap_or(f64::MAX) / p.weight.max(0.001)
}

/// The order a strategy tries pools in.
fn order(pools: &[Pool], spot: bool, strategy: &str, now: chrono::DateTime<chrono::Utc>) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..pools.len()).collect();
    let prioritized =
        matches!(strategy, "prioritized" | "capacityOptimizedPrioritized" | "capacity-optimized-prioritized");
    if prioritized {
        idx.sort_by(|a, b| pools[*a].priority.partial_cmp(&pools[*b].priority).unwrap_or(std::cmp::Ordering::Equal));
    } else if !matches!(strategy, "diversified") {
        idx.sort_by(|a, b| {
            unit_price(&pools[*a], spot, now)
                .partial_cmp(&unit_price(&pools[*b], spot, now))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    idx
}

fn spot_tags(key: &str, id: &str) -> Vec<t::Tag> {
    vec![t::Tag { key: Some(key.into()), value: Some(id.into()) }]
}

fn instance_ended(r: &RegionState, id: &str) -> bool {
    r.instances
        .get(id)
        .and_then(|i| i.instance.state.as_ref())
        .and_then(|s| s.name.as_deref())
        .is_none_or(|s| s == "terminated" || s == "shutting-down")
}

fn fleet_template_spec(spec: &t::FleetLaunchTemplateSpecification) -> t::LaunchTemplateSpecification {
    t::LaunchTemplateSpecification {
        launch_template_id: spec.launch_template_id.clone(),
        launch_template_name: spec.launch_template_name.clone(),
        version: spec.version.clone(),
    }
}

impl Ec2 {
    /// Launch from `pools` until `need` units are running. Returns the new
    /// members and the pools that failed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn fill_capacity(
        &self,
        ctx: &RequestContext,
        pools: &[Pool],
        need: f64,
        spot: bool,
        strategy: &str,
        default_max_price: Option<f64>,
        tag_key: &str,
        fleet_id: &str,
    ) -> (Vec<FleetMember>, Vec<PoolError>) {
        let now = ctx.received_at;
        let lifecycle = if spot { "spot" } else { "on-demand" };
        let mut members = Vec::new();
        let mut errors: Vec<PoolError> = Vec::new();
        let mut usable: Vec<usize> = order(pools, spot, strategy, now);
        // Pools whose price is above their maximum never launch.
        if spot {
            usable.retain(|i| {
                let p = &pools[*i];
                let market = p.zone.as_deref().and_then(|z| spot_price(&p.instance_type, z, PRODUCT, now));
                let max = p.max_price.or(default_max_price).or_else(|| on_demand_price(&p.instance_type));
                match (market, max) {
                    (Some(m), Some(max)) if max < m => {
                        errors.push(PoolError {
                            pool: *i,
                            lifecycle: lifecycle.into(),
                            code: "SpotMaxPriceTooLow".into(),
                            message: format!(
                                "Your Spot request price of {max} is lower than the minimum required Spot request fulfillment price of {}.",
                                fmt_price(m)
                            ),
                        });
                        false
                    }
                    _ => true,
                }
            });
        }
        let mut fulfilled = 0.0;
        let mut turn = 0usize;
        let mut launches = 0;
        while fulfilled < need && !usable.is_empty() && launches < 1000 {
            launches += 1;
            let slot = if strategy == "diversified" { turn % usable.len() } else { 0 };
            turn += 1;
            let pool_index = usable[slot];
            let pool = &pools[pool_index];
            let mut run = pool.run.clone();
            run.min_count = 1;
            run.max_count = 1;
            let sir = spot.then(|| new_id("sir")[..12].to_string());
            let max_price =
                pool.max_price.or(default_max_price).or_else(|| on_demand_price(&pool.instance_type)).map(fmt_price);
            run.instance_market_options = if spot {
                Some(t::InstanceMarketOptionsRequest {
                    market_type: Some("spot".into()),
                    spot_options: Some(t::SpotMarketOptions { max_price: max_price.clone(), ..Default::default() }),
                })
            } else {
                None
            };
            match self.run_instances_with(ctx, run, spot_tags(tag_key, fleet_id), sir.clone()).await {
                Ok(res) => {
                    let inst = res.instances.unwrap_or_default().into_iter().next().unwrap_or_default();
                    let id = inst.instance_id.clone().unwrap_or_default();
                    if let Some(sir) = &sir {
                        self.with_region(ctx, |r| {
                            record_fleet_request(r, sir, fleet_id, &inst, max_price.as_deref().unwrap_or_default(), now)
                        });
                    }
                    fulfilled += pool.weight;
                    members.push(FleetMember {
                        instance_id: id,
                        instance_type: inst.instance_type.clone().unwrap_or_default(),
                        lifecycle: lifecycle.into(),
                        spot_request_id: sir,
                        weight: pool.weight,
                        pool: pool_index,
                    });
                }
                Err(e) => {
                    errors.push(PoolError {
                        pool: pool_index,
                        lifecycle: lifecycle.into(),
                        code: e.code.to_string(),
                        message: e.message.clone(),
                    });
                    usable.retain(|i| *i != pool_index);
                }
            }
        }
        (members, errors)
    }

    async fn terminate_members(&self, ctx: &RequestContext, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        let live: Vec<String> = self.with_region(ctx, |r| ids.into_iter().filter(|i| !instance_ended(r, i)).collect());
        if live.is_empty() {
            return;
        }
        let _ = self
            .terminate_instances_op(
                &service_ctx(ctx),
                t::TerminateInstancesRequest { instance_ids: live, ..Default::default() },
            )
            .await;
    }

    // ---- Spot Fleet -------------------------------------------------------------------------------

    fn spot_fleet_pools(
        &self,
        ctx: &RequestContext,
        cfg: &t::SpotFleetRequestConfigData,
    ) -> Result<Vec<Pool>, ServiceError> {
        let mut pools = Vec::new();
        let specs = cfg.launch_specifications.clone().unwrap_or_default();
        let templates = cfg.launch_template_configs.clone().unwrap_or_default();
        match (specs.is_empty(), templates.is_empty()) {
            (true, true) => {
                return Err(err(
                    "InvalidSpotFleetRequestConfig",
                    "Either LaunchSpecifications or LaunchTemplateConfigs must be specified.",
                ))
            }
            (false, false) => {
                return Err(err(
                    "InvalidSpotFleetRequestConfig",
                    "LaunchSpecifications and LaunchTemplateConfigs cannot both be specified.",
                ))
            }
            _ => {}
        }
        for spec in &specs {
            let itype = spec.instance_type.clone().ok_or_else(|| {
                err("InvalidSpotFleetRequestConfig", "Each launch specification must specify an instance type.")
            })?;
            if spec.image_id.is_none() {
                return Err(err(
                    "InvalidSpotFleetRequestConfig",
                    "Each launch specification must specify an image ID.",
                ));
            }
            let subnets: Vec<Option<String>> = match &spec.subnet_id {
                Some(list) => list.split(',').map(|s| Some(s.trim().to_string())).collect(),
                None => vec![None],
            };
            let zones: Vec<Option<String>> = match spec.placement.as_ref().and_then(|p| p.availability_zone.clone()) {
                Some(list) => list.split(',').map(|s| Some(s.trim().to_string())).collect(),
                None => vec![None],
            };
            for subnet in &subnets {
                for zone in &zones {
                    let tags: Vec<t::TagSpecification> = spec
                        .tag_specifications
                        .iter()
                        .flatten()
                        .map(|ts| t::TagSpecification {
                            resource_type: ts.resource_type.clone(),
                            tags: ts.tags.clone(),
                        })
                        .collect();
                    let run = t::RunInstancesRequest {
                        image_id: spec.image_id.clone(),
                        instance_type: Some(itype.clone()),
                        key_name: spec.key_name.clone(),
                        kernel_id: spec.kernel_id.clone(),
                        ramdisk_id: spec.ramdisk_id.clone(),
                        security_group_ids: spec
                            .security_groups
                            .as_ref()
                            .map(|g| g.iter().filter_map(|g| g.group_id.clone()).collect::<Vec<_>>())
                            .filter(|g| !g.is_empty()),
                        block_device_mappings: spec.block_device_mappings.clone(),
                        ebs_optimized: spec.ebs_optimized,
                        iam_instance_profile: spec.iam_instance_profile.clone(),
                        monitoring: spec
                            .monitoring
                            .as_ref()
                            .map(|m| t::RunInstancesMonitoringEnabled { enabled: m.enabled.unwrap_or(false) }),
                        network_interfaces: spec.network_interfaces.clone(),
                        placement: zone.as_ref().map(|z| t::Placement {
                            availability_zone: Some(z.clone()),
                            tenancy: spec.placement.as_ref().and_then(|p| p.tenancy.clone()),
                            group_name: spec.placement.as_ref().and_then(|p| p.group_name.clone()),
                            ..Default::default()
                        }),
                        subnet_id: subnet.clone(),
                        user_data: spec.user_data.clone(),
                        tag_specifications: (!tags.is_empty()).then_some(tags),
                        min_count: 1,
                        max_count: 1,
                        ..Default::default()
                    };
                    let z = self.with_region(ctx, |r| launch_zone(r, subnet.as_deref(), zone.as_deref()));
                    pools.push(Pool {
                        run,
                        instance_type: itype.clone(),
                        weight: spec.weighted_capacity.unwrap_or(1.0),
                        priority: pools.len() as f64,
                        max_price: spec.spot_price.as_deref().and_then(|p| p.parse().ok()),
                        zone: z,
                        template: None,
                        overrides: None,
                    });
                }
            }
        }
        for cfg in &templates {
            let spec = cfg
                .launch_template_specification
                .clone()
                .ok_or_else(|| missing_parameter("LaunchTemplateConfigs.LaunchTemplateSpecification"))?;
            self.template_pools(
                ctx,
                &spec,
                cfg.overrides
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|o| t::FleetLaunchTemplateOverrides {
                        instance_type: o.instance_type,
                        max_price: o.spot_price,
                        subnet_id: o.subnet_id,
                        availability_zone: o.availability_zone,
                        weighted_capacity: o.weighted_capacity,
                        priority: o.priority,
                        ..Default::default()
                    })
                    .collect(),
                &mut pools,
            )?;
        }
        Ok(pools)
    }

    /// Pools for a launch template: one per override, or the template as is.
    fn template_pools(
        &self,
        ctx: &RequestContext,
        spec: &t::FleetLaunchTemplateSpecification,
        overrides: Vec<t::FleetLaunchTemplateOverrides>,
        pools: &mut Vec<Pool>,
    ) -> Result<(), ServiceError> {
        let lt = self.resolve_launch_template(ctx, &fleet_template_spec(spec))?;
        let resolved = t::FleetLaunchTemplateSpecification {
            launch_template_id: Some(lt.id.clone()),
            launch_template_name: Some(lt.name.clone()),
            version: Some(spec.version.clone().unwrap_or_else(|| lt.version.to_string())),
        };
        let overrides = if overrides.is_empty() { vec![t::FleetLaunchTemplateOverrides::default()] } else { overrides };
        for o in overrides {
            let itype = o.instance_type.clone().or_else(|| lt.data.instance_type.clone()).ok_or_else(|| {
                invalid_parameter("The launch template or its overrides must specify an instance type.")
            })?;
            let run = t::RunInstancesRequest {
                launch_template: Some(t::LaunchTemplateSpecification {
                    launch_template_id: Some(lt.id.clone()),
                    launch_template_name: None,
                    version: resolved.version.clone(),
                }),
                instance_type: Some(itype.clone()),
                subnet_id: o.subnet_id.clone(),
                image_id: o.image_id.clone(),
                placement: o
                    .availability_zone
                    .as_ref()
                    .map(|z| t::Placement { availability_zone: Some(z.clone()), ..Default::default() }),
                min_count: 1,
                max_count: 1,
                ..Default::default()
            };
            let subnet = o.subnet_id.clone().or_else(|| {
                lt.data.network_interfaces.as_ref().and_then(|n| n.first()).and_then(|n| n.subnet_id.clone())
            });
            let zone = self.with_region(ctx, |r| launch_zone(r, subnet.as_deref(), o.availability_zone.as_deref()));
            pools.push(Pool {
                run,
                instance_type: itype,
                weight: o.weighted_capacity.unwrap_or(1.0),
                priority: o.priority.unwrap_or(pools.len() as f64),
                max_price: o.max_price.as_deref().and_then(|p| p.parse().ok()),
                zone,
                template: Some(resolved.clone()),
                overrides: Some(o),
            });
        }
        Ok(())
    }

    pub(crate) async fn request_spot_fleet_op(
        &self,
        ctx: &RequestContext,
        input: t::RequestSpotFleetRequest,
    ) -> Result<t::RequestSpotFleetResponse, ServiceError> {
        let mut cfg = input.spot_fleet_request_config.clone();
        let tags = tags_for(&cfg.tag_specifications, "spot-fleet-request", &["spot-fleet-request"])?;
        let kind = cfg.r#type.clone().unwrap_or_else(|| "maintain".into());
        if kind != "request" && kind != "maintain" {
            return Err(invalid_parameter(format!(
                "Value ({kind}) for parameter type is invalid. Valid values: request, maintain"
            )));
        }
        if cfg.target_capacity < 0 {
            return Err(err("InvalidSpotFleetRequestConfig", "TargetCapacity must be a non-negative number."));
        }
        let on_demand = cfg.on_demand_target_capacity.unwrap_or(0);
        if on_demand < 0 || on_demand > cfg.target_capacity {
            return Err(err(
                "InvalidSpotFleetRequestConfig",
                "OnDemandTargetCapacity must be between 0 and the TargetCapacity.",
            ));
        }
        let strategy = cfg.allocation_strategy.clone().unwrap_or_else(|| "lowestPrice".into());
        if !matches!(
            strategy.as_str(),
            "lowestPrice"
                | "diversified"
                | "capacityOptimized"
                | "capacityOptimizedPrioritized"
                | "priceCapacityOptimized"
        ) {
            return Err(invalid_parameter(format!("Value ({strategy}) for parameter allocationStrategy is invalid.")));
        }
        let now = ctx.received_at;
        if cfg.valid_until.is_some_and(|u| u <= now) {
            return Err(err("InvalidSpotFleetRequestConfig", "ValidUntil must be in the future."));
        }
        let default_max: Option<f64> = match &cfg.spot_price {
            Some(p) => Some(p.parse().map_err(|_| invalid_parameter(format!("Invalid value '{p}' for spotPrice.")))?),
            None => None,
        };
        let pools = self.spot_fleet_pools(ctx, &cfg)?;
        let account = account_of(ctx);
        authorize(
            ctx,
            "RequestSpotFleet",
            &[(arn(ctx, &account, "spot-fleet-request/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        let role = cfg.iam_fleet_role.clone();
        if !role.starts_with("arn:") {
            return Err(err(
                "InvalidSpotFleetRequestConfig",
                format!("Parameter: SpotFleetRequestConfig.IamFleetRole is invalid: {role}"),
            ));
        }
        let mut pass = ConditionContext::new();
        pass.insert("iam:PassedToService".into(), vec!["spotfleet.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", &role, pass).map_err(|e| {
            err("UnauthorizedOperation", format!("You are not authorized to perform this operation. {}", e.message))
        })?;
        if let Some(token) = &cfg.client_token {
            let existing = self.with_region(ctx, |r| {
                r.spot_fleets
                    .values()
                    .find(|f| {
                        f.config.spot_fleet_request_config.as_ref().and_then(|c| c.client_token.as_deref())
                            == Some(token.as_str())
                    })
                    .and_then(|f| f.config.spot_fleet_request_id.clone())
            });
            if let Some(id) = existing {
                return Ok(t::RequestSpotFleetResponse { spot_fleet_request_id: Some(id) });
            }
        }
        let id = format!("sfr-{}", uuid());
        cfg.r#type = Some(kind.clone());
        cfg.allocation_strategy = Some(strategy.clone());
        cfg.excess_capacity_termination_policy.get_or_insert_with(|| "Default".into());
        cfg.on_demand_target_capacity = Some(on_demand);
        cfg.on_demand_allocation_strategy.get_or_insert_with(|| "lowestPrice".into());
        cfg.instance_interruption_behavior.get_or_insert_with(|| "terminate".into());
        cfg.terminate_instances_with_expiration.get_or_insert(false);
        cfg.replace_unhealthy_instances.get_or_insert(false);
        cfg.target_capacity_unit_type.get_or_insert_with(|| "units".into());
        cfg.spot_price = cfg.spot_price.clone().or(None);
        let record = SpotFleetRecord {
            config: t::SpotFleetRequestConfig {
                activity_status: Some("pending_fulfillment".into()),
                create_time: Some(now),
                spot_fleet_request_config: Some(cfg.clone()),
                spot_fleet_request_id: Some(id.clone()),
                spot_fleet_request_state: Some("submitted".into()),
                tags: Some(tags),
            },
            members: Vec::new(),
            history: vec![t::HistoryRecord {
                event_type: Some("fleetRequestChange".into()),
                event_information: Some(t::EventInformation {
                    event_sub_type: Some("submitted".into()),
                    ..Default::default()
                }),
                timestamp: Some(now),
            }],
        };
        self.with_region(ctx, |r| r.spot_fleets.insert(id.clone(), record));
        let _ = default_max;
        let _ = pools;
        self.evaluate_spot_fleet(ctx, &id).await;
        Ok(t::RequestSpotFleetResponse { spot_fleet_request_id: Some(id) })
    }

    /// Bring a Spot Fleet up to date: drop ended instances, expire it, and
    /// launch towards its target.
    async fn evaluate_spot_fleet(&self, ctx: &RequestContext, id: &str) {
        let now = ctx.received_at;
        let later = service_ctx(ctx);
        let Some((cfg, state, members)) = self.with_region(ctx, |r| {
            let ended: Vec<String> = r
                .spot_fleets
                .get(id)?
                .members
                .iter()
                .filter(|m| instance_ended(r, &m.instance_id))
                .map(|m| m.instance_id.clone())
                .collect();
            let f = r.spot_fleets.get_mut(id)?;
            for i in &ended {
                f.members.retain(|m| &m.instance_id != i);
                f.history.push(t::HistoryRecord {
                    event_type: Some("instanceChange".into()),
                    event_information: Some(t::EventInformation {
                        event_sub_type: Some("terminated".into()),
                        instance_id: Some(i.clone()),
                        ..Default::default()
                    }),
                    timestamp: Some(now),
                });
            }
            Some((
                f.config.spot_fleet_request_config.clone().unwrap_or_default(),
                f.config.spot_fleet_request_state.clone().unwrap_or_default(),
                f.members.clone(),
            ))
        }) else {
            return;
        };
        if !matches!(state.as_str(), "submitted" | "active" | "modifying") {
            return;
        }
        if cfg.valid_until.is_some_and(|u| u <= now) {
            let terminate = cfg.terminate_instances_with_expiration.unwrap_or(false);
            if terminate {
                self.terminate_members(ctx, members.iter().map(|m| m.instance_id.clone()).collect()).await;
            }
            self.with_region(ctx, |r| {
                if let Some(f) = r.spot_fleets.get_mut(id) {
                    f.config.spot_fleet_request_state =
                        Some(if terminate { "cancelled" } else { "cancelled_running" }.into());
                    f.history.push(fleet_change("expired", now));
                    if terminate {
                        f.members.clear();
                    }
                }
            });
            return;
        }
        let first = state == "submitted";
        let replace = cfg.r#type.as_deref() != Some("request") || first;
        let pools = match self.spot_fleet_pools(ctx, &cfg) {
            Ok(p) => p,
            Err(e) => {
                self.with_region(ctx, |r| {
                    if let Some(f) = r.spot_fleets.get_mut(id) {
                        f.config.spot_fleet_request_state = Some("failed".into());
                        f.config.activity_status = Some("error".into());
                        f.history.push(t::HistoryRecord {
                            event_type: Some("error".into()),
                            event_information: Some(t::EventInformation {
                                event_sub_type: Some("spotFleetRequestConfigurationInvalid".into()),
                                event_description: Some(e.message.clone()),
                                ..Default::default()
                            }),
                            timestamp: Some(now),
                        });
                    }
                });
                return;
            }
        };
        let mut errors = Vec::new();
        let mut new_members = Vec::new();
        if replace {
            let have = |lifecycle: &str| -> f64 {
                members.iter().filter(|m| m.lifecycle == lifecycle).map(|m| m.weight).sum()
            };
            let od_target = cfg.on_demand_target_capacity.unwrap_or(0) as f64;
            let spot_target = cfg.target_capacity as f64 - od_target;
            let launch_ctx = if first { ctx } else { &later };
            let default_max = cfg.spot_price.as_deref().and_then(|p| p.parse().ok());
            if have("on-demand") < od_target {
                let strategy = cfg.on_demand_allocation_strategy.clone().unwrap_or_else(|| "lowestPrice".into());
                let (m, e) = self
                    .fill_capacity(
                        launch_ctx,
                        &pools,
                        od_target - have("on-demand"),
                        false,
                        &strategy,
                        None,
                        "aws:ec2spot:fleet-request-id",
                        id,
                    )
                    .await;
                new_members.extend(m);
                errors.extend(e);
            }
            if have("spot") < spot_target {
                let strategy = cfg.allocation_strategy.clone().unwrap_or_else(|| "lowestPrice".into());
                let (m, e) = self
                    .fill_capacity(
                        launch_ctx,
                        &pools,
                        spot_target - have("spot"),
                        true,
                        &strategy,
                        default_max,
                        "aws:ec2spot:fleet-request-id",
                        id,
                    )
                    .await;
                new_members.extend(m);
                errors.extend(e);
            }
        }
        self.with_region(ctx, |r| {
            let Some(f) = r.spot_fleets.get_mut(id) else { return };
            for m in &new_members {
                f.history.push(t::HistoryRecord {
                    event_type: Some("instanceChange".into()),
                    event_information: Some(t::EventInformation {
                        event_sub_type: Some("launched".into()),
                        instance_id: Some(m.instance_id.clone()),
                        event_description: Some(format!("{{\"instanceType\":\"{}\",\"image\":\"\",\"productDescription\":\"{PRODUCT}\",\"availabilityZone\":\"\"}}", m.instance_type)),
                    }),
                    timestamp: Some(now),
                });
            }
            for e in &errors {
                f.history.push(t::HistoryRecord {
                    event_type: Some("error".into()),
                    event_information: Some(t::EventInformation {
                        event_sub_type: Some("launchSpecUnusable".into()),
                        event_description: Some(format!("{}: {}", e.code, e.message)),
                        ..Default::default()
                    }),
                    timestamp: Some(now),
                });
            }
            f.members.extend(new_members.iter().cloned());
            if first {
                f.config.spot_fleet_request_state = Some("active".into());
                f.history.push(fleet_change("active", now));
            }
            if f.config.spot_fleet_request_state.as_deref() == Some("modifying") {
                f.config.spot_fleet_request_state = Some("active".into());
                f.history.push(fleet_change("modify_succeeded", now));
            }
            let fulfilled: f64 = f.members.iter().map(|m| m.weight).sum();
            let od: f64 = f.members.iter().filter(|m| m.lifecycle == "on-demand").map(|m| m.weight).sum();
            if let Some(c) = f.config.spot_fleet_request_config.as_mut() {
                c.fulfilled_capacity = Some(fulfilled - od);
                c.on_demand_fulfilled_capacity = Some(od);
            }
            let target = cfg.target_capacity as f64;
            f.config.activity_status = Some(
                if fulfilled >= target {
                    "fulfilled"
                } else if !errors.is_empty() {
                    "error"
                } else {
                    "pending_fulfillment"
                }
                .into(),
            );
        });
    }

    async fn evaluate_spot_fleets(&self, ctx: &RequestContext) {
        let ids: Vec<String> = self.with_region(ctx, |r| r.spot_fleets.keys().cloned().collect());
        for id in ids {
            self.evaluate_spot_fleet(ctx, &id).await;
        }
    }

    fn spot_fleet_resources(&self, ctx: &RequestContext, ids: &[String]) -> Vec<(String, ConditionContext)> {
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            ids.iter()
                .map(|id| {
                    (
                        arn(ctx, &account, &format!("spot-fleet-request/{id}")),
                        resource_tag_context(r.spot_fleets.get(id).and_then(|f| f.config.tags.as_ref())),
                    )
                })
                .collect()
        })
    }

    fn find_spot_fleet(&self, ctx: &RequestContext, id: &str) -> Result<(), ServiceError> {
        if !id.starts_with("sfr-") {
            return Err(err("InvalidSpotFleetRequestId.Malformed", format!("Invalid id: \"{id}\"")));
        }
        self.with_region(ctx, |r| {
            if r.spot_fleets.contains_key(id) {
                Ok(())
            } else {
                Err(err(
                    "InvalidSpotFleetRequestId.NotFound",
                    format!("The spot fleet request ID '{id}' does not exist"),
                ))
            }
        })
    }

    pub(crate) async fn describe_spot_fleet_requests_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSpotFleetRequestsRequest,
    ) -> Result<t::DescribeSpotFleetRequestsResponse, ServiceError> {
        authorize(ctx, "DescribeSpotFleetRequests", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let ids = input.spot_fleet_request_ids.clone().unwrap_or_default();
        for id in &ids {
            self.find_spot_fleet(ctx, id)?;
        }
        self.evaluate_spot_fleets(ctx).await;
        self.with_region(ctx, |r| {
            let items: Vec<t::SpotFleetRequestConfig> = r
                .spot_fleets
                .values()
                .filter(|f| {
                    ids.is_empty() || ids.contains(f.config.spot_fleet_request_id.as_ref().unwrap_or(&String::new()))
                })
                .map(|f| f.config.clone())
                .collect();
            let (items, next_token) = paginate(items, input.max_results, &input.next_token)?;
            Ok(t::DescribeSpotFleetRequestsResponse { spot_fleet_request_configs: Some(items), next_token })
        })
    }

    pub(crate) async fn describe_spot_fleet_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSpotFleetInstancesRequest,
    ) -> Result<t::DescribeSpotFleetInstancesResponse, ServiceError> {
        authorize(ctx, "DescribeSpotFleetInstances", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let id = input.spot_fleet_request_id.clone();
        self.find_spot_fleet(ctx, &id)?;
        self.evaluate_spot_fleet(ctx, &id).await;
        self.with_region(ctx, |r| {
            let items: Vec<t::ActiveInstance> = r.spot_fleets[&id]
                .members
                .iter()
                .map(|m| t::ActiveInstance {
                    instance_id: Some(m.instance_id.clone()),
                    instance_type: Some(m.instance_type.clone()),
                    spot_instance_request_id: m.spot_request_id.clone(),
                    instance_health: Some("healthy".into()),
                })
                .collect();
            let (items, next_token) = paginate(items, input.max_results, &input.next_token)?;
            Ok(t::DescribeSpotFleetInstancesResponse {
                active_instances: Some(items),
                next_token,
                spot_fleet_request_id: Some(id.clone()),
            })
        })
    }

    pub(crate) async fn describe_spot_fleet_request_history_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSpotFleetRequestHistoryRequest,
    ) -> Result<t::DescribeSpotFleetRequestHistoryResponse, ServiceError> {
        authorize(ctx, "DescribeSpotFleetRequestHistory", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let id = input.spot_fleet_request_id.clone();
        self.find_spot_fleet(ctx, &id)?;
        if let Some(e) = &input.event_type {
            if !matches!(e.as_str(), "instanceChange" | "fleetRequestChange" | "error" | "information") {
                return Err(invalid_parameter(format!("Value ({e}) for parameter eventType is invalid.")));
            }
        }
        self.evaluate_spot_fleet(ctx, &id).await;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let items: Vec<t::HistoryRecord> = r.spot_fleets[&id]
                .history
                .iter()
                .filter(|h| h.timestamp.is_some_and(|t| t >= input.start_time))
                .filter(|h| input.event_type.is_none() || h.event_type == input.event_type)
                .cloned()
                .collect();
            let (items, next_token) = paginate(items, input.max_results, &input.next_token)?;
            Ok(t::DescribeSpotFleetRequestHistoryResponse {
                history_records: Some(items),
                last_evaluated_time: Some(now),
                next_token,
                spot_fleet_request_id: Some(id.clone()),
                start_time: Some(input.start_time),
            })
        })
    }

    pub(crate) async fn modify_spot_fleet_request_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifySpotFleetRequestRequest,
    ) -> Result<t::ModifySpotFleetRequestResponse, ServiceError> {
        let id = input.spot_fleet_request_id.clone();
        self.find_spot_fleet(ctx, &id)?;
        authorize(ctx, "ModifySpotFleetRequest", &self.spot_fleet_resources(ctx, std::slice::from_ref(&id)), None)?;
        self.evaluate_spot_fleet(ctx, &id).await;
        let now = ctx.received_at;
        let excess = self.with_region(ctx, |r| {
            let f = r.spot_fleets.get_mut(&id).expect("checked");
            let cfg = f.config.spot_fleet_request_config.get_or_insert_with(Default::default);
            if cfg.r#type.as_deref() != Some("maintain") {
                return Err(err(
                    "InvalidSpotFleetRequestType",
                    "Only Spot Fleet requests of type 'maintain' can be modified.",
                ));
            }
            if f.config.spot_fleet_request_state.as_deref() != Some("active") {
                return Err(err(
                    "InvalidSpotFleetRequestState",
                    format!("The spot fleet request '{id}' is not in the active state."),
                ));
            }
            if let Some(policy) = &input.excess_capacity_termination_policy {
                if policy != "noTermination" && policy != "default" && policy != "Default" {
                    return Err(invalid_parameter(format!(
                        "Value ({policy}) for parameter excessCapacityTerminationPolicy is invalid."
                    )));
                }
                cfg.excess_capacity_termination_policy = Some(policy.clone());
            }
            if let Some(tc) = input.target_capacity {
                if tc < 0 {
                    return Err(invalid_parameter("TargetCapacity must be a non-negative number."));
                }
                cfg.target_capacity = tc;
            }
            if let Some(od) = input.on_demand_target_capacity {
                cfg.on_demand_target_capacity = Some(od);
            }
            if cfg.on_demand_target_capacity.unwrap_or(0) > cfg.target_capacity {
                return Err(invalid_parameter("OnDemandTargetCapacity cannot be more than the TargetCapacity."));
            }
            if let Some(ltc) = &input.launch_template_configs {
                cfg.launch_template_configs = Some(ltc.clone());
            }
            if input.context.is_some() {
                cfg.context = input.context.clone();
            }
            let target = cfg.target_capacity as f64;
            let od_target = cfg.on_demand_target_capacity.unwrap_or(0) as f64;
            let terminate = !cfg.excess_capacity_termination_policy.as_deref().is_some_and(|p| p == "noTermination");
            f.config.spot_fleet_request_state = Some("modifying".into());
            f.history.push(fleet_change("modify_in_progress", now));
            // Excess capacity: newest instances go first.
            let mut excess = Vec::new();
            if terminate {
                for lifecycle in ["spot", "on-demand"] {
                    let goal = if lifecycle == "spot" { target - od_target } else { od_target };
                    let mut have: f64 = f.members.iter().filter(|m| m.lifecycle == lifecycle).map(|m| m.weight).sum();
                    for m in f.members.iter().rev().filter(|m| m.lifecycle == lifecycle) {
                        if have - m.weight < goal {
                            break;
                        }
                        have -= m.weight;
                        excess.push(m.instance_id.clone());
                    }
                }
            }
            Ok(excess)
        })?;
        self.terminate_members(ctx, excess).await;
        self.evaluate_spot_fleet(ctx, &id).await;
        Ok(t::ModifySpotFleetRequestResponse { r#return: Some(true) })
    }

    pub(crate) async fn cancel_spot_fleet_requests_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelSpotFleetRequestsRequest,
    ) -> Result<t::CancelSpotFleetRequestsResponse, ServiceError> {
        if input.spot_fleet_request_ids.is_empty() {
            return Err(missing_parameter("SpotFleetRequestIds"));
        }
        authorize(
            ctx,
            "CancelSpotFleetRequests",
            &self.spot_fleet_resources(ctx, &input.spot_fleet_request_ids),
            input.dry_run,
        )?;
        let now = ctx.received_at;
        let mut ok = Vec::new();
        let mut failed = Vec::new();
        for id in &input.spot_fleet_request_ids {
            let fail = |code: &str, message: String| t::CancelSpotFleetRequestsErrorItem {
                spot_fleet_request_id: Some(id.clone()),
                error: Some(t::CancelSpotFleetRequestsError { code: Some(code.into()), message: Some(message) }),
            };
            if !id.starts_with("sfr-") {
                failed.push(fail("fleetRequestIdMalformed", format!("Invalid id: \"{id}\"")));
                continue;
            }
            let found = self.with_region(ctx, |r| {
                r.spot_fleets
                    .get(id)
                    .map(|f| (f.config.spot_fleet_request_state.clone().unwrap_or_default(), f.members.clone()))
            });
            let Some((previous, members)) = found else {
                failed.push(fail(
                    "fleetRequestIdDoesNotExist",
                    format!("The spot fleet request ID '{id}' does not exist"),
                ));
                continue;
            };
            if !matches!(previous.as_str(), "submitted" | "active" | "modifying") {
                failed.push(fail(
                    "fleetRequestNotInCancellableState",
                    format!("The spot fleet request '{id}' is in the {previous} state and cannot be cancelled."),
                ));
                continue;
            }
            if input.terminate_instances {
                self.terminate_members(ctx, members.iter().map(|m| m.instance_id.clone()).collect()).await;
            }
            let current = if input.terminate_instances { "cancelled_terminating" } else { "cancelled_running" };
            self.with_region(ctx, |r| {
                if let Some(f) = r.spot_fleets.get_mut(id) {
                    f.config.spot_fleet_request_state =
                        Some(if input.terminate_instances { "cancelled" } else { "cancelled_running" }.into());
                    f.history.push(fleet_change(current, now));
                    if input.terminate_instances {
                        f.members.clear();
                        f.history.push(fleet_change("cancelled", now));
                    }
                }
                for rec in r.spot_requests.values_mut().filter(|s| s.fleet_id.as_deref() == Some(id.as_str())) {
                    if rec.request.state.as_deref() == Some("active") {
                        rec.request.state = Some("cancelled".into());
                        rec.request.status = Some(t::SpotInstanceStatus {
                            code: Some(
                                if input.terminate_instances {
                                    "instance-terminated-by-user"
                                } else {
                                    "request-canceled-and-instance-running"
                                }
                                .into(),
                            ),
                            message: Some("The Spot Fleet request was cancelled.".into()),
                            update_time: Some(now),
                        });
                    }
                }
            });
            ok.push(t::CancelSpotFleetRequestsSuccessItem {
                spot_fleet_request_id: Some(id.clone()),
                previous_spot_fleet_request_state: Some(previous),
                current_spot_fleet_request_state: Some(current.into()),
            });
        }
        Ok(t::CancelSpotFleetRequestsResponse {
            successful_fleet_requests: Some(ok),
            unsuccessful_fleet_requests: Some(failed),
        })
    }

    // ---- EC2 Fleet ----------------------------------------------------------------------------------

    fn ec2_fleet_pools(
        &self,
        ctx: &RequestContext,
        configs: &[t::FleetLaunchTemplateConfigRequest],
    ) -> Result<Vec<Pool>, ServiceError> {
        if configs.is_empty() {
            return Err(missing_parameter("LaunchTemplateConfigs"));
        }
        let mut pools = Vec::new();
        for c in configs {
            let spec = c
                .launch_template_specification
                .clone()
                .ok_or_else(|| missing_parameter("LaunchTemplateConfigs.LaunchTemplateSpecification"))?;
            if spec.launch_template_id.is_none() && spec.launch_template_name.is_none() {
                return Err(missing_parameter("LaunchTemplateId or LaunchTemplateName"));
            }
            if spec.version.is_none() {
                return Err(missing_parameter("LaunchTemplateConfigs.LaunchTemplateSpecification.Version"));
            }
            let fleet_spec = t::FleetLaunchTemplateSpecification {
                launch_template_id: spec.launch_template_id.clone(),
                launch_template_name: spec.launch_template_name.clone(),
                version: spec.version.clone(),
            };
            let overrides: Vec<t::FleetLaunchTemplateOverrides> = c
                .overrides
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|o| t::FleetLaunchTemplateOverrides {
                    instance_type: o.instance_type,
                    max_price: o.max_price,
                    subnet_id: o.subnet_id,
                    availability_zone: o
                        .availability_zone
                        .or(o.placement.as_ref().and_then(|p| p.availability_zone.clone())),
                    weighted_capacity: o.weighted_capacity,
                    priority: o.priority,
                    image_id: o.image_id,
                    availability_zone_id: o.availability_zone_id,
                    ..Default::default()
                })
                .collect();
            self.template_pools(ctx, &fleet_spec, overrides, &mut pools)?;
        }
        Ok(pools)
    }

    /// How many on-demand and Spot units an EC2 Fleet wants.
    fn ec2_fleet_targets(spec: &t::TargetCapacitySpecificationRequest) -> Result<(f64, f64), ServiceError> {
        let total = spec.total_target_capacity;
        let od = spec.on_demand_target_capacity.unwrap_or(0);
        let spot = spec.spot_target_capacity.unwrap_or(0);
        if total < 0 || od < 0 || spot < 0 {
            return Err(invalid_parameter("Target capacities must be non-negative numbers."));
        }
        if od + spot > total {
            return Err(invalid_parameter(
                "The sum of OnDemandTargetCapacity and SpotTargetCapacity cannot be more than the TotalTargetCapacity.",
            ));
        }
        let default = spec.default_target_capacity_type.as_deref().unwrap_or("on-demand");
        if !matches!(default, "on-demand" | "spot") {
            return Err(invalid_parameter(format!(
                "Value ({default}) for parameter defaultTargetCapacityType is invalid."
            )));
        }
        let rest = (total - od - spot) as f64;
        Ok(if default == "spot" { (od as f64, spot as f64 + rest) } else { (od as f64 + rest, spot as f64) })
    }

    pub(crate) async fn create_fleet_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateFleetRequest,
    ) -> Result<t::CreateFleetResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "fleet", &["fleet", "instance", "volume", "network-interface"])?;
        let kind = input.r#type.clone().unwrap_or_else(|| "maintain".into());
        if !matches!(kind.as_str(), "instant" | "request" | "maintain") {
            return Err(invalid_parameter(format!(
                "Value ({kind}) for parameter type is invalid. Valid values: instant, request, maintain"
            )));
        }
        let (od_target, spot_target) = Self::ec2_fleet_targets(&input.target_capacity_specification)?;
        let now = ctx.received_at;
        if input.valid_until.is_some_and(|u| u <= now) {
            return Err(invalid_parameter("ValidUntil must be in the future."));
        }
        let spot_opts = input.spot_options.clone().unwrap_or_default();
        let od_opts = input.on_demand_options.clone().unwrap_or_default();
        let spot_strategy = spot_opts.allocation_strategy.clone().unwrap_or_else(|| "lowest-price".into());
        if !matches!(
            spot_strategy.as_str(),
            "lowest-price"
                | "diversified"
                | "capacity-optimized"
                | "capacity-optimized-prioritized"
                | "price-capacity-optimized"
        ) {
            return Err(invalid_parameter(format!(
                "Value ({spot_strategy}) for parameter allocationStrategy is invalid."
            )));
        }
        let od_strategy = od_opts.allocation_strategy.clone().unwrap_or_else(|| "lowest-price".into());
        if od_strategy != "lowest-price" && od_strategy != "prioritized" {
            return Err(invalid_parameter(format!(
                "Value ({od_strategy}) for parameter allocationStrategy is invalid."
            )));
        }
        let pools = self.ec2_fleet_pools(ctx, &input.launch_template_configs)?;
        let account = account_of(ctx);
        authorize(ctx, "CreateFleet", &[(arn(ctx, &account, "fleet/*"), request_tag_context(&tags))], input.dry_run)?;
        let id = format!("fleet-{}", uuid());
        let fleet_tags: Vec<t::Tag> = input
            .tag_specifications
            .iter()
            .flatten()
            .filter(|ts| ts.resource_type.as_deref() == Some("fleet"))
            .flat_map(|ts| ts.tags.clone().unwrap_or_default())
            .collect();
        let fleet = t::FleetData {
            activity_status: Some("pending_fulfillment".into()),
            create_time: Some(now),
            fleet_id: Some(id.clone()),
            fleet_state: Some("submitted".into()),
            client_token: input.client_token.clone(),
            excess_capacity_termination_policy: Some(
                input.excess_capacity_termination_policy.clone().unwrap_or_else(|| "termination".into()),
            ),
            fulfilled_capacity: Some(0.0),
            fulfilled_on_demand_capacity: Some(0.0),
            launch_template_configs: Some(
                input
                    .launch_template_configs
                    .iter()
                    .map(|c| t::FleetLaunchTemplateConfig {
                        launch_template_specification: c.launch_template_specification.as_ref().map(|s| {
                            t::FleetLaunchTemplateSpecification {
                                launch_template_id: s.launch_template_id.clone(),
                                launch_template_name: s.launch_template_name.clone(),
                                version: s.version.clone(),
                            }
                        }),
                        overrides: c.overrides.as_ref().map(|os| {
                            os.iter()
                                .map(|o| t::FleetLaunchTemplateOverrides {
                                    instance_type: o.instance_type.clone(),
                                    max_price: o.max_price.clone(),
                                    subnet_id: o.subnet_id.clone(),
                                    availability_zone: o.availability_zone.clone(),
                                    weighted_capacity: o.weighted_capacity,
                                    priority: o.priority,
                                    image_id: o.image_id.clone(),
                                    ..Default::default()
                                })
                                .collect()
                        }),
                    })
                    .collect(),
            ),
            target_capacity_specification: Some(t::TargetCapacitySpecification {
                total_target_capacity: Some(input.target_capacity_specification.total_target_capacity),
                on_demand_target_capacity: Some(od_target as i32),
                spot_target_capacity: Some(spot_target as i32),
                default_target_capacity_type: Some(
                    input
                        .target_capacity_specification
                        .default_target_capacity_type
                        .clone()
                        .unwrap_or_else(|| "on-demand".into()),
                ),
                target_capacity_unit_type: input.target_capacity_specification.target_capacity_unit_type.clone(),
            }),
            terminate_instances_with_expiration: Some(input.terminate_instances_with_expiration.unwrap_or(false)),
            valid_from: input.valid_from,
            valid_until: input.valid_until,
            replace_unhealthy_instances: Some(input.replace_unhealthy_instances.unwrap_or(false)),
            spot_options: Some(t::SpotOptions {
                allocation_strategy: Some(spot_strategy.clone()),
                instance_interruption_behavior: Some(
                    spot_opts.instance_interruption_behavior.clone().unwrap_or_else(|| "terminate".into()),
                ),
                instance_pools_to_use_count: spot_opts.instance_pools_to_use_count,
                single_instance_type: spot_opts.single_instance_type,
                single_availability_zone: spot_opts.single_availability_zone,
                min_target_capacity: spot_opts.min_target_capacity,
                max_total_price: spot_opts.max_total_price.clone(),
                ..Default::default()
            }),
            on_demand_options: Some(t::OnDemandOptions {
                allocation_strategy: Some(od_strategy.clone()),
                single_instance_type: od_opts.single_instance_type,
                single_availability_zone: od_opts.single_availability_zone,
                min_target_capacity: od_opts.min_target_capacity,
                max_total_price: od_opts.max_total_price.clone(),
                ..Default::default()
            }),
            tags: some_tags(fleet_tags),
            context: input.context.clone(),
            ..Default::default()
        };
        let mut history = vec![fleet_history("fleet-change", "submitted", None, now)];
        // Launch what the fleet asks for now.
        let (mut members, mut errors) = (Vec::new(), Vec::new());
        if od_target > 0.0 {
            let (m, e) =
                self.fill_capacity(ctx, &pools, od_target, false, &od_strategy, None, "aws:ec2:fleet-id", &id).await;
            members.extend(m);
            errors.extend(e);
        }
        if spot_target > 0.0 {
            let (m, e) =
                self.fill_capacity(ctx, &pools, spot_target, true, &spot_strategy, None, "aws:ec2:fleet-id", &id).await;
            members.extend(m);
            errors.extend(e);
        }
        let od_have: f64 = members.iter().filter(|m| m.lifecycle == "on-demand").map(|m| m.weight).sum();
        let spot_have: f64 = members.iter().filter(|m| m.lifecycle == "spot").map(|m| m.weight).sum();
        let below_min = |min: Option<i32>, have: f64| min.is_some_and(|m| have < m as f64);
        if kind == "instant"
            && (below_min(od_opts.min_target_capacity, od_have) || below_min(spot_opts.min_target_capacity, spot_have))
        {
            // All or nothing: the minimum was not met.
            self.terminate_members(ctx, members.iter().map(|m| m.instance_id.clone()).collect()).await;
            members.clear();
        }
        for m in &members {
            history.push(fleet_history("instance-change", "launched", Some(m.instance_id.clone()), now));
        }
        let fulfilled = od_have + spot_have;
        let mut fleet = fleet;
        fleet.fleet_state = Some("active".into());
        fleet.fulfilled_capacity = Some(members.iter().map(|m| m.weight).sum());
        fleet.fulfilled_on_demand_capacity =
            Some(members.iter().filter(|m| m.lifecycle == "on-demand").map(|m| m.weight).sum());
        fleet.activity_status = Some(
            if fulfilled >= od_target + spot_target {
                "fulfilled"
            } else if errors.is_empty() {
                "pending_fulfillment"
            } else {
                "error"
            }
            .into(),
        );
        history.push(fleet_history("fleet-change", "active", None, now));
        let group = |pool: usize| t::LaunchTemplateAndOverridesResponse {
            launch_template_specification: pools[pool].template.clone(),
            overrides: pools[pool].overrides.clone(),
        };
        let mut instances: Vec<t::CreateFleetInstance> = Vec::new();
        for m in &members {
            match instances.iter_mut().find(|i| {
                i.lifecycle.as_deref() == Some(m.lifecycle.as_str())
                    && i.launch_template_and_overrides.as_ref() == Some(&group(m.pool))
            }) {
                Some(i) => i.instance_ids.get_or_insert_with(Vec::new).push(m.instance_id.clone()),
                None => instances.push(t::CreateFleetInstance {
                    launch_template_and_overrides: Some(group(m.pool)),
                    lifecycle: Some(m.lifecycle.clone()),
                    instance_ids: Some(vec![m.instance_id.clone()]),
                    instance_type: Some(m.instance_type.clone()),
                    platform: None,
                    ..Default::default()
                }),
            }
        }
        let errs: Vec<t::CreateFleetError> = errors
            .iter()
            .map(|e| t::CreateFleetError {
                launch_template_and_overrides: Some(group(e.pool)),
                lifecycle: Some(e.lifecycle.clone()),
                error_code: Some(e.code.clone()),
                error_message: Some(e.message.clone()),
            })
            .collect();
        if kind == "instant" {
            fleet.instances = Some(
                instances
                    .iter()
                    .map(|i| t::DescribeFleetsInstances {
                        launch_template_and_overrides: i.launch_template_and_overrides.clone(),
                        lifecycle: i.lifecycle.clone(),
                        instance_ids: i.instance_ids.clone(),
                        instance_type: i.instance_type.clone(),
                        platform: None,
                    })
                    .collect(),
            );
            fleet.errors = Some(
                errs.iter()
                    .map(|e| t::DescribeFleetError {
                        launch_template_and_overrides: e.launch_template_and_overrides.clone(),
                        lifecycle: e.lifecycle.clone(),
                        error_code: e.error_code.clone(),
                        error_message: e.error_message.clone(),
                    })
                    .collect(),
            );
        }
        self.with_region(ctx, |r| {
            r.fleets
                .insert(id.clone(), FleetRecord { fleet, kind: kind.clone(), members, history, request: input.clone() })
        });
        if kind == "instant" {
            Ok(t::CreateFleetResult { fleet_id: Some(id), errors: Some(errs), instances: Some(instances) })
        } else {
            Ok(t::CreateFleetResult { fleet_id: Some(id), errors: None, instances: None })
        }
    }

    /// Bring an EC2 Fleet up to date.
    async fn evaluate_fleet(&self, ctx: &RequestContext, id: &str) {
        let now = ctx.received_at;
        let Some((rec_kind, state, request, members, valid_until)) = self.with_region(ctx, |r| {
            let ended: Vec<String> = r
                .fleets
                .get(id)?
                .members
                .iter()
                .filter(|m| instance_ended(r, &m.instance_id))
                .map(|m| m.instance_id.clone())
                .collect();
            let f = r.fleets.get_mut(id)?;
            for i in &ended {
                f.members.retain(|m| &m.instance_id != i);
                f.history.push(fleet_history("instance-change", "terminated", Some(i.clone()), now));
            }
            Some((
                f.kind.clone(),
                f.fleet.fleet_state.clone().unwrap_or_default(),
                f.request.clone(),
                f.members.clone(),
                f.fleet.valid_until,
            ))
        }) else {
            return;
        };
        if state != "active" && state != "modifying" {
            return;
        }
        if valid_until.is_some_and(|u| u <= now) {
            let terminate = request.terminate_instances_with_expiration.unwrap_or(false);
            if terminate {
                self.terminate_members(ctx, members.iter().map(|m| m.instance_id.clone()).collect()).await;
            }
            self.with_region(ctx, |r| {
                if let Some(f) = r.fleets.get_mut(id) {
                    f.fleet.fleet_state = Some(if terminate { "deleted" } else { "deleted_running" }.into());
                    f.history.push(fleet_history("fleet-change", "expired", None, now));
                }
            });
            return;
        }
        if rec_kind == "maintain" {
            if let (Ok(pools), Ok((od_target, spot_target))) = (
                self.ec2_fleet_pools(ctx, &request.launch_template_configs),
                Self::ec2_fleet_targets(&request.target_capacity_specification),
            ) {
                let have = |l: &str| -> f64 { members.iter().filter(|m| m.lifecycle == l).map(|m| m.weight).sum() };
                let later = service_ctx(ctx);
                let mut new_members = Vec::new();
                if have("on-demand") < od_target {
                    let strategy = request
                        .on_demand_options
                        .as_ref()
                        .and_then(|o| o.allocation_strategy.clone())
                        .unwrap_or_else(|| "lowest-price".into());
                    new_members.extend(
                        self.fill_capacity(
                            &later,
                            &pools,
                            od_target - have("on-demand"),
                            false,
                            &strategy,
                            None,
                            "aws:ec2:fleet-id",
                            id,
                        )
                        .await
                        .0,
                    );
                }
                if have("spot") < spot_target {
                    let strategy = request
                        .spot_options
                        .as_ref()
                        .and_then(|o| o.allocation_strategy.clone())
                        .unwrap_or_else(|| "lowest-price".into());
                    new_members.extend(
                        self.fill_capacity(
                            &later,
                            &pools,
                            spot_target - have("spot"),
                            true,
                            &strategy,
                            None,
                            "aws:ec2:fleet-id",
                            id,
                        )
                        .await
                        .0,
                    );
                }
                self.with_region(ctx, |r| {
                    if let Some(f) = r.fleets.get_mut(id) {
                        for m in &new_members {
                            f.history.push(fleet_history(
                                "instance-change",
                                "launched",
                                Some(m.instance_id.clone()),
                                now,
                            ));
                        }
                        f.members.extend(new_members);
                    }
                });
            }
        }
        self.with_region(ctx, |r| {
            if let Some(f) = r.fleets.get_mut(id) {
                if f.fleet.fleet_state.as_deref() == Some("modifying") {
                    f.fleet.fleet_state = Some("active".into());
                    f.history.push(fleet_history("fleet-change", "modify_succeeded", None, now));
                }
                let total: f64 = f.members.iter().map(|m| m.weight).sum();
                let od: f64 = f.members.iter().filter(|m| m.lifecycle == "on-demand").map(|m| m.weight).sum();
                f.fleet.fulfilled_capacity = Some(total);
                f.fleet.fulfilled_on_demand_capacity = Some(od);
                let target =
                    f.fleet.target_capacity_specification.as_ref().and_then(|t| t.total_target_capacity).unwrap_or(0)
                        as f64;
                if f.kind != "instant" {
                    f.fleet.activity_status =
                        Some(if total >= target { "fulfilled" } else { "pending_fulfillment" }.into());
                }
            }
        });
    }

    fn fleet_resources(&self, ctx: &RequestContext, ids: &[String]) -> Vec<(String, ConditionContext)> {
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            ids.iter()
                .map(|id| {
                    (
                        arn(ctx, &account, &format!("fleet/{id}")),
                        resource_tag_context(r.fleets.get(id).and_then(|f| f.fleet.tags.as_ref())),
                    )
                })
                .collect()
        })
    }

    fn find_fleet(&self, ctx: &RequestContext, id: &str) -> Result<(), ServiceError> {
        if !id.starts_with("fleet-") {
            return Err(err("InvalidFleetId.Malformed", format!("Invalid id: \"{id}\"")));
        }
        self.with_region(ctx, |r| {
            if r.fleets.contains_key(id) {
                Ok(())
            } else {
                Err(err("InvalidFleetId.NotFound", format!("The fleet ID '{id}' does not exist")))
            }
        })
    }

    pub(crate) async fn describe_fleets_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeFleetsRequest,
    ) -> Result<t::DescribeFleetsResult, ServiceError> {
        authorize(ctx, "DescribeFleets", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let ids = input.fleet_ids.clone().unwrap_or_default();
        for id in &ids {
            self.find_fleet(ctx, id)?;
        }
        let all: Vec<String> = self.with_region(ctx, |r| r.fleets.keys().cloned().collect());
        for id in &all {
            self.evaluate_fleet(ctx, id).await;
        }
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for f in r.fleets.values() {
                let id = f.fleet.fleet_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let d = &f.fleet;
                let ok = filters.matches(d.tags.as_ref(), |name| {
                    Some(match name {
                        "activity-status" => s(&d.activity_status),
                        "excess-capacity-termination-policy" => s(&d.excess_capacity_termination_policy),
                        "fleet-state" => s(&d.fleet_state),
                        "replace-unhealthy-instances" => {
                            d.replace_unhealthy_instances.map(|b| b.to_string()).into_iter().collect()
                        }
                        "type" => vec![f.kind.clone()],
                        _ => return None,
                    })
                })?;
                if ok {
                    let mut d = d.clone();
                    d.r#type = Some(f.kind.clone());
                    out.push(d);
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeFleetsResult { fleets: Some(items), next_token })
        })
    }

    pub(crate) async fn describe_fleet_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeFleetInstancesRequest,
    ) -> Result<t::DescribeFleetInstancesResult, ServiceError> {
        authorize(ctx, "DescribeFleetInstances", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let id = input.fleet_id.clone();
        self.find_fleet(ctx, &id)?;
        self.evaluate_fleet(ctx, &id).await;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for m in &r.fleets[&id].members {
                let ok = filters.matches(None, |name| match name {
                    "instance-type" => Some(vec![m.instance_type.clone()]),
                    _ => None,
                })?;
                if ok {
                    out.push(t::ActiveInstance {
                        instance_id: Some(m.instance_id.clone()),
                        instance_type: Some(m.instance_type.clone()),
                        spot_instance_request_id: m.spot_request_id.clone(),
                        instance_health: Some("healthy".into()),
                    });
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeFleetInstancesResult {
                active_instances: Some(items),
                next_token,
                fleet_id: Some(id.clone()),
            })
        })
    }

    pub(crate) async fn describe_fleet_history_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeFleetHistoryRequest,
    ) -> Result<t::DescribeFleetHistoryResult, ServiceError> {
        authorize(ctx, "DescribeFleetHistory", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let id = input.fleet_id.clone();
        self.find_fleet(ctx, &id)?;
        if let Some(e) = &input.event_type {
            if !matches!(e.as_str(), "instance-change" | "fleet-change" | "service-error") {
                return Err(invalid_parameter(format!("Value ({e}) for parameter eventType is invalid.")));
            }
        }
        self.evaluate_fleet(ctx, &id).await;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let items: Vec<t::HistoryRecordEntry> = r.fleets[&id]
                .history
                .iter()
                .filter(|h| h.timestamp.is_some_and(|t| t >= input.start_time))
                .filter(|h| input.event_type.is_none() || h.event_type == input.event_type)
                .cloned()
                .collect();
            let (items, next_token) = paginate(items, input.max_results, &input.next_token)?;
            Ok(t::DescribeFleetHistoryResult {
                history_records: Some(items),
                last_evaluated_time: Some(now),
                next_token,
                fleet_id: Some(id.clone()),
                start_time: Some(input.start_time),
            })
        })
    }

    pub(crate) async fn modify_fleet_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyFleetRequest,
    ) -> Result<t::ModifyFleetResult, ServiceError> {
        let id = input.fleet_id.clone();
        self.find_fleet(ctx, &id)?;
        authorize(ctx, "ModifyFleet", &self.fleet_resources(ctx, std::slice::from_ref(&id)), input.dry_run)?;
        self.evaluate_fleet(ctx, &id).await;
        let now = ctx.received_at;
        let excess = self.with_region(ctx, |r| {
            let f = r.fleets.get_mut(&id).expect("checked");
            if f.kind != "maintain" {
                return Err(err("InvalidFleetConfiguration", "Only EC2 Fleets of type 'maintain' can be modified."));
            }
            if f.fleet.fleet_state.as_deref() != Some("active") {
                return Err(err("IncorrectState", format!("The fleet '{id}' is not in the active state.")));
            }
            if let Some(tcs) = &input.target_capacity_specification {
                Self::ec2_fleet_targets(tcs)?;
                f.request.target_capacity_specification = tcs.clone();
                if let Some(t) = f.fleet.target_capacity_specification.as_mut() {
                    t.total_target_capacity = Some(tcs.total_target_capacity);
                    t.on_demand_target_capacity = tcs.on_demand_target_capacity.or(t.on_demand_target_capacity);
                    t.spot_target_capacity = tcs.spot_target_capacity.or(t.spot_target_capacity);
                }
            }
            if let Some(ltc) = &input.launch_template_configs {
                f.request.launch_template_configs = ltc.clone();
            }
            if let Some(p) = &input.excess_capacity_termination_policy {
                if p != "no-termination" && p != "termination" {
                    return Err(invalid_parameter(format!(
                        "Value ({p}) for parameter excessCapacityTerminationPolicy is invalid."
                    )));
                }
                f.fleet.excess_capacity_termination_policy = Some(p.clone());
            }
            if input.context.is_some() {
                f.fleet.context = input.context.clone();
            }
            f.fleet.fleet_state = Some("modifying".into());
            f.history.push(fleet_history("fleet-change", "modify_in_progress", None, now));
            let (od_target, spot_target) = Self::ec2_fleet_targets(&f.request.target_capacity_specification)?;
            let mut excess = Vec::new();
            if f.fleet.excess_capacity_termination_policy.as_deref() != Some("no-termination") {
                for (lifecycle, goal) in [("spot", spot_target), ("on-demand", od_target)] {
                    let mut have: f64 = f.members.iter().filter(|m| m.lifecycle == lifecycle).map(|m| m.weight).sum();
                    for m in f.members.iter().rev().filter(|m| m.lifecycle == lifecycle) {
                        if have - m.weight < goal {
                            break;
                        }
                        have -= m.weight;
                        excess.push(m.instance_id.clone());
                    }
                }
            }
            Ok(excess)
        })?;
        self.terminate_members(ctx, excess).await;
        self.evaluate_fleet(ctx, &id).await;
        Ok(t::ModifyFleetResult { r#return: Some(true) })
    }

    pub(crate) async fn delete_fleets_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteFleetsRequest,
    ) -> Result<t::DeleteFleetsResult, ServiceError> {
        if input.fleet_ids.is_empty() {
            return Err(missing_parameter("FleetIds"));
        }
        authorize(ctx, "DeleteFleets", &self.fleet_resources(ctx, &input.fleet_ids), input.dry_run)?;
        let now = ctx.received_at;
        let mut ok = Vec::new();
        let mut failed = Vec::new();
        for id in &input.fleet_ids {
            let fail = |code: &str, message: String| t::DeleteFleetErrorItem {
                fleet_id: Some(id.clone()),
                error: Some(t::DeleteFleetError { code: Some(code.into()), message: Some(message) }),
            };
            if !id.starts_with("fleet-") {
                failed.push(fail("fleetIdMalformed", format!("Invalid id: \"{id}\"")));
                continue;
            }
            let found = self.with_region(ctx, |r| {
                r.fleets
                    .get(id)
                    .map(|f| (f.fleet.fleet_state.clone().unwrap_or_default(), f.kind.clone(), f.members.clone()))
            });
            let Some((previous, kind, members)) = found else {
                failed.push(fail("fleetIdDoesNotExist", format!("The fleet ID '{id}' does not exist")));
                continue;
            };
            if previous.starts_with("deleted") {
                failed.push(fail("fleetNotInDeletableState", format!("The fleet '{id}' is already deleted.")));
                continue;
            }
            if kind == "instant" && !input.terminate_instances {
                failed.push(fail(
                    "unexpectedError",
                    "NoTerminateInstances is not supported for EC2 Fleets of type instant.".into(),
                ));
                continue;
            }
            if input.terminate_instances {
                self.terminate_members(ctx, members.iter().map(|m| m.instance_id.clone()).collect()).await;
            }
            let current = if input.terminate_instances { "deleted_terminating" } else { "deleted_running" };
            self.with_region(ctx, |r| {
                if let Some(f) = r.fleets.get_mut(id) {
                    f.fleet.fleet_state =
                        Some(if input.terminate_instances { "deleted" } else { "deleted_running" }.into());
                    f.history.push(fleet_history("fleet-change", current, None, now));
                    if input.terminate_instances {
                        f.members.clear();
                        f.history.push(fleet_history("fleet-change", "deleted", None, now));
                    }
                }
            });
            ok.push(t::DeleteFleetSuccessItem {
                fleet_id: Some(id.clone()),
                previous_fleet_state: Some(previous),
                current_fleet_state: Some(current.into()),
            });
        }
        Ok(t::DeleteFleetsResult { successful_fleet_deletions: Some(ok), unsuccessful_fleet_deletions: Some(failed) })
    }
}

fn fleet_change(sub: &str, at: chrono::DateTime<chrono::Utc>) -> t::HistoryRecord {
    t::HistoryRecord {
        event_type: Some("fleetRequestChange".into()),
        event_information: Some(t::EventInformation { event_sub_type: Some(sub.into()), ..Default::default() }),
        timestamp: Some(at),
    }
}

fn fleet_history(
    kind: &str,
    sub: &str,
    instance: Option<String>,
    at: chrono::DateTime<chrono::Utc>,
) -> t::HistoryRecordEntry {
    t::HistoryRecordEntry {
        event_type: Some(kind.into()),
        event_information: Some(t::EventInformation {
            event_sub_type: Some(sub.into()),
            instance_id: instance,
            ..Default::default()
        }),
        timestamp: Some(at),
    }
}
