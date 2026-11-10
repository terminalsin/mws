//! Spot Instances: requests (`RequestSpotInstances`, and the requests Spot
//! `RunInstances` and fleets make), their lifecycle on the emulated clock,
//! and the simulated Spot market (`DescribeSpotPriceHistory`).
//!
//! Requests are evaluated when they are made and whenever Spot requests
//! are described: an open request launches when its price clears the
//! market, a persistent one launches again after its instance is
//! terminated, and requests whose instances end close. MWS does not
//! interrupt Spot Instances.


use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::pricing::{fmt_price, spot_price};
use crate::state::{InstanceRecord, RegionState, SpotRequestRecord};
use crate::util::{
    arn, err, invalid_parameter, missing_parameter, new_id, paginate, request_tag_context, resource_tag_context, s,
    tags_for, Filters, Kind,
};
use crate::{account_of, Ec2};

pub(crate) const PRODUCT: &str = "Linux/UNIX";

/// A context for launches MWS makes on a requester's behalf later (a
/// persistent request relaunching, a fleet keeping its capacity): the
/// request was authorized when it was made.
pub(crate) fn service_ctx(ctx: &RequestContext) -> RequestContext {
    ctx.on_behalf()
}

fn status(code: &str, message: impl Into<String>, at: DateTime<Utc>) -> Option<t::SpotInstanceStatus> {
    Some(t::SpotInstanceStatus { code: Some(code.into()), message: Some(message.into()), update_time: Some(at) })
}

fn set_status(
    req: &mut t::SpotInstanceRequest,
    state: &str,
    code: &str,
    message: impl Into<String>,
    at: DateTime<Utc>,
) {
    let message = message.into();
    let same = req.state.as_deref() == Some(state)
        && req
            .status
            .as_ref()
            .is_some_and(|s| s.code.as_deref() == Some(code) && s.message.as_deref() == Some(message.as_str()));
    if !same {
        req.state = Some(state.into());
        req.status = status(code, message, at);
    }
}

/// The zone a launch lands in, for its price: the subnet's, the placement's,
/// or the default VPC's first zone.
pub(crate) fn launch_zone(r: &RegionState, subnet_id: Option<&str>, zone: Option<&str>) -> Option<String> {
    if let Some(z) = zone {
        return Some(z.to_string());
    }
    if let Some(id) = subnet_id {
        return r.subnets.get(id).and_then(|s| s.availability_zone.clone());
    }
    let default_vpc = r.vpcs.values().find(|v| v.vpc.is_default == Some(true)).and_then(|v| v.vpc.vpc_id.clone())?;
    let mut zones: Vec<String> = r
        .subnets
        .values()
        .filter(|s| s.vpc_id.as_deref() == Some(default_vpc.as_str()) && s.default_for_az == Some(true))
        .filter_map(|s| s.availability_zone.clone())
        .collect();
    zones.sort();
    zones.into_iter().next()
}

fn instance_state(r: &RegionState, id: &str) -> Option<String> {
    r.instances.get(id).and_then(|i| i.instance.state.as_ref()).and_then(|s| s.name.clone())
}

/// The Spot request a Spot `RunInstances` makes for each instance.
pub(crate) fn record_run_instances_request(
    r: &mut RegionState,
    rec: &InstanceRecord,
    options: &t::SpotMarketOptions,
    price: f64,
    now: DateTime<Utc>,
) {
    let i = &rec.instance;
    let id = i.spot_instance_request_id.clone().unwrap_or_default();
    let max = options
        .max_price
        .clone()
        .or_else(|| crate::pricing::on_demand_price(i.instance_type.as_deref().unwrap_or_default()).map(fmt_price))
        .unwrap_or_else(|| fmt_price(price));
    let request = t::SpotInstanceRequest {
        spot_instance_request_id: Some(id.clone()),
        create_time: Some(now),
        instance_id: i.instance_id.clone(),
        launch_specification: Some(t::LaunchSpecification {
            image_id: i.image_id.clone(),
            instance_type: i.instance_type.clone(),
            key_name: i.key_name.clone(),
            subnet_id: i.subnet_id.clone(),
            placement: Some(t::SpotPlacement {
                availability_zone: i.placement.as_ref().and_then(|p| p.availability_zone.clone()),
                tenancy: Some("default".into()),
                ..Default::default()
            }),
            security_groups: i.security_groups.clone(),
            monitoring: Some(t::RunInstancesMonitoringEnabled { enabled: false }),
            ..Default::default()
        }),
        launched_availability_zone: i.placement.as_ref().and_then(|p| p.availability_zone.clone()),
        launched_availability_zone_id: i.placement.as_ref().and_then(|p| p.availability_zone_id.clone()),
        product_description: Some(PRODUCT.into()),
        spot_price: Some(max),
        state: Some("active".into()),
        status: status("fulfilled", "Your spot request is fulfilled.", now),
        r#type: Some(options.spot_instance_type.clone().unwrap_or_else(|| "one-time".into())),
        valid_until: options.valid_until,
        instance_interruption_behavior: Some(
            options.instance_interruption_behavior.clone().unwrap_or_else(|| "terminate".into()),
        ),
        tags: Some(Vec::new()),
        ..Default::default()
    };
    r.spot_requests.insert(id, SpotRequestRecord { request, launch: None, fleet_id: None, client_token: None });
}

/// `RunInstances` for one instance of a `RequestSpotInstances` request.
fn run_request(spec: &t::RequestSpotLaunchSpecification, req: &t::SpotInstanceRequest) -> t::RunInstancesRequest {
    t::RunInstancesRequest {
        image_id: spec.image_id.clone(),
        instance_type: spec.instance_type.clone(),
        key_name: spec.key_name.clone(),
        kernel_id: spec.kernel_id.clone(),
        ramdisk_id: spec.ramdisk_id.clone(),
        security_group_ids: spec.security_group_ids.clone(),
        security_groups: spec.security_groups.clone(),
        block_device_mappings: spec.block_device_mappings.clone(),
        ebs_optimized: spec.ebs_optimized,
        iam_instance_profile: spec.iam_instance_profile.clone(),
        monitoring: spec.monitoring.clone(),
        network_interfaces: spec.network_interfaces.clone(),
        placement: spec.placement.as_ref().map(|p| t::Placement {
            availability_zone: p.availability_zone.clone(),
            group_name: p.group_name.clone(),
            tenancy: p.tenancy.clone(),
            ..Default::default()
        }),
        subnet_id: spec.subnet_id.clone(),
        user_data: spec.user_data.clone(),
        instance_market_options: Some(t::InstanceMarketOptionsRequest {
            market_type: Some("spot".into()),
            spot_options: Some(t::SpotMarketOptions {
                max_price: req.spot_price.clone(),
                // The request itself is the persistent one; each launch is
                // one instance.
                spot_instance_type: Some("one-time".into()),
                instance_interruption_behavior: None,
                ..Default::default()
            }),
        }),
        min_count: 1,
        max_count: 1,
        ..Default::default()
    }
}

impl Ec2 {
    /// Bring Spot requests up to date with their instances and the market,
    /// launching what is due. `strict` is the caller's own request: an
    /// authorization failure is theirs to see.
    pub(crate) async fn evaluate_spot_requests(
        &self,
        ctx: &RequestContext,
        only: Option<&[String]>,
        strict: bool,
    ) -> Result<(), ServiceError> {
        let now = ctx.received_at;
        let due = self.with_region(ctx, |r| {
            let mut due = Vec::new();
            let ids: Vec<String> = r.spot_requests.keys().cloned().collect();
            for id in ids {
                if only.is_some_and(|o| !o.contains(&id)) {
                    continue;
                }
                let instance = r.spot_requests[&id].request.instance_id.clone();
                let inst_state = instance.as_deref().and_then(|i| instance_state(r, i));
                let zone = {
                    let rec = &r.spot_requests[&id];
                    rec.launch.as_ref().and_then(|l| {
                        launch_zone(
                            r,
                            l.subnet_id.as_deref(),
                            l.placement.as_ref().and_then(|p| p.availability_zone.as_deref()),
                        )
                    })
                };
                let rec = r.spot_requests.get_mut(&id).expect("listed");
                let req = &mut rec.request;
                let state = req.state.clone().unwrap_or_default();
                let persistent = req.r#type.as_deref() == Some("persistent");
                match state.as_str() {
                    "active" | "disabled" => match inst_state.as_deref() {
                        Some("terminated") | Some("shutting-down") | None => {
                            if persistent && rec.launch.is_some() {
                                set_status(req, "open", "instance-terminated-by-user", "Spot Instance terminated due to user-initiated termination.", now);
                                req.instance_id = None;
                            } else {
                                set_status(req, "closed", "instance-terminated-by-user", "Spot Instance terminated due to user-initiated termination.", now);
                            }
                        }
                        Some("stopped") | Some("stopping") => {
                            set_status(req, "disabled", "instance-stopped-by-user", "Spot Instance stopped due to user-initiated stop.", now);
                        }
                        _ => set_status(req, "active", "fulfilled", "Your spot request is fulfilled.", now),
                    },
                    "cancelled" => match inst_state.as_deref() {
                        Some("terminated") | None if instance.is_some() => {
                            set_status(req, "cancelled", "instance-terminated-by-user", "Spot Instance terminated due to user-initiated termination.", now)
                        }
                        _ => {}
                    },
                    _ => {}
                }
                if req.state.as_deref() != Some("open") || rec.launch.is_none() {
                    continue;
                }
                if req.valid_until.is_some_and(|u| u <= now) {
                    set_status(req, "closed", "schedule-expired", "Your Spot request has expired because it was not fulfilled before its valid-until time.", now);
                    continue;
                }
                if let Some(from) = req.valid_from.filter(|f| *f > now) {
                    set_status(req, "open", "not-scheduled-yet", format!("Your Spot request will not be evaluated until {}.", from.format("%Y-%m-%dT%H:%M:%SZ")), now);
                    continue;
                }
                let itype = rec.launch.as_ref().and_then(|l| l.instance_type.clone()).unwrap_or_else(|| "m1.small".into());
                let market = zone.as_deref().and_then(|z| spot_price(&itype, z, PRODUCT, now));
                let max: Option<f64> = req.spot_price.as_deref().and_then(|p| p.parse().ok());
                if let (Some(m), Some(max)) = (market, max) {
                    if max < m {
                        set_status(
                            req,
                            "open",
                            "price-too-low",
                            format!("Your Spot request price of {max} is lower than the minimum required Spot request fulfillment price of {}.", fmt_price(m)),
                            now,
                        );
                        continue;
                    }
                }
                due.push((id.clone(), run_request(rec.launch.as_ref().expect("checked"), req)));
            }
            due
        });
        let later = service_ctx(ctx);
        for (id, run) in due {
            let launch_ctx = if strict { ctx } else { &later };
            match self.run_instances_with(launch_ctx, run, Vec::new(), Some(id.clone())).await {
                Ok(res) => {
                    let inst = res.instances.unwrap_or_default().into_iter().next().unwrap_or_default();
                    self.with_region(ctx, |r| {
                        if let Some(rec) = r.spot_requests.get_mut(&id) {
                            let req = &mut rec.request;
                            req.instance_id = inst.instance_id.clone();
                            req.launched_availability_zone =
                                inst.placement.as_ref().and_then(|p| p.availability_zone.clone());
                            req.launched_availability_zone_id =
                                inst.placement.as_ref().and_then(|p| p.availability_zone_id.clone());
                            set_status(req, "active", "fulfilled", "Your spot request is fulfilled.", now);
                        }
                    });
                }
                Err(e) if strict && (e.code == "UnauthorizedOperation" || e.code == "DryRunOperation") => {
                    return Err(e)
                }
                Err(e) => self.with_region(ctx, |r| {
                    if let Some(rec) = r.spot_requests.get_mut(&id) {
                        let code = if e.code == "InsufficientInstanceCapacity" || e.code == "VcpuLimitExceeded" {
                            "capacity-not-available"
                        } else {
                            "bad-parameters"
                        };
                        let state = if code == "bad-parameters" { "closed" } else { "open" };
                        set_status(&mut rec.request, state, code, e.message.clone(), now);
                        rec.request.fault = Some(t::SpotInstanceStateFault {
                            code: Some(e.code.to_string()),
                            message: Some(e.message.clone()),
                        });
                    }
                }),
            }
        }
        Ok(())
    }

    pub(crate) async fn request_spot_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::RequestSpotInstancesRequest,
    ) -> Result<t::RequestSpotInstancesResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "spot-instances-request", &["spot-instances-request"])?;
        let spec = input.launch_specification.clone().ok_or_else(|| missing_parameter("LaunchSpecification"))?;
        if spec.image_id.is_none() {
            return Err(missing_parameter("LaunchSpecification.ImageId"));
        }
        let count = input.instance_count.unwrap_or(1);
        if count < 1 {
            return Err(invalid_parameter(format!(
                "Value ({count}) for parameter instanceCount is invalid. Expected a positive integer."
            )));
        }
        let kind = input.r#type.clone().unwrap_or_else(|| "one-time".into());
        if kind != "one-time" && kind != "persistent" {
            return Err(invalid_parameter(format!(
                "Value ({kind}) for parameter type is invalid. Valid values: one-time, persistent"
            )));
        }
        let behavior = input.instance_interruption_behavior.clone().unwrap_or_else(|| "terminate".into());
        if !matches!(behavior.as_str(), "terminate" | "stop" | "hibernate") {
            return Err(invalid_parameter(format!(
                "Value ({behavior}) for parameter instanceInterruptionBehavior is invalid."
            )));
        }
        if behavior != "terminate" && kind != "persistent" {
            return Err(err(
                "InvalidParameterCombination",
                "The instance interruption behavior 'stop' or 'hibernate' is supported only for persistent Spot requests.",
            ));
        }
        if input.block_duration_minutes.is_some() {
            return Err(err(
                "Unsupported",
                "Spot Instances with a defined duration (Spot blocks) are no longer available.",
            ));
        }
        let now = ctx.received_at;
        if input.valid_until.is_some_and(|u| u <= now) {
            return Err(invalid_parameter("validUntil must be in the future."));
        }
        if let (Some(f), Some(u)) = (input.valid_from, input.valid_until) {
            if u <= f {
                return Err(invalid_parameter("validUntil must be later than validFrom."));
            }
        }
        let itype = spec.instance_type.clone().unwrap_or_else(|| "m1.small".into());
        let od = crate::pricing::on_demand_price(&itype)
            .ok_or_else(|| invalid_parameter(format!("Invalid value '{itype}' for InstanceType.")))?;
        let max = match &input.spot_price {
            Some(p) => {
                let v: f64 = p.parse().map_err(|_| invalid_parameter(format!("Invalid value '{p}' for spotPrice.")))?;
                if v <= 0.0 {
                    return Err(invalid_parameter(format!("Invalid value '{p}' for spotPrice.")));
                }
                p.clone()
            }
            None => fmt_price(od),
        };
        let account = account_of(ctx);
        self.authorize_known(
            ctx,
            "RequestSpotInstances",
            &[(arn(ctx, &account, "spot-instances-request/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        let fp = crate::idempotency::fingerprint(&input);
        self.with_region(ctx, |r| {
            crate::idempotency::replay(r, "RequestSpotInstances", input.client_token.as_deref(), &fp, |_| true)
        })?;
        if let Some(token) = &input.client_token {
            let existing: Vec<t::SpotInstanceRequest> = self.with_region(ctx, |r| {
                r.spot_requests
                    .values()
                    .filter(|s| s.client_token.as_deref() == Some(token.as_str()))
                    .map(|s| s.request.clone())
                    .collect()
            });
            if !existing.is_empty() {
                return Ok(t::RequestSpotInstancesResult { spot_instance_requests: Some(existing) });
            }
        }
        let mut submitted = Vec::new();
        let ids: Vec<String> = self.with_region(ctx, |r| {
            (0..count)
                .map(|_| {
                    let id = new_id("sir")[..12].to_string();
                    let request = t::SpotInstanceRequest {
                        spot_instance_request_id: Some(id.clone()),
                        create_time: Some(now),
                        launch_specification: Some(t::LaunchSpecification {
                            image_id: spec.image_id.clone(),
                            instance_type: Some(itype.clone()),
                            key_name: spec.key_name.clone(),
                            subnet_id: spec.subnet_id.clone(),
                            user_data: spec.user_data.clone(),
                            block_device_mappings: spec.block_device_mappings.clone(),
                            ebs_optimized: spec.ebs_optimized,
                            iam_instance_profile: spec.iam_instance_profile.clone(),
                            kernel_id: spec.kernel_id.clone(),
                            ramdisk_id: spec.ramdisk_id.clone(),
                            network_interfaces: spec.network_interfaces.clone(),
                            placement: spec.placement.clone(),
                            security_groups: Some(
                                spec.security_group_ids
                                    .iter()
                                    .flatten()
                                    .map(|g| t::GroupIdentifier { group_id: Some(g.clone()), group_name: None })
                                    .chain(
                                        spec.security_groups.iter().flatten().map(|g| t::GroupIdentifier {
                                            group_id: None,
                                            group_name: Some(g.clone()),
                                        }),
                                    )
                                    .collect(),
                            ),
                            monitoring: Some(
                                spec.monitoring.clone().unwrap_or(t::RunInstancesMonitoringEnabled { enabled: false }),
                            ),
                            addressing_type: spec.addressing_type.clone(),
                        }),
                        product_description: Some(PRODUCT.into()),
                        spot_price: Some(max.clone()),
                        state: Some("open".into()),
                        status: status(
                            "pending-evaluation",
                            "Your Spot request has been submitted for review, and is pending evaluation.",
                            now,
                        ),
                        r#type: Some(kind.clone()),
                        valid_from: input.valid_from,
                        valid_until: input.valid_until,
                        launch_group: input.launch_group.clone(),
                        availability_zone_group: input.availability_zone_group.clone(),
                        instance_interruption_behavior: Some(behavior.clone()),
                        tags: Some(tags.clone()),
                        ..Default::default()
                    };
                    submitted.push(request.clone());
                    r.spot_requests.insert(
                        id.clone(),
                        SpotRequestRecord {
                            request,
                            launch: Some(spec.clone()),
                            fleet_id: None,
                            client_token: input.client_token.clone(),
                        },
                    );
                    id
                })
                .collect()
        });
        self.with_region(ctx, |r| {
            crate::idempotency::remember(r, "RequestSpotInstances", input.client_token.as_deref(), &fp, &ids.join(","))
        });
        if let Err(e) = self.evaluate_spot_requests(ctx, Some(&ids), true).await {
            self.with_region(ctx, |r| {
                for id in &ids {
                    r.spot_requests.remove(id);
                }
            });
            return Err(e);
        }
        Ok(t::RequestSpotInstancesResult { spot_instance_requests: Some(submitted) })
    }

    pub(crate) async fn describe_spot_instance_requests_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSpotInstanceRequestsRequest,
    ) -> Result<t::DescribeSpotInstanceRequestsResult, ServiceError> {
        self.authorize_known(
            ctx,
            "DescribeSpotInstanceRequests",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let ids = input.spot_instance_request_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| Kind::SpotInstanceRequest.check_all(&ids, |id| r.spot_requests.contains_key(id)))?;
        self.evaluate_spot_requests(ctx, None, false).await?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for rec in r.spot_requests.values() {
                let q = &rec.request;
                let id = q.spot_instance_request_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let spec = q.launch_specification.clone().unwrap_or_default();
                let st = q.status.clone().unwrap_or_default();
                let ok = filters.matches(q.tags.as_ref(), |name| {
                    Some(match name {
                        "availability-zone-group" => s(&q.availability_zone_group),
                        "create-time" => q.create_time.map(|t| t.to_rfc3339()).into_iter().collect(),
                        "fault-code" => q.fault.as_ref().map(|f| s(&f.code)).unwrap_or_default(),
                        "fault-message" => q.fault.as_ref().map(|f| s(&f.message)).unwrap_or_default(),
                        "instance-id" => s(&q.instance_id),
                        "launch-group" => s(&q.launch_group),
                        "launch.image-id" => s(&spec.image_id),
                        "launch.instance-type" => s(&spec.instance_type),
                        "launch.key-name" => s(&spec.key_name),
                        "launched-availability-zone" => s(&q.launched_availability_zone),
                        "product-description" => s(&q.product_description),
                        "spot-instance-request-id" => vec![id.clone()],
                        "spot-price" => s(&q.spot_price),
                        "state" => s(&q.state),
                        "status-code" => s(&st.code),
                        "status-message" => s(&st.message),
                        "type" => s(&q.r#type),
                        "instance-interruption-behavior" => s(&q.instance_interruption_behavior),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(q.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeSpotInstanceRequestsResult { spot_instance_requests: Some(items), next_token })
        })
    }

    pub(crate) async fn cancel_spot_instance_requests_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelSpotInstanceRequestsRequest,
    ) -> Result<t::CancelSpotInstanceRequestsResult, ServiceError> {
        if input.spot_instance_request_ids.is_empty() {
            return Err(missing_parameter("SpotInstanceRequestIds"));
        }
        let account = account_of(ctx);
        let ids = input.spot_instance_request_ids.clone();
        let resources = self.with_region(ctx, |r| {
            Kind::SpotInstanceRequest.check_all(&ids, |id| r.spot_requests.contains_key(id))?;
            Ok::<_, ServiceError>(
                ids.iter()
                    .map(|id| {
                        (
                            arn(ctx, &account, &format!("spot-instances-request/{id}")),
                            resource_tag_context(r.spot_requests[id].request.tags.as_ref()),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })?;
        self.authorize_known(ctx, "CancelSpotInstanceRequests", &resources, input.dry_run)?;
        self.evaluate_spot_requests(ctx, Some(&ids), false).await?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for id in &ids {
                let instance = r.spot_requests[id].request.instance_id.clone();
                let running = instance.as_deref().and_then(|i| instance_state(r, i)).is_some_and(|s| s != "terminated");
                let rec = r.spot_requests.get_mut(id).expect("checked");
                let req = &mut rec.request;
                match req.state.as_deref() {
                    Some("open") | Some("active") | Some("disabled") => {
                        if running {
                            set_status(
                                req,
                                "cancelled",
                                "request-canceled-and-instance-running",
                                "Spot Instance request is canceled, but the instance is still running.",
                                now,
                            );
                        } else {
                            set_status(
                                req,
                                "cancelled",
                                "canceled-before-fulfillment",
                                "Your Spot request was canceled before it was fulfilled.",
                                now,
                            );
                        }
                    }
                    _ => {}
                }
                out.push(t::CancelledSpotInstanceRequest {
                    spot_instance_request_id: Some(id.clone()),
                    state: Some(if req.state.as_deref() == Some("closed") { "closed" } else { "cancelled" }.into()),
                });
            }
            Ok(t::CancelSpotInstanceRequestsResult { cancelled_spot_instance_requests: Some(out) })
        })
    }

    pub(crate) fn describe_spot_price_history_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSpotPriceHistoryRequest,
    ) -> Result<t::DescribeSpotPriceHistoryResult, ServiceError> {
        self.authorize_known(ctx, "DescribeSpotPriceHistory", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let now = ctx.received_at;
        let end = input.end_time.unwrap_or(now).min(now);
        let start = input.start_time.unwrap_or(end - chrono::Duration::days(1));
        if start > end {
            return Err(invalid_parameter("The start time must be before the end time."));
        }
        if start < now - chrono::Duration::days(90) {
            return Err(invalid_parameter("Spot price history is available for the past 90 days only."));
        }
        let types = input.instance_types.clone().unwrap_or_default();
        let products = input.product_descriptions.clone().unwrap_or_default();
        let zone = match (&input.availability_zone, &input.availability_zone_id) {
            (Some(z), _) => Some(z.clone()),
            (None, Some(id)) => crate::catalog::zone_name(&ctx.region, id),
            _ => None,
        };
        let filters = Filters::new(&input.filters);
        let zones = crate::catalog::zones(&ctx.region);
        let period = chrono::Duration::hours(crate::pricing::SPOT_PERIOD_HOURS);
        let mut out = Vec::new();
        let mut at = crate::pricing::spot_period_start(end);
        let first = crate::pricing::spot_period_start(start);
        while at >= first {
            for itype in crate::catalog::INSTANCE_TYPES {
                if !types.is_empty() && !types.iter().any(|t| t == itype.name) {
                    continue;
                }
                for (z, zid) in &zones {
                    if zone.as_ref().is_some_and(|w| w != z) {
                        continue;
                    }
                    for product in crate::pricing::PRODUCTS {
                        if !products.is_empty() && !products.iter().any(|p| p == product) {
                            continue;
                        }
                        let Some(price) = spot_price(itype.name, z, product, at) else { continue };
                        let item = t::SpotPrice {
                            availability_zone: Some(z.clone()),
                            availability_zone_id: Some(zid.clone()),
                            instance_type: Some(itype.name.into()),
                            product_description: Some(product.to_string()),
                            spot_price: Some(fmt_price(price)),
                            timestamp: Some(at),
                        };
                        let ok = filters.matches(None, |name| {
                            Some(match name {
                                "availability-zone" => s(&item.availability_zone),
                                "instance-type" => s(&item.instance_type),
                                "product-description" => s(&item.product_description),
                                "spot-price" => s(&item.spot_price),
                                "timestamp" => vec![at.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()],
                                _ => return None,
                            })
                        })?;
                        if ok {
                            out.push(item);
                        }
                    }
                }
            }
            at -= period;
        }
        let max = input.max_results.unwrap_or(1000).clamp(1, 1000);
        let (items, next_token) = paginate(out, Some(max), &input.next_token)?;
        Ok(t::DescribeSpotPriceHistoryResult {
            spot_price_history: Some(items),
            next_token: next_token.or(Some(String::new())),
        })
    }
}

/// The Spot requests a fleet's instances fulfil.
pub(crate) fn record_fleet_request(
    r: &mut RegionState,
    id: &str,
    fleet_id: &str,
    inst: &t::Instance,
    max: &str,
    now: DateTime<Utc>,
) {
    let request = t::SpotInstanceRequest {
        spot_instance_request_id: Some(id.into()),
        create_time: Some(now),
        instance_id: inst.instance_id.clone(),
        launch_specification: Some(t::LaunchSpecification {
            image_id: inst.image_id.clone(),
            instance_type: inst.instance_type.clone(),
            key_name: inst.key_name.clone(),
            subnet_id: inst.subnet_id.clone(),
            security_groups: inst.security_groups.clone(),
            placement: Some(t::SpotPlacement {
                availability_zone: inst.placement.as_ref().and_then(|p| p.availability_zone.clone()),
                tenancy: Some("default".into()),
                ..Default::default()
            }),
            monitoring: Some(t::RunInstancesMonitoringEnabled { enabled: false }),
            ..Default::default()
        }),
        launched_availability_zone: inst.placement.as_ref().and_then(|p| p.availability_zone.clone()),
        launched_availability_zone_id: inst.placement.as_ref().and_then(|p| p.availability_zone_id.clone()),
        product_description: Some(PRODUCT.into()),
        spot_price: Some(max.into()),
        state: Some("active".into()),
        status: status("fulfilled", "Your spot request is fulfilled.", now),
        r#type: Some("one-time".into()),
        instance_interruption_behavior: Some("terminate".into()),
        tags: Some(Vec::new()),
        ..Default::default()
    };
    r.spot_requests.insert(
        id.into(),
        SpotRequestRecord { request, launch: None, fleet_id: Some(fleet_id.into()), client_token: None },
    );
}
