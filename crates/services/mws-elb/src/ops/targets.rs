//! Registering targets and reporting their health.

use mws_core::{RequestContext, ServiceError};

use crate::health::{self, HealthKey};
use crate::names::{self, validation};
use crate::state::RegisteredTarget;
use crate::v2::{errors, types as t};
use crate::{account_of, Elb};

fn is_ipv4_private(ip: &std::net::Ipv4Addr) -> bool {
    ip.is_private() || names::ipv4_in_cidr(&ip.to_string(), "100.64.0.0/10")
}

impl Elb {
    pub(crate) fn register_targets_op(
        &self,
        ctx: &RequestContext,
        input: t::RegisterTargetsInput,
    ) -> Result<t::RegisterTargetsOutput, ServiceError> {
        self.authorize_on(ctx, "RegisterTargets", &input.target_group_arn)?;
        let account = account_of(ctx);
        let tg = self.with_region(ctx, |r| super::tg::find_tg(r, &input.target_group_arn).cloned())?;
        let ty = tg.target_type().to_string();
        if input.targets.is_empty() {
            return Err(validation("At least one target must be specified"));
        }
        let mut resolved = Vec::new();
        for target in &input.targets {
            let port = match (&ty[..], target.port.or(tg.tg.port)) {
                ("lambda", _) => 0,
                (_, Some(p)) if (1..=65535).contains(&p) => p,
                (_, _) => return Err(validation("A port must be specified for the target")),
            };
            let mut az = target.availability_zone.clone();
            match ty.as_str() {
                "instance" => {
                    if !target.id.starts_with("i-") {
                        return Err(errors::invalid_target(format!(
                            "The following targets are not valid instances: '{}'",
                            target.id
                        )));
                    }
                    if let Some(ec2) = self.ec2() {
                        let info = ec2.instance_info(&account, &ctx.region, &target.id).ok_or_else(|| {
                            errors::invalid_target(format!(
                                "The following targets are not valid instances: '{}'",
                                target.id
                            ))
                        })?;
                        if !matches!(info.state.as_str(), "running" | "pending" | "stopped" | "stopping") {
                            return Err(errors::invalid_target(format!(
                                "The following targets are not in a running state and cannot be registered: '{}'",
                                target.id
                            )));
                        }
                        if info.vpc_id.is_some() && info.vpc_id != tg.tg.vpc_id {
                            return Err(errors::invalid_target(format!(
                                "The following targets are not in the target group VPC '{}': '{}'",
                                tg.tg.vpc_id.clone().unwrap_or_default(),
                                target.id
                            )));
                        }
                        if az.is_some() {
                            return Err(validation("An Availability Zone cannot be specified for instance targets"));
                        }
                        az = info.availability_zone;
                    }
                }
                "ip" => {
                    let ip: std::net::IpAddr = target.id.parse().map_err(|_| {
                        errors::invalid_target(format!("The IP address '{}' is not a valid IPv4 address", target.id))
                    })?;
                    // MWS also accepts loopback addresses, so processes on
                    // this machine can sit behind a load balancer.
                    let loopback = ip.is_loopback();
                    let outside_ok = az.as_deref() == Some("all");
                    let in_vpc = match (&ip, self.ec2(), tg.tg.vpc_id.as_deref()) {
                        (std::net::IpAddr::V4(v4), Some(ec2), Some(vpc)) => ec2
                            .vpc_info(ctx, &account, Some(vpc))
                            .is_some_and(|v| v.cidr_blocks.iter().any(|c| names::ipv4_in_cidr(&v4.to_string(), c))),
                        (std::net::IpAddr::V6(v6), Some(ec2), Some(vpc)) => {
                            ec2.vpc_info(ctx, &account, Some(vpc)).is_some_and(|v| {
                                v.ipv6_cidr_blocks.iter().any(|c| names::ipv6_in_cidr(&v6.to_string(), c))
                            })
                        }
                        (_, None, _) => true,
                        _ => false,
                    };
                    let allowed = loopback
                        || in_vpc
                        || (outside_ok && matches!(ip, std::net::IpAddr::V4(v4) if is_ipv4_private(&v4)));
                    if !allowed {
                        return Err(errors::invalid_target(format!(
                            "The IP address '{}' is not within the CIDR of the target group VPC '{}'",
                            target.id,
                            tg.tg.vpc_id.clone().unwrap_or_default()
                        )));
                    }
                    if ip.is_ipv4() != (tg.tg.ip_address_type.as_deref() != Some("ipv6")) {
                        return Err(errors::invalid_target(format!(
                            "The IP address '{}' does not match the target group IP address type",
                            target.id
                        )));
                    }
                }
                "lambda" => {
                    if input.targets.len() > 1 || !tg.targets.is_empty() && tg.targets.iter().any(|x| x.id != target.id)
                    {
                        return Err(errors::too_many_targets(
                            "You can register only one Lambda function per target group",
                        ));
                    }
                    if target.port.is_some() {
                        return Err(validation("A port cannot be specified for Lambda targets"));
                    }
                    let lambda = self.lambda().ok_or_else(|| errors::invalid_target("Lambda is not available"))?;
                    let inv = mws_lambda::ServiceInvocation {
                        function: &target.id,
                        service_principal: "elasticloadbalancing.amazonaws.com",
                        source_account: Some(&account),
                        source_arn: Some(&input.target_group_arn),
                        payload: Vec::new(),
                    };
                    match lambda.check_service_invoke(ctx, &inv) {
                        Ok(_) => {}
                        Err(mws_lambda::ServiceInvokeError::NotFound) => {
                            return Err(errors::invalid_target(format!("The function '{}' was not found", target.id)))
                        }
                        Err(_) => {
                            return Err(ServiceError::client(
                                "AccessDenied",
                                400,
                                format!(
                                    "elasticloadbalancing principal does not have permission to invoke {} from target group {}",
                                    target.id, input.target_group_arn
                                ),
                            ))
                        }
                    }
                }
                "alb" => {
                    let alb_port = tg.tg.port.unwrap_or_default();
                    let ok = self.with_region(ctx, |r| {
                        r.load_balancers.get(&target.id).is_some_and(|l| l.ty() == "application")
                            && r.listeners
                                .values()
                                .any(|l| l.lb_arn() == target.id && l.listener.port == Some(alb_port))
                    });
                    if !ok {
                        return Err(errors::invalid_target(format!(
                            "The target '{}' must be an Application Load Balancer with a listener on port {alb_port}",
                            target.id
                        )));
                    }
                    if !tg.targets.is_empty() && tg.targets.iter().any(|x| x.id != target.id) {
                        return Err(errors::too_many_targets(
                            "You can register only one Application Load Balancer per target group",
                        ));
                    }
                }
                _ => {}
            }
            resolved.push(RegisteredTarget {
                id: target.id.clone(),
                port,
                availability_zone: az,
                registered_at: Some(ctx.received_at),
                draining_until: None,
            });
        }
        self.with_region(ctx, |r| {
            let tg = r.target_groups.get_mut(&input.target_group_arn).ok_or_else(super::tg::tg_not_found)?;
            for target in resolved {
                if let Some(existing) = tg.targets.iter_mut().find(|x| x.id == target.id && x.port == target.port) {
                    // Registering a draining target again cancels the drain.
                    existing.draining_until = None;
                    continue;
                }
                if tg.targets.len() >= 1000 {
                    return Err(errors::too_many_targets(
                        "You have reached the maximum number of targets for this target group",
                    ));
                }
                self.inner.health.forget(&HealthKey::v2(&input.target_group_arn, &target.id, target.port));
                tg.targets.push(target);
            }
            Ok(())
        })?;
        self.reconcile();
        Ok(t::RegisterTargetsOutput {})
    }

    pub(crate) fn deregister_targets_op(
        &self,
        ctx: &RequestContext,
        input: t::DeregisterTargetsInput,
    ) -> Result<t::DeregisterTargetsOutput, ServiceError> {
        self.authorize_on(ctx, "DeregisterTargets", &input.target_group_arn)?;
        self.with_region(ctx, |r| {
            let in_use = !super::tg::load_balancers_of(r, &input.target_group_arn).is_empty();
            let tg = r.target_groups.get_mut(&input.target_group_arn).ok_or_else(super::tg::tg_not_found)?;
            let delay: i64 =
                tg.attr("deregistration_delay.timeout_seconds").and_then(|v| v.parse().ok()).unwrap_or(300);
            let default_port = tg.tg.port.unwrap_or_default();
            for target in &input.targets {
                let port = if tg.target_type() == "lambda" { 0 } else { target.port.unwrap_or(default_port) };
                let found = tg.targets.iter().position(|x| x.id == target.id && x.port == port);
                let Some(i) = found else {
                    if tg.target_type() == "instance" && !target.id.starts_with("i-") {
                        return Err(errors::invalid_target(format!(
                            "The following targets are not valid instances: '{}'",
                            target.id
                        )));
                    }
                    continue;
                };
                if in_use && delay > 0 && tg.target_type() != "lambda" {
                    let until = ctx.received_at + chrono::Duration::seconds(delay);
                    tg.targets[i].draining_until.get_or_insert(until);
                } else {
                    let removed = tg.targets.remove(i);
                    self.inner.health.forget(&HealthKey::v2(&input.target_group_arn, &removed.id, removed.port));
                }
            }
            Ok(t::DeregisterTargetsOutput {})
        })
    }

    pub(crate) fn describe_target_health_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTargetHealthInput,
    ) -> Result<t::DescribeTargetHealthOutput, ServiceError> {
        names::authorize(ctx, "DescribeTargetHealth", "*", Default::default())?;
        let account = account_of(ctx);
        health::sweep_draining(self, ctx.received_at);
        let anomaly = input.include.iter().flatten().any(|i| matches!(i.as_str(), "AnomalyDetection" | "All"));
        let descriptions = self.with_region(ctx, |r| {
            let tg = super::tg::find_tg(r, &input.target_group_arn)?;
            let hc_port = tg.tg.health_check_port.clone();
            let wanted: Vec<RegisteredTarget> = match &input.targets {
                Some(ts) if !ts.is_empty() => ts
                    .iter()
                    .map(|x| {
                        let port =
                            if tg.target_type() == "lambda" { 0 } else { x.port.or(tg.tg.port).unwrap_or_default() };
                        tg.targets.iter().find(|y| y.id == x.id && y.port == port).cloned().unwrap_or(
                            RegisteredTarget {
                                id: x.id.clone(),
                                port,
                                availability_zone: x.availability_zone.clone(),
                                registered_at: None,
                                draining_until: None,
                            },
                        )
                    })
                    .collect(),
                _ => tg.targets.clone(),
            };
            let mut out = Vec::new();
            for target in wanted {
                let registered = target.registered_at.is_some();
                let status = if registered {
                    health::classify(self, r, &account, &ctx.region, tg, &target)
                } else {
                    health::Status::unused("Target.NotRegistered", "Target is not registered to the target group")
                };
                let port_shown = match hc_port.as_deref() {
                    Some("traffic-port") | None => (target.port != 0).then(|| target.port.to_string()),
                    Some(p) => Some(p.to_string()),
                };
                out.push(t::TargetHealthDescription {
                    target: Some(t::TargetDescription {
                        id: target.id.clone(),
                        port: (tg.target_type() != "lambda").then_some(target.port),
                        availability_zone: if tg.target_type() == "ip" || tg.target_type() == "alb" {
                            target.availability_zone.clone()
                        } else {
                            None
                        },
                        quic_server_id: None,
                    }),
                    health_check_port: if tg.target_type() == "lambda" { None } else { port_shown },
                    target_health: Some(status.wire()),
                    anomaly_detection: (anomaly && tg.target_type() != "lambda").then(|| t::AnomalyDetection {
                        result: Some("normal".into()),
                        mitigation_in_effect: Some("no".into()),
                    }),
                    administrative_override: Some(t::AdministrativeOverride {
                        state: Some("no_override".into()),
                        reason: Some("AdministrativeOverride.NoOverride".into()),
                        description: Some("No override is currently active on target".into()),
                    }),
                });
            }
            Ok::<_, ServiceError>(out)
        })?;
        Ok(t::DescribeTargetHealthOutput { target_health_descriptions: Some(descriptions) })
    }
}
