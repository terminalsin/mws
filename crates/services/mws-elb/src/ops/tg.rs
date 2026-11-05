//! Target groups: create, describe, modify, delete and attributes.

use mws_core::{RequestContext, ServiceError};

use crate::names::{self, validation};
use crate::state::{RegionState, TargetGroupRecord};
use crate::v2::{errors, types as t};
use crate::{account_of, catalog, Elb};

pub(crate) fn tg_not_found() -> ServiceError {
    errors::target_group_not_found("One or more target groups not found")
}

pub(crate) fn find_tg<'a>(r: &'a RegionState, arn: &str) -> Result<&'a TargetGroupRecord, ServiceError> {
    r.target_groups.get(arn).ok_or_else(tg_not_found)
}

const TG_PROTOCOLS: &[&str] = &["HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP", "GENEVE", "QUIC", "TCP_QUIC"];

/// Load balancers whose listeners or rules forward to `tg_arn`.
pub(crate) fn load_balancers_of(r: &RegionState, tg_arn: &str) -> Vec<String> {
    let mut lbs: Vec<String> = Vec::new();
    let mut add = |listener_arn: &str| {
        if let Some(l) = r.listeners.get(listener_arn) {
            if !lbs.iter().any(|x| x == l.lb_arn()) {
                lbs.push(l.lb_arn().to_string());
            }
        }
    };
    for rule in r.rules.values() {
        let actions = rule.rule.actions.iter().flatten();
        if super::forwarded_target_groups(actions).iter().any(|a| a == tg_arn) {
            add(&rule.listener_arn);
        }
    }
    lbs
}

pub(crate) fn describe_tg(r: &RegionState, tg: &TargetGroupRecord) -> t::TargetGroup {
    let mut out = tg.tg.clone();
    out.load_balancer_arns = Some(load_balancers_of(r, tg.arn()));
    out
}

fn check_health_settings(
    protocol: Option<&str>,
    hc_protocol: Option<&str>,
    interval: Option<i32>,
    timeout: Option<i32>,
    path: Option<&str>,
    matcher: Option<&t::Matcher>,
) -> Result<(), ServiceError> {
    if let (Some(i), Some(to)) = (interval, timeout) {
        if to >= i {
            return Err(validation("Health check timeout must be smaller than the interval"));
        }
    }
    if let Some(p) = path {
        if !p.starts_with('/') {
            return Err(validation("Health check path must begin with a '/' character"));
        }
        if hc_protocol.is_some_and(|h| matches!(h, "TCP" | "UDP")) {
            return Err(validation("Health check path cannot be specified for TCP health checks"));
        }
    }
    if let Some(m) = matcher {
        if let Some(code) = &m.http_code {
            let valid = code.split(',').all(|part| {
                let mut it = part.split('-');
                let ok = |s: Option<&str>| {
                    s.and_then(|s| s.trim().parse::<u16>().ok()).is_some_and(|n| (200..600).contains(&n))
                };
                match (it.next(), it.next(), it.next()) {
                    (a, None, None) => ok(a),
                    (a, b, None) => ok(a) && ok(b),
                    _ => false,
                }
            });
            if !valid {
                return Err(validation(format!("Health check matcher HTTP code '{code}' must be within '200-499'")));
            }
        }
    }
    if let (Some(p), Some(h)) = (protocol, hc_protocol) {
        let l4 = matches!(p, "TCP" | "TLS" | "UDP" | "TCP_UDP" | "GENEVE");
        if !l4 && matches!(h, "TCP") {
            return Err(validation(format!(
                "Health check protocol '{h}' is not supported for target groups with the '{p}' protocol"
            )));
        }
        if !matches!(h, "HTTP" | "HTTPS" | "TCP") {
            return Err(validation(format!("Health check protocol '{h}' is not valid")));
        }
    }
    Ok(())
}

impl Elb {
    pub(crate) fn create_target_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTargetGroupInput,
    ) -> Result<t::CreateTargetGroupOutput, ServiceError> {
        names::check_name("Target group", &input.name)?;
        let tags = input.tags.clone().unwrap_or_default();
        names::check_tags(&tags)?;
        let target_type = input.target_type.clone().unwrap_or_else(|| "instance".into());
        if !matches!(target_type.as_str(), "instance" | "ip" | "lambda" | "alb") {
            return Err(validation(format!("Target type '{target_type}' is not valid")));
        }
        let account = account_of(ctx);
        let lambda = target_type == "lambda";
        if lambda {
            if input.protocol.is_some() || input.port.is_some() || input.vpc_id.is_some() {
                return Err(validation(
                    "Protocol, port and VPC ID cannot be specified for target groups with target type 'lambda'",
                ));
            }
        } else {
            let protocol = input.protocol.as_deref().ok_or_else(|| {
                validation("A protocol must be specified for target groups with target type other than 'lambda'")
            })?;
            if !TG_PROTOCOLS.contains(&protocol) {
                return Err(validation(format!("Protocol '{protocol}' is not valid")));
            }
            if input.port.is_none() {
                return Err(validation(
                    "A port must be specified for target groups with target type other than 'lambda'",
                ));
            }
            let vpc = input.vpc_id.as_deref().ok_or_else(|| {
                validation("A VPC ID must be specified for target groups with target type other than 'lambda'")
            })?;
            if let Some(ec2) = self.ec2() {
                if ec2.vpc_info(ctx, &account, Some(vpc)).is_none() {
                    return Err(validation(format!("The VPC ID '{vpc}' is not found")));
                }
            }
            if target_type == "alb" && protocol != "TCP" {
                return Err(validation("Target groups with target type 'alb' must use the 'TCP' protocol"));
            }
            if protocol == "GENEVE" && input.port != Some(6081) {
                return Err(validation("Target groups with the 'GENEVE' protocol must use port 6081"));
            }
        }
        let protocol = input.protocol.clone().unwrap_or_default();
        let version = match (&input.protocol_version, protocol.as_str()) {
            (Some(v), "HTTP" | "HTTPS") => {
                if !matches!(v.as_str(), "HTTP1" | "HTTP2" | "GRPC") {
                    return Err(validation(format!("Protocol version '{v}' is not valid")));
                }
                Some(v.clone())
            }
            (Some(_), _) => {
                return Err(validation("A protocol version can only be specified for HTTP and HTTPS target groups"))
            }
            (None, "HTTP" | "HTTPS") => Some("HTTP1".to_string()),
            (None, _) => None,
        };
        let hc_protocol_in = input.health_check_protocol.clone();
        let d = catalog::health_defaults(
            &protocol,
            version.as_deref().unwrap_or(""),
            &target_type,
            hc_protocol_in.as_deref().unwrap_or(""),
        );
        let enabled = input.health_check_enabled.unwrap_or(d.enabled);
        let hc_protocol = hc_protocol_in.clone().or(d.protocol.map(str::to_string));
        let http_hc = lambda || matches!(hc_protocol.as_deref(), Some("HTTP" | "HTTPS"));
        check_health_settings(
            input.protocol.as_deref(),
            hc_protocol.as_deref(),
            Some(input.health_check_interval_seconds.unwrap_or(d.interval)),
            Some(input.health_check_timeout_seconds.unwrap_or(d.timeout)),
            input.health_check_path.as_deref(),
            input.matcher.as_ref(),
        )?;
        let matcher = if http_hc {
            Some(input.matcher.clone().unwrap_or(t::Matcher {
                http_code: d.http_code.map(str::to_string),
                grpc_code: d.grpc_code.map(str::to_string),
            }))
        } else {
            None
        };
        let id = names::hex_id(16);
        let arn = names::arn(ctx, &account, &format!("targetgroup/{}/{id}", input.name));
        self.authorize_create(ctx, "CreateTargetGroup", &arn, &tags)?;
        let ip_type = (matches!(target_type.as_str(), "ip" | "instance"))
            .then(|| input.ip_address_type.clone().unwrap_or_else(|| "ipv4".into()));
        let tg = t::TargetGroup {
            target_group_arn: Some(arn.clone()),
            target_group_name: Some(input.name.clone()),
            protocol: input.protocol.clone(),
            port: input.port,
            vpc_id: input.vpc_id.clone(),
            health_check_protocol: if lambda { None } else { hc_protocol.clone() },
            health_check_port: if lambda {
                None
            } else {
                // GENEVE target groups check port 80 unless told otherwise.
                let default = if input.protocol.as_deref() == Some("GENEVE") { "80" } else { "traffic-port" };
                Some(input.health_check_port.clone().unwrap_or_else(|| default.into()))
            },
            health_check_enabled: Some(enabled),
            health_check_interval_seconds: Some(input.health_check_interval_seconds.unwrap_or(d.interval)),
            health_check_timeout_seconds: Some(input.health_check_timeout_seconds.unwrap_or(d.timeout)),
            healthy_threshold_count: Some(input.healthy_threshold_count.unwrap_or(d.healthy)),
            unhealthy_threshold_count: Some(input.unhealthy_threshold_count.unwrap_or(d.unhealthy)),
            health_check_path: if http_hc {
                input.health_check_path.clone().or(d.path.map(str::to_string))
            } else {
                None
            },
            matcher,
            load_balancer_arns: Some(Vec::new()),
            target_type: Some(target_type.clone()),
            protocol_version: version,
            ip_address_type: ip_type,
            target_control_port: input.target_control_port,
        };
        let out = self.with_region(ctx, |r| {
            if let Some(existing) = r.target_groups.values().find(|g| g.name() == input.name) {
                let e = &existing.tg;
                let same = e.protocol == tg.protocol
                    && e.port == tg.port
                    && e.vpc_id == tg.vpc_id
                    && e.target_type == tg.target_type
                    && e.health_check_protocol == tg.health_check_protocol
                    && e.health_check_path == tg.health_check_path
                    && e.health_check_interval_seconds == tg.health_check_interval_seconds
                    && e.matcher == tg.matcher;
                if same {
                    return Ok(describe_tg(r, existing));
                }
                return Err(errors::duplicate_target_group_name(format!(
                    "A target group with the same name '{}' exists, but with different settings",
                    input.name
                )));
            }
            if r.target_groups.len() >= catalog::limit("target-groups") {
                return Err(errors::too_many_target_groups(
                    "You have reached the maximum number of target groups for your account",
                ));
            }
            r.target_groups.insert(
                arn.clone(),
                TargetGroupRecord {
                    tg: tg.clone(),
                    attributes: catalog::target_group_attributes(&protocol, &target_type),
                    targets: Vec::new(),
                },
            );
            if !tags.is_empty() {
                r.tags.insert(arn.clone(), tags.clone());
            }
            Ok(tg.clone())
        })?;
        Ok(t::CreateTargetGroupOutput { target_groups: Some(vec![out]) })
    }

    pub(crate) fn describe_target_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTargetGroupsInput,
    ) -> Result<t::DescribeTargetGroupsOutput, ServiceError> {
        names::authorize(ctx, "DescribeTargetGroups", "*", Default::default())?;
        let arns = input.target_group_arns.unwrap_or_default();
        let wanted = input.names.unwrap_or_default();
        let given = [input.load_balancer_arn.is_some(), !arns.is_empty(), !wanted.is_empty()];
        if given.iter().filter(|g| **g).count() > 1 {
            return Err(validation(
                "Target group names, target group ARNs, and a load balancer ARN cannot be specified at the same time",
            ));
        }
        let all =
            self.with_region(ctx, |r| -> Result<Vec<t::TargetGroup>, ServiceError> {
                if let Some(lb) = &input.load_balancer_arn {
                    super::lb::find_lb(r, lb)?;
                    return Ok(r
                        .target_groups
                        .values()
                        .filter(|g| load_balancers_of(r, g.arn()).iter().any(|l| l == lb))
                        .map(|g| describe_tg(r, g))
                        .collect());
                }
                if !arns.is_empty() {
                    return arns.iter().map(|a| find_tg(r, a).map(|g| describe_tg(r, g))).collect();
                }
                if !wanted.is_empty() {
                    return wanted
                        .iter()
                        .map(|n| {
                            r.target_groups.values().find(|g| g.name() == n).map(|g| describe_tg(r, g)).ok_or_else(
                                || errors::target_group_not_found(format!("Target groups '[{n}]' not found")),
                            )
                        })
                        .collect();
                }
                let mut v: Vec<_> = r.target_groups.values().map(|g| describe_tg(r, g)).collect();
                v.sort_by(|a, b| a.target_group_name.cmp(&b.target_group_name));
                Ok(v)
            })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(t::DescribeTargetGroupsOutput { target_groups: Some(items), next_marker: next })
    }

    pub(crate) fn modify_target_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyTargetGroupInput,
    ) -> Result<t::ModifyTargetGroupOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyTargetGroup", &input.target_group_arn)?;
        let out = self.with_region(ctx, |r| {
            let current = find_tg(r, &input.target_group_arn)?.tg.clone();
            let mut tg = current.clone();
            let lambda = current.target_type.as_deref() == Some("lambda");
            if let Some(p) = &input.health_check_protocol {
                if lambda {
                    return Err(validation(
                        "Health check protocol cannot be specified for target groups with target type 'lambda'",
                    ));
                }
                tg.health_check_protocol = Some(p.clone());
            }
            if let Some(p) = &input.health_check_port {
                if lambda {
                    return Err(validation(
                        "Health check port cannot be specified for target groups with target type 'lambda'",
                    ));
                }
                if p != "traffic-port" && p.parse::<u16>().is_err() {
                    return Err(validation(format!("Health check port '{p}' is not valid")));
                }
                tg.health_check_port = Some(p.clone());
            }
            if let Some(p) = &input.health_check_path {
                tg.health_check_path = Some(p.clone());
            }
            if let Some(e) = input.health_check_enabled {
                tg.health_check_enabled = Some(e);
            }
            if let Some(i) = input.health_check_interval_seconds {
                tg.health_check_interval_seconds = Some(i);
            }
            if let Some(i) = input.health_check_timeout_seconds {
                tg.health_check_timeout_seconds = Some(i);
            }
            if let Some(i) = input.healthy_threshold_count {
                tg.healthy_threshold_count = Some(i);
            }
            if let Some(i) = input.unhealthy_threshold_count {
                tg.unhealthy_threshold_count = Some(i);
            }
            if let Some(m) = &input.matcher {
                tg.matcher = Some(m.clone());
            }
            let http_hc = lambda || matches!(tg.health_check_protocol.as_deref(), Some("HTTP" | "HTTPS"));
            if http_hc {
                if tg.health_check_path.is_none() {
                    tg.health_check_path = Some("/".into());
                }
                if tg.matcher.is_none() {
                    tg.matcher = Some(t::Matcher { http_code: Some("200-399".into()), grpc_code: None });
                }
            } else {
                tg.health_check_path = None;
                tg.matcher = None;
            }
            check_health_settings(
                tg.protocol.as_deref(),
                tg.health_check_protocol.as_deref(),
                tg.health_check_interval_seconds,
                tg.health_check_timeout_seconds,
                input.health_check_path.as_deref(),
                input.matcher.as_ref(),
            )?;
            let rec = r.target_groups.get_mut(&input.target_group_arn).ok_or_else(tg_not_found)?;
            rec.tg = tg;
            let rec = r.target_groups.get(&input.target_group_arn).ok_or_else(tg_not_found)?;
            Ok(describe_tg(r, rec))
        })?;
        self.inner.health.config_changed(&input.target_group_arn);
        Ok(t::ModifyTargetGroupOutput { target_groups: Some(vec![out]) })
    }

    pub(crate) fn delete_target_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTargetGroupInput,
    ) -> Result<t::DeleteTargetGroupOutput, ServiceError> {
        self.authorize_on(ctx, "DeleteTargetGroup", &input.target_group_arn)?;
        self.with_region(ctx, |r| {
            if !r.target_groups.contains_key(&input.target_group_arn) {
                return Ok(());
            }
            if !load_balancers_of(r, &input.target_group_arn).is_empty() {
                return Err(errors::resource_in_use(format!(
                    "Target group '{}' is currently in use by a listener or a rule",
                    input.target_group_arn
                )));
            }
            r.target_groups.remove(&input.target_group_arn);
            r.tags.remove(&input.target_group_arn);
            Ok(())
        })?;
        self.inner.health.forget_group(&input.target_group_arn);
        Ok(t::DeleteTargetGroupOutput {})
    }

    pub(crate) fn describe_target_group_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTargetGroupAttributesInput,
    ) -> Result<t::DescribeTargetGroupAttributesOutput, ServiceError> {
        names::authorize(ctx, "DescribeTargetGroupAttributes", "*", Default::default())?;
        self.with_region(ctx, |r| {
            let tg = find_tg(r, &input.target_group_arn)?;
            Ok(t::DescribeTargetGroupAttributesOutput { attributes: Some(tg_attributes(tg)) })
        })
    }

    pub(crate) fn modify_target_group_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyTargetGroupAttributesInput,
    ) -> Result<t::ModifyTargetGroupAttributesOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyTargetGroupAttributes", &input.target_group_arn)?;
        let out = self.with_region(ctx, |r| {
            let tg = r.target_groups.get_mut(&input.target_group_arn).ok_or_else(tg_not_found)?;
            let mut next = tg.attributes.clone();
            for a in &input.attributes {
                let key = a.key.clone().unwrap_or_default();
                let value = a.value.clone().unwrap_or_default();
                if !tg.attributes.contains_key(&key) {
                    return Err(validation(format!("Target group attribute key '{key}' is not recognized")));
                }
                catalog::check_tg_attribute(&key, &value).map_err(validation)?;
                next.insert(key, value);
            }
            if next.get("stickiness.type").map(String::as_str) == Some("app_cookie")
                && next.get("stickiness.enabled").map(String::as_str) == Some("true")
                && next.get("stickiness.app_cookie.cookie_name").is_none_or(String::is_empty)
            {
                return Err(validation("The app cookie name must be specified for application-based stickiness"));
            }
            if next.get("load_balancing.algorithm.anomaly_mitigation").map(String::as_str) == Some("on")
                && next.get("load_balancing.algorithm.type").map(String::as_str) != Some("weighted_random")
            {
                return Err(errors::invalid_configuration_request(
                    "Anomaly mitigation is only supported with the weighted_random load balancing algorithm",
                ));
            }
            tg.attributes = next;
            Ok(tg_attributes(tg))
        })?;
        Ok(t::ModifyTargetGroupAttributesOutput { attributes: Some(out) })
    }
}

pub(crate) fn tg_attributes(tg: &TargetGroupRecord) -> Vec<t::TargetGroupAttribute> {
    tg.attributes
        .iter()
        .map(|(k, v)| t::TargetGroupAttribute { key: Some(k.clone()), value: Some(v.clone()) })
        .collect()
}
