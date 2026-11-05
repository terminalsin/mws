//! Listener and rule actions: validation and the normalized form ELB
//! describes them in.

use mws_core::ServiceError;

use crate::names::validation;
use crate::state::RegionState;
use crate::v2::{errors, types as t};

/// Every target group the actions forward to.
pub(crate) fn forwarded_target_groups<'a>(actions: impl IntoIterator<Item = &'a t::Action>) -> Vec<String> {
    let mut out = Vec::new();
    for a in actions {
        if a.r#type != "forward" {
            continue;
        }
        if let Some(arn) = &a.target_group_arn {
            out.push(arn.clone());
        }
        for g in a.forward_config.iter().flat_map(|f| f.target_groups.iter().flatten()) {
            if let Some(arn) = &g.target_group_arn {
                if !out.contains(arn) {
                    out.push(arn.clone());
                }
            }
        }
    }
    out
}

/// Check `actions` for a listener of `protocol` on load balancer `lb_arn`
/// (of type `lb_type`) and return them as ELB stores them.
pub(crate) fn normalize(
    r: &RegionState,
    lb_arn: &str,
    lb_type: &str,
    protocol: &str,
    actions: &[t::Action],
) -> Result<Vec<t::Action>, ServiceError> {
    if actions.is_empty() {
        return Err(validation("At least one action must be specified"));
    }
    let terminal = ["forward", "redirect", "fixed-response"];
    let mut out = Vec::new();
    let mut sorted: Vec<t::Action> = actions.to_vec();
    if sorted.iter().any(|a| a.order.is_some()) {
        if sorted.iter().any(|a| a.order.is_none()) {
            return Err(validation("Either all actions or none must specify an order"));
        }
        sorted.sort_by_key(|a| a.order);
        let mut orders: Vec<i32> = sorted.iter().filter_map(|a| a.order).collect();
        orders.dedup();
        if orders.len() != sorted.len() {
            return Err(validation("Action orders must be unique"));
        }
    }
    let terminals = sorted.iter().filter(|a| terminal.contains(&a.r#type.as_str())).count();
    if terminals != 1 || !terminal.contains(&sorted.last().map(|a| a.r#type.as_str()).unwrap_or("")) {
        return Err(errors::invalid_load_balancer_action(
            "Exactly one terminal action (forward, redirect or fixed-response) must be specified, and it must be last",
        ));
    }
    let vpc = r.load_balancers.get(lb_arn).and_then(|l| l.lb.vpc_id.clone());
    for a in sorted {
        let ty = a.r#type.as_str();
        match (lb_type, ty) {
            (
                "application",
                "forward"
                | "redirect"
                | "fixed-response"
                | "authenticate-oidc"
                | "authenticate-cognito"
                | "jwt-validation",
            ) => {}
            ("network" | "gateway", "forward") => {}
            (
                _,
                "forward"
                | "redirect"
                | "fixed-response"
                | "authenticate-oidc"
                | "authenticate-cognito"
                | "jwt-validation",
            ) => {
                return Err(errors::invalid_load_balancer_action(format!(
                    "The action type '{ty}' is not valid with a '{}' listener",
                    if protocol.is_empty() { "GENEVE" } else { protocol }
                )))
            }
            _ => return Err(validation(format!("Action type '{ty}' is not valid"))),
        }
        if matches!(ty, "authenticate-oidc" | "authenticate-cognito") && protocol != "HTTPS" {
            return Err(errors::invalid_load_balancer_action(format!(
                "The action type '{ty}' is only supported on HTTPS listeners"
            )));
        }
        let mut a = a.clone();
        match ty {
            "forward" => {
                let mut groups: Vec<t::TargetGroupTuple> =
                    a.forward_config.as_ref().and_then(|f| f.target_groups.clone()).unwrap_or_default();
                if let Some(arn) = &a.target_group_arn {
                    if groups.is_empty() {
                        groups.push(t::TargetGroupTuple { target_group_arn: Some(arn.clone()), weight: Some(1) });
                    } else if groups.len() != 1 || groups[0].target_group_arn.as_deref() != Some(arn) {
                        return Err(validation(
                            "You cannot specify both a target group ARN and a forward config with different target groups",
                        ));
                    }
                }
                if groups.is_empty() {
                    return Err(validation("A target group ARN must be specified for a forward action"));
                }
                let max = if lb_type == "application" { 5 } else { 1 };
                if groups.len() > max {
                    return Err(errors::too_many_target_groups(format!(
                        "You can specify at most {max} target groups in a forward action"
                    )));
                }
                for g in &mut groups {
                    let arn = g.target_group_arn.clone().unwrap_or_default();
                    let tg = r.target_groups.get(&arn).ok_or_else(super::tg::tg_not_found)?;
                    if g.weight.is_none() {
                        g.weight = Some(1);
                    }
                    if g.weight.is_some_and(|w| !(0..=999).contains(&w)) {
                        return Err(validation("Target group weights must be between 0 and 999"));
                    }
                    let tg_proto = tg.protocol();
                    let compatible = match (lb_type, protocol) {
                        ("application", _) => tg.target_type() == "lambda" || matches!(tg_proto, "HTTP" | "HTTPS"),
                        ("network", "TCP") => matches!(tg_proto, "TCP" | "TCP_UDP"),
                        ("network", "TLS") => matches!(tg_proto, "TCP" | "TLS"),
                        ("network", "UDP") => matches!(tg_proto, "UDP" | "TCP_UDP"),
                        ("network", "TCP_UDP") => tg_proto == "TCP_UDP",
                        ("network", "QUIC") => tg_proto == "QUIC",
                        ("network", "TCP_QUIC") => tg_proto == "TCP_QUIC",
                        ("gateway", _) => tg_proto == "GENEVE",
                        _ => false,
                    };
                    if !compatible {
                        return Err(errors::incompatible_protocols(format!(
                            "The protocol of target group '{arn}' ({}) is not compatible with the listener protocol",
                            if tg_proto.is_empty() { "lambda" } else { tg_proto }
                        )));
                    }
                    if lb_type == "application" && tg.target_type() == "alb" {
                        return Err(errors::invalid_configuration_request(
                            "Target groups of type 'alb' can only be used with Network Load Balancers",
                        ));
                    }
                    if tg.target_type() != "lambda" && tg.tg.vpc_id.is_some() && vpc.is_some() && tg.tg.vpc_id != vpc {
                        return Err(errors::invalid_configuration_request(format!(
                            "The target group '{arn}' must be in the load balancer's VPC"
                        )));
                    }
                    let elsewhere: Vec<String> =
                        super::tg::load_balancers_of(r, &arn).into_iter().filter(|l| l != lb_arn).collect();
                    if !elsewhere.is_empty() {
                        return Err(errors::target_group_association_limit(format!(
                            "The following target groups cannot be associated with more than one load balancer: {arn}"
                        )));
                    }
                }
                let stickiness = a
                    .forward_config
                    .as_ref()
                    .and_then(|f| f.target_group_stickiness_config.clone())
                    .unwrap_or(t::TargetGroupStickinessConfig { enabled: Some(false), duration_seconds: None });
                if stickiness.enabled == Some(true) {
                    let d = stickiness.duration_seconds.ok_or_else(|| {
                        validation("A duration must be specified when target group stickiness is enabled")
                    })?;
                    if !(1..=604_800).contains(&d) {
                        return Err(validation(
                            "Target group stickiness duration must be between 1 and 604800 seconds",
                        ));
                    }
                }
                a.target_group_arn = (groups.len() == 1).then(|| groups[0].target_group_arn.clone()).flatten();
                a.forward_config = Some(t::ForwardActionConfig {
                    target_groups: Some(groups),
                    target_group_stickiness_config: Some(stickiness),
                });
            }
            "redirect" => {
                let mut c = a
                    .redirect_config
                    .clone()
                    .ok_or_else(|| validation("A redirect config must be specified for a redirect action"))?;
                if !matches!(c.status_code.as_str(), "HTTP_301" | "HTTP_302") {
                    return Err(validation(format!("Redirect status code '{}' is not valid", c.status_code)));
                }
                if let Some(p) = &c.protocol {
                    if !matches!(p.as_str(), "HTTP" | "HTTPS" | "#{protocol}") {
                        return Err(validation(format!("Redirect protocol '{p}' is not valid")));
                    }
                }
                if let Some(p) = &c.path {
                    if !p.starts_with('/') {
                        return Err(validation("The redirect path must start with a '/'"));
                    }
                }
                let unchanged = c.protocol.as_deref().is_none_or(|p| p == "#{protocol}")
                    && c.port.as_deref().is_none_or(|p| p == "#{port}")
                    && c.host.as_deref().is_none_or(|h| h == "#{host}")
                    && c.path.as_deref().is_none_or(|p| p == "/#{path}")
                    && c.query.as_deref().is_none_or(|q| q == "#{query}");
                if unchanged {
                    return Err(errors::invalid_load_balancer_action(
                        "The redirect must change at least one of protocol, port, host, path or query, to avoid a redirect loop",
                    ));
                }
                c.protocol.get_or_insert_with(|| "#{protocol}".into());
                c.port.get_or_insert_with(|| "#{port}".into());
                c.host.get_or_insert_with(|| "#{host}".into());
                c.path.get_or_insert_with(|| "/#{path}".into());
                c.query.get_or_insert_with(|| "#{query}".into());
                a.redirect_config = Some(c);
            }
            "fixed-response" => {
                let c = a.fixed_response_config.clone().ok_or_else(|| {
                    validation("A fixed response config must be specified for a fixed-response action")
                })?;
                let code: u16 = c.status_code.parse().unwrap_or(0);
                if !(200..600).contains(&code) {
                    return Err(validation(format!("Fixed response status code '{}' is not valid", c.status_code)));
                }
                if let Some(ct) = &c.content_type {
                    if !matches!(
                        ct.as_str(),
                        "text/plain" | "text/css" | "text/html" | "application/javascript" | "application/json"
                    ) {
                        return Err(validation(format!("Fixed response content type '{ct}' is not valid")));
                    }
                }
                if c.message_body.as_ref().is_some_and(|b| b.len() > 1024) {
                    return Err(validation("Fixed response message body cannot be longer than 1024 characters"));
                }
            }
            "authenticate-oidc" => {
                let mut c =
                    a.authenticate_oidc_config.clone().ok_or_else(|| validation("An OIDC config must be specified"))?;
                if c.client_secret.is_none() && c.use_existing_client_secret != Some(true) {
                    return Err(validation("A client secret must be specified for an authenticate-oidc action"));
                }
                c.scope.get_or_insert_with(|| "openid".into());
                c.session_cookie_name.get_or_insert_with(|| "AWSELBAuthSessionCookie".into());
                c.session_timeout.get_or_insert(604_800);
                c.on_unauthenticated_request.get_or_insert_with(|| "authenticate".into());
                // ELB never shows the secret again.
                c.client_secret = None;
                c.use_existing_client_secret = None;
                a.authenticate_oidc_config = Some(c);
            }
            "authenticate-cognito" => {
                let mut c = a
                    .authenticate_cognito_config
                    .clone()
                    .ok_or_else(|| validation("A Cognito config must be specified"))?;
                c.scope.get_or_insert_with(|| "openid".into());
                c.session_cookie_name.get_or_insert_with(|| "AWSELBAuthSessionCookie".into());
                c.session_timeout.get_or_insert(604_800);
                c.on_unauthenticated_request.get_or_insert_with(|| "authenticate".into());
                a.authenticate_cognito_config = Some(c);
            }
            "jwt-validation" if a.jwt_validation_config.is_none() => {
                return Err(validation("A JWT validation config must be specified"));
            }
            _ => {}
        }
        out.push(a);
    }
    Ok(out)
}
