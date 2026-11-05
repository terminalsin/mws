//! Standard endpoint groups and their endpoints, with health from the
//! services that own the endpoints.

use mws_core::{RequestContext, ServiceError};

use crate::accelerators::{find, find_mut};
use crate::generated::{errors, types};
use crate::listeners::listener;
use crate::names::{self, authorize, group_not_found, invalid, now_ms, page, resource_tags, EndpointKind, REGIONS};
use crate::state::{Accelerator, Endpoint, EndpointGroup, Listener, State, TRANSITION_MS};
use crate::{EndpointHealth, GlobalAccelerator, Lookup};

/// Endpoints per endpoint group, and port overrides per endpoint group.
const ENDPOINT_LIMIT: usize = 10;
const PORT_OVERRIDE_LIMIT: usize = 10;

/// The accelerator, listener and endpoint group `arn` names, if the caller
/// owns them.
pub fn group<'a>(
    st: &'a State,
    ctx: &RequestContext,
    arn: &str,
    custom: bool,
) -> Result<(&'a Accelerator, &'a Listener, &'a EndpointGroup), ServiceError> {
    let path = names::parse(arn).filter(|p| p.group.as_deref() == Some(arn));
    let path = path.ok_or_else(|| group_not_found(arn))?;
    let a = find(st, ctx, &path.accelerator, custom).map_err(|_| group_not_found(arn))?;
    let l = path.listener.as_ref().and_then(|l| a.listeners.get(l)).ok_or_else(|| group_not_found(arn))?;
    let g = l.groups.get(arn).ok_or_else(|| group_not_found(arn))?;
    Ok((a, l, g))
}

/// Replace endpoint group `arn` (and mark the accelerator as deploying).
pub fn store_group(st: &mut State, ctx: &RequestContext, g: EndpointGroup, custom: bool, now: i64) {
    let path = names::parse(&g.arn).expect("stored group ARN parses");
    let a = find_mut(st, ctx, &path.accelerator, custom).expect("group's accelerator exists");
    let l = a.listeners.get_mut(path.listener.as_deref().unwrap_or_default()).expect("group's listener exists");
    l.groups.insert(g.arn.clone(), g);
    a.touch(now);
}

pub fn check_region(region: &str) -> Result<(), ServiceError> {
    if !REGIONS.contains(&region) {
        return Err(invalid(format!("EndpointGroupRegion {region} is not a supported Region.")));
    }
    Ok(())
}

/// Who owns endpoint `id` and through which attachment, for an accelerator
/// in the caller's account. Endpoints in other accounts need a
/// cross-account attachment that names the caller (or the accelerator) and
/// the endpoint.
pub fn endpoint_owner(
    st: &State,
    caller: &str,
    accelerator: &str,
    id: &str,
    region: &str,
    natural_owner: Option<&str>,
    attachment_arn: Option<&str>,
) -> Result<(String, Option<String>), ServiceError> {
    let grants = |t: &crate::state::Attachment| {
        t.principals.iter().any(|p| p == caller || p == accelerator)
            && t.resources
                .iter()
                .any(|r| r.endpoint_id.as_deref() == Some(id) && r.region.as_deref().is_none_or(|rr| rr == region))
    };
    if let Some(arn) = attachment_arn {
        let t = st
            .attachments
            .get(arn)
            .ok_or_else(|| invalid(format!("The cross-account attachment {arn} was not found.")))?;
        if t.account == caller && natural_owner.is_none_or(|o| o == caller) {
            return Ok((caller.to_string(), Some(arn.to_string())));
        }
        if !grants(t) {
            return Err(errors::access_denied(format!(
                "The cross-account attachment {arn} doesn't allow you to add endpoint {id}."
            )));
        }
        if natural_owner.is_some_and(|o| o != t.account) {
            return Err(invalid(format!("Endpoint {id} isn't owned by the account that owns attachment {arn}.")));
        }
        return Ok((t.account.clone(), Some(arn.to_string())));
    }
    let owner = natural_owner.unwrap_or(caller);
    if owner == caller {
        return Ok((caller.to_string(), None));
    }
    match st.attachments.values().filter(|t| t.account == owner).find(|t| grants(t)) {
        Some(t) => Ok((owner.to_string(), Some(t.arn.clone()))),
        None => Err(errors::access_denied(format!(
            "Endpoint {id} belongs to account {owner}, which hasn't shared it with you through a cross-account attachment."
        ))),
    }
}

fn check_health_check(
    protocol: Option<&str>,
    port: Option<i32>,
    interval: Option<i32>,
    threshold: Option<i32>,
) -> Result<(), ServiceError> {
    if let Some(p) = protocol {
        if !["TCP", "HTTP", "HTTPS"].contains(&p) {
            return Err(invalid(format!(
                "HealthCheckProtocol {p} is not valid. Valid values are TCP, HTTP and HTTPS."
            )));
        }
    }
    if let Some(p) = port {
        if !(1..=65535).contains(&p) {
            return Err(invalid("HealthCheckPort must be from 1 to 65535."));
        }
    }
    if let Some(i) = interval {
        if i != 10 && i != 30 {
            return Err(invalid("HealthCheckIntervalSeconds must be 10 or 30."));
        }
    }
    if let Some(t) = threshold {
        if !(1..=10).contains(&t) {
            return Err(invalid("ThresholdCount must be from 1 to 10."));
        }
    }
    Ok(())
}

fn port_overrides(l: &Listener, overrides: &[types::PortOverride]) -> Result<Vec<(i32, i32)>, ServiceError> {
    if overrides.len() > PORT_OVERRIDE_LIMIT {
        return Err(errors::limit_exceeded(format!(
            "An endpoint group can have at most {PORT_OVERRIDE_LIMIT} port overrides."
        )));
    }
    let mut out: Vec<(i32, i32)> = Vec::new();
    for o in overrides {
        let (Some(listener_port), Some(endpoint_port)) = (o.listener_port, o.endpoint_port) else {
            return Err(invalid("A port override must have both ListenerPort and EndpointPort."));
        };
        if !(1..=65535).contains(&endpoint_port) {
            return Err(invalid("EndpointPort must be from 1 to 65535."));
        }
        if !l.contains_port(listener_port) {
            return Err(invalid(format!(
                "Port override listener port {listener_port} is not in the listener's port ranges."
            )));
        }
        if out.iter().any(|(p, _)| *p == listener_port) {
            return Err(invalid(format!("Listener port {listener_port} has more than one port override.")));
        }
        out.push((listener_port, endpoint_port));
    }
    Ok(out)
}

impl GlobalAccelerator {
    /// Endpoints from their configurations: ids checked against the
    /// services that own them, owners resolved through attachments.
    #[allow(clippy::too_many_arguments)]
    fn endpoints(
        &self,
        st: &State,
        a: &Accelerator,
        l: &Listener,
        region: &str,
        configs: &[types::EndpointConfiguration],
        existing: &[Endpoint],
        now: i64,
    ) -> Result<Vec<Endpoint>, ServiceError> {
        let mut out: Vec<Endpoint> = Vec::new();
        for c in configs {
            let id =
                c.endpoint_id.clone().filter(|i| !i.is_empty()).ok_or_else(|| invalid("EndpointId is required."))?;
            let kind = EndpointKind::of(&id).ok_or_else(|| {
                invalid(format!(
                    "The endpoint ID {id} is not valid. Specify a load balancer ARN, an EC2 instance ID, or an Elastic IP address allocation ID."
                ))
            })?;
            if out.iter().any(|e| e.id == id) {
                return Err(invalid(format!("Endpoint {id} is specified more than once.")));
            }
            let natural_owner = match kind {
                EndpointKind::ApplicationLoadBalancer | EndpointKind::NetworkLoadBalancer => {
                    let (lb_region, lb_account) = names::elb_region_account(&id).unwrap_or_default();
                    if lb_region != region {
                        return Err(invalid(format!("Endpoint {id} is not in the endpoint group's Region {region}.")));
                    }
                    Some(lb_account)
                }
                _ => None,
            };
            if kind == EndpointKind::ApplicationLoadBalancer && l.protocol == "UDP" {
                return Err(invalid("Application Load Balancer endpoints support only the TCP protocol."));
            }
            let weight = c.weight.unwrap_or(128);
            if !(0..=255).contains(&weight) {
                return Err(invalid("Weight must be from 0 to 255."));
            }
            let preserve = c.client_ip_preservation_enabled.unwrap_or(kind.preserves_client_ip_by_default());
            if preserve && kind == EndpointKind::ElasticIp {
                return Err(invalid(
                    "Client IP address preservation isn't supported for Elastic IP address endpoints.",
                ));
            }
            let (owner, attachment) =
                endpoint_owner(st, &a.account, &a.arn, &id, region, natural_owner, c.attachment_arn.as_deref())?;
            if self.lookup_endpoint(&owner, region, &id) == Lookup::Missing {
                return Err(invalid(format!("Endpoint {id} doesn't exist in Region {region}.")));
            }
            let added = existing.iter().find(|e| e.id == id).map(|e| e.added).unwrap_or(now);
            out.push(Endpoint {
                id,
                owner,
                attachment_arn: attachment,
                weight,
                client_ip_preservation: preserve,
                added,
                ..Default::default()
            });
        }
        Ok(out)
    }

    fn endpoint_description(&self, g: &EndpointGroup, e: &Endpoint, now: i64) -> types::EndpointDescription {
        let (state, reason) = if now < e.added + TRANSITION_MS {
            ("INITIAL", None)
        } else {
            match self.lookup_endpoint(&e.owner, &g.region, &e.id) {
                Lookup::NotMine => ("HEALTHY", None),
                Lookup::Missing => ("UNHEALTHY", Some("The endpoint doesn't exist.".to_string())),
                Lookup::Found(EndpointHealth { healthy: true, .. }) => ("HEALTHY", None),
                Lookup::Found(EndpointHealth { reason, .. }) => ("UNHEALTHY", reason),
            }
        };
        types::EndpointDescription {
            endpoint_id: Some(e.id.clone()),
            weight: Some(e.weight),
            health_state: Some(state.into()),
            health_reason: reason,
            client_ip_preservation_enabled: Some(e.client_ip_preservation),
        }
    }

    fn describe_group(&self, l: &Listener, g: &EndpointGroup, now: i64) -> types::EndpointGroup {
        let lowest = l.port_ranges.iter().map(|r| r.from).min();
        let http = g.health_check_protocol != "TCP";
        types::EndpointGroup {
            endpoint_group_arn: Some(g.arn.clone()),
            endpoint_group_region: Some(g.region.clone()),
            endpoint_descriptions: Some(g.endpoints.iter().map(|e| self.endpoint_description(g, e, now)).collect()),
            traffic_dial_percentage: Some(g.traffic_dial),
            health_check_port: g.health_check_port.or(lowest),
            health_check_protocol: Some(g.health_check_protocol.clone()),
            health_check_path: if http {
                Some(g.health_check_path.clone().unwrap_or_else(|| "/".into()))
            } else {
                None
            },
            health_check_interval_seconds: Some(g.health_check_interval),
            threshold_count: Some(g.threshold_count),
            port_overrides: Some(
                g.port_overrides
                    .iter()
                    .map(|(l, e)| types::PortOverride { listener_port: Some(*l), endpoint_port: Some(*e) })
                    .collect(),
            ),
        }
    }

    pub fn create_endpoint_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateEndpointGroupRequest,
    ) -> Result<types::CreateEndpointGroupResponse, ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, &input.listener_arn, false)?;
        authorize(ctx, "CreateEndpointGroup", &l.arn, resource_tags(&a.tags))?;
        let key = format!("{}/CreateEndpointGroup/{}", a.account, input.idempotency_token);
        if let Some(g) = st.idempotency.get(&key).and_then(|arn| l.groups.get(arn)) {
            return Ok(types::CreateEndpointGroupResponse { endpoint_group: Some(self.describe_group(l, g, now)) });
        }
        let region = input.endpoint_group_region.clone();
        check_region(&region)?;
        if l.groups.values().any(|g| g.region == region) {
            return Err(errors::endpoint_group_already_exists(format!(
                "The listener already has an endpoint group in Region {region}."
            )));
        }
        let dial = input.traffic_dial_percentage.unwrap_or(100.0);
        if !(0.0..=100.0).contains(&dial) {
            return Err(invalid("TrafficDialPercentage must be from 0 to 100."));
        }
        check_health_check(
            input.health_check_protocol.as_deref(),
            input.health_check_port,
            input.health_check_interval_seconds,
            input.threshold_count,
        )?;
        let configs = input.endpoint_configurations.unwrap_or_default();
        if configs.len() > ENDPOINT_LIMIT {
            return Err(errors::limit_exceeded(format!(
                "An endpoint group can have at most {ENDPOINT_LIMIT} endpoints."
            )));
        }
        let endpoints = self.endpoints(&st, a, l, &region, &configs, &[], now)?;
        let overrides = port_overrides(l, input.port_overrides.as_deref().unwrap_or_default())?;
        let g = EndpointGroup {
            arn: names::group_arn(&l.arn),
            seq: 0,
            region,
            endpoints,
            traffic_dial: dial,
            health_check_port: input.health_check_port,
            health_check_protocol: input.health_check_protocol.unwrap_or_else(|| "TCP".into()),
            health_check_path: input.health_check_path,
            health_check_interval: input.health_check_interval_seconds.unwrap_or(30),
            threshold_count: input.threshold_count.unwrap_or(3),
            port_overrides: overrides,
            destinations: Vec::new(),
        };
        let l = l.clone();
        let g = EndpointGroup { seq: st.next_seq(), ..g };
        st.idempotency.insert(key, g.arn.clone());
        store_group(&mut st, ctx, g.clone(), false, now);
        Ok(types::CreateEndpointGroupResponse { endpoint_group: Some(self.describe_group(&l, &g, now)) })
    }

    pub fn describe_endpoint_group(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEndpointGroupRequest,
    ) -> Result<types::DescribeEndpointGroupResponse, ServiceError> {
        let now = now_ms(ctx);
        let st = self.settled(ctx);
        let (a, l, g) = group(&st, ctx, &input.endpoint_group_arn, false)?;
        authorize(ctx, "DescribeEndpointGroup", &g.arn, resource_tags(&a.tags))?;
        Ok(types::DescribeEndpointGroupResponse { endpoint_group: Some(self.describe_group(l, g, now)) })
    }

    pub fn list_endpoint_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListEndpointGroupsRequest,
    ) -> Result<types::ListEndpointGroupsResponse, ServiceError> {
        let now = now_ms(ctx);
        let st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, &input.listener_arn, false)?;
        authorize(ctx, "ListEndpointGroups", &l.arn, resource_tags(&a.tags))?;
        let mut items: Vec<&EndpointGroup> = l.groups.values().collect();
        items.sort_by_key(|g| g.seq);
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref(), 10)?;
        Ok(types::ListEndpointGroupsResponse {
            endpoint_groups: Some(items.into_iter().map(|g| self.describe_group(l, g, now)).collect()),
            next_token,
        })
    }

    pub fn update_endpoint_group(
        &self,
        ctx: &RequestContext,
        input: types::UpdateEndpointGroupRequest,
    ) -> Result<types::UpdateEndpointGroupResponse, ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, l, g) = group(&st, ctx, &input.endpoint_group_arn, false)?;
        authorize(ctx, "UpdateEndpointGroup", &g.arn, resource_tags(&a.tags))?;
        check_health_check(
            input.health_check_protocol.as_deref(),
            input.health_check_port,
            input.health_check_interval_seconds,
            input.threshold_count,
        )?;
        let mut g = g.clone();
        if let Some(configs) = &input.endpoint_configurations {
            if configs.len() > ENDPOINT_LIMIT {
                return Err(errors::limit_exceeded(format!(
                    "An endpoint group can have at most {ENDPOINT_LIMIT} endpoints."
                )));
            }
            g.endpoints = self.endpoints(&st, a, l, &g.region, configs, &g.endpoints, now)?;
        }
        if let Some(d) = input.traffic_dial_percentage {
            if !(0.0..=100.0).contains(&d) {
                return Err(invalid("TrafficDialPercentage must be from 0 to 100."));
            }
            g.traffic_dial = d;
        }
        if let Some(p) = input.health_check_port {
            g.health_check_port = Some(p);
        }
        if let Some(p) = input.health_check_protocol {
            g.health_check_protocol = p;
        }
        if let Some(p) = input.health_check_path {
            g.health_check_path = Some(p);
        }
        if let Some(i) = input.health_check_interval_seconds {
            g.health_check_interval = i;
        }
        if let Some(t) = input.threshold_count {
            g.threshold_count = t;
        }
        if let Some(o) = &input.port_overrides {
            g.port_overrides = port_overrides(l, o)?;
        }
        let l = l.clone();
        store_group(&mut st, ctx, g.clone(), false, now);
        Ok(types::UpdateEndpointGroupResponse { endpoint_group: Some(self.describe_group(&l, &g, now)) })
    }

    pub fn delete_endpoint_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEndpointGroupRequest,
    ) -> Result<(), ServiceError> {
        self.delete_group_common(ctx, &input.endpoint_group_arn, false)
    }

    pub(crate) fn delete_group_common(
        &self,
        ctx: &RequestContext,
        arn: &str,
        custom: bool,
    ) -> Result<(), ServiceError> {
        let op = if custom { "DeleteCustomRoutingEndpointGroup" } else { "DeleteEndpointGroup" };
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, _, g) = group(&st, ctx, arn, custom)?;
        authorize(ctx, op, &g.arn, resource_tags(&a.tags))?;
        let path = names::parse(arn).expect("group ARN parses");
        let a = find_mut(&mut st, ctx, &path.accelerator, custom)?;
        if let Some(l) = a.listeners.get_mut(path.listener.as_deref().unwrap_or_default()) {
            l.groups.remove(arn);
        }
        a.touch(now);
        st.idempotency.retain(|_, v| v != arn);
        Ok(())
    }

    pub fn add_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::AddEndpointsRequest,
    ) -> Result<types::AddEndpointsResponse, ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, l, g) = group(&st, ctx, &input.endpoint_group_arn, false)?;
        authorize(ctx, "AddEndpoints", &g.arn, resource_tags(&a.tags))?;
        if input.endpoint_configurations.is_empty() {
            return Err(invalid("You must specify at least one endpoint configuration."));
        }
        let added = self.endpoints(&st, a, l, &g.region, &input.endpoint_configurations, &g.endpoints, now)?;
        let mut g = g.clone();
        for e in &added {
            match g.endpoints.iter_mut().find(|x| x.id == e.id) {
                Some(x) => *x = e.clone(),
                None => g.endpoints.push(e.clone()),
            }
        }
        if g.endpoints.len() > ENDPOINT_LIMIT {
            return Err(errors::limit_exceeded(format!(
                "An endpoint group can have at most {ENDPOINT_LIMIT} endpoints."
            )));
        }
        let descriptions = added.iter().map(|e| self.endpoint_description(&g, e, now)).collect();
        let arn = g.arn.clone();
        store_group(&mut st, ctx, g, false, now);
        Ok(types::AddEndpointsResponse { endpoint_descriptions: Some(descriptions), endpoint_group_arn: Some(arn) })
    }

    pub fn remove_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::RemoveEndpointsRequest,
    ) -> Result<(), ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, _, g) = group(&st, ctx, &input.endpoint_group_arn, false)?;
        authorize(ctx, "RemoveEndpoints", &g.arn, resource_tags(&a.tags))?;
        if input.endpoint_identifiers.is_empty() {
            return Err(invalid("You must specify at least one endpoint identifier."));
        }
        let mut g = g.clone();
        g.endpoints.retain(|e| !input.endpoint_identifiers.iter().any(|i| i.endpoint_id == e.id));
        store_group(&mut st, ctx, g, false, now);
        Ok(())
    }
}
