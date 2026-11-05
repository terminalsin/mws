//! Listeners (standard and custom routing).

use mws_core::{RequestContext, ServiceError};

use crate::accelerators::{find, find_mut};
use crate::generated::{errors, types};
use crate::names::{self, authorize, invalid, listener_not_found, now_ms, page, resource_tags};
use crate::state::{Accelerator, Listener, PortRange, State};
use crate::GlobalAccelerator;

/// Listeners per accelerator, and port ranges per listener.
const LISTENER_LIMIT: usize = 10;
const PORT_RANGE_LIMIT: usize = 10;

/// The accelerator that owns listener `arn`, if the caller owns it.
pub fn listener<'a>(
    st: &'a State,
    ctx: &RequestContext,
    arn: &str,
    custom: bool,
) -> Result<(&'a Accelerator, &'a Listener), ServiceError> {
    let path = names::parse(arn).filter(|p| p.listener.as_deref() == Some(arn) && p.group.is_none());
    let path = path.ok_or_else(|| listener_not_found(arn))?;
    let a = find(st, ctx, &path.accelerator, custom).map_err(|_| listener_not_found(arn))?;
    let l = a.listeners.get(arn).ok_or_else(|| listener_not_found(arn))?;
    Ok((a, l))
}

pub fn listener_mut<'a>(
    st: &'a mut State,
    ctx: &RequestContext,
    arn: &str,
    custom: bool,
) -> Result<&'a mut Accelerator, ServiceError> {
    let path = names::parse(arn).filter(|p| p.listener.as_deref() == Some(arn) && p.group.is_none());
    let path = path.ok_or_else(|| listener_not_found(arn))?;
    let a = find_mut(st, ctx, &path.accelerator, custom).map_err(|_| listener_not_found(arn))?;
    if !a.listeners.contains_key(arn) {
        return Err(listener_not_found(arn));
    }
    Ok(a)
}

pub fn port_ranges(ranges: &[types::PortRange]) -> Result<Vec<PortRange>, ServiceError> {
    if ranges.is_empty() {
        return Err(invalid("You must specify at least one port range."));
    }
    if ranges.len() > PORT_RANGE_LIMIT {
        return Err(errors::limit_exceeded(format!("A listener can have at most {PORT_RANGE_LIMIT} port ranges.")));
    }
    let mut out: Vec<PortRange> = Vec::new();
    for r in ranges {
        let (Some(from), Some(to)) = (r.from_port, r.to_port) else {
            return Err(errors::invalid_port_range("A port range must have both FromPort and ToPort."));
        };
        if !(1..=65535).contains(&from) || !(1..=65535).contains(&to) || from > to {
            return Err(errors::invalid_port_range(format!(
                "The port range {from}-{to} is not valid. Ports must be from 1 to 65535, and FromPort must not be greater than ToPort."
            )));
        }
        let range = PortRange { from, to };
        if out.iter().any(|o| o.overlaps(&range)) {
            return Err(errors::invalid_port_range(format!("The port range {from}-{to} overlaps another port range.")));
        }
        out.push(range);
    }
    Ok(out)
}

/// Port ranges must be unique for the accelerator (per protocol, for
/// standard listeners).
fn check_unique(
    a: &Accelerator,
    except: Option<&str>,
    protocol: &str,
    ranges: &[PortRange],
) -> Result<(), ServiceError> {
    for l in a.listeners.values().filter(|l| Some(l.arn.as_str()) != except && l.protocol == protocol) {
        for r in ranges {
            if l.port_ranges.iter().any(|o| o.overlaps(r)) {
                return Err(errors::invalid_port_range(format!(
                    "The port range {}-{} overlaps a port range of listener {}.",
                    r.from, r.to, l.arn
                )));
            }
        }
    }
    Ok(())
}

fn check_protocol(p: &str) -> Result<(), ServiceError> {
    if p != "TCP" && p != "UDP" {
        return Err(invalid(format!("Protocol {p} is not valid. Valid values are TCP and UDP.")));
    }
    Ok(())
}

fn check_affinity(c: &str) -> Result<(), ServiceError> {
    if c != "NONE" && c != "SOURCE_IP" {
        return Err(invalid(format!("ClientAffinity {c} is not valid. Valid values are NONE and SOURCE_IP.")));
    }
    Ok(())
}

pub fn wire_ranges(ranges: &[PortRange]) -> Vec<types::PortRange> {
    ranges.iter().map(|r| types::PortRange { from_port: Some(r.from), to_port: Some(r.to) }).collect()
}

fn describe(l: &Listener) -> types::Listener {
    types::Listener {
        listener_arn: Some(l.arn.clone()),
        port_ranges: Some(wire_ranges(&l.port_ranges)),
        protocol: Some(l.protocol.clone()),
        client_affinity: Some(l.client_affinity.clone()),
    }
}

fn describe_custom(l: &Listener) -> types::CustomRoutingListener {
    types::CustomRoutingListener { listener_arn: Some(l.arn.clone()), port_ranges: Some(wire_ranges(&l.port_ranges)) }
}

impl GlobalAccelerator {
    #[allow(clippy::too_many_arguments)]
    fn create_listener_common(
        &self,
        ctx: &RequestContext,
        accelerator_arn: &str,
        ranges: &[types::PortRange],
        protocol: &str,
        affinity: &str,
        token: &str,
        custom: bool,
    ) -> Result<Listener, ServiceError> {
        let op = if custom { "CreateCustomRoutingListener" } else { "CreateListener" };
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let a = find(&st, ctx, accelerator_arn, custom)?;
        authorize(ctx, op, accelerator_arn, resource_tags(&a.tags))?;
        let key = format!("{}/{op}/{token}", a.account);
        if let Some(l) = st.idempotency.get(&key).and_then(|arn| a.listeners.get(arn)) {
            return Ok(l.clone());
        }
        if !custom {
            check_protocol(protocol)?;
            check_affinity(affinity)?;
        }
        let ranges = port_ranges(ranges)?;
        check_unique(a, None, protocol, &ranges)?;
        if a.listeners.len() >= LISTENER_LIMIT {
            return Err(errors::limit_exceeded(format!("An accelerator can have at most {LISTENER_LIMIT} listeners.")));
        }
        let seq = st.next_seq();
        let l = Listener {
            arn: names::listener_arn(accelerator_arn),
            seq,
            protocol: protocol.to_string(),
            client_affinity: affinity.to_string(),
            port_ranges: ranges,
            groups: Default::default(),
        };
        st.idempotency.insert(key, l.arn.clone());
        let a = find_mut(&mut st, ctx, accelerator_arn, custom)?;
        a.listeners.insert(l.arn.clone(), l.clone());
        a.touch(now);
        Ok(l)
    }

    fn delete_listener_common(&self, ctx: &RequestContext, arn: &str, custom: bool) -> Result<(), ServiceError> {
        let op = if custom { "DeleteCustomRoutingListener" } else { "DeleteListener" };
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, arn, custom)?;
        authorize(ctx, op, arn, resource_tags(&a.tags))?;
        if !l.groups.is_empty() {
            return Err(errors::associated_endpoint_group_found(
                "The listener has endpoint groups associated with it. Delete the endpoint groups before deleting the listener.",
            ));
        }
        let a = listener_mut(&mut st, ctx, arn, custom)?;
        a.listeners.remove(arn);
        a.touch(now);
        st.idempotency.retain(|_, v| v != arn);
        Ok(())
    }

    fn list_listeners_common(
        &self,
        ctx: &RequestContext,
        accelerator_arn: &str,
        custom: bool,
        max_results: Option<i32>,
        next_token: Option<&str>,
    ) -> Result<(Vec<Listener>, Option<String>), ServiceError> {
        let op = if custom { "ListCustomRoutingListeners" } else { "ListListeners" };
        let st = self.settled(ctx);
        let a = find(&st, ctx, accelerator_arn, custom)?;
        authorize(ctx, op, accelerator_arn, resource_tags(&a.tags))?;
        let mut items: Vec<Listener> = a.listeners.values().cloned().collect();
        items.sort_by_key(|l| l.seq);
        page(items, max_results, next_token, 10)
    }

    pub fn create_listener(
        &self,
        ctx: &RequestContext,
        input: types::CreateListenerRequest,
    ) -> Result<types::CreateListenerResponse, ServiceError> {
        let l = self.create_listener_common(
            ctx,
            &input.accelerator_arn,
            &input.port_ranges,
            &input.protocol,
            input.client_affinity.as_deref().unwrap_or("NONE"),
            &input.idempotency_token,
            false,
        )?;
        Ok(types::CreateListenerResponse { listener: Some(describe(&l)) })
    }

    pub fn describe_listener(
        &self,
        ctx: &RequestContext,
        input: types::DescribeListenerRequest,
    ) -> Result<types::DescribeListenerResponse, ServiceError> {
        let st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, &input.listener_arn, false)?;
        authorize(ctx, "DescribeListener", &l.arn, resource_tags(&a.tags))?;
        Ok(types::DescribeListenerResponse { listener: Some(describe(l)) })
    }

    pub fn list_listeners(
        &self,
        ctx: &RequestContext,
        input: types::ListListenersRequest,
    ) -> Result<types::ListListenersResponse, ServiceError> {
        let (items, next_token) = self.list_listeners_common(
            ctx,
            &input.accelerator_arn,
            false,
            input.max_results,
            input.next_token.as_deref(),
        )?;
        Ok(types::ListListenersResponse { listeners: Some(items.iter().map(describe).collect()), next_token })
    }

    pub fn update_listener(
        &self,
        ctx: &RequestContext,
        input: types::UpdateListenerRequest,
    ) -> Result<types::UpdateListenerResponse, ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, &input.listener_arn, false)?;
        authorize(ctx, "UpdateListener", &l.arn, resource_tags(&a.tags))?;
        let mut l = l.clone();
        if let Some(p) = &input.protocol {
            check_protocol(p)?;
            if p == "UDP"
                && l.groups
                    .values()
                    .flat_map(|g| &g.endpoints)
                    .any(|e| names::EndpointKind::of(&e.id) == Some(names::EndpointKind::ApplicationLoadBalancer))
            {
                return Err(invalid("Application Load Balancer endpoints support only the TCP protocol."));
            }
            l.protocol = p.clone();
        }
        if let Some(c) = &input.client_affinity {
            check_affinity(c)?;
            l.client_affinity = c.clone();
        }
        if let Some(r) = &input.port_ranges {
            l.port_ranges = port_ranges(r)?;
        }
        check_unique(a, Some(&l.arn), &l.protocol, &l.port_ranges)?;
        for g in l.groups.values() {
            if let Some((port, _)) = g.port_overrides.iter().find(|(p, _)| !l.contains_port(*p)) {
                return Err(invalid(format!(
                    "Port override listener port {port} is not in the listener's new port ranges."
                )));
            }
        }
        let a = listener_mut(&mut st, ctx, &input.listener_arn, false)?;
        a.listeners.insert(l.arn.clone(), l.clone());
        a.touch(now);
        Ok(types::UpdateListenerResponse { listener: Some(describe(&l)) })
    }

    pub fn delete_listener(
        &self,
        ctx: &RequestContext,
        input: types::DeleteListenerRequest,
    ) -> Result<(), ServiceError> {
        self.delete_listener_common(ctx, &input.listener_arn, false)
    }

    pub fn create_custom_routing_listener(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomRoutingListenerRequest,
    ) -> Result<types::CreateCustomRoutingListenerResponse, ServiceError> {
        let l = self.create_listener_common(
            ctx,
            &input.accelerator_arn,
            &input.port_ranges,
            "",
            "",
            &input.idempotency_token,
            true,
        )?;
        Ok(types::CreateCustomRoutingListenerResponse { listener: Some(describe_custom(&l)) })
    }

    pub fn describe_custom_routing_listener(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCustomRoutingListenerRequest,
    ) -> Result<types::DescribeCustomRoutingListenerResponse, ServiceError> {
        let st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, &input.listener_arn, true)?;
        authorize(ctx, "DescribeCustomRoutingListener", &l.arn, resource_tags(&a.tags))?;
        Ok(types::DescribeCustomRoutingListenerResponse { listener: Some(describe_custom(l)) })
    }

    pub fn list_custom_routing_listeners(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomRoutingListenersRequest,
    ) -> Result<types::ListCustomRoutingListenersResponse, ServiceError> {
        let (items, next_token) = self.list_listeners_common(
            ctx,
            &input.accelerator_arn,
            true,
            input.max_results,
            input.next_token.as_deref(),
        )?;
        Ok(types::ListCustomRoutingListenersResponse {
            listeners: Some(items.iter().map(describe_custom).collect()),
            next_token,
        })
    }

    pub fn update_custom_routing_listener(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomRoutingListenerRequest,
    ) -> Result<types::UpdateCustomRoutingListenerResponse, ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, &input.listener_arn, true)?;
        authorize(ctx, "UpdateCustomRoutingListener", &l.arn, resource_tags(&a.tags))?;
        let mut l = l.clone();
        l.port_ranges = port_ranges(&input.port_ranges)?;
        check_unique(a, Some(&l.arn), "", &l.port_ranges)?;
        // The subnets already mapped must still fit.
        let needed = crate::custom::blocks(&l).into_iter().map(|(start, len)| start + len).max().unwrap_or(0);
        if needed > l.port_count() {
            return Err(errors::invalid_port_range(format!(
                "The listener's port ranges must include at least {needed} ports for the subnet endpoints that are mapped to it."
            )));
        }
        let a = listener_mut(&mut st, ctx, &input.listener_arn, true)?;
        a.listeners.insert(l.arn.clone(), l.clone());
        a.touch(now);
        Ok(types::UpdateCustomRoutingListenerResponse { listener: Some(describe_custom(&l)) })
    }

    pub fn delete_custom_routing_listener(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomRoutingListenerRequest,
    ) -> Result<(), ServiceError> {
        self.delete_listener_common(ctx, &input.listener_arn, true)
    }
}
