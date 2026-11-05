//! Custom routing: endpoint groups of VPC subnets, the static mapping of
//! listener ports onto every subnet address and destination port, and
//! per-destination traffic allow/deny.
//!
//! Each subnet endpoint gets a block of consecutive listener ports (in the
//! listener's ports, lowest first) the size of its address count times the
//! group's destination port count, placed at the lowest free offset when
//! it is added, so mappings stay put as other subnets come and go. Within
//! a block, ports go address by address, then destination port by
//! destination port.

use std::net::Ipv4Addr;

use mws_core::{RequestContext, ServiceError};

use crate::accelerators::find;
use crate::generated::{errors, types};
use crate::groups::{check_region, endpoint_owner, group, store_group};
use crate::ips::Cidr;
use crate::listeners::listener;
use crate::names::{self, authorize, invalid, now_ms, page, resource_tags};
use crate::state::{Accelerator, Destination, Endpoint, EndpointGroup, Listener, TrafficRule};
use crate::{GlobalAccelerator, Lookup};

const DESTINATION_LIMIT: usize = 100;
const ENDPOINT_LIMIT: usize = 20;

fn cidr_of(e: &Endpoint) -> Cidr {
    e.cidr.as_deref().and_then(Cidr::parse).expect("custom routing endpoints keep their subnet CIDR")
}

fn block_len(g: &EndpointGroup, e: &Endpoint) -> u32 {
    let ports = g.destination_ports().len() as u64;
    (cidr_of(e).size() * ports).min(u64::from(u32::MAX)) as u32
}

/// The listener port blocks in use: `(start, length)` per subnet endpoint.
pub fn blocks(l: &Listener) -> Vec<(u32, u32)> {
    l.groups.values().flat_map(|g| g.endpoints.iter().map(move |e| (e.port_base, block_len(g, e)))).collect()
}

/// The lowest offset with `len` free listener ports.
fn place(l: &Listener, len: u32, taken: &mut Vec<(u32, u32)>) -> Option<u32> {
    taken.sort();
    let mut start = 0u32;
    for (s, n) in taken.iter() {
        if start.checked_add(len)? <= *s {
            break;
        }
        start = start.max(s + n);
    }
    let fits = start.checked_add(len).is_some_and(|end| end <= l.port_count());
    if fits {
        taken.push((start, len));
    }
    fits.then_some(start)
}

/// Whether traffic to `ip:port` of endpoint `e` is allowed.
fn allowed(e: &Endpoint, ip: &str, port: i32) -> bool {
    let mut allow = e.allow_all;
    for r in &e.traffic_rules {
        let ip_match = r.addresses.as_ref().is_none_or(|a| a.iter().any(|x| x == ip));
        let port_match = r.ports.as_ref().is_none_or(|p| p.contains(&port));
        if ip_match && port_match {
            allow = r.allow;
        }
    }
    allow
}

fn destinations(configs: &[types::CustomRoutingDestinationConfiguration]) -> Result<Vec<Destination>, ServiceError> {
    if configs.is_empty() {
        return Err(invalid("You must specify at least one destination configuration."));
    }
    if configs.len() > DESTINATION_LIMIT {
        return Err(errors::limit_exceeded(format!(
            "An endpoint group can have at most {DESTINATION_LIMIT} destination configurations."
        )));
    }
    let mut out: Vec<Destination> = Vec::new();
    for c in configs {
        if !(1..=65535).contains(&c.from_port) || !(1..=65535).contains(&c.to_port) || c.from_port > c.to_port {
            return Err(errors::invalid_port_range(format!(
                "The destination port range {}-{} is not valid.",
                c.from_port, c.to_port
            )));
        }
        if out.iter().any(|d| d.from <= c.to_port && c.from_port <= d.to) {
            return Err(errors::invalid_port_range(format!(
                "The destination port range {}-{} overlaps another destination port range.",
                c.from_port, c.to_port
            )));
        }
        if c.protocols.is_empty() || c.protocols.iter().any(|p| p != "TCP" && p != "UDP") {
            return Err(invalid("Protocols must contain TCP, UDP or both."));
        }
        let mut protocols = c.protocols.clone();
        protocols.dedup();
        out.push(Destination { from: c.from_port, to: c.to_port, protocols });
    }
    Ok(out)
}

fn describe_group(g: &EndpointGroup) -> types::CustomRoutingEndpointGroup {
    types::CustomRoutingEndpointGroup {
        endpoint_group_arn: Some(g.arn.clone()),
        endpoint_group_region: Some(g.region.clone()),
        destination_descriptions: Some(
            g.destinations
                .iter()
                .map(|d| types::CustomRoutingDestinationDescription {
                    from_port: Some(d.from),
                    to_port: Some(d.to),
                    protocols: Some(d.protocols.clone()),
                })
                .collect(),
        ),
        endpoint_descriptions: Some(
            g.endpoints
                .iter()
                .map(|e| types::CustomRoutingEndpointDescription { endpoint_id: Some(e.id.clone()) })
                .collect(),
        ),
    }
}

fn is_subnet_id(id: &str) -> bool {
    id.strip_prefix("subnet-").is_some_and(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Iterate the mappings of endpoint `e` from `skip` on, calling `f` until
/// it returns false.
fn mappings_of(
    l: &Listener,
    g: &EndpointGroup,
    e: &Endpoint,
    skip: u32,
    mut f: impl FnMut(types::PortMapping) -> bool,
) -> bool {
    let cidr = cidr_of(e);
    let ports = g.destination_ports();
    let per_ip = ports.len() as u32;
    let total = block_len(g, e);
    for offset in skip..total {
        let (ip_index, port_index) = (offset / per_ip, offset % per_ip);
        let ip = cidr.nth(u64::from(ip_index)).to_string();
        let (port, protocols) = &ports[port_index as usize];
        let Some(accelerator_port) = l.port_at(e.port_base + offset) else { return true };
        let m = types::PortMapping {
            accelerator_port: Some(accelerator_port),
            endpoint_group_arn: Some(g.arn.clone()),
            endpoint_id: Some(e.id.clone()),
            destination_socket_address: Some(types::SocketAddress { ip_address: Some(ip.clone()), port: Some(*port) }),
            protocols: Some(protocols.clone()),
            destination_traffic_state: Some(if allowed(e, &ip, *port) { "ALLOW" } else { "DENY" }.into()),
        };
        if !f(m) {
            return false;
        }
    }
    true
}

impl GlobalAccelerator {
    fn custom_endpoints(
        &self,
        st: &crate::state::State,
        a: &Accelerator,
        l: &Listener,
        g: &EndpointGroup,
        configs: &[types::CustomRoutingEndpointConfiguration],
        now: i64,
    ) -> Result<Vec<Endpoint>, ServiceError> {
        let mut taken = blocks(l);
        let mut out: Vec<Endpoint> = Vec::new();
        for c in configs {
            let id =
                c.endpoint_id.clone().filter(|i| !i.is_empty()).ok_or_else(|| invalid("EndpointId is required."))?;
            if !is_subnet_id(&id) {
                return Err(invalid(format!("The endpoint ID {id} is not valid. Specify a VPC subnet ID.")));
            }
            if g.endpoints.iter().any(|e| e.id == id) {
                return Err(errors::endpoint_already_exists(format!(
                    "Endpoint {id} already exists in the endpoint group."
                )));
            }
            if out.iter().any(|e| e.id == id) {
                return Err(invalid(format!("Endpoint {id} is specified more than once.")));
            }
            let (owner, attachment) =
                endpoint_owner(st, &a.account, &a.arn, &id, &g.region, None, c.attachment_arn.as_deref())?;
            let cidr = match self.lookup_subnet(&owner, &g.region, &id) {
                Lookup::Found(c) => c,
                Lookup::Missing => return Err(invalid(format!("Subnet {id} doesn't exist in Region {}.", g.region))),
                Lookup::NotMine => {
                    return Err(errors::internal_service_error("Subnets can't be looked up: EC2 isn't available."))
                }
            };
            let parsed = Cidr::parse(&cidr).ok_or_else(|| invalid(format!("Subnet {id} has no IPv4 CIDR block.")))?;
            let mut e = Endpoint {
                id: id.clone(),
                owner,
                attachment_arn: attachment,
                cidr: Some(cidr),
                added: now,
                ..Default::default()
            };
            let len = (parsed.size() * g.destination_ports().len() as u64).min(u64::from(u32::MAX)) as u32;
            e.port_base = place(l, len, &mut taken).ok_or_else(|| {
                invalid(format!(
                    "The listener doesn't have enough free ports for subnet {id}: it needs {len} ports (each address in the subnet times each destination port)."
                ))
            })?;
            out.push(e);
        }
        Ok(out)
    }

    pub fn create_custom_routing_endpoint_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomRoutingEndpointGroupRequest,
    ) -> Result<types::CreateCustomRoutingEndpointGroupResponse, ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, &input.listener_arn, true)?;
        authorize(ctx, "CreateCustomRoutingEndpointGroup", &l.arn, resource_tags(&a.tags))?;
        let key = format!("{}/CreateCustomRoutingEndpointGroup/{}", a.account, input.idempotency_token);
        if let Some(g) = st.idempotency.get(&key).and_then(|arn| l.groups.get(arn)) {
            return Ok(types::CreateCustomRoutingEndpointGroupResponse { endpoint_group: Some(describe_group(g)) });
        }
        let region = input.endpoint_group_region.clone();
        check_region(&region)?;
        if l.groups.values().any(|g| g.region == region) {
            return Err(errors::endpoint_group_already_exists(format!(
                "The listener already has an endpoint group in Region {region}."
            )));
        }
        let g = EndpointGroup {
            arn: names::group_arn(&l.arn),
            region,
            destinations: destinations(&input.destination_configurations)?,
            traffic_dial: 100.0,
            health_check_protocol: "TCP".into(),
            health_check_interval: 30,
            threshold_count: 3,
            ..Default::default()
        };
        let g = EndpointGroup { seq: st.next_seq(), ..g };
        st.idempotency.insert(key, g.arn.clone());
        store_group(&mut st, ctx, g.clone(), true, now);
        Ok(types::CreateCustomRoutingEndpointGroupResponse { endpoint_group: Some(describe_group(&g)) })
    }

    pub fn describe_custom_routing_endpoint_group(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCustomRoutingEndpointGroupRequest,
    ) -> Result<types::DescribeCustomRoutingEndpointGroupResponse, ServiceError> {
        let st = self.settled(ctx);
        let (a, _, g) = group(&st, ctx, &input.endpoint_group_arn, true)?;
        authorize(ctx, "DescribeCustomRoutingEndpointGroup", &g.arn, resource_tags(&a.tags))?;
        Ok(types::DescribeCustomRoutingEndpointGroupResponse { endpoint_group: Some(describe_group(g)) })
    }

    pub fn list_custom_routing_endpoint_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomRoutingEndpointGroupsRequest,
    ) -> Result<types::ListCustomRoutingEndpointGroupsResponse, ServiceError> {
        let st = self.settled(ctx);
        let (a, l) = listener(&st, ctx, &input.listener_arn, true)?;
        authorize(ctx, "ListCustomRoutingEndpointGroups", &l.arn, resource_tags(&a.tags))?;
        let mut items: Vec<&EndpointGroup> = l.groups.values().collect();
        items.sort_by_key(|g| g.seq);
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref(), 10)?;
        Ok(types::ListCustomRoutingEndpointGroupsResponse {
            endpoint_groups: Some(items.into_iter().map(describe_group).collect()),
            next_token,
        })
    }

    pub fn delete_custom_routing_endpoint_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomRoutingEndpointGroupRequest,
    ) -> Result<(), ServiceError> {
        self.delete_group_common(ctx, &input.endpoint_group_arn, true)
    }

    pub fn add_custom_routing_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::AddCustomRoutingEndpointsRequest,
    ) -> Result<types::AddCustomRoutingEndpointsResponse, ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, l, g) = group(&st, ctx, &input.endpoint_group_arn, true)?;
        authorize(ctx, "AddCustomRoutingEndpoints", &g.arn, resource_tags(&a.tags))?;
        if input.endpoint_configurations.is_empty() {
            return Err(invalid("You must specify at least one endpoint configuration."));
        }
        if g.endpoints.len() + input.endpoint_configurations.len() > ENDPOINT_LIMIT {
            return Err(errors::limit_exceeded(format!(
                "An endpoint group can have at most {ENDPOINT_LIMIT} endpoints."
            )));
        }
        let added = self.custom_endpoints(&st, a, l, g, &input.endpoint_configurations, now)?;
        let mut g = g.clone();
        g.endpoints.extend(added.iter().cloned());
        let arn = g.arn.clone();
        store_group(&mut st, ctx, g, true, now);
        Ok(types::AddCustomRoutingEndpointsResponse {
            endpoint_descriptions: Some(
                added
                    .iter()
                    .map(|e| types::CustomRoutingEndpointDescription { endpoint_id: Some(e.id.clone()) })
                    .collect(),
            ),
            endpoint_group_arn: Some(arn),
        })
    }

    pub fn remove_custom_routing_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::RemoveCustomRoutingEndpointsRequest,
    ) -> Result<(), ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, _, g) = group(&st, ctx, &input.endpoint_group_arn, true)?;
        authorize(ctx, "RemoveCustomRoutingEndpoints", &g.arn, resource_tags(&a.tags))?;
        if let Some(missing) = input.endpoint_ids.iter().find(|id| !g.endpoints.iter().any(|e| &e.id == *id)) {
            return Err(errors::endpoint_not_found(format!("Endpoint {missing} isn't in the endpoint group.")));
        }
        let mut g = g.clone();
        g.endpoints.retain(|e| !input.endpoint_ids.contains(&e.id));
        store_group(&mut st, ctx, g, true, now);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn traffic(
        &self,
        ctx: &RequestContext,
        op: &str,
        group_arn: &str,
        endpoint_id: &str,
        addresses: Option<Vec<String>>,
        ports: Option<Vec<i32>>,
        all: Option<bool>,
        allow: bool,
    ) -> Result<(), ServiceError> {
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let (a, _, g) = group(&st, ctx, group_arn, true)?;
        authorize(ctx, op, &g.arn, resource_tags(&a.tags))?;
        let mut g = g.clone();
        let destination_ports = g.destination_ports();
        let e = g
            .endpoints
            .iter_mut()
            .find(|e| e.id == endpoint_id)
            .ok_or_else(|| invalid(format!("Endpoint {endpoint_id} isn't in the endpoint group.")))?;
        let addresses = addresses.filter(|a| !a.is_empty());
        let ports = ports.filter(|p| !p.is_empty());
        if all == Some(true) {
            if addresses.is_some() || ports.is_some() {
                let flag = if allow { "AllowAllTrafficToEndpoint" } else { "DenyAllTrafficToEndpoint" };
                return Err(invalid(format!(
                    "You can't specify DestinationAddresses or DestinationPorts when {flag} is true."
                )));
            }
            e.allow_all = allow;
            e.traffic_rules.clear();
        } else {
            if addresses.is_none() && ports.is_none() {
                return Err(invalid("Specify DestinationAddresses, DestinationPorts, or both."));
            }
            let cidr = cidr_of(e);
            for ip in addresses.iter().flatten() {
                let ok = ip.parse::<Ipv4Addr>().is_ok_and(|p| cidr.contains(p));
                if !ok {
                    return Err(invalid(format!("Destination address {ip} isn't in subnet {endpoint_id}.")));
                }
            }
            for p in ports.iter().flatten() {
                if !destination_ports.iter().any(|(d, _)| d == p) {
                    return Err(invalid(format!(
                        "Destination port {p} isn't in the endpoint group's destination port ranges."
                    )));
                }
            }
            e.traffic_rules.push(TrafficRule { allow, addresses, ports });
        }
        store_group(&mut st, ctx, g, true, now);
        Ok(())
    }

    pub fn allow_custom_routing_traffic(
        &self,
        ctx: &RequestContext,
        input: types::AllowCustomRoutingTrafficRequest,
    ) -> Result<(), ServiceError> {
        self.traffic(
            ctx,
            "AllowCustomRoutingTraffic",
            &input.endpoint_group_arn,
            &input.endpoint_id,
            input.destination_addresses,
            input.destination_ports,
            input.allow_all_traffic_to_endpoint,
            true,
        )
    }

    pub fn deny_custom_routing_traffic(
        &self,
        ctx: &RequestContext,
        input: types::DenyCustomRoutingTrafficRequest,
    ) -> Result<(), ServiceError> {
        self.traffic(
            ctx,
            "DenyCustomRoutingTraffic",
            &input.endpoint_group_arn,
            &input.endpoint_id,
            input.destination_addresses,
            input.destination_ports,
            input.deny_all_traffic_to_endpoint,
            false,
        )
    }

    pub fn list_custom_routing_port_mappings(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomRoutingPortMappingsRequest,
    ) -> Result<types::ListCustomRoutingPortMappingsResponse, ServiceError> {
        let st = self.settled(ctx);
        let a = find(&st, ctx, &input.accelerator_arn, true)?;
        authorize(ctx, "ListCustomRoutingPortMappings", &a.arn, resource_tags(&a.tags))?;
        if let Some(g) = &input.endpoint_group_arn {
            group(&st, ctx, g, true)?;
            if names::parse(g).map(|p| p.accelerator) != Some(a.arn.clone()) {
                return Err(names::group_not_found(g));
            }
        }
        let start = match &input.next_token {
            None => 0,
            Some(t) => names::decode_token(t)?,
        };
        let max = input.max_results.map(|m| m.clamp(1, 20_000) as usize).unwrap_or(10_000);
        let mut listeners: Vec<&Listener> = a.listeners.values().collect();
        listeners.sort_by_key(|l| l.seq);
        let mut out = Vec::new();
        let mut index = 0usize;
        let mut more = false;
        'outer: for l in listeners {
            let mut groups: Vec<&EndpointGroup> =
                l.groups.values().filter(|g| input.endpoint_group_arn.as_deref().is_none_or(|x| x == g.arn)).collect();
            groups.sort_by_key(|g| g.seq);
            for g in groups {
                for e in &g.endpoints {
                    let len = block_len(g, e) as usize;
                    if index + len <= start {
                        index += len;
                        continue;
                    }
                    let skip = start.saturating_sub(index) as u32;
                    index += skip as usize;
                    let finished = mappings_of(l, g, e, skip, |m| {
                        if out.len() == max {
                            more = true;
                            return false;
                        }
                        out.push(m);
                        index += 1;
                        true
                    });
                    if !finished {
                        break 'outer;
                    }
                }
            }
        }
        Ok(types::ListCustomRoutingPortMappingsResponse {
            port_mappings: Some(out),
            next_token: more.then(|| names::encode_token(index)),
        })
    }

    pub fn list_custom_routing_port_mappings_by_destination(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomRoutingPortMappingsByDestinationRequest,
    ) -> Result<types::ListCustomRoutingPortMappingsByDestinationResponse, ServiceError> {
        authorize(ctx, "ListCustomRoutingPortMappingsByDestination", "*", Default::default())?;
        let ip: Ipv4Addr = input.destination_address.parse().map_err(|_| {
            invalid(format!("DestinationAddress {} is not a valid IPv4 address.", input.destination_address))
        })?;
        let st = self.settled(ctx);
        let mut accelerators: Vec<&Accelerator> =
            st.accelerators.values().filter(|a| a.custom && a.account == ctx.caller.account_id).collect();
        accelerators.sort_by_key(|a| a.seq);
        let mut found = false;
        let mut out = Vec::new();
        for a in accelerators {
            let mut listeners: Vec<&Listener> = a.listeners.values().collect();
            listeners.sort_by_key(|l| l.seq);
            for l in listeners {
                let mut groups: Vec<&EndpointGroup> = l.groups.values().collect();
                groups.sort_by_key(|g| g.seq);
                for g in groups {
                    for e in g.endpoints.iter().filter(|e| e.id == input.endpoint_id) {
                        found = true;
                        let cidr = cidr_of(e);
                        let Some(ip_index) = cidr.index_of(ip) else { continue };
                        let ports = g.destination_ports();
                        for (port_index, (port, _)) in ports.iter().enumerate() {
                            let offset = ip_index as u32 * ports.len() as u32 + port_index as u32;
                            let Some(accelerator_port) = l.port_at(e.port_base + offset) else { continue };
                            let socket = |ip: &String| types::SocketAddress {
                                ip_address: Some(ip.clone()),
                                port: Some(accelerator_port),
                            };
                            out.push(types::DestinationPortMapping {
                                accelerator_arn: Some(a.arn.clone()),
                                accelerator_socket_addresses: Some(a.ipv4.iter().chain(&a.ipv6).map(socket).collect()),
                                endpoint_group_arn: Some(g.arn.clone()),
                                endpoint_id: Some(e.id.clone()),
                                endpoint_group_region: Some(g.region.clone()),
                                destination_socket_address: Some(types::SocketAddress {
                                    ip_address: Some(ip.to_string()),
                                    port: Some(*port),
                                }),
                                ip_address_type: Some("IPv4".into()),
                                destination_traffic_state: Some(
                                    if allowed(e, &ip.to_string(), *port) { "ALLOW" } else { "DENY" }.into(),
                                ),
                            });
                        }
                    }
                }
            }
        }
        if !found {
            return Err(errors::endpoint_not_found(format!(
                "Endpoint {} isn't in any of your custom routing accelerators.",
                input.endpoint_id
            )));
        }
        let (items, next_token) = page(out, input.max_results, input.next_token.as_deref(), 10_000)?;
        Ok(types::ListCustomRoutingPortMappingsByDestinationResponse {
            destination_port_mappings: Some(items),
            next_token,
        })
    }
}
