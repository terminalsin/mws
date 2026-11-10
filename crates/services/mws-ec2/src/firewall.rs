//! What an instance's traffic may do, worked out from VPC state the way EC2
//! decides it (security groups, the subnet's network ACL and route table),
//! and kept applied through the compute backend as that state changes.

use std::collections::HashMap;
use std::sync::Arc;

use crate::backend::{AclRule, AllowRule, Firewall, Protocol, RouteRule};
use crate::generated::types as t;
use crate::state::{RegionState, State};
use crate::util::Cidr;
use crate::Ec2;

fn port(p: Option<i32>, default: u16) -> u16 {
    match p {
        Some(n) if (0..=65535).contains(&n) => n as u16,
        _ => default,
    }
}

/// A protocol name or number with EC2's port fields (`-1` means all).
fn protocol(name: &str, from: Option<i32>, to: Option<i32>) -> Option<Protocol> {
    let all_ports = from.is_none_or(|f| f < 0) && to.is_none_or(|t| t < 0);
    Some(match name.to_ascii_lowercase().as_str() {
        "-1" | "all" => Protocol::All,
        "tcp" | "6" if all_ports => Protocol::Tcp(0, 65535),
        "tcp" | "6" => Protocol::Tcp(port(from, 0), port(to, 65535)),
        "udp" | "17" if all_ports => Protocol::Udp(0, 65535),
        "udp" | "17" => Protocol::Udp(port(from, 0), port(to, 65535)),
        "icmp" | "1" => {
            let t = from.filter(|v| (0..=255).contains(v)).map(|v| v as u8);
            let c = to.filter(|v| (0..=255).contains(v)).map(|v| v as u8);
            Protocol::Icmp(t, c)
        }
        // IPv6-only protocols never match the IPv4 traffic instances have.
        "icmpv6" | "58" => return None,
        n => Protocol::Number(n.parse().ok()?),
    })
}

/// The private addresses of every interface in a security group.
fn group_members(r: &RegionState, group_id: &str) -> Vec<String> {
    let mut ips: Vec<String> = r
        .network_interfaces
        .values()
        .filter(|n| n.groups.iter().flatten().any(|g| g.group_id.as_deref() == Some(group_id)))
        .flat_map(|n| n.private_ip_addresses.iter().flatten().filter_map(|p| p.private_ip_address.clone()))
        .map(|ip| format!("{ip}/32"))
        .collect();
    ips.sort();
    ips.dedup();
    ips
}

fn sg_rules(r: &RegionState, region: &str, groups: &[String], egress: bool) -> Vec<AllowRule> {
    let mut out = Vec::new();
    for rule in r.sg_rules.values().filter(|x| x.egress == egress && groups.contains(&x.group_id)) {
        let Some(p) = protocol(&rule.protocol, rule.from_port, rule.to_port) else { continue };
        let cidrs: Vec<String> = if let Some(c) = &rule.cidr_ipv4 {
            vec![c.clone()]
        } else if let Some(pl) = &rule.prefix_list_id {
            crate::ops::endpoint::prefix_list_cidrs(r, region, pl).unwrap_or_default()
        } else if let Some(g) = &rule.referenced_group_id {
            group_members(r, g)
        } else {
            Vec::new()
        };
        for cidr in cidrs.into_iter().filter(|c| Cidr::parse(c).is_some()) {
            let rule = AllowRule { protocol: p.clone(), cidr };
            if !out.contains(&rule) {
                out.push(rule);
            }
        }
    }
    out
}

fn acl_rules(acl: Option<&t::NetworkAcl>, egress: bool) -> Vec<AclRule> {
    let mut entries: Vec<&t::NetworkAclEntry> = acl
        .into_iter()
        .flat_map(|a| a.entries.iter().flatten())
        .filter(|e| e.egress == Some(egress) && e.cidr_block.is_some())
        .collect();
    entries.sort_by_key(|e| e.rule_number.unwrap_or(i32::MAX));
    entries
        .into_iter()
        .filter_map(|e| {
            let name = e.protocol.as_deref().unwrap_or("-1");
            let p = if matches!(name, "1" | "icmp") {
                let tc = e.icmp_type_code.clone().unwrap_or_default();
                protocol(name, tc.r#type, tc.code)?
            } else {
                let range = e.port_range.clone().unwrap_or_default();
                protocol(name, range.from, range.to)?
            };
            Some(AclRule { protocol: p, cidr: e.cidr_block.clone()?, allow: e.rule_action.as_deref() == Some("allow") })
        })
        .collect()
}

/// The route table that governs a subnet: its own association, else the
/// VPC's main table.
pub fn subnet_route_table<'a>(r: &'a RegionState, vpc_id: &str, subnet_id: &str) -> Option<&'a t::RouteTable> {
    let explicit = r
        .route_tables
        .values()
        .find(|rt| rt.associations.iter().flatten().any(|a| a.subnet_id.as_deref() == Some(subnet_id)));
    explicit.or_else(|| {
        r.route_tables.values().find(|rt| {
            rt.vpc_id.as_deref() == Some(vpc_id) && rt.associations.iter().flatten().any(|a| a.main == Some(true))
        })
    })
}

fn route_destinations(r: &RegionState, region: &str, route: &t::Route) -> Vec<String> {
    if let Some(c) = &route.destination_cidr_block {
        return vec![c.clone()];
    }
    if let Some(pl) = &route.destination_prefix_list_id {
        return crate::ops::endpoint::prefix_list_cidrs(r, region, pl).unwrap_or_default();
    }
    Vec::new()
}

fn igw_attached(r: &RegionState, igw: &str, vpc_id: &str) -> bool {
    r.internet_gateways
        .get(igw)
        .is_some_and(|g| g.attachments.iter().flatten().any(|a| a.vpc_id.as_deref() == Some(vpc_id)))
}

/// Whether a NAT gateway can carry traffic to `dest` out of the VPC: it is
/// available, public, and its own subnet routes `dest` to an attached
/// internet gateway.
fn nat_reaches(r: &RegionState, region: &str, nat_id: &str, dest: &Cidr) -> bool {
    let Some(nat) = r.nat_gateways.get(nat_id) else { return false };
    if nat.state.as_deref() != Some("available") || nat.connectivity_type.as_deref() == Some("private") {
        return false;
    }
    let (Some(vpc), Some(subnet)) = (&nat.vpc_id, &nat.subnet_id) else { return false };
    let Some(rt) = subnet_route_table(r, vpc, subnet) else { return false };
    let mut best: Option<(u8, bool)> = None;
    for route in rt.routes.iter().flatten().filter(|x| x.state.as_deref() != Some("blackhole")) {
        for d in route_destinations(r, region, route) {
            let Some(c) = Cidr::parse(&d) else { continue };
            if !c.contains_cidr(dest) || best.is_some_and(|(p, _)| p >= c.prefix) {
                continue;
            }
            let ok = route.gateway_id.as_deref().is_some_and(|g| g.starts_with("igw-") && igw_attached(r, g, vpc));
            best = Some((c.prefix, ok));
        }
    }
    best.is_some_and(|(_, ok)| ok)
}

/// The firewall an instance should have now, or `None` if it has no
/// network interface.
pub fn firewall_for(r: &RegionState, region: &str, instance_id: &str, service_port: Option<u16>) -> Option<Firewall> {
    let enis: Vec<&t::NetworkInterface> = r
        .network_interfaces
        .values()
        .filter(|n| n.attachment.as_ref().and_then(|a| a.instance_id.as_deref()) == Some(instance_id))
        .collect();
    let primary =
        enis.iter().find(|n| n.attachment.as_ref().and_then(|a| a.device_index) == Some(0)).or(enis.first())?;
    let vpc_id = primary.vpc_id.clone()?;
    let subnet_id = primary.subnet_id.clone()?;
    let subnet = r.subnets.get(&subnet_id)?;
    let vpc = r.vpcs.get(&vpc_id)?;
    let mut groups: Vec<String> =
        enis.iter().flat_map(|n| n.groups.iter().flatten().filter_map(|g| g.group_id.clone())).collect();
    groups.sort();
    groups.dedup();
    let vpc_cidrs: Vec<String> = vpc
        .vpc
        .cidr_block_association_set
        .iter()
        .flatten()
        .filter(|a| a.cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) != Some("disassociated"))
        .filter_map(|a| a.cidr_block.clone())
        .chain(vpc.vpc.cidr_block.clone())
        .fold(Vec::new(), |mut v, c| {
            if !v.contains(&c) {
                v.push(c);
            }
            v
        });
    let acl = r
        .network_acls
        .values()
        .find(|a| a.associations.iter().flatten().any(|x| x.subnet_id.as_deref() == Some(subnet_id.as_str())));
    let public = primary.association.as_ref().is_some_and(|a| a.public_ip.is_some());
    // Routes out of the VPC, longest prefix first.
    let mut routes: Vec<(Cidr, RouteRule)> = Vec::new();
    if let Some(rt) = subnet_route_table(r, &vpc_id, &subnet_id) {
        for route in rt.routes.iter().flatten() {
            if route.gateway_id.as_deref() == Some("local") {
                continue;
            }
            let active = route.state.as_deref() != Some("blackhole");
            for d in route_destinations(r, region, route) {
                let Some(c) = Cidr::parse(&d) else { continue };
                let reachable = active
                    && if let Some(g) = &route.gateway_id {
                        if g.starts_with("igw-") {
                            public && igw_attached(r, g, &vpc_id)
                        } else {
                            // Gateway endpoints reach their service.
                            g.starts_with("vpce-")
                        }
                    } else if let Some(nat) = &route.nat_gateway_id {
                        nat_reaches(r, region, nat, &c)
                    } else {
                        // Appliances (instances, interfaces) forward what they get.
                        route.instance_id.is_some() || route.network_interface_id.is_some()
                    };
                routes.push((c, RouteRule { cidr: d, reachable }));
            }
        }
    }
    routes.sort_by_key(|r| std::cmp::Reverse(r.0.prefix));
    Some(Firewall {
        subnet_cidr: subnet.cidr_block.clone().unwrap_or_default(),
        vpc_cidrs,
        ingress: sg_rules(r, region, &groups, false),
        egress: sg_rules(r, region, &groups, true),
        acl_ingress: acl_rules(acl, false),
        acl_egress: acl_rules(acl, true),
        routes: routes.into_iter().map(|(_, r)| r).collect(),
        service_port,
    })
}

/// Firewalls the backend has been given, by instance id.
#[derive(Default)]
pub(crate) struct Applied {
    pub(crate) rules: std::sync::Mutex<HashMap<String, Firewall>>,
    pub(crate) wake: Arc<tokio::sync::Notify>,
    pub(crate) started: std::sync::atomic::AtomicBool,
    /// MWS's port, as instances reach it.
    pub(crate) service_port: std::sync::Mutex<Option<u16>>,
}

/// The firewalls every running instance should have, with their handles.
fn desired(state: &State, service_port: Option<u16>) -> Vec<(String, String, Firewall)> {
    let mut out = Vec::new();
    for (key, r) in &state.regions {
        let region = key.split_once('/').map(|(_, r)| r).unwrap_or_default();
        for (id, rec) in &r.instances {
            let st = rec.instance.state.as_ref().and_then(|s| s.name.as_deref()).unwrap_or_default();
            let (Some(handle), true) = (&rec.handle, matches!(st, "running" | "pending")) else { continue };
            if let Some(fw) = firewall_for(r, region, id, service_port) {
                out.push((id.clone(), handle.clone(), fw));
            }
        }
    }
    out
}

impl Ec2 {
    /// Note the port MWS serves on (from a request's endpoint).
    pub(crate) fn note_endpoint(&self, endpoint: Option<&str>) {
        let port = endpoint.and_then(|e| {
            let rest = e.split("://").nth(1).unwrap_or(e);
            let host = rest.split('/').next().unwrap_or_default();
            host.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok())
        });
        if let Some(p) = port {
            *self.inner.firewalls.service_port.lock().expect("lock") = Some(p);
        }
    }

    fn service_port(&self) -> Option<u16> {
        *self.inner.firewalls.service_port.lock().expect("lock")
    }

    /// Bring every instance's firewall up to date with VPC state, in the
    /// background. Cheap when nothing changed.
    pub(crate) fn sync_firewalls(&self) {
        if !self.inner.backend.filters_traffic() {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        if !self.inner.firewalls.started.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let weak = Arc::downgrade(&self.inner);
            let wake = self.inner.firewalls.wake.clone();
            rt.spawn(async move {
                loop {
                    wake.notified().await;
                    // Let a burst of changes settle.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let Some(inner) = weak.upgrade() else { return };
                    Ec2 { inner }.apply_changed_firewalls().await;
                }
            });
        }
        self.inner.firewalls.wake.notify_one();
    }

    async fn apply_changed_firewalls(&self) {
        let want = desired(&self.lock(), self.service_port());
        let changed: Vec<(String, String, Firewall)> = {
            let mut applied = self.inner.firewalls.rules.lock().expect("lock");
            applied.retain(|id, _| want.iter().any(|(w, _, _)| w == id));
            want.into_iter().filter(|(id, _, fw)| applied.get(id) != Some(fw)).collect()
        };
        let backend = self.backend();
        let tasks = changed.into_iter().map(|(id, handle, fw)| {
            let backend = backend.clone();
            let this = self.clone();
            async move {
                match backend.apply_firewall(&handle, &fw).await {
                    Ok(()) => {
                        this.inner.firewalls.rules.lock().expect("lock").insert(id, fw);
                    }
                    Err(e) => tracing::warn!(instance = %id, "applying security groups: {e}"),
                }
            }
        });
        futures_join_all(tasks).await;
    }

    /// Set up a freshly booted instance's firewall before it runs user
    /// data.
    pub(crate) async fn firewall_on_boot(&self, account: &str, region: &str, instance_id: &str, handle: &str) {
        let backend = self.backend();
        if !backend.filters_traffic() {
            return;
        }
        let fw = {
            let state = self.lock();
            state
                .regions
                .get(&State::key(account, region))
                .and_then(|r| firewall_for(r, region, instance_id, self.service_port()))
        };
        if let Some(fw) = fw {
            match backend.apply_firewall(handle, &fw).await {
                Ok(()) => {
                    self.inner.firewalls.rules.lock().expect("lock").insert(instance_id.to_string(), fw);
                }
                Err(e) => {
                    self.inner.firewalls.rules.lock().expect("lock").remove(instance_id);
                    tracing::warn!(instance = %instance_id, "applying security groups: {e}");
                }
            }
        }
        let _ = backend.network_ready(handle).await;
    }
}

/// Wait for every future (no extra dependency for one join).
async fn futures_join_all<F: std::future::Future<Output = ()> + Send + 'static>(tasks: impl Iterator<Item = F>) {
    let handles: Vec<_> = tasks.map(tokio::spawn).collect();
    for h in handles {
        let _ = h.await;
    }
}

impl Ec2 {
    /// Whether security groups `groups` (in `account` and `region`) let
    /// TCP or UDP traffic to `port` in from `source`, as for a load
    /// balancer's front end. No groups means no filtering.
    pub fn security_groups_allow(
        &self,
        account: &str,
        region: &str,
        groups: &[String],
        udp: bool,
        port: u16,
        source: std::net::IpAddr,
    ) -> bool {
        if groups.is_empty() {
            return true;
        }
        let source = match source {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4,
                None if v6.is_loopback() => std::net::Ipv4Addr::LOCALHOST,
                // IPv6 sources: only rules open to every IPv6 address match.
                None => {
                    let st = self.lock();
                    let Some(r) = st.regions.get(&State::key(account, region)) else { return false };
                    return r
                        .sg_rules
                        .values()
                        .any(|x| !x.egress && groups.contains(&x.group_id) && x.cidr_ipv6.as_deref() == Some("::/0"));
                }
            },
        };
        let ip = u32::from(source);
        let st = self.lock();
        let Some(r) = st.regions.get(&State::key(account, region)) else { return false };
        sg_rules(r, region, groups, false).iter().any(|rule| {
            let proto = match rule.protocol {
                Protocol::All => true,
                Protocol::Tcp(a, b) => !udp && (a..=b).contains(&port),
                Protocol::Udp(a, b) => udp && (a..=b).contains(&port),
                _ => false,
            };
            proto && Cidr::parse(&rule.cidr).is_some_and(|c| c.contains(ip))
        })
    }
}
