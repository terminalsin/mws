//! What other services read about EC2 networking and instances. Elastic
//! Load Balancing places load balancers in subnets, checks security groups
//! and sends traffic to instances' private addresses, as it does in AWS.

use mws_core::RequestContext;

use crate::generated::types as t;
use crate::ops::eni::{new_eni, resolve_groups};
use crate::state::RegionState;
use crate::util::{parse_ip, Cidr};
use crate::Ec2;

/// A subnet as other services see it.
#[derive(Debug, Clone)]
pub struct SubnetInfo {
    pub subnet_id: String,
    pub vpc_id: String,
    pub availability_zone: String,
    pub availability_zone_id: String,
    pub cidr_block: Option<String>,
    pub ipv6_cidr_blocks: Vec<String>,
}

/// A VPC as other services see it.
#[derive(Debug, Clone)]
pub struct VpcInfo {
    pub vpc_id: String,
    /// Associated IPv4 CIDR blocks, primary first.
    pub cidr_blocks: Vec<String>,
    pub ipv6_cidr_blocks: Vec<String>,
    pub is_default: bool,
    /// The VPC's `default` security group.
    pub default_security_group: Option<String>,
}

/// A security group as other services see it.
#[derive(Debug, Clone)]
pub struct SecurityGroupInfo {
    pub group_id: String,
    pub group_name: String,
    pub vpc_id: String,
}

/// An instance as other services see it.
#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub instance_id: String,
    /// `pending`, `running`, `stopping`, `stopped`, `shutting-down` or
    /// `terminated`.
    pub state: String,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub availability_zone: Option<String>,
    pub private_ip: Option<String>,
    pub ipv6_addresses: Vec<String>,
    /// Whether nothing runs the instance (the metadata backend launched
    /// it), so nothing can answer health checks or traffic.
    pub runs_nothing: bool,
}

impl Ec2 {
    /// A subnet in `account` and the request's Region.
    pub fn subnet_info(&self, ctx: &RequestContext, account: &str, subnet_id: &str) -> Option<SubnetInfo> {
        self.with_region_of(account, &ctx.region, ctx, |r| {
            let s = r.subnets.get(subnet_id)?;
            Some(SubnetInfo {
                subnet_id: subnet_id.to_string(),
                vpc_id: s.vpc_id.clone().unwrap_or_default(),
                availability_zone: s.availability_zone.clone().unwrap_or_default(),
                availability_zone_id: s.availability_zone_id.clone().unwrap_or_default(),
                cidr_block: s.cidr_block.clone(),
                ipv6_cidr_blocks: s
                    .ipv6_cidr_block_association_set
                    .iter()
                    .flatten()
                    .filter_map(|a| a.ipv6_cidr_block.clone())
                    .collect(),
            })
        })
    }

    /// The subnets of a VPC (the default VPC when `vpc_id` is `None`).
    pub fn subnets_of_vpc(&self, ctx: &RequestContext, account: &str, vpc_id: Option<&str>) -> Vec<SubnetInfo> {
        let vpc = match vpc_id {
            Some(v) => v.to_string(),
            None => match self.vpc_info(ctx, account, None) {
                Some(v) => v.vpc_id,
                None => return Vec::new(),
            },
        };
        let ids: Vec<String> = self.with_region_of(account, &ctx.region, ctx, |r| {
            r.subnets
                .iter()
                .filter(|(_, s)| s.vpc_id.as_deref() == Some(vpc.as_str()))
                .map(|(id, _)| id.clone())
                .collect()
        });
        ids.iter().filter_map(|id| self.subnet_info(ctx, account, id)).collect()
    }

    /// A VPC in `account` and the request's Region; `None` for the default
    /// VPC lookup when the Region has none.
    pub fn vpc_info(&self, ctx: &RequestContext, account: &str, vpc_id: Option<&str>) -> Option<VpcInfo> {
        self.with_region_of(account, &ctx.region, ctx, |r| {
            let v = match vpc_id {
                Some(id) => r.vpcs.get(id)?,
                None => r.vpcs.values().find(|v| v.vpc.is_default == Some(true))?,
            };
            let id = v.vpc.vpc_id.clone().unwrap_or_default();
            let mut cidrs: Vec<String> = v.vpc.cidr_block.iter().cloned().collect();
            for a in v.vpc.cidr_block_association_set.iter().flatten() {
                let associated =
                    a.cidr_block_state.as_ref().and_then(|s| s.state.as_deref()).is_none_or(|s| s == "associated");
                if let Some(c) = &a.cidr_block {
                    if associated && !cidrs.contains(c) {
                        cidrs.push(c.clone());
                    }
                }
            }
            let default_security_group = r
                .security_groups
                .values()
                .find(|g| g.vpc_id.as_deref() == Some(id.as_str()) && g.group_name.as_deref() == Some("default"))
                .and_then(|g| g.group_id.clone());
            Some(VpcInfo {
                vpc_id: id,
                cidr_blocks: cidrs,
                ipv6_cidr_blocks: v
                    .vpc
                    .ipv6_cidr_block_association_set
                    .iter()
                    .flatten()
                    .filter_map(|a| a.ipv6_cidr_block.clone())
                    .collect(),
                is_default: v.vpc.is_default == Some(true),
                default_security_group,
            })
        })
    }

    /// A security group in `account` and the request's Region.
    pub fn security_group_info(
        &self,
        ctx: &RequestContext,
        account: &str,
        group_id: &str,
    ) -> Option<SecurityGroupInfo> {
        self.with_region_of(account, &ctx.region, ctx, |r| {
            let g = r.security_groups.get(group_id)?;
            Some(SecurityGroupInfo {
                group_id: group_id.to_string(),
                group_name: g.group_name.clone().unwrap_or_default(),
                vpc_id: g.vpc_id.clone().unwrap_or_default(),
            })
        })
    }

    /// An instance in `account` and `region`, if EC2 knows it there. This
    /// needs no request: load balancers look targets up from background
    /// health checks.
    pub fn instance_info(&self, account: &str, region: &str, instance_id: &str) -> Option<InstanceInfo> {
        let state = self.lock();
        let r = state.regions.get(&crate::state::State::key(account, region))?;
        let rec = r.instances.get(instance_id)?;
        let i = &rec.instance;
        Some(InstanceInfo {
            instance_id: instance_id.to_string(),
            state: i.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default(),
            vpc_id: i.vpc_id.clone(),
            subnet_id: i.subnet_id.clone(),
            availability_zone: i.placement.as_ref().and_then(|p| p.availability_zone.clone()),
            private_ip: i.private_ip_address.clone(),
            ipv6_addresses: i
                .network_interfaces
                .iter()
                .flatten()
                .flat_map(|n| n.ipv6_addresses.iter().flatten())
                .filter_map(|a| a.ipv6_address.clone())
                .collect(),
            runs_nothing: match rec.handle.as_deref() {
                // The metadata backend hands out instance ids as handles.
                Some(h) => h.starts_with("i-"),
                None => self.backend_name() == "metadata",
            },
        })
    }
}

/// A network interface a service asks for in a customer's subnet.
#[derive(Debug, Clone, Default)]
pub struct ServiceInterfaceRequest {
    pub subnet_id: String,
    /// The primary private IPv4 address; the next free one when `None`.
    pub ip_address: Option<String>,
    /// Security group ids; the VPC's default group when empty.
    pub security_groups: Vec<String>,
    pub description: String,
    /// `interface`, `efs`, `nat_gateway`, ...
    pub interface_type: String,
    /// The service that manages the interface (an AWS account id or service
    /// principal), reported as `RequesterId`.
    pub requester_id: String,
}

/// An interface made by [`Ec2::create_service_interface`].
#[derive(Debug, Clone)]
pub struct ServiceInterface {
    pub network_interface_id: String,
    pub ip_address: String,
    pub security_groups: Vec<String>,
}

/// Why a service interface could not be made, for the calling service to
/// word in its own terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceInterfaceError {
    SubnetNotFound(String),
    SecurityGroupNotFound(String),
    /// The group is in another VPC than the subnet.
    SecurityGroupInOtherVpc(String),
    /// The address is malformed or outside the subnet's usable range.
    InvalidIpAddress(String),
    IpAddressInUse(String),
    NoFreeAddresses,
    NetworkInterfaceNotFound(String),
}

/// Where an instance sits on the network.
#[derive(Debug, Clone)]
pub struct InstanceNetwork {
    pub instance_id: String,
    pub account_id: String,
    pub region: String,
    /// `pending`, `running`, `stopped`, ...
    pub state: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub availability_zone: String,
    pub private_ip: String,
    pub security_groups: Vec<String>,
    /// The instance profile's role, if any.
    pub role_arn: Option<String>,
}

impl Ec2 {
    /// Check that every one of `groups` exists in `vpc_id` (or name the
    /// first that does not).
    pub fn check_security_groups(
        &self,
        ctx: &RequestContext,
        account: &str,
        vpc_id: &str,
        groups: &[String],
    ) -> Result<(), ServiceInterfaceError> {
        self.with_region_of(account, &ctx.region, ctx, |r| check_groups(r, vpc_id, groups))
    }

    /// Make a requester-managed network interface for a service. It is
    /// `in-use` from the start, so customers cannot delete it themselves.
    pub fn create_service_interface(
        &self,
        ctx: &RequestContext,
        account: &str,
        req: &ServiceInterfaceRequest,
    ) -> Result<ServiceInterface, ServiceInterfaceError> {
        let region = ctx.region.clone();
        let now = ctx.received_at;
        self.with_region_of(account, &ctx.region, ctx, |r| {
            let subnet = r
                .subnets
                .get(&req.subnet_id)
                .cloned()
                .ok_or_else(|| ServiceInterfaceError::SubnetNotFound(req.subnet_id.clone()))?;
            let vpc_id = subnet.vpc_id.clone().unwrap_or_default();
            check_groups(r, &vpc_id, &req.security_groups)?;
            let groups = resolve_groups(r, &vpc_id, Some(&req.security_groups))
                .map_err(|_| ServiceInterfaceError::SecurityGroupNotFound(req.security_groups.join(",")))?;
            let ip = match &req.ip_address {
                Some(ip) => {
                    check_ip(r, &subnet, ip)?;
                    ip.clone()
                }
                None => {
                    crate::ops::vpc::allocate_ip(r, &req.subnet_id).ok_or(ServiceInterfaceError::NoFreeAddresses)?
                }
            };
            let id = new_eni(
                r,
                account,
                &region,
                &subnet,
                &ip,
                groups.clone(),
                &req.description,
                if req.interface_type.is_empty() { "interface" } else { &req.interface_type },
                now,
            );
            let eni = r.network_interfaces.get_mut(&id).expect("just made");
            eni.requester_managed = Some(true);
            eni.requester_id = Some(req.requester_id.clone());
            eni.status = Some("in-use".into());
            Ok(ServiceInterface {
                network_interface_id: id,
                ip_address: ip,
                security_groups: groups.into_iter().filter_map(|g| g.group_id).collect(),
            })
        })
    }

    /// Replace the security groups of a service interface.
    pub fn set_service_interface_groups(
        &self,
        ctx: &RequestContext,
        account: &str,
        network_interface_id: &str,
        groups: &[String],
    ) -> Result<Vec<String>, ServiceInterfaceError> {
        self.with_region_of(account, &ctx.region, ctx, |r| {
            let vpc_id = r
                .network_interfaces
                .get(network_interface_id)
                .and_then(|n| n.vpc_id.clone())
                .ok_or_else(|| ServiceInterfaceError::NetworkInterfaceNotFound(network_interface_id.into()))?;
            check_groups(r, &vpc_id, groups)?;
            let resolved = resolve_groups(r, &vpc_id, Some(groups))
                .map_err(|_| ServiceInterfaceError::SecurityGroupNotFound(groups.join(",")))?;
            let eni = r.network_interfaces.get_mut(network_interface_id).expect("checked");
            eni.groups = Some(resolved.clone());
            Ok(resolved.into_iter().filter_map(|g| g.group_id).collect())
        })
    }

    /// Remove a service interface (a no-op when it is already gone).
    pub fn delete_service_interface(&self, ctx: &RequestContext, account: &str, network_interface_id: &str) {
        self.with_region_of(account, &ctx.region, ctx, |r| {
            r.network_interfaces.remove(network_interface_id);
        })
    }

    /// Where `instance_id` sits, in whichever account and Region it lives.
    pub fn instance_network(&self, instance_id: &str) -> Option<InstanceNetwork> {
        let st = self.lock();
        for (key, r) in &st.regions {
            let Some(rec) = r.instances.get(instance_id) else { continue };
            let (account, region) = key.split_once('/').unwrap_or_default();
            let i = &rec.instance;
            // The instance's groups live on its primary interface.
            let eni = crate::ops::eni::primary_eni(r, instance_id).and_then(|e| r.network_interfaces.get(&e));
            let security_groups = match eni {
                Some(n) => n.groups.iter().flatten().filter_map(|g| g.group_id.clone()).collect(),
                None => i.security_groups.iter().flatten().filter_map(|g| g.group_id.clone()).collect(),
            };
            return Some(InstanceNetwork {
                instance_id: instance_id.to_string(),
                account_id: account.to_string(),
                region: region.to_string(),
                state: i.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default(),
                vpc_id: i.vpc_id.clone().unwrap_or_default(),
                subnet_id: i.subnet_id.clone().unwrap_or_default(),
                availability_zone: i.placement.as_ref().and_then(|p| p.availability_zone.clone()).unwrap_or_default(),
                private_ip: i.private_ip_address.clone().unwrap_or_default(),
                security_groups,
                role_arn: rec.role_arn.clone(),
            });
        }
        None
    }

    /// Whether the inbound rules of `groups` (in `account`/`region`) let
    /// TCP traffic to `port` in from `source_ip`, or from an interface in
    /// one of `source_groups`. MWS does not filter traffic itself; services
    /// that answer on a port (EFS's NFS) ask this to refuse what AWS would
    /// drop.
    pub fn ingress_allows_tcp(
        &self,
        account: &str,
        region: &str,
        groups: &[String],
        port: i32,
        source_ip: &str,
        source_groups: &[String],
    ) -> bool {
        let st = self.lock();
        let Some(r) = st.regions.get(&crate::state::State::key(account, region)) else { return false };
        let ip = parse_ip(source_ip);
        r.sg_rules.values().filter(|rule| !rule.egress && groups.contains(&rule.group_id)).any(|rule| {
            let proto_ok = rule.protocol == "-1" || rule.protocol == "tcp" || rule.protocol == "6";
            let port_ok = rule.protocol == "-1"
                || (rule.from_port.unwrap_or(0) <= port && port <= rule.to_port.unwrap_or(65535))
                || (rule.from_port == Some(-1));
            let source_ok = rule.referenced_group_id.as_ref().is_some_and(|g| source_groups.contains(g))
                || rule.cidr_ipv4.as_deref().and_then(Cidr::parse).zip(ip).is_some_and(|(cidr, ip)| cidr.contains(ip));
            proto_ok && port_ok && source_ok
        })
    }
}

fn check_groups(r: &RegionState, vpc_id: &str, groups: &[String]) -> Result<(), ServiceInterfaceError> {
    for g in groups {
        let group = r.security_groups.get(g).ok_or_else(|| ServiceInterfaceError::SecurityGroupNotFound(g.clone()))?;
        if group.vpc_id.as_deref() != Some(vpc_id) {
            return Err(ServiceInterfaceError::SecurityGroupInOtherVpc(g.clone()));
        }
    }
    Ok(())
}

fn check_ip(r: &RegionState, subnet: &t::Subnet, ip: &str) -> Result<(), ServiceInterfaceError> {
    let subnet_id = subnet.subnet_id.as_deref().unwrap_or_default();
    match crate::ops::vpc::check_ip(r, subnet_id, ip) {
        Ok(()) => Ok(()),
        Err(e) if e.code.contains("InUse") => Err(ServiceInterfaceError::IpAddressInUse(ip.into())),
        Err(_) => Err(ServiceInterfaceError::InvalidIpAddress(ip.into())),
    }
}

/// The Availability Zones of `region`: `(name, id)` pairs such as
/// `("us-east-1a", "use1-az1")`.
pub fn availability_zones(region: &str) -> Vec<(String, String)> {
    crate::catalog::zones(region)
}
