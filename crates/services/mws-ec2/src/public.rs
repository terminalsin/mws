//! What other services read about EC2 networking and instances. Elastic
//! Load Balancing places load balancers in subnets, checks security groups
//! and sends traffic to instances' private addresses, as it does in AWS.

use mws_core::RequestContext;

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
        })
    }
}
