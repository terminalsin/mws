//! Read-only VPC lookups for services that place resources in subnets
//! (ElastiCache subnet groups, ...).

use chrono::Utc;

use crate::state::{RegionState, State};
use crate::Ec2;

/// A subnet as other services see it.
#[derive(Debug, Clone)]
pub struct SubnetView {
    pub subnet_id: String,
    pub vpc_id: String,
    pub availability_zone: String,
    /// Whether the subnet has an IPv6 CIDR block.
    pub ipv6: bool,
}

fn view(s: &crate::generated::types::Subnet) -> SubnetView {
    SubnetView {
        subnet_id: s.subnet_id.clone().unwrap_or_default(),
        vpc_id: s.vpc_id.clone().unwrap_or_default(),
        availability_zone: s.availability_zone.clone().unwrap_or_default(),
        ipv6: s.ipv6_cidr_block_association_set.as_ref().is_some_and(|l| !l.is_empty()),
    }
}

/// The Docker network the Docker backend runs a VPC's instances on.
/// Other services' containers join it to be reachable from instances.
pub fn docker_network_name(vpc_id: &str) -> String {
    format!("mws-{vpc_id}")
}

impl Ec2 {
    fn with_network<R>(&self, account: &str, region: &str, partition: &str, f: impl FnOnce(&RegionState) -> R) -> R {
        let mut state = self.lock();
        let r = state.regions.entry(State::key(account, region)).or_default();
        if !r.initialized {
            crate::ops::vpc::init_region(r, account, region, partition, Utc::now());
            r.initialized = true;
        }
        f(r)
    }

    /// A subnet of `account` in `region`.
    pub fn subnet_view(&self, account: &str, region: &str, partition: &str, subnet_id: &str) -> Option<SubnetView> {
        self.with_network(account, region, partition, |r| r.subnets.get(subnet_id).map(view))
    }

    /// The default VPC's default subnets, one per Availability Zone.
    pub fn default_subnet_views(&self, account: &str, region: &str, partition: &str) -> Vec<SubnetView> {
        self.with_network(account, region, partition, |r| {
            let Some(vpc) = r.vpcs.values().find(|v| v.vpc.is_default == Some(true)).and_then(|v| v.vpc.vpc_id.clone())
            else {
                return Vec::new();
            };
            r.subnets
                .values()
                .filter(|s| s.vpc_id.as_deref() == Some(vpc.as_str()) && s.default_for_az == Some(true))
                .map(view)
                .collect()
        })
    }

    /// The VPC a security group belongs to.
    pub fn security_group_vpc(&self, account: &str, region: &str, partition: &str, group_id: &str) -> Option<String> {
        self.with_network(account, region, partition, |r| {
            r.security_groups.get(group_id).and_then(|g| g.vpc_id.clone())
        })
    }

    /// A VPC's `default` security group.
    pub fn default_security_group(&self, account: &str, region: &str, partition: &str, vpc_id: &str) -> Option<String> {
        self.with_network(account, region, partition, |r| {
            r.security_groups
                .values()
                .find(|g| g.vpc_id.as_deref() == Some(vpc_id) && g.group_name.as_deref() == Some("default"))
                .and_then(|g| g.group_id.clone())
        })
    }
}
