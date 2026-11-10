//! Network interfaces other services create in a caller's VPC (ECS awsvpc
//! tasks), as AWS does on their behalf: requester-managed, in use while the
//! owner keeps them, and deleted by the owner.

use mws_core::{RequestContext, ServiceError};

use crate::ops::eni::{assign_public_ip, new_eni, resolve_groups};
use crate::ops::vpc::allocate_ip;
use crate::util::{err, Kind};
use crate::Ec2;

/// A network interface a service made.
#[derive(Debug, Clone, Default)]
pub struct TaskInterface {
    pub eni_id: String,
    pub private_ip: String,
    pub mac_address: String,
    pub private_dns_name: String,
    pub public_ip: Option<String>,
    pub subnet_id: String,
    pub vpc_id: String,
    pub vpc_cidr: String,
    pub availability_zone: String,
}

impl Ec2 {
    /// Create an interface in `subnet_id` of `account` (in `ctx`'s Region)
    /// for `requester` (a service principal), with `security_groups` (the
    /// VPC's default group when empty). No IAM check: the calling service
    /// authorized its own action.
    #[allow(clippy::too_many_arguments)]
    pub fn create_task_interface(
        &self,
        ctx: &RequestContext,
        account: &str,
        subnet_id: &str,
        security_groups: &[String],
        assign_public: bool,
        description: &str,
        requester: &str,
    ) -> Result<TaskInterface, ServiceError> {
        Kind::Subnet.check(subnet_id)?;
        let region = ctx.region.clone();
        self.with_region_of(account, &ctx.region, ctx, |r| {
            let subnet = r.subnets.get(subnet_id).ok_or_else(|| Kind::Subnet.not_found(subnet_id))?.clone();
            let vpc_id = subnet.vpc_id.clone().unwrap_or_default();
            let groups = resolve_groups(r, &vpc_id, (!security_groups.is_empty()).then_some(security_groups))?;
            let ip = allocate_ip(r, subnet_id)
                .ok_or_else(|| err("InsufficientFreeAddressesInSubnet", "Insufficient free IP addresses in subnet."))?;
            let id = new_eni(r, account, &region, &subnet, &ip, groups, description, "interface", ctx.received_at);
            if assign_public {
                assign_public_ip(r, &region, &id);
            }
            let vpc_cidr = r.vpcs.get(&vpc_id).and_then(|v| v.vpc.cidr_block.clone()).unwrap_or_default();
            let eni = r.network_interfaces.get_mut(&id).expect("just made");
            eni.requester_managed = Some(true);
            eni.requester_id = Some(requester.to_string());
            eni.status = Some("in-use".into());
            Ok(TaskInterface {
                eni_id: id.clone(),
                private_ip: ip,
                mac_address: eni.mac_address.clone().unwrap_or_default(),
                private_dns_name: eni.private_dns_name.clone().unwrap_or_default(),
                public_ip: eni.association.as_ref().and_then(|a| a.public_ip.clone()),
                subnet_id: subnet_id.to_string(),
                vpc_id,
                vpc_cidr,
                availability_zone: subnet.availability_zone.clone().unwrap_or_default(),
            })
        })
    }

    /// Delete an interface [`Ec2::create_task_interface`] made.
    pub fn delete_task_interface(&self, ctx: &RequestContext, account: &str, eni_id: &str) {
        self.with_region_of(account, &ctx.region, ctx, |r| {
            r.network_interfaces.remove(eni_id);
        });
    }

    /// Replace the security groups of an interface
    /// [`Ec2::create_task_interface`] made (the VPC's default group when
    /// empty).
    pub fn set_task_interface_groups(
        &self,
        ctx: &RequestContext,
        account: &str,
        eni_id: &str,
        security_groups: &[String],
    ) -> Result<(), ServiceError> {
        self.with_region_of(account, &ctx.region, ctx, |r| {
            let vpc_id = r.network_interfaces.get(eni_id).and_then(|n| n.vpc_id.clone()).unwrap_or_default();
            let groups = resolve_groups(r, &vpc_id, (!security_groups.is_empty()).then_some(security_groups))?;
            if let Some(eni) = r.network_interfaces.get_mut(eni_id) {
                eni.groups = Some(groups);
            }
            Ok(())
        })
    }

    /// The default VPC's subnets in `account` and `ctx`'s Region.
    pub fn default_subnets(&self, ctx: &RequestContext, account: &str) -> Vec<String> {
        self.with_region_of(account, &ctx.region, ctx, |r| {
            r.subnets.values().filter(|s| s.default_for_az == Some(true)).filter_map(|s| s.subnet_id.clone()).collect()
        })
    }
}
