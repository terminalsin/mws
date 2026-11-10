//! Network interfaces other services create in a caller's VPC (ECS awsvpc
//! tasks), as AWS does on their behalf: requester-managed, in use while the
//! owner keeps them, and deleted by the owner.

use mws_core::{RequestContext, ServiceError};

use crate::generated::types as t;
use crate::ops::eni::{assign_public_ip, new_eni, resolve_groups, set_association};
use crate::ops::vpc::{allocate_ip, check_ip};
use crate::util::{err, new_id, public_dns, Kind};
use crate::Ec2;

/// What [`Ec2::create_task_interface_with`] makes.
#[derive(Debug, Clone, Default)]
pub struct TaskInterfaceRequest {
    pub subnet_id: String,
    /// Security group ids: the VPC's default group when `None`, no group
    /// at all when empty (Network Load Balancers without groups).
    pub security_groups: Option<Vec<String>>,
    /// Give the interface an auto-assigned public address (ignored with
    /// `allocation_id`).
    pub assign_public: bool,
    pub description: String,
    /// The service principal reported as `RequesterId`.
    pub requester: String,
    /// The primary private IPv4 address; the next free one when `None`.
    pub private_ip: Option<String>,
    /// An Elastic IP of the account to associate with the interface.
    pub allocation_id: Option<String>,
}

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
        self.create_task_interface_with(
            ctx,
            account,
            &TaskInterfaceRequest {
                subnet_id: subnet_id.to_string(),
                security_groups: (!security_groups.is_empty()).then(|| security_groups.to_vec()),
                assign_public,
                description: description.to_string(),
                requester: requester.to_string(),
                ..Default::default()
            },
        )
    }

    /// [`Ec2::create_task_interface`] with a chosen private address, an
    /// Elastic IP, or explicitly no security groups. Errors are EC2's
    /// (`InvalidIPAddress.InUse`, `InvalidAllocationID.NotFound`, ...).
    pub fn create_task_interface_with(
        &self,
        ctx: &RequestContext,
        account: &str,
        req: &TaskInterfaceRequest,
    ) -> Result<TaskInterface, ServiceError> {
        let subnet_id = req.subnet_id.as_str();
        Kind::Subnet.check(subnet_id)?;
        if let Some(a) = &req.allocation_id {
            Kind::Allocation.check(a)?;
        }
        let region = ctx.region.clone();
        self.with_region_of(account, &ctx.region, ctx, |r| {
            let subnet = r.subnets.get(subnet_id).ok_or_else(|| Kind::Subnet.not_found(subnet_id))?.clone();
            let vpc_id = subnet.vpc_id.clone().unwrap_or_default();
            let groups = match &req.security_groups {
                Some(g) if g.is_empty() => Vec::new(),
                g => resolve_groups(r, &vpc_id, g.as_deref())?,
            };
            if let Some(a) = &req.allocation_id {
                let addr = r.addresses.get(a).ok_or_else(|| Kind::Allocation.not_found(a))?;
                if let Some(assoc) = &addr.association_id {
                    return Err(err(
                        "Resource.AlreadyAssociated",
                        format!("resource {a} is already associated with associate-id {assoc}"),
                    ));
                }
            }
            let ip = match &req.private_ip {
                Some(ip) => {
                    check_ip(r, subnet_id, ip)?;
                    ip.clone()
                }
                None => allocate_ip(r, subnet_id).ok_or_else(|| {
                    err("InsufficientFreeAddressesInSubnet", "Insufficient free IP addresses in subnet.")
                })?,
            };
            let id = new_eni(r, account, &region, &subnet, &ip, groups, &req.description, "interface", ctx.received_at);
            if let Some(alloc) = &req.allocation_id {
                let assoc_id = new_id("eipassoc");
                let public_ip = r.addresses.get(alloc).and_then(|a| a.public_ip.clone()).unwrap_or_default();
                if let Some(eni) = r.network_interfaces.get_mut(&id) {
                    set_association(
                        eni,
                        Some(t::NetworkInterfaceAssociation {
                            allocation_id: Some(alloc.clone()),
                            association_id: Some(assoc_id.clone()),
                            ip_owner_id: Some(account.to_string()),
                            public_dns_name: Some(public_dns(&region, &public_ip)),
                            public_ip: Some(public_ip),
                            ..Default::default()
                        }),
                    );
                }
                if let Some(a) = r.addresses.get_mut(alloc) {
                    a.association_id = Some(assoc_id);
                    a.network_interface_id = Some(id.clone());
                    a.network_interface_owner_id = Some(account.to_string());
                    a.private_ip_address = Some(ip.clone());
                }
            } else if req.assign_public {
                assign_public_ip(r, &region, &id);
            }
            let vpc_cidr = r.vpcs.get(&vpc_id).and_then(|v| v.vpc.cidr_block.clone()).unwrap_or_default();
            let eni = r.network_interfaces.get_mut(&id).expect("just made");
            eni.requester_managed = Some(true);
            eni.requester_id = Some(req.requester.clone());
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
            // An Elastic IP on it is free again.
            for a in r.addresses.values_mut().filter(|a| a.network_interface_id.as_deref() == Some(eni_id)) {
                a.network_interface_id = None;
                a.association_id = None;
                a.network_interface_owner_id = None;
                a.private_ip_address = None;
                a.instance_id = None;
            }
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
