//! IPv6 for VPCs and subnets, secondary private addresses and prefixes on
//! network interfaces, subnet CIDR reservations, and a few VPC-level reads
//! (`ModifyVpcTenancy`, `GetSecurityGroupsForVpc`, ClassicLink).

use std::net::Ipv6Addr;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::types as t;
use crate::ops::gateways::{authorize_create, authorize_on};
use crate::ops::vpc::{allocate_ip, check_ip, used_ips};
use crate::state::RegionState;
use crate::util::{
    arn, authorize, err, invalid_parameter, ip_str, missing_parameter, new_id, paginate, resource_tag_context, s,
    some_tags, tags_for, Cidr, Filters, Kind,
};
use crate::{account_of, Ec2};

/// An IPv6 network: address and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr6 {
    pub base: u128,
    pub prefix: u8,
}

impl Cidr6 {
    pub fn parse(s: &str) -> Option<Self> {
        let (a, p) = s.split_once('/')?;
        let prefix: u8 = p.parse().ok()?;
        if prefix > 128 {
            return None;
        }
        let base = u128::from(a.parse::<Ipv6Addr>().ok()?);
        Some(Self { base, prefix })
    }

    fn mask(&self) -> u128 {
        if self.prefix == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix)
        }
    }

    pub fn is_network(&self) -> bool {
        self.base & !self.mask() == 0
    }

    pub fn contains(&self, ip: u128) -> bool {
        ip & self.mask() == self.base & self.mask()
    }

    pub fn contains_cidr(&self, o: &Cidr6) -> bool {
        o.prefix >= self.prefix && self.contains(o.base)
    }

    pub fn overlaps(&self, o: &Cidr6) -> bool {
        self.contains_cidr(o) || o.contains_cidr(self)
    }

    pub fn to_text(self) -> String {
        format!("{}/{}", Ipv6Addr::from(self.base), self.prefix)
    }
}

/// A fresh Amazon-provided `/56` for a VPC.
fn amazon_ipv6_block() -> String {
    let mut rng = rand::thread_rng();
    let base: u128 = (0x2600_1f18u128 << 96) | ((rng.gen::<u16>() as u128) << 80) | ((rng.gen::<u8>() as u128) << 72);
    Cidr6 { base, prefix: 56 }.to_text()
}

fn ipv6_assoc_state(state: &str) -> Option<t::VpcCidrBlockState> {
    Some(t::VpcCidrBlockState { state: Some(state.into()), status_message: None })
}

/// Give a VPC an Amazon-provided IPv6 block (and its local route).
pub(crate) fn add_vpc_ipv6(
    r: &mut RegionState,
    vpc_id: &str,
    region: &str,
    border_group: Option<String>,
) -> Result<t::VpcIpv6CidrBlockAssociation, ServiceError> {
    let rec = r.vpcs.get_mut(vpc_id).ok_or_else(|| Kind::Vpc.not_found(vpc_id))?;
    let set = rec.vpc.ipv6_cidr_block_association_set.get_or_insert_with(Vec::new);
    if set.iter().any(|a| a.ipv6_cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) == Some("associated")) {
        return Err(err(
            "CidrLimitExceeded",
            format!("This network '{vpc_id}' has met its maximum number of allowed CIDRs: 1"),
        ));
    }
    let block = amazon_ipv6_block();
    let assoc = t::VpcIpv6CidrBlockAssociation {
        association_id: Some(new_id("vpc-cidr-assoc")),
        ipv6_cidr_block: Some(block.clone()),
        ipv6_cidr_block_state: ipv6_assoc_state("associated"),
        network_border_group: Some(border_group.unwrap_or_else(|| region.to_string())),
        ipv6_pool: Some("Amazon".into()),
        ipv6_address_attribute: Some("public".into()),
        ip_source: Some("amazon".into()),
    };
    set.push(assoc.clone());
    for rt in r.route_tables.values_mut().filter(|rt| rt.vpc_id.as_deref() == Some(vpc_id)) {
        rt.routes.get_or_insert_with(Vec::new).push(t::Route {
            destination_ipv6_cidr_block: Some(block.clone()),
            gateway_id: Some("local".into()),
            origin: Some("CreateRouteTable".into()),
            state: Some("active".into()),
            ..Default::default()
        });
    }
    Ok(assoc)
}

/// Remove a VPC's IPv6 block by association id, if it is one.
pub(crate) fn remove_vpc_ipv6(
    r: &mut RegionState,
    association_id: &str,
) -> Option<Result<(String, t::VpcIpv6CidrBlockAssociation), ServiceError>> {
    let (vpc_id, block) = r.vpcs.values().find_map(|v| {
        v.vpc
            .ipv6_cidr_block_association_set
            .iter()
            .flatten()
            .find(|a| a.association_id.as_deref() == Some(association_id))
            .map(|a| (v.vpc.vpc_id.clone().unwrap_or_default(), a.ipv6_cidr_block.clone().unwrap_or_default()))
    })?;
    let in_use = r.subnets.values().any(|s| {
        s.vpc_id.as_deref() == Some(vpc_id.as_str())
            && s.ipv6_cidr_block_association_set
                .iter()
                .flatten()
                .any(|a| a.ipv6_cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) == Some("associated"))
    });
    if in_use {
        return Some(Err(err("InvalidCidrBlock.InUse", format!("The vpc CIDR block {block} is in use by subnets"))));
    }
    let rec = r.vpcs.get_mut(&vpc_id).expect("found");
    let set = rec.vpc.ipv6_cidr_block_association_set.get_or_insert_with(Vec::new);
    let i = set.iter().position(|a| a.association_id.as_deref() == Some(association_id)).expect("found");
    let mut removed = set.remove(i);
    for rt in r.route_tables.values_mut().filter(|rt| rt.vpc_id.as_deref() == Some(vpc_id.as_str())) {
        if let Some(routes) = &mut rt.routes {
            routes.retain(|x| {
                !(x.gateway_id.as_deref() == Some("local")
                    && x.destination_ipv6_cidr_block.as_deref() == Some(block.as_str()))
            });
        }
    }
    removed.ipv6_cidr_block_state = ipv6_assoc_state("disassociating");
    Some(Ok((vpc_id, removed)))
}

fn subnet_ipv6(sn: &t::Subnet) -> Option<Cidr6> {
    sn.ipv6_cidr_block_association_set
        .iter()
        .flatten()
        .find(|a| a.ipv6_cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) == Some("associated"))
        .and_then(|a| a.ipv6_cidr_block.as_deref())
        .and_then(Cidr6::parse)
}

fn used_ipv6(r: &RegionState, subnet_id: &str) -> Vec<u128> {
    r.network_interfaces
        .values()
        .filter(|n| n.subnet_id.as_deref() == Some(subnet_id))
        .flat_map(|n| n.ipv6_addresses.iter().flatten().filter_map(|a| a.ipv6_address.clone()))
        .filter_map(|a| a.parse::<Ipv6Addr>().ok().map(u128::from))
        .collect()
}

impl Ec2 {
    // ---- subnet IPv6 ------------------------------------------------------------------------------

    pub(crate) fn associate_subnet_cidr_block_op(
        &self,
        ctx: &RequestContext,
        input: t::AssociateSubnetCidrBlockRequest,
    ) -> Result<t::AssociateSubnetCidrBlockResult, ServiceError> {
        let sid = input.subnet_id.clone();
        authorize_on(
            self,
            ctx,
            "AssociateSubnetCidrBlock",
            Kind::Subnet,
            "subnet",
            &sid,
            |r| r.subnets.get(&sid).map(|s| s.tags.clone()),
            None,
        )?;
        let block = input.ipv6_cidr_block.clone().ok_or_else(|| missing_parameter("ipv6CidrBlock"))?;
        let parsed = Cidr6::parse(&block)
            .filter(|c| c.is_network())
            .ok_or_else(|| err("InvalidSubnet.Range", format!("The CIDR '{block}' is invalid.")))?;
        if parsed.prefix < 44 || parsed.prefix > 64 {
            return Err(err("InvalidSubnet.Range", format!("The CIDR '{block}' is invalid.")));
        }
        self.with_region(ctx, |r| {
            let sn = r.subnets.get(&sid).ok_or_else(|| Kind::Subnet.not_found(&sid))?;
            if subnet_ipv6(sn).is_some() {
                return Err(err(
                    "InvalidParameterValue",
                    format!("The subnet '{sid}' already has an IPv6 CIDR block association."),
                ));
            }
            let vpc_id = sn.vpc_id.clone().unwrap_or_default();
            let vpc_blocks: Vec<Cidr6> = r
                .vpcs
                .get(&vpc_id)
                .map(|v| {
                    v.vpc
                        .ipv6_cidr_block_association_set
                        .iter()
                        .flatten()
                        .filter(|a| {
                            a.ipv6_cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) == Some("associated")
                        })
                        .filter_map(|a| a.ipv6_cidr_block.as_deref().and_then(Cidr6::parse))
                        .collect()
                })
                .unwrap_or_default();
            if !vpc_blocks.iter().any(|v| v.contains_cidr(&parsed)) {
                return Err(err("InvalidSubnet.Range", format!("The CIDR '{block}' is invalid.")));
            }
            let conflict = r.subnets.values().any(|o| {
                o.vpc_id.as_deref() == Some(vpc_id.as_str()) && subnet_ipv6(o).is_some_and(|c| c.overlaps(&parsed))
            });
            if conflict {
                return Err(err("InvalidSubnet.Conflict", format!("The CIDR '{block}' conflicts with another subnet")));
            }
            let assoc = t::SubnetIpv6CidrBlockAssociation {
                association_id: Some(new_id("subnet-cidr-assoc")),
                ipv6_cidr_block: Some(parsed.to_text()),
                ipv6_cidr_block_state: Some(t::SubnetCidrBlockState {
                    state: Some("associated".into()),
                    status_message: None,
                }),
                ipv6_address_attribute: Some("public".into()),
                ip_source: Some("amazon".into()),
            };
            let sn = r.subnets.get_mut(&sid).expect("checked");
            sn.ipv6_cidr_block_association_set.get_or_insert_with(Vec::new).push(assoc.clone());
            let mut shown = assoc;
            shown.ipv6_cidr_block_state =
                Some(t::SubnetCidrBlockState { state: Some("associating".into()), status_message: None });
            Ok(t::AssociateSubnetCidrBlockResult {
                ipv6_cidr_block_association: Some(shown),
                subnet_id: Some(sid.clone()),
            })
        })
    }

    pub(crate) fn disassociate_subnet_cidr_block_op(
        &self,
        ctx: &RequestContext,
        input: t::DisassociateSubnetCidrBlockRequest,
    ) -> Result<t::DisassociateSubnetCidrBlockResult, ServiceError> {
        authorize(ctx, "DisassociateSubnetCidrBlock", &[("*".into(), ConditionContext::new())], None)?;
        let id = input.association_id.clone();
        self.with_region(ctx, |r| {
            let sid = r
                .subnets
                .values()
                .find(|s| {
                    s.ipv6_cidr_block_association_set
                        .iter()
                        .flatten()
                        .any(|a| a.association_id.as_deref() == Some(id.as_str()))
                })
                .and_then(|s| s.subnet_id.clone())
                .ok_or_else(|| {
                    err(
                        "InvalidSubnetCidrBlockAssociationID.NotFound",
                        format!("The subnet CIDR block with association ID '{id}' does not exist"),
                    )
                })?;
            if !used_ipv6(r, &sid).is_empty() {
                return Err(err(
                    "InvalidCidrBlock.InUse",
                    format!("The subnet CIDR block with association ID {id} is in use by network interfaces"),
                ));
            }
            let sn = r.subnets.get_mut(&sid).expect("found");
            let set = sn.ipv6_cidr_block_association_set.get_or_insert_with(Vec::new);
            let i = set.iter().position(|a| a.association_id.as_deref() == Some(id.as_str())).expect("found");
            let mut removed = set.remove(i);
            removed.ipv6_cidr_block_state =
                Some(t::SubnetCidrBlockState { state: Some("disassociating".into()), status_message: None });
            Ok(t::DisassociateSubnetCidrBlockResult {
                ipv6_cidr_block_association: Some(removed),
                subnet_id: Some(sid),
            })
        })
    }

    // ---- subnet CIDR reservations -----------------------------------------------------------------

    pub(crate) fn create_subnet_cidr_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateSubnetCidrReservationRequest,
    ) -> Result<t::CreateSubnetCidrReservationResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "subnet-cidr-reservation", &["subnet-cidr-reservation"])?;
        let sid = input.subnet_id.clone();
        Kind::Subnet.check(&sid)?;
        if !matches!(input.reservation_type.as_str(), "prefix" | "explicit") {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter reservationType is invalid. Valid values: prefix, explicit",
                input.reservation_type
            )));
        }
        let account = account_of(ctx);
        authorize_create(
            ctx,
            "CreateSubnetCidrReservation",
            "subnet-cidr-reservation",
            &tags,
            &[arn(ctx, &account, &format!("subnet/{sid}"))],
            input.dry_run,
        )?;
        let cidr = input.cidr.clone();
        self.with_region(ctx, |r| {
            let sn = r.subnets.get(&sid).ok_or_else(|| Kind::Subnet.not_found(&sid))?;
            let ok = if let Some(c) = Cidr::parse(&cidr) {
                c.is_network() && sn.cidr_block.as_deref().and_then(Cidr::parse).is_some_and(|s| s.contains_cidr(&c))
            } else if let Some(c) = Cidr6::parse(&cidr) {
                c.is_network() && subnet_ipv6(sn).is_some_and(|s| s.contains_cidr(&c))
            } else {
                false
            };
            if !ok {
                return Err(err(
                    "InvalidSubnet.Range",
                    format!("The CIDR '{cidr}' is not within the range of subnet {sid}."),
                ));
            }
            let clash = r.subnet_cidr_reservations.values().any(|x| {
                x.subnet_id.as_deref() == Some(sid.as_str())
                    && match (x.cidr.as_deref().and_then(Cidr::parse), Cidr::parse(&cidr)) {
                        (Some(a), Some(b)) => a.overlaps(&b),
                        _ => match (x.cidr.as_deref().and_then(Cidr6::parse), Cidr6::parse(&cidr)) {
                            (Some(a), Some(b)) => a.overlaps(&b),
                            _ => false,
                        },
                    }
            });
            if clash {
                return Err(err(
                    "InvalidSubnetCidrReservation.Conflict",
                    format!("The CIDR '{cidr}' overlaps an existing reservation in subnet {sid}."),
                ));
            }
            let id = new_id("scr");
            let res = t::SubnetCidrReservation {
                subnet_cidr_reservation_id: Some(id.clone()),
                subnet_id: Some(sid.clone()),
                cidr: Some(cidr.clone()),
                reservation_type: Some(input.reservation_type.clone()),
                owner_id: Some(account.clone()),
                description: input.description.clone(),
                tags: some_tags(tags),
            };
            r.subnet_cidr_reservations.insert(id, res.clone());
            Ok(t::CreateSubnetCidrReservationResult { subnet_cidr_reservation: Some(res) })
        })
    }

    pub(crate) fn delete_subnet_cidr_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteSubnetCidrReservationRequest,
    ) -> Result<t::DeleteSubnetCidrReservationResult, ServiceError> {
        let id = input.subnet_cidr_reservation_id.clone();
        authorize_on(
            self,
            ctx,
            "DeleteSubnetCidrReservation",
            Kind::SubnetCidrReservation,
            "subnet-cidr-reservation",
            &id,
            |r| r.subnet_cidr_reservations.get(&id).map(|x| x.tags.clone()),
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let res =
                r.subnet_cidr_reservations.remove(&id).ok_or_else(|| Kind::SubnetCidrReservation.not_found(&id))?;
            Ok(t::DeleteSubnetCidrReservationResult { deleted_subnet_cidr_reservation: Some(res) })
        })
    }

    pub(crate) fn get_subnet_cidr_reservations_op(
        &self,
        ctx: &RequestContext,
        input: t::GetSubnetCidrReservationsRequest,
    ) -> Result<t::GetSubnetCidrReservationsResult, ServiceError> {
        let sid = input.subnet_id.clone();
        authorize_on(
            self,
            ctx,
            "GetSubnetCidrReservations",
            Kind::Subnet,
            "subnet",
            &sid,
            |r| r.subnets.get(&sid).map(|s| s.tags.clone()),
            input.dry_run,
        )?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let (mut v4, mut v6) = (Vec::new(), Vec::new());
            for x in r.subnet_cidr_reservations.values().filter(|x| x.subnet_id.as_deref() == Some(sid.as_str())) {
                let ok = filters.matches(x.tags.as_ref(), |name| {
                    Some(match name {
                        "reservationType" => s(&x.reservation_type),
                        "subnet-id" => s(&x.subnet_id),
                        "owner-id" => s(&x.owner_id),
                        _ => return None,
                    })
                })?;
                if !ok {
                    continue;
                }
                if x.cidr.as_deref().is_some_and(|c| c.contains(':')) {
                    v6.push(x.clone());
                } else {
                    v4.push(x.clone());
                }
            }
            let (v4, next_token) = paginate(v4, input.max_results, &input.next_token)?;
            Ok(t::GetSubnetCidrReservationsResult {
                subnet_ipv4_cidr_reservations: Some(v4),
                subnet_ipv6_cidr_reservations: Some(v6),
                next_token,
            })
        })
    }

    // ---- interface addresses ----------------------------------------------------------------------

    fn eni_check(&self, ctx: &RequestContext, action: &str, eni: &str) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::NetworkInterface.check(eni)?;
        let tags = self.with_region(ctx, |r| r.network_interfaces.get(eni).map(|n| n.tag_set.clone()));
        let tags = tags.ok_or_else(|| Kind::NetworkInterface.not_found(eni))?;
        authorize(
            ctx,
            action,
            &[(arn(ctx, &account, &format!("network-interface/{eni}")), resource_tag_context(tags.as_ref()))],
            None,
        )
    }

    pub(crate) fn assign_private_ip_addresses_op(
        &self,
        ctx: &RequestContext,
        input: t::AssignPrivateIpAddressesRequest,
    ) -> Result<t::AssignPrivateIpAddressesResult, ServiceError> {
        let eni_id = input.network_interface_id.clone();
        self.eni_check(ctx, "AssignPrivateIpAddresses", &eni_id)?;
        let explicit = input.private_ip_addresses.clone().unwrap_or_default();
        let count = input.secondary_private_ip_address_count.unwrap_or(0);
        let prefixes = input.ipv4_prefixes.clone().unwrap_or_default();
        let prefix_count = input.ipv4_prefix_count.unwrap_or(0);
        let modes =
            [!explicit.is_empty(), count > 0, !prefixes.is_empty(), prefix_count > 0].iter().filter(|b| **b).count();
        if modes == 0 {
            return Err(missing_parameter("secondaryPrivateIpAddressCount or privateIpAddresses"));
        }
        if modes > 1 {
            return Err(err(
                "InvalidParameterCombination",
                "Specify only one of PrivateIpAddresses, SecondaryPrivateIpAddressCount, Ipv4Prefixes or Ipv4PrefixCount.",
            ));
        }
        let region = ctx.region.clone();
        self.with_region(ctx, |r| {
            let subnet = r.network_interfaces[&eni_id].subnet_id.clone().unwrap_or_default();
            let mut assigned = Vec::new();
            let mut assigned_prefixes = Vec::new();
            for ip in &explicit {
                let taken_by = r.network_interfaces.values().find(|n| {
                    n.network_interface_id.as_deref() != Some(eni_id.as_str())
                        && n.private_ip_addresses
                            .iter()
                            .flatten()
                            .any(|p| p.private_ip_address.as_deref() == Some(ip.as_str()))
                });
                if let Some(other) = taken_by {
                    if input.allow_reassignment != Some(true) || other.subnet_id.as_deref() != Some(subnet.as_str()) {
                        return Err(err("InvalidIPAddress.InUse", format!("Address {ip} is in use.")));
                    }
                    let other_id = other.network_interface_id.clone().unwrap_or_default();
                    let o = r.network_interfaces.get_mut(&other_id).expect("found");
                    if o.private_ip_addresses
                        .iter()
                        .flatten()
                        .any(|p| p.private_ip_address.as_deref() == Some(ip.as_str()) && p.primary == Some(true))
                    {
                        return Err(err(
                            "InvalidIPAddress.InUse",
                            format!("Address {ip} is the primary address of {other_id}."),
                        ));
                    }
                    if let Some(list) = o.private_ip_addresses.as_mut() {
                        list.retain(|p| p.private_ip_address.as_deref() != Some(ip.as_str()));
                    }
                } else if r.network_interfaces[&eni_id]
                    .private_ip_addresses
                    .iter()
                    .flatten()
                    .any(|p| p.private_ip_address.as_deref() == Some(ip.as_str()))
                {
                    return Err(err("InvalidParameterValue", format!("Address {ip} is already assigned to {eni_id}")));
                } else {
                    check_ip(r, &subnet, ip)?;
                }
                assigned.push(ip.clone());
                push_ip(r, &eni_id, ip, &region);
            }
            for _ in 0..count {
                let ip = allocate_ip(r, &subnet).ok_or_else(|| {
                    err(
                        "InsufficientFreeAddressesInSubnet",
                        format!(
                            "The specified subnet {subnet} does not have enough free addresses to satisfy the request."
                        ),
                    )
                })?;
                assigned.push(ip.clone());
                push_ip(r, &eni_id, &ip, &region);
            }
            let wanted: Vec<Option<String>> = if prefixes.is_empty() {
                (0..prefix_count).map(|_| None).collect()
            } else {
                prefixes.iter().cloned().map(Some).collect()
            };
            for want in wanted {
                let p = allocate_prefix(r, &subnet, want.as_deref())?;
                assigned_prefixes.push(t::Ipv4PrefixSpecification { ipv4_prefix: Some(p.clone()) });
                let eni = r.network_interfaces.get_mut(&eni_id).expect("checked");
                eni.ipv4_prefixes
                    .get_or_insert_with(Vec::new)
                    .push(t::Ipv4PrefixSpecification { ipv4_prefix: Some(p) });
            }
            Ok(t::AssignPrivateIpAddressesResult {
                network_interface_id: Some(eni_id.clone()),
                assigned_private_ip_addresses: Some(
                    assigned
                        .into_iter()
                        .map(|ip| t::AssignedPrivateIpAddress { private_ip_address: Some(ip) })
                        .collect(),
                ),
                assigned_ipv4_prefixes: Some(assigned_prefixes),
            })
        })
    }

    pub(crate) fn unassign_private_ip_addresses_op(
        &self,
        ctx: &RequestContext,
        input: t::UnassignPrivateIpAddressesRequest,
    ) -> Result<(), ServiceError> {
        let eni_id = input.network_interface_id.clone();
        self.eni_check(ctx, "UnassignPrivateIpAddresses", &eni_id)?;
        let ips = input.private_ip_addresses.clone().unwrap_or_default();
        let prefixes = input.ipv4_prefixes.clone().unwrap_or_default();
        if ips.is_empty() && prefixes.is_empty() {
            return Err(missing_parameter("privateIpAddress"));
        }
        self.with_region(ctx, |r| {
            let eni = r.network_interfaces.get_mut(&eni_id).expect("checked");
            let list = eni.private_ip_addresses.get_or_insert_with(Vec::new);
            for ip in &ips {
                match list.iter().find(|p| p.private_ip_address.as_deref() == Some(ip.as_str())) {
                    None => {
                        return Err(err(
                            "InvalidParameterValue",
                            format!("Some of the specified addresses are not assigned to interface {eni_id}"),
                        ))
                    }
                    Some(p) if p.primary == Some(true) => {
                        return Err(err(
                            "InvalidParameterValue",
                            format!("The primary private IP address {ip} of {eni_id} cannot be unassigned."),
                        ))
                    }
                    Some(_) => {}
                }
            }
            list.retain(|p| !p.private_ip_address.as_ref().is_some_and(|a| ips.contains(a)));
            let pl = eni.ipv4_prefixes.get_or_insert_with(Vec::new);
            for p in &prefixes {
                if !pl.iter().any(|x| x.ipv4_prefix.as_deref() == Some(p.as_str())) {
                    return Err(err(
                        "InvalidParameterValue",
                        format!("Some of the specified prefixes are not assigned to interface {eni_id}"),
                    ));
                }
            }
            pl.retain(|x| !x.ipv4_prefix.as_ref().is_some_and(|p| prefixes.contains(p)));
            if pl.is_empty() {
                eni.ipv4_prefixes = None;
            }
            Ok(())
        })
    }

    pub(crate) fn assign_ipv6_addresses_op(
        &self,
        ctx: &RequestContext,
        input: t::AssignIpv6AddressesRequest,
    ) -> Result<t::AssignIpv6AddressesResult, ServiceError> {
        let eni_id = input.network_interface_id.clone();
        self.eni_check(ctx, "AssignIpv6Addresses", &eni_id)?;
        let explicit = input.ipv6_addresses.clone().unwrap_or_default();
        let count = input.ipv6_address_count.unwrap_or(0);
        if explicit.is_empty() && count == 0 && input.ipv6_prefix_count.is_none() && input.ipv6_prefixes.is_none() {
            return Err(missing_parameter("ipv6AddressCount or ipv6Addresses"));
        }
        if input.ipv6_prefix_count.is_some() || input.ipv6_prefixes.is_some() {
            return Err(err(
                "InvalidParameterValue",
                "IPv6 prefix delegation is only supported on interfaces of Nitro instances.",
            ));
        }
        self.with_region(ctx, |r| {
            let subnet = r.network_interfaces[&eni_id].subnet_id.clone().unwrap_or_default();
            let block = r.subnets.get(&subnet).and_then(subnet_ipv6).ok_or_else(|| {
                err("InvalidParameterValue", format!("Subnet {subnet} does not have an IPv6 CIDR block"))
            })?;
            let mut used = used_ipv6(r, &subnet);
            let mut assigned = Vec::new();
            for a in &explicit {
                let ip = a
                    .parse::<Ipv6Addr>()
                    .map(u128::from)
                    .map_err(|_| invalid_parameter(format!("Invalid value '{a}' for IPv6 address.")))?;
                if !block.contains(ip) {
                    return Err(invalid_parameter(format!(
                        "Address {a} does not fall within the subnet's address range"
                    )));
                }
                if used.contains(&ip) {
                    return Err(err("InvalidIPAddress.InUse", format!("Address {a} is in use.")));
                }
                used.push(ip);
                assigned.push(Ipv6Addr::from(ip).to_string());
            }
            let mut rng = rand::thread_rng();
            for _ in 0..count {
                let host_bits = 128 - u32::from(block.prefix);
                let ip = loop {
                    let host: u128 =
                        if host_bits >= 128 { rng.gen() } else { rng.gen::<u128>() & ((1u128 << host_bits) - 1) };
                    let ip = block.base | host.max(4);
                    if !used.contains(&ip) {
                        break ip;
                    }
                };
                used.push(ip);
                assigned.push(Ipv6Addr::from(ip).to_string());
            }
            let eni = r.network_interfaces.get_mut(&eni_id).expect("checked");
            let list = eni.ipv6_addresses.get_or_insert_with(Vec::new);
            for a in &assigned {
                list.push(t::NetworkInterfaceIpv6Address {
                    ipv6_address: Some(a.clone()),
                    is_primary_ipv6: Some(false),
                    public_ipv6_dns_name: None,
                });
            }
            if eni.ipv6_address.is_none() {
                eni.ipv6_address = assigned.first().cloned();
            }
            Ok(t::AssignIpv6AddressesResult {
                assigned_ipv6_addresses: Some(assigned),
                assigned_ipv6_prefixes: None,
                network_interface_id: Some(eni_id.clone()),
            })
        })
    }

    pub(crate) fn unassign_ipv6_addresses_op(
        &self,
        ctx: &RequestContext,
        input: t::UnassignIpv6AddressesRequest,
    ) -> Result<t::UnassignIpv6AddressesResult, ServiceError> {
        let eni_id = input.network_interface_id.clone();
        self.eni_check(ctx, "UnassignIpv6Addresses", &eni_id)?;
        let addrs = input.ipv6_addresses.clone().unwrap_or_default();
        if addrs.is_empty() && input.ipv6_prefixes.is_none() {
            return Err(missing_parameter("ipv6Addresses"));
        }
        self.with_region(ctx, |r| {
            let eni = r.network_interfaces.get_mut(&eni_id).expect("checked");
            let list = eni.ipv6_addresses.get_or_insert_with(Vec::new);
            let norm = |a: &str| a.parse::<Ipv6Addr>().map(|x| x.to_string()).unwrap_or_else(|_| a.to_string());
            let wanted: Vec<String> = addrs.iter().map(|a| norm(a)).collect();
            for a in &wanted {
                if !list.iter().any(|x| x.ipv6_address.as_deref() == Some(a.as_str())) {
                    return Err(err(
                        "InvalidParameterValue",
                        format!("Some of the specified addresses are not assigned to interface {eni_id}"),
                    ));
                }
            }
            list.retain(|x| !x.ipv6_address.as_ref().is_some_and(|a| wanted.contains(a)));
            if eni.ipv6_address.as_ref().is_some_and(|a| wanted.contains(a)) {
                eni.ipv6_address = list.first().and_then(|x| x.ipv6_address.clone());
            }
            Ok(t::UnassignIpv6AddressesResult {
                network_interface_id: Some(eni_id.clone()),
                unassigned_ipv6_addresses: Some(wanted),
                unassigned_ipv6_prefixes: None,
            })
        })
    }

    pub(crate) fn describe_network_interface_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeNetworkInterfaceAttributeRequest,
    ) -> Result<t::DescribeNetworkInterfaceAttributeResult, ServiceError> {
        let eni_id = input.network_interface_id.clone();
        Kind::NetworkInterface.check(&eni_id)?;
        let account = account_of(ctx);
        let tags = self.with_region(ctx, |r| r.network_interfaces.get(&eni_id).map(|n| n.tag_set.clone()));
        let tags = tags.ok_or_else(|| Kind::NetworkInterface.not_found(&eni_id))?;
        authorize(
            ctx,
            "DescribeNetworkInterfaceAttribute",
            &[(arn(ctx, &account, &format!("network-interface/{eni_id}")), resource_tag_context(tags.as_ref()))],
            input.dry_run,
        )?;
        let attr = input.attribute.clone().ok_or_else(|| missing_parameter("attribute"))?;
        self.with_region(ctx, |r| {
            let n = r.network_interfaces.get(&eni_id).expect("checked");
            let mut out = t::DescribeNetworkInterfaceAttributeResult {
                network_interface_id: Some(eni_id.clone()),
                ..Default::default()
            };
            match attr.as_str() {
                "description" => {
                    out.description = Some(t::AttributeValue { value: Some(n.description.clone().unwrap_or_default()) })
                }
                "groupSet" => out.groups = Some(n.groups.clone().unwrap_or_default()),
                "sourceDestCheck" => {
                    out.source_dest_check =
                        Some(t::AttributeBooleanValue { value: Some(n.source_dest_check.unwrap_or(true)) })
                }
                "attachment" => out.attachment = n.attachment.clone(),
                "associatePublicIpAddress" => {
                    out.associate_public_ip_address =
                        Some(n.association.as_ref().is_some_and(|a| a.public_ip.is_some()))
                }
                other => {
                    return Err(invalid_parameter(format!(
                        "Value ({other}) for parameter attribute is invalid. Unknown attribute."
                    )))
                }
            }
            Ok(out)
        })
    }

    // ---- VPC-level --------------------------------------------------------------------------------

    pub(crate) fn modify_vpc_tenancy_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVpcTenancyRequest,
    ) -> Result<t::ModifyVpcTenancyResult, ServiceError> {
        let vpc = input.vpc_id.clone();
        authorize_on(
            self,
            ctx,
            "ModifyVpcTenancy",
            Kind::Vpc,
            "vpc",
            &vpc,
            |r| r.vpcs.get(&vpc).map(|v| v.vpc.tags.clone()),
            input.dry_run,
        )?;
        if input.instance_tenancy != "default" {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter instanceTenancy is invalid. The only supported value is default.",
                input.instance_tenancy
            )));
        }
        self.with_region(ctx, |r| {
            let rec = r.vpcs.get_mut(&vpc).ok_or_else(|| Kind::Vpc.not_found(&vpc))?;
            rec.vpc.instance_tenancy = Some("default".into());
            Ok(t::ModifyVpcTenancyResult { return_value: Some(true) })
        })
    }

    pub(crate) fn get_security_groups_for_vpc_op(
        &self,
        ctx: &RequestContext,
        input: t::GetSecurityGroupsForVpcRequest,
    ) -> Result<t::GetSecurityGroupsForVpcResult, ServiceError> {
        let vpc = input.vpc_id.clone();
        authorize_on(
            self,
            ctx,
            "GetSecurityGroupsForVpc",
            Kind::Vpc,
            "vpc",
            &vpc,
            |r| r.vpcs.get(&vpc).map(|v| v.vpc.tags.clone()),
            input.dry_run,
        )?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for g in r.security_groups.values() {
                if g.vpc_id.as_deref() != Some(vpc.as_str()) {
                    continue;
                }
                let ok = filters.matches(g.tags.as_ref(), |name| {
                    Some(match name {
                        "group-id" => s(&g.group_id),
                        "group-name" => s(&g.group_name),
                        "owner-id" => s(&g.owner_id),
                        "primary-vpc-id" => s(&g.vpc_id),
                        "description" => s(&g.description),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(t::SecurityGroupForVpc {
                        description: g.description.clone(),
                        group_name: g.group_name.clone(),
                        owner_id: g.owner_id.clone(),
                        group_id: g.group_id.clone(),
                        tags: g.tags.clone(),
                        primary_vpc_id: g.vpc_id.clone(),
                    });
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::GetSecurityGroupsForVpcResult { next_token, security_group_for_vpcs: Some(items) })
        })
    }

    // ---- ClassicLink (retired with EC2-Classic) ---------------------------------------------------

    pub(crate) fn describe_vpc_classic_link_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcClassicLinkRequest,
    ) -> Result<t::DescribeVpcClassicLinkResult, ServiceError> {
        authorize(ctx, "DescribeVpcClassicLink", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let ids = input.vpc_ids.clone().unwrap_or_default();
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            Kind::Vpc.check_all(&ids, |id| r.vpcs.contains_key(id))?;
            let mut out = Vec::new();
            for v in r.vpcs.values() {
                let id = v.vpc.vpc_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let ok = filters.matches(v.vpc.tags.as_ref(), |name| {
                    Some(match name {
                        "is-classic-link-enabled" => vec!["false".into()],
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(t::VpcClassicLink {
                        vpc_id: Some(id),
                        classic_link_enabled: Some(false),
                        tags: v.vpc.tags.clone(),
                    });
                }
            }
            Ok(t::DescribeVpcClassicLinkResult { vpcs: Some(out) })
        })
    }

    pub(crate) fn describe_vpc_classic_link_dns_support_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcClassicLinkDnsSupportRequest,
    ) -> Result<t::DescribeVpcClassicLinkDnsSupportResult, ServiceError> {
        authorize(ctx, "DescribeVpcClassicLinkDnsSupport", &[("*".into(), ConditionContext::new())], None)?;
        let ids = input.vpc_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Vpc.check_all(&ids, |id| r.vpcs.contains_key(id))?;
            let all: Vec<t::ClassicLinkDnsSupport> = r
                .vpcs
                .values()
                .filter(|v| ids.is_empty() || ids.contains(v.vpc.vpc_id.as_ref().unwrap()))
                .map(|v| t::ClassicLinkDnsSupport {
                    vpc_id: v.vpc.vpc_id.clone(),
                    classic_link_dns_supported: Some(false),
                })
                .collect();
            let (items, next_token) = paginate(all, input.max_results, &input.next_token)?;
            Ok(t::DescribeVpcClassicLinkDnsSupportResult { vpcs: Some(items), next_token })
        })
    }

    pub(crate) fn enable_vpc_classic_link_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableVpcClassicLinkRequest,
    ) -> Result<t::EnableVpcClassicLinkResult, ServiceError> {
        let vpc = input.vpc_id.clone();
        authorize_on(
            self,
            ctx,
            "EnableVpcClassicLink",
            Kind::Vpc,
            "vpc",
            &vpc,
            |r| r.vpcs.get(&vpc).map(|v| v.vpc.tags.clone()),
            input.dry_run,
        )?;
        Err(err(
            "UnsupportedOperation",
            "ClassicLink is no longer supported. EC2-Classic was retired on August 15, 2023.",
        ))
    }

    pub(crate) fn disable_vpc_classic_link_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableVpcClassicLinkRequest,
    ) -> Result<t::DisableVpcClassicLinkResult, ServiceError> {
        let vpc = input.vpc_id.clone();
        authorize_on(
            self,
            ctx,
            "DisableVpcClassicLink",
            Kind::Vpc,
            "vpc",
            &vpc,
            |r| r.vpcs.get(&vpc).map(|v| v.vpc.tags.clone()),
            input.dry_run,
        )?;
        // ClassicLink can no longer be enabled, so it is already off.
        Ok(t::DisableVpcClassicLinkResult { r#return: Some(true) })
    }
}

fn push_ip(r: &mut RegionState, eni_id: &str, ip: &str, region: &str) {
    let eni = r.network_interfaces.get_mut(eni_id).expect("checked");
    eni.private_ip_addresses.get_or_insert_with(Vec::new).push(t::NetworkInterfacePrivateIpAddress {
        primary: Some(false),
        private_ip_address: Some(ip.into()),
        private_dns_name: Some(crate::util::private_dns(region, ip)),
        association: None,
    });
}

/// A free, aligned `/28` in the subnet (or the one asked for).
fn allocate_prefix(r: &RegionState, subnet: &str, want: Option<&str>) -> Result<String, ServiceError> {
    let cidr = r
        .subnets
        .get(subnet)
        .and_then(|s| s.cidr_block.as_deref())
        .and_then(Cidr::parse)
        .ok_or_else(|| Kind::Subnet.not_found(subnet))?;
    let used = used_ips(r, subnet);
    let taken: Vec<Cidr> = r
        .network_interfaces
        .values()
        .filter(|n| n.subnet_id.as_deref() == Some(subnet))
        .flat_map(|n| n.ipv4_prefixes.iter().flatten().filter_map(|p| p.ipv4_prefix.as_deref().and_then(Cidr::parse)))
        .collect();
    let free = |p: &Cidr| {
        cidr.contains_cidr(p)
            && p.first() >= cidr.first() + 4
            && p.last() < cidr.last()
            && !used.iter().any(|ip| p.contains(*ip))
            && !taken.iter().any(|t| t.overlaps(p))
    };
    if let Some(w) = want {
        let p = Cidr::parse(w).filter(|p| p.prefix == 28 && p.is_network()).ok_or_else(|| {
            invalid_parameter(format!("Invalid value '{w}' for Ipv4Prefix. It must be a /28 prefix."))
        })?;
        if !free(&p) {
            return Err(err("InvalidParameterValue", format!("The prefix {w} is not available in subnet {subnet}.")));
        }
        return Ok(w.to_string());
    }
    let mut base = cidr.first() & !0xf;
    while base + 15 <= cidr.last() {
        let p = Cidr { base, prefix: 28 };
        if free(&p) {
            return Ok(format!("{}/28", ip_str(base)));
        }
        base += 16;
    }
    Err(err(
        "InsufficientCidrBlocks",
        format!("The specified subnet {subnet} does not have enough free cidr blocks to satisfy the request."),
    ))
}
