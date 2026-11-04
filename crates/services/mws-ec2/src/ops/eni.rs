//! Elastic network interfaces and Elastic IP addresses.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::RegionState;
use crate::util::{
    arn, authorize, b, err, missing_parameter, new_id, new_mac, new_public_ip, paginate, private_dns, public_dns,
    request_tag_context, resource_tag_context, s, some_tags, tags_for, Filters, Kind,
};
use crate::{account_of, Ec2};

/// A new network interface in `subnet` with primary address `ip`.
#[allow(clippy::too_many_arguments)]
pub fn new_eni(
    r: &mut RegionState,
    account: &str,
    region: &str,
    subnet: &t::Subnet,
    ip: &str,
    groups: Vec<t::GroupIdentifier>,
    description: &str,
    interface_type: &str,
    _now: DateTime<Utc>,
) -> String {
    let id = new_id("eni");
    let dns = private_dns(region, ip);
    r.network_interfaces.insert(
        id.clone(),
        t::NetworkInterface {
            network_interface_id: Some(id.clone()),
            subnet_id: subnet.subnet_id.clone(),
            vpc_id: subnet.vpc_id.clone(),
            availability_zone: subnet.availability_zone.clone(),
            availability_zone_id: subnet.availability_zone_id.clone(),
            description: Some(description.into()),
            groups: Some(groups),
            interface_type: Some(interface_type.into()),
            mac_address: Some(new_mac()),
            owner_id: Some(account.into()),
            requester_id: None,
            requester_managed: Some(false),
            source_dest_check: Some(true),
            status: Some("available".into()),
            private_ip_address: Some(ip.into()),
            private_dns_name: Some(dns.clone()),
            private_ip_addresses: Some(vec![t::NetworkInterfacePrivateIpAddress {
                primary: Some(true),
                private_ip_address: Some(ip.into()),
                private_dns_name: Some(dns),
                association: None,
            }]),
            ipv6_addresses: Some(Vec::new()),
            tag_set: None,
            ..Default::default()
        },
    );
    id
}

/// Give an interface an auto-assigned public address (owned by Amazon).
pub fn assign_public_ip(r: &mut RegionState, region: &str, eni_id: &str) {
    if let Some(eni) = r.network_interfaces.get_mut(eni_id) {
        let ip = new_public_ip();
        let assoc = t::NetworkInterfaceAssociation {
            ip_owner_id: Some("amazon".into()),
            public_ip: Some(ip.clone()),
            public_dns_name: Some(public_dns(region, &ip)),
            ..Default::default()
        };
        set_association(eni, Some(assoc));
    }
}

/// Drop an auto-assigned public address (on stop); Elastic IPs stay.
pub fn release_public_ip(r: &mut RegionState, eni_id: &str) {
    if let Some(eni) = r.network_interfaces.get_mut(eni_id) {
        if eni.association.as_ref().is_some_and(|a| a.allocation_id.is_none()) {
            set_association(eni, None);
        }
    }
}

fn set_association(eni: &mut t::NetworkInterface, assoc: Option<t::NetworkInterfaceAssociation>) {
    eni.association = assoc.clone();
    if let Some(primary) = eni.private_ip_addresses.iter_mut().flatten().find(|p| p.primary == Some(true)) {
        primary.association = assoc;
    }
}

fn eni_filter_values(n: &t::NetworkInterface, name: &str) -> Option<Vec<String>> {
    let att = n.attachment.clone().unwrap_or_default();
    let assoc = n.association.clone().unwrap_or_default();
    let groups = n.groups.clone().unwrap_or_default();
    Some(match name {
        "network-interface-id" => s(&n.network_interface_id),
        "subnet-id" => s(&n.subnet_id),
        "vpc-id" => s(&n.vpc_id),
        "availability-zone" => s(&n.availability_zone),
        "description" => s(&n.description),
        "status" => s(&n.status),
        "interface-type" => s(&n.interface_type),
        "mac-address" => s(&n.mac_address),
        "owner-id" => s(&n.owner_id),
        "private-ip-address" | "addresses.private-ip-address" => {
            n.private_ip_addresses.iter().flatten().filter_map(|p| p.private_ip_address.clone()).collect()
        }
        "private-dns-name" => s(&n.private_dns_name),
        "requester-managed" => b(n.requester_managed),
        "source-dest-check" => b(n.source_dest_check),
        "group-id" => groups.iter().filter_map(|g| g.group_id.clone()).collect(),
        "group-name" => groups.iter().filter_map(|g| g.group_name.clone()).collect(),
        "attachment.attachment-id" => s(&att.attachment_id),
        "attachment.instance-id" => s(&att.instance_id),
        "attachment.instance-owner-id" => s(&att.instance_owner_id),
        "attachment.device-index" => att.device_index.map(|d| d.to_string()).into_iter().collect(),
        "attachment.status" => s(&att.status),
        "attachment.delete-on-termination" => b(att.delete_on_termination),
        "association.public-ip" => s(&assoc.public_ip),
        "association.allocation-id" => s(&assoc.allocation_id),
        "association.association-id" => s(&assoc.association_id),
        "association.ip-owner-id" => s(&assoc.ip_owner_id),
        _ => return None,
    })
}

impl Ec2 {
    // ---- network interfaces ------------------------------------------------------------------

    pub(crate) fn create_network_interface_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateNetworkInterfaceRequest,
    ) -> Result<t::CreateNetworkInterfaceResult, ServiceError> {
        let account = account_of(ctx);
        Kind::Subnet.check(&input.subnet_id)?;
        let tags = tags_for(&input.tag_specifications, "network-interface", &["network-interface"])?;
        authorize(
            ctx,
            "CreateNetworkInterface",
            &[
                (arn(ctx, &account, "network-interface/*"), request_tag_context(&tags)),
                (arn(ctx, &account, &format!("subnet/{}", input.subnet_id)), ConditionContext::new()),
            ],
            input.dry_run,
        )?;
        let region = ctx.region.clone();
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let subnet =
                r.subnets.get(&input.subnet_id).ok_or_else(|| Kind::Subnet.not_found(&input.subnet_id))?.clone();
            let vpc_id = subnet.vpc_id.clone().unwrap_or_default();
            let groups = resolve_groups(r, &vpc_id, input.groups.as_deref())?;
            let ip = match input.private_ip_address.clone().or_else(|| {
                input
                    .private_ip_addresses
                    .iter()
                    .flatten()
                    .find(|p| p.primary == Some(true))
                    .and_then(|p| p.private_ip_address.clone())
            }) {
                Some(ip) => {
                    super::vpc::check_ip(r, &input.subnet_id, &ip)?;
                    ip
                }
                None => super::vpc::allocate_ip(r, &input.subnet_id).ok_or_else(|| {
                    err("InsufficientFreeAddressesInSubnet", "Insufficient free IP addresses in subnet.")
                })?,
            };
            let id = new_eni(
                r,
                &account,
                &region,
                &subnet,
                &ip,
                groups,
                input.description.as_deref().unwrap_or_default(),
                input.interface_type.as_deref().unwrap_or("interface"),
                now,
            );
            let eni = r.network_interfaces.get_mut(&id).expect("just made");
            eni.tag_set = some_tags(tags);
            Ok(t::CreateNetworkInterfaceResult {
                network_interface: Some(eni.clone()),
                client_token: input.client_token.clone(),
            })
        })
    }

    fn eni_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        eni_id: &str,
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::NetworkInterface.check(eni_id)?;
        let tags = self.with_region(ctx, |r| r.network_interfaces.get(eni_id).map(|n| n.tag_set.clone()));
        let tags = tags.ok_or_else(|| Kind::NetworkInterface.not_found(eni_id))?;
        authorize(
            ctx,
            action,
            &[(arn(ctx, &account, &format!("network-interface/{eni_id}")), resource_tag_context(tags.as_ref()))],
            dry_run,
        )
    }

    pub(crate) fn delete_network_interface_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteNetworkInterfaceRequest,
    ) -> Result<(), ServiceError> {
        self.eni_authorize(ctx, "DeleteNetworkInterface", &input.network_interface_id, input.dry_run)?;
        self.with_region(ctx, |r| {
            let eni = r
                .network_interfaces
                .get(&input.network_interface_id)
                .ok_or_else(|| Kind::NetworkInterface.not_found(&input.network_interface_id))?;
            if eni.attachment.is_some() || eni.status.as_deref() == Some("in-use") {
                return Err(err(
                    "InvalidNetworkInterface.InUse",
                    format!("The network interface '{}' is currently in use.", input.network_interface_id),
                ));
            }
            r.network_interfaces.remove(&input.network_interface_id);
            for a in r.addresses.values_mut() {
                if a.network_interface_id.as_deref() == Some(input.network_interface_id.as_str()) {
                    a.association_id = None;
                    a.network_interface_id = None;
                    a.network_interface_owner_id = None;
                    a.private_ip_address = None;
                }
            }
            Ok(())
        })
    }

    pub(crate) fn describe_network_interfaces_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeNetworkInterfacesRequest,
    ) -> Result<t::DescribeNetworkInterfacesResult, ServiceError> {
        authorize(ctx, "DescribeNetworkInterfaces", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.network_interface_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::NetworkInterface.check_all(&ids, |id| r.network_interfaces.contains_key(id))?;
            let mut out = Vec::new();
            for n in r.network_interfaces.values() {
                if !ids.is_empty() && !ids.contains(n.network_interface_id.as_ref().unwrap()) {
                    continue;
                }
                if filters.matches(n.tag_set.as_ref(), |name| eni_filter_values(n, name))? {
                    out.push(n.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeNetworkInterfacesResult { network_interfaces: Some(items), next_token })
        })
    }

    pub(crate) fn attach_network_interface_op(
        &self,
        ctx: &RequestContext,
        input: t::AttachNetworkInterfaceRequest,
    ) -> Result<t::AttachNetworkInterfaceResult, ServiceError> {
        self.eni_authorize(ctx, "AttachNetworkInterface", &input.network_interface_id, input.dry_run)?;
        Kind::Instance.check(&input.instance_id)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let inst =
                r.instances.get(&input.instance_id).ok_or_else(|| Kind::Instance.not_found(&input.instance_id))?;
            let state = inst.instance.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default();
            if !matches!(state.as_str(), "running" | "stopped") {
                return Err(err(
                    "IncorrectState",
                    format!("The instance '{}' is not in the 'running' or 'stopped' states.", input.instance_id),
                ));
            }
            let zone = inst.instance.placement.as_ref().and_then(|p| p.availability_zone.clone());
            let owner = inst.owner_id.clone();
            if r.network_interfaces.values().any(|n| {
                n.attachment.as_ref().is_some_and(|a| {
                    a.instance_id.as_deref() == Some(input.instance_id.as_str())
                        && a.device_index == Some(input.device_index)
                })
            }) {
                return Err(err(
                    "InvalidParameterValue",
                    format!(
                        "Instance '{}' already has an interface attached at device index '{}'.",
                        input.instance_id, input.device_index
                    ),
                ));
            }
            let eni = r
                .network_interfaces
                .get_mut(&input.network_interface_id)
                .ok_or_else(|| Kind::NetworkInterface.not_found(&input.network_interface_id))?;
            if eni.attachment.is_some() {
                return Err(err(
                    "InvalidNetworkInterface.InUse",
                    format!("Interface: [{}] in use.", input.network_interface_id),
                ));
            }
            if eni.availability_zone != zone {
                return Err(err(
                    "InvalidParameterValue",
                    "The network interface and the instance must be in the same availability zone.",
                ));
            }
            let id = new_id("eni-attach");
            eni.status = Some("in-use".into());
            eni.attachment = Some(t::NetworkInterfaceAttachment {
                attachment_id: Some(id.clone()),
                attach_time: Some(now),
                delete_on_termination: Some(false),
                device_index: Some(input.device_index),
                network_card_index: Some(input.network_card_index.unwrap_or(0)),
                instance_id: Some(input.instance_id.clone()),
                instance_owner_id: Some(owner),
                status: Some("attached".into()),
                ..Default::default()
            });
            Ok(t::AttachNetworkInterfaceResult {
                attachment_id: Some(id),
                network_card_index: Some(input.network_card_index.unwrap_or(0)),
            })
        })
    }

    pub(crate) fn detach_network_interface_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachNetworkInterfaceRequest,
    ) -> Result<(), ServiceError> {
        authorize(
            ctx,
            "DetachNetworkInterface",
            &[(arn(ctx, &account_of(ctx), "network-interface/*"), ConditionContext::new())],
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let eni = r
                .network_interfaces
                .values_mut()
                .find(|n| {
                    n.attachment.as_ref().and_then(|a| a.attachment_id.as_deref()) == Some(input.attachment_id.as_str())
                })
                .ok_or_else(|| {
                    err(
                        "InvalidAttachmentID.NotFound",
                        format!("Interface does not have attachment id: {}", input.attachment_id),
                    )
                })?;
            if eni.attachment.as_ref().and_then(|a| a.device_index) == Some(0) {
                return Err(err(
                    "OperationNotPermitted",
                    "The network interface at device index 0 cannot be detached.",
                ));
            }
            eni.attachment = None;
            eni.status = Some("available".into());
            Ok(())
        })
    }

    pub(crate) fn modify_network_interface_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyNetworkInterfaceAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.eni_authorize(ctx, "ModifyNetworkInterfaceAttribute", &input.network_interface_id, input.dry_run)?;
        self.with_region(ctx, |r| {
            let vpc_id = r
                .network_interfaces
                .get(&input.network_interface_id)
                .and_then(|n| n.vpc_id.clone())
                .unwrap_or_default();
            let groups = match &input.groups {
                Some(g) => Some(resolve_groups(r, &vpc_id, Some(g))?),
                None => None,
            };
            let eni = r
                .network_interfaces
                .get_mut(&input.network_interface_id)
                .ok_or_else(|| Kind::NetworkInterface.not_found(&input.network_interface_id))?;
            if let Some(d) = input.description.as_ref().and_then(|d| d.value.clone()) {
                eni.description = Some(d);
            }
            if let Some(v) = input.source_dest_check.as_ref().and_then(|v| v.value) {
                eni.source_dest_check = Some(v);
            }
            if let Some(g) = groups {
                eni.groups = Some(g);
            }
            if let Some(change) = &input.attachment {
                let att = eni
                    .attachment
                    .as_mut()
                    .ok_or_else(|| err("InvalidAttachmentID.NotFound", "The network interface is not attached."))?;
                if change.attachment_id.is_some() && change.attachment_id != att.attachment_id {
                    return Err(err(
                        "InvalidAttachmentID.NotFound",
                        format!(
                            "Interface does not have attachment id: {}",
                            change.attachment_id.clone().unwrap_or_default()
                        ),
                    ));
                }
                if let Some(d) = change.delete_on_termination {
                    att.delete_on_termination = Some(d);
                }
            }
            Ok(())
        })
    }

    // ---- Elastic IPs --------------------------------------------------------------------------

    pub(crate) fn allocate_address_op(
        &self,
        ctx: &RequestContext,
        input: t::AllocateAddressRequest,
    ) -> Result<t::AllocateAddressResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "elastic-ip", &["elastic-ip"])?;
        authorize(
            ctx,
            "AllocateAddress",
            &[(arn(ctx, &account, "elastic-ip/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        let region = ctx.region.clone();
        self.with_region(ctx, |r| {
            if r.addresses.len() >= 5 {
                return Err(err("AddressLimitExceeded", "The maximum number of addresses has been reached."));
            }
            let ip = input.address.clone().unwrap_or_else(new_public_ip);
            if r.addresses.values().any(|a| a.public_ip.as_deref() == Some(ip.as_str())) {
                return Err(err("InvalidAddress.InUse", format!("Address {ip} is in use.")));
            }
            let id = new_id("eipalloc");
            let addr = t::Address {
                allocation_id: Some(id.clone()),
                public_ip: Some(ip.clone()),
                domain: Some("vpc".into()),
                public_ipv4_pool: Some(input.public_ipv4_pool.clone().unwrap_or_else(|| "amazon".into())),
                network_border_group: Some(input.network_border_group.clone().unwrap_or_else(|| region.clone())),
                tags: some_tags(tags),
                ..Default::default()
            };
            r.addresses.insert(id.clone(), addr.clone());
            Ok(t::AllocateAddressResult {
                allocation_id: Some(id),
                public_ip: Some(ip),
                domain: Some("vpc".into()),
                public_ipv4_pool: addr.public_ipv4_pool,
                network_border_group: addr.network_border_group,
                ..Default::default()
            })
        })
    }

    fn find_allocation(
        r: &RegionState,
        allocation_id: &Option<String>,
        public_ip: &Option<String>,
    ) -> Result<String, ServiceError> {
        match (allocation_id, public_ip) {
            (Some(id), _) => {
                Kind::Allocation.check(id)?;
                r.addresses.contains_key(id).then(|| id.clone()).ok_or_else(|| Kind::Allocation.not_found(id))
            }
            (None, Some(ip)) => r
                .addresses
                .values()
                .find(|a| a.public_ip.as_deref() == Some(ip.as_str()))
                .and_then(|a| a.allocation_id.clone())
                .ok_or_else(|| err("InvalidAddress.NotFound", format!("Address '{ip}' not found."))),
            (None, None) => Err(missing_parameter("AllocationId")),
        }
    }

    pub(crate) fn release_address_op(
        &self,
        ctx: &RequestContext,
        input: t::ReleaseAddressRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let alloc = self.with_region(ctx, |r| Self::find_allocation(r, &input.allocation_id, &input.public_ip))?;
        authorize(
            ctx,
            "ReleaseAddress",
            &[(arn(ctx, &account, &format!("elastic-ip/{alloc}")), ConditionContext::new())],
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            if r.addresses.get(&alloc).is_some_and(|a| a.association_id.is_some()) {
                return Err(err("InvalidIPAddress.InUse", "Address is in use."));
            }
            r.addresses.remove(&alloc);
            Ok(())
        })
    }

    pub(crate) fn associate_address_op(
        &self,
        ctx: &RequestContext,
        input: t::AssociateAddressRequest,
    ) -> Result<t::AssociateAddressResult, ServiceError> {
        let account = account_of(ctx);
        let alloc = self.with_region(ctx, |r| Self::find_allocation(r, &input.allocation_id, &input.public_ip))?;
        let mut resources = vec![(arn(ctx, &account, &format!("elastic-ip/{alloc}")), ConditionContext::new())];
        if let Some(i) = &input.instance_id {
            Kind::Instance.check(i)?;
            resources.push((arn(ctx, &account, &format!("instance/{i}")), ConditionContext::new()));
        }
        if let Some(n) = &input.network_interface_id {
            Kind::NetworkInterface.check(n)?;
            resources.push((arn(ctx, &account, &format!("network-interface/{n}")), ConditionContext::new()));
        }
        authorize(ctx, "AssociateAddress", &resources, input.dry_run)?;
        let region = ctx.region.clone();
        self.with_region(ctx, |r| {
            let eni_id = match (&input.network_interface_id, &input.instance_id) {
                (Some(n), _) => {
                    if !r.network_interfaces.contains_key(n) {
                        return Err(Kind::NetworkInterface.not_found(n));
                    }
                    n.clone()
                }
                (None, Some(i)) => {
                    let inst = r.instances.get(i).ok_or_else(|| Kind::Instance.not_found(i))?;
                    let state = inst.instance.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default();
                    if !matches!(state.as_str(), "running" | "stopped" | "pending") {
                        return Err(err(
                            "IncorrectInstanceState",
                            format!("The pending instance '{i}' is not in a valid state for this operation."),
                        ));
                    }
                    primary_eni(r, i).ok_or_else(|| {
                        err("InvalidInstanceID", format!("The instance '{i}' has no network interface"))
                    })?
                }
                (None, None) => return Err(missing_parameter("InstanceId")),
            };
            let addr = r.addresses.get(&alloc).expect("found above").clone();
            if addr.association_id.is_some() && input.allow_reassociation != Some(true) {
                return Err(err(
                    "Resource.AlreadyAssociated",
                    format!(
                        "resource {alloc} is already associated with associate-id {}",
                        addr.association_id.unwrap_or_default()
                    ),
                ));
            }
            // An address moves: clear it from its old interface first.
            if let Some(old) = &addr.network_interface_id {
                if let Some(e) = r.network_interfaces.get_mut(old) {
                    set_association(e, None);
                }
            }
            let eni = r.network_interfaces.get_mut(&eni_id).expect("checked");
            let private_ip = input.private_ip_address.clone().or_else(|| eni.private_ip_address.clone());
            let assoc_id = new_id("eipassoc");
            let ip = addr.public_ip.clone().unwrap_or_default();
            set_association(
                eni,
                Some(t::NetworkInterfaceAssociation {
                    allocation_id: Some(alloc.clone()),
                    association_id: Some(assoc_id.clone()),
                    ip_owner_id: Some(account.clone()),
                    public_ip: Some(ip.clone()),
                    public_dns_name: Some(public_dns(&region, &ip)),
                    ..Default::default()
                }),
            );
            let instance_id = eni.attachment.as_ref().and_then(|a| a.instance_id.clone());
            let a = r.addresses.get_mut(&alloc).expect("checked");
            a.association_id = Some(assoc_id.clone());
            a.network_interface_id = Some(eni_id);
            a.network_interface_owner_id = Some(account.clone());
            a.private_ip_address = private_ip;
            a.instance_id = instance_id;
            Ok(t::AssociateAddressResult { association_id: Some(assoc_id) })
        })
    }

    pub(crate) fn disassociate_address_op(
        &self,
        ctx: &RequestContext,
        input: t::DisassociateAddressRequest,
    ) -> Result<(), ServiceError> {
        authorize(
            ctx,
            "DisassociateAddress",
            &[(arn(ctx, &account_of(ctx), "elastic-ip/*"), ConditionContext::new())],
            input.dry_run,
        )?;
        let region = ctx.region.clone();
        self.with_region(ctx, |r| {
            let alloc = match (&input.association_id, &input.public_ip) {
                (Some(assoc), _) => r
                    .addresses
                    .values()
                    .find(|a| a.association_id.as_deref() == Some(assoc.as_str()))
                    .and_then(|a| a.allocation_id.clone())
                    .ok_or_else(|| {
                        err("InvalidAssociationID.NotFound", format!("The association ID '{assoc}' does not exist"))
                    })?,
                (None, Some(ip)) => Self::find_allocation(r, &None, &Some(ip.clone()))?,
                (None, None) => return Err(missing_parameter("AssociationId")),
            };
            let a = r.addresses.get_mut(&alloc).expect("found");
            let eni_id = a.network_interface_id.take();
            a.association_id = None;
            a.network_interface_owner_id = None;
            a.private_ip_address = None;
            a.instance_id = None;
            if let Some(eni_id) = eni_id {
                let running_instance = r
                    .network_interfaces
                    .get(&eni_id)
                    .and_then(|e| e.attachment.as_ref().and_then(|a| a.instance_id.clone()))
                    .and_then(|i| r.instances.get(&i))
                    .is_some_and(|i| i.instance.state.as_ref().and_then(|s| s.name.as_deref()) == Some("running"));
                if let Some(e) = r.network_interfaces.get_mut(&eni_id) {
                    set_association(e, None);
                }
                // A public subnet's running instance gets a fresh public address back.
                let public_subnet = r
                    .network_interfaces
                    .get(&eni_id)
                    .and_then(|e| e.subnet_id.clone())
                    .and_then(|s| r.subnets.get(&s))
                    .is_some_and(|s| s.map_public_ip_on_launch == Some(true));
                if running_instance && public_subnet {
                    assign_public_ip(r, &region, &eni_id);
                }
            }
            Ok(())
        })
    }

    pub(crate) fn describe_addresses_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeAddressesRequest,
    ) -> Result<t::DescribeAddressesResult, ServiceError> {
        authorize(ctx, "DescribeAddresses", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.allocation_ids.clone().unwrap_or_default();
        let ips = input.public_ips.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Allocation.check_all(&ids, |id| r.addresses.contains_key(id))?;
            for ip in &ips {
                if !r.addresses.values().any(|a| a.public_ip.as_deref() == Some(ip.as_str())) {
                    return Err(err("InvalidAddress.NotFound", format!("Address '{ip}' not found.")));
                }
            }
            let mut out = Vec::new();
            for a in r.addresses.values() {
                if !ids.is_empty() && !ids.contains(a.allocation_id.as_ref().unwrap()) {
                    continue;
                }
                if !ips.is_empty() && !a.public_ip.as_ref().is_some_and(|p| ips.contains(p)) {
                    continue;
                }
                let ok = filters.matches(a.tags.as_ref(), |name| {
                    Some(match name {
                        "allocation-id" => s(&a.allocation_id),
                        "association-id" => s(&a.association_id),
                        "domain" => s(&a.domain),
                        "instance-id" => s(&a.instance_id),
                        "network-border-group" => s(&a.network_border_group),
                        "network-interface-id" => s(&a.network_interface_id),
                        "network-interface-owner-id" => s(&a.network_interface_owner_id),
                        "private-ip-address" => s(&a.private_ip_address),
                        "public-ip" => s(&a.public_ip),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(a.clone());
                }
            }
            Ok(t::DescribeAddressesResult { addresses: Some(out) })
        })
    }
}

/// The interface at device index 0 of an instance.
pub fn primary_eni(r: &RegionState, instance_id: &str) -> Option<String> {
    r.network_interfaces
        .values()
        .find(|n| {
            n.attachment
                .as_ref()
                .is_some_and(|a| a.instance_id.as_deref() == Some(instance_id) && a.device_index == Some(0))
        })
        .and_then(|n| n.network_interface_id.clone())
}

/// Security groups by id, checked to be in `vpc_id`; the VPC's default
/// group when none are named.
pub fn resolve_groups(
    r: &RegionState,
    vpc_id: &str,
    ids: Option<&[String]>,
) -> Result<Vec<t::GroupIdentifier>, ServiceError> {
    let ids: Vec<String> = match ids {
        Some(ids) if !ids.is_empty() => ids.to_vec(),
        _ => r
            .security_groups
            .values()
            .filter(|g| g.vpc_id.as_deref() == Some(vpc_id) && g.group_name.as_deref() == Some("default"))
            .filter_map(|g| g.group_id.clone())
            .collect(),
    };
    let mut out = Vec::new();
    for id in ids {
        Kind::Group.check(&id)?;
        let g = r.security_groups.get(&id).ok_or_else(|| Kind::Group.not_found(&id))?;
        if g.vpc_id.as_deref() != Some(vpc_id) {
            return Err(err(
                "InvalidParameter",
                format!("Security group {id} and subnet belong to different networks."),
            ));
        }
        out.push(t::GroupIdentifier { group_id: Some(id), group_name: g.group_name.clone() });
    }
    Ok(out)
}
