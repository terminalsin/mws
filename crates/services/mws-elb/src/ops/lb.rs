//! Load balancers: create, describe, delete, subnets, security groups,
//! address types, attributes, capacity reservations and IPAM pools.

use std::collections::BTreeSet;

use mws_core::{RequestContext, ServiceError};

use crate::names::{self, validation};
use crate::state::{LoadBalancerRecord, RegionState};
use crate::v2::{errors, types as t};
use crate::{account_of, catalog, Elb};

pub(crate) fn lb_not_found() -> ServiceError {
    errors::load_balancer_not_found("One or more load balancers not found")
}

pub(crate) fn find_lb<'a>(r: &'a RegionState, arn: &str) -> Result<&'a LoadBalancerRecord, ServiceError> {
    r.load_balancers.get(arn).ok_or_else(lb_not_found)
}

/// Subnets resolved through EC2: `(subnet id, AZ, VPC)` per mapping.
struct Placement {
    vpc_id: String,
    zones: Vec<t::AvailabilityZone>,
}

impl Elb {
    fn place(
        &self,
        ctx: &RequestContext,
        ty: &str,
        subnets: Option<&Vec<String>>,
        mappings: Option<&Vec<t::SubnetMapping>>,
        current_vpc: Option<&str>,
    ) -> Result<Placement, ServiceError> {
        let account = account_of(ctx);
        let mut wanted: Vec<t::SubnetMapping> = Vec::new();
        match (subnets.filter(|s| !s.is_empty()), mappings.filter(|m| !m.is_empty())) {
            (Some(_), Some(_)) => {
                return Err(validation("You can specify subnets or subnet mappings, not both"));
            }
            (Some(s), None) => {
                wanted =
                    s.iter().map(|id| t::SubnetMapping { subnet_id: Some(id.clone()), ..Default::default() }).collect()
            }
            (None, Some(m)) => wanted.clone_from(m),
            (None, None) => {}
        }
        if wanted.is_empty() {
            return Err(validation("At least one subnet must be specified"));
        }
        let ec2 = self.ec2();
        let mut vpc: Option<String> = current_vpc.map(str::to_string);
        let mut seen_zones = BTreeSet::new();
        let mut zones = Vec::new();
        for m in &wanted {
            let id = m.subnet_id.clone().unwrap_or_default();
            if ty != "network" && (m.allocation_id.is_some() || m.private_i_pv4_address.is_some()) {
                return Err(errors::invalid_configuration_request(
                    "Subnet mappings with an allocation ID or private IPv4 address are only supported for Network Load Balancers",
                ));
            }
            let info = match ec2 {
                Some(ec2) => ec2
                    .subnet_info(ctx, &account, &id)
                    .ok_or_else(|| errors::subnet_not_found(format!("The subnet ID '{id}' is not valid")))?,
                None => mws_ec2::SubnetInfo {
                    subnet_id: id.clone(),
                    vpc_id: current_vpc.unwrap_or("vpc-00000000").to_string(),
                    availability_zone: format!("{}a", ctx.region),
                    availability_zone_id: String::new(),
                    cidr_block: None,
                    ipv6_cidr_blocks: Vec::new(),
                },
            };
            match &vpc {
                Some(v) if *v != info.vpc_id => {
                    return Err(errors::invalid_configuration_request(format!(
                        "Subnet '{id}' is not in VPC '{v}'; all subnets of a load balancer must be in the same VPC"
                    )))
                }
                _ => vpc = Some(info.vpc_id.clone()),
            }
            if !seen_zones.insert(info.availability_zone.clone()) {
                return Err(errors::invalid_configuration_request(
                    "A load balancer cannot be attached to multiple subnets in the same Availability Zone",
                ));
            }
            if let Some(ip) = &m.private_i_pv4_address {
                if info.cidr_block.as_deref().is_some_and(|c| !names::ipv4_in_cidr(ip, c)) {
                    return Err(errors::invalid_configuration_request(format!(
                        "The private IPv4 address '{ip}' is not in the subnet '{id}'"
                    )));
                }
            }
            let addresses =
                if m.allocation_id.is_some() || m.private_i_pv4_address.is_some() || m.i_pv6_address.is_some() {
                    Some(vec![t::LoadBalancerAddress {
                        ip_address: None,
                        allocation_id: m.allocation_id.clone(),
                        private_i_pv4_address: m.private_i_pv4_address.clone(),
                        i_pv6_address: m.i_pv6_address.clone(),
                    }])
                } else if ty == "network" {
                    Some(Vec::new())
                } else {
                    None
                };
            zones.push(t::AvailabilityZone {
                zone_name: Some(info.availability_zone.clone()),
                subnet_id: Some(id),
                outpost_id: None,
                load_balancer_addresses: addresses,
                source_nat_ipv6_prefixes: m.source_nat_ipv6_prefix.clone().map(|p| vec![p]),
            });
        }
        if ty == "application" && zones.len() < 2 {
            return Err(validation("At least two subnets in two different Availability Zones must be specified"));
        }
        Ok(Placement { vpc_id: vpc.unwrap_or_default(), zones })
    }

    fn check_security_groups(&self, ctx: &RequestContext, vpc_id: &str, groups: &[String]) -> Result<(), ServiceError> {
        let Some(ec2) = self.ec2() else { return Ok(()) };
        let account = account_of(ctx);
        for g in groups {
            match ec2.security_group_info(ctx, &account, g) {
                Some(info) if info.vpc_id == vpc_id => {}
                Some(_) => {
                    return Err(errors::invalid_security_group(format!(
                        "Security group '{g}' does not belong to VPC '{vpc_id}'"
                    )))
                }
                None => return Err(errors::invalid_security_group(format!("Security group '{g}' does not exist"))),
            }
        }
        Ok(())
    }

    pub(crate) fn create_load_balancer_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateLoadBalancerInput,
    ) -> Result<t::CreateLoadBalancerOutput, ServiceError> {
        let ty = input.r#type.clone().unwrap_or_else(|| "application".into());
        if !matches!(ty.as_str(), "application" | "network" | "gateway") {
            return Err(validation(format!("Load balancer type '{ty}' is not valid")));
        }
        names::check_name("Load balancer", &input.name)?;
        if input.name.starts_with("internal-") {
            return Err(validation(format!("Load balancer name '{}' cannot begin with 'internal-'", input.name)));
        }
        let tags = input.tags.clone().unwrap_or_default();
        names::check_tags(&tags)?;
        let scheme = match (&input.scheme, ty.as_str()) {
            (Some(_), "gateway") => {
                return Err(validation("Scheme is not supported for load balancers of type 'gateway'"));
            }
            (Some(s), _) => s.clone(),
            (None, _) => "internet-facing".into(),
        };
        if !matches!(scheme.as_str(), "internet-facing" | "internal") {
            return Err(errors::invalid_scheme(format!("The scheme '{scheme}' is not valid")));
        }
        let ip_type = input.ip_address_type.clone().unwrap_or_else(|| "ipv4".into());
        match (ty.as_str(), ip_type.as_str()) {
            (_, "ipv4" | "dualstack") => {}
            ("application", "dualstack-without-public-ipv4") if scheme == "internet-facing" => {}
            _ => return Err(validation(format!("IP address type '{ip_type}' is not valid for this load balancer"))),
        }
        if ty == "gateway" && input.security_groups.as_ref().is_some_and(|s| !s.is_empty()) {
            return Err(validation("Security groups are not supported for load balancers of type 'gateway'"));
        }
        let placement = self.place(ctx, &ty, input.subnets.as_ref(), input.subnet_mappings.as_ref(), None)?;
        let mut security_groups = input.security_groups.clone().unwrap_or_default();
        self.check_security_groups(ctx, &placement.vpc_id, &security_groups)?;
        if ty == "application" && security_groups.is_empty() {
            if let Some(sg) = self
                .ec2()
                .and_then(|e| e.vpc_info(ctx, &account_of(ctx), Some(&placement.vpc_id)))
                .and_then(|v| v.default_security_group)
            {
                security_groups.push(sg);
            }
        }

        let account = account_of(ctx);
        let id = names::hex_id(16);
        let arn = names::arn(ctx, &account, &format!("loadbalancer/{}/{}/{id}", names::type_prefix(&ty), input.name));
        self.authorize_create(ctx, "CreateLoadBalancer", &arn, &tags)?;

        let result = self.with_region(ctx, |r| {
            if let Some(existing) = r.load_balancers.values().find(|l| l.name() == input.name) {
                let same = existing.ty() == ty
                    && existing.lb.scheme.as_deref().unwrap_or("internet-facing") == scheme
                    && existing.lb.availability_zones.iter().flatten().map(|z| z.subnet_id.clone()).collect::<Vec<_>>()
                        == placement.zones.iter().map(|z| z.subnet_id.clone()).collect::<Vec<_>>();
                if same {
                    return Ok(existing.lb.clone());
                }
                return Err(errors::duplicate_load_balancer_name(format!(
                    "A load balancer with the same name '{}' exists, but with different settings",
                    input.name
                )));
            }
            let count = r.load_balancers.values().filter(|l| l.ty() == ty).count();
            let limit = catalog::limit(match ty.as_str() {
                "network" => "network-load-balancers",
                "gateway" => "gateway-load-balancers",
                _ => "application-load-balancers",
            });
            if count >= limit {
                return Err(errors::too_many_load_balancers(
                    "You have reached the maximum number of load balancers for your account",
                ));
            }
            let lb = t::LoadBalancer {
                load_balancer_arn: Some(arn.clone()),
                dns_name: (ty != "gateway").then(|| names::dns_name(ctx, &ty, &input.name, &scheme)),
                canonical_hosted_zone_id: (ty != "gateway")
                    .then(|| names::canonical_hosted_zone(&ctx.region, &ty).into()),
                created_time: Some(ctx.received_at),
                load_balancer_name: Some(input.name.clone()),
                scheme: (ty != "gateway").then(|| scheme.clone()),
                vpc_id: Some(placement.vpc_id.clone()),
                state: Some(t::LoadBalancerState { code: Some("active".into()), reason: None }),
                r#type: Some(ty.clone()),
                availability_zones: Some(placement.zones.clone()),
                security_groups: (ty != "gateway" && (ty == "application" || !security_groups.is_empty()))
                    .then(|| security_groups.clone()),
                ip_address_type: Some(ip_type.clone()),
                customer_owned_ipv4_pool: input.customer_owned_ipv4_pool.clone(),
                enforce_security_group_inbound_rules_on_private_link_traffic: (ty == "network"
                    && !security_groups.is_empty())
                .then(|| "on".into()),
                enable_prefix_for_ipv6_source_nat: (ty == "network")
                    .then(|| input.enable_prefix_for_ipv6_source_nat.clone().unwrap_or_else(|| "off".into())),
                ipam_pools: input.ipam_pools.clone(),
            };
            r.load_balancers.insert(
                arn.clone(),
                LoadBalancerRecord {
                    lb: lb.clone(),
                    attributes: catalog::load_balancer_attributes(&ty, &scheme, &ip_type),
                    ..Default::default()
                },
            );
            if !tags.is_empty() {
                r.tags.insert(arn.clone(), tags.clone());
            }
            // A new load balancer is provisioning until its first describe.
            let mut out = lb;
            out.state = Some(t::LoadBalancerState { code: Some("provisioning".into()), reason: None });
            Ok(out)
        })?;
        Ok(t::CreateLoadBalancerOutput { load_balancers: Some(vec![result]) })
    }

    pub(crate) fn describe_load_balancers_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLoadBalancersInput,
    ) -> Result<t::DescribeLoadBalancersOutput, ServiceError> {
        names::authorize(ctx, "DescribeLoadBalancers", "*", Default::default())?;
        let arns = input.load_balancer_arns.unwrap_or_default();
        let wanted_names = input.names.unwrap_or_default();
        if !arns.is_empty() && !wanted_names.is_empty() {
            return Err(validation("Load balancer names and load balancer ARNs cannot be specified at the same time"));
        }
        let all: Vec<t::LoadBalancer> = self.with_region(ctx, |r| {
            if !arns.is_empty() {
                arns.iter().map(|a| find_lb(r, a).map(|l| l.lb.clone())).collect::<Result<Vec<_>, _>>()
            } else if !wanted_names.is_empty() {
                let mut out = Vec::new();
                let mut missing = Vec::new();
                for n in &wanted_names {
                    match r.load_balancers.values().find(|l| l.name() == n) {
                        Some(l) => out.push(l.lb.clone()),
                        None => missing.push(format!("'{n}'")),
                    }
                }
                if !missing.is_empty() {
                    return Err(errors::load_balancer_not_found(format!(
                        "Load balancers '[{}]' not found",
                        missing.join(", ").replace('\'', "")
                    )));
                }
                Ok(out)
            } else {
                let mut v: Vec<_> = r.load_balancers.values().map(|l| l.lb.clone()).collect();
                v.sort_by_key(|l| l.created_time);
                Ok(v)
            }
        })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(t::DescribeLoadBalancersOutput { load_balancers: Some(items), next_marker: next })
    }

    pub(crate) fn delete_load_balancer_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteLoadBalancerInput,
    ) -> Result<t::DeleteLoadBalancerOutput, ServiceError> {
        let arn = input.load_balancer_arn;
        self.authorize_on(ctx, "DeleteLoadBalancer", &arn)?;
        let removed_listeners = self.with_region(ctx, |r| {
            let Some(lb) = r.load_balancers.get(&arn) else { return Ok(Vec::new()) };
            if lb.attributes.get("deletion_protection.enabled").map(String::as_str) == Some("true") {
                return Err(errors::operation_not_permitted(format!(
                    "Load balancer '{arn}' cannot be deleted because deletion protection is enabled"
                )));
            }
            r.load_balancers.remove(&arn);
            r.tags.remove(&arn);
            let listeners: Vec<_> = r.listeners.values().filter(|l| l.lb_arn() == arn).cloned().collect();
            for l in &listeners {
                r.listeners.remove(l.arn());
                r.tags.remove(l.arn());
                let rules: Vec<String> =
                    r.rules.values().filter(|x| x.listener_arn == l.arn()).map(|x| x.arn().to_string()).collect();
                for rule in rules {
                    r.rules.remove(&rule);
                    r.tags.remove(&rule);
                }
            }
            Ok(listeners)
        })?;
        for l in removed_listeners {
            self.release_certificates(
                l.arn(),
                l.listener
                    .certificates
                    .iter()
                    .flatten()
                    .filter_map(|c| c.certificate_arn.clone())
                    .chain(l.extra_certificates.iter().cloned()),
            );
        }
        self.reconcile();
        Ok(t::DeleteLoadBalancerOutput {})
    }

    pub(crate) fn set_subnets_op(
        &self,
        ctx: &RequestContext,
        input: t::SetSubnetsInput,
    ) -> Result<t::SetSubnetsOutput, ServiceError> {
        self.authorize_on(ctx, "SetSubnets", &input.load_balancer_arn)?;
        let (ty, vpc, current) = self.with_region(ctx, |r| {
            find_lb(r, &input.load_balancer_arn).map(|l| (l.ty().to_string(), l.lb.vpc_id.clone(), l.zones()))
        })?;
        let placement = self.place(ctx, &ty, input.subnets.as_ref(), input.subnet_mappings.as_ref(), vpc.as_deref())?;
        if ty == "network" {
            // Network Load Balancers can add subnets but not remove them.
            let new: BTreeSet<_> = placement.zones.iter().filter_map(|z| z.zone_name.clone()).collect();
            if current.iter().any(|z| !new.contains(z)) {
                return Err(validation("Subnets cannot be removed from a Network Load Balancer"));
            }
        }
        self.with_region(ctx, |r| {
            let lb = r.load_balancers.get_mut(&input.load_balancer_arn).ok_or_else(lb_not_found)?;
            lb.lb.availability_zones = Some(placement.zones.clone());
            if let Some(t) = &input.ip_address_type {
                lb.lb.ip_address_type = Some(t.clone());
            }
            if let Some(p) = &input.enable_prefix_for_ipv6_source_nat {
                lb.lb.enable_prefix_for_ipv6_source_nat = Some(p.clone());
            }
            Ok(t::SetSubnetsOutput {
                availability_zones: Some(placement.zones.clone()),
                ip_address_type: lb.lb.ip_address_type.clone(),
                enable_prefix_for_ipv6_source_nat: lb.lb.enable_prefix_for_ipv6_source_nat.clone(),
            })
        })
    }

    pub(crate) fn set_security_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::SetSecurityGroupsInput,
    ) -> Result<t::SetSecurityGroupsOutput, ServiceError> {
        self.authorize_on(ctx, "SetSecurityGroups", &input.load_balancer_arn)?;
        let (ty, vpc, had) = self.with_region(ctx, |r| {
            find_lb(r, &input.load_balancer_arn)
                .map(|l| (l.ty().to_string(), l.lb.vpc_id.clone().unwrap_or_default(), l.lb.security_groups.clone()))
        })?;
        match ty.as_str() {
            "gateway" => {
                return Err(validation("Security groups are not supported for load balancers of type 'gateway'"))
            }
            "network" if had.as_ref().is_none_or(Vec::is_empty) && !input.security_groups.is_empty() => {
                return Err(validation(
                    "You cannot set security groups for a Network Load Balancer that was created without any",
                ))
            }
            "network" if had.as_ref().is_some_and(|h| !h.is_empty()) && input.security_groups.is_empty() => {
                return Err(validation("You cannot remove all security groups from a Network Load Balancer"));
            }
            _ => {}
        }
        self.check_security_groups(ctx, &vpc, &input.security_groups)?;
        self.with_region(ctx, |r| {
            let lb = r.load_balancers.get_mut(&input.load_balancer_arn).ok_or_else(lb_not_found)?;
            lb.lb.security_groups = Some(input.security_groups.clone());
            if let Some(e) = &input.enforce_security_group_inbound_rules_on_private_link_traffic {
                if ty != "network" {
                    return Err(validation(
                        "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic is only supported for Network Load Balancers",
                    ));
                }
                lb.lb.enforce_security_group_inbound_rules_on_private_link_traffic = Some(e.clone());
            }
            Ok(t::SetSecurityGroupsOutput {
                security_group_ids: Some(input.security_groups.clone()),
                enforce_security_group_inbound_rules_on_private_link_traffic: lb
                    .lb
                    .enforce_security_group_inbound_rules_on_private_link_traffic
                    .clone(),
            })
        })
    }

    pub(crate) fn set_ip_address_type_op(
        &self,
        ctx: &RequestContext,
        input: t::SetIpAddressTypeInput,
    ) -> Result<t::SetIpAddressTypeOutput, ServiceError> {
        self.authorize_on(ctx, "SetIpAddressType", &input.load_balancer_arn)?;
        self.with_region(ctx, |r| {
            let lb = r.load_balancers.get_mut(&input.load_balancer_arn).ok_or_else(lb_not_found)?;
            let ok = match input.ip_address_type.as_str() {
                "ipv4" | "dualstack" => true,
                "dualstack-without-public-ipv4" => {
                    lb.ty() == "application" && lb.lb.scheme.as_deref() == Some("internet-facing")
                }
                _ => false,
            };
            if !ok {
                return Err(validation(format!(
                    "IP address type '{}' is not valid for this load balancer",
                    input.ip_address_type
                )));
            }
            lb.lb.ip_address_type = Some(input.ip_address_type.clone());
            Ok(t::SetIpAddressTypeOutput { ip_address_type: Some(input.ip_address_type.clone()) })
        })
    }

    pub(crate) fn describe_load_balancer_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLoadBalancerAttributesInput,
    ) -> Result<t::DescribeLoadBalancerAttributesOutput, ServiceError> {
        names::authorize(ctx, "DescribeLoadBalancerAttributes", "*", Default::default())?;
        self.with_region(ctx, |r| {
            let lb = find_lb(r, &input.load_balancer_arn)?;
            Ok(t::DescribeLoadBalancerAttributesOutput { attributes: Some(lb_attributes(lb)) })
        })
    }

    pub(crate) fn modify_load_balancer_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyLoadBalancerAttributesInput,
    ) -> Result<t::ModifyLoadBalancerAttributesOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyLoadBalancerAttributes", &input.load_balancer_arn)?;
        let out = self.with_region(ctx, |r| {
            let lb = r.load_balancers.get_mut(&input.load_balancer_arn).ok_or_else(lb_not_found)?;
            let mut next = lb.attributes.clone();
            for a in &input.attributes {
                let key = a.key.clone().unwrap_or_default();
                let value = a.value.clone().unwrap_or_default();
                if !lb.attributes.contains_key(&key) && !optional_lb_attribute(lb.ty(), &key) {
                    return Err(validation(format!("Load balancer attribute key '{key}' is not recognized")));
                }
                if lb.ty() == "application" && key == "load_balancing.cross_zone.enabled" && value != "true" {
                    return Err(errors::invalid_configuration_request(
                        "Cross-zone load balancing cannot be disabled for Application Load Balancers",
                    ));
                }
                catalog::check_lb_attribute(&key, &value).map_err(validation)?;
                next.insert(key, value);
            }
            for kind in ["access_logs", "connection_logs", "health_check_logs"] {
                if next.get(&format!("{kind}.s3.enabled")).map(String::as_str) == Some("true")
                    && next.get(&format!("{kind}.s3.bucket")).is_none_or(String::is_empty)
                {
                    return Err(errors::invalid_configuration_request(format!(
                        "The value of '{kind}.s3.bucket' cannot be empty when '{kind}.s3.enabled' is true"
                    )));
                }
                // ELB writes a test file when logging is turned on or
                // pointed somewhere new.
                let changed = ["enabled", "bucket", "prefix"].iter().any(|f| {
                    let k = format!("{kind}.s3.{f}");
                    next.get(&k) != lb.attributes.get(&k)
                });
                if changed && next.get(&format!("{kind}.s3.enabled")).map(String::as_str) == Some("true") {
                    let arn = lb.arn().to_string();
                    let mut parts = arn.split(':');
                    let (region, account) = (parts.nth(3).unwrap_or_default(), parts.next().unwrap_or_default());
                    let bucket = next.get(&format!("{kind}.s3.bucket")).cloned().unwrap_or_default();
                    let prefix = next.get(&format!("{kind}.s3.prefix")).cloned().unwrap_or_default();
                    self.check_log_bucket(&arn, account, region, &bucket, &prefix)
                        .map_err(errors::invalid_configuration_request)?;
                }
            }
            lb.attributes = next;
            Ok(lb_attributes(lb))
        })?;
        Ok(t::ModifyLoadBalancerAttributesOutput { attributes: Some(out) })
    }

    pub(crate) fn describe_capacity_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeCapacityReservationInput,
    ) -> Result<t::DescribeCapacityReservationOutput, ServiceError> {
        names::authorize(ctx, "DescribeCapacityReservation", "*", Default::default())?;
        self.with_region(ctx, |r| {
            let lb = find_lb(r, &input.load_balancer_arn)?;
            Ok(capacity_output(lb, ctx))
        })
    }

    pub(crate) fn modify_capacity_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyCapacityReservationInput,
    ) -> Result<t::ModifyCapacityReservationOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyCapacityReservation", &input.load_balancer_arn)?;
        let reset = input.reset_capacity_reservation == Some(true);
        let units = input.minimum_load_balancer_capacity.as_ref().and_then(|m| m.capacity_units);
        if reset == units.is_some() {
            return Err(validation("Specify either MinimumLoadBalancerCapacity or ResetCapacityReservation"));
        }
        self.with_region(ctx, |r| {
            let lb = r.load_balancers.get_mut(&input.load_balancer_arn).ok_or_else(lb_not_found)?;
            if lb.ty() == "gateway" {
                return Err(errors::operation_not_permitted(
                    "Capacity reservations are not supported for Gateway Load Balancers",
                ));
            }
            let (lo, per_zone) = if lb.ty() == "network" { (2750, 2750) } else { (100, 100) };
            if let Some(u) = units {
                let zones = lb.zones().len().max(1) as i32;
                if u < lo || u % if lb.ty() == "network" { per_zone } else { 1 } != 0 {
                    return Err(validation(format!(
                        "The minimum capacity units for a load balancer of type '{}' is {lo}",
                        lb.ty()
                    )));
                }
                if u > 1500 * zones * if lb.ty() == "network" { 30 } else { 1 } {
                    return Err(errors::capacity_units_limit_exceeded("The requested capacity units exceed the limit"));
                }
            }
            let decreasing = match (lb.capacity_units, units) {
                (Some(old), Some(new)) => new < old,
                (Some(_), None) => true,
                _ => false,
            };
            if decreasing {
                let day_ago = ctx.received_at - chrono::Duration::hours(24);
                lb.capacity_decreases.retain(|t| *t > day_ago);
                if lb.capacity_decreases.len() >= 4 {
                    return Err(errors::capacity_decrease_requests_limit_exceeded(
                        "You have reached the limit of capacity decrease requests in 24 hours",
                    ));
                }
                lb.capacity_decreases.push(ctx.received_at);
            }
            lb.capacity_units = units;
            lb.capacity_modified_at = Some(ctx.received_at);
            let out = capacity_output(lb, ctx);
            Ok(t::ModifyCapacityReservationOutput {
                last_modified_time: out.last_modified_time,
                decrease_requests_remaining: out.decrease_requests_remaining,
                minimum_load_balancer_capacity: out.minimum_load_balancer_capacity,
                capacity_reservation_state: out.capacity_reservation_state,
            })
        })
    }

    pub(crate) fn modify_ip_pools_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyIpPoolsInput,
    ) -> Result<t::ModifyIpPoolsOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyIpPools", &input.load_balancer_arn)?;
        self.with_region(ctx, |r| {
            let lb = r.load_balancers.get_mut(&input.load_balancer_arn).ok_or_else(lb_not_found)?;
            if lb.ty() != "application" {
                return Err(errors::operation_not_permitted(
                    "IPAM pools are only supported for Application Load Balancers",
                ));
            }
            let mut pools = lb.lb.ipam_pools.clone().unwrap_or_default();
            if let Some(p) = input.ipam_pools.as_ref().and_then(|p| p.ipv4_ipam_pool_id.clone()) {
                if !p.starts_with("ipam-pool-") {
                    return Err(validation(format!("The IPAM pool ID '{p}' is not valid")));
                }
                pools.ipv4_ipam_pool_id = Some(p);
            }
            for removed in input.remove_ipam_pools.iter().flatten() {
                if removed == "ipv4" {
                    pools.ipv4_ipam_pool_id = None;
                }
            }
            lb.lb.ipam_pools = pools.ipv4_ipam_pool_id.is_some().then(|| pools.clone());
            Ok(t::ModifyIpPoolsOutput { ipam_pools: lb.lb.ipam_pools.clone() })
        })
    }
}

/// Attributes some load balancers accept without listing them by default.
fn optional_lb_attribute(ty: &str, key: &str) -> bool {
    matches!(
        (ty, key),
        ("application" | "network", "ipv6.deny_all_igw_traffic") | ("application", "routing.http.x_amzn_mtls.enabled")
    )
}

pub(crate) fn lb_attributes(lb: &LoadBalancerRecord) -> Vec<t::LoadBalancerAttribute> {
    lb.attributes
        .iter()
        .map(|(k, v)| t::LoadBalancerAttribute { key: Some(k.clone()), value: Some(v.clone()) })
        .collect()
}

fn capacity_output(lb: &LoadBalancerRecord, ctx: &RequestContext) -> t::DescribeCapacityReservationOutput {
    let day_ago = ctx.received_at - chrono::Duration::hours(24);
    let used = lb.capacity_decreases.iter().filter(|t| **t > day_ago).count() as i32;
    let zones = lb.zones();
    let per_zone = lb.capacity_units.map(|u| u as f64 / zones.len().max(1) as f64);
    t::DescribeCapacityReservationOutput {
        last_modified_time: lb.capacity_modified_at,
        decrease_requests_remaining: Some((4 - used).max(0)),
        minimum_load_balancer_capacity: lb
            .capacity_units
            .map(|u| t::MinimumLoadBalancerCapacity { capacity_units: Some(u) }),
        capacity_reservation_state: Some(
            zones
                .into_iter()
                .filter(|_| lb.capacity_units.is_some())
                .map(|z| t::ZonalCapacityReservationState {
                    state: Some(t::CapacityReservationStatus { code: Some("provisioned".into()), reason: None }),
                    availability_zone: Some(z),
                    effective_capacity_units: per_zone,
                })
                .collect(),
        ),
    }
}
