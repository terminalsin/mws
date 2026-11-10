//! VPCs, subnets, internet and NAT gateways, route tables, network ACLs and
//! DHCP options, and the default VPC every account has in every Region.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::catalog;
use crate::generated::types as t;
use crate::idempotency;
use crate::state::{RegionState, VpcRecord};
use crate::util::{
    arn, b, err, invalid_parameter, ip_str, missing_parameter, new_id, paginate, request_tag_context,
    resource_tag_context, s, some_tags, tags_for, Cidr, Filters, Kind,
};
use crate::{account_of, Ec2};

pub const DEFAULT_VPC_CIDR: &str = "172.31.0.0/16";

/// Deleted NAT gateways stay visible for an hour, as in EC2. `pending`
/// and `deleting` ones finish their transition first.
pub fn expire_deleted(r: &mut RegionState, now: DateTime<Utc>) {
    let due: Vec<(String, DateTime<Utc>)> =
        r.nat_transitions.iter().filter(|(_, at)| **at <= now).map(|(id, at)| (id.clone(), *at)).collect();
    for (id, at) in due {
        r.nat_transitions.remove(&id);
        let Some(n) = r.nat_gateways.get_mut(&id) else { continue };
        match n.state.as_deref() {
            Some("pending") => n.state = Some("available".into()),
            Some("deleting") => {
                n.state = Some("deleted".into());
                n.delete_time = Some(at);
            }
            _ => {}
        }
    }
    r.nat_gateways.retain(|_, n| {
        n.state.as_deref() != Some("deleted") || n.delete_time.is_none_or(|t| now - t < chrono::Duration::hours(1))
    });
}

/// Create the default VPC and its companions, as a new account has them.
pub fn init_region(r: &mut RegionState, account: &str, region: &str, partition: &str, now: DateTime<Utc>) {
    let dopt = default_dhcp_options(r, account, region);
    let _ = partition;
    let vpc_id = new_vpc(r, account, DEFAULT_VPC_CIDR, true, Vec::new(), Some(dopt), "default");
    // A /20 default subnet per zone, public by default.
    for (i, (zone, zone_id)) in catalog::zones(region).into_iter().enumerate() {
        let cidr = format!("172.31.{}.0/20", i * 16);
        let id = new_subnet(r, account, region, partition, &vpc_id, &cidr, &zone, &zone_id, Vec::new());
        if let Some(s) = r.subnets.get_mut(&id) {
            s.default_for_az = Some(true);
            s.map_public_ip_on_launch = Some(true);
        }
    }
    let igw_id = new_id("igw");
    r.internet_gateways.insert(
        igw_id.clone(),
        t::InternetGateway {
            internet_gateway_id: Some(igw_id.clone()),
            owner_id: Some(account.into()),
            attachments: Some(vec![t::InternetGatewayAttachment {
                state: Some("available".into()),
                vpc_id: Some(vpc_id.clone()),
            }]),
            tags: None,
        },
    );
    if let Some(rtb) = main_route_table_mut(r, &vpc_id) {
        rtb.routes.get_or_insert_with(Vec::new).push(t::Route {
            destination_cidr_block: Some("0.0.0.0/0".into()),
            gateway_id: Some(igw_id),
            origin: Some("CreateRoute".into()),
            state: Some("active".into()),
            ..Default::default()
        });
    }
    let _ = now;
}

fn default_dhcp_options(r: &mut RegionState, account: &str, region: &str) -> String {
    let id = new_id("dopt");
    let domain = if region == "us-east-1" { "ec2.internal".to_string() } else { format!("{region}.compute.internal") };
    let conf = |k: &str, v: &str| t::DhcpConfiguration {
        key: Some(k.into()),
        values: Some(vec![t::AttributeValue { value: Some(v.into()) }]),
    };
    r.dhcp_options.insert(
        id.clone(),
        t::DhcpOptions {
            dhcp_options_id: Some(id.clone()),
            owner_id: Some(account.into()),
            dhcp_configurations: Some(vec![
                conf("domain-name", &domain),
                conf("domain-name-servers", "AmazonProvidedDNS"),
            ]),
            tags: None,
        },
    );
    id
}

/// A VPC with its main route table, default network ACL and default
/// security group.
fn new_vpc(
    r: &mut RegionState,
    account: &str,
    cidr: &str,
    is_default: bool,
    tags: Vec<t::Tag>,
    dhcp: Option<String>,
    tenancy: &str,
) -> String {
    let vpc_id = new_id("vpc");
    let dhcp = dhcp.or_else(|| r.dhcp_options.keys().next().cloned()).unwrap_or_else(|| "default".into());
    r.vpcs.insert(
        vpc_id.clone(),
        VpcRecord {
            vpc: t::Vpc {
                vpc_id: Some(vpc_id.clone()),
                owner_id: Some(account.into()),
                instance_tenancy: Some(tenancy.into()),
                cidr_block: Some(cidr.into()),
                cidr_block_association_set: Some(vec![t::VpcCidrBlockAssociation {
                    association_id: Some(new_id("vpc-cidr-assoc")),
                    cidr_block: Some(cidr.into()),
                    cidr_block_state: Some(t::VpcCidrBlockState {
                        state: Some("associated".into()),
                        status_message: None,
                    }),
                }]),
                is_default: Some(is_default),
                state: Some("available".into()),
                dhcp_options_id: Some(dhcp),
                block_public_access_states: Some(t::BlockPublicAccessStates {
                    internet_gateway_block_mode: Some("off".into()),
                }),
                tags: some_tags(tags),
                ..Default::default()
            },
            enable_dns_support: true,
            enable_dns_hostnames: is_default,
            enable_network_address_usage_metrics: false,
        },
    );
    let rtb_id = new_id("rtb");
    r.route_tables.insert(
        rtb_id.clone(),
        t::RouteTable {
            route_table_id: Some(rtb_id.clone()),
            vpc_id: Some(vpc_id.clone()),
            owner_id: Some(account.into()),
            routes: Some(vec![local_route(cidr)]),
            associations: Some(vec![t::RouteTableAssociation {
                main: Some(true),
                route_table_association_id: Some(new_id("rtbassoc")),
                route_table_id: Some(rtb_id),
                association_state: Some(assoc_state("associated")),
                ..Default::default()
            }]),
            propagating_vgws: Some(Vec::new()),
            tags: None,
        },
    );
    let acl_id = new_id("acl");
    r.network_acls.insert(
        acl_id.clone(),
        t::NetworkAcl {
            network_acl_id: Some(acl_id),
            vpc_id: Some(vpc_id.clone()),
            owner_id: Some(account.into()),
            is_default: Some(true),
            associations: Some(Vec::new()),
            entries: Some(vec![
                acl_entry(100, true, "-1", "allow", "0.0.0.0/0"),
                acl_entry(32767, true, "-1", "deny", "0.0.0.0/0"),
                acl_entry(100, false, "-1", "allow", "0.0.0.0/0"),
                acl_entry(32767, false, "-1", "deny", "0.0.0.0/0"),
            ]),
            tags: None,
        },
    );
    super::sg::new_default_group(r, account, &vpc_id);
    vpc_id
}

fn local_route(cidr: &str) -> t::Route {
    t::Route {
        destination_cidr_block: Some(cidr.into()),
        gateway_id: Some("local".into()),
        origin: Some("CreateRouteTable".into()),
        state: Some("active".into()),
        ..Default::default()
    }
}

fn assoc_state(s: &str) -> t::RouteTableAssociationState {
    t::RouteTableAssociationState { state: Some(s.into()), status_message: None }
}

fn acl_entry(n: i32, egress: bool, protocol: &str, action: &str, cidr: &str) -> t::NetworkAclEntry {
    t::NetworkAclEntry {
        rule_number: Some(n),
        egress: Some(egress),
        protocol: Some(protocol.into()),
        rule_action: Some(action.into()),
        cidr_block: Some(cidr.into()),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn new_subnet(
    r: &mut RegionState,
    account: &str,
    region: &str,
    partition: &str,
    vpc_id: &str,
    cidr: &str,
    zone: &str,
    zone_id: &str,
    tags: Vec<t::Tag>,
) -> String {
    let id = new_id("subnet");
    r.subnets.insert(
        id.clone(),
        t::Subnet {
            subnet_id: Some(id.clone()),
            subnet_arn: Some(format!("arn:{partition}:ec2:{region}:{account}:subnet/{id}")),
            vpc_id: Some(vpc_id.into()),
            owner_id: Some(account.into()),
            cidr_block: Some(cidr.into()),
            availability_zone: Some(zone.into()),
            availability_zone_id: Some(zone_id.into()),
            state: Some("available".into()),
            default_for_az: Some(false),
            map_public_ip_on_launch: Some(false),
            map_customer_owned_ip_on_launch: Some(false),
            assign_ipv6_address_on_creation: Some(false),
            ipv6_cidr_block_association_set: Some(Vec::new()),
            enable_dns64: Some(false),
            ipv6_native: Some(false),
            private_dns_name_options_on_launch: Some(t::PrivateDnsNameOptionsOnLaunch {
                hostname_type: Some("ip-name".into()),
                enable_resource_name_dns_a_record: Some(false),
                enable_resource_name_dns_aaaa_record: Some(false),
            }),
            block_public_access_states: Some(t::BlockPublicAccessStates {
                internet_gateway_block_mode: Some("off".into()),
            }),
            tags: some_tags(tags),
            ..Default::default()
        },
    );
    // New subnets use the VPC's default network ACL.
    if let Some(acl) =
        r.network_acls.values_mut().find(|a| a.vpc_id.as_deref() == Some(vpc_id) && a.is_default == Some(true))
    {
        let acl_id = acl.network_acl_id.clone();
        acl.associations.get_or_insert_with(Vec::new).push(t::NetworkAclAssociation {
            network_acl_association_id: Some(new_id("aclassoc")),
            network_acl_id: acl_id,
            subnet_id: Some(id.clone()),
        });
    }
    id
}

pub fn main_route_table_mut<'a>(r: &'a mut RegionState, vpc_id: &str) -> Option<&'a mut t::RouteTable> {
    r.route_tables.values_mut().find(|rt| {
        rt.vpc_id.as_deref() == Some(vpc_id) && rt.associations.iter().flatten().any(|a| a.main == Some(true))
    })
}

/// Addresses in use in a subnet (network interfaces and NAT gateways).
pub fn used_ips(r: &RegionState, subnet_id: &str) -> Vec<u32> {
    let mut used: Vec<u32> = r
        .network_interfaces
        .values()
        .filter(|n| n.subnet_id.as_deref() == Some(subnet_id))
        .flat_map(|n| n.private_ip_addresses.iter().flatten().filter_map(|p| p.private_ip_address.clone()))
        .filter_map(|ip| crate::util::parse_ip(&ip))
        .collect();
    used.sort_unstable();
    used
}

/// The next free address in a subnet. AWS reserves the first four and
/// the last address of every subnet.
pub fn allocate_ip(r: &RegionState, subnet_id: &str) -> Option<String> {
    let cidr = Cidr::parse(r.subnets.get(subnet_id)?.cidr_block.as_deref()?)?;
    let used = used_ips(r, subnet_id);
    (cidr.first() + 4..cidr.last()).find(|ip| used.binary_search(ip).is_err()).map(ip_str)
}

/// Check that `ip` may be used in `subnet_id`.
pub fn check_ip(r: &RegionState, subnet_id: &str, ip: &str) -> Result<(), ServiceError> {
    let subnet = r.subnets.get(subnet_id).ok_or_else(|| Kind::Subnet.not_found(subnet_id))?;
    let cidr =
        Cidr::parse(subnet.cidr_block.as_deref().unwrap_or_default()).ok_or_else(|| invalid_parameter("bad subnet"))?;
    let addr = crate::util::parse_ip(ip)
        .ok_or_else(|| invalid_parameter(format!("Invalid value '{ip}' for IP address. The IP address is invalid.")))?;
    if !cidr.contains(addr) || addr < cidr.first() + 4 || addr == cidr.last() {
        return Err(err(
            "InvalidParameterValue",
            format!("Address {ip} does not fall within the subnet's address range"),
        ));
    }
    if used_ips(r, subnet_id).contains(&addr) {
        return Err(err("InvalidIPAddress.InUse", format!("Address {ip} is in use.")));
    }
    Ok(())
}

pub fn render_subnet(r: &RegionState, s: &t::Subnet) -> t::Subnet {
    let mut out = s.clone();
    if let Some(cidr) = s.cidr_block.as_deref().and_then(Cidr::parse) {
        let used = used_ips(r, s.subnet_id.as_deref().unwrap_or_default()).len() as i64;
        out.available_ip_address_count = Some((cidr.size() as i64 - 5 - used).max(0) as i32);
    }
    out
}

fn vpc_cidrs(v: &t::Vpc) -> Vec<Cidr> {
    v.cidr_block_association_set
        .iter()
        .flatten()
        .filter(|a| a.cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) == Some("associated"))
        .filter_map(|a| a.cidr_block.as_deref().and_then(Cidr::parse))
        .collect()
}

fn parse_vpc_cidr(cidr: &str) -> Result<Cidr, ServiceError> {
    match Cidr::parse(cidr) {
        Some(c) if (16..=28).contains(&c.prefix) && c.is_network() => Ok(c),
        Some(c) if !c.is_network() && (16..=28).contains(&c.prefix) => Err(err(
            "InvalidParameterValue",
            format!("Value ({cidr}) for parameter cidrBlock is invalid. This is not a valid CIDR block."),
        )),
        _ => Err(err("InvalidVpc.Range", format!("The CIDR '{cidr}' is invalid."))),
    }
}

impl Ec2 {
    // ---- VPCs -------------------------------------------------------------------------

    pub(crate) fn create_vpc_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateVpcRequest,
    ) -> Result<t::CreateVpcResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "vpc", &["vpc"])?;
        let mut cond = request_tag_context(&tags);
        cond.insert("ec2:Tenancy".into(), vec![input.instance_tenancy.clone().unwrap_or_else(|| "default".into())]);
        self.authorize_known(ctx, "CreateVpc", &[(arn(ctx, &account, "vpc/*"), cond)], input.dry_run)?;
        let cidr = input.cidr_block.clone().ok_or_else(|| missing_parameter("CidrBlock"))?;
        parse_vpc_cidr(&cidr)?;
        let tenancy = input.instance_tenancy.clone().unwrap_or_else(|| "default".into());
        let limit = self.quota(&account, &ctx.region, crate::quotas::VPCS, ctx.received_at);
        self.with_region(ctx, |r| {
            if r.vpcs.len() as f64 >= limit {
                return Err(err("VpcLimitExceeded", "The maximum number of VPCs has been reached."));
            }
            let id = new_vpc(r, &account, &cidr, false, tags, None, &tenancy);
            if input.amazon_provided_ipv6_cidr_block == Some(true) {
                crate::ops::addressing::add_vpc_ipv6(
                    r,
                    &id,
                    &ctx.region,
                    input.ipv6_cidr_block_network_border_group.clone(),
                )?;
            }
            let mut vpc = r.vpcs[&id].vpc.clone();
            vpc.state = Some("pending".into());
            Ok(t::CreateVpcResult { vpc: Some(vpc) })
        })
    }

    pub(crate) fn create_default_vpc_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDefaultVpcRequest,
    ) -> Result<t::CreateDefaultVpcResult, ServiceError> {
        let account = account_of(ctx);
        self.authorize_known(
            ctx,
            "CreateDefaultVpc",
            &[(arn(ctx, &account, "vpc/*"), ConditionContext::new())],
            input.dry_run,
        )?;
        let region = ctx.region.clone();
        let partition = ctx.partition.clone();
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            if let Some(v) = r.vpcs.values().find(|v| v.vpc.is_default == Some(true)) {
                return Err(err(
                    "DefaultVpcAlreadyExists",
                    format!(
                        "A Default VPC already exists for this account in this region. ({})",
                        v.vpc.vpc_id.clone().unwrap_or_default()
                    ),
                ));
            }
            let before: Vec<String> = r.vpcs.keys().cloned().collect();
            init_region(r, &account, &region, &partition, now);
            let vpc = r.vpcs.values().find(|v| !before.contains(v.vpc.vpc_id.as_ref().unwrap())).map(|v| v.vpc.clone());
            Ok(t::CreateDefaultVpcResult { vpc })
        })
    }

    pub(crate) fn delete_vpc_op(&self, ctx: &RequestContext, input: t::DeleteVpcRequest) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::Vpc.check(&input.vpc_id)?;
        let tags = self.with_region(ctx, |r| r.vpcs.get(&input.vpc_id).map(|v| v.vpc.tags.clone()));
        let tags = tags.ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
        self.authorize_known(
            ctx,
            "DeleteVpc",
            &[(arn(ctx, &account, &format!("vpc/{}", input.vpc_id)), resource_tag_context(tags.as_ref()))],
            input.dry_run,
        )?;
        let vpc_id = input.vpc_id.clone();
        self.with_region(ctx, |r| {
            let in_vpc = |v: &Option<String>| v.as_deref() == Some(vpc_id.as_str());
            let dependency = r.subnets.values().any(|s| in_vpc(&s.vpc_id))
                || r.internet_gateways.values().any(|g| g.attachments.iter().flatten().any(|a| in_vpc(&a.vpc_id)))
                || r.security_groups.values().any(|g| in_vpc(&g.vpc_id) && g.group_name.as_deref() != Some("default"))
                || r.route_tables
                    .values()
                    .any(|rt| in_vpc(&rt.vpc_id) && !rt.associations.iter().flatten().any(|a| a.main == Some(true)))
                || r.network_acls.values().any(|a| in_vpc(&a.vpc_id) && a.is_default != Some(true))
                || r.vpc_endpoints.values().any(|e| in_vpc(&e.vpc_id))
                || r.nat_gateways.values().any(|n| in_vpc(&n.vpc_id) && n.state.as_deref() != Some("deleted"));
            if dependency {
                return Err(err(
                    "DependencyViolation",
                    format!("The vpc '{vpc_id}' has dependencies and cannot be deleted."),
                ));
            }
            r.vpcs.remove(&vpc_id);
            r.route_tables.retain(|_, rt| !in_vpc(&rt.vpc_id));
            r.network_acls.retain(|_, a| !in_vpc(&a.vpc_id));
            let groups: Vec<String> =
                r.security_groups.values().filter(|g| in_vpc(&g.vpc_id)).filter_map(|g| g.group_id.clone()).collect();
            r.security_groups.retain(|_, g| !in_vpc(&g.vpc_id));
            r.sg_rules.retain(|_, rule| !groups.contains(&rule.group_id));
            Ok(())
        })?;
        let backend = self.backend();
        tokio::spawn(async move {
            if let Err(e) = backend.delete_network(&vpc_id).await {
                tracing::warn!(%vpc_id, "removing the VPC's network: {e}");
            }
        });
        Ok(())
    }

    pub(crate) fn describe_vpcs_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcsRequest,
    ) -> Result<t::DescribeVpcsResult, ServiceError> {
        self.authorize_known(ctx, "DescribeVpcs", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.vpc_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Vpc.check_all(&ids, |id| r.vpcs.contains_key(id))?;
            let mut out = Vec::new();
            for rec in r.vpcs.values() {
                let v = &rec.vpc;
                if !ids.is_empty() && !ids.contains(v.vpc_id.as_ref().unwrap()) {
                    continue;
                }
                let assoc = v.cidr_block_association_set.clone().unwrap_or_default();
                let ok = filters.matches(v.tags.as_ref(), |name| {
                    Some(match name {
                        "cidr" | "cidr-block" => s(&v.cidr_block),
                        "cidr-block-association.cidr-block" => {
                            assoc.iter().filter_map(|a| a.cidr_block.clone()).collect()
                        }
                        "cidr-block-association.association-id" => {
                            assoc.iter().filter_map(|a| a.association_id.clone()).collect()
                        }
                        "cidr-block-association.state" => assoc
                            .iter()
                            .filter_map(|a| a.cidr_block_state.as_ref().and_then(|s| s.state.clone()))
                            .collect(),
                        "dhcp-options-id" => s(&v.dhcp_options_id),
                        "is-default" | "isDefault" => b(v.is_default),
                        "owner-id" => s(&v.owner_id),
                        "state" => s(&v.state),
                        "vpc-id" => s(&v.vpc_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(v.clone());
                }
            }
            let (vpcs, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeVpcsResult { vpcs: Some(vpcs), next_token })
        })
    }

    pub(crate) fn modify_vpc_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVpcAttributeRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::Vpc.check(&input.vpc_id)?;
        let tags = self.with_region(ctx, |r| r.vpcs.get(&input.vpc_id).map(|v| v.vpc.tags.clone()));
        let tags = tags.ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
        self.authorize_known(
            ctx,
            "ModifyVpcAttribute",
            &[(arn(ctx, &account, &format!("vpc/{}", input.vpc_id)), resource_tag_context(tags.as_ref()))],
            None,
        )?;
        let set = [
            input.enable_dns_hostnames.as_ref().and_then(|v| v.value),
            input.enable_dns_support.as_ref().and_then(|v| v.value),
            input.enable_network_address_usage_metrics.as_ref().and_then(|v| v.value),
        ];
        if set.iter().filter(|v| v.is_some()).count() != 1 {
            return Err(err("InvalidParameterCombination", "Only one attribute can be modified at a time."));
        }
        self.with_region(ctx, |r| {
            let rec = r.vpcs.get_mut(&input.vpc_id).ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
            if let Some(v) = set[0] {
                if v && !rec.enable_dns_support {
                    return Err(err(
                        "InvalidParameterCombination",
                        "Cannot enable DNS hostnames when DNS support is disabled.",
                    ));
                }
                rec.enable_dns_hostnames = v;
            }
            if let Some(v) = set[1] {
                rec.enable_dns_support = v;
            }
            if let Some(v) = set[2] {
                rec.enable_network_address_usage_metrics = v;
            }
            Ok(())
        })
    }

    pub(crate) fn describe_vpc_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcAttributeRequest,
    ) -> Result<t::DescribeVpcAttributeResult, ServiceError> {
        self.authorize_known(ctx, "DescribeVpcAttribute", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        Kind::Vpc.check(&input.vpc_id)?;
        self.with_region(ctx, |r| {
            let rec = r.vpcs.get(&input.vpc_id).ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
            let v = |b: bool| Some(t::AttributeBooleanValue { value: Some(b) });
            let mut out = t::DescribeVpcAttributeResult { vpc_id: Some(input.vpc_id.clone()), ..Default::default() };
            match input.attribute.as_str() {
                "enableDnsSupport" => out.enable_dns_support = v(rec.enable_dns_support),
                "enableDnsHostnames" => out.enable_dns_hostnames = v(rec.enable_dns_hostnames),
                "enableNetworkAddressUsageMetrics" => {
                    out.enable_network_address_usage_metrics = v(rec.enable_network_address_usage_metrics)
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

    pub(crate) fn associate_vpc_cidr_block_op(
        &self,
        ctx: &RequestContext,
        input: t::AssociateVpcCidrBlockRequest,
    ) -> Result<t::AssociateVpcCidrBlockResult, ServiceError> {
        let account = account_of(ctx);
        Kind::Vpc.check(&input.vpc_id)?;
        self.authorize_known(
            ctx,
            "AssociateVpcCidrBlock",
            &[(arn(ctx, &account, &format!("vpc/{}", input.vpc_id)), ConditionContext::new())],
            None,
        )?;
        if input.amazon_provided_ipv6_cidr_block == Some(true) {
            if input.cidr_block.is_some() {
                return Err(err(
                    "InvalidParameterCombination",
                    "The parameters CidrBlock and AmazonProvidedIpv6CidrBlock are mutually exclusive.",
                ));
            }
            return self.with_region(ctx, |r| {
                if !r.vpcs.contains_key(&input.vpc_id) {
                    return Err(Kind::Vpc.not_found(&input.vpc_id));
                }
                let mut assoc = crate::ops::addressing::add_vpc_ipv6(
                    r,
                    &input.vpc_id,
                    &ctx.region,
                    input.ipv6_cidr_block_network_border_group.clone(),
                )?;
                assoc.ipv6_cidr_block_state =
                    Some(t::VpcCidrBlockState { state: Some("associating".into()), status_message: None });
                Ok(t::AssociateVpcCidrBlockResult {
                    vpc_id: Some(input.vpc_id.clone()),
                    ipv6_cidr_block_association: Some(assoc),
                    ..Default::default()
                })
            });
        }
        let cidr = input.cidr_block.clone().ok_or_else(|| missing_parameter("CidrBlock"))?;
        let parsed = parse_vpc_cidr(&cidr)?;
        self.with_region(ctx, |r| {
            let rec = r.vpcs.get_mut(&input.vpc_id).ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
            let existing = vpc_cidrs(&rec.vpc);
            if existing.iter().any(|c| c.overlaps(&parsed)) {
                return Err(err("InvalidVpc.Range", format!("The CIDR '{cidr}' is invalid.")));
            }
            if existing.len() >= 5 {
                return Err(err(
                    "CidrLimitExceeded",
                    format!("This network '{}' has met its maximum number of allowed CIDRs: 5", input.vpc_id),
                ));
            }
            let assoc = t::VpcCidrBlockAssociation {
                association_id: Some(new_id("vpc-cidr-assoc")),
                cidr_block: Some(cidr.clone()),
                cidr_block_state: Some(t::VpcCidrBlockState { state: Some("associated".into()), status_message: None }),
            };
            rec.vpc.cidr_block_association_set.get_or_insert_with(Vec::new).push(assoc.clone());
            let vpc_id = input.vpc_id.clone();
            for rt in r.route_tables.values_mut().filter(|rt| rt.vpc_id.as_deref() == Some(vpc_id.as_str())) {
                rt.routes.get_or_insert_with(Vec::new).push(local_route(&cidr));
            }
            let mut shown = assoc;
            shown.cidr_block_state =
                Some(t::VpcCidrBlockState { state: Some("associating".into()), status_message: None });
            Ok(t::AssociateVpcCidrBlockResult {
                vpc_id: Some(vpc_id),
                cidr_block_association: Some(shown),
                ..Default::default()
            })
        })
    }

    pub(crate) fn disassociate_vpc_cidr_block_op(
        &self,
        ctx: &RequestContext,
        input: t::DisassociateVpcCidrBlockRequest,
    ) -> Result<t::DisassociateVpcCidrBlockResult, ServiceError> {
        self.authorize_known(ctx, "DisassociateVpcCidrBlock", &[("*".into(), ConditionContext::new())], None)?;
        self.with_region(ctx, |r| {
            if let Some(v6) = crate::ops::addressing::remove_vpc_ipv6(r, &input.association_id) {
                let (vpc_id, assoc) = v6?;
                return Ok(t::DisassociateVpcCidrBlockResult {
                    vpc_id: Some(vpc_id),
                    ipv6_cidr_block_association: Some(assoc),
                    ..Default::default()
                });
            }
            let (vpc_id, cidr) = r
                .vpcs
                .values()
                .find_map(|v| {
                    v.vpc.cidr_block_association_set.iter().flatten().find(|a| a.association_id.as_deref() == Some(input.association_id.as_str())).map(|a| {
                        (v.vpc.vpc_id.clone().unwrap_or_default(), a.cidr_block.clone().unwrap_or_default())
                    })
                })
                .ok_or_else(|| err("InvalidVpcCidrBlockAssociationID.NotFound", format!("The vpc CIDR block association ID '{}' does not exist", input.association_id)))?;
            let rec = r.vpcs.get_mut(&vpc_id).expect("found above");
            if rec.vpc.cidr_block.as_deref() == Some(cidr.as_str()) {
                return Err(err(
                    "OperationNotPermitted",
                    format!("The vpc CIDR block with association ID {} may not be disassociated. It is the primary IPv4 CIDR block of the VPC", input.association_id),
                ));
            }
            let parsed = Cidr::parse(&cidr);
            if r.subnets.values().any(|s| s.vpc_id.as_deref() == Some(vpc_id.as_str()) && s.cidr_block.as_deref().and_then(Cidr::parse).zip(parsed).is_some_and(|(s, c)| c.contains_cidr(&s))) {
                return Err(err("InvalidCidrBlock.InUse", format!("The vpc CIDR block {cidr} is in use by subnets")));
            }
            let rec = r.vpcs.get_mut(&vpc_id).expect("found above");
            let mut removed = None;
            if let Some(set) = &mut rec.vpc.cidr_block_association_set {
                if let Some(i) = set.iter().position(|a| a.association_id.as_deref() == Some(input.association_id.as_str())) {
                    removed = Some(set.remove(i));
                }
            }
            for rt in r.route_tables.values_mut().filter(|rt| rt.vpc_id.as_deref() == Some(vpc_id.as_str())) {
                if let Some(routes) = &mut rt.routes {
                    routes.retain(|rr| !(rr.gateway_id.as_deref() == Some("local") && rr.destination_cidr_block.as_deref() == Some(cidr.as_str())));
                }
            }
            let mut shown = removed.unwrap_or_default();
            shown.cidr_block_state = Some(t::VpcCidrBlockState { state: Some("disassociating".into()), status_message: None });
            Ok(t::DisassociateVpcCidrBlockResult { vpc_id: Some(vpc_id), cidr_block_association: Some(shown), ..Default::default() })
        })
    }

    // ---- subnets ------------------------------------------------------------------------

    pub(crate) fn create_subnet_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateSubnetRequest,
    ) -> Result<t::CreateSubnetResult, ServiceError> {
        let account = account_of(ctx);
        Kind::Vpc.check(&input.vpc_id)?;
        let tags = tags_for(&input.tag_specifications, "subnet", &["subnet"])?;
        let mut cond = request_tag_context(&tags);
        cond.insert("ec2:Vpc".into(), vec![arn(ctx, &account, &format!("vpc/{}", input.vpc_id))]);
        self.authorize_known(
            ctx,
            "CreateSubnet",
            &[
                (arn(ctx, &account, "subnet/*"), cond),
                (arn(ctx, &account, &format!("vpc/{}", input.vpc_id)), ConditionContext::new()),
            ],
            input.dry_run,
        )?;
        let cidr = input.cidr_block.clone().ok_or_else(|| missing_parameter("CidrBlock"))?;
        let parsed = match Cidr::parse(&cidr) {
            Some(c) if (16..=28).contains(&c.prefix) => c,
            _ => return Err(err("InvalidSubnet.Range", format!("The CIDR '{cidr}' is invalid."))),
        };
        if !parsed.is_network() {
            return Err(invalid_parameter(format!(
                "Value ({cidr}) for parameter cidrBlock is invalid. This is not a valid CIDR block."
            )));
        }
        let region = ctx.region.clone();
        let (zone, zone_id) = match (&input.availability_zone, &input.availability_zone_id) {
            (Some(z), _) => (z.clone(), catalog::zone_id(&region, z).ok_or_else(|| invalid_parameter(format!("Value ({z}) for parameter availabilityZone is invalid. Subnets can currently only be created in the following availability zones: {}.", catalog::zones(&region).into_iter().map(|z| z.0).collect::<Vec<_>>().join(", "))))?),
            (None, Some(id)) => (catalog::zone_name(&region, id).ok_or_else(|| invalid_parameter(format!("Value ({id}) for parameter availabilityZoneId is invalid.")))?, id.clone()),
            (None, None) => {
                let zones = catalog::zones(&region);
                let i = rand::random::<usize>() % zones.len();
                zones[i].clone()
            }
        };
        let partition = ctx.partition.clone();
        let limit = self.quota(&account, &region, crate::quotas::SUBNETS_PER_VPC, ctx.received_at);
        self.with_region(ctx, |r| {
            let vpc = r.vpcs.get(&input.vpc_id).ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
            if r.subnets.values().filter(|s| s.vpc_id.as_deref() == Some(input.vpc_id.as_str())).count() as f64 >= limit
            {
                return Err(err("SubnetLimitExceeded", "The maximum number of subnets has been reached."));
            }
            if !vpc_cidrs(&vpc.vpc).iter().any(|c| c.contains_cidr(&parsed)) {
                return Err(err("InvalidSubnet.Range", format!("The CIDR '{cidr}' is invalid.")));
            }
            let conflict = r.subnets.values().any(|s| {
                s.vpc_id.as_deref() == Some(input.vpc_id.as_str())
                    && s.cidr_block.as_deref().and_then(Cidr::parse).is_some_and(|c| c.overlaps(&parsed))
            });
            if conflict {
                return Err(err("InvalidSubnet.Conflict", format!("The CIDR '{cidr}' conflicts with another subnet")));
            }
            let id = new_subnet(r, &account, &region, &partition, &input.vpc_id, &cidr, &zone, &zone_id, tags);
            let mut subnet = render_subnet(r, &r.subnets[&id]);
            subnet.state = Some("pending".into());
            Ok(t::CreateSubnetResult { subnet: Some(subnet) })
        })
    }

    pub(crate) fn create_default_subnet_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDefaultSubnetRequest,
    ) -> Result<t::CreateDefaultSubnetResult, ServiceError> {
        let account = account_of(ctx);
        self.authorize_known(
            ctx,
            "CreateDefaultSubnet",
            &[(arn(ctx, &account, "subnet/*"), ConditionContext::new())],
            input.dry_run,
        )?;
        let region = ctx.region.clone();
        let partition = ctx.partition.clone();
        let zone = match (&input.availability_zone, &input.availability_zone_id) {
            (Some(z), _) => z.clone(),
            (None, Some(id)) => catalog::zone_name(&region, id)
                .ok_or_else(|| invalid_parameter(format!("Invalid availability zone id: {id}")))?,
            (None, None) => return Err(missing_parameter("AvailabilityZone")),
        };
        let zone_id = catalog::zone_id(&region, &zone)
            .ok_or_else(|| invalid_parameter(format!("Value ({zone}) for parameter availabilityZone is invalid.")))?;
        self.with_region(ctx, |r| {
            let vpc_id = r
                .vpcs
                .values()
                .find(|v| v.vpc.is_default == Some(true))
                .and_then(|v| v.vpc.vpc_id.clone())
                .ok_or_else(|| err("DefaultVpcDoesNotExist", "No default VPC for this user"))?;
            if r.subnets.values().any(|s| {
                s.vpc_id.as_deref() == Some(vpc_id.as_str())
                    && s.availability_zone.as_deref() == Some(zone.as_str())
                    && s.default_for_az == Some(true)
            }) {
                return Err(err(
                    "DefaultSubnetAlreadyExistsInAvailabilityZone",
                    format!("{zone} already has a default subnet."),
                ));
            }
            let vpc = Cidr::parse(DEFAULT_VPC_CIDR).expect("valid");
            let free = (0..16u32).map(|i| Cidr { base: vpc.base + i * 4096, prefix: 20 }).find(|c| {
                !r.subnets.values().any(|s| {
                    s.vpc_id.as_deref() == Some(vpc_id.as_str())
                        && s.cidr_block.as_deref().and_then(Cidr::parse).is_some_and(|x| x.overlaps(c))
                })
            });
            let cidr = free.ok_or_else(|| {
                err(
                    "InsufficientFreeAddressesInSubnet",
                    "There is no room in the default VPC for another default subnet.",
                )
            })?;
            let id = new_subnet(
                r,
                &account,
                &region,
                &partition,
                &vpc_id,
                &format!("{}/20", ip_str(cidr.base)),
                &zone,
                &zone_id,
                Vec::new(),
            );
            let s = r.subnets.get_mut(&id).expect("just made");
            s.default_for_az = Some(true);
            s.map_public_ip_on_launch = Some(true);
            Ok(t::CreateDefaultSubnetResult { subnet: Some(render_subnet(r, &r.subnets[&id])) })
        })
    }

    pub(crate) fn delete_subnet_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteSubnetRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::Subnet.check(&input.subnet_id)?;
        let tags = self.with_region(ctx, |r| r.subnets.get(&input.subnet_id).map(|s| s.tags.clone()));
        let tags = tags.ok_or_else(|| Kind::Subnet.not_found(&input.subnet_id))?;
        self.authorize_known(
            ctx,
            "DeleteSubnet",
            &[(arn(ctx, &account, &format!("subnet/{}", input.subnet_id)), resource_tag_context(tags.as_ref()))],
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let id = input.subnet_id.as_str();
            if r.network_interfaces.values().any(|n| n.subnet_id.as_deref() == Some(id))
                || r.nat_gateways
                    .values()
                    .any(|n| n.subnet_id.as_deref() == Some(id) && n.state.as_deref() != Some("deleted"))
            {
                return Err(err(
                    "DependencyViolation",
                    format!("The subnet '{id}' has dependencies and cannot be deleted."),
                ));
            }
            r.subnets.remove(id);
            for rt in r.route_tables.values_mut() {
                if let Some(a) = &mut rt.associations {
                    a.retain(|a| a.subnet_id.as_deref() != Some(id));
                }
            }
            for acl in r.network_acls.values_mut() {
                if let Some(a) = &mut acl.associations {
                    a.retain(|a| a.subnet_id.as_deref() != Some(id));
                }
            }
            Ok(())
        })
    }

    pub(crate) fn describe_subnets_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSubnetsRequest,
    ) -> Result<t::DescribeSubnetsResult, ServiceError> {
        self.authorize_known(ctx, "DescribeSubnets", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.subnet_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Subnet.check_all(&ids, |id| r.subnets.contains_key(id))?;
            let mut out = Vec::new();
            for sn in r.subnets.values() {
                if !ids.is_empty() && !ids.contains(sn.subnet_id.as_ref().unwrap()) {
                    continue;
                }
                let v = render_subnet(r, sn);
                let ok = filters.matches(v.tags.as_ref(), |name| {
                    Some(match name {
                        "availability-zone" | "availabilityZone" => s(&v.availability_zone),
                        "availability-zone-id" | "availabilityZoneId" => s(&v.availability_zone_id),
                        "available-ip-address-count" => {
                            v.available_ip_address_count.map(|c| c.to_string()).into_iter().collect()
                        }
                        "cidr-block" | "cidr" | "cidrBlock" => s(&v.cidr_block),
                        "default-for-az" | "defaultForAz" => b(v.default_for_az),
                        "map-public-ip-on-launch" => b(v.map_public_ip_on_launch),
                        "owner-id" => s(&v.owner_id),
                        "state" => s(&v.state),
                        "subnet-arn" => s(&v.subnet_arn),
                        "subnet-id" => s(&v.subnet_id),
                        "vpc-id" => s(&v.vpc_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(v);
                }
            }
            let (subnets, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeSubnetsResult { subnets: Some(subnets), next_token })
        })
    }

    pub(crate) fn modify_subnet_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifySubnetAttributeRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::Subnet.check(&input.subnet_id)?;
        self.authorize_known(
            ctx,
            "ModifySubnetAttribute",
            &[(arn(ctx, &account, &format!("subnet/{}", input.subnet_id)), ConditionContext::new())],
            None,
        )?;
        self.with_region(ctx, |r| {
            let sn = r.subnets.get_mut(&input.subnet_id).ok_or_else(|| Kind::Subnet.not_found(&input.subnet_id))?;
            if let Some(v) = input.map_public_ip_on_launch.as_ref().and_then(|v| v.value) {
                sn.map_public_ip_on_launch = Some(v);
            }
            if let Some(v) = input.assign_ipv6_address_on_creation.as_ref().and_then(|v| v.value) {
                sn.assign_ipv6_address_on_creation = Some(v);
            }
            if let Some(v) = input.map_customer_owned_ip_on_launch.as_ref().and_then(|v| v.value) {
                sn.map_customer_owned_ip_on_launch = Some(v);
            }
            if let Some(v) = input.enable_dns64.as_ref().and_then(|v| v.value) {
                sn.enable_dns64 = Some(v);
            }
            let opts = sn.private_dns_name_options_on_launch.get_or_insert_with(Default::default);
            if let Some(v) = &input.private_dns_hostname_type_on_launch {
                opts.hostname_type = Some(v.clone());
            }
            if let Some(v) = input.enable_resource_name_dns_a_record_on_launch.as_ref().and_then(|v| v.value) {
                opts.enable_resource_name_dns_a_record = Some(v);
            }
            if let Some(v) = input.enable_resource_name_dns_aaaa_record_on_launch.as_ref().and_then(|v| v.value) {
                opts.enable_resource_name_dns_aaaa_record = Some(v);
            }
            Ok(())
        })
    }

    // ---- internet gateways ---------------------------------------------------------------------

    pub(crate) fn create_internet_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateInternetGatewayRequest,
    ) -> Result<t::CreateInternetGatewayResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "internet-gateway", &["internet-gateway"])?;
        self.authorize_known(
            ctx,
            "CreateInternetGateway",
            &[(arn(ctx, &account, "internet-gateway/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        let limit = self.quota(&account, &ctx.region, crate::quotas::INTERNET_GATEWAYS, ctx.received_at);
        self.with_region(ctx, |r| {
            if r.internet_gateways.len() as f64 >= limit {
                return Err(err(
                    "InternetGatewayLimitExceeded",
                    "The maximum number of internet gateways has been reached.",
                ));
            }
            let id = new_id("igw");
            let igw = t::InternetGateway {
                internet_gateway_id: Some(id.clone()),
                owner_id: Some(account.clone()),
                attachments: Some(Vec::new()),
                tags: some_tags(tags),
            };
            r.internet_gateways.insert(id, igw.clone());
            Ok(t::CreateInternetGatewayResult { internet_gateway: Some(igw) })
        })
    }

    fn igw_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        igw_id: &str,
        vpc_id: Option<&str>,
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::InternetGateway.check(igw_id)?;
        if let Some(v) = vpc_id {
            Kind::Vpc.check(v)?;
        }
        let tags = self.with_region(ctx, |r| r.internet_gateways.get(igw_id).map(|g| g.tags.clone()));
        let tags = tags.ok_or_else(|| Kind::InternetGateway.not_found(igw_id))?;
        let mut resources =
            vec![(arn(ctx, &account, &format!("internet-gateway/{igw_id}")), resource_tag_context(tags.as_ref()))];
        if let Some(v) = vpc_id {
            resources.push((arn(ctx, &account, &format!("vpc/{v}")), ConditionContext::new()));
        }
        self.authorize_known(ctx, action, &resources, dry_run)
    }

    pub(crate) fn delete_internet_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteInternetGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.igw_authorize(ctx, "DeleteInternetGateway", &input.internet_gateway_id, None, input.dry_run)?;
        self.with_region(ctx, |r| {
            let igw = r
                .internet_gateways
                .get(&input.internet_gateway_id)
                .ok_or_else(|| Kind::InternetGateway.not_found(&input.internet_gateway_id))?;
            if !igw.attachments.clone().unwrap_or_default().is_empty() {
                return Err(err(
                    "DependencyViolation",
                    format!(
                        "The internetGateway '{}' has dependencies and cannot be deleted.",
                        input.internet_gateway_id
                    ),
                ));
            }
            r.internet_gateways.remove(&input.internet_gateway_id);
            Ok(())
        })
    }

    pub(crate) fn attach_internet_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::AttachInternetGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.igw_authorize(
            ctx,
            "AttachInternetGateway",
            &input.internet_gateway_id,
            Some(&input.vpc_id),
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            if !r.vpcs.contains_key(&input.vpc_id) {
                return Err(Kind::Vpc.not_found(&input.vpc_id));
            }
            if let Some(other) = r
                .internet_gateways
                .values()
                .find(|g| g.attachments.iter().flatten().any(|a| a.vpc_id.as_deref() == Some(input.vpc_id.as_str())))
            {
                if other.internet_gateway_id.as_deref() != Some(input.internet_gateway_id.as_str()) {
                    return Err(err(
                        "Resource.AlreadyAssociated",
                        format!("Network {} already has an internet gateway attached", input.vpc_id),
                    ));
                }
            }
            let igw = r
                .internet_gateways
                .get_mut(&input.internet_gateway_id)
                .ok_or_else(|| Kind::InternetGateway.not_found(&input.internet_gateway_id))?;
            if let Some(a) = igw.attachments.iter().flatten().next() {
                return Err(err(
                    "Resource.AlreadyAssociated",
                    format!(
                        "resource {} is already attached to network {}",
                        input.internet_gateway_id,
                        a.vpc_id.clone().unwrap_or_default()
                    ),
                ));
            }
            igw.attachments = Some(vec![t::InternetGatewayAttachment {
                state: Some("available".into()),
                vpc_id: Some(input.vpc_id.clone()),
            }]);
            // Routes left as blackholes by a detach work again.
            for rt in r.route_tables.values_mut() {
                if rt.vpc_id.as_deref() != Some(input.vpc_id.as_str()) {
                    continue;
                }
                for route in rt.routes.iter_mut().flatten() {
                    if route.gateway_id.as_deref() == Some(input.internet_gateway_id.as_str()) {
                        route.state = Some("active".into());
                    }
                }
            }
            Ok(())
        })
    }

    pub(crate) fn detach_internet_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachInternetGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.igw_authorize(
            ctx,
            "DetachInternetGateway",
            &input.internet_gateway_id,
            Some(&input.vpc_id),
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let igw = r
                .internet_gateways
                .get_mut(&input.internet_gateway_id)
                .ok_or_else(|| Kind::InternetGateway.not_found(&input.internet_gateway_id))?;
            let attached = igw.attachments.iter().flatten().any(|a| a.vpc_id.as_deref() == Some(input.vpc_id.as_str()));
            if !attached {
                return Err(err(
                    "Gateway.NotAttached",
                    format!("resource {} is not attached to network {}", input.internet_gateway_id, input.vpc_id),
                ));
            }
            // Public addresses in the VPC need the gateway.
            let vpc = input.vpc_id.as_str();
            let in_vpc = |eni: &str| r.network_interfaces.get(eni).is_some_and(|n| n.vpc_id.as_deref() == Some(vpc));
            let mapped = r.network_interfaces.values().any(|n| {
                n.vpc_id.as_deref() == Some(vpc) && n.association.as_ref().is_some_and(|a| a.public_ip.is_some())
            }) || r.addresses.values().any(|a| a.network_interface_id.as_deref().is_some_and(in_vpc));
            if mapped {
                return Err(err(
                    "DependencyViolation",
                    format!(
                        "Network {vpc} has some mapped public address(es). Please unmap those public address(es) before detaching the gateway."
                    ),
                ));
            }
            let igw = r.internet_gateways.get_mut(&input.internet_gateway_id).expect("checked");
            igw.attachments = Some(Vec::new());
            // Routes through it become blackholes.
            for rt in r.route_tables.values_mut() {
                for route in rt.routes.iter_mut().flatten() {
                    if route.gateway_id.as_deref() == Some(input.internet_gateway_id.as_str()) {
                        route.state = Some("blackhole".into());
                    }
                }
            }
            Ok(())
        })
    }

    pub(crate) fn describe_internet_gateways_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInternetGatewaysRequest,
    ) -> Result<t::DescribeInternetGatewaysResult, ServiceError> {
        self.authorize_known(ctx, "DescribeInternetGateways", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.internet_gateway_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::InternetGateway.check_all(&ids, |id| r.internet_gateways.contains_key(id))?;
            let mut out = Vec::new();
            for g in r.internet_gateways.values() {
                if !ids.is_empty() && !ids.contains(g.internet_gateway_id.as_ref().unwrap()) {
                    continue;
                }
                let atts = g.attachments.clone().unwrap_or_default();
                let ok = filters.matches(g.tags.as_ref(), |name| {
                    Some(match name {
                        "attachment.state" => atts.iter().filter_map(|a| a.state.clone()).collect(),
                        "attachment.vpc-id" => atts.iter().filter_map(|a| a.vpc_id.clone()).collect(),
                        "internet-gateway-id" => s(&g.internet_gateway_id),
                        "owner-id" => s(&g.owner_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(g.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeInternetGatewaysResult { internet_gateways: Some(items), next_token })
        })
    }

    // ---- NAT gateways ------------------------------------------------------------------------

    pub(crate) fn create_nat_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateNatGatewayRequest,
    ) -> Result<t::CreateNatGatewayResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "natgateway", &["natgateway"])?;
        let subnet_id = input.subnet_id.clone().ok_or_else(|| missing_parameter("SubnetId"))?;
        Kind::Subnet.check(&subnet_id)?;
        self.authorize_known(
            ctx,
            "CreateNatGateway",
            &[
                (arn(ctx, &account, "natgateway/*"), request_tag_context(&tags)),
                (arn(ctx, &account, &format!("subnet/{subnet_id}")), ConditionContext::new()),
            ],
            input.dry_run,
        )?;
        let connectivity = input.connectivity_type.clone().unwrap_or_else(|| "public".into());
        // `pending` for the transition delay, then `available`.
        let pending_for = chrono::Duration::milliseconds(self.transition_delay().as_millis() as i64);
        let now = ctx.received_at;
        let region = ctx.region.clone();
        let limit = self.quota(&account, &region, crate::quotas::NAT_GATEWAYS_PER_AZ, now);
        let fp = idempotency::fingerprint(&input);
        let token = input.client_token.as_deref();
        self.with_region(ctx, |r| {
            if let Some(id) =
                idempotency::replay(r, "CreateNatGateway", token, &fp, |id| r.nat_gateways.contains_key(id))?
            {
                return Ok(t::CreateNatGatewayResult {
                    nat_gateway: r.nat_gateways.get(&id).cloned(),
                    client_token: input.client_token.clone(),
                });
            }
            let subnet = r.subnets.get(&subnet_id).ok_or_else(|| Kind::Subnet.not_found(&subnet_id))?.clone();
            let in_zone = r
                .nat_gateways
                .values()
                .filter(|n| !matches!(n.state.as_deref(), Some("deleted" | "deleting" | "failed")))
                .filter(|n| {
                    n.subnet_id.as_ref().and_then(|s| r.subnets.get(s)).and_then(|s| s.availability_zone.as_ref())
                        == subnet.availability_zone.as_ref()
                })
                .count();
            if in_zone as f64 >= limit {
                return Err(err("NatGatewayLimitExceeded", "The maximum number of NAT Gateways has been reached."));
            }
            let public_ip = if connectivity == "public" {
                let alloc = input.allocation_id.clone().ok_or_else(|| missing_parameter("AllocationId"))?;
                let addr = r.addresses.get(&alloc).ok_or_else(|| Kind::Allocation.not_found(&alloc))?;
                if addr.association_id.is_some() {
                    return Err(err(
                        "Resource.AlreadyAssociated",
                        format!("Elastic IP address [{alloc}] is already associated"),
                    ));
                }
                Some((alloc, addr.public_ip.clone()))
            } else {
                None
            };
            let ip = match &input.private_ip_address {
                Some(ip) => {
                    check_ip(r, &subnet_id, ip)?;
                    ip.clone()
                }
                None => allocate_ip(r, &subnet_id).ok_or_else(|| {
                    err("InsufficientFreeAddressesInSubnet", "Insufficient free IP addresses in subnet.")
                })?,
            };
            let nat_id = new_id("nat");
            let eni_id = super::eni::new_eni(
                r,
                &account,
                &region,
                &subnet,
                &ip,
                Vec::new(),
                &format!("Interface for NAT Gateway {nat_id}"),
                "nat_gateway",
                now,
            );
            if let Some(eni) = r.network_interfaces.get_mut(&eni_id) {
                eni.requester_managed = Some(true);
                eni.status = Some("in-use".into());
            }
            let assoc_id = public_ip.as_ref().map(|_| new_id("eipassoc"));
            if let Some((alloc, _)) = &public_ip {
                if let Some(a) = r.addresses.get_mut(alloc) {
                    a.association_id = assoc_id.clone();
                    a.network_interface_id = Some(eni_id.clone());
                    a.network_interface_owner_id = Some(account.clone());
                    a.private_ip_address = Some(ip.clone());
                }
            }
            let nat = t::NatGateway {
                nat_gateway_id: Some(nat_id.clone()),
                subnet_id: Some(subnet_id.clone()),
                vpc_id: subnet.vpc_id.clone(),
                create_time: Some(now),
                state: Some(if pending_for.is_zero() { "available" } else { "pending" }.into()),
                connectivity_type: Some(connectivity.clone()),
                availability_mode: Some("zonal".into()),
                nat_gateway_addresses: Some(vec![t::NatGatewayAddress {
                    allocation_id: public_ip.as_ref().map(|p| p.0.clone()),
                    public_ip: public_ip.as_ref().and_then(|p| p.1.clone()),
                    association_id: assoc_id,
                    network_interface_id: Some(eni_id),
                    private_ip: Some(ip),
                    is_primary: Some(true),
                    status: Some("succeeded".into()),
                    ..Default::default()
                }]),
                tags: some_tags(tags),
                ..Default::default()
            };
            r.nat_gateways.insert(nat_id.clone(), nat.clone());
            if !pending_for.is_zero() {
                r.nat_transitions.insert(nat_id.clone(), now + pending_for);
            }
            idempotency::remember(r, "CreateNatGateway", token, &fp, &nat_id);
            let mut shown = nat;
            shown.state = Some("pending".into());
            Ok(t::CreateNatGatewayResult { nat_gateway: Some(shown), client_token: input.client_token.clone() })
        })
    }

    pub(crate) fn delete_nat_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteNatGatewayRequest,
    ) -> Result<t::DeleteNatGatewayResult, ServiceError> {
        let account = account_of(ctx);
        Kind::NatGateway.check(&input.nat_gateway_id)?;
        self.authorize_known(
            ctx,
            "DeleteNatGateway",
            &[(arn(ctx, &account, &format!("natgateway/{}", input.nat_gateway_id)), ConditionContext::new())],
            input.dry_run,
        )?;
        let now = ctx.received_at;
        let transition_ms = self.transition_delay().as_millis() as i64;
        self.with_region(ctx, |r| {
            let nat = r
                .nat_gateways
                .get_mut(&input.nat_gateway_id)
                .ok_or_else(|| Kind::NatGateway.not_found(&input.nat_gateway_id))?;
            // `deleting` for a moment, then `deleted` (see `expire_deleted`).
            let deleting_for = chrono::Duration::milliseconds(transition_ms);
            if deleting_for.is_zero() {
                nat.state = Some("deleted".into());
                nat.delete_time = Some(now);
            } else if nat.state.as_deref() != Some("deleted") {
                nat.state = Some("deleting".into());
                r.nat_transitions.insert(input.nat_gateway_id.clone(), now + deleting_for);
            }
            let nat = r.nat_gateways.get(&input.nat_gateway_id).expect("found above");
            let addrs = nat.nat_gateway_addresses.clone().unwrap_or_default();
            for a in &addrs {
                if let Some(eni) = &a.network_interface_id {
                    r.network_interfaces.remove(eni);
                }
                if let Some(alloc) = &a.allocation_id {
                    if let Some(addr) = r.addresses.get_mut(alloc) {
                        addr.association_id = None;
                        addr.network_interface_id = None;
                        addr.network_interface_owner_id = None;
                        addr.private_ip_address = None;
                    }
                }
            }
            for rt in r.route_tables.values_mut() {
                for route in rt.routes.iter_mut().flatten() {
                    if route.nat_gateway_id.as_deref() == Some(input.nat_gateway_id.as_str()) {
                        route.state = Some("blackhole".into());
                    }
                }
            }
            Ok(t::DeleteNatGatewayResult { nat_gateway_id: Some(input.nat_gateway_id.clone()) })
        })
    }

    pub(crate) fn describe_nat_gateways_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeNatGatewaysRequest,
    ) -> Result<t::DescribeNatGatewaysResult, ServiceError> {
        self.authorize_known(ctx, "DescribeNatGateways", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filter);
        let ids = input.nat_gateway_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::NatGateway.check_all(&ids, |id| r.nat_gateways.contains_key(id))?;
            let mut out = Vec::new();
            for n in r.nat_gateways.values() {
                if !ids.is_empty() && !ids.contains(n.nat_gateway_id.as_ref().unwrap()) {
                    continue;
                }
                let ok = filters.matches(n.tags.as_ref(), |name| {
                    Some(match name {
                        "nat-gateway-id" => s(&n.nat_gateway_id),
                        "state" => s(&n.state),
                        "subnet-id" => s(&n.subnet_id),
                        "vpc-id" => s(&n.vpc_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(n.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeNatGatewaysResult { nat_gateways: Some(items), next_token })
        })
    }

    // ---- route tables ----------------------------------------------------------------------------

    pub(crate) fn create_route_table_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateRouteTableRequest,
    ) -> Result<t::CreateRouteTableResult, ServiceError> {
        let account = account_of(ctx);
        Kind::Vpc.check(&input.vpc_id)?;
        let tags = tags_for(&input.tag_specifications, "route-table", &["route-table"])?;
        self.authorize_known(
            ctx,
            "CreateRouteTable",
            &[
                (arn(ctx, &account, "route-table/*"), {
                    let mut c = request_tag_context(&tags);
                    c.extend(crate::conditions::in_vpc(ctx, &account, &input.vpc_id));
                    c
                }),
                (arn(ctx, &account, &format!("vpc/{}", input.vpc_id)), ConditionContext::new()),
            ],
            input.dry_run,
        )?;
        let fp = idempotency::fingerprint(&input);
        let token = input.client_token.as_deref();
        self.with_region(ctx, |r| {
            if let Some(id) =
                idempotency::replay(r, "CreateRouteTable", token, &fp, |id| r.route_tables.contains_key(id))?
            {
                return Ok(t::CreateRouteTableResult {
                    route_table: r.route_tables.get(&id).cloned(),
                    client_token: input.client_token.clone(),
                });
            }
            let vpc = r.vpcs.get(&input.vpc_id).ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
            let routes: Vec<t::Route> =
                vpc_cidrs(&vpc.vpc).iter().map(|c| local_route(&format!("{}/{}", ip_str(c.base), c.prefix))).collect();
            let id = new_id("rtb");
            let rt = t::RouteTable {
                route_table_id: Some(id.clone()),
                vpc_id: Some(input.vpc_id.clone()),
                owner_id: Some(account.clone()),
                routes: Some(routes),
                associations: Some(Vec::new()),
                propagating_vgws: Some(Vec::new()),
                tags: some_tags(tags),
            };
            r.route_tables.insert(id.clone(), rt.clone());
            idempotency::remember(r, "CreateRouteTable", token, &fp, &id);
            Ok(t::CreateRouteTableResult { route_table: Some(rt), client_token: input.client_token.clone() })
        })
    }

    pub(crate) fn rtb_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        rtb_id: &str,
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::RouteTable.check(rtb_id)?;
        let tags = self.with_region(ctx, |r| r.route_tables.get(rtb_id).map(|g| g.tags.clone()));
        let tags = tags.ok_or_else(|| Kind::RouteTable.not_found(rtb_id))?;
        let resources = self.with_resource_context(
            ctx,
            vec![(arn(ctx, &account, &format!("route-table/{rtb_id}")), resource_tag_context(tags.as_ref()))],
        );
        self.authorize_known(ctx, action, &resources, dry_run)
    }

    pub(crate) fn delete_route_table_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteRouteTableRequest,
    ) -> Result<(), ServiceError> {
        self.rtb_authorize(ctx, "DeleteRouteTable", &input.route_table_id, input.dry_run)?;
        self.with_region(ctx, |r| {
            let rt = r
                .route_tables
                .get(&input.route_table_id)
                .ok_or_else(|| Kind::RouteTable.not_found(&input.route_table_id))?;
            if !rt.associations.clone().unwrap_or_default().is_empty() {
                return Err(err(
                    "DependencyViolation",
                    format!("The routeTable '{}' has dependencies and cannot be deleted.", input.route_table_id),
                ));
            }
            r.route_tables.remove(&input.route_table_id);
            Ok(())
        })
    }

    pub(crate) fn describe_route_tables_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeRouteTablesRequest,
    ) -> Result<t::DescribeRouteTablesResult, ServiceError> {
        self.authorize_known(ctx, "DescribeRouteTables", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.route_table_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::RouteTable.check_all(&ids, |id| r.route_tables.contains_key(id))?;
            let mut out = Vec::new();
            for rt in r.route_tables.values() {
                if !ids.is_empty() && !ids.contains(rt.route_table_id.as_ref().unwrap()) {
                    continue;
                }
                let assoc = rt.associations.clone().unwrap_or_default();
                let routes = rt.routes.clone().unwrap_or_default();
                let ok = filters.matches(rt.tags.as_ref(), |name| {
                    Some(match name {
                        "association.route-table-association-id" => {
                            assoc.iter().filter_map(|a| a.route_table_association_id.clone()).collect()
                        }
                        "association.route-table-id" => assoc.iter().filter_map(|a| a.route_table_id.clone()).collect(),
                        "association.subnet-id" => assoc.iter().filter_map(|a| a.subnet_id.clone()).collect(),
                        "association.gateway-id" => assoc.iter().filter_map(|a| a.gateway_id.clone()).collect(),
                        "association.main" => {
                            let main = assoc.iter().any(|a| a.main == Some(true));
                            vec![main.to_string()]
                        }
                        "owner-id" => s(&rt.owner_id),
                        "route-table-id" => s(&rt.route_table_id),
                        "route.destination-cidr-block" => {
                            routes.iter().filter_map(|r| r.destination_cidr_block.clone()).collect()
                        }
                        "route.destination-ipv6-cidr-block" => {
                            routes.iter().filter_map(|r| r.destination_ipv6_cidr_block.clone()).collect()
                        }
                        "route.destination-prefix-list-id" => {
                            routes.iter().filter_map(|r| r.destination_prefix_list_id.clone()).collect()
                        }
                        "route.egress-only-internet-gateway-id" => {
                            routes.iter().filter_map(|r| r.egress_only_internet_gateway_id.clone()).collect()
                        }
                        "route.transit-gateway-id" => {
                            routes.iter().filter_map(|r| r.transit_gateway_id.clone()).collect()
                        }
                        "route.vpc-peering-connection-id" => {
                            routes.iter().filter_map(|r| r.vpc_peering_connection_id.clone()).collect()
                        }
                        "route.gateway-id" => routes.iter().filter_map(|r| r.gateway_id.clone()).collect(),
                        "route.nat-gateway-id" => routes.iter().filter_map(|r| r.nat_gateway_id.clone()).collect(),
                        "route.instance-id" => routes.iter().filter_map(|r| r.instance_id.clone()).collect(),
                        "route.state" => routes.iter().filter_map(|r| r.state.clone()).collect(),
                        "route.origin" => routes.iter().filter_map(|r| r.origin.clone()).collect(),
                        "vpc-id" => s(&rt.vpc_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(rt.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeRouteTablesResult { route_tables: Some(items), next_token })
        })
    }

    /// A route from `CreateRoute`/`ReplaceRoute` targets, checked against
    /// the Region's resources.
    #[allow(clippy::too_many_arguments)]
    fn build_route(
        r: &RegionState,
        vpc_id: &str,
        dest: &str,
        gateway_id: &Option<String>,
        nat_gateway_id: &Option<String>,
        instance_id: &Option<String>,
        network_interface_id: &Option<String>,
        others: &[&Option<String>],
    ) -> Result<t::Route, ServiceError> {
        let mut route = t::Route {
            destination_cidr_block: Some(dest.into()),
            origin: Some("CreateRoute".into()),
            state: Some("active".into()),
            ..Default::default()
        };
        let targets =
            [gateway_id, nat_gateway_id, instance_id, network_interface_id].iter().filter(|v| v.is_some()).count()
                + others.iter().filter(|v| v.is_some()).count();
        if targets == 0 {
            return Err(err("InvalidParameterCombination", "No route target specified"));
        }
        if targets > 1 {
            return Err(err("InvalidParameterCombination", "More than one target specified"));
        }
        if let Some(g) = gateway_id {
            if g.starts_with("igw-") {
                let igw = r.internet_gateways.get(g).ok_or_else(|| Kind::InternetGateway.not_found(g))?;
                if !igw.attachments.iter().flatten().any(|a| a.vpc_id.as_deref() == Some(vpc_id)) {
                    return Err(err(
                        "InvalidParameterValue",
                        "route table and network gateway belong to different networks".to_string(),
                    ));
                }
            } else if g.starts_with("vgw-") {
                let attached = r.vpn_gateways.get(g).is_some_and(|v| {
                    v.vpc_attachments
                        .iter()
                        .flatten()
                        .any(|a| a.vpc_id.as_deref() == Some(vpc_id) && a.state.as_deref() == Some("attached"))
                });
                if !r.vpn_gateways.get(g).is_some_and(|v| v.state.as_deref() == Some("available")) {
                    return Err(Kind::VpnGateway.not_found(g));
                }
                if !attached {
                    return Err(err(
                        "InvalidParameterValue",
                        "route table and network gateway belong to different networks".to_string(),
                    ));
                }
            } else if g != "local" && !g.starts_with("vpce-") {
                return Err(err("InvalidGatewayID.NotFound", format!("The gateway ID '{g}' does not exist")));
            }
            route.gateway_id = Some(g.clone());
        }
        for target in others.iter().filter_map(|o| o.as_deref()) {
            check_route_target(r, vpc_id, target)?;
        }
        if let Some(n) = nat_gateway_id {
            if !r.nat_gateways.contains_key(n) {
                return Err(Kind::NatGateway.not_found(n));
            }
            route.nat_gateway_id = Some(n.clone());
        }
        if let Some(i) = instance_id {
            let inst = r.instances.get(i).ok_or_else(|| Kind::Instance.not_found(i))?;
            route.instance_id = Some(i.clone());
            route.instance_owner_id = Some(inst.owner_id.clone());
            route.network_interface_id =
                inst.instance.network_interfaces.iter().flatten().next().and_then(|n| n.network_interface_id.clone());
        }
        if let Some(n) = network_interface_id {
            if !r.network_interfaces.contains_key(n) {
                return Err(Kind::NetworkInterface.not_found(n));
            }
            route.network_interface_id = Some(n.clone());
        }
        Ok(route)
    }

    pub(crate) fn create_route_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateRouteRequest,
    ) -> Result<t::CreateRouteResult, ServiceError> {
        self.rtb_authorize(ctx, "CreateRoute", &input.route_table_id, input.dry_run)?;
        let dest = input
            .destination_cidr_block
            .clone()
            .or_else(|| input.destination_ipv6_cidr_block.clone())
            .or_else(|| input.destination_prefix_list_id.clone())
            .ok_or_else(|| missing_parameter("destinationCidrBlock"))?;
        if input.destination_cidr_block.is_some() && Cidr::parse(&dest).is_none() {
            return Err(invalid_parameter(format!(
                "Value ({dest}) for parameter destinationCidrBlock is invalid. This is not a valid CIDR block."
            )));
        }
        let limit = self.quota(&account_of(ctx), &ctx.region, crate::quotas::ROUTES_PER_TABLE, ctx.received_at);
        self.with_region(ctx, |r| {
            let rt = r
                .route_tables
                .get(&input.route_table_id)
                .ok_or_else(|| Kind::RouteTable.not_found(&input.route_table_id))?;
            let vpc_id = rt.vpc_id.clone().unwrap_or_default();
            // Local and propagated routes do not count.
            let routes = rt.routes.iter().flatten().filter(|x| x.origin.as_deref() == Some("CreateRoute")).count();
            if routes as f64 >= limit {
                return Err(err("RouteLimitExceeded", "The maximum number of routes has been reached."));
            }
            if rt.routes.iter().flatten().any(|x| {
                x.destination_cidr_block.as_deref() == Some(dest.as_str())
                    || x.destination_ipv6_cidr_block.as_deref() == Some(dest.as_str())
                    || x.destination_prefix_list_id.as_deref() == Some(dest.as_str())
            }) {
                return Err(err("RouteAlreadyExists", format!("The route identified by {dest} already exists.")));
            }
            let mut route = Self::build_route(
                r,
                &vpc_id,
                &dest,
                &input.gateway_id,
                &input.nat_gateway_id,
                &input.instance_id,
                &input.network_interface_id,
                &[
                    &input.vpc_peering_connection_id,
                    &input.transit_gateway_id,
                    &input.egress_only_internet_gateway_id,
                    &input.vpc_endpoint_id,
                    &input.local_gateway_id,
                    &input.carrier_gateway_id,
                    &input.core_network_arn,
                ],
            )?;
            if input.destination_cidr_block.is_none() {
                route.destination_cidr_block = None;
                route.destination_ipv6_cidr_block = input.destination_ipv6_cidr_block.clone();
                route.destination_prefix_list_id = input.destination_prefix_list_id.clone();
            }
            route.vpc_peering_connection_id = input.vpc_peering_connection_id.clone();
            route.transit_gateway_id = input.transit_gateway_id.clone();
            route.egress_only_internet_gateway_id = input.egress_only_internet_gateway_id.clone();
            route.local_gateway_id = input.local_gateway_id.clone();
            route.carrier_gateway_id = input.carrier_gateway_id.clone();
            route.core_network_arn = input.core_network_arn.clone();
            if let Some(ep) = &input.vpc_endpoint_id {
                route.gateway_id = Some(ep.clone());
            }
            let rt = r.route_tables.get_mut(&input.route_table_id).expect("checked");
            rt.routes.get_or_insert_with(Vec::new).push(route);
            Ok(t::CreateRouteResult { r#return: Some(true) })
        })
    }

    pub(crate) fn replace_route_op(
        &self,
        ctx: &RequestContext,
        input: t::ReplaceRouteRequest,
    ) -> Result<(), ServiceError> {
        self.rtb_authorize(ctx, "ReplaceRoute", &input.route_table_id, input.dry_run)?;
        let dest = input
            .destination_cidr_block
            .clone()
            .or_else(|| input.destination_ipv6_cidr_block.clone())
            .or_else(|| input.destination_prefix_list_id.clone())
            .ok_or_else(|| missing_parameter("destinationCidrBlock"))?;
        self.with_region(ctx, |r| {
            let rt = r
                .route_tables
                .get(&input.route_table_id)
                .ok_or_else(|| Kind::RouteTable.not_found(&input.route_table_id))?;
            let vpc_id = rt.vpc_id.clone().unwrap_or_default();
            let idx = rt
                .routes
                .iter()
                .flatten()
                .position(|x| {
                    x.destination_cidr_block.as_deref() == Some(dest.as_str())
                        || x.destination_ipv6_cidr_block.as_deref() == Some(dest.as_str())
                })
                .ok_or_else(|| {
                    err(
                        "InvalidRoute.NotFound",
                        format!("no route with destination-cidr-block {dest} in route table {}", input.route_table_id),
                    )
                })?;
            let gateway =
                if input.local_target == Some(true) { Some("local".to_string()) } else { input.gateway_id.clone() };
            let mut route = Self::build_route(
                r,
                &vpc_id,
                &dest,
                &gateway,
                &input.nat_gateway_id,
                &input.instance_id,
                &input.network_interface_id,
                &[
                    &input.vpc_peering_connection_id,
                    &input.transit_gateway_id,
                    &input.egress_only_internet_gateway_id,
                    &input.vpc_endpoint_id,
                ],
            )?;
            route.origin = Some("CreateRoute".into());
            route.vpc_peering_connection_id = input.vpc_peering_connection_id.clone();
            route.transit_gateway_id = input.transit_gateway_id.clone();
            route.egress_only_internet_gateway_id = input.egress_only_internet_gateway_id.clone();
            let rt = r.route_tables.get_mut(&input.route_table_id).expect("checked");
            rt.routes.as_mut().expect("has routes")[idx] = route;
            Ok(())
        })
    }

    pub(crate) fn delete_route_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteRouteRequest,
    ) -> Result<(), ServiceError> {
        self.rtb_authorize(ctx, "DeleteRoute", &input.route_table_id, input.dry_run)?;
        let dest = input
            .destination_cidr_block
            .clone()
            .or_else(|| input.destination_ipv6_cidr_block.clone())
            .or_else(|| input.destination_prefix_list_id.clone())
            .ok_or_else(|| missing_parameter("destinationCidrBlock"))?;
        self.with_region(ctx, |r| {
            let rt = r
                .route_tables
                .get_mut(&input.route_table_id)
                .ok_or_else(|| Kind::RouteTable.not_found(&input.route_table_id))?;
            let routes = rt.routes.get_or_insert_with(Vec::new);
            let idx = routes
                .iter()
                .position(|x| {
                    x.destination_cidr_block.as_deref() == Some(dest.as_str())
                        || x.destination_ipv6_cidr_block.as_deref() == Some(dest.as_str())
                        || x.destination_prefix_list_id.as_deref() == Some(dest.as_str())
                })
                .ok_or_else(|| {
                    err(
                        "InvalidRoute.NotFound",
                        format!("no route with destination-cidr-block {dest} in route table {}", input.route_table_id),
                    )
                })?;
            if routes[idx].gateway_id.as_deref() == Some("local") {
                return Err(err(
                    "InvalidParameterValue",
                    format!("cannot remove local route {dest} in route table {}", input.route_table_id),
                ));
            }
            routes.remove(idx);
            Ok(())
        })
    }

    pub(crate) fn associate_route_table_op(
        &self,
        ctx: &RequestContext,
        input: t::AssociateRouteTableRequest,
    ) -> Result<t::AssociateRouteTableResult, ServiceError> {
        self.rtb_authorize(ctx, "AssociateRouteTable", &input.route_table_id, input.dry_run)?;
        self.with_region(ctx, |r| {
            let rt = r
                .route_tables
                .get(&input.route_table_id)
                .ok_or_else(|| Kind::RouteTable.not_found(&input.route_table_id))?;
            let vpc_id = rt.vpc_id.clone().unwrap_or_default();
            match (&input.subnet_id, &input.gateway_id) {
                (Some(sub), None) => {
                    Kind::Subnet.check(sub)?;
                    let subnet = r.subnets.get(sub).ok_or_else(|| Kind::Subnet.not_found(sub))?;
                    if subnet.vpc_id.as_deref() != Some(vpc_id.as_str()) {
                        return Err(err(
                            "InvalidParameterValue",
                            format!(
                                "Route table {} and subnet {sub} belong to different networks",
                                input.route_table_id
                            ),
                        ));
                    }
                    if let Some(other) = r.route_tables.values().find(|rt| {
                        rt.associations.iter().flatten().any(|a| a.subnet_id.as_deref() == Some(sub.as_str()))
                    }) {
                        return Err(err(
                            "Resource.AlreadyAssociated",
                            format!(
                                "the specified association for route table {} conflicts with an existing association",
                                other.route_table_id.clone().unwrap_or_default()
                            ),
                        ));
                    }
                }
                (None, Some(g)) => {
                    if !r.internet_gateways.contains_key(g) {
                        return Err(Kind::InternetGateway.not_found(g));
                    }
                }
                _ => {
                    return Err(err(
                        "InvalidParameterCombination",
                        "Exactly one of SubnetId or GatewayId must be specified.",
                    ))
                }
            }
            let id = new_id("rtbassoc");
            let rt = r.route_tables.get_mut(&input.route_table_id).expect("checked");
            rt.associations.get_or_insert_with(Vec::new).push(t::RouteTableAssociation {
                main: Some(false),
                route_table_association_id: Some(id.clone()),
                route_table_id: Some(input.route_table_id.clone()),
                subnet_id: input.subnet_id.clone(),
                gateway_id: input.gateway_id.clone(),
                association_state: Some(assoc_state("associated")),
                ..Default::default()
            });
            Ok(t::AssociateRouteTableResult {
                association_id: Some(id),
                association_state: Some(assoc_state("associated")),
            })
        })
    }

    pub(crate) fn disassociate_route_table_op(
        &self,
        ctx: &RequestContext,
        input: t::DisassociateRouteTableRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_known(ctx, "DisassociateRouteTable", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        self.with_region(ctx, |r| {
            for rt in r.route_tables.values_mut() {
                if let Some(assocs) = &mut rt.associations {
                    if let Some(i) = assocs
                        .iter()
                        .position(|a| a.route_table_association_id.as_deref() == Some(input.association_id.as_str()))
                    {
                        if assocs[i].main == Some(true) {
                            return Err(err(
                                "InvalidParameterValue",
                                format!(
                                    "cannot disassociate the main route table association {}",
                                    input.association_id
                                ),
                            ));
                        }
                        assocs.remove(i);
                        return Ok(());
                    }
                }
            }
            Err(err(
                "InvalidAssociationID.NotFound",
                format!("The association ID '{}' does not exist", input.association_id),
            ))
        })
    }

    pub(crate) fn replace_route_table_association_op(
        &self,
        ctx: &RequestContext,
        input: t::ReplaceRouteTableAssociationRequest,
    ) -> Result<t::ReplaceRouteTableAssociationResult, ServiceError> {
        self.rtb_authorize(ctx, "ReplaceRouteTableAssociation", &input.route_table_id, input.dry_run)?;
        self.with_region(ctx, |r| {
            let mut found: Option<t::RouteTableAssociation> = None;
            for rt in r.route_tables.values_mut() {
                if let Some(assocs) = &mut rt.associations {
                    if let Some(i) = assocs
                        .iter()
                        .position(|a| a.route_table_association_id.as_deref() == Some(input.association_id.as_str()))
                    {
                        found = Some(assocs.remove(i));
                        break;
                    }
                }
            }
            let old = found.ok_or_else(|| {
                err(
                    "InvalidAssociationID.NotFound",
                    format!("The association ID '{}' does not exist", input.association_id),
                )
            })?;
            let id = new_id("rtbassoc");
            let rt = r
                .route_tables
                .get_mut(&input.route_table_id)
                .ok_or_else(|| Kind::RouteTable.not_found(&input.route_table_id))?;
            rt.associations.get_or_insert_with(Vec::new).push(t::RouteTableAssociation {
                route_table_association_id: Some(id.clone()),
                route_table_id: Some(input.route_table_id.clone()),
                association_state: Some(assoc_state("associated")),
                ..old
            });
            Ok(t::ReplaceRouteTableAssociationResult {
                new_association_id: Some(id),
                association_state: Some(assoc_state("associated")),
            })
        })
    }

    // ---- network ACLs ---------------------------------------------------------------------------

    pub(crate) fn create_network_acl_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateNetworkAclRequest,
    ) -> Result<t::CreateNetworkAclResult, ServiceError> {
        let account = account_of(ctx);
        Kind::Vpc.check(&input.vpc_id)?;
        let tags = tags_for(&input.tag_specifications, "network-acl", &["network-acl"])?;
        self.authorize_known(
            ctx,
            "CreateNetworkAcl",
            &[
                (arn(ctx, &account, "network-acl/*"), {
                    let mut c = request_tag_context(&tags);
                    c.extend(crate::conditions::in_vpc(ctx, &account, &input.vpc_id));
                    c
                }),
                (arn(ctx, &account, &format!("vpc/{}", input.vpc_id)), ConditionContext::new()),
            ],
            input.dry_run,
        )?;
        let fp = idempotency::fingerprint(&input);
        let token = input.client_token.as_deref();
        self.with_region(ctx, |r| {
            if let Some(id) =
                idempotency::replay(r, "CreateNetworkAcl", token, &fp, |id| r.network_acls.contains_key(id))?
            {
                return Ok(t::CreateNetworkAclResult {
                    network_acl: r.network_acls.get(&id).cloned(),
                    client_token: input.client_token.clone(),
                });
            }
            if !r.vpcs.contains_key(&input.vpc_id) {
                return Err(Kind::Vpc.not_found(&input.vpc_id));
            }
            let id = new_id("acl");
            let acl = t::NetworkAcl {
                network_acl_id: Some(id.clone()),
                vpc_id: Some(input.vpc_id.clone()),
                owner_id: Some(account.clone()),
                is_default: Some(false),
                associations: Some(Vec::new()),
                entries: Some(vec![
                    acl_entry(32767, true, "-1", "deny", "0.0.0.0/0"),
                    acl_entry(32767, false, "-1", "deny", "0.0.0.0/0"),
                ]),
                tags: some_tags(tags),
            };
            r.network_acls.insert(id.clone(), acl.clone());
            idempotency::remember(r, "CreateNetworkAcl", token, &fp, &id);
            Ok(t::CreateNetworkAclResult { network_acl: Some(acl), client_token: input.client_token.clone() })
        })
    }

    pub(crate) fn delete_network_acl_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteNetworkAclRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_known(
            ctx,
            "DeleteNetworkAcl",
            &[(arn(ctx, &account_of(ctx), &format!("network-acl/{}", input.network_acl_id)), ConditionContext::new())],
            input.dry_run,
        )?;
        Kind::NetworkAcl.check(&input.network_acl_id)?;
        self.with_region(ctx, |r| {
            let acl = r
                .network_acls
                .get(&input.network_acl_id)
                .ok_or_else(|| Kind::NetworkAcl.not_found(&input.network_acl_id))?;
            if acl.is_default == Some(true) {
                return Err(err(
                    "InvalidParameterValue",
                    format!("cannot delete default network ACL {}", input.network_acl_id),
                ));
            }
            if !acl.associations.clone().unwrap_or_default().is_empty() {
                return Err(err(
                    "DependencyViolation",
                    format!("The networkAcl '{}' has dependencies and cannot be deleted.", input.network_acl_id),
                ));
            }
            r.network_acls.remove(&input.network_acl_id);
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn put_acl_entry(
        &self,
        ctx: &RequestContext,
        action: &str,
        acl_id: &str,
        replace: bool,
        entry: t::NetworkAclEntry,
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        self.authorize_known(
            ctx,
            action,
            &[(arn(ctx, &account_of(ctx), &format!("network-acl/{acl_id}")), ConditionContext::new())],
            dry_run,
        )?;
        Kind::NetworkAcl.check(acl_id)?;
        let n = entry.rule_number.unwrap_or_default();
        if !(1..=32766).contains(&n) {
            return Err(invalid_parameter(format!(
                "Value ({n}) for parameter ruleNumber is invalid. Rule number must be between 1 and 32766."
            )));
        }
        let limit = self.quota(&account_of(ctx), &ctx.region, crate::quotas::RULES_PER_ACL, ctx.received_at);
        self.with_region(ctx, |r| {
            let acl = r.network_acls.get_mut(acl_id).ok_or_else(|| Kind::NetworkAcl.not_found(acl_id))?;
            let entries = acl.entries.get_or_insert_with(Vec::new);
            let pos = entries.iter().position(|e| e.rule_number == Some(n) && e.egress == entry.egress);
            // Per direction; the default `*` rules do not count.
            let rules = entries
                .iter()
                .filter(|e| e.egress == entry.egress && e.rule_number.is_some_and(|n| n <= 32766))
                .count();
            if pos.is_none() && !replace && rules as f64 >= limit {
                return Err(err(
                    "NetworkAclEntryLimitExceeded",
                    "The maximum number of network ACL entries has been reached.",
                ));
            }
            match (pos, replace) {
                (Some(_), false) => Err(err(
                    "NetworkAclEntryAlreadyExists",
                    format!("The network acl entry identified by {n} already exists."),
                )),
                (None, true) => Err(err(
                    "InvalidNetworkAclEntry.NotFound",
                    format!("The network acl entry identified by {n} does not exist."),
                )),
                (Some(i), true) => {
                    entries[i] = entry;
                    Ok(())
                }
                (None, false) => {
                    entries.push(entry);
                    entries.sort_by_key(|e| (e.egress, e.rule_number));
                    Ok(())
                }
            }
        })
    }

    pub(crate) fn create_network_acl_entry_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateNetworkAclEntryRequest,
    ) -> Result<(), ServiceError> {
        let entry = t::NetworkAclEntry {
            rule_number: Some(input.rule_number),
            egress: Some(input.egress),
            protocol: Some(input.protocol.clone()),
            rule_action: Some(input.rule_action.clone()),
            cidr_block: input.cidr_block.clone(),
            ipv6_cidr_block: input.ipv6_cidr_block.clone(),
            icmp_type_code: input.icmp_type_code.clone(),
            port_range: input.port_range.clone(),
        };
        self.put_acl_entry(ctx, "CreateNetworkAclEntry", &input.network_acl_id, false, entry, input.dry_run)
    }

    pub(crate) fn replace_network_acl_entry_op(
        &self,
        ctx: &RequestContext,
        input: t::ReplaceNetworkAclEntryRequest,
    ) -> Result<(), ServiceError> {
        let entry = t::NetworkAclEntry {
            rule_number: Some(input.rule_number),
            egress: Some(input.egress),
            protocol: Some(input.protocol.clone()),
            rule_action: Some(input.rule_action.clone()),
            cidr_block: input.cidr_block.clone(),
            ipv6_cidr_block: input.ipv6_cidr_block.clone(),
            icmp_type_code: input.icmp_type_code.clone(),
            port_range: input.port_range.clone(),
        };
        self.put_acl_entry(ctx, "ReplaceNetworkAclEntry", &input.network_acl_id, true, entry, input.dry_run)
    }

    pub(crate) fn delete_network_acl_entry_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteNetworkAclEntryRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_known(
            ctx,
            "DeleteNetworkAclEntry",
            &[(arn(ctx, &account_of(ctx), &format!("network-acl/{}", input.network_acl_id)), ConditionContext::new())],
            input.dry_run,
        )?;
        Kind::NetworkAcl.check(&input.network_acl_id)?;
        self.with_region(ctx, |r| {
            let acl = r
                .network_acls
                .get_mut(&input.network_acl_id)
                .ok_or_else(|| Kind::NetworkAcl.not_found(&input.network_acl_id))?;
            let entries = acl.entries.get_or_insert_with(Vec::new);
            let pos = entries
                .iter()
                .position(|e| {
                    e.rule_number == Some(input.rule_number)
                        && e.egress == Some(input.egress)
                        && input.rule_number != 32767
                })
                .ok_or_else(|| {
                    err(
                        "InvalidNetworkAclEntry.NotFound",
                        format!("The network acl entry identified by {} does not exist.", input.rule_number),
                    )
                })?;
            entries.remove(pos);
            Ok(())
        })
    }

    pub(crate) fn replace_network_acl_association_op(
        &self,
        ctx: &RequestContext,
        input: t::ReplaceNetworkAclAssociationRequest,
    ) -> Result<t::ReplaceNetworkAclAssociationResult, ServiceError> {
        self.authorize_known(
            ctx,
            "ReplaceNetworkAclAssociation",
            &[(arn(ctx, &account_of(ctx), &format!("network-acl/{}", input.network_acl_id)), ConditionContext::new())],
            input.dry_run,
        )?;
        Kind::NetworkAcl.check(&input.network_acl_id)?;
        self.with_region(ctx, |r| {
            if !r.network_acls.contains_key(&input.network_acl_id) {
                return Err(Kind::NetworkAcl.not_found(&input.network_acl_id));
            }
            let mut subnet = None;
            for acl in r.network_acls.values_mut() {
                if let Some(assocs) = &mut acl.associations {
                    if let Some(i) = assocs
                        .iter()
                        .position(|a| a.network_acl_association_id.as_deref() == Some(input.association_id.as_str()))
                    {
                        subnet = assocs.remove(i).subnet_id;
                        break;
                    }
                }
            }
            let subnet = subnet.ok_or_else(|| {
                err(
                    "InvalidAssociationID.NotFound",
                    format!("The association ID '{}' does not exist", input.association_id),
                )
            })?;
            let id = new_id("aclassoc");
            let acl = r.network_acls.get_mut(&input.network_acl_id).expect("checked");
            acl.associations.get_or_insert_with(Vec::new).push(t::NetworkAclAssociation {
                network_acl_association_id: Some(id.clone()),
                network_acl_id: Some(input.network_acl_id.clone()),
                subnet_id: Some(subnet),
            });
            Ok(t::ReplaceNetworkAclAssociationResult { new_association_id: Some(id) })
        })
    }

    pub(crate) fn describe_network_acls_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeNetworkAclsRequest,
    ) -> Result<t::DescribeNetworkAclsResult, ServiceError> {
        self.authorize_known(ctx, "DescribeNetworkAcls", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.network_acl_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::NetworkAcl.check_all(&ids, |id| r.network_acls.contains_key(id))?;
            let mut out = Vec::new();
            for a in r.network_acls.values() {
                if !ids.is_empty() && !ids.contains(a.network_acl_id.as_ref().unwrap()) {
                    continue;
                }
                let assoc = a.associations.clone().unwrap_or_default();
                let ok = filters.matches(a.tags.as_ref(), |name| {
                    Some(match name {
                        "association.association-id" => {
                            assoc.iter().filter_map(|x| x.network_acl_association_id.clone()).collect()
                        }
                        "association.network-acl-id" => assoc.iter().filter_map(|x| x.network_acl_id.clone()).collect(),
                        "association.subnet-id" => assoc.iter().filter_map(|x| x.subnet_id.clone()).collect(),
                        "default" => b(a.is_default),
                        "network-acl-id" => s(&a.network_acl_id),
                        "owner-id" => s(&a.owner_id),
                        "vpc-id" => s(&a.vpc_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(a.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeNetworkAclsResult { network_acls: Some(items), next_token })
        })
    }

    // ---- DHCP options ---------------------------------------------------------------------------

    pub(crate) fn create_dhcp_options_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDhcpOptionsRequest,
    ) -> Result<t::CreateDhcpOptionsResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "dhcp-options", &["dhcp-options"])?;
        self.authorize_known(
            ctx,
            "CreateDhcpOptions",
            &[(arn(ctx, &account, "dhcp-options/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        const KEYS: &[&str] = &[
            "domain-name",
            "domain-name-servers",
            "ntp-servers",
            "netbios-name-servers",
            "netbios-node-type",
            "ipv6-address-preferred-lease-time",
        ];
        let mut confs = Vec::new();
        for c in &input.dhcp_configurations {
            let key = c.key.clone().unwrap_or_default();
            if !KEYS.contains(&key.as_str()) {
                return Err(invalid_parameter(format!(
                    "Value ({key}) for parameter name is invalid. Unknown DHCP option"
                )));
            }
            confs.push(t::DhcpConfiguration {
                key: Some(key),
                values: Some(c.values.iter().flatten().map(|v| t::AttributeValue { value: Some(v.clone()) }).collect()),
            });
        }
        self.with_region(ctx, |r| {
            let id = new_id("dopt");
            let d = t::DhcpOptions {
                dhcp_options_id: Some(id.clone()),
                owner_id: Some(account.clone()),
                dhcp_configurations: Some(confs),
                tags: some_tags(tags),
            };
            r.dhcp_options.insert(id, d.clone());
            Ok(t::CreateDhcpOptionsResult { dhcp_options: Some(d) })
        })
    }

    pub(crate) fn delete_dhcp_options_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDhcpOptionsRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_known(
            ctx,
            "DeleteDhcpOptions",
            &[(
                arn(ctx, &account_of(ctx), &format!("dhcp-options/{}", input.dhcp_options_id)),
                ConditionContext::new(),
            )],
            input.dry_run,
        )?;
        Kind::DhcpOptions.check(&input.dhcp_options_id)?;
        self.with_region(ctx, |r| {
            if !r.dhcp_options.contains_key(&input.dhcp_options_id) {
                return Err(Kind::DhcpOptions.not_found(&input.dhcp_options_id));
            }
            if r.vpcs.values().any(|v| v.vpc.dhcp_options_id.as_deref() == Some(input.dhcp_options_id.as_str())) {
                return Err(err(
                    "DependencyViolation",
                    format!("The dhcpOptions '{}' has dependencies and cannot be deleted.", input.dhcp_options_id),
                ));
            }
            r.dhcp_options.remove(&input.dhcp_options_id);
            Ok(())
        })
    }

    pub(crate) fn associate_dhcp_options_op(
        &self,
        ctx: &RequestContext,
        input: t::AssociateDhcpOptionsRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        Kind::Vpc.check(&input.vpc_id)?;
        self.authorize_known(
            ctx,
            "AssociateDhcpOptions",
            &[(arn(ctx, &account, &format!("vpc/{}", input.vpc_id)), ConditionContext::new())],
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            if input.dhcp_options_id != "default" && !r.dhcp_options.contains_key(&input.dhcp_options_id) {
                Kind::DhcpOptions.check(&input.dhcp_options_id)?;
                return Err(Kind::DhcpOptions.not_found(&input.dhcp_options_id));
            }
            let vpc = r.vpcs.get_mut(&input.vpc_id).ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
            vpc.vpc.dhcp_options_id = Some(input.dhcp_options_id.clone());
            Ok(())
        })
    }

    pub(crate) fn describe_dhcp_options_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDhcpOptionsRequest,
    ) -> Result<t::DescribeDhcpOptionsResult, ServiceError> {
        self.authorize_known(ctx, "DescribeDhcpOptions", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.dhcp_options_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::DhcpOptions.check_all(&ids, |id| r.dhcp_options.contains_key(id))?;
            let mut out = Vec::new();
            for d in r.dhcp_options.values() {
                if !ids.is_empty() && !ids.contains(d.dhcp_options_id.as_ref().unwrap()) {
                    continue;
                }
                let confs = d.dhcp_configurations.clone().unwrap_or_default();
                let ok = filters.matches(d.tags.as_ref(), |name| {
                    Some(match name {
                        "dhcp-options-id" => s(&d.dhcp_options_id),
                        "key" => confs.iter().filter_map(|c| c.key.clone()).collect(),
                        "value" => confs
                            .iter()
                            .flat_map(|c| c.values.iter().flatten().filter_map(|v| v.value.clone()))
                            .collect(),
                        "owner-id" => s(&d.owner_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(d.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeDhcpOptionsResult { dhcp_options: Some(items), next_token })
        })
    }
}

/// Check a route's peering, transit, egress-only or carrier gateway target.
fn check_route_target(r: &RegionState, vpc_id: &str, target: &str) -> Result<(), ServiceError> {
    let different = || err("InvalidParameterValue", "route table and network gateway belong to different networks");
    match target.rsplit_once('-').map(|(p, _)| p).unwrap_or_default() {
        "pcx" => {
            let p =
                r.vpc_peering_connections.get(target).ok_or_else(|| Kind::VpcPeeringConnection.not_found(target))?;
            let active = p.status.as_ref().and_then(|s| s.code.as_deref()) == Some("active");
            let ours = [&p.requester_vpc_info, &p.accepter_vpc_info]
                .iter()
                .any(|i| i.as_ref().and_then(|i| i.vpc_id.as_deref()) == Some(vpc_id));
            if !active {
                return Err(err(
                    "InvalidVpcPeeringConnectionID.NotFound",
                    format!("The vpcPeeringConnection ID '{target}' does not exist"),
                ));
            }
            if !ours {
                return Err(different());
            }
        }
        "tgw" => {
            if !r.transit_gateways.get(target).is_some_and(|g| g.state.as_deref() == Some("available")) {
                return Err(Kind::TransitGateway.not_found(target));
            }
            if !crate::state::State::tgw_attached_to(r, target, vpc_id) {
                return Err(err(
                    "InvalidTransitGatewayID.NotFound",
                    format!("The transit gateway ID '{target}' does not exist or is not attached to {vpc_id}."),
                ));
            }
        }
        "eigw" => {
            let g = r
                .egress_only_internet_gateways
                .get(target)
                .ok_or_else(|| Kind::EgressOnlyInternetGateway.not_found(target))?;
            if !g.attachments.iter().flatten().any(|a| a.vpc_id.as_deref() == Some(vpc_id)) {
                return Err(different());
            }
        }
        "cagw" => {
            let g = r.carrier_gateways.get(target).ok_or_else(|| Kind::CarrierGateway.not_found(target))?;
            if g.vpc_id.as_deref() != Some(vpc_id) {
                return Err(different());
            }
        }
        _ => {}
    }
    Ok(())
}
