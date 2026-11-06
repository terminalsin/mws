//! Egress-only internet gateways, carrier gateways, customer gateways,
//! virtual private gateways and Site-to-Site VPN connections.
//!
//! These are control-plane resources: no IPsec tunnel comes up and no
//! traffic flows through them, but their lifecycle, validation and the way
//! route tables refer to them follow EC2.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::types as t;
use crate::state::RegionState;
use crate::util::{
    arn, authorize, err, invalid_parameter, missing_parameter, new_id, new_public_ip, paginate, request_tag_context,
    resource_tag_context, s, some_tags, tags_for, Cidr, Filters, Kind,
};
use crate::{account_of, Ec2};

/// Resources kept visible after deletion disappear after an hour.
pub fn expire_deleted(r: &mut RegionState, now: DateTime<Utc>) {
    let expired: Vec<String> = r
        .deleted_at
        .iter()
        .filter(|(_, t)| now - **t >= chrono::Duration::hours(1))
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        r.deleted_at.remove(&id);
        r.customer_gateways.remove(&id);
        r.vpn_gateways.remove(&id);
        r.vpn_connections.remove(&id);
        r.vpc_peering_connections.remove(&id);
        r.transit_gateways.remove(&id);
        r.transit_gateway_attachments.remove(&id);
        r.transit_gateway_route_tables.remove(&id);
    }
}

/// Authorize `action` on one existing resource of `kind`, whose tags
/// `tags` looks up (`None` when it does not exist).
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_on(
    ec2: &Ec2,
    ctx: &RequestContext,
    action: &str,
    kind: Kind,
    resource_type: &str,
    id: &str,
    tags: impl FnOnce(&RegionState) -> Option<Option<Vec<t::Tag>>>,
    dry_run: Option<bool>,
) -> Result<(), ServiceError> {
    kind.check(id)?;
    let found = ec2.with_region(ctx, |r| tags(r));
    let tags = found.ok_or_else(|| kind.not_found(id))?;
    let account = account_of(ctx);
    authorize(
        ctx,
        action,
        &[(arn(ctx, &account, &format!("{resource_type}/{id}")), resource_tag_context(tags.as_ref()))],
        dry_run,
    )
}

/// Authorize a create call on `resource_type/*` with its request tags.
pub(crate) fn authorize_create(
    ctx: &RequestContext,
    action: &str,
    resource_type: &str,
    tags: &[t::Tag],
    extra: &[String],
    dry_run: Option<bool>,
) -> Result<(), ServiceError> {
    let account = account_of(ctx);
    let mut resources = vec![(arn(ctx, &account, &format!("{resource_type}/*")), request_tag_context(tags))];
    for r in extra {
        resources.push((r.clone(), ConditionContext::new()));
    }
    authorize(ctx, action, &resources, dry_run)
}

fn vpc_arn(ctx: &RequestContext, vpc: &str) -> String {
    arn(ctx, &account_of(ctx), &format!("vpc/{vpc}"))
}

fn random_key() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
    let mut rng = rand::thread_rng();
    (0..32).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

/// A free `169.254.x.y/30` for a tunnel's inside addresses.
fn inside_cidr() -> String {
    let mut rng = rand::thread_rng();
    format!("169.254.{}.{}/30", rng.gen_range(10..250), rng.gen_range(0..64) * 4)
}

fn check_inside_cidr(c: &str) -> Result<(), ServiceError> {
    let ok = Cidr::parse(c).is_some_and(|x| x.prefix == 30 && x.is_network() && c.starts_with("169.254."));
    let reserved = [
        "169.254.0.0/30",
        "169.254.1.0/30",
        "169.254.2.0/30",
        "169.254.3.0/30",
        "169.254.4.0/30",
        "169.254.5.0/30",
        "169.254.169.252/30",
    ];
    if !ok || reserved.contains(&c) {
        return Err(invalid_parameter(format!(
            "The tunnel inside CIDR {c} is invalid. Specify a size /30 CIDR block from the 169.254.0.0/16 range, outside the reserved blocks."
        )));
    }
    Ok(())
}

impl Ec2 {
    // ---- egress-only internet gateways ------------------------------------------------------------

    pub(crate) fn create_egress_only_internet_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateEgressOnlyInternetGatewayRequest,
    ) -> Result<t::CreateEgressOnlyInternetGatewayResult, ServiceError> {
        let tags =
            tags_for(&input.tag_specifications, "egress-only-internet-gateway", &["egress-only-internet-gateway"])?;
        Kind::Vpc.check(&input.vpc_id)?;
        authorize_create(
            ctx,
            "CreateEgressOnlyInternetGateway",
            "egress-only-internet-gateway",
            &tags,
            &[vpc_arn(ctx, &input.vpc_id)],
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            if !r.vpcs.contains_key(&input.vpc_id) {
                return Err(Kind::Vpc.not_found(&input.vpc_id));
            }
            let id = new_id("eigw");
            let g = t::EgressOnlyInternetGateway {
                egress_only_internet_gateway_id: Some(id.clone()),
                attachments: Some(vec![t::InternetGatewayAttachment {
                    state: Some("attached".into()),
                    vpc_id: Some(input.vpc_id.clone()),
                }]),
                tags: some_tags(tags),
            };
            r.egress_only_internet_gateways.insert(id, g.clone());
            Ok(t::CreateEgressOnlyInternetGatewayResult {
                client_token: input.client_token.clone(),
                egress_only_internet_gateway: Some(g),
            })
        })
    }

    pub(crate) fn delete_egress_only_internet_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteEgressOnlyInternetGatewayRequest,
    ) -> Result<t::DeleteEgressOnlyInternetGatewayResult, ServiceError> {
        let id = input.egress_only_internet_gateway_id.clone();
        authorize_on(
            self,
            ctx,
            "DeleteEgressOnlyInternetGateway",
            Kind::EgressOnlyInternetGateway,
            "egress-only-internet-gateway",
            &id,
            |r| r.egress_only_internet_gateways.get(&id).map(|g| g.tags.clone()),
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            r.egress_only_internet_gateways.remove(&id);
            blackhole_routes(r, |route| route.egress_only_internet_gateway_id.as_deref() == Some(id.as_str()));
            Ok(t::DeleteEgressOnlyInternetGatewayResult { return_code: Some(true) })
        })
    }

    pub(crate) fn describe_egress_only_internet_gateways_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeEgressOnlyInternetGatewaysRequest,
    ) -> Result<t::DescribeEgressOnlyInternetGatewaysResult, ServiceError> {
        authorize(ctx, "DescribeEgressOnlyInternetGateways", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.egress_only_internet_gateway_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::EgressOnlyInternetGateway.check_all(&ids, |id| r.egress_only_internet_gateways.contains_key(id))?;
            let mut out = Vec::new();
            for g in r.egress_only_internet_gateways.values() {
                let id = g.egress_only_internet_gateway_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let atts = g.attachments.clone().unwrap_or_default();
                let ok = filters.matches(g.tags.as_ref(), |name| {
                    Some(match name {
                        "egress-only-internet-gateway-id" => vec![id.clone()],
                        "attachment.state" => atts.iter().filter_map(|a| a.state.clone()).collect(),
                        "attachment.vpc-id" => atts.iter().filter_map(|a| a.vpc_id.clone()).collect(),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(g.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeEgressOnlyInternetGatewaysResult { egress_only_internet_gateways: Some(items), next_token })
        })
    }

    // ---- carrier gateways -------------------------------------------------------------------------

    pub(crate) fn create_carrier_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateCarrierGatewayRequest,
    ) -> Result<t::CreateCarrierGatewayResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "carrier-gateway", &["carrier-gateway"])?;
        Kind::Vpc.check(&input.vpc_id)?;
        authorize_create(
            ctx,
            "CreateCarrierGateway",
            "carrier-gateway",
            &tags,
            &[vpc_arn(ctx, &input.vpc_id)],
            input.dry_run,
        )?;
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            if !r.vpcs.contains_key(&input.vpc_id) {
                return Err(Kind::Vpc.not_found(&input.vpc_id));
            }
            if r.carrier_gateways
                .values()
                .any(|g| g.vpc_id.as_deref() == Some(input.vpc_id.as_str()) && g.state.as_deref() != Some("deleted"))
            {
                return Err(err(
                    "CarrierGatewayLimitExceeded",
                    format!("VPC {} already has a carrier gateway.", input.vpc_id),
                ));
            }
            let id = new_id("cagw");
            let g = t::CarrierGateway {
                carrier_gateway_id: Some(id.clone()),
                vpc_id: Some(input.vpc_id.clone()),
                state: Some("available".into()),
                owner_id: Some(account.clone()),
                tags: some_tags(tags),
            };
            r.carrier_gateways.insert(id, g.clone());
            Ok(t::CreateCarrierGatewayResult { carrier_gateway: Some(g) })
        })
    }

    pub(crate) fn delete_carrier_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteCarrierGatewayRequest,
    ) -> Result<t::DeleteCarrierGatewayResult, ServiceError> {
        let id = input.carrier_gateway_id.clone();
        authorize_on(
            self,
            ctx,
            "DeleteCarrierGateway",
            Kind::CarrierGateway,
            "carrier-gateway",
            &id,
            |r| r.carrier_gateways.get(&id).map(|g| g.tags.clone()),
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let mut g = r.carrier_gateways.remove(&id).ok_or_else(|| Kind::CarrierGateway.not_found(&id))?;
            g.state = Some("deleting".into());
            blackhole_routes(r, |route| route.carrier_gateway_id.as_deref() == Some(id.as_str()));
            Ok(t::DeleteCarrierGatewayResult { carrier_gateway: Some(g) })
        })
    }

    pub(crate) fn describe_carrier_gateways_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeCarrierGatewaysRequest,
    ) -> Result<t::DescribeCarrierGatewaysResult, ServiceError> {
        authorize(ctx, "DescribeCarrierGateways", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.carrier_gateway_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::CarrierGateway.check_all(&ids, |id| r.carrier_gateways.contains_key(id))?;
            let mut out = Vec::new();
            for g in r.carrier_gateways.values() {
                let id = g.carrier_gateway_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let ok = filters.matches(g.tags.as_ref(), |name| {
                    Some(match name {
                        "carrier-gateway-id" => vec![id.clone()],
                        "state" => s(&g.state),
                        "owner-id" => s(&g.owner_id),
                        "vpc-id" => s(&g.vpc_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(g.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeCarrierGatewaysResult { carrier_gateways: Some(items), next_token })
        })
    }

    // ---- customer gateways ------------------------------------------------------------------------

    pub(crate) fn create_customer_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateCustomerGatewayRequest,
    ) -> Result<t::CreateCustomerGatewayResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "customer-gateway", &["customer-gateway"])?;
        if input.r#type != "ipsec.1" {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter type is invalid. Valid value is ipsec.1",
                input.r#type
            )));
        }
        let ip = input.ip_address.clone().or_else(|| input.public_ip.clone());
        if ip.is_none() && input.certificate_arn.is_none() {
            return Err(missing_parameter("IpAddress"));
        }
        if let Some(ip) = &ip {
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(invalid_parameter(format!("Value ({ip}) for parameter ipAddress is invalid.")));
            }
        }
        if input.bgp_asn.is_some() && input.bgp_asn_extended.is_some() {
            return Err(err("InvalidParameterCombination", "Only one of BgpAsn or BgpAsnExtended may be specified."));
        }
        let asn = match (input.bgp_asn, input.bgp_asn_extended) {
            (Some(a), _) => i64::from(a),
            (None, Some(a)) => {
                if !(2_147_483_648..=4_294_967_295).contains(&a) {
                    return Err(invalid_parameter(format!(
                        "Value ({a}) for parameter BgpAsnExtended is invalid. It must be between 2147483648 and 4294967295."
                    )));
                }
                a
            }
            (None, None) => 65000,
        };
        if !(1..=4_294_967_295).contains(&asn) {
            return Err(invalid_parameter(format!("Value ({asn}) for parameter bgpAsn is invalid.")));
        }
        authorize_create(ctx, "CreateCustomerGateway", "customer-gateway", &tags, &[], input.dry_run)?;
        self.with_region(ctx, |r| {
            // The same address, ASN and type answer the existing gateway.
            if let Some(existing) = r.customer_gateways.values().find(|g| {
                g.state.as_deref() == Some("available")
                    && g.ip_address == ip
                    && g.bgp_asn.as_deref() == Some(asn.to_string().as_str())
                    && g.certificate_arn == input.certificate_arn
            }) {
                return Ok(t::CreateCustomerGatewayResult { customer_gateway: Some(existing.clone()) });
            }
            let id = new_id("cgw");
            let g = t::CustomerGateway {
                customer_gateway_id: Some(id.clone()),
                bgp_asn: Some(asn.to_string()),
                bgp_asn_extended: input.bgp_asn_extended.map(|a| a.to_string()),
                ip_address: ip.clone(),
                certificate_arn: input.certificate_arn.clone(),
                device_name: input.device_name.clone(),
                state: Some("available".into()),
                r#type: Some("ipsec.1".into()),
                tags: some_tags(tags),
            };
            r.customer_gateways.insert(id, g.clone());
            Ok(t::CreateCustomerGatewayResult { customer_gateway: Some(g) })
        })
    }

    pub(crate) fn delete_customer_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteCustomerGatewayRequest,
    ) -> Result<(), ServiceError> {
        let id = input.customer_gateway_id.clone();
        authorize_on(
            self,
            ctx,
            "DeleteCustomerGateway",
            Kind::CustomerGateway,
            "customer-gateway",
            &id,
            |r| r.customer_gateways.get(&id).map(|g| g.tags.clone()),
            input.dry_run,
        )?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let in_use = r.vpn_connections.values().any(|v| {
                v.customer_gateway_id.as_deref() == Some(id.as_str()) && v.state.as_deref() != Some("deleted")
            });
            if in_use {
                return Err(err(
                    "IncorrectState",
                    format!("The customer gateway '{id}' is in use by one or more VPN connections."),
                ));
            }
            let g = r.customer_gateways.get_mut(&id).ok_or_else(|| Kind::CustomerGateway.not_found(&id))?;
            if g.state.as_deref() != Some("deleted") {
                g.state = Some("deleted".into());
                r.deleted_at.insert(id.clone(), now);
            }
            Ok(())
        })
    }

    pub(crate) fn describe_customer_gateways_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeCustomerGatewaysRequest,
    ) -> Result<t::DescribeCustomerGatewaysResult, ServiceError> {
        authorize(ctx, "DescribeCustomerGateways", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.customer_gateway_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::CustomerGateway.check_all(&ids, |id| r.customer_gateways.contains_key(id))?;
            let mut out = Vec::new();
            for g in r.customer_gateways.values() {
                let id = g.customer_gateway_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let ok = filters.matches(g.tags.as_ref(), |name| {
                    Some(match name {
                        "bgp-asn" => s(&g.bgp_asn),
                        "customer-gateway-id" => vec![id.clone()],
                        "ip-address" => s(&g.ip_address),
                        "state" => s(&g.state),
                        "type" => s(&g.r#type),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(g.clone());
                }
            }
            Ok(t::DescribeCustomerGatewaysResult { customer_gateways: Some(out) })
        })
    }

    // ---- virtual private gateways -----------------------------------------------------------------

    pub(crate) fn create_vpn_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateVpnGatewayRequest,
    ) -> Result<t::CreateVpnGatewayResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "vpn-gateway", &["vpn-gateway"])?;
        if input.r#type != "ipsec.1" {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter type is invalid. Valid value is ipsec.1",
                input.r#type
            )));
        }
        let asn = input.amazon_side_asn.unwrap_or(64512);
        let private16 = (64512..=65534).contains(&asn);
        let private32 = (4_200_000_000..=4_294_967_294).contains(&asn);
        if input.amazon_side_asn.is_some() && !private16 && !private32 && asn != 7224 && asn != 9059 {
            return Err(invalid_parameter(format!(
                "Invalid ASN {asn}. Valid ASNs are 64512 to 65534 and 4200000000 to 4294967294."
            )));
        }
        authorize_create(ctx, "CreateVpnGateway", "vpn-gateway", &tags, &[], input.dry_run)?;
        self.with_region(ctx, |r| {
            let id = new_id("vgw");
            let g = t::VpnGateway {
                vpn_gateway_id: Some(id.clone()),
                state: Some("available".into()),
                r#type: Some("ipsec.1".into()),
                availability_zone: input.availability_zone.clone(),
                amazon_side_asn: Some(asn),
                vpc_attachments: Some(Vec::new()),
                tags: some_tags(tags),
            };
            r.vpn_gateways.insert(id, g.clone());
            Ok(t::CreateVpnGatewayResult { vpn_gateway: Some(g) })
        })
    }

    fn vgw_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        authorize_on(
            self,
            ctx,
            action,
            Kind::VpnGateway,
            "vpn-gateway",
            id,
            |r| r.vpn_gateways.get(id).filter(|g| g.state.as_deref() != Some("deleted")).map(|g| g.tags.clone()),
            dry_run,
        )
    }

    pub(crate) fn delete_vpn_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteVpnGatewayRequest,
    ) -> Result<(), ServiceError> {
        let id = input.vpn_gateway_id.clone();
        self.vgw_authorize(ctx, "DeleteVpnGateway", &id, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let g = r.vpn_gateways.get(&id).ok_or_else(|| Kind::VpnGateway.not_found(&id))?;
            if g.vpc_attachments.iter().flatten().any(|a| a.state.as_deref() == Some("attached")) {
                return Err(err(
                    "IncorrectState",
                    format!(
                        "The vpnGateway '{id}' is in an incorrect state for this operation: it is attached to a VPC"
                    ),
                ));
            }
            if r.vpn_connections
                .values()
                .any(|v| v.vpn_gateway_id.as_deref() == Some(id.as_str()) && v.state.as_deref() != Some("deleted"))
            {
                return Err(err(
                    "IncorrectState",
                    format!("The vpnGateway '{id}' is in use by one or more VPN connections."),
                ));
            }
            let g = r.vpn_gateways.get_mut(&id).expect("checked");
            g.state = Some("deleted".into());
            r.deleted_at.insert(id.clone(), now);
            Ok(())
        })
    }

    pub(crate) fn describe_vpn_gateways_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpnGatewaysRequest,
    ) -> Result<t::DescribeVpnGatewaysResult, ServiceError> {
        authorize(ctx, "DescribeVpnGateways", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.vpn_gateway_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::VpnGateway.check_all(&ids, |id| r.vpn_gateways.contains_key(id))?;
            let mut out = Vec::new();
            for g in r.vpn_gateways.values() {
                let id = g.vpn_gateway_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let atts = g.vpc_attachments.clone().unwrap_or_default();
                let ok = filters.matches(g.tags.as_ref(), |name| {
                    Some(match name {
                        "amazon-side-asn" => g.amazon_side_asn.map(|a| a.to_string()).into_iter().collect(),
                        "attachment.state" => atts.iter().filter_map(|a| a.state.clone()).collect(),
                        "attachment.vpc-id" => atts.iter().filter_map(|a| a.vpc_id.clone()).collect(),
                        "availability-zone" => s(&g.availability_zone),
                        "state" => s(&g.state),
                        "type" => s(&g.r#type),
                        "vpn-gateway-id" => vec![id.clone()],
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(g.clone());
                }
            }
            Ok(t::DescribeVpnGatewaysResult { vpn_gateways: Some(out) })
        })
    }

    pub(crate) fn attach_vpn_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::AttachVpnGatewayRequest,
    ) -> Result<t::AttachVpnGatewayResult, ServiceError> {
        let id = input.vpn_gateway_id.clone();
        self.vgw_authorize(ctx, "AttachVpnGateway", &id, input.dry_run)?;
        Kind::Vpc.check(&input.vpc_id)?;
        self.with_region(ctx, |r| {
            if !r.vpcs.contains_key(&input.vpc_id) {
                return Err(Kind::Vpc.not_found(&input.vpc_id));
            }
            let vpc_taken = r.vpn_gateways.values().any(|g| {
                g.vpn_gateway_id.as_deref() != Some(id.as_str())
                    && g.vpc_attachments.iter().flatten().any(|a| {
                        a.vpc_id.as_deref() == Some(input.vpc_id.as_str()) && a.state.as_deref() == Some("attached")
                    })
            });
            if vpc_taken {
                return Err(err(
                    "VpnGatewayAttachmentLimitExceeded",
                    format!("VPC {} already has a virtual private gateway attached.", input.vpc_id),
                ));
            }
            let g = r.vpn_gateways.get_mut(&id).ok_or_else(|| Kind::VpnGateway.not_found(&id))?;
            if let Some(a) = g.vpc_attachments.iter().flatten().find(|a| a.state.as_deref() == Some("attached")) {
                if a.vpc_id.as_deref() != Some(input.vpc_id.as_str()) {
                    return Err(err(
                        "VpnGatewayAttachmentLimitExceeded",
                        format!(
                            "The vpnGateway '{id}' is already attached to {}",
                            a.vpc_id.clone().unwrap_or_default()
                        ),
                    ));
                }
            }
            let att = t::VpcAttachment { vpc_id: Some(input.vpc_id.clone()), state: Some("attached".into()) };
            g.vpc_attachments = Some(vec![att.clone()]);
            // Routes left as blackholes by a detach work again.
            for rt in r.route_tables.values_mut() {
                if rt.vpc_id.as_deref() != Some(input.vpc_id.as_str()) {
                    continue;
                }
                for route in rt.routes.iter_mut().flatten() {
                    if route.gateway_id.as_deref() == Some(id.as_str()) {
                        route.state = Some("active".into());
                    }
                }
            }
            Ok(t::AttachVpnGatewayResult { vpc_attachment: Some(att) })
        })
    }

    pub(crate) fn detach_vpn_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachVpnGatewayRequest,
    ) -> Result<(), ServiceError> {
        let id = input.vpn_gateway_id.clone();
        self.vgw_authorize(ctx, "DetachVpnGateway", &id, input.dry_run)?;
        Kind::Vpc.check(&input.vpc_id)?;
        self.with_region(ctx, |r| {
            let g = r.vpn_gateways.get_mut(&id).ok_or_else(|| Kind::VpnGateway.not_found(&id))?;
            let att = g
                .vpc_attachments
                .iter_mut()
                .flatten()
                .find(|a| a.vpc_id.as_deref() == Some(input.vpc_id.as_str()) && a.state.as_deref() == Some("attached"))
                .ok_or_else(|| {
                    err(
                        "InvalidVpnGatewayAttachment.NotFound",
                        format!(
                            "The attachment with vpn gateway ID '{id}' and vpc ID '{}' does not exist",
                            input.vpc_id
                        ),
                    )
                })?;
            att.state = Some("detached".into());
            for rt in r.route_tables.values_mut() {
                if rt.vpc_id.as_deref() != Some(input.vpc_id.as_str()) {
                    continue;
                }
                for route in rt.routes.iter_mut().flatten() {
                    if route.gateway_id.as_deref() == Some(id.as_str()) {
                        route.state = Some("blackhole".into());
                    }
                }
                if let Some(p) = rt.propagating_vgws.as_mut() {
                    p.retain(|v| v.gateway_id.as_deref() != Some(id.as_str()));
                }
            }
            Ok(())
        })
    }

    pub(crate) fn enable_vgw_route_propagation_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableVgwRoutePropagationRequest,
    ) -> Result<(), ServiceError> {
        self.rtb_authorize(ctx, "EnableVgwRoutePropagation", &input.route_table_id, input.dry_run)?;
        Kind::VpnGateway.check(&input.gateway_id)?;
        self.with_region(ctx, |r| {
            let g = r
                .vpn_gateways
                .get(&input.gateway_id)
                .filter(|g| g.state.as_deref() != Some("deleted"))
                .ok_or_else(|| Kind::VpnGateway.not_found(&input.gateway_id))?;
            let rt = r
                .route_tables
                .get(&input.route_table_id)
                .ok_or_else(|| Kind::RouteTable.not_found(&input.route_table_id))?;
            let attached = g
                .vpc_attachments
                .iter()
                .flatten()
                .any(|a| a.state.as_deref() == Some("attached") && a.vpc_id.is_some() && a.vpc_id == rt.vpc_id);
            if !attached {
                return Err(err(
                    "Gateway.NotAttached",
                    format!(
                        "resource {} is not attached to network {}",
                        input.gateway_id,
                        rt.vpc_id.clone().unwrap_or_default()
                    ),
                ));
            }
            let rt = r.route_tables.get_mut(&input.route_table_id).expect("checked");
            let p = rt.propagating_vgws.get_or_insert_with(Vec::new);
            if !p.iter().any(|v| v.gateway_id.as_deref() == Some(input.gateway_id.as_str())) {
                p.push(t::PropagatingVgw { gateway_id: Some(input.gateway_id.clone()) });
            }
            Ok(())
        })
    }

    pub(crate) fn disable_vgw_route_propagation_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableVgwRoutePropagationRequest,
    ) -> Result<(), ServiceError> {
        self.rtb_authorize(ctx, "DisableVgwRoutePropagation", &input.route_table_id, input.dry_run)?;
        Kind::VpnGateway.check(&input.gateway_id)?;
        self.with_region(ctx, |r| {
            if !r.vpn_gateways.contains_key(&input.gateway_id) {
                return Err(Kind::VpnGateway.not_found(&input.gateway_id));
            }
            let rt = r
                .route_tables
                .get_mut(&input.route_table_id)
                .ok_or_else(|| Kind::RouteTable.not_found(&input.route_table_id))?;
            if let Some(p) = rt.propagating_vgws.as_mut() {
                p.retain(|v| v.gateway_id.as_deref() != Some(input.gateway_id.as_str()));
            }
            Ok(())
        })
    }

    // ---- VPN connections --------------------------------------------------------------------------

    pub(crate) fn create_vpn_connection_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateVpnConnectionRequest,
    ) -> Result<t::CreateVpnConnectionResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "vpn-connection", &["vpn-connection"])?;
        if input.r#type != "ipsec.1" {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter type is invalid. Valid value is ipsec.1",
                input.r#type
            )));
        }
        Kind::CustomerGateway.check(&input.customer_gateway_id)?;
        let targets = [&input.vpn_gateway_id, &input.transit_gateway_id].iter().filter(|v| v.is_some()).count();
        if targets == 0 {
            return Err(missing_parameter("VpnGatewayId or TransitGatewayId"));
        }
        if targets > 1 {
            return Err(err(
                "InvalidParameterCombination",
                "The parameters VpnGatewayId and TransitGatewayId are mutually exclusive.",
            ));
        }
        if let Some(v) = &input.vpn_gateway_id {
            Kind::VpnGateway.check(v)?;
        }
        if let Some(v) = &input.transit_gateway_id {
            Kind::TransitGateway.check(v)?;
        }
        let opts = input.options.clone().unwrap_or_default();
        let tunnels = opts.tunnel_options.clone().unwrap_or_default();
        if tunnels.len() > 2 {
            return Err(invalid_parameter(
                "A VPN connection has two tunnels; at most two tunnel options may be given.",
            ));
        }
        for tun in &tunnels {
            if let Some(c) = &tun.tunnel_inside_cidr {
                check_inside_cidr(c)?;
            }
            if let Some(k) = &tun.pre_shared_key {
                let ok = (8..=64).contains(&k.len())
                    && !k.starts_with('0')
                    && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_');
                if !ok {
                    return Err(invalid_parameter(
                        "The pre-shared key must be 8 to 64 characters of letters, numbers, periods and underscores, and cannot start with zero.",
                    ));
                }
            }
        }
        authorize_create(ctx, "CreateVpnConnection", "vpn-connection", &tags, &[], input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            r.customer_gateways
                .get(&input.customer_gateway_id)
                .filter(|g| g.state.as_deref() == Some("available"))
                .ok_or_else(|| Kind::CustomerGateway.not_found(&input.customer_gateway_id))?;
            if let Some(v) = &input.vpn_gateway_id {
                r.vpn_gateways
                    .get(v)
                    .filter(|g| g.state.as_deref() == Some("available"))
                    .ok_or_else(|| Kind::VpnGateway.not_found(v))?;
            }
            if let Some(v) = &input.transit_gateway_id {
                r.transit_gateways
                    .get(v)
                    .filter(|g| g.state.as_deref() == Some("available"))
                    .ok_or_else(|| Kind::TransitGateway.not_found(v))?;
            }
            let id = new_id("vpn");
            let tunnel_opts: Vec<t::TunnelOption> = (0..2)
                .map(|i| {
                    let spec = tunnels.get(i).cloned().unwrap_or_default();
                    t::TunnelOption {
                        outside_ip_address: Some(new_public_ip()),
                        tunnel_inside_cidr: Some(spec.tunnel_inside_cidr.clone().unwrap_or_else(inside_cidr)),
                        pre_shared_key: Some(spec.pre_shared_key.clone().unwrap_or_else(random_key)),
                        log_options: Some(t::VpnTunnelLogOptions {
                            cloud_watch_log_options: Some(t::CloudWatchLogOptions {
                                log_enabled: Some(false),
                                bgp_log_enabled: Some(false),
                                ..Default::default()
                            }),
                        }),
                        ..Default::default()
                    }
                })
                .collect();
            let telemetry = tunnel_opts
                .iter()
                .map(|tun| t::VgwTelemetry {
                    accepted_route_count: Some(0),
                    last_status_change: Some(now),
                    outside_ip_address: tun.outside_ip_address.clone(),
                    status: Some("DOWN".into()),
                    status_message: Some(String::new()),
                    certificate_arn: None,
                })
                .collect();
            let cgw = r.customer_gateways.get(&input.customer_gateway_id).cloned().unwrap_or_default();
            let mut vpn = t::VpnConnection {
                vpn_connection_id: Some(id.clone()),
                customer_gateway_id: Some(input.customer_gateway_id.clone()),
                vpn_gateway_id: input.vpn_gateway_id.clone(),
                transit_gateway_id: input.transit_gateway_id.clone(),
                category: Some("VPN".into()),
                state: Some("available".into()),
                r#type: Some("ipsec.1".into()),
                options: Some(t::VpnConnectionOptions {
                    enable_acceleration: Some(opts.enable_acceleration.unwrap_or(false)),
                    static_routes_only: Some(opts.static_routes_only.unwrap_or(false)),
                    local_ipv4_network_cidr: Some(
                        opts.local_ipv4_network_cidr.clone().unwrap_or_else(|| "0.0.0.0/0".into()),
                    ),
                    remote_ipv4_network_cidr: Some(
                        opts.remote_ipv4_network_cidr.clone().unwrap_or_else(|| "0.0.0.0/0".into()),
                    ),
                    outside_ip_address_type: Some(
                        opts.outside_ip_address_type.clone().unwrap_or_else(|| "PublicIpv4".into()),
                    ),
                    tunnel_inside_ip_version: Some(
                        opts.tunnel_inside_ip_version.clone().unwrap_or_else(|| "ipv4".into()),
                    ),
                    tunnel_options: Some(tunnel_opts.clone()),
                    ..Default::default()
                }),
                routes: Some(Vec::new()),
                vgw_telemetry: Some(telemetry),
                tags: some_tags(tags),
                ..Default::default()
            };
            vpn.customer_gateway_configuration = Some(customer_gateway_configuration(&vpn, &cgw, &tunnel_opts));
            r.vpn_connections.insert(id.clone(), vpn.clone());
            if let Some(tgw) = &input.transit_gateway_id {
                crate::ops::tgw::attach_vpn(r, tgw, &id, now);
            }
            Ok(t::CreateVpnConnectionResult { vpn_connection: Some(vpn) })
        })
    }

    fn vpn_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        authorize_on(
            self,
            ctx,
            action,
            Kind::VpnConnection,
            "vpn-connection",
            id,
            |r| r.vpn_connections.get(id).filter(|v| v.state.as_deref() != Some("deleted")).map(|v| v.tags.clone()),
            dry_run,
        )
    }

    pub(crate) fn delete_vpn_connection_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteVpnConnectionRequest,
    ) -> Result<(), ServiceError> {
        let id = input.vpn_connection_id.clone();
        self.vpn_authorize(ctx, "DeleteVpnConnection", &id, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let v = r.vpn_connections.get_mut(&id).ok_or_else(|| Kind::VpnConnection.not_found(&id))?;
            v.state = Some("deleted".into());
            for route in v.routes.iter_mut().flatten() {
                route.state = Some("deleted".into());
            }
            r.deleted_at.insert(id.clone(), now);
            crate::ops::tgw::detach_vpn(r, &id, now);
            Ok(())
        })
    }

    pub(crate) fn describe_vpn_connections_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpnConnectionsRequest,
    ) -> Result<t::DescribeVpnConnectionsResult, ServiceError> {
        authorize(ctx, "DescribeVpnConnections", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.vpn_connection_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::VpnConnection.check_all(&ids, |id| r.vpn_connections.contains_key(id))?;
            let mut out = Vec::new();
            for v in r.vpn_connections.values() {
                let id = v.vpn_connection_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let routes = v.routes.clone().unwrap_or_default();
                let cgw = v.customer_gateway_id.as_ref().and_then(|c| r.customer_gateways.get(c));
                let ok = filters.matches(v.tags.as_ref(), |name| {
                    Some(match name {
                        "customer-gateway-configuration" => s(&v.customer_gateway_configuration),
                        "customer-gateway-id" => s(&v.customer_gateway_id),
                        "state" => s(&v.state),
                        "option.static-routes-only" => v
                            .options
                            .as_ref()
                            .and_then(|o| o.static_routes_only)
                            .map(|b| b.to_string())
                            .into_iter()
                            .collect(),
                        "route.destination-cidr-block" => {
                            routes.iter().filter_map(|r| r.destination_cidr_block.clone()).collect()
                        }
                        "bgp-asn" => cgw.and_then(|c| c.bgp_asn.clone()).into_iter().collect(),
                        "type" => s(&v.r#type),
                        "vpn-connection-id" => vec![id.clone()],
                        "vpn-gateway-id" => s(&v.vpn_gateway_id),
                        "transit-gateway-id" => s(&v.transit_gateway_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(v.clone());
                }
            }
            Ok(t::DescribeVpnConnectionsResult { vpn_connections: Some(out) })
        })
    }

    pub(crate) fn create_vpn_connection_route_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateVpnConnectionRouteRequest,
    ) -> Result<(), ServiceError> {
        let id = input.vpn_connection_id.clone();
        self.vpn_authorize(ctx, "CreateVpnConnectionRoute", &id, None)?;
        let cidr = input.destination_cidr_block.clone();
        if Cidr::parse(&cidr).is_none() {
            return Err(invalid_parameter(format!(
                "Value ({cidr}) for parameter destinationCidrBlock is invalid. This is not a valid CIDR block."
            )));
        }
        self.with_region(ctx, |r| {
            let v = r.vpn_connections.get_mut(&id).ok_or_else(|| Kind::VpnConnection.not_found(&id))?;
            if v.options.as_ref().and_then(|o| o.static_routes_only) != Some(true) {
                return Err(err(
                    "InvalidVpnConnection.InvalidType",
                    format!("The VPN connection {id} is not configured for static routes."),
                ));
            }
            let routes = v.routes.get_or_insert_with(Vec::new);
            if routes.iter().any(|x| x.destination_cidr_block.as_deref() == Some(cidr.as_str())) {
                return Err(err("RouteAlreadyExists", format!("The route identified by {cidr} already exists.")));
            }
            routes.push(t::VpnStaticRoute {
                destination_cidr_block: Some(cidr.clone()),
                source: Some("Static".into()),
                state: Some("available".into()),
            });
            Ok(())
        })
    }

    pub(crate) fn delete_vpn_connection_route_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteVpnConnectionRouteRequest,
    ) -> Result<(), ServiceError> {
        let id = input.vpn_connection_id.clone();
        self.vpn_authorize(ctx, "DeleteVpnConnectionRoute", &id, None)?;
        let cidr = input.destination_cidr_block.clone();
        self.with_region(ctx, |r| {
            let v = r.vpn_connections.get_mut(&id).ok_or_else(|| Kind::VpnConnection.not_found(&id))?;
            let routes = v.routes.get_or_insert_with(Vec::new);
            let before = routes.len();
            routes.retain(|x| x.destination_cidr_block.as_deref() != Some(cidr.as_str()));
            if routes.len() == before {
                return Err(err(
                    "InvalidRoute.NotFound",
                    format!("The route identified by {cidr} does not exist for VPN connection {id}"),
                ));
            }
            Ok(())
        })
    }
}

/// Mark routes through a removed target as blackholes.
pub(crate) fn blackhole_routes(r: &mut RegionState, through: impl Fn(&t::Route) -> bool) {
    for rt in r.route_tables.values_mut() {
        for route in rt.routes.iter_mut().flatten() {
            if through(route) {
                route.state = Some("blackhole".into());
            }
        }
    }
}

/// The customer gateway configuration EC2 returns: the generic
/// `vpn_connection` XML with each tunnel's addresses and keys.
fn customer_gateway_configuration(
    vpn: &t::VpnConnection,
    cgw: &t::CustomerGateway,
    tunnels: &[t::TunnelOption],
) -> String {
    let id = vpn.vpn_connection_id.clone().unwrap_or_default();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn_connection id=\"{id}\">\n  <customer_gateway_id>{}</customer_gateway_id>\n  <vpn_gateway_id>{}</vpn_gateway_id>\n  <vpn_connection_type>ipsec.1</vpn_connection_type>\n",
        cgw.customer_gateway_id.clone().unwrap_or_default(),
        vpn.vpn_gateway_id.clone().or_else(|| vpn.transit_gateway_id.clone()).unwrap_or_default(),
    );
    for tun in tunnels {
        let inside = tun.tunnel_inside_cidr.as_deref().and_then(Cidr::parse);
        let (cgw_inside, vgw_inside) = match inside {
            Some(c) => (crate::util::ip_str(c.first() + 2), crate::util::ip_str(c.first() + 1)),
            None => (String::new(), String::new()),
        };
        xml.push_str(&format!(
            "  <ipsec_tunnel>\n    <customer_gateway>\n      <tunnel_outside_address>\n        <ip_address>{}</ip_address>\n      </tunnel_outside_address>\n      <tunnel_inside_address>\n        <ip_address>{cgw_inside}</ip_address>\n        <network_mask>255.255.255.252</network_mask>\n        <network_cidr>30</network_cidr>\n      </tunnel_inside_address>\n      <bgp>\n        <asn>{}</asn>\n        <hold_time>30</hold_time>\n      </bgp>\n    </customer_gateway>\n    <vpn_gateway>\n      <tunnel_outside_address>\n        <ip_address>{}</ip_address>\n      </tunnel_outside_address>\n      <tunnel_inside_address>\n        <ip_address>{vgw_inside}</ip_address>\n        <network_mask>255.255.255.252</network_mask>\n        <network_cidr>30</network_cidr>\n      </tunnel_inside_address>\n    </vpn_gateway>\n    <ike>\n      <authentication_protocol>sha1</authentication_protocol>\n      <encryption_protocol>aes-128-cbc</encryption_protocol>\n      <lifetime>28800</lifetime>\n      <perfect_forward_secrecy>group2</perfect_forward_secrecy>\n      <mode>main</mode>\n      <pre_shared_key>{}</pre_shared_key>\n    </ike>\n    <ipsec>\n      <protocol>esp</protocol>\n      <authentication_protocol>hmac-sha1-96</authentication_protocol>\n      <encryption_protocol>aes-128-cbc</encryption_protocol>\n      <lifetime>3600</lifetime>\n      <perfect_forward_secrecy>group2</perfect_forward_secrecy>\n      <mode>tunnel</mode>\n      <clear_df_bit>true</clear_df_bit>\n      <fragmentation_before_encryption>true</fragmentation_before_encryption>\n      <tcp_mss_adjustment>1379</tcp_mss_adjustment>\n      <dead_peer_detection>\n        <delay>10</delay>\n        <retries>3</retries>\n      </dead_peer_detection>\n    </ipsec>\n  </ipsec_tunnel>\n",
            cgw.ip_address.clone().unwrap_or_default(),
            cgw.bgp_asn.clone().unwrap_or_default(),
            tun.outside_ip_address.clone().unwrap_or_default(),
            tun.pre_shared_key.clone().unwrap_or_default(),
        ));
    }
    xml.push_str("</vpn_connection>");
    xml
}
