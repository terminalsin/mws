//! Transit gateways: attachments (VPC, VPN, peering), route tables,
//! associations, propagations and routes.
//!
//! The control plane follows EC2: default association and propagation
//! route tables, propagated routes from attached VPCs' CIDR blocks and VPN
//! static routes, route search. Traffic does not flow through it.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::ops::gateways::{authorize_create, authorize_on};
use crate::state::{RegionState, State, TgwAttachmentRecord, TgwRouteTableRecord};
use crate::util::{
    arn, authorize, err, invalid_parameter, new_id, paginate, s, some_tags, tags_for, Cidr, Filters, Kind,
};
use crate::{account_of, Ec2};

const ENABLE: &str = "enable";
const DISABLE: &str = "disable";

fn enable_disable(name: &str, v: &Option<String>, default: &str) -> Result<String, ServiceError> {
    match v.as_deref() {
        None => Ok(default.into()),
        Some(x @ (ENABLE | DISABLE)) => Ok(x.into()),
        Some(x) => Err(invalid_parameter(format!(
            "Value ({x}) for parameter {name} is invalid. Valid values: enable, disable"
        ))),
    }
}

fn is_live(state: &Option<String>) -> bool {
    !matches!(state.as_deref(), Some("deleted" | "deleting" | "rejected" | "failed"))
}

/// Attach a VPN connection to a transit gateway (from `CreateVpnConnection`).
pub(crate) fn attach_vpn(r: &mut RegionState, tgw_id: &str, vpn_id: &str, now: DateTime<Utc>) {
    let Some(tgw) = r.transit_gateways.get(tgw_id).cloned() else { return };
    let id = new_id("tgw-attach");
    let att = t::TransitGatewayAttachment {
        transit_gateway_attachment_id: Some(id.clone()),
        transit_gateway_id: Some(tgw_id.into()),
        transit_gateway_owner_id: tgw.owner_id.clone(),
        resource_owner_id: tgw.owner_id.clone(),
        resource_type: Some("vpn".into()),
        resource_id: Some(vpn_id.into()),
        state: Some("available".into()),
        creation_time: Some(now),
        ..Default::default()
    };
    r.transit_gateway_attachments.insert(id.clone(), TgwAttachmentRecord { attachment: att, vpc: None, peering: None });
    apply_defaults(r, &tgw, &id);
}

/// Detach a deleted VPN connection's attachment.
pub(crate) fn detach_vpn(r: &mut RegionState, vpn_id: &str, now: DateTime<Utc>) {
    let ids: Vec<String> = r
        .transit_gateway_attachments
        .values()
        .filter(|a| a.attachment.resource_id.as_deref() == Some(vpn_id) && is_live(&a.attachment.state))
        .filter_map(|a| a.attachment.transit_gateway_attachment_id.clone())
        .collect();
    for id in ids {
        mark_attachment_deleted(r, &id, now);
    }
}

/// Associate and propagate a new attachment as its gateway's defaults say.
fn apply_defaults(r: &mut RegionState, tgw: &t::TransitGateway, att_id: &str) {
    let opts = tgw.options.clone().unwrap_or_default();
    if opts.default_route_table_association.as_deref() == Some(ENABLE) {
        if let Some(rtb) = opts.association_default_route_table_id.as_ref() {
            associate(r, rtb, att_id);
        }
    }
    if opts.default_route_table_propagation.as_deref() == Some(ENABLE) {
        if let Some(rtb) = opts.propagation_default_route_table_id.as_ref() {
            if let Some(t) = r.transit_gateway_route_tables.get_mut(rtb) {
                if !t.propagations.iter().any(|p| p == att_id) {
                    t.propagations.push(att_id.into());
                }
            }
        }
    }
}

fn associate(r: &mut RegionState, rtb: &str, att_id: &str) {
    if let Some(t) = r.transit_gateway_route_tables.get_mut(rtb) {
        if !t.associations.iter().any(|a| a == att_id) {
            t.associations.push(att_id.into());
        }
    }
    if let Some(a) = r.transit_gateway_attachments.get_mut(att_id) {
        a.attachment.association = Some(t::TransitGatewayAttachmentAssociation {
            transit_gateway_route_table_id: Some(rtb.into()),
            state: Some("associated".into()),
            ..Default::default()
        });
    }
}

fn mark_attachment_deleted(r: &mut RegionState, id: &str, now: DateTime<Utc>) {
    for t in r.transit_gateway_route_tables.values_mut() {
        t.associations.retain(|a| a != id);
        t.propagations.retain(|a| a != id);
        for route in &mut t.routes {
            if route
                .transit_gateway_attachments
                .iter()
                .flatten()
                .any(|a| a.transit_gateway_attachment_id.as_deref() == Some(id))
            {
                route.state = Some("blackhole".into());
                route.transit_gateway_attachments = None;
            }
        }
    }
    if let Some(a) = r.transit_gateway_attachments.get_mut(id) {
        a.attachment.state = Some("deleted".into());
        a.attachment.association = None;
        if let Some(v) = a.vpc.as_mut() {
            v.state = Some("deleted".into());
        }
        if let Some(p) = a.peering.as_mut() {
            p.state = Some("deleted".into());
            p.status =
                Some(t::PeeringAttachmentStatus { code: Some("deleted".into()), message: Some("Deleted".into()) });
        }
    }
    r.deleted_at.insert(id.into(), now);
    // VPC routes through the gateway lose their target when no attachment
    // of that VPC remains.
}

/// Routes of a route table: static ones plus those propagated from
/// attachments (VPC CIDR blocks, VPN static routes).
fn routes_of(r: &RegionState, table: &TgwRouteTableRecord) -> Vec<t::TransitGatewayRoute> {
    let mut out = table.routes.clone();
    for att_id in &table.propagations {
        let Some(a) = r.transit_gateway_attachments.get(att_id) else { continue };
        if a.attachment.state.as_deref() != Some("available") {
            continue;
        }
        let route_att = t::TransitGatewayRouteAttachment {
            resource_id: a.attachment.resource_id.clone(),
            transit_gateway_attachment_id: Some(att_id.clone()),
            resource_type: a.attachment.resource_type.clone(),
        };
        let cidrs: Vec<String> = match a.attachment.resource_type.as_deref() {
            Some("vpc") => a
                .attachment
                .resource_id
                .as_ref()
                .and_then(|v| r.vpcs.get(v))
                .map(|v| {
                    v.vpc
                        .cidr_block_association_set
                        .iter()
                        .flatten()
                        .filter(|c| c.cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) == Some("associated"))
                        .filter_map(|c| c.cidr_block.clone())
                        .collect()
                })
                .unwrap_or_default(),
            Some("vpn") => a
                .attachment
                .resource_id
                .as_ref()
                .and_then(|v| r.vpn_connections.get(v))
                .map(|v| v.routes.iter().flatten().filter_map(|x| x.destination_cidr_block.clone()).collect())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        for cidr in cidrs {
            if out.iter().any(|x| {
                x.destination_cidr_block.as_deref() == Some(cidr.as_str()) && x.r#type.as_deref() == Some("static")
            }) {
                continue;
            }
            if let Some(existing) = out.iter_mut().find(|x| {
                x.destination_cidr_block.as_deref() == Some(cidr.as_str()) && x.r#type.as_deref() == Some("propagated")
            }) {
                existing.transit_gateway_attachments.get_or_insert_with(Vec::new).push(route_att.clone());
                continue;
            }
            out.push(t::TransitGatewayRoute {
                destination_cidr_block: Some(cidr),
                transit_gateway_attachments: Some(vec![route_att.clone()]),
                r#type: Some("propagated".into()),
                state: Some("active".into()),
                ..Default::default()
            });
        }
    }
    out.sort_by(|a, b| a.destination_cidr_block.cmp(&b.destination_cidr_block));
    out
}

fn association_view(r: &RegionState, rtb: &str, att_id: &str, state: &str) -> t::TransitGatewayAssociation {
    let a = r.transit_gateway_attachments.get(att_id).map(|a| a.attachment.clone()).unwrap_or_default();
    t::TransitGatewayAssociation {
        transit_gateway_route_table_id: Some(rtb.into()),
        transit_gateway_attachment_id: Some(att_id.into()),
        resource_id: a.resource_id,
        resource_type: a.resource_type,
        state: Some(state.into()),
    }
}

fn propagation_view(r: &RegionState, rtb: &str, att_id: &str, state: &str) -> t::TransitGatewayPropagation {
    let a = r.transit_gateway_attachments.get(att_id).map(|a| a.attachment.clone()).unwrap_or_default();
    t::TransitGatewayPropagation {
        transit_gateway_attachment_id: Some(att_id.into()),
        resource_id: a.resource_id,
        resource_type: a.resource_type,
        transit_gateway_route_table_id: Some(rtb.into()),
        state: Some(state.into()),
        transit_gateway_route_table_announcement_id: None,
    }
}

/// Keep an attachment's typed view in step with its summary.
fn sync_views(rec: &mut TgwAttachmentRecord) {
    let state = rec.attachment.state.clone();
    let tags = rec.attachment.tags.clone();
    if let Some(v) = rec.vpc.as_mut() {
        v.state = state.clone();
        v.tags = tags.clone();
    }
    if let Some(p) = rec.peering.as_mut() {
        p.state = state.clone();
        p.tags = tags;
        let message = match state.as_deref() {
            Some("available") => "Available",
            Some("pendingAcceptance") => "Pending Acceptance",
            Some("rejected") => "Rejected",
            Some("deleted") => "Deleted",
            Some("initiatingRequest") => "Initiating Request",
            _ => "",
        };
        p.status = Some(t::PeeringAttachmentStatus { code: state, message: Some(message.into()) });
    }
}

impl Ec2 {
    fn tgw_authorize(
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
            Kind::TransitGateway,
            "transit-gateway",
            id,
            |r| r.transit_gateways.get(id).filter(|g| is_live(&g.state)).map(|g| g.tags.clone()),
            dry_run,
        )
    }

    fn attachment_authorize(
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
            Kind::TransitGatewayAttachment,
            "transit-gateway-attachment",
            id,
            |r| {
                r.transit_gateway_attachments
                    .get(id)
                    .filter(|a| a.attachment.state.as_deref() != Some("deleted"))
                    .map(|a| a.attachment.tags.clone())
            },
            dry_run,
        )
    }

    fn tgw_rtb_authorize(
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
            Kind::TransitGatewayRouteTable,
            "transit-gateway-route-table",
            id,
            |r| {
                r.transit_gateway_route_tables
                    .get(id)
                    .filter(|t| t.table.state.as_deref() != Some("deleted"))
                    .map(|t| t.table.tags.clone())
            },
            dry_run,
        )
    }

    // ---- transit gateways --------------------------------------------------------------------------

    pub(crate) fn create_transit_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTransitGatewayRequest,
    ) -> Result<t::CreateTransitGatewayResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "transit-gateway", &["transit-gateway"])?;
        let o = input.options.clone().unwrap_or_default();
        let asn = o.amazon_side_asn.unwrap_or(64512);
        if !((64512..=65534).contains(&asn) || (4_200_000_000..=4_294_967_294).contains(&asn)) {
            return Err(invalid_parameter(format!(
                "Invalid ASN {asn}. Valid ASNs are 64512 to 65534 and 4200000000 to 4294967294."
            )));
        }
        for c in o.transit_gateway_cidr_blocks.iter().flatten() {
            if Cidr::parse(c).is_none() && !c.contains(':') {
                return Err(invalid_parameter(format!("Invalid CIDR block {c}")));
            }
        }
        let options = t::TransitGatewayOptions {
            amazon_side_asn: Some(asn),
            transit_gateway_cidr_blocks: o.transit_gateway_cidr_blocks.clone(),
            auto_accept_shared_attachments: Some(enable_disable(
                "AutoAcceptSharedAttachments",
                &o.auto_accept_shared_attachments,
                DISABLE,
            )?),
            default_route_table_association: Some(enable_disable(
                "DefaultRouteTableAssociation",
                &o.default_route_table_association,
                ENABLE,
            )?),
            default_route_table_propagation: Some(enable_disable(
                "DefaultRouteTablePropagation",
                &o.default_route_table_propagation,
                ENABLE,
            )?),
            vpn_ecmp_support: Some(enable_disable("VpnEcmpSupport", &o.vpn_ecmp_support, ENABLE)?),
            dns_support: Some(enable_disable("DnsSupport", &o.dns_support, ENABLE)?),
            security_group_referencing_support: Some(enable_disable(
                "SecurityGroupReferencingSupport",
                &o.security_group_referencing_support,
                DISABLE,
            )?),
            multicast_support: Some(enable_disable("MulticastSupport", &o.multicast_support, DISABLE)?),
            ..Default::default()
        };
        authorize_create(ctx, "CreateTransitGateway", "transit-gateway", &tags, &[], input.dry_run)?;
        let account = account_of(ctx);
        let now = ctx.received_at;
        let id = new_id("tgw");
        let tgw_arn = arn(ctx, &account, &format!("transit-gateway/{id}"));
        self.with_region(ctx, |r| {
            let mut tgw = t::TransitGateway {
                transit_gateway_id: Some(id.clone()),
                transit_gateway_arn: Some(tgw_arn),
                state: Some("available".into()),
                owner_id: Some(account.clone()),
                description: input.description.clone(),
                creation_time: Some(now),
                options: Some(options),
                tags: some_tags(tags),
            };
            let assoc = tgw.options.as_ref().and_then(|o| o.default_route_table_association.clone());
            let prop = tgw.options.as_ref().and_then(|o| o.default_route_table_propagation.clone());
            if assoc.as_deref() == Some(ENABLE) || prop.as_deref() == Some(ENABLE) {
                let rtb = new_id("tgw-rtb");
                r.transit_gateway_route_tables.insert(
                    rtb.clone(),
                    TgwRouteTableRecord {
                        table: t::TransitGatewayRouteTable {
                            transit_gateway_route_table_id: Some(rtb.clone()),
                            transit_gateway_id: Some(id.clone()),
                            state: Some("available".into()),
                            default_association_route_table: Some(assoc.as_deref() == Some(ENABLE)),
                            default_propagation_route_table: Some(prop.as_deref() == Some(ENABLE)),
                            creation_time: Some(now),
                            tags: None,
                        },
                        ..Default::default()
                    },
                );
                let o = tgw.options.as_mut().expect("set");
                if assoc.as_deref() == Some(ENABLE) {
                    o.association_default_route_table_id = Some(rtb.clone());
                }
                if prop.as_deref() == Some(ENABLE) {
                    o.propagation_default_route_table_id = Some(rtb);
                }
            }
            r.transit_gateways.insert(id.clone(), tgw.clone());
            // The create call answers while the gateway is still pending.
            tgw.state = Some("pending".into());
            Ok(t::CreateTransitGatewayResult { transit_gateway: Some(tgw) })
        })
    }

    pub(crate) fn delete_transit_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTransitGatewayRequest,
    ) -> Result<t::DeleteTransitGatewayResult, ServiceError> {
        let id = input.transit_gateway_id.clone();
        self.tgw_authorize(ctx, "DeleteTransitGateway", &id, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let live: Vec<String> = r
                .transit_gateway_attachments
                .values()
                .filter(|a| {
                    a.attachment.transit_gateway_id.as_deref() == Some(id.as_str()) && is_live(&a.attachment.state)
                })
                .filter_map(|a| a.attachment.transit_gateway_attachment_id.clone())
                .collect();
            if !live.is_empty() {
                return Err(err(
                    "IncorrectState",
                    format!("{id} has non-deleted Transit Gateway Attachments: {}", live.join(", ")),
                ));
            }
            let defaults: Vec<String> = r
                .transit_gateway_route_tables
                .values()
                .filter(|t| t.table.transit_gateway_id.as_deref() == Some(id.as_str()))
                .filter(|t| {
                    t.table.default_association_route_table == Some(true)
                        || t.table.default_propagation_route_table == Some(true)
                })
                .filter_map(|t| t.table.transit_gateway_route_table_id.clone())
                .collect();
            let others = r.transit_gateway_route_tables.values().any(|t| {
                t.table.transit_gateway_id.as_deref() == Some(id.as_str())
                    && is_live(&t.table.state)
                    && !defaults.contains(t.table.transit_gateway_route_table_id.as_ref().unwrap())
            });
            if others {
                return Err(err(
                    "IncorrectState",
                    format!("{id} has non-default Transit Gateway Route Tables; delete them first."),
                ));
            }
            for rtb in defaults {
                if let Some(t) = r.transit_gateway_route_tables.get_mut(&rtb) {
                    t.table.state = Some("deleted".into());
                }
                r.deleted_at.insert(rtb, now);
            }
            let g = r.transit_gateways.get_mut(&id).ok_or_else(|| Kind::TransitGateway.not_found(&id))?;
            g.state = Some("deleted".into());
            let mut out = g.clone();
            out.state = Some("deleting".into());
            r.deleted_at.insert(id.clone(), now);
            crate::ops::gateways::blackhole_routes(r, |route| route.transit_gateway_id.as_deref() == Some(id.as_str()));
            Ok(t::DeleteTransitGatewayResult { transit_gateway: Some(out) })
        })
    }

    pub(crate) fn describe_transit_gateways_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTransitGatewaysRequest,
    ) -> Result<t::DescribeTransitGatewaysResult, ServiceError> {
        authorize(ctx, "DescribeTransitGateways", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.transit_gateway_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::TransitGateway.check_all(&ids, |id| r.transit_gateways.contains_key(id))?;
            let mut out = Vec::new();
            for g in r.transit_gateways.values() {
                let id = g.transit_gateway_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let o = g.options.clone().unwrap_or_default();
                let ok = filters.matches(g.tags.as_ref(), |name| {
                    Some(match name {
                        "options.propagation-default-route-table-id" => s(&o.propagation_default_route_table_id),
                        "options.amazon-side-asn" => o.amazon_side_asn.map(|a| a.to_string()).into_iter().collect(),
                        "options.association-default-route-table-id" => s(&o.association_default_route_table_id),
                        "options.auto-accept-shared-attachments" => s(&o.auto_accept_shared_attachments),
                        "options.default-route-table-association" => s(&o.default_route_table_association),
                        "options.default-route-table-propagation" => s(&o.default_route_table_propagation),
                        "options.dns-support" => s(&o.dns_support),
                        "options.vpn-ecmp-support" => s(&o.vpn_ecmp_support),
                        "owner-id" => s(&g.owner_id),
                        "state" => s(&g.state),
                        "transit-gateway-id" => vec![id.clone()],
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(g.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeTransitGatewaysResult { transit_gateways: Some(items), next_token })
        })
    }

    pub(crate) fn modify_transit_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyTransitGatewayRequest,
    ) -> Result<t::ModifyTransitGatewayResult, ServiceError> {
        let id = input.transit_gateway_id.clone();
        self.tgw_authorize(ctx, "ModifyTransitGateway", &id, input.dry_run)?;
        let m = input.options.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            for rtb in
                [&m.association_default_route_table_id, &m.propagation_default_route_table_id].into_iter().flatten()
            {
                let ok = r.transit_gateway_route_tables.get(rtb).is_some_and(|t| {
                    t.table.transit_gateway_id.as_deref() == Some(id.as_str()) && is_live(&t.table.state)
                });
                if !ok {
                    return Err(Kind::TransitGatewayRouteTable.not_found(rtb));
                }
            }
            let g = r.transit_gateways.get_mut(&id).ok_or_else(|| Kind::TransitGateway.not_found(&id))?;
            if let Some(d) = &input.description {
                g.description = Some(d.clone());
            }
            let o = g.options.get_or_insert_with(Default::default);
            let set = |field: &mut Option<String>, name: &str, v: &Option<String>| -> Result<(), ServiceError> {
                if v.is_some() {
                    *field = Some(enable_disable(name, v, ENABLE)?);
                }
                Ok(())
            };
            set(&mut o.vpn_ecmp_support, "VpnEcmpSupport", &m.vpn_ecmp_support)?;
            set(&mut o.dns_support, "DnsSupport", &m.dns_support)?;
            set(
                &mut o.security_group_referencing_support,
                "SecurityGroupReferencingSupport",
                &m.security_group_referencing_support,
            )?;
            set(
                &mut o.auto_accept_shared_attachments,
                "AutoAcceptSharedAttachments",
                &m.auto_accept_shared_attachments,
            )?;
            set(
                &mut o.default_route_table_association,
                "DefaultRouteTableAssociation",
                &m.default_route_table_association,
            )?;
            set(
                &mut o.default_route_table_propagation,
                "DefaultRouteTablePropagation",
                &m.default_route_table_propagation,
            )?;
            if let Some(a) = m.amazon_side_asn {
                o.amazon_side_asn = Some(a);
            }
            if let Some(rtb) = &m.association_default_route_table_id {
                o.association_default_route_table_id = Some(rtb.clone());
            }
            if let Some(rtb) = &m.propagation_default_route_table_id {
                o.propagation_default_route_table_id = Some(rtb.clone());
            }
            let blocks = o.transit_gateway_cidr_blocks.get_or_insert_with(Vec::new);
            for c in m.add_transit_gateway_cidr_blocks.iter().flatten() {
                if !blocks.contains(c) {
                    blocks.push(c.clone());
                }
            }
            if let Some(remove) = &m.remove_transit_gateway_cidr_blocks {
                blocks.retain(|c| !remove.contains(c));
            }
            if blocks.is_empty() {
                o.transit_gateway_cidr_blocks = None;
            }
            let o = o.clone();
            let mut out = g.clone();
            out.state = Some("modifying".into());
            // Default route table flags follow the options.
            for t in r.transit_gateway_route_tables.values_mut() {
                if t.table.transit_gateway_id.as_deref() != Some(id.as_str()) {
                    continue;
                }
                let tid = t.table.transit_gateway_route_table_id.clone();
                t.table.default_association_route_table = Some(
                    o.default_route_table_association.as_deref() == Some(ENABLE)
                        && o.association_default_route_table_id == tid,
                );
                t.table.default_propagation_route_table = Some(
                    o.default_route_table_propagation.as_deref() == Some(ENABLE)
                        && o.propagation_default_route_table_id == tid,
                );
            }
            Ok(t::ModifyTransitGatewayResult { transit_gateway: Some(out) })
        })
    }

    // ---- VPC attachments ---------------------------------------------------------------------------

    pub(crate) fn create_transit_gateway_vpc_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTransitGatewayVpcAttachmentRequest,
    ) -> Result<t::CreateTransitGatewayVpcAttachmentResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "transit-gateway-attachment", &["transit-gateway-attachment"])?;
        self.tgw_authorize(ctx, "CreateTransitGatewayVpcAttachment", &input.transit_gateway_id, None)?;
        Kind::Vpc.check(&input.vpc_id)?;
        for sn in &input.subnet_ids {
            Kind::Subnet.check(sn)?;
        }
        let o = input.options.clone().unwrap_or_default();
        let options = t::TransitGatewayVpcAttachmentOptions {
            dns_support: Some(enable_disable("DnsSupport", &o.dns_support, ENABLE)?),
            security_group_referencing_support: Some(enable_disable(
                "SecurityGroupReferencingSupport",
                &o.security_group_referencing_support,
                ENABLE,
            )?),
            ipv6_support: Some(enable_disable("Ipv6Support", &o.ipv6_support, DISABLE)?),
            appliance_mode_support: Some(enable_disable("ApplianceModeSupport", &o.appliance_mode_support, DISABLE)?),
        };
        let account = account_of(ctx);
        authorize_create(
            ctx,
            "CreateTransitGatewayVpcAttachment",
            "transit-gateway-attachment",
            &tags,
            &[arn(ctx, &account, &format!("vpc/{}", input.vpc_id))],
            input.dry_run,
        )?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            if !r.vpcs.contains_key(&input.vpc_id) {
                return Err(Kind::Vpc.not_found(&input.vpc_id));
            }
            if input.subnet_ids.is_empty() {
                return Err(invalid_parameter("At least one subnet must be specified."));
            }
            let mut zones = Vec::new();
            for sn in &input.subnet_ids {
                let subnet = r.subnets.get(sn).ok_or_else(|| Kind::Subnet.not_found(sn))?;
                if subnet.vpc_id.as_deref() != Some(input.vpc_id.as_str()) {
                    return Err(invalid_parameter(format!("Subnet {sn} does not belong to VPC {}", input.vpc_id)));
                }
                let z = subnet.availability_zone.clone().unwrap_or_default();
                if zones.contains(&z) {
                    return Err(err(
                        "DuplicateSubnetsInSameZone",
                        format!("Duplicate Subnets for same AZ: {}", input.subnet_ids.join(",")),
                    ));
                }
                zones.push(z);
            }
            let duplicate = r.transit_gateway_attachments.values().any(|a| {
                a.attachment.transit_gateway_id.as_deref() == Some(input.transit_gateway_id.as_str())
                    && a.attachment.resource_id.as_deref() == Some(input.vpc_id.as_str())
                    && is_live(&a.attachment.state)
            });
            if duplicate {
                return Err(err(
                    "DuplicateTransitGatewayAttachment",
                    format!(
                        "{} has non-deleted Transit Gateway Attachments with same VPC ID.",
                        input.transit_gateway_id
                    ),
                ));
            }
            let tgw = r.transit_gateways.get(&input.transit_gateway_id).cloned().expect("authorized");
            let id = new_id("tgw-attach");
            let tags = some_tags(tags);
            let vpc_view = t::TransitGatewayVpcAttachment {
                transit_gateway_attachment_id: Some(id.clone()),
                transit_gateway_id: Some(input.transit_gateway_id.clone()),
                vpc_id: Some(input.vpc_id.clone()),
                vpc_owner_id: Some(account.clone()),
                state: Some("available".into()),
                subnet_ids: Some(input.subnet_ids.clone()),
                creation_time: Some(now),
                options: Some(options),
                tags: tags.clone(),
            };
            let att = t::TransitGatewayAttachment {
                transit_gateway_attachment_id: Some(id.clone()),
                transit_gateway_id: Some(input.transit_gateway_id.clone()),
                transit_gateway_owner_id: tgw.owner_id.clone(),
                resource_owner_id: Some(account.clone()),
                resource_type: Some("vpc".into()),
                resource_id: Some(input.vpc_id.clone()),
                state: Some("available".into()),
                creation_time: Some(now),
                tags,
                ..Default::default()
            };
            r.transit_gateway_attachments.insert(
                id.clone(),
                TgwAttachmentRecord { attachment: att, vpc: Some(vpc_view.clone()), peering: None },
            );
            apply_defaults(r, &tgw, &id);
            let mut out = vpc_view;
            out.state = Some("pending".into());
            Ok(t::CreateTransitGatewayVpcAttachmentResult { transit_gateway_vpc_attachment: Some(out) })
        })
    }

    fn vpc_attachment(r: &RegionState, id: &str) -> Result<t::TransitGatewayVpcAttachment, ServiceError> {
        r.transit_gateway_attachments
            .get(id)
            .and_then(|a| a.vpc.clone())
            .ok_or_else(|| Kind::TransitGatewayAttachment.not_found(id))
    }

    pub(crate) fn delete_transit_gateway_vpc_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTransitGatewayVpcAttachmentRequest,
    ) -> Result<t::DeleteTransitGatewayVpcAttachmentResult, ServiceError> {
        let id = input.transit_gateway_attachment_id.clone();
        self.attachment_authorize(ctx, "DeleteTransitGatewayVpcAttachment", &id, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let mut view = Self::vpc_attachment(r, &id)?;
            let vpc = view.vpc_id.clone().unwrap_or_default();
            let tgw = view.transit_gateway_id.clone().unwrap_or_default();
            mark_attachment_deleted(r, &id, now);
            // Routes in the VPC through this gateway become blackholes.
            for rt in r.route_tables.values_mut() {
                if rt.vpc_id.as_deref() != Some(vpc.as_str()) {
                    continue;
                }
                for route in rt.routes.iter_mut().flatten() {
                    if route.transit_gateway_id.as_deref() == Some(tgw.as_str()) {
                        route.state = Some("blackhole".into());
                    }
                }
            }
            view.state = Some("deleting".into());
            Ok(t::DeleteTransitGatewayVpcAttachmentResult { transit_gateway_vpc_attachment: Some(view) })
        })
    }

    pub(crate) fn describe_transit_gateway_vpc_attachments_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTransitGatewayVpcAttachmentsRequest,
    ) -> Result<t::DescribeTransitGatewayVpcAttachmentsResult, ServiceError> {
        authorize(
            ctx,
            "DescribeTransitGatewayVpcAttachments",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let filters = Filters::new(&input.filters);
        let ids = input.transit_gateway_attachment_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::TransitGatewayAttachment
                .check_all(&ids, |id| r.transit_gateway_attachments.get(id).is_some_and(|a| a.vpc.is_some()))?;
            let mut out = Vec::new();
            for a in r.transit_gateway_attachments.values() {
                let Some(v) = &a.vpc else { continue };
                let id = v.transit_gateway_attachment_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let ok = filters.matches(v.tags.as_ref(), |name| {
                    Some(match name {
                        "state" => s(&v.state),
                        "transit-gateway-attachment-id" => vec![id.clone()],
                        "transit-gateway-id" => s(&v.transit_gateway_id),
                        "vpc-id" => s(&v.vpc_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(v.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeTransitGatewayVpcAttachmentsResult {
                transit_gateway_vpc_attachments: Some(items),
                next_token,
            })
        })
    }

    pub(crate) fn modify_transit_gateway_vpc_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyTransitGatewayVpcAttachmentRequest,
    ) -> Result<t::ModifyTransitGatewayVpcAttachmentResult, ServiceError> {
        let id = input.transit_gateway_attachment_id.clone();
        self.attachment_authorize(ctx, "ModifyTransitGatewayVpcAttachment", &id, input.dry_run)?;
        self.with_region(ctx, |r| {
            let view = Self::vpc_attachment(r, &id)?;
            let vpc = view.vpc_id.clone().unwrap_or_default();
            let mut subnets = view.subnet_ids.clone().unwrap_or_default();
            if let Some(remove) = &input.remove_subnet_ids {
                for sn in remove {
                    if !subnets.contains(sn) {
                        return Err(invalid_parameter(format!("Subnet {sn} is not part of attachment {id}")));
                    }
                }
                subnets.retain(|sn| !remove.contains(sn));
            }
            for sn in input.add_subnet_ids.iter().flatten() {
                Kind::Subnet.check(sn)?;
                let subnet = r.subnets.get(sn).ok_or_else(|| Kind::Subnet.not_found(sn))?;
                if subnet.vpc_id.as_deref() != Some(vpc.as_str()) {
                    return Err(invalid_parameter(format!("Subnet {sn} does not belong to VPC {vpc}")));
                }
                let zone = subnet.availability_zone.clone();
                if subnets.iter().any(|x| r.subnets.get(x).and_then(|s| s.availability_zone.clone()) == zone) {
                    return Err(err("DuplicateSubnetsInSameZone", format!("Duplicate Subnets for same AZ: {sn}")));
                }
                subnets.push(sn.clone());
            }
            if subnets.is_empty() {
                return Err(invalid_parameter("A VPC attachment needs at least one subnet."));
            }
            let rec = r.transit_gateway_attachments.get_mut(&id).expect("checked");
            let v = rec.vpc.as_mut().expect("vpc attachment");
            v.subnet_ids = Some(subnets);
            if let Some(o) = &input.options {
                let opts = v.options.get_or_insert_with(Default::default);
                if o.dns_support.is_some() {
                    opts.dns_support = Some(enable_disable("DnsSupport", &o.dns_support, ENABLE)?);
                }
                if o.security_group_referencing_support.is_some() {
                    opts.security_group_referencing_support = Some(enable_disable(
                        "SecurityGroupReferencingSupport",
                        &o.security_group_referencing_support,
                        ENABLE,
                    )?);
                }
                if o.ipv6_support.is_some() {
                    opts.ipv6_support = Some(enable_disable("Ipv6Support", &o.ipv6_support, DISABLE)?);
                }
                if o.appliance_mode_support.is_some() {
                    opts.appliance_mode_support =
                        Some(enable_disable("ApplianceModeSupport", &o.appliance_mode_support, DISABLE)?);
                }
            }
            let mut out = v.clone();
            out.state = Some("modifying".into());
            Ok(t::ModifyTransitGatewayVpcAttachmentResult { transit_gateway_vpc_attachment: Some(out) })
        })
    }

    fn set_pending_attachment_state(
        &self,
        ctx: &RequestContext,
        id: &str,
        to: &str,
    ) -> Result<TgwAttachmentRecord, ServiceError> {
        self.with_region(ctx, |r| {
            let rec = r
                .transit_gateway_attachments
                .get_mut(id)
                .ok_or_else(|| Kind::TransitGatewayAttachment.not_found(id))?;
            if rec.attachment.state.as_deref() != Some("pendingAcceptance") {
                return Err(err(
                    "IncorrectState",
                    format!("{id} is in invalid state {}", rec.attachment.state.clone().unwrap_or_default()),
                ));
            }
            rec.attachment.state = Some(to.into());
            sync_views(rec);
            let rec = rec.clone();
            if to == "available" {
                if let Some(tgw) =
                    rec.attachment.transit_gateway_id.as_ref().and_then(|g| r.transit_gateways.get(g)).cloned()
                {
                    apply_defaults(r, &tgw, id);
                }
            }
            Ok(rec)
        })
    }

    pub(crate) fn accept_transit_gateway_vpc_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::AcceptTransitGatewayVpcAttachmentRequest,
    ) -> Result<t::AcceptTransitGatewayVpcAttachmentResult, ServiceError> {
        let id = input.transit_gateway_attachment_id.clone();
        self.attachment_authorize(ctx, "AcceptTransitGatewayVpcAttachment", &id, input.dry_run)?;
        let rec = self.set_pending_attachment_state(ctx, &id, "available")?;
        Ok(t::AcceptTransitGatewayVpcAttachmentResult { transit_gateway_vpc_attachment: rec.vpc })
    }

    pub(crate) fn reject_transit_gateway_vpc_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::RejectTransitGatewayVpcAttachmentRequest,
    ) -> Result<t::RejectTransitGatewayVpcAttachmentResult, ServiceError> {
        let id = input.transit_gateway_attachment_id.clone();
        self.attachment_authorize(ctx, "RejectTransitGatewayVpcAttachment", &id, input.dry_run)?;
        let rec = self.set_pending_attachment_state(ctx, &id, "rejected")?;
        Ok(t::RejectTransitGatewayVpcAttachmentResult { transit_gateway_vpc_attachment: rec.vpc })
    }

    // ---- peering attachments -----------------------------------------------------------------------

    pub(crate) fn create_transit_gateway_peering_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTransitGatewayPeeringAttachmentRequest,
    ) -> Result<t::CreateTransitGatewayPeeringAttachmentResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "transit-gateway-attachment", &["transit-gateway-attachment"])?;
        self.tgw_authorize(ctx, "CreateTransitGatewayPeeringAttachment", &input.transit_gateway_id, None)?;
        Kind::TransitGateway.check(&input.peer_transit_gateway_id)?;
        if input.peer_transit_gateway_id == input.transit_gateway_id {
            return Err(invalid_parameter("A transit gateway cannot peer with itself."));
        }
        authorize_create(
            ctx,
            "CreateTransitGatewayPeeringAttachment",
            "transit-gateway-attachment",
            &tags,
            &[],
            input.dry_run,
        )?;
        let account = account_of(ctx);
        let peer_account = input.peer_account_id.clone();
        let peer_region = input.peer_region.clone();
        let peer_tgw = input.peer_transit_gateway_id.clone();
        let exists = self.with_region_of(&peer_account, &peer_region, ctx, |r| {
            r.transit_gateways.get(&peer_tgw).is_some_and(|g| is_live(&g.state))
        });
        if !exists {
            return Err(Kind::TransitGateway.not_found(&peer_tgw));
        }
        let now = ctx.received_at;
        let id = new_id("tgw-attach");
        let peering = t::TransitGatewayPeeringAttachment {
            transit_gateway_attachment_id: Some(id.clone()),
            requester_tgw_info: Some(t::PeeringTgwInfo {
                transit_gateway_id: Some(input.transit_gateway_id.clone()),
                owner_id: Some(account.clone()),
                region: Some(ctx.region.clone()),
                core_network_id: None,
            }),
            accepter_tgw_info: Some(t::PeeringTgwInfo {
                transit_gateway_id: Some(peer_tgw.clone()),
                owner_id: Some(peer_account.clone()),
                region: Some(peer_region.clone()),
                core_network_id: None,
            }),
            options: input
                .options
                .as_ref()
                .and_then(|o| o.dynamic_routing.clone())
                .map(|d| t::TransitGatewayPeeringAttachmentOptions { dynamic_routing: Some(d) }),
            state: Some("pendingAcceptance".into()),
            creation_time: Some(now),
            tags: some_tags(tags),
            ..Default::default()
        };
        let mut requester = TgwAttachmentRecord {
            attachment: t::TransitGatewayAttachment {
                transit_gateway_attachment_id: Some(id.clone()),
                transit_gateway_id: Some(input.transit_gateway_id.clone()),
                transit_gateway_owner_id: Some(account.clone()),
                resource_owner_id: Some(peer_account.clone()),
                resource_type: Some("peering".into()),
                resource_id: Some(peer_tgw.clone()),
                state: Some("pendingAcceptance".into()),
                creation_time: Some(now),
                tags: peering.tags.clone(),
                ..Default::default()
            },
            vpc: None,
            peering: Some(peering.clone()),
        };
        sync_views(&mut requester);
        // The accepter sees the same attachment from its gateway's side,
        // without the requester's tags.
        let mut accepter = requester.clone();
        accepter.attachment.transit_gateway_id = Some(peer_tgw.clone());
        accepter.attachment.transit_gateway_owner_id = Some(peer_account.clone());
        accepter.attachment.resource_owner_id = Some(account.clone());
        accepter.attachment.resource_id = Some(input.transit_gateway_id.clone());
        accepter.attachment.tags = None;
        sync_views(&mut accepter);
        let out = requester.peering.clone();
        self.with_region(ctx, |r| r.transit_gateway_attachments.insert(id.clone(), requester));
        self.with_region_of(&peer_account, &peer_region, ctx, |r| {
            r.transit_gateway_attachments.insert(id.clone(), accepter)
        });
        let mut out = out.expect("peering");
        out.state = Some("initiatingRequest".into());
        out.status = Some(t::PeeringAttachmentStatus {
            code: Some("initiatingRequest".into()),
            message: Some("Initiating Request".into()),
        });
        Ok(t::CreateTransitGatewayPeeringAttachmentResult { transit_gateway_peering_attachment: Some(out) })
    }

    /// The other side of a peering attachment: its account and Region.
    fn peering_peer(&self, ctx: &RequestContext, rec: &TgwAttachmentRecord) -> Option<(String, String)> {
        let p = rec.peering.as_ref()?;
        let account = account_of(ctx);
        let me = (account.clone(), ctx.region.clone());
        let req = p.requester_tgw_info.as_ref()?;
        let acc = p.accepter_tgw_info.as_ref()?;
        let req_side = (req.owner_id.clone()?, req.region.clone()?);
        let acc_side = (acc.owner_id.clone()?, acc.region.clone()?);
        if req_side == me {
            Some(acc_side)
        } else {
            Some(req_side)
        }
    }

    fn update_peering(
        &self,
        ctx: &RequestContext,
        id: &str,
        f: impl Fn(&mut RegionState, &mut TgwAttachmentRecord) -> Result<(), ServiceError>,
    ) -> Result<TgwAttachmentRecord, ServiceError> {
        let rec = self.with_region(ctx, |r| {
            let mut rec = r
                .transit_gateway_attachments
                .get(id)
                .filter(|a| a.peering.is_some())
                .cloned()
                .ok_or_else(|| Kind::TransitGatewayAttachment.not_found(id))?;
            f(r, &mut rec)?;
            sync_views(&mut rec);
            r.transit_gateway_attachments.insert(id.into(), rec.clone());
            Ok::<_, ServiceError>(rec)
        })?;
        if let Some((acct, region)) = self.peering_peer(ctx, &rec) {
            self.with_region_of(&acct, &region, ctx, |r| {
                if let Some(mut other) = r.transit_gateway_attachments.get(id).cloned() {
                    let _ = f(r, &mut other);
                    sync_views(&mut other);
                    r.transit_gateway_attachments.insert(id.into(), other);
                }
            });
        }
        Ok(rec)
    }

    pub(crate) fn accept_transit_gateway_peering_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::AcceptTransitGatewayPeeringAttachmentRequest,
    ) -> Result<t::AcceptTransitGatewayPeeringAttachmentResult, ServiceError> {
        let id = input.transit_gateway_attachment_id.clone();
        self.attachment_authorize(ctx, "AcceptTransitGatewayPeeringAttachment", &id, input.dry_run)?;
        let account = account_of(ctx);
        let region = ctx.region.clone();
        let rec = self.update_peering(ctx, &id, |_, rec| {
            let p = rec.peering.as_ref().expect("peering");
            if rec.attachment.state.as_deref() != Some("pendingAcceptance") {
                return Err(err(
                    "IncorrectState",
                    format!("{id} is in invalid state {}", rec.attachment.state.clone().unwrap_or_default()),
                ));
            }
            let acc = p.accepter_tgw_info.clone().unwrap_or_default();
            if acc.owner_id.as_deref() != Some(account.as_str()) || acc.region.as_deref() != Some(region.as_str()) {
                return Err(err("InvalidParameterValue", format!("Only the accepter of {id} can accept it.")));
            }
            rec.attachment.state = Some("available".into());
            Ok(())
        });
        // Only the caller's side was checked; apply the result to both.
        let rec = rec?;
        let mut out = rec.peering.expect("peering");
        out.state = Some("pendingAcceptance".into());
        out.status = Some(t::PeeringAttachmentStatus {
            code: Some("pendingAcceptance".into()),
            message: Some("Pending Acceptance".into()),
        });
        Ok(t::AcceptTransitGatewayPeeringAttachmentResult { transit_gateway_peering_attachment: Some(out) })
    }

    pub(crate) fn reject_transit_gateway_peering_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::RejectTransitGatewayPeeringAttachmentRequest,
    ) -> Result<t::RejectTransitGatewayPeeringAttachmentResult, ServiceError> {
        let id = input.transit_gateway_attachment_id.clone();
        self.attachment_authorize(ctx, "RejectTransitGatewayPeeringAttachment", &id, input.dry_run)?;
        let now = ctx.received_at;
        let rec = self.update_peering(ctx, &id, |r, rec| {
            if rec.attachment.state.as_deref() != Some("pendingAcceptance") {
                return Err(err(
                    "IncorrectState",
                    format!("{id} is in invalid state {}", rec.attachment.state.clone().unwrap_or_default()),
                ));
            }
            rec.attachment.state = Some("rejected".into());
            r.deleted_at.insert(id.clone(), now);
            Ok(())
        })?;
        let mut out = rec.peering.expect("peering");
        out.state = Some("rejecting".into());
        Ok(t::RejectTransitGatewayPeeringAttachmentResult { transit_gateway_peering_attachment: Some(out) })
    }

    pub(crate) fn delete_transit_gateway_peering_attachment_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTransitGatewayPeeringAttachmentRequest,
    ) -> Result<t::DeleteTransitGatewayPeeringAttachmentResult, ServiceError> {
        let id = input.transit_gateway_attachment_id.clone();
        self.attachment_authorize(ctx, "DeleteTransitGatewayPeeringAttachment", &id, input.dry_run)?;
        let now = ctx.received_at;
        let rec = self.update_peering(ctx, &id, |r, rec| {
            mark_attachment_deleted(r, &id, now);
            rec.attachment.state = Some("deleted".into());
            rec.attachment.association = None;
            Ok(())
        })?;
        let mut out = rec.peering.expect("peering");
        out.state = Some("deleting".into());
        out.status =
            Some(t::PeeringAttachmentStatus { code: Some("deleting".into()), message: Some("Deleting".into()) });
        Ok(t::DeleteTransitGatewayPeeringAttachmentResult { transit_gateway_peering_attachment: Some(out) })
    }

    pub(crate) fn describe_transit_gateway_peering_attachments_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTransitGatewayPeeringAttachmentsRequest,
    ) -> Result<t::DescribeTransitGatewayPeeringAttachmentsResult, ServiceError> {
        authorize(
            ctx,
            "DescribeTransitGatewayPeeringAttachments",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let filters = Filters::new(&input.filters);
        let ids = input.transit_gateway_attachment_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::TransitGatewayAttachment
                .check_all(&ids, |id| r.transit_gateway_attachments.get(id).is_some_and(|a| a.peering.is_some()))?;
            let mut out = Vec::new();
            for a in r.transit_gateway_attachments.values() {
                let Some(p) = &a.peering else { continue };
                let id = p.transit_gateway_attachment_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let req = p.requester_tgw_info.clone().unwrap_or_default();
                let acc = p.accepter_tgw_info.clone().unwrap_or_default();
                let ok = filters.matches(p.tags.as_ref(), |name| {
                    Some(match name {
                        "transit-gateway-attachment-id" => vec![id.clone()],
                        "local-owner-id" => s(&a.attachment.transit_gateway_owner_id),
                        "remote-owner-id" => s(&a.attachment.resource_owner_id),
                        "state" => s(&p.state),
                        "transit-gateway-id" => s(&a.attachment.transit_gateway_id),
                        "requester-transit-gateway-id" => s(&req.transit_gateway_id),
                        "accepter-transit-gateway-id" => s(&acc.transit_gateway_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(p.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeTransitGatewayPeeringAttachmentsResult {
                transit_gateway_peering_attachments: Some(items),
                next_token,
            })
        })
    }

    pub(crate) fn describe_transit_gateway_attachments_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTransitGatewayAttachmentsRequest,
    ) -> Result<t::DescribeTransitGatewayAttachmentsResult, ServiceError> {
        authorize(ctx, "DescribeTransitGatewayAttachments", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.transit_gateway_attachment_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::TransitGatewayAttachment.check_all(&ids, |id| r.transit_gateway_attachments.contains_key(id))?;
            let mut out = Vec::new();
            for rec in r.transit_gateway_attachments.values() {
                let a = &rec.attachment;
                let id = a.transit_gateway_attachment_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let assoc = a.association.clone().unwrap_or_default();
                let ok = filters.matches(a.tags.as_ref(), |name| {
                    Some(match name {
                        "association.state" => s(&assoc.state),
                        "association.transit-gateway-route-table-id" => s(&assoc.transit_gateway_route_table_id),
                        "resource-id" => s(&a.resource_id),
                        "resource-owner-id" => s(&a.resource_owner_id),
                        "resource-type" => s(&a.resource_type),
                        "state" => s(&a.state),
                        "transit-gateway-attachment-id" => vec![id.clone()],
                        "transit-gateway-id" => s(&a.transit_gateway_id),
                        "transit-gateway-owner-id" => s(&a.transit_gateway_owner_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(a.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeTransitGatewayAttachmentsResult { transit_gateway_attachments: Some(items), next_token })
        })
    }

    // ---- route tables ------------------------------------------------------------------------------

    pub(crate) fn create_transit_gateway_route_table_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTransitGatewayRouteTableRequest,
    ) -> Result<t::CreateTransitGatewayRouteTableResult, ServiceError> {
        let tags =
            tags_for(&input.tag_specifications, "transit-gateway-route-table", &["transit-gateway-route-table"])?;
        self.tgw_authorize(ctx, "CreateTransitGatewayRouteTable", &input.transit_gateway_id, None)?;
        authorize_create(
            ctx,
            "CreateTransitGatewayRouteTable",
            "transit-gateway-route-table",
            &tags,
            &[],
            input.dry_run,
        )?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let id = new_id("tgw-rtb");
            let table = t::TransitGatewayRouteTable {
                transit_gateway_route_table_id: Some(id.clone()),
                transit_gateway_id: Some(input.transit_gateway_id.clone()),
                state: Some("available".into()),
                default_association_route_table: Some(false),
                default_propagation_route_table: Some(false),
                creation_time: Some(now),
                tags: some_tags(tags),
            };
            r.transit_gateway_route_tables
                .insert(id, TgwRouteTableRecord { table: table.clone(), ..Default::default() });
            let mut out = table;
            out.state = Some("pending".into());
            Ok(t::CreateTransitGatewayRouteTableResult { transit_gateway_route_table: Some(out) })
        })
    }

    pub(crate) fn delete_transit_gateway_route_table_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTransitGatewayRouteTableRequest,
    ) -> Result<t::DeleteTransitGatewayRouteTableResult, ServiceError> {
        let id = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "DeleteTransitGatewayRouteTable", &id, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let t =
                r.transit_gateway_route_tables.get(&id).ok_or_else(|| Kind::TransitGatewayRouteTable.not_found(&id))?;
            if t.table.default_association_route_table == Some(true)
                || t.table.default_propagation_route_table == Some(true)
            {
                return Err(err(
                    "IncorrectState",
                    format!("{id} is the default association or propagation route table of its transit gateway."),
                ));
            }
            if !t.associations.is_empty() {
                return Err(err("IncorrectState", format!("{id} has associations: {}", t.associations.join(", "))));
            }
            let t = r.transit_gateway_route_tables.get_mut(&id).expect("checked");
            t.table.state = Some("deleted".into());
            t.propagations.clear();
            let mut out = t.table.clone();
            out.state = Some("deleting".into());
            r.deleted_at.insert(id.clone(), now);
            Ok(t::DeleteTransitGatewayRouteTableResult { transit_gateway_route_table: Some(out) })
        })
    }

    pub(crate) fn describe_transit_gateway_route_tables_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTransitGatewayRouteTablesRequest,
    ) -> Result<t::DescribeTransitGatewayRouteTablesResult, ServiceError> {
        authorize(ctx, "DescribeTransitGatewayRouteTables", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.transit_gateway_route_table_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::TransitGatewayRouteTable.check_all(&ids, |id| r.transit_gateway_route_tables.contains_key(id))?;
            let mut out = Vec::new();
            for rec in r.transit_gateway_route_tables.values() {
                let tb = &rec.table;
                let id = tb.transit_gateway_route_table_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let ok = filters.matches(tb.tags.as_ref(), |name| {
                    Some(match name {
                        "default-association-route-table" => crate::util::b(tb.default_association_route_table),
                        "default-propagation-route-table" => crate::util::b(tb.default_propagation_route_table),
                        "state" => s(&tb.state),
                        "transit-gateway-id" => s(&tb.transit_gateway_id),
                        "transit-gateway-route-table-id" => vec![id.clone()],
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(tb.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeTransitGatewayRouteTablesResult { transit_gateway_route_tables: Some(items), next_token })
        })
    }

    /// Check that a route table and an attachment exist and belong to the
    /// same transit gateway.
    fn table_and_attachment(r: &RegionState, rtb: &str, att: &str) -> Result<(), ServiceError> {
        let table = r
            .transit_gateway_route_tables
            .get(rtb)
            .filter(|t| is_live(&t.table.state))
            .ok_or_else(|| Kind::TransitGatewayRouteTable.not_found(rtb))?;
        let a = r
            .transit_gateway_attachments
            .get(att)
            .filter(|a| is_live(&a.attachment.state))
            .ok_or_else(|| Kind::TransitGatewayAttachment.not_found(att))?;
        if a.attachment.transit_gateway_id != table.table.transit_gateway_id {
            return Err(invalid_parameter(format!(
                "Transit Gateway Attachment {att} and Route Table {rtb} belong to different Transit Gateways."
            )));
        }
        Ok(())
    }

    pub(crate) fn associate_transit_gateway_route_table_op(
        &self,
        ctx: &RequestContext,
        input: t::AssociateTransitGatewayRouteTableRequest,
    ) -> Result<t::AssociateTransitGatewayRouteTableResult, ServiceError> {
        let (rtb, att) = (input.transit_gateway_route_table_id.clone(), input.transit_gateway_attachment_id.clone());
        self.tgw_rtb_authorize(ctx, "AssociateTransitGatewayRouteTable", &rtb, input.dry_run)?;
        Kind::TransitGatewayAttachment.check(&att)?;
        self.with_region(ctx, |r| {
            Self::table_and_attachment(r, &rtb, &att)?;
            if let Some(existing) = r.transit_gateway_attachments[&att].attachment.association.clone() {
                return Err(err(
                    "Resource.AlreadyAssociated",
                    format!(
                        "Transit Gateway Attachment {att} is already associated to a route table {}.",
                        existing.transit_gateway_route_table_id.unwrap_or_default()
                    ),
                ));
            }
            associate(r, &rtb, &att);
            Ok(t::AssociateTransitGatewayRouteTableResult {
                association: Some(association_view(r, &rtb, &att, "associating")),
            })
        })
    }

    pub(crate) fn disassociate_transit_gateway_route_table_op(
        &self,
        ctx: &RequestContext,
        input: t::DisassociateTransitGatewayRouteTableRequest,
    ) -> Result<t::DisassociateTransitGatewayRouteTableResult, ServiceError> {
        let (rtb, att) = (input.transit_gateway_route_table_id.clone(), input.transit_gateway_attachment_id.clone());
        self.tgw_rtb_authorize(ctx, "DisassociateTransitGatewayRouteTable", &rtb, input.dry_run)?;
        Kind::TransitGatewayAttachment.check(&att)?;
        self.with_region(ctx, |r| {
            Self::table_and_attachment(r, &rtb, &att)?;
            let table = r.transit_gateway_route_tables.get_mut(&rtb).expect("checked");
            if !table.associations.iter().any(|a| a == &att) {
                return Err(err(
                    "InvalidAssociation.NotFound",
                    format!("Transit Gateway Attachment {att} is not associated with route table {rtb}."),
                ));
            }
            table.associations.retain(|a| a != &att);
            if let Some(a) = r.transit_gateway_attachments.get_mut(&att) {
                a.attachment.association = None;
            }
            Ok(t::DisassociateTransitGatewayRouteTableResult {
                association: Some(association_view(r, &rtb, &att, "disassociating")),
            })
        })
    }

    pub(crate) fn enable_transit_gateway_route_table_propagation_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableTransitGatewayRouteTablePropagationRequest,
    ) -> Result<t::EnableTransitGatewayRouteTablePropagationResult, ServiceError> {
        let rtb = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "EnableTransitGatewayRouteTablePropagation", &rtb, input.dry_run)?;
        let att = input
            .transit_gateway_attachment_id
            .clone()
            .ok_or_else(|| crate::util::missing_parameter("TransitGatewayAttachmentId"))?;
        Kind::TransitGatewayAttachment.check(&att)?;
        self.with_region(ctx, |r| {
            Self::table_and_attachment(r, &rtb, &att)?;
            let table = r.transit_gateway_route_tables.get_mut(&rtb).expect("checked");
            if table.propagations.iter().any(|a| a == &att) {
                return Err(err(
                    "TransitGatewayRouteTablePropagation.Duplicate",
                    format!("Propagation for {att} already exists in route table {rtb}."),
                ));
            }
            table.propagations.push(att.clone());
            Ok(t::EnableTransitGatewayRouteTablePropagationResult {
                propagation: Some(propagation_view(r, &rtb, &att, "enabling")),
            })
        })
    }

    pub(crate) fn disable_transit_gateway_route_table_propagation_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableTransitGatewayRouteTablePropagationRequest,
    ) -> Result<t::DisableTransitGatewayRouteTablePropagationResult, ServiceError> {
        let rtb = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "DisableTransitGatewayRouteTablePropagation", &rtb, input.dry_run)?;
        let att = input
            .transit_gateway_attachment_id
            .clone()
            .ok_or_else(|| crate::util::missing_parameter("TransitGatewayAttachmentId"))?;
        Kind::TransitGatewayAttachment.check(&att)?;
        self.with_region(ctx, |r| {
            Self::table_and_attachment(r, &rtb, &att)?;
            let table = r.transit_gateway_route_tables.get_mut(&rtb).expect("checked");
            if !table.propagations.iter().any(|a| a == &att) {
                return Err(err(
                    "TransitGatewayRouteTablePropagation.NotFound",
                    format!("Propagation for {att} does not exist in route table {rtb}."),
                ));
            }
            table.propagations.retain(|a| a != &att);
            Ok(t::DisableTransitGatewayRouteTablePropagationResult {
                propagation: Some(propagation_view(r, &rtb, &att, "disabling")),
            })
        })
    }

    pub(crate) fn get_transit_gateway_route_table_associations_op(
        &self,
        ctx: &RequestContext,
        input: t::GetTransitGatewayRouteTableAssociationsRequest,
    ) -> Result<t::GetTransitGatewayRouteTableAssociationsResult, ServiceError> {
        let rtb = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "GetTransitGatewayRouteTableAssociations", &rtb, input.dry_run)?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let table = r
                .transit_gateway_route_tables
                .get(&rtb)
                .ok_or_else(|| Kind::TransitGatewayRouteTable.not_found(&rtb))?;
            let mut out = Vec::new();
            for att in &table.associations {
                let v = association_view(r, &rtb, att, "associated");
                let ok = filters.matches(None, |name| {
                    Some(match name {
                        "resource-id" => s(&v.resource_id),
                        "resource-type" => s(&v.resource_type),
                        "transit-gateway-attachment-id" => s(&v.transit_gateway_attachment_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(t::TransitGatewayRouteTableAssociation {
                        transit_gateway_attachment_id: v.transit_gateway_attachment_id,
                        resource_id: v.resource_id,
                        resource_type: v.resource_type,
                        state: v.state,
                    });
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::GetTransitGatewayRouteTableAssociationsResult { associations: Some(items), next_token })
        })
    }

    pub(crate) fn get_transit_gateway_route_table_propagations_op(
        &self,
        ctx: &RequestContext,
        input: t::GetTransitGatewayRouteTablePropagationsRequest,
    ) -> Result<t::GetTransitGatewayRouteTablePropagationsResult, ServiceError> {
        let rtb = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "GetTransitGatewayRouteTablePropagations", &rtb, input.dry_run)?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let table = r
                .transit_gateway_route_tables
                .get(&rtb)
                .ok_or_else(|| Kind::TransitGatewayRouteTable.not_found(&rtb))?;
            let mut out = Vec::new();
            for att in &table.propagations {
                let v = propagation_view(r, &rtb, att, "enabled");
                let ok = filters.matches(None, |name| {
                    Some(match name {
                        "resource-id" => s(&v.resource_id),
                        "resource-type" => s(&v.resource_type),
                        "transit-gateway-attachment-id" => s(&v.transit_gateway_attachment_id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(t::TransitGatewayRouteTablePropagation {
                        transit_gateway_attachment_id: v.transit_gateway_attachment_id,
                        resource_id: v.resource_id,
                        resource_type: v.resource_type,
                        state: v.state,
                        transit_gateway_route_table_announcement_id: None,
                    });
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::GetTransitGatewayRouteTablePropagationsResult {
                transit_gateway_route_table_propagations: Some(items),
                next_token,
            })
        })
    }

    pub(crate) fn get_transit_gateway_attachment_propagations_op(
        &self,
        ctx: &RequestContext,
        input: t::GetTransitGatewayAttachmentPropagationsRequest,
    ) -> Result<t::GetTransitGatewayAttachmentPropagationsResult, ServiceError> {
        let att = input.transit_gateway_attachment_id.clone();
        self.attachment_authorize(ctx, "GetTransitGatewayAttachmentPropagations", &att, input.dry_run)?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for table in r.transit_gateway_route_tables.values() {
                if !table.propagations.iter().any(|a| a == &att) {
                    continue;
                }
                let id = table.table.transit_gateway_route_table_id.clone();
                let ok = filters.matches(None, |name| {
                    Some(match name {
                        "transit-gateway-route-table-id" => s(&id),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(t::TransitGatewayAttachmentPropagation {
                        transit_gateway_route_table_id: id,
                        state: Some("enabled".into()),
                    });
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::GetTransitGatewayAttachmentPropagationsResult {
                transit_gateway_attachment_propagations: Some(items),
                next_token,
            })
        })
    }

    // ---- routes ------------------------------------------------------------------------------------

    fn static_route(
        r: &RegionState,
        rtb: &str,
        cidr: &str,
        att: &Option<String>,
        blackhole: Option<bool>,
    ) -> Result<t::TransitGatewayRoute, ServiceError> {
        if Cidr::parse(cidr).is_none() && !cidr.contains(':') {
            return Err(invalid_parameter(format!(
                "Value ({cidr}) for parameter destinationCidrBlock is invalid. This is not a valid CIDR block."
            )));
        }
        let black = blackhole == Some(true);
        let attachments = match (att, black) {
            (Some(_), true) => {
                return Err(err(
                    "InvalidParameterCombination",
                    "The parameters TransitGatewayAttachmentId and Blackhole are mutually exclusive.",
                ))
            }
            (None, false) => return Err(crate::util::missing_parameter("TransitGatewayAttachmentId")),
            (None, true) => None,
            (Some(a), false) => {
                Kind::TransitGatewayAttachment.check(a)?;
                Self::table_and_attachment(r, rtb, a)?;
                let rec = &r.transit_gateway_attachments[a].attachment;
                Some(vec![t::TransitGatewayRouteAttachment {
                    resource_id: rec.resource_id.clone(),
                    transit_gateway_attachment_id: Some(a.clone()),
                    resource_type: rec.resource_type.clone(),
                }])
            }
        };
        Ok(t::TransitGatewayRoute {
            destination_cidr_block: Some(cidr.into()),
            transit_gateway_attachments: attachments,
            r#type: Some("static".into()),
            state: Some(if black { "blackhole" } else { "active" }.into()),
            ..Default::default()
        })
    }

    pub(crate) fn create_transit_gateway_route_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTransitGatewayRouteRequest,
    ) -> Result<t::CreateTransitGatewayRouteResult, ServiceError> {
        let rtb = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "CreateTransitGatewayRoute", &rtb, input.dry_run)?;
        self.with_region(ctx, |r| {
            let route = Self::static_route(
                r,
                &rtb,
                &input.destination_cidr_block,
                &input.transit_gateway_attachment_id,
                input.blackhole,
            )?;
            let table = r.transit_gateway_route_tables.get_mut(&rtb).expect("checked");
            if table.routes.iter().any(|x| x.destination_cidr_block == route.destination_cidr_block) {
                return Err(err(
                    "RouteAlreadyExists",
                    format!(
                        "Route {} already exists in Transit Gateway Route Table {rtb}.",
                        input.destination_cidr_block
                    ),
                ));
            }
            table.routes.push(route.clone());
            Ok(t::CreateTransitGatewayRouteResult { route: Some(route) })
        })
    }

    pub(crate) fn replace_transit_gateway_route_op(
        &self,
        ctx: &RequestContext,
        input: t::ReplaceTransitGatewayRouteRequest,
    ) -> Result<t::ReplaceTransitGatewayRouteResult, ServiceError> {
        let rtb = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "ReplaceTransitGatewayRoute", &rtb, input.dry_run)?;
        self.with_region(ctx, |r| {
            let route = Self::static_route(
                r,
                &rtb,
                &input.destination_cidr_block,
                &input.transit_gateway_attachment_id,
                input.blackhole,
            )?;
            let table = r.transit_gateway_route_tables.get_mut(&rtb).expect("checked");
            let slot =
                table.routes.iter_mut().find(|x| x.destination_cidr_block == route.destination_cidr_block).ok_or_else(
                    || {
                        err(
                            "InvalidRoute.NotFound",
                            format!(
                                "No route with destination-cidr-block {} in Transit Gateway Route Table {rtb}",
                                input.destination_cidr_block
                            ),
                        )
                    },
                )?;
            *slot = route.clone();
            Ok(t::ReplaceTransitGatewayRouteResult { route: Some(route) })
        })
    }

    pub(crate) fn delete_transit_gateway_route_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTransitGatewayRouteRequest,
    ) -> Result<t::DeleteTransitGatewayRouteResult, ServiceError> {
        let rtb = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "DeleteTransitGatewayRoute", &rtb, input.dry_run)?;
        self.with_region(ctx, |r| {
            let table = r
                .transit_gateway_route_tables
                .get_mut(&rtb)
                .ok_or_else(|| Kind::TransitGatewayRouteTable.not_found(&rtb))?;
            let idx = table
                .routes
                .iter()
                .position(|x| x.destination_cidr_block.as_deref() == Some(input.destination_cidr_block.as_str()))
                .ok_or_else(|| {
                    err(
                        "InvalidRoute.NotFound",
                        format!(
                            "No route with destination-cidr-block {} in Transit Gateway Route Table {rtb}",
                            input.destination_cidr_block
                        ),
                    )
                })?;
            let mut route = table.routes.remove(idx);
            route.state = Some("deleted".into());
            Ok(t::DeleteTransitGatewayRouteResult { route: Some(route) })
        })
    }

    pub(crate) fn search_transit_gateway_routes_op(
        &self,
        ctx: &RequestContext,
        input: t::SearchTransitGatewayRoutesRequest,
    ) -> Result<t::SearchTransitGatewayRoutesResult, ServiceError> {
        let rtb = input.transit_gateway_route_table_id.clone();
        self.tgw_rtb_authorize(ctx, "SearchTransitGatewayRoutes", &rtb, input.dry_run)?;
        // The route-search filters are matched on CIDR arithmetic below.
        let plain: Vec<t::Filter> = input
            .filters
            .iter()
            .filter(|f| !f.name.as_deref().is_some_and(|n| n.starts_with("route-search.")))
            .cloned()
            .collect();
        let filters = Filters::new(&Some(plain));
        let wanted = |name: &str| -> Vec<String> {
            input
                .filters
                .iter()
                .filter(|f| f.name.as_deref() == Some(name))
                .flat_map(|f| f.values.clone().unwrap_or_default())
                .collect()
        };
        let exact = wanted("route-search.exact-match");
        let longest = wanted("route-search.longest-prefix-match");
        let subnet_of = wanted("route-search.subnet-of-match");
        let supernet_of = wanted("route-search.supernet-of-match");
        let parse_all = |v: &[String]| -> Result<Vec<Cidr>, ServiceError> {
            v.iter().map(|c| Cidr::parse(c).ok_or_else(|| invalid_parameter(format!("Invalid CIDR {c}")))).collect()
        };
        let (longest_c, subnet_c, supernet_c) =
            (parse_all(&longest)?, parse_all(&subnet_of)?, parse_all(&supernet_of)?);
        self.with_region(ctx, |r| {
            let table = r
                .transit_gateway_route_tables
                .get(&rtb)
                .ok_or_else(|| Kind::TransitGatewayRouteTable.not_found(&rtb))?;
            let mut out = Vec::new();
            for route in routes_of(r, table) {
                let dest = route.destination_cidr_block.clone().unwrap_or_default();
                let dc = Cidr::parse(&dest);
                let atts = route.transit_gateway_attachments.clone().unwrap_or_default();
                let ok = filters.matches(None, |name| {
                    Some(match name {
                        "attachment.transit-gateway-attachment-id" => {
                            atts.iter().filter_map(|a| a.transit_gateway_attachment_id.clone()).collect()
                        }
                        "attachment.resource-id" => atts.iter().filter_map(|a| a.resource_id.clone()).collect(),
                        "attachment.resource-type" => atts.iter().filter_map(|a| a.resource_type.clone()).collect(),
                        "prefix-list-id" => s(&route.prefix_list_id),
                        "state" => s(&route.state),
                        "type" => s(&route.r#type),
                        _ => return None,
                    })
                })?;
                if !ok {
                    continue;
                }
                if !exact.is_empty() && !exact.contains(&dest) {
                    continue;
                }
                if !subnet_c.is_empty() && !dc.is_some_and(|d| subnet_c.iter().any(|c| c.contains_cidr(&d))) {
                    continue;
                }
                if !supernet_c.is_empty() && !dc.is_some_and(|d| supernet_c.iter().any(|c| d.contains_cidr(c))) {
                    continue;
                }
                if !longest_c.is_empty() && !dc.is_some_and(|d| longest_c.iter().any(|c| d.contains_cidr(c))) {
                    continue;
                }
                out.push(route);
            }
            if !longest_c.is_empty() {
                // Only the most specific match for each searched address.
                let best = out
                    .iter()
                    .filter_map(|r| r.destination_cidr_block.as_deref().and_then(Cidr::parse))
                    .map(|c| c.prefix)
                    .max();
                out.retain(|r| r.destination_cidr_block.as_deref().and_then(Cidr::parse).map(|c| c.prefix) == best);
            }
            let max = input.max_results.unwrap_or(1000).clamp(5, 1000) as usize;
            let more = out.len() > max;
            out.truncate(max);
            Ok(t::SearchTransitGatewayRoutesResult {
                routes: Some(out),
                additional_routes_available: Some(more),
                next_token: None,
            })
        })
    }
}

impl State {
    /// Whether `tgw` (in this account and Region) has a live VPC attachment
    /// for `vpc`.
    pub fn tgw_attached_to(r: &RegionState, tgw: &str, vpc: &str) -> bool {
        r.transit_gateway_attachments.values().any(|a| {
            a.attachment.transit_gateway_id.as_deref() == Some(tgw)
                && a.attachment.resource_id.as_deref() == Some(vpc)
                && a.attachment.state.as_deref() == Some("available")
        })
    }
}
