//! VPC peering connections, within and across accounts and Regions.
//!
//! Each side's account and Region keeps its own copy of the connection
//! (with its own tags); every change is written to both.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::ops::gateways::{authorize_create, authorize_on};
use crate::state::RegionState;
use crate::util::{
    arn, authorize, err, missing_parameter, new_id, paginate, s, some_tags, tags_for, Cidr, Filters, Kind,
};
use crate::{account_of, Ec2};

fn status(code: &str, message: impl Into<String>) -> Option<t::VpcPeeringConnectionStateReason> {
    Some(t::VpcPeeringConnectionStateReason { code: Some(code.into()), message: Some(message.into()) })
}

fn code(p: &t::VpcPeeringConnection) -> String {
    p.status.as_ref().and_then(|s| s.code.clone()).unwrap_or_default()
}

fn no_options() -> Option<t::VpcPeeringConnectionOptionsDescription> {
    Some(t::VpcPeeringConnectionOptionsDescription {
        allow_dns_resolution_from_remote_vpc: Some(false),
        allow_egress_from_local_classic_link_to_remote_vpc: Some(false),
        allow_egress_from_local_vpc_to_remote_classic_link: Some(false),
    })
}

/// The VPC's addresses as a peering connection shows them.
fn vpc_info(r: &RegionState, vpc: &str, owner: &str, region: &str, full: bool) -> t::VpcPeeringConnectionVpcInfo {
    let mut info = t::VpcPeeringConnectionVpcInfo {
        owner_id: Some(owner.into()),
        vpc_id: Some(vpc.into()),
        region: Some(region.into()),
        ..Default::default()
    };
    if !full {
        return info;
    }
    if let Some(v) = r.vpcs.get(vpc) {
        info.cidr_block = v.vpc.cidr_block.clone();
        let blocks: Vec<t::CidrBlock> = v
            .vpc
            .cidr_block_association_set
            .iter()
            .flatten()
            .filter(|c| c.cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) == Some("associated"))
            .map(|c| t::CidrBlock { cidr_block: c.cidr_block.clone() })
            .collect();
        info.cidr_block_set = Some(blocks);
        let v6: Vec<t::Ipv6CidrBlock> = v
            .vpc
            .ipv6_cidr_block_association_set
            .iter()
            .flatten()
            .filter(|c| c.ipv6_cidr_block_state.as_ref().and_then(|s| s.state.as_deref()) == Some("associated"))
            .map(|c| t::Ipv6CidrBlock { ipv6_cidr_block: c.ipv6_cidr_block.clone() })
            .collect();
        if !v6.is_empty() {
            info.ipv6_cidr_block_set = Some(v6);
        }
        info.peering_options = no_options();
    }
    info
}

fn cidrs(info: &t::VpcPeeringConnectionVpcInfo) -> Vec<Cidr> {
    info.cidr_block_set.iter().flatten().filter_map(|c| c.cidr_block.as_deref().and_then(Cidr::parse)).collect()
}

impl Ec2 {
    /// Both sides of a connection: (account, Region) of requester and accepter.
    fn sides(p: &t::VpcPeeringConnection) -> [(String, String); 2] {
        let req = p.requester_vpc_info.clone().unwrap_or_default();
        let acc = p.accepter_vpc_info.clone().unwrap_or_default();
        [
            (req.owner_id.unwrap_or_default(), req.region.unwrap_or_default()),
            (acc.owner_id.unwrap_or_default(), acc.region.unwrap_or_default()),
        ]
    }

    /// Store `p` on both sides, keeping each side's own tags.
    fn put_peering(&self, ctx: &RequestContext, p: &t::VpcPeeringConnection) {
        let id = p.vpc_peering_connection_id.clone().unwrap_or_default();
        let me = (account_of(ctx), ctx.region.clone());
        let sides = Self::sides(p);
        for (i, side) in sides.iter().enumerate() {
            if i == 1 && sides[0] == sides[1] {
                break;
            }
            self.with_region_of(&side.0, &side.1, ctx, |r| {
                let mut copy = p.clone();
                if *side != me {
                    copy.tags = r.vpc_peering_connections.get(&id).and_then(|x| x.tags.clone());
                }
                if copy.status.as_ref().and_then(|s| s.code.as_deref()) == Some("deleted") {
                    r.deleted_at.insert(id.clone(), ctx.received_at);
                }
                r.vpc_peering_connections.insert(id.clone(), copy);
            });
        }
    }

    fn pcx_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
    ) -> Result<t::VpcPeeringConnection, ServiceError> {
        authorize_on(
            self,
            ctx,
            action,
            Kind::VpcPeeringConnection,
            "vpc-peering-connection",
            id,
            |r| r.vpc_peering_connections.get(id).filter(|p| code(p) != "deleted").map(|p| p.tags.clone()),
            dry_run,
        )?;
        self.with_region(ctx, |r| r.vpc_peering_connections.get(id).cloned())
            .ok_or_else(|| Kind::VpcPeeringConnection.not_found(id))
    }

    pub(crate) fn create_vpc_peering_connection_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateVpcPeeringConnectionRequest,
    ) -> Result<t::CreateVpcPeeringConnectionResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "vpc-peering-connection", &["vpc-peering-connection"])?;
        let account = account_of(ctx);
        Kind::Vpc.check(&input.vpc_id)?;
        let peer_vpc = input.peer_vpc_id.clone().ok_or_else(|| missing_parameter("peerVpcId"))?;
        Kind::Vpc.check(&peer_vpc)?;
        let peer_owner = input.peer_owner_id.clone().unwrap_or_else(|| account.clone());
        let peer_region = input.peer_region.clone().unwrap_or_else(|| ctx.region.clone());
        authorize_create(
            ctx,
            "CreateVpcPeeringConnection",
            "vpc-peering-connection",
            &tags,
            &[arn(ctx, &account, &format!("vpc/{}", input.vpc_id))],
            input.dry_run,
        )?;
        let requester = self.with_region(ctx, |r| {
            r.vpcs.contains_key(&input.vpc_id).then(|| vpc_info(r, &input.vpc_id, &account, &ctx.region, true))
        });
        let requester = requester.ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?;
        let same_side = peer_owner == account && peer_region == ctx.region;
        let accepter_full = self.with_region_of(&peer_owner, &peer_region, ctx, |r| {
            r.vpcs.contains_key(&peer_vpc).then(|| vpc_info(r, &peer_vpc, &peer_owner, &peer_region, true))
        });
        if same_side && accepter_full.is_none() {
            return Err(Kind::Vpc.not_found(&peer_vpc));
        }
        if same_side && peer_vpc == input.vpc_id {
            return Err(err(
                "InvalidVpcPeeringConnection.Duplicate",
                format!("A VPC cannot be peered with itself: {peer_vpc}"),
            ));
        }
        let now = ctx.received_at;
        let id = new_id("pcx");
        let overlap = accepter_full.as_ref().is_some_and(|a| {
            let theirs = cidrs(a);
            cidrs(&requester).iter().any(|c| theirs.iter().any(|o| c.overlaps(o)))
        });
        let mut p = t::VpcPeeringConnection {
            vpc_peering_connection_id: Some(id.clone()),
            requester_vpc_info: Some(requester),
            accepter_vpc_info: Some(t::VpcPeeringConnectionVpcInfo {
                owner_id: Some(peer_owner.clone()),
                vpc_id: Some(peer_vpc.clone()),
                region: Some(peer_region.clone()),
                ..Default::default()
            }),
            expiration_time: Some(now + chrono::Duration::days(7)),
            status: status("pending-acceptance", format!("Pending Acceptance by {peer_owner}")),
            tags: some_tags(tags),
        };
        if accepter_full.is_none() || overlap {
            p.status = status("failed", "Failed due to incorrect VPC-ID, Account ID, or overlapping CIDR range");
            p.expiration_time = None;
        }
        self.put_peering(ctx, &p);
        let mut out = p;
        out.status = status("initiating-request", format!("Initiating Request to {peer_owner}"));
        Ok(t::CreateVpcPeeringConnectionResult { vpc_peering_connection: Some(out) })
    }

    pub(crate) fn accept_vpc_peering_connection_op(
        &self,
        ctx: &RequestContext,
        input: t::AcceptVpcPeeringConnectionRequest,
    ) -> Result<t::AcceptVpcPeeringConnectionResult, ServiceError> {
        let id = input.vpc_peering_connection_id.clone();
        let mut p = self.pcx_authorize(ctx, "AcceptVpcPeeringConnection", &id, input.dry_run)?;
        let account = account_of(ctx);
        let [_, acc] = Self::sides(&p);
        if acc != (account.clone(), ctx.region.clone()) {
            return Err(err("OperationNotPermitted", format!("User {account} cannot accept peering {id}")));
        }
        let c = code(&p);
        if c != "pending-acceptance" {
            return Err(err(
                "InvalidStateTransition",
                format!("Invalid state transition for {id}, attempted to transition from {c} to active"),
            ));
        }
        let vpc = p.accepter_vpc_info.as_ref().and_then(|a| a.vpc_id.clone()).unwrap_or_default();
        let info = self.with_region(ctx, |r| vpc_info(r, &vpc, &account, &ctx.region, true));
        p.accepter_vpc_info = Some(info);
        p.status = status("active", "Active");
        p.expiration_time = None;
        self.put_peering(ctx, &p);
        let mut out = p;
        out.status = status("provisioning", "Provisioning");
        Ok(t::AcceptVpcPeeringConnectionResult { vpc_peering_connection: Some(out) })
    }

    pub(crate) fn reject_vpc_peering_connection_op(
        &self,
        ctx: &RequestContext,
        input: t::RejectVpcPeeringConnectionRequest,
    ) -> Result<t::RejectVpcPeeringConnectionResult, ServiceError> {
        let id = input.vpc_peering_connection_id.clone();
        let mut p = self.pcx_authorize(ctx, "RejectVpcPeeringConnection", &id, input.dry_run)?;
        let account = account_of(ctx);
        let [_, acc] = Self::sides(&p);
        if acc != (account.clone(), ctx.region.clone()) {
            return Err(err("OperationNotPermitted", format!("User {account} cannot reject peering {id}")));
        }
        let c = code(&p);
        if c != "pending-acceptance" {
            return Err(err(
                "InvalidStateTransition",
                format!("Invalid state transition for {id}, attempted to transition from {c} to rejected"),
            ));
        }
        p.status = status("rejected", format!("Rejected by {account}"));
        p.expiration_time = None;
        self.put_peering(ctx, &p);
        Ok(t::RejectVpcPeeringConnectionResult { r#return: Some(true) })
    }

    pub(crate) fn delete_vpc_peering_connection_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteVpcPeeringConnectionRequest,
    ) -> Result<t::DeleteVpcPeeringConnectionResult, ServiceError> {
        let id = input.vpc_peering_connection_id.clone();
        let mut p = self.pcx_authorize(ctx, "DeleteVpcPeeringConnection", &id, input.dry_run)?;
        let account = account_of(ctx);
        let c = code(&p);
        let [req, _] = Self::sides(&p);
        let requester = req == (account.clone(), ctx.region.clone());
        // The accepter rejects a pending request rather than deleting it.
        let allowed = c == "active" || (c == "pending-acceptance" && requester) || c == "failed";
        if !allowed {
            return Err(err(
                "InvalidStateTransition",
                format!("Invalid state transition for {id}, attempted to transition from {c} to deleted"),
            ));
        }
        p.status = status("deleted", format!("Deleted by {account}"));
        p.expiration_time = None;
        self.put_peering(ctx, &p);
        // Routes through it become blackholes on both sides.
        for (acct, region) in Self::sides(&p) {
            self.with_region_of(&acct, &region, ctx, |r| {
                crate::ops::gateways::blackhole_routes(r, |route| {
                    route.vpc_peering_connection_id.as_deref() == Some(id.as_str())
                })
            });
        }
        Ok(t::DeleteVpcPeeringConnectionResult { r#return: Some(true) })
    }

    pub(crate) fn describe_vpc_peering_connections_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcPeeringConnectionsRequest,
    ) -> Result<t::DescribeVpcPeeringConnectionsResult, ServiceError> {
        authorize(ctx, "DescribeVpcPeeringConnections", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.vpc_peering_connection_ids.clone().unwrap_or_default();
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            // Requests nobody answered in a week expire.
            for p in r.vpc_peering_connections.values_mut() {
                if code(p) == "pending-acceptance" && p.expiration_time.is_some_and(|e| e <= now) {
                    p.status = status("expired", "Expired");
                    p.expiration_time = None;
                }
            }
            Kind::VpcPeeringConnection.check_all(&ids, |id| r.vpc_peering_connections.contains_key(id))?;
            let mut out = Vec::new();
            for p in r.vpc_peering_connections.values() {
                let id = p.vpc_peering_connection_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let req = p.requester_vpc_info.clone().unwrap_or_default();
                let acc = p.accepter_vpc_info.clone().unwrap_or_default();
                let blocks = |i: &t::VpcPeeringConnectionVpcInfo| -> Vec<String> {
                    i.cidr_block_set.iter().flatten().filter_map(|c| c.cidr_block.clone()).collect()
                };
                let ok = filters.matches(p.tags.as_ref(), |name| {
                    Some(match name {
                        "accepter-vpc-info.cidr-block" => blocks(&acc),
                        "accepter-vpc-info.owner-id" => s(&acc.owner_id),
                        "accepter-vpc-info.vpc-id" => s(&acc.vpc_id),
                        "expiration-time" => p.expiration_time.map(|t| t.to_rfc3339()).into_iter().collect(),
                        "requester-vpc-info.cidr-block" => blocks(&req),
                        "requester-vpc-info.owner-id" => s(&req.owner_id),
                        "requester-vpc-info.vpc-id" => s(&req.vpc_id),
                        "status-code" => vec![code(p)],
                        "status-message" => p.status.as_ref().and_then(|s| s.message.clone()).into_iter().collect(),
                        "vpc-peering-connection-id" => vec![id.clone()],
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(p.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeVpcPeeringConnectionsResult { vpc_peering_connections: Some(items), next_token })
        })
    }

    pub(crate) fn modify_vpc_peering_connection_options_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVpcPeeringConnectionOptionsRequest,
    ) -> Result<t::ModifyVpcPeeringConnectionOptionsResult, ServiceError> {
        let id = input.vpc_peering_connection_id.clone();
        let mut p = self.pcx_authorize(ctx, "ModifyVpcPeeringConnectionOptions", &id, input.dry_run)?;
        let account = account_of(ctx);
        if code(&p) != "active" {
            return Err(err(
                "InvalidStateTransition",
                format!("Peering connection {id} is not active; its options cannot be modified."),
            ));
        }
        let me = (account.clone(), ctx.region.clone());
        let [req, acc] = Self::sides(&p);
        if input.requester_peering_connection_options.is_some() && req != me {
            return Err(err(
                "OperationNotPermitted",
                format!("User {account} cannot modify the requester options of peering {id}"),
            ));
        }
        if input.accepter_peering_connection_options.is_some() && acc != me {
            return Err(err(
                "OperationNotPermitted",
                format!("User {account} cannot modify the accepter options of peering {id}"),
            ));
        }
        let apply = |info: &mut Option<t::VpcPeeringConnectionVpcInfo>,
                     o: &Option<t::PeeringConnectionOptionsRequest>| {
            let Some(o) = o else { return None };
            let info = info.get_or_insert_with(Default::default);
            let opts = info.peering_options.get_or_insert_with(|| no_options().expect("set"));
            if let Some(v) = o.allow_dns_resolution_from_remote_vpc {
                opts.allow_dns_resolution_from_remote_vpc = Some(v);
            }
            if let Some(v) = o.allow_egress_from_local_classic_link_to_remote_vpc {
                opts.allow_egress_from_local_classic_link_to_remote_vpc = Some(v);
            }
            if let Some(v) = o.allow_egress_from_local_vpc_to_remote_classic_link {
                opts.allow_egress_from_local_vpc_to_remote_classic_link = Some(v);
            }
            Some(t::PeeringConnectionOptions {
                allow_dns_resolution_from_remote_vpc: opts.allow_dns_resolution_from_remote_vpc,
                allow_egress_from_local_classic_link_to_remote_vpc: opts
                    .allow_egress_from_local_classic_link_to_remote_vpc,
                allow_egress_from_local_vpc_to_remote_classic_link: opts
                    .allow_egress_from_local_vpc_to_remote_classic_link,
            })
        };
        let requester = apply(&mut p.requester_vpc_info, &input.requester_peering_connection_options);
        let accepter = apply(&mut p.accepter_vpc_info, &input.accepter_peering_connection_options);
        self.put_peering(ctx, &p);
        Ok(t::ModifyVpcPeeringConnectionOptionsResult {
            accepter_peering_connection_options: accepter,
            requester_peering_connection_options: requester,
        })
    }
}
