//! Hosted zones, VPC associations and changes.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};
use rand::Rng;

use crate::generated::{errors, types};
use crate::names;
use crate::state::{record_key, vpc_key, State, Zone};
use crate::{arn, max_items, new_id, strip_id, Route53};

pub(crate) fn no_such_zone(id: &str) -> ServiceError {
    errors::no_such_hosted_zone(format!("No hosted zone found with ID: {id}"))
}

impl State {
    pub(crate) fn zone_mut(&mut self, id: &str) -> Result<&mut Zone, ServiceError> {
        self.zones.get_mut(id).ok_or_else(|| no_such_zone(id))
    }
}

impl Zone {
    pub(crate) fn wire(&self) -> types::HostedZone {
        types::HostedZone {
            id: format!("/hostedzone/{}", self.id),
            name: names::display(&self.name),
            caller_reference: self.caller_reference.clone(),
            config: Some(types::HostedZoneConfig { comment: self.comment.clone(), private_zone: self.private }),
            resource_record_set_count: Some(self.records.len() as i64),
            linked_service: None,
            features: self.accelerated_recovery.then(|| types::HostedZoneFeatures {
                accelerated_recovery_status: Some("ENABLED".into()),
                failure_reasons: None,
            }),
        }
    }

    fn delegation_set(&self) -> types::DelegationSet {
        types::DelegationSet {
            id: self.delegation_set_id.as_ref().map(|d| format!("/delegationset/{d}")),
            caller_reference: None,
            name_servers: self.name_servers.clone(),
        }
    }
}

pub(crate) fn name_servers() -> Vec<String> {
    let mut rng = rand::thread_rng();
    ["com", "net", "org", "co.uk"]
        .iter()
        .map(|tld| format!("ns-{}.awsdns-{:02}.{tld}", rng.gen_range(0..2048), rng.gen_range(0..64)))
        .collect()
}

pub(crate) fn check_vpc(vpc: &types::VPC) -> Result<(), ServiceError> {
    let id = vpc.vpc_id.as_deref().unwrap_or_default();
    if !id.starts_with("vpc-") || id.len() < 8 {
        return Err(errors::invalid_vpc_id(format!("The VPC ID '{id}' is invalid.")));
    }
    if vpc.vpc_region.is_none() {
        return Err(errors::invalid_input("Invalid request: VPCRegion is required"));
    }
    Ok(())
}

/// Route 53's answer for a VPC the caller's account doesn't have in that
/// Region.
pub(crate) fn unknown_vpc(vpc: &types::VPC) -> ServiceError {
    errors::invalid_vpc_id(format!(
        "The VPC: {} you provided is not authorized to make the association.",
        vpc.vpc_id.as_deref().unwrap_or_default()
    ))
}

fn same_vpc(a: &types::VPC, b: &types::VPC) -> bool {
    a.vpc_id == b.vpc_id && a.vpc_region == b.vpc_region
}

impl Route53 {
    pub(crate) fn create_hosted_zone(
        &self,
        ctx: &RequestContext,
        input: types::CreateHostedZoneRequest,
    ) -> Result<types::CreateHostedZoneResponse, ServiceError> {
        self.authorize(ctx, "CreateHostedZone", "*")?;
        if input.vpc.is_some() {
            // Creating a private zone also needs permission on the VPC.
            self.authorize(ctx, "AssociateVPCWithHostedZone", "*")?;
        }
        let name = names::normalize(&input.name)
            .filter(|n| n != ".")
            .ok_or_else(|| errors::invalid_domain_name(format!("{} is not a valid domain name.", input.name)))?;
        let private = input.vpc.is_some() || input.hosted_zone_config.as_ref().is_some_and(|c| c.private_zone);
        if private && input.vpc.is_none() {
            return Err(errors::invalid_input("Invalid request: Private hosted zones require a VPC."));
        }
        if let Some(vpc) = &input.vpc {
            check_vpc(vpc)?;
            if !self.vpc_exists(ctx, vpc) {
                return Err(unknown_vpc(vpc));
            }
        }
        let mut st = self.lock(ctx);
        let delegation_set_id = input.delegation_set_id.as_deref().map(|d| strip_id(d).to_string());
        if let Some(ds) = &delegation_set_id {
            if private {
                return Err(errors::invalid_input(
                    "Invalid request: A reusable delegation set cannot be used with a private hosted zone.",
                ));
            }
            if !st.delegation_sets.contains_key(ds) {
                return Err(errors::no_such_delegation_set(format!(
                    "A reusable delegation set with the specified ID does not exist: {ds}"
                )));
            }
            let in_use = st.zones.values().filter(|z| z.delegation_set_id.as_deref() == Some(ds.as_str()));
            if in_use.clone().any(|z| z.name == name) {
                return Err(errors::conflicting_domain_exists(format!(
                    "Cannot create hosted zone with DelegationSetId {ds} as the DNSName {} conflicts with existing ones sharing the delegation set",
                    input.name
                )));
            }
            if in_use.count() >= crate::limits::MAX_ZONES_BY_REUSABLE_DELEGATION_SET as usize {
                return Err(errors::delegation_set_not_available(format!(
                    "The delegation set {ds} has reached the limit of hosted zones."
                )));
            }
        }
        if st.zones.len() >= crate::limits::MAX_HOSTED_ZONES_BY_OWNER as usize {
            return Err(errors::too_many_hosted_zones(
                "This operation can't be completed either because the current account has reached the limit on the number of hosted zones or because you've reached the limit on the number of hosted zones that can be associated with a reusable delegation set.",
            ));
        }
        if st.zones.values().any(|z| z.caller_reference == input.caller_reference) {
            return Err(errors::hosted_zone_already_exists(format!(
                "A hosted zone has already been created with the specified caller reference: {}",
                input.caller_reference
            )));
        }
        let id = new_id('Z');
        let ns = match &delegation_set_id {
            Some(ds) => st.delegation_sets[ds].name_servers.clone(),
            None => name_servers(),
        };
        let mut zone = Zone {
            id: id.clone(),
            name: name.clone(),
            caller_reference: input.caller_reference,
            comment: input.hosted_zone_config.and_then(|c| c.comment),
            private,
            vpcs: input.vpc.iter().cloned().collect(),
            name_servers: ns.clone(),
            records: BTreeMap::new(),
            tags: BTreeMap::new(),
            delegation_set_id: delegation_set_id.clone(),
            ksks: BTreeMap::new(),
            dnssec_signing: false,
            vpc_authorizations: Vec::new(),
            accelerated_recovery: false,
            vpc_accounts: BTreeMap::new(),
        };
        let soa = types::ResourceRecordSet {
            name: name.clone(),
            r#type: "SOA".into(),
            ttl: Some(900),
            resource_records: Some(vec![types::ResourceRecord {
                value: format!("{}. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400", ns[0]),
            }]),
            ..Default::default()
        };
        let ns_set = types::ResourceRecordSet {
            name: name.clone(),
            r#type: "NS".into(),
            ttl: Some(172800),
            resource_records: Some(ns.iter().map(|n| types::ResourceRecord { value: format!("{n}.") }).collect()),
            ..Default::default()
        };
        zone.records.insert(record_key(&name, "SOA", None), soa);
        zone.records.insert(record_key(&name, "NS", None), ns_set);
        let hosted_zone = zone.wire();
        let delegation_set = zone.delegation_set();
        st.zones.insert(id.clone(), zone);
        let change_info = st.new_change(None);
        Ok(types::CreateHostedZoneResponse {
            hosted_zone,
            change_info,
            delegation_set,
            vpc: input.vpc,
            location: format!("https://route53.amazonaws.com/2013-04-01/hostedzone/{id}"),
        })
    }

    pub(crate) fn get_hosted_zone(
        &self,
        ctx: &RequestContext,
        input: types::GetHostedZoneRequest,
    ) -> Result<types::GetHostedZoneResponse, ServiceError> {
        let id = strip_id(&input.id);
        self.authorize(ctx, "GetHostedZone", &arn(ctx, "hostedzone", id))?;
        let st = self.lock(ctx);
        let z = st.zone(id)?;
        Ok(types::GetHostedZoneResponse {
            hosted_zone: z.wire(),
            delegation_set: (!z.private).then(|| z.delegation_set()),
            vp_cs: z.private.then(|| z.vpcs.clone()),
        })
    }

    pub(crate) fn get_hosted_zone_count(
        &self,
        ctx: &RequestContext,
        _input: types::GetHostedZoneCountRequest,
    ) -> Result<types::GetHostedZoneCountResponse, ServiceError> {
        self.authorize(ctx, "GetHostedZoneCount", "*")?;
        Ok(types::GetHostedZoneCountResponse { hosted_zone_count: self.lock(ctx).zones.len() as i64 })
    }

    pub(crate) fn list_hosted_zones(
        &self,
        ctx: &RequestContext,
        input: types::ListHostedZonesRequest,
    ) -> Result<types::ListHostedZonesResponse, ServiceError> {
        self.authorize(ctx, "ListHostedZones", "*")?;
        let limit = max_items(input.max_items, 100, 100);
        let st = self.lock(ctx);
        let delegation_set = input.delegation_set_id.as_deref().map(strip_id);
        if let Some(ds) = delegation_set {
            if !st.delegation_sets.contains_key(ds) {
                return Err(errors::no_such_delegation_set(format!(
                    "A reusable delegation set with the specified ID does not exist: {ds}"
                )));
            }
        }
        let want_private = input.hosted_zone_type.as_deref().map(|t| t == "PrivateHostedZone");
        let zones: Vec<&Zone> = st
            .zones
            .values()
            .filter(|z| want_private.is_none_or(|p| z.private == p))
            .filter(|z| delegation_set.is_none_or(|d| z.delegation_set_id.as_deref() == Some(d)))
            .filter(|z| input.marker.as_deref().is_none_or(|m| z.id.as_str() >= strip_id(m)))
            .collect();
        let page: Vec<types::HostedZone> = zones.iter().take(limit).map(|z| z.wire()).collect();
        let next = zones.get(limit).map(|z| z.id.clone());
        Ok(types::ListHostedZonesResponse {
            hosted_zones: page,
            marker: input.marker.unwrap_or_default(),
            is_truncated: next.is_some(),
            next_marker: next,
            max_items: limit as i32,
        })
    }

    pub(crate) fn list_hosted_zones_by_name(
        &self,
        ctx: &RequestContext,
        input: types::ListHostedZonesByNameRequest,
    ) -> Result<types::ListHostedZonesByNameResponse, ServiceError> {
        self.authorize(ctx, "ListHostedZonesByName", "*")?;
        if input.hosted_zone_id.is_some() && input.dns_name.is_none() {
            return Err(errors::invalid_input(
                "Invalid request: HostedZoneId can only be specified together with DNSName.",
            ));
        }
        let start = match &input.dns_name {
            Some(n) => Some(
                names::normalize(n)
                    .ok_or_else(|| errors::invalid_domain_name(format!("{n} is not a valid domain name.")))?,
            ),
            None => None,
        };
        let limit = max_items(input.max_items, 100, 100);
        let st = self.lock(ctx);
        let mut zones: Vec<&Zone> = st.zones.values().collect();
        zones.sort_by(|a, b| (names::sort_key(&a.name), &a.id).cmp(&(names::sort_key(&b.name), &b.id)));
        let start_id = input.hosted_zone_id.as_deref().map(strip_id).unwrap_or_default();
        let zones: Vec<&Zone> = zones
            .into_iter()
            .filter(|z| match &start {
                None => true,
                Some(s) => (names::sort_key(&z.name), z.id.as_str()) >= (names::sort_key(s), start_id),
            })
            .collect();
        let next = zones.get(limit);
        Ok(types::ListHostedZonesByNameResponse {
            hosted_zones: zones.iter().take(limit).map(|z| z.wire()).collect(),
            dns_name: input.dns_name.clone(),
            hosted_zone_id: input.hosted_zone_id.clone(),
            is_truncated: next.is_some(),
            next_dns_name: next.map(|z| names::display(&z.name)),
            next_hosted_zone_id: next.map(|z| z.id.clone()),
            max_items: limit as i32,
        })
    }

    pub(crate) fn update_hosted_zone_comment(
        &self,
        ctx: &RequestContext,
        input: types::UpdateHostedZoneCommentRequest,
    ) -> Result<types::UpdateHostedZoneCommentResponse, ServiceError> {
        let id = strip_id(&input.id);
        self.authorize(ctx, "UpdateHostedZoneComment", &arn(ctx, "hostedzone", id))?;
        let mut st = self.lock(ctx);
        let z = st.zone_mut(id)?;
        z.comment = input.comment.filter(|c| !c.is_empty());
        Ok(types::UpdateHostedZoneCommentResponse { hosted_zone: z.wire() })
    }

    pub(crate) fn delete_hosted_zone(
        &self,
        ctx: &RequestContext,
        input: types::DeleteHostedZoneRequest,
    ) -> Result<types::DeleteHostedZoneResponse, ServiceError> {
        let id = strip_id(&input.id);
        self.authorize(ctx, "DeleteHostedZone", &arn(ctx, "hostedzone", id))?;
        let mut st = self.lock(ctx);
        let z = st.zone(id)?;
        let only_required = z.records.values().all(|r| r.name == z.name && (r.r#type == "SOA" || r.r#type == "NS"));
        if !only_required {
            return Err(errors::hosted_zone_not_empty(
                "The specified hosted zone contains non-required resource record sets and so cannot be deleted.",
            ));
        }
        if z.dnssec_signing {
            return Err(errors::invalid_input(
                "The hosted zone has DNSSEC signing enabled. Disable DNSSEC signing before deleting the hosted zone.",
            ));
        }
        st.zones.remove(id);
        st.query_logging.retain(|_, q| q.hosted_zone_id != id);
        Ok(types::DeleteHostedZoneResponse { change_info: st.new_change(None) })
    }

    pub(crate) fn get_change(
        &self,
        ctx: &RequestContext,
        input: types::GetChangeRequest,
    ) -> Result<types::GetChangeResponse, ServiceError> {
        let id = strip_id(&input.id);
        self.authorize(ctx, "GetChange", &arn(ctx, "change", id))?;
        let st = self.lock(ctx);
        let c = st.changes.get(id).ok_or_else(|| {
            errors::no_such_change(format!("A change with the specified change ID does not exist: {id}"))
        })?;
        // MWS applies changes immediately, so they are in sync once queried.
        Ok(types::GetChangeResponse {
            change_info: types::ChangeInfo {
                id: format!("/change/{id}"),
                status: "INSYNC".into(),
                submitted_at: c.submitted_at,
                comment: c.comment.clone(),
            },
        })
    }

    pub(crate) fn associate_vpc_with_hosted_zone(
        &self,
        ctx: &RequestContext,
        input: types::AssociateVPCWithHostedZoneRequest,
    ) -> Result<types::AssociateVPCWithHostedZoneResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id);
        self.authorize(ctx, "AssociateVPCWithHostedZone", &arn(ctx, "hostedzone", id))?;
        check_vpc(&input.vpc)?;
        // The VPC must be the caller's (for another account's zone, the
        // VPC owner associates it after the zone owner authorizes it).
        if !self.vpc_exists(ctx, &input.vpc) {
            return Err(unknown_vpc(&input.vpc));
        }
        let caller = ctx.caller.account_id.as_str();
        let mut all = self.lock_all();
        // Another account's zone takes an authorization from its owner.
        let owner = all.zone_owner(id).map(str::to_string);
        let Some(owner) = owner else { return Err(no_such_zone(id)) };
        let state = all.accounts.get_mut(&owner).expect("owner exists");
        let z = state.zones.get_mut(id).expect("zone exists");
        if !z.private {
            return Err(errors::public_zone_vpc_association("Public hosted zones cannot be associated with VPCs."));
        }
        if owner != caller && !z.vpc_authorizations.iter().any(|v| same_vpc(v, &input.vpc)) {
            return Err(errors::not_authorized(format!(
                "The VPC: {} has not authorized to associate with your hosted zone.",
                input.vpc.vpc_id.as_deref().unwrap_or_default()
            )));
        }
        if z.vpcs.iter().any(|v| same_vpc(v, &input.vpc)) {
            return Err(errors::conflicting_domain_exists(format!(
                "The VPC {} is already associated with the hosted zone {id}.",
                input.vpc.vpc_id.as_deref().unwrap_or_default()
            )));
        }
        if z.vpcs.len() as i64 >= crate::limits::MAX_VPCS_ASSOCIATED_BY_ZONE {
            return Err(errors::limits_exceeded(
                "This operation can't be completed because the hosted zone has reached the limit on the number of VPCs that can be associated with it.",
            ));
        }
        if owner != caller {
            z.vpc_accounts.insert(vpc_key(&input.vpc), caller.to_string());
        }
        z.vpcs.push(input.vpc);
        Ok(types::AssociateVPCWithHostedZoneResponse { change_info: state.new_change(input.comment) })
    }

    pub(crate) fn disassociate_vpc_from_hosted_zone(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateVPCFromHostedZoneRequest,
    ) -> Result<types::DisassociateVPCFromHostedZoneResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id);
        self.authorize(ctx, "DisassociateVPCFromHostedZone", &arn(ctx, "hostedzone", id))?;
        let caller = ctx.caller.account_id.as_str();
        let mut all = self.lock_all();
        let owner = all.zone_owner(id).map(str::to_string);
        let Some(owner) = owner else { return Err(no_such_zone(id)) };
        let state = all.accounts.get_mut(&owner).expect("owner exists");
        let z = state.zones.get_mut(id).expect("zone exists");
        // The zone's owner, or the account whose VPC it is, may disassociate.
        let key = vpc_key(&input.vpc);
        if owner != caller && z.vpc_accounts.get(&key).map(String::as_str) != Some(caller) {
            drop(all);
            return Err(self.lock(ctx).access_denied());
        }
        let Some(pos) = z.vpcs.iter().position(|v| same_vpc(v, &input.vpc)) else {
            return Err(errors::vpc_association_not_found(format!(
                "The specified VPC {} is not associated with the hosted zone {id}.",
                input.vpc.vpc_id.as_deref().unwrap_or_default()
            )));
        };
        if z.vpcs.len() == 1 {
            return Err(errors::last_vpc_association(
                "The VPC that you're trying to disassociate from the private hosted zone is the last VPC that is associated with the hosted zone. Amazon Route 53 doesn't support disassociating the last VPC from a hosted zone.",
            ));
        }
        z.vpcs.remove(pos);
        z.vpc_accounts.remove(&key);
        Ok(types::DisassociateVPCFromHostedZoneResponse { change_info: state.new_change(input.comment) })
    }

    pub(crate) fn list_hosted_zones_by_vpc(
        &self,
        ctx: &RequestContext,
        input: types::ListHostedZonesByVPCRequest,
    ) -> Result<types::ListHostedZonesByVPCResponse, ServiceError> {
        self.authorize(ctx, "ListHostedZonesByVPC", "*")?;
        let limit = max_items(input.max_items, 100, 100);
        let caller = ctx.caller.account_id.as_str();
        let all = self.lock_all();
        let vpc = types::VPC { vpc_id: Some(input.vpc_id), vpc_region: Some(input.vpc_region) };
        let key = vpc_key(&vpc);
        // The caller's own zones, and other accounts' zones the caller
        // associated its VPC with.
        let mut matching: Vec<(&str, &Zone)> = all
            .all_zones()
            .filter(|(owner, z)| {
                z.vpcs.iter().any(|v| same_vpc(v, &vpc))
                    && (*owner == caller || z.vpc_accounts.get(&key).map(String::as_str) == Some(caller))
            })
            .filter(|(_, z)| input.next_token.as_deref().is_none_or(|t| z.id.as_str() >= t))
            .collect();
        matching.sort_by(|a, b| a.1.id.cmp(&b.1.id));
        Ok(types::ListHostedZonesByVPCResponse {
            hosted_zone_summaries: matching
                .iter()
                .take(limit)
                .map(|(owner, z)| types::HostedZoneSummary {
                    hosted_zone_id: z.id.clone(),
                    name: names::display(&z.name),
                    owner: types::HostedZoneOwner { owning_account: Some(owner.to_string()), owning_service: None },
                })
                .collect(),
            max_items: limit as i32,
            next_token: matching.get(limit).map(|(_, z)| z.id.clone()),
        })
    }
}
