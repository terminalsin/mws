//! Resource record sets: atomic change batches and listing.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names;
use crate::state::{record_key, Zone};
use crate::{arn, max_items, strip_id, Route53};

fn describe(rr: &types::ResourceRecordSet) -> String {
    format!(
        "[name='{}', type='{}'{}]",
        names::display(&rr.name),
        rr.r#type,
        match &rr.set_identifier {
            Some(s) => format!(", set-identifier='{s}'"),
            None => String::new(),
        }
    )
}

/// Content equality used by DELETE: everything except the name spelling.
fn same_content(a: &types::ResourceRecordSet, b: &types::ResourceRecordSet) -> bool {
    let norm = |r: &types::ResourceRecordSet| {
        let mut r = r.clone();
        r.name = String::new();
        if let Some(t) = &mut r.alias_target {
            t.dns_name = names::normalize(&t.dns_name).unwrap_or_else(|| t.dns_name.clone());
        }
        r
    };
    norm(a) == norm(b)
}

/// `[Action=CREATE, Name=www.example.com., Type=A, SetIdentifier=null]`, as
/// Route 53 names a change in its messages.
fn change_label(change: &types::Change, rr: &types::ResourceRecordSet) -> String {
    format!(
        "[Action={}, Name={}, Type={}, SetIdentifier={}]",
        change.action,
        names::display(&rr.name),
        rr.r#type,
        rr.set_identifier.as_deref().unwrap_or("null")
    )
}

/// A record value problem, worded as Route 53's record parser reports it.
fn bad_value(code: &str, explanation: &str, value: &str) -> String {
    format!("Invalid Resource Record: 'FATAL problem: {code} ({explanation}) encountered with '{value}''")
}

/// Whether `v` is a domain name Route 53 accepts in record data.
fn domain_problem(v: &str) -> Option<(&'static str, &'static str)> {
    let bare = v.strip_suffix('.').unwrap_or(v);
    if bare.is_empty() {
        return (v != ".").then_some(("DomainLabelEmpty", "Domain label is empty"));
    }
    if bare.len() > 253 {
        return Some(("DomainNameTooLong", "Domain name is too long"));
    }
    for label in bare.split('.') {
        if label.is_empty() {
            return Some(("DomainLabelEmpty", "Domain label is empty"));
        }
        if label.len() > 63 {
            return Some(("DomainLabelTooLong", "Domain label is too long"));
        }
    }
    None
}

/// Check one value of a record of type `ty`.
fn check_value(ty: &str, v: &str) -> Option<String> {
    let fields: Vec<&str> = v.split_whitespace().collect();
    let u16_ok = |f: &str| f.parse::<u16>().is_ok();
    let problem = match ty {
        "A" if v.parse::<Ipv4Addr>().is_err() => {
            Some(("ARRDATAIllegalIPv4Address", "Value is not a valid IPv4 address"))
        }
        "AAAA" if v.parse::<Ipv6Addr>().is_err() => {
            Some(("AAAARRDATAIllegalIPv6Address", "Value is not a valid IPv6 address"))
        }
        "CNAME" | "NS" | "PTR" => domain_problem(v),
        "MX" if fields.len() != 2 => Some(("MXRRDATANotTwoFields", "Value does not contain exactly two fields")),
        "MX" if !u16_ok(fields[0]) => Some(("MXRRDATAIllegalPriority", "Priority is not a valid integer")),
        "MX" => domain_problem(fields[1]),
        "SRV" if fields.len() != 4 => Some(("SRVRRDATANotFourFields", "Value does not contain exactly four fields")),
        "SRV" if !fields[..3].iter().all(|f| u16_ok(f)) => {
            Some(("SRVRRDATAIllegalNumber", "Priority, weight and port must be integers between 0 and 65535"))
        }
        "SRV" => domain_problem(fields[3]),
        "CAA" if fields.len() < 3 || fields[0].parse::<u8>().is_err() => {
            Some(("CAARRDATAIllegalValue", "Value must be a flag, a tag and a value"))
        }
        "TXT" | "SPF" if crate::dns::txt_strings(v).iter().any(|s| s.len() > 255) => {
            Some(("TXTRDATATooLong", "Value is too long"))
        }
        "TXT" | "SPF" if v.len() > 4000 => Some(("TXTRDATATooLong", "Value is too long")),
        _ => None,
    };
    problem.map(|(code, why)| bad_value(code, why, v))
}

/// The routing policy fields a record set carries.
fn routing_fields(rr: &types::ResourceRecordSet) -> Vec<&'static str> {
    let mut out = Vec::new();
    if rr.weight.is_some() {
        out.push("weighted");
    }
    if rr.region.is_some() {
        out.push("latency");
    }
    if rr.failover.is_some() {
        out.push("failover");
    }
    if rr.geo_location.is_some() {
        out.push("geolocation");
    }
    if rr.multi_value_answer.is_some() {
        out.push("multivalue answer");
    }
    if rr.geo_proximity_location.is_some() {
        out.push("geoproximity");
    }
    if rr.cidr_routing_config.is_some() {
        out.push("IP-based");
    }
    out
}

/// A record set's routing policy: `None` for simple routing.
pub(crate) fn routing_policy(rr: &types::ResourceRecordSet) -> Option<&'static str> {
    routing_fields(rr).first().copied()
}

/// Checks that do not depend on zone contents. Returns messages.
fn validate_shape(change: &types::Change, rr: &types::ResourceRecordSet, zone: &Zone) -> Vec<String> {
    let mut msgs = Vec::new();
    let shown = names::display(&rr.name);
    if !names::in_zone(&rr.name, &zone.name) {
        msgs.push(format!("RRSet with DNS name {shown} is not permitted in zone {}", names::display(&zone.name)));
        return msgs;
    }
    let has_alias = rr.alias_target.is_some();
    let has_records = rr.ttl.is_some() && rr.resource_records.as_ref().is_some_and(|r| !r.is_empty());
    let has_tp = rr.traffic_policy_instance_id.is_some();
    if [has_alias, has_records, has_tp].iter().filter(|b| **b).count() != 1 {
        let found = if has_alias || has_records || has_tp { "more than one" } else { "none" };
        msgs.push(format!(
            "Invalid request: Expected exactly one of [AliasTarget, all of [TTL, and ResourceRecords], or TrafficPolicyInstanceId], but found {found} in Change with {}",
            change_label(change, rr)
        ));
        return msgs;
    }
    let policies = routing_fields(rr);
    if policies.len() > 1 || (policies.is_empty() && rr.set_identifier.is_some()) {
        let found = if policies.is_empty() { "none" } else { "more than one" };
        msgs.push(format!(
            "Invalid request: Expected exactly one of [Weight, Region, Failover, GeoLocation, MultiValueAnswer, GeoProximityLocation, or CidrRoutingConfig], but found {found} in Change with {}",
            change_label(change, rr)
        ));
        return msgs;
    }
    if !policies.is_empty() && rr.set_identifier.is_none() {
        msgs.push(format!(
            "Invalid request: Missing field 'SetIdentifier' in Change with {}",
            change_label(change, rr)
        ));
        return msgs;
    }
    if rr.multi_value_answer.is_some() && has_alias {
        msgs.push(format!(
            "Invalid request: Alias records are not supported for multivalue answer routing in Change with {}",
            change_label(change, rr)
        ));
    }
    if let Some(f) = &rr.failover {
        if f != "PRIMARY" && f != "SECONDARY" {
            msgs.push(format!(
                "Invalid request: Invalid failover value {f} in Change with {}",
                change_label(change, rr)
            ));
        }
    }
    if rr.r#type == "CNAME" && rr.name == zone.name {
        msgs.push(format!(
            "RRSet of type CNAME with DNS name {shown} is not permitted at apex in zone {}",
            names::display(&zone.name)
        ));
    }
    let values: Vec<&str> = rr.resource_records.iter().flatten().map(|r| r.value.as_str()).collect();
    msgs.extend(values.iter().filter_map(|v| check_value(&rr.r#type, v)));
    if rr.r#type == "CNAME" && values.len() > 1 {
        msgs.push(format!(
            "RRSet of type CNAME with DNS name {shown} has more than one record, but CNAME records may only have one"
        ));
    }
    if rr.r#type == "SOA" && change.action == "CREATE" {
        msgs.push(format!("Tried to create resource record set {} but it already exists", describe(rr)));
    }
    msgs
}

/// Checks on the record sets sharing a name and type once the whole batch
/// is applied: one routing policy per name and type, unique failover roles,
/// locations and regions.
fn validate_group(group: &[&types::ResourceRecordSet], new: &BTreeSet<crate::state::RecordKey>) -> Vec<String> {
    let mut msgs = Vec::new();
    if group.len() < 2 {
        return msgs;
    }
    let first = group[0];
    let shown = names::display(&first.name);
    let ty = &first.r#type;
    let is_new =
        |r: &types::ResourceRecordSet| new.contains(&record_key(&r.name, &r.r#type, r.set_identifier.as_deref()));
    if let Some(simple) = group.iter().find(|r| routing_policy(r).is_none()) {
        match group.iter().find(|r| r.set_identifier.is_some() && is_new(r)) {
            Some(other) if !is_new(simple) => msgs.push(format!(
                "RRSet with DNS name {shown}, type {ty}, SetIdentifier {} cannot be created as a non-{} set exists with the same name and type.",
                other.set_identifier.as_deref().unwrap_or("null"),
                routing_policy(other).unwrap_or_default()
            )),
            _ => msgs.push(format!(
                "RRSet with DNS name {shown}, type {ty} cannot be created as other RRsets exist with the same name and type."
            )),
        }
        return msgs;
    }
    // Judge against a record set that was already there, if any.
    let base = group.iter().find(|r| !is_new(r)).unwrap_or(&first);
    let kind = routing_policy(base);
    if let Some(other) = group.iter().find(|r| routing_policy(r) != kind) {
        msgs.push(format!(
            "RRSet with DNS name {shown}, type {ty}, SetIdentifier {} cannot be created as a non-{} set exists with the same name and type.",
            other.set_identifier.as_deref().unwrap_or("null"),
            routing_policy(other).unwrap_or("simple")
        ));
        return msgs;
    }
    let mut seen = BTreeSet::new();
    for r in group {
        let key = match kind {
            Some("failover") => r.failover.clone(),
            Some("latency") => r.region.clone(),
            Some("geolocation") => r.geo_location.as_ref().map(|g| {
                format!(
                    "{}/{}/{}",
                    g.continent_code.as_deref().unwrap_or_default(),
                    g.country_code.as_deref().unwrap_or_default(),
                    g.subdivision_code.as_deref().unwrap_or_default()
                )
            }),
            Some("IP-based") => {
                r.cidr_routing_config.as_ref().map(|c| format!("{}/{}", c.collection_id, c.location_name))
            }
            _ => None,
        };
        if let Some(key) = key {
            if !seen.insert(key.clone()) {
                msgs.push(format!(
                    "RRSet with DNS name {shown}, type {ty}, SetIdentifier {} cannot be created because another {} RRSet with the same name and type already uses {key}.",
                    r.set_identifier.as_deref().unwrap_or("null"),
                    kind.unwrap_or_default()
                ));
            }
        }
    }
    msgs
}

/// Where an alias may point besides its own zone.
pub(crate) struct AliasTargets<'a> {
    /// The caller's other hosted zones, by id (aliases into them are
    /// rejected).
    pub zones: &'a dyn Fn(&str) -> Option<&'a Zone>,
    /// Targets in other services' hosted zones (load balancers, S3 website
    /// endpoints, ...); `None` when nothing knows the zone.
    pub external: &'a dyn Fn(&str, &str, &str) -> Option<crate::AliasTargetCheck>,
}

/// An alias needs its target to exist: a record in the same zone, or an
/// AWS resource in its service's hosted zone. A record in another of the
/// caller's zones is never a valid target. Targets in hosted zones nothing knows (CloudFront, API
/// Gateway, ...) go unchecked.
fn validate_alias(
    rr: &types::ResourceRecordSet,
    zone: &Zone,
    records: &std::collections::BTreeMap<crate::state::RecordKey, types::ResourceRecordSet>,
    targets: &AliasTargets<'_>,
) -> Option<String> {
    let alias = rr.alias_target.as_ref()?;
    let target_zone_id = strip_id(&alias.hosted_zone_id);
    let target = names::normalize(&alias.dns_name).unwrap_or_else(|| alias.dns_name.clone());
    let shown = names::display(&target);
    let outside = |zone_id: &str| {
        format!(
            "Tried to create an alias that targets {shown}, type {} in zone {zone_id}, but the alias target name does not lie within the target zone",
            rr.r#type
        )
    };
    let not_found = |zone_id: &str| {
        format!(
            "Tried to create an alias that targets {shown}, type {} in zone {zone_id}, but that target was not found",
            rr.r#type
        )
    };
    if target_zone_id != zone.id {
        if let Some(other) = (targets.zones)(target_zone_id) {
            if !names::in_zone(&target, &other.name) {
                return Some(outside(&other.id));
            }
            // An alias can only reference records in its own hosted zone;
            // Route 53 does not look into the other zone.
            return Some(not_found(&other.id));
        }
        return match (targets.external)(target_zone_id, &alias.dns_name, &rr.r#type)? {
            crate::AliasTargetCheck::Found => None,
            crate::AliasTargetCheck::OutsideZone => Some(outside(target_zone_id)),
            crate::AliasTargetCheck::NotFound => Some(not_found(target_zone_id)),
        };
    }
    if !names::in_zone(&target, &zone.name) {
        return Some(outside(&zone.id));
    }
    if target == rr.name {
        return Some(format!(
            "Tried to create an alias that targets {shown}, type {} in zone {}, but the alias target is the alias itself",
            rr.r#type, zone.id
        ));
    }
    let exists = records.values().any(|r| r.name == target && r.r#type == rr.r#type);
    (!exists).then(|| not_found(&zone.id))
}

impl Route53 {
    pub(crate) fn change_resource_record_sets(
        &self,
        ctx: &RequestContext,
        input: types::ChangeResourceRecordSetsRequest,
    ) -> Result<types::ChangeResourceRecordSetsResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id).to_string();
        // Route 53's fine-grained condition keys.
        let mut cond = ConditionContext::new();
        let mut names_k = Vec::new();
        let mut types_k = Vec::new();
        let mut actions_k = Vec::new();
        for c in &input.change_batch.changes {
            let n = names::normalize(&c.resource_record_set.name).unwrap_or_else(|| c.resource_record_set.name.clone());
            names_k.push(names::bare(&n).to_string());
            types_k.push(c.resource_record_set.r#type.clone());
            actions_k.push(c.action.clone());
        }
        cond.insert("route53:ChangeResourceRecordSetsNormalizedRecordNames".into(), names_k);
        cond.insert("route53:ChangeResourceRecordSetsRecordTypes".into(), types_k);
        cond.insert("route53:ChangeResourceRecordSetsActions".into(), actions_k);
        ctx.authorize("route53:ChangeResourceRecordSets", &arn(ctx, "hostedzone", &id), cond)?;

        let mut st = self.lock(ctx);
        let health_ids: BTreeSet<String> = st.health_checks.keys().cloned().collect();
        let zone = st.zone(&id)?;
        let mut records = zone.records.clone();
        let mut msgs = Vec::new();
        for change in &input.change_batch.changes {
            let mut rr = change.resource_record_set.clone();
            let Some(name) = names::normalize(&rr.name) else {
                msgs.push(format!("{} is not a valid DNS name", rr.name));
                continue;
            };
            rr.name = name;
            let shape_msgs = validate_shape(change, &rr, zone);
            if !shape_msgs.is_empty() {
                msgs.extend(shape_msgs);
                continue;
            }
            if let Some(hc) = &rr.health_check_id {
                if !health_ids.contains(hc) && change.action != "DELETE" {
                    msgs.push(format!("Invalid request: Health check {hc} does not exist"));
                    continue;
                }
            }
            let key = record_key(&rr.name, &rr.r#type, rr.set_identifier.as_deref());
            match change.action.as_str() {
                "CREATE" | "UPSERT" => {
                    if change.action == "CREATE" && records.contains_key(&key) {
                        msgs.push(format!("Tried to create resource record set {} but it already exists", describe(&rr)));
                        continue;
                    }
                    let same_name: Vec<&types::ResourceRecordSet> =
                        records.values().filter(|r| r.name == rr.name && !(r.r#type == rr.r#type)).collect();
                    let zone_name = names::display(&zone.name);
                    if rr.r#type == "CNAME" && !same_name.is_empty() {
                        msgs.push(format!(
                            "RRSet of type CNAME with DNS name {} is not permitted as it conflicts with other records with the same DNS name in zone {zone_name}",
                            names::display(&rr.name)
                        ));
                        continue;
                    }
                    if rr.r#type != "CNAME" && same_name.iter().any(|r| r.r#type == "CNAME") {
                        msgs.push(format!(
                            "RRSet of type {} with DNS name {} is not permitted because a conflicting RRSet of type CNAME with the same DNS name already exists in zone {zone_name}",
                            rr.r#type,
                            names::display(&rr.name)
                        ));
                        continue;
                    }
                    records.insert(key, rr);
                }
                "DELETE" => match records.get(&key) {
                    None => msgs.push(format!("Tried to delete resource record set {} but it was not found", describe(&rr))),
                    Some(existing) if !same_content(existing, &rr) => msgs.push(format!(
                        "Tried to delete resource record set {} but the values provided do not match the current values",
                        describe(&rr)
                    )),
                    Some(_) => {
                        records.remove(&key);
                    }
                },
                other => msgs.push(format!("Invalid action {other}")),
            }
        }
        if msgs.is_empty() {
            // Aliases and routing groups are judged on the batch's result.
            let zones = |zid: &str| st.zones.get(zid);
            let external = |zid: &str, name: &str, ty: &str| self.check_external_alias(zid, name, ty);
            let targets = AliasTargets { zones: &zones, external: &external };
            for change in input.change_batch.changes.iter().filter(|c| c.action != "DELETE") {
                let mut rr = change.resource_record_set.clone();
                rr.name = names::normalize(&rr.name).unwrap_or_default();
                msgs.extend(validate_alias(&rr, zone, &records, &targets));
            }
            let touched: BTreeSet<(String, String)> = input
                .change_batch
                .changes
                .iter()
                .map(|c| {
                    let rr = &c.resource_record_set;
                    (names::normalize(&rr.name).unwrap_or_default(), rr.r#type.clone())
                })
                .collect();
            let new: BTreeSet<crate::state::RecordKey> = input
                .change_batch
                .changes
                .iter()
                .filter(|c| c.action != "DELETE")
                .map(|c| {
                    let rr = &c.resource_record_set;
                    let name = names::normalize(&rr.name).unwrap_or_default();
                    record_key(&name, &rr.r#type, rr.set_identifier.as_deref())
                })
                .collect();
            for (name, ty) in &touched {
                let group: Vec<&types::ResourceRecordSet> =
                    records.values().filter(|r| &r.name == name && &r.r#type == ty).collect();
                msgs.extend(validate_group(&group, &new));
            }
            if records.len() as i64 > crate::limits::MAX_RRSETS_BY_ZONE {
                msgs.push(format!(
                    "The hosted zone {} would exceed the limit of {} resource record sets.",
                    zone.id,
                    crate::limits::MAX_RRSETS_BY_ZONE
                ));
            }
        }
        if msgs.is_empty() {
            let apex = |t: &str| records.contains_key(&record_key(&zone.name, t, None));
            if !apex("SOA") {
                msgs.push("A HostedZone must contain exactly one SOA record.".into());
            }
            if !apex("NS") {
                msgs.push("A HostedZone must contain at least one NS record for the zone itself.".into());
            }
        }
        if !msgs.is_empty() {
            return Err(errors::invalid_change_batch_with_messages(format!("[{}]", msgs.join(", ")), msgs));
        }
        st.zone_mut(&id)?.records = records;
        let change_info = st.new_change(input.change_batch.comment);
        Ok(types::ChangeResourceRecordSetsResponse { change_info })
    }

    pub(crate) fn list_resource_record_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceRecordSetsRequest,
    ) -> Result<types::ListResourceRecordSetsResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id);
        self.authorize(ctx, "ListResourceRecordSets", &arn(ctx, "hostedzone", id))?;
        if input.start_record_type.is_some() && input.start_record_name.is_none() {
            return Err(errors::invalid_input("The input is not valid: StartRecordType requires StartRecordName"));
        }
        let limit = max_items(input.max_items, 300, 300);
        let st = self.lock(ctx);
        let zone = st.zone(id)?;
        let start = match &input.start_record_name {
            Some(n) => {
                let n =
                    names::normalize(n).ok_or_else(|| errors::invalid_input(format!("{n} is not a valid DNS name")))?;
                Some(record_key(
                    &n,
                    input.start_record_type.as_deref().unwrap_or_default(),
                    input.start_record_identifier.as_deref(),
                ))
            }
            None => None,
        };
        let matching: Vec<&types::ResourceRecordSet> = match &start {
            Some(k) => zone.records.range(k.clone()..).map(|(_, v)| v).collect(),
            None => zone.records.values().collect(),
        };
        let wire = |r: &types::ResourceRecordSet| {
            let mut r = r.clone();
            r.name = names::display(&r.name);
            r
        };
        let next = matching.get(limit);
        Ok(types::ListResourceRecordSetsResponse {
            resource_record_sets: matching.iter().take(limit).map(|r| wire(r)).collect(),
            is_truncated: next.is_some(),
            next_record_name: next.map(|r| names::display(&r.name)),
            next_record_type: next.map(|r| r.r#type.clone()),
            next_record_identifier: next.and_then(|r| r.set_identifier.clone()),
            max_items: limit as i32,
        })
    }
}
