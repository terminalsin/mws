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
            "Invalid request: Expected exactly one of [AliasTarget, all of [TTL, and ResourceRecords], or TrafficPolicyInstanceId], but found {found} in Change with [Action={}, Name={shown}, Type={}, SetIdentifier={}]",
            change.action,
            rr.r#type,
            rr.set_identifier.as_deref().unwrap_or("null")
        ));
        return msgs;
    }
    if rr.r#type == "CNAME" && rr.name == zone.name {
        msgs.push(format!(
            "RRSet of type CNAME with DNS name {shown} is not permitted at apex in zone {}",
            names::display(&zone.name)
        ));
    }
    let values: Vec<&str> = rr.resource_records.iter().flatten().map(|r| r.value.as_str()).collect();
    for v in &values {
        match rr.r#type.as_str() {
            "A" if v.parse::<Ipv4Addr>().is_err() => msgs
                .push(format!("ARRDATAIllegalIPv4Address (Value is not a valid IPv4 address) encountered with '{v}'")),
            "AAAA" if v.parse::<Ipv6Addr>().is_err() => msgs.push(format!(
                "AAAARRDATAIllegalIPv6Address (Value is not a valid IPv6 address) encountered with '{v}'"
            )),
            _ => {}
        }
    }
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

        let mut st = self.lock();
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
        let st = self.lock();
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
