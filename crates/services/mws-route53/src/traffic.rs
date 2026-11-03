//! Traffic policies, their versions, and traffic policy instances.
//!
//! A policy document is validated the way Route 53 does (format version,
//! record type, a start endpoint or rule, resolvable references, no
//! cycles). An instance turns the document into record sets at its name:
//! one record for a start endpoint, or one record per branch of the start
//! rule with that rule's routing (failover, weighted, latency, geo,
//! geoproximity, multivalue), each answering with the first endpoint
//! reachable from the branch. The records carry `TrafficPolicyInstanceId`.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};
use serde_json::{Map, Value};

use crate::generated::{errors, types};
use crate::limits::{
    MAX_TRAFFIC_POLICIES_BY_OWNER, MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER, MAX_VERSIONS_PER_TRAFFIC_POLICY,
};
use crate::state::{record_key, State, TrafficPolicy};
use crate::{arn, max_items, names, strip_id, Route53};

const RECORD_TYPES: &[&str] = &["A", "AAAA", "CAA", "CNAME", "MX", "NAPTR", "PTR", "SPF", "SRV", "TXT"];
const ENDPOINT_TYPES: &[&str] = &[
    "value",
    "cloudfront",
    "elastic-load-balancer",
    "application-load-balancer",
    "network-load-balancer",
    "s3-website",
    "elastic-beanstalk",
];

fn invalid(msg: impl Into<String>) -> ServiceError {
    errors::invalid_traffic_policy_document(msg)
}

fn no_such_policy(id: &str, version: Option<i32>) -> ServiceError {
    match version {
        Some(v) => errors::no_such_traffic_policy(format!("No traffic policy found with ID {id} and version {v}")),
        None => errors::no_such_traffic_policy(format!("No traffic policy found with ID {id}")),
    }
}

fn no_such_instance(id: &str) -> ServiceError {
    errors::no_such_traffic_policy_instance(format!("No traffic policy instance found with ID {id}"))
}

/// A parsed, validated policy document.
struct Document {
    record_type: String,
    endpoints: Map<String, Value>,
    rules: Map<String, Value>,
    start_endpoint: Option<String>,
    start_rule: Option<String>,
}

/// The references (endpoint or rule) a rule branch points at.
fn branch_target(branch: &Value) -> Option<(bool, &str)> {
    if let Some(e) = branch.get("EndpointReference").and_then(Value::as_str) {
        return Some((true, e));
    }
    branch.get("RuleReference").and_then(Value::as_str).map(|r| (false, r))
}

/// The branches of a rule, in document order.
fn branches(rule: &Value) -> Vec<&Value> {
    match rule.get("RuleType").and_then(Value::as_str) {
        Some("failover") => ["Primary", "Secondary"].iter().filter_map(|k| rule.get(*k)).collect(),
        Some("geo") => rule.get("Locations").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default(),
        Some("latency") => {
            rule.get("Regions").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default()
        }
        Some("weighted") | Some("multivalue") => {
            rule.get("Items").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default()
        }
        Some("geoproximity") => {
            rule.get("GeoproximityLocations").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

fn parse_document(raw: &str) -> Result<Document, ServiceError> {
    let v: Value = serde_json::from_str(raw).map_err(|e| invalid(format!("Invalid JSON: {e}")))?;
    let obj = v.as_object().ok_or_else(|| invalid("The traffic policy document must be a JSON object."))?;
    match obj.get("AWSPolicyFormatVersion").and_then(Value::as_str) {
        Some("2015-10-01") => {}
        _ => return Err(invalid("AWSPolicyFormatVersion must be 2015-10-01.")),
    }
    let record_type = obj
        .get("RecordType")
        .and_then(Value::as_str)
        .filter(|t| RECORD_TYPES.contains(t))
        .ok_or_else(|| invalid("RecordType is missing or not a supported DNS type."))?
        .to_string();
    let endpoints = obj.get("Endpoints").and_then(Value::as_object).cloned().unwrap_or_default();
    let rules = obj.get("Rules").and_then(Value::as_object).cloned().unwrap_or_default();
    let start_endpoint = obj.get("StartEndpoint").and_then(Value::as_str).map(str::to_string);
    let start_rule = obj.get("StartRule").and_then(Value::as_str).map(str::to_string);
    if start_endpoint.is_some() == start_rule.is_some() {
        return Err(invalid("The document must specify exactly one of StartEndpoint and StartRule."));
    }
    for (name, e) in &endpoints {
        let ty = e.get("Type").and_then(Value::as_str).unwrap_or_default();
        if !ENDPOINT_TYPES.contains(&ty) {
            return Err(invalid(format!("Endpoint {name} has an invalid Type {ty}.")));
        }
        if e.get("Value").and_then(Value::as_str).is_none_or(str::is_empty) {
            return Err(invalid(format!("Endpoint {name} must have a Value.")));
        }
        if ty != "value" && !matches!(record_type.as_str(), "A" | "AAAA") {
            return Err(invalid(format!("Endpoint {name} of type {ty} requires RecordType A or AAAA.")));
        }
    }
    for (name, rule) in &rules {
        let ty = rule.get("RuleType").and_then(Value::as_str).unwrap_or_default();
        if !["failover", "geo", "latency", "weighted", "multivalue", "geoproximity"].contains(&ty) {
            return Err(invalid(format!("Rule {name} has an invalid RuleType {ty}.")));
        }
        let bs = branches(rule);
        if bs.is_empty() || (ty == "failover" && bs.len() != 2) {
            return Err(invalid(format!("Rule {name} of type {ty} is missing its branches.")));
        }
        for b in bs {
            match branch_target(b) {
                Some((true, e)) if endpoints.contains_key(e) => {}
                Some((false, r)) if rules.contains_key(r) && ty != "multivalue" => {}
                Some((_, target)) => {
                    return Err(invalid(format!("Rule {name} references {target}, which doesn't exist.")))
                }
                None => {
                    return Err(invalid(format!(
                        "Rule {name} has a branch without an EndpointReference or RuleReference."
                    )))
                }
            }
        }
    }
    let doc = Document { record_type, endpoints, rules, start_endpoint, start_rule };
    if let Some(e) = &doc.start_endpoint {
        if !doc.endpoints.contains_key(e) {
            return Err(invalid(format!("StartEndpoint {e} doesn't exist.")));
        }
    }
    if let Some(r) = &doc.start_rule {
        if !doc.rules.contains_key(r) {
            return Err(invalid(format!("StartRule {r} doesn't exist.")));
        }
        // Rules form a tree: no rule may be reached twice on one path.
        fn walk(doc: &Document, rule: &str, path: &mut Vec<String>) -> Result<(), ServiceError> {
            if path.iter().any(|p| p == rule) {
                return Err(invalid(format!("The rules contain a cycle through {rule}.")));
            }
            path.push(rule.to_string());
            for b in branches(&doc.rules[rule]) {
                if let Some((false, next)) = branch_target(b) {
                    walk(doc, next, path)?;
                }
            }
            path.pop();
            Ok(())
        }
        walk(&doc, r, &mut Vec::new())?;
    }
    Ok(doc)
}

impl Document {
    /// The first endpoint value reachable from a branch target.
    fn first_value(&self, is_endpoint: bool, name: &str) -> String {
        if is_endpoint {
            return self.endpoints[name].get("Value").and_then(Value::as_str).unwrap_or_default().to_string();
        }
        let first = branches(&self.rules[name]).into_iter().find_map(branch_target);
        first.map(|(e, n)| self.first_value(e, n)).unwrap_or_default()
    }

    fn records(&self, name: &str, ttl: i64, instance_id: &str) -> Vec<types::ResourceRecordSet> {
        let base = |value: String| types::ResourceRecordSet {
            name: name.to_string(),
            r#type: self.record_type.clone(),
            ttl: Some(ttl),
            resource_records: Some(vec![types::ResourceRecord { value }]),
            traffic_policy_instance_id: Some(instance_id.to_string()),
            ..Default::default()
        };
        if let Some(e) = &self.start_endpoint {
            return vec![base(self.first_value(true, e))];
        }
        let rule_name = self.start_rule.as_deref().unwrap_or_default();
        let rule = &self.rules[rule_name];
        let ty = rule.get("RuleType").and_then(Value::as_str).unwrap_or_default();
        let str_field = |b: &Value, k: &str| b.get(k).and_then(Value::as_str).map(str::to_string);
        branches(rule)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| {
                let (is_endpoint, target) = branch_target(b)?;
                let mut rr = base(self.first_value(is_endpoint, target));
                match ty {
                    "failover" => {
                        let role = if i == 0 { "PRIMARY" } else { "SECONDARY" };
                        rr.failover = Some(role.into());
                        rr.set_identifier = Some(format!("{rule_name}-{}", role.to_lowercase()));
                    }
                    "weighted" => {
                        rr.weight = Some(
                            b.get("Weight").and_then(|w| w.as_i64().or_else(|| w.as_str()?.parse().ok())).unwrap_or(0),
                        );
                        rr.set_identifier = Some(format!("{rule_name}-{i}"));
                    }
                    "latency" => {
                        rr.region = str_field(b, "Region");
                        rr.set_identifier = Some(format!("{rule_name}-{}", rr.region.clone().unwrap_or_default()));
                    }
                    "geo" => {
                        let default = b.get("IsDefault").and_then(Value::as_bool).unwrap_or(false);
                        rr.geo_location = Some(if default {
                            types::GeoLocation { country_code: Some("*".into()), ..Default::default() }
                        } else {
                            types::GeoLocation {
                                continent_code: str_field(b, "Continent"),
                                country_code: str_field(b, "Country"),
                                subdivision_code: str_field(b, "Subdivision"),
                            }
                        });
                        rr.set_identifier = Some(format!("{rule_name}-{i}"));
                    }
                    "geoproximity" => {
                        let coordinates = match (str_field(b, "Latitude"), str_field(b, "Longitude")) {
                            (Some(latitude), Some(longitude)) => Some(types::Coordinates { latitude, longitude }),
                            _ => None,
                        };
                        rr.geo_proximity_location = Some(types::GeoProximityLocation {
                            aws_region: str_field(b, "Region")
                                .map(|r| r.trim_start_matches("aws:route53:").to_string()),
                            local_zone_group: None,
                            coordinates,
                            bias: b.get("Bias").and_then(Value::as_i64).map(|v| v as i32),
                        });
                        rr.set_identifier = Some(format!("{rule_name}-{i}"));
                    }
                    _ => {
                        rr.multi_value_answer = Some(true);
                        rr.set_identifier = Some(format!("{rule_name}-{i}"));
                    }
                }
                Some(rr)
            })
            .collect()
    }
}

impl State {
    fn policy(&self, id: &str) -> Result<&TrafficPolicy, ServiceError> {
        self.traffic_policies.get(id).ok_or_else(|| no_such_policy(id, None))
    }

    fn policy_version(&self, id: &str, version: i32) -> Result<&types::TrafficPolicy, ServiceError> {
        self.traffic_policies
            .get(id)
            .and_then(|p| p.versions.get(&version))
            .ok_or_else(|| no_such_policy(id, Some(version)))
    }

    /// Remove an instance's records from its zone.
    fn clear_instance_records(&mut self, instance: &types::TrafficPolicyInstance) {
        if let Some(zone) = self.zones.get_mut(&instance.hosted_zone_id) {
            zone.records.retain(|_, r| r.traffic_policy_instance_id.as_deref() != Some(instance.id.as_str()));
        }
    }

    /// Write an instance's records, refusing to overwrite other records.
    fn apply_instance(&mut self, instance: &types::TrafficPolicyInstance, document: &str) -> Result<(), ServiceError> {
        let doc = parse_document(document)?;
        let name = names::normalize(&instance.name).unwrap_or_default();
        let zone = self.zone_mut(&instance.hosted_zone_id)?;
        let clash = zone.records.values().any(|r| {
            r.name == name
                && r.r#type == doc.record_type
                && r.traffic_policy_instance_id.as_deref() != Some(&instance.id)
        });
        if clash {
            return Err(errors::invalid_input(format!(
                "Invalid input: A resource record set of type {} named {} already exists and is not managed by this traffic policy instance.",
                doc.record_type, instance.name
            )));
        }
        zone.records.retain(|_, r| r.traffic_policy_instance_id.as_deref() != Some(instance.id.as_str()));
        for rr in doc.records(&name, instance.ttl, &instance.id) {
            zone.records.insert(record_key(&rr.name, &rr.r#type, rr.set_identifier.as_deref()), rr);
        }
        Ok(())
    }
}

fn summary(p: &TrafficPolicy) -> types::TrafficPolicySummary {
    types::TrafficPolicySummary {
        id: p.id.clone(),
        name: p.name.clone(),
        r#type: p.record_type.clone(),
        latest_version: p.latest_version,
        traffic_policy_count: p.versions.len() as i32,
    }
}

/// Instance listing order and markers: (hosted zone id, name, type).
fn instance_key(i: &types::TrafficPolicyInstance) -> (String, String, String) {
    (
        i.hosted_zone_id.clone(),
        names::sort_key(&names::normalize(&i.name).unwrap_or_default()),
        i.traffic_policy_type.clone(),
    )
}

struct InstancePage {
    items: Vec<types::TrafficPolicyInstance>,
    next: Option<(String, String, String)>,
    limit: usize,
}

fn page_instances<'a>(
    all: impl Iterator<Item = &'a types::TrafficPolicyInstance>,
    zone_marker: Option<&str>,
    name_marker: Option<&str>,
    type_marker: Option<&str>,
    max: Option<i32>,
) -> InstancePage {
    let limit = max_items(max, 100, 100);
    let mut sorted: Vec<&types::TrafficPolicyInstance> = all.collect();
    sorted.sort_by_key(|i| instance_key(i));
    let start = name_marker.map(|n| {
        (
            zone_marker.map(strip_id).unwrap_or_default().to_string(),
            names::sort_key(&names::normalize(n).unwrap_or_default()),
            type_marker.unwrap_or_default().to_string(),
        )
    });
    let rest: Vec<&types::TrafficPolicyInstance> = sorted
        .into_iter()
        .filter(|i| {
            start.as_ref().is_none_or(|s| {
                let k = instance_key(i);
                if zone_marker.is_none() {
                    (&k.1, &k.2) >= (&s.1, &s.2)
                } else {
                    k >= *s
                }
            })
        })
        .collect();
    let next = rest.get(limit).map(|i| {
        (
            i.hosted_zone_id.clone(),
            names::display(&names::normalize(&i.name).unwrap_or_default()),
            i.traffic_policy_type.clone(),
        )
    });
    InstancePage { items: rest.into_iter().take(limit).cloned().collect(), next, limit }
}

impl Route53 {
    pub(crate) fn create_traffic_policy(
        &self,
        ctx: &RequestContext,
        input: types::CreateTrafficPolicyRequest,
    ) -> Result<types::CreateTrafficPolicyResponse, ServiceError> {
        self.authorize(ctx, "CreateTrafficPolicy", "*")?;
        let doc = parse_document(&input.document)?;
        let mut st = self.lock();
        if st.traffic_policies.values().any(|p| p.name == input.name) {
            return Err(errors::traffic_policy_already_exists(format!(
                "A traffic policy with the name {} already exists.",
                input.name
            )));
        }
        if st.traffic_policies.len() as i64 >= MAX_TRAFFIC_POLICIES_BY_OWNER {
            return Err(errors::too_many_traffic_policies(
                "This traffic policy can't be created because the current account has reached the limit on the number of traffic policies.",
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let policy = types::TrafficPolicy {
            id: id.clone(),
            version: 1,
            name: input.name.clone(),
            r#type: doc.record_type.clone(),
            document: input.document,
            comment: input.comment,
        };
        st.traffic_policies.insert(
            id.clone(),
            TrafficPolicy {
                id: id.clone(),
                name: input.name,
                record_type: doc.record_type,
                versions: BTreeMap::from([(1, policy.clone())]),
                latest_version: 1,
            },
        );
        Ok(types::CreateTrafficPolicyResponse {
            traffic_policy: policy,
            location: format!("https://route53.amazonaws.com/2013-04-01/trafficpolicy/{id}/1"),
        })
    }

    pub(crate) fn create_traffic_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::CreateTrafficPolicyVersionRequest,
    ) -> Result<types::CreateTrafficPolicyVersionResponse, ServiceError> {
        self.authorize(ctx, "CreateTrafficPolicyVersion", &arn(ctx, "trafficpolicy", &input.id))?;
        let doc = parse_document(&input.document)?;
        let mut st = self.lock();
        let p = st.traffic_policies.get_mut(&input.id).ok_or_else(|| no_such_policy(&input.id, None))?;
        if doc.record_type != p.record_type {
            return Err(invalid(format!(
                "The RecordType of a new version must match the traffic policy's type ({}).",
                p.record_type
            )));
        }
        if p.versions.len() >= MAX_VERSIONS_PER_TRAFFIC_POLICY {
            return Err(errors::too_many_traffic_policy_versions_for_current_policy(
                "This traffic policy version can't be created because you've reached the limit of 1000 on the number of versions that you can create for the current traffic policy.",
            ));
        }
        p.latest_version += 1;
        let version = p.latest_version;
        let policy = types::TrafficPolicy {
            id: p.id.clone(),
            version,
            name: p.name.clone(),
            r#type: p.record_type.clone(),
            document: input.document,
            comment: input.comment,
        };
        p.versions.insert(version, policy.clone());
        Ok(types::CreateTrafficPolicyVersionResponse {
            location: format!("https://route53.amazonaws.com/2013-04-01/trafficpolicy/{}/{version}", input.id),
            traffic_policy: policy,
        })
    }

    pub(crate) fn get_traffic_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetTrafficPolicyRequest,
    ) -> Result<types::GetTrafficPolicyResponse, ServiceError> {
        self.authorize(ctx, "GetTrafficPolicy", &arn(ctx, "trafficpolicy", &input.id))?;
        let st = self.lock();
        Ok(types::GetTrafficPolicyResponse { traffic_policy: st.policy_version(&input.id, input.version)?.clone() })
    }

    pub(crate) fn update_traffic_policy_comment(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTrafficPolicyCommentRequest,
    ) -> Result<types::UpdateTrafficPolicyCommentResponse, ServiceError> {
        self.authorize(ctx, "UpdateTrafficPolicyComment", &arn(ctx, "trafficpolicy", &input.id))?;
        let mut st = self.lock();
        st.policy_version(&input.id, input.version)?;
        let v =
            st.traffic_policies.get_mut(&input.id).and_then(|p| p.versions.get_mut(&input.version)).expect("checked");
        v.comment = Some(input.comment);
        Ok(types::UpdateTrafficPolicyCommentResponse { traffic_policy: v.clone() })
    }

    pub(crate) fn delete_traffic_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTrafficPolicyRequest,
    ) -> Result<types::DeleteTrafficPolicyResponse, ServiceError> {
        self.authorize(ctx, "DeleteTrafficPolicy", &arn(ctx, "trafficpolicy", &input.id))?;
        let mut st = self.lock();
        st.policy_version(&input.id, input.version)?;
        let in_use = st
            .traffic_policy_instances
            .values()
            .any(|i| i.traffic_policy_id == input.id && i.traffic_policy_version == input.version);
        if in_use {
            return Err(errors::traffic_policy_in_use(
                "One or more traffic policy instances were created by using the specified traffic policy.",
            ));
        }
        let p = st.traffic_policies.get_mut(&input.id).expect("checked");
        p.versions.remove(&input.version);
        if p.versions.is_empty() {
            st.traffic_policies.remove(&input.id);
        }
        Ok(types::DeleteTrafficPolicyResponse {})
    }

    pub(crate) fn list_traffic_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListTrafficPoliciesRequest,
    ) -> Result<types::ListTrafficPoliciesResponse, ServiceError> {
        self.authorize(ctx, "ListTrafficPolicies", "*")?;
        let limit = max_items(input.max_items, 100, 100);
        let st = self.lock();
        let all: Vec<&TrafficPolicy> = st
            .traffic_policies
            .values()
            .filter(|p| input.traffic_policy_id_marker.as_deref().is_none_or(|m| p.id.as_str() >= m))
            .collect();
        let next = all.get(limit);
        Ok(types::ListTrafficPoliciesResponse {
            traffic_policy_summaries: all.iter().take(limit).map(|p| summary(p)).collect(),
            is_truncated: next.is_some(),
            traffic_policy_id_marker: next.map(|p| p.id.clone()).unwrap_or_default(),
            max_items: limit as i32,
        })
    }

    pub(crate) fn list_traffic_policy_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListTrafficPolicyVersionsRequest,
    ) -> Result<types::ListTrafficPolicyVersionsResponse, ServiceError> {
        self.authorize(ctx, "ListTrafficPolicyVersions", &arn(ctx, "trafficpolicy", &input.id))?;
        let limit = max_items(input.max_items, 100, 100);
        let start: i32 = match &input.traffic_policy_version_marker {
            Some(m) => m.parse().map_err(|_| errors::invalid_input(format!("Invalid input: {m} is not a version.")))?,
            None => 0,
        };
        let st = self.lock();
        let p = st.policy(&input.id)?;
        let all: Vec<&types::TrafficPolicy> = p.versions.range(start..).map(|(_, v)| v).collect();
        let next = all.get(limit);
        Ok(types::ListTrafficPolicyVersionsResponse {
            traffic_policies: all.iter().take(limit).map(|v| (*v).clone()).collect(),
            is_truncated: next.is_some(),
            traffic_policy_version_marker: next.map(|v| v.version.to_string()).unwrap_or_default(),
            max_items: limit as i32,
        })
    }

    pub(crate) fn create_traffic_policy_instance(
        &self,
        ctx: &RequestContext,
        input: types::CreateTrafficPolicyInstanceRequest,
    ) -> Result<types::CreateTrafficPolicyInstanceResponse, ServiceError> {
        let zone_id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "CreateTrafficPolicyInstance", &arn(ctx, "hostedzone", &zone_id))?;
        let mut st = self.lock();
        let zone_name = st.zone(&zone_id)?.name.clone();
        let policy = st.policy_version(&input.traffic_policy_id, input.traffic_policy_version)?.clone();
        let name = names::normalize(&input.name).filter(|n| names::in_zone(n, &zone_name)).ok_or_else(|| {
            errors::invalid_input(format!("Invalid input: {} is not in the hosted zone.", input.name))
        })?;
        let exists = st.traffic_policy_instances.values().any(|i| {
            i.hosted_zone_id == zone_id
                && names::normalize(&i.name).as_deref() == Some(&name)
                && i.traffic_policy_type == policy.r#type
        });
        if exists {
            return Err(errors::traffic_policy_instance_already_exists(
                "There is already a traffic policy instance with the specified name and type.",
            ));
        }
        if st.traffic_policy_instances.len() as i64 >= MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER {
            return Err(errors::too_many_traffic_policy_instances(
                "This traffic policy instance can't be created because the current account has reached the limit on the number of traffic policy instances.",
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let instance = types::TrafficPolicyInstance {
            id: id.clone(),
            hosted_zone_id: zone_id,
            name: names::display(&name),
            ttl: input.ttl,
            state: "Applied".into(),
            message: String::new(),
            traffic_policy_id: policy.id.clone(),
            traffic_policy_version: policy.version,
            traffic_policy_type: policy.r#type.clone(),
        };
        st.apply_instance(&instance, &policy.document)?;
        st.traffic_policy_instances.insert(id.clone(), instance.clone());
        Ok(types::CreateTrafficPolicyInstanceResponse {
            traffic_policy_instance: instance,
            location: format!("https://route53.amazonaws.com/2013-04-01/trafficpolicyinstance/{id}"),
        })
    }

    pub(crate) fn get_traffic_policy_instance(
        &self,
        ctx: &RequestContext,
        input: types::GetTrafficPolicyInstanceRequest,
    ) -> Result<types::GetTrafficPolicyInstanceResponse, ServiceError> {
        self.authorize(ctx, "GetTrafficPolicyInstance", &arn(ctx, "trafficpolicyinstance", &input.id))?;
        let st = self.lock();
        let instance =
            st.traffic_policy_instances.get(&input.id).cloned().ok_or_else(|| no_such_instance(&input.id))?;
        Ok(types::GetTrafficPolicyInstanceResponse { traffic_policy_instance: instance })
    }

    pub(crate) fn update_traffic_policy_instance(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTrafficPolicyInstanceRequest,
    ) -> Result<types::UpdateTrafficPolicyInstanceResponse, ServiceError> {
        self.authorize(ctx, "UpdateTrafficPolicyInstance", &arn(ctx, "trafficpolicyinstance", &input.id))?;
        let mut st = self.lock();
        let current = st.traffic_policy_instances.get(&input.id).cloned().ok_or_else(|| no_such_instance(&input.id))?;
        let policy = st.policy_version(&input.traffic_policy_id, input.traffic_policy_version)?.clone();
        if policy.r#type != current.traffic_policy_type {
            return Err(errors::conflicting_types(
                "You tried to update a traffic policy instance by using a traffic policy version that has a different DNS type than the current type for the instance.",
            ));
        }
        let updated = types::TrafficPolicyInstance {
            ttl: input.ttl,
            traffic_policy_id: policy.id.clone(),
            traffic_policy_version: policy.version,
            ..current
        };
        st.apply_instance(&updated, &policy.document)?;
        st.traffic_policy_instances.insert(input.id, updated.clone());
        Ok(types::UpdateTrafficPolicyInstanceResponse { traffic_policy_instance: updated })
    }

    pub(crate) fn delete_traffic_policy_instance(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTrafficPolicyInstanceRequest,
    ) -> Result<types::DeleteTrafficPolicyInstanceResponse, ServiceError> {
        self.authorize(ctx, "DeleteTrafficPolicyInstance", &arn(ctx, "trafficpolicyinstance", &input.id))?;
        let mut st = self.lock();
        let instance = st.traffic_policy_instances.remove(&input.id).ok_or_else(|| no_such_instance(&input.id))?;
        st.clear_instance_records(&instance);
        Ok(types::DeleteTrafficPolicyInstanceResponse {})
    }

    pub(crate) fn get_traffic_policy_instance_count(
        &self,
        ctx: &RequestContext,
        _input: types::GetTrafficPolicyInstanceCountRequest,
    ) -> Result<types::GetTrafficPolicyInstanceCountResponse, ServiceError> {
        self.authorize(ctx, "GetTrafficPolicyInstanceCount", "*")?;
        Ok(types::GetTrafficPolicyInstanceCountResponse {
            traffic_policy_instance_count: self.lock().traffic_policy_instances.len() as i32,
        })
    }

    pub(crate) fn list_traffic_policy_instances(
        &self,
        ctx: &RequestContext,
        input: types::ListTrafficPolicyInstancesRequest,
    ) -> Result<types::ListTrafficPolicyInstancesResponse, ServiceError> {
        self.authorize(ctx, "ListTrafficPolicyInstances", "*")?;
        let st = self.lock();
        let page = page_instances(
            st.traffic_policy_instances.values(),
            input.hosted_zone_id_marker.as_deref(),
            input.traffic_policy_instance_name_marker.as_deref(),
            input.traffic_policy_instance_type_marker.as_deref(),
            input.max_items,
        );
        Ok(types::ListTrafficPolicyInstancesResponse {
            traffic_policy_instances: page.items,
            is_truncated: page.next.is_some(),
            hosted_zone_id_marker: page.next.as_ref().map(|n| n.0.clone()),
            traffic_policy_instance_name_marker: page.next.as_ref().map(|n| n.1.clone()),
            traffic_policy_instance_type_marker: page.next.as_ref().map(|n| n.2.clone()),
            max_items: page.limit as i32,
        })
    }

    pub(crate) fn list_traffic_policy_instances_by_hosted_zone(
        &self,
        ctx: &RequestContext,
        input: types::ListTrafficPolicyInstancesByHostedZoneRequest,
    ) -> Result<types::ListTrafficPolicyInstancesByHostedZoneResponse, ServiceError> {
        let zone_id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "ListTrafficPolicyInstancesByHostedZone", &arn(ctx, "hostedzone", &zone_id))?;
        let st = self.lock();
        st.zone(&zone_id)?;
        let page = page_instances(
            st.traffic_policy_instances.values().filter(|i| i.hosted_zone_id == zone_id),
            None,
            input.traffic_policy_instance_name_marker.as_deref(),
            input.traffic_policy_instance_type_marker.as_deref(),
            input.max_items,
        );
        Ok(types::ListTrafficPolicyInstancesByHostedZoneResponse {
            traffic_policy_instances: page.items,
            is_truncated: page.next.is_some(),
            traffic_policy_instance_name_marker: page.next.as_ref().map(|n| n.1.clone()),
            traffic_policy_instance_type_marker: page.next.as_ref().map(|n| n.2.clone()),
            max_items: page.limit as i32,
        })
    }

    pub(crate) fn list_traffic_policy_instances_by_policy(
        &self,
        ctx: &RequestContext,
        input: types::ListTrafficPolicyInstancesByPolicyRequest,
    ) -> Result<types::ListTrafficPolicyInstancesByPolicyResponse, ServiceError> {
        self.authorize(
            ctx,
            "ListTrafficPolicyInstancesByPolicy",
            &arn(ctx, "trafficpolicy", &input.traffic_policy_id),
        )?;
        let st = self.lock();
        st.policy_version(&input.traffic_policy_id, input.traffic_policy_version)?;
        let page = page_instances(
            st.traffic_policy_instances.values().filter(|i| {
                i.traffic_policy_id == input.traffic_policy_id
                    && i.traffic_policy_version == input.traffic_policy_version
            }),
            input.hosted_zone_id_marker.as_deref(),
            input.traffic_policy_instance_name_marker.as_deref(),
            input.traffic_policy_instance_type_marker.as_deref(),
            input.max_items,
        );
        Ok(types::ListTrafficPolicyInstancesByPolicyResponse {
            traffic_policy_instances: page.items,
            is_truncated: page.next.is_some(),
            hosted_zone_id_marker: page.next.as_ref().map(|n| n.0.clone()),
            traffic_policy_instance_name_marker: page.next.as_ref().map(|n| n.1.clone()),
            traffic_policy_instance_type_marker: page.next.as_ref().map(|n| n.2.clone()),
            max_items: page.limit as i32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAILOVER: &str = r#"{
        "AWSPolicyFormatVersion": "2015-10-01",
        "RecordType": "A",
        "StartRule": "switch",
        "Endpoints": {
            "main": {"Type": "value", "Value": "192.0.2.1"},
            "backup": {"Type": "value", "Value": "192.0.2.2"}
        },
        "Rules": {
            "switch": {"RuleType": "failover", "Primary": {"EndpointReference": "main"}, "Secondary": {"EndpointReference": "backup"}}
        }
    }"#;

    #[test]
    fn failover_document_becomes_two_records() {
        let doc = parse_document(FAILOVER).unwrap();
        let records = doc.records("www.example.com.", 60, "i-1");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].failover.as_deref(), Some("PRIMARY"));
        assert_eq!(records[1].resource_records.as_ref().unwrap()[0].value, "192.0.2.2");
    }

    #[test]
    fn rejects_bad_documents() {
        assert!(parse_document("{}").is_err());
        let dangling = FAILOVER.replace(r#""EndpointReference": "backup""#, r#""EndpointReference": "nope""#);
        assert!(parse_document(&dangling).is_err());
        let cyclic = FAILOVER.replace(r#""EndpointReference": "backup""#, r#""RuleReference": "switch""#);
        assert!(parse_document(&cyclic).is_err());
    }
}
