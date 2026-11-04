//! Resource policies, account policies, data protection (masking), index
//! policies and field indexes.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use regex::Regex;
use serde_json::Value;

use crate::generated::{errors, types};
use crate::names::{now_ms, page, random_hex, GroupRef};
use crate::state::ResourcePolicy;
use crate::Logs;

const MAX_ACCOUNT_RESOURCE_POLICIES: usize = 10;

fn managed_identifier(name: &str) -> Option<&'static str> {
    Some(match name {
        "EmailAddress" => r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "IpAddress" => r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "Ssn-US" => r"\b\d{3}-\d{2}-\d{4}\b",
        "PhoneNumber-US" => r"(?:\+1[ -]?)?\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b",
        "CreditCardNumber" => r"\b(?:\d[ -]?){12,18}\d\b",
        "AwsSecretKey" => r"(?i)\b(?:aws_?secret_?(?:access_?)?key)\b\s*[:=]\s*[A-Za-z0-9/+=]{40}",
        "OpenSshPrivateKey" => r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
        "PkcsPrivateKey" => r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----",
        _ => return None,
    })
}

fn luhn(digits: &str) -> bool {
    let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() < 13 {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 1 {
                let y = x * 2;
                if y > 9 {
                    y - 9
                } else {
                    y
                }
            } else {
                x
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// The data identifiers a policy document de-identifies, as regexes.
fn deidentify_patterns(doc: &str) -> Vec<(String, Regex)> {
    let Ok(v) = serde_json::from_str::<Value>(doc) else { return Vec::new() };
    let mut custom = BTreeMap::new();
    for c in v.pointer("/Configuration/CustomDataIdentifier").and_then(Value::as_array).into_iter().flatten() {
        if let (Some(n), Some(r)) = (c.get("Name").and_then(Value::as_str), c.get("Regex").and_then(Value::as_str)) {
            custom.insert(n.to_string(), r.to_string());
        }
    }
    let mut out = Vec::new();
    for s in v.get("Statement").and_then(Value::as_array).into_iter().flatten() {
        if s.pointer("/Operation/Deidentify").is_none() {
            continue;
        }
        for id in s.get("DataIdentifier").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            let name = id.rsplit('/').next().unwrap_or(id);
            let re = custom.get(name).cloned().or_else(|| managed_identifier(name).map(str::to_string));
            if let Some(re) = re.and_then(|r| Regex::new(&r).ok()) {
                out.push((name.to_string(), re));
            }
        }
    }
    out
}

/// The data protection policies that apply to `g`'s events: its own and
/// the account's, each with the time it took effect.
pub(crate) fn masks_for(st: &crate::state::State, g: &GroupRef) -> Vec<(String, i64)> {
    let mut out: Vec<(String, i64)> =
        st.group(g).ok().and_then(|group| group.data_protection_policy.clone()).into_iter().collect();
    if let Some(region) = st.region_ref(&g.account, &g.region) {
        out.extend(
            region
                .account_policies
                .values()
                .filter(|p| p.policy_type.as_deref() == Some("DATA_PROTECTION_POLICY"))
                .filter_map(|p| Some((p.policy_document.clone()?, p.last_updated_time.unwrap_or(0)))),
        );
    }
    out
}

/// Mask what the data protection policies in `policies` de-identify: each
/// matched character becomes `*`. Like AWS, a policy masks only events
/// ingested after it took effect.
pub fn mask(policies: &[(String, i64)], ingested: i64, message: &str) -> String {
    let mut out = message.to_string();
    for (doc, since) in policies {
        if ingested < *since {
            continue;
        }
        for (name, re) in deidentify_patterns(doc) {
            out = re
                .replace_all(&out, |c: &regex::Captures<'_>| {
                    let m = &c[0];
                    if name == "CreditCardNumber" && !luhn(m) {
                        m.to_string()
                    } else {
                        "*".repeat(m.chars().count())
                    }
                })
                .into_owned();
        }
    }
    out
}

fn check_data_protection_policy(doc: &str) -> Result<(), ServiceError> {
    let bad = || errors::invalid_parameter("Invalid data protection policy document.");
    let v: Value = serde_json::from_str(doc).map_err(|_| bad())?;
    let statements = v.get("Statement").and_then(Value::as_array).ok_or_else(bad)?;
    let ops = |kind: &str| statements.iter().filter(|s| s.pointer(&format!("/Operation/{kind}")).is_some()).count();
    if statements.len() != 2 || ops("Audit") != 1 || ops("Deidentify") != 1 {
        return Err(errors::invalid_parameter(
            "A data protection policy must contain exactly one Audit statement and one Deidentify statement.",
        ));
    }
    for s in statements {
        if s.get("DataIdentifier").and_then(Value::as_array).is_none_or(|a| a.is_empty()) {
            return Err(bad());
        }
    }
    Ok(())
}

/// Field names an index policy document indexes.
pub fn indexed_fields(doc: &str) -> Vec<String> {
    serde_json::from_str::<Value>(doc)
        .ok()
        .and_then(|v| v.get("Fields").cloned())
        .and_then(|f| f.as_array().cloned())
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

fn check_json(doc: &str, what: &str) -> Result<Value, ServiceError> {
    serde_json::from_str(doc).map_err(|_| errors::invalid_parameter(format!("{what} is not valid JSON.")))
}

impl Logs {
    // ---- resource policies ---------------------------------------------------

    pub(crate) fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyRequest,
    ) -> Result<types::PutResourcePolicyResponse, ServiceError> {
        let doc = input.policy_document.ok_or_else(|| errors::invalid_parameter("policyDocument is required."))?;
        check_json(&doc, "Policy document")?;
        let now = now_ms(ctx);
        let (key, name, resource_arn) = match &input.resource_arn {
            Some(r) => {
                let g = GroupRef::parse(ctx, r)?;
                self.authorize_group(ctx, "PutResourcePolicy", &g, None, ConditionContext::new())?;
                self.lock().group(&g)?;
                (format!("@{}", g.arn()), input.policy_name.clone(), Some(g.arn()))
            }
            None => {
                let name = input
                    .policy_name
                    .clone()
                    .ok_or_else(|| errors::invalid_parameter("policyName is required for an account-level policy."))?;
                self.authorize(ctx, "PutResourcePolicy", "*", ConditionContext::new())?;
                (name.clone(), Some(name), None)
            }
        };
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(expected) = &input.expected_revision_id {
            let current = region.resource_policies.get(&key).map(|p| p.revision_id.clone());
            if current.as_ref() != Some(expected) {
                return Err(errors::operation_aborted("The expected revision ID does not match the current revision."));
            }
        }
        if resource_arn.is_none()
            && !region.resource_policies.contains_key(&key)
            && region.resource_policies.values().filter(|p| p.resource_arn.is_none()).count()
                >= MAX_ACCOUNT_RESOURCE_POLICIES
        {
            return Err(errors::limit_exceeded("Resource limit exceeded."));
        }
        let p =
            ResourcePolicy { name, resource_arn, document: doc, last_updated_time: now, revision_id: random_hex(32) };
        region.resource_policies.insert(key, p.clone());
        Ok(types::PutResourcePolicyResponse {
            revision_id: Some(p.revision_id.clone()),
            resource_policy: Some(describe_rp(&p)),
        })
    }

    pub(crate) fn describe_resource_policies(
        &self,
        ctx: &RequestContext,
        input: types::DescribeResourcePoliciesRequest,
    ) -> Result<types::DescribeResourcePoliciesResponse, ServiceError> {
        self.authorize(ctx, "DescribeResourcePolicies", "*", ConditionContext::new())?;
        let wanted = input.resource_arn.as_ref().map(|r| GroupRef::parse(ctx, r).map(|g| g.arn())).transpose()?;
        let st = self.lock();
        let out: Vec<types::ResourcePolicy> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.resource_policies
                    .values()
                    .filter(|p| match (&wanted, input.policy_scope.as_deref()) {
                        (Some(w), _) => p.resource_arn.as_ref() == Some(w),
                        (None, Some("RESOURCE")) => p.resource_arn.is_some(),
                        (None, _) => p.resource_arn.is_none(),
                    })
                    .map(describe_rp)
                    .collect()
            })
            .unwrap_or_default();
        let (policies, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeResourcePoliciesResponse { resource_policies: Some(policies), next_token })
    }

    pub(crate) fn delete_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourcePolicyRequest,
    ) -> Result<(), ServiceError> {
        let key = match (&input.resource_arn, &input.policy_name) {
            (Some(r), _) => {
                let g = GroupRef::parse(ctx, r)?;
                self.authorize_group(ctx, "DeleteResourcePolicy", &g, None, ConditionContext::new())?;
                format!("@{}", g.arn())
            }
            (None, Some(n)) => {
                self.authorize(ctx, "DeleteResourcePolicy", "*", ConditionContext::new())?;
                n.clone()
            }
            (None, None) => return Err(errors::invalid_parameter("Either policyName or resourceArn is required.")),
        };
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let current = region
            .resource_policies
            .get(&key)
            .ok_or_else(|| errors::resource_not_found("Policy with the specified name does not exist."))?;
        if input.expected_revision_id.as_ref().is_some_and(|e| e != &current.revision_id) {
            return Err(errors::operation_aborted("The expected revision ID does not match the current revision."));
        }
        region.resource_policies.remove(&key);
        Ok(())
    }

    // ---- account policies ----------------------------------------------------

    pub(crate) fn put_account_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountPolicyRequest,
    ) -> Result<types::PutAccountPolicyResponse, ServiceError> {
        self.authorize(ctx, "PutAccountPolicy", "*", ConditionContext::new())?;
        if input.policy_type == "DATA_PROTECTION_POLICY" {
            check_data_protection_policy(&input.policy_document)?;
        } else if input.policy_type == "TRANSFORMER_POLICY" {
            let doc = check_json(&input.policy_document, "Policy document")?;
            let mut d = mws_proto_json::Decoder::new();
            let processors =
                crate::generated::de::de_processors(&mut d, doc.get("transformerConfig"), "transformerConfig")
                    .ok_or_else(|| errors::invalid_parameter("Policy document must contain a transformerConfig."))?;
            d.finish("InvalidParameterException")?;
            crate::transform::validate(&processors).map_err(errors::invalid_parameter)?;
        } else {
            check_json(&input.policy_document, "Policy document")?;
        }
        if input.selection_criteria.is_some() && matches!(input.policy_type.as_str(), "DATA_PROTECTION_POLICY") {
            return Err(errors::invalid_parameter("selectionCriteria is not supported for data protection policies."));
        }
        let policy = types::AccountPolicy {
            policy_name: Some(input.policy_name.clone()),
            policy_document: Some(input.policy_document.clone()),
            last_updated_time: Some(now_ms(ctx)),
            policy_type: Some(input.policy_type.clone()),
            scope: Some(input.scope.unwrap_or_else(|| "ALL".into())),
            selection_criteria: input.selection_criteria,
            account_id: Some(ctx.caller.account_id.clone()),
        };
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let dry_run = (input.policy_type == "RETENTION_POLICY" || input.dry_run).then(|| {
            let days = check_json(&input.policy_document, "Policy document")
                .ok()
                .and_then(|v| v.get("retentionInDays").or_else(|| v.get("RetentionInDays")).and_then(Value::as_i64));
            let mut r = types::DryRunResult::default();
            let mut impacted = Vec::new();
            for g in region.log_groups.values() {
                r.total_matched_log_groups += 1;
                let (cur, new) = (g.retention_in_days.map(i64::from), days);
                let ord = match (cur, new) {
                    (Some(c), Some(n)) => c.cmp(&n).reverse(),
                    (None, Some(_)) => std::cmp::Ordering::Less,
                    _ => std::cmp::Ordering::Equal,
                };
                match ord {
                    std::cmp::Ordering::Greater => r.increased_retention_log_group_count += 1,
                    std::cmp::Ordering::Less => r.decreased_retention_log_group_count += 1,
                    std::cmp::Ordering::Equal => r.unchanged_retention_log_group_count += 1,
                }
                if ord != std::cmp::Ordering::Equal {
                    impacted.push(types::LogGroupImpact {
                        log_group_name: Some(g.name.clone()),
                        current_retention: Some(cur.map_or("Never expire".into(), |c| c.to_string())),
                        proposed_retention: Some(new.map_or("Never expire".into(), |n| n.to_string())),
                        stored_bytes: Some(g.streams.values().map(crate::state::LogStream::stored_bytes).sum()),
                    });
                }
            }
            r.top_log_groups_impacted = Some(impacted.into_iter().take(10).collect());
            r
        });
        if input.dry_run {
            return Ok(types::PutAccountPolicyResponse { account_policy: None, dry_run_result: dry_run });
        }
        if matches!(input.policy_type.as_str(), "DATA_PROTECTION_POLICY" | "SUBSCRIPTION_FILTER_POLICY") {
            let prefix = format!("{}/", input.policy_type);
            region.account_policies.retain(|k, _| !k.starts_with(&prefix));
        }
        let same_type =
            region.account_policies.keys().filter(|k| k.starts_with(&format!("{}/", input.policy_type))).count();
        let key = format!("{}/{}", input.policy_type, input.policy_name);
        if !region.account_policies.contains_key(&key) && same_type >= 20 {
            return Err(errors::limit_exceeded("Resource limit exceeded."));
        }
        region.account_policies.insert(key, policy.clone());
        Ok(types::PutAccountPolicyResponse { account_policy: Some(policy), dry_run_result: dry_run })
    }

    pub(crate) fn describe_account_policies(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountPoliciesRequest,
    ) -> Result<types::DescribeAccountPoliciesResponse, ServiceError> {
        self.authorize(ctx, "DescribeAccountPolicies", "*", ConditionContext::new())?;
        let st = self.lock();
        let mut accounts = vec![ctx.caller.account_id.clone()];
        accounts.extend(input.account_identifiers.iter().flatten().filter(|a| **a != ctx.caller.account_id).cloned());
        let mut out = Vec::new();
        for a in &accounts {
            if let Some(r) = st.region_ref(a, &ctx.region) {
                out.extend(
                    r.account_policies
                        .values()
                        .filter(|p| p.policy_type.as_deref() == Some(&input.policy_type))
                        .filter(|p| input.policy_name.as_ref().is_none_or(|n| p.policy_name.as_ref() == Some(n)))
                        .cloned(),
                );
            }
        }
        let (out, next_token) = page(out, input.next_token.as_deref(), 50)?;
        Ok(types::DescribeAccountPoliciesResponse { account_policies: Some(out), next_token })
    }

    pub(crate) fn delete_account_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccountPolicyRequest,
    ) -> Result<types::DeleteAccountPolicyResponse, ServiceError> {
        self.authorize(ctx, "DeleteAccountPolicy", "*", ConditionContext::new())?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let key = format!("{}/{}", input.policy_type, input.policy_name);
        if !region.account_policies.contains_key(&key) {
            return Err(errors::resource_not_found(format!("Policy with name [{}] does not exist", input.policy_name)));
        }
        if input.dry_run {
            return Ok(types::DeleteAccountPolicyResponse {
                dry_run_result: Some(types::DryRunResult {
                    total_matched_log_groups: region.log_groups.len() as i32,
                    unchanged_retention_log_group_count: region.log_groups.len() as i32,
                    ..Default::default()
                }),
            });
        }
        region.account_policies.remove(&key);
        Ok(types::DeleteAccountPolicyResponse { dry_run_result: None })
    }

    // ---- data protection -----------------------------------------------------

    pub(crate) fn put_data_protection_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutDataProtectionPolicyRequest,
    ) -> Result<types::PutDataProtectionPolicyResponse, ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "PutDataProtectionPolicy", &g, None, ConditionContext::new())?;
        check_data_protection_policy(&input.policy_document)?;
        let now = now_ms(ctx);
        self.lock().group_mut(&g)?.data_protection_policy = Some((input.policy_document.clone(), now));
        Ok(types::PutDataProtectionPolicyResponse {
            log_group_identifier: Some(input.log_group_identifier),
            policy_document: Some(input.policy_document),
            last_updated_time: Some(now),
        })
    }

    pub(crate) fn get_data_protection_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetDataProtectionPolicyRequest,
    ) -> Result<types::GetDataProtectionPolicyResponse, ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "GetDataProtectionPolicy", &g, None, ConditionContext::new())?;
        let st = self.lock();
        let p = st.group(&g)?.data_protection_policy.clone();
        Ok(types::GetDataProtectionPolicyResponse {
            log_group_identifier: Some(input.log_group_identifier),
            policy_document: p.as_ref().map(|(d, _)| d.clone()),
            last_updated_time: p.map(|(_, t)| t),
        })
    }

    pub(crate) fn delete_data_protection_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDataProtectionPolicyRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "DeleteDataProtectionPolicy", &g, None, ConditionContext::new())?;
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        group
            .data_protection_policy
            .take()
            .ok_or_else(|| errors::resource_not_found("No data protection policy found for the log group."))?;
        Ok(())
    }

    // ---- index policies and field indexes ------------------------------------

    pub(crate) fn put_index_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutIndexPolicyRequest,
    ) -> Result<types::PutIndexPolicyResponse, ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "PutIndexPolicy", &g, None, ConditionContext::new())?;
        let v = check_json(&input.policy_document, "Policy document")?;
        if !v.get("Fields").is_some_and(Value::is_array) {
            return Err(errors::invalid_parameter("The index policy document must contain a Fields array."));
        }
        let policy = types::IndexPolicy {
            log_group_identifier: Some(g.arn()),
            last_update_time: Some(now_ms(ctx)),
            policy_document: Some(input.policy_document),
            policy_name: None,
            source: Some("LOG_GROUP".into()),
        };
        self.lock().group_mut(&g)?.index_policy = Some(policy.clone());
        Ok(types::PutIndexPolicyResponse { index_policy: Some(policy) })
    }

    pub(crate) fn delete_index_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteIndexPolicyRequest,
    ) -> Result<types::DeleteIndexPolicyResponse, ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "DeleteIndexPolicy", &g, None, ConditionContext::new())?;
        let mut st = self.lock();
        st.group_mut(&g)?
            .index_policy
            .take()
            .ok_or_else(|| errors::resource_not_found("No index policy found for the log group."))?;
        Ok(types::DeleteIndexPolicyResponse {})
    }

    /// Index policies that apply to `g`: its own, else the account's.
    fn effective_index_policies(&self, g: &GroupRef) -> Result<Vec<types::IndexPolicy>, ServiceError> {
        let st = self.lock();
        let group = st.group(g)?;
        if let Some(p) = &group.index_policy {
            return Ok(vec![p.clone()]);
        }
        let region = st.region_ref(&g.account, &g.region);
        Ok(region
            .into_iter()
            .flat_map(|r| r.account_policies.values())
            .filter(|p| p.policy_type.as_deref() == Some("FIELD_INDEX_POLICY"))
            .filter(|p| selection_matches(p.selection_criteria.as_deref(), &g.name))
            .map(|p| types::IndexPolicy {
                log_group_identifier: Some(g.arn()),
                last_update_time: p.last_updated_time,
                policy_document: p.policy_document.clone(),
                policy_name: p.policy_name.clone(),
                source: Some("ACCOUNT".into()),
            })
            .collect())
    }

    pub(crate) fn describe_index_policies(
        &self,
        ctx: &RequestContext,
        input: types::DescribeIndexPoliciesRequest,
    ) -> Result<types::DescribeIndexPoliciesResponse, ServiceError> {
        let mut out = Vec::new();
        for id in &input.log_group_identifiers {
            let g = GroupRef::parse(ctx, id)?;
            self.authorize_group(ctx, "DescribeIndexPolicies", &g, None, ConditionContext::new())?;
            out.extend(self.effective_index_policies(&g)?);
        }
        let (out, next_token) = page(out, input.next_token.as_deref(), 50)?;
        Ok(types::DescribeIndexPoliciesResponse { index_policies: Some(out), next_token })
    }

    pub(crate) fn describe_field_indexes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFieldIndexesRequest,
    ) -> Result<types::DescribeFieldIndexesResponse, ServiceError> {
        let mut out = Vec::new();
        for id in &input.log_group_identifiers {
            let g = GroupRef::parse(ctx, id)?;
            self.authorize_group(ctx, "DescribeFieldIndexes", &g, None, ConditionContext::new())?;
            let policies = self.effective_index_policies(&g)?;
            let st = self.lock();
            let group = st.group(&g)?;
            for p in policies {
                for field in indexed_fields(p.policy_document.as_deref().unwrap_or("{}")) {
                    let mut first = None;
                    let mut last = None;
                    for s in group.streams.values() {
                        for e in &s.events {
                            let mut r = crate::insights::Record::new();
                            crate::insights::discover_json(&e.message, &mut r);
                            if r.contains_key(&field) {
                                first = Some(first.map_or(e.timestamp, |f: i64| f.min(e.timestamp)));
                                last = Some(last.map_or(e.timestamp, |l: i64| l.max(e.timestamp)));
                            }
                        }
                    }
                    let category = "CUSTOM";
                    if input.index_categories.as_ref().is_some_and(|c| !c.iter().any(|x| x == category)) {
                        continue;
                    }
                    out.push(types::FieldIndex {
                        log_group_identifier: Some(g.arn()),
                        field_index_name: Some(field),
                        last_scan_time: Some(now_ms(ctx)),
                        first_event_time: first,
                        last_event_time: last,
                        r#type: Some("FIELD_INDEX".into()),
                        index_category: Some(category.into()),
                    });
                }
            }
        }
        let (out, next_token) = page(out, input.next_token.as_deref(), 100)?;
        Ok(types::DescribeFieldIndexesResponse { field_indexes: Some(out), next_token })
    }
}

fn describe_rp(p: &ResourcePolicy) -> types::ResourcePolicy {
    types::ResourcePolicy {
        policy_name: p.name.clone(),
        policy_document: Some(p.document.clone()),
        last_updated_time: Some(p.last_updated_time),
        policy_scope: Some(if p.resource_arn.is_some() { "RESOURCE" } else { "ACCOUNT" }.into()),
        resource_arn: p.resource_arn.clone(),
        revision_id: Some(p.revision_id.clone()),
    }
}

/// Account policy selection criteria: `LogGroupName NOT IN ["a", "b"]` or
/// `LogGroupNamePrefix IN ["/aws/", ...]`. No criteria selects everything.
pub fn selection_matches(criteria: Option<&str>, group: &str) -> bool {
    let Some(c) = criteria.map(str::trim).filter(|c| !c.is_empty()) else { return true };
    let values: Vec<String> =
        c.find('[').and_then(|i| serde_json::from_str::<Vec<String>>(&c[i..]).ok()).unwrap_or_default();
    if c.starts_with("LogGroupNamePrefix") {
        let hit = values.iter().any(|p| group.starts_with(p.as_str()));
        if c.contains("NOT IN") {
            !hit
        } else {
            hit
        }
    } else if c.starts_with("LogGroupName") {
        let hit = values.iter().any(|n| n == group);
        if c.contains("NOT IN") {
            !hit
        } else {
            hit
        }
    } else {
        true
    }
}
