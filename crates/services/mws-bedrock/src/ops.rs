//! Guardrails, Provisioned Throughput, prompt routers, invocation logging,
//! account-enforced guardrails, Marketplace endpoints, resource policies
//! and tags.

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Map, Value};

use crate::catalog;
use crate::generated::types;
use crate::resolve::foundation_from_arn;
use crate::state::{kind, Guardrail, GuardrailVersion, Record, Scope};
use crate::util::{
    arn, conflict, from_doc, last_segment, not_found, page, random_id, rename, request_tag_context,
    resource_tag_context, set, sort_records, tag_list, tag_map, to_doc, too_many_tags, ts, validation, MAX_TAGS,
};
use crate::Bedrock;

/// How long Provisioned Throughput takes to come into service.
const PROVISIONING_SECS: i64 = 1;

fn guardrail_not_found(ident: &str) -> ServiceError {
    not_found(format!("The guardrail {ident} was not found."))
}

/// `Create`/`UpdateGuardrail` configuration fields as the policy fields
/// `GetGuardrail` reports.
fn guardrail_doc<T: serde::Serialize>(config: &T, ctx: &RequestContext) -> Map<String, Value> {
    let mut d = to_doc(config);
    for (from, to, pairs) in [
        ("topic_policy_config", "topic_policy", &[("topics_config", "topics"), ("tier_config", "tier")][..]),
        ("content_policy_config", "content_policy", &[("filters_config", "filters"), ("tier_config", "tier")][..]),
        (
            "word_policy_config",
            "word_policy",
            &[("words_config", "words"), ("managed_word_lists_config", "managed_word_lists")][..],
        ),
        (
            "sensitive_information_policy_config",
            "sensitive_information_policy",
            &[("pii_entities_config", "pii_entities"), ("regexes_config", "regexes")][..],
        ),
        (
            "contextual_grounding_policy_config",
            "contextual_grounding_policy",
            &[("filters_config", "filters"), ("tier_config", "tier")][..],
        ),
        ("automated_reasoning_policy_config", "automated_reasoning_policy", &[][..]),
    ] {
        if let Some(Value::Object(mut policy)) = d.remove(from) {
            for (a, b) in pairs {
                rename(&mut policy, a, b);
            }
            d.insert(to.to_string(), Value::Object(policy));
        }
    }
    if let Some(Value::Object(cr)) = d.remove("cross_region_config") {
        if let Some(p) = cr.get("guardrail_profile_identifier").and_then(Value::as_str) {
            let id = last_segment(p).to_string();
            d.insert(
                "cross_region_details".into(),
                json!({"guardrail_profile_id": id, "guardrail_profile_arn": arn(ctx, &format!("guardrail-profile/{id}"))}),
            );
        }
    }
    if let Some(k) = d.remove("kms_key_id") {
        let k = k.as_str().unwrap_or_default().to_string();
        let key_arn = if k.starts_with("arn:") {
            k
        } else {
            format!("arn:{}:kms:{}:{}:key/{k}", ctx.partition, ctx.region, ctx.caller.account_id)
        };
        d.insert("kms_key_arn".into(), json!(key_arn));
    }
    for k in ["tags", "client_request_token", "guardrail_identifier"] {
        d.remove(k);
    }
    d
}

fn check_guardrail_config(
    content: &Option<types::GuardrailContentPolicyConfig>,
    sensitive: &Option<types::GuardrailSensitiveInformationPolicyConfig>,
) -> Result<(), ServiceError> {
    for f in content.iter().flat_map(|c| &c.filters_config) {
        if f.r#type == "PROMPT_ATTACK" && f.output_strength != "NONE" {
            return Err(validation("PROMPT_ATTACK content filter strength for response must be NONE."));
        }
    }
    for r in sensitive.iter().flat_map(|s| s.regexes_config.iter().flatten()) {
        if regex::Regex::new(&r.pattern).is_err() {
            return Err(validation(format!("The regex pattern {} is invalid.", r.pattern)));
        }
    }
    Ok(())
}

fn find_guardrail<'a>(s: &'a Scope, ident: &str) -> Option<&'a Guardrail> {
    let id = last_segment(ident);
    s.guardrails.get(id).filter(|g| !ident.starts_with("arn:") || g.arn == ident)
}

fn version_view(g: &Guardrail, v: &GuardrailVersion, version: &str) -> types::GetGuardrailResponse {
    let mut out: types::GetGuardrailResponse = from_doc(&v.doc);
    out.guardrail_id = g.id.clone();
    out.guardrail_arn = g.arn.clone();
    out.version = version.to_string();
    out.status = "READY".into();
    out.created_at = g.created;
    out.updated_at = v.updated;
    out
}

/// A guardrail version, `DRAFT` or a number.
fn guardrail_version(g: &Guardrail, version: Option<&str>) -> Option<types::GetGuardrailResponse> {
    match version.unwrap_or("DRAFT") {
        "DRAFT" | "" => Some(version_view(g, &g.draft, "DRAFT")),
        n => {
            let n: u32 = n.parse().ok()?;
            g.versions.get(&n).map(|v| version_view(g, v, &n.to_string()))
        }
    }
}

fn summary_of(v: &types::GetGuardrailResponse) -> types::GuardrailSummary {
    types::GuardrailSummary {
        id: v.guardrail_id.clone(),
        arn: v.guardrail_arn.clone(),
        status: v.status.clone(),
        name: v.name.clone(),
        description: v.description.clone(),
        version: v.version.clone(),
        created_at: v.created_at,
        updated_at: v.updated_at,
        cross_region_details: v.cross_region_details.clone(),
    }
}

/// Whether a resource with this ARN exists in the scope.
fn exists(s: &Scope, resource_arn: &str) -> bool {
    s.records.values().flatten().any(|(_, r)| r.arn == resource_arn)
        || s.guardrails.values().any(|g| g.arn == resource_arn)
}

impl Bedrock {
    /// A guardrail version for bedrock-runtime to enforce, after checking
    /// the caller may apply it.
    pub fn guardrail_for_invocation(
        &self,
        ctx: &RequestContext,
        identifier: &str,
        version: &str,
    ) -> Result<types::GetGuardrailResponse, ServiceError> {
        let missing = || {
            validation(format!(
                "The guardrail identifier or version provided in the request does not exist: {identifier}:{version}."
            ))
        };
        let (view, tags) = self.scope(ctx, |s| {
            let g = find_guardrail(s, identifier).ok_or_else(missing)?;
            let v = guardrail_version(g, Some(version)).ok_or_else(missing)?;
            Ok::<_, ServiceError>((v, s.tags.get(&g.arn).cloned()))
        })?;
        ctx.authorize("bedrock:ApplyGuardrail", &view.guardrail_arn, resource_tag_context(tags.as_ref()))?;
        Ok(view)
    }

    /// The account's enforced guardrails, as (identifier, version).
    pub fn enforced_guardrails(&self, ctx: &RequestContext) -> Vec<(String, String)> {
        self.scope(ctx, |s| {
            s.kind(kind::ENFORCED_GUARDRAIL)
                .map(|r| {
                    (
                        r.str("guardrail_id").unwrap_or_default().to_string(),
                        r.str("guardrail_version").unwrap_or("DRAFT").to_string(),
                    )
                })
                .collect()
        })
    }

    // Guardrails ----------------------------------------------------------

    pub fn create_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::CreateGuardrailRequest,
    ) -> Result<types::CreateGuardrailResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        if tags.len() > MAX_TAGS {
            return Err(too_many_tags(&input.name));
        }
        check_guardrail_config(&input.content_policy_config, &input.sensitive_information_policy_config)?;
        let id = random_id(12);
        let g_arn = arn(ctx, &format!("guardrail/{id}"));
        ctx.authorize("bedrock:CreateGuardrail", &g_arn, request_tag_context(&tags))?;
        let now = ctx.received_at;
        let doc = guardrail_doc(&input, ctx);
        self.scope(ctx, |s| {
            if s.guardrails.values().any(|g| g.draft.doc.get("name").and_then(Value::as_str) == Some(&input.name)) {
                return Err(conflict(format!("A guardrail with the name {} already exists.", input.name)));
            }
            s.guardrails.insert(
                id.clone(),
                Guardrail {
                    id: id.clone(),
                    arn: g_arn.clone(),
                    created: now,
                    draft: GuardrailVersion { updated: now, doc },
                    versions: Default::default(),
                    next_version: 1,
                },
            );
            if !tags.is_empty() {
                s.tags.insert(g_arn.clone(), tag_map(&tags));
            }
            Ok(())
        })?;
        Ok(types::CreateGuardrailResponse {
            guardrail_id: id,
            guardrail_arn: g_arn,
            version: "DRAFT".into(),
            created_at: now,
        })
    }

    pub fn get_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::GetGuardrailRequest,
    ) -> Result<types::GetGuardrailResponse, ServiceError> {
        let ident = input.guardrail_identifier.as_str();
        let (view, tags) = self.scope(ctx, |s| {
            let g = find_guardrail(s, ident).ok_or_else(|| guardrail_not_found(ident))?;
            let v = guardrail_version(g, input.guardrail_version.as_deref()).ok_or_else(|| {
                not_found(format!(
                    "The guardrail version {} was not found.",
                    input.guardrail_version.as_deref().unwrap_or("DRAFT")
                ))
            })?;
            Ok::<_, ServiceError>((v, s.tags.get(&g.arn).cloned()))
        })?;
        ctx.authorize("bedrock:GetGuardrail", &view.guardrail_arn, resource_tag_context(tags.as_ref()))?;
        Ok(view)
    }

    pub fn update_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::UpdateGuardrailRequest,
    ) -> Result<types::UpdateGuardrailResponse, ServiceError> {
        check_guardrail_config(&input.content_policy_config, &input.sensitive_information_policy_config)?;
        let ident = input.guardrail_identifier.clone();
        let (g_arn, tags) = self.scope(ctx, |s| {
            let g = find_guardrail(s, &ident).ok_or_else(|| guardrail_not_found(&ident))?;
            Ok::<_, ServiceError>((g.arn.clone(), s.tags.get(&g.arn).cloned()))
        })?;
        ctx.authorize("bedrock:UpdateGuardrail", &g_arn, resource_tag_context(tags.as_ref()))?;
        let now = ctx.received_at;
        let doc = guardrail_doc(&input, ctx);
        let id = self.scope(ctx, |s| {
            let other = s.guardrails.values().any(|g| {
                g.arn != g_arn && g.draft.doc.get("name").and_then(Value::as_str) == Some(input.name.as_str())
            });
            if other {
                return Err(conflict(format!("A guardrail with the name {} already exists.", input.name)));
            }
            let g = s.guardrails.values_mut().find(|g| g.arn == g_arn).ok_or_else(|| guardrail_not_found(&ident))?;
            g.draft = GuardrailVersion { updated: now, doc };
            Ok(g.id.clone())
        })?;
        Ok(types::UpdateGuardrailResponse {
            guardrail_id: id,
            guardrail_arn: g_arn,
            version: "DRAFT".into(),
            updated_at: now,
        })
    }

    pub fn create_guardrail_version(
        &self,
        ctx: &RequestContext,
        input: types::CreateGuardrailVersionRequest,
    ) -> Result<types::CreateGuardrailVersionResponse, ServiceError> {
        let ident = input.guardrail_identifier.clone();
        let (g_arn, tags) = self.scope(ctx, |s| {
            let g = find_guardrail(s, &ident).ok_or_else(|| guardrail_not_found(&ident))?;
            Ok::<_, ServiceError>((g.arn.clone(), s.tags.get(&g.arn).cloned()))
        })?;
        ctx.authorize("bedrock:CreateGuardrailVersion", &g_arn, resource_tag_context(tags.as_ref()))?;
        let now = ctx.received_at;
        self.scope(ctx, |s| {
            let g = s.guardrails.values_mut().find(|g| g.arn == g_arn).ok_or_else(|| guardrail_not_found(&ident))?;
            let n = g.next_version.max(1);
            g.next_version = n + 1;
            let mut doc = g.draft.doc.clone();
            if let Some(d) = &input.description {
                doc.insert("description".into(), json!(d));
            }
            g.versions.insert(n, GuardrailVersion { updated: now, doc });
            Ok(types::CreateGuardrailVersionResponse { guardrail_id: g.id.clone(), version: n.to_string() })
        })
    }

    pub fn list_guardrails(
        &self,
        ctx: &RequestContext,
        input: types::ListGuardrailsRequest,
    ) -> Result<types::ListGuardrailsResponse, ServiceError> {
        ctx.authorize("bedrock:ListGuardrails", "*", ConditionContext::new())?;
        let views: Vec<types::GuardrailSummary> = self.scope(ctx, |s| match input.guardrail_identifier.as_deref() {
            Some(ident) => {
                let g = find_guardrail(s, ident).ok_or_else(|| guardrail_not_found(ident))?;
                let mut v = vec![summary_of(&version_view(g, &g.draft, "DRAFT"))];
                v.extend(g.versions.iter().map(|(n, ver)| summary_of(&version_view(g, ver, &n.to_string()))));
                Ok::<_, ServiceError>(v)
            }
            None => {
                let mut gs: Vec<&Guardrail> = s.guardrails.values().collect();
                gs.sort_by(|a, b| b.created.cmp(&a.created).then(a.id.cmp(&b.id)));
                Ok(gs.into_iter().map(|g| summary_of(&version_view(g, &g.draft, "DRAFT"))).collect())
            }
        })?;
        let (guardrails, next_token) = page(views, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListGuardrailsResponse { guardrails, next_token })
    }

    pub fn delete_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::DeleteGuardrailRequest,
    ) -> Result<types::DeleteGuardrailResponse, ServiceError> {
        let ident = input.guardrail_identifier.clone();
        let (g_arn, tags) = self.scope(ctx, |s| {
            let g = find_guardrail(s, &ident).ok_or_else(|| guardrail_not_found(&ident))?;
            Ok::<_, ServiceError>((g.arn.clone(), s.tags.get(&g.arn).cloned()))
        })?;
        ctx.authorize("bedrock:DeleteGuardrail", &g_arn, resource_tag_context(tags.as_ref()))?;
        self.scope(ctx, |s| {
            let id = last_segment(&g_arn).to_string();
            let in_use = s.kind(kind::ENFORCED_GUARDRAIL).any(|r| r.str("guardrail_id") == Some(id.as_str()));
            match input.guardrail_version.as_deref() {
                Some(v) => {
                    let n: u32 = v.parse().map_err(|_| validation(format!("The guardrail version {v} is invalid.")))?;
                    let g = s.guardrails.get_mut(&id).ok_or_else(|| guardrail_not_found(&ident))?;
                    g.versions
                        .remove(&n)
                        .ok_or_else(|| not_found(format!("The guardrail version {v} was not found.")))?;
                }
                None => {
                    if in_use {
                        return Err(crate::util::in_use(
                            "The guardrail is in use by an account-enforced guardrail configuration.",
                        ));
                    }
                    s.guardrails.remove(&id);
                    s.tags.remove(&g_arn);
                }
            }
            Ok(types::DeleteGuardrailResponse {})
        })
    }

    // Provisioned Throughput ---------------------------------------------

    pub fn create_provisioned_model_throughput(
        &self,
        ctx: &RequestContext,
        input: types::CreateProvisionedModelThroughputRequest,
    ) -> Result<types::CreateProvisionedModelThroughputResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        if tags.len() > MAX_TAGS {
            return Err(too_many_tags(&input.provisioned_model_name));
        }
        let id = random_id(12);
        let pt_arn = arn(ctx, &format!("provisioned-model/{id}"));
        ctx.authorize("bedrock:CreateProvisionedModelThroughput", &pt_arn, request_tag_context(&tags))?;
        let now = ctx.received_at;
        self.scope(ctx, |s| {
            let (model_arn, fm_arn) = provisioned_model(s, ctx, &input.model_id)?;
            if s.kind(kind::PROVISIONED).any(|r| r.name == input.provisioned_model_name) {
                return Err(conflict(format!(
                    "A Provisioned Throughput with the name {} already exists.",
                    input.provisioned_model_name
                )));
            }
            let mut doc = Map::new();
            set(&mut doc, "model_units", input.model_units);
            set(&mut doc, "desired_model_units", input.model_units);
            set(&mut doc, "model_arn", model_arn.clone());
            set(&mut doc, "desired_model_arn", model_arn);
            set(&mut doc, "foundation_model_arn", fm_arn);
            if let Some(c) = &input.commitment_duration {
                set(&mut doc, "commitment_duration", c.clone());
                let months = if c == "SixMonths" { 6 } else { 1 };
                set(&mut doc, "commitment_expiration_time", ts(now + Duration::days(30 * months)));
            }
            s.insert(
                kind::PROVISIONED,
                Record {
                    id: id.clone(),
                    arn: pt_arn.clone(),
                    name: input.provisioned_model_name.clone(),
                    created: now,
                    updated: now,
                    status: "Creating".into(),
                    transition: Some(("InService".into(), now + Duration::seconds(PROVISIONING_SECS))),
                    steps: Vec::new(),
                    doc,
                },
            );
            if !tags.is_empty() {
                s.tags.insert(pt_arn.clone(), tag_map(&tags));
            }
            Ok(())
        })?;
        Ok(types::CreateProvisionedModelThroughputResponse { provisioned_model_arn: pt_arn })
    }

    fn provisioned(&self, ctx: &RequestContext, ident: &str, action: &str) -> Result<Record, ServiceError> {
        let (r, tags) = self.scope(ctx, |s| {
            let r = s
                .find(kind::PROVISIONED, ident)
                .cloned()
                .ok_or_else(|| not_found(format!("Provisioned Throughput {ident} was not found.")))?;
            let tags = s.tags.get(&r.arn).cloned();
            Ok::<_, ServiceError>((r, tags))
        })?;
        ctx.authorize(action, &r.arn, resource_tag_context(tags.as_ref()))?;
        Ok(r)
    }

    pub fn get_provisioned_model_throughput(
        &self,
        ctx: &RequestContext,
        input: types::GetProvisionedModelThroughputRequest,
    ) -> Result<types::GetProvisionedModelThroughputResponse, ServiceError> {
        let r = self.provisioned(ctx, &input.provisioned_model_id, "bedrock:GetProvisionedModelThroughput")?;
        Ok(from_doc(&provisioned_doc(&r)))
    }

    pub fn update_provisioned_model_throughput(
        &self,
        ctx: &RequestContext,
        input: types::UpdateProvisionedModelThroughputRequest,
    ) -> Result<types::UpdateProvisionedModelThroughputResponse, ServiceError> {
        let r = self.provisioned(ctx, &input.provisioned_model_id, "bedrock:UpdateProvisionedModelThroughput")?;
        let now = ctx.received_at;
        self.scope(ctx, |s| {
            let desired = match &input.desired_model_id {
                Some(m) => {
                    let (model_arn, fm) = provisioned_model(s, ctx, m)?;
                    if Some(fm.as_str()) != r.str("foundation_model_arn") {
                        return Err(validation(
                            "The desired model must be customized from the same base model as the current model.",
                        ));
                    }
                    Some(model_arn)
                }
                None => None,
            };
            if let Some(name) = &input.desired_provisioned_model_name {
                if s.kind(kind::PROVISIONED).any(|o| &o.name == name && o.id != r.id) {
                    return Err(conflict(format!("A Provisioned Throughput with the name {name} already exists.")));
                }
            }
            let rec = s.get_mut(kind::PROVISIONED, &r.id).expect("record exists");
            if rec.status != "InService" {
                return Err(conflict("The Provisioned Throughput is not in service. Try again when it is."));
            }
            if let Some(name) = &input.desired_provisioned_model_name {
                rec.name = name.clone();
            }
            if let Some(m) = desired {
                set(&mut rec.doc, "desired_model_arn", m.clone());
                set(&mut rec.doc, "model_arn", m);
                rec.status = "Updating".into();
                rec.transition = Some(("InService".into(), now + Duration::seconds(PROVISIONING_SECS)));
            }
            rec.updated = now;
            Ok(types::UpdateProvisionedModelThroughputResponse {})
        })
    }

    pub fn delete_provisioned_model_throughput(
        &self,
        ctx: &RequestContext,
        input: types::DeleteProvisionedModelThroughputRequest,
    ) -> Result<types::DeleteProvisionedModelThroughputResponse, ServiceError> {
        let r = self.provisioned(ctx, &input.provisioned_model_id, "bedrock:DeleteProvisionedModelThroughput")?;
        if let Some(exp) = r
            .doc
            .get("commitment_expiration_time")
            .and_then(|v| serde_json::from_value::<chrono::DateTime<chrono::Utc>>(v.clone()).ok())
        {
            if ctx.received_at < exp {
                return Err(conflict("You can't delete a Provisioned Throughput before its commitment term ends."));
            }
        }
        self.scope(ctx, |s| s.remove(kind::PROVISIONED, &r.id));
        Ok(types::DeleteProvisionedModelThroughputResponse {})
    }

    pub fn list_provisioned_model_throughputs(
        &self,
        ctx: &RequestContext,
        input: types::ListProvisionedModelThroughputsRequest,
    ) -> Result<types::ListProvisionedModelThroughputsResponse, ServiceError> {
        ctx.authorize("bedrock:ListProvisionedModelThroughputs", "*", ConditionContext::new())?;
        let items: Vec<types::ProvisionedModelSummary> = self.scope(ctx, |s| {
            let mut v: Vec<&Record> = s
                .kind(kind::PROVISIONED)
                .filter(|r| input.status_equals.as_ref().is_none_or(|st| &r.status == st))
                .filter(|r| input.model_arn_equals.as_ref().is_none_or(|m| r.str("model_arn") == Some(m.as_str())))
                .filter(|r| input.name_contains.as_ref().is_none_or(|n| r.name.contains(n.as_str())))
                .filter(|r| input.creation_time_after.is_none_or(|t| r.created > t))
                .filter(|r| input.creation_time_before.is_none_or(|t| r.created < t))
                .collect();
            sort_records(&mut v, input.sort_by.as_deref(), input.sort_order.as_deref());
            v.into_iter().map(|r| from_doc(&provisioned_doc(r))).collect()
        });
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListProvisionedModelThroughputsResponse { next_token, provisioned_model_summaries: Some(items) })
    }

    // Prompt routers ------------------------------------------------------

    pub fn create_prompt_router(
        &self,
        ctx: &RequestContext,
        input: types::CreatePromptRouterRequest,
    ) -> Result<types::CreatePromptRouterResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        let id = random_id(12);
        let router_arn = arn(ctx, &format!("prompt-router/{id}"));
        ctx.authorize("bedrock:CreatePromptRouter", &router_arn, request_tag_context(&tags))?;
        if input.models.len() != 2 {
            return Err(validation("A prompt router must have exactly two models."));
        }
        let provider = |a: &str| -> Option<String> {
            let id = a.rsplit('/').next()?;
            let id = id
                .split_once('.')
                .map(|(p, rest)| if ["us", "eu", "apac", "global"].contains(&p) { rest } else { id })
                .unwrap_or(id);
            Some(id.split('.').next()?.to_string())
        };
        let providers: Vec<Option<String>> = input.models.iter().map(|m| provider(&m.model_arn)).collect();
        if providers[0] != providers[1] {
            return Err(validation("The models in a prompt router must be from the same model provider."));
        }
        if !input.models.iter().any(|m| m.model_arn == input.fallback_model.model_arn) {
            return Err(validation("The fallback model must be one of the prompt router's models."));
        }
        let now = ctx.received_at;
        self.scope(ctx, |s| {
            if s.kind(kind::PROMPT_ROUTER).any(|r| r.name == input.prompt_router_name) {
                return Err(conflict(format!(
                    "A prompt router with the name {} already exists.",
                    input.prompt_router_name
                )));
            }
            let mut doc = to_doc(&input);
            for k in ["tags", "client_request_token"] {
                doc.remove(k);
            }
            set(&mut doc, "prompt_router_arn", router_arn.clone());
            set(&mut doc, "created_at", ts(now));
            set(&mut doc, "updated_at", ts(now));
            set(&mut doc, "status", "AVAILABLE");
            set(&mut doc, "type", "custom");
            s.insert(
                kind::PROMPT_ROUTER,
                Record {
                    id: id.clone(),
                    arn: router_arn.clone(),
                    name: input.prompt_router_name.clone(),
                    created: now,
                    updated: now,
                    status: "AVAILABLE".into(),
                    transition: None,
                    steps: Vec::new(),
                    doc,
                },
            );
            if !tags.is_empty() {
                s.tags.insert(router_arn.clone(), tag_map(&tags));
            }
            Ok(())
        })?;
        Ok(types::CreatePromptRouterResponse { prompt_router_arn: Some(router_arn) })
    }

    pub fn get_prompt_router(
        &self,
        ctx: &RequestContext,
        input: types::GetPromptRouterRequest,
    ) -> Result<types::GetPromptRouterResponse, ServiceError> {
        let ident = input.prompt_router_arn.as_str();
        let missing = || not_found(format!("The prompt router {ident} was not found."));
        let router = if ident.contains(":default-prompt-router/") {
            crate::models::default_router(ctx, ident.split(":default-prompt-router/").nth(1).unwrap_or_default())
                .filter(|r| r.prompt_router_arn == ident)
                .ok_or_else(missing)?
        } else {
            self.scope(ctx, |s| s.find(kind::PROMPT_ROUTER, ident).map(|r| from_doc(&r.doc))).ok_or_else(missing)?
        };
        ctx.authorize("bedrock:GetPromptRouter", &router.prompt_router_arn, ConditionContext::new())?;
        Ok(router)
    }

    pub fn list_prompt_routers(
        &self,
        ctx: &RequestContext,
        input: types::ListPromptRoutersRequest,
    ) -> Result<types::ListPromptRoutersResponse, ServiceError> {
        ctx.authorize("bedrock:ListPromptRouters", "*", ConditionContext::new())?;
        let routers: Vec<types::GetPromptRouterResponse> = if input.r#type == "custom" {
            self.scope(ctx, |s| {
                let mut v: Vec<&Record> = s.kind(kind::PROMPT_ROUTER).collect();
                sort_records(&mut v, None, Some("Ascending"));
                v.into_iter().map(|r| from_doc(&r.doc)).collect()
            })
        } else {
            crate::models::default_routers(ctx)
        };
        let (items, next_token) = page(routers, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListPromptRoutersResponse {
            prompt_router_summaries: Some(items.iter().map(|r| from_doc(&to_doc(r))).collect()),
            next_token,
        })
    }

    pub fn delete_prompt_router(
        &self,
        ctx: &RequestContext,
        input: types::DeletePromptRouterRequest,
    ) -> Result<types::DeletePromptRouterResponse, ServiceError> {
        let ident = input.prompt_router_arn.as_str();
        if ident.contains(":default-prompt-router/") {
            return Err(validation("Default prompt routers can't be deleted."));
        }
        let id = self
            .scope(ctx, |s| s.find_id(kind::PROMPT_ROUTER, ident))
            .ok_or_else(|| not_found(format!("The prompt router {ident} was not found.")))?;
        ctx.authorize("bedrock:DeletePromptRouter", ident, ConditionContext::new())?;
        self.scope(ctx, |s| s.remove(kind::PROMPT_ROUTER, &id));
        Ok(types::DeletePromptRouterResponse {})
    }

    // Invocation logging ----------------------------------------------------

    pub fn put_model_invocation_logging_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutModelInvocationLoggingConfigurationRequest,
    ) -> Result<types::PutModelInvocationLoggingConfigurationResponse, ServiceError> {
        ctx.authorize("bedrock:PutModelInvocationLoggingConfiguration", "*", ConditionContext::new())?;
        let c = &input.logging_config;
        if c.cloud_watch_config.is_none() && c.s3_config.is_none() {
            return Err(validation("At least one of cloudWatchConfig or s3Config must be specified."));
        }
        let doc = serde_json::to_value(&input.logging_config).expect("logging config serializes");
        self.scope(ctx, |s| s.logging = Some(crate::util::strip_nulls(doc)));
        Ok(types::PutModelInvocationLoggingConfigurationResponse {})
    }

    pub fn get_model_invocation_logging_configuration(
        &self,
        ctx: &RequestContext,
        _input: types::GetModelInvocationLoggingConfigurationRequest,
    ) -> Result<types::GetModelInvocationLoggingConfigurationResponse, ServiceError> {
        ctx.authorize("bedrock:GetModelInvocationLoggingConfiguration", "*", ConditionContext::new())?;
        let logging = self.scope(ctx, |s| s.logging.clone());
        Ok(types::GetModelInvocationLoggingConfigurationResponse {
            logging_config: logging.and_then(|d| serde_json::from_value(d).ok()),
        })
    }

    pub fn delete_model_invocation_logging_configuration(
        &self,
        ctx: &RequestContext,
        _input: types::DeleteModelInvocationLoggingConfigurationRequest,
    ) -> Result<types::DeleteModelInvocationLoggingConfigurationResponse, ServiceError> {
        ctx.authorize("bedrock:DeleteModelInvocationLoggingConfiguration", "*", ConditionContext::new())?;
        self.scope(ctx, |s| s.logging = None);
        Ok(types::DeleteModelInvocationLoggingConfigurationResponse {})
    }

    // Account-enforced guardrails ------------------------------------------

    pub fn put_enforced_guardrail_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutEnforcedGuardrailConfigurationRequest,
    ) -> Result<types::PutEnforcedGuardrailConfigurationResponse, ServiceError> {
        ctx.authorize("bedrock:PutEnforcedGuardrailConfiguration", "*", ConditionContext::new())?;
        let cfg = &input.guardrail_inference_config;
        let now = ctx.received_at;
        let who = ctx.caller.arn.clone();
        let account = ctx.caller.account_id.clone();
        self.scope(ctx, |s| {
            let g = find_guardrail(s, &cfg.guardrail_identifier)
                .ok_or_else(|| guardrail_not_found(&cfg.guardrail_identifier))?;
            if cfg.guardrail_version == "DRAFT" || guardrail_version(g, Some(&cfg.guardrail_version)).is_none() {
                return Err(validation(format!(
                    "The guardrail version {} was not found. Enforced guardrails need a numbered version.",
                    cfg.guardrail_version
                )));
            }
            let (g_id, g_arn) = (g.id.clone(), g.arn.clone());
            let id = match &input.config_id {
                Some(id) => {
                    if s.get(kind::ENFORCED_GUARDRAIL, id).is_none() {
                        return Err(not_found(format!("The enforced guardrail configuration {id} was not found.")));
                    }
                    id.clone()
                }
                None => random_id(12),
            };
            let created = s.get(kind::ENFORCED_GUARDRAIL, &id).map(|r| r.created).unwrap_or(now);
            let created_by = s
                .get(kind::ENFORCED_GUARDRAIL, &id)
                .and_then(|r| r.str("created_by").map(str::to_string))
                .unwrap_or_else(|| who.clone());
            let mut doc = to_doc(cfg);
            doc.remove("guardrail_identifier");
            set(&mut doc, "config_id", id.clone());
            set(&mut doc, "guardrail_id", g_id);
            set(&mut doc, "guardrail_arn", g_arn);
            set(&mut doc, "created_at", ts(created));
            set(&mut doc, "created_by", created_by);
            set(&mut doc, "updated_at", ts(now));
            set(&mut doc, "updated_by", who.clone());
            set(&mut doc, "owner", "ACCOUNT");
            s.insert(
                kind::ENFORCED_GUARDRAIL,
                Record {
                    id: id.clone(),
                    arn: format!("enforced-guardrail/{account}/{id}"),
                    name: id.clone(),
                    created,
                    updated: now,
                    status: "ACTIVE".into(),
                    transition: None,
                    steps: Vec::new(),
                    doc,
                },
            );
            Ok(types::PutEnforcedGuardrailConfigurationResponse {
                config_id: Some(id),
                updated_at: Some(now),
                updated_by: Some(who),
            })
        })
    }

    pub fn list_enforced_guardrails_configuration(
        &self,
        ctx: &RequestContext,
        input: types::ListEnforcedGuardrailsConfigurationRequest,
    ) -> Result<types::ListEnforcedGuardrailsConfigurationResponse, ServiceError> {
        ctx.authorize("bedrock:ListEnforcedGuardrailsConfiguration", "*", ConditionContext::new())?;
        let items: Vec<types::AccountEnforcedGuardrailOutputConfiguration> = self.scope(ctx, |s| {
            let mut v: Vec<&Record> = s.kind(kind::ENFORCED_GUARDRAIL).collect();
            sort_records(&mut v, None, Some("Ascending"));
            v.into_iter().map(|r| from_doc(&r.doc)).collect()
        });
        let (guardrails_config, next_token) = page(items, None, input.next_token.as_deref())?;
        Ok(types::ListEnforcedGuardrailsConfigurationResponse { guardrails_config, next_token })
    }

    pub fn delete_enforced_guardrail_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEnforcedGuardrailConfigurationRequest,
    ) -> Result<types::DeleteEnforcedGuardrailConfigurationResponse, ServiceError> {
        ctx.authorize("bedrock:DeleteEnforcedGuardrailConfiguration", "*", ConditionContext::new())?;
        self.scope(ctx, |s| s.remove(kind::ENFORCED_GUARDRAIL, &input.config_id)).ok_or_else(|| {
            not_found(format!("The enforced guardrail configuration {} was not found.", input.config_id))
        })?;
        Ok(types::DeleteEnforcedGuardrailConfigurationResponse {})
    }

    // Marketplace endpoints ---------------------------------------------------

    pub fn create_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::CreateMarketplaceModelEndpointRequest,
    ) -> Result<types::CreateMarketplaceModelEndpointResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        let endpoint_arn = format!(
            "arn:{}:sagemaker:{}:{}:endpoint/{}",
            ctx.partition,
            ctx.region,
            ctx.caller.account_id,
            input.endpoint_name.to_ascii_lowercase()
        );
        ctx.authorize("bedrock:CreateMarketplaceModelEndpoint", "*", request_tag_context(&tags))?;
        if !input.accept_eula {
            return Err(validation("You must accept the model's end user license agreement (acceptEula)."));
        }
        let now = ctx.received_at;
        self.scope(ctx, |s| {
            if s.get(kind::MARKETPLACE_ENDPOINT, &endpoint_arn).is_some() {
                return Err(conflict(format!("An endpoint named {} already exists.", input.endpoint_name)));
            }
            let mut doc = Map::new();
            set(&mut doc, "endpoint_arn", endpoint_arn.clone());
            set(&mut doc, "model_source_identifier", input.model_source_identifier.clone());
            set(&mut doc, "endpoint_config", Value::Object(to_doc(&input.endpoint_config)));
            set(&mut doc, "endpoint_status", "InService");
            s.insert(
                kind::MARKETPLACE_ENDPOINT,
                Record {
                    id: endpoint_arn.clone(),
                    arn: endpoint_arn.clone(),
                    name: input.endpoint_name.clone(),
                    created: now,
                    updated: now,
                    status: "REGISTERED".into(),
                    transition: None,
                    steps: Vec::new(),
                    doc,
                },
            );
            if !tags.is_empty() {
                s.tags.insert(endpoint_arn.clone(), tag_map(&tags));
            }
            Ok(())
        })?;
        Ok(types::CreateMarketplaceModelEndpointResponse {
            marketplace_model_endpoint: self.endpoint(ctx, &endpoint_arn)?,
        })
    }

    fn endpoint(
        &self,
        ctx: &RequestContext,
        endpoint_arn: &str,
    ) -> Result<types::MarketplaceModelEndpoint, ServiceError> {
        self.scope(ctx, |s| s.get(kind::MARKETPLACE_ENDPOINT, endpoint_arn).map(endpoint_view))
            .ok_or_else(|| not_found(format!("The endpoint {endpoint_arn} was not found.")))
    }

    pub fn get_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::GetMarketplaceModelEndpointRequest,
    ) -> Result<types::GetMarketplaceModelEndpointResponse, ServiceError> {
        ctx.authorize("bedrock:GetMarketplaceModelEndpoint", &input.endpoint_arn, ConditionContext::new())?;
        Ok(types::GetMarketplaceModelEndpointResponse {
            marketplace_model_endpoint: Some(self.endpoint(ctx, &input.endpoint_arn)?),
        })
    }

    pub fn list_marketplace_model_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::ListMarketplaceModelEndpointsRequest,
    ) -> Result<types::ListMarketplaceModelEndpointsResponse, ServiceError> {
        ctx.authorize("bedrock:ListMarketplaceModelEndpoints", "*", ConditionContext::new())?;
        let items: Vec<types::MarketplaceModelEndpointSummary> = self.scope(ctx, |s| {
            let mut v: Vec<&Record> = s
                .kind(kind::MARKETPLACE_ENDPOINT)
                .filter(|r| {
                    input
                        .model_source_equals
                        .as_ref()
                        .is_none_or(|m| r.str("model_source_identifier") == Some(m.as_str()))
                })
                .collect();
            sort_records(&mut v, None, Some("Ascending"));
            v.into_iter().map(|r| from_doc(&to_doc(&endpoint_view(r)))).collect()
        });
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListMarketplaceModelEndpointsResponse { marketplace_model_endpoints: Some(items), next_token })
    }

    pub fn update_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMarketplaceModelEndpointRequest,
    ) -> Result<types::UpdateMarketplaceModelEndpointResponse, ServiceError> {
        ctx.authorize("bedrock:UpdateMarketplaceModelEndpoint", &input.endpoint_arn, ConditionContext::new())?;
        let now = ctx.received_at;
        self.scope(ctx, |s| {
            let r = s
                .get_mut(kind::MARKETPLACE_ENDPOINT, &input.endpoint_arn)
                .ok_or_else(|| not_found(format!("The endpoint {} was not found.", input.endpoint_arn)))?;
            set(&mut r.doc, "endpoint_config", Value::Object(to_doc(&input.endpoint_config)));
            r.updated = now;
            Ok::<_, ServiceError>(())
        })?;
        Ok(types::UpdateMarketplaceModelEndpointResponse {
            marketplace_model_endpoint: self.endpoint(ctx, &input.endpoint_arn)?,
        })
    }

    pub fn delete_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMarketplaceModelEndpointRequest,
    ) -> Result<types::DeleteMarketplaceModelEndpointResponse, ServiceError> {
        ctx.authorize("bedrock:DeleteMarketplaceModelEndpoint", &input.endpoint_arn, ConditionContext::new())?;
        self.scope(ctx, |s| s.remove(kind::MARKETPLACE_ENDPOINT, &input.endpoint_arn))
            .ok_or_else(|| not_found(format!("The endpoint {} was not found.", input.endpoint_arn)))?;
        Ok(types::DeleteMarketplaceModelEndpointResponse {})
    }

    pub fn register_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::RegisterMarketplaceModelEndpointRequest,
    ) -> Result<types::RegisterMarketplaceModelEndpointResponse, ServiceError> {
        ctx.authorize("bedrock:RegisterMarketplaceModelEndpoint", &input.endpoint_identifier, ConditionContext::new())?;
        let now = ctx.received_at;
        let ident = input.endpoint_identifier.clone();
        self.scope(ctx, |s| {
            if let Some(r) = s.get_mut(kind::MARKETPLACE_ENDPOINT, &ident) {
                r.status = "REGISTERED".into();
                set(&mut r.doc, "model_source_identifier", input.model_source_identifier.clone());
                r.updated = now;
            } else {
                // A SageMaker endpoint made outside Bedrock.
                let mut doc = Map::new();
                set(&mut doc, "endpoint_arn", ident.clone());
                set(&mut doc, "model_source_identifier", input.model_source_identifier.clone());
                set(&mut doc, "endpoint_status", "InService");
                s.insert(
                    kind::MARKETPLACE_ENDPOINT,
                    Record {
                        id: ident.clone(),
                        arn: ident.clone(),
                        name: last_segment(&ident).to_string(),
                        created: now,
                        updated: now,
                        status: "REGISTERED".into(),
                        transition: None,
                        steps: Vec::new(),
                        doc,
                    },
                );
            }
        });
        Ok(types::RegisterMarketplaceModelEndpointResponse { marketplace_model_endpoint: self.endpoint(ctx, &ident)? })
    }

    pub fn deregister_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterMarketplaceModelEndpointRequest,
    ) -> Result<types::DeregisterMarketplaceModelEndpointResponse, ServiceError> {
        ctx.authorize("bedrock:DeregisterMarketplaceModelEndpoint", &input.endpoint_arn, ConditionContext::new())?;
        self.scope(ctx, |s| s.remove(kind::MARKETPLACE_ENDPOINT, &input.endpoint_arn))
            .ok_or_else(|| not_found(format!("The endpoint {} was not found.", input.endpoint_arn)))?;
        Ok(types::DeregisterMarketplaceModelEndpointResponse {})
    }

    // Resource policies -------------------------------------------------------

    pub fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyRequest,
    ) -> Result<types::PutResourcePolicyResponse, ServiceError> {
        ctx.authorize("bedrock:PutResourcePolicy", &input.resource_arn, ConditionContext::new())?;
        if serde_json::from_str::<Value>(&input.resource_policy).map(|v| !v.is_object()).unwrap_or(true) {
            return Err(validation("The resource policy is not valid JSON."));
        }
        self.scope(ctx, |s| {
            if !exists(s, &input.resource_arn) {
                return Err(not_found(format!("The resource {} was not found.", input.resource_arn)));
            }
            s.resource_policies.insert(input.resource_arn.clone(), input.resource_policy.clone());
            Ok(())
        })?;
        Ok(types::PutResourcePolicyResponse { resource_arn: Some(input.resource_arn) })
    }

    pub fn get_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePolicyRequest,
    ) -> Result<types::GetResourcePolicyResponse, ServiceError> {
        ctx.authorize("bedrock:GetResourcePolicy", &input.resource_arn, ConditionContext::new())?;
        let p = self
            .scope(ctx, |s| s.resource_policies.get(&input.resource_arn).cloned())
            .ok_or_else(|| not_found(format!("No resource policy exists for {}.", input.resource_arn)))?;
        Ok(types::GetResourcePolicyResponse { resource_policy: Some(p) })
    }

    pub fn delete_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourcePolicyRequest,
    ) -> Result<types::DeleteResourcePolicyResponse, ServiceError> {
        ctx.authorize("bedrock:DeleteResourcePolicy", &input.resource_arn, ConditionContext::new())?;
        self.scope(ctx, |s| s.resource_policies.remove(&input.resource_arn))
            .ok_or_else(|| not_found(format!("No resource policy exists for {}.", input.resource_arn)))?;
        Ok(types::DeleteResourcePolicyResponse {})
    }

    // Tags ----------------------------------------------------------------------

    pub fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        let tags = self.taggable(ctx, &input.resource_arn)?;
        let mut cond = request_tag_context(&input.tags);
        cond.extend(resource_tag_context(Some(&tags)));
        ctx.authorize("bedrock:TagResource", &input.resource_arn, cond)?;
        let mut merged = tags;
        merged.extend(tag_map(&input.tags));
        if merged.len() > MAX_TAGS {
            return Err(too_many_tags(&input.resource_arn));
        }
        self.scope(ctx, |s| s.tags.insert(input.resource_arn.clone(), merged));
        Ok(types::TagResourceResponse {})
    }

    pub fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let tags = self.taggable(ctx, &input.resource_arn)?;
        let mut cond = resource_tag_context(Some(&tags));
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        ctx.authorize("bedrock:UntagResource", &input.resource_arn, cond)?;
        self.scope(ctx, |s| {
            if let Some(t) = s.tags.get_mut(&input.resource_arn) {
                for k in &input.tag_keys {
                    t.remove(k);
                }
            }
        });
        Ok(types::UntagResourceResponse {})
    }

    pub fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let tags = self.taggable(ctx, &input.resource_arn)?;
        ctx.authorize("bedrock:ListTagsForResource", &input.resource_arn, resource_tag_context(Some(&tags)))?;
        Ok(types::ListTagsForResourceResponse { tags: Some(tag_list(&tags)) })
    }

    /// The tags of an existing taggable resource.
    fn taggable(
        &self,
        ctx: &RequestContext,
        resource_arn: &str,
    ) -> Result<std::collections::BTreeMap<String, String>, ServiceError> {
        self.scope(ctx, |s| {
            if !exists(s, resource_arn) {
                return Err(not_found(format!("The resource {resource_arn} was not found.")));
            }
            Ok(s.tags.get(resource_arn).cloned().unwrap_or_default())
        })
    }
}

fn endpoint_view(r: &Record) -> types::MarketplaceModelEndpoint {
    let mut doc = r.doc.clone();
    set(&mut doc, "status", r.status.clone());
    set(&mut doc, "created_at", ts(r.created));
    set(&mut doc, "updated_at", ts(r.updated));
    from_doc(&doc)
}

fn provisioned_doc(r: &Record) -> Map<String, Value> {
    let mut doc = r.doc.clone();
    set(&mut doc, "provisioned_model_name", r.name.clone());
    set(&mut doc, "provisioned_model_arn", r.arn.clone());
    set(&mut doc, "status", r.status.clone());
    set(&mut doc, "creation_time", ts(r.created));
    set(&mut doc, "last_modified_time", ts(r.updated));
    doc
}

/// The model a Provisioned Throughput serves: (model ARN, foundation
/// model ARN). Foundation models by id or ARN, or custom models.
fn provisioned_model(s: &Scope, ctx: &RequestContext, ident: &str) -> Result<(String, String), ServiceError> {
    let id = ident.rsplit("foundation-model/").next().unwrap_or(ident);
    if let Some(m) = catalog::model(id) {
        let a = m.arn(&ctx.partition, &ctx.region);
        return Ok((a.clone(), a));
    }
    if let Some(c) = s.find(kind::CUSTOM_MODEL, ident) {
        if c.status != "Active" {
            return Err(validation(format!("The custom model {ident} is not active.")));
        }
        let base = c.str("base_model_arn").unwrap_or_default().to_string();
        let fm = foundation_from_arn(&base).map(|m| m.arn(&ctx.partition, &ctx.region)).unwrap_or(base);
        return Ok((c.arn.clone(), fm));
    }
    Err(validation(format!("The model identifier {ident} is invalid.")))
}
