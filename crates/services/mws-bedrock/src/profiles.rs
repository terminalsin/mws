//! Inference profiles: the system-defined cross-Region profiles from the
//! catalog, and application inference profiles that track usage (and
//! carry tags) for a foundation model or a cross-Region profile.

use chrono::{DateTime, TimeZone, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::json;

use crate::catalog::{self, SystemProfile};
use crate::generated::types;
use crate::resolve::foundation_from_arn;
use crate::state::{kind, Record};
use crate::util::{
    arn, conflict, from_doc, last_segment, not_found, page, random_id, request_tag_context, resource_tag_context,
    tag_map, too_many_tags, validation, MAX_TAGS,
};
use crate::Bedrock;

fn system_created() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 8, 27, 0, 0, 0).single().expect("valid date")
}

fn system_view(ctx: &RequestContext, p: &SystemProfile) -> types::GetInferenceProfileResponse {
    types::GetInferenceProfileResponse {
        inference_profile_name: p.name.clone(),
        description: Some(p.description.clone()),
        created_at: Some(system_created()),
        updated_at: Some(system_created()),
        inference_profile_arn: arn(ctx, &format!("inference-profile/{}", p.id)),
        models: p.model_arns.iter().map(|a| types::InferenceProfileModel { model_arn: Some(a.clone()) }).collect(),
        inference_profile_id: p.id.clone(),
        status: "ACTIVE".into(),
        r#type: "SYSTEM_DEFINED".into(),
    }
}

fn app_view(r: &Record) -> types::GetInferenceProfileResponse {
    let mut v: types::GetInferenceProfileResponse = from_doc(&r.doc);
    v.inference_profile_name = r.name.clone();
    v.inference_profile_arn = r.arn.clone();
    v.inference_profile_id = r.id.clone();
    v.created_at = Some(r.created);
    v.updated_at = Some(r.updated);
    v.status = r.status.clone();
    v.r#type = "APPLICATION".into();
    v
}

fn not_found_profile(ident: &str) -> ServiceError {
    not_found(format!("The inference profile {ident} does not exist."))
}

impl Bedrock {
    pub fn create_inference_profile(
        &self,
        ctx: &RequestContext,
        input: types::CreateInferenceProfileRequest,
    ) -> Result<types::CreateInferenceProfileResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        if tags.len() > MAX_TAGS {
            return Err(too_many_tags(&input.inference_profile_name));
        }
        let id = random_id(12);
        let profile_arn = arn(ctx, &format!("application-inference-profile/{id}"));
        ctx.authorize("bedrock:CreateInferenceProfile", &profile_arn, request_tag_context(&tags))?;
        let types::InferenceProfileModelSource::CopyFrom(source) = &input.model_source;
        let models: Vec<String> = if let Some(m) = foundation_from_arn(source) {
            if !source.contains(&format!(":{}::", ctx.region)) {
                return Err(validation(format!("The model source {source} is not in the Region {}.", ctx.region)));
            }
            vec![m.arn(&ctx.partition, &ctx.region)]
        } else if let Some(pid) = source.split(":inference-profile/").nth(1) {
            if *source != arn(ctx, &format!("inference-profile/{pid}")) {
                return Err(validation(format!("The model source {source} is not valid.")));
            }
            catalog::system_profile(&ctx.partition, &ctx.region, pid)
                .ok_or_else(|| validation(format!("The model source {source} is not valid.")))?
                .model_arns
        } else {
            return Err(validation(format!(
                "The model source {source} is not valid. Specify the ARN of a foundation model or a system-defined inference profile."
            )));
        };
        let now = ctx.received_at;
        let name = input.inference_profile_name.clone();
        self.scope(ctx, |s| {
            if s.kind(kind::PROFILE).any(|r| r.name == name) {
                return Err(conflict(format!("An inference profile with the name {name} already exists.")));
            }
            let mut doc = serde_json::Map::new();
            if let Some(d) = &input.description {
                doc.insert("description".into(), json!(d));
            }
            doc.insert("models".into(), json!(models.iter().map(|a| json!({"model_arn": a})).collect::<Vec<_>>()));
            s.insert(
                kind::PROFILE,
                Record {
                    id: id.clone(),
                    arn: profile_arn.clone(),
                    name: name.clone(),
                    created: now,
                    updated: now,
                    status: "ACTIVE".into(),
                    transition: None,
                    doc,
                },
            );
            if !tags.is_empty() {
                s.tags.insert(profile_arn.clone(), tag_map(&tags));
            }
            Ok(())
        })?;
        Ok(types::CreateInferenceProfileResponse { inference_profile_arn: profile_arn, status: Some("ACTIVE".into()) })
    }

    pub fn get_inference_profile(
        &self,
        ctx: &RequestContext,
        input: types::GetInferenceProfileRequest,
    ) -> Result<types::GetInferenceProfileResponse, ServiceError> {
        let ident = input.inference_profile_identifier.as_str();
        let id = last_segment(ident);
        if let Some(p) = catalog::system_profile(&ctx.partition, &ctx.region, id) {
            let v = system_view(ctx, &p);
            if ident.starts_with("arn:") && ident != v.inference_profile_arn {
                return Err(not_found_profile(ident));
            }
            ctx.authorize("bedrock:GetInferenceProfile", &v.inference_profile_arn, ConditionContext::new())?;
            return Ok(v);
        }
        let (view, tags) = self.scope(ctx, |s| {
            let r = s
                .find(kind::PROFILE, ident)
                .or_else(|| s.get(kind::PROFILE, id))
                .ok_or_else(|| not_found_profile(ident))?;
            Ok::<_, ServiceError>((app_view(r), s.tags.get(&r.arn).cloned()))
        })?;
        ctx.authorize("bedrock:GetInferenceProfile", &view.inference_profile_arn, resource_tag_context(tags.as_ref()))?;
        Ok(view)
    }

    pub fn list_inference_profiles(
        &self,
        ctx: &RequestContext,
        input: types::ListInferenceProfilesRequest,
    ) -> Result<types::ListInferenceProfilesResponse, ServiceError> {
        ctx.authorize("bedrock:ListInferenceProfiles", "*", ConditionContext::new())?;
        let views: Vec<types::GetInferenceProfileResponse> = match input.type_equals.as_deref() {
            Some("APPLICATION") => self.scope(ctx, |s| {
                let mut v: Vec<&Record> = s.kind(kind::PROFILE).collect();
                v.sort_by(|a, b| a.created.cmp(&b.created).then(a.id.cmp(&b.id)));
                v.into_iter().map(app_view).collect()
            }),
            _ => catalog::system_profiles(&ctx.partition, &ctx.region).iter().map(|p| system_view(ctx, p)).collect(),
        };
        let (items, next) = page(views, input.max_results, input.next_token.as_deref())?;
        let summaries = items.iter().map(|v| from_doc(&crate::util::to_doc(v))).collect();
        Ok(types::ListInferenceProfilesResponse { inference_profile_summaries: Some(summaries), next_token: next })
    }

    pub fn delete_inference_profile(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInferenceProfileRequest,
    ) -> Result<types::DeleteInferenceProfileResponse, ServiceError> {
        let ident = input.inference_profile_identifier.as_str();
        if catalog::system_profile(&ctx.partition, &ctx.region, last_segment(ident)).is_some() {
            return Err(validation("System-defined inference profiles can't be deleted."));
        }
        let (id, profile_arn, tags) = self.scope(ctx, |s| {
            let r = s.find(kind::PROFILE, ident).ok_or_else(|| not_found_profile(ident))?;
            Ok::<_, ServiceError>((r.id.clone(), r.arn.clone(), s.tags.get(&r.arn).cloned()))
        })?;
        ctx.authorize("bedrock:DeleteInferenceProfile", &profile_arn, resource_tag_context(tags.as_ref()))?;
        self.scope(ctx, |s| s.remove(kind::PROFILE, &id));
        Ok(types::DeleteInferenceProfileResponse {})
    }
}
