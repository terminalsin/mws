//! Foundation model operations: the catalog, availability, Marketplace
//! agreements, the model access use case and account data retention; and
//! the default prompt routers AWS provides.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::json;

use crate::catalog::{self, ModelSpec};
use crate::generated::types;
use crate::util::{arn, from_doc, not_found, to_doc};
use crate::Bedrock;

fn summary(ctx: &RequestContext, m: &ModelSpec) -> types::FoundationModelSummary {
    types::FoundationModelSummary {
        model_arn: m.arn(&ctx.partition, &ctx.region),
        model_id: m.model_id.clone(),
        model_name: Some(m.model_name.clone()),
        provider_name: Some(m.provider_name.clone()),
        input_modalities: Some(m.input_modalities.clone()),
        output_modalities: Some(m.output_modalities.clone()),
        response_streaming_supported: Some(m.response_streaming_supported),
        customizations_supported: Some(m.customizations_supported.clone()),
        inference_types_supported: Some(m.inference_types_supported.clone()),
        model_lifecycle: Some(types::FoundationModelLifecycle { status: m.lifecycle.clone(), ..Default::default() }),
    }
}

/// The model a `modelIdentifier` (id or ARN) names, or the AWS error.
fn lookup(ident: &str) -> Result<&'static ModelSpec, ServiceError> {
    let id = ident.rsplit("foundation-model/").next().unwrap_or(ident);
    catalog::model(id).ok_or_else(|| not_found(format!("The model {ident} does not exist.")))
}

/// The foundation model format an imported model speaks.
pub fn imported_spec(architecture: &str) -> &'static ModelSpec {
    let a = architecture.to_ascii_lowercase();
    let id = if a.contains("mistral") || a.contains("mixtral") {
        "mistral.mistral-7b-instruct-v0:2"
    } else {
        "meta.llama3-1-8b-instruct-v1:0"
    };
    catalog::model(id).expect("built-in model")
}

/// The prompt routers AWS provides in every account: id -> (name, models,
/// fallback, quality difference).
const DEFAULT_ROUTERS: &[(&str, &str, &[&str], &str)] = &[
    (
        "anthropic.claude:1",
        "Anthropic Prompt Router",
        &["anthropic.claude-3-haiku-20240307-v1:0", "anthropic.claude-3-5-sonnet-20240620-v1:0"],
        "anthropic.claude-3-5-sonnet-20240620-v1:0",
    ),
    (
        "meta.llama:1",
        "Meta Prompt Router",
        &["meta.llama3-1-8b-instruct-v1:0", "meta.llama3-1-70b-instruct-v1:0"],
        "meta.llama3-1-70b-instruct-v1:0",
    ),
    (
        "amazon.nova:1",
        "Nova Prompt Router",
        &["amazon.nova-lite-v1:0", "amazon.nova-pro-v1:0"],
        "amazon.nova-lite-v1:0",
    ),
];

pub fn default_routers(ctx: &RequestContext) -> Vec<types::GetPromptRouterResponse> {
    DEFAULT_ROUTERS
        .iter()
        .map(|(id, name, models, fallback)| {
            let target =
                |m: &str| types::PromptRouterTargetModel { model_arn: arn(ctx, &format!("inference-profile/us.{m}")) };
            types::GetPromptRouterResponse {
                prompt_router_name: name.to_string(),
                routing_criteria: types::RoutingCriteria { response_quality_difference: 0.0 },
                description: Some(format!(
                    "Routes requests among models in the {} family",
                    name.trim_end_matches(" Prompt Router")
                )),
                created_at: None,
                updated_at: None,
                prompt_router_arn: arn(ctx, &format!("default-prompt-router/{id}")),
                models: models.iter().map(|m| target(m)).collect(),
                fallback_model: target(fallback),
                status: "AVAILABLE".into(),
                r#type: "default".into(),
            }
        })
        .collect()
}

pub fn default_router(ctx: &RequestContext, id: &str) -> Option<types::GetPromptRouterResponse> {
    default_routers(ctx).into_iter().find(|r| r.prompt_router_arn.ends_with(&format!("/{id}")))
}

impl Bedrock {
    pub fn list_foundation_models(
        &self,
        ctx: &RequestContext,
        input: types::ListFoundationModelsRequest,
    ) -> Result<types::ListFoundationModelsResponse, ServiceError> {
        ctx.authorize("bedrock:ListFoundationModels", "*", ConditionContext::new())?;
        let eq = |want: &Option<String>, have: &str| want.as_ref().is_none_or(|w| w.eq_ignore_ascii_case(have));
        let any = |want: &Option<String>, have: &[String]| want.as_ref().is_none_or(|w| have.iter().any(|h| h == w));
        let summaries = catalog::all()
            .into_iter()
            .filter(|m| eq(&input.by_provider, &m.provider_name) || eq(&input.by_provider, provider_slug(&m.model_id)))
            .filter(|m| any(&input.by_customization_type, &m.customizations_supported))
            .filter(|m| any(&input.by_output_modality, &m.output_modalities))
            .filter(|m| any(&input.by_inference_type, &m.inference_types_supported))
            .map(|m| summary(ctx, m))
            .collect();
        Ok(types::ListFoundationModelsResponse { model_summaries: Some(summaries) })
    }

    pub fn get_foundation_model(
        &self,
        ctx: &RequestContext,
        input: types::GetFoundationModelRequest,
    ) -> Result<types::GetFoundationModelResponse, ServiceError> {
        let m = lookup(&input.model_identifier)?;
        ctx.authorize("bedrock:GetFoundationModel", &m.arn(&ctx.partition, &ctx.region), ConditionContext::new())?;
        let s = summary(ctx, m);
        Ok(types::GetFoundationModelResponse { model_details: Some(from_doc(&to_doc(&s))) })
    }

    pub fn get_foundation_model_availability(
        &self,
        ctx: &RequestContext,
        input: types::GetFoundationModelAvailabilityRequest,
    ) -> Result<types::GetFoundationModelAvailabilityResponse, ServiceError> {
        let m = lookup(&input.model_id)?;
        ctx.authorize(
            "bedrock:GetFoundationModelAvailability",
            &m.arn(&ctx.partition, &ctx.region),
            ConditionContext::new(),
        )?;
        // Amazon models need no agreement; others report one once it exists
        // (MWS lets every model be invoked either way).
        let agreed = m.provider_name == "Amazon" || self.scope(ctx, |s| s.agreements.contains(&m.model_id));
        let status = if agreed { "AVAILABLE" } else { "NOT_AVAILABLE" };
        Ok(types::GetFoundationModelAvailabilityResponse {
            model_id: m.model_id.clone(),
            agreement_availability: types::AgreementAvailability { status: status.into(), error_message: None },
            authorization_status: "AUTHORIZED".into(),
            entitlement_availability: "AVAILABLE".into(),
            region_availability: "AVAILABLE".into(),
        })
    }

    pub fn list_foundation_model_agreement_offers(
        &self,
        ctx: &RequestContext,
        input: types::ListFoundationModelAgreementOffersRequest,
    ) -> Result<types::ListFoundationModelAgreementOffersResponse, ServiceError> {
        let m = lookup(&input.model_id)?;
        ctx.authorize("bedrock:ListFoundationModelAgreementOffers", "*", ConditionContext::new())?;
        let offer = json!({
            "offer_id": format!("offer-{}", crate::util::random_id(12)),
            "offer_token": format!("mws-offer-{}", m.model_id),
            "term_details": {
                "usage_based_pricing_term": { "rate_card": [
                    { "dimension": "InputTokens", "price": "0.00", "unit": "1K tokens", "description": "Input tokens" },
                    { "dimension": "OutputTokens", "price": "0.00", "unit": "1K tokens", "description": "Output tokens" }
                ]},
                "legal_term": { "url": "https://aws.amazon.com/legal/bedrock/third-party-models/" },
                "support_term": { "refund_policy_description": "No refunds." },
            },
        });
        let offer: types::Offer = serde_json::from_value(offer).expect("offer fits the model");
        Ok(types::ListFoundationModelAgreementOffersResponse { model_id: m.model_id.clone(), offers: vec![offer] })
    }

    pub fn create_foundation_model_agreement(
        &self,
        ctx: &RequestContext,
        input: types::CreateFoundationModelAgreementRequest,
    ) -> Result<types::CreateFoundationModelAgreementResponse, ServiceError> {
        let m = lookup(&input.model_id)?;
        ctx.authorize("bedrock:CreateFoundationModelAgreement", "*", ConditionContext::new())?;
        if input.offer_token != format!("mws-offer-{}", m.model_id) {
            return Err(crate::util::validation("The provided offer token is invalid."));
        }
        self.scope(ctx, |s| s.agreements.insert(m.model_id.clone()));
        Ok(types::CreateFoundationModelAgreementResponse { model_id: m.model_id.clone() })
    }

    pub fn delete_foundation_model_agreement(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFoundationModelAgreementRequest,
    ) -> Result<types::DeleteFoundationModelAgreementResponse, ServiceError> {
        let m = lookup(&input.model_id)?;
        ctx.authorize("bedrock:DeleteFoundationModelAgreement", "*", ConditionContext::new())?;
        if !self.scope(ctx, |s| s.agreements.remove(&m.model_id)) {
            return Err(not_found(format!("No agreement exists for model {}.", m.model_id)));
        }
        Ok(types::DeleteFoundationModelAgreementResponse {})
    }

    pub fn get_use_case_for_model_access(
        &self,
        ctx: &RequestContext,
        _input: types::GetUseCaseForModelAccessRequest,
    ) -> Result<types::GetUseCaseForModelAccessResponse, ServiceError> {
        ctx.authorize("bedrock:GetUseCaseForModelAccess", "*", ConditionContext::new())?;
        let form =
            self.scope(ctx, |s| s.use_case.clone()).ok_or_else(|| not_found("No use case has been submitted."))?;
        use base64::Engine;
        let form_data = base64::engine::general_purpose::STANDARD.decode(form).unwrap_or_default();
        Ok(types::GetUseCaseForModelAccessResponse { form_data })
    }

    pub fn put_use_case_for_model_access(
        &self,
        ctx: &RequestContext,
        input: types::PutUseCaseForModelAccessRequest,
    ) -> Result<types::PutUseCaseForModelAccessResponse, ServiceError> {
        ctx.authorize("bedrock:PutUseCaseForModelAccess", "*", ConditionContext::new())?;
        use base64::Engine;
        let form = base64::engine::general_purpose::STANDARD.encode(&input.form_data);
        self.scope(ctx, |s| s.use_case = Some(form));
        Ok(types::PutUseCaseForModelAccessResponse {})
    }

    pub fn get_account_data_retention(
        &self,
        ctx: &RequestContext,
        _input: types::GetAccountDataRetentionRequest,
    ) -> Result<types::GetAccountDataRetentionResponse, ServiceError> {
        ctx.authorize("bedrock:GetAccountDataRetention", "*", ConditionContext::new())?;
        Ok(match self.scope(ctx, |s| s.data_retention.clone()) {
            Some((mode, at)) => types::GetAccountDataRetentionResponse { mode, updated_at: Some(at) },
            None => types::GetAccountDataRetentionResponse { mode: default_retention().into(), updated_at: None },
        })
    }

    pub fn put_account_data_retention(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountDataRetentionRequest,
    ) -> Result<types::PutAccountDataRetentionResponse, ServiceError> {
        ctx.authorize("bedrock:PutAccountDataRetention", "*", ConditionContext::new())?;
        let now = ctx.received_at;
        self.scope(ctx, |s| s.data_retention = Some((input.mode.clone(), now)));
        Ok(types::PutAccountDataRetentionResponse { mode: input.mode, updated_at: Some(now) })
    }
}

fn default_retention() -> &'static str {
    types::DATA_RETENTION_MODE.first().copied().unwrap_or("DEFAULT")
}

/// The provider part of a model id (`anthropic` in `anthropic.claude-...`).
fn provider_slug(model_id: &str) -> &str {
    model_id.split('.').next().unwrap_or("")
}
