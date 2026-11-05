//! Resolving the model identifier of an invocation: a foundation model, a
//! cross-Region or application inference profile, Provisioned Throughput,
//! a custom model deployment, an imported model, a prompt router or a
//! Marketplace endpoint, down to the foundation model that answers.

use mws_core::{RequestContext, ServiceError};

use crate::catalog::{self, ModelSpec};
use crate::state::{kind, Scope};
use crate::util::validation;
use crate::Bedrock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    FoundationModel,
    SystemProfile,
    ApplicationProfile,
    Provisioned,
    CustomModelDeployment,
    ImportedModel,
    PromptRouter,
    MarketplaceEndpoint,
}

/// What an invocation's model identifier names.
#[derive(Debug, Clone)]
pub struct InvocationTarget {
    pub kind: TargetKind,
    /// The foundation model whose request format and behaviour apply.
    pub model: &'static ModelSpec,
    /// The canonical ARN of what the caller named.
    pub arn: String,
    /// The resources the caller needs `bedrock:InvokeModel*` on: the
    /// profile or router and every model it can route to.
    pub resources: Vec<String>,
    /// For prompt routers, the model the request was routed to.
    pub routed_to: Option<String>,
}

pub fn invalid_model() -> ServiceError {
    validation("The provided model identifier is invalid.")
}

struct Arn<'a> {
    region: &'a str,
    account: &'a str,
    resource: &'a str,
}

fn parse_arn(s: &str) -> Option<Arn<'_>> {
    let mut parts = s.splitn(6, ':');
    let (Some("arn"), Some(_partition), Some(service), Some(region), Some(account), Some(resource)) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    // Marketplace model endpoints are SageMaker endpoints.
    let ok = service == "bedrock" || (service == "sagemaker" && resource.starts_with("endpoint/"));
    ok.then_some(Arn { region, account, resource })
}

/// The foundation model of a `foundation-model/<id>` ARN.
pub fn foundation_from_arn(arn: &str) -> Option<&'static ModelSpec> {
    let a = parse_arn(arn)?;
    catalog::model(a.resource.strip_prefix("foundation-model/")?)
}

impl Bedrock {
    /// Resolve `ident` (as `InvokeModel`, `Converse` and their streaming
    /// forms take it) for the caller's account and Region.
    pub fn resolve_invocation(&self, ctx: &RequestContext, ident: &str) -> Result<InvocationTarget, ServiceError> {
        let partition = ctx.partition.clone();
        let region = ctx.region.clone();
        if let Some(a) = parse_arn(ident) {
            if a.region != region || (!a.account.is_empty() && a.account != ctx.caller.account_id) {
                return Err(invalid_model());
            }
        }
        let resource = parse_arn(ident).map(|a| a.resource).unwrap_or(ident);
        let (rtype, rest) = resource.split_once('/').unwrap_or(("", resource));
        let fm_arn = |m: &ModelSpec| m.arn(&partition, &region);
        let profile_arn = |id: &str| crate::util::arn(ctx, &format!("inference-profile/{id}"));
        match rtype {
            "" | "foundation-model" => {
                if let Some(spec) = catalog::model(rest) {
                    if !spec.on_demand() {
                        return Err(validation(format!(
                            "Invocation of model ID {} with on-demand throughput isn\u{2019}t supported. Retry your request with the ID or ARN of an inference profile that contains this model.",
                            spec.model_id
                        )));
                    }
                    return Ok(InvocationTarget {
                        kind: TargetKind::FoundationModel,
                        model: spec,
                        arn: fm_arn(spec),
                        resources: vec![fm_arn(spec)],
                        routed_to: None,
                    });
                }
                if rtype.is_empty() {
                    if let Some(p) = catalog::system_profile(&partition, &region, rest) {
                        let arn = profile_arn(&p.id);
                        let mut resources = vec![arn.clone()];
                        resources.extend(p.model_arns.iter().cloned());
                        return Ok(InvocationTarget {
                            kind: TargetKind::SystemProfile,
                            model: p.model,
                            arn,
                            resources,
                            routed_to: None,
                        });
                    }
                }
                Err(invalid_model())
            }
            "inference-profile" => {
                let p = catalog::system_profile(&partition, &region, rest).ok_or_else(invalid_model)?;
                let arn = profile_arn(&p.id);
                let mut resources = vec![arn.clone()];
                resources.extend(p.model_arns.iter().cloned());
                Ok(InvocationTarget {
                    kind: TargetKind::SystemProfile,
                    model: p.model,
                    arn,
                    resources,
                    routed_to: None,
                })
            }
            _ => self.scope(ctx, |s| resolve_owned(s, ctx, rtype, rest)),
        }
    }
}

fn resolve_owned(s: &Scope, ctx: &RequestContext, rtype: &str, id: &str) -> Result<InvocationTarget, ServiceError> {
    match rtype {
        "application-inference-profile" => {
            let r = s.get(kind::PROFILE, id).ok_or_else(invalid_model)?;
            let models: Vec<String> = r
                .doc
                .get("models")
                .and_then(|m| m.as_array())
                .into_iter()
                .flatten()
                .filter_map(|m| m.get("model_arn").and_then(|a| a.as_str()).map(str::to_string))
                .collect();
            let spec = models.iter().find_map(|a| foundation_from_arn(a)).ok_or_else(invalid_model)?;
            let mut resources = vec![r.arn.clone()];
            resources.extend(models);
            Ok(InvocationTarget {
                kind: TargetKind::ApplicationProfile,
                model: spec,
                arn: r.arn.clone(),
                resources,
                routed_to: None,
            })
        }
        "provisioned-model" => {
            let r = s.get(kind::PROVISIONED, id).ok_or_else(invalid_model)?;
            if r.status != "InService" {
                return Err(ServiceError::client(
                    "ModelNotReadyException",
                    429,
                    "The provisioned throughput is not ready yet. Try again later.",
                ));
            }
            let spec = r.str("foundation_model_arn").and_then(foundation_from_arn).ok_or_else(invalid_model)?;
            Ok(InvocationTarget {
                kind: TargetKind::Provisioned,
                model: spec,
                arn: r.arn.clone(),
                resources: vec![r.arn.clone()],
                routed_to: None,
            })
        }
        "custom-model-deployment" => {
            let r = s.get(kind::DEPLOYMENT, id).ok_or_else(invalid_model)?;
            if r.status != "Active" {
                return Err(ServiceError::client(
                    "ModelNotReadyException",
                    429,
                    "The custom model deployment is not active yet. Try again later.",
                ));
            }
            let spec = r
                .str("model_arn")
                .and_then(|m| s.find(kind::CUSTOM_MODEL, m))
                .and_then(|m| m.str("base_model_arn"))
                .and_then(foundation_from_arn)
                .ok_or_else(invalid_model)?;
            Ok(InvocationTarget {
                kind: TargetKind::CustomModelDeployment,
                model: spec,
                arn: r.arn.clone(),
                resources: vec![r.arn.clone()],
                routed_to: None,
            })
        }
        "custom-model" => Err(validation(
            "Invocation of a custom model with on-demand throughput isn\u{2019}t supported. Deploy the model with a custom model deployment or Provisioned Throughput and invoke that instead.",
        )),
        "imported-model" => {
            let r = s.get(kind::IMPORTED_MODEL, id).ok_or_else(invalid_model)?;
            let spec = crate::models::imported_spec(r.str("model_architecture").unwrap_or("llama"));
            Ok(InvocationTarget {
                kind: TargetKind::ImportedModel,
                model: spec,
                arn: r.arn.clone(),
                resources: vec![r.arn.clone()],
                routed_to: None,
            })
        }
        "prompt-router" | "default-prompt-router" => {
            let router = if rtype == "default-prompt-router" {
                crate::models::default_router(ctx, id).ok_or_else(invalid_model)?
            } else {
                let r = s.get(kind::PROMPT_ROUTER, id).ok_or_else(invalid_model)?;
                crate::util::from_doc(&r.doc)
            };
            let fallback = router.fallback_model.model_arn.clone();
            let spec = model_of_target(ctx, &fallback).ok_or_else(invalid_model)?;
            let mut resources = vec![router.prompt_router_arn.clone()];
            for m in &router.models {
                let a = &m.model_arn;
                resources.push(a.clone());
                if let Some(p) = a.split("inference-profile/").nth(1) {
                    if let Some(sp) = catalog::system_profile(&ctx.partition, &ctx.region, p) {
                        resources.extend(sp.model_arns);
                    }
                }
            }
            resources.dedup();
            Ok(InvocationTarget {
                kind: TargetKind::PromptRouter,
                model: spec,
                arn: router.prompt_router_arn.clone(),
                resources,
                routed_to: Some(fallback),
            })
        }
        "endpoint" => {
            let arn = format!("arn:{}:sagemaker:{}:{}:endpoint/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
            let r = s.get(kind::MARKETPLACE_ENDPOINT, &arn).ok_or_else(invalid_model)?;
            if r.status != "REGISTERED" {
                return Err(validation(format!(
                    "The endpoint {arn} is not registered with Amazon Bedrock. Register it and try again."
                )));
            }
            // Answer in the request format of the model family the
            // Marketplace model's identifier names; OpenAI-style chat
            // otherwise.
            let source = r.str("model_source_identifier").unwrap_or_default().to_ascii_lowercase();
            let spec = if ["llama", "mistral", "mixtral"].iter().any(|f| source.contains(f)) {
                crate::models::imported_spec(&source)
            } else {
                catalog::model("openai.gpt-oss-20b-1:0").expect("built-in model")
            };
            Ok(InvocationTarget {
                kind: TargetKind::MarketplaceEndpoint,
                model: spec,
                arn: arn.clone(),
                resources: vec![arn],
                routed_to: None,
            })
        }
        _ => Err(invalid_model()),
    }
}

/// The foundation model behind a router target: a foundation model or
/// inference profile ARN.
fn model_of_target(ctx: &RequestContext, arn: &str) -> Option<&'static ModelSpec> {
    if let Some(m) = foundation_from_arn(arn) {
        return Some(m);
    }
    let id = arn.split("inference-profile/").nth(1)?;
    catalog::system_profile(&ctx.partition, &ctx.region, id).map(|p| p.model)
}
