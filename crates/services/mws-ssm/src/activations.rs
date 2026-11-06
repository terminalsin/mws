//! Hybrid activations: created, listed and deleted. No agent registers
//! with them in MWS, so their registration count stays 0.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::generated::{errors, types};
use crate::names::{now, page, request_tag_conditions};
use crate::Ssm;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivationRecord {
    pub activation: types::Activation,
    pub tags: BTreeMap<String, String>,
}

fn arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ssm:{}:{}:activation/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

impl Ssm {
    pub(crate) fn create_activation(
        &self,
        ctx: &RequestContext,
        input: types::CreateActivationRequest,
    ) -> Result<types::CreateActivationResult, ServiceError> {
        let tags: Vec<(String, String)> =
            input.tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect();
        ctx.authorize(
            "ssm:CreateActivation",
            &arn(ctx, "*"),
            request_tag_conditions(tags.iter().map(|(k, v)| (k, v))),
        )?;
        let at = now(ctx);
        let expiration = input.expiration_date.unwrap_or(at + chrono::Duration::hours(24));
        if expiration <= at || expiration > at + chrono::Duration::days(30) {
            return Err(errors::invalid_parameters(
                "The expiration date must be in the future and no more than 30 days from now.",
            ));
        }
        let limit = input.registration_limit.unwrap_or(1);
        let id = uuid::Uuid::new_v4().to_string();
        let mut raw = [0u8; 15];
        aws_lc_rs::rand::fill(&mut raw).map_err(|_| errors::internal_server_error("random generation failed"))?;
        let code = base64::engine::general_purpose::STANDARD.encode(raw);
        let activation = types::Activation {
            activation_id: Some(id.clone()),
            description: input.description,
            default_instance_name: input.default_instance_name,
            iam_role: Some(input.iam_role),
            registration_limit: Some(limit),
            registrations_count: Some(0),
            expiration_date: Some(expiration),
            expired: false,
            created_date: Some(at),
            tags: Some(tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()),
        };
        self.lock()
            .region(&ctx.caller.account_id, &ctx.region)
            .activations
            .insert(id.clone(), ActivationRecord { activation, tags: tags.into_iter().collect() });
        Ok(types::CreateActivationResult { activation_id: Some(id), activation_code: Some(code) })
    }

    pub(crate) fn describe_activations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeActivationsRequest,
    ) -> Result<types::DescribeActivationsResult, ServiceError> {
        ctx.authorize("ssm:DescribeActivations", &arn(ctx, "*"), ConditionContext::new())?;
        let mut filters = Vec::new();
        for f in input.filters.unwrap_or_default() {
            let key = f.filter_key.unwrap_or_default();
            if !matches!(key.as_str(), "ActivationIds" | "DefaultInstanceName" | "IamRole") {
                return Err(errors::invalid_filter("The filter key isn't valid."));
            }
            filters.push((key, f.filter_values.unwrap_or_default()));
        }
        let at = now(ctx);
        let items: Vec<types::Activation> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.activations.values().map(|a| a.activation.clone()).collect())
                .unwrap_or_default()
        };
        let items: Vec<_> = items
            .into_iter()
            .filter(|a| {
                filters.iter().all(|(k, v)| {
                    let value = match k.as_str() {
                        "ActivationIds" => a.activation_id.clone(),
                        "DefaultInstanceName" => a.default_instance_name.clone(),
                        _ => a.iam_role.clone(),
                    };
                    v.iter().any(|x| value.as_deref() == Some(x.as_str()))
                })
            })
            .map(|mut a| {
                a.expired = a.expiration_date.is_some_and(|e| e <= at);
                a
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeActivationsResult { activation_list: Some(items), next_token: next })
    }

    pub(crate) fn delete_activation(
        &self,
        ctx: &RequestContext,
        input: types::DeleteActivationRequest,
    ) -> Result<types::DeleteActivationResult, ServiceError> {
        ctx.authorize("ssm:DeleteActivation", &arn(ctx, &input.activation_id), ConditionContext::new())?;
        let removed = self.lock().region(&ctx.caller.account_id, &ctx.region).activations.remove(&input.activation_id);
        removed.map(|_| types::DeleteActivationResult::default()).ok_or_else(|| errors::invalid_activation_id(""))
    }

    pub(crate) fn deregister_managed_instance(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterManagedInstanceRequest,
    ) -> Result<types::DeregisterManagedInstanceResult, ServiceError> {
        let target = format!(
            "arn:{}:ssm:{}:{}:managed-instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.instance_id
        );
        ctx.authorize("ssm:DeregisterManagedInstance", &target, ConditionContext::new())?;
        // Only hybrid nodes (mi-...) can be deregistered, and none register
        // in MWS.
        Err(errors::invalid_instance_id(""))
    }
}
