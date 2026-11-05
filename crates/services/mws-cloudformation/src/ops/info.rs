//! Template inspection, account limits and the public type registry.

use mws_core::{RequestContext, ServiceError};
use serde_json::{json, Value};

use super::{find, page, required_capabilities, validation};
use crate::generated::{errors, types};
use crate::template::Template;
use crate::CloudFormation;

fn param_type(decl: &serde_json::Map<String, Value>) -> String {
    decl.get("Type").and_then(Value::as_str).unwrap_or("String").to_string()
}

fn no_echo(decl: &serde_json::Map<String, Value>) -> bool {
    match decl.get("NoEcho") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn type_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:cloudformation:{}::type/resource/{}", ctx.partition, ctx.region, name.replace("::", "-"))
}

impl CloudFormation {
    pub(crate) async fn validate_template_op(
        &self,
        ctx: &RequestContext,
        input: types::ValidateTemplateInput,
    ) -> Result<types::ValidateTemplateOutput, ServiceError> {
        ctx.authorize("cloudformation:ValidateTemplate", "*", Default::default())?;
        let body = self.template_text(ctx, input.template_body.as_deref(), input.template_url.as_deref()).await?;
        let t = Template::parse(&body).map_err(validation)?;
        self.check_template(ctx, &t)?;
        let (caps, iam) = required_capabilities(&t);
        let params = t
            .parameters()
            .into_iter()
            .map(|(k, d)| types::TemplateParameter {
                parameter_key: Some(k),
                default_value: d.get("Default").map(scalar),
                no_echo: Some(no_echo(&d)),
                description: d.get("Description").and_then(Value::as_str).map(str::to_string),
            })
            .collect();
        Ok(types::ValidateTemplateOutput {
            parameters: Some(params),
            description: t.description(),
            capabilities_reason: (!caps.is_empty())
                .then(|| format!("The following resource(s) require capabilities: [{}]", iam.join(", "))),
            capabilities: Some(caps),
            declared_transforms: Some(t.transforms()),
        })
    }

    pub(crate) async fn get_template_summary_op(
        &self,
        ctx: &RequestContext,
        input: types::GetTemplateSummaryInput,
    ) -> Result<types::GetTemplateSummaryOutput, ServiceError> {
        let body = match (&input.stack_name, &input.template_body, &input.template_url, &input.stack_set_name) {
            (Some(name), None, None, None) => {
                let st = self.state();
                let s = find(&st, ctx, name)?;
                ctx.authorize("cloudformation:GetTemplateSummary", &s.id, Default::default())?;
                s.template_body.clone()
            }
            (None, b, u, None) if b.is_some() || u.is_some() => {
                ctx.authorize("cloudformation:GetTemplateSummary", "*", Default::default())?;
                self.template_text(ctx, b.as_deref(), u.as_deref()).await?
            }
            (None, None, None, Some(_)) => return Err(validation("MWS does not support stack sets yet.")),
            _ => {
                return Err(validation("Specify exactly one of TemplateBody, TemplateUrl, StackName or StackSetName."))
            }
        };
        let t = Template::parse(&body).map_err(validation)?;
        self.check_template(ctx, &t)?;
        let (caps, iam) = required_capabilities(&t);
        let params = t
            .parameters()
            .into_iter()
            .map(|(k, d)| types::ParameterDeclaration {
                parameter_key: Some(k),
                default_value: d.get("Default").map(scalar),
                parameter_type: Some(param_type(&d)),
                no_echo: Some(no_echo(&d)),
                description: d.get("Description").and_then(Value::as_str).map(str::to_string),
                parameter_constraints: Some(types::ParameterConstraints {
                    allowed_values: d
                        .get("AllowedValues")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().map(scalar).collect()),
                }),
            })
            .collect();
        let mut resource_types: Vec<String> =
            t.resources().values().filter_map(|r| r.get("Type").and_then(Value::as_str)).map(str::to_string).collect();
        resource_types.sort();
        resource_types.dedup();
        let mut by_type: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for (name, r) in t.resources() {
            if let Some(ty) = r.get("Type").and_then(Value::as_str) {
                by_type.entry(ty.to_string()).or_default().push(name.clone());
            }
        }
        let summaries = by_type
            .into_iter()
            .map(|(ty, ids)| types::ResourceIdentifierSummary {
                resource_type: Some(ty),
                logical_resource_ids: Some(ids),
                resource_identifiers: None,
            })
            .collect();
        Ok(types::GetTemplateSummaryOutput {
            parameters: Some(params),
            description: t.description(),
            capabilities_reason: (!caps.is_empty())
                .then(|| format!("The following resource(s) require capabilities: [{}]", iam.join(", "))),
            capabilities: Some(caps),
            resource_types: Some(resource_types),
            version: Some("2010-09-09".into()),
            metadata: t.root.get("Metadata").map(|m| m.to_string()),
            declared_transforms: Some(t.transforms()),
            resource_identifier_summaries: Some(summaries),
            warnings: None,
        })
    }

    pub(crate) async fn estimate_template_cost_op(
        &self,
        ctx: &RequestContext,
        input: types::EstimateTemplateCostInput,
    ) -> Result<types::EstimateTemplateCostOutput, ServiceError> {
        ctx.authorize("cloudformation:EstimateTemplateCost", "*", Default::default())?;
        let body = self.template_text(ctx, input.template_body.as_deref(), input.template_url.as_deref()).await?;
        let t = Template::parse(&body).map_err(validation)?;
        self.check_template(ctx, &t)?;
        Ok(types::EstimateTemplateCostOutput {
            url: Some(format!("https://calculator.aws/#/estimate?id={}", uuid::Uuid::new_v4().simple())),
        })
    }

    pub(crate) fn describe_account_limits_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountLimitsInput,
    ) -> Result<types::DescribeAccountLimitsOutput, ServiceError> {
        ctx.authorize("cloudformation:DescribeAccountLimits", "*", Default::default())?;
        let limits = vec![
            types::AccountLimit { name: Some("StackLimit".into()), value: Some(2000) },
            types::AccountLimit { name: Some("StackOutputsLimit".into()), value: Some(200) },
            types::AccountLimit { name: Some("ConcurrentResourcesLimit".into()), value: Some(2500) },
        ];
        let (items, next) = page(&limits, input.next_token.as_deref(), 100)?;
        Ok(types::DescribeAccountLimitsOutput { account_limits: Some(items), next_token: next })
    }

    pub(crate) fn list_types_op(
        &self,
        ctx: &RequestContext,
        input: types::ListTypesInput,
    ) -> Result<types::ListTypesOutput, ServiceError> {
        ctx.authorize("cloudformation:ListTypes", "*", Default::default())?;
        let visibility = input.visibility.clone().unwrap_or_else(|| "PRIVATE".into());
        let kind = input.r#type.clone().unwrap_or_else(|| "RESOURCE".into());
        let prefix = input.filters.as_ref().and_then(|f| f.type_name_prefix.clone()).unwrap_or_default();
        let category = input.filters.as_ref().and_then(|f| f.category.clone());
        let publisher = input.filters.as_ref().and_then(|f| f.publisher_id.clone());
        let deprecated = input.deprecated_status.clone().unwrap_or_else(|| "LIVE".into());
        let mut all: Vec<types::TypeSummary> = if visibility == "PUBLIC"
            && kind == "RESOURCE"
            && matches!(category.as_deref(), None | Some("AWS_TYPES"))
            && publisher.as_deref().is_none_or(|p| p == "aws-cloudformation")
        {
            self.resource_types()
                .into_iter()
                .filter(|t| super::is_registry_type(t) && t.starts_with(&prefix))
                .map(|t| types::TypeSummary {
                    r#type: Some("RESOURCE".into()),
                    type_name: Some(t.to_string()),
                    default_version_id: Some("00000001".into()),
                    type_arn: Some(type_arn(ctx, t)),
                    description: Some(format!("{t} resources, created through the MWS service that owns them")),
                    publisher_id: Some("aws-cloudformation".into()),
                    publisher_name: Some("AWS".into()),
                    is_activated: Some(true),
                    ..Default::default()
                })
                .collect()
        } else {
            Vec::new()
        };
        if visibility == "PUBLIC"
            && !matches!(category.as_deref(), Some("AWS_TYPES") | Some("ACTIVATED") | Some("REGISTERED"))
        {
            all.extend(self.public_type_summaries(ctx, &kind, publisher.as_deref()));
        }
        if visibility == "PRIVATE" {
            all.extend(
                self.private_type_summaries(ctx, &kind, category.as_deref(), &deprecated)
                    .into_iter()
                    .filter(|t| t.type_name.as_deref().is_some_and(|n| n.starts_with(&prefix)))
                    .filter(|t| publisher.as_ref().is_none_or(|p| t.publisher_id.as_ref() == Some(p))),
            );
        }
        if let Some(p) = &input.provisioning_type {
            // Every built-in type is fully mutable.
            if p != "FULLY_MUTABLE" {
                all.retain(|t| t.publisher_id.as_deref() != Some("aws-cloudformation"));
            }
        }
        let size = input.max_results.map(|m| m.max(1) as usize).unwrap_or(100);
        let (items, next) = page(&all, input.next_token.as_deref(), size)?;
        Ok(types::ListTypesOutput { type_summaries: Some(items), next_token: next })
    }

    pub(crate) fn describe_type_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTypeInput,
    ) -> Result<types::DescribeTypeOutput, ServiceError> {
        ctx.authorize("cloudformation:DescribeType", "*", Default::default())?;
        if let Some(found) = self.describe_registry_type(ctx, &input) {
            return found;
        }
        let name = match (&input.type_name, &input.arn) {
            (Some(n), _) => n.clone(),
            (None, Some(arn)) => arn.rsplit('/').next().unwrap_or_default().replace('-', "::"),
            (None, None) => return Err(validation("Either TypeName and Type, or Arn, must be specified")),
        };
        if input.r#type.as_deref().is_some_and(|t| t != "RESOURCE") {
            return Err(errors::type_not_found(format!("The type '{name}' cannot be found.")));
        }
        let provider = self
            .resource_types()
            .contains(&name.as_str())
            .then(|| self.provider(&name))
            .flatten()
            .ok_or_else(|| errors::type_not_found(format!("The type '{name}' cannot be found.")))?;
        let read_only: Vec<String> = provider.attributes().iter().map(|a| format!("/properties/{a}")).collect();
        let create_only: Vec<String> = provider.create_only().iter().map(|a| format!("/properties/{a}")).collect();
        let schema = json!({
            "typeName": name,
            "description": format!("{name} resources, created through the MWS service that owns them"),
            "additionalProperties": true,
            "required": provider.required(),
            "readOnlyProperties": read_only,
            "createOnlyProperties": create_only,
            "handlers": {
                "create": {"permissions": []},
                "read": {"permissions": []},
                "update": {"permissions": []},
                "delete": {"permissions": []}
            }
        });
        Ok(types::DescribeTypeOutput {
            arn: Some(type_arn(ctx, &name)),
            r#type: Some("RESOURCE".into()),
            type_name: Some(name),
            default_version_id: Some("00000001".into()),
            is_default_version: Some(true),
            description: schema["description"].as_str().map(str::to_string),
            schema: Some(schema.to_string()),
            provisioning_type: Some("FULLY_MUTABLE".into()),
            deprecated_status: Some("LIVE".into()),
            visibility: Some("PUBLIC".into()),
            publisher_id: Some("aws-cloudformation".into()),
            is_activated: Some(true),
            ..Default::default()
        })
    }
}
