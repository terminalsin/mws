//! Vended log deliveries: delivery sources, delivery destinations (with
//! their policies), deliveries between them and configuration templates.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind, PrincipalInfo, Request};

use crate::generated::{errors, types};
use crate::names::{arn, check_tags, page, random_alnum, request_tag_conditions};
use crate::Logs;

fn not_found(what: &str) -> ServiceError {
    errors::resource_not_found(format!("{what} does not exist"))
}

/// The destination type of a destination resource ARN.
fn destination_type(resource: &str) -> Result<&'static str, ServiceError> {
    match resource.split(':').nth(2) {
        Some("s3") => Ok("S3"),
        Some("logs") => Ok("CWL"),
        Some("firehose") => Ok("FH"),
        _ => Err(errors::validation(format!("Unsupported delivery destination resource: {resource}"))),
    }
}

/// Fields every vended log type offers, for templates and defaults.
const RECORD_FIELDS: &[&str] = &["timestamp", "event_type", "resource_arn", "request_id", "status", "message"];

impl Logs {
    // ---- delivery sources ------------------------------------------------------

    pub(crate) fn put_delivery_source(
        &self,
        ctx: &RequestContext,
        input: types::PutDeliverySourceRequest,
    ) -> Result<types::PutDeliverySourceResponse, ServiceError> {
        let a = arn(ctx, &format!("delivery-source:{}", input.name));
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize(ctx, "PutDeliverySource", &a, request_tag_conditions(&tags))?;
        check_tags(0, &tags)?;
        let service = input
            .resource_arn
            .split(':')
            .nth(2)
            .filter(|s| input.resource_arn.starts_with("arn:") && !s.is_empty())
            .ok_or_else(|| errors::validation(format!("Invalid resourceArn: {}", input.resource_arn)))?
            .to_string();
        ctx.authorize(
            &format!("{service}:AllowVendedLogDeliveryForResource"),
            &input.resource_arn,
            ConditionContext::new(),
        )?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(existing) = region.delivery_sources.get(&input.name) {
            if existing.log_type.as_deref() != Some(&input.log_type) {
                return Err(errors::conflict("The logType of an existing delivery source cannot be changed."));
            }
        }
        let source = types::DeliverySource {
            name: Some(input.name.clone()),
            arn: Some(a),
            resource_arns: Some(vec![input.resource_arn]),
            service: Some(service),
            log_type: Some(input.log_type),
            tags: Some(tags),
            delivery_source_configuration: input.delivery_source_configuration,
            status: Some("ACTIVE".into()),
            status_reason: None,
        };
        region.delivery_sources.insert(input.name, source.clone());
        Ok(types::PutDeliverySourceResponse { delivery_source: Some(source) })
    }

    pub(crate) fn get_delivery_source(
        &self,
        ctx: &RequestContext,
        input: types::GetDeliverySourceRequest,
    ) -> Result<types::GetDeliverySourceResponse, ServiceError> {
        self.authorize(
            ctx,
            "GetDeliverySource",
            &arn(ctx, &format!("delivery-source:{}", input.name)),
            ConditionContext::new(),
        )?;
        let st = self.lock();
        let s = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.delivery_sources.get(&input.name))
            .cloned()
            .ok_or_else(|| not_found("Delivery source"))?;
        Ok(types::GetDeliverySourceResponse { delivery_source: Some(s) })
    }

    pub(crate) fn describe_delivery_sources(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDeliverySourcesRequest,
    ) -> Result<types::DescribeDeliverySourcesResponse, ServiceError> {
        self.authorize(ctx, "DescribeDeliverySources", &arn(ctx, "delivery-source:*"), ConditionContext::new())?;
        let st = self.lock();
        let out: Vec<_> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.delivery_sources
                    .values()
                    .filter(|s| {
                        input
                            .resource_arns
                            .as_ref()
                            .is_none_or(|want| s.resource_arns.iter().flatten().any(|a| want.contains(a)))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeDeliverySourcesResponse { delivery_sources: Some(out), next_token })
    }

    pub(crate) fn delete_delivery_source(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDeliverySourceRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "DeleteDeliverySource",
            &arn(ctx, &format!("delivery-source:{}", input.name)),
            ConditionContext::new(),
        )?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if !region.delivery_sources.contains_key(&input.name) {
            return Err(not_found("Delivery source"));
        }
        if region.deliveries.values().any(|d| d.delivery_source_name.as_ref() == Some(&input.name)) {
            return Err(errors::conflict("The delivery source is in use by a delivery. Delete the delivery first."));
        }
        region.delivery_sources.remove(&input.name);
        Ok(())
    }

    // ---- delivery destinations -------------------------------------------------

    pub(crate) fn put_delivery_destination(
        &self,
        ctx: &RequestContext,
        input: types::PutDeliveryDestinationRequest,
    ) -> Result<types::PutDeliveryDestinationResponse, ServiceError> {
        let a = arn(ctx, &format!("delivery-destination:{}", input.name));
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize(ctx, "PutDeliveryDestination", &a, request_tag_conditions(&tags))?;
        check_tags(0, &tags)?;
        let ty = match (&input.delivery_destination_configuration, input.delivery_destination_type.as_deref()) {
            (Some(c), t) => {
                let inferred = destination_type(&c.destination_resource_arn)?;
                if t.is_some_and(|t| t != inferred) {
                    return Err(errors::validation("deliveryDestinationType does not match the destination resource."));
                }
                inferred.to_string()
            }
            (None, Some("XRAY")) => "XRAY".to_string(),
            (None, _) => {
                return Err(errors::validation(
                    "deliveryDestinationConfiguration is required for this destination type.",
                ))
            }
        };
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let mut all_tags =
            region.delivery_destinations.get(&input.name).and_then(|d| d.tags.clone()).unwrap_or_default();
        all_tags.extend(tags);
        let dest = types::DeliveryDestination {
            name: Some(input.name.clone()),
            arn: Some(a),
            delivery_destination_type: Some(ty),
            output_format: Some(input.output_format.unwrap_or_else(|| "json".into())),
            delivery_destination_configuration: input.delivery_destination_configuration,
            role_arn: input.role_arn,
            tags: Some(all_tags),
        };
        region.delivery_destinations.insert(input.name, dest.clone());
        Ok(types::PutDeliveryDestinationResponse { delivery_destination: Some(dest) })
    }

    pub(crate) fn get_delivery_destination(
        &self,
        ctx: &RequestContext,
        input: types::GetDeliveryDestinationRequest,
    ) -> Result<types::GetDeliveryDestinationResponse, ServiceError> {
        self.authorize(
            ctx,
            "GetDeliveryDestination",
            &arn(ctx, &format!("delivery-destination:{}", input.name)),
            ConditionContext::new(),
        )?;
        let st = self.lock();
        let d = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.delivery_destinations.get(&input.name))
            .cloned()
            .ok_or_else(|| not_found("Delivery destination"))?;
        Ok(types::GetDeliveryDestinationResponse { delivery_destination: Some(d) })
    }

    pub(crate) fn describe_delivery_destinations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDeliveryDestinationsRequest,
    ) -> Result<types::DescribeDeliveryDestinationsResponse, ServiceError> {
        self.authorize(
            ctx,
            "DescribeDeliveryDestinations",
            &arn(ctx, "delivery-destination:*"),
            ConditionContext::new(),
        )?;
        let st = self.lock();
        let out: Vec<_> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.delivery_destinations
                    .values()
                    .filter(|d| input.names.as_ref().is_none_or(|n| d.name.as_ref().is_some_and(|x| n.contains(x))))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeDeliveryDestinationsResponse { delivery_destinations: Some(out), next_token })
    }

    pub(crate) fn delete_delivery_destination(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDeliveryDestinationRequest,
    ) -> Result<(), ServiceError> {
        let a = arn(ctx, &format!("delivery-destination:{}", input.name));
        self.authorize(ctx, "DeleteDeliveryDestination", &a, ConditionContext::new())?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if !region.delivery_destinations.contains_key(&input.name) {
            return Err(not_found("Delivery destination"));
        }
        if region.deliveries.values().any(|d| d.delivery_destination_arn.as_ref() == Some(&a)) {
            return Err(errors::conflict(
                "The delivery destination is in use by a delivery. Delete the delivery first.",
            ));
        }
        region.delivery_destinations.remove(&input.name);
        region.delivery_destination_policies.remove(&input.name);
        Ok(())
    }

    pub(crate) fn put_delivery_destination_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutDeliveryDestinationPolicyRequest,
    ) -> Result<types::PutDeliveryDestinationPolicyResponse, ServiceError> {
        let a = arn(ctx, &format!("delivery-destination:{}", input.delivery_destination_name));
        self.authorize(ctx, "PutDeliveryDestinationPolicy", &a, ConditionContext::new())?;
        Policy::parse(&input.delivery_destination_policy, PolicyKind::Resource)
            .map_err(|e| errors::validation(format!("Invalid policy: {}", e.0)))?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if !region.delivery_destinations.contains_key(&input.delivery_destination_name) {
            return Err(not_found("Delivery destination"));
        }
        region
            .delivery_destination_policies
            .insert(input.delivery_destination_name, input.delivery_destination_policy.clone());
        Ok(types::PutDeliveryDestinationPolicyResponse {
            policy: Some(types::Policy { delivery_destination_policy: Some(input.delivery_destination_policy) }),
        })
    }

    pub(crate) fn get_delivery_destination_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetDeliveryDestinationPolicyRequest,
    ) -> Result<types::GetDeliveryDestinationPolicyResponse, ServiceError> {
        let a = arn(ctx, &format!("delivery-destination:{}", input.delivery_destination_name));
        self.authorize(ctx, "GetDeliveryDestinationPolicy", &a, ConditionContext::new())?;
        let st = self.lock();
        let region = st.region_ref(&ctx.caller.account_id, &ctx.region);
        if !region.is_some_and(|r| r.delivery_destinations.contains_key(&input.delivery_destination_name)) {
            return Err(not_found("Delivery destination"));
        }
        let p = region.and_then(|r| r.delivery_destination_policies.get(&input.delivery_destination_name)).cloned();
        Ok(types::GetDeliveryDestinationPolicyResponse {
            policy: Some(types::Policy { delivery_destination_policy: p }),
        })
    }

    pub(crate) fn delete_delivery_destination_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDeliveryDestinationPolicyRequest,
    ) -> Result<(), ServiceError> {
        let a = arn(ctx, &format!("delivery-destination:{}", input.delivery_destination_name));
        self.authorize(ctx, "DeleteDeliveryDestinationPolicy", &a, ConditionContext::new())?;
        let mut st = self.lock();
        st.region(&ctx.caller.account_id, &ctx.region)
            .delivery_destination_policies
            .remove(&input.delivery_destination_name)
            .ok_or_else(|| not_found("Delivery destination policy"))?;
        Ok(())
    }

    // ---- deliveries -------------------------------------------------------------

    pub(crate) fn create_delivery(
        &self,
        ctx: &RequestContext,
        input: types::CreateDeliveryRequest,
    ) -> Result<types::CreateDeliveryResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize(
            ctx,
            "CreateDelivery",
            &arn(ctx, &format!("delivery-source:{}", input.delivery_source_name)),
            request_tag_conditions(&tags),
        )?;
        self.authorize(ctx, "CreateDelivery", &input.delivery_destination_arn, ConditionContext::new())?;
        check_tags(0, &tags)?;
        let parts: Vec<&str> = input.delivery_destination_arn.splitn(6, ':').collect();
        let (dest_region, dest_account, dest_name) = match parts.as_slice() {
            ["arn", _, "logs", r, a, rest] => match rest.strip_prefix("delivery-destination:") {
                Some(n) => (r.to_string(), a.to_string(), n.to_string()),
                None => return Err(errors::validation("Invalid deliveryDestinationArn.")),
            },
            _ => return Err(errors::validation("Invalid deliveryDestinationArn.")),
        };
        let mut st = self.lock();
        let (dest, dest_policy) = {
            let r = st.region_ref(&dest_account, &dest_region).ok_or_else(|| not_found("Delivery destination"))?;
            let d =
                r.delivery_destinations.get(&dest_name).cloned().ok_or_else(|| not_found("Delivery destination"))?;
            (d, r.delivery_destination_policies.get(&dest_name).cloned())
        };
        if dest_account != ctx.caller.account_id {
            let allowed = dest_policy.and_then(|doc| Policy::parse(&doc, PolicyKind::Resource).ok()).is_some_and(|p| {
                let principal = PrincipalInfo {
                    account_id: ctx.caller.account_id.clone(),
                    arns: vec![ctx.caller.arn.clone()],
                    ..Default::default()
                };
                let context = mws_iam_policy::ConditionContext::new();
                let e = p.evaluate(&Request {
                    action: "logs:CreateDelivery",
                    resource: &input.delivery_destination_arn,
                    principal: &principal,
                    context: &context,
                });
                e.allowed() && !e.denied()
            });
            if !allowed {
                return Err(errors::access_denied(format!(
                    "The delivery destination policy of {} does not allow account {} to create deliveries.",
                    input.delivery_destination_arn, ctx.caller.account_id
                )));
            }
        }
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if !region.delivery_sources.contains_key(&input.delivery_source_name) {
            return Err(not_found("Delivery source"));
        }
        if region.deliveries.values().any(|d| {
            d.delivery_source_name.as_ref() == Some(&input.delivery_source_name)
                && d.delivery_destination_arn.as_ref() == Some(&input.delivery_destination_arn)
        }) {
            return Err(errors::conflict("A delivery between this source and destination already exists."));
        }
        let id = random_alnum(16);
        let is_s3 = dest.delivery_destination_type.as_deref() == Some("S3");
        let delivery = types::Delivery {
            id: Some(id.clone()),
            arn: Some(format!("arn:{}:logs:{}:{}:delivery:{id}", ctx.partition, ctx.region, ctx.caller.account_id)),
            delivery_source_name: Some(input.delivery_source_name),
            delivery_destination_arn: Some(input.delivery_destination_arn),
            delivery_destination_type: dest.delivery_destination_type,
            record_fields: Some(
                input.record_fields.unwrap_or_else(|| RECORD_FIELDS.iter().map(|s| s.to_string()).collect()),
            ),
            field_delimiter: input.field_delimiter,
            s3_delivery_configuration: input.s3_delivery_configuration.or_else(|| {
                is_s3.then(|| types::S3DeliveryConfiguration {
                    suffix_path: Some("AWSLogs/{account-id}/{region}".into()),
                    enable_hive_compatible_path: Some(false),
                })
            }),
            tags: Some(tags),
        };
        region.deliveries.insert(id, delivery.clone());
        Ok(types::CreateDeliveryResponse { delivery: Some(delivery) })
    }

    fn delivery_arn(ctx: &RequestContext, id: &str) -> String {
        arn(ctx, &format!("delivery:{id}"))
    }

    pub(crate) fn get_delivery(
        &self,
        ctx: &RequestContext,
        input: types::GetDeliveryRequest,
    ) -> Result<types::GetDeliveryResponse, ServiceError> {
        self.authorize(ctx, "GetDelivery", &Self::delivery_arn(ctx, &input.id), ConditionContext::new())?;
        let st = self.lock();
        let d = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.deliveries.get(&input.id))
            .cloned()
            .ok_or_else(|| not_found("Delivery"))?;
        Ok(types::GetDeliveryResponse { delivery: Some(d) })
    }

    pub(crate) fn describe_deliveries(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDeliveriesRequest,
    ) -> Result<types::DescribeDeliveriesResponse, ServiceError> {
        self.authorize(ctx, "DescribeDeliveries", &arn(ctx, "delivery:*"), ConditionContext::new())?;
        let st = self.lock();
        let out: Vec<_> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.deliveries
                    .values()
                    .filter(|d| {
                        input
                            .delivery_source_names
                            .as_ref()
                            .is_none_or(|n| d.delivery_source_name.as_ref().is_some_and(|s| n.contains(s)))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeDeliveriesResponse { deliveries: Some(out), next_token })
    }

    pub(crate) fn delete_delivery(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDeliveryRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteDelivery", &Self::delivery_arn(ctx, &input.id), ConditionContext::new())?;
        let mut st = self.lock();
        st.region(&ctx.caller.account_id, &ctx.region)
            .deliveries
            .remove(&input.id)
            .ok_or_else(|| not_found("Delivery"))?;
        Ok(())
    }

    pub(crate) fn update_delivery_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDeliveryConfigurationRequest,
    ) -> Result<types::UpdateDeliveryConfigurationResponse, ServiceError> {
        self.authorize(
            ctx,
            "UpdateDeliveryConfiguration",
            &Self::delivery_arn(ctx, &input.id),
            ConditionContext::new(),
        )?;
        let mut st = self.lock();
        let d = st
            .region(&ctx.caller.account_id, &ctx.region)
            .deliveries
            .get_mut(&input.id)
            .ok_or_else(|| not_found("Delivery"))?;
        if input.s3_delivery_configuration.is_some() && d.delivery_destination_type.as_deref() != Some("S3") {
            return Err(errors::validation("s3DeliveryConfiguration only applies to deliveries to S3."));
        }
        if let Some(f) = input.record_fields {
            d.record_fields = Some(f);
        }
        if let Some(f) = input.field_delimiter {
            d.field_delimiter = Some(f);
        }
        if let Some(c) = input.s3_delivery_configuration {
            d.s3_delivery_configuration = Some(c);
        }
        Ok(types::UpdateDeliveryConfigurationResponse {})
    }

    pub(crate) fn describe_configuration_templates(
        &self,
        ctx: &RequestContext,
        input: types::DescribeConfigurationTemplatesRequest,
    ) -> Result<types::DescribeConfigurationTemplatesResponse, ServiceError> {
        self.authorize(ctx, "DescribeConfigurationTemplates", "*", ConditionContext::new())?;
        let sources: &[(&str, &str, &str)] = &[
            ("cloudfront", "ACCESS_LOGS", "AWS::CloudFront::Distribution"),
            ("bedrock-agentcore", "APPLICATION_LOGS", "AWS::BedrockAgentCore::Runtime"),
            ("codewhisperer", "EVENT_LOGS", "AWS::CodeWhisperer::Profile"),
        ];
        let mut out = Vec::new();
        for (service, log_type, resource_type) in sources {
            for dest in ["S3", "CWL", "FH"] {
                if input.service.as_ref().is_some_and(|s| s != service)
                    || input.log_types.as_ref().is_some_and(|l| !l.iter().any(|x| x == log_type))
                    || input.resource_types.as_ref().is_some_and(|r| !r.iter().any(|x| x == resource_type))
                    || input.delivery_destination_types.as_ref().is_some_and(|d| !d.iter().any(|x| x == dest))
                {
                    continue;
                }
                let formats: Vec<String> = match dest {
                    "S3" => vec!["json", "plain", "w3c", "parquet"],
                    "CWL" => vec!["json", "plain"],
                    _ => vec!["json", "plain", "raw"],
                }
                .into_iter()
                .map(str::to_string)
                .collect();
                out.push(types::ConfigurationTemplate {
                    service: Some(service.to_string()),
                    log_type: Some(log_type.to_string()),
                    resource_type: Some(resource_type.to_string()),
                    delivery_destination_type: Some(dest.to_string()),
                    default_delivery_config_values: Some(types::ConfigurationTemplateDeliveryConfigValues {
                        record_fields: Some(RECORD_FIELDS.iter().map(|s| s.to_string()).collect()),
                        field_delimiter: Some(String::new()),
                        s3_delivery_configuration: (dest == "S3").then(|| types::S3DeliveryConfiguration {
                            suffix_path: Some("AWSLogs/{account-id}/{region}".into()),
                            enable_hive_compatible_path: Some(false),
                        }),
                    }),
                    allowed_fields: Some(
                        RECORD_FIELDS
                            .iter()
                            .map(|f| types::RecordField {
                                name: Some(f.to_string()),
                                mandatory: Some(*f == "timestamp"),
                            })
                            .collect(),
                    ),
                    allowed_output_formats: Some(formats),
                    allowed_action_for_allow_vended_logs_delivery_for_resource: Some(format!(
                        "{service}:AllowVendedLogDeliveryForResource"
                    )),
                    allowed_field_delimiters: Some(vec![",".into(), " ".into(), "\t".into(), "|".into()]),
                    allowed_suffix_path_fields: (dest == "S3").then(|| {
                        vec!["{account-id}".into(), "{region}".into(), "{yyyy}".into(), "{MM}".into(), "{dd}".into()]
                    }),
                    delivery_source_configuration: None,
                    s3_tables_integration: None,
                });
            }
        }
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeConfigurationTemplatesResponse { configuration_templates: Some(out), next_token })
    }
}
