//! Standards, their controls, and security controls (the consolidated,
//! cross-standard view): enabling standards, control status, control
//! parameters and the standard-to-control associations.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::catalog::{self, Control, Param};
use crate::common::{self, account, authorize, authorize_hub, hub, hub_mut, invalid_input, not_found, paginate};
use crate::generated::types;
use crate::hub::enable_standard;
use crate::state::{ControlOverride, Hub};
use crate::SecurityHub;

fn override_key(standards_arn: &str, control_id: &str) -> String {
    format!("{standards_arn}|{control_id}")
}

/// The standard's subscription in a hub, by standards ARN.
fn subscription<'h>(h: &'h Hub, standards_arn: &str) -> Option<(&'h String, &'h crate::state::StandardsSub)> {
    h.standards.iter().find(|(_, s)| s.standards_arn == standards_arn)
}

/// `ENABLED` or `DISABLED` for a control in a standard of a hub.
pub fn association_status<'h>(
    h: &'h Hub,
    standards_arn: &str,
    control_id: &str,
) -> (String, Option<&'h ControlOverride>) {
    if subscription(h, standards_arn).is_none() {
        return ("DISABLED".into(), None);
    }
    match h.control_overrides.get(&override_key(standards_arn, control_id)) {
        Some(o) => (o.status.clone(), Some(o)),
        None => ("ENABLED".into(), None),
    }
}

fn security_control_status(h: &Hub, partition: &str, c: &Control) -> &'static str {
    let enabled = c.in_standards.iter().any(|(key, _, _)| {
        let Some(s) = catalog::standard(key) else { return false };
        association_status(h, &catalog::standards_arn(partition, &h.region, s), c.id).0 == "ENABLED"
    });
    if enabled {
        "ENABLED"
    } else {
        "DISABLED"
    }
}

fn default_value(p: &Param) -> Option<types::ParameterValue> {
    match p {
        Param::Integer { default, .. } => default.map(types::ParameterValue::Integer),
        Param::IntegerList { default, .. } => Some(types::ParameterValue::IntegerList(default.to_vec())),
        Param::StringList { default, .. } => {
            Some(types::ParameterValue::StringList(default.iter().map(|s| s.to_string()).collect()))
        }
        Param::Boolean { default, .. } => Some(types::ParameterValue::Boolean(*default)),
        Param::EnumList { default, .. } => {
            Some(types::ParameterValue::EnumList(default.iter().map(|s| s.to_string()).collect()))
        }
    }
}

/// The current parameters of a control: customized values, else defaults.
pub fn current_parameters(h: &Hub, c: &Control) -> BTreeMap<String, types::ParameterConfiguration> {
    let custom = h.security_controls.get(c.id);
    c.params
        .iter()
        .map(|p| {
            let conf = custom
                .and_then(|s| s.parameters.get(p.name()))
                .cloned()
                .unwrap_or(types::ParameterConfiguration { value_type: "DEFAULT".into(), value: default_value(p) });
            (p.name().to_string(), conf)
        })
        .collect()
}

fn definition(c: &Control) -> types::SecurityControlDefinition {
    let defs: BTreeMap<String, types::ParameterDefinition> = c
        .params
        .iter()
        .map(|p| {
            let (description, options) = match p {
                Param::Integer { description, min, max, default, .. } => (
                    description,
                    types::ConfigurationOptions::Integer(types::IntegerConfigurationOptions {
                        default_value: *default,
                        min: Some(*min),
                        max: Some(*max),
                    }),
                ),
                Param::IntegerList { description, min, max, default, .. } => (
                    description,
                    types::ConfigurationOptions::IntegerList(types::IntegerListConfigurationOptions {
                        default_value: Some(default.to_vec()),
                        min: Some(*min),
                        max: Some(*max),
                        max_items: Some(32),
                    }),
                ),
                Param::StringList { description, default, .. } => (
                    description,
                    types::ConfigurationOptions::StringList(types::StringListConfigurationOptions {
                        default_value: Some(default.iter().map(|s| s.to_string()).collect()),
                        re2_expression: None,
                        max_items: Some(6),
                        expression_description: None,
                    }),
                ),
                Param::Boolean { description, default, .. } => (
                    description,
                    types::ConfigurationOptions::Boolean(types::BooleanConfigurationOptions {
                        default_value: Some(*default),
                    }),
                ),
                Param::EnumList { description, allowed, default, .. } => (
                    description,
                    types::ConfigurationOptions::EnumList(types::EnumListConfigurationOptions {
                        default_value: Some(default.iter().map(|s| s.to_string()).collect()),
                        max_items: Some(allowed.len() as i32),
                        allowed_values: Some(allowed.iter().map(|s| s.to_string()).collect()),
                    }),
                ),
            };
            (
                p.name().to_string(),
                types::ParameterDefinition { description: description.to_string(), configuration_options: options },
            )
        })
        .collect();
    types::SecurityControlDefinition {
        security_control_id: c.id.into(),
        title: c.title.into(),
        description: catalog::description(c),
        remediation_url: catalog::remediation_url(c),
        severity_rating: c.severity.into(),
        current_region_availability: "AVAILABLE".into(),
        customizable_properties: (!c.params.is_empty()).then(|| vec!["Parameters".to_string()]),
        parameter_definitions: (!defs.is_empty()).then_some(defs),
        provider: None,
    }
}

/// Check customized parameters against a control's definitions.
pub fn validate_parameters(
    c: &Control,
    params: &BTreeMap<String, types::ParameterConfiguration>,
) -> Result<(), String> {
    for (name, conf) in params {
        let Some(p) = c.params.iter().find(|p| p.name() == name) else {
            return Err(format!("{name} is not a valid parameter for control {}.", c.id));
        };
        match conf.value_type.as_str() {
            "DEFAULT" => continue,
            "CUSTOM" => {}
            other => return Err(format!("Invalid ValueType {other}.")),
        }
        let Some(v) = &conf.value else {
            return Err(format!("A value is required for parameter {name} when ValueType is CUSTOM."));
        };
        let ok = match (p, v) {
            (Param::Integer { min, max, .. }, types::ParameterValue::Integer(x)) => (*min..=*max).contains(x),
            (Param::IntegerList { min, max, .. }, types::ParameterValue::IntegerList(xs)) => {
                xs.len() <= 32 && xs.iter().all(|x| (*min..=*max).contains(x))
            }
            (Param::StringList { .. }, types::ParameterValue::StringList(xs)) => xs.len() <= 6,
            (Param::Boolean { .. }, types::ParameterValue::Boolean(_)) => true,
            (Param::EnumList { allowed, .. }, types::ParameterValue::EnumList(xs)) => {
                xs.iter().all(|x| allowed.contains(&x.as_str()))
            }
            _ => false,
        };
        if !ok {
            return Err(format!("Invalid value for parameter {name} of control {}.", c.id));
        }
    }
    Ok(())
}

fn subscription_wire(arn: &str, s: &crate::state::StandardsSub, status: &str) -> types::StandardsSubscription {
    types::StandardsSubscription {
        standards_subscription_arn: arn.to_string(),
        standards_arn: s.standards_arn.clone(),
        standards_input: s.input.clone(),
        standards_status: status.to_string(),
        standards_controls_updatable: Some(
            if status == "READY" { "READY_FOR_UPDATES" } else { "NOT_READY_FOR_UPDATES" }.into(),
        ),
        standards_status_reason: None,
        provider: None,
    }
}

impl SecurityHub {
    pub(crate) fn describe_standards_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStandardsRequest,
    ) -> Result<types::DescribeStandardsResponse, ServiceError> {
        authorize_hub(ctx, "DescribeStandards")?;
        let all: Vec<types::Standard> = catalog::STANDARDS
            .iter()
            .map(|s| types::Standard {
                standards_arn: Some(catalog::standards_arn(&ctx.partition, &ctx.region, s)),
                name: Some(s.name.into()),
                description: Some(s.description.into()),
                enabled_by_default: Some(s.enabled_by_default),
                provider: None,
                standards_managed_by: Some(types::StandardsManagedBy {
                    company: Some("AWS".into()),
                    product: Some("Security Hub".into()),
                }),
            })
            .collect();
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::DescribeStandardsResponse { standards: Some(page), next_token })
    }

    pub(crate) fn batch_enable_standards_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchEnableStandardsRequest,
    ) -> Result<types::BatchEnableStandardsResponse, ServiceError> {
        authorize_hub(ctx, "BatchEnableStandards")?;
        if input.standards_subscription_requests.is_empty() || input.standards_subscription_requests.len() > 25 {
            return Err(invalid_input("StandardsSubscriptionRequests must contain between 1 and 25 items."));
        }
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let mut out = Vec::new();
        for r in input.standards_subscription_requests {
            let s = catalog::standard_from_arn(&r.standards_arn)
                .filter(|s| s.ruleset || common::arn_region(&r.standards_arn) == Some(ctx.region.as_str()))
                .ok_or_else(|| invalid_input(format!("Invalid StandardsArn: {}", r.standards_arn)))?;
            let existed = h.standards.values().any(|x| x.standards_arn == r.standards_arn);
            let arn = enable_standard(h, &ctx.partition, s, r.standards_input.unwrap_or_default(), ctx.received_at);
            let sub = &h.standards[&arn];
            out.push(subscription_wire(&arn, sub, if existed { "READY" } else { "PENDING" }));
        }
        h.evaluation.dirty = true;
        Ok(types::BatchEnableStandardsResponse { standards_subscriptions: Some(out) })
    }

    pub(crate) fn batch_disable_standards_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchDisableStandardsRequest,
    ) -> Result<types::BatchDisableStandardsResponse, ServiceError> {
        authorize_hub(ctx, "BatchDisableStandards")?;
        if input.standards_subscription_arns.is_empty() || input.standards_subscription_arns.len() > 25 {
            return Err(invalid_input("StandardsSubscriptionArns must contain between 1 and 25 items."));
        }
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        for arn in &input.standards_subscription_arns {
            if !h.standards.contains_key(arn) {
                return Err(invalid_input(format!("Invalid StandardsSubscriptionArn: {arn}")));
            }
        }
        let mut out = Vec::new();
        for arn in input.standards_subscription_arns {
            if let Some(sub) = h.standards.remove(&arn) {
                h.control_overrides.retain(|k, _| !k.starts_with(&format!("{}|", sub.standards_arn)));
                out.push(subscription_wire(&arn, &sub, "DELETING"));
            }
        }
        h.evaluation.dirty = true;
        Ok(types::BatchDisableStandardsResponse { standards_subscriptions: Some(out) })
    }

    pub(crate) fn get_enabled_standards_op(
        &self,
        ctx: &RequestContext,
        input: types::GetEnabledStandardsRequest,
    ) -> Result<types::GetEnabledStandardsResponse, ServiceError> {
        authorize_hub(ctx, "GetEnabledStandards")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let wanted = input.standards_subscription_arns.unwrap_or_default();
        let all: Vec<types::StandardsSubscription> = h
            .standards
            .iter()
            .filter(|(arn, _)| wanted.is_empty() || wanted.contains(arn))
            .map(|(arn, s)| subscription_wire(arn, s, "READY"))
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetEnabledStandardsResponse { standards_subscriptions: Some(page), next_token })
    }

    pub(crate) fn describe_standards_controls_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStandardsControlsRequest,
    ) -> Result<types::DescribeStandardsControlsResponse, ServiceError> {
        authorize(ctx, "DescribeStandardsControls", &input.standards_subscription_arn)?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let sub = h.standards.get(&input.standards_subscription_arn).ok_or_else(|| {
            not_found(format!("Standards subscription {} not found", input.standards_subscription_arn))
        })?;
        let s = catalog::standard_from_arn(&sub.standards_arn).expect("subscribed standards are in the catalogue");
        let controls: Vec<types::StandardsControl> = catalog::controls_in(s.key)
            .map(|(c, cid, reqs)| {
                let (status, o) = association_status(h, &sub.standards_arn, c.id);
                types::StandardsControl {
                    standards_control_arn: Some(common::arn(ctx, &format!("control/{}/{cid}", s.key))),
                    control_status: Some(status),
                    disabled_reason: o.and_then(|o| o.reason.clone()),
                    control_status_updated_at: Some(o.map(|o| o.updated_at).unwrap_or(sub.enabled_at)),
                    control_id: Some(cid.into()),
                    title: Some(c.title.into()),
                    description: Some(catalog::description(c)),
                    remediation_url: Some(catalog::remediation_url(c)),
                    severity_rating: Some(c.severity.into()),
                    related_requirements: Some(reqs.iter().map(|r| r.to_string()).collect()),
                }
            })
            .collect();
        drop(state);
        let (page, next_token) = paginate(controls, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::DescribeStandardsControlsResponse { controls: Some(page), next_token })
    }

    pub(crate) fn update_standards_control_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStandardsControlRequest,
    ) -> Result<types::UpdateStandardsControlResponse, ServiceError> {
        authorize(ctx, "UpdateStandardsControl", &input.standards_control_arn)?;
        let resource = input.standards_control_arn.splitn(6, ':').nth(5).unwrap_or_default().to_string();
        let path = resource.strip_prefix("control/").ok_or_else(|| invalid_input("Invalid StandardsControlArn"))?;
        let (key, cid) = path.rsplit_once('/').ok_or_else(|| invalid_input("Invalid StandardsControlArn"))?;
        let s = catalog::standard(key)
            .ok_or_else(|| not_found(format!("Control {} not found", input.standards_control_arn)))?;
        let (c, _, _) = catalog::controls_in(s.key)
            .find(|(_, x, _)| *x == cid)
            .ok_or_else(|| not_found(format!("Control {} not found", input.standards_control_arn)))?;
        let status = input.control_status.clone().unwrap_or_else(|| "ENABLED".into());
        if status == "DISABLED" && input.disabled_reason.as_deref().is_none_or(str::is_empty) {
            return Err(invalid_input("DisabledReason must be provided when disabling a control."));
        }
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let standards_arn = catalog::standards_arn(&ctx.partition, &ctx.region, s);
        if subscription(h, &standards_arn).is_none()
            || common::arn_account(&input.standards_control_arn) != Some(account(ctx))
        {
            return Err(not_found(format!("Control {} not found", input.standards_control_arn)));
        }
        h.control_overrides.insert(
            override_key(&standards_arn, c.id),
            ControlOverride {
                status: status.clone(),
                reason: if status == "DISABLED" { input.disabled_reason } else { None },
                updated_at: ctx.received_at,
            },
        );
        h.evaluation.dirty = true;
        Ok(types::UpdateStandardsControlResponse {})
    }

    // ---- security controls --------------------------------------------------------

    pub(crate) fn batch_get_security_controls_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetSecurityControlsRequest,
    ) -> Result<types::BatchGetSecurityControlsResponse, ServiceError> {
        authorize_hub(ctx, "BatchGetSecurityControls")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let mut controls = Vec::new();
        let mut unprocessed = Vec::new();
        for id in input.security_control_ids {
            let Some(c) = catalog::control(&id) else {
                unprocessed.push(types::UnprocessedSecurityControl {
                    security_control_id: id,
                    error_code: "NOT_FOUND".into(),
                    error_reason: Some("Security control not found".into()),
                });
                continue;
            };
            let params = current_parameters(h, c);
            controls.push(types::SecurityControl {
                security_control_id: c.id.into(),
                security_control_arn: common::arn(ctx, &format!("security-control/{}", c.id)),
                title: c.title.into(),
                description: catalog::description(c),
                remediation_url: catalog::remediation_url(c),
                severity_rating: c.severity.into(),
                security_control_status: security_control_status(h, &ctx.partition, c).into(),
                update_status: Some("READY".into()),
                parameters: (!params.is_empty()).then_some(params),
                last_update_reason: h.security_controls.get(c.id).and_then(|s| s.last_update_reason.clone()),
                provider: None,
            });
        }
        Ok(types::BatchGetSecurityControlsResponse { security_controls: controls, unprocessed_ids: Some(unprocessed) })
    }

    pub(crate) fn get_security_control_definition_op(
        &self,
        ctx: &RequestContext,
        input: types::GetSecurityControlDefinitionRequest,
    ) -> Result<types::GetSecurityControlDefinitionResponse, ServiceError> {
        authorize_hub(ctx, "GetSecurityControlDefinition")?;
        let state = self.read();
        hub(&state, ctx)?;
        let c = catalog::control(&input.security_control_id)
            .ok_or_else(|| not_found(format!("Security control {} not found", input.security_control_id)))?;
        Ok(types::GetSecurityControlDefinitionResponse { security_control_definition: definition(c) })
    }

    pub(crate) fn list_security_control_definitions_op(
        &self,
        ctx: &RequestContext,
        input: types::ListSecurityControlDefinitionsRequest,
    ) -> Result<types::ListSecurityControlDefinitionsResponse, ServiceError> {
        authorize_hub(ctx, "ListSecurityControlDefinitions")?;
        let state = self.read();
        hub(&state, ctx)?;
        drop(state);
        let all: Vec<types::SecurityControlDefinition> = match &input.standards_arn {
            Some(arn) => {
                let s = catalog::standard_from_arn(arn)
                    .ok_or_else(|| invalid_input(format!("Invalid StandardsArn: {arn}")))?;
                catalog::controls_in(s.key).map(|(c, _, _)| definition(c)).collect()
            }
            None => catalog::controls().iter().map(definition).collect(),
        };
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListSecurityControlDefinitionsResponse { security_control_definitions: page, next_token })
    }

    pub(crate) fn update_security_control_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSecurityControlRequest,
    ) -> Result<types::UpdateSecurityControlResponse, ServiceError> {
        let arn = common::arn(ctx, &format!("security-control/{}", input.security_control_id));
        authorize(ctx, "UpdateSecurityControl", &arn)?;
        let c = catalog::control(&input.security_control_id)
            .ok_or_else(|| not_found(format!("Security control {} not found", input.security_control_id)))?;
        validate_parameters(c, &input.parameters).map_err(invalid_input)?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let rec = h.security_controls.entry(c.id.to_string()).or_default();
        rec.parameters.extend(input.parameters);
        rec.last_update_reason = input.last_update_reason;
        h.evaluation.dirty = true;
        Ok(types::UpdateSecurityControlResponse {})
    }

    // ---- associations -----------------------------------------------------------------

    pub(crate) fn list_standards_control_associations_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStandardsControlAssociationsRequest,
    ) -> Result<types::ListStandardsControlAssociationsResponse, ServiceError> {
        authorize_hub(ctx, "ListStandardsControlAssociations")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let c = catalog::control(&input.security_control_id)
            .ok_or_else(|| not_found(format!("Security control {} not found", input.security_control_id)))?;
        let all: Vec<types::StandardsControlAssociationSummary> = c
            .in_standards
            .iter()
            .filter_map(|(key, cid, reqs)| {
                let s = catalog::standard(key)?;
                let standards_arn = catalog::standards_arn(&ctx.partition, &ctx.region, s);
                let (status, o) = association_status(h, &standards_arn, c.id);
                Some(types::StandardsControlAssociationSummary {
                    standards_arn,
                    security_control_id: c.id.into(),
                    security_control_arn: common::arn(ctx, &format!("security-control/{}", c.id)),
                    association_status: status,
                    related_requirements: Some(reqs.iter().map(|r| r.to_string()).collect()),
                    updated_at: o.map(|o| o.updated_at),
                    updated_reason: o.and_then(|o| o.reason.clone()),
                    standards_control_title: Some(format!("{cid} {}", c.title)),
                    standards_control_description: Some(catalog::description(c)),
                })
            })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListStandardsControlAssociationsResponse {
            standards_control_association_summaries: page,
            next_token,
        })
    }

    pub(crate) fn batch_get_standards_control_associations_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetStandardsControlAssociationsRequest,
    ) -> Result<types::BatchGetStandardsControlAssociationsResponse, ServiceError> {
        authorize_hub(ctx, "BatchGetStandardsControlAssociations")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let mut details = Vec::new();
        let mut unprocessed = Vec::new();
        for id in input.standards_control_association_ids {
            let found = catalog::control(&id.security_control_id).and_then(|c| {
                let s = catalog::standard_from_arn(&id.standards_arn)?;
                let (_, cid, reqs) = c.in_standards.iter().find(|(k, _, _)| *k == s.key)?;
                Some((c, s, *cid, *reqs))
            });
            let Some((c, s, cid, reqs)) = found else {
                unprocessed.push(types::UnprocessedStandardsControlAssociation {
                    standards_control_association_id: id,
                    error_code: "NOT_FOUND".into(),
                    error_reason: Some("The control is not associated with the standard".into()),
                });
                continue;
            };
            let (status, o) = association_status(h, &id.standards_arn, c.id);
            details.push(types::StandardsControlAssociationDetail {
                standards_arn: id.standards_arn.clone(),
                security_control_id: c.id.into(),
                security_control_arn: common::arn(ctx, &format!("security-control/{}", c.id)),
                association_status: status,
                related_requirements: Some(reqs.iter().map(|r| r.to_string()).collect()),
                updated_at: o.map(|o| o.updated_at),
                updated_reason: o.and_then(|o| o.reason.clone()),
                standards_control_title: Some(format!("{cid} {}", c.title)),
                standards_control_description: Some(catalog::description(c)),
                standards_control_arns: Some(vec![common::arn(ctx, &format!("control/{}/{cid}", s.key))]),
            });
        }
        Ok(types::BatchGetStandardsControlAssociationsResponse {
            standards_control_association_details: details,
            unprocessed_associations: Some(unprocessed),
        })
    }

    pub(crate) fn batch_update_standards_control_associations_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchUpdateStandardsControlAssociationsRequest,
    ) -> Result<types::BatchUpdateStandardsControlAssociationsResponse, ServiceError> {
        authorize_hub(ctx, "BatchUpdateStandardsControlAssociations")?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let mut unprocessed = Vec::new();
        for u in input.standards_control_association_updates {
            let fail = |u: types::StandardsControlAssociationUpdate, code: &str, reason: &str| {
                types::UnprocessedStandardsControlAssociationUpdate {
                    standards_control_association_update: u,
                    error_code: code.into(),
                    error_reason: Some(reason.into()),
                }
            };
            let in_standard = catalog::control(&u.security_control_id).is_some_and(|c| {
                catalog::standard_from_arn(&u.standards_arn)
                    .is_some_and(|s| c.in_standards.iter().any(|(k, _, _)| *k == s.key))
            });
            if !in_standard {
                unprocessed.push(fail(u, "NOT_FOUND", "The control is not associated with the standard"));
                continue;
            }
            if subscription(h, &u.standards_arn).is_none() {
                unprocessed.push(fail(u, "INVALID_INPUT", "The standard is not enabled"));
                continue;
            }
            if u.association_status == "DISABLED" && u.updated_reason.as_deref().is_none_or(str::is_empty) {
                unprocessed.push(fail(u, "INVALID_INPUT", "UpdatedReason is required when disabling a control"));
                continue;
            }
            h.control_overrides.insert(
                override_key(&u.standards_arn, &u.security_control_id),
                ControlOverride {
                    status: u.association_status.clone(),
                    reason: u.updated_reason.clone(),
                    updated_at: ctx.received_at,
                },
            );
        }
        h.evaluation.dirty = true;
        Ok(types::BatchUpdateStandardsControlAssociationsResponse {
            unprocessed_association_updates: Some(unprocessed),
        })
    }
}

/// Set every control's status in every enabled standard of a hub, as
/// central configuration does: enabled unless listed as disabled (or, with
/// an enabled list, unless missing from it).
pub fn apply_control_policy(
    h: &mut Hub,
    partition: &str,
    enabled: Option<&[String]>,
    disabled: Option<&[String]>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let subs: Vec<String> = h.standards.values().map(|s| s.standards_arn.clone()).collect();
    for standards_arn in subs {
        let Some(s) = catalog::standard_from_arn(&standards_arn) else { continue };
        for (c, _, _) in catalog::controls_in(s.key) {
            let on = match (enabled, disabled) {
                (Some(list), _) => list.iter().any(|x| x == c.id),
                (None, Some(list)) => !list.iter().any(|x| x == c.id),
                (None, None) => true,
            };
            let key = override_key(&standards_arn, c.id);
            if on {
                h.control_overrides.remove(&key);
            } else {
                h.control_overrides.insert(
                    key,
                    ControlOverride {
                        status: "DISABLED".into(),
                        reason: Some("Disabled by configuration policy".into()),
                        updated_at: now,
                    },
                );
            }
        }
    }
    h.evaluation.dirty = true;
    let _ = partition;
}
