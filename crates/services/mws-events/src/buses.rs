//! Event buses and their resource policies.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Value};

use crate::generated::{errors, types};
use crate::names::{self, not_found, own_region, request_tags, validation, BusRef};
use crate::state::Bus;
use crate::Events;

fn check_dead_letter(d: Option<&types::DeadLetterConfig>) -> Result<(), ServiceError> {
    if let Some(arn) = d.and_then(|d| d.arn.as_deref()) {
        if names::split_arn(arn).map(|p| p.1) != Some("sqs") {
            return Err(validation(format!(
                "Parameter DeadLetterConfig.Arn is not valid. Reason: Provided Arn {arn} is not a valid SQS queue ARN."
            )));
        }
    }
    Ok(())
}

impl Events {
    pub fn create_event_bus(
        &self,
        ctx: &RequestContext,
        input: types::CreateEventBusRequest,
    ) -> Result<types::CreateEventBusResponse, ServiceError> {
        let bus = BusRef::own(ctx, &input.name);
        let tags: Vec<(String, String)> =
            input.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        self.authorize_own(ctx, "events:CreateEventBus", &bus.arn(), request_tags(tags.iter().map(|(k, v)| (k, v))))?;
        check_dead_letter(input.dead_letter_config.as_ref())?;
        match &input.event_source_name {
            Some(source) if *source != input.name => {
                return Err(validation("Event bus name must match the event source name."));
            }
            None if input.name.starts_with("aws.") => {
                return Err(validation("Event bus name must not start with 'aws.'"));
            }
            _ => {}
        }
        let now = ctx.received_at;
        let mut st = self.lock();
        let region = own_region(&mut st, ctx);
        if region.buses.contains_key(&input.name) {
            return Err(errors::resource_already_exists(format!("Event bus {} already exists.", input.name)));
        }
        if let Some(source) = &input.event_source_name {
            let es = region
                .event_sources
                .get_mut(source)
                .filter(|s| s.state != "DELETED")
                .ok_or_else(|| not_found(format!("Event source {source} does not exist.")))?;
            es.state = "ACTIVE".into();
        }
        let arn = bus.arn();
        region.buses.insert(
            input.name.clone(),
            Bus {
                name: input.name.clone(),
                arn: arn.clone(),
                description: input.description.clone(),
                kms_key_identifier: input.kms_key_identifier.clone(),
                dead_letter_config: input.dead_letter_config.clone(),
                log_config: input.log_config.clone(),
                event_source_name: input.event_source_name.clone(),
                creation_time: now,
                last_modified_time: now,
                ..Bus::default()
            },
        );
        if !tags.is_empty() {
            region.tags.insert(arn.clone(), tags.into_iter().collect());
        }
        Ok(types::CreateEventBusResponse {
            event_bus_arn: Some(arn),
            description: input.description,
            kms_key_identifier: input.kms_key_identifier,
            dead_letter_config: input.dead_letter_config,
            log_config: input.log_config,
        })
    }

    pub fn delete_event_bus(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEventBusRequest,
    ) -> Result<(), ServiceError> {
        let bus = BusRef::own(ctx, &input.name);
        self.authorize_own(ctx, "events:DeleteEventBus", &bus.arn(), ConditionContext::new())?;
        if input.name == "default" {
            return Err(validation("Cannot delete event bus default."));
        }
        let mut st = self.lock();
        let region = own_region(&mut st, ctx);
        if let Some(b) = region.buses.remove(&input.name) {
            for rule in b.rules.values() {
                region.tags.remove(&rule.arn);
            }
            region.tags.remove(&b.arn);
            if let Some(es) = b.event_source_name.and_then(|s| region.event_sources.get_mut(&s)) {
                if es.state == "ACTIVE" {
                    es.state = "PENDING".into();
                }
            }
        }
        Ok(())
    }

    pub fn describe_event_bus(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEventBusRequest,
    ) -> Result<types::DescribeEventBusResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.name.as_deref())?;
        self.authorize_on_bus(ctx, "events:DescribeEventBus", &bus, &bus.arn(), ConditionContext::new())?;
        self.with_bus(ctx, &bus, |b| {
            Ok(types::DescribeEventBusResponse {
                name: Some(b.name.clone()),
                arn: Some(b.arn.clone()),
                description: b.description.clone(),
                kms_key_identifier: b.kms_key_identifier.clone(),
                dead_letter_config: b.dead_letter_config.clone(),
                policy: b.policy.clone(),
                log_config: b.log_config.clone(),
                creation_time: Some(b.creation_time),
                last_modified_time: Some(b.last_modified_time),
                managed_by: None,
            })
        })
    }

    pub fn list_event_buses(
        &self,
        ctx: &RequestContext,
        input: types::ListEventBusesRequest,
    ) -> Result<types::ListEventBusesResponse, ServiceError> {
        ctx.authorize("events:ListEventBuses", "*", ConditionContext::new())?;
        let buses: Vec<types::EventBus> = {
            let mut st = self.lock();
            own_region(&mut st, ctx)
                .buses
                .values()
                .filter(|b| input.name_prefix.as_deref().is_none_or(|p| b.name.starts_with(p)))
                .map(|b| types::EventBus {
                    name: Some(b.name.clone()),
                    arn: Some(b.arn.clone()),
                    description: b.description.clone(),
                    policy: b.policy.clone(),
                    creation_time: Some(b.creation_time),
                    last_modified_time: Some(b.last_modified_time),
                    managed_by: None,
                })
                .collect()
        };
        let (page, next_token) = names::paginate(buses, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListEventBusesResponse { event_buses: Some(page), next_token })
    }

    pub fn update_event_bus(
        &self,
        ctx: &RequestContext,
        input: types::UpdateEventBusRequest,
    ) -> Result<types::UpdateEventBusResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.name.as_deref())?;
        self.authorize_own(ctx, "events:UpdateEventBus", &bus.arn(), ConditionContext::new())?;
        check_dead_letter(input.dead_letter_config.as_ref())?;
        let now = ctx.received_at;
        self.with_bus(ctx, &bus, |b| {
            if input.description.is_some() {
                b.description = input.description.clone().filter(|d| !d.is_empty());
            }
            if input.kms_key_identifier.is_some() {
                b.kms_key_identifier = input.kms_key_identifier.clone().filter(|k| !k.is_empty());
            }
            if input.dead_letter_config.is_some() {
                b.dead_letter_config = input.dead_letter_config.clone().filter(|d| d.arn.is_some());
            }
            if input.log_config.is_some() {
                b.log_config = input.log_config.clone();
            }
            b.last_modified_time = now;
            Ok(types::UpdateEventBusResponse {
                arn: Some(b.arn.clone()),
                name: Some(b.name.clone()),
                kms_key_identifier: b.kms_key_identifier.clone(),
                description: b.description.clone(),
                dead_letter_config: b.dead_letter_config.clone(),
                log_config: b.log_config.clone(),
            })
        })
    }

    pub fn put_permission(&self, ctx: &RequestContext, input: types::PutPermissionRequest) -> Result<(), ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        self.authorize_own(ctx, "events:PutPermission", &bus.arn(), ConditionContext::new())?;
        if bus.account != ctx.caller.account_id {
            return Err(errors::access_denied("You can only change the policy of event buses in your own account."));
        }
        let bus_arn = bus.arn();
        if let Some(policy) = &input.policy {
            let doc: Value = serde_json::from_str(policy)
                .map_err(|_| validation("Parameter Policy is not valid. Reason: Policy is not valid JSON."))?;
            if !doc.get("Statement").is_some_and(|s| s.is_array() || s.is_object()) {
                return Err(validation("Parameter Policy is not valid. Reason: Policy must contain a Statement."));
            }
            if policy.len() > 10_240 {
                return Err(errors::policy_length_exceeded("Event bus policy exceeds the maximum size."));
            }
            let text = doc.to_string();
            return self.with_bus(ctx, &bus, |b| {
                b.policy = Some(text);
                b.last_modified_time = ctx.received_at;
                Ok(())
            });
        }
        let (Some(action), Some(principal), Some(sid)) = (&input.action, &input.principal, &input.statement_id) else {
            return Err(validation("Parameter(s) Action, Principal and StatementId must be specified."));
        };
        if !action.starts_with("events:") {
            return Err(validation(format!(
                "Parameter Action is not valid. Reason: Provided action {action} is not supported."
            )));
        }
        let principal_value = if principal == "*" {
            json!("*")
        } else if principal.len() == 12 && principal.bytes().all(|b| b.is_ascii_digit()) {
            json!({ "AWS": format!("arn:{}:iam::{principal}:root", ctx.partition) })
        } else if principal.starts_with("arn:") {
            json!({ "AWS": principal })
        } else {
            return Err(validation(format!(
                "Parameter Principal is not valid. Reason: Provided principal {principal} is not valid."
            )));
        };
        let mut statement = json!({
            "Sid": sid,
            "Effect": "Allow",
            "Principal": principal_value,
            "Action": action,
            "Resource": bus_arn,
        });
        if let Some(c) = &input.condition {
            if c.r#type != "StringEquals" || c.key != "aws:PrincipalOrgID" {
                return Err(validation(
                    "Parameter Condition is not valid. Reason: Only StringEquals on aws:PrincipalOrgID is supported.",
                ));
            }
            statement["Condition"] = json!({ "StringEquals": { "aws:PrincipalOrgID": c.value } });
        }
        self.with_bus(ctx, &bus, |b| {
            let mut doc: Value = b
                .policy
                .as_deref()
                .and_then(|p| serde_json::from_str(p).ok())
                .unwrap_or_else(|| json!({ "Version": "2012-10-17", "Statement": [] }));
            let statements = statements_mut(&mut doc);
            if statements.iter().any(|s| s.get("Sid").and_then(Value::as_str) == Some(sid)) {
                return Err(errors::resource_already_exists("Statement with the provided id already exists."));
            }
            statements.push(statement);
            b.policy = Some(doc.to_string());
            b.last_modified_time = ctx.received_at;
            Ok(())
        })
    }

    pub fn remove_permission(
        &self,
        ctx: &RequestContext,
        input: types::RemovePermissionRequest,
    ) -> Result<(), ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        self.authorize_own(ctx, "events:RemovePermission", &bus.arn(), ConditionContext::new())?;
        self.with_bus(ctx, &bus, |b| {
            let Some(policy) = b.policy.clone() else {
                return Err(not_found("EventBus does not have a policy."));
            };
            if input.remove_all_permissions {
                b.policy = None;
                return Ok(());
            }
            let Some(sid) = &input.statement_id else {
                return Err(validation("Parameter StatementId must be specified."));
            };
            let mut doc: Value = serde_json::from_str(&policy).unwrap_or_else(|_| json!({}));
            let statements = statements_mut(&mut doc);
            let before = statements.len();
            statements.retain(|s| s.get("Sid").and_then(Value::as_str) != Some(sid.as_str()));
            if statements.len() == before {
                return Err(not_found("Statement with the provided id does not exist."));
            }
            b.policy = if statements.is_empty() { None } else { Some(doc.to_string()) };
            b.last_modified_time = ctx.received_at;
            Ok(())
        })
    }
}

fn statements_mut(doc: &mut Value) -> &mut Vec<Value> {
    if !doc.get("Statement").is_some_and(Value::is_array) {
        let existing = doc.get("Statement").cloned();
        doc["Statement"] = Value::Array(existing.into_iter().collect());
    }
    doc["Statement"].as_array_mut().expect("statement array")
}
