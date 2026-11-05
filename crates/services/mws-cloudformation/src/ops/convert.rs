//! Stored state to wire types.

use crate::changes::ResourceChange;
use crate::generated::types;
use crate::state::{Event, Resource, Stack};

pub fn tags(t: &[crate::state::Tag]) -> Option<Vec<types::Tag>> {
    (!t.is_empty()).then(|| t.iter().map(|t| types::Tag { key: t.key.clone(), value: t.value.clone() }).collect())
}

pub fn parameters(p: &[crate::parameters::StackParameter]) -> Option<Vec<types::Parameter>> {
    (!p.is_empty()).then(|| {
        p.iter()
            .map(|p| types::Parameter {
                parameter_key: Some(p.key.clone()),
                parameter_value: Some(if p.no_echo { "****".into() } else { p.value.clone() }),
                use_previous_value: None,
                resolved_value: p.resolved.clone().map(|r| if p.no_echo { "****".into() } else { r }),
            })
            .collect()
    })
}

pub fn stack(s: &Stack) -> types::Stack {
    let drift = types::StackDriftInformation {
        stack_drift_status: s.drift_status.clone().unwrap_or_else(|| "NOT_CHECKED".into()),
        last_check_timestamp: s.drift_checked,
    };
    types::Stack {
        stack_id: Some(s.id.clone()),
        stack_name: s.name.clone(),
        change_set_id: s.change_set_id.clone(),
        description: s.description.clone(),
        parameters: parameters(&s.parameters),
        creation_time: s.created,
        deletion_time: s.deleted,
        last_updated_time: s.updated,
        rollback_configuration: Some(types::RollbackConfiguration::default()),
        stack_status: s.status.clone(),
        stack_status_reason: s.status_reason.clone(),
        disable_rollback: Some(s.disable_rollback),
        notification_ar_ns: Some(s.notification_arns.clone()),
        timeout_in_minutes: s.timeout_in_minutes,
        capabilities: (!s.capabilities.is_empty()).then(|| s.capabilities.clone()),
        outputs: (!s.outputs.is_empty()).then(|| {
            s.outputs
                .iter()
                .map(|o| types::Output {
                    output_key: Some(o.key.clone()),
                    output_value: Some(o.value.clone()),
                    description: o.description.clone(),
                    export_name: o.export_name.clone(),
                })
                .collect()
        }),
        role_arn: s.role_arn.clone(),
        tags: tags(&s.tags),
        enable_termination_protection: Some(s.termination_protection),
        parent_id: s.parent_id.clone(),
        root_id: s.root_id.clone(),
        drift_information: Some(drift),
        retain_except_on_create: Some(s.retain_except_on_create),
        last_operations: s.last_operation.as_ref().map(|(t, id)| {
            vec![types::OperationEntry { operation_type: Some(t.clone()), operation_id: Some(id.clone()) }]
        }),
        ..Default::default()
    }
}

pub fn summary(s: &Stack) -> types::StackSummary {
    types::StackSummary {
        stack_id: Some(s.id.clone()),
        stack_name: s.name.clone(),
        template_description: s.description.clone(),
        creation_time: s.created,
        last_updated_time: s.updated,
        deletion_time: s.deleted,
        stack_status: s.status.clone(),
        stack_status_reason: s.status_reason.clone(),
        parent_id: s.parent_id.clone(),
        root_id: s.root_id.clone(),
        drift_information: Some(types::StackDriftInformationSummary {
            stack_drift_status: s.drift_status.clone().unwrap_or_else(|| "NOT_CHECKED".into()),
            last_check_timestamp: s.drift_checked,
        }),
        last_operations: s.last_operation.as_ref().map(|(t, id)| {
            vec![types::OperationEntry { operation_type: Some(t.clone()), operation_id: Some(id.clone()) }]
        }),
    }
}

pub fn event(s: &Stack, e: &Event) -> types::StackEvent {
    types::StackEvent {
        stack_id: s.id.clone(),
        event_id: e.id.clone(),
        stack_name: s.name.clone(),
        operation_id: e.operation_id.clone(),
        logical_resource_id: Some(e.logical_id.clone()),
        physical_resource_id: e.physical_id.clone(),
        resource_type: Some(e.resource_type.clone()),
        timestamp: e.timestamp,
        resource_status: Some(e.status.clone()),
        resource_status_reason: e.reason.clone(),
        resource_properties: e.properties.clone(),
        client_request_token: e.client_request_token.clone(),
        hook_type: e.hook_type.clone(),
        hook_status: e.hook_status.clone(),
        hook_status_reason: e.hook_status_reason.clone(),
        hook_invocation_point: e.hook_invocation_point.clone(),
        hook_invocation_id: e.hook_invocation_id.clone(),
        hook_failure_mode: e.hook_failure_mode.clone(),
        ..Default::default()
    }
}

fn drift_info(r: &Resource) -> types::StackResourceDriftInformation {
    types::StackResourceDriftInformation {
        stack_resource_drift_status: r.drift_status.clone().unwrap_or_else(|| "NOT_CHECKED".into()),
        last_check_timestamp: r.drift_checked,
    }
}

pub fn resource(s: &Stack, r: &Resource) -> types::StackResource {
    types::StackResource {
        stack_name: Some(s.name.clone()),
        stack_id: Some(s.id.clone()),
        logical_resource_id: r.logical_id.clone(),
        physical_resource_id: r.physical_id.clone(),
        resource_type: r.resource_type.clone(),
        timestamp: r.updated,
        resource_status: r.status.clone(),
        resource_status_reason: r.status_reason.clone(),
        description: r.description.clone(),
        drift_information: Some(drift_info(r)),
        module_info: None,
    }
}

pub fn resource_detail(s: &Stack, r: &Resource) -> types::StackResourceDetail {
    types::StackResourceDetail {
        stack_name: Some(s.name.clone()),
        stack_id: Some(s.id.clone()),
        logical_resource_id: r.logical_id.clone(),
        physical_resource_id: r.physical_id.clone(),
        resource_type: r.resource_type.clone(),
        last_updated_timestamp: r.updated,
        resource_status: r.status.clone(),
        resource_status_reason: r.status_reason.clone(),
        description: r.description.clone(),
        metadata: Some(r.metadata.as_ref().map(|m| m.to_string()).unwrap_or_else(|| "{}".into())),
        drift_information: Some(drift_info(r)),
        module_info: None,
    }
}

pub fn resource_summary(r: &Resource) -> types::StackResourceSummary {
    types::StackResourceSummary {
        logical_resource_id: r.logical_id.clone(),
        physical_resource_id: r.physical_id.clone(),
        resource_type: r.resource_type.clone(),
        last_updated_timestamp: r.updated,
        resource_status: r.status.clone(),
        resource_status_reason: r.status_reason.clone(),
        drift_information: Some(types::StackResourceDriftInformationSummary {
            stack_resource_drift_status: r.drift_status.clone().unwrap_or_else(|| "NOT_CHECKED".into()),
            last_check_timestamp: r.drift_checked,
        }),
        module_info: None,
    }
}

pub fn change(c: &ResourceChange, with_values: bool) -> types::Change {
    types::Change {
        r#type: Some("Resource".into()),
        hook_invocation_count: None,
        resource_change: Some(types::ResourceChange {
            policy_action: c.policy_action.clone(),
            action: Some(c.action.clone()),
            logical_resource_id: Some(c.logical_id.clone()),
            physical_resource_id: c.physical_id.clone(),
            resource_type: Some(c.resource_type.clone()),
            replacement: c.replacement.clone(),
            scope: (c.action == "Modify").then(|| c.scope.clone()),
            details: (c.action == "Modify").then(|| {
                c.details
                    .iter()
                    .map(|d| types::ResourceChangeDetail {
                        target: Some(types::ResourceTargetDefinition {
                            attribute: Some(d.attribute.clone()),
                            name: d.name.clone(),
                            requires_recreation: Some(d.requires_recreation.clone()),
                            before_value: if with_values { d.before.clone() } else { None },
                            after_value: if with_values { d.after.clone() } else { None },
                            ..Default::default()
                        }),
                        evaluation: Some(d.evaluation.clone()),
                        change_source: Some(d.change_source.clone()),
                        causing_entity: d.causing_entity.clone(),
                    })
                    .collect()
            }),
            change_set_id: None,
            before_context: if with_values { c.before.clone() } else { None },
            after_context: if with_values { c.after.clone() } else { None },
            ..Default::default()
        }),
    }
}
