//! What deploying a template would change: the `Changes` of a change set.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::engine::{EvalData, StackResources};
use crate::intrinsics::EvalError;
use crate::state::Stack;
use crate::template::Template;
use crate::CloudFormation;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ResourceChange {
    pub action: String,
    pub logical_id: String,
    pub physical_id: Option<String>,
    pub resource_type: String,
    pub replacement: Option<String>,
    pub policy_action: Option<String>,
    pub scope: Vec<String>,
    pub details: Vec<Detail>,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Detail {
    pub attribute: String,
    pub name: Option<String>,
    pub requires_recreation: String,
    pub evaluation: String,
    pub change_source: String,
    pub causing_entity: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
}

fn show(v: Option<&Value>) -> Option<String> {
    v.map(|v| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

/// The changes deploying `template` with `data` onto `stack` makes.
pub fn compute(
    cfn: &CloudFormation,
    stack: &Stack,
    template: &Template,
    data: &EvalData,
) -> Result<Vec<ResourceChange>, String> {
    let order = template.creation_order(&|l| data.included(template, l))?;
    let mut pending: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for logical in &order {
        let ty = template.resource_type(logical).unwrap_or_default().to_string();
        let def = template.resource(logical).cloned().unwrap_or_default();
        let existing = stack.resource(logical).filter(|r| r.exists());
        let Some(old) = existing else {
            pending.insert(logical.clone());
            let after = {
                let lookup = StackResources {
                    resources: &stack.resources,
                    template,
                    data,
                    pending: &pending,
                    preview: true,
                    cfn,
                    account: &stack.account,
                    region: &stack.region,
                };
                data.evaluator(template, &lookup).eval_properties(def.get("Properties")).ok()
            };
            out.push(ResourceChange {
                action: "Add".into(),
                logical_id: logical.clone(),
                resource_type: ty,
                after: after.map(|p| serde_json::json!({"Properties": p}).to_string()),
                ..Default::default()
            });
            continue;
        };
        if old.resource_type != ty {
            return Err(format!(
                "Update of resource type is not permitted. The new template modifies resource type of the following resources: [{logical}]"
            ));
        }
        let lookup = StackResources {
            resources: &stack.resources,
            template,
            data,
            pending: &pending,
            preview: true,
            cfn,
            account: &stack.account,
            region: &stack.region,
        };
        let ev = data.evaluator(template, &lookup);
        let new_props = def.get("Properties").and_then(Value::as_object).cloned().unwrap_or_default();
        let keys: BTreeSet<String> = old.properties.keys().chain(new_props.keys()).cloned().collect();
        let provider = cfn.provider_in(&stack.account, &stack.region, &ty);
        let create_only: &[&str] = provider.as_ref().map(|p| p.create_only()).unwrap_or(&[]);
        let updatable = provider.as_ref().is_none_or(|p| p.updatable());
        let mut details = Vec::new();
        let mut after_props = serde_json::Map::new();
        for key in keys {
            let (value, dynamic, causing) = match new_props.get(&key) {
                None => (None, false, None),
                Some(expr) => match ev.eval(expr) {
                    Ok(Value::Null) => (None, false, None),
                    Ok(v) => (Some(v), false, None),
                    Err(EvalError::Unknown) => {
                        let refs = crate::template::references(expr);
                        let cause = refs
                            .refs
                            .iter()
                            .chain(refs.get_atts.iter().map(|(r, _)| r))
                            .find(|r| pending.contains(*r))
                            .cloned();
                        (None, true, cause)
                    }
                    Err(EvalError::Error(e)) => return Err(e),
                },
            };
            if let Some(v) = &value {
                after_props.insert(key.clone(), v.clone());
            }
            if !dynamic && value.as_ref() == old.properties.get(&key) {
                continue;
            }
            let recreate = if !updatable || create_only.contains(&key.as_str()) {
                if dynamic {
                    "Conditionally"
                } else {
                    "Always"
                }
            } else {
                "Never"
            };
            let is_tags = key == "Tags";
            details.push(Detail {
                attribute: if is_tags { "Tags".into() } else { "Properties".into() },
                name: if is_tags { None } else { Some(key.clone()) },
                requires_recreation: recreate.into(),
                evaluation: if dynamic { "Dynamic".into() } else { "Static".into() },
                change_source: if dynamic {
                    if causing.as_ref().is_some_and(|c| {
                        new_props
                            .get(&key)
                            .is_some_and(|e| crate::template::references(e).get_atts.iter().any(|(r, _)| r == c))
                    }) {
                        "ResourceAttribute".into()
                    } else {
                        "ResourceReference".into()
                    }
                } else {
                    "DirectModification".into()
                },
                causing_entity: causing,
                before: show(old.properties.get(&key)),
                after: show(value.as_ref()),
            });
        }
        if details.is_empty() {
            continue;
        }
        let replacement = if details.iter().any(|d| d.requires_recreation == "Always") {
            "True"
        } else if details.iter().any(|d| d.requires_recreation == "Conditionally") {
            "Conditional"
        } else {
            "False"
        };
        if replacement != "False" {
            pending.insert(logical.clone());
        }
        let mut scope: Vec<String> = Vec::new();
        for d in &details {
            if !scope.contains(&d.attribute) {
                scope.push(d.attribute.clone());
            }
        }
        out.push(ResourceChange {
            action: "Modify".into(),
            logical_id: logical.clone(),
            physical_id: old.physical_id.clone(),
            resource_type: ty,
            replacement: Some(replacement.into()),
            policy_action: Some(if replacement == "True" { "ReplaceAndDelete".into() } else { "Modify".into() }),
            scope,
            details,
            before: Some(serde_json::json!({"Properties": old.properties}).to_string()),
            after: Some(serde_json::json!({"Properties": after_props}).to_string()),
        });
    }
    for r in &stack.resources {
        if !r.exists() || order.contains(&r.logical_id) {
            continue;
        }
        let old_template = Template::parse(&stack.template_body).ok();
        let policy = old_template
            .as_ref()
            .and_then(|t| t.resource(&r.logical_id))
            .and_then(|d| d.get("DeletionPolicy"))
            .and_then(Value::as_str)
            .unwrap_or("Delete");
        out.push(ResourceChange {
            action: "Remove".into(),
            logical_id: r.logical_id.clone(),
            physical_id: r.physical_id.clone(),
            resource_type: r.resource_type.clone(),
            policy_action: Some(if matches!(policy, "Retain" | "RetainExceptOnCreate") {
                "Retain".into()
            } else {
                "Delete".into()
            }),
            before: Some(serde_json::json!({"Properties": r.properties}).to_string()),
            ..Default::default()
        });
    }
    Ok(out)
}
