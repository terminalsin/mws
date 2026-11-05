//! Lifecycle policies: validation, evaluation (expiring or archiving
//! images on the emulated clock), previews, and the other clock-driven
//! changes (scans completing, archived images being restored).

use std::collections::BTreeSet;

use mws_core::{RequestContext, ServiceError};
use serde_json::Value;

use crate::generated::{errors, types};
use crate::images::image_event;
use crate::names::{dt, invalid_parameter, now_ms};
use crate::state::{Preview, PreviewResult, Repo, State};
use crate::{Ecr, EcrEvent};

/// How long restoring an archived image takes.
pub(crate) const RESTORE_MS: i64 = 20 * 60 * 1000;
const DAY_MS: i64 = 24 * 3600 * 1000;

#[derive(Debug, Clone)]
pub(crate) struct Rule {
    pub priority: i32,
    pub tag_status: String,
    pub prefixes: Vec<String>,
    pub patterns: Vec<String>,
    pub count_type: String,
    pub count_number: i64,
    pub storage_class: String,
    pub action: String,
    pub target_storage_class: Option<String>,
}

fn failure(message: impl std::fmt::Display) -> ServiceError {
    invalid_parameter(format!(
        "Invalid parameter at 'LifecyclePolicyText' failed to satisfy constraint: 'Lifecycle policy validation failure: {message}'"
    ))
}

fn strings(v: Option<&Value>, what: &str) -> Result<Vec<String>, ServiceError> {
    match v {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| i.as_str().map(str::to_string).ok_or_else(|| failure(format!("{what} must be a list of strings"))))
            .collect(),
        Some(_) => Err(failure(format!("{what} must be a list of strings"))),
    }
}

/// Parse and validate a lifecycle policy, rules in priority order.
pub(crate) fn parse(text: &str) -> Result<Vec<Rule>, ServiceError> {
    let doc: Value = serde_json::from_str(text).map_err(|_| failure("Unable to parse policy text as JSON."))?;
    let rules = doc
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| failure("object has missing required properties ([\"rules\"])"))?;
    if rules.is_empty() {
        return Err(failure("array is too short: must have at least 1 elements but instance has 0 elements"));
    }
    let mut out = Vec::new();
    let mut priorities = BTreeSet::new();
    for r in rules {
        let priority = r
            .get("rulePriority")
            .and_then(Value::as_i64)
            .ok_or_else(|| failure("object has missing required properties ([\"rulePriority\"])"))?;
        if priority < 1 {
            return Err(failure("rulePriority must be greater than or equal to 1"));
        }
        if !priorities.insert(priority) {
            return Err(failure(format!("The rulePriority {priority} is used more than once.")));
        }
        let selection =
            r.get("selection").ok_or_else(|| failure("object has missing required properties ([\"selection\"])"))?;
        let tag_status = selection
            .get("tagStatus")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("object has missing required properties ([\"tagStatus\"])"))?
            .to_ascii_lowercase();
        if !matches!(tag_status.as_str(), "tagged" | "untagged" | "any") {
            return Err(failure(format!("instance value (\"{tag_status}\") not found in enum (possible values: [\"tagged\",\"untagged\",\"any\"])")));
        }
        let prefixes = strings(selection.get("tagPrefixList"), "tagPrefixList")?;
        let patterns = strings(selection.get("tagPatternList"), "tagPatternList")?;
        if tag_status == "tagged" && prefixes.is_empty() && patterns.is_empty() {
            return Err(failure("The tagPrefixList or tagPatternList field is required when tagStatus is tagged."));
        }
        if !prefixes.is_empty() && !patterns.is_empty() {
            return Err(failure("You cannot specify both tagPrefixList and tagPatternList in the same rule."));
        }
        if tag_status != "tagged" && (!prefixes.is_empty() || !patterns.is_empty()) {
            return Err(failure("tagPrefixList and tagPatternList can only be used when tagStatus is tagged."));
        }
        let count_type = selection
            .get("countType")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("object has missing required properties ([\"countType\"])"))?
            .to_string();
        let count_number = selection
            .get("countNumber")
            .and_then(Value::as_i64)
            .ok_or_else(|| failure("object has missing required properties ([\"countNumber\"])"))?;
        if count_number < 1 {
            return Err(failure("countNumber must be greater than or equal to 1"));
        }
        let unit = selection.get("countUnit").and_then(Value::as_str);
        match count_type.as_str() {
            "imageCountMoreThan" => {
                if unit.is_some() {
                    return Err(failure("countUnit cannot be used with countType imageCountMoreThan."));
                }
            }
            "sinceImagePushed" | "sinceImagePulled" | "sinceImageTransitioned" => {
                if unit != Some("days") {
                    return Err(failure(format!("countUnit must be days when countType is {count_type}.")));
                }
            }
            other => {
                return Err(failure(format!("instance value (\"{other}\") not found in enum (possible values: [\"imageCountMoreThan\",\"sinceImagePushed\",\"sinceImagePulled\",\"sinceImageTransitioned\"])")));
            }
        }
        let storage_class =
            selection.get("storageClass").and_then(Value::as_str).unwrap_or("standard").to_ascii_lowercase();
        let action = r
            .pointer("/action/type")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("object has missing required properties ([\"action\"])"))?
            .to_ascii_lowercase();
        let target_storage_class =
            r.pointer("/action/targetStorageClass").and_then(Value::as_str).map(str::to_ascii_lowercase);
        match action.as_str() {
            "expire" => {}
            "transition" => {
                if target_storage_class.as_deref() != Some("archive") {
                    return Err(failure("targetStorageClass must be archive when action type is transition."));
                }
                if storage_class == "archive" {
                    return Err(failure("Images in the archive storage class cannot be transitioned."));
                }
            }
            other => {
                return Err(failure(format!(
                    "instance value (\"{other}\") not found in enum (possible values: [\"expire\",\"transition\"])"
                )))
            }
        }
        if count_type == "sinceImageTransitioned" && storage_class != "archive" {
            return Err(failure("countType sinceImageTransitioned requires storageClass archive."));
        }
        out.push(Rule {
            priority: priority as i32,
            tag_status,
            prefixes,
            patterns,
            count_type,
            count_number,
            storage_class,
            action,
            target_storage_class,
        });
    }
    out.sort_by_key(|r| r.priority);
    if let Some(pos) = out.iter().position(|r| r.tag_status == "any") {
        if pos != out.len() - 1 {
            return Err(failure("The rule with tagStatus any must have the highest rulePriority value."));
        }
    }
    Ok(out)
}

fn selects(rule: &Rule, tags: &[String]) -> bool {
    match rule.tag_status.as_str() {
        "untagged" => tags.is_empty(),
        "any" => true,
        _ => {
            !tags.is_empty()
                && rule.prefixes.iter().all(|p| tags.iter().any(|t| t.starts_with(p.as_str())))
                && rule.patterns.iter().all(|p| tags.iter().any(|t| crate::names::wildcard(p, t)))
        }
    }
}

/// What a policy would do to a repository's images now.
pub(crate) fn evaluate(rules: &[Rule], repo: &Repo, now: i64) -> Vec<PreviewResult> {
    let mut claimed = BTreeSet::new();
    let mut results = Vec::new();
    for rule in rules {
        let mut candidates: Vec<_> = repo
            .content
            .images
            .values()
            .filter(|i| !claimed.contains(&i.digest))
            .filter(|i| {
                let status = repo.status(&i.digest);
                match rule.storage_class.as_str() {
                    "archive" => status == "ARCHIVED",
                    _ => status == "ACTIVE",
                }
            })
            .filter(|i| selects(rule, &repo.content.tags_of(&i.digest)))
            // Images an index references go with the index.
            .filter(|i| !repo.content.referenced_by_index(&i.digest))
            .collect();
        candidates.sort_by(|a, b| b.pushed_at.cmp(&a.pushed_at).then_with(|| b.digest.cmp(&a.digest)));
        for c in &candidates {
            claimed.insert(c.digest.clone());
        }
        let limit = rule.count_number * DAY_MS;
        let meta = |d: &str| repo.meta(d);
        let chosen: Vec<_> = match rule.count_type.as_str() {
            "imageCountMoreThan" => candidates.iter().skip(rule.count_number as usize).collect(),
            "sinceImagePushed" => candidates.iter().filter(|i| now - i.pushed_at > limit).collect(),
            "sinceImagePulled" => {
                candidates.iter().filter(|i| now - i.last_pulled_at.unwrap_or(i.pushed_at) > limit).collect()
            }
            _ => candidates
                .iter()
                .filter(|i| meta(&i.digest).last_archived_at.is_some_and(|t| now - t > limit))
                .collect(),
        };
        for i in chosen {
            results.push(PreviewResult {
                digest: i.digest.clone(),
                tags: repo.content.tags_of(&i.digest),
                pushed_at: i.pushed_at,
                action: rule.action.to_ascii_uppercase(),
                target_storage_class: rule.target_storage_class.as_ref().map(|s| s.to_ascii_uppercase()),
                priority: rule.priority,
                storage_class: rule.storage_class.to_ascii_uppercase(),
            });
        }
    }
    results
}

/// Apply what the emulated clock has made due: finished scans, restored
/// images, and lifecycle policies. Returns the events that follow.
pub(crate) fn settle(st: &mut State, partition: &str, now: i64) -> Vec<EcrEvent> {
    let mut events = Vec::new();
    for reg in st.registries.values_mut() {
        let snapshot = reg.clone();
        for repo in reg.repositories.values_mut() {
            for (d, meta) in repo.meta.iter_mut() {
                if meta.status == "ACTIVATING" && meta.activates_at.is_some_and(|t| t <= now) {
                    meta.status = "ACTIVE".into();
                    meta.activates_at = None;
                    meta.last_activated_at = Some(now);
                }
                if let Some(scan) = meta.scan.as_mut().filter(|s| s.status == "IN_PROGRESS") {
                    scan.status = "COMPLETE".into();
                    scan.completed_at = Some(now);
                    let tags = repo.content.tags_of(d);
                    events.push(EcrEvent {
                        partition: partition.to_string(),
                        account: snapshot.account.clone(),
                        region: snapshot.region.clone(),
                        detail_type: "ECR Image Scan".into(),
                        resources: vec![repo.arn.clone()],
                        detail: serde_json::json!({
                            "scan-status": "COMPLETE",
                            "repository-name": repo.name,
                            "finding-severity-counts": {},
                            "image-digest": d,
                            "image-tags": tags,
                        }),
                        time: dt(now),
                    });
                }
            }
            let Some(text) = repo.lifecycle.clone() else { continue };
            let Ok(rules) = parse(&text) else { continue };
            let results = evaluate(&rules, repo, now);
            repo.lifecycle_evaluated_at = Some(now);
            for r in results {
                if r.action == "EXPIRE" {
                    repo.content.delete_image(&r.digest);
                    repo.meta.remove(&r.digest);
                    events.push(image_event(
                        partition,
                        &snapshot,
                        &repo.name,
                        "DELETE",
                        &r.digest,
                        r.tags.first().map(String::as_str),
                        now,
                    ));
                } else {
                    let meta = repo.meta.entry(r.digest.clone()).or_default();
                    meta.status = "ARCHIVED".into();
                    meta.last_archived_at = Some(now);
                }
            }
        }
    }
    events
}

impl Ecr {
    /// Apply clock-driven changes before a request sees the state.
    pub(crate) fn settle(&self, ctx: &RequestContext) {
        let events = {
            let mut st = self.lock();
            settle(&mut st, &ctx.partition, now_ms(ctx))
        };
        self.emit(ctx, events);
    }

    fn lifecycle_not_found(name: &str, account: &str) -> ServiceError {
        errors::lifecycle_policy_not_found(format!(
            "Lifecycle policy does not exist for the repository with name '{name}' in the registry with id '{account}'"
        ))
    }

    pub(crate) fn put_lifecycle_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutLifecyclePolicyRequest,
    ) -> Result<types::PutLifecyclePolicyResponse, ServiceError> {
        parse(&input.lifecycle_policy_text)?;
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:PutLifecyclePolicy",
            |_, reg, name| {
                reg.repositories.get_mut(name).expect("checked").lifecycle = Some(input.lifecycle_policy_text.clone());
                Ok(types::PutLifecyclePolicyResponse {
                    registry_id: Some(reg.account.clone()),
                    repository_name: Some(name.to_string()),
                    lifecycle_policy_text: Some(input.lifecycle_policy_text),
                })
            },
        )
    }

    pub(crate) fn get_lifecycle_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetLifecyclePolicyRequest,
    ) -> Result<types::GetLifecyclePolicyResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:GetLifecyclePolicy",
            |_, reg, name| {
                let repo = &reg.repositories[name];
                let text = repo.lifecycle.clone().ok_or_else(|| Self::lifecycle_not_found(name, &reg.account))?;
                Ok(types::GetLifecyclePolicyResponse {
                    registry_id: Some(reg.account.clone()),
                    repository_name: Some(name.to_string()),
                    lifecycle_policy_text: Some(text),
                    last_evaluated_at: Some(dt(repo.lifecycle_evaluated_at.unwrap_or(0))),
                })
            },
        )
    }

    pub(crate) fn delete_lifecycle_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLifecyclePolicyRequest,
    ) -> Result<types::DeleteLifecyclePolicyResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:DeleteLifecyclePolicy",
            |_, reg, name| {
                let account = reg.account.clone();
                let repo = reg.repositories.get_mut(name).expect("checked");
                let text = repo.lifecycle.take().ok_or_else(|| Self::lifecycle_not_found(name, &account))?;
                Ok(types::DeleteLifecyclePolicyResponse {
                    registry_id: Some(account),
                    repository_name: Some(name.to_string()),
                    lifecycle_policy_text: Some(text),
                    last_evaluated_at: Some(dt(repo.lifecycle_evaluated_at.take().unwrap_or(0))),
                })
            },
        )
    }

    pub(crate) fn start_lifecycle_policy_preview(
        &self,
        ctx: &RequestContext,
        input: types::StartLifecyclePolicyPreviewRequest,
    ) -> Result<types::StartLifecyclePolicyPreviewResponse, ServiceError> {
        if let Some(t) = &input.lifecycle_policy_text {
            parse(t)?;
        }
        let now = now_ms(ctx);
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:StartLifecyclePolicyPreview",
            |_, reg, name| {
                let account = reg.account.clone();
                let repo = reg.repositories.get_mut(name).expect("checked");
                let text = input
                    .lifecycle_policy_text
                    .clone()
                    .or_else(|| repo.lifecycle.clone())
                    .ok_or_else(|| Self::lifecycle_not_found(name, &account))?;
                let rules = parse(&text)?;
                let results = evaluate(&rules, repo, now);
                repo.preview = Some(Preview { text: text.clone(), started_at: now, results });
                Ok(types::StartLifecyclePolicyPreviewResponse {
                    registry_id: Some(account),
                    repository_name: Some(name.to_string()),
                    lifecycle_policy_text: Some(text),
                    status: Some("IN_PROGRESS".into()),
                })
            },
        )
    }

    pub(crate) fn get_lifecycle_policy_preview(
        &self,
        ctx: &RequestContext,
        input: types::GetLifecyclePolicyPreviewRequest,
    ) -> Result<types::GetLifecyclePolicyPreviewResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:GetLifecyclePolicyPreview",
            |_, reg, name| {
                let repo = &reg.repositories[name];
                let preview = repo.preview.clone().ok_or_else(|| {
                    errors::lifecycle_policy_preview_not_found(format!(
                        "Lifecycle policy preview does not exist for the repository with name '{name}' in the registry with id '{}'",
                        reg.account
                    ))
                })?;
                let tag_status = input.filter.as_ref().and_then(|f| f.tag_status.clone()).unwrap_or_else(|| "ANY".into());
                let wanted: Option<Vec<String>> = input.image_ids.as_ref().map(|ids| {
                    ids.iter().filter_map(|id| crate::images::find_image(reg, name, id).ok()).collect()
                });
                let all: Vec<types::LifecyclePolicyPreviewResult> = preview
                    .results
                    .iter()
                    .filter(|r| wanted.as_ref().is_none_or(|w| w.contains(&r.digest)))
                    .filter(|r| match tag_status.as_str() {
                        "TAGGED" => !r.tags.is_empty(),
                        "UNTAGGED" => r.tags.is_empty(),
                        _ => true,
                    })
                    .map(|r| types::LifecyclePolicyPreviewResult {
                        image_tags: Some(r.tags.clone()),
                        image_digest: Some(r.digest.clone()),
                        image_pushed_at: Some(dt(r.pushed_at)),
                        action: Some(types::LifecyclePolicyRuleAction {
                            r#type: Some(r.action.clone()),
                            target_storage_class: r.target_storage_class.clone(),
                        }),
                        applied_rule_priority: Some(r.priority),
                        storage_class: Some(r.storage_class.clone()),
                    })
                    .collect();
                let expiring = preview.results.iter().filter(|r| r.action == "EXPIRE").count() as i32;
                let transitioning = preview.results.iter().filter(|r| r.action == "TRANSITION").count() as i32;
                let (results, next_token) = crate::names::page(&all, input.next_token.as_deref(), input.max_results, 100)?;
                Ok(types::GetLifecyclePolicyPreviewResponse {
                    registry_id: Some(reg.account.clone()),
                    repository_name: Some(name.to_string()),
                    lifecycle_policy_text: Some(preview.text),
                    status: Some("COMPLETE".into()),
                    next_token,
                    preview_results: Some(results),
                    summary: Some(types::LifecyclePolicyPreviewSummary {
                        expiring_image_total_count: Some(expiring),
                        transitioning_image_total_counts: (transitioning > 0).then(|| {
                            vec![types::TransitioningImageTotalCount {
                                target_storage_class: Some("ARCHIVE".into()),
                                image_total_count: Some(transitioning),
                            }]
                        }),
                    }),
                })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_policies() {
        let ok = r#"{"rules":[{"rulePriority":1,"selection":{"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days","countNumber":14},"action":{"type":"expire"}}]}"#;
        assert_eq!(parse(ok).unwrap().len(), 1);
        let bad = r#"{"rules":[{"rulePriority":1,"selection":{"tagStatus":"tagged","countType":"imageCountMoreThan","countNumber":1},"action":{"type":"expire"}}]}"#;
        assert!(parse(bad).is_err());
        let any_first = r#"{"rules":[{"rulePriority":1,"selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":1},"action":{"type":"expire"}},{"rulePriority":2,"selection":{"tagStatus":"untagged","countType":"imageCountMoreThan","countNumber":1},"action":{"type":"expire"}}]}"#;
        assert!(parse(any_first).is_err());
    }
}
