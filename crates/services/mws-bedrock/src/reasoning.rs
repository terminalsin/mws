//! Automated Reasoning policies: definitions with numbered versions,
//! build workflows (which finish on the emulated clock and publish their
//! result assets), annotations, test cases and test runs.
//!
//! Build workflows don't extract rules from documents: an
//! `IMPORT_POLICY` workflow yields the definition it was given, the others
//! yield the policy's current definition. Test runs report each test
//! case's expected result as the finding, so they pass.

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::generated::types;
use crate::state::{kind, Record};
use crate::util::{
    arn, conflict, from_doc, in_use, not_found, page, random_id, request_tag_context, resource_tag_context, set,
    tag_map, to_doc, ts, validation,
};
use crate::Bedrock;

const BUILD_SECS: i64 = 2;

fn hash(v: &Value) -> String {
    hex::encode(sha2::Sha256::digest(serde_json::to_vec(v).unwrap_or_default()))
}

fn empty_definition() -> Value {
    json!({"version": "1.0", "types": [], "rules": [], "variables": []})
}

/// Split `arn[:version]` into the policy ARN and version.
fn split_version(policy_arn: &str) -> (&str, Option<&str>) {
    let tail = policy_arn.rsplit('/').next().unwrap_or("");
    match tail.split_once(':') {
        Some((_, v)) => (&policy_arn[..policy_arn.len() - v.len() - 1], Some(v)),
        None => (policy_arn, None),
    }
}

fn time(v: Option<&Value>) -> Option<DateTime<Utc>> {
    v.and_then(|v| serde_json::from_value(v.clone()).ok())
}

fn obj<'a>(doc: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    if !doc.get(key).is_some_and(Value::is_object) {
        doc.insert(key.to_string(), json!({}));
    }
    doc.get_mut(key).and_then(Value::as_object_mut).expect("object")
}

/// A build workflow's status at `now`.
fn workflow_status(w: &Value, now: DateTime<Utc>) -> String {
    let status = w.get("status").and_then(Value::as_str).unwrap_or("SCHEDULED");
    if matches!(status, "SCHEDULED" | "BUILDING") {
        if let Some(at) = time(w.get("created_at")) {
            if now >= at + Duration::seconds(BUILD_SECS) {
                return "COMPLETED".into();
            }
        }
    }
    status.to_string()
}

impl Bedrock {
    fn policy(&self, ctx: &RequestContext, policy_arn: &str, action: &str) -> Result<Record, ServiceError> {
        let (base, _) = split_version(policy_arn);
        let (r, tags) = self.scope(ctx, |s| {
            let r = s
                .find(kind::REASONING_POLICY, base)
                .cloned()
                .ok_or_else(|| not_found(format!("The Automated Reasoning policy {policy_arn} was not found.")))?;
            let tags = s.tags.get(&r.arn).cloned();
            Ok::<_, ServiceError>((r, tags))
        })?;
        ctx.authorize(action, policy_arn, resource_tag_context(tags.as_ref()))?;
        Ok(r)
    }

    fn update_policy<R>(
        &self,
        ctx: &RequestContext,
        r: &Record,
        f: impl FnOnce(&mut Record) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        self.scope(ctx, |s| {
            let rec = s.get_mut(kind::REASONING_POLICY, &r.id).ok_or_else(|| not_found("The policy was deleted."))?;
            f(rec)
        })
    }

    pub fn create_automated_reasoning_policy(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomatedReasoningPolicyRequest,
    ) -> Result<types::CreateAutomatedReasoningPolicyResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        let id = random_id(12);
        let policy_arn = arn(ctx, &format!("automated-reasoning-policy/{id}"));
        ctx.authorize("bedrock:CreateAutomatedReasoningPolicy", &policy_arn, request_tag_context(&tags))?;
        if self.scope(ctx, |s| s.kind(kind::REASONING_POLICY).any(|r| r.name == input.name)) {
            return Err(conflict(format!("An Automated Reasoning policy named {} already exists.", input.name)));
        }
        let now = ctx.received_at;
        let definition =
            input.policy_definition.as_ref().map(|d| Value::Object(to_doc(d))).unwrap_or_else(empty_definition);
        let definition_hash = hash(&definition);
        let mut doc = Map::new();
        if let Some(d) = &input.description {
            set(&mut doc, "description", d.clone());
        }
        if let Some(k) = &input.kms_key_id {
            set(&mut doc, "kms_key_arn", k.clone());
        }
        set(&mut doc, "definition", definition);
        set(&mut doc, "definition_hash", definition_hash.clone());
        self.scope(ctx, |s| {
            if !tags.is_empty() {
                s.tags.insert(policy_arn.clone(), tag_map(&tags));
            }
            s.insert(
                kind::REASONING_POLICY,
                Record {
                    id: id.clone(),
                    arn: policy_arn.clone(),
                    name: input.name.clone(),
                    created: now,
                    updated: now,
                    status: "ACTIVE".into(),
                    transition: None,
                    doc,
                },
            )
        });
        Ok(types::CreateAutomatedReasoningPolicyResponse {
            policy_arn,
            version: "DRAFT".into(),
            name: input.name,
            description: input.description,
            definition_hash: Some(definition_hash),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn get_automated_reasoning_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:GetAutomatedReasoningPolicy")?;
        let (_, version) = split_version(&input.policy_arn);
        let (definition_hash, created) = match version {
            Some(v) => {
                let ver = r
                    .doc
                    .get("versions")
                    .and_then(|vs| vs.get(v))
                    .ok_or_else(|| not_found(format!("Version {v} of the policy was not found.")))?;
                (
                    ver.get("definition_hash").and_then(Value::as_str).unwrap_or_default().to_string(),
                    time(ver.get("created_at")).unwrap_or(r.created),
                )
            }
            None => (r.str("definition_hash").unwrap_or_default().to_string(), r.created),
        };
        Ok(types::GetAutomatedReasoningPolicyResponse {
            policy_arn: input.policy_arn.clone(),
            name: r.name.clone(),
            version: version.unwrap_or("DRAFT").to_string(),
            policy_id: r.id.clone(),
            description: r.str("description").map(str::to_string),
            definition_hash,
            kms_key_arn: r.str("kms_key_arn").map(str::to_string),
            created_at: Some(created),
            updated_at: r.updated,
        })
    }

    pub fn list_automated_reasoning_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomatedReasoningPoliciesRequest,
    ) -> Result<types::ListAutomatedReasoningPoliciesResponse, ServiceError> {
        ctx.authorize("bedrock:ListAutomatedReasoningPolicies", "*", ConditionContext::new())?;
        let summaries: Vec<types::AutomatedReasoningPolicySummary> = self.scope(ctx, |s| {
            let mut out = Vec::new();
            let mut rs: Vec<&Record> = s.kind(kind::REASONING_POLICY).collect();
            rs.sort_by(|a, b| a.created.cmp(&b.created));
            for r in rs {
                let summary =
                    |arn: String, version: String, created: DateTime<Utc>| types::AutomatedReasoningPolicySummary {
                        policy_arn: arn,
                        name: r.name.clone(),
                        description: r.str("description").map(str::to_string),
                        version,
                        policy_id: r.id.clone(),
                        created_at: created,
                        updated_at: r.updated,
                    };
                match &input.policy_arn {
                    // With a policy ARN, list that policy's versions.
                    Some(p) if split_version(p).0 == r.arn => {
                        for (v, ver) in r.doc.get("versions").and_then(Value::as_object).into_iter().flatten() {
                            out.push(summary(
                                format!("{}:{v}", r.arn),
                                v.clone(),
                                time(ver.get("created_at")).unwrap_or(r.created),
                            ));
                        }
                    }
                    Some(_) => {}
                    None => out.push(summary(r.arn.clone(), "DRAFT".into(), r.created)),
                }
            }
            out
        });
        let (items, next_token) = page(summaries, Some(input.max_results), input.next_token.as_deref())?;
        Ok(types::ListAutomatedReasoningPoliciesResponse { automated_reasoning_policy_summaries: items, next_token })
    }

    pub fn update_automated_reasoning_policy(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutomatedReasoningPolicyRequest,
    ) -> Result<types::UpdateAutomatedReasoningPolicyResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:UpdateAutomatedReasoningPolicy")?;
        let now = ctx.received_at;
        let definition = Value::Object(to_doc(&input.policy_definition));
        let h = hash(&definition);
        let name = self.update_policy(ctx, &r, |rec| {
            set(&mut rec.doc, "definition", definition);
            set(&mut rec.doc, "definition_hash", h.clone());
            if let Some(n) = &input.name {
                rec.name = n.clone();
            }
            if let Some(d) = &input.description {
                set(&mut rec.doc, "description", d.clone());
            }
            rec.updated = now;
            Ok(rec.name.clone())
        })?;
        Ok(types::UpdateAutomatedReasoningPolicyResponse {
            policy_arn: r.arn,
            name,
            definition_hash: h,
            updated_at: now,
        })
    }

    pub fn delete_automated_reasoning_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutomatedReasoningPolicyRequest,
    ) -> Result<types::DeleteAutomatedReasoningPolicyResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:DeleteAutomatedReasoningPolicy")?;
        self.scope(ctx, |s| {
            let used = s.guardrails.values().any(|g| {
                std::iter::once(&g.draft).chain(g.versions.values()).any(|v| {
                    v.doc
                        .get("automated_reasoning_policy")
                        .and_then(|p| p.get("policies"))
                        .and_then(Value::as_array)
                        .is_some_and(|ps| ps.iter().any(|p| p.as_str().is_some_and(|p| split_version(p).0 == r.arn)))
                })
            });
            if used && !input.force {
                return Err(in_use("The policy is used by a guardrail. Set force to delete it anyway."));
            }
            s.remove(kind::REASONING_POLICY, &r.id);
            Ok(types::DeleteAutomatedReasoningPolicyResponse {})
        })
    }

    pub fn create_automated_reasoning_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomatedReasoningPolicyVersionRequest,
    ) -> Result<types::CreateAutomatedReasoningPolicyVersionResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:CreateAutomatedReasoningPolicyVersion")?;
        let now = ctx.received_at;
        let (version, h) = self.update_policy(ctx, &r, |rec| {
            let current = rec.str("definition_hash").unwrap_or_default().to_string();
            if current != input.last_updated_definition_hash {
                return Err(conflict(
                    "The policy definition changed since the hash you provided. Get the policy and retry.",
                ));
            }
            let definition = rec.doc.get("definition").cloned().unwrap_or_else(empty_definition);
            let versions = obj(&mut rec.doc, "versions");
            let n = (versions.len() + 1).to_string();
            versions.insert(
                n.clone(),
                json!({"definition": definition, "definition_hash": current, "created_at": ts(now)}),
            );
            Ok((n, current))
        })?;
        Ok(types::CreateAutomatedReasoningPolicyVersionResponse {
            policy_arn: format!("{}:{version}", r.arn),
            version,
            name: r.name.clone(),
            description: r.str("description").map(str::to_string),
            definition_hash: h,
            created_at: now,
        })
    }

    pub fn export_automated_reasoning_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::ExportAutomatedReasoningPolicyVersionRequest,
    ) -> Result<types::ExportAutomatedReasoningPolicyVersionResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:ExportAutomatedReasoningPolicyVersion")?;
        let definition = match split_version(&input.policy_arn).1 {
            Some(v) => r
                .doc
                .get("versions")
                .and_then(|vs| vs.get(v))
                .and_then(|v| v.get("definition"))
                .cloned()
                .ok_or_else(|| not_found(format!("Version {v} of the policy was not found.")))?,
            None => r.doc.get("definition").cloned().unwrap_or_else(empty_definition),
        };
        Ok(types::ExportAutomatedReasoningPolicyVersionResponse {
            policy_definition: serde_json::from_value(definition).unwrap_or_default(),
        })
    }

    // Build workflows -------------------------------------------------------

    pub fn start_automated_reasoning_policy_build_workflow(
        &self,
        ctx: &RequestContext,
        input: types::StartAutomatedReasoningPolicyBuildWorkflowRequest,
    ) -> Result<types::StartAutomatedReasoningPolicyBuildWorkflowResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:StartAutomatedReasoningPolicyBuildWorkflow")?;
        let now = ctx.received_at;
        let id = random_id(12);
        let source = Value::Object(to_doc(&input.source_content));
        self.update_policy(ctx, &r, |rec| {
            let running = rec
                .doc
                .get("workflows")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .any(|(_, w)| matches!(workflow_status(w, now).as_str(), "SCHEDULED" | "BUILDING"));
            if running {
                return Err(conflict("A build workflow is already running for this policy."));
            }
            let doc_name = source.pointer("/workflow_content/Documents/0/document_name").cloned();
            let content_type = source.pointer("/workflow_content/Documents/0/document_content_type").cloned();
            let mut w = json!({
                "build_workflow_type": input.build_workflow_type,
                "status": "SCHEDULED",
                "created_at": ts(now),
                "updated_at": ts(now),
                "source": source,
                "annotations": [],
            });
            if let Some(n) = doc_name {
                w["document_name"] = n;
            }
            if let Some(c) = content_type {
                w["document_content_type"] = c;
            }
            obj(&mut rec.doc, "workflows").insert(id.clone(), w);
            Ok(())
        })?;
        Ok(types::StartAutomatedReasoningPolicyBuildWorkflowResponse { policy_arn: r.arn, build_workflow_id: id })
    }

    fn workflow(&self, r: &Record, id: &str, now: DateTime<Utc>) -> Result<Value, ServiceError> {
        let mut w = r
            .doc
            .get("workflows")
            .and_then(|ws| ws.get(id))
            .cloned()
            .ok_or_else(|| not_found(format!("The build workflow {id} was not found.")))?;
        let status = workflow_status(&w, now);
        if status == "COMPLETED" && w["status"] != "COMPLETED" {
            if let Some(at) = time(w.get("created_at")) {
                w["updated_at"] = ts(at + Duration::seconds(BUILD_SECS));
            }
        }
        w["status"] = json!(status);
        Ok(w)
    }

    pub fn get_automated_reasoning_policy_build_workflow(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyBuildWorkflowRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyBuildWorkflowResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:GetAutomatedReasoningPolicyBuildWorkflow")?;
        let mut w = self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        w["policy_arn"] = json!(r.arn);
        w["build_workflow_id"] = json!(input.build_workflow_id);
        Ok(from_doc(w.as_object().expect("object")))
    }

    pub fn list_automated_reasoning_policy_build_workflows(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomatedReasoningPolicyBuildWorkflowsRequest,
    ) -> Result<types::ListAutomatedReasoningPolicyBuildWorkflowsResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:ListAutomatedReasoningPolicyBuildWorkflows")?;
        let mut items = Vec::new();
        for id in r.doc.get("workflows").and_then(Value::as_object).into_iter().flatten().map(|(k, _)| k) {
            let mut w = self.workflow(&r, id, ctx.received_at)?;
            w["policy_arn"] = json!(r.arn);
            w["build_workflow_id"] = json!(id);
            items.push(from_doc::<types::AutomatedReasoningPolicyBuildWorkflowSummary>(w.as_object().expect("object")));
        }
        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let (items, next_token) = page(items, Some(input.max_results), input.next_token.as_deref())?;
        Ok(types::ListAutomatedReasoningPolicyBuildWorkflowsResponse {
            automated_reasoning_policy_build_workflow_summaries: items,
            next_token,
        })
    }

    pub fn cancel_automated_reasoning_policy_build_workflow(
        &self,
        ctx: &RequestContext,
        input: types::CancelAutomatedReasoningPolicyBuildWorkflowRequest,
    ) -> Result<types::CancelAutomatedReasoningPolicyBuildWorkflowResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:CancelAutomatedReasoningPolicyBuildWorkflow")?;
        let now = ctx.received_at;
        let w = self.workflow(&r, &input.build_workflow_id, now)?;
        if !matches!(w["status"].as_str(), Some("SCHEDULED" | "BUILDING")) {
            return Err(validation("The build workflow has finished and can't be cancelled."));
        }
        self.update_policy(ctx, &r, |rec| {
            let ws = obj(&mut rec.doc, "workflows");
            if let Some(w) = ws.get_mut(&input.build_workflow_id) {
                w["status"] = json!("CANCELLED");
                w["updated_at"] = ts(now);
            }
            Ok(())
        })?;
        Ok(types::CancelAutomatedReasoningPolicyBuildWorkflowResponse {})
    }

    pub fn delete_automated_reasoning_policy_build_workflow(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutomatedReasoningPolicyBuildWorkflowRequest,
    ) -> Result<types::DeleteAutomatedReasoningPolicyBuildWorkflowResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:DeleteAutomatedReasoningPolicyBuildWorkflow")?;
        let w = self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        if time(w.get("updated_at")) != Some(input.last_updated_at) {
            return Err(conflict("The build workflow changed since lastUpdatedAt. Get it and retry."));
        }
        self.update_policy(ctx, &r, |rec| {
            obj(&mut rec.doc, "workflows").remove(&input.build_workflow_id);
            Ok(())
        })?;
        Ok(types::DeleteAutomatedReasoningPolicyBuildWorkflowResponse {})
    }

    pub fn get_automated_reasoning_policy_build_workflow_result_assets(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyBuildWorkflowResultAssetsRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyBuildWorkflowResultAssetsResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:GetAutomatedReasoningPolicyBuildWorkflowResultAssets")?;
        let w = self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        if w["status"] != "COMPLETED" {
            return Err(validation("The build workflow hasn't completed, so it has no result assets yet."));
        }
        let definition = if w["build_workflow_type"] == "IMPORT_POLICY" {
            w.pointer("/source/policy_definition").cloned()
        } else {
            None
        }
        .or_else(|| r.doc.get("definition").cloned())
        .unwrap_or_else(empty_definition);
        let count = |k: &str| definition.get(k).and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
        let asset = match input.asset_type.as_str() {
            "POLICY_DEFINITION" => json!({ "PolicyDefinition": definition }),
            "BUILD_LOG" => json!({ "BuildLog": { "entries": [] } }),
            "QUALITY_REPORT" => json!({ "QualityReport": {
                "type_count": count("types"),
                "variable_count": count("variables"),
                "rule_count": count("rules"),
                "unused_types": [], "unused_type_values": [], "unused_variables": [],
                "conflicting_rules": [], "disjoint_rule_sets": [],
            }}),
            "GENERATED_TEST_CASES" => json!({ "GeneratedTestCases": { "generated_test_cases": [] } }),
            "POLICY_SCENARIOS" => json!({ "PolicyScenarios": { "policy_scenarios": [] } }),
            "ASSET_MANIFEST" => json!({ "AssetManifest": { "entries": [] } }),
            other => return Err(validation(format!("The asset type {other} is not available for this workflow."))),
        };
        Ok(types::GetAutomatedReasoningPolicyBuildWorkflowResultAssetsResponse {
            policy_arn: r.arn,
            build_workflow_id: input.build_workflow_id,
            build_workflow_assets: serde_json::from_value(asset).ok(),
        })
    }

    pub fn get_automated_reasoning_policy_next_scenario(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyNextScenarioRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyNextScenarioResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:GetAutomatedReasoningPolicyNextScenario")?;
        self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        let rule = r
            .doc
            .get("definition")
            .and_then(|d| d.get("rules"))
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .cloned();
        let scenario = rule.map(|rule| types::AutomatedReasoningPolicyScenario {
            expression: rule.get("expression").and_then(Value::as_str).unwrap_or_default().to_string(),
            alternate_expression: rule
                .get("alternate_expression")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            expected_result: "SATISFIABLE".into(),
            rule_ids: vec![rule.get("id").and_then(Value::as_str).unwrap_or_default().to_string()],
        });
        Ok(types::GetAutomatedReasoningPolicyNextScenarioResponse { policy_arn: r.arn, scenario })
    }

    pub fn get_automated_reasoning_policy_annotations(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyAnnotationsRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyAnnotationsResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:GetAutomatedReasoningPolicyAnnotations")?;
        let w = self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        let annotations = w.get("annotations").cloned().unwrap_or_else(|| json!([]));
        Ok(types::GetAutomatedReasoningPolicyAnnotationsResponse {
            policy_arn: r.arn.clone(),
            name: r.name.clone(),
            build_workflow_id: input.build_workflow_id,
            annotation_set_hash: hash(&annotations),
            annotations: serde_json::from_value(annotations).unwrap_or_default(),
            updated_at: time(w.get("updated_at")).unwrap_or(r.updated),
        })
    }

    pub fn update_automated_reasoning_policy_annotations(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutomatedReasoningPolicyAnnotationsRequest,
    ) -> Result<types::UpdateAutomatedReasoningPolicyAnnotationsResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:UpdateAutomatedReasoningPolicyAnnotations")?;
        let w = self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        let current = w.get("annotations").cloned().unwrap_or_else(|| json!([]));
        if hash(&current) != input.last_updated_annotation_set_hash {
            return Err(conflict("The annotations changed since the hash you provided. Get them and retry."));
        }
        let annotations = crate::util::strip_nulls(serde_json::to_value(&input.annotations).unwrap_or_default());
        let h = hash(&annotations);
        let now = ctx.received_at;
        self.update_policy(ctx, &r, |rec| {
            if let Some(w) = obj(&mut rec.doc, "workflows").get_mut(&input.build_workflow_id) {
                w["annotations"] = annotations;
                w["updated_at"] = ts(now);
            }
            Ok(())
        })?;
        Ok(types::UpdateAutomatedReasoningPolicyAnnotationsResponse {
            policy_arn: r.arn,
            build_workflow_id: input.build_workflow_id,
            annotation_set_hash: h,
            updated_at: now,
        })
    }

    // Test cases ----------------------------------------------------------------

    pub fn create_automated_reasoning_policy_test_case(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomatedReasoningPolicyTestCaseRequest,
    ) -> Result<types::CreateAutomatedReasoningPolicyTestCaseResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:CreateAutomatedReasoningPolicyTestCase")?;
        let now = ctx.received_at;
        let id = random_id(12);
        let mut tc = to_doc(&input);
        for k in ["policy_arn", "client_request_token"] {
            tc.remove(k);
        }
        set(&mut tc, "test_case_id", id.clone());
        set(&mut tc, "created_at", ts(now));
        set(&mut tc, "updated_at", ts(now));
        self.update_policy(ctx, &r, |rec| {
            obj(&mut rec.doc, "test_cases").insert(id.clone(), Value::Object(tc));
            Ok(())
        })?;
        Ok(types::CreateAutomatedReasoningPolicyTestCaseResponse { policy_arn: r.arn, test_case_id: id })
    }

    fn test_case(&self, r: &Record, id: &str) -> Result<Value, ServiceError> {
        r.doc
            .get("test_cases")
            .and_then(|t| t.get(id))
            .cloned()
            .ok_or_else(|| not_found(format!("The test case {id} was not found.")))
    }

    pub fn get_automated_reasoning_policy_test_case(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyTestCaseRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyTestCaseResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:GetAutomatedReasoningPolicyTestCase")?;
        let tc = self.test_case(&r, &input.test_case_id)?;
        Ok(types::GetAutomatedReasoningPolicyTestCaseResponse {
            policy_arn: r.arn,
            test_case: from_doc(tc.as_object().expect("object")),
        })
    }

    pub fn list_automated_reasoning_policy_test_cases(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomatedReasoningPolicyTestCasesRequest,
    ) -> Result<types::ListAutomatedReasoningPolicyTestCasesResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:ListAutomatedReasoningPolicyTestCases")?;
        let mut items: Vec<types::AutomatedReasoningPolicyTestCase> = r
            .doc
            .get("test_cases")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(_, v)| from_doc(v.as_object().expect("object")))
            .collect();
        items.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        let (test_cases, next_token) = page(items, Some(input.max_results), input.next_token.as_deref())?;
        Ok(types::ListAutomatedReasoningPolicyTestCasesResponse { test_cases, next_token })
    }

    pub fn update_automated_reasoning_policy_test_case(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutomatedReasoningPolicyTestCaseRequest,
    ) -> Result<types::UpdateAutomatedReasoningPolicyTestCaseResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:UpdateAutomatedReasoningPolicyTestCase")?;
        let tc = self.test_case(&r, &input.test_case_id)?;
        if time(tc.get("updated_at")) != Some(input.last_updated_at) {
            return Err(conflict("The test case changed since lastUpdatedAt. Get it and retry."));
        }
        let now = ctx.received_at;
        let mut new = to_doc(&input);
        for k in ["policy_arn", "client_request_token", "last_updated_at"] {
            new.remove(k);
        }
        set(&mut new, "created_at", tc.get("created_at").cloned().unwrap_or(Value::Null));
        set(&mut new, "updated_at", ts(now));
        self.update_policy(ctx, &r, |rec| {
            obj(&mut rec.doc, "test_cases").insert(input.test_case_id.clone(), Value::Object(new));
            Ok(())
        })?;
        Ok(types::UpdateAutomatedReasoningPolicyTestCaseResponse {
            policy_arn: r.arn,
            test_case_id: input.test_case_id,
        })
    }

    pub fn delete_automated_reasoning_policy_test_case(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutomatedReasoningPolicyTestCaseRequest,
    ) -> Result<types::DeleteAutomatedReasoningPolicyTestCaseResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:DeleteAutomatedReasoningPolicyTestCase")?;
        let tc = self.test_case(&r, &input.test_case_id)?;
        if time(tc.get("updated_at")) != Some(input.last_updated_at) {
            return Err(conflict("The test case changed since lastUpdatedAt. Get it and retry."));
        }
        self.update_policy(ctx, &r, |rec| {
            obj(&mut rec.doc, "test_cases").remove(&input.test_case_id);
            Ok(())
        })?;
        Ok(types::DeleteAutomatedReasoningPolicyTestCaseResponse {})
    }

    pub fn start_automated_reasoning_policy_test_workflow(
        &self,
        ctx: &RequestContext,
        input: types::StartAutomatedReasoningPolicyTestWorkflowRequest,
    ) -> Result<types::StartAutomatedReasoningPolicyTestWorkflowResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:StartAutomatedReasoningPolicyTestWorkflow")?;
        let w = self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        if w["status"] != "COMPLETED" {
            return Err(validation("Tests run against a completed build workflow."));
        }
        let now = ctx.received_at;
        let all: Vec<String> =
            r.doc.get("test_cases").and_then(Value::as_object).into_iter().flatten().map(|(k, _)| k.clone()).collect();
        let ids = input.test_case_ids.clone().unwrap_or(all);
        let mut results = Map::new();
        for id in &ids {
            let tc = self.test_case(&r, id)?;
            let expected = tc.get("expected_aggregated_findings_result").cloned().unwrap_or(json!("VALID"));
            results.insert(
                id.clone(),
                json!({
                    "test_case": tc,
                    "policy_arn": r.arn,
                    "test_run_status": "COMPLETED",
                    "test_findings": [],
                    "test_run_result": "PASSED",
                    "aggregated_test_findings_result": expected,
                    "updated_at": ts(now),
                }),
            );
        }
        self.update_policy(ctx, &r, |rec| {
            if let Some(w) = obj(&mut rec.doc, "workflows").get_mut(&input.build_workflow_id) {
                let existing = w.get_mut("test_results").and_then(Value::as_object_mut);
                match existing {
                    Some(e) => e.extend(results),
                    None => w["test_results"] = Value::Object(results),
                }
            }
            Ok(())
        })?;
        Ok(types::StartAutomatedReasoningPolicyTestWorkflowResponse { policy_arn: r.arn })
    }

    pub fn get_automated_reasoning_policy_test_result(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyTestResultRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyTestResultResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:GetAutomatedReasoningPolicyTestResult")?;
        let w = self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        let res = w
            .get("test_results")
            .and_then(|t| t.get(&input.test_case_id))
            .cloned()
            .ok_or_else(|| not_found(format!("No test result exists for test case {}.", input.test_case_id)))?;
        Ok(types::GetAutomatedReasoningPolicyTestResultResponse {
            test_result: from_doc(res.as_object().expect("object")),
        })
    }

    pub fn list_automated_reasoning_policy_test_results(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomatedReasoningPolicyTestResultsRequest,
    ) -> Result<types::ListAutomatedReasoningPolicyTestResultsResponse, ServiceError> {
        let r = self.policy(ctx, &input.policy_arn, "bedrock:ListAutomatedReasoningPolicyTestResults")?;
        let w = self.workflow(&r, &input.build_workflow_id, ctx.received_at)?;
        let items: Vec<types::AutomatedReasoningPolicyTestResult> = w
            .get("test_results")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(_, v)| from_doc(v.as_object().expect("object")))
            .collect();
        let (test_results, next_token) = page(items, Some(input.max_results), input.next_token.as_deref())?;
        Ok(types::ListAutomatedReasoningPolicyTestResultsResponse { test_results, next_token })
    }
}
