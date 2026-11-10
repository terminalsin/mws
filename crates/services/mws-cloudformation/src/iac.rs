//! The IaC generator: resource scans of what exists in an account,
//! templates generated from scanned resources, and IMPORT change sets
//! that bring existing resources under a stack.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::generated::{errors, types};
use crate::ops::{page, validation};
use crate::providers::scan::{self, Scanned, SCANNABLE};
use crate::providers::Cx;
use crate::CloudFormation;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceScan {
    pub id: String,
    pub account: String,
    pub region: String,
    pub status: String,
    pub reason: Option<String>,
    pub start: DateTime<Utc>,
    pub end: Option<DateTime<Utc>>,
    pub filters: Option<Vec<types::ScanFilter>>,
    pub types: Vec<String>,
    pub resources: Vec<ScanItem>,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanItem {
    pub resource_type: String,
    pub identifier: BTreeMap<String, String>,
    pub physical_id: String,
    pub properties: Map<String, Value>,
    pub managed: bool,
    pub tags: Vec<(String, String)>,
    /// String attribute values (ARNs, URLs) other resources may refer to.
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratedTemplate {
    pub id: String,
    pub name: String,
    pub account: String,
    pub region: String,
    pub status: String,
    pub reason: Option<String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub stack_id: Option<String>,
    pub config: Option<types::TemplateConfiguration>,
    pub resources: Vec<GenResource>,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GenResource {
    pub resource_type: String,
    pub logical_id: String,
    pub identifier: BTreeMap<String, String>,
    pub status: String,
    pub reason: Option<String>,
    pub write_only: Vec<String>,
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn ident_map(p: &Map<String, Value>) -> BTreeMap<String, String> {
    p.iter().map(|(k, v)| (k.clone(), scalar(v))).collect()
}

fn scan_not_found(id: &str) -> ServiceError {
    errors::resource_scan_not_found(format!("Resource scan {id} not found."))
}

fn template_not_found(name: &str) -> ServiceError {
    errors::generated_template_not_found(format!("Generated template {name} not found."))
}

/// A logical id AWS's generator would pick: the type's name and the
/// identifier's alphanumerics.
fn logical_id_for(ty: &str, identifier: &BTreeMap<String, String>, taken: &BTreeSet<String>) -> String {
    let base: String = ty.trim_start_matches("AWS::").replace("::", "");
    let id: String = identifier
        .values()
        .flat_map(|v| v.rsplit(['/', ':']).next().unwrap_or(v).chars())
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let mut first: String = id.chars().take(1).flat_map(|c| c.to_uppercase()).collect();
    first.push_str(&id.chars().skip(1).collect::<String>());
    let mut name: String = format!("{base}{first}").chars().take(240).collect();
    if taken.contains(&name) {
        let mut n = 2;
        while taken.contains(&format!("{name}{n}")) {
            n += 1;
        }
        name = format!("{name}{n}");
    }
    name
}

impl CloudFormation {
    fn scan_cx<'a>(&'a self, ctx: &'a RequestContext) -> Cx<'a> {
        Cx {
            cfn: self,
            ctx,
            stack_name: "",
            stack_id: "",
            logical_id: "",
            stack_tags: &[],
            offset: chrono::Duration::zero(),
            deadline: None,
        }
    }

    /// Physical ids of a type that stacks in the account manage.
    fn managed_ids(&self, account: &str, region: &str) -> BTreeSet<(String, String)> {
        let st = self.state();
        st.stacks
            .values()
            .filter(|s| s.account == account && s.region == region && !s.is_deleted())
            .flat_map(|s| s.resources.iter().filter(|r| r.exists()))
            .filter_map(|r| Some((r.resource_type.clone(), r.physical_id.clone()?)))
            .collect()
    }

    /// The existing resource of `ty` an identifier names.
    pub(crate) async fn find_existing(
        &self,
        ctx: &RequestContext,
        ty: &str,
        identifier: &BTreeMap<String, String>,
    ) -> Result<Option<Scanned>, String> {
        let deploy = self.via(ctx);
        let cx = self.scan_cx(&deploy);
        let Some(found) = scan::list(&cx, ty).await else {
            return Err(format!("Resource type {ty} does not support import"));
        };
        let found = found.map_err(|e| e.message)?;
        Ok(found.into_iter().find(|s| {
            identifier.iter().all(|(k, v)| {
                s.identifier.get(k).map(scalar).as_deref() == Some(v.as_str())
                    || s.properties.get(k).map(scalar).as_deref() == Some(v.as_str())
            })
        }))
    }

    pub(crate) async fn start_resource_scan_op(
        &self,
        ctx: &RequestContext,
        input: types::StartResourceScanInput,
    ) -> Result<types::StartResourceScanOutput, ServiceError> {
        ctx.authorize("cloudformation:StartResourceScan", "*", Default::default())?;
        let (busy, same) = {
            let st = self.state();
            let mine = st.scans.values().filter(|s| s.account == ctx.caller.account_id && s.region == ctx.region);
            let mine: Vec<&ResourceScan> = mine.collect();
            (
                mine.iter().any(|s| s.status == "IN_PROGRESS"),
                input
                    .client_request_token
                    .as_ref()
                    .and_then(|t| mine.iter().find(|s| s.token.as_ref() == Some(t)).map(|s| s.id.clone())),
            )
        };
        if let Some(id) = same {
            return Ok(types::StartResourceScanOutput { resource_scan_id: Some(id) });
        }
        if busy {
            return Err(errors::resource_scan_in_progress("A resource scan is already in progress for this account."));
        }
        let mut wanted: Vec<String> = Vec::new();
        for f in input.scan_filters.iter().flatten() {
            for t in f.types.iter().flatten() {
                let matching: Vec<&str> = SCANNABLE
                    .iter()
                    .copied()
                    .filter(|s| match t.strip_suffix("::*") {
                        Some(prefix) => s.starts_with(&format!("{prefix}::")),
                        None => s == t,
                    })
                    .collect();
                if matching.is_empty() && !self.has_type(ctx, t) && !t.ends_with("::*") {
                    return Err(validation(format!("Unsupported resource type {t} in scan filters")));
                }
                wanted.extend(matching.into_iter().map(str::to_string));
            }
        }
        let partial = !wanted.is_empty();
        if !partial {
            wanted = SCANNABLE.iter().map(|s| s.to_string()).collect();
        }
        wanted.sort();
        wanted.dedup();
        let id = format!(
            "arn:{}:cloudformation:{}:{}:resourceScan/{}",
            ctx.partition,
            ctx.region,
            ctx.caller.account_id,
            uuid::Uuid::new_v4()
        );
        self.state().scans.insert(
            id.clone(),
            ResourceScan {
                id: id.clone(),
                account: ctx.caller.account_id.clone(),
                region: ctx.region.clone(),
                status: "IN_PROGRESS".into(),
                start: ctx.received_at,
                filters: input.scan_filters.clone(),
                types: wanted.clone(),
                token: input.client_request_token.clone(),
                ..Default::default()
            },
        );
        let me = self.clone();
        let ctx = ctx.clone();
        let scan_id = id.clone();
        tokio::spawn(async move {
            let deploy = me.via(&ctx);
            let managed = me.managed_ids(&ctx.caller.account_id, &ctx.region);
            let mut items = Vec::new();
            let mut failure = None;
            for ty in &wanted {
                let cx = me.scan_cx(&deploy);
                match scan::list(&cx, ty).await {
                    Some(Ok(found)) => items.extend(found.into_iter().map(|s| ScanItem {
                        resource_type: ty.clone(),
                        identifier: ident_map(&s.identifier),
                        managed: managed.contains(&(ty.clone(), s.physical_id.clone())),
                        physical_id: s.physical_id,
                        properties: s.properties,
                        tags: s.tags,
                        references: s.attributes.values().filter_map(|v| v.as_str().map(str::to_string)).collect(),
                    })),
                    Some(Err(e)) if !e.code.starts_with("AccessDenied") => failure = Some(e.message),
                    _ => {}
                }
            }
            if let Some(scan) = me.state().scans.get_mut(&scan_id) {
                scan.resources = items;
                scan.end = Some(Utc::now());
                match failure {
                    Some(reason) => {
                        scan.status = "FAILED".into();
                        scan.reason = Some(reason);
                    }
                    None => scan.status = "COMPLETE".into(),
                }
            }
        });
        Ok(types::StartResourceScanOutput { resource_scan_id: Some(id) })
    }

    fn find_scan(&self, ctx: &RequestContext, id: &str) -> Result<ResourceScan, ServiceError> {
        self.state()
            .scans
            .get(id)
            .filter(|s| s.account == ctx.caller.account_id && s.region == ctx.region)
            .cloned()
            .ok_or_else(|| scan_not_found(id))
    }

    pub(crate) fn describe_resource_scan_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeResourceScanInput,
    ) -> Result<types::DescribeResourceScanOutput, ServiceError> {
        ctx.authorize("cloudformation:DescribeResourceScan", &input.resource_scan_id, Default::default())?;
        let s = self.find_scan(ctx, &input.resource_scan_id)?;
        let done = s.status != "IN_PROGRESS";
        let mut types: Vec<String> = s.resources.iter().map(|r| r.resource_type.clone()).collect();
        types.sort();
        types.dedup();
        Ok(types::DescribeResourceScanOutput {
            resource_scan_id: Some(s.id.clone()),
            status: Some(s.status.clone()),
            status_reason: s.reason.clone(),
            start_time: Some(s.start),
            end_time: s.end,
            percentage_completed: Some(if done { 100.0 } else { 0.0 }),
            resource_types: Some(types),
            resources_scanned: Some(s.resources.len() as i32),
            resources_read: Some(s.resources.len() as i32),
            scan_filters: s.filters.clone(),
        })
    }

    pub(crate) fn list_resource_scans_op(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceScansInput,
    ) -> Result<types::ListResourceScansOutput, ServiceError> {
        ctx.authorize("cloudformation:ListResourceScans", "*", Default::default())?;
        let mut scans: Vec<ResourceScan> = self
            .state()
            .scans
            .values()
            .filter(|s| s.account == ctx.caller.account_id && s.region == ctx.region)
            .cloned()
            .collect();
        scans.sort_by_key(|s| std::cmp::Reverse(s.start));
        let all: Vec<types::ResourceScanSummary> = scans
            .iter()
            .map(|s| types::ResourceScanSummary {
                resource_scan_id: Some(s.id.clone()),
                status: Some(s.status.clone()),
                status_reason: s.reason.clone(),
                start_time: Some(s.start),
                end_time: s.end,
                percentage_completed: Some(if s.status == "IN_PROGRESS" { 0.0 } else { 100.0 }),
                scan_type: Some(
                    if s.filters.as_ref().is_some_and(|f| !f.is_empty()) { "PARTIAL" } else { "FULL" }.into(),
                ),
            })
            .filter(|s| input.scan_type_filter.as_ref().is_none_or(|f| s.scan_type.as_ref() == Some(f)))
            .collect();
        let (items, next_token) = page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(20) as usize)?;
        Ok(types::ListResourceScansOutput { resource_scan_summaries: Some(items), next_token })
    }

    fn complete_scan(&self, ctx: &RequestContext, id: &str) -> Result<ResourceScan, ServiceError> {
        let s = self.find_scan(ctx, id)?;
        if s.status == "IN_PROGRESS" {
            return Err(errors::resource_scan_in_progress(format!("Resource scan {id} is still in progress.")));
        }
        if s.status == "FAILED" {
            return Err(validation(format!("Resource scan {id} failed: {}", s.reason.unwrap_or_default())));
        }
        Ok(s)
    }

    pub(crate) fn list_resource_scan_resources_op(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceScanResourcesInput,
    ) -> Result<types::ListResourceScanResourcesOutput, ServiceError> {
        ctx.authorize("cloudformation:ListResourceScanResources", &input.resource_scan_id, Default::default())?;
        let s = self.complete_scan(ctx, &input.resource_scan_id)?;
        let all: Vec<types::ScannedResource> = s
            .resources
            .iter()
            .filter(|r| {
                input.resource_type_prefix.as_ref().is_none_or(|p| r.resource_type.starts_with(p.trim_end_matches('*')))
            })
            .filter(|r| {
                input.resource_identifier.as_ref().is_none_or(|i| r.identifier.values().any(|v| v.contains(i.as_str())))
            })
            .filter(|r| input.tag_key.as_ref().is_none_or(|k| r.tags.iter().any(|(tk, _)| tk == k)))
            .filter(|r| input.tag_value.as_ref().is_none_or(|v| r.tags.iter().any(|(_, tv)| tv == v)))
            .map(|r| types::ScannedResource {
                resource_type: Some(r.resource_type.clone()),
                resource_identifier: Some(r.identifier.clone()),
                managed_by_stack: Some(r.managed),
            })
            .collect();
        let (resources, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListResourceScanResourcesOutput { resources: Some(resources), next_token })
    }

    pub(crate) fn list_resource_scan_related_resources_op(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceScanRelatedResourcesInput,
    ) -> Result<types::ListResourceScanRelatedResourcesOutput, ServiceError> {
        ctx.authorize("cloudformation:ListResourceScanRelatedResources", &input.resource_scan_id, Default::default())?;
        let s = self.complete_scan(ctx, &input.resource_scan_id)?;
        if input.resources.is_empty() || input.resources.len() > 100 {
            return Err(validation("Resources must name between 1 and 100 scanned resources"));
        }
        let mut chosen: Vec<&ScanItem> = Vec::new();
        for want in &input.resources {
            let found = s
                .resources
                .iter()
                .find(|r| r.resource_type == want.resource_type && r.identifier == want.resource_identifier);
            match found {
                Some(r) => chosen.push(r),
                None => {
                    return Err(validation(format!(
                        "Resource of type {} with identifier {:?} was not found in the scan",
                        want.resource_type, want.resource_identifier
                    )))
                }
            }
        }
        // Related: either one's properties mention the other's identifier.
        let mentions = |a: &ScanItem, b: &ScanItem| {
            let text = Value::Object(a.properties.clone()).to_string();
            b.identifier
                .values()
                .chain(std::iter::once(&b.physical_id))
                .chain(&b.references)
                .any(|v| v.len() > 3 && text.contains(v.as_str()))
        };
        let mut related: Vec<&ScanItem> = Vec::new();
        for r in &s.resources {
            if chosen.iter().any(|c| std::ptr::eq(*c, r)) || related.iter().any(|x| std::ptr::eq(*x, r)) {
                continue;
            }
            if chosen.iter().any(|c| mentions(c, r) || mentions(r, c)) {
                related.push(r);
            }
        }
        let all: Vec<types::ScannedResource> = related
            .iter()
            .map(|r| types::ScannedResource {
                resource_type: Some(r.resource_type.clone()),
                resource_identifier: Some(r.identifier.clone()),
                managed_by_stack: Some(r.managed),
            })
            .collect();
        let (related_resources, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListResourceScanRelatedResourcesOutput { related_resources: Some(related_resources), next_token })
    }

    fn find_generated(&self, ctx: &RequestContext, name: &str) -> Result<GeneratedTemplate, ServiceError> {
        self.state()
            .generated
            .values()
            .find(|g| g.account == ctx.caller.account_id && g.region == ctx.region && (g.name == name || g.id == name))
            .cloned()
            .ok_or_else(|| template_not_found(name))
    }

    pub(crate) async fn create_generated_template_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateGeneratedTemplateInput,
    ) -> Result<types::CreateGeneratedTemplateOutput, ServiceError> {
        ctx.authorize("cloudformation:CreateGeneratedTemplate", "*", Default::default())?;
        if self.find_generated(ctx, &input.generated_template_name).is_ok() {
            return Err(errors::already_exists(format!(
                "Generated template {} already exists.",
                input.generated_template_name
            )));
        }
        let stack_id = match &input.stack_name {
            Some(n) => Some(crate::ops::find(&self.state(), ctx, n)?.id.clone()),
            None => None,
        };
        check_config(input.template_configuration.as_ref())?;
        let id = format!(
            "arn:{}:cloudformation:{}:{}:generatedtemplate/{}",
            ctx.partition,
            ctx.region,
            ctx.caller.account_id,
            uuid::Uuid::new_v4()
        );
        let mut g = GeneratedTemplate {
            id: id.clone(),
            name: input.generated_template_name.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            status: "CREATE_PENDING".into(),
            created: ctx.received_at,
            updated: ctx.received_at,
            stack_id,
            config: input.template_configuration.clone(),
            ..Default::default()
        };
        add_resources(&mut g, input.resources.as_deref().unwrap_or_default())?;
        self.state().generated.insert(id.clone(), g);
        self.generate(ctx, &id, "CREATE");
        Ok(types::CreateGeneratedTemplateOutput { generated_template_id: Some(id) })
    }

    /// Build a generated template in the background.
    fn generate(&self, ctx: &RequestContext, id: &str, phase: &str) {
        let me = self.clone();
        let ctx = ctx.clone();
        let id = id.to_string();
        let phase = phase.to_string();
        tokio::spawn(async move {
            let Some(g) = me.state().generated.get_mut(&id).map(|g| {
                g.status = format!("{phase}_IN_PROGRESS");
                for r in g.resources.iter_mut().filter(|r| r.status != "COMPLETE") {
                    r.status = "IN_PROGRESS".into();
                }
                g.clone()
            }) else {
                return;
            };
            let mut found: BTreeMap<String, Scanned> = BTreeMap::new();
            let mut results: Vec<(String, Result<(), String>)> = Vec::new();
            for r in &g.resources {
                let outcome = match me.find_existing(&ctx, &r.resource_type, &r.identifier).await {
                    Ok(Some(s)) => {
                        found.insert(r.logical_id.clone(), s);
                        Ok(())
                    }
                    Ok(None) => Err(format!(
                        "Resource of type {} with identifier {:?} was not found",
                        r.resource_type, r.identifier
                    )),
                    Err(e) => Err(e),
                };
                results.push((r.logical_id.clone(), outcome));
            }
            let body = me.template_from(&g, &found);
            if let Some(g) = me.state().generated.get_mut(&id) {
                let mut failed = 0;
                for (logical, outcome) in results {
                    if let Some(r) = g.resources.iter_mut().find(|r| r.logical_id == logical) {
                        match outcome {
                            Ok(()) => {
                                r.status = "COMPLETE".into();
                                r.reason = None;
                                r.write_only = found.get(&logical).map(|s| s.write_only.clone()).unwrap_or_default();
                            }
                            Err(e) => {
                                failed += 1;
                                r.status = "FAILED".into();
                                r.reason = Some(e);
                            }
                        }
                    }
                }
                g.body = Some(body);
                g.updated = Utc::now();
                if failed > 0 && failed == g.resources.len() {
                    g.status = "FAILED".into();
                    g.reason = Some("All resources failed to be added to the template".into());
                } else {
                    g.status = "COMPLETE".into();
                    g.reason = (failed > 0).then(|| format!("{failed} resource(s) could not be added to the template"));
                }
            }
        });
    }

    /// The template for the resources found, referring between them with
    /// `Ref` and `Fn::GetAtt` where one names another.
    fn template_from(&self, g: &GeneratedTemplate, found: &BTreeMap<String, Scanned>) -> Value {
        let deletion = g.config.as_ref().and_then(|c| c.deletion_policy.clone()).unwrap_or_else(|| "RETAIN".into());
        let replace =
            g.config.as_ref().and_then(|c| c.update_replace_policy.clone()).unwrap_or_else(|| "RETAIN".into());
        let cap = |p: &str| if p == "RETAIN" { "Retain".to_string() } else { "Delete".to_string() };
        let mut refs: Vec<(String, Value)> = Vec::new();
        for (logical, s) in found {
            refs.push((s.physical_id.clone(), json!({"Ref": logical})));
            for (k, v) in &s.attributes {
                if let Value::String(x) = v {
                    if x != &s.physical_id && x.len() > 3 {
                        refs.push((x.clone(), json!({"Fn::GetAtt": [logical, k]})));
                    }
                }
            }
        }
        let mut resources = Map::new();
        // Resources of a base stack come first, as they are.
        let mut root = Map::new();
        if let Some(stack) = g.stack_id.as_ref().and_then(|id| self.state().stacks.get(id).cloned()) {
            if let Ok(t) = crate::template::Template::parse(&stack.template_body) {
                root = t.root.clone();
                if let Some(r) = root.get("Resources").and_then(Value::as_object) {
                    resources = r.clone();
                }
            }
        }
        for (logical, s) in found {
            let own: Vec<(String, Value)> =
                refs.iter().filter(|(_, r)| !r.to_string().contains(&format!("\"{logical}\""))).cloned().collect();
            let props = substitute(&Value::Object(s.properties.clone()), &own);
            let ty = g
                .resources
                .iter()
                .find(|r| &r.logical_id == logical)
                .map(|r| r.resource_type.clone())
                .unwrap_or_default();
            resources.insert(
                logical.clone(),
                json!({"Type": ty, "DeletionPolicy": cap(&deletion), "UpdateReplacePolicy": cap(&replace), "Properties": props}),
            );
        }
        root.insert("AWSTemplateFormatVersion".into(), json!("2010-09-09"));
        root.entry("Metadata")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .map(|m| m.insert("TemplateId".into(), json!(g.id)));
        root.insert("Resources".into(), Value::Object(resources));
        Value::Object(root)
    }

    pub(crate) fn describe_generated_template_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeGeneratedTemplateInput,
    ) -> Result<types::DescribeGeneratedTemplateOutput, ServiceError> {
        ctx.authorize("cloudformation:DescribeGeneratedTemplate", "*", Default::default())?;
        let g = self.find_generated(ctx, &input.generated_template_name)?;
        let count = |s: &str| g.resources.iter().filter(|r| r.status == s).count() as i32;
        let resources: Vec<types::ResourceDetail> = g
            .resources
            .iter()
            .map(|r| types::ResourceDetail {
                resource_type: Some(r.resource_type.clone()),
                logical_resource_id: Some(r.logical_id.clone()),
                resource_identifier: Some(r.identifier.clone()),
                resource_status: Some(r.status.clone()),
                resource_status_reason: r.reason.clone(),
                warnings: Some(
                    (!r.write_only.is_empty())
                        .then(|| types::WarningDetail {
                            r#type: Some("WRITE_ONLY_PROPERTIES".into()),
                            properties: Some(
                                r.write_only
                                    .iter()
                                    .map(|p| types::WarningProperty {
                                        property_path: Some(p.clone()),
                                        required: Some(p.ends_with("/Code")),
                                        description: Some("The property is write-only; the template has a placeholder value (REPLACEME) for it.".into()),
                                    })
                                    .collect(),
                            ),
                        })
                        .into_iter()
                        .collect(),
                ),
            })
            .collect();
        let total_warnings = g.resources.iter().filter(|r| !r.write_only.is_empty()).count() as i32;
        Ok(types::DescribeGeneratedTemplateOutput {
            generated_template_id: Some(g.id.clone()),
            generated_template_name: Some(g.name.clone()),
            resources: Some(resources),
            status: Some(g.status.clone()),
            status_reason: g.reason.clone(),
            creation_time: Some(g.created),
            last_updated_time: Some(g.updated),
            progress: Some(types::TemplateProgress {
                resources_succeeded: Some(count("COMPLETE")),
                resources_failed: Some(count("FAILED")),
                resources_processing: Some(count("IN_PROGRESS")),
                resources_pending: Some(count("PENDING")),
            }),
            stack_id: g.stack_id.clone(),
            template_configuration: Some(g.config.clone().unwrap_or(types::TemplateConfiguration {
                deletion_policy: Some("RETAIN".into()),
                update_replace_policy: Some("RETAIN".into()),
            })),
            total_warnings: Some(total_warnings),
        })
    }

    pub(crate) fn get_generated_template_op(
        &self,
        ctx: &RequestContext,
        input: types::GetGeneratedTemplateInput,
    ) -> Result<types::GetGeneratedTemplateOutput, ServiceError> {
        ctx.authorize("cloudformation:GetGeneratedTemplate", "*", Default::default())?;
        let g = self.find_generated(ctx, &input.generated_template_name)?;
        let body = match &g.body {
            None => None,
            Some(b) if input.format.as_deref() == Some("YAML") => Some(serde_yaml::to_string(b).unwrap_or_default()),
            Some(b) => Some(serde_json::to_string_pretty(b).unwrap_or_default()),
        };
        Ok(types::GetGeneratedTemplateOutput { status: Some(g.status.clone()), template_body: body })
    }

    pub(crate) fn list_generated_templates_op(
        &self,
        ctx: &RequestContext,
        input: types::ListGeneratedTemplatesInput,
    ) -> Result<types::ListGeneratedTemplatesOutput, ServiceError> {
        ctx.authorize("cloudformation:ListGeneratedTemplates", "*", Default::default())?;
        let mut all: Vec<GeneratedTemplate> = self
            .state()
            .generated
            .values()
            .filter(|g| g.account == ctx.caller.account_id && g.region == ctx.region)
            .cloned()
            .collect();
        all.sort_by_key(|g| g.created);
        let all: Vec<types::TemplateSummary> = all
            .iter()
            .map(|g| types::TemplateSummary {
                generated_template_id: Some(g.id.clone()),
                generated_template_name: Some(g.name.clone()),
                status: Some(g.status.clone()),
                status_reason: g.reason.clone(),
                creation_time: Some(g.created),
                last_updated_time: Some(g.updated),
                number_of_resources: Some(g.resources.len() as i32),
            })
            .collect();
        let (summaries, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(50) as usize)?;
        Ok(types::ListGeneratedTemplatesOutput { summaries: Some(summaries), next_token })
    }

    pub(crate) fn update_generated_template_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateGeneratedTemplateInput,
    ) -> Result<types::UpdateGeneratedTemplateOutput, ServiceError> {
        ctx.authorize("cloudformation:UpdateGeneratedTemplate", "*", Default::default())?;
        let g = self.find_generated(ctx, &input.generated_template_name)?;
        if g.status.ends_with("_IN_PROGRESS") || g.status.ends_with("_PENDING") {
            return Err(validation(format!(
                "Generated template {} cannot be updated while it is in status {}",
                g.name, g.status
            )));
        }
        if let Some(n) = &input.new_generated_template_name {
            if n != &g.name && self.find_generated(ctx, n).is_ok() {
                return Err(errors::already_exists(format!("Generated template {n} already exists.")));
            }
        }
        check_config(input.template_configuration.as_ref())?;
        let mut updated = g.clone();
        if let Some(n) = &input.new_generated_template_name {
            updated.name = n.clone();
        }
        if let Some(c) = &input.template_configuration {
            updated.config = Some(c.clone());
        }
        for r in input.remove_resources.iter().flatten() {
            if !updated.resources.iter().any(|x| &x.logical_id == r) {
                return Err(validation(format!("Resource {r} is not in the generated template")));
            }
            updated.resources.retain(|x| &x.logical_id != r);
        }
        add_resources(&mut updated, input.add_resources.as_deref().unwrap_or_default())?;
        if input.refresh_all_resources == Some(true) {
            for r in updated.resources.iter_mut() {
                r.status = "PENDING".into();
            }
        }
        let regenerate = input.add_resources.is_some()
            || input.remove_resources.is_some()
            || input.refresh_all_resources == Some(true)
            || input.template_configuration.is_some();
        updated.updated = ctx.received_at;
        if regenerate {
            updated.status = "UPDATE_PENDING".into();
            // Already-found resources are kept; regeneration looks again.
            for r in updated.resources.iter_mut() {
                r.status = "PENDING".into();
            }
        }
        self.state().generated.insert(g.id.clone(), updated);
        if regenerate {
            self.generate(ctx, &g.id, "UPDATE");
        }
        Ok(types::UpdateGeneratedTemplateOutput { generated_template_id: Some(g.id) })
    }

    pub(crate) fn delete_generated_template_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteGeneratedTemplateInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize("cloudformation:DeleteGeneratedTemplate", "*", Default::default())?;
        let g = self.find_generated(ctx, &input.generated_template_name)?;
        if g.status.ends_with("_IN_PROGRESS") {
            return Err(errors::concurrent_resources_limit_exceeded(format!(
                "Generated template {} cannot be deleted while it is in status {}",
                g.name, g.status
            )));
        }
        self.state().generated.remove(&g.id);
        Ok(())
    }
}

fn check_config(c: Option<&types::TemplateConfiguration>) -> Result<(), ServiceError> {
    let Some(c) = c else { return Ok(()) };
    for v in [&c.deletion_policy, &c.update_replace_policy].into_iter().flatten() {
        if v != "DELETE" && v != "RETAIN" {
            return Err(validation(format!("Invalid policy {v}; expected DELETE or RETAIN")));
        }
    }
    Ok(())
}

fn add_resources(g: &mut GeneratedTemplate, defs: &[types::ResourceDefinition]) -> Result<(), ServiceError> {
    let mut taken: BTreeSet<String> = g.resources.iter().map(|r| r.logical_id.clone()).collect();
    for d in defs {
        if !SCANNABLE.contains(&d.resource_type.as_str()) {
            return Err(validation(format!("Resource type {} is not supported by the IaC generator", d.resource_type)));
        }
        if d.resource_identifier.is_empty() {
            return Err(validation("ResourceIdentifier must not be empty"));
        }
        if g.resources.iter().any(|r| r.resource_type == d.resource_type && r.identifier == d.resource_identifier) {
            return Err(validation(format!(
                "Resource of type {} with identifier {:?} is already in the template",
                d.resource_type, d.resource_identifier
            )));
        }
        let logical = match &d.logical_resource_id {
            Some(l) if taken.contains(l) => {
                return Err(validation(format!("Logical resource id {l} is already in the template")))
            }
            Some(l) => l.clone(),
            None => logical_id_for(&d.resource_type, &d.resource_identifier, &taken),
        };
        taken.insert(logical.clone());
        g.resources.push(GenResource {
            resource_type: d.resource_type.clone(),
            logical_id: logical,
            identifier: d.resource_identifier.clone(),
            status: "PENDING".into(),
            ..Default::default()
        });
    }
    Ok(())
}

/// Replace values that name other template resources with references.
fn substitute(v: &Value, refs: &[(String, Value)]) -> Value {
    match v {
        Value::String(s) => refs.iter().find(|(k, _)| k == s).map(|(_, r)| r.clone()).unwrap_or_else(|| v.clone()),
        Value::Array(a) => Value::Array(a.iter().map(|x| substitute(x, refs)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), substitute(x, refs))).collect()),
        other => other.clone(),
    }
}
