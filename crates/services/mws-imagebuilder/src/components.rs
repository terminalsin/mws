//! Components: versioned AWSTOE documents that recipes install and test.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::{State, Versioned};
use crate::toe::Document;
use crate::util::{
    account_of, already_exists_component, arn, arn_not_found, authorize, filters_match, invalid_combination,
    invalid_parameter_value, invalid_request, latest_references, not_found, paginate, request_tags, resource_tags, s,
    slug, Arn, Version, VersionPattern,
};
use crate::{managed, ImageBuilder};

pub const POLICY_ACTIONS: &[&str] = &["imagebuilder:GetComponent", "imagebuilder:ListComponents"];

/// A component the caller can see, with its owner.
#[derive(Debug, Clone)]
pub struct Found {
    pub component: t::Component,
    pub policy: Option<String>,
    /// The owning account, `aws` for AWS-managed components.
    pub owner: String,
}

fn version_of(c: &t::Component) -> Version {
    c.version.as_deref().and_then(Version::parse).unwrap_or(Version(0, 0, 0))
}

fn build_of(c: &t::Component) -> u32 {
    c.arn.as_deref().and_then(Arn::parse).and_then(|a| a.build).unwrap_or(1)
}

impl ImageBuilder {
    /// Every build of component `name` owned by `account` (or AWS) in the
    /// ARN's Region.
    fn component_builds(&self, a: &Arn) -> Vec<Found> {
        if a.account == "aws" {
            return managed::components(&a.partition, &a.region)
                .into_iter()
                .filter(|c| c.name.as_deref() == Some(a.name.as_str()))
                .map(|c| Found { component: c, policy: None, owner: "aws".into() })
                .collect();
        }
        let st = self.lock();
        let Some(r) = st.regions.get(&State::key(&a.account, &a.region)) else { return Vec::new() };
        r.components
            .values()
            .filter(|v| v.resource.arn.as_deref().and_then(Arn::parse).is_some_and(|x| x.name == a.name))
            .map(|v| Found { component: v.resource.clone(), policy: v.policy.clone(), owner: a.account.clone() })
            .collect()
    }

    /// Resolve a component ARN: a build version, an exact version (its
    /// latest build) or a wildcard version (the latest matching build).
    pub(crate) fn resolve_component(&self, arn_text: &str) -> Option<Found> {
        let a = Arn::parse(arn_text).filter(|a| a.kind == "component")?;
        let pattern = VersionPattern::parse(a.version.as_deref()?)?;
        self.component_builds(&a)
            .into_iter()
            .filter(|f| pattern.matches(version_of(&f.component)))
            .filter(|f| a.build.is_none_or(|b| b == build_of(&f.component)))
            .max_by_key(|f| (version_of(&f.component), build_of(&f.component)))
    }

    /// Look a component up for `action`, authorizing the caller with the
    /// component's resource policy (which can share it across accounts).
    pub(crate) fn component_for(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn_text: &str,
    ) -> Result<Found, ServiceError> {
        match self.resolve_component(arn_text) {
            Some(f) => {
                if f.owner != "aws" {
                    let resource = f.component.arn.clone().unwrap_or_default();
                    ctx.authorize_with_resource_policy(
                        &format!("imagebuilder:{action}"),
                        &resource,
                        f.policy.as_deref(),
                        resource_tags(&f.component.tags),
                    )?;
                } else {
                    authorize(ctx, action, arn_text, ConditionContext::new())?;
                }
                Ok(f)
            }
            None => {
                authorize(ctx, action, arn_text, ConditionContext::new())?;
                Err(arn_not_found(arn_text))
            }
        }
    }

    fn latest_component_references(&self, c: &t::Component) -> Option<t::LatestVersionReferences> {
        let a = Arn::parse(c.arn.as_deref()?)?;
        let builds: Vec<(Version, u32)> =
            self.component_builds(&a).iter().map(|f| (version_of(&f.component), build_of(&f.component))).collect();
        Some(latest_references(&a.base(), version_of(c), builds.into_iter()))
    }

    /// Read a document from S3 with the caller's permissions.
    pub(crate) async fn document_from_uri(&self, ctx: &RequestContext, uri: &str) -> Result<String, ServiceError> {
        let bad = || {
            invalid_parameter_value(format!(
                "The value supplied for parameter 'uri' is not valid. '{uri}' is not a valid S3 URI."
            ))
        };
        let rest = uri.strip_prefix("s3://").ok_or_else(bad)?;
        let (bucket, key) = rest.split_once('/').filter(|(b, k)| !b.is_empty() && !k.is_empty()).ok_or_else(bad)?;
        let Some(s3) = self.s3() else {
            return Err(invalid_parameter_value(format!("The S3 object '{uri}' could not be read.")));
        };
        let out = s3
            .invoke(ctx.clone(), "GetObject", serde_json::json!({ "Bucket": bucket, "Key": key }))
            .await
            .map_err(|e| invalid_parameter_value(format!("The S3 object '{uri}' could not be read: {}", e.message)))?;
        let body = out.get("Body").and_then(serde_json::Value::as_str).unwrap_or("");
        let bytes = base64::engine::general_purpose::STANDARD.decode(body).unwrap_or_else(|_| body.as_bytes().to_vec());
        String::from_utf8(bytes)
            .map_err(|_| invalid_parameter_value(format!("The S3 object '{uri}' is not UTF-8 text.")))
    }

    async fn document_text(
        &self,
        ctx: &RequestContext,
        data: &Option<String>,
        uri: &Option<String>,
    ) -> Result<String, ServiceError> {
        match (data, uri) {
            (Some(d), None) => Ok(d.clone()),
            (None, Some(u)) => self.document_from_uri(ctx, u).await,
            _ => Err(invalid_combination("You must specify either 'data' or 'uri', but not both.")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn store_component(
        &self,
        ctx: &RequestContext,
        name: &str,
        version: &str,
        doc_text: String,
        doc: &Document,
        component_type: &str,
        mut component: t::Component,
    ) -> Result<(String, Option<t::LatestVersionReferences>), ServiceError> {
        let v = Version::for_create(version)?;
        let account = account_of(ctx);
        let build_arn = arn(ctx, &account, &format!("component/{}/{v}/1", slug(name)));
        let version_arn = arn(ctx, &account, &format!("component/{}/{v}", slug(name)));
        component.arn = Some(build_arn.clone());
        component.name = Some(name.to_string());
        component.version = Some(v.to_string());
        component.r#type = Some(component_type.to_string());
        component.owner = Some(account.clone());
        component.data = Some(doc_text);
        component.encrypted = Some(true);
        component.date_created = Some(crate::util::now(ctx));
        component.state = Some(t::ComponentState { status: Some("ACTIVE".into()), reason: None });
        component.parameters = (!doc.parameters.is_empty()).then(|| doc.parameters.clone());
        component.tags = Some(component.tags.clone().unwrap_or_default());
        self.with_region(ctx, |r| {
            if r.components.contains_key(&build_arn) {
                return Err(already_exists_component(&version_arn));
            }
            r.components.insert(build_arn.clone(), Versioned { resource: component.clone(), policy: None });
            Ok(())
        })?;
        Ok((build_arn, self.latest_component_references(&component)))
    }

    pub(crate) async fn create_component_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateComponentRequest,
    ) -> Result<t::CreateComponentResponse, ServiceError> {
        let account = account_of(ctx);
        let target = arn(ctx, &account, &format!("component/{}/{}/1", slug(&input.name), input.semantic_version));
        authorize(ctx, "CreateComponent", &target, request_tags(&input.tags))?;
        if input.dry_run {
            return Err(crate::util::dry_run_ok());
        }
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateComponent", &token, &input.clone(), async {
            let text = self.document_text(ctx, &input.data, &input.uri).await?;
            let doc = Document::parse(&text).map_err(|e| {
                invalid_parameter_value(format!("The value supplied for parameter 'data' is not valid. {e}"))
            })?;
            let component = t::Component {
                description: input.description.clone(),
                change_description: input.change_description.clone(),
                platform: Some(input.platform.clone()),
                supported_os_versions: input.supported_os_versions.clone(),
                kms_key_id: input.kms_key_id.clone(),
                tags: input.tags.clone(),
                ..Default::default()
            };
            let (build_arn, latest) = self.store_component(
                ctx,
                &input.name,
                &input.semantic_version,
                text,
                &doc,
                doc.component_type(),
                component,
            )?;
            Ok(t::CreateComponentResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                component_build_version_arn: Some(build_arn),
                latest_version_references: latest,
            })
        })
        .await
    }

    pub(crate) async fn import_component_op(
        &self,
        ctx: &RequestContext,
        input: t::ImportComponentRequest,
    ) -> Result<t::ImportComponentResponse, ServiceError> {
        let account = account_of(ctx);
        let target = arn(ctx, &account, &format!("component/{}/{}/1", slug(&input.name), input.semantic_version));
        authorize(ctx, "ImportComponent", &target, request_tags(&input.tags))?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "ImportComponent", &token, &input.clone(), async {
            if input.format != "SHELL" {
                return Err(invalid_parameter_value("The value supplied for parameter 'format' is not valid."));
            }
            let script = self.document_text(ctx, &input.data, &input.uri).await?;
            let phase = if input.r#type == "TEST" { "test" } else { "build" };
            let mut text = format!(
                "name: {}\ndescription: {}\nschemaVersion: 1.0\nphases:\n  - name: {phase}\n    steps:\n      - name: ImportedScript\n        action: ExecuteBash\n        inputs:\n          commands:\n            - |\n",
                serde_json::Value::String(input.name.clone()),
                serde_json::Value::String(input.description.clone().unwrap_or_else(|| "Imported shell script".into())),
            );
            for line in script.lines() {
                text.push_str("              ");
                text.push_str(line);
                text.push('\n');
            }
            let doc = Document::parse(&text).map_err(|e| invalid_parameter_value(format!("The value supplied for parameter 'data' is not valid. {e}")))?;
            let component = t::Component {
                description: input.description.clone(),
                change_description: input.change_description.clone(),
                platform: Some(input.platform.clone()),
                kms_key_id: input.kms_key_id.clone(),
                tags: input.tags.clone(),
                ..Default::default()
            };
            let (build_arn, _) =
                self.store_component(ctx, &input.name, &input.semantic_version, text, &doc, &input.r#type, component)?;
            Ok(t::ImportComponentResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                component_build_version_arn: Some(build_arn),
            })
        })
        .await
    }

    pub(crate) fn get_component_op(
        &self,
        ctx: &RequestContext,
        input: t::GetComponentRequest,
    ) -> Result<t::GetComponentResponse, ServiceError> {
        let f = self.component_for(ctx, "GetComponent", &input.component_build_version_arn)?;
        let latest = self.latest_component_references(&f.component);
        Ok(t::GetComponentResponse {
            request_id: Some(ctx.request_id.clone()),
            component: Some(f.component),
            latest_version_references: latest,
        })
    }

    /// Components visible to the caller for `owner`.
    fn visible_components(&self, ctx: &RequestContext, owner: &str) -> Vec<t::Component> {
        let account = account_of(ctx);
        match owner {
            "Amazon" => managed::components(&ctx.partition, &ctx.region),
            "Shared" => {
                let st = self.lock();
                let mut out = Vec::new();
                for (key, r) in &st.regions {
                    let Some((acct, region)) = key.split_once('/') else { continue };
                    if acct == account || region != ctx.region {
                        continue;
                    }
                    for v in r.components.values() {
                        let Some(policy) = &v.policy else { continue };
                        let decision = ctx.check(
                            "imagebuilder:ListComponents",
                            v.resource.arn.as_deref().unwrap_or_default(),
                            Some(policy),
                            mws_core::ResourcePolicyMode::Required,
                            ConditionContext::new(),
                        );
                        if decision == mws_core::AuthzDecision::Allow {
                            out.push(v.resource.clone());
                        }
                    }
                }
                out
            }
            "Self" => self.with_region(ctx, |r| r.components.values().map(|v| v.resource.clone()).collect()),
            _ => Vec::new(),
        }
    }

    pub(crate) fn list_components_op(
        &self,
        ctx: &RequestContext,
        input: t::ListComponentsRequest,
    ) -> Result<t::ListComponentsResponse, ServiceError> {
        authorize(ctx, "ListComponents", &arn(ctx, &account_of(ctx), "component/*"), ConditionContext::new())?;
        let owner = input.owner.clone().unwrap_or_else(|| "Self".into());
        let mut matched = Vec::new();
        for c in self.visible_components(ctx, &owner) {
            let ok =
                filters_match(&input.filters, &["name", "platform", "supportedOsVersion", "type", "version"], |n| {
                    match n {
                        "name" => s(&c.name),
                        "platform" => s(&c.platform),
                        "type" => s(&c.r#type),
                        "version" => s(&c.version),
                        _ => c.supported_os_versions.clone().unwrap_or_default(),
                    }
                })?;
            if ok {
                matched.push(c);
            }
        }
        // One entry per version: its latest build.
        let mut by_version: BTreeMap<String, t::Component> = BTreeMap::new();
        for c in matched {
            let key = Arn::parse(c.arn.as_deref().unwrap_or_default()).map(|a| a.version_arn()).unwrap_or_default();
            let keep = by_version.get(&key).is_none_or(|prev| build_of(prev) < build_of(&c));
            if keep {
                by_version.insert(key, c);
            }
        }
        let mut list: Vec<(String, t::Component)> = by_version.into_iter().collect();
        if input.by_name {
            let mut latest: BTreeMap<String, (String, t::Component)> = BTreeMap::new();
            for (k, c) in list {
                let name = Arn::parse(&k).map(|a| a.base()).unwrap_or_default();
                let keep = latest.get(&name).is_none_or(|(_, prev)| version_of(prev) < version_of(&c));
                if keep {
                    latest.insert(name, (k, c));
                }
            }
            list = latest.into_values().collect();
        }
        list.sort_by(|a, b| a.0.cmp(&b.0));
        let versions: Vec<t::ComponentVersion> = list
            .into_iter()
            .map(|(k, c)| t::ComponentVersion {
                arn: Some(k),
                name: c.name,
                version: c.version,
                description: c.description,
                platform: c.platform,
                supported_os_versions: c.supported_os_versions,
                r#type: c.r#type,
                owner: c.owner,
                date_created: c.date_created,
                status: c.state.and_then(|s| s.status),
                product_codes: c.product_codes,
            })
            .collect();
        let (page, next_token) = paginate(versions, input.max_results, &input.next_token)?;
        Ok(t::ListComponentsResponse {
            request_id: Some(ctx.request_id.clone()),
            component_version_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn list_component_build_versions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListComponentBuildVersionsRequest,
    ) -> Result<t::ListComponentBuildVersionsResponse, ServiceError> {
        let version_arn = input
            .component_version_arn
            .clone()
            .ok_or_else(|| invalid_request("The componentVersionArn parameter is required."))?;
        authorize(ctx, "ListComponentBuildVersions", &version_arn, ConditionContext::new())?;
        let a = Arn::parse(&version_arn).ok_or_else(|| arn_not_found(&version_arn))?;
        let mut builds: Vec<t::Component> =
            self.component_builds(&a).into_iter().map(|f| f.component).filter(|c| c.version == a.version).collect();
        builds.sort_by_key(build_of);
        let summaries: Vec<t::ComponentSummary> = builds
            .into_iter()
            .map(|c| t::ComponentSummary {
                arn: c.arn,
                name: c.name,
                version: c.version,
                platform: c.platform,
                supported_os_versions: c.supported_os_versions,
                state: c.state,
                r#type: c.r#type,
                owner: c.owner,
                description: c.description,
                change_description: c.change_description,
                date_created: c.date_created,
                tags: c.tags,
                publisher: c.publisher,
                obfuscate: c.obfuscate,
            })
            .collect();
        let (page, next_token) = paginate(summaries, input.max_results, &input.next_token)?;
        Ok(t::ListComponentBuildVersionsResponse {
            request_id: Some(ctx.request_id.clone()),
            component_summary_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn delete_component_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteComponentRequest,
    ) -> Result<t::DeleteComponentResponse, ServiceError> {
        let target = input.component_build_version_arn.clone();
        let tags = self.with_region(ctx, |r| r.components.get(&target).map(|c| c.resource.tags.clone()));
        authorize(ctx, "DeleteComponent", &target, resource_tags(&tags.clone().flatten()))?;
        if tags.is_none() {
            return Err(arn_not_found(&target));
        }
        let users = self.recipes_using_component(ctx, &target);
        if !users.is_empty() {
            return Err(crate::util::dependency(format!(
                "Resource dependency error: The resource ARN '{target}' has the following dependencies: {}.",
                users.join(", ")
            )));
        }
        self.with_region(ctx, |r| r.components.remove(&target));
        Ok(t::DeleteComponentResponse {
            request_id: Some(ctx.request_id.clone()),
            component_build_version_arn: Some(target),
        })
    }

    /// Recipes of the caller whose component references resolve to `build_arn`.
    fn recipes_using_component(&self, ctx: &RequestContext, build_arn: &str) -> Vec<String> {
        let Some(target) = Arn::parse(build_arn) else { return Vec::new() };
        let refers = |c: &t::ComponentConfiguration| {
            Arn::parse(&c.component_arn).is_some_and(|a| {
                a.account == target.account
                    && a.name == target.name
                    && a.version.as_deref().and_then(VersionPattern::parse).is_some_and(|p| {
                        target.version.as_deref().and_then(Version::parse).is_some_and(|v| p.matches(v))
                    })
                    && a.build.is_none_or(|b| Some(b) == target.build)
            })
        };
        self.with_region(ctx, |r| {
            let mut out: Vec<String> = r
                .image_recipes
                .iter()
                .filter(|(_, v)| v.resource.components.iter().flatten().any(refers))
                .map(|(k, _)| k.clone())
                .collect();
            out.extend(
                r.container_recipes
                    .iter()
                    .filter(|(_, v)| v.resource.components.iter().flatten().any(refers))
                    .map(|(k, _)| k.clone()),
            );
            out
        })
    }

    pub(crate) fn get_component_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::GetComponentPolicyRequest,
    ) -> Result<t::GetComponentPolicyResponse, ServiceError> {
        let target = input.component_arn.clone();
        let found = self.with_region(ctx, |r| r.components.get(&target).cloned());
        authorize(ctx, "GetComponentPolicy", &target, ConditionContext::new())?;
        let found = found.ok_or_else(|| arn_not_found(&target))?;
        let policy =
            found.policy.ok_or_else(|| not_found(format!("The resource policy for '{target}' does not exist.")))?;
        Ok(t::GetComponentPolicyResponse { request_id: Some(ctx.request_id.clone()), policy: Some(policy) })
    }

    pub(crate) fn put_component_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::PutComponentPolicyRequest,
    ) -> Result<t::PutComponentPolicyResponse, ServiceError> {
        let target = input.component_arn.clone();
        authorize(ctx, "PutComponentPolicy", &target, ConditionContext::new())?;
        crate::util::check_policy(&input.policy, POLICY_ACTIONS)?;
        self.with_region(ctx, |r| match r.components.get_mut(&target) {
            Some(c) => {
                c.policy = Some(input.policy.clone());
                Ok(())
            }
            None => Err(arn_not_found(&target)),
        })?;
        Ok(t::PutComponentPolicyResponse { request_id: Some(ctx.request_id.clone()), component_arn: Some(target) })
    }
}

/// Merge the parameters a recipe sets with a component's defaults.
pub fn component_parameters(config: &t::ComponentConfiguration) -> BTreeMap<String, String> {
    config.parameters.iter().flatten().map(|p| (p.name.clone(), p.value.join(","))).collect()
}

/// Check that a recipe's component parameters exist and are complete.
pub fn check_component_parameters(c: &t::Component, config: &t::ComponentConfiguration) -> Result<(), ServiceError> {
    let declared = c.parameters.clone().unwrap_or_default();
    for p in config.parameters.iter().flatten() {
        if !declared.iter().any(|d| d.name == p.name) {
            return Err(invalid_parameter_value(format!(
                "The parameter '{}' is not defined in component '{}'.",
                p.name,
                c.arn.clone().unwrap_or_default()
            )));
        }
    }
    Ok(())
}
