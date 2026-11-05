//! Launch templates and their versions, and launching from them.
//!
//! A version's data is kept as the API reports it
//! (`ResponseLaunchTemplateData`); request and response shapes share their
//! member names, so they convert through their serde forms.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::generated::types as t;
use crate::state::{LaunchTemplateRecord, RegionState};
use crate::util::{
    arn, authorize, b, err, invalid_parameter, new_id, paginate, request_tag_context, resource_tag_context, s,
    some_tags, tags_for, Filters,
};
use crate::{account_of, Ec2};

/// A launch template version resolved for a launch.
#[derive(Debug, Clone)]
pub struct ResolvedLaunchTemplate {
    pub id: String,
    pub name: String,
    pub version: i64,
    pub data: t::ResponseLaunchTemplateData,
}

fn not_found_by_id(id: &str) -> ServiceError {
    err(
        "InvalidLaunchTemplateId.NotFound",
        format!("The specified launch template, with template ID {id}, does not exist."),
    )
}

fn not_found_by_name() -> ServiceError {
    err(
        "InvalidLaunchTemplateName.NotFoundException",
        "At least one of the launch templates specified in the request does not exist.",
    )
}

fn check_id(id: &str) -> Result<(), ServiceError> {
    let ok = id
        .strip_prefix("lt-")
        .is_some_and(|hex| (hex.len() == 8 || hex.len() == 17) && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(())
    } else {
        Err(err(
            "InvalidLaunchTemplateId.Malformed",
            format!("The specified ID for the launch template ID is not valid. Ensure that you specify the ID in the form lt-xxxxxxxxxxxxxxxxx. ({id})"),
        ))
    }
}

fn check_name(name: &str) -> Result<(), ServiceError> {
    let ok = (3..=128).contains(&name.chars().count())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "().-/_".contains(c));
    if ok {
        Ok(())
    } else {
        Err(err(
            "InvalidLaunchTemplateName.MalformedException",
            "A launch template name must be between 3 and 128 characters, and may contain letters, numbers, and the following characters: - ( ) . / _.'",
        ))
    }
}

pub fn template_arn(ctx: &RequestContext, account: &str, id: &str) -> String {
    arn(ctx, account, &format!("launch-template/{id}"))
}

/// Find a template by id or name (exactly one of them).
fn find<'a>(
    r: &'a mut RegionState,
    id: &Option<String>,
    name: &Option<String>,
) -> Result<&'a mut LaunchTemplateRecord, ServiceError> {
    match (id.as_deref().filter(|s| !s.is_empty()), name.as_deref().filter(|s| !s.is_empty())) {
        (Some(_), Some(_)) => Err(err(
            "InvalidParameterCombination",
            "Specify either the launch template ID or the launch template name in the request, but not both.",
        )),
        (Some(id), None) => {
            check_id(id)?;
            r.launch_templates.get_mut(id).ok_or_else(|| not_found_by_id(id))
        }
        (None, Some(name)) => r
            .launch_templates
            .values_mut()
            .find(|l| l.template.launch_template_name.as_deref() == Some(name))
            .ok_or_else(not_found_by_name),
        (None, None) => Err(err(
            "MissingParameter",
            "The request must contain the parameter launchTemplateName or launchTemplateId",
        )),
    }
}

/// Resolve `$Latest`, `$Default` or a number.
fn version_number(rec: &LaunchTemplateRecord, v: Option<&str>) -> Result<i64, ServiceError> {
    let id = rec.template.launch_template_id.clone().unwrap_or_default();
    match v.unwrap_or("$Default") {
        "$Latest" => Ok(rec.template.latest_version_number.unwrap_or(1)),
        "$Default" | "" => Ok(rec.template.default_version_number.unwrap_or(1)),
        n => {
            let n: i64 = n.parse().map_err(|_| {
                err(
                    "InvalidLaunchTemplateId.VersionNotFound",
                    format!("Could not find launch template version {n} for launch template with ID {id}."),
                )
            })?;
            if rec.versions.contains_key(&n) {
                Ok(n)
            } else {
                Err(err(
                    "InvalidLaunchTemplateId.VersionNotFound",
                    format!("Could not find launch template version {n} for launch template with ID {id}."),
                ))
            }
        }
    }
}

/// Drop `null`s, so optional members become absent.
fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, strip_nulls(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        other => other,
    }
}

/// Convert between shapes that share member names.
fn convert<A: serde::Serialize, B: serde::de::DeserializeOwned + Default>(a: &A) -> B {
    serde_json::to_value(a).ok().map(strip_nulls).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default()
}

pub fn response_data(req: &t::RequestLaunchTemplateData) -> t::ResponseLaunchTemplateData {
    convert(req)
}

fn validate_data(data: &t::RequestLaunchTemplateData) -> Result<(), ServiceError> {
    if let Some(u) = &data.user_data {
        use base64::Engine;
        if base64::engine::general_purpose::STANDARD.decode(u.trim()).is_err() {
            return Err(invalid_parameter("Invalid BASE64 encoding of user data."));
        }
    }
    if let Some(it) = &data.instance_type {
        if crate::catalog::instance_type(it).is_none() {
            return Err(invalid_parameter(format!("Invalid value '{it}' for InstanceType.")));
        }
    }
    for spec in data.tag_specifications.iter().flatten() {
        let rt = spec.resource_type.clone().unwrap_or_default();
        if !["instance", "volume", "network-interface", "spot-instances-request", "elastic-gpu"].contains(&rt.as_str())
        {
            return Err(invalid_parameter(format!("'{rt}' is not a valid taggable resource type for this operation.")));
        }
        crate::util::validate_tags(spec.tags.as_deref().unwrap_or_default())?;
    }
    Ok(())
}

/// Merge the explicit parameters of a `RunInstances` call over a launch
/// template's data: what the call names wins.
pub fn merge_run_instances(
    data: &t::ResponseLaunchTemplateData,
    input: &t::RunInstancesRequest,
) -> t::RunInstancesRequest {
    let mut base = strip_nulls(serde_json::to_value(data).unwrap_or(Value::Null));
    if let Value::Object(m) = &mut base {
        // The few members whose names differ.
        if let Some(v) = m.remove("ram_disk_id") {
            m.insert("ramdisk_id".into(), v);
        }
        if let Some(Value::Object(mon)) = m.get("monitoring") {
            let enabled = mon.get("enabled").and_then(Value::as_bool).unwrap_or(false);
            m.insert("monitoring".into(), serde_json::json!({ "enabled": enabled }));
        }
        // Response-only members RunInstances does not take.
        if let Some(Value::Object(md)) = m.get_mut("metadata_options") {
            md.remove("state");
        }
        m.remove("operator");
    }
    let over = strip_nulls(serde_json::to_value(input).unwrap_or(Value::Null));
    if let (Value::Object(b), Value::Object(o)) = (&mut base, over) {
        for (k, v) in o {
            if k == "tag_specifications" {
                // Tags from both, the call's winning per key and type.
                let mut specs: Vec<t::TagSpecification> =
                    serde_json::from_value(b.remove(&k).unwrap_or(Value::Array(vec![]))).unwrap_or_default();
                let extra: Vec<t::TagSpecification> = serde_json::from_value(v).unwrap_or_default();
                for e in extra {
                    match specs.iter_mut().find(|s| s.resource_type == e.resource_type) {
                        Some(s) => {
                            let tags = s.tags.get_or_insert_with(Vec::new);
                            for tag in e.tags.unwrap_or_default() {
                                tags.retain(|x| x.key != tag.key);
                                tags.push(tag);
                            }
                        }
                        None => specs.push(e),
                    }
                }
                b.insert(k, serde_json::to_value(specs).unwrap_or_default());
            } else {
                b.insert(k, v);
            }
        }
    }
    serde_json::from_value(base).unwrap_or_else(|_| input.clone())
}

fn version_filter(v: &t::LaunchTemplateVersion, name: &str) -> Option<Vec<String>> {
    let d = v.launch_template_data.clone().unwrap_or_default();
    Some(match name {
        "create-time" => v.create_time.map(|t| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()).into_iter().collect(),
        "ebs-optimized" => b(d.ebs_optimized),
        "iam-instance-profile" => {
            d.iam_instance_profile.map(|p| p.arn.into_iter().chain(p.name).collect()).unwrap_or_default()
        }
        "image-id" => s(&d.image_id),
        "instance-type" => s(&d.instance_type),
        "is-default-version" => b(v.default_version),
        "kernel-id" => s(&d.kernel_id),
        "ram-disk-id" => s(&d.ram_disk_id),
        "http-endpoint" => d.metadata_options.as_ref().map(|m| s(&m.http_endpoint)).unwrap_or_default(),
        "http-protocol-ipv4" => vec!["enabled".into()],
        "http-protocol-ipv6" => d.metadata_options.as_ref().map(|m| s(&m.http_protocol_ipv6)).unwrap_or_default(),
        "host-resource-group-arn" => d.placement.as_ref().map(|p| s(&p.host_resource_group_arn)).unwrap_or_default(),
        "network-card-index" => Vec::new(),
        _ => return None,
    })
}

impl Ec2 {
    pub(crate) fn create_launch_template_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateLaunchTemplateRequest,
    ) -> Result<t::CreateLaunchTemplateResult, ServiceError> {
        let account = account_of(ctx);
        check_name(&input.launch_template_name)?;
        let tags = tags_for(&input.tag_specifications, "launch-template", &["launch-template"])?;
        validate_data(&input.launch_template_data)?;
        authorize(
            ctx,
            "CreateLaunchTemplate",
            &[(arn(ctx, &account, "launch-template/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        if let Some(desc) = &input.version_description {
            if desc.chars().count() > 255 {
                return Err(invalid_parameter(
                    "Value for parameter versionDescription is invalid. Description is too long.",
                ));
            }
        }
        let now = ctx.received_at;
        let created_by = ctx.caller.arn.clone();
        self.with_region(ctx, |r| {
            if let Some(token) = input.client_token.as_deref().filter(|t| !t.is_empty()) {
                if let Some(existing) = r.launch_templates.values().find(|l| l.client_token.as_deref() == Some(token)) {
                    return Ok(t::CreateLaunchTemplateResult {
                        launch_template: Some(existing.template.clone()),
                        warning: None,
                    });
                }
            }
            if r.launch_templates
                .values()
                .any(|l| l.template.launch_template_name.as_deref() == Some(input.launch_template_name.as_str()))
            {
                return Err(err(
                    "InvalidLaunchTemplateName.AlreadyExistsException",
                    "Launch template name already in use.",
                ));
            }
            let id = new_id("lt");
            let template = t::LaunchTemplate {
                launch_template_id: Some(id.clone()),
                launch_template_name: Some(input.launch_template_name.clone()),
                create_time: Some(now),
                created_by: Some(created_by.clone()),
                default_version_number: Some(1),
                latest_version_number: Some(1),
                tags: some_tags(tags),
                operator: None,
            };
            let version = t::LaunchTemplateVersion {
                launch_template_id: Some(id.clone()),
                launch_template_name: Some(input.launch_template_name.clone()),
                version_number: Some(1),
                version_description: input.version_description.clone(),
                create_time: Some(now),
                created_by: Some(created_by),
                default_version: Some(true),
                launch_template_data: Some(response_data(&input.launch_template_data)),
                operator: None,
            };
            let mut rec = LaunchTemplateRecord {
                template: template.clone(),
                versions: Default::default(),
                client_token: input.client_token.clone(),
                version_tokens: Default::default(),
            };
            rec.versions.insert(1, version);
            r.launch_templates.insert(id, rec);
            Ok(t::CreateLaunchTemplateResult { launch_template: Some(template), warning: None })
        })
    }

    fn template_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &Option<String>,
        name: &Option<String>,
        dry_run: Option<bool>,
    ) -> Result<LaunchTemplateRecord, ServiceError> {
        let rec = self.with_region(ctx, |r| find(r, id, name).map(|l| l.clone()))?;
        let lt_id = rec.template.launch_template_id.clone().unwrap_or_default();
        authorize(
            ctx,
            action,
            &[(template_arn(ctx, &account_of(ctx), &lt_id), resource_tag_context(rec.template.tags.as_ref()))],
            dry_run,
        )?;
        Ok(rec)
    }

    pub(crate) fn create_launch_template_version_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateLaunchTemplateVersionRequest,
    ) -> Result<t::CreateLaunchTemplateVersionResult, ServiceError> {
        let rec = self.template_authorize(
            ctx,
            "CreateLaunchTemplateVersion",
            &input.launch_template_id,
            &input.launch_template_name,
            input.dry_run,
        )?;
        validate_data(&input.launch_template_data)?;
        let lt_id = rec.template.launch_template_id.clone().unwrap_or_default();
        let now = ctx.received_at;
        let created_by = ctx.caller.arn.clone();
        self.with_region(ctx, |r| {
            let rec = r.launch_templates.get_mut(&lt_id).ok_or_else(|| not_found_by_id(&lt_id))?;
            if let Some(token) = input.client_token.as_deref().filter(|t| !t.is_empty()) {
                if let Some(v) = rec.version_tokens.get(token).and_then(|n| rec.versions.get(n)) {
                    return Ok(t::CreateLaunchTemplateVersionResult {
                        launch_template_version: Some(v.clone()),
                        warning: None,
                    });
                }
            }
            let mut data = response_data(&input.launch_template_data);
            if let Some(src) = &input.source_version {
                let n = version_number(rec, Some(src))?;
                let base = rec.versions[&n].launch_template_data.clone().unwrap_or_default();
                // The new data overrides the source version's, member by member.
                let mut merged = strip_nulls(serde_json::to_value(&base).unwrap_or_default());
                if let (Value::Object(m), Value::Object(o)) =
                    (&mut merged, strip_nulls(serde_json::to_value(&data).unwrap_or_default()))
                {
                    m.extend(o);
                }
                data = serde_json::from_value(merged).unwrap_or(data);
            }
            let n = rec.template.latest_version_number.unwrap_or(0) + 1;
            rec.template.latest_version_number = Some(n);
            let v = t::LaunchTemplateVersion {
                launch_template_id: rec.template.launch_template_id.clone(),
                launch_template_name: rec.template.launch_template_name.clone(),
                version_number: Some(n),
                version_description: input.version_description.clone(),
                create_time: Some(now),
                created_by: Some(created_by),
                default_version: Some(false),
                launch_template_data: Some(data),
                operator: None,
            };
            rec.versions.insert(n, v.clone());
            if let Some(token) = input.client_token.clone().filter(|t| !t.is_empty()) {
                rec.version_tokens.insert(token, n);
            }
            Ok(t::CreateLaunchTemplateVersionResult { launch_template_version: Some(v), warning: None })
        })
    }

    pub(crate) fn describe_launch_templates_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLaunchTemplatesRequest,
    ) -> Result<t::DescribeLaunchTemplatesResult, ServiceError> {
        authorize(ctx, "DescribeLaunchTemplates", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let ids = input.launch_template_ids.clone().unwrap_or_default();
        let names = input.launch_template_names.clone().unwrap_or_default();
        if !ids.is_empty() && !names.is_empty() {
            return Err(err(
                "InvalidParameterCombination",
                "Specify either the launch template ID or the launch template name in the request, but not both.",
            ));
        }
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            for id in &ids {
                check_id(id)?;
                if !r.launch_templates.contains_key(id) {
                    return Err(not_found_by_id(id));
                }
            }
            for name in &names {
                if !r.launch_templates.values().any(|l| l.template.launch_template_name.as_deref() == Some(name)) {
                    return Err(not_found_by_name());
                }
            }
            let mut out = Vec::new();
            for rec in r.launch_templates.values() {
                let lt = &rec.template;
                if !ids.is_empty() && !ids.contains(lt.launch_template_id.as_ref().unwrap()) {
                    continue;
                }
                if !names.is_empty() && !names.contains(lt.launch_template_name.as_ref().unwrap()) {
                    continue;
                }
                let ok = filters.matches(lt.tags.as_ref(), |n| {
                    Some(match n {
                        "create-time" => {
                            lt.create_time.map(|t| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()).into_iter().collect()
                        }
                        "launch-template-name" => s(&lt.launch_template_name),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(lt.clone());
                }
            }
            out.sort_by_key(|a| a.create_time);
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeLaunchTemplatesResult { launch_templates: Some(items), next_token })
        })
    }

    pub(crate) fn describe_launch_template_versions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLaunchTemplateVersionsRequest,
    ) -> Result<t::DescribeLaunchTemplateVersionsResult, ServiceError> {
        authorize(ctx, "DescribeLaunchTemplateVersions", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let versions = input.versions.clone().unwrap_or_default();
        let named = input.launch_template_id.is_some() || input.launch_template_name.is_some();
        let min = input.min_version.as_deref().map(str::parse::<i64>).transpose().map_err(|_| {
            invalid_parameter(format!(
                "Invalid value '{}' for minVersion",
                input.min_version.clone().unwrap_or_default()
            ))
        })?;
        let max = input.max_version.as_deref().map(str::parse::<i64>).transpose().map_err(|_| {
            invalid_parameter(format!(
                "Invalid value '{}' for maxVersion",
                input.max_version.clone().unwrap_or_default()
            ))
        })?;
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            let templates: Vec<LaunchTemplateRecord> = if named {
                vec![find(r, &input.launch_template_id, &input.launch_template_name)?.clone()]
            } else {
                if versions.is_empty() || versions.iter().any(|v| v != "$Latest" && v != "$Default") {
                    return Err(err(
                        "MissingParameter",
                        "The request must contain the parameter launchTemplateName or launchTemplateId",
                    ));
                }
                r.launch_templates.values().cloned().collect()
            };
            for rec in &templates {
                let wanted: Option<Vec<i64>> = if versions.is_empty() {
                    None
                } else {
                    Some(versions.iter().map(|v| version_number(rec, Some(v))).collect::<Result<_, _>>()?)
                };
                for (n, v) in &rec.versions {
                    if wanted.as_ref().is_some_and(|w| !w.contains(n)) {
                        continue;
                    }
                    if min.is_some_and(|m| *n < m) || max.is_some_and(|m| *n > m) {
                        continue;
                    }
                    if filters.matches(None, |f| version_filter(v, f))? {
                        let mut v = v.clone();
                        v.default_version = Some(rec.template.default_version_number == Some(*n));
                        out.push(v);
                    }
                }
            }
            // Newest first, as EC2 lists them.
            out.sort_by(|a, b| {
                a.launch_template_id.cmp(&b.launch_template_id).then(b.version_number.cmp(&a.version_number))
            });
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeLaunchTemplateVersionsResult { launch_template_versions: Some(items), next_token })
        })
    }

    pub(crate) fn modify_launch_template_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyLaunchTemplateRequest,
    ) -> Result<t::ModifyLaunchTemplateResult, ServiceError> {
        let rec = self.template_authorize(
            ctx,
            "ModifyLaunchTemplate",
            &input.launch_template_id,
            &input.launch_template_name,
            input.dry_run,
        )?;
        let lt_id = rec.template.launch_template_id.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            let rec = r.launch_templates.get_mut(&lt_id).ok_or_else(|| not_found_by_id(&lt_id))?;
            if let Some(v) = &input.default_version {
                let n = match v.as_str() {
                    "$Latest" => rec.template.latest_version_number.unwrap_or(1),
                    other => version_number(rec, Some(other))?,
                };
                rec.template.default_version_number = Some(n);
            }
            Ok(t::ModifyLaunchTemplateResult { launch_template: Some(rec.template.clone()) })
        })
    }

    pub(crate) fn delete_launch_template_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteLaunchTemplateRequest,
    ) -> Result<t::DeleteLaunchTemplateResult, ServiceError> {
        let rec = self.template_authorize(
            ctx,
            "DeleteLaunchTemplate",
            &input.launch_template_id,
            &input.launch_template_name,
            input.dry_run,
        )?;
        let lt_id = rec.template.launch_template_id.clone().unwrap_or_default();
        self.with_region(ctx, |r| r.launch_templates.remove(&lt_id));
        Ok(t::DeleteLaunchTemplateResult { launch_template: Some(rec.template) })
    }

    pub(crate) fn delete_launch_template_versions_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteLaunchTemplateVersionsRequest,
    ) -> Result<t::DeleteLaunchTemplateVersionsResult, ServiceError> {
        let rec = self.template_authorize(
            ctx,
            "DeleteLaunchTemplateVersion",
            &input.launch_template_id,
            &input.launch_template_name,
            input.dry_run,
        )?;
        if input.versions.len() > 200 {
            return Err(invalid_parameter("You can specify a maximum of 200 launch template versions in a request."));
        }
        let lt_id = rec.template.launch_template_id.clone().unwrap_or_default();
        let lt_name = rec.template.launch_template_name.clone();
        self.with_region(ctx, |r| {
            let rec = r.launch_templates.get_mut(&lt_id).ok_or_else(|| not_found_by_id(&lt_id))?;
            let mut ok = Vec::new();
            let mut failed = Vec::new();
            for v in &input.versions {
                let fail =
                    |code: &str, message: String, n: Option<i64>| t::DeleteLaunchTemplateVersionsResponseErrorItem {
                        launch_template_id: Some(lt_id.clone()),
                        launch_template_name: lt_name.clone(),
                        version_number: n,
                        response_error: Some(t::ResponseError { code: Some(code.into()), message: Some(message) }),
                    };
                let n = match v.parse::<i64>() {
                    Ok(n) => n,
                    Err(_) => {
                        failed.push(fail(
                            "launchTemplateVersionDoesNotExist",
                            format!("The specified launch template version does not exist: {v}"),
                            None,
                        ));
                        continue;
                    }
                };
                if !rec.versions.contains_key(&n) {
                    failed.push(fail(
                        "launchTemplateVersionDoesNotExist",
                        "Could not find the specified version for the specified launch template".into(),
                        Some(n),
                    ));
                } else if rec.template.default_version_number == Some(n) {
                    failed.push(fail(
                        "unexpectedError",
                        "Cannot delete the default version of a launch template".into(),
                        Some(n),
                    ));
                } else {
                    rec.versions.remove(&n);
                    ok.push(t::DeleteLaunchTemplateVersionsResponseSuccessItem {
                        launch_template_id: Some(lt_id.clone()),
                        launch_template_name: lt_name.clone(),
                        version_number: Some(n),
                    });
                }
            }
            Ok(t::DeleteLaunchTemplateVersionsResult {
                successfully_deleted_launch_template_versions: Some(ok),
                unsuccessfully_deleted_launch_template_versions: Some(failed),
            })
        })
    }

    pub(crate) fn get_launch_template_data_op(
        &self,
        ctx: &RequestContext,
        input: t::GetLaunchTemplateDataRequest,
    ) -> Result<t::GetLaunchTemplateDataResult, ServiceError> {
        crate::util::Kind::Instance.check(&input.instance_id)?;
        let account = account_of(ctx);
        let (inst, user_data, groups, bdms, profile) = self
            .with_region(ctx, |r| {
                r.instances.get(&input.instance_id).map(|rec| {
                    let i = super::instance::render(r, rec);
                    let bdms: Vec<t::LaunchTemplateBlockDeviceMapping> = i
                        .block_device_mappings
                        .iter()
                        .flatten()
                        .map(|m| {
                            let vol = m.ebs.as_ref().and_then(|e| e.volume_id.as_ref()).and_then(|v| r.volumes.get(v));
                            t::LaunchTemplateBlockDeviceMapping {
                                device_name: m.device_name.clone(),
                                ebs: Some(t::LaunchTemplateEbsBlockDevice {
                                    delete_on_termination: m.ebs.as_ref().and_then(|e| e.delete_on_termination),
                                    encrypted: vol.and_then(|v| v.encrypted),
                                    iops: vol.and_then(|v| v.iops),
                                    snapshot_id: vol.and_then(|v| v.snapshot_id.clone()).filter(|s| !s.is_empty()),
                                    volume_size: vol.and_then(|v| v.size),
                                    volume_type: vol.and_then(|v| v.volume_type.clone()),
                                    throughput: vol.and_then(|v| v.throughput),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }
                        })
                        .collect();
                    let profile = r
                        .iam_associations
                        .values()
                        .find(|a| {
                            a.instance_id.as_deref() == Some(input.instance_id.as_str())
                                && a.state.as_deref() == Some("associated")
                        })
                        .and_then(|a| a.iam_instance_profile.clone());
                    let groups: Vec<String> =
                        i.security_groups.iter().flatten().filter_map(|g| g.group_id.clone()).collect();
                    (i, rec.user_data.clone(), groups, bdms, profile)
                })
            })
            .ok_or_else(|| crate::util::Kind::Instance.not_found(&input.instance_id))?;
        authorize(
            ctx,
            "GetLaunchTemplateData",
            &[(
                arn(ctx, &account, &format!("instance/{}", input.instance_id)),
                resource_tag_context(inst.tags.as_ref()),
            )],
            input.dry_run,
        )?;
        let data = t::ResponseLaunchTemplateData {
            ebs_optimized: inst.ebs_optimized,
            iam_instance_profile: profile
                .map(|p| t::LaunchTemplateIamInstanceProfileSpecification { arn: p.arn, name: None }),
            block_device_mappings: Some(bdms),
            network_interfaces: Some(vec![t::LaunchTemplateInstanceNetworkInterfaceSpecification {
                associate_public_ip_address: Some(inst.public_ip_address.is_some()),
                delete_on_termination: Some(true),
                device_index: Some(0),
                groups: Some(groups),
                subnet_id: inst.subnet_id.clone(),
                private_ip_address: inst.private_ip_address.clone(),
                network_card_index: Some(0),
                ..Default::default()
            }]),
            image_id: inst.image_id.clone(),
            instance_type: inst.instance_type.clone(),
            key_name: inst.key_name.clone(),
            monitoring: Some(t::LaunchTemplatesMonitoring {
                enabled: Some(inst.monitoring.as_ref().and_then(|m| m.state.as_deref()) == Some("enabled")),
            }),
            placement: inst.placement.as_ref().map(|p| t::LaunchTemplatePlacement {
                availability_zone: p.availability_zone.clone(),
                group_name: p.group_name.clone(),
                tenancy: p.tenancy.clone(),
                ..Default::default()
            }),
            user_data,
            tag_specifications: inst.tags.as_ref().filter(|t| !t.is_empty()).map(|tags| {
                vec![t::LaunchTemplateTagSpecification {
                    resource_type: Some("instance".into()),
                    tags: Some(
                        tags.iter().filter(|t| !t.key.as_deref().unwrap_or("").starts_with("aws:")).cloned().collect(),
                    ),
                }]
            }),
            metadata_options: inst.metadata_options.as_ref().map(|m| t::LaunchTemplateInstanceMetadataOptions {
                state: Some("applied".into()),
                http_tokens: m.http_tokens.clone(),
                http_put_response_hop_limit: m.http_put_response_hop_limit,
                http_endpoint: m.http_endpoint.clone(),
                http_protocol_ipv6: m.http_protocol_ipv6.clone(),
                instance_metadata_tags: m.instance_metadata_tags.clone(),
            }),
            disable_api_termination: None,
            ..Default::default()
        };
        Ok(t::GetLaunchTemplateDataResult { launch_template_data: Some(data) })
    }

    /// Resolve a launch template and version as `RunInstances` (and EC2
    /// Auto Scaling) does.
    pub fn resolve_launch_template(
        &self,
        ctx: &RequestContext,
        spec: &t::LaunchTemplateSpecification,
    ) -> Result<ResolvedLaunchTemplate, ServiceError> {
        self.with_region(ctx, |r| {
            let rec = find(r, &spec.launch_template_id, &spec.launch_template_name)?;
            let n = version_number(rec, spec.version.as_deref())?;
            Ok(ResolvedLaunchTemplate {
                id: rec.template.launch_template_id.clone().unwrap_or_default(),
                name: rec.template.launch_template_name.clone().unwrap_or_default(),
                version: n,
                data: rec.versions[&n].launch_template_data.clone().unwrap_or_default(),
            })
        })
    }
}
