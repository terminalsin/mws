//! `GetParametersByPath`, `DescribeParameters` and their filters.

use mws_core::{AuthzDecision, ConditionContext, RequestContext, ResourcePolicyMode, ServiceError};

use crate::generated::{errors, types};
use crate::names::{self, now, rooted, under_path, ParamRef};
use crate::params::inline_policies;
use crate::state::{Parameter, Version};
use crate::{sweep, Ssm};

/// A validated `ParameterStringFilter`.
struct Filter {
    key: String,
    option: String,
    values: Vec<String>,
}

const TYPES: &[&str] = &["String", "StringList", "SecureString"];
const TIERS: &[&str] = &["Standard", "Advanced", "Intelligent-Tiering"];

fn validate_filters(filters: Vec<types::ParameterStringFilter>, by_path: bool) -> Result<Vec<Filter>, ServiceError> {
    let mut out: Vec<Filter> = Vec::new();
    for f in filters {
        let key = f.key;
        let option = f.option.unwrap_or_else(|| if key == "Path" { "OneLevel".into() } else { "Equals".into() });
        let values = f.values.unwrap_or_default();
        if by_path && matches!(key.as_str(), "Name" | "Path" | "Tier") {
            return Err(errors::invalid_filter_key(format!(
                "The following filter key is not valid: {key}. Valid filter keys include: [Type, KeyId, Label, DataType]."
            )));
        }
        if !by_path && key == "Label" {
            return Err(errors::invalid_filter_key(
                "The following filter key is not valid: Label. Valid filter keys include: [Path, Name, Type, KeyId, Tier, DataType].",
            ));
        }
        if !key.starts_with("tag:") && values.is_empty() {
            return Err(errors::invalid_filter_value(format!(
                "The following filter values are missing : null for filter key {key}."
            )));
        }
        if out.iter().any(|o| o.key == key) {
            return Err(errors::invalid_filter_key(format!(
                "The following filter is duplicated in the request: {key}. A request can contain only one occurrence of a specific filter."
            )));
        }
        match key.as_str() {
            "Path" => {
                if !matches!(option.as_str(), "Recursive" | "OneLevel") {
                    return Err(errors::invalid_filter_option(format!(
                        "The following filter option is not valid: {option}. Valid options include: [Recursive, OneLevel]."
                    )));
                }
                for v in &values {
                    let l = v.to_ascii_lowercase();
                    if l.starts_with("/aws") || l.starts_with("/ssm") {
                        return Err(errors::validation(
                            "Filters for common parameters can't be prefixed with \"aws\" or \"ssm\" (case-insensitive). When using global parameters, please specify within a global namespace.",
                        ));
                    }
                    names::validate_path(v)?;
                }
            }
            _ => {
                let allowed: &[&str] = match key.as_str() {
                    "Name" => &["Equals", "BeginsWith", "Contains"],
                    "Label" => &["Equals"],
                    _ => &["Equals", "BeginsWith"],
                };
                if !allowed.contains(&option.as_str()) {
                    return Err(errors::invalid_filter_option(format!(
                        "The following filter option is not valid: {option}. Valid options include: [{}].",
                        allowed.join(", ")
                    )));
                }
            }
        }
        let enumerated: Option<(&str, &[&str])> = match key.as_str() {
            "Type" => Some(("String, StringList, SecureString", TYPES)),
            "Tier" => Some(("Standard, Advanced, Intelligent-Tiering", TIERS)),
            _ => None,
        };
        if let Some((list, valid)) = enumerated {
            if option == "Equals" {
                if let Some(bad) = values.iter().find(|v| !valid.contains(&v.as_str())) {
                    return Err(errors::invalid_filter_value(format!(
                        "The following filter value is not valid: {bad}. Valid values include: [{list}]."
                    )));
                }
            }
        }
        out.push(Filter { key, option, values });
    }
    Ok(out)
}

fn compare(option: &str, what: &str, values: &[String]) -> bool {
    match option {
        "BeginsWith" => values.iter().any(|v| what.starts_with(v.as_str())),
        "Contains" => values.iter().any(|v| what.contains(v.as_str())),
        _ => values.iter().any(|v| v == what),
    }
}

/// Whether `v` (the version a filter picked) of `p` passes every filter.
fn matches(p: &Parameter, v: &Version, filters: &[Filter]) -> bool {
    filters.iter().all(|f| match f.key.as_str() {
        "Name" => {
            let name = rooted(&v.name);
            if f.option == "Contains" {
                compare("Contains", &v.name, &f.values)
            } else {
                let vals: Vec<String> = f.values.iter().map(|x| rooted(x)).collect();
                compare(&f.option, &name, &vals)
            }
        }
        "Path" => f.values.iter().any(|path| under_path(&v.name, path, f.option == "Recursive")),
        "Type" => compare(&f.option, &v.param_type, &f.values),
        "KeyId" => v.key_id.as_deref().is_some_and(|k| compare(&f.option, k, &f.values)),
        "Tier" => {
            // Intelligent-Tiering parameters are stored in one of the two.
            compare(&f.option, &v.tier, &f.values) || f.values.iter().any(|x| x == "Intelligent-Tiering")
        }
        "DataType" => compare(&f.option, &v.data_type, &f.values),
        "Label" => v.labels.iter().any(|l| f.values.contains(l)),
        k => {
            let tag = &k[4..];
            match p.tags.get(tag) {
                None => false,
                Some(_) if f.values.is_empty() => true,
                Some(t) => compare(&f.option, t, &f.values),
            }
        }
    })
}

/// `ParametersFilter`, the older `Filters` of `DescribeParameters`.
fn matches_legacy(v: &Version, filters: &[types::ParametersFilter]) -> bool {
    filters.iter().all(|f| match f.key.as_str() {
        "Name" => f.values.iter().any(|x| rooted(&v.name).starts_with(&rooted(x))),
        "Type" => f.values.contains(&v.param_type),
        "KeyId" => v.key_id.as_ref().is_some_and(|k| f.values.contains(k)),
        _ => false,
    })
}

impl Ssm {
    pub(crate) fn get_parameters_by_path(
        &self,
        ctx: &RequestContext,
        input: types::GetParametersByPathRequest,
    ) -> Result<types::GetParametersByPathResult, ServiceError> {
        let path = input.path.trim().to_string();
        names::validate_path(&path)?;
        let recursive = input.recursive.unwrap_or(false);
        let decrypt = input.with_decryption.unwrap_or(false);
        let path_ref = ParamRef::own(ctx, path.trim_end_matches('/'));
        let mut cond = ConditionContext::new();
        cond.insert("ssm:Recursive".into(), vec![recursive.to_string()]);
        ctx.authorize("ssm:GetParametersByPath", &path_ref.arn(), cond)?;
        let filters = validate_filters(input.parameter_filters.unwrap_or_default(), true)?;
        let label = filters.iter().find(|f| f.key == "Label").map(|f| f.values.clone());

        let found: Vec<(ParamRef, Version)> = {
            let mut st = self.lock();
            let region = st.region(&ctx.caller.account_id, &ctx.region);
            sweep(region, now(ctx));
            region
                .parameters
                .values()
                .filter(|p| under_path(&p.latest().name, &path, recursive))
                .filter_map(|p| {
                    let v = match &label {
                        Some(labels) => {
                            p.versions.iter().rev().find(|v| v.labels.iter().any(|l| labels.contains(l)))?
                        }
                        None => p.latest(),
                    };
                    matches(p, v, &filters).then(|| (ParamRef::own(ctx, &v.name), v.clone()))
                })
                .collect()
        };
        let (found, next) = names::page(found, input.next_token.as_deref(), input.max_results.unwrap_or(10) as usize)?;
        let mut out = Vec::new();
        for (r, v) in found {
            out.push(self.render(ctx, &r, &v, decrypt)?);
        }
        Ok(types::GetParametersByPathResult { parameters: Some(out), next_token: next })
    }

    pub(crate) fn describe_parameters(
        &self,
        ctx: &RequestContext,
        input: types::DescribeParametersRequest,
    ) -> Result<types::DescribeParametersResult, ServiceError> {
        ctx.authorize("ssm:DescribeParameters", "*", ConditionContext::new())?;
        let legacy = input.filters.unwrap_or_default();
        let filters = input.parameter_filters.unwrap_or_default();
        if !legacy.is_empty() && !filters.is_empty() {
            return Err(errors::validation("You can use either Filters or ParameterFilters in a single request."));
        }
        let filters = validate_filters(filters, false)?;
        let shared = input.shared.unwrap_or(false);

        let candidates: Vec<(ParamRef, Parameter)> = {
            let mut st = self.lock();
            let now = now(ctx);
            let suffix = format!("/{}", ctx.region);
            let own = format!("{}/{}", ctx.caller.account_id, ctx.region);
            st.regions
                .iter_mut()
                .filter(|(k, _)| if shared { k.ends_with(&suffix) && **k != own } else { **k == own })
                .flat_map(|(k, region)| {
                    sweep(region, now);
                    let account = k.split('/').next().unwrap_or_default().to_string();
                    region
                        .parameters
                        .values()
                        .filter(|p| !shared || !p.resource_policies.is_empty())
                        .map(|p| {
                            let mut r = ParamRef::own(ctx, &p.latest().name);
                            r.account = account.clone();
                            r.by_arn = shared;
                            (r, p.clone())
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let mut found = Vec::new();
        for (r, p) in candidates {
            let v = p.latest();
            if !matches(&p, v, &filters) || !matches_legacy(v, &legacy) {
                continue;
            }
            if shared {
                let policy = p.policy_document();
                let decision = ctx.check(
                    "ssm:DescribeParameters",
                    &r.arn(),
                    policy.as_deref(),
                    ResourcePolicyMode::Required,
                    ConditionContext::new(),
                );
                if decision != AuthzDecision::Allow {
                    continue;
                }
            }
            found.push(types::ParameterMetadata {
                name: Some(r.shown()),
                arn: Some(r.arn()),
                r#type: Some(v.param_type.clone()),
                key_id: v.key_id.clone(),
                last_modified_date: Some(v.last_modified_date),
                last_modified_user: Some(v.last_modified_user.clone()),
                description: v.description.clone(),
                allowed_pattern: v.allowed_pattern.clone(),
                version: v.version,
                tier: Some(v.tier.clone()),
                policies: inline_policies(v),
                data_type: Some(v.data_type.clone()),
            });
        }
        let (page, next) = names::page(found, input.next_token.as_deref(), input.max_results.unwrap_or(50) as usize)?;
        Ok(types::DescribeParametersResult { parameters: Some(page), next_token: next })
    }
}
