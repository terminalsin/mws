//! Creating, reading, versioning, labelling and deleting parameters.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{
    self, key, not_found, now, request_tag_conditions, valid_label, version_not_found, ParamRef, Selector,
    SECRETS_PREFIX,
};
use crate::state::{Parameter, Version};
use crate::{policies, secure, settings, sweep, Ssm};

pub const STANDARD_MAX: usize = 4096;
pub const ADVANCED_MAX: usize = 8192;
const MAX_VERSIONS: usize = 100;
const MAX_STANDARD_PARAMETERS: usize = 10_000;
const MAX_ADVANCED_PARAMETERS: usize = 100_000;
const DATA_TYPES: &[&str] = &["text", "aws:ec2:image", "aws:ssm:integration"];

fn is_ami_id(v: &str) -> bool {
    v.strip_prefix("ami-").is_some_and(|h| (h.len() == 8 || h.len() == 17) && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The version `r` selects in `p`.
pub(crate) fn select<'a>(p: &'a Parameter, r: &ParamRef) -> Result<&'a Version, ServiceError> {
    match &r.selector {
        None => Ok(p.latest()),
        Some(Selector::Version(n)) => p.version(*n).ok_or_else(|| version_not_found(&r.name, &n.to_string())),
        Some(Selector::Label(l)) => p.labelled(l).ok_or_else(|| not_found(&format!("{}:{l}", r.name))),
    }
}

/// The value as the caller sees it.
pub(crate) fn shown_value(
    ssm: &Ssm,
    ctx: &RequestContext,
    arn: &str,
    v: &Version,
    decrypt: bool,
) -> Result<String, ServiceError> {
    if decrypt && v.param_type == "SecureString" {
        secure::open(&ssm.kms, ctx, arn, &v.value)
    } else {
        Ok(v.value.clone())
    }
}

pub(crate) fn inline_policies(v: &Version) -> Option<Vec<types::ParameterInlinePolicy>> {
    Some(
        v.policies
            .iter()
            .map(|p| types::ParameterInlinePolicy {
                policy_text: Some(p.text.clone()),
                policy_type: Some(p.policy_type.clone()),
                policy_status: Some(p.status.clone()),
            })
            .collect(),
    )
}

impl Ssm {
    /// Render a version as `GetParameter` returns it.
    pub(crate) fn render(
        &self,
        ctx: &RequestContext,
        r: &ParamRef,
        v: &Version,
        decrypt: bool,
    ) -> Result<types::Parameter, ServiceError> {
        let arn = r.arn();
        Ok(types::Parameter {
            name: Some(if r.by_arn { arn.clone() } else { v.name.clone() }),
            r#type: Some(v.param_type.clone()),
            value: Some(shown_value(self, ctx, &arn, v, decrypt)?),
            version: v.version,
            selector: r.selector.as_ref().map(Selector::text),
            source_result: None,
            last_modified_date: Some(v.last_modified_date),
            arn: Some(arn),
            data_type: Some(v.data_type.clone()),
        })
    }

    /// Look a parameter up for reading: authorize `action` on it, then find
    /// the version the name selects.
    pub(crate) fn read(
        &self,
        ctx: &RequestContext,
        action: &str,
        input: &str,
        decrypt: bool,
    ) -> Result<types::Parameter, ServiceError> {
        if input.starts_with(SECRETS_PREFIX) {
            return self.read_secret_reference(ctx, action, input, decrypt);
        }
        if let Some(name) = crate::public::public_name(ctx, input) {
            return crate::public::read(ctx, action, input, &name);
        }
        let r = ParamRef::parse(ctx, input).ok_or_else(|| not_found(input))?;
        let p = self.snapshot(ctx, &r);
        self.authorize_param(ctx, action, &r, p.as_ref(), ConditionContext::new())?;
        let p = p.ok_or_else(|| not_found(input))?;
        let v = select(&p, &r)?;
        self.render(ctx, &r, v, decrypt)
    }

    pub(crate) fn get_parameter(
        &self,
        ctx: &RequestContext,
        input: types::GetParameterRequest,
    ) -> Result<types::GetParameterResult, ServiceError> {
        let p = self.read(ctx, "GetParameter", &input.name, input.with_decryption.unwrap_or(false))?;
        Ok(types::GetParameterResult { parameter: Some(p) })
    }

    pub(crate) fn get_parameters(
        &self,
        ctx: &RequestContext,
        input: types::GetParametersRequest,
    ) -> Result<types::GetParametersResult, ServiceError> {
        let decrypt = input.with_decryption.unwrap_or(false);
        let mut parameters = Vec::new();
        let mut invalid = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for name in input.names {
            if !seen.insert(name.clone()) {
                continue;
            }
            match self.read(ctx, "GetParameters", &name, decrypt) {
                Ok(p) => parameters.push(p),
                Err(e) if e.code == "ParameterNotFound" || e.code == "ParameterVersionNotFound" => invalid.push(name),
                Err(e) => return Err(e),
            }
        }
        Ok(types::GetParametersResult { parameters: Some(parameters), invalid_parameters: Some(invalid) })
    }

    pub(crate) fn put_parameter(
        &self,
        ctx: &RequestContext,
        input: types::PutParameterRequest,
    ) -> Result<types::PutParameterResult, ServiceError> {
        let name = input.name.trim().to_string();
        names::validate_new_name(ctx, &name)?;
        let r = ParamRef::own(ctx, &name);
        let overwrite = input.overwrite.unwrap_or(false);
        let tags: BTreeMap<String, String> =
            input.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        let existing = self.snapshot(ctx, &r);

        let mut cond = ConditionContext::new();
        cond.insert("ssm:Overwrite".into(), vec![overwrite.to_string()]);
        if let Some(p) = &input.policies {
            cond.insert("ssm:Policies".into(), vec![p.clone()]);
        }
        cond.extend(request_tag_conditions(&tags));
        self.authorize_param(ctx, "PutParameter", &r, existing.as_ref(), cond)?;
        if !tags.is_empty() {
            self.authorize_param(ctx, "AddTagsToResource", &r, existing.as_ref(), request_tag_conditions(&tags))?;
        }

        if overwrite && !tags.is_empty() {
            return Err(errors::validation(
                "Invalid request: tags and overwrite can't be used together. To create a parameter with tags, please remove overwrite flag. To update tags for an existing parameter, please use AddTagsToResource or RemoveTagsFromResource.",
            ));
        }
        if tags.len() > 50 {
            return Err(errors::too_many_tags_error(
                "The Targets parameter includes too many tags. Remove one or more tags and try the command again.",
            ));
        }
        if input.value.is_empty() {
            return Err(errors::validation(
                "1 validation error detected: Value '' at 'value' failed to satisfy constraint: Member must have length greater than or equal to 1.",
            ));
        }
        if input.value.contains("{{") && input.value.contains("}}") {
            return Err(errors::validation(
                "Parameter value can't nest another parameter. Do not use \"{{}}\" in the value.",
            ));
        }
        let previous = existing.as_ref().map(|p| p.latest().clone());
        if previous.is_some() {
            if !overwrite {
                return Err(errors::parameter_already_exists(
                    "The parameter already exists. To overwrite this value, set the overwrite option in the request to true.",
                ));
            }
            let p = existing.as_ref().expect("previous comes from existing");
            if p.versions.len() >= MAX_VERSIONS && !p.versions[0].labels.is_empty() {
                return Err(errors::parameter_max_version_limit_exceeded(format!(
                    "You attempted to create a new version of {name} by calling the PutParameter API with the overwrite flag. Version {}, the oldest version, can't be deleted because it has a label associated with it. Move the label to another version of the parameter, and try again.",
                    p.versions[0].version
                )));
            }
        }

        let param_type = match (&input.r#type, &previous) {
            (Some(t), _) => t.clone(),
            (None, Some(prev)) => prev.param_type.clone(),
            (None, None) => {
                return Err(errors::validation("A parameter type is required when you create a parameter."))
            }
        };
        let data_type = input
            .data_type
            .clone()
            .filter(|d| !d.is_empty())
            .or_else(|| previous.as_ref().map(|p| p.data_type.clone()))
            .unwrap_or_else(|| "text".into());
        if !DATA_TYPES.contains(&data_type.as_str()) {
            return Err(errors::validation(format!(
                "The following data type is not supported: {data_type} (Data type names are all lowercase.)"
            )));
        }
        if data_type != "text" && param_type != "String" {
            return Err(errors::validation(format!(
                "The data type {data_type} is only supported for parameters of type String."
            )));
        }
        if input.key_id.is_some() && param_type != "SecureString" {
            return Err(errors::validation("KeyId is required for SecureString type parameter only."));
        }
        let key_id = if param_type == "SecureString" {
            Some(
                input
                    .key_id
                    .clone()
                    .or_else(|| previous.as_ref().and_then(|p| p.key_id.clone()))
                    .unwrap_or_else(|| secure::DEFAULT_KEY.into()),
            )
        } else {
            None
        };
        let description = input.description.clone().or_else(|| previous.as_ref().and_then(|p| p.description.clone()));
        let allowed_pattern =
            input.allowed_pattern.clone().or_else(|| previous.as_ref().and_then(|p| p.allowed_pattern.clone()));
        if let Some(pattern) = allowed_pattern.as_deref().filter(|p| !p.is_empty()) {
            let re = regex::Regex::new(pattern).map_err(|_| {
                errors::invalid_allowed_pattern(format!(
                    "The allowed pattern {pattern} isn't a valid regular expression."
                ))
            })?;
            if !re.is_match(&input.value) {
                return Err(errors::parameter_pattern_mismatch(format!(
                    "Parameter value, cannot be validated against allowedPattern: {pattern}"
                )));
            }
        }
        let policies = match &input.policies {
            Some(text) => policies::parse(text, now(ctx))?,
            None => previous.as_ref().map(|p| p.policies.clone()).unwrap_or_default(),
        };

        // The tier: as asked, else the account's default tier.
        let default_tier = {
            let st = self.lock();
            settings::default_tier(st.region_ref(&r.account, &r.region))
        };
        let was_advanced = previous.as_ref().is_some_and(|p| p.tier == "Advanced");
        let requested = input.tier.clone().unwrap_or_else(|| default_tier.clone());
        let tier = match requested.as_str() {
            "Advanced" => "Advanced",
            "Intelligent-Tiering" => {
                if was_advanced || input.value.len() > STANDARD_MAX || !policies.is_empty() {
                    "Advanced"
                } else {
                    "Standard"
                }
            }
            _ if was_advanced => {
                if input.tier.is_some() {
                    return Err(errors::validation(
                        "This parameter uses the advanced-parameter tier. You can't downgrade a parameter from the advanced-parameter tier to the standard-parameter tier. If necessary, you can delete the advanced parameter and recreate it as a standard parameter.",
                    ));
                }
                "Advanced"
            }
            _ => "Standard",
        };
        if tier == "Standard" && input.value.len() > STANDARD_MAX {
            return Err(errors::validation(
                "Standard tier parameters support a maximum parameter value of 4096 characters. To create a larger parameter value, upgrade the parameter to use the advanced-parameter tier. For more information, see https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-advanced-parameters.html",
            ));
        }
        if tier == "Advanced" && input.value.len() > ADVANCED_MAX {
            return Err(errors::validation(format!(
                "1 validation error detected: Value at 'value' failed to satisfy constraint: Member must have length less than or equal to {ADVANCED_MAX}."
            )));
        }
        if tier == "Standard" && !policies.is_empty() {
            return Err(errors::validation(
                "Parameter policies are supported only for advanced-tier parameters. Upgrade the parameter to the advanced-parameter tier, and try again.",
            ));
        }

        let value = match &key_id {
            Some(k) => secure::seal(&self.kms, ctx, k, tier == "Advanced", &r.arn(), &input.value)?,
            None => input.value.clone(),
        };
        let version_number = previous.as_ref().map_or(1, |p| p.version + 1);
        let version = Version {
            version: version_number,
            name: previous.as_ref().map_or_else(|| name.clone(), |p| p.name.clone()),
            param_type,
            value,
            key_id,
            description,
            allowed_pattern,
            tier: tier.to_string(),
            policies,
            data_type: data_type.clone(),
            labels: Vec::new(),
            last_modified_date: now(ctx),
            last_modified_user: ctx.caller.arn.clone(),
        };

        // AWS validates aws:ec2:image values asynchronously after answering;
        // an invalid AMI ID is never stored.
        let stored = data_type != "aws:ec2:image" || is_ami_id(&input.value);

        let mut st = self.lock();
        let region = st.region(&r.account, &r.region);
        sweep(region, now(ctx));
        let k = key(&name);
        let current = region.parameters.get(&k).map(|p| p.latest().version);
        if current != previous.as_ref().map(|p| p.version) {
            return Err(errors::too_many_updates(
                "There are concurrent updates for a resource that supports one update at a time.",
            ));
        }
        if current.is_none() {
            let (limit, count) = if tier == "Advanced" {
                (MAX_ADVANCED_PARAMETERS, region.parameters.values().filter(|p| p.latest().tier == "Advanced").count())
            } else {
                (MAX_STANDARD_PARAMETERS, region.parameters.values().filter(|p| p.latest().tier != "Advanced").count())
            };
            if count >= limit {
                return Err(errors::parameter_limit_exceeded(
                    "You have exceeded the number of parameters for this AWS account. Delete one or more parameters and try again.",
                ));
            }
        }
        if stored {
            let p = region.parameters.entry(k).or_default();
            if p.versions.is_empty() {
                p.tags = tags;
            }
            p.versions.push(version);
            if p.versions.len() > MAX_VERSIONS {
                p.versions.remove(0);
            }
        }
        Ok(types::PutParameterResult { version: version_number, tier: Some(tier.to_string()) })
    }

    pub(crate) fn delete_parameter(
        &self,
        ctx: &RequestContext,
        input: types::DeleteParameterRequest,
    ) -> Result<types::DeleteParameterResult, ServiceError> {
        self.delete_one(ctx, "DeleteParameter", &input.name)?;
        Ok(types::DeleteParameterResult::default())
    }

    fn delete_one(&self, ctx: &RequestContext, action: &str, name: &str) -> Result<(), ServiceError> {
        let r = ParamRef::parse(ctx, name).filter(|r| r.selector.is_none()).ok_or_else(|| not_found(name))?;
        let p = self.snapshot(ctx, &r);
        self.authorize_param(ctx, action, &r, p.as_ref(), ConditionContext::new())?;
        let mut st = self.lock();
        st.region(&r.account, &r.region).parameters.remove(&r.key()).map(|_| ()).ok_or_else(|| not_found(name))
    }

    pub(crate) fn delete_parameters(
        &self,
        ctx: &RequestContext,
        input: types::DeleteParametersRequest,
    ) -> Result<types::DeleteParametersResult, ServiceError> {
        let mut deleted = Vec::new();
        let mut invalid = Vec::new();
        for name in input.names {
            match self.delete_one(ctx, "DeleteParameters", &name) {
                Ok(()) => deleted.push(name),
                Err(e) if e.code == "ParameterNotFound" => invalid.push(name),
                Err(e) => return Err(e),
            }
        }
        Ok(types::DeleteParametersResult { deleted_parameters: Some(deleted), invalid_parameters: Some(invalid) })
    }

    pub(crate) fn get_parameter_history(
        &self,
        ctx: &RequestContext,
        input: types::GetParameterHistoryRequest,
    ) -> Result<types::GetParameterHistoryResult, ServiceError> {
        let decrypt = input.with_decryption.unwrap_or(false);
        let r =
            ParamRef::parse(ctx, &input.name).filter(|r| r.selector.is_none()).ok_or_else(|| not_found(&input.name))?;
        let p = self.snapshot(ctx, &r);
        self.authorize_param(ctx, "GetParameterHistory", &r, p.as_ref(), ConditionContext::new())?;
        let p = p.ok_or_else(|| not_found(&input.name))?;
        let (versions, next) =
            names::page(p.versions, input.next_token.as_deref(), input.max_results.unwrap_or(50) as usize)?;
        let arn = r.arn();
        let mut out = Vec::new();
        for v in versions {
            out.push(types::ParameterHistory {
                name: Some(if r.by_arn { arn.clone() } else { v.name.clone() }),
                r#type: Some(v.param_type.clone()),
                key_id: v.key_id.clone(),
                last_modified_date: Some(v.last_modified_date),
                last_modified_user: Some(v.last_modified_user.clone()),
                description: v.description.clone(),
                value: Some(shown_value(self, ctx, &arn, &v, decrypt)?),
                allowed_pattern: v.allowed_pattern.clone(),
                version: v.version,
                labels: Some(v.labels.clone()),
                tier: Some(v.tier.clone()),
                policies: inline_policies(&v),
                data_type: Some(v.data_type.clone()),
            });
        }
        Ok(types::GetParameterHistoryResult { parameters: Some(out), next_token: next })
    }

    pub(crate) fn label_parameter_version(
        &self,
        ctx: &RequestContext,
        input: types::LabelParameterVersionRequest,
    ) -> Result<types::LabelParameterVersionResult, ServiceError> {
        let r =
            ParamRef::parse(ctx, &input.name).filter(|r| r.selector.is_none()).ok_or_else(|| not_found(&input.name))?;
        let p = self.snapshot(ctx, &r);
        self.authorize_param(ctx, "LabelParameterVersion", &r, p.as_ref(), ConditionContext::new())?;
        let mut st = self.lock();
        let p = st.region(&r.account, &r.region).parameters.get_mut(&r.key()).ok_or_else(|| not_found(&input.name))?;
        let version = input.parameter_version.unwrap_or_else(|| p.latest().version);
        let idx = p
            .versions
            .iter()
            .position(|v| v.version == version)
            .ok_or_else(|| version_not_found(&input.name, &version.to_string()))?;
        let (valid, invalid): (Vec<String>, Vec<String>) = input.labels.into_iter().partition(|l| valid_label(l));
        let mut labels = p.versions[idx].labels.clone();
        for l in &valid {
            if !labels.contains(l) {
                labels.push(l.clone());
            }
        }
        if labels.len() > 10 {
            return Err(errors::parameter_version_label_limit_exceeded(
                "A parameter version can have maximum 10 labels.Move one or more labels to another version and try again.",
            ));
        }
        for (i, v) in p.versions.iter_mut().enumerate() {
            if i == idx {
                v.labels = labels.clone();
            } else {
                v.labels.retain(|l| !valid.contains(l));
            }
        }
        Ok(types::LabelParameterVersionResult { invalid_labels: Some(invalid), parameter_version: version })
    }

    pub(crate) fn unlabel_parameter_version(
        &self,
        ctx: &RequestContext,
        input: types::UnlabelParameterVersionRequest,
    ) -> Result<types::UnlabelParameterVersionResult, ServiceError> {
        let r =
            ParamRef::parse(ctx, &input.name).filter(|r| r.selector.is_none()).ok_or_else(|| not_found(&input.name))?;
        let p = self.snapshot(ctx, &r);
        self.authorize_param(ctx, "UnlabelParameterVersion", &r, p.as_ref(), ConditionContext::new())?;
        let mut st = self.lock();
        let p = st.region(&r.account, &r.region).parameters.get_mut(&r.key()).ok_or_else(|| not_found(&input.name))?;
        let v = p
            .versions
            .iter_mut()
            .find(|v| v.version == input.parameter_version)
            .ok_or_else(|| version_not_found(&input.name, &input.parameter_version.to_string()))?;
        let mut removed = Vec::new();
        let mut invalid = Vec::new();
        for l in input.labels {
            if let Some(i) = v.labels.iter().position(|x| *x == l) {
                v.labels.remove(i);
                removed.push(l);
            } else {
                invalid.push(l);
            }
        }
        Ok(types::UnlabelParameterVersionResult { removed_labels: Some(removed), invalid_labels: Some(invalid) })
    }
}
