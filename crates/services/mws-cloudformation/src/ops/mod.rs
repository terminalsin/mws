//! Operation handlers.

mod change_sets;
mod convert;
mod drift;
mod handler;
mod info;
mod stacks;

use std::collections::{BTreeMap, BTreeSet};

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Value};

use crate::engine::EvalData;
use crate::intrinsics::{evaluate_conditions, Pseudo};
use crate::parameters::{self, Provided, StackParameter};
use crate::providers::is_custom;
use crate::state::{Stack, State};
use crate::template::{format_error, Template};
use crate::CloudFormation;

pub(crate) fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationError", 400, message)
}

pub(crate) fn not_found(name: &str) -> ServiceError {
    validation(format!("Stack with id {name} does not exist"))
}

/// A new stack id.
pub(crate) fn new_stack_id(ctx: &RequestContext, name: &str) -> String {
    format!(
        "arn:{}:cloudformation:{}:{}:stack/{name}/{}",
        ctx.partition,
        ctx.region,
        ctx.caller.account_id,
        uuid::Uuid::new_v4()
    )
}

/// The ARN to authorize against for a stack that may not exist yet.
pub(crate) fn stack_resource(ctx: &RequestContext, name: &str) -> String {
    if name.starts_with("arn:") {
        return name.to_string();
    }
    format!("arn:{}:cloudformation:{}:{}:stack/{name}/*", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// Find a live stack by name, or any stack (deleted ones too) by id.
pub(crate) fn find<'a>(st: &'a State, ctx: &RequestContext, name: &str) -> Result<&'a Stack, ServiceError> {
    let account = &ctx.caller.account_id;
    let found = if name.starts_with("arn:") {
        st.stacks.get(name).filter(|s| &s.account == account && s.region == ctx.region)
    } else {
        st.stacks
            .values()
            .find(|s| s.name == name && !s.is_deleted() && &s.account == account && s.region == ctx.region)
    };
    found.ok_or_else(|| not_found(name))
}

pub(crate) fn find_id(st: &State, ctx: &RequestContext, name: &str) -> Result<String, ServiceError> {
    find(st, ctx, name).map(|s| s.id.clone())
}

/// Exports in an account and region, by name.
pub(crate) fn exports(st: &State, account: &str, region: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for s in st.stacks.values() {
        if s.is_deleted() || s.account != account || s.region != region {
            continue;
        }
        for o in &s.outputs {
            if let Some(n) = &o.export_name {
                out.insert(n.clone(), o.value.clone());
            }
        }
    }
    out
}

pub(crate) fn condition_keys(pairs: &[(&str, Vec<String>)]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for (k, v) in pairs {
        if !v.is_empty() {
            c.insert((*k).to_string(), v.clone());
        }
    }
    c
}

impl CloudFormation {
    /// The template text a request names, fetching `TemplateURL` from S3.
    pub(crate) async fn template_text(
        &self,
        ctx: &RequestContext,
        body: Option<&str>,
        url: Option<&str>,
    ) -> Result<String, ServiceError> {
        match (body, url) {
            (Some(_), Some(_)) => Err(validation("Specify exactly one of TemplateBody or TemplateUrl.")),
            (None, None) => Err(validation("Either Template URL or Template Body must be specified.")),
            (Some(b), None) => self.expand_modules(ctx, b),
            (None, Some(u)) => {
                let text = self.fetch_s3(ctx, u).await?;
                self.expand_modules(ctx, &text)
            }
        }
    }

    /// Read an object an S3 URL names, as the caller.
    pub(crate) async fn fetch_s3(&self, ctx: &RequestContext, url: &str) -> Result<String, ServiceError> {
        let (bucket, key) = parse_s3_url(url).ok_or_else(|| validation("TemplateURL must be a supported URL."))?;
        let out = self
            .call(ctx, "s3", "GetObject", json!({"Bucket": bucket, "Key": key}))
            .await
            .map_err(|e| validation(format!("S3 error: {}", e.message)))?;
        let body = match out.get("Body") {
            Some(Value::String(b64)) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_else(|_| b64.as_bytes().to_vec())
            }
            _ => Vec::new(),
        };
        String::from_utf8(body).map_err(|_| validation("Template format error: unsupported structure."))
    }

    /// Parse and check a template and its parameters for a deployment.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prepare(
        &self,
        ctx: &RequestContext,
        deploy_ctx: &RequestContext,
        stack_name: &str,
        stack_id: &str,
        body: &str,
        provided: &[Provided],
        previous: &[StackParameter],
        capabilities: &[String],
        notification_arns: &[String],
    ) -> Result<(Template, Vec<StackParameter>, EvalData), ServiceError> {
        let template = Template::parse(body).map_err(validation)?;
        self.check_template(ctx, &template)?;
        check_capabilities(&template, capabilities)?;
        let mut params = parameters::assign(&template, provided, previous).map_err(validation)?;
        for p in params.iter_mut() {
            if parameters::ssm_value_type(&p.ty).is_some() {
                let out =
                    self.call(deploy_ctx, "ssm", "GetParameter", json!({"Name": p.value})).await.map_err(|_| {
                        validation(format!(
                            "Unable to fetch parameters [{}] from parameter store for this account.",
                            p.value
                        ))
                    })?;
                p.resolved = out["Parameter"]["Value"].as_str().map(str::to_string);
            }
        }
        let data = self.eval_data(ctx, &template, &params, stack_name, stack_id, notification_arns).await?;
        template.creation_order(&|l| data.included(&template, l)).map_err(validation)?;
        Ok((template, params, data))
    }

    /// Structural and reference checks shared by every operation that
    /// takes a template.
    pub(crate) fn check_template(&self, ctx: &RequestContext, template: &Template) -> Result<(), ServiceError> {
        template.check_references().map_err(validation)?;
        let mut unknown: Vec<String> = template
            .resources()
            .values()
            .filter_map(|r| r.get("Type").and_then(Value::as_str))
            .filter(|t| !self.has_type(ctx, t))
            .map(str::to_string)
            .collect();
        unknown.sort();
        unknown.dedup();
        if !unknown.is_empty() {
            return Err(validation(format_error(format!("Unrecognized resource types: [{}]", unknown.join(", ")))));
        }
        // Attributes Fn::GetAtt asks for must exist.
        for r in template.resources().values() {
            let Some(props) = r.get("Properties") else { continue };
            for (res, attr) in crate::template::references(props).get_atts {
                let Some(ty) = template.resource_type(&res) else { continue };
                if let Some(p) = self.provider_in(&ctx.caller.account_id, &ctx.region, ty) {
                    if !p.open_attributes() && !p.attributes().contains(&attr.as_str()) && attr != "*" {
                        return Err(validation(format!(
                            "Template error: resource {res} does not support attribute type {attr} in Fn::GetAtt"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn eval_data(
        &self,
        ctx: &RequestContext,
        template: &Template,
        params: &[StackParameter],
        stack_name: &str,
        stack_id: &str,
        notification_arns: &[String],
    ) -> Result<EvalData, ServiceError> {
        let pseudo = Pseudo {
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            partition: ctx.partition.clone(),
            stack_id: stack_id.to_string(),
            stack_name: stack_name.to_string(),
            notification_arns: notification_arns.to_vec(),
        };
        let values = parameters::ref_values(params);
        let le = template.has_language_extensions();
        let conditions = evaluate_conditions(template, &values, &pseudo, le).map_err(validation)?;
        let azs = self.availability_zones(ctx).await;
        let exports = exports(&self.state(), &ctx.caller.account_id, &ctx.region);
        let data = EvalData { params: values, pseudo, conditions, exports, azs, language_extensions: le };
        // Imports must exist before anything is deployed.
        for name in imports(template, &data) {
            if !data.exports.contains_key(&name) {
                return Err(validation(format!("No export named {name} found")));
            }
        }
        Ok(data)
    }

    async fn availability_zones(&self, ctx: &RequestContext) -> Vec<String> {
        let fallback = || ["a", "b", "c"].iter().map(|s| format!("{}{s}", ctx.region)).collect::<Vec<_>>();
        match self.call(ctx, "ec2", "DescribeAvailabilityZones", json!({})).await {
            Ok(out) => {
                let zones: Vec<String> = out["AvailabilityZones"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|z| z["ZoneName"].as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                if zones.is_empty() {
                    fallback()
                } else {
                    zones
                }
            }
            Err(_) => fallback(),
        }
    }
}

/// Export names a template imports (literal or computable without
/// resources).
pub(crate) fn imports(template: &Template, data: &EvalData) -> Vec<String> {
    let mut found = Vec::new();
    fn walk(v: &Value, data: &EvalData, template: &Template, out: &mut Vec<String>) {
        match v {
            Value::Object(o) if o.len() == 1 && o.contains_key("Fn::ImportValue") => {
                let ev = data.evaluator(template, &crate::intrinsics::NoResources);
                if let Ok(Value::String(s)) = ev.eval(&o["Fn::ImportValue"]) {
                    out.push(s);
                }
            }
            Value::Object(o) => o.values().for_each(|x| walk(x, data, template, out)),
            Value::Array(a) => a.iter().for_each(|x| walk(x, data, template, out)),
            _ => {}
        }
    }
    for (name, r) in template.resources() {
        if data.included(template, name) {
            if let Some(p) = r.get("Properties") {
                walk(p, data, template, &mut found);
            }
        }
    }
    if let Some(o) = template.section("Outputs") {
        walk(&Value::Object(o.clone()), data, template, &mut found);
    }
    found.sort();
    found.dedup();
    found
}

const IAM_TYPES: &[(&str, Option<&str>)] = &[
    ("AWS::IAM::AccessKey", None),
    ("AWS::IAM::Group", Some("GroupName")),
    ("AWS::IAM::GroupPolicy", None),
    ("AWS::IAM::InstanceProfile", Some("InstanceProfileName")),
    ("AWS::IAM::ManagedPolicy", Some("ManagedPolicyName")),
    ("AWS::IAM::Policy", None),
    ("AWS::IAM::Role", Some("RoleName")),
    ("AWS::IAM::RolePolicy", None),
    ("AWS::IAM::User", Some("UserName")),
    ("AWS::IAM::UserPolicy", None),
    ("AWS::IAM::UserToGroupAddition", None),
];

/// The capabilities a template needs, and the resources that need them.
pub(crate) fn required_capabilities(template: &Template) -> (Vec<String>, Vec<String>) {
    let mut iam = BTreeSet::new();
    let mut named = false;
    for r in template.resources().values() {
        let Some(ty) = r.get("Type").and_then(Value::as_str) else { continue };
        if let Some((_, name_prop)) = IAM_TYPES.iter().find(|(t, _)| *t == ty) {
            iam.insert(ty.to_string());
            if let Some(n) = name_prop {
                if r.get("Properties").and_then(|p| p.get(*n)).is_some() {
                    named = true;
                }
            }
        }
    }
    let mut caps = Vec::new();
    if !iam.is_empty() {
        caps.push(if named { "CAPABILITY_NAMED_IAM".to_string() } else { "CAPABILITY_IAM".to_string() });
    }
    (caps, iam.into_iter().collect())
}

pub(crate) fn check_capabilities(template: &Template, given: &[String]) -> Result<(), ServiceError> {
    let (needed, _) = required_capabilities(template);
    for c in needed {
        let ok = given.contains(&c);
        if !ok {
            return Err(ServiceError::client(
                "InsufficientCapabilitiesException",
                400,
                format!("Requires capabilities : [{c}]"),
            ));
        }
    }
    Ok(())
}

/// Bucket and key of an S3 object URL (virtual-hosted or path style, on
/// AWS or on this emulator's endpoint).
pub(crate) fn parse_s3_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/')?;
    let host = host.split(':').next().unwrap_or(host);
    let path = path.split('?').next().unwrap_or(path);
    let decode = |s: &str| percent_decode(s);
    if let Some(pos) = host.find(".s3.").or_else(|| host.find(".s3-")) {
        let bucket = &host[..pos];
        return Some((bucket.to_string(), decode(path)));
    }
    let (bucket, key) = path.split_once('/')?;
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket.to_string(), decode(key)))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn provided(params: Option<Vec<crate::generated::types::Parameter>>) -> Vec<Provided> {
    params
        .unwrap_or_default()
        .into_iter()
        .map(|p| Provided {
            key: p.parameter_key.unwrap_or_default(),
            value: p.parameter_value,
            use_previous: p.use_previous_value.unwrap_or(false),
        })
        .collect()
}

/// Simple offset-based pagination.
pub(crate) fn page<T: Clone>(
    items: &[T],
    token: Option<&str>,
    size: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        Some(t) => t.parse::<usize>().map_err(|_| validation("Invalid NextToken"))?,
        None => 0,
    };
    let end = (start + size).min(items.len());
    let slice = items.get(start..end).unwrap_or_default().to_vec();
    let next = (end < items.len()).then(|| end.to_string());
    Ok((slice, next))
}

/// Whether a type is one CloudFormation runs handlers for (not a custom
/// resource), for the registry operations.
pub(crate) fn is_registry_type(t: &str) -> bool {
    !is_custom(t)
}

#[cfg(test)]
mod tests {
    use super::parse_s3_url;

    #[test]
    fn s3_urls() {
        assert_eq!(parse_s3_url("https://b.s3.amazonaws.com/t.yaml"), Some(("b".into(), "t.yaml".into())));
        assert_eq!(
            parse_s3_url("https://b.s3.us-west-2.amazonaws.com/dir/t.yaml"),
            Some(("b".into(), "dir/t.yaml".into()))
        );
        assert_eq!(parse_s3_url("https://s3.amazonaws.com/b/k"), Some(("b".into(), "k".into())));
        assert_eq!(parse_s3_url("http://127.0.0.1:4566/b/k%20x"), Some(("b".into(), "k x".into())));
    }
}
