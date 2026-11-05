//! The private CloudFormation registry: resource, module and hook types
//! registered from schema handler packages, their versions and
//! configurations, publishers, public third-party types and activation.
//!
//! Resource and hook handlers run for real: the handler package's code is
//! deployed as a Lambda function in the registering account
//! (`CloudFormation-<kind>-<Type-Name>-<version>`) and invoked with the
//! CloudFormation CLI's `HandlerRequest`/`ProgressEvent` protocol, the way
//! AWS's registry runs it. Modules expand into their template fragments.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::generated::{errors, types};
use crate::ops::{page, validation};
use crate::providers::{Created, Cx, HResult, HandlerError, Props, Provider};
use crate::CloudFormation;

pub(crate) const REGISTRY_PRINCIPAL: &str = "resources.cloudformation.amazonaws.com";
pub(crate) const HOOKS_PRINCIPAL: &str = "hooks.cloudformation.amazonaws.com";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Registry {
    /// Private types (registered or activated), by
    /// `account/region/KIND/TypeName`.
    pub types: BTreeMap<String, RegType>,
    pub registrations: BTreeMap<String, Registration>,
    /// Publishers by account.
    pub publishers: BTreeMap<String, Publisher>,
    /// Published third-party types, by `region/KIND/TypeName`.
    pub public: BTreeMap<String, PublicType>,
    /// Handler invocations in flight, by bearer token.
    pub progress: BTreeMap<String, Progress>,
    pub hook_results: BTreeMap<String, HookResult>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RegType {
    pub kind: String,
    pub name: String,
    pub account: String,
    pub region: String,
    pub arn: String,
    pub versions: BTreeMap<String, TypeVersion>,
    pub default_version: String,
    /// Configuration JSON and when it was set, by alias.
    pub configurations: BTreeMap<String, (String, DateTime<Utc>)>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub activation: Option<Activation>,
    pub next_version: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TypeVersion {
    pub id: String,
    pub schema: String,
    /// The schema handler package (a zip), base64.
    pub package: String,
    pub execution_role_arn: Option<String>,
    pub logging: Option<types::LoggingConfig>,
    pub created: DateTime<Utc>,
    pub deprecated: bool,
    pub tests_status: String,
    pub tests_description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Activation {
    pub public_arn: String,
    pub publisher_id: String,
    pub original_name: String,
    pub auto_update: bool,
    pub major_version: Option<i64>,
    pub public_version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Registration {
    pub token: String,
    pub kind: String,
    pub name: String,
    pub account: String,
    pub region: String,
    pub status: String,
    pub description: Option<String>,
    pub type_arn: String,
    pub version_arn: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Publisher {
    pub id: String,
    pub account: String,
    pub connection_arn: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PublicType {
    pub arn: String,
    pub kind: String,
    pub name: String,
    pub region: String,
    pub publisher_id: String,
    pub source_arn: String,
    /// Public version number to (schema, package).
    pub versions: BTreeMap<String, (String, String)>,
    pub latest: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Progress {
    pub status: String,
    pub message: Option<String>,
    pub error_code: Option<String>,
    pub model: Option<String>,
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HookResult {
    pub id: String,
    pub invocation_point: String,
    pub failure_mode: String,
    pub type_name: String,
    pub type_version: String,
    pub type_arn: String,
    pub status: String,
    pub reason: Option<String>,
    pub invoked_at: DateTime<Utc>,
    pub stack_id: String,
    pub account: String,
    pub region: String,
    pub target_type_name: String,
    pub target_logical_id: String,
    pub action: String,
}

pub(crate) fn kind_path(kind: &str) -> &'static str {
    match kind {
        "MODULE" => "module",
        "HOOK" => "hook",
        _ => "resource",
    }
}

fn dashed(name: &str) -> String {
    name.replace("::", "-")
}

fn key(account: &str, region: &str, kind: &str, name: &str) -> String {
    format!("{account}/{region}/{kind}/{name}")
}

fn type_not_found(name: &str) -> ServiceError {
    errors::type_not_found(format!("The type '{name}' cannot be found."))
}

fn registry_error(message: impl Into<String>) -> ServiceError {
    errors::cfn_registry(message.into())
}

/// The type a name implies when `Type` is not given.
fn kind_of(kind: Option<&str>, name: &str) -> String {
    match kind {
        Some(k) => k.to_string(),
        None if name.ends_with("::MODULE") => "MODULE".into(),
        None => "RESOURCE".into(),
    }
}

fn check_name(kind: &str, name: &str) -> Result<(), ServiceError> {
    let parts: Vec<&str> = name.split("::").collect();
    let ok_part = |p: &&str| p.len() >= 2 && p.len() <= 64 && p.chars().all(|c| c.is_ascii_alphanumeric());
    let ok = match kind {
        "MODULE" => parts.len() == 4 && parts[3] == "MODULE" && parts[..3].iter().all(ok_part),
        _ => parts.len() == 3 && parts.iter().all(ok_part),
    };
    if !ok {
        return Err(validation(format!(
            "1 validation error detected: Value '{name}' at 'typeName' failed to satisfy constraint: Member must satisfy regular expression pattern: {}",
            if kind == "MODULE" {
                "[A-Za-z0-9]{2,64}::[A-Za-z0-9]{2,64}::[A-Za-z0-9]{2,64}::MODULE"
            } else {
                "[A-Za-z0-9]{2,64}::[A-Za-z0-9]{2,64}::[A-Za-z0-9]{2,64}"
            }
        )));
    }
    let ns = parts[0].to_ascii_uppercase();
    if ["AWS", "ALEXA", "CUSTOM", "DEV", "AMZN", "AMAZON", "ASK"].contains(&ns.as_str()) {
        return Err(registry_error(format!("Type name {name} uses the reserved namespace {}", parts[0])));
    }
    Ok(())
}

/// Files in a schema handler package.
pub(crate) struct Package {
    pub files: BTreeMap<String, Vec<u8>>,
}

impl Package {
    pub fn read(bytes: &[u8]) -> Result<Self, String> {
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .map_err(|_| "The schema handler package is not a valid zip file".to_string())?;
        let mut files = BTreeMap::new();
        for i in 0..z.len() {
            let mut f = z.by_index(i).map_err(|e| e.to_string())?;
            if f.is_dir() {
                continue;
            }
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
            files.insert(f.name().trim_start_matches("./").to_string(), buf);
        }
        Ok(Self { files })
    }

    fn text(&self, name: &str) -> Option<String> {
        self.files.get(name).and_then(|b| String::from_utf8(b.clone()).ok())
    }

    pub fn config(&self) -> Value {
        self.text(".rpdk-config").and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null)
    }

    pub fn schema(&self) -> Option<String> {
        if let Some(s) = self.text("schema.json") {
            return Some(s);
        }
        self.files
            .iter()
            .filter(|(n, _)| n.ends_with(".json") && !n.contains('/') && !n.starts_with('.'))
            .filter_map(|(_, b)| String::from_utf8(b.clone()).ok())
            .find(|t| serde_json::from_str::<Value>(t).is_ok_and(|v| v.get("typeName").is_some()))
    }

    pub fn fragment(&self) -> Option<String> {
        self.files
            .iter()
            .find(|(n, _)| {
                n.starts_with("fragments/") && (n.ends_with(".json") || n.ends_with(".yaml") || n.ends_with(".yml"))
            })
            .and_then(|(_, b)| String::from_utf8(b.clone()).ok())
    }

    /// The Lambda deployment package: the nested `ResourceProvider.zip`
    /// the CloudFormation CLI builds, or the package itself.
    pub fn code(&self, whole: &[u8]) -> Vec<u8> {
        self.files.get("ResourceProvider.zip").cloned().unwrap_or_else(|| whole.to_vec())
    }
}

/// The JSON-pointer property names (`/properties/A/B` -> `A.B`).
fn pointers(schema: &Value, key: &str) -> Vec<String> {
    schema
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().filter_map(Value::as_str).map(|p| p.trim_start_matches("/properties/").replace('/', ".")).collect()
        })
        .unwrap_or_default()
}

/// A module's schema, generated from its fragment's parameters as the
/// CloudFormation CLI does.
fn module_schema(name: &str, fragment: &str) -> Result<String, String> {
    let t = crate::template::Template::parse(fragment).map_err(|e| format!("Fragment is invalid: {e}"))?;
    let params = t.root.get("Parameters").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut props = Map::new();
    for (k, v) in &params {
        props.insert(
            k.clone(),
            json!({"type": "string", "description": v.get("Description").cloned().unwrap_or(Value::String(k.clone()))}),
        );
    }
    let mut resources = Map::new();
    for (k, v) in t.resources() {
        resources.insert(
            k.clone(),
            json!({"type": "object", "properties": {"Type": {"type": "string", "const": v.get("Type")}}}),
        );
    }
    Ok(json!({
        "typeName": name,
        "description": t.root.get("Description").cloned().unwrap_or(Value::String(format!("Schema for Module Fragment of type {name}"))),
        "properties": {
            "Parameters": {"type": "object", "properties": props},
            "Resources": {"type": "object", "properties": resources}
        },
        "additionalProperties": true
    })
    .to_string())
}

fn validate_schema(kind: &str, name: &str, schema: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(schema).map_err(|e| format!("Schema is not valid JSON: {e}"))?;
    if v.get("typeName").and_then(Value::as_str) != Some(name) {
        return Err(format!(
            "Type name {name} does not match the typeName {} in the schema",
            v.get("typeName").map(|t| t.to_string()).unwrap_or_else(|| "(missing)".into())
        ));
    }
    if v.get("description").and_then(Value::as_str).is_none() {
        return Err("Schema validation failed: #: required key [description] not found".into());
    }
    if kind == "RESOURCE" {
        if !v.get("properties").is_some_and(Value::is_object) {
            return Err("Schema validation failed: #: required key [properties] not found".into());
        }
        if pointers(&v, "primaryIdentifier").is_empty() {
            return Err("Schema validation failed: #: required key [primaryIdentifier] not found".into());
        }
    }
    if kind == "HOOK" && !v.get("handlers").is_some_and(Value::is_object) {
        return Err("Schema validation failed: #: required key [handlers] not found".into());
    }
    Ok(v)
}

/// What a handler returned.
struct ProgressEvent {
    status: String,
    model: Option<Value>,
    message: Option<String>,
    error_code: Option<String>,
    callback_context: Option<Value>,
    delay: u64,
}

fn parse_progress(v: &Value) -> ProgressEvent {
    ProgressEvent {
        status: v.get("status").and_then(Value::as_str).unwrap_or("FAILED").to_string(),
        model: v.get("resourceModel").cloned().filter(|m| !m.is_null()),
        message: v.get("message").and_then(Value::as_str).map(str::to_string),
        error_code: v.get("errorCode").and_then(Value::as_str).map(str::to_string),
        callback_context: v.get("callbackContext").cloned().filter(|c| !c.is_null()),
        delay: v.get("callbackDelaySeconds").and_then(Value::as_u64).unwrap_or(0),
    }
}

/// Scalars in a model as CloudFormation stores attribute values.
fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for p in path.split('.') {
        cur = cur.get(p)?;
    }
    Some(cur)
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl CloudFormation {
    fn with_registry<R>(&self, f: impl FnOnce(&mut Registry) -> R) -> R {
        f(&mut self.state().registry)
    }

    /// The private type a name or ARN names in the caller's account.
    fn resolve_type(
        &self,
        ctx: &RequestContext,
        kind: Option<&str>,
        name: Option<&str>,
        arn: Option<&str>,
    ) -> Result<(RegType, Option<String>), ServiceError> {
        let st = self.state();
        if let Some(arn) = arn {
            for t in st.registry.types.values() {
                if t.account != ctx.caller.account_id || t.region != ctx.region {
                    continue;
                }
                if t.arn == arn {
                    return Ok((t.clone(), None));
                }
                if let Some(v) = arn.strip_prefix(&format!("{}/", t.arn)) {
                    if t.versions.contains_key(v) {
                        return Ok((t.clone(), Some(v.to_string())));
                    }
                }
            }
            return Err(type_not_found(arn));
        }
        let name = name.ok_or_else(|| validation("Either TypeName and Type, or Arn, must be specified"))?;
        let kind = kind_of(kind, name);
        st.registry
            .types
            .get(&key(&ctx.caller.account_id, &ctx.region, &kind, name))
            .cloned()
            .map(|t| (t, None))
            .ok_or_else(|| type_not_found(name))
    }

    pub(crate) async fn register_type_op(
        &self,
        ctx: &RequestContext,
        input: types::RegisterTypeInput,
    ) -> Result<types::RegisterTypeOutput, ServiceError> {
        ctx.authorize("cloudformation:RegisterType", "*", Default::default())?;
        let kind = kind_of(input.r#type.as_deref(), &input.type_name);
        check_name(&kind, &input.type_name)?;
        if let Some(role) = &input.execution_role_arn {
            ctx.authorize(
                "iam:PassRole",
                role,
                crate::ops::condition_keys(&[("iam:PassedToService", vec![REGISTRY_PRINCIPAL.into()])]),
            )?;
        }
        let account = ctx.caller.account_id.clone();
        let type_arn = format!(
            "arn:{}:cloudformation:{}:{account}:type/{}/{}",
            ctx.partition,
            ctx.region,
            kind_path(&kind),
            dashed(&input.type_name)
        );
        if let Some(t) = &input.client_request_token {
            if let Some(r) = self.with_registry(|r| r.registrations.get(t).cloned()) {
                return if r.name == input.type_name {
                    Ok(types::RegisterTypeOutput { registration_token: Some(r.token) })
                } else {
                    Err(errors::token_already_exists(format!("Token {t} already exists")))
                };
            }
        }
        let token = input.client_request_token.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.with_registry(|r| {
            r.registrations.insert(
                token.clone(),
                Registration {
                    token: token.clone(),
                    kind: kind.clone(),
                    name: input.type_name.clone(),
                    account: account.clone(),
                    region: ctx.region.clone(),
                    status: "IN_PROGRESS".into(),
                    description: Some("Deployment is currently in DEPLOY_STAGE of status IN_PROGRESS; ".into()),
                    type_arn: type_arn.clone(),
                    version_arn: None,
                },
            )
        });
        let me = self.clone();
        let ctx = ctx.clone();
        let token2 = token.clone();
        tokio::spawn(async move {
            let result = me.complete_registration(&ctx, &kind, &input, &type_arn).await;
            me.with_registry(|r| {
                if let Some(reg) = r.registrations.get_mut(&token2) {
                    match result {
                        Ok(version_arn) => {
                            reg.status = "COMPLETE".into();
                            reg.description =
                                Some("Deployment is currently in DEPLOY_STAGE of status COMPLETED; ".into());
                            reg.version_arn = Some(version_arn);
                        }
                        Err(why) => {
                            reg.status = "FAILED".into();
                            reg.description = Some(why);
                        }
                    }
                }
            });
        });
        Ok(types::RegisterTypeOutput { registration_token: Some(token) })
    }

    async fn complete_registration(
        &self,
        ctx: &RequestContext,
        kind: &str,
        input: &types::RegisterTypeInput,
        type_arn: &str,
    ) -> Result<String, String> {
        let bytes = self.fetch_s3_bytes(ctx, &input.schema_handler_package).await.map_err(|e| e.message)?;
        let package = Package::read(&bytes)?;
        let schema = match kind {
            "MODULE" => {
                let fragment = package.fragment().ok_or("The module package has no template fragment in fragments/")?;
                // The fragment must be a valid template.
                let t = crate::template::Template::parse(&fragment).map_err(|e| format!("Fragment is invalid: {e}"))?;
                if t.resources().is_empty() {
                    return Err("Fragment is invalid: Resources must not be empty".into());
                }
                package.schema().unwrap_or(module_schema(&input.type_name, &fragment)?)
            }
            _ => package.schema().ok_or("The schema handler package has no schema.json")?,
        };
        validate_schema(kind, &input.type_name, &schema)?;
        let now = Utc::now();
        let k = key(&ctx.caller.account_id, &ctx.region, kind, &input.type_name);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(self.with_registry(|r| {
            let t = r.types.entry(k).or_insert_with(|| RegType {
                kind: kind.to_string(),
                name: input.type_name.clone(),
                account: ctx.caller.account_id.clone(),
                region: ctx.region.clone(),
                arn: type_arn.to_string(),
                created: now,
                next_version: 1,
                ..Default::default()
            });
            let id = format!("{:08}", t.next_version.max(1));
            t.next_version = t.next_version.max(1) + 1;
            t.versions.insert(
                id.clone(),
                TypeVersion {
                    id: id.clone(),
                    schema,
                    package: b64,
                    execution_role_arn: input.execution_role_arn.clone(),
                    logging: input.logging_config.clone(),
                    created: now,
                    deprecated: false,
                    tests_status: "NOT_TESTED".into(),
                    tests_description: None,
                },
            );
            if t.default_version.is_empty() || t.versions.get(&t.default_version).is_none_or(|v| v.deprecated) {
                t.default_version = id.clone();
            }
            t.updated = now;
            format!("{type_arn}/{id}")
        }))
    }

    pub(crate) async fn fetch_s3_bytes(&self, ctx: &RequestContext, url: &str) -> Result<Vec<u8>, ServiceError> {
        let (bucket, key) = crate::ops::parse_s3_url(url)
            .or_else(|| {
                url.strip_prefix("s3://").and_then(|r| r.split_once('/')).map(|(b, k)| (b.to_string(), k.to_string()))
            })
            .ok_or_else(|| validation(format!("Invalid S3 URL {url}")))?;
        let out = self
            .call(ctx, "s3", "GetObject", json!({"Bucket": bucket, "Key": key}))
            .await
            .map_err(|e| registry_error(format!("Failed to download the schema handler package: {}", e.message)))?;
        Ok(match out.get("Body") {
            Some(Value::String(b64)) => {
                base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_else(|_| b64.as_bytes().to_vec())
            }
            _ => Vec::new(),
        })
    }

    pub(crate) fn describe_type_registration_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTypeRegistrationInput,
    ) -> Result<types::DescribeTypeRegistrationOutput, ServiceError> {
        ctx.authorize("cloudformation:DescribeTypeRegistration", "*", Default::default())?;
        let r = self
            .with_registry(|r| r.registrations.get(&input.registration_token).cloned())
            .filter(|r| r.account == ctx.caller.account_id && r.region == ctx.region)
            .ok_or_else(|| registry_error(format!("Registration token {} was not found", input.registration_token)))?;
        Ok(types::DescribeTypeRegistrationOutput {
            progress_status: Some(r.status),
            description: r.description,
            type_arn: Some(r.type_arn),
            type_version_arn: r.version_arn,
        })
    }

    pub(crate) fn list_type_registrations_op(
        &self,
        ctx: &RequestContext,
        input: types::ListTypeRegistrationsInput,
    ) -> Result<types::ListTypeRegistrationsOutput, ServiceError> {
        ctx.authorize("cloudformation:ListTypeRegistrations", "*", Default::default())?;
        let kind = input.type_name.as_deref().map(|n| kind_of(input.r#type.as_deref(), n));
        let all: Vec<String> = self.with_registry(|r| {
            r.registrations
                .values()
                .filter(|x| x.account == ctx.caller.account_id && x.region == ctx.region)
                .filter(|x| {
                    input.type_name.as_ref().is_none_or(|n| &x.name == n && kind.as_deref() == Some(x.kind.as_str()))
                })
                .filter(|x| input.type_arn.as_ref().is_none_or(|a| &x.type_arn == a))
                .filter(|x| input.registration_status_filter.as_ref().is_none_or(|s| &x.status == s))
                .map(|x| x.token.clone())
                .collect()
        });
        let (tokens, next_token) = page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListTypeRegistrationsOutput { registration_token_list: Some(tokens), next_token })
    }

    pub(crate) fn deregister_type_op(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterTypeInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize("cloudformation:DeregisterType", "*", Default::default())?;
        let (t, arn_version) =
            self.resolve_type(ctx, input.r#type.as_deref(), input.type_name.as_deref(), input.arn.as_deref())?;
        if t.activation.is_some() {
            return Err(registry_error(format!("Type {} is activated; use DeactivateType", t.name)));
        }
        let version = input.version_id.clone().or(arn_version);
        let k = key(&t.account, &t.region, &t.kind, &t.name);
        let live: Vec<String> = t.versions.values().filter(|v| !v.deprecated).map(|v| v.id.clone()).collect();
        if let Some(v) = &version {
            if !live.contains(v) {
                return Err(type_not_found(&format!("{}/{v}", t.arn)));
            }
            if v == &t.default_version && live.len() > 1 {
                return Err(registry_error(format!(
                    "Version '{v}' is the default version and cannot be deregistered. Set another version as the default first."
                )));
            }
        }
        self.with_registry(|r| {
            if let Some(t) = r.types.get_mut(&k) {
                match &version {
                    Some(v) if live.len() > 1 => {
                        if let Some(x) = t.versions.get_mut(v) {
                            x.deprecated = true;
                        }
                    }
                    _ => {
                        for x in t.versions.values_mut() {
                            x.deprecated = true;
                        }
                    }
                }
                t.updated = Utc::now();
            }
        });
        Ok(())
    }

    pub(crate) fn list_type_versions_op(
        &self,
        ctx: &RequestContext,
        input: types::ListTypeVersionsInput,
    ) -> Result<types::ListTypeVersionsOutput, ServiceError> {
        ctx.authorize("cloudformation:ListTypeVersions", "*", Default::default())?;
        let wanted = input.deprecated_status.clone().unwrap_or_else(|| "LIVE".into());
        // Public third-party types list their public versions.
        if let Some(p) = input.publisher_id.as_ref().filter(|p| self.own_publisher(ctx).as_deref() != Some(p.as_str()))
        {
            let name = input.type_name.clone().unwrap_or_default();
            let kind = kind_of(input.r#type.as_deref(), &name);
            let public = self
                .with_registry(|r| r.public.get(&format!("{}/{kind}/{name}", ctx.region)).cloned())
                .filter(|t| &t.publisher_id == p)
                .ok_or_else(|| type_not_found(&name))?;
            let all: Vec<types::TypeVersionSummary> = public
                .versions
                .keys()
                .map(|v| types::TypeVersionSummary {
                    r#type: Some(public.kind.clone()),
                    type_name: Some(public.name.clone()),
                    arn: Some(format!("{}/{v}", public.arn)),
                    is_default_version: Some(v == &public.latest),
                    time_created: Some(public.created),
                    public_version_number: Some(v.clone()),
                    ..Default::default()
                })
                .collect();
            let (items, next_token) =
                page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
            return Ok(types::ListTypeVersionsOutput { type_version_summaries: Some(items), next_token });
        }
        let (t, _) =
            self.resolve_type(ctx, input.r#type.as_deref(), input.type_name.as_deref(), input.arn.as_deref())?;
        let all: Vec<types::TypeVersionSummary> = t
            .versions
            .values()
            .filter(|v| (if v.deprecated { "DEPRECATED" } else { "LIVE" }) == wanted)
            .map(|v| types::TypeVersionSummary {
                r#type: Some(t.kind.clone()),
                type_name: Some(t.name.clone()),
                version_id: Some(v.id.clone()),
                is_default_version: Some(v.id == t.default_version),
                arn: Some(format!("{}/{}", t.arn, v.id)),
                time_created: Some(v.created),
                description: serde_json::from_str::<Value>(&v.schema)
                    .ok()
                    .and_then(|s| s.get("description").and_then(Value::as_str).map(str::to_string)),
                public_version_number: None,
            })
            .collect();
        let (items, next_token) = page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListTypeVersionsOutput { type_version_summaries: Some(items), next_token })
    }

    pub(crate) fn set_type_default_version_op(
        &self,
        ctx: &RequestContext,
        input: types::SetTypeDefaultVersionInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize("cloudformation:SetTypeDefaultVersion", "*", Default::default())?;
        let (t, arn_version) =
            self.resolve_type(ctx, input.r#type.as_deref(), input.type_name.as_deref(), input.arn.as_deref())?;
        let v = input
            .version_id
            .clone()
            .or(arn_version)
            .ok_or_else(|| validation("VersionId must be specified with TypeName"))?;
        if t.versions.get(&v).is_none_or(|x| x.deprecated) {
            return Err(type_not_found(&format!("{}/{v}", t.arn)));
        }
        let k = key(&t.account, &t.region, &t.kind, &t.name);
        self.with_registry(|r| {
            if let Some(t) = r.types.get_mut(&k) {
                t.default_version = v;
                t.updated = Utc::now();
            }
        });
        Ok(())
    }

    pub(crate) fn set_type_configuration_op(
        &self,
        ctx: &RequestContext,
        input: types::SetTypeConfigurationInput,
    ) -> Result<types::SetTypeConfigurationOutput, ServiceError> {
        ctx.authorize("cloudformation:SetTypeConfiguration", "*", Default::default())?;
        let (t, _) =
            self.resolve_type(ctx, input.r#type.as_deref(), input.type_name.as_deref(), input.type_arn.as_deref())?;
        let config: Value = serde_json::from_str(&input.configuration)
            .map_err(|_| validation("Configuration must be a valid JSON object"))?;
        if !config.is_object() {
            return Err(validation("Configuration must be a valid JSON object"));
        }
        if t.kind == "HOOK" {
            let hc = &config["CloudFormationConfiguration"]["HookConfiguration"];
            if !hc.is_object() {
                return Err(validation(
                    "Hook configuration must contain CloudFormationConfiguration.HookConfiguration",
                ));
            }
            for (k, allowed) in [
                ("HookInvocationStatus", &["ENABLED", "DISABLED"][..]),
                ("FailureMode", &["FAIL", "WARN"][..]),
                ("TargetStacks", &["ALL", "NONE"][..]),
            ] {
                if let Some(v) = hc.get(k) {
                    if !v.as_str().is_some_and(|s| allowed.contains(&s)) {
                        return Err(validation(format!("Invalid value {v} for {k}; expected one of {allowed:?}")));
                    }
                }
            }
        } else {
            // Validate against the schema's typeConfiguration, when it has
            // required keys.
            let version = t.versions.get(&t.default_version).cloned().unwrap_or_default();
            let schema: Value = serde_json::from_str(&version.schema).unwrap_or(Value::Null);
            let required = schema["typeConfiguration"]["required"].as_array().cloned().unwrap_or_default();
            let given = config.get("CloudFormationConfiguration").unwrap_or(&config);
            for r in required.iter().filter_map(Value::as_str) {
                if config.get(r).is_none() && given.get(r).is_none() {
                    return Err(validation(format!(
                        "Configuration validation failed: #: required key [{r}] not found"
                    )));
                }
            }
        }
        let alias = input.configuration_alias.clone().unwrap_or_else(|| "default".into());
        let k = key(&t.account, &t.region, &t.kind, &t.name);
        self.with_registry(|r| {
            if let Some(t) = r.types.get_mut(&k) {
                t.configurations.insert(alias.clone(), (input.configuration.clone(), Utc::now()));
            }
        });
        Ok(types::SetTypeConfigurationOutput { configuration_arn: Some(config_arn(ctx, &t, &alias)) })
    }

    pub(crate) fn batch_describe_type_configurations_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchDescribeTypeConfigurationsInput,
    ) -> Result<types::BatchDescribeTypeConfigurationsOutput, ServiceError> {
        ctx.authorize("cloudformation:BatchDescribeTypeConfigurations", "*", Default::default())?;
        if input.type_configuration_identifiers.is_empty() {
            return Err(validation("TypeConfigurationIdentifiers must not be empty"));
        }
        let mut found = Vec::new();
        let mut errs = Vec::new();
        for id in &input.type_configuration_identifiers {
            let (arn, alias) = match &id.type_configuration_arn {
                Some(c) => {
                    // arn:...:type-configuration/<kind>/<Name>/<alias>
                    let mut parts = c.rsplitn(2, '/');
                    let alias = parts.next().unwrap_or_default().to_string();
                    let base = parts.next().unwrap_or_default().replace(":type-configuration/", ":type/");
                    (Some(base), Some(alias))
                }
                None => (id.type_arn.clone(), id.type_configuration_alias.clone()),
            };
            let resolved = self.resolve_type(ctx, id.r#type.as_deref(), id.type_name.as_deref(), arn.as_deref());
            let Ok((t, _)) = resolved else {
                errs.push(types::BatchDescribeTypeConfigurationsError {
                    error_code: Some("TypeNotFound".into()),
                    error_message: Some("The type cannot be found.".into()),
                    type_configuration_identifier: Some(id.clone()),
                });
                continue;
            };
            let aliases: Vec<String> = match &alias {
                Some(a) => vec![a.clone()],
                None => t.configurations.keys().cloned().collect(),
            };
            if aliases.iter().all(|a| !t.configurations.contains_key(a)) {
                errs.push(types::BatchDescribeTypeConfigurationsError {
                    error_code: Some("TypeConfigurationNotFound".into()),
                    error_message: Some(format!(
                        "Type configuration {} cannot be found.",
                        alias.clone().unwrap_or_else(|| "default".into())
                    )),
                    type_configuration_identifier: Some(id.clone()),
                });
                continue;
            }
            for a in aliases {
                if let Some((c, at)) = t.configurations.get(&a) {
                    found.push(types::TypeConfigurationDetails {
                        arn: Some(config_arn(ctx, &t, &a)),
                        alias: Some(a.clone()),
                        configuration: Some(c.clone()),
                        last_updated: Some(*at),
                        type_arn: Some(t.arn.clone()),
                        type_name: Some(t.name.clone()),
                        is_default_configuration: Some(a == "default"),
                    });
                }
            }
        }
        Ok(types::BatchDescribeTypeConfigurationsOutput {
            errors: Some(errs),
            unprocessed_type_configurations: Some(vec![]),
            type_configurations: Some(found),
        })
    }

    fn own_publisher(&self, ctx: &RequestContext) -> Option<String> {
        self.with_registry(|r| r.publishers.get(&ctx.caller.account_id).map(|p| p.id.clone()))
    }

    pub(crate) fn register_publisher_op(
        &self,
        ctx: &RequestContext,
        input: types::RegisterPublisherInput,
    ) -> Result<types::RegisterPublisherOutput, ServiceError> {
        ctx.authorize("cloudformation:RegisterPublisher", "*", Default::default())?;
        if input.accept_terms_and_conditions != Some(true) {
            return Err(validation("You must accept the terms and conditions to register as a publisher"));
        }
        if let Some(existing) = self.own_publisher(ctx) {
            return Ok(types::RegisterPublisherOutput { publisher_id: Some(existing) });
        }
        use sha2::Digest;
        let id = hex::encode(sha2::Sha256::digest(format!("publisher:{}", ctx.caller.account_id)))[..40].to_string();
        self.with_registry(|r| {
            r.publishers.insert(
                ctx.caller.account_id.clone(),
                Publisher {
                    id: id.clone(),
                    account: ctx.caller.account_id.clone(),
                    connection_arn: input.connection_arn.clone(),
                },
            )
        });
        Ok(types::RegisterPublisherOutput { publisher_id: Some(id) })
    }

    pub(crate) fn describe_publisher_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribePublisherInput,
    ) -> Result<types::DescribePublisherOutput, ServiceError> {
        ctx.authorize("cloudformation:DescribePublisher", "*", Default::default())?;
        let p = self.with_registry(|r| match &input.publisher_id {
            Some(id) => r.publishers.values().find(|p| &p.id == id).cloned(),
            None => r.publishers.get(&ctx.caller.account_id).cloned(),
        });
        let Some(p) = p else {
            return Err(registry_error(match &input.publisher_id {
                Some(id) => format!("Publisher {id} not found"),
                None => "The account is not registered as a publisher".to_string(),
            }));
        };
        let provider = match &p.connection_arn {
            Some(c) if c.contains("bitbucket") => "Bitbucket",
            Some(_) => "GitHub",
            None => "AWS_Marketplace",
        };
        Ok(types::DescribePublisherOutput {
            publisher_id: Some(p.id.clone()),
            publisher_status: Some("VERIFIED".into()),
            identity_provider: Some(provider.into()),
            publisher_profile: Some(format!("https://github.com/{}", p.account)),
        })
    }

    pub(crate) async fn test_type_op(
        &self,
        ctx: &RequestContext,
        input: types::TestTypeInput,
    ) -> Result<types::TestTypeOutput, ServiceError> {
        ctx.authorize("cloudformation:TestType", "*", Default::default())?;
        let (t, arn_version) =
            self.resolve_type(ctx, input.r#type.as_deref(), input.type_name.as_deref(), input.arn.as_deref())?;
        if t.activation.is_some() {
            return Err(registry_error("Only types registered in this account can be tested"));
        }
        let version = input.version_id.clone().or(arn_version).unwrap_or_else(|| t.default_version.clone());
        if !t.versions.contains_key(&version) {
            return Err(type_not_found(&format!("{}/{version}", t.arn)));
        }
        let k = key(&t.account, &t.region, &t.kind, &t.name);
        self.set_tests(&k, &version, "IN_PROGRESS", None);
        let me = self.clone();
        let ctx = ctx.clone();
        let bucket = input.log_delivery_bucket.clone();
        let tv = version.clone();
        tokio::spawn(async move {
            let (status, why, log) = me.contract_tests(&ctx, &k, &tv).await;
            if let Some(bucket) = bucket {
                let name = k.rsplit('/').next().unwrap_or_default().to_string();
                let _ = me
                    .call(
                        &me.via(&ctx),
                        "s3",
                        "PutObject",
                        json!({
                            "Bucket": bucket,
                            "Key": format!("{}/{tv}/contract-tests.log", dashed(&name)),
                            "Body": base64::engine::general_purpose::STANDARD.encode(log.as_bytes()),
                        }),
                    )
                    .await;
            }
            me.set_tests(&k, &tv, status, why);
        });
        Ok(types::TestTypeOutput { type_version_arn: Some(format!("{}/{version}", t.arn)) })
    }

    fn set_tests(&self, k: &str, version: &str, status: &str, why: Option<String>) {
        self.with_registry(|r| {
            if let Some(v) = r.types.get_mut(k).and_then(|t| t.versions.get_mut(version)) {
                v.tests_status = status.to_string();
                v.tests_description = why;
            }
        });
    }

    /// Run the package's contract test inputs (`inputs/inputs_N_create.json`,
    /// `_update.json`) through the handlers: create, read, update, read,
    /// delete, and a read that must report NotFound.
    async fn contract_tests(
        &self,
        ctx: &RequestContext,
        k: &str,
        version: &str,
    ) -> (&'static str, Option<String>, String) {
        let Some(t) = self.with_registry(|r| r.types.get(k).cloned()) else {
            return ("FAILED", Some("The type no longer exists".into()), String::new());
        };
        let Some(v) = t.versions.get(version).cloned() else {
            return ("FAILED", Some("The version no longer exists".into()), String::new());
        };
        if t.kind != "RESOURCE" {
            let ok = validate_schema(&t.kind, &t.name, &v.schema);
            return match ok {
                Ok(_) => ("PASSED", Some("Schema validation passed".into()), "schema: PASSED\n".into()),
                Err(e) => ("FAILED", Some(e.clone()), format!("schema: FAILED {e}\n")),
            };
        }
        let bytes = base64::engine::general_purpose::STANDARD.decode(&v.package).unwrap_or_default();
        let Ok(pkg) = Package::read(&bytes) else {
            return ("FAILED", Some("The schema handler package is not a valid zip file".into()), String::new());
        };
        let mut inputs: Vec<(String, Value, Option<Value>)> = Vec::new();
        for (name, body) in &pkg.files {
            if let Some(rest) = name.strip_prefix("inputs/") {
                if let Some(n) = rest.strip_suffix("_create.json") {
                    let create: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
                    let update =
                        pkg.files.get(&format!("inputs/{n}_update.json")).and_then(|b| serde_json::from_slice(b).ok());
                    inputs.push((n.to_string(), create, update));
                }
            }
        }
        if inputs.is_empty() {
            return (
                "FAILED",
                Some("The schema handler package has no contract test inputs (inputs/inputs_1_create.json)".into()),
                String::new(),
            );
        }
        let schema: Value = serde_json::from_str(&v.schema).unwrap_or(Value::Null);
        let mut log = String::new();
        let deploy = self.via(ctx);
        for (n, create, update) in inputs {
            let run = async {
                let model =
                    self.run_handler(&deploy, &t, version, "CREATE", create.clone(), None, "ContractTest", "").await?;
                log.push_str(&format!("{n} create: PASSED\n"));
                let ids = identifier_model(&schema, &model);
                self.run_handler(&deploy, &t, version, "READ", ids.clone(), None, "ContractTest", "").await?;
                log.push_str(&format!("{n} read: PASSED\n"));
                if let Some(u) = &update {
                    let mut m = u.clone();
                    merge_ids(&mut m, &ids);
                    self.run_handler(&deploy, &t, version, "UPDATE", m, Some(model.clone()), "ContractTest", "")
                        .await?;
                    log.push_str(&format!("{n} update: PASSED\n"));
                }
                self.run_handler(&deploy, &t, version, "DELETE", ids.clone(), None, "ContractTest", "").await?;
                log.push_str(&format!("{n} delete: PASSED\n"));
                match self.run_handler(&deploy, &t, version, "READ", ids, None, "ContractTest", "").await {
                    Err(e) if e.not_found => {
                        log.push_str(&format!("{n} read after delete: PASSED\n"));
                        Ok(())
                    }
                    Ok(_) => Err(HandlerError::invalid("READ after DELETE must fail with NotFound")),
                    Err(e) => Err(e),
                }
            };
            if let Err(e) = run.await {
                log.push_str(&format!("{n}: FAILED {}\n", e.message));
                return ("FAILED", Some(e.message), log);
            }
        }
        ("PASSED", Some("Contract tests passed".into()), log)
    }

    pub(crate) fn publish_type_op(
        &self,
        ctx: &RequestContext,
        input: types::PublishTypeInput,
    ) -> Result<types::PublishTypeOutput, ServiceError> {
        ctx.authorize("cloudformation:PublishType", "*", Default::default())?;
        let publisher = self.own_publisher(ctx).ok_or_else(|| {
            registry_error("You must register as a publisher (RegisterPublisher) before publishing types")
        })?;
        let (t, arn_version) =
            self.resolve_type(ctx, input.r#type.as_deref(), input.type_name.as_deref(), input.arn.as_deref())?;
        if t.activation.is_some() {
            return Err(registry_error("Activated types cannot be published"));
        }
        let version = arn_version.unwrap_or_else(|| t.default_version.clone());
        let v = t.versions.get(&version).cloned().ok_or_else(|| type_not_found(&t.name))?;
        if t.kind != "MODULE" && v.tests_status != "PASSED" {
            return Err(registry_error(format!(
                "Type {} version {version} must pass testing (TestType) before it can be published; its test status is {}",
                t.name, v.tests_status
            )));
        }
        let pk = format!("{}/{}/{}", ctx.region, t.kind, t.name);
        let existing = self.with_registry(|r| r.public.get(&pk).cloned());
        if let Some(e) = &existing {
            if e.publisher_id != publisher {
                return Err(registry_error(format!("Type name {} is already published by another publisher", t.name)));
            }
        }
        let number = match input.public_version_number.clone() {
            Some(n) => {
                let parsed = parse_semver(&n).ok_or_else(|| validation(format!("Invalid PublicVersionNumber {n}")))?;
                if let Some(e) = &existing {
                    if parse_semver(&e.latest).is_some_and(|l| parsed <= l) {
                        return Err(registry_error(format!(
                            "Public version {n} must be greater than the latest public version {}",
                            e.latest
                        )));
                    }
                }
                n
            }
            None => match &existing {
                Some(e) => {
                    let (a, b, c) = parse_semver(&e.latest).unwrap_or((1, 0, 0));
                    format!("{a}.{b}.{}", c + 1)
                }
                None => "1.0.0".into(),
            },
        };
        let arn = format!(
            "arn:{}:cloudformation:{}::type/{}/{publisher}/{}",
            ctx.partition,
            ctx.region,
            kind_path(&t.kind),
            dashed(&t.name)
        );
        self.with_registry(|r| {
            let p = r.public.entry(pk).or_insert_with(|| PublicType {
                arn: arn.clone(),
                kind: t.kind.clone(),
                name: t.name.clone(),
                region: ctx.region.clone(),
                publisher_id: publisher.clone(),
                source_arn: t.arn.clone(),
                created: Utc::now(),
                ..Default::default()
            });
            p.versions.insert(number.clone(), (v.schema.clone(), v.package.clone()));
            p.latest = number.clone();
            // Activations that follow minor versions update automatically.
            for at in r.types.values_mut() {
                if let Some(a) = at.activation.as_mut() {
                    let major = parse_semver(&number).map(|x| x.0 as i64);
                    if a.public_arn == arn && a.auto_update && (a.major_version.is_none() || a.major_version == major) {
                        a.public_version = number.clone();
                    }
                }
            }
        });
        Ok(types::PublishTypeOutput { public_type_arn: Some(arn) })
    }

    pub(crate) fn activate_type_op(
        &self,
        ctx: &RequestContext,
        input: types::ActivateTypeInput,
    ) -> Result<types::ActivateTypeOutput, ServiceError> {
        ctx.authorize("cloudformation:ActivateType", "*", Default::default())?;
        let public = self.with_registry(|r| {
            r.public
                .values()
                .find(|p| {
                    p.region == ctx.region
                        && match (&input.public_type_arn, &input.publisher_id, &input.type_name) {
                            (Some(a), _, _) => &p.arn == a,
                            (None, Some(pid), Some(n)) => &p.publisher_id == pid && &p.name == n,
                            _ => false,
                        }
                })
                .cloned()
        });
        let public = public.ok_or_else(|| {
            type_not_found(input.public_type_arn.as_deref().or(input.type_name.as_deref()).unwrap_or_default())
        })?;
        if let Some(role) = &input.execution_role_arn {
            ctx.authorize(
                "iam:PassRole",
                role,
                crate::ops::condition_keys(&[("iam:PassedToService", vec![REGISTRY_PRINCIPAL.into()])]),
            )?;
        }
        let alias = input.type_name_alias.clone().unwrap_or_else(|| public.name.clone());
        check_name(&public.kind, &alias)?;
        let version = match input.major_version {
            Some(m) => public
                .versions
                .keys()
                .filter(|v| parse_semver(v).is_some_and(|x| x.0 as i64 == m))
                .max_by_key(|v| parse_semver(v))
                .cloned()
                .ok_or_else(|| registry_error(format!("Major version {m} of {} does not exist", public.name)))?,
            None => public.latest.clone(),
        };
        let k = key(&ctx.caller.account_id, &ctx.region, &public.kind, &alias);
        let arn = format!(
            "arn:{}:cloudformation:{}:{}:type/{}/{}",
            ctx.partition,
            ctx.region,
            ctx.caller.account_id,
            kind_path(&public.kind),
            dashed(&alias)
        );
        let exists = self.with_registry(|r| r.types.get(&k).cloned());
        if let Some(e) = &exists {
            if e.activation.is_none() && e.versions.values().any(|v| !v.deprecated) {
                return Err(registry_error(format!(
                    "A private type named {alias} is already registered in this account"
                )));
            }
        }
        let now = Utc::now();
        let (schema, package) = public.versions.get(&version).cloned().unwrap_or_default();
        self.with_registry(|r| {
            r.types.insert(
                k,
                RegType {
                    kind: public.kind.clone(),
                    name: alias.clone(),
                    account: ctx.caller.account_id.clone(),
                    region: ctx.region.clone(),
                    arn: arn.clone(),
                    versions: [(
                        "00000001".to_string(),
                        TypeVersion {
                            id: "00000001".into(),
                            schema: schema.replace(&public.name, &alias),
                            package,
                            execution_role_arn: input.execution_role_arn.clone(),
                            logging: input.logging_config.clone(),
                            created: now,
                            deprecated: false,
                            tests_status: "PASSED".into(),
                            tests_description: None,
                        },
                    )]
                    .into_iter()
                    .collect(),
                    default_version: "00000001".into(),
                    configurations: exists.map(|e| e.configurations).unwrap_or_default(),
                    created: now,
                    updated: now,
                    activation: Some(Activation {
                        public_arn: public.arn.clone(),
                        publisher_id: public.publisher_id.clone(),
                        original_name: public.name.clone(),
                        auto_update: input.auto_update.unwrap_or(true),
                        major_version: input.major_version,
                        public_version: version,
                    }),
                    next_version: 2,
                },
            );
        });
        Ok(types::ActivateTypeOutput { arn: Some(arn) })
    }

    pub(crate) fn deactivate_type_op(
        &self,
        ctx: &RequestContext,
        input: types::DeactivateTypeInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize("cloudformation:DeactivateType", "*", Default::default())?;
        let (t, _) =
            self.resolve_type(ctx, input.r#type.as_deref(), input.type_name.as_deref(), input.arn.as_deref())?;
        if t.activation.is_none() {
            return Err(registry_error(format!("Type {} is not an activated public type", t.name)));
        }
        let in_use = {
            let st = self.state();
            st.stacks.values().any(|s| {
                s.account == t.account
                    && s.region == t.region
                    && !s.is_deleted()
                    && s.resources.iter().any(|r| r.resource_type == t.name && r.exists())
            })
        };
        if in_use {
            return Err(registry_error(format!(
                "Type {} is used by stacks in this account and cannot be deactivated",
                t.name
            )));
        }
        let k = key(&t.account, &t.region, &t.kind, &t.name);
        self.with_registry(|r| r.types.remove(&k));
        Ok(())
    }

    pub(crate) fn record_handler_progress_op(
        &self,
        ctx: &RequestContext,
        input: types::RecordHandlerProgressInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize("cloudformation:RecordHandlerProgress", "*", Default::default())?;
        self.with_registry(|r| {
            let p = r.progress.get_mut(&input.bearer_token).ok_or_else(|| {
                errors::operation_status_check_failed("The bearer token is not valid for an operation in progress")
            })?;
            if let Some(t) = &input.client_request_token {
                if p.tokens.contains(t) {
                    return Ok(());
                }
            }
            if let Some(cur) = &input.current_operation_status {
                if cur != &p.status {
                    return Err(errors::operation_status_check_failed(format!(
                        "The operation status is {}, not {cur}",
                        p.status
                    )));
                }
            }
            if p.status != "PENDING" && p.status != "IN_PROGRESS" {
                return Err(errors::invalid_state_transition(format!(
                    "The operation is already {} and cannot move to {}",
                    p.status, input.operation_status
                )));
            }
            p.status = input.operation_status.clone();
            p.message = input.status_message.clone();
            p.error_code = input.error_code.clone();
            p.model = input.resource_model.clone().or(p.model.take());
            p.tokens.extend(input.client_request_token.clone());
            Ok(())
        })
    }

    pub(crate) fn get_hook_result_op(
        &self,
        ctx: &RequestContext,
        input: types::GetHookResultInput,
    ) -> Result<types::GetHookResultOutput, ServiceError> {
        ctx.authorize("cloudformation:GetHookResult", "*", Default::default())?;
        let id = input.hook_result_id.clone().unwrap_or_default();
        let h = self
            .with_registry(|r| r.hook_results.get(&id).cloned())
            .filter(|h| h.account == ctx.caller.account_id && h.region == ctx.region)
            .ok_or_else(|| errors::hook_result_not_found(format!("Hook result {id} not found")))?;
        Ok(types::GetHookResultOutput {
            hook_result_id: Some(h.id.clone()),
            invocation_point: Some("PRE_PROVISION".into()),
            failure_mode: Some(h.failure_mode.clone()),
            type_name: Some(h.type_name.clone()),
            original_type_name: Some(h.type_name.clone()),
            type_version_id: Some(h.type_version.clone()),
            type_configuration_version_id: Some("00000001".into()),
            type_arn: Some(h.type_arn.clone()),
            status: Some(h.status.clone()),
            hook_status_reason: h.reason.clone(),
            invoked_at: Some(h.invoked_at),
            target: Some(types::HookTarget {
                target_type: "RESOURCE".into(),
                target_type_name: h.target_type_name.clone(),
                target_id: h.target_logical_id.clone(),
                action: h.action.clone(),
            }),
            annotations: Some(vec![]),
        })
    }

    pub(crate) fn list_hook_results_op(
        &self,
        ctx: &RequestContext,
        input: types::ListHookResultsInput,
    ) -> Result<types::ListHookResultsOutput, ServiceError> {
        ctx.authorize("cloudformation:ListHookResults", "*", Default::default())?;
        if input.target_type.is_some() != input.target_id.is_some() {
            return Err(validation("TargetType and TargetId must be specified together"));
        }
        if input.target_type.is_none() && input.type_arn.is_none() {
            return Err(validation("Either TargetType and TargetId, or TypeArn, must be specified"));
        }
        let stack_ids: Vec<String> = match (input.target_type.as_deref(), input.target_id.as_deref()) {
            (Some("STACK"), Some(id)) => {
                let st = self.state();
                crate::ops::find(&st, ctx, id).map(|s| vec![s.id.clone()]).unwrap_or_else(|_| vec![id.to_string()])
            }
            _ => vec![],
        };
        let mut all: Vec<HookResult> = self.with_registry(|r| {
            r.hook_results
                .values()
                .filter(|h| h.account == ctx.caller.account_id && h.region == ctx.region)
                .filter(|h| match (input.target_type.as_deref(), input.target_id.as_deref()) {
                    (Some("STACK"), Some(_)) => stack_ids.contains(&h.stack_id),
                    (Some("RESOURCE"), Some(id)) => h.target_logical_id == id,
                    (Some(_), Some(_)) => false,
                    _ => true,
                })
                .filter(|h| input.type_arn.as_ref().is_none_or(|a| &h.type_arn == a))
                .filter(|h| input.status.as_ref().is_none_or(|s| &h.status == s))
                .cloned()
                .collect()
        });
        all.sort_by_key(|h| h.invoked_at);
        let items: Vec<types::HookResultSummary> = all
            .iter()
            .map(|h| types::HookResultSummary {
                hook_result_id: Some(h.id.clone()),
                invocation_point: Some("PRE_PROVISION".into()),
                failure_mode: Some(h.failure_mode.clone()),
                type_name: Some(h.type_name.clone()),
                type_version_id: Some(h.type_version.clone()),
                type_configuration_version_id: Some("00000001".into()),
                status: Some(h.status.clone()),
                hook_status_reason: h.reason.clone(),
                invoked_at: Some(h.invoked_at),
                target_type: Some("STACK".into()),
                target_id: Some(h.stack_id.clone()),
                type_arn: Some(h.type_arn.clone()),
                hook_execution_target: Some(h.target_logical_id.clone()),
            })
            .collect();
        let (hook_results, next_token) = page(&items, input.next_token.as_deref(), 100)?;
        Ok(types::ListHookResultsOutput {
            target_type: input.target_type.clone(),
            target_id: input.target_id.clone(),
            hook_results: Some(hook_results),
            next_token,
        })
    }

    /// Private and activated types in the caller's account, for ListTypes.
    pub(crate) fn private_type_summaries(
        &self,
        ctx: &RequestContext,
        kind: &str,
        category: Option<&str>,
        deprecated: &str,
    ) -> Vec<types::TypeSummary> {
        self.with_registry(|r| {
            r.types
                .values()
                .filter(|t| t.account == ctx.caller.account_id && t.region == ctx.region && t.kind == kind)
                .filter(|t| match category {
                    Some("ACTIVATED") | Some("THIRD_PARTY") => t.activation.is_some(),
                    Some("REGISTERED") => t.activation.is_none(),
                    Some("AWS_TYPES") => false,
                    _ => true,
                })
                .filter(|t| {
                    let live = t.versions.values().any(|v| !v.deprecated);
                    (deprecated == "LIVE") == live
                })
                .map(|t| {
                    let v = t.versions.get(&t.default_version).cloned().unwrap_or_default();
                    let schema: Value = serde_json::from_str(&v.schema).unwrap_or(Value::Null);
                    types::TypeSummary {
                        r#type: Some(t.kind.clone()),
                        type_name: Some(t.name.clone()),
                        default_version_id: (t.activation.is_none()).then(|| t.default_version.clone()),
                        type_arn: Some(t.arn.clone()),
                        last_updated: Some(t.updated),
                        description: schema.get("description").and_then(Value::as_str).map(str::to_string),
                        publisher_id: t.activation.as_ref().map(|a| a.publisher_id.clone()),
                        original_type_name: t.activation.as_ref().map(|a| a.original_name.clone()),
                        public_version_number: t.activation.as_ref().map(|a| a.public_version.clone()),
                        latest_public_version: t
                            .activation
                            .as_ref()
                            .and_then(|a| r.public.values().find(|p| p.arn == a.public_arn).map(|p| p.latest.clone())),
                        is_activated: t.activation.as_ref().map(|_| true),
                        ..Default::default()
                    }
                })
                .collect()
        })
    }

    /// Published third-party types in the Region, for ListTypes.
    pub(crate) fn public_type_summaries(
        &self,
        ctx: &RequestContext,
        kind: &str,
        publisher: Option<&str>,
    ) -> Vec<types::TypeSummary> {
        self.with_registry(|r| {
            r.public
                .values()
                .filter(|p| p.region == ctx.region && p.kind == kind)
                .filter(|p| publisher.is_none_or(|x| x == p.publisher_id))
                .map(|p| {
                    let activated = r.types.values().any(|t| {
                        t.account == ctx.caller.account_id
                            && t.activation.as_ref().is_some_and(|a| a.public_arn == p.arn)
                    });
                    let schema: Value = p
                        .versions
                        .get(&p.latest)
                        .and_then(|(s, _)| serde_json::from_str(s).ok())
                        .unwrap_or(Value::Null);
                    types::TypeSummary {
                        r#type: Some(p.kind.clone()),
                        type_name: Some(p.name.clone()),
                        type_arn: Some(p.arn.clone()),
                        last_updated: Some(p.created),
                        description: schema.get("description").and_then(Value::as_str).map(str::to_string),
                        publisher_id: Some(p.publisher_id.clone()),
                        latest_public_version: Some(p.latest.clone()),
                        publisher_name: Some(p.publisher_id.clone()),
                        is_activated: Some(activated),
                        ..Default::default()
                    }
                })
                .collect()
        })
    }

    /// DescribeType for registry types; `None` when the name is not one.
    pub(crate) fn describe_registry_type(
        &self,
        ctx: &RequestContext,
        input: &types::DescribeTypeInput,
    ) -> Option<Result<types::DescribeTypeOutput, ServiceError>> {
        // A public third-party type.
        let public = self.with_registry(|r| {
            r.public
                .values()
                .find(|p| {
                    p.region == ctx.region
                        && match (&input.arn, &input.publisher_id, &input.type_name) {
                            (Some(a), _, _) => a == &p.arn || a.starts_with(&format!("{}/", p.arn)),
                            (None, Some(pid), Some(n)) => &p.publisher_id == pid && &p.name == n,
                            _ => false,
                        }
                })
                .cloned()
        });
        if let Some(p) =
            public.filter(|p| input.publisher_id.is_some() || input.arn.as_ref().is_some_and(|a| a.starts_with(&p.arn)))
        {
            let version = input
                .public_version_number
                .clone()
                .or_else(|| input.arn.as_ref().and_then(|a| a.strip_prefix(&format!("{}/", p.arn)).map(str::to_string)))
                .unwrap_or_else(|| p.latest.clone());
            let Some((schema, _)) = p.versions.get(&version) else {
                return Some(Err(type_not_found(&p.name)));
            };
            let s: Value = serde_json::from_str(schema).unwrap_or(Value::Null);
            return Some(Ok(types::DescribeTypeOutput {
                arn: Some(p.arn.clone()),
                r#type: Some(p.kind.clone()),
                type_name: Some(p.name.clone()),
                description: s.get("description").and_then(Value::as_str).map(str::to_string),
                schema: Some(schema.clone()),
                provisioning_type: Some(provisioning(&s)),
                deprecated_status: Some("LIVE".into()),
                visibility: Some("PUBLIC".into()),
                publisher_id: Some(p.publisher_id.clone()),
                public_version_number: Some(version),
                latest_public_version: Some(p.latest.clone()),
                type_tests_status: Some("PASSED".into()),
                time_created: Some(p.created),
                last_updated: Some(p.created),
                is_activated: Some(self.with_registry(|r| {
                    r.types.values().any(|t| {
                        t.account == ctx.caller.account_id
                            && t.activation.as_ref().is_some_and(|a| a.public_arn == p.arn)
                    })
                })),
                ..Default::default()
            }));
        }
        let found = self.resolve_type(ctx, input.r#type.as_deref(), input.type_name.as_deref(), input.arn.as_deref());
        let (t, arn_version) = match found {
            Ok(x) => x,
            Err(_) => return None,
        };
        let version = input.version_id.clone().or(arn_version).unwrap_or_else(|| t.default_version.clone());
        let Some(v) = t.versions.get(&version) else {
            return Some(Err(type_not_found(&format!("{}/{version}", t.arn))));
        };
        let s: Value = serde_json::from_str(&v.schema).unwrap_or(Value::Null);
        Some(Ok(types::DescribeTypeOutput {
            arn: Some(if input.version_id.is_some() { format!("{}/{version}", t.arn) } else { t.arn.clone() }),
            r#type: Some(t.kind.clone()),
            type_name: Some(t.name.clone()),
            default_version_id: t.activation.is_none().then(|| t.default_version.clone()),
            is_default_version: Some(version == t.default_version),
            type_tests_status: Some(v.tests_status.clone()),
            type_tests_status_description: v.tests_description.clone(),
            description: s.get("description").and_then(Value::as_str).map(str::to_string),
            schema: Some(v.schema.clone()),
            provisioning_type: (t.kind == "RESOURCE").then(|| provisioning(&s)),
            deprecated_status: Some(if v.deprecated { "DEPRECATED" } else { "LIVE" }.into()),
            logging_config: v.logging.clone(),
            execution_role_arn: v.execution_role_arn.clone(),
            visibility: Some("PRIVATE".into()),
            source_url: s.get("sourceUrl").and_then(Value::as_str).map(str::to_string),
            documentation_url: s.get("documentationUrl").and_then(Value::as_str).map(str::to_string),
            last_updated: Some(t.updated),
            time_created: Some(v.created),
            configuration_schema: s.get("typeConfiguration").map(|c| c.to_string()),
            publisher_id: t.activation.as_ref().map(|a| a.publisher_id.clone()),
            original_type_name: t.activation.as_ref().map(|a| a.original_name.clone()),
            original_type_arn: t.activation.as_ref().map(|a| a.public_arn.clone()),
            public_version_number: t.activation.as_ref().map(|a| a.public_version.clone()),
            latest_public_version: t.activation.as_ref().and_then(|a| {
                self.with_registry(|r| r.public.values().find(|p| p.arn == a.public_arn).map(|p| p.latest.clone()))
            }),
            is_activated: Some(t.activation.is_some()),
            auto_update: t.activation.as_ref().map(|a| a.auto_update),
            required_activated_types: None,
        }))
    }

    /// The resource provider for a private or activated resource type in
    /// an account, if there is one.
    pub(crate) fn registry_provider(&self, account: &str, region: &str, ty: &str) -> Option<Arc<dyn Provider>> {
        let t = self.with_registry(|r| r.types.get(&key(account, region, "RESOURCE", ty)).cloned())?;
        let v = t.versions.get(&t.default_version).filter(|v| !v.deprecated)?;
        static CACHE: OnceLock<Mutex<HashMap<String, Arc<dyn Provider>>>> = OnceLock::new();
        let cache_key = format!("{}#{}#{}", t.arn, v.id, v.schema.len());
        let cache = CACHE.get_or_init(Default::default);
        if let Some(p) = cache.lock().expect("lock").get(&cache_key) {
            return Some(p.clone());
        }
        let schema: Value = serde_json::from_str(&v.schema).ok()?;
        let leak = |v: Vec<String>| -> &'static [&'static str] {
            Box::leak(
                v.into_iter()
                    .map(|s| &*Box::leak(s.into_boxed_str()))
                    .collect::<Vec<&'static str>>()
                    .into_boxed_slice(),
            )
        };
        let p: Arc<dyn Provider> = Arc::new(RegistryProvider {
            key: key(account, region, "RESOURCE", ty),
            create_only: leak(pointers(&schema, "createOnlyProperties")),
            required: leak(
                schema
                    .get("required")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                    .unwrap_or_default(),
            ),
            attributes: leak(pointers(&schema, "readOnlyProperties")),
            updatable: schema.get("handlers").is_some_and(|h| h.get("update").is_some()),
            schema,
        });
        cache.lock().expect("lock").insert(cache_key, p.clone());
        Some(p)
    }

    /// Whether `ty` is a module type the account can use.
    pub(crate) fn has_registry_type(&self, account: &str, region: &str, ty: &str) -> bool {
        let kind = if ty.ends_with("::MODULE") { "MODULE" } else { "RESOURCE" };
        self.with_registry(|r| {
            r.types.get(&key(account, region, kind, ty)).is_some_and(|t| t.versions.values().any(|v| !v.deprecated))
        })
    }

    /// Run a resource or hook handler to completion: invoke it, follow
    /// `IN_PROGRESS` callbacks (and `RecordHandlerProgress` reports), and
    /// return the final resource model.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_handler(
        &self,
        ctx: &RequestContext,
        t: &RegType,
        version: &str,
        action: &str,
        model: Value,
        previous: Option<Value>,
        logical_id: &str,
        stack_id: &str,
    ) -> HResult<Value> {
        let v = t
            .versions
            .get(version)
            .cloned()
            .ok_or_else(|| HandlerError::invalid(format!("Type {} has no version {version}", t.name)))?;
        let function = self.handler_function(ctx, t, &v).await?;
        let roles = self
            .role_assumer()
            .ok_or_else(|| HandlerError::invalid("Registry handlers cannot run in this deployment"))?;
        let (svc, _) = roles.registry_identity(&t.account, ctx.received_at).map_err(HandlerError::invalid)?;
        let mut svc_ctx = ctx.clone();
        svc_ctx.caller = svc;
        let provider_creds = match &v.execution_role_arn {
            Some(role) => {
                let (a, s, tk) =
                    roles.credentials(role, REGISTRY_PRINCIPAL, "CloudFormation", ctx.received_at).map_err(|_| {
                        HandlerError::handler(
                            "AccessDenied",
                            format!("Role {role} cannot be assumed by {REGISTRY_PRINCIPAL}"),
                        )
                    })?;
                json!({"accessKeyId": a, "secretAccessKey": s, "sessionToken": tk})
            }
            None => Value::Null,
        };
        let config = t.configurations.get("default").and_then(|(c, _)| serde_json::from_str::<Value>(c).ok());
        let bearer = uuid::Uuid::new_v4().to_string();
        self.with_registry(|r| {
            r.progress.insert(bearer.clone(), Progress { status: "PENDING".into(), ..Default::default() })
        });
        let mut callback: Option<Value> = None;
        let mut result = Err(HandlerError::invalid("Handler did not complete"));
        for _ in 0..720 {
            let request = json!({
                "awsAccountId": t.account,
                "bearerToken": bearer,
                "region": t.region,
                "action": action,
                "responseEndpoint": format!("https://cloudformation.{}.amazonaws.com", t.region),
                "resourceType": t.name,
                "resourceTypeVersion": version,
                "requestData": {
                    "callerCredentials": provider_creds,
                    "providerCredentials": provider_creds,
                    "providerLogGroupName": v.logging.as_ref().map(|l| l.log_group_name.clone()),
                    "logicalResourceId": logical_id,
                    "resourceProperties": model,
                    "previousResourceProperties": previous,
                    "stackTags": {},
                    "previousStackTags": {},
                    "systemTags": {},
                    "typeConfiguration": config.as_ref().and_then(|c| c.get("CloudFormationConfiguration").cloned()).or(config.clone()),
                },
                "stackId": stack_id,
                "callbackContext": callback,
            });
            let out = self
                .call(
                    &svc_ctx,
                    "lambda",
                    "Invoke",
                    json!({"FunctionName": function, "Payload": base64::engine::general_purpose::STANDARD.encode(request.to_string())}),
                )
                .await;
            let out = match out {
                Ok(o) => o,
                Err(e) => {
                    result = Err(HandlerError::handler("InternalFailure", e.message));
                    break;
                }
            };
            let payload = out["Payload"]
                .as_str()
                .and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok())
                .unwrap_or_default();
            let body: Value = serde_json::from_slice(&payload).unwrap_or(Value::Null);
            if out.get("FunctionError").is_some_and(|e| !e.is_null()) {
                result = Err(HandlerError::handler(
                    "InternalFailure",
                    body.get("errorMessage").and_then(Value::as_str).unwrap_or("The handler failed"),
                ));
                break;
            }
            let ev = parse_progress(&body);
            self.with_registry(|r| {
                if let Some(p) = r.progress.get_mut(&bearer) {
                    if p.status == "PENDING" {
                        p.status = "IN_PROGRESS".into();
                    }
                }
            });
            match ev.status.as_str() {
                "SUCCESS" => {
                    result = Ok(ev.model.unwrap_or(model.clone()));
                    break;
                }
                "FAILED" => {
                    result = Err(HandlerError::handler(
                        ev.error_code.as_deref().unwrap_or("GeneralServiceException"),
                        ev.message.unwrap_or_default(),
                    ));
                    break;
                }
                _ => {
                    callback = ev.callback_context;
                    // Wait for the callback, or for RecordHandlerProgress to
                    // finish the operation.
                    let until = std::time::Instant::now() + Duration::from_secs(ev.delay.min(3600));
                    let mut reported = None;
                    loop {
                        let p = self.with_registry(|r| r.progress.get(&bearer).cloned()).unwrap_or_default();
                        if p.status == "SUCCESS" || p.status == "FAILED" {
                            reported = Some(p);
                            break;
                        }
                        if std::time::Instant::now() >= until {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    if let Some(p) = reported {
                        result = if p.status == "SUCCESS" {
                            Ok(p.model
                                .and_then(|m| serde_json::from_str(&m).ok())
                                .unwrap_or(ev.model.unwrap_or(model.clone())))
                        } else {
                            Err(HandlerError::handler(
                                p.error_code.as_deref().unwrap_or("GeneralServiceException"),
                                p.message.unwrap_or_default(),
                            ))
                        };
                        break;
                    }
                }
            }
        }
        self.with_registry(|r| {
            if let Some(p) = r.progress.get_mut(&bearer) {
                p.status = if result.is_ok() { "SUCCESS".into() } else { "FAILED".into() };
            }
        });
        result
    }

    /// Deploy a type version's handler code as a Lambda function.
    async fn handler_function(&self, ctx: &RequestContext, t: &RegType, v: &TypeVersion) -> HResult<String> {
        let name: String =
            format!("CloudFormation-{}-{}-{}", kind_path(&t.kind), dashed(&t.name), v.id).chars().take(64).collect();
        let roles = self
            .role_assumer()
            .ok_or_else(|| HandlerError::invalid("Registry handlers cannot run in this deployment"))?;
        let (svc, role_arn) = roles.registry_identity(&t.account, ctx.received_at).map_err(HandlerError::invalid)?;
        let mut svc_ctx = ctx.clone();
        svc_ctx.caller = svc;
        svc_ctx.region = t.region.clone();
        if self.call(&svc_ctx, "lambda", "GetFunction", json!({"FunctionName": name})).await.is_ok() {
            return Ok(name);
        }
        let bytes = base64::engine::general_purpose::STANDARD.decode(&v.package).unwrap_or_default();
        let pkg = Package::read(&bytes).map_err(HandlerError::invalid)?;
        let config = pkg.config();
        let runtime = config
            .get("runtime")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                config.get("settings").and_then(|s| s.get("runtime")).and_then(Value::as_str).map(str::to_string)
            })
            .unwrap_or_else(|| "python3.12".into());
        let handler = config
            .get("entrypoint")
            .and_then(Value::as_str)
            .unwrap_or(if t.kind == "HOOK" { "handler.hook" } else { "handler.resource" })
            .to_string();
        let code = pkg.code(&bytes);
        let created = self
            .call(
                &svc_ctx,
                "lambda",
                "CreateFunction",
                json!({
                    "FunctionName": name,
                    "Runtime": runtime,
                    "Handler": handler,
                    "Role": role_arn,
                    "Timeout": 900,
                    "Code": {"ZipFile": base64::engine::general_purpose::STANDARD.encode(code)},
                    "Description": format!("Handlers for the CloudFormation registry type {} version {}", t.name, v.id),
                }),
            )
            .await;
        match created {
            Ok(_) => Ok(name),
            Err(e) if e.code.contains("ResourceConflict") => Ok(name),
            Err(e) => Err(HandlerError::handler(
                "InternalFailure",
                format!("The type's handlers could not be deployed: {}", e.message),
            )),
        }
    }

    /// Run the hooks that target a resource before it is provisioned.
    /// Returns the hooks' events to record and whether provisioning may go
    /// ahead.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_hooks(
        &self,
        ctx: &RequestContext,
        stack_id: &str,
        logical_id: &str,
        resource_type: &str,
        action: &str,
        props: &Props,
        previous: Option<&Props>,
        mut on_event: impl FnMut(HookEvent) + Send,
    ) -> Result<(), String> {
        let account = ctx.caller.account_id.clone();
        let region = ctx.region.clone();
        let hooks: Vec<RegType> = self.with_registry(|r| {
            r.types
                .values()
                .filter(|t| t.account == account && t.region == region && t.kind == "HOOK")
                .filter(|t| t.versions.values().any(|v| !v.deprecated))
                .cloned()
                .collect()
        });
        let point = match action {
            "CREATE" => ("preCreate", "CREATE_PRE_PROVISION"),
            "UPDATE" => ("preUpdate", "UPDATE_PRE_PROVISION"),
            _ => ("preDelete", "DELETE_PRE_PROVISION"),
        };
        let mut failed = Vec::new();
        for t in hooks {
            let Some((config, _)) = t.configurations.get("default").cloned() else { continue };
            let config: Value = serde_json::from_str(&config).unwrap_or(Value::Null);
            let hc = &config["CloudFormationConfiguration"]["HookConfiguration"];
            if hc["HookInvocationStatus"].as_str() != Some("ENABLED") || hc["TargetStacks"].as_str() == Some("NONE") {
                continue;
            }
            let v = t.versions.get(&t.default_version).cloned().unwrap_or_default();
            let schema: Value = serde_json::from_str(&v.schema).unwrap_or(Value::Null);
            let targets: Vec<String> = schema["handlers"][point.0]["targetNames"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            if !targets.iter().any(|p| glob(p, resource_type)) {
                continue;
            }
            let failure_mode = hc["FailureMode"].as_str().unwrap_or("FAIL").to_string();
            let invocation = uuid::Uuid::new_v4().to_string();
            on_event(HookEvent {
                hook_type: t.name.clone(),
                status: "HOOK_IN_PROGRESS".into(),
                reason: Some("Hook invocation is in progress".into()),
                point: point.1.into(),
                failure_mode: failure_mode.clone(),
                invocation_id: invocation.clone(),
            });
            let outcome =
                self.invoke_hook(ctx, &t, &v, point, stack_id, logical_id, resource_type, props, previous, hc).await;
            let (status, reason) = match &outcome {
                Ok(m) => ("HOOK_COMPLETE_SUCCEEDED", m.clone().unwrap_or_else(|| "Hook succeeded".into())),
                Err(m) => ("HOOK_COMPLETE_FAILED", m.clone()),
            };
            let result = HookResult {
                id: invocation.clone(),
                invocation_point: point.1.into(),
                failure_mode: failure_mode.clone(),
                type_name: t.name.clone(),
                type_version: t.default_version.clone(),
                type_arn: t.arn.clone(),
                status: if outcome.is_ok() { "HOOK_COMPLETE_SUCCEEDED".into() } else { "HOOK_COMPLETE_FAILED".into() },
                reason: Some(reason.clone()),
                invoked_at: Utc::now(),
                stack_id: stack_id.to_string(),
                account: account.clone(),
                region: region.clone(),
                target_type_name: resource_type.to_string(),
                target_logical_id: logical_id.to_string(),
                action: action.to_string(),
            };
            self.with_registry(|r| r.hook_results.insert(invocation.clone(), result));
            on_event(HookEvent {
                hook_type: t.name.clone(),
                status: status.into(),
                reason: Some(reason),
                point: point.1.into(),
                failure_mode: failure_mode.clone(),
                invocation_id: invocation,
            });
            if outcome.is_err() && failure_mode == "FAIL" {
                failed.push(t.name.clone());
            }
        }
        if failed.is_empty() {
            Ok(())
        } else {
            Err(format!("The following hook(s) failed: [{}]", failed.join(", ")))
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn invoke_hook(
        &self,
        ctx: &RequestContext,
        t: &RegType,
        v: &TypeVersion,
        point: (&str, &str),
        stack_id: &str,
        logical_id: &str,
        resource_type: &str,
        props: &Props,
        previous: Option<&Props>,
        hc: &Value,
    ) -> Result<Option<String>, String> {
        let function = self.handler_function(ctx, t, v).await.map_err(|e| e.message)?;
        let roles = self.role_assumer().ok_or("Hooks cannot run in this deployment")?;
        let (svc, _) = roles.registry_identity(&t.account, ctx.received_at)?;
        let mut svc_ctx = ctx.clone();
        svc_ctx.caller = svc;
        let creds = match &v.execution_role_arn {
            Some(role) => match roles.credentials(role, HOOKS_PRINCIPAL, "CloudFormationHook", ctx.received_at) {
                Ok((a, s, tk)) => json!({"accessKeyId": a, "secretAccessKey": s, "sessionToken": tk}),
                Err(_) => Value::Null,
            },
            None => Value::Null,
        };
        let mut callback: Option<Value> = None;
        for invocation in 1..=60 {
            let request = json!({
                "clientRequestToken": uuid::Uuid::new_v4().to_string(),
                "awsAccountId": t.account,
                "stackId": stack_id,
                "hookTypeName": t.name,
                "hookTypeVersion": t.default_version,
                "hookModel": hc.get("Properties").cloned().unwrap_or(json!({})),
                "actionInvocationPoint": point.1,
                "requestData": {
                    "targetName": resource_type,
                    "targetType": "RESOURCE",
                    "targetLogicalId": logical_id,
                    "targetModel": {
                        "resourceProperties": Value::Object(props.clone()),
                        "previousResourceProperties": previous.map(|p| Value::Object(p.clone())),
                    },
                    "callerCredentials": creds,
                    "providerCredentials": creds,
                    "providerLogGroupName": v.logging.as_ref().map(|l| l.log_group_name.clone()),
                },
                "requestContext": {"invocation": invocation, "callbackContext": callback},
            });
            let out = self
                .call(
                    &svc_ctx,
                    "lambda",
                    "Invoke",
                    json!({"FunctionName": function, "Payload": base64::engine::general_purpose::STANDARD.encode(request.to_string())}),
                )
                .await
                .map_err(|e| e.message)?;
            let payload = out["Payload"]
                .as_str()
                .and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok())
                .unwrap_or_default();
            let body: Value = serde_json::from_slice(&payload).unwrap_or(Value::Null);
            if out.get("FunctionError").is_some_and(|e| !e.is_null()) {
                return Err(body
                    .get("errorMessage")
                    .and_then(Value::as_str)
                    .unwrap_or("The hook handler failed")
                    .to_string());
            }
            let ev = parse_progress(&body);
            match ev.status.as_str() {
                "SUCCESS" => return Ok(ev.message),
                "IN_PROGRESS" => {
                    callback = ev.callback_context;
                    tokio::time::sleep(Duration::from_secs(ev.delay.min(30))).await;
                }
                _ => return Err(ev.message.unwrap_or_else(|| "Hook failed".into())),
            }
        }
        Err("Hook timed out".into())
    }

    /// Expand module resources (`*::MODULE`) into their fragments'
    /// resources, as CloudFormation processes a template that uses
    /// modules. Templates without modules come back unchanged.
    pub(crate) fn expand_modules(&self, ctx: &RequestContext, body: &str) -> Result<String, ServiceError> {
        if !body.contains("::MODULE") {
            return Ok(body.to_string());
        }
        let t = crate::template::Template::parse(body).map_err(validation)?;
        let mut root = Value::Object(t.root.clone());
        let mut changed = false;
        for _ in 0..5 {
            let modules: Vec<(String, String)> = root
                .get("Resources")
                .and_then(Value::as_object)
                .map(|r| {
                    r.iter()
                        .filter_map(|(k, v)| {
                            let ty = v.get("Type")?.as_str()?;
                            ty.ends_with("::MODULE").then(|| (k.clone(), ty.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            if modules.is_empty() {
                break;
            }
            changed = true;
            for (logical, ty) in modules {
                let fragment = self.module_fragment(ctx, &ty)?;
                expand_one(&mut root, &logical, &fragment).map_err(validation)?;
            }
        }
        if !changed {
            return Ok(body.to_string());
        }
        Ok(serde_json::to_string_pretty(&root).unwrap_or_default())
    }

    fn module_fragment(&self, ctx: &RequestContext, ty: &str) -> Result<Value, ServiceError> {
        let t = self
            .with_registry(|r| r.types.get(&key(&ctx.caller.account_id, &ctx.region, "MODULE", ty)).cloned())
            .filter(|t| t.versions.values().any(|v| !v.deprecated))
            .ok_or_else(|| validation(format!("Template format error: Unrecognized resource types: [{ty}]")))?;
        let v = t.versions.get(&t.default_version).cloned().unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD.decode(&v.package).unwrap_or_default();
        let pkg = Package::read(&bytes).map_err(validation)?;
        let text = pkg.fragment().ok_or_else(|| validation(format!("Module {ty} has no fragment")))?;
        Ok(Value::Object(crate::template::Template::parse(&text).map_err(validation)?.root))
    }
}

/// What a hook invocation reports as a stack event.
pub(crate) struct HookEvent {
    pub hook_type: String,
    pub status: String,
    pub reason: Option<String>,
    pub point: String,
    pub failure_mode: String,
    pub invocation_id: String,
}

fn glob(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == value,
        Some((pre, post)) => value.starts_with(pre) && value[pre.len()..].ends_with(post),
    }
}

fn provisioning(schema: &Value) -> String {
    let h = schema.get("handlers");
    match h {
        Some(h) if h.get("create").is_some() && h.get("update").is_some() => "FULLY_MUTABLE".into(),
        Some(h) if h.get("create").is_some() => "IMMUTABLE".into(),
        _ => "NON_PROVISIONABLE".into(),
    }
}

fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.').map(|p| p.parse::<u64>().ok());
    let a = it.next()??;
    let b = it.next().flatten().unwrap_or(0);
    let c = it.next().flatten().unwrap_or(0);
    Some((a, b, c))
}

fn config_arn(ctx: &RequestContext, t: &RegType, alias: &str) -> String {
    format!(
        "arn:{}:cloudformation:{}:{}:type-configuration/{}/{}/{alias}",
        ctx.partition,
        t.region,
        t.account,
        kind_path(&t.kind),
        dashed(&t.name)
    )
}

/// The primary identifier values of a model, as a model.
fn identifier_model(schema: &Value, model: &Value) -> Value {
    let mut out = Map::new();
    for p in pointers(schema, "primaryIdentifier") {
        if let Some(v) = get_path(model, &p) {
            out.insert(p.clone(), v.clone());
        }
    }
    Value::Object(out)
}

fn merge_ids(model: &mut Value, ids: &Value) {
    if let (Some(m), Some(i)) = (model.as_object_mut(), ids.as_object()) {
        for (k, v) in i {
            m.insert(k.clone(), v.clone());
        }
    }
}

/// A private resource type's handlers.
struct RegistryProvider {
    key: String,
    schema: Value,
    create_only: &'static [&'static str],
    required: &'static [&'static str],
    attributes: &'static [&'static str],
    updatable: bool,
}

impl RegistryProvider {
    fn current(&self, cx: &Cx<'_>) -> HResult<(RegType, String)> {
        let t = cx
            .cfn
            .with_registry(|r| r.types.get(&self.key).cloned())
            .ok_or_else(|| HandlerError::invalid(format!("Type {} is no longer registered", self.key)))?;
        let v = t.default_version.clone();
        Ok((t, v))
    }

    fn physical_id(&self, model: &Value) -> String {
        pointers(&self.schema, "primaryIdentifier")
            .iter()
            .map(|p| get_path(model, p).map(scalar_text).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("|")
    }

    fn ids(&self, physical_id: &str, attrs: &Props) -> Map<String, Value> {
        let mut out = Map::new();
        let ids = pointers(&self.schema, "primaryIdentifier");
        let parts: Vec<&str> = physical_id.split('|').collect();
        for (n, p) in ids.iter().enumerate() {
            let v = attrs
                .get(p)
                .cloned()
                .unwrap_or_else(|| Value::String(parts.get(n).copied().unwrap_or_default().to_string()));
            out.insert(p.clone(), v);
        }
        out
    }
}

fn attrs_of(model: &Value) -> Props {
    let mut out = Props::new();
    if let Some(m) = model.as_object() {
        for (k, v) in m {
            out.insert(k.clone(), v.clone());
            if let Some(inner) = v.as_object() {
                for (k2, v2) in inner {
                    out.insert(format!("{k}.{k2}"), v2.clone());
                }
            }
        }
    }
    out
}

#[async_trait::async_trait]
impl Provider for RegistryProvider {
    fn create_only(&self) -> &'static [&'static str] {
        self.create_only
    }

    fn required(&self) -> &'static [&'static str] {
        self.required
    }

    fn attributes(&self) -> &'static [&'static str] {
        self.attributes
    }

    fn updatable(&self) -> bool {
        self.updatable
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let (t, v) = self.current(cx)?;
        let model = cx
            .cfn
            .run_handler(cx.ctx, &t, &v, "CREATE", Value::Object(props.clone()), None, cx.logical_id, cx.stack_id)
            .await?;
        let id = self.physical_id(&model);
        if id.replace('|', "").is_empty() {
            return Err(HandlerError::handler(
                "InternalFailure",
                "The handler's model is missing its primary identifier",
            ));
        }
        Ok(Created { physical_id: id, attributes: attrs_of(&model) })
    }

    async fn update(&self, cx: &Cx<'_>, physical_id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let (t, v) = self.current(cx)?;
        let mut model = new.clone();
        model.extend(self.ids(physical_id, attrs));
        let mut previous = old.clone();
        previous.extend(self.ids(physical_id, attrs));
        let out = cx
            .cfn
            .run_handler(
                cx.ctx,
                &t,
                &v,
                "UPDATE",
                Value::Object(model),
                Some(Value::Object(previous)),
                cx.logical_id,
                cx.stack_id,
            )
            .await?;
        Ok(attrs_of(&out))
    }

    async fn delete(&self, cx: &Cx<'_>, physical_id: &str, props: &Props, attrs: &Props) -> HResult<()> {
        let (t, v) = self.current(cx)?;
        let mut model = props.clone();
        model.extend(self.ids(physical_id, attrs));
        match cx.cfn.run_handler(cx.ctx, &t, &v, "DELETE", Value::Object(model), None, cx.logical_id, cx.stack_id).await
        {
            Ok(_) => Ok(()),
            Err(e) if e.not_found => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn read(&self, cx: &Cx<'_>, physical_id: &str, props: &Props) -> Option<HResult<Props>> {
        let (t, v) = match self.current(cx) {
            Ok(x) => x,
            Err(e) => return Some(Err(e)),
        };
        let ids = self.ids(physical_id, &Props::new());
        let out =
            cx.cfn.run_handler(cx.ctx, &t, &v, "READ", Value::Object(ids), None, cx.logical_id, cx.stack_id).await;
        Some(out.map(|m| {
            let mut live = Props::new();
            if let Some(m) = m.as_object() {
                for k in props.keys() {
                    if let Some(v) = m.get(k) {
                        live.insert(k.clone(), v.clone());
                    }
                }
            }
            live
        }))
    }
}

/// Splice one module's fragment into a template in place of the module
/// resource `logical`.
fn expand_one(root: &mut Value, logical: &str, fragment: &Value) -> Result<(), String> {
    let module = root["Resources"][logical].clone();
    let given = module.get("Properties").and_then(Value::as_object).cloned().unwrap_or_default();
    let params = fragment.get("Parameters").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut values = Map::new();
    for (p, decl) in &params {
        match given.get(p).or_else(|| decl.get("Default")) {
            Some(v) => {
                values.insert(p.clone(), v.clone());
            }
            None => {
                return Err(format!(
                    "Template error: Module {logical} requires the parameter {p}, which is not specified"
                ))
            }
        }
    }
    for k in given.keys() {
        if !params.contains_key(k) {
            return Err(format!("Template error: Module {logical} has no parameter {k}"));
        }
    }
    let resources = fragment.get("Resources").and_then(Value::as_object).cloned().unwrap_or_default();
    let names: Vec<String> = resources.keys().cloned().collect();
    let conditions: Vec<String> =
        fragment.get("Conditions").and_then(Value::as_object).map(|c| c.keys().cloned().collect()).unwrap_or_default();
    let rename = |n: &str| format!("{logical}{n}");
    let rw = Rewriter { logical, names: &names, conditions: &conditions, values: &values };
    let root_obj = root.as_object_mut().ok_or("Template format error: not an object")?;
    // Conditions and Mappings come along, renamed.
    if let Some(c) = fragment.get("Conditions").and_then(Value::as_object) {
        let target = root_obj.entry("Conditions").or_insert_with(|| json!({}));
        for (k, v) in c {
            target[rename(k)] = rw.rewrite(v);
        }
    }
    if let Some(m) = fragment.get("Mappings").and_then(Value::as_object) {
        let target = root_obj.entry("Mappings").or_insert_with(|| json!({}));
        for (k, v) in m {
            target[k.clone()] = v.clone();
        }
    }
    let res =
        root_obj.get_mut("Resources").and_then(Value::as_object_mut).ok_or("Template format error: no Resources")?;
    res.remove(logical);
    for (name, def) in &resources {
        let mut d = rw.rewrite(def);
        if let Some(o) = d.as_object_mut() {
            for attr in ["DeletionPolicy", "UpdateReplacePolicy", "Condition"] {
                if !o.contains_key(attr) {
                    if let Some(v) = module.get(attr) {
                        o.insert(attr.into(), v.clone());
                    }
                }
            }
            if let Some(Value::String(c)) = o.get("Condition").cloned() {
                if conditions.contains(&c) {
                    o.insert("Condition".into(), Value::String(rename(&c)));
                }
            }
            let mut deps: Vec<Value> = match o.get("DependsOn") {
                Some(Value::String(s)) => vec![Value::String(s.clone())],
                Some(Value::Array(a)) => a.clone(),
                _ => vec![],
            };
            for dep in deps.iter_mut() {
                if let Value::String(s) = dep {
                    if names.contains(s) {
                        *s = rename(s);
                    }
                }
            }
            if let Some(v) = module.get("DependsOn") {
                match v {
                    Value::String(s) => deps.push(Value::String(s.clone())),
                    Value::Array(a) => deps.extend(a.iter().cloned()),
                    _ => {}
                }
            }
            if !deps.is_empty() {
                o.insert("DependsOn".into(), Value::Array(deps));
            }
        }
        res.insert(rename(name), d);
    }
    // The parent refers to module resources as `Module.Resource`.
    let parent = std::mem::take(root);
    *root = rewrite_parent(&parent, logical, &names);
    Ok(())
}

struct Rewriter<'a> {
    logical: &'a str,
    names: &'a [String],
    conditions: &'a [String],
    values: &'a Map<String, Value>,
}

impl Rewriter<'_> {
    fn rewrite(&self, v: &Value) -> Value {
        match v {
            Value::Object(m) if m.len() == 1 => {
                let (k, inner) = m.iter().next().expect("one entry");
                match k.as_str() {
                    "Ref" => {
                        if let Some(name) = inner.as_str() {
                            if let Some(value) = self.values.get(name) {
                                return value.clone();
                            }
                            if self.names.iter().any(|n| n == name) {
                                return json!({"Ref": format!("{}{name}", self.logical)});
                            }
                        }
                        v.clone()
                    }
                    "Fn::GetAtt" => {
                        let mut parts: Vec<Value> = match inner {
                            Value::String(s) => s.splitn(2, '.').map(|p| Value::String(p.to_string())).collect(),
                            Value::Array(a) => a.clone(),
                            _ => vec![],
                        };
                        if let Some(Value::String(r)) = parts.first() {
                            if self.names.contains(r) {
                                parts[0] = Value::String(format!("{}{r}", self.logical));
                            }
                        }
                        json!({"Fn::GetAtt": parts.iter().map(|p| self.rewrite(p)).collect::<Vec<_>>()})
                    }
                    "Fn::Sub" => {
                        let (text, vars) = match inner {
                            Value::String(s) => (s.clone(), None),
                            Value::Array(a) => {
                                (a.first().and_then(Value::as_str).unwrap_or_default().to_string(), a.get(1).cloned())
                            }
                            _ => return v.clone(),
                        };
                        let text = self.sub_text(&text, vars.as_ref());
                        match vars {
                            Some(vars) => json!({"Fn::Sub": [text, self.rewrite(&vars)]}),
                            None => json!({"Fn::Sub": text}),
                        }
                    }
                    "Fn::If" => {
                        let mut a = inner.as_array().cloned().unwrap_or_default();
                        if let Some(Value::String(c)) = a.first() {
                            if self.conditions.contains(c) {
                                a[0] = Value::String(format!("{}{c}", self.logical));
                            }
                        }
                        json!({"Fn::If": a.iter().map(|x| self.rewrite(x)).collect::<Vec<_>>()})
                    }
                    "Condition" => match inner.as_str() {
                        Some(c) if self.conditions.iter().any(|x| x == c) => {
                            json!({"Condition": format!("{}{c}", self.logical)})
                        }
                        _ => v.clone(),
                    },
                    _ => Value::Object(m.iter().map(|(k, x)| (k.clone(), self.rewrite(x))).collect()),
                }
            }
            Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), self.rewrite(x))).collect()),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.rewrite(x)).collect()),
            other => other.clone(),
        }
    }

    fn sub_text(&self, text: &str, vars: Option<&Value>) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let Some(end) = after.find('}') else {
                out.push_str(&rest[start..]);
                return out;
            };
            let name = &after[..end];
            let local = vars.and_then(|v| v.get(name)).is_some();
            let (head, tail) = name.split_once('.').map(|(h, t)| (h, Some(t))).unwrap_or((name, None));
            if name.starts_with('!') || local {
                out.push_str(&format!("${{{name}}}"));
            } else if let (Some(value), None) = (self.values.get(head), tail) {
                out.push_str(&scalar_text(value).replace("${", "${!"));
            } else if self.names.iter().any(|n| n == head) {
                match tail {
                    Some(t) => out.push_str(&format!("${{{}{head}.{t}}}", self.logical)),
                    None => out.push_str(&format!("${{{}{head}}}", self.logical)),
                }
            } else {
                out.push_str(&format!("${{{name}}}"));
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        out
    }
}

/// Rewrite `Module.Resource` references in the parent template.
fn rewrite_parent(v: &Value, logical: &str, names: &[String]) -> Value {
    let dotted = |s: &str| -> Option<String> {
        let rest = s.strip_prefix(logical)?.strip_prefix('.')?;
        let (res, tail) = rest.split_once('.').map(|(a, b)| (a, Some(b))).unwrap_or((rest, None));
        names.iter().any(|n| n == res).then(|| match tail {
            Some(t) => format!("{logical}{res}.{t}"),
            None => format!("{logical}{res}"),
        })
    };
    match v {
        Value::Object(m) if m.len() == 1 => {
            let (k, inner) = m.iter().next().expect("one entry");
            match (k.as_str(), inner) {
                ("Ref", Value::String(s)) => json!({"Ref": dotted(s).unwrap_or_else(|| s.clone())}),
                ("Fn::GetAtt", Value::String(s)) => match dotted(s) {
                    Some(d) => {
                        let (r, a) = d.split_once('.').unwrap_or((&d, ""));
                        json!({"Fn::GetAtt": [r, a]})
                    }
                    None => v.clone(),
                },
                ("Fn::GetAtt", Value::Array(a)) => {
                    let mut a = a.clone();
                    match (a.first().and_then(Value::as_str), a.get(1).and_then(Value::as_str)) {
                        // [Module, Resource.Attribute] (the YAML short form).
                        (Some(m), Some(rest)) if m == logical => {
                            if let Some((res, attr)) = rest.split_once('.') {
                                if names.iter().any(|n| n == res) {
                                    return json!({"Fn::GetAtt": [format!("{logical}{res}"), attr]});
                                }
                            }
                        }
                        // [Module.Resource, Attribute]
                        (Some(first), _) => {
                            if let Some(d) = dotted(first) {
                                a[0] = Value::String(d);
                            }
                        }
                        _ => {}
                    }
                    json!({"Fn::GetAtt": a})
                }
                ("Fn::Sub", _) => {
                    let fix = |t: &str| {
                        let mut out = t.to_string();
                        for n in names {
                            out = out.replace(&format!("${{{logical}.{n}"), &format!("${{{logical}{n}"));
                        }
                        out
                    };
                    match inner {
                        Value::String(s) => json!({"Fn::Sub": fix(s)}),
                        Value::Array(a) => {
                            let mut a = a.clone();
                            if let Some(Value::String(s)) = a.first().cloned() {
                                a[0] = Value::String(fix(&s));
                            }
                            json!({"Fn::Sub": a.iter().map(|x| rewrite_parent(x, logical, names)).collect::<Vec<_>>()})
                        }
                        _ => v.clone(),
                    }
                }
                _ => Value::Object(m.iter().map(|(k, x)| (k.clone(), rewrite_parent(x, logical, names))).collect()),
            }
        }
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, x) in m {
                let x = rewrite_parent(x, logical, names);
                if k == "DependsOn" {
                    let fix = |d: &Value| match d {
                        Value::String(s) if s == logical => {
                            Value::Array(names.iter().map(|n| Value::String(format!("{logical}{n}"))).collect())
                        }
                        Value::String(s) => Value::String(dotted(s).unwrap_or_else(|| s.clone())),
                        other => other.clone(),
                    };
                    let fixed = match &x {
                        Value::Array(a) => {
                            let mut v = Vec::new();
                            for d in a {
                                match fix(d) {
                                    Value::Array(many) => v.extend(many),
                                    one => v.push(one),
                                }
                            }
                            Value::Array(v)
                        }
                        one => fix(one),
                    };
                    out.insert(k.clone(), fixed);
                } else {
                    out.insert(k.clone(), x);
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| rewrite_parent(x, logical, names)).collect()),
        other => other.clone(),
    }
}
