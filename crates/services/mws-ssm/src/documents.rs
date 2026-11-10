//! SSM documents: create, version, describe, list, share and delete
//! documents, beside a catalogue of AWS-owned documents (`AWS-RunShellScript`
//! and others) that every account sees.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::{errors, types};
use crate::names::{now, page, request_tag_conditions, resource_tag_conditions};
use crate::Ssm;

/// Versions a document may keep.
const MAX_VERSIONS: usize = 1000;
/// Accounts a document may be shared with.
const MAX_SHARES: usize = 1000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DocVersion {
    pub version: i64,
    pub version_name: Option<String>,
    pub display_name: Option<String>,
    pub content: String,
    /// `JSON`, `YAML` or `TEXT`.
    pub format: String,
    pub created: DateTime<Utc>,
    pub requires: Option<Vec<types::DocumentRequires>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Document {
    pub name: String,
    pub document_type: String,
    pub target_type: Option<String>,
    /// Oldest first.
    pub versions: Vec<DocVersion>,
    pub default_version: i64,
    pub tags: BTreeMap<String, String>,
    /// Accounts it is shared with (`All` for everyone), and the version
    /// each sees (`$DEFAULT` or a number).
    pub shared_with: BTreeMap<String, String>,
    /// `Amazon` for the AWS-owned catalogue, else the owning account.
    pub owner: String,
}

impl Document {
    pub fn latest(&self) -> &DocVersion {
        self.versions.last().expect("documents always have a version")
    }

    pub fn default(&self) -> &DocVersion {
        self.version(self.default_version).unwrap_or_else(|| self.latest())
    }

    pub fn version(&self, v: i64) -> Option<&DocVersion> {
        self.versions.iter().find(|x| x.version == v)
    }

    fn by_name(&self, name: &str) -> Option<&DocVersion> {
        self.versions.iter().find(|x| x.version_name.as_deref() == Some(name))
    }

    pub fn amazon(&self) -> bool {
        self.owner == "Amazon"
    }
}

pub fn parse_content(content: &str, format: &str) -> Result<Value, ServiceError> {
    match format {
        "YAML" => serde_yaml::from_str::<Value>(content)
            .map_err(|e| errors::invalid_document_content(format!("YAML not well-formed. {e}"))),
        "TEXT" => Ok(Value::String(content.to_string())),
        _ => serde_json::from_str::<Value>(content).map_err(|e| {
            errors::invalid_document_content(format!(
                "JSON not well-formed. at Line: {}, Column: {}",
                e.line(),
                e.column()
            ))
        }),
    }
}

/// Check `content` is a valid document of `doc_type`; its schema version.
pub fn validate(content: &str, format: &str, doc_type: &str) -> Result<String, ServiceError> {
    let value = parse_content(content, format)?;
    if format == "TEXT" {
        return Ok(String::new());
    }
    let Some(obj) = value.as_object() else {
        return Err(errors::invalid_document_content("The content of the document must be a JSON or YAML object."));
    };
    let schema = match obj.get("schemaVersion") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => return Err(errors::invalid_document_content("Missing required field schemaVersion.")),
    };
    let allowed: &[&str] = match doc_type {
        "Command" => &["1.2", "2.0", "2.2"],
        "Automation" | "Automation.ChangeTemplate" => &["0.3"],
        "Session" => &["1.0"],
        "Policy" => &["2.0"],
        _ => &[],
    };
    if !allowed.is_empty() && !allowed.contains(&schema.as_str()) {
        return Err(errors::invalid_document_schema_version(format!(
            "Document schema version, {schema}, is not supported by association that is created with this document."
        )));
    }
    match (doc_type, schema.as_str()) {
        ("Command", "1.2") => {
            if !obj.get("runtimeConfig").is_some_and(Value::is_object) {
                return Err(errors::invalid_document_content("Missing required field runtimeConfig."));
            }
        }
        ("Command", _) | ("Automation", _) | ("Automation.ChangeTemplate", _) => {
            let Some(steps) = obj.get("mainSteps").and_then(Value::as_array) else {
                return Err(errors::invalid_document_content("Missing required field mainSteps."));
            };
            if steps.is_empty() {
                return Err(errors::invalid_document_content("mainSteps must contain at least one step."));
            }
            let mut names = Vec::new();
            for s in steps {
                let action = s.get("action").and_then(Value::as_str);
                let name = s.get("name").and_then(Value::as_str);
                let (Some(_), Some(name)) = (action, name) else {
                    return Err(errors::invalid_document_content("Every step needs an action and a name."));
                };
                if names.contains(&name) {
                    return Err(errors::invalid_document_content(format!("Step name {name} is not unique.")));
                }
                names.push(name);
            }
        }
        ("Session", _) if !obj.get("sessionType").is_some_and(Value::is_string) => {
            return Err(errors::invalid_document_content("Missing required field sessionType."));
        }
        _ => {}
    }
    if let Some(params) = obj.get("parameters") {
        let Some(params) = params.as_object() else {
            return Err(errors::invalid_document_content("parameters must be an object."));
        };
        for (name, p) in params {
            let t = p.get("type").and_then(Value::as_str).unwrap_or("");
            const TYPES: &[&str] = &["String", "StringList", "Integer", "Boolean", "MapList", "StringMap"];
            if !TYPES.contains(&t) && !t.starts_with("AWS::") {
                return Err(errors::invalid_document_content(format!(
                    "Parameter \"{name}\" has an invalid type \"{t}\"."
                )));
            }
        }
    }
    Ok(schema)
}

/// The plugins (`aws:runShellScript`, ...) a document runs, in order.
pub fn plugins(value: &Value) -> Vec<String> {
    if let Some(rc) = value.get("runtimeConfig").and_then(Value::as_object) {
        return rc.keys().cloned().collect();
    }
    value
        .get("mainSteps")
        .and_then(Value::as_array)
        .map(|s| s.iter().filter_map(|s| s.get("action").and_then(Value::as_str)).map(str::to_string).collect())
        .unwrap_or_default()
}

fn platforms(doc_type: &str, value: &Value) -> Vec<String> {
    let all = || vec!["Windows".to_string(), "Linux".to_string(), "MacOS".to_string()];
    if doc_type != "Command" {
        return all();
    }
    let mut out: Vec<String> = Vec::new();
    for p in plugins(value) {
        let these: &[&str] = match p.as_str() {
            "aws:runShellScript" => &["Linux", "MacOS"],
            "aws:runPowerShellScript" | "aws:applications" | "aws:psModule" | "aws:updateAgent" => &["Windows"],
            _ => &["Windows", "Linux", "MacOS"],
        };
        for t in these {
            if !out.iter().any(|o| o == t) {
                out.push(t.to_string());
            }
        }
    }
    if out.is_empty() {
        all()
    } else {
        // AWS lists them in this order.
        let order = ["Windows", "Linux", "MacOS"];
        out.sort_by_key(|p| order.iter().position(|o| o == p));
        out
    }
}

fn parameters(value: &Value) -> Vec<types::DocumentParameter> {
    let Some(params) = value.get("parameters").and_then(Value::as_object) else { return Vec::new() };
    params
        .iter()
        .map(|(name, p)| types::DocumentParameter {
            name: Some(name.clone()),
            r#type: p.get("type").and_then(Value::as_str).map(str::to_string),
            description: p.get("description").and_then(Value::as_str).map(str::to_string),
            default_value: p.get("default").map(|d| match d {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            }),
        })
        .collect()
}

pub fn sha256(content: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, content.as_bytes());
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:ssm:{region}:{account}:document/{name}")
}

fn doc_arn(ctx: &RequestContext, d: &Document) -> String {
    let account = if d.amazon() { "" } else { d.owner.as_str() };
    arn(&ctx.partition, &ctx.region, account, &d.name)
}

pub fn not_found(_name: &str) -> ServiceError {
    errors::invalid_document("The specified document does not exist.")
}

fn version_not_found() -> ServiceError {
    errors::invalid_document_version("The document version is not valid or does not exist.")
}

/// A `DocumentVersion` argument: a number, `$LATEST` or `$DEFAULT`.
pub fn pick_version<'a>(
    d: &'a Document,
    version: Option<&str>,
    version_name: Option<&str>,
) -> Result<&'a DocVersion, ServiceError> {
    let by_number = match version {
        None | Some("") | Some("$DEFAULT") => None,
        Some("$LATEST") => Some(d.latest()),
        Some(v) => Some(v.parse::<i64>().ok().and_then(|n| d.version(n)).ok_or_else(version_not_found)?),
    };
    match (by_number, version_name) {
        (Some(v), Some(n)) if v.version_name.as_deref() != Some(n) => Err(version_not_found()),
        (Some(v), _) => Ok(v),
        (None, Some(n)) => d.by_name(n).ok_or_else(version_not_found),
        (None, None) => Ok(d.default()),
    }
}

/// The AWS-owned documents every account sees.
fn catalogue() -> &'static BTreeMap<String, Document> {
    static DOCS: OnceLock<BTreeMap<String, Document>> = OnceLock::new();
    DOCS.get_or_init(|| {
        let created = DateTime::parse_from_rfc3339("2017-08-28T16:00:00Z").expect("valid date").with_timezone(&Utc);
        let docs: [(&str, &str, &str); 15] = [
            ("AWS-RunShellScript", "Command", RUN_SHELL_SCRIPT),
            ("AWS-RunPowerShellScript", "Command", RUN_POWERSHELL_SCRIPT),
            ("AWS-RunPatchBaseline", "Command", RUN_PATCH_BASELINE),
            ("AWS-GatherSoftwareInventory", "Policy", GATHER_SOFTWARE_INVENTORY),
            ("AWS-UpdateSSMAgent", "Command", UPDATE_SSM_AGENT),
            ("AWS-ConfigureAWSPackage", "Command", CONFIGURE_PACKAGE),
            ("AWS-StartPortForwardingSession", "Session", PORT_FORWARDING),
            ("AWS-StartInteractiveCommand", "Session", INTERACTIVE_COMMAND),
            ("AWS-StartPortForwardingSessionToRemoteHost", "Session", PORT_FORWARDING_REMOTE),
            ("AWS-StartSSHSession", "Session", SSH_SESSION),
            ("SSM-SessionManagerRunShell", "Session", RUN_SHELL),
            ("AWS-StopEC2Instance", "Automation", STOP_EC2_INSTANCE),
            ("AWS-StartEC2Instance", "Automation", START_EC2_INSTANCE),
            ("AWS-RestartEC2Instance", "Automation", RESTART_EC2_INSTANCE),
            ("AWS-CreateImage", "Automation", CREATE_IMAGE),
        ];
        docs.into_iter()
            .map(|(name, doc_type, content)| {
                let d = Document {
                    name: name.to_string(),
                    document_type: doc_type.to_string(),
                    target_type: None,
                    versions: vec![DocVersion {
                        version: 1,
                        content: content.to_string(),
                        format: "JSON".into(),
                        created,
                        ..Default::default()
                    }],
                    default_version: 1,
                    owner: "Amazon".into(),
                    ..Default::default()
                };
                (name.to_string(), d)
            })
            .collect()
    })
}

/// A document the caller can use: their own, an AWS-owned one, or one
/// another account shared with them (named by ARN). With the account that
/// owns it (empty for AWS).
pub(crate) struct Found {
    pub doc: Document,
    pub owner_account: String,
}

impl Ssm {
    pub(crate) fn find_document(&self, ctx: &RequestContext, name: &str) -> Option<Found> {
        self.find_document_in(&ctx.caller.account_id, &ctx.region, name)
    }

    /// [`Ssm::find_document`] for a caller in `caller` and `caller_region`.
    pub(crate) fn find_document_in(&self, caller: &str, caller_region: &str, name: &str) -> Option<Found> {
        let (account, region, bare) = match name.strip_prefix("arn:") {
            Some(rest) => {
                let parts: Vec<&str> = rest.splitn(5, ':').collect();
                if parts.len() != 5 || parts[1] != "ssm" {
                    return None;
                }
                let bare = parts[4].strip_prefix("document/")?;
                (parts[3].to_string(), parts[2].to_string(), bare.to_string())
            }
            None => (caller.to_string(), caller_region.to_string(), name.to_string()),
        };
        if let Some(d) = catalogue().get(&bare) {
            return (account.is_empty() || account == caller)
                .then(|| Found { doc: d.clone(), owner_account: String::new() });
        }
        let st = self.lock();
        let d = st.region_ref(&account, &region)?.documents.get(&bare)?;
        if account != caller && !d.shared_with.contains_key(caller) && !d.shared_with.contains_key("All") {
            return None;
        }
        Some(Found { doc: d.clone(), owner_account: account })
    }

    fn own_document(&self, ctx: &RequestContext, action: &str, name: &str) -> Result<Document, ServiceError> {
        if let Some(d) = catalogue().get(name) {
            ctx.authorize(&format!("ssm:{action}"), &doc_arn(ctx, d), ConditionContext::new())?;
            return Err(errors::invalid_document_operation("You can't modify documents that Amazon owns."));
        }
        let d = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.documents.get(name)).cloned()
        };
        let arn = arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, name);
        let cond = d.as_ref().map(|d| resource_tag_conditions(&d.tags)).unwrap_or_default();
        ctx.authorize(&format!("ssm:{action}"), &arn, cond)?;
        d.ok_or_else(|| not_found(name))
    }

    fn save_document(&self, ctx: &RequestContext, d: Document) {
        self.lock().region(&ctx.caller.account_id, &ctx.region).documents.insert(d.name.clone(), d);
    }

    pub(crate) fn create_document(
        &self,
        ctx: &RequestContext,
        input: types::CreateDocumentRequest,
    ) -> Result<types::CreateDocumentResult, ServiceError> {
        let tags: Vec<(String, String)> =
            input.tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect();
        let arn = arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.name);
        ctx.authorize("ssm:CreateDocument", &arn, request_tag_conditions(tags.iter().map(|(k, v)| (k, v))))?;
        let lower = input.name.to_ascii_lowercase();
        if ["aws", "amazon", "amzn"].iter().any(|p| lower.starts_with(p)) {
            return Err(errors::validation(
                "Document name can't start with the reserved prefixes aws, amazon or amzn.".to_string(),
            ));
        }
        let doc_type = input.document_type.unwrap_or_else(|| "Command".into());
        let format = input.document_format.unwrap_or_else(|| "JSON".into());
        if format == "TEXT" && doc_type != "ChangeCalendar" {
            return Err(errors::invalid_document_content(
                "TEXT format is supported only for ChangeCalendar documents.",
            ));
        }
        validate(&input.content, &format, &doc_type)?;
        if self
            .lock()
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .is_some_and(|r| r.documents.contains_key(&input.name))
        {
            return Err(errors::document_already_exists("Document with same name already exists."));
        }
        let d = Document {
            name: input.name,
            document_type: doc_type,
            target_type: input.target_type,
            versions: vec![DocVersion {
                version: 1,
                version_name: input.version_name,
                display_name: input.display_name,
                content: input.content,
                format,
                created: now(ctx),
                requires: input.requires,
            }],
            default_version: 1,
            tags: tags.into_iter().collect(),
            shared_with: BTreeMap::new(),
            owner: ctx.caller.account_id.clone(),
        };
        let mut desc = describe(ctx, &d, d.latest());
        desc.status = Some("Creating".into());
        self.save_document(ctx, d);
        Ok(types::CreateDocumentResult { document_description: Some(desc) })
    }

    pub(crate) fn describe_document(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDocumentRequest,
    ) -> Result<types::DescribeDocumentResult, ServiceError> {
        let found = self.readable(ctx, "DescribeDocument", &input.name)?;
        let v = pick_version(&found.doc, input.document_version.as_deref(), input.version_name.as_deref())?;
        Ok(types::DescribeDocumentResult { document: Some(describe(ctx, &found.doc, v)) })
    }

    /// A document the caller may read, authorized for `action`.
    fn readable(&self, ctx: &RequestContext, action: &str, name: &str) -> Result<Found, ServiceError> {
        let found = self.find_document(ctx, name);
        let arn = match &found {
            Some(f) => doc_arn(ctx, &f.doc),
            None => arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, name),
        };
        let cond = found.as_ref().map(|f| resource_tag_conditions(&f.doc.tags)).unwrap_or_default();
        ctx.authorize(&format!("ssm:{action}"), &arn, cond)?;
        found.ok_or_else(|| not_found(name))
    }

    pub(crate) fn get_document(
        &self,
        ctx: &RequestContext,
        input: types::GetDocumentRequest,
    ) -> Result<types::GetDocumentResult, ServiceError> {
        let found = self.readable(ctx, "GetDocument", &input.name)?;
        let d = &found.doc;
        let v = pick_version(d, input.document_version.as_deref(), input.version_name.as_deref())?;
        let format = input.document_format.unwrap_or_else(|| v.format.clone());
        let content = convert(&v.content, &v.format, &format)?;
        Ok(types::GetDocumentResult {
            name: Some(d.name.clone()),
            created_date: Some(v.created),
            display_name: v.display_name.clone(),
            version_name: v.version_name.clone(),
            document_version: Some(v.version.to_string()),
            status: Some("Active".into()),
            content: Some(content),
            document_type: Some(d.document_type.clone()),
            document_format: Some(format),
            requires: v.requires.clone(),
            attachments_content: None,
            review_status: None,
            status_information: None,
        })
    }

    pub(crate) fn list_documents(
        &self,
        ctx: &RequestContext,
        input: types::ListDocumentsRequest,
    ) -> Result<types::ListDocumentsResult, ServiceError> {
        ctx.authorize(
            "ssm:ListDocuments",
            &format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id),
            ConditionContext::new(),
        )?;
        let mut filters: Vec<(String, Vec<String>)> = Vec::new();
        for f in input.document_filter_list.unwrap_or_default() {
            let key = match f.key.as_str() {
                "Name" | "Owner" | "PlatformTypes" | "DocumentType" => f.key,
                _ => return Err(errors::invalid_filter_key("The specified key isn't valid.")),
            };
            filters.push((key, vec![f.value]));
        }
        for f in input.filters.unwrap_or_default() {
            let key = f.key.unwrap_or_default();
            let ok = matches!(
                key.as_str(),
                "Name" | "Owner" | "PlatformTypes" | "DocumentType" | "TargetType" | "SearchKeyword"
            ) || key.starts_with("tag:");
            if !ok {
                return Err(errors::invalid_filter_key("The specified key isn't valid."));
            }
            filters.push((key, f.values.unwrap_or_default()));
        }
        let account = ctx.caller.account_id.clone();
        let mut docs: Vec<Document> = catalogue().values().cloned().collect();
        {
            let st = self.lock();
            for (key, region) in &st.regions {
                let Some((acct, reg)) = key.split_once('/') else { continue };
                if reg != ctx.region {
                    continue;
                }
                for d in region.documents.values() {
                    if acct == account || d.shared_with.contains_key(&account) || d.shared_with.contains_key("All") {
                        docs.push(d.clone());
                    }
                }
            }
        }
        let owners = filters.iter().filter(|(k, _)| k == "Owner").flat_map(|(_, v)| v.clone()).collect::<Vec<_>>();
        docs.retain(|d| {
            let own = d.owner == account;
            let class_ok = owners.is_empty()
                || owners.iter().any(|o| match o.as_str() {
                    "Self" => own,
                    "Amazon" => d.amazon(),
                    "Private" => !own && !d.amazon() && !d.shared_with.contains_key("All"),
                    "Public" => d.amazon() || d.shared_with.contains_key("All"),
                    "All" => true,
                    other => d.owner == other,
                });
            class_ok
                && filters.iter().all(|(k, values)| {
                    let v = d.default();
                    let parsed = parse_content(&v.content, &v.format).unwrap_or(Value::Null);
                    match k.as_str() {
                        "Owner" => true,
                        "Name" => values.iter().any(|x| d.name.starts_with(x.as_str())),
                        "SearchKeyword" => {
                            values.iter().any(|x| d.name.to_ascii_lowercase().contains(&x.to_ascii_lowercase()))
                        }
                        "DocumentType" => values.contains(&d.document_type),
                        "TargetType" => values.iter().any(|x| d.target_type.as_deref() == Some(x.as_str())),
                        "PlatformTypes" => {
                            let p = platforms(&d.document_type, &parsed);
                            values.iter().any(|x| p.contains(x))
                        }
                        tag => {
                            let key = tag.trim_start_matches("tag:");
                            d.tags.get(key).is_some_and(|t| values.is_empty() || values.contains(t))
                        }
                    }
                })
        });
        docs.sort_by(|a, b| a.name.cmp(&b.name));
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(docs, input.next_token.as_deref(), limit)?;
        let ids = items.iter().map(|d| identifier(d, d.default())).collect();
        Ok(types::ListDocumentsResult { document_identifiers: Some(ids), next_token: next })
    }

    pub(crate) fn list_document_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListDocumentVersionsRequest,
    ) -> Result<types::ListDocumentVersionsResult, ServiceError> {
        let found = self.readable(ctx, "ListDocumentVersions", &input.name)?;
        let d = found.doc;
        let versions: Vec<types::DocumentVersionInfo> = d
            .versions
            .iter()
            .rev()
            .map(|v| types::DocumentVersionInfo {
                name: Some(d.name.clone()),
                display_name: v.display_name.clone(),
                document_version: Some(v.version.to_string()),
                version_name: v.version_name.clone(),
                created_date: Some(v.created),
                is_default_version: v.version == d.default_version,
                document_format: Some(v.format.clone()),
                status: Some("Active".into()),
                status_information: None,
                review_status: None,
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(versions, input.next_token.as_deref(), limit)?;
        Ok(types::ListDocumentVersionsResult { document_versions: Some(items), next_token: next })
    }

    pub(crate) fn update_document(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDocumentRequest,
    ) -> Result<types::UpdateDocumentResult, ServiceError> {
        let mut d = self.own_document(ctx, "UpdateDocument", &input.name)?;
        match input.document_version.as_deref() {
            None | Some("$LATEST") => {}
            Some(v) if v == d.latest().version.to_string() => {}
            Some(_) => return Err(errors::invalid_document_version(
                "The document version is not valid or does not exist. Specify $LATEST or the latest version number.",
            )),
        }
        let format = input.document_format.unwrap_or_else(|| d.latest().format.clone());
        validate(&input.content, &format, &d.document_type)?;
        if d.versions.iter().any(|v| v.content == input.content) {
            return Err(errors::duplicate_document_content("The content of the association document matches another document. Change the content of the document and try again."));
        }
        if let Some(n) = &input.version_name {
            if d.by_name(n).is_some() {
                return Err(errors::duplicate_document_version_name(
                    "The version name has already been used in this document. Specify a different version name, and then try again.",
                ));
            }
        }
        if d.versions.len() >= MAX_VERSIONS {
            return Err(errors::document_version_limit_exceeded(
                "The document has too many versions. Delete one or more document versions and try again.",
            ));
        }
        let version = d.latest().version + 1;
        let display_name = input.display_name.or_else(|| d.latest().display_name.clone());
        d.versions.push(DocVersion {
            version,
            version_name: input.version_name,
            display_name,
            content: input.content,
            format,
            created: now(ctx),
            requires: d.latest().requires.clone(),
        });
        if input.target_type.is_some() {
            d.target_type = input.target_type;
        }
        let mut desc = describe(ctx, &d, d.latest());
        desc.status = Some("Updating".into());
        self.save_document(ctx, d);
        Ok(types::UpdateDocumentResult { document_description: Some(desc) })
    }

    pub(crate) fn update_document_default_version(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDocumentDefaultVersionRequest,
    ) -> Result<types::UpdateDocumentDefaultVersionResult, ServiceError> {
        let mut d = self.own_document(ctx, "UpdateDocumentDefaultVersion", &input.name)?;
        let v = input.document_version.parse::<i64>().ok().and_then(|n| d.version(n)).ok_or_else(version_not_found)?;
        let (number, name) = (v.version, v.version_name.clone());
        d.default_version = number;
        let out = types::DocumentDefaultVersionDescription {
            name: Some(d.name.clone()),
            default_version: Some(number.to_string()),
            default_version_name: name,
        };
        self.save_document(ctx, d);
        Ok(types::UpdateDocumentDefaultVersionResult { description: Some(out) })
    }

    pub(crate) fn delete_document(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDocumentRequest,
    ) -> Result<types::DeleteDocumentResult, ServiceError> {
        let mut d = self.own_document(ctx, "DeleteDocument", &input.name)?;
        if input.document_version.is_some() || input.version_name.is_some() {
            let v = pick_version(&d, input.document_version.as_deref(), input.version_name.as_deref())?.version;
            if v == d.default_version {
                return Err(errors::invalid_document_operation(
                    "You can't delete the default version of a document. Change the default version and try again.",
                ));
            }
            d.versions.retain(|x| x.version != v);
            self.save_document(ctx, d);
        } else {
            let mut st = self.lock();
            st.region(&ctx.caller.account_id, &ctx.region).documents.remove(&d.name);
        }
        Ok(types::DeleteDocumentResult::default())
    }

    pub(crate) fn describe_document_permission(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDocumentPermissionRequest,
    ) -> Result<types::DescribeDocumentPermissionResponse, ServiceError> {
        if input.permission_type != "Share" {
            return Err(errors::invalid_permission_type(
                "The permission type isn't supported. Share is the only supported permission type.",
            ));
        }
        let d = self.own_document(ctx, "DescribeDocumentPermission", &input.name)?;
        let shares: Vec<(String, String)> = d.shared_with.into_iter().collect();
        let limit = input.max_results.unwrap_or(200).clamp(1, 200) as usize;
        let (items, next) = page(shares, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeDocumentPermissionResponse {
            account_ids: Some(items.iter().map(|(a, _)| a.clone()).collect()),
            account_sharing_info_list: Some(
                items
                    .into_iter()
                    .map(|(a, v)| types::AccountSharingInfo { account_id: Some(a), shared_document_version: Some(v) })
                    .collect(),
            ),
            next_token: next,
        })
    }

    pub(crate) fn modify_document_permission(
        &self,
        ctx: &RequestContext,
        input: types::ModifyDocumentPermissionRequest,
    ) -> Result<types::ModifyDocumentPermissionResponse, ServiceError> {
        if input.permission_type != "Share" {
            return Err(errors::invalid_permission_type(
                "The permission type isn't supported. Share is the only supported permission type.",
            ));
        }
        let mut d = self.own_document(ctx, "ModifyDocumentPermission", &input.name)?;
        let add = input.account_ids_to_add.unwrap_or_default();
        let remove = input.account_ids_to_remove.unwrap_or_default();
        let shared_version = match input.shared_document_version.as_deref() {
            None | Some("$DEFAULT") => "$DEFAULT".to_string(),
            Some("$LATEST") => "$LATEST".to_string(),
            Some(v) => {
                v.parse::<i64>().ok().and_then(|n| d.version(n)).ok_or_else(version_not_found)?;
                v.to_string()
            }
        };
        for a in &add {
            if a != "All" && !(a.len() == 12 && a.bytes().all(|b| b.is_ascii_digit())) {
                return Err(errors::invalid_parameters(format!("{a} is not a valid account ID.")));
            }
            if a == &ctx.caller.account_id {
                return Err(errors::invalid_parameters("You can't share a document with your own account."));
            }
        }
        if add.iter().any(|a| a == "All") && add.len() > 1 {
            return Err(errors::invalid_parameters("Specify All or a list of account IDs, not both."));
        }
        for a in &remove {
            d.shared_with.remove(a);
        }
        for a in add {
            d.shared_with.insert(a, shared_version.clone());
        }
        if d.shared_with.len() > MAX_SHARES {
            return Err(errors::document_permission_limit(
                "The document can't be shared with more accounts. You can share a document with a maximum of 1000 accounts.",
            ));
        }
        self.save_document(ctx, d);
        Ok(types::ModifyDocumentPermissionResponse::default())
    }
}

/// `content` in `to` (JSON or YAML) from `from`.
fn convert(content: &str, from: &str, to: &str) -> Result<String, ServiceError> {
    if from == to || from == "TEXT" || to == "TEXT" {
        return Ok(content.to_string());
    }
    let v = parse_content(content, from)?;
    Ok(match to {
        "YAML" => serde_yaml::to_string(&v).unwrap_or_default(),
        _ => serde_json::to_string_pretty(&v).unwrap_or_default(),
    })
}

fn tag_list(tags: &BTreeMap<String, String>) -> Vec<types::Tag> {
    tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()
}

fn describe(ctx: &RequestContext, d: &Document, v: &DocVersion) -> types::DocumentDescription {
    let parsed = parse_content(&v.content, &v.format).unwrap_or(Value::Null);
    let schema = match parsed.get("schemaVersion") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };
    let _ = ctx;
    types::DocumentDescription {
        hash: Some(sha256(&v.content)),
        hash_type: Some("Sha256".into()),
        name: Some(d.name.clone()),
        display_name: v.display_name.clone(),
        version_name: v.version_name.clone(),
        owner: Some(d.owner.clone()),
        created_date: Some(v.created),
        status: Some("Active".into()),
        document_version: Some(v.version.to_string()),
        description: parsed.get("description").and_then(Value::as_str).map(str::to_string),
        parameters: Some(parameters(&parsed)),
        platform_types: Some(platforms(&d.document_type, &parsed)),
        document_type: Some(d.document_type.clone()),
        schema_version: schema,
        latest_version: Some(d.latest().version.to_string()),
        default_version: Some(d.default_version.to_string()),
        document_format: Some(v.format.clone()),
        target_type: d.target_type.clone(),
        tags: Some(tag_list(&d.tags)),
        requires: v.requires.clone(),
        ..Default::default()
    }
}

fn identifier(d: &Document, v: &DocVersion) -> types::DocumentIdentifier {
    let parsed = parse_content(&v.content, &v.format).unwrap_or(Value::Null);
    let schema = match parsed.get("schemaVersion") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };
    types::DocumentIdentifier {
        name: Some(d.name.clone()),
        created_date: Some(v.created),
        display_name: v.display_name.clone(),
        owner: Some(d.owner.clone()),
        version_name: v.version_name.clone(),
        platform_types: Some(platforms(&d.document_type, &parsed)),
        document_version: Some(v.version.to_string()),
        document_type: Some(d.document_type.clone()),
        schema_version: schema,
        document_format: Some(v.format.clone()),
        target_type: d.target_type.clone(),
        tags: Some(tag_list(&d.tags)),
        requires: v.requires.clone(),
        review_status: None,
        author: None,
    }
}

#[cfg(test)]
pub const RUN_SHELL_SCRIPT_FOR_TESTS: &str = RUN_SHELL_SCRIPT;

const RUN_SHELL_SCRIPT: &str = r#"{
  "schemaVersion": "1.2",
  "description": "Run a shell script or specify the commands to run.",
  "parameters": {
    "commands": {
      "type": "StringList",
      "description": "(Required) Specify a shell script or a command to run.",
      "minItems": 1,
      "displayType": "textarea"
    },
    "workingDirectory": {
      "type": "String",
      "default": "",
      "description": "(Optional) The path to the working directory on your instance.",
      "maxChars": 4096
    },
    "executionTimeout": {
      "type": "String",
      "default": "3600",
      "description": "(Optional) The time in seconds for a command to complete before it is considered to have failed. Default is 3600 (1 hour). Maximum is 172800 (48 hours).",
      "allowedPattern": "([1-9][0-9]{0,4})|(1[0-6][0-9]{4})|(17[0-1][0-9]{3})|(172[0-7][0-9]{2})|(172800)"
    }
  },
  "runtimeConfig": {
    "aws:runShellScript": {
      "properties": [
        {
          "id": "0.aws:runShellScript",
          "runCommand": "{{ commands }}",
          "workingDirectory": "{{ workingDirectory }}",
          "timeoutSeconds": "{{ executionTimeout }}"
        }
      ]
    }
  }
}"#;

const RUN_POWERSHELL_SCRIPT: &str = r#"{
  "schemaVersion": "1.2",
  "description": "Run a PowerShell script or specify the paths to scripts to run.",
  "parameters": {
    "commands": {
      "type": "StringList",
      "description": "(Required) Specify the commands to run or the paths to existing scripts on the instance.",
      "minItems": 1,
      "displayType": "textarea"
    },
    "workingDirectory": {
      "type": "String",
      "default": "",
      "description": "(Optional) The path to the working directory on your instance.",
      "maxChars": 4096
    },
    "executionTimeout": {
      "type": "String",
      "default": "3600",
      "description": "(Optional) The time in seconds for a command to be completed before it is considered to have failed. Default is 3600 (1 hour). Maximum is 172800 (48 hours).",
      "allowedPattern": "([1-9][0-9]{0,4})|(1[0-6][0-9]{4})|(17[0-1][0-9]{3})|(172[0-7][0-9]{2})|(172800)"
    }
  },
  "runtimeConfig": {
    "aws:runPowerShellScript": {
      "properties": [
        {
          "id": "0.aws:runPowerShellScript",
          "runCommand": "{{ commands }}",
          "workingDirectory": "{{ workingDirectory }}",
          "timeoutSeconds": "{{ executionTimeout }}"
        }
      ]
    }
  }
}"#;

const GATHER_SOFTWARE_INVENTORY: &str = r#"{
  "schemaVersion": "2.0",
  "description": "Software Inventory Policy Document.",
  "parameters": {
    "applications": {"type": "String", "default": "Enabled", "description": "(Optional) Collect data for installed applications.", "allowedValues": ["Enabled", "Disabled"]},
    "awsComponents": {"type": "String", "default": "Enabled", "description": "(Optional) Collect data for AWS Components like amazon-ssm-agent.", "allowedValues": ["Enabled", "Disabled"]},
    "files": {"type": "String", "default": "", "description": "(Optional, requires SSMAgent version 2.2.64.0 and above) Linux example: [{\"Path\":\"/usr/bin\", \"Pattern\":[\"aws*\", \"*ssm*\"],\"Recursive\":false}]"},
    "networkConfig": {"type": "String", "default": "Enabled", "description": "(Optional) Collect data for Network configurations.", "allowedValues": ["Enabled", "Disabled"]},
    "billingInfo": {"type": "String", "default": "Enabled", "description": "(Optional) Collect billing info for license included applications.", "allowedValues": ["Enabled", "Disabled"]},
    "windowsUpdates": {"type": "String", "default": "Enabled", "description": "(Optional) Collect data for all Windows Updates.", "allowedValues": ["Enabled", "Disabled"]},
    "instanceDetailedInformation": {"type": "String", "default": "Enabled", "description": "(Optional) Collect additional information about the instance, including the CPU model, speed, and the number of cores, to name a few.", "allowedValues": ["Enabled", "Disabled"]},
    "services": {"type": "String", "default": "Enabled", "description": "(Optional, Windows OS only, requires SSMAgent version 2.2.64.0 and above) Collect data for service configurations.", "allowedValues": ["Enabled", "Disabled"]},
    "windowsRegistry": {"type": "String", "default": "", "description": "(Optional, Windows OS only, requires SSMAgent version 2.2.64.0 and above) Windows example: [{\"Path\":\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Amazon\", \"Recursive\":true}]"},
    "windowsRoles": {"type": "String", "default": "Enabled", "description": "(Optional, Windows OS only, requires SSMAgent version 2.2.64.0 and above) Collect data for Microsoft Windows role configurations.", "allowedValues": ["Enabled", "Disabled"]},
    "customInventory": {"type": "String", "default": "Enabled", "description": "(Optional) Collect data for custom inventory.", "allowedValues": ["Enabled", "Disabled"]}
  },
  "mainSteps": [
    {
      "action": "aws:softwareInventory",
      "name": "collectSoftwareInventoryItems",
      "inputs": {
        "applications": "{{ applications }}",
        "awsComponents": "{{ awsComponents }}",
        "networkConfig": "{{ networkConfig }}",
        "files": "{{ files }}",
        "services": "{{ services }}",
        "windowsRoles": "{{ windowsRoles }}",
        "windowsRegistry": "{{ windowsRegistry }}",
        "windowsUpdates": "{{ windowsUpdates }}",
        "instanceDetailedInformation": "{{ instanceDetailedInformation }}",
        "billingInfo": "{{ billingInfo }}",
        "customInventory": "{{ customInventory }}"
      }
    }
  ]
}"#;

const RUN_PATCH_BASELINE: &str = r#"{
  "schemaVersion": "2.2",
  "description": "Scans for or installs patches from a patch baseline to a Linux or Windows operating system.",
  "parameters": {
    "Operation": {
      "type": "String",
      "description": "(Required) The update or configuration to perform on the instance. The system checks if patches specified in the patch baseline are installed on the instance. The install operation installs patches missing from the baseline.",
      "allowedValues": ["Scan", "Install"]
    },
    "SnapshotId": {
      "type": "String",
      "description": "(Optional) The snapshot ID to use to retrieve a patch baseline snapshot.",
      "allowedPattern": "(^$)|^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
      "default": ""
    },
    "RebootOption": {
      "type": "String",
      "description": "(Optional) Reboot behavior after a patch Install operation.",
      "allowedValues": ["RebootIfNeeded", "NoReboot"],
      "default": "RebootIfNeeded"
    }
  },
  "mainSteps": [
    {
      "precondition": {"StringEquals": ["platformType", "Linux"]},
      "action": "aws:runPatchBaseline",
      "name": "PatchLinux",
      "inputs": {"Operation": "{{ Operation }}", "SnapshotId": "{{ SnapshotId }}", "RebootOption": "{{ RebootOption }}"}
    }
  ]
}"#;

const STOP_EC2_INSTANCE: &str = r#"{
  "schemaVersion": "0.3",
  "description": "Stop EC2 instances",
  "assumeRole": "{{ AutomationAssumeRole }}",
  "parameters": {
    "InstanceId": { "type": "StringList", "description": "(Required) EC2 Instance(s) to stop" },
    "AutomationAssumeRole": { "type": "String", "description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.", "default": "" }
  },
  "mainSteps": [
    { "name": "stopInstances", "action": "aws:changeInstanceState", "inputs": { "InstanceIds": "{{ InstanceId }}", "DesiredState": "stopped" } }
  ]
}"#;

const START_EC2_INSTANCE: &str = r#"{
  "schemaVersion": "0.3",
  "description": "Start EC2 instances",
  "assumeRole": "{{ AutomationAssumeRole }}",
  "parameters": {
    "InstanceId": { "type": "StringList", "description": "(Required) EC2 Instance(s) to start" },
    "AutomationAssumeRole": { "type": "String", "description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.", "default": "" }
  },
  "mainSteps": [
    { "name": "startInstances", "action": "aws:changeInstanceState", "inputs": { "InstanceIds": "{{ InstanceId }}", "DesiredState": "running" } }
  ]
}"#;

const RESTART_EC2_INSTANCE: &str = r#"{
  "schemaVersion": "0.3",
  "description": "Restart EC2 instances",
  "assumeRole": "{{ AutomationAssumeRole }}",
  "parameters": {
    "InstanceId": { "type": "StringList", "description": "(Required) EC2 Instance(s) to restart" },
    "AutomationAssumeRole": { "type": "String", "description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.", "default": "" }
  },
  "mainSteps": [
    { "name": "stopInstances", "action": "aws:changeInstanceState", "inputs": { "InstanceIds": "{{ InstanceId }}", "DesiredState": "stopped" } },
    { "name": "startInstances", "action": "aws:changeInstanceState", "inputs": { "InstanceIds": "{{ InstanceId }}", "DesiredState": "running" } }
  ]
}"#;

const CREATE_IMAGE: &str = r#"{
  "schemaVersion": "0.3",
  "description": "Creates a new Amazon Machine Image (AMI) from an Amazon EC2 instance",
  "assumeRole": "{{ AutomationAssumeRole }}",
  "parameters": {
    "InstanceId": { "type": "String", "description": "(Required) The ID of the Amazon EC2 instance." },
    "NoReboot": { "type": "Boolean", "description": "(Optional) Do not reboot the instance before creating the image.", "default": false },
    "AutomationAssumeRole": { "type": "String", "description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.", "default": "" }
  },
  "mainSteps": [
    {
      "name": "createImage",
      "action": "aws:createImage",
      "onFailure": "Abort",
      "inputs": {
        "InstanceId": "{{ InstanceId }}",
        "ImageName": "{{ InstanceId }}_{{automation:EXECUTION_ID}}",
        "NoReboot": "{{ NoReboot }}"
      }
    }
  ],
  "outputs": ["createImage.ImageId"]
}"#;

const UPDATE_SSM_AGENT: &str = r#"{
  "schemaVersion": "1.2",
  "description": "Updates the Amazon SSM Agent to the specified version or the latest version.",
  "parameters": {
    "version": {"type": "String", "default": "", "description": "(Optional) A specific version of the Amazon SSM Agent to install.", "allowedPattern": "(^(?:(\\d+)\\.)(?:(\\d+)\\.)(?:(\\d+)\\.)(\\d+)$|^$)"},
    "allowDowngrade": {"type": "String", "default": "false", "description": "(Optional) Allow the Amazon SSM Agent service to be downgraded to an earlier version.", "allowedValues": ["true", "false"]}
  },
  "runtimeConfig": {
    "aws:updateSsmAgent": {
      "properties": [
        {"agentName": "amazon-ssm-agent", "source": "https://s3.{Region}.amazonaws.com/amazon-ssm-{Region}/ssm-agent-manifest.json", "allowDowngrade": "{{ allowDowngrade }}", "targetVersion": "{{ version }}"}
      ]
    }
  }
}"#;

const CONFIGURE_PACKAGE: &str = r#"{
  "schemaVersion": "2.2",
  "description": "Install or uninstall a Distributor package.",
  "parameters": {
    "action": {"description": "(Required) Specify whether or not to install or uninstall the package.", "type": "String", "allowedValues": ["Install", "Uninstall"]},
    "name": {"description": "(Required) The package to install/uninstall.", "type": "String"},
    "version": {"type": "String", "description": "(Optional) The version of the package to install or uninstall.", "default": ""}
  },
  "mainSteps": [
    {"action": "aws:configurePackage", "name": "configurePackage", "inputs": {"name": "{{ name }}", "action": "{{ action }}", "version": "{{ version }}"}}
  ]
}"#;

const PORT_FORWARDING: &str = r#"{
  "schemaVersion": "1.0",
  "description": "Document to start port forwarding session over Session Manager",
  "sessionType": "Port",
  "parameters": {
    "portNumber": {"type": "String", "description": "(Optional) Port number of the server on the instance", "allowedPattern": "^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", "default": "80"},
    "localPortNumber": {"type": "String", "description": "(Optional) Port number on local machine to forward traffic to. An open port is chosen at run-time if not provided", "allowedPattern": "^([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", "default": "0"}
  },
  "properties": {"portNumber": "{{ portNumber }}", "type": "LocalPortForwarding", "localPortNumber": "{{ localPortNumber }}"}
}"#;

const PORT_FORWARDING_REMOTE: &str = r#"{
  "schemaVersion": "1.0",
  "description": "Document to start port forwarding session over Session Manager to a remote host",
  "sessionType": "Port",
  "parameters": {
    "portNumber": {"type": "String", "description": "(Optional) Port number of the server on the remote host", "allowedPattern": "^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", "default": "80"},
    "localPortNumber": {"type": "String", "description": "(Optional) Port number on local machine to forward traffic to. An open port is chosen at run-time if not provided", "allowedPattern": "^([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", "default": "0"},
    "host": {"type": "String", "description": "(Required) The IP address or DNS name of the remote host"}
  },
  "properties": {"portNumber": "{{ portNumber }}", "type": "LocalPortForwarding", "localPortNumber": "{{ localPortNumber }}", "host": "{{ host }}"}
}"#;

const SSH_SESSION: &str = r#"{
  "schemaVersion": "1.0",
  "description": "Document to start SSH session",
  "sessionType": "Port",
  "parameters": {
    "portNumber": {"type": "String", "description": "(Optional) Port number of SSH server on the instance", "allowedPattern": "^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", "default": "22"}
  },
  "properties": {"portNumber": "{{ portNumber }}"}
}"#;

const RUN_SHELL: &str = r#"{
  "schemaVersion": "1.0",
  "description": "Document to hold regional settings for Session Manager",
  "sessionType": "Standard_Stream",
  "inputs": {
    "s3BucketName": "",
    "s3KeyPrefix": "",
    "s3EncryptionEnabled": true,
    "cloudWatchLogGroupName": "",
    "cloudWatchEncryptionEnabled": true,
    "cloudWatchStreamingEnabled": true,
    "idleSessionTimeout": "20",
    "maxSessionDuration": "",
    "kmsKeyId": "",
    "runAsEnabled": false,
    "runAsDefaultUser": "",
    "shellProfile": {"windows": "", "linux": ""}
  }
}"#;

const INTERACTIVE_COMMAND: &str = r#"{
  "schemaVersion": "1.0",
  "description": "Document to run single interactive command on an instance",
  "sessionType": "InteractiveCommands",
  "parameters": {
    "command": {"type": "String", "description": "The command to run on the instance"}
  },
  "properties": {
    "linux": {"commands": "{{command}}", "runAsElevated": false},
    "windows": {"commands": "{{command}}", "runAsElevated": false}
  }
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_documents_are_valid() {
        for d in catalogue().values() {
            let v = d.latest();
            validate(&v.content, &v.format, &d.document_type).unwrap_or_else(|e| panic!("{}: {e:?}", d.name));
        }
        let shell = &catalogue()["AWS-RunShellScript"];
        let parsed = parse_content(&shell.latest().content, "JSON").unwrap();
        assert_eq!(platforms("Command", &parsed), ["Linux", "MacOS"]);
        assert_eq!(plugins(&parsed), ["aws:runShellScript"]);
    }

    #[test]
    fn content_checks() {
        assert!(validate("{", "JSON", "Command").is_err());
        assert!(validate(r#"{"schemaVersion":"0.3","mainSteps":[]}"#, "JSON", "Command").is_err());
        let yaml = "schemaVersion: '2.2'\nmainSteps:\n- action: aws:runShellScript\n  name: run\n  inputs:\n    runCommand: [echo hi]\n";
        assert_eq!(validate(yaml, "YAML", "Command").unwrap(), "2.2");
        assert!(validate(
            r#"{"schemaVersion":"2.2","mainSteps":[{"action":"a","name":"x"},{"action":"b","name":"x"}]}"#,
            "JSON",
            "Command"
        )
        .is_err());
    }
}
