//! Bedrock control-plane state, per account and Region.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by `account/region`.
    pub scopes: BTreeMap<String, Scope>,
}

/// Resource kinds kept as generic [`Record`]s.
pub mod kind {
    pub const PROFILE: &str = "application-inference-profile";
    pub const PROVISIONED: &str = "provisioned-model";
    pub const CUSTOMIZATION_JOB: &str = "model-customization-job";
    pub const CUSTOM_MODEL: &str = "custom-model";
    pub const DEPLOYMENT: &str = "custom-model-deployment";
    pub const IMPORT_JOB: &str = "model-import-job";
    pub const IMPORTED_MODEL: &str = "imported-model";
    pub const COPY_JOB: &str = "model-copy-job";
    pub const INVOCATION_JOB: &str = "model-invocation-job";
    pub const EVALUATION_JOB: &str = "evaluation-job";
    pub const PROMPT_ROUTER: &str = "prompt-router";
    pub const MARKETPLACE_ENDPOINT: &str = "marketplace-model-endpoint";
    pub const PROMPT_OPTIMIZATION_JOB: &str = "advanced-prompt-optimization-job";
    pub const REASONING_POLICY: &str = "automated-reasoning-policy";
    pub const ENFORCED_GUARDRAIL: &str = "enforced-guardrail";
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Scope {
    /// Generic resources: kind -> id -> record.
    pub records: BTreeMap<String, BTreeMap<String, Record>>,
    pub guardrails: BTreeMap<String, Guardrail>,
    /// Tags by resource ARN.
    pub tags: BTreeMap<String, BTreeMap<String, String>>,
    /// Resource policies by resource ARN.
    pub resource_policies: BTreeMap<String, String>,
    /// `LoggingConfig`, as a document of generated-type fields.
    pub logging: Option<Value>,
    pub data_retention: Option<(String, DateTime<Utc>)>,
    /// `PutUseCaseForModelAccess` form data (base64).
    pub use_case: Option<String>,
    /// Models with a Marketplace agreement.
    pub agreements: BTreeSet<String>,
}

impl Scope {
    pub fn kind(&self, kind: &str) -> impl Iterator<Item = &Record> {
        self.records.get(kind).into_iter().flat_map(|m| m.values())
    }

    pub fn get(&self, kind: &str, id: &str) -> Option<&Record> {
        self.records.get(kind)?.get(id)
    }

    pub fn get_mut(&mut self, kind: &str, id: &str) -> Option<&mut Record> {
        self.records.get_mut(kind)?.get_mut(id)
    }

    /// The record of `kind` whose id, ARN or name is `ident`.
    pub fn find(&self, kind: &str, ident: &str) -> Option<&Record> {
        self.kind(kind).find(|r| r.id == ident || r.arn == ident || r.name == ident)
    }

    pub fn find_id(&self, kind: &str, ident: &str) -> Option<String> {
        self.find(kind, ident).map(|r| r.id.clone())
    }

    pub fn insert(&mut self, kind: &str, record: Record) {
        self.records.entry(kind.to_string()).or_default().insert(record.id.clone(), record);
    }

    pub fn remove(&mut self, kind: &str, id: &str) -> Option<Record> {
        let r = self.records.get_mut(kind)?.remove(id)?;
        self.tags.remove(&r.arn);
        self.resource_policies.remove(&r.arn);
        Some(r)
    }

    /// Bring every timed transition up to `now`.
    pub fn settle(&mut self, now: DateTime<Utc>) {
        for records in self.records.values_mut() {
            for r in records.values_mut() {
                r.settle(now);
            }
        }
    }
}

/// A resource: identity, lifecycle and its fields as a document keyed by
/// generated-type field names (so `serde` turns it into any of the
/// resource's output shapes).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub status: String,
    /// A pending transition: the status the resource reaches, and when.
    pub transition: Option<(String, DateTime<Utc>)>,
    /// Further timed steps, applied in order once due: each sets the
    /// status and merges its fields into `doc`.
    pub steps: Vec<Step>,
    pub doc: Map<String, Value>,
}

/// A timed step of a job's lifecycle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Step {
    pub at: DateTime<Utc>,
    pub status: String,
    /// Fields merged into the record's document (nested objects merge).
    pub doc: Map<String, Value>,
}

fn merge(into: &mut Map<String, Value>, from: &Map<String, Value>) {
    for (k, v) in from {
        match (into.get_mut(k), v) {
            (Some(Value::Object(a)), Value::Object(b)) => merge(a, b),
            _ => {
                into.insert(k.clone(), v.clone());
            }
        }
    }
}

impl Record {
    pub fn settle(&mut self, now: DateTime<Utc>) {
        if let Some((status, at)) = &self.transition {
            if *at <= now {
                self.status = status.clone();
                self.updated = *at;
                self.transition = None;
            }
        }
        while self.steps.first().is_some_and(|s| s.at <= now) {
            let step = self.steps.remove(0);
            self.status = step.status;
            self.updated = step.at;
            merge(&mut self.doc, &step.doc);
        }
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        self.doc.get(key).and_then(Value::as_str)
    }
}

/// A guardrail: its working draft and published numbered versions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Guardrail {
    pub id: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub draft: GuardrailVersion,
    pub versions: BTreeMap<u32, GuardrailVersion>,
    pub next_version: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardrailVersion {
    pub updated: DateTime<Utc>,
    /// `GetGuardrailResponse` fields for this version.
    pub doc: Map<String, Value>,
}
