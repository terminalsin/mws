//! Lambda state: functions with their versions, aliases, permissions and
//! settings, layers, event source mappings and code signing configs.
//! Deployment packages live in a content-addressed store so versions that
//! share code share bytes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By unqualified function ARN.
    pub functions: BTreeMap<String, Function>,
    /// By layer ARN (without version).
    pub layers: BTreeMap<String, Layer>,
    /// By UUID.
    pub event_source_mappings: BTreeMap<String, EventSourceMapping>,
    /// By ARN.
    pub code_signing_configs: BTreeMap<String, CodeSigningConfig>,
    /// Deployment packages by hex SHA-256.
    pub code: BTreeMap<String, CodeBlob>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Function {
    pub account_id: String,
    pub region: String,
    pub name: String,
    pub arn: String,
    /// `$LATEST`.
    pub latest: Version,
    /// Published versions by number.
    pub versions: BTreeMap<u64, Version>,
    pub last_version: u64,
    pub aliases: BTreeMap<String, types::AliasConfiguration>,
    /// Resource-based policy statements by qualifier (`""` for the
    /// unqualified function).
    pub policies: BTreeMap<String, Vec<serde_json::Value>>,
    pub policy_revisions: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub reserved_concurrency: Option<i32>,
    /// By qualifier (`$LATEST` when none was given).
    pub event_invoke_configs: BTreeMap<String, types::FunctionEventInvokeConfig>,
    /// By qualifier (`""` for the unqualified function).
    pub url_configs: BTreeMap<String, types::FunctionUrlConfig>,
    /// By qualifier.
    pub provisioned: BTreeMap<String, Provisioned>,
    pub recursive_loop: Option<String>,
    /// By qualifier (`$LATEST` when none was given).
    pub runtime_management: BTreeMap<String, RuntimeManagement>,
    pub code_signing_config_arn: Option<String>,
}

/// One version of a function (`$LATEST` or a published number).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Version {
    pub config: types::FunctionConfiguration,
    /// SHA-256 (hex) of the zip in [`State::code`], for zip packages.
    pub code_hex: Option<String>,
    pub image_uri: Option<String>,
    /// The image `image_uri` resolved to (`<registry>/<repository>@<digest>`).
    pub resolved_image_uri: Option<String>,
    /// The resolved image's own entry point, command and working directory.
    pub image_run_config: Option<ImageRunConfig>,
    /// Where the zip came from, if S3.
    pub s3_source: Option<(String, String, Option<String>)>,
}

/// How an image starts, from its config.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageRunConfig {
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Provisioned {
    pub requested: i32,
    pub last_modified: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeManagement {
    pub update_runtime_on: String,
    pub runtime_version_arn: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Layer {
    pub account_id: String,
    pub name: String,
    pub arn: String,
    pub versions: BTreeMap<i64, LayerVersion>,
    pub last_version: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LayerVersion {
    pub version: i64,
    pub description: Option<String>,
    pub created_date: String,
    pub compatible_runtimes: Option<Vec<String>>,
    pub compatible_architectures: Option<Vec<String>>,
    pub license_info: Option<String>,
    pub code_hex: String,
    pub code_sha256: String,
    pub code_size: i64,
    pub policy: Vec<serde_json::Value>,
    pub policy_revision: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventSourceMapping {
    pub account_id: String,
    pub region: String,
    pub config: types::EventSourceMappingConfiguration,
    pub tags: BTreeMap<String, String>,
    /// Stream sources: progress per shard.
    pub shards: BTreeMap<String, crate::esm_stream::ShardProgress>,
    /// When the mapping was created (where `LATEST` starts).
    pub created: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeSigningConfig {
    pub account_id: String,
    pub config: types::CodeSigningConfig,
    pub tags: BTreeMap<String, String>,
}

/// Bytes stored base64-encoded in state documents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeBlob(pub Vec<u8>);

impl Serialize for CodeBlob {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for CodeBlob {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map(CodeBlob).map_err(serde::de::Error::custom)
    }
}

impl Function {
    /// The version a qualifier names: `$LATEST`, a number, or an alias
    /// (resolved to its version). `None` means unqualified (`$LATEST`).
    pub fn version_for(&self, qualifier: Option<&str>) -> Option<&Version> {
        match qualifier {
            None | Some("$LATEST") => Some(&self.latest),
            Some(q) if q.bytes().all(|b| b.is_ascii_digit()) => self.versions.get(&q.parse::<u64>().ok()?),
            Some(alias) => {
                let a = self.aliases.get(alias)?;
                self.version_for(a.function_version.as_deref())
            }
        }
    }

    /// Whether a qualifier names something that exists.
    pub fn has_qualifier(&self, qualifier: &str) -> bool {
        self.version_for(Some(qualifier)).is_some()
    }
}
