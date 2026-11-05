//! CodeArtifact's state: domains, holding repositories and package
//! groups; repositories holding packages, their versions and assets.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use mws_core::Caller;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by [`domain_key`].
    pub domains: BTreeMap<String, Domain>,
    /// Authorization tokens handed out by `GetAuthorizationToken`.
    pub tokens: BTreeMap<String, Token>,
}

/// `region/owner/name`.
pub fn domain_key(region: &str, owner: &str, name: &str) -> String {
    format!("{region}/{owner}/{name}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Domain {
    pub name: String,
    pub owner: String,
    pub region: String,
    pub partition: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub encryption_key: String,
    pub s3_bucket_arn: String,
    pub policy: Option<ResourcePolicy>,
    pub tags: BTreeMap<String, String>,
    pub repositories: BTreeMap<String, Repository>,
    /// Keyed by pattern.
    pub groups: BTreeMap<String, PackageGroup>,
}

impl Default for Domain {
    fn default() -> Self {
        Self {
            name: String::new(),
            owner: String::new(),
            region: String::new(),
            partition: "aws".into(),
            arn: String::new(),
            created: DateTime::<Utc>::UNIX_EPOCH,
            encryption_key: String::new(),
            s3_bucket_arn: String::new(),
            policy: None,
            tags: BTreeMap::new(),
            repositories: BTreeMap::new(),
            groups: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourcePolicy {
    pub document: String,
    pub revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Repository {
    pub name: String,
    pub arn: String,
    pub description: Option<String>,
    pub administrator_account: String,
    pub created: DateTime<Utc>,
    /// Upstream repository names, in priority order.
    pub upstreams: Vec<String>,
    /// External connection names (`public:npmjs`, ...).
    pub external_connections: Vec<String>,
    pub policy: Option<ResourcePolicy>,
    pub tags: BTreeMap<String, String>,
    /// Keyed by [`package_key`].
    pub packages: BTreeMap<String, Package>,
}

impl Default for Repository {
    fn default() -> Self {
        Self {
            name: String::new(),
            arn: String::new(),
            description: None,
            administrator_account: String::new(),
            created: DateTime::<Utc>::UNIX_EPOCH,
            upstreams: Vec::new(),
            external_connections: Vec::new(),
            policy: None,
            tags: BTreeMap::new(),
            packages: BTreeMap::new(),
        }
    }
}

/// `format/namespace/name` (namespace empty when there is none).
pub fn package_key(format: &str, namespace: Option<&str>, name: &str) -> String {
    format!("{format}/{}/{name}", namespace.unwrap_or(""))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Package {
    pub format: String,
    pub namespace: Option<String>,
    pub name: String,
    /// Package origin controls: `ALLOW` or `BLOCK`.
    pub publish: String,
    pub upstream: String,
    pub versions: BTreeMap<String, Version>,
    /// npm dist-tags.
    pub dist_tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Version {
    pub version: String,
    pub revision: String,
    /// `Published`, `Unfinished`, `Unlisted`, `Archived` or `Disposed`.
    pub status: String,
    pub published: DateTime<Utc>,
    /// `INTERNAL`, `EXTERNAL` or `UNKNOWN`.
    pub origin_type: String,
    /// Where the version entered the domain: a repository...
    pub entry_repository: Option<String>,
    /// ...or an external connection.
    pub entry_external_connection: Option<String>,
    pub assets: Vec<Asset>,
    pub meta: VersionMeta,
}

impl Default for Version {
    fn default() -> Self {
        Self {
            version: String::new(),
            revision: String::new(),
            status: "Published".into(),
            published: DateTime::<Utc>::UNIX_EPOCH,
            origin_type: "INTERNAL".into(),
            entry_repository: None,
            entry_external_connection: None,
            assets: Vec::new(),
            meta: VersionMeta::default(),
        }
    }
}

impl Version {
    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }

    /// Put an asset, replacing one of the same name.
    pub fn put_asset(&mut self, asset: Asset) {
        match self.assets.iter_mut().find(|a| a.name == asset.name) {
            Some(existing) => *existing = asset,
            None => self.assets.push(asset),
        }
        self.revision = revision(&self.assets);
    }
}

/// A revision identifies a version's contents: copies of a version keep it.
pub fn revision(assets: &[Asset]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for a in assets {
        h.update(a.name.as_bytes());
        h.update([0]);
        h.update(a.sha256().as_bytes());
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&h.finalize()[..15])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VersionMeta {
    pub display_name: Option<String>,
    pub summary: Option<String>,
    pub home_page: Option<String>,
    pub source_code_repository: Option<String>,
    pub licenses: Vec<License>,
    pub readme: Option<String>,
    pub dependencies: Vec<Dependency>,
    /// The npm version manifest (`package.json` as published), served in
    /// the packument.
    pub npm_manifest: Option<serde_json::Value>,
    /// PyPI `Requires-Python`.
    pub requires_python: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct License {
    pub name: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Dependency {
    pub namespace: Option<String>,
    pub package: String,
    pub dependency_type: String,
    pub version_requirement: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Asset {
    pub name: String,
    #[serde(with = "b64")]
    pub content: Vec<u8>,
}

impl Asset {
    pub fn new(name: impl Into<String>, content: Vec<u8>) -> Self {
        Self { name: name.into(), content }
    }

    pub fn sha256(&self) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&self.content))
    }

    pub fn hashes(&self) -> BTreeMap<String, String> {
        use sha2::Digest;
        let mut m = BTreeMap::new();
        m.insert("MD5".into(), hex::encode(md5::Md5::digest(&self.content)));
        m.insert("SHA-1".into(), hex::encode(sha1::Sha1::digest(&self.content)));
        m.insert("SHA-256".into(), self.sha256());
        m.insert("SHA-512".into(), hex::encode(sha2::Sha512::digest(&self.content)));
        m
    }
}

mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PackageGroup {
    pub pattern: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub contact_info: Option<String>,
    pub description: Option<String>,
    /// Restriction type (`PUBLISH`, `EXTERNAL_UPSTREAM`,
    /// `INTERNAL_UPSTREAM`) to mode (`ALLOW`, `BLOCK`,
    /// `ALLOW_SPECIFIC_REPOSITORIES`, `INHERIT`).
    pub restrictions: BTreeMap<String, String>,
    /// Restriction type to the repositories allowed by
    /// `ALLOW_SPECIFIC_REPOSITORIES`.
    pub allowed_repositories: BTreeMap<String, BTreeSet<String>>,
    pub tags: BTreeMap<String, String>,
}

impl Default for PackageGroup {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            arn: String::new(),
            created: DateTime::<Utc>::UNIX_EPOCH,
            contact_info: None,
            description: None,
            restrictions: BTreeMap::new(),
            allowed_repositories: BTreeMap::new(),
            tags: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub domain: String,
    pub caller: Caller,
    pub expires: DateTime<Utc>,
}
