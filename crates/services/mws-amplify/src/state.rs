//! Amplify's state: apps with their branches, jobs, deployed sites,
//! domains, backend environments and webhooks.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By app id. App ids are unique across accounts and Regions; each app
    /// records which it belongs to.
    pub apps: BTreeMap<String, AppRecord>,
    /// By webhook id.
    pub webhooks: BTreeMap<String, WebhookRecord>,
    /// Upload URLs handed out by `CreateDeployment`, by token.
    pub uploads: BTreeMap<String, Upload>,
    /// Build artifacts by artifact id.
    pub artifacts: BTreeMap<String, ArtifactRecord>,
    /// Links that download job logs and access logs, by token.
    pub downloads: BTreeMap<String, Download>,
    /// File contents by SHA-256, shared between deployments.
    pub blobs: BTreeMap<String, Blob>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppRecord {
    pub account: String,
    pub region: String,
    pub app: types::App,
    /// The repository token (`accessToken`/`oauthToken`). AWS never returns
    /// it; builds use it to clone.
    pub repository_token: Option<String>,
    pub branches: BTreeMap<String, BranchRecord>,
    pub domains: BTreeMap<String, DomainRecord>,
    pub backends: BTreeMap<String, types::BackendEnvironment>,
    /// Requests the app's sites served, oldest first (bounded).
    pub access_log: Vec<AccessEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BranchRecord {
    pub branch: types::Branch,
    pub jobs: BTreeMap<u64, JobRecord>,
    pub next_job: u64,
    /// What the branch serves: the files of its last successful deployment.
    pub site: Option<Site>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobRecord {
    pub summary: types::JobSummary,
    pub steps: Vec<types::Step>,
    /// Files uploaded for a manual deployment that has not started yet:
    /// the zip (key `""`) or individual files by path.
    pub uploaded: BTreeMap<String, String>,
    /// Paths `CreateDeployment` handed out upload URLs for, with the MD5
    /// its file map gave.
    pub expected_files: BTreeMap<String, String>,
    /// The job's log, served behind each step's `logUrl`.
    pub log: String,
    pub artifact_ids: Vec<String>,
}

/// A deployed site: file paths (without a leading `/`) to blob hashes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Site {
    pub job_id: String,
    pub files: BTreeMap<String, String>,
    /// Custom headers from the build's `customHttp.yml`, overriding the
    /// app's.
    pub custom_headers: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainRecord {
    pub domain: types::DomainAssociation,
    /// The CNAME that proves domain ownership for the managed certificate.
    pub verification_name: String,
    pub verification_value: String,
    /// The CloudFront-style target subdomains point at.
    pub distribution: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookRecord {
    pub account: String,
    pub region: String,
    pub webhook: types::Webhook,
    pub token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Upload {
    pub app_id: String,
    pub branch_name: String,
    pub job_id: u64,
    /// The file this URL uploads; `None` for the zip.
    pub file: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ArtifactRecord {
    pub account: String,
    pub region: String,
    pub app_id: String,
    pub branch_name: String,
    pub job_id: u64,
    pub file_name: String,
    pub blob: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Download {
    pub content_type: String,
    pub blob: String,
    /// Seconds since the epoch after which the link stops working.
    pub expires: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessEntry {
    pub time: chrono::DateTime<chrono::Utc>,
    pub client_ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub status: u16,
    pub bytes: usize,
    pub referer: String,
    pub user_agent: String,
    pub request_id: String,
    pub content_type: String,
}

/// File content, base64 in saved state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);

impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map(Blob).map_err(serde::de::Error::custom)
    }
}

impl State {
    /// Store `data` and return its hash.
    pub fn put_blob(&mut self, data: Vec<u8>) -> String {
        let hash = crate::names::sha256_hex(&data);
        self.blobs.entry(hash.clone()).or_insert(Blob(data));
        hash
    }

    /// Drop blobs nothing refers to any more.
    pub fn collect_garbage(&mut self) {
        let mut live = std::collections::BTreeSet::new();
        for app in self.apps.values() {
            for b in app.branches.values() {
                if let Some(site) = &b.site {
                    live.extend(site.files.values().cloned());
                }
                for j in b.jobs.values() {
                    live.extend(j.uploaded.values().cloned());
                }
            }
        }
        live.extend(self.artifacts.values().map(|a| a.blob.clone()));
        live.extend(self.downloads.values().map(|d| d.blob.clone()));
        self.blobs.retain(|k, _| live.contains(k));
    }
}
