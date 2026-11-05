//! External connections: public registries a repository ingests packages
//! from on demand. npm, PyPI and Maven connections really fetch from their
//! registry (or the URL set with [`crate::CodeArtifact::set_registry_url`]).

use crate::http;
use crate::state::{Asset, Version};

/// Every external connection CodeArtifact offers, with its package format.
pub const CONNECTIONS: &[(&str, &str)] = &[
    ("public:npmjs", "npm"),
    ("public:pypi", "pypi"),
    ("public:maven-central", "maven"),
    ("public:maven-googleandroid", "maven"),
    ("public:maven-gradleplugins", "maven"),
    ("public:maven-commonsware", "maven"),
    ("public:maven-clojars", "maven"),
    ("public:nuget-org", "nuget"),
    ("public:crates-io", "cargo"),
    ("public:ruby-gems-org", "ruby"),
];

pub fn format_of(connection: &str) -> Option<&'static str> {
    CONNECTIONS.iter().find(|(n, _)| *n == connection).map(|(_, f)| *f)
}

pub fn default_registry(connection: &str) -> Option<&'static str> {
    Some(match connection {
        "public:npmjs" => "https://registry.npmjs.org",
        "public:pypi" => "https://pypi.org",
        "public:maven-central" => "https://repo1.maven.org/maven2",
        "public:maven-googleandroid" => "https://maven.google.com",
        "public:maven-gradleplugins" => "https://plugins.gradle.org/m2",
        "public:maven-commonsware" => "https://repo.commonsware.com",
        "public:maven-clojars" => "https://repo.clojars.org",
        _ => return None,
    })
}

fn ingested(version: &str, connection: &str, now: chrono::DateTime<chrono::Utc>) -> Version {
    Version {
        version: version.to_string(),
        status: "Published".into(),
        published: now,
        origin_type: "EXTERNAL".into(),
        entry_external_connection: Some(connection.to_string()),
        ..Default::default()
    }
}

async fn fetch(url: &str, accept: &str) -> Option<Vec<u8>> {
    match http::get(url, &[("Accept", accept)]).await {
        Ok(r) if r.status == 200 => Some(r.body),
        Ok(r) => {
            tracing::debug!(url, status = r.status, "external connection fetch");
            None
        }
        Err(e) => {
            tracing::warn!(url, "external connection fetch failed: {e}");
            None
        }
    }
}

/// `@scope/name` or `name` as the npm registry addresses it.
fn npm_path(namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(ns) => format!("@{ns}%2f{name}"),
        None => name.to_string(),
    }
}

/// The npm packument from the registry.
pub async fn npm_packument(base: &str, namespace: Option<&str>, name: &str) -> Option<serde_json::Value> {
    let body = fetch(&format!("{base}/{}", npm_path(namespace, name)), "application/json").await?;
    serde_json::from_slice(&body).ok()
}

/// Ingest one npm version: its manifest and tarball.
pub async fn npm_version(
    base: &str,
    connection: &str,
    namespace: Option<&str>,
    name: &str,
    version: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Version> {
    let packument = npm_packument(base, namespace, name).await?;
    let mut manifest = packument.get("versions")?.get(version)?.clone();
    let tarball = manifest.get("dist")?.get("tarball")?.as_str()?.to_string();
    let content = fetch(&tarball, "application/octet-stream").await?;
    let mut v = ingested(version, connection, now);
    if let Some(m) = manifest.as_object_mut() {
        m.remove("dist");
    }
    v.meta = crate::endpoints::npm::meta_from_manifest(&manifest, packument.get("readme").and_then(|r| r.as_str()));
    v.put_asset(Asset::new("package.tgz", content));
    Some(v)
}

/// A PyPI project's files: `(filename, url)`.
pub async fn pypi_files(base: &str, project: &str) -> Vec<(String, String)> {
    let Some(body) = fetch(&format!("{base}/simple/{project}/"), "application/vnd.pypi.simple.v1+json").await else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) else { return Vec::new() };
    json.get("files")
        .and_then(|f| f.as_array())
        .into_iter()
        .flatten()
        .filter_map(|f| Some((f.get("filename")?.as_str()?.to_string(), f.get("url")?.as_str()?.to_string())))
        .collect()
}

/// Ingest one PyPI version: every file of it.
pub async fn pypi_version(
    base: &str,
    connection: &str,
    project: &str,
    version: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Version> {
    let files = pypi_files(base, project).await;
    let mut v = ingested(version, connection, now);
    for (filename, url) in files {
        if crate::endpoints::pypi::version_of(&filename, project).as_deref() != Some(version) {
            continue;
        }
        let url = if url.starts_with("http") { url } else { format!("{base}/simple/{project}/{url}") };
        let content = fetch(&url, "application/octet-stream").await?;
        v.put_asset(Asset::new(filename, content));
    }
    (!v.assets.is_empty()).then_some(v)
}

/// A file from a Maven repository.
pub async fn maven_file(base: &str, path: &str) -> Option<Vec<u8>> {
    fetch(&format!("{base}/{path}"), "*/*").await
}

/// Ingest one Maven file into a (possibly new) version.
pub fn maven_version(version: &str, connection: &str, now: chrono::DateTime<chrono::Utc>) -> Version {
    ingested(version, connection, now)
}
