//! External connections: public registries a repository ingests packages
//! from on demand. Every connection fetches from its
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
        "public:crates-io" => "https://index.crates.io",
        "public:nuget-org" => "https://api.nuget.org/v3/index.json",
        "public:ruby-gems-org" => "https://rubygems.org",
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

/// A crate's lines in a sparse Cargo index.
pub async fn cargo_index(base: &str, name: &str) -> Vec<String> {
    let path = crate::endpoints::cargo::index_path(name);
    let Some(body) = fetch(&format!("{}/{path}", base.trim_end_matches('/')), "text/plain").await else {
        return Vec::new();
    };
    String::from_utf8_lossy(&body).lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect()
}

/// Ingest one crate version: its index entry and `.crate` file.
pub async fn cargo_version(
    base: &str,
    connection: &str,
    name: &str,
    version: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Version> {
    let base = base.trim_end_matches('/');
    let line = cargo_index(base, name)
        .await
        .into_iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
        .find(|e| e.get("vers").and_then(|v| v.as_str()) == Some(version))?;
    let real = line.get("name").and_then(|n| n.as_str()).unwrap_or(name).to_string();
    let config: serde_json::Value =
        serde_json::from_slice(&fetch(&format!("{base}/config.json"), "application/json").await?).ok()?;
    let dl = config.get("dl")?.as_str()?;
    let url = if dl.contains('{') {
        dl.replace("{crate}", &real).replace("{version}", version).replace(
            "{lowerprefix}",
            &crate::endpoints::cargo::index_path(&real).rsplit_once('/').map(|x| x.0.to_string()).unwrap_or_default(),
        )
    } else {
        format!("{dl}/{real}/{version}/download")
    };
    let content = fetch(&url, "application/octet-stream").await?;
    let mut v = ingested(version, connection, now);
    v.meta = crate::endpoints::cargo::meta_from_index(&line);
    v.put_asset(crate::endpoints::cargo::crate_asset(&real, version, content));
    Some(v)
}

/// The NuGet package base address (flat container) of a V3 service index.
async fn nuget_base_address(index: &str) -> Option<String> {
    let body: serde_json::Value = serde_json::from_slice(&fetch(index, "application/json").await?).ok()?;
    let base = body.get("resources")?.as_array()?.iter().find_map(|r| {
        (r.get("@type")?.as_str()? == "PackageBaseAddress/3.0.0").then(|| r.get("@id")?.as_str().map(str::to_string))?
    })?;
    Some(if base.ends_with('/') { base } else { format!("{base}/") })
}

/// A NuGet package's versions.
pub async fn nuget_versions(index: &str, id: &str) -> Vec<String> {
    let Some(base) = nuget_base_address(index).await else { return Vec::new() };
    let Some(body) = fetch(&format!("{base}{}/index.json", id.to_ascii_lowercase()), "application/json").await else {
        return Vec::new();
    };
    serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|j| j.get("versions").and_then(|v| v.as_array()).cloned())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
        .collect()
}

/// Ingest one NuGet version: its `.nupkg`.
pub async fn nuget_version(
    index: &str,
    connection: &str,
    id: &str,
    version: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Version> {
    let base = nuget_base_address(index).await?;
    let id = id.to_ascii_lowercase();
    let content = fetch(&format!("{base}{id}/{version}/{id}.{version}.nupkg"), "application/octet-stream").await?;
    let (_, _, meta) =
        crate::endpoints::nuget::nuspec(&content).as_deref().and_then(crate::endpoints::nuget::parse_nuspec)?;
    let mut v = ingested(version, connection, now);
    v.meta = meta;
    v.put_asset(Asset::new(format!("{id}.{version}.nupkg"), content));
    Some(v)
}

/// A gem's compact index lines (without the `---` header).
pub async fn ruby_info(base: &str, name: &str) -> Vec<String> {
    let Some(body) = fetch(&format!("{}/info/{name}", base.trim_end_matches('/')), "text/plain").await else {
        return Vec::new();
    };
    String::from_utf8_lossy(&body).lines().filter(|l| !l.is_empty() && *l != "---").map(str::to_string).collect()
}

/// Ingest one gem version: its `.gem`.
pub async fn ruby_version(
    base: &str,
    connection: &str,
    name: &str,
    version: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Version> {
    let content =
        fetch(&format!("{}/gems/{name}-{version}.gem", base.trim_end_matches('/')), "application/octet-stream").await?;
    let mut v = ingested(version, connection, now);
    v.meta = match crate::endpoints::ruby::parse_gem(&content) {
        Some((_, _, meta)) => meta,
        None => crate::endpoints::ruby::meta_from_info(&format!("{version} |")),
    };
    v.put_asset(Asset::new(format!("{name}-{version}.gem"), content));
    Some(v)
}
