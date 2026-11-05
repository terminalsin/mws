//! The Swift package registry protocol (SE-0292), which `swift package`
//! resolves from and publishes to: release lists, release metadata,
//! manifests, source archives, identifier lookup, and publishing.

use std::io::Read;

use base64::Engine;
use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Value};

use super::{error, json, multipart, percent_decode, respond, Session};
use crate::names::{check_coordinates, compare_versions, Coordinates};
use crate::state::{Asset, License, Version, VersionMeta};
use crate::upstream::listed;
use crate::CodeArtifact;

const ARCHIVE: &str = "source-archive.zip";

fn with_version_header(mut r: HttpResponse) -> HttpResponse {
    r.headers_mut().insert("content-version", http::HeaderValue::from_static("1"));
    r
}

/// The package manifest(s) at the root of a source archive (whose files
/// sit under one top-level directory): `(file name, contents)`.
pub fn manifests(archive: &[u8]) -> Vec<(String, String)> {
    let Ok(mut zip) = zip::ZipArchive::new(std::io::Cursor::new(archive)) else { return Vec::new() };
    let names: Vec<String> = zip.file_names().map(str::to_string).collect();
    let mut out = Vec::new();
    for name in names {
        let file = name.rsplit('/').next().unwrap_or(&name).to_string();
        let depth = name.trim_end_matches('/').matches('/').count();
        let is_manifest = file == "Package.swift" || (file.starts_with("Package@swift-") && file.ends_with(".swift"));
        if !is_manifest || depth > 1 {
            continue;
        }
        let mut text = String::new();
        if let Ok(mut f) = zip.by_name(&name) {
            if f.read_to_string(&mut text).is_ok() {
                out.push((file, text));
            }
        }
    }
    out
}

fn release_metadata(meta: &Value) -> VersionMeta {
    let s = |k: &str| meta.get(k).and_then(Value::as_str).map(str::to_string);
    VersionMeta {
        display_name: s("name"),
        summary: s("description"),
        home_page: s("readmeURL"),
        source_code_repository: meta
            .get("repositoryURLs")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(str::to_string),
        licenses: s("licenseURL").map(|u| vec![License { name: None, url: Some(u) }]).unwrap_or_default(),
        registry_metadata: Some(meta.clone()),
        ..Default::default()
    }
}

/// Repository URLs compare without scheme, `.git` or a trailing slash.
fn normalize_url(u: &str) -> String {
    let u = u.trim().to_ascii_lowercase();
    let u = u.split_once("://").map(|(_, r)| r.to_string()).unwrap_or(u);
    let u = u.strip_prefix("git@").map(|r| r.replacen(':', "/", 1)).unwrap_or(u);
    u.trim_end_matches('/').trim_end_matches(".git").to_string()
}

impl CodeArtifact {
    pub(crate) async fn serve_swift(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let rest = percent_decode(&s.target.rest);
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        let method = request.method().as_str();
        let query = request.uri().query().unwrap_or("");
        let response = match (method, parts.as_slice()) {
            ("POST", ["login"]) => match self.authorize_read(s) {
                Ok(()) => respond(200, "text/plain", ""),
                Err(r) => r,
            },
            ("GET", ["identifiers"]) => self.swift_identifiers(s, query),
            ("GET" | "HEAD", [scope, name]) => self.swift_releases(s, scope, name.trim_end_matches(".json")),
            ("GET" | "HEAD", [scope, name, version]) if version.ends_with(".zip") => {
                self.swift_archive(s, scope, name, version.trim_end_matches(".zip"))
            }
            ("GET" | "HEAD", [scope, name, version]) => {
                self.swift_release(s, scope, name, version.trim_end_matches(".json"))
            }
            ("GET" | "HEAD", [scope, name, version, "Package.swift"]) => {
                let swift_version = query.split('&').find_map(|kv| kv.strip_prefix("swift-version="));
                self.swift_manifest(s, scope, name, version, swift_version)
            }
            ("PUT", [scope, name, version]) => self.swift_publish(s, scope, name, version, request),
            _ => error("swift", 404, "Not Found"),
        };
        with_version_header(response)
    }

    fn swift_coordinates(scope: &str, name: &str) -> Option<Coordinates> {
        check_coordinates("swift", Some(scope), name).ok()
    }

    fn swift_versions(&self, s: &Session, c: &Coordinates) -> Vec<Version> {
        let (mut versions, _) = self.listing(s, c);
        versions.retain(|v| listed(v) || v.status == "Unlisted");
        versions.sort_by(|a, b| compare_versions(&b.version, &a.version));
        versions
    }

    fn swift_releases(&self, s: &Session, scope: &str, name: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Some(c) = Self::swift_coordinates(scope, name) else { return error("swift", 404, "Not Found") };
        let versions = self.swift_versions(s, &c);
        if versions.is_empty() {
            return error("swift", 404, "Not Found");
        }
        let root = s.repo_url();
        let releases: serde_json::Map<String, Value> = versions
            .iter()
            .map(|v| {
                let mut r = json!({ "url": format!("{root}{scope}/{name}/{}", v.version) });
                if v.status == "Unlisted" {
                    r["problem"] = json!({ "status": 410, "title": "Gone", "detail": "this release was removed" });
                }
                (v.version.clone(), r)
            })
            .collect();
        let latest = versions.iter().find(|v| listed(v)).map(|v| v.version.clone());
        let mut r = json(200, &json!({ "releases": releases }));
        if let Some(l) = latest {
            let link = format!("<{root}{scope}/{name}/{l}>; rel=\"latest-version\"");
            r.headers_mut().insert("link", http::HeaderValue::from_str(&link).expect("ascii"));
        }
        r
    }

    #[allow(clippy::result_large_err)]
    fn swift_find(
        &self,
        s: &Session,
        scope: &str,
        name: &str,
        version: &str,
    ) -> Result<(Coordinates, Version), HttpResponse> {
        self.authorize_read(s)?;
        let c = Self::swift_coordinates(scope, name).ok_or_else(|| error("swift", 404, "Not Found"))?;
        let v = self
            .swift_versions(s, &c)
            .into_iter()
            .find(|v| v.version == version)
            .ok_or_else(|| error("swift", 404, "Not Found"))?;
        Ok((c, v))
    }

    fn swift_release(&self, s: &Session, scope: &str, name: &str, version: &str) -> HttpResponse {
        let (_, v) = match self.swift_find(s, scope, name, version) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let resources: Vec<Value> = v
            .asset(ARCHIVE)
            .map(|a| json!({ "name": "source-archive", "type": "application/zip", "checksum": a.sha256() }))
            .into_iter()
            .collect();
        json(
            200,
            &json!({
                "id": format!("{scope}.{name}"),
                "version": v.version,
                "resources": resources,
                "metadata": v.meta.registry_metadata.clone().unwrap_or_else(|| json!({})),
                "publishedAt": v.published.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            }),
        )
    }

    fn swift_manifest(
        &self,
        s: &Session,
        scope: &str,
        name: &str,
        version: &str,
        swift_version: Option<&str>,
    ) -> HttpResponse {
        let (_, v) = match self.swift_find(s, scope, name, version) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let all = v.asset(ARCHIVE).map(|a| manifests(&a.content)).unwrap_or_default();
        let wanted = match swift_version {
            Some(sv) => format!("Package@swift-{sv}.swift"),
            None => "Package.swift".into(),
        };
        let Some((_, text)) = all.iter().find(|(f, _)| *f == wanted) else {
            return match swift_version {
                // The client then falls back to `Package.swift`.
                Some(_) => {
                    let mut r = respond(303, "text/plain", "");
                    let loc = format!("{}{scope}/{name}/{version}/Package.swift", s.repo_url());
                    r.headers_mut().insert("location", http::HeaderValue::from_str(&loc).expect("ascii"));
                    r
                }
                None => error("swift", 404, "Not Found"),
            };
        };
        let mut r = respond(200, "text/x-swift", text.clone());
        r.headers_mut().insert(
            "content-disposition",
            http::HeaderValue::from_str(&format!("attachment; filename=\"{wanted}\"")).expect("ascii"),
        );
        let alternates: Vec<String> = all
            .iter()
            .filter(|(f, _)| f != "Package.swift")
            .filter_map(|(f, _)| {
                let tools = f.strip_prefix("Package@swift-")?.strip_suffix(".swift")?;
                Some(format!(
                    "<{}{scope}/{name}/{version}/Package.swift?swift-version={tools}>; rel=\"alternate\"; filename=\"{f}\"; swift-tools-version=\"{tools}\"",
                    s.repo_url()
                ))
            })
            .collect();
        if swift_version.is_none() && !alternates.is_empty() {
            if let Ok(h) = http::HeaderValue::from_str(&alternates.join(", ")) {
                r.headers_mut().insert("link", h);
            }
        }
        r
    }

    fn swift_archive(&self, s: &Session, scope: &str, name: &str, version: &str) -> HttpResponse {
        let (_, v) = match self.swift_find(s, scope, name, version) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let Some(a) = v.asset(ARCHIVE) else { return error("swift", 404, "Not Found") };
        use sha2::Digest;
        let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&a.content));
        let mut r = respond(200, "application/zip", a.content.clone());
        let h = r.headers_mut();
        h.insert("digest", http::HeaderValue::from_str(&format!("sha-256={digest}")).expect("ascii"));
        h.insert(
            "content-disposition",
            http::HeaderValue::from_str(&format!("attachment; filename=\"{name}-{version}.zip\"")).expect("ascii"),
        );
        r
    }

    fn swift_identifiers(&self, s: &Session, query: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Some(url) = query.split('&').find_map(|kv| kv.strip_prefix("url=")).map(percent_decode) else {
            return error("swift", 400, "The url query parameter is required.");
        };
        let wanted = normalize_url(&url);
        let ids: Vec<String> = self
            .with_domain(s, |d| {
                d.repositories
                    .get(&s.target.repo)
                    .map(|r| {
                        r.packages
                            .values()
                            .filter(|p| p.format == "swift")
                            .filter(|p| {
                                p.versions.values().any(|v| {
                                    v.meta
                                        .registry_metadata
                                        .as_ref()
                                        .and_then(|m| m.get("repositoryURLs"))
                                        .and_then(Value::as_array)
                                        .is_some_and(|urls| {
                                            urls.iter().filter_map(Value::as_str).any(|u| normalize_url(u) == wanted)
                                        })
                                })
                            })
                            .map(|p| format!("{}.{}", p.namespace.clone().unwrap_or_default(), p.name))
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        if ids.is_empty() {
            return error("swift", 404, "Not Found");
        }
        json(200, &json!({ "identifiers": ids }))
    }

    fn swift_publish(
        &self,
        s: &Session,
        scope: &str,
        name: &str,
        version: &str,
        request: &HttpRequest,
    ) -> HttpResponse {
        let Some(c) = Self::swift_coordinates(scope, name) else {
            return error("swift", 400, "Invalid package identifier.");
        };
        let content_type = request.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
        let Some(boundary) = multipart::boundary(content_type) else {
            return error("swift", 415, "Publishing takes multipart/form-data.");
        };
        let parts = multipart::parse(request.body(), &boundary);
        let Some(archive) = parts.iter().find(|p| p.name == "source-archive") else {
            return error("swift", 422, "The source-archive part is missing.");
        };
        if manifests(&archive.data).iter().all(|(f, _)| f != "Package.swift") {
            return error("swift", 422, "The source archive has no Package.swift.");
        }
        let metadata = match parts.iter().find(|p| p.name == "metadata") {
            Some(p) => match serde_json::from_slice::<Value>(&p.data) {
                Ok(m) => m,
                Err(_) => return error("swift", 422, "The metadata is not valid JSON."),
            },
            None => json!({}),
        };
        let asset = Asset::new(ARCHIVE, archive.data.clone());
        match self.publish_asset(s, &c, version, asset, Some(release_metadata(&metadata)), true, false) {
            Ok(_) => {
                let mut r = respond(201, "text/plain", "");
                let loc = format!("{}{scope}/{name}/{version}", s.repo_url());
                r.headers_mut().insert("location", http::HeaderValue::from_str(&loc).expect("ascii"));
                r
            }
            Err(r) => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_normalize() {
        assert_eq!(normalize_url("https://github.com/Acme/Lib.git"), "github.com/acme/lib");
        assert_eq!(normalize_url("git@github.com:acme/lib.git"), "github.com/acme/lib");
    }
}
