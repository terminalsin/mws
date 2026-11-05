//! The Cargo registry protocol: a sparse index, crate downloads,
//! `cargo publish`, and yanking.

use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Value};
use sha2::Digest;

use super::{error, json, percent_decode, respond, Session};
use crate::names::{check_coordinates, compare_versions};
use crate::state::{Asset, Dependency, License, VersionMeta};
use crate::upstream::Source;
use crate::{external, CodeArtifact};

/// The sparse index path of a crate (`1/a`, `2/ab`, `3/a/abc`, `ab/cd/abcd`).
pub fn index_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    match n.len() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

fn asset_name(name: &str, version: &str) -> String {
    format!("{name}-{version}.crate")
}

/// The index entry and what CodeArtifact reports, from `cargo publish`
/// metadata.
fn from_publish(meta: &Value, content: &[u8]) -> (Value, VersionMeta) {
    let s = |k: &str| meta.get(k).and_then(Value::as_str).map(str::to_string);
    let mut deps = Vec::new();
    let mut dependencies = Vec::new();
    for d in meta.get("deps").and_then(Value::as_array).into_iter().flatten() {
        let name = d.get("name").and_then(Value::as_str).unwrap_or_default();
        let explicit = d.get("explicit_name_in_toml").and_then(Value::as_str);
        let req = d.get("version_req").and_then(Value::as_str).unwrap_or("*");
        let kind = d.get("kind").and_then(Value::as_str).unwrap_or("normal");
        let mut entry = json!({
            "name": explicit.unwrap_or(name),
            "req": req,
            "features": d.get("features").cloned().unwrap_or_else(|| json!([])),
            "optional": d.get("optional").cloned().unwrap_or(Value::Bool(false)),
            "default_features": d.get("default_features").cloned().unwrap_or(Value::Bool(true)),
            "target": d.get("target").cloned().unwrap_or(Value::Null),
            "kind": kind,
            "registry": d.get("registry").cloned().unwrap_or(Value::Null),
        });
        if explicit.is_some() {
            entry["package"] = Value::String(name.to_string());
        }
        deps.push(entry);
        dependencies.push(Dependency {
            namespace: None,
            package: name.to_string(),
            dependency_type: kind.to_string(),
            version_requirement: Some(req.to_string()),
        });
    }
    let entry = json!({
        "name": meta.get("name").cloned().unwrap_or(Value::Null),
        "vers": meta.get("vers").cloned().unwrap_or(Value::Null),
        "deps": deps,
        "cksum": hex::encode(sha2::Sha256::digest(content)),
        "features": meta.get("features").cloned().unwrap_or_else(|| json!({})),
        "yanked": false,
        "links": meta.get("links").cloned().unwrap_or(Value::Null),
        "rust_version": meta.get("rust_version").cloned().unwrap_or(Value::Null),
        "v": 2,
    });
    let meta = VersionMeta {
        display_name: s("name"),
        summary: s("description"),
        home_page: s("homepage"),
        source_code_repository: s("repository"),
        licenses: s("license").map(|l| vec![License { name: Some(l), url: None }]).unwrap_or_default(),
        readme: s("readme"),
        dependencies,
        registry_metadata: Some(entry.clone()),
        ..Default::default()
    };
    (entry, meta)
}

/// `u32 LE length, JSON, u32 LE length, .crate`.
fn split_publish(body: &[u8]) -> Option<(Value, &[u8])> {
    let len =
        |at: usize| -> Option<usize> { Some(u32::from_le_bytes(body.get(at..at + 4)?.try_into().ok()?) as usize) };
    let jl = len(0)?;
    let meta: Value = serde_json::from_slice(body.get(4..4 + jl)?).ok()?;
    let cl = len(4 + jl)?;
    let content = body.get(8 + jl..8 + jl + cl)?;
    Some((meta, content))
}

impl CodeArtifact {
    pub(crate) async fn serve_cargo(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let rest = percent_decode(&s.target.rest);
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        let method = request.method().as_str();
        match (method, parts.as_slice()) {
            ("GET", ["config.json"]) => {
                if let Err(r) = self.authorize_read(s) {
                    return r;
                }
                let root = s.repo_url();
                json(
                    200,
                    &json!({ "dl": format!("{root}api/v1/crates"), "api": root.trim_end_matches('/'), "auth-required": true }),
                )
            }
            ("PUT", ["api", "v1", "crates", "new"]) => self.cargo_publish(s, request.body()),
            ("GET", ["api", "v1", "crates", name, version, "download"]) => self.cargo_download(s, name, version).await,
            ("DELETE", ["api", "v1", "crates", name, version, "yank"]) => self.cargo_yank(s, name, version, "Unlisted"),
            ("PUT", ["api", "v1", "crates", name, version, "unyank"]) => self.cargo_yank(s, name, version, "Published"),
            ("GET", ["api", "v1", "crates"]) => self.cargo_search(s, request.uri().query().unwrap_or("")),
            ("GET", [.., name]) if index_path(name) == parts.join("/") => self.cargo_index(s, name).await,
            _ => error("cargo", 404, "Not Found"),
        }
    }

    async fn cargo_index(&self, s: &Session, name: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("cargo", None, name) else { return error("cargo", 404, "Not Found") };
        let (mut versions, externals) = self.listing(s, &c);
        versions.retain(|v| matches!(v.status.as_str(), "Published" | "Unlisted"));
        versions.sort_by(|a, b| compare_versions(&a.version, &b.version));
        let mut lines: Vec<(String, String)> = versions
            .iter()
            .filter_map(|v| {
                let mut e = v.meta.registry_metadata.clone()?;
                e["yanked"] = Value::Bool(v.status == "Unlisted");
                Some((v.version.clone(), e.to_string()))
            })
            .collect();
        for src in externals {
            let Source::External { connection, .. } = src else { continue };
            let Some(base) = self.registry_url(&connection) else { continue };
            for line in external::cargo_index(&base, &c.name).await {
                let Ok(e) = serde_json::from_str::<Value>(&line) else { continue };
                let Some(v) = e.get("vers").and_then(Value::as_str) else { continue };
                if !lines.iter().any(|(x, _)| x == v) {
                    lines.push((v.to_string(), line));
                }
            }
        }
        if lines.is_empty() {
            return error("cargo", 404, "Not Found");
        }
        let body: String = lines.into_iter().map(|(_, l)| l + "\n").collect();
        respond(200, "text/plain", body)
    }

    async fn cargo_download(&self, s: &Session, name: &str, version: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("cargo", None, name) else { return error("cargo", 404, "Not Found") };
        match self.fetch_version(s, &c, version).await.and_then(|v| v.assets.first().cloned()) {
            Some(a) => respond(200, "application/x-tar", a.content),
            None => error("cargo", 404, "Not Found"),
        }
    }

    fn cargo_publish(&self, s: &Session, body: &[u8]) -> HttpResponse {
        let Some((meta, content)) = split_publish(body) else {
            return error("cargo", 400, "The publish request is malformed.");
        };
        let (Some(name), Some(version)) =
            (meta.get("name").and_then(Value::as_str), meta.get("vers").and_then(Value::as_str))
        else {
            return error("cargo", 400, "The publish metadata has no name or version.");
        };
        let Ok(c) = check_coordinates("cargo", None, name) else { return error("cargo", 400, "Invalid crate name.") };
        let (_, vmeta) = from_publish(&meta, content);
        match self.publish_asset(
            s,
            &c,
            version,
            Asset::new(asset_name(name, version), content.to_vec()),
            Some(vmeta),
            true,
            false,
        ) {
            Ok(_) => json(200, &json!({ "warnings": { "invalid_categories": [], "invalid_badges": [], "other": [] } })),
            Err(r) if r.status() == 409 => {
                error("cargo", 409, &format!("crate version `{version}` is already uploaded"))
            }
            Err(r) => r,
        }
    }

    fn cargo_yank(&self, s: &Session, name: &str, version: &str, status: &str) -> HttpResponse {
        let Ok(c) = check_coordinates("cargo", None, name) else { return error("cargo", 404, "Not Found") };
        match self.set_status(s, &c, version, status) {
            Ok(true) => json(200, &json!({ "ok": true })),
            Ok(false) => error("cargo", 404, "Not Found"),
            Err(r) => r,
        }
    }

    fn cargo_search(&self, s: &Session, query: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let q = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("q="))
            .map(|q| percent_decode(&q.replace('+', " ")).to_ascii_lowercase())
            .unwrap_or_default();
        let crates: Vec<Value> = self
            .with_domain(s, |d| {
                d.repositories
                    .get(&s.target.repo)
                    .map(|r| {
                        r.packages
                            .values()
                            .filter(|p| p.format == "cargo" && p.name.contains(&q))
                            .filter_map(|p| {
                                let v = p
                                    .versions
                                    .values()
                                    .filter(|v| v.status == "Published")
                                    .max_by(|a, b| compare_versions(&a.version, &b.version))?;
                                Some(json!({
                                    "name": p.name,
                                    "max_version": v.version,
                                    "description": v.meta.summary,
                                }))
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        json(200, &json!({ "meta": { "total": crates.len() }, "crates": crates }))
    }
}

/// An ingested crate's metadata, from its index line.
pub fn meta_from_index(line: &Value) -> VersionMeta {
    VersionMeta {
        display_name: line.get("name").and_then(Value::as_str).map(str::to_string),
        dependencies: line
            .get("deps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|d| {
                Some(Dependency {
                    namespace: None,
                    package: d.get("package").or_else(|| d.get("name"))?.as_str()?.to_string(),
                    dependency_type: d.get("kind").and_then(Value::as_str).unwrap_or("normal").to_string(),
                    version_requirement: d.get("req").and_then(Value::as_str).map(str::to_string),
                })
            })
            .collect(),
        registry_metadata: Some(line.clone()),
        ..Default::default()
    }
}

pub fn crate_asset(name: &str, version: &str, content: Vec<u8>) -> Asset {
    Asset::new(asset_name(name, version), content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_paths() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn publish_bodies_split() {
        let meta = br#"{"name":"x","vers":"1.0.0","deps":[{"name":"serde","version_req":"^1","kind":"normal","explicit_name_in_toml":"s"}]}"#;
        let mut body = (meta.len() as u32).to_le_bytes().to_vec();
        body.extend_from_slice(meta);
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(b"abc");
        let (m, c) = split_publish(&body).unwrap();
        assert_eq!(c, b"abc");
        let (entry, vm) = from_publish(&m, c);
        assert_eq!(entry["deps"][0]["name"], "s");
        assert_eq!(entry["deps"][0]["package"], "serde");
        assert_eq!(vm.dependencies[0].package, "serde");
    }
}
