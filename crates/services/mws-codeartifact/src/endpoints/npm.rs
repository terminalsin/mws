//! The npm registry protocol: packuments, tarballs, `npm publish` and
//! dist-tags.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Map, Value};
use sha2::Digest;

use super::{error, json, percent_decode, Session};
use crate::names::{check_coordinates, Coordinates};
use crate::state::{Asset, Dependency, License, Version, VersionMeta};
use crate::upstream::{self, listed, Source};
use crate::{external, packages, CodeArtifact};

/// CodeArtifact stores an npm version's tarball as this asset.
pub const TARBALL_ASSET: &str = "package.tgz";

/// `@scope/name` or `name`.
fn coordinates(name: &str) -> Option<Coordinates> {
    let (namespace, package) = match name.strip_prefix('@') {
        Some(scoped) => {
            let (scope, package) = scoped.split_once('/')?;
            (Some(scope), package)
        }
        None => (None, name),
    };
    if package.is_empty() || package.contains('/') {
        return None;
    }
    check_coordinates("npm", namespace, package).ok()
}

fn full_name(c: &Coordinates) -> String {
    match &c.namespace {
        Some(ns) => format!("@{ns}/{}", c.name),
        None => c.name.clone(),
    }
}

fn tarball_url(s: &Session, c: &Coordinates, version: &str) -> String {
    format!("{}{}/-/{}-{version}.tgz", s.repo_url(), full_name(c), c.name)
}

fn license_of(manifest: &Value) -> Vec<License> {
    match manifest.get("license") {
        Some(Value::String(l)) => vec![License { name: Some(l.clone()), url: None }],
        Some(Value::Object(o)) => vec![License {
            name: o.get("type").and_then(Value::as_str).map(str::to_string),
            url: o.get("url").and_then(Value::as_str).map(str::to_string),
        }],
        _ => Vec::new(),
    }
}

/// What CodeArtifact reports about an npm version, from its manifest.
pub fn meta_from_manifest(manifest: &Value, readme: Option<&str>) -> VersionMeta {
    let s = |k: &str| manifest.get(k).and_then(Value::as_str).map(str::to_string);
    let mut dependencies = Vec::new();
    for (key, kind) in [
        ("dependencies", "regular"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
        ("bundleDependencies", "bundled"),
    ] {
        let Some(Value::Object(deps)) = manifest.get(key) else { continue };
        for (name, req) in deps {
            let (namespace, package) = match name.strip_prefix('@').and_then(|n| n.split_once('/')) {
                Some((scope, p)) => (Some(scope.to_string()), p.to_string()),
                None => (None, name.clone()),
            };
            dependencies.push(Dependency {
                namespace,
                package,
                dependency_type: kind.into(),
                version_requirement: req.as_str().map(str::to_string),
            });
        }
    }
    let repository = match manifest.get("repository") {
        Some(Value::String(r)) => Some(r.clone()),
        Some(Value::Object(o)) => o.get("url").and_then(Value::as_str).map(str::to_string),
        _ => None,
    };
    VersionMeta {
        display_name: s("name"),
        summary: s("description"),
        home_page: s("homepage"),
        source_code_repository: repository,
        licenses: license_of(manifest),
        readme: readme.map(str::to_string).or_else(|| s("readme")),
        dependencies,
        npm_manifest: Some(manifest.clone()),
        requires_python: None,
    }
}

fn dist(content: &[u8], tarball: String) -> Value {
    let integrity = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(content));
    json!({
        "tarball": tarball,
        "shasum": hex::encode(sha1::Sha1::digest(content)),
        "integrity": format!("sha512-{integrity}"),
    })
}

fn manifest_for(s: &Session, c: &Coordinates, v: &Version) -> Value {
    let mut m = v.meta.npm_manifest.clone().unwrap_or_else(|| json!({}));
    if !m.is_object() {
        m = json!({});
    }
    let o = m.as_object_mut().expect("object");
    o.insert("name".into(), Value::String(full_name(c)));
    o.insert("version".into(), Value::String(v.version.clone()));
    if let Some(a) = v.asset(TARBALL_ASSET) {
        o.insert("dist".into(), dist(&a.content, tarball_url(s, c, &v.version)));
    }
    m
}

impl CodeArtifact {
    pub(crate) async fn serve_npm(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let rest = percent_decode(&s.target.rest);
        let rest = rest.trim_end_matches('/');
        let method = request.method().as_str();
        match rest {
            "-/ping" => return json(200, &json!({})),
            "-/whoami" => return json(200, &json!({ "username": "aws" })),
            _ => {}
        }
        if let Some(r) = rest.strip_prefix("-/package/") {
            return self.npm_dist_tags(s, method, r, request.body()).await;
        }
        if rest.starts_with("-/") {
            return error("npm", 404, "Not found");
        }
        if let Some((name, file)) = rest.split_once("/-/") {
            let Some(c) = coordinates(name) else { return error("npm", 400, "Invalid package name") };
            if method != "GET" && method != "HEAD" {
                return error("npm", 405, "Method not allowed");
            }
            return self.npm_tarball(s, &c, file).await;
        }
        let Some(c) = coordinates(rest) else { return error("npm", 400, "Invalid package name") };
        match method {
            "GET" | "HEAD" => self.npm_packument(s, &c).await,
            "PUT" => self.npm_publish(s, &c, request.body()).await,
            _ => error("npm", 405, "CodeArtifact does not support this npm operation."),
        }
    }

    async fn npm_packument(&self, s: &Session, c: &Coordinates) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Some((versions, externals, mut tags)) = self.with_domain(s, |d| {
            let (versions, externals) = upstream::visible_versions(d, &s.target.repo, c);
            let mut tags = BTreeMap::new();
            for src in upstream::sources(d, &s.target.repo, c) {
                if let Source::Repo { path } = src {
                    let repo = path.last().expect("non-empty");
                    if let Some(p) = d.repositories.get(repo).and_then(|r| r.packages.get(&c.key())) {
                        for (t, v) in &p.dist_tags {
                            tags.entry(t.clone()).or_insert_with(|| v.clone());
                        }
                    }
                }
            }
            (versions, externals, tags)
        }) else {
            return error("npm", 404, "Not found");
        };
        let mut out = Map::new();
        let mut times = Map::new();
        for v in versions.iter().filter(|v| listed(v)) {
            out.insert(v.version.clone(), manifest_for(s, c, v));
            times.insert(v.version.clone(), Value::String(v.published.to_rfc3339()));
        }
        let mut readme =
            versions.iter().filter(|v| listed(v)).max_by_key(|v| v.published).and_then(|v| v.meta.readme.clone());
        for src in externals {
            let Source::External { connection, .. } = src else { continue };
            let Some(base) = self.registry_url(&connection) else { continue };
            let Some(remote) = external::npm_packument(&base, c.namespace.as_deref(), &c.name).await else { continue };
            if let Some(Value::Object(rv)) = remote.get("versions") {
                for (version, manifest) in rv {
                    if out.contains_key(version) {
                        continue;
                    }
                    let mut m = manifest.clone();
                    if let Some(d) = m.get_mut("dist").and_then(Value::as_object_mut) {
                        d.insert("tarball".into(), Value::String(tarball_url(s, c, version)));
                    }
                    out.insert(version.clone(), m);
                    if let Some(t) = remote.get("time").and_then(|t| t.get(version)) {
                        times.insert(version.clone(), t.clone());
                    }
                }
            }
            if let Some(Value::Object(rt)) = remote.get("dist-tags") {
                for (t, v) in rt {
                    if let Some(v) = v.as_str() {
                        tags.entry(t.clone()).or_insert_with(|| v.to_string());
                    }
                }
            }
            if readme.is_none() {
                readme = remote.get("readme").and_then(Value::as_str).map(str::to_string);
            }
        }
        if out.is_empty() {
            return error("npm", 404, "Not found");
        }
        tags.retain(|_, v| out.contains_key(v));
        if !tags.contains_key("latest") {
            if let Some(latest) = out.keys().max_by(|a, b| crate::names::compare_versions(a, b)) {
                tags.insert("latest".into(), latest.clone());
            }
        }
        let name = full_name(c);
        let mut body = json!({
            "_id": name,
            "name": name,
            "dist-tags": tags,
            "versions": out,
            "time": times,
        });
        if let Some(r) = readme {
            body["readme"] = Value::String(r);
        }
        json(200, &body)
    }

    async fn npm_tarball(&self, s: &Session, c: &Coordinates, file: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let version =
            file.strip_suffix(".tgz").and_then(|f| f.strip_prefix(&format!("{}-", c.name))).map(str::to_string);
        let Some(version) = version else { return error("npm", 404, "Not found") };
        match self.fetch_version(s, c, &version).await {
            Some(v) => match v.asset(TARBALL_ASSET) {
                Some(a) => super::respond(200, "application/octet-stream", a.content.clone()),
                None => error("npm", 404, "Not found"),
            },
            None => error("npm", 404, "Not found"),
        }
    }

    async fn npm_publish(&self, s: &Session, c: &Coordinates, body: &[u8]) -> HttpResponse {
        if let Err(r) = self.authorize_publish(s, c) {
            return r;
        }
        let Ok(doc) = serde_json::from_slice::<Value>(body) else {
            return error("npm", 400, "The request body is not valid JSON.");
        };
        let Some(Value::Object(versions)) = doc.get("versions") else {
            return error("npm", 400, "The publish request has no versions.");
        };
        let attachments = doc.get("_attachments").and_then(Value::as_object).cloned().unwrap_or_default();
        let readme = doc.get("readme").and_then(Value::as_str);
        let now = s.ctx.received_at;
        for (version, manifest) in versions {
            let attachment = attachments
                .get(&format!("{}-{version}.tgz", c.name))
                .or_else(|| attachments.get(&format!("{}-{version}.tgz", full_name(c))))
                .or_else(|| attachments.values().next());
            let Some(data) = attachment.and_then(|a| a.get("data")).and_then(Value::as_str) else {
                return error("npm", 400, "The publish request has no tarball.");
            };
            let Ok(content) = base64::engine::general_purpose::STANDARD.decode(data) else {
                return error("npm", 400, "The tarball is not valid base64.");
            };
            let mut manifest = manifest.clone();
            if let Some(m) = manifest.as_object_mut() {
                m.remove("dist");
                m.remove("readme");
            }
            let meta = meta_from_manifest(&manifest, readme);
            let result = self.with_domain_mut(s, |d| {
                packages::publish(
                    d,
                    &s.target.repo,
                    c,
                    version,
                    Asset::new(TARBALL_ASSET, content),
                    Some(meta),
                    true,
                    now,
                    false,
                )
            });
            match result {
                Some(Ok(_)) => {}
                Some(Err(e)) if e.status == 409 => {
                    return error(
                        "npm",
                        409,
                        &format!("Cannot publish over previously published version \"{version}\"."),
                    )
                }
                Some(Err(e)) => return error("npm", e.status, &e.message),
                None => return error("npm", 404, "Not found"),
            }
        }
        if let Some(Value::Object(tags)) = doc.get("dist-tags") {
            self.with_domain_mut(s, |d| {
                let p = upstream::package_for_publish(d, &s.target.repo, c);
                for (t, v) in tags {
                    if let Some(v) = v.as_str() {
                        p.dist_tags.insert(t.clone(), v.to_string());
                    }
                }
            });
        }
        json(200, &json!({ "success": true }))
    }

    async fn npm_dist_tags(&self, s: &Session, method: &str, rest: &str, body: &[u8]) -> HttpResponse {
        let Some((name, tag_part)) = rest.rsplit_once("/dist-tags").map(|(n, t)| (n, t.trim_start_matches('/'))) else {
            return error("npm", 404, "Not found");
        };
        let Some(c) = coordinates(name) else { return error("npm", 400, "Invalid package name") };
        let tag = (!tag_part.is_empty()).then(|| tag_part.to_string());
        match (method, tag) {
            ("GET", _) => {
                if let Err(r) = self.authorize_read(s) {
                    return r;
                }
                let tags = self.with_domain(s, |d| {
                    d.repositories
                        .get(&s.target.repo)
                        .and_then(|r| r.packages.get(&c.key()))
                        .map(|p| p.dist_tags.clone())
                });
                match tags.flatten() {
                    Some(t) => json(200, &json!(t)),
                    None => error("npm", 404, "Not found"),
                }
            }
            ("PUT" | "POST", Some(tag)) => {
                if let Err(r) = self.authorize_publish(s, &c) {
                    return r;
                }
                let Some(version) =
                    serde_json::from_slice::<Value>(body).ok().and_then(|v| v.as_str().map(str::to_string))
                else {
                    return error("npm", 400, "The dist-tag must name a version.");
                };
                let ok = self.with_domain_mut(s, |d| {
                    let Some(p) = d.repositories.get_mut(&s.target.repo).and_then(|r| r.packages.get_mut(&c.key()))
                    else {
                        return false;
                    };
                    if !p.versions.contains_key(&version) {
                        return false;
                    }
                    p.dist_tags.insert(tag, version);
                    true
                });
                if ok == Some(true) {
                    json(200, &json!({ "ok": true }))
                } else {
                    error("npm", 404, "Not found")
                }
            }
            ("DELETE", Some(tag)) => {
                if let Err(r) = self.authorize_publish(s, &c) {
                    return r;
                }
                if tag == "latest" {
                    return error("npm", 400, "The latest dist-tag cannot be removed.");
                }
                self.with_domain_mut(s, |d| {
                    if let Some(p) = d.repositories.get_mut(&s.target.repo).and_then(|r| r.packages.get_mut(&c.key())) {
                        p.dist_tags.remove(&tag);
                    }
                });
                json(200, &json!({ "ok": true }))
            }
            _ => error("npm", 405, "Method not allowed"),
        }
    }
}
