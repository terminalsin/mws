//! The NuGet V3 protocol: the service index, the package base address
//! (flat container), registrations, search, and `dotnet nuget push`.

use std::io::Read;

use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Value};

use super::{error, json, multipart, percent_decode, respond, Session};
use crate::names::{check_coordinates, compare_versions, Coordinates};
use crate::state::{Asset, Dependency, License, Version, VersionMeta};
use crate::upstream::{listed, Source};
use crate::{external, CodeArtifact};

/// NuGet's normalized version: no leading zeros, at least three parts,
/// no build metadata, lower case.
pub fn normalize_version(v: &str) -> String {
    let v = v.split('+').next().unwrap_or(v);
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut parts: Vec<String> =
        core.split('.').map(|p| p.parse::<u64>().map(|n| n.to_string()).unwrap_or_else(|_| p.to_string())).collect();
    while parts.len() < 3 {
        parts.push("0".into());
    }
    if parts.len() == 4 && parts[3] == "0" {
        parts.pop();
    }
    let mut out = parts.join(".");
    if let Some(p) = pre {
        out.push('-');
        out.push_str(p);
    }
    out.to_ascii_lowercase()
}

fn nupkg_name(id: &str, version: &str) -> String {
    format!("{}.{}.nupkg", id.to_ascii_lowercase(), version)
}

/// The `.nuspec` inside a package.
pub fn nuspec(nupkg: &[u8]) -> Option<String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(nupkg)).ok()?;
    let name = zip.file_names().find(|n| !n.contains('/') && n.ends_with(".nuspec"))?.to_string();
    let mut out = String::new();
    zip.by_name(&name).ok()?.read_to_string(&mut out).ok()?;
    Some(out)
}

/// What the registry and CodeArtifact report about a package, from its
/// `.nuspec`: `(id, version, metadata)`.
pub fn parse_nuspec(xml: &str) -> Option<(String, String, VersionMeta)> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let metadata = doc.descendants().find(|n| n.is_element() && n.tag_name().name() == "metadata")?;
    let text = |name: &str| {
        metadata
            .children()
            .find(|c| c.is_element() && c.tag_name().name() == name)
            .and_then(|c| c.text())
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    };
    let id = text("id")?;
    let version = normalize_version(&text("version")?);
    let mut groups = Vec::new();
    let mut dependencies = Vec::new();
    if let Some(deps) = metadata.children().find(|c| c.is_element() && c.tag_name().name() == "dependencies") {
        let mut add_group = |framework: Option<&str>, node: roxmltree::Node<'_, '_>| {
            let ds: Vec<Value> = node
                .children()
                .filter(|d| d.is_element() && d.tag_name().name() == "dependency")
                .filter_map(|d| {
                    let id = d.attribute("id")?;
                    let range = d.attribute("version").unwrap_or("");
                    dependencies.push(Dependency {
                        namespace: None,
                        package: id.to_ascii_lowercase(),
                        dependency_type: framework.unwrap_or("").to_string(),
                        version_requirement: (!range.is_empty()).then(|| range.to_string()),
                    });
                    Some(json!({ "id": id, "range": range }))
                })
                .collect();
            let mut g = json!({ "dependencies": ds });
            if let Some(f) = framework {
                g["targetFramework"] = Value::String(f.to_string());
            }
            groups.push(g);
        };
        let group_nodes: Vec<_> =
            deps.children().filter(|g| g.is_element() && g.tag_name().name() == "group").collect();
        if group_nodes.is_empty() {
            add_group(None, deps);
        } else {
            for g in group_nodes {
                add_group(g.attribute("targetFramework"), g);
            }
        }
    }
    let repository = metadata
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "repository")
        .and_then(|r| r.attribute("url"));
    let entry = json!({
        "id": id,
        "version": version,
        "description": text("description"),
        "authors": text("authors"),
        "title": text("title"),
        "tags": text("tags"),
        "projectUrl": text("projectUrl"),
        "licenseExpression": text("license"),
        "dependencyGroups": groups,
    });
    let meta = VersionMeta {
        display_name: Some(text("title").unwrap_or_else(|| id.clone())),
        summary: text("summary").or_else(|| text("description")),
        home_page: text("projectUrl"),
        source_code_repository: repository.map(str::to_string),
        licenses: text("license").map(|l| vec![License { name: Some(l), url: text("licenseUrl") }]).unwrap_or_default(),
        readme: None,
        dependencies,
        registry_metadata: Some(entry),
        ..Default::default()
    };
    Some((id, version, meta))
}

impl CodeArtifact {
    pub(crate) async fn serve_nuget(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let rest = percent_decode(&s.target.rest);
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        let method = request.method().as_str();
        match (method, parts.as_slice()) {
            ("GET", ["v3", "index.json"]) => self.nuget_service_index(s),
            ("GET", ["v3", "package", id, "index.json"]) => self.nuget_versions(s, id).await,
            ("GET", ["v3", "package", id, version, file]) => self.nuget_download(s, id, version, file).await,
            ("GET", ["v3", "registration", id, "index.json"]) => self.nuget_registration(s, id).await,
            ("GET", ["v3", "registration", id, leaf]) => match leaf.strip_suffix(".json") {
                Some(v) => self.nuget_leaf(s, id, v),
                None => error("nuget", 404, "Not Found"),
            },
            ("GET", ["v3", "query"]) => self.nuget_search(s, request.uri().query().unwrap_or("")),
            ("PUT" | "POST", ["api", "v2", "package"]) => self.nuget_push(s, request),
            ("DELETE", ["api", "v2", "package", id, version]) => self.nuget_list(s, id, version, "Unlisted"),
            ("POST", ["api", "v2", "package", id, version]) => self.nuget_list(s, id, version, "Published"),
            _ => error("nuget", 404, "Not Found"),
        }
    }

    fn nuget_service_index(&self, s: &Session) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let root = s.repo_url();
        let resource = |path: &str, t: &str| json!({ "@id": format!("{root}{path}"), "@type": t });
        json(
            200,
            &json!({
                "version": "3.0.0",
                "resources": [
                    resource("v3/package/", "PackageBaseAddress/3.0.0"),
                    resource("api/v2/package/", "PackagePublish/2.0.0"),
                    resource("v3/registration/", "RegistrationsBaseUrl"),
                    resource("v3/registration/", "RegistrationsBaseUrl/3.0.0-rc"),
                    resource("v3/registration/", "RegistrationsBaseUrl/3.6.0"),
                    resource("v3/query", "SearchQueryService"),
                    resource("v3/query", "SearchQueryService/3.0.0-rc"),
                    resource("v3/query", "SearchQueryService/3.5.0"),
                ],
            }),
        )
    }

    /// Local, upstream and external versions of a package.
    async fn nuget_all_versions(&self, s: &Session, c: &Coordinates) -> (Vec<Version>, Vec<String>) {
        let (versions, externals) = self.listing(s, c);
        let mut remote = Vec::new();
        for src in externals {
            let Source::External { connection, .. } = src else { continue };
            let Some(base) = self.registry_url(&connection) else { continue };
            for v in external::nuget_versions(&base, &c.name).await {
                if !versions.iter().any(|x| x.version == v) && !remote.contains(&v) {
                    remote.push(v);
                }
            }
        }
        (versions, remote)
    }

    async fn nuget_versions(&self, s: &Session, id: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("nuget", None, id) else { return error("nuget", 404, "Not Found") };
        let (versions, remote) = self.nuget_all_versions(s, &c).await;
        let mut all: Vec<String> =
            versions.iter().filter(|v| listed(v) || v.status == "Unlisted").map(|v| v.version.clone()).collect();
        all.extend(remote);
        if all.is_empty() {
            return error("nuget", 404, "Not Found");
        }
        all.sort_by(|a, b| compare_versions(a, b));
        json(200, &json!({ "versions": all }))
    }

    async fn nuget_download(&self, s: &Session, id: &str, version: &str, file: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("nuget", None, id) else { return error("nuget", 404, "Not Found") };
        let version = normalize_version(version);
        let Some(v) = self.fetch_version(s, &c, &version).await else { return error("nuget", 404, "Not Found") };
        let Some(pkg) = v.asset(&nupkg_name(&c.name, &version)).or_else(|| v.assets.first()) else {
            return error("nuget", 404, "Not Found");
        };
        if file.ends_with(".nuspec") {
            return match nuspec(&pkg.content) {
                Some(x) => respond(200, "application/xml", x),
                None => error("nuget", 404, "Not Found"),
            };
        }
        respond(200, "application/octet-stream", pkg.content.clone())
    }

    fn catalog_entry(
        &self,
        s: &Session,
        c: &Coordinates,
        version: &str,
        entry: Option<&Value>,
        is_listed: bool,
    ) -> Value {
        let root = s.repo_url();
        let content = format!("{root}v3/package/{}/{version}/{}", c.name, nupkg_name(&c.name, version));
        let mut e = entry.cloned().unwrap_or_else(|| json!({ "id": c.name, "version": version }));
        e["@id"] = Value::String(format!("{root}v3/registration/{}/{version}.json", c.name));
        e["listed"] = Value::Bool(is_listed);
        e["packageContent"] = Value::String(content.clone());
        if e.get("dependencyGroups").is_none() {
            e["dependencyGroups"] = json!([]);
        }
        json!({
            "@id": format!("{root}v3/registration/{}/{version}.json", c.name),
            "catalogEntry": e,
            "packageContent": content,
            "registration": format!("{root}v3/registration/{}/index.json", c.name),
        })
    }

    async fn nuget_registration(&self, s: &Session, id: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("nuget", None, id) else { return error("nuget", 404, "Not Found") };
        let (versions, remote) = self.nuget_all_versions(s, &c).await;
        let mut items: Vec<(String, Value)> = versions
            .iter()
            .filter(|v| matches!(v.status.as_str(), "Published" | "Unlisted"))
            .map(|v| {
                (v.version.clone(), self.catalog_entry(s, &c, &v.version, v.meta.registry_metadata.as_ref(), listed(v)))
            })
            .collect();
        items.extend(remote.iter().map(|v| (v.clone(), self.catalog_entry(s, &c, v, None, true))));
        if items.is_empty() {
            return error("nuget", 404, "Not Found");
        }
        items.sort_by(|a, b| compare_versions(&a.0, &b.0));
        let root = s.repo_url();
        let index = format!("{root}v3/registration/{}/index.json", c.name);
        json(
            200,
            &json!({
                "@id": index,
                "count": 1,
                "items": [{
                    "@id": format!("{index}#page"),
                    "count": items.len(),
                    "lower": items.first().map(|i| i.0.clone()),
                    "upper": items.last().map(|i| i.0.clone()),
                    "items": items.into_iter().map(|i| i.1).collect::<Vec<_>>(),
                }],
            }),
        )
    }

    fn nuget_leaf(&self, s: &Session, id: &str, version: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("nuget", None, id) else { return error("nuget", 404, "Not Found") };
        let version = normalize_version(version);
        let (versions, _) = self.listing(s, &c);
        match versions.iter().find(|v| v.version == version) {
            Some(v) => json(200, &self.catalog_entry(s, &c, &version, v.meta.registry_metadata.as_ref(), listed(v))),
            None => error("nuget", 404, "Not Found"),
        }
    }

    fn nuget_search(&self, s: &Session, query: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let q = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("q="))
            .map(|q| percent_decode(&q.replace('+', " ")).to_ascii_lowercase())
            .unwrap_or_default();
        let root = s.repo_url();
        let data: Vec<Value> = self
            .with_domain(s, |d| {
                d.repositories
                    .get(&s.target.repo)
                    .map(|r| {
                        r.packages
                            .values()
                            .filter(|p| p.format == "nuget" && p.name.contains(&q))
                            .filter_map(|p| {
                                let mut vs: Vec<&Version> = p.versions.values().filter(|v| listed(v)).collect();
                                vs.sort_by(|a, b| compare_versions(&a.version, &b.version));
                                let latest = vs.last()?;
                                let id = latest
                                    .meta
                                    .registry_metadata
                                    .as_ref()
                                    .and_then(|m| m.get("id"))
                                    .and_then(Value::as_str)
                                    .unwrap_or(&p.name)
                                    .to_string();
                                Some(json!({
                                    "@id": format!("{root}v3/registration/{}/index.json", p.name),
                                    "id": id,
                                    "version": latest.version,
                                    "description": latest.meta.summary,
                                    "versions": vs.iter().map(|v| json!({ "version": v.version, "@id": format!("{root}v3/registration/{}/{}.json", p.name, v.version) })).collect::<Vec<_>>(),
                                }))
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        json(200, &json!({ "totalHits": data.len(), "data": data }))
    }

    fn nuget_push(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let content_type = request.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
        let body = match multipart::boundary(content_type) {
            Some(b) => match multipart::parse(request.body(), &b).into_iter().next() {
                Some(p) => p.data,
                None => return error("nuget", 400, "The push request has no package."),
            },
            None => request.body().to_vec(),
        };
        let Some((id, version, meta)) = nuspec(&body).as_deref().and_then(parse_nuspec) else {
            return error("nuget", 400, "The package is not a valid .nupkg (no .nuspec found).");
        };
        let Ok(c) = check_coordinates("nuget", None, &id) else { return error("nuget", 400, "Invalid package id.") };
        match self.publish_asset(s, &c, &version, Asset::new(nupkg_name(&id, &version), body), Some(meta), true, false)
        {
            Ok(_) => respond(201, "text/plain", ""),
            Err(r) => r,
        }
    }

    fn nuget_list(&self, s: &Session, id: &str, version: &str, status: &str) -> HttpResponse {
        let Ok(c) = check_coordinates("nuget", None, id) else { return error("nuget", 404, "Not Found") };
        match self.set_status(s, &c, &normalize_version(version), status) {
            Ok(true) => respond(204, "text/plain", ""),
            Ok(false) => error("nuget", 404, "Not Found"),
            Err(r) => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_normalize() {
        assert_eq!(normalize_version("1.0"), "1.0.0");
        assert_eq!(normalize_version("01.2.3.0+build"), "1.2.3");
        assert_eq!(normalize_version("1.2.3-Beta"), "1.2.3-beta");
    }

    #[test]
    fn nuspecs_parse() {
        let xml = r#"<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>Acme.Lib</id><version>1.0</version><authors>me</authors><description>d</description><dependencies><group targetFramework="net8.0"><dependency id="Newtonsoft.Json" version="13.0.1" /></group></dependencies></metadata></package>"#;
        let (id, v, m) = parse_nuspec(xml).unwrap();
        assert_eq!((id.as_str(), v.as_str()), ("Acme.Lib", "1.0.0"));
        assert_eq!(m.dependencies[0].package, "newtonsoft.json");
        assert_eq!(m.registry_metadata.unwrap()["dependencyGroups"][0]["targetFramework"], "net8.0");
    }
}
