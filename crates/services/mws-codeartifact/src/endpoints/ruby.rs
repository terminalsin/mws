//! The RubyGems protocol: the compact index (`versions`, `info/<gem>`,
//! `names`) Bundler and `gem` resolve from, gem downloads, and `gem push`.

use std::io::Read;

use md5::Digest as _;
use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Value};
use yaml_rust2::{Yaml, YamlLoader};

use super::{error, percent_decode, respond, Session};
use crate::names::{check_coordinates, compare_versions};
use crate::state::{Asset, Dependency, License, Version, VersionMeta};
use crate::upstream::{listed, Source};
use crate::{external, CodeArtifact};

/// The files of a tar archive (ustar, as `gem build` writes them).
pub fn tar_entries(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 512 <= data.len() {
        let header = &data[at..at + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let field = |r: std::ops::Range<usize>| {
            let f = &header[r];
            String::from_utf8_lossy(&f[..f.iter().position(|b| *b == 0).unwrap_or(f.len())]).into_owned()
        };
        let mut name = field(0..100);
        let prefix = field(345..500);
        if header[257..262] == *b"ustar" && !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let size = usize::from_str_radix(field(124..136).trim(), 8).unwrap_or(0);
        let start = at + 512;
        let Some(content) = data.get(start..start + size) else { break };
        if matches!(header[156], b'0' | 0) {
            out.push((name, content.to_vec()));
        }
        at = start + size.div_ceil(512) * 512;
    }
    out
}

fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data).read_to_end(&mut out).ok()?;
    Some(out)
}

/// A gem's version with its platform, as the compact index names it
/// (`1.0.0` or `1.0.0-x86_64-linux`).
fn full_version(version: &str, platform: &str) -> String {
    if platform.is_empty() || platform == "ruby" {
        version.to_string()
    } else {
        format!("{version}-{platform}")
    }
}

fn requirements(r: &Yaml) -> String {
    let reqs: Vec<String> = r["requirements"]
        .as_vec()
        .into_iter()
        .flatten()
        .filter_map(|pair| {
            let op = pair[0].as_str()?;
            let v = &pair[1]["version"];
            let v = v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string()))?;
            Some(format!("{op} {v}"))
        })
        .collect();
    reqs.join("&")
}

/// A gem's specification, from the `metadata.gz` YAML inside the `.gem`:
/// `(name, full version, metadata)`. The registry metadata holds the
/// compact index line's dependencies and requirements.
pub fn parse_gem(gem: &[u8]) -> Option<(String, String, VersionMeta)> {
    let metadata = tar_entries(gem).into_iter().find(|(n, _)| n == "metadata.gz")?.1;
    let yaml = String::from_utf8(gunzip(&metadata)?).ok()?;
    let doc = YamlLoader::load_from_str(&yaml).ok()?.into_iter().next()?;
    let s = |y: &Yaml| y.as_str().map(str::to_string).filter(|s| !s.is_empty());
    let name = s(&doc["name"])?;
    let version = &doc["version"]["version"];
    let version = s(version).or_else(|| version.as_f64().map(|f| f.to_string()))?;
    let platform = s(&doc["platform"]).unwrap_or_else(|| "ruby".into());
    let mut deps = Vec::new();
    let mut dependencies = Vec::new();
    for d in doc["dependencies"].as_vec().into_iter().flatten() {
        let Some(dep) = s(&d["name"]) else { continue };
        let kind = s(&d["type"]).unwrap_or_else(|| ":runtime".into()).trim_start_matches(':').to_string();
        let req = requirements(&d["requirement"]);
        if kind == "runtime" {
            deps.push(format!("{dep}:{req}"));
        }
        dependencies.push(Dependency {
            namespace: None,
            package: dep,
            dependency_type: kind,
            version_requirement: (!req.is_empty()).then_some(req),
        });
    }
    let ruby = requirements(&doc["required_ruby_version"]);
    let rubygems = requirements(&doc["required_rubygems_version"]);
    let licenses = doc["licenses"].as_vec().into_iter().flatten().map(|l| License { name: s(l), url: None }).collect();
    let meta = VersionMeta {
        display_name: Some(name.clone()),
        summary: s(&doc["summary"]),
        home_page: s(&doc["homepage"]),
        source_code_repository: s(&doc["metadata"]["source_code_uri"]),
        licenses,
        readme: s(&doc["description"]),
        dependencies,
        registry_metadata: Some(json!({
            "platform": platform,
            "dependencies": deps,
            "ruby": ruby,
            "rubygems": rubygems,
        })),
        ..Default::default()
    };
    Some((name, full_version(&version, &platform), meta))
}

/// The compact index line of a version (`<version> <deps>|checksum:<sha256>,...`).
fn info_line(v: &Version) -> String {
    let m = v.meta.registry_metadata.clone().unwrap_or(Value::Null);
    let deps: Vec<&str> = m["dependencies"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut line = format!(
        "{} {}|checksum:{}",
        v.version,
        deps.join(","),
        v.assets.first().map(Asset::sha256).unwrap_or_default()
    );
    for (key, field) in [("ruby", "ruby"), ("rubygems", "rubygems")] {
        if let Some(r) = m[field].as_str().filter(|r| !r.is_empty() && *r != ">= 0") {
            line.push_str(&format!(",{key}:{r}"));
        }
    }
    line
}

/// The compact index line of an ingested version (from the registry's
/// own `info` file).
pub fn meta_from_info(line: &str) -> VersionMeta {
    let (_, rest) = line.split_once(' ').unwrap_or((line, ""));
    let (deps, reqs) = rest.split_once('|').unwrap_or((rest, ""));
    let deps: Vec<String> = deps.split(',').filter(|d| !d.is_empty()).map(str::to_string).collect();
    let req = |k: &str| reqs.split(',').find_map(|r| r.strip_prefix(&format!("{k}:"))).unwrap_or("").to_string();
    VersionMeta {
        dependencies: deps
            .iter()
            .map(|d| {
                let (name, req) = d.split_once(':').unwrap_or((d, ""));
                Dependency {
                    namespace: None,
                    package: name.to_string(),
                    dependency_type: "runtime".into(),
                    version_requirement: (!req.is_empty()).then(|| req.to_string()),
                }
            })
            .collect(),
        registry_metadata: Some(json!({ "dependencies": deps, "ruby": req("ruby"), "rubygems": req("rubygems") })),
        ..Default::default()
    }
}

impl CodeArtifact {
    pub(crate) async fn serve_ruby(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let rest = percent_decode(&s.target.rest);
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        let method = request.method().as_str();
        match (method, parts.as_slice()) {
            ("GET" | "HEAD", []) => match self.authorize_read(s) {
                Ok(()) => respond(200, "text/plain", ""),
                Err(r) => r,
            },
            ("GET" | "HEAD", ["versions"]) => self.ruby_versions(s),
            ("GET" | "HEAD", ["names"]) => self.ruby_names(s),
            ("GET" | "HEAD", ["info", gem]) => self.ruby_info(s, gem).await,
            ("GET" | "HEAD", ["gems", file]) => self.ruby_download(s, file).await,
            ("POST", ["api", "v1", "gems"]) => self.ruby_push(s, request.body()),
            _ => error("ruby", 404, "Not Found"),
        }
    }

    /// The gems in the session's repository, with their listed versions.
    fn ruby_gems(&self, s: &Session) -> Vec<(String, Vec<Version>)> {
        self.with_domain(s, |d| {
            d.repositories
                .get(&s.target.repo)
                .map(|r| {
                    r.packages
                        .values()
                        .filter(|p| p.format == "ruby")
                        .map(|p| {
                            let mut vs: Vec<Version> = p.versions.values().filter(|v| listed(v)).cloned().collect();
                            vs.sort_by(|a, b| {
                                a.published.cmp(&b.published).then(compare_versions(&a.version, &b.version))
                            });
                            (p.name.clone(), vs)
                        })
                        .filter(|(_, vs)| !vs.is_empty())
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default()
    }

    fn info_body(versions: &[Version]) -> String {
        let mut body = String::from("---\n");
        for v in versions {
            body.push_str(&info_line(v));
            body.push('\n');
        }
        body
    }

    fn ruby_versions(&self, s: &Session) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let mut body = format!("created_at: {}\n---\n", s.ctx.received_at.format("%Y-%m-%dT%H:%M:%SZ"));
        for (name, versions) in self.ruby_gems(s) {
            let list: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
            let md5 = hex::encode(md5::Md5::digest(Self::info_body(&versions).as_bytes()));
            body.push_str(&format!("{name} {} {md5}\n", list.join(",")));
        }
        respond(200, "text/plain; charset=utf-8", body)
    }

    fn ruby_names(&self, s: &Session) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let mut body = String::from("---\n");
        for (name, _) in self.ruby_gems(s) {
            body.push_str(&name);
            body.push('\n');
        }
        respond(200, "text/plain; charset=utf-8", body)
    }

    async fn ruby_info(&self, s: &Session, gem: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("ruby", None, gem) else { return error("ruby", 404, "Not Found") };
        let (mut versions, externals) = self.listing(s, &c);
        versions.retain(listed);
        versions.sort_by(|a, b| a.published.cmp(&b.published).then(compare_versions(&a.version, &b.version)));
        let mut body = Self::info_body(&versions);
        let mut found = !versions.is_empty();
        for src in externals {
            let Source::External { connection, .. } = src else { continue };
            let Some(base) = self.registry_url(&connection) else { continue };
            for line in external::ruby_info(&base, &c.name).await {
                let v = line.split(' ').next().unwrap_or_default();
                if !versions.iter().any(|x| x.version == v) {
                    body.push_str(&line);
                    body.push('\n');
                    found = true;
                }
            }
        }
        if !found {
            return error("ruby", 404, "Not Found");
        }
        respond(200, "text/plain; charset=utf-8", body)
    }

    async fn ruby_download(&self, s: &Session, file: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Some(stem) = file.strip_suffix(".gem") else { return error("ruby", 404, "Not Found") };
        // `<name>-<version>[-<platform>]`: names may contain `-`, versions
        // start with a digit.
        let split =
            stem.match_indices('-').map(|(i, _)| i).find(|i| stem[i + 1..].starts_with(|c: char| c.is_ascii_digit()));
        let Some(i) = split else { return error("ruby", 404, "Not Found") };
        let (name, version) = (&stem[..i], &stem[i + 1..]);
        let Ok(c) = check_coordinates("ruby", None, name) else { return error("ruby", 404, "Not Found") };
        match self.fetch_version(s, &c, version).await.and_then(|v| v.assets.first().cloned()) {
            Some(a) => respond(200, "application/octet-stream", a.content),
            None => error("ruby", 404, "Not Found"),
        }
    }

    fn ruby_push(&self, s: &Session, body: &[u8]) -> HttpResponse {
        let Some((name, version, meta)) = parse_gem(body) else {
            return error("ruby", 422, "RubyGems.org cannot process this gem.\nThe metadata is invalid.");
        };
        let Ok(c) = check_coordinates("ruby", None, &name) else { return error("ruby", 422, "Invalid gem name.") };
        let asset = Asset::new(format!("{name}-{version}.gem"), body.to_vec());
        match self.publish_asset(s, &c, &version, asset, Some(meta), true, false) {
            Ok(_) => respond(200, "text/plain", format!("Successfully registered gem: {name} ({version})")),
            Err(r) if r.status() == 409 => error(
                "ruby",
                409,
                &format!(
                    "Repushing of gem versions is not allowed.\nPlease bump the version number: {name} ({version})"
                ),
            ),
            Err(r) => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_lines_parse() {
        let m = meta_from_info("1.2.0 rack:>= 1.0&< 3,json:>= 0|checksum:abc,ruby:>= 2.7");
        assert_eq!(m.dependencies.len(), 2);
        assert_eq!(m.dependencies[0].version_requirement.as_deref(), Some(">= 1.0&< 3"));
        assert_eq!(m.registry_metadata.unwrap()["ruby"], ">= 2.7");
    }

    #[test]
    fn platforms_join_versions() {
        assert_eq!(full_version("1.0.0", "ruby"), "1.0.0");
        assert_eq!(full_version("1.0.0", "x86_64-linux"), "1.0.0-x86_64-linux");
    }
}
