//! The Maven repository layout Maven and Gradle deploy to and resolve
//! from. As in CodeArtifact, a version stays `Unfinished` while its files
//! upload and is published when the artifact's `maven-metadata.xml` that
//! lists it is uploaded; SNAPSHOT versions take new files at any time.

use mws_core::{HttpRequest, HttpResponse};
use sha2::Digest;

use super::{error, percent_decode, respond, Session};
use crate::names::{check_coordinates, compare_versions, Coordinates};
use crate::state::{Asset, Dependency, License, VersionMeta};
use crate::upstream::{self, listed, Source};
use crate::{external, packages, CodeArtifact};

const METADATA: &str = "maven-metadata.xml";
const CHECKSUMS: &[&str] = &["md5", "sha1", "sha256", "sha512"];

#[derive(Debug, PartialEq)]
enum Path {
    /// `<group>/<artifact>/maven-metadata.xml[.<checksum>]`
    ArtifactMetadata { group: String, artifact: String, checksum: Option<String> },
    /// `<group>/<artifact>/<version>/<file>[.<checksum>]`
    File { group: String, artifact: String, version: String, file: String, checksum: Option<String> },
}

fn split_checksum(file: &str) -> (String, Option<String>) {
    for c in CHECKSUMS {
        if let Some(base) = file.strip_suffix(&format!(".{c}")) {
            return (base.to_string(), Some(c.to_string()));
        }
    }
    (file.to_string(), None)
}

fn parse_path(rest: &str) -> Option<Path> {
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let n = segs.len();
    let (file, checksum) = split_checksum(segs.last()?);
    if file == METADATA && n >= 3 && !segs[n - 2].ends_with("-SNAPSHOT") {
        return Some(Path::ArtifactMetadata {
            group: segs[..n - 2].join("."),
            artifact: segs[n - 2].to_string(),
            checksum,
        });
    }
    if n < 4 {
        return None;
    }
    Some(Path::File {
        group: segs[..n - 3].join("."),
        artifact: segs[n - 3].to_string(),
        version: segs[n - 2].to_string(),
        file,
        checksum,
    })
}

fn checksum(kind: &str, data: &[u8]) -> String {
    match kind {
        "md5" => hex::encode(md5::Md5::digest(data)),
        "sha1" => hex::encode(sha1::Sha1::digest(data)),
        "sha256" => hex::encode(sha2::Sha256::digest(data)),
        _ => hex::encode(sha2::Sha512::digest(data)),
    }
}

fn content_type(file: &str) -> &'static str {
    if file.ends_with(".pom") || file.ends_with(".xml") {
        "text/xml"
    } else if file.ends_with(".jar") {
        "application/java-archive"
    } else if file.ends_with(".module") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn group_path(group: &str) -> String {
    group.replace('.', "/")
}

/// What CodeArtifact reports about a Maven version, from its POM.
fn meta_from_pom(pom: &[u8]) -> Option<VersionMeta> {
    let text = std::str::from_utf8(pom).ok()?;
    let doc = roxmltree::Document::parse(text).ok()?;
    let project = doc.root_element();
    fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
        n.children().find(|c| c.is_element() && c.tag_name().name() == name)
    }
    fn text_of(n: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
        child(n, name).and_then(|c| c.text()).map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
    }
    let licenses = child(project, "licenses")
        .map(|ls| {
            ls.children()
                .filter(|l| l.is_element())
                .map(|l| License { name: text_of(l, "name"), url: text_of(l, "url") })
                .collect()
        })
        .unwrap_or_default();
    let dependencies = child(project, "dependencies")
        .map(|ds| {
            ds.children()
                .filter(|d| d.is_element())
                .filter_map(|d| {
                    Some(Dependency {
                        namespace: text_of(d, "groupId"),
                        package: text_of(d, "artifactId")?,
                        dependency_type: text_of(d, "scope").unwrap_or_else(|| "compile".into()),
                        version_requirement: text_of(d, "version"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(VersionMeta {
        display_name: text_of(project, "name"),
        summary: text_of(project, "description"),
        home_page: text_of(project, "url"),
        source_code_repository: child(project, "scm").and_then(|s| text_of(s, "url")),
        licenses,
        readme: None,
        dependencies,
        npm_manifest: None,
        requires_python: None,
        registry_metadata: None,
    })
}

/// The versions a `maven-metadata.xml` lists.
fn listed_versions(xml: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(xml) else { return Vec::new() };
    let Ok(doc) = roxmltree::Document::parse(text) else { return Vec::new() };
    let mut out: Vec<String> = doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "version")
        .filter(|n| n.parent().is_some_and(|p| p.tag_name().name() == "versions"))
        .filter_map(|n| n.text().map(|t| t.trim().to_string()))
        .collect();
    // A single-version metadata (`<metadata><version>`) names it at the top.
    if out.is_empty() {
        if let Some(v) = doc.root_element().children().find(|c| c.is_element() && c.tag_name().name() == "version") {
            out.extend(v.text().map(|t| t.trim().to_string()));
        }
    }
    out
}

fn metadata_xml(group: &str, artifact: &str, versions: &[String], now: chrono::DateTime<chrono::Utc>) -> String {
    let latest = versions.last().cloned().unwrap_or_default();
    let release = versions.iter().rev().find(|v| !v.ends_with("-SNAPSHOT")).cloned().unwrap_or_default();
    let list: String = versions.iter().map(|v| format!("      <version>{v}</version>\n")).collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n  <versioning>\n    <latest>{latest}</latest>\n    <release>{release}</release>\n    <versions>\n{list}    </versions>\n    <lastUpdated>{}</lastUpdated>\n  </versioning>\n</metadata>\n",
        now.format("%Y%m%d%H%M%S")
    )
}

fn body_or_checksum(data: &[u8], file: &str, checksum_kind: Option<&str>) -> HttpResponse {
    match checksum_kind {
        Some(kind) => respond(200, "text/plain", checksum(kind, data)),
        None => respond(200, content_type(file), data.to_vec()),
    }
}

impl CodeArtifact {
    pub(crate) async fn serve_maven(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let rest = percent_decode(&s.target.rest);
        let Some(path) = parse_path(&rest) else { return error("maven", 404, "Not Found") };
        let method = request.method().as_str();
        let response = match method {
            "GET" | "HEAD" => self.maven_get(s, path).await,
            "PUT" => self.maven_put(s, path, request.body()),
            _ => error("maven", 405, "Method Not Allowed"),
        };
        if method == "HEAD" {
            let (mut parts, body) = response.into_parts();
            parts.headers.insert("content-length", http::HeaderValue::from(body.len()));
            return http::Response::from_parts(parts, bytes::Bytes::new());
        }
        response
    }

    async fn maven_get(&self, s: &Session, path: Path) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        match path {
            Path::ArtifactMetadata { group, artifact, checksum } => {
                let Ok(c) = check_coordinates("maven", Some(&group), &artifact) else {
                    return error("maven", 404, "Not Found");
                };
                let Some((versions, externals)) =
                    self.with_domain(s, |d| upstream::visible_versions(d, &s.target.repo, &c))
                else {
                    return error("maven", 404, "Not Found");
                };
                let mut list: Vec<String> = versions.iter().filter(|v| listed(v)).map(|v| v.version.clone()).collect();
                for src in externals {
                    let Source::External { connection, .. } = src else { continue };
                    let Some(base) = self.registry_url(&connection) else { continue };
                    let remote = format!("{}/{artifact}/{METADATA}", group_path(&group));
                    if let Some(xml) = external::maven_file(&base, &remote).await {
                        for v in listed_versions(&xml) {
                            if !list.contains(&v) {
                                list.push(v);
                            }
                        }
                    }
                }
                if list.is_empty() {
                    return error("maven", 404, "Not Found");
                }
                list.sort_by(|a, b| compare_versions(a, b));
                let xml = metadata_xml(&group, &artifact, &list, s.ctx.received_at);
                body_or_checksum(xml.as_bytes(), METADATA, checksum.as_deref())
            }
            Path::File { group, artifact, version, file, checksum } => {
                let Ok(c) = check_coordinates("maven", Some(&group), &artifact) else {
                    return error("maven", 404, "Not Found");
                };
                match self.maven_file(s, &c, &version, &file).await {
                    Some(data) => body_or_checksum(&data, &file, checksum.as_deref()),
                    None => error("maven", 404, "Not Found"),
                }
            }
        }
    }

    /// A file of a Maven version: from the repository, its upstreams, or
    /// (file by file, as Maven asks for them) its external connections.
    async fn maven_file(&self, s: &Session, c: &Coordinates, version: &str, file: &str) -> Option<Vec<u8>> {
        if let Some(a) = self.fetch_version(s, c, version).await.and_then(|v| v.asset(file).cloned()) {
            return Some(a.content);
        }
        let externals = self.with_domain(s, |d| {
            upstream::sources(d, &s.target.repo, c)
                .into_iter()
                .filter(|src| matches!(src, Source::External { .. }))
                .collect::<Vec<_>>()
        })?;
        let ns = c.namespace.as_deref().unwrap_or("");
        for src in externals {
            let Source::External { path, connection } = src else { continue };
            let Some(base) = self.registry_url(&connection) else { continue };
            let remote = format!("{}/{}/{version}/{file}", group_path(ns), c.name);
            let Some(data) = external::maven_file(&base, &remote).await else { continue };
            let now = s.ctx.received_at;
            self.with_domain_mut(s, |d| {
                let mut v = d
                    .repositories
                    .get(path.last().expect("non-empty"))
                    .and_then(|r| r.packages.get(&c.key()))
                    .and_then(|p| p.versions.get(version))
                    .cloned()
                    .unwrap_or_else(|| external::maven_version(version, &connection, now));
                if file.ends_with(".pom") {
                    if let Some(m) = meta_from_pom(&data) {
                        v.meta = m;
                    }
                }
                v.put_asset(Asset::new(file, data.clone()));
                for repo in &path {
                    if let Some(r) = d.repositories.get_mut(repo) {
                        let p = r.packages.entry(c.key()).or_insert_with(|| crate::state::Package {
                            format: c.format.clone(),
                            namespace: c.namespace.clone(),
                            name: c.name.clone(),
                            publish: "BLOCK".into(),
                            upstream: "ALLOW".into(),
                            ..Default::default()
                        });
                        p.versions.insert(version.to_string(), v.clone());
                    }
                }
            });
            return Some(data);
        }
        None
    }

    fn maven_put(&self, s: &Session, path: Path, body: &[u8]) -> HttpResponse {
        let (group, artifact) = match &path {
            Path::ArtifactMetadata { group, artifact, .. } | Path::File { group, artifact, .. } => (group, artifact),
        };
        let Ok(c) = check_coordinates("maven", Some(group), artifact) else {
            return error("maven", 400, "Invalid Maven coordinates.");
        };
        if let Err(r) = self.authorize_publish(s, &c) {
            return r;
        }
        let created = respond(201, "text/plain", "");
        match path {
            // Clients upload checksums next to every file; CodeArtifact
            // computes its own.
            Path::ArtifactMetadata { checksum: Some(_), .. } | Path::File { checksum: Some(_), .. } => created,
            Path::ArtifactMetadata { .. } => {
                let versions = listed_versions(body);
                let now = s.ctx.received_at;
                self.with_domain_mut(s, |d| {
                    if let Some(p) = d.repositories.get_mut(&s.target.repo).and_then(|r| r.packages.get_mut(&c.key())) {
                        for v in versions {
                            if let Some(v) = p.versions.get_mut(&v).filter(|v| v.status == "Unfinished") {
                                v.status = "Published".into();
                                v.published = now;
                            }
                        }
                    }
                });
                created
            }
            Path::File { version, file, .. } => {
                let snapshot = version.ends_with("-SNAPSHOT");
                let meta = if file.ends_with(".pom") { meta_from_pom(body) } else { None };
                let now = s.ctx.received_at;
                let result = self.with_domain_mut(s, |d| {
                    let existing = d
                        .repositories
                        .get(&s.target.repo)
                        .and_then(|r| r.packages.get(&c.key()))
                        .and_then(|p| p.versions.get(&version))
                        .map(|v| v.meta.clone());
                    let meta = meta.or(existing);
                    packages::publish(
                        d,
                        &s.target.repo,
                        &c,
                        &version,
                        Asset::new(file, body.to_vec()),
                        meta,
                        false,
                        now,
                        snapshot,
                    )
                });
                match result {
                    Some(Ok(_)) => created,
                    Some(Err(e)) => error("maven", e.status, &e.message),
                    None => error("maven", 404, "Not Found"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_parse() {
        assert_eq!(
            parse_path("com/example/lib/maven-metadata.xml.sha1"),
            Some(Path::ArtifactMetadata {
                group: "com.example".into(),
                artifact: "lib".into(),
                checksum: Some("sha1".into())
            })
        );
        assert_eq!(
            parse_path("com/example/lib/1.0/lib-1.0.jar"),
            Some(Path::File {
                group: "com.example".into(),
                artifact: "lib".into(),
                version: "1.0".into(),
                file: "lib-1.0.jar".into(),
                checksum: None
            })
        );
        assert!(matches!(parse_path("com/example/lib/1.0-SNAPSHOT/maven-metadata.xml"), Some(Path::File { .. })));
    }

    #[test]
    fn metadata_lists_versions() {
        let xml = metadata_xml("g", "a", &["1.0".into(), "1.1".into()], chrono::Utc::now());
        assert_eq!(listed_versions(xml.as_bytes()), vec!["1.0", "1.1"]);
        let pom = b"<project><name>Lib</name><description>d</description><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency></dependencies></project>";
        let m = meta_from_pom(pom).unwrap();
        assert_eq!(m.summary.as_deref(), Some("d"));
        assert_eq!(m.dependencies[0].dependency_type, "compile");
    }
}
