//! The PyPI protocols: the simple repository API (PEP 503) pip installs
//! from and the upload API twine publishes with.

use mws_core::{HttpRequest, HttpResponse};

use super::{error, multipart, percent_decode, respond, Session};
use crate::names::{check_coordinates, normalize_pypi};
use crate::state::{Asset, Dependency, License, VersionMeta};
use crate::upstream::{self, listed, Source};
use crate::{external, packages, CodeArtifact};

/// The version in a distribution's file name, for project `project`
/// (normalized).
pub fn version_of(filename: &str, project: &str) -> Option<String> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        let name = parts.next()?;
        return (normalize_pypi(name) == project).then(|| parts.next().map(str::to_string)).flatten();
    }
    let stem =
        [".tar.gz", ".zip", ".tar.bz2", ".tgz", ".tar.xz", ".egg"].iter().find_map(|ext| filename.strip_suffix(ext))?;
    let stem = stem.split("-py").next().unwrap_or(stem);
    for (i, _) in stem.match_indices('-') {
        if normalize_pypi(&stem[..i]) == project {
            return Some(stem[i + 1..].to_string());
        }
    }
    None
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// `Requires-Dist` entries as dependencies.
fn dependencies(requires: &[String]) -> Vec<Dependency> {
    requires
        .iter()
        .filter_map(|r| {
            let end = r.find(|c: char| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))).unwrap_or(r.len());
            let name = r[..end].trim();
            if name.is_empty() {
                return None;
            }
            let rest = r[end..].split(';').next().unwrap_or("").trim();
            let rest = rest.trim_start_matches('[').split(']').next_back().unwrap_or("").trim();
            let rest = rest.trim_start_matches('(').trim_end_matches(')').trim();
            Some(Dependency {
                namespace: None,
                package: normalize_pypi(name),
                dependency_type: "install".into(),
                version_requirement: (!rest.is_empty()).then(|| rest.to_string()),
            })
        })
        .collect()
}

impl CodeArtifact {
    pub(crate) async fn serve_pypi(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let rest = percent_decode(&s.target.rest);
        let method = request.method().as_str();
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        match (method, parts.as_slice()) {
            ("POST", [] | ["legacy"]) => self.pypi_upload(s, request).await,
            ("GET" | "HEAD", ["simple"]) => self.pypi_projects(s),
            ("GET" | "HEAD", ["simple", project]) => self.pypi_index(s, project).await,
            ("GET" | "HEAD", ["simple", project, version, file]) => self.pypi_download(s, project, version, file).await,
            _ => error("pypi", 404, "Not Found"),
        }
    }

    fn pypi_projects(&self, s: &Session) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let names = self
            .with_domain(s, |d| {
                d.repositories
                    .get(&s.target.repo)
                    .map(|r| {
                        r.packages.values().filter(|p| p.format == "pypi").map(|p| p.name.clone()).collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let mut html = String::from("<!DOCTYPE html>\n<html><head><title>Simple Index</title></head><body>\n");
        for n in names {
            html.push_str(&format!("<a href=\"{n}/\">{n}</a><br/>\n", n = escape(&n)));
        }
        html.push_str("</body></html>\n");
        respond(200, "text/html; charset=utf-8", html)
    }

    async fn pypi_index(&self, s: &Session, project: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("pypi", None, project) else { return error("pypi", 404, "Not Found") };
        let Some((versions, externals)) = self.with_domain(s, |d| upstream::visible_versions(d, &s.target.repo, &c))
        else {
            return error("pypi", 404, "Not Found");
        };
        let base = format!("{}simple/{}/", s.repo_url(), c.name);
        let mut links = Vec::new();
        let mut files = std::collections::BTreeSet::new();
        for v in versions.iter().filter(|v| listed(v)) {
            for a in &v.assets {
                files.insert(a.name.clone());
                let rp = v
                    .meta
                    .requires_python
                    .as_ref()
                    .map(|r| format!(" data-requires-python=\"{}\"", escape(r)))
                    .unwrap_or_default();
                links.push(format!(
                    "<a href=\"{base}{}/{}#sha256={}\"{rp}>{}</a><br/>",
                    escape(&v.version),
                    escape(&a.name),
                    a.sha256(),
                    escape(&a.name)
                ));
            }
        }
        for src in externals {
            let Source::External { connection, .. } = src else { continue };
            let Some(registry) = self.registry_url(&connection) else { continue };
            for (filename, _) in external::pypi_files(&registry, &c.name).await {
                if files.contains(&filename) {
                    continue;
                }
                let Some(version) = version_of(&filename, &c.name) else { continue };
                files.insert(filename.clone());
                links.push(format!(
                    "<a href=\"{base}{}/{}\">{}</a><br/>",
                    escape(&version),
                    escape(&filename),
                    escape(&filename)
                ));
            }
        }
        if links.is_empty() {
            return error("pypi", 404, "Not Found");
        }
        let html = format!(
            "<!DOCTYPE html>\n<html><head><title>Links for {n}</title></head><body>\n<h1>Links for {n}</h1>\n{}\n</body></html>\n",
            links.join("\n"),
            n = escape(&c.name)
        );
        respond(200, "text/html; charset=utf-8", html)
    }

    async fn pypi_download(&self, s: &Session, project: &str, version: &str, file: &str) -> HttpResponse {
        if let Err(r) = self.authorize_read(s) {
            return r;
        }
        let Ok(c) = check_coordinates("pypi", None, project) else { return error("pypi", 404, "Not Found") };
        match self.fetch_version(s, &c, version).await.and_then(|v| v.asset(file).cloned()) {
            Some(a) => respond(200, "application/octet-stream", a.content),
            None => error("pypi", 404, "Not Found"),
        }
    }

    #[allow(clippy::result_large_err)]
    async fn pypi_upload(&self, s: &Session, request: &HttpRequest) -> HttpResponse {
        let content_type = request.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
        let Some(boundary) = multipart::boundary(content_type) else {
            return error("pypi", 400, "Uploads must be multipart/form-data.");
        };
        let parts = multipart::parse(request.body(), &boundary);
        let field = |n: &str| parts.iter().find(|p| p.name == n && p.filename.is_none()).map(|p| p.text());
        let fields = |n: &str| parts.iter().filter(|p| p.name == n).map(|p| p.text()).collect::<Vec<_>>();
        if field(":action").as_deref() != Some("file_upload") {
            return error("pypi", 400, "Unsupported action.");
        }
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            return error("pypi", 400, "The upload is missing the name or version.");
        };
        let Some(file) = parts.iter().find(|p| p.name == "content" && p.filename.is_some()) else {
            return error("pypi", 400, "The upload has no file.");
        };
        let filename = file.filename.clone().unwrap_or_default();
        let Ok(c) = check_coordinates("pypi", None, &name) else { return error("pypi", 400, "Invalid project name.") };
        if version_of(&filename, &c.name).as_deref() != Some(version.as_str()) {
            return error(
                "pypi",
                400,
                &format!("The file name '{filename}' does not match project {name} version {version}."),
            );
        }
        if let Some(sha) = field("sha256_digest").filter(|d| !d.is_empty()) {
            use sha2::Digest;
            if !hex::encode(sha2::Sha256::digest(&file.data)).eq_ignore_ascii_case(&sha) {
                return error("pypi", 400, "The SHA256 digest does not match the uploaded file.");
            }
        }
        if let Err(r) = self.authorize_publish(s, &c) {
            return r;
        }
        let license = field("license").filter(|l| !l.is_empty());
        let meta = VersionMeta {
            display_name: Some(name.clone()),
            summary: field("summary").filter(|v| !v.is_empty()),
            home_page: field("home_page").filter(|v| !v.is_empty()),
            source_code_repository: None,
            licenses: license.map(|l| vec![License { name: Some(l), url: None }]).unwrap_or_default(),
            readme: field("description").filter(|v| !v.is_empty()),
            dependencies: dependencies(&fields("requires_dist")),
            npm_manifest: None,
            requires_python: field("requires_python").filter(|v| !v.is_empty()),
        };
        let content = file.data.clone();
        let now = s.ctx.received_at;
        let result = self.with_domain_mut(s, |d| {
            let exists = d
                .repositories
                .get(&s.target.repo)
                .and_then(|r| r.packages.get(&c.key()))
                .and_then(|p| p.versions.get(&version))
                .is_some_and(|v| v.asset(&filename).is_some());
            if exists {
                return Err(error("pypi", 409, &format!("File already exists: '{filename}'")));
            }
            packages::publish(
                d,
                &s.target.repo,
                &c,
                &version,
                Asset::new(filename.clone(), content),
                Some(meta),
                true,
                now,
                true,
            )
            .map_err(|e| error("pypi", e.status, &e.message))
        });
        match result {
            Some(Ok(_)) => respond(200, "text/plain", "OK"),
            Some(Err(r)) => r,
            None => error("pypi", 404, "Not Found"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_from_file_names() {
        assert_eq!(version_of("my_pkg-1.2.0-py3-none-any.whl", "my-pkg").as_deref(), Some("1.2.0"));
        assert_eq!(version_of("my-pkg-1.2.0.tar.gz", "my-pkg").as_deref(), Some("1.2.0"));
        assert_eq!(version_of("other-1.0.tar.gz", "my-pkg"), None);
    }

    #[test]
    fn requires_dist_parses() {
        let d = dependencies(&["requests (>=2.0)".into(), "Foo_Bar[x]>=1; python_version<'3.9'".into()]);
        assert_eq!(d[0].package, "requests");
        assert_eq!(d[0].version_requirement.as_deref(), Some(">=2.0"));
        assert_eq!(d[1].package, "foo-bar");
        assert_eq!(d[1].version_requirement.as_deref(), Some(">=1"));
    }
}
