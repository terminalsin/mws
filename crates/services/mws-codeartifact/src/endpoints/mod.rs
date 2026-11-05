//! Repository endpoints: the URLs `GetRepositoryEndpoint` returns, serving
//! the npm registry, PyPI (simple index and uploads) and Maven repository
//! protocols.
//!
//! AWS serves them at `https://<domain>-<owner>.d.codeartifact.<region>.amazonaws.com/<format>/<repo>/`.
//! MWS answers requests for that host (with a resolver pointing it at MWS,
//! or `Host` set) and, as `GetRepositoryEndpoint` hands out, at
//! `<endpoint>/_aws/codeartifact/<region>/<domain>-<owner>/<format>/<repo>/`.
//!
//! Requests authenticate with a token from `GetAuthorizationToken`, sent
//! as `Authorization: Bearer <token>` (npm) or as the password of basic
//! authentication with user `aws` (pip, twine, Maven, Gradle). They act as
//! the principal that asked for the token: reads need
//! `codeartifact:ReadFromRepository` on the repository, publishing
//! `codeartifact:PublishPackageVersion` on the package, both evaluated
//! with the repository's policy.

pub(crate) mod maven;
mod multipart;
pub(crate) mod npm;
pub(crate) mod pypi;

use base64::Engine;
use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext};

use crate::names::{self, Coordinates};
use crate::state::{Domain, Version};
use crate::upstream::{self, Lookup, Source};
use crate::{external, CodeArtifact};

const PATH_PREFIX: &str = "/_aws/codeartifact/";

/// A request for a repository endpoint.
#[derive(Debug, Clone)]
pub struct Target {
    pub region: String,
    pub owner: String,
    pub domain: String,
    pub format: String,
    pub repo: String,
    /// The rest of the path, after `<format>/<repo>/`, still percent-encoded.
    pub rest: String,
}

/// Split `<domain>-<owner>`: the owner is the 12-digit account id.
fn split_domain_owner(s: &str) -> Option<(String, String)> {
    let (domain, owner) = s.rsplit_once('-')?;
    (owner.len() == 12 && owner.bytes().all(|b| b.is_ascii_digit()) && !domain.is_empty())
        .then(|| (domain.to_string(), owner.to_string()))
}

fn format_and_repo(path: &str) -> Option<(String, String, String)> {
    let path = path.trim_start_matches('/');
    let mut parts = path.splitn(3, '/');
    let format = parts.next()?;
    let repo = parts.next()?;
    if !names::FORMATS.contains(&format) || repo.is_empty() {
        return None;
    }
    Some((format.to_string(), repo.to_string(), parts.next().unwrap_or("").to_string()))
}

pub fn target(request: &HttpRequest) -> Option<Target> {
    let path = request.uri().path();
    if let Some(rest) = path.strip_prefix(PATH_PREFIX) {
        let (region, rest) = rest.split_once('/')?;
        let (domain_owner, rest) = rest.split_once('/')?;
        let (domain, owner) = split_domain_owner(domain_owner)?;
        let (format, repo, rest) = format_and_repo(rest)?;
        return Some(Target { region: region.to_string(), owner, domain, format, repo, rest });
    }
    let host = request.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    let (label, rest) = host.split_once(".d.codeartifact.")?;
    let region = rest.strip_suffix(".amazonaws.com").or_else(|| rest.strip_suffix(".amazonaws.com.cn"))?;
    let (domain, owner) = split_domain_owner(label)?;
    let (format, repo, rest) = format_and_repo(path)?;
    Some(Target { region: region.to_string(), owner, domain, format, repo, rest })
}

/// The URL of a repository's endpoint for `format`.
pub fn repository_url(ctx: &RequestContext, owner: &str, domain: &str, format: &str, repo: &str) -> String {
    match &ctx.endpoint {
        Some(e) => format!("{}{PATH_PREFIX}{}/{domain}-{owner}/{format}/{repo}/", e.trim_end_matches('/'), ctx.region),
        None => format!("https://{domain}-{owner}.d.codeartifact.{}.amazonaws.com/{format}/{repo}/", ctx.region),
    }
}

pub(crate) fn respond(status: u16, content_type: &str, body: impl Into<Bytes>) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(body.into())
        .expect("valid response")
}

pub(crate) fn json(status: u16, value: &serde_json::Value) -> HttpResponse {
    respond(status, "application/json", value.to_string())
}

pub(crate) fn text(status: u16, message: &str) -> HttpResponse {
    respond(status, "text/plain; charset=utf-8", message.to_string())
}

/// An error in the shape the format's clients show.
pub(crate) fn error(format: &str, status: u16, message: &str) -> HttpResponse {
    if format == "npm" {
        json(status, &serde_json::json!({ "error": message }))
    } else {
        text(status, message)
    }
}

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn bearer_or_basic(request: &HttpRequest) -> Option<String> {
    let value = request.headers().get(http::header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(rest.trim().to_string());
    }
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = base64::engine::general_purpose::STANDARD.decode(rest.trim()).ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        return decoded.split_once(':').map(|(_, p)| p.to_string());
    }
    None
}

fn unauthorized(t: &Target, message: &str) -> HttpResponse {
    let mut r = error(&t.format, 401, message);
    let realm = format!("Basic realm=\"{}/{}\"", t.domain, t.owner);
    r.headers_mut().insert("www-authenticate", http::HeaderValue::from_str(&realm).expect("ascii"));
    r
}

/// Who a package request acts as, and in which repository.
pub(crate) struct Session {
    pub ctx: RequestContext,
    pub target: Target,
}

impl Session {
    pub fn domain_key(&self) -> String {
        crate::state::domain_key(&self.target.region, &self.target.owner, &self.target.domain)
    }

    pub fn repo_url(&self) -> String {
        repository_url(&self.ctx, &self.target.owner, &self.target.domain, &self.target.format, &self.target.repo)
    }

    pub fn package_arn(&self, c: &Coordinates) -> String {
        names::package_arn(
            &self.ctx.partition,
            &self.ctx.region,
            &self.target.owner,
            &self.target.domain,
            &self.target.repo,
            &c.format,
            c.namespace.as_deref(),
            &c.name,
        )
    }
}

impl CodeArtifact {
    pub(crate) async fn serve_endpoint(&self, ctx: RequestContext, request: HttpRequest, t: Target) -> HttpResponse {
        let Some(token) = bearer_or_basic(&request) else {
            return unauthorized(&t, "Unauthorized");
        };
        let key = crate::state::domain_key(&t.region, &t.owner, &t.domain);
        let caller = {
            let st = self.read();
            match st.tokens.get(&token) {
                Some(tok) if tok.domain == key && tok.expires > ctx.received_at => Some(tok.caller.clone()),
                _ => None,
            }
        };
        let Some(caller) = caller else {
            return unauthorized(&t, "The security token included in the request is invalid or expired.");
        };
        let mut ctx = ctx;
        ctx.caller = caller;
        ctx.region = t.region.clone();
        {
            let st = self.read();
            let Some(d) = st.domains.get(&key) else { return error(&t.format, 404, "Domain not found") };
            if !d.repositories.contains_key(&t.repo) {
                return error(&t.format, 404, "Repository not found");
            }
        }
        let session = Session { ctx, target: t };
        match session.target.format.as_str() {
            "npm" => self.serve_npm(&session, &request).await,
            "pypi" => self.serve_pypi(&session, &request).await,
            "maven" => self.serve_maven(&session, &request).await,
            f => error(f, 404, &format!("Repository endpoints for {f} packages are not supported by MWS.")),
        }
    }

    /// Authorize reading from the session's repository.
    #[allow(clippy::result_large_err)]
    pub(crate) fn authorize_read(&self, s: &Session) -> Result<(), HttpResponse> {
        self.authorize_repo(
            &s.ctx,
            &s.target.owner,
            &s.target.domain,
            &s.target.repo,
            "codeartifact:ReadFromRepository",
            None,
        )
        .map_err(|e| error(&s.target.format, 403, &e.message))
    }

    /// Authorize publishing a package to the session's repository.
    #[allow(clippy::result_large_err)]
    pub(crate) fn authorize_publish(&self, s: &Session, c: &Coordinates) -> Result<(), HttpResponse> {
        let arn = s.package_arn(c);
        self.authorize_repo(
            &s.ctx,
            &s.target.owner,
            &s.target.domain,
            &s.target.repo,
            "codeartifact:PublishPackageVersion",
            Some(&arn),
        )
        .map_err(|e| error(&s.target.format, 403, &e.message))
    }

    pub(crate) fn with_domain<T>(&self, s: &Session, f: impl FnOnce(&Domain) -> T) -> Option<T> {
        let st = self.read();
        st.domains.get(&s.domain_key()).map(f)
    }

    pub(crate) fn with_domain_mut<T>(&self, s: &Session, f: impl FnOnce(&mut Domain) -> T) -> Option<T> {
        let mut st = self.write();
        st.domains.get_mut(&s.domain_key()).map(f)
    }

    /// A version a package manager asked for, found in the repository or
    /// through its upstreams and external connections (and then kept in
    /// the repositories it passed through, as AWS does).
    pub(crate) async fn fetch_version(&self, s: &Session, c: &Coordinates, version: &str) -> Option<Version> {
        let lookup = self.with_domain(s, |d| upstream::lookup(d, &s.target.repo, c, version))?;
        let externals = match lookup {
            Lookup::Found { version, retain_in } => {
                if !retain_in.is_empty() {
                    self.with_domain_mut(s, |d| upstream::retain(d, &retain_in, c, &version));
                }
                return Some(*version);
            }
            Lookup::External(e) => e,
        };
        for source in externals {
            let Source::External { path, connection } = source else { continue };
            let Some(base) = self.registry_url(&connection) else { continue };
            let now = s.ctx.received_at;
            let ingested = match c.format.as_str() {
                "npm" => external::npm_version(&base, &connection, c.namespace.as_deref(), &c.name, version, now).await,
                "pypi" => external::pypi_version(&base, &connection, &c.name, version, now).await,
                _ => None,
            };
            if let Some(v) = ingested {
                self.with_domain_mut(s, |d| upstream::retain(d, &path, c, &v));
                return Some(v);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host: &str, path: &str) -> HttpRequest {
        http::Request::builder().uri(path).header("host", host).body(Bytes::new()).unwrap()
    }

    #[test]
    fn targets_parse_from_path_and_host() {
        let t = target(&req("localhost", "/_aws/codeartifact/us-east-1/my-dom-123456789012/npm/repo/@s%2fx")).unwrap();
        assert_eq!((t.domain.as_str(), t.owner.as_str(), t.repo.as_str()), ("my-dom", "123456789012", "repo"));
        assert_eq!(t.rest, "@s%2fx");
        let t = target(&req("d-123456789012.d.codeartifact.eu-west-1.amazonaws.com", "/pypi/r/simple/")).unwrap();
        assert_eq!((t.region.as_str(), t.format.as_str(), t.rest.as_str()), ("eu-west-1", "pypi", "simple/"));
        assert!(target(&req("localhost", "/v1/domain")).is_none());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("@scope%2fname"), "@scope/name");
        assert_eq!(percent_decode("a%"), "a%");
    }
}
