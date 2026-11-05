//! A client for upstream registries (Docker registry HTTP API v2), for
//! pull-through caches: manifests and blobs, with the bearer token flow
//! registries challenge with (anonymous or with Basic credentials) and
//! the redirects blob downloads take.

use base64::Engine;

use crate::http::{self, Request, Response};
use crate::manifest;

/// What a pull asks registries for.
const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

/// An upstream registry's API.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// The API base, ending in `/v2` (e.g. `https://quay.io/v2`).
    pub base: String,
    /// `(username, password)` for Basic authentication or a token.
    pub credentials: Option<(String, String)>,
}

/// A manifest as the upstream serves it.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub digest: String,
    pub media_type: String,
    pub manifest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The upstream has no such repository, manifest or blob.
    NotFound,
    /// The upstream refused the credentials (or asks for some).
    Unauthorized(String),
    /// The upstream is rate limiting (`429`).
    Throttled,
    /// Anything else: network, protocol, digests that don't match.
    Failed(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NotFound => write!(f, "not found upstream"),
            FetchError::Throttled => write!(f, "the upstream registry is rate limiting requests"),
            FetchError::Unauthorized(m) | FetchError::Failed(m) => write!(f, "{m}"),
        }
    }
}

impl Upstream {
    /// The manifest `reference` (tag or digest) of `repository`.
    pub async fn manifest(&self, repository: &str, reference: &str) -> Result<Fetched, FetchError> {
        let url = format!("{}/{repository}/manifests/{reference}", self.base);
        let r = self.get(repository, &url, &[("Accept", ACCEPT)]).await?;
        let declared = header(&r, "content-type").map(|c| c.split(';').next().unwrap_or("").trim().to_string());
        let text = String::from_utf8(r.body).map_err(|_| FetchError::Failed("the manifest is not UTF-8".into()))?;
        let parsed = manifest::parse(text.as_bytes(), None)
            .map_err(|e| FetchError::Failed(format!("the upstream manifest is invalid: {e:?}")))?;
        let digest = crate::digest::sha256(text.as_bytes());
        if reference.contains(':') && !crate::digest::matches(reference, text.as_bytes()) {
            return Err(FetchError::Failed(format!("the upstream manifest does not match {reference}")));
        }
        let media_type = if parsed.media_type.is_empty() { declared.unwrap_or_default() } else { parsed.media_type };
        Ok(Fetched { digest, media_type, manifest: text })
    }

    /// The blob `digest` of `repository`, checked against its digest.
    pub async fn blob(&self, repository: &str, digest: &str) -> Result<Vec<u8>, FetchError> {
        let url = format!("{}/{repository}/blobs/{digest}", self.base);
        let r = self.get(repository, &url, &[]).await?;
        if !crate::digest::matches(digest, &r.body) {
            return Err(FetchError::Failed(format!("the upstream blob does not match {digest}")));
        }
        Ok(r.body)
    }

    /// `GET`, answering a bearer challenge once and following redirects.
    async fn get(&self, repository: &str, url: &str, headers: &[(&str, &str)]) -> Result<Response, FetchError> {
        let mut auth = self.credentials.as_ref().map(|(u, p)| format!("Basic {}", basic(u, p)));
        let mut challenged = false;
        let mut url = url.to_string();
        let mut redirects = 0;
        loop {
            let mut h: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            if let Some(a) = &auth {
                h.push(("Authorization".into(), a.clone()));
            }
            h.push(("User-Agent".into(), "mws-registry-client".into()));
            let r = http::send(Request { method: "GET", url: &url, headers: h, body: None })
                .await
                .map_err(FetchError::Failed)?;
            match r.status {
                200 => return Ok(r),
                301 | 302 | 303 | 307 | 308 if redirects < 5 => {
                    let Some(location) = header(&r, "location") else {
                        return Err(FetchError::Failed("a redirect without a Location".into()));
                    };
                    let next = resolve(&url, location);
                    // Blob stores (CDNs, S3) are signed by the URL itself.
                    if host_of(&next) != host_of(&url) {
                        auth = None;
                    }
                    url = next;
                    redirects += 1;
                }
                401 if !challenged => {
                    challenged = true;
                    let challenge = header(&r, "www-authenticate").unwrap_or_default().to_string();
                    match parse_challenge(&challenge) {
                        Some((scheme, params)) if scheme.eq_ignore_ascii_case("bearer") => {
                            let token = self.token(&params, repository).await?;
                            auth = Some(format!("Bearer {token}"));
                        }
                        Some((scheme, _)) if scheme.eq_ignore_ascii_case("basic") && auth.is_some() => {
                            return Err(FetchError::Unauthorized(
                                "the upstream registry refused the credentials".into(),
                            ));
                        }
                        _ => return Err(FetchError::Unauthorized("the upstream registry requires credentials".into())),
                    }
                }
                401 | 403 => {
                    return Err(FetchError::Unauthorized(format!("the upstream registry answered {}", r.status)))
                }
                404 => return Err(FetchError::NotFound),
                429 => return Err(FetchError::Throttled),
                s => return Err(FetchError::Failed(format!("the upstream registry answered {s}"))),
            }
        }
    }

    /// A bearer token from the challenge's realm, for pulls of `repository`.
    async fn token(&self, params: &[(String, String)], repository: &str) -> Result<String, FetchError> {
        let get = |k: &str| params.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone());
        let realm = get("realm").ok_or_else(|| FetchError::Failed("a bearer challenge without a realm".into()))?;
        let query = {
            let mut q = form_urlencoded::Serializer::new(String::new());
            if let Some(s) = get("service") {
                q.append_pair("service", &s);
            }
            q.append_pair("scope", &get("scope").unwrap_or_else(|| format!("repository:{repository}:pull")));
            q.finish()
        };
        let sep = if realm.contains('?') { '&' } else { '?' };
        let url = format!("{realm}{sep}{query}");
        let mut headers = vec![("User-Agent".to_string(), "mws-registry-client".to_string())];
        if let Some((u, p)) = &self.credentials {
            headers.push(("Authorization".into(), format!("Basic {}", basic(u, p))));
        }
        let r =
            http::send(Request { method: "GET", url: &url, headers, body: None }).await.map_err(FetchError::Failed)?;
        if r.status == 401 || r.status == 403 {
            return Err(FetchError::Unauthorized("the upstream token service refused the credentials".into()));
        }
        if r.status != 200 {
            return Err(FetchError::Failed(format!("the upstream token service answered {}", r.status)));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&r.body).map_err(|_| FetchError::Failed("the token response is not JSON".into()))?;
        v.get("token")
            .or_else(|| v.get("access_token"))
            .and_then(|t| t.as_str())
            .map(str::to_string)
            .ok_or_else(|| FetchError::Failed("the token response has no token".into()))
    }
}

fn basic(user: &str, password: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
}

fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
    r.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', '?']).next().unwrap_or("")
}

fn resolve(base: &str, location: &str) -> String {
    if location.contains("://") {
        return location.to_string();
    }
    let scheme = base.split_once("://").map(|(s, _)| s).unwrap_or("https");
    if location.starts_with('/') {
        format!("{scheme}://{}{location}", host_of(base))
    } else {
        let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
        format!("{dir}/{location}")
    }
}

/// `Bearer realm="...",service="..."` as its scheme and parameters.
pub(crate) fn parse_challenge(h: &str) -> Option<(String, Vec<(String, String)>)> {
    let h = h.trim();
    let (scheme, rest) = h.split_once(' ').unwrap_or((h, ""));
    let mut params = Vec::new();
    let mut rest = rest.trim();
    while !rest.is_empty() {
        let (key, after) = rest.split_once('=')?;
        let key = key.trim().trim_start_matches(',').trim().to_string();
        let after = after.trim_start();
        let (value, next) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"')?;
            (q[..end].to_string(), &q[end + 1..])
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (after[..end].trim().to_string(), &after[end..])
        };
        params.push((key, value));
        rest = next.trim_start().trim_start_matches(',').trim_start();
    }
    Some((scheme.to_string(), params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_parse() {
        let (scheme, p) = parse_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        )
        .unwrap();
        assert_eq!(scheme, "Bearer");
        assert_eq!(p[0], ("realm".into(), "https://auth.docker.io/token".into()));
        assert_eq!(p[2].1, "repository:library/alpine:pull");
        assert_eq!(resolve("https://a.io/v2/x/blobs/y", "/z?sig=1"), "https://a.io/z?sig=1");
        assert_eq!(host_of("https://a.io:443/v2"), "a.io:443");
    }
}
