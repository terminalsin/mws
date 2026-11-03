//! Deployment packages: validating and storing zips, fetching them from S3,
//! extracting them for execution, and the download links `GetFunction`
//! and `GetLayerVersion` hand out.

use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use sha2::{Digest, Sha256};

use crate::generated::errors;
use crate::state::CodeBlob;
use crate::Lambda;

/// Largest unzipped function or layer content (250 MB).
const MAX_UNZIPPED: u64 = 262_144_000;
/// Largest zip uploaded directly in a request (50 MB).
const MAX_ZIPPED: usize = 52_428_800;
const DOWNLOAD_PREFIX: &str = "/mws-lambda/code/";
/// How long download links stay valid, as in Lambda (10 minutes).
const DOWNLOAD_TTL_SECS: i64 = 600;

/// A stored package: its store key and what Lambda reports about it.
pub struct Stored {
    pub hex: String,
    /// Base64 SHA-256, as `CodeSha256` reports it.
    pub sha256: String,
    pub size: i64,
}

pub fn is_download(request: &HttpRequest) -> bool {
    request.method() == http::Method::GET && request.uri().path().starts_with(DOWNLOAD_PREFIX)
}

fn download_secret() -> &'static str {
    static SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SECRET.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

fn download_signature(hex: &str, expires: i64) -> String {
    hex::encode(Sha256::digest(format!("{}:{hex}:{expires}", download_secret()).as_bytes()))
}

/// Check that `zip` is a readable archive within Lambda's size limits.
pub fn validate_zip(zip: &[u8]) -> Result<(), ServiceError> {
    let unreadable = || {
        errors::invalid_parameter_value(
            "Could not unzip uploaded file. Please check your file, then try to upload again.",
        )
    };
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).map_err(|_| unreadable())?;
    let mut total = 0u64;
    for i in 0..archive.len() {
        let f = archive.by_index(i).map_err(|_| unreadable())?;
        total += f.size();
    }
    if total > MAX_UNZIPPED {
        return Err(errors::invalid_parameter_value(format!(
            "Unzipped size must be smaller than {MAX_UNZIPPED} bytes"
        )));
    }
    Ok(())
}

/// Extract `zip` into `dir` (once; later calls find it there).
pub fn extract(zip: &[u8], dir: &Path) -> std::io::Result<()> {
    if dir.join(".mws-complete").exists() {
        return Ok(());
    }
    let tmp = dir.with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&tmp)?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).map_err(std::io::Error::other)?;
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).map_err(std::io::Error::other)?;
        let Some(rel) = f.enclosed_name() else { continue };
        let out = tmp.join(rel);
        if f.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        std::fs::write(&out, data)?;
        #[cfg(unix)]
        if let Some(mode) = f.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode & 0o7777 | 0o400));
        }
    }
    std::fs::write(tmp.join(".mws-complete"), b"")?;
    if dir.exists() {
        let _ = std::fs::remove_dir_all(dir);
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::rename(&tmp, dir) {
        Ok(()) => Ok(()),
        // Another invocation extracted it first.
        Err(_) if dir.join(".mws-complete").exists() => {
            let _ = std::fs::remove_dir_all(&tmp);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

impl Lambda {
    /// Store a validated zip and describe it.
    pub(crate) fn store_zip(&self, zip: Vec<u8>) -> Result<Stored, ServiceError> {
        validate_zip(&zip)?;
        let digest = Sha256::digest(&zip);
        let stored = Stored {
            hex: hex::encode(digest),
            sha256: base64::engine::general_purpose::STANDARD.encode(digest),
            size: zip.len() as i64,
        };
        self.write().code.entry(stored.hex.clone()).or_insert(CodeBlob(zip));
        Ok(stored)
    }

    /// A zip uploaded in the request, checked against the direct-upload
    /// limit.
    pub(crate) fn direct_zip(zip: Vec<u8>) -> Result<Vec<u8>, ServiceError> {
        if zip.len() > MAX_ZIPPED {
            return Err(errors::request_too_large(format!(
                "Request must be smaller than {MAX_ZIPPED} bytes for the CreateFunction operation"
            )));
        }
        Ok(zip)
    }

    /// Read a package from S3 with the caller's permissions, as Lambda does.
    pub(crate) async fn zip_from_s3(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> Result<Vec<u8>, ServiceError> {
        let Some(s3) = &self.inner.s3 else {
            return Err(errors::invalid_parameter_value(
                "Error occurred while GetObject. S3 Error Code: NoSuchBucket. S3 Error Message: The specified bucket does not exist",
            ));
        };
        let mut input = serde_json::json!({ "Bucket": bucket, "Key": key });
        if let Some(v) = version {
            input["VersionId"] = serde_json::Value::String(v.to_string());
        }
        let out = s3.invoke(ctx.clone(), "GetObject", input).await.map_err(|e| {
            let message = if e.code == "AccessDenied" { "Access Denied".to_string() } else { e.message.clone() };
            errors::invalid_parameter_value(format!(
                "Error occurred while GetObject. S3 Error Code: {}. S3 Error Message: {message}",
                e.code
            ))
        })?;
        let body = out.get("Body").and_then(serde_json::Value::as_str).unwrap_or("");
        base64::engine::general_purpose::STANDARD.decode(body).map_err(|_| {
            errors::invalid_parameter_value(
                "Could not unzip uploaded file. Please check your file, then try to upload again.",
            )
        })
    }

    /// The extracted content of a stored zip.
    pub(crate) fn extracted(&self, kind: &str, hex: &str) -> Result<PathBuf, ServiceError> {
        let dir = self.inner.runtimes.base_dir().join(kind).join(hex);
        if dir.join(".mws-complete").exists() {
            return Ok(dir);
        }
        let zip = self
            .read()
            .code
            .get(hex)
            .map(|b| b.0.clone())
            .ok_or_else(|| errors::service("The function's deployment package is missing."))?;
        extract(&zip, &dir).map_err(|e| errors::service(format!("Unpacking the deployment package failed: {e}")))?;
        Ok(dir)
    }

    /// A link that downloads a stored zip for ten minutes.
    pub(crate) fn download_url(&self, ctx: &RequestContext, hex: &str) -> String {
        let expires = ctx.received_at.timestamp() + DOWNLOAD_TTL_SECS;
        let base = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
        format!(
            "{base}{DOWNLOAD_PREFIX}{hex}?X-Mws-Expires={expires}&X-Mws-Signature={}",
            download_signature(hex, expires)
        )
    }

    pub(crate) fn serve_code_download(&self, ctx: &RequestContext, request: &HttpRequest) -> Option<HttpResponse> {
        if !is_download(request) {
            return None;
        }
        let hex = request.uri().path().strip_prefix(DOWNLOAD_PREFIX).unwrap_or_default().to_string();
        let query = request.uri().query().unwrap_or("");
        let get = |k: &str| {
            query.split('&').find_map(|p| p.strip_prefix(k).and_then(|v| v.strip_prefix('='))).map(str::to_string)
        };
        let expires = get("X-Mws-Expires").and_then(|e| e.parse::<i64>().ok()).unwrap_or(0);
        let valid = get("X-Mws-Signature").as_deref() == Some(download_signature(&hex, expires).as_str())
            && expires >= chrono::Utc::now().timestamp();
        let forbidden = || {
            http::Response::builder()
                .status(403)
                .header("content-type", "application/xml")
                .body(bytes::Bytes::from_static(
                    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AccessDenied</Code><Message>Request has expired</Message></Error>",
                ))
                .expect("valid response")
        };
        if !valid {
            return Some(forbidden());
        }
        let _ = ctx;
        let body = self.read().code.get(&hex).map(|b| b.0.clone());
        Some(match body {
            Some(b) => http::Response::builder()
                .status(200)
                .header("content-type", "application/zip")
                .body(bytes::Bytes::from(b))
                .expect("valid response"),
            None => forbidden(),
        })
    }
}

/// What Lambda reports as `CodeSha256` for a container image: its digest
/// when the URI pins one, otherwise a digest of the URI.
pub fn image_digest(uri: &str) -> String {
    match uri.split_once("@sha256:") {
        Some((_, d)) => d.to_string(),
        None => hex::encode(Sha256::digest(uri.as_bytes())),
    }
}
