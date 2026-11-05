//! Getting a deployment's files: from uploads, S3 or an HTTP(S) URL, and
//! zip handling.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::names;
use crate::Amplify;

/// A deployment's files by path (no leading `/`).
pub type Files = BTreeMap<String, Vec<u8>>;

/// Where a manual deployment's files come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// Uploaded to `CreateDeployment`'s URLs: the zip under `""`, or files
    /// by path (blob hashes), plus the file map's expectations.
    Uploaded { uploaded: BTreeMap<String, String>, expected: BTreeMap<String, String> },
    /// `StartDeployment`'s `sourceUrl`.
    Url { url: String, kind: String },
}

/// Who Amplify is acting for, for the bucket policy.
pub struct Origin<'a> {
    pub account: &'a str,
    pub branch_arn: &'a str,
}

/// Unpack a zip into files, skipping directories and unsafe paths.
pub fn unzip(data: &[u8]) -> Result<Files, String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))
        .map_err(|e| format!("The deployment is not a valid zip file: {e}"))?;
    let mut files = Files::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).map_err(|e| format!("Reading the zip failed: {e}"))?;
        if f.is_dir() {
            continue;
        }
        let Some(rel) = f.enclosed_name() else { continue };
        let path = rel.components().map(|c| c.as_os_str().to_string_lossy().to_string()).collect::<Vec<_>>().join("/");
        if path.is_empty() || path.starts_with("__MACOSX/") {
            continue;
        }
        let mut data = Vec::new();
        f.read_to_end(&mut data).map_err(|e| format!("Reading {path} from the zip failed: {e}"))?;
        files.insert(path, data);
    }
    Ok(files)
}

/// Zip up files (build artifacts).
pub fn zip_files(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut out);
        let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (path, data) in files {
            if w.start_file(path.as_str(), options).is_ok() {
                let _ = w.write_all(data);
            }
        }
        let _ = w.finish();
    }
    out.into_inner()
}

/// `s3://bucket/key` into bucket and key.
fn parse_s3(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("s3://")?;
    Some(rest.split_once('/').unwrap_or((rest, "")))
}

impl Amplify {
    /// Fetch a deployment's files. Errors are messages for the job log.
    pub(crate) async fn fetch_source(
        &self,
        source: &Source,
        origin: &Origin<'_>,
        current: &BTreeMap<String, String>,
    ) -> Result<Files, String> {
        match source {
            Source::Uploaded { uploaded, expected } => {
                let blob = |hash: &str| self.read().blobs.get(hash).map(|b| b.0.clone());
                if expected.is_empty() {
                    let hash = uploaded.get("").ok_or("No zip file was uploaded for this deployment.")?;
                    return unzip(&blob(hash).ok_or("The uploaded zip file is missing.")?);
                }
                let mut files = Files::new();
                for (path, md5) in expected {
                    let data = match uploaded.get(path).and_then(|h| blob(h)) {
                        Some(d) => d,
                        // A file the previous deployment already has with
                        // the same content need not be uploaded again.
                        None => current
                            .get(path)
                            .and_then(|h| blob(h))
                            .filter(|d| md5.is_empty() || hex::encode(md5_digest(d)) == md5.to_ascii_lowercase())
                            .ok_or_else(|| format!("File {path} was not uploaded."))?,
                    };
                    files.insert(path.trim_start_matches('/').to_string(), data);
                }
                Ok(files)
            }
            Source::Url { url, kind } => {
                if url.starts_with("s3://") {
                    self.fetch_s3(url, kind, origin)
                } else if kind == "BUCKET_PREFIX" {
                    Err("A BUCKET_PREFIX source must be an s3:// URL.".into())
                } else {
                    let response =
                        crate::http::send(crate::http::Request { method: "GET", url, headers: Vec::new(), body: None })
                            .await
                            .map_err(|e| format!("Downloading {url} failed: {e}"))?;
                    if response.status != 200 {
                        return Err(format!("Downloading {url} failed with HTTP status {}.", response.status));
                    }
                    unzip(&response.body)
                }
            }
        }
    }

    fn fetch_s3(&self, url: &str, kind: &str, origin: &Origin<'_>) -> Result<Files, String> {
        let s3 = self.inner.s3.as_ref().ok_or("S3 is not available.")?;
        let (bucket, key) = parse_s3(url).ok_or_else(|| format!("Invalid S3 URL {url}"))?;
        let read = mws_s3::ServiceRead {
            bucket,
            service_principal: names::SERVICE_PRINCIPAL,
            source_account: origin.account,
            source_arn: origin.branch_arn,
            partition: "aws",
        };
        let s3_error = |e: mws_s3::ServicePutError| match e {
            mws_s3::ServicePutError::NoSuchBucket => format!("The bucket {bucket} does not exist."),
            mws_s3::ServicePutError::AccessDenied { action } => format!(
                "Amplify does not have permission to access {url}: the bucket policy must allow {} {action}.",
                names::SERVICE_PRINCIPAL
            ),
            other => other.to_string(),
        };
        if kind == "BUCKET_PREFIX" {
            let prefix = if key.is_empty() || key.ends_with('/') { key.to_string() } else { format!("{key}/") };
            let keys = s3.list_objects_as_service(&read, &prefix).map_err(s3_error)?;
            let mut files = Files::new();
            for k in keys {
                let rel = k[prefix.len()..].to_string();
                if rel.is_empty() || rel.ends_with('/') {
                    continue;
                }
                if let Some(data) = s3.get_object_as_service(&read, &k).map_err(s3_error)? {
                    files.insert(rel, data);
                }
            }
            if files.is_empty() {
                return Err(format!("No files were found under {url}."));
            }
            Ok(files)
        } else {
            let data = s3
                .get_object_as_service(&read, key)
                .map_err(s3_error)?
                .ok_or_else(|| format!("The object {url} does not exist."))?;
            unzip(&data)
        }
    }
}

pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    Md5::digest(data).into()
}

/// Glob matching for build artifact patterns and custom header patterns:
/// `**` spans directories, `*` and `?` stay within one.
pub fn glob_regex(pattern: &str) -> Option<regex::Regex> {
    let pattern = pattern.trim().trim_start_matches("./").trim_start_matches('/');
    let mut re = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if chars.get(i + 1) == Some(&'*') => {
                if chars.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    re.push_str(".*");
                    i += 2;
                }
                continue;
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    re.push('$');
    regex::Regex::new(&re).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        let all = glob_regex("**/*").unwrap();
        assert!(all.is_match("index.html") && all.is_match("a/b/c.js"));
        let json = glob_regex("*.json").unwrap();
        assert!(json.is_match("a.json") && !json.is_match("x/a.json"));
        let deep = glob_regex("/assets/**").unwrap();
        assert!(deep.is_match("assets/x/y.css") && !deep.is_match("other/x.css"));
    }

    #[test]
    fn zip_round_trip() {
        let mut files = BTreeMap::new();
        files.insert("index.html".to_string(), b"<h1>hi</h1>".to_vec());
        files.insert("a/b.css".to_string(), b"body{}".to_vec());
        assert_eq!(unzip(&zip_files(&files)).unwrap(), files);
    }
}
