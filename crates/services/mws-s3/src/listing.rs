//! Listing: ListObjects (v1 and v2), ListObjectVersions, and the shared
//! prefix / delimiter / marker walk.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::acl;
use crate::auth::Resource;
use crate::buckets::{check_owner, decode_token, encode_token};
use crate::errors;
use crate::generated::types;
use crate::state::{Bucket, ObjectVersion};
use crate::Call;

/// What `encoding-type=url` leaves alone.
const URL_SAFE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~').remove(b'/');

/// Encodes listing strings when the request asked for `encoding-type=url`.
#[derive(Clone, Copy)]
pub struct Encoder(bool);

impl Encoder {
    pub fn new(encoding_type: Option<&str>) -> Result<Self, ServiceError> {
        match encoding_type {
            None => Ok(Self(false)),
            Some(e) if e.eq_ignore_ascii_case("url") => Ok(Self(true)),
            Some(e) => {
                Err(errors::invalid_argument("Invalid Encoding Method specified in Request", "encoding-type", e))
            }
        }
    }

    pub fn enc(&self, s: &str) -> String {
        if self.0 {
            utf8_percent_encode(s, URL_SAFE).to_string()
        } else {
            s.to_string()
        }
    }

    pub fn opt(&self, s: Option<&str>) -> Option<String> {
        s.map(|s| self.enc(s))
    }

    pub fn name(&self) -> Option<String> {
        self.0.then(|| "url".to_string())
    }
}

pub fn max_keys(requested: Option<i32>) -> Result<usize, ServiceError> {
    match requested {
        Some(n) if n < 0 => Err(errors::invalid_argument(
            "Provided max-keys not an integer or within integer range",
            "max-keys",
            &n.to_string(),
        )),
        Some(n) => Ok((n as usize).min(1000)),
        None => Ok(1000),
    }
}

/// One step of a listing walk.
pub enum Entry<'a> {
    Key(&'a str),
    Prefix(String),
}

/// Walk `keys` (sorted) after `after`, grouping by `delimiter` under
/// `prefix`. Returns up to `max` entries and whether more remain.
pub fn walk<'a>(
    keys: impl Iterator<Item = &'a str>,
    prefix: &str,
    delimiter: Option<&str>,
    after: Option<&str>,
    max: usize,
) -> (Vec<Entry<'a>>, bool) {
    let delimiter = delimiter.filter(|d| !d.is_empty());
    let mut out: Vec<Entry<'a>> = Vec::new();
    let mut last_prefix: Option<String> = None;
    for key in keys {
        if !key.starts_with(prefix) {
            continue;
        }
        if let Some(a) = after {
            if key <= a {
                continue;
            }
            // Resuming after a common prefix skips everything under it.
            if delimiter.is_some_and(|d| a.ends_with(d)) && key.starts_with(a) {
                continue;
            }
        }
        let entry = match delimiter.and_then(|d| key[prefix.len()..].find(d).map(|i| (i, d))) {
            Some((i, d)) => {
                let cp = key[..prefix.len() + i + d.len()].to_string();
                if last_prefix.as_deref() == Some(cp.as_str()) {
                    continue;
                }
                last_prefix = Some(cp.clone());
                Entry::Prefix(cp)
            }
            None => Entry::Key(key),
        };
        if out.len() == max {
            return (out, true);
        }
        out.push(entry);
    }
    (out, false)
}

fn object_entry(v: &ObjectVersion, key: &str, enc: Encoder, owner: bool) -> types::Object {
    types::Object {
        key: Some(enc.enc(key)),
        last_modified: Some(v.last_modified),
        e_tag: Some(v.etag.clone()),
        checksum_algorithm: v.checksum.as_ref().map(|c| vec![c.algorithm.clone()]),
        checksum_type: v.checksum.as_ref().map(|c| c.kind.clone()),
        size: Some(v.size()),
        storage_class: Some(v.storage_class.clone()),
        owner: owner.then(|| acl::owner(&v.owner)),
        restore_status: None,
    }
}

/// Keys whose latest version is an object (not a delete marker).
fn live_keys(b: &Bucket) -> impl Iterator<Item = &str> {
    b.objects.iter().filter(|(_, v)| v.last().is_some_and(|l| !l.delete_marker)).map(|(k, _)| k.as_str())
}

fn list_context(prefix: Option<&str>, delimiter: Option<&str>, max: Option<i32>) -> ConditionContext {
    let mut c = ConditionContext::new();
    c.insert("s3:prefix".into(), vec![prefix.unwrap_or_default().to_string()]);
    if let Some(d) = delimiter {
        c.insert("s3:delimiter".into(), vec![d.to_string()]);
    }
    if let Some(m) = max {
        c.insert("s3:max-keys".into(), vec![m.to_string()]);
    }
    c
}

impl Call {
    fn list_bucket<R>(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        expected_owner: Option<&str>,
        action: &str,
        context: ConditionContext,
        f: impl FnOnce(&Bucket) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let st = self.read();
        let b = st.bucket(bucket)?;
        check_owner(b, expected_owner)?;
        self.authorize(ctx, action, b, Resource::Bucket, context)?;
        f(b)
    }

    pub fn list_objects_v2(
        &self,
        ctx: &RequestContext,
        input: types::ListObjectsV2Request,
    ) -> Result<types::ListObjectsV2Output, ServiceError> {
        let enc = Encoder::new(input.encoding_type.as_deref())?;
        let max = max_keys(input.max_keys)?;
        let token = match &input.continuation_token {
            Some(t) => Some(decode_token(t).ok_or_else(|| {
                errors::invalid_argument("The continuation token provided is incorrect", "continuation-token", t)
            })?),
            None => None,
        };
        let context = list_context(input.prefix.as_deref(), input.delimiter.as_deref(), input.max_keys);
        self.list_bucket(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:ListBucket", context, |b| {
            let prefix = input.prefix.clone().unwrap_or_default();
            let after = token.as_deref().or(input.start_after.as_deref());
            let (entries, truncated) = walk(live_keys(b), &prefix, input.delimiter.as_deref(), after, max);
            let mut contents = Vec::new();
            let mut prefixes = Vec::new();
            let mut last = None;
            for e in &entries {
                match e {
                    Entry::Key(k) => {
                        if let Some(v) = b.latest(k) {
                            contents.push(object_entry(v, k, enc, input.fetch_owner == Some(true)));
                        }
                        last = Some(k.to_string());
                    }
                    Entry::Prefix(p) => {
                        prefixes.push(types::CommonPrefix { prefix: Some(enc.enc(p)) });
                        last = Some(p.clone());
                    }
                }
            }
            Ok(types::ListObjectsV2Output {
                is_truncated: Some(truncated),
                key_count: Some(entries.len() as i32),
                contents: (!contents.is_empty()).then_some(contents),
                common_prefixes: (!prefixes.is_empty()).then_some(prefixes),
                name: Some(b.name.clone()),
                prefix: Some(enc.enc(&prefix)),
                delimiter: enc.opt(input.delimiter.as_deref()),
                max_keys: Some(input.max_keys.map(|m| m.min(1000)).unwrap_or(1000)),
                encoding_type: enc.name(),
                continuation_token: input.continuation_token.clone(),
                next_continuation_token: truncated.then(|| encode_token(&last.unwrap_or_default())),
                start_after: enc.opt(input.start_after.as_deref()),
                request_charged: None,
            })
        })
    }

    pub fn list_objects(
        &self,
        ctx: &RequestContext,
        input: types::ListObjectsRequest,
    ) -> Result<types::ListObjectsOutput, ServiceError> {
        let enc = Encoder::new(input.encoding_type.as_deref())?;
        let max = max_keys(input.max_keys)?;
        let context = list_context(input.prefix.as_deref(), input.delimiter.as_deref(), input.max_keys);
        self.list_bucket(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:ListBucket", context, |b| {
            let prefix = input.prefix.clone().unwrap_or_default();
            let marker = input.marker.as_deref().filter(|m| !m.is_empty());
            let (entries, truncated) = walk(live_keys(b), &prefix, input.delimiter.as_deref(), marker, max);
            let mut contents = Vec::new();
            let mut prefixes = Vec::new();
            let mut last = None;
            for e in &entries {
                match e {
                    Entry::Key(k) => {
                        if let Some(v) = b.latest(k) {
                            contents.push(object_entry(v, k, enc, true));
                        }
                        last = Some(k.to_string());
                    }
                    Entry::Prefix(p) => {
                        prefixes.push(types::CommonPrefix { prefix: Some(enc.enc(p)) });
                        last = Some(p.clone());
                    }
                }
            }
            let delimited = input.delimiter.as_deref().is_some_and(|d| !d.is_empty());
            Ok(types::ListObjectsOutput {
                is_truncated: Some(truncated),
                marker: Some(enc.enc(input.marker.as_deref().unwrap_or_default())),
                next_marker: (truncated && delimited).then(|| enc.enc(&last.unwrap_or_default())),
                contents: (!contents.is_empty()).then_some(contents),
                common_prefixes: (!prefixes.is_empty()).then_some(prefixes),
                name: Some(b.name.clone()),
                prefix: Some(enc.enc(&prefix)),
                delimiter: enc.opt(input.delimiter.as_deref()),
                max_keys: Some(input.max_keys.map(|m| m.min(1000)).unwrap_or(1000)),
                encoding_type: enc.name(),
                request_charged: None,
            })
        })
    }

    pub fn list_object_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListObjectVersionsRequest,
    ) -> Result<types::ListObjectVersionsOutput, ServiceError> {
        let enc = Encoder::new(input.encoding_type.as_deref())?;
        let max = max_keys(input.max_keys)?;
        if input.version_id_marker.is_some() && input.key_marker.is_none() {
            return Err(errors::invalid_argument(
                "A version-id marker cannot be specified without a key marker.",
                "version-id-marker",
                input.version_id_marker.as_deref().unwrap_or_default(),
            ));
        }
        let context = list_context(input.prefix.as_deref(), input.delimiter.as_deref(), input.max_keys);
        self.list_bucket(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:ListBucketVersions",
            context,
            |b| {
                let prefix = input.prefix.clone().unwrap_or_default();
                let delimiter = input.delimiter.as_deref().filter(|d| !d.is_empty());
                let key_marker = input.key_marker.as_deref().filter(|m| !m.is_empty());
                let version_marker = input.version_id_marker.as_deref().filter(|m| !m.is_empty());

                let mut versions = Vec::new();
                let mut markers = Vec::new();
                let mut prefixes: Vec<String> = Vec::new();
                let mut count = 0;
                let mut truncated = false;
                let mut next: Option<(String, Option<String>)> = None;
                'keys: for (key, list) in &b.objects {
                    if !key.starts_with(prefix.as_str()) {
                        continue;
                    }
                    // Versions of the marker key older than the version marker
                    // still come; with no version marker the key is done.
                    let mut skip_until: Option<&str> = None;
                    if let Some(m) = key_marker {
                        if key.as_str() < m {
                            continue;
                        }
                        if key == m {
                            match version_marker {
                                Some(vm) => skip_until = Some(vm),
                                None => continue,
                            }
                        }
                        if delimiter.is_some_and(|d| m.ends_with(d)) && key.starts_with(m) {
                            continue;
                        }
                    }
                    if let Some(d) = delimiter {
                        if let Some(i) = key[prefix.len()..].find(d) {
                            let cp = key[..prefix.len() + i + d.len()].to_string();
                            if prefixes.last() == Some(&cp) {
                                continue;
                            }
                            if count == max {
                                truncated = true;
                                break;
                            }
                            prefixes.push(cp.clone());
                            count += 1;
                            next = Some((cp, None));
                            continue;
                        }
                    }
                    let mut skipping = skip_until.is_some();
                    for (i, v) in list.iter().enumerate().rev() {
                        if skipping {
                            if Some(v.version_id.as_str()) == skip_until {
                                skipping = false;
                            }
                            continue;
                        }
                        if count == max {
                            truncated = true;
                            break 'keys;
                        }
                        let is_latest = i == list.len() - 1;
                        if v.delete_marker {
                            markers.push(types::DeleteMarkerEntry {
                                owner: Some(acl::owner(&v.owner)),
                                key: Some(enc.enc(key)),
                                version_id: Some(v.version_id.clone()),
                                is_latest: Some(is_latest),
                                last_modified: Some(v.last_modified),
                            });
                        } else {
                            versions.push(types::ObjectVersion {
                                e_tag: Some(v.etag.clone()),
                                checksum_algorithm: v.checksum.as_ref().map(|c| vec![c.algorithm.clone()]),
                                checksum_type: v.checksum.as_ref().map(|c| c.kind.clone()),
                                size: Some(v.size()),
                                storage_class: Some(v.storage_class.clone()),
                                key: Some(enc.enc(key)),
                                version_id: Some(v.version_id.clone()),
                                is_latest: Some(is_latest),
                                last_modified: Some(v.last_modified),
                                owner: Some(acl::owner(&v.owner)),
                                restore_status: None,
                            });
                        }
                        count += 1;
                        next = Some((key.clone(), Some(v.version_id.clone())));
                    }
                }
                let (next_key, next_version) = match (truncated, next) {
                    (true, Some((k, v))) => (Some(enc.enc(&k)), v),
                    _ => (None, None),
                };
                Ok(types::ListObjectVersionsOutput {
                    is_truncated: Some(truncated),
                    key_marker: Some(enc.enc(input.key_marker.as_deref().unwrap_or_default())),
                    version_id_marker: Some(input.version_id_marker.clone().unwrap_or_default()),
                    next_key_marker: next_key,
                    next_version_id_marker: next_version,
                    versions: (!versions.is_empty()).then_some(versions),
                    delete_markers: (!markers.is_empty()).then_some(markers),
                    name: Some(b.name.clone()),
                    prefix: Some(enc.enc(&prefix)),
                    delimiter: enc.opt(input.delimiter.as_deref()),
                    max_keys: Some(input.max_keys.map(|m| m.min(1000)).unwrap_or(1000)),
                    common_prefixes: (!prefixes.is_empty()).then(|| {
                        prefixes.into_iter().map(|p| types::CommonPrefix { prefix: Some(enc.enc(&p)) }).collect()
                    }),
                    encoding_type: enc.name(),
                    request_charged: None,
                })
            },
        )
    }

    pub fn list_directory_buckets(
        &self,
        ctx: &RequestContext,
        _input: types::ListDirectoryBucketsRequest,
    ) -> Result<types::ListDirectoryBucketsOutput, ServiceError> {
        self.authorize_plain(ctx, "s3express:ListAllMyDirectoryBuckets", "*", ConditionContext::new())?;
        // MWS emulates general purpose buckets only.
        Ok(types::ListDirectoryBucketsOutput { buckets: Some(Vec::new()), continuation_token: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(entries: &[Entry<'_>]) -> Vec<String> {
        entries
            .iter()
            .map(|e| match e {
                Entry::Key(k) => k.to_string(),
                Entry::Prefix(p) => format!("P:{p}"),
            })
            .collect()
    }

    #[test]
    fn delimiter_walk() {
        let keys = ["a/1", "a/2", "b", "c/x/y", "c/z", "d"];
        let (e, t) = walk(keys.iter().copied(), "", Some("/"), None, 1000);
        assert_eq!(names(&e), ["P:a/", "b", "P:c/", "d"]);
        assert!(!t);
        let (e, t) = walk(keys.iter().copied(), "", Some("/"), None, 2);
        assert_eq!(names(&e), ["P:a/", "b"]);
        assert!(t);
        let (e, _) = walk(keys.iter().copied(), "", Some("/"), Some("a/"), 1000);
        assert_eq!(names(&e), ["b", "P:c/", "d"]);
        let (e, _) = walk(keys.iter().copied(), "c/", Some("/"), None, 1000);
        assert_eq!(names(&e), ["P:c/x/", "c/z"]);
    }

    #[test]
    fn url_encoding() {
        assert_eq!(Encoder(true).enc("a b/c+d"), "a%20b/c%2Bd");
    }
}
