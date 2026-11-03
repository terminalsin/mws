//! Objects: put, get, head, delete (single and batch), copy, tagging,
//! ACLs, attributes, object lock (retention and legal hold), restore and
//! encryption updates.

use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use mws_core::{CallerKind, ConditionContext, RequestContext, ServiceError};

use crate::acl::{self, GrantHeaders};
use crate::auth::{bucket_arn, Resource};
use crate::buckets::{apply_acl_rules, check_owner, resolve_acl, validate_tags};
use crate::checksum;
use crate::errors;
use crate::generated::types;
use crate::state::{Bucket, Checksum, ObjectVersion, Sse, State};
use crate::Call;

/// Largest object a single PUT may carry.
pub const MAX_PUT_SIZE: i64 = 5 * 1024 * 1024 * 1024;
const ARCHIVE_CLASSES: &[&str] = &["GLACIER", "DEEP_ARCHIVE"];

// ---- shared helpers ---------------------------------------------------------

/// Whether an `If-Match` / `If-None-Match` list names `etag` (or is `*`).
pub fn etag_matches(list: &str, etag: &str) -> bool {
    let etag = etag.trim_matches('"');
    list.split(',').map(|e| e.trim().trim_start_matches("W/").trim_matches('"')).any(|e| e == "*" || e == etag)
}

/// HTTP dates have second precision.
fn secs(t: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(t.timestamp(), 0).unwrap_or(t)
}

/// RFC 7232 evaluation as S3 applies it to reads.
pub fn check_read_conditions(
    v: &ObjectVersion,
    if_match: Option<&str>,
    if_none_match: Option<&str>,
    if_modified_since: Option<DateTime<Utc>>,
    if_unmodified_since: Option<DateTime<Utc>>,
) -> Result<(), ServiceError> {
    let lm = secs(v.last_modified);
    match if_match {
        Some(m) if !etag_matches(m, &v.etag) => return Err(errors::precondition_failed("If-Match")),
        Some(_) => {}
        None => {
            if if_unmodified_since.is_some_and(|t| lm > t) {
                return Err(errors::precondition_failed("If-Unmodified-Since"));
            }
        }
    }
    match if_none_match {
        Some(n) if etag_matches(n, &v.etag) => return Err(errors::not_modified()),
        Some(_) => {}
        None => {
            if if_modified_since.is_some_and(|t| lm <= t) {
                return Err(errors::not_modified());
            }
        }
    }
    Ok(())
}

/// Copy-source conditions answer 412 rather than 304.
fn check_copy_conditions(
    v: &ObjectVersion,
    if_match: Option<&str>,
    if_none_match: Option<&str>,
    if_modified_since: Option<DateTime<Utc>>,
    if_unmodified_since: Option<DateTime<Utc>>,
) -> Result<(), ServiceError> {
    check_read_conditions(v, if_match, if_none_match, if_modified_since, if_unmodified_since).map_err(|e| {
        if e.code == "NotModified" {
            let which = if if_none_match.is_some() {
                "x-amz-copy-source-If-None-Match"
            } else {
                "x-amz-copy-source-If-Modified-Since"
            };
            errors::precondition_failed(which)
        } else {
            let which =
                if if_match.is_some() { "x-amz-copy-source-If-Match" } else { "x-amz-copy-source-If-Unmodified-Since" };
            errors::precondition_failed(which)
        }
    })
}

/// Parse a single `bytes=` range against `size`. Unparseable or multiple
/// ranges are ignored (the whole object is returned), as S3 does.
pub fn parse_range(range: &str, size: i64) -> Result<Option<(i64, i64)>, ServiceError> {
    let Some(spec) = range.trim().strip_prefix("bytes=") else { return Ok(None) };
    if spec.contains(',') {
        return Ok(None);
    }
    let Some((a, b)) = spec.split_once('-') else { return Ok(None) };
    let (a, b) = (a.trim(), b.trim());
    let parsed = match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ok(None),
        (true, false) => {
            let Ok(n) = b.parse::<i64>() else { return Ok(None) };
            if n == 0 || size == 0 {
                return Err(errors::invalid_range(range, size));
            }
            ((size - n).max(0), size - 1)
        }
        (false, _) => {
            let Ok(start) = a.parse::<i64>() else { return Ok(None) };
            let end = if b.is_empty() {
                size - 1
            } else {
                let Ok(e) = b.parse::<i64>() else { return Ok(None) };
                if e < start {
                    return Ok(None);
                }
                e.min(size - 1)
            };
            if start >= size {
                return Err(errors::invalid_range(range, size));
            }
            (start, end)
        }
    };
    Ok(Some(parsed))
}

pub(crate) fn validate_key(key: &str) -> Result<(), ServiceError> {
    if key.len() > 1024 {
        return Err(errors::key_too_long(key.len()));
    }
    if key.is_empty() {
        return Err(errors::invalid_argument("Object key cannot be empty", "key", ""));
    }
    Ok(())
}

fn validate_metadata(meta: &std::collections::BTreeMap<String, String>) -> Result<(), ServiceError> {
    let size: usize = meta.iter().map(|(k, v)| k.len() + v.len()).sum();
    if size > 2048 {
        return Err(errors::metadata_too_large(size));
    }
    Ok(())
}

fn validate_storage_class(class: &str) -> Result<(), ServiceError> {
    const ALLOWED: &[&str] = &[
        "STANDARD",
        "REDUCED_REDUNDANCY",
        "STANDARD_IA",
        "ONEZONE_IA",
        "INTELLIGENT_TIERING",
        "GLACIER",
        "DEEP_ARCHIVE",
        "GLACIER_IR",
        "EXPRESS_ONEZONE",
    ];
    if ALLOWED.contains(&class) {
        Ok(())
    } else {
        Err(errors::invalid_storage_class(class))
    }
}

/// Parse an `x-amz-tagging` header (`k1=v1&k2=v2`, URL encoded).
pub fn parse_tagging(header: &str) -> Result<Vec<types::Tag>, ServiceError> {
    let mut tags = Vec::new();
    for pair in header.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let decode =
            |s: &str| percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned();
        tags.push(types::Tag { key: decode(k), value: decode(v) });
    }
    validate_tags(&tags, 10, true)?;
    Ok(tags)
}

/// Check `Content-MD5` and `x-amz-checksum-*` against `data`. Returns the
/// checksum to store: the one supplied, or `None` to use the default.
pub fn verify_integrity(
    data: &[u8],
    content_md5: Option<&str>,
    provided: &[(&'static str, Option<String>)],
    sdk_algorithm: Option<&str>,
) -> Result<Option<(String, String)>, ServiceError> {
    if let Some(md5) = content_md5 {
        let decoded = base64::engine::general_purpose::STANDARD.decode(md5.trim()).ok().filter(|d| d.len() == 16);
        if decoded.is_none() {
            return Err(errors::invalid_digest(md5));
        }
        let actual = checksum::md5_b64(data);
        if actual != md5.trim() {
            return Err(errors::bad_digest_md5(md5, &actual));
        }
    }
    let given: Vec<(&str, &String)> = provided.iter().filter_map(|(a, v)| v.as_ref().map(|v| (*a, v))).collect();
    if given.len() > 1 {
        return Err(errors::invalid_request(
            "Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.",
        ));
    }
    if let Some((alg, value)) = given.first() {
        if let Some(sdk) = sdk_algorithm {
            if !sdk.eq_ignore_ascii_case(alg) {
                return Err(errors::invalid_request(format!(
                    "Value for x-amz-sdk-checksum-algorithm header is invalid. Expected {sdk} but received {alg}."
                )));
            }
        }
        if base64::engine::general_purpose::STANDARD.decode(value.as_bytes()).is_err() {
            return Err(errors::invalid_checksum(alg));
        }
        if let Some(actual) = checksum::compute(alg, data) {
            if &actual != *value {
                return Err(errors::bad_checksum(alg));
            }
        }
        return Ok(Some((alg.to_string(), (*value).clone())));
    }
    if let Some(sdk) = sdk_algorithm {
        let alg = sdk.to_ascii_uppercase();
        if !checksum::ALGORITHMS.contains(&alg.as_str()) {
            return Err(errors::invalid_request("Checksum algorithm provided is unsupported. Please try again with any of the valid types: [CRC32, CRC32C, CRC64NVME, SHA1, SHA256]"));
        }
        // The SDK named an algorithm but sent no value: compute it.
        if let Some(v) = checksum::compute(&alg, data) {
            return Ok(Some((alg, v)));
        }
    }
    Ok(None)
}

/// The id of the AWS managed `aws/s3` KMS key MWS reports.
fn aws_managed_key(ctx: &RequestContext, account: &str, region: &str) -> String {
    use sha2::Digest;
    let h = hex::encode(sha2::Sha256::digest(format!("aws/s3:{account}:{region}").as_bytes()));
    format!(
        "arn:{}:kms:{region}:{account}:key/{}-{}-{}-{}-{}",
        ctx.partition,
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Normalize a KMS key reference to a key ARN, as S3 reports it.
fn kms_arn(ctx: &RequestContext, key: &str, account: &str, region: &str) -> String {
    if key.starts_with("arn:") {
        key.to_string()
    } else if key.starts_with("alias/") {
        format!("arn:{}:kms:{region}:{account}:{key}", ctx.partition)
    } else {
        format!("arn:{}:kms:{region}:{account}:key/{key}", ctx.partition)
    }
}

/// Server-side encryption request headers.
pub struct SseRequest<'a> {
    pub algorithm: Option<&'a str>,
    pub kms_key_id: Option<&'a str>,
    pub kms_context: Option<&'a str>,
    pub bucket_key: Option<bool>,
    pub customer_algorithm: Option<&'a str>,
    pub customer_key: Option<&'a str>,
    pub customer_key_md5: Option<&'a str>,
}

/// Check SSE-C headers and return the key's MD5.
fn customer_key(
    algorithm: Option<&str>,
    key: Option<&str>,
    key_md5: Option<&str>,
) -> Result<Option<String>, ServiceError> {
    match (algorithm, key, key_md5) {
        (None, None, None) => Ok(None),
        (Some(alg), Some(key), md5) => {
            if alg != "AES256" {
                return Err(errors::invalid_argument(
                    "The encryption method specified is not supported",
                    "x-amz-server-side-encryption-customer-algorithm",
                    alg,
                ));
            }
            let raw = base64::engine::general_purpose::STANDARD.decode(key).ok().filter(|k| k.len() == 32).ok_or_else(|| {
                errors::invalid_argument(
                    "The secret key was invalid for the specified algorithm.",
                    "x-amz-server-side-encryption-customer-key",
                    "****",
                )
            })?;
            let actual = checksum::md5_b64(&raw);
            if let Some(md5) = md5 {
                if md5 != actual {
                    return Err(errors::invalid_argument(
                        "The calculated MD5 hash of the key did not match the hash that was provided.",
                        "x-amz-server-side-encryption-customer-key-MD5",
                        md5,
                    ));
                }
            }
            Ok(Some(actual))
        }
        (None, Some(_), _) | (None, None, Some(_)) => Err(errors::invalid_argument(
            "Requests specifying Server Side Encryption with Customer provided keys must provide a valid encryption algorithm.",
            "x-amz-server-side-encryption",
            "null",
        )),
        (Some(_), None, _) => Err(errors::invalid_argument(
            "Requests specifying Server Side Encryption with Customer provided keys must provide an appropriate secret key.",
            "x-amz-server-side-encryption",
            "null",
        )),
    }
}

/// Work out how a new object is encrypted: SSE-C, an explicit
/// `x-amz-server-side-encryption`, or the bucket default.
pub fn resolve_sse(ctx: &RequestContext, b: &Bucket, req: &SseRequest<'_>) -> Result<Sse, ServiceError> {
    if let Some(md5) = customer_key(req.customer_algorithm, req.customer_key, req.customer_key_md5)? {
        if req.algorithm.is_some() {
            return Err(errors::invalid_argument(
                "Server Side Encryption with Customer provided key is incompatible with the encryption method specified",
                "x-amz-server-side-encryption",
                req.algorithm.unwrap_or_default(),
            ));
        }
        let blocked = b.encryption.as_ref().is_some_and(|e| {
            e.rules.iter().any(|r| {
                r.blocked_encryption_types
                    .as_ref()
                    .and_then(|t| t.encryption_type.as_ref())
                    .is_some_and(|t| t.iter().any(|x| x == "SSE-C"))
            })
        });
        if blocked {
            return Err(errors::access_denied(
                "Requests specifying Server Side Encryption with Customer provided keys are blocked for this bucket.",
            ));
        }
        return Ok(Sse { algorithm: None, customer_key_md5: Some(md5), ..Sse::default() });
    }
    let default_rule = b.encryption.as_ref().and_then(|e| e.rules.first());
    let (algorithm, key, bucket_key) = match req.algorithm {
        Some(a) => (a.to_string(), req.kms_key_id.map(str::to_string), req.bucket_key),
        None => {
            if req.kms_key_id.is_some() {
                return Err(errors::invalid_argument(
                    "Specifying KMS key id without server-side encryption is not supported.",
                    "x-amz-server-side-encryption-aws-kms-key-id",
                    req.kms_key_id.unwrap_or_default(),
                ));
            }
            let d = default_rule.and_then(|r| r.apply_server_side_encryption_by_default.as_ref());
            (
                d.map(|d| d.sse_algorithm.clone()).unwrap_or_else(|| "AES256".into()),
                d.and_then(|d| d.kms_master_key_id.clone()),
                req.bucket_key.or_else(|| default_rule.and_then(|r| r.bucket_key_enabled)),
            )
        }
    };
    match algorithm.as_str() {
        "AES256" => {
            if req.kms_key_id.is_some() {
                return Err(errors::invalid_argument(
                    "Server Side Encryption with AWS KMS managed key requires HTTP header x-amz-server-side-encryption : aws:kms",
                    "x-amz-server-side-encryption-aws-kms-key-id",
                    req.kms_key_id.unwrap_or_default(),
                ));
            }
            Ok(Sse { algorithm: Some(algorithm), ..Sse::default() })
        }
        "aws:kms" | "aws:kms:dsse" => {
            let default_key = key.is_none();
            let key = match key {
                Some(k) => kms_arn(ctx, &k, &b.owner, &b.region),
                None => aws_managed_key(ctx, &b.owner, &b.region),
            };
            if let Some(c) = req.kms_context {
                let ok = base64::engine::general_purpose::STANDARD
                    .decode(c)
                    .ok()
                    .and_then(|j| serde_json::from_slice::<serde_json::Value>(&j).ok())
                    .is_some_and(|v| v.is_object());
                if !ok {
                    return Err(errors::invalid_argument(
                        "The header 'x-amz-server-side-encryption-context' shall be Base64-encoded UTF-8 string holding JSON which represents a string-string map",
                        "x-amz-server-side-encryption-context",
                        c,
                    ));
                }
            }
            Ok(Sse {
                algorithm: Some(algorithm),
                kms_key_id: Some(key),
                kms_context: req.kms_context.map(str::to_string),
                bucket_key: bucket_key.unwrap_or(false),
                kms_default_key: default_key,
                ..Sse::default()
            })
        }
        other => Err(errors::invalid_argument(
            "The encryption method specified is not supported",
            "x-amz-server-side-encryption",
            other,
        )),
    }
}

/// Reading an SSE-C object needs the same key.
pub fn check_customer_key(
    v: &ObjectVersion,
    algorithm: Option<&str>,
    key: Option<&str>,
    key_md5: Option<&str>,
) -> Result<(), ServiceError> {
    let given = customer_key(algorithm, key, key_md5)?;
    match (&v.sse.customer_key_md5, given) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(errors::invalid_request(
            "The encryption parameters are not applicable to this object.",
        )),
        (Some(_), None) => Err(errors::invalid_request(
            "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.",
        )),
        (Some(want), Some(got)) if *want == got => Ok(()),
        (Some(_), Some(_)) => Err(errors::access_denied(
            "Requests specifying Server Side Encryption with Customer provided keys must provide the correct secret key.",
        )),
    }
}

/// Retention mode, retain-until date and legal hold status.
type LockSettings = (Option<String>, Option<DateTime<Utc>>, Option<String>);

/// Object lock settings requested on a write, or the bucket default.
fn resolve_lock(
    b: &Bucket,
    mode: Option<&str>,
    until: Option<DateTime<Utc>>,
    legal_hold: Option<&str>,
    now: DateTime<Utc>,
) -> Result<LockSettings, ServiceError> {
    if (mode.is_some() || until.is_some() || legal_hold.is_some()) && !b.object_lock_enabled {
        return Err(errors::invalid_request("Bucket is missing Object Lock Configuration"));
    }
    match (mode, until) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(errors::invalid_argument(
                "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied",
                "x-amz-object-lock-mode",
                mode.unwrap_or_default(),
            ))
        }
        (Some(m), Some(u)) => {
            if !matches!(m, "GOVERNANCE" | "COMPLIANCE") {
                return Err(errors::invalid_argument("Unknown wormMode directive.", "x-amz-object-lock-mode", m));
            }
            if u <= now {
                return Err(errors::invalid_argument(
                    "The retain until date must be in the future!",
                    "x-amz-object-lock-retain-until-date",
                    &u.to_rfc3339(),
                ));
            }
            return Ok((Some(m.to_string()), Some(u), legal_hold.map(str::to_string)));
        }
        (None, None) => {}
    }
    let default = b.object_lock.as_ref().and_then(|c| c.rule.as_ref()).and_then(|r| r.default_retention.as_ref());
    let (mode, until) = match default {
        Some(d) => {
            let days = d.days.map(i64::from).unwrap_or(0) + d.years.map(|y| i64::from(y) * 365).unwrap_or(0);
            (d.mode.clone(), (days > 0).then(|| now + Duration::days(days)))
        }
        None => (None, None),
    };
    Ok((mode, until, legal_hold.map(str::to_string)))
}

/// Condition keys describing the object a request reads.
fn existing_object_context(v: Option<&ObjectVersion>, version_id: Option<&str>) -> ConditionContext {
    let mut c = ConditionContext::new();
    if let Some(v) = v {
        for t in &v.tags {
            c.insert(format!("s3:ExistingObjectTag/{}", t.key), vec![t.value.clone()]);
        }
    }
    if let Some(id) = version_id {
        c.insert("s3:VersionId".into(), vec![id.to_string()]);
    }
    c
}

/// Condition keys describing a write.
#[allow(clippy::too_many_arguments)]
fn write_context(
    acl: Option<&str>,
    sse: Option<&str>,
    kms_key: Option<&str>,
    storage_class: Option<&str>,
    tags: &[types::Tag],
    lock_mode: Option<&str>,
    lock_until: Option<DateTime<Utc>>,
    legal_hold: Option<&str>,
) -> ConditionContext {
    let mut c = ConditionContext::new();
    let mut put = |k: &str, v: Option<&str>| {
        if let Some(v) = v {
            c.insert(k.to_string(), vec![v.to_string()]);
        }
    };
    put("s3:x-amz-acl", acl);
    put("s3:x-amz-server-side-encryption", sse);
    put("s3:x-amz-server-side-encryption-aws-kms-key-id", kms_key);
    put("s3:x-amz-storage-class", storage_class);
    put("s3:object-lock-mode", lock_mode);
    put("s3:object-lock-legal-hold", legal_hold);
    if let Some(u) = lock_until {
        c.insert("s3:object-lock-retain-until-date".into(), vec![u.format("%Y-%m-%dT%H:%M:%SZ").to_string()]);
        c.insert("s3:object-lock-remaining-retention-days".into(), vec![(u - Utc::now()).num_days().to_string()]);
    }
    if !tags.is_empty() {
        c.insert("s3:RequestObjectTagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
        for t in tags {
            c.insert(format!("s3:RequestObjectTag/{}", t.key), vec![t.value.clone()]);
        }
    }
    c
}

/// Look up a version as reads see it.
pub fn find<'a>(
    b: &'a Bucket,
    key: &str,
    version_id: Option<&str>,
    method: &str,
) -> Result<&'a ObjectVersion, ServiceError> {
    match version_id {
        None => match b.latest(key) {
            Some(v) if !v.delete_marker => Ok(v),
            _ => Err(errors::no_such_key(key)),
        },
        Some(id) => {
            if id.is_empty() {
                return Err(errors::invalid_version_id(id));
            }
            match b.version(key, id) {
                Some(v) if v.delete_marker => Err(errors::method_not_allowed(method, "DeleteMarker")),
                Some(v) => Ok(v),
                None if id != "null" && (id.len() != 32) => Err(errors::invalid_version_id(id)),
                None => Err(errors::no_such_version(key, id)),
            }
        }
    }
}

/// Whether the bucket ever had versioning configured (S3 then reports
/// version ids).
fn reports_versions(b: &Bucket) -> bool {
    b.versioning.is_some()
}

fn version_header(b: &Bucket, v: &ObjectVersion) -> Option<String> {
    reports_versions(b).then(|| v.version_id.clone())
}

fn restore_header(v: &ObjectVersion) -> Option<String> {
    v.restored_until
        .map(|t| format!("ongoing-request=\"false\", expiry-date=\"{}\"", t.format("%a, %d %b %Y %H:%M:%S GMT")))
}

/// Fill the response headers GetObject and HeadObject share.
macro_rules! object_headers {
    ($out:ident, $b:expr, $v:expr, $checksums:expr) => {{
        let v: &ObjectVersion = $v;
        $out.accept_ranges = Some("bytes".into());
        $out.last_modified = Some(v.last_modified);
        $out.e_tag = Some(v.etag.clone());
        $out.version_id = version_header($b, v);
        $out.cache_control = v.cache_control.clone();
        $out.content_disposition = v.content_disposition.clone();
        $out.content_encoding = v.content_encoding.clone();
        $out.content_language = v.content_language.clone();
        $out.content_type = v.content_type.clone();
        $out.expires = v.expires.clone();
        $out.website_redirect_location = v.website_redirect.clone();
        $out.metadata = (!v.metadata.is_empty()).then(|| v.metadata.clone());
        $out.server_side_encryption = v.sse.algorithm.clone();
        $out.ssekms_key_id = v.sse.kms_key_id.clone();
        $out.bucket_key_enabled = v.sse.bucket_key.then_some(true);
        if v.sse.customer_key_md5.is_some() {
            $out.sse_customer_algorithm = Some("AES256".into());
            $out.sse_customer_key_md5 = v.sse.customer_key_md5.clone();
        }
        $out.storage_class = (v.storage_class != "STANDARD").then(|| v.storage_class.clone());
        $out.object_lock_mode = v.lock_mode.clone();
        $out.object_lock_retain_until_date = v.lock_until;
        $out.object_lock_legal_hold_status = v.legal_hold.clone();
        $out.restore = restore_header(v);
        $out.replication_status = v.replication_status.clone();
        $out.tag_count = (!v.tags.is_empty()).then(|| v.tags.len() as i32);
        if $checksums {
            if let Some(c) = &v.checksum {
                set_checksum!($out, c.algorithm.as_str(), Some(c.value.clone()));
                $out.checksum_type = Some(c.kind.clone());
            }
        }
    }};
}

/// `response-*` query parameters override the stored headers.
macro_rules! apply_overrides {
    ($out:ident, $input:ident) => {
        if let Some(x) = &$input.response_cache_control {
            $out.cache_control = Some(x.clone());
        }
        if let Some(x) = &$input.response_content_disposition {
            $out.content_disposition = Some(x.clone());
        }
        if let Some(x) = &$input.response_content_encoding {
            $out.content_encoding = Some(x.clone());
        }
        if let Some(x) = &$input.response_content_language {
            $out.content_language = Some(x.clone());
        }
        if let Some(x) = &$input.response_content_type {
            $out.content_type = Some(x.clone());
        }
        if let Some(x) = &$input.response_expires {
            $out.expires = Some(x.format("%a, %d %b %Y %H:%M:%S GMT").to_string());
        }
    };
}

/// The bytes a read returns: a range, a part, or everything. Returns
/// `(start, end_inclusive, content_range)`.
fn read_window(
    v: &ObjectVersion,
    range: Option<&str>,
    part_number: Option<i32>,
) -> Result<(usize, usize, Option<String>), ServiceError> {
    let size = v.size();
    if range.is_some() && part_number.is_some() {
        return Err(errors::invalid_request("Cannot specify both Range header and partNumber query parameter"));
    }
    if let Some(n) = part_number {
        if !(1..=10000).contains(&n) {
            return Err(errors::invalid_argument(
                "Part number must be an integer between 1 and 10000, inclusive",
                "partNumber",
                &n.to_string(),
            ));
        }
        if v.parts.is_empty() {
            if n != 1 {
                return Err(ServiceError::client(
                    "InvalidPartNumber",
                    416,
                    "The requested partnumber is not satisfiable",
                ));
            }
            let end = (size - 1).max(0);
            return Ok((0, end as usize, (size > 0).then(|| format!("bytes 0-{end}/{size}"))));
        }
        let idx = (n - 1) as usize;
        let part = v.parts.get(idx).ok_or_else(|| {
            ServiceError::client("InvalidPartNumber", 416, "The requested partnumber is not satisfiable")
        })?;
        let start: i64 = v.parts[..idx].iter().map(|p| p.size).sum();
        let end = start + part.size - 1;
        return Ok((start as usize, end as usize, Some(format!("bytes {start}-{end}/{size}"))));
    }
    if let Some(r) = range {
        if let Some((s, e)) = parse_range(r, size)? {
            return Ok((s as usize, e as usize, Some(format!("bytes {s}-{e}/{size}"))));
        }
    }
    Ok((0, (size as usize).saturating_sub(1), None))
}

fn slice(data: &Bytes, start: usize, end: usize) -> Bytes {
    if data.is_empty() {
        return Bytes::new();
    }
    data.slice(start..=end.min(data.len() - 1))
}

impl Call {
    /// A read of a missing key answers 404 only to callers who may list the
    /// bucket; everyone else gets 403.
    fn missing(&self, ctx: &RequestContext, b: &Bucket, err: ServiceError) -> ServiceError {
        if !matches!(err.code.as_ref(), "NoSuchKey" | "NoSuchVersion") {
            return err;
        }
        match self.authorize(ctx, "s3:ListBucket", b, Resource::Bucket, ConditionContext::new()) {
            Ok(()) => err,
            Err(denied) => denied,
        }
    }

    // ---- PutObject ----------------------------------------------------------

    pub fn put_object(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectRequest,
    ) -> Result<types::PutObjectOutput, ServiceError> {
        validate_key(&input.key)?;
        let data = Bytes::from(input.body);
        if data.len() as i64 > MAX_PUT_SIZE {
            return Err(errors::entity_too_large(data.len() as i64, MAX_PUT_SIZE));
        }
        if input.write_offset_bytes.is_some() {
            return Err(errors::invalid_request("WriteOffsetBytes is only supported for directory buckets."));
        }
        let provided = provided_checksums!(input);
        let supplied =
            verify_integrity(&data, input.content_md5.as_deref(), &provided, input.checksum_algorithm.as_deref())?;
        let metadata = input.metadata.clone().unwrap_or_default();
        validate_metadata(&metadata)?;
        let storage_class = input.storage_class.clone().unwrap_or_else(|| "STANDARD".into());
        validate_storage_class(&storage_class)?;
        let tags = match &input.tagging {
            Some(t) => parse_tagging(t)?,
            None => Vec::new(),
        };
        let now = ctx.received_at;
        let mut st = self.write();
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let extra = write_context(
            input.acl.as_deref(),
            input.server_side_encryption.as_deref(),
            input.ssekms_key_id.as_deref(),
            input.storage_class.as_deref(),
            &tags,
            input.object_lock_mode.as_deref(),
            input.object_lock_retain_until_date,
            input.object_lock_legal_hold_status.as_deref(),
        );
        self.authorize(ctx, "s3:PutObject", b, Resource::Object { key: &input.key, grants: None }, extra)?;
        if input.object_lock_legal_hold_status.is_some() {
            self.authorize(
                ctx,
                "s3:PutObjectLegalHold",
                b,
                Resource::Object { key: &input.key, grants: None },
                ConditionContext::new(),
            )?;
        }
        if input.object_lock_mode.is_some() {
            self.authorize(
                ctx,
                "s3:PutObjectRetention",
                b,
                Resource::Object { key: &input.key, grants: None },
                ConditionContext::new(),
            )?;
        }
        check_write_conditions(b, &input.key, input.if_match.as_deref(), input.if_none_match.as_deref())?;
        let grants = object_grants(
            b,
            &ctx.caller.account_id,
            input.acl.as_deref(),
            &GrantHeaders {
                full_control: input.grant_full_control.as_deref(),
                read: input.grant_read.as_deref(),
                read_acp: input.grant_read_acp.as_deref(),
                write: None,
                write_acp: input.grant_write_acp.as_deref(),
            },
        )?;
        let mut sse = resolve_sse(
            ctx,
            b,
            &SseRequest {
                algorithm: input.server_side_encryption.as_deref(),
                kms_key_id: input.ssekms_key_id.as_deref(),
                kms_context: input.ssekms_encryption_context.as_deref(),
                bucket_key: input.bucket_key_enabled,
                customer_algorithm: input.sse_customer_algorithm.as_deref(),
                customer_key: input.sse_customer_key.as_deref(),
                customer_key_md5: input.sse_customer_key_md5.as_deref(),
            },
        )?;
        self.seal_kms(ctx, &mut sse, &input.bucket, &input.key)?;
        let (lock_mode, lock_until, legal_hold) = resolve_lock(
            b,
            input.object_lock_mode.as_deref(),
            input.object_lock_retain_until_date,
            input.object_lock_legal_hold_status.as_deref(),
            now,
        )?;
        let (alg, value) = match supplied {
            Some(c) => c,
            None => ("CRC64NVME".to_string(), checksum::compute("CRC64NVME", &data).unwrap_or_default()),
        };
        let version = ObjectVersion {
            last_modified: now,
            etag: checksum::etag(&data),
            owner: ctx.caller.account_id.clone(),
            content_type: Some(input.content_type.clone().unwrap_or_else(|| "binary/octet-stream".into())),
            cache_control: input.cache_control.clone(),
            content_disposition: input.content_disposition.clone(),
            content_encoding: input.content_encoding.clone(),
            content_language: input.content_language.clone(),
            expires: input.expires.clone(),
            website_redirect: input.website_redirect_location.clone(),
            metadata,
            storage_class,
            tags,
            checksum: Some(Checksum { algorithm: alg.clone(), value: value.clone(), kind: "FULL_OBJECT".into() }),
            sse: sse.clone(),
            acl: grants,
            lock_mode,
            lock_until,
            legal_hold,
            data,
            ..ObjectVersion::default()
        };
        let etag = version.etag.clone();
        let size = version.size();
        let id = b.insert_version(&input.key, version);
        self.wrote(&input.bucket, &input.key, &id);
        let expiration = b.latest(&input.key).and_then(|v| crate::lifecycle::expiration_header(b, &input.key, v));
        let mut out = types::PutObjectOutput {
            expiration,
            e_tag: Some(etag),
            version_id: reports_versions(b).then_some(id),
            server_side_encryption: sse.algorithm.clone(),
            ssekms_key_id: sse.kms_key_id.clone(),
            ssekms_encryption_context: sse.kms_context.clone(),
            bucket_key_enabled: sse.bucket_key.then_some(true),
            checksum_type: Some("FULL_OBJECT".into()),
            size: Some(size),
            ..Default::default()
        };
        if sse.customer_key_md5.is_some() {
            out.sse_customer_algorithm = Some("AES256".into());
            out.sse_customer_key_md5 = sse.customer_key_md5.clone();
        }
        set_checksum!(out, alg.as_str(), Some(value));
        Ok(out)
    }

    // ---- GetObject / HeadObject --------------------------------------------

    pub fn get_object(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectRequest,
    ) -> Result<types::GetObjectOutput, ServiceError> {
        let st = self.read();
        let b = st.bucket(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let found = find(b, &input.key, input.version_id.as_deref(), "GET");
        let action = if input.version_id.is_some() { "s3:GetObjectVersion" } else { "s3:GetObject" };
        let grants = found.as_ref().ok().map(|v| v.acl.as_slice());
        let extra = existing_object_context(found.as_ref().ok().copied(), input.version_id.as_deref());
        self.authorize(ctx, action, b, Resource::Object { key: &input.key, grants }, extra)?;
        let v = found.map_err(|e| self.missing(ctx, b, e))?;
        if v.is_archived() && v.restored_until.is_none_or(|t| t < ctx.received_at) {
            return Err(errors::invalid_object_state(&v.storage_class));
        }
        check_response_overrides(
            ctx,
            input.response_content_type.is_some()
                || input.response_cache_control.is_some()
                || input.response_content_disposition.is_some()
                || input.response_content_encoding.is_some()
                || input.response_content_language.is_some()
                || input.response_expires.is_some(),
        )?;
        check_customer_key(
            v,
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        check_read_conditions(
            v,
            input.if_match.as_deref(),
            input.if_none_match.as_deref(),
            input.if_modified_since,
            input.if_unmodified_since,
        )?;
        self.open_kms(ctx, v, &input.bucket, &input.key)?;
        let (start, end, content_range) = read_window(v, input.range.as_deref(), input.part_number)?;
        let body = slice(&v.data, start, end);
        let whole = content_range.is_none();
        let mut out = types::GetObjectOutput::default();
        let checksums = input.checksum_mode.as_deref() == Some("ENABLED")
            && (whole || (input.part_number.is_some() && v.parts.is_empty()));
        object_headers!(out, b, v, checksums);
        if b.latest(&input.key).is_some_and(|l| l.version_id == v.version_id) {
            out.expiration = crate::lifecycle::expiration_header(b, &input.key, v);
        }
        out.content_length = Some(body.len() as i64);
        out.content_range = content_range;
        out.parts_count = (input.part_number.is_some() && !v.parts.is_empty()).then_some(v.parts.len() as i32);
        apply_overrides!(out, input);
        out.body = body.to_vec();
        Ok(out)
    }

    pub fn head_object(
        &self,
        ctx: &RequestContext,
        input: types::HeadObjectRequest,
    ) -> Result<types::HeadObjectOutput, ServiceError> {
        let st = self.read();
        let b = st.bucket(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let found = find(b, &input.key, input.version_id.as_deref(), "HEAD");
        let action = if input.version_id.is_some() { "s3:GetObjectVersion" } else { "s3:GetObject" };
        let grants = found.as_ref().ok().map(|v| v.acl.as_slice());
        let extra = existing_object_context(found.as_ref().ok().copied(), input.version_id.as_deref());
        self.authorize(ctx, action, b, Resource::Object { key: &input.key, grants }, extra)?;
        let v = found.map_err(|e| self.missing(ctx, b, e))?;
        check_customer_key(
            v,
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        check_read_conditions(
            v,
            input.if_match.as_deref(),
            input.if_none_match.as_deref(),
            input.if_modified_since,
            input.if_unmodified_since,
        )?;
        let (start, end, content_range) = read_window(v, input.range.as_deref(), input.part_number)?;
        let len = if v.data.is_empty() { 0 } else { end - start + 1 };
        let mut out = types::HeadObjectOutput::default();
        let checksums = input.checksum_mode.as_deref() == Some("ENABLED") && content_range.is_none();
        object_headers!(out, b, v, checksums);
        if b.latest(&input.key).is_some_and(|l| l.version_id == v.version_id) {
            out.expiration = crate::lifecycle::expiration_header(b, &input.key, v);
        }
        out.content_length = Some(len as i64);
        out.content_range = content_range;
        out.parts_count = (input.part_number.is_some() && !v.parts.is_empty()).then_some(v.parts.len() as i32);
        if v.is_archived() {
            out.archive_status = None;
        }
        apply_overrides!(out, input);
        Ok(out)
    }

    // ---- DeleteObject(s) ----------------------------------------------------

    pub fn delete_object(
        &self,
        ctx: &RequestContext,
        input: types::DeleteObjectRequest,
    ) -> Result<types::DeleteObjectOutput, ServiceError> {
        let mut st = self.write();
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let conditions = DeleteConditions {
            if_match: input.if_match.as_deref(),
            last_modified: input.if_match_last_modified_time,
            size: input.if_match_size,
        };
        self.delete_one(
            ctx,
            b,
            &input.key,
            input.version_id.as_deref(),
            input.bypass_governance_retention.unwrap_or(false),
            &conditions,
        )
        .map(|(marker, version)| types::DeleteObjectOutput {
            delete_marker: marker.then_some(true),
            version_id: version,
            request_charged: None,
        })
    }

    /// Delete one key or version. Returns `(delete_marker, version_id)`.
    fn delete_one(
        &self,
        ctx: &RequestContext,
        b: &mut Bucket,
        key: &str,
        version_id: Option<&str>,
        bypass_governance: bool,
        conditions: &DeleteConditions<'_>,
    ) -> Result<(bool, Option<String>), ServiceError> {
        let action = if version_id.is_some() { "s3:DeleteObjectVersion" } else { "s3:DeleteObject" };
        let mut extra = ConditionContext::new();
        if let Some(id) = version_id {
            extra.insert("s3:VersionId".into(), vec![id.to_string()]);
        }
        self.authorize(ctx, action, b, Resource::Object { key, grants: None }, extra)?;
        let now = ctx.received_at;
        if let Some(id) = version_id {
            if id.is_empty() {
                return Err(errors::invalid_version_id(id));
            }
            let Some(v) = b.version(key, id) else { return Ok((false, Some(id.to_string()))) };
            match v.locked(now) {
                Some("COMPLIANCE") | Some("LEGAL_HOLD") => {
                    return Err(errors::access_denied("Access Denied because object protected by object lock."))
                }
                Some(_) => {
                    let allowed = bypass_governance
                        && self
                            .authorize(
                                ctx,
                                "s3:BypassGovernanceRetention",
                                b,
                                Resource::Object { key, grants: None },
                                ConditionContext::new(),
                            )
                            .is_ok();
                    if !allowed {
                        return Err(errors::access_denied("Access Denied because object protected by object lock."));
                    }
                }
                None => {}
            }
            let marker = v.delete_marker;
            if let Some(versions) = b.objects.get_mut(key) {
                versions.retain(|v| v.version_id != id);
                if versions.is_empty() {
                    b.objects.remove(key);
                }
            }
            return Ok((marker, Some(id.to_string())));
        }
        conditions.check(b.latest(key).filter(|v| !v.delete_marker), key)?;
        match b.versioning.as_deref() {
            None => {
                if let Some(versions) = b.objects.get_mut(key) {
                    versions.retain(|v| v.version_id != "null");
                    if versions.is_empty() {
                        b.objects.remove(key);
                    }
                }
                Ok((false, None))
            }
            Some(_) => {
                let marker = ObjectVersion {
                    delete_marker: true,
                    last_modified: now,
                    owner: ctx.caller.account_id.clone(),
                    ..ObjectVersion::default()
                };
                let id = b.insert_version(key, marker);
                self.wrote(&b.name, key, &id);
                Ok((true, Some(id)))
            }
        }
    }

    pub fn delete_objects(
        &self,
        ctx: &RequestContext,
        input: types::DeleteObjectsRequest,
    ) -> Result<types::DeleteObjectsOutput, ServiceError> {
        let objects = input.delete.objects;
        if objects.is_empty() || objects.len() > 1000 {
            return Err(errors::malformed_xml());
        }
        let quiet = input.delete.quiet.unwrap_or(false);
        let mut st = self.write();
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let mut deleted = Vec::new();
        let mut errs = Vec::new();
        for o in objects {
            let conditions =
                DeleteConditions { if_match: o.e_tag.as_deref(), last_modified: o.last_modified_time, size: o.size };
            match self.delete_one(
                ctx,
                b,
                &o.key,
                o.version_id.as_deref(),
                input.bypass_governance_retention.unwrap_or(false),
                &conditions,
            ) {
                Ok((marker, version)) => {
                    if !quiet {
                        let (version_id, delete_marker_version_id) = match (&o.version_id, marker) {
                            (Some(v), _) => (Some(v.clone()), marker.then(|| v.clone())),
                            (None, true) => (None, version.clone()),
                            (None, false) => (None, None),
                        };
                        deleted.push(types::DeletedObject {
                            key: Some(o.key.clone()),
                            version_id,
                            delete_marker: marker.then_some(true),
                            delete_marker_version_id,
                        });
                    }
                }
                Err(e) => errs.push(types::Error {
                    key: Some(o.key.clone()),
                    version_id: o.version_id.clone(),
                    code: Some(e.code.to_string()),
                    message: Some(e.message.clone()),
                }),
            }
        }
        Ok(types::DeleteObjectsOutput {
            deleted: (!deleted.is_empty()).then_some(deleted),
            errors: (!errs.is_empty()).then_some(errs),
            request_charged: None,
        })
    }

    // ---- CopyObject ---------------------------------------------------------

    pub fn copy_object(
        &self,
        ctx: &RequestContext,
        input: types::CopyObjectRequest,
    ) -> Result<types::CopyObjectOutput, ServiceError> {
        validate_key(&input.key)?;
        let source = CopySource::parse(&input.copy_source)?;
        let metadata_directive = input.metadata_directive.clone().unwrap_or_else(|| "COPY".into());
        let tagging_directive = input.tagging_directive.clone().unwrap_or_else(|| "COPY".into());
        let annotation_directive = input.annotation_directive.clone().unwrap_or_else(|| "COPY".into());
        if !matches!(annotation_directive.as_str(), "COPY" | "EXCLUDE") {
            return Err(errors::invalid_argument(
                "Unknown annotation directive.",
                "x-amz-annotation-directive",
                &annotation_directive,
            ));
        }
        if !matches!(metadata_directive.as_str(), "COPY" | "REPLACE") {
            return Err(errors::invalid_argument(
                "Unknown metadata directive.",
                "x-amz-metadata-directive",
                &metadata_directive,
            ));
        }
        if !matches!(tagging_directive.as_str(), "COPY" | "REPLACE") {
            return Err(errors::invalid_argument(
                "Unknown tagging directive.",
                "x-amz-tagging-directive",
                &tagging_directive,
            ));
        }
        if let Some(sc) = &input.storage_class {
            validate_storage_class(sc)?;
        }
        let now = ctx.received_at;
        let mut st = self.write();
        let src = self.read_copy_source(
            ctx,
            &st,
            &source,
            input.expected_source_bucket_owner.as_deref(),
            input.copy_source_sse_customer_algorithm.as_deref(),
            input.copy_source_sse_customer_key.as_deref(),
            input.copy_source_sse_customer_key_md5.as_deref(),
        )?;
        check_copy_conditions(
            &src,
            input.copy_source_if_match.as_deref(),
            input.copy_source_if_none_match.as_deref(),
            input.copy_source_if_modified_since,
            input.copy_source_if_unmodified_since,
        )?;
        let source_bucket_versioned = st.bucket(&source.bucket)?.versioning.is_some();
        let tags = if tagging_directive == "REPLACE" {
            match &input.tagging {
                Some(t) => parse_tagging(t)?,
                None => Vec::new(),
            }
        } else {
            src.tags.clone()
        };
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let mut extra = write_context(
            input.acl.as_deref(),
            input.server_side_encryption.as_deref(),
            input.ssekms_key_id.as_deref(),
            input.storage_class.as_deref(),
            if tagging_directive == "REPLACE" { &tags } else { &[] },
            input.object_lock_mode.as_deref(),
            input.object_lock_retain_until_date,
            input.object_lock_legal_hold_status.as_deref(),
        );
        extra.insert("s3:x-amz-copy-source".into(), vec![input.copy_source.trim_start_matches('/').to_string()]);
        extra.insert("s3:x-amz-metadata-directive".into(), vec![metadata_directive.clone()]);
        self.authorize(ctx, "s3:PutObject", b, Resource::Object { key: &input.key, grants: None }, extra)?;
        if tagging_directive == "REPLACE" && !tags.is_empty() {
            self.authorize(
                ctx,
                "s3:PutObjectTagging",
                b,
                Resource::Object { key: &input.key, grants: None },
                ConditionContext::new(),
            )?;
        }
        check_write_conditions(b, &input.key, input.if_match.as_deref(), input.if_none_match.as_deref())?;

        let replace = metadata_directive == "REPLACE";
        let same_object = source.bucket == input.bucket
            && source.key == input.key
            && source.version_id.as_ref().is_none_or(|v| b.latest(&input.key).is_some_and(|l| &l.version_id == v));
        let changes = replace
            || input.storage_class.is_some()
            || input.website_redirect_location.is_some()
            || input.server_side_encryption.is_some()
            || input.sse_customer_algorithm.is_some()
            || input.ssekms_key_id.is_some()
            || input.checksum_algorithm.is_some();
        if same_object && !changes {
            return Err(errors::invalid_request(
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
            ));
        }
        let mut sse = resolve_sse(
            ctx,
            b,
            &SseRequest {
                algorithm: input.server_side_encryption.as_deref(),
                kms_key_id: input.ssekms_key_id.as_deref(),
                kms_context: input.ssekms_encryption_context.as_deref(),
                bucket_key: input.bucket_key_enabled,
                customer_algorithm: input.sse_customer_algorithm.as_deref(),
                customer_key: input.sse_customer_key.as_deref(),
                customer_key_md5: input.sse_customer_key_md5.as_deref(),
            },
        )?;
        self.seal_kms(ctx, &mut sse, &input.bucket, &input.key)?;
        let grants = object_grants(
            b,
            &ctx.caller.account_id,
            input.acl.as_deref(),
            &GrantHeaders {
                full_control: input.grant_full_control.as_deref(),
                read: input.grant_read.as_deref(),
                read_acp: input.grant_read_acp.as_deref(),
                write: None,
                write_acp: input.grant_write_acp.as_deref(),
            },
        )?;
        let (lock_mode, lock_until, legal_hold) = resolve_lock(
            b,
            input.object_lock_mode.as_deref(),
            input.object_lock_retain_until_date,
            input.object_lock_legal_hold_status.as_deref(),
            now,
        )?;
        let algorithm = input
            .checksum_algorithm
            .clone()
            .map(|a| a.to_ascii_uppercase())
            .or_else(|| src.checksum.as_ref().map(|c| c.algorithm.clone()))
            .filter(|a| checksum::compute(a, b"").is_some())
            .unwrap_or_else(|| "CRC64NVME".into());
        let value = checksum::compute(&algorithm, &src.data).unwrap_or_default();
        let metadata = if replace { input.metadata.clone().unwrap_or_default() } else { src.metadata.clone() };
        validate_metadata(&metadata)?;
        let pick = |new: &Option<String>, old: &Option<String>| if replace { new.clone() } else { old.clone() };
        let version = ObjectVersion {
            last_modified: now,
            etag: checksum::etag(&src.data),
            owner: ctx.caller.account_id.clone(),
            content_type: if replace {
                Some(input.content_type.clone().unwrap_or_else(|| "binary/octet-stream".into()))
            } else {
                src.content_type.clone()
            },
            cache_control: pick(&input.cache_control, &src.cache_control),
            content_disposition: pick(&input.content_disposition, &src.content_disposition),
            content_encoding: pick(&input.content_encoding, &src.content_encoding),
            content_language: pick(&input.content_language, &src.content_language),
            expires: pick(&input.expires, &src.expires),
            website_redirect: input.website_redirect_location.clone().or_else(|| {
                if replace {
                    None
                } else {
                    src.website_redirect.clone()
                }
            }),
            metadata,
            storage_class: input.storage_class.clone().unwrap_or_else(|| "STANDARD".into()),
            tags,
            checksum: Some(Checksum { algorithm: algorithm.clone(), value: value.clone(), kind: "FULL_OBJECT".into() }),
            sse: sse.clone(),
            acl: grants,
            lock_mode,
            lock_until,
            legal_hold,
            data: src.data.clone(),
            annotations: if annotation_directive == "EXCLUDE" { Default::default() } else { src.annotations.clone() },
            ..ObjectVersion::default()
        };
        let etag = version.etag.clone();
        let id = b.insert_version(&input.key, version);
        self.wrote(&input.bucket, &input.key, &id);
        let mut result = types::CopyObjectResult {
            e_tag: Some(etag),
            last_modified: Some(now),
            checksum_type: Some("FULL_OBJECT".into()),
            ..Default::default()
        };
        set_checksum!(result, algorithm.as_str(), Some(value));
        let mut out = types::CopyObjectOutput {
            copy_object_result: Some(result),
            copy_source_version_id: source_bucket_versioned.then(|| src.version_id.clone()),
            version_id: reports_versions(b).then_some(id),
            server_side_encryption: sse.algorithm.clone(),
            ssekms_key_id: sse.kms_key_id.clone(),
            ssekms_encryption_context: sse.kms_context.clone(),
            bucket_key_enabled: sse.bucket_key.then_some(true),
            ..Default::default()
        };
        if sse.customer_key_md5.is_some() {
            out.sse_customer_algorithm = Some("AES256".into());
            out.sse_customer_key_md5 = sse.customer_key_md5.clone();
        }
        Ok(out)
    }

    /// Authorize and fetch a copy source (a clone, so the caller can borrow
    /// the destination mutably).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn read_copy_source(
        &self,
        ctx: &RequestContext,
        st: &State,
        source: &CopySource,
        expected_owner: Option<&str>,
        customer_algorithm: Option<&str>,
        customer_key: Option<&str>,
        customer_key_md5: Option<&str>,
    ) -> Result<ObjectVersion, ServiceError> {
        let sb = st.bucket(&source.bucket)?;
        check_owner(sb, expected_owner)?;
        let found = find(sb, &source.key, source.version_id.as_deref(), "GET");
        let action = if source.version_id.is_some() { "s3:GetObjectVersion" } else { "s3:GetObject" };
        let grants = found.as_ref().ok().map(|v| v.acl.as_slice());
        let extra = existing_object_context(found.as_ref().ok().copied(), source.version_id.as_deref());
        self.authorize(ctx, action, sb, Resource::Object { key: &source.key, grants }, extra)?;
        let v = found.map_err(|e| {
            let e = self.missing(ctx, sb, e);
            if e.code == "MethodNotAllowed" {
                errors::invalid_request(
                    "The source of a copy request may not specifically refer to a delete marker by version id.",
                )
            } else {
                e
            }
        })?;
        if v.is_archived() && v.restored_until.is_none_or(|t| t < ctx.received_at) {
            return Err(errors::invalid_object_state(&v.storage_class));
        }
        check_customer_key(v, customer_algorithm, customer_key, customer_key_md5)?;
        self.open_kms(ctx, v, &source.bucket, &source.key)?;
        Ok(v.clone())
    }

    // ---- tagging ------------------------------------------------------------

    pub fn get_object_tagging(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectTaggingRequest,
    ) -> Result<types::GetObjectTaggingOutput, ServiceError> {
        let action = if input.version_id.is_some() { "s3:GetObjectVersionTagging" } else { "s3:GetObjectTagging" };
        self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            action,
            |b, v| Ok(types::GetObjectTaggingOutput { version_id: version_header(b, v), tag_set: v.tags.clone() }),
        )
    }

    pub fn put_object_tagging(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectTaggingRequest,
    ) -> Result<types::PutObjectTaggingOutput, ServiceError> {
        let tags = input.tagging.tag_set;
        validate_tags(&tags, 10, true)?;
        let action = if input.version_id.is_some() { "s3:PutObjectVersionTagging" } else { "s3:PutObjectTagging" };
        let mut extra = ConditionContext::new();
        if !tags.is_empty() {
            extra.insert("s3:RequestObjectTagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
            for t in &tags {
                extra.insert(format!("s3:RequestObjectTag/{}", t.key), vec![t.value.clone()]);
            }
        }
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            action,
            extra,
            |reports, v| {
                v.tags = tags;
                Ok(types::PutObjectTaggingOutput { version_id: reports.then(|| v.version_id.clone()) })
            },
        )
    }

    pub fn delete_object_tagging(
        &self,
        ctx: &RequestContext,
        input: types::DeleteObjectTaggingRequest,
    ) -> Result<types::DeleteObjectTaggingOutput, ServiceError> {
        let action =
            if input.version_id.is_some() { "s3:DeleteObjectVersionTagging" } else { "s3:DeleteObjectTagging" };
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            action,
            ConditionContext::new(),
            |reports, v| {
                v.tags.clear();
                Ok(types::DeleteObjectTaggingOutput { version_id: reports.then(|| v.version_id.clone()) })
            },
        )
    }

    /// Find a version, authorize `action` on it, then run `f`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn object_read<R>(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        expected_owner: Option<&str>,
        action: &str,
        f: impl FnOnce(&Bucket, &ObjectVersion) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let st = self.read();
        let b = st.bucket(bucket)?;
        check_owner(b, expected_owner)?;
        let found = find(b, key, version_id, "GET");
        let grants = found.as_ref().ok().map(|v| v.acl.as_slice());
        let extra = existing_object_context(found.as_ref().ok().copied(), version_id);
        self.authorize(ctx, action, b, Resource::Object { key, grants }, extra)?;
        let v = found.map_err(|e| self.missing(ctx, b, e))?;
        f(b, v)
    }

    /// Like [`Call::object_read`], with the version mutable. `f` gets
    /// whether the bucket reports version ids.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn object_write<R>(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        expected_owner: Option<&str>,
        action: &str,
        extra: ConditionContext,
        f: impl FnOnce(bool, &mut ObjectVersion) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let mut st = self.write();
        let b = st.bucket_mut(bucket)?;
        check_owner(b, expected_owner)?;
        let found = find(b, key, version_id, "PUT").cloned();
        let grants = found.as_ref().ok().map(|v| v.acl.as_slice());
        let mut context = existing_object_context(found.as_ref().ok(), version_id);
        context.extend(extra);
        self.authorize(ctx, action, b, Resource::Object { key, grants }, context)?;
        let v = found.map_err(|e| self.missing(ctx, b, e))?;
        let reports = reports_versions(b);
        let target = b.version_mut(key, Some(&v.version_id)).ok_or_else(|| errors::no_such_key(key))?;
        f(reports, target)
    }

    // ---- ACLs ---------------------------------------------------------------

    pub fn get_object_acl(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectAclRequest,
    ) -> Result<types::GetObjectAclOutput, ServiceError> {
        let action = if input.version_id.is_some() { "s3:GetObjectVersionAcl" } else { "s3:GetObjectAcl" };
        self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            action,
            |b, v| {
                let grants = if b.acls_enabled() { v.acl.clone() } else { acl::canned("private", &b.owner, &b.owner)? };
                let owner = if b.acls_enabled() { &v.owner } else { &b.owner };
                Ok(types::GetObjectAclOutput {
                    owner: Some(acl::owner(owner)),
                    grants: Some(grants),
                    request_charged: None,
                })
            },
        )
    }

    pub fn put_object_acl(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectAclRequest,
    ) -> Result<types::PutObjectAclOutput, ServiceError> {
        let action = if input.version_id.is_some() { "s3:PutObjectVersionAcl" } else { "s3:PutObjectAcl" };
        let headers = GrantHeaders {
            full_control: input.grant_full_control.as_deref(),
            read: input.grant_read.as_deref(),
            read_acp: input.grant_read_acp.as_deref(),
            write: input.grant_write.as_deref(),
            write_acp: input.grant_write_acp.as_deref(),
        };
        let bucket_info = {
            let st = self.read();
            let b = st.bucket(&input.bucket)?;
            (b.owner.clone(), b.clone_settings())
        };
        let mut extra = ConditionContext::new();
        if let Some(a) = &input.acl {
            extra.insert("s3:x-amz-acl".into(), vec![a.clone()]);
        }
        let canned = input.acl.clone();
        let body = input.access_control_policy.clone();
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            action,
            extra,
            |_, v| {
                let grants = resolve_acl(canned.as_deref(), &headers, body.as_ref(), &v.owner, &bucket_info.0)?;
                apply_acl_rules(&bucket_info.1, &grants)?;
                v.acl = grants;
                Ok(types::PutObjectAclOutput { request_charged: None })
            },
        )
    }

    // ---- object lock --------------------------------------------------------

    pub fn get_object_legal_hold(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectLegalHoldRequest,
    ) -> Result<types::GetObjectLegalHoldOutput, ServiceError> {
        self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:GetObjectLegalHold",
            |b, v| {
                if !b.object_lock_enabled {
                    return Err(errors::invalid_request("Bucket is missing Object Lock Configuration"));
                }
                let status = v.legal_hold.clone().ok_or_else(no_lock_config)?;
                Ok(types::GetObjectLegalHoldOutput {
                    legal_hold: Some(types::ObjectLockLegalHold { status: Some(status) }),
                })
            },
        )
    }

    pub fn put_object_legal_hold(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectLegalHoldRequest,
    ) -> Result<types::PutObjectLegalHoldOutput, ServiceError> {
        let status = input.legal_hold.and_then(|h| h.status).ok_or_else(errors::malformed_xml)?;
        if !matches!(status.as_str(), "ON" | "OFF") {
            return Err(errors::malformed_xml());
        }
        self.check_lock_enabled(&input.bucket)?;
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:PutObjectLegalHold",
            ConditionContext::new(),
            |_, v| {
                v.legal_hold = Some(status);
                Ok(types::PutObjectLegalHoldOutput { request_charged: None })
            },
        )
    }

    pub fn get_object_retention(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectRetentionRequest,
    ) -> Result<types::GetObjectRetentionOutput, ServiceError> {
        self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:GetObjectRetention",
            |b, v| {
                if !b.object_lock_enabled {
                    return Err(errors::invalid_request("Bucket is missing Object Lock Configuration"));
                }
                if v.lock_mode.is_none() {
                    return Err(no_lock_config());
                }
                Ok(types::GetObjectRetentionOutput {
                    retention: Some(types::ObjectLockRetention {
                        mode: v.lock_mode.clone(),
                        retain_until_date: v.lock_until,
                        ..Default::default()
                    }),
                })
            },
        )
    }

    pub fn put_object_retention(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectRetentionRequest,
    ) -> Result<types::PutObjectRetentionOutput, ServiceError> {
        let retention = input.retention.ok_or_else(errors::malformed_xml)?;
        if let Some(m) = &retention.mode {
            if !matches!(m.as_str(), "GOVERNANCE" | "COMPLIANCE") {
                return Err(errors::malformed_xml());
            }
        }
        if retention.mode.is_some() != retention.retain_until_date.is_some() {
            return Err(errors::malformed_xml());
        }
        let now = ctx.received_at;
        if retention.retain_until_date.is_some_and(|u| u <= now) {
            return Err(errors::invalid_argument(
                "The retain until date must be in the future!",
                "RetainUntilDate",
                &retention.retain_until_date.map(|u| u.to_rfc3339()).unwrap_or_default(),
            ));
        }
        self.check_lock_enabled(&input.bucket)?;
        let bypass = input.bypass_governance_retention.unwrap_or(false) && {
            let st = self.read();
            let b = st.bucket(&input.bucket)?;
            self.authorize(
                ctx,
                "s3:BypassGovernanceRetention",
                b,
                Resource::Object { key: &input.key, grants: None },
                ConditionContext::new(),
            )
            .is_ok()
        };
        let mut extra = ConditionContext::new();
        if let Some(m) = &retention.mode {
            extra.insert("s3:object-lock-mode".into(), vec![m.clone()]);
        }
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:PutObjectRetention",
            extra,
            |_, v| {
                let active = v.lock_until.is_some_and(|u| u > now);
                if active {
                    let shortens = match (v.lock_until, retention.retain_until_date) {
                        (Some(old), Some(new)) => new < old,
                        (Some(_), None) => true,
                        _ => false,
                    };
                    let mode_change = retention.mode != v.lock_mode;
                    match v.lock_mode.as_deref() {
                        Some("COMPLIANCE") if shortens || mode_change => {
                            return Err(errors::access_denied("Access Denied because object protected by object lock."))
                        }
                        Some("GOVERNANCE") if (shortens || mode_change) && !bypass => {
                            return Err(errors::access_denied("Access Denied because object protected by object lock."))
                        }
                        _ => {}
                    }
                }
                v.lock_mode = retention.mode;
                v.lock_until = retention.retain_until_date;
                Ok(types::PutObjectRetentionOutput { request_charged: None })
            },
        )
    }

    fn check_lock_enabled(&self, bucket: &str) -> Result<(), ServiceError> {
        let st = self.read();
        if !st.bucket(bucket)?.object_lock_enabled {
            return Err(errors::invalid_request("Bucket is missing Object Lock Configuration"));
        }
        Ok(())
    }

    // ---- attributes, restore, encryption ------------------------------------

    pub fn get_object_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectAttributesRequest,
    ) -> Result<types::GetObjectAttributesOutput, ServiceError> {
        let (get, attrs) = if input.version_id.is_some() {
            ("s3:GetObjectVersion", "s3:GetObjectVersionAttributes")
        } else {
            ("s3:GetObject", "s3:GetObjectAttributes")
        };
        let wanted: Vec<String> =
            input.object_attributes.iter().flat_map(|a| a.split(',')).map(|a| a.trim().to_string()).collect();
        for a in &wanted {
            if !matches!(a.as_str(), "ETag" | "Checksum" | "ObjectParts" | "StorageClass" | "ObjectSize") {
                return Err(errors::invalid_argument(
                    "Invalid attribute name specified.",
                    "x-amz-object-attributes",
                    a,
                ));
            }
        }
        let max_parts = input.max_parts.unwrap_or(1000).clamp(0, 1000) as usize;
        let marker: usize = input.part_number_marker.as_deref().and_then(|m| m.parse().ok()).unwrap_or(0);
        self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            get,
            |b, v| {
                self.authorize(
                    ctx,
                    attrs,
                    b,
                    Resource::Object { key: &input.key, grants: Some(&v.acl) },
                    ConditionContext::new(),
                )?;
                check_customer_key(
                    v,
                    input.sse_customer_algorithm.as_deref(),
                    input.sse_customer_key.as_deref(),
                    input.sse_customer_key_md5.as_deref(),
                )?;
                let has = |a: &str| wanted.iter().any(|w| w == a);
                let mut out = types::GetObjectAttributesOutput {
                    last_modified: Some(v.last_modified),
                    version_id: version_header(b, v),
                    ..Default::default()
                };
                if has("ETag") {
                    out.e_tag = Some(v.etag.trim_matches('"').to_string());
                }
                if has("StorageClass") {
                    out.storage_class = Some(v.storage_class.clone());
                }
                if has("ObjectSize") {
                    out.object_size = Some(v.size());
                }
                if has("Checksum") {
                    if let Some(c) = &v.checksum {
                        let mut cs = types::Checksum { checksum_type: Some(c.kind.clone()), ..Default::default() };
                        set_checksum!(cs, c.algorithm.as_str(), Some(c.value.clone()));
                        out.checksum = Some(cs);
                    }
                }
                if has("ObjectParts") && !v.parts.is_empty() {
                    let alg = v.checksum.as_ref().map(|c| c.algorithm.clone());
                    let all: Vec<(usize, &crate::state::PartInfo)> =
                        v.parts.iter().enumerate().map(|(i, p)| (i + 1, p)).filter(|(n, _)| *n > marker).collect();
                    let truncated = all.len() > max_parts;
                    let page: Vec<_> = all.into_iter().take(max_parts).collect();
                    let parts: Vec<types::ObjectPart> = page
                        .iter()
                        .map(|(n, p)| {
                            let mut part = types::ObjectPart {
                                part_number: Some(*n as i32),
                                size: Some(p.size),
                                ..Default::default()
                            };
                            if let (Some(a), Some(c)) = (&alg, &p.checksum) {
                                set_checksum!(part, a.as_str(), Some(c.clone()));
                            }
                            part
                        })
                        .collect();
                    out.object_parts = Some(types::GetObjectAttributesParts {
                        total_parts_count: Some(v.parts.len() as i32),
                        part_number_marker: Some(marker.to_string()),
                        next_part_number_marker: page.last().map(|(n, _)| n.to_string()),
                        max_parts: Some(max_parts as i32),
                        is_truncated: Some(truncated),
                        parts: (v.parts.iter().any(|p| p.checksum.is_some())).then_some(parts),
                    });
                }
                Ok(out)
            },
        )
    }

    pub fn restore_object(
        &self,
        ctx: &RequestContext,
        input: types::RestoreObjectRequest,
    ) -> Result<types::RestoreObjectOutput, ServiceError> {
        let request = input.restore_request.unwrap_or_default();
        if request.r#type.as_deref() == Some("SELECT") || request.select_parameters.is_some() {
            return Err(ServiceError::not_implemented("RestoreObject (SELECT)"));
        }
        let days = request.days.ok_or_else(errors::malformed_xml)?;
        if days <= 0 {
            return Err(errors::invalid_argument("Days must be a positive integer.", "Days", &days.to_string()));
        }
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:RestoreObject",
            ConditionContext::new(),
            |_, v| {
                if !ARCHIVE_CLASSES.contains(&v.storage_class.as_str()) {
                    return Err(ServiceError::client(
                        "InvalidObjectState",
                        403,
                        "Restore is not allowed for the object's current storage class",
                    ));
                }
                // Restores complete immediately in MWS.
                v.restored_until = Some(ctx.received_at + Duration::days(i64::from(days)));
                Ok(types::RestoreObjectOutput::default())
            },
        )
    }

    pub fn update_object_encryption(
        &self,
        ctx: &RequestContext,
        input: types::UpdateObjectEncryptionRequest,
    ) -> Result<types::UpdateObjectEncryptionResponse, ServiceError> {
        let types::ObjectEncryption::SSEKMS(kms) = input.object_encryption;
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:PutObject",
            ConditionContext::new(),
            |_, v| {
                if v.sse.customer_key_md5.is_some() {
                    return Err(errors::invalid_request("Objects encrypted with SSE-C cannot be updated."));
                }
                let mut sse = Sse {
                    algorithm: Some("aws:kms".into()),
                    kms_key_id: Some(kms.kms_key_arn.clone()),
                    bucket_key: kms.bucket_key_enabled.unwrap_or(false),
                    customer_key_md5: None,
                    ..Sse::default()
                };
                self.seal_kms(ctx, &mut sse, &input.bucket, &input.key)?;
                v.sse = sse;
                Ok(types::UpdateObjectEncryptionResponse { request_charged: None })
            },
        )
    }
}

fn no_lock_config() -> ServiceError {
    ServiceError::client(
        "NoSuchObjectLockConfiguration",
        404,
        "The specified object does not have a ObjectLock configuration",
    )
}

fn check_response_overrides(ctx: &RequestContext, any: bool) -> Result<(), ServiceError> {
    if any && ctx.caller.kind == CallerKind::Anonymous {
        return Err(errors::invalid_request(
            "Request specific response headers cannot be used for anonymous GET requests.",
        ));
    }
    Ok(())
}

/// Conditional writes: `If-None-Match: *` and `If-Match: <etag>`.
pub fn check_write_conditions(
    b: &Bucket,
    key: &str,
    if_match: Option<&str>,
    if_none_match: Option<&str>,
) -> Result<(), ServiceError> {
    let current = b.latest(key).filter(|v| !v.delete_marker);
    if let Some(n) = if_none_match {
        if n.trim() != "*" {
            return Err(ServiceError::not_implemented("If-None-Match with a value other than *"));
        }
        if current.is_some() {
            return Err(errors::precondition_failed("If-None-Match"));
        }
    }
    if let Some(m) = if_match {
        match current {
            None => return Err(errors::no_such_key(key)),
            Some(v) if !etag_matches(m, &v.etag) => return Err(errors::precondition_failed("If-Match")),
            Some(_) => {}
        }
    }
    Ok(())
}

/// Conditional deletes (`If-Match`, `x-amz-if-match-last-modified-time`,
/// `x-amz-if-match-size`).
pub struct DeleteConditions<'a> {
    pub if_match: Option<&'a str>,
    pub last_modified: Option<DateTime<Utc>>,
    pub size: Option<i64>,
}

impl DeleteConditions<'_> {
    fn check(&self, current: Option<&ObjectVersion>, key: &str) -> Result<(), ServiceError> {
        if self.if_match.is_none() && self.last_modified.is_none() && self.size.is_none() {
            return Ok(());
        }
        let Some(v) = current else { return Err(errors::no_such_key(key)) };
        if self.if_match.is_some_and(|m| !etag_matches(m, &v.etag)) {
            return Err(errors::precondition_failed("If-Match"));
        }
        if self.last_modified.is_some_and(|t| secs(t) != secs(v.last_modified)) {
            return Err(errors::precondition_failed("x-amz-if-match-last-modified-time"));
        }
        if self.size.is_some_and(|s| s != v.size()) {
            return Err(errors::precondition_failed("x-amz-if-match-size"));
        }
        Ok(())
    }
}

/// Grants for a new object: from the request, checked against the bucket's
/// ownership controls and Block Public Access.
fn object_grants(
    b: &Bucket,
    writer: &str,
    canned: Option<&str>,
    headers: &GrantHeaders<'_>,
) -> Result<Vec<types::Grant>, ServiceError> {
    if canned.is_some() && headers.any() {
        return Err(errors::invalid_request("Specifying both Canned ACLs and Header Grants is not allowed"));
    }
    let owner = if b.acls_enabled() && b.ownership.as_deref() == Some("ObjectWriter") { writer } else { &b.owner };
    let grants = if headers.any() {
        let mut g = acl::canned("private", owner, &b.owner)?;
        let extra = headers.grants()?;
        acl::validate_grants(&extra, &b.owner)?;
        g.extend(extra);
        g
    } else {
        acl::canned(canned.unwrap_or("private"), owner, &b.owner)?
    };
    if !b.acls_enabled() {
        // ACL-disabled buckets accept only bucket-owner-full-control (or no ACL).
        if !matches!(canned, None | Some("bucket-owner-full-control")) || headers.any() {
            return Err(errors::acls_not_supported());
        }
        return acl::canned("private", &b.owner, &b.owner);
    }
    if b.pab().block_public_acls.unwrap_or(false) && acl::is_public(&grants) {
        return Err(errors::access_denied("Access Denied"));
    }
    Ok(grants)
}

/// A parsed `x-amz-copy-source`.
pub struct CopySource {
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
}

impl CopySource {
    pub fn parse(raw: &str) -> Result<Self, ServiceError> {
        let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
        let version_id = query
            .split('&')
            .find_map(|p| p.strip_prefix("versionId="))
            .map(|v| percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned());
        let path = percent_encoding::percent_decode_str(path.trim_start_matches('/')).decode_utf8_lossy().into_owned();
        let (bucket, key) = path.split_once('/').ok_or_else(|| {
            errors::invalid_argument(
                "Copy Source must mention the source bucket and key: sourcebucket/sourcekey",
                "x-amz-copy-source",
                raw,
            )
        })?;
        if bucket.is_empty() || key.is_empty() {
            return Err(errors::invalid_argument(
                "Copy Source must mention the source bucket and key: sourcebucket/sourcekey",
                "x-amz-copy-source",
                raw,
            ));
        }
        Ok(Self { bucket: bucket.to_string(), key: key.to_string(), version_id })
    }
}

impl Bucket {
    /// The settings ACL checks need, without the objects.
    pub fn clone_settings(&self) -> Bucket {
        Bucket {
            name: self.name.clone(),
            owner: self.owner.clone(),
            ownership: self.ownership.clone(),
            public_access_block: self.public_access_block.clone(),
            ..Bucket::default()
        }
    }
}

#[allow(dead_code)]
fn arn_of(ctx: &RequestContext, b: &Bucket) -> String {
    bucket_arn(ctx, &b.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-4", 10).unwrap(), Some((0, 4)));
        assert_eq!(parse_range("bytes=5-", 10).unwrap(), Some((5, 9)));
        assert_eq!(parse_range("bytes=-3", 10).unwrap(), Some((7, 9)));
        assert_eq!(parse_range("bytes=0-100", 10).unwrap(), Some((0, 9)));
        assert!(parse_range("bytes=10-", 10).is_err());
        assert_eq!(parse_range("bytes=0-1,3-4", 10).unwrap(), None);
        assert_eq!(parse_range("items=0-1", 10).unwrap(), None);
    }

    #[test]
    fn copy_sources() {
        let s = CopySource::parse("/b/dir/a%20b.txt?versionId=abc").unwrap();
        assert_eq!((s.bucket.as_str(), s.key.as_str(), s.version_id.as_deref()), ("b", "dir/a b.txt", Some("abc")));
        assert!(CopySource::parse("nokey").is_err());
    }

    #[test]
    fn etags() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("abc", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(etag_matches("\"x\", \"abc\"", "\"abc\""));
        assert!(!etag_matches("\"x\"", "\"abc\""));
    }
}
