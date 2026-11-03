//! Object annotations (named UTF-8 payloads on an object version) and
//! BitTorrent descriptors for objects.

use bytes::Bytes;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::buckets::{decode_token, encode_token};
use crate::checksum;
use crate::errors;
use crate::generated::{errors as gen_errors, types};
use crate::objects::verify_integrity;
use crate::state::{Annotation, Checksum, ObjectVersion};
use crate::Call;

const MAX_NAME_BYTES: usize = 512;
const MAX_PAYLOAD: usize = 1024 * 1024;
const MAX_PER_VERSION: usize = 1000;

fn validate_name(name: &str) -> Result<(), ServiceError> {
    if name.len() > MAX_NAME_BYTES {
        return Err(gen_errors::annotation_name_too_long(format!(
            "The annotation name must not exceed {MAX_NAME_BYTES} bytes."
        )));
    }
    let lower = name.to_lowercase();
    let valid = !name.trim().is_empty()
        && name.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && !lower.starts_with("aws")
        && !lower.starts_with("s3");
    if !valid {
        return Err(gen_errors::invalid_annotation_name(format!(
            "The annotation name '{name}' is not valid. Names may contain letters, digits, '_', '.' and '-', and may not start with 'aws' or 's3'."
        )));
    }
    Ok(())
}

fn check_object_if_match(v: &ObjectVersion, if_match: Option<&str>) -> Result<(), ServiceError> {
    match if_match {
        Some(etag) if etag.trim_matches('"') != v.etag.trim_matches('"') => {
            Err(errors::precondition_failed("If-Match"))
        }
        _ => Ok(()),
    }
}

fn not_for_sse_c(v: &ObjectVersion) -> Result<(), ServiceError> {
    if v.sse.customer_key_md5.is_some() {
        return Err(errors::invalid_request(
            "Annotations are not supported for objects encrypted with customer-provided keys (SSE-C).",
        ));
    }
    Ok(())
}

fn no_such_annotation(name: &str) -> ServiceError {
    gen_errors::no_such_annotation(format!("The specified annotation does not exist: {name}"))
}

impl Call {
    pub fn put_object_annotation(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectAnnotationRequest,
    ) -> Result<types::PutObjectAnnotationOutput, ServiceError> {
        validate_name(&input.annotation_name)?;
        let data = Bytes::from(input.annotation_payload);
        if data.is_empty() || data.len() > MAX_PAYLOAD {
            return Err(errors::invalid_request("The annotation payload must be between 1 byte and 1 MiB."));
        }
        if std::str::from_utf8(&data).is_err() {
            return Err(errors::invalid_request("The annotation payload must be valid UTF-8 text."));
        }
        let provided = provided_checksums!(input);
        let supplied =
            verify_integrity(&data, input.content_md5.as_deref(), &provided, input.checksum_algorithm.as_deref())?;
        let (alg, value) = supplied
            .unwrap_or_else(|| ("CRC64NVME".to_string(), checksum::compute("CRC64NVME", &data).unwrap_or_default()));
        let name = input.annotation_name.clone();
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:PutObjectAnnotation",
            ConditionContext::new(),
            |reports, v| {
                not_for_sse_c(v)?;
                check_object_if_match(v, input.object_if_match.as_deref())?;
                if !v.annotations.contains_key(&name) && v.annotations.len() >= MAX_PER_VERSION {
                    return Err(gen_errors::annotation_limit_exceeded(format!(
                        "An object version can have at most {MAX_PER_VERSION} annotations."
                    )));
                }
                let etag = checksum::etag(&data);
                v.annotations.insert(
                    name.clone(),
                    Annotation {
                        data,
                        etag: etag.clone(),
                        last_modified: ctx.received_at,
                        checksum: Some(Checksum {
                            algorithm: alg.clone(),
                            value: value.clone(),
                            kind: "FULL_OBJECT".into(),
                        }),
                    },
                );
                let mut out = types::PutObjectAnnotationOutput {
                    key: Some(input.key.clone()),
                    annotation_name: Some(name),
                    object_version_id: reports.then(|| v.version_id.clone()),
                    e_tag: Some(etag),
                    checksum_type: Some("FULL_OBJECT".into()),
                    server_side_encryption: v.sse.algorithm.clone(),
                    ..Default::default()
                };
                set_checksum!(out, alg.as_str(), Some(value));
                Ok(out)
            },
        )
    }

    pub fn get_object_annotation(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectAnnotationRequest,
    ) -> Result<types::GetObjectAnnotationOutput, ServiceError> {
        let checksums = input.checksum_mode.as_deref() == Some("ENABLED");
        self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:GetObjectAnnotation",
            |b, v| {
                let a = v
                    .annotations
                    .get(&input.annotation_name)
                    .ok_or_else(|| no_such_annotation(&input.annotation_name))?;
                let mut out = types::GetObjectAnnotationOutput {
                    annotation_payload: a.data.to_vec(),
                    object_version_id: b.versioning.is_some().then(|| v.version_id.clone()),
                    last_modified: Some(a.last_modified),
                    content_length: Some(a.data.len() as i64),
                    e_tag: Some(a.etag.clone()),
                    server_side_encryption: v.sse.algorithm.clone(),
                    replication_status: v.replication_status.clone(),
                    ..Default::default()
                };
                if checksums {
                    if let Some(c) = &a.checksum {
                        out.checksum_type = Some(c.kind.clone());
                        set_checksum!(out, c.algorithm.as_str(), Some(c.value.clone()));
                    }
                }
                Ok(out)
            },
        )
    }

    pub fn list_object_annotations(
        &self,
        ctx: &RequestContext,
        input: types::ListObjectAnnotationsRequest,
    ) -> Result<types::ListObjectAnnotationsOutput, ServiceError> {
        let max = input.max_annotation_results.unwrap_or(1000).clamp(1, 1000) as usize;
        let after = match &input.continuation_token {
            Some(t) => Some(decode_token(t).ok_or_else(|| {
                errors::invalid_argument("The continuation token provided is incorrect", "continuation-token", t)
            })?),
            None => None,
        };
        let prefix = input.annotation_prefix.clone().unwrap_or_default();
        self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:ListObjectAnnotations",
            |b, v| {
                let matching: Vec<_> = v
                    .annotations
                    .iter()
                    .filter(|(n, _)| n.starts_with(&prefix))
                    .filter(|(n, _)| after.as_ref().is_none_or(|a| n.as_str() > a.as_str()))
                    .collect();
                let page: Vec<_> = matching.iter().take(max).collect();
                let truncated = matching.len() > page.len();
                let entries: Vec<types::AnnotationEntry> = page
                    .iter()
                    .map(|(n, a)| types::AnnotationEntry {
                        annotation_name: (*n).clone(),
                        last_modified: a.last_modified,
                        e_tag: Some(a.etag.clone()),
                        checksum_algorithm: a.checksum.as_ref().map(|c| vec![c.algorithm.clone()]),
                        size: a.data.len() as i64,
                        replication_status: v.replication_status.clone(),
                    })
                    .collect();
                Ok(types::ListObjectAnnotationsOutput {
                    annotation_count: Some(entries.len() as i32),
                    next_continuation_token: truncated
                        .then(|| encode_token(page.last().map(|(n, _)| n.as_str()).unwrap_or_default())),
                    annotations: Some(entries),
                    bucket: Some(input.bucket.clone()),
                    key: Some(input.key.clone()),
                    object_version_id: b.versioning.is_some().then(|| v.version_id.clone()),
                    annotation_prefix: input.annotation_prefix.clone(),
                    max_annotation_results: Some(max as i32),
                    continuation_token: input.continuation_token.clone(),
                    request_charged: None,
                })
            },
        )
    }

    pub fn delete_object_annotation(
        &self,
        ctx: &RequestContext,
        input: types::DeleteObjectAnnotationRequest,
    ) -> Result<types::DeleteObjectAnnotationOutput, ServiceError> {
        self.object_write(
            ctx,
            &input.bucket,
            &input.key,
            input.version_id.as_deref(),
            input.expected_bucket_owner.as_deref(),
            "s3:DeleteObjectAnnotation",
            ConditionContext::new(),
            |reports, v| {
                check_object_if_match(v, input.object_if_match.as_deref())?;
                v.annotations.remove(&input.annotation_name);
                Ok(types::DeleteObjectAnnotationOutput {
                    object_version_id: reports.then(|| v.version_id.clone()),
                    request_charged: None,
                })
            },
        )
    }

    /// A BitTorrent metainfo file for the object, as S3 serves it.
    pub fn get_object_torrent(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectTorrentRequest,
    ) -> Result<types::GetObjectTorrentOutput, ServiceError> {
        self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            None,
            input.expected_bucket_owner.as_deref(),
            "s3:GetObjectTorrent",
            |_, v| {
                if v.sse.algorithm.as_deref().is_some_and(|a| a.starts_with("aws:kms"))
                    || v.sse.customer_key_md5.is_some()
                {
                    return Err(errors::invalid_request("Torrents are not supported for encrypted objects."));
                }
                if v.size() > 5 * 1024 * 1024 * 1024 {
                    return Err(errors::invalid_request("Torrents are not supported for objects larger than 5 GB."));
                }
                Ok(types::GetObjectTorrentOutput {
                    body: torrent(&input.bucket, &input.key, &v.data),
                    request_charged: None,
                })
            },
        )
    }
}

const PIECE_LENGTH: usize = 256 * 1024;

fn bstr(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(s.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(s);
}

fn bint(out: &mut Vec<u8>, n: usize) {
    out.push(b'i');
    out.extend_from_slice(n.to_string().as_bytes());
    out.push(b'e');
}

/// A bencoded metainfo dictionary: S3's tracker, the object as one file,
/// SHA-1 of each 256 KiB piece, and S3 as the web seed.
pub fn torrent(bucket: &str, key: &str, data: &[u8]) -> Vec<u8> {
    let mut pieces = Vec::new();
    for chunk in data.chunks(PIECE_LENGTH) {
        pieces
            .extend_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, chunk).as_ref());
    }
    let name = key.rsplit('/').next().unwrap_or(key);
    let mut out = b"d".to_vec();
    bstr(&mut out, b"announce");
    bstr(&mut out, b"http://bittorrent.amazonaws.com:6969/announce");
    bstr(&mut out, b"info");
    out.push(b'd');
    bstr(&mut out, b"length");
    bint(&mut out, data.len());
    bstr(&mut out, b"name");
    bstr(&mut out, name.as_bytes());
    bstr(&mut out, b"piece length");
    bint(&mut out, PIECE_LENGTH);
    bstr(&mut out, b"pieces");
    bstr(&mut out, &pieces);
    bstr(&mut out, b"x-amz-bucket");
    bstr(&mut out, bucket.as_bytes());
    bstr(&mut out, b"x-amz-key");
    bstr(&mut out, key.as_bytes());
    out.push(b'e');
    bstr(&mut out, b"url-list");
    out.push(b'l');
    bstr(&mut out, format!("http://{bucket}.s3.amazonaws.com/{key}").as_bytes());
    out.push(b'e');
    out.push(b'e');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(validate_name("reviewed-by.v1_x").is_ok());
        assert!(validate_name("Grüße").is_ok());
        assert_eq!(validate_name("aws-thing").unwrap_err().code, "InvalidAnnotationName");
        assert_eq!(validate_name("S3x").unwrap_err().code, "InvalidAnnotationName");
        assert_eq!(validate_name("a b").unwrap_err().code, "InvalidAnnotationName");
        assert_eq!(validate_name(&"a".repeat(513)).unwrap_err().code, "AnnotationNameTooLong");
    }

    #[test]
    fn torrent_is_bencoded() {
        let t = torrent("b", "dir/f.txt", b"hello");
        assert!(t.starts_with(b"d8:announce"));
        assert!(t.windows(13).any(|w| w == b"4:name5:f.txt"));
        assert!(t.windows(9).any(|w| w == b"6:lengthi"));
        assert!(t.ends_with(b"ee"));
    }
}
