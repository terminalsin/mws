//! Multipart uploads: create, upload (and copy) parts, complete, abort and
//! list.

use bytes::{Bytes, BytesMut};
use mws_core::{CallerKind, ConditionContext, RequestContext, ServiceError};

use crate::acl::{self, GrantHeaders};
use crate::auth::{canonical_id, Resource};
use crate::buckets::check_owner;
use crate::checksum;
use crate::errors;
use crate::generated::types;
use crate::listing::{walk, Encoder, Entry};
use crate::objects::{
    check_customer_key, check_write_conditions, parse_range, parse_tagging, resolve_sse, verify_integrity, CopySource,
    SseRequest,
};
use crate::state::{new_upload_id, Bucket, Checksum, ObjectVersion, Part, PartInfo, Upload};
use crate::Call;

/// Every part but the last must be at least 5 MiB.
pub const MIN_PART_SIZE: i64 = 5 * 1024 * 1024;
const MAX_PART_SIZE: i64 = 5 * 1024 * 1024 * 1024;

fn check_part_number(n: i32) -> Result<(), ServiceError> {
    if !(1..=10000).contains(&n) {
        return Err(errors::invalid_argument(
            "Part number must be an integer between 1 and 10000, inclusive",
            "partNumber",
            &n.to_string(),
        ));
    }
    Ok(())
}

fn upload<'a>(b: &'a Bucket, key: &str, id: &str) -> Result<&'a Upload, ServiceError> {
    b.uploads.get(id).filter(|u| u.key == key).ok_or_else(|| errors::no_such_upload(id))
}

fn initiator(ctx: &RequestContext) -> (String, String) {
    let id = match ctx.caller.kind {
        CallerKind::Root => canonical_id(&ctx.caller.account_id),
        _ => ctx.caller.arn.clone(),
    };
    (id, ctx.caller.arn.clone())
}

impl Call {
    pub fn create_multipart_upload(
        &self,
        ctx: &RequestContext,
        input: types::CreateMultipartUploadRequest,
    ) -> Result<types::CreateMultipartUploadOutput, ServiceError> {
        if input.key.len() > 1024 {
            return Err(errors::key_too_long(input.key.len()));
        }
        let algorithm = input.checksum_algorithm.as_ref().map(|a| a.to_ascii_uppercase());
        let checksum_type = match (&algorithm, input.checksum_type.as_deref()) {
            (None, Some(_)) => {
                return Err(errors::invalid_request(
                    "The x-amz-checksum-type header can only be used with the x-amz-checksum-algorithm header.",
                ))
            }
            (Some(a), Some("FULL_OBJECT")) if !checksum::supports_full_object(a) => {
                return Err(errors::invalid_request(format!(
                    "The FULL_OBJECT checksum type cannot be used with the {} checksum algorithm.",
                    a.to_ascii_lowercase()
                )))
            }
            (Some(a), Some("COMPOSITE")) if a == "CRC64NVME" => {
                return Err(errors::invalid_request(
                    "The COMPOSITE checksum type cannot be used with the crc64nvme checksum algorithm.",
                ))
            }
            (Some(_), Some(t)) => Some(t.to_string()),
            (Some(a), None) => {
                Some(if checksum::full_object_by_default(a) { "FULL_OBJECT" } else { "COMPOSITE" }.to_string())
            }
            (None, None) => None,
        };
        let metadata = input.metadata.clone().unwrap_or_default();
        let tags = match &input.tagging {
            Some(t) => parse_tagging(t)?,
            None => Vec::new(),
        };
        let storage_class = input.storage_class.clone().unwrap_or_else(|| "STANDARD".into());
        let mut st = self.write();
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let mut extra = ConditionContext::new();
        if let Some(a) = &input.acl {
            extra.insert("s3:x-amz-acl".into(), vec![a.clone()]);
        }
        if let Some(s) = &input.server_side_encryption {
            extra.insert("s3:x-amz-server-side-encryption".into(), vec![s.clone()]);
        }
        self.authorize(ctx, "s3:PutObject", b, Resource::Object { key: &input.key, grants: None }, extra)?;
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
        let headers = GrantHeaders {
            full_control: input.grant_full_control.as_deref(),
            read: input.grant_read.as_deref(),
            read_acp: input.grant_read_acp.as_deref(),
            write: None,
            write_acp: input.grant_write_acp.as_deref(),
        };
        let grants = if !b.acls_enabled() {
            if !matches!(input.acl.as_deref(), None | Some("bucket-owner-full-control")) || headers.any() {
                return Err(errors::acls_not_supported());
            }
            acl::canned("private", &b.owner, &b.owner)?
        } else if headers.any() {
            headers.grants()?
        } else {
            acl::canned(input.acl.as_deref().unwrap_or("private"), &ctx.caller.account_id, &b.owner)?
        };
        if input.object_lock_mode.is_some() != input.object_lock_retain_until_date.is_some() {
            return Err(errors::invalid_argument(
                "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied",
                "x-amz-object-lock-mode",
                input.object_lock_mode.as_deref().unwrap_or_default(),
            ));
        }
        if (input.object_lock_mode.is_some() || input.object_lock_legal_hold_status.is_some()) && !b.object_lock_enabled
        {
            return Err(errors::invalid_request("Bucket is missing Object Lock Configuration"));
        }
        let (id, arn) = initiator(ctx);
        let upload_id = new_upload_id();
        let template = ObjectVersion {
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
            sse: sse.clone(),
            acl: grants,
            lock_mode: input.object_lock_mode.clone(),
            lock_until: input.object_lock_retain_until_date,
            legal_hold: input.object_lock_legal_hold_status.clone(),
            ..ObjectVersion::default()
        };
        b.uploads.insert(
            upload_id.clone(),
            Upload {
                upload_id: upload_id.clone(),
                key: input.key.clone(),
                initiated: ctx.received_at,
                initiator: id,
                initiator_arn: arn,
                template,
                checksum_algorithm: algorithm.clone(),
                checksum_type: checksum_type.clone(),
                parts: Default::default(),
            },
        );
        let mut out = types::CreateMultipartUploadOutput {
            bucket: Some(input.bucket),
            key: Some(input.key),
            upload_id: Some(upload_id),
            server_side_encryption: sse.algorithm.clone(),
            ssekms_key_id: sse.kms_key_id.clone(),
            ssekms_encryption_context: sse.kms_context.clone(),
            bucket_key_enabled: sse.bucket_key.then_some(true),
            checksum_algorithm: algorithm,
            checksum_type,
            ..Default::default()
        };
        if sse.customer_key_md5.is_some() {
            out.sse_customer_algorithm = Some("AES256".into());
            out.sse_customer_key_md5 = sse.customer_key_md5.clone();
        }
        Ok(out)
    }

    pub fn upload_part(
        &self,
        ctx: &RequestContext,
        input: types::UploadPartRequest,
    ) -> Result<types::UploadPartOutput, ServiceError> {
        check_part_number(input.part_number)?;
        let data = Bytes::from(input.body);
        if data.len() as i64 > MAX_PART_SIZE {
            return Err(errors::entity_too_large(data.len() as i64, MAX_PART_SIZE));
        }
        let provided = provided_checksums!(input);
        let supplied =
            verify_integrity(&data, input.content_md5.as_deref(), &provided, input.checksum_algorithm.as_deref())?;
        let mut st = self.write();
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        self.authorize(
            ctx,
            "s3:PutObject",
            b,
            Resource::Object { key: &input.key, grants: None },
            ConditionContext::new(),
        )?;
        let up = upload(b, &input.key, &input.upload_id)?;
        check_upload_customer_key(
            up,
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let part_checksum = part_checksum(up, supplied, &data)?;
        let sse = up.template.sse.clone();
        let algorithm = up.checksum_algorithm.clone();
        let etag = checksum::etag(&data);
        let up = b.uploads.get_mut(&input.upload_id).expect("upload exists");
        up.parts.insert(
            input.part_number,
            Part { etag: etag.clone(), last_modified: ctx.received_at, data, checksum: part_checksum.clone() },
        );
        let mut out = types::UploadPartOutput {
            e_tag: Some(etag),
            server_side_encryption: sse.algorithm.clone(),
            ssekms_key_id: sse.kms_key_id.clone(),
            bucket_key_enabled: sse.bucket_key.then_some(true),
            ..Default::default()
        };
        if sse.customer_key_md5.is_some() {
            out.sse_customer_algorithm = Some("AES256".into());
            out.sse_customer_key_md5 = sse.customer_key_md5.clone();
        }
        if let (Some(a), Some(c)) = (algorithm, part_checksum) {
            set_checksum!(out, a.as_str(), Some(c));
        }
        Ok(out)
    }

    pub fn upload_part_copy(
        &self,
        ctx: &RequestContext,
        input: types::UploadPartCopyRequest,
    ) -> Result<types::UploadPartCopyOutput, ServiceError> {
        check_part_number(input.part_number)?;
        let source = CopySource::parse(&input.copy_source)?;
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
        crate::objects::check_read_conditions(
            &src,
            input.copy_source_if_match.as_deref(),
            input.copy_source_if_none_match.as_deref(),
            input.copy_source_if_modified_since,
            input.copy_source_if_unmodified_since,
        )
        .map_err(|e| {
            if e.code == "NotModified" {
                errors::precondition_failed("x-amz-copy-source-If-None-Match")
            } else {
                e
            }
        })?;
        let source_versioned = st.bucket(&source.bucket)?.versioning.is_some();
        let data = match &input.copy_source_range {
            Some(r) => {
                let bad = || {
                    errors::invalid_argument(
                        "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
                        "x-amz-copy-source-range",
                        r,
                    )
                };
                let spec = r.strip_prefix("bytes=").ok_or_else(bad)?;
                let (a, z) = spec.split_once('-').ok_or_else(bad)?;
                let (a, z): (i64, i64) = (a.parse().map_err(|_| bad())?, z.parse().map_err(|_| bad())?);
                if a > z {
                    return Err(bad());
                }
                if z >= src.size() {
                    return Err(errors::invalid_argument(
                        format!("Range specified is not valid for source object of size: {}", src.size()),
                        "x-amz-copy-source-range",
                        r,
                    ));
                }
                let (s, e) = parse_range(r, src.size())?.unwrap_or((a, z));
                src.data.slice(s as usize..=e as usize)
            }
            None => src.data.clone(),
        };
        if data.len() as i64 > MAX_PART_SIZE {
            return Err(errors::entity_too_large(data.len() as i64, MAX_PART_SIZE));
        }
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let mut extra = ConditionContext::new();
        extra.insert("s3:x-amz-copy-source".into(), vec![input.copy_source.trim_start_matches('/').to_string()]);
        self.authorize(ctx, "s3:PutObject", b, Resource::Object { key: &input.key, grants: None }, extra)?;
        let up = upload(b, &input.key, &input.upload_id)?;
        check_upload_customer_key(
            up,
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        let part_checksum = part_checksum(up, None, &data)?;
        let algorithm = up.checksum_algorithm.clone();
        let sse = up.template.sse.clone();
        let etag = checksum::etag(&data);
        let now = ctx.received_at;
        let up = b.uploads.get_mut(&input.upload_id).expect("upload exists");
        up.parts.insert(
            input.part_number,
            Part { etag: etag.clone(), last_modified: now, data, checksum: part_checksum.clone() },
        );
        let mut result = types::CopyPartResult { e_tag: Some(etag), last_modified: Some(now), ..Default::default() };
        if let (Some(a), Some(c)) = (algorithm, part_checksum) {
            set_checksum!(result, a.as_str(), Some(c));
        }
        Ok(types::UploadPartCopyOutput {
            copy_source_version_id: source_versioned.then(|| src.version_id.clone()),
            copy_part_result: Some(result),
            server_side_encryption: sse.algorithm.clone(),
            ssekms_key_id: sse.kms_key_id.clone(),
            bucket_key_enabled: sse.bucket_key.then_some(true),
            ..Default::default()
        })
    }

    pub fn complete_multipart_upload(
        &self,
        ctx: &RequestContext,
        input: types::CompleteMultipartUploadRequest,
    ) -> Result<types::CompleteMultipartUploadOutput, ServiceError> {
        let requested = input.multipart_upload.as_ref().and_then(|m| m.parts.clone()).unwrap_or_default();
        if requested.is_empty() {
            return Err(errors::malformed_xml());
        }
        let mut st = self.write();
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        self.authorize(
            ctx,
            "s3:PutObject",
            b,
            Resource::Object { key: &input.key, grants: None },
            ConditionContext::new(),
        )?;
        let up = upload(b, &input.key, &input.upload_id)?;
        check_upload_customer_key(
            up,
            input.sse_customer_algorithm.as_deref(),
            input.sse_customer_key.as_deref(),
            input.sse_customer_key_md5.as_deref(),
        )?;
        check_write_conditions(b, &input.key, input.if_match.as_deref(), input.if_none_match.as_deref())?;
        let up = upload(b, &input.key, &input.upload_id)?;

        let mut last = 0;
        let mut chosen: Vec<&Part> = Vec::new();
        for p in &requested {
            let n = p.part_number.ok_or_else(errors::malformed_xml)?;
            if n <= last {
                return Err(errors::invalid_part_order(&input.upload_id));
            }
            last = n;
            let etag = p.e_tag.clone().unwrap_or_default();
            let part = up.parts.get(&n).ok_or_else(|| errors::invalid_part(&input.upload_id, n, &etag))?;
            if part.etag.trim_matches('"') != etag.trim_matches('"') {
                return Err(errors::invalid_part(&input.upload_id, n, &etag));
            }
            if let Some(alg) = &up.checksum_algorithm {
                let given = provided_checksums!(p).into_iter().find(|(a, _)| a == alg).and_then(|(_, v)| v);
                if let Some(g) = given {
                    if Some(&g) != part.checksum.as_ref() {
                        return Err(errors::invalid_part(&input.upload_id, n, &etag));
                    }
                } else if up.checksum_type.as_deref() == Some("COMPOSITE") {
                    return Err(errors::invalid_request(format!(
                        "The upload was created using a {} checksum. The complete request must include the checksum for each part. It was missing for part {n} in the request.",
                        alg.to_ascii_lowercase()
                    )));
                }
            }
            chosen.push(part);
        }
        for (i, part) in chosen.iter().enumerate() {
            if i + 1 < chosen.len() && (part.data.len() as i64) < MIN_PART_SIZE {
                return Err(errors::entity_too_small(
                    part.data.len() as i64,
                    requested[i].part_number.unwrap_or(0),
                    &part.etag,
                ));
            }
        }
        let total: usize = chosen.iter().map(|p| p.data.len()).sum();
        if let Some(size) = input.mpu_object_size {
            if size != total as i64 {
                return Err(errors::invalid_request(format!(
                    "The provided 'x-amz-mp-object-size' header value {size} does not match what was computed: {total}"
                )));
            }
        }
        let mut data = BytesMut::with_capacity(total);
        for p in &chosen {
            data.extend_from_slice(&p.data);
        }
        let data = data.freeze();
        let etag = checksum::multipart_etag(&chosen.iter().map(|p| p.etag.clone()).collect::<Vec<_>>());
        let (alg, kind) = match (&up.checksum_algorithm, &up.checksum_type) {
            (Some(a), Some(t)) => (a.clone(), t.clone()),
            _ => ("CRC64NVME".to_string(), "FULL_OBJECT".to_string()),
        };
        let value = if kind == "COMPOSITE" {
            let parts: Vec<String> = chosen.iter().map(|p| p.checksum.clone().unwrap_or_default()).collect();
            checksum::composite(&alg, &parts).unwrap_or_default()
        } else {
            checksum::compute(&alg, &data).unwrap_or_default()
        };
        if kind == "FULL_OBJECT" {
            let given = provided_checksums!(input).into_iter().find(|(a, _)| *a == alg).and_then(|(_, v)| v);
            if given.is_some_and(|g| g != value) {
                return Err(errors::bad_checksum(&alg));
            }
        }
        let parts: Vec<PartInfo> = chosen
            .iter()
            .map(|p| PartInfo { size: p.data.len() as i64, etag: p.etag.clone(), checksum: p.checksum.clone() })
            .collect();
        let mut version = up.template.clone();
        version.last_modified = ctx.received_at;
        version.data = data;
        version.etag = etag.clone();
        version.parts = parts;
        version.checksum = Some(Checksum { algorithm: alg.clone(), value: value.clone(), kind: kind.clone() });
        if version.lock_mode.is_none() {
            if let Some(d) =
                b.object_lock.as_ref().and_then(|c| c.rule.as_ref()).and_then(|r| r.default_retention.as_ref())
            {
                let days = d.days.map(i64::from).unwrap_or(0) + d.years.map(|y| i64::from(y) * 365).unwrap_or(0);
                version.lock_mode = d.mode.clone();
                version.lock_until = (days > 0).then(|| version.last_modified + chrono::Duration::days(days));
            }
        }
        let sse = version.sse.clone();
        b.uploads.remove(&input.upload_id);
        let id = b.insert_version(&input.key, version);
        self.wrote(&input.bucket, &input.key, &id);
        let mut out = types::CompleteMultipartUploadOutput {
            location: Some(format!("/{}/{}", input.bucket, input.key)),
            bucket: Some(input.bucket.clone()),
            key: Some(input.key.clone()),
            e_tag: Some(etag),
            checksum_type: Some(kind),
            server_side_encryption: sse.algorithm.clone(),
            version_id: b.versioning.is_some().then_some(id),
            ssekms_key_id: sse.kms_key_id.clone(),
            bucket_key_enabled: sse.bucket_key.then_some(true),
            ..Default::default()
        };
        set_checksum!(out, alg.as_str(), Some(value));
        Ok(out)
    }

    pub fn abort_multipart_upload(
        &self,
        ctx: &RequestContext,
        input: types::AbortMultipartUploadRequest,
    ) -> Result<types::AbortMultipartUploadOutput, ServiceError> {
        let mut st = self.write();
        let b = st.bucket_mut(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        self.authorize(
            ctx,
            "s3:AbortMultipartUpload",
            b,
            Resource::Object { key: &input.key, grants: None },
            ConditionContext::new(),
        )?;
        let up = upload(b, &input.key, &input.upload_id)?;
        if let Some(t) = input.if_match_initiated_time {
            if t.timestamp() != up.initiated.timestamp() {
                return Err(errors::precondition_failed("x-amz-if-match-initiated-time"));
            }
        }
        b.uploads.remove(&input.upload_id);
        Ok(types::AbortMultipartUploadOutput { request_charged: None })
    }

    pub fn list_parts(
        &self,
        ctx: &RequestContext,
        input: types::ListPartsRequest,
    ) -> Result<types::ListPartsOutput, ServiceError> {
        let max = match input.max_parts {
            Some(n) if n < 0 => {
                return Err(errors::invalid_argument(
                    "Argument max-parts must be an integer between 0 and 2147483647",
                    "max-parts",
                    &n.to_string(),
                ))
            }
            Some(n) => (n as usize).min(1000),
            None => 1000,
        };
        let marker: i32 = match input.part_number_marker.as_deref() {
            Some(m) => m.parse().map_err(|_| {
                errors::invalid_argument(
                    "Argument part-number-marker must be an integer between 0 and 2147483647",
                    "part-number-marker",
                    m,
                )
            })?,
            None => 0,
        };
        let st = self.read();
        let b = st.bucket(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        self.authorize(
            ctx,
            "s3:ListMultipartUploadParts",
            b,
            Resource::Object { key: &input.key, grants: None },
            ConditionContext::new(),
        )?;
        let up = upload(b, &input.key, &input.upload_id)?;
        let all: Vec<(&i32, &Part)> = up.parts.range(marker + 1..).collect();
        let truncated = all.len() > max;
        let page: Vec<(&i32, &Part)> = all.into_iter().take(max).collect();
        let parts: Vec<types::Part> = page
            .iter()
            .map(|(n, p)| {
                let mut part = types::Part {
                    part_number: Some(**n),
                    last_modified: Some(p.last_modified),
                    e_tag: Some(p.etag.clone()),
                    size: Some(p.data.len() as i64),
                    ..Default::default()
                };
                if let (Some(a), Some(c)) = (&up.checksum_algorithm, &p.checksum) {
                    set_checksum!(part, a.as_str(), Some(c.clone()));
                }
                part
            })
            .collect();
        Ok(types::ListPartsOutput {
            bucket: Some(input.bucket.clone()),
            key: Some(input.key.clone()),
            upload_id: Some(input.upload_id.clone()),
            part_number_marker: Some(marker.to_string()),
            next_part_number_marker: page.last().map(|(n, _)| n.to_string()),
            max_parts: Some(max as i32),
            is_truncated: Some(truncated),
            parts: (!parts.is_empty()).then_some(parts),
            initiator: Some(types::Initiator { id: Some(up.initiator.clone()), display_name: None }),
            owner: Some(acl::owner(&up.template.owner)),
            storage_class: Some(up.template.storage_class.clone()),
            checksum_algorithm: up.checksum_algorithm.clone(),
            checksum_type: up.checksum_type.clone(),
            ..Default::default()
        })
    }

    pub fn list_multipart_uploads(
        &self,
        ctx: &RequestContext,
        input: types::ListMultipartUploadsRequest,
    ) -> Result<types::ListMultipartUploadsOutput, ServiceError> {
        let enc = Encoder::new(input.encoding_type.as_deref())?;
        let max = match input.max_uploads {
            Some(n) if n < 0 => {
                return Err(errors::invalid_argument(
                    "Argument max-uploads must be an integer between 0 and 2147483647",
                    "max-uploads",
                    &n.to_string(),
                ))
            }
            Some(n) => (n as usize).min(1000),
            None => 1000,
        };
        let st = self.read();
        let b = st.bucket(&input.bucket)?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let mut context = ConditionContext::new();
        context.insert("s3:prefix".into(), vec![input.prefix.clone().unwrap_or_default()]);
        self.authorize(ctx, "s3:ListBucketMultipartUploads", b, Resource::Bucket, context)?;
        let prefix = input.prefix.clone().unwrap_or_default();
        let key_marker = input.key_marker.as_deref().filter(|m| !m.is_empty());
        let id_marker = input.upload_id_marker.as_deref().filter(|m| !m.is_empty());
        // Uploads in key order, then initiation order.
        let mut ups: Vec<&Upload> = b.uploads.values().collect();
        ups.sort_by(|a, b| a.key.cmp(&b.key).then(a.initiated.cmp(&b.initiated)).then(a.upload_id.cmp(&b.upload_id)));
        let ups: Vec<&Upload> = ups
            .into_iter()
            .filter(|u| match key_marker {
                None => true,
                Some(m) => match id_marker {
                    // With an upload id marker, later uploads of the marker
                    // key still come.
                    Some(id) => u.key.as_str() > m || (u.key == m && u.upload_id.as_str() > id),
                    None => u.key.as_str() > m,
                },
            })
            .collect();
        let keys: Vec<&str> = ups.iter().map(|u| u.key.as_str()).collect();
        let (entries, _) = walk(keys.iter().copied(), &prefix, input.delimiter.as_deref(), None, usize::MAX);
        let mut uploads = Vec::new();
        let mut prefixes = Vec::new();
        let mut truncated = false;
        let mut next: Option<(String, Option<String>)> = None;
        let mut seen_keys = std::collections::BTreeSet::new();
        let mut count = 0;
        for e in entries {
            match e {
                Entry::Prefix(p) => {
                    if count == max {
                        truncated = true;
                        break;
                    }
                    count += 1;
                    next = Some((p.clone(), None));
                    prefixes.push(types::CommonPrefix { prefix: Some(enc.enc(&p)) });
                }
                Entry::Key(k) => {
                    if !seen_keys.insert(k) {
                        continue;
                    }
                    for u in ups.iter().filter(|u| u.key == k) {
                        if count == max {
                            truncated = true;
                            break;
                        }
                        count += 1;
                        next = Some((u.key.clone(), Some(u.upload_id.clone())));
                        uploads.push(types::MultipartUpload {
                            upload_id: Some(u.upload_id.clone()),
                            key: Some(enc.enc(&u.key)),
                            initiated: Some(u.initiated),
                            storage_class: Some(u.template.storage_class.clone()),
                            owner: Some(acl::owner(&u.template.owner)),
                            initiator: Some(types::Initiator { id: Some(u.initiator.clone()), display_name: None }),
                            checksum_algorithm: u.checksum_algorithm.clone(),
                            checksum_type: u.checksum_type.clone(),
                        });
                    }
                    if truncated {
                        break;
                    }
                }
            }
        }
        let (nk, nu) = match (truncated, next) {
            (true, Some((k, u))) => (Some(enc.enc(&k)), u),
            _ => (None, None),
        };
        Ok(types::ListMultipartUploadsOutput {
            bucket: Some(b.name.clone()),
            key_marker: Some(enc.enc(input.key_marker.as_deref().unwrap_or_default())),
            upload_id_marker: Some(input.upload_id_marker.clone().unwrap_or_default()),
            next_key_marker: nk,
            prefix: Some(enc.enc(&prefix)),
            delimiter: enc.opt(input.delimiter.as_deref()),
            next_upload_id_marker: nu,
            max_uploads: Some(max as i32),
            is_truncated: Some(truncated),
            uploads: (!uploads.is_empty()).then_some(uploads),
            common_prefixes: (!prefixes.is_empty()).then_some(prefixes),
            encoding_type: enc.name(),
            request_charged: None,
        })
    }
}

/// SSE-C uploads need the same key on every part request.
fn check_upload_customer_key(
    up: &Upload,
    algorithm: Option<&str>,
    key: Option<&str>,
    key_md5: Option<&str>,
) -> Result<(), ServiceError> {
    check_customer_key(&up.template, algorithm, key, key_md5)
}

/// The checksum stored for a part: the one supplied (which must use the
/// upload's algorithm), or one computed in the upload's algorithm.
fn part_checksum(up: &Upload, supplied: Option<(String, String)>, data: &[u8]) -> Result<Option<String>, ServiceError> {
    match (&up.checksum_algorithm, supplied) {
        (Some(want), Some((got, _))) if *want != got => Err(errors::invalid_request(format!(
            "Checksum Type mismatch occurred, expected checksum Type: {}, actual checksum Type: {}",
            want.to_ascii_lowercase(),
            got.to_ascii_lowercase()
        ))),
        (Some(_), Some((_, v))) => Ok(Some(v)),
        (Some(want), None) => Ok(checksum::compute(want, data)),
        (None, _) => Ok(None),
    }
}
