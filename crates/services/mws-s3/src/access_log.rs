//! Server access logging: requests to a bucket with logging enabled are
//! written to its target bucket as access log records, in S3's log format,
//! by the `logging.s3.amazonaws.com` service principal. As in AWS, the
//! target bucket's policy must let that principal `s3:PutObject` (with
//! `aws:SourceArn`/`aws:SourceAccount` naming the source bucket); without
//! it the records are lost silently.
//!
//! AWS batches records into log objects some minutes later; MWS writes one
//! object per request straight away, named the way AWS names them
//! (`SimplePrefix` or `PartitionedPrefix` key formats).

use chrono::{DateTime, Utc};
use mws_core::RequestContext;

use crate::public::ServicePutObject;
use crate::S3;

const LOGGING_PRINCIPAL: &str = "logging.s3.amazonaws.com";

/// What a log record says about one request.
pub(crate) struct Entry<'a> {
    pub bucket: &'a str,
    pub key: Option<&'a str>,
    pub operation: Option<&'a str>,
    pub status: u16,
    pub error_code: Option<String>,
    pub bytes_sent: usize,
    pub object_size: Option<u64>,
    pub version_id: Option<String>,
    pub started: std::time::Instant,
}

/// S3's operation field: `REST.GET.OBJECT`, `REST.PUT.BUCKETPOLICY`, ...
fn operation_field(method: &str, op: Option<&str>, has_key: bool, query: &str) -> String {
    let named = match op {
        Some("GetObject") => Some("GET.OBJECT"),
        Some("PutObject") => Some("PUT.OBJECT"),
        Some("HeadObject") => Some("HEAD.OBJECT"),
        Some("DeleteObject") => Some("DELETE.OBJECT"),
        Some("CopyObject") => Some("COPY.OBJECT"),
        Some("ListObjects") | Some("ListObjectsV2") => Some("GET.BUCKET"),
        Some("ListObjectVersions") => Some("GET.BUCKETVERSIONS"),
        Some("HeadBucket") => Some("HEAD.BUCKET"),
        Some("CreateBucket") => Some("PUT.BUCKET"),
        Some("DeleteBucket") => Some("DELETE.BUCKET"),
        Some("DeleteObjects") => Some("POST.MULTI_OBJECT_DELETE"),
        Some("CreateMultipartUpload") => Some("POST.UPLOADS"),
        Some("UploadPart") => Some("PUT.PART"),
        Some("UploadPartCopy") => Some("COPY.PART"),
        Some("CompleteMultipartUpload") => Some("POST.UPLOAD"),
        Some("AbortMultipartUpload") => Some("DELETE.UPLOAD"),
        Some("ListParts") => Some("GET.UPLOAD"),
        Some("ListMultipartUploads") => Some("GET.UPLOADS"),
        Some("GetBucketPolicy") => Some("GET.BUCKETPOLICY"),
        Some("PutBucketPolicy") => Some("PUT.BUCKETPOLICY"),
        Some("DeleteBucketPolicy") => Some("DELETE.BUCKETPOLICY"),
        Some("GetBucketLogging") => Some("GET.LOGGING_STATUS"),
        Some("PutBucketLogging") => Some("PUT.LOGGING_STATUS"),
        _ => None,
    };
    if let Some(n) = named {
        return format!("REST.{n}");
    }
    let sub = query.split('&').next().and_then(|q| q.split('=').next()).filter(|s| !s.is_empty() && *s != "x-id");
    let target = match sub {
        Some(s) => s.to_ascii_uppercase(),
        None if has_key => "OBJECT".into(),
        None => "BUCKET".into(),
    };
    format!("REST.{method}.{target}")
}

fn dash(v: Option<&str>) -> String {
    match v {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => "-".into(),
    }
}

fn quoted(v: Option<&str>) -> String {
    match v {
        Some(s) if !s.is_empty() => format!("\"{}\"", s.replace('"', "\\\"")),
        _ => "\"-\"".into(),
    }
}

/// The log object key for a record written at `at`.
fn object_key(
    l: &crate::generated::types::LoggingEnabled,
    account: &str,
    region: &str,
    bucket: &str,
    at: DateTime<Utc>,
) -> String {
    let unique: String = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..16).map(|_| format!("{:X}", rng.gen_range(0..16u8))).collect()
    };
    let stamp = at.format("%Y-%m-%d-%H-%M-%S");
    let partitioned = l.target_object_key_format.as_ref().and_then(|f| f.partitioned_prefix.as_ref()).is_some();
    if partitioned {
        format!("{}{account}/{region}/{bucket}/{}/{stamp}-{unique}", l.target_prefix, at.format("%Y/%m/%d"))
    } else {
        format!("{}{stamp}-{unique}", l.target_prefix)
    }
}

impl S3 {
    /// Write the access log record for a request, if the bucket logs.
    pub(crate) fn log_access(&self, ctx: &RequestContext, request: &mws_core::HttpRequest, e: Entry<'_>) {
        let (logging, owner, region) = {
            let st = self.read();
            let Some(b) = st.buckets.get(e.bucket) else { return };
            let Some(l) = b.logging.clone() else { return };
            (l, b.owner.clone(), b.region.clone())
        };
        let at = ctx.received_at;
        let header = |name: &str| request.headers().get(name).and_then(|v| v.to_str().ok());
        let auth = header("authorization");
        let query = request.uri().query().unwrap_or_default();
        let (sig, auth_type) = if auth.is_some() {
            ("SigV4", "AuthHeader")
        } else if query.contains("X-Amz-Signature=") {
            ("SigV4", "QueryString")
        } else {
            ("-", "-")
        };
        let requester = if ctx.caller.arn.is_empty() { "-".to_string() } else { ctx.caller.arn.clone() };
        let path_and_query = request.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let request_uri = format!("{} {} HTTP/1.1", request.method(), path_and_query);
        let total = e.started.elapsed().as_millis();
        let line = [
            crate::auth::canonical_id(&owner),
            e.bucket.to_string(),
            at.format("[%d/%b/%Y:%H:%M:%S %z]").to_string(),
            dash(ctx.source_ip.as_deref()),
            requester,
            ctx.request_id.clone(),
            operation_field(request.method().as_str(), e.operation, e.key.is_some(), query),
            dash(e.key),
            quoted(Some(&request_uri)),
            e.status.to_string(),
            dash(e.error_code.as_deref()),
            if e.bytes_sent == 0 { "-".into() } else { e.bytes_sent.to_string() },
            e.object_size.map_or("-".into(), |s| s.to_string()),
            total.to_string(),
            total.to_string(),
            quoted(header("referer")),
            quoted(header("user-agent")),
            dash(e.version_id.as_deref()),
            crate::host_id(&ctx.request_id),
            sig.into(),
            "-".into(),
            auth_type.into(),
            dash(header("host")),
            "-".into(),
            "-".into(),
            "-".into(),
        ]
        .join(" ");
        let key = object_key(&logging, &owner, &region, e.bucket, at);
        let source_arn = format!("arn:{}:s3:::{}", ctx.partition, e.bucket);
        let put = ServicePutObject {
            bucket: &logging.target_bucket,
            key: &key,
            body: format!("{line}\n").into_bytes(),
            content_type: "text/plain",
            service_principal: LOGGING_PRINCIPAL,
            source_account: &owner,
            source_arn: &source_arn,
            acl: None,
            partition: &ctx.partition,
        };
        // Like AWS, a target bucket that refuses the log delivery loses the
        // record without telling anyone.
        let _ = self.put_object_as_service(put);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations() {
        assert_eq!(operation_field("GET", Some("GetObject"), true, ""), "REST.GET.OBJECT");
        assert_eq!(operation_field("GET", Some("GetBucketVersioning"), false, "versioning"), "REST.GET.VERSIONING");
        assert_eq!(operation_field("PUT", Some("PutBucketTagging"), false, "tagging"), "REST.PUT.TAGGING");
        assert_eq!(operation_field("GET", Some("ListObjectsV2"), false, "list-type=2"), "REST.GET.BUCKET");
    }

    #[test]
    fn keys() {
        let at = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 11, 3, 7, 8, 9).unwrap();
        let mut l = crate::generated::types::LoggingEnabled {
            target_bucket: "logs".into(),
            target_prefix: "access/".into(),
            ..Default::default()
        };
        let k = object_key(&l, "123456789012", "us-east-1", "data", at);
        assert!(k.starts_with("access/2026-11-03-07-08-09-"), "{k}");
        assert_eq!(k.len(), "access/2026-11-03-07-08-09-".len() + 16);
        l.target_object_key_format = Some(crate::generated::types::TargetObjectKeyFormat {
            partitioned_prefix: Some(Default::default()),
            ..Default::default()
        });
        let k = object_key(&l, "123456789012", "us-east-1", "data", at);
        assert!(k.starts_with("access/123456789012/us-east-1/data/2026/11/03/2026-11-03-07-08-09-"), "{k}");
    }
}
