//! SSE-KMS through MWS's KMS: S3 asks KMS for a data key for each object
//! (`kms:GenerateDataKey`) and decrypts it on reads (`kms:Decrypt`), with
//! the caller's permissions and `kms:ViaService` = `s3.<region>.amazonaws.com`,
//! as AWS does. The object bytes themselves are kept as written.
//!
//! Multipart uploads need `kms:GenerateDataKey` to start and `kms:Decrypt`
//! for every part and to complete, as in S3.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{RequestContext, ServiceError};

use crate::state::{ObjectVersion, Sse};
use crate::S3;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The encryption context S3 uses: `aws:s3:arn` (the object's ARN, or the
/// bucket's with S3 Bucket Keys) plus any context the caller gave in
/// `x-amz-server-side-encryption-context`, which is additional.
pub(crate) fn encryption_context(sse: &Sse, partition: &str, bucket: &str, key: &str) -> BTreeMap<String, String> {
    let mut map = sse
        .kms_context
        .as_deref()
        .and_then(|c| b64().decode(c).ok())
        .and_then(|j| serde_json::from_slice::<BTreeMap<String, String>>(&j).ok())
        .unwrap_or_default();
    let arn = if sse.bucket_key {
        format!("arn:{partition}:s3:::{bucket}")
    } else {
        format!("arn:{partition}:s3:::{bucket}/{key}")
    };
    map.insert("aws:s3:arn".to_string(), arn);
    map
}

/// KMS errors as S3 reports them.
fn s3_error(e: ServiceError) -> ServiceError {
    match &*e.code {
        "AccessDeniedException" | "AccessDenied" => ServiceError::client("AccessDenied", 403, e.message),
        "NotFoundException" => ServiceError::client("KMS.NotFoundException", 400, e.message),
        "DisabledException" => ServiceError::client("KMS.DisabledException", 400, e.message),
        "KMSInvalidStateException" => ServiceError::client("KMS.KMSInvalidStateException", 400, e.message),
        "InvalidKeyUsageException" => ServiceError::client("KMS.InvalidKeyUsageException", 400, e.message),
        "InvalidCiphertextException" => ServiceError::client("KMS.InvalidCiphertextException", 400, e.message),
        _ => ServiceError::client("KMS.".to_string() + &e.code, e.status, e.message),
    }
}

impl S3 {
    /// Fetch a data key for a new SSE-KMS object and record the key ARN.
    pub(crate) fn seal_kms(
        &self,
        ctx: &RequestContext,
        sse: &mut Sse,
        bucket: &str,
        key: &str,
    ) -> Result<(), ServiceError> {
        let Some(kms) = &self.kms else { return Ok(()) };
        if !sse.algorithm.as_deref().is_some_and(|a| a.starts_with("aws:kms")) {
            return Ok(());
        }
        let key_id = match (&sse.kms_key_id, sse.kms_default_key) {
            (Some(k), false) => k.clone(),
            _ => kms.aws_managed_key(ctx, "s3"),
        };
        let context = encryption_context(sse, &ctx.partition, bucket, key);
        let data_key = kms.generate_data_key_via(ctx, "s3", &key_id, &context, 32).map_err(s3_error)?;
        sse.kms_key_id = Some(data_key.key_arn);
        sse.kms_data_key = Some(b64().encode(&data_key.ciphertext));
        sse.kms_default_key = false;
        Ok(())
    }

    /// Reading an SSE-KMS object needs `kms:Decrypt` on its key.
    pub(crate) fn open_kms(
        &self,
        ctx: &RequestContext,
        v: &ObjectVersion,
        bucket: &str,
        key: &str,
    ) -> Result<(), ServiceError> {
        let (Some(kms), Some(data_key)) = (&self.kms, &v.sse.kms_data_key) else { return Ok(()) };
        let blob = b64().decode(data_key).unwrap_or_default();
        let context = encryption_context(&v.sse, &ctx.partition, bucket, key);
        kms.decrypt_via(ctx, "s3", &blob, &context).map_err(s3_error)?;
        Ok(())
    }
}
