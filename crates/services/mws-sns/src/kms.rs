//! Server-side encryption of topics (`KmsMasterKeyId`).
//!
//! SNS encrypts every message published to an encrypted topic under a data
//! key from KMS, so publishers need `kms:GenerateDataKey*` and `kms:Decrypt`
//! on the topic's key. Callers publish with their own permissions (and
//! `kms:ViaService` = `sns.<region>.amazonaws.com`, which is what the AWS
//! managed key `alias/aws/sns` allows); AWS service principals publishing
//! for a bucket or a rule (S3 events, EventBridge, ...) need the key policy
//! to allow the service principal, which the AWS managed key never does.
//! KMS failures come back as SNS's `KMS*` errors.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::state::Topic;
use crate::{errors, Sns};

/// The encryption context SNS uses for a topic's data keys.
fn context(topic_arn: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("aws:sns:topicArn".to_string(), topic_arn.to_string())])
}

/// A KMS error as SNS reports it.
pub(crate) fn sns_error(e: ServiceError) -> ServiceError {
    let message = e.message.clone();
    match e.code.as_ref() {
        "NotFoundException" | "InvalidArnException" => errors::kms_not_found(message),
        "DisabledException" => errors::kms_disabled(message),
        "KMSInvalidStateException" | "InvalidKeyUsageException" => errors::kms_invalid_state(message),
        "AccessDeniedException" | "AccessDenied" => errors::kms_access_denied(message),
        "ThrottlingException" => errors::kms_throttling(message),
        _ => e,
    }
}

/// The topic's key as a key or alias ARN, if it is encrypted.
fn key_reference(topic: &Topic) -> Option<String> {
    let key = topic.attributes.get("KmsMasterKeyId").filter(|k| !k.is_empty())?;
    let partition = topic.arn.split(':').nth(1).unwrap_or("aws");
    Some(if key.starts_with("arn:") {
        key.clone()
    } else if key.starts_with("alias/") {
        format!("arn:{partition}:kms:{}:{}:{key}", topic.region, topic.account)
    } else {
        format!("arn:{partition}:kms:{}:{}:key/{key}", topic.region, topic.account)
    })
}

fn is_aws_managed(key: &str) -> bool {
    key.ends_with(":alias/aws/sns")
}

impl Sns {
    /// Encrypt a message for `topic` with the caller's permissions: a data
    /// key from `kms:GenerateDataKey`, which the caller must also be able
    /// to `kms:Decrypt`. Topics without a key pass straight through.
    pub(crate) fn seal_for_caller(&self, ctx: &RequestContext, topic: &Topic) -> Result<(), ServiceError> {
        let (Some(kms), Some(key)) = (self.inner.kms.get(), key_reference(topic)) else { return Ok(()) };
        let key = if is_aws_managed(&key) {
            let scoped = RequestContext { region: topic.region.clone(), ..ctx.clone() };
            kms.aws_managed_key(&scoped, "sns")
        } else {
            key
        };
        let context = context(&topic.arn);
        let data_key = kms.generate_data_key_via(ctx, "sns", &key, &context, 32).map_err(sns_error)?;
        kms.decrypt_via(ctx, "sns", &data_key.ciphertext, &context).map_err(sns_error)?;
        Ok(())
    }

    /// The same check for an AWS service principal publishing on behalf
    /// of `source_arn`: the key policy alone decides.
    pub(crate) fn seal_for_service(
        &self,
        topic: &Topic,
        service_principal: &str,
        source_arn: &str,
        source_account: &str,
    ) -> Result<(), ServiceError> {
        let (Some(kms), Some(key)) = (self.inner.kms.get(), key_reference(topic)) else { return Ok(()) };
        if is_aws_managed(&key) {
            return Err(errors::kms_access_denied(format!(
                "{service_principal} is not authorized to perform: kms:GenerateDataKey on the AWS managed key alias/aws/sns"
            )));
        }
        let mut conditions = mws_core::ConditionContext::new();
        conditions.insert("aws:SourceArn".into(), vec![source_arn.to_string()]);
        conditions.insert("aws:SourceAccount".into(), vec![source_account.to_string()]);
        let k = kms
            .key_for_service(&key, service_principal, &["kms:GenerateDataKey", "kms:Decrypt"], &conditions)
            .map_err(sns_error)?;
        match k.key_state.as_str() {
            "Enabled" => Ok(()),
            "Disabled" => Err(errors::kms_disabled(format!("{} is disabled.", k.arn))),
            state => Err(errors::kms_invalid_state(format!("{} is {state}.", k.arn))),
        }
    }
}
