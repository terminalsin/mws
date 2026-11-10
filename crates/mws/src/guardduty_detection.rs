//! GuardDuty's threat detection wiring: the CloudTrail management events
//! it analyses, its service-linked role in IAM and the threat list files
//! it reads from S3.

use std::sync::Arc;

use mws_core::RequestContext;

/// The IAM policy AWS attaches to `AWSServiceRoleForAmazonGuardDuty`.
const ROLE_POLICY: &str = "AmazonGuardDutyServiceRolePolicy";

/// Every event CloudTrail records, for GuardDuty to analyse its management
/// events.
struct CloudTrailToGuardDuty(mws_guardduty::GuardDuty);

impl mws_cloudtrail::EventSubscriber for CloudTrailToGuardDuty {
    fn on_event(&self, ctx: &RequestContext, event: &mws_cloudtrail::record::Recorded) {
        // Data events are not analysed, but keep the emulated clock fresh
        // for publishing.
        self.0.observe_management_event(ctx, &event.record);
    }
}

/// `AWSServiceRoleForAmazonGuardDuty` in IAM.
struct GuardDutyServiceRole {
    iam: mws_iam::Iam,
    partition: String,
}

impl mws_guardduty::ServiceLinkedRoles for GuardDutyServiceRole {
    fn exists(&self, account: &str) -> bool {
        let arn = format!(
            "arn:{}:iam::{account}:role/aws-service-role/{}/AWSServiceRoleForAmazonGuardDuty",
            self.partition,
            mws_guardduty::SERVICE_PRINCIPAL
        );
        self.iam.role_by_arn(&arn).is_some()
    }

    fn ensure(&self, account: &str) {
        self.iam.ensure_service_linked_role(account, mws_guardduty::SERVICE_PRINCIPAL, ROLE_POLICY);
    }
}

/// Threat list files, read as the account's GuardDuty service-linked role:
/// GuardDuty grants that role access to the file in the same account
/// (which is why changing lists needs `iam:PutRolePolicy`); a bucket in
/// another account must allow `guardduty.amazonaws.com` in its policy.
struct GuardDutyThreatLists(mws_s3::S3);

impl mws_guardduty::ThreatListSource for GuardDutyThreatLists {
    fn read(
        &self,
        partition: &str,
        account: &str,
        detector_arn: &str,
        bucket: &str,
        key: &str,
        expected_bucket_owner: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        let owner = self.0.bucket_owner(bucket).ok_or_else(|| "NoSuchBucket".to_string())?;
        if expected_bucket_owner.is_some_and(|o| o != owner) {
            return Err("AccessDenied".into());
        }
        if owner == account {
            return self.0.object_bytes(bucket, key).ok_or_else(|| "NoSuchKey".to_string());
        }
        let read = mws_s3::ServiceRead {
            bucket,
            service_principal: mws_guardduty::SERVICE_PRINCIPAL,
            source_account: account,
            source_arn: detector_arn,
            partition,
        };
        match self.0.get_object_as_service(&read, key) {
            Ok(Some(body)) => Ok(body),
            Ok(None) => Err("NoSuchKey".into()),
            Err(mws_s3::ServicePutError::NoSuchBucket) => Err("NoSuchBucket".into()),
            Err(_) => Err("AccessDenied".into()),
        }
    }
}

/// Connect GuardDuty to CloudTrail, IAM and S3.
pub(crate) fn wire(
    guardduty: &mws_guardduty::GuardDuty,
    cloudtrail: &mws_cloudtrail::CloudTrail,
    iam: &mws_iam::Iam,
    s3: &mws_s3::S3,
    partition: &str,
) {
    cloudtrail.add_event_subscriber(Arc::new(CloudTrailToGuardDuty(guardduty.clone())));
    guardduty
        .set_service_linked_roles(Arc::new(GuardDutyServiceRole { iam: iam.clone(), partition: partition.into() }));
    guardduty.set_threat_list_source(Arc::new(GuardDutyThreatLists(s3.clone())));
}
