//! S3 event notifications published to topics as `s3.amazonaws.com`,
//! judged by the topic policy alone, as in AWS.

use mws_core::RequestContext;
use mws_s3::{NotificationDestination, NotificationSource};

use crate::{ServicePublish, ServicePublishError, Sns};

const S3_PRINCIPAL: &str = "s3.amazonaws.com";

fn request<'a>(arn: &'a str, source: &'a NotificationSource<'_>, message: String) -> ServicePublish<'a> {
    ServicePublish {
        topic_arn: arn,
        service_principal: S3_PRINCIPAL,
        source_arn: source.bucket_arn,
        source_account: source.bucket_owner,
        message,
        subject: Some("Amazon S3 Notification".to_string()),
        attributes: Default::default(),
        message_group_id: None,
        message_deduplication_id: None,
    }
}

impl NotificationDestination for Sns {
    fn service(&self) -> &'static str {
        "sns"
    }

    fn check(&self, _ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>) -> Result<(), String> {
        match self.check_service_publish(&request(arn, source, String::new())) {
            Ok(()) => Ok(()),
            Err(ServicePublishError::NoSuchTopic) => Err("The destination topic does not exist".to_string()),
            Err(_) => {
                Err("Permissions on the destination topic do not allow S3 to publish notifications from this bucket"
                    .to_string())
            }
        }
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>, message: String) {
        if let Err(e) = self.publish_as_service(ctx, &request(arn, source, message)) {
            tracing::warn!(topic = arn, "S3 could not publish a notification: {e}");
        }
    }
}
