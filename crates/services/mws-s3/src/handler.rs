//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Call;

#[async_trait::async_trait]
impl Handler for Call {
    async fn abort_multipart_upload(
        &self,
        ctx: &RequestContext,
        input: types::AbortMultipartUploadRequest,
    ) -> Result<types::AbortMultipartUploadOutput, ServiceError> {
        Call::abort_multipart_upload(self, ctx, input)
    }
    async fn complete_multipart_upload(
        &self,
        ctx: &RequestContext,
        input: types::CompleteMultipartUploadRequest,
    ) -> Result<types::CompleteMultipartUploadOutput, ServiceError> {
        let (bucket, key) = (input.bucket.clone(), input.key.clone());
        let out = Call::complete_multipart_upload(self, ctx, input)?;
        let v = out.version_id.clone();
        self.object_event(
            ctx,
            &bucket,
            &key,
            v.as_deref(),
            ("ObjectCreated:CompleteMultipartUpload", "CompleteMultipartUpload", None),
        );
        Ok(out)
    }
    async fn copy_object(
        &self,
        ctx: &RequestContext,
        input: types::CopyObjectRequest,
    ) -> Result<types::CopyObjectOutput, ServiceError> {
        let (bucket, key) = (input.bucket.clone(), input.key.clone());
        let out = Call::copy_object(self, ctx, input)?;
        let v = out.version_id.clone();
        self.object_event(ctx, &bucket, &key, v.as_deref(), ("ObjectCreated:Copy", "CopyObject", None));
        Ok(out)
    }
    async fn create_bucket(
        &self,
        ctx: &RequestContext,
        input: types::CreateBucketRequest,
    ) -> Result<types::CreateBucketOutput, ServiceError> {
        Call::create_bucket(self, ctx, input)
    }
    async fn create_multipart_upload(
        &self,
        ctx: &RequestContext,
        input: types::CreateMultipartUploadRequest,
    ) -> Result<types::CreateMultipartUploadOutput, ServiceError> {
        Call::create_multipart_upload(self, ctx, input)
    }
    async fn delete_bucket(&self, ctx: &RequestContext, input: types::DeleteBucketRequest) -> Result<(), ServiceError> {
        Call::delete_bucket(self, ctx, input)
    }
    async fn delete_bucket_analytics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketAnalyticsConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_analytics_configuration(self, ctx, input)
    }
    async fn delete_bucket_cors(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketCorsRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_cors(self, ctx, input)
    }
    async fn delete_bucket_encryption(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketEncryptionRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_encryption(self, ctx, input)
    }
    async fn delete_bucket_intelligent_tiering_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketIntelligentTieringConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_intelligent_tiering_configuration(self, ctx, input)
    }
    async fn delete_bucket_inventory_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketInventoryConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_inventory_configuration(self, ctx, input)
    }
    async fn delete_bucket_lifecycle(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketLifecycleRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_lifecycle(self, ctx, input)
    }
    async fn delete_bucket_metrics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketMetricsConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_metrics_configuration(self, ctx, input)
    }
    async fn delete_bucket_ownership_controls(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketOwnershipControlsRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_ownership_controls(self, ctx, input)
    }
    async fn delete_bucket_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketPolicyRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_policy(self, ctx, input)
    }
    async fn delete_bucket_replication(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketReplicationRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_replication(self, ctx, input)
    }
    async fn delete_bucket_tagging(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketTaggingRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_tagging(self, ctx, input)
    }
    async fn delete_bucket_website(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketWebsiteRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_website(self, ctx, input)
    }
    async fn delete_object(
        &self,
        ctx: &RequestContext,
        input: types::DeleteObjectRequest,
    ) -> Result<types::DeleteObjectOutput, ServiceError> {
        let (bucket, key) = (input.bucket.clone(), input.key.clone());
        let requested = input.version_id.clone();
        let out = Call::delete_object(self, ctx, input)?;
        if out.delete_marker == Some(true) && requested.is_none() {
            let v = out.version_id.clone();
            self.object_event(
                ctx,
                &bucket,
                &key,
                v.as_deref(),
                ("ObjectRemoved:DeleteMarkerCreated", "DeleteObject", Some("Delete Marker Created")),
            );
        } else {
            let v = out.version_id.clone().or(requested);
            self.object_event(
                ctx,
                &bucket,
                &key,
                v.as_deref(),
                ("ObjectRemoved:Delete", "DeleteObject", Some("Permanently Deleted")),
            );
        }
        Ok(out)
    }
    async fn delete_object_tagging(
        &self,
        ctx: &RequestContext,
        input: types::DeleteObjectTaggingRequest,
    ) -> Result<types::DeleteObjectTaggingOutput, ServiceError> {
        let (bucket, key) = (input.bucket.clone(), input.key.clone());
        let out = Call::delete_object_tagging(self, ctx, input)?;
        let v = out.version_id.clone();
        self.object_event(ctx, &bucket, &key, v.as_deref(), ("ObjectTagging:Delete", "DeleteObjectTagging", None));
        Ok(out)
    }
    async fn delete_objects(
        &self,
        ctx: &RequestContext,
        input: types::DeleteObjectsRequest,
    ) -> Result<types::DeleteObjectsOutput, ServiceError> {
        let bucket = input.bucket.clone();
        let out = Call::delete_objects(self, ctx, input)?;
        for d in out.deleted.iter().flatten() {
            let key = d.key.clone().unwrap_or_default();
            if d.delete_marker == Some(true) && d.version_id.is_none() {
                let v = d.delete_marker_version_id.clone();
                self.object_event(
                    ctx,
                    &bucket,
                    &key,
                    v.as_deref(),
                    ("ObjectRemoved:DeleteMarkerCreated", "DeleteObjects", Some("Delete Marker Created")),
                );
            } else {
                let v = d.version_id.clone();
                self.object_event(
                    ctx,
                    &bucket,
                    &key,
                    v.as_deref(),
                    ("ObjectRemoved:Delete", "DeleteObjects", Some("Permanently Deleted")),
                );
            }
        }
        Ok(out)
    }
    async fn delete_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::DeletePublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_public_access_block(self, ctx, input)
    }
    async fn get_bucket_abac(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketAbacRequest,
    ) -> Result<types::GetBucketAbacOutput, ServiceError> {
        Call::get_bucket_abac(self, ctx, input)
    }
    async fn get_bucket_accelerate_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketAccelerateConfigurationRequest,
    ) -> Result<types::GetBucketAccelerateConfigurationOutput, ServiceError> {
        Call::get_bucket_accelerate_configuration(self, ctx, input)
    }
    async fn get_bucket_acl(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketAclRequest,
    ) -> Result<types::GetBucketAclOutput, ServiceError> {
        Call::get_bucket_acl(self, ctx, input)
    }
    async fn get_bucket_analytics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketAnalyticsConfigurationRequest,
    ) -> Result<types::GetBucketAnalyticsConfigurationOutput, ServiceError> {
        Call::get_bucket_analytics_configuration(self, ctx, input)
    }
    async fn get_bucket_cors(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketCorsRequest,
    ) -> Result<types::GetBucketCorsOutput, ServiceError> {
        Call::get_bucket_cors(self, ctx, input)
    }
    async fn get_bucket_encryption(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketEncryptionRequest,
    ) -> Result<types::GetBucketEncryptionOutput, ServiceError> {
        Call::get_bucket_encryption(self, ctx, input)
    }
    async fn get_bucket_intelligent_tiering_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketIntelligentTieringConfigurationRequest,
    ) -> Result<types::GetBucketIntelligentTieringConfigurationOutput, ServiceError> {
        Call::get_bucket_intelligent_tiering_configuration(self, ctx, input)
    }
    async fn get_bucket_inventory_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketInventoryConfigurationRequest,
    ) -> Result<types::GetBucketInventoryConfigurationOutput, ServiceError> {
        Call::get_bucket_inventory_configuration(self, ctx, input)
    }
    async fn get_bucket_lifecycle_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketLifecycleConfigurationRequest,
    ) -> Result<types::GetBucketLifecycleConfigurationOutput, ServiceError> {
        Call::get_bucket_lifecycle_configuration(self, ctx, input)
    }
    async fn get_bucket_location(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketLocationRequest,
    ) -> Result<types::GetBucketLocationOutput, ServiceError> {
        Call::get_bucket_location(self, ctx, input)
    }
    async fn get_bucket_logging(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketLoggingRequest,
    ) -> Result<types::GetBucketLoggingOutput, ServiceError> {
        Call::get_bucket_logging(self, ctx, input)
    }
    async fn get_bucket_metrics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketMetricsConfigurationRequest,
    ) -> Result<types::GetBucketMetricsConfigurationOutput, ServiceError> {
        Call::get_bucket_metrics_configuration(self, ctx, input)
    }
    async fn get_bucket_notification_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketNotificationConfigurationRequest,
    ) -> Result<types::NotificationConfiguration, ServiceError> {
        Call::get_bucket_notification_configuration(self, ctx, input)
    }
    async fn get_bucket_ownership_controls(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketOwnershipControlsRequest,
    ) -> Result<types::GetBucketOwnershipControlsOutput, ServiceError> {
        Call::get_bucket_ownership_controls(self, ctx, input)
    }
    async fn get_bucket_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketPolicyRequest,
    ) -> Result<types::GetBucketPolicyOutput, ServiceError> {
        Call::get_bucket_policy(self, ctx, input)
    }
    async fn get_bucket_policy_status(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketPolicyStatusRequest,
    ) -> Result<types::GetBucketPolicyStatusOutput, ServiceError> {
        Call::get_bucket_policy_status(self, ctx, input)
    }
    async fn get_bucket_replication(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketReplicationRequest,
    ) -> Result<types::GetBucketReplicationOutput, ServiceError> {
        Call::get_bucket_replication(self, ctx, input)
    }
    async fn get_bucket_request_payment(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketRequestPaymentRequest,
    ) -> Result<types::GetBucketRequestPaymentOutput, ServiceError> {
        Call::get_bucket_request_payment(self, ctx, input)
    }
    async fn get_bucket_tagging(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketTaggingRequest,
    ) -> Result<types::GetBucketTaggingOutput, ServiceError> {
        Call::get_bucket_tagging(self, ctx, input)
    }
    async fn get_bucket_versioning(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketVersioningRequest,
    ) -> Result<types::GetBucketVersioningOutput, ServiceError> {
        Call::get_bucket_versioning(self, ctx, input)
    }
    async fn get_bucket_website(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketWebsiteRequest,
    ) -> Result<types::GetBucketWebsiteOutput, ServiceError> {
        Call::get_bucket_website(self, ctx, input)
    }
    async fn get_object(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectRequest,
    ) -> Result<types::GetObjectOutput, ServiceError> {
        Call::get_object(self, ctx, input)
    }
    async fn get_object_acl(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectAclRequest,
    ) -> Result<types::GetObjectAclOutput, ServiceError> {
        Call::get_object_acl(self, ctx, input)
    }
    async fn get_object_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectAttributesRequest,
    ) -> Result<types::GetObjectAttributesOutput, ServiceError> {
        Call::get_object_attributes(self, ctx, input)
    }
    async fn get_object_legal_hold(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectLegalHoldRequest,
    ) -> Result<types::GetObjectLegalHoldOutput, ServiceError> {
        Call::get_object_legal_hold(self, ctx, input)
    }
    async fn get_object_lock_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectLockConfigurationRequest,
    ) -> Result<types::GetObjectLockConfigurationOutput, ServiceError> {
        Call::get_object_lock_configuration(self, ctx, input)
    }
    async fn get_object_retention(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectRetentionRequest,
    ) -> Result<types::GetObjectRetentionOutput, ServiceError> {
        Call::get_object_retention(self, ctx, input)
    }
    async fn get_object_tagging(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectTaggingRequest,
    ) -> Result<types::GetObjectTaggingOutput, ServiceError> {
        Call::get_object_tagging(self, ctx, input)
    }
    async fn get_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::GetPublicAccessBlockRequest,
    ) -> Result<types::GetPublicAccessBlockOutput, ServiceError> {
        Call::get_public_access_block(self, ctx, input)
    }
    async fn head_bucket(
        &self,
        ctx: &RequestContext,
        input: types::HeadBucketRequest,
    ) -> Result<types::HeadBucketOutput, ServiceError> {
        Call::head_bucket(self, ctx, input)
    }
    async fn head_object(
        &self,
        ctx: &RequestContext,
        input: types::HeadObjectRequest,
    ) -> Result<types::HeadObjectOutput, ServiceError> {
        Call::head_object(self, ctx, input)
    }
    async fn list_bucket_analytics_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListBucketAnalyticsConfigurationsRequest,
    ) -> Result<types::ListBucketAnalyticsConfigurationsOutput, ServiceError> {
        Call::list_bucket_analytics_configurations(self, ctx, input)
    }
    async fn list_bucket_intelligent_tiering_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListBucketIntelligentTieringConfigurationsRequest,
    ) -> Result<types::ListBucketIntelligentTieringConfigurationsOutput, ServiceError> {
        Call::list_bucket_intelligent_tiering_configurations(self, ctx, input)
    }
    async fn list_bucket_inventory_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListBucketInventoryConfigurationsRequest,
    ) -> Result<types::ListBucketInventoryConfigurationsOutput, ServiceError> {
        Call::list_bucket_inventory_configurations(self, ctx, input)
    }
    async fn list_bucket_metrics_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListBucketMetricsConfigurationsRequest,
    ) -> Result<types::ListBucketMetricsConfigurationsOutput, ServiceError> {
        Call::list_bucket_metrics_configurations(self, ctx, input)
    }
    async fn list_buckets(
        &self,
        ctx: &RequestContext,
        input: types::ListBucketsRequest,
    ) -> Result<types::ListBucketsOutput, ServiceError> {
        Call::list_buckets(self, ctx, input)
    }
    async fn list_directory_buckets(
        &self,
        ctx: &RequestContext,
        input: types::ListDirectoryBucketsRequest,
    ) -> Result<types::ListDirectoryBucketsOutput, ServiceError> {
        Call::list_directory_buckets(self, ctx, input)
    }
    async fn list_multipart_uploads(
        &self,
        ctx: &RequestContext,
        input: types::ListMultipartUploadsRequest,
    ) -> Result<types::ListMultipartUploadsOutput, ServiceError> {
        Call::list_multipart_uploads(self, ctx, input)
    }
    async fn list_object_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListObjectVersionsRequest,
    ) -> Result<types::ListObjectVersionsOutput, ServiceError> {
        Call::list_object_versions(self, ctx, input)
    }
    async fn list_objects(
        &self,
        ctx: &RequestContext,
        input: types::ListObjectsRequest,
    ) -> Result<types::ListObjectsOutput, ServiceError> {
        Call::list_objects(self, ctx, input)
    }
    async fn list_objects_v2(
        &self,
        ctx: &RequestContext,
        input: types::ListObjectsV2Request,
    ) -> Result<types::ListObjectsV2Output, ServiceError> {
        Call::list_objects_v2(self, ctx, input)
    }
    async fn list_parts(
        &self,
        ctx: &RequestContext,
        input: types::ListPartsRequest,
    ) -> Result<types::ListPartsOutput, ServiceError> {
        Call::list_parts(self, ctx, input)
    }
    async fn put_bucket_abac(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketAbacRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_abac(self, ctx, input)
    }
    async fn put_bucket_accelerate_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketAccelerateConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_accelerate_configuration(self, ctx, input)
    }
    async fn put_bucket_acl(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketAclRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_acl(self, ctx, input)
    }
    async fn put_bucket_analytics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketAnalyticsConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_analytics_configuration(self, ctx, input)
    }
    async fn put_bucket_cors(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketCorsRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_cors(self, ctx, input)
    }
    async fn put_bucket_encryption(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketEncryptionRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_encryption(self, ctx, input)
    }
    async fn put_bucket_intelligent_tiering_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketIntelligentTieringConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_intelligent_tiering_configuration(self, ctx, input)
    }
    async fn put_bucket_inventory_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketInventoryConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_inventory_configuration(self, ctx, input)
    }
    async fn put_bucket_lifecycle_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketLifecycleConfigurationRequest,
    ) -> Result<types::PutBucketLifecycleConfigurationOutput, ServiceError> {
        Call::put_bucket_lifecycle_configuration(self, ctx, input)
    }
    async fn put_bucket_logging(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketLoggingRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_logging(self, ctx, input)
    }
    async fn put_bucket_metrics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketMetricsConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_metrics_configuration(self, ctx, input)
    }
    async fn put_bucket_notification_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketNotificationConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_notification_configuration(self, ctx, input)
    }
    async fn put_bucket_ownership_controls(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketOwnershipControlsRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_ownership_controls(self, ctx, input)
    }
    async fn put_bucket_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketPolicyRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_policy(self, ctx, input)
    }
    async fn put_bucket_replication(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketReplicationRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_replication(self, ctx, input)
    }
    async fn put_bucket_request_payment(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketRequestPaymentRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_request_payment(self, ctx, input)
    }
    async fn put_bucket_tagging(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketTaggingRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_tagging(self, ctx, input)
    }
    async fn put_bucket_versioning(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketVersioningRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_versioning(self, ctx, input)
    }
    async fn put_bucket_website(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketWebsiteRequest,
    ) -> Result<(), ServiceError> {
        Call::put_bucket_website(self, ctx, input)
    }
    async fn put_object(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectRequest,
    ) -> Result<types::PutObjectOutput, ServiceError> {
        let (bucket, key) = (input.bucket.clone(), input.key.clone());
        let out = Call::put_object(self, ctx, input)?;
        let v = out.version_id.clone();
        let what = if self.form_post {
            ("ObjectCreated:Post", "PostObject", None)
        } else {
            ("ObjectCreated:Put", "PutObject", None)
        };
        self.object_event(ctx, &bucket, &key, v.as_deref(), what);
        Ok(out)
    }
    async fn put_object_acl(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectAclRequest,
    ) -> Result<types::PutObjectAclOutput, ServiceError> {
        let (bucket, key, v) = (input.bucket.clone(), input.key.clone(), input.version_id.clone());
        let out = Call::put_object_acl(self, ctx, input)?;
        self.object_event(ctx, &bucket, &key, v.as_deref(), ("ObjectAcl:Put", "PutObjectAcl", None));
        Ok(out)
    }
    async fn put_object_legal_hold(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectLegalHoldRequest,
    ) -> Result<types::PutObjectLegalHoldOutput, ServiceError> {
        Call::put_object_legal_hold(self, ctx, input)
    }
    async fn put_object_lock_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectLockConfigurationRequest,
    ) -> Result<types::PutObjectLockConfigurationOutput, ServiceError> {
        Call::put_object_lock_configuration(self, ctx, input)
    }
    async fn put_object_retention(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectRetentionRequest,
    ) -> Result<types::PutObjectRetentionOutput, ServiceError> {
        Call::put_object_retention(self, ctx, input)
    }
    async fn put_object_tagging(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectTaggingRequest,
    ) -> Result<types::PutObjectTaggingOutput, ServiceError> {
        let (bucket, key) = (input.bucket.clone(), input.key.clone());
        let out = Call::put_object_tagging(self, ctx, input)?;
        let v = out.version_id.clone();
        self.object_event(ctx, &bucket, &key, v.as_deref(), ("ObjectTagging:Put", "PutObjectTagging", None));
        Ok(out)
    }
    async fn put_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::PutPublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        Call::put_public_access_block(self, ctx, input)
    }
    async fn restore_object(
        &self,
        ctx: &RequestContext,
        input: types::RestoreObjectRequest,
    ) -> Result<types::RestoreObjectOutput, ServiceError> {
        let (bucket, key, v) = (input.bucket.clone(), input.key.clone(), input.version_id.clone());
        let out = Call::restore_object(self, ctx, input)?;
        self.object_event(ctx, &bucket, &key, v.as_deref(), ("ObjectRestore:Post", "RestoreObject", None));
        Ok(out)
    }
    async fn update_object_encryption(
        &self,
        ctx: &RequestContext,
        input: types::UpdateObjectEncryptionRequest,
    ) -> Result<types::UpdateObjectEncryptionResponse, ServiceError> {
        Call::update_object_encryption(self, ctx, input)
    }
    async fn upload_part(
        &self,
        ctx: &RequestContext,
        input: types::UploadPartRequest,
    ) -> Result<types::UploadPartOutput, ServiceError> {
        Call::upload_part(self, ctx, input)
    }
    async fn upload_part_copy(
        &self,
        ctx: &RequestContext,
        input: types::UploadPartCopyRequest,
    ) -> Result<types::UploadPartCopyOutput, ServiceError> {
        Call::upload_part_copy(self, ctx, input)
    }
    async fn put_object_annotation(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectAnnotationRequest,
    ) -> Result<types::PutObjectAnnotationOutput, ServiceError> {
        Call::put_object_annotation(self, ctx, input)
    }
    async fn get_object_annotation(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectAnnotationRequest,
    ) -> Result<types::GetObjectAnnotationOutput, ServiceError> {
        Call::get_object_annotation(self, ctx, input)
    }
    async fn list_object_annotations(
        &self,
        ctx: &RequestContext,
        input: types::ListObjectAnnotationsRequest,
    ) -> Result<types::ListObjectAnnotationsOutput, ServiceError> {
        Call::list_object_annotations(self, ctx, input)
    }
    async fn delete_object_annotation(
        &self,
        ctx: &RequestContext,
        input: types::DeleteObjectAnnotationRequest,
    ) -> Result<types::DeleteObjectAnnotationOutput, ServiceError> {
        Call::delete_object_annotation(self, ctx, input)
    }
    async fn get_object_torrent(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectTorrentRequest,
    ) -> Result<types::GetObjectTorrentOutput, ServiceError> {
        Call::get_object_torrent(self, ctx, input)
    }
    async fn create_bucket_metadata_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateBucketMetadataConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::create_bucket_metadata_configuration(self, ctx, input)
    }
    async fn get_bucket_metadata_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketMetadataConfigurationRequest,
    ) -> Result<types::GetBucketMetadataConfigurationOutput, ServiceError> {
        Call::get_bucket_metadata_configuration(self, ctx, input)
    }
    async fn delete_bucket_metadata_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketMetadataConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_metadata_configuration(self, ctx, input)
    }
    async fn update_bucket_metadata_journal_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateBucketMetadataJournalTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::update_bucket_metadata_journal_table_configuration(self, ctx, input)
    }
    async fn update_bucket_metadata_inventory_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateBucketMetadataInventoryTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::update_bucket_metadata_inventory_table_configuration(self, ctx, input)
    }
    async fn update_bucket_metadata_annotation_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateBucketMetadataAnnotationTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::update_bucket_metadata_annotation_table_configuration(self, ctx, input)
    }
    async fn create_bucket_metadata_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateBucketMetadataTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::create_bucket_metadata_table_configuration(self, ctx, input)
    }
    async fn get_bucket_metadata_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketMetadataTableConfigurationRequest,
    ) -> Result<types::GetBucketMetadataTableConfigurationOutput, ServiceError> {
        Call::get_bucket_metadata_table_configuration(self, ctx, input)
    }
    async fn delete_bucket_metadata_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketMetadataTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Call::delete_bucket_metadata_table_configuration(self, ctx, input)
    }
    async fn select_object_content(
        &self,
        ctx: &RequestContext,
        input: types::SelectObjectContentRequest,
    ) -> Result<types::SelectObjectContentOutput, ServiceError> {
        Call::select_object_content(self, ctx, input)
    }
    async fn create_session(
        &self,
        ctx: &RequestContext,
        input: types::CreateSessionRequest,
    ) -> Result<types::CreateSessionOutput, ServiceError> {
        Call::create_session(self, ctx, input)
    }
    async fn rename_object(
        &self,
        ctx: &RequestContext,
        input: types::RenameObjectRequest,
    ) -> Result<types::RenameObjectOutput, ServiceError> {
        Call::rename_object(self, ctx, input)
    }
    async fn write_get_object_response(
        &self,
        ctx: &RequestContext,
        input: types::WriteGetObjectResponseRequest,
    ) -> Result<(), ServiceError> {
        Call::write_get_object_response(self, ctx, input)
    }
}
