//! The generated `Handler`, forwarding to the operations and putting
//! errors in SNS's words.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::{errors, Sns};

#[async_trait::async_trait]
impl Handler for Sns {
    async fn add_permission(&self, ctx: &RequestContext, input: types::AddPermissionInput) -> Result<(), ServiceError> {
        self.add_permission_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn check_if_phone_number_is_opted_out(
        &self,
        ctx: &RequestContext,
        input: types::CheckIfPhoneNumberIsOptedOutInput,
    ) -> Result<types::CheckIfPhoneNumberIsOptedOutResponse, ServiceError> {
        self.check_if_phone_number_is_opted_out_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn confirm_subscription(
        &self,
        ctx: &RequestContext,
        input: types::ConfirmSubscriptionInput,
    ) -> Result<types::ConfirmSubscriptionResponse, ServiceError> {
        self.confirm_subscription_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn create_platform_application(
        &self,
        ctx: &RequestContext,
        input: types::CreatePlatformApplicationInput,
    ) -> Result<types::CreatePlatformApplicationResponse, ServiceError> {
        self.create_platform_application_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn create_platform_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::CreatePlatformEndpointInput,
    ) -> Result<types::CreateEndpointResponse, ServiceError> {
        self.create_platform_endpoint_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn create_sms_sandbox_phone_number(
        &self,
        ctx: &RequestContext,
        input: types::CreateSMSSandboxPhoneNumberInput,
    ) -> Result<types::CreateSMSSandboxPhoneNumberResult, ServiceError> {
        self.create_sms_sandbox_phone_number_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn create_topic(
        &self,
        ctx: &RequestContext,
        input: types::CreateTopicInput,
    ) -> Result<types::CreateTopicResponse, ServiceError> {
        self.create_topic_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn delete_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEndpointInput,
    ) -> Result<(), ServiceError> {
        self.delete_endpoint_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn delete_platform_application(
        &self,
        ctx: &RequestContext,
        input: types::DeletePlatformApplicationInput,
    ) -> Result<(), ServiceError> {
        self.delete_platform_application_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn delete_sms_sandbox_phone_number(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSMSSandboxPhoneNumberInput,
    ) -> Result<types::DeleteSMSSandboxPhoneNumberResult, ServiceError> {
        self.delete_sms_sandbox_phone_number_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn delete_topic(&self, ctx: &RequestContext, input: types::DeleteTopicInput) -> Result<(), ServiceError> {
        self.delete_topic_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn get_data_protection_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetDataProtectionPolicyInput,
    ) -> Result<types::GetDataProtectionPolicyResponse, ServiceError> {
        self.get_data_protection_policy_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn get_endpoint_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetEndpointAttributesInput,
    ) -> Result<types::GetEndpointAttributesResponse, ServiceError> {
        self.get_endpoint_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn get_platform_application_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetPlatformApplicationAttributesInput,
    ) -> Result<types::GetPlatformApplicationAttributesResponse, ServiceError> {
        self.get_platform_application_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn get_sms_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetSMSAttributesInput,
    ) -> Result<types::GetSMSAttributesResponse, ServiceError> {
        self.get_sms_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn get_sms_sandbox_account_status(
        &self,
        ctx: &RequestContext,
        _input: types::GetSMSSandboxAccountStatusInput,
    ) -> Result<types::GetSMSSandboxAccountStatusResult, ServiceError> {
        self.get_sms_sandbox_account_status_impl(ctx).map_err(errors::sns_error)
    }

    async fn get_subscription_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetSubscriptionAttributesInput,
    ) -> Result<types::GetSubscriptionAttributesResponse, ServiceError> {
        self.get_subscription_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn get_topic_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetTopicAttributesInput,
    ) -> Result<types::GetTopicAttributesResponse, ServiceError> {
        self.get_topic_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_endpoints_by_platform_application(
        &self,
        ctx: &RequestContext,
        input: types::ListEndpointsByPlatformApplicationInput,
    ) -> Result<types::ListEndpointsByPlatformApplicationResponse, ServiceError> {
        self.list_endpoints_by_platform_application_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_origination_numbers(
        &self,
        ctx: &RequestContext,
        input: types::ListOriginationNumbersRequest,
    ) -> Result<types::ListOriginationNumbersResult, ServiceError> {
        self.list_origination_numbers_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_phone_numbers_opted_out(
        &self,
        ctx: &RequestContext,
        input: types::ListPhoneNumbersOptedOutInput,
    ) -> Result<types::ListPhoneNumbersOptedOutResponse, ServiceError> {
        self.list_phone_numbers_opted_out_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_platform_applications(
        &self,
        ctx: &RequestContext,
        input: types::ListPlatformApplicationsInput,
    ) -> Result<types::ListPlatformApplicationsResponse, ServiceError> {
        self.list_platform_applications_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_sms_sandbox_phone_numbers(
        &self,
        ctx: &RequestContext,
        input: types::ListSMSSandboxPhoneNumbersInput,
    ) -> Result<types::ListSMSSandboxPhoneNumbersResult, ServiceError> {
        self.list_sms_sandbox_phone_numbers_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_subscriptions(
        &self,
        ctx: &RequestContext,
        input: types::ListSubscriptionsInput,
    ) -> Result<types::ListSubscriptionsResponse, ServiceError> {
        self.list_subscriptions_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_subscriptions_by_topic(
        &self,
        ctx: &RequestContext,
        input: types::ListSubscriptionsByTopicInput,
    ) -> Result<types::ListSubscriptionsByTopicResponse, ServiceError> {
        self.list_subscriptions_by_topic_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.list_tags_for_resource_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn list_topics(
        &self,
        ctx: &RequestContext,
        input: types::ListTopicsInput,
    ) -> Result<types::ListTopicsResponse, ServiceError> {
        self.list_topics_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn opt_in_phone_number(
        &self,
        ctx: &RequestContext,
        input: types::OptInPhoneNumberInput,
    ) -> Result<types::OptInPhoneNumberResponse, ServiceError> {
        self.opt_in_phone_number_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn publish(
        &self,
        ctx: &RequestContext,
        input: types::PublishInput,
    ) -> Result<types::PublishResponse, ServiceError> {
        self.publish_impl(ctx, input).await.map_err(errors::sns_error)
    }

    async fn publish_batch(
        &self,
        ctx: &RequestContext,
        input: types::PublishBatchInput,
    ) -> Result<types::PublishBatchResponse, ServiceError> {
        self.publish_batch_impl(ctx, input).await.map_err(errors::sns_error)
    }

    async fn put_data_protection_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutDataProtectionPolicyInput,
    ) -> Result<(), ServiceError> {
        self.put_data_protection_policy_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn remove_permission(
        &self,
        ctx: &RequestContext,
        input: types::RemovePermissionInput,
    ) -> Result<(), ServiceError> {
        self.remove_permission_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn set_endpoint_attributes(
        &self,
        ctx: &RequestContext,
        input: types::SetEndpointAttributesInput,
    ) -> Result<(), ServiceError> {
        self.set_endpoint_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn set_platform_application_attributes(
        &self,
        ctx: &RequestContext,
        input: types::SetPlatformApplicationAttributesInput,
    ) -> Result<(), ServiceError> {
        self.set_platform_application_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn set_sms_attributes(
        &self,
        ctx: &RequestContext,
        input: types::SetSMSAttributesInput,
    ) -> Result<types::SetSMSAttributesResponse, ServiceError> {
        self.set_sms_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn set_subscription_attributes(
        &self,
        ctx: &RequestContext,
        input: types::SetSubscriptionAttributesInput,
    ) -> Result<(), ServiceError> {
        self.set_subscription_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn set_topic_attributes(
        &self,
        ctx: &RequestContext,
        input: types::SetTopicAttributesInput,
    ) -> Result<(), ServiceError> {
        self.set_topic_attributes_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn subscribe(
        &self,
        ctx: &RequestContext,
        input: types::SubscribeInput,
    ) -> Result<types::SubscribeResponse, ServiceError> {
        self.subscribe_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        self.tag_resource_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn unsubscribe(&self, ctx: &RequestContext, input: types::UnsubscribeInput) -> Result<(), ServiceError> {
        self.unsubscribe_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        self.untag_resource_impl(ctx, input).map_err(errors::sns_error)
    }

    async fn verify_sms_sandbox_phone_number(
        &self,
        ctx: &RequestContext,
        input: types::VerifySMSSandboxPhoneNumberInput,
    ) -> Result<types::VerifySMSSandboxPhoneNumberResult, ServiceError> {
        self.verify_sms_sandbox_phone_number_impl(ctx, input).map_err(errors::sns_error)
    }
}
