//! The generated handler traits, forwarding to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::Ses;

mod v1_impl {
    use super::*;
    use crate::v1::types;

    #[async_trait::async_trait]
    impl crate::v1::Handler for Ses {
        async fn clone_receipt_rule_set(
            &self,
            ctx: &RequestContext,
            input: types::CloneReceiptRuleSetRequest,
        ) -> Result<types::CloneReceiptRuleSetResponse, ServiceError> {
            self.observe(ctx);
            self.clone_receipt_rule_set_v1(ctx, input)
        }
        async fn create_configuration_set(
            &self,
            ctx: &RequestContext,
            input: types::CreateConfigurationSetRequest,
        ) -> Result<types::CreateConfigurationSetResponse, ServiceError> {
            self.observe(ctx);
            self.create_configuration_set_v1(ctx, input).map(|()| Default::default())
        }
        async fn create_configuration_set_event_destination(
            &self,
            ctx: &RequestContext,
            input: types::CreateConfigurationSetEventDestinationRequest,
        ) -> Result<types::CreateConfigurationSetEventDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.create_configuration_set_event_destination_v1(ctx, input).map(|()| Default::default())
        }
        async fn create_configuration_set_tracking_options(
            &self,
            ctx: &RequestContext,
            input: types::CreateConfigurationSetTrackingOptionsRequest,
        ) -> Result<types::CreateConfigurationSetTrackingOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.create_configuration_set_tracking_options_v1(ctx, input).map(|()| Default::default())
        }
        async fn create_custom_verification_email_template(
            &self,
            ctx: &RequestContext,
            input: types::CreateCustomVerificationEmailTemplateRequest,
        ) -> Result<(), ServiceError> {
            self.observe(ctx);
            self.create_custom_verification_email_template_v1(ctx, input)
        }
        async fn create_receipt_filter(
            &self,
            ctx: &RequestContext,
            input: types::CreateReceiptFilterRequest,
        ) -> Result<types::CreateReceiptFilterResponse, ServiceError> {
            self.observe(ctx);
            self.create_receipt_filter_v1(ctx, input)
        }
        async fn create_receipt_rule(
            &self,
            ctx: &RequestContext,
            input: types::CreateReceiptRuleRequest,
        ) -> Result<types::CreateReceiptRuleResponse, ServiceError> {
            self.observe(ctx);
            self.create_receipt_rule_v1(ctx, input)
        }
        async fn create_receipt_rule_set(
            &self,
            ctx: &RequestContext,
            input: types::CreateReceiptRuleSetRequest,
        ) -> Result<types::CreateReceiptRuleSetResponse, ServiceError> {
            self.observe(ctx);
            self.create_receipt_rule_set_v1(ctx, input)
        }
        async fn create_template(
            &self,
            ctx: &RequestContext,
            input: types::CreateTemplateRequest,
        ) -> Result<types::CreateTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.create_template_v1(ctx, input).map(|()| Default::default())
        }
        async fn delete_configuration_set(
            &self,
            ctx: &RequestContext,
            input: types::DeleteConfigurationSetRequest,
        ) -> Result<types::DeleteConfigurationSetResponse, ServiceError> {
            self.observe(ctx);
            self.delete_configuration_set_v1(ctx, input).map(|()| Default::default())
        }
        async fn delete_configuration_set_event_destination(
            &self,
            ctx: &RequestContext,
            input: types::DeleteConfigurationSetEventDestinationRequest,
        ) -> Result<types::DeleteConfigurationSetEventDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.delete_configuration_set_event_destination_v1(ctx, input).map(|()| Default::default())
        }
        async fn delete_configuration_set_tracking_options(
            &self,
            ctx: &RequestContext,
            input: types::DeleteConfigurationSetTrackingOptionsRequest,
        ) -> Result<types::DeleteConfigurationSetTrackingOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.delete_configuration_set_tracking_options_v1(ctx, input).map(|()| Default::default())
        }
        async fn delete_custom_verification_email_template(
            &self,
            ctx: &RequestContext,
            input: types::DeleteCustomVerificationEmailTemplateRequest,
        ) -> Result<(), ServiceError> {
            self.observe(ctx);
            self.delete_custom_verification_email_template_v1(ctx, input)
        }
        async fn delete_identity(
            &self,
            ctx: &RequestContext,
            input: types::DeleteIdentityRequest,
        ) -> Result<types::DeleteIdentityResponse, ServiceError> {
            self.observe(ctx);
            self.delete_identity_v1(ctx, input).map(|()| Default::default())
        }
        async fn delete_identity_policy(
            &self,
            ctx: &RequestContext,
            input: types::DeleteIdentityPolicyRequest,
        ) -> Result<types::DeleteIdentityPolicyResponse, ServiceError> {
            self.observe(ctx);
            self.delete_identity_policy_v1(ctx, input).map(|()| Default::default())
        }
        async fn delete_receipt_filter(
            &self,
            ctx: &RequestContext,
            input: types::DeleteReceiptFilterRequest,
        ) -> Result<types::DeleteReceiptFilterResponse, ServiceError> {
            self.observe(ctx);
            self.delete_receipt_filter_v1(ctx, input)
        }
        async fn delete_receipt_rule(
            &self,
            ctx: &RequestContext,
            input: types::DeleteReceiptRuleRequest,
        ) -> Result<types::DeleteReceiptRuleResponse, ServiceError> {
            self.observe(ctx);
            self.delete_receipt_rule_v1(ctx, input)
        }
        async fn delete_receipt_rule_set(
            &self,
            ctx: &RequestContext,
            input: types::DeleteReceiptRuleSetRequest,
        ) -> Result<types::DeleteReceiptRuleSetResponse, ServiceError> {
            self.observe(ctx);
            self.delete_receipt_rule_set_v1(ctx, input)
        }
        async fn delete_template(
            &self,
            ctx: &RequestContext,
            input: types::DeleteTemplateRequest,
        ) -> Result<types::DeleteTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.delete_template_v1(ctx, input).map(|()| Default::default())
        }
        async fn delete_verified_email_address(
            &self,
            ctx: &RequestContext,
            input: types::DeleteVerifiedEmailAddressRequest,
        ) -> Result<(), ServiceError> {
            self.observe(ctx);
            self.delete_verified_email_address_v1(ctx, input)
        }
        async fn describe_active_receipt_rule_set(
            &self,
            ctx: &RequestContext,
            input: types::DescribeActiveReceiptRuleSetRequest,
        ) -> Result<types::DescribeActiveReceiptRuleSetResponse, ServiceError> {
            self.observe(ctx);
            self.describe_active_receipt_rule_set_v1(ctx, input)
        }
        async fn describe_configuration_set(
            &self,
            ctx: &RequestContext,
            input: types::DescribeConfigurationSetRequest,
        ) -> Result<types::DescribeConfigurationSetResponse, ServiceError> {
            self.observe(ctx);
            self.describe_configuration_set_v1(ctx, input)
        }
        async fn describe_receipt_rule(
            &self,
            ctx: &RequestContext,
            input: types::DescribeReceiptRuleRequest,
        ) -> Result<types::DescribeReceiptRuleResponse, ServiceError> {
            self.observe(ctx);
            self.describe_receipt_rule_v1(ctx, input)
        }
        async fn describe_receipt_rule_set(
            &self,
            ctx: &RequestContext,
            input: types::DescribeReceiptRuleSetRequest,
        ) -> Result<types::DescribeReceiptRuleSetResponse, ServiceError> {
            self.observe(ctx);
            self.describe_receipt_rule_set_v1(ctx, input)
        }
        async fn get_account_sending_enabled(
            &self,
            ctx: &RequestContext,
            input: (),
        ) -> Result<types::GetAccountSendingEnabledResponse, ServiceError> {
            self.observe(ctx);
            self.get_account_sending_enabled_v1(ctx, input)
        }
        async fn get_custom_verification_email_template(
            &self,
            ctx: &RequestContext,
            input: types::GetCustomVerificationEmailTemplateRequest,
        ) -> Result<types::GetCustomVerificationEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.get_custom_verification_email_template_v1(ctx, input)
        }
        async fn get_identity_dkim_attributes(
            &self,
            ctx: &RequestContext,
            input: types::GetIdentityDkimAttributesRequest,
        ) -> Result<types::GetIdentityDkimAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.get_identity_dkim_attributes_v1(ctx, input)
        }
        async fn get_identity_mail_from_domain_attributes(
            &self,
            ctx: &RequestContext,
            input: types::GetIdentityMailFromDomainAttributesRequest,
        ) -> Result<types::GetIdentityMailFromDomainAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.get_identity_mail_from_domain_attributes_v1(ctx, input)
        }
        async fn get_identity_notification_attributes(
            &self,
            ctx: &RequestContext,
            input: types::GetIdentityNotificationAttributesRequest,
        ) -> Result<types::GetIdentityNotificationAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.get_identity_notification_attributes_v1(ctx, input)
        }
        async fn get_identity_policies(
            &self,
            ctx: &RequestContext,
            input: types::GetIdentityPoliciesRequest,
        ) -> Result<types::GetIdentityPoliciesResponse, ServiceError> {
            self.observe(ctx);
            self.get_identity_policies_v1(ctx, input)
        }
        async fn get_identity_verification_attributes(
            &self,
            ctx: &RequestContext,
            input: types::GetIdentityVerificationAttributesRequest,
        ) -> Result<types::GetIdentityVerificationAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.get_identity_verification_attributes_v1(ctx, input)
        }
        async fn get_send_quota(
            &self,
            ctx: &RequestContext,
            input: (),
        ) -> Result<types::GetSendQuotaResponse, ServiceError> {
            self.observe(ctx);
            self.get_send_quota_v1(ctx, input)
        }
        async fn get_send_statistics(
            &self,
            ctx: &RequestContext,
            input: (),
        ) -> Result<types::GetSendStatisticsResponse, ServiceError> {
            self.observe(ctx);
            self.get_send_statistics_v1(ctx, input)
        }
        async fn get_template(
            &self,
            ctx: &RequestContext,
            input: types::GetTemplateRequest,
        ) -> Result<types::GetTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.get_template_v1(ctx, input)
        }
        async fn list_configuration_sets(
            &self,
            ctx: &RequestContext,
            input: types::ListConfigurationSetsRequest,
        ) -> Result<types::ListConfigurationSetsResponse, ServiceError> {
            self.observe(ctx);
            self.list_configuration_sets_v1(ctx, input)
        }
        async fn list_custom_verification_email_templates(
            &self,
            ctx: &RequestContext,
            input: types::ListCustomVerificationEmailTemplatesRequest,
        ) -> Result<types::ListCustomVerificationEmailTemplatesResponse, ServiceError> {
            self.observe(ctx);
            self.list_custom_verification_email_templates_v1(ctx, input)
        }
        async fn list_identities(
            &self,
            ctx: &RequestContext,
            input: types::ListIdentitiesRequest,
        ) -> Result<types::ListIdentitiesResponse, ServiceError> {
            self.observe(ctx);
            self.list_identities_v1(ctx, input)
        }
        async fn list_identity_policies(
            &self,
            ctx: &RequestContext,
            input: types::ListIdentityPoliciesRequest,
        ) -> Result<types::ListIdentityPoliciesResponse, ServiceError> {
            self.observe(ctx);
            self.list_identity_policies_v1(ctx, input)
        }
        async fn list_receipt_filters(
            &self,
            ctx: &RequestContext,
            input: types::ListReceiptFiltersRequest,
        ) -> Result<types::ListReceiptFiltersResponse, ServiceError> {
            self.observe(ctx);
            self.list_receipt_filters_v1(ctx, input)
        }
        async fn list_receipt_rule_sets(
            &self,
            ctx: &RequestContext,
            input: types::ListReceiptRuleSetsRequest,
        ) -> Result<types::ListReceiptRuleSetsResponse, ServiceError> {
            self.observe(ctx);
            self.list_receipt_rule_sets_v1(ctx, input)
        }
        async fn list_templates(
            &self,
            ctx: &RequestContext,
            input: types::ListTemplatesRequest,
        ) -> Result<types::ListTemplatesResponse, ServiceError> {
            self.observe(ctx);
            self.list_templates_v1(ctx, input)
        }
        async fn list_verified_email_addresses(
            &self,
            ctx: &RequestContext,
            input: (),
        ) -> Result<types::ListVerifiedEmailAddressesResponse, ServiceError> {
            self.observe(ctx);
            self.list_verified_email_addresses_v1(ctx, input)
        }
        async fn put_configuration_set_delivery_options(
            &self,
            ctx: &RequestContext,
            input: types::PutConfigurationSetDeliveryOptionsRequest,
        ) -> Result<types::PutConfigurationSetDeliveryOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.put_configuration_set_delivery_options_v1(ctx, input).map(|()| Default::default())
        }
        async fn put_identity_policy(
            &self,
            ctx: &RequestContext,
            input: types::PutIdentityPolicyRequest,
        ) -> Result<types::PutIdentityPolicyResponse, ServiceError> {
            self.observe(ctx);
            self.put_identity_policy_v1(ctx, input).map(|()| Default::default())
        }
        async fn reorder_receipt_rule_set(
            &self,
            ctx: &RequestContext,
            input: types::ReorderReceiptRuleSetRequest,
        ) -> Result<types::ReorderReceiptRuleSetResponse, ServiceError> {
            self.observe(ctx);
            self.reorder_receipt_rule_set_v1(ctx, input)
        }
        async fn send_bounce(
            &self,
            ctx: &RequestContext,
            input: types::SendBounceRequest,
        ) -> Result<types::SendBounceResponse, ServiceError> {
            self.observe(ctx);
            self.send_bounce_v1(ctx, input)
        }
        async fn send_bulk_templated_email(
            &self,
            ctx: &RequestContext,
            input: types::SendBulkTemplatedEmailRequest,
        ) -> Result<types::SendBulkTemplatedEmailResponse, ServiceError> {
            self.observe(ctx);
            self.send_bulk_templated_email_v1(ctx, input)
        }
        async fn send_custom_verification_email(
            &self,
            ctx: &RequestContext,
            input: types::SendCustomVerificationEmailRequest,
        ) -> Result<types::SendCustomVerificationEmailResponse, ServiceError> {
            self.observe(ctx);
            self.send_custom_verification_email_v1(ctx, input)
        }
        async fn send_email(
            &self,
            ctx: &RequestContext,
            input: types::SendEmailRequest,
        ) -> Result<types::SendEmailResponse, ServiceError> {
            self.observe(ctx);
            self.send_email_v1(ctx, input)
        }
        async fn send_raw_email(
            &self,
            ctx: &RequestContext,
            input: types::SendRawEmailRequest,
        ) -> Result<types::SendRawEmailResponse, ServiceError> {
            self.observe(ctx);
            self.send_raw_email_v1(ctx, input)
        }
        async fn send_templated_email(
            &self,
            ctx: &RequestContext,
            input: types::SendTemplatedEmailRequest,
        ) -> Result<types::SendTemplatedEmailResponse, ServiceError> {
            self.observe(ctx);
            self.send_templated_email_v1(ctx, input)
        }
        async fn set_active_receipt_rule_set(
            &self,
            ctx: &RequestContext,
            input: types::SetActiveReceiptRuleSetRequest,
        ) -> Result<types::SetActiveReceiptRuleSetResponse, ServiceError> {
            self.observe(ctx);
            self.set_active_receipt_rule_set_v1(ctx, input)
        }
        async fn set_identity_dkim_enabled(
            &self,
            ctx: &RequestContext,
            input: types::SetIdentityDkimEnabledRequest,
        ) -> Result<types::SetIdentityDkimEnabledResponse, ServiceError> {
            self.observe(ctx);
            self.set_identity_dkim_enabled_v1(ctx, input).map(|()| Default::default())
        }
        async fn set_identity_feedback_forwarding_enabled(
            &self,
            ctx: &RequestContext,
            input: types::SetIdentityFeedbackForwardingEnabledRequest,
        ) -> Result<types::SetIdentityFeedbackForwardingEnabledResponse, ServiceError> {
            self.observe(ctx);
            self.set_identity_feedback_forwarding_enabled_v1(ctx, input).map(|()| Default::default())
        }
        async fn set_identity_headers_in_notifications_enabled(
            &self,
            ctx: &RequestContext,
            input: types::SetIdentityHeadersInNotificationsEnabledRequest,
        ) -> Result<types::SetIdentityHeadersInNotificationsEnabledResponse, ServiceError> {
            self.observe(ctx);
            self.set_identity_headers_in_notifications_enabled_v1(ctx, input).map(|()| Default::default())
        }
        async fn set_identity_mail_from_domain(
            &self,
            ctx: &RequestContext,
            input: types::SetIdentityMailFromDomainRequest,
        ) -> Result<types::SetIdentityMailFromDomainResponse, ServiceError> {
            self.observe(ctx);
            self.set_identity_mail_from_domain_v1(ctx, input).map(|()| Default::default())
        }
        async fn set_identity_notification_topic(
            &self,
            ctx: &RequestContext,
            input: types::SetIdentityNotificationTopicRequest,
        ) -> Result<types::SetIdentityNotificationTopicResponse, ServiceError> {
            self.observe(ctx);
            self.set_identity_notification_topic_v1(ctx, input).map(|()| Default::default())
        }
        async fn set_receipt_rule_position(
            &self,
            ctx: &RequestContext,
            input: types::SetReceiptRulePositionRequest,
        ) -> Result<types::SetReceiptRulePositionResponse, ServiceError> {
            self.observe(ctx);
            self.set_receipt_rule_position_v1(ctx, input)
        }
        async fn test_render_template(
            &self,
            ctx: &RequestContext,
            input: types::TestRenderTemplateRequest,
        ) -> Result<types::TestRenderTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.test_render_template_v1(ctx, input)
        }
        async fn update_account_sending_enabled(
            &self,
            ctx: &RequestContext,
            input: types::UpdateAccountSendingEnabledRequest,
        ) -> Result<(), ServiceError> {
            self.observe(ctx);
            self.update_account_sending_enabled_v1(ctx, input)
        }
        async fn update_configuration_set_event_destination(
            &self,
            ctx: &RequestContext,
            input: types::UpdateConfigurationSetEventDestinationRequest,
        ) -> Result<types::UpdateConfigurationSetEventDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.update_configuration_set_event_destination_v1(ctx, input).map(|()| Default::default())
        }
        async fn update_configuration_set_reputation_metrics_enabled(
            &self,
            ctx: &RequestContext,
            input: types::UpdateConfigurationSetReputationMetricsEnabledRequest,
        ) -> Result<(), ServiceError> {
            self.observe(ctx);
            self.update_configuration_set_reputation_metrics_enabled_v1(ctx, input)
        }
        async fn update_configuration_set_sending_enabled(
            &self,
            ctx: &RequestContext,
            input: types::UpdateConfigurationSetSendingEnabledRequest,
        ) -> Result<(), ServiceError> {
            self.observe(ctx);
            self.update_configuration_set_sending_enabled_v1(ctx, input)
        }
        async fn update_configuration_set_tracking_options(
            &self,
            ctx: &RequestContext,
            input: types::UpdateConfigurationSetTrackingOptionsRequest,
        ) -> Result<types::UpdateConfigurationSetTrackingOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.update_configuration_set_tracking_options_v1(ctx, input).map(|()| Default::default())
        }
        async fn update_custom_verification_email_template(
            &self,
            ctx: &RequestContext,
            input: types::UpdateCustomVerificationEmailTemplateRequest,
        ) -> Result<(), ServiceError> {
            self.observe(ctx);
            self.update_custom_verification_email_template_v1(ctx, input)
        }
        async fn update_receipt_rule(
            &self,
            ctx: &RequestContext,
            input: types::UpdateReceiptRuleRequest,
        ) -> Result<types::UpdateReceiptRuleResponse, ServiceError> {
            self.observe(ctx);
            self.update_receipt_rule_v1(ctx, input)
        }
        async fn update_template(
            &self,
            ctx: &RequestContext,
            input: types::UpdateTemplateRequest,
        ) -> Result<types::UpdateTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.update_template_v1(ctx, input).map(|()| Default::default())
        }
        async fn verify_domain_dkim(
            &self,
            ctx: &RequestContext,
            input: types::VerifyDomainDkimRequest,
        ) -> Result<types::VerifyDomainDkimResponse, ServiceError> {
            self.observe(ctx);
            self.verify_domain_dkim_v1(ctx, input)
        }
        async fn verify_domain_identity(
            &self,
            ctx: &RequestContext,
            input: types::VerifyDomainIdentityRequest,
        ) -> Result<types::VerifyDomainIdentityResponse, ServiceError> {
            self.observe(ctx);
            self.verify_domain_identity_v1(ctx, input)
        }
        async fn verify_email_address(
            &self,
            ctx: &RequestContext,
            input: types::VerifyEmailAddressRequest,
        ) -> Result<(), ServiceError> {
            self.observe(ctx);
            self.verify_email_address_v1(ctx, input)
        }
        async fn verify_email_identity(
            &self,
            ctx: &RequestContext,
            input: types::VerifyEmailIdentityRequest,
        ) -> Result<types::VerifyEmailIdentityResponse, ServiceError> {
            self.observe(ctx);
            self.verify_email_identity_v1(ctx, input)
        }
    }
}

mod v2_impl {
    use super::*;
    use crate::v2::types;

    #[async_trait::async_trait]
    impl crate::v2::Handler for Ses {
        async fn associate_email_identity_certificate(
            &self,
            ctx: &RequestContext,
            input: types::AssociateEmailIdentityCertificateRequest,
        ) -> Result<types::AssociateEmailIdentityCertificateResponse, ServiceError> {
            self.observe(ctx);
            self.associate_email_identity_certificate_v2(ctx, input)
        }
        async fn batch_get_metric_data(
            &self,
            ctx: &RequestContext,
            input: types::BatchGetMetricDataRequest,
        ) -> Result<types::BatchGetMetricDataResponse, ServiceError> {
            self.observe(ctx);
            self.batch_get_metric_data_v2(ctx, input)
        }
        async fn cancel_export_job(
            &self,
            ctx: &RequestContext,
            input: types::CancelExportJobRequest,
        ) -> Result<types::CancelExportJobResponse, ServiceError> {
            self.observe(ctx);
            self.cancel_export_job_v2(ctx, input)
        }
        async fn create_configuration_set(
            &self,
            ctx: &RequestContext,
            input: types::CreateConfigurationSetRequest,
        ) -> Result<types::CreateConfigurationSetResponse, ServiceError> {
            self.observe(ctx);
            self.create_configuration_set_v2(ctx, input)
        }
        async fn create_configuration_set_event_destination(
            &self,
            ctx: &RequestContext,
            input: types::CreateConfigurationSetEventDestinationRequest,
        ) -> Result<types::CreateConfigurationSetEventDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.create_configuration_set_event_destination_v2(ctx, input)
        }
        async fn create_contact(
            &self,
            ctx: &RequestContext,
            input: types::CreateContactRequest,
        ) -> Result<types::CreateContactResponse, ServiceError> {
            self.observe(ctx);
            self.create_contact_v2(ctx, input)
        }
        async fn create_contact_list(
            &self,
            ctx: &RequestContext,
            input: types::CreateContactListRequest,
        ) -> Result<types::CreateContactListResponse, ServiceError> {
            self.observe(ctx);
            self.create_contact_list_v2(ctx, input)
        }
        async fn create_custom_verification_email_template(
            &self,
            ctx: &RequestContext,
            input: types::CreateCustomVerificationEmailTemplateRequest,
        ) -> Result<types::CreateCustomVerificationEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.create_custom_verification_email_template_v2(ctx, input)
        }
        async fn create_dedicated_ip_pool(
            &self,
            ctx: &RequestContext,
            input: types::CreateDedicatedIpPoolRequest,
        ) -> Result<types::CreateDedicatedIpPoolResponse, ServiceError> {
            self.observe(ctx);
            self.create_dedicated_ip_pool_v2(ctx, input)
        }
        async fn create_deliverability_test_report(
            &self,
            ctx: &RequestContext,
            input: types::CreateDeliverabilityTestReportRequest,
        ) -> Result<types::CreateDeliverabilityTestReportResponse, ServiceError> {
            self.observe(ctx);
            self.create_deliverability_test_report_v2(ctx, input)
        }
        async fn create_email_identity(
            &self,
            ctx: &RequestContext,
            input: types::CreateEmailIdentityRequest,
        ) -> Result<types::CreateEmailIdentityResponse, ServiceError> {
            self.observe(ctx);
            self.create_email_identity_v2(ctx, input)
        }
        async fn create_email_identity_policy(
            &self,
            ctx: &RequestContext,
            input: types::CreateEmailIdentityPolicyRequest,
        ) -> Result<types::CreateEmailIdentityPolicyResponse, ServiceError> {
            self.observe(ctx);
            self.create_email_identity_policy_v2(ctx, input)
        }
        async fn create_email_template(
            &self,
            ctx: &RequestContext,
            input: types::CreateEmailTemplateRequest,
        ) -> Result<types::CreateEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.create_email_template_v2(ctx, input)
        }
        async fn create_export_job(
            &self,
            ctx: &RequestContext,
            input: types::CreateExportJobRequest,
        ) -> Result<types::CreateExportJobResponse, ServiceError> {
            self.observe(ctx);
            self.create_export_job_v2(ctx, input).await
        }
        async fn create_import_job(
            &self,
            ctx: &RequestContext,
            input: types::CreateImportJobRequest,
        ) -> Result<types::CreateImportJobResponse, ServiceError> {
            self.observe(ctx);
            self.create_import_job_v2(ctx, input)
        }
        async fn create_multi_region_endpoint(
            &self,
            ctx: &RequestContext,
            input: types::CreateMultiRegionEndpointRequest,
        ) -> Result<types::CreateMultiRegionEndpointResponse, ServiceError> {
            self.observe(ctx);
            self.create_multi_region_endpoint_v2(ctx, input)
        }
        async fn create_tenant(
            &self,
            ctx: &RequestContext,
            input: types::CreateTenantRequest,
        ) -> Result<types::CreateTenantResponse, ServiceError> {
            self.observe(ctx);
            self.create_tenant_v2(ctx, input)
        }
        async fn create_tenant_resource_association(
            &self,
            ctx: &RequestContext,
            input: types::CreateTenantResourceAssociationRequest,
        ) -> Result<types::CreateTenantResourceAssociationResponse, ServiceError> {
            self.observe(ctx);
            self.create_tenant_resource_association_v2(ctx, input)
        }
        async fn delete_configuration_set(
            &self,
            ctx: &RequestContext,
            input: types::DeleteConfigurationSetRequest,
        ) -> Result<types::DeleteConfigurationSetResponse, ServiceError> {
            self.observe(ctx);
            self.delete_configuration_set_v2(ctx, input)
        }
        async fn delete_configuration_set_event_destination(
            &self,
            ctx: &RequestContext,
            input: types::DeleteConfigurationSetEventDestinationRequest,
        ) -> Result<types::DeleteConfigurationSetEventDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.delete_configuration_set_event_destination_v2(ctx, input)
        }
        async fn delete_contact(
            &self,
            ctx: &RequestContext,
            input: types::DeleteContactRequest,
        ) -> Result<types::DeleteContactResponse, ServiceError> {
            self.observe(ctx);
            self.delete_contact_v2(ctx, input)
        }
        async fn delete_contact_list(
            &self,
            ctx: &RequestContext,
            input: types::DeleteContactListRequest,
        ) -> Result<types::DeleteContactListResponse, ServiceError> {
            self.observe(ctx);
            self.delete_contact_list_v2(ctx, input)
        }
        async fn delete_custom_verification_email_template(
            &self,
            ctx: &RequestContext,
            input: types::DeleteCustomVerificationEmailTemplateRequest,
        ) -> Result<types::DeleteCustomVerificationEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.delete_custom_verification_email_template_v2(ctx, input)
        }
        async fn delete_dedicated_ip_pool(
            &self,
            ctx: &RequestContext,
            input: types::DeleteDedicatedIpPoolRequest,
        ) -> Result<types::DeleteDedicatedIpPoolResponse, ServiceError> {
            self.observe(ctx);
            self.delete_dedicated_ip_pool_v2(ctx, input)
        }
        async fn delete_email_identity(
            &self,
            ctx: &RequestContext,
            input: types::DeleteEmailIdentityRequest,
        ) -> Result<types::DeleteEmailIdentityResponse, ServiceError> {
            self.observe(ctx);
            self.delete_email_identity_v2(ctx, input)
        }
        async fn delete_email_identity_policy(
            &self,
            ctx: &RequestContext,
            input: types::DeleteEmailIdentityPolicyRequest,
        ) -> Result<types::DeleteEmailIdentityPolicyResponse, ServiceError> {
            self.observe(ctx);
            self.delete_email_identity_policy_v2(ctx, input)
        }
        async fn delete_email_template(
            &self,
            ctx: &RequestContext,
            input: types::DeleteEmailTemplateRequest,
        ) -> Result<types::DeleteEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.delete_email_template_v2(ctx, input)
        }
        async fn delete_multi_region_endpoint(
            &self,
            ctx: &RequestContext,
            input: types::DeleteMultiRegionEndpointRequest,
        ) -> Result<types::DeleteMultiRegionEndpointResponse, ServiceError> {
            self.observe(ctx);
            self.delete_multi_region_endpoint_v2(ctx, input)
        }
        async fn delete_suppressed_destination(
            &self,
            ctx: &RequestContext,
            input: types::DeleteSuppressedDestinationRequest,
        ) -> Result<types::DeleteSuppressedDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.delete_suppressed_destination_v2(ctx, input)
        }
        async fn delete_tenant(
            &self,
            ctx: &RequestContext,
            input: types::DeleteTenantRequest,
        ) -> Result<types::DeleteTenantResponse, ServiceError> {
            self.observe(ctx);
            self.delete_tenant_v2(ctx, input)
        }
        async fn delete_tenant_resource_association(
            &self,
            ctx: &RequestContext,
            input: types::DeleteTenantResourceAssociationRequest,
        ) -> Result<types::DeleteTenantResourceAssociationResponse, ServiceError> {
            self.observe(ctx);
            self.delete_tenant_resource_association_v2(ctx, input)
        }
        async fn disassociate_email_identity_certificate(
            &self,
            ctx: &RequestContext,
            input: types::DisassociateEmailIdentityCertificateRequest,
        ) -> Result<types::DisassociateEmailIdentityCertificateResponse, ServiceError> {
            self.observe(ctx);
            self.disassociate_email_identity_certificate_v2(ctx, input)
        }
        async fn get_account(
            &self,
            ctx: &RequestContext,
            input: types::GetAccountRequest,
        ) -> Result<types::GetAccountResponse, ServiceError> {
            self.observe(ctx);
            self.get_account_v2(ctx, input)
        }
        async fn get_blacklist_reports(
            &self,
            ctx: &RequestContext,
            input: types::GetBlacklistReportsRequest,
        ) -> Result<types::GetBlacklistReportsResponse, ServiceError> {
            self.observe(ctx);
            self.get_blacklist_reports_v2(ctx, input)
        }
        async fn get_configuration_set(
            &self,
            ctx: &RequestContext,
            input: types::GetConfigurationSetRequest,
        ) -> Result<types::GetConfigurationSetResponse, ServiceError> {
            self.observe(ctx);
            self.get_configuration_set_v2(ctx, input)
        }
        async fn get_configuration_set_event_destinations(
            &self,
            ctx: &RequestContext,
            input: types::GetConfigurationSetEventDestinationsRequest,
        ) -> Result<types::GetConfigurationSetEventDestinationsResponse, ServiceError> {
            self.observe(ctx);
            self.get_configuration_set_event_destinations_v2(ctx, input)
        }
        async fn get_contact(
            &self,
            ctx: &RequestContext,
            input: types::GetContactRequest,
        ) -> Result<types::GetContactResponse, ServiceError> {
            self.observe(ctx);
            self.get_contact_v2(ctx, input)
        }
        async fn get_contact_list(
            &self,
            ctx: &RequestContext,
            input: types::GetContactListRequest,
        ) -> Result<types::GetContactListResponse, ServiceError> {
            self.observe(ctx);
            self.get_contact_list_v2(ctx, input)
        }
        async fn get_custom_verification_email_template(
            &self,
            ctx: &RequestContext,
            input: types::GetCustomVerificationEmailTemplateRequest,
        ) -> Result<types::GetCustomVerificationEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.get_custom_verification_email_template_v2(ctx, input)
        }
        async fn get_dedicated_ip(
            &self,
            ctx: &RequestContext,
            input: types::GetDedicatedIpRequest,
        ) -> Result<types::GetDedicatedIpResponse, ServiceError> {
            self.observe(ctx);
            self.get_dedicated_ip_v2(ctx, input)
        }
        async fn get_dedicated_ip_pool(
            &self,
            ctx: &RequestContext,
            input: types::GetDedicatedIpPoolRequest,
        ) -> Result<types::GetDedicatedIpPoolResponse, ServiceError> {
            self.observe(ctx);
            self.get_dedicated_ip_pool_v2(ctx, input)
        }
        async fn get_dedicated_ips(
            &self,
            ctx: &RequestContext,
            input: types::GetDedicatedIpsRequest,
        ) -> Result<types::GetDedicatedIpsResponse, ServiceError> {
            self.observe(ctx);
            self.get_dedicated_ips_v2(ctx, input)
        }
        async fn get_deliverability_dashboard_options(
            &self,
            ctx: &RequestContext,
            input: types::GetDeliverabilityDashboardOptionsRequest,
        ) -> Result<types::GetDeliverabilityDashboardOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.get_deliverability_dashboard_options_v2(ctx, input)
        }
        async fn get_deliverability_test_report(
            &self,
            ctx: &RequestContext,
            input: types::GetDeliverabilityTestReportRequest,
        ) -> Result<types::GetDeliverabilityTestReportResponse, ServiceError> {
            self.observe(ctx);
            self.get_deliverability_test_report_v2(ctx, input)
        }
        async fn get_domain_deliverability_campaign(
            &self,
            ctx: &RequestContext,
            input: types::GetDomainDeliverabilityCampaignRequest,
        ) -> Result<types::GetDomainDeliverabilityCampaignResponse, ServiceError> {
            self.observe(ctx);
            self.get_domain_deliverability_campaign_v2(ctx, input)
        }
        async fn get_domain_statistics_report(
            &self,
            ctx: &RequestContext,
            input: types::GetDomainStatisticsReportRequest,
        ) -> Result<types::GetDomainStatisticsReportResponse, ServiceError> {
            self.observe(ctx);
            self.get_domain_statistics_report_v2(ctx, input)
        }
        async fn get_email_address_insights(
            &self,
            ctx: &RequestContext,
            input: types::GetEmailAddressInsightsRequest,
        ) -> Result<types::GetEmailAddressInsightsResponse, ServiceError> {
            self.observe(ctx);
            self.get_email_address_insights_v2(ctx, input)
        }
        async fn get_email_identity(
            &self,
            ctx: &RequestContext,
            input: types::GetEmailIdentityRequest,
        ) -> Result<types::GetEmailIdentityResponse, ServiceError> {
            self.observe(ctx);
            self.get_email_identity_v2(ctx, input)
        }
        async fn get_email_identity_policies(
            &self,
            ctx: &RequestContext,
            input: types::GetEmailIdentityPoliciesRequest,
        ) -> Result<types::GetEmailIdentityPoliciesResponse, ServiceError> {
            self.observe(ctx);
            self.get_email_identity_policies_v2(ctx, input)
        }
        async fn get_email_template(
            &self,
            ctx: &RequestContext,
            input: types::GetEmailTemplateRequest,
        ) -> Result<types::GetEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.get_email_template_v2(ctx, input)
        }
        async fn get_export_job(
            &self,
            ctx: &RequestContext,
            input: types::GetExportJobRequest,
        ) -> Result<types::GetExportJobResponse, ServiceError> {
            self.observe(ctx);
            self.get_export_job_v2(ctx, input)
        }
        async fn get_import_job(
            &self,
            ctx: &RequestContext,
            input: types::GetImportJobRequest,
        ) -> Result<types::GetImportJobResponse, ServiceError> {
            self.observe(ctx);
            self.get_import_job_v2(ctx, input)
        }
        async fn get_message_insights(
            &self,
            ctx: &RequestContext,
            input: types::GetMessageInsightsRequest,
        ) -> Result<types::GetMessageInsightsResponse, ServiceError> {
            self.observe(ctx);
            self.get_message_insights_v2(ctx, input)
        }
        async fn get_multi_region_endpoint(
            &self,
            ctx: &RequestContext,
            input: types::GetMultiRegionEndpointRequest,
        ) -> Result<types::GetMultiRegionEndpointResponse, ServiceError> {
            self.observe(ctx);
            self.get_multi_region_endpoint_v2(ctx, input)
        }
        async fn get_reputation_entity(
            &self,
            ctx: &RequestContext,
            input: types::GetReputationEntityRequest,
        ) -> Result<types::GetReputationEntityResponse, ServiceError> {
            self.observe(ctx);
            self.get_reputation_entity_v2(ctx, input)
        }
        async fn get_suppressed_destination(
            &self,
            ctx: &RequestContext,
            input: types::GetSuppressedDestinationRequest,
        ) -> Result<types::GetSuppressedDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.get_suppressed_destination_v2(ctx, input)
        }
        async fn get_tenant(
            &self,
            ctx: &RequestContext,
            input: types::GetTenantRequest,
        ) -> Result<types::GetTenantResponse, ServiceError> {
            self.observe(ctx);
            self.get_tenant_v2(ctx, input)
        }
        async fn list_configuration_sets(
            &self,
            ctx: &RequestContext,
            input: types::ListConfigurationSetsRequest,
        ) -> Result<types::ListConfigurationSetsResponse, ServiceError> {
            self.observe(ctx);
            self.list_configuration_sets_v2(ctx, input)
        }
        async fn list_contact_lists(
            &self,
            ctx: &RequestContext,
            input: types::ListContactListsRequest,
        ) -> Result<types::ListContactListsResponse, ServiceError> {
            self.observe(ctx);
            self.list_contact_lists_v2(ctx, input)
        }
        async fn list_contacts(
            &self,
            ctx: &RequestContext,
            input: types::ListContactsRequest,
        ) -> Result<types::ListContactsResponse, ServiceError> {
            self.observe(ctx);
            self.list_contacts_v2(ctx, input)
        }
        async fn list_custom_verification_email_templates(
            &self,
            ctx: &RequestContext,
            input: types::ListCustomVerificationEmailTemplatesRequest,
        ) -> Result<types::ListCustomVerificationEmailTemplatesResponse, ServiceError> {
            self.observe(ctx);
            self.list_custom_verification_email_templates_v2(ctx, input)
        }
        async fn list_dedicated_ip_pools(
            &self,
            ctx: &RequestContext,
            input: types::ListDedicatedIpPoolsRequest,
        ) -> Result<types::ListDedicatedIpPoolsResponse, ServiceError> {
            self.observe(ctx);
            self.list_dedicated_ip_pools_v2(ctx, input)
        }
        async fn list_deliverability_test_reports(
            &self,
            ctx: &RequestContext,
            input: types::ListDeliverabilityTestReportsRequest,
        ) -> Result<types::ListDeliverabilityTestReportsResponse, ServiceError> {
            self.observe(ctx);
            self.list_deliverability_test_reports_v2(ctx, input)
        }
        async fn list_domain_deliverability_campaigns(
            &self,
            ctx: &RequestContext,
            input: types::ListDomainDeliverabilityCampaignsRequest,
        ) -> Result<types::ListDomainDeliverabilityCampaignsResponse, ServiceError> {
            self.observe(ctx);
            self.list_domain_deliverability_campaigns_v2(ctx, input)
        }
        async fn list_email_identities(
            &self,
            ctx: &RequestContext,
            input: types::ListEmailIdentitiesRequest,
        ) -> Result<types::ListEmailIdentitiesResponse, ServiceError> {
            self.observe(ctx);
            self.list_email_identities_v2(ctx, input)
        }
        async fn list_email_identity_certificates(
            &self,
            ctx: &RequestContext,
            input: types::ListEmailIdentityCertificatesRequest,
        ) -> Result<types::ListEmailIdentityCertificatesResponse, ServiceError> {
            self.observe(ctx);
            self.list_email_identity_certificates_v2(ctx, input)
        }
        async fn list_email_templates(
            &self,
            ctx: &RequestContext,
            input: types::ListEmailTemplatesRequest,
        ) -> Result<types::ListEmailTemplatesResponse, ServiceError> {
            self.observe(ctx);
            self.list_email_templates_v2(ctx, input)
        }
        async fn list_export_jobs(
            &self,
            ctx: &RequestContext,
            input: types::ListExportJobsRequest,
        ) -> Result<types::ListExportJobsResponse, ServiceError> {
            self.observe(ctx);
            self.list_export_jobs_v2(ctx, input)
        }
        async fn list_import_jobs(
            &self,
            ctx: &RequestContext,
            input: types::ListImportJobsRequest,
        ) -> Result<types::ListImportJobsResponse, ServiceError> {
            self.observe(ctx);
            self.list_import_jobs_v2(ctx, input)
        }
        async fn list_multi_region_endpoints(
            &self,
            ctx: &RequestContext,
            input: types::ListMultiRegionEndpointsRequest,
        ) -> Result<types::ListMultiRegionEndpointsResponse, ServiceError> {
            self.observe(ctx);
            self.list_multi_region_endpoints_v2(ctx, input)
        }
        async fn list_recommendations(
            &self,
            ctx: &RequestContext,
            input: types::ListRecommendationsRequest,
        ) -> Result<types::ListRecommendationsResponse, ServiceError> {
            self.observe(ctx);
            self.list_recommendations_v2(ctx, input)
        }
        async fn list_reputation_entities(
            &self,
            ctx: &RequestContext,
            input: types::ListReputationEntitiesRequest,
        ) -> Result<types::ListReputationEntitiesResponse, ServiceError> {
            self.observe(ctx);
            self.list_reputation_entities_v2(ctx, input)
        }
        async fn list_resource_tenants(
            &self,
            ctx: &RequestContext,
            input: types::ListResourceTenantsRequest,
        ) -> Result<types::ListResourceTenantsResponse, ServiceError> {
            self.observe(ctx);
            self.list_resource_tenants_v2(ctx, input)
        }
        async fn list_suppressed_destinations(
            &self,
            ctx: &RequestContext,
            input: types::ListSuppressedDestinationsRequest,
        ) -> Result<types::ListSuppressedDestinationsResponse, ServiceError> {
            self.observe(ctx);
            self.list_suppressed_destinations_v2(ctx, input)
        }
        async fn list_tags_for_resource(
            &self,
            ctx: &RequestContext,
            input: types::ListTagsForResourceRequest,
        ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
            self.observe(ctx);
            self.list_tags_for_resource_v2(ctx, input)
        }
        async fn list_tenant_resources(
            &self,
            ctx: &RequestContext,
            input: types::ListTenantResourcesRequest,
        ) -> Result<types::ListTenantResourcesResponse, ServiceError> {
            self.observe(ctx);
            self.list_tenant_resources_v2(ctx, input)
        }
        async fn list_tenants(
            &self,
            ctx: &RequestContext,
            input: types::ListTenantsRequest,
        ) -> Result<types::ListTenantsResponse, ServiceError> {
            self.observe(ctx);
            self.list_tenants_v2(ctx, input)
        }
        async fn put_account_dedicated_ip_warmup_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutAccountDedicatedIpWarmupAttributesRequest,
        ) -> Result<types::PutAccountDedicatedIpWarmupAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_account_dedicated_ip_warmup_attributes_v2(ctx, input)
        }
        async fn put_account_details(
            &self,
            ctx: &RequestContext,
            input: types::PutAccountDetailsRequest,
        ) -> Result<types::PutAccountDetailsResponse, ServiceError> {
            self.observe(ctx);
            self.put_account_details_v2(ctx, input)
        }
        async fn put_account_pricing_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutAccountPricingAttributesRequest,
        ) -> Result<types::PutAccountPricingAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_account_pricing_attributes_v2(ctx, input)
        }
        async fn put_account_sending_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutAccountSendingAttributesRequest,
        ) -> Result<types::PutAccountSendingAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_account_sending_attributes_v2(ctx, input)
        }
        async fn put_account_suppression_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutAccountSuppressionAttributesRequest,
        ) -> Result<types::PutAccountSuppressionAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_account_suppression_attributes_v2(ctx, input)
        }
        async fn put_account_vdm_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutAccountVdmAttributesRequest,
        ) -> Result<types::PutAccountVdmAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_account_vdm_attributes_v2(ctx, input)
        }
        async fn put_configuration_set_archiving_options(
            &self,
            ctx: &RequestContext,
            input: types::PutConfigurationSetArchivingOptionsRequest,
        ) -> Result<types::PutConfigurationSetArchivingOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.put_configuration_set_archiving_options_v2(ctx, input)
        }
        async fn put_configuration_set_delivery_options(
            &self,
            ctx: &RequestContext,
            input: types::PutConfigurationSetDeliveryOptionsRequest,
        ) -> Result<types::PutConfigurationSetDeliveryOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.put_configuration_set_delivery_options_v2(ctx, input)
        }
        async fn put_configuration_set_reputation_options(
            &self,
            ctx: &RequestContext,
            input: types::PutConfigurationSetReputationOptionsRequest,
        ) -> Result<types::PutConfigurationSetReputationOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.put_configuration_set_reputation_options_v2(ctx, input)
        }
        async fn put_configuration_set_sending_options(
            &self,
            ctx: &RequestContext,
            input: types::PutConfigurationSetSendingOptionsRequest,
        ) -> Result<types::PutConfigurationSetSendingOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.put_configuration_set_sending_options_v2(ctx, input)
        }
        async fn put_configuration_set_suppression_options(
            &self,
            ctx: &RequestContext,
            input: types::PutConfigurationSetSuppressionOptionsRequest,
        ) -> Result<types::PutConfigurationSetSuppressionOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.put_configuration_set_suppression_options_v2(ctx, input)
        }
        async fn put_configuration_set_tracking_options(
            &self,
            ctx: &RequestContext,
            input: types::PutConfigurationSetTrackingOptionsRequest,
        ) -> Result<types::PutConfigurationSetTrackingOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.put_configuration_set_tracking_options_v2(ctx, input)
        }
        async fn put_configuration_set_vdm_options(
            &self,
            ctx: &RequestContext,
            input: types::PutConfigurationSetVdmOptionsRequest,
        ) -> Result<types::PutConfigurationSetVdmOptionsResponse, ServiceError> {
            self.observe(ctx);
            self.put_configuration_set_vdm_options_v2(ctx, input)
        }
        async fn put_dedicated_ip_in_pool(
            &self,
            ctx: &RequestContext,
            input: types::PutDedicatedIpInPoolRequest,
        ) -> Result<types::PutDedicatedIpInPoolResponse, ServiceError> {
            self.observe(ctx);
            self.put_dedicated_ip_in_pool_v2(ctx, input)
        }
        async fn put_dedicated_ip_pool_scaling_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutDedicatedIpPoolScalingAttributesRequest,
        ) -> Result<types::PutDedicatedIpPoolScalingAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_dedicated_ip_pool_scaling_attributes_v2(ctx, input)
        }
        async fn put_dedicated_ip_warmup_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutDedicatedIpWarmupAttributesRequest,
        ) -> Result<types::PutDedicatedIpWarmupAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_dedicated_ip_warmup_attributes_v2(ctx, input)
        }
        async fn put_deliverability_dashboard_option(
            &self,
            ctx: &RequestContext,
            input: types::PutDeliverabilityDashboardOptionRequest,
        ) -> Result<types::PutDeliverabilityDashboardOptionResponse, ServiceError> {
            self.observe(ctx);
            self.put_deliverability_dashboard_option_v2(ctx, input)
        }
        async fn put_email_identity_configuration_set_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutEmailIdentityConfigurationSetAttributesRequest,
        ) -> Result<types::PutEmailIdentityConfigurationSetAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_email_identity_configuration_set_attributes_v2(ctx, input)
        }
        async fn put_email_identity_dkim_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutEmailIdentityDkimAttributesRequest,
        ) -> Result<types::PutEmailIdentityDkimAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_email_identity_dkim_attributes_v2(ctx, input)
        }
        async fn put_email_identity_dkim_signing_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutEmailIdentityDkimSigningAttributesRequest,
        ) -> Result<types::PutEmailIdentityDkimSigningAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_email_identity_dkim_signing_attributes_v2(ctx, input)
        }
        async fn put_email_identity_feedback_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutEmailIdentityFeedbackAttributesRequest,
        ) -> Result<types::PutEmailIdentityFeedbackAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_email_identity_feedback_attributes_v2(ctx, input)
        }
        async fn put_email_identity_mail_from_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutEmailIdentityMailFromAttributesRequest,
        ) -> Result<types::PutEmailIdentityMailFromAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_email_identity_mail_from_attributes_v2(ctx, input)
        }
        async fn put_suppressed_destination(
            &self,
            ctx: &RequestContext,
            input: types::PutSuppressedDestinationRequest,
        ) -> Result<types::PutSuppressedDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.put_suppressed_destination_v2(ctx, input)
        }
        async fn put_tenant_suppression_attributes(
            &self,
            ctx: &RequestContext,
            input: types::PutTenantSuppressionAttributesRequest,
        ) -> Result<types::PutTenantSuppressionAttributesResponse, ServiceError> {
            self.observe(ctx);
            self.put_tenant_suppression_attributes_v2(ctx, input)
        }
        async fn send_bulk_email(
            &self,
            ctx: &RequestContext,
            input: types::SendBulkEmailRequest,
        ) -> Result<types::SendBulkEmailResponse, ServiceError> {
            self.observe(ctx);
            self.send_bulk_email_v2(ctx, input)
        }
        async fn send_custom_verification_email(
            &self,
            ctx: &RequestContext,
            input: types::SendCustomVerificationEmailRequest,
        ) -> Result<types::SendCustomVerificationEmailResponse, ServiceError> {
            self.observe(ctx);
            self.send_custom_verification_email_v2(ctx, input)
        }
        async fn send_email(
            &self,
            ctx: &RequestContext,
            input: types::SendEmailRequest,
        ) -> Result<types::SendEmailResponse, ServiceError> {
            self.observe(ctx);
            self.send_email_v2(ctx, input)
        }
        async fn tag_resource(
            &self,
            ctx: &RequestContext,
            input: types::TagResourceRequest,
        ) -> Result<types::TagResourceResponse, ServiceError> {
            self.observe(ctx);
            self.tag_resource_v2(ctx, input)
        }
        async fn test_render_email_template(
            &self,
            ctx: &RequestContext,
            input: types::TestRenderEmailTemplateRequest,
        ) -> Result<types::TestRenderEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.test_render_email_template_v2(ctx, input)
        }
        async fn untag_resource(
            &self,
            ctx: &RequestContext,
            input: types::UntagResourceRequest,
        ) -> Result<types::UntagResourceResponse, ServiceError> {
            self.observe(ctx);
            self.untag_resource_v2(ctx, input)
        }
        async fn update_configuration_set(
            &self,
            ctx: &RequestContext,
            input: types::UpdateConfigurationSetRequest,
        ) -> Result<types::UpdateConfigurationSetResponse, ServiceError> {
            self.observe(ctx);
            self.update_configuration_set_v2(ctx, input)
        }
        async fn update_configuration_set_event_destination(
            &self,
            ctx: &RequestContext,
            input: types::UpdateConfigurationSetEventDestinationRequest,
        ) -> Result<types::UpdateConfigurationSetEventDestinationResponse, ServiceError> {
            self.observe(ctx);
            self.update_configuration_set_event_destination_v2(ctx, input)
        }
        async fn update_contact(
            &self,
            ctx: &RequestContext,
            input: types::UpdateContactRequest,
        ) -> Result<types::UpdateContactResponse, ServiceError> {
            self.observe(ctx);
            self.update_contact_v2(ctx, input)
        }
        async fn update_contact_list(
            &self,
            ctx: &RequestContext,
            input: types::UpdateContactListRequest,
        ) -> Result<types::UpdateContactListResponse, ServiceError> {
            self.observe(ctx);
            self.update_contact_list_v2(ctx, input)
        }
        async fn update_custom_verification_email_template(
            &self,
            ctx: &RequestContext,
            input: types::UpdateCustomVerificationEmailTemplateRequest,
        ) -> Result<types::UpdateCustomVerificationEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.update_custom_verification_email_template_v2(ctx, input)
        }
        async fn update_email_identity_policy(
            &self,
            ctx: &RequestContext,
            input: types::UpdateEmailIdentityPolicyRequest,
        ) -> Result<types::UpdateEmailIdentityPolicyResponse, ServiceError> {
            self.observe(ctx);
            self.update_email_identity_policy_v2(ctx, input)
        }
        async fn update_email_template(
            &self,
            ctx: &RequestContext,
            input: types::UpdateEmailTemplateRequest,
        ) -> Result<types::UpdateEmailTemplateResponse, ServiceError> {
            self.observe(ctx);
            self.update_email_template_v2(ctx, input)
        }
        async fn update_reputation_entity_customer_managed_status(
            &self,
            ctx: &RequestContext,
            input: types::UpdateReputationEntityCustomerManagedStatusRequest,
        ) -> Result<types::UpdateReputationEntityCustomerManagedStatusResponse, ServiceError> {
            self.observe(ctx);
            self.update_reputation_entity_customer_managed_status_v2(ctx, input)
        }
        async fn update_reputation_entity_policy(
            &self,
            ctx: &RequestContext,
            input: types::UpdateReputationEntityPolicyRequest,
        ) -> Result<types::UpdateReputationEntityPolicyResponse, ServiceError> {
            self.observe(ctx);
            self.update_reputation_entity_policy_v2(ctx, input)
        }
    }
}
