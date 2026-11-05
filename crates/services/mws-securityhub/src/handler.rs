//! Forwards every generated operation to its implementation.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::SecurityHub;

#[async_trait::async_trait]
impl Handler for SecurityHub {
    async fn accept_administrator_invitation(
        &self,
        ctx: &RequestContext,
        input: types::AcceptAdministratorInvitationRequest,
    ) -> Result<types::AcceptAdministratorInvitationResponse, ServiceError> {
        self.accept_administrator_invitation_op(ctx, input)
    }
    async fn accept_invitation(
        &self,
        ctx: &RequestContext,
        input: types::AcceptInvitationRequest,
    ) -> Result<types::AcceptInvitationResponse, ServiceError> {
        self.accept_invitation_op(ctx, input)
    }
    async fn batch_delete_automation_rules(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteAutomationRulesRequest,
    ) -> Result<types::BatchDeleteAutomationRulesResponse, ServiceError> {
        self.batch_delete_automation_rules_op(ctx, input)
    }
    async fn batch_disable_standards(
        &self,
        ctx: &RequestContext,
        input: types::BatchDisableStandardsRequest,
    ) -> Result<types::BatchDisableStandardsResponse, ServiceError> {
        self.batch_disable_standards_op(ctx, input)
    }
    async fn batch_enable_standards(
        &self,
        ctx: &RequestContext,
        input: types::BatchEnableStandardsRequest,
    ) -> Result<types::BatchEnableStandardsResponse, ServiceError> {
        self.batch_enable_standards_op(ctx, input)
    }
    async fn batch_get_automation_rules(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetAutomationRulesRequest,
    ) -> Result<types::BatchGetAutomationRulesResponse, ServiceError> {
        self.batch_get_automation_rules_op(ctx, input)
    }
    async fn batch_get_configuration_policy_associations(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetConfigurationPolicyAssociationsRequest,
    ) -> Result<types::BatchGetConfigurationPolicyAssociationsResponse, ServiceError> {
        self.batch_get_configuration_policy_associations_op(ctx, input)
    }
    async fn batch_get_security_controls(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetSecurityControlsRequest,
    ) -> Result<types::BatchGetSecurityControlsResponse, ServiceError> {
        self.batch_get_security_controls_op(ctx, input)
    }
    async fn batch_get_standards_control_associations(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetStandardsControlAssociationsRequest,
    ) -> Result<types::BatchGetStandardsControlAssociationsResponse, ServiceError> {
        self.batch_get_standards_control_associations_op(ctx, input)
    }
    async fn batch_import_findings(
        &self,
        ctx: &RequestContext,
        input: types::BatchImportFindingsRequest,
    ) -> Result<types::BatchImportFindingsResponse, ServiceError> {
        self.batch_import_findings_op(ctx, input)
    }
    async fn batch_update_automation_rules(
        &self,
        ctx: &RequestContext,
        input: types::BatchUpdateAutomationRulesRequest,
    ) -> Result<types::BatchUpdateAutomationRulesResponse, ServiceError> {
        self.batch_update_automation_rules_op(ctx, input)
    }
    async fn batch_update_findings(
        &self,
        ctx: &RequestContext,
        input: types::BatchUpdateFindingsRequest,
    ) -> Result<types::BatchUpdateFindingsResponse, ServiceError> {
        self.batch_update_findings_op(ctx, input)
    }
    async fn batch_update_findings_v2(
        &self,
        ctx: &RequestContext,
        input: types::BatchUpdateFindingsV2Request,
    ) -> Result<types::BatchUpdateFindingsV2Response, ServiceError> {
        self.batch_update_findings_v2_op(ctx, input)
    }
    async fn batch_update_standards_control_associations(
        &self,
        ctx: &RequestContext,
        input: types::BatchUpdateStandardsControlAssociationsRequest,
    ) -> Result<types::BatchUpdateStandardsControlAssociationsResponse, ServiceError> {
        self.batch_update_standards_control_associations_op(ctx, input)
    }
    async fn cancel_export_job_v2(
        &self,
        ctx: &RequestContext,
        input: types::CancelExportJobV2Request,
    ) -> Result<types::CancelExportJobV2Response, ServiceError> {
        self.cancel_export_job_v2_op(ctx, input)
    }
    async fn create_action_target(
        &self,
        ctx: &RequestContext,
        input: types::CreateActionTargetRequest,
    ) -> Result<types::CreateActionTargetResponse, ServiceError> {
        self.create_action_target_op(ctx, input)
    }
    async fn create_aggregator_v2(
        &self,
        ctx: &RequestContext,
        input: types::CreateAggregatorV2Request,
    ) -> Result<types::CreateAggregatorV2Response, ServiceError> {
        self.create_aggregator_v2_op(ctx, input)
    }
    async fn create_automation_rule(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomationRuleRequest,
    ) -> Result<types::CreateAutomationRuleResponse, ServiceError> {
        self.create_automation_rule_op(ctx, input)
    }
    async fn create_automation_rule_v2(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomationRuleV2Request,
    ) -> Result<types::CreateAutomationRuleV2Response, ServiceError> {
        self.create_automation_rule_v2_op(ctx, input)
    }
    async fn create_configuration_policy(
        &self,
        ctx: &RequestContext,
        input: types::CreateConfigurationPolicyRequest,
    ) -> Result<types::CreateConfigurationPolicyResponse, ServiceError> {
        self.create_configuration_policy_op(ctx, input)
    }
    async fn create_connector(
        &self,
        ctx: &RequestContext,
        input: types::CreateConnectorRequest,
    ) -> Result<types::CreateConnectorResponse, ServiceError> {
        self.create_connector_op(ctx, input)
    }
    async fn create_connector_v2(
        &self,
        ctx: &RequestContext,
        input: types::CreateConnectorV2Request,
    ) -> Result<types::CreateConnectorV2Response, ServiceError> {
        self.create_connector_v2_op(ctx, input)
    }
    async fn create_finding_aggregator(
        &self,
        ctx: &RequestContext,
        input: types::CreateFindingAggregatorRequest,
    ) -> Result<types::CreateFindingAggregatorResponse, ServiceError> {
        self.create_finding_aggregator_op(ctx, input)
    }
    async fn create_insight(
        &self,
        ctx: &RequestContext,
        input: types::CreateInsightRequest,
    ) -> Result<types::CreateInsightResponse, ServiceError> {
        self.create_insight_op(ctx, input)
    }
    async fn create_members(
        &self,
        ctx: &RequestContext,
        input: types::CreateMembersRequest,
    ) -> Result<types::CreateMembersResponse, ServiceError> {
        self.create_members_op(ctx, input)
    }
    async fn create_ticket_v2(
        &self,
        ctx: &RequestContext,
        input: types::CreateTicketV2Request,
    ) -> Result<types::CreateTicketV2Response, ServiceError> {
        self.create_ticket_v2_op(ctx, input)
    }
    async fn decline_invitations(
        &self,
        ctx: &RequestContext,
        input: types::DeclineInvitationsRequest,
    ) -> Result<types::DeclineInvitationsResponse, ServiceError> {
        self.decline_invitations_op(ctx, input)
    }
    async fn delete_action_target(
        &self,
        ctx: &RequestContext,
        input: types::DeleteActionTargetRequest,
    ) -> Result<types::DeleteActionTargetResponse, ServiceError> {
        self.delete_action_target_op(ctx, input)
    }
    async fn delete_aggregator_v2(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAggregatorV2Request,
    ) -> Result<types::DeleteAggregatorV2Response, ServiceError> {
        self.delete_aggregator_v2_op(ctx, input)
    }
    async fn delete_automation_rule_v2(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutomationRuleV2Request,
    ) -> Result<types::DeleteAutomationRuleV2Response, ServiceError> {
        self.delete_automation_rule_v2_op(ctx, input)
    }
    async fn delete_configuration_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteConfigurationPolicyRequest,
    ) -> Result<types::DeleteConfigurationPolicyResponse, ServiceError> {
        self.delete_configuration_policy_op(ctx, input)
    }
    async fn delete_connector(
        &self,
        ctx: &RequestContext,
        input: types::DeleteConnectorRequest,
    ) -> Result<types::DeleteConnectorResponse, ServiceError> {
        self.delete_connector_op(ctx, input)
    }
    async fn delete_connector_v2(
        &self,
        ctx: &RequestContext,
        input: types::DeleteConnectorV2Request,
    ) -> Result<types::DeleteConnectorV2Response, ServiceError> {
        self.delete_connector_v2_op(ctx, input)
    }
    async fn delete_finding_aggregator(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFindingAggregatorRequest,
    ) -> Result<types::DeleteFindingAggregatorResponse, ServiceError> {
        self.delete_finding_aggregator_op(ctx, input)
    }
    async fn delete_insight(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInsightRequest,
    ) -> Result<types::DeleteInsightResponse, ServiceError> {
        self.delete_insight_op(ctx, input)
    }
    async fn delete_invitations(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInvitationsRequest,
    ) -> Result<types::DeleteInvitationsResponse, ServiceError> {
        self.delete_invitations_op(ctx, input)
    }
    async fn delete_members(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMembersRequest,
    ) -> Result<types::DeleteMembersResponse, ServiceError> {
        self.delete_members_op(ctx, input)
    }
    async fn describe_action_targets(
        &self,
        ctx: &RequestContext,
        input: types::DescribeActionTargetsRequest,
    ) -> Result<types::DescribeActionTargetsResponse, ServiceError> {
        self.describe_action_targets_op(ctx, input)
    }
    async fn describe_hub(
        &self,
        ctx: &RequestContext,
        input: types::DescribeHubRequest,
    ) -> Result<types::DescribeHubResponse, ServiceError> {
        self.describe_hub_op(ctx, input)
    }
    async fn describe_organization_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DescribeOrganizationConfigurationRequest,
    ) -> Result<types::DescribeOrganizationConfigurationResponse, ServiceError> {
        self.describe_organization_configuration_op(ctx, input)
    }
    async fn describe_products(
        &self,
        ctx: &RequestContext,
        input: types::DescribeProductsRequest,
    ) -> Result<types::DescribeProductsResponse, ServiceError> {
        self.describe_products_op(ctx, input)
    }
    async fn describe_products_v2(
        &self,
        ctx: &RequestContext,
        input: types::DescribeProductsV2Request,
    ) -> Result<types::DescribeProductsV2Response, ServiceError> {
        self.describe_products_v2_op(ctx, input)
    }
    async fn describe_security_hub_v2(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSecurityHubV2Request,
    ) -> Result<types::DescribeSecurityHubV2Response, ServiceError> {
        self.describe_security_hub_v2_op(ctx, input)
    }
    async fn describe_standards(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStandardsRequest,
    ) -> Result<types::DescribeStandardsResponse, ServiceError> {
        self.describe_standards_op(ctx, input)
    }
    async fn describe_standards_controls(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStandardsControlsRequest,
    ) -> Result<types::DescribeStandardsControlsResponse, ServiceError> {
        self.describe_standards_controls_op(ctx, input)
    }
    async fn disable_import_findings_for_product(
        &self,
        ctx: &RequestContext,
        input: types::DisableImportFindingsForProductRequest,
    ) -> Result<types::DisableImportFindingsForProductResponse, ServiceError> {
        self.disable_import_findings_for_product_op(ctx, input)
    }
    async fn disable_organization_admin_account(
        &self,
        ctx: &RequestContext,
        input: types::DisableOrganizationAdminAccountRequest,
    ) -> Result<types::DisableOrganizationAdminAccountResponse, ServiceError> {
        self.disable_organization_admin_account_op(ctx, input)
    }
    async fn disable_security_hub(
        &self,
        ctx: &RequestContext,
        input: types::DisableSecurityHubRequest,
    ) -> Result<types::DisableSecurityHubResponse, ServiceError> {
        self.disable_security_hub_op(ctx, input)
    }
    async fn disable_security_hub_feature_v2(
        &self,
        ctx: &RequestContext,
        input: types::DisableSecurityHubFeatureV2Request,
    ) -> Result<types::DisableSecurityHubFeatureV2Response, ServiceError> {
        self.disable_security_hub_feature_v2_op(ctx, input)
    }
    async fn disable_security_hub_v2(
        &self,
        ctx: &RequestContext,
        input: types::DisableSecurityHubV2Request,
    ) -> Result<types::DisableSecurityHubV2Response, ServiceError> {
        self.disable_security_hub_v2_op(ctx, input)
    }
    async fn disassociate_from_administrator_account(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateFromAdministratorAccountRequest,
    ) -> Result<types::DisassociateFromAdministratorAccountResponse, ServiceError> {
        self.disassociate_from_administrator_account_op(ctx, input)
    }
    async fn disassociate_from_master_account(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateFromMasterAccountRequest,
    ) -> Result<types::DisassociateFromMasterAccountResponse, ServiceError> {
        self.disassociate_from_master_account_op(ctx, input)
    }
    async fn disassociate_members(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateMembersRequest,
    ) -> Result<types::DisassociateMembersResponse, ServiceError> {
        self.disassociate_members_op(ctx, input)
    }
    async fn enable_import_findings_for_product(
        &self,
        ctx: &RequestContext,
        input: types::EnableImportFindingsForProductRequest,
    ) -> Result<types::EnableImportFindingsForProductResponse, ServiceError> {
        self.enable_import_findings_for_product_op(ctx, input)
    }
    async fn enable_organization_admin_account(
        &self,
        ctx: &RequestContext,
        input: types::EnableOrganizationAdminAccountRequest,
    ) -> Result<types::EnableOrganizationAdminAccountResponse, ServiceError> {
        self.enable_organization_admin_account_op(ctx, input)
    }
    async fn enable_security_hub(
        &self,
        ctx: &RequestContext,
        input: types::EnableSecurityHubRequest,
    ) -> Result<types::EnableSecurityHubResponse, ServiceError> {
        self.enable_security_hub_op(ctx, input)
    }
    async fn enable_security_hub_feature_v2(
        &self,
        ctx: &RequestContext,
        input: types::EnableSecurityHubFeatureV2Request,
    ) -> Result<types::EnableSecurityHubFeatureV2Response, ServiceError> {
        self.enable_security_hub_feature_v2_op(ctx, input)
    }
    async fn enable_security_hub_v2(
        &self,
        ctx: &RequestContext,
        input: types::EnableSecurityHubV2Request,
    ) -> Result<types::EnableSecurityHubV2Response, ServiceError> {
        self.enable_security_hub_v2_op(ctx, input)
    }
    async fn generate_recommended_policy_v2(
        &self,
        ctx: &RequestContext,
        input: types::GenerateRecommendedPolicyV2Request,
    ) -> Result<types::GenerateRecommendedPolicyV2Response, ServiceError> {
        self.generate_recommended_policy_v2_op(ctx, input)
    }
    async fn get_administrator_account(
        &self,
        ctx: &RequestContext,
        input: types::GetAdministratorAccountRequest,
    ) -> Result<types::GetAdministratorAccountResponse, ServiceError> {
        self.get_administrator_account_op(ctx, input)
    }
    async fn get_aggregator_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetAggregatorV2Request,
    ) -> Result<types::GetAggregatorV2Response, ServiceError> {
        self.get_aggregator_v2_op(ctx, input)
    }
    async fn get_automation_rule_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomationRuleV2Request,
    ) -> Result<types::GetAutomationRuleV2Response, ServiceError> {
        self.get_automation_rule_v2_op(ctx, input)
    }
    async fn get_configuration_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetConfigurationPolicyRequest,
    ) -> Result<types::GetConfigurationPolicyResponse, ServiceError> {
        self.get_configuration_policy_op(ctx, input)
    }
    async fn get_configuration_policy_association(
        &self,
        ctx: &RequestContext,
        input: types::GetConfigurationPolicyAssociationRequest,
    ) -> Result<types::GetConfigurationPolicyAssociationResponse, ServiceError> {
        self.get_configuration_policy_association_op(ctx, input)
    }
    async fn get_connector(
        &self,
        ctx: &RequestContext,
        input: types::GetConnectorRequest,
    ) -> Result<types::GetConnectorResponse, ServiceError> {
        self.get_connector_op(ctx, input)
    }
    async fn get_connector_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetConnectorV2Request,
    ) -> Result<types::GetConnectorV2Response, ServiceError> {
        self.get_connector_v2_op(ctx, input)
    }
    async fn get_enabled_standards(
        &self,
        ctx: &RequestContext,
        input: types::GetEnabledStandardsRequest,
    ) -> Result<types::GetEnabledStandardsResponse, ServiceError> {
        self.get_enabled_standards_op(ctx, input)
    }
    async fn get_export_job_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetExportJobV2Request,
    ) -> Result<types::GetExportJobV2Response, ServiceError> {
        self.get_export_job_v2_op(ctx, input)
    }
    async fn get_finding_aggregator(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingAggregatorRequest,
    ) -> Result<types::GetFindingAggregatorResponse, ServiceError> {
        self.get_finding_aggregator_op(ctx, input)
    }
    async fn get_finding_history(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingHistoryRequest,
    ) -> Result<types::GetFindingHistoryResponse, ServiceError> {
        self.get_finding_history_op(ctx, input)
    }
    async fn get_finding_statistics_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingStatisticsV2Request,
    ) -> Result<types::GetFindingStatisticsV2Response, ServiceError> {
        self.get_finding_statistics_v2_op(ctx, input)
    }
    async fn get_findings(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsRequest,
    ) -> Result<types::GetFindingsResponse, ServiceError> {
        self.get_findings_op(ctx, input)
    }
    async fn get_findings_trends_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsTrendsV2Request,
    ) -> Result<types::GetFindingsTrendsV2Response, ServiceError> {
        self.get_findings_trends_v2_op(ctx, input)
    }
    async fn get_findings_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsV2Request,
    ) -> Result<types::GetFindingsV2Response, ServiceError> {
        self.get_findings_v2_op(ctx, input)
    }
    async fn get_insight_results(
        &self,
        ctx: &RequestContext,
        input: types::GetInsightResultsRequest,
    ) -> Result<types::GetInsightResultsResponse, ServiceError> {
        self.get_insight_results_op(ctx, input)
    }
    async fn get_insights(
        &self,
        ctx: &RequestContext,
        input: types::GetInsightsRequest,
    ) -> Result<types::GetInsightsResponse, ServiceError> {
        self.get_insights_op(ctx, input)
    }
    async fn get_invitations_count(
        &self,
        ctx: &RequestContext,
        input: types::GetInvitationsCountRequest,
    ) -> Result<types::GetInvitationsCountResponse, ServiceError> {
        self.get_invitations_count_op(ctx, input)
    }
    async fn get_master_account(
        &self,
        ctx: &RequestContext,
        input: types::GetMasterAccountRequest,
    ) -> Result<types::GetMasterAccountResponse, ServiceError> {
        self.get_master_account_op(ctx, input)
    }
    async fn get_members(
        &self,
        ctx: &RequestContext,
        input: types::GetMembersRequest,
    ) -> Result<types::GetMembersResponse, ServiceError> {
        self.get_members_op(ctx, input)
    }
    async fn get_recommended_policy_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetRecommendedPolicyV2Request,
    ) -> Result<types::GetRecommendedPolicyV2Response, ServiceError> {
        self.get_recommended_policy_v2_op(ctx, input)
    }
    async fn get_remediations_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetRemediationsV2Request,
    ) -> Result<types::GetRemediationsV2Response, ServiceError> {
        self.get_remediations_v2_op(ctx, input)
    }
    async fn get_resources_statistics_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcesStatisticsV2Request,
    ) -> Result<types::GetResourcesStatisticsV2Response, ServiceError> {
        self.get_resources_statistics_v2_op(ctx, input)
    }
    async fn get_resources_trends_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcesTrendsV2Request,
    ) -> Result<types::GetResourcesTrendsV2Response, ServiceError> {
        self.get_resources_trends_v2_op(ctx, input)
    }
    async fn get_resources_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcesV2Request,
    ) -> Result<types::GetResourcesV2Response, ServiceError> {
        self.get_resources_v2_op(ctx, input)
    }
    async fn get_security_control_definition(
        &self,
        ctx: &RequestContext,
        input: types::GetSecurityControlDefinitionRequest,
    ) -> Result<types::GetSecurityControlDefinitionResponse, ServiceError> {
        self.get_security_control_definition_op(ctx, input)
    }
    async fn get_software_resources_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetSoftwareResourcesV2Request,
    ) -> Result<types::GetSoftwareResourcesV2Response, ServiceError> {
        self.get_software_resources_v2_op(ctx, input)
    }
    async fn get_software_statistics_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetSoftwareStatisticsV2Request,
    ) -> Result<types::GetSoftwareStatisticsV2Response, ServiceError> {
        self.get_software_statistics_v2_op(ctx, input)
    }
    async fn get_software_v2(
        &self,
        ctx: &RequestContext,
        input: types::GetSoftwareV2Request,
    ) -> Result<types::GetSoftwareV2Response, ServiceError> {
        self.get_software_v2_op(ctx, input)
    }
    async fn invite_members(
        &self,
        ctx: &RequestContext,
        input: types::InviteMembersRequest,
    ) -> Result<types::InviteMembersResponse, ServiceError> {
        self.invite_members_op(ctx, input)
    }
    async fn list_aggregators_v2(
        &self,
        ctx: &RequestContext,
        input: types::ListAggregatorsV2Request,
    ) -> Result<types::ListAggregatorsV2Response, ServiceError> {
        self.list_aggregators_v2_op(ctx, input)
    }
    async fn list_automation_rules(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomationRulesRequest,
    ) -> Result<types::ListAutomationRulesResponse, ServiceError> {
        self.list_automation_rules_op(ctx, input)
    }
    async fn list_automation_rules_v2(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomationRulesV2Request,
    ) -> Result<types::ListAutomationRulesV2Response, ServiceError> {
        self.list_automation_rules_v2_op(ctx, input)
    }
    async fn list_configuration_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListConfigurationPoliciesRequest,
    ) -> Result<types::ListConfigurationPoliciesResponse, ServiceError> {
        self.list_configuration_policies_op(ctx, input)
    }
    async fn list_configuration_policy_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListConfigurationPolicyAssociationsRequest,
    ) -> Result<types::ListConfigurationPolicyAssociationsResponse, ServiceError> {
        self.list_configuration_policy_associations_op(ctx, input)
    }
    async fn list_connectors(
        &self,
        ctx: &RequestContext,
        input: types::ListConnectorsRequest,
    ) -> Result<types::ListConnectorsResponse, ServiceError> {
        self.list_connectors_op(ctx, input)
    }
    async fn list_connectors_v2(
        &self,
        ctx: &RequestContext,
        input: types::ListConnectorsV2Request,
    ) -> Result<types::ListConnectorsV2Response, ServiceError> {
        self.list_connectors_v2_op(ctx, input)
    }
    async fn list_enabled_products_for_import(
        &self,
        ctx: &RequestContext,
        input: types::ListEnabledProductsForImportRequest,
    ) -> Result<types::ListEnabledProductsForImportResponse, ServiceError> {
        self.list_enabled_products_for_import_op(ctx, input)
    }
    async fn list_export_jobs_v2(
        &self,
        ctx: &RequestContext,
        input: types::ListExportJobsV2Request,
    ) -> Result<types::ListExportJobsV2Response, ServiceError> {
        self.list_export_jobs_v2_op(ctx, input)
    }
    async fn list_exposures_by_remediation_v2(
        &self,
        ctx: &RequestContext,
        input: types::ListExposuresByRemediationV2Request,
    ) -> Result<types::ListExposuresByRemediationV2Response, ServiceError> {
        self.list_exposures_by_remediation_v2_op(ctx, input)
    }
    async fn list_finding_aggregators(
        &self,
        ctx: &RequestContext,
        input: types::ListFindingAggregatorsRequest,
    ) -> Result<types::ListFindingAggregatorsResponse, ServiceError> {
        self.list_finding_aggregators_op(ctx, input)
    }
    async fn list_free_trial_statuses_v2(
        &self,
        ctx: &RequestContext,
        input: types::ListFreeTrialStatusesV2Request,
    ) -> Result<types::ListFreeTrialStatusesV2Response, ServiceError> {
        self.list_free_trial_statuses_v2_op(ctx, input)
    }
    async fn list_invitations(
        &self,
        ctx: &RequestContext,
        input: types::ListInvitationsRequest,
    ) -> Result<types::ListInvitationsResponse, ServiceError> {
        self.list_invitations_op(ctx, input)
    }
    async fn list_members(
        &self,
        ctx: &RequestContext,
        input: types::ListMembersRequest,
    ) -> Result<types::ListMembersResponse, ServiceError> {
        self.list_members_op(ctx, input)
    }
    async fn list_organization_admin_accounts(
        &self,
        ctx: &RequestContext,
        input: types::ListOrganizationAdminAccountsRequest,
    ) -> Result<types::ListOrganizationAdminAccountsResponse, ServiceError> {
        self.list_organization_admin_accounts_op(ctx, input)
    }
    async fn list_security_control_definitions(
        &self,
        ctx: &RequestContext,
        input: types::ListSecurityControlDefinitionsRequest,
    ) -> Result<types::ListSecurityControlDefinitionsResponse, ServiceError> {
        self.list_security_control_definitions_op(ctx, input)
    }
    async fn list_standards_control_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListStandardsControlAssociationsRequest,
    ) -> Result<types::ListStandardsControlAssociationsResponse, ServiceError> {
        self.list_standards_control_associations_op(ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.list_tags_for_resource_op(ctx, input)
    }
    async fn register_connector_v2(
        &self,
        ctx: &RequestContext,
        input: types::RegisterConnectorV2Request,
    ) -> Result<types::RegisterConnectorV2Response, ServiceError> {
        self.register_connector_v2_op(ctx, input)
    }
    async fn start_configuration_policy_association(
        &self,
        ctx: &RequestContext,
        input: types::StartConfigurationPolicyAssociationRequest,
    ) -> Result<types::StartConfigurationPolicyAssociationResponse, ServiceError> {
        self.start_configuration_policy_association_op(ctx, input)
    }
    async fn start_configuration_policy_disassociation(
        &self,
        ctx: &RequestContext,
        input: types::StartConfigurationPolicyDisassociationRequest,
    ) -> Result<types::StartConfigurationPolicyDisassociationResponse, ServiceError> {
        self.start_configuration_policy_disassociation_op(ctx, input)
    }
    async fn start_export_job_v2(
        &self,
        ctx: &RequestContext,
        input: types::StartExportJobV2Request,
    ) -> Result<types::StartExportJobV2Response, ServiceError> {
        self.start_export_job_v2_op(ctx, input)
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        self.tag_resource_op(ctx, input)
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        self.untag_resource_op(ctx, input)
    }
    async fn update_action_target(
        &self,
        ctx: &RequestContext,
        input: types::UpdateActionTargetRequest,
    ) -> Result<types::UpdateActionTargetResponse, ServiceError> {
        self.update_action_target_op(ctx, input)
    }
    async fn update_aggregator_v2(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAggregatorV2Request,
    ) -> Result<types::UpdateAggregatorV2Response, ServiceError> {
        self.update_aggregator_v2_op(ctx, input)
    }
    async fn update_automation_rule_v2(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutomationRuleV2Request,
    ) -> Result<types::UpdateAutomationRuleV2Response, ServiceError> {
        self.update_automation_rule_v2_op(ctx, input)
    }
    async fn update_configuration_policy(
        &self,
        ctx: &RequestContext,
        input: types::UpdateConfigurationPolicyRequest,
    ) -> Result<types::UpdateConfigurationPolicyResponse, ServiceError> {
        self.update_configuration_policy_op(ctx, input)
    }
    async fn update_connector(
        &self,
        ctx: &RequestContext,
        input: types::UpdateConnectorRequest,
    ) -> Result<types::UpdateConnectorResponse, ServiceError> {
        self.update_connector_op(ctx, input)
    }
    async fn update_connector_v2(
        &self,
        ctx: &RequestContext,
        input: types::UpdateConnectorV2Request,
    ) -> Result<types::UpdateConnectorV2Response, ServiceError> {
        self.update_connector_v2_op(ctx, input)
    }
    async fn update_finding_aggregator(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFindingAggregatorRequest,
    ) -> Result<types::UpdateFindingAggregatorResponse, ServiceError> {
        self.update_finding_aggregator_op(ctx, input)
    }
    async fn update_findings(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFindingsRequest,
    ) -> Result<types::UpdateFindingsResponse, ServiceError> {
        self.update_findings_op(ctx, input)
    }
    async fn update_insight(
        &self,
        ctx: &RequestContext,
        input: types::UpdateInsightRequest,
    ) -> Result<types::UpdateInsightResponse, ServiceError> {
        self.update_insight_op(ctx, input)
    }
    async fn update_organization_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateOrganizationConfigurationRequest,
    ) -> Result<types::UpdateOrganizationConfigurationResponse, ServiceError> {
        self.update_organization_configuration_op(ctx, input)
    }
    async fn update_security_control(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSecurityControlRequest,
    ) -> Result<types::UpdateSecurityControlResponse, ServiceError> {
        self.update_security_control_op(ctx, input)
    }
    async fn update_security_hub_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSecurityHubConfigurationRequest,
    ) -> Result<types::UpdateSecurityHubConfigurationResponse, ServiceError> {
        self.update_security_hub_configuration_op(ctx, input)
    }
    async fn update_standards_control(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStandardsControlRequest,
    ) -> Result<types::UpdateStandardsControlResponse, ServiceError> {
        self.update_standards_control_op(ctx, input)
    }
}
