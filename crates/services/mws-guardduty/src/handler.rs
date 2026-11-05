//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::lists::{Kind, ListUpdate, NewList};
use crate::GuardDuty;

#[async_trait::async_trait]
impl Handler for GuardDuty {
    async fn accept_administrator_invitation(
        &self,
        ctx: &RequestContext,
        input: types::AcceptAdministratorInvitationRequest,
    ) -> Result<types::AcceptAdministratorInvitationResponse, ServiceError> {
        self.accept_administrator(
            ctx,
            "AcceptAdministratorInvitation",
            &input.detector_id,
            &input.administrator_id,
            &input.invitation_id,
        )?;
        Ok(Default::default())
    }
    async fn accept_invitation(
        &self,
        ctx: &RequestContext,
        input: types::AcceptInvitationRequest,
    ) -> Result<types::AcceptInvitationResponse, ServiceError> {
        self.accept_administrator(ctx, "AcceptInvitation", &input.detector_id, &input.master_id, &input.invitation_id)?;
        Ok(Default::default())
    }
    async fn archive_findings(
        &self,
        ctx: &RequestContext,
        input: types::ArchiveFindingsRequest,
    ) -> Result<types::ArchiveFindingsResponse, ServiceError> {
        GuardDuty::archive_findings(self, ctx, input)
    }
    async fn create_custom_detection_rule_association(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomDetectionRuleAssociationRequest,
    ) -> Result<types::CreateCustomDetectionRuleAssociationResponse, ServiceError> {
        GuardDuty::create_custom_detection_rule_association(self, ctx, input)
    }
    async fn create_custom_detection_rule_org_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomDetectionRuleOrgConfigurationRequest,
    ) -> Result<types::CreateCustomDetectionRuleOrgConfigurationResponse, ServiceError> {
        GuardDuty::create_custom_detection_rule_org_configuration(self, ctx, input)
    }
    async fn create_detector(
        &self,
        ctx: &RequestContext,
        input: types::CreateDetectorRequest,
    ) -> Result<types::CreateDetectorResponse, ServiceError> {
        GuardDuty::create_detector(self, ctx, input)
    }
    async fn create_filter(
        &self,
        ctx: &RequestContext,
        input: types::CreateFilterRequest,
    ) -> Result<types::CreateFilterResponse, ServiceError> {
        GuardDuty::create_filter(self, ctx, input)
    }
    async fn create_ip_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateIPSetRequest,
    ) -> Result<types::CreateIPSetResponse, ServiceError> {
        let id = self.create_list(
            ctx,
            Kind::IpSet,
            &input.detector_id,
            NewList {
                name: input.name,
                format: input.format,
                location: input.location,
                activate: input.activate,
                expected_bucket_owner: input.expected_bucket_owner,
                tags: input.tags,
                client_token: input.client_token,
            },
        )?;
        Ok(types::CreateIPSetResponse { ip_set_id: id })
    }
    async fn create_investigation(
        &self,
        ctx: &RequestContext,
        input: types::CreateInvestigationRequest,
    ) -> Result<types::CreateInvestigationResponse, ServiceError> {
        GuardDuty::create_investigation(self, ctx, input)
    }
    async fn create_malware_protection_plan(
        &self,
        ctx: &RequestContext,
        input: types::CreateMalwareProtectionPlanRequest,
    ) -> Result<types::CreateMalwareProtectionPlanResponse, ServiceError> {
        GuardDuty::create_malware_protection_plan(self, ctx, input).await
    }
    async fn create_members(
        &self,
        ctx: &RequestContext,
        input: types::CreateMembersRequest,
    ) -> Result<types::CreateMembersResponse, ServiceError> {
        GuardDuty::create_members(self, ctx, input)
    }
    async fn create_publishing_destination(
        &self,
        ctx: &RequestContext,
        input: types::CreatePublishingDestinationRequest,
    ) -> Result<types::CreatePublishingDestinationResponse, ServiceError> {
        GuardDuty::create_publishing_destination(self, ctx, input)
    }
    async fn create_sample_findings(
        &self,
        ctx: &RequestContext,
        input: types::CreateSampleFindingsRequest,
    ) -> Result<types::CreateSampleFindingsResponse, ServiceError> {
        GuardDuty::create_sample_findings(self, ctx, input)
    }
    async fn create_threat_entity_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateThreatEntitySetRequest,
    ) -> Result<types::CreateThreatEntitySetResponse, ServiceError> {
        let id = self.create_list(
            ctx,
            Kind::ThreatEntitySet,
            &input.detector_id,
            NewList {
                name: input.name,
                format: input.format,
                location: input.location,
                activate: input.activate,
                expected_bucket_owner: input.expected_bucket_owner,
                tags: input.tags,
                client_token: input.client_token,
            },
        )?;
        Ok(types::CreateThreatEntitySetResponse { threat_entity_set_id: id })
    }
    async fn create_threat_intel_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateThreatIntelSetRequest,
    ) -> Result<types::CreateThreatIntelSetResponse, ServiceError> {
        let id = self.create_list(
            ctx,
            Kind::ThreatIntelSet,
            &input.detector_id,
            NewList {
                name: input.name,
                format: input.format,
                location: input.location,
                activate: input.activate,
                expected_bucket_owner: input.expected_bucket_owner,
                tags: input.tags,
                client_token: input.client_token,
            },
        )?;
        Ok(types::CreateThreatIntelSetResponse { threat_intel_set_id: id })
    }
    async fn create_trusted_entity_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateTrustedEntitySetRequest,
    ) -> Result<types::CreateTrustedEntitySetResponse, ServiceError> {
        let id = self.create_list(
            ctx,
            Kind::TrustedEntitySet,
            &input.detector_id,
            NewList {
                name: input.name,
                format: input.format,
                location: input.location,
                activate: input.activate,
                expected_bucket_owner: input.expected_bucket_owner,
                tags: input.tags,
                client_token: input.client_token,
            },
        )?;
        Ok(types::CreateTrustedEntitySetResponse { trusted_entity_set_id: id })
    }
    async fn decline_invitations(
        &self,
        ctx: &RequestContext,
        input: types::DeclineInvitationsRequest,
    ) -> Result<types::DeclineInvitationsResponse, ServiceError> {
        GuardDuty::decline_invitations(self, ctx, input)
    }
    async fn delete_custom_detection_rule_association(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomDetectionRuleAssociationRequest,
    ) -> Result<types::DeleteCustomDetectionRuleAssociationResponse, ServiceError> {
        GuardDuty::delete_custom_detection_rule_association(self, ctx, input)
    }
    async fn delete_custom_detection_rule_org_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomDetectionRuleOrgConfigurationRequest,
    ) -> Result<types::DeleteCustomDetectionRuleOrgConfigurationResponse, ServiceError> {
        GuardDuty::delete_custom_detection_rule_org_configuration(self, ctx, input)
    }
    async fn delete_detector(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDetectorRequest,
    ) -> Result<types::DeleteDetectorResponse, ServiceError> {
        GuardDuty::delete_detector(self, ctx, input)
    }
    async fn delete_filter(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFilterRequest,
    ) -> Result<types::DeleteFilterResponse, ServiceError> {
        GuardDuty::delete_filter(self, ctx, input)
    }
    async fn delete_ip_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteIPSetRequest,
    ) -> Result<types::DeleteIPSetResponse, ServiceError> {
        self.delete_list(ctx, Kind::IpSet, &input.detector_id, &input.ip_set_id)?;
        Ok(Default::default())
    }
    async fn delete_invitations(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInvitationsRequest,
    ) -> Result<types::DeleteInvitationsResponse, ServiceError> {
        GuardDuty::delete_invitations(self, ctx, input)
    }
    async fn delete_malware_protection_plan(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMalwareProtectionPlanRequest,
    ) -> Result<(), ServiceError> {
        GuardDuty::delete_malware_protection_plan(self, ctx, input)
    }
    async fn delete_members(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMembersRequest,
    ) -> Result<types::DeleteMembersResponse, ServiceError> {
        GuardDuty::delete_members(self, ctx, input)
    }
    async fn delete_publishing_destination(
        &self,
        ctx: &RequestContext,
        input: types::DeletePublishingDestinationRequest,
    ) -> Result<types::DeletePublishingDestinationResponse, ServiceError> {
        GuardDuty::delete_publishing_destination(self, ctx, input)
    }
    async fn delete_threat_entity_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteThreatEntitySetRequest,
    ) -> Result<types::DeleteThreatEntitySetResponse, ServiceError> {
        self.delete_list(ctx, Kind::ThreatEntitySet, &input.detector_id, &input.threat_entity_set_id)?;
        Ok(Default::default())
    }
    async fn delete_threat_intel_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteThreatIntelSetRequest,
    ) -> Result<types::DeleteThreatIntelSetResponse, ServiceError> {
        self.delete_list(ctx, Kind::ThreatIntelSet, &input.detector_id, &input.threat_intel_set_id)?;
        Ok(Default::default())
    }
    async fn delete_trusted_entity_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTrustedEntitySetRequest,
    ) -> Result<types::DeleteTrustedEntitySetResponse, ServiceError> {
        self.delete_list(ctx, Kind::TrustedEntitySet, &input.detector_id, &input.trusted_entity_set_id)?;
        Ok(Default::default())
    }
    async fn describe_malware_scans(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMalwareScansRequest,
    ) -> Result<types::DescribeMalwareScansResponse, ServiceError> {
        GuardDuty::describe_malware_scans(self, ctx, input)
    }
    async fn describe_organization_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DescribeOrganizationConfigurationRequest,
    ) -> Result<types::DescribeOrganizationConfigurationResponse, ServiceError> {
        GuardDuty::describe_organization_configuration(self, ctx, input)
    }
    async fn describe_publishing_destination(
        &self,
        ctx: &RequestContext,
        input: types::DescribePublishingDestinationRequest,
    ) -> Result<types::DescribePublishingDestinationResponse, ServiceError> {
        GuardDuty::describe_publishing_destination(self, ctx, input)
    }
    async fn disable_organization_admin_account(
        &self,
        ctx: &RequestContext,
        input: types::DisableOrganizationAdminAccountRequest,
    ) -> Result<types::DisableOrganizationAdminAccountResponse, ServiceError> {
        GuardDuty::disable_organization_admin_account(self, ctx, input)
    }
    async fn disassociate_from_administrator_account(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateFromAdministratorAccountRequest,
    ) -> Result<types::DisassociateFromAdministratorAccountResponse, ServiceError> {
        self.leave_administrator(ctx, "DisassociateFromAdministratorAccount", &input.detector_id)?;
        Ok(Default::default())
    }
    async fn disassociate_from_master_account(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateFromMasterAccountRequest,
    ) -> Result<types::DisassociateFromMasterAccountResponse, ServiceError> {
        self.leave_administrator(ctx, "DisassociateFromMasterAccount", &input.detector_id)?;
        Ok(Default::default())
    }
    async fn disassociate_members(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateMembersRequest,
    ) -> Result<types::DisassociateMembersResponse, ServiceError> {
        GuardDuty::disassociate_members(self, ctx, input)
    }
    async fn enable_organization_admin_account(
        &self,
        ctx: &RequestContext,
        input: types::EnableOrganizationAdminAccountRequest,
    ) -> Result<types::EnableOrganizationAdminAccountResponse, ServiceError> {
        GuardDuty::enable_organization_admin_account(self, ctx, input)
    }
    async fn get_administrator_account(
        &self,
        ctx: &RequestContext,
        input: types::GetAdministratorAccountRequest,
    ) -> Result<types::GetAdministratorAccountResponse, ServiceError> {
        let administrator = self.administrator_of(ctx, "GetAdministratorAccount", &input.detector_id)?;
        Ok(types::GetAdministratorAccountResponse { administrator })
    }
    async fn get_coverage_statistics(
        &self,
        ctx: &RequestContext,
        input: types::GetCoverageStatisticsRequest,
    ) -> Result<types::GetCoverageStatisticsResponse, ServiceError> {
        GuardDuty::get_coverage_statistics(self, ctx, input)
    }
    async fn get_custom_detection_rule(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomDetectionRuleRequest,
    ) -> Result<types::GetCustomDetectionRuleResponse, ServiceError> {
        GuardDuty::get_custom_detection_rule(self, ctx, input)
    }
    async fn get_custom_detection_rule_association(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomDetectionRuleAssociationRequest,
    ) -> Result<types::GetCustomDetectionRuleAssociationResponse, ServiceError> {
        GuardDuty::get_custom_detection_rule_association(self, ctx, input)
    }
    async fn get_custom_detection_rule_org_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomDetectionRuleOrgConfigurationRequest,
    ) -> Result<types::GetCustomDetectionRuleOrgConfigurationResponse, ServiceError> {
        GuardDuty::get_custom_detection_rule_org_configuration(self, ctx, input)
    }
    async fn get_detector(
        &self,
        ctx: &RequestContext,
        input: types::GetDetectorRequest,
    ) -> Result<types::GetDetectorResponse, ServiceError> {
        GuardDuty::get_detector(self, ctx, input)
    }
    async fn get_filter(
        &self,
        ctx: &RequestContext,
        input: types::GetFilterRequest,
    ) -> Result<types::GetFilterResponse, ServiceError> {
        GuardDuty::get_filter(self, ctx, input)
    }
    async fn get_findings(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsRequest,
    ) -> Result<types::GetFindingsResponse, ServiceError> {
        GuardDuty::get_findings(self, ctx, input)
    }
    async fn get_findings_statistics(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsStatisticsRequest,
    ) -> Result<types::GetFindingsStatisticsResponse, ServiceError> {
        GuardDuty::get_findings_statistics(self, ctx, input)
    }
    async fn get_ip_set(
        &self,
        ctx: &RequestContext,
        input: types::GetIPSetRequest,
    ) -> Result<types::GetIPSetResponse, ServiceError> {
        let l = self.get_list(ctx, Kind::IpSet, &input.detector_id, &input.ip_set_id)?;
        Ok(types::GetIPSetResponse {
            name: l.name,
            format: l.format,
            location: l.location,
            status: l.status,
            tags: Some(l.tags),
            expected_bucket_owner: l.expected_bucket_owner,
        })
    }
    async fn get_investigation(
        &self,
        ctx: &RequestContext,
        input: types::GetInvestigationRequest,
    ) -> Result<types::GetInvestigationResponse, ServiceError> {
        GuardDuty::get_investigation(self, ctx, input)
    }
    async fn get_invitations_count(
        &self,
        ctx: &RequestContext,
        input: types::GetInvitationsCountRequest,
    ) -> Result<types::GetInvitationsCountResponse, ServiceError> {
        GuardDuty::get_invitations_count(self, ctx, input)
    }
    async fn get_malware_protection_plan(
        &self,
        ctx: &RequestContext,
        input: types::GetMalwareProtectionPlanRequest,
    ) -> Result<types::GetMalwareProtectionPlanResponse, ServiceError> {
        GuardDuty::get_malware_protection_plan(self, ctx, input)
    }
    async fn get_malware_scan(
        &self,
        ctx: &RequestContext,
        input: types::GetMalwareScanRequest,
    ) -> Result<types::GetMalwareScanResponse, ServiceError> {
        GuardDuty::get_malware_scan(self, ctx, input)
    }
    async fn get_malware_scan_settings(
        &self,
        ctx: &RequestContext,
        input: types::GetMalwareScanSettingsRequest,
    ) -> Result<types::GetMalwareScanSettingsResponse, ServiceError> {
        GuardDuty::get_malware_scan_settings(self, ctx, input)
    }
    async fn get_master_account(
        &self,
        ctx: &RequestContext,
        input: types::GetMasterAccountRequest,
    ) -> Result<types::GetMasterAccountResponse, ServiceError> {
        let a = self.administrator_of(ctx, "GetMasterAccount", &input.detector_id)?;
        Ok(types::GetMasterAccountResponse {
            master: types::Master {
                account_id: a.account_id,
                invitation_id: a.invitation_id,
                relationship_status: a.relationship_status,
                invited_at: a.invited_at,
            },
        })
    }
    async fn get_member_detectors(
        &self,
        ctx: &RequestContext,
        input: types::GetMemberDetectorsRequest,
    ) -> Result<types::GetMemberDetectorsResponse, ServiceError> {
        GuardDuty::get_member_detectors(self, ctx, input)
    }
    async fn get_members(
        &self,
        ctx: &RequestContext,
        input: types::GetMembersRequest,
    ) -> Result<types::GetMembersResponse, ServiceError> {
        GuardDuty::get_members(self, ctx, input)
    }
    async fn get_remaining_free_trial_days(
        &self,
        ctx: &RequestContext,
        input: types::GetRemainingFreeTrialDaysRequest,
    ) -> Result<types::GetRemainingFreeTrialDaysResponse, ServiceError> {
        GuardDuty::get_remaining_free_trial_days(self, ctx, input)
    }
    async fn get_threat_entity_set(
        &self,
        ctx: &RequestContext,
        input: types::GetThreatEntitySetRequest,
    ) -> Result<types::GetThreatEntitySetResponse, ServiceError> {
        let l = self.get_list(ctx, Kind::ThreatEntitySet, &input.detector_id, &input.threat_entity_set_id)?;
        Ok(types::GetThreatEntitySetResponse {
            name: l.name,
            format: l.format,
            location: l.location,
            status: l.status,
            tags: Some(l.tags),
            expected_bucket_owner: l.expected_bucket_owner,
            created_at: Some(l.created_at),
            updated_at: Some(l.updated_at),
            error_details: None,
        })
    }
    async fn get_threat_intel_set(
        &self,
        ctx: &RequestContext,
        input: types::GetThreatIntelSetRequest,
    ) -> Result<types::GetThreatIntelSetResponse, ServiceError> {
        let l = self.get_list(ctx, Kind::ThreatIntelSet, &input.detector_id, &input.threat_intel_set_id)?;
        Ok(types::GetThreatIntelSetResponse {
            name: l.name,
            format: l.format,
            location: l.location,
            status: l.status,
            tags: Some(l.tags),
            expected_bucket_owner: l.expected_bucket_owner,
        })
    }
    async fn get_trusted_entity_set(
        &self,
        ctx: &RequestContext,
        input: types::GetTrustedEntitySetRequest,
    ) -> Result<types::GetTrustedEntitySetResponse, ServiceError> {
        let l = self.get_list(ctx, Kind::TrustedEntitySet, &input.detector_id, &input.trusted_entity_set_id)?;
        Ok(types::GetTrustedEntitySetResponse {
            name: l.name,
            format: l.format,
            location: l.location,
            status: l.status,
            tags: Some(l.tags),
            expected_bucket_owner: l.expected_bucket_owner,
            created_at: Some(l.created_at),
            updated_at: Some(l.updated_at),
            error_details: None,
        })
    }
    async fn get_usage_statistics(
        &self,
        ctx: &RequestContext,
        input: types::GetUsageStatisticsRequest,
    ) -> Result<types::GetUsageStatisticsResponse, ServiceError> {
        GuardDuty::get_usage_statistics(self, ctx, input)
    }
    async fn invite_members(
        &self,
        ctx: &RequestContext,
        input: types::InviteMembersRequest,
    ) -> Result<types::InviteMembersResponse, ServiceError> {
        GuardDuty::invite_members(self, ctx, input)
    }
    async fn list_coverage(
        &self,
        ctx: &RequestContext,
        input: types::ListCoverageRequest,
    ) -> Result<types::ListCoverageResponse, ServiceError> {
        GuardDuty::list_coverage(self, ctx, input)
    }
    async fn list_custom_detection_rule_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomDetectionRuleAssociationsRequest,
    ) -> Result<types::ListCustomDetectionRuleAssociationsResponse, ServiceError> {
        GuardDuty::list_custom_detection_rule_associations(self, ctx, input)
    }
    async fn list_custom_detection_rule_org_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomDetectionRuleOrgConfigurationsRequest,
    ) -> Result<types::ListCustomDetectionRuleOrgConfigurationsResponse, ServiceError> {
        GuardDuty::list_custom_detection_rule_org_configurations(self, ctx, input)
    }
    async fn list_custom_detection_rules(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomDetectionRulesRequest,
    ) -> Result<types::ListCustomDetectionRulesResponse, ServiceError> {
        GuardDuty::list_custom_detection_rules(self, ctx, input)
    }
    async fn list_detectors(
        &self,
        ctx: &RequestContext,
        input: types::ListDetectorsRequest,
    ) -> Result<types::ListDetectorsResponse, ServiceError> {
        GuardDuty::list_detectors(self, ctx, input)
    }
    async fn list_filters(
        &self,
        ctx: &RequestContext,
        input: types::ListFiltersRequest,
    ) -> Result<types::ListFiltersResponse, ServiceError> {
        GuardDuty::list_filters(self, ctx, input)
    }
    async fn list_findings(
        &self,
        ctx: &RequestContext,
        input: types::ListFindingsRequest,
    ) -> Result<types::ListFindingsResponse, ServiceError> {
        GuardDuty::list_findings(self, ctx, input)
    }
    async fn list_ip_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListIPSetsRequest,
    ) -> Result<types::ListIPSetsResponse, ServiceError> {
        let (ids, next_token) =
            self.list_ids(ctx, Kind::IpSet, &input.detector_id, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListIPSetsResponse { ip_set_ids: ids, next_token })
    }
    async fn list_investigations(
        &self,
        ctx: &RequestContext,
        input: types::ListInvestigationsRequest,
    ) -> Result<types::ListInvestigationsResponse, ServiceError> {
        GuardDuty::list_investigations(self, ctx, input)
    }
    async fn list_invitations(
        &self,
        ctx: &RequestContext,
        input: types::ListInvitationsRequest,
    ) -> Result<types::ListInvitationsResponse, ServiceError> {
        GuardDuty::list_invitations(self, ctx, input)
    }
    async fn list_malware_protection_plans(
        &self,
        ctx: &RequestContext,
        input: types::ListMalwareProtectionPlansRequest,
    ) -> Result<types::ListMalwareProtectionPlansResponse, ServiceError> {
        GuardDuty::list_malware_protection_plans(self, ctx, input)
    }
    async fn list_malware_scans(
        &self,
        ctx: &RequestContext,
        input: types::ListMalwareScansRequest,
    ) -> Result<types::ListMalwareScansResponse, ServiceError> {
        GuardDuty::list_malware_scans(self, ctx, input)
    }
    async fn list_members(
        &self,
        ctx: &RequestContext,
        input: types::ListMembersRequest,
    ) -> Result<types::ListMembersResponse, ServiceError> {
        GuardDuty::list_members(self, ctx, input)
    }
    async fn list_organization_admin_accounts(
        &self,
        ctx: &RequestContext,
        input: types::ListOrganizationAdminAccountsRequest,
    ) -> Result<types::ListOrganizationAdminAccountsResponse, ServiceError> {
        GuardDuty::list_organization_admin_accounts(self, ctx, input)
    }
    async fn list_publishing_destinations(
        &self,
        ctx: &RequestContext,
        input: types::ListPublishingDestinationsRequest,
    ) -> Result<types::ListPublishingDestinationsResponse, ServiceError> {
        GuardDuty::list_publishing_destinations(self, ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        GuardDuty::list_tags_for_resource(self, ctx, input)
    }
    async fn list_threat_entity_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListThreatEntitySetsRequest,
    ) -> Result<types::ListThreatEntitySetsResponse, ServiceError> {
        let (ids, next_token) = self.list_ids(
            ctx,
            Kind::ThreatEntitySet,
            &input.detector_id,
            input.max_results,
            input.next_token.as_deref(),
        )?;
        Ok(types::ListThreatEntitySetsResponse { threat_entity_set_ids: ids, next_token })
    }
    async fn list_threat_intel_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListThreatIntelSetsRequest,
    ) -> Result<types::ListThreatIntelSetsResponse, ServiceError> {
        let (ids, next_token) = self.list_ids(
            ctx,
            Kind::ThreatIntelSet,
            &input.detector_id,
            input.max_results,
            input.next_token.as_deref(),
        )?;
        Ok(types::ListThreatIntelSetsResponse { threat_intel_set_ids: ids, next_token })
    }
    async fn list_trusted_entity_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListTrustedEntitySetsRequest,
    ) -> Result<types::ListTrustedEntitySetsResponse, ServiceError> {
        let (ids, next_token) = self.list_ids(
            ctx,
            Kind::TrustedEntitySet,
            &input.detector_id,
            input.max_results,
            input.next_token.as_deref(),
        )?;
        Ok(types::ListTrustedEntitySetsResponse { trusted_entity_set_ids: ids, next_token })
    }
    async fn send_object_malware_scan(
        &self,
        ctx: &RequestContext,
        input: types::SendObjectMalwareScanRequest,
    ) -> Result<types::SendObjectMalwareScanResponse, ServiceError> {
        GuardDuty::send_object_malware_scan(self, ctx, input).await
    }
    async fn start_malware_scan(
        &self,
        ctx: &RequestContext,
        input: types::StartMalwareScanRequest,
    ) -> Result<types::StartMalwareScanResponse, ServiceError> {
        GuardDuty::start_malware_scan(self, ctx, input)
    }
    async fn start_monitoring_members(
        &self,
        ctx: &RequestContext,
        input: types::StartMonitoringMembersRequest,
    ) -> Result<types::StartMonitoringMembersResponse, ServiceError> {
        GuardDuty::start_monitoring_members(self, ctx, input)
    }
    async fn stop_monitoring_members(
        &self,
        ctx: &RequestContext,
        input: types::StopMonitoringMembersRequest,
    ) -> Result<types::StopMonitoringMembersResponse, ServiceError> {
        GuardDuty::stop_monitoring_members(self, ctx, input)
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        GuardDuty::tag_resource(self, ctx, input)
    }
    async fn unarchive_findings(
        &self,
        ctx: &RequestContext,
        input: types::UnarchiveFindingsRequest,
    ) -> Result<types::UnarchiveFindingsResponse, ServiceError> {
        GuardDuty::unarchive_findings(self, ctx, input)
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        GuardDuty::untag_resource(self, ctx, input)
    }
    async fn update_custom_detection_rule_association(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomDetectionRuleAssociationRequest,
    ) -> Result<types::UpdateCustomDetectionRuleAssociationResponse, ServiceError> {
        GuardDuty::update_custom_detection_rule_association(self, ctx, input)
    }
    async fn update_custom_detection_rule_org_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomDetectionRuleOrgConfigurationRequest,
    ) -> Result<types::UpdateCustomDetectionRuleOrgConfigurationResponse, ServiceError> {
        GuardDuty::update_custom_detection_rule_org_configuration(self, ctx, input)
    }
    async fn update_detector(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDetectorRequest,
    ) -> Result<types::UpdateDetectorResponse, ServiceError> {
        GuardDuty::update_detector(self, ctx, input)
    }
    async fn update_filter(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFilterRequest,
    ) -> Result<types::UpdateFilterResponse, ServiceError> {
        GuardDuty::update_filter(self, ctx, input)
    }
    async fn update_findings_feedback(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFindingsFeedbackRequest,
    ) -> Result<types::UpdateFindingsFeedbackResponse, ServiceError> {
        GuardDuty::update_findings_feedback(self, ctx, input)
    }
    async fn update_ip_set(
        &self,
        ctx: &RequestContext,
        input: types::UpdateIPSetRequest,
    ) -> Result<types::UpdateIPSetResponse, ServiceError> {
        self.update_list(
            ctx,
            Kind::IpSet,
            &input.detector_id,
            &input.ip_set_id,
            ListUpdate {
                name: input.name,
                location: input.location,
                activate: input.activate,
                expected_bucket_owner: input.expected_bucket_owner,
            },
        )?;
        Ok(Default::default())
    }
    async fn update_malware_protection_plan(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMalwareProtectionPlanRequest,
    ) -> Result<(), ServiceError> {
        GuardDuty::update_malware_protection_plan(self, ctx, input).await
    }
    async fn update_malware_scan_settings(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMalwareScanSettingsRequest,
    ) -> Result<types::UpdateMalwareScanSettingsResponse, ServiceError> {
        GuardDuty::update_malware_scan_settings(self, ctx, input)
    }
    async fn update_member_detectors(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMemberDetectorsRequest,
    ) -> Result<types::UpdateMemberDetectorsResponse, ServiceError> {
        GuardDuty::update_member_detectors(self, ctx, input)
    }
    async fn update_organization_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateOrganizationConfigurationRequest,
    ) -> Result<types::UpdateOrganizationConfigurationResponse, ServiceError> {
        GuardDuty::update_organization_configuration(self, ctx, input)
    }
    async fn update_publishing_destination(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePublishingDestinationRequest,
    ) -> Result<types::UpdatePublishingDestinationResponse, ServiceError> {
        GuardDuty::update_publishing_destination(self, ctx, input)
    }
    async fn update_threat_entity_set(
        &self,
        ctx: &RequestContext,
        input: types::UpdateThreatEntitySetRequest,
    ) -> Result<types::UpdateThreatEntitySetResponse, ServiceError> {
        self.update_list(
            ctx,
            Kind::ThreatEntitySet,
            &input.detector_id,
            &input.threat_entity_set_id,
            ListUpdate {
                name: input.name,
                location: input.location,
                activate: input.activate,
                expected_bucket_owner: input.expected_bucket_owner,
            },
        )?;
        Ok(Default::default())
    }
    async fn update_threat_intel_set(
        &self,
        ctx: &RequestContext,
        input: types::UpdateThreatIntelSetRequest,
    ) -> Result<types::UpdateThreatIntelSetResponse, ServiceError> {
        self.update_list(
            ctx,
            Kind::ThreatIntelSet,
            &input.detector_id,
            &input.threat_intel_set_id,
            ListUpdate {
                name: input.name,
                location: input.location,
                activate: input.activate,
                expected_bucket_owner: input.expected_bucket_owner,
            },
        )?;
        Ok(Default::default())
    }
    async fn update_trusted_entity_set(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTrustedEntitySetRequest,
    ) -> Result<types::UpdateTrustedEntitySetResponse, ServiceError> {
        self.update_list(
            ctx,
            Kind::TrustedEntitySet,
            &input.detector_id,
            &input.trusted_entity_set_id,
            ListUpdate {
                name: input.name,
                location: input.location,
                activate: input.activate,
                expected_bucket_owner: input.expected_bucket_owner,
            },
        )?;
        Ok(Default::default())
    }
    async fn get_organization_statistics(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::GetOrganizationStatisticsResponse, ServiceError> {
        GuardDuty::get_organization_statistics(self, ctx)
    }
}
