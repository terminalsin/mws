//! AWS Organizations: the GuardDuty delegated administrator, the
//! organization configuration (auto-enable) and organization statistics.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::common::*;
use crate::detectors::{additional_for, apply_features};
use crate::generated::types;
use crate::state::{MemberRec, OrgAdmin, State};
use crate::{GuardDuty, OrgInfo};

const ORG_FEATURES: &[&str] = &[
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
    "EKS_RUNTIME_MONITORING",
    "RUNTIME_MONITORING",
    "AI_PROTECTION",
];

fn not_management() -> ServiceError {
    invalid_input(
        "The request is rejected because the current account is not the management account of an organization.",
    )
}

fn not_delegated_admin() -> ServiceError {
    invalid_input(
        "The request is rejected because the current account is not the delegated GuardDuty administrator account of an organization.",
    )
}

fn org_key(org: &str, region: &str) -> String {
    format!("{org}/{region}")
}

impl GuardDuty {
    pub(crate) fn org_admin_of<'s>(state: &'s State, org: &str, region: &str) -> Option<&'s str> {
        state.org_admins.get(&org_key(org, region)).map(|a| a.account.as_str())
    }

    fn caller_org(&self, ctx: &RequestContext) -> Option<OrgInfo> {
        self.organizations().and_then(|o| o.organization(&ctx.caller.account_id))
    }

    /// The caller's organization, which the caller must manage.
    fn managed_org(&self, ctx: &RequestContext) -> Result<OrgInfo, ServiceError> {
        self.caller_org(ctx).filter(|o| o.management_account == ctx.caller.account_id).ok_or_else(not_management)
    }

    pub(crate) fn enable_organization_admin_account(
        &self,
        ctx: &RequestContext,
        input: types::EnableOrganizationAdminAccountRequest,
    ) -> Result<types::EnableOrganizationAdminAccountResponse, ServiceError> {
        self.authorize(ctx, "EnableOrganizationAdminAccount", "*", ConditionContext::new())?;
        let org = self.managed_org(ctx)?;
        let admin = input.admin_account_id.clone();
        if !org.accounts.iter().any(|a| a.id == admin) {
            return Err(invalid_input(
                "The request is rejected because the input account ID is not a member of the current organization.",
            ));
        }
        {
            let state = self.lock();
            if let Some(current) = Self::org_admin_of(&state, &org.id, &ctx.region) {
                if current == admin {
                    return Ok(Default::default());
                }
                return Err(invalid_input(
                    "The request is rejected because an organization admin account is already enabled in this Region. Disable it first.",
                ));
            }
        }
        if admin != org.management_account {
            let link = self.organizations().expect("an organization was found through the link");
            link.register_admin(ctx, &admin).map_err(|e| {
                if e.code.contains("AccessDenied") {
                    e
                } else {
                    invalid_input(format!("The request failed because Organizations rejected it: {}", e.message))
                }
            })?;
        }
        let mut state = self.lock();
        state.org_admins.insert(
            org_key(&org.id, &ctx.region),
            OrgAdmin { account: admin.clone(), status: "ENABLED".into(), since: ctx.received_at },
        );
        let created = state.detector(&admin, &ctx.region).is_none();
        if created {
            state.account_mut(&admin, &ctx.region).detector = Some(crate::detectors::new_detector(ctx.received_at));
        }
        drop(state);
        // GuardDuty enables itself in the delegated administrator, with its
        // service-linked role.
        if let (true, Some(roles)) = (created, self.roles()) {
            roles.ensure(&admin);
        }
        Ok(Default::default())
    }

    pub(crate) fn disable_organization_admin_account(
        &self,
        ctx: &RequestContext,
        input: types::DisableOrganizationAdminAccountRequest,
    ) -> Result<types::DisableOrganizationAdminAccountResponse, ServiceError> {
        self.authorize(ctx, "DisableOrganizationAdminAccount", "*", ConditionContext::new())?;
        let org = self.managed_org(ctx)?;
        let admin = input.admin_account_id.clone();
        let elsewhere = {
            let state = self.lock();
            if Self::org_admin_of(&state, &org.id, &ctx.region) != Some(admin.as_str()) {
                return Err(invalid_input(
                    "The request is rejected because the input account ID is not the GuardDuty delegated administrator of the organization.",
                ));
            }
            state
                .org_admins
                .iter()
                .any(|(k, a)| a.account == admin && *k != org_key(&org.id, &ctx.region) && k.starts_with(&org.id))
        };
        if admin != org.management_account && !elsewhere {
            let link = self.organizations().expect("an organization was found through the link");
            if let Err(e) = link.deregister_admin(ctx, &admin) {
                if e.code.contains("AccessDenied") {
                    return Err(e);
                }
                tracing::debug!("deregistering GuardDuty delegated administrator: {}", e.message);
            }
        }
        let mut state = self.lock();
        state.org_admins.remove(&org_key(&org.id, &ctx.region));
        let org_members: Vec<String> = state
            .detector(&admin, &ctx.region)
            .map(|d| d.members.values().filter(|m| m.via_organization).map(|m| m.account.clone()).collect())
            .unwrap_or_default();
        for m in org_members {
            let acct = state.account_mut(&m, &ctx.region);
            if acct.administrator.as_ref().is_some_and(|l| l.account == admin) {
                acct.administrator = None;
            }
            if let Some(d) = state.detector_mut(&admin, &ctx.region) {
                d.members.remove(&m);
            }
        }
        if let Some(d) = state.detector_mut(&admin, &ctx.region) {
            d.org_config = Default::default();
        }
        Ok(Default::default())
    }

    pub(crate) fn list_organization_admin_accounts(
        &self,
        ctx: &RequestContext,
        input: types::ListOrganizationAdminAccountsRequest,
    ) -> Result<types::ListOrganizationAdminAccountsResponse, ServiceError> {
        self.authorize(ctx, "ListOrganizationAdminAccounts", "*", ConditionContext::new())?;
        let org = self.managed_org(ctx)?;
        let state = self.lock();
        let all: Vec<types::AdminAccount> = state
            .org_admins
            .get(&org_key(&org.id, &ctx.region))
            .map(|a| types::AdminAccount {
                admin_account_id: Some(a.account.clone()),
                admin_status: Some(a.status.clone()),
            })
            .into_iter()
            .collect();
        let (admin_accounts, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListOrganizationAdminAccountsResponse { admin_accounts: Some(admin_accounts), next_token })
    }

    /// The caller's organization, of which it must be the delegated
    /// administrator in this Region.
    fn administered_org(&self, ctx: &RequestContext) -> Result<OrgInfo, ServiceError> {
        let org = self.caller_org(ctx).ok_or_else(not_delegated_admin)?;
        let state = self.lock();
        if Self::org_admin_of(&state, &org.id, &ctx.region) != Some(ctx.caller.account_id.as_str()) {
            return Err(not_delegated_admin());
        }
        Ok(org)
    }

    pub(crate) fn describe_organization_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DescribeOrganizationConfigurationRequest,
    ) -> Result<types::DescribeOrganizationConfigurationResponse, ServiceError> {
        self.authorize_detector(ctx, "DescribeOrganizationConfiguration", &input.detector_id)?;
        self.administered_org(ctx)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let cfg = &det.org_config;
        let mode = |f: &str| cfg.features.get(f).map(|(m, _)| m.clone()).unwrap_or_else(|| "NONE".into());
        let features = ORG_FEATURES
            .iter()
            .map(|f| types::OrganizationFeatureConfigurationResult {
                name: Some(f.to_string()),
                auto_enable: Some(mode(f)),
                additional_configuration: (!additional_for(f).is_empty()).then(|| {
                    additional_for(f)
                        .iter()
                        .map(|a| types::OrganizationAdditionalConfigurationResult {
                            name: Some(a.to_string()),
                            auto_enable: Some(
                                cfg.features
                                    .get(*f)
                                    .and_then(|(_, add)| add.get(*a).cloned())
                                    .unwrap_or_else(|| "NONE".into()),
                            ),
                        })
                        .collect()
                }),
            })
            .collect();
        let on = |f: &str| mode(f) != "NONE";
        Ok(types::DescribeOrganizationConfigurationResponse {
            auto_enable: Some(cfg.auto_enable_members != "NONE"),
            member_account_limit_reached: false,
            data_sources: Some(types::OrganizationDataSourceConfigurationsResult {
                s3_logs: types::OrganizationS3LogsConfigurationResult { auto_enable: on("S3_DATA_EVENTS") },
                kubernetes: Some(types::OrganizationKubernetesConfigurationResult {
                    audit_logs: types::OrganizationKubernetesAuditLogsConfigurationResult {
                        auto_enable: on("EKS_AUDIT_LOGS"),
                    },
                }),
                malware_protection: Some(types::OrganizationMalwareProtectionConfigurationResult {
                    scan_ec2_instance_with_findings: Some(types::OrganizationScanEc2InstanceWithFindingsResult {
                        ebs_volumes: Some(types::OrganizationEbsVolumesResult {
                            auto_enable: Some(on("EBS_MALWARE_PROTECTION")),
                        }),
                    }),
                }),
            }),
            features: Some(features),
            next_token: None,
            auto_enable_organization_members: Some(cfg.auto_enable_members.clone()),
        })
    }

    pub(crate) fn update_organization_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateOrganizationConfigurationRequest,
    ) -> Result<types::UpdateOrganizationConfigurationResponse, ServiceError> {
        self.authorize_detector(ctx, "UpdateOrganizationConfiguration", &input.detector_id)?;
        self.administered_org(ctx)?;
        if input.auto_enable.is_some() && input.auto_enable_organization_members.is_some() {
            return Err(invalid_input(
                "The request is rejected because autoEnable and autoEnableOrganizationMembers are both specified. Use only autoEnableOrganizationMembers.",
            ));
        }
        if input.data_sources.is_some() && input.features.is_some() {
            return Err(invalid_input(
                "The request is rejected because both data source and feature configurations are specified. Use only features.",
            ));
        }
        let mut requested: Vec<(String, String, BTreeMap<String, String>)> = Vec::new();
        if let Some(ds) = &input.data_sources {
            let mode = |b: bool| if b { "NEW" } else { "NONE" }.to_string();
            if let Some(s3) = &ds.s3_logs {
                requested.push(("S3_DATA_EVENTS".into(), mode(s3.auto_enable), BTreeMap::new()));
            }
            if let Some(k) = &ds.kubernetes {
                requested.push(("EKS_AUDIT_LOGS".into(), mode(k.audit_logs.auto_enable), BTreeMap::new()));
            }
            if let Some(ebs) = ds
                .malware_protection
                .as_ref()
                .and_then(|m| m.scan_ec2_instance_with_findings.as_ref())
                .and_then(|s| s.ebs_volumes.as_ref())
                .and_then(|e| e.auto_enable)
            {
                requested.push(("EBS_MALWARE_PROTECTION".into(), mode(ebs), BTreeMap::new()));
            }
        }
        for f in input.features.iter().flatten() {
            let Some(name) = f.name.clone() else { continue };
            let add = f
                .additional_configuration
                .iter()
                .flatten()
                .filter_map(|a| Some((a.name.clone()?, a.auto_enable.clone().unwrap_or_else(|| "NONE".into()))))
                .collect();
            requested.push((name, f.auto_enable.clone().unwrap_or_else(|| "NONE".into()), add));
        }
        let members_mode = input
            .auto_enable_organization_members
            .clone()
            .or_else(|| input.auto_enable.map(|b| if b { "NEW" } else { "NONE" }.to_string()));
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        if let Some(m) = members_mode {
            if det.org_config.auto_enable_members != m {
                det.org_config.auto_enable_members = m;
                det.org_config.since = Some(ctx.received_at);
            }
        }
        for (name, mode, add) in &requested {
            let slot = det.org_config.features.entry(name.clone()).or_insert_with(|| ("NONE".into(), BTreeMap::new()));
            slot.0 = mode.clone();
            slot.1.extend(add.clone());
        }
        // `ALL` turns the feature on in every member now.
        let all: Vec<_> = requested.iter().filter(|(_, m, _)| m == "ALL").cloned().collect();
        let members: Vec<String> =
            det.members.values().filter(|m| m.via_organization).map(|m| m.account.clone()).collect();
        drop(state);
        if !all.is_empty() {
            let mut state = self.lock();
            for m in members {
                Self::apply_org_features(&mut state, ctx, &m, &all);
            }
        }
        self.sync_organization(ctx);
        Ok(Default::default())
    }

    fn apply_org_features(
        state: &mut State,
        ctx: &RequestContext,
        member: &str,
        features: &[(String, String, BTreeMap<String, String>)],
    ) {
        let Some(det) = state.detector_mut(member, &ctx.region) else { return };
        let req: crate::detectors::FeatureRequest = features
            .iter()
            .filter(|(_, m, _)| m != "NONE")
            .map(|(n, _, add)| {
                let add = add
                    .iter()
                    .filter(|(_, m)| *m != "NONE")
                    .map(|(a, _)| (Some(a.clone()), Some("ENABLED".to_string())))
                    .collect();
                (Some(n.clone()), Some("ENABLED".to_string()), add)
            })
            .collect();
        let _ = apply_features(&mut det.features, &req, ctx.received_at);
    }

    pub(crate) fn get_organization_statistics(
        &self,
        ctx: &RequestContext,
    ) -> Result<types::GetOrganizationStatisticsResponse, ServiceError> {
        self.authorize(ctx, "GetOrganizationStatistics", "*", ConditionContext::new())?;
        let org = self.administered_org(ctx)?;
        let state = self.lock();
        let admin = &ctx.caller.account_id;
        let det = state.detector(admin, &ctx.region);
        let members: Vec<&MemberRec> = det
            .map(|d| d.members.values().filter(|m| m.status == "Enabled" || m.status == "Disabled").collect())
            .unwrap_or_default();
        let enabled: Vec<&str> = members
            .iter()
            .filter(|m| state.detector(&m.account, &ctx.region).is_some_and(|d| d.enabled))
            .map(|m| m.account.as_str())
            .chain(det.filter(|d| d.enabled).map(|_| admin.as_str()))
            .collect();
        let count_by_feature = ORG_FEATURES
            .iter()
            .map(|f| {
                let n = enabled
                    .iter()
                    .filter(|a| {
                        state
                            .detector(a, &ctx.region)
                            .is_some_and(|d| d.features.get(*f).is_some_and(|x| x.status == "ENABLED"))
                    })
                    .count();
                types::OrganizationFeatureStatistics {
                    name: Some(f.to_string()),
                    enabled_accounts_count: Some(n as i32),
                    additional_configuration: None,
                }
            })
            .collect();
        Ok(types::GetOrganizationStatisticsResponse {
            organization_details: Some(types::OrganizationDetails {
                updated_at: Some(ctx.received_at),
                organization_statistics: Some(types::OrganizationStatistics {
                    total_accounts_count: Some(org.accounts.len() as i32),
                    member_accounts_count: Some(members.len() as i32),
                    active_accounts_count: Some(org.accounts.iter().filter(|a| a.status == "ACTIVE").count() as i32),
                    enabled_accounts_count: Some(enabled.len() as i32),
                    count_by_feature: Some(count_by_feature),
                }),
            }),
        })
    }

    /// Add organization accounts as members of the delegated administrator
    /// as its `AutoEnableOrganizationMembers` says: `ALL` takes every
    /// account, `NEW` those that joined since the setting changed.
    pub(crate) fn sync_organization(&self, ctx: &RequestContext) {
        let Some(org) = self.caller_org(ctx) else { return };
        let mut state = self.lock();
        let Some(admin) = Self::org_admin_of(&state, &org.id, &ctx.region).map(str::to_string) else { return };
        let Some(det) = state.detector(&admin, &ctx.region) else { return };
        let cfg = det.org_config.clone();
        let candidates: Vec<(String, String)> = org
            .accounts
            .iter()
            .filter(|a| a.id != admin && a.status == "ACTIVE")
            .filter(|a| match cfg.auto_enable_members.as_str() {
                "ALL" => true,
                "NEW" => cfg.since.is_some_and(|since| a.joined > since),
                _ => false,
            })
            .filter(|a| !det.members.contains_key(&a.id))
            .filter(|a| state.account(&a.id, &ctx.region).and_then(|x| x.administrator.as_ref()).is_none())
            .map(|a| (a.id.clone(), a.email.clone()))
            .collect();
        let features: Vec<(String, String, BTreeMap<String, String>)> =
            cfg.features.iter().map(|(n, (m, add))| (n.clone(), m.clone(), add.clone())).collect();
        for (id, email) in candidates {
            let det = state.detector_mut(&admin, &ctx.region).expect("checked above");
            det.members.insert(
                id.clone(),
                MemberRec {
                    account: id.clone(),
                    email,
                    status: "Created".into(),
                    invited_at: None,
                    updated_at: ctx.received_at,
                    invitation_id: None,
                    via_organization: true,
                },
            );
            Self::associate(&mut state, ctx, &admin, &id, true);
            Self::apply_org_features(&mut state, ctx, &id, &features);
        }
    }
}
