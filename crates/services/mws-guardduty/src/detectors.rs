//! Detectors, their features and data sources, malware scan settings,
//! usage, coverage and free trial days.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::common::*;
use crate::generated::types;
use crate::state::{Detector, Feature, State};
use crate::GuardDuty;

/// Features a new detector has, and whether each starts enabled.
const DEFAULT_FEATURES: &[(&str, bool)] = &[
    ("S3_DATA_EVENTS", true),
    ("EKS_AUDIT_LOGS", true),
    ("EBS_MALWARE_PROTECTION", true),
    ("RDS_LOGIN_EVENTS", true),
    ("LAMBDA_NETWORK_LOGS", true),
    ("EKS_RUNTIME_MONITORING", false),
    ("RUNTIME_MONITORING", false),
    ("AI_PROTECTION", false),
];

/// The additional configuration each feature carries.
pub fn additional_for(feature: &str) -> &'static [&'static str] {
    match feature {
        "EKS_RUNTIME_MONITORING" => &["EKS_ADDON_MANAGEMENT"],
        "RUNTIME_MONITORING" => &["EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT", "EC2_AGENT_MANAGEMENT"],
        _ => &[],
    }
}

/// Foundational sources every enabled detector analyses.
const FOUNDATIONAL: &[&str] = &["CLOUD_TRAIL", "DNS_LOGS", "FLOW_LOGS"];

pub fn status(enabled: bool) -> String {
    if enabled { "ENABLED" } else { "DISABLED" }.to_string()
}

fn default_features(now: DateTime<Utc>) -> BTreeMap<String, Feature> {
    DEFAULT_FEATURES
        .iter()
        .map(|(name, on)| {
            let additional =
                additional_for(name).iter().map(|a| (a.to_string(), (status(false), now))).collect::<BTreeMap<_, _>>();
            (name.to_string(), Feature { status: status(*on), updated_at: now, additional })
        })
        .collect()
}

/// A requested feature: name, status and `(name, status)` additional configuration.
pub type RequestedFeature = (Option<String>, Option<String>, Vec<(Option<String>, Option<String>)>);

/// Apply `Features` from a create or update request.
pub fn apply_features(
    features: &mut BTreeMap<String, Feature>,
    requested: &[RequestedFeature],
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    for (name, st, additional) in requested {
        let Some(name) = name else { continue };
        let f = features.entry(name.clone()).or_insert_with(|| Feature {
            status: status(false),
            updated_at: now,
            additional: BTreeMap::new(),
        });
        if let Some(st) = st {
            if f.status != *st {
                f.status = st.clone();
                f.updated_at = now;
            }
        }
        for (an, ast) in additional {
            let Some(an) = an else { continue };
            if !additional_for(name).contains(&an.as_str()) {
                return Err(invalid_input(format!(
                    "The request is rejected because the additional configuration {an} is not supported for feature {name}."
                )));
            }
            let slot = f.additional.entry(an.clone()).or_insert((status(false), now));
            if let Some(ast) = ast {
                if slot.0 != *ast {
                    *slot = (ast.clone(), now);
                }
            }
        }
    }
    Ok(())
}

pub fn detector_features(features: &[types::DetectorFeatureConfiguration]) -> FeatureRequest {
    features
        .iter()
        .map(|f| {
            let add = f.additional_configuration.iter().flatten().map(|a| (a.name.clone(), a.status.clone())).collect();
            (f.name.clone(), f.status.clone(), add)
        })
        .collect()
}

pub type FeatureRequest = Vec<(Option<String>, Option<String>, Vec<(Option<String>, Option<String>)>)>;

/// The features the legacy `DataSources` map to.
pub fn data_source_features(ds: &types::DataSourceConfigurations) -> FeatureRequest {
    let mut out = Vec::new();
    if let Some(s3) = &ds.s3_logs {
        out.push((Some("S3_DATA_EVENTS".into()), Some(status(s3.enable)), Vec::new()));
    }
    if let Some(k) = &ds.kubernetes {
        out.push((Some("EKS_AUDIT_LOGS".into()), Some(status(k.audit_logs.enable)), Vec::new()));
    }
    if let Some(ebs) = ds.malware_protection.as_ref().and_then(|m| m.scan_ec2_instance_with_findings.as_ref()) {
        if let Some(on) = ebs.ebs_volumes {
            out.push((Some("EBS_MALWARE_PROTECTION".into()), Some(status(on)), Vec::new()));
        }
    }
    out
}

fn feature_on(features: &BTreeMap<String, Feature>, name: &str) -> bool {
    features.get(name).is_some_and(|f| f.status == "ENABLED")
}

/// `DataSources` as `GetDetector` reports them.
pub fn data_sources_result(
    ctx: &RequestContext,
    account: &str,
    det: &Detector,
) -> types::DataSourceConfigurationsResult {
    let on = |name: &str| status(det.enabled && feature_on(&det.features, name));
    let all = status(det.enabled);
    types::DataSourceConfigurationsResult {
        cloud_trail: types::CloudTrailConfigurationResult { status: all.clone() },
        dns_logs: types::DNSLogsConfigurationResult { status: all.clone() },
        flow_logs: types::FlowLogsConfigurationResult { status: all },
        s3_logs: types::S3LogsConfigurationResult { status: on("S3_DATA_EVENTS") },
        kubernetes: Some(types::KubernetesConfigurationResult {
            audit_logs: types::KubernetesAuditLogsConfigurationResult { status: on("EKS_AUDIT_LOGS") },
        }),
        malware_protection: Some(types::MalwareProtectionConfigurationResult {
            scan_ec2_instance_with_findings: Some(types::ScanEc2InstanceWithFindingsResult {
                ebs_volumes: Some(types::EbsVolumesResult { status: Some(on("EBS_MALWARE_PROTECTION")), reason: None }),
            }),
            service_role: Some(format!(
                "arn:{}:iam::{account}:role/aws-service-role/malware-protection.guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDutyMalwareProtection",
                ctx.partition
            )),
        }),
    }
}

pub fn features_result(det: &Detector) -> Vec<types::DetectorFeatureConfigurationResult> {
    let mut out: Vec<types::DetectorFeatureConfigurationResult> = FOUNDATIONAL
        .iter()
        .map(|n| types::DetectorFeatureConfigurationResult {
            name: Some(n.to_string()),
            status: Some(status(det.enabled)),
            updated_at: Some(det.updated_at),
            ..Default::default()
        })
        .collect();
    for (name, f) in &det.features {
        out.push(types::DetectorFeatureConfigurationResult {
            name: Some(name.clone()),
            status: Some(f.status.clone()),
            updated_at: Some(f.updated_at),
            additional_configuration: (!f.additional.is_empty()).then(|| {
                f.additional
                    .iter()
                    .map(|(n, (s, at))| types::DetectorAdditionalConfigurationResult {
                        name: Some(n.clone()),
                        status: Some(s.clone()),
                        updated_at: Some(*at),
                        managed_by: None,
                    })
                    .collect()
            }),
            managed_by: None,
        });
    }
    out
}

pub fn member_features_result(det: &Detector) -> Vec<types::MemberFeaturesConfigurationResult> {
    features_result(det)
        .into_iter()
        .map(|f| types::MemberFeaturesConfigurationResult {
            name: f.name,
            status: f.status,
            updated_at: f.updated_at,
            additional_configuration: f.additional_configuration.map(|a| {
                a.into_iter()
                    .map(|a| types::MemberAdditionalConfigurationResult {
                        name: a.name,
                        status: a.status,
                        updated_at: a.updated_at,
                        managed_by: a.managed_by,
                    })
                    .collect()
            }),
            managed_by: None,
        })
        .collect()
}

/// A new detector for `account`, as `CreateDetector` makes it.
pub fn new_detector(now: DateTime<Utc>) -> Detector {
    Detector {
        id: hex_id(32),
        created_at: now,
        updated_at: now,
        features: default_features(now),
        ..Detector::default()
    }
}

impl GuardDuty {
    /// The caller's detector, which must be `detector_id`.
    pub(crate) fn owned<'s>(
        state: &'s State,
        ctx: &RequestContext,
        detector_id: &str,
    ) -> Result<&'s Detector, ServiceError> {
        state
            .detector(&ctx.caller.account_id, &ctx.region)
            .filter(|d| d.id == detector_id)
            .ok_or_else(detector_not_owned)
    }

    pub(crate) fn owned_mut<'s>(
        state: &'s mut State,
        ctx: &RequestContext,
        detector_id: &str,
    ) -> Result<&'s mut Detector, ServiceError> {
        state
            .detector_mut(&ctx.caller.account_id, &ctx.region)
            .filter(|d| d.id == detector_id)
            .ok_or_else(detector_not_owned)
    }

    /// Authorize `action` on the caller's detector `detector_id` (with its
    /// tags), failing first when the detector is not the caller's.
    pub(crate) fn authorize_detector(
        &self,
        ctx: &RequestContext,
        action: &str,
        detector_id: &str,
    ) -> Result<(), ServiceError> {
        let tags = {
            let state = self.lock();
            Self::owned(&state, ctx, detector_id)?.tags.clone()
        };
        let arn = detector_arn(ctx, &ctx.caller.account_id, detector_id);
        self.authorize(ctx, action, &arn, resource_tag_context(&tags))
    }

    pub(crate) fn create_detector(
        &self,
        ctx: &RequestContext,
        input: types::CreateDetectorRequest,
    ) -> Result<types::CreateDetectorResponse, ServiceError> {
        if let Some(tags) = &input.tags {
            validate_tags(tags)?;
        }
        self.authorize(ctx, "CreateDetector", "*", request_tag_context(input.tags.as_ref()))?;
        if input.tags.as_ref().is_some_and(|t| !t.is_empty()) {
            self.authorize(ctx, "TagResource", "*", request_tag_context(input.tags.as_ref()))?;
        }
        if input.data_sources.is_some() && input.features.is_some() {
            return Err(invalid_input(
                "The request is rejected because both data source and feature configurations are specified. Use only features.",
            ));
        }
        let account = ctx.caller.account_id.clone();
        let mut state = self.lock();
        let acct = state.account_mut(&account, &ctx.region);
        if let Some(d) = &acct.detector {
            if let Some(token) = input.client_token.as_deref().filter(|t| !t.is_empty()) {
                if acct.client_tokens.get(&format!("detector/{token}")) == Some(&d.id) {
                    return Ok(types::CreateDetectorResponse { detector_id: Some(d.id.clone()), ..Default::default() });
                }
            }
            return Err(invalid_input(
                "The request is rejected because a detector already exists for the current account.",
            ));
        }
        let now = ctx.received_at;
        let mut det = new_detector(now);
        det.enabled = input.enable;
        if let Some(f) = input.finding_publishing_frequency {
            det.frequency = f;
        }
        if let Some(ds) = &input.data_sources {
            apply_features(&mut det.features, &data_source_features(ds), now)?;
        }
        if let Some(f) = &input.features {
            apply_features(&mut det.features, &detector_features(f), now)?;
        }
        det.tags = input.tags.unwrap_or_default();
        let id = det.id.clone();
        if let Some(token) = input.client_token.filter(|t| !t.is_empty()) {
            acct.client_tokens.insert(format!("detector/{token}"), id.clone());
        }
        acct.detector = Some(det);
        Ok(types::CreateDetectorResponse { detector_id: Some(id), unprocessed_data_sources: None })
    }

    pub(crate) fn get_detector(
        &self,
        ctx: &RequestContext,
        input: types::GetDetectorRequest,
    ) -> Result<types::GetDetectorResponse, ServiceError> {
        self.authorize_detector(ctx, "GetDetector", &input.detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        Ok(types::GetDetectorResponse {
            created_at: Some(iso(det.created_at)),
            finding_publishing_frequency: Some(det.frequency.clone()),
            service_role: service_role_arn(ctx, &ctx.caller.account_id),
            status: status(det.enabled),
            updated_at: Some(iso(det.updated_at)),
            data_sources: Some(data_sources_result(ctx, &ctx.caller.account_id, det)),
            tags: Some(det.tags.clone()),
            features: Some(features_result(det)),
        })
    }

    pub(crate) fn update_detector(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDetectorRequest,
    ) -> Result<types::UpdateDetectorResponse, ServiceError> {
        self.authorize_detector(ctx, "UpdateDetector", &input.detector_id)?;
        if input.data_sources.is_some() && input.features.is_some() {
            return Err(invalid_input(
                "The request is rejected because both data source and feature configurations are specified. Use only features.",
            ));
        }
        let now = ctx.received_at;
        let mut state = self.lock();
        let managed = Self::managed_by_admin(&state, ctx);
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        if managed && input.enable == Some(false) {
            return Err(invalid_input(
                "The request is rejected because a member account cannot disable GuardDuty. Contact your administrator account.",
            ));
        }
        if let Some(e) = input.enable {
            det.enabled = e;
        }
        if let Some(f) = input.finding_publishing_frequency {
            det.frequency = f;
        }
        if let Some(ds) = &input.data_sources {
            apply_features(&mut det.features, &data_source_features(ds), now)?;
        }
        if let Some(f) = &input.features {
            apply_features(&mut det.features, &detector_features(f), now)?;
        }
        det.updated_at = now;
        Ok(Default::default())
    }

    /// Whether the caller is an enabled member of an administrator.
    pub(crate) fn managed_by_admin(state: &State, ctx: &RequestContext) -> bool {
        let Some(link) = state.account(&ctx.caller.account_id, &ctx.region).and_then(|a| a.administrator.as_ref())
        else {
            return false;
        };
        state
            .detector(&link.account, &ctx.region)
            .and_then(|d| d.members.get(&ctx.caller.account_id))
            .is_some_and(|m| m.status == "Enabled")
    }

    pub(crate) fn delete_detector(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDetectorRequest,
    ) -> Result<types::DeleteDetectorResponse, ServiceError> {
        self.authorize_detector(ctx, "DeleteDetector", &input.detector_id)?;
        let account = ctx.caller.account_id.clone();
        let mut state = self.lock();
        Self::owned(&state, ctx, &input.detector_id)?;
        if Self::managed_by_admin(&state, ctx) {
            return Err(invalid_input(
                "The request is rejected because the current account cannot delete detector while it has an active administrator relationship.",
            ));
        }
        let det = state.detector(&account, &ctx.region).expect("checked above");
        if det.members.values().any(|m| m.status == "Enabled") {
            return Err(invalid_input(
                "The request is rejected because the current account has members associated with the detector. Disassociate all members before deleting the detector.",
            ));
        }
        let acct = state.account_mut(&account, &ctx.region);
        acct.detector = None;
        acct.client_tokens.retain(|k, _| !k.starts_with("detector/"));
        Ok(Default::default())
    }

    pub(crate) fn list_detectors(
        &self,
        ctx: &RequestContext,
        input: types::ListDetectorsRequest,
    ) -> Result<types::ListDetectorsResponse, ServiceError> {
        self.authorize(ctx, "ListDetectors", "*", ConditionContext::new())?;
        let state = self.lock();
        let ids: Vec<String> =
            state.detector(&ctx.caller.account_id, &ctx.region).map(|d| d.id.clone()).into_iter().collect();
        let (detector_ids, next_token) = paginate(ids, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListDetectorsResponse { detector_ids, next_token })
    }

    pub(crate) fn get_malware_scan_settings(
        &self,
        ctx: &RequestContext,
        input: types::GetMalwareScanSettingsRequest,
    ) -> Result<types::GetMalwareScanSettingsResponse, ServiceError> {
        self.authorize_detector(ctx, "GetMalwareScanSettings", &input.detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        Ok(types::GetMalwareScanSettingsResponse {
            scan_resource_criteria: det.scan_settings.scan_resource_criteria.clone(),
            ebs_snapshot_preservation: Some(
                det.scan_settings.ebs_snapshot_preservation.clone().unwrap_or_else(|| "NO_RETENTION".into()),
            ),
        })
    }

    pub(crate) fn update_malware_scan_settings(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMalwareScanSettingsRequest,
    ) -> Result<types::UpdateMalwareScanSettingsResponse, ServiceError> {
        self.authorize_detector(ctx, "UpdateMalwareScanSettings", &input.detector_id)?;
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        if input.scan_resource_criteria.is_some() {
            det.scan_settings.scan_resource_criteria = input.scan_resource_criteria;
        }
        if input.ebs_snapshot_preservation.is_some() {
            det.scan_settings.ebs_snapshot_preservation = input.ebs_snapshot_preservation;
        }
        Ok(Default::default())
    }

    /// Accounts whose usage the caller sees: itself and its members.
    fn visible_accounts(state: &State, ctx: &RequestContext) -> Vec<String> {
        let mut out = vec![ctx.caller.account_id.clone()];
        if let Some(d) = state.detector(&ctx.caller.account_id, &ctx.region) {
            out.extend(d.members.values().filter(|m| m.status == "Enabled").map(|m| m.account.clone()));
        }
        out
    }

    pub(crate) fn get_usage_statistics(
        &self,
        ctx: &RequestContext,
        input: types::GetUsageStatisticsRequest,
    ) -> Result<types::GetUsageStatisticsResponse, ServiceError> {
        self.authorize_detector(ctx, "GetUsageStatistics", &input.detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let unit = input.unit.clone().unwrap_or_else(|| "USD".into());
        let zero = || Some(types::Total { amount: Some("0".into()), unit: Some(unit.clone()) });
        let criteria = &input.usage_criteria;
        let accounts: Vec<String> = match &criteria.account_ids {
            Some(ids) => ids.clone(),
            None => Self::visible_accounts(&state, ctx),
        };
        let features: Vec<String> = match &criteria.features {
            Some(f) => f.clone(),
            None => {
                let mut f: Vec<String> = FOUNDATIONAL.iter().map(|s| s.to_string()).collect();
                f.extend(det.features.iter().filter(|(_, v)| v.status == "ENABLED").map(|(k, _)| k.clone()));
                f
            }
        };
        let mut stats = types::UsageStatistics::default();
        match input.usage_statistic_type.as_str() {
            "SUM_BY_ACCOUNT" => {
                stats.sum_by_account = Some(
                    accounts
                        .iter()
                        .map(|a| types::UsageAccountResult { account_id: Some(a.clone()), total: zero() })
                        .collect(),
                )
            }
            "SUM_BY_DATA_SOURCE" => {
                let sources = criteria.data_sources.clone().unwrap_or_else(|| {
                    ["FLOW_LOGS", "CLOUD_TRAIL", "DNS_LOGS", "S3_LOGS", "KUBERNETES_AUDIT_LOGS", "EC2_MALWARE_SCAN"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                });
                stats.sum_by_data_source = Some(
                    sources
                        .into_iter()
                        .map(|s| types::UsageDataSourceResult { data_source: Some(s), total: zero() })
                        .collect(),
                )
            }
            "SUM_BY_FEATURES" => {
                stats.sum_by_feature = Some(
                    features
                        .iter()
                        .map(|f| types::UsageFeatureResult { feature: Some(f.clone()), total: zero() })
                        .collect(),
                )
            }
            "TOP_ACCOUNTS_BY_FEATURE" => {
                stats.top_accounts_by_feature = Some(
                    features
                        .iter()
                        .map(|f| types::UsageTopAccountsResult {
                            feature: Some(f.clone()),
                            accounts: Some(
                                accounts
                                    .iter()
                                    .map(|a| types::UsageTopAccountResult {
                                        account_id: Some(a.clone()),
                                        total: zero(),
                                    })
                                    .collect(),
                            ),
                        })
                        .collect(),
                )
            }
            "SUM_BY_RESOURCE" => stats.sum_by_resource = Some(Vec::new()),
            _ => stats.top_resources = Some(Vec::new()),
        }
        Ok(types::GetUsageStatisticsResponse { usage_statistics: Some(stats), next_token: None })
    }

    pub(crate) fn get_remaining_free_trial_days(
        &self,
        ctx: &RequestContext,
        input: types::GetRemainingFreeTrialDaysRequest,
    ) -> Result<types::GetRemainingFreeTrialDaysResponse, ServiceError> {
        self.authorize_detector(ctx, "GetRemainingFreeTrialDays", &input.detector_id)?;
        let state = self.lock();
        let own = Self::owned(&state, ctx, &input.detector_id)?;
        let mut accounts = Vec::new();
        let mut unprocessed_accounts = Vec::new();
        for id in &input.account_ids {
            let det = if *id == ctx.caller.account_id {
                Some(own)
            } else if own.members.get(id).is_some_and(|m| m.status == "Enabled") {
                state.detector(id, &ctx.region)
            } else {
                None
            };
            let Some(det) = det else {
                unprocessed_accounts.push(unprocessed(id, "The request is rejected because the given account ID is not an associated member of account the current account."));
                continue;
            };
            let days = (30 - (ctx.received_at - det.created_at).num_days()).max(0) as i32;
            let trial = || Some(types::DataSourceFreeTrial { free_trial_days_remaining: Some(days) });
            let mut features: Vec<types::FreeTrialFeatureConfigurationResult> = FOUNDATIONAL
                .iter()
                .map(|n| types::FreeTrialFeatureConfigurationResult {
                    name: Some(n.to_string()),
                    free_trial_days_remaining: Some(days),
                })
                .collect();
            for name in det.features.keys() {
                let name = match name.as_str() {
                    "RUNTIME_MONITORING" => "EC2_RUNTIME_MONITORING",
                    n => n,
                };
                features.push(types::FreeTrialFeatureConfigurationResult {
                    name: Some(name.to_string()),
                    free_trial_days_remaining: Some(days),
                });
            }
            accounts.push(types::AccountFreeTrialInfo {
                account_id: Some(id.clone()),
                data_sources: Some(types::DataSourcesFreeTrial {
                    cloud_trail: trial(),
                    dns_logs: trial(),
                    flow_logs: trial(),
                    s3_logs: trial(),
                    kubernetes: Some(types::KubernetesDataSourceFreeTrial { audit_logs: trial() }),
                    malware_protection: Some(types::MalwareProtectionDataSourceFreeTrial {
                        scan_ec2_instance_with_findings: trial(),
                    }),
                }),
                features: Some(features),
            });
        }
        Ok(types::GetRemainingFreeTrialDaysResponse {
            accounts: Some(accounts),
            unprocessed_accounts: Some(unprocessed_accounts),
        })
    }

    pub(crate) fn list_coverage(
        &self,
        ctx: &RequestContext,
        input: types::ListCoverageRequest,
    ) -> Result<types::ListCoverageResponse, ServiceError> {
        self.authorize_detector(ctx, "ListCoverage", &input.detector_id)?;
        // MWS runs no GuardDuty security agents, so no resource is covered.
        let (resources, next_token) =
            paginate(Vec::<types::CoverageResource>::new(), input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListCoverageResponse { resources, next_token })
    }

    pub(crate) fn get_coverage_statistics(
        &self,
        ctx: &RequestContext,
        input: types::GetCoverageStatisticsRequest,
    ) -> Result<types::GetCoverageStatisticsResponse, ServiceError> {
        self.authorize_detector(ctx, "GetCoverageStatistics", &input.detector_id)?;
        let mut stats = types::CoverageStatistics::default();
        for t in &input.statistics_type {
            match t.as_str() {
                "COUNT_BY_RESOURCE_TYPE" => stats.count_by_resource_type = Some(BTreeMap::new()),
                _ => stats.count_by_coverage_status = Some(BTreeMap::new()),
            }
        }
        Ok(types::GetCoverageStatisticsResponse { coverage_statistics: Some(stats) })
    }
}
