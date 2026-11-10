//! Compliance and patch states. `PutComplianceItems` records custom
//! compliance; State Manager records `Association` compliance and
//! `AWS-RunPatchBaseline` records `Patch` compliance. A patch baseline run
//! really scans the managed node's package manager (installed packages,
//! available updates and security advisories), installs updates for the
//! `Install` operation, and keeps the node's patch state
//! (`DescribeInstancePatchStates`, `DescribeInstancePatches`).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::generated::{errors, types};
use crate::names::page;
use crate::Ssm;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ComplianceRecord {
    pub compliance_type: String,
    pub resource_type: String,
    pub resource_id: String,
    pub execution_summary: Option<types::ComplianceExecutionSummary>,
    pub items: Vec<types::ComplianceItem>,
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PatchRecord {
    pub state: Option<types::InstancePatchState>,
    pub patches: Vec<types::PatchComplianceData>,
}

const SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNSPECIFIED"];

fn severity_rank(s: &str) -> usize {
    SEVERITIES.iter().position(|x| *x == s).unwrap_or(SEVERITIES.len())
}

fn severity_summary<'a>(items: impl Iterator<Item = &'a str>) -> types::SeveritySummary {
    let mut s = types::SeveritySummary::default();
    for sev in items {
        match sev {
            "CRITICAL" => s.critical_count += 1,
            "HIGH" => s.high_count += 1,
            "MEDIUM" => s.medium_count += 1,
            "LOW" => s.low_count += 1,
            "INFORMATIONAL" => s.informational_count += 1,
            _ => s.unspecified_count += 1,
        }
    }
    s
}

fn string_filter(value: Option<&str>, f: &types::ComplianceStringFilter) -> bool {
    let values = f.values.clone().unwrap_or_default();
    let Some(v) = value else { return false };
    match f.r#type.as_deref().unwrap_or("EQUAL") {
        "NOT_EQUAL" => !values.iter().any(|x| x == v),
        "BEGIN_WITH" => values.iter().any(|x| v.starts_with(x.as_str())),
        "LESS_THAN" => values.iter().any(|x| v < x.as_str()),
        "GREATER_THAN" => values.iter().any(|x| v > x.as_str()),
        _ => values.iter().any(|x| x == v),
    }
}

fn resource_summary(r: &ComplianceRecord) -> types::ResourceComplianceSummaryItem {
    let non: Vec<&types::ComplianceItem> =
        r.items.iter().filter(|i| i.status.as_deref() == Some("NON_COMPLIANT")).collect();
    let ok: Vec<&types::ComplianceItem> = r.items.iter().filter(|i| i.status.as_deref() == Some("COMPLIANT")).collect();
    let worst = |items: &[&types::ComplianceItem]| {
        items
            .iter()
            .filter_map(|i| i.severity.clone())
            .min_by_key(|s| severity_rank(s))
            .unwrap_or_else(|| "UNSPECIFIED".into())
    };
    let status = if non.is_empty() { "COMPLIANT" } else { "NON_COMPLIANT" };
    types::ResourceComplianceSummaryItem {
        compliance_type: Some(r.compliance_type.clone()),
        resource_type: Some(r.resource_type.clone()),
        resource_id: Some(r.resource_id.clone()),
        status: Some(status.into()),
        overall_severity: Some(if non.is_empty() { worst(&ok) } else { worst(&non) }),
        execution_summary: r.execution_summary.clone(),
        compliant_summary: Some(types::CompliantSummary {
            compliant_count: ok.len() as i32,
            severity_summary: Some(severity_summary(ok.iter().filter_map(|i| i.severity.as_deref()))),
        }),
        non_compliant_summary: Some(types::NonCompliantSummary {
            non_compliant_count: non.len() as i32,
            severity_summary: Some(severity_summary(non.iter().filter_map(|i| i.severity.as_deref()))),
        }),
    }
}

impl Ssm {
    /// Record compliance for a resource (no authorization).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_compliance(
        &self,
        account: &str,
        region: &str,
        resource_type: &str,
        resource_id: &str,
        compliance_type: &str,
        summary: types::ComplianceExecutionSummary,
        entries: Vec<types::ComplianceItemEntry>,
        partial: bool,
    ) {
        let key = format!("{compliance_type}|{resource_type}|{resource_id}");
        let mut st = self.lock();
        let rec = st.region(account, region).compliance.entry(key).or_insert_with(|| ComplianceRecord {
            compliance_type: compliance_type.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            ..Default::default()
        });
        let items: Vec<types::ComplianceItem> = entries
            .into_iter()
            .map(|e| types::ComplianceItem {
                compliance_type: Some(compliance_type.into()),
                resource_type: Some(resource_type.into()),
                resource_id: Some(resource_id.into()),
                id: e.id,
                title: e.title,
                status: Some(e.status),
                severity: Some(e.severity),
                execution_summary: Some(summary.clone()),
                details: e.details,
            })
            .collect();
        if partial {
            for item in items {
                rec.items.retain(|i| i.id != item.id);
                rec.items.push(item);
            }
        } else {
            rec.items = items;
        }
        rec.execution_summary = Some(summary);
        drop(st);
        self.data_changed(account, region);
    }

    pub(crate) fn put_compliance_items(
        &self,
        ctx: &RequestContext,
        input: types::PutComplianceItemsRequest,
    ) -> Result<types::PutComplianceItemsResult, ServiceError> {
        let arn = format!(
            "arn:{}:ec2:{}:{}:instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.resource_id
        );
        ctx.authorize("ssm:PutComplianceItems", &arn, ConditionContext::new())?;
        if input.resource_type != "ManagedInstance" {
            return Err(errors::invalid_resource_type("The resource type isn't valid."));
        }
        if !self.nodes_of(&ctx.caller.account_id, &ctx.region).iter().any(|n| n.instance_id == input.resource_id) {
            return Err(errors::invalid_resource_id("The resource ID isn't valid."));
        }
        let custom = input.compliance_type.starts_with("Custom:");
        if !custom && !matches!(input.compliance_type.as_str(), "Association" | "Patch") {
            return Err(errors::validation(format!(
                "1 validation error detected: Value '{}' at 'complianceType' failed to satisfy constraint: Member must satisfy regular expression pattern: [A-Za-z0-9_\\-]\\w+|Custom:[a-zA-Z0-9_\\-]\\w+",
                input.compliance_type
            )));
        }
        for i in &input.items {
            if !SEVERITIES.contains(&i.severity.as_str()) {
                return Err(errors::validation(format!("Invalid Severity: {}", i.severity)));
            }
            if i.status != "COMPLIANT" && i.status != "NON_COMPLIANT" {
                return Err(errors::validation(format!("Invalid Status: {}", i.status)));
            }
        }
        {
            let st = self.lock();
            let types_: std::collections::BTreeSet<&String> = st
                .region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| {
                    r.compliance
                        .values()
                        .filter(|c| c.compliance_type.starts_with("Custom:"))
                        .map(|c| &c.compliance_type)
                        .collect()
                })
                .unwrap_or_default();
            if custom && !types_.contains(&input.compliance_type) && types_.len() >= 10 {
                return Err(errors::compliance_type_count_limit_exceeded(
                    "You have exceeded the limit for custom compliance types.",
                ));
            }
            let key = format!("{}|{}|{}", input.compliance_type, input.resource_type, input.resource_id);
            let same = st
                .region_ref(&ctx.caller.account_id, &ctx.region)
                .and_then(|r| r.compliance.get(&key))
                .and_then(|c| c.content_hash.clone());
            if same.is_some() && same == input.item_content_hash {
                return Ok(types::PutComplianceItemsResult {});
            }
        }
        let partial = input.upload_type.as_deref() == Some("PARTIAL");
        self.record_compliance(
            &ctx.caller.account_id,
            &ctx.region,
            &input.resource_type,
            &input.resource_id,
            &input.compliance_type,
            input.execution_summary,
            input.items,
            partial,
        );
        if let Some(h) = input.item_content_hash {
            let key = format!("{}|{}|{}", input.compliance_type, input.resource_type, input.resource_id);
            if let Some(c) = self.lock().region(&ctx.caller.account_id, &ctx.region).compliance.get_mut(&key) {
                c.content_hash = Some(h);
            }
        }
        Ok(types::PutComplianceItemsResult {})
    }

    fn compliance_records(&self, ctx: &RequestContext) -> Vec<ComplianceRecord> {
        let st = self.lock();
        st.region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| r.compliance.values().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn list_compliance_items(
        &self,
        ctx: &RequestContext,
        input: types::ListComplianceItemsRequest,
    ) -> Result<types::ListComplianceItemsResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:ListComplianceItems", &list_arn, ConditionContext::new())?;
        let ids = input.resource_ids.unwrap_or_default();
        let kinds = input.resource_types.unwrap_or_default();
        let filters = input.filters.unwrap_or_default();
        let items: Vec<types::ComplianceItem> = self
            .compliance_records(ctx)
            .into_iter()
            .filter(|r| ids.is_empty() || ids.contains(&r.resource_id))
            .filter(|r| kinds.is_empty() || kinds.contains(&r.resource_type))
            .flat_map(|r| r.items)
            .filter(|i| {
                filters.iter().all(|f| {
                    let v = match f.key.as_deref().unwrap_or_default() {
                        "ComplianceType" => i.compliance_type.as_deref(),
                        "Status" => i.status.as_deref(),
                        "Severity" => i.severity.as_deref(),
                        "Id" => i.id.as_deref(),
                        "Title" => i.title.as_deref(),
                        "ExecutionId" => i.execution_summary.as_ref().and_then(|e| e.execution_id.as_deref()),
                        "ExecutionType" => i.execution_summary.as_ref().and_then(|e| e.execution_type.as_deref()),
                        key => i.details.as_ref().and_then(|d| d.get(key)).map(String::as_str),
                    };
                    string_filter(v, f)
                })
            })
            .collect();
        let limit = input.max_results.unwrap_or(10).clamp(1, 50) as usize;
        let (page_items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::ListComplianceItemsResult { compliance_items: Some(page_items), next_token: next })
    }

    fn filtered_resources(
        &self,
        ctx: &RequestContext,
        filters: &[types::ComplianceStringFilter],
    ) -> Vec<types::ResourceComplianceSummaryItem> {
        self.compliance_records(ctx)
            .iter()
            .map(resource_summary)
            .filter(|s| {
                filters.iter().all(|f| {
                    let v = match f.key.as_deref().unwrap_or_default() {
                        "ComplianceType" => s.compliance_type.as_deref(),
                        "Status" => s.status.as_deref(),
                        "OverallSeverity" => s.overall_severity.as_deref(),
                        "ResourceId" => s.resource_id.as_deref(),
                        "ResourceType" => s.resource_type.as_deref(),
                        "ExecutionId" => s.execution_summary.as_ref().and_then(|e| e.execution_id.as_deref()),
                        _ => None,
                    };
                    string_filter(v, f)
                })
            })
            .collect()
    }

    pub(crate) fn list_resource_compliance_summaries(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceComplianceSummariesRequest,
    ) -> Result<types::ListResourceComplianceSummariesResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:ListResourceComplianceSummaries", &list_arn, ConditionContext::new())?;
        let all = self.filtered_resources(ctx, &input.filters.unwrap_or_default());
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::ListResourceComplianceSummariesResult {
            resource_compliance_summary_items: Some(items),
            next_token: next,
        })
    }

    pub(crate) fn list_compliance_summaries(
        &self,
        ctx: &RequestContext,
        input: types::ListComplianceSummariesRequest,
    ) -> Result<types::ListComplianceSummariesResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:ListComplianceSummaries", &list_arn, ConditionContext::new())?;
        let resources = self.filtered_resources(ctx, &input.filters.unwrap_or_default());
        let mut by_type: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
        for r in resources {
            let e = by_type.entry(r.compliance_type.clone().unwrap_or_default()).or_default();
            let sev = r.overall_severity.clone().unwrap_or_else(|| "UNSPECIFIED".into());
            if r.status.as_deref() == Some("COMPLIANT") {
                e.0.push(sev);
            } else {
                e.1.push(sev);
            }
        }
        let all: Vec<types::ComplianceSummaryItem> = by_type
            .into_iter()
            .map(|(t, (ok, non))| types::ComplianceSummaryItem {
                compliance_type: Some(t),
                compliant_summary: Some(types::CompliantSummary {
                    compliant_count: ok.len() as i32,
                    severity_summary: Some(severity_summary(ok.iter().map(String::as_str))),
                }),
                non_compliant_summary: Some(types::NonCompliantSummary {
                    non_compliant_count: non.len() as i32,
                    severity_summary: Some(severity_summary(non.iter().map(String::as_str))),
                }),
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::ListComplianceSummariesResult { compliance_summary_items: Some(items), next_token: next })
    }

    // ---- Patch states ----

    pub(crate) fn describe_instance_patch_states(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstancePatchStatesRequest,
    ) -> Result<types::DescribeInstancePatchStatesResult, ServiceError> {
        for id in &input.instance_ids {
            let arn = format!("arn:{}:ec2:{}:{}:instance/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
            ctx.authorize("ssm:DescribeInstancePatchStates", &arn, ConditionContext::new())?;
        }
        let st = self.lock();
        let all: Vec<types::InstancePatchState> = input
            .instance_ids
            .iter()
            .filter_map(|id| st.region_ref(&ctx.caller.account_id, &ctx.region)?.patch_states.get(id)?.state.clone())
            .collect();
        drop(st);
        let limit = input.max_results.unwrap_or(10).clamp(10, 100) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeInstancePatchStatesResult { instance_patch_states: Some(items), next_token: next })
    }

    pub(crate) fn describe_instance_patch_states_for_patch_group(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstancePatchStatesForPatchGroupRequest,
    ) -> Result<types::DescribeInstancePatchStatesForPatchGroupResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:DescribeInstancePatchStatesForPatchGroup", &list_arn, ConditionContext::new())?;
        let filters = input.filters.unwrap_or_default();
        let st = self.lock();
        let all: Vec<types::InstancePatchState> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| r.patch_states.values().filter_map(|p| p.state.clone()).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.patch_group == input.patch_group)
            .filter(|s| {
                filters.iter().all(|f| {
                    let n = match f.key.as_str() {
                        "InstalledCount" => s.installed_count,
                        "InstalledOtherCount" => s.installed_other_count,
                        "InstalledPendingRebootCount" => s.installed_pending_reboot_count.unwrap_or(0),
                        "InstalledRejectedCount" => s.installed_rejected_count.unwrap_or(0),
                        "MissingCount" => s.missing_count,
                        "FailedCount" => s.failed_count,
                        "UnreportedNotApplicableCount" => s.unreported_not_applicable_count.unwrap_or(0),
                        "NotApplicableCount" => s.not_applicable_count,
                        _ => return false,
                    };
                    let v: i32 = f.values.first().and_then(|v| v.parse().ok()).unwrap_or(0);
                    match f.r#type.as_str() {
                        "LessThan" => n < v,
                        "GreaterThan" => n > v,
                        "NotEqual" => n != v,
                        _ => n == v,
                    }
                })
            })
            .collect();
        drop(st);
        let limit = input.max_results.unwrap_or(50).clamp(10, 100) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeInstancePatchStatesForPatchGroupResult {
            instance_patch_states: Some(items),
            next_token: next,
        })
    }

    pub(crate) fn describe_instance_patches(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstancePatchesRequest,
    ) -> Result<types::DescribeInstancePatchesResult, ServiceError> {
        let arn = format!(
            "arn:{}:ec2:{}:{}:instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.instance_id
        );
        ctx.authorize("ssm:DescribeInstancePatches", &arn, ConditionContext::new())?;
        if !self.nodes_of(&ctx.caller.account_id, &ctx.region).iter().any(|n| n.instance_id == input.instance_id) {
            return Err(errors::invalid_instance_id("Invalid instance ID."));
        }
        let filters = input.filters.unwrap_or_default();
        let st = self.lock();
        let all: Vec<types::PatchComplianceData> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.patch_states.get(&input.instance_id))
            .map(|p| p.patches.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|p| {
                filters.iter().all(|f| {
                    let values = f.values.clone().unwrap_or_default();
                    let v = match f.key.as_deref().unwrap_or_default() {
                        "Classification" => &p.classification,
                        "KBId" => &p.kb_id,
                        "Severity" => &p.severity,
                        "State" => &p.state,
                        _ => return false,
                    };
                    values.iter().any(|x| x == v)
                })
            })
            .collect();
        drop(st);
        let limit = input.max_results.unwrap_or(50).clamp(10, 100) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeInstancePatchesResult { patches: Some(items), next_token: next })
    }

    pub(crate) fn get_deployable_patch_snapshot_for_instance(
        &self,
        ctx: &RequestContext,
        input: types::GetDeployablePatchSnapshotForInstanceRequest,
    ) -> Result<types::GetDeployablePatchSnapshotForInstanceResult, ServiceError> {
        let arn = format!(
            "arn:{}:ec2:{}:{}:instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.instance_id
        );
        ctx.authorize("ssm:GetDeployablePatchSnapshotForInstance", &arn, ConditionContext::new())?;
        let node = self
            .nodes_of(&ctx.caller.account_id, &ctx.region)
            .into_iter()
            .find(|n| n.instance_id == input.instance_id)
            .ok_or_else(|| errors::invalid_instance_id("Invalid instance ID."))?;
        let product = format!("{}{}", node.platform_name.replace(' ', ""), node.platform_version);
        Ok(types::GetDeployablePatchSnapshotForInstanceResult {
            instance_id: Some(input.instance_id.clone()),
            snapshot_id: Some(input.snapshot_id.clone()),
            snapshot_download_url: Some(format!(
                "https://patch-baseline-snapshot-{}.s3.{}.amazonaws.com/{}/{}",
                ctx.region, ctx.region, input.instance_id, input.snapshot_id
            )),
            product: Some(product),
        })
    }

    pub(crate) fn describe_patch_properties(
        &self,
        ctx: &RequestContext,
        input: types::DescribePatchPropertiesRequest,
    ) -> Result<types::DescribePatchPropertiesResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:DescribePatchProperties", &list_arn, ConditionContext::new())?;
        let os = input.operating_system.as_str();
        let values: Vec<&str> = match (os, input.property.as_str()) {
            ("WINDOWS", "PRODUCT") => {
                vec!["WindowsServer2016", "WindowsServer2019", "WindowsServer2022", "WindowsServer2025"]
            }
            ("WINDOWS", "PRODUCT_FAMILY") => vec!["Windows", "Office"],
            ("WINDOWS", "CLASSIFICATION") => vec![
                "CriticalUpdates",
                "DefinitionUpdates",
                "Drivers",
                "FeaturePacks",
                "SecurityUpdates",
                "ServicePacks",
                "Tools",
                "UpdateRollups",
                "Updates",
                "Upgrades",
            ],
            ("WINDOWS", "MSRC_SEVERITY") | ("WINDOWS", "SEVERITY") => {
                vec!["Critical", "Important", "Moderate", "Low", "Unspecified"]
            }
            ("AMAZON_LINUX_2023", "PRODUCT") => vec!["AmazonLinux2023"],
            ("AMAZON_LINUX_2", "PRODUCT") => vec!["AmazonLinux2", "AmazonLinux2.0"],
            ("UBUNTU", "PRODUCT") => vec!["Ubuntu20.04", "Ubuntu22.04", "Ubuntu24.04"],
            ("DEBIAN", "PRODUCT") => vec!["Debian11", "Debian12"],
            ("UBUNTU" | "DEBIAN", "PRIORITY") => vec!["Required", "Important", "Standard", "Optional", "Extra"],
            ("UBUNTU" | "DEBIAN", "SECTION") => vec!["admin", "devel", "libs", "net", "python", "utils", "web"],
            (_, "CLASSIFICATION") => vec!["Security", "Bugfix", "Enhancement", "Recommended", "Newpackage"],
            (_, "SEVERITY") => vec!["Critical", "Important", "Medium", "Low", "None"],
            (_, "PRODUCT") => vec!["*"],
            _ => return Err(errors::validation(format!("The property {} isn't supported for {os}.", input.property))),
        };
        let key = match input.property.as_str() {
            "PRODUCT" | "PRODUCT_FAMILY" => "Name",
            _ => "Name",
        };
        let all: Vec<BTreeMap<String, String>> =
            values.into_iter().map(|v| BTreeMap::from([(key.to_string(), v.to_string())])).collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribePatchPropertiesResult { properties: Some(items), next_token: next })
    }
}

/// Prints the node's OS, installed packages (`I`), available updates
/// (`M`) and security advisories (`U`) as tab-separated lines.
pub(crate) const PATCH_SCAN_SCRIPT: &str = r#"
. /etc/os-release 2>/dev/null
printf 'OS\t%s\t%s\n' "$ID" "$VERSION_ID"
if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PM=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)
  rpm -qa --queryformat 'I\t%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n' 2>/dev/null
  timeout 60 $PM -q check-update 2>/dev/null | awk 'NF==3 && $1 ~ /\./ {print "M\t"$1"\t"$2}'
  timeout 60 $PM -q updateinfo list --security 2>/dev/null | awk 'NF>=3 {print "U\t"$1"\t"$2"\t"$3}'
elif command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='I\t${Package}\t${Version}\t${Architecture}\t0\n' 2>/dev/null
  apt list --upgradable 2>/dev/null | awk -F'[/ ]' 'NR>1 && NF>2 {print "M\t"$1"\t"$3"\t"$2}'
fi
"#;

/// Installs available updates (security updates for dnf/yum).
pub(crate) const PATCH_INSTALL_SCRIPT: &str = r#"
if command -v dnf >/dev/null 2>&1; then timeout 900 dnf -y -q upgrade --security
elif command -v yum >/dev/null 2>&1; then timeout 900 yum -y -q update --security
elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive timeout 900 apt-get -y -q upgrade
fi
"#;

/// What a patch scan found.
#[derive(Debug, Default)]
pub(crate) struct Scan {
    pub os_id: String,
    pub os_version: String,
    /// Name, version-release, arch, install time.
    pub installed: Vec<(String, String, String, Option<DateTime<Utc>>)>,
    /// Name (without arch), arch, new version.
    pub missing: Vec<(String, String, String)>,
    /// Package (name-version.arch or name) -> (advisory, severity).
    pub advisories: BTreeMap<String, (String, String)>,
}

pub(crate) fn parse_scan(out: &str) -> Scan {
    let mut s = Scan::default();
    for line in out.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["OS", id, version, ..] => {
                s.os_id = id.to_string();
                s.os_version = version.to_string();
            }
            ["I", name, version, arch, time, ..] => {
                let t = time.parse::<i64>().ok().filter(|t| *t > 0).and_then(|t| DateTime::from_timestamp(t, 0));
                s.installed.push((name.to_string(), version.to_string(), arch.to_string(), t));
            }
            ["M", pkg, version, ..] => {
                let (name, arch) = match pkg.rsplit_once('.') {
                    Some((n, a)) if f.len() == 3 => (n.to_string(), a.to_string()),
                    _ => (pkg.to_string(), f.get(3).map(|a| a.to_string()).unwrap_or_default()),
                };
                s.missing.push((name, arch, version.to_string()));
            }
            ["U", advisory, severity, pkg] => {
                let severity = severity.split('/').next().unwrap_or("").to_string();
                s.advisories.insert(pkg.to_string(), (advisory.to_string(), severity));
            }
            _ => {}
        }
    }
    s
}

/// The patch baseline operating system of a node.
pub(crate) fn operating_system(os_id: &str, os_version: &str, platform_name: &str) -> &'static str {
    let id = if os_id.is_empty() { platform_name.to_ascii_lowercase() } else { os_id.to_ascii_lowercase() };
    match id.as_str() {
        i if i.starts_with("amzn") || i.contains("amazon") => {
            if os_version.starts_with("2023") || platform_name.contains("2023") {
                "AMAZON_LINUX_2023"
            } else if os_version.starts_with('2') {
                "AMAZON_LINUX_2"
            } else {
                "AMAZON_LINUX_2023"
            }
        }
        i if i.contains("ubuntu") => "UBUNTU",
        i if i.contains("debian") => "DEBIAN",
        i if i.contains("rhel") || i.contains("red hat") => "REDHAT_ENTERPRISE_LINUX",
        i if i.contains("centos") => "CENTOS",
        i if i == "ol" || i.contains("oracle") => "ORACLE_LINUX",
        i if i.contains("sles") || i.contains("suse") => "SUSE",
        i if i.contains("rocky") => "ROCKY_LINUX",
        i if i.contains("alma") => "ALMA_LINUX",
        i if i.contains("windows") => "WINDOWS",
        i if i.contains("mac") => "MACOS",
        _ => "AMAZON_LINUX_2023",
    }
}

fn compliance_severity(patch_severity: &str) -> &'static str {
    match patch_severity {
        "Critical" => "CRITICAL",
        "Important" | "High" => "HIGH",
        "Medium" | "Moderate" => "MEDIUM",
        "Low" => "LOW",
        _ => "UNSPECIFIED",
    }
}

impl Ssm {
    /// Record a patch baseline run on a node: its patch state, patches,
    /// `Patch` compliance and `AWS:PatchSummary` inventory.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_patch_run(
        &self,
        partition: &str,
        account: &str,
        region: &str,
        instance: &str,
        operation: &str,
        reboot_option: &str,
        scan: &Scan,
        failed: bool,
        started: DateTime<Utc>,
        ended: DateTime<Utc>,
        execution_id: &str,
    ) {
        let node = self.nodes_of(account, region).into_iter().find(|n| n.instance_id == instance);
        let platform_name = node.as_ref().map(|n| n.platform_name.clone()).unwrap_or_default();
        let os = operating_system(&scan.os_id, &scan.os_version, &platform_name);
        let patch_group = node
            .as_ref()
            .and_then(|n| n.tags.get("Patch Group").or_else(|| n.tags.get("PatchGroup")).cloned())
            .unwrap_or_default();
        let (baseline_id, rejected, approved) = {
            let st = self.lock();
            let p = st.region_ref(account, region).map(|r| r.patch.clone()).unwrap_or_default();
            let id = p
                .groups
                .get(&patch_group)
                .and_then(|m| m.get(os).cloned())
                .or_else(|| p.defaults.get(os).cloned())
                .unwrap_or_else(|| crate::patch::predefined_arn(partition, region, os));
            let bare = id.rsplit('/').next().unwrap_or(&id).to_string();
            let custom = p.baselines.get(&bare).map(|b| b.baseline.clone());
            let rejected = custom.as_ref().and_then(|b| b.rejected_patches.clone()).unwrap_or_default();
            let approved = custom.as_ref().and_then(|b| b.approved_patches.clone()).unwrap_or_default();
            (bare, rejected, approved)
        };
        let advisory_of = |name: &str, arch: &str, version: &str| {
            scan.advisories
                .get(&format!("{name}-{version}.{arch}"))
                .or_else(|| scan.advisories.iter().find(|(k, _)| k.starts_with(&format!("{name}-"))).map(|(_, v)| v))
                .cloned()
        };
        let mut patches = Vec::new();
        let mut missing_count = 0;
        let mut rejected_count = 0;
        let mut security_missing = 0;
        let mut critical_missing = 0;
        let mut other_missing = 0;
        for (name, arch, version) in &scan.missing {
            let advisory = advisory_of(name, arch, version);
            let explicitly = approved.iter().any(|a| a == name);
            if advisory.is_none() && !explicitly && !matches!(os, "UBUNTU" | "DEBIAN") {
                continue;
            }
            if rejected.iter().any(|r| r == name) {
                rejected_count += 1;
                continue;
            }
            let (classification, severity) = match &advisory {
                Some((_, sev)) => ("Security".to_string(), sev.clone()),
                None => ("Unspecified".to_string(), "Unspecified".to_string()),
            };
            missing_count += 1;
            match compliance_severity(&severity) {
                "CRITICAL" => critical_missing += 1,
                _ if classification == "Security" => security_missing += 1,
                _ => other_missing += 1,
            }
            patches.push(types::PatchComplianceData {
                title: format!("{name}.{arch}:{version}"),
                kb_id: advisory.as_ref().map(|a| a.0.clone()).unwrap_or_else(|| name.clone()),
                classification,
                severity,
                state: if failed { "FAILED".into() } else { "MISSING".into() },
                installed_time: DateTime::<Utc>::UNIX_EPOCH,
                cve_ids: None,
            });
        }
        let mut installed_count = 0;
        for (name, version, arch, at) in &scan.installed {
            installed_count += 1;
            patches.push(types::PatchComplianceData {
                title: format!("{name}.{arch}:{version}"),
                kb_id: name.clone(),
                classification: String::new(),
                severity: String::new(),
                state: "INSTALLED".into(),
                installed_time: at.unwrap_or(ended),
                cve_ids: None,
            });
        }
        let failed_count = if failed { missing_count } else { 0 };
        let state = types::InstancePatchState {
            instance_id: instance.into(),
            patch_group: patch_group.clone(),
            baseline_id: baseline_id.clone(),
            snapshot_id: Some(uuid::Uuid::new_v4().to_string()),
            install_override_list: None,
            owner_information: None,
            installed_count,
            installed_other_count: 0,
            installed_pending_reboot_count: Some(0),
            installed_rejected_count: Some(rejected_count),
            missing_count: if failed { 0 } else { missing_count },
            failed_count,
            unreported_not_applicable_count: Some(0),
            not_applicable_count: 0,
            available_security_update_count: Some(security_missing + critical_missing),
            operation_start_time: started,
            operation_end_time: ended,
            operation: operation.into(),
            last_no_reboot_install_operation_time: (operation == "Install" && reboot_option == "NoReboot")
                .then_some(ended),
            reboot_option: Some(reboot_option.into()),
            critical_non_compliant_count: Some(critical_missing),
            security_non_compliant_count: Some(security_missing + critical_missing),
            other_non_compliant_count: Some(other_missing),
        };
        let entries: Vec<types::ComplianceItemEntry> = patches
            .iter()
            .filter(|p| p.state != "INSTALLED" || !p.classification.is_empty())
            .map(|p| types::ComplianceItemEntry {
                id: Some(p.kb_id.clone()),
                title: Some(p.title.clone()),
                severity: compliance_severity(&p.severity).into(),
                status: if p.state == "INSTALLED" { "COMPLIANT" } else { "NON_COMPLIANT" }.into(),
                details: Some(BTreeMap::from([
                    ("Classification".to_string(), p.classification.clone()),
                    ("PatchSeverity".to_string(), p.severity.clone()),
                    ("PatchState".to_string(), p.state.clone()),
                    ("PatchBaselineId".to_string(), baseline_id.clone()),
                    ("PatchGroup".to_string(), patch_group.clone()),
                ])),
            })
            .collect();
        let summary = BTreeMap::from([
            ("PatchGroup".to_string(), patch_group.clone()),
            ("BaselineId".to_string(), baseline_id.clone()),
            ("InstalledCount".to_string(), installed_count.to_string()),
            ("InstalledOtherCount".to_string(), "0".to_string()),
            ("InstalledRejectedCount".to_string(), rejected_count.to_string()),
            ("MissingCount".to_string(), state.missing_count.to_string()),
            ("FailedCount".to_string(), failed_count.to_string()),
            ("NotApplicableCount".to_string(), "0".to_string()),
            ("OperationType".to_string(), operation.to_string()),
            ("OperationStartTime".to_string(), started.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            ("OperationEndTime".to_string(), ended.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            ("RebootOption".to_string(), reboot_option.to_string()),
        ]);
        self.lock()
            .region(account, region)
            .patch_states
            .insert(instance.to_string(), PatchRecord { state: Some(state), patches });
        self.record_compliance(
            account,
            region,
            "ManagedInstance",
            instance,
            "Patch",
            types::ComplianceExecutionSummary {
                execution_time: ended,
                execution_id: Some(execution_id.to_string()),
                execution_type: Some("Command".into()),
            },
            entries,
            false,
        );
        self.record_inventory(account, region, instance, "AWS:PatchSummary", vec![summary], ended);
    }

    /// Run an `aws:runPatchBaseline` step on a node: scan, install for the
    /// `Install` operation (then scan again), and record the outcome.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_patch_baseline(
        &self,
        nodes: &Option<std::sync::Arc<dyn crate::commands::ManagedNodes>>,
        account: &str,
        region: &str,
        instance: &str,
        command_id: &str,
        inputs: &serde_json::Value,
        started: DateTime<Utc>,
    ) -> crate::commands::StepOutcome {
        let operation = inputs["Operation"].as_str().unwrap_or("Scan").to_string();
        let reboot = inputs["RebootOption"].as_str().unwrap_or("RebootIfNeeded").to_string();
        let run = |script: &'static str| async move {
            match nodes {
                Some(m) => m.run_shell(account, region, instance, script).await,
                None => Ok(None),
            }
        };
        let mut log = String::new();
        let mut failed = false;
        if operation == "Install" {
            match run(PATCH_INSTALL_SCRIPT).await {
                Ok(Some(out)) => {
                    log.push_str(&out.stdout);
                    if out.exit_code != 0 {
                        failed = true;
                        log.push_str(&out.stderr);
                    }
                }
                Ok(None) => {}
                Err(e) => return ("Failed", "Undeliverable", -1, String::new(), e),
            }
        }
        let scan = match run(PATCH_SCAN_SCRIPT).await {
            Ok(Some(out)) => parse_scan(&out.stdout),
            Ok(None) => Scan::default(),
            Err(e) => return ("Failed", "Undeliverable", -1, String::new(), e),
        };
        let ended = started + chrono::Duration::seconds(1);
        let partition = self.template().map(|t| t.partition).unwrap_or_else(|| "aws".into());
        self.record_patch_run(
            &partition, account, region, instance, &operation, &reboot, &scan, failed, started, ended, command_id,
        );
        let missing = self
            .lock()
            .region(account, region)
            .patch_states
            .get(instance)
            .and_then(|p| p.state.as_ref().map(|s| s.missing_count))
            .unwrap_or(0);
        let summary = format!(
            "{log}Patch baseline {operation} completed: {} installed, {missing} missing.\n",
            scan.installed.len()
        );
        if failed {
            ("Failed", "Failed", 1, summary, "failed to install patches".into())
        } else {
            ("Success", "Success", 0, summary, String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{operating_system, parse_scan};

    #[test]
    fn parses_dnf_scan() {
        let out = "OS\tamzn\t2023\nI\tbash\t5.2.15-1.amzn2023\tx86_64\t1700000000\nM\topenssl-libs.x86_64\t1:3.0.8-1.amzn2023.0.14\nU\tALAS2023-2024-001\tImportant/Sec.\topenssl-libs-1:3.0.8-1.amzn2023.0.14.x86_64\n";
        let s = parse_scan(out);
        assert_eq!(operating_system(&s.os_id, &s.os_version, ""), "AMAZON_LINUX_2023");
        assert_eq!(s.installed.len(), 1);
        assert_eq!(s.missing[0], ("openssl-libs".into(), "x86_64".into(), "1:3.0.8-1.amzn2023.0.14".into()));
        assert_eq!(s.advisories["openssl-libs-1:3.0.8-1.amzn2023.0.14.x86_64"].1, "Important");
    }

    #[test]
    fn parses_apt_scan() {
        let s = parse_scan("OS\tubuntu\t22.04\nM\tcurl\t7.81.0-1ubuntu1.16\tjammy-updates\n");
        assert_eq!(operating_system(&s.os_id, &s.os_version, ""), "UBUNTU");
        assert_eq!(s.missing[0].0, "curl");
    }
}
