//! Patch Manager's baselines: the predefined AWS baselines for each
//! operating system, custom baselines, defaults and patch groups. MWS has
//! no patch catalogue, so the patch listings are empty.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::generated::{errors, types};
use crate::names::{now, page, request_tag_conditions, resource_tag_conditions};
use crate::Ssm;

/// The account AWS's predefined baselines belong to.
const AWS_OWNER: &str = "075727635805";
const MAX_BASELINES: usize = 50;

/// The operating systems and their predefined default baselines.
const PREDEFINED: &[(&str, &str, &str)] = &[
    ("WINDOWS", "AWS-DefaultPatchBaseline", "Default Patch Baseline Provided by AWS."),
    ("AMAZON_LINUX", "AWS-AmazonLinuxDefaultPatchBaseline", "Default Patch Baseline for Amazon Linux Provided by AWS."),
    (
        "AMAZON_LINUX_2",
        "AWS-AmazonLinux2DefaultPatchBaseline",
        "Default Patch Baseline for Amazon Linux 2 Provided by AWS.",
    ),
    (
        "AMAZON_LINUX_2022",
        "AWS-AmazonLinux2022DefaultPatchBaseline",
        "Default Patch Baseline for Amazon Linux 2022 Provided by AWS.",
    ),
    (
        "AMAZON_LINUX_2023",
        "AWS-AmazonLinux2023DefaultPatchBaseline",
        "Default Patch Baseline for Amazon Linux 2023 Provided by AWS.",
    ),
    ("UBUNTU", "AWS-UbuntuDefaultPatchBaseline", "Default Patch Baseline for Ubuntu Provided by AWS."),
    (
        "REDHAT_ENTERPRISE_LINUX",
        "AWS-RedHatDefaultPatchBaseline",
        "Default Patch Baseline for Redhat Enterprise Linux Provided by AWS.",
    ),
    ("SUSE", "AWS-SuseDefaultPatchBaseline", "Default Patch Baseline for Suse Provided by AWS."),
    ("CENTOS", "AWS-CentOSDefaultPatchBaseline", "Default Patch Baseline for CentOS Provided by AWS."),
    ("ORACLE_LINUX", "AWS-OracleLinuxDefaultPatchBaseline", "Default Patch Baseline for Oracle Linux Provided by AWS."),
    ("DEBIAN", "AWS-DebianDefaultPatchBaseline", "Default Patch Baseline for Debian Provided by AWS."),
    ("MACOS", "AWS-MacOSDefaultPatchBaseline", "Default Patch Baseline for MacOS Provided by AWS."),
    (
        "RASPBIAN",
        "AWS-RaspbianDefaultPatchBaseline",
        "Default Patch Baseline for Raspberry Pi OS (formerly Raspbian) Provided by AWS.",
    ),
    ("ROCKY_LINUX", "AWS-RockyLinuxDefaultPatchBaseline", "Default Patch Baseline for Rocky Linux Provided by AWS."),
    ("ALMA_LINUX", "AWS-AlmaLinuxDefaultPatchBaseline", "Default Patch Baseline for Alma Linux Provided by AWS."),
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Baseline {
    pub baseline: types::GetPatchBaselineResult,
    pub tags: BTreeMap<String, String>,
    pub client_token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PatchState {
    /// Custom baselines, by id.
    pub baselines: BTreeMap<String, Baseline>,
    /// The default baseline per operating system, when changed.
    pub defaults: BTreeMap<String, String>,
    /// Patch group -> operating system -> baseline id.
    pub groups: BTreeMap<String, BTreeMap<String, String>>,
}

fn predefined_id(region: &str, os: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, format!("{region}/{os}").as_bytes());
    let hex: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("pb-{}", &hex[..17])
}

fn predefined_arn(partition: &str, region: &str, os: &str) -> String {
    format!("arn:{partition}:ssm:{region}:{AWS_OWNER}:patchbaseline/{}", predefined_id(region, os))
}

fn predefined(ctx: &RequestContext) -> Vec<types::GetPatchBaselineResult> {
    let created = DateTime::parse_from_rfc3339("2017-05-31T00:00:00Z").expect("valid date").with_timezone(&Utc);
    PREDEFINED
        .iter()
        .map(|(os, name, description)| {
            let (key, values): (&str, Vec<&str>) = match *os {
                "WINDOWS" => ("CLASSIFICATION", vec!["CriticalUpdates", "SecurityUpdates"]),
                "MACOS" => ("PRODUCT", vec!["*"]),
                "UBUNTU" | "DEBIAN" | "RASPBIAN" => ("PRIORITY", vec!["Required", "Important", "Standard"]),
                _ => ("CLASSIFICATION", vec!["Security"]),
            };
            let rule = types::PatchRule {
                patch_filter_group: types::PatchFilterGroup {
                    patch_filters: vec![types::PatchFilter {
                        key: key.into(),
                        values: values.into_iter().map(String::from).collect(),
                    }],
                },
                compliance_level: Some("UNSPECIFIED".into()),
                approve_after_days: Some(7),
                approve_until_date: None,
                enable_non_security: Some(false),
            };
            types::GetPatchBaselineResult {
                baseline_id: Some(predefined_arn(&ctx.partition, &ctx.region, os)),
                name: Some(name.to_string()),
                operating_system: Some(os.to_string()),
                global_filters: Some(types::PatchFilterGroup { patch_filters: Vec::new() }),
                approval_rules: Some(types::PatchRuleGroup { patch_rules: vec![rule] }),
                approved_patches: Some(Vec::new()),
                approved_patches_compliance_level: Some("UNSPECIFIED".into()),
                approved_patches_enable_non_security: Some(false),
                rejected_patches: Some(Vec::new()),
                rejected_patches_action: Some("ALLOW_AS_DEPENDENCY".into()),
                patch_groups: Some(Vec::new()),
                created_date: Some(created),
                modified_date: Some(created),
                description: Some(description.to_string()),
                sources: Some(Vec::new()),
                available_security_updates_compliance_status: None,
            }
        })
        .collect()
}

fn baseline_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ssm:{}:{}:patchbaseline/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

fn not_found(id: &str) -> ServiceError {
    errors::does_not_exist(format!("Patch Baseline {id} does not exist."))
}

/// `pb-...` from an id or ARN.
fn bare(id: &str) -> &str {
    id.rsplit('/').next().unwrap_or(id)
}

fn validate_rules(rules: &Option<types::PatchRuleGroup>) -> Result<(), ServiceError> {
    for r in rules.iter().flat_map(|g| &g.patch_rules) {
        match (r.approve_after_days, &r.approve_until_date) {
            (Some(d), None) if (0..=360).contains(&d) => {}
            (None, Some(date)) => {
                chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|_| {
                    errors::validation(format!("ApproveUntilDate {date} must be in the format YYYY-MM-DD."))
                })?;
            }
            (Some(_), None) => return Err(errors::validation("ApproveAfterDays must be between 0 and 360.")),
            _ => {
                return Err(errors::validation(
                    "Each approval rule needs exactly one of ApproveAfterDays and ApproveUntilDate.",
                ))
            }
        }
    }
    Ok(())
}

fn identity(b: &types::GetPatchBaselineResult, default: bool) -> types::PatchBaselineIdentity {
    types::PatchBaselineIdentity {
        baseline_id: b.baseline_id.clone(),
        baseline_name: b.name.clone(),
        operating_system: b.operating_system.clone(),
        baseline_description: b.description.clone(),
        default_baseline: default,
    }
}

impl Ssm {
    fn list_arn_patch(ctx: &RequestContext) -> String {
        format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id)
    }

    fn patch_state(&self, ctx: &RequestContext) -> PatchState {
        let st = self.lock();
        st.region_ref(&ctx.caller.account_id, &ctx.region).map(|r| r.patch.clone()).unwrap_or_default()
    }

    /// The default baseline id for `os` (an ARN for AWS's).
    fn default_baseline(&self, ctx: &RequestContext, p: &PatchState, os: &str) -> String {
        p.defaults.get(os).cloned().unwrap_or_else(|| predefined_arn(&ctx.partition, &ctx.region, os))
    }

    /// A baseline by id or ARN: a custom one or a predefined one.
    fn find_baseline(&self, ctx: &RequestContext, p: &PatchState, id: &str) -> Option<types::GetPatchBaselineResult> {
        if let Some(b) = p.baselines.get(bare(id)) {
            let mut out = b.baseline.clone();
            out.patch_groups = Some(
                p.groups
                    .iter()
                    .filter(|(_, m)| m.values().any(|v| bare(v) == bare(id)))
                    .map(|(g, _)| g.clone())
                    .collect(),
            );
            return Some(out);
        }
        predefined(ctx).into_iter().find(|b| b.baseline_id.as_deref().is_some_and(|x| bare(x) == bare(id))).map(
            |mut b| {
                let full = b.baseline_id.clone().unwrap_or_default();
                b.patch_groups = Some(
                    p.groups.iter().filter(|(_, m)| m.values().any(|v| *v == full)).map(|(g, _)| g.clone()).collect(),
                );
                b
            },
        )
    }

    fn custom_baseline(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
    ) -> Result<(PatchState, Baseline), ServiceError> {
        let p = self.patch_state(ctx);
        let b = p.baselines.get(bare(id)).cloned();
        let cond = b.as_ref().map(|b| resource_tag_conditions(&b.tags)).unwrap_or_default();
        ctx.authorize(&format!("ssm:{action}"), &baseline_arn(ctx, bare(id)), cond)?;
        match b {
            Some(b) => Ok((p, b)),
            None if self.find_baseline(ctx, &p, id).is_some() => {
                Err(errors::validation("You can't modify a patch baseline that AWS provides."))
            }
            None => Err(not_found(id)),
        }
    }

    fn save_patch(&self, ctx: &RequestContext, f: impl FnOnce(&mut PatchState)) {
        f(&mut self.lock().region(&ctx.caller.account_id, &ctx.region).patch);
    }

    pub(crate) fn create_patch_baseline(
        &self,
        ctx: &RequestContext,
        input: types::CreatePatchBaselineRequest,
    ) -> Result<types::CreatePatchBaselineResult, ServiceError> {
        let tags: Vec<(String, String)> =
            input.tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect();
        ctx.authorize(
            "ssm:CreatePatchBaseline",
            &baseline_arn(ctx, "*"),
            request_tag_conditions(tags.iter().map(|(k, v)| (k, v))),
        )?;
        validate_rules(&input.approval_rules)?;
        let os = input.operating_system.unwrap_or_else(|| "WINDOWS".into());
        if input.sources.as_ref().is_some_and(|s| !s.is_empty()) && os == "WINDOWS" {
            return Err(errors::validation("Sources are not supported for Windows patch baselines."));
        }
        let p = self.patch_state(ctx);
        if let Some(token) = &input.client_token {
            if let Some(b) = p.baselines.values().find(|b| b.client_token.as_deref() == Some(token.as_str())) {
                return Ok(types::CreatePatchBaselineResult { baseline_id: b.baseline.baseline_id.clone() });
            }
        }
        if p.baselines.len() >= MAX_BASELINES {
            return Err(errors::resource_limit_exceeded(format!(
                "Patch baseline limit exceeded. You can create up to {MAX_BASELINES} patch baselines."
            )));
        }
        let u = uuid::Uuid::new_v4().simple().to_string();
        let id = format!("pb-{}", &u[..17]);
        let at = now(ctx);
        let baseline = types::GetPatchBaselineResult {
            baseline_id: Some(id.clone()),
            name: Some(input.name),
            operating_system: Some(os),
            global_filters: Some(input.global_filters.unwrap_or(types::PatchFilterGroup { patch_filters: Vec::new() })),
            approval_rules: Some(input.approval_rules.unwrap_or(types::PatchRuleGroup { patch_rules: Vec::new() })),
            approved_patches: Some(input.approved_patches.unwrap_or_default()),
            approved_patches_compliance_level: Some(
                input.approved_patches_compliance_level.unwrap_or_else(|| "UNSPECIFIED".into()),
            ),
            approved_patches_enable_non_security: Some(input.approved_patches_enable_non_security.unwrap_or(false)),
            rejected_patches: Some(input.rejected_patches.unwrap_or_default()),
            rejected_patches_action: Some(
                input.rejected_patches_action.unwrap_or_else(|| "ALLOW_AS_DEPENDENCY".into()),
            ),
            patch_groups: Some(Vec::new()),
            created_date: Some(at),
            modified_date: Some(at),
            description: input.description,
            sources: Some(input.sources.unwrap_or_default()),
            available_security_updates_compliance_status: input.available_security_updates_compliance_status,
        };
        self.save_patch(ctx, |p| {
            p.baselines.insert(
                id.clone(),
                Baseline { baseline, tags: tags.into_iter().collect(), client_token: input.client_token },
            );
        });
        Ok(types::CreatePatchBaselineResult { baseline_id: Some(id) })
    }

    pub(crate) fn get_patch_baseline(
        &self,
        ctx: &RequestContext,
        input: types::GetPatchBaselineRequest,
    ) -> Result<types::GetPatchBaselineResult, ServiceError> {
        let p = self.patch_state(ctx);
        let cond =
            p.baselines.get(bare(&input.baseline_id)).map(|b| resource_tag_conditions(&b.tags)).unwrap_or_default();
        ctx.authorize("ssm:GetPatchBaseline", &baseline_arn(ctx, bare(&input.baseline_id)), cond)?;
        self.find_baseline(ctx, &p, &input.baseline_id).ok_or_else(|| not_found(&input.baseline_id))
    }

    pub(crate) fn update_patch_baseline(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePatchBaselineRequest,
    ) -> Result<types::UpdatePatchBaselineResult, ServiceError> {
        let (_, mut b) = self.custom_baseline(ctx, "UpdatePatchBaseline", &input.baseline_id)?;
        validate_rules(&input.approval_rules)?;
        let replace = input.replace.unwrap_or(false);
        let x = &mut b.baseline;
        macro_rules! set {
            ($field:ident) => {
                if input.$field.is_some() || replace {
                    x.$field = input.$field.clone();
                }
            };
        }
        if input.name.is_some() {
            x.name = input.name.clone();
        }
        set!(global_filters);
        set!(approval_rules);
        set!(approved_patches);
        set!(approved_patches_compliance_level);
        set!(approved_patches_enable_non_security);
        set!(rejected_patches);
        set!(rejected_patches_action);
        set!(description);
        set!(sources);
        set!(available_security_updates_compliance_status);
        x.modified_date = Some(now(ctx));
        let x = x.clone();
        let id = x.baseline_id.clone().unwrap_or_default();
        self.save_patch(ctx, |p| {
            p.baselines.insert(id, b);
        });
        Ok(types::UpdatePatchBaselineResult {
            baseline_id: x.baseline_id,
            name: x.name,
            operating_system: x.operating_system,
            global_filters: x.global_filters,
            approval_rules: x.approval_rules,
            approved_patches: x.approved_patches,
            approved_patches_compliance_level: x.approved_patches_compliance_level,
            approved_patches_enable_non_security: x.approved_patches_enable_non_security,
            rejected_patches: x.rejected_patches,
            rejected_patches_action: x.rejected_patches_action,
            created_date: x.created_date,
            modified_date: x.modified_date,
            description: x.description,
            sources: x.sources,
            available_security_updates_compliance_status: x.available_security_updates_compliance_status,
        })
    }

    pub(crate) fn delete_patch_baseline(
        &self,
        ctx: &RequestContext,
        input: types::DeletePatchBaselineRequest,
    ) -> Result<types::DeletePatchBaselineResult, ServiceError> {
        let id = bare(&input.baseline_id).to_string();
        let p = self.patch_state(ctx);
        ctx.authorize("ssm:DeletePatchBaseline", &baseline_arn(ctx, &id), ConditionContext::new())?;
        if p.defaults.values().any(|d| bare(d) == id) {
            return Err(errors::resource_in_use(
                "The patch baseline is the default baseline for its operating system. Register a different default first.",
            ));
        }
        if p.groups.values().any(|m| m.values().any(|v| bare(v) == id)) {
            return Err(errors::resource_in_use(
                "The patch baseline is registered with a patch group. Deregister it first.",
            ));
        }
        // Deleting a baseline that doesn't exist succeeds, as in AWS.
        self.save_patch(ctx, |p| {
            p.baselines.remove(&id);
        });
        Ok(types::DeletePatchBaselineResult { baseline_id: Some(id) })
    }

    pub(crate) fn describe_patch_baselines(
        &self,
        ctx: &RequestContext,
        input: types::DescribePatchBaselinesRequest,
    ) -> Result<types::DescribePatchBaselinesResult, ServiceError> {
        ctx.authorize("ssm:DescribePatchBaselines", &Self::list_arn_patch(ctx), ConditionContext::new())?;
        let p = self.patch_state(ctx);
        let mut all: Vec<(bool, types::GetPatchBaselineResult)> =
            predefined(ctx).into_iter().map(|b| (true, b)).collect();
        all.extend(p.baselines.values().map(|b| (false, b.baseline.clone())));
        let mut filters = Vec::new();
        for f in input.filters.unwrap_or_default() {
            let key = f.key.unwrap_or_default();
            if !matches!(key.as_str(), "NAME_PREFIX" | "OWNER" | "OPERATING_SYSTEM") {
                return Err(errors::validation(format!(
                    "Filter key {key} is not supported. Valid keys: NAME_PREFIX, OWNER, OPERATING_SYSTEM"
                )));
            }
            filters.push((key, f.values.unwrap_or_default()));
        }
        let items: Vec<types::PatchBaselineIdentity> = all
            .into_iter()
            .filter(|(aws, b)| {
                filters.iter().all(|(k, v)| match k.as_str() {
                    "NAME_PREFIX" => v.iter().any(|x| b.name.as_deref().unwrap_or_default().starts_with(x.as_str())),
                    "OWNER" => v.iter().any(|x| match x.as_str() {
                        "AWS" => *aws,
                        "Self" => !*aws,
                        _ => true,
                    }),
                    _ => v.iter().any(|x| b.operating_system.as_deref() == Some(x.as_str())),
                })
            })
            .map(|(_, b)| {
                let os = b.operating_system.clone().unwrap_or_default();
                let default = self.default_baseline(ctx, &p, &os);
                let is_default = b.baseline_id.as_deref().is_some_and(|id| bare(id) == bare(&default));
                identity(&b, is_default)
            })
            .collect();
        let limit = input.max_results.unwrap_or(100).clamp(1, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribePatchBaselinesResult { baseline_identities: Some(items), next_token: next })
    }

    pub(crate) fn get_default_patch_baseline(
        &self,
        ctx: &RequestContext,
        input: types::GetDefaultPatchBaselineRequest,
    ) -> Result<types::GetDefaultPatchBaselineResult, ServiceError> {
        ctx.authorize("ssm:GetDefaultPatchBaseline", &Self::list_arn_patch(ctx), ConditionContext::new())?;
        let os = input.operating_system.unwrap_or_else(|| "WINDOWS".into());
        let p = self.patch_state(ctx);
        Ok(types::GetDefaultPatchBaselineResult {
            baseline_id: Some(self.default_baseline(ctx, &p, &os)),
            operating_system: Some(os),
        })
    }

    pub(crate) fn register_default_patch_baseline(
        &self,
        ctx: &RequestContext,
        input: types::RegisterDefaultPatchBaselineRequest,
    ) -> Result<types::RegisterDefaultPatchBaselineResult, ServiceError> {
        ctx.authorize(
            "ssm:RegisterDefaultPatchBaseline",
            &baseline_arn(ctx, bare(&input.baseline_id)),
            ConditionContext::new(),
        )?;
        let p = self.patch_state(ctx);
        let b = self.find_baseline(ctx, &p, &input.baseline_id).ok_or_else(|| not_found(&input.baseline_id))?;
        let os = b.operating_system.clone().unwrap_or_default();
        let id = b.baseline_id.clone().unwrap_or_default();
        self.save_patch(ctx, |p| {
            p.defaults.insert(os, id.clone());
        });
        Ok(types::RegisterDefaultPatchBaselineResult { baseline_id: Some(id) })
    }

    pub(crate) fn register_patch_baseline_for_patch_group(
        &self,
        ctx: &RequestContext,
        input: types::RegisterPatchBaselineForPatchGroupRequest,
    ) -> Result<types::RegisterPatchBaselineForPatchGroupResult, ServiceError> {
        ctx.authorize(
            "ssm:RegisterPatchBaselineForPatchGroup",
            &baseline_arn(ctx, bare(&input.baseline_id)),
            ConditionContext::new(),
        )?;
        let p = self.patch_state(ctx);
        let b = self.find_baseline(ctx, &p, &input.baseline_id).ok_or_else(|| not_found(&input.baseline_id))?;
        let os = b.operating_system.clone().unwrap_or_default();
        let id = b.baseline_id.clone().unwrap_or_default();
        if p.groups.get(&input.patch_group).is_some_and(|m| m.contains_key(&os)) {
            return Err(errors::already_exists(format!(
                "Patch Group {} is already registered with a baseline for operating system {os}.",
                input.patch_group
            )));
        }
        self.save_patch(ctx, |p| {
            p.groups.entry(input.patch_group.clone()).or_default().insert(os, id.clone());
        });
        Ok(types::RegisterPatchBaselineForPatchGroupResult {
            baseline_id: Some(id),
            patch_group: Some(input.patch_group),
        })
    }

    pub(crate) fn deregister_patch_baseline_for_patch_group(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterPatchBaselineForPatchGroupRequest,
    ) -> Result<types::DeregisterPatchBaselineForPatchGroupResult, ServiceError> {
        ctx.authorize(
            "ssm:DeregisterPatchBaselineForPatchGroup",
            &baseline_arn(ctx, bare(&input.baseline_id)),
            ConditionContext::new(),
        )?;
        let p = self.patch_state(ctx);
        let registered =
            p.groups.get(&input.patch_group).is_some_and(|m| m.values().any(|v| bare(v) == bare(&input.baseline_id)));
        if !registered {
            return Err(errors::does_not_exist(format!(
                "Patch Baseline {} is not registered with Patch Group {}.",
                input.baseline_id, input.patch_group
            )));
        }
        self.save_patch(ctx, |p| {
            if let Some(m) = p.groups.get_mut(&input.patch_group) {
                m.retain(|_, v| bare(v) != bare(&input.baseline_id));
                if m.is_empty() {
                    p.groups.remove(&input.patch_group);
                }
            }
        });
        Ok(types::DeregisterPatchBaselineForPatchGroupResult {
            baseline_id: Some(input.baseline_id),
            patch_group: Some(input.patch_group),
        })
    }

    pub(crate) fn describe_patch_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribePatchGroupsRequest,
    ) -> Result<types::DescribePatchGroupsResult, ServiceError> {
        ctx.authorize("ssm:DescribePatchGroups", &Self::list_arn_patch(ctx), ConditionContext::new())?;
        let p = self.patch_state(ctx);
        let mut filters = Vec::new();
        for f in input.filters.unwrap_or_default() {
            let key = f.key.unwrap_or_default();
            if !matches!(key.as_str(), "NAME_PREFIX" | "OPERATING_SYSTEM") {
                return Err(errors::validation(format!(
                    "Filter key {key} is not supported. Valid keys: NAME_PREFIX, OPERATING_SYSTEM"
                )));
            }
            filters.push((key, f.values.unwrap_or_default()));
        }
        let mut items = Vec::new();
        for (group, by_os) in &p.groups {
            for (os, id) in by_os {
                let ok = filters.iter().all(|(k, v)| match k.as_str() {
                    "NAME_PREFIX" => v.iter().any(|x| group.starts_with(x.as_str())),
                    _ => v.contains(os),
                });
                if !ok {
                    continue;
                }
                let Some(b) = self.find_baseline(ctx, &p, id) else { continue };
                let default = self.default_baseline(ctx, &p, os);
                items.push(types::PatchGroupPatchBaselineMapping {
                    patch_group: Some(group.clone()),
                    baseline_identity: Some(identity(&b, bare(&default) == bare(id))),
                });
            }
        }
        let limit = input.max_results.unwrap_or(100).clamp(1, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribePatchGroupsResult { mappings: Some(items), next_token: next })
    }

    pub(crate) fn get_patch_baseline_for_patch_group(
        &self,
        ctx: &RequestContext,
        input: types::GetPatchBaselineForPatchGroupRequest,
    ) -> Result<types::GetPatchBaselineForPatchGroupResult, ServiceError> {
        ctx.authorize("ssm:GetPatchBaselineForPatchGroup", &Self::list_arn_patch(ctx), ConditionContext::new())?;
        let os = input.operating_system.unwrap_or_else(|| "WINDOWS".into());
        let p = self.patch_state(ctx);
        // A group with no baseline for the system uses the default.
        let id = p
            .groups
            .get(&input.patch_group)
            .and_then(|m| m.get(&os))
            .cloned()
            .unwrap_or_else(|| self.default_baseline(ctx, &p, &os));
        Ok(types::GetPatchBaselineForPatchGroupResult {
            baseline_id: Some(id),
            patch_group: Some(input.patch_group),
            operating_system: Some(os),
        })
    }

    pub(crate) fn describe_patch_group_state(
        &self,
        ctx: &RequestContext,
        input: types::DescribePatchGroupStateRequest,
    ) -> Result<types::DescribePatchGroupStateResult, ServiceError> {
        ctx.authorize("ssm:DescribePatchGroupState", &Self::list_arn_patch(ctx), ConditionContext::new())?;
        let members = self
            .nodes_of(&ctx.caller.account_id, &ctx.region)
            .into_iter()
            .filter(|n| {
                n.tags.get("Patch Group").or_else(|| n.tags.get("PatchGroup")).is_some_and(|g| *g == input.patch_group)
            })
            .count() as i32;
        // No node has reported patch compliance, so nothing is installed
        // or missing.
        Ok(types::DescribePatchGroupStateResult {
            instances: members,
            instances_with_unreported_not_applicable_patches: Some(0),
            instances_with_installed_pending_reboot_patches: Some(0),
            instances_with_installed_rejected_patches: Some(0),
            instances_with_critical_non_compliant_patches: Some(0),
            instances_with_security_non_compliant_patches: Some(0),
            instances_with_other_non_compliant_patches: Some(0),
            instances_with_available_security_updates: Some(0),
            ..Default::default()
        })
    }

    pub(crate) fn describe_available_patches(
        &self,
        ctx: &RequestContext,
        _input: types::DescribeAvailablePatchesRequest,
    ) -> Result<types::DescribeAvailablePatchesResult, ServiceError> {
        ctx.authorize("ssm:DescribeAvailablePatches", &Self::list_arn_patch(ctx), ConditionContext::new())?;
        Ok(types::DescribeAvailablePatchesResult { patches: Some(Vec::new()), next_token: None })
    }

    pub(crate) fn describe_effective_patches_for_patch_baseline(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEffectivePatchesForPatchBaselineRequest,
    ) -> Result<types::DescribeEffectivePatchesForPatchBaselineResult, ServiceError> {
        let p = self.patch_state(ctx);
        ctx.authorize(
            "ssm:DescribeEffectivePatchesForPatchBaseline",
            &baseline_arn(ctx, bare(&input.baseline_id)),
            ConditionContext::new(),
        )?;
        let b = self.find_baseline(ctx, &p, &input.baseline_id).ok_or_else(|| not_found(&input.baseline_id))?;
        if b.operating_system.as_deref() != Some("WINDOWS") {
            return Err(errors::unsupported_operating_system(
                "The operating system you specified is not supported, or the operation is not supported for the operating system.",
            ));
        }
        Ok(types::DescribeEffectivePatchesForPatchBaselineResult {
            effective_patches: Some(Vec::new()),
            next_token: None,
        })
    }

    /// The tags of the caller's baseline `id`, for the tagging calls.
    pub(crate) fn baseline_tags_mut<'a>(
        region: &'a mut crate::state::Region,
        id: &str,
    ) -> Option<&'a mut BTreeMap<String, String>> {
        region.patch.baselines.get_mut(bare(id)).map(|b| &mut b.tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predefined_ids_are_stable_per_region() {
        assert_eq!(predefined_id("us-east-1", "WINDOWS"), predefined_id("us-east-1", "WINDOWS"));
        assert_ne!(predefined_id("us-east-1", "WINDOWS"), predefined_id("us-west-2", "WINDOWS"));
        assert_eq!(predefined_id("us-east-1", "UBUNTU").len(), 20);
        assert_eq!(bare("arn:aws:ssm:us-east-1:075727635805:patchbaseline/pb-0123"), "pb-0123");
    }
}
