//! Per file system settings (file system policy, backup policy, lifecycle
//! policies) and account preferences.

use mws_core::{CallerKind, ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind, PrincipalInfo, Request};

use crate::generated::types as t;
use crate::state::State;
use crate::util::{account_of, bad_request, err, fs_not_found};
use crate::Efs;

/// The principal of a request, as policy `Principal` elements see it.
pub fn principal_of(ctx: &RequestContext) -> PrincipalInfo {
    let c = &ctx.caller;
    let role_arn = match &c.kind {
        CallerKind::AssumedRole { role_name, .. } => {
            Some(format!("arn:{}:iam::{}:role/{role_name}", ctx.partition, c.account_id))
        }
        _ => None,
    };
    PrincipalInfo {
        account_id: c.account_id.clone(),
        arns: vec![c.arn.clone()],
        role_arn,
        anonymous: matches!(c.kind, CallerKind::Anonymous),
        ..Default::default()
    }
}

impl Efs {
    fn update_fs<R>(
        &self,
        ctx: &RequestContext,
        id: &str,
        f: impl FnOnce(&mut crate::state::FileSystem) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let account = account_of(ctx);
        let mut st = self.lock();
        let fs = st.region(&account, &ctx.region).file_systems.get_mut(id).ok_or_else(|| fs_not_found(id))?;
        f(fs)
    }

    pub(crate) async fn put_file_system_policy(
        &self,
        ctx: &RequestContext,
        input: t::PutFileSystemPolicyRequest,
    ) -> Result<t::FileSystemPolicyDescription, ServiceError> {
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "PutFileSystemPolicy", &fs, ConditionContext::new())?;
        let policy = Policy::parse(&input.policy, PolicyKind::Resource)
            .map_err(|e| err("InvalidPolicyException", 400, format!("Invalid policy: {}", e.0)))?;
        if input.policy.len() > 20_000 {
            return Err(err("InvalidPolicyException", 400, "The policy exceeds the maximum size of 20 KB."));
        }
        if !input.bypass_policy_lockout_safety_check {
            let principal = principal_of(ctx);
            let mut context = mws_iam_policy::ConditionContext::new();
            for (k, v) in ctx.global_condition_context() {
                context.insert(k, v);
            }
            let arn = fs.description.file_system_arn.clone().unwrap_or_default();
            let e = policy.evaluate(&Request {
                action: "elasticfilesystem:PutFileSystemPolicy",
                resource: &arn,
                principal: &principal,
                context: &context,
            });
            if e.denied() {
                return Err(err(
                    "InvalidPolicyException",
                    400,
                    "The policy would lock out the principal making the request from making future PutFileSystemPolicy requests on this file system. Set BypassPolicyLockoutSafetyCheck to true to put it anyway.",
                ));
            }
        }
        let id = fs.id().to_string();
        self.update_fs(ctx, &id, |f| {
            f.policy = Some(input.policy.clone());
            Ok(())
        })?;
        Ok(t::FileSystemPolicyDescription { file_system_id: Some(id), policy: Some(input.policy) })
    }

    pub(crate) async fn describe_file_system_policy(
        &self,
        ctx: &RequestContext,
        input: t::DescribeFileSystemPolicyRequest,
    ) -> Result<t::FileSystemPolicyDescription, ServiceError> {
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "DescribeFileSystemPolicy", &fs, ConditionContext::new())?;
        let id = fs.id().to_string();
        match fs.policy {
            Some(p) => Ok(t::FileSystemPolicyDescription { file_system_id: Some(id), policy: Some(p) }),
            None => Err(err("PolicyNotFound", 404, format!("File system '{id}' does not have a file system policy."))),
        }
    }

    pub(crate) async fn delete_file_system_policy(
        &self,
        ctx: &RequestContext,
        input: t::DeleteFileSystemPolicyRequest,
    ) -> Result<(), ServiceError> {
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "DeleteFileSystemPolicy", &fs, ConditionContext::new())?;
        self.update_fs(ctx, fs.id(), |f| {
            f.policy = None;
            Ok(())
        })
    }

    pub(crate) async fn put_backup_policy(
        &self,
        ctx: &RequestContext,
        input: t::PutBackupPolicyRequest,
    ) -> Result<t::BackupPolicyDescription, ServiceError> {
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "PutBackupPolicy", &fs, ConditionContext::new())?;
        let status = input.backup_policy.status.clone();
        if !matches!(status.as_str(), "ENABLED" | "DISABLED") {
            return Err(bad_request("The backup policy status must be ENABLED or DISABLED."));
        }
        self.update_fs(ctx, fs.id(), |f| {
            f.backup = status.clone();
            Ok(())
        })?;
        Ok(t::BackupPolicyDescription { backup_policy: Some(t::BackupPolicy { status }) })
    }

    pub(crate) async fn describe_backup_policy(
        &self,
        ctx: &RequestContext,
        input: t::DescribeBackupPolicyRequest,
    ) -> Result<t::BackupPolicyDescription, ServiceError> {
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "DescribeBackupPolicy", &fs, ConditionContext::new())?;
        let status = if fs.backup.is_empty() { "DISABLED".into() } else { fs.backup };
        Ok(t::BackupPolicyDescription { backup_policy: Some(t::BackupPolicy { status }) })
    }

    pub(crate) async fn put_lifecycle_configuration(
        &self,
        ctx: &RequestContext,
        input: t::PutLifecycleConfigurationRequest,
    ) -> Result<t::LifecycleConfigurationDescription, ServiceError> {
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "PutLifecycleConfiguration", &fs, ConditionContext::new())?;
        let policies = input.lifecycle_policies.clone();
        let (mut ia, mut primary, mut archive) = (0, 0, 0);
        for p in &policies {
            let set = [
                p.transition_to_ia.is_some(),
                p.transition_to_primary_storage_class.is_some(),
                p.transition_to_archive.is_some(),
            ]
            .iter()
            .filter(|b| **b)
            .count();
            if set != 1 {
                return Err(bad_request("Each lifecycle policy must specify exactly one transition."));
            }
            ia += p.transition_to_ia.is_some() as u32;
            primary += p.transition_to_primary_storage_class.is_some() as u32;
            archive += p.transition_to_archive.is_some() as u32;
        }
        if ia > 1 || primary > 1 || archive > 1 {
            return Err(bad_request(
                "A lifecycle configuration can contain at most one policy of each transition type.",
            ));
        }
        if archive == 1 && fs.description.throughput_mode.as_deref() != Some("elastic") {
            return Err(bad_request(
                "Transitions to Archive storage are only supported for file systems using Elastic throughput.",
            ));
        }
        let days = |rule: &Option<String>| {
            rule.as_deref()
                .and_then(|r| r.strip_prefix("AFTER_"))
                .and_then(|r| r.split('_').next())
                .and_then(|d| d.parse::<u32>().ok())
        };
        let ia_days = policies.iter().find_map(|p| days(&p.transition_to_ia));
        let archive_days = policies.iter().find_map(|p| days(&p.transition_to_archive));
        if let (Some(ia), Some(ar)) = (ia_days, archive_days) {
            if ar <= ia {
                return Err(bad_request(
                    "The TransitionToArchive value must be greater than the TransitionToIA value.",
                ));
            }
        }
        self.update_fs(ctx, fs.id(), |f| {
            f.lifecycle = policies.clone();
            Ok(())
        })?;
        Ok(t::LifecycleConfigurationDescription { lifecycle_policies: Some(policies) })
    }

    pub(crate) async fn describe_lifecycle_configuration(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLifecycleConfigurationRequest,
    ) -> Result<t::LifecycleConfigurationDescription, ServiceError> {
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "DescribeLifecycleConfiguration", &fs, ConditionContext::new())?;
        Ok(t::LifecycleConfigurationDescription { lifecycle_policies: Some(fs.lifecycle) })
    }

    pub(crate) async fn put_account_preferences(
        &self,
        ctx: &RequestContext,
        input: t::PutAccountPreferencesRequest,
    ) -> Result<t::PutAccountPreferencesResponse, ServiceError> {
        ctx.authorize("elasticfilesystem:PutAccountPreferences", "*", ConditionContext::new())?;
        let account = account_of(ctx);
        if !matches!(input.resource_id_type.as_str(), "LONG_ID" | "SHORT_ID") {
            return Err(bad_request("ResourceIdType must be LONG_ID or SHORT_ID."));
        }
        self.lock().preferences.insert(State::key(&account, &ctx.region), input.resource_id_type.clone());
        Ok(t::PutAccountPreferencesResponse { resource_id_preference: Some(preference(&input.resource_id_type)) })
    }

    pub(crate) async fn describe_account_preferences(
        &self,
        ctx: &RequestContext,
        _input: t::DescribeAccountPreferencesRequest,
    ) -> Result<t::DescribeAccountPreferencesResponse, ServiceError> {
        ctx.authorize("elasticfilesystem:DescribeAccountPreferences", "*", ConditionContext::new())?;
        let account = account_of(ctx);
        let kind = self
            .lock()
            .preferences
            .get(&State::key(&account, &ctx.region))
            .cloned()
            .unwrap_or_else(|| "LONG_ID".into());
        Ok(t::DescribeAccountPreferencesResponse { resource_id_preference: Some(preference(&kind)), next_token: None })
    }
}

fn preference(kind: &str) -> t::ResourceIdPreference {
    t::ResourceIdPreference {
        resource_id_type: Some(kind.into()),
        resources: Some(vec!["FILE_SYSTEM".into(), "MOUNT_TARGET".into()]),
    }
}
