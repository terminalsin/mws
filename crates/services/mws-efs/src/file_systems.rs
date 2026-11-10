//! File systems: create, describe, update, protection and delete.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::{FileSystem, State};
use crate::util::{
    account_of, bad_request, err, fs_arn, fs_not_found, name_tag, new_id, page, request_tag_context,
    resource_tag_context, validate_tags, with_member, wrong_state,
};
use crate::Efs;

/// A file system's id from an id or ARN.
pub fn fs_id(id_or_arn: &str) -> &str {
    id_or_arn.rsplit('/').next().unwrap_or(id_or_arn)
}

impl Efs {
    /// Whether new ids in the caller's account and Region are long.
    pub(crate) fn long_ids(st: &State, account: &str, region: &str) -> bool {
        st.preferences.get(&State::key(account, region)).is_none_or(|p| p == "LONG_ID")
    }

    /// A copy of the caller's file system `id` (id or ARN).
    pub(crate) fn file_system(&self, ctx: &RequestContext, id: &str) -> Result<FileSystem, ServiceError> {
        let account = account_of(ctx);
        let id = fs_id(id);
        let mut st = self.lock();
        st.region(&account, &ctx.region).file_systems.get(id).cloned().ok_or_else(|| fs_not_found(id))
    }

    /// Authorize `action` on a file system, with its tags and its file
    /// system policy.
    pub(crate) fn authorize_fs(
        &self,
        ctx: &RequestContext,
        action: &str,
        fs: &FileSystem,
        mut extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        extra.extend(resource_tag_context(&fs.description.tags));
        let arn = fs.description.file_system_arn.clone().unwrap_or_default();
        ctx.authorize_with_resource_policy(&format!("elasticfilesystem:{action}"), &arn, fs.policy.as_deref(), extra)
    }

    /// The description AWS returns, with live mount target count and size.
    pub(crate) fn render_fs(
        &self,
        st: &State,
        account: &str,
        region: &str,
        fs: &FileSystem,
        now: chrono::DateTime<chrono::Utc>,
    ) -> t::FileSystemDescription {
        let mut d = fs.description.clone();
        let key = State::key(account, region);
        d.number_of_mount_targets = st
            .regions
            .get(&key)
            .map(|r| r.mount_targets.values().filter(|m| m.description.file_system_id == d.file_system_id).count())
            .unwrap_or(0) as i32;
        let size = self.storage().size(&d.file_system_id);
        d.size_in_bytes = t::FileSystemSize {
            value: size,
            timestamp: Some(now),
            value_in_ia: Some(0),
            value_in_standard: Some(size),
            value_in_archive: Some(0),
        };
        d.name = name_tag(&d.tags);
        d
    }

    pub(crate) async fn create_file_system(
        &self,
        ctx: &RequestContext,
        input: t::CreateFileSystemRequest,
    ) -> Result<t::FileSystemDescription, ServiceError> {
        let account = account_of(ctx);
        let tags = input.tags.clone().unwrap_or_default();
        validate_tags(&tags)?;
        let encrypted = input.encrypted.unwrap_or(false);
        let mut context = request_tag_context(&tags);
        context.insert("elasticfilesystem:Encrypted".into(), vec![encrypted.to_string()]);
        if !tags.is_empty() {
            context.insert("elasticfilesystem:CreateAction".into(), vec!["CreateFileSystem".into()]);
        }
        let wildcard = fs_arn(&ctx.partition, &ctx.region, &account, "*");
        ctx.authorize("elasticfilesystem:CreateFileSystem", &wildcard, context.clone())?;
        if !tags.is_empty() {
            ctx.authorize("elasticfilesystem:TagResource", &wildcard, context)?;
        }

        let performance = input.performance_mode.clone().unwrap_or_else(|| "generalPurpose".into());
        let throughput = input.throughput_mode.clone().unwrap_or_else(|| "bursting".into());
        check_throughput(&throughput, input.provisioned_throughput_in_mibps)?;
        if performance == "maxIO" && throughput == "elastic" {
            return Err(bad_request("Max I/O performance mode is not supported with Elastic throughput mode."));
        }
        let (az_name, az_id) = match &input.availability_zone_name {
            Some(az) => {
                let zones = mws_ec2::availability_zones(&ctx.region);
                let Some((name, id)) = zones.into_iter().find(|(n, id)| n == az || id == az) else {
                    return Err(err(
                        "UnsupportedAvailabilityZone",
                        400,
                        format!("The Availability Zone {az} is not supported for One Zone file systems."),
                    ));
                };
                if performance == "maxIO" {
                    return Err(bad_request("One Zone file systems do not support the Max I/O performance mode."));
                }
                (Some(name), Some(id))
            }
            None => (None, None),
        };
        if input.kms_key_id.is_some() && !encrypted {
            return Err(bad_request("KmsKeyId can only be specified for encrypted file systems."));
        }
        let kms_key_id = if encrypted {
            Some(match &input.kms_key_id {
                Some(k) => self.resolve_kms_key(ctx, &account, k)?,
                None => self.kms().aws_managed_key(ctx, "elasticfilesystem"),
            })
        } else {
            None
        };

        let mut st = self.lock();
        let long = Self::long_ids(&st, &account, &ctx.region);
        let region = st.region(&account, &ctx.region);
        if let Some(existing) =
            region.file_systems.values().find(|f| f.description.creation_token == input.creation_token)
        {
            let id = existing.id().to_string();
            return Err(with_member(
                err(
                    "FileSystemAlreadyExists",
                    409,
                    format!("File system '{id}' already exists with creation token '{}'", input.creation_token),
                ),
                "FileSystemId",
                &id,
            ));
        }
        if region.file_systems.len() >= 1000 {
            return Err(err(
                "FileSystemLimitExceeded",
                403,
                "You have reached the maximum number of file systems allowed for this account.",
            ));
        }
        let id = new_id("fs", long);
        let description = t::FileSystemDescription {
            owner_id: account.clone(),
            creation_token: input.creation_token.clone(),
            file_system_id: id.clone(),
            file_system_arn: Some(fs_arn(&ctx.partition, &ctx.region, &account, &id)),
            creation_time: ctx.received_at,
            life_cycle_state: "creating".into(),
            name: name_tag(&tags),
            number_of_mount_targets: 0,
            size_in_bytes: Default::default(),
            performance_mode: performance,
            encrypted: Some(encrypted),
            kms_key_id,
            throughput_mode: Some(throughput),
            provisioned_throughput_in_mibps: input.provisioned_throughput_in_mibps,
            availability_zone_name: az_name.clone(),
            availability_zone_id: az_id,
            tags,
            file_system_protection: Some(t::FileSystemProtectionDescription {
                replication_overwrite_protection: Some("ENABLED".into()),
            }),
        };
        // One Zone file systems back up by default; Regional ones only when
        // asked.
        let backup = input.backup.unwrap_or(az_name.is_some());
        let fs = FileSystem {
            description,
            policy: None,
            backup: if backup { "ENABLED".into() } else { "DISABLED".into() },
            lifecycle: Vec::new(),
            throughput_changed_at: None,
            throughput_restricted_at: None,
            transition_ends: Some(ctx.received_at + crate::state::file_system_create()),
        };
        region.file_systems.insert(id.clone(), fs.clone());
        self.storage().create(&id);
        Ok(self.render_fs(&st, &account, &ctx.region, &fs, ctx.received_at))
    }

    /// A KMS key reference as an ARN, checked to be an enabled symmetric
    /// encryption key.
    fn resolve_kms_key(&self, ctx: &RequestContext, account: &str, key: &str) -> Result<String, ServiceError> {
        let arn = if key.starts_with("arn:") {
            key.to_string()
        } else if key.starts_with("alias/") {
            format!("arn:{}:kms:{}:{account}:{key}", ctx.partition, ctx.region)
        } else {
            format!("arn:{}:kms:{}:{account}:key/{key}", ctx.partition, ctx.region)
        };
        let invalid =
            || bad_request(format!("Invalid KMS key '{key}'. The key must be an enabled symmetric encryption key."));
        let k = self
            .kms()
            .key_for_service(&arn, "elasticfilesystem.amazonaws.com", &[], &ConditionContext::new())
            .map_err(|_| invalid())?;
        if k.key_state != "Enabled" || k.key_spec != "SYMMETRIC_DEFAULT" || k.key_usage != "ENCRYPT_DECRYPT" {
            return Err(invalid());
        }
        Ok(k.arn)
    }

    pub(crate) async fn describe_file_systems(
        &self,
        ctx: &RequestContext,
        input: t::DescribeFileSystemsRequest,
    ) -> Result<t::DescribeFileSystemsResponse, ServiceError> {
        let account = account_of(ctx);
        if input.file_system_id.is_some() && input.creation_token.is_some() {
            return Err(bad_request("Specify either a file system ID or a creation token, not both."));
        }
        if let Some(id) = &input.file_system_id {
            let fs = self.file_system(ctx, id)?;
            self.authorize_fs(ctx, "DescribeFileSystems", &fs, ConditionContext::new())?;
        } else {
            ctx.authorize(
                "elasticfilesystem:DescribeFileSystems",
                &fs_arn(&ctx.partition, &ctx.region, &account, "*"),
                ConditionContext::new(),
            )?;
        }
        let mut st = self.lock();
        let all: Vec<FileSystem> = st
            .region(&account, &ctx.region)
            .file_systems
            .values()
            .filter(|f| input.file_system_id.as_deref().is_none_or(|id| f.id() == fs_id(id)))
            .filter(|f| input.creation_token.as_deref().is_none_or(|t| f.description.creation_token == t))
            .cloned()
            .collect();
        let (items, next) = page(all, |f| f.id().to_string(), input.marker.as_deref(), input.max_items, 100)?;
        let file_systems =
            items.iter().map(|f| self.render_fs(&st, &account, &ctx.region, f, ctx.received_at)).collect();
        Ok(t::DescribeFileSystemsResponse { marker: input.marker, file_systems: Some(file_systems), next_marker: next })
    }

    pub(crate) async fn update_file_system(
        &self,
        ctx: &RequestContext,
        input: t::UpdateFileSystemRequest,
    ) -> Result<t::FileSystemDescription, ServiceError> {
        let account = account_of(ctx);
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "UpdateFileSystem", &fs, ConditionContext::new())?;
        if fs.description.life_cycle_state != "available" {
            return Err(wrong_state(fs.id(), &fs.description.life_cycle_state));
        }
        let current = fs.description.throughput_mode.clone().unwrap_or_else(|| "bursting".into());
        let mode = input.throughput_mode.clone().unwrap_or_else(|| current.clone());
        let mibps = match (&input.throughput_mode, input.provisioned_throughput_in_mibps) {
            (_, Some(v)) => Some(v),
            (Some(m), None) if m != "provisioned" => None,
            _ => fs.description.provisioned_throughput_in_mibps,
        };
        check_throughput(&mode, mibps)?;
        if mode == "elastic" && fs.description.performance_mode == "maxIO" {
            return Err(bad_request("Max I/O performance mode is not supported with Elastic throughput mode."));
        }
        let old_mibps = fs.description.provisioned_throughput_in_mibps;
        let changed = mode != current || mibps != old_mibps;
        // Changing the mode, or decreasing provisioned throughput, must
        // wait 24 hours after the last mode change or decrease; increases
        // are allowed at any time.
        let decrease = mode == "provisioned" && current == "provisioned" && mibps < old_mibps;
        if mode != current || decrease {
            if let Some(at) = fs.throughput_restricted_at {
                let until = at + chrono::Duration::hours(24);
                if ctx.received_at < until {
                    return Err(err(
                        "TooManyRequests",
                        429,
                        format!(
                            "You have reached the maximum number of throughput mode changes or provisioned throughput value decreases. Wait until {} UTC to retry.",
                            until.format("%Y-%m-%dT%H:%M:%SZ")
                        ),
                    ));
                }
            }
        }
        let restricts = mode != current || decrease;
        let mut st = self.lock();
        let f = st.region(&account, &ctx.region).file_systems.get_mut(fs.id()).ok_or_else(|| fs_not_found(fs.id()))?;
        if changed {
            f.description.throughput_mode = Some(mode);
            f.description.provisioned_throughput_in_mibps = mibps;
            f.throughput_changed_at = Some(ctx.received_at);
            if restricts {
                f.throughput_restricted_at = Some(ctx.received_at);
            }
        }
        let f = f.clone();
        let mut out = self.render_fs(&st, &account, &ctx.region, &f, ctx.received_at);
        if changed {
            out.life_cycle_state = "updating".into();
        }
        Ok(out)
    }

    pub(crate) async fn update_file_system_protection(
        &self,
        ctx: &RequestContext,
        input: t::UpdateFileSystemProtectionRequest,
    ) -> Result<t::FileSystemProtectionDescription, ServiceError> {
        let account = account_of(ctx);
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "UpdateFileSystemProtection", &fs, ConditionContext::new())?;
        let mut st = self.lock();
        let replicating = st.replications.values().any(|r| r.destinations.iter().any(|d| d.file_system_id == fs.id()));
        let f = st.region(&account, &ctx.region).file_systems.get_mut(fs.id()).ok_or_else(|| fs_not_found(fs.id()))?;
        let protection = f.description.file_system_protection.get_or_insert_with(Default::default);
        if let Some(p) = input.replication_overwrite_protection {
            if p == "REPLICATING" {
                return Err(bad_request("ReplicationOverwriteProtection can only be set to ENABLED or DISABLED."));
            }
            if replicating {
                return Err(err(
                    "ReplicationAlreadyExists",
                    409,
                    format!("File system '{}' is a replication destination; its protection cannot change.", fs.id()),
                ));
            }
            protection.replication_overwrite_protection = Some(p);
        }
        Ok(protection.clone())
    }

    pub(crate) async fn delete_file_system(
        &self,
        ctx: &RequestContext,
        input: t::DeleteFileSystemRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "DeleteFileSystem", &fs, ConditionContext::new())?;
        let id = fs.id().to_string();
        let mut st = self.lock();
        if st.replication_of(&id).is_some() {
            return Err(err(
                "FileSystemInUse",
                409,
                format!("File system '{id}' is part of a replication configuration. Delete the replication configuration first."),
            ));
        }
        let region = st.region(&account, &ctx.region);
        if region.mount_targets.values().any(|m| m.description.file_system_id == id) {
            return Err(err(
                "FileSystemInUse",
                409,
                format!("File system '{id}' has mount targets and cannot be deleted."),
            ));
        }
        // `deleting` for a moment, then gone (see `State::settle`).
        if let Some(f) = region.file_systems.get_mut(&id).filter(|f| f.description.life_cycle_state != "deleting") {
            f.description.life_cycle_state = "deleting".into();
            f.transition_ends = Some(ctx.received_at + crate::state::file_system_delete());
        }
        Ok(())
    }
}

fn check_throughput(mode: &str, mibps: Option<f64>) -> Result<(), ServiceError> {
    match (mode, mibps) {
        ("provisioned", None) => {
            Err(bad_request("ProvisionedThroughputInMibps is required when ThroughputMode is provisioned."))
        }
        ("provisioned", Some(v)) if v > 3414.0 => {
            Err(err("ThroughputLimitExceeded", 400, "The requested throughput exceeds the limit for this file system."))
        }
        (m, Some(_)) if m != "provisioned" => {
            Err(bad_request("ProvisionedThroughputInMibps can only be specified when ThroughputMode is provisioned."))
        }
        _ => Ok(()),
    }
}
