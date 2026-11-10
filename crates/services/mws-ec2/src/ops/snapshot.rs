//! EBS snapshots (create, copy, share, archive, lock, fast restore) and
//! the account's EBS settings (encryption by default, the default KMS key,
//! block public access for snapshots), plus root volume replacement.

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::ebs::{default_kms_key, snapshot_arn};
use crate::generated::types as t;
use crate::state::{RegionState, State};
use crate::util::{
    arn, b, err, invalid_parameter, new_id, paginate, request_tag_context, resource_tag_context, s, some_tags,
    tags_for, Filters, Kind,
};
use crate::volumes::VolumeJob;
use crate::{account_of, catalog, Ec2};

fn snapshot_filter(snap: &t::Snapshot, name: &str) -> Option<Vec<String>> {
    Some(match name {
        "snapshot-id" => s(&snap.snapshot_id),
        "volume-id" => s(&snap.volume_id),
        "status" => s(&snap.state),
        "owner-id" => s(&snap.owner_id),
        "owner-alias" => s(&snap.owner_alias),
        "description" => s(&snap.description),
        "progress" => s(&snap.progress),
        "encrypted" => b(snap.encrypted),
        "volume-size" => snap.volume_size.map(|x| x.to_string()).into_iter().collect(),
        "storage-tier" => s(&snap.storage_tier),
        "start-time" => snap.start_time.map(|t| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()).into_iter().collect(),
        "kms-key-id" => s(&snap.kms_key_id),
        "transfer-type" => s(&snap.transfer_type),
        _ => return None,
    })
}

fn may_restore(r: &RegionState, id: &str, account: &str) -> bool {
    r.snapshot_permissions.get(id).is_some_and(|p| p.public || p.users.iter().any(|u| u == account))
}

/// A snapshot the volume of a new snapshot is made from: the volume's
/// fields copied over.
fn new_snapshot(
    account: &str,
    volume: &t::Volume,
    description: String,
    tags: Vec<t::Tag>,
    now: chrono::DateTime<chrono::Utc>,
) -> t::Snapshot {
    t::Snapshot {
        snapshot_id: Some(new_id("snap")),
        volume_id: volume.volume_id.clone(),
        state: Some("completed".into()),
        start_time: Some(now),
        completion_time: Some(now),
        progress: Some("100%".into()),
        owner_id: Some(account.to_string()),
        description: Some(description),
        volume_size: volume.size,
        encrypted: volume.encrypted,
        kms_key_id: volume.kms_key_id.clone(),
        storage_tier: Some("standard".into()),
        full_snapshot_size_in_bytes: Some(0),
        tags: some_tags(tags),
        ..Default::default()
    }
}

/// How a just-created snapshot is first reported.
fn pending(mut snap: t::Snapshot) -> t::Snapshot {
    snap.state = Some("pending".into());
    snap.progress = Some(String::new());
    snap.completion_time = None;
    snap.storage_tier = None;
    snap.full_snapshot_size_in_bytes = None;
    snap
}

impl Ec2 {
    /// A snapshot in the caller's Region: their own, or one another account
    /// shares with them (or publicly). Returns the owner and the snapshot.
    pub(crate) fn find_snapshot(&self, ctx: &RequestContext, id: &str) -> Result<(String, t::Snapshot), ServiceError> {
        let account = account_of(ctx);
        if let Some(snap) = self.with_region(ctx, |r| r.snapshots.get(id).cloned()) {
            return Ok((account, snap));
        }
        let suffix = format!("/{}", ctx.region);
        let state = self.lock();
        for (key, r) in &state.regions {
            if !key.ends_with(&suffix) {
                continue;
            }
            if let Some(snap) = r.snapshots.get(id) {
                if may_restore(r, id, &account) {
                    return Ok((key.split('/').next().unwrap_or_default().to_string(), snap.clone()));
                }
            }
        }
        Err(Kind::Snapshot.not_found(id))
    }

    fn own_snapshot(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
    ) -> Result<t::Snapshot, ServiceError> {
        Kind::Snapshot.check(id)?;
        let snap =
            self.with_region(ctx, |r| r.snapshots.get(id).cloned()).ok_or_else(|| Kind::Snapshot.not_found(id))?;
        self.authorize_known(
            ctx,
            action,
            &[(snapshot_arn(ctx, id), resource_tag_context(snap.tags.as_ref()))],
            dry_run,
        )?;
        Ok(snap)
    }

    pub(crate) fn create_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateSnapshotRequest,
    ) -> Result<t::Snapshot, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "snapshot", &["snapshot"])?;
        Kind::Volume.check(&input.volume_id)?;
        let v = self
            .with_region(ctx, |r| r.volumes.get(&input.volume_id).cloned())
            .ok_or_else(|| Kind::Volume.not_found(&input.volume_id))?;
        self.authorize_known(
            ctx,
            "CreateSnapshot",
            &[
                (arn(ctx, &account, &format!("volume/{}", input.volume_id)), resource_tag_context(v.tags.as_ref())),
                (snapshot_arn(ctx, "*"), request_tag_context(&tags)),
            ],
            input.dry_run,
        )?;
        if let Some(d) = &input.description {
            if d.chars().count() > 255 {
                return Err(invalid_parameter("Value for parameter description is invalid. Description is too long."));
            }
        }
        let snap = new_snapshot(&account, &v, input.description.clone().unwrap_or_default(), tags, ctx.received_at);
        let id = snap.snapshot_id.clone().unwrap_or_default();
        self.with_region(ctx, |r| r.snapshots.insert(id.clone(), snap.clone()));
        self.volume_job(VolumeJob::Snapshot { volume_id: input.volume_id.clone(), snapshot_id: id });
        Ok(pending(snap))
    }

    pub(crate) fn create_snapshots_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateSnapshotsRequest,
    ) -> Result<t::CreateSnapshotsResult, ServiceError> {
        let account = account_of(ctx);
        let spec = &input.instance_specification;
        Kind::Instance.check(&spec.instance_id)?;
        let tags = tags_for(&input.tag_specifications, "snapshot", &["snapshot"])?;
        let (inst_tags, root, volumes) = self
            .with_region(ctx, |r| {
                r.instances.get(&spec.instance_id).map(|rec| {
                    let vols: Vec<t::Volume> = r
                        .volumes
                        .values()
                        .filter(|v| {
                            v.attachments
                                .iter()
                                .flatten()
                                .any(|a| a.instance_id.as_deref() == Some(spec.instance_id.as_str()))
                        })
                        .cloned()
                        .collect();
                    (rec.instance.tags.clone(), rec.instance.root_device_name.clone(), vols)
                })
            })
            .ok_or_else(|| Kind::Instance.not_found(&spec.instance_id))?;
        let excluded = spec.exclude_data_volume_ids.clone().unwrap_or_default();
        for id in &excluded {
            Kind::Volume.check(id)?;
            if !volumes.iter().any(|v| v.volume_id.as_deref() == Some(id.as_str())) {
                return Err(invalid_parameter(format!(
                    "The volume {id} is not attached to instance {}",
                    spec.instance_id
                )));
            }
        }
        let chosen: Vec<t::Volume> = volumes
            .into_iter()
            .filter(|v| {
                let is_root = v
                    .attachments
                    .iter()
                    .flatten()
                    .any(|a| a.instance_id.as_deref() == Some(spec.instance_id.as_str()) && a.device == root);
                let id = v.volume_id.clone().unwrap_or_default();
                if is_root {
                    spec.exclude_boot_volume != Some(true)
                } else {
                    !excluded.contains(&id)
                }
            })
            .collect();
        let mut resources = vec![
            (arn(ctx, &account, &format!("instance/{}", spec.instance_id)), resource_tag_context(inst_tags.as_ref())),
            (snapshot_arn(ctx, "*"), request_tag_context(&tags)),
        ];
        for v in &chosen {
            resources.push((
                arn(ctx, &account, &format!("volume/{}", v.volume_id.clone().unwrap_or_default())),
                resource_tag_context(v.tags.as_ref()),
            ));
        }
        self.authorize_known(ctx, "CreateSnapshots", &resources, input.dry_run)?;
        let now = ctx.received_at;
        let mut out = Vec::new();
        let mut jobs = Vec::new();
        self.with_region(ctx, |r| {
            for v in &chosen {
                let mut snap_tags = tags.clone();
                if input.copy_tags_from_source.as_deref() == Some("volume") {
                    for tag in v.tags.iter().flatten() {
                        if !snap_tags.iter().any(|x| x.key == tag.key) {
                            snap_tags.push(tag.clone());
                        }
                    }
                }
                let snap = new_snapshot(&account, v, input.description.clone().unwrap_or_default(), snap_tags, now);
                let id = snap.snapshot_id.clone().unwrap_or_default();
                r.snapshots.insert(id.clone(), snap.clone());
                jobs.push(VolumeJob::Snapshot { volume_id: v.volume_id.clone().unwrap_or_default(), snapshot_id: id });
                out.push(t::SnapshotInfo {
                    description: snap.description.clone(),
                    tags: snap.tags.clone(),
                    encrypted: snap.encrypted,
                    volume_id: snap.volume_id.clone(),
                    state: Some("pending".into()),
                    volume_size: snap.volume_size,
                    start_time: snap.start_time,
                    progress: Some(String::new()),
                    owner_id: snap.owner_id.clone(),
                    snapshot_id: snap.snapshot_id.clone(),
                    ..Default::default()
                });
            }
        });
        for job in jobs {
            self.volume_job(job);
        }
        Ok(t::CreateSnapshotsResult { snapshots: Some(out) })
    }

    pub(crate) fn copy_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::CopySnapshotRequest,
    ) -> Result<t::CopySnapshotResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "snapshot", &["snapshot"])?;
        Kind::Snapshot.check(&input.source_snapshot_id)?;
        if !catalog::REGIONS.contains(&input.source_region.as_str()) {
            return Err(invalid_parameter(format!("Invalid region: {}", input.source_region)));
        }
        let mut source_ctx = ctx.clone();
        source_ctx.region = input.source_region.clone();
        let (_, source) = self.find_snapshot(&source_ctx, &input.source_snapshot_id)?;
        if source.state.as_deref() != Some("completed") {
            return Err(err(
                "IncorrectState",
                format!("Snapshot {} is not in a completed state.", input.source_snapshot_id),
            ));
        }
        self.authorize_known(
            ctx,
            "CopySnapshot",
            &[
                (snapshot_arn(&source_ctx, &input.source_snapshot_id), resource_tag_context(source.tags.as_ref())),
                (snapshot_arn(ctx, "*"), request_tag_context(&tags)),
            ],
            input.dry_run,
        )?;
        if input.kms_key_id.is_some() && input.encrypted != Some(true) && source.encrypted != Some(true) {
            return Err(invalid_parameter("The parameter KmsKeyId requires the parameter Encrypted to be set."));
        }
        let now = ctx.received_at;
        let id = new_id("snap");
        let description = input
            .description
            .clone()
            .unwrap_or_else(|| format!("[Copied {} from {}]", input.source_snapshot_id, input.source_region));
        self.with_region(ctx, |r| {
            let encrypted =
                input.encrypted == Some(true) || source.encrypted == Some(true) || r.ebs_encryption_by_default;
            let kms_key_id = encrypted.then(|| {
                input
                    .kms_key_id
                    .clone()
                    .or_else(|| (input.source_region == ctx.region).then(|| source.kms_key_id.clone()).flatten())
                    .unwrap_or_else(|| default_kms_key(ctx, &account, r))
            });
            let snap = t::Snapshot {
                snapshot_id: Some(id.clone()),
                // Copies name a placeholder volume, as EC2 reports them.
                volume_id: Some("vol-ffffffff".into()),
                state: Some("completed".into()),
                start_time: Some(now),
                completion_time: Some(now),
                progress: Some("100%".into()),
                owner_id: Some(account.clone()),
                description: Some(description.clone()),
                volume_size: source.volume_size,
                encrypted: Some(encrypted),
                kms_key_id,
                storage_tier: Some("standard".into()),
                full_snapshot_size_in_bytes: source.full_snapshot_size_in_bytes,
                tags: some_tags(tags.clone()),
                transfer_type: Some("standard".into()),
                ..Default::default()
            };
            r.snapshots.insert(id.clone(), snap);
        });
        self.volume_job(VolumeJob::CopySnapshot {
            source_id: input.source_snapshot_id.clone(),
            snapshot_id: id.clone(),
        });
        Ok(t::CopySnapshotResult { snapshot_id: Some(id), tags: some_tags(tags) })
    }

    pub(crate) fn delete_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteSnapshotRequest,
    ) -> Result<(), ServiceError> {
        self.own_snapshot(ctx, "DeleteSnapshot", &input.snapshot_id, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let in_use =
                r.images.values().find(|i| {
                    i.image.block_device_mappings.iter().flatten().any(|b| {
                        b.ebs.as_ref().and_then(|e| e.snapshot_id.as_deref()) == Some(input.snapshot_id.as_str())
                    })
                });
            if let Some(img) = in_use {
                return Err(err(
                    "InvalidSnapshot.InUse",
                    format!(
                        "The snapshot {} is currently in use by {}",
                        input.snapshot_id,
                        img.image.image_id.clone().unwrap_or_default()
                    ),
                ));
            }
            if let Some(lock) = r.snapshot_locks.get(&input.snapshot_id) {
                let active = lock.lock_expires_on.is_none_or(|e| now < e);
                if active {
                    return Err(err(
                        "SnapshotLocked",
                        format!(
                            "The snapshot {} is locked in {} mode and can't be deleted.",
                            input.snapshot_id,
                            lock.lock_state.clone().unwrap_or_default()
                        ),
                    ));
                }
            }
            r.snapshots.remove(&input.snapshot_id);
            r.snapshot_permissions.remove(&input.snapshot_id);
            r.snapshot_locks.remove(&input.snapshot_id);
            r.snapshot_tiers.remove(&input.snapshot_id);
            r.fast_snapshot_restores.retain(|k, _| !k.starts_with(&format!("{}/", input.snapshot_id)));
            Ok(())
        })?;
        self.volume_job(VolumeJob::DeleteSnapshot(input.snapshot_id.clone()));
        Ok(())
    }

    pub(crate) fn describe_snapshots_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSnapshotsRequest,
    ) -> Result<t::DescribeSnapshotsResult, ServiceError> {
        self.authorize_known(ctx, "DescribeSnapshots", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let account = account_of(ctx);
        let filters = Filters::new(&input.filters);
        let ids = input.snapshot_ids.clone().unwrap_or_default();
        let owners = input.owner_ids.clone().unwrap_or_default();
        let restorable_by = input.restorable_by_user_ids.clone().unwrap_or_default();
        for id in &ids {
            Kind::Snapshot.check(id)?;
        }
        self.with_region(ctx, |_| ());
        let suffix = format!("/{}", ctx.region);
        let state = self.lock();
        // Own snapshots, then those others share with the caller or publicly.
        let mut candidates: Vec<(String, t::Snapshot, bool)> = Vec::new();
        for (key, r) in &state.regions {
            if !key.ends_with(&suffix) {
                continue;
            }
            let owner = key.split('/').next().unwrap_or_default().to_string();
            for (id, snap) in &r.snapshots {
                let public = r.snapshot_permissions.get(id).is_some_and(|p| p.public);
                if owner == account || may_restore(r, id, &account) {
                    candidates.push((owner.clone(), snap.clone(), public));
                }
            }
        }
        for id in &ids {
            if !candidates.iter().any(|(_, s, _)| s.snapshot_id.as_deref() == Some(id.as_str())) {
                return Err(Kind::Snapshot.not_found(id));
            }
        }
        let mut out = Vec::new();
        for (owner, snap, public) in candidates {
            if !ids.is_empty() && !ids.contains(snap.snapshot_id.as_ref().unwrap()) {
                continue;
            }
            if !owners.is_empty() && !owners.iter().any(|o| (o == "self" && owner == account) || o == &owner) {
                continue;
            }
            if !restorable_by.is_empty() {
                let key = State::key(&owner, &ctx.region);
                let id = snap.snapshot_id.clone().unwrap_or_default();
                let ok = restorable_by.iter().any(|u| {
                    let u = if u == "self" { account.as_str() } else { u.as_str() };
                    u == owner
                        || public
                        || state.regions.get(&key).is_some_and(|r| {
                            r.snapshot_permissions.get(&id).is_some_and(|p| p.users.iter().any(|x| x == u))
                        })
                });
                if !ok {
                    continue;
                }
            }
            if filters.matches(snap.tags.as_ref(), |n| snapshot_filter(&snap, n))? {
                out.push(snap);
            }
        }
        drop(state);
        let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribeSnapshotsResult { snapshots: Some(items), next_token })
    }

    pub(crate) fn describe_snapshot_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSnapshotAttributeRequest,
    ) -> Result<t::DescribeSnapshotAttributeResult, ServiceError> {
        self.own_snapshot(ctx, "DescribeSnapshotAttribute", &input.snapshot_id, input.dry_run)?;
        let mut out =
            t::DescribeSnapshotAttributeResult { snapshot_id: Some(input.snapshot_id.clone()), ..Default::default() };
        match input.attribute.as_str() {
            "createVolumePermission" => {
                let perms = self.with_region(ctx, |r| r.snapshot_permissions.get(&input.snapshot_id).cloned());
                let perms = perms.unwrap_or_default();
                let mut list: Vec<t::CreateVolumePermission> = perms
                    .users
                    .iter()
                    .map(|u| t::CreateVolumePermission { user_id: Some(u.clone()), group: None })
                    .collect();
                if perms.public {
                    list.push(t::CreateVolumePermission { user_id: None, group: Some("all".into()) });
                }
                out.create_volume_permissions = Some(list);
            }
            "productCodes" => out.product_codes = Some(Vec::new()),
            other => {
                return Err(invalid_parameter(format!(
                    "Value ({other}) for parameter attribute is invalid. Unknown attribute."
                )))
            }
        }
        Ok(out)
    }

    pub(crate) fn modify_snapshot_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifySnapshotAttributeRequest,
    ) -> Result<(), ServiceError> {
        let snap = self.own_snapshot(ctx, "ModifySnapshotAttribute", &input.snapshot_id, input.dry_run)?;
        if let Some(a) = input.attribute.as_deref() {
            if a != "createVolumePermission" {
                return Err(invalid_parameter(format!(
                    "Value ({a}) for parameter attribute is invalid. Only createVolumePermission can be modified."
                )));
            }
        }
        let mut add: Vec<t::CreateVolumePermission> = Vec::new();
        let mut remove: Vec<t::CreateVolumePermission> = Vec::new();
        if let Some(m) = &input.create_volume_permission {
            add.extend(m.add.iter().flatten().cloned());
            remove.extend(m.remove.iter().flatten().cloned());
        }
        let listed: Vec<t::CreateVolumePermission> = input
            .user_ids
            .iter()
            .flatten()
            .map(|u| t::CreateVolumePermission { user_id: Some(u.clone()), group: None })
            .chain(
                input
                    .group_names
                    .iter()
                    .flatten()
                    .map(|g| t::CreateVolumePermission { user_id: None, group: Some(g.clone()) }),
            )
            .collect();
        match input.operation_type.as_deref() {
            Some("add") => add.extend(listed),
            Some("remove") => remove.extend(listed),
            None if listed.is_empty() => {}
            None => return Err(err("MissingParameter", "The request must contain the parameter operationType")),
            Some(o) => return Err(invalid_parameter(format!("Value ({o}) for parameter operationType is invalid."))),
        }
        if add.is_empty() && remove.is_empty() {
            return Err(err("MissingParameter", "The request must contain the parameter createVolumePermission"));
        }
        for p in add.iter().chain(&remove) {
            if let Some(g) = &p.group {
                if g != "all" {
                    return Err(invalid_parameter(format!("Value ({g}) for parameter group is invalid.")));
                }
            }
            if let Some(u) = &p.user_id {
                if u.len() != 12 || !u.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid_parameter(format!("Value ({u}) for parameter userId is invalid.")));
                }
            }
        }
        let going_public = add.iter().any(|p| p.group.as_deref() == Some("all"));
        if going_public && snap.encrypted == Some(true) {
            return Err(err("OperationNotPermitted", "Encrypted snapshots with EBS default key cannot be shared"));
        }
        self.with_region(ctx, |r| {
            if going_public && r.snapshot_block_public_access.is_some() {
                return Err(err(
                    "OperationNotPermitted",
                    "Block public access for snapshots is enabled in this Region, so snapshots can't be shared publicly.",
                ));
            }
            let perms = r.snapshot_permissions.entry(input.snapshot_id.clone()).or_default();
            for p in &add {
                if p.group.is_some() {
                    perms.public = true;
                } else if let Some(u) = &p.user_id {
                    if !perms.users.contains(u) {
                        perms.users.push(u.clone());
                    }
                }
            }
            for p in &remove {
                if p.group.is_some() {
                    perms.public = false;
                } else if let Some(u) = &p.user_id {
                    perms.users.retain(|x| x != u);
                }
            }
            Ok(())
        })
    }

    pub(crate) fn reset_snapshot_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ResetSnapshotAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.own_snapshot(ctx, "ResetSnapshotAttribute", &input.snapshot_id, input.dry_run)?;
        if input.attribute != "createVolumePermission" {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter attribute is invalid. Only createVolumePermission can be reset.",
                input.attribute
            )));
        }
        self.with_region(ctx, |r| r.snapshot_permissions.remove(&input.snapshot_id));
        Ok(())
    }

    // ---- storage tiers ---------------------------------------------------------------------

    fn tier_status(snap: &t::Snapshot) -> t::SnapshotTierStatus {
        t::SnapshotTierStatus {
            snapshot_id: snap.snapshot_id.clone(),
            volume_id: snap.volume_id.clone(),
            status: snap.state.clone(),
            owner_id: snap.owner_id.clone(),
            tags: snap.tags.clone(),
            storage_tier: snap.storage_tier.clone(),
            ..Default::default()
        }
    }

    pub(crate) fn modify_snapshot_tier_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifySnapshotTierRequest,
    ) -> Result<t::ModifySnapshotTierResult, ServiceError> {
        let snap = self.own_snapshot(ctx, "ModifySnapshotTier", &input.snapshot_id, input.dry_run)?;
        let tier = input.storage_tier.clone().unwrap_or_else(|| "archive".into());
        if tier != "archive" {
            return Err(invalid_parameter(format!("Value ({tier}) for parameter storageTier is invalid.")));
        }
        if snap.storage_tier.as_deref() == Some("archive") {
            return Err(err(
                "IncorrectState",
                format!("The snapshot {} is already in the archive tier.", input.snapshot_id),
            ));
        }
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let snap = r.snapshots.get_mut(&input.snapshot_id).expect("checked");
            snap.storage_tier = Some("archive".into());
            let mut st = Self::tier_status(snap);
            st.last_tiering_start_time = Some(now);
            st.last_tiering_progress = Some(100);
            st.last_tiering_operation_status = Some("archival-completed".into());
            st.archival_complete_time = Some(now);
            r.snapshot_tiers.insert(input.snapshot_id.clone(), st);
        });
        Ok(t::ModifySnapshotTierResult { snapshot_id: Some(input.snapshot_id), tiering_start_time: Some(now) })
    }

    pub(crate) fn restore_snapshot_tier_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreSnapshotTierRequest,
    ) -> Result<t::RestoreSnapshotTierResult, ServiceError> {
        let snap = self.own_snapshot(ctx, "RestoreSnapshotTier", &input.snapshot_id, input.dry_run)?;
        if snap.storage_tier.as_deref() != Some("archive") {
            return Err(err(
                "IncorrectState",
                format!("The snapshot {} is not in the archive tier.", input.snapshot_id),
            ));
        }
        let permanent = input.permanent_restore == Some(true);
        if permanent == input.temporary_restore_days.is_some() {
            return Err(err(
                "InvalidParameterCombination",
                "Specify either TemporaryRestoreDays or PermanentRestore, but not both.",
            ));
        }
        let now = ctx.received_at;
        let days = input.temporary_restore_days;
        self.with_region(ctx, |r| {
            let snap = r.snapshots.get_mut(&input.snapshot_id).expect("checked");
            snap.storage_tier = Some("standard".into());
            snap.restore_expiry_time = days.map(|d| now + Duration::days(d as i64));
            let mut st = Self::tier_status(snap);
            st.last_tiering_start_time = Some(now);
            st.last_tiering_progress = Some(100);
            st.last_tiering_operation_status =
                Some(if permanent { "permanent-restore-completed" } else { "temporary-restore-completed" }.into());
            st.restore_expiry_time = snap.restore_expiry_time;
            r.snapshot_tiers.insert(input.snapshot_id.clone(), st);
        });
        Ok(t::RestoreSnapshotTierResult {
            snapshot_id: Some(input.snapshot_id),
            restore_start_time: Some(now),
            restore_duration: days,
            is_permanent_restore: Some(permanent),
        })
    }

    pub(crate) fn describe_snapshot_tier_status_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSnapshotTierStatusRequest,
    ) -> Result<t::DescribeSnapshotTierStatusResult, ServiceError> {
        self.authorize_known(
            ctx,
            "DescribeSnapshotTierStatus",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for st in r.snapshot_tiers.values() {
                let ok = filters.matches(None, |n| {
                    Some(match n {
                        "snapshot-id" => s(&st.snapshot_id),
                        "volume-id" => s(&st.volume_id),
                        "last-tiering-operation" => s(&st.last_tiering_operation_status),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(st.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeSnapshotTierStatusResult { snapshot_tier_statuses: Some(items), next_token })
        })
    }

    // ---- locks -------------------------------------------------------------------------------

    pub(crate) fn lock_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::LockSnapshotRequest,
    ) -> Result<t::LockSnapshotResult, ServiceError> {
        self.own_snapshot(ctx, "LockSnapshot", &input.snapshot_id, input.dry_run)?;
        let now = ctx.received_at;
        if !matches!(input.lock_mode.as_str(), "compliance" | "governance") {
            return Err(invalid_parameter(format!("Value ({}) for parameter lockMode is invalid.", input.lock_mode)));
        }
        if input.lock_duration.is_some() == input.expiration_date.is_some() {
            return Err(err(
                "InvalidParameterCombination",
                "Specify either LockDuration or ExpirationDate, but not both.",
            ));
        }
        if let Some(d) = input.lock_duration {
            if !(1..=36500).contains(&d) {
                return Err(invalid_parameter("The lock duration must be between 1 and 36500 days."));
            }
        }
        if input.cool_off_period.is_some() && input.lock_mode != "compliance" {
            return Err(err(
                "InvalidParameterCombination",
                "A cooling-off period can be specified only for snapshots locked in compliance mode.",
            ));
        }
        let expires = match (input.lock_duration, input.expiration_date) {
            (Some(d), _) => now + Duration::days(d as i64),
            (_, Some(e)) => e,
            _ => unreachable!("checked"),
        };
        self.with_region(ctx, |r| {
            if let Some(existing) = r.snapshot_locks.get(&input.snapshot_id) {
                let cooling = existing.cool_off_period_expires_on.is_some_and(|c| now < c);
                if existing.lock_state.as_deref() == Some("compliance") && !cooling {
                    return Err(err(
                        "IncorrectState",
                        format!(
                            "The snapshot {} is locked in compliance mode and its lock can't be modified.",
                            input.snapshot_id
                        ),
                    ));
                }
            }
            let cool = input.cool_off_period.map(|h| now + Duration::hours(h as i64));
            let state = match (input.lock_mode.as_str(), cool) {
                ("compliance", Some(_)) => "compliance-cooloff",
                (m, _) => m,
            };
            let info = t::LockedSnapshotsInfo {
                owner_id: Some(account_of(ctx)),
                snapshot_id: Some(input.snapshot_id.clone()),
                lock_state: Some(state.to_string()),
                lock_duration: input.lock_duration,
                cool_off_period: input.cool_off_period,
                cool_off_period_expires_on: cool,
                lock_created_on: Some(now),
                lock_duration_start_time: Some(now),
                lock_expires_on: Some(expires),
            };
            r.snapshot_locks.insert(input.snapshot_id.clone(), info.clone());
            Ok(t::LockSnapshotResult {
                snapshot_id: info.snapshot_id,
                lock_state: info.lock_state,
                lock_duration: info.lock_duration,
                cool_off_period: info.cool_off_period,
                cool_off_period_expires_on: info.cool_off_period_expires_on,
                lock_created_on: info.lock_created_on,
                lock_expires_on: info.lock_expires_on,
                lock_duration_start_time: info.lock_duration_start_time,
            })
        })
    }

    pub(crate) fn unlock_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::UnlockSnapshotRequest,
    ) -> Result<t::UnlockSnapshotResult, ServiceError> {
        self.own_snapshot(ctx, "UnlockSnapshot", &input.snapshot_id, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let Some(lock) = r.snapshot_locks.get(&input.snapshot_id) else {
                return Err(err("IncorrectState", format!("The snapshot {} is not locked.", input.snapshot_id)));
            };
            let cooling = lock.cool_off_period_expires_on.is_some_and(|c| now < c);
            let expired = lock.lock_expires_on.is_some_and(|e| now >= e);
            if lock.lock_state.as_deref().is_some_and(|s| s.starts_with("compliance")) && !cooling && !expired {
                return Err(err(
                    "IncorrectState",
                    format!("The snapshot {} is locked in compliance mode and can't be unlocked.", input.snapshot_id),
                ));
            }
            r.snapshot_locks.remove(&input.snapshot_id);
            Ok(t::UnlockSnapshotResult { snapshot_id: Some(input.snapshot_id.clone()) })
        })
    }

    pub(crate) fn describe_locked_snapshots_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLockedSnapshotsRequest,
    ) -> Result<t::DescribeLockedSnapshotsResult, ServiceError> {
        self.authorize_known(ctx, "DescribeLockedSnapshots", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.snapshot_ids.clone().unwrap_or_default();
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            Kind::Snapshot.check_all(&ids, |id| r.snapshots.contains_key(id))?;
            let mut out = Vec::new();
            for (id, lock) in &r.snapshot_locks {
                if !ids.is_empty() && !ids.contains(id) {
                    continue;
                }
                let mut lock = lock.clone();
                if lock.lock_expires_on.is_some_and(|e| now >= e) {
                    lock.lock_state = Some("expired".into());
                } else if lock.lock_state.as_deref() == Some("compliance-cooloff")
                    && lock.cool_off_period_expires_on.is_some_and(|c| now >= c)
                {
                    lock.lock_state = Some("compliance".into());
                }
                let ok = filters.matches(None, |n| match n {
                    "lock-state" => Some(s(&lock.lock_state)),
                    _ => None,
                })?;
                if ok {
                    out.push(lock);
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeLockedSnapshotsResult { snapshots: Some(items), next_token })
        })
    }

    // ---- fast snapshot restores ---------------------------------------------------------------

    fn fsr_zones(
        ctx: &RequestContext,
        names: &Option<Vec<String>>,
        ids: &Option<Vec<String>>,
    ) -> Result<Vec<String>, ServiceError> {
        let mut zones: Vec<String> = names.clone().unwrap_or_default();
        for id in ids.iter().flatten() {
            zones.push(
                catalog::zone_name(&ctx.region, id)
                    .ok_or_else(|| invalid_parameter(format!("Invalid availability zone ID: [{id}]")))?,
            );
        }
        if zones.is_empty() {
            return Err(err("MissingParameter", "The request must contain the parameter AvailabilityZones"));
        }
        for z in &zones {
            if !catalog::zones(&ctx.region).iter().any(|(n, _)| n == z) {
                return Err(invalid_parameter(format!("Invalid availability zone: [{z}]")));
            }
        }
        Ok(zones)
    }

    pub(crate) fn enable_fast_snapshot_restores_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableFastSnapshotRestoresRequest,
    ) -> Result<t::EnableFastSnapshotRestoresResult, ServiceError> {
        let zones = Self::fsr_zones(ctx, &input.availability_zones, &input.availability_zone_ids)?;
        let account = account_of(ctx);
        let mut resources = Vec::new();
        for id in &input.source_snapshot_ids {
            Kind::Snapshot.check(id)?;
            resources.push((snapshot_arn(ctx, id), ConditionContext::new()));
        }
        self.authorize_known(ctx, "EnableFastSnapshotRestores", &resources, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let mut ok = Vec::new();
            let mut failed = Vec::new();
            for id in &input.source_snapshot_ids {
                if !r.snapshots.contains_key(id) {
                    failed.push(t::EnableFastSnapshotRestoreErrorItem {
                        snapshot_id: Some(id.clone()),
                        fast_snapshot_restore_state_errors: Some(
                            zones
                                .iter()
                                .map(|z| t::EnableFastSnapshotRestoreStateErrorItem {
                                    availability_zone: Some(z.clone()),
                                    availability_zone_id: catalog::zone_id(&ctx.region, z),
                                    error: Some(t::EnableFastSnapshotRestoreStateError {
                                        code: Some("InvalidSnapshot.NotFound".into()),
                                        message: Some(format!("The snapshot '{id}' does not exist.")),
                                    }),
                                })
                                .collect(),
                        ),
                    });
                    continue;
                }
                for z in &zones {
                    let item = t::DescribeFastSnapshotRestoreSuccessItem {
                        snapshot_id: Some(id.clone()),
                        availability_zone: Some(z.clone()),
                        availability_zone_id: catalog::zone_id(&ctx.region, z),
                        state: Some("enabled".into()),
                        state_transition_reason: Some("Client.UserInitiated - Lifecycle state transition".into()),
                        owner_id: Some(account.clone()),
                        enabling_time: Some(now),
                        optimizing_time: Some(now),
                        enabled_time: Some(now),
                        ..Default::default()
                    };
                    r.fast_snapshot_restores.insert(format!("{id}/{z}"), item.clone());
                    ok.push(t::EnableFastSnapshotRestoreSuccessItem {
                        snapshot_id: item.snapshot_id,
                        availability_zone: item.availability_zone,
                        availability_zone_id: item.availability_zone_id,
                        state: Some("enabling".into()),
                        state_transition_reason: Some("Client.UserInitiated".into()),
                        owner_id: item.owner_id,
                        enabling_time: Some(now),
                        ..Default::default()
                    });
                }
            }
            Ok(t::EnableFastSnapshotRestoresResult { successful: Some(ok), unsuccessful: Some(failed) })
        })
    }

    pub(crate) fn disable_fast_snapshot_restores_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableFastSnapshotRestoresRequest,
    ) -> Result<t::DisableFastSnapshotRestoresResult, ServiceError> {
        let zones = Self::fsr_zones(ctx, &input.availability_zones, &input.availability_zone_ids)?;
        let mut resources = Vec::new();
        for id in &input.source_snapshot_ids {
            Kind::Snapshot.check(id)?;
            resources.push((snapshot_arn(ctx, id), ConditionContext::new()));
        }
        self.authorize_known(ctx, "DisableFastSnapshotRestores", &resources, input.dry_run)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let mut ok = Vec::new();
            let mut failed = Vec::new();
            for id in &input.source_snapshot_ids {
                for z in &zones {
                    match r.fast_snapshot_restores.remove(&format!("{id}/{z}")) {
                        Some(item) => ok.push(t::DisableFastSnapshotRestoreSuccessItem {
                            snapshot_id: item.snapshot_id,
                            availability_zone: item.availability_zone,
                            availability_zone_id: item.availability_zone_id,
                            state: Some("disabling".into()),
                            state_transition_reason: Some("Client.UserInitiated".into()),
                            owner_id: item.owner_id,
                            enabling_time: item.enabling_time,
                            optimizing_time: item.optimizing_time,
                            enabled_time: item.enabled_time,
                            disabling_time: Some(now),
                            ..Default::default()
                        }),
                        None => failed.push(t::DisableFastSnapshotRestoreErrorItem {
                            snapshot_id: Some(id.clone()),
                            fast_snapshot_restore_state_errors: Some(vec![
                                t::DisableFastSnapshotRestoreStateErrorItem {
                                    availability_zone: Some(z.clone()),
                                    availability_zone_id: catalog::zone_id(&ctx.region, z),
                                    error: Some(t::DisableFastSnapshotRestoreStateError {
                                        code: Some("InvalidFastSnapshotRestoreState".into()),
                                        message: Some(format!(
                                            "Fast snapshot restores are not enabled for snapshot {id} in {z}."
                                        )),
                                    }),
                                },
                            ]),
                        }),
                    }
                }
            }
            Ok(t::DisableFastSnapshotRestoresResult { successful: Some(ok), unsuccessful: Some(failed) })
        })
    }

    pub(crate) fn describe_fast_snapshot_restores_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeFastSnapshotRestoresRequest,
    ) -> Result<t::DescribeFastSnapshotRestoresResult, ServiceError> {
        self.authorize_known(
            ctx,
            "DescribeFastSnapshotRestores",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for f in r.fast_snapshot_restores.values() {
                let ok = filters.matches(None, |n| {
                    Some(match n {
                        "availability-zone" => s(&f.availability_zone),
                        "availability-zone-id" => s(&f.availability_zone_id),
                        "owner-id" => s(&f.owner_id),
                        "snapshot-id" => s(&f.snapshot_id),
                        "state" => s(&f.state),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(f.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeFastSnapshotRestoresResult { fast_snapshot_restores: Some(items), next_token })
        })
    }

    // ---- account settings ----------------------------------------------------------------------

    fn account_setting(&self, ctx: &RequestContext, action: &str, dry_run: Option<bool>) -> Result<(), ServiceError> {
        self.authorize_known(ctx, action, &[("*".into(), ConditionContext::new())], dry_run)
    }

    pub(crate) fn enable_ebs_encryption_by_default_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableEbsEncryptionByDefaultRequest,
    ) -> Result<t::EnableEbsEncryptionByDefaultResult, ServiceError> {
        self.account_setting(ctx, "EnableEbsEncryptionByDefault", input.dry_run)?;
        self.with_region(ctx, |r| r.ebs_encryption_by_default = true);
        Ok(t::EnableEbsEncryptionByDefaultResult { ebs_encryption_by_default: Some(true) })
    }

    pub(crate) fn disable_ebs_encryption_by_default_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableEbsEncryptionByDefaultRequest,
    ) -> Result<t::DisableEbsEncryptionByDefaultResult, ServiceError> {
        self.account_setting(ctx, "DisableEbsEncryptionByDefault", input.dry_run)?;
        self.with_region(ctx, |r| r.ebs_encryption_by_default = false);
        Ok(t::DisableEbsEncryptionByDefaultResult { ebs_encryption_by_default: Some(false) })
    }

    pub(crate) fn get_ebs_encryption_by_default_op(
        &self,
        ctx: &RequestContext,
        input: t::GetEbsEncryptionByDefaultRequest,
    ) -> Result<t::GetEbsEncryptionByDefaultResult, ServiceError> {
        self.account_setting(ctx, "GetEbsEncryptionByDefault", input.dry_run)?;
        let on = self.with_region(ctx, |r| r.ebs_encryption_by_default);
        Ok(t::GetEbsEncryptionByDefaultResult { ebs_encryption_by_default: Some(on), sse_type: None })
    }

    pub(crate) fn get_ebs_default_kms_key_id_op(
        &self,
        ctx: &RequestContext,
        input: t::GetEbsDefaultKmsKeyIdRequest,
    ) -> Result<t::GetEbsDefaultKmsKeyIdResult, ServiceError> {
        self.account_setting(ctx, "GetEbsDefaultKmsKeyId", input.dry_run)?;
        let key = self.with_region(ctx, |r| r.ebs_default_kms_key_id.clone());
        Ok(t::GetEbsDefaultKmsKeyIdResult { kms_key_id: Some(key.unwrap_or_else(|| "alias/aws/ebs".into())) })
    }

    pub(crate) fn modify_ebs_default_kms_key_id_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyEbsDefaultKmsKeyIdRequest,
    ) -> Result<t::ModifyEbsDefaultKmsKeyIdResult, ServiceError> {
        self.account_setting(ctx, "ModifyEbsDefaultKmsKeyId", input.dry_run)?;
        let account = account_of(ctx);
        let key = input.kms_key_id.trim().to_string();
        // Key ids, aliases and their ARNs; ids and aliases become ARNs.
        let full = if key.starts_with("arn:") {
            key.clone()
        } else if key.starts_with("alias/") || uuid_like(&key) || key.starts_with("mrk-") {
            let resource = if key.starts_with("alias/") { key.clone() } else { format!("key/{key}") };
            format!("arn:{}:kms:{}:{account}:{resource}", ctx.partition, ctx.region)
        } else {
            return Err(invalid_parameter(format!("Invalid kms key id: {key}")));
        };
        self.with_region(ctx, |r| r.ebs_default_kms_key_id = Some(full.clone()));
        Ok(t::ModifyEbsDefaultKmsKeyIdResult { kms_key_id: Some(full) })
    }

    pub(crate) fn reset_ebs_default_kms_key_id_op(
        &self,
        ctx: &RequestContext,
        input: t::ResetEbsDefaultKmsKeyIdRequest,
    ) -> Result<t::ResetEbsDefaultKmsKeyIdResult, ServiceError> {
        self.account_setting(ctx, "ResetEbsDefaultKmsKeyId", input.dry_run)?;
        self.with_region(ctx, |r| r.ebs_default_kms_key_id = None);
        Ok(t::ResetEbsDefaultKmsKeyIdResult { kms_key_id: Some("alias/aws/ebs".into()) })
    }

    pub(crate) fn enable_snapshot_block_public_access_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableSnapshotBlockPublicAccessRequest,
    ) -> Result<t::EnableSnapshotBlockPublicAccessResult, ServiceError> {
        self.account_setting(ctx, "EnableSnapshotBlockPublicAccess", input.dry_run)?;
        if !matches!(input.state.as_str(), "block-all-sharing" | "block-new-sharing") {
            return Err(invalid_parameter(format!("Value ({}) for parameter state is invalid.", input.state)));
        }
        self.with_region(ctx, |r| r.snapshot_block_public_access = Some(input.state.clone()));
        Ok(t::EnableSnapshotBlockPublicAccessResult { state: Some(input.state) })
    }

    pub(crate) fn disable_snapshot_block_public_access_op(
        &self,
        ctx: &RequestContext,
        input: t::DisableSnapshotBlockPublicAccessRequest,
    ) -> Result<t::DisableSnapshotBlockPublicAccessResult, ServiceError> {
        self.account_setting(ctx, "DisableSnapshotBlockPublicAccess", input.dry_run)?;
        self.with_region(ctx, |r| r.snapshot_block_public_access = None);
        Ok(t::DisableSnapshotBlockPublicAccessResult { state: Some("unblocked".into()) })
    }

    pub(crate) fn get_snapshot_block_public_access_state_op(
        &self,
        ctx: &RequestContext,
        input: t::GetSnapshotBlockPublicAccessStateRequest,
    ) -> Result<t::GetSnapshotBlockPublicAccessStateResult, ServiceError> {
        self.account_setting(ctx, "GetSnapshotBlockPublicAccessState", input.dry_run)?;
        let state = self.with_region(ctx, |r| r.snapshot_block_public_access.clone());
        Ok(t::GetSnapshotBlockPublicAccessStateResult {
            state: Some(state.unwrap_or_else(|| "unblocked".into())),
            managed_by: Some("account".into()),
        })
    }

    // ---- recycle bin ---------------------------------------------------------------------------

    pub(crate) fn list_snapshots_in_recycle_bin_op(
        &self,
        ctx: &RequestContext,
        input: t::ListSnapshotsInRecycleBinRequest,
    ) -> Result<t::ListSnapshotsInRecycleBinResult, ServiceError> {
        self.authorize_known(
            ctx,
            "ListSnapshotsInRecycleBin",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        for id in input.snapshot_ids.iter().flatten() {
            Kind::Snapshot.check(id)?;
        }
        // No Recycle Bin retention rules exist, so deleted snapshots are gone.
        Ok(t::ListSnapshotsInRecycleBinResult { snapshots: Some(Vec::new()), next_token: None })
    }

    pub(crate) fn restore_snapshot_from_recycle_bin_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreSnapshotFromRecycleBinRequest,
    ) -> Result<t::RestoreSnapshotFromRecycleBinResult, ServiceError> {
        Kind::Snapshot.check(&input.snapshot_id)?;
        self.authorize_known(
            ctx,
            "RestoreSnapshotFromRecycleBin",
            &[(snapshot_arn(ctx, &input.snapshot_id), ConditionContext::new())],
            input.dry_run,
        )?;
        Err(Kind::Snapshot.not_found(&input.snapshot_id))
    }

    // ---- root volume replacement -----------------------------------------------------------------

    pub(crate) fn create_replace_root_volume_task_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateReplaceRootVolumeTaskRequest,
    ) -> Result<t::CreateReplaceRootVolumeTaskResult, ServiceError> {
        let account = account_of(ctx);
        Kind::Instance.check(&input.instance_id)?;
        let tags = tags_for(&input.tag_specifications, "replace-root-volume-task", &["replace-root-volume-task"])?;
        let set = [input.snapshot_id.is_some(), input.image_id.is_some(), input.volume_id.is_some()]
            .iter()
            .filter(|x| **x)
            .count();
        if set > 1 {
            return Err(err(
                "InvalidParameterCombination",
                "You can specify only one of the following parameters: SnapshotId, ImageId, or VolumeId.",
            ));
        }
        if input.image_id.is_some() && input.delete_replaced_root_volume.is_none() {
            return Err(err("MissingParameter", "The request must contain the parameter DeleteReplacedRootVolume"));
        }
        let image = match &input.image_id {
            Some(id) => Some(self.find_image(ctx, id)?.record.image),
            None => None,
        };
        let inst_tags = self
            .with_region(ctx, |r| r.instances.get(&input.instance_id).map(|i| i.instance.tags.clone()))
            .ok_or_else(|| Kind::Instance.not_found(&input.instance_id))?;
        self.authorize_known(
            ctx,
            "CreateReplaceRootVolumeTask",
            &[
                (
                    arn(ctx, &account, &format!("instance/{}", input.instance_id)),
                    resource_tag_context(inst_tags.as_ref()),
                ),
                (arn(ctx, &account, "replace-root-volume-task/*"), request_tag_context(&tags)),
            ],
            input.dry_run,
        )?;
        let now = ctx.received_at;
        let stamp = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut deleted = None;
        let task = self.with_region(ctx, |r| {
            let rec = &r.instances[&input.instance_id];
            let st = super::instance::state_name(rec);
            if st != "running" {
                return Err(err(
                    "IncorrectState",
                    format!("The instance '{}' is not in the 'running' state.", input.instance_id),
                ));
            }
            let root = rec.instance.root_device_name.clone().unwrap_or_else(|| "/dev/xvda".into());
            let zone = rec.instance.placement.as_ref().and_then(|p| p.availability_zone.clone());
            let zone_id = rec.instance.placement.as_ref().and_then(|p| p.availability_zone_id.clone());
            let old = r
                .volumes
                .values()
                .find(|v| {
                    v.attachments.iter().flatten().any(|a| {
                        a.instance_id.as_deref() == Some(input.instance_id.as_str())
                            && a.device.as_deref() == Some(root.as_str())
                    })
                })
                .cloned()
                .ok_or_else(|| {
                    err("IncorrectState", format!("The instance '{}' has no root volume.", input.instance_id))
                })?;
            let old_id = old.volume_id.clone().unwrap_or_default();
            if let Some(snap) = &input.snapshot_id {
                Kind::Snapshot.check(snap)?;
                let s = r.snapshots.get(snap).ok_or_else(|| Kind::Snapshot.not_found(snap))?;
                if s.volume_id.as_deref() != Some(old_id.as_str()) {
                    return Err(invalid_parameter(format!(
                        "The snapshot '{snap}' was not created from the instance's root volume."
                    )));
                }
            }
            let new_volume = match &input.volume_id {
                Some(v) => {
                    Kind::Volume.check(v)?;
                    let vol = r.volumes.get(v).ok_or_else(|| Kind::Volume.not_found(v))?;
                    if vol.state.as_deref() != Some("available") {
                        return Err(err("VolumeInUse", format!("{v} is already attached to an instance")));
                    }
                    Some(v.clone())
                }
                None => None,
            };
            // Detach the old root volume, attach the replacement.
            let delete_old = input.delete_replaced_root_volume == Some(true);
            if let Some(vol) = r.volumes.get_mut(&old_id) {
                vol.attachments = Some(Vec::new());
                vol.state = Some("available".into());
            }
            let attach = t::VolumeAttachment {
                instance_id: Some(input.instance_id.clone()),
                device: Some(root.clone()),
                state: Some("attached".into()),
                attach_time: Some(now),
                delete_on_termination: Some(true),
                ..Default::default()
            };
            match new_volume {
                Some(v) => {
                    let vol = r.volumes.get_mut(&v).expect("checked");
                    vol.attachments = Some(vec![t::VolumeAttachment { volume_id: Some(v.clone()), ..attach }]);
                    vol.state = Some("in-use".into());
                }
                None => {
                    let plan = super::ebs::PlannedVolume {
                        device: root.clone(),
                        size: image
                            .as_ref()
                            .and_then(|i| {
                                i.block_device_mappings
                                    .iter()
                                    .flatten()
                                    .find_map(|b| b.ebs.as_ref().and_then(|e| e.volume_size))
                            })
                            .unwrap_or(old.size.unwrap_or(8))
                            .max(old.size.unwrap_or(8)),
                        volume_type: old.volume_type.clone().unwrap_or_else(|| "gp3".into()),
                        iops: old.iops,
                        throughput: old.throughput,
                        encrypted: old.encrypted.unwrap_or(false),
                        kms_key_id: old.kms_key_id.clone(),
                        snapshot_id: input.snapshot_id.clone().or_else(|| {
                            image.as_ref().and_then(|i| {
                                i.block_device_mappings
                                    .iter()
                                    .flatten()
                                    .find_map(|b| b.ebs.as_ref().and_then(|e| e.snapshot_id.clone()))
                            })
                        }),
                        delete_on_termination: true,
                    };
                    super::ebs::create_attached_volume(
                        r,
                        &account,
                        &plan,
                        &input.instance_id,
                        zone,
                        zone_id,
                        old.tags.clone().unwrap_or_default(),
                        now,
                    );
                }
            }
            if delete_old {
                r.volumes.remove(&old_id);
                deleted = Some(old_id.clone());
            }
            if let Some(img) = &input.image_id {
                if let Some(rec) = r.instances.get_mut(&input.instance_id) {
                    rec.instance.image_id = Some(img.clone());
                }
            }
            let id = new_id("replacevol");
            let task = t::ReplaceRootVolumeTask {
                replace_root_volume_task_id: Some(id.clone()),
                instance_id: Some(input.instance_id.clone()),
                task_state: Some("succeeded".into()),
                start_time: Some(stamp.clone()),
                complete_time: Some(stamp.clone()),
                tags: some_tags(tags.clone()),
                image_id: input.image_id.clone(),
                snapshot_id: input.snapshot_id.clone(),
                delete_replaced_root_volume: Some(delete_old),
            };
            r.replace_root_tasks.insert(id, task.clone());
            Ok(task)
        })?;
        if let Some(v) = deleted {
            self.volume_job(VolumeJob::Delete(v));
        }
        let mut shown = task;
        shown.task_state = Some("pending".into());
        shown.complete_time = None;
        Ok(t::CreateReplaceRootVolumeTaskResult { replace_root_volume_task: Some(shown) })
    }

    pub(crate) fn describe_replace_root_volume_tasks_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeReplaceRootVolumeTasksRequest,
    ) -> Result<t::DescribeReplaceRootVolumeTasksResult, ServiceError> {
        self.authorize_known(
            ctx,
            "DescribeReplaceRootVolumeTasks",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let filters = Filters::new(&input.filters);
        let ids = input.replace_root_volume_task_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            for id in &ids {
                if !r.replace_root_tasks.contains_key(id) {
                    return Err(err(
                        "InvalidReplaceRootVolumeTaskId.NotFound",
                        format!("The replace root volume task ID '{id}' does not exist"),
                    ));
                }
            }
            let mut out = Vec::new();
            for (id, task) in &r.replace_root_tasks {
                if !ids.is_empty() && !ids.contains(id) {
                    continue;
                }
                let ok = filters.matches(task.tags.as_ref(), |n| match n {
                    "instance-id" => Some(s(&task.instance_id)),
                    _ => None,
                })?;
                if ok {
                    out.push(task.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeReplaceRootVolumeTasksResult { replace_root_volume_tasks: Some(items), next_token })
        })
    }
}

fn uuid_like(s: &str) -> bool {
    s.len() == 36 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}
