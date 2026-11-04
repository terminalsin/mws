//! EBS volumes and snapshots. Volumes are metadata (instances use the
//! container's own filesystem); attachment and snapshot lifecycles follow
//! EC2's states and errors.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::util::{
    arn, authorize, b, err, invalid_parameter, new_id, paginate, request_tag_context, resource_tag_context, s,
    some_tags, tags_for, Filters, Kind,
};
use crate::{account_of, catalog, Ec2};

const VOLUME_TYPES: &[&str] = &["standard", "io1", "io2", "gp2", "gp3", "sc1", "st1"];

fn snapshot_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ec2:{}::snapshot/{id}", ctx.partition, ctx.region)
}

fn volume_filter(v: &t::Volume, name: &str) -> Option<Vec<String>> {
    let atts = v.attachments.clone().unwrap_or_default();
    Some(match name {
        "volume-id" => s(&v.volume_id),
        "availability-zone" => s(&v.availability_zone),
        "create-time" => v.create_time.map(|t| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()).into_iter().collect(),
        "encrypted" => b(v.encrypted),
        "multi-attach-enabled" => b(v.multi_attach_enabled),
        "size" => v.size.map(|x| x.to_string()).into_iter().collect(),
        "snapshot-id" => s(&v.snapshot_id),
        "status" => s(&v.state),
        "volume-type" => s(&v.volume_type),
        "attachment.instance-id" => atts.iter().filter_map(|a| a.instance_id.clone()).collect(),
        "attachment.device" => atts.iter().filter_map(|a| a.device.clone()).collect(),
        "attachment.status" => atts.iter().filter_map(|a| a.state.clone()).collect(),
        "attachment.delete-on-termination" => atts.iter().flat_map(|a| b(a.delete_on_termination)).collect(),
        "attachment.attach-time" => {
            atts.iter().filter_map(|a| a.attach_time.map(|t| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string())).collect()
        }
        _ => return None,
    })
}

impl Ec2 {
    pub(crate) fn create_volume_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateVolumeRequest,
    ) -> Result<t::Volume, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "volume", &["volume"])?;
        let volume_type = input.volume_type.clone().unwrap_or_else(|| "gp2".into());
        if !VOLUME_TYPES.contains(&volume_type.as_str()) {
            return Err(invalid_parameter(format!(
                "Value ({volume_type}) for parameter volumeType is invalid. Valid volume types are {VOLUME_TYPES:?}"
            )));
        }
        let zone = match (&input.availability_zone, &input.availability_zone_id) {
            (Some(z), _) => z.clone(),
            (None, Some(id)) => catalog::zone_name(&ctx.region, id)
                .ok_or_else(|| invalid_parameter(format!("Invalid availability zone ID: [{id}]")))?,
            (None, None) => {
                return Err(err(
                    "MissingParameter",
                    "The request must contain the parameter AvailabilityZone or AvailabilityZoneId",
                ))
            }
        };
        if !catalog::zones(&ctx.region).iter().any(|z| z.0 == zone) {
            return Err(invalid_parameter(format!("Invalid availability zone: [{zone}]")));
        }
        let snapshot = match &input.snapshot_id {
            Some(id) => {
                Kind::Snapshot.check(id)?;
                Some(
                    self.with_region(ctx, |r| r.snapshots.get(id).cloned())
                        .ok_or_else(|| Kind::Snapshot.not_found(id))?,
                )
            }
            None => None,
        };
        let size = match (input.size, &snapshot) {
            (Some(sz), Some(snap)) if sz < snap.volume_size.unwrap_or(0) => {
                return Err(invalid_parameter(format!(
                    "Volume of {sz}GiB is too small; minimum is {}GiB.",
                    snap.volume_size.unwrap_or(0)
                )))
            }
            (Some(sz), _) => sz,
            (None, Some(snap)) => snap.volume_size.unwrap_or(8),
            (None, None) => {
                return Err(err("MissingParameter", "The request must contain the parameter size or snapshotId"))
            }
        };
        let (min, max) = match volume_type.as_str() {
            "gp2" | "gp3" => (1, 16384),
            "io1" => (4, 16384),
            "io2" => (4, 65536),
            "st1" | "sc1" => (125, 16384),
            _ => (1, 1024),
        };
        if !(min..=max).contains(&size) {
            return Err(invalid_parameter(format!(
                "Volume of size {size}GiB is too {}; {} is {}GiB.",
                if size < min { "small" } else { "large" },
                if size < min { "minimum" } else { "maximum" },
                if size < min { min } else { max }
            )));
        }
        let iops = match volume_type.as_str() {
            "gp3" => Some(input.iops.unwrap_or(3000)),
            "gp2" => Some((size * 3).clamp(100, 16000)),
            "io1" | "io2" => Some(
                input
                    .iops
                    .ok_or_else(|| err("MissingParameter", "The parameter iops must be specified for io1 volumes."))?,
            ),
            _ => {
                if input.iops.is_some() {
                    return Err(invalid_parameter(format!(
                        "The parameter iops is not supported for {volume_type} volumes."
                    )));
                }
                None
            }
        };
        let mut cond = request_tag_context(&tags);
        cond.insert("ec2:VolumeType".into(), vec![volume_type.clone()]);
        cond.insert("ec2:VolumeSize".into(), vec![size.to_string()]);
        cond.insert("ec2:AvailabilityZone".into(), vec![zone.clone()]);
        cond.insert("ec2:Encrypted".into(), vec![input.encrypted.unwrap_or(false).to_string()]);
        let mut resources = vec![(arn(ctx, &account, "volume/*"), cond)];
        if let Some(snap) = &snapshot {
            resources.push((
                snapshot_arn(ctx, snap.snapshot_id.as_deref().unwrap_or_default()),
                resource_tag_context(snap.tags.as_ref()),
            ));
        }
        authorize(ctx, "CreateVolume", &resources, input.dry_run)?;
        let id = new_id("vol");
        let encrypted =
            input.encrypted.unwrap_or(false) || snapshot.as_ref().is_some_and(|s| s.encrypted == Some(true));
        let volume = t::Volume {
            volume_id: Some(id.clone()),
            size: Some(size),
            snapshot_id: Some(input.snapshot_id.clone().unwrap_or_default()),
            availability_zone: Some(zone.clone()),
            availability_zone_id: catalog::zone_id(&ctx.region, &zone),
            state: Some("available".into()),
            create_time: Some(ctx.received_at),
            attachments: Some(Vec::new()),
            volume_type: Some(volume_type.clone()),
            iops,
            throughput: (volume_type == "gp3").then(|| input.throughput.unwrap_or(125)),
            encrypted: Some(encrypted),
            kms_key_id: encrypted.then(|| {
                input
                    .kms_key_id
                    .clone()
                    .unwrap_or_else(|| format!("arn:{}:kms:{}:{account}:alias/aws/ebs", ctx.partition, ctx.region))
            }),
            multi_attach_enabled: Some(input.multi_attach_enabled.unwrap_or(false)),
            tags: some_tags(tags),
            ..Default::default()
        };
        self.with_region(ctx, |r| r.volumes.insert(id.clone(), volume.clone()));
        let mut shown = volume;
        shown.state = Some("creating".into());
        shown.attachments = None;
        Ok(shown)
    }

    fn volume_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
    ) -> Result<t::Volume, ServiceError> {
        Kind::Volume.check(id)?;
        let v = self.with_region(ctx, |r| r.volumes.get(id).cloned()).ok_or_else(|| Kind::Volume.not_found(id))?;
        authorize(
            ctx,
            action,
            &[(arn(ctx, &account_of(ctx), &format!("volume/{id}")), resource_tag_context(v.tags.as_ref()))],
            dry_run,
        )?;
        Ok(v)
    }

    pub(crate) fn delete_volume_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteVolumeRequest,
    ) -> Result<(), ServiceError> {
        let v = self.volume_authorize(ctx, "DeleteVolume", &input.volume_id, input.dry_run)?;
        if v.attachments.as_ref().is_some_and(|a| !a.is_empty()) {
            return Err(err(
                "VolumeInUse",
                format!(
                    "Volume {} is currently attached to {}",
                    input.volume_id,
                    v.attachments.unwrap()[0].instance_id.clone().unwrap_or_default()
                ),
            ));
        }
        self.with_region(ctx, |r| r.volumes.remove(&input.volume_id));
        Ok(())
    }

    pub(crate) fn describe_volumes_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVolumesRequest,
    ) -> Result<t::DescribeVolumesResult, ServiceError> {
        authorize(ctx, "DescribeVolumes", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.volume_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Volume.check_all(&ids, |id| r.volumes.contains_key(id))?;
            let mut out = Vec::new();
            for v in r.volumes.values() {
                if !ids.is_empty() && !ids.contains(v.volume_id.as_ref().unwrap()) {
                    continue;
                }
                if filters.matches(v.tags.as_ref(), |n| volume_filter(v, n))? {
                    out.push(v.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeVolumesResult { volumes: Some(items), next_token })
        })
    }

    pub(crate) fn attach_volume_op(
        &self,
        ctx: &RequestContext,
        input: t::AttachVolumeRequest,
    ) -> Result<t::VolumeAttachment, ServiceError> {
        let account = account_of(ctx);
        let v = self.volume_authorize(ctx, "AttachVolume", &input.volume_id, None)?;
        Kind::Instance.check(&input.instance_id)?;
        let tags = self
            .with_region(ctx, |r| r.instances.get(&input.instance_id).map(|i| i.instance.tags.clone()))
            .ok_or_else(|| Kind::Instance.not_found(&input.instance_id))?;
        authorize(
            ctx,
            "AttachVolume",
            &[(arn(ctx, &account, &format!("instance/{}", input.instance_id)), resource_tag_context(tags.as_ref()))],
            input.dry_run,
        )?;
        if !input.device.starts_with("/dev/") && !input.device.starts_with("xvd") {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter device is invalid. {} is not a valid EBS device name.",
                input.device, input.device
            )));
        }
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let rec = &r.instances[&input.instance_id];
            let st = super::instance::state_name(rec);
            if !matches!(st.as_str(), "running" | "stopped") {
                return Err(err("IncorrectState", format!("Instance '{}' is not 'running'.", input.instance_id)));
            }
            let zone = rec.instance.placement.as_ref().and_then(|p| p.availability_zone.clone());
            if zone != v.availability_zone {
                return Err(invalid_parameter(format!(
                    "The volume '{}' is not in the same availability zone as instance '{}'",
                    input.volume_id, input.instance_id
                )));
            }
            if v.state.as_deref() != Some("available") && v.multi_attach_enabled != Some(true) {
                return Err(err("VolumeInUse", format!("{} is already attached to an instance", input.volume_id)));
            }
            let device_taken = r.volumes.values().any(|x| {
                x.attachments.iter().flatten().any(|a| {
                    a.instance_id.as_deref() == Some(input.instance_id.as_str())
                        && a.device.as_deref() == Some(input.device.as_str())
                })
            });
            if device_taken {
                return Err(invalid_parameter(format!(
                    "Invalid value '{}' for unixDevice. Attachment point {} is already in use",
                    input.device, input.device
                )));
            }
            let att = t::VolumeAttachment {
                volume_id: Some(input.volume_id.clone()),
                instance_id: Some(input.instance_id.clone()),
                device: Some(input.device.clone()),
                state: Some("attached".into()),
                attach_time: Some(now),
                delete_on_termination: Some(false),
                ..Default::default()
            };
            let vol = r.volumes.get_mut(&input.volume_id).expect("checked");
            vol.attachments.get_or_insert_with(Vec::new).push(att.clone());
            vol.state = Some("in-use".into());
            let mut shown = att;
            shown.state = Some("attaching".into());
            shown.delete_on_termination = None;
            Ok(shown)
        })
    }

    pub(crate) fn detach_volume_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachVolumeRequest,
    ) -> Result<t::VolumeAttachment, ServiceError> {
        let v = self.volume_authorize(ctx, "DetachVolume", &input.volume_id, input.dry_run)?;
        let atts = v.attachments.clone().unwrap_or_default();
        let pos = atts
            .iter()
            .position(|a| {
                input.instance_id.as_ref().is_none_or(|i| a.instance_id.as_ref() == Some(i))
                    && input.device.as_ref().is_none_or(|d| a.device.as_ref() == Some(d))
            })
            .ok_or_else(|| {
                err("IncorrectState", format!("Volume '{}' is in the 'available' state.", input.volume_id))
            })?;
        let att = atts[pos].clone();
        let instance_id = att.instance_id.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            if let Some(rec) = r.instances.get(&instance_id) {
                if rec.instance.root_device_name == att.device
                    && super::instance::state_name(rec) == "running"
                    && input.force != Some(true)
                {
                    return Err(err(
                        "OperationNotPermitted",
                        format!("Unable to detach root volume '{}' from instance '{instance_id}'", input.volume_id),
                    ));
                }
            }
            let vol = r.volumes.get_mut(&input.volume_id).expect("checked");
            if let Some(list) = &mut vol.attachments {
                list.remove(pos);
                if list.is_empty() {
                    vol.state = Some("available".into());
                }
            }
            let mut shown = att.clone();
            shown.state = Some("detaching".into());
            shown.delete_on_termination = None;
            Ok(shown)
        })
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
        authorize(
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
        let id = new_id("snap");
        let snap = t::Snapshot {
            snapshot_id: Some(id.clone()),
            volume_id: Some(input.volume_id.clone()),
            state: Some("completed".into()),
            start_time: Some(ctx.received_at),
            completion_time: Some(ctx.received_at),
            progress: Some("100%".into()),
            owner_id: Some(account),
            description: Some(input.description.clone().unwrap_or_default()),
            volume_size: v.size,
            encrypted: v.encrypted,
            kms_key_id: v.kms_key_id.clone(),
            storage_tier: Some("standard".into()),
            tags: some_tags(tags),
            ..Default::default()
        };
        self.with_region(ctx, |r| r.snapshots.insert(id, snap.clone()));
        let mut shown = snap;
        shown.state = Some("pending".into());
        shown.progress = Some(String::new());
        shown.completion_time = None;
        shown.storage_tier = None;
        Ok(shown)
    }

    pub(crate) fn delete_snapshot_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteSnapshotRequest,
    ) -> Result<(), ServiceError> {
        Kind::Snapshot.check(&input.snapshot_id)?;
        let snap = self
            .with_region(ctx, |r| r.snapshots.get(&input.snapshot_id).cloned())
            .ok_or_else(|| Kind::Snapshot.not_found(&input.snapshot_id))?;
        authorize(
            ctx,
            "DeleteSnapshot",
            &[(snapshot_arn(ctx, &input.snapshot_id), resource_tag_context(snap.tags.as_ref()))],
            input.dry_run,
        )?;
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
            r.snapshots.remove(&input.snapshot_id);
            Ok(())
        })
    }

    pub(crate) fn describe_snapshots_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSnapshotsRequest,
    ) -> Result<t::DescribeSnapshotsResult, ServiceError> {
        authorize(ctx, "DescribeSnapshots", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let account = account_of(ctx);
        let filters = Filters::new(&input.filters);
        let ids = input.snapshot_ids.clone().unwrap_or_default();
        let owners = input.owner_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Snapshot.check_all(&ids, |id| r.snapshots.contains_key(id))?;
            let mut out = Vec::new();
            for snap in r.snapshots.values() {
                if !ids.is_empty() && !ids.contains(snap.snapshot_id.as_ref().unwrap()) {
                    continue;
                }
                if !owners.is_empty()
                    && !owners.iter().any(|o| {
                        o == "self" && account == snap.owner_id.clone().unwrap_or_default()
                            || Some(o) == snap.owner_id.as_ref()
                    })
                {
                    continue;
                }
                let ok = filters.matches(snap.tags.as_ref(), |n| {
                    Some(match n {
                        "snapshot-id" => s(&snap.snapshot_id),
                        "volume-id" => s(&snap.volume_id),
                        "status" => s(&snap.state),
                        "owner-id" => s(&snap.owner_id),
                        "description" => s(&snap.description),
                        "progress" => s(&snap.progress),
                        "encrypted" => b(snap.encrypted),
                        "volume-size" => snap.volume_size.map(|x| x.to_string()).into_iter().collect(),
                        "storage-tier" => s(&snap.storage_tier),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(snap.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeSnapshotsResult { snapshots: Some(items), next_token })
        })
    }
}
