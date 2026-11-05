//! EBS volumes: create, attach, modify, delete, and the block devices an
//! instance launches with. The API follows EC2's states and errors; the
//! compute backend holds the data (the Docker backend keeps each data
//! volume in a Docker volume, see [`crate::backend::DockerBackend`]).

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::RegionState;
use crate::util::{
    arn, authorize, b, err, invalid_parameter, new_id, paginate, request_tag_context, resource_tag_context, s,
    some_tags, tags_for, Filters, Kind,
};
use crate::volumes::VolumeJob;
use crate::{account_of, catalog, Ec2};

pub const VOLUME_TYPES: &[&str] = &["standard", "io1", "io2", "gp2", "gp3", "sc1", "st1"];

/// How long EBS makes you wait between modifications of one volume.
const MODIFICATION_COOLDOWN_HOURS: i64 = 6;

pub fn snapshot_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ec2:{}::snapshot/{id}", ctx.partition, ctx.region)
}

fn ts(t: Option<DateTime<Utc>>) -> Vec<String> {
    t.map(|t| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()).into_iter().collect()
}

/// The KMS key EBS encrypts with when none is named.
pub fn default_kms_key(ctx: &RequestContext, account: &str, r: &RegionState) -> String {
    r.ebs_default_kms_key_id
        .clone()
        .unwrap_or_else(|| format!("arn:{}:kms:{}:{account}:alias/aws/ebs", ctx.partition, ctx.region))
}

/// Size and performance limits of a volume type, in EC2's words.
pub fn check_volume_shape(
    volume_type: &str,
    size: i32,
    iops: Option<i32>,
    throughput: Option<i32>,
) -> Result<(Option<i32>, Option<i32>), ServiceError> {
    if !VOLUME_TYPES.contains(&volume_type) {
        return Err(invalid_parameter(format!(
            "Value ({volume_type}) for parameter volumeType is invalid. Valid volume types are {VOLUME_TYPES:?}"
        )));
    }
    let (min, max) = match volume_type {
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
    let iops = match volume_type {
        "gp3" => {
            let v = iops.unwrap_or(3000);
            if !(3000..=80000).contains(&v) {
                return Err(invalid_parameter(format!(
                    "The parameter iops must be between 3000 and 80000 for gp3 volumes, got {v}."
                )));
            }
            Some(v)
        }
        "gp2" => {
            if iops.is_some() {
                return Err(invalid_parameter("The parameter iops is not supported for gp2 volumes."));
            }
            Some((size * 3).clamp(100, 16000))
        }
        "io1" | "io2" => {
            let v = iops.ok_or_else(|| {
                err("MissingParameter", format!("The parameter iops must be specified for {volume_type} volumes."))
            })?;
            let max_ratio = if volume_type == "io1" { 50 } else { 1000 };
            if v < 100 || v > max_ratio * size {
                return Err(invalid_parameter(format!(
                    "Iops to volume size ratio of {:.6} is too high; maximum is {max_ratio:.6}.",
                    v as f64 / size as f64
                )));
            }
            Some(v)
        }
        _ => {
            if iops.is_some() {
                return Err(invalid_parameter(format!(
                    "The parameter iops is not supported for {volume_type} volumes."
                )));
            }
            None
        }
    };
    let throughput = match volume_type {
        "gp3" => {
            let v = throughput.unwrap_or(125);
            if !(125..=2000).contains(&v) {
                return Err(invalid_parameter(format!(
                    "The parameter throughput must be between 125 and 2000 for gp3 volumes, got {v}."
                )));
            }
            Some(v)
        }
        _ => {
            if throughput.is_some() {
                return Err(invalid_parameter(format!(
                    "The parameter throughput is not supported for {volume_type} volumes."
                )));
            }
            None
        }
    };
    Ok((iops, throughput))
}

/// A volume an instance launches with, from its AMI's and the request's
/// block device mappings.
#[derive(Debug, Clone)]
pub struct PlannedVolume {
    pub device: String,
    pub size: i32,
    pub volume_type: String,
    pub iops: Option<i32>,
    pub throughput: Option<i32>,
    pub encrypted: bool,
    pub kms_key_id: Option<String>,
    pub snapshot_id: Option<String>,
    pub delete_on_termination: bool,
}

/// The EBS volumes for a launch: the AMI's mappings, overridden device by
/// device by the request's (`NoDevice` drops one).
pub fn plan_block_devices(
    ctx: &RequestContext,
    account: &str,
    r: &RegionState,
    image: &t::Image,
    requested: &[t::BlockDeviceMapping],
) -> Result<Vec<PlannedVolume>, ServiceError> {
    let root = image.root_device_name.clone().unwrap_or_else(|| "/dev/xvda".into());
    let mut mappings: Vec<t::BlockDeviceMapping> = image.block_device_mappings.clone().unwrap_or_default();
    if !mappings.iter().any(|m| m.device_name.as_deref() == Some(root.as_str())) {
        mappings.insert(
            0,
            t::BlockDeviceMapping {
                device_name: Some(root.clone()),
                ebs: Some(t::EbsBlockDevice {
                    delete_on_termination: Some(true),
                    volume_size: Some(8),
                    volume_type: Some("gp3".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    for req in requested {
        let Some(dev) = req.device_name.clone() else {
            return Err(err(
                "InvalidBlockDeviceMapping",
                "The device name is required for every block device mapping.",
            ));
        };
        let pos = mappings.iter().position(|m| m.device_name.as_deref() == Some(dev.as_str()));
        if req.no_device.is_some() {
            if dev == root {
                return Err(err("InvalidBlockDeviceMapping", "The device for the root volume cannot be removed."));
            }
            if let Some(p) = pos {
                mappings.remove(p);
            }
            continue;
        }
        if req.virtual_name.is_some() {
            // Instance store: nothing to make.
            continue;
        }
        match (pos, &req.ebs) {
            (Some(p), Some(ebs)) => {
                let base = mappings[p].ebs.get_or_insert_with(Default::default);
                macro_rules! over {
                    ($($f:ident),*) => { $( if ebs.$f.is_some() { base.$f = ebs.$f.clone(); } )* };
                }
                over!(
                    delete_on_termination,
                    iops,
                    snapshot_id,
                    volume_size,
                    volume_type,
                    kms_key_id,
                    throughput,
                    encrypted
                );
            }
            (None, Some(_)) => mappings.push(req.clone()),
            (_, None) => {}
        }
    }
    let mut out = Vec::new();
    for m in &mappings {
        let Some(ebs) = &m.ebs else { continue };
        let device = m.device_name.clone().unwrap_or_default();
        let snapshot = match ebs.snapshot_id.as_deref().filter(|s| !s.is_empty()) {
            Some(id) => r.snapshots.get(id).cloned(),
            None => None,
        };
        let snap_size = snapshot.as_ref().and_then(|s| s.volume_size);
        let size = match (ebs.volume_size, snap_size) {
            (Some(sz), Some(min)) if sz < min => {
                return Err(err(
                    "InvalidBlockDeviceMapping",
                    format!(
                        "Volume of size {sz}GB is smaller than snapshot '{}', expect size >= {min}GB",
                        ebs.snapshot_id.clone().unwrap_or_default()
                    ),
                ))
            }
            (Some(sz), _) => sz,
            (None, Some(min)) => min,
            (None, None) if device == root => 8,
            (None, None) => {
                return Err(err(
                    "InvalidBlockDeviceMapping",
                    format!("snapshotId or volumeSize must be specified for device {device}"),
                ))
            }
        };
        let volume_type = ebs.volume_type.clone().unwrap_or_else(|| "gp2".into());
        let (iops, throughput) = check_volume_shape(&volume_type, size, ebs.iops, ebs.throughput)?;
        let encrypted = ebs.encrypted.unwrap_or(false)
            || snapshot.as_ref().is_some_and(|s| s.encrypted == Some(true))
            || r.ebs_encryption_by_default;
        let kms_key_id = encrypted.then(|| {
            ebs.kms_key_id
                .clone()
                .or_else(|| snapshot.as_ref().and_then(|s| s.kms_key_id.clone()))
                .unwrap_or_else(|| default_kms_key(ctx, account, r))
        });
        out.push(PlannedVolume {
            device,
            size,
            volume_type,
            iops,
            throughput,
            encrypted,
            kms_key_id,
            snapshot_id: ebs.snapshot_id.clone().filter(|s| !s.is_empty()),
            delete_on_termination: ebs.delete_on_termination.unwrap_or(true),
        });
    }
    Ok(out)
}

/// Make a planned volume, attached to `instance_id`, and return its id.
#[allow(clippy::too_many_arguments)]
pub fn create_attached_volume(
    r: &mut RegionState,
    account: &str,
    plan: &PlannedVolume,
    instance_id: &str,
    zone: Option<String>,
    zone_id: Option<String>,
    tags: Vec<t::Tag>,
    now: DateTime<Utc>,
) -> String {
    let vol_id = new_id("vol");
    r.volumes.insert(
        vol_id.clone(),
        t::Volume {
            volume_id: Some(vol_id.clone()),
            size: Some(plan.size),
            snapshot_id: Some(plan.snapshot_id.clone().unwrap_or_default()),
            availability_zone: zone,
            availability_zone_id: zone_id,
            state: Some("in-use".into()),
            create_time: Some(now),
            volume_type: Some(plan.volume_type.clone()),
            iops: plan.iops,
            throughput: plan.throughput,
            encrypted: Some(plan.encrypted),
            kms_key_id: plan.kms_key_id.clone(),
            multi_attach_enabled: Some(false),
            owner_id: Some(account.to_string()),
            attachments: Some(vec![t::VolumeAttachment {
                volume_id: Some(vol_id.clone()),
                instance_id: Some(instance_id.to_string()),
                device: Some(plan.device.clone()),
                state: Some("attached".into()),
                attach_time: Some(now),
                delete_on_termination: Some(plan.delete_on_termination),
                ..Default::default()
            }]),
            tags: some_tags(tags),
            fast_restored: Some(false),
            ..Default::default()
        },
    );
    vol_id
}

fn volume_filter(v: &t::Volume, name: &str) -> Option<Vec<String>> {
    let atts = v.attachments.clone().unwrap_or_default();
    Some(match name {
        "volume-id" => s(&v.volume_id),
        "availability-zone" => s(&v.availability_zone),
        "availability-zone-id" => s(&v.availability_zone_id),
        "create-time" => ts(v.create_time),
        "encrypted" => b(v.encrypted),
        "fast-restored" => b(v.fast_restored),
        "multi-attach-enabled" => b(v.multi_attach_enabled),
        "size" => v.size.map(|x| x.to_string()).into_iter().collect(),
        "snapshot-id" => s(&v.snapshot_id),
        "status" => s(&v.state),
        "volume-type" => s(&v.volume_type),
        "attachment.instance-id" => atts.iter().filter_map(|a| a.instance_id.clone()).collect(),
        "attachment.device" => atts.iter().filter_map(|a| a.device.clone()).collect(),
        "attachment.status" => atts.iter().filter_map(|a| a.state.clone()).collect(),
        "attachment.delete-on-termination" => atts.iter().flat_map(|a| b(a.delete_on_termination)).collect(),
        "attachment.attach-time" => atts.iter().flat_map(|a| ts(a.attach_time)).collect(),
        _ => return None,
    })
}

fn modification_filter(m: &t::VolumeModification, name: &str) -> Option<Vec<String>> {
    let n = |v: Option<i32>| v.map(|x| x.to_string()).into_iter().collect::<Vec<_>>();
    Some(match name {
        "volume-id" => s(&m.volume_id),
        "modification-state" => s(&m.modification_state),
        "target-size" => n(m.target_size),
        "target-iops" => n(m.target_iops),
        "target-volume-type" => s(&m.target_volume_type),
        "target-throughput" => n(m.target_throughput),
        "target-multi-attach-enabled" => b(m.target_multi_attach_enabled),
        "original-size" => n(m.original_size),
        "original-iops" => n(m.original_iops),
        "original-volume-type" => s(&m.original_volume_type),
        "original-throughput" => n(m.original_throughput),
        "original-multi-attach-enabled" => b(m.original_multi_attach_enabled),
        "start-time" => ts(m.start_time),
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
        if let Some(token) = input.client_token.as_deref().filter(|t| !t.is_empty()) {
            let existing =
                self.with_region(ctx, |r| r.volume_tokens.get(token).and_then(|id| r.volumes.get(id)).cloned());
            if let Some(v) = existing {
                return Ok(v);
            }
        }
        let snapshot = match &input.snapshot_id {
            Some(id) => {
                Kind::Snapshot.check(id)?;
                Some(self.find_snapshot(ctx, id)?.1)
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
        let (iops, throughput) = check_volume_shape(&volume_type, size, input.iops, input.throughput)?;
        if input.multi_attach_enabled == Some(true) && !matches!(volume_type.as_str(), "io1" | "io2") {
            return Err(invalid_parameter(
                "The parameter multiAttachEnabled is only supported for io1 and io2 volumes.",
            ));
        }
        let by_default = self.with_region(ctx, |r| r.ebs_encryption_by_default);
        if input.encrypted == Some(false) && by_default {
            return Err(invalid_parameter(
                "The parameter encrypted is invalid. Encryption by default is enabled for this account and Region.",
            ));
        }
        let encrypted = input.encrypted.unwrap_or(false)
            || by_default
            || snapshot.as_ref().is_some_and(|s| s.encrypted == Some(true));
        if input.kms_key_id.is_some() && !encrypted {
            return Err(invalid_parameter("The parameter KmsKeyId requires the parameter Encrypted to be set."));
        }
        let mut cond = request_tag_context(&tags);
        cond.insert("ec2:VolumeType".into(), vec![volume_type.clone()]);
        cond.insert("ec2:VolumeSize".into(), vec![size.to_string()]);
        cond.insert("ec2:AvailabilityZone".into(), vec![zone.clone()]);
        cond.insert("ec2:Encrypted".into(), vec![encrypted.to_string()]);
        if let Some(i) = iops {
            cond.insert("ec2:VolumeIops".into(), vec![i.to_string()]);
        }
        if let Some(tp) = throughput {
            cond.insert("ec2:VolumeThroughput".into(), vec![tp.to_string()]);
        }
        let mut resources = vec![(arn(ctx, &account, "volume/*"), cond)];
        if let Some(snap) = &snapshot {
            resources.push((
                snapshot_arn(ctx, snap.snapshot_id.as_deref().unwrap_or_default()),
                resource_tag_context(snap.tags.as_ref()),
            ));
        }
        authorize(ctx, "CreateVolume", &resources, input.dry_run)?;
        let id = new_id("vol");
        let snapshot_id = input.snapshot_id.clone().unwrap_or_default();
        let volume = self.with_region(ctx, |r| {
            let fast = !snapshot_id.is_empty()
                && r.fast_snapshot_restores
                    .get(&format!("{snapshot_id}/{zone}"))
                    .is_some_and(|f| f.state.as_deref() == Some("enabled"));
            let volume = t::Volume {
                volume_id: Some(id.clone()),
                size: Some(size),
                snapshot_id: Some(snapshot_id.clone()),
                availability_zone: Some(zone.clone()),
                availability_zone_id: catalog::zone_id(&ctx.region, &zone),
                state: Some("available".into()),
                create_time: Some(ctx.received_at),
                attachments: Some(Vec::new()),
                volume_type: Some(volume_type.clone()),
                iops,
                throughput,
                encrypted: Some(encrypted),
                kms_key_id: encrypted.then(|| {
                    input
                        .kms_key_id
                        .clone()
                        .or_else(|| snapshot.as_ref().and_then(|s| s.kms_key_id.clone()))
                        .unwrap_or_else(|| default_kms_key(ctx, &account, r))
                }),
                multi_attach_enabled: Some(input.multi_attach_enabled.unwrap_or(false)),
                fast_restored: Some(fast),
                tags: some_tags(tags),
                ..Default::default()
            };
            r.volumes.insert(id.clone(), volume.clone());
            if let Some(token) = input.client_token.clone().filter(|t| !t.is_empty()) {
                r.volume_tokens.insert(token, id.clone());
            }
            volume
        });
        self.volume_job(VolumeJob::Create {
            volume_id: id.clone(),
            snapshot_id: Some(snapshot_id).filter(|s| !s.is_empty()),
        });
        let mut shown = volume;
        shown.state = Some("creating".into());
        shown.attachments = None;
        Ok(shown)
    }

    pub(crate) fn copy_volumes_op(
        &self,
        ctx: &RequestContext,
        input: t::CopyVolumesRequest,
    ) -> Result<t::CopyVolumesResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "volume", &["volume"])?;
        let source = self.volume_authorize(ctx, "CopyVolumes", &input.source_volume_id, None)?;
        authorize(ctx, "CopyVolumes", &[(arn(ctx, &account, "volume/*"), request_tag_context(&tags))], input.dry_run)?;
        if let Some(token) = input.client_token.as_deref().filter(|t| !t.is_empty()) {
            let existing =
                self.with_region(ctx, |r| r.volume_tokens.get(token).and_then(|id| r.volumes.get(id)).cloned());
            if let Some(v) = existing {
                return Ok(t::CopyVolumesResult { volumes: Some(vec![v]) });
            }
        }
        let size = input.size.unwrap_or(source.size.unwrap_or(1));
        if size < source.size.unwrap_or(0) {
            return Err(invalid_parameter(format!(
                "Volume of {size}GiB is too small; minimum is {}GiB.",
                source.size.unwrap_or(0)
            )));
        }
        let volume_type = input.volume_type.clone().or(source.volume_type.clone()).unwrap_or_else(|| "gp2".into());
        let keep = |new: Option<i32>, old: Option<i32>| new.or(if input.volume_type.is_some() { None } else { old });
        let (iops, throughput) = check_volume_shape(
            &volume_type,
            size,
            if volume_type == "gp2" { None } else { keep(input.iops, source.iops) },
            if volume_type == "gp3" { keep(input.throughput, source.throughput) } else { None },
        )?;
        let id = new_id("vol");
        let encrypted = input.encrypted.unwrap_or(false) || source.encrypted == Some(true);
        let mut volume = t::Volume {
            volume_id: Some(id.clone()),
            size: Some(size),
            snapshot_id: Some(String::new()),
            source_volume_id: Some(input.source_volume_id.clone()),
            availability_zone: source.availability_zone.clone(),
            availability_zone_id: source.availability_zone_id.clone(),
            state: Some("available".into()),
            create_time: Some(ctx.received_at),
            attachments: Some(Vec::new()),
            volume_type: Some(volume_type),
            iops,
            throughput,
            encrypted: Some(encrypted),
            kms_key_id: if encrypted { input.kms_key_id.clone().or(source.kms_key_id.clone()) } else { None },
            multi_attach_enabled: Some(input.multi_attach_enabled.unwrap_or(false)),
            fast_restored: Some(false),
            tags: some_tags(tags),
            ..Default::default()
        };
        self.with_region(ctx, |r| {
            if volume.encrypted == Some(true) && volume.kms_key_id.is_none() {
                volume.kms_key_id = Some(default_kms_key(ctx, &account, r));
            }
            r.volumes.insert(id.clone(), volume.clone());
            if let Some(token) = input.client_token.clone().filter(|t| !t.is_empty()) {
                r.volume_tokens.insert(token, id.clone());
            }
        });
        // A copy is a snapshot of the source restored at once.
        self.volume_job(VolumeJob::Snapshot { volume_id: input.source_volume_id.clone(), snapshot_id: id.clone() });
        volume.state = Some("creating".into());
        volume.attachments = None;
        Ok(t::CopyVolumesResult { volumes: Some(vec![volume]) })
    }

    pub(crate) fn volume_authorize(
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
        self.with_region(ctx, |r| {
            r.volumes.remove(&input.volume_id);
            r.volume_modifications.remove(&input.volume_id);
            r.volume_auto_enable_io.remove(&input.volume_id);
            r.volume_tokens.retain(|_, id| id != &input.volume_id);
        });
        self.volume_job(VolumeJob::Delete(input.volume_id.clone()));
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
        let device_ok = input.device.starts_with("/dev/sd")
            || input.device.starts_with("/dev/xvd")
            || input.device.starts_with("/dev/hd")
            || input.device.starts_with("xvd")
            || input.device.starts_with("sd");
        if !device_ok || input.device.len() > 32 {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter device is invalid. {} is not a valid EBS device name.",
                input.device, input.device
            )));
        }
        let now = ctx.received_at;
        let shown = self.with_region(ctx, |r| {
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
            if v.attachments.iter().flatten().any(|a| a.instance_id.as_deref() == Some(input.instance_id.as_str())) {
                return Err(err(
                    "VolumeInUse",
                    format!("{} is already attached to {}", input.volume_id, input.instance_id),
                ));
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
        })?;
        self.volume_job(VolumeJob::Sync {
            account,
            region: ctx.region.clone(),
            instance_id: input.instance_id.clone(),
        });
        Ok(shown)
    }

    pub(crate) fn detach_volume_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachVolumeRequest,
    ) -> Result<t::VolumeAttachment, ServiceError> {
        let v = self.volume_authorize(ctx, "DetachVolume", &input.volume_id, input.dry_run)?;
        let atts = v.attachments.clone().unwrap_or_default();
        if atts.len() > 1 && input.instance_id.is_none() {
            return Err(err(
                "InvalidParameterCombination",
                format!(
                    "Volume {} is attached to multiple instances. You must specify the instance ID.",
                    input.volume_id
                ),
            ));
        }
        let pos = atts
            .iter()
            .position(|a| {
                input.instance_id.as_ref().is_none_or(|i| a.instance_id.as_ref() == Some(i))
                    && input.device.as_ref().is_none_or(|d| a.device.as_ref() == Some(d))
            })
            .ok_or_else(|| match &input.instance_id {
                Some(i) if !atts.is_empty() => err(
                    "InvalidAttachment.NotFound",
                    format!("The volume '{}' is not attached to instance '{i}'.", input.volume_id),
                ),
                _ => err("IncorrectState", format!("Volume '{}' is in the 'available' state.", input.volume_id)),
            })?;
        let att = atts[pos].clone();
        let instance_id = att.instance_id.clone().unwrap_or_default();
        let shown = self.with_region(ctx, |r| {
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
        })?;
        self.volume_job(VolumeJob::Sync { account: account_of(ctx), region: ctx.region.clone(), instance_id });
        Ok(shown)
    }

    pub(crate) fn modify_volume_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVolumeRequest,
    ) -> Result<t::ModifyVolumeResult, ServiceError> {
        let v = self.volume_authorize(ctx, "ModifyVolume", &input.volume_id, input.dry_run)?;
        let now = ctx.received_at;
        let original_type = v.volume_type.clone().unwrap_or_else(|| "gp2".into());
        let target_type = input.volume_type.clone().unwrap_or(original_type.clone());
        let size = input.size.unwrap_or(v.size.unwrap_or(1));
        if size < v.size.unwrap_or(0) {
            return Err(invalid_parameter(format!(
                "New size cannot be smaller than existing size. Existing size: {}GiB, requested size: {size}GiB.",
                v.size.unwrap_or(0)
            )));
        }
        let changing_type = target_type != original_type;
        let (iops, throughput) = check_volume_shape(
            &target_type,
            size,
            match target_type.as_str() {
                "gp2" | "st1" | "sc1" | "standard" => None,
                _ => input.iops.or(if changing_type && target_type == "gp3" { None } else { v.iops }),
            },
            match target_type.as_str() {
                "gp3" => input.throughput.or(if changing_type { None } else { v.throughput }),
                _ => input.throughput,
            },
        )?;
        let multi = input.multi_attach_enabled.unwrap_or(v.multi_attach_enabled.unwrap_or(false));
        if multi && !matches!(target_type.as_str(), "io1" | "io2") {
            return Err(invalid_parameter(
                "The parameter multiAttachEnabled is only supported for io1 and io2 volumes.",
            ));
        }
        if size == v.size.unwrap_or(0)
            && !changing_type
            && iops == v.iops
            && throughput == v.throughput
            && Some(multi) == v.multi_attach_enabled
        {
            return Err(invalid_parameter(format!(
                "New size, IOPS, throughput, type, or Multi-Attach setting must be different from the existing ones for volume {}.",
                input.volume_id
            )));
        }
        self.with_region(ctx, |r| {
            if let Some(last) = r.volume_modifications.get(&input.volume_id) {
                let since = last.start_time.unwrap_or(now);
                if now < since + Duration::hours(MODIFICATION_COOLDOWN_HOURS) {
                    return Err(err(
                        "VolumeModificationRateExceeded",
                        "You've reached the maximum modification rate per volume limit. Wait at least 6 hours between modifications per EBS volume.",
                    ));
                }
            }
            let m = t::VolumeModification {
                volume_id: Some(input.volume_id.clone()),
                modification_state: Some("completed".into()),
                target_size: Some(size),
                target_iops: iops,
                target_volume_type: Some(target_type.clone()),
                target_throughput: throughput,
                target_multi_attach_enabled: Some(multi),
                original_size: v.size,
                original_iops: v.iops,
                original_volume_type: Some(original_type.clone()),
                original_throughput: v.throughput,
                original_multi_attach_enabled: v.multi_attach_enabled,
                progress: Some(100),
                start_time: Some(now),
                end_time: Some(now),
                ..Default::default()
            };
            r.volume_modifications.insert(input.volume_id.clone(), m.clone());
            let vol = r.volumes.get_mut(&input.volume_id).expect("checked");
            vol.size = Some(size);
            vol.volume_type = Some(target_type.clone());
            vol.iops = iops;
            vol.throughput = throughput;
            vol.multi_attach_enabled = Some(multi);
            let mut shown = m;
            shown.modification_state = Some("modifying".into());
            shown.progress = Some(0);
            shown.end_time = None;
            Ok(t::ModifyVolumeResult { volume_modification: Some(shown) })
        })
    }

    pub(crate) fn describe_volumes_modifications_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVolumesModificationsRequest,
    ) -> Result<t::DescribeVolumesModificationsResult, ServiceError> {
        authorize(ctx, "DescribeVolumesModifications", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.volume_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Volume.check_all(&ids, |id| r.volumes.contains_key(id))?;
            for id in &ids {
                if !r.volume_modifications.contains_key(id) {
                    return Err(err(
                        "InvalidVolumeModification.NotFound",
                        format!("Modification for volume '{id}' does not exist."),
                    ));
                }
            }
            let mut out = Vec::new();
            for (id, m) in &r.volume_modifications {
                if !ids.is_empty() && !ids.contains(id) {
                    continue;
                }
                if filters.matches(None, |n| modification_filter(m, n))? {
                    out.push(m.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeVolumesModificationsResult { volumes_modifications: Some(items), next_token })
        })
    }

    pub(crate) fn describe_volume_status_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVolumeStatusRequest,
    ) -> Result<t::DescribeVolumeStatusResult, ServiceError> {
        authorize(ctx, "DescribeVolumeStatus", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.volume_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Volume.check_all(&ids, |id| r.volumes.contains_key(id))?;
            let mut out = Vec::new();
            for v in r.volumes.values() {
                let id = v.volume_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let item = t::VolumeStatusItem {
                    volume_id: Some(id.clone()),
                    availability_zone: v.availability_zone.clone(),
                    availability_zone_id: v.availability_zone_id.clone(),
                    volume_status: Some(t::VolumeStatusInfo {
                        status: Some("ok".into()),
                        details: Some(vec![
                            t::VolumeStatusDetails { name: Some("io-enabled".into()), status: Some("passed".into()) },
                            t::VolumeStatusDetails {
                                name: Some("io-performance".into()),
                                status: Some("not-applicable".into()),
                            },
                        ]),
                    }),
                    actions: Some(Vec::new()),
                    events: Some(Vec::new()),
                    attachment_statuses: Some(
                        v.attachments
                            .iter()
                            .flatten()
                            .map(|a| t::VolumeStatusAttachmentStatus {
                                instance_id: a.instance_id.clone(),
                                io_performance: Some("not-applicable".into()),
                            })
                            .collect(),
                    ),
                    ..Default::default()
                };
                let ok = filters.matches(None, |n| {
                    Some(match n {
                        "availability-zone" => s(&v.availability_zone),
                        "volume-status.status" => vec!["ok".into()],
                        "volume-status.details-name" => vec!["io-enabled".into(), "io-performance".into()],
                        "volume-status.details-status" => vec!["passed".into(), "not-applicable".into()],
                        "action.code" | "action.description" | "action.event-id" => Vec::new(),
                        "event.description" | "event.event-id" | "event.event-type" | "event.not-after"
                        | "event.not-before" => Vec::new(),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(item);
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeVolumeStatusResult { volume_statuses: Some(items), next_token })
        })
    }

    pub(crate) fn describe_volume_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVolumeAttributeRequest,
    ) -> Result<t::DescribeVolumeAttributeResult, ServiceError> {
        self.volume_authorize(ctx, "DescribeVolumeAttribute", &input.volume_id, input.dry_run)?;
        let mut out =
            t::DescribeVolumeAttributeResult { volume_id: Some(input.volume_id.clone()), ..Default::default() };
        match input.attribute.as_str() {
            "autoEnableIO" => {
                let v = self.with_region(ctx, |r| r.volume_auto_enable_io.get(&input.volume_id).copied());
                out.auto_enable_io = Some(t::AttributeBooleanValue { value: Some(v.unwrap_or(false)) });
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

    pub(crate) fn modify_volume_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVolumeAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.volume_authorize(ctx, "ModifyVolumeAttribute", &input.volume_id, input.dry_run)?;
        let Some(v) = input.auto_enable_io.as_ref().and_then(|a| a.value) else {
            return Err(err("MissingParameter", "The request must contain the parameter AutoEnableIO"));
        };
        self.with_region(ctx, |r| r.volume_auto_enable_io.insert(input.volume_id.clone(), v));
        Ok(())
    }

    pub(crate) fn enable_volume_io_op(
        &self,
        ctx: &RequestContext,
        input: t::EnableVolumeIORequest,
    ) -> Result<(), ServiceError> {
        self.volume_authorize(ctx, "EnableVolumeIO", &input.volume_id, input.dry_run)?;
        Ok(())
    }

    pub(crate) fn list_volumes_in_recycle_bin_op(
        &self,
        ctx: &RequestContext,
        input: t::ListVolumesInRecycleBinRequest,
    ) -> Result<t::ListVolumesInRecycleBinResult, ServiceError> {
        authorize(ctx, "ListVolumesInRecycleBin", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        for id in input.volume_ids.iter().flatten() {
            Kind::Volume.check(id)?;
        }
        // No Recycle Bin retention rules exist, so deleted volumes are gone.
        Ok(t::ListVolumesInRecycleBinResult { volumes: Some(Vec::new()), next_token: None })
    }

    pub(crate) fn restore_volume_from_recycle_bin_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreVolumeFromRecycleBinRequest,
    ) -> Result<t::RestoreVolumeFromRecycleBinResult, ServiceError> {
        Kind::Volume.check(&input.volume_id)?;
        authorize(
            ctx,
            "RestoreVolumeFromRecycleBin",
            &[(arn(ctx, &account_of(ctx), &format!("volume/{}", input.volume_id)), ConditionContext::new())],
            input.dry_run,
        )?;
        Err(Kind::Volume.not_found(&input.volume_id))
    }
}
