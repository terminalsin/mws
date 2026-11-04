//! AMIs. The public catalogue (Amazon Linux, Ubuntu, Debian, Alpine) maps
//! each AMI to a container image; `CreateImage` captures an instance's
//! container as a new image; `RegisterImage` with an `ImageLocation` of
//! `docker:<image>` makes any container image launchable as an AMI (run
//! with its own entrypoint).

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::catalog;
use crate::generated::types as t;
use crate::state::{ImageRecord, State};
use crate::util::{
    authorize, err, invalid_parameter, missing_parameter, new_id, paginate, request_tag_context, resource_tag_context,
    s, some_tags, tags_for, Filters, Kind,
};
use crate::{account_of, Ec2};

/// The container image MWS boots for AMIs it cannot otherwise map.
pub const FALLBACK_CONTAINER_IMAGE: &str = "amazonlinux:2023";

pub fn image_arn(ctx: &RequestContext, region: &str, id: &str) -> String {
    format!("arn:{}:ec2:{region}::image/{id}", ctx.partition)
}

/// An image the caller can see: `(owner account or None for public, record)`.
pub struct Found {
    pub owner: Option<String>,
    pub record: ImageRecord,
}

fn public_record(region: &str, img: &catalog::PublicImage) -> ImageRecord {
    ImageRecord {
        image: catalog::public_image_shape(region, img),
        container_image: img.container_image.into(),
        boot: true,
        owned_container_image: false,
        launch_users: Vec::new(),
        launch_public: true,
    }
}

fn can_launch(rec: &ImageRecord, owner: &str, caller: &str) -> bool {
    owner == caller || rec.launch_public || rec.launch_users.iter().any(|u| u == caller)
}

/// Every image visible to `caller` in `region`.
fn visible(state: &State, region: &str, caller: &str) -> Vec<Found> {
    let mut out: Vec<Found> =
        catalog::PUBLIC_IMAGES.iter().map(|i| Found { owner: None, record: public_record(region, i) }).collect();
    for (key, r) in &state.regions {
        let Some((account, reg)) = key.split_once('/') else { continue };
        if reg != region {
            continue;
        }
        for rec in r.images.values() {
            if can_launch(rec, account, caller) {
                out.push(Found { owner: Some(account.to_string()), record: rec.clone() });
            }
        }
    }
    out
}

impl Ec2 {
    /// Look up an image the caller may use.
    pub(crate) fn find_image(&self, ctx: &RequestContext, id: &str) -> Result<Found, ServiceError> {
        Kind::Image.check(id)?;
        let caller = account_of(ctx);
        if let Some(img) = catalog::public_image(&ctx.region, id) {
            return Ok(Found { owner: None, record: public_record(&ctx.region, img) });
        }
        // Make sure the caller's own Region state exists.
        self.with_region(ctx, |_| ());
        let state = self.lock();
        visible(&state, &ctx.region, &caller)
            .into_iter()
            .find(|f| f.record.image.image_id.as_deref() == Some(id))
            .ok_or_else(|| Kind::Image.not_found(id))
    }

    pub(crate) fn describe_images_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeImagesRequest,
    ) -> Result<t::DescribeImagesResult, ServiceError> {
        authorize(ctx, "DescribeImages", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let caller = account_of(ctx);
        let filters = Filters::new(&input.filters);
        let ids = input.image_ids.clone().unwrap_or_default();
        for id in &ids {
            Kind::Image.check(id)?;
        }
        let owners = input.owners.clone().unwrap_or_default();
        self.with_region(ctx, |_| ());
        let all = visible(&self.lock(), &ctx.region, &caller);
        for id in &ids {
            if !all.iter().any(|f| f.record.image.image_id.as_deref() == Some(id.as_str())) {
                return Err(Kind::Image.not_found(id));
            }
        }
        let mut out = Vec::new();
        for f in all {
            let img = &f.record.image;
            if !ids.is_empty() && !ids.iter().any(|i| Some(i) == img.image_id.as_ref()) {
                continue;
            }
            let owner_id = img.owner_id.clone().unwrap_or_default();
            if !owners.is_empty() {
                let matches = owners.iter().any(|o| match o.as_str() {
                    "self" => owner_id == caller,
                    other => other == owner_id || img.image_owner_alias.as_deref() == Some(other),
                });
                if !matches {
                    continue;
                }
            }
            if let Some(users) = &input.executable_users {
                let ok = users.iter().any(|u| match u.as_str() {
                    "self" => can_launch(&f.record, f.owner.as_deref().unwrap_or("public"), &caller),
                    "all" => f.record.launch_public,
                    other => f.record.launch_users.iter().any(|x| x == other) || f.record.launch_public,
                });
                if !ok {
                    continue;
                }
            }
            let bdm = img.block_device_mappings.clone().unwrap_or_default();
            let ok = filters.matches(img.tags.as_ref(), |name| {
                Some(match name {
                    "architecture" => s(&img.architecture),
                    "description" => s(&img.description),
                    "image-id" => s(&img.image_id),
                    "image-type" => s(&img.image_type),
                    "is-public" => img.public.map(|p| p.to_string()).into_iter().collect(),
                    "name" => s(&img.name),
                    "owner-alias" => s(&img.image_owner_alias),
                    "owner-id" => vec![owner_id.clone()],
                    "platform" => s(&img.platform),
                    "platform-details" => s(&img.platform_details),
                    "root-device-name" => s(&img.root_device_name),
                    "root-device-type" => s(&img.root_device_type),
                    "state" => s(&img.state),
                    "virtualization-type" => s(&img.virtualization_type),
                    "hypervisor" => s(&img.hypervisor),
                    "ena-support" => img.ena_support.map(|p| p.to_string()).into_iter().collect(),
                    "creation-date" => s(&img.creation_date),
                    "source-instance-id" => s(&img.source_instance_id),
                    "block-device-mapping.device-name" => bdm.iter().filter_map(|b| b.device_name.clone()).collect(),
                    "block-device-mapping.snapshot-id" => {
                        bdm.iter().filter_map(|b| b.ebs.as_ref().and_then(|e| e.snapshot_id.clone())).collect()
                    }
                    "block-device-mapping.volume-type" => {
                        bdm.iter().filter_map(|b| b.ebs.as_ref().and_then(|e| e.volume_type.clone())).collect()
                    }
                    "block-device-mapping.volume-size" => bdm
                        .iter()
                        .filter_map(|b| b.ebs.as_ref().and_then(|e| e.volume_size.map(|v| v.to_string())))
                        .collect(),
                    _ => return None,
                })
            })?;
            if ok {
                out.push(img.clone());
            }
        }
        let (images, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribeImagesResult { images: Some(images), next_token })
    }

    fn check_new_image_name(&self, ctx: &RequestContext, name: &str) -> Result<(), ServiceError> {
        let valid = (3..=128).contains(&name.chars().count())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || "()[] ./-'@_".contains(c));
        if !valid {
            return Err(err(
                "InvalidAMIName.Malformed",
                "AMI names must be between 3 and 128 characters long, and may contain letters, numbers, '(', ')', '.', '-', '/' and '_'".to_string(),
            ));
        }
        self.with_region(ctx, |r| {
            if let Some(existing) = r.images.values().find(|i| i.image.name.as_deref() == Some(name)) {
                return Err(err(
                    "InvalidAMIName.Duplicate",
                    format!(
                        "AMI name {name} is already in use by AMI {}",
                        existing.image.image_id.clone().unwrap_or_default()
                    ),
                ));
            }
            Ok(())
        })
    }

    pub(crate) fn register_image_op(
        &self,
        ctx: &RequestContext,
        input: t::RegisterImageRequest,
    ) -> Result<t::RegisterImageResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "image", &["image", "snapshot"])?;
        authorize(
            ctx,
            "RegisterImage",
            &[(image_arn(ctx, &ctx.region, "*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        self.check_new_image_name(ctx, &input.name)?;
        let docker = input
            .image_location
            .as_deref()
            .and_then(|l| l.strip_prefix("docker://").or_else(|| l.strip_prefix("docker:")))
            .map(str::to_string);
        if docker.is_none()
            && input.image_location.is_none()
            && input.block_device_mappings.as_ref().is_none_or(|b| b.is_empty())
        {
            return Err(missing_parameter("ImageLocation"));
        }
        let now = ctx.received_at;
        let id = new_id("ami");
        let root = input.root_device_name.clone().unwrap_or_else(|| "/dev/xvda".into());
        let image = t::Image {
            image_id: Some(id.clone()),
            image_location: Some(input.image_location.clone().unwrap_or_else(|| format!("{account}/{}", input.name))),
            state: Some("available".into()),
            owner_id: Some(account.clone()),
            creation_date: Some(now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
            public: Some(false),
            architecture: Some(input.architecture.clone().unwrap_or_else(|| "x86_64".into())),
            image_type: Some("machine".into()),
            name: Some(input.name.clone()),
            description: input.description.clone(),
            root_device_name: Some(root),
            root_device_type: Some(if input.block_device_mappings.is_some() { "ebs" } else { "instance-store" }.into()),
            virtualization_type: Some(input.virtualization_type.clone().unwrap_or_else(|| "hvm".into())),
            hypervisor: Some("xen".into()),
            ena_support: input.ena_support,
            sriov_net_support: input.sriov_net_support.clone(),
            boot_mode: input.boot_mode.clone(),
            imds_support: input.imds_support.clone(),
            platform_details: Some("Linux/UNIX".into()),
            usage_operation: Some("RunInstances".into()),
            block_device_mappings: Some(
                input
                    .block_device_mappings
                    .iter()
                    .flatten()
                    .map(|b| t::BlockDeviceMapping {
                        device_name: b.device_name.clone(),
                        virtual_name: b.virtual_name.clone(),
                        no_device: b.no_device.clone(),
                        ebs: b.ebs.clone(),
                    })
                    .collect(),
            ),
            tags: some_tags(tags),
            ..Default::default()
        };
        let boot = docker.is_none();
        let container_image = docker.unwrap_or_else(|| FALLBACK_CONTAINER_IMAGE.into());
        self.with_region(ctx, |r| {
            r.images.insert(
                id.clone(),
                ImageRecord {
                    image,
                    container_image,
                    boot,
                    owned_container_image: false,
                    launch_users: Vec::new(),
                    launch_public: false,
                },
            );
        });
        Ok(t::RegisterImageResult { image_id: Some(id) })
    }

    pub(crate) async fn create_image_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateImageRequest,
    ) -> Result<t::CreateImageResult, ServiceError> {
        let account = account_of(ctx);
        Kind::Instance.check(&input.instance_id)?;
        let tags = tags_for(&input.tag_specifications, "image", &["image", "snapshot"])?;
        let inst_tags = self.with_region(ctx, |r| r.instances.get(&input.instance_id).map(|i| i.instance.tags.clone()));
        let inst_tags = inst_tags.ok_or_else(|| Kind::Instance.not_found(&input.instance_id))?;
        authorize(
            ctx,
            "CreateImage",
            &[
                (image_arn(ctx, &ctx.region, "*"), request_tag_context(&tags)),
                (
                    crate::util::arn(ctx, &account, &format!("instance/{}", input.instance_id)),
                    resource_tag_context(inst_tags.as_ref()),
                ),
            ],
            input.dry_run,
        )?;
        self.check_new_image_name(ctx, &input.name)?;
        let now = ctx.received_at;
        let id = new_id("ami");
        let (handle, source) = self.with_region(ctx, |r| {
            let rec =
                r.instances.get(&input.instance_id).ok_or_else(|| Kind::Instance.not_found(&input.instance_id))?;
            let state = rec.instance.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default();
            if !matches!(state.as_str(), "running" | "stopped") {
                return Err(err(
                    "IncorrectInstanceState",
                    format!("The instance '{}' is not in a valid state for this operation.", input.instance_id),
                ));
            }
            let i = &rec.instance;
            let image = t::Image {
                image_id: Some(id.clone()),
                image_location: Some(format!("{account}/{}", input.name)),
                state: Some("pending".into()),
                owner_id: Some(account.clone()),
                creation_date: Some(now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
                public: Some(false),
                architecture: i.architecture.clone(),
                image_type: Some("machine".into()),
                name: Some(input.name.clone()),
                description: input.description.clone(),
                root_device_name: i.root_device_name.clone(),
                root_device_type: Some("ebs".into()),
                virtualization_type: Some("hvm".into()),
                hypervisor: Some("xen".into()),
                ena_support: Some(true),
                platform_details: Some("Linux/UNIX".into()),
                usage_operation: Some("RunInstances".into()),
                source_instance_id: Some(input.instance_id.clone()),
                block_device_mappings: Some(vec![t::BlockDeviceMapping {
                    device_name: i.root_device_name.clone(),
                    ebs: Some(t::EbsBlockDevice {
                        delete_on_termination: Some(true),
                        snapshot_id: Some(new_id("snap")),
                        volume_size: Some(8),
                        volume_type: Some("gp3".into()),
                        encrypted: Some(false),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                tags: some_tags(tags),
                ..Default::default()
            };
            let source = (rec.container_image.clone(), rec.boot);
            let handle = rec.handle.clone();
            r.images.insert(
                id.clone(),
                ImageRecord {
                    image,
                    container_image: source.0.clone(),
                    boot: source.1,
                    owned_container_image: false,
                    launch_users: Vec::new(),
                    launch_public: false,
                },
            );
            Ok((handle, source))
        })?;
        let this = self.clone();
        let account2 = account.clone();
        let region = ctx.region.clone();
        let ctx2 = ctx.clone();
        let id2 = id.clone();
        let backend = self.backend();
        let spawn = handle.is_some();
        let task = async move {
            let result = match &handle {
                Some(h) => backend.create_image(h, &format!("mws-ec2/{id2}:latest")).await.map(Some),
                None => Ok(None),
            };
            this.with_region_of(&account2, &region, &ctx2, |r| {
                if let Some(rec) = r.images.get_mut(&id2) {
                    match result {
                        Ok(made) => {
                            rec.image.state = Some("available".into());
                            if let Some(made) = made {
                                rec.container_image = made;
                                rec.owned_container_image = true;
                            } else {
                                rec.container_image = source.0.clone();
                            }
                        }
                        Err(e) => {
                            tracing::warn!(image = %id2, "creating the image failed: {e}");
                            rec.image.state = Some("failed".into());
                            rec.image.state_reason = Some(t::StateReason {
                                code: Some("Client.InternalError".into()),
                                message: Some(format!("Client.InternalError: {e}")),
                            });
                        }
                    }
                }
            });
        };
        if spawn {
            tokio::spawn(task);
        } else {
            task.await;
        }
        Ok(t::CreateImageResult { image_id: Some(id) })
    }

    pub(crate) fn copy_image_op(
        &self,
        ctx: &RequestContext,
        input: t::CopyImageRequest,
    ) -> Result<t::CopyImageResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "image", &["image", "snapshot"])?;
        authorize(ctx, "CopyImage", &[(image_arn(ctx, &ctx.region, "*"), request_tag_context(&tags))], input.dry_run)?;
        Kind::Image.check(&input.source_image_id)?;
        if !catalog::REGIONS.contains(&input.source_region.as_str()) {
            return Err(invalid_parameter(format!("Invalid region: {}", input.source_region)));
        }
        let mut source_ctx = ctx.clone();
        source_ctx.region = input.source_region.clone();
        let source = self.find_image(&source_ctx, &input.source_image_id)?;
        self.check_new_image_name(ctx, &input.name)?;
        let id = new_id("ami");
        let mut image = source.record.image.clone();
        image.image_id = Some(id.clone());
        image.name = Some(input.name.clone());
        image.description = input.description.clone().or(image.description);
        image.owner_id = Some(account.clone());
        image.image_owner_alias = None;
        image.public = Some(false);
        image.source_image_id = Some(input.source_image_id.clone());
        image.source_image_region = Some(input.source_region.clone());
        image.creation_date = Some(ctx.received_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());
        let mut all_tags =
            if input.copy_image_tags == Some(true) { image.tags.clone().unwrap_or_default() } else { Vec::new() };
        all_tags.extend(tags);
        image.tags = some_tags(all_tags);
        image.deprecation_time = None;
        let record = ImageRecord {
            image,
            container_image: source.record.container_image,
            boot: source.record.boot,
            owned_container_image: false,
            launch_users: Vec::new(),
            launch_public: false,
        };
        self.with_region(ctx, |r| r.images.insert(id.clone(), record));
        Ok(t::CopyImageResult { image_id: Some(id) })
    }

    pub(crate) fn deregister_image_op(
        &self,
        ctx: &RequestContext,
        input: t::DeregisterImageRequest,
    ) -> Result<t::DeregisterImageResult, ServiceError> {
        Kind::Image.check(&input.image_id)?;
        let tags = self.with_region(ctx, |r| r.images.get(&input.image_id).map(|i| i.image.tags.clone()));
        let Some(tags) = tags else {
            // A public image, or someone else's.
            return Err(match self.find_image(ctx, &input.image_id) {
                Ok(_) => err("AuthFailure", format!("Not authorized for image:{}", input.image_id)),
                Err(e) => e,
            });
        };
        authorize(
            ctx,
            "DeregisterImage",
            &[(image_arn(ctx, &ctx.region, &input.image_id), resource_tag_context(tags.as_ref()))],
            input.dry_run,
        )?;
        let removed = self.with_region(ctx, |r| r.images.remove(&input.image_id));
        if let Some(rec) = removed.filter(|r| r.owned_container_image) {
            let backend = self.backend();
            tokio::spawn(async move {
                if let Err(e) = backend.delete_image(&rec.container_image).await {
                    tracing::debug!("removing image {}: {e}", rec.container_image);
                }
            });
        }
        Ok(t::DeregisterImageResult { r#return: Some(true), delete_snapshot_results: None })
    }

    pub(crate) fn describe_image_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeImageAttributeRequest,
    ) -> Result<t::ImageAttribute, ServiceError> {
        authorize(
            ctx,
            "DescribeImageAttribute",
            &[(image_arn(ctx, &ctx.region, &input.image_id), ConditionContext::new())],
            input.dry_run,
        )?;
        let found = self.find_image(ctx, &input.image_id)?;
        let img = &found.record.image;
        let v = |s: &Option<String>| s.clone().map(|value| t::AttributeValue { value: Some(value) });
        let mut out = t::ImageAttribute { image_id: Some(input.image_id.clone()), ..Default::default() };
        match input.attribute.as_str() {
            "description" => out.description = Some(t::AttributeValue { value: img.description.clone() }),
            "kernel" => out.kernel_id = v(&img.kernel_id),
            "ramdisk" => out.ramdisk_id = v(&img.ramdisk_id),
            "launchPermission" => {
                let mut perms: Vec<t::LaunchPermission> = found
                    .record
                    .launch_users
                    .iter()
                    .map(|u| t::LaunchPermission { user_id: Some(u.clone()), ..Default::default() })
                    .collect();
                if found.record.launch_public {
                    perms.push(t::LaunchPermission { group: Some("all".into()), ..Default::default() });
                }
                out.launch_permissions = Some(perms);
            }
            "productCodes" => out.product_codes = Some(Vec::new()),
            "blockDeviceMapping" => out.block_device_mappings = img.block_device_mappings.clone(),
            "sriovNetSupport" => out.sriov_net_support = v(&img.sriov_net_support),
            "bootMode" => out.boot_mode = v(&img.boot_mode),
            "imdsSupport" => out.imds_support = v(&img.imds_support),
            "deregistrationProtection" => {
                out.deregistration_protection = Some(t::AttributeValue { value: Some("disabled".into()) })
            }
            "lastLaunchedTime" => out.last_launched_time = v(&img.last_launched_time),
            "tpmSupport" => out.tpm_support = v(&img.tpm_support),
            "uefiData" => out.uefi_data = Some(t::AttributeValue { value: None }),
            other => {
                return Err(invalid_parameter(format!(
                    "Value ({other}) for parameter attribute is invalid. Unknown attribute."
                )))
            }
        }
        Ok(out)
    }

    pub(crate) fn modify_image_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyImageAttributeRequest,
    ) -> Result<(), ServiceError> {
        Kind::Image.check(&input.image_id)?;
        authorize(
            ctx,
            "ModifyImageAttribute",
            &[(image_arn(ctx, &ctx.region, &input.image_id), ConditionContext::new())],
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let rec = r.images.get_mut(&input.image_id).ok_or_else(|| Kind::Image.not_found(&input.image_id))?;
            if let Some(d) = input.description.as_ref().and_then(|d| d.value.clone()) {
                rec.image.description = Some(d);
            }
            if let Some(v) = input.imds_support.as_ref().and_then(|d| d.value.clone()) {
                rec.image.imds_support = Some(v);
            }
            let mut add: Vec<t::LaunchPermission> = Vec::new();
            let mut remove: Vec<t::LaunchPermission> = Vec::new();
            if let Some(lp) = &input.launch_permission {
                add.extend(lp.add.iter().flatten().cloned());
                remove.extend(lp.remove.iter().flatten().cloned());
            }
            let legacy: Vec<t::LaunchPermission> = input
                .user_ids
                .iter()
                .flatten()
                .map(|u| t::LaunchPermission { user_id: Some(u.clone()), ..Default::default() })
                .chain(
                    input
                        .user_groups
                        .iter()
                        .flatten()
                        .map(|g| t::LaunchPermission { group: Some(g.clone()), ..Default::default() }),
                )
                .collect();
            match input.operation_type.as_deref() {
                Some("remove") => remove.extend(legacy),
                _ => add.extend(legacy),
            }
            for p in add {
                if p.group.as_deref() == Some("all") {
                    rec.launch_public = true;
                }
                if let Some(u) = p.user_id {
                    if !(u.len() == 12 && u.bytes().all(|b| b.is_ascii_digit())) {
                        return Err(err(
                            "InvalidAMIAttributeItemValue",
                            format!("Invalid attribute item value \"{u}\" for userId item type."),
                        ));
                    }
                    if !rec.launch_users.contains(&u) {
                        rec.launch_users.push(u);
                    }
                }
            }
            for p in remove {
                if p.group.as_deref() == Some("all") {
                    rec.launch_public = false;
                }
                if let Some(u) = p.user_id {
                    rec.launch_users.retain(|x| x != &u);
                }
            }
            rec.image.public = Some(rec.launch_public);
            Ok(())
        })
    }
}
