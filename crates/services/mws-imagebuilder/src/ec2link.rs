//! The EC2 calls Image Builder makes, through EC2's public API, as the
//! service-linked role.

use std::collections::BTreeMap;
use std::time::Duration;

use mws_core::{RequestContext, ServiceError};
use mws_ec2::generated::{types as e, Handler};

pub use mws_ec2::Ec2;

/// How long to wait for an instance or AMI to become ready.
const READY_TIMEOUT: Duration = Duration::from_secs(600);

fn tags(map: &BTreeMap<String, String>) -> Vec<e::Tag> {
    map.iter().map(|(k, v)| e::Tag { key: Some(k.clone()), value: Some(v.clone()) }).collect()
}

fn tag_spec(resource_type: &str, map: &BTreeMap<String, String>) -> Option<e::TagSpecification> {
    (!map.is_empty()).then(|| e::TagSpecification { resource_type: Some(resource_type.into()), tags: Some(tags(map)) })
}

/// An AMI the caller can see.
pub async fn describe_image(ec2: &Ec2, ctx: &RequestContext, image_id: &str) -> Option<e::Image> {
    let out = ec2
        .describe_images(ctx, e::DescribeImagesRequest { image_ids: Some(vec![image_id.into()]), ..Default::default() })
        .await
        .ok()?;
    out.images.and_then(|i| i.into_iter().next())
}

/// The id of the public AMI named `name`.
pub async fn public_image_by_name(ec2: &Ec2, ctx: &RequestContext, name: &str) -> Option<String> {
    let out = ec2
        .describe_images(
            ctx,
            e::DescribeImagesRequest {
                filters: Some(vec![e::Filter { name: Some("name".into()), values: Some(vec![name.into()]) }]),
                ..Default::default()
            },
        )
        .await
        .ok()?;
    out.images?.into_iter().find(|i| i.public == Some(true)).and_then(|i| i.image_id)
}

pub struct Launch<'a> {
    pub image_id: &'a str,
    pub instance_type: &'a str,
    pub subnet_id: Option<String>,
    pub security_group_ids: Option<Vec<String>>,
    pub key_name: Option<String>,
    pub instance_profile: &'a str,
    pub user_data: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub http_tokens: Option<String>,
    pub hop_limit: Option<i32>,
    pub availability_zone: Option<String>,
    pub tenancy: Option<String>,
}

pub async fn run_instance(ec2: &Ec2, ctx: &RequestContext, l: Launch<'_>) -> Result<String, ServiceError> {
    let metadata_options =
        (l.http_tokens.is_some() || l.hop_limit.is_some()).then(|| e::InstanceMetadataOptionsRequest {
            http_tokens: l.http_tokens.clone(),
            http_put_response_hop_limit: l.hop_limit,
            ..Default::default()
        });
    let placement = (l.availability_zone.is_some() || l.tenancy.is_some()).then(|| e::Placement {
        availability_zone: l.availability_zone.clone(),
        tenancy: l.tenancy.clone(),
        ..Default::default()
    });
    let req = e::RunInstancesRequest {
        image_id: Some(l.image_id.into()),
        instance_type: Some(l.instance_type.into()),
        min_count: 1,
        max_count: 1,
        subnet_id: l.subnet_id,
        security_group_ids: l.security_group_ids,
        key_name: l.key_name,
        user_data: l.user_data,
        iam_instance_profile: Some(e::IamInstanceProfileSpecification {
            name: (!l.instance_profile.starts_with("arn:")).then(|| l.instance_profile.to_string()),
            arn: l.instance_profile.starts_with("arn:").then(|| l.instance_profile.to_string()),
        }),
        tag_specifications: Some(tag_spec("instance", &l.tags).into_iter().collect()),
        metadata_options,
        placement,
        ..Default::default()
    };
    let r = ec2.run_instances(ctx, req).await?;
    r.instances
        .and_then(|i| i.into_iter().next())
        .and_then(|i| i.instance_id)
        .ok_or_else(|| ServiceError::internal("RunInstances returned no instance"))
}

/// Wait for an instance to reach `running`.
pub async fn wait_running(ec2: &Ec2, ctx: &RequestContext, instance_id: &str) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        let out = ec2
            .describe_instances(
                ctx,
                e::DescribeInstancesRequest { instance_ids: Some(vec![instance_id.into()]), ..Default::default() },
            )
            .await
            .map_err(|e| e.message)?;
        let state = out
            .reservations
            .into_iter()
            .flatten()
            .flat_map(|r| r.instances.unwrap_or_default())
            .find(|i| i.instance_id.as_deref() == Some(instance_id))
            .and_then(|i| i.state)
            .and_then(|s| s.name)
            .unwrap_or_default();
        match state.as_str() {
            "running" => return Ok(()),
            "pending" => {}
            other => return Err(format!("The instance {instance_id} entered state '{other}' while starting.")),
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("The instance {instance_id} did not start in time."));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub async fn create_image(
    ec2: &Ec2,
    ctx: &RequestContext,
    instance_id: &str,
    name: &str,
    description: Option<String>,
    ami_tags: &BTreeMap<String, String>,
) -> Result<String, ServiceError> {
    let out = ec2
        .create_image(
            ctx,
            e::CreateImageRequest {
                instance_id: instance_id.into(),
                name: name.into(),
                description,
                tag_specifications: tag_spec("image", ami_tags).map(|t| vec![t]),
                ..Default::default()
            },
        )
        .await?;
    out.image_id.ok_or_else(|| ServiceError::internal("CreateImage returned no image"))
}

/// Wait for an AMI to become `available`.
pub async fn wait_available(ec2: &Ec2, ctx: &RequestContext, image_id: &str) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        match describe_image(ec2, ctx, image_id).await.and_then(|i| i.state).as_deref() {
            Some("available") => return Ok(()),
            Some("pending") | None => {}
            Some(other) => return Err(format!("The AMI {image_id} entered state '{other}'.")),
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("The AMI {image_id} did not become available in time."));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub async fn terminate(ec2: &Ec2, ctx: &RequestContext, instance_id: &str) -> Result<(), ServiceError> {
    ec2.terminate_instances(
        ctx,
        e::TerminateInstancesRequest { instance_ids: vec![instance_id.into()], ..Default::default() },
    )
    .await
    .map(drop)
}

pub async fn copy_image(
    ec2: &Ec2,
    ctx: &RequestContext,
    source_region: &str,
    source_image_id: &str,
    name: &str,
    description: Option<String>,
    kms_key_id: Option<String>,
) -> Result<String, ServiceError> {
    let out = ec2
        .copy_image(
            ctx,
            e::CopyImageRequest {
                name: name.into(),
                source_image_id: source_image_id.into(),
                source_region: source_region.into(),
                description,
                encrypted: kms_key_id.as_ref().map(|_| true),
                kms_key_id,
                ..Default::default()
            },
        )
        .await?;
    out.image_id.ok_or_else(|| ServiceError::internal("CopyImage returned no image"))
}

/// Add a version of a launch template that launches `image_id`, based on
/// the template's latest version, and make it the default when asked.
/// Returns the new version number.
pub async fn update_launch_template(
    ec2: &Ec2,
    ctx: &RequestContext,
    launch_template_id: &str,
    image_id: &str,
    description: &str,
    set_default: bool,
) -> Result<i64, ServiceError> {
    let out = ec2
        .create_launch_template_version(
            ctx,
            e::CreateLaunchTemplateVersionRequest {
                launch_template_id: Some(launch_template_id.into()),
                source_version: Some("$Latest".into()),
                version_description: Some(description.into()),
                launch_template_data: e::RequestLaunchTemplateData {
                    image_id: Some(image_id.into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await?;
    let version = out
        .launch_template_version
        .and_then(|v| v.version_number)
        .ok_or_else(|| ServiceError::internal("CreateLaunchTemplateVersion returned no version"))?;
    if set_default {
        ec2.modify_launch_template(
            ctx,
            e::ModifyLaunchTemplateRequest {
                launch_template_id: Some(launch_template_id.into()),
                default_version: Some(version.to_string()),
                ..Default::default()
            },
        )
        .await?;
    }
    Ok(version)
}

pub async fn add_launch_permissions(
    ec2: &Ec2,
    ctx: &RequestContext,
    image_id: &str,
    user_ids: &[String],
    groups: &[String],
    organization_arns: &[String],
    ou_arns: &[String],
) -> Result<(), ServiceError> {
    let mut add: Vec<e::LaunchPermission> = Vec::new();
    add.extend(user_ids.iter().map(|u| e::LaunchPermission { user_id: Some(u.clone()), ..Default::default() }));
    add.extend(groups.iter().map(|g| e::LaunchPermission { group: Some(g.clone()), ..Default::default() }));
    add.extend(
        organization_arns
            .iter()
            .map(|o| e::LaunchPermission { organization_arn: Some(o.clone()), ..Default::default() }),
    );
    add.extend(
        ou_arns.iter().map(|o| e::LaunchPermission { organizational_unit_arn: Some(o.clone()), ..Default::default() }),
    );
    if add.is_empty() {
        return Ok(());
    }
    ec2.modify_image_attribute(
        ctx,
        e::ModifyImageAttributeRequest {
            image_id: image_id.into(),
            launch_permission: Some(e::LaunchPermissionModifications { add: Some(add), remove: None }),
            ..Default::default()
        },
    )
    .await
}

pub async fn create_tags(
    ec2: &Ec2,
    ctx: &RequestContext,
    resource: &str,
    map: &BTreeMap<String, String>,
) -> Result<(), ServiceError> {
    if map.is_empty() {
        return Ok(());
    }
    ec2.create_tags(ctx, e::CreateTagsRequest { resources: vec![resource.into()], tags: tags(map), dry_run: None })
        .await
}

pub async fn deregister(ec2: &Ec2, ctx: &RequestContext, image_id: &str) -> Result<(), ServiceError> {
    ec2.deregister_image(
        ctx,
        e::DeregisterImageRequest { image_id: image_id.into(), delete_associated_snapshots: Some(true), dry_run: None },
    )
    .await
    .map(drop)
}

pub async fn subnet_exists(ec2: &Ec2, ctx: &RequestContext, subnet_id: &str) -> bool {
    ec2.describe_subnets(
        ctx,
        e::DescribeSubnetsRequest { subnet_ids: Some(vec![subnet_id.into()]), ..Default::default() },
    )
    .await
    .is_ok_and(|o| !o.subnets.unwrap_or_default().is_empty())
}

pub async fn security_groups_exist(ec2: &Ec2, ctx: &RequestContext, ids: &[String]) -> bool {
    ids.is_empty()
        || ec2
            .describe_security_groups(
                ctx,
                e::DescribeSecurityGroupsRequest { group_ids: Some(ids.to_vec()), ..Default::default() },
            )
            .await
            .is_ok_and(|o| o.security_groups.unwrap_or_default().len() == ids.len())
}

pub async fn key_pair_exists(ec2: &Ec2, ctx: &RequestContext, name: &str) -> bool {
    ec2.describe_key_pairs(ctx, e::DescribeKeyPairsRequest { key_names: Some(vec![name.into()]), ..Default::default() })
        .await
        .is_ok_and(|o| !o.key_pairs.unwrap_or_default().is_empty())
}
