//! Launch configurations.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_ec2::generated::types as et;
use mws_ec2::generated::Handler as _;

use crate::generated::types as t;
use crate::util::{
    already_exists, authorize, launch_configuration_arn, limit_exceeded, paginate, resource_in_use, validation,
};
use crate::{account_of, AutoScaling};

pub(crate) const MAX_LAUNCH_CONFIGURATIONS: usize = 200;

fn resource(ctx: &RequestContext, name: &str) -> String {
    format!(
        "arn:{}:autoscaling:{}:{}:launchConfiguration:*:launchConfigurationName/{name}",
        ctx.partition,
        ctx.region,
        account_of(ctx)
    )
}

impl AutoScaling {
    pub(crate) async fn create_launch_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateLaunchConfigurationType,
    ) -> Result<(), ServiceError> {
        let name = input.launch_configuration_name.clone();
        authorize(ctx, "CreateLaunchConfiguration", &resource(ctx, &name), None, ConditionContext::new())?;
        let (exists, count) =
            self.with_region(ctx, |r| (r.launch_configurations.contains_key(&name), r.launch_configurations.len()));
        if exists {
            return Err(already_exists(format!(
                "Launch Configuration by this name already exists - A launch configuration already exists with the name {name}"
            )));
        }
        if count >= MAX_LAUNCH_CONFIGURATIONS {
            return Err(limit_exceeded(format!(
                "You have reached your limit of {MAX_LAUNCH_CONFIGURATIONS} launch configurations. Delete unused launch configurations or request a limit increase."
            )));
        }
        let mut lc = match &input.instance_id {
            Some(id) => self.configuration_from_instance(ctx, &name, id).await?.0,
            None => t::LaunchConfiguration {
                launch_configuration_name: name.clone(),
                launch_configuration_arn: Some(launch_configuration_arn(ctx, &account_of(ctx), &name)),
                created_time: self.now(),
                ..Default::default()
            },
        };
        if let Some(v) = &input.image_id {
            lc.image_id = v.clone();
        }
        if let Some(v) = &input.instance_type {
            lc.instance_type = v.clone();
        }
        if lc.image_id.is_empty() {
            return Err(validation("Valid requests must contain either the InstanceID parameter or both the ImageId and InstanceType parameters."));
        }
        if lc.instance_type.is_empty() {
            return Err(validation("Valid requests must contain either the InstanceID parameter or both the ImageId and InstanceType parameters."));
        }
        // The AMI must exist (and be visible to the caller).
        let images = self
            .ec2()
            .describe_images(
                ctx,
                et::DescribeImagesRequest { image_ids: Some(vec![lc.image_id.clone()]), ..Default::default() },
            )
            .await
            .map(|o| o.images.unwrap_or_default())
            .unwrap_or_default();
        if images.is_empty() {
            return Err(validation(format!("The image id '[{}]' does not exist", lc.image_id)));
        }
        if let Some(key) = &input.key_name {
            let found = self
                .ec2()
                .describe_key_pairs(
                    ctx,
                    et::DescribeKeyPairsRequest { key_names: Some(vec![key.clone()]), ..Default::default() },
                )
                .await
                .is_ok();
            if !found {
                return Err(validation(format!("The key pair '{key}' does not exist")));
            }
        }
        if let Some(t) = &input.placement_tenancy {
            if !matches!(t.as_str(), "default" | "dedicated") {
                return Err(validation(format!(
                    "Invalid PlacementTenancy: {t}. Valid values are default and dedicated."
                )));
            }
        }
        macro_rules! take {
            ($($f:ident),*) => { $( if input.$f.is_some() { lc.$f = input.$f.clone(); } )* };
        }
        take!(
            key_name,
            security_groups,
            classic_link_vpc_id,
            classic_link_vpc_security_groups,
            user_data,
            kernel_id,
            ramdisk_id,
            block_device_mappings,
            instance_monitoring,
            spot_price,
            iam_instance_profile,
            ebs_optimized,
            associate_public_ip_address,
            placement_tenancy,
            metadata_options
        );
        lc.security_groups.get_or_insert_with(Vec::new);
        lc.block_device_mappings.get_or_insert_with(Vec::new);
        lc.classic_link_vpc_security_groups.get_or_insert_with(Vec::new);
        lc.instance_monitoring.get_or_insert(t::InstanceMonitoring { enabled: Some(true) });
        lc.ebs_optimized.get_or_insert(false);
        lc.kernel_id.get_or_insert_with(String::new);
        lc.ramdisk_id.get_or_insert_with(String::new);
        lc.key_name.get_or_insert_with(String::new);
        lc.user_data.get_or_insert_with(String::new);
        self.with_region(ctx, |r| {
            if r.launch_configurations.contains_key(&name) {
                return Err(already_exists(format!(
                    "Launch Configuration by this name already exists - A launch configuration already exists with the name {name}"
                )));
            }
            r.launch_configurations.insert(name.clone(), lc);
            Ok(())
        })
    }

    pub(crate) fn delete_launch_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::LaunchConfigurationNameType,
    ) -> Result<(), ServiceError> {
        let name = input.launch_configuration_name.clone();
        authorize(ctx, "DeleteLaunchConfiguration", &resource(ctx, &name), None, ConditionContext::new())?;
        self.with_region(ctx, |r| {
            if !r.launch_configurations.contains_key(&name) {
                return Err(validation(format!(
                    "Launch configuration name not found - Launch configuration {name} not found"
                )));
            }
            if let Some(g) = r.groups.values().find(|g| {
                g.cfg.launch_configuration_name.as_deref() == Some(name.as_str())
                    || g.members.values().any(|m| m.launch_configuration_name.as_deref() == Some(name.as_str()))
            }) {
                return Err(resource_in_use(format!(
                    "Cannot delete launch configuration {name} because it is attached to AutoScalingGroup {}",
                    g.name()
                )));
            }
            r.launch_configurations.remove(&name);
            Ok(())
        })
    }

    pub(crate) fn describe_launch_configurations_op(
        &self,
        ctx: &RequestContext,
        input: t::LaunchConfigurationNamesType,
    ) -> Result<t::LaunchConfigurationsType, ServiceError> {
        authorize(ctx, "DescribeLaunchConfigurations", "*", None, ConditionContext::new())?;
        let names = input.launch_configuration_names.clone().unwrap_or_default();
        let list: Vec<t::LaunchConfiguration> = self.with_region(ctx, |r| {
            r.launch_configurations
                .values()
                .filter(|l| names.is_empty() || names.contains(&l.launch_configuration_name))
                .cloned()
                .collect()
        });
        let (page, next_token) = paginate(list, input.max_records, &input.next_token, 100)?;
        Ok(t::LaunchConfigurationsType { launch_configurations: page, next_token })
    }
}
