//! What Auto Scaling asks of EC2, through `mws-ec2`'s generated handler,
//! as its service-linked role.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use mws_ec2::generated::types as et;
use mws_ec2::generated::Handler;

use crate::AutoScaling;

/// What Auto Scaling needs to know about an instance.
#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub state: String,
    pub availability_zone: String,
    pub availability_zone_id: Option<String>,
    pub subnet_id: Option<String>,
    pub instance_type: String,
    pub image_id: Option<String>,
    pub launch_time: Option<DateTime<Utc>>,
}

fn filter(name: &str, values: Vec<String>) -> et::Filter {
    et::Filter { name: Some(name.into()), values: Some(values) }
}

impl AutoScaling {
    pub(crate) async fn ec2_subnets(
        &self,
        ctx: &RequestContext,
        ids: &[String],
    ) -> Result<Vec<et::Subnet>, ServiceError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let out = self
            .ec2()
            .describe_subnets(ctx, et::DescribeSubnetsRequest { subnet_ids: Some(ids.to_vec()), ..Default::default() })
            .await?;
        Ok(out.subnets.unwrap_or_default())
    }

    /// The default subnet of each zone in the default VPC.
    pub(crate) async fn ec2_default_subnets(
        &self,
        ctx: &RequestContext,
        zones: &[String],
    ) -> Result<Vec<et::Subnet>, ServiceError> {
        let out = self
            .ec2()
            .describe_subnets(
                ctx,
                et::DescribeSubnetsRequest {
                    filters: Some(vec![
                        filter("default-for-az", vec!["true".into()]),
                        filter("availability-zone", zones.to_vec()),
                    ]),
                    ..Default::default()
                },
            )
            .await?;
        Ok(out.subnets.unwrap_or_default())
    }

    pub(crate) async fn ec2_zones(&self, ctx: &RequestContext) -> Vec<(String, String)> {
        match self.ec2().describe_availability_zones(ctx, Default::default()).await {
            Ok(out) => out
                .availability_zones
                .unwrap_or_default()
                .into_iter()
                .filter_map(|z| Some((z.zone_name?, z.zone_id.unwrap_or_default())))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub(crate) async fn ec2_instances(
        &self,
        ctx: &RequestContext,
        ids: &[String],
    ) -> Result<BTreeMap<String, InstanceInfo>, ServiceError> {
        let mut out = BTreeMap::new();
        if ids.is_empty() {
            return Ok(out);
        }
        // A filter, not InstanceIds, so long-gone instances are just absent.
        let res = self
            .ec2()
            .describe_instances(
                ctx,
                et::DescribeInstancesRequest {
                    filters: Some(vec![filter("instance-id", ids.to_vec())]),
                    ..Default::default()
                },
            )
            .await?;
        for r in res.reservations.unwrap_or_default() {
            for i in r.instances.unwrap_or_default() {
                let Some(id) = i.instance_id.clone() else { continue };
                out.insert(
                    id,
                    InstanceInfo {
                        state: i.state.and_then(|s| s.name).unwrap_or_default(),
                        availability_zone: i
                            .placement
                            .as_ref()
                            .and_then(|p| p.availability_zone.clone())
                            .unwrap_or_default(),
                        availability_zone_id: i.placement.as_ref().and_then(|p| p.availability_zone_id.clone()),
                        subnet_id: i.subnet_id,
                        instance_type: i.instance_type.unwrap_or_default(),
                        image_id: i.image_id,
                        launch_time: i.launch_time,
                    },
                );
            }
        }
        Ok(out)
    }

    pub(crate) async fn ec2_terminate(&self, ctx: &RequestContext, ids: Vec<String>) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Ok(());
        }
        self.ec2()
            .terminate_instances(ctx, et::TerminateInstancesRequest { instance_ids: ids, ..Default::default() })
            .await
            .map(drop)
    }

    pub(crate) async fn ec2_stop(
        &self,
        ctx: &RequestContext,
        ids: Vec<String>,
        hibernate: bool,
    ) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Ok(());
        }
        self.ec2()
            .stop_instances(
                ctx,
                et::StopInstancesRequest { instance_ids: ids, hibernate: Some(hibernate), ..Default::default() },
            )
            .await
            .map(drop)
    }

    pub(crate) async fn ec2_start(&self, ctx: &RequestContext, ids: Vec<String>) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Ok(());
        }
        self.ec2()
            .start_instances(ctx, et::StartInstancesRequest { instance_ids: ids, ..Default::default() })
            .await
            .map(drop)
    }
}
