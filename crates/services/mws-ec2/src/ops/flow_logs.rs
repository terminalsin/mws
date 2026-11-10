//! VPC flow logs, and instance extras: burstable credit options, Windows
//! password data and UEFI variable stores.
//!
//! Flow logs keep their configuration and destination checks; no flow
//! records are written, because MWS does not capture traffic.

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::util::{
    arn, authorize, err, invalid_parameter, missing_parameter, new_id, paginate, request_tag_context,
    resource_tag_context, s, some_tags, tags_for, Filters, Kind,
};
use crate::{account_of, Ec2};

const DEFAULT_FORMAT: &str = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}";

fn unsuccessful(id: &str, code: &str, message: impl Into<String>) -> t::UnsuccessfulItem {
    t::UnsuccessfulItem {
        resource_id: Some(id.into()),
        error: Some(t::UnsuccessfulItemError { code: Some(code.into()), message: Some(message.into()) }),
    }
}

/// Whether an instance type earns CPU credits, and its default option.
pub(crate) fn burstable_default(instance_type: &str) -> Option<&'static str> {
    let family = instance_type.split('.').next().unwrap_or_default();
    match family {
        "t2" => Some("standard"),
        "t3" | "t3a" | "t4g" => Some("unlimited"),
        _ => None,
    }
}

impl Ec2 {
    pub(crate) fn create_flow_logs_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateFlowLogsRequest,
    ) -> Result<t::CreateFlowLogsResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "vpc-flow-log", &["vpc-flow-log"])?;
        let kind = input.resource_type.as_str();
        let kinds = ["VPC", "Subnet", "NetworkInterface", "TransitGateway", "TransitGatewayAttachment"];
        if !kinds.contains(&kind) {
            return Err(invalid_parameter(format!(
                "Value ({kind}) for parameter resourceType is invalid. Valid values: {}",
                kinds.join(", ")
            )));
        }
        if input.resource_ids.is_empty() {
            return Err(missing_parameter("ResourceIds"));
        }
        let tgw = kind.starts_with("TransitGateway");
        let traffic = match (&input.traffic_type, tgw) {
            (Some(t), false) if matches!(t.as_str(), "ACCEPT" | "REJECT" | "ALL") => Some(t.clone()),
            (Some(t), false) => {
                return Err(invalid_parameter(format!(
                    "Value ({t}) for parameter trafficType is invalid. Valid values: ACCEPT, REJECT, ALL"
                )))
            }
            (None, false) => return Err(missing_parameter("TrafficType")),
            (Some(_), true) => {
                return Err(invalid_parameter("TrafficType is not supported for transit gateway flow logs."))
            }
            (None, true) => None,
        };
        let dest_type = input.log_destination_type.clone().unwrap_or_else(|| "cloud-watch-logs".into());
        let (destination, group) = match dest_type.as_str() {
            "cloud-watch-logs" => {
                if input.log_group_name.is_some() && input.log_destination.is_some() {
                    return Err(err(
                        "InvalidParameterCombination",
                        "Specify either LogGroupName or LogDestination, not both.",
                    ));
                }
                let group = match (&input.log_group_name, &input.log_destination) {
                    (Some(g), _) => g.clone(),
                    (None, Some(d)) => d.rsplit(":log-group:").next().unwrap_or(d).trim_end_matches(":*").to_string(),
                    (None, None) => return Err(missing_parameter("LogGroupName or LogDestination")),
                };
                if input.deliver_logs_permission_arn.is_none() {
                    return Err(invalid_parameter(
                        "DeliverLogsPermissionArn is required when LogDestinationType is cloud-watch-logs.",
                    ));
                }
                let dest = input.log_destination.clone().unwrap_or_else(|| {
                    format!("arn:{}:logs:{}:{}:log-group:{group}", ctx.partition, ctx.region, account_of(ctx))
                });
                (dest, Some(group))
            }
            "s3" | "kinesis-data-firehose" => {
                let d = input.log_destination.clone().ok_or_else(|| missing_parameter("LogDestination"))?;
                if !d.starts_with("arn:") {
                    return Err(invalid_parameter(format!("LogDestination {d} is not a valid ARN.")));
                }
                if input.log_group_name.is_some() {
                    return Err(err(
                        "InvalidParameterCombination",
                        "LogGroupName can only be used with LogDestinationType cloud-watch-logs.",
                    ));
                }
                (d, None)
            }
            other => {
                return Err(invalid_parameter(format!(
                    "Value ({other}) for parameter logDestinationType is invalid. Valid values: cloud-watch-logs, s3, kinesis-data-firehose"
                )))
            }
        };
        let interval = input.max_aggregation_interval.unwrap_or(600);
        if interval != 60 && interval != 600 {
            return Err(invalid_parameter(format!(
                "Value ({interval}) for parameter maxAggregationInterval is invalid. Valid values: 60, 600"
            )));
        }
        if tgw && interval != 60 {
            return Err(invalid_parameter("Transit gateway flow logs aggregate over 60 seconds."));
        }
        let format = input.log_format.clone().unwrap_or_else(|| DEFAULT_FORMAT.into());
        let account = account_of(ctx);
        authorize(
            ctx,
            "CreateFlowLogs",
            &[(arn(ctx, &account, "vpc-flow-log/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        if let Some(role) = &input.deliver_logs_permission_arn {
            ctx.authorize("iam:PassRole", role, ConditionContext::new()).map_err(|_| {
                err(
                    "UnauthorizedOperation",
                    format!("You are not authorized to perform this operation. User: {} is not authorized to perform: iam:PassRole on resource: {role}", ctx.caller.arn),
                )
            })?;
        }
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let mut ids = Vec::new();
            let mut failed = Vec::new();
            for rid in &input.resource_ids {
                let (exists, code, noun) = match kind {
                    "VPC" => (r.vpcs.contains_key(rid), "InvalidVpcID.NotFound", "VPC"),
                    "Subnet" => (r.subnets.contains_key(rid), "InvalidSubnetID.NotFound", "Subnet"),
                    "NetworkInterface" => (
                        r.network_interfaces.contains_key(rid),
                        "InvalidNetworkInterfaceID.NotFound",
                        "Network interface",
                    ),
                    "TransitGateway" => {
                        (r.transit_gateways.contains_key(rid), "InvalidTransitGatewayID.NotFound", "Transit gateway")
                    }
                    _ => (
                        r.transit_gateway_attachments.contains_key(rid),
                        "InvalidTransitGatewayAttachmentID.NotFound",
                        "Transit gateway attachment",
                    ),
                };
                if !exists {
                    failed.push(unsuccessful(rid, code, format!("{noun} {rid} does not exist")));
                    continue;
                }
                let duplicate = r.flow_logs.values().any(|f| {
                    f.resource_id.as_deref() == Some(rid.as_str())
                        && f.log_destination.as_deref() == Some(destination.as_str())
                        && f.traffic_type == traffic
                });
                if duplicate {
                    failed.push(unsuccessful(
                        rid,
                        "FlowLogAlreadyExists",
                        "Error. There is an existing Flow Log with the same configuration and log destination.",
                    ));
                    continue;
                }
                let id = new_id("fl");
                r.flow_logs.insert(
                    id.clone(),
                    t::FlowLog {
                        creation_time: Some(now),
                        deliver_logs_permission_arn: input.deliver_logs_permission_arn.clone(),
                        deliver_cross_account_role: input.deliver_cross_account_role.clone(),
                        deliver_logs_status: Some("SUCCESS".into()),
                        flow_log_id: Some(id.clone()),
                        flow_log_status: Some("ACTIVE".into()),
                        log_group_name: group.clone(),
                        resource_id: Some(rid.clone()),
                        traffic_type: traffic.clone(),
                        log_destination_type: Some(dest_type.clone()),
                        log_destination: Some(destination.clone()),
                        log_format: Some(format.clone()),
                        tags: some_tags(tags.clone()),
                        max_aggregation_interval: Some(interval),
                        destination_options: (dest_type == "s3").then(|| {
                            let o = input.destination_options.clone().unwrap_or_default();
                            t::DestinationOptionsResponse {
                                file_format: Some(o.file_format.unwrap_or_else(|| "plain-text".into())),
                                hive_compatible_partitions: Some(o.hive_compatible_partitions.unwrap_or(false)),
                                per_hour_partition: Some(o.per_hour_partition.unwrap_or(false)),
                            }
                        }),
                        ..Default::default()
                    },
                );
                ids.push(id);
            }
            Ok(t::CreateFlowLogsResult {
                client_token: input.client_token.clone(),
                flow_log_ids: Some(ids),
                unsuccessful: Some(failed),
            })
        })
    }

    pub(crate) fn delete_flow_logs_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteFlowLogsRequest,
    ) -> Result<t::DeleteFlowLogsResult, ServiceError> {
        if input.flow_log_ids.is_empty() {
            return Err(missing_parameter("FlowLogIds"));
        }
        let account = account_of(ctx);
        let tags = self.with_region(ctx, |r| {
            input
                .flow_log_ids
                .iter()
                .filter_map(|id| r.flow_logs.get(id).map(|f| (id.clone(), f.tags.clone())))
                .collect::<Vec<_>>()
        });
        let resources: Vec<(String, ConditionContext)> = tags
            .iter()
            .map(|(id, tags)| (arn(ctx, &account, &format!("vpc-flow-log/{id}")), resource_tag_context(tags.as_ref())))
            .collect();
        let resources = if resources.is_empty() {
            vec![(arn(ctx, &account, "vpc-flow-log/*"), ConditionContext::new())]
        } else {
            resources
        };
        authorize(ctx, "DeleteFlowLogs", &resources, input.dry_run)?;
        self.with_region(ctx, |r| {
            let mut failed = Vec::new();
            for id in &input.flow_log_ids {
                if r.flow_logs.remove(id).is_none() {
                    failed.push(unsuccessful(id, "InvalidFlowLogId.NotFound", "This flow log does not exist"));
                }
            }
            Ok(t::DeleteFlowLogsResult { unsuccessful: Some(failed) })
        })
    }

    pub(crate) fn describe_flow_logs_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeFlowLogsRequest,
    ) -> Result<t::DescribeFlowLogsResult, ServiceError> {
        authorize(ctx, "DescribeFlowLogs", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filter);
        let ids = input.flow_log_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for f in r.flow_logs.values() {
                let id = f.flow_log_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let ok = filters.matches(f.tags.as_ref(), |name| {
                    Some(match name {
                        "deliver-log-status" => s(&f.deliver_logs_status),
                        "log-destination-type" => s(&f.log_destination_type),
                        "flow-log-id" => vec![id.clone()],
                        "log-group-name" => s(&f.log_group_name),
                        "resource-id" => s(&f.resource_id),
                        "traffic-type" => s(&f.traffic_type),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(f.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeFlowLogsResult { flow_logs: Some(items), next_token })
        })
    }

    // ---- instance extras --------------------------------------------------------------------------

    pub(crate) fn describe_instance_credit_specifications_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInstanceCreditSpecificationsRequest,
    ) -> Result<t::DescribeInstanceCreditSpecificationsResult, ServiceError> {
        authorize(
            ctx,
            "DescribeInstanceCreditSpecifications",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let ids = input.instance_ids.clone().unwrap_or_default();
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            Kind::Instance.check_all(&ids, |id| r.instances.contains_key(id))?;
            let mut out = Vec::new();
            for rec in r.instances.values() {
                let i = &rec.instance;
                let id = i.instance_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                if i.state.as_ref().and_then(|s| s.name.as_deref()) == Some("terminated") {
                    continue;
                }
                let it = i.instance_type.clone().unwrap_or_default();
                let Some(default) = burstable_default(&it) else {
                    if !ids.is_empty() {
                        return Err(err(
                            "UnsupportedOperation",
                            format!(
                                "The instance '{id}' is not a burstable performance instance (instance type {it})."
                            ),
                        ));
                    }
                    continue;
                };
                let credits = r.instance_credit_specifications.get(&id).cloned().unwrap_or_else(|| default.to_string());
                let ok = filters.matches(None, |name| {
                    Some(match name {
                        "instance-id" => vec![id.clone()],
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(t::InstanceCreditSpecification { instance_id: Some(id), cpu_credits: Some(credits) });
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeInstanceCreditSpecificationsResult {
                instance_credit_specifications: Some(items),
                next_token,
            })
        })
    }

    pub(crate) fn modify_instance_credit_specification_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyInstanceCreditSpecificationRequest,
    ) -> Result<t::ModifyInstanceCreditSpecificationResult, ServiceError> {
        let account = account_of(ctx);
        let resources: Vec<(String, ConditionContext)> = input
            .instance_credit_specifications
            .iter()
            .map(|s| (arn(ctx, &account, &format!("instance/{}", s.instance_id)), ConditionContext::new()))
            .collect();
        authorize(ctx, "ModifyInstanceCreditSpecification", &resources, input.dry_run)?;
        self.with_region(ctx, |r| {
            let mut ok = Vec::new();
            let mut failed = Vec::new();
            for spec in &input.instance_credit_specifications {
                let id = spec.instance_id.clone();
                let fail = |code: &str, msg: String| t::UnsuccessfulInstanceCreditSpecificationItem {
                    instance_id: Some(id.clone()),
                    error: Some(t::UnsuccessfulInstanceCreditSpecificationItemError {
                        code: Some(code.into()),
                        message: Some(msg),
                    }),
                };
                let Some(rec) = r.instances.get(&id) else {
                    failed.push(fail("InvalidInstanceID.NotFound", format!("The instance ID '{id}' does not exist")));
                    continue;
                };
                let it = rec.instance.instance_type.clone().unwrap_or_default();
                if burstable_default(&it).is_none() {
                    failed.push(fail(
                        "UnsupportedOperation",
                        format!("The instance '{id}' is not a burstable performance instance."),
                    ));
                    continue;
                }
                match spec.cpu_credits.as_deref() {
                    Some(c @ ("standard" | "unlimited")) => {
                        r.instance_credit_specifications.insert(id.clone(), c.to_string());
                        ok.push(t::SuccessfulInstanceCreditSpecificationItem { instance_id: Some(id.clone()) });
                    }
                    other => failed.push(fail(
                        "InvalidCpuCredits.Malformed",
                        format!(
                            "{} is not a valid value for CpuCredits. Valid values: standard, unlimited",
                            other.unwrap_or("")
                        ),
                    )),
                }
            }
            Ok(t::ModifyInstanceCreditSpecificationResult {
                successful_instance_credit_specifications: Some(ok),
                unsuccessful_instance_credit_specifications: Some(failed),
            })
        })
    }

    fn instance_read(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
    ) -> Result<t::Instance, ServiceError> {
        Kind::Instance.check(id)?;
        let account = account_of(ctx);
        let found = self.with_region(ctx, |r| r.instances.get(id).map(|i| i.instance.clone()));
        let inst = found.ok_or_else(|| Kind::Instance.not_found(id))?;
        authorize(
            ctx,
            action,
            &[(arn(ctx, &account, &format!("instance/{id}")), resource_tag_context(inst.tags.as_ref()))],
            dry_run,
        )?;
        Ok(inst)
    }

    pub(crate) fn get_password_data_op(
        &self,
        ctx: &RequestContext,
        input: t::GetPasswordDataRequest,
    ) -> Result<t::GetPasswordDataResult, ServiceError> {
        let inst = self.instance_read(ctx, "GetPasswordData", &input.instance_id, input.dry_run)?;
        // Only Windows instances generate an administrator password; MWS
        // runs Linux images, so there is none.
        Ok(t::GetPasswordDataResult {
            instance_id: Some(input.instance_id.clone()),
            timestamp: inst.launch_time,
            password_data: Some(String::new()),
        })
    }

    pub(crate) fn get_instance_uefi_data_op(
        &self,
        ctx: &RequestContext,
        input: t::GetInstanceUefiDataRequest,
    ) -> Result<t::GetInstanceUefiDataResult, ServiceError> {
        let inst = self.instance_read(ctx, "GetInstanceUefiData", &input.instance_id, input.dry_run)?;
        if inst.current_instance_boot_mode.as_deref() != Some("uefi") {
            return Err(err(
                "UnsupportedOperation",
                format!("The instance {} does not boot in UEFI mode.", input.instance_id),
            ));
        }
        // An empty variable store in the AWS `AMZNUEFI` container format.
        let mut blob = b"AMZNUEFI".to_vec();
        blob.extend_from_slice(&[0u8; 24]);
        Ok(t::GetInstanceUefiDataResult {
            instance_id: Some(input.instance_id.clone()),
            uefi_data: Some(base64::engine::general_purpose::STANDARD.encode(blob)),
        })
    }
}
