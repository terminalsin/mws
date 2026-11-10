//! EC2 account defaults, instance settings, AMI controls, placement groups,
//! capacity reservations and network interface permissions through the
//! official Rust SDK.

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{
    CapacityReservationPreference, CapacityReservationSpecification, CapacityReservationTarget,
    DefaultInstanceMetadataEndpointState, DefaultInstanceMetadataTagsState, Filter, HttpTokensState,
    ImageAttributeName, InstanceAttributeName, InstanceMatchCriteria, InstanceStateName, InstanceType,
    LaunchPermission, LaunchPermissionModifications, MetadataDefaultHttpTokensState, Placement, PlacementStrategy,
    PrivateDnsNameOptionsRequest, UnlimitedSupportedInstanceFamily,
};
use aws_sdk_ec2::Client;
use mws_e2e::Mws;

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

async fn alpine_ami(ec2: &Client) -> String {
    let images = ec2.describe_images().owners("amazon").filters(filter("name", "mws-alpine-*")).send().await.unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

async fn instance(ec2: &Client, id: &str) -> aws_sdk_ec2::types::Instance {
    let d = ec2.describe_instances().instance_ids(id).send().await.unwrap();
    d.reservations()[0].instances()[0].clone()
}

#[tokio::test]
async fn account_defaults_apply_to_new_instances() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let ami = alpine_ami(&ec2).await;

    // Credit specification defaults per burstable family.
    let d = ec2
        .get_default_credit_specification()
        .instance_family(UnlimitedSupportedInstanceFamily::T2)
        .send()
        .await
        .unwrap();
    assert_eq!(d.instance_family_credit_specification().unwrap().cpu_credits(), Some("standard"));
    ec2.modify_default_credit_specification()
        .instance_family(UnlimitedSupportedInstanceFamily::T3)
        .cpu_credits("standard")
        .send()
        .await
        .unwrap();
    let d = ec2
        .get_default_credit_specification()
        .instance_family(UnlimitedSupportedInstanceFamily::T3)
        .send()
        .await
        .unwrap();
    assert_eq!(d.instance_family_credit_specification().unwrap().cpu_credits(), Some("standard"));

    // Instance metadata defaults.
    ec2.modify_instance_metadata_defaults()
        .http_tokens(MetadataDefaultHttpTokensState::Required)
        .http_put_response_hop_limit(3)
        .instance_metadata_tags(DefaultInstanceMetadataTagsState::Enabled)
        .http_endpoint(DefaultInstanceMetadataEndpointState::Enabled)
        .send()
        .await
        .unwrap();
    let m = ec2.get_instance_metadata_defaults().send().await.unwrap();
    let m = m.account_level().unwrap();
    assert_eq!(m.http_tokens(), Some(&HttpTokensState::Required));
    assert_eq!(m.http_put_response_hop_limit(), Some(3));

    // A new t3 instance picks up both defaults.
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    let i = instance(&ec2, &id).await;
    let meta = i.metadata_options().unwrap();
    assert_eq!(meta.http_tokens(), Some(&HttpTokensState::Required));
    assert_eq!(meta.http_put_response_hop_limit(), Some(3));
    let c = ec2.describe_instance_credit_specifications().instance_ids(&id).send().await.unwrap();
    assert_eq!(c.instance_credit_specifications()[0].cpu_credits(), Some("standard"));

    // Clearing a default goes back to no preference.
    ec2.modify_instance_metadata_defaults()
        .http_tokens(MetadataDefaultHttpTokensState::NoPreference)
        .http_put_response_hop_limit(-1)
        .send()
        .await
        .unwrap();
    let m = ec2.get_instance_metadata_defaults().send().await.unwrap();
    assert_eq!(m.account_level().unwrap().http_tokens(), None);
    assert_eq!(m.account_level().unwrap().http_put_response_hop_limit(), None);

    // Serial console access and AMI block public access.
    assert_eq!(
        ec2.get_serial_console_access_status().send().await.unwrap().serial_console_access_enabled(),
        Some(false)
    );
    ec2.enable_serial_console_access().send().await.unwrap();
    assert_eq!(
        ec2.get_serial_console_access_status().send().await.unwrap().serial_console_access_enabled(),
        Some(true)
    );
    let bpa = ec2.get_image_block_public_access_state().send().await.unwrap();
    assert_eq!(bpa.image_block_public_access_state(), Some("block-new-sharing"));

    // Ids are long everywhere, and can't be made short.
    let f = ec2.describe_id_format().resource("instance").send().await.unwrap();
    assert_eq!(f.statuses()[0].use_long_ids(), Some(true));
    assert_eq!(ec2.describe_aggregate_id_format().send().await.unwrap().use_long_ids_aggregated(), Some(true));
    let e =
        ec2.modify_id_format().resource("instance").use_long_ids(false).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "InvalidParameterValue");
    let p = ec2.describe_principal_id_format().resources("volume").send().await.unwrap();
    assert!(p.principals()[0].arn().unwrap().ends_with(":root"));
}

#[tokio::test]
async fn instance_settings() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let ami = alpine_ami(&ec2).await;
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .private_dns_name_options(PrivateDnsNameOptionsRequest::builder().hostname_type("resource-name".into()).build())
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    assert_eq!(run.instances()[0].private_dns_name(), Some(format!("{id}.ec2.internal").as_str()));
    crate::ec2::wait_state(&ec2, &id, InstanceStateName::Running).await;

    // Detailed monitoring: the change shows in progress, then done.
    let m = ec2.monitor_instances().instance_ids(&id).send().await.unwrap();
    assert_eq!(m.instance_monitorings()[0].monitoring().unwrap().state().unwrap().as_str(), "pending");
    assert_eq!(instance(&ec2, &id).await.monitoring().unwrap().state().unwrap().as_str(), "enabled");
    let m = ec2.unmonitor_instances().instance_ids(&id).send().await.unwrap();
    assert_eq!(m.instance_monitorings()[0].monitoring().unwrap().state().unwrap().as_str(), "disabling");

    // Maintenance options.
    let r = ec2
        .modify_instance_maintenance_options()
        .instance_id(&id)
        .auto_recovery(aws_sdk_ec2::types::InstanceAutoRecoveryState::Disabled)
        .send()
        .await
        .unwrap();
    assert_eq!(r.auto_recovery().unwrap().as_str(), "disabled");

    // CPU options and the hostname type need a stopped instance.
    let e =
        ec2.modify_instance_cpu_options().instance_id(&id).core_count(1).threads_per_core(1).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectInstanceState");
    ec2.stop_instances().instance_ids(&id).send().await.unwrap();
    crate::ec2::wait_state(&ec2, &id, InstanceStateName::Stopped).await;
    let c = ec2.modify_instance_cpu_options().instance_id(&id).core_count(1).threads_per_core(1).send().await.unwrap();
    assert_eq!(c.core_count(), Some(1));
    let e =
        ec2.modify_instance_cpu_options().instance_id(&id).core_count(4).threads_per_core(2).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let cpu = instance(&ec2, &id).await;
    assert_eq!(cpu.cpu_options().unwrap().threads_per_core(), Some(1));
    ec2.modify_private_dns_name_options()
        .instance_id(&id)
        .private_dns_hostname_type(aws_sdk_ec2::types::HostnameType::IpName)
        .send()
        .await
        .unwrap();
    let i = instance(&ec2, &id).await;
    assert!(i.private_dns_name().unwrap().starts_with("ip-"));

    // Attribute resets.
    ec2.modify_instance_attribute()
        .instance_id(&id)
        .source_dest_check(aws_sdk_ec2::types::AttributeBooleanValue::builder().value(false).build())
        .send()
        .await
        .unwrap();
    ec2.reset_instance_attribute()
        .instance_id(&id)
        .attribute(InstanceAttributeName::SourceDestCheck)
        .send()
        .await
        .unwrap();
    assert_eq!(instance(&ec2, &id).await.source_dest_check(), Some(true));

    // Status reports and diagnostic interrupts.
    ec2.report_instance_status()
        .instances(&id)
        .status(aws_sdk_ec2::types::ReportStatusType::Impaired)
        .reason_codes(aws_sdk_ec2::types::ReportInstanceReasonCodes::Unresponsive)
        .send()
        .await
        .unwrap();
    let e = ec2.send_diagnostic_interrupt().instance_id(&id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectInstanceState");
    ec2.start_instances().instance_ids(&id).send().await.unwrap();
    crate::ec2::wait_state(&ec2, &id, InstanceStateName::Running).await;
    ec2.send_diagnostic_interrupt().instance_id(&id).send().await.unwrap();

    // Topology covers only the families that have it.
    let t = ec2.describe_instance_topology().send().await.unwrap();
    assert!(t.instances().is_empty());
}

#[tokio::test]
async fn image_controls() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let ami = alpine_ami(&ec2).await;
    let run = ec2.run_instances().image_id(&ami).min_count(1).max_count(1).send().await.unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    let image =
        ec2.create_image().instance_id(&id).name("golden").send().await.unwrap().image_id().unwrap().to_string();

    // Block public access stops public sharing until turned off.
    let public =
        LaunchPermissionModifications::builder().add(LaunchPermission::builder().group("all".into()).build()).build();
    let e = ec2.modify_image_attribute().image_id(&image).launch_permission(public.clone()).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "OperationNotPermitted");
    ec2.disable_image_block_public_access().send().await.unwrap();
    ec2.modify_image_attribute().image_id(&image).launch_permission(public.clone()).send().await.unwrap();
    ec2.reset_image_attribute().image_id(&image).attribute("launchPermission".into()).send().await.unwrap();
    let d = ec2.describe_images().image_ids(&image).send().await.unwrap();
    assert_eq!(d.images()[0].public(), Some(false));

    // Deprecation.
    let at = aws_sdk_ec2::primitives::DateTime::from_secs(chrono_now() + 86_400 * 30);
    ec2.enable_image_deprecation().image_id(&image).deprecate_at(at).send().await.unwrap();
    let d = ec2.describe_images().image_ids(&image).send().await.unwrap();
    assert!(d.images()[0].deprecation_time().unwrap().ends_with(":00.000Z"));
    ec2.disable_image_deprecation().image_id(&image).send().await.unwrap();

    // Deregistration protection, with a cooldown.
    let p = ec2.enable_image_deregistration_protection().image_id(&image).with_cooldown(true).send().await.unwrap();
    assert_eq!(p.r#return(), Some("enabled-with-cooldown"));
    let e = ec2.deregister_image().image_id(&image).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let p = ec2.disable_image_deregistration_protection().image_id(&image).send().await.unwrap();
    assert!(p.r#return().unwrap().starts_with("disabled-until "));
    let a = ec2
        .describe_image_attribute()
        .image_id(&image)
        .attribute(ImageAttributeName::DeregistrationProtection)
        .send()
        .await
        .unwrap();
    assert!(a.deregistration_protection().unwrap().value().unwrap().starts_with("disabled-until"));
    assert!(ec2.deregister_image().image_id(&image).send().await.is_err());

    // Disabled images are hidden and can't launch.
    ec2.disable_image().image_id(&image).send().await.unwrap();
    let d = ec2.describe_images().owners("self").send().await.unwrap();
    assert!(d.images().iter().all(|i| i.image_id() != Some(image.as_str())));
    let d = ec2.describe_images().owners("self").include_disabled(true).send().await.unwrap();
    assert!(d.images().iter().any(|i| i.image_id() == Some(image.as_str())));
    let e = ec2.run_instances().image_id(&image).min_count(1).max_count(1).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidAMIID.Unavailable");
    ec2.enable_image().image_id(&image).send().await.unwrap();
    ec2.run_instances().image_id(&image).min_count(1).max_count(1).send().await.unwrap();

    // Past the cooldown the image can go.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 90000}"#)).await;
    assert_eq!(status, 200);
    let deregistered = ec2.deregister_image().image_id(&image).send().await;
    mws.control("POST", "/_mws/clock", Some(r#"{"offsetSeconds": 0}"#)).await;
    deregistered.unwrap();
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tokio::test]
async fn placement_groups() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let ami = alpine_ami(&ec2).await;

    let g = ec2
        .create_placement_group()
        .group_name("parts")
        .strategy(PlacementStrategy::Partition)
        .partition_count(3)
        .send()
        .await
        .unwrap();
    assert_eq!(g.placement_group().unwrap().partition_count(), Some(3));
    let e = ec2.create_placement_group().group_name("parts").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPlacementGroup.Duplicate");

    // Instances spread over the partitions.
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(3)
        .max_count(3)
        .placement(Placement::builder().group_name("parts").build())
        .send()
        .await
        .unwrap();
    let mut parts: Vec<i32> =
        run.instances().iter().map(|i| i.placement().unwrap().partition_number().unwrap()).collect();
    parts.sort();
    assert_eq!(parts, [1, 2, 3]);
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .placement(Placement::builder().group_name("missing").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPlacementGroup.Unknown");

    // A group in use can't be deleted.
    let e = ec2.delete_placement_group().group_name("parts").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPlacementGroup.InUse");
    let ids: Vec<String> = run.instances().iter().map(|i| i.instance_id().unwrap().to_string()).collect();
    ec2.terminate_instances().set_instance_ids(Some(ids.clone())).send().await.unwrap();
    for id in &ids {
        crate::ec2::wait_state(&ec2, id, InstanceStateName::Terminated).await;
    }
    ec2.delete_placement_group().group_name("parts").send().await.unwrap();

    // Spread groups hold at most seven instances per zone.
    ec2.create_placement_group().group_name("spread").strategy(PlacementStrategy::Spread).send().await.unwrap();
    let d = ec2.describe_placement_groups().filters(filter("strategy", "spread")).send().await.unwrap();
    assert_eq!(d.placement_groups()[0].spread_level().map(|s| s.as_str()), Some("rack"));
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(8)
        .max_count(8)
        .placement(Placement::builder().group_name("spread").availability_zone("us-east-1a").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InsufficientInstanceCapacity");
}

#[tokio::test]
async fn capacity_reservations() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let ami = alpine_ami(&ec2).await;

    let cr = ec2
        .create_capacity_reservation()
        .instance_type("t3.micro")
        .instance_platform(aws_sdk_ec2::types::CapacityReservationInstancePlatform::LinuxUnix)
        .availability_zone("us-east-1a")
        .instance_count(2)
        .instance_match_criteria(InstanceMatchCriteria::Targeted)
        .send()
        .await
        .unwrap();
    let cr_id = cr.capacity_reservation().unwrap().capacity_reservation_id().unwrap().to_string();
    let target = CapacityReservationSpecification::builder()
        .capacity_reservation_target(CapacityReservationTarget::builder().capacity_reservation_id(&cr_id).build())
        .build();

    // Targeted launches use the reservation, until it is full.
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(2)
        .max_count(2)
        .placement(Placement::builder().availability_zone("us-east-1a").build())
        .capacity_reservation_specification(target.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(run.instances()[0].capacity_reservation_id(), Some(cr_id.as_str()));
    let d = ec2.describe_capacity_reservations().capacity_reservation_ids(&cr_id).send().await.unwrap();
    assert_eq!(d.capacity_reservations()[0].available_instance_count(), Some(0));
    let usage = ec2.get_capacity_reservation_usage().capacity_reservation_id(&cr_id).send().await.unwrap();
    assert_eq!(usage.instance_usages()[0].used_instance_count(), Some(2));
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .placement(Placement::builder().availability_zone("us-east-1a").build())
        .capacity_reservation_specification(target.clone())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ReservationCapacityExceeded");

    // Growing it makes room; stopping an instance frees its slot.
    ec2.modify_capacity_reservation().capacity_reservation_id(&cr_id).instance_count(3).send().await.unwrap();
    let first = run.instances()[0].instance_id().unwrap().to_string();
    crate::ec2::wait_state(&ec2, &first, InstanceStateName::Running).await;
    ec2.stop_instances().instance_ids(&first).send().await.unwrap();
    let d = ec2.describe_capacity_reservations().capacity_reservation_ids(&cr_id).send().await.unwrap();
    assert_eq!(d.capacity_reservations()[0].available_instance_count(), Some(2));
    ec2.modify_instance_capacity_reservation_attributes()
        .instance_id(&first)
        .capacity_reservation_specification(
            CapacityReservationSpecification::builder()
                .capacity_reservation_preference(CapacityReservationPreference::None)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(instance(&ec2, &first).await.capacity_reservation_id(), None);

    // Cancelled reservations have no capacity left.
    ec2.cancel_capacity_reservation().capacity_reservation_id(&cr_id).send().await.unwrap();
    let d = ec2.describe_capacity_reservations().filters(filter("state", "cancelled")).send().await.unwrap();
    assert_eq!(d.capacity_reservations()[0].available_instance_count(), Some(0));

    // Open reservations pick up matching launches.
    let open = ec2
        .create_capacity_reservation()
        .instance_type("t3.micro")
        .instance_platform(aws_sdk_ec2::types::CapacityReservationInstancePlatform::LinuxUnix)
        .availability_zone("us-east-1a")
        .instance_count(1)
        .send()
        .await
        .unwrap();
    let open_id = open.capacity_reservation().unwrap().capacity_reservation_id().unwrap().to_string();
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .placement(Placement::builder().availability_zone("us-east-1a").build())
        .send()
        .await
        .unwrap();
    assert_eq!(run.instances()[0].capacity_reservation_id(), Some(open_id.as_str()));
}

#[tokio::test]
async fn network_interface_permissions() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let subnets = ec2.describe_subnets().send().await.unwrap();
    let subnet = subnets.subnets()[0].subnet_id().unwrap().to_string();
    let eni = ec2.create_network_interface().subnet_id(&subnet).send().await.unwrap();
    let eni = eni.network_interface().unwrap().network_interface_id().unwrap().to_string();

    let p = ec2
        .create_network_interface_permission()
        .network_interface_id(&eni)
        .aws_account_id("210987654321")
        .permission(aws_sdk_ec2::types::InterfacePermissionType::InstanceAttach)
        .send()
        .await
        .unwrap();
    let perm = p.interface_permission().unwrap();
    assert_eq!(perm.permission_state().unwrap().state().map(|s| s.as_str()), Some("granted"));
    let perm_id = perm.network_interface_permission_id().unwrap().to_string();
    let e = ec2
        .create_network_interface_permission()
        .network_interface_id(&eni)
        .aws_account_id("210987654321")
        .permission(aws_sdk_ec2::types::InterfacePermissionType::InstanceAttach)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPermission.Duplicate");
    let d = ec2
        .describe_network_interface_permissions()
        .filters(filter("network-interface-permission.network-interface-id", &eni))
        .send()
        .await
        .unwrap();
    assert_eq!(d.network_interface_permissions().len(), 1);
    ec2.delete_network_interface_permission().network_interface_permission_id(&perm_id).send().await.unwrap();
    let e =
        ec2.delete_network_interface_permission().network_interface_permission_id(&perm_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPermissionID.NotFound");

    ec2.modify_network_interface_attribute()
        .network_interface_id(&eni)
        .source_dest_check(aws_sdk_ec2::types::AttributeBooleanValue::builder().value(false).build())
        .send()
        .await
        .unwrap();
    ec2.reset_network_interface_attribute()
        .network_interface_id(&eni)
        .source_dest_check("sourceDestCheck")
        .send()
        .await
        .unwrap();
    let d = ec2.describe_network_interfaces().network_interface_ids(&eni).send().await.unwrap();
    assert_eq!(d.network_interfaces()[0].source_dest_check(), Some(true));
}
