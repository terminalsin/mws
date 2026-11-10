//! Spot Instances, Spot Fleet, EC2 Fleet, Dedicated Hosts and Reserved
//! Instances through the official Rust SDK (metadata-only backend).

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{
    AllocationStrategy, AutoPlacement, DefaultTargetCapacityType, Filter, FleetLaunchTemplateConfigRequest,
    FleetLaunchTemplateOverridesRequest, FleetLaunchTemplateSpecificationRequest, FleetType,
    InstanceMarketOptionsRequest, InstanceType, MarketType, OfferingClassType, OfferingTypeValues, Placement,
    RequestLaunchTemplateData, RequestSpotLaunchSpecification, RiProductDescription, SpotFleetLaunchSpecification,
    SpotFleetRequestConfigData, SpotInstanceType, SpotMarketOptions, SpotPlacement, TargetCapacitySpecificationRequest,
    Tenancy,
};
use aws_sdk_ec2::Client;
use mws_e2e::Mws;

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

/// The x86 Alpine AMI MWS publishes.
async fn ami(ec2: &Client) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(filter("name", "mws-alpine-*"))
        .filters(filter("architecture", "x86_64"))
        .send()
        .await
        .unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

async fn spot_request(ec2: &Client, id: &str) -> aws_sdk_ec2::types::SpotInstanceRequest {
    ec2.describe_spot_instance_requests().spot_instance_request_ids(id).send().await.unwrap().spot_instance_requests()
        [0]
    .clone()
}

async fn instance_state(ec2: &Client, id: &str) -> String {
    let out = ec2.describe_instances().instance_ids(id).send().await.unwrap();
    out.reservations()[0].instances()[0].state().unwrap().name().unwrap().as_str().to_string()
}

async fn terminate(ec2: &Client, id: &str) {
    ec2.terminate_instances().instance_ids(id).send().await.unwrap();
    wait_for(ec2, id, "terminated").await;
}

/// Wait until instance `id` is in `want` (transitions take a moment).
async fn wait_for(ec2: &Client, id: &str, want: &str) {
    for _ in 0..200 {
        if instance_state(ec2, id).await == want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("{id} never became {want}");
}

#[tokio::test]
async fn spot_requests_launch_and_follow_their_instances() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let ami = ami(&ec2).await;

    // The simulated market: below On-Demand, every six hours.
    let history = ec2
        .describe_spot_price_history()
        .instance_types(InstanceType::M5Large)
        .product_descriptions("Linux/UNIX")
        .availability_zone("us-east-1a")
        .send()
        .await
        .unwrap();
    let prices = history.spot_price_history();
    assert!(prices.len() >= 4, "{prices:?}");
    let latest: f64 = prices[0].spot_price().unwrap().parse().unwrap();
    assert!(latest > 0.0 && latest < 0.096);
    assert!(prices[0].timestamp().unwrap().secs() >= prices[1].timestamp().unwrap().secs());

    let spec = RequestSpotLaunchSpecification::builder()
        .image_id(&ami)
        .instance_type(InstanceType::M5Large)
        .placement(SpotPlacement::builder().availability_zone("us-east-1a").build())
        .build();
    let made = ec2.request_spot_instances().instance_count(2).launch_specification(spec.clone()).send().await.unwrap();
    let requests = made.spot_instance_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].state().map(|s| s.as_str()), Some("open"));
    assert_eq!(requests[0].status().unwrap().code(), Some("pending-evaluation"));
    let one_time = requests[0].spot_instance_request_id().unwrap().to_string();

    let req = spot_request(&ec2, &one_time).await;
    assert_eq!(req.state().map(|s| s.as_str()), Some("active"));
    assert_eq!(req.status().unwrap().code(), Some("fulfilled"));
    assert_eq!(req.launched_availability_zone(), Some("us-east-1a"));
    let instance = req.instance_id().unwrap().to_string();
    let described = ec2.describe_instances().instance_ids(&instance).send().await.unwrap();
    let i = &described.reservations()[0].instances()[0];
    assert_eq!(i.instance_lifecycle().map(|l| l.as_str()), Some("spot"));
    assert_eq!(i.spot_instance_request_id(), Some(one_time.as_str()));

    // A one-time request closes when its instance ends.
    terminate(&ec2, &instance).await;
    let req = spot_request(&ec2, &one_time).await;
    assert_eq!(req.state().map(|s| s.as_str()), Some("closed"));
    assert_eq!(req.status().unwrap().code(), Some("instance-terminated-by-user"));

    // A persistent request launches again.
    let persistent = ec2
        .request_spot_instances()
        .r#type(SpotInstanceType::Persistent)
        .launch_specification(spec.clone())
        .send()
        .await
        .unwrap()
        .spot_instance_requests()[0]
        .spot_instance_request_id()
        .unwrap()
        .to_string();
    let first = spot_request(&ec2, &persistent).await.instance_id().unwrap().to_string();
    terminate(&ec2, &first).await;
    let req = spot_request(&ec2, &persistent).await;
    assert_eq!(req.state().map(|s| s.as_str()), Some("active"));
    let second = req.instance_id().unwrap().to_string();
    assert_ne!(first, second);
    assert_ne!(instance_state(&ec2, &second).await, "terminated");

    // Below the market the request waits; cancelling it ends it.
    let low = ec2
        .request_spot_instances()
        .spot_price("0.0001")
        .launch_specification(spec.clone())
        .send()
        .await
        .unwrap()
        .spot_instance_requests()[0]
        .spot_instance_request_id()
        .unwrap()
        .to_string();
    let req = spot_request(&ec2, &low).await;
    assert_eq!(req.state().map(|s| s.as_str()), Some("open"));
    assert_eq!(req.status().unwrap().code(), Some("price-too-low"));
    assert!(req.instance_id().is_none());
    let cancelled = ec2.cancel_spot_instance_requests().spot_instance_request_ids(&low).send().await.unwrap();
    assert_eq!(cancelled.cancelled_spot_instance_requests()[0].state().map(|s| s.as_str()), Some("cancelled"));
    let req = spot_request(&ec2, &low).await;
    assert_eq!(req.status().unwrap().code(), Some("canceled-before-fulfillment"));

    // Cancelling a fulfilled request leaves its instance running.
    ec2.cancel_spot_instance_requests().spot_instance_request_ids(&persistent).send().await.unwrap();
    let req = spot_request(&ec2, &persistent).await;
    assert_eq!(req.status().unwrap().code(), Some("request-canceled-and-instance-running"));
    assert_ne!(instance_state(&ec2, &second).await, "terminated");

    // Spot RunInstances makes a request too, and checks the price.
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::M5Large)
        .min_count(1)
        .max_count(1)
        .instance_market_options(InstanceMarketOptionsRequest::builder().market_type(MarketType::Spot).build())
        .send()
        .await
        .unwrap();
    let sir = run.instances()[0].spot_instance_request_id().unwrap().to_string();
    let req = spot_request(&ec2, &sir).await;
    assert_eq!(req.instance_id(), run.instances()[0].instance_id());
    assert_eq!(req.r#type().map(|t| t.as_str()), Some("one-time"));
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::M5Large)
        .min_count(1)
        .max_count(1)
        .instance_market_options(
            InstanceMarketOptionsRequest::builder()
                .market_type(MarketType::Spot)
                .spot_options(SpotMarketOptions::builder().max_price("0.0001").build())
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "SpotMaxPriceTooLow");

    let e = ec2.describe_spot_instance_requests().spot_instance_request_ids("sir-0000abcd").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidSpotInstanceRequestID.NotFound");
    let e = ec2
        .request_spot_instances()
        .instance_interruption_behavior(aws_sdk_ec2::types::InstanceInterruptionBehavior::Stop)
        .launch_specification(spec)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterCombination");
}

#[tokio::test]
async fn spot_fleet_keeps_its_target_capacity() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let ami = ami(&ec2).await;
    let role = "arn:aws:iam::123456789012:role/aws-ec2-spot-fleet-tagging-role";
    let spec = |ty: InstanceType, weight: f64| {
        SpotFleetLaunchSpecification::builder().image_id(&ami).instance_type(ty).weighted_capacity(weight).build()
    };

    let e = ec2
        .request_spot_fleet()
        .spot_fleet_request_config(
            SpotFleetRequestConfigData::builder().iam_fleet_role(role).target_capacity(1).build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidSpotFleetRequestConfig");

    let config = SpotFleetRequestConfigData::builder()
        .iam_fleet_role(role)
        .target_capacity(4)
        .on_demand_target_capacity(1)
        .allocation_strategy(AllocationStrategy::LowestPrice)
        .launch_specifications(spec(InstanceType::M5Large, 1.0))
        .launch_specifications(spec(InstanceType::C5Large, 1.0))
        .build();
    let id = ec2
        .request_spot_fleet()
        .spot_fleet_request_config(config)
        .send()
        .await
        .unwrap()
        .spot_fleet_request_id()
        .unwrap()
        .to_string();
    assert!(id.starts_with("sfr-"));
    let fleets = ec2.describe_spot_fleet_requests().spot_fleet_request_ids(&id).send().await.unwrap();
    let f = &fleets.spot_fleet_request_configs()[0];
    assert_eq!(f.spot_fleet_request_state().map(|s| s.as_str()), Some("active"));
    assert_eq!(f.activity_status().map(|s| s.as_str()), Some("fulfilled"));
    let cfg = f.spot_fleet_request_config().unwrap();
    assert_eq!(cfg.fulfilled_capacity(), Some(3.0));
    assert_eq!(cfg.on_demand_fulfilled_capacity(), Some(1.0));

    let instances = ec2.describe_spot_fleet_instances().spot_fleet_request_id(&id).send().await.unwrap();
    let active = instances.active_instances();
    assert_eq!(active.len(), 4);
    assert_eq!(active.iter().filter(|a| a.spot_instance_request_id().is_some()).count(), 3);
    // Lowest price: every Spot instance is the cheaper type per unit.
    let spot_types: Vec<_> =
        active.iter().filter(|a| a.spot_instance_request_id().is_some()).map(|a| a.instance_type().unwrap()).collect();
    assert!(spot_types.windows(2).all(|w| w[0] == w[1]), "{spot_types:?}");
    let tagged =
        ec2.describe_instances().filters(filter("tag:aws:ec2spot:fleet-request-id", &id)).send().await.unwrap();
    assert_eq!(tagged.reservations().iter().map(|r| r.instances().len()).sum::<usize>(), 4);

    // A maintain fleet replaces instances that end.
    let gone = active[0].instance_id().unwrap().to_string();
    terminate(&ec2, &gone).await;
    let instances = ec2.describe_spot_fleet_instances().spot_fleet_request_id(&id).send().await.unwrap();
    assert_eq!(instances.active_instances().len(), 4);
    assert!(instances.active_instances().iter().all(|a| a.instance_id() != Some(gone.as_str())));

    // Lowering the target terminates the excess.
    ec2.modify_spot_fleet_request().spot_fleet_request_id(&id).target_capacity(2).send().await.unwrap();
    let instances = ec2.describe_spot_fleet_instances().spot_fleet_request_id(&id).send().await.unwrap();
    assert_eq!(instances.active_instances().len(), 2);
    let history = ec2
        .describe_spot_fleet_request_history()
        .spot_fleet_request_id(&id)
        .start_time(aws_sdk_ec2::primitives::DateTime::from_secs(0))
        .send()
        .await
        .unwrap();
    let subs: Vec<_> = history
        .history_records()
        .iter()
        .filter_map(|h| h.event_information().and_then(|e| e.event_sub_type()))
        .collect();
    for want in ["submitted", "active", "launched", "terminated", "modify_in_progress", "modify_succeeded"] {
        assert!(subs.contains(&want), "{want} missing from {subs:?}");
    }

    let cancelled = ec2
        .cancel_spot_fleet_requests()
        .spot_fleet_request_ids(&id)
        .spot_fleet_request_ids("sfr-00000000-0000-4000-a000-000000000000")
        .terminate_instances(true)
        .send()
        .await
        .unwrap();
    let ok = &cancelled.successful_fleet_requests()[0];
    assert_eq!(ok.current_spot_fleet_request_state().map(|s| s.as_str()), Some("cancelled_terminating"));
    assert_eq!(ok.previous_spot_fleet_request_state().map(|s| s.as_str()), Some("active"));
    assert_eq!(
        cancelled.unsuccessful_fleet_requests()[0].error().unwrap().code().map(|c| c.as_str()),
        Some("fleetRequestIdDoesNotExist")
    );
    let left = instances.active_instances()[0].instance_id().unwrap();
    wait_for(&ec2, left, "terminated").await;
    let fleets = ec2.describe_spot_fleet_requests().spot_fleet_request_ids(&id).send().await.unwrap();
    assert_eq!(
        fleets.spot_fleet_request_configs()[0].spot_fleet_request_state().map(|s| s.as_str()),
        Some("cancelled")
    );
}

#[tokio::test]
async fn ec2_fleets_launch_instantly_or_maintain_capacity() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let ami = ami(&ec2).await;
    let lt = ec2
        .create_launch_template()
        .launch_template_name("fleet-template")
        .launch_template_data(
            RequestLaunchTemplateData::builder().image_id(&ami).instance_type(InstanceType::T3Micro).build(),
        )
        .send()
        .await
        .unwrap()
        .launch_template
        .unwrap()
        .launch_template_id
        .unwrap();
    let config = |overrides: &[InstanceType]| {
        let mut c = FleetLaunchTemplateConfigRequest::builder().launch_template_specification(
            FleetLaunchTemplateSpecificationRequest::builder().launch_template_id(&lt).version("$Latest").build(),
        );
        for o in overrides {
            c = c.overrides(FleetLaunchTemplateOverridesRequest::builder().instance_type(o.clone()).build());
        }
        c.build()
    };

    let instant = ec2
        .create_fleet()
        .r#type(FleetType::Instant)
        .launch_template_configs(config(&[InstanceType::T3Micro, InstanceType::T3Small]))
        .target_capacity_specification(
            TargetCapacitySpecificationRequest::builder()
                .total_target_capacity(3)
                .on_demand_target_capacity(1)
                .default_target_capacity_type(DefaultTargetCapacityType::Spot)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let fleet_id = instant.fleet_id().unwrap().to_string();
    assert!(fleet_id.starts_with("fleet-"));
    assert!(instant.errors().is_empty(), "{:?}", instant.errors());
    let count = |lifecycle: &str| -> usize {
        instant
            .instances()
            .iter()
            .filter(|i| i.lifecycle().map(|l| l.as_str()) == Some(lifecycle))
            .map(|i| i.instance_ids().len())
            .sum()
    };
    assert_eq!(count("on-demand"), 1);
    assert_eq!(count("spot"), 2);
    let group = &instant.instances()[0];
    assert_eq!(
        group.launch_template_and_overrides().unwrap().launch_template_specification().unwrap().launch_template_id(),
        Some(lt.as_str())
    );
    let described = ec2.describe_fleets().fleet_ids(&fleet_id).send().await.unwrap();
    let f = &described.fleets()[0];
    assert_eq!(f.r#type().map(|t| t.as_str()), Some("instant"));
    assert_eq!(f.fleet_state().map(|s| s.as_str()), Some("active"));
    assert_eq!(f.fulfilled_capacity(), Some(3.0));
    assert_eq!(f.instances().iter().map(|i| i.instance_ids().len()).sum::<usize>(), 3);
    let e = ec2
        .modify_fleet()
        .fleet_id(&fleet_id)
        .target_capacity_specification(TargetCapacitySpecificationRequest::builder().total_target_capacity(1).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidFleetConfiguration");

    // A maintain fleet replaces what ends and follows its target.
    let maintain = ec2
        .create_fleet()
        .launch_template_configs(config(&[]))
        .target_capacity_specification(
            TargetCapacitySpecificationRequest::builder()
                .total_target_capacity(2)
                .default_target_capacity_type(DefaultTargetCapacityType::OnDemand)
                .build(),
        )
        .send()
        .await
        .unwrap()
        .fleet_id()
        .unwrap()
        .to_string();
    let members = ec2.describe_fleet_instances().fleet_id(&maintain).send().await.unwrap();
    assert_eq!(members.active_instances().len(), 2);
    let gone = members.active_instances()[0].instance_id().unwrap().to_string();
    terminate(&ec2, &gone).await;
    let members = ec2.describe_fleet_instances().fleet_id(&maintain).send().await.unwrap();
    assert_eq!(members.active_instances().len(), 2);
    assert!(members.active_instances().iter().all(|a| a.instance_id() != Some(gone.as_str())));
    ec2.modify_fleet()
        .fleet_id(&maintain)
        .target_capacity_specification(TargetCapacitySpecificationRequest::builder().total_target_capacity(1).build())
        .send()
        .await
        .unwrap();
    let members = ec2.describe_fleet_instances().fleet_id(&maintain).send().await.unwrap();
    assert_eq!(members.active_instances().len(), 1);

    let deleted =
        ec2.delete_fleets().fleet_ids(&maintain).fleet_ids(&fleet_id).terminate_instances(true).send().await.unwrap();
    assert_eq!(deleted.successful_fleet_deletions().len(), 2);
    assert_eq!(
        deleted.successful_fleet_deletions()[0].current_fleet_state().map(|s| s.as_str()),
        Some("deleted_terminating")
    );
    let history = ec2
        .describe_fleet_history()
        .fleet_id(&maintain)
        .start_time(aws_sdk_ec2::primitives::DateTime::from_secs(0))
        .send()
        .await
        .unwrap();
    let subs: Vec<_> = history
        .history_records()
        .iter()
        .filter_map(|h| h.event_information().and_then(|e| e.event_sub_type()))
        .collect();
    for want in ["submitted", "active", "launched", "terminated", "modify_succeeded", "deleted"] {
        assert!(subs.contains(&want), "{want} missing from {subs:?}");
    }
    let e = ec2.describe_fleets().fleet_ids("fleet-00000000-0000-4000-a000-000000000000").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidFleetId.NotFound");
}

#[tokio::test]
async fn dedicated_hosts_hold_the_instances_placed_on_them() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let ami = ami(&ec2).await;
    let host = ec2
        .allocate_hosts()
        .instance_type("m5.large")
        .availability_zone("us-east-1a")
        .auto_placement(AutoPlacement::On)
        .send()
        .await
        .unwrap()
        .host_ids()[0]
        .clone();
    let describe = |id: String| {
        let ec2 = ec2.clone();
        async move { ec2.describe_hosts().host_ids(id).send().await.unwrap().hosts()[0].clone() }
    };
    let h = describe(host.clone()).await;
    assert_eq!(h.state().map(|s| s.as_str()), Some("available"));
    let props = h.host_properties().unwrap();
    assert_eq!((props.sockets(), props.cores(), props.total_v_cpus()), (Some(2), Some(48), Some(96)));
    let cap = &h.available_capacity().unwrap().available_instance_capacity()[0];
    assert_eq!((cap.total_capacity(), cap.available_capacity()), (Some(48), Some(48)));

    // Tenancy host with auto-placement lands on the host.
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::M5Large)
        .placement(Placement::builder().tenancy(Tenancy::Host).availability_zone("us-east-1a").build())
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let instance = run.instances()[0].instance_id().unwrap().to_string();
    assert_eq!(run.instances()[0].placement().unwrap().host_id(), Some(host.as_str()));
    let h = describe(host.clone()).await;
    assert_eq!(h.instances()[0].instance_id(), Some(instance.as_str()));
    assert_eq!(h.available_capacity().unwrap().available_instance_capacity()[0].available_capacity(), Some(47));

    let e = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::C5Large)
        .placement(Placement::builder().host_id(&host).build())
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");

    // Occupied hosts are not released.
    let released = ec2.release_hosts().host_ids(&host).send().await.unwrap();
    assert_eq!(released.unsuccessful()[0].error().unwrap().code(), Some("Client.InvalidHost.Occupied"));
    terminate(&ec2, &instance).await;
    let released = ec2.release_hosts().host_ids(&host).send().await.unwrap();
    assert_eq!(released.successful(), std::slice::from_ref(&host));
    assert_eq!(describe(host.clone()).await.state().map(|s| s.as_str()), Some("released"));

    // A family host takes several sizes; stopped instances move onto it.
    let family =
        ec2.allocate_hosts().instance_family("c5").availability_zone("us-east-1a").send().await.unwrap().host_ids()[0]
            .clone();
    for ty in [InstanceType::C5Large, InstanceType::C5Xlarge] {
        ec2.run_instances()
            .image_id(&ami)
            .instance_type(ty)
            .placement(Placement::builder().host_id(&family).availability_zone("us-east-1a").build())
            .min_count(1)
            .max_count(1)
            .send()
            .await
            .unwrap();
    }
    let h = describe(family.clone()).await;
    assert_eq!(h.allows_multiple_instance_types().map(|a| a.as_str()), Some("on"));
    assert_eq!(h.available_capacity().unwrap().available_v_cpus(), Some(72 - 6));
    let moving = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::C5Large)
        .placement(Placement::builder().availability_zone("us-east-1a").build())
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap()
        .instances()[0]
        .instance_id()
        .unwrap()
        .to_string();
    let e = ec2.modify_instance_placement().instance_id(&moving).host_id(&family).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectInstanceState");
    wait_for(&ec2, &moving, "running").await;
    ec2.stop_instances().instance_ids(&moving).send().await.unwrap();
    for _ in 0..50 {
        if instance_state(&ec2, &moving).await == "stopped" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    ec2.modify_instance_placement().instance_id(&moving).host_id(&family).send().await.unwrap();
    let out = ec2.describe_instances().instance_ids(&moving).send().await.unwrap();
    let p = out.reservations()[0].instances()[0].placement().unwrap();
    assert_eq!((p.host_id(), p.tenancy().map(|t| t.as_str())), (Some(family.as_str()), Some("host")));

    let modified = ec2.modify_hosts().host_ids(&family).auto_placement(AutoPlacement::On).send().await.unwrap();
    assert_eq!(modified.successful(), std::slice::from_ref(&family));
    let e = ec2.allocate_hosts().instance_family("t2").availability_zone("us-east-1a").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let e = ec2.describe_hosts().host_ids("h-0123456789abcdef0").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidHostID.NotFound");
}

#[tokio::test]
async fn reserved_instances_are_offered_and_purchased() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let offerings = ec2
        .describe_reserved_instances_offerings()
        .instance_type(InstanceType::M5Large)
        .product_description(RiProductDescription::LinuxUnix)
        .offering_class(OfferingClassType::Standard)
        .offering_type(OfferingTypeValues::AllUpfront)
        .instance_tenancy(Tenancy::Default)
        .min_duration(31_536_000)
        .max_duration(31_536_000)
        .filters(filter("scope", "Region"))
        .send()
        .await
        .unwrap();
    let all = offerings.reserved_instances_offerings();
    assert_eq!(all.len(), 1, "{all:?}");
    let o = &all[0];
    assert!(o.fixed_price().unwrap() > 0.0 && (o.fixed_price().unwrap() as f64) < 0.096 * 8760.0);
    assert!(o.recurring_charges().is_empty());
    assert_eq!(o.currency_code().map(|c| c.as_str()), Some("USD"));
    let page = ec2
        .describe_reserved_instances_offerings()
        .instance_type(InstanceType::M5Large)
        .max_results(10)
        .send()
        .await
        .unwrap();
    assert_eq!(page.reserved_instances_offerings().len(), 10);
    let next = page.next_token().unwrap();
    let page2 = ec2
        .describe_reserved_instances_offerings()
        .instance_type(InstanceType::M5Large)
        .max_results(10)
        .next_token(next)
        .send()
        .await
        .unwrap();
    assert_ne!(
        page.reserved_instances_offerings()[0].reserved_instances_offering_id(),
        page2.reserved_instances_offerings()[0].reserved_instances_offering_id()
    );

    let ri = ec2
        .purchase_reserved_instances_offering()
        .reserved_instances_offering_id(o.reserved_instances_offering_id().unwrap())
        .instance_count(2)
        .send()
        .await
        .unwrap()
        .reserved_instances_id()
        .unwrap()
        .to_string();
    let later = ec2
        .purchase_reserved_instances_offering()
        .reserved_instances_offering_id(o.reserved_instances_offering_id().unwrap())
        .instance_count(1)
        .purchase_time(aws_sdk_ec2::primitives::DateTime::from_secs(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 + 86_400,
        ))
        .send()
        .await
        .unwrap()
        .reserved_instances_id()
        .unwrap()
        .to_string();
    let bought = ec2.describe_reserved_instances().reserved_instances_ids(&ri).send().await.unwrap();
    let r = &bought.reserved_instances()[0];
    assert_eq!(r.state().map(|s| s.as_str()), Some("active"));
    assert_eq!(r.instance_count(), Some(2));
    assert_eq!(r.instance_type().map(|t| t.as_str()), Some("m5.large"));
    assert_eq!(r.end().unwrap().secs() - r.start().unwrap().secs(), 31_536_000);
    let queued = ec2.describe_reserved_instances().filters(filter("state", "queued")).send().await.unwrap();
    assert_eq!(queued.reserved_instances()[0].reserved_instances_id(), Some(later.as_str()));

    let e = ec2
        .purchase_reserved_instances_offering()
        .reserved_instances_offering_id("00000000-0000-4000-a000-000000000000")
        .instance_count(1)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidReservedInstancesOfferingId");
}
