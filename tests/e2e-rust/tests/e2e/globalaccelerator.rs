//! AWS Global Accelerator through the official Rust SDK: static anycast
//! IPs, listeners and endpoint groups whose health follows the real EC2
//! endpoints, custom routing port mappings onto real subnets, BYOIP and
//! cross-account attachments.

use aws_sdk_ec2::types::{DomainType, InstanceStateName};
use aws_sdk_globalaccelerator::error::ProvideErrorMetadata;
use aws_sdk_globalaccelerator::types::{
    AcceleratorStatus, ByoipCidrState, CidrAuthorizationContext, ClientAffinity, CustomRoutingDestinationConfiguration,
    CustomRoutingDestinationTrafficState, CustomRoutingEndpointConfiguration, CustomRoutingProtocol,
    EndpointConfiguration, EndpointIdentifier, HealthCheckProtocol, HealthState, IpAddressType, PortOverride,
    PortRange, Protocol, Resource, Tag,
};
use aws_sdk_globalaccelerator::Client;
use mws_e2e::{sts_config, user_with_policy, Mws};
use serde_json::json;

const ACCOUNT: &str = "123456789012";
const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn ports(from: i32, to: i32) -> PortRange {
    PortRange::builder().from_port(from).to_port(to).build()
}

/// Let pending changes deploy (they take a second on the emulated clock).
async fn deploy(mws: &Mws) {
    let body = json!({"advanceSeconds": 2}).to_string();
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

async fn status(ga: &Client, arn: &str) -> AcceleratorStatus {
    let d = ga.describe_accelerator().accelerator_arn(arn).send().await.unwrap();
    d.accelerator().unwrap().status().unwrap().clone()
}

/// A running instance in the default VPC.
async fn instance(ec2: &aws_sdk_ec2::Client) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(aws_sdk_ec2::types::Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let run = ec2.run_instances().image_id(ami).min_count(1).max_count(1).send().await.unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    for _ in 0..100 {
        let d = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().unwrap().name() == Some(&InstanceStateName::Running) {
            return id;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("instance {id} never ran");
}

#[tokio::test]
async fn accelerator_lifecycle_and_static_ips() {
    let mws = Mws::start().await;
    let ga = Client::new(&mws.root_sdk_config().await);

    let e = ga.create_accelerator().name("-bad-").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");

    let created = ga
        .create_accelerator()
        .name("web")
        .idempotency_token("token-1")
        .tags(Tag::builder().key("team").value("edge").build().unwrap())
        .send()
        .await
        .unwrap();
    let a = created.accelerator().unwrap();
    let arn = a.accelerator_arn().unwrap().to_string();
    assert!(arn.starts_with(&format!("arn:aws:globalaccelerator::{ACCOUNT}:accelerator/")), "{arn}");
    assert_eq!(a.status(), Some(&AcceleratorStatus::InProgress));
    assert_eq!(a.enabled(), Some(true));
    assert_eq!(a.ip_address_type(), Some(&IpAddressType::Ipv4));
    assert!(a.dns_name().unwrap().ends_with(".awsglobalaccelerator.com"));
    assert!(a.dual_stack_dns_name().is_none());
    let sets = a.ip_sets();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].ip_address_family().map(|f| f.as_str()), Some("IPv4"));
    let ips = sets[0].ip_addresses().to_vec();
    assert_eq!(ips.len(), 2);
    assert!(ips[0].starts_with("75.2.") && ips[1].starts_with("99.83."), "{ips:?}");

    // Same idempotency token: the same accelerator.
    let again = ga.create_accelerator().name("web").idempotency_token("token-1").send().await.unwrap();
    assert_eq!(again.accelerator().unwrap().accelerator_arn(), Some(arn.as_str()));
    // Another accelerator never shares static IPs.
    let other = ga.create_accelerator().name("other").send().await.unwrap();
    let other_ips = other.accelerator().unwrap().ip_sets()[0].ip_addresses().to_vec();
    assert!(other_ips.iter().all(|ip| !ips.contains(ip)));

    deploy(&mws).await;
    assert_eq!(status(&ga, &arn).await, AcceleratorStatus::Deployed);
    let listed = ga.list_accelerators().max_results(1).send().await.unwrap();
    assert_eq!(listed.accelerators().len(), 1);
    let rest = ga.list_accelerators().next_token(listed.next_token().unwrap()).send().await.unwrap();
    assert_eq!(rest.accelerators().len(), 1);
    assert!(rest.next_token().is_none());

    // Dual stack adds two IPv6 addresses and a dual-stack DNS name; the
    // IPv4 addresses stay.
    let updated = ga
        .update_accelerator()
        .accelerator_arn(&arn)
        .ip_address_type(IpAddressType::DualStack)
        .name("web-2")
        .send()
        .await
        .unwrap();
    let a = updated.accelerator().unwrap();
    assert_eq!(a.status(), Some(&AcceleratorStatus::InProgress));
    assert_eq!(a.name(), Some("web-2"));
    assert_eq!(a.ip_sets().len(), 2);
    assert_eq!(a.ip_sets()[0].ip_addresses(), ips.as_slice());
    assert!(a.ip_sets()[1].ip_addresses().iter().all(|ip| ip.starts_with("2600:9000:a")));
    assert!(a.dual_stack_dns_name().unwrap().ends_with(".dualstack.awsglobalaccelerator.com"));

    // Flow logs need a bucket.
    let e = ga.update_accelerator_attributes().accelerator_arn(&arn).flow_logs_enabled(true).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let attrs = ga
        .update_accelerator_attributes()
        .accelerator_arn(&arn)
        .flow_logs_enabled(true)
        .flow_logs_s3_bucket("flow-logs")
        .flow_logs_s3_prefix("ga/")
        .send()
        .await
        .unwrap();
    assert_eq!(attrs.accelerator_attributes().unwrap().flow_logs_s3_bucket(), Some("flow-logs"));
    let attrs = ga.describe_accelerator_attributes().accelerator_arn(&arn).send().await.unwrap();
    let attrs = attrs.accelerator_attributes().unwrap();
    assert_eq!(attrs.flow_logs_enabled(), Some(true));
    assert_eq!(attrs.flow_logs_s3_prefix(), Some("ga/"));

    // Tags.
    ga.tag_resource()
        .resource_arn(&arn)
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .unwrap();
    ga.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let tags = ga.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    let keys: Vec<_> = tags.tags().iter().map(|t| t.key()).collect();
    assert_eq!(keys, ["env"]);

    // Deleting needs the accelerator disabled, deployed and without
    // listeners.
    let listener = ga
        .create_listener()
        .accelerator_arn(&arn)
        .protocol(Protocol::Tcp)
        .port_ranges(ports(443, 443))
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listener().unwrap().listener_arn().unwrap().to_string();
    let e = ga.delete_accelerator().accelerator_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AcceleratorNotDisabledException");
    ga.update_accelerator().accelerator_arn(&arn).enabled(false).send().await.unwrap();
    let e = ga.delete_accelerator().accelerator_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AcceleratorNotDisabledException");
    deploy(&mws).await;
    let e = ga.delete_accelerator().accelerator_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AssociatedListenerFoundException");
    ga.delete_listener().listener_arn(&listener_arn).send().await.unwrap();
    deploy(&mws).await;
    ga.delete_accelerator().accelerator_arn(&arn).send().await.unwrap();
    let e = ga.describe_accelerator().accelerator_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AcceleratorNotFoundException");
    let e = ga.describe_listener().listener_arn(&listener_arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ListenerNotFoundException");
}

#[tokio::test]
async fn endpoint_groups_follow_ec2_endpoints() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ga = Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);

    let a = ga.create_accelerator().name("app").send().await.unwrap();
    let arn = a.accelerator().unwrap().accelerator_arn().unwrap().to_string();
    let tcp = ga
        .create_listener()
        .accelerator_arn(&arn)
        .protocol(Protocol::Tcp)
        .port_ranges(ports(80, 80))
        .port_ranges(ports(443, 443))
        .client_affinity(ClientAffinity::SourceIp)
        .send()
        .await
        .unwrap();
    let tcp = tcp.listener().unwrap();
    assert_eq!(tcp.client_affinity(), Some(&ClientAffinity::SourceIp));
    let tcp_arn = tcp.listener_arn().unwrap().to_string();
    assert!(tcp_arn.starts_with(&format!("{arn}/listener/")));

    // Port ranges are unique per protocol on an accelerator.
    let e = ga
        .create_listener()
        .accelerator_arn(&arn)
        .protocol(Protocol::Tcp)
        .port_ranges(ports(440, 450))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPortRangeException");
    let udp = ga
        .create_listener()
        .accelerator_arn(&arn)
        .protocol(Protocol::Udp)
        .port_ranges(ports(443, 443))
        .send()
        .await
        .unwrap();
    let udp_arn = udp.listener().unwrap().listener_arn().unwrap().to_string();
    let listeners = ga.list_listeners().accelerator_arn(&arn).send().await.unwrap();
    assert_eq!(listeners.listeners().len(), 2);

    let instance_id = instance(&ec2).await;
    let eip = ec2.allocate_address().domain(DomainType::Vpc).send().await.unwrap();
    let allocation = eip.allocation_id().unwrap().to_string();
    ec2.associate_address().allocation_id(&allocation).instance_id(&instance_id).send().await.unwrap();

    // Endpoints must exist.
    let e = ga
        .create_endpoint_group()
        .listener_arn(&tcp_arn)
        .endpoint_group_region("us-east-1")
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id("i-0123456789abcdef0").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let e = ga
        .create_endpoint_group()
        .listener_arn(&tcp_arn)
        .endpoint_group_region("us-east-1")
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id("not-an-endpoint").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");

    let group = ga
        .create_endpoint_group()
        .listener_arn(&tcp_arn)
        .endpoint_group_region("us-east-1")
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id(&instance_id).weight(200).build())
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id(&allocation).build())
        .port_overrides(PortOverride::builder().listener_port(443).endpoint_port(8443).build())
        .send()
        .await
        .unwrap();
    let g = group.endpoint_group().unwrap();
    let group_arn = g.endpoint_group_arn().unwrap().to_string();
    assert!(group_arn.starts_with(&format!("{tcp_arn}/endpoint-group/")));
    assert_eq!(g.endpoint_group_region(), Some("us-east-1"));
    assert_eq!(g.traffic_dial_percentage(), Some(100.0));
    assert_eq!(g.health_check_port(), Some(80));
    assert_eq!(g.health_check_protocol(), Some(&HealthCheckProtocol::Tcp));
    assert_eq!(g.health_check_interval_seconds(), Some(30));
    assert_eq!(g.threshold_count(), Some(3));
    assert_eq!(g.port_overrides()[0].endpoint_port(), Some(8443));
    let endpoints = g.endpoint_descriptions();
    assert_eq!(endpoints[0].weight(), Some(200));
    assert_eq!(endpoints[0].client_ip_preservation_enabled(), Some(true));
    assert_eq!(endpoints[1].weight(), Some(128));
    assert_eq!(endpoints[1].client_ip_preservation_enabled(), Some(false));
    assert!(endpoints.iter().all(|e| e.health_state() == Some(&HealthState::Initial)));

    deploy(&mws).await;
    let d = ga.describe_endpoint_group().endpoint_group_arn(&group_arn).send().await.unwrap();
    let health: Vec<_> = d.endpoint_group().unwrap().endpoint_descriptions().iter().map(|e| e.health_state()).collect();
    assert_eq!(health, [Some(&HealthState::Healthy), Some(&HealthState::Healthy)]);

    // A stopped instance fails its health checks, through the Elastic IP
    // too.
    ec2.stop_instances().instance_ids(&instance_id).send().await.unwrap();
    crate::ec2::wait_state(&ec2, &instance_id, InstanceStateName::Stopped).await;
    let d = ga.describe_endpoint_group().endpoint_group_arn(&group_arn).send().await.unwrap();
    let endpoints = d.endpoint_group().unwrap().endpoint_descriptions();
    assert!(endpoints.iter().all(|e| e.health_state() == Some(&HealthState::Unhealthy)), "{endpoints:?}");
    assert!(endpoints[0].health_reason().unwrap().contains("stopped"));

    // One endpoint group per Region per listener.
    let e =
        ga.create_endpoint_group().listener_arn(&tcp_arn).endpoint_group_region("us-east-1").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "EndpointGroupAlreadyExistsException");
    // Port overrides must use listener ports.
    let e = ga
        .update_endpoint_group()
        .endpoint_group_arn(&group_arn)
        .port_overrides(PortOverride::builder().listener_port(8080).endpoint_port(80).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");

    // A load balancer in another Region of the group, and an Application
    // Load Balancer behind UDP, are refused.
    let alb = format!("arn:aws:elasticloadbalancing:eu-west-1:{ACCOUNT}:loadbalancer/app/web/50dc6c495c0c9188");
    let eu = ga
        .create_endpoint_group()
        .listener_arn(&udp_arn)
        .endpoint_group_region("eu-west-1")
        .health_check_protocol(HealthCheckProtocol::Http)
        .health_check_interval_seconds(10)
        .send()
        .await
        .unwrap();
    let eu = eu.endpoint_group().unwrap();
    assert_eq!(eu.health_check_path(), Some("/"));
    assert_eq!(eu.health_check_interval_seconds(), Some(10));
    let eu_arn = eu.endpoint_group_arn().unwrap().to_string();
    let e = ga
        .add_endpoints()
        .endpoint_group_arn(&eu_arn)
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id(&alb).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let e = ga
        .add_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id(&alb).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");

    // Add, update and remove endpoints.
    let second = instance(&ec2).await;
    let added = ga
        .add_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id(&second).weight(10).build())
        .send()
        .await
        .unwrap();
    assert_eq!(added.endpoint_descriptions().len(), 1);
    assert_eq!(added.endpoint_descriptions()[0].health_state(), Some(&HealthState::Initial));
    ga.remove_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_identifiers(EndpointIdentifier::builder().endpoint_id(&allocation).build().unwrap())
        .send()
        .await
        .unwrap();
    let updated = ga
        .update_endpoint_group()
        .endpoint_group_arn(&group_arn)
        .traffic_dial_percentage(50.0)
        .threshold_count(5)
        .send()
        .await
        .unwrap();
    let g = updated.endpoint_group().unwrap();
    assert_eq!(g.traffic_dial_percentage(), Some(50.0));
    assert_eq!(g.threshold_count(), Some(5));
    let ids: Vec<_> = g.endpoint_descriptions().iter().map(|e| e.endpoint_id().unwrap()).collect();
    assert_eq!(ids, [instance_id.as_str(), second.as_str()]);
    let e = ga
        .update_endpoint_group()
        .endpoint_group_arn(&group_arn)
        .health_check_interval_seconds(20)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let groups = ga.list_endpoint_groups().listener_arn(&tcp_arn).send().await.unwrap();
    assert_eq!(groups.endpoint_groups().len(), 1);

    // Listeners with endpoint groups can't be deleted.
    let e = ga.delete_listener().listener_arn(&tcp_arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AssociatedEndpointGroupFoundException");
    // The port override on 443 must stay in the listener's ports.
    let e = ga.update_listener().listener_arn(&tcp_arn).port_ranges(ports(80, 80)).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    ga.delete_endpoint_group().endpoint_group_arn(&group_arn).send().await.unwrap();
    let e = ga.describe_endpoint_group().endpoint_group_arn(&group_arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "EndpointGroupNotFoundException");
    let l = ga.update_listener().listener_arn(&tcp_arn).port_ranges(ports(8000, 8010)).send().await.unwrap();
    assert_eq!(l.listener().unwrap().port_ranges()[0].from_port(), Some(8000));
    ga.delete_listener().listener_arn(&tcp_arn).send().await.unwrap();
}

#[tokio::test]
async fn custom_routing_maps_ports_onto_subnets() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ga = Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let vpc = ec2.create_vpc().cidr_block("10.9.0.0/16").send().await.unwrap();
    let vpc_id = vpc.vpc().unwrap().vpc_id().unwrap().to_string();
    let subnet = ec2.create_subnet().vpc_id(&vpc_id).cidr_block("10.9.1.0/28").send().await.unwrap();
    let subnet_id = subnet.subnet().unwrap().subnet_id().unwrap().to_string();
    let big = ec2.create_subnet().vpc_id(&vpc_id).cidr_block("10.9.4.0/24").send().await.unwrap();
    let big_id = big.subnet().unwrap().subnet_id().unwrap().to_string();

    let a = ga.create_custom_routing_accelerator().name("games").send().await.unwrap();
    let a = a.accelerator().unwrap();
    let arn = a.accelerator_arn().unwrap().to_string();
    let static_ips = a.ip_sets()[0].ip_addresses().to_vec();
    // A custom routing accelerator is not a standard one.
    let e = ga.describe_accelerator().accelerator_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AcceleratorNotFoundException");
    let listed = ga.list_custom_routing_accelerators().send().await.unwrap();
    assert_eq!(listed.accelerators().len(), 1);

    let listener = ga
        .create_custom_routing_listener()
        .accelerator_arn(&arn)
        .port_ranges(ports(10000, 10099))
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listener().unwrap().listener_arn().unwrap().to_string();
    let group = ga
        .create_custom_routing_endpoint_group()
        .listener_arn(&listener_arn)
        .endpoint_group_region("us-east-1")
        .destination_configurations(
            CustomRoutingDestinationConfiguration::builder()
                .from_port(80)
                .to_port(81)
                .protocols(CustomRoutingProtocol::Tcp)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let group_arn = group.endpoint_group().unwrap().endpoint_group_arn().unwrap().to_string();

    // 16 addresses x 2 ports fit in the 100 listener ports; 256 x 2 don't.
    let e = ga
        .add_custom_routing_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_configurations(CustomRoutingEndpointConfiguration::builder().endpoint_id(&big_id).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let e = ga
        .add_custom_routing_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_configurations(
            CustomRoutingEndpointConfiguration::builder().endpoint_id("subnet-0123456789abcdef0").build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    ga.add_custom_routing_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_configurations(CustomRoutingEndpointConfiguration::builder().endpoint_id(&subnet_id).build())
        .send()
        .await
        .unwrap();
    let e = ga
        .add_custom_routing_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_configurations(CustomRoutingEndpointConfiguration::builder().endpoint_id(&subnet_id).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "EndpointAlreadyExistsException");

    let mappings = ga.list_custom_routing_port_mappings().accelerator_arn(&arn).send().await.unwrap();
    let m = mappings.port_mappings();
    assert_eq!(m.len(), 32);
    assert_eq!(m[0].accelerator_port(), Some(10000));
    assert_eq!(m[0].destination_socket_address().unwrap().ip_address(), Some("10.9.1.0"));
    assert_eq!(m[0].destination_socket_address().unwrap().port(), Some(80));
    assert_eq!(m[1].destination_socket_address().unwrap().port(), Some(81));
    assert_eq!(m[31].accelerator_port(), Some(10031));
    assert_eq!(m[31].destination_socket_address().unwrap().ip_address(), Some("10.9.1.15"));
    assert!(m.iter().all(|m| m.destination_traffic_state() == Some(&CustomRoutingDestinationTrafficState::Deny)));
    let page = ga.list_custom_routing_port_mappings().accelerator_arn(&arn).max_results(20).send().await.unwrap();
    let rest = ga
        .list_custom_routing_port_mappings()
        .accelerator_arn(&arn)
        .next_token(page.next_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(rest.port_mappings().len(), 12);
    assert_eq!(rest.port_mappings()[0].accelerator_port(), Some(10020));

    // Allow one destination, then everything but one port.
    ga.allow_custom_routing_traffic()
        .endpoint_group_arn(&group_arn)
        .endpoint_id(&subnet_id)
        .destination_addresses("10.9.1.5")
        .destination_ports(81)
        .send()
        .await
        .unwrap();
    let e = ga
        .allow_custom_routing_traffic()
        .endpoint_group_arn(&group_arn)
        .endpoint_id(&subnet_id)
        .destination_addresses("10.9.2.5")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let by_dest = ga
        .list_custom_routing_port_mappings_by_destination()
        .endpoint_id(&subnet_id)
        .destination_address("10.9.1.5")
        .send()
        .await
        .unwrap();
    let d = by_dest.destination_port_mappings();
    assert_eq!(d.len(), 2);
    assert_eq!(d[1].destination_traffic_state(), Some(&CustomRoutingDestinationTrafficState::Allow));
    assert_eq!(d[0].destination_traffic_state(), Some(&CustomRoutingDestinationTrafficState::Deny));
    let sockets = d[1].accelerator_socket_addresses();
    assert_eq!(sockets.len(), 2);
    assert_eq!(sockets[0].ip_address(), Some(static_ips[0].as_str()));
    assert_eq!(sockets[0].port(), Some(10011));
    assert_eq!(d[1].endpoint_group_region(), Some("us-east-1"));

    ga.allow_custom_routing_traffic()
        .endpoint_group_arn(&group_arn)
        .endpoint_id(&subnet_id)
        .allow_all_traffic_to_endpoint(true)
        .send()
        .await
        .unwrap();
    ga.deny_custom_routing_traffic()
        .endpoint_group_arn(&group_arn)
        .endpoint_id(&subnet_id)
        .destination_ports(80)
        .send()
        .await
        .unwrap();
    let mappings = ga.list_custom_routing_port_mappings().accelerator_arn(&arn).send().await.unwrap();
    for m in mappings.port_mappings() {
        let port = m.destination_socket_address().unwrap().port().unwrap();
        let expected = if port == 80 {
            CustomRoutingDestinationTrafficState::Deny
        } else {
            CustomRoutingDestinationTrafficState::Allow
        };
        assert_eq!(m.destination_traffic_state(), Some(&expected));
    }

    // The listener can't shrink below the mapped ports.
    let e = ga
        .update_custom_routing_listener()
        .listener_arn(&listener_arn)
        .port_ranges(ports(10000, 10009))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPortRangeException");

    let e = ga
        .list_custom_routing_port_mappings_by_destination()
        .endpoint_id(&big_id)
        .destination_address("10.9.4.1")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "EndpointNotFoundException");
    ga.remove_custom_routing_endpoints().endpoint_group_arn(&group_arn).endpoint_ids(&subnet_id).send().await.unwrap();
    let described = ga.describe_custom_routing_endpoint_group().endpoint_group_arn(&group_arn).send().await.unwrap();
    let described = described.endpoint_group().unwrap();
    assert!(described.endpoint_descriptions().is_empty());
    assert_eq!(described.destination_descriptions()[0].to_port(), Some(81));
    let groups = ga.list_custom_routing_endpoint_groups().listener_arn(&listener_arn).send().await.unwrap();
    assert_eq!(groups.endpoint_groups().len(), 1);
    ga.delete_custom_routing_endpoint_group().endpoint_group_arn(&group_arn).send().await.unwrap();
    let listeners = ga.list_custom_routing_listeners().accelerator_arn(&arn).send().await.unwrap();
    assert_eq!(listeners.listeners().len(), 1);
    let l = ga.describe_custom_routing_listener().listener_arn(&listener_arn).send().await.unwrap();
    assert_eq!(l.listener().unwrap().port_ranges()[0].to_port(), Some(10099));
    ga.delete_custom_routing_listener().listener_arn(&listener_arn).send().await.unwrap();

    let attrs = ga.describe_custom_routing_accelerator_attributes().accelerator_arn(&arn).send().await.unwrap();
    assert_eq!(attrs.accelerator_attributes().unwrap().flow_logs_enabled(), Some(false));
    ga.update_custom_routing_accelerator_attributes()
        .accelerator_arn(&arn)
        .flow_logs_enabled(true)
        .flow_logs_s3_bucket("cr-logs")
        .send()
        .await
        .unwrap();
    ga.update_custom_routing_accelerator().accelerator_arn(&arn).enabled(false).send().await.unwrap();
    let d = ga.describe_custom_routing_accelerator().accelerator_arn(&arn).send().await.unwrap();
    assert_eq!(d.accelerator().unwrap().enabled(), Some(false));
    deploy(&mws).await;
    ga.delete_custom_routing_accelerator().accelerator_arn(&arn).send().await.unwrap();
}

#[tokio::test]
async fn byoip_ranges_and_cross_account_attachments() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let ga = Client::new(&root);

    // BYOIP ranges move through their states on the clock.
    let auth = CidrAuthorizationContext::builder()
        .message("1|aws|123456789012|203.0.113.0/24|20991231|SHA256|RSAPSS")
        .signature("c2lnbmF0dXJl")
        .build()
        .unwrap();
    let e = ga
        .provision_byoip_cidr()
        .cidr("203.0.113.0/25")
        .cidr_authorization_context(auth.clone())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let p =
        ga.provision_byoip_cidr().cidr("203.0.113.0/24").cidr_authorization_context(auth.clone()).send().await.unwrap();
    assert_eq!(p.byoip_cidr().unwrap().state(), Some(&ByoipCidrState::PendingProvisioning));
    let e = ga.advertise_byoip_cidr().cidr("203.0.113.0/24").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectCidrStateException");
    deploy(&mws).await;
    let a = ga.advertise_byoip_cidr().cidr("203.0.113.0/24").send().await.unwrap();
    assert_eq!(a.byoip_cidr().unwrap().state(), Some(&ByoipCidrState::PendingAdvertising));
    deploy(&mws).await;
    let listed = ga.list_byoip_cidrs().send().await.unwrap();
    let c = &listed.byoip_cidrs()[0];
    assert_eq!(c.state(), Some(&ByoipCidrState::Advertising));
    assert_eq!(c.events().len(), 2);
    let e = ga.withdraw_byoip_cidr().cidr("198.51.100.0/24").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ByoipCidrNotFoundException");

    // An accelerator can take addresses from the range.
    let e = ga.create_accelerator().name("bad-ip").ip_addresses("192.0.2.10").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let byo = ga.create_accelerator().name("byo").ip_addresses("203.0.113.10").send().await.unwrap();
    let byo = byo.accelerator().unwrap();
    let byo_arn = byo.accelerator_arn().unwrap().to_string();
    let ips = byo.ip_sets()[0].ip_addresses();
    assert_eq!(ips[0], "203.0.113.10");
    assert!(ips[1].starts_with("99.83."));
    ga.withdraw_byoip_cidr().cidr("203.0.113.0/24").send().await.unwrap();
    deploy(&mws).await;
    let e = ga.deprovision_byoip_cidr().cidr("203.0.113.0/24").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectCidrStateException");
    ga.update_accelerator().accelerator_arn(&byo_arn).enabled(false).send().await.unwrap();
    deploy(&mws).await;
    ga.delete_accelerator().accelerator_arn(&byo_arn).send().await.unwrap();
    let d = ga.deprovision_byoip_cidr().cidr("203.0.113.0/24").send().await.unwrap();
    assert_eq!(d.byoip_cidr().unwrap().state(), Some(&ByoipCidrState::PendingDeprovisioning));

    // A member account shares its Elastic IP with the management account.
    let orgs = aws_sdk_organizations::Client::new(&root);
    orgs.create_organization().send().await.unwrap();
    let created = orgs.create_account().email("edge@example.com").account_name("edge").send().await.unwrap();
    let request = created.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request).send().await.unwrap();
    let member = status.create_account_status().unwrap().account_id().unwrap().to_string();
    let (_, admin) = user_with_policy(&mws, "admin", Some(ADMIN)).await;
    let creds = aws_sdk_sts::Client::new(&admin)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{member}:role/OrganizationAccountAccessRole"))
        .role_session_name("ga")
        .send()
        .await
        .unwrap();
    let member_cfg = sts_config(&mws, creds.credentials().unwrap()).await;
    let member_ga = Client::new(&member_cfg);
    let member_ec2 = aws_sdk_ec2::Client::new(&member_cfg);
    let eip = member_ec2.allocate_address().domain(DomainType::Vpc).send().await.unwrap();
    let allocation = eip.allocation_id().unwrap().to_string();

    let accelerator = ga.create_accelerator().name("shared").send().await.unwrap();
    let arn = accelerator.accelerator().unwrap().accelerator_arn().unwrap().to_string();
    let listener = ga
        .create_listener()
        .accelerator_arn(&arn)
        .protocol(Protocol::Tcp)
        .port_ranges(ports(80, 80))
        .send()
        .await
        .unwrap();
    let group = ga
        .create_endpoint_group()
        .listener_arn(listener.listener().unwrap().listener_arn().unwrap())
        .endpoint_group_region("us-east-1")
        .send()
        .await
        .unwrap();
    let group_arn = group.endpoint_group().unwrap().endpoint_group_arn().unwrap().to_string();
    let endpoint = |attachment: Option<&str>| {
        EndpointConfiguration::builder()
            .endpoint_id(&allocation)
            .client_ip_preservation_enabled(false)
            .set_attachment_arn(attachment.map(str::to_string))
            .build()
    };

    // The member's EIP isn't the caller's: without an attachment it
    // doesn't exist here.
    let e = ga
        .add_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_configurations(endpoint(None))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");

    let e = member_ga
        .create_cross_account_attachment()
        .name("share")
        .principals(ACCOUNT)
        .resources(Resource::builder().endpoint_id("eipalloc-0123456789abcdef0").region("us-east-1").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");
    let attachment = member_ga
        .create_cross_account_attachment()
        .name("share")
        .principals(ACCOUNT)
        .resources(Resource::builder().endpoint_id(&allocation).region("us-east-1").build())
        .tags(Tag::builder().key("purpose").value("edge").build().unwrap())
        .send()
        .await
        .unwrap();
    let attachment = attachment.cross_account_attachment().unwrap();
    let attachment_arn = attachment.attachment_arn().unwrap().to_string();
    assert!(attachment_arn.starts_with(&format!("arn:aws:globalaccelerator::{member}:attachment/")));

    let accounts = ga.list_cross_account_resource_accounts().send().await.unwrap();
    assert_eq!(accounts.resource_owner_aws_account_ids(), std::slice::from_ref(&member));
    let resources = ga.list_cross_account_resources().resource_owner_aws_account_id(&member).send().await.unwrap();
    let r = &resources.cross_account_resources()[0];
    assert_eq!(r.endpoint_id(), Some(allocation.as_str()));
    assert_eq!(r.attachment_arn(), Some(attachment_arn.as_str()));

    let added = ga
        .add_endpoints()
        .endpoint_group_arn(&group_arn)
        .endpoint_configurations(endpoint(Some(&attachment_arn)))
        .send()
        .await
        .unwrap();
    assert_eq!(added.endpoint_descriptions()[0].endpoint_id(), Some(allocation.as_str()));
    deploy(&mws).await;
    let d = ga.describe_endpoint_group().endpoint_group_arn(&group_arn).send().await.unwrap();
    let e = &d.endpoint_group().unwrap().endpoint_descriptions()[0];
    // Not associated with anything: unhealthy.
    assert_eq!(e.health_state(), Some(&HealthState::Unhealthy));

    // Removing the principal stops the sharing.
    let updated = member_ga
        .update_cross_account_attachment()
        .attachment_arn(&attachment_arn)
        .remove_principals(ACCOUNT)
        .add_principals(&arn)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.cross_account_attachment().unwrap().principals(), std::slice::from_ref(&arn));
    let described = member_ga.describe_cross_account_attachment().attachment_arn(&attachment_arn).send().await.unwrap();
    assert_eq!(described.cross_account_attachment().unwrap().name(), Some("share"));
    let listed = member_ga.list_cross_account_attachments().send().await.unwrap();
    assert_eq!(listed.cross_account_attachments().len(), 1);
    let tags = member_ga.list_tags_for_resource().resource_arn(&attachment_arn).send().await.unwrap();
    assert_eq!(tags.tags()[0].value(), "edge");
    let e = ga.describe_cross_account_attachment().attachment_arn(&attachment_arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AttachmentNotFoundException");
    member_ga.delete_cross_account_attachment().attachment_arn(&attachment_arn).send().await.unwrap();
    let accounts = ga.list_cross_account_resource_accounts().send().await.unwrap();
    assert!(accounts.resource_owner_aws_account_ids().is_empty());
}

#[tokio::test]
async fn route53_aliases_resolve_to_the_static_ips() {
    use aws_sdk_route53::types::{AliasTarget, Change, ChangeAction, ChangeBatch, ResourceRecordSet, RrType};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ga = Client::new(&cfg);
    let r53 = aws_sdk_route53::Client::new(&cfg);
    let a = ga.create_accelerator().name("dns").ip_address_type(IpAddressType::DualStack).send().await.unwrap();
    let a = a.accelerator().unwrap();
    let v4 = a.ip_sets()[0].ip_addresses().to_vec();
    let v6 = a.ip_sets()[1].ip_addresses().to_vec();
    let zone = r53.create_hosted_zone().name("example.com").caller_reference("ga").send().await.unwrap();
    let zone_id = zone.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    let alias = |name: &str, ty: RrType, target: &str| {
        Change::builder()
            .action(ChangeAction::Create)
            .resource_record_set(
                ResourceRecordSet::builder()
                    .name(name)
                    .r#type(ty)
                    .alias_target(
                        AliasTarget::builder()
                            .hosted_zone_id("Z2BJ6XQ5FK7U4H")
                            .dns_name(target)
                            .evaluate_target_health(true)
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    };
    let dual = a.dual_stack_dns_name().unwrap();
    r53.change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(
            ChangeBatch::builder()
                .changes(alias("www.example.com", RrType::A, a.dns_name().unwrap()))
                .changes(alias("app.example.com", RrType::A, dual))
                .changes(alias("app.example.com", RrType::Aaaa, dual))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let answer = |name: &'static str, ty: RrType| {
        r53.test_dns_answer().hosted_zone_id(&zone_id).record_name(name).record_type(ty).send()
    };
    let www = answer("www.example.com", RrType::A).await.unwrap();
    let mut got = www.record_data().to_vec();
    got.sort();
    let mut want = v4.clone();
    want.sort();
    assert_eq!(got, want);
    let app = answer("app.example.com", RrType::Aaaa).await.unwrap();
    assert_eq!(app.record_data().len(), 2);
    assert!(app.record_data().iter().all(|ip| v6.contains(ip)));
}

#[tokio::test]
async fn calls_are_authorized_through_iam() {
    let mws = Mws::start().await;
    let ga = Client::new(&mws.root_sdk_config().await);
    let a = ga
        .create_accelerator()
        .name("guarded")
        .tags(Tag::builder().key("team").value("edge").build().unwrap())
        .send()
        .await
        .unwrap();
    let arn = a.accelerator().unwrap().accelerator_arn().unwrap().to_string();

    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"globalaccelerator:Describe*","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"edge"}}},
        {"Effect":"Allow","Action":"globalaccelerator:ListAccelerators","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "viewer", Some(policy)).await;
    let viewer = Client::new(&cfg);
    viewer.describe_accelerator().accelerator_arn(&arn).send().await.unwrap();
    viewer.list_accelerators().send().await.unwrap();
    let e = viewer.create_accelerator().name("nope").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AccessDeniedException");
    let e = viewer.update_accelerator().accelerator_arn(&arn).enabled(false).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AccessDeniedException");
    ga.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let e = viewer.describe_accelerator().accelerator_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AccessDeniedException");
}

#[tokio::test]
async fn load_balancer_endpoints_follow_elb() {
    use aws_sdk_elasticloadbalancingv2::types::{ProtocolEnum, TargetDescription, TargetHealthStateEnum};

    use crate::elbv2::{default_network, forward, ip_target_group, wait_for_health, Backend};

    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ga = Client::new(&cfg);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&cfg);
    let (vpc, subnets) = default_network(&mws).await;
    let lb = elb.create_load_balancer().name("edge").set_subnets(Some(subnets)).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();

    let a = ga.create_accelerator().name("front").send().await.unwrap();
    let arn = a.accelerator().unwrap().accelerator_arn().unwrap().to_string();
    let listener = ga
        .create_listener()
        .accelerator_arn(&arn)
        .protocol(Protocol::Tcp)
        .port_ranges(ports(80, 80))
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listener().unwrap().listener_arn().unwrap().to_string();

    // A load balancer that doesn't exist is refused.
    let missing = format!("arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/gone/50dc6c495c0c9188");
    let e = ga
        .create_endpoint_group()
        .listener_arn(&listener_arn)
        .endpoint_group_region("us-east-1")
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id(&missing).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidArgumentException");

    let group = ga
        .create_endpoint_group()
        .listener_arn(&listener_arn)
        .endpoint_group_region("us-east-1")
        .endpoint_configurations(EndpointConfiguration::builder().endpoint_id(&lb_arn).build())
        .send()
        .await
        .unwrap();
    let group_arn = group.endpoint_group().unwrap().endpoint_group_arn().unwrap().to_string();
    let health = |ga: Client, group_arn: String| async move {
        let d = ga.describe_endpoint_group().endpoint_group_arn(group_arn).send().await.unwrap();
        d.endpoint_group().unwrap().endpoint_descriptions()[0].clone()
    };
    deploy(&mws).await;
    // No healthy targets yet.
    let e = health(ga.clone(), group_arn.clone()).await;
    assert_eq!(e.health_state(), Some(&HealthState::Unhealthy));
    assert!(e.health_reason().unwrap().contains("no healthy targets"), "{e:?}");

    // A healthy target behind a listener makes the endpoint healthy.
    let backend = Backend::start("ga").await;
    let tg = ip_target_group(&elb, "ga-targets", &vpc, ProtocolEnum::Http).await;
    elb.register_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(backend.port()).build())
        .send()
        .await
        .unwrap();
    elb.create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();
    wait_for_health(&elb, &tg, &[(backend.port(), TargetHealthStateEnum::Healthy)]).await;
    let e = health(ga.clone(), group_arn.clone()).await;
    assert_eq!(e.health_state(), Some(&HealthState::Healthy), "{e:?}");
    assert_eq!(e.client_ip_preservation_enabled(), Some(true));
}
