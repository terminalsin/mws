//! VPC endpoints, prefix lists, NAT gateways and Elastic IP attributes
//! through the official Rust SDK (metadata-only backend; `ec2_docker` shows
//! security groups, network ACLs and routes filtering real traffic).

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{
    AddPrefixListEntry, AttributeBooleanValue, DnsOptionsSpecification, Filter, IpPermission, PrefixListId,
    RemovePrefixListEntry, ResourceType, Tag, TagSpecification, VpcEndpointType,
};
use aws_sdk_ec2::Client;
use mws_e2e::Mws;

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

/// A VPC with two subnets in different zones, and the VPC's main route
/// table.
async fn network(ec2: &Client, cidr: &str) -> (String, Vec<String>, String) {
    let vpc = ec2.create_vpc().cidr_block(cidr).send().await.unwrap();
    let vpc_id = vpc.vpc().unwrap().vpc_id().unwrap().to_string();
    let base = cidr.trim_end_matches(".0.0/16");
    let mut subnets = Vec::new();
    for (i, zone) in ["us-east-1a", "us-east-1b"].iter().enumerate() {
        let s = ec2
            .create_subnet()
            .vpc_id(&vpc_id)
            .cidr_block(format!("{base}.{}.0/24", i + 1))
            .availability_zone(*zone)
            .send()
            .await
            .unwrap();
        subnets.push(s.subnet().unwrap().subnet_id().unwrap().to_string());
    }
    let rts = ec2
        .describe_route_tables()
        .filters(filter("vpc-id", &vpc_id))
        .filters(filter("association.main", "true"))
        .send()
        .await
        .unwrap();
    let main = rts.route_tables()[0].route_table_id().unwrap().to_string();
    (vpc_id, subnets, main)
}

#[tokio::test]
async fn gateway_endpoints_route_to_prefix_lists() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let (vpc_id, _, main_rt) = network(&ec2, "10.60.0.0/16").await;

    // The service catalogue offers S3 both ways and STS as an interface.
    let services = ec2.describe_vpc_endpoint_services().send().await.unwrap();
    let s3: Vec<_> =
        services.service_details().iter().filter(|d| d.service_name() == Some("com.amazonaws.us-east-1.s3")).collect();
    assert_eq!(s3.len(), 2);
    let sts = ec2.describe_vpc_endpoint_services().service_names("com.amazonaws.us-east-1.sts").send().await.unwrap();
    let sts = &sts.service_details()[0];
    assert_eq!(sts.private_dns_name(), Some("sts.us-east-1.amazonaws.com"));
    assert_eq!(sts.base_endpoint_dns_names(), ["sts.us-east-1.vpce.amazonaws.com"]);
    assert_eq!(sts.owner(), Some("amazon"));
    let gateways =
        ec2.describe_vpc_endpoint_services().filters(filter("service-type", "Gateway")).send().await.unwrap();
    assert_eq!(gateways.service_names(), ["com.amazonaws.us-east-1.dynamodb", "com.amazonaws.us-east-1.s3"]);
    let e =
        ec2.describe_vpc_endpoint_services().service_names("com.amazonaws.us-east-1.nope").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidServiceName");

    // The S3 prefix list has AWS's id in us-east-1.
    let pls = ec2
        .describe_prefix_lists()
        .filters(filter("prefix-list-name", "com.amazonaws.us-east-1.s3"))
        .send()
        .await
        .unwrap();
    let pl = &pls.prefix_lists()[0];
    assert_eq!(pl.prefix_list_id(), Some("pl-63a5400a"));
    assert!(!pl.cidrs().is_empty());
    let entries = ec2.get_managed_prefix_list_entries().prefix_list_id("pl-63a5400a").send().await.unwrap();
    assert_eq!(entries.entries().len(), pl.cidrs().len());

    let ep = ec2
        .create_vpc_endpoint()
        .vpc_id(&vpc_id)
        .service_name("com.amazonaws.us-east-1.s3")
        .route_table_ids(&main_rt)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::VpcEndpoint)
                .tags(Tag::builder().key("Name").value("s3").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let ep = ep.vpc_endpoint().unwrap();
    let ep_id = ep.vpc_endpoint_id().unwrap().to_string();
    assert!(ep_id.starts_with("vpce-"));
    assert_eq!(ep.vpc_endpoint_type(), Some(&VpcEndpointType::Gateway));
    assert!(ep.policy_document().unwrap().contains("\"Effect\":\"Allow\""));
    let rt = ec2.describe_route_tables().route_table_ids(&main_rt).send().await.unwrap();
    let route = rt.route_tables()[0]
        .routes()
        .iter()
        .find(|r| r.destination_prefix_list_id() == Some("pl-63a5400a"))
        .expect("a route to the S3 prefix list");
    assert_eq!(route.gateway_id(), Some(ep_id.as_str()));
    let by_pl = ec2
        .describe_route_tables()
        .filters(filter("route.destination-prefix-list-id", "pl-63a5400a"))
        .send()
        .await
        .unwrap();
    assert_eq!(by_pl.route_tables().len(), 1);

    // One gateway endpoint per service and VPC.
    let e =
        ec2.create_vpc_endpoint().vpc_id(&vpc_id).service_name("com.amazonaws.us-east-1.s3").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "RouteAlreadyExists");

    // Policies and route tables change; the route goes with the table.
    let policy = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}"#;
    ec2.modify_vpc_endpoint()
        .vpc_endpoint_id(&ep_id)
        .policy_document(policy)
        .remove_route_table_ids(&main_rt)
        .send()
        .await
        .unwrap();
    let d = ec2.describe_vpc_endpoints().vpc_endpoint_ids(&ep_id).send().await.unwrap();
    let got = &d.vpc_endpoints()[0];
    assert_eq!(got.policy_document(), Some(policy));
    assert!(got.route_table_ids().is_empty());
    assert_eq!(got.state().map(|s| s.as_str()), Some("available"));
    let rt = ec2.describe_route_tables().route_table_ids(&main_rt).send().await.unwrap();
    assert!(rt.route_tables()[0].routes().iter().all(|r| r.destination_prefix_list_id().is_none()));
    ec2.modify_vpc_endpoint()
        .vpc_endpoint_id(&ep_id)
        .reset_policy(true)
        .add_route_table_ids(&main_rt)
        .send()
        .await
        .unwrap();
    let by_tag = ec2.describe_vpc_endpoints().filters(filter("tag:Name", "s3")).send().await.unwrap();
    assert_eq!(by_tag.vpc_endpoints()[0].route_table_ids(), [main_rt.as_str()]);

    // A VPC with an endpoint cannot be deleted.
    let e = ec2.delete_vpc().vpc_id(&vpc_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DependencyViolation");

    let del = ec2
        .delete_vpc_endpoints()
        .vpc_endpoint_ids(&ep_id)
        .vpc_endpoint_ids("vpce-0123456789abcdef0")
        .send()
        .await
        .unwrap();
    assert_eq!(del.unsuccessful().len(), 1);
    let failure = &del.unsuccessful()[0];
    assert_eq!(failure.resource_id(), Some("vpce-0123456789abcdef0"));
    assert_eq!(failure.error().unwrap().code(), Some("InvalidVpcEndpoint.NotFound"));
    let rt = ec2.describe_route_tables().route_table_ids(&main_rt).send().await.unwrap();
    assert!(rt.route_tables()[0].routes().iter().all(|r| r.destination_prefix_list_id().is_none()));
    let e = ec2.describe_vpc_endpoints().vpc_endpoint_ids(&ep_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidVpcEndpoint.NotFound");
    let e = ec2.describe_vpc_endpoints().vpc_endpoint_ids("vpce-nope").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidVpcEndpointId.Malformed");
    ec2.delete_vpc().vpc_id(&vpc_id).send().await.unwrap_err(); // subnets remain
    mws.stop().await;
}

#[tokio::test]
async fn interface_endpoints_with_private_dns() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let (vpc_id, subnets, _) = network(&ec2, "10.61.0.0/16").await;
    let sg = ec2
        .create_security_group()
        .group_name("endpoints")
        .description("endpoints")
        .vpc_id(&vpc_id)
        .send()
        .await
        .unwrap();
    let sg_id = sg.group_id().unwrap().to_string();

    // Private DNS (on by default) needs the VPC's DNS hostnames.
    let e = ec2
        .create_vpc_endpoint()
        .vpc_id(&vpc_id)
        .vpc_endpoint_type(VpcEndpointType::Interface)
        .service_name("com.amazonaws.us-east-1.sts")
        .subnet_ids(&subnets[0])
        .send()
        .await
        .unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "InvalidParameter");
    assert!(message(&e).contains("enableDnsSupport and enableDnsHostnames"), "{}", message(&e));
    ec2.modify_vpc_attribute()
        .vpc_id(&vpc_id)
        .enable_dns_hostnames(AttributeBooleanValue::builder().value(true).build())
        .send()
        .await
        .unwrap();

    let ep = ec2
        .create_vpc_endpoint()
        .vpc_id(&vpc_id)
        .vpc_endpoint_type(VpcEndpointType::Interface)
        .service_name("com.amazonaws.us-east-1.sts")
        .subnet_ids(&subnets[0])
        .security_group_ids(&sg_id)
        .dns_options(DnsOptionsSpecification::builder().dns_record_ip_type("ipv4".into()).build())
        .send()
        .await
        .unwrap();
    let ep = ep.vpc_endpoint().unwrap();
    let ep_id = ep.vpc_endpoint_id().unwrap().to_string();
    assert_eq!(ep.private_dns_enabled(), Some(true));
    assert_eq!(ep.groups()[0].group_id(), Some(sg_id.as_str()));
    let names: Vec<&str> = ep.dns_entries().iter().filter_map(|d| d.dns_name()).collect();
    assert_eq!(names.len(), 3, "{names:?}");
    assert!(names[0].starts_with(&format!("{ep_id}-")) && names[0].ends_with(".sts.us-east-1.vpce.amazonaws.com"));
    assert!(names[1].ends_with("-us-east-1a.sts.us-east-1.vpce.amazonaws.com"), "{names:?}");
    assert_eq!(names[2], "sts.us-east-1.amazonaws.com");
    assert_eq!(ep.dns_entries()[0].hosted_zone_id(), Some("Z7HUB22UULQXV"));

    // Each subnet gets a requester-managed interface in the endpoint's groups.
    let eni_id = ep.network_interface_ids()[0].to_string();
    let enis = ec2.describe_network_interfaces().network_interface_ids(&eni_id).send().await.unwrap();
    let eni = &enis.network_interfaces()[0];
    assert_eq!(eni.interface_type().map(|t| t.as_str()), Some("vpc_endpoint"));
    assert_eq!(eni.requester_managed(), Some(true));
    assert_eq!(eni.description(), Some(format!("VPC Endpoint Interface {ep_id}").as_str()));
    assert_eq!(eni.groups()[0].group_id(), Some(sg_id.as_str()));
    let e = ec2.delete_network_interface().network_interface_id(&eni_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidNetworkInterface.InUse");
    let e = ec2.delete_subnet().subnet_id(&subnets[0]).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DependencyViolation");

    // A second private-DNS endpoint for the same service conflicts.
    let e = ec2
        .create_vpc_endpoint()
        .vpc_id(&vpc_id)
        .vpc_endpoint_type(VpcEndpointType::Interface)
        .service_name("com.amazonaws.us-east-1.sts")
        .subnet_ids(&subnets[1])
        .send()
        .await
        .unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "InvalidParameter");
    assert!(message(&e).contains("conflicting DNS domain for sts.us-east-1.amazonaws.com"), "{}", message(&e));
    // Interfaces go one per zone.
    let extra = ec2
        .create_subnet()
        .vpc_id(&vpc_id)
        .cidr_block("10.61.9.0/24")
        .availability_zone("us-east-1a")
        .send()
        .await
        .unwrap();
    let extra = extra.subnet().unwrap().subnet_id().unwrap().to_string();
    let e = ec2.modify_vpc_endpoint().vpc_endpoint_id(&ep_id).add_subnet_ids(&extra).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DuplicateSubnetsInSameZone");

    ec2.modify_vpc_endpoint()
        .vpc_endpoint_id(&ep_id)
        .add_subnet_ids(&subnets[1])
        .private_dns_enabled(false)
        .send()
        .await
        .unwrap();
    let d = ec2.describe_vpc_endpoints().filters(filter("vpc-endpoint-type", "Interface")).send().await.unwrap();
    let got = d.vpc_endpoints().iter().find(|e| e.vpc_endpoint_id() == Some(ep_id.as_str())).unwrap();
    assert_eq!(got.private_dns_enabled(), Some(false));
    assert_eq!(got.subnet_ids().len(), 2);
    assert_eq!(got.network_interface_ids().len(), 2);
    let names: Vec<&str> = got.dns_entries().iter().filter_map(|d| d.dns_name()).collect();
    assert_eq!(names.len(), 3, "regional and two zonal names, no private name: {names:?}");
    assert!(names.iter().all(|n| n.contains(".vpce.amazonaws.com")));
    assert!(names[0].starts_with(&ep.dns_entries()[0].dns_name().unwrap()[..ep_id.len() + 9]), "the label stays");

    ec2.delete_vpc_endpoints().vpc_endpoint_ids(&ep_id).send().await.unwrap();
    let left = ec2.describe_network_interfaces().filters(filter("vpc-id", &vpc_id)).send().await.unwrap();
    assert!(left.network_interfaces().is_empty(), "the endpoint's interfaces go with it");
    mws.stop().await;
}

#[tokio::test]
async fn managed_prefix_lists_have_versions() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let entry = |cidr: &str| AddPrefixListEntry::builder().cidr(cidr).description("office").build();

    let created = ec2
        .create_managed_prefix_list()
        .prefix_list_name("offices")
        .address_family("IPv4")
        .max_entries(3)
        .entries(entry("198.51.100.0/24"))
        .send()
        .await
        .unwrap();
    let pl = created.prefix_list().unwrap();
    let pl_id = pl.prefix_list_id().unwrap().to_string();
    assert_eq!(pl.version(), Some(1));
    assert_eq!(pl.owner_id(), Some("123456789012"));
    assert!(pl.prefix_list_arn().unwrap().ends_with(&format!(":prefix-list/{pl_id}")));
    let e = ec2
        .create_managed_prefix_list()
        .prefix_list_name("com.amazonaws.mine")
        .address_family("IPv4")
        .max_entries(1)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");

    let modified = ec2
        .modify_managed_prefix_list()
        .prefix_list_id(&pl_id)
        .current_version(1)
        .add_entries(entry("203.0.113.0/24"))
        .send()
        .await
        .unwrap();
    assert_eq!(modified.prefix_list().unwrap().version(), Some(2));
    let e = ec2
        .modify_managed_prefix_list()
        .prefix_list_id(&pl_id)
        .current_version(1)
        .remove_entries(RemovePrefixListEntry::builder().cidr("198.51.100.0/24").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "PrefixListVersionMismatch");
    let e = ec2
        .modify_managed_prefix_list()
        .prefix_list_id(&pl_id)
        .current_version(2)
        .add_entries(entry("192.0.2.0/25"))
        .add_entries(entry("192.0.2.128/25"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "PrefixListMaxEntriesExceeded");

    let v1 = ec2.get_managed_prefix_list_entries().prefix_list_id(&pl_id).target_version(1).send().await.unwrap();
    assert_eq!(v1.entries().len(), 1);
    let now = ec2.get_managed_prefix_list_entries().prefix_list_id(&pl_id).send().await.unwrap();
    let cidrs: Vec<&str> = now.entries().iter().filter_map(|e| e.cidr()).collect();
    assert_eq!(cidrs, ["198.51.100.0/24", "203.0.113.0/24"]);

    // AWS's lists are listed but cannot be changed.
    let all = ec2.describe_managed_prefix_lists().send().await.unwrap();
    assert!(all
        .prefix_lists()
        .iter()
        .any(|p| p.owner_id() == Some("AWS") && p.prefix_list_name() == Some("com.amazonaws.us-east-1.dynamodb")));
    let mine = ec2.describe_managed_prefix_lists().filters(filter("owner-id", "123456789012")).send().await.unwrap();
    assert_eq!(mine.prefix_lists().len(), 1);
    let e = ec2
        .modify_managed_prefix_list()
        .prefix_list_id("pl-63a5400a")
        .current_version(1)
        .add_entries(entry("192.0.2.0/24"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPrefixListModification");

    // Security group rules reference lists, which then cannot be deleted.
    let vpcs = ec2.describe_vpcs().filters(filter("is-default", "true")).send().await.unwrap();
    let vpc_id = vpcs.vpcs()[0].vpc_id().unwrap().to_string();
    let sg =
        ec2.create_security_group().group_name("from-offices").description("x").vpc_id(&vpc_id).send().await.unwrap();
    let sg_id = sg.group_id().unwrap().to_string();
    ec2.authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(443)
                .to_port(443)
                .prefix_list_ids(PrefixListId::builder().prefix_list_id(&pl_id).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let assocs = ec2.get_managed_prefix_list_associations().prefix_list_id(&pl_id).send().await.unwrap();
    assert_eq!(assocs.prefix_list_associations()[0].resource_id(), Some(sg_id.as_str()));
    let e = ec2.delete_managed_prefix_list().prefix_list_id(&pl_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "PrefixListInUse");
    ec2.delete_security_group().group_id(&sg_id).send().await.unwrap();
    let deleted = ec2.delete_managed_prefix_list().prefix_list_id(&pl_id).send().await.unwrap();
    assert_eq!(deleted.prefix_list().unwrap().state().map(|s| s.as_str()), Some("delete-in-progress"));
    let e = ec2.describe_managed_prefix_lists().prefix_list_ids(&pl_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPrefixListID.NotFound");
    mws.stop().await;
}

#[tokio::test]
async fn nat_gateways_and_elastic_ip_attributes() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let (vpc_id, subnets, main_rt) = network(&ec2, "10.62.0.0/16").await;

    let eip = ec2.allocate_address().send().await.unwrap();
    let alloc = eip.allocation_id().unwrap().to_string();
    let ip = eip.public_ip().unwrap().to_string();
    // Reverse DNS defaults to EC2's name and can be set and reset.
    let attrs =
        ec2.describe_addresses_attribute().allocation_ids(&alloc).attribute("domain-name".into()).send().await.unwrap();
    assert_eq!(
        attrs.addresses()[0].ptr_record(),
        Some(format!("ec2-{}.compute-1.amazonaws.com.", ip.replace('.', "-")).as_str())
    );
    let set =
        ec2.modify_address_attribute().allocation_id(&alloc).domain_name("mail.example.com").send().await.unwrap();
    assert_eq!(set.address().unwrap().ptr_record(), Some("mail.example.com."));
    let attrs = ec2.describe_addresses_attribute().allocation_ids(&alloc).send().await.unwrap();
    assert_eq!(attrs.addresses()[0].ptr_record(), Some("mail.example.com."));
    let reset =
        ec2.reset_address_attribute().allocation_id(&alloc).attribute("domain-name".into()).send().await.unwrap();
    assert!(reset.address().unwrap().ptr_record().unwrap().starts_with("ec2-"));

    let nat = ec2.create_nat_gateway().subnet_id(&subnets[0]).allocation_id(&alloc).send().await.unwrap();
    let nat = nat.nat_gateway().unwrap();
    let nat_id = nat.nat_gateway_id().unwrap().to_string();
    assert_eq!(nat.state().map(|s| s.as_str()), Some("pending"));
    let d = ec2.describe_nat_gateways().nat_gateway_ids(&nat_id).send().await.unwrap();
    let got = &d.nat_gateways()[0];
    assert_eq!(got.state().map(|s| s.as_str()), Some("available"));
    assert_eq!(got.nat_gateway_addresses()[0].public_ip(), Some(ip.as_str()));
    // The address is in use by the NAT gateway's interface.
    let e = ec2.release_address().allocation_id(&alloc).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidIPAddress.InUse");
    ec2.create_route()
        .route_table_id(&main_rt)
        .destination_cidr_block("0.0.0.0/0")
        .nat_gateway_id(&nat_id)
        .send()
        .await
        .unwrap();

    // With an internet gateway, detaching needs the public addresses gone.
    let igw = ec2.create_internet_gateway().send().await.unwrap();
    let igw_id = igw.internet_gateway().unwrap().internet_gateway_id().unwrap().to_string();
    ec2.attach_internet_gateway().internet_gateway_id(&igw_id).vpc_id(&vpc_id).send().await.unwrap();
    let e = ec2.detach_internet_gateway().internet_gateway_id(&igw_id).vpc_id(&vpc_id).send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "DependencyViolation");
    assert!(message(&e).contains("mapped public address"), "{}", message(&e));

    let e = ec2.delete_vpc().vpc_id(&vpc_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DependencyViolation");
    ec2.delete_nat_gateway().nat_gateway_id(&nat_id).send().await.unwrap();
    let d = ec2.describe_nat_gateways().filter(filter("state", "deleted")).send().await.unwrap();
    assert_eq!(d.nat_gateways()[0].nat_gateway_id(), Some(nat_id.as_str()));
    let rt = ec2.describe_route_tables().route_table_ids(&main_rt).send().await.unwrap();
    let route = rt.route_tables()[0].routes().iter().find(|r| r.nat_gateway_id() == Some(nat_id.as_str())).unwrap();
    assert_eq!(route.state().map(|s| s.as_str()), Some("blackhole"));
    ec2.detach_internet_gateway().internet_gateway_id(&igw_id).vpc_id(&vpc_id).send().await.unwrap();
    ec2.release_address().allocation_id(&alloc).send().await.unwrap();

    // Deleted NAT gateways disappear after an hour.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 3700}"#)).await;
    assert_eq!(status, 200);
    let d = ec2.describe_nat_gateways().filter(filter("vpc-id", &vpc_id)).send().await.unwrap();
    assert!(d.nat_gateways().is_empty());
    mws.control("POST", "/_mws/clock", Some(r#"{"offsetSeconds": 0}"#)).await;
    mws.stop().await;
}
