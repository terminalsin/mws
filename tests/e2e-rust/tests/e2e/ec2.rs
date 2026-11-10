//! EC2 and VPC through the official Rust SDK (metadata-only backend; see
//! `ec2_docker` for instances that really run).

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::primitives::Blob;
use aws_sdk_ec2::types::{
    AttributeBooleanValue, AttributeValue, BlockDeviceMapping, DomainType, EbsBlockDevice, Filter,
    IamInstanceProfileSpecification, ImageAttributeName, InstanceAttributeName, InstanceStateName, InstanceType,
    IpPermission, IpRange, KeyType, LaunchPermission, LaunchPermissionModifications, ResourceType, RuleAction,
    SecurityGroupRuleDescription, SecurityGroupRuleRequest, SecurityGroupRuleUpdate, Tag, TagSpecification,
    VpcAttributeName,
};
use aws_sdk_ec2::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

fn tags(rt: ResourceType, key: &str, value: &str) -> TagSpecification {
    TagSpecification::builder().resource_type(rt).tags(Tag::builder().key(key).value(value).build()).build()
}

/// Wait until instance `id` reaches `want` (transitions take a moment,
/// as on AWS).
pub(crate) async fn wait_state(ec2: &Client, id: &str, want: InstanceStateName) {
    for _ in 0..200 {
        let d = ec2.describe_instances().instance_ids(id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().and_then(|s| s.name()) == Some(&want) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("{id} never became {want:?}");
}

/// The Alpine AMI MWS publishes, found the way a user would.
async fn alpine_ami(ec2: &Client) -> String {
    let images = ec2.describe_images().owners("amazon").filters(filter("name", "mws-alpine-*")).send().await.unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

#[tokio::test]
async fn regions_zones_and_the_default_vpc() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;

    let regions = ec2.describe_regions().send().await.unwrap();
    let names: Vec<_> = regions.regions().iter().filter_map(|r| r.region_name()).collect();
    assert!(names.contains(&"us-east-1") && names.contains(&"eu-west-1"));
    let us = &regions.regions().iter().find(|r| r.region_name() == Some("us-east-1")).unwrap();
    assert_eq!(us.endpoint(), Some("ec2.us-east-1.amazonaws.com"));
    let zones = ec2.describe_availability_zones().send().await.unwrap();
    let zone_names: Vec<_> = zones.availability_zones().iter().filter_map(|z| z.zone_name()).collect();
    assert_eq!(zone_names[0], "us-east-1a");
    assert_eq!(zones.availability_zones()[0].zone_id(), Some("use1-az1"));
    let attrs = ec2.describe_account_attributes().send().await.unwrap();
    let default_vpc_attr =
        attrs.account_attributes().iter().find(|a| a.attribute_name() == Some("default-vpc")).unwrap();
    let default_vpc_id = default_vpc_attr.attribute_values()[0].attribute_value().unwrap().to_string();
    assert!(default_vpc_id.starts_with("vpc-"));

    // The default VPC, its default subnets (one per zone), the main route
    // table to the internet gateway, the default security group.
    let vpcs = ec2.describe_vpcs().filters(filter("isDefault", "true")).send().await.unwrap();
    let vpc = &vpcs.vpcs()[0];
    assert_eq!(vpc.vpc_id(), Some(default_vpc_id.as_str()));
    assert_eq!(vpc.cidr_block(), Some("172.31.0.0/16"));
    assert_eq!(vpc.owner_id(), Some(ACCOUNT));
    let subnets = ec2.describe_subnets().filters(filter("default-for-az", "true")).send().await.unwrap();
    assert_eq!(subnets.subnets().len(), zone_names.len());
    assert!(subnets.subnets().iter().all(|s| s.map_public_ip_on_launch() == Some(true)));
    assert_eq!(subnets.subnets()[0].available_ip_address_count(), Some(4091));
    let rts = ec2
        .describe_route_tables()
        .filters(filter("vpc-id", &default_vpc_id))
        .filters(filter("association.main", "true"))
        .send()
        .await
        .unwrap();
    let routes = rts.route_tables()[0].routes();
    assert!(routes
        .iter()
        .any(|r| r.destination_cidr_block() == Some("0.0.0.0/0")
            && r.gateway_id().is_some_and(|g| g.starts_with("igw-"))));
    let sgs = ec2.describe_security_groups().group_names("default").send().await.unwrap();
    assert_eq!(sgs.security_groups()[0].vpc_id(), Some(default_vpc_id.as_str()));

    let e = ec2.create_default_vpc().send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DefaultVpcAlreadyExists");
    let e = ec2.create_default_subnet().availability_zone("us-east-1a").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DefaultSubnetAlreadyExistsInAvailabilityZone");

    let types = ec2.describe_instance_types().instance_types(InstanceType::T3Micro).send().await.unwrap();
    let t3 = &types.instance_types()[0];
    assert_eq!(t3.v_cpu_info().unwrap().default_v_cpus(), Some(2));
    assert_eq!(t3.memory_info().unwrap().size_in_mib(), Some(1024));
    let offerings = ec2
        .describe_instance_type_offerings()
        .location_type(aws_sdk_ec2::types::LocationType::AvailabilityZone)
        .filters(filter("instance-type", "t3.micro"))
        .send()
        .await
        .unwrap();
    assert_eq!(offerings.instance_type_offerings().len(), zone_names.len());

    // Malformed and unknown ids.
    let e = ec2.describe_vpcs().vpc_ids("vpc-nope").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidVpcID.Malformed");
    let e = ec2.describe_vpcs().vpc_ids("vpc-0123456789abcdef0").send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "InvalidVpcID.NotFound");
    assert_eq!(message(&e), "The vpc ID 'vpc-0123456789abcdef0' does not exist");
}

#[tokio::test]
async fn vpcs_subnets_gateways_and_routes() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;

    let vpc = ec2
        .create_vpc()
        .cidr_block("10.0.0.0/16")
        .tag_specifications(tags(ResourceType::Vpc, "Name", "app"))
        .send()
        .await
        .unwrap();
    let vpc = vpc.vpc().unwrap();
    let vpc_id = vpc.vpc_id().unwrap().to_string();
    assert_eq!(vpc.is_default(), Some(false));
    assert_eq!(vpc.tags()[0].value(), Some("app"));
    let e = ec2.create_vpc().cidr_block("10.0.0.0/30").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidVpc.Range");

    ec2.modify_vpc_attribute()
        .vpc_id(&vpc_id)
        .enable_dns_hostnames(AttributeBooleanValue::builder().value(true).build())
        .send()
        .await
        .unwrap();
    let attr = ec2
        .describe_vpc_attribute()
        .vpc_id(&vpc_id)
        .attribute(VpcAttributeName::EnableDnsHostnames)
        .send()
        .await
        .unwrap();
    assert_eq!(attr.enable_dns_hostnames().unwrap().value(), Some(true));

    let assoc = ec2.associate_vpc_cidr_block().vpc_id(&vpc_id).cidr_block("10.1.0.0/16").send().await.unwrap();
    let assoc_id = assoc.cidr_block_association().unwrap().association_id().unwrap().to_string();
    let dis = ec2.disassociate_vpc_cidr_block().association_id(&assoc_id).send().await.unwrap();
    assert_eq!(
        dis.cidr_block_association().unwrap().cidr_block_state().unwrap().state().map(|s| s.as_str()),
        Some("disassociating")
    );

    let subnet = ec2
        .create_subnet()
        .vpc_id(&vpc_id)
        .cidr_block("10.0.1.0/24")
        .availability_zone("us-east-1b")
        .send()
        .await
        .unwrap();
    let subnet = subnet.subnet().unwrap();
    let subnet_id = subnet.subnet_id().unwrap().to_string();
    assert_eq!(subnet.available_ip_address_count(), Some(251));
    assert_eq!(subnet.availability_zone_id(), Some("use1-az2"));
    let e = ec2.create_subnet().vpc_id(&vpc_id).cidr_block("10.0.1.128/25").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidSubnet.Conflict");
    let e = ec2.create_subnet().vpc_id(&vpc_id).cidr_block("192.168.0.0/24").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidSubnet.Range");
    ec2.modify_subnet_attribute()
        .subnet_id(&subnet_id)
        .map_public_ip_on_launch(AttributeBooleanValue::builder().value(true).build())
        .send()
        .await
        .unwrap();
    let got = ec2.describe_subnets().subnet_ids(&subnet_id).send().await.unwrap();
    assert_eq!(got.subnets()[0].map_public_ip_on_launch(), Some(true));

    // Internet gateway and a public route table.
    let igw = ec2.create_internet_gateway().send().await.unwrap();
    let igw_id = igw.internet_gateway().unwrap().internet_gateway_id().unwrap().to_string();
    ec2.attach_internet_gateway().internet_gateway_id(&igw_id).vpc_id(&vpc_id).send().await.unwrap();
    let e = ec2.attach_internet_gateway().internet_gateway_id(&igw_id).vpc_id(&vpc_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "Resource.AlreadyAssociated");
    let igws = ec2.describe_internet_gateways().filters(filter("attachment.vpc-id", &vpc_id)).send().await.unwrap();
    assert_eq!(igws.internet_gateways()[0].attachments()[0].state().map(|s| s.as_str()), Some("available"));

    let rt = ec2.create_route_table().vpc_id(&vpc_id).send().await.unwrap();
    let rt_id = rt.route_table().unwrap().route_table_id().unwrap().to_string();
    assert_eq!(rt.route_table().unwrap().routes()[0].gateway_id(), Some("local"));
    ec2.create_route()
        .route_table_id(&rt_id)
        .destination_cidr_block("0.0.0.0/0")
        .gateway_id(&igw_id)
        .send()
        .await
        .unwrap();
    let e = ec2
        .create_route()
        .route_table_id(&rt_id)
        .destination_cidr_block("0.0.0.0/0")
        .gateway_id(&igw_id)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "RouteAlreadyExists");
    let a = ec2.associate_route_table().route_table_id(&rt_id).subnet_id(&subnet_id).send().await.unwrap();
    let rt_assoc = a.association_id().unwrap().to_string();

    // A NAT gateway on an Elastic IP, and a private route table through it.
    let eip = ec2.allocate_address().domain(DomainType::Vpc).send().await.unwrap();
    let alloc = eip.allocation_id().unwrap().to_string();
    let nat = ec2.create_nat_gateway().subnet_id(&subnet_id).allocation_id(&alloc).send().await.unwrap();
    let nat_id = nat.nat_gateway().unwrap().nat_gateway_id().unwrap().to_string();
    // `pending`, then `available` once the emulated clock moves on.
    let nats = ec2.describe_nat_gateways().nat_gateway_ids(&nat_id).send().await.unwrap();
    assert_eq!(nats.nat_gateways()[0].state().map(|s| s.as_str()), Some("pending"));
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 5}"#)).await;
    assert_eq!(status, 200);
    let nats = ec2.describe_nat_gateways().nat_gateway_ids(&nat_id).send().await.unwrap();
    assert_eq!(nats.nat_gateways()[0].state().map(|s| s.as_str()), Some("available"));
    assert_eq!(nats.nat_gateways()[0].nat_gateway_addresses()[0].public_ip(), eip.public_ip());
    let private = ec2.create_route_table().vpc_id(&vpc_id).send().await.unwrap();
    let private_id = private.route_table().unwrap().route_table_id().unwrap().to_string();
    ec2.create_route()
        .route_table_id(&private_id)
        .destination_cidr_block("0.0.0.0/0")
        .nat_gateway_id(&nat_id)
        .send()
        .await
        .unwrap();
    ec2.replace_route()
        .route_table_id(&private_id)
        .destination_cidr_block("0.0.0.0/0")
        .gateway_id(&igw_id)
        .send()
        .await
        .unwrap();
    let new_assoc = ec2
        .replace_route_table_association()
        .association_id(&rt_assoc)
        .route_table_id(&private_id)
        .send()
        .await
        .unwrap();
    let rt_assoc = new_assoc.new_association_id().unwrap().to_string();
    ec2.disassociate_route_table().association_id(&rt_assoc).send().await.unwrap();
    ec2.delete_route().route_table_id(&private_id).destination_cidr_block("0.0.0.0/0").send().await.unwrap();
    let e =
        ec2.delete_route().route_table_id(&private_id).destination_cidr_block("0.0.0.0/0").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidRoute.NotFound");

    // Network ACLs.
    let acl = ec2.create_network_acl().vpc_id(&vpc_id).send().await.unwrap();
    let acl_id = acl.network_acl().unwrap().network_acl_id().unwrap().to_string();
    ec2.create_network_acl_entry()
        .network_acl_id(&acl_id)
        .rule_number(100)
        .protocol("6")
        .rule_action(RuleAction::Allow)
        .egress(false)
        .cidr_block("0.0.0.0/0")
        .port_range(aws_sdk_ec2::types::PortRange::builder().from(443).to(443).build())
        .send()
        .await
        .unwrap();
    ec2.replace_network_acl_entry()
        .network_acl_id(&acl_id)
        .rule_number(100)
        .protocol("-1")
        .rule_action(RuleAction::Deny)
        .egress(false)
        .cidr_block("10.0.0.0/8")
        .send()
        .await
        .unwrap();
    let acls = ec2.describe_network_acls().filters(filter("association.subnet-id", &subnet_id)).send().await.unwrap();
    let acl_assoc = acls.network_acls()[0]
        .associations()
        .iter()
        .find(|a| a.subnet_id() == Some(subnet_id.as_str()))
        .unwrap()
        .network_acl_association_id()
        .unwrap()
        .to_string();
    let default_acl = acls.network_acls()[0].network_acl_id().unwrap().to_string();
    let moved =
        ec2.replace_network_acl_association().association_id(&acl_assoc).network_acl_id(&acl_id).send().await.unwrap();
    let e = ec2.delete_network_acl().network_acl_id(&acl_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DependencyViolation");
    ec2.replace_network_acl_association()
        .association_id(moved.new_association_id().unwrap())
        .network_acl_id(&default_acl)
        .send()
        .await
        .unwrap();
    ec2.delete_network_acl_entry().network_acl_id(&acl_id).rule_number(100).egress(false).send().await.unwrap();
    ec2.delete_network_acl().network_acl_id(&acl_id).send().await.unwrap();

    // DHCP options.
    let dopt = ec2
        .create_dhcp_options()
        .dhcp_configurations(
            aws_sdk_ec2::types::NewDhcpConfiguration::builder().key("domain-name").values("corp.internal").build(),
        )
        .send()
        .await
        .unwrap();
    let dopt_id = dopt.dhcp_options().unwrap().dhcp_options_id().unwrap().to_string();
    ec2.associate_dhcp_options().dhcp_options_id(&dopt_id).vpc_id(&vpc_id).send().await.unwrap();
    let described = ec2.describe_dhcp_options().dhcp_options_ids(&dopt_id).send().await.unwrap();
    assert_eq!(described.dhcp_options()[0].dhcp_configurations()[0].key(), Some("domain-name"));
    let e = ec2.delete_dhcp_options().dhcp_options_id(&dopt_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DependencyViolation");
    ec2.associate_dhcp_options().dhcp_options_id("default").vpc_id(&vpc_id).send().await.unwrap();
    ec2.delete_dhcp_options().dhcp_options_id(&dopt_id).send().await.unwrap();

    // Tear down: dependencies block deletes until they are gone.
    let e = ec2.delete_vpc().vpc_id(&vpc_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DependencyViolation");
    ec2.delete_nat_gateway().nat_gateway_id(&nat_id).send().await.unwrap();
    // The NAT gateway keeps its subnet and address until it is deleted.
    for _ in 0..100 {
        let d = ec2.describe_nat_gateways().nat_gateway_ids(&nat_id).send().await.unwrap();
        if d.nat_gateways()[0].state() == Some(&aws_sdk_ec2::types::NatGatewayState::Deleted) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    ec2.release_address().allocation_id(&alloc).send().await.unwrap();
    ec2.delete_route_table().route_table_id(&private_id).send().await.unwrap();
    ec2.delete_route_table().route_table_id(&rt_id).send().await.unwrap();
    ec2.delete_subnet().subnet_id(&subnet_id).send().await.unwrap();
    let e = ec2.delete_internet_gateway().internet_gateway_id(&igw_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DependencyViolation");
    ec2.detach_internet_gateway().internet_gateway_id(&igw_id).vpc_id(&vpc_id).send().await.unwrap();
    ec2.delete_internet_gateway().internet_gateway_id(&igw_id).send().await.unwrap();
    ec2.delete_vpc().vpc_id(&vpc_id).send().await.unwrap();
    let e = ec2.describe_vpcs().vpc_ids(&vpc_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidVpcID.NotFound");
}

#[tokio::test]
async fn security_groups_and_rules() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let vpc = ec2.create_vpc().cidr_block("10.2.0.0/16").send().await.unwrap();
    let vpc_id = vpc.vpc().unwrap().vpc_id().unwrap().to_string();

    let sg =
        ec2.create_security_group().group_name("web").description("web tier").vpc_id(&vpc_id).send().await.unwrap();
    let sg_id = sg.group_id().unwrap().to_string();
    let e =
        ec2.create_security_group().group_name("web").description("again").vpc_id(&vpc_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidGroup.Duplicate");

    let https = IpPermission::builder()
        .ip_protocol("tcp")
        .from_port(443)
        .to_port(443)
        .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").description("https").build())
        .build();
    let added =
        ec2.authorize_security_group_ingress().group_id(&sg_id).ip_permissions(https.clone()).send().await.unwrap();
    assert_eq!(added.r#return(), Some(true));
    let rule_id = added.security_group_rules()[0].security_group_rule_id().unwrap().to_string();
    let e =
        ec2.authorize_security_group_ingress().group_id(&sg_id).ip_permissions(https.clone()).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPermission.Duplicate");
    // The legacy flat form.
    ec2.authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_protocol("tcp")
        .from_port(22)
        .to_port(22)
        .cidr_ip("10.0.0.0/8")
        .send()
        .await
        .unwrap();

    let groups = ec2.describe_security_groups().group_ids(&sg_id).send().await.unwrap();
    let g = &groups.security_groups()[0];
    assert_eq!(g.ip_permissions().len(), 2);
    assert_eq!(g.ip_permissions_egress()[0].ip_protocol(), Some("-1"));
    let rules = ec2.describe_security_group_rules().filters(filter("group-id", &sg_id)).send().await.unwrap();
    assert_eq!(rules.security_group_rules().len(), 3);

    ec2.modify_security_group_rules()
        .group_id(&sg_id)
        .security_group_rules(
            SecurityGroupRuleUpdate::builder()
                .security_group_rule_id(&rule_id)
                .security_group_rule(
                    SecurityGroupRuleRequest::builder()
                        .ip_protocol("tcp")
                        .from_port(8443)
                        .to_port(8443)
                        .cidr_ipv4("0.0.0.0/0")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    ec2.update_security_group_rule_descriptions_ingress()
        .group_id(&sg_id)
        .security_group_rule_descriptions(
            SecurityGroupRuleDescription::builder().security_group_rule_id(&rule_id).description("alt https").build(),
        )
        .send()
        .await
        .unwrap();
    let rule = ec2.describe_security_group_rules().security_group_rule_ids(&rule_id).send().await.unwrap();
    let rule = &rule.security_group_rules()[0];
    assert_eq!((rule.from_port(), rule.description()), (Some(8443), Some("alt https")));

    let egress = IpPermission::builder()
        .ip_protocol("udp")
        .from_port(53)
        .to_port(53)
        .ip_ranges(IpRange::builder().cidr_ip("10.2.0.2/32").build())
        .build();
    ec2.authorize_security_group_egress().group_id(&sg_id).ip_permissions(egress.clone()).send().await.unwrap();
    let described = IpPermission::builder()
        .ip_protocol("udp")
        .from_port(53)
        .to_port(53)
        .ip_ranges(IpRange::builder().cidr_ip("10.2.0.2/32").description("dns").build())
        .build();
    ec2.update_security_group_rule_descriptions_egress()
        .group_id(&sg_id)
        .ip_permissions(described)
        .send()
        .await
        .unwrap();
    ec2.revoke_security_group_egress().group_id(&sg_id).ip_permissions(egress).send().await.unwrap();
    let revoked =
        ec2.revoke_security_group_ingress().group_id(&sg_id).security_group_rule_ids(&rule_id).send().await.unwrap();
    assert_eq!(revoked.r#return(), Some(true));
    let e = ec2.revoke_security_group_ingress().group_id(&sg_id).ip_permissions(https).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPermission.NotFound");

    // Groups referencing each other.
    let app =
        ec2.create_security_group().group_name("app").description("app tier").vpc_id(&vpc_id).send().await.unwrap();
    let app_id = app.group_id().unwrap().to_string();
    ec2.authorize_security_group_ingress()
        .group_id(&app_id)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(8080)
                .to_port(8080)
                .user_id_group_pairs(aws_sdk_ec2::types::UserIdGroupPair::builder().group_id(&sg_id).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let e = ec2.delete_security_group().group_id(&sg_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DependencyViolation");
    ec2.delete_security_group().group_id(&app_id).send().await.unwrap();
    ec2.delete_security_group().group_id(&sg_id).send().await.unwrap();
    let default = ec2
        .describe_security_groups()
        .filters(filter("vpc-id", &vpc_id))
        .filters(filter("group-name", "default"))
        .send()
        .await
        .unwrap();
    let default_id = default.security_groups()[0].group_id().unwrap();
    let e = ec2.delete_security_group().group_id(default_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CannotDelete");
}

#[tokio::test]
async fn key_pairs() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let rsa = ec2.create_key_pair().key_name("deploy").send().await.unwrap();
    assert!(rsa.key_material().unwrap().starts_with("-----BEGIN RSA PRIVATE KEY-----"));
    assert_eq!(rsa.key_fingerprint().unwrap().split(':').count(), 20);
    let ed = ec2
        .create_key_pair()
        .key_name("ed")
        .key_type(KeyType::Ed25519)
        .tag_specifications(tags(ResourceType::KeyPair, "team", "ops"))
        .send()
        .await
        .unwrap();
    assert!(ed.key_material().unwrap().starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    let e = ec2.create_key_pair().key_name("deploy").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidKeyPair.Duplicate");

    let public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl laptop";
    let imported =
        ec2.import_key_pair().key_name("laptop").public_key_material(Blob::new(public)).send().await.unwrap();
    assert!(imported.key_fingerprint().unwrap().ends_with('='));
    let described = ec2.describe_key_pairs().include_public_key(true).key_names("laptop").send().await.unwrap();
    assert_eq!(described.key_pairs()[0].key_type().map(|k| k.as_str()), Some("ed25519"));
    assert!(described.key_pairs()[0].public_key().unwrap().starts_with("ssh-ed25519 "));
    let by_tag = ec2.describe_key_pairs().filters(filter("tag:team", "ops")).send().await.unwrap();
    assert_eq!(by_tag.key_pairs()[0].key_name(), Some("ed"));

    ec2.delete_key_pair().key_name("laptop").send().await.unwrap();
    // Deleting a missing key succeeds, as in EC2.
    ec2.delete_key_pair().key_name("laptop").send().await.unwrap();
    let e = ec2.describe_key_pairs().key_names("laptop").send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "InvalidKeyPair.NotFound");
    assert_eq!(message(&e), "The key pair 'laptop' does not exist");
}

#[tokio::test]
async fn instance_lifecycle() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let ami = alpine_ami(&ec2).await;
    ec2.create_key_pair().key_name("k").send().await.unwrap();
    use base64::Engine;
    let user_data = base64::engine::general_purpose::STANDARD.encode("#!/bin/sh\necho hello\n");

    let e = ec2.run_instances().image_id(&ami).min_count(1).max_count(1).dry_run(true).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DryRunOperation");
    let e = ec2.run_instances().image_id("ami-0123456789abcdef0").min_count(1).max_count(1).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidAMIID.NotFound");
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T4gMicro)
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");

    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .key_name("k")
        .user_data(&user_data)
        .min_count(2)
        .max_count(2)
        .tag_specifications(tags(ResourceType::Instance, "Name", "web"))
        .tag_specifications(tags(ResourceType::Volume, "Name", "web-root"))
        .send()
        .await
        .unwrap();
    assert_eq!(run.owner_id(), Some(ACCOUNT));
    assert_eq!(run.instances().len(), 2);
    let first = &run.instances()[0];
    assert_eq!(first.state().unwrap().name(), Some(&InstanceStateName::Pending));
    assert!(first.private_ip_address().unwrap().starts_with("172.31."));
    assert!(first.private_dns_name().unwrap().ends_with(".ec2.internal"));
    let ids: Vec<String> = run.instances().iter().map(|i| i.instance_id().unwrap().to_string()).collect();
    let id = ids[0].clone();
    for i in &ids {
        wait_state(&ec2, i, InstanceStateName::Running).await;
    }

    let described = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
    let i = &described.reservations()[0].instances()[0];
    assert_eq!(i.state().unwrap().name(), Some(&InstanceStateName::Running));
    assert_eq!(i.state().unwrap().code(), Some(16));
    assert_eq!(i.key_name(), Some("k"));
    assert!(i.public_ip_address().is_some());
    assert_eq!(i.network_interfaces().len(), 1);
    assert_eq!(i.block_device_mappings()[0].device_name(), Some("/dev/xvda"));
    let by_tag = ec2
        .describe_instances()
        .filters(filter("tag:Name", "web"))
        .filters(filter("instance-state-name", "running"))
        .send()
        .await
        .unwrap();
    assert_eq!(by_tag.reservations()[0].instances().len(), 2);
    let volumes = ec2.describe_volumes().filters(filter("attachment.instance-id", &id)).send().await.unwrap();
    assert_eq!(volumes.volumes()[0].tags()[0].value(), Some("web-root"));
    let status = ec2.describe_instance_status().instance_ids(&id).send().await.unwrap();
    assert_eq!(status.instance_statuses()[0].instance_status().unwrap().status().map(|s| s.as_str()), Some("ok"));

    // Attributes.
    let ud = ec2
        .describe_instance_attribute()
        .instance_id(&id)
        .attribute(InstanceAttributeName::UserData)
        .send()
        .await
        .unwrap();
    assert_eq!(ud.user_data().unwrap().value(), Some(user_data.as_str()));
    ec2.modify_instance_attribute()
        .instance_id(&id)
        .disable_api_termination(AttributeBooleanValue::builder().value(true).build())
        .send()
        .await
        .unwrap();
    let e = ec2.terminate_instances().instance_ids(&id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "OperationNotPermitted");
    ec2.modify_instance_attribute()
        .instance_id(&id)
        .attribute(InstanceAttributeName::DisableApiTermination)
        .value("false")
        .send()
        .await
        .unwrap();
    let e = ec2
        .modify_instance_attribute()
        .instance_id(&id)
        .instance_type(AttributeValue::builder().value("t3.small").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectInstanceState");
    let md = ec2
        .modify_instance_metadata_options()
        .instance_id(&id)
        .http_tokens(aws_sdk_ec2::types::HttpTokensState::Required)
        .send()
        .await
        .unwrap();
    assert_eq!(md.instance_metadata_options().unwrap().http_tokens().map(|t| t.as_str()), Some("required"));

    // Stop, resize, start; reboot; console output.
    let stopped = ec2.stop_instances().instance_ids(&id).send().await.unwrap();
    let change = &stopped.stopping_instances()[0];
    assert_eq!(change.previous_state().unwrap().name(), Some(&InstanceStateName::Running));
    assert_eq!(change.current_state().unwrap().name(), Some(&InstanceStateName::Stopping));
    wait_state(&ec2, &id, InstanceStateName::Stopped).await;
    let i = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
    let i = &i.reservations()[0].instances()[0];
    assert_eq!(i.state().unwrap().name(), Some(&InstanceStateName::Stopped));
    assert_eq!(i.public_ip_address(), None);
    assert_eq!(i.state_reason().unwrap().code(), Some("Client.UserInitiatedShutdown"));
    ec2.modify_instance_attribute()
        .instance_id(&id)
        .instance_type(AttributeValue::builder().value("t3.small").build())
        .send()
        .await
        .unwrap();
    let e = ec2.reboot_instances().instance_ids("i-0123456789abcdef0").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidInstanceID.NotFound");
    let started = ec2.start_instances().instance_ids(&id).send().await.unwrap();
    assert_eq!(started.starting_instances()[0].current_state().unwrap().name(), Some(&InstanceStateName::Pending));
    wait_state(&ec2, &id, InstanceStateName::Running).await;
    ec2.reboot_instances().instance_ids(&id).send().await.unwrap();
    let i = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
    let i = &i.reservations()[0].instances()[0];
    assert_eq!(i.instance_type(), Some(&InstanceType::T3Small));
    assert!(i.public_ip_address().is_some());
    let console = ec2.get_console_output().instance_id(&id).send().await.unwrap();
    assert_eq!(console.instance_id(), Some(id.as_str()));

    // An Elastic IP and a second network interface.
    let eip = ec2.allocate_address().send().await.unwrap();
    let alloc = eip.allocation_id().unwrap().to_string();
    let assoc = ec2.associate_address().allocation_id(&alloc).instance_id(&id).send().await.unwrap();
    let i = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
    assert_eq!(i.reservations()[0].instances()[0].public_ip_address(), eip.public_ip());
    let addrs = ec2.describe_addresses().filters(filter("instance-id", &id)).send().await.unwrap();
    assert_eq!(addrs.addresses()[0].allocation_id(), Some(alloc.as_str()));
    let e = ec2.release_address().allocation_id(&alloc).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidIPAddress.InUse");
    ec2.disassociate_address().association_id(assoc.association_id().unwrap()).send().await.unwrap();
    ec2.release_address().allocation_id(&alloc).send().await.unwrap();

    let subnet = i.reservations()[0].instances()[0].subnet_id().unwrap().to_string();
    let eni = ec2.create_network_interface().subnet_id(&subnet).description("extra").send().await.unwrap();
    let eni_id = eni.network_interface().unwrap().network_interface_id().unwrap().to_string();
    ec2.modify_network_interface_attribute()
        .network_interface_id(&eni_id)
        .source_dest_check(AttributeBooleanValue::builder().value(false).build())
        .send()
        .await
        .unwrap();
    let att = ec2
        .attach_network_interface()
        .network_interface_id(&eni_id)
        .instance_id(&id)
        .device_index(1)
        .send()
        .await
        .unwrap();
    let e = ec2.delete_network_interface().network_interface_id(&eni_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidNetworkInterface.InUse");
    let enis = ec2.describe_network_interfaces().filters(filter("attachment.instance-id", &id)).send().await.unwrap();
    assert_eq!(enis.network_interfaces().len(), 2);
    ec2.detach_network_interface().attachment_id(att.attachment_id().unwrap()).send().await.unwrap();
    ec2.delete_network_interface().network_interface_id(&eni_id).send().await.unwrap();

    // Volumes and snapshots.
    let vol = ec2.create_volume().availability_zone("us-east-1a").size(10).send().await.unwrap();
    let vol_id = vol.volume_id().unwrap().to_string();
    let zone = i.reservations()[0].instances()[0].placement().unwrap().availability_zone().unwrap().to_string();
    assert_eq!(zone, "us-east-1a");
    let attached = ec2.attach_volume().volume_id(&vol_id).instance_id(&id).device("/dev/sdf").send().await.unwrap();
    assert_eq!(attached.state().map(|s| s.as_str()), Some("attaching"));
    let e = ec2.delete_volume().volume_id(&vol_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "VolumeInUse");
    let snap = ec2.create_snapshot().volume_id(&vol_id).description("backup").send().await.unwrap();
    let snap_id = snap.snapshot_id().unwrap().to_string();
    let snaps = ec2.describe_snapshots().owner_ids("self").send().await.unwrap();
    assert_eq!(snaps.snapshots()[0].state().map(|s| s.as_str()), Some("completed"));
    ec2.detach_volume().volume_id(&vol_id).send().await.unwrap();
    ec2.delete_volume().volume_id(&vol_id).send().await.unwrap();
    let restored = ec2.create_volume().availability_zone("us-east-1a").snapshot_id(&snap_id).send().await.unwrap();
    assert_eq!(restored.size(), Some(10));
    ec2.delete_volume().volume_id(restored.volume_id().unwrap()).send().await.unwrap();
    ec2.delete_snapshot().snapshot_id(&snap_id).send().await.unwrap();

    // Tags.
    ec2.create_tags()
        .resources(&id)
        .resources(&ids[1])
        .tags(Tag::builder().key("env").value("dev").build())
        .send()
        .await
        .unwrap();
    let t = ec2.describe_tags().filters(filter("key", "env")).send().await.unwrap();
    assert_eq!(t.tags().len(), 2);
    assert_eq!(t.tags()[0].resource_type().map(|r| r.as_str()), Some("instance"));
    ec2.delete_tags().resources(&id).tags(Tag::builder().key("env").build()).send().await.unwrap();
    let t = ec2.describe_tags().filters(filter("key", "env")).send().await.unwrap();
    assert_eq!(t.tags().len(), 1);

    // Terminate: the instance stays visible as terminated, its root volume
    // and interface go with it.
    let terminated = ec2.terminate_instances().instance_ids(&ids[0]).instance_ids(&ids[1]).send().await.unwrap();
    assert_eq!(
        terminated.terminating_instances()[0].current_state().unwrap().name(),
        Some(&InstanceStateName::ShuttingDown)
    );
    wait_state(&ec2, &id, InstanceStateName::Terminated).await;
    let volumes = ec2.describe_volumes().filters(filter("attachment.instance-id", &id)).send().await.unwrap();
    assert!(volumes.volumes().is_empty());
    let e = ec2.start_instances().instance_ids(&id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectInstanceState");
}

#[tokio::test]
async fn images() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let ami = alpine_ami(&ec2).await;
    let al2023 = ec2
        .describe_images()
        .owners("amazon")
        .filters(filter("name", "al2023-ami-2023*"))
        .filters(filter("architecture", "x86_64"))
        .send()
        .await
        .unwrap();
    assert!(!al2023.images().is_empty());
    assert_eq!(al2023.images()[0].public(), Some(true));

    let run = ec2.run_instances().image_id(&ami).min_count(1).max_count(1).send().await.unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    wait_state(&ec2, &id, InstanceStateName::Running).await;
    let made = ec2.create_image().instance_id(&id).name("golden").description("baked").send().await.unwrap();
    let image_id = made.image_id().unwrap().to_string();
    let mine = ec2.describe_images().owners("self").send().await.unwrap();
    let img = &mine.images()[0];
    assert_eq!(img.image_id(), Some(image_id.as_str()));
    assert_eq!(img.owner_id(), Some(ACCOUNT));
    assert_eq!(img.state().map(|s| s.as_str()), Some("available"));
    assert_eq!(img.public(), Some(false));
    let e = ec2.create_image().instance_id(&id).name("golden").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidAMIName.Duplicate");

    ec2.modify_image_attribute()
        .image_id(&image_id)
        .launch_permission(
            LaunchPermissionModifications::builder()
                .add(LaunchPermission::builder().user_id("210987654321").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let attr = ec2
        .describe_image_attribute()
        .image_id(&image_id)
        .attribute(ImageAttributeName::LaunchPermission)
        .send()
        .await
        .unwrap();
    assert_eq!(attr.launch_permissions()[0].user_id(), Some("210987654321"));
    let desc = ec2
        .describe_image_attribute()
        .image_id(&image_id)
        .attribute(ImageAttributeName::Description)
        .send()
        .await
        .unwrap();
    assert_eq!(desc.description().unwrap().value(), Some("baked"));

    let copied = ec2
        .copy_image()
        .source_image_id(&image_id)
        .source_region("us-east-1")
        .name("golden-copy")
        .send()
        .await
        .unwrap();
    let copy_id = copied.image_id().unwrap().to_string();
    // A container image registered as an AMI.
    let registered = ec2
        .register_image()
        .name("nginx")
        .image_location("docker:nginx:1.27-alpine")
        .architecture(aws_sdk_ec2::types::ArchitectureValues::X8664)
        .root_device_name("/dev/xvda")
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/xvda")
                .ebs(EbsBlockDevice::builder().volume_size(8).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let nginx = registered.image_id().unwrap().to_string();
    let launched = ec2.run_instances().image_id(&nginx).min_count(1).max_count(1).send().await.unwrap();
    assert_eq!(launched.instances()[0].image_id(), Some(nginx.as_str()));

    for image in [&image_id, &copy_id, &nginx] {
        ec2.deregister_image().image_id(image).send().await.unwrap();
    }
    let e = ec2.describe_images().image_ids(&image_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidAMIID.NotFound");
}

#[tokio::test]
async fn iam_enforcement_and_instance_profiles() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let ami = alpine_ami(&ec2).await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("app").assume_role_policy_document(trust).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    for name in ["app-profile", "other-profile"] {
        iam.create_instance_profile().instance_profile_name(name).send().await.unwrap();
        iam.add_role_to_instance_profile().instance_profile_name(name).role_name("app").send().await.unwrap();
    }

    // A user who may only describe: launching is UnauthorizedOperation with
    // a message STS decodes.
    let policy =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:Describe*"],"Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "viewer", Some(policy)).await;
    let viewer = Client::new(&cfg);
    viewer.describe_instances().send().await.unwrap();
    let e = viewer.run_instances().image_id(&ami).min_count(1).max_count(1).send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(code(&e), "UnauthorizedOperation");
    let encoded = message(&e).rsplit("Encoded authorization failure message: ").next().unwrap().to_string();
    let sts = aws_sdk_sts::Client::new(&mws.root_sdk_config().await);
    let decoded = sts.decode_authorization_message().encoded_message(encoded).send().await.unwrap();
    let doc: serde_json::Value = serde_json::from_str(decoded.decoded_message().unwrap()).unwrap();
    assert_eq!(doc["context"]["action"], "ec2:RunInstances");

    // Launching with a profile needs iam:PassRole on its role.
    let launcher_policy =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "launcher", Some(launcher_policy)).await;
    let launcher = Client::new(&cfg);
    let profile = IamInstanceProfileSpecification::builder().name("app-profile").build();
    let e = launcher
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .iam_instance_profile(profile.clone())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "UnauthorizedOperation");
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .iam_instance_profile(profile)
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    assert!(run.instances()[0]
        .iam_instance_profile()
        .unwrap()
        .arn()
        .unwrap()
        .ends_with(":instance-profile/app-profile"));

    let assocs =
        ec2.describe_iam_instance_profile_associations().filters(filter("instance-id", &id)).send().await.unwrap();
    let assoc_id = assocs.iam_instance_profile_associations()[0].association_id().unwrap().to_string();
    let replaced = ec2
        .replace_iam_instance_profile_association()
        .association_id(&assoc_id)
        .iam_instance_profile(IamInstanceProfileSpecification::builder().name("other-profile").build())
        .send()
        .await
        .unwrap();
    let assoc_id = replaced.iam_instance_profile_association().unwrap().association_id().unwrap().to_string();
    let e = ec2
        .associate_iam_instance_profile()
        .instance_id(&id)
        .iam_instance_profile(IamInstanceProfileSpecification::builder().name("app-profile").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectState");

    // Instance metadata: IMDSv2 token, then the role's credentials, which
    // work as the role (session named after the instance).
    let base = format!("/_aws/ec2/metadata/{id}/latest");
    let (status, _, token) =
        mws.raw("PUT", &format!("{base}/api/token"), &[("X-aws-ec2-metadata-token-ttl-seconds", "60")], b"").await;
    assert_eq!(status, 200);
    let token = String::from_utf8(token).unwrap();
    let get = |path: &'static str| {
        let (mws, base, token) = (&mws, base.clone(), token.clone());
        async move {
            let (status, _, body) =
                mws.raw("GET", &format!("{base}/{path}"), &[("X-aws-ec2-metadata-token", &token)], b"").await;
            (status, String::from_utf8(body).unwrap())
        }
    };
    assert_eq!(get("meta-data/instance-id").await, (200, id.clone()));
    assert_eq!(get("meta-data/placement/region").await.1, "us-east-1");
    assert_eq!(get("meta-data/iam/security-credentials/").await.1, "app");
    let (_, creds) = get("meta-data/iam/security-credentials/app").await;
    let creds: serde_json::Value = serde_json::from_str(&creds).unwrap();
    assert_eq!(creds["Code"], "Success");
    let cfg = mws
        .sdk_config(
            creds["AccessKeyId"].as_str().unwrap(),
            creds["SecretAccessKey"].as_str().unwrap(),
            creds["Token"].as_str(),
        )
        .await;
    let who = aws_sdk_sts::Client::new(&cfg).get_caller_identity().send().await.unwrap();
    assert_eq!(who.arn(), Some(format!("arn:aws:sts::{ACCOUNT}:assumed-role/app/{id}").as_str()));
    let (_, doc) = get("dynamic/instance-identity/document").await;
    let doc: serde_json::Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(doc["accountId"], ACCOUNT);
    // IMDSv1 works until the instance requires tokens.
    let (status, _, _) = mws.raw("GET", &format!("{base}/meta-data/instance-id"), &[], b"").await;
    assert_eq!(status, 200);
    ec2.modify_instance_metadata_options()
        .instance_id(&id)
        .http_tokens(aws_sdk_ec2::types::HttpTokensState::Required)
        .send()
        .await
        .unwrap();
    let (status, _, _) = mws.raw("GET", &format!("{base}/meta-data/instance-id"), &[], b"").await;
    assert_eq!(status, 401);

    let gone = ec2.disassociate_iam_instance_profile().association_id(&assoc_id).send().await.unwrap();
    assert_eq!(gone.iam_instance_profile_association().unwrap().state().map(|s| s.as_str()), Some("disassociating"));
    assert_eq!(get("meta-data/iam/security-credentials/").await.0, 404);
    let _ = role_arn;
}

#[tokio::test]
async fn launch_templates() {
    use aws_sdk_ec2::types::{
        LaunchTemplateSpecification, LaunchTemplateTagSpecificationRequest, RequestLaunchTemplateData,
    };
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let ami = alpine_ami(&ec2).await;

    let created = ec2
        .create_launch_template()
        .launch_template_name("router")
        .version_description("first")
        .launch_template_data(
            RequestLaunchTemplateData::builder()
                .image_id(&ami)
                .instance_type(InstanceType::T3Micro)
                .tag_specifications(
                    LaunchTemplateTagSpecificationRequest::builder()
                        .resource_type(ResourceType::Instance)
                        .tags(Tag::builder().key("Role").value("router").build())
                        .build(),
                )
                .build(),
        )
        .client_token("lt-1")
        .send()
        .await
        .unwrap();
    let lt = created.launch_template().unwrap();
    let id = lt.launch_template_id().unwrap().to_string();
    assert!(id.starts_with("lt-"));
    assert_eq!(lt.default_version_number(), Some(1));
    assert_eq!(lt.latest_version_number(), Some(1));
    let err = ec2
        .create_launch_template()
        .launch_template_name("router")
        .launch_template_data(RequestLaunchTemplateData::builder().image_id(&ami).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidLaunchTemplateName.AlreadyExistsException", "{}", message(&err));

    // A new version from the first, with another instance type.
    let v2 = ec2
        .create_launch_template_version()
        .launch_template_id(&id)
        .source_version("1")
        .version_description("bigger")
        .launch_template_data(RequestLaunchTemplateData::builder().instance_type(InstanceType::T3Small).build())
        .send()
        .await
        .unwrap();
    let v2 = v2.launch_template_version().unwrap();
    assert_eq!(v2.version_number(), Some(2));
    let data = v2.launch_template_data().unwrap();
    assert_eq!(data.image_id(), Some(ami.as_str()));
    assert_eq!(data.instance_type(), Some(&InstanceType::T3Small));

    let versions = ec2.describe_launch_template_versions().launch_template_id(&id).send().await.unwrap();
    assert_eq!(versions.launch_template_versions().len(), 2);
    let latest =
        ec2.describe_launch_template_versions().launch_template_id(&id).versions("$Latest").send().await.unwrap();
    assert_eq!(latest.launch_template_versions()[0].version_number(), Some(2));
    ec2.modify_launch_template().launch_template_id(&id).default_version("2").send().await.unwrap();
    let described = ec2
        .describe_launch_template_versions()
        .launch_template_name("router")
        .versions("$Default")
        .send()
        .await
        .unwrap();
    assert_eq!(described.launch_template_versions()[0].version_number(), Some(2));
    let templates = ec2.describe_launch_templates().launch_template_names("router").send().await.unwrap();
    assert_eq!(templates.launch_templates()[0].default_version_number(), Some(2));

    // RunInstances merges the default version under the call's parameters.
    let run = ec2
        .run_instances()
        .launch_template(LaunchTemplateSpecification::builder().launch_template_id(&id).build())
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let inst = &run.instances()[0];
    assert_eq!(inst.image_id(), Some(ami.as_str()));
    assert_eq!(inst.instance_type(), Some(&InstanceType::T3Small));
    let tag = |k: &str| inst.tags().iter().find(|t| t.key() == Some(k)).and_then(|t| t.value()).map(str::to_string);
    assert_eq!(tag("Role").as_deref(), Some("router"));
    assert_eq!(tag("aws:ec2launchtemplate:id").as_deref(), Some(id.as_str()));
    assert_eq!(tag("aws:ec2launchtemplate:version").as_deref(), Some("2"));
    let data = ec2.get_launch_template_data().instance_id(inst.instance_id().unwrap()).send().await.unwrap();
    assert_eq!(data.launch_template_data().unwrap().image_id(), Some(ami.as_str()));

    // The default version can't be deleted; others can.
    let del = ec2.delete_launch_template_versions().launch_template_id(&id).versions("2").send().await.unwrap();
    assert_eq!(del.unsuccessfully_deleted_launch_template_versions().len(), 1);
    let del = ec2.delete_launch_template_versions().launch_template_id(&id).versions("1").send().await.unwrap();
    assert_eq!(del.successfully_deleted_launch_template_versions().len(), 1);
    ec2.delete_launch_template().launch_template_id(&id).send().await.unwrap();
    let err = ec2.describe_launch_templates().launch_template_ids(&id).send().await.unwrap_err();
    assert_eq!(code(&err), "InvalidLaunchTemplateId.NotFound", "{}", message(&err));
}
