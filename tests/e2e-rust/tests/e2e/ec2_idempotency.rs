//! EC2 `ClientToken` idempotency through the official Rust SDK: a retried
//! create call with the same token returns the same resource, and the same
//! token with other parameters is `IdempotentParameterMismatch`.

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{
    Filter, FlowLogsResourceType, InstanceType, LogDestinationType, ResourceType, Tag, TagSpecification, TrafficType,
    VpcEndpointType,
};
use aws_sdk_ec2::Client;
use mws_e2e::{user_with_policy, Mws};

const MISMATCH: &str = "IdempotentParameterMismatch";

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

fn tagged(kind: ResourceType, value: &str) -> TagSpecification {
    TagSpecification::builder().resource_type(kind).tags(Tag::builder().key("Name").value(value).build()).build()
}

async fn vpc_and_subnet(ec2: &Client, cidr: &str) -> (String, String) {
    let vpc = ec2.create_vpc().cidr_block(cidr).send().await.unwrap();
    let vpc_id = vpc.vpc().unwrap().vpc_id().unwrap().to_string();
    let subnet_cidr = cidr.replace(".0.0/16", ".1.0/24");
    let subnet = ec2
        .create_subnet()
        .vpc_id(&vpc_id)
        .cidr_block(subnet_cidr)
        .availability_zone("us-east-1a")
        .send()
        .await
        .unwrap();
    (vpc_id, subnet.subnet().unwrap().subnet_id().unwrap().to_string())
}

#[tokio::test]
async fn vpc_resources_honour_client_tokens() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let (vpc_id, subnet_id) = vpc_and_subnet(&ec2, "10.70.0.0/16").await;

    // Route tables.
    let a = ec2.create_route_table().vpc_id(&vpc_id).client_token("rtb-1").send().await.unwrap();
    let b = ec2.create_route_table().vpc_id(&vpc_id).client_token("rtb-1").send().await.unwrap();
    let id = a.route_table().unwrap().route_table_id().unwrap();
    assert_eq!(b.route_table().unwrap().route_table_id(), Some(id));
    assert_eq!(b.client_token(), Some("rtb-1"));
    let rts = ec2.describe_route_tables().filters(filter("vpc-id", &vpc_id)).send().await.unwrap();
    assert_eq!(rts.route_tables().len(), 2, "main table plus one");
    let e = ec2
        .create_route_table()
        .vpc_id(&vpc_id)
        .client_token("rtb-1")
        .tag_specifications(tagged(ResourceType::RouteTable, "other"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), MISMATCH);
    assert!(e.message().unwrap().contains("same client token"), "{:?}", e.message());
    // A fresh token makes a new table.
    let c = ec2.create_route_table().vpc_id(&vpc_id).client_token("rtb-2").send().await.unwrap();
    assert_ne!(c.route_table().unwrap().route_table_id(), Some(id));

    // Network ACLs.
    let a = ec2.create_network_acl().vpc_id(&vpc_id).client_token("acl").send().await.unwrap();
    let b = ec2.create_network_acl().vpc_id(&vpc_id).client_token("acl").send().await.unwrap();
    assert_eq!(a.network_acl().unwrap().network_acl_id(), b.network_acl().unwrap().network_acl_id());
    let e = ec2
        .create_network_acl()
        .vpc_id(&vpc_id)
        .client_token("acl")
        .tag_specifications(tagged(ResourceType::NetworkAcl, "x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), MISMATCH);

    // Network interfaces.
    let a = ec2.create_network_interface().subnet_id(&subnet_id).client_token("eni").send().await.unwrap();
    let b = ec2.create_network_interface().subnet_id(&subnet_id).client_token("eni").send().await.unwrap();
    let eni = a.network_interface().unwrap().network_interface_id().unwrap();
    assert_eq!(b.network_interface().unwrap().network_interface_id(), Some(eni));
    let enis = ec2.describe_network_interfaces().filters(filter("subnet-id", &subnet_id)).send().await.unwrap();
    assert_eq!(enis.network_interfaces().len(), 1);
    let e = ec2
        .create_network_interface()
        .subnet_id(&subnet_id)
        .description("different")
        .client_token("eni")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), MISMATCH);

    // NAT gateways (they cost money when duplicated).
    let igw = ec2.create_internet_gateway().send().await.unwrap();
    let igw_id = igw.internet_gateway().unwrap().internet_gateway_id().unwrap();
    ec2.attach_internet_gateway().internet_gateway_id(igw_id).vpc_id(&vpc_id).send().await.unwrap();
    let eip = ec2.allocate_address().send().await.unwrap();
    let alloc = eip.allocation_id().unwrap();
    let a =
        ec2.create_nat_gateway().subnet_id(&subnet_id).allocation_id(alloc).client_token("nat").send().await.unwrap();
    let b =
        ec2.create_nat_gateway().subnet_id(&subnet_id).allocation_id(alloc).client_token("nat").send().await.unwrap();
    let nat = a.nat_gateway().unwrap().nat_gateway_id().unwrap();
    assert_eq!(b.nat_gateway().unwrap().nat_gateway_id(), Some(nat));
    let nats = ec2.describe_nat_gateways().filter(filter("vpc-id", &vpc_id)).send().await.unwrap();
    assert_eq!(nats.nat_gateways().len(), 1);
    let e = ec2
        .create_nat_gateway()
        .subnet_id(&subnet_id)
        .connectivity_type(aws_sdk_ec2::types::ConnectivityType::Private)
        .client_token("nat")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), MISMATCH);

    // Egress-only internet gateways.
    let a = ec2.create_egress_only_internet_gateway().vpc_id(&vpc_id).client_token("eigw").send().await.unwrap();
    let b = ec2.create_egress_only_internet_gateway().vpc_id(&vpc_id).client_token("eigw").send().await.unwrap();
    assert_eq!(
        a.egress_only_internet_gateway().unwrap().egress_only_internet_gateway_id(),
        b.egress_only_internet_gateway().unwrap().egress_only_internet_gateway_id()
    );
    let (other_vpc, _) = vpc_and_subnet(&ec2, "10.71.0.0/16").await;
    let e = ec2.create_egress_only_internet_gateway().vpc_id(&other_vpc).client_token("eigw").send().await.unwrap_err();
    assert_eq!(code(&e), MISMATCH);

    // VPC endpoints.
    let main = ec2
        .describe_route_tables()
        .filters(filter("vpc-id", &vpc_id))
        .filters(filter("association.main", "true"))
        .send()
        .await
        .unwrap();
    let main = main.route_tables()[0].route_table_id().unwrap().to_string();
    let endpoint = |token: &str| {
        ec2.create_vpc_endpoint()
            .vpc_id(&vpc_id)
            .vpc_endpoint_type(VpcEndpointType::Gateway)
            .service_name("com.amazonaws.us-east-1.s3")
            .route_table_ids(&main)
            .client_token(token)
    };
    let a = endpoint("vpce").send().await.unwrap();
    // Without idempotency the retry would fail: the route already exists.
    let b = endpoint("vpce").send().await.unwrap();
    assert_eq!(a.vpc_endpoint().unwrap().vpc_endpoint_id(), b.vpc_endpoint().unwrap().vpc_endpoint_id());
    let e = endpoint("vpce").policy_document(r#"{"Statement":[]}"#).send().await.unwrap_err();
    assert_eq!(code(&e), MISMATCH);

    // Flow logs.
    let flow = |traffic: TrafficType| {
        ec2.create_flow_logs()
            .resource_type(FlowLogsResourceType::Vpc)
            .resource_ids(&vpc_id)
            .traffic_type(traffic)
            .log_destination_type(LogDestinationType::S3)
            .log_destination("arn:aws:s3:::flow-log-bucket")
            .client_token("fl")
    };
    let a = flow(TrafficType::All).send().await.unwrap();
    let b = flow(TrafficType::All).send().await.unwrap();
    assert_eq!(a.flow_log_ids().len(), 1);
    assert_eq!(a.flow_log_ids(), b.flow_log_ids());
    assert!(b.unsuccessful().is_empty());
    let e = flow(TrafficType::Reject).send().await.unwrap_err();
    assert_eq!(code(&e), MISMATCH);

    // Tokens are scoped to the Region.
    let west = Client::from_conf(
        aws_sdk_ec2::config::Builder::from(&mws.root_sdk_config().await)
            .region(aws_sdk_ec2::config::Region::new("us-west-2"))
            .build(),
    );
    let default_vpc = west.describe_vpcs().filters(filter("is-default", "true")).send().await.unwrap();
    let west_vpc = default_vpc.vpcs()[0].vpc_id().unwrap();
    west.create_route_table().vpc_id(west_vpc).client_token("rtb-1").send().await.unwrap();
}

#[tokio::test]
async fn run_instances_token_mismatch_and_authorization() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let images = ec2.describe_images().owners("amazon").filters(filter("name", "mws-alpine-*")).send().await.unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let run = |ty: InstanceType| {
        ec2.run_instances().image_id(&ami).instance_type(ty).min_count(1).max_count(1).client_token("launch-1")
    };
    let a = run(InstanceType::T3Micro).send().await.unwrap();
    let b = run(InstanceType::T3Micro).send().await.unwrap();
    assert_eq!(a.reservation_id(), b.reservation_id());
    assert_eq!(a.instances()[0].instance_id(), b.instances()[0].instance_id());
    let all = ec2.describe_instances().filters(filter("client-token", "launch-1")).send().await.unwrap();
    assert_eq!(all.reservations().iter().map(|r| r.instances().len()).sum::<usize>(), 1);

    // Same token, other parameters.
    let e = run(InstanceType::T3Small).send().await.unwrap_err();
    assert_eq!(code(&e), MISMATCH);

    // A caller without ec2:RunInstances cannot read another launch back
    // through its token: authorization comes first.
    let (_, cfg) = user_with_policy(
        &mws,
        "reader",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}"#),
    )
    .await;
    let reader = Client::new(&cfg);
    let e = reader
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .client_token("launch-1")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "UnauthorizedOperation");
}

#[tokio::test]
async fn volumes_and_launch_templates_reject_mismatched_tokens() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let a = ec2.create_volume().availability_zone("us-east-1a").size(8).client_token("vol").send().await.unwrap();
    let b = ec2.create_volume().availability_zone("us-east-1a").size(8).client_token("vol").send().await.unwrap();
    assert_eq!(a.volume_id(), b.volume_id());
    let e = ec2.create_volume().availability_zone("us-east-1a").size(9).client_token("vol").send().await.unwrap_err();
    assert_eq!(code(&e), MISMATCH);

    let data = aws_sdk_ec2::types::RequestLaunchTemplateData::builder().instance_type(InstanceType::T3Micro).build();
    let a = ec2
        .create_launch_template()
        .launch_template_name("web")
        .launch_template_data(data.clone())
        .client_token("lt")
        .send()
        .await
        .unwrap();
    let b = ec2
        .create_launch_template()
        .launch_template_name("web")
        .launch_template_data(data.clone())
        .client_token("lt")
        .send()
        .await
        .unwrap();
    assert_eq!(a.launch_template().unwrap().launch_template_id(), b.launch_template().unwrap().launch_template_id());
    let e = ec2
        .create_launch_template()
        .launch_template_name("web2")
        .launch_template_data(data)
        .client_token("lt")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), MISMATCH);
}
