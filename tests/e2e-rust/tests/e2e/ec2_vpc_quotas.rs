//! VPC quotas EC2 enforces, with AWS's error codes, through the official
//! Rust SDK: subnets per VPC, internet gateways per Region, NAT gateways per
//! Availability Zone, routes per route table, rules per network ACL,
//! security groups per Region and per network interface. Service Quotas
//! increases raise them.

use std::time::Duration;

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{ConnectivityType, RuleAction};
use aws_sdk_ec2::Client;
use aws_sdk_servicequotas::types::RequestStatus;
use mws_e2e::Mws;

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

/// Raise a VPC quota and wait for the increase to be approved.
async fn raise(sq: &aws_sdk_servicequotas::Client, code: &str, value: f64) {
    let r = sq
        .request_service_quota_increase()
        .service_code("vpc")
        .quota_code(code)
        .desired_value(value)
        .send()
        .await
        .unwrap();
    let id = r.requested_quota().unwrap().id().unwrap().to_string();
    for _ in 0..50 {
        let r = sq.get_requested_service_quota_change().request_id(&id).send().await.unwrap();
        if r.requested_quota().unwrap().status() == Some(&RequestStatus::Approved) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("request {id} was never approved");
}

async fn vpc(ec2: &Client, cidr: &str) -> String {
    let v = ec2.create_vpc().cidr_block(cidr).send().await.unwrap();
    v.vpc().unwrap().vpc_id().unwrap().to_string()
}

#[tokio::test]
async fn subnets_gateways_and_routes() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = Client::new(&cfg);
    let sq = aws_sdk_servicequotas::Client::new(&cfg);

    // Subnets per VPC: 200.
    let vpc_id = vpc(&ec2, "10.0.0.0/16").await;
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..200 {
        let (ec2, vpc_id) = (ec2.clone(), vpc_id.clone());
        tasks.spawn(async move {
            ec2.create_subnet()
                .vpc_id(vpc_id)
                .cidr_block(format!("10.0.{i}.0/24"))
                .availability_zone("us-east-1a")
                .send()
                .await
                .unwrap();
        });
    }
    while let Some(r) = tasks.join_next().await {
        r.unwrap();
    }
    let e = ec2.create_subnet().vpc_id(&vpc_id).cidr_block("10.0.200.0/24").send().await.unwrap_err();
    assert_eq!(code(&e), "SubnetLimitExceeded");
    assert_eq!(e.message(), Some("The maximum number of subnets has been reached."));
    raise(&sq, "L-407747CB", 201.0).await;
    ec2.create_subnet().vpc_id(&vpc_id).cidr_block("10.0.200.0/24").send().await.unwrap();

    // Internet gateways per Region: 5, the default VPC's included.
    for _ in 0..4 {
        ec2.create_internet_gateway().send().await.unwrap();
    }
    let e = ec2.create_internet_gateway().send().await.unwrap_err();
    assert_eq!(code(&e), "InternetGatewayLimitExceeded");
    raise(&sq, "L-A4707A72", 6.0).await;
    let igw = ec2.create_internet_gateway().send().await.unwrap();
    let igw_id = igw.internet_gateway().unwrap().internet_gateway_id().unwrap().to_string();

    // NAT gateways per Availability Zone: 5.
    let other = vpc(&ec2, "10.1.0.0/16").await;
    let mut subnets = Vec::new();
    for (i, zone) in ["us-east-1a", "us-east-1b"].iter().enumerate() {
        let s = ec2
            .create_subnet()
            .vpc_id(&other)
            .cidr_block(format!("10.1.{i}.0/24"))
            .availability_zone(*zone)
            .send()
            .await
            .unwrap();
        subnets.push(s.subnet().unwrap().subnet_id().unwrap().to_string());
    }
    let nat = |subnet: &str| ec2.create_nat_gateway().subnet_id(subnet).connectivity_type(ConnectivityType::Private);
    let mut first = String::new();
    for _ in 0..5 {
        let n = nat(&subnets[0]).send().await.unwrap();
        first = n.nat_gateway().unwrap().nat_gateway_id().unwrap().to_string();
    }
    let e = nat(&subnets[0]).send().await.unwrap_err();
    assert_eq!(code(&e), "NatGatewayLimitExceeded");
    // Another zone has its own allowance, and deleted gateways free theirs.
    nat(&subnets[1]).send().await.unwrap();
    ec2.delete_nat_gateway().nat_gateway_id(&first).send().await.unwrap();
    nat(&subnets[0]).send().await.unwrap();

    // Routes per route table: 50, not counting the local route.
    ec2.attach_internet_gateway().internet_gateway_id(&igw_id).vpc_id(&other).send().await.unwrap();
    let rt = ec2.create_route_table().vpc_id(&other).send().await.unwrap();
    let rt_id = rt.route_table().unwrap().route_table_id().unwrap().to_string();
    let route = |n: u32| {
        ec2.create_route()
            .route_table_id(&rt_id)
            .destination_cidr_block(format!("192.168.{n}.0/24"))
            .gateway_id(&igw_id)
    };
    for n in 0..50 {
        route(n).send().await.unwrap();
    }
    let e = route(50).send().await.unwrap_err();
    assert_eq!(code(&e), "RouteLimitExceeded");
    raise(&sq, "L-93826ACB", 51.0).await;
    route(50).send().await.unwrap();
}

#[tokio::test]
async fn acl_rules_and_security_groups() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = Client::new(&cfg);
    let vpc_id = vpc(&ec2, "10.2.0.0/16").await;

    // Rules per network ACL: 20 per direction.
    let acl = ec2.create_network_acl().vpc_id(&vpc_id).send().await.unwrap();
    let acl_id = acl.network_acl().unwrap().network_acl_id().unwrap().to_string();
    let entry = |n: i32, egress: bool| {
        ec2.create_network_acl_entry()
            .network_acl_id(&acl_id)
            .rule_number(n)
            .egress(egress)
            .protocol("-1")
            .rule_action(RuleAction::Allow)
            .cidr_block(format!("10.9.{n}.0/24"))
    };
    for n in 1..=20 {
        entry(n, false).send().await.unwrap();
    }
    let e = entry(21, false).send().await.unwrap_err();
    assert_eq!(code(&e), "NetworkAclEntryLimitExceeded");
    // Replacing an existing rule and the other direction are fine.
    ec2.replace_network_acl_entry()
        .network_acl_id(&acl_id)
        .rule_number(5)
        .egress(false)
        .protocol("6")
        .rule_action(RuleAction::Deny)
        .cidr_block("0.0.0.0/0")
        .send()
        .await
        .unwrap();
    entry(1, true).send().await.unwrap();

    // Security groups per network interface: 5.
    let subnet = ec2.create_subnet().vpc_id(&vpc_id).cidr_block("10.2.1.0/24").send().await.unwrap();
    let subnet_id = subnet.subnet().unwrap().subnet_id().unwrap().to_string();
    let mut groups = Vec::new();
    for i in 0..6 {
        let g = ec2
            .create_security_group()
            .vpc_id(&vpc_id)
            .group_name(format!("g{i}"))
            .description("quota")
            .send()
            .await
            .unwrap();
        groups.push(g.group_id().unwrap().to_string());
    }
    let e =
        ec2.create_network_interface().subnet_id(&subnet_id).set_groups(Some(groups.clone())).send().await.unwrap_err();
    assert_eq!(code(&e), "SecurityGroupsPerInterfaceLimitExceeded");
    let eni = ec2
        .create_network_interface()
        .subnet_id(&subnet_id)
        .set_groups(Some(groups[..5].to_vec()))
        .send()
        .await
        .unwrap();
    let eni_id = eni.network_interface().unwrap().network_interface_id().unwrap().to_string();
    let e = ec2
        .modify_network_interface_attribute()
        .network_interface_id(&eni_id)
        .set_groups(Some(groups.clone()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "SecurityGroupsPerInterfaceLimitExceeded");

    // VPC security groups per Region: 2500, default groups included.
    let have = ec2.describe_security_groups().send().await.unwrap().security_groups().len();
    let mut tasks = tokio::task::JoinSet::new();
    for i in have..2500 {
        let (ec2, vpc_id) = (ec2.clone(), vpc_id.clone());
        tasks.spawn(async move {
            ec2.create_security_group()
                .vpc_id(vpc_id)
                .group_name(format!("bulk-{i}"))
                .description("quota")
                .send()
                .await
                .unwrap();
        });
        if tasks.len() >= 32 {
            tasks.join_next().await.unwrap().unwrap();
        }
    }
    while let Some(r) = tasks.join_next().await {
        r.unwrap();
    }
    let e = ec2
        .create_security_group()
        .vpc_id(&vpc_id)
        .group_name("one-too-many")
        .description("quota")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "SecurityGroupLimitExceeded");
    assert_eq!(e.message(), Some("The maximum number of security groups has been reached."));
}
