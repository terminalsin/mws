//! VPN, transit gateways, VPC peering, egress-only gateways, flow logs and
//! interface addressing through the official Rust SDK.

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{
    Filter, FlowLogsResourceType, GatewayType, LogDestinationType, TrafficType, VpnConnectionOptionsSpecification,
};
use aws_sdk_ec2::Client;
use mws_e2e::Mws;

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn vpc(ec2: &Client, cidr: &str) -> String {
    ec2.create_vpc().cidr_block(cidr).send().await.unwrap().vpc.unwrap().vpc_id.unwrap()
}

async fn subnet(ec2: &Client, vpc: &str, cidr: &str, zone: &str) -> String {
    ec2.create_subnet()
        .vpc_id(vpc)
        .cidr_block(cidr)
        .availability_zone(zone)
        .send()
        .await
        .unwrap()
        .subnet
        .unwrap()
        .subnet_id
        .unwrap()
}

async fn main_route_table(ec2: &Client, vpc: &str) -> String {
    ec2.describe_route_tables()
        .filters(Filter::builder().name("vpc-id").values(vpc).build())
        .send()
        .await
        .unwrap()
        .route_tables()[0]
        .route_table_id()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn site_to_site_vpn_lifecycle() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let vpc = vpc(&ec2, "10.30.0.0/16").await;

    let cgw = ec2
        .create_customer_gateway()
        .r#type(GatewayType::Ipsec1)
        .ip_address("198.51.100.7")
        .bgp_asn(65020)
        .send()
        .await
        .unwrap()
        .customer_gateway
        .unwrap();
    // The same address, ASN and type answer the existing gateway.
    let again = ec2
        .create_customer_gateway()
        .r#type(GatewayType::Ipsec1)
        .ip_address("198.51.100.7")
        .bgp_asn(65020)
        .send()
        .await
        .unwrap();
    assert_eq!(again.customer_gateway().unwrap().customer_gateway_id(), cgw.customer_gateway_id());

    let vgw = ec2.create_vpn_gateway().r#type(GatewayType::Ipsec1).send().await.unwrap().vpn_gateway.unwrap();
    let vgw_id = vgw.vpn_gateway_id().unwrap().to_string();
    assert_eq!(vgw.amazon_side_asn(), Some(64512));
    let att = ec2.attach_vpn_gateway().vpc_id(&vpc).vpn_gateway_id(&vgw_id).send().await.unwrap();
    assert_eq!(att.vpc_attachment().unwrap().state().unwrap().as_str(), "attached");

    // Routes through the gateway and propagation need it attached.
    let rtb = main_route_table(&ec2, &vpc).await;
    ec2.create_route()
        .route_table_id(&rtb)
        .destination_cidr_block("192.168.0.0/16")
        .gateway_id(&vgw_id)
        .send()
        .await
        .unwrap();
    ec2.enable_vgw_route_propagation().route_table_id(&rtb).gateway_id(&vgw_id).send().await.unwrap();
    let table = ec2.describe_route_tables().route_table_ids(&rtb).send().await.unwrap();
    assert_eq!(table.route_tables()[0].propagating_vgws()[0].gateway_id(), Some(vgw_id.as_str()));

    let vpn = ec2
        .create_vpn_connection()
        .r#type("ipsec.1")
        .customer_gateway_id(cgw.customer_gateway_id().unwrap())
        .vpn_gateway_id(&vgw_id)
        .options(VpnConnectionOptionsSpecification::builder().static_routes_only(true).build())
        .send()
        .await
        .unwrap()
        .vpn_connection
        .unwrap();
    let vpn_id = vpn.vpn_connection_id().unwrap().to_string();
    let tunnels = vpn.options().unwrap().tunnel_options();
    assert_eq!(tunnels.len(), 2);
    assert!(tunnels[0].tunnel_inside_cidr().unwrap().starts_with("169.254."));
    assert!(vpn.customer_gateway_configuration().unwrap().contains(&vpn_id));
    ec2.create_vpn_connection_route()
        .vpn_connection_id(&vpn_id)
        .destination_cidr_block("172.20.0.0/16")
        .send()
        .await
        .unwrap();
    let described = ec2.describe_vpn_connections().vpn_connection_ids(&vpn_id).send().await.unwrap();
    assert_eq!(described.vpn_connections()[0].routes()[0].destination_cidr_block(), Some("172.20.0.0/16"));

    // A gateway in use cannot go away.
    let e =
        ec2.delete_customer_gateway().customer_gateway_id(cgw.customer_gateway_id().unwrap()).send().await.unwrap_err();
    assert_eq!(code(&e), "IncorrectState");
    ec2.delete_vpn_connection().vpn_connection_id(&vpn_id).send().await.unwrap();
    let e = ec2.delete_vpn_gateway().vpn_gateway_id(&vgw_id).send().await.unwrap_err();
    assert_eq!(code(&e), "IncorrectState");
    ec2.detach_vpn_gateway().vpc_id(&vpc).vpn_gateway_id(&vgw_id).send().await.unwrap();
    // Detaching leaves the route a blackhole.
    let table = ec2.describe_route_tables().route_table_ids(&rtb).send().await.unwrap();
    let route = table.route_tables()[0]
        .routes()
        .iter()
        .find(|r| r.destination_cidr_block() == Some("192.168.0.0/16"))
        .unwrap()
        .clone();
    assert_eq!(route.state().unwrap().as_str(), "blackhole");
    ec2.delete_vpn_gateway().vpn_gateway_id(&vgw_id).send().await.unwrap();
    ec2.delete_customer_gateway().customer_gateway_id(cgw.customer_gateway_id().unwrap()).send().await.unwrap();
    let gone = ec2.describe_vpn_gateways().vpn_gateway_ids(&vgw_id).send().await.unwrap();
    assert_eq!(gone.vpn_gateways()[0].state().unwrap().as_str(), "deleted");

    let e = ec2.describe_vpn_gateways().vpn_gateway_ids("vgw-0123456789abcdef0").send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidVpnGatewayID.NotFound");
}

#[tokio::test]
async fn transit_gateway_routes_between_vpcs() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let a = vpc(&ec2, "10.40.0.0/16").await;
    let b = vpc(&ec2, "10.41.0.0/16").await;
    let sa = subnet(&ec2, &a, "10.40.1.0/24", "us-east-1a").await;
    let sa2 = subnet(&ec2, &a, "10.40.2.0/24", "us-east-1a").await;
    let sb = subnet(&ec2, &b, "10.41.1.0/24", "us-east-1b").await;

    let tgw = ec2.create_transit_gateway().description("hub").send().await.unwrap().transit_gateway.unwrap();
    let tgw_id = tgw.transit_gateway_id().unwrap().to_string();
    let rtb = tgw.options().unwrap().association_default_route_table_id().unwrap().to_string();

    // One subnet per zone.
    let e = ec2
        .create_transit_gateway_vpc_attachment()
        .transit_gateway_id(&tgw_id)
        .vpc_id(&a)
        .subnet_ids(&sa)
        .subnet_ids(&sa2)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "DuplicateSubnetsInSameZone");

    let att_a = ec2
        .create_transit_gateway_vpc_attachment()
        .transit_gateway_id(&tgw_id)
        .vpc_id(&a)
        .subnet_ids(&sa)
        .send()
        .await
        .unwrap()
        .transit_gateway_vpc_attachment
        .unwrap()
        .transit_gateway_attachment_id
        .unwrap();
    let att_b = ec2
        .create_transit_gateway_vpc_attachment()
        .transit_gateway_id(&tgw_id)
        .vpc_id(&b)
        .subnet_ids(&sb)
        .send()
        .await
        .unwrap()
        .transit_gateway_vpc_attachment
        .unwrap()
        .transit_gateway_attachment_id
        .unwrap();

    // Both VPCs propagate their CIDR blocks into the default table.
    let routes = ec2
        .search_transit_gateway_routes()
        .transit_gateway_route_table_id(&rtb)
        .filters(Filter::builder().name("type").values("propagated").build())
        .send()
        .await
        .unwrap();
    let dests: Vec<_> = routes.routes().iter().filter_map(|r| r.destination_cidr_block()).collect();
    assert_eq!(dests, ["10.40.0.0/16", "10.41.0.0/16"]);
    let hit = ec2
        .search_transit_gateway_routes()
        .transit_gateway_route_table_id(&rtb)
        .filters(Filter::builder().name("route-search.longest-prefix-match").values("10.41.7.0/24").build())
        .send()
        .await
        .unwrap();
    assert_eq!(hit.routes()[0].transit_gateway_attachments()[0].transit_gateway_attachment_id(), Some(att_b.as_str()));

    ec2.create_transit_gateway_route()
        .transit_gateway_route_table_id(&rtb)
        .destination_cidr_block("0.0.0.0/0")
        .transit_gateway_attachment_id(&att_a)
        .send()
        .await
        .unwrap();
    let assoc =
        ec2.get_transit_gateway_route_table_associations().transit_gateway_route_table_id(&rtb).send().await.unwrap();
    assert_eq!(assoc.associations().len(), 2);

    // VPC routes may target the gateway once the VPC is attached.
    let rt = main_route_table(&ec2, &a).await;
    ec2.create_route()
        .route_table_id(&rt)
        .destination_cidr_block("10.41.0.0/16")
        .transit_gateway_id(&tgw_id)
        .send()
        .await
        .unwrap();

    let e = ec2.delete_transit_gateway().transit_gateway_id(&tgw_id).send().await.unwrap_err();
    assert_eq!(code(&e), "IncorrectState");
    ec2.delete_transit_gateway_vpc_attachment().transit_gateway_attachment_id(&att_a).send().await.unwrap();
    ec2.delete_transit_gateway_vpc_attachment().transit_gateway_attachment_id(&att_b).send().await.unwrap();
    let static_route = ec2
        .search_transit_gateway_routes()
        .transit_gateway_route_table_id(&rtb)
        .filters(Filter::builder().name("type").values("static").build())
        .send()
        .await
        .unwrap();
    assert_eq!(static_route.routes()[0].state().unwrap().as_str(), "blackhole");
    ec2.delete_transit_gateway().transit_gateway_id(&tgw_id).send().await.unwrap();
}

#[tokio::test]
async fn vpc_peering_lifecycle() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let a = vpc(&ec2, "10.50.0.0/16").await;
    let b = vpc(&ec2, "10.51.0.0/16").await;
    let overlapping = vpc(&ec2, "10.50.0.0/20").await;

    let pcx = ec2
        .create_vpc_peering_connection()
        .vpc_id(&a)
        .peer_vpc_id(&b)
        .send()
        .await
        .unwrap()
        .vpc_peering_connection
        .unwrap();
    let id = pcx.vpc_peering_connection_id().unwrap().to_string();
    assert_eq!(pcx.status().unwrap().code().unwrap().as_str(), "initiating-request");
    let rt = main_route_table(&ec2, &a).await;
    // Not active yet.
    let e = ec2
        .create_route()
        .route_table_id(&rt)
        .destination_cidr_block("10.51.0.0/16")
        .vpc_peering_connection_id(&id)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "InvalidVpcPeeringConnectionID.NotFound");

    ec2.accept_vpc_peering_connection().vpc_peering_connection_id(&id).send().await.unwrap();
    let described = ec2.describe_vpc_peering_connections().vpc_peering_connection_ids(&id).send().await.unwrap();
    let p = &described.vpc_peering_connections()[0];
    assert_eq!(p.status().unwrap().code().unwrap().as_str(), "active");
    assert_eq!(p.accepter_vpc_info().unwrap().cidr_block(), Some("10.51.0.0/16"));
    ec2.create_route()
        .route_table_id(&rt)
        .destination_cidr_block("10.51.0.0/16")
        .vpc_peering_connection_id(&id)
        .send()
        .await
        .unwrap();
    let e = ec2.accept_vpc_peering_connection().vpc_peering_connection_id(&id).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidStateTransition");

    ec2.delete_vpc_peering_connection().vpc_peering_connection_id(&id).send().await.unwrap();
    let described = ec2.describe_vpc_peering_connections().vpc_peering_connection_ids(&id).send().await.unwrap();
    assert_eq!(described.vpc_peering_connections()[0].status().unwrap().code().unwrap().as_str(), "deleted");

    // Overlapping address ranges cannot peer.
    let failed = ec2
        .create_vpc_peering_connection()
        .vpc_id(&a)
        .peer_vpc_id(&overlapping)
        .send()
        .await
        .unwrap()
        .vpc_peering_connection
        .unwrap();
    let fid = failed.vpc_peering_connection_id().unwrap();
    let d = ec2.describe_vpc_peering_connections().vpc_peering_connection_ids(fid).send().await.unwrap();
    assert_eq!(d.vpc_peering_connections()[0].status().unwrap().code().unwrap().as_str(), "failed");
}

#[tokio::test]
async fn ipv6_egress_only_gateway_and_interface_addresses() {
    let mws = Mws::start().await;
    let ec2 = client(&mws).await;
    let v = ec2
        .create_vpc()
        .cidr_block("10.60.0.0/16")
        .amazon_provided_ipv6_cidr_block(true)
        .send()
        .await
        .unwrap()
        .vpc
        .unwrap();
    let vpc_id = v.vpc_id().unwrap().to_string();
    let block = v.ipv6_cidr_block_association_set()[0].ipv6_cidr_block().unwrap().to_string();
    assert!(block.ends_with("::/56"));
    let sn = subnet(&ec2, &vpc_id, "10.60.1.0/24", "us-east-1a").await;
    let sub64 = block.replace("00::/56", "01::/64");
    let assoc = ec2.associate_subnet_cidr_block().subnet_id(&sn).ipv6_cidr_block(&sub64).send().await.unwrap();
    let assoc_id = assoc.ipv6_cidr_block_association().unwrap().association_id().unwrap().to_string();

    let eni = ec2.create_network_interface().subnet_id(&sn).send().await.unwrap().network_interface.unwrap();
    let eni_id = eni.network_interface_id().unwrap().to_string();
    let v4 = ec2
        .assign_private_ip_addresses()
        .network_interface_id(&eni_id)
        .secondary_private_ip_address_count(2)
        .send()
        .await
        .unwrap();
    assert_eq!(v4.assigned_private_ip_addresses().len(), 2);
    let v6 = ec2.assign_ipv6_addresses().network_interface_id(&eni_id).ipv6_address_count(1).send().await.unwrap();
    let addr = v6.assigned_ipv6_addresses()[0].clone();
    assert!(addr.starts_with(&sub64[..sub64.len() - 5]));
    let prefix =
        ec2.assign_private_ip_addresses().network_interface_id(&eni_id).ipv4_prefix_count(1).send().await.unwrap();
    assert!(prefix.assigned_ipv4_prefixes()[0].ipv4_prefix().unwrap().ends_with("/28"));

    // The subnet block is in use while an interface holds an address from it.
    let e = ec2.disassociate_subnet_cidr_block().association_id(&assoc_id).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidCidrBlock.InUse");
    ec2.unassign_ipv6_addresses().network_interface_id(&eni_id).ipv6_addresses(&addr).send().await.unwrap();
    let ip = v4.assigned_private_ip_addresses()[0].private_ip_address().unwrap().to_string();
    ec2.unassign_private_ip_addresses().network_interface_id(&eni_id).private_ip_addresses(&ip).send().await.unwrap();
    ec2.disassociate_subnet_cidr_block().association_id(&assoc_id).send().await.unwrap();

    let eigw = ec2
        .create_egress_only_internet_gateway()
        .vpc_id(&vpc_id)
        .send()
        .await
        .unwrap()
        .egress_only_internet_gateway
        .unwrap()
        .egress_only_internet_gateway_id
        .unwrap();
    let rt = main_route_table(&ec2, &vpc_id).await;
    ec2.create_route()
        .route_table_id(&rt)
        .destination_ipv6_cidr_block("::/0")
        .egress_only_internet_gateway_id(&eigw)
        .send()
        .await
        .unwrap();
    ec2.delete_egress_only_internet_gateway().egress_only_internet_gateway_id(&eigw).send().await.unwrap();

    let fl = ec2
        .create_flow_logs()
        .resource_ids(&vpc_id)
        .resource_ids("vpc-0123456789abcdef0")
        .resource_type(FlowLogsResourceType::Vpc)
        .traffic_type(TrafficType::All)
        .log_destination_type(LogDestinationType::S3)
        .log_destination("arn:aws:s3:::flow-log-bucket")
        .send()
        .await
        .unwrap();
    assert_eq!(fl.flow_log_ids().len(), 1);
    assert_eq!(fl.unsuccessful()[0].error().unwrap().code(), Some("InvalidVpcID.NotFound"));
    let logs = ec2.describe_flow_logs().flow_log_ids(&fl.flow_log_ids()[0]).send().await.unwrap();
    assert_eq!(logs.flow_logs()[0].max_aggregation_interval(), Some(600));
    let deleted = ec2
        .delete_flow_logs()
        .flow_log_ids(&fl.flow_log_ids()[0])
        .flow_log_ids("fl-0123456789abcdef0")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.unsuccessful()[0].error().unwrap().code(), Some("InvalidFlowLogId.NotFound"));
}
