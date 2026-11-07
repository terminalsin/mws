//! VPC endpoint services (AWS PrivateLink) through the official Rust SDK:
//! a service offered behind a Network Load Balancer, the principals allowed
//! to connect, and a consumer account's interface endpoint waiting for the
//! owner to accept it.

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{Filter, VpcEndpointType};
use aws_sdk_ec2::Client;
use aws_sdk_elasticloadbalancingv2::types::LoadBalancerTypeEnum;
use aws_sdk_organizations::Client as Orgs;
use mws_e2e::{sts_config, user_with_policy, Mws};

const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

/// The default subnets of an account, ordered by zone: `(id, zone)`.
async fn default_subnets(ec2: &Client) -> Vec<(String, String)> {
    let filter = Filter::builder().name("default-for-az").values("true").build();
    let out = ec2.describe_subnets().filters(filter).send().await.unwrap();
    let mut v: Vec<(String, String)> = out
        .subnets()
        .iter()
        .map(|s| (s.subnet_id().unwrap().to_string(), s.availability_zone().unwrap().to_string()))
        .collect();
    v.sort_by(|a, b| a.1.cmp(&b.1));
    v
}

async fn vpc_of(ec2: &Client, subnet: &str) -> String {
    let out = ec2.describe_subnets().subnet_ids(subnet).send().await.unwrap();
    out.subnets()[0].vpc_id().unwrap().to_string()
}

/// A member account of a new organization, and a session in it.
async fn member(mws: &Mws) -> (String, aws_config::SdkConfig) {
    let root = mws.root_sdk_config().await;
    let orgs = Orgs::new(&root);
    orgs.create_organization().send().await.unwrap();
    let out = orgs.create_account().email("consumer@example.com").account_name("consumer").send().await.unwrap();
    let id = out.create_account_status().unwrap().id().unwrap();
    let st = orgs.describe_create_account_status().create_account_request_id(id).send().await.unwrap();
    let account = st.create_account_status().unwrap().account_id().unwrap().to_string();
    let (_, admin) = user_with_policy(mws, "admin", Some(ADMIN)).await;
    let creds = aws_sdk_sts::Client::new(&admin)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
        .role_session_name("consumer")
        .send()
        .await
        .unwrap();
    (account, sts_config(mws, creds.credentials().unwrap()).await)
}

async fn endpoint_state(ec2: &Client, id: &str) -> String {
    let out = ec2.describe_vpc_endpoints().vpc_endpoint_ids(id).send().await.unwrap();
    out.vpc_endpoints()[0].state().unwrap().as_str().to_string()
}

#[tokio::test]
async fn endpoint_services_accept_endpoints_from_allowed_accounts() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let ec2 = Client::new(&root);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&root);
    let subnets = default_subnets(&ec2).await;

    let lb = elb
        .create_load_balancer()
        .name("privatelink")
        .r#type(LoadBalancerTypeEnum::Network)
        .scheme(aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::Internal)
        .subnets(&subnets[0].0)
        .subnets(&subnets[1].0)
        .send()
        .await
        .unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();

    // Only Network or Gateway Load Balancers, and ones that exist.
    let e = ec2
        .create_vpc_endpoint_service_configuration()
        .network_load_balancer_arns(lb_arn.replace("/net/", "/app/"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameter");

    let svc = ec2
        .create_vpc_endpoint_service_configuration()
        .network_load_balancer_arns(&lb_arn)
        .private_dns_name("api.example.test")
        .send()
        .await
        .unwrap();
    let svc = svc.service_configuration().unwrap();
    let svc_id = svc.service_id().unwrap().to_string();
    let svc_name = svc.service_name().unwrap().to_string();
    assert!(svc_id.starts_with("vpce-svc-"));
    assert_eq!(svc_name, format!("com.amazonaws.vpce.us-east-1.{svc_id}"));
    assert_eq!(svc.acceptance_required(), Some(true));
    assert_eq!(svc.availability_zones(), [subnets[0].1.clone(), subnets[1].1.clone()]);
    assert_eq!(svc.base_endpoint_dns_names(), [format!("{svc_id}.us-east-1.vpce.amazonaws.com")]);
    let pdns = svc.private_dns_name_configuration().unwrap();
    assert_eq!(pdns.state().unwrap().as_str(), "pendingVerification");
    assert_eq!(pdns.r#type(), Some("TXT"));

    // The owner sees it among the endpoint services.
    let listed = ec2.describe_vpc_endpoint_services().service_names(&svc_name).send().await.unwrap();
    assert_eq!(listed.service_details()[0].service_type()[0].service_type().unwrap().as_str(), "Interface");

    // Another account sees it only once allowed.
    let (consumer_account, consumer) = member(&mws).await;
    let consumer_ec2 = Client::new(&consumer);
    let e = consumer_ec2.describe_vpc_endpoint_services().service_names(&svc_name).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidServiceName");

    let e = ec2
        .modify_vpc_endpoint_service_permissions()
        .service_id(&svc_id)
        .add_allowed_principals("not-a-principal")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidPrincipal");
    let added = ec2
        .modify_vpc_endpoint_service_permissions()
        .service_id(&svc_id)
        .add_allowed_principals(format!("arn:aws:iam::{consumer_account}:root"))
        .send()
        .await
        .unwrap();
    assert_eq!(added.added_principals()[0].principal_type().unwrap().as_str(), "Account");
    let perms = ec2.describe_vpc_endpoint_service_permissions().service_id(&svc_id).send().await.unwrap();
    assert_eq!(perms.allowed_principals().len(), 1);

    let seen = consumer_ec2.describe_vpc_endpoint_services().service_names(&svc_name).send().await.unwrap();
    let detail = &seen.service_details()[0];
    assert_eq!(detail.owner(), Some("123456789012"));
    assert_eq!(detail.acceptance_required(), Some(true));

    // The consumer's endpoint waits for acceptance.
    let consumer_subnets = default_subnets(&consumer_ec2).await;
    let consumer_vpc = vpc_of(&consumer_ec2, &consumer_subnets[0].0).await;
    let e = consumer_ec2
        .create_vpc_endpoint()
        .vpc_endpoint_type(VpcEndpointType::Interface)
        .vpc_id(&consumer_vpc)
        .service_name(&svc_name)
        .subnet_ids(&consumer_subnets[0].0)
        .private_dns_enabled(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameter", "private DNS needs a verified name");
    let ep = consumer_ec2
        .create_vpc_endpoint()
        .vpc_endpoint_type(VpcEndpointType::Interface)
        .vpc_id(&consumer_vpc)
        .service_name(&svc_name)
        .subnet_ids(&consumer_subnets[0].0)
        .send()
        .await
        .unwrap();
    let ep = ep.vpc_endpoint().unwrap();
    let ep_id = ep.vpc_endpoint_id().unwrap().to_string();
    assert_eq!(ep.state().unwrap().as_str(), "pendingAcceptance");
    assert_eq!(ep.network_interface_ids().len(), 1);
    assert!(ep.dns_entries()[0].dns_name().unwrap().ends_with(&format!(".{svc_id}.us-east-1.vpce.amazonaws.com")));

    let conns = ec2.describe_vpc_endpoint_connections().send().await.unwrap();
    let conn = &conns.vpc_endpoint_connections()[0];
    assert_eq!(conn.vpc_endpoint_id(), Some(ep_id.as_str()));
    assert_eq!(conn.vpc_endpoint_owner(), Some(consumer_account.as_str()));
    assert_eq!(conn.vpc_endpoint_state().unwrap().as_str(), "pendingAcceptance");

    // A service with live connections cannot be deleted.
    let del = ec2.delete_vpc_endpoint_service_configurations().service_ids(&svc_id).send().await.unwrap();
    assert_eq!(del.unsuccessful()[0].error().unwrap().code(), Some("ExistingVpcEndpointConnections"));

    let accepted =
        ec2.accept_vpc_endpoint_connections().service_id(&svc_id).vpc_endpoint_ids(&ep_id).send().await.unwrap();
    assert!(accepted.unsuccessful().is_empty());
    assert_eq!(endpoint_state(&consumer_ec2, &ep_id).await, "available");
    let again =
        ec2.accept_vpc_endpoint_connections().service_id(&svc_id).vpc_endpoint_ids(&ep_id).send().await.unwrap();
    assert_eq!(again.unsuccessful()[0].error().unwrap().code(), Some("InvalidVpcEndpointState"));

    ec2.reject_vpc_endpoint_connections().service_id(&svc_id).vpc_endpoint_ids(&ep_id).send().await.unwrap();
    assert_eq!(endpoint_state(&consumer_ec2, &ep_id).await, "rejected");

    // Verifying the private DNS name.
    ec2.start_vpc_endpoint_service_private_dns_verification().service_id(&svc_id).send().await.unwrap();
    let cfg = ec2.describe_vpc_endpoint_service_configurations().service_ids(&svc_id).send().await.unwrap();
    let cfg = &cfg.service_configurations()[0];
    assert_eq!(cfg.private_dns_name_configuration().unwrap().state().unwrap().as_str(), "verified");

    ec2.modify_vpc_endpoint_service_configuration()
        .service_id(&svc_id)
        .acceptance_required(false)
        .send()
        .await
        .unwrap();
    consumer_ec2.delete_vpc_endpoints().vpc_endpoint_ids(&ep_id).send().await.unwrap();
    assert!(ec2.describe_vpc_endpoint_connections().send().await.unwrap().vpc_endpoint_connections().is_empty());

    // Without acceptance, a new endpoint is available straight away.
    let ep = consumer_ec2
        .create_vpc_endpoint()
        .vpc_endpoint_type(VpcEndpointType::Interface)
        .vpc_id(&consumer_vpc)
        .service_name(&svc_name)
        .subnet_ids(&consumer_subnets[1].0)
        .private_dns_enabled(true)
        .send()
        .await
        .unwrap();
    let ep_id = ep.vpc_endpoint().unwrap().vpc_endpoint_id().unwrap().to_string();
    assert_eq!(endpoint_state(&consumer_ec2, &ep_id).await, "available");
    consumer_ec2.delete_vpc_endpoints().vpc_endpoint_ids(&ep_id).send().await.unwrap();

    let del = ec2.delete_vpc_endpoint_service_configurations().service_ids(&svc_id).send().await.unwrap();
    assert!(del.unsuccessful().is_empty());
    let e = ec2.describe_vpc_endpoint_service_configurations().service_ids(&svc_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidVpcEndpointServiceId.NotFound");
    mws.stop().await;
}

#[tokio::test]
async fn endpoint_service_payer_and_filters() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&mws.root_sdk_config().await);
    let subnets = default_subnets(&ec2).await;
    let lb = elb
        .create_load_balancer()
        .name("gwlb")
        .r#type(LoadBalancerTypeEnum::Gateway)
        .subnets(&subnets[0].0)
        .send()
        .await
        .unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let svc = ec2
        .create_vpc_endpoint_service_configuration()
        .gateway_load_balancer_arns(&lb_arn)
        .acceptance_required(false)
        .send()
        .await
        .unwrap();
    let svc = svc.service_configuration().unwrap();
    let svc_id = svc.service_id().unwrap().to_string();
    assert_eq!(svc.service_type()[0].service_type().unwrap().as_str(), "GatewayLoadBalancer");
    assert_eq!(svc.availability_zones(), [subnets[0].1.clone()]);
    assert!(svc.base_endpoint_dns_names().is_empty());

    let e = ec2
        .modify_vpc_endpoint_service_payer_responsibility()
        .service_id(&svc_id)
        .payer_responsibility(aws_sdk_ec2::types::PayerResponsibility::from("Requester"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");

    let found = ec2
        .describe_vpc_endpoint_service_configurations()
        .filters(Filter::builder().name("service-id").values(&svc_id).build())
        .send()
        .await
        .unwrap();
    assert_eq!(found.service_configurations().len(), 1);

    // A Gateway Load Balancer endpoint in one subnet, accepted at once.
    let vpc = vpc_of(&ec2, &subnets[0].0).await;
    let ep = ec2
        .create_vpc_endpoint()
        .vpc_endpoint_type(VpcEndpointType::GatewayLoadBalancer)
        .vpc_id(&vpc)
        .service_name(svc.service_name().unwrap())
        .subnet_ids(&subnets[0].0)
        .send()
        .await
        .unwrap();
    let ep_id = ep.vpc_endpoint().unwrap().vpc_endpoint_id().unwrap().to_string();
    assert_eq!(endpoint_state(&ec2, &ep_id).await, "available");
    let e = ec2
        .create_vpc_endpoint()
        .vpc_endpoint_type(VpcEndpointType::Interface)
        .vpc_id(&vpc)
        .service_name(svc.service_name().unwrap())
        .subnet_ids(&subnets[1].0)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameter");
    mws.stop().await;
}
