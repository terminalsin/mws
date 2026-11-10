//! Elastic Load Balancing v2 network interfaces through the official Rust
//! SDKs: load balancers put a requester-managed `ELB app/...` or
//! `ELB net/...` interface in each enabled subnet, which keeps the subnet
//! and security groups in use and follows SetSubnets, SetSecurityGroups and
//! DeleteLoadBalancer. Also CreateListener and CreateRule authorization on
//! the parent resource.

use aws_sdk_ec2::types::{Filter, NetworkInterface};
use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, FixedResponseActionConfig, LoadBalancerTypeEnum, PathPatternConditionConfig, ProtocolEnum,
    RuleCondition, Tag,
};
use mws_e2e::{user_with_policy, Mws};

use crate::elbv2::{code, default_network};

async fn interfaces(ec2: &aws_sdk_ec2::Client, description: &str) -> Vec<NetworkInterface> {
    let out = ec2
        .describe_network_interfaces()
        .filters(Filter::builder().name("description").values(description).build())
        .send()
        .await
        .unwrap();
    out.network_interfaces().to_vec()
}

fn description(lb_arn: &str) -> String {
    format!("ELB {}", lb_arn.split_once(":loadbalancer/").unwrap().1)
}

#[tokio::test]
async fn load_balancers_own_network_interfaces() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&config);
    let (vpc, subnets) = default_network(&mws).await;
    let sg = ec2.create_security_group().group_name("alb").description("alb").vpc_id(&vpc).send().await.unwrap();
    let sg = sg.group_id().unwrap().to_string();

    let lb = elb
        .create_load_balancer()
        .name("front")
        .set_subnets(Some(subnets.clone()))
        .security_groups(&sg)
        .send()
        .await
        .unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let desc = description(&lb_arn);
    assert!(desc.starts_with("ELB app/front/"), "{desc}");
    let enis = interfaces(&ec2, &desc).await;
    assert_eq!(enis.len(), 2);
    let mut in_subnets: Vec<String> = enis.iter().map(|e| e.subnet_id().unwrap().to_string()).collect();
    in_subnets.sort();
    let mut want = subnets.clone();
    want.sort();
    assert_eq!(in_subnets, want);
    for e in &enis {
        assert_eq!(e.requester_managed(), Some(true));
        assert_eq!(e.requester_id(), Some("amazon-elb"));
        assert_eq!(e.interface_type().map(|t| t.as_str()), Some("interface"));
        assert_eq!(e.vpc_id(), Some(vpc.as_str()));
        assert!(e.private_ip_address().is_some());
        assert!(e.association().and_then(|a| a.public_ip()).is_some(), "internet-facing gets a public IP");
        assert_eq!(e.groups().iter().filter_map(|g| g.group_id()).collect::<Vec<_>>(), vec![sg.as_str()]);
    }

    // The subnet and the security group are in use.
    let err = ec2.delete_subnet().subnet_id(&subnets[0]).send().await.unwrap_err();
    assert_eq!(aws_sdk_ec2::error::ProvideErrorMetadata::code(&err), Some("DependencyViolation"));
    let err = ec2.delete_security_group().group_id(&sg).send().await.unwrap_err();
    assert_eq!(aws_sdk_ec2::error::ProvideErrorMetadata::code(&err), Some("DependencyViolation"));

    // SetSecurityGroups moves the interfaces to the new groups.
    let sg2 = ec2.create_security_group().group_name("alb2").description("alb2").vpc_id(&vpc).send().await.unwrap();
    let sg2 = sg2.group_id().unwrap().to_string();
    elb.set_security_groups().load_balancer_arn(&lb_arn).security_groups(&sg2).send().await.unwrap();
    for e in interfaces(&ec2, &desc).await {
        assert_eq!(e.groups().iter().filter_map(|g| g.group_id()).collect::<Vec<_>>(), vec![sg2.as_str()]);
    }
    ec2.delete_security_group().group_id(&sg).send().await.unwrap();

    // SetSubnets: a third subnet gets an interface, a dropped one loses it.
    let all = ec2
        .describe_subnets()
        .filters(Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    let third = all
        .subnets()
        .iter()
        .filter_map(|s| s.subnet_id())
        .find(|s| !subnets.iter().any(|x| x == s))
        .unwrap()
        .to_string();
    elb.set_subnets().load_balancer_arn(&lb_arn).subnets(&subnets[1]).subnets(&third).send().await.unwrap();
    let mut in_subnets: Vec<String> =
        interfaces(&ec2, &desc).await.iter().map(|e| e.subnet_id().unwrap().to_string()).collect();
    in_subnets.sort();
    let mut want = vec![subnets[1].clone(), third.clone()];
    want.sort();
    assert_eq!(in_subnets, want);

    // Network Load Balancers are `ELB net/...`; internal ones get no
    // public address.
    let nlb = elb
        .create_load_balancer()
        .name("inner")
        .r#type(LoadBalancerTypeEnum::Network)
        .scheme(aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::Internal)
        .subnets(&subnets[0])
        .send()
        .await
        .unwrap();
    let nlb_arn = nlb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let nlb_enis = interfaces(&ec2, &description(&nlb_arn)).await;
    assert_eq!(nlb_enis.len(), 1);
    assert!(description(&nlb_arn).starts_with("ELB net/inner/"));
    assert!(nlb_enis[0].association().is_none());
    // Created without security groups, its interfaces have none.
    assert!(nlb_enis[0].groups().is_empty(), "{:?}", nlb_enis[0].groups());

    // Deleting the load balancers deletes their interfaces.
    elb.delete_load_balancer().load_balancer_arn(&lb_arn).send().await.unwrap();
    elb.delete_load_balancer().load_balancer_arn(&nlb_arn).send().await.unwrap();
    assert!(interfaces(&ec2, &desc).await.is_empty());
    assert!(interfaces(&ec2, &description(&nlb_arn)).await.is_empty());
    ec2.delete_security_group().group_id(&sg2).send().await.unwrap();
}

#[tokio::test]
async fn network_load_balancer_subnet_mappings_pick_the_address_and_elastic_ip() {
    use aws_sdk_elasticloadbalancingv2::types::SubnetMapping;
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&config);
    let (_, subnets) = default_network(&mws).await;
    let subnet = ec2.describe_subnets().subnet_ids(&subnets[0]).send().await.unwrap();
    let cidr = subnet.subnets()[0].cidr_block().unwrap().to_string();
    let base: std::net::Ipv4Addr = cidr.split('/').next().unwrap().parse().unwrap();
    let ip = std::net::Ipv4Addr::from(u32::from(base) + 10).to_string();
    let eip = ec2.allocate_address().send().await.unwrap();
    let alloc = eip.allocation_id().unwrap().to_string();

    // An unknown Elastic IP is refused.
    let err = elb
        .create_load_balancer()
        .name("pinned")
        .r#type(LoadBalancerTypeEnum::Network)
        .subnet_mappings(
            SubnetMapping::builder().subnet_id(&subnets[0]).allocation_id("eipalloc-0123456789abcdef0").build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "AllocationIdNotFound");

    let lb = elb
        .create_load_balancer()
        .name("pinned")
        .r#type(LoadBalancerTypeEnum::Network)
        .subnet_mappings(
            SubnetMapping::builder().subnet_id(&subnets[0]).private_ipv4_address(&ip).allocation_id(&alloc).build(),
        )
        .send()
        .await
        .unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let enis = interfaces(&ec2, &description(&lb_arn)).await;
    assert_eq!(enis.len(), 1);
    assert_eq!(enis[0].private_ip_address(), Some(ip.as_str()));
    assert_eq!(enis[0].association().and_then(|a| a.allocation_id()), Some(alloc.as_str()));
    assert_eq!(enis[0].association().and_then(|a| a.public_ip()), eip.public_ip());
    let a = ec2.describe_addresses().allocation_ids(&alloc).send().await.unwrap();
    let a = &a.addresses()[0];
    assert_eq!(a.network_interface_id(), enis[0].network_interface_id());
    assert_eq!(a.private_ip_address(), Some(ip.as_str()));
    assert!(a.association_id().is_some());

    // The address is taken: an instance cannot have it.
    let d = elb.describe_load_balancers().load_balancer_arns(&lb_arn).send().await.unwrap();
    let addr = &d.load_balancers()[0].availability_zones()[0].load_balancer_addresses()[0];
    assert_eq!(addr.ip_address(), eip.public_ip());
    let err = ec2.create_network_interface().subnet_id(&subnets[0]).private_ip_address(&ip).send().await.unwrap_err();
    assert_eq!(aws_sdk_ec2::error::ProvideErrorMetadata::code(&err), Some("InvalidIPAddress.InUse"));

    // Deleting the load balancer frees the Elastic IP.
    elb.delete_load_balancer().load_balancer_arn(&lb_arn).send().await.unwrap();
    let a = ec2.describe_addresses().allocation_ids(&alloc).send().await.unwrap();
    assert!(a.addresses()[0].association_id().is_none());
    ec2.release_address().allocation_id(&alloc).send().await.unwrap();
}

#[tokio::test]
async fn listeners_and_rules_are_authorized_on_their_parent() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&config);
    let (_, subnets) = default_network(&mws).await;
    let mk = |name: &'static str, team: &'static str| {
        let elb = elb.clone();
        let subnets = subnets.clone();
        async move {
            let lb = elb
                .create_load_balancer()
                .name(name)
                .set_subnets(Some(subnets))
                .tags(Tag::builder().key("team").value(team).build())
                .send()
                .await
                .unwrap();
            lb.load_balancers()[0].load_balancer_arn().unwrap().to_string()
        }
    };
    let mine = mk("mine", "web").await;
    let theirs = mk("theirs", "data").await;
    // Only load balancers tagged team=web.
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":["elasticloadbalancing:CreateListener","elasticloadbalancing:CreateRule"],"Resource":"*",
         "Condition":{"StringEquals":{"aws:ResourceTag/team":"web"}}}]}"#;
    let (_, cfg) = user_with_policy(&mws, "web-dev", Some(policy)).await;
    let dev = aws_sdk_elasticloadbalancingv2::Client::new(&cfg);
    let fixed = || {
        Action::builder()
            .r#type(ActionTypeEnum::FixedResponse)
            .fixed_response_config(FixedResponseActionConfig::builder().status_code("200").build())
            .build()
    };
    let listener = |lb: &str| {
        dev.create_listener().load_balancer_arn(lb).protocol(ProtocolEnum::Http).port(80).default_actions(fixed())
    };
    let err = listener(&theirs).send().await.unwrap_err();
    assert_eq!(code(&err), "AccessDenied");
    let out = listener(&mine).send().await.unwrap();
    let listener_arn = out.listeners()[0].listener_arn().unwrap().to_string();

    // CreateRule is authorized on the listener, which carries its own tags.
    let rule = || {
        dev.create_rule()
            .listener_arn(&listener_arn)
            .priority(10)
            .conditions(
                RuleCondition::builder()
                    .field("path-pattern")
                    .path_pattern_config(PathPatternConditionConfig::builder().values("/a").build())
                    .build(),
            )
            .actions(fixed())
    };
    let err = rule().send().await.unwrap_err();
    assert_eq!(code(&err), "AccessDenied");
    elb.add_tags()
        .resource_arns(&listener_arn)
        .tags(Tag::builder().key("team").value("web").build())
        .send()
        .await
        .unwrap();
    rule().send().await.unwrap();
}
