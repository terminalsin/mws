//! Route 53 alias records that point outside their zone (load balancers,
//! S3 website endpoints, other hosted zones) and private hosted zone VPCs,
//! through the official Rust SDK.

use std::time::Duration;

use aws_sdk_elasticloadbalancingv2::types::{ProtocolEnum, TargetDescription, TargetHealthStateEnum};
use aws_sdk_route53::error::ProvideErrorMetadata;
use aws_sdk_route53::types::{
    AliasTarget, Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType, Vpc, VpcRegion,
};
use aws_sdk_route53::Client;
use mws_e2e::Mws;

use crate::elbv2::{default_network, forward, ip_target_group, wait_for_health, Backend};

async fn zone(r53: &Client, name: &str) -> String {
    let out = r53.create_hosted_zone().name(name).caller_reference(format!("ref-{name}")).send().await.unwrap();
    out.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string()
}

fn alias(
    name: &str,
    zone: &str,
    target: &str,
    evaluate: bool,
) -> aws_sdk_route53::types::builders::ResourceRecordSetBuilder {
    ResourceRecordSet::builder().name(name).r#type(RrType::A).alias_target(
        AliasTarget::builder().hosted_zone_id(zone).dns_name(target).evaluate_target_health(evaluate).build().unwrap(),
    )
}

fn plain(name: &str, ip: &str) -> aws_sdk_route53::types::builders::ResourceRecordSetBuilder {
    ResourceRecordSet::builder()
        .name(name)
        .r#type(RrType::A)
        .ttl(60)
        .resource_records(ResourceRecord::builder().value(ip).build().unwrap())
}

/// Apply one change; the error's message on failure.
async fn create(r53: &Client, zone: &str, set: ResourceRecordSet) -> Result<(), String> {
    let batch = ChangeBatch::builder()
        .changes(Change::builder().action(ChangeAction::Upsert).resource_record_set(set).build().unwrap())
        .build()
        .unwrap();
    r53.change_resource_record_sets().hosted_zone_id(zone).change_batch(batch).send().await.map(|_| ()).map_err(|e| {
        let e = e.into_service_error();
        format!("{}: {}", e.code().unwrap_or_default(), e.message().unwrap_or_default())
    })
}

async fn answer(r53: &Client, zone: &str, name: &str) -> Vec<String> {
    let a = r53.test_dns_answer().hosted_zone_id(zone).record_name(name).record_type(RrType::A).send().await.unwrap();
    a.record_data().to_vec()
}

#[tokio::test]
async fn aliases_to_load_balancers_follow_their_health() {
    let mws = Mws::start().await;
    let r53 = Client::new(&mws.root_sdk_config().await);
    let elb = crate::elbv2::client(&mws).await;
    let z = zone(&r53, "shop.example").await;

    // Load balancer names that aren't there, or aren't in the zone.
    let err = create(
        &r53,
        &z,
        alias("www.shop.example", "Z35SXDOTRQ7X7K", "nope-1234567890.us-east-1.elb.amazonaws.com", false)
            .build()
            .unwrap(),
    )
    .await
    .unwrap_err();
    assert!(err.starts_with("InvalidChangeBatch"), "{err}");
    assert!(
        err.contains("Tried to create an alias that targets nope-1234567890.us-east-1.elb.amazonaws.com., type A in zone Z35SXDOTRQ7X7K, but that target was not found"),
        "{err}"
    );
    let err = create(&r53, &z, alias("www.shop.example", "Z35SXDOTRQ7X7K", "www.example.org", false).build().unwrap())
        .await
        .unwrap_err();
    assert!(
        err.contains("Tried to create an alias that targets www.example.org., type A in zone Z35SXDOTRQ7X7K, but the alias target name does not lie within the target zone"),
        "{err}"
    );

    // An Application Load Balancer with a listener and no healthy target.
    let (vpc, subnets) = default_network(&mws).await;
    let lb = elb.create_load_balancer().name("shop").set_subnets(Some(subnets)).send().await.unwrap();
    let lb = &lb.load_balancers()[0];
    let dns = lb.dns_name().unwrap().to_string();
    assert_eq!(lb.canonical_hosted_zone_id(), Some("Z35SXDOTRQ7X7K"));
    let tg = ip_target_group(&elb, "shop", &vpc, ProtocolEnum::Http).await;
    elb.create_listener()
        .load_balancer_arn(lb.load_balancer_arn().unwrap())
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();

    // In the wrong ELB zone (Network Load Balancers'), it is outside it.
    let err =
        create(&r53, &z, alias("www.shop.example", "Z26RNL4JYFTOTI", &dns, false).build().unwrap()).await.unwrap_err();
    assert!(err.contains("but the alias target name does not lie within the target zone"), "{err}");

    // Failover: the load balancer first while it has a healthy target,
    // else a static page.
    create(
        &r53,
        &z,
        alias("www.shop.example", "Z35SXDOTRQ7X7K", &format!("dualstack.{dns}"), true)
            .set_identifier("primary")
            .failover("PRIMARY".into())
            .build()
            .unwrap(),
    )
    .await
    .unwrap();
    create(
        &r53,
        &z,
        plain("www.shop.example", "192.0.2.80")
            .set_identifier("secondary")
            .failover("SECONDARY".into())
            .build()
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(answer(&r53, &z, "www.shop.example").await, ["192.0.2.80"]);

    // A plain alias answers with the load balancer's addresses.
    create(&r53, &z, alias("lb.shop.example", "Z35SXDOTRQ7X7K", &dns, false).build().unwrap()).await.unwrap();
    assert_eq!(answer(&r53, &z, "lb.shop.example").await, ["127.0.0.1"]);

    let backend = Backend::start("shop").await;
    elb.register_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(backend.port()).build())
        .send()
        .await
        .unwrap();
    wait_for_health(&elb, &tg, &[(backend.port(), TargetHealthStateEnum::Healthy)]).await;
    let mut got = Vec::new();
    for _ in 0..40 {
        got = answer(&r53, &z, "www.shop.example").await;
        if got == ["127.0.0.1"] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(got, ["127.0.0.1"]);
}

#[tokio::test]
async fn aliases_to_s3_websites_other_zones_and_unchecked_services() {
    let mws = Mws::start().await;
    let r53 = Client::new(&mws.root_sdk_config().await);
    let z = zone(&r53, "site.example").await;
    let other = zone(&r53, "other.example").await;
    create(&r53, &other, plain("www.other.example", "192.0.2.9").build().unwrap()).await.unwrap();

    // S3 website endpoints, in their Region's zone.
    create(
        &r53,
        &z,
        alias("site.example", "Z3AQBSTGFYJSTF", "s3-website-us-east-1.amazonaws.com", false).build().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(answer(&r53, &z, "site.example").await, ["127.0.0.1"]);
    let err = create(
        &r53,
        &z,
        alias("blog.site.example", "Z3AQBSTGFYJSTF", "s3-website-us-west-2.amazonaws.com", false).build().unwrap(),
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("Tried to create an alias that targets s3-website-us-west-2.amazonaws.com., type A in zone Z3AQBSTGFYJSTF, but the alias target name does not lie within the target zone"),
        "{err}"
    );

    // Records in another of the account's zones.
    create(&r53, &z, alias("x.site.example", &other, "www.other.example", false).build().unwrap()).await.unwrap();
    assert_eq!(answer(&r53, &z, "x.site.example").await, ["192.0.2.9"]);
    let err = create(&r53, &z, alias("y.site.example", &other, "missing.other.example", false).build().unwrap())
        .await
        .unwrap_err();
    assert!(
        err.contains(&format!(
            "Tried to create an alias that targets missing.other.example., type A in zone {other}, but that target was not found"
        )),
        "{err}"
    );
    let err = create(&r53, &z, alias("y.site.example", &other, "elsewhere.example", false).build().unwrap())
        .await
        .unwrap_err();
    assert!(err.contains("but the alias target name does not lie within the target zone"), "{err}");

    // CloudFront isn't emulated: its targets go unchecked.
    create(
        &r53,
        &z,
        alias("cdn.site.example", "Z2FDTNDATAQYW2", "d111111abcdef8.cloudfront.net", false).build().unwrap(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn private_zone_vpcs_must_exist() {
    let mws = Mws::start().await;
    let conf = mws.root_sdk_config().await;
    let r53 = Client::new(&conf);
    let vpc = |id: &str| Vpc::builder().vpc_id(id).vpc_region(VpcRegion::UsEast1).build();

    let e = r53
        .create_hosted_zone()
        .name("corp.internal")
        .caller_reference("missing")
        .vpc(vpc("vpc-0123456789abcdef0"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("InvalidVPCId"));
    assert_eq!(
        e.message(),
        Some("The VPC: vpc-0123456789abcdef0 you provided is not authorized to make the association.")
    );

    let real = crate::route53::real_vpc(&conf, "us-east-1").await;
    let out =
        r53.create_hosted_zone().name("corp.internal").caller_reference("real").vpc(vpc(&real)).send().await.unwrap();
    let id = out.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();

    // The VPC must be in the Region named, too.
    let e = r53
        .associate_vpc_with_hosted_zone()
        .hosted_zone_id(&id)
        .vpc(Vpc::builder().vpc_id(&real).vpc_region(VpcRegion::UsWest2).build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("InvalidVPCId"));
    let west = crate::route53::real_vpc(&conf, "us-west-2").await;
    r53.associate_vpc_with_hosted_zone()
        .hosted_zone_id(&id)
        .vpc(Vpc::builder().vpc_id(&west).vpc_region(VpcRegion::UsWest2).build())
        .send()
        .await
        .unwrap();
}
