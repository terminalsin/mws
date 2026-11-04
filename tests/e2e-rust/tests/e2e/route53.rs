//! Route 53 through the official Rust SDK.

use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, HealthCheckConfig, HealthCheckType, HostedZoneConfig, ResourceRecord,
    ResourceRecordSet, RrType, Tag, TagResourceType, Vpc, VpcRegion,
};
use aws_sdk_route53::Client;
use mws_e2e::{user_with_policy, Mws};

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn rrset(name: &str, ty: RrType, ttl: i64, values: &[&str]) -> ResourceRecordSet {
    let mut b = ResourceRecordSet::builder().name(name).r#type(ty).ttl(ttl);
    for v in values {
        b = b.resource_records(ResourceRecord::builder().value(*v).build().unwrap());
    }
    b.build().unwrap()
}

fn change(action: ChangeAction, set: ResourceRecordSet) -> Change {
    Change::builder().action(action).resource_record_set(set).build().unwrap()
}

async fn create_zone(r53: &Client, name: &str) -> String {
    let out = r53
        .create_hosted_zone()
        .name(name)
        .caller_reference(format!("ref-{name}"))
        .hosted_zone_config(HostedZoneConfig::builder().comment("e2e").build())
        .send()
        .await
        .unwrap();
    out.hosted_zone().unwrap().id().to_string()
}

#[tokio::test]
async fn hosted_zone_lifecycle() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;

    let out = r53.create_hosted_zone().name("Example.com").caller_reference("r1").send().await.unwrap();
    let zone = out.hosted_zone().unwrap();
    assert!(zone.id().starts_with("/hostedzone/Z"));
    assert_eq!(zone.name(), "example.com.");
    assert_eq!(zone.resource_record_set_count(), Some(2));
    assert_eq!(out.delegation_set().unwrap().name_servers().len(), 4);
    assert_eq!(out.change_info().unwrap().status().as_str(), "PENDING");
    assert!(out.location().ends_with(zone.id()));

    let dup = r53.create_hosted_zone().name("other.com").caller_reference("r1").send().await.unwrap_err();
    assert_eq!(dup.into_service_error().meta().code(), Some("HostedZoneAlreadyExists"));

    // The SDK strips the /hostedzone/ prefix from ids it sends.
    let got = r53.get_hosted_zone().id(zone.id()).send().await.unwrap();
    assert_eq!(got.hosted_zone().unwrap().name(), "example.com.");
    assert_eq!(r53.get_hosted_zone_count().send().await.unwrap().hosted_zone_count(), 1);

    let change_id = out.change_info().unwrap().id();
    let change = r53.get_change().id(change_id).send().await.unwrap();
    assert_eq!(change.change_info().unwrap().status().as_str(), "INSYNC");

    let listed = r53.list_hosted_zones().send().await.unwrap();
    assert_eq!(listed.hosted_zones().len(), 1);
    assert!(!listed.is_truncated());

    let updated = r53.update_hosted_zone_comment().id(zone.id()).comment("hello").send().await.unwrap();
    assert_eq!(updated.hosted_zone().unwrap().config().unwrap().comment(), Some("hello"));

    r53.delete_hosted_zone().id(zone.id()).send().await.unwrap();
    let err = r53.get_hosted_zone().id(zone.id()).send().await.unwrap_err().into_service_error();
    assert!(err.is_no_such_hosted_zone(), "{err:?}");
    assert!(err.meta().message().unwrap().starts_with("No hosted zone found with ID: Z"));
}

#[tokio::test]
async fn record_sets_change_atomically_and_list_in_route53_order() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let zone = create_zone(&r53, "example.com").await;

    let batch = ChangeBatch::builder()
        .changes(change(ChangeAction::Create, rrset("www.example.com", RrType::A, 60, &["192.0.2.1", "192.0.2.2"])))
        .changes(change(ChangeAction::Create, rrset("*.example.com", RrType::Txt, 300, &["\"hi\""])))
        .changes(change(ChangeAction::Create, rrset("api.example.com", RrType::Cname, 60, &["www.example.com"])))
        .build()
        .unwrap();
    let out = r53.change_resource_record_sets().hosted_zone_id(&zone).change_batch(batch).send().await.unwrap();
    assert_eq!(out.change_info().unwrap().status().as_str(), "PENDING");

    let sets = r53.list_resource_record_sets().hosted_zone_id(&zone).send().await.unwrap();
    let names: Vec<(String, String)> =
        sets.resource_record_sets().iter().map(|r| (r.name().to_string(), r.r#type().as_str().to_string())).collect();
    assert_eq!(
        names,
        [
            ("example.com.", "NS"),
            ("example.com.", "SOA"),
            ("\\052.example.com.", "TXT"),
            ("api.example.com.", "CNAME"),
            ("www.example.com.", "A"),
        ]
        .map(|(a, b)| (a.to_string(), b.to_string()))
    );

    // One bad change rejects the whole batch, with Route 53's messages.
    let batch = ChangeBatch::builder()
        .changes(change(ChangeAction::Create, rrset("new.example.com", RrType::A, 60, &["192.0.2.9"])))
        .changes(change(ChangeAction::Create, rrset("www.example.com", RrType::A, 60, &["192.0.2.1"])))
        .changes(change(ChangeAction::Delete, rrset("gone.example.com", RrType::A, 60, &["192.0.2.1"])))
        .changes(change(ChangeAction::Create, rrset("api.example.com", RrType::Txt, 60, &["\"x\""])))
        .build()
        .unwrap();
    let err = r53
        .change_resource_record_sets()
        .hosted_zone_id(&zone)
        .change_batch(batch)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    let aws_sdk_route53::operation::change_resource_record_sets::ChangeResourceRecordSetsError::InvalidChangeBatch(e) =
        err
    else {
        panic!("expected InvalidChangeBatch, got {err:?}");
    };
    assert_eq!(
        e.messages(),
        [
            "Tried to create resource record set [name='www.example.com.', type='A'] but it already exists",
            "Tried to delete resource record set [name='gone.example.com.', type='A'] but it was not found",
            "RRSet of type TXT with DNS name api.example.com. is not permitted because a conflicting RRSet of type CNAME with the same DNS name already exists in zone example.com.",
        ]
    );
    let count = r53.get_hosted_zone().id(&zone).send().await.unwrap();
    assert_eq!(count.hosted_zone().unwrap().resource_record_set_count(), Some(5), "batch was not applied");

    // UPSERT replaces; DELETE must match the current values.
    let batch = ChangeBatch::builder()
        .changes(change(ChangeAction::Upsert, rrset("www.example.com", RrType::A, 120, &["198.51.100.7"])))
        .build()
        .unwrap();
    r53.change_resource_record_sets().hosted_zone_id(&zone).change_batch(batch).send().await.unwrap();
    let page = r53
        .list_resource_record_sets()
        .hosted_zone_id(&zone)
        .start_record_name("www.example.com")
        .start_record_type(RrType::A)
        .max_items(1)
        .send()
        .await
        .unwrap();
    let www = &page.resource_record_sets()[0];
    assert_eq!(www.ttl(), Some(120));
    assert_eq!(www.resource_records()[0].value(), "198.51.100.7");

    let stale = ChangeBatch::builder()
        .changes(change(ChangeAction::Delete, rrset("www.example.com", RrType::A, 60, &["192.0.2.1"])))
        .build()
        .unwrap();
    let err = r53.change_resource_record_sets().hosted_zone_id(&zone).change_batch(stale).send().await.unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("InvalidChangeBatch"));

    // A zone with records cannot be deleted.
    let err = r53.delete_hosted_zone().id(&zone).send().await.unwrap_err().into_service_error();
    assert!(err.is_hosted_zone_not_empty(), "{err:?}");
}

#[tokio::test]
async fn pagination_and_validation() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let zone = create_zone(&r53, "pages.test").await;
    let mut batch = ChangeBatch::builder();
    for i in 0..7 {
        batch = batch
            .changes(change(ChangeAction::Create, rrset(&format!("h{i}.pages.test"), RrType::A, 60, &["10.0.0.1"])));
    }
    r53.change_resource_record_sets().hosted_zone_id(&zone).change_batch(batch.build().unwrap()).send().await.unwrap();

    let mut seen = 0;
    let mut start: Option<(String, RrType)> = None;
    loop {
        let mut req = r53.list_resource_record_sets().hosted_zone_id(&zone).max_items(3);
        if let Some((n, t)) = &start {
            req = req.start_record_name(n).start_record_type(t.clone());
        }
        let page = req.send().await.unwrap();
        seen += page.resource_record_sets().len();
        if !page.is_truncated() {
            break;
        }
        start = Some((page.next_record_name().unwrap().into(), page.next_record_type().unwrap().clone()));
    }
    assert_eq!(seen, 9);

    // Model constraints come back as InvalidInput with AWS's wording.
    let err = r53.get_hosted_zone().id("Z".repeat(40)).send().await.unwrap_err().into_service_error();
    assert_eq!(err.meta().code(), Some("InvalidInput"));
    assert_eq!(
        err.meta().message(),
        Some(format!("1 validation error detected: Value '{}' at 'id' failed to satisfy constraint: Member must have length less than or equal to 32", "Z".repeat(40)).as_str())
    );

    let bad = ChangeBatch::builder()
        .changes(change(ChangeAction::Create, rrset("x.other.test", RrType::A, 60, &["10.0.0.1"])))
        .changes(change(ChangeAction::Create, rrset("y.pages.test", RrType::A, 60, &["not-an-ip"])))
        .build()
        .unwrap();
    let err = r53.change_resource_record_sets().hosted_zone_id(&zone).change_batch(bad).send().await.unwrap_err();
    let msg = err.into_service_error().meta().message().unwrap().to_string();
    assert!(msg.contains("RRSet with DNS name x.other.test. is not permitted in zone pages.test."), "{msg}");
    assert!(msg.contains("ARRDATAIllegalIPv4Address"), "{msg}");
}

#[tokio::test]
async fn private_zones_health_checks_and_tags() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let vpc = Vpc::builder().vpc_id("vpc-0abc1234").vpc_region(VpcRegion::UsEast1).build();
    let out =
        r53.create_hosted_zone().name("internal.corp").caller_reference("p1").vpc(vpc.clone()).send().await.unwrap();
    let zone_id = out.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    assert!(out.hosted_zone().unwrap().config().unwrap().private_zone());
    let by_vpc =
        r53.list_hosted_zones_by_vpc().vpc_id("vpc-0abc1234").vpc_region(VpcRegion::UsEast1).send().await.unwrap();
    assert_eq!(by_vpc.hosted_zone_summaries()[0].hosted_zone_id(), zone_id);
    let err =
        r53.disassociate_vpc_from_hosted_zone().hosted_zone_id(&zone_id).vpc(vpc.clone()).send().await.unwrap_err();
    assert!(err.into_service_error().is_last_vpc_association());

    // A second VPC can be associated and disassociated again.
    let second = Vpc::builder().vpc_id("vpc-0def5678").vpc_region(VpcRegion::UsWest2).build();
    let change = r53
        .associate_vpc_with_hosted_zone()
        .hosted_zone_id(&zone_id)
        .vpc(second.clone())
        .comment("west")
        .send()
        .await
        .unwrap();
    assert!(change.change_info().unwrap().id().starts_with("/change/"));
    let dup = r53.associate_vpc_with_hosted_zone().hosted_zone_id(&zone_id).vpc(second.clone()).send().await;
    assert!(dup.unwrap_err().into_service_error().is_conflicting_domain_exists());
    let zone = r53.get_hosted_zone().id(&zone_id).send().await.unwrap();
    assert_eq!(zone.vpcs().len(), 2);
    let by_vpc =
        r53.list_hosted_zones_by_vpc().vpc_id("vpc-0def5678").vpc_region(VpcRegion::UsWest2).send().await.unwrap();
    assert_eq!(by_vpc.hosted_zone_summaries().len(), 1);
    r53.disassociate_vpc_from_hosted_zone().hosted_zone_id(&zone_id).vpc(second.clone()).send().await.unwrap();
    let not_associated = r53.disassociate_vpc_from_hosted_zone().hosted_zone_id(&zone_id).vpc(second).send().await;
    assert!(not_associated.unwrap_err().into_service_error().is_vpc_association_not_found());
    let public = create_zone(&r53, "public.corp").await;
    let public_id = public.trim_start_matches("/hostedzone/");
    let not_private = r53.associate_vpc_with_hosted_zone().hosted_zone_id(public_id).vpc(vpc).send().await;
    assert!(not_private.unwrap_err().into_service_error().is_public_zone_vpc_association());

    let hc = r53
        .create_health_check()
        .caller_reference("hc1")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Https)
                .fully_qualified_domain_name("example.com")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let hc = hc.health_check().unwrap();
    assert_eq!(hc.health_check_config().unwrap().port(), Some(443));
    assert_eq!(hc.health_check_version(), 1);
    let updated = r53.update_health_check().health_check_id(hc.id()).failure_threshold(5).send().await.unwrap();
    assert_eq!(updated.health_check().unwrap().health_check_version(), 2);
    assert_eq!(r53.list_health_checks().send().await.unwrap().health_checks().len(), 1);
    assert_eq!(r53.get_health_check_count().send().await.unwrap().health_check_count(), 1);

    r53.change_tags_for_resource()
        .resource_type(TagResourceType::Hostedzone)
        .resource_id(&zone_id)
        .add_tags(Tag::builder().key("env").value("dev").build())
        .add_tags(Tag::builder().key("team").value("dns").build())
        .send()
        .await
        .unwrap();
    r53.change_tags_for_resource()
        .resource_type(TagResourceType::Hostedzone)
        .resource_id(&zone_id)
        .remove_tag_keys("team")
        .send()
        .await
        .unwrap();
    let tags = r53
        .list_tags_for_resource()
        .resource_type(TagResourceType::Hostedzone)
        .resource_id(&zone_id)
        .send()
        .await
        .unwrap();
    let tags = tags.resource_tag_set().unwrap().tags();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].key(), Some("env"));
    r53.change_tags_for_resource()
        .resource_type(TagResourceType::Healthcheck)
        .resource_id(hc.id())
        .add_tags(Tag::builder().key("probe").value("https").build())
        .send()
        .await
        .unwrap();
    let many = r53
        .list_tags_for_resources()
        .resource_type(TagResourceType::Healthcheck)
        .resource_ids(hc.id())
        .resource_ids("00000000-0000-0000-0000-000000000000")
        .send()
        .await;
    assert!(many.unwrap_err().into_service_error().is_no_such_health_check());
    let many = r53
        .list_tags_for_resources()
        .resource_type(TagResourceType::Healthcheck)
        .resource_ids(hc.id())
        .send()
        .await
        .unwrap();
    let set = &many.resource_tag_sets()[0];
    assert_eq!(set.resource_id(), Some(hc.id()));
    assert_eq!(set.tags()[0].key(), Some("probe"));

    r53.delete_health_check().health_check_id(hc.id()).send().await.unwrap();
    assert_eq!(r53.get_health_check_count().send().await.unwrap().health_check_count(), 0);
    let err = r53.get_health_check().health_check_id(hc.id()).send().await.unwrap_err();
    assert!(err.into_service_error().is_no_such_health_check());
}

#[tokio::test]
async fn iam_policies_govern_route53() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let allowed = create_zone(&r53, "allowed.test").await;
    let other = create_zone(&r53, "other.test").await;
    let allowed_id = allowed.trim_start_matches("/hostedzone/");

    // May only manage A records under the allowed zone.
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["route53:ListHostedZones", "route53:GetHostedZone"], "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "route53:ChangeResourceRecordSets",
                "Resource": format!("arn:aws:route53:::hostedzone/{allowed_id}"),
                "Condition": {"ForAllValues:StringEquals": {"route53:ChangeResourceRecordSetsRecordTypes": ["A"]}}
            }
        ]
    })
    .to_string();
    let (_, cfg) = user_with_policy(&mws, "dns-operator", Some(&policy)).await;
    let user = Client::new(&cfg);

    assert_eq!(user.list_hosted_zones().send().await.unwrap().hosted_zones().len(), 2);
    let a = || {
        ChangeBatch::builder()
            .changes(change(
                ChangeAction::Create,
                rrset(&format!("a.{}", "allowed.test"), RrType::A, 60, &["10.1.1.1"]),
            ))
            .build()
            .unwrap()
    };
    user.change_resource_record_sets().hosted_zone_id(&allowed).change_batch(a()).send().await.unwrap();

    let txt = ChangeBatch::builder()
        .changes(change(ChangeAction::Create, rrset("t.allowed.test", RrType::Txt, 60, &["\"x\""])))
        .build()
        .unwrap();
    let err = user.change_resource_record_sets().hosted_zone_id(&allowed).change_batch(txt).send().await.unwrap_err();
    let err = err.into_service_error();
    assert_eq!(err.meta().code(), Some("AccessDenied"));
    assert!(err.meta().message().unwrap().contains("is not authorized to perform: route53:ChangeResourceRecordSets"));

    let err = user.change_resource_record_sets().hosted_zone_id(&other).change_batch(a()).send().await.unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("AccessDenied"));
    let err = user.delete_hosted_zone().id(&allowed).send().await.unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("AccessDenied"));
}

/// Records created through the API resolve through the DNS responder.
#[tokio::test]
async fn dns_responder_serves_records() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let zone = create_zone(&r53, "dns.test").await;
    let alias = ResourceRecordSet::builder()
        .name("alias.dns.test")
        .r#type(RrType::A)
        .alias_target(
            aws_sdk_route53::types::AliasTarget::builder()
                .hosted_zone_id(zone.trim_start_matches("/hostedzone/"))
                .dns_name("www.dns.test")
                .evaluate_target_health(false)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let batch = ChangeBatch::builder()
        .changes(change(ChangeAction::Create, rrset("www.dns.test", RrType::A, 30, &["203.0.113.5"])))
        .changes(change(ChangeAction::Create, alias))
        .build()
        .unwrap();
    r53.change_resource_record_sets().hosted_zone_id(&zone).change_batch(batch).send().await.unwrap();

    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(mws_route53::serve_dns(mws.route53.clone(), server));
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    async fn query(client: &tokio::net::UdpSocket, addr: std::net::SocketAddr, name: &str) -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        client.send_to(&q, addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf)).await.unwrap().unwrap();
        buf[..n].to_vec()
    }

    for name in ["www.dns.test", "alias.dns.test"] {
        let reply = query(&client, addr, name).await;
        assert_eq!(&reply[0..2], &[0xab, 0xcd]);
        assert_eq!(reply[3] & 0x0f, 0, "NOERROR for {name}");
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1, "one answer for {name}");
        assert_eq!(&reply[reply.len() - 4..], &[203, 0, 113, 5]);
    }
    let reply = query(&client, addr, "nope.dns.test").await;
    assert_eq!(reply[3] & 0x0f, 3, "NXDOMAIN");
}
