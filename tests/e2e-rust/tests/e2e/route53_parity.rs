//! Route 53 behaviour beyond the API shapes, through the official Rust SDK:
//! accounts kept apart, change batch validation for routing policies and
//! aliases, health checkers that really probe, and DNS answers that follow
//! routing policies, health, wildcards and delegations.

use std::time::Duration;

use aws_sdk_route53::error::ProvideErrorMetadata;
use aws_sdk_route53::types::{
    AliasTarget, Change, ChangeAction, ChangeBatch, CidrCollectionChange, CidrCollectionChangeAction,
    CidrRoutingConfig, GeoLocation, HealthCheckConfig, HealthCheckType, HostedZoneConfig, ResourceRecord,
    ResourceRecordSet, ResourceRecordSetFailover, RrType, Vpc, VpcRegion,
};
use aws_sdk_route53::Client;
use mws_e2e::{sts_config, user_with_policy, Mws};

const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;

fn rrset(name: &str, ty: RrType, values: &[&str]) -> aws_sdk_route53::types::builders::ResourceRecordSetBuilder {
    let mut b = ResourceRecordSet::builder().name(name).r#type(ty).ttl(60);
    for v in values {
        b = b.resource_records(ResourceRecord::builder().value(*v).build().unwrap());
    }
    b
}

fn batch(changes: Vec<(ChangeAction, ResourceRecordSet)>) -> ChangeBatch {
    let mut b = ChangeBatch::builder();
    for (action, set) in changes {
        b = b.changes(Change::builder().action(action).resource_record_set(set).build().unwrap());
    }
    b.build().unwrap()
}

async fn zone(r53: &Client, name: &str) -> String {
    let out = r53.create_hosted_zone().name(name).caller_reference(format!("ref-{name}")).send().await.unwrap();
    out.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string()
}

async fn change(r53: &Client, zone: &str, changes: Vec<(ChangeAction, ResourceRecordSet)>) -> Result<(), String> {
    r53.change_resource_record_sets()
        .hosted_zone_id(zone)
        .change_batch(batch(changes))
        .send()
        .await
        .map(|_| ())
        .map_err(|e| {
            let e = e.into_service_error();
            format!("{}: {}", e.code().unwrap_or_default(), e.message().unwrap_or_default())
        })
}

/// A minimal DNS client for the responder.
mod wire {
    pub fn query(name: &str, qtype: u16, edns: bool) -> Vec<u8> {
        let mut q = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, edns as u8];
        for label in name.trim_end_matches('.').split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        if edns {
            q.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
        }
        q
    }

    pub struct Reply {
        pub rcode: u8,
        pub aa: bool,
        pub tc: bool,
        /// `(type, ttl, rdata)` per section.
        pub answers: Vec<(u16, u32, Vec<u8>)>,
        pub authority: Vec<(u16, u32, Vec<u8>)>,
    }

    fn skip_name(m: &[u8], mut p: usize) -> usize {
        loop {
            let l = m[p] as usize;
            if l & 0xC0 == 0xC0 {
                return p + 2;
            }
            p += 1;
            if l == 0 {
                return p;
            }
            p += l;
        }
    }

    pub fn parse(m: &[u8]) -> Reply {
        let count = |i: usize| u16::from_be_bytes([m[i], m[i + 1]]) as usize;
        let mut p = skip_name(m, 12) + 4;
        let section = |n: usize, p: &mut usize| {
            (0..n)
                .map(|_| {
                    let at = skip_name(m, *p);
                    let ty = u16::from_be_bytes([m[at], m[at + 1]]);
                    let ttl = u32::from_be_bytes([m[at + 4], m[at + 5], m[at + 6], m[at + 7]]);
                    let len = u16::from_be_bytes([m[at + 8], m[at + 9]]) as usize;
                    *p = at + 10 + len;
                    (ty, ttl, m[at + 10..at + 10 + len].to_vec())
                })
                .collect::<Vec<_>>()
        };
        let answers = section(count(6), &mut p);
        let authority = section(count(8), &mut p);
        Reply { rcode: m[3] & 0x0f, aa: m[2] & 0x04 != 0, tc: m[2] & 0x02 != 0, answers, authority }
    }
}

fn ask(mws: &Mws, name: &str, qtype: u16) -> wire::Reply {
    wire::parse(&mws_route53::dns_answer(&mws.route53, &wire::query(name, qtype, false)).unwrap())
}

fn ipv4s(reply: &wire::Reply) -> Vec<String> {
    reply
        .answers
        .iter()
        .filter(|(t, _, _)| *t == 1)
        .map(|(_, _, d)| std::net::Ipv4Addr::new(d[0], d[1], d[2], d[3]).to_string())
        .collect()
}

/// Hosted zones and health checks belong to the account that created them.
#[tokio::test]
async fn accounts_keep_their_route53_resources_apart() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let orgs = aws_sdk_organizations::Client::new(&root);
    orgs.create_organization().send().await.unwrap();
    let created = orgs.create_account().email("dns@example.com").account_name("dns").send().await.unwrap();
    let request = created.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request).send().await.unwrap();
    let member_account = status.create_account_status().unwrap().account_id().unwrap().to_string();
    let (_, admin) = user_with_policy(&mws, "admin", Some(ADMIN)).await;
    let creds = aws_sdk_sts::Client::new(&admin)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{member_account}:role/OrganizationAccountAccessRole"))
        .role_session_name("dns")
        .send()
        .await
        .unwrap();
    let member = Client::new(&sts_config(&mws, creds.credentials().unwrap()).await);
    let owner = Client::new(&root);

    let vpc = |id: &str| Vpc::builder().vpc_id(id).vpc_region(VpcRegion::UsEast1).build();
    let private = owner
        .create_hosted_zone()
        .name("corp.internal")
        .caller_reference("corp")
        .vpc(vpc("vpc-0aaaaaaa"))
        .hosted_zone_config(HostedZoneConfig::builder().private_zone(true).build())
        .send()
        .await
        .unwrap();
    let private_id = private.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    let public_id = zone(&owner, "owner.example").await;

    // The member sees none of it, and touching it is denied.
    assert!(member.list_hosted_zones().send().await.unwrap().hosted_zones().is_empty());
    assert_eq!(member.get_hosted_zone_count().send().await.unwrap().hosted_zone_count(), 0);
    let denied = member.get_hosted_zone().id(&public_id).send().await.unwrap_err().into_service_error();
    assert_eq!(denied.code(), Some("AccessDenied"));
    assert!(denied.message().unwrap().ends_with("is not authorized to access this resource"), "{denied:?}");
    let err = change(
        &member,
        &public_id,
        vec![(ChangeAction::Create, rrset("x.owner.example", RrType::A, &["192.0.2.1"]).build().unwrap())],
    )
    .await
    .unwrap_err();
    assert!(err.starts_with("AccessDenied"), "{err}");
    let missing = member.get_hosted_zone().id("Z0000000000000000000X").send().await.unwrap_err().into_service_error();
    assert_eq!(missing.code(), Some("NoSuchHostedZone"));
    // Caller references are per account.
    member.create_hosted_zone().name("member.example").caller_reference("ref-owner.example").send().await.unwrap();
    assert_eq!(owner.get_hosted_zone_count().send().await.unwrap().hosted_zone_count(), 2);

    let hc = owner
        .create_health_check()
        .caller_reference("owner-hc")
        .health_check_config(
            HealthCheckConfig::builder().r#type(HealthCheckType::Calculated).child_health_checks("x").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let hc_id = hc.health_check().unwrap().id().to_string();
    assert!(member.list_health_checks().send().await.unwrap().health_checks().is_empty());
    let denied = member.get_health_check().health_check_id(&hc_id).send().await.unwrap_err().into_service_error();
    assert_eq!(denied.code(), Some("AccessDenied"));

    // Another account's VPC joins a private zone only once authorized.
    let unauthorized = member
        .associate_vpc_with_hosted_zone()
        .hosted_zone_id(&private_id)
        .vpc(vpc("vpc-0bbbbbbb"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(unauthorized.code(), Some("NotAuthorizedException"));
    owner
        .create_vpc_association_authorization()
        .hosted_zone_id(&private_id)
        .vpc(vpc("vpc-0bbbbbbb"))
        .send()
        .await
        .unwrap();
    member.associate_vpc_with_hosted_zone().hosted_zone_id(&private_id).vpc(vpc("vpc-0bbbbbbb")).send().await.unwrap();
    let listed =
        member.list_hosted_zones_by_vpc().vpc_id("vpc-0bbbbbbb").vpc_region(VpcRegion::UsEast1).send().await.unwrap();
    let summary = &listed.hosted_zone_summaries()[0];
    assert_eq!(summary.hosted_zone_id(), private_id);
    assert_eq!(summary.owner().unwrap().owning_account(), Some("123456789012"));
    member
        .disassociate_vpc_from_hosted_zone()
        .hosted_zone_id(&private_id)
        .vpc(vpc("vpc-0bbbbbbb"))
        .send()
        .await
        .unwrap();
    // The member may not remove the owner's own VPC.
    let denied = member
        .disassociate_vpc_from_hosted_zone()
        .hosted_zone_id(&private_id)
        .vpc(vpc("vpc-0aaaaaaa"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(denied.code(), Some("AccessDenied"));

    // Public DNS still answers from every account's zones.
    owner
        .change_resource_record_sets()
        .hosted_zone_id(&public_id)
        .change_batch(batch(vec![(
            ChangeAction::Create,
            rrset("www.owner.example", RrType::A, &["192.0.2.10"]).build().unwrap(),
        )]))
        .send()
        .await
        .unwrap();
    assert_eq!(ipv4s(&ask(&mws, "www.owner.example", 1)), ["192.0.2.10"]);
}

/// Change batches are checked the way Route 53 checks them.
#[tokio::test]
async fn change_batches_validate_routing_policies_aliases_and_values() {
    let mws = Mws::start().await;
    let r53 = Client::new(&mws.root_sdk_config().await);
    let z = zone(&r53, "rules.example").await;

    let weighted = |id: &str, w: i64, ip: &str| {
        rrset("w.rules.example", RrType::A, &[ip]).set_identifier(id).weight(w).build().unwrap()
    };
    let err = change(
        &r53,
        &z,
        vec![(ChangeAction::Create, rrset("w.rules.example", RrType::A, &["192.0.2.1"]).weight(1).build().unwrap())],
    )
    .await
    .unwrap_err();
    assert!(err.contains("Missing field 'SetIdentifier'"), "{err}");
    let err = change(
        &r53,
        &z,
        vec![(
            ChangeAction::Create,
            rrset("w.rules.example", RrType::A, &["192.0.2.1"]).set_identifier("x").build().unwrap(),
        )],
    )
    .await
    .unwrap_err();
    assert!(err.contains("Expected exactly one of [Weight, Region, Failover"), "{err}");
    change(
        &r53,
        &z,
        vec![
            (ChangeAction::Create, weighted("a", 1, "192.0.2.1")),
            (ChangeAction::Create, weighted("b", 1, "192.0.2.2")),
        ],
    )
    .await
    .unwrap();
    // A simple record set cannot join weighted ones, nor a latency one.
    let err = change(
        &r53,
        &z,
        vec![(ChangeAction::Create, rrset("w.rules.example", RrType::A, &["192.0.2.3"]).build().unwrap())],
    )
    .await
    .unwrap_err();
    assert!(err.starts_with("InvalidChangeBatch"), "{err}");
    let latency = rrset("w.rules.example", RrType::A, &["192.0.2.4"])
        .set_identifier("l")
        .region("us-east-1".into())
        .build()
        .unwrap();
    let err = change(&r53, &z, vec![(ChangeAction::Create, latency)]).await.unwrap_err();
    assert!(err.contains("cannot be created as a non-"), "{err}");

    // Two PRIMARY failover record sets.
    let primary = |id: &str| {
        rrset("f.rules.example", RrType::A, &["192.0.2.5"])
            .set_identifier(id)
            .failover(ResourceRecordSetFailover::Primary)
            .build()
            .unwrap()
    };
    let err = change(&r53, &z, vec![(ChangeAction::Create, primary("p1")), (ChangeAction::Create, primary("p2"))])
        .await
        .unwrap_err();
    assert!(err.starts_with("InvalidChangeBatch"), "{err}");

    // Aliases to the zone's own records need the target.
    let alias = |target: &str| {
        ResourceRecordSet::builder()
            .name("alias.rules.example")
            .r#type(RrType::A)
            .alias_target(
                AliasTarget::builder()
                    .hosted_zone_id(&z)
                    .dns_name(target)
                    .evaluate_target_health(false)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    };
    let err = change(&r53, &z, vec![(ChangeAction::Create, alias("missing.rules.example"))]).await.unwrap_err();
    assert!(err.contains("but that target was not found"), "{err}");
    let err = change(&r53, &z, vec![(ChangeAction::Create, alias("elsewhere.example"))]).await.unwrap_err();
    assert!(err.contains("does not lie within the target zone"), "{err}");
    change(&r53, &z, vec![(ChangeAction::Create, alias("w.rules.example"))]).await.unwrap();

    // Record values.
    for (ty, value, code) in [
        (RrType::Mx, "mail.rules.example", "MXRRDATANotTwoFields"),
        (RrType::Mx, "x mail.rules.example", "MXRRDATAIllegalPriority"),
        (RrType::Srv, "1 2 mail.rules.example", "SRVRRDATANotFourFields"),
        (RrType::Cname, "a..b", "DomainLabelEmpty"),
    ] {
        let err =
            change(&r53, &z, vec![(ChangeAction::Create, rrset("v.rules.example", ty, &[value]).build().unwrap())])
                .await
                .unwrap_err();
        assert!(err.contains(&format!("Invalid Resource Record: 'FATAL problem: {code}")), "{err}");
    }
    let long = format!("\"{}\"", "x".repeat(256));
    let err = change(
        &r53,
        &z,
        vec![(ChangeAction::Create, rrset("t.rules.example", RrType::Txt, &[&long]).build().unwrap())],
    )
    .await
    .unwrap_err();
    assert!(err.contains("TXTRDATATooLong"), "{err}");
    change(
        &r53,
        &z,
        vec![(ChangeAction::Create, rrset("v.rules.example", RrType::Mx, &["10 mail.rules.example"]).build().unwrap())],
    )
    .await
    .unwrap();
}

/// An HTTP server that answers every request with `status` and `body`.
async fn http_server(status: &'static str, body: &'static str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let reply =
                    format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = s.write_all(reply.as_bytes()).await;
            });
        }
    });
    port
}

/// A port nothing listens on.
async fn closed_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn health_check(r53: &Client, reference: &str, config: HealthCheckConfig) -> String {
    let out = r53.create_health_check().caller_reference(reference).health_check_config(config).send().await.unwrap();
    out.health_check().unwrap().id().to_string()
}

fn http_check(ty: HealthCheckType, port: u16) -> aws_sdk_route53::types::builders::HealthCheckConfigBuilder {
    HealthCheckConfig::builder()
        .r#type(ty)
        .ip_address("127.0.0.1")
        .port(port as i32)
        .request_interval(10)
        .failure_threshold(1)
}

/// Wait until the checkers report `prefix` for a health check.
async fn wait_for(r53: &Client, id: &str, prefix: &str) -> String {
    for _ in 0..80 {
        let status = r53.get_health_check_status().health_check_id(id).send().await.unwrap();
        if let Some(report) = status.health_check_observations().first().and_then(|o| o.status_report()?.status()) {
            if report.starts_with(prefix) {
                return report.to_string();
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("health check {id} never reported {prefix}");
}

/// Health checkers probe endpoints, and DNS answers follow them.
#[tokio::test]
async fn health_checks_probe_and_drive_failover() {
    let mws = Mws::start().await;
    let r53 = Client::new(&mws.root_sdk_config().await);
    let up = http_server("200 OK", "all systems go").await;
    let broken = http_server("503 Service Unavailable", "").await;
    let down = closed_port().await;

    let ok = health_check(
        &r53,
        "ok",
        http_check(HealthCheckType::HttpStrMatch, up).search_string("systems").build().unwrap(),
    )
    .await;
    let no_match = health_check(
        &r53,
        "nomatch",
        http_check(HealthCheckType::HttpStrMatch, up).search_string("absent").build().unwrap(),
    )
    .await;
    let error = health_check(&r53, "503", http_check(HealthCheckType::Http, broken).build().unwrap()).await;
    let refused = health_check(&r53, "down", http_check(HealthCheckType::Tcp, down).build().unwrap()).await;

    assert_eq!(wait_for(&r53, &ok, "Success").await, "Success: HTTP Status Code 200, OK");
    assert!(wait_for(&r53, &no_match, "Failure").await.contains("Failed to find the specified string"));
    assert!(wait_for(&r53, &error, "Failure").await.starts_with("Failure: HTTP Status Code 503, Service Unavailable"));
    wait_for(&r53, &refused, "Failure").await;
    let last = r53.get_health_check_last_failure_reason().health_check_id(&error).send().await.unwrap();
    assert_eq!(last.health_check_observations().len(), 8);

    // A calculated check needing both children.
    let calculated = health_check(
        &r53,
        "calc",
        HealthCheckConfig::builder()
            .r#type(HealthCheckType::Calculated)
            .child_health_checks(&ok)
            .child_health_checks(&error)
            .health_threshold(2)
            .build()
            .unwrap(),
    )
    .await;

    let z = zone(&r53, "failover.example").await;
    let role = |id: &str, ip: &str, role: ResourceRecordSetFailover, hc: Option<&str>| {
        rrset("app.failover.example", RrType::A, &[ip])
            .set_identifier(id)
            .failover(role)
            .set_health_check_id(hc.map(str::to_string))
            .build()
            .unwrap()
    };
    change(
        &r53,
        &z,
        vec![
            (ChangeAction::Create, role("primary", "192.0.2.1", ResourceRecordSetFailover::Primary, Some(&refused))),
            (ChangeAction::Create, role("secondary", "192.0.2.2", ResourceRecordSetFailover::Secondary, None)),
        ],
    )
    .await
    .unwrap();
    assert_eq!(ipv4s(&ask(&mws, "app.failover.example", 1)), ["192.0.2.2"]);
    let tested = r53
        .test_dns_answer()
        .hosted_zone_id(&z)
        .record_name("app.failover.example")
        .record_type(RrType::A)
        .send()
        .await
        .unwrap();
    assert_eq!(tested.record_data(), ["192.0.2.2"]);

    // Fix the primary: point it at the healthy server.
    r53.update_health_check().health_check_id(&refused).port(up as i32).send().await.unwrap();
    wait_for(&r53, &refused, "Success").await;
    assert_eq!(ipv4s(&ask(&mws, "app.failover.example", 1)), ["192.0.2.1"]);

    // Multivalue answers leave out unhealthy record sets; an inverted or
    // disabled check reads the other way.
    let mv = |id: &str, ip: &str, hc: &str| {
        rrset("mv.failover.example", RrType::A, &[ip])
            .set_identifier(id)
            .multi_value_answer(true)
            .health_check_id(hc)
            .build()
            .unwrap()
    };
    change(
        &r53,
        &z,
        vec![
            (ChangeAction::Create, mv("1", "192.0.2.11", &ok)),
            (ChangeAction::Create, mv("2", "192.0.2.12", &error)),
            (ChangeAction::Create, mv("3", "192.0.2.13", &calculated)),
        ],
    )
    .await
    .unwrap();
    assert_eq!(ipv4s(&ask(&mws, "mv.failover.example", 1)), ["192.0.2.11"]);
    // Inverting the failing child also satisfies the calculated check.
    r53.update_health_check().health_check_id(&error).inverted(true).send().await.unwrap();
    let mut all = ipv4s(&ask(&mws, "mv.failover.example", 1));
    all.sort();
    assert_eq!(all, ["192.0.2.11", "192.0.2.12", "192.0.2.13"]);
}

/// The responder answers like an authoritative Route 53 name server.
#[tokio::test]
async fn dns_answers_follow_routing_and_the_dns_rules() {
    let mws = Mws::start().await;
    let r53 = Client::new(&mws.root_sdk_config().await);
    let z = zone(&r53, "dns.example").await;
    let collection = r53.create_cidr_collection().name("offices").caller_reference("offices").send().await.unwrap();
    let collection_id = collection.collection().unwrap().id().unwrap().to_string();
    r53.change_cidr_collection()
        .id(&collection_id)
        .changes(
            CidrCollectionChange::builder()
                .location_name("london")
                .action(CidrCollectionChangeAction::Put)
                .cidr_list("198.51.100.0/24")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let cidr = |id: &str, location: &str, ip: &str| {
        rrset("office.dns.example", RrType::A, &[ip])
            .set_identifier(id)
            .cidr_routing_config(
                CidrRoutingConfig::builder().collection_id(&collection_id).location_name(location).build().unwrap(),
            )
            .build()
            .unwrap()
    };
    let geo = |id: &str, country: &str, ip: &str| {
        rrset("geo.dns.example", RrType::A, &[ip])
            .set_identifier(id)
            .geo_location(GeoLocation::builder().country_code(country).build())
            .build()
            .unwrap()
    };
    let weighted = |id: &str, w: i64, ip: &str| {
        rrset("w.dns.example", RrType::A, &[ip]).set_identifier(id).weight(w).build().unwrap()
    };
    let many: Vec<String> = (1..=40).map(|i| format!("192.0.2.{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    change(
        &r53,
        &z,
        vec![
            (ChangeAction::Create, rrset("*.dns.example", RrType::A, &["192.0.2.100"]).build().unwrap()),
            (ChangeAction::Create, rrset("a.b.c.dns.example", RrType::Txt, &["\"deep\""]).build().unwrap()),
            (ChangeAction::Create, rrset("www.dns.example", RrType::Cname, &["web.dns.example"]).build().unwrap()),
            (ChangeAction::Create, rrset("web.dns.example", RrType::A, &["192.0.2.80"]).build().unwrap()),
            (ChangeAction::Create, rrset("sub.dns.example", RrType::Ns, &["ns1.elsewhere.example."]).build().unwrap()),
            (ChangeAction::Create, rrset("caa.dns.example", RrType::Caa, &["0 issue \"amazon.com\""]).build().unwrap()),
            (ChangeAction::Create, rrset("big.dns.example", RrType::A, &many).build().unwrap()),
            (ChangeAction::Create, cidr("london", "london", "192.0.2.51")),
            (ChangeAction::Create, cidr("default", "*", "192.0.2.52")),
            (ChangeAction::Create, geo("de", "DE", "192.0.2.61")),
            (ChangeAction::Create, geo("default", "*", "192.0.2.62")),
            (ChangeAction::Create, weighted("never", 0, "192.0.2.71")),
            (ChangeAction::Create, weighted("always", 5, "192.0.2.72")),
        ],
    )
    .await
    .unwrap();

    // Wildcards match any depth below their closest encloser.
    assert_eq!(ipv4s(&ask(&mws, "x.y.dns.example", 1)), ["192.0.2.100"]);
    // `b.c.dns.example` only has names below it: NODATA with the SOA.
    let ent = ask(&mws, "b.c.dns.example", 1);
    assert_eq!((ent.rcode, ent.answers.len()), (0, 0));
    assert_eq!(ent.authority[0].0, 6);
    assert_eq!(ent.authority[0].1, 900, "negative TTL is the lower of the SOA TTL and minimum");
    // A wildcard below an existing name does not apply above it.
    let nx = ask(&mws, "q.c.dns.example", 1);
    assert_eq!((nx.rcode, nx.aa, nx.authority[0].0), (3, true, 6));
    // CNAMEs inside the zone are followed.
    let www = ask(&mws, "www.dns.example", 1);
    assert_eq!(www.answers.iter().map(|a| a.0).collect::<Vec<_>>(), [5, 1]);
    assert_eq!(ipv4s(&www), ["192.0.2.80"]);
    // Delegated subdomains refer.
    let referral = ask(&mws, "host.sub.dns.example", 1);
    assert_eq!((referral.rcode, referral.aa, referral.answers.len(), referral.authority[0].0), (0, false, 0, 2));
    assert_eq!(ask(&mws, "caa.dns.example", 257).answers[0].2, b"\x00\x05issueamazon.com");
    // Too big for plain UDP: truncated; with EDNS it fits.
    assert!(ask(&mws, "big.dns.example", 1).tc);
    let edns = wire::parse(&mws_route53::dns_answer(&mws.route53, &wire::query("big.dns.example", 1, true)).unwrap());
    assert_eq!((edns.tc, edns.answers.len()), (false, 40));

    // Routing: zero weights lose to positive ones, geolocation answers from
    // the default location, IP-based routing matches the resolver.
    for _ in 0..10 {
        assert_eq!(ipv4s(&ask(&mws, "w.dns.example", 1)), ["192.0.2.72"]);
    }
    assert_eq!(ipv4s(&ask(&mws, "geo.dns.example", 1)), ["192.0.2.62"]);
    let from = |ip: &str| {
        let q = wire::query("office.dns.example", 1, false);
        ipv4s(&wire::parse(&mws_route53::dns_answer_from(&mws.route53, &q, Some(ip.parse().unwrap())).unwrap()))
    };
    assert_eq!(from("198.51.100.7"), ["192.0.2.51"]);
    assert_eq!(from("203.0.113.7"), ["192.0.2.52"]);
    let tested = r53
        .test_dns_answer()
        .hosted_zone_id(&z)
        .record_name("office.dns.example")
        .record_type(RrType::A)
        .resolver_ip("198.51.100.9")
        .send()
        .await
        .unwrap();
    assert_eq!(tested.record_data(), ["192.0.2.51"]);

    // The responder also speaks TCP.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(mws_route53::serve_dns_tcp(mws.route53.clone(), listener));
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let q = wire::query("big.dns.example", 1, false);
    s.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
    s.write_all(&q).await.unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await.unwrap();
    let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(wire::parse(&reply).answers.len(), 40);
}
