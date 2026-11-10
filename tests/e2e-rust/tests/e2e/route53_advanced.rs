//! Route 53 beyond zones and records: delegation sets, traffic policies,
//! DNSSEC, CIDR collections, query logging, VPC authorizations, limits,
//! the geolocation catalogue, TestDNSAnswer and health check status.

use aws_sdk_route53::types::{
    AccountLimitType, CidrCollectionChange, CidrCollectionChangeAction, HealthCheckConfig, HealthCheckType,
    HostedZoneConfig, HostedZoneLimitType, ReusableDelegationSetLimitType, RrType, Vpc, VpcRegion,
};
use aws_sdk_route53::Client;
use base64::Engine;
use mws_e2e::Mws;

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: aws_sdk_route53::error::ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

/// A KMS key Route 53 can use for DNSSEC: ECC_NIST_P256 signing, with a key
/// policy that lets the DNSSEC service principal use it.
async fn dnssec_kms_key(mws: &Mws, allow_route53: bool) -> String {
    let kms = aws_sdk_kms::Client::new(&mws.root_sdk_config().await);
    let mut statements = vec![serde_json::json!({
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
        "Action": "kms:*",
        "Resource": "*"
    })];
    if allow_route53 {
        statements.push(serde_json::json!({
            "Sid": "Allow Route 53 DNSSEC Service",
            "Effect": "Allow",
            "Principal": {"Service": "dnssec-route53.amazonaws.com"},
            "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}}
        }));
    }
    let policy = serde_json::json!({"Version": "2012-10-17", "Statement": statements}).to_string();
    let key = kms
        .create_key()
        .key_spec(aws_sdk_kms::types::KeySpec::EccNistP256)
        .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
        .policy(policy)
        .send()
        .await
        .unwrap();
    key.key_metadata().unwrap().arn().unwrap().to_string()
}

#[tokio::test]
async fn reusable_delegation_sets() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let set = r53.create_reusable_delegation_set().caller_reference("ds-1").send().await.unwrap();
    let set = set.delegation_set().unwrap();
    let set_id = set.id().unwrap().trim_start_matches("/delegationset/").to_string();
    assert_eq!(set.name_servers().len(), 4);

    let dup = r53.create_reusable_delegation_set().caller_reference("ds-1").send().await.unwrap_err();
    assert_eq!(code(dup.into_service_error()), "DelegationSetAlreadyCreated");

    let mut zone_ids = Vec::new();
    for name in ["a.example.com", "b.example.com"] {
        let z =
            r53.create_hosted_zone().name(name).caller_reference(name).delegation_set_id(&set_id).send().await.unwrap();
        assert_eq!(z.delegation_set().unwrap().name_servers(), set.name_servers());
        zone_ids.push(z.hosted_zone().unwrap().id().to_string());
    }
    let listed = r53.list_hosted_zones().delegation_set_id(&set_id).send().await.unwrap();
    assert_eq!(listed.hosted_zones().len(), 2);
    let other = r53.create_reusable_delegation_set().caller_reference("ds-2").send().await.unwrap();
    let sets = r53.list_reusable_delegation_sets().send().await.unwrap();
    let ids: Vec<_> = sets.delegation_sets().iter().filter_map(|d| d.id()).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().any(|i| i.ends_with(&set_id)));
    let page = r53.list_reusable_delegation_sets().max_items(1).send().await.unwrap();
    assert!(page.is_truncated());
    assert_eq!(page.delegation_sets().len(), 1);
    let rest = r53.list_reusable_delegation_sets().marker(page.next_marker().unwrap()).send().await.unwrap();
    assert_eq!(rest.delegation_sets().len(), 1);
    assert!(!rest.is_truncated());
    r53.delete_reusable_delegation_set().id(other.delegation_set().unwrap().id().unwrap()).send().await.unwrap();
    let limit = r53
        .get_reusable_delegation_set_limit()
        .delegation_set_id(&set_id)
        .r#type(ReusableDelegationSetLimitType::MaxZonesByReusableDelegationSet)
        .send()
        .await
        .unwrap();
    assert_eq!((limit.count(), limit.limit().unwrap().value()), (2, 100));

    let in_use = r53.delete_reusable_delegation_set().id(&set_id).send().await.unwrap_err();
    assert_eq!(code(in_use.into_service_error()), "DelegationSetInUse");
    for id in &zone_ids {
        r53.delete_hosted_zone().id(id).send().await.unwrap();
    }
    r53.delete_reusable_delegation_set().id(&set_id).send().await.unwrap();
    let gone = r53.get_reusable_delegation_set().id(&set_id).send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "NoSuchDelegationSet");
}

const POLICY: &str = r#"{
    "AWSPolicyFormatVersion": "2015-10-01",
    "RecordType": "A",
    "StartRule": "site",
    "Endpoints": {
        "primary": {"Type": "value", "Value": "192.0.2.10"},
        "secondary": {"Type": "value", "Value": "192.0.2.20"}
    },
    "Rules": {
        "site": {"RuleType": "failover", "Primary": {"EndpointReference": "primary"}, "Secondary": {"EndpointReference": "secondary"}}
    }
}"#;

#[tokio::test]
async fn traffic_policies_and_instances() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let bad = r53.create_traffic_policy().name("bad").document("{}").send().await.unwrap_err();
    assert_eq!(code(bad.into_service_error()), "InvalidTrafficPolicyDocument");

    let created = r53.create_traffic_policy().name("site").document(POLICY).comment("v1").send().await.unwrap();
    let policy = created.traffic_policy().unwrap();
    let pid = policy.id().to_string();
    assert_eq!((policy.version(), policy.r#type()), (1, &RrType::A));
    let v2 = r53
        .create_traffic_policy_version()
        .id(&pid)
        .document(POLICY.replace("192.0.2.20", "192.0.2.30"))
        .send()
        .await
        .unwrap();
    assert_eq!(v2.traffic_policy().unwrap().version(), 2);
    let summaries = r53.list_traffic_policies().send().await.unwrap();
    let s = &summaries.traffic_policy_summaries()[0];
    assert_eq!((s.latest_version(), s.traffic_policy_count()), (2, 2));
    r53.update_traffic_policy_comment().id(&pid).version(1).comment("first").send().await.unwrap();
    let v1 = r53.get_traffic_policy().id(&pid).version(1).send().await.unwrap();
    assert_eq!(v1.traffic_policy().unwrap().comment(), Some("first"));

    let zone = r53.create_hosted_zone().name("tp.example.com").caller_reference("tp").send().await.unwrap();
    let zone_id = zone.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    let inst = r53
        .create_traffic_policy_instance()
        .hosted_zone_id(&zone_id)
        .name("www.tp.example.com")
        .ttl(60)
        .traffic_policy_id(&pid)
        .traffic_policy_version(1)
        .send()
        .await
        .unwrap();
    let inst = inst.traffic_policy_instance().unwrap();
    let iid = inst.id().to_string();
    assert_eq!(inst.state(), "Applied");

    let records = r53.list_resource_record_sets().hosted_zone_id(&zone_id).send().await.unwrap();
    let managed: Vec<_> = records
        .resource_record_sets()
        .iter()
        .filter(|r| r.traffic_policy_instance_id() == Some(iid.as_str()))
        .collect();
    assert_eq!(managed.len(), 2);
    assert!(managed.iter().any(|r| r.resource_records()[0].value() == "192.0.2.20"));

    r53.update_traffic_policy_instance()
        .id(&iid)
        .ttl(30)
        .traffic_policy_id(&pid)
        .traffic_policy_version(2)
        .send()
        .await
        .unwrap();
    let records = r53.list_resource_record_sets().hosted_zone_id(&zone_id).send().await.unwrap();
    assert!(records
        .resource_record_sets()
        .iter()
        .any(|r| r.resource_records().first().map(|v| v.value()) == Some("192.0.2.30")));

    let got = r53.get_traffic_policy_instance().id(&iid).send().await.unwrap();
    let got = got.traffic_policy_instance().unwrap();
    assert_eq!((got.ttl(), got.traffic_policy_version()), (30, 2));
    assert_eq!(got.name(), "www.tp.example.com.");
    let all = r53.list_traffic_policy_instances().send().await.unwrap();
    assert_eq!(all.traffic_policy_instances().len(), 1);
    assert!(!all.is_truncated());
    let by_policy = r53
        .list_traffic_policy_instances_by_policy()
        .traffic_policy_id(&pid)
        .traffic_policy_version(2)
        .send()
        .await
        .unwrap();
    assert_eq!(by_policy.traffic_policy_instances().len(), 1);
    let none = r53
        .list_traffic_policy_instances_by_policy()
        .traffic_policy_id(&pid)
        .traffic_policy_version(1)
        .send()
        .await
        .unwrap();
    assert!(none.traffic_policy_instances().is_empty());
    let versions = r53.list_traffic_policy_versions().id(&pid).send().await.unwrap();
    let numbers: Vec<_> = versions.traffic_policies().iter().map(|p| p.version()).collect();
    assert_eq!(numbers, [1, 2]);
    let missing = r53.get_traffic_policy_instance().id("00000000-0000-0000-0000-000000000000").send().await;
    assert_eq!(code(missing.unwrap_err().into_service_error()), "NoSuchTrafficPolicyInstance");

    let in_use = r53.delete_traffic_policy().id(&pid).version(2).send().await.unwrap_err();
    assert_eq!(code(in_use.into_service_error()), "TrafficPolicyInUse");
    let by_zone = r53.list_traffic_policy_instances_by_hosted_zone().hosted_zone_id(&zone_id).send().await.unwrap();
    assert_eq!(by_zone.traffic_policy_instances().len(), 1);
    assert_eq!(r53.get_traffic_policy_instance_count().send().await.unwrap().traffic_policy_instance_count(), 1);

    r53.delete_traffic_policy_instance().id(&iid).send().await.unwrap();
    let records = r53.list_resource_record_sets().hosted_zone_id(&zone_id).send().await.unwrap();
    assert_eq!(records.resource_record_sets().len(), 2, "only SOA and NS remain");
    r53.delete_traffic_policy().id(&pid).version(2).send().await.unwrap();
    r53.delete_traffic_policy().id(&pid).version(1).send().await.unwrap();
    let gone = r53.get_traffic_policy().id(&pid).version(1).send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "NoSuchTrafficPolicy");
}

#[tokio::test]
async fn dnssec_key_signing_keys() {
    use aws_lc_rs::digest::{digest, SHA256};
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let zone = r53.create_hosted_zone().name("secure.example.com").caller_reference("sec").send().await.unwrap();
    let zone_id = zone.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    let kms_arn = dnssec_kms_key(&mws, true).await;
    let kms = kms_arn.as_str();

    // A key whose policy does not let Route 53 use it, and one that does
    // not exist, are both rejected.
    let unshared = dnssec_kms_key(&mws, false).await;
    for arn in [unshared.as_str(), "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"] {
        let err = r53
            .create_key_signing_key()
            .caller_reference("k-bad")
            .hosted_zone_id(&zone_id)
            .key_management_service_arn(arn)
            .name("ksk_bad")
            .status("ACTIVE")
            .send()
            .await
            .unwrap_err();
        assert_eq!(code(err.into_service_error()), "InvalidKMSArn");
    }

    let bad = r53
        .create_key_signing_key()
        .caller_reference("k0")
        .hosted_zone_id(&zone_id)
        .key_management_service_arn("arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555")
        .name("ksk_one")
        .status("ACTIVE")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(bad.into_service_error()), "InvalidKMSArn");

    let no_key = r53.enable_hosted_zone_dnssec().hosted_zone_id(&zone_id).send().await.unwrap_err();
    assert_eq!(code(no_key.into_service_error()), "KeySigningKeyWithActiveStatusNotFound");

    let ksk = r53
        .create_key_signing_key()
        .caller_reference("k1")
        .hosted_zone_id(&zone_id)
        .key_management_service_arn(kms)
        .name("ksk_one")
        .status("ACTIVE")
        .send()
        .await
        .unwrap();
    let ksk = ksk.key_signing_key().unwrap();
    assert_eq!((ksk.flag(), ksk.signing_algorithm_type(), ksk.digest_algorithm_type()), (257, 13, 2));

    // The DNSKEY is the KMS key's public key.
    let public = base64::engine::general_purpose::STANDARD.decode(ksk.public_key().unwrap()).unwrap();
    let kms_client = aws_sdk_kms::Client::new(&mws.root_sdk_config().await);
    let spki = kms_client.get_public_key().key_id(kms).send().await.unwrap();
    let spki = spki.public_key().unwrap().as_ref();
    assert_eq!(&spki[spki.len() - 64..], public.as_slice());

    // Recompute the DS digest from the DNSKEY independently.
    let mut rdata = vec![1, 1, 3, 13];
    rdata.extend(&public);
    let owner = b"\x06secure\x07example\x03com\x00".to_vec();
    let expected = digest(&SHA256, &[owner, rdata.clone()].concat());
    let expected_hex: String = expected.as_ref().iter().map(|b| format!("{b:02X}")).collect();
    assert_eq!(ksk.digest_value(), Some(expected_hex.as_str()));
    let mut ac: u32 = 0;
    for (i, b) in rdata.iter().enumerate() {
        ac += if i % 2 == 0 { (*b as u32) << 8 } else { *b as u32 };
    }
    ac += (ac >> 16) & 0xffff;
    assert_eq!(ksk.key_tag(), (ac & 0xffff) as i32);
    assert_eq!(ksk.ds_record(), Some(format!("{} 13 2 {expected_hex}", ksk.key_tag()).as_str()));

    r53.enable_hosted_zone_dnssec().hosted_zone_id(&zone_id).send().await.unwrap();
    let status = r53.get_dnssec().hosted_zone_id(&zone_id).send().await.unwrap();
    assert_eq!(status.status().unwrap().serve_signature(), Some("SIGNING"));
    let in_use = r53.deactivate_key_signing_key().hosted_zone_id(&zone_id).name("ksk_one").send().await.unwrap_err();
    assert_eq!(code(in_use.into_service_error()), "KeySigningKeyInUse");

    r53.disable_hosted_zone_dnssec().hosted_zone_id(&zone_id).send().await.unwrap();
    let active = r53.delete_key_signing_key().hosted_zone_id(&zone_id).name("ksk_one").send().await.unwrap_err();
    assert_eq!(code(active.into_service_error()), "InvalidKeySigningKeyStatus");
    r53.deactivate_key_signing_key().hosted_zone_id(&zone_id).name("ksk_one").send().await.unwrap();
    let reactivated = r53.activate_key_signing_key().hosted_zone_id(&zone_id).name("ksk_one").send().await.unwrap();
    assert!(reactivated.change_info().unwrap().id().starts_with("/change/"));
    let status = r53.get_dnssec().hosted_zone_id(&zone_id).send().await.unwrap();
    assert_eq!(status.key_signing_keys()[0].status(), Some("ACTIVE"));
    let missing = r53.activate_key_signing_key().hosted_zone_id(&zone_id).name("ksk_nope").send().await;
    assert_eq!(code(missing.unwrap_err().into_service_error()), "NoSuchKeySigningKey");
    r53.deactivate_key_signing_key().hosted_zone_id(&zone_id).name("ksk_one").send().await.unwrap();
    r53.delete_key_signing_key().hosted_zone_id(&zone_id).name("ksk_one").send().await.unwrap();
    let status = r53.get_dnssec().hosted_zone_id(&zone_id).send().await.unwrap();
    assert_eq!(status.status().unwrap().serve_signature(), Some("NOT_SIGNING"));
    assert!(status.key_signing_keys().is_empty());
}

#[tokio::test]
async fn cidr_collections() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let c = r53.create_cidr_collection().name("offices").caller_reference("c1").send().await.unwrap();
    let c = c.collection().unwrap();
    let id = c.id().unwrap().to_string();
    assert_eq!(c.version(), Some(1));
    assert!(c.arn().unwrap().ends_with(&format!(":cidrcollection/{id}")));

    let put = |loc: &str, cidrs: &[&str]| {
        CidrCollectionChange::builder()
            .location_name(loc)
            .action(CidrCollectionChangeAction::Put)
            .set_cidr_list(Some(cidrs.iter().map(|s| s.to_string()).collect()))
            .build()
            .unwrap()
    };
    r53.change_cidr_collection()
        .id(&id)
        .collection_version(1)
        .changes(put("nyc", &["192.0.2.0/24", "2001:db8::/48"]))
        .changes(put("ldn", &["198.51.100.0/24"]))
        .send()
        .await
        .unwrap();
    let stale = r53
        .change_cidr_collection()
        .id(&id)
        .collection_version(1)
        .changes(put("x", &["203.0.113.0/24"]))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(stale.into_service_error()), "CidrCollectionVersionMismatchException");
    let bad = r53.change_cidr_collection().id(&id).changes(put("x", &["203.0.113.7/24"])).send().await.unwrap_err();
    assert_eq!(code(bad.into_service_error()), "InvalidInput");

    let locs = r53.list_cidr_locations().collection_id(&id).send().await.unwrap();
    let names: Vec<_> = locs.cidr_locations().iter().filter_map(|l| l.location_name()).collect();
    assert_eq!(names, vec!["ldn", "nyc"]);
    let blocks = r53.list_cidr_blocks().collection_id(&id).location_name("nyc").send().await.unwrap();
    assert_eq!(blocks.cidr_blocks().len(), 2);
    let cols = r53.list_cidr_collections().send().await.unwrap();
    assert_eq!(cols.cidr_collections()[0].version(), Some(2));

    let in_use = r53.delete_cidr_collection().id(&id).send().await.unwrap_err();
    assert_eq!(code(in_use.into_service_error()), "CidrCollectionInUseException");
    let del = |loc: &str, cidrs: &[&str]| {
        CidrCollectionChange::builder()
            .location_name(loc)
            .action(CidrCollectionChangeAction::DeleteIfExists)
            .set_cidr_list(Some(cidrs.iter().map(|s| s.to_string()).collect()))
            .build()
            .unwrap()
    };
    r53.change_cidr_collection()
        .id(&id)
        .changes(del("nyc", &["192.0.2.0/24", "2001:db8::/48"]))
        .changes(del("ldn", &["198.51.100.0/24"]))
        .send()
        .await
        .unwrap();
    r53.delete_cidr_collection().id(&id).send().await.unwrap();
}

#[tokio::test]
async fn query_logging_vpc_authorizations_and_features() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let public = r53.create_hosted_zone().name("logs.example.com").caller_reference("ql").send().await.unwrap();
    let public_id = public.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    let group = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/logs.example.com";
    // The log group must exist and let Route 53 write to it.
    let logs = aws_sdk_cloudwatchlogs::Client::new(&mws.root_sdk_config().await);
    let attempt =
        || r53.create_query_logging_config().hosted_zone_id(&public_id).cloud_watch_logs_log_group_arn(group).send();
    assert_eq!(code(attempt().await.unwrap_err().into_service_error()), "NoSuchCloudWatchLogsLogGroup");
    logs.create_log_group().log_group_name("/aws/route53/logs.example.com").send().await.unwrap();
    assert_eq!(code(attempt().await.unwrap_err().into_service_error()), "InsufficientCloudWatchLogsResourcePolicy");
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "route53.amazonaws.com"},
                       "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                       "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/*"}]
    });
    logs.put_resource_policy()
        .policy_name("route53-query-logging")
        .policy_document(policy.to_string())
        .send()
        .await
        .unwrap();
    let cfg = r53
        .create_query_logging_config()
        .hosted_zone_id(&public_id)
        .cloud_watch_logs_log_group_arn(group)
        .send()
        .await
        .unwrap();
    let cfg_id = cfg.query_logging_config().unwrap().id().to_string();
    let dup = r53
        .create_query_logging_config()
        .hosted_zone_id(&public_id)
        .cloud_watch_logs_log_group_arn(group)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(dup.into_service_error()), "QueryLoggingConfigAlreadyExists");
    let listed = r53.list_query_logging_configs().hosted_zone_id(&public_id).send().await.unwrap();
    assert_eq!(listed.query_logging_configs()[0].cloud_watch_logs_log_group_arn(), group);
    r53.delete_query_logging_config().id(&cfg_id).send().await.unwrap();
    let gone = r53.get_query_logging_config().id(&cfg_id).send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "NoSuchQueryLoggingConfig");

    let vpc = |id: &str| Vpc::builder().vpc_id(id).vpc_region(VpcRegion::UsEast1).build();
    let home = crate::route53::real_vpc(&mws.root_sdk_config().await, "us-east-1").await;
    let private = r53
        .create_hosted_zone()
        .name("internal.example.com")
        .caller_reference("pv")
        .vpc(vpc(&home))
        .hosted_zone_config(HostedZoneConfig::builder().private_zone(true).build())
        .send()
        .await
        .unwrap();
    let private_id = private.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    r53.create_vpc_association_authorization()
        .hosted_zone_id(&private_id)
        .vpc(vpc("vpc-22222222"))
        .send()
        .await
        .unwrap();
    let auths = r53.list_vpc_association_authorizations().hosted_zone_id(&private_id).send().await.unwrap();
    assert_eq!(auths.vpcs()[0].vpc_id(), Some("vpc-22222222"));
    r53.delete_vpc_association_authorization()
        .hosted_zone_id(&private_id)
        .vpc(vpc("vpc-22222222"))
        .send()
        .await
        .unwrap();
    let missing = r53
        .delete_vpc_association_authorization()
        .hosted_zone_id(&private_id)
        .vpc(vpc("vpc-22222222"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(missing.into_service_error()), "VPCAssociationAuthorizationNotFound");

    let limit = r53
        .get_hosted_zone_limit()
        .hosted_zone_id(&private_id)
        .r#type(HostedZoneLimitType::MaxVpcsAssociatedByZone)
        .send()
        .await
        .unwrap();
    assert_eq!((limit.count(), limit.limit().unwrap().value()), (1, 300));
    let account = r53.get_account_limit().r#type(AccountLimitType::MaxHostedZonesByOwner).send().await.unwrap();
    assert_eq!((account.count(), account.limit().unwrap().value()), (2, 500));

    r53.update_hosted_zone_features()
        .hosted_zone_id(&public_id)
        .enable_accelerated_recovery(true)
        .send()
        .await
        .unwrap();
    let z = r53.get_hosted_zone().id(&public_id).send().await.unwrap();
    assert_eq!(
        z.hosted_zone().unwrap().features().unwrap().accelerated_recovery_status().map(|s| s.as_str()),
        Some("ENABLED")
    );
}

#[tokio::test]
async fn geo_catalogue_test_dns_answer_and_health_status() {
    let mws = Mws::start().await;
    let r53 = client(&mws).await;
    let eu = r53.get_geo_location().continent_code("EU").send().await.unwrap();
    assert_eq!(eu.geo_location_details().unwrap().continent_name(), Some("Europe"));
    let wa = r53.get_geo_location().country_code("US").subdivision_code("WA").send().await.unwrap();
    assert_eq!(wa.geo_location_details().unwrap().subdivision_name(), Some("Washington"));
    let none = r53.get_geo_location().country_code("ZZ").send().await.unwrap_err();
    assert_eq!(code(none.into_service_error()), "NoSuchGeoLocation");
    let page = r53.list_geo_locations().max_items(10).send().await.unwrap();
    assert_eq!(page.geo_location_details_list().len(), 10);
    assert!(page.is_truncated());
    let next = r53
        .list_geo_locations()
        .set_start_continent_code(page.next_continent_code().map(str::to_string))
        .set_start_country_code(page.next_country_code().map(str::to_string))
        .max_items(1)
        .send()
        .await
        .unwrap();
    assert_eq!(next.geo_location_details_list()[0].country_code(), page.next_country_code());

    let zone = r53.create_hosted_zone().name("answer.example.com").caller_reference("ans").send().await.unwrap();
    let zone_id = zone.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string();
    let answer = r53
        .test_dns_answer()
        .hosted_zone_id(&zone_id)
        .record_name("answer.example.com")
        .record_type(RrType::Ns)
        .send()
        .await
        .unwrap();
    assert_eq!((answer.response_code(), answer.protocol()), ("NOERROR", "UDP"));
    assert_eq!(answer.record_data().len(), 4);
    let nx = r53
        .test_dns_answer()
        .hosted_zone_id(&zone_id)
        .record_name("nope.answer.example.com")
        .record_type(RrType::A)
        .send()
        .await
        .unwrap();
    assert_eq!(nx.response_code(), "NXDOMAIN");

    assert!(!r53.get_checker_ip_ranges().send().await.unwrap().checker_ip_ranges().is_empty());
    // The checkers really probe: a TCP check of a port that accepts.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port() as i32;
    let hc = r53
        .create_health_check()
        .caller_reference("hc")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Tcp)
                .ip_address("127.0.0.1")
                .port(port)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let hc_id = hc.health_check().unwrap().id().to_string();
    let mut observations = Vec::new();
    for _ in 0..50 {
        let status = r53.get_health_check_status().health_check_id(&hc_id).send().await.unwrap();
        observations = status.health_check_observations().to_vec();
        if !observations.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(observations.len(), 8);
    assert!(observations[0].status_report().unwrap().status().unwrap().starts_with("Success"));
    let failures = r53.get_health_check_last_failure_reason().health_check_id(&hc_id).send().await.unwrap();
    assert!(failures.health_check_observations().is_empty());
    drop(listener);
}
