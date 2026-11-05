//! The rest of the ELBv2 control plane through the official Rust SDK:
//! attributes, tags, subnets and security groups, capacity reservations,
//! SSL policies and limits, rule priorities, trust stores and mutual TLS.

use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, Certificate, IpAddressType, IpamPools, ListenerAttribute, LoadBalancerAttribute,
    LoadBalancerTypeEnum, MinimumLoadBalancerCapacity, MutualAuthenticationAttributes, ProtocolEnum,
    RemoveIpamPoolEnum, RevocationContent, RuleCondition, RulePriorityPair, Tag, TargetDescription,
    TargetGroupAttribute, TargetHealthStateEnum, TargetTypeEnum, TrustStoreStatus,
};
use aws_sdk_elasticloadbalancingv2::Client;
use mws_e2e::Mws;

use crate::elbv2::{code, default_network, https_get, listener_address, message, Backend};

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn fixed(status: &str) -> Action {
    Action::builder()
        .r#type(ActionTypeEnum::FixedResponse)
        .fixed_response_config(
            aws_sdk_elasticloadbalancingv2::types::FixedResponseActionConfig::builder().status_code(status).build(),
        )
        .build()
}

#[tokio::test]
async fn load_balancer_settings_and_errors() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let ec2 = aws_sdk_ec2::Client::new(&mws.root_sdk_config().await);
    let (vpc, subnets) = default_network(&mws).await;

    // ALBs need subnets in two Availability Zones.
    let err =
        elb.create_load_balancer().name("one").subnets(&subnets[0]).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ValidationError");
    assert!(
        message(&err).contains("At least two subnets in two different Availability Zones must be specified"),
        "{}",
        message(&err)
    );
    let err = elb.create_load_balancer().name("-bad").set_subnets(Some(subnets.clone())).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "ValidationError");

    let lb = elb
        .create_load_balancer()
        .name("settings")
        .set_subnets(Some(subnets.clone()))
        .tags(Tag::builder().key("env").value("test").build())
        .send()
        .await
        .unwrap();
    let lb = lb.load_balancers()[0].clone();
    let arn = lb.load_balancer_arn().unwrap().to_string();
    // Same name and settings: the same load balancer comes back.
    let again = elb.create_load_balancer().name("settings").set_subnets(Some(subnets.clone())).send().await.unwrap();
    assert_eq!(again.load_balancers()[0].load_balancer_arn(), Some(arn.as_str()));
    let default_sg = lb.security_groups()[0].to_string();
    assert!(default_sg.starts_with("sg-"));

    let d = elb.describe_load_balancers().names("settings").send().await.unwrap();
    assert_eq!(d.load_balancers()[0].state().unwrap().code().unwrap().as_str(), "active");
    let err = elb.describe_load_balancers().names("missing").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "LoadBalancerNotFound");
    assert_eq!(message(&err), "Load balancers '[missing]' not found");

    // Attributes.
    let attrs = elb.describe_load_balancer_attributes().load_balancer_arn(&arn).send().await.unwrap();
    let get =
        |k: &str| attrs.attributes().iter().find(|a| a.key() == Some(k)).and_then(|a| a.value()).map(str::to_string);
    assert_eq!(get("idle_timeout.timeout_seconds").as_deref(), Some("60"));
    assert_eq!(get("deletion_protection.enabled").as_deref(), Some("false"));
    assert_eq!(get("routing.http2.enabled").as_deref(), Some("true"));
    elb.modify_load_balancer_attributes()
        .load_balancer_arn(&arn)
        .attributes(LoadBalancerAttribute::builder().key("deletion_protection.enabled").value("true").build())
        .attributes(LoadBalancerAttribute::builder().key("idle_timeout.timeout_seconds").value("120").build())
        .send()
        .await
        .unwrap();
    let err = elb
        .modify_load_balancer_attributes()
        .load_balancer_arn(&arn)
        .attributes(LoadBalancerAttribute::builder().key("idle_timeout.timeout_seconds").value("0").build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");
    let err = elb.delete_load_balancer().load_balancer_arn(&arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "OperationNotPermitted");
    assert!(message(&err).contains("deletion protection"), "{}", message(&err));

    // Tags.
    elb.add_tags().resource_arns(&arn).tags(Tag::builder().key("owner").value("me").build()).send().await.unwrap();
    elb.remove_tags().resource_arns(&arn).tag_keys("env").send().await.unwrap();
    let tags = elb.describe_tags().resource_arns(&arn).send().await.unwrap();
    let keys: Vec<_> = tags.tag_descriptions()[0].tags().iter().filter_map(|t| t.key()).collect();
    assert_eq!(keys, ["owner"]);

    // Subnets, security groups, address type.
    let all_subnets = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    let mut three: Vec<String> =
        all_subnets.subnets().iter().filter_map(|s| s.subnet_id().map(str::to_string)).collect();
    three.truncate(3);
    let set = elb.set_subnets().load_balancer_arn(&arn).set_subnets(Some(three.clone())).send().await.unwrap();
    assert_eq!(set.availability_zones().len(), 3);
    let sg = ec2.create_security_group().group_name("alb").description("alb").vpc_id(&vpc).send().await.unwrap();
    let sg = sg.group_id().unwrap().to_string();
    let out = elb.set_security_groups().load_balancer_arn(&arn).security_groups(&sg).send().await.unwrap();
    assert_eq!(out.security_group_ids(), std::slice::from_ref(&sg));
    let err = elb
        .set_security_groups()
        .load_balancer_arn(&arn)
        .security_groups("sg-0000000000000000f")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidSecurityGroup");
    let out =
        elb.set_ip_address_type().load_balancer_arn(&arn).ip_address_type(IpAddressType::Ipv4).send().await.unwrap();
    assert_eq!(out.ip_address_type(), Some(&IpAddressType::Ipv4));

    // Capacity reservation and IPAM pools.
    let cap = elb.describe_capacity_reservation().load_balancer_arn(&arn).send().await.unwrap();
    assert!(cap.minimum_load_balancer_capacity().is_none());
    let cap = elb
        .modify_capacity_reservation()
        .load_balancer_arn(&arn)
        .minimum_load_balancer_capacity(MinimumLoadBalancerCapacity::builder().capacity_units(200).build())
        .send()
        .await
        .unwrap();
    assert_eq!(cap.minimum_load_balancer_capacity().unwrap().capacity_units(), Some(200));
    assert!(!cap.capacity_reservation_state().is_empty());
    let cap = elb.describe_capacity_reservation().load_balancer_arn(&arn).send().await.unwrap();
    assert_eq!(cap.minimum_load_balancer_capacity().unwrap().capacity_units(), Some(200));
    let err = elb
        .modify_capacity_reservation()
        .load_balancer_arn(&arn)
        .minimum_load_balancer_capacity(MinimumLoadBalancerCapacity::builder().capacity_units(10).build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");
    elb.modify_capacity_reservation().load_balancer_arn(&arn).reset_capacity_reservation(true).send().await.unwrap();
    let pools = elb
        .modify_ip_pools()
        .load_balancer_arn(&arn)
        .ipam_pools(IpamPools::builder().ipv4_ipam_pool_id("ipam-pool-0123456789abcdef0").build())
        .send()
        .await
        .unwrap();
    assert_eq!(pools.ipam_pools().unwrap().ipv4_ipam_pool_id(), Some("ipam-pool-0123456789abcdef0"));
    let pools =
        elb.modify_ip_pools().load_balancer_arn(&arn).remove_ipam_pools(RemoveIpamPoolEnum::Ipv4).send().await.unwrap();
    assert!(pools.ipam_pools().is_none());

    // Account limits and SSL policies.
    let limits = elb.describe_account_limits().send().await.unwrap();
    let lim = |n: &str| limits.limits().iter().find(|l| l.name() == Some(n)).and_then(|l| l.max()).map(str::to_string);
    assert_eq!(lim("application-load-balancers").as_deref(), Some("50"));
    assert_eq!(lim("target-groups").as_deref(), Some("3000"));
    let policies = elb.describe_ssl_policies().names("ELBSecurityPolicy-TLS13-1-2-2021-06").send().await.unwrap();
    let p = &policies.ssl_policies()[0];
    assert_eq!(p.ssl_protocols(), ["TLSv1.2", "TLSv1.3"]);
    assert!(p.ciphers().iter().any(|c| c.name() == Some("TLS_AES_128_GCM_SHA256")));
    let err = elb.describe_ssl_policies().names("NoSuchPolicy").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "SSLPolicyNotFound");

    // Turn deletion protection off and delete.
    elb.modify_load_balancer_attributes()
        .load_balancer_arn(&arn)
        .attributes(LoadBalancerAttribute::builder().key("deletion_protection.enabled").value("false").build())
        .send()
        .await
        .unwrap();
    elb.delete_load_balancer().load_balancer_arn(&arn).send().await.unwrap();
    // Deleting again succeeds, as in AWS.
    elb.delete_load_balancer().load_balancer_arn(&arn).send().await.unwrap();
}

#[tokio::test]
async fn listeners_rules_and_target_groups() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let (vpc, subnets) = default_network(&mws).await;
    let lb = elb.create_load_balancer().name("rules").set_subnets(Some(subnets)).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();

    let tg = elb
        .create_target_group()
        .name("rules")
        .protocol(ProtocolEnum::Http)
        .port(8080)
        .vpc_id(&vpc)
        .send()
        .await
        .unwrap();
    let tg = tg.target_groups()[0].clone();
    let tg_arn = tg.target_group_arn().unwrap().to_string();
    assert_eq!(tg.health_check_path(), Some("/"));
    assert_eq!(tg.health_check_interval_seconds(), Some(30));
    assert_eq!(tg.healthy_threshold_count(), Some(5));
    assert_eq!(tg.unhealthy_threshold_count(), Some(2));
    assert_eq!(tg.matcher().unwrap().http_code(), Some("200"));
    assert_eq!(tg.target_type(), Some(&TargetTypeEnum::Instance));
    assert!(tg.load_balancer_arns().is_empty());

    let m = elb
        .modify_target_group()
        .target_group_arn(&tg_arn)
        .health_check_path("/ping")
        .health_check_interval_seconds(10)
        .send()
        .await
        .unwrap();
    assert_eq!(m.target_groups()[0].health_check_path(), Some("/ping"));
    let attrs = elb.describe_target_group_attributes().target_group_arn(&tg_arn).send().await.unwrap();
    let get =
        |k: &str| attrs.attributes().iter().find(|a| a.key() == Some(k)).and_then(|a| a.value()).map(str::to_string);
    assert_eq!(get("deregistration_delay.timeout_seconds").as_deref(), Some("300"));
    assert_eq!(get("load_balancing.algorithm.type").as_deref(), Some("round_robin"));
    let err = elb
        .modify_target_group_attributes()
        .target_group_arn(&tg_arn)
        .attributes(TargetGroupAttribute::builder().key("no.such.attribute").value("1").build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");

    // Instance targets must be EC2 instances.
    let err = elb
        .register_targets()
        .target_group_arn(&tg_arn)
        .targets(TargetDescription::builder().id("i-0123456789abcdef0").build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidTarget");

    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(fixed("404"))
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listeners()[0].listener_arn().unwrap().to_string();
    let err = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(fixed("500"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "DuplicateListener");
    let d = elb.describe_listeners().load_balancer_arn(&lb_arn).send().await.unwrap();
    assert_eq!(d.listeners().len(), 1);

    let la = elb.describe_listener_attributes().listener_arn(&listener_arn).send().await.unwrap();
    assert!(la.attributes().iter().any(|a| a.key() == Some("routing.http.response.server.enabled")));
    elb.modify_listener_attributes()
        .listener_arn(&listener_arn)
        .attributes(ListenerAttribute::builder().key("routing.http.response.server.enabled").value("false").build())
        .send()
        .await
        .unwrap();

    let path_rule = |p: &str| RuleCondition::builder().field("path-pattern").values(p).build();
    let fwd = Action::builder().r#type(ActionTypeEnum::Forward).target_group_arn(&tg_arn).build();
    let r1 = elb
        .create_rule()
        .listener_arn(&listener_arn)
        .priority(1)
        .conditions(path_rule("/a"))
        .actions(fwd.clone())
        .send()
        .await
        .unwrap();
    let r1 = r1.rules()[0].rule_arn().unwrap().to_string();
    let r2 = elb
        .create_rule()
        .listener_arn(&listener_arn)
        .priority(2)
        .conditions(path_rule("/b"))
        .actions(fixed("204"))
        .send()
        .await
        .unwrap();
    let r2 = r2.rules()[0].rule_arn().unwrap().to_string();
    let err = elb
        .create_rule()
        .listener_arn(&listener_arn)
        .priority(2)
        .conditions(path_rule("/c"))
        .actions(fixed("204"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "PriorityInUse");

    // The target group now reports the load balancer.
    let d = elb.describe_target_groups().load_balancer_arn(&lb_arn).send().await.unwrap();
    assert_eq!(d.target_groups()[0].load_balancer_arns(), std::slice::from_ref(&lb_arn));

    let swapped = elb
        .set_rule_priorities()
        .rule_priorities(RulePriorityPair::builder().rule_arn(&r1).priority(20).build())
        .rule_priorities(RulePriorityPair::builder().rule_arn(&r2).priority(10).build())
        .send()
        .await
        .unwrap();
    assert_eq!(swapped.rules().len(), 2);
    let rules = elb.describe_rules().listener_arn(&listener_arn).send().await.unwrap();
    let order: Vec<_> = rules.rules().iter().map(|r| r.rule_arn().unwrap().to_string()).collect();
    assert_eq!(&order[..2], [r2.clone(), r1.clone()]);
    let modified = elb.modify_rule().rule_arn(&r2).actions(fixed("202")).send().await.unwrap();
    assert_eq!(modified.rules()[0].actions()[0].fixed_response_config().unwrap().status_code(), Some("202"));
    // The default rule cannot be deleted; others can.
    let default_rule =
        rules.rules().iter().find(|r| r.is_default() == Some(true)).unwrap().rule_arn().unwrap().to_string();
    let err = elb.delete_rule().rule_arn(&default_rule).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "OperationNotPermitted");
    elb.delete_rule().rule_arn(&r1).send().await.unwrap();

    let ml = elb.modify_listener().listener_arn(&listener_arn).port(8081).send().await.unwrap();
    assert_eq!(ml.listeners()[0].port(), Some(8081));
    elb.delete_listener().listener_arn(&listener_arn).send().await.unwrap();
    let err = elb.describe_listeners().listener_arns(&listener_arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ListenerNotFound");
    elb.delete_target_group().target_group_arn(&tg_arn).send().await.unwrap();
    let err = elb.describe_target_groups().target_group_arns(&tg_arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "TargetGroupNotFound");
}

struct Pki {
    ca: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

impl Pki {
    fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "Client CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        let ca = params.self_signed(&ca_key).unwrap();
        Self { ca, ca_key }
    }

    /// A client certificate: `(DER, PKCS#8 key DER)`.
    fn client(&self, cn: &str, serial: u64) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, &self.ca, &self.ca_key).unwrap();
        (cert.der().to_vec(), key.serialize_der())
    }

    fn crl(&self, serials: &[u64]) -> Vec<u8> {
        let now = time::OffsetDateTime::now_utc();
        let params = rcgen::CertificateRevocationListParams {
            this_update: now - time::Duration::hours(1),
            next_update: now + time::Duration::days(7),
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|s| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(*s),
                    revocation_time: now - time::Duration::minutes(5),
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        params.signed_by(&self.ca, &self.ca_key).unwrap().der().to_vec()
    }
}

#[tokio::test]
async fn trust_stores_and_mutual_tls() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let elb = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let (vpc, subnets) = default_network(&mws).await;
    let pki = Pki::new();
    s3.create_bucket().bucket("pki").send().await.unwrap();
    s3.put_object()
        .bucket("pki")
        .key("ca.pem")
        .body(aws_sdk_s3::primitives::ByteStream::from(pki.ca.pem().into_bytes()))
        .send()
        .await
        .unwrap();
    s3.put_object()
        .bucket("pki")
        .key("revoked.crl")
        .body(aws_sdk_s3::primitives::ByteStream::from(pki.crl(&[66])))
        .send()
        .await
        .unwrap();

    // A bundle that is not there.
    let err = elb
        .create_trust_store()
        .name("clients")
        .ca_certificates_bundle_s3_bucket("pki")
        .ca_certificates_bundle_s3_key("missing.pem")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "CaCertificatesBundleNotFound");

    let ts = elb
        .create_trust_store()
        .name("clients")
        .ca_certificates_bundle_s3_bucket("pki")
        .ca_certificates_bundle_s3_key("ca.pem")
        .tags(Tag::builder().key("k").value("v").build())
        .send()
        .await
        .unwrap();
    let ts = ts.trust_stores()[0].clone();
    let ts_arn = ts.trust_store_arn().unwrap().to_string();
    assert!(ts_arn.contains(":truststore/clients/"), "{ts_arn}");
    assert_eq!(ts.status(), Some(&TrustStoreStatus::Active));
    assert_eq!(ts.number_of_ca_certificates(), Some(1));
    let d = elb.describe_trust_stores().names("clients").send().await.unwrap();
    assert_eq!(d.trust_stores()[0].trust_store_arn(), Some(ts_arn.as_str()));
    let m = elb
        .modify_trust_store()
        .trust_store_arn(&ts_arn)
        .ca_certificates_bundle_s3_bucket("pki")
        .ca_certificates_bundle_s3_key("ca.pem")
        .send()
        .await
        .unwrap();
    assert_eq!(m.trust_stores()[0].number_of_ca_certificates(), Some(1));

    let bundle = elb.get_trust_store_ca_certificates_bundle().trust_store_arn(&ts_arn).send().await.unwrap();
    let (status, _, body) = mws.raw("GET", bundle.location().unwrap(), &[], b"").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("BEGIN CERTIFICATE"));

    let rev = elb
        .add_trust_store_revocations()
        .trust_store_arn(&ts_arn)
        .revocation_contents(RevocationContent::builder().s3_bucket("pki").s3_key("revoked.crl").build())
        .send()
        .await
        .unwrap();
    let rev_id = rev.trust_store_revocations()[0].revocation_id().unwrap();
    assert_eq!(rev.trust_store_revocations()[0].number_of_revoked_entries(), Some(1));
    let revs = elb.describe_trust_store_revocations().trust_store_arn(&ts_arn).send().await.unwrap();
    assert_eq!(revs.trust_store_revocations().len(), 1);
    let content =
        elb.get_trust_store_revocation_content().trust_store_arn(&ts_arn).revocation_id(rev_id).send().await.unwrap();
    assert!(content.location().unwrap().contains("/_aws/elb/trust-stores/"));
    let err = elb.get_resource_policy().resource_arn(&ts_arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceNotFound");

    // An HTTPS listener that verifies client certificates.
    let backend = Backend::start("mtls").await;
    let (server_cert, _) = imported(&mws).await;
    let lb = elb.create_load_balancer().name("mtls").set_subnets(Some(subnets)).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let tg = elb
        .create_target_group()
        .name("mtls")
        .protocol(ProtocolEnum::Http)
        .port(80)
        .vpc_id(&vpc)
        .target_type(TargetTypeEnum::Ip)
        .health_check_interval_seconds(5)
        .health_check_timeout_seconds(2)
        .send()
        .await
        .unwrap();
    let tg_arn = tg.target_groups()[0].target_group_arn().unwrap().to_string();
    elb.register_targets()
        .target_group_arn(&tg_arn)
        .targets(TargetDescription::builder().id("127.0.0.1").port(backend.port()).build())
        .send()
        .await
        .unwrap();
    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Https)
        .port(443)
        .certificates(Certificate::builder().certificate_arn(&server_cert).build())
        .mutual_authentication(
            MutualAuthenticationAttributes::builder().mode("verify").trust_store_arn(&ts_arn).build(),
        )
        .default_actions(Action::builder().r#type(ActionTypeEnum::Forward).target_group_arn(&tg_arn).build())
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listeners()[0].listener_arn().unwrap().to_string();
    let assoc = elb.describe_trust_store_associations().trust_store_arn(&ts_arn).send().await.unwrap();
    assert_eq!(assoc.trust_store_associations()[0].resource_arn(), Some(lb_arn.as_str()));
    let err = elb
        .delete_shared_trust_store_association()
        .trust_store_arn(&ts_arn)
        .resource_arn(&lb_arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "DeleteAssociationSameAccount");
    let err = elb.delete_trust_store().trust_store_arn(&ts_arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "TrustStoreInUse");

    let addr = listener_address(&mws, &listener_arn).await;
    for _ in 0..100 {
        let h = elb.describe_target_health().target_group_arn(&tg_arn).send().await.unwrap();
        if h.target_health_descriptions()[0].target_health().unwrap().state() == Some(&TargetHealthStateEnum::Healthy) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let (r, _) = https_get(&addr, "mtls.example.com", "/", Some(pki.client("alice", 7))).await.unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    let headers = &r.json()["headers"];
    assert_eq!(headers["x-amzn-mtls-clientcert-subject"], "CN=alice");
    assert_eq!(headers["x-amzn-mtls-clientcert-serial-number"], "07");
    assert!(headers["x-amzn-mtls-clientcert-leaf"].as_str().unwrap().contains("BEGIN%20CERTIFICATE"));
    // No certificate, or a revoked one: the handshake fails.
    assert!(https_get(&addr, "mtls.example.com", "/", None).await.is_err());
    assert!(https_get(&addr, "mtls.example.com", "/", Some(pki.client("mallory", 66))).await.is_err());

    // Revocations can be removed; then the trust store goes once unused.
    elb.remove_trust_store_revocations().trust_store_arn(&ts_arn).revocation_ids(rev_id).send().await.unwrap();
    assert!(https_get(&addr, "mtls.example.com", "/", Some(pki.client("mallory", 66))).await.is_ok());
    elb.delete_listener().listener_arn(&listener_arn).send().await.unwrap();
    elb.delete_trust_store().trust_store_arn(&ts_arn).send().await.unwrap();
    let err = elb.describe_trust_stores().trust_store_arns(&ts_arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "TrustStoreNotFound");
    backend.stop();
}

async fn imported(mws: &Mws) -> (String, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["mtls.example.com".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let acm = aws_sdk_acm::Client::new(&mws.root_sdk_config().await);
    let arn = acm
        .import_certificate()
        .certificate(aws_sdk_acm::primitives::Blob::new(cert.pem().as_bytes()))
        .private_key(aws_sdk_acm::primitives::Blob::new(key.serialize_pem().as_bytes()))
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    (arn, cert.der().to_vec())
}

#[tokio::test]
async fn gateway_and_network_specifics() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let (vpc, subnets) = default_network(&mws).await;
    let gw = elb
        .create_load_balancer()
        .name("gwlb")
        .r#type(LoadBalancerTypeEnum::Gateway)
        .subnets(&subnets[0])
        .send()
        .await
        .unwrap();
    let gw_arn = gw.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    assert!(gw_arn.contains(":loadbalancer/gwy/gwlb/"), "{gw_arn}");
    let tg = elb
        .create_target_group()
        .name("geneve")
        .protocol(ProtocolEnum::Geneve)
        .port(6081)
        .vpc_id(&vpc)
        .send()
        .await
        .unwrap();
    let tg = tg.target_groups()[0].clone();
    assert_eq!(tg.health_check_protocol(), Some(&ProtocolEnum::Tcp));
    assert_eq!(tg.health_check_port(), Some("80"));
    let l = elb
        .create_listener()
        .load_balancer_arn(&gw_arn)
        .default_actions(
            Action::builder().r#type(ActionTypeEnum::Forward).target_group_arn(tg.target_group_arn().unwrap()).build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(l.listeners()[0].protocol(), None);
    let err = elb
        .set_security_groups()
        .load_balancer_arn(&gw_arn)
        .security_groups("sg-123")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");
    let err = elb
        .modify_capacity_reservation()
        .load_balancer_arn(&gw_arn)
        .reset_capacity_reservation(true)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "OperationNotPermitted");
    let err = elb
        .modify_ip_pools()
        .load_balancer_arn(&gw_arn)
        .remove_ipam_pools(RemoveIpamPoolEnum::Ipv4)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "OperationNotPermitted");
}
