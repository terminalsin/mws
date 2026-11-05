//! Classic Load Balancers (the 2012-06-01 API) through the official Rust
//! SDK: every operation, instance health, policies and the listener that
//! answers for them.

use aws_sdk_elasticloadbalancing::types::{
    AdditionalAttribute, ConnectionDraining, ConnectionSettings, CrossZoneLoadBalancing, HealthCheck, Instance,
    Listener, LoadBalancerAttributes, PolicyAttribute, Tag, TagKeyOnly,
};
use aws_sdk_elasticloadbalancing::Client;
use mws_e2e::Mws;

use crate::elbv2::{code, default_network, get, listener_address, message};

#[tokio::test]
async fn classic_load_balancers() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let elb = Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let (vpc, subnets) = default_network(&mws).await;
    let zones = ec2.describe_availability_zones().send().await.unwrap();
    let zone_names: Vec<String> =
        zones.availability_zones().iter().filter_map(|z| z.zone_name().map(str::to_string)).collect();

    let http = Listener::builder().protocol("HTTP").load_balancer_port(80).instance_port(8080).build().unwrap();
    let out = elb
        .create_load_balancer()
        .load_balancer_name("classic")
        .listeners(http.clone())
        .availability_zones(&zone_names[0])
        .tags(Tag::builder().key("app").value("legacy").build().unwrap())
        .send()
        .await
        .unwrap();
    let dns = out.dns_name().unwrap().to_string();
    assert!(dns.starts_with("classic-") && dns.ends_with(".us-east-1.elb.amazonaws.com"), "{dns}");
    // Creating it again with the same listeners returns it.
    let again = elb
        .create_load_balancer()
        .load_balancer_name("classic")
        .listeners(http.clone())
        .availability_zones(&zone_names[0])
        .send()
        .await
        .unwrap();
    assert_eq!(again.dns_name(), Some(dns.as_str()));
    let err = elb
        .create_load_balancer()
        .load_balancer_name("classic")
        .listeners(Listener::builder().protocol("TCP").load_balancer_port(81).instance_port(81).build().unwrap())
        .availability_zones(&zone_names[0])
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "DuplicateLoadBalancerName");

    let d = elb.describe_load_balancers().load_balancer_names("classic").send().await.unwrap();
    let lb = &d.load_balancer_descriptions()[0];
    assert_eq!(lb.vpc_id(), Some(vpc.as_str()));
    assert_eq!(lb.availability_zones(), [zone_names[0].clone()]);
    assert_eq!(lb.scheme(), Some("internet-facing"));
    assert_eq!(lb.canonical_hosted_zone_name_id(), Some("Z35SXDOTRQ7X7K"));
    let hc = lb.health_check().unwrap();
    assert_eq!(
        (hc.target(), hc.interval(), hc.timeout(), hc.unhealthy_threshold(), hc.healthy_threshold()),
        ("TCP:8080", 30, 5, 2, 10)
    );
    let err = elb.describe_load_balancers().load_balancer_names("nope").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "LoadBalancerNotFound");
    assert_eq!(message(&err), "There is no ACTIVE Load Balancer named 'nope'");

    // Subnets and zones.
    let attached =
        elb.attach_load_balancer_to_subnets().load_balancer_name("classic").subnets(&subnets[1]).send().await.unwrap();
    assert_eq!(attached.subnets().len(), 2);
    let detached = elb
        .detach_load_balancer_from_subnets()
        .load_balancer_name("classic")
        .subnets(&subnets[1])
        .send()
        .await
        .unwrap();
    assert_eq!(detached.subnets().len(), 1);
    let enabled = elb
        .enable_availability_zones_for_load_balancer()
        .load_balancer_name("classic")
        .availability_zones(&zone_names[1])
        .send()
        .await
        .unwrap();
    assert_eq!(enabled.availability_zones().len(), 2);
    let disabled = elb
        .disable_availability_zones_for_load_balancer()
        .load_balancer_name("classic")
        .availability_zones(&zone_names[1])
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.availability_zones(), [zone_names[0].clone()]);
    let sg = ec2.create_security_group().group_name("clb").description("clb").vpc_id(&vpc).send().await.unwrap();
    let sg = sg.group_id().unwrap().to_string();
    let applied = elb
        .apply_security_groups_to_load_balancer()
        .load_balancer_name("classic")
        .security_groups(&sg)
        .send()
        .await
        .unwrap();
    assert_eq!(applied.security_groups(), [sg]);

    // Health check, attributes.
    let hc = HealthCheck::builder()
        .target("HTTP:8080/health")
        .interval(10)
        .timeout(3)
        .unhealthy_threshold(2)
        .healthy_threshold(3)
        .build()
        .unwrap();
    let out = elb.configure_health_check().load_balancer_name("classic").health_check(hc).send().await.unwrap();
    assert_eq!(out.health_check().unwrap().target(), "HTTP:8080/health");
    let bad = HealthCheck::builder()
        .target("FTP:21")
        .interval(10)
        .timeout(3)
        .unhealthy_threshold(2)
        .healthy_threshold(3)
        .build()
        .unwrap();
    let err = elb.configure_health_check().load_balancer_name("classic").health_check(bad).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "ValidationError");
    let attrs = elb.describe_load_balancer_attributes().load_balancer_name("classic").send().await.unwrap();
    let a = attrs.load_balancer_attributes().unwrap();
    assert!(!a.cross_zone_load_balancing().unwrap().enabled());
    assert_eq!(a.connection_settings().unwrap().idle_timeout(), 60);
    assert_eq!(a.additional_attributes()[0].key(), Some("elb.http.desyncmitigationmode"));
    let m = elb
        .modify_load_balancer_attributes()
        .load_balancer_name("classic")
        .load_balancer_attributes(
            LoadBalancerAttributes::builder()
                .cross_zone_load_balancing(CrossZoneLoadBalancing::builder().enabled(true).build())
                .connection_draining(ConnectionDraining::builder().enabled(true).timeout(60).build())
                .connection_settings(ConnectionSettings::builder().idle_timeout(30).build().unwrap())
                .additional_attributes(
                    AdditionalAttribute::builder().key("elb.http.desyncmitigationmode").value("strictest").build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let a = m.load_balancer_attributes().unwrap();
    assert!(a.cross_zone_load_balancing().unwrap().enabled());
    assert_eq!(a.connection_draining().unwrap().timeout(), Some(60));

    // Instances: metadata-only EC2 instances register, but nothing answers
    // their health checks, so they stay out of service.
    let image = ec2
        .describe_images()
        .owners("amazon")
        .filters(aws_sdk_ec2::types::Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap()
        .images()[0]
        .image_id()
        .unwrap()
        .to_string();
    let run = ec2.run_instances().image_id(image).min_count(1).max_count(1).send().await.unwrap();
    let instance = run.instances()[0].instance_id().unwrap().to_string();
    let err = elb
        .register_instances_with_load_balancer()
        .load_balancer_name("classic")
        .instances(Instance::builder().instance_id("i-0000000000000000f").build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidInstance");
    let reg = elb
        .register_instances_with_load_balancer()
        .load_balancer_name("classic")
        .instances(Instance::builder().instance_id(&instance).build())
        .send()
        .await
        .unwrap();
    assert_eq!(reg.instances()[0].instance_id(), Some(instance.as_str()));
    let health = elb.describe_instance_health().load_balancer_name("classic").send().await.unwrap();
    let s = &health.instance_states()[0];
    assert_eq!(s.instance_id(), Some(instance.as_str()));
    assert_eq!(s.state(), Some("OutOfService"));
    assert!(matches!(s.reason_code(), Some("ELB") | Some("Instance")), "{s:?}");

    // The HTTP listener answers 503 while no instance is in service.
    let d = elb.describe_load_balancers().load_balancer_names("classic").send().await.unwrap();
    let listener_key = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/classic:80";
    let addr = listener_address(&mws, listener_key).await;
    let r = get(&addr, &dns, "/", &[]).await;
    assert_eq!(r.status, 503);
    assert_eq!(d.load_balancer_descriptions()[0].instances().len(), 1);

    // Policies.
    elb.create_lb_cookie_stickiness_policy()
        .load_balancer_name("classic")
        .policy_name("sticky")
        .cookie_expiration_period(300)
        .send()
        .await
        .unwrap();
    elb.create_app_cookie_stickiness_policy()
        .load_balancer_name("classic")
        .policy_name("app-sticky")
        .cookie_name("SESSION")
        .send()
        .await
        .unwrap();
    elb.create_load_balancer_policy()
        .load_balancer_name("classic")
        .policy_name("proxy")
        .policy_type_name("ProxyProtocolPolicyType")
        .policy_attributes(PolicyAttribute::builder().attribute_name("ProxyProtocol").attribute_value("true").build())
        .send()
        .await
        .unwrap();
    let err = elb
        .create_load_balancer_policy()
        .load_balancer_name("classic")
        .policy_name("bad")
        .policy_type_name("NoSuchPolicyType")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "PolicyTypeNotFound");
    elb.set_load_balancer_policies_of_listener()
        .load_balancer_name("classic")
        .load_balancer_port(80)
        .policy_names("sticky")
        .send()
        .await
        .unwrap();
    elb.set_load_balancer_policies_for_backend_server()
        .load_balancer_name("classic")
        .instance_port(8080)
        .policy_names("proxy")
        .send()
        .await
        .unwrap();
    let d = elb.describe_load_balancers().load_balancer_names("classic").send().await.unwrap();
    let lb = &d.load_balancer_descriptions()[0];
    let p = lb.policies().unwrap();
    assert_eq!(p.lb_cookie_stickiness_policies()[0].cookie_expiration_period(), Some(300));
    assert_eq!(p.app_cookie_stickiness_policies()[0].cookie_name(), Some("SESSION"));
    assert_eq!(p.other_policies(), ["proxy"]);
    assert_eq!(lb.listener_descriptions()[0].policy_names(), ["sticky"]);
    assert_eq!(lb.backend_server_descriptions()[0].policy_names(), ["proxy"]);
    let policies = elb.describe_load_balancer_policies().load_balancer_name("classic").send().await.unwrap();
    assert_eq!(policies.policy_descriptions().len(), 3);
    let samples = elb.describe_load_balancer_policies().send().await.unwrap();
    assert!(samples.policy_descriptions().iter().any(|p| p.policy_name() == Some("ELBSecurityPolicy-2016-08")));
    let types =
        elb.describe_load_balancer_policy_types().policy_type_names("SSLNegotiationPolicyType").send().await.unwrap();
    assert!(types.policy_type_descriptions()[0]
        .policy_attribute_type_descriptions()
        .iter()
        .any(|a| a.attribute_name() == Some("Reference-Security-Policy")));
    let err = elb
        .delete_load_balancer_policy()
        .load_balancer_name("classic")
        .policy_name("sticky")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidConfigurationRequest");
    elb.delete_load_balancer_policy().load_balancer_name("classic").policy_name("app-sticky").send().await.unwrap();

    // Listeners with ACM certificates.
    let key = rcgen::KeyPair::generate().unwrap();
    let cert =
        rcgen::CertificateParams::new(vec!["legacy.example.com".to_string()]).unwrap().self_signed(&key).unwrap();
    let acm = aws_sdk_acm::Client::new(&cfg);
    let cert_arn = acm
        .import_certificate()
        .certificate(aws_sdk_acm::primitives::Blob::new(cert.pem().as_bytes()))
        .private_key(aws_sdk_acm::primitives::Blob::new(key.serialize_pem().as_bytes()))
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    let https = Listener::builder()
        .protocol("HTTPS")
        .load_balancer_port(443)
        .instance_protocol("HTTP")
        .instance_port(8080)
        .ssl_certificate_id(&cert_arn)
        .build()
        .unwrap();
    elb.create_load_balancer_listeners().load_balancer_name("classic").listeners(https).send().await.unwrap();
    let err = elb
        .create_load_balancer_listeners()
        .load_balancer_name("classic")
        .listeners(Listener::builder().protocol("HTTP").load_balancer_port(80).instance_port(9090).build().unwrap())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "DuplicateListener");
    let in_use = acm.describe_certificate().certificate_arn(&cert_arn).send().await.unwrap();
    assert_eq!(in_use.certificate().unwrap().in_use_by().len(), 1);
    elb.set_load_balancer_listener_ssl_certificate()
        .load_balancer_name("classic")
        .load_balancer_port(443)
        .ssl_certificate_id(&cert_arn)
        .send()
        .await
        .unwrap();
    let err = elb
        .set_load_balancer_listener_ssl_certificate()
        .load_balancer_name("classic")
        .load_balancer_port(443)
        .ssl_certificate_id("arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "CertificateNotFound");
    elb.delete_load_balancer_listeners().load_balancer_name("classic").load_balancer_ports(443).send().await.unwrap();
    let released = acm.describe_certificate().certificate_arn(&cert_arn).send().await.unwrap();
    assert!(released.certificate().unwrap().in_use_by().is_empty());

    // Tags and limits.
    elb.add_tags()
        .load_balancer_names("classic")
        .tags(Tag::builder().key("tier").value("1").build().unwrap())
        .send()
        .await
        .unwrap();
    elb.remove_tags()
        .load_balancer_names("classic")
        .tags(TagKeyOnly::builder().key("app").build())
        .send()
        .await
        .unwrap();
    let tags = elb.describe_tags().load_balancer_names("classic").send().await.unwrap();
    let keys: Vec<_> = tags.tag_descriptions()[0].tags().iter().map(|t| t.key().to_string()).collect();
    assert_eq!(keys, ["tier"]);
    let limits = elb.describe_account_limits().send().await.unwrap();
    assert!(limits.limits().iter().any(|l| l.name() == Some("classic-load-balancers")));

    elb.deregister_instances_from_load_balancer()
        .load_balancer_name("classic")
        .instances(Instance::builder().instance_id(&instance).build())
        .send()
        .await
        .unwrap();
    let health = elb.describe_instance_health().load_balancer_name("classic").send().await.unwrap();
    assert!(health.instance_states().is_empty());
    elb.delete_load_balancer().load_balancer_name("classic").send().await.unwrap();
    let d = elb.describe_load_balancers().send().await.unwrap();
    assert!(d.load_balancer_descriptions().is_empty());
}
