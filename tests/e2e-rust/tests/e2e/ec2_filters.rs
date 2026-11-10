//! DescribeInstances filters through the official Rust SDK: block device
//! mappings, instance profiles, network interfaces (secondary addresses
//! included), metadata and hibernation options, and the other documented
//! names.

use std::time::Duration;

use aws_sdk_ec2::client::Waiters;
use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{
    Filter, HibernationOptionsRequest, IamInstanceProfileSpecification, InstanceMetadataOptionsRequest, InstanceType,
};
use aws_sdk_ec2::Client;
use mws_e2e::Mws;

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

/// The instances one filter matches.
async fn matching(ec2: &Client, name: &str, value: &str) -> Vec<String> {
    let out = ec2.describe_instances().filters(filter(name, value)).send().await.unwrap();
    out.reservations().iter().flat_map(|r| r.instances()).filter_map(|i| i.instance_id().map(String::from)).collect()
}

#[tokio::test]
async fn describe_instances_filters() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    iam.create_role()
        .role_name("web")
        .assume_role_policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let profile = iam.create_instance_profile().instance_profile_name("web").send().await.unwrap();
    let profile = profile.instance_profile().unwrap();
    let (profile_arn, profile_id) = (profile.arn().to_string(), profile.instance_profile_id().to_string());
    iam.add_role_to_instance_profile().instance_profile_name("web").role_name("web").send().await.unwrap();

    let images = ec2.describe_images().owners("amazon").filters(filter("name", "mws-alpine-*")).send().await.unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .iam_instance_profile(IamInstanceProfileSpecification::builder().name("web").build())
        .metadata_options(InstanceMetadataOptionsRequest::builder().http_put_response_hop_limit(3).build())
        .hibernation_options(HibernationOptionsRequest::builder().configured(true).build())
        .send()
        .await
        .unwrap();
    let instance = &run.instances()[0];
    let id = instance.instance_id().unwrap().to_string();
    // A second, plain instance that the filters must leave out.
    let plain = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let plain_id = plain.instances()[0].instance_id().unwrap().to_string();
    ec2.wait_until_instance_running()
        .instance_ids(&id)
        .instance_ids(&plain_id)
        .wait(Duration::from_secs(60))
        .await
        .unwrap();

    let eni_id = instance.network_interfaces()[0].network_interface_id().unwrap().to_string();
    ec2.assign_private_ip_addresses()
        .network_interface_id(&eni_id)
        .secondary_private_ip_address_count(1)
        .send()
        .await
        .unwrap();
    let eni = ec2.describe_network_interfaces().network_interface_ids(&eni_id).send().await.unwrap();
    let eni = &eni.network_interfaces()[0];
    let secondary = eni
        .private_ip_addresses()
        .iter()
        .find(|a| a.primary() == Some(false))
        .and_then(|a| a.private_ip_address())
        .unwrap()
        .to_string();
    let zone = eni.availability_zone().unwrap().to_string();

    let volume = ec2.create_volume().availability_zone(&zone).size(8).send().await.unwrap();
    let volume_id = volume.volume_id().unwrap().to_string();
    ec2.wait_until_volume_available().volume_ids(&volume_id).wait(Duration::from_secs(60)).await.unwrap();
    ec2.attach_volume().volume_id(&volume_id).instance_id(&id).device("/dev/sdf").send().await.unwrap();
    ec2.wait_until_volume_in_use().volume_ids(&volume_id).wait(Duration::from_secs(60)).await.unwrap();

    let only = vec![id.clone()];
    let cases: Vec<(&str, String)> = vec![
        ("block-device-mapping.volume-id", volume_id.clone()),
        ("block-device-mapping.device-name", "/dev/sdf".into()),
        ("iam-instance-profile.arn", profile_arn.clone()),
        ("iam-instance-profile.id", profile_id.clone()),
        ("network-interface.addresses.private-ip-address", secondary.clone()),
        ("network-interface.private-ip-address", secondary.clone()),
        ("network-interface.network-interface-id", eni_id.clone()),
        ("metadata-options.http-put-response-hop-limit", "3".into()),
        ("hibernation-options.configured", "true".into()),
    ];
    for (name, value) in &cases {
        assert_eq!(matching(&ec2, name, value).await, only, "{name}={value}");
    }

    // Filters both instances share match both.
    let both = |mut v: Vec<String>| {
        v.sort();
        v
    };
    let mut expected = vec![id.clone(), plain_id.clone()];
    expected.sort();
    for (name, value) in [
        ("block-device-mapping.status", "attached"),
        ("block-device-mapping.delete-on-termination", "true"),
        ("network-interface.status", "in-use"),
        ("network-interface.attachment.status", "attached"),
        ("network-interface.attachment.device-index", "0"),
        ("network-interface.addresses.primary", "true"),
        ("network-interface.requester-managed", "false"),
        ("network-interface.availability-zone", zone.as_str()),
        ("metadata-options.http-endpoint", "enabled"),
        ("metadata-options.http-protocol-ipv4", "enabled"),
        ("enclave-options.enabled", "false"),
        ("maintenance-options.auto-recovery", "default"),
        ("operator.managed", "false"),
        ("usage-operation", "RunInstances"),
        ("network-interface.attachment.instance-owner-id", "123456789012"),
    ] {
        assert_eq!(both(matching(&ec2, name, value).await), expected, "{name}={value}");
    }
    assert!(matching(&ec2, "hibernation-options.configured", "false").await.contains(&plain_id));
    assert!(matching(&ec2, "host-id", "h-0123456789abcdef0").await.is_empty());
    assert!(matching(&ec2, "capacity-reservation-id", "cr-0123456789abcdef0").await.is_empty());
    assert!(matching(&ec2, "product-code", "abc").await.is_empty());
    assert!(matching(&ec2, "ipv6-address", "2001:db8::1").await.is_empty());

    // A name EC2 does not document is still an error.
    let e = ec2.describe_instances().filters(filter("no-such-filter", "x")).send().await.unwrap_err();
    assert_eq!(e.code(), Some("InvalidParameterValue"));
}
