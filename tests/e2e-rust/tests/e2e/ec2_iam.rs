//! EC2 IAM fidelity: tag-on-create (`ec2:CreateTags` with
//! `ec2:CreateAction`) and the condition keys EC2 sets per resource type
//! (`ec2:Vpc`, `ec2:MetadataHttpTokens`, the volume keys, and the tags of
//! the resources a request names).

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{
    BlockDeviceMapping, EbsBlockDevice, Filter, HttpTokensState, InstanceMetadataOptionsRequest, IpPermission, IpRange,
    ResourceType, Tag, TagSpecification,
};
use aws_sdk_ec2::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

fn tags(rt: ResourceType, key: &str, value: &str) -> TagSpecification {
    TagSpecification::builder().resource_type(rt).tags(Tag::builder().key(key).value(value).build()).build()
}

async fn alpine_ami(ec2: &Client) -> String {
    let f = Filter::builder().name("name").values("mws-alpine-*").build();
    let images = ec2.describe_images().owners("amazon").filters(f).send().await.unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

async fn user(mws: &Mws, name: &str, policy: serde_json::Value) -> Client {
    let (_, cfg) = user_with_policy(mws, name, Some(&policy.to_string())).await;
    Client::new(&cfg)
}

fn unauthorized<E: ProvideErrorMetadata>(e: &E, action: &str) {
    assert_eq!(e.code(), Some("UnauthorizedOperation"), "{:?}", e.message());
    let msg = e.message().unwrap_or_default();
    assert!(msg.contains(&format!("is not authorized to perform: {action} ")), "{msg}");
    assert!(msg.contains("Encoded authorization failure message: "), "{msg}");
}

fn vpc_arn(id: &str) -> String {
    format!("arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/{id}")
}

#[tokio::test]
async fn tag_on_create_needs_create_tags_with_create_action() {
    let mws = Mws::start().await;
    let root = Client::new(&mws.root_sdk_config().await);
    let ami = alpine_ami(&root).await;
    let ec2 = user(
        &mws,
        "launcher",
        serde_json::json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["ec2:RunInstances", "ec2:CreateVpc", "ec2:Describe*"], "Resource": "*"},
            {"Effect": "Allow", "Action": "ec2:CreateTags", "Resource": "*",
             "Condition": {"StringEquals": {"ec2:CreateAction": "RunInstances"}}},
            {"Effect": "Deny", "Action": "ec2:CreateTags", "Resource": "*",
             "Condition": {"StringEquals": {"aws:RequestTag/env": "prod"}}}
        ]}),
    )
    .await;

    // Tagging at launch is allowed by the CreateAction condition.
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .tag_specifications(tags(ResourceType::Instance, "env", "dev"))
        .send()
        .await
        .unwrap();
    assert_eq!(run.instances()[0].tags()[0].value(), Some("dev"));

    // A denied tag fails the whole launch, and nothing is created.
    let before = root.describe_instances().send().await.unwrap().reservations().len();
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .tag_specifications(tags(ResourceType::Instance, "env", "prod"))
        .send()
        .await
        .unwrap_err();
    unauthorized(&e.into_service_error(), "ec2:CreateTags");
    assert_eq!(root.describe_instances().send().await.unwrap().reservations().len(), before);

    // The same holds under DryRun: the tag check comes first.
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .dry_run(true)
        .tag_specifications(tags(ResourceType::Instance, "env", "prod"))
        .send()
        .await
        .unwrap_err();
    unauthorized(&e.into_service_error(), "ec2:CreateTags");

    // CreateVpc may run, but not tag: ec2:CreateAction is CreateVpc.
    ec2.create_vpc().cidr_block("10.1.0.0/16").send().await.unwrap();
    let vpcs = root.describe_vpcs().send().await.unwrap().vpcs().len();
    let e = ec2
        .create_vpc()
        .cidr_block("10.2.0.0/16")
        .tag_specifications(tags(ResourceType::Vpc, "env", "dev"))
        .send()
        .await
        .unwrap_err();
    let e = e.into_service_error();
    unauthorized(&e, "ec2:CreateTags");
    assert!(e.message().unwrap().contains(&format!("on resource: arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/*")));
    assert_eq!(root.describe_vpcs().send().await.unwrap().vpcs().len(), vpcs);

    // The decoded message names ec2:CreateTags and the CreateAction key.
    let encoded = e.message().unwrap().rsplit("Encoded authorization failure message: ").next().unwrap().to_string();
    let sts = aws_sdk_sts::Client::new(&mws.root_sdk_config().await);
    let decoded = sts.decode_authorization_message().encoded_message(encoded).send().await.unwrap();
    let doc: serde_json::Value = serde_json::from_str(decoded.decoded_message().unwrap()).unwrap();
    assert_eq!(doc["context"]["action"], "ec2:CreateTags");
    let keys = doc["context"]["conditions"]["items"].as_array().unwrap();
    let action = keys.iter().find(|k| k["key"] == "ec2:CreateAction").expect("ec2:CreateAction");
    assert_eq!(action["values"]["items"][0]["value"], "CreateVpc");
}

#[tokio::test]
async fn security_groups_only_in_one_vpc() {
    let mws = Mws::start().await;
    let root = Client::new(&mws.root_sdk_config().await);
    let mut groups = Vec::new();
    let mut vpcs = Vec::new();
    for (i, cidr) in ["10.10.0.0/16", "10.20.0.0/16"].iter().enumerate() {
        let vpc = root.create_vpc().cidr_block(*cidr).send().await.unwrap();
        let vpc = vpc.vpc().unwrap().vpc_id().unwrap().to_string();
        let sg = root
            .create_security_group()
            .group_name(format!("g{i}"))
            .description("d")
            .vpc_id(&vpc)
            .send()
            .await
            .unwrap();
        groups.push(sg.group_id().unwrap().to_string());
        vpcs.push(vpc);
    }
    let ec2 = user(
        &mws,
        "netadmin",
        serde_json::json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow",
             "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:CreateSecurityGroup"],
             "Resource": format!("arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/*"),
             "Condition": {"ArnEquals": {"ec2:Vpc": vpc_arn(&vpcs[0])}}},
            {"Effect": "Allow", "Action": "ec2:CreateSecurityGroup",
             "Resource": format!("arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/*")}
        ]}),
    )
    .await;
    let perm = IpPermission::builder()
        .ip_protocol("tcp")
        .from_port(22)
        .to_port(22)
        .ip_ranges(IpRange::builder().cidr_ip("10.0.0.0/8").build())
        .build();
    ec2.authorize_security_group_ingress().group_id(&groups[0]).ip_permissions(perm.clone()).send().await.unwrap();
    let e = ec2.authorize_security_group_ingress().group_id(&groups[1]).ip_permissions(perm).send().await.unwrap_err();
    unauthorized(&e.into_service_error(), "ec2:AuthorizeSecurityGroupIngress");

    // ec2:Vpc is also on the new group in CreateSecurityGroup.
    ec2.create_security_group().group_name("ok").description("d").vpc_id(&vpcs[0]).send().await.unwrap();
    let e = ec2.create_security_group().group_name("no").description("d").vpc_id(&vpcs[1]).send().await.unwrap_err();
    unauthorized(&e.into_service_error(), "ec2:CreateSecurityGroup");
}

#[tokio::test]
async fn require_imdsv2_and_volume_limits() {
    let mws = Mws::start().await;
    let root = Client::new(&mws.root_sdk_config().await);
    let ami = alpine_ami(&root).await;
    let ec2 = user(
        &mws,
        "imdsv2",
        serde_json::json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["ec2:RunInstances", "ec2:CreateVolume"], "Resource": "*"},
            {"Effect": "Deny", "Action": "ec2:RunInstances",
             "Resource": format!("arn:aws:ec2:us-east-1:{ACCOUNT}:instance/*"),
             "Condition": {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}},
            {"Effect": "Deny", "Action": "ec2:RunInstances",
             "Resource": format!("arn:aws:ec2:us-east-1:{ACCOUNT}:instance/*"),
             "Condition": {"NumericGreaterThan": {"ec2:MetadataHttpPutResponseHopLimit": "2"}}},
            {"Effect": "Deny", "Action": ["ec2:RunInstances", "ec2:CreateVolume"],
             "Resource": format!("arn:aws:ec2:us-east-1:{ACCOUNT}:volume/*"),
             "Condition": {"NumericGreaterThan": {"ec2:VolumeSize": "50"}}},
            {"Effect": "Deny", "Action": "ec2:CreateVolume",
             "Resource": format!("arn:aws:ec2:us-east-1:{ACCOUNT}:volume/*"),
             "Condition": {"Bool": {"ec2:Encrypted": "false"}}}
        ]}),
    )
    .await;
    let md = |tokens: HttpTokensState, hops: i32| {
        InstanceMetadataOptionsRequest::builder().http_tokens(tokens).http_put_response_hop_limit(hops).build()
    };
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .metadata_options(md(HttpTokensState::Optional, 1))
        .send()
        .await
        .unwrap_err();
    unauthorized(&e.into_service_error(), "ec2:RunInstances");
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .metadata_options(md(HttpTokensState::Required, 5))
        .send()
        .await
        .unwrap_err();
    unauthorized(&e.into_service_error(), "ec2:RunInstances");
    ec2.run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .metadata_options(md(HttpTokensState::Required, 2))
        .send()
        .await
        .unwrap();

    // A root volume over the limit fails the launch (ec2:VolumeSize on volume/*).
    let root_device = root.describe_images().image_ids(&ami).send().await.unwrap().images()[0]
        .root_device_name()
        .unwrap()
        .to_string();
    let e = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .metadata_options(md(HttpTokensState::Required, 1))
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name(root_device)
                .ebs(EbsBlockDevice::builder().volume_size(60).build())
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    let e = e.into_service_error();
    unauthorized(&e, "ec2:RunInstances");
    assert!(e.message().unwrap().contains(":volume/*"), "{:?}", e.message());

    // CreateVolume: ec2:Encrypted and ec2:VolumeSize.
    let zone = "us-east-1a";
    ec2.create_volume().availability_zone(zone).size(10).encrypted(true).send().await.unwrap();
    let e = ec2.create_volume().availability_zone(zone).size(10).send().await.unwrap_err();
    unauthorized(&e.into_service_error(), "ec2:CreateVolume");
    let e = ec2.create_volume().availability_zone(zone).size(80).encrypted(true).send().await.unwrap_err();
    unauthorized(&e.into_service_error(), "ec2:CreateVolume");
}

#[tokio::test]
async fn resource_tags_on_the_vpc_named_in_create_subnet() {
    let mws = Mws::start().await;
    let root = Client::new(&mws.root_sdk_config().await);
    let blue = root
        .create_vpc()
        .cidr_block("10.30.0.0/16")
        .tag_specifications(tags(ResourceType::Vpc, "team", "blue"))
        .send()
        .await
        .unwrap();
    let blue = blue.vpc().unwrap().vpc_id().unwrap().to_string();
    let red = root
        .create_vpc()
        .cidr_block("10.40.0.0/16")
        .tag_specifications(tags(ResourceType::Vpc, "team", "red"))
        .send()
        .await
        .unwrap();
    let red = red.vpc().unwrap().vpc_id().unwrap().to_string();
    let ec2 = user(
        &mws,
        "blue-team",
        serde_json::json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "ec2:CreateSubnet",
             "Resource": format!("arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/*")},
            {"Effect": "Allow", "Action": "ec2:CreateSubnet",
             "Resource": format!("arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/*"),
             "Condition": {"StringEquals": {"aws:ResourceTag/team": "blue"}}}
        ]}),
    )
    .await;
    ec2.create_subnet().vpc_id(&blue).cidr_block("10.30.1.0/24").send().await.unwrap();
    let e = ec2.create_subnet().vpc_id(&red).cidr_block("10.40.1.0/24").send().await.unwrap_err();
    let e = e.into_service_error();
    unauthorized(&e, "ec2:CreateSubnet");
    assert!(e.message().unwrap().contains(&format!("on resource: {}", vpc_arn(&red))), "{:?}", e.message());
}
