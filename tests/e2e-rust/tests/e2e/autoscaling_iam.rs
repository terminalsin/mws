//! EC2 Auto Scaling permissions through the official Rust SDK: passing an
//! instance profile's role (launch templates and launch configurations) or
//! a custom service-linked role needs `iam:PassRole`, and tagging a group
//! on create needs `autoscaling:CreateOrUpdateTags`.

use aws_sdk_autoscaling::error::ProvideErrorMetadata;
use aws_sdk_autoscaling::types::{LaunchTemplateSpecification, Tag};
use aws_sdk_autoscaling::Client;
use aws_sdk_ec2::types::{
    Filter, InstanceType, LaunchTemplateIamInstanceProfileSpecificationRequest, RequestLaunchTemplateData,
};
use mws_e2e::{user_with_policy, Mws};

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

const BASE: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["autoscaling:*","ec2:*"],"Resource":"*"}]}"#;

#[tokio::test]
async fn launches_need_pass_role_and_tags_need_create_or_update_tags() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&root);
    let ec2 = aws_sdk_ec2::Client::new(&root);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("app").assume_role_policy_document(trust).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    iam.create_instance_profile().instance_profile_name("app").send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name("app").role_name("app").send().await.unwrap();
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let lt = ec2
        .create_launch_template()
        .launch_template_name("with-role")
        .launch_template_data(
            RequestLaunchTemplateData::builder()
                .image_id(&ami)
                .instance_type(InstanceType::T3Micro)
                .iam_instance_profile(
                    LaunchTemplateIamInstanceProfileSpecificationRequest::builder().name("app").build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let lt_id = lt.launch_template().unwrap().launch_template_id().unwrap().to_string();
    let spec = LaunchTemplateSpecification::builder().launch_template_id(&lt_id).version("$Latest").build();

    let (_, cfg) = user_with_policy(&mws, "deployer", Some(BASE)).await;
    let asg = Client::new(&cfg);
    let create = |name: &str| {
        asg.create_auto_scaling_group()
            .auto_scaling_group_name(name)
            .min_size(0)
            .max_size(1)
            .availability_zones("us-east-1a")
            .launch_template(spec.clone())
    };

    // Without iam:PassRole on the profile's role, the template is refused.
    let err = create("web").send().await.unwrap_err();
    assert_eq!(code(&err), "AccessDenied");
    assert_eq!(message(&err), "You are not authorized to use launch template: with-role");
    let err = asg
        .create_launch_configuration()
        .launch_configuration_name("legacy")
        .image_id(&ami)
        .instance_type("t3.micro")
        .iam_instance_profile("app")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "AccessDenied");
    assert!(message(&err).contains("iam:PassRole"), "{}", message(&err));
    let err = asg
        .create_launch_configuration()
        .launch_configuration_name("legacy")
        .image_id(&ami)
        .instance_type("t3.micro")
        .iam_instance_profile("no-such-profile")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ValidationError");

    // PassRole for EC2 only: the template and configuration work, a custom
    // service-linked role (passed to Auto Scaling) does not.
    let pass = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"iam:PassRole","Resource":"{role_arn}","Condition":{{"StringEquals":{{"iam:PassedToService":"ec2.amazonaws.com"}}}}}}]}}"#
    );
    iam.put_user_policy().user_name("deployer").policy_name("pass").policy_document(&pass).send().await.unwrap();
    create("web").send().await.unwrap();
    asg.create_launch_configuration()
        .launch_configuration_name("legacy")
        .image_id(&ami)
        .instance_type("t3.micro")
        .iam_instance_profile("app")
        .send()
        .await
        .unwrap();
    let slr =
        "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling_custom";
    let err = create("custom-role").service_linked_role_arn(slr).send().await.unwrap_err();
    assert_eq!(code(&err), "AccessDenied");
    assert!(message(&err).contains("iam:PassRole"), "{}", message(&err));
    let err = asg
        .update_auto_scaling_group()
        .auto_scaling_group_name("web")
        .service_linked_role_arn(slr)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "AccessDenied");

    // Tags on create need autoscaling:CreateOrUpdateTags.
    let no_tags = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":["autoscaling:*","ec2:*","iam:PassRole"],"Resource":"*"},
        {"Effect":"Deny","Action":"autoscaling:CreateOrUpdateTags","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/team":"ops"}}}]}"#;
    let (_, cfg) = user_with_policy(&mws, "tagger", Some(no_tags)).await;
    let tagger = Client::new(&cfg);
    let tagged = |name: &str, team: &str| {
        tagger
            .create_auto_scaling_group()
            .auto_scaling_group_name(name)
            .min_size(0)
            .max_size(1)
            .availability_zones("us-east-1a")
            .launch_template(spec.clone())
            .tags(Tag::builder().key("team").value(team).build())
    };
    let err = tagged("ops-group", "ops").send().await.unwrap_err();
    assert_eq!(code(&err), "AccessDenied");
    assert!(message(&err).contains("autoscaling:CreateOrUpdateTags"), "{}", message(&err));
    tagged("dev-group", "dev").send().await.unwrap();
}
