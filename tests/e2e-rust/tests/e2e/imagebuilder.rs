//! EC2 Image Builder through the official Rust SDK: pipelines that build
//! real AMIs in MWS's EC2 (metadata-only backend here), distribution to a
//! second Region, versioning, workflows, lifecycle policies, sharing and
//! errors.

use std::time::Duration;

use aws_sdk_ec2::types::Filter;
use aws_sdk_imagebuilder::error::ProvideErrorMetadata;
use aws_sdk_imagebuilder::types::{
    AmiDistributionConfiguration, ComponentConfiguration, ComponentParameter, ContainerRepositoryService,
    ContainerType, Distribution, ImageStatus, LaunchPermissionConfiguration, LaunchTemplateConfiguration,
    LifecyclePolicyDetail, LifecyclePolicyDetailAction, LifecyclePolicyDetailActionType, LifecyclePolicyDetailFilter,
    LifecyclePolicyDetailFilterType, LifecyclePolicyResourceSelection, LifecyclePolicyResourceType,
    LifecyclePolicyStatus, Ownership, PipelineExecutionStartCondition, ResourceState, ResourceStatus, Schedule,
    SsmParameterConfiguration, TargetContainerRepository, WorkflowConfiguration, WorkflowStepActionType, WorkflowType,
};
use aws_sdk_imagebuilder::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

const COMPONENT: &str = r#"name: install-tailscale
description: Installs and configures Tailscale
schemaVersion: 1.0
parameters:
  - AuthKey:
      type: string
      default: tskey-none
      description: The Tailscale auth key.
phases:
  - name: build
    steps:
      - name: Install
        action: ExecuteBash
        inputs:
          commands:
            - echo "installing tailscale with {{ AuthKey }}"
      - name: Forwarding
        action: CreateFile
        inputs:
          - path: /etc/sysctl.d/99-tailscale.conf
            content: net.ipv4.ip_forward = 1
  - name: validate
    steps:
      - name: Check
        action: ExecuteBash
        inputs:
          commands:
            - test -f /etc/sysctl.d/99-tailscale.conf || true
"#;

const TEST_COMPONENT: &str = r#"name: smoke
schemaVersion: 1.0
phases:
  - name: test
    steps:
      - name: Smoke
        action: ExecuteBash
        inputs:
          commands:
            - echo ok
"#;

const WAIT_WORKFLOW: &str = r#"name: approve-then-build
schemaVersion: 1.0
parameters:
  - name: approve
    type: boolean
    default: true
steps:
  - name: LaunchBuildInstance
    action: LaunchInstance
    onFailure: Abort
    inputs:
      waitFor: "ssmAgent"
  - name: ApplyBuildComponents
    action: ExecuteComponents
    onFailure: Abort
    inputs:
      instanceId.$: "$.stepOutputs.LaunchBuildInstance.instanceId"
  - name: Approval
    action: WaitForAction
    onFailure: Abort
    if:
      booleanEquals: true
      value.$: "$.parameters.approve"
  - name: CreateOutputAMI
    action: CreateImage
    onFailure: Abort
    inputs:
      instanceId.$: "$.stepOutputs.LaunchBuildInstance.instanceId"
  - name: TerminateBuildInstance
    action: TerminateInstance
    onFailure: Continue
    inputs:
      instanceId.$: "$.stepOutputs.LaunchBuildInstance.instanceId"
outputs:
  - name: ImageId
    value: "$.stepOutputs.CreateOutputAMI.imageId"
"#;

const AL2023: &str = "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2023-x86/x.x.x";

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

async fn ec2_in(mws: &Mws, region: &'static str) -> aws_sdk_ec2::Client {
    let config = mws.root_sdk_config().await;
    let config = aws_sdk_ec2::config::Builder::from(&config).region(aws_sdk_ec2::config::Region::new(region)).build();
    aws_sdk_ec2::Client::from_conf(config)
}

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

/// Poll an image until it leaves the building states.
async fn wait_for_image(ib: &Client, arn: &str) -> aws_sdk_imagebuilder::types::Image {
    for _ in 0..600 {
        let image = ib.get_image().image_build_version_arn(arn).send().await.unwrap().image.unwrap();
        let status = image.state().and_then(|s| s.status()).cloned().unwrap();
        if matches!(status, ImageStatus::Available | ImageStatus::Failed | ImageStatus::Cancelled) {
            return image;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("image {arn} never finished building");
}

async fn status_of(ib: &Client, arn: &str) -> ImageStatus {
    let image = ib.get_image().image_build_version_arn(arn).send().await.unwrap().image.unwrap();
    image.state().and_then(|s| s.status()).cloned().unwrap()
}

/// The instance profile builds run with, as the Image Builder console
/// creates it.
async fn instance_profile(mws: &Mws) {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let name = "EC2InstanceProfileForImageBuilder";
    if iam.get_instance_profile().instance_profile_name(name).send().await.is_ok() {
        return;
    }
    iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    iam.create_instance_profile().instance_profile_name(name).send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name(name).role_name(name).send().await.unwrap();
}

/// A component, recipe, infrastructure and distribution configuration.
struct Setup {
    component: String,
    recipe: String,
    infra: String,
    dist: String,
}

async fn setup(mws: &Mws, ib: &Client, name: &str) -> Setup {
    instance_profile(mws).await;
    let component = ib
        .create_component()
        .name(format!("{name}-component"))
        .semantic_version("1.0.0")
        .platform("Linux".into())
        .data(COMPONENT)
        .client_token(format!("{name}-c"))
        .send()
        .await
        .unwrap()
        .component_build_version_arn
        .unwrap();
    let recipe = ib
        .create_image_recipe()
        .name(format!("{name}-recipe"))
        .semantic_version("1.0.0")
        .parent_image(AL2023)
        .components(
            ComponentConfiguration::builder()
                .component_arn(&component)
                .parameters(ComponentParameter::builder().name("AuthKey").value("tskey-auth-123").build().unwrap())
                .build()
                .unwrap(),
        )
        .components(
            ComponentConfiguration::builder()
                .component_arn("arn:aws:imagebuilder:us-east-1:aws:component/update-linux/x.x.x")
                .build()
                .unwrap(),
        )
        .client_token(format!("{name}-r"))
        .send()
        .await
        .unwrap()
        .image_recipe_arn
        .unwrap();
    let infra = ib
        .create_infrastructure_configuration()
        .name(format!("{name}-infra"))
        .instance_types("t3.micro")
        .instance_profile_name("EC2InstanceProfileForImageBuilder")
        .terminate_instance_on_failure(true)
        .client_token(format!("{name}-i"))
        .send()
        .await
        .unwrap()
        .infrastructure_configuration_arn
        .unwrap();
    let ami = |region: &str| {
        Distribution::builder().region(region).ami_distribution_configuration(
            AmiDistributionConfiguration::builder()
                .name(format!("{name}-{{{{ imagebuilder:buildDate }}}}"))
                .ami_tags("Role", "tailscale-router")
                .launch_permission(LaunchPermissionConfiguration::builder().user_ids("111122223333").build())
                .build(),
        )
    };
    let dist = ib
        .create_distribution_configuration()
        .name(format!("{name}-dist"))
        .distributions(
            ami("us-east-1")
                .ssm_parameter_configurations(
                    SsmParameterConfiguration::builder()
                        .parameter_name(format!("/amis/{name}/latest"))
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .distributions(ami("eu-west-1").build().unwrap())
        .client_token(format!("{name}-d"))
        .send()
        .await
        .unwrap()
        .distribution_configuration_arn
        .unwrap();
    Setup { component, recipe, infra, dist }
}

#[tokio::test]
async fn pipeline_builds_an_ami_registered_in_ec2() {
    let mws = Mws::start().await;
    let ib = client(&mws).await;
    let s = setup(&mws, &ib, "tailscale").await;
    assert_eq!(s.component, format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:component/tailscale-component/1.0.0/1"));
    assert_eq!(s.recipe, format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:image-recipe/tailscale-recipe/1.0.0"));

    let pipeline = ib
        .create_image_pipeline()
        .name("tailscale")
        .image_recipe_arn(&s.recipe)
        .infrastructure_configuration_arn(&s.infra)
        .distribution_configuration_arn(&s.dist)
        .schedule(
            Schedule::builder()
                .schedule_expression("cron(0 4 ? * mon *)")
                .pipeline_execution_start_condition(PipelineExecutionStartCondition::ExpressionMatchOnly)
                .build(),
        )
        .client_token("p")
        .send()
        .await
        .unwrap()
        .image_pipeline_arn
        .unwrap();
    let got = ib.get_image_pipeline().image_pipeline_arn(&pipeline).send().await.unwrap().image_pipeline.unwrap();
    assert!(got.date_next_run().is_some());
    assert_eq!(got.status().map(|s| s.as_str()), Some("ENABLED"));

    let started =
        ib.start_image_pipeline_execution().image_pipeline_arn(&pipeline).client_token("run-1").send().await.unwrap();
    let image_arn = started.image_build_version_arn.unwrap();
    assert_eq!(image_arn, format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:image/tailscale-recipe/1.0.0/1"));
    // The same client token gets the same build.
    let again =
        ib.start_image_pipeline_execution().image_pipeline_arn(&pipeline).client_token("run-1").send().await.unwrap();
    assert_eq!(again.image_build_version_arn.as_deref(), Some(image_arn.as_str()));

    let image = wait_for_image(&ib, &image_arn).await;
    assert_eq!(image.state().unwrap().status(), Some(&ImageStatus::Available), "{:?}", image.state());
    assert_eq!(image.source_pipeline_arn(), Some(pipeline.as_str()));
    let amis = image.output_resources().unwrap().amis();
    assert_eq!(amis.len(), 2);
    let home = amis.iter().find(|a| a.region() == Some("us-east-1")).unwrap();
    let copy = amis.iter().find(|a| a.region() == Some("eu-west-1")).unwrap();
    let home_id = home.image().unwrap().to_string();
    assert!(home.name().unwrap().starts_with("tailscale-20"), "{:?}", home.name());

    // The AMIs are ordinary EC2 images, in both Regions.
    let ec2 = ec2_in(&mws, "us-east-1").await;
    let described = ec2.describe_images().image_ids(&home_id).send().await.unwrap();
    let ami = &described.images()[0];
    assert_eq!(ami.name(), home.name());
    let tag = |k: &str| ami.tags().iter().find(|t| t.key() == Some(k)).and_then(|t| t.value()).map(str::to_string);
    assert_eq!(tag("Role").as_deref(), Some("tailscale-router"));
    assert_eq!(tag("Ec2ImageBuilderArn").as_deref(), Some(image_arn.as_str()));
    let perms = ec2
        .describe_image_attribute()
        .image_id(&home_id)
        .attribute(aws_sdk_ec2::types::ImageAttributeName::LaunchPermission)
        .send()
        .await
        .unwrap();
    assert!(perms.launch_permissions().iter().any(|p| p.user_id() == Some("111122223333")));
    let eu = ec2_in(&mws, "eu-west-1").await;
    let eu_images = eu.describe_images().image_ids(copy.image().unwrap()).send().await.unwrap();
    assert_eq!(eu_images.images().len(), 1);
    // Build and test instances are gone.
    let running = ec2
        .describe_instances()
        .filters(Filter::builder().name("instance-state-name").values("running").build())
        .send()
        .await
        .unwrap();
    assert!(running.reservations().is_empty());
    // An instance launches from the new AMI.
    let run = ec2
        .run_instances()
        .image_id(&home_id)
        .instance_type(aws_sdk_ec2::types::InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    assert_eq!(run.instances()[0].image_id(), Some(home_id.as_str()));

    // The distribution wrote the SSM parameter.
    let ssm = aws_sdk_ssm::Client::new(&mws.root_sdk_config().await);
    let param = ssm.get_parameter().name("/amis/tailscale/latest").send().await.unwrap();
    assert_eq!(param.parameter().unwrap().value(), Some(home_id.as_str()));

    // Listings.
    let images = ib.list_image_pipeline_images().image_pipeline_arn(&pipeline).send().await.unwrap();
    assert_eq!(images.image_summary_list().len(), 1);
    let listed = ib.list_images().owner(Ownership::SelfValue).send().await.unwrap();
    let version = listed.image_version_list().iter().find(|v| v.name() == Some("tailscale-recipe")).unwrap();
    assert_eq!(
        version.arn(),
        Some(format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:image/tailscale-recipe/1.0.0").as_str())
    );
    let builds = ib.list_image_build_versions().image_version_arn(version.arn().unwrap()).send().await.unwrap();
    assert_eq!(builds.image_summary_list()[0].arn(), Some(image_arn.as_str()));
    let packages = ib.list_image_packages().image_build_version_arn(&image_arn).send().await.unwrap();
    assert!(packages.image_package_list().iter().all(|p| p.package_name().is_some()));
    let findings = ib.list_image_scan_findings().send().await.unwrap();
    assert!(findings.findings().is_empty());
    let aggregations = ib.list_image_scan_finding_aggregations().send().await.unwrap();
    assert!(aggregations.responses().is_empty());

    // Workflow executions: AWS's build-image then test-image.
    let execs = ib.list_workflow_executions().image_build_version_arn(&image_arn).send().await.unwrap();
    let names: Vec<_> =
        execs.workflow_executions().iter().filter_map(|e| e.workflow_build_version_arn()).map(str::to_string).collect();
    assert!(names[0].contains(":workflow/build/build-image/"), "{names:?}");
    assert!(names[1].contains(":workflow/test/test-image/"), "{names:?}");
    let build_exec = execs.workflow_executions()[0].workflow_execution_id().unwrap().to_string();
    let exec = ib.get_workflow_execution().workflow_execution_id(&build_exec).send().await.unwrap();
    assert_eq!(exec.status().map(|s| s.as_str()), Some("COMPLETED"));
    let steps = ib.list_workflow_step_executions().workflow_execution_id(&build_exec).send().await.unwrap();
    let step_names: Vec<_> = steps.steps().iter().filter_map(|s| s.name()).collect();
    assert_eq!(step_names[0], "LaunchBuildInstance");
    assert!(step_names.contains(&"CreateOutputAMI"));
    let create = steps.steps().iter().find(|s| s.name() == Some("CreateOutputAMI")).unwrap();
    let step =
        ib.get_workflow_step_execution().step_execution_id(create.step_execution_id().unwrap()).send().await.unwrap();
    assert_eq!(step.action(), Some("CreateImage"));
    assert!(step.outputs().unwrap().contains("ami-"), "{:?}", step.outputs());

    // Logs went to CloudWatch Logs.
    let logs = aws_sdk_cloudwatchlogs::Client::new(&mws.root_sdk_config().await);
    let streams =
        logs.describe_log_streams().log_group_name("/aws/imagebuilder/tailscale-recipe").send().await.unwrap();
    assert!(!streams.log_streams().is_empty());

    // A second run is build 2; the pipeline remembers the last run.
    let second =
        ib.start_image_pipeline_execution().image_pipeline_arn(&pipeline).client_token("run-2").send().await.unwrap();
    let second = second.image_build_version_arn.unwrap();
    assert!(second.ends_with("/1.0.0/2"));
    assert_eq!(wait_for_image(&ib, &second).await.state().unwrap().status(), Some(&ImageStatus::Available));
    let got = ib.get_image_pipeline().image_pipeline_arn(&pipeline).send().await.unwrap().image_pipeline.unwrap();
    assert!(got.date_last_run().is_some());

    // Resources in use can't be deleted.
    let err = ib.delete_image_recipe().image_recipe_arn(&s.recipe).send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceDependencyException");
    let err = ib.delete_component().component_build_version_arn(&s.component).send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceDependencyException");

    // Deleting the image leaves the AMI (as in AWS); then tear down.
    ib.delete_image().image_build_version_arn(&second).send().await.unwrap();
    let err = ib.get_image().image_build_version_arn(&second).send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceNotFoundException");
    ib.delete_image_pipeline().image_pipeline_arn(&pipeline).send().await.unwrap();
    ib.delete_image().image_build_version_arn(&image_arn).send().await.unwrap();
    ib.delete_image_recipe().image_recipe_arn(&s.recipe).send().await.unwrap();
    ib.delete_component().component_build_version_arn(&s.component).send().await.unwrap();
    ib.delete_infrastructure_configuration().infrastructure_configuration_arn(&s.infra).send().await.unwrap();
    ib.delete_distribution_configuration().distribution_configuration_arn(&s.dist).send().await.unwrap();
    assert_eq!(ec2.describe_images().image_ids(&home_id).send().await.unwrap().images().len(), 1);
}

#[tokio::test]
async fn components_recipes_and_versions() {
    let mws = Mws::start().await;
    let ib = client(&mws).await;

    for v in ["1.0.0", "1.1.0", "2.0.0"] {
        ib.create_component()
            .name("versions")
            .semantic_version(v)
            .platform("Linux".into())
            .data(COMPONENT)
            .change_description(format!("release {v}"))
            .tags("team", "net")
            .send()
            .await
            .unwrap();
    }
    let err = ib
        .create_component()
        .name("versions")
        .semantic_version("1.0.0")
        .platform("Linux".into())
        .data(COMPONENT)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ResourceInUseException", "{}", message(&err));
    let err = ib
        .create_component()
        .name("broken")
        .semantic_version("1.0.0")
        .platform("Linux".into())
        .data("schemaVersion: 1.0\nphases:\n  - name: deploy\n    steps: []\n")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    let err = ib
        .create_component()
        .name("badversion")
        .semantic_version("1.0")
        .platform("Linux".into())
        .data(COMPONENT)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidRequestException", "{}", message(&err));

    let mine = ib.list_components().owner(Ownership::SelfValue).send().await.unwrap();
    let versions: Vec<_> = mine.component_version_list().iter().filter_map(|c| c.version()).collect();
    assert_eq!(versions, ["1.0.0", "1.1.0", "2.0.0"]);
    let by_name = ib.list_components().owner(Ownership::SelfValue).by_name(true).send().await.unwrap();
    assert_eq!(by_name.component_version_list().len(), 1);
    let amazon = ib.list_components().owner(Ownership::Amazon).send().await.unwrap();
    assert!(amazon.component_version_list().iter().any(|c| c.name() == Some("update-linux")));
    let builds = ib
        .list_component_build_versions()
        .component_version_arn(format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:component/versions/1.1.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(builds.component_summary_list().len(), 1);
    assert_eq!(builds.component_summary_list()[0].change_description(), Some("release 1.1.0"));

    // Wildcards resolve to the newest matching version.
    let latest = ib
        .get_component()
        .component_build_version_arn(format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:component/versions/1.x.x"))
        .send()
        .await
        .unwrap();
    assert_eq!(latest.component().unwrap().version(), Some("1.1.0"));
    assert_eq!(latest.component().unwrap().r#type().map(|t| t.as_str()), Some("BUILD"));
    let params = latest.component().unwrap().parameters();
    assert_eq!(params[0].name(), "AuthKey");

    // Import a shell script as a component.
    let imported = ib
        .import_component()
        .name("imported")
        .semantic_version("1.0.0")
        .r#type(aws_sdk_imagebuilder::types::ComponentType::Test)
        .format(aws_sdk_imagebuilder::types::ComponentFormat::Shell)
        .platform("Linux".into())
        .data("echo hello")
        .client_token("imp")
        .send()
        .await
        .unwrap();
    let imported = imported.component_build_version_arn.unwrap();
    let doc = ib.get_component().component_build_version_arn(&imported).send().await.unwrap();
    assert!(doc.component().unwrap().data().unwrap().contains("echo hello"));

    // A test component as a recipe's component, and unknown parameters.
    let test = ib
        .create_component()
        .name("smoke")
        .semantic_version("1.0.0")
        .platform("Linux".into())
        .data(TEST_COMPONENT)
        .send()
        .await
        .unwrap()
        .component_build_version_arn
        .unwrap();
    assert_eq!(
        ib.get_component()
            .component_build_version_arn(&test)
            .send()
            .await
            .unwrap()
            .component()
            .unwrap()
            .r#type()
            .map(|t| t.as_str()),
        Some("TEST")
    );
    let err = ib
        .create_image_recipe()
        .name("bad-params")
        .semantic_version("1.0.0")
        .parent_image(AL2023)
        .components(
            ComponentConfiguration::builder()
                .component_arn(format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:component/versions/1.0.0/1"))
                .parameters(ComponentParameter::builder().name("Nope").value("x").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    let err = ib
        .create_image_recipe()
        .name("missing")
        .semantic_version("1.0.0")
        .parent_image(AL2023)
        .components(
            ComponentConfiguration::builder()
                .component_arn(format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:component/nope/1.0.0/1"))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));

    let recipe = ib
        .create_image_recipe()
        .name("router")
        .semantic_version("1.0.0")
        .parent_image(AL2023)
        .components(ComponentConfiguration::builder().component_arn(&test).build().unwrap())
        .working_directory("/opt/build")
        .send()
        .await
        .unwrap()
        .image_recipe_arn
        .unwrap();
    let got = ib.get_image_recipe().image_recipe_arn(&recipe).send().await.unwrap().image_recipe.unwrap();
    assert_eq!(got.parent_image(), Some(AL2023));
    assert_eq!(got.working_directory(), Some("/opt/build"));
    let recipes = ib.list_image_recipes().owner(Ownership::SelfValue).send().await.unwrap();
    assert_eq!(recipes.image_recipe_summary_list().len(), 1);
    let managed = ib.list_images().owner(Ownership::Amazon).send().await.unwrap();
    assert!(managed.image_version_list().iter().any(|i| i.name() == Some("amazon-linux-2023-x86")));

    // Container recipes.
    let container = ib
        .create_container_recipe()
        .container_type(ContainerType::Docker)
        .name("web")
        .semantic_version("1.0.0")
        .parent_image("amazonlinux:2023")
        .components(ComponentConfiguration::builder().component_arn(&test).build().unwrap())
        .dockerfile_template_data("FROM {{{ imagebuilder:parentImage }}}\n{{{ imagebuilder:environments }}}\n{{{ imagebuilder:components }}}\n")
        .target_repository(
            TargetContainerRepository::builder()
                .service(ContainerRepositoryService::Ecr)
                .repository_name("web")
                .build()
                .unwrap(),
        )
        .client_token("cr")
        .send()
        .await
        .unwrap()
        .container_recipe_arn
        .unwrap();
    let got = ib.get_container_recipe().container_recipe_arn(&container).send().await.unwrap();
    assert_eq!(got.container_recipe().unwrap().parent_image(), Some("amazonlinux:2023"));
    let listed = ib.list_container_recipes().send().await.unwrap();
    assert_eq!(listed.container_recipe_summary_list().len(), 1);
    ib.delete_container_recipe().container_recipe_arn(&container).send().await.unwrap();

    // Tags.
    let arn = format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:component/versions/2.0.0/1");
    ib.tag_resource().resource_arn(&arn).tags("env", "prod").send().await.unwrap();
    ib.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let tags = ib.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    let tags = tags.tags().unwrap();
    assert_eq!(tags.get("env").map(String::as_str), Some("prod"));
    assert!(!tags.contains_key("team"));
    let err = ib
        .list_tags_for_resource()
        .resource_arn(format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:component/ghost/1.0.0/1"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ResourceNotFoundException");

    // Idempotency: same token, other parameters.
    ib.create_component()
        .name("idem")
        .semantic_version("1.0.0")
        .platform("Linux".into())
        .data(COMPONENT)
        .client_token("tok")
        .send()
        .await
        .unwrap();
    let err = ib
        .create_component()
        .name("idem")
        .semantic_version("1.0.1")
        .platform("Linux".into())
        .data(COMPONENT)
        .client_token("tok")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "IdempotentParameterMismatchException");

    ib.delete_image_recipe().image_recipe_arn(&recipe).send().await.unwrap();
    ib.delete_component().component_build_version_arn(&test).send().await.unwrap();
    ib.delete_component().component_build_version_arn(&imported).send().await.unwrap();
}

#[tokio::test]
async fn infrastructure_and_distribution_configurations() {
    let mws = Mws::start().await;
    let ib = client(&mws).await;
    let err = ib
        .create_infrastructure_configuration()
        .name("no-profile")
        .instance_profile_name("EC2InstanceProfileForImageBuilder")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    instance_profile(&mws).await;

    let infra = ib
        .create_infrastructure_configuration()
        .name("infra")
        .instance_profile_name("EC2InstanceProfileForImageBuilder")
        .instance_types("m5.large")
        .description("first")
        .resource_tags("cost", "amis")
        .send()
        .await
        .unwrap()
        .infrastructure_configuration_arn
        .unwrap();
    let err = ib
        .create_infrastructure_configuration()
        .name("infra")
        .instance_profile_name("EC2InstanceProfileForImageBuilder")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ResourceAlreadyExistsException", "{}", message(&err));
    let err = ib
        .create_infrastructure_configuration()
        .name("bad-subnet")
        .instance_profile_name("EC2InstanceProfileForImageBuilder")
        .subnet_id("subnet-00000000")
        .security_group_ids("sg-00000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    ib.update_infrastructure_configuration()
        .infrastructure_configuration_arn(&infra)
        .instance_profile_name("EC2InstanceProfileForImageBuilder")
        .description("second")
        .send()
        .await
        .unwrap();
    let got = ib
        .get_infrastructure_configuration()
        .infrastructure_configuration_arn(&infra)
        .send()
        .await
        .unwrap()
        .infrastructure_configuration
        .unwrap();
    assert_eq!(got.description(), Some("second"));
    assert!(got.date_updated().is_some());
    let listed = ib.list_infrastructure_configurations().send().await.unwrap();
    assert_eq!(listed.infrastructure_configuration_summary_list().len(), 1);

    let dist = ib
        .create_distribution_configuration()
        .name("dist")
        .distributions(
            Distribution::builder()
                .region("us-east-1")
                .ami_distribution_configuration(
                    AmiDistributionConfiguration::builder().name("x-{{ imagebuilder:buildDate }}").build(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .distribution_configuration_arn
        .unwrap();
    let err = ib
        .create_distribution_configuration()
        .name("dupe-regions")
        .distributions(Distribution::builder().region("us-east-1").build().unwrap())
        .distributions(Distribution::builder().region("us-east-1").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    ib.update_distribution_configuration()
        .distribution_configuration_arn(&dist)
        .description("updated")
        .distributions(Distribution::builder().region("us-west-2").build().unwrap())
        .send()
        .await
        .unwrap();
    let got = ib
        .get_distribution_configuration()
        .distribution_configuration_arn(&dist)
        .send()
        .await
        .unwrap()
        .distribution_configuration
        .unwrap();
    assert_eq!(got.distributions()[0].region(), "us-west-2");
    let listed = ib.list_distribution_configurations().send().await.unwrap();
    assert_eq!(listed.distribution_configuration_summary_list()[0].regions(), ["us-west-2"]);

    // Pipelines: update, disable, list.
    let component = ib
        .create_component()
        .name("pipeline-component")
        .semantic_version("1.0.0")
        .platform("Linux".into())
        .data(COMPONENT)
        .send()
        .await
        .unwrap()
        .component_build_version_arn
        .unwrap();
    let recipe = ib
        .create_image_recipe()
        .name("pipeline-recipe")
        .semantic_version("1.0.0")
        .parent_image(AL2023)
        .components(ComponentConfiguration::builder().component_arn(&component).build().unwrap())
        .send()
        .await
        .unwrap()
        .image_recipe_arn
        .unwrap();
    let pipeline = ib
        .create_image_pipeline()
        .name("pipeline")
        .image_recipe_arn(&recipe)
        .infrastructure_configuration_arn(&infra)
        .send()
        .await
        .unwrap()
        .image_pipeline_arn
        .unwrap();
    let err = ib
        .create_image_pipeline()
        .name("bad-cron")
        .image_recipe_arn(&recipe)
        .infrastructure_configuration_arn(&infra)
        .schedule(Schedule::builder().schedule_expression("cron(nope)").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    ib.update_image_pipeline()
        .image_pipeline_arn(&pipeline)
        .image_recipe_arn(&recipe)
        .infrastructure_configuration_arn(&infra)
        .distribution_configuration_arn(&dist)
        .status(aws_sdk_imagebuilder::types::PipelineStatus::Disabled)
        .send()
        .await
        .unwrap();
    let pipelines = ib.list_image_pipelines().send().await.unwrap();
    assert_eq!(pipelines.image_pipeline_list()[0].status().map(|s| s.as_str()), Some("DISABLED"));

    let err =
        ib.delete_infrastructure_configuration().infrastructure_configuration_arn(&infra).send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceDependencyException");
    ib.delete_image_pipeline().image_pipeline_arn(&pipeline).send().await.unwrap();
    ib.delete_infrastructure_configuration().infrastructure_configuration_arn(&infra).send().await.unwrap();
    ib.delete_distribution_configuration().distribution_configuration_arn(&dist).send().await.unwrap();
    let err = ib.get_distribution_configuration().distribution_configuration_arn(&dist).send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceNotFoundException");
}

#[tokio::test]
async fn custom_workflows_wait_for_actions() {
    let mws = Mws::start().await;
    let ib = client(&mws).await;
    let s = setup(&mws, &ib, "wf").await;

    let workflow = ib
        .create_workflow()
        .name("approve-then-build")
        .semantic_version("1.0.0")
        .r#type(WorkflowType::Build)
        .data(WAIT_WORKFLOW)
        .client_token("w")
        .send()
        .await
        .unwrap()
        .workflow_build_version_arn
        .unwrap();
    assert_eq!(workflow, format!("arn:aws:imagebuilder:us-east-1:{ACCOUNT}:workflow/build/approve-then-build/1.0.0/1"));
    let err = ib
        .create_workflow()
        .name("bad")
        .semantic_version("1.0.0")
        .r#type(WorkflowType::Build)
        .data("name: bad\nschemaVersion: 1.0\nsteps:\n  - name: X\n    action: Teleport\n")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    let got = ib.get_workflow().workflow_build_version_arn(&workflow).send().await.unwrap().workflow.unwrap();
    assert_eq!(got.r#type().map(|t| t.as_str()), Some("BUILD"));
    let listed = ib.list_workflows().owner(Ownership::SelfValue).send().await.unwrap();
    assert_eq!(listed.workflow_version_list().len(), 1);
    let amazon = ib.list_workflows().owner(Ownership::Amazon).send().await.unwrap();
    assert!(amazon.workflow_version_list().iter().any(|w| w.name() == Some("build-image")));
    let builds = ib
        .list_workflow_build_versions()
        .workflow_version_arn(format!(
            "arn:aws:imagebuilder:us-east-1:{ACCOUNT}:workflow/build/approve-then-build/1.0.0"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(builds.workflow_summary_list().len(), 1);

    // An image built directly (no pipeline) with the custom workflow.
    let image = ib
        .create_image()
        .image_recipe_arn(&s.recipe)
        .infrastructure_configuration_arn(&s.infra)
        .workflows(WorkflowConfiguration::builder().workflow_arn(&workflow).build().unwrap())
        .execution_role(format!(
            "arn:aws:iam::{ACCOUNT}:role/aws-service-role/imagebuilder.amazonaws.com/AWSServiceRoleForImageBuilder"
        ))
        .client_token("img")
        .send()
        .await
        .unwrap()
        .image_build_version_arn
        .unwrap();
    let mut waiting = None;
    for _ in 0..300 {
        let steps = ib.list_waiting_workflow_steps().send().await.unwrap();
        if let Some(step) = steps.steps().first() {
            waiting = Some(step.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let waiting = waiting.expect("the build waits for an action");
    assert_eq!(waiting.name(), Some("Approval"));
    assert_eq!(waiting.image_build_version_arn(), Some(image.as_str()));
    assert_eq!(status_of(&ib, &image).await, ImageStatus::Building);
    let sent = ib
        .send_workflow_step_action()
        .step_execution_id(waiting.step_execution_id().unwrap())
        .image_build_version_arn(&image)
        .action(WorkflowStepActionType::Resume)
        .reason("looks good")
        .client_token("resume")
        .send()
        .await
        .unwrap();
    assert_eq!(sent.step_execution_id(), waiting.step_execution_id());
    let done = wait_for_image(&ib, &image).await;
    assert_eq!(done.state().unwrap().status(), Some(&ImageStatus::Available), "{:?}", done.state());
    // No distribution configuration: one AMI, in the build Region.
    assert_eq!(done.output_resources().unwrap().amis().len(), 1);

    // A second build is stopped at the approval step.
    let stopped = ib
        .create_image()
        .image_recipe_arn(&s.recipe)
        .infrastructure_configuration_arn(&s.infra)
        .workflows(WorkflowConfiguration::builder().workflow_arn(&workflow).build().unwrap())
        .execution_role(format!(
            "arn:aws:iam::{ACCOUNT}:role/aws-service-role/imagebuilder.amazonaws.com/AWSServiceRoleForImageBuilder"
        ))
        .send()
        .await
        .unwrap()
        .image_build_version_arn
        .unwrap();
    let mut step_id = None;
    for _ in 0..300 {
        let steps = ib.list_waiting_workflow_steps().send().await.unwrap();
        if let Some(step) = steps.steps().iter().find(|s| s.image_build_version_arn() == Some(stopped.as_str())) {
            step_id = step.step_execution_id().map(str::to_string);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ib.send_workflow_step_action()
        .step_execution_id(step_id.unwrap())
        .image_build_version_arn(&stopped)
        .action(WorkflowStepActionType::Stop)
        .send()
        .await
        .unwrap();
    let failed = wait_for_image(&ib, &stopped).await;
    assert_eq!(failed.state().unwrap().status(), Some(&ImageStatus::Failed));

    // Retry runs the same build version again.
    let retried = ib.retry_image().image_build_version_arn(&stopped).client_token("retry").send().await.unwrap();
    let retried = retried.image_build_version_arn.unwrap();
    assert_eq!(retried, stopped);

    // Cancel stops a build in progress.
    let cancelled =
        ib.cancel_image_creation().image_build_version_arn(&retried).client_token("cancel").send().await.unwrap();
    assert_eq!(cancelled.image_build_version_arn(), Some(retried.as_str()));
    assert_eq!(wait_for_image(&ib, &retried).await.state().unwrap().status(), Some(&ImageStatus::Cancelled));
    let err =
        ib.cancel_image_creation().image_build_version_arn(&image).client_token("cancel-2").send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceInUseException", "{}", message(&err));

    // Distribute the finished image again with another configuration.
    let dist2 = ib
        .create_distribution_configuration()
        .name("west")
        .distributions(Distribution::builder().region("us-west-2").build().unwrap())
        .send()
        .await
        .unwrap()
        .distribution_configuration_arn
        .unwrap();
    let redistributed = ib
        .distribute_image()
        .source_image(&image)
        .distribution_configuration_arn(&dist2)
        .execution_role(format!(
            "arn:aws:iam::{ACCOUNT}:role/aws-service-role/imagebuilder.amazonaws.com/AWSServiceRoleForImageBuilder"
        ))
        .client_token("distribute")
        .send()
        .await
        .unwrap()
        .image_build_version_arn
        .unwrap();
    let redistributed = wait_for_image(&ib, &redistributed).await;
    assert_eq!(redistributed.state().unwrap().status(), Some(&ImageStatus::Available), "{:?}", redistributed.state());
    let west = redistributed.output_resources().unwrap().amis();
    assert!(west.iter().any(|a| a.region() == Some("us-west-2")));

    ib.delete_workflow().workflow_build_version_arn(&workflow).send().await.unwrap();
    let err = ib.get_workflow().workflow_build_version_arn(&workflow).send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceNotFoundException");
}

#[tokio::test]
async fn lifecycle_policies_deprecate_and_delete_amis() {
    let mws = Mws::start().await;
    let ib = client(&mws).await;
    let s = setup(&mws, &ib, "life").await;
    let pipeline = ib
        .create_image_pipeline()
        .name("life")
        .image_recipe_arn(&s.recipe)
        .infrastructure_configuration_arn(&s.infra)
        .send()
        .await
        .unwrap()
        .image_pipeline_arn
        .unwrap();
    let mut images = Vec::new();
    for i in 0..3 {
        let arn = ib
            .start_image_pipeline_execution()
            .image_pipeline_arn(&pipeline)
            .client_token(format!("life-{i}"))
            .send()
            .await
            .unwrap()
            .image_build_version_arn
            .unwrap();
        assert_eq!(wait_for_image(&ib, &arn).await.state().unwrap().status(), Some(&ImageStatus::Available));
        images.push(arn);
    }

    // A manual state update deletes the oldest image's AMI.
    let ec2 = ec2_in(&mws, "us-east-1").await;
    let oldest = ib.get_image().image_build_version_arn(&images[0]).send().await.unwrap().image.unwrap();
    let ami = oldest.output_resources().unwrap().amis()[0].image().unwrap().to_string();
    let role = format!(
        "arn:aws:iam::{ACCOUNT}:role/aws-service-role/imagebuilder.amazonaws.com/AWSServiceRoleForImageBuilder"
    );
    let update = ib
        .start_resource_state_update()
        .resource_arn(&images[0])
        .state(ResourceState::builder().status(ResourceStatus::Deleted).build())
        .execution_role(&role)
        .client_token("delete-oldest")
        .send()
        .await
        .unwrap();
    let execution = update.lifecycle_execution_id.unwrap();
    let got = ib.get_lifecycle_execution().lifecycle_execution_id(&execution).send().await.unwrap();
    assert_eq!(got.lifecycle_execution().unwrap().state().unwrap().status().map(|s| s.as_str()), Some("SUCCESS"));
    let resources = ib.list_lifecycle_execution_resources().lifecycle_execution_id(&execution).send().await.unwrap();
    assert_eq!(resources.resources()[0].resource_id(), Some(ami.as_str()));
    let err = ec2.describe_images().image_ids(&ami).send().await.unwrap_err();
    assert_eq!(aws_sdk_ec2::error::ProvideErrorMetadata::code(&err), Some("InvalidAMIID.NotFound"));
    assert_eq!(status_of(&ib, &images[0]).await, ImageStatus::Deleted);
    let err =
        ib.cancel_lifecycle_execution().lifecycle_execution_id(&execution).client_token("c").send().await.unwrap_err();
    assert_eq!(code(&err), "ResourceInUseException", "{}", message(&err));

    // A policy keeps one image and deprecates the rest, once a day.
    let policy = ib
        .create_lifecycle_policy()
        .name("keep-one")
        .execution_role(&role)
        .resource_type(LifecyclePolicyResourceType::AmiImage)
        .status(LifecyclePolicyStatus::Enabled)
        .policy_details(
            LifecyclePolicyDetail::builder()
                .action(
                    LifecyclePolicyDetailAction::builder()
                        .r#type(LifecyclePolicyDetailActionType::Deprecate)
                        .build()
                        .unwrap(),
                )
                .filter(
                    LifecyclePolicyDetailFilter::builder()
                        .r#type(LifecyclePolicyDetailFilterType::Count)
                        .value(1)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .resource_selection(
            LifecyclePolicyResourceSelection::builder()
                .recipes(
                    aws_sdk_imagebuilder::types::LifecyclePolicyResourceSelectionRecipe::builder()
                        .name("life-recipe")
                        .semantic_version("1.0.0")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .client_token("lp")
        .send()
        .await
        .unwrap()
        .lifecycle_policy_arn
        .unwrap();
    let err = ib
        .create_lifecycle_policy()
        .name("bad")
        .execution_role(&role)
        .resource_type(LifecyclePolicyResourceType::AmiImage)
        .policy_details(
            LifecyclePolicyDetail::builder()
                .action(
                    LifecyclePolicyDetailAction::builder()
                        .r#type(LifecyclePolicyDetailActionType::Delete)
                        .build()
                        .unwrap(),
                )
                .filter(
                    LifecyclePolicyDetailFilter::builder()
                        .r#type(LifecyclePolicyDetailFilterType::Age)
                        .value(3)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .resource_selection(LifecyclePolicyResourceSelection::builder().tag_map("a", "b").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    ib.update_lifecycle_policy()
        .lifecycle_policy_arn(&policy)
        .description("keep the newest")
        .execution_role(&role)
        .resource_type(LifecyclePolicyResourceType::AmiImage)
        .policy_details(
            LifecyclePolicyDetail::builder()
                .action(
                    LifecyclePolicyDetailAction::builder()
                        .r#type(LifecyclePolicyDetailActionType::Deprecate)
                        .build()
                        .unwrap(),
                )
                .filter(
                    LifecyclePolicyDetailFilter::builder()
                        .r#type(LifecyclePolicyDetailFilterType::Count)
                        .value(1)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .resource_selection(
            LifecyclePolicyResourceSelection::builder()
                .recipes(
                    aws_sdk_imagebuilder::types::LifecyclePolicyResourceSelectionRecipe::builder()
                        .name("life-recipe")
                        .semantic_version("1.0.x")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let got = ib.get_lifecycle_policy().lifecycle_policy_arn(&policy).send().await.unwrap().lifecycle_policy.unwrap();
    assert_eq!(got.description(), Some("keep the newest"));
    assert_eq!(ib.list_lifecycle_policies().send().await.unwrap().lifecycle_policy_summary_list().len(), 1);

    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 90000}"#)).await;
    assert_eq!(status, 200);
    let mut runs = Vec::new();
    for _ in 0..100 {
        // Any request lets Image Builder see the new time.
        runs =
            ib.list_lifecycle_executions().resource_arn(&policy).send().await.unwrap().lifecycle_executions().to_vec();
        if !runs.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": -90000}"#)).await;
    assert_eq!(runs.len(), 1, "the policy ran");
    assert_eq!(status_of(&ib, &images[1]).await, ImageStatus::Deprecated);
    assert_eq!(status_of(&ib, &images[2]).await, ImageStatus::Available);
    ib.delete_lifecycle_policy().lifecycle_policy_arn(&policy).send().await.unwrap();
}

#[tokio::test]
async fn sharing_imports_and_permissions() {
    let mws = Mws::start().await;
    let ib = client(&mws).await;
    let s = setup(&mws, &ib, "share").await;

    // Resource policies share components, recipes and images.
    let policy = |arn: &str, actions: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["111122223333"]}},"Action":[{actions}],"Resource":["{arn}"]}}]}}"#
        )
    };
    ib.put_component_policy()
        .component_arn(&s.component)
        .policy(policy(&s.component, r#""imagebuilder:GetComponent","imagebuilder:ListComponents""#))
        .send()
        .await
        .unwrap();
    let got = ib.get_component_policy().component_arn(&s.component).send().await.unwrap();
    assert!(got.policy().unwrap().contains("111122223333"));
    let err = ib
        .put_component_policy()
        .component_arn(&s.component)
        .policy(policy(&s.component, r#""imagebuilder:DeleteComponent""#))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    ib.put_image_recipe_policy()
        .image_recipe_arn(&s.recipe)
        .policy(policy(&s.recipe, r#""imagebuilder:GetImageRecipe","imagebuilder:ListImageRecipes""#))
        .send()
        .await
        .unwrap();
    assert!(ib.get_image_recipe_policy().image_recipe_arn(&s.recipe).send().await.unwrap().policy().is_some());

    let container = ib
        .create_container_recipe()
        .container_type(ContainerType::Docker)
        .name("shared-web")
        .semantic_version("1.0.0")
        .parent_image("amazonlinux:2023")
        .components(ComponentConfiguration::builder().component_arn(&s.component).build().unwrap())
        .dockerfile_template_data("FROM {{{ imagebuilder:parentImage }}}\n{{{ imagebuilder:components }}}\n")
        .target_repository(
            TargetContainerRepository::builder()
                .service(ContainerRepositoryService::Ecr)
                .repository_name("web")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .container_recipe_arn
        .unwrap();
    ib.put_container_recipe_policy()
        .container_recipe_arn(&container)
        .policy(policy(&container, r#""imagebuilder:GetContainerRecipe","imagebuilder:ListContainerRecipes""#))
        .send()
        .await
        .unwrap();
    assert!(ib.get_container_recipe_policy().container_recipe_arn(&container).send().await.unwrap().policy().is_some());

    // Import a disk image from S3; it becomes an AMI.
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    s3.create_bucket().bucket("isos").send().await.unwrap();
    s3.put_object().bucket("isos").key("router.iso").body(b"iso".to_vec().into()).send().await.unwrap();
    let imported = ib
        .import_disk_image()
        .name("imported-router")
        .semantic_version("1.0.0")
        .platform("Linux")
        .os_version("Amazon Linux 2023")
        .infrastructure_configuration_arn(&s.infra)
        .uri("s3://isos/router.iso")
        .client_token("iso")
        .send()
        .await
        .unwrap()
        .image_build_version_arn
        .unwrap();
    let image = wait_for_image(&ib, &imported).await;
    assert_eq!(image.state().unwrap().status(), Some(&ImageStatus::Available), "{:?}", image.state());
    assert_eq!(image.image_source().map(|s| s.as_str()), Some("IMPORTED"));
    ib.put_image_policy()
        .image_arn(&imported)
        .policy(policy(&imported, r#""imagebuilder:GetImage","imagebuilder:ListImages""#))
        .send()
        .await
        .unwrap();
    assert!(ib.get_image_policy().image_arn(&imported).send().await.unwrap().policy().is_some());

    // VM Import isn't emulated, so no import task id exists.
    let err = ib
        .import_vm_image()
        .name("vm")
        .semantic_version("1.0.0")
        .platform(aws_sdk_imagebuilder::types::Platform::Linux)
        .vm_import_task_id("import-ami-0123456789abcdef0")
        .client_token("vm")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidParameterValueException", "{}", message(&err));
    let err = ib
        .get_marketplace_resource()
        .resource_type(aws_sdk_imagebuilder::types::MarketplaceResourceType::ComponentData)
        .resource_arn("arn:aws:imagebuilder:us-east-1:aws-marketplace:component/x/1.0.0/1")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "ResourceNotFoundException", "{}", message(&err));

    // IAM: a user without Image Builder permissions is denied.
    let (_, config) = user_with_policy(
        &mws,
        "reader",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"imagebuilder:Get*","Resource":"*"}]}"#,
        ),
    )
    .await;
    let reader = Client::new(&config);
    reader.get_component().component_build_version_arn(&s.component).send().await.unwrap();
    let err = reader
        .create_component()
        .name("nope")
        .semantic_version("1.0.0")
        .platform("Linux".into())
        .data(COMPONENT)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "AccessDeniedException", "{}", message(&err));
}

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// With EC2's Docker backend the components really run on the build
/// instance, and the AMI carries what they did. Skipped without Docker.
#[tokio::test]
async fn components_run_on_docker_instances() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { ec2_backend: mws_ec2::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let ib = client(&mws).await;
    let ec2 = ec2_in(&mws, "us-east-1").await;
    instance_profile(&mws).await;
    let alpine = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap()
        .images()[0]
        .image_id()
        .unwrap()
        .to_string();

    let component = |name: &str, command: &str| {
        format!(
            "name: {name}\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: Marker\n        action: CreateFile\n        inputs:\n          - path: /etc/mws-image-builder\n            content: built by {name}\n      - name: Run\n        action: ExecuteBash\n        inputs:\n          commands:\n            - {command}\n"
        )
    };
    let infra = ib
        .create_infrastructure_configuration()
        .name("docker")
        .instance_profile_name("EC2InstanceProfileForImageBuilder")
        .instance_types("t3.micro")
        .send()
        .await
        .unwrap()
        .infrastructure_configuration_arn
        .unwrap();
    let build = |name: &'static str, command: &'static str| {
        let ib = ib.clone();
        let infra = infra.clone();
        let alpine = alpine.clone();
        let data = component(name, command);
        async move {
            let c = ib
                .create_component()
                .name(name)
                .semantic_version("1.0.0")
                .platform("Linux".into())
                .data(data)
                .send()
                .await
                .unwrap()
                .component_build_version_arn
                .unwrap();
            let recipe = ib
                .create_image_recipe()
                .name(name)
                .semantic_version("1.0.0")
                .parent_image(&alpine)
                .components(ComponentConfiguration::builder().component_arn(c).build().unwrap())
                .send()
                .await
                .unwrap()
                .image_recipe_arn
                .unwrap();
            let image = ib
                .create_image()
                .image_recipe_arn(recipe)
                .infrastructure_configuration_arn(infra)
                .send()
                .await
                .unwrap()
                .image_build_version_arn
                .unwrap();
            wait_for_image(&ib, &image).await
        }
    };

    let good = build("marker", "echo ran > /root/ran").await;
    assert_eq!(good.state().unwrap().status(), Some(&ImageStatus::Available), "{:?}", good.state());
    let ami = good.output_resources().unwrap().amis()[0].image().unwrap().to_string();
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(aws_sdk_ec2::types::InstanceType::T3Micro)
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    let mut contents = String::new();
    for _ in 0..120 {
        let out = std::process::Command::new("docker")
            .args(["exec", &format!("mws-ec2-{id}"), "cat", "/etc/mws-image-builder", "/root/ran"])
            .output()
            .unwrap();
        if out.status.success() {
            contents = String::from_utf8_lossy(&out.stdout).to_string();
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(contents.contains("built by marker") && contents.contains("ran"), "{contents:?}");
    ec2.terminate_instances().instance_ids(&id).send().await.unwrap();

    // A failing command fails the build, and says which step.
    let bad = build("failing", "exit 3").await;
    assert_eq!(bad.state().unwrap().status(), Some(&ImageStatus::Failed));
    let reason = bad.state().unwrap().reason().unwrap_or_default().to_string();
    assert!(reason.contains("Run"), "{reason}");
}

/// Distributions add a launch template version that launches the new AMI.
#[tokio::test]
async fn distribution_updates_launch_templates() {
    let mws = Mws::start().await;
    let ib = client(&mws).await;
    let ec2 = ec2_in(&mws, "us-east-1").await;
    let s = setup(&mws, &ib, "lt").await;
    let alpine = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap()
        .images()[0]
        .image_id()
        .unwrap()
        .to_string();
    let lt = |name: &'static str| {
        let ec2 = ec2.clone();
        let alpine = alpine.clone();
        async move {
            ec2.create_launch_template()
                .launch_template_name(name)
                .launch_template_data(
                    aws_sdk_ec2::types::RequestLaunchTemplateData::builder()
                        .image_id(alpine)
                        .instance_type(aws_sdk_ec2::types::InstanceType::T3Micro)
                        .build(),
                )
                .send()
                .await
                .unwrap()
                .launch_template()
                .unwrap()
                .launch_template_id()
                .unwrap()
                .to_string()
        }
    };
    let default_lt = lt("routers").await;
    let latest_only = lt("canary").await;

    let dist = ib
        .create_distribution_configuration()
        .name("with-templates")
        .distributions(
            Distribution::builder()
                .region("us-east-1")
                .launch_template_configurations(
                    LaunchTemplateConfiguration::builder()
                        .launch_template_id(&default_lt)
                        .set_default_version(true)
                        .build()
                        .unwrap(),
                )
                .launch_template_configurations(
                    LaunchTemplateConfiguration::builder().launch_template_id(&latest_only).build().unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .distribution_configuration_arn
        .unwrap();
    let image = ib
        .create_image()
        .image_recipe_arn(&s.recipe)
        .infrastructure_configuration_arn(&s.infra)
        .distribution_configuration_arn(&dist)
        .send()
        .await
        .unwrap()
        .image_build_version_arn
        .unwrap();
    let image = wait_for_image(&ib, &image).await;
    assert_eq!(image.state().unwrap().status(), Some(&ImageStatus::Available), "{:?}", image.state());
    let ami = image.output_resources().unwrap().amis()[0].image().unwrap().to_string();

    let default = ec2
        .describe_launch_template_versions()
        .launch_template_id(&default_lt)
        .versions("$Default")
        .send()
        .await
        .unwrap();
    let v = &default.launch_template_versions()[0];
    assert_eq!(v.version_number(), Some(2));
    assert_eq!(v.launch_template_data().unwrap().image_id(), Some(ami.as_str()));
    // The rest of the template data carries over from the latest version.
    assert_eq!(v.launch_template_data().unwrap().instance_type(), Some(&aws_sdk_ec2::types::InstanceType::T3Micro));

    let canary = ec2.describe_launch_templates().launch_template_ids(&latest_only).send().await.unwrap();
    let canary = &canary.launch_templates()[0];
    assert_eq!(canary.latest_version_number(), Some(2));
    assert_eq!(canary.default_version_number(), Some(1));

    // A template that doesn't exist fails the distribution.
    let missing = ib
        .create_distribution_configuration()
        .name("missing-template")
        .distributions(
            Distribution::builder()
                .region("us-east-1")
                .launch_template_configurations(
                    LaunchTemplateConfiguration::builder().launch_template_id("lt-0123456789abcdef0").build().unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .distribution_configuration_arn
        .unwrap();
    let failed = ib
        .create_image()
        .image_recipe_arn(&s.recipe)
        .infrastructure_configuration_arn(&s.infra)
        .distribution_configuration_arn(&missing)
        .send()
        .await
        .unwrap()
        .image_build_version_arn
        .unwrap();
    let failed = wait_for_image(&ib, &failed).await;
    assert_eq!(failed.state().unwrap().status(), Some(&ImageStatus::Failed));
    assert!(failed.state().unwrap().reason().unwrap().contains("lt-0123456789abcdef0"), "{:?}", failed.state());
}
