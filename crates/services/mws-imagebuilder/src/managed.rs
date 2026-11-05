//! AWS-managed resources every account sees: components, parent images
//! and the default workflows (owner `Amazon`, account `aws` in ARNs).

use crate::generated::types as t;

pub struct ManagedComponent {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub data: &'static str,
}

pub const COMPONENTS: &[ManagedComponent] = &[
    ManagedComponent {
        name: "update-linux",
        version: "1.0.2",
        description: "Updates Linux with the latest security updates.",
        data: "name: update-linux\ndescription: Updates Linux with the latest security updates.\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: UpdateOS\n        action: UpdateOS\n  - name: validate\n    steps:\n      - name: Validate\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"OS updated\"\n",
    },
    ManagedComponent {
        name: "hello-world-linux",
        version: "1.0.0",
        description: "Hello world component for Linux.",
        data: "name: hello-world-linux\ndescription: Hello world component for Linux.\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Build.\"\n  - name: validate\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Validate.\"\n  - name: test\n    steps:\n      - name: HelloWorldStep\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Hello World! Test.\"\n",
    },
    ManagedComponent {
        name: "reboot-linux",
        version: "1.0.1",
        description: "Reboots the instance.",
        data: "name: reboot-linux\ndescription: Reboots the instance.\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: Reboot\n        action: Reboot\n",
    },
    ManagedComponent {
        name: "simple-boot-test-linux",
        version: "1.0.0",
        description: "Checks that the instance boots.",
        data: "name: simple-boot-test-linux\ndescription: Checks that the instance boots.\nschemaVersion: 1.0\nphases:\n  - name: test\n    steps:\n      - name: BootTest\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo \"Instance booted\"\n            - test -d /\n",
    },
    ManagedComponent {
        name: "aws-cli-version-2-linux",
        version: "1.0.4",
        description: "Installs the latest version of the AWS CLI version 2.",
        data: "name: aws-cli-version-2-linux\ndescription: Installs the latest version of the AWS CLI version 2.\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: InstallAwsCli\n        action: ExecuteBash\n        inputs:\n          commands:\n            - |\n              if command -v aws >/dev/null 2>&1; then exit 0; fi\n              if command -v dnf >/dev/null 2>&1; then dnf -y install awscli-2 || dnf -y install awscli\n              elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get -y install awscli\n              elif command -v apk >/dev/null 2>&1; then apk add --no-cache aws-cli\n              else yum -y install awscli; fi\n  - name: validate\n    steps:\n      - name: Validate\n        action: ExecuteBash\n        inputs:\n          commands:\n            - aws --version\n",
    },
    ManagedComponent {
        name: "amazon-cloudwatch-agent-linux",
        version: "1.0.1",
        description: "Installs the latest version of the Amazon CloudWatch agent.",
        data: "name: amazon-cloudwatch-agent-linux\ndescription: Installs the latest version of the Amazon CloudWatch agent.\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: InstallAgent\n        action: ExecuteBash\n        inputs:\n          commands:\n            - if command -v dnf >/dev/null 2>&1; then dnf -y install amazon-cloudwatch-agent; else yum -y install amazon-cloudwatch-agent; fi\n",
    },
    ManagedComponent {
        name: "docker-ce-linux",
        version: "1.0.0",
        description: "Installs Docker Community Edition.",
        data: "name: docker-ce-linux\ndescription: Installs Docker Community Edition.\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: InstallDocker\n        action: ExecuteBash\n        inputs:\n          commands:\n            - |\n              if command -v dnf >/dev/null 2>&1; then dnf -y install docker\n              elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get -y install docker.io\n              elif command -v apk >/dev/null 2>&1; then apk add --no-cache docker\n              else yum -y install docker; fi\n",
    },
    ManagedComponent {
        name: "python-3-linux",
        version: "1.0.3",
        description: "Installs Python 3.",
        data: "name: python-3-linux\ndescription: Installs Python 3.\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: InstallPython\n        action: ExecuteBash\n        inputs:\n          commands:\n            - |\n              if command -v python3 >/dev/null 2>&1; then exit 0; fi\n              if command -v dnf >/dev/null 2>&1; then dnf -y install python3\n              elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get -y install python3\n              elif command -v apk >/dev/null 2>&1; then apk add --no-cache python3\n              else yum -y install python3; fi\n",
    },
];

/// An AWS-managed parent image and the EC2 public AMI it names.
pub struct ManagedImage {
    pub name: &'static str,
    pub version: &'static str,
    pub os_version: &'static str,
    /// The EC2 public image name.
    pub ami_name: &'static str,
}

pub const IMAGES: &[ManagedImage] = &[
    ManagedImage {
        name: "amazon-linux-2023-x86",
        version: "2025.1.1",
        os_version: "Amazon Linux 2023",
        ami_name: "al2023-ami-2023.6.20250101.0-kernel-6.1-x86_64",
    },
    ManagedImage {
        name: "amazon-linux-2023-arm64",
        version: "2025.1.1",
        os_version: "Amazon Linux 2023",
        ami_name: "al2023-ami-2023.6.20250101.0-kernel-6.1-arm64",
    },
    ManagedImage {
        name: "amazon-linux-2-x86",
        version: "2025.1.1",
        os_version: "Amazon Linux 2",
        ami_name: "amzn2-ami-kernel-5.10-hvm-2.0.20250101.0-x86_64-gp2",
    },
    ManagedImage {
        name: "ubuntu-server-24-lts-x86",
        version: "2025.1.1",
        os_version: "Ubuntu 24",
        ami_name: "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20250101",
    },
    ManagedImage {
        name: "ubuntu-server-22-lts-x86",
        version: "2025.1.1",
        os_version: "Ubuntu 22",
        ami_name: "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20250101",
    },
];

pub struct ManagedWorkflow {
    pub kind: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub data: &'static str,
}

pub const BUILD_IMAGE: &str = "name: build-image\ndescription: Workflow to build an AMI\nschemaVersion: 1.0\nsteps:\n  - name: LaunchBuildInstance\n    action: LaunchInstance\n    onFailure: Abort\n    inputs:\n      waitFor: \"ssmAgent\"\n  - name: ApplyBuildComponents\n    action: ExecuteComponents\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchBuildInstance.instanceId\"\n  - name: InventoryCollection\n    action: CollectImageMetadata\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchBuildInstance.instanceId\"\n  - name: RunSanitizeScript\n    action: SanitizeInstance\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchBuildInstance.instanceId\"\n  - name: CreateOutputAMI\n    action: CreateImage\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchBuildInstance.instanceId\"\n  - name: TerminateBuildInstance\n    action: TerminateInstance\n    onFailure: Continue\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchBuildInstance.instanceId\"\noutputs:\n  - name: \"ImageId\"\n    value: \"$.stepOutputs.CreateOutputAMI.imageId\"\n";

pub const TEST_IMAGE: &str = "name: test-image\ndescription: Workflow to test an AMI\nschemaVersion: 1.0\nsteps:\n  - name: LaunchTestInstance\n    action: LaunchInstance\n    onFailure: Abort\n    inputs:\n      waitFor: \"ssmAgent\"\n  - name: CollectImageScanFindings\n    action: CollectImageScanFindings\n    onFailure: Continue\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchTestInstance.instanceId\"\n  - name: ApplyTestComponents\n    action: ExecuteComponents\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchTestInstance.instanceId\"\n  - name: TerminateTestInstance\n    action: TerminateInstance\n    onFailure: Continue\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchTestInstance.instanceId\"\n";

pub const BUILD_CONTAINER: &str = "name: build-container\ndescription: Workflow to build a container image\nschemaVersion: 1.0\nsteps:\n  - name: LaunchBuildInstance\n    action: LaunchInstance\n    onFailure: Abort\n    inputs:\n      waitFor: \"ssmAgent\"\n  - name: BootstrapBuildInstance\n    action: BootstrapInstanceForContainer\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchBuildInstance.instanceId\"\n  - name: ApplyBuildComponents\n    action: ExecuteComponents\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchBuildInstance.instanceId\"\n  - name: TerminateBuildInstance\n    action: TerminateInstance\n    onFailure: Continue\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchBuildInstance.instanceId\"\n";

pub const TEST_CONTAINER: &str = "name: test-container\ndescription: Workflow to test a container image\nschemaVersion: 1.0\nsteps:\n  - name: LaunchTestInstance\n    action: LaunchInstance\n    onFailure: Abort\n    inputs:\n      waitFor: \"ssmAgent\"\n  - name: BootstrapTestInstance\n    action: BootstrapInstanceForContainer\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchTestInstance.instanceId\"\n  - name: ApplyTestComponents\n    action: ExecuteComponents\n    onFailure: Abort\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchTestInstance.instanceId\"\n  - name: TerminateTestInstance\n    action: TerminateInstance\n    onFailure: Continue\n    inputs:\n      instanceId.$: \"$.stepOutputs.LaunchTestInstance.instanceId\"\n";

pub const WORKFLOWS: &[ManagedWorkflow] = &[
    ManagedWorkflow {
        kind: "build",
        name: "build-image",
        version: "1.0.1",
        description: "Workflow to build an AMI",
        data: BUILD_IMAGE,
    },
    ManagedWorkflow {
        kind: "test",
        name: "test-image",
        version: "1.0.0",
        description: "Workflow to test an AMI",
        data: TEST_IMAGE,
    },
    ManagedWorkflow {
        kind: "build",
        name: "build-container",
        version: "1.0.1",
        description: "Workflow to build a container image",
        data: BUILD_CONTAINER,
    },
    ManagedWorkflow {
        kind: "test",
        name: "test-container",
        version: "1.0.0",
        description: "Workflow to test a container image",
        data: TEST_CONTAINER,
    },
];

const DATE: &str = "2025-01-01T00:00:00.000Z";

fn base(partition: &str, region: &str) -> String {
    format!("arn:{partition}:imagebuilder:{region}:aws")
}

pub fn component(partition: &str, region: &str, c: &ManagedComponent) -> t::Component {
    let doc = crate::toe::Document::parse(c.data).expect("managed component documents parse");
    t::Component {
        arn: Some(format!("{}:component/{}/{}/1", base(partition, region), c.name, c.version)),
        name: Some(c.name.into()),
        version: Some(c.version.into()),
        description: Some(c.description.into()),
        r#type: Some(doc.component_type().into()),
        platform: Some("Linux".into()),
        supported_os_versions: Some(vec!["Amazon Linux 2023".into(), "Amazon Linux 2".into(), "Ubuntu".into()]),
        state: Some(t::ComponentState { status: Some("ACTIVE".into()), reason: None }),
        parameters: (!doc.parameters.is_empty()).then_some(doc.parameters),
        owner: Some("Amazon".into()),
        data: Some(c.data.into()),
        encrypted: Some(true),
        date_created: Some(DATE.into()),
        tags: Some(Default::default()),
        ..Default::default()
    }
}

pub fn components(partition: &str, region: &str) -> Vec<t::Component> {
    COMPONENTS.iter().map(|c| component(partition, region, c)).collect()
}

pub fn image(partition: &str, region: &str, i: &ManagedImage) -> t::Image {
    t::Image {
        arn: Some(format!("{}:image/{}/{}/1", base(partition, region), i.name, i.version)),
        r#type: Some("AMI".into()),
        name: Some(i.name.into()),
        version: Some(i.version.into()),
        platform: Some("Linux".into()),
        os_version: Some(i.os_version.into()),
        state: Some(t::ImageState { status: Some("AVAILABLE".into()), ..Default::default() }),
        date_created: Some(DATE.into()),
        build_type: Some("USER_INITIATED".into()),
        image_source: Some("AMAZON_MANAGED".into()),
        tags: Some(Default::default()),
        ..Default::default()
    }
}

pub fn images(partition: &str, region: &str) -> Vec<(t::Image, &'static ManagedImage)> {
    IMAGES.iter().map(|i| (image(partition, region, i), i)).collect()
}

pub fn workflow(partition: &str, region: &str, w: &ManagedWorkflow) -> t::Workflow {
    t::Workflow {
        arn: Some(format!("{}:workflow/{}/{}/{}/1", base(partition, region), w.kind, w.name, w.version)),
        name: Some(w.name.into()),
        version: Some(w.version.into()),
        description: Some(w.description.into()),
        r#type: Some(w.kind.to_uppercase()),
        state: Some(t::WorkflowState { status: Some("ACTIVE".into()), reason: None }),
        owner: Some("Amazon".into()),
        data: Some(w.data.into()),
        date_created: Some(DATE.into()),
        tags: Some(Default::default()),
        parameters: None,
        ..Default::default()
    }
}

pub fn workflows(partition: &str, region: &str) -> Vec<t::Workflow> {
    WORKFLOWS.iter().map(|w| workflow(partition, region, w)).collect()
}

/// The managed workflow a build of this kind runs by default.
pub fn default_workflow(partition: &str, region: &str, kind: &str, container: bool) -> t::Workflow {
    let name = match (kind, container) {
        ("build", false) => "build-image",
        ("test", false) => "test-image",
        ("build", true) => "build-container",
        _ => "test-container",
    };
    let w = WORKFLOWS.iter().find(|w| w.name == name).expect("managed workflow exists");
    workflow(partition, region, w)
}

#[cfg(test)]
mod tests {
    #[test]
    fn managed_documents_parse() {
        for c in super::COMPONENTS {
            crate::toe::Document::parse(c.data).unwrap();
        }
        for w in super::WORKFLOWS {
            crate::workflows::WorkflowDocument::parse(w.data).unwrap();
        }
    }
}
