//! Fixed EC2 facts: Regions, Availability Zones, instance types and the
//! public AMIs, each mapped to the container image it runs.

use crate::generated::types as t;

pub const REGIONS: &[&str] = &[
    "af-south-1",
    "ap-east-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ca-central-1",
    "eu-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "il-central-1",
    "me-central-1",
    "me-south-1",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
];

/// Regions that are not enabled by default.
const OPT_IN: &[&str] = &[
    "af-south-1",
    "ap-east-1",
    "ap-south-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "eu-central-2",
    "eu-south-1",
    "eu-south-2",
    "il-central-1",
    "me-central-1",
    "me-south-1",
];

pub fn region_opt_in_status(region: &str) -> &'static str {
    if OPT_IN.contains(&region) {
        "not-opted-in"
    } else {
        "opt-in-not-required"
    }
}

/// `use1`, `euw1`, ...: the prefix of zone ids.
fn zone_id_prefix(region: &str) -> String {
    let mut parts = region.split('-');
    let geo = parts.next().unwrap_or_default();
    let dir = parts.next().unwrap_or_default();
    let n = parts.next().unwrap_or("1");
    let d: String = match dir {
        "northeast" => "ne".into(),
        "southeast" => "se".into(),
        "northwest" => "nw".into(),
        "southwest" => "sw".into(),
        other => other.chars().next().map(String::from).unwrap_or_default(),
    };
    format!("{geo}{d}{n}")
}

/// `(zone name, zone id)` for every Availability Zone of `region`.
pub fn zones(region: &str) -> Vec<(String, String)> {
    let letters = if region == "us-east-1" { "abcdef" } else { "abc" };
    let prefix = zone_id_prefix(region);
    letters.chars().enumerate().map(|(i, c)| (format!("{region}{c}"), format!("{prefix}-az{}", i + 1))).collect()
}

pub fn zone_id(region: &str, zone: &str) -> Option<String> {
    zones(region).into_iter().find(|(n, _)| n == zone).map(|(_, id)| id)
}

pub fn zone_name(region: &str, zone_id: &str) -> Option<String> {
    zones(region).into_iter().find(|(_, id)| id == zone_id).map(|(n, _)| n)
}

/// An instance type: name, vCPUs, memory (MiB), architecture, burstable.
pub struct InstanceType {
    pub name: &'static str,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub arch: &'static str,
    pub burstable: bool,
}

const fn it(name: &'static str, vcpus: u32, memory_mib: u64, arch: &'static str, burstable: bool) -> InstanceType {
    InstanceType { name, vcpus, memory_mib, arch, burstable }
}

pub const INSTANCE_TYPES: &[InstanceType] = &[
    it("m1.small", 1, 1740, "x86_64", false),
    it("t2.nano", 1, 512, "x86_64", true),
    it("t2.micro", 1, 1024, "x86_64", true),
    it("t2.small", 1, 2048, "x86_64", true),
    it("t2.medium", 2, 4096, "x86_64", true),
    it("t2.large", 2, 8192, "x86_64", true),
    it("t3.nano", 2, 512, "x86_64", true),
    it("t3.micro", 2, 1024, "x86_64", true),
    it("t3.small", 2, 2048, "x86_64", true),
    it("t3.medium", 2, 4096, "x86_64", true),
    it("t3.large", 2, 8192, "x86_64", true),
    it("t3.xlarge", 4, 16384, "x86_64", true),
    it("t3.2xlarge", 8, 32768, "x86_64", true),
    it("t3a.micro", 2, 1024, "x86_64", true),
    it("t3a.small", 2, 2048, "x86_64", true),
    it("t3a.medium", 2, 4096, "x86_64", true),
    it("t4g.nano", 2, 512, "arm64", true),
    it("t4g.micro", 2, 1024, "arm64", true),
    it("t4g.small", 2, 2048, "arm64", true),
    it("t4g.medium", 2, 4096, "arm64", true),
    it("t4g.large", 2, 8192, "arm64", true),
    it("m5.large", 2, 8192, "x86_64", false),
    it("m5.xlarge", 4, 16384, "x86_64", false),
    it("m5.2xlarge", 8, 32768, "x86_64", false),
    it("m6i.large", 2, 8192, "x86_64", false),
    it("m6i.xlarge", 4, 16384, "x86_64", false),
    it("m6g.large", 2, 8192, "arm64", false),
    it("m7g.large", 2, 8192, "arm64", false),
    it("m7i.large", 2, 8192, "x86_64", false),
    it("c5.large", 2, 4096, "x86_64", false),
    it("c5.xlarge", 4, 8192, "x86_64", false),
    it("c6i.large", 2, 4096, "x86_64", false),
    it("c6g.large", 2, 4096, "arm64", false),
    it("c7g.large", 2, 4096, "arm64", false),
    it("r5.large", 2, 16384, "x86_64", false),
    it("r6i.large", 2, 16384, "x86_64", false),
    it("r6g.large", 2, 16384, "arm64", false),
];

pub fn instance_type(name: &str) -> Option<&'static InstanceType> {
    INSTANCE_TYPES.iter().find(|i| i.name == name)
}

pub fn instance_type_info(i: &InstanceType) -> t::InstanceTypeInfo {
    let family = i.name.split('.').next().unwrap_or_default();
    let current = !matches!(family, "m1" | "t2");
    t::InstanceTypeInfo {
        instance_type: Some(i.name.into()),
        current_generation: Some(current),
        free_tier_eligible: Some(matches!(i.name, "t2.micro" | "t3.micro" | "t4g.micro")),
        supported_usage_classes: Some(vec!["on-demand".into(), "spot".into()]),
        supported_root_device_types: Some(vec!["ebs".into()]),
        supported_virtualization_types: Some(vec!["hvm".into()]),
        bare_metal: Some(false),
        hypervisor: Some(if current { "nitro" } else { "xen" }.into()),
        processor_info: Some(t::ProcessorInfo {
            supported_architectures: Some(vec![i.arch.into()]),
            sustained_clock_speed_in_ghz: Some(if i.arch == "arm64" { 2.5 } else { 3.1 }),
            ..Default::default()
        }),
        v_cpu_info: Some(t::VCpuInfo {
            default_v_cpus: Some(i.vcpus as i32),
            default_cores: Some(i.vcpus.div_ceil(if i.arch == "arm64" { 1 } else { 2 }).max(1) as i32),
            default_threads_per_core: Some(if i.arch == "arm64" || i.vcpus == 1 { 1 } else { 2 }),
            ..Default::default()
        }),
        memory_info: Some(t::MemoryInfo { size_in_mi_b: Some(i.memory_mib as i64) }),
        instance_storage_supported: Some(false),
        ebs_info: Some(t::EbsInfo {
            ebs_optimized_support: Some(if current { "default" } else { "unsupported" }.into()),
            encryption_support: Some("supported".into()),
            nvme_support: Some(if current { "required" } else { "unsupported" }.into()),
            ..Default::default()
        }),
        network_info: Some(t::NetworkInfo {
            network_performance: Some(if i.burstable { "Up to 5 Gigabit" } else { "Up to 10 Gigabit" }.into()),
            maximum_network_interfaces: Some(if i.vcpus <= 2 { 3 } else { 4 }),
            ipv4_addresses_per_interface: Some(if i.vcpus <= 2 { 4 } else { 15 }),
            ipv6_addresses_per_interface: Some(if i.vcpus <= 2 { 4 } else { 15 }),
            ipv6_supported: Some(current),
            ena_support: Some(if current { "required" } else { "unsupported" }.into()),
            ..Default::default()
        }),
        placement_group_info: Some(t::PlacementGroupInfo {
            supported_strategies: Some(vec!["partition".into(), "spread".into()]),
        }),
        hibernation_supported: Some(current),
        burstable_performance_supported: Some(i.burstable),
        dedicated_hosts_supported: Some(!i.burstable),
        auto_recovery_supported: Some(true),
        supported_boot_modes: Some(if i.arch == "arm64" {
            vec!["uefi".into()]
        } else {
            vec!["legacy-bios".into(), "uefi".into()]
        }),
        ..Default::default()
    }
}

/// A public AMI and the container image it runs.
pub struct PublicImage {
    /// The image name in `DescribeImages`.
    pub name: &'static str,
    /// Path under `/aws/service/` of the Parameter Store parameter naming
    /// it, if it has one (its id is then the one Parameter Store reports).
    pub ssm_path: Option<&'static str>,
    pub description: &'static str,
    pub owner_id: &'static str,
    pub owner_alias: Option<&'static str>,
    pub arch: &'static str,
    pub container_image: &'static str,
    pub platform_details: &'static str,
}

const AMAZON: &str = "137112412989";
const CANONICAL: &str = "099720109477";
const DEBIAN: &str = "136693071363";
/// The account that publishes the EKS-optimized AMIs.
const EKS: &str = "602401143452";

const fn al(
    name: &'static str,
    ssm: &'static str,
    description: &'static str,
    arch: &'static str,
    container_image: &'static str,
) -> PublicImage {
    PublicImage {
        name,
        ssm_path: Some(ssm),
        description,
        owner_id: AMAZON,
        owner_alias: Some("amazon"),
        arch,
        container_image,
        platform_details: "Linux/UNIX",
    }
}

/// An EKS-optimized AMI, as managed node groups run them.
const fn eks(
    name: &'static str,
    ssm: &'static str,
    description: &'static str,
    arch: &'static str,
    container_image: &'static str,
) -> PublicImage {
    PublicImage { owner_id: EKS, ..al(name, ssm, description, arch, container_image) }
}

pub const PUBLIC_IMAGES: &[PublicImage] = &[
    al(
        "al2023-ami-2023.6.20250101.0-kernel-6.1-x86_64",
        "ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
        "Amazon Linux 2023 AMI 2023.6.20250101.0 x86_64 HVM kernel-6.1",
        "x86_64",
        "amazonlinux:2023",
    ),
    al(
        "al2023-ami-2023.6.20250101.0-kernel-6.1-arm64",
        "ami-amazon-linux-latest/al2023-ami-kernel-default-arm64",
        "Amazon Linux 2023 AMI 2023.6.20250101.0 arm64 HVM kernel-6.1",
        "arm64",
        "amazonlinux:2023",
    ),
    al(
        "al2023-ami-minimal-2023.6.20250101.0-kernel-6.1-x86_64",
        "ami-amazon-linux-latest/al2023-ami-minimal-kernel-default-x86_64",
        "Amazon Linux 2023 AMI 2023.6.20250101.0 x86_64 Minimal HVM kernel-6.1",
        "x86_64",
        "amazonlinux:2023",
    ),
    al(
        "amzn2-ami-kernel-5.10-hvm-2.0.20250101.0-x86_64-gp2",
        "ami-amazon-linux-latest/amzn2-ami-kernel-5.10-hvm-x86_64-gp2",
        "Amazon Linux 2 Kernel 5.10 AMI 2.0.20250101.0 x86_64 HVM gp2",
        "x86_64",
        "amazonlinux:2",
    ),
    al(
        "amzn2-ami-hvm-2.0.20250101.0-x86_64-gp2",
        "ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2",
        "Amazon Linux 2 AMI 2.0.20250101.0 x86_64 HVM gp2",
        "x86_64",
        "amazonlinux:2",
    ),
    al(
        "al2023-ami-ecs-hvm-2023.0.20250101-kernel-6.1-x86_64",
        "ecs/optimized-ami/amazon-linux-2023/recommended/image_id",
        "Amazon Linux AMI 2023.0.20250101 x86_64 ECS HVM EBS",
        "x86_64",
        "amazonlinux:2023",
    ),
    PublicImage {
        name: "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20250101",
        ssm_path: None,
        description: "Canonical, Ubuntu, 24.04, amd64 noble image",
        owner_id: CANONICAL,
        owner_alias: None,
        arch: "x86_64",
        container_image: "ubuntu:24.04",
        platform_details: "Linux/UNIX",
    },
    PublicImage {
        name: "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20250101",
        ssm_path: None,
        description: "Canonical, Ubuntu, 22.04 LTS, amd64 jammy image",
        owner_id: CANONICAL,
        owner_alias: None,
        arch: "x86_64",
        container_image: "ubuntu:22.04",
        platform_details: "Linux/UNIX",
    },
    PublicImage {
        name: "debian-12-amd64-20250101-1980",
        ssm_path: None,
        description: "Debian 12 (20250101-1980)",
        owner_id: DEBIAN,
        owner_alias: None,
        arch: "x86_64",
        container_image: "debian:12",
        platform_details: "Linux/UNIX",
    },
    eks(
        "amazon-eks-node-al2023-x86_64-standard-1.29-v20250101",
        "eks/optimized-ami/1.29/amazon-linux-2023/x86_64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.29, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-arm64-standard-1.29-v20250101",
        "eks/optimized-ami/1.29/amazon-linux-2023/arm64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.29, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-x86_64-standard-1.30-v20250101",
        "eks/optimized-ami/1.30/amazon-linux-2023/x86_64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.30, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-arm64-standard-1.30-v20250101",
        "eks/optimized-ami/1.30/amazon-linux-2023/arm64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.30, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-x86_64-standard-1.31-v20250101",
        "eks/optimized-ami/1.31/amazon-linux-2023/x86_64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.31, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-arm64-standard-1.31-v20250101",
        "eks/optimized-ami/1.31/amazon-linux-2023/arm64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.31, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-x86_64-standard-1.32-v20250101",
        "eks/optimized-ami/1.32/amazon-linux-2023/x86_64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.32, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-arm64-standard-1.32-v20250101",
        "eks/optimized-ami/1.32/amazon-linux-2023/arm64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.32, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-x86_64-standard-1.33-v20250101",
        "eks/optimized-ami/1.33/amazon-linux-2023/x86_64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.33, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-arm64-standard-1.33-v20250101",
        "eks/optimized-ami/1.33/amazon-linux-2023/arm64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.33, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-x86_64-standard-1.34-v20250101",
        "eks/optimized-ami/1.34/amazon-linux-2023/x86_64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.34, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-arm64-standard-1.34-v20250101",
        "eks/optimized-ami/1.34/amazon-linux-2023/arm64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.34, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-x86_64-standard-1.35-v20250101",
        "eks/optimized-ami/1.35/amazon-linux-2023/x86_64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.35, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-al2023-arm64-standard-1.35-v20250101",
        "eks/optimized-ami/1.35/amazon-linux-2023/arm64/standard/recommended/image_id",
        "EKS-optimized Kubernetes node based on Amazon Linux 2023, (k8s: 1.35, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2023",
    ),
    eks(
        "amazon-eks-node-1.29-v20250101",
        "eks/optimized-ami/1.29/amazon-linux-2/recommended/image_id",
        "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.29, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2",
    ),
    eks(
        "amazon-eks-arm64-node-1.29-v20250101",
        "eks/optimized-ami/1.29/amazon-linux-2-arm64/recommended/image_id",
        "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.29, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2",
    ),
    eks(
        "amazon-eks-node-1.30-v20250101",
        "eks/optimized-ami/1.30/amazon-linux-2/recommended/image_id",
        "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.30, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2",
    ),
    eks(
        "amazon-eks-arm64-node-1.30-v20250101",
        "eks/optimized-ami/1.30/amazon-linux-2-arm64/recommended/image_id",
        "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.30, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2",
    ),
    eks(
        "amazon-eks-node-1.31-v20250101",
        "eks/optimized-ami/1.31/amazon-linux-2/recommended/image_id",
        "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.31, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2",
    ),
    eks(
        "amazon-eks-arm64-node-1.31-v20250101",
        "eks/optimized-ami/1.31/amazon-linux-2-arm64/recommended/image_id",
        "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.31, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2",
    ),
    eks(
        "amazon-eks-node-1.32-v20250101",
        "eks/optimized-ami/1.32/amazon-linux-2/recommended/image_id",
        "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.32, containerd: 1.7.*)",
        "x86_64",
        "amazonlinux:2",
    ),
    eks(
        "amazon-eks-arm64-node-1.32-v20250101",
        "eks/optimized-ami/1.32/amazon-linux-2-arm64/recommended/image_id",
        "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.32, containerd: 1.7.*)",
        "arm64",
        "amazonlinux:2",
    ),
    PublicImage {
        name: "mws-alpine-3.20-x86_64",
        ssm_path: None,
        description: "Alpine Linux 3.20, a small image for fast local instances (MWS)",
        owner_id: AMAZON,
        owner_alias: Some("amazon"),
        arch: "x86_64",
        container_image: "alpine:3.20",
        platform_details: "Linux/UNIX",
    },
];

/// The id of a public image in `region`. Images Parameter Store names
/// share its ids, so `/aws/service/ami-amazon-linux-latest/...` resolves to
/// an image `RunInstances` knows.
pub fn public_image_id(region: &str, img: &PublicImage) -> String {
    let key = img.ssm_path.unwrap_or(img.name);
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, format!("{region}/{key}").as_bytes());
    let hex: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("ami-{}", &hex[..17])
}

pub fn public_image(region: &str, id: &str) -> Option<&'static PublicImage> {
    PUBLIC_IMAGES.iter().find(|i| public_image_id(region, i) == id)
}

pub fn public_image_shape(region: &str, img: &PublicImage) -> t::Image {
    let id = public_image_id(region, img);
    t::Image {
        image_id: Some(id),
        image_location: Some(format!("{}/{}", img.owner_alias.unwrap_or(img.owner_id), img.name)),
        state: Some("available".into()),
        owner_id: Some(img.owner_id.into()),
        image_owner_alias: img.owner_alias.map(Into::into),
        creation_date: Some("2025-01-01T00:00:00.000Z".into()),
        public: Some(true),
        architecture: Some(img.arch.into()),
        image_type: Some("machine".into()),
        name: Some(img.name.into()),
        description: Some(img.description.into()),
        platform_details: Some(img.platform_details.into()),
        usage_operation: Some("RunInstances".into()),
        root_device_name: Some("/dev/xvda".into()),
        root_device_type: Some("ebs".into()),
        virtualization_type: Some("hvm".into()),
        hypervisor: Some("xen".into()),
        ena_support: Some(true),
        sriov_net_support: Some("simple".into()),
        boot_mode: Some(if img.arch == "arm64" { "uefi" } else { "uefi-preferred" }.into()),
        // Amazon Linux 2023 AMIs require IMDSv2; the others allow v1.
        imds_support: img.name.starts_with("al2023").then(|| "v2.0".into()),
        deprecation_time: Some("2027-01-01T00:00:00.000Z".into()),
        block_device_mappings: Some(vec![t::BlockDeviceMapping {
            device_name: Some("/dev/xvda".into()),
            ebs: Some(t::EbsBlockDevice {
                delete_on_termination: Some(true),
                snapshot_id: Some(format!("snap-{}", &public_image_id(region, img)[4..])),
                volume_size: Some(8),
                volume_type: Some("gp3".into()),
                encrypted: Some(false),
                iops: Some(3000),
                throughput: Some(125),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_ids() {
        assert_eq!(zones("us-east-1")[0], ("us-east-1a".into(), "use1-az1".into()));
        assert_eq!(zones("eu-west-1")[1], ("eu-west-1b".into(), "euw1-az2".into()));
        assert_eq!(zones("ap-southeast-2")[0].1, "apse2-az1");
    }
}
