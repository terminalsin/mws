//! What EKS offers: Kubernetes versions, add-ons and their versions, and
//! access policies. A fixed catalog in the shape AWS publishes it.

use chrono::{DateTime, Months, NaiveDate, TimeZone, Utc};

/// A Kubernetes minor version EKS runs.
pub(crate) struct KubeVersion {
    pub version: &'static str,
    pub patch: &'static str,
    pub platform_version: &'static str,
    /// `YYYY-MM-DD`.
    pub release: &'static str,
    pub default: bool,
}

pub(crate) const VERSIONS: &[KubeVersion] = &[
    KubeVersion { version: "1.35", patch: "1.35.0", platform_version: "eks.3", release: "2026-01-27", default: false },
    KubeVersion { version: "1.34", patch: "1.34.2", platform_version: "eks.8", release: "2025-10-02", default: true },
    KubeVersion { version: "1.33", patch: "1.33.6", platform_version: "eks.20", release: "2025-05-29", default: false },
    KubeVersion {
        version: "1.32",
        patch: "1.32.10",
        platform_version: "eks.27",
        release: "2025-01-23",
        default: false,
    },
    KubeVersion {
        version: "1.31",
        patch: "1.31.14",
        platform_version: "eks.43",
        release: "2024-09-26",
        default: false,
    },
    KubeVersion {
        version: "1.30",
        patch: "1.30.14",
        platform_version: "eks.51",
        release: "2024-05-23",
        default: false,
    },
    KubeVersion {
        version: "1.29",
        patch: "1.29.15",
        platform_version: "eks.54",
        release: "2024-01-23",
        default: false,
    },
    KubeVersion {
        version: "1.28",
        patch: "1.28.15",
        platform_version: "eks.60",
        release: "2023-09-26",
        default: false,
    },
];

impl KubeVersion {
    pub fn release_date(&self) -> DateTime<Utc> {
        let d = NaiveDate::parse_from_str(self.release, "%Y-%m-%d").expect("catalog dates parse");
        Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).expect("midnight"))
    }

    /// Standard support lasts 14 months.
    pub fn end_of_standard_support(&self) -> DateTime<Utc> {
        self.release_date() + Months::new(14)
    }

    /// Extended support adds 12 more.
    pub fn end_of_extended_support(&self) -> DateTime<Utc> {
        self.release_date() + Months::new(26)
    }

    /// `standard-support`, `extended-support` or `unsupported` at `now`.
    pub fn status(&self, now: DateTime<Utc>) -> &'static str {
        if now < self.end_of_standard_support() {
            "standard-support"
        } else if now < self.end_of_extended_support() {
            "extended-support"
        } else {
            "unsupported"
        }
    }

    pub fn minor(&self) -> u32 {
        minor(self.version).unwrap_or_default()
    }
}

pub(crate) fn version(v: &str) -> Option<&'static KubeVersion> {
    VERSIONS.iter().find(|k| k.version == v)
}

pub(crate) fn default_version() -> &'static KubeVersion {
    VERSIONS.iter().find(|k| k.default).expect("a default version")
}

/// The minor number of `1.NN`.
pub(crate) fn minor(v: &str) -> Option<u32> {
    v.strip_prefix("1.")?.split('.').next()?.parse().ok()
}

/// A node group's release version: the Kubernetes patch release and the
/// AMI build date.
pub(crate) fn release_version(v: &KubeVersion, ami_type: &str) -> String {
    if ami_type.starts_with("BOTTLEROCKET") {
        "1.50.0-1f2c3a4b".into()
    } else if ami_type.starts_with("WINDOWS") {
        format!("{}-2025.01.01", v.patch)
    } else {
        format!("{}-20250101", v.patch)
    }
}

/// The CPU architecture of an AMI type.
pub(crate) fn ami_arch(ami_type: &str) -> &'static str {
    if ami_type.contains("ARM_64") {
        "arm64"
    } else {
        "x86_64"
    }
}

/// Whether an instance type runs on Graviton (arm64): `t4g`, `m7g`, `c6gd`...
pub(crate) fn instance_arch(instance_type: &str) -> &'static str {
    let family = instance_type.split('.').next().unwrap_or_default();
    let after_generation = family.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let suffix = after_generation.trim_start_matches(|c: char| c.is_ascii_digit());
    if suffix.starts_with('g') && !family.starts_with('g') {
        "arm64"
    } else {
        "x86_64"
    }
}

/// An EKS add-on.
pub(crate) struct AddonSpec {
    pub name: &'static str,
    pub kind: &'static str,
    pub publisher: &'static str,
    pub owner: &'static str,
    pub default_namespace: &'static str,
    /// Newest first; each version runs on Kubernetes minors `min..=max`.
    pub versions: &'static [(&'static str, u32, u32)],
    /// Service accounts that use IAM, with the managed policy AWS
    /// recommends.
    pub pod_identity: &'static [(&'static str, &'static str)],
    pub schema: &'static str,
}

const GENERIC_SCHEMA: &str = r##"{"$ref":"#/definitions/Config","$schema":"http://json-schema.org/draft-06/schema#","definitions":{"Config":{"additionalProperties":false,"properties":{"affinity":{"type":["object","null"]},"nodeSelector":{"additionalProperties":{"type":"string"},"type":"object"},"podAnnotations":{"type":"object"},"podLabels":{"type":"object"},"replicaCount":{"type":"integer"},"resources":{"type":"object"},"tolerations":{"type":"array"}},"title":"Config","type":"object"}}}"##;

const VPC_CNI_SCHEMA: &str = r##"{"$ref":"#/definitions/VpcCni","$schema":"http://json-schema.org/draft-06/schema#","definitions":{"VpcCni":{"additionalProperties":false,"properties":{"enableNetworkPolicy":{"format":"boolean","type":"string"},"enableWindowsIpam":{"format":"boolean","type":"string"},"env":{"type":"object"},"init":{"type":"object"},"nodeAgent":{"type":"object"},"resources":{"type":"object"},"tolerations":{"type":"array"}},"title":"VpcCni","type":"object"}}}"##;

pub(crate) const ADDONS: &[AddonSpec] = &[
    AddonSpec {
        name: "vpc-cni",
        kind: "networking",
        publisher: "eks",
        owner: "aws",
        default_namespace: "kube-system",
        versions: &[("v1.20.4-eksbuild.2", 28, 35), ("v1.19.6-eksbuild.7", 28, 34), ("v1.18.6-eksbuild.1", 28, 31)],
        pod_identity: &[("aws-node", "AmazonEKS_CNI_Policy")],
        schema: VPC_CNI_SCHEMA,
    },
    AddonSpec {
        name: "coredns",
        kind: "networking",
        publisher: "eks",
        owner: "aws",
        default_namespace: "kube-system",
        versions: &[("v1.12.4-eksbuild.1", 33, 35), ("v1.11.4-eksbuild.24", 29, 33), ("v1.10.1-eksbuild.38", 28, 29)],
        pod_identity: &[],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "kube-proxy",
        kind: "networking",
        publisher: "eks",
        owner: "aws",
        default_namespace: "kube-system",
        versions: &[
            ("v1.35.0-eksbuild.2", 35, 35),
            ("v1.34.1-eksbuild.2", 34, 34),
            ("v1.33.5-eksbuild.2", 33, 33),
            ("v1.32.9-eksbuild.2", 32, 32),
            ("v1.31.13-eksbuild.2", 31, 31),
            ("v1.30.14-eksbuild.12", 30, 30),
            ("v1.29.15-eksbuild.21", 29, 29),
            ("v1.28.15-eksbuild.31", 28, 28),
        ],
        pod_identity: &[],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "eks-pod-identity-agent",
        kind: "security",
        publisher: "eks",
        owner: "aws",
        default_namespace: "kube-system",
        versions: &[("v1.3.9-eksbuild.3", 28, 35), ("v1.3.4-eksbuild.1", 28, 32)],
        pod_identity: &[],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "aws-ebs-csi-driver",
        kind: "storage",
        publisher: "eks",
        owner: "aws",
        default_namespace: "kube-system",
        versions: &[("v1.51.1-eksbuild.1", 28, 35), ("v1.48.0-eksbuild.2", 28, 34)],
        pod_identity: &[("ebs-csi-controller-sa", "AmazonEBSCSIDriverPolicy")],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "aws-efs-csi-driver",
        kind: "storage",
        publisher: "eks",
        owner: "aws",
        default_namespace: "kube-system",
        versions: &[("v2.1.13-eksbuild.1", 28, 35), ("v2.1.10-eksbuild.1", 28, 34)],
        pod_identity: &[("efs-csi-controller-sa", "AmazonEFSCSIDriverPolicy")],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "snapshot-controller",
        kind: "storage",
        publisher: "eks",
        owner: "aws",
        default_namespace: "kube-system",
        versions: &[("v8.3.0-eksbuild.1", 28, 35)],
        pod_identity: &[],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "aws-mountpoint-s3-csi-driver",
        kind: "storage",
        publisher: "s3",
        owner: "aws",
        default_namespace: "kube-system",
        versions: &[("v2.1.0-eksbuild.1", 29, 35)],
        pod_identity: &[("s3-csi-driver-sa", "AmazonS3FullAccess")],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "metrics-server",
        kind: "observability",
        publisher: "eks",
        owner: "community",
        default_namespace: "kube-system",
        versions: &[("v0.8.0-eksbuild.2", 28, 35)],
        pod_identity: &[],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "amazon-cloudwatch-observability",
        kind: "observability",
        publisher: "eks",
        owner: "aws",
        default_namespace: "amazon-cloudwatch",
        versions: &[("v4.5.0-eksbuild.1", 28, 35)],
        pod_identity: &[("cloudwatch-agent", "CloudWatchAgentServerPolicy")],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "aws-guardduty-agent",
        kind: "security",
        publisher: "eks",
        owner: "aws",
        default_namespace: "amazon-guardduty",
        versions: &[("v1.11.0-eksbuild.4", 28, 35)],
        pod_identity: &[],
        schema: GENERIC_SCHEMA,
    },
    AddonSpec {
        name: "adot",
        kind: "observability",
        publisher: "eks",
        owner: "aws",
        default_namespace: "opentelemetry-operator-system",
        versions: &[("v0.131.0-eksbuild.1", 28, 35)],
        pod_identity: &[],
        schema: GENERIC_SCHEMA,
    },
];

pub(crate) fn addon(name: &str) -> Option<&'static AddonSpec> {
    ADDONS.iter().find(|a| a.name == name)
}

impl AddonSpec {
    pub fn supports(&self, version: &str, kube_minor: u32) -> bool {
        self.versions.iter().any(|(v, lo, hi)| *v == version && (*lo..=*hi).contains(&kube_minor))
    }

    /// The newest version for a Kubernetes minor (EKS's default).
    pub fn default_for(&self, kube_minor: u32) -> Option<&'static str> {
        self.versions.iter().find(|(_, lo, hi)| (*lo..=*hi).contains(&kube_minor)).map(|(v, _, _)| *v)
    }
}

/// EKS access policies: `arn:aws:eks::aws:cluster-access-policy/<name>`.
pub(crate) const ACCESS_POLICIES: &[&str] = &[
    "AmazonAIOpsAssistantPolicy",
    "AmazonARCRegionSwitchScalingPolicy",
    "AmazonEKSAdminPolicy",
    "AmazonEKSAdminViewPolicy",
    "AmazonEKSAutoNodePolicy",
    "AmazonEKSBlockStorageClusterPolicy",
    "AmazonEKSBlockStoragePolicy",
    "AmazonEKSClusterAdminPolicy",
    "AmazonEKSComputeClusterPolicy",
    "AmazonEKSComputePolicy",
    "AmazonEKSEditPolicy",
    "AmazonEKSHybridPolicy",
    "AmazonEKSLoadBalancingClusterPolicy",
    "AmazonEKSLoadBalancingPolicy",
    "AmazonEKSNetworkingClusterPolicy",
    "AmazonEKSNetworkingPolicy",
    "AmazonEKSSecretReaderPolicy",
    "AmazonEKSViewPolicy",
    "AmazonEMRJobPolicy",
    "AmazonSagemakerHyperpodClusterPolicy",
    "AmazonSagemakerHyperpodControllerPolicy",
    "AmazonSagemakerHyperpodSystemNamespacePolicy",
];

pub(crate) fn access_policy_arn(partition: &str, name: &str) -> String {
    format!("arn:{partition}:eks::aws:cluster-access-policy/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graviton_types() {
        assert_eq!(instance_arch("t3.medium"), "x86_64");
        assert_eq!(instance_arch("t4g.medium"), "arm64");
        assert_eq!(instance_arch("c6gd.large"), "arm64");
        assert_eq!(instance_arch("g5.xlarge"), "x86_64");
        assert_eq!(instance_arch("m7i.large"), "x86_64");
    }

    #[test]
    fn support_windows() {
        let v = version("1.29").unwrap();
        assert_eq!(v.end_of_standard_support().format("%Y-%m-%d").to_string(), "2025-03-23");
        assert_eq!(v.status(Utc.with_ymd_and_hms(2026, 11, 5, 0, 0, 0).unwrap()), "unsupported");
        assert_eq!(default_version().version, "1.34");
    }
}
