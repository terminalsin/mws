//! What Security Hub ships with: its standards, the security controls in
//! them, the product integrations findings come from, and the managed
//! insights. The control catalogue is a representative subset of AWS's
//! (the controls for the services MWS emulates and the common CIS ones),
//! with AWS's IDs, titles and severities.

/// A security standard. `key` is the part of its ARN after
/// `standards/` (or `ruleset/` for CIS 1.2.0).
pub struct Standard {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub enabled_by_default: bool,
    /// CIS 1.2.0 predates regional standards ARNs: `arn:aws:securityhub:::ruleset/...`.
    pub ruleset: bool,
}

pub const FSBP: &str = "aws-foundational-security-best-practices/v/1.0.0";
pub const CIS_1_2: &str = "cis-aws-foundations-benchmark/v/1.2.0";
pub const CIS_1_4: &str = "cis-aws-foundations-benchmark/v/1.4.0";
pub const CIS_3_0: &str = "cis-aws-foundations-benchmark/v/3.0.0";
pub const PCI_3_2_1: &str = "pci-dss/v/3.2.1";
pub const NIST_800_53: &str = "nist-800-53/v/5.0.0";
pub const TAGGING: &str = "aws-resource-tagging-standard/v/1.0.0";

pub const STANDARDS: &[Standard] = &[
    Standard {
        key: CIS_1_2,
        name: "CIS AWS Foundations Benchmark v1.2.0",
        description: "The Center for Internet Security (CIS) AWS Foundations Benchmark v1.2.0 is a set of security configuration best practices for AWS. This Security Hub standard automatically checks for your compliance readiness against a subset of CIS requirements.",
        enabled_by_default: true,
        ruleset: true,
    },
    Standard {
        key: FSBP,
        name: "AWS Foundational Security Best Practices v1.0.0",
        description: "The AWS Foundational Security Best Practices standard is a set of automated security checks that detect when AWS accounts and deployed resources do not align to security best practices. The standard is defined by AWS security experts. This curated set of controls helps improve your security posture in AWS, and cover AWS's most popular and foundational services.",
        enabled_by_default: true,
        ruleset: false,
    },
    Standard {
        key: PCI_3_2_1,
        name: "PCI DSS v3.2.1",
        description: "The Payment Card Industry Data Security Standard (PCI DSS) v3.2.1 is an information security standard for entities that store, process, and/or transmit cardholder data. This Security Hub standard automatically checks for your compliance readiness against a subset of PCI DSS requirements.",
        enabled_by_default: false,
        ruleset: false,
    },
    Standard {
        key: CIS_1_4,
        name: "CIS AWS Foundations Benchmark v1.4.0",
        description: "The Center for Internet Security (CIS) AWS Foundations Benchmark v1.4.0 is a set of security configuration best practices for AWS. This Security Hub standard automatically checks for your compliance readiness against a subset of CIS requirements.",
        enabled_by_default: false,
        ruleset: false,
    },
    Standard {
        key: NIST_800_53,
        name: "NIST Special Publication 800-53 Revision 5",
        description: "National Institute of Standards and Technology (NIST) SP 800-53 Rev. 5 is a cybersecurity and compliance framework developed by NIST, an agency that is part of the U.S. Department of Commerce. This compliance framework provides a catalog of security and privacy requirements for protecting the confidentiality, integrity, and availability of information systems and critical resources.",
        enabled_by_default: false,
        ruleset: false,
    },
    Standard {
        key: TAGGING,
        name: "AWS Resource Tagging Standard v1.0.0",
        description: "The AWS Resource Tagging Standard v1.0.0 is a set of automated security checks that detect when AWS resources do not have tags. You can use tags to manage, identify, organize, search for, and filter resources.",
        enabled_by_default: false,
        ruleset: false,
    },
    Standard {
        key: CIS_3_0,
        name: "CIS AWS Foundations Benchmark v3.0.0",
        description: "The Center for Internet Security (CIS) AWS Foundations Benchmark v3.0.0 is a set of security configuration best practices for AWS. This Security Hub standard automatically checks for your compliance readiness against a subset of CIS requirements.",
        enabled_by_default: false,
        ruleset: false,
    },
];

pub fn standard(key: &str) -> Option<&'static Standard> {
    STANDARDS.iter().find(|s| s.key == key)
}

pub fn standards_arn(partition: &str, region: &str, s: &Standard) -> String {
    if s.ruleset {
        format!("arn:{partition}:securityhub:::ruleset/{}", s.key)
    } else {
        format!("arn:{partition}:securityhub:{region}::standards/{}", s.key)
    }
}

/// The standard a standards ARN names (in any region), if it is one.
pub fn standard_from_arn(arn: &str) -> Option<&'static Standard> {
    let rest = arn.split(':').nth(5)?;
    let key = rest.strip_prefix("standards/").or_else(|| rest.strip_prefix("ruleset/"))?;
    let s = standard(key)?;
    let region = arn.split(':').nth(3)?;
    // Ruleset ARNs carry no region; standards ARNs must.
    (s.ruleset == region.is_empty()).then_some(s)
}

/// A control parameter's definition.
pub enum Param {
    Integer { name: &'static str, description: &'static str, min: i32, max: i32, default: Option<i32> },
    IntegerList { name: &'static str, description: &'static str, min: i32, max: i32, default: &'static [i32] },
    StringList { name: &'static str, description: &'static str, default: &'static [&'static str] },
    Boolean { name: &'static str, description: &'static str, default: bool },
    EnumList { name: &'static str, description: &'static str, allowed: &'static [&'static str], default: &'static [&'static str] },
}

impl Param {
    pub fn name(&self) -> &'static str {
        match self {
            Param::Integer { name, .. }
            | Param::IntegerList { name, .. }
            | Param::StringList { name, .. }
            | Param::Boolean { name, .. }
            | Param::EnumList { name, .. } => name,
        }
    }
}

/// A security control and where it appears in each standard: the
/// standard's own control ID and its related requirements.
pub struct Control {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
    pub in_standards: &'static [(&'static str, &'static str, &'static [&'static str])],
    pub params: &'static [Param],
}

const RUNTIMES: &[&str] = &[
    "dotnet8", "java21", "java17", "java11", "java8.al2", "nodejs22.x", "nodejs20.x", "nodejs18.x", "python3.13",
    "python3.12", "python3.11", "python3.10", "python3.9", "ruby3.3", "ruby3.2",
];

macro_rules! c {
    ($id:literal, $sev:literal, $title:literal, [$(($std:expr, $cid:literal, [$($req:literal),*])),*] $(, $params:expr)?) => {
        Control { id: $id, severity: $sev, title: $title, in_standards: &[$(($std, $cid, &[$($req),*])),*], params: c!(@p $($params)?) }
    };
    (@p) => { &[] };
    (@p $p:expr) => { $p };
}

pub const CONTROLS: &[Control] = &[
    c!("ACM.1", "MEDIUM", "Imported and ACM-issued certificates should be renewed after a specified time period",
        [(FSBP, "ACM.1", []), (NIST_800_53, "ACM.1", ["NIST.800-53.r5 SC-28(3)", "NIST.800-53.r5 SC-7(16)"]), (PCI_3_2_1, "PCI.ACM.1", [])],
        &[Param::Integer { name: "daysToExpiration", description: "Number of days within which the ACM certificate must be renewed", min: 14, max: 365, default: Some(30) }]),
    c!("ACM.2", "HIGH", "RSA certificates managed by ACM should use a key length of at least 2,048 bits",
        [(FSBP, "ACM.2", [])]),
    c!("ACM.3", "LOW", "ACM certificates should be tagged",
        [(TAGGING, "ACM.3", [])],
        &[Param::StringList { name: "requiredTagKeys", description: "List of non-system tag keys that the evaluated resource must contain. Tag keys are case sensitive.", default: &[] }]),
    c!("CloudTrail.1", "HIGH", "CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events",
        [(FSBP, "CloudTrail.1", []), (CIS_1_2, "2.1", ["CIS AWS Foundations 2.1"]), (CIS_1_4, "3.1", ["CIS AWS Foundations Benchmark v1.4.0/3.1"]), (CIS_3_0, "3.1", ["CIS AWS Foundations Benchmark v3.0.0/3.1"]), (NIST_800_53, "CloudTrail.1", ["NIST.800-53.r5 AC-2(4)", "NIST.800-53.r5 AU-12"])]),
    c!("CloudTrail.2", "MEDIUM", "CloudTrail should have encryption at-rest enabled",
        [(FSBP, "CloudTrail.2", []), (CIS_1_2, "2.7", ["CIS AWS Foundations 2.7"]), (CIS_1_4, "3.7", ["CIS AWS Foundations Benchmark v1.4.0/3.7"]), (PCI_3_2_1, "PCI.CloudTrail.1", ["PCI DSS 3.4"]), (NIST_800_53, "CloudTrail.2", ["NIST.800-53.r5 AU-9", "NIST.800-53.r5 SC-28"])]),
    c!("CloudTrail.4", "LOW", "CloudTrail log file validation should be enabled",
        [(FSBP, "CloudTrail.4", []), (CIS_1_2, "2.2", ["CIS AWS Foundations 2.2"]), (CIS_1_4, "3.2", ["CIS AWS Foundations Benchmark v1.4.0/3.2"]), (PCI_3_2_1, "PCI.CloudTrail.3", ["PCI DSS 10.5.2", "PCI DSS 10.5.5"])]),
    c!("CloudTrail.5", "LOW", "CloudTrail trails should be integrated with Amazon CloudWatch Logs",
        [(FSBP, "CloudTrail.5", []), (CIS_1_2, "2.4", ["CIS AWS Foundations 2.4"]), (CIS_1_4, "3.4", ["CIS AWS Foundations Benchmark v1.4.0/3.4"]), (PCI_3_2_1, "PCI.CloudTrail.4", ["PCI DSS 10.1", "PCI DSS 10.2.1"])]),
    c!("CloudWatch.1", "LOW", "A log metric filter and alarm should exist for usage of the \"root\" user",
        [(CIS_1_2, "3.3", ["CIS AWS Foundations 1.1", "CIS AWS Foundations 3.3"]), (CIS_1_4, "4.3", ["CIS AWS Foundations Benchmark v1.4.0/1.7", "CIS AWS Foundations Benchmark v1.4.0/4.3"]), (PCI_3_2_1, "PCI.CW.1", ["PCI DSS 7.2.1"])]),
    c!("CloudWatch.4", "LOW", "Ensure a log metric filter and alarm exist for IAM policy changes",
        [(CIS_1_2, "3.4", ["CIS AWS Foundations 3.4"]), (CIS_1_4, "4.4", ["CIS AWS Foundations Benchmark v1.4.0/4.4"])]),
    c!("Config.1", "MEDIUM", "AWS Config should be enabled and use the service-linked role for resource recording",
        [(FSBP, "Config.1", []), (CIS_1_2, "2.5", ["CIS AWS Foundations 2.5"]), (CIS_1_4, "3.5", ["CIS AWS Foundations Benchmark v1.4.0/3.5"]), (PCI_3_2_1, "PCI.Config.1", ["PCI DSS 10.5.2", "PCI DSS 11.5"]), (NIST_800_53, "Config.1", ["NIST.800-53.r5 CM-3", "NIST.800-53.r5 CM-8"])],
        &[Param::Boolean { name: "includeConfigServiceLinkedRoleCheck", description: "Whether the control checks if AWS Config uses the service-linked role", default: true }]),
    c!("EC2.1", "CRITICAL", "Amazon EBS snapshots should not be publicly restorable",
        [(FSBP, "EC2.1", []), (PCI_3_2_1, "PCI.EC2.1", ["PCI DSS 1.2.1", "PCI DSS 1.3.1"]), (NIST_800_53, "EC2.1", ["NIST.800-53.r5 AC-21", "NIST.800-53.r5 AC-3"])]),
    c!("EC2.2", "HIGH", "VPC default security groups should not allow inbound or outbound traffic",
        [(FSBP, "EC2.2", []), (CIS_1_2, "4.3", ["CIS AWS Foundations 4.3"]), (CIS_1_4, "5.3", ["CIS AWS Foundations Benchmark v1.4.0/5.3"]), (CIS_3_0, "5.4", ["CIS AWS Foundations Benchmark v3.0.0/5.4"]), (PCI_3_2_1, "PCI.EC2.2", ["PCI DSS 1.2.1", "PCI DSS 1.3.4", "PCI DSS 2.1"])]),
    c!("EC2.6", "MEDIUM", "VPC flow logging should be enabled in all VPCs",
        [(FSBP, "EC2.6", []), (CIS_1_2, "2.9", ["CIS AWS Foundations 2.9"]), (CIS_1_4, "3.9", ["CIS AWS Foundations Benchmark v1.4.0/3.9"]), (PCI_3_2_1, "PCI.EC2.6", ["PCI DSS 10.3.3", "PCI DSS 10.3.4"])],
        &[Param::StringList { name: "trafficType", description: "Type of flow log traffic that the control evaluates", default: &["REJECT"] }]),
    c!("EC2.7", "MEDIUM", "EBS default encryption should be enabled",
        [(FSBP, "EC2.7", []), (CIS_1_4, "2.2.1", ["CIS AWS Foundations Benchmark v1.4.0/2.2.1"]), (CIS_3_0, "2.2.1", ["CIS AWS Foundations Benchmark v3.0.0/2.2.1"])]),
    c!("EC2.8", "HIGH", "EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)",
        [(FSBP, "EC2.8", []), (CIS_3_0, "5.6", ["CIS AWS Foundations Benchmark v3.0.0/5.6"]), (NIST_800_53, "EC2.8", ["NIST.800-53.r5 AC-3", "NIST.800-53.r5 AC-6"])]),
    c!("EC2.18", "HIGH", "Security groups should only allow unrestricted incoming traffic for authorized ports",
        [(FSBP, "EC2.18", []), (NIST_800_53, "EC2.18", ["NIST.800-53.r5 AC-4", "NIST.800-53.r5 SC-7"])],
        &[Param::IntegerList { name: "authorizedTcpPorts", description: "List of TCP ports that are allowed to be accessible from 0.0.0.0/0 or ::/0", min: 1, max: 65535, default: &[80, 443] },
          Param::IntegerList { name: "authorizedUdpPorts", description: "List of UDP ports that are allowed to be accessible from 0.0.0.0/0 or ::/0", min: 1, max: 65535, default: &[] }]),
    c!("EC2.19", "CRITICAL", "Security groups should not allow unrestricted access to ports with high risk",
        [(FSBP, "EC2.19", []), (NIST_800_53, "EC2.19", ["NIST.800-53.r5 AC-4", "NIST.800-53.r5 SC-7"])]),
    c!("ECR.1", "HIGH", "ECR private repositories should have image scanning configured",
        [(FSBP, "ECR.1", []), (NIST_800_53, "ECR.1", ["NIST.800-53.r5 RA-5"])]),
    c!("ECR.2", "MEDIUM", "ECR private repositories should have tag immutability configured",
        [(FSBP, "ECR.2", []), (NIST_800_53, "ECR.2", ["NIST.800-53.r5 CA-9(1)", "NIST.800-53.r5 CM-2"])]),
    c!("ECR.3", "MEDIUM", "ECR repositories should have at least one lifecycle policy configured",
        [(FSBP, "ECR.3", [])]),
    c!("EFS.1", "MEDIUM", "Elastic File System should be configured to encrypt file data at-rest using AWS KMS",
        [(FSBP, "EFS.1", []), (CIS_1_4, "2.4.1", ["CIS AWS Foundations Benchmark v1.4.0/2.4.1"])]),
    c!("EKS.1", "HIGH", "EKS cluster endpoints should not be publicly accessible",
        [(FSBP, "EKS.1", []), (NIST_800_53, "EKS.1", ["NIST.800-53.r5 AC-21", "NIST.800-53.r5 SC-7"])]),
    c!("EKS.2", "HIGH", "EKS clusters should run on a supported Kubernetes version",
        [(FSBP, "EKS.2", [])],
        &[Param::StringList { name: "oldestVersionSupported", description: "Oldest Kubernetes version the control treats as supported", default: &["1.29"] }]),
    c!("ELB.1", "MEDIUM", "Application Load Balancer should be configured to redirect all HTTP requests to HTTPS",
        [(FSBP, "ELB.1", []), (PCI_3_2_1, "PCI.ELBv2.1", ["PCI DSS 2.3", "PCI DSS 4.1"])]),
    c!("GuardDuty.1", "HIGH", "GuardDuty should be enabled",
        [(FSBP, "GuardDuty.1", []), (PCI_3_2_1, "PCI.GuardDuty.1", ["PCI DSS 11.4"]), (NIST_800_53, "GuardDuty.1", ["NIST.800-53.r5 AC-2(12)", "NIST.800-53.r5 SI-4"])]),
    c!("IAM.1", "HIGH", "IAM policies should not allow full \"*\" administrative privileges",
        [(FSBP, "IAM.1", []), (CIS_1_2, "1.22", ["CIS AWS Foundations 1.22"]), (CIS_1_4, "1.16", ["CIS AWS Foundations Benchmark v1.4.0/1.16"]), (PCI_3_2_1, "PCI.IAM.3", ["PCI DSS 7.2.1"]), (NIST_800_53, "IAM.1", ["NIST.800-53.r5 AC-2", "NIST.800-53.r5 AC-6"])],
        &[Param::Boolean { name: "excludePermissionBoundaryPolicy", description: "Whether the control excludes policies used as permissions boundaries", default: true }]),
    c!("IAM.2", "LOW", "IAM users should not have IAM policies attached",
        [(FSBP, "IAM.2", []), (CIS_1_2, "1.16", ["CIS AWS Foundations 1.16"]), (PCI_3_2_1, "PCI.IAM.2", ["PCI DSS 7.2.1"])]),
    c!("IAM.3", "MEDIUM", "IAM users' access keys should be rotated every 90 days or less",
        [(FSBP, "IAM.3", []), (CIS_1_2, "1.4", ["CIS AWS Foundations 1.4"]), (CIS_1_4, "1.14", ["CIS AWS Foundations Benchmark v1.4.0/1.14"]), (CIS_3_0, "1.14", ["CIS AWS Foundations Benchmark v3.0.0/1.14"])]),
    c!("IAM.4", "CRITICAL", "IAM root user access key should not exist",
        [(FSBP, "IAM.4", []), (CIS_1_2, "1.12", ["CIS AWS Foundations 1.12"]), (CIS_1_4, "1.4", ["CIS AWS Foundations Benchmark v1.4.0/1.4"]), (CIS_3_0, "1.4", ["CIS AWS Foundations Benchmark v3.0.0/1.4"]), (PCI_3_2_1, "PCI.IAM.1", ["PCI DSS 2.1", "PCI DSS 2.2", "PCI DSS 7.2.1"])]),
    c!("IAM.5", "MEDIUM", "MFA should be enabled for all IAM users that have a console password",
        [(FSBP, "IAM.5", []), (CIS_1_2, "1.2", ["CIS AWS Foundations 1.2"]), (CIS_1_4, "1.10", ["CIS AWS Foundations Benchmark v1.4.0/1.10"]), (CIS_3_0, "1.10", ["CIS AWS Foundations Benchmark v3.0.0/1.10"])]),
    c!("IAM.6", "CRITICAL", "Hardware MFA should be enabled for the root user",
        [(FSBP, "IAM.6", []), (CIS_1_2, "1.14", ["CIS AWS Foundations 1.14"]), (CIS_1_4, "1.6", ["CIS AWS Foundations Benchmark v1.4.0/1.6"]), (PCI_3_2_1, "PCI.IAM.4", ["PCI DSS 8.3.1"])]),
    c!("IAM.7", "MEDIUM", "Password policies for IAM users should have strong configurations",
        [(FSBP, "IAM.7", []), (NIST_800_53, "IAM.7", ["NIST.800-53.r5 AC-2(1)", "NIST.800-53.r5 IA-5(1)"])],
        &[Param::Boolean { name: "RequireUppercaseCharacters", description: "Require at least one uppercase character in password", default: true },
          Param::Boolean { name: "RequireLowercaseCharacters", description: "Require at least one lowercase character in password", default: true },
          Param::Boolean { name: "RequireSymbols", description: "Require at least one symbol in password", default: true },
          Param::Boolean { name: "RequireNumbers", description: "Require at least one number in password", default: true },
          Param::Integer { name: "MinimumPasswordLength", description: "Minimum number of characters in password", min: 8, max: 128, default: Some(8) },
          Param::Integer { name: "PasswordReusePrevention", description: "Number of password iterations before a password can be reused", min: 1, max: 24, default: None },
          Param::Integer { name: "MaxPasswordAge", description: "Number of days before password expiration", min: 1, max: 1095, default: None }]),
    c!("IAM.9", "CRITICAL", "MFA should be enabled for the root user",
        [(FSBP, "IAM.9", []), (CIS_1_2, "1.13", ["CIS AWS Foundations 1.13"]), (CIS_1_4, "1.5", ["CIS AWS Foundations Benchmark v1.4.0/1.5"]), (CIS_3_0, "1.5", ["CIS AWS Foundations Benchmark v3.0.0/1.5"]), (PCI_3_2_1, "PCI.IAM.5", ["PCI DSS 8.3.1"])]),
    c!("KMS.4", "MEDIUM", "AWS KMS key rotation should be enabled",
        [(FSBP, "KMS.4", []), (CIS_1_2, "2.8", ["CIS AWS Foundations 2.8"]), (CIS_1_4, "3.8", ["CIS AWS Foundations Benchmark v1.4.0/3.8"]), (CIS_3_0, "3.6", ["CIS AWS Foundations Benchmark v3.0.0/3.6"]), (PCI_3_2_1, "PCI.KMS.1", ["PCI DSS 3.6.4"])]),
    c!("Lambda.1", "CRITICAL", "Lambda function policies should prohibit public access",
        [(FSBP, "Lambda.1", []), (PCI_3_2_1, "PCI.Lambda.1", ["PCI DSS 1.2.1", "PCI DSS 1.3.1"]), (NIST_800_53, "Lambda.1", ["NIST.800-53.r5 AC-21", "NIST.800-53.r5 AC-3"])]),
    c!("Lambda.2", "MEDIUM", "Lambda functions should use supported runtimes",
        [(FSBP, "Lambda.2", []), (NIST_800_53, "Lambda.2", ["NIST.800-53.r5 CA-9(1)", "NIST.800-53.r5 CM-2"])],
        &[Param::EnumList { name: "runtime", description: "Supported runtimes for Lambda functions", allowed: RUNTIMES, default: RUNTIMES }]),
    c!("RDS.1", "CRITICAL", "RDS snapshot should be private",
        [(FSBP, "RDS.1", []), (PCI_3_2_1, "PCI.RDS.1", ["PCI DSS 1.2.1", "PCI DSS 1.3.1"])]),
    c!("RDS.3", "MEDIUM", "RDS DB instances should have encryption at-rest enabled",
        [(FSBP, "RDS.3", []), (CIS_1_4, "2.3.1", ["CIS AWS Foundations Benchmark v1.4.0/2.3.1"]), (CIS_3_0, "2.3.1", ["CIS AWS Foundations Benchmark v3.0.0/2.3.1"])]),
    c!("Route53.2", "MEDIUM", "Route 53 public hosted zones should log DNS queries",
        [(FSBP, "Route53.2", []), (NIST_800_53, "Route53.2", ["NIST.800-53.r5 AU-2", "NIST.800-53.r5 AU-12"])]),
    c!("S3.1", "MEDIUM", "S3 general purpose buckets should have block public access settings enabled",
        [(FSBP, "S3.1", []), (CIS_1_4, "2.1.5", ["CIS AWS Foundations Benchmark v1.4.0/2.1.5"]), (CIS_3_0, "2.1.4", ["CIS AWS Foundations Benchmark v3.0.0/2.1.4"]), (PCI_3_2_1, "PCI.S3.6", ["PCI DSS 1.2.1", "PCI DSS 1.3.1"])]),
    c!("S3.5", "MEDIUM", "S3 general purpose buckets should require requests to use SSL",
        [(FSBP, "S3.5", []), (CIS_1_4, "2.1.2", ["CIS AWS Foundations Benchmark v1.4.0/2.1.2"]), (CIS_3_0, "2.1.1", ["CIS AWS Foundations Benchmark v3.0.0/2.1.1"]), (PCI_3_2_1, "PCI.S3.5", ["PCI DSS 4.1"])]),
    c!("S3.8", "HIGH", "S3 general purpose buckets should block public access",
        [(FSBP, "S3.8", []), (CIS_1_4, "2.1.5", ["CIS AWS Foundations Benchmark v1.4.0/2.1.5"]), (NIST_800_53, "S3.8", ["NIST.800-53.r5 AC-21", "NIST.800-53.r5 AC-3"])]),
    c!("SecretsManager.1", "MEDIUM", "Secrets Manager secrets should have automatic rotation enabled",
        [(FSBP, "SecretsManager.1", []), (NIST_800_53, "SecretsManager.1", ["NIST.800-53.r5 AC-2(1)", "NIST.800-53.r5 IA-5(1)"])],
        &[Param::Integer { name: "maximumAllowedRotationFrequency", description: "Maximum number of days allowed for the rotation frequency", min: 1, max: 365, default: None }]),
    c!("SecurityHub.1", "HIGH", "Security Hub should be enabled",
        [(NIST_800_53, "SecurityHub.1", ["NIST.800-53.r5 CA-7", "NIST.800-53.r5 SI-4"])]),
    c!("SNS.1", "MEDIUM", "SNS topics should be encrypted at-rest using AWS KMS",
        [(FSBP, "SNS.1", []), (NIST_800_53, "SNS.1", ["NIST.800-53.r5 SC-28", "NIST.800-53.r5 SC-28(1)"])]),
    c!("SQS.1", "MEDIUM", "Amazon SQS queues should be encrypted at rest",
        [(FSBP, "SQS.1", []), (NIST_800_53, "SQS.1", ["NIST.800-53.r5 SC-28", "NIST.800-53.r5 SC-28(1)"])]),
    c!("SSM.1", "MEDIUM", "Amazon EC2 instances should be managed by AWS Systems Manager",
        [(FSBP, "SSM.1", []), (PCI_3_2_1, "PCI.SSM.3", ["PCI DSS 2.4"]), (NIST_800_53, "SSM.1", ["NIST.800-53.r5 CA-9(1)", "NIST.800-53.r5 CM-2"])]),
];

pub fn control(id: &str) -> Option<&'static Control> {
    CONTROLS.iter().find(|c| c.id == id)
}

/// The controls in a standard, with the standard's own control IDs.
pub fn controls_in(standard_key: &str) -> impl Iterator<Item = (&'static Control, &'static str, &'static [&'static str])> {
    let key = standard_key.to_string();
    CONTROLS.iter().filter_map(move |c| {
        c.in_standards.iter().find(|(s, _, _)| *s == key).map(|(_, cid, reqs)| (c, *cid, *reqs))
    })
}

pub fn description(c: &Control) -> String {
    let mut t = c.title.to_string();
    if let Some(first) = t.get(..1) {
        t.replace_range(..1, &first.to_lowercase());
    }
    format!("This control checks whether {t}.")
}

pub fn remediation_url(c: &Control) -> String {
    format!("https://docs.aws.amazon.com/console/securityhub/{}/remediation", c.id)
}

/// A product that sends findings to (or receives them from) Security Hub.
pub struct Product {
    /// `company/product`, the part of the ARN after `product/`.
    pub key: &'static str,
    pub name: &'static str,
    pub company: &'static str,
    pub description: &'static str,
    pub categories: &'static [&'static str],
    pub integration_types: &'static [&'static str],
    /// AWS integrations are enabled for import when Security Hub is.
    pub aws: bool,
}

pub const PRODUCTS: &[Product] = &[
    Product { key: "aws/securityhub", name: "Security Hub", company: "AWS", description: "AWS Security Hub provides you with a comprehensive view of your security state in AWS and helps you check your environment against security industry standards and best practices.", categories: &["Compliance"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/guardduty", name: "GuardDuty", company: "Amazon", description: "Amazon GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior to protect your AWS accounts and workloads.", categories: &["Intrusion Detection Systems (IDS)", "Threat Intelligence"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/inspector", name: "Inspector", company: "Amazon", description: "Amazon Inspector is a vulnerability management service that continuously scans your AWS workloads for software vulnerabilities and unintended network exposure.", categories: &["Vulnerability"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/macie", name: "Macie", company: "Amazon", description: "Amazon Macie is a data security service that discovers sensitive data by using machine learning and pattern matching.", categories: &["Data Protection"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/access-analyzer", name: "IAM Access Analyzer", company: "AWS", description: "AWS IAM Access Analyzer helps you identify resources in your organization and accounts that are shared with an external entity.", categories: &["Identity and Access Management"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/firewall-manager", name: "Firewall Manager", company: "AWS", description: "AWS Firewall Manager is a security management service that allows you to centrally configure and manage firewall rules across your accounts and applications.", categories: &["Firewall"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/config", name: "Config", company: "AWS", description: "AWS Config evaluates the configuration settings of your AWS resources.", categories: &["Compliance"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/health", name: "Health", company: "AWS", description: "AWS Health provides ongoing visibility into your resource performance and the availability of your AWS services and accounts.", categories: &["Monitoring"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/ssm-patch-manager", name: "Systems Manager Patch Manager", company: "AWS", description: "AWS Systems Manager Patch Manager automates the process of patching managed instances.", categories: &["Patch Management"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: true },
    Product { key: "aws/detective", name: "Detective", company: "Amazon", description: "Amazon Detective makes it easy to analyze, investigate, and quickly identify the root cause of potential security issues.", categories: &["Investigation"], integration_types: &["RECEIVE_FINDINGS_FROM_SECURITY_HUB"], aws: false },
    Product { key: "crowdstrike/crowdstrike-falcon", name: "CrowdStrike Falcon", company: "CrowdStrike", description: "CrowdStrike Falcon is a cloud-native endpoint protection platform.", categories: &["Endpoint Detection and Response (EDR)"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: false },
    Product { key: "paloaltonetworks/prisma-cloud-enterprise", name: "Prisma Cloud Enterprise", company: "Palo Alto Networks", description: "Prisma Cloud is a comprehensive cloud native security platform.", categories: &["Cloud Security Posture Management (CSPM)"], integration_types: &["SEND_FINDINGS_TO_SECURITY_HUB"], aws: false },
];

pub fn product(key: &str) -> Option<&'static Product> {
    PRODUCTS.iter().find(|p| p.key == key)
}

pub fn product_arn(partition: &str, region: &str, p: &Product) -> String {
    format!("arn:{partition}:securityhub:{region}::product/{}", p.key)
}

/// Security Hub's managed insights: `(number, name, group by, filters as
/// ASFF filter JSON)`.
pub const MANAGED_INSIGHTS: &[(u32, &str, &str, &str)] = &[
    (1, "AWS resources with the most findings", "ResourceId", r#"{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"},{"Value":"NOTIFIED","Comparison":"EQUALS"}]}"#),
    (2, "S3 buckets with public write or read permissions", "ResourceId", r#"{"ResourceType":[{"Value":"AwsS3Bucket","Comparison":"EQUALS"}],"Type":[{"Value":"Effects/Data Exposure","Comparison":"PREFIX"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#),
    (3, "AMIs that are generating the most findings", "ResourceAwsEc2InstanceImageId", r#"{"ResourceType":[{"Value":"AwsEc2Instance","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#),
    (10, "Users with the most suspicious activity", "ResourceAwsIamAccessKeyUserName", r#"{"ResourceType":[{"Value":"AwsIamAccessKey","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#),
    (13, "AWS resources with the most findings of high or critical severity", "ResourceId", r#"{"SeverityLabel":[{"Value":"HIGH","Comparison":"EQUALS"},{"Value":"CRITICAL","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#),
    (17, "Top accounts by counts of findings", "AwsAccountId", r#"{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#),
    (18, "Top products by counts of findings", "ProductName", r#"{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#),
    (19, "Severity by counts of findings", "SeverityLabel", r#"{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#),
];

pub fn managed_insight_arn(partition: &str, n: u32) -> String {
    format!("arn:{partition}:securityhub:::insight/securityhub/default/{n}")
}
