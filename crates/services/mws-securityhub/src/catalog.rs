//! What Security Hub ships with: its standards, the security controls in
//! them, the product integrations findings come from, and the managed
//! insights. The control catalogue (`controls.txt`) lists every AWS
//! Foundational Security Best Practices control and the CIS controls,
//! with AWS's IDs, titles, severities and standards mappings; PCI DSS and
//! NIST 800-53 mappings are partial.

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
    Integer {
        name: &'static str,
        description: &'static str,
        min: i32,
        max: i32,
        default: Option<i32>,
    },
    IntegerList {
        name: &'static str,
        description: &'static str,
        min: i32,
        max: i32,
        default: &'static [i32],
    },
    StringList {
        name: &'static str,
        description: &'static str,
        default: &'static [&'static str],
    },
    Boolean {
        name: &'static str,
        description: &'static str,
        default: bool,
    },
    EnumList {
        name: &'static str,
        description: &'static str,
        allowed: &'static [&'static str],
        default: &'static [&'static str],
    },
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
    "dotnet8",
    "java21",
    "java17",
    "java11",
    "java8.al2",
    "nodejs22.x",
    "nodejs20.x",
    "nodejs18.x",
    "python3.13",
    "python3.12",
    "python3.11",
    "python3.10",
    "python3.9",
    "ruby3.3",
    "ruby3.2",
];

/// The security controls, one per line (see the file's header).
const CONTROL_TABLE: &str = include_str!("controls.txt");

/// Customizable parameters, by security control ID.
fn params_of(id: &str) -> &'static [Param] {
    match id {
        "ACM.1" => &[Param::Integer {
            name: "daysToExpiration",
            description: "Number of days within which the ACM certificate must be renewed",
            min: 14,
            max: 365,
            default: Some(30),
        }],
        "ACM.3" => &[Param::StringList {
            name: "requiredTagKeys",
            description:
                "List of non-system tag keys that the evaluated resource must contain. Tag keys are case sensitive.",
            default: &[],
        }],
        "Config.1" => &[Param::Boolean {
            name: "includeConfigServiceLinkedRoleCheck",
            description: "Whether the control checks if AWS Config uses the service-linked role",
            default: true,
        }],
        "EC2.6" => &[Param::StringList {
            name: "trafficType",
            description: "Type of flow log traffic that the control evaluates",
            default: &["REJECT"],
        }],
        "EC2.18" => &[
            Param::IntegerList {
                name: "authorizedTcpPorts",
                description: "List of TCP ports that are allowed to be accessible from 0.0.0.0/0 or ::/0",
                min: 1,
                max: 65535,
                default: &[80, 443],
            },
            Param::IntegerList {
                name: "authorizedUdpPorts",
                description: "List of UDP ports that are allowed to be accessible from 0.0.0.0/0 or ::/0",
                min: 1,
                max: 65535,
                default: &[],
            },
        ],
        "EKS.2" => &[Param::StringList {
            name: "oldestVersionSupported",
            description: "Oldest Kubernetes version the control treats as supported",
            default: &["1.29"],
        }],
        "IAM.1" => &[Param::Boolean {
            name: "excludePermissionBoundaryPolicy",
            description: "Whether the control excludes policies used as permissions boundaries",
            default: true,
        }],
        "IAM.7" => &[
            Param::Boolean {
                name: "RequireUppercaseCharacters",
                description: "Require at least one uppercase character in password",
                default: true,
            },
            Param::Boolean {
                name: "RequireLowercaseCharacters",
                description: "Require at least one lowercase character in password",
                default: true,
            },
            Param::Boolean {
                name: "RequireSymbols",
                description: "Require at least one symbol in password",
                default: true,
            },
            Param::Boolean {
                name: "RequireNumbers",
                description: "Require at least one number in password",
                default: true,
            },
            Param::Integer {
                name: "MinimumPasswordLength",
                description: "Minimum number of characters in password",
                min: 8,
                max: 128,
                default: Some(8),
            },
            Param::Integer {
                name: "PasswordReusePrevention",
                description: "Number of password iterations before a password can be reused",
                min: 1,
                max: 24,
                default: None,
            },
            Param::Integer {
                name: "MaxPasswordAge",
                description: "Number of days before password expiration",
                min: 1,
                max: 1095,
                default: None,
            },
        ],
        "Lambda.2" => &[Param::EnumList {
            name: "runtime",
            description: "Supported runtimes for Lambda functions",
            allowed: RUNTIMES,
            default: RUNTIMES,
        }],
        "SecretsManager.1" => &[Param::Integer {
            name: "maximumAllowedRotationFrequency",
            description: "Maximum number of days allowed for the rotation frequency",
            min: 1,
            max: 365,
            default: None,
        }],
        "SecretsManager.4" => &[Param::Integer {
            name: "maxDaysSinceRotation",
            description: "Maximum number of days within which the secret must be rotated",
            min: 1,
            max: 180,
            default: Some(90),
        }],
        "Kinesis.3" => &[Param::Integer {
            name: "minimumBackupRetentionPeriod",
            description: "Minimum data retention period in hours",
            min: 24,
            max: 8760,
            default: Some(168),
        }],
        _ => &[],
    }
}

fn leak<T>(v: Vec<T>) -> &'static [T] {
    Box::leak(v.into_boxed_slice())
}

/// One `standards` entry of the table: `(standard key, control ID,
/// related requirements)`.
fn parse_mapping(id: &'static str, entry: &'static str) -> (&'static str, &'static str, &'static [&'static str]) {
    let (head, reqs) = match entry.split_once('[') {
        Some((h, r)) => (h.trim(), Some(r.trim_end_matches(']'))),
        None => (entry.trim(), None),
    };
    let (std, cid) = head.split_once('=').map_or((head, id), |(s, c)| (s.trim(), c.trim()));
    let key = match std {
        "FSBP" => FSBP,
        "CIS12" => CIS_1_2,
        "CIS14" => CIS_1_4,
        "CIS30" => CIS_3_0,
        "PCI" => PCI_3_2_1,
        "NIST" => NIST_800_53,
        "TAG" => TAGGING,
        other => panic!("unknown standard {other} for control {id} in controls.txt"),
    };
    let requirements: Vec<&'static str> = match reqs {
        Some(r) => r.split(',').map(str::trim).filter(|s| !s.is_empty()).collect(),
        None => match std {
            "CIS12" => vec![Box::leak(format!("CIS AWS Foundations {cid}").into_boxed_str())],
            "CIS14" => vec![Box::leak(format!("CIS AWS Foundations Benchmark v1.4.0/{cid}").into_boxed_str())],
            "CIS30" => vec![Box::leak(format!("CIS AWS Foundations Benchmark v3.0.0/{cid}").into_boxed_str())],
            _ => Vec::new(),
        },
    };
    (key, cid, leak(requirements))
}

/// Every security control in the catalogue, in the table's order.
pub fn controls() -> &'static [Control] {
    static CONTROLS: std::sync::OnceLock<&'static [Control]> = std::sync::OnceLock::new();
    CONTROLS.get_or_init(|| {
        let mut out = Vec::new();
        for line in CONTROL_TABLE.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let cols: Vec<&'static str> = line.splitn(4, '|').collect();
            let [id, severity, title, standards] = cols[..] else {
                panic!("malformed line in controls.txt: {line}");
            };
            let in_standards = leak(
                standards.split(';').map(str::trim).filter(|s| !s.is_empty()).map(|e| parse_mapping(id, e)).collect(),
            );
            out.push(Control { id, severity, title, in_standards, params: params_of(id) });
        }
        leak(out)
    })
}

pub fn control(id: &str) -> Option<&'static Control> {
    controls().iter().find(|c| c.id == id)
}

/// The controls in a standard, with the standard's own control IDs.
pub fn controls_in(
    standard_key: &str,
) -> impl Iterator<Item = (&'static Control, &'static str, &'static [&'static str])> {
    let key = standard_key.to_string();
    controls()
        .iter()
        .filter_map(move |c| c.in_standards.iter().find(|(s, _, _)| *s == key).map(|(_, cid, reqs)| (c, *cid, *reqs)))
}

/// AWS's description of the controls MWS evaluates; others are derived
/// from the title.
fn known_description(id: &str) -> Option<&'static str> {
    Some(match id {
        "CloudTrail.1" => "This control checks whether there is at least one multi-Region AWS CloudTrail trail that captures read and write management events. The control fails if CloudTrail is disabled or if there isn't at least one CloudTrail trail that captures read and write management events.",
        "CloudTrail.2" => "This control checks whether CloudTrail is configured to use the server-side encryption (SSE) AWS KMS key encryption. The control will fail if the KmsKeyId is not defined.",
        "EC2.2" => "This control checks whether the default security group of a VPC allows inbound or outbound traffic. The control fails if the security group allows inbound or outbound traffic.",
        "EC2.19" => "This control checks whether unrestricted incoming traffic for an Amazon EC2 security group is accessible to the specified ports that are considered to be high risk. This control fails if any of the rules in a security group allow ingress traffic from '0.0.0.0/0' or '::/0' to those ports.",
        "IAM.1" => "This control checks whether the default version of IAM policies (also known as customer managed policies) has administrator access that includes a statement with \"Effect\": \"Allow\" with \"Action\": \"*\" over \"Resource\": \"*\". The control fails if you have IAM policies with such a statement.",
        "IAM.2" => "This control checks whether your IAM users have policies attached. The control fails if your IAM users have policies attached. Instead, IAM users should inherit permissions from IAM groups or assume a role.",
        "IAM.4" => "This control checks whether the root user access key is available. The control fails if the root user access key exists.",
        "IAM.6" => "This control checks whether your AWS account is enabled to use a hardware multi-factor authentication (MFA) device to sign in with root user credentials. The control fails if MFA isn't enabled or if any virtual MFA devices are permitted for signing in with root user credentials.",
        "IAM.9" => "This control checks whether multi-factor authentication (MFA) is enabled for the IAM root user of an AWS account to sign in to the AWS Management Console. The control fails if MFA isn't enabled for the root user of the account.",
        "KMS.4" => "This control checks whether key rotation is enabled for each KMS key that you create, other than keys with imported key material and asymmetric keys. The control fails if key rotation is disabled.",
        "Lambda.1" => "This control checks whether the Lambda function resource-based policy prohibits public access outside of your account. The control fails if public access is allowed.",
        "RDS.3" => "This control checks whether storage encryption is enabled for your Amazon RDS DB instances. The control fails if an RDS DB instance isn't configured with storage encryption.",
        "S3.1" => "This control checks whether the preceding Amazon S3 block public access settings are configured at the account level for an S3 general purpose bucket. The control fails if one or more of the block public access settings are set to false.",
        "S3.5" => "This control checks whether an Amazon S3 general purpose bucket has a policy that requires requests to use SSL. The control fails if the bucket policy doesn't require requests to use SSL.",
        "S3.8" => "This control checks whether an Amazon S3 general purpose bucket blocks public access at the bucket level. The control fails if any of the following settings are set to false: ignorePublicAcls, blockPublicPolicy, blockPublicAcls, restrictPublicBuckets.",
        "SecretsManager.1" => "This control checks whether a secret stored in AWS Secrets Manager is configured with automatic rotation. The control fails if the secret isn't configured with automatic rotation.",
        "SNS.1" => "This control checks whether an Amazon SNS topic is encrypted at rest using keys managed in AWS Key Management Service (AWS KMS). The control fails if the SNS topic doesn't use a KMS key for server-side encryption (SSE).",
        "SQS.1" => "This control checks whether an Amazon SQS queue is encrypted at rest. The control fails if the queue isn't encrypted with an SQS-managed key (SSE-SQS) or an AWS Key Management Service (AWS KMS) key (SSE-KMS).",
        _ => return None,
    })
}

pub fn description(c: &Control) -> String {
    if let Some(d) = known_description(c.id) {
        return d.to_string();
    }
    let mut t = c.title.to_string();
    if let Some(first) = t.get(..1) {
        t.replace_range(..1, &first.to_lowercase());
    }
    format!("This control checks whether {t}.")
}

/// The control's page in the Security Hub user guide:
/// `<svc>-controls.html#<svc>-<n>`.
pub fn remediation_url(c: &Control) -> String {
    let (svc, n) = c.id.split_once('.').unwrap_or((c.id, ""));
    let svc = svc.to_lowercase();
    format!("https://docs.aws.amazon.com/securityhub/latest/userguide/{svc}-controls.html#{svc}-{n}")
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
    (
        1,
        "AWS resources with the most findings",
        "ResourceId",
        r#"{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"},{"Value":"NOTIFIED","Comparison":"EQUALS"}]}"#,
    ),
    (
        2,
        "S3 buckets with public write or read permissions",
        "ResourceId",
        r#"{"ResourceType":[{"Value":"AwsS3Bucket","Comparison":"EQUALS"}],"Type":[{"Value":"Effects/Data Exposure","Comparison":"PREFIX"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#,
    ),
    (
        3,
        "AMIs that are generating the most findings",
        "ResourceAwsEc2InstanceImageId",
        r#"{"ResourceType":[{"Value":"AwsEc2Instance","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#,
    ),
    (
        10,
        "Users with the most suspicious activity",
        "ResourceAwsIamAccessKeyUserName",
        r#"{"ResourceType":[{"Value":"AwsIamAccessKey","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#,
    ),
    (
        13,
        "AWS resources with the most findings of high or critical severity",
        "ResourceId",
        r#"{"SeverityLabel":[{"Value":"HIGH","Comparison":"EQUALS"},{"Value":"CRITICAL","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#,
    ),
    (
        17,
        "Top accounts by counts of findings",
        "AwsAccountId",
        r#"{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#,
    ),
    (
        18,
        "Top products by counts of findings",
        "ProductName",
        r#"{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#,
    ),
    (
        19,
        "Severity by counts of findings",
        "SeverityLabel",
        r#"{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}"#,
    ),
];

pub fn managed_insight_arn(partition: &str, n: u32) -> String {
    format!("arn:{partition}:securityhub:::insight/securityhub/default/{n}")
}
