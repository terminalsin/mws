//! The services and quotas Service Quotas knows about: AWS's service codes,
//! quota codes, names and default values, for the services MWS emulates and
//! the ones commonly managed alongside them.
//!
//! Quota codes and names are AWS's. Default values are the documented
//! defaults for a new account in the commercial partition.

/// An `AWS/Usage` metric that measures a quota's usage.
#[derive(Debug, Clone, Copy)]
pub struct UsageMetric {
    pub namespace: &'static str,
    pub name: &'static str,
    pub dimensions: &'static [(&'static str, &'static str)],
    pub statistic: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct QuotaDef {
    pub service: &'static str,
    pub code: &'static str,
    pub name: &'static str,
    pub value: f64,
    /// `None`, `Count`, `Gigabytes`, `Seconds`, ...
    pub unit: &'static str,
    pub adjustable: bool,
    /// Applies across Regions (IAM, Route 53, S3 bucket counts).
    pub global: bool,
    pub usage: Option<UsageMetric>,
    pub description: &'static str,
}

impl QuotaDef {
    /// The default value in `region` (a few quotas differ by Region).
    pub fn default_in(&self, region: &str) -> f64 {
        let big = matches!(region, "us-east-1" | "us-west-2" | "eu-west-1");
        match (self.service, self.code) {
            ("kinesis", "L-0918CF54") if !big => 200.0,
            ("firehose", "L-14BB0BE7") if !big => 2000.0,
            _ => self.value,
        }
    }
}

/// `(service code, service name)`.
pub const SERVICES: &[(&str, &str)] = &[
    ("acm", "AWS Certificate Manager (ACM)"),
    ("acm-pca", "AWS Private Certificate Authority"),
    ("amplify", "AWS Amplify"),
    ("autoscaling", "Amazon EC2 Auto Scaling"),
    ("cloudtrail", "AWS CloudTrail"),
    ("ebs", "Amazon Elastic Block Store (Amazon EBS)"),
    ("ec2", "Amazon Elastic Compute Cloud (Amazon EC2)"),
    ("eks", "Amazon Elastic Kubernetes Service (Amazon EKS)"),
    ("elasticache", "Amazon ElastiCache"),
    ("elasticfilesystem", "Amazon Elastic File System (EFS)"),
    ("elasticloadbalancing", "Elastic Load Balancing (ELB)"),
    ("events", "Amazon EventBridge (CloudWatch Events)"),
    ("firehose", "Amazon Kinesis Data Firehose"),
    ("guardduty", "Amazon GuardDuty"),
    ("iam", "AWS Identity and Access Management (IAM)"),
    ("kinesis", "Amazon Kinesis Data Streams"),
    ("kms", "AWS Key Management Service (AWS KMS)"),
    ("lambda", "AWS Lambda"),
    ("logs", "Amazon CloudWatch Logs"),
    ("rds", "Amazon Relational Database Service (Amazon RDS)"),
    ("route53", "Amazon Route 53"),
    ("s3", "Amazon Simple Storage Service (Amazon S3)"),
    ("secretsmanager", "AWS Secrets Manager"),
    ("securityhub", "AWS Security Hub"),
    ("ses", "Amazon Simple Email Service(Amazon SES)"),
    ("sns", "Amazon Simple Notification Service (Amazon SNS)"),
    ("ssm", "AWS Systems Manager"),
    ("vpc", "Amazon Virtual Private Cloud (Amazon VPC)"),
];

pub fn service_name(code: &str) -> Option<&'static str> {
    SERVICES.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

const fn vcpu(class: &'static str) -> Option<UsageMetric> {
    Some(UsageMetric {
        namespace: "AWS/Usage",
        name: "ResourceCount",
        dimensions: match class.as_bytes() {
            b"Standard/OnDemand" => {
                &[("Class", "Standard/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")]
            }
            b"G/OnDemand" => &[("Class", "G/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")],
            b"P/OnDemand" => &[("Class", "P/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")],
            b"X/OnDemand" => &[("Class", "X/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")],
            b"F/OnDemand" => &[("Class", "F/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")],
            b"Inf/OnDemand" => {
                &[("Class", "Inf/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")]
            }
            b"DL/OnDemand" => {
                &[("Class", "DL/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")]
            }
            b"Trn/OnDemand" => {
                &[("Class", "Trn/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")]
            }
            b"HPC/OnDemand" => {
                &[("Class", "HPC/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")]
            }
            b"HighMem/OnDemand" => {
                &[("Class", "HighMem/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")]
            }
            _ => &[("Class", "Standard/Spot"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")],
        },
        statistic: "Maximum",
    })
}

const fn q(service: &'static str, code: &'static str, name: &'static str, value: f64) -> QuotaDef {
    QuotaDef { service, code, name, value, unit: "None", adjustable: true, global: false, usage: None, description: "" }
}

const fn fixed(mut d: QuotaDef) -> QuotaDef {
    d.adjustable = false;
    d
}

const fn global(mut d: QuotaDef) -> QuotaDef {
    d.global = true;
    d
}

const fn unit(mut d: QuotaDef, unit: &'static str) -> QuotaDef {
    d.unit = unit;
    d
}

const fn usage(mut d: QuotaDef, usage: Option<UsageMetric>) -> QuotaDef {
    d.usage = usage;
    d
}

const fn described(mut d: QuotaDef, description: &'static str) -> QuotaDef {
    d.description = description;
    d
}

pub const QUOTAS: &[QuotaDef] = &[
    // ---- EC2 ------------------------------------------------------------
    described(
        usage(q("ec2", "L-1216C47A", "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances", 5.0), vcpu("Standard/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances.",
    ),
    described(
        usage(q("ec2", "L-DB2E81BA", "Running On-Demand G and VT instances", 0.0), vcpu("G/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand G and VT instances.",
    ),
    described(
        usage(q("ec2", "L-417A185B", "Running On-Demand P instances", 0.0), vcpu("P/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand P instances.",
    ),
    described(
        usage(q("ec2", "L-7295265B", "Running On-Demand X instances", 0.0), vcpu("X/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand X instances.",
    ),
    described(
        usage(q("ec2", "L-74FC7D96", "Running On-Demand F instances", 0.0), vcpu("F/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand F instances.",
    ),
    described(
        usage(q("ec2", "L-1945791B", "Running On-Demand Inf instances", 0.0), vcpu("Inf/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand Inf instances.",
    ),
    described(
        usage(q("ec2", "L-6E869C2A", "Running On-Demand DL instances", 0.0), vcpu("DL/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand DL instances.",
    ),
    described(
        usage(q("ec2", "L-2C3B7624", "Running On-Demand Trn instances", 0.0), vcpu("Trn/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand Trn instances.",
    ),
    described(
        usage(q("ec2", "L-F7808C92", "Running On-Demand HPC instances", 0.0), vcpu("HPC/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand HPC instances.",
    ),
    described(
        usage(q("ec2", "L-43DA4232", "Running On-Demand High Memory instances", 0.0), vcpu("HighMem/OnDemand")),
        "Maximum number of vCPUs assigned to the Running On-Demand High Memory instances.",
    ),
    described(
        usage(q("ec2", "L-34B43A08", "All Standard (A, C, D, H, I, M, R, T, Z) Spot Instance Requests", 5.0), vcpu("Standard/Spot")),
        "Maximum number of vCPUs for all running or requested Standard (A, C, D, H, I, M, R, T, Z) Spot Instances per Region.",
    ),
    described(
        q("ec2", "L-0263D0A3", "EC2-VPC Elastic IPs", 5.0),
        "The maximum number of Elastic IP addresses that you can allocate for EC2-VPC in this Region.",
    ),
    // ---- VPC ------------------------------------------------------------
    described(q("vpc", "L-F678F1CE", "VPCs per Region", 5.0), "The maximum number of VPCs per Region. This quota is directly tied to the maximum number of internet gateways per Region."),
    q("vpc", "L-407747CB", "Subnets per VPC", 200.0),
    q("vpc", "L-A4707A72", "Internet gateways per Region", 5.0),
    q("vpc", "L-45FE3B85", "Egress-only internet gateways per Region", 5.0),
    q("vpc", "L-E79EC296", "VPC security groups per Region", 2500.0),
    described(q("vpc", "L-0EA8095F", "Inbound or outbound rules per security group", 60.0), "The maximum number of inbound or outbound rules per VPC security group (120 rules in total)."),
    q("vpc", "L-2AFB9258", "Security groups per network interface", 5.0),
    q("vpc", "L-FE5A380F", "NAT gateways per Availability Zone", 5.0),
    q("vpc", "L-589F43AA", "Route tables per VPC", 200.0),
    q("vpc", "L-93826ACB", "Routes per route table", 50.0),
    q("vpc", "L-DF5E4CA3", "Network interfaces per Region", 5000.0),
    q("vpc", "L-83CA0A9D", "IPv4 CIDR blocks per VPC", 5.0),
    q("vpc", "L-29B6F2EB", "Interface VPC endpoints per VPC", 50.0),
    q("vpc", "L-1B52E74A", "Gateway VPC endpoints per Region", 20.0),
    q("vpc", "L-B4A6D682", "Network ACLs per VPC", 200.0),
    q("vpc", "L-2AEEBF1A", "Rules per network ACL", 20.0),
    q("vpc", "L-7E9ECCDB", "Active VPC peering connections per VPC", 50.0),
    // ---- EBS ------------------------------------------------------------
    unit(q("ebs", "L-D18FCD1D", "Storage for General Purpose SSD (gp2) volumes, in TiB", 50.0), "None"),
    q("ebs", "L-7A658B76", "Storage for General Purpose SSD (gp3) volumes, in TiB", 50.0),
    q("ebs", "L-FD252861", "Storage for Provisioned IOPS SSD (io1) volumes, in TiB", 50.0),
    q("ebs", "L-09BD8365", "Storage for Provisioned IOPS SSD (io2) volumes, in TiB", 20.0),
    q("ebs", "L-82ACEF56", "Storage for Throughput Optimized HDD (st1) volumes, in TiB", 50.0),
    q("ebs", "L-17AF77E8", "Storage for Cold HDD (sc1) volumes, in TiB", 50.0),
    q("ebs", "L-9CF3C2EB", "Storage for Magnetic (standard) volumes, in TiB", 50.0),
    q("ebs", "L-B3A130E6", "IOPS for Provisioned IOPS SSD (io1) volumes", 300000.0),
    q("ebs", "L-8D977E7E", "IOPS for Provisioned IOPS SSD (io2) volumes", 100000.0),
    q("ebs", "L-309BACF6", "Snapshots per Region", 100000.0),
    // ---- EKS / Auto Scaling / ELB ----------------------------------------
    q("eks", "L-1194D53C", "Clusters", 100.0),
    q("eks", "L-6D54EA21", "Managed node groups per cluster", 30.0),
    q("eks", "L-BD136A63", "Nodes per managed node group", 450.0),
    q("eks", "L-33415657", "Fargate profiles per cluster", 10.0),
    q("eks", "L-11427A54", "Control plane security groups per cluster", 4.0),
    q("autoscaling", "L-CDE20ADC", "Auto Scaling groups per region", 500.0),
    q("autoscaling", "L-6B80B8FA", "Launch configurations per region", 200.0),
    q("elasticloadbalancing", "L-53DA6B97", "Application Load Balancers per Region", 50.0),
    q("elasticloadbalancing", "L-69A177A2", "Network Load Balancers per Region", 50.0),
    q("elasticloadbalancing", "L-E9E9831D", "Classic Load Balancers per Region", 20.0),
    q("elasticloadbalancing", "L-B22855CB", "Target Groups per Region", 3000.0),
    q("elasticloadbalancing", "L-7EED9B64", "Rules per Application Load Balancer", 100.0),
    q("elasticloadbalancing", "L-B6DF7632", "Listeners per Application Load Balancer", 50.0),
    q("elasticloadbalancing", "L-57A373D6", "Listeners per Network Load Balancer", 50.0),
    // ---- Storage and databases -------------------------------------------
    global(described(q("s3", "L-DC2B2D3D", "General purpose buckets", 10000.0), "The number of Amazon S3 general purpose buckets that you can create in an account.")),
    q("s3", "L-B461D596", "Replication rules", 1000.0),
    q("elasticfilesystem", "L-848C634D", "File systems per account", 1000.0),
    q("elasticfilesystem", "L-4CCB99B3", "Access points per file system", 10000.0),
    fixed(q("elasticfilesystem", "L-6D380DD0", "Mount targets per Availability Zone", 1.0)),
    q("elasticfilesystem", "L-7391004C", "Mount targets per VPC", 400.0),
    q("rds", "L-7B6409FD", "DB instances", 40.0),
    q("rds", "L-952B80B8", "DB clusters", 40.0),
    unit(q("rds", "L-7ADDB58A", "Total storage for all DB instances", 100000.0), "Gigabytes"),
    q("rds", "L-5BC124EF", "Read replicas per primary", 15.0),
    q("rds", "L-48C6BF61", "DB subnet groups", 50.0),
    q("rds", "L-DE55804A", "Parameter groups", 50.0),
    q("rds", "L-9B510759", "Manual DB cluster snapshots", 100.0),
    q("rds", "L-272F1212", "Manual DB instance snapshots", 100.0),
    q("elasticache", "L-DFE45DF3", "Nodes per Region", 300.0),
    q("elasticache", "L-AF354865", "Nodes per cluster (cluster mode enabled)", 90.0),
    q("elasticache", "L-3E7F7726", "Subnet groups per Region", 150.0),
    q("elasticache", "L-3F15A733", "Parameter groups per Region", 150.0),
    q("elasticache", "L-BBCDAECC", "Serverless Caches per Region", 40.0),
    // ---- Lambda ------------------------------------------------------------
    described(
        usage(
            q("lambda", "L-B99A9384", "Concurrent executions", 1000.0),
            Some(UsageMetric {
                namespace: "AWS/Lambda",
                name: "ConcurrentExecutions",
                dimensions: &[],
                statistic: "Maximum",
            }),
        ),
        "The maximum number of events that functions can process simultaneously in the current region.",
    ),
    unit(q("lambda", "L-2ACBD22F", "Function and layer storage", 75.0), "Gigabytes"),
    fixed(q("lambda", "L-01237738", "Function layers", 5.0)),
    unit(fixed(q("lambda", "L-9FEEFFC0", "Function timeout", 900.0)), "Seconds"),
    unit(fixed(q("lambda", "L-6581F036", "Environment variable size", 4.0)), "Kilobytes"),
    unit(fixed(q("lambda", "L-5C4B2C97", "Synchronous payload", 6.0)), "Megabytes"),
    unit(fixed(q("lambda", "L-7C0F49F9", "Asynchronous payload", 1.0)), "Megabytes"),
    unit(fixed(q("lambda", "L-75F48B05", "Deployment package size (direct upload)", 50.0)), "Megabytes"),
    unit(fixed(q("lambda", "L-E49FF7B8", "Deployment package size (unzipped)", 250.0)), "Megabytes"),
    unit(fixed(q("lambda", "L-07A00131", "Function resource-based policy", 20.0)), "Kilobytes"),
    // ---- Identity and security ---------------------------------------------
    global(described(q("iam", "L-FE177D64", "Roles per account", 1000.0), "Maximum number of IAM roles per account.")),
    global(described(q("iam", "L-0DA4ABF3", "Managed policies per role", 10.0), "Maximum number of managed policies attached to an IAM role.")),
    q("kms", "L-C2F1777E", "Customer Master Keys (CMKs)", 100000.0),
    q("kms", "L-340F62FB", "Aliases per CMK", 50.0),
    q("kms", "L-D594A657", "Grants per CMK", 50000.0),
    q("kms", "L-F33DCFEB", "Custom Key Stores", 10.0),
    q("secretsmanager", "L-2F66C23C", "Secrets", 500000.0),
    unit(fixed(q("secretsmanager", "L-2F24C883", "Secret value size", 65536.0)), "Bytes"),
    unit(fixed(q("secretsmanager", "L-7AA14F8F", "Resource-based policy length", 20480.0)), "Bytes"),
    fixed(q("secretsmanager", "L-7823223D", "Versions per secret", 100.0)),
    fixed(q("secretsmanager", "L-06876EE2", "Staging labels attached across all versions of a secret", 20.0)),
    q("acm", "L-F141DD1D", "ACM certificates", 2500.0),
    q("acm-pca", "L-799883CD", "Number of private certificate authorities", 200.0),
    q("acm-pca", "L-5D3ECC67", "Number of private certificates for each CA", 1000000.0),
    q("guardduty", "L-FA6D6E3D", "Detectors", 1.0),
    q("guardduty", "L-9ABF7A23", "Filters", 100.0),
    q("guardduty", "L-AFBA2260", "Trusted IP sets", 1.0),
    q("guardduty", "L-2C0E14B9", "Threat intel sets", 6.0),
    q("securityhub", "L-D348B3A2", "Number of automation rules", 100.0),
    fixed(q("cloudtrail", "L-1568E18E", "Trails per region", 5.0)),
    q("cloudtrail", "L-FAC66D2D", "Event data stores", 10.0),
    // ---- Networking and DNS -------------------------------------------------
    global(q("route53", "L-4EA4796A", "Hosted zones", 500.0)),
    global(q("route53", "L-ACB674F3", "Health checks", 200.0)),
    global(q("route53", "L-E209CC9F", "Records per hosted zone", 10000.0)),
    // ---- Messaging, streaming and monitoring --------------------------------
    q("sns", "L-61103206", "Topics per Account", 100000.0),
    q("sns", "L-A4340BCD", "Subscriptions per Topic", 12500000.0),
    q("sns", "L-1A43D3DB", "Pending Subscriptions per Account", 5000.0),
    q("sns", "L-4126E74A", "Filter Policies per Account", 200.0),
    q("sns", "L-B96EDA7D", "Filter Policies per Topic", 200.0),
    q("kinesis", "L-0918CF54", "Shards per Region", 500.0),
    q("firehose", "L-14BB0BE7", "Delivery streams", 5000.0),
    q("events", "L-244521F2", "Number of rules", 300.0),
    q("events", "L-388D1D08", "Targets per rule", 5.0),
    q("events", "L-658A4FD9", "Event buses", 100.0),
    q("events", "L-FB1C3A6D", "Api destinations", 3000.0),
    q("events", "L-595D6D42", "Connections", 3000.0),
    q("logs", "L-C7B9AAAB", "Log groups", 1000000.0),
    q("logs", "L-3D5753EA", "Metrics filters per log group", 100.0),
    fixed(q("logs", "L-87E7D306", "Subscription filters per log group", 2.0)),
    fixed(q("logs", "L-89892494", "Resource policies", 10.0)),
    q("ssm", "L-C3B871CB", "Standard parameters", 10000.0),
    fixed(q("ssm", "L-0BB2D2EE", "Parameter versions", 100.0)),
    unit(fixed(q("ssm", "L-BCC99751", "Standard parameter value", 4.0)), "Kilobytes"),
    q("ses", "L-804C8AE8", "Sending quota", 200.0),
    q("ses", "L-5C01A92C", "Email identity count", 10000.0),
    q("ses", "L-10E24536", "Configuration set count", 10000.0),
    q("amplify", "L-1BED97F3", "Apps", 25.0),
    q("amplify", "L-A6716586", "Branches per app", 50.0),
    q("amplify", "L-AD277529", "Domains per app", 5.0),
];

pub fn quota(service: &str, code: &str) -> Option<&'static QuotaDef> {
    QUOTAS.iter().find(|d| d.service == service && d.code == code)
}

pub fn quotas_of(service: &str) -> impl Iterator<Item = &'static QuotaDef> + '_ {
    QUOTAS.iter().filter(move |d| d.service == service)
}

/// The value of the `Service` dimension of `AWS/Usage` API metrics for a
/// SigV4 signing name.
pub fn usage_service_dimension(signing_name: &str) -> Option<&'static str> {
    Some(match signing_name {
        "acm" => "ACM",
        "acm-pca" => "ACMPCA",
        "ce" => "CostExplorer",
        "ec2" => "EC2",
        "events" => "Events",
        "firehose" => "Firehose",
        "iam" => "IAM",
        "kinesis" => "Kinesis",
        "kms" => "KMS",
        "lambda" => "Lambda",
        "logs" => "Logs",
        "monitoring" => "CloudWatch",
        "organizations" => "Organizations",
        "route53" => "Route53",
        "s3" => "S3",
        "secretsmanager" => "SecretsManager",
        "servicequotas" => "ServiceQuotas",
        "sns" => "SNS",
        "sqs" => "SQS",
        "ssm" => "SSM",
        "sts" => "STS",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_quota_names_a_known_service_and_codes_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for d in QUOTAS {
            assert!(service_name(d.service).is_some(), "{} has no service", d.code);
            assert!(seen.insert((d.service, d.code)), "duplicate {} {}", d.service, d.code);
            assert!(d.code.starts_with("L-") && d.code.len() == 10, "{}", d.code);
        }
        for (code, _) in SERVICES {
            assert!(quotas_of(code).next().is_some(), "{code} has no quotas");
        }
    }
}
