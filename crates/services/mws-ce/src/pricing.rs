//! Request charges for API calls, at AWS's public on-demand prices
//! (US East; free tiers are not applied).

use mws_core::ApiCall;

pub struct Charge {
    pub service: &'static str,
    pub service_code: &'static str,
    pub usage_type: String,
    pub operation: String,
    pub price: f64,
}

/// The usage type prefix of a Region (`USE2-`; none in US East (N.
/// Virginia), as most of its usage types have none).
pub fn region_prefix(region: &str) -> String {
    let code = match region {
        "us-east-1" => return String::new(),
        "us-east-2" => "USE2",
        "us-west-1" => "USW1",
        "us-west-2" => "USW2",
        "eu-west-1" => "EU",
        "eu-west-2" => "EUW2",
        "eu-west-3" => "EUW3",
        "eu-central-1" => "EUC1",
        "eu-north-1" => "EUN1",
        "ap-southeast-1" => "APS1",
        "ap-southeast-2" => "APS2",
        "ap-northeast-1" => "APN1",
        "ap-northeast-2" => "APN2",
        "ap-south-1" => "APS3",
        "ca-central-1" => "CAN1",
        "sa-east-1" => "SAE1",
        other => return format!("{other}-"),
    };
    format!("{code}-")
}

/// The service code (`AmazonEC2`) of a Cost Explorer service name.
pub fn service_code(service: &str) -> Option<&'static str> {
    Some(match service {
        "Amazon Elastic Compute Cloud - Compute" | "EC2 - Other" => "AmazonEC2",
        "Amazon Simple Storage Service" => "AmazonS3",
        "AWS Key Management Service" => "awskms",
        "AWS Secrets Manager" => "AWSSecretsManager",
        "Amazon Simple Queue Service" => "AWSQueueService",
        "Amazon Simple Notification Service" => "AmazonSNS",
        "AWS Lambda" => "AWSLambda",
        "AmazonCloudWatch" => "AmazonCloudWatch",
        "CloudWatch Events" => "AWSEvents",
        "Amazon Kinesis" => "AmazonKinesis",
        "AWS Cost Explorer" => "AWSCostExplorer",
        "Amazon Relational Database Service" => "AmazonRDS",
        "Amazon ElastiCache" => "AmazonElastiCache",
        "Amazon Elastic Container Service for Kubernetes" => "AmazonEKS",
        "Amazon Elastic Load Balancing" => "AWSELB",
        "Amazon Elastic File System" => "AmazonEFS",
        "Amazon Route 53" => "AmazonRoute53",
        "Amazon Virtual Private Cloud" => "AmazonVPC",
        "Amazon EC2 Container Registry (ECR)" => "AmazonECR",
        "Amazon Bedrock" => "AmazonBedrock",
        "AWS Certificate Manager" => "AWSCertificateManager",
        "Amazon GuardDuty" => "AmazonGuardDuty",
        "AWS Security Hub" => "AWSSecurityHub",
        "AWS CloudTrail" => "AWSCloudTrail",
        "Amazon Simple Email Service" => "AmazonSES",
        "AWS Amplify" => "AWSAmplify",
        "AWS Global Accelerator" => "AWSGlobalAccelerator",
        "AWS Systems Manager" => "AWSSystemsManager",
        "Tax" => "Tax",
        _ => return None,
    })
}

/// What `call` costs, if AWS bills it per request.
pub fn charge(call: &ApiCall) -> Option<Charge> {
    let op = call.operation()?.to_string();
    let p = region_prefix(&call.region);
    let (service, usage_type, price) = match call.service {
        "kms" => ("AWS Key Management Service", format!("{}-KMS-Requests", call.region), 0.03 / 10_000.0),
        "secretsmanager" => ("AWS Secrets Manager", format!("{p}AWSSecretsManager-APIRequest"), 0.05 / 10_000.0),
        "sqs" => ("Amazon Simple Queue Service", format!("{p}Requests-Tier1"), 0.40 / 1_000_000.0),
        "sns" if op == "Publish" || op == "PublishBatch" => {
            ("Amazon Simple Notification Service", format!("{p}Requests-Tier1"), 0.50 / 1_000_000.0)
        }
        "lambda" if op == "InvokeFunction" => ("AWS Lambda", format!("{p}Request"), 0.20 / 1_000_000.0),
        "s3" => match op.as_str() {
            "PutObject"
            | "ListBucket"
            | "ListAllMyBuckets"
            | "ListBucketVersions"
            | "ListBucketMultipartUploads"
            | "CreateBucket" => ("Amazon Simple Storage Service", format!("{p}Requests-Tier1"), 0.005 / 1_000.0),
            "GetObject" | "GetObjectVersion" => {
                ("Amazon Simple Storage Service", format!("{p}Requests-Tier2"), 0.0004 / 1_000.0)
            }
            _ => return None,
        },
        "monitoring" => match op.as_str() {
            "GetMetricData" => ("AmazonCloudWatch", format!("{p}CW:GMD-Metrics"), 0.01 / 1_000.0),
            "PutMetricData" | "GetMetricStatistics" | "ListMetrics" | "GetMetricWidgetImage" => {
                ("AmazonCloudWatch", format!("{p}CW:Requests"), 0.01 / 1_000.0)
            }
            _ => return None,
        },
        "events" if op == "PutEvents" => ("CloudWatch Events", format!("{p}Event"), 1.0 / 1_000_000.0),
        "kinesis" if op == "PutRecord" || op == "PutRecords" => {
            ("Amazon Kinesis", format!("{p}PutRequestPayloadUnitsTier1"), 0.014 / 1_000_000.0)
        }
        "ce" if op.starts_with("Get") => ("AWS Cost Explorer", "APIRequest".to_string(), 0.01),
        _ => return None,
    };
    Some(Charge { service, service_code: service_code(service).unwrap_or(""), usage_type, operation: op, price })
}
