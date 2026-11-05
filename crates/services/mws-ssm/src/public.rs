//! Public parameters: the read-only `/aws/service/...` parameters AWS
//! publishes in every Region (Region and service catalogues, latest Amazon
//! Linux and ECS-optimized AMI ids). Their ARNs have no account
//! (`arn:aws:ssm:us-east-1::parameter/aws/service/...`). MWS has no EC2, so
//! AMI ids are stable made-up `ami-` ids, distinct per Region and image.

use chrono::{DateTime, TimeZone, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types;
use crate::names::under_path;

pub const PREFIX: &str = "/aws/service/";

/// Commercial Regions and their long names.
const REGIONS: &[(&str, &str)] = &[
    ("af-south-1", "Africa (Cape Town)"),
    ("ap-east-1", "Asia Pacific (Hong Kong)"),
    ("ap-northeast-1", "Asia Pacific (Tokyo)"),
    ("ap-northeast-2", "Asia Pacific (Seoul)"),
    ("ap-northeast-3", "Asia Pacific (Osaka)"),
    ("ap-south-1", "Asia Pacific (Mumbai)"),
    ("ap-south-2", "Asia Pacific (Hyderabad)"),
    ("ap-southeast-1", "Asia Pacific (Singapore)"),
    ("ap-southeast-2", "Asia Pacific (Sydney)"),
    ("ap-southeast-3", "Asia Pacific (Jakarta)"),
    ("ap-southeast-4", "Asia Pacific (Melbourne)"),
    ("ap-southeast-5", "Asia Pacific (Malaysia)"),
    ("ap-southeast-7", "Asia Pacific (Thailand)"),
    ("ca-central-1", "Canada (Central)"),
    ("ca-west-1", "Canada West (Calgary)"),
    ("eu-central-1", "Europe (Frankfurt)"),
    ("eu-central-2", "Europe (Zurich)"),
    ("eu-north-1", "Europe (Stockholm)"),
    ("eu-south-1", "Europe (Milan)"),
    ("eu-south-2", "Europe (Spain)"),
    ("eu-west-1", "Europe (Ireland)"),
    ("eu-west-2", "Europe (London)"),
    ("eu-west-3", "Europe (Paris)"),
    ("il-central-1", "Israel (Tel Aviv)"),
    ("me-central-1", "Middle East (UAE)"),
    ("me-south-1", "Middle East (Bahrain)"),
    ("mx-central-1", "Mexico (Central)"),
    ("sa-east-1", "South America (Sao Paulo)"),
    ("us-east-1", "US East (N. Virginia)"),
    ("us-east-2", "US East (Ohio)"),
    ("us-west-1", "US West (N. California)"),
    ("us-west-2", "US West (Oregon)"),
];

/// Services in the catalogue: the ones MWS emulates.
const SERVICES: &[(&str, &str)] = &[
    ("acm", "AWS Certificate Manager"),
    ("acm-pca", "AWS Private Certificate Authority"),
    ("cloudwatch", "Amazon CloudWatch"),
    ("events", "Amazon EventBridge"),
    ("iam", "AWS Identity and Access Management (IAM)"),
    ("kms", "AWS Key Management Service"),
    ("lambda", "AWS Lambda"),
    ("logs", "Amazon CloudWatch Logs"),
    ("organizations", "AWS Organizations"),
    ("route53", "Amazon Route 53"),
    ("s3", "Amazon Simple Storage Service (S3)"),
    ("secretsmanager", "AWS Secrets Manager"),
    ("sns", "Amazon Simple Notification Service (SNS)"),
    ("sqs", "Amazon Simple Queue Service (SQS)"),
    ("ssm", "AWS Systems Manager"),
    ("sts", "AWS Security Token Service"),
];

/// AMI parameters, relative to `/aws/service/`.
const IMAGES: &[&str] = &[
    "ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
    "ami-amazon-linux-latest/al2023-ami-kernel-default-arm64",
    "ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64",
    "ami-amazon-linux-latest/al2023-ami-kernel-6.1-arm64",
    "ami-amazon-linux-latest/al2023-ami-minimal-kernel-default-x86_64",
    "ami-amazon-linux-latest/al2023-ami-minimal-kernel-default-arm64",
    "ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2",
    "ami-amazon-linux-latest/amzn2-ami-hvm-arm64-gp2",
    "ami-amazon-linux-latest/amzn2-ami-kernel-5.10-hvm-x86_64-gp2",
    "ami-amazon-linux-latest/amzn2-ami-kernel-5.10-hvm-arm64-gp2",
    "ecs/optimized-ami/amazon-linux-2023/recommended/image_id",
    "ecs/optimized-ami/amazon-linux-2023/arm64/recommended/image_id",
    "ecs/optimized-ami/amazon-linux-2/recommended/image_id",
    "eks/optimized-ami/1.29/amazon-linux-2023/x86_64/standard/recommended/image_id",
    "eks/optimized-ami/1.29/amazon-linux-2023/arm64/standard/recommended/image_id",
    "eks/optimized-ami/1.30/amazon-linux-2023/x86_64/standard/recommended/image_id",
    "eks/optimized-ami/1.30/amazon-linux-2023/arm64/standard/recommended/image_id",
    "eks/optimized-ami/1.31/amazon-linux-2023/x86_64/standard/recommended/image_id",
    "eks/optimized-ami/1.31/amazon-linux-2023/arm64/standard/recommended/image_id",
    "eks/optimized-ami/1.32/amazon-linux-2023/x86_64/standard/recommended/image_id",
    "eks/optimized-ami/1.32/amazon-linux-2023/arm64/standard/recommended/image_id",
    "eks/optimized-ami/1.33/amazon-linux-2023/x86_64/standard/recommended/image_id",
    "eks/optimized-ami/1.33/amazon-linux-2023/arm64/standard/recommended/image_id",
    "eks/optimized-ami/1.34/amazon-linux-2023/x86_64/standard/recommended/image_id",
    "eks/optimized-ami/1.34/amazon-linux-2023/arm64/standard/recommended/image_id",
    "eks/optimized-ami/1.35/amazon-linux-2023/x86_64/standard/recommended/image_id",
    "eks/optimized-ami/1.35/amazon-linux-2023/arm64/standard/recommended/image_id",
    "eks/optimized-ami/1.29/amazon-linux-2/recommended/image_id",
    "eks/optimized-ami/1.29/amazon-linux-2-arm64/recommended/image_id",
    "eks/optimized-ami/1.30/amazon-linux-2/recommended/image_id",
    "eks/optimized-ami/1.30/amazon-linux-2-arm64/recommended/image_id",
    "eks/optimized-ami/1.31/amazon-linux-2/recommended/image_id",
    "eks/optimized-ami/1.31/amazon-linux-2-arm64/recommended/image_id",
    "eks/optimized-ami/1.32/amazon-linux-2/recommended/image_id",
    "eks/optimized-ami/1.32/amazon-linux-2-arm64/recommended/image_id",
];

/// One public parameter.
pub struct Public {
    pub name: String,
    pub value: String,
    pub data_type: &'static str,
}

fn ami_id(region: &str, image: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, format!("{region}/{image}").as_bytes());
    let hex: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("ami-{}", &hex[..17])
}

/// Every public parameter in `region`, sorted by name.
pub fn catalogue(region: &str) -> Vec<Public> {
    let text = |name: String, value: &str| Public { name, value: value.to_string(), data_type: "text" };
    let mut out = Vec::new();
    for (code, long) in REGIONS {
        let base = format!("{PREFIX}global-infrastructure/regions/{code}");
        out.push(text(format!("{base}/domain"), "amazonaws.com"));
        out.push(text(format!("{base}/longName"), long));
        out.push(text(format!("{base}/partition"), "aws"));
        out.push(text(base, code));
    }
    for (code, long) in SERVICES {
        let base = format!("{PREFIX}global-infrastructure/services/{code}");
        out.push(text(format!("{base}/longName"), long));
        for (r, _) in REGIONS {
            out.push(text(format!("{base}/regions/{r}"), r));
        }
        out.push(text(base, code));
    }
    out.push(text(format!("{PREFIX}global-infrastructure/current-region"), region));
    for image in IMAGES {
        out.push(Public { name: format!("{PREFIX}{image}"), value: ami_id(region, image), data_type: "aws:ec2:image" });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn published() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).single().expect("valid date")
}

pub fn arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:ssm:{}::parameter{}", ctx.partition, ctx.region, name)
}

/// `name` given as a public parameter's name or ARN, as its name.
pub fn public_name(ctx: &RequestContext, input: &str) -> Option<String> {
    let name = match input.strip_prefix(&format!("arn:{}:ssm:{}::parameter", ctx.partition, ctx.region)) {
        Some(rest) => rest,
        None => input,
    };
    name.starts_with(PREFIX).then(|| name.to_string())
}

pub fn render(ctx: &RequestContext, p: &Public, by_arn: bool) -> types::Parameter {
    let arn = arn(ctx, &p.name);
    types::Parameter {
        name: Some(if by_arn { arn.clone() } else { p.name.clone() }),
        r#type: Some("String".into()),
        value: Some(p.value.clone()),
        version: 1,
        selector: None,
        source_result: None,
        last_modified_date: Some(published()),
        arn: Some(arn),
        data_type: Some(p.data_type.into()),
    }
}

/// `GetParameter(s)` for a public parameter.
pub fn read(ctx: &RequestContext, action: &str, input: &str, name: &str) -> Result<types::Parameter, ServiceError> {
    let (bare, selector) = match name.rsplit_once(':') {
        Some((n, s)) => (n, Some(s)),
        None => (name, None),
    };
    ctx.authorize(&format!("ssm:{action}"), &arn(ctx, bare), ConditionContext::new())?;
    let not_found = || crate::names::not_found(input);
    let found = catalogue(&ctx.region).into_iter().find(|p| p.name == bare).ok_or_else(not_found)?;
    match selector {
        None | Some("1") => {}
        Some(s) if s.bytes().all(|b| b.is_ascii_digit()) => {
            return Err(crate::generated::errors::parameter_version_not_found(format!(
                "Systems Manager could not find version {s} of {bare}. Verify the version and try again."
            )));
        }
        Some(_) => return Err(not_found()),
    }
    let mut p = render(ctx, &found, input.starts_with("arn:"));
    p.selector = selector.map(|s| format!(":{s}"));
    Ok(p)
}

/// The public parameters under `path`.
pub fn under(ctx: &RequestContext, path: &str, recursive: bool) -> Vec<types::Parameter> {
    catalogue(&ctx.region)
        .iter()
        .filter(|p| under_path(&p.name, path, recursive))
        .map(|p| render(ctx, p, false))
        .collect()
}
