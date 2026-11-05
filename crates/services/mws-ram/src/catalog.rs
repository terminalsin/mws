//! AWS managed permissions: the permission library RAM ships for each
//! resource type it can share.

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};

/// One AWS managed permission (always version 1 here).
#[derive(Debug, Clone)]
pub struct Managed {
    pub name: &'static str,
    pub resource_type: &'static str,
    pub is_default: bool,
    /// Statements without `Principal` or `Resource`.
    pub statements: Vec<Value>,
}

impl Managed {
    pub fn arn(&self, partition: &str) -> String {
        format!("arn:{partition}:ram::aws:permission/{}", self.name)
    }

    /// The policy template as `GetPermission` shows it.
    pub fn template(&self, partition: &str) -> String {
        let doc = if self.statements.len() == 1 {
            self.statements[0].clone()
        } else {
            json!({ "Statement": self.statements })
        };
        doc.to_string().replace("arn:aws:", &format!("arn:{partition}:"))
    }
}

/// When the AWS managed permissions were published.
pub fn published() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2021, 6, 1, 0, 0, 0).single().expect("valid date")
}

const CA_READ: [&str; 5] = [
    "acm-pca:DescribeCertificateAuthority",
    "acm-pca:GetCertificate",
    "acm-pca:GetCertificateAuthorityCertificate",
    "acm-pca:ListPermissions",
    "acm-pca:ListTags",
];

fn ca_issuance(name: &'static str, template: &str, is_default: bool) -> Managed {
    Managed {
        name,
        resource_type: "acm-pca:CertificateAuthority",
        is_default,
        statements: vec![
            json!({ "Effect": "Allow", "Action": CA_READ }),
            json!({
                "Effect": "Allow",
                "Action": ["acm-pca:IssueCertificate"],
                "Condition": { "StringEquals": { "acm-pca:TemplateArn": format!("arn:aws:acm-pca:::template/{template}/V1") } }
            }),
        ],
    }
}

/// Every AWS managed permission, for every resource type RAM knows.
pub fn all() -> Vec<Managed> {
    vec![
        ca_issuance("AWSRAMDefaultPermissionCertificateAuthority", "EndEntityCertificate", true),
        ca_issuance(
            "AWSRAMBlankEndEntityCertificateAPIPassthroughIssuanceCertificateAuthority",
            "BlankEndEntityCertificate_APIPassthrough",
            false,
        ),
        ca_issuance(
            "AWSRAMBlankEndEntityCertificateAPICSRPassthroughIssuanceCertificateAuthority",
            "BlankEndEntityCertificate_APICSRPassthrough",
            false,
        ),
        ca_issuance(
            "AWSRAMEndEntityClientAuthCertificateIssuanceCertificateAuthority",
            "EndEntityClientAuthCertificate",
            false,
        ),
        ca_issuance(
            "AWSRAMEndEntityServerAuthCertificateIssuanceCertificateAuthority",
            "EndEntityServerAuthCertificate",
            false,
        ),
        ca_issuance(
            "AWSRAMSubordinateCACertificatePathLen0IssuanceCertificateAuthority",
            "SubordinateCACertificate_PathLen0",
            false,
        ),
        Managed {
            name: "AWSRAMRevokeCertificateCertificateAuthority",
            resource_type: "acm-pca:CertificateAuthority",
            is_default: false,
            statements: vec![
                json!({ "Effect": "Allow", "Action": CA_READ }),
                json!({ "Effect": "Allow", "Action": ["acm-pca:RevokeCertificate"] }),
            ],
        },
    ]
}

/// The AWS managed permission named by `arn`, if any.
pub fn find(arn: &str) -> Option<Managed> {
    let name = arn.strip_prefix("arn:").and_then(|r| r.split_once(":ram::aws:permission/")).map(|(_, n)| n)?;
    all().into_iter().find(|m| m.name == name)
}
