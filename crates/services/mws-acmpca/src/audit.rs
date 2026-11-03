//! Audit reports: every certificate the CA's key issued or revoked.
//!
//! ACM PCA writes the report to `audit-report/{ca-id}/{report-id}.{json|csv}`
//! in the named S3 bucket, whose policy must let `acm-pca.amazonaws.com`
//! write there.

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use serde_json::{json, Map, Value};

use crate::generated::{errors, types};
use crate::ops::{check_arn, invalid_state};
use crate::revocation::ca_id;
use crate::state::{AuditReport, Ca};
use crate::PrivateCa;

fn ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%z").to_string()
}

const COLUMNS: [&str; 10] = [
    "awsAccountId",
    "certificateArn",
    "serial",
    "subject",
    "notBefore",
    "notAfter",
    "issuedAt",
    "revokedAt",
    "revocationReason",
    "templateArn",
];

fn rows(ca: &Ca) -> Vec<Map<String, Value>> {
    let mut certs: Vec<_> = ca.certs.iter().collect();
    certs.sort_by_key(|(_, c)| c.issued_at);
    certs
        .into_iter()
        .map(|(serial, c)| {
            let mut row = Map::new();
            row.insert("awsAccountId".into(), json!(ca.owner));
            row.insert("certificateArn".into(), json!(format!("{}/certificate/{serial}", ca.arn)));
            let colon: Vec<String> = (0..serial.len() / 2).map(|i| serial[i * 2..i * 2 + 2].to_string()).collect();
            row.insert("serial".into(), json!(colon.join(":")));
            row.insert("subject".into(), json!(c.subject));
            row.insert("notBefore".into(), json!(ts(c.not_before)));
            row.insert("notAfter".into(), json!(ts(c.not_after)));
            row.insert("issuedAt".into(), json!(ts(c.issued_at)));
            if let Some((reason, at)) = &c.revoked {
                row.insert("revokedAt".into(), json!(ts(*at)));
                row.insert("revocationReason".into(), json!(reason));
            }
            row.insert("templateArn".into(), json!(c.template_arn));
            row
        })
        .collect()
}

fn csv_field(v: &str) -> String {
    if v.contains([',', '"', '\n']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

fn render(ca: &Ca, format: &str) -> (Vec<u8>, &'static str) {
    let rows = rows(ca);
    if format == "CSV" {
        let mut out = COLUMNS.join(",");
        out.push('\n');
        for row in rows {
            let line: Vec<String> =
                COLUMNS.iter().map(|c| csv_field(row.get(*c).and_then(Value::as_str).unwrap_or_default())).collect();
            out.push_str(&line.join(","));
            out.push('\n');
        }
        (out.into_bytes(), "text/csv")
    } else {
        let body = serde_json::to_vec(&Value::Array(rows.into_iter().map(Value::Object).collect())).unwrap_or_default();
        (body, "application/json")
    }
}

impl PrivateCa {
    pub(crate) fn create_certificate_authority_audit_report(
        &self,
        ctx: &RequestContext,
        input: types::CreateCertificateAuthorityAuditReportRequest,
    ) -> Result<types::CreateCertificateAuthorityAuditReportResponse, ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "CreateCertificateAuthorityAuditReport", arn)?;
        let format = input.audit_report_response_format.as_str();
        if !matches!(format, "JSON" | "CSV") {
            return Err(errors::invalid_args(format!("The audit report format {format} is not valid.")));
        }
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        if matches!(ca.status.as_str(), "CREATING" | "PENDING_CERTIFICATE" | "DELETED" | "FAILED") {
            return Err(invalid_state(format!(
                "The certificate authority {arn} is not in a valid state ({}).",
                ca.status
            )));
        }
        let report_id = uuid::Uuid::new_v4().to_string();
        let key = format!("audit-report/{}/{report_id}.{}", ca_id(arn), format.to_ascii_lowercase());
        let (body, content_type) = render(ca, format);
        self.publish_audit_report(ca, &input.s3_bucket_name, &key, body, content_type)?;
        ca.audit_reports.insert(
            report_id.clone(),
            AuditReport { bucket: input.s3_bucket_name, key: key.clone(), created_at: Utc::now() },
        );
        Ok(types::CreateCertificateAuthorityAuditReportResponse { audit_report_id: Some(report_id), s3_key: Some(key) })
    }

    pub(crate) fn describe_certificate_authority_audit_report(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCertificateAuthorityAuditReportRequest,
    ) -> Result<types::DescribeCertificateAuthorityAuditReportResponse, ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "DescribeCertificateAuthorityAuditReport", arn)?;
        let st = self.lock();
        let report = st.ca(arn)?.audit_reports.get(&input.audit_report_id).ok_or_else(|| {
            errors::resource_not_found(format!("Could not find audit report {}.", input.audit_report_id))
        })?;
        Ok(types::DescribeCertificateAuthorityAuditReportResponse {
            audit_report_status: Some("SUCCESS".into()),
            s3_bucket_name: Some(report.bucket.clone()),
            s3_key: Some(report.key.clone()),
            created_at: Some(report.created_at),
        })
    }
}
