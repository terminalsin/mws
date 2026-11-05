//! ACM resource types.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::{changed, copy, gone_ok, list, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::CertificateManager::Certificate", Arc::new(Certificate));
}

struct Certificate;

/// How long a create waits for validation before failing. AWS waits as
/// long as the stack timeout allows; this caps a forgotten stack.
const VALIDATION_WAIT: Duration = Duration::from_secs(3600);

#[async_trait::async_trait]
impl Provider for Certificate {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "DomainName",
            "SubjectAlternativeNames",
            "ValidationMethod",
            "DomainValidationOptions",
            "CertificateAuthorityArn",
            "KeyAlgorithm",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["DomainName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        copy(props, &mut input, &["DomainName", "ValidationMethod", "CertificateAuthorityArn", "KeyAlgorithm"]);
        let sans = list(props, "SubjectAlternativeNames");
        if !sans.is_empty() {
            input.insert("SubjectAlternativeNames".into(), json!(sans));
        }
        let dvo: Vec<Value> =
            props.get("DomainValidationOptions").and_then(Value::as_array).cloned().unwrap_or_default();
        let email: Vec<Value> = dvo
            .iter()
            .filter(|d| d.get("ValidationDomain").is_some())
            .map(|d| json!({"DomainName": d.get("DomainName").map(text), "ValidationDomain": d.get("ValidationDomain").map(text)}))
            .collect();
        if !email.is_empty() {
            input.insert("DomainValidationOptions".into(), json!(email));
        }
        if let Some(p) = props.get("CertificateTransparencyLoggingPreference") {
            input.insert("Options".into(), json!({"CertificateTransparencyLoggingPreference": text(p)}));
        }
        input.insert("IdempotencyToken".into(), json!(uuid::Uuid::new_v4().simple().to_string()[..32].to_string()));
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), json!(tags));
        }
        let out = cx.call("acm", "RequestCertificate", Value::Object(input)).await?;
        let arn = text(&out["CertificateArn"]);
        // Zones to write validation records into, by domain.
        let zones: BTreeMap<String, String> = dvo
            .iter()
            .filter_map(|d| Some((d.get("DomainName").map(text)?, d.get("HostedZoneId").map(text)?)))
            .collect();
        let mut written = false;
        let start = tokio::time::Instant::now();
        loop {
            let d = cx.call("acm", "DescribeCertificate", json!({"CertificateArn": arn})).await?;
            let c = &d["Certificate"];
            match c["Status"].as_str() {
                Some("ISSUED") => break,
                Some("PENDING_VALIDATION") | None => {}
                Some(other) => {
                    let _ = cx.call("acm", "DeleteCertificate", json!({"CertificateArn": arn})).await;
                    return Err(HandlerError::handler(
                        "NotStabilized",
                        format!("Certificate {arn} reached status {other}: {}", text(&c["FailureReason"])),
                    ));
                }
            }
            if !written && !zones.is_empty() {
                let options = c["DomainValidationOptions"].as_array().cloned().unwrap_or_default();
                let records: Vec<(String, Value)> = options
                    .iter()
                    .filter_map(|o| {
                        let zone = zones.get(&text(&o["DomainName"]))?;
                        let r = o.get("ResourceRecord")?;
                        Some((zone.clone(), r.clone()))
                    })
                    .collect();
                if records.len() == zones.len() {
                    for (zone, r) in records {
                        cx.call(
                            "route53",
                            "ChangeResourceRecordSets",
                            json!({"HostedZoneId": zone, "ChangeBatch": {"Changes": [{"Action": "UPSERT", "ResourceRecordSet": {
                                "Name": text(&r["Name"]), "Type": text(&r["Type"]), "TTL": 300, "ResourceRecords": [{"Value": text(&r["Value"])}]
                            }}]}}),
                        )
                        .await?;
                    }
                    written = true;
                }
            }
            if start.elapsed() > VALIDATION_WAIT {
                return Err(HandlerError::handler(
                    "NotStabilized",
                    format!("Certificate {arn} was not validated in time"),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Ok(Created::new(arn))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "CertificateTransparencyLoggingPreference") {
            let p = s(new, "CertificateTransparencyLoggingPreference").unwrap_or_else(|| "ENABLED".into());
            cx.call(
                "acm",
                "UpdateCertificateOptions",
                json!({"CertificateArn": arn, "Options": {"CertificateTransparencyLoggingPreference": p}}),
            )
            .await?;
        }
        if changed(old, new, "Tags") {
            let keys: Vec<String> = cx.tags(new).iter().map(|t| text(&t["Key"])).collect();
            let removed: Vec<Value> = cx.tags(old).into_iter().filter(|t| !keys.contains(&text(&t["Key"]))).collect();
            if !removed.is_empty() {
                cx.call("acm", "RemoveTagsFromCertificate", json!({"CertificateArn": arn, "Tags": removed})).await?;
            }
            let tags = cx.tags(new);
            if !tags.is_empty() {
                cx.call("acm", "AddTagsToCertificate", json!({"CertificateArn": arn, "Tags": tags})).await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("acm", "DeleteCertificate", json!({"CertificateArn": arn})).await)
    }
}
