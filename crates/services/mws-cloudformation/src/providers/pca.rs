//! AWS Private CA resource types.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::{copy, gone_ok, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::ACMPCA::CertificateAuthority", Arc::new(CertificateAuthority));
    m.insert("AWS::ACMPCA::Certificate", Arc::new(Certificate));
    m.insert("AWS::ACMPCA::CertificateAuthorityActivation", Arc::new(Activation));
    m.insert("AWS::ACMPCA::Permission", Arc::new(Permission));
}

/// Retry a call while the CA is still being created (the CSR is not
/// ready yet), the way the resource handler stabilizes.
async fn retry(cx: &Cx<'_>, op: &str, input: Value) -> HResult<Value> {
    let mut last = None;
    for _ in 0..200 {
        match cx.call("acm-pca", op, input.clone()).await {
            Ok(v) => return Ok(v),
            Err(e) if e.code == "RequestInProgressException" => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| HandlerError::handler("NotStabilized", "timed out")))
}

struct CertificateAuthority;

#[async_trait::async_trait]
impl Provider for CertificateAuthority {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "Type",
            "KeyAlgorithm",
            "SigningAlgorithm",
            "Subject",
            "CsrExtensions",
            "KeyStorageSecurityStandard",
            "UsageMode",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Type", "KeyAlgorithm", "SigningAlgorithm", "Subject"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "CertificateSigningRequest"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut config = Map::new();
        config.insert("KeyAlgorithm".into(), json!(req(props, "KeyAlgorithm")?));
        config.insert("SigningAlgorithm".into(), json!(req(props, "SigningAlgorithm")?));
        config.insert("Subject".into(), props.get("Subject").cloned().unwrap_or_default());
        if let Some(e) = props.get("CsrExtensions") {
            config.insert("CsrExtensions".into(), e.clone());
        }
        let mut input = Map::new();
        input.insert("CertificateAuthorityConfiguration".into(), Value::Object(config));
        input.insert("CertificateAuthorityType".into(), json!(req(props, "Type")?));
        copy(props, &mut input, &["RevocationConfiguration", "KeyStorageSecurityStandard", "UsageMode"]);
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), json!(tags));
        }
        let out = cx.call("acm-pca", "CreateCertificateAuthority", Value::Object(input)).await?;
        let arn = text(&out["CertificateAuthorityArn"]);
        let csr = retry(cx, "GetCertificateAuthorityCsr", json!({"CertificateAuthorityArn": arn})).await?;
        Ok(Created::new(&arn).attr("Arn", arn.clone()).attr("CertificateSigningRequest", csr["Csr"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if super::changed(old, new, "RevocationConfiguration") {
            let rc = new.get("RevocationConfiguration").cloned().unwrap_or_else(|| json!({}));
            cx.call(
                "acm-pca",
                "UpdateCertificateAuthority",
                json!({"CertificateAuthorityArn": arn, "RevocationConfiguration": rc}),
            )
            .await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        // An ACTIVE CA must be disabled before it can be deleted.
        if let Ok(d) = cx.call("acm-pca", "DescribeCertificateAuthority", json!({"CertificateAuthorityArn": arn})).await
        {
            if d["CertificateAuthority"]["Status"] == json!("ACTIVE") {
                let _ = cx
                    .call(
                        "acm-pca",
                        "UpdateCertificateAuthority",
                        json!({"CertificateAuthorityArn": arn, "Status": "DISABLED"}),
                    )
                    .await;
            }
        }
        gone_ok(
            cx.call(
                "acm-pca",
                "DeleteCertificateAuthority",
                json!({"CertificateAuthorityArn": arn, "PermanentDeletionTimeInDays": 7}),
            )
            .await,
        )
    }
}

struct Certificate;

#[async_trait::async_trait]
impl Provider for Certificate {
    fn updatable(&self) -> bool {
        false
    }
    fn required(&self) -> &'static [&'static str] {
        &["CertificateAuthorityArn", "CertificateSigningRequest", "SigningAlgorithm", "Validity"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "Certificate"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let ca = req(props, "CertificateAuthorityArn")?;
        let csr = req(props, "CertificateSigningRequest")?;
        let mut input = Map::new();
        input.insert("CertificateAuthorityArn".into(), json!(ca));
        input.insert(
            "Csr".into(),
            json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, csr.as_bytes())),
        );
        copy(props, &mut input, &["SigningAlgorithm", "TemplateArn", "ApiPassthrough"]);
        let mut validity = props.get("Validity").and_then(Value::as_object).cloned().unwrap_or_default();
        super::numbers(&mut validity, &["Value"]);
        input.insert("Validity".into(), Value::Object(validity));
        if let Some(v) = props.get("ValidityNotBefore").and_then(Value::as_object) {
            let mut v = v.clone();
            super::numbers(&mut v, &["Value"]);
            input.insert("ValidityNotBefore".into(), Value::Object(v));
        }
        input.insert("IdempotencyToken".into(), json!(uuid::Uuid::new_v4().simple().to_string()[..32].to_string()));
        let out = cx.call("acm-pca", "IssueCertificate", Value::Object(input)).await?;
        let arn = text(&out["CertificateArn"]);
        let cert = retry(cx, "GetCertificate", json!({"CertificateAuthorityArn": ca, "CertificateArn": arn})).await?;
        Ok(Created::new(&arn).attr("Arn", arn.clone()).attr("Certificate", cert["Certificate"].clone()))
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        // Deleting the resource revokes nothing in AWS either; the
        // certificate simply expires.
        let _ = (cx, arn, props);
        Ok(())
    }
}

struct Activation;

#[async_trait::async_trait]
impl Provider for Activation {
    fn create_only(&self) -> &'static [&'static str] {
        &["CertificateAuthorityArn"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["CertificateAuthorityArn", "Certificate"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["CompleteCertificateChain"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let ca = req(props, "CertificateAuthorityArn")?;
        let b64 = |v: String| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, v.as_bytes());
        let mut input = json!({"CertificateAuthorityArn": ca, "Certificate": b64(req(props, "Certificate")?)});
        if let Some(chain) = s(props, "CertificateChain") {
            input["CertificateChain"] = json!(b64(chain));
        }
        cx.call("acm-pca", "ImportCertificateAuthorityCertificate", input).await?;
        if let Some(status) = s(props, "Status").filter(|s| s != "ACTIVE") {
            cx.call("acm-pca", "UpdateCertificateAuthority", json!({"CertificateAuthorityArn": ca, "Status": status}))
                .await?;
        }
        let chain =
            cx.call("acm-pca", "GetCertificateAuthorityCertificate", json!({"CertificateAuthorityArn": ca})).await?;
        let full = [text(&chain["Certificate"]), text(&chain["CertificateChain"])]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(Created::new(&ca).attr("CompleteCertificateChain", full))
    }

    async fn update(&self, cx: &Cx<'_>, ca: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if super::changed(old, new, "Certificate") || super::changed(old, new, "CertificateChain") {
            self.create(cx, new).await?;
        } else if super::changed(old, new, "Status") {
            let status = s(new, "Status").unwrap_or_else(|| "ACTIVE".into());
            cx.call("acm-pca", "UpdateCertificateAuthority", json!({"CertificateAuthorityArn": ca, "Status": status}))
                .await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, ca: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        // Removing the activation disables the CA.
        match cx
            .call("acm-pca", "UpdateCertificateAuthority", json!({"CertificateAuthorityArn": ca, "Status": "DISABLED"}))
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.not_found || e.code == "InvalidStateException" => Ok(()),
            Err(e) => Err(e),
        }
    }
}

struct Permission;

#[async_trait::async_trait]
impl Provider for Permission {
    fn updatable(&self) -> bool {
        false
    }
    fn required(&self) -> &'static [&'static str] {
        &["Actions", "CertificateAuthorityArn", "Principal"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        copy(props, &mut input, &["CertificateAuthorityArn", "Principal", "SourceAccount", "Actions"]);
        cx.call("acm-pca", "CreatePermission", Value::Object(input)).await?;
        Ok(Created::new(format!("{}|{}", req(props, "CertificateAuthorityArn")?, req(props, "Principal")?)))
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let mut input = Map::new();
        copy(props, &mut input, &["CertificateAuthorityArn", "Principal", "SourceAccount"]);
        gone_ok(cx.call("acm-pca", "DeletePermission", Value::Object(input)).await)
    }
}
