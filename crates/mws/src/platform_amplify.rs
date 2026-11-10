//! What Amplify reaches in other services: IAM roles handed to it, its
//! service role assumed as `amplify.amazonaws.com` for builds, secrets in
//! SSM Parameter Store and custom certificates in ACM.

use async_trait::async_trait;
use mws_amplify::{CertificateInfo, RoleSession};
use mws_core::{RequestContext, Service};

pub(crate) struct AmplifyPlatform {
    pub iam: mws_iam::Iam,
    pub sts: mws_sts::Sts,
    pub ssm: mws_ssm::Ssm,
    pub acm: mws_acm::Acm,
}

#[async_trait]
impl mws_amplify::AmplifyPlatform for AmplifyPlatform {
    fn role_exists(&self, role_arn: &str) -> bool {
        self.iam.role_by_arn(role_arn).is_some()
    }

    fn assume_role(
        &self,
        template: &RequestContext,
        role_arn: &str,
        session_name: &str,
        source_account: &str,
        source_arn: &str,
    ) -> Result<RoleSession, String> {
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: "amplify.amazonaws.com",
                session_name,
                duration_seconds: 3600,
                source_account: Some(source_account),
                source_arn: Some(source_arn),
                now: template.received_at,
            })
            .map_err(|e| format!("{e:?}"))?;
        let caller = self
            .sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), template.received_at)
            .map_err(|e| format!("{e:?}"))?
            .map(|r| r.caller)
            .ok_or_else(|| "the role session could not be resolved".to_string())?;
        Ok(RoleSession {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            context: RequestContext { caller, source_ip: None, ..template.clone() },
        })
    }

    async fn parameters_by_path(&self, ctx: &RequestContext, path: &str) -> Result<Vec<(String, String)>, String> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut input = serde_json::json!({
                "Path": path.trim_end_matches('/'),
                "Recursive": true,
                "WithDecryption": true,
                "MaxResults": 10,
            });
            if let Some(t) = &token {
                input["NextToken"] = t.clone().into();
            }
            let page = self
                .ssm
                .invoke(ctx.clone(), "GetParametersByPath", input)
                .await
                .map_err(|e| format!("{}: {}", e.code, e.message))?;
            for p in page["Parameters"].as_array().into_iter().flatten() {
                if let (Some(name), Some(value)) = (p["Name"].as_str(), p["Value"].as_str()) {
                    out.push((name.to_string(), value.to_string()));
                }
            }
            token = page["NextToken"].as_str().filter(|t| !t.is_empty()).map(str::to_string);
            if token.is_none() {
                return Ok(out);
            }
        }
    }

    fn certificate(&self, arn: &str) -> Option<CertificateInfo> {
        let c = self.acm.server_certificate(arn)?;
        Some(CertificateInfo {
            account: c.account,
            region: c.region,
            status: c.status,
            domain_name: c.domain_name,
            subject_alternative_names: c.subject_alternative_names,
        })
    }
}
