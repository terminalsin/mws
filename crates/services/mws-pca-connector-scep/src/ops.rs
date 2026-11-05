//! The Connector for SCEP API: connectors, challenge passwords and tags.

use std::collections::BTreeMap;

use chrono::Duration;
use mws_acmpca::{ServiceIssue, ServiceIssueError};
use mws_core::{ConditionContext, ErrorValue, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::{errors, types};
use crate::state::{Challenge, Connector, State};
use crate::{ScepConnector, SERVICE_PRINCIPAL};

/// The template connectors issue with (the RAM permission AWS documents
/// for sharing a CA with Connector for SCEP allows exactly this one).
pub const TEMPLATE: &str = "arn:aws:acm-pca:::template/BlankEndEntityCertificate_APICSRPassthrough/V1";
const MAX_CHALLENGES: usize = 5;

pub fn not_found(id: &str, ty: &str) -> ServiceError {
    errors::resource_not_found(format!("The {} {id} does not exist.", ty.to_ascii_lowercase()))
        .with_field("ResourceId", ErrorValue::String(id.to_string()))
        .with_field("ResourceType", ErrorValue::String(ty.to_string()))
}

pub fn validation(reason: &str, message: impl Into<String>) -> ServiceError {
    errors::validation(message).with_field("Reason", ErrorValue::String(reason.to_string()))
}

fn paginate<T>(items: Vec<T>, max: Option<i32>, token: Option<&str>) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| validation("OTHER", "The next token is not valid."))?,
        None => 0,
    };
    let max = max.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(100);
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + max < total).then(|| format!("mws-{}", start + max));
    Ok((page, next))
}

fn tag_context(tags: &BTreeMap<String, String>, prefix: &str) -> ConditionContext {
    let mut cond: ConditionContext = tags.iter().map(|(k, v)| (format!("{prefix}{k}"), vec![v.clone()])).collect();
    if prefix == "aws:RequestTag/" && !tags.is_empty() {
        cond.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    cond
}

fn check_tags(tags: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    for k in tags.keys() {
        if k.to_ascii_lowercase().starts_with("aws:") {
            return Err(validation("OTHER", format!("The tag key {k} uses the reserved prefix aws:.")));
        }
    }
    if tags.len() > 50 {
        return Err(validation("OTHER", "A resource can have at most 50 tags."));
    }
    Ok(())
}

impl Connector {
    fn wire(&self) -> types::Connector {
        types::Connector {
            arn: Some(self.arn.clone()),
            certificate_authority_arn: Some(self.ca_arn.clone()),
            r#type: Some(self.ty.clone()),
            mobile_device_management: self.mdm.clone(),
            open_id_configuration: self.openid.clone(),
            status: Some(self.status.clone()),
            status_reason: self.status_reason.clone(),
            endpoint: Some(self.endpoint.clone()),
            created_at: self.created,
            updated_at: self.updated,
        }
    }

    fn summary(&self) -> types::ConnectorSummary {
        let c = self.wire();
        types::ConnectorSummary {
            arn: c.arn,
            certificate_authority_arn: c.certificate_authority_arn,
            r#type: c.r#type,
            mobile_device_management: c.mobile_device_management,
            open_id_configuration: c.open_id_configuration,
            status: c.status,
            status_reason: c.status_reason,
            endpoint: c.endpoint,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

/// A fresh RSA key and a CSR for the connector's registration authority.
fn ra_key_and_csr(id: &str) -> Result<(Vec<u8>, String), ServiceError> {
    let key = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
        .map_err(|e| ServiceError::internal(format!("generating the RA key: {e}")))?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, format!("Connector for SCEP RA {id}"));
    let csr = params
        .serialize_request(&key)
        .and_then(|c| c.pem())
        .map_err(|e| ServiceError::internal(format!("creating the RA CSR: {e}")))?;
    Ok((key.serialize_der(), csr))
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok().map(|(_, p)| p.contents)
}

impl ScepConnector {
    fn owned_connector<'s>(&self, st: &'s State, ctx: &RequestContext, arn: &str) -> Result<&'s Connector, ServiceError> {
        st.connectors
            .get(arn)
            .filter(|c| c.owner == ctx.caller.account_id && c.region == ctx.region)
            .ok_or_else(|| not_found(arn, "Connector"))
    }

    fn owned_challenge<'s>(&self, st: &'s State, ctx: &RequestContext, arn: &str) -> Result<&'s Challenge, ServiceError> {
        st.challenges
            .get(arn)
            .filter(|c| c.owner == ctx.caller.account_id && st.connectors.get(&c.connector_arn).is_some_and(|k| k.region == ctx.region))
            .ok_or_else(|| not_found(arn, "Challenge"))
    }

    fn resource_tags(&self, arn: &str) -> BTreeMap<String, String> {
        let st = self.lock();
        st.connectors.get(arn).map(|c| c.tags.clone()).or_else(|| st.challenges.get(arn).map(|c| c.tags.clone())).unwrap_or_default()
    }

    fn authorize_on(&self, ctx: &RequestContext, action: &str, arn: &str) -> Result<(), ServiceError> {
        let cond = tag_context(&self.resource_tags(arn), "aws:ResourceTag/");
        ctx.authorize(&format!("pca-connector-scep:{action}"), arn, cond)
    }

    pub(crate) fn create_connector(
        &self,
        ctx: &RequestContext,
        input: types::CreateConnectorRequest,
    ) -> Result<types::CreateConnectorResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        ctx.authorize("pca-connector-scep:CreateConnector", "*", tag_context(&tags, "aws:RequestTag/"))?;
        check_tags(&tags)?;
        let token = input.client_token.as_ref().map(|t| format!("{}/{t}", ctx.caller.account_id));
        if let Some(arn) = token.as_ref().and_then(|t| self.lock().client_tokens.get(t).cloned()) {
            return Ok(types::CreateConnectorResponse { connector_arn: Some(arn) });
        }
        let ca_arn = input.certificate_authority_arn.clone();
        let in_region = ca_arn.split(':').nth(3) == Some(ctx.region.as_str()) && ca_arn.contains(":certificate-authority/");
        let ca = self
            .pca
            .ca_info(&ca_arn)
            .filter(|_| in_region)
            .ok_or_else(|| not_found(&ca_arn, "CertificateAuthority"))?;
        if ca.owner != ctx.caller.account_id {
            return Err(errors::access_denied(
                "You can use Connector for SCEP only with a private CA that your account owns.",
            ));
        }
        if ca.usage_mode != "GENERAL_PURPOSE" {
            return Err(validation(
                "INVALID_CA_USAGE_MODE",
                "The certificate authority must use the GENERAL_PURPOSE usage mode.",
            ));
        }
        if ca.status != "ACTIVE" {
            return Err(validation("INVALID_STATE", "The certificate authority is not active."));
        }
        let now = ctx.received_at;
        if ca.not_after.is_none_or(|end| end - now < Duration::days(365)) {
            return Err(validation(
                "CA_CERT_VALIDITY_TOO_SHORT",
                "The certificate authority certificate validity must be at least one year from today.",
            ));
        }
        let ty = match &input.mobile_device_management {
            Some(types::MobileDeviceManagement::Intune(_)) => "INTUNE",
            None => "GENERAL_PURPOSE",
        };
        let id = uuid::Uuid::new_v4().to_string();
        let arn = format!("arn:{}:pca-connector-scep:{}:{}:connector/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
        let base = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
        let openid = (ty == "INTUNE").then(|| types::OpenIdConfiguration {
            issuer: Some(format!("https://oidc.pca-connector-scep.{}.amazonaws.com/{id}", ctx.region)),
            subject: Some(format!("connector/{id}")),
            audience: Some("api://AzureADTokenExchange".into()),
        });

        // The registration authority certificate comes from the CA, issued
        // as the connector's service principal: it is also how the
        // connector finds out whether the CA is shared with it.
        let (ra_key, csr) = ra_key_and_csr(&id)?;
        let ra_validity = ca.not_after.map(|end| end.min(now + Duration::days(365))).unwrap_or(now + Duration::days(365));
        let issued = self.pca.issue_as_service(ServiceIssue {
            service_principal: SERVICE_PRINCIPAL,
            source_account: &ctx.caller.account_id,
            source_arn: &arn,
            ca_arn: &ca_arn,
            csr: csr.as_bytes(),
            template_arn: &TEMPLATE.replace("arn:aws:", &format!("arn:{}:", ctx.partition)),
            not_after: ra_validity,
            api_passthrough: Some(ra_passthrough()),
            now,
        });
        let (status, reason, ra_cert) = match issued {
            Ok(i) => ("ACTIVE", None, pem_to_der(&i.certificate_pem).unwrap_or_default()),
            Err(ServiceIssueError::AccessDenied) => ("FAILED", Some("PRIVATECA_ACCESS_DENIED"), Vec::new()),
            Err(ServiceIssueError::NotFound) => ("FAILED", Some("PRIVATECA_RESOURCE_NOT_FOUND"), Vec::new()),
            Err(ServiceIssueError::Refused(e)) => {
                tracing::debug!("Connector for SCEP RA issuance refused: {e:?}");
                ("FAILED", Some("PRIVATECA_INVALID_STATE"), Vec::new())
            }
        };
        let connector = Connector {
            arn: arn.clone(),
            id: id.clone(),
            owner: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            ca_arn,
            ty: ty.into(),
            mdm: input.mobile_device_management,
            openid,
            status: status.into(),
            status_reason: reason.map(str::to_string),
            endpoint: format!("{base}/_aws/pca-connector-scep/{id}"),
            created: Some(now),
            updated: Some(now),
            tags,
            ra_key,
            ra_cert,
            issued: BTreeMap::new(),
        };
        let mut st = self.lock();
        if let Some(t) = token {
            st.client_tokens.insert(t, arn.clone());
        }
        st.connectors.insert(arn.clone(), connector);
        Ok(types::CreateConnectorResponse { connector_arn: Some(arn) })
    }

    pub(crate) fn get_connector(
        &self,
        ctx: &RequestContext,
        input: types::GetConnectorRequest,
    ) -> Result<types::GetConnectorResponse, ServiceError> {
        self.authorize_on(ctx, "GetConnector", &input.connector_arn)?;
        let st = self.lock();
        Ok(types::GetConnectorResponse { connector: Some(self.owned_connector(&st, ctx, &input.connector_arn)?.wire()) })
    }

    pub(crate) fn list_connectors(
        &self,
        ctx: &RequestContext,
        input: types::ListConnectorsRequest,
    ) -> Result<types::ListConnectorsResponse, ServiceError> {
        ctx.authorize("pca-connector-scep:ListConnectors", "*", ConditionContext::new())?;
        let st = self.lock();
        let all: Vec<_> = st
            .connectors
            .values()
            .filter(|c| c.owner == ctx.caller.account_id && c.region == ctx.region)
            .map(Connector::summary)
            .collect();
        let (page, next) = paginate(all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListConnectorsResponse { connectors: Some(page), next_token: next })
    }

    pub(crate) fn delete_connector(&self, ctx: &RequestContext, input: types::DeleteConnectorRequest) -> Result<(), ServiceError> {
        let arn = &input.connector_arn;
        self.authorize_on(ctx, "DeleteConnector", arn)?;
        let mut st = self.lock();
        self.owned_connector(&st, ctx, arn)?;
        st.connectors.remove(arn);
        st.challenges.retain(|_, c| &c.connector_arn != arn);
        Ok(())
    }

    pub(crate) fn create_challenge(
        &self,
        ctx: &RequestContext,
        input: types::CreateChallengeRequest,
    ) -> Result<types::CreateChallengeResponse, ServiceError> {
        let arn = &input.connector_arn;
        let tags = input.tags.clone().unwrap_or_default();
        let mut cond = tag_context(&tags, "aws:RequestTag/");
        cond.extend(tag_context(&self.resource_tags(arn), "aws:ResourceTag/"));
        ctx.authorize("pca-connector-scep:CreateChallenge", arn, cond)?;
        check_tags(&tags)?;
        let mut st = self.lock();
        let token = input.client_token.as_ref().map(|t| format!("{}/{t}", ctx.caller.account_id));
        if let Some(existing) = token.as_ref().and_then(|t| st.client_tokens.get(t)).and_then(|a| st.challenges.get(a)) {
            return Ok(types::CreateChallengeResponse { challenge: Some(wire_challenge(existing)) });
        }
        let connector = self.owned_connector(&st, ctx, arn)?;
        if connector.ty != "GENERAL_PURPOSE" {
            return Err(validation(
                "INVALID_CONNECTOR_TYPE",
                "You can create challenge passwords only for general-purpose connectors.",
            ));
        }
        if connector.status != "ACTIVE" {
            return Err(validation("INVALID_STATE", "The connector is not active."));
        }
        if st.challenges.values().filter(|c| &c.connector_arn == arn).count() >= MAX_CHALLENGES {
            return Err(errors::service_quota_exceeded(format!(
                "A connector can have at most {MAX_CHALLENGES} challenge passwords."
            ))
            .with_field("ResourceType", ErrorValue::String("Challenge".into()))
            .with_field("ServiceCode", ErrorValue::String("pca-connector-scep".into()))
            .with_field("QuotaCode", ErrorValue::String("L-6E2F3B52".into())));
        }
        let now = ctx.received_at;
        let challenge = Challenge {
            arn: format!("{arn}/challenge/{}", uuid::Uuid::new_v4()),
            connector_arn: arn.clone(),
            owner: ctx.caller.account_id.clone(),
            password: password(),
            created: Some(now),
            updated: Some(now),
            tags,
        };
        let out = wire_challenge(&challenge);
        if let Some(t) = token {
            st.client_tokens.insert(t, challenge.arn.clone());
        }
        st.challenges.insert(challenge.arn.clone(), challenge);
        Ok(types::CreateChallengeResponse { challenge: Some(out) })
    }

    pub(crate) fn get_challenge_metadata(
        &self,
        ctx: &RequestContext,
        input: types::GetChallengeMetadataRequest,
    ) -> Result<types::GetChallengeMetadataResponse, ServiceError> {
        self.authorize_on(ctx, "GetChallengeMetadata", &input.challenge_arn)?;
        let st = self.lock();
        let c = self.owned_challenge(&st, ctx, &input.challenge_arn)?;
        Ok(types::GetChallengeMetadataResponse {
            challenge_metadata: Some(types::ChallengeMetadata {
                arn: Some(c.arn.clone()),
                connector_arn: Some(c.connector_arn.clone()),
                created_at: c.created,
                updated_at: c.updated,
            }),
        })
    }

    pub(crate) fn get_challenge_password(
        &self,
        ctx: &RequestContext,
        input: types::GetChallengePasswordRequest,
    ) -> Result<types::GetChallengePasswordResponse, ServiceError> {
        self.authorize_on(ctx, "GetChallengePassword", &input.challenge_arn)?;
        let st = self.lock();
        let c = self.owned_challenge(&st, ctx, &input.challenge_arn)?;
        Ok(types::GetChallengePasswordResponse { password: Some(c.password.clone()) })
    }

    pub(crate) fn list_challenge_metadata(
        &self,
        ctx: &RequestContext,
        input: types::ListChallengeMetadataRequest,
    ) -> Result<types::ListChallengeMetadataResponse, ServiceError> {
        self.authorize_on(ctx, "ListChallengeMetadata", &input.connector_arn)?;
        let st = self.lock();
        self.owned_connector(&st, ctx, &input.connector_arn)?;
        let all: Vec<_> = st
            .challenges
            .values()
            .filter(|c| c.connector_arn == input.connector_arn)
            .map(|c| types::ChallengeMetadataSummary {
                arn: Some(c.arn.clone()),
                connector_arn: Some(c.connector_arn.clone()),
                created_at: c.created,
                updated_at: c.updated,
            })
            .collect();
        let (page, next) = paginate(all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListChallengeMetadataResponse { challenges: Some(page), next_token: next })
    }

    pub(crate) fn delete_challenge(&self, ctx: &RequestContext, input: types::DeleteChallengeRequest) -> Result<(), ServiceError> {
        self.authorize_on(ctx, "DeleteChallenge", &input.challenge_arn)?;
        let mut st = self.lock();
        self.owned_challenge(&st, ctx, &input.challenge_arn)?;
        st.challenges.remove(&input.challenge_arn);
        Ok(())
    }

    fn tags_mut<'s>(&self, st: &'s mut State, ctx: &RequestContext, arn: &str) -> Result<&'s mut BTreeMap<String, String>, ServiceError> {
        if self.owned_connector(st, ctx, arn).is_ok() {
            return Ok(&mut st.connectors.get_mut(arn).expect("checked").tags);
        }
        if self.owned_challenge(st, ctx, arn).is_ok() {
            return Ok(&mut st.challenges.get_mut(arn).expect("checked").tags);
        }
        let ty = if arn.contains("/challenge/") { "Challenge" } else { "Connector" };
        Err(not_found(arn, ty))
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.authorize_on(ctx, "ListTagsForResource", &input.resource_arn)?;
        let mut st = self.lock();
        let tags = self.tags_mut(&mut st, ctx, &input.resource_arn)?.clone();
        Ok(types::ListTagsForResourceResponse { tags: Some(tags) })
    }

    pub(crate) fn tag_resource(&self, ctx: &RequestContext, input: types::TagResourceRequest) -> Result<(), ServiceError> {
        let mut cond = tag_context(&input.tags, "aws:RequestTag/");
        cond.extend(tag_context(&self.resource_tags(&input.resource_arn), "aws:ResourceTag/"));
        ctx.authorize("pca-connector-scep:TagResource", &input.resource_arn, cond)?;
        let mut st = self.lock();
        let tags = self.tags_mut(&mut st, ctx, &input.resource_arn)?;
        let mut merged = tags.clone();
        merged.extend(input.tags);
        check_tags(&merged)?;
        *tags = merged;
        Ok(())
    }

    pub(crate) fn untag_resource(&self, ctx: &RequestContext, input: types::UntagResourceRequest) -> Result<(), ServiceError> {
        let mut cond = tag_context(&self.resource_tags(&input.resource_arn), "aws:ResourceTag/");
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        ctx.authorize("pca-connector-scep:UntagResource", &input.resource_arn, cond)?;
        let mut st = self.lock();
        let tags = self.tags_mut(&mut st, ctx, &input.resource_arn)?;
        for k in &input.tag_keys {
            tags.remove(k);
        }
        Ok(())
    }
}

fn wire_challenge(c: &Challenge) -> types::Challenge {
    types::Challenge {
        arn: Some(c.arn.clone()),
        connector_arn: Some(c.connector_arn.clone()),
        created_at: c.created,
        updated_at: c.updated,
        password: Some(c.password.clone()),
    }
}

/// A random challenge password.
fn password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..32).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect()
}

/// Key usages for the RA certificate: it signs replies and receives
/// encrypted requests.
fn ra_passthrough() -> mws_acmpca::ApiPassthrough {
    let mut ext = mws_acmpca::ApiPassthrough::default();
    ext.extensions = Some(mws_acmpca::generated::types::Extensions {
        key_usage: Some(mws_acmpca::generated::types::KeyUsage {
            digital_signature: true,
            key_encipherment: true,
            ..Default::default()
        }),
        ..Default::default()
    });
    ext
}
