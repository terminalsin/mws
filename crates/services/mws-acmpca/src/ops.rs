//! ACM PCA operations.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Months, NaiveDateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind};
use rand::Rng;

use crate::generated::{errors, types};
use crate::state::{Ca, IssuedCert, State};
use crate::{extensions, revocation, x509, PrivateCa};

const MAX_TAGS: usize = 50;
/// The longest validity a short-lived-certificate CA issues.
const SHORT_LIVED_MAX_DAYS: i64 = 7;
const DEFAULT_TEMPLATE: &str = "arn:aws:acm-pca:::template/EndEntityCertificate/V1";

fn not_found(arn: &str) -> ServiceError {
    errors::resource_not_found(format!("Could not find certificate authority {arn}."))
}

pub(crate) fn invalid_state(message: impl Into<String>) -> ServiceError {
    errors::invalid_state(message)
}

fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationException", 400, message)
}

pub(crate) fn check_arn(ctx: &RequestContext, arn: &str) -> Result<(), ServiceError> {
    let prefix = format!("arn:{}:acm-pca:", ctx.partition);
    if !arn.starts_with(&prefix) || !arn.contains(":certificate-authority/") {
        return Err(errors::invalid_arn(format!("The ARN {arn} is not valid.")));
    }
    // Each region's endpoint only knows its own CAs.
    if revocation::region(arn) != ctx.region {
        return Err(not_found(arn));
    }
    Ok(())
}

impl State {
    pub(crate) fn ca(&self, arn: &str) -> Result<&Ca, ServiceError> {
        self.cas.get(arn).ok_or_else(|| not_found(arn))
    }

    pub(crate) fn ca_mut(&mut self, arn: &str) -> Result<&mut Ca, ServiceError> {
        self.cas.get_mut(arn).ok_or_else(|| not_found(arn))
    }
}

impl Ca {
    fn set_status(&mut self, status: &str, now: DateTime<Utc>) {
        self.status = status.to_string();
        self.last_state_change_at = now;
    }

    fn wire(&self) -> types::CertificateAuthority {
        types::CertificateAuthority {
            arn: Some(self.arn.clone()),
            owner_account: Some(self.owner.clone()),
            created_at: Some(self.created_at),
            last_state_change_at: Some(self.last_state_change_at),
            r#type: Some(self.ty.clone()),
            serial: self.serial.clone(),
            status: Some(self.status.clone()),
            not_before: self.not_before,
            not_after: self.not_after,
            failure_reason: None,
            certificate_authority_configuration: Some(self.config.clone()),
            // AWS shows a disabled CRL and OCSP when they are not configured.
            revocation_configuration: {
                let rc = self.revocation.clone().unwrap_or_default();
                Some(types::RevocationConfiguration {
                    crl_configuration: Some(rc.crl_configuration.unwrap_or_default()),
                    ocsp_configuration: Some(rc.ocsp_configuration.unwrap_or_default()),
                })
            },
            restorable_until: self.restorable_until,
            key_storage_security_standard: self.key_storage.clone(),
            usage_mode: self.usage_mode.clone(),
        }
    }

    fn require_usable(&self) -> Result<(), ServiceError> {
        match self.status.as_str() {
            "ACTIVE" => Ok(()),
            s => Err(invalid_state(format!("The certificate authority {} is not in a valid state ({s}).", self.arn))),
        }
    }

    /// The CA's own certificate plus its chain, for `CertificateChain`.
    pub(crate) fn full_chain_pem(&self) -> Option<String> {
        self.full_chain()
    }

    fn full_chain(&self) -> Option<String> {
        let cert = self.cert_pem.clone()?;
        Some(match &self.chain_pem {
            Some(chain) => format!("{cert}\n{chain}"),
            None => cert,
        })
    }
}

fn validity_time(v: &types::Validity, now: DateTime<Utc>) -> Result<DateTime<Utc>, ServiceError> {
    let bad = || validation(format!("The validity value {} of type {} is not valid.", v.value, v.r#type));
    if v.value <= 0 && v.r#type != "ABSOLUTE" {
        return Err(bad());
    }
    Ok(match v.r#type.as_str() {
        "DAYS" => now + Duration::days(v.value),
        "MONTHS" => now.checked_add_months(Months::new(v.value as u32)).ok_or_else(bad)?,
        "YEARS" => now.checked_add_months(Months::new((v.value * 12) as u32)).ok_or_else(bad)?,
        "ABSOLUTE" => DateTime::from_timestamp(v.value, 0).ok_or_else(bad)?,
        "END_DATE" => {
            NaiveDateTime::parse_from_str(&format!("{:014}", v.value), "%Y%m%d%H%M%S").map_err(|_| bad())?.and_utc()
        }
        _ => return Err(bad()),
    })
}

fn serial() -> [u8; 16] {
    let mut s: [u8; 16] = rand::thread_rng().gen();
    s[0] &= 0x7f;
    if s[0] == 0 {
        s[0] = 1;
    }
    s
}

fn validate_tags(tags: &[types::Tag]) -> Result<(), ServiceError> {
    for t in tags {
        if t.key.starts_with("aws:") {
            return Err(errors::invalid_tag(format!("The tag key {} uses the reserved prefix aws:.", t.key)));
        }
    }
    Ok(())
}

impl PrivateCa {
    /// Authorize `acm-pca:{action}` on a CA, evaluating its resource policy.
    /// Reads the policy under the lock, then releases it before asking the
    /// authorizer.
    pub(crate) fn authorize(&self, ctx: &RequestContext, action: &str, arn: &str) -> Result<(), ServiceError> {
        self.authorize_with(ctx, action, arn, ConditionContext::new())
    }

    pub(crate) fn authorize_with(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let (policy, tags) = match self.lock().cas.get(arn) {
            Some(c) => (c.effective_policy(), c.tags.clone()),
            None => (None, Default::default()),
        };
        // The CA's own tags, for ABAC policies (`aws:ResourceTag/<key>`).
        let mut context: ConditionContext =
            tags.into_iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v])).collect();
        context.extend(extra);
        ctx.authorize_with_resource_policy(&format!("acm-pca:{action}"), arn, policy.as_deref(), context)
    }

    pub(crate) fn create_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::CreateCertificateAuthorityRequest,
    ) -> Result<types::CreateCertificateAuthorityResponse, ServiceError> {
        let mut cond = ConditionContext::new();
        for t in input.tags.iter().flatten() {
            cond.insert(format!("aws:RequestTag/{}", t.key), vec![t.value.clone().unwrap_or_default()]);
        }
        if let Some(tags) = &input.tags {
            cond.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
        }
        ctx.authorize("acm-pca:CreateCertificateAuthority", "*", cond)?;
        let token_key = input.idempotency_token.as_ref().map(|t| format!("{}/{t}", ctx.caller.account_id));
        if let Some(token) = &token_key {
            if let Some(arn) = self.lock().create_tokens.get(token) {
                return Ok(types::CreateCertificateAuthorityResponse { certificate_authority_arn: Some(arn.clone()) });
            }
        }
        let tags = input.tags.unwrap_or_default();
        validate_tags(&tags)?;
        if tags.len() > MAX_TAGS {
            return Err(errors::too_many_tags(format!("A certificate authority can have at most {MAX_TAGS} tags.")));
        }
        if let Some(rc) = &input.revocation_configuration {
            revocation::validate(rc)?;
        }
        let config = input.certificate_authority_configuration;
        if config.subject == types::ASN1Subject::default() {
            return Err(errors::invalid_args("The subject must contain at least one attribute."));
        }
        let key_der = x509::generate_key(&config.key_algorithm, &config.signing_algorithm)?;
        let alg = x509::signature_algorithm(&config.key_algorithm, &config.signing_algorithm)?;
        let key = x509::key_for(&key_der, alg)?;
        let csr_extensions = match &config.csr_extensions {
            Some(c) => extensions::csr_extensions(c)?,
            None => Vec::new(),
        };
        let csr_pem = x509::csr_pem(&key, &x509::subject_dn(&config.subject)?, &csr_extensions)?;

        let id = uuid::Uuid::new_v4().to_string();
        let arn = format!(
            "arn:{}:acm-pca:{}:{}:certificate-authority/{id}",
            ctx.partition, ctx.region, ctx.caller.account_id
        );
        self.check_crl_bucket(&arn, input.revocation_configuration.as_ref())?;
        let now = ctx.received_at;
        let ca = Ca {
            arn: arn.clone(),
            owner: ctx.caller.account_id.clone(),
            created_at: now,
            last_state_change_at: now,
            ty: input.certificate_authority_type,
            status: "PENDING_CERTIFICATE".into(),
            config,
            revocation: input.revocation_configuration,
            key_storage: Some(
                input.key_storage_security_standard.unwrap_or_else(|| "FIPS_140_2_LEVEL_3_OR_HIGHER".into()),
            ),
            usage_mode: Some(input.usage_mode.unwrap_or_else(|| "GENERAL_PURPOSE".into())),
            key_der,
            csr_pem,
            cert_pem: None,
            chain_pem: None,
            serial: None,
            not_before: None,
            not_after: None,
            restorable_until: None,
            status_before_delete: None,
            tags: tags.into_iter().map(|t| (t.key, t.value.unwrap_or_default())).collect(),
            policy: None,
            permissions: Vec::new(),
            certs: BTreeMap::new(),
            issue_tokens: Default::default(),
            crl: None,
            crl_number: 0,
            audit_reports: BTreeMap::new(),
            ram_policy: None,
        };
        let mut st = self.lock();
        if let Some(token) = token_key {
            st.create_tokens.insert(token, arn.clone());
        }
        st.cas.insert(arn.clone(), ca);
        Ok(types::CreateCertificateAuthorityResponse { certificate_authority_arn: Some(arn) })
    }

    pub(crate) fn describe_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCertificateAuthorityRequest,
    ) -> Result<types::DescribeCertificateAuthorityResponse, ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "DescribeCertificateAuthority", arn)?;
        let st = self.lock();
        Ok(types::DescribeCertificateAuthorityResponse { certificate_authority: Some(st.ca(arn)?.wire()) })
    }

    pub(crate) fn list_certificate_authorities(
        &self,
        ctx: &RequestContext,
        input: types::ListCertificateAuthoritiesRequest,
    ) -> Result<types::ListCertificateAuthoritiesResponse, ServiceError> {
        ctx.authorize("acm-pca:ListCertificateAuthorities", "*", ConditionContext::new())?;
        let account = ctx.caller.account_id.as_str();
        let in_region: Vec<types::CertificateAuthority> =
            self.lock().cas.values().filter(|ca| revocation::region(&ca.arn) == ctx.region).map(Ca::wire).collect();
        let all: Vec<types::CertificateAuthority> = if input.resource_owner.as_deref() == Some("OTHER_ACCOUNTS") {
            // CAs other accounts share with this one: through AWS RAM or a
            // policy set with PutPolicy, either of which lets the caller
            // describe the CA.
            in_region
                .into_iter()
                .filter(|ca| ca.owner_account.as_deref() != Some(account))
                .filter(|ca| {
                    let arn = ca.arn.as_deref().unwrap_or_default();
                    let has_policy = self.lock().cas.get(arn).is_some_and(|c| c.effective_policy().is_some());
                    has_policy && self.authorize(ctx, "DescribeCertificateAuthority", arn).is_ok()
                })
                .collect()
        } else {
            in_region.into_iter().filter(|ca| ca.owner_account.as_deref() == Some(account)).collect()
        };
        let (page, next) = paginate(all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListCertificateAuthoritiesResponse { next_token: next, certificate_authorities: Some(page) })
    }

    pub(crate) fn get_certificate_authority_csr(
        &self,
        ctx: &RequestContext,
        input: types::GetCertificateAuthorityCsrRequest,
    ) -> Result<types::GetCertificateAuthorityCsrResponse, ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "GetCertificateAuthorityCsr", arn)?;
        let st = self.lock();
        let ca = st.ca(arn)?;
        if ca.status == "DELETED" {
            return Err(invalid_state(format!("The certificate authority {arn} is not in a valid state (DELETED).")));
        }
        Ok(types::GetCertificateAuthorityCsrResponse { csr: Some(ca.csr_pem.clone()) })
    }

    pub(crate) fn get_certificate_authority_certificate(
        &self,
        ctx: &RequestContext,
        input: types::GetCertificateAuthorityCertificateRequest,
    ) -> Result<types::GetCertificateAuthorityCertificateResponse, ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "GetCertificateAuthorityCertificate", arn)?;
        let st = self.lock();
        let ca = st.ca(arn)?;
        if ca.cert_pem.is_none() {
            return Err(invalid_state(format!(
                "The certificate authority {arn} is not in a valid state ({}).",
                ca.status
            )));
        }
        Ok(types::GetCertificateAuthorityCertificateResponse {
            certificate: ca.cert_pem.clone(),
            certificate_chain: ca.chain_pem.clone(),
        })
    }

    pub(crate) fn import_certificate_authority_certificate(
        &self,
        ctx: &RequestContext,
        input: types::ImportCertificateAuthorityCertificateRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "ImportCertificateAuthorityCertificate", arn)?;
        let info = x509::cert_info(&input.certificate)?;
        let chain = input.certificate_chain.as_deref().map(x509::split_chain).transpose()?;
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        if !matches!(ca.status.as_str(), "PENDING_CERTIFICATE" | "ACTIVE" | "DISABLED" | "EXPIRED") {
            return Err(invalid_state(format!(
                "The certificate authority {arn} is not in a valid state ({}).",
                ca.status
            )));
        }
        let alg = x509::signature_algorithm(&ca.config.key_algorithm, &ca.config.signing_algorithm)?;
        let key = x509::key_for(&ca.key_der, alg)?;
        if info.spki_der != x509::public_key_der(&key) {
            return Err(errors::certificate_mismatch(
                "The certificate does not match the certificate authority's private key.",
            ));
        }
        if !info.is_ca {
            return Err(errors::invalid_request("The certificate is not a CA certificate."));
        }
        match (ca.ty.as_str(), &chain) {
            ("ROOT", Some(_)) => {
                return Err(errors::invalid_request("A root CA certificate must not have a certificate chain."))
            }
            ("ROOT", None) if !info.self_signed => {
                return Err(errors::invalid_request("A root CA certificate must be self-signed."))
            }
            ("SUBORDINATE", None) => {
                return Err(errors::invalid_request("A subordinate CA certificate requires a certificate chain."))
            }
            ("SUBORDINATE", Some(chain)) if !x509::verify_signed_by(&info.pem, &chain[0]) => {
                return Err(errors::invalid_request(
                    "The certificate is not signed by the first certificate in the chain.",
                ));
            }
            _ => {}
        }
        ca.cert_pem = Some(info.pem);
        ca.chain_pem = chain.map(|c| c.join("\n"));
        ca.serial = Some(info.serial);
        ca.not_before = Some(info.not_before);
        ca.not_after = Some(info.not_after);
        if ca.status != "DISABLED" {
            ca.set_status("ACTIVE", ctx.received_at);
        }
        revocation::refresh_crl(ca, ctx.received_at)?;
        self.publish_crl(ca);
        Ok(())
    }

    pub(crate) fn issue_certificate(
        &self,
        ctx: &RequestContext,
        input: types::IssueCertificateRequest,
    ) -> Result<types::IssueCertificateResponse, ServiceError> {
        let arn = input.certificate_authority_arn.clone();
        check_arn(ctx, &arn)?;
        let template_arn = input.template_arn.clone().unwrap_or_else(|| DEFAULT_TEMPLATE.to_string());
        let mut cond = ConditionContext::new();
        cond.insert("acm-pca:TemplateArn".into(), vec![template_arn.clone()]);
        self.authorize_with(ctx, "IssueCertificate", &arn, cond)?;
        self.issue_authorized(input, ctx.received_at)
    }

    /// `IssueCertificate` once the caller has been authorized.
    pub(crate) fn issue_authorized(
        &self,
        input: types::IssueCertificateRequest,
        now: DateTime<Utc>,
    ) -> Result<types::IssueCertificateResponse, ServiceError> {
        let arn = input.certificate_authority_arn.clone();
        let template_arn = input.template_arn.clone().unwrap_or_else(|| DEFAULT_TEMPLATE.to_string());

        if let Some(token) = &input.idempotency_token {
            if let Some(existing) = self.lock().ca(&arn)?.issue_tokens.get(token) {
                return Ok(types::IssueCertificateResponse { certificate_arn: Some(existing.clone()) });
            }
        }
        let template = x509::template(&template_arn)?;
        let csr = x509::parse_csr(&input.csr)?;
        if let Some(subject) = input.api_passthrough.as_ref().and_then(|a| a.subject.as_ref()) {
            extensions::subject_attributes(subject)?;
        }
        let not_after = validity_time(&input.validity, now)?;
        let not_before = match &input.validity_not_before {
            Some(v) => validity_time(v, now)?,
            None => now - Duration::minutes(60),
        };
        if not_after <= now {
            return Err(validation("The certificate validity end must be in the future."));
        }
        let serial = serial();
        let mut st = self.lock();
        let ca = st.ca_mut(&arn)?;
        let alg = x509::signature_algorithm(&ca.config.key_algorithm, &input.signing_algorithm)?;
        let key = x509::key_for(&ca.key_der, alg)?;
        let is_root_cert = template.root;
        let (crl_url, ocsp_url) =
            if is_root_cert { (None, None) } else { (revocation::crl_url(ca), revocation::ocsp_url(ca)) };
        let api = input.api_passthrough.as_ref();
        let issue = x509::Issue { csr: &csr, template, api, not_before, not_after, serial, crl_url, ocsp_url };
        let pem = if is_root_cert {
            if ca.ty != "ROOT" {
                return Err(errors::invalid_args("Only a root certificate authority can issue a root CA certificate."));
            }
            if !matches!(ca.status.as_str(), "PENDING_CERTIFICATE" | "ACTIVE") {
                return Err(invalid_state(format!(
                    "The certificate authority {arn} is not in a valid state ({}).",
                    ca.status
                )));
            }
            issue.self_signed(&key)?
        } else {
            ca.require_usable()?;
            if ca.usage_mode.as_deref() == Some("SHORT_LIVED_CERTIFICATE")
                && not_after - not_before.max(now) > Duration::days(SHORT_LIVED_MAX_DAYS)
            {
                return Err(validation(format!(
                    "A certificate authority in SHORT_LIVED_CERTIFICATE mode issues certificates valid for at most {SHORT_LIVED_MAX_DAYS} days."
                )));
            }
            if ca.not_after.is_some_and(|ca_end| not_after > ca_end) {
                return Err(validation(
                    "The certificate validity specified exceeds the certificate authority validity.",
                ));
            }
            issue.signed_by(ca.cert_pem.as_deref().unwrap_or_default(), &key)?
        };
        let id = serial.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let cert_arn = format!("{arn}/certificate/{id}");
        let subject = x509::subject_string(&pem);
        ca.certs.insert(
            id,
            IssuedCert {
                pem,
                revoked: None,
                issued_at: now,
                not_before,
                not_after,
                subject,
                template_arn: template_arn.clone(),
            },
        );
        if let Some(token) = input.idempotency_token {
            ca.issue_tokens.insert(token, cert_arn.clone());
        }
        Ok(types::IssueCertificateResponse { certificate_arn: Some(cert_arn) })
    }

    pub(crate) fn get_certificate(
        &self,
        ctx: &RequestContext,
        input: types::GetCertificateRequest,
    ) -> Result<types::GetCertificateResponse, ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "GetCertificate", arn)?;
        let st = self.lock();
        let ca = st.ca(arn)?;
        let missing = || errors::resource_not_found(format!("Could not find certificate {}.", input.certificate_arn));
        let id = input.certificate_arn.strip_prefix(&format!("{arn}/certificate/")).ok_or_else(missing)?;
        let cert = ca.certs.get(id).ok_or_else(missing)?;
        // A root CA's self-signed certificate has no chain until it is imported.
        let chain =
            if ca.cert_pem.as_deref() == Some(cert.pem.as_str()) { ca.chain_pem.clone() } else { ca.full_chain() };
        Ok(types::GetCertificateResponse { certificate: Some(cert.pem.clone()), certificate_chain: chain })
    }

    pub(crate) fn revoke_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RevokeCertificateRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "RevokeCertificate", arn)?;
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        if !matches!(ca.status.as_str(), "ACTIVE" | "DISABLED") {
            return Err(invalid_state(format!(
                "The certificate authority {arn} is not in a valid state ({}).",
                ca.status
            )));
        }
        // A serial number is a number: leading zeros and colons don't matter.
        let wanted = input.certificate_serial.replace(':', "").to_ascii_lowercase();
        let wanted = wanted.trim_start_matches('0');
        let id = ca.certs.keys().find(|k| k.trim_start_matches('0') == wanted).cloned().unwrap_or_default();
        let cert = ca.certs.get_mut(&id).ok_or_else(|| {
            errors::resource_not_found(format!("Could not find certificate with serial {}.", input.certificate_serial))
        })?;
        if cert.revoked.is_some() {
            return Err(errors::request_already_processed("This certificate is already revoked."));
        }
        cert.revoked = Some((input.revocation_reason, ctx.received_at));
        revocation::refresh_crl(ca, ctx.received_at)?;
        self.publish_crl(ca);
        Ok(())
    }

    pub(crate) fn update_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCertificateAuthorityRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "UpdateCertificateAuthority", arn)?;
        if let Some(rc) = &input.revocation_configuration {
            revocation::validate(rc)?;
        }
        self.check_crl_bucket(arn, input.revocation_configuration.as_ref())?;
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        if let Some(status) = &input.status {
            if !matches!(status.as_str(), "ACTIVE" | "DISABLED") {
                return Err(errors::invalid_args(format!("The status {status} cannot be set directly.")));
            }
            if !matches!(ca.status.as_str(), "ACTIVE" | "DISABLED") {
                return Err(invalid_state(format!(
                    "The certificate authority {arn} is not in a valid state ({}).",
                    ca.status
                )));
            }
            ca.set_status(status, ctx.received_at);
        }
        if input.revocation_configuration.is_some() {
            ca.revocation = input.revocation_configuration;
            revocation::refresh_crl(ca, ctx.received_at)?;
            self.publish_crl(ca);
        }
        Ok(())
    }

    pub(crate) fn delete_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCertificateAuthorityRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "DeleteCertificateAuthority", arn)?;
        let days = input.permanent_deletion_time_in_days.unwrap_or(30);
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        match ca.status.as_str() {
            "ACTIVE" => Err(invalid_state(format!(
                "The certificate authority {arn} is in the ACTIVE state. Disable it before deleting it."
            ))),
            "DELETED" => Err(invalid_state(format!("The certificate authority {arn} is already deleted."))),
            _ => {
                // Every other state, PENDING_CERTIFICATE included, keeps a
                // restoration period; RestoreCertificateAuthority puts the CA
                // back in the state it was deleted from.
                ca.status_before_delete = Some(ca.status.clone());
                ca.restorable_until = Some(ctx.received_at + Duration::days(days as i64));
                ca.set_status("DELETED", ctx.received_at);
                Ok(())
            }
        }
    }

    pub(crate) fn restore_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::RestoreCertificateAuthorityRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "RestoreCertificateAuthority", arn)?;
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        if ca.status != "DELETED" || ca.restorable_until.is_some_and(|t| t < ctx.received_at) {
            return Err(invalid_state(format!(
                "The certificate authority {arn} is not in a valid state ({}).",
                ca.status
            )));
        }
        ca.restorable_until = None;
        let fallback = if ca.cert_pem.is_some() { "DISABLED" } else { "PENDING_CERTIFICATE" };
        let back = ca.status_before_delete.take().unwrap_or_else(|| fallback.to_string());
        ca.set_status(&back, ctx.received_at);
        Ok(())
    }

    pub(crate) fn tag_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::TagCertificateAuthorityRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        let mut cond = ConditionContext::new();
        for t in &input.tags {
            cond.insert(format!("aws:RequestTag/{}", t.key), vec![t.value.clone().unwrap_or_default()]);
        }
        cond.insert("aws:TagKeys".into(), input.tags.iter().map(|t| t.key.clone()).collect());
        self.authorize_with(ctx, "TagCertificateAuthority", arn, cond)?;
        validate_tags(&input.tags)?;
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        let mut next = ca.tags.clone();
        for t in input.tags {
            next.insert(t.key, t.value.unwrap_or_default());
        }
        if next.len() > MAX_TAGS {
            return Err(errors::too_many_tags(format!("A certificate authority can have at most {MAX_TAGS} tags.")));
        }
        ca.tags = next;
        Ok(())
    }

    pub(crate) fn untag_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::UntagCertificateAuthorityRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        let mut cond = ConditionContext::new();
        cond.insert("aws:TagKeys".into(), input.tags.iter().map(|t| t.key.clone()).collect());
        self.authorize_with(ctx, "UntagCertificateAuthority", arn, cond)?;
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        for t in input.tags {
            let matches = match (&t.value, ca.tags.get(&t.key)) {
                (Some(v), Some(cur)) => v == cur,
                (None, Some(_)) => true,
                _ => false,
            };
            if matches {
                ca.tags.remove(&t.key);
            }
        }
        Ok(())
    }

    pub(crate) fn list_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsRequest,
    ) -> Result<types::ListTagsResponse, ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "ListTags", arn)?;
        let st = self.lock();
        let tags: Vec<types::Tag> =
            st.ca(arn)?.tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: Some(v.clone()) }).collect();
        let (page, next) = paginate(tags, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListTagsResponse { next_token: next, tags: Some(page) })
    }

    pub(crate) fn create_permission(
        &self,
        ctx: &RequestContext,
        input: types::CreatePermissionRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "CreatePermission", arn)?;
        if input.principal != "acm.amazonaws.com" {
            return Err(errors::invalid_request("The principal must be acm.amazonaws.com."));
        }
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        if ca.permissions.iter().any(|p| p.principal.as_deref() == Some(input.principal.as_str())) {
            return Err(errors::permission_already_exists(
                "The designated permission has already been given to the user.",
            ));
        }
        ca.permissions.push(types::Permission {
            certificate_authority_arn: Some(arn.clone()),
            created_at: Some(ctx.received_at),
            principal: Some(input.principal),
            source_account: Some(input.source_account.unwrap_or_else(|| ctx.caller.account_id.clone())),
            actions: Some(input.actions),
            policy: None,
        });
        Ok(())
    }

    pub(crate) fn delete_permission(
        &self,
        ctx: &RequestContext,
        input: types::DeletePermissionRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "DeletePermission", arn)?;
        let mut st = self.lock();
        let ca = st.ca_mut(arn)?;
        let before = ca.permissions.len();
        ca.permissions.retain(|p| p.principal.as_deref() != Some(input.principal.as_str()));
        if ca.permissions.len() == before {
            return Err(errors::resource_not_found(format!(
                "Could not find a permission for principal {} on {arn}.",
                input.principal
            )));
        }
        Ok(())
    }

    pub(crate) fn list_permissions(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionsRequest,
    ) -> Result<types::ListPermissionsResponse, ServiceError> {
        let arn = &input.certificate_authority_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "ListPermissions", arn)?;
        let st = self.lock();
        let (page, next) = paginate(st.ca(arn)?.permissions.clone(), input.max_results, input.next_token.as_deref())?;
        Ok(types::ListPermissionsResponse { next_token: next, permissions: Some(page) })
    }

    pub(crate) fn put_policy(&self, ctx: &RequestContext, input: types::PutPolicyRequest) -> Result<(), ServiceError> {
        let arn = &input.resource_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "PutPolicy", arn)?;
        Policy::parse(&input.policy, PolicyKind::Resource).map_err(|e| errors::invalid_policy(e.to_string()))?;
        let owner = {
            let mut st = self.lock();
            let ca = st.ca_mut(arn)?;
            ca.policy = Some(input.policy.clone());
            ca.owner.clone()
        };
        self.notify_policy(arn, &owner, Some(&input.policy), ctx.received_at);
        Ok(())
    }

    pub(crate) fn get_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetPolicyRequest,
    ) -> Result<types::GetPolicyResponse, ServiceError> {
        let arn = &input.resource_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "GetPolicy", arn)?;
        let st = self.lock();
        let policy = st.ca(arn)?.effective_policy();
        if policy.is_none() {
            return Err(errors::resource_not_found(format!("Could not find a policy for {arn}.")));
        }
        Ok(types::GetPolicyResponse { policy })
    }

    pub(crate) fn delete_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeletePolicyRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.resource_arn;
        check_arn(ctx, arn)?;
        self.authorize(ctx, "DeletePolicy", arn)?;
        let owner = {
            let mut st = self.lock();
            let ca = st.ca_mut(arn)?;
            if ca.policy.take().is_none() {
                return Err(errors::resource_not_found(format!("Could not find a policy for {arn}.")));
            }
            ca.owner.clone()
        };
        self.notify_policy(arn, &owner, None, ctx.received_at);
        Ok(())
    }
}

/// Index-based pagination with an opaque token.
pub(crate) fn paginate<T>(
    items: Vec<T>,
    max: Option<i32>,
    token: Option<&str>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| errors::invalid_next_token("The token specified in the NextToken argument is not valid."))?,
        None => 0,
    };
    let max = max.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(100);
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + max < total).then(|| format!("mws-{}", start + max));
    Ok((page, next))
}
