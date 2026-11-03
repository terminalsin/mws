//! Certificate operations.

use chrono::{Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::common::{self, check_certificate_arn, is_local, Tags};
use crate::generated::{errors, types};
use crate::pki::{self, CertInfo};
use crate::state::{Certificate, DomainValidation, MethodUpdate};
use crate::validation::{self, dns_record, validation_emails};
use crate::Acm;

/// Domain names per certificate (ACM's default quota).
const MAX_DOMAINS: usize = 10;
const CT_OPT_OUT_GONE: &str =
    "Certificate transparency logging opt-out is no longer available. All public certificates are recorded in a certificate transparency log.";
const REQUEST_KEY_ALGORITHMS: &[&str] = &["RSA_2048", "EC_prime256v1", "EC_secp384r1"];

fn not_found(arn: &str) -> ServiceError {
    errors::resource_not_found(format!("Could not find certificate {arn}."))
}

/// `RSA_2048` as `DescribeCertificate` shows it (`RSA-2048`).
fn describe_key_algorithm(k: &str) -> String {
    k.replacen('_', "-", 1)
}

fn renewal_eligibility(c: &Certificate) -> &'static str {
    let eligible = match c.ty.as_str() {
        "IMPORTED" => false,
        _ => c.status == "ISSUED" && c.origin != "ACME",
    };
    if eligible {
        "ELIGIBLE"
    } else {
        "INELIGIBLE"
    }
}

fn dv_wire(c: &Certificate, v: &DomainValidation) -> types::DomainValidation {
    let mut out = types::DomainValidation { domain_name: v.domain.clone(), ..Default::default() };
    if c.ty != "AMAZON_ISSUED" || c.origin == "ACME" {
        return out;
    }
    out.validation_domain = Some(v.validation_domain.clone());
    out.validation_status = Some(v.status.clone());
    out.validation_method = v.method.clone();
    match v.method.as_deref() {
        Some("EMAIL") => out.validation_emails = Some(validation_emails(&v.validation_domain)),
        Some("DNS") => out.resource_record = Some(dns_record(&c.account, &v.domain)),
        _ => {}
    }
    out
}

fn key_usage_wire(info: &CertInfo) -> Vec<types::KeyUsage> {
    info.key_usages.iter().map(|k| types::KeyUsage { name: Some(k.clone()) }).collect()
}

fn eku_wire(info: &CertInfo) -> Vec<types::ExtendedKeyUsage> {
    info.extended_key_usages
        .iter()
        .map(|(n, o)| types::ExtendedKeyUsage { name: Some(n.clone()), oid: Some(o.clone()) })
        .collect()
}

pub(crate) fn validation_method(c: &Certificate) -> Option<String> {
    c.validations.iter().find_map(|v| v.method.clone())
}

fn options_wire(c: &Certificate) -> types::CertificateOptions {
    types::CertificateOptions {
        certificate_transparency_logging_preference: Some(c.ct_logging.clone()),
        export: Some(c.export_option.clone()),
        validation_method: None,
    }
}

pub(crate) fn detail(c: &Certificate) -> types::CertificateDetail {
    let info = c.cert_pem.as_deref().and_then(pki::inspect_pem);
    let mut d = types::CertificateDetail {
        certificate_arn: Some(c.arn.clone()),
        domain_name: Some(c.domain_name.clone()),
        subject_alternative_names: Some(c.sans.clone()),
        managed_by: c.managed_by.clone(),
        created_at: c.created_at,
        issued_at: c.issued_at,
        imported_at: c.imported_at,
        status: Some(c.status.clone()),
        revoked_at: c.revoked_at,
        revocation_reason: c.revocation_reason.clone(),
        key_algorithm: Some(describe_key_algorithm(&c.key_algorithm)),
        in_use_by: Some(Vec::new()),
        failure_reason: c.failure_reason.clone(),
        r#type: Some(c.ty.clone()),
        certificate_authority_arn: c.ca_arn.clone(),
        renewal_eligibility: Some(renewal_eligibility(c).into()),
        options: Some(options_wire(c)),
        certificate_key_pair_origin: Some(c.origin.clone()),
        acme_endpoint_arn: c.acme_endpoint_arn.clone(),
        acme_account_id: c.acme_account_id.clone(),
        ..Default::default()
    };
    if c.ty != "IMPORTED" {
        d.domain_validation_options = Some(c.validations.iter().map(|v| dv_wire(c, v)).collect());
    }
    if let Some(info) = &info {
        d.serial = Some(info.serial.clone());
        d.subject = Some(info.subject.clone());
        d.issuer = Some(info.issuer.clone());
        d.not_before = Some(info.not_before);
        d.not_after = Some(info.not_after);
        d.signature_algorithm = Some(info.signature_algorithm.clone());
        d.key_usages = Some(key_usage_wire(info));
        d.extended_key_usages = Some(eku_wire(info));
    }
    if let Some(r) = &c.renewal {
        d.renewal_summary = Some(types::RenewalSummary {
            renewal_status: r.status.clone(),
            domain_validation_options: c.validations.iter().map(|v| dv_wire(c, v)).collect(),
            renewal_status_reason: r.reason.clone(),
            updated_at: r.updated_at,
        });
    }
    if let Some(u) = &c.method_update {
        d.update_summary = Some(types::UpdateSummary {
            status: Some(u.status.clone()),
            r#type: Some("DOMAIN_VALIDATION_METHOD".into()),
            domain_validation_method_update_summary: Some(types::DomainValidationMethodUpdateSummary {
                from: Some(u.from.clone()),
                to: Some(u.to.clone()),
            }),
            requested_at: Some(u.requested_at),
            updated_at: Some(u.updated_at),
        });
    }
    d
}

fn summary(c: &Certificate, info: Option<&CertInfo>) -> types::CertificateSummary {
    let names: Vec<String> = c.sans.iter().take(100).cloned().collect();
    types::CertificateSummary {
        certificate_arn: Some(c.arn.clone()),
        domain_name: Some(c.domain_name.clone()),
        subject_alternative_name_summaries: Some(names),
        has_additional_subject_alternative_names: Some(c.sans.len() > 100),
        status: Some(c.status.clone()),
        r#type: Some(c.ty.clone()),
        key_algorithm: Some(c.key_algorithm.clone()),
        key_usages: info.map(|i| i.key_usages.clone()),
        extended_key_usages: info.map(|i| i.extended_key_usages.iter().map(|(n, _)| n.clone()).collect()),
        export_option: Some(c.export_option.clone()),
        in_use: Some(false),
        exported: Some(c.exported),
        renewal_eligibility: Some(renewal_eligibility(c).into()),
        not_before: info.map(|i| i.not_before),
        not_after: info.map(|i| i.not_after),
        created_at: c.created_at,
        issued_at: c.issued_at,
        imported_at: c.imported_at,
        revoked_at: c.revoked_at,
        managed_by: c.managed_by.clone(),
        certificate_key_pair_origin: Some(c.origin.clone()),
    }
}

/// Whether `domain` is `validation_domain` or below it.
fn within(domain: &str, validation_domain: &str) -> bool {
    let d = validation::base_domain(domain).to_ascii_lowercase();
    let v = validation_domain.to_ascii_lowercase();
    d == v || d.ends_with(&format!(".{v}"))
}

impl Acm {
    /// Authorize `acm:{action}` on a certificate, with its tags for ABAC.
    pub(crate) fn authorize_cert(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let tags = self.lock().certificates.get(arn).map(|c| c.tags.clone()).unwrap_or_default();
        let mut cond = common::resource_tag_context(&tags);
        cond.extend(extra);
        ctx.authorize(&format!("acm:{action}"), arn, cond)
    }

    /// The certificate, if it is the caller's.
    pub(crate) fn certificate(&self, ctx: &RequestContext, arn: &str) -> Result<Certificate, ServiceError> {
        if !is_local(ctx, arn) {
            return Err(not_found(arn));
        }
        self.lock().certificates.get(arn).cloned().ok_or_else(|| not_found(arn))
    }

    /// Check the ARN, authorize, bring state up to date and fetch.
    fn begin(&self, ctx: &RequestContext, action: &str, arn: &str) -> Result<Certificate, ServiceError> {
        check_certificate_arn(ctx, arn)?;
        self.authorize_cert(ctx, action, arn, ConditionContext::new())?;
        self.refresh(ctx);
        self.certificate(ctx, arn)
    }

    fn update_cert(&self, arn: &str, f: impl FnOnce(&mut Certificate)) {
        if let Some(c) = self.lock().certificates.get_mut(arn) {
            f(c);
        }
    }

    pub(crate) async fn request_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RequestCertificateRequest,
    ) -> Result<types::RequestCertificateResponse, ServiceError> {
        let domain = input.domain_name.to_ascii_lowercase();
        let mut names = vec![domain.clone()];
        for n in input.subject_alternative_names.iter().flatten() {
            let n = n.to_ascii_lowercase();
            if !names.contains(&n) {
                names.push(n);
            }
        }
        let private = input.certificate_authority_arn.is_some();
        let method =
            if private { None } else { Some(input.validation_method.clone().unwrap_or_else(|| "EMAIL".into())) };
        let key_algorithm = input.key_algorithm.clone().unwrap_or_else(|| "RSA_2048".into());
        let options = input.options.clone().unwrap_or_default();
        let ct = options.certificate_transparency_logging_preference.clone().unwrap_or_else(|| "ENABLED".into());
        let export = options.export.clone().unwrap_or_else(|| "DISABLED".into());

        let tags = input.tags.clone().unwrap_or_default();
        let mut cond = common::request_tag_context(&tags);
        cond.insert("acm:DomainNames".into(), names.clone());
        cond.insert("acm:KeyAlgorithm".into(), vec![key_algorithm.clone()]);
        cond.insert("acm:CertificateTransparencyLogging".into(), vec![ct.clone()]);
        cond.insert("acm:Export".into(), vec![export.clone()]);
        if let Some(m) = &method {
            cond.insert("acm:ValidationMethod".into(), vec![m.clone()]);
        }
        if let Some(ca) = &input.certificate_authority_arn {
            cond.insert("acm:CertificateAuthority".into(), vec![ca.clone()]);
        }
        ctx.authorize("acm:RequestCertificate", "*", cond)?;
        self.refresh(ctx);

        let now = ctx.received_at;
        let token_key =
            input.idempotency_token.as_ref().map(|t| format!("{}|{}|{t}", ctx.caller.account_id, ctx.region));
        if let Some(key) = &token_key {
            let mut st = self.lock();
            st.request_tokens.retain(|_, (_, at)| now - *at < Duration::hours(1));
            if let Some((arn, _)) = st.request_tokens.get(key) {
                return Ok(types::RequestCertificateResponse { certificate_arn: Some(arn.clone()) });
            }
        }
        if names.len() > MAX_DOMAINS {
            return Err(errors::limit_exceeded(format!(
                "Cannot request a certificate with more than {MAX_DOMAINS} domain names."
            )));
        }
        if !REQUEST_KEY_ALGORITHMS.contains(&key_algorithm.as_str()) {
            return Err(errors::invalid_parameter(format!(
                "Key algorithm {key_algorithm} is not supported for certificate requests. Supported: {}.",
                REQUEST_KEY_ALGORITHMS.join(", ")
            )));
        }
        common::validate_tags(&tags)?;
        if tags.len() > common::MAX_TAGS {
            return Err(errors::too_many_tags(format!("A certificate can have at most {} tags.", common::MAX_TAGS)));
        }
        if !private && ct == "DISABLED" {
            return Err(errors::validation(CT_OPT_OUT_GONE));
        }
        if private && export == "ENABLED" {
            return Err(errors::validation(
                "The Export option applies only to public certificates. Private certificates can always be exported.",
            ));
        }
        if method.as_deref() == Some("HTTP") && input.managed_by.as_deref() != Some("CLOUDFRONT") {
            return Err(errors::validation(
                "HTTP validation is only available for certificates managed by CloudFront.",
            ));
        }
        let dvo = input.domain_validation_options.clone().unwrap_or_default();
        for o in &dvo {
            let d = o.domain_name.to_ascii_lowercase();
            if !names.contains(&d) {
                return Err(errors::invalid_domain_validation_options(format!(
                    "DomainValidationOption {d} is not one of the certificate's domain names."
                )));
            }
            if !within(&d, &o.validation_domain) {
                return Err(errors::invalid_domain_validation_options(format!(
                    "The validation domain {} must be the domain {d} or a superdomain of it.",
                    o.validation_domain
                )));
            }
        }

        let id = uuid::Uuid::new_v4().to_string();
        let arn = format!("arn:{}:acm:{}:{}:certificate/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
        let validations = names
            .iter()
            .map(|n| {
                let validation_domain = dvo
                    .iter()
                    .find(|o| o.domain_name.eq_ignore_ascii_case(n))
                    .map(|o| o.validation_domain.to_ascii_lowercase())
                    .unwrap_or_else(|| validation::base_domain(n).to_string());
                DomainValidation {
                    domain: n.clone(),
                    validation_domain,
                    method: method.clone(),
                    status: if private { "SUCCESS".into() } else { "PENDING_VALIDATION".into() },
                    requested_method: None,
                    requested_status: None,
                }
            })
            .collect();
        let mut cert = Certificate {
            arn: arn.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            domain_name: domain.clone(),
            sans: names.clone(),
            ty: if private { "PRIVATE".into() } else { "AMAZON_ISSUED".into() },
            status: "PENDING_VALIDATION".into(),
            failure_reason: None,
            created_at: Some(now),
            issued_at: None,
            imported_at: None,
            revoked_at: None,
            revocation_reason: None,
            key_algorithm: key_algorithm.clone(),
            ca_arn: input.certificate_authority_arn.clone(),
            ct_logging: ct,
            export_option: if private { "DISABLED".into() } else { export },
            managed_by: input.managed_by.clone(),
            validations,
            method_update: None,
            cert_pem: None,
            chain_pem: None,
            key_der: None,
            imported_key: None,
            exported: false,
            renewal: None,
            tags: common::tags_from_wire(&tags),
            origin: "AWS_MANAGED".into(),
            acme_endpoint_arn: None,
            acme_account_id: None,
            pca_certificate_arn: None,
            emails_sent: 0,
        };
        if !private {
            if let Some(reason) = names.iter().find_map(|n| validation::public_domain_problem(n)) {
                cert.status = "FAILED".into();
                cert.failure_reason = Some(reason.into());
            }
        }
        if let Some(ca_arn) = &input.certificate_authority_arn {
            self.issue_private(ctx, &mut cert, ca_arn)?;
        }
        let emails = cert.validations.iter().any(|v| v.method.as_deref() == Some("EMAIL"));
        {
            let mut st = self.lock();
            if let Some(key) = token_key {
                st.request_tokens.insert(key, (arn.clone(), now));
            }
            st.certificates.insert(arn.clone(), cert);
        }
        if emails && !private {
            self.send_validation_emails(ctx, &arn, None);
        }
        Ok(types::RequestCertificateResponse { certificate_arn: Some(arn) })
    }

    /// Have Private CA issue `cert` with the requester's permissions.
    fn issue_private(&self, ctx: &RequestContext, cert: &mut Certificate, ca_arn: &str) -> Result<(), ServiceError> {
        let Some(pca) = &self.pca else {
            cert.status = "FAILED".into();
            cert.failure_reason = Some("PCA_RESOURCE_NOT_FOUND".into());
            return Ok(());
        };
        let pca_prefix = format!("arn:{}:acm-pca:", ctx.partition);
        if !ca_arn.starts_with(&pca_prefix) || !ca_arn.contains(":certificate-authority/") {
            return Err(errors::invalid_arn(format!("String '{ca_arn}' is not a valid ARN.")));
        }
        let key_der = pki::generate_key(&cert.key_algorithm)?;
        let key = pki::load_key(&key_der, &cert.key_algorithm)?;
        let csr = pki::csr_pem(&key, &cert.domain_name, &cert.sans)?;
        let now = ctx.received_at;
        let not_after = validation::private_not_after(pca, ca_arn, now);
        match pca.issue_for_acm(ctx, ca_arn, &csr, not_after, mws_acmpca::AcmIssuer::Caller, &cert.account) {
            Ok(issued) => {
                cert.cert_pem = Some(issued.certificate_pem);
                cert.chain_pem = Some(issued.chain_pem);
                cert.pca_certificate_arn = Some(issued.certificate_arn);
                cert.key_der = Some(key_der);
                cert.status = "ISSUED".into();
                cert.issued_at = Some(now);
            }
            Err(e) => {
                tracing::debug!(arn = %cert.arn, error = %e.message, "private certificate request failed");
                cert.key_der = Some(key_der);
                cert.status = "FAILED".into();
                cert.failure_reason = Some(validation::pca_failure(&e));
            }
        }
        Ok(())
    }

    pub(crate) fn describe_certificate(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCertificateRequest,
    ) -> Result<types::DescribeCertificateResponse, ServiceError> {
        let c = self.begin(ctx, "DescribeCertificate", &input.certificate_arn)?;
        Ok(types::DescribeCertificateResponse { certificate: Some(detail(&c)) })
    }

    pub(crate) fn get_certificate(
        &self,
        ctx: &RequestContext,
        input: types::GetCertificateRequest,
    ) -> Result<types::GetCertificateResponse, ServiceError> {
        let c = self.begin(ctx, "GetCertificate", &input.certificate_arn)?;
        match c.status.as_str() {
            "ISSUED" | "EXPIRED" | "REVOKED" | "INACTIVE" => {}
            "PENDING_VALIDATION" => {
                return Err(errors::request_in_progress(format!(
                    "Certificate '{}' in account '{}' with status PENDING_VALIDATION is still being issued.",
                    c.arn, c.account
                )))
            }
            s => return Err(errors::invalid_state(format!("Certificate {} is in state {s}.", c.arn))),
        }
        Ok(types::GetCertificateResponse { certificate: c.cert_pem.clone(), certificate_chain: c.chain_pem.clone() })
    }

    pub(crate) fn list_certificates(
        &self,
        ctx: &RequestContext,
        input: types::ListCertificatesRequest,
    ) -> Result<types::ListCertificatesResponse, ServiceError> {
        ctx.authorize("acm:ListCertificates", "*", ConditionContext::new())?;
        self.refresh(ctx);
        let includes = input.includes.clone().unwrap_or_default();
        let key_types = includes.key_types.clone().unwrap_or_else(|| vec!["RSA_2048".into()]);
        let origins = input.certificate_key_pair_origins.clone();
        let st = self.lock();
        let mut certs: Vec<(&Certificate, Option<CertInfo>)> = st
            .certificates
            .values()
            .filter(|c| c.account == ctx.caller.account_id && c.region == ctx.region)
            .map(|c| (c, c.cert_pem.as_deref().and_then(pki::inspect_pem)))
            .filter(|(c, _)| input.certificate_statuses.as_ref().is_none_or(|s| s.is_empty() || s.contains(&c.status)))
            .filter(|(c, _)| match &origins {
                Some(o) if !o.is_empty() => o.contains(&c.origin),
                _ => c.origin != "ACME",
            })
            .filter(|(c, _)| key_types.contains(&c.key_algorithm))
            .filter(|(c, _)| includes.export_option.as_ref().is_none_or(|e| *e == c.export_option))
            .filter(|(c, _)| includes.managed_by.as_ref().is_none_or(|m| Some(m) == c.managed_by.as_ref()))
            .filter(|(_, info)| {
                includes.key_usage.as_ref().is_none_or(|wanted| {
                    wanted.iter().all(|k| k == "ANY" || info.as_ref().is_some_and(|i| i.key_usages.contains(k)))
                })
            })
            .filter(|(_, info)| {
                includes.extended_key_usage.as_ref().is_none_or(|wanted| {
                    wanted.iter().all(|k| {
                        k == "ANY"
                            || (k == "NONE" && info.as_ref().is_none_or(|i| i.extended_key_usages.is_empty()))
                            || info.as_ref().is_some_and(|i| i.extended_key_usages.iter().any(|(n, _)| n == k))
                    })
                })
            })
            .collect();
        certs.sort_by_key(|(c, _)| c.created_at.or(c.imported_at));
        if input.sort_order.as_deref() == Some("DESCENDING") {
            certs.reverse();
        }
        let summaries: Vec<_> = certs.iter().map(|(c, i)| summary(c, i.as_ref())).collect();
        let (page, next) = common::paginate(summaries, input.max_items, 1000, input.next_token.as_deref())?;
        Ok(types::ListCertificatesResponse { next_token: next, certificate_summary_list: Some(page) })
    }

    pub(crate) fn delete_certificate(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCertificateRequest,
    ) -> Result<(), ServiceError> {
        let c = self.begin(ctx, "DeleteCertificate", &input.certificate_arn)?;
        self.lock().certificates.remove(&c.arn);
        Ok(())
    }

    pub(crate) fn import_certificate(
        &self,
        ctx: &RequestContext,
        input: types::ImportCertificateRequest,
    ) -> Result<types::ImportCertificateResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        let reimport = input.certificate_arn.clone();
        match &reimport {
            Some(arn) => {
                check_certificate_arn(ctx, arn)?;
                self.authorize_cert(ctx, "ImportCertificate", arn, common::request_tag_context(&tags))?;
            }
            None => ctx.authorize("acm:ImportCertificate", "*", common::request_tag_context(&tags))?,
        }
        self.refresh(ctx);
        let now = ctx.received_at;
        let certs = pki::pem_blocks(&input.certificate, "CERTIFICATE");
        let der = match certs.as_slice() {
            [one] => one.clone(),
            [] => return Err(errors::validation("Could not validate the certificate with the certificate chain.")),
            _ => {
                return Err(errors::validation(
                    "The certificate field contains more than one certificate. You can specify only one certificate in this field.",
                ))
            }
        };
        let info = pki::inspect_der(&der).ok_or_else(|| {
            errors::validation("Unable to parse certificate. Please ensure the certificate is in PEM format.")
        })?;
        if info.not_after <= now {
            return Err(errors::validation("The certificate has expired."));
        }
        if info.not_before > now {
            return Err(errors::validation("The certificate is not yet valid."));
        }
        match pki::check_key_matches(&input.private_key, &info.spki_der) {
            Ok(()) => {}
            Err(pki::KeyError::Encrypted) => {
                return Err(errors::validation("The private key is encrypted. Provide an unencrypted private key."))
            }
            Err(pki::KeyError::Unreadable) => {
                return Err(errors::validation("Unable to parse key; the body is not a valid PEM-encoded private key."))
            }
            Err(pki::KeyError::Mismatch) => {
                return Err(errors::validation("The private key is not supported or does not match the certificate."))
            }
        }
        let chain = match &input.certificate_chain {
            Some(chain) => {
                let blocks = pki::pem_blocks(chain, "CERTIFICATE");
                if blocks.is_empty() {
                    return Err(errors::validation("Could not validate the certificate with the certificate chain."));
                }
                Some(blocks.iter().map(|b| pki::to_pem("CERTIFICATE", b)).collect::<String>())
            }
            None => None,
        };
        let domain = info.subject_cn.clone().or_else(|| info.dns_names.first().cloned()).unwrap_or_default();
        let mut sans = Vec::new();
        if !domain.is_empty() {
            sans.push(domain.clone());
        }
        for n in &info.dns_names {
            if !sans.contains(n) {
                sans.push(n.clone());
            }
        }
        let cert_pem = pki::to_pem("CERTIFICATE", &der);
        if let Some(arn) = reimport {
            if !tags.is_empty() {
                return Err(errors::invalid_parameter("You cannot specify tags when reimporting a certificate."));
            }
            let existing = self.certificate(ctx, &arn)?;
            if existing.ty != "IMPORTED" {
                return Err(errors::validation(format!(
                    "Certificate {arn} was not imported, so it cannot be reimported."
                )));
            }
            self.update_cert(&arn, |c| {
                c.domain_name = domain;
                c.sans = sans;
                c.key_algorithm = info.key_algorithm.clone();
                c.cert_pem = Some(cert_pem);
                c.chain_pem = chain;
                c.imported_key = Some(input.private_key.clone());
                c.imported_at = Some(now);
                c.status = "ISSUED".into();
            });
            return Ok(types::ImportCertificateResponse { certificate_arn: Some(arn) });
        }
        common::validate_tags(&tags)?;
        if tags.len() > common::MAX_TAGS {
            return Err(errors::too_many_tags(format!("A certificate can have at most {} tags.", common::MAX_TAGS)));
        }
        let arn = format!(
            "arn:{}:acm:{}:{}:certificate/{}",
            ctx.partition,
            ctx.region,
            ctx.caller.account_id,
            uuid::Uuid::new_v4()
        );
        let cert = Certificate {
            arn: arn.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            domain_name: domain,
            sans,
            ty: "IMPORTED".into(),
            status: "ISSUED".into(),
            failure_reason: None,
            created_at: None,
            issued_at: None,
            imported_at: Some(now),
            revoked_at: None,
            revocation_reason: None,
            key_algorithm: info.key_algorithm.clone(),
            ca_arn: None,
            ct_logging: "ENABLED".into(),
            export_option: "DISABLED".into(),
            managed_by: None,
            validations: Vec::new(),
            method_update: None,
            cert_pem: Some(cert_pem),
            chain_pem: chain,
            key_der: None,
            imported_key: Some(input.private_key.clone()),
            exported: false,
            renewal: None,
            tags: common::tags_from_wire(&tags),
            origin: "CUSTOMER_PROVIDED".into(),
            acme_endpoint_arn: None,
            acme_account_id: None,
            pca_certificate_arn: None,
            emails_sent: 0,
        };
        self.lock().certificates.insert(arn.clone(), cert);
        Ok(types::ImportCertificateResponse { certificate_arn: Some(arn) })
    }

    pub(crate) fn export_certificate(
        &self,
        ctx: &RequestContext,
        input: types::ExportCertificateRequest,
    ) -> Result<types::ExportCertificateResponse, ServiceError> {
        let c = self.begin(ctx, "ExportCertificate", &input.certificate_arn)?;
        let exportable = c.ty == "PRIVATE" || (c.ty == "AMAZON_ISSUED" && c.export_option == "ENABLED");
        if !exportable || c.key_der.is_none() {
            return Err(errors::validation(format!(
                "Certificate ARN: {} is not a private certificate or an exportable public certificate.",
                c.arn
            )));
        }
        if c.status != "ISSUED" {
            return Err(errors::request_in_progress(format!(
                "Certificate '{}' with status {} cannot be exported.",
                c.arn, c.status
            )));
        }
        if input.passphrase.len() < 4 || input.passphrase.iter().any(|b| matches!(b, b'#' | b'$' | b'%')) {
            return Err(errors::invalid_parameter(
                "The passphrase must be at least 4 characters and must not contain #, $ or %.",
            ));
        }
        let private_key = pki::encrypt_pkcs8(c.key_der.as_deref().unwrap_or_default(), &input.passphrase)?;
        self.update_cert(&c.arn, |c| c.exported = true);
        Ok(types::ExportCertificateResponse {
            certificate: c.cert_pem.clone(),
            certificate_chain: c.chain_pem.clone(),
            private_key: Some(private_key),
        })
    }

    pub(crate) fn renew_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RenewCertificateRequest,
    ) -> Result<(), ServiceError> {
        let c = self.begin(ctx, "RenewCertificate", &input.certificate_arn)?;
        if c.ty != "PRIVATE" {
            return Err(errors::validation(format!(
                "Certificate {} is not a private certificate. Only private certificates can be renewed with RenewCertificate.",
                c.arn
            )));
        }
        if c.status != "ISSUED" {
            return Err(errors::invalid_state(format!(
                "Certificate {} must be in the ISSUED state to be renewed, but it is {}.",
                c.arn, c.status
            )));
        }
        self.renew_private(ctx, &c.arn, true);
        Ok(())
    }

    pub(crate) fn revoke_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RevokeCertificateRequest,
    ) -> Result<types::RevokeCertificateResponse, ServiceError> {
        let c = self.begin(ctx, "RevokeCertificate", &input.certificate_arn)?;
        if c.ty != "AMAZON_ISSUED" {
            return Err(errors::validation(format!(
                "Certificate {} is not a public certificate. Revoke private certificates through AWS Private CA.",
                c.arn
            )));
        }
        if c.status == "REVOKED" {
            return Err(errors::invalid_state(format!("Certificate {} has already been revoked.", c.arn)));
        }
        if !c.exported {
            return Err(errors::validation(format!(
                "Certificate {} has not been exported. Only exported certificates can be revoked.",
                c.arn
            )));
        }
        let now = ctx.received_at;
        self.update_cert(&c.arn, |c| {
            c.status = "REVOKED".into();
            c.revoked_at = Some(now);
            c.revocation_reason = Some(input.revocation_reason.clone());
        });
        Ok(types::RevokeCertificateResponse { certificate_arn: Some(c.arn) })
    }

    pub(crate) fn resend_validation_email(
        &self,
        ctx: &RequestContext,
        input: types::ResendValidationEmailRequest,
    ) -> Result<(), ServiceError> {
        let c = self.begin(ctx, "ResendValidationEmail", &input.certificate_arn)?;
        if c.status != "PENDING_VALIDATION" {
            return Err(errors::invalid_state(format!(
                "Certificate {} is not in the PENDING_VALIDATION state (it is {}).",
                c.arn, c.status
            )));
        }
        let domain = input.domain.to_ascii_lowercase();
        let Some(v) = c.validations.iter().find(|v| v.domain == domain) else {
            return Err(errors::invalid_domain_validation_options(format!(
                "The domain {domain} is not one of the certificate's domain names."
            )));
        };
        if v.method.as_deref() != Some("EMAIL") {
            return Err(errors::invalid_domain_validation_options(format!(
                "The domain {domain} is not validated by email."
            )));
        }
        let validation_domain = input.validation_domain.to_ascii_lowercase();
        if !within(&domain, &validation_domain) {
            return Err(errors::invalid_domain_validation_options(format!(
                "The validation domain {validation_domain} must be the domain {domain} or a superdomain of it."
            )));
        }
        self.update_cert(&c.arn, |c| {
            c.emails_sent += 1;
            if let Some(v) = c.validations.iter_mut().find(|v| v.domain == domain) {
                v.validation_domain = validation_domain.clone();
            }
        });
        self.send_validation_emails(ctx, &c.arn, Some(&domain));
        Ok(())
    }

    pub(crate) fn update_certificate_options(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCertificateOptionsRequest,
    ) -> Result<(), ServiceError> {
        let c = self.begin(ctx, "UpdateCertificateOptions", &input.certificate_arn)?;
        let o = input.options;
        if c.ty == "IMPORTED" {
            return Err(errors::invalid_state(format!(
                "Certificate {} is imported; its options cannot be updated.",
                c.arn
            )));
        }
        if let Some(export) = &o.export {
            if *export != c.export_option {
                return Err(errors::validation(
                    "The Export option is set when a certificate is requested and cannot be changed.",
                ));
            }
        }
        if c.ty == "AMAZON_ISSUED" && o.certificate_transparency_logging_preference.as_deref() == Some("DISABLED") {
            return Err(errors::validation(CT_OPT_OUT_GONE));
        }
        let now = ctx.received_at;
        let migrate = match o.validation_method.as_deref() {
            None => None,
            Some(m) if Some(m) == validation_method(&c).as_deref() => None,
            Some("DNS") if c.ty == "AMAZON_ISSUED" && validation_method(&c).as_deref() == Some("EMAIL") => Some("DNS"),
            Some(m) => {
                return Err(errors::validation(format!(
                "Certificate {} cannot change its validation method to {m}. Only email to DNS migration is supported.",
                c.arn
            )))
            }
        };
        if migrate.is_some() && c.method_update.as_ref().is_some_and(|u| u.status == "PENDING_DOMAIN_VALIDATION") {
            return Err(errors::conflict(format!("A validation method update for {} is already in progress.", c.arn)));
        }
        self.update_cert(&c.arn, |c| {
            if let Some(ct) = o.certificate_transparency_logging_preference {
                c.ct_logging = ct;
            }
            if let Some(to) = migrate {
                if c.status == "PENDING_VALIDATION" {
                    // Not issued yet: switch outright.
                    for v in &mut c.validations {
                        v.method = Some(to.into());
                    }
                } else {
                    for v in &mut c.validations {
                        v.requested_method = Some(to.into());
                        v.requested_status = Some("PENDING_VALIDATION".into());
                    }
                    c.method_update = Some(MethodUpdate {
                        from: "EMAIL".into(),
                        to: to.into(),
                        status: "PENDING_DOMAIN_VALIDATION".into(),
                        requested_at: now,
                        updated_at: now,
                    });
                }
            }
        });
        self.refresh(ctx);
        Ok(())
    }

    pub(crate) fn list_certificate_domain_validations(
        &self,
        ctx: &RequestContext,
        input: types::ListCertificateDomainValidationsRequest,
    ) -> Result<types::ListCertificateDomainValidationsResponse, ServiceError> {
        let c = self.begin(ctx, "ListCertificateDomainValidations", &input.certificate_arn)?;
        let config =
            |method: Option<&str>, status: Option<&str>, v: &DomainValidation| -> types::ValidationConfiguration {
                let challenge = match method {
                    Some("EMAIL") => {
                        Some(types::ValidationChallenge::EmailValidationChallenge(types::EmailValidationChallenge {
                            validation_emails: Some(validation_emails(&v.validation_domain)),
                            validation_domain: Some(v.validation_domain.clone()),
                        }))
                    }
                    Some("DNS") => {
                        Some(types::ValidationChallenge::DnsValidationChallenge(types::DnsValidationChallenge {
                            resource_record: Some(dns_record(&c.account, &v.domain)),
                        }))
                    }
                    _ => None,
                };
                types::ValidationConfiguration {
                    validation_method: method.map(str::to_string),
                    validation_challenge: challenge,
                    validation_status: status.map(str::to_string),
                }
            };
        let summaries: Vec<types::DomainValidationSummary> = c
            .validations
            .iter()
            .map(|v| types::DomainValidationSummary {
                domain_name: v.domain.clone(),
                active_validation_configuration: Some(config(v.method.as_deref(), Some(&v.status), v)),
                requested_validation_configuration: v
                    .requested_method
                    .as_deref()
                    .map(|m| config(Some(m), v.requested_status.as_deref(), v)),
            })
            .collect();
        let (page, next) = common::paginate(summaries, input.max_items, 1000, input.next_token.as_deref())?;
        Ok(types::ListCertificateDomainValidationsResponse {
            domain_validation_summary_list: Some(page),
            next_token: next,
        })
    }

    pub(crate) fn add_tags_to_certificate(
        &self,
        ctx: &RequestContext,
        input: types::AddTagsToCertificateRequest,
    ) -> Result<(), ServiceError> {
        check_certificate_arn(ctx, &input.certificate_arn)?;
        self.authorize_cert(
            ctx,
            "AddTagsToCertificate",
            &input.certificate_arn,
            common::request_tag_context(&input.tags),
        )?;
        let c = self.certificate(ctx, &input.certificate_arn)?;
        let mut tags: Tags = c.tags.clone();
        common::merge_tags(&mut tags, &input.tags)?;
        self.update_cert(&c.arn, |c| c.tags = tags);
        Ok(())
    }

    pub(crate) fn remove_tags_from_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTagsFromCertificateRequest,
    ) -> Result<(), ServiceError> {
        check_certificate_arn(ctx, &input.certificate_arn)?;
        let mut cond = ConditionContext::new();
        cond.insert("aws:TagKeys".into(), input.tags.iter().map(|t| t.key.clone()).collect());
        self.authorize_cert(ctx, "RemoveTagsFromCertificate", &input.certificate_arn, cond)?;
        let c = self.certificate(ctx, &input.certificate_arn)?;
        let mut tags = c.tags.clone();
        common::remove_tags(&mut tags, &input.tags)?;
        self.update_cert(&c.arn, |c| c.tags = tags);
        Ok(())
    }

    pub(crate) fn list_tags_for_certificate(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForCertificateRequest,
    ) -> Result<types::ListTagsForCertificateResponse, ServiceError> {
        check_certificate_arn(ctx, &input.certificate_arn)?;
        self.authorize_cert(ctx, "ListTagsForCertificate", &input.certificate_arn, ConditionContext::new())?;
        let c = self.certificate(ctx, &input.certificate_arn)?;
        Ok(types::ListTagsForCertificateResponse { tags: Some(common::tags_to_wire(&c.tags)) })
    }

    pub(crate) fn get_account_configuration(
        &self,
        ctx: &RequestContext,
    ) -> Result<types::GetAccountConfigurationResponse, ServiceError> {
        ctx.authorize("acm:GetAccountConfiguration", "*", ConditionContext::new())?;
        let config = self.lock().account_configs.get(&ctx.caller.account_id).cloned().unwrap_or_default();
        Ok(types::GetAccountConfigurationResponse {
            expiry_events: Some(types::ExpiryEventsConfiguration {
                days_before_expiry: Some(config.days_before_expiry),
            }),
        })
    }

    pub(crate) fn put_account_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountConfigurationRequest,
    ) -> Result<(), ServiceError> {
        ctx.authorize("acm:PutAccountConfiguration", "*", ConditionContext::new())?;
        let key = format!("{}|account-configuration|{}", ctx.caller.account_id, input.idempotency_token);
        let mut st = self.lock();
        if st.create_tokens.contains_key(&key) {
            return Ok(());
        }
        st.create_tokens.insert(key, String::new());
        let entry = st.account_configs.entry(ctx.caller.account_id.clone()).or_default();
        if let Some(days) = input.expiry_events.and_then(|e| e.days_before_expiry) {
            entry.days_before_expiry = days;
        }
        Ok(())
    }

    /// "Send" the validation emails: log the message and the approval link.
    fn send_validation_emails(&self, ctx: &RequestContext, arn: &str, only: Option<&str>) {
        let Ok(c) = self.certificate(ctx, arn) else { return };
        let base = ctx.endpoint.clone().unwrap_or_default();
        for v in c.validations.iter().filter(|v| v.method.as_deref() == Some("EMAIL")) {
            if only.is_some_and(|d| d != v.domain) {
                continue;
            }
            let link = crate::approval::approval_link(&base, arn, &v.domain);
            tracing::info!(
                certificate = %arn,
                domain = %v.domain,
                to = %validation_emails(&v.validation_domain).join(", "),
                "ACM validation email: approve the certificate request at {link}"
            );
        }
    }

    /// Approve the email validation of `domain` on `arn`.
    pub(crate) fn approve_email(&self, arn: &str, domain: &str, now: chrono::DateTime<Utc>) -> Result<(), String> {
        let mut st = self.lock();
        let Some(mut c) = st.certificates.get(arn).cloned() else { return Err("certificate not found".into()) };
        let Some(v) = c.validations.iter_mut().find(|v| v.domain == domain && v.method.as_deref() == Some("EMAIL"))
        else {
            return Err("domain not validated by email".into());
        };
        if c.status != "PENDING_VALIDATION" {
            return Err(format!("certificate is {}", c.status));
        }
        v.status = "SUCCESS".into();
        if c.validations.iter().all(|v| v.status == "SUCCESS") {
            validation::issue_public(&mut st, &mut c, now).map_err(|e| e.message.clone())?;
        }
        st.certificates.insert(arn.to_string(), c);
        Ok(())
    }
}
