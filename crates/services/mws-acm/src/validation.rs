//! Domain validation and the certificate lifecycle that follows the clock:
//! DNS records checked against Route 53, issuance once every domain is
//! validated, timeouts, expiry and managed renewal.

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;
use sha2::{Digest, Sha256};

use crate::generated::types;
use crate::state::{Certificate, Renewal, State};
use crate::Acm;
use crate::{events, pki};

/// Public certificates are valid for 198 days, private ones for 395.
pub const PUBLIC_VALIDITY_DAYS: i64 = 198;
pub const PRIVATE_VALIDITY_DAYS: i64 = 395;
/// Validation gives up after 72 hours.
const VALIDATION_TIMEOUT_HOURS: i64 = 72;
/// Managed renewal starts 60 days before expiry.
const RENEWAL_WINDOW_DAYS: i64 = 60;

fn hash_hex(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    hex::encode(h.finalize())
}

/// The domain a validation record is for: a wildcard shares its base
/// domain's record.
pub fn base_domain(domain: &str) -> &str {
    domain.strip_prefix("*.").unwrap_or(domain)
}

/// The CNAME record that proves control of `domain`, the same for every
/// certificate of the account (as in ACM).
pub fn dns_record(account: &str, domain: &str) -> types::ResourceRecord {
    let base = base_domain(domain).to_ascii_lowercase();
    let name = &hash_hex(&["name", account, &base])[..32];
    let value = &hash_hex(&["value", account, &base])[..32];
    let label: String = hash_hex(&["label", account, &base])[..10]
        .bytes()
        .map(|b| (b'a' + (if b.is_ascii_digit() { b - b'0' } else { b - b'a' + 10 }) % 26) as char)
        .collect();
    types::ResourceRecord {
        name: format!("_{name}.{base}."),
        r#type: "CNAME".into(),
        value: format!("_{value}.{label}.acm-validations.aws."),
    }
}

/// Where validation emails for `validation_domain` go.
pub fn validation_emails(validation_domain: &str) -> Vec<String> {
    let d = base_domain(validation_domain);
    ["admin", "administrator", "hostmaster", "postmaster", "webmaster"].iter().map(|u| format!("{u}@{d}")).collect()
}

/// Why a public certificate cannot be issued for `domain`, if it cannot.
pub fn public_domain_problem(domain: &str) -> Option<&'static str> {
    let d = base_domain(domain).to_ascii_lowercase();
    let tld = d.rsplit('.').next().unwrap_or_default();
    if ["local", "localhost", "internal", "test", "invalid", "example", "lan", "home", "corp", "intranet"]
        .contains(&tld)
    {
        return Some("INVALID_PUBLIC_DOMAIN");
    }
    if d == "amazonaws.com" || d.ends_with(".amazonaws.com") || d.ends_with(".aws") && d.contains("acm-validations") {
        return Some("DOMAIN_NOT_ALLOWED");
    }
    None
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.').eq_ignore_ascii_case(b.trim_end_matches('.'))
}

impl Acm {
    /// Whether `record` exists in a public hosted zone.
    pub(crate) fn record_published(&self, record: &types::ResourceRecord) -> bool {
        let Some(r53) = &self.route53 else { return false };
        r53.public_record_values(&record.name, &record.r#type).iter().any(|v| same_name(v, &record.value))
    }

    /// Bring the account's certificates and ACME domain validations up to
    /// date with Route 53 and the clock. Runs before every call.
    pub(crate) fn refresh(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let account = ctx.caller.account_id.clone();
        // DNS records to look up, collected without holding the lock while
        // Route 53 is asked.
        let wanted: Vec<types::ResourceRecord> = {
            let st = self.lock();
            let mut out = Vec::new();
            for c in st.certificates.values().filter(|c| c.account == account) {
                let checking = c.status == "PENDING_VALIDATION" || c.method_update.is_some() || c.status == "ISSUED";
                if !checking {
                    continue;
                }
                for v in &c.validations {
                    if v.method.as_deref() == Some("DNS") || v.requested_method.as_deref() == Some("DNS") {
                        out.push(dns_record(&c.account, &v.domain));
                    }
                }
            }
            for dv in st.domain_validations.values().filter(|d| d.status == "VALIDATING") {
                if st.endpoints.get(&dv.endpoint_arn).is_some_and(|e| e.account == account) {
                    out.push(types::ResourceRecord {
                        name: dv.record_name.clone(),
                        r#type: "CNAME".into(),
                        value: dv.record_value.clone(),
                    });
                }
            }
            out
        };
        let published: Vec<(String, bool)> =
            wanted.iter().map(|r| (r.name.to_ascii_lowercase(), self.record_published(r))).collect();
        let is_published = |name: &str| published.iter().any(|(n, ok)| *ok && same_name(n, name));

        let mut followups = Followups::default();
        {
            let mut st = self.lock();
            let arns: Vec<String> =
                st.certificates.values().filter(|c| c.account == account).map(|c| c.arn.clone()).collect();
            for arn in arns {
                let mut cert = st.certificates.get(&arn).cloned().expect("listed");
                self.advance(&mut st, &mut cert, now, &is_published, &mut followups);
                st.certificates.insert(arn, cert);
            }
            for dv in st.domain_validations.values_mut() {
                if dv.status == "VALIDATING" && is_published(&dv.record_name) {
                    dv.status = "VALID".into();
                    dv.updated_at = now;
                }
            }
        }
        for arn in followups.private_renewals {
            self.renew_private(ctx, &arn, false);
        }
        for arn in followups.renewal_emails {
            self.send_validation_emails(ctx, &arn, None);
        }
    }

    fn advance(
        &self,
        st: &mut State,
        c: &mut Certificate,
        now: DateTime<Utc>,
        is_published: &dyn Fn(&str) -> bool,
        followups: &mut Followups,
    ) {
        let account = c.account.clone();
        // DNS validation.
        if c.status == "PENDING_VALIDATION" {
            for v in c.validations.iter_mut().filter(|v| v.status == "PENDING_VALIDATION") {
                if v.method.as_deref() == Some("DNS") && is_published(&dns_record(&account, &v.domain).name) {
                    v.status = "SUCCESS".into();
                }
            }
            if c.validations.iter().all(|v| v.status == "SUCCESS") {
                match issue_public(st, c, now) {
                    Ok(()) => st.pending_events.extend(events::available(c, "ISSUANCE", now)),
                    Err(e) => {
                        tracing::warn!(arn = %c.arn, error = %e.message, "issuing certificate failed");
                        c.status = "FAILED".into();
                        c.failure_reason = Some("OTHER".into());
                    }
                }
            } else if c.created_at.is_some_and(|t| now - t > Duration::hours(VALIDATION_TIMEOUT_HOURS)) {
                c.status = "VALIDATION_TIMED_OUT".into();
                for v in &mut c.validations {
                    if v.status == "PENDING_VALIDATION" {
                        v.status = "FAILED".into();
                    }
                }
            }
        }
        // A validation method migration completes once the new method
        // validates every domain.
        if let Some(update) = c.method_update.as_mut().filter(|u| u.status == "PENDING_DOMAIN_VALIDATION") {
            for v in c.validations.iter_mut() {
                if v.requested_method.as_deref() == Some("DNS")
                    && v.requested_status.as_deref() == Some("PENDING_VALIDATION")
                    && is_published(&dns_record(&account, &v.domain).name)
                {
                    v.requested_status = Some("SUCCESS".into());
                }
            }
            if c.validations.iter().all(|v| v.requested_status.as_deref() == Some("SUCCESS")) {
                for v in c.validations.iter_mut() {
                    v.method = v.requested_method.take();
                    v.status = v.requested_status.take().unwrap_or_else(|| "SUCCESS".into());
                }
                update.status = "SUCCESS".into();
                update.updated_at = now;
            }
        }
        // Expiry.
        let not_after = c.cert_pem.as_deref().and_then(pki::inspect_pem).map(|i| i.not_after);
        if c.status == "ISSUED" {
            if let Some(end) = not_after {
                if end <= now {
                    c.status = "EXPIRED".into();
                    st.pending_events.extend(events::expired(c, now));
                    return;
                }
                if end - now <= Duration::days(RENEWAL_WINDOW_DAYS) {
                    match (c.ty.as_str(), c.origin.as_str()) {
                        ("AMAZON_ISSUED", "AWS_MANAGED") => {
                            if renew_public(st, c, now, is_published) {
                                followups.renewal_emails.push(c.arn.clone());
                            }
                        }
                        ("PRIVATE", _) if c.renewal.as_ref().is_none_or(|r| r.status != "FAILED") => {
                            followups.private_renewals.push(c.arn.clone())
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Renew a private certificate through Private CA as ACM's service
    /// principal. `RenewCertificate` passes `explicit`.
    pub(crate) fn renew_private(&self, ctx: &RequestContext, arn: &str, explicit: bool) {
        let Some(pca) = &self.pca else { return };
        let Some(cert) = self.lock().certificates.get(arn).cloned() else { return };
        let (Some(ca_arn), Some(key_der)) = (cert.ca_arn.clone(), cert.key_der.clone()) else { return };
        let now = ctx.received_at;
        let csr =
            pki::load_key(&key_der, &cert.key_algorithm).and_then(|k| pki::csr_pem(&k, &cert.domain_name, &cert.sans));
        let not_after = private_not_after(pca, &ca_arn, now);
        let result = csr.and_then(|csr| {
            pca.issue_for_acm(ctx, &ca_arn, &csr, not_after, mws_acmpca::AcmIssuer::ServicePrincipal, &cert.account)
        });
        let mut st = self.lock();
        let Some(c) = st.certificates.get_mut(arn) else { return };
        match result {
            Ok(issued) => {
                c.cert_pem = Some(issued.certificate_pem);
                c.chain_pem = Some(issued.chain_pem);
                c.pca_certificate_arn = Some(issued.certificate_arn);
                c.issued_at = Some(now);
                c.status = "ISSUED".into();
                c.renewal = Some(Renewal { status: "SUCCESS".into(), reason: None, updated_at: now });
                let e = events::available(c, "RENEWAL", now);
                st.pending_events.extend(e);
            }
            Err(e) => {
                tracing::debug!(%arn, explicit, error = %e.message, "private certificate renewal failed");
                c.renewal = Some(Renewal { status: "FAILED".into(), reason: Some(pca_failure(&e)), updated_at: now });
                let e = events::renewal_action_required(c, now);
                st.pending_events.extend(e);
            }
        }
    }
}

/// The end of a private certificate's validity: 395 days, or the CA's own
/// end if that comes first.
pub fn private_not_after(pca: &mws_acmpca::PrivateCa, ca_arn: &str, now: DateTime<Utc>) -> DateTime<Utc> {
    let wanted = now + Duration::days(PRIVATE_VALIDITY_DAYS);
    match pca.ca_for_acm(ca_arn).and_then(|c| c.not_after) {
        Some(ca_end) if ca_end < wanted => ca_end,
        _ => wanted,
    }
}

/// The `FailureReason` for an error from Private CA.
pub fn pca_failure(e: &mws_core::ServiceError) -> String {
    match e.code.as_ref() {
        "AccessDenied" | "AccessDeniedException" => "PCA_ACCESS_DENIED",
        "ResourceNotFoundException" => "PCA_RESOURCE_NOT_FOUND",
        "InvalidStateException" => "PCA_INVALID_STATE",
        "InvalidArnException" => "PCA_INVALID_ARN",
        "InvalidArgsException" | "ValidationException" | "MalformedCSRException" => "PCA_INVALID_ARGS",
        "LimitExceededException" => "PCA_LIMIT_EXCEEDED",
        _ => "PCA_REQUEST_FAILED",
    }
    .to_string()
}

/// The issuing CA for `key_algorithm`, made on first use.
pub fn issuer(
    st: &mut State,
    key_algorithm: &str,
    now: DateTime<Utc>,
) -> Result<pki::IssuingCa, mws_core::ServiceError> {
    let kind = pki::intermediate_kind(key_algorithm);
    if let Some(ca) = st.issuers.get(kind) {
        return Ok(ca.clone());
    }
    if st.root.is_none() {
        st.root = Some(pki::new_root(now)?);
    }
    let ca = pki::new_intermediate(st.root.as_ref().expect("just set"), kind, now)?;
    st.issuers.insert(kind.to_string(), ca.clone());
    Ok(ca)
}

/// Generate a key pair and sign an Amazon-issued certificate for `c`.
pub fn issue_public(st: &mut State, c: &mut Certificate, now: DateTime<Utc>) -> Result<(), mws_core::ServiceError> {
    let ca = issuer(st, &c.key_algorithm, now)?;
    let key_der = pki::generate_key(&c.key_algorithm)?;
    let key = pki::load_key(&key_der, &c.key_algorithm)?;
    let pem = pki::issue_leaf(
        &ca,
        &pki::LeafRequest {
            common_name: &c.domain_name,
            names: &c.sans,
            spki_der: &pki::spki_of(&key),
            not_before: now,
            not_after: now + Duration::days(PUBLIC_VALIDITY_DAYS),
        },
    )?;
    c.cert_pem = Some(pem);
    c.chain_pem = Some(format!("{}{}", ca.cert_pem, ca.root_pem));
    c.key_der = Some(key_der);
    c.status = "ISSUED".into();
    c.issued_at = Some(now);
    Ok(())
}

/// Managed renewal of an Amazon-issued certificate. Each domain must
/// validate again: DNS domains as soon as their record is (still) in
/// Route 53, email domains once the owner approves the renewal email.
/// Returns whether renewal emails should go out.
fn renew_public(st: &mut State, c: &mut Certificate, now: DateTime<Utc>, is_published: &dyn Fn(&str) -> bool) -> bool {
    let new_cycle = c.renewal.as_ref().is_none_or(|r| r.status == "SUCCESS");
    let account = c.account.clone();
    for v in c.validations.iter_mut() {
        if new_cycle {
            v.renewal_status = Some("PENDING_VALIDATION".into());
        }
        if v.renewal_status.as_deref() == Some("PENDING_VALIDATION")
            && v.method.as_deref() == Some("DNS")
            && is_published(&dns_record(&account, &v.domain).name)
        {
            v.renewal_status = Some("SUCCESS".into());
        }
    }
    if c.validations.iter().all(|v| v.renewal_status.as_deref() == Some("SUCCESS")) {
        complete_public_renewal(st, c, now);
        return false;
    }
    if !new_cycle {
        return false;
    }
    let email = c.validations.iter().any(|v| v.method.as_deref() == Some("EMAIL"));
    let status = if email { "PENDING_VALIDATION" } else { "PENDING_AUTO_RENEWAL" };
    c.renewal = Some(Renewal { status: status.into(), reason: None, updated_at: now });
    st.pending_events.extend(events::renewal_action_required(c, now));
    email
}

/// Issue the renewed certificate once every domain validated again.
pub fn complete_public_renewal(st: &mut State, c: &mut Certificate, now: DateTime<Utc>) {
    match issue_public(st, c, now) {
        Ok(()) => {
            for v in c.validations.iter_mut() {
                v.renewal_status = None;
            }
            c.renewal = Some(Renewal { status: "SUCCESS".into(), reason: None, updated_at: now });
            st.pending_events.extend(events::available(c, "RENEWAL", now));
        }
        Err(e) => tracing::warn!(arn = %c.arn, error = %e.message, "renewing certificate failed"),
    }
}

/// Work `refresh` does after releasing the state lock.
#[derive(Default)]
pub(crate) struct Followups {
    pub private_renewals: Vec<String>,
    pub renewal_emails: Vec<String>,
}
