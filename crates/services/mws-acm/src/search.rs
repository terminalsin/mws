//! `SearchCertificates`: filter statements over X.509 attributes and ACM
//! metadata.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::certs::validation_method;
use crate::common;
use crate::generated::{errors, types};
use crate::pki::{self, CertInfo, Dn, GeneralNameInfo};
use crate::state::Certificate;
use crate::Acm;

fn compare(value: &str, filter_value: &str, op: &str) -> bool {
    let (v, f) = (value.to_ascii_lowercase(), filter_value.to_ascii_lowercase());
    match op {
        "CONTAINS" => v.contains(&f),
        _ => v == f,
    }
}

fn in_range(t: Option<chrono::DateTime<chrono::Utc>>, r: &types::TimestampRange) -> bool {
    let Some(t) = t else { return false };
    r.start.is_none_or(|s| t >= s) && r.end.is_none_or(|e| t <= e)
}

fn renewal_status(c: &Certificate) -> Option<String> {
    c.renewal.as_ref().map(|r| r.status.clone())
}

fn matches_filter(c: &Certificate, info: Option<&CertInfo>, f: &types::CertificateFilter) -> bool {
    use types::{AcmCertificateMetadataFilter as M, X509AttributeFilter as X};
    match f {
        types::CertificateFilter::CertificateArn(arn) => c.arn == *arn,
        types::CertificateFilter::X509AttributeFilter(x) => {
            let Some(i) = info else { return false };
            match x {
                X::Subject(types::SubjectFilter::CommonName(cn)) => {
                    i.subject_cn.as_deref().is_some_and(|v| compare(v, &cn.value, &cn.comparison_operator))
                }
                X::SubjectAlternativeName(types::SubjectAlternativeNameFilter::DnsName(d)) => {
                    i.dns_names.iter().any(|n| compare(n, &d.value, &d.comparison_operator))
                }
                X::ExtendedKeyUsage(name) => i.extended_key_usages.iter().any(|(n, _)| n == name),
                X::KeyUsage(name) => i.key_usages.contains(name),
                X::KeyAlgorithm(k) => i.key_algorithm == *k,
                X::SerialNumber(s) => i.serial.eq_ignore_ascii_case(s),
                X::NotAfter(r) => in_range(Some(i.not_after), r),
                X::NotBefore(r) => in_range(Some(i.not_before), r),
            }
        }
        types::CertificateFilter::AcmCertificateMetadataFilter(m) => match m {
            M::Status(s) => c.status == *s,
            M::RenewalStatus(s) => renewal_status(c).as_deref() == Some(s.as_str()),
            M::Type(t) => c.ty == *t,
            M::InUse(b) => !*b,
            M::Exported(b) => c.exported == *b,
            M::ExportOption(e) => c.export_option == *e,
            M::ManagedBy(m) => c.managed_by.as_deref() == Some(m.as_str()),
            M::ValidationMethod(v) => validation_method(c).as_deref() == Some(v.as_str()),
            M::CertificateKeyPairOrigin(o) => c.origin == *o,
            M::AcmeEndpointArn(a) => c.acme_endpoint_arn.as_deref() == Some(a.as_str()),
            M::AcmeAccountId(a) => c.acme_account_id.as_deref() == Some(a.as_str()),
        },
    }
}

fn matches(c: &Certificate, info: Option<&CertInfo>, s: &types::CertificateFilterStatement) -> bool {
    match s {
        types::CertificateFilterStatement::And(list) => list.iter().all(|s| matches(c, info, s)),
        types::CertificateFilterStatement::Or(list) => list.iter().any(|s| matches(c, info, s)),
        types::CertificateFilterStatement::Not(s) => !matches(c, info, s),
        types::CertificateFilterStatement::Filter(f) => matches_filter(c, info, f),
    }
}

fn dn_wire(dn: &Dn) -> types::DistinguishedName {
    types::DistinguishedName {
        common_name: dn.common_name.clone(),
        domain_components: (!dn.domain_components.is_empty()).then(|| dn.domain_components.clone()),
        country: dn.country.clone(),
        custom_attributes: (!dn.custom.is_empty()).then(|| {
            dn.custom
                .iter()
                .map(|(o, v)| types::CustomAttribute { object_identifier: Some(o.clone()), value: Some(v.clone()) })
                .collect()
        }),
        distinguished_name_qualifier: dn.distinguished_name_qualifier.clone(),
        generation_qualifier: dn.generation_qualifier.clone(),
        given_name: dn.given_name.clone(),
        initials: dn.initials.clone(),
        locality: dn.locality.clone(),
        organization: dn.organization.clone(),
        organizational_unit: dn.organizational_unit.clone(),
        pseudonym: dn.pseudonym.clone(),
        serial_number: dn.serial_number.clone(),
        state: dn.state.clone(),
        surname: dn.surname.clone(),
        title: dn.title.clone(),
    }
}

fn general_name_wire(n: &GeneralNameInfo) -> types::GeneralName {
    match n {
        GeneralNameInfo::Dns(d) => types::GeneralName::DnsName(d.clone()),
        GeneralNameInfo::Ip(i) => types::GeneralName::IpAddress(i.clone()),
        GeneralNameInfo::Email(e) => types::GeneralName::Rfc822Name(e.clone()),
        GeneralNameInfo::Uri(u) => types::GeneralName::UniformResourceIdentifier(u.clone()),
        GeneralNameInfo::RegisteredId(o) => types::GeneralName::RegisteredId(o.clone()),
        GeneralNameInfo::Directory(dn) => types::GeneralName::DirectoryName(dn_wire(dn)),
        GeneralNameInfo::Other(o, v) => types::GeneralName::OtherName(types::OtherName {
            object_identifier: Some(o.clone()),
            value: Some(v.clone()),
        }),
    }
}

fn result(c: &Certificate, info: Option<&CertInfo>) -> types::CertificateSearchResult {
    let renewal_eligibility = crate::certs::detail(c).renewal_eligibility;
    types::CertificateSearchResult {
        certificate_arn: Some(c.arn.clone()),
        x509_attributes: info.map(|i| types::X509Attributes {
            issuer: Some(dn_wire(&i.issuer_dn)),
            subject: Some(dn_wire(&i.subject_dn)),
            subject_alternative_names: Some(i.sans.iter().map(general_name_wire).collect()),
            extended_key_usages: Some(i.extended_key_usages.iter().map(|(n, _)| n.clone()).collect()),
            key_algorithm: Some(i.key_algorithm.clone()),
            key_usages: Some(i.key_usages.clone()),
            serial_number: Some(i.serial.clone()),
            not_after: Some(i.not_after),
            not_before: Some(i.not_before),
        }),
        certificate_metadata: Some(types::CertificateMetadata::AcmCertificateMetadata(types::AcmCertificateMetadata {
            created_at: c.created_at,
            exported: Some(c.exported),
            imported_at: c.imported_at,
            in_use: Some(false),
            issued_at: c.issued_at,
            renewal_eligibility,
            revoked_at: c.revoked_at,
            status: Some(c.status.clone()),
            renewal_status: renewal_status(c),
            r#type: Some(c.ty.clone()),
            export_option: Some(c.export_option.clone()),
            managed_by: c.managed_by.clone(),
            validation_method: validation_method(c),
            certificate_key_pair_origin: Some(c.origin.clone()),
            acme_endpoint_arn: c.acme_endpoint_arn.clone(),
            acme_account_id: c.acme_account_id.clone(),
        })),
    }
}

/// The sort key for `sort_by`, as a string that orders correctly.
fn sort_key(c: &Certificate, info: Option<&CertInfo>, sort_by: &str) -> String {
    let t = |t: Option<chrono::DateTime<chrono::Utc>>| {
        t.map(|t| format!("{:020}", t.timestamp_millis())).unwrap_or_default()
    };
    match sort_by {
        "NOT_AFTER" => t(info.map(|i| i.not_after)),
        "NOT_BEFORE" => t(info.map(|i| i.not_before)),
        "STATUS" => c.status.clone(),
        "RENEWAL_STATUS" => renewal_status(c).unwrap_or_default(),
        "EXPORTED" => c.exported.to_string(),
        "IN_USE" => "false".into(),
        "KEY_ALGORITHM" => c.key_algorithm.clone(),
        "TYPE" => c.ty.clone(),
        "CERTIFICATE_ARN" => c.arn.clone(),
        "COMMON_NAME" => info.and_then(|i| i.subject_cn.clone()).unwrap_or_default(),
        "REVOKED_AT" => t(c.revoked_at),
        "RENEWAL_ELIGIBILITY" => crate::certs::detail(c).renewal_eligibility.unwrap_or_default(),
        "ISSUED_AT" => t(c.issued_at),
        "MANAGED_BY" => c.managed_by.clone().unwrap_or_default(),
        "EXPORT_OPTION" => c.export_option.clone(),
        "VALIDATION_METHOD" => validation_method(c).unwrap_or_default(),
        "IMPORTED_AT" => t(c.imported_at),
        "ACME_ENDPOINT_ARN" => c.acme_endpoint_arn.clone().unwrap_or_default(),
        "ACME_ACCOUNT_ID" => c.acme_account_id.clone().unwrap_or_default(),
        "CERTIFICATE_KEY_PAIR_ORIGIN" => c.origin.clone(),
        _ => t(c.created_at.or(c.imported_at)),
    }
}

fn depth(s: &types::CertificateFilterStatement) -> usize {
    match s {
        types::CertificateFilterStatement::And(l) | types::CertificateFilterStatement::Or(l) => {
            1 + l.iter().map(depth).max().unwrap_or(0)
        }
        types::CertificateFilterStatement::Not(s) => 1 + depth(s),
        types::CertificateFilterStatement::Filter(_) => 1,
    }
}

impl Acm {
    pub(crate) fn search_certificates(
        &self,
        ctx: &RequestContext,
        input: types::SearchCertificatesRequest,
    ) -> Result<types::SearchCertificatesResponse, ServiceError> {
        ctx.authorize("acm:SearchCertificates", "*", ConditionContext::new())?;
        if input.filter_statement.as_ref().is_some_and(|s| depth(s) > 5) {
            return Err(errors::validation("The filter statement is nested too deeply. The maximum depth is 5."));
        }
        self.refresh(ctx);
        let st = self.lock();
        let mut found: Vec<(&Certificate, Option<CertInfo>)> = st
            .certificates
            .values()
            .filter(|c| c.account == ctx.caller.account_id && c.region == ctx.region)
            .map(|c| (c, c.cert_pem.as_deref().and_then(pki::inspect_pem)))
            .filter(|(c, info)| input.filter_statement.as_ref().is_none_or(|s| matches(c, info.as_ref(), s)))
            .collect();
        let sort_by = if input.sort_by.is_empty() { "CREATED_AT".to_string() } else { input.sort_by.clone() };
        found.sort_by_cached_key(|(c, info)| sort_key(c, info.as_ref(), &sort_by));
        if input.sort_order == "DESCENDING" {
            found.reverse();
        }
        let results: Vec<_> = found.iter().map(|(c, i)| result(c, i.as_ref())).collect();
        let (page, next) = common::paginate(results, Some(input.max_results), 100, input.next_token.as_deref())?;
        Ok(types::SearchCertificatesResponse { results: Some(page), next_token: next })
    }
}
