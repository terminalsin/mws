//! Cluster certificate authorities: the `kubernetes` CA every cluster
//! starts with, and the CA rotation API (create a CA, distribute it,
//! activate it for signing, delete the old one).

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose, RsaKeySize};

use crate::generated::{errors, types};
use crate::state::{durations, CaRec, ClusterRec};
use crate::util::{self, param, text};
use crate::Eks;

/// A self-signed `CN=kubernetes` CA certificate, PEM, valid ten years.
pub(crate) fn kubernetes_ca(now: DateTime<Utc>) -> Result<String, ServiceError> {
    let key = KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, RsaKeySize::_2048)
        .map_err(|e| ServiceError::internal(format!("CA key generation failed: {e}")))?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "kubernetes");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = to_offset(now - Duration::minutes(5));
    params.not_after = to_offset(now + Duration::days(3650));
    let mut serial = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut serial);
    serial[0] &= 0x7f;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    let cert = params.self_signed(&key).map_err(|e| ServiceError::internal(format!("CA signing failed: {e}")))?;
    Ok(cert.pem())
}

fn to_offset(t: DateTime<Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(t.timestamp()).expect("valid timestamp")
}

fn b64(pem: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(pem)
}

/// A new CA record.
pub(crate) fn new_ca(now: DateTime<Utc>, created_by: &str, in_use: bool) -> Result<CaRec, ServiceError> {
    let pem = kubernetes_ca(now)?;
    let id = format!("ca-{}", util::random(util::LOWER_ALNUM, 17));
    Ok(CaRec {
        ca: types::CertificateAuthority {
            id: Some(id),
            created_at: Some(now),
            created_by: Some(created_by.into()),
            activated_at: in_use.then_some(now),
            activated_by: in_use.then(|| created_by.to_string()),
            signing_status: Some(if in_use { "IN_USE" } else { "NOT_USED" }.into()),
            distribution_status: Some(if in_use { "COMPLETE" } else { "IN_PROGRESS" }.into()),
            validity: Some(types::CertificateAuthorityValidity {
                not_before: Some(now - Duration::minutes(5)),
                not_after: Some(now + Duration::days(3650)),
            }),
            scheduled_events: None,
            rollback_available: Some(false),
            data: Some(b64(&pem)),
        },
    })
}

/// The cluster's `certificateAuthority`: every distributed CA (the trust
/// bundle kubeconfigs carry) and the one that signs.
pub(crate) fn refresh_cluster_certificate(rec: &mut ClusterRec) {
    let mut bundle = String::new();
    for c in &rec.certificate_authorities {
        if c.ca.distribution_status.as_deref() == Some("COMPLETE") {
            if let Some(pem) =
                c.ca.data.as_deref().and_then(|d| base64::engine::general_purpose::STANDARD.decode(d).ok())
            {
                bundle.push_str(&String::from_utf8_lossy(&pem));
            }
        }
    }
    let active = rec.certificate_authorities.iter().find(|c| c.ca.signing_status.as_deref() == Some("IN_USE"));
    rec.cluster.certificate_authority = Some(types::Certificate {
        data: Some(b64(&bundle)),
        active: active.map(|c| types::ActiveCertificateAuthority {
            id: c.ca.id.clone(),
            activated_by: c.ca.activated_by.clone(),
        }),
    });
}

fn summary(c: &types::CertificateAuthority) -> types::CertificateAuthoritySummary {
    types::CertificateAuthoritySummary {
        id: c.id.clone(),
        created_at: c.created_at,
        created_by: c.created_by.clone(),
        activated_at: c.activated_at,
        activated_by: c.activated_by.clone(),
        signing_status: c.signing_status.clone(),
        distribution_status: c.distribution_status.clone(),
    }
}

fn ca_not_found(id: &str) -> ServiceError {
    errors::resource_not_found(format!("No certificate authority found with id: {id}."))
}

fn ca_index(rec: &ClusterRec, id: &str) -> Result<usize, ServiceError> {
    rec.certificate_authorities.iter().position(|c| c.ca.id.as_deref() == Some(id)).ok_or_else(|| ca_not_found(id))
}

impl Eks {
    pub(crate) async fn create_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::CreateCertificateAuthorityRequest,
    ) -> Result<types::CreateCertificateAuthorityResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let ca = new_ca(ctx.received_at, "CUSTOMER", false)?;
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "CreateCertificateAuthority",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        if rec.certificate_authorities.len() >= 2 {
            return Err(errors::resource_limit_exceeded(
                "The cluster already has the maximum of 2 certificate authorities. Delete one that is not in use first.",
            )
            .with_field("clusterName", text(&input.cluster_name)));
        }
        let id = ca.ca.id.clone().unwrap_or_default();
        let s = summary(&ca.ca);
        rec.certificate_authorities.push(ca);
        let done_at = rec.begin("certs", ctx.received_at, durations::CERTIFICATE_AUTHORITY);
        let update = crate::updates::push(
            rec,
            ctx.received_at,
            done_at,
            "CertificateAuthorityUpdate",
            vec![param("CertificateAuthorityId", id)],
            None,
        );
        Ok(types::CreateCertificateAuthorityResponse { update: Some(update), certificate_authority: Some(s) })
    }

    pub(crate) async fn activate_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::ActivateCertificateAuthorityRequest,
    ) -> Result<types::ActivateCertificateAuthorityResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "ActivateCertificateAuthority",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        let i = ca_index(rec, &input.certificate_authority_id)?;
        let ca = &rec.certificate_authorities[i].ca;
        if ca.signing_status.as_deref() != Some("NOT_USED") {
            return Err(errors::invalid_parameter(format!(
                "Certificate authority {} is already {}.",
                input.certificate_authority_id,
                ca.signing_status.as_deref().unwrap_or_default()
            )));
        }
        if ca.distribution_status.as_deref() != Some("COMPLETE") {
            return Err(errors::invalid_parameter(format!(
                "Certificate authority {} cannot be activated until its distribution is COMPLETE.",
                input.certificate_authority_id
            )));
        }
        let now = ctx.received_at;
        let ca = &mut rec.certificate_authorities[i].ca;
        ca.signing_status = Some("ACTIVATING".into());
        ca.activated_at = Some(now);
        ca.activated_by = Some("CUSTOMER".into());
        let s = summary(ca);
        let done_at = rec.begin("certs", now, durations::CERTIFICATE_AUTHORITY);
        let update = crate::updates::push(
            rec,
            now,
            done_at,
            "CertificateAuthorityUpdate",
            vec![param("ActiveCertificateAuthority", input.certificate_authority_id.clone())],
            None,
        );
        Ok(types::ActivateCertificateAuthorityResponse { update: Some(update), certificate_authority: Some(s) })
    }

    pub(crate) async fn delete_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCertificateAuthorityRequest,
    ) -> Result<types::DeleteCertificateAuthorityResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "DeleteCertificateAuthority",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        let i = ca_index(rec, &input.certificate_authority_id)?;
        if rec.certificate_authorities[i].ca.signing_status.as_deref() != Some("NOT_USED") {
            return Err(errors::resource_in_use(format!(
                "Certificate authority {} is in use and cannot be deleted.",
                input.certificate_authority_id
            )));
        }
        rec.certificate_authorities[i].ca.distribution_status = Some("DELETING".into());
        let s = summary(&rec.certificate_authorities[i].ca);
        let done_at = rec.begin("certs", ctx.received_at, durations::CERTIFICATE_AUTHORITY);
        let update = crate::updates::push(
            rec,
            ctx.received_at,
            done_at,
            "CertificateAuthorityUpdate",
            vec![param("CertificateAuthorityId", input.certificate_authority_id.clone())],
            None,
        );
        Ok(types::DeleteCertificateAuthorityResponse { update: Some(update), certificate_authority: Some(s) })
    }

    pub(crate) async fn describe_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCertificateAuthorityRequest,
    ) -> Result<types::DescribeCertificateAuthorityResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "DescribeCertificateAuthority",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        let i = ca_index(rec, &input.certificate_authority_id)?;
        let mut ca = rec.certificate_authorities[i].ca.clone();
        ca.rollback_available = Some(
            ca.signing_status.as_deref() == Some("IN_USE")
                && rec.certificate_authorities.iter().any(|c| c.ca.id != ca.id && c.ca.created_by.is_some()),
        );
        Ok(types::DescribeCertificateAuthorityResponse { certificate_authority: Some(ca) })
    }

    pub(crate) async fn list_certificate_authorities(
        &self,
        ctx: &RequestContext,
        input: types::ListCertificateAuthoritiesRequest,
    ) -> Result<types::ListCertificateAuthoritiesResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "ListCertificateAuthorities",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        let all: Vec<_> = rec.certificate_authorities.iter().map(|c| summary(&c.ca)).collect();
        let (items, next) = util::page(&all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListCertificateAuthoritiesResponse { certificate_authorities: Some(items), next_token: next })
    }
}

/// Move certificate authorities through distribution and activation.
pub(crate) fn settle(rec: &mut ClusterRec) {
    let activating = rec.certificate_authorities.iter().any(|c| c.ca.signing_status.as_deref() == Some("ACTIVATING"));
    rec.certificate_authorities.retain(|c| c.ca.distribution_status.as_deref() != Some("DELETING"));
    for c in &mut rec.certificate_authorities {
        if c.ca.distribution_status.as_deref() == Some("IN_PROGRESS") {
            c.ca.distribution_status = Some("COMPLETE".into());
        }
        match c.ca.signing_status.as_deref() {
            Some("ACTIVATING") => c.ca.signing_status = Some("IN_USE".into()),
            Some("IN_USE") if activating => c.ca.signing_status = Some("NOT_USED".into()),
            _ => {}
        }
    }
    refresh_cluster_certificate(rec);
}
