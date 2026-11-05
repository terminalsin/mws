//! Trust stores for mutual TLS: CA bundles and revocation lists read from
//! S3 with the caller's permissions, as ELB does.

use mws_core::{RequestContext, ServiceError};

use crate::names::{self, validation};
use crate::state::{Revocation, TrustStoreRecord};
use crate::v2::{errors, types as t};
use crate::{account_of, Elb};

pub(crate) fn trust_store_not_found() -> ServiceError {
    errors::trust_store_not_found("One or more trust stores not found")
}

/// Every PEM block of `label` in `text`, as DER.
pub(crate) fn pem_blocks(text: &str, label: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else { break };
        let body: String = after[..stop].chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body) {
            out.push(der);
        }
        rest = &after[stop + end.len()..];
    }
    out
}

impl Elb {
    fn read_s3(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> Result<Vec<u8>, ServiceError> {
        let s3 = self.s3().ok_or_else(|| errors::ca_certificates_bundle_not_found("S3 is not available"))?;
        let req = mws_s3::generated::types::GetObjectRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            version_id: version.map(str::to_string),
            ..Default::default()
        };
        s3.get_object_as_caller(ctx, req).map(|o| o.body).map_err(|e| {
            if e.code == "AccessDenied" {
                e
            } else {
                errors::ca_certificates_bundle_not_found(format!(
                    "The specified S3 object 's3://{bucket}/{key}' was not found"
                ))
            }
        })
    }

    fn read_bundle(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> Result<(String, i32), ServiceError> {
        let body = self.read_s3(ctx, bucket, key, version)?;
        let text = String::from_utf8(body)
            .map_err(|_| errors::invalid_ca_certificates_bundle("The CA certificates bundle must be PEM encoded"))?;
        let ders = pem_blocks(&text, "CERTIFICATE");
        if ders.is_empty() {
            return Err(errors::invalid_ca_certificates_bundle("The CA certificates bundle contains no certificates"));
        }
        for der in &ders {
            let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|_| {
                errors::invalid_ca_certificates_bundle("The CA certificates bundle contains an invalid certificate")
            })?;
            if !cert.is_ca() {
                return Err(errors::invalid_ca_certificates_bundle(
                    "The CA certificates bundle contains a certificate that is not a CA",
                ));
            }
        }
        Ok((text, ders.len() as i32))
    }

    pub(crate) fn create_trust_store_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTrustStoreInput,
    ) -> Result<t::CreateTrustStoreOutput, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        names::check_tags(&tags)?;
        names::check_name("Trust store", &input.name)?;
        let account = account_of(ctx);
        let arn = names::arn(ctx, &account, &format!("truststore/{}/{}", input.name, names::hex_id(16)));
        self.authorize_create(ctx, "CreateTrustStore", &arn, &tags)?;
        let (bundle, count) = self.read_bundle(
            ctx,
            &input.ca_certificates_bundle_s3_bucket,
            &input.ca_certificates_bundle_s3_key,
            input.ca_certificates_bundle_s3_object_version.as_deref(),
        )?;
        let store = self.with_region(ctx, |r| {
            if r.trust_stores.values().any(|s| s.store.name.as_deref() == Some(input.name.as_str())) {
                return Err(errors::duplicate_trust_store_name(format!(
                    "A trust store with the name '{}' already exists",
                    input.name
                )));
            }
            if r.trust_stores.len() >= crate::catalog::limit("trust-stores-per-account") {
                return Err(errors::too_many_trust_stores("You have reached the maximum number of trust stores"));
            }
            let store = t::TrustStore {
                name: Some(input.name.clone()),
                trust_store_arn: Some(arn.clone()),
                status: Some("ACTIVE".into()),
                number_of_ca_certificates: Some(count),
                total_revoked_entries: Some(0),
            };
            r.trust_stores.insert(
                arn.clone(),
                TrustStoreRecord {
                    store: store.clone(),
                    bundle_pem: bundle,
                    bundle_source: (
                        input.ca_certificates_bundle_s3_bucket.clone(),
                        input.ca_certificates_bundle_s3_key.clone(),
                        input.ca_certificates_bundle_s3_object_version.clone(),
                    ),
                    revocations: Vec::new(),
                    next_revocation_id: 1,
                },
            );
            if !tags.is_empty() {
                r.tags.insert(arn.clone(), tags.clone());
            }
            Ok(store)
        })?;
        Ok(t::CreateTrustStoreOutput { trust_stores: Some(vec![store]) })
    }

    pub(crate) fn modify_trust_store_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyTrustStoreInput,
    ) -> Result<t::ModifyTrustStoreOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyTrustStore", &input.trust_store_arn)?;
        self.with_region(ctx, |r| {
            r.trust_stores.get(&input.trust_store_arn).map(|_| ()).ok_or_else(trust_store_not_found)
        })?;
        let (bundle, count) = self.read_bundle(
            ctx,
            &input.ca_certificates_bundle_s3_bucket,
            &input.ca_certificates_bundle_s3_key,
            input.ca_certificates_bundle_s3_object_version.as_deref(),
        )?;
        self.with_region(ctx, |r| {
            let s = r.trust_stores.get_mut(&input.trust_store_arn).ok_or_else(trust_store_not_found)?;
            s.bundle_pem = bundle;
            s.bundle_source = (
                input.ca_certificates_bundle_s3_bucket.clone(),
                input.ca_certificates_bundle_s3_key.clone(),
                input.ca_certificates_bundle_s3_object_version.clone(),
            );
            s.store.number_of_ca_certificates = Some(count);
            Ok(t::ModifyTrustStoreOutput { trust_stores: Some(vec![s.store.clone()]) })
        })
    }

    pub(crate) fn delete_trust_store_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTrustStoreInput,
    ) -> Result<t::DeleteTrustStoreOutput, ServiceError> {
        self.authorize_on(ctx, "DeleteTrustStore", &input.trust_store_arn)?;
        self.with_region(ctx, |r| {
            if !r.trust_stores.contains_key(&input.trust_store_arn) {
                return Err(trust_store_not_found());
            }
            let used = r.listeners.values().any(|l| {
                l.listener.mutual_authentication.as_ref().and_then(|m| m.trust_store_arn.as_deref())
                    == Some(input.trust_store_arn.as_str())
            });
            if used {
                return Err(errors::trust_store_in_use(format!(
                    "Trust store '{}' is in use by a listener",
                    input.trust_store_arn
                )));
            }
            r.trust_stores.remove(&input.trust_store_arn);
            r.tags.remove(&input.trust_store_arn);
            Ok(t::DeleteTrustStoreOutput {})
        })
    }

    pub(crate) fn describe_trust_stores_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTrustStoresInput,
    ) -> Result<t::DescribeTrustStoresOutput, ServiceError> {
        names::authorize(ctx, "DescribeTrustStores", "*", Default::default())?;
        let arns = input.trust_store_arns.unwrap_or_default();
        let wanted = input.names.unwrap_or_default();
        let all = self.with_region(ctx, |r| -> Result<Vec<t::TrustStore>, ServiceError> {
            if !arns.is_empty() {
                return arns
                    .iter()
                    .map(|a| r.trust_stores.get(a).map(|s| s.store.clone()).ok_or_else(trust_store_not_found))
                    .collect();
            }
            if !wanted.is_empty() {
                return wanted
                    .iter()
                    .map(|n| {
                        r.trust_stores
                            .values()
                            .find(|s| s.store.name.as_deref() == Some(n.as_str()))
                            .map(|s| s.store.clone())
                            .ok_or_else(trust_store_not_found)
                    })
                    .collect();
            }
            Ok(r.trust_stores.values().map(|s| s.store.clone()).collect())
        })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 20)?;
        Ok(t::DescribeTrustStoresOutput { trust_stores: Some(items), next_marker: next })
    }

    pub(crate) fn describe_trust_store_associations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTrustStoreAssociationsInput,
    ) -> Result<t::DescribeTrustStoreAssociationsOutput, ServiceError> {
        names::authorize(ctx, "DescribeTrustStoreAssociations", "*", Default::default())?;
        let all = self.with_region(ctx, |r| {
            if !r.trust_stores.contains_key(&input.trust_store_arn) {
                return Err(trust_store_not_found());
            }
            let mut lbs: Vec<String> = Vec::new();
            for l in r.listeners.values() {
                if l.listener.mutual_authentication.as_ref().and_then(|m| m.trust_store_arn.as_deref())
                    == Some(input.trust_store_arn.as_str())
                    && !lbs.iter().any(|x| x == l.lb_arn())
                {
                    lbs.push(l.lb_arn().to_string());
                }
            }
            Ok(lbs.into_iter().map(|a| t::TrustStoreAssociation { resource_arn: Some(a) }).collect::<Vec<_>>())
        })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(t::DescribeTrustStoreAssociationsOutput { trust_store_associations: Some(items), next_marker: next })
    }

    pub(crate) fn delete_shared_trust_store_association_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteSharedTrustStoreAssociationInput,
    ) -> Result<t::DeleteSharedTrustStoreAssociationOutput, ServiceError> {
        self.authorize_on(ctx, "DeleteSharedTrustStoreAssociation", &input.trust_store_arn)?;
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            if !r.trust_stores.contains_key(&input.trust_store_arn) {
                return Err(trust_store_not_found());
            }
            let resource_account = input.resource_arn.split(':').nth(4).unwrap_or_default();
            if resource_account == account {
                return Err(errors::delete_association_same_account(
                    "The trust store and the load balancer are in the same account; remove the trust store from the listener instead",
                ));
            }
            Err(errors::trust_store_association_not_found(format!(
                "No association was found between trust store '{}' and '{}'",
                input.trust_store_arn, input.resource_arn
            )))
        })
    }

    pub(crate) fn add_trust_store_revocations_op(
        &self,
        ctx: &RequestContext,
        input: t::AddTrustStoreRevocationsInput,
    ) -> Result<t::AddTrustStoreRevocationsOutput, ServiceError> {
        self.authorize_on(ctx, "AddTrustStoreRevocations", &input.trust_store_arn)?;
        self.with_region(ctx, |r| {
            r.trust_stores.get(&input.trust_store_arn).map(|_| ()).ok_or_else(trust_store_not_found)
        })?;
        let mut parsed = Vec::new();
        for c in input.revocation_contents.iter().flatten() {
            let ty = c.revocation_type.clone().unwrap_or_else(|| "CRL".into());
            if ty != "CRL" {
                return Err(errors::invalid_revocation_content(format!("Revocation type '{ty}' is not supported")));
            }
            let (bucket, key) = (c.s3_bucket.clone().unwrap_or_default(), c.s3_key.clone().unwrap_or_default());
            let body = self.read_s3(ctx, &bucket, &key, c.s3_object_version.as_deref()).map_err(|e| {
                if e.code == "AccessDenied" {
                    e
                } else {
                    errors::revocation_content_not_found(format!(
                        "The specified S3 object 's3://{bucket}/{key}' was not found"
                    ))
                }
            })?;
            let der = match std::str::from_utf8(&body) {
                Ok(text) if text.contains("-----BEGIN X509 CRL-----") => {
                    pem_blocks(text, "X509 CRL").into_iter().next().unwrap_or_default()
                }
                _ => body,
            };
            let (_, crl) = x509_parser::parse_x509_crl(&der)
                .map_err(|_| errors::invalid_revocation_content("The revocation content is not a valid CRL"))?;
            let serials: Vec<String> = crl.iter_revoked_certificates().map(|rc| hex::encode(rc.raw_serial())).collect();
            parsed.push((ty, (bucket, key, c.s3_object_version.clone()), serials, der.clone()));
        }
        self.with_region(ctx, |r| {
            let s = r.trust_stores.get_mut(&input.trust_store_arn).ok_or_else(trust_store_not_found)?;
            let mut out = Vec::new();
            for (ty, source, serials, crl) in parsed {
                let id = s.next_revocation_id.max(1);
                s.next_revocation_id = id + 1;
                out.push(t::TrustStoreRevocation {
                    trust_store_arn: Some(input.trust_store_arn.clone()),
                    revocation_id: Some(id),
                    revocation_type: Some(ty.clone()),
                    number_of_revoked_entries: Some(serials.len() as i64),
                });
                s.revocations.push(Revocation { id, ty, source, serials, crl });
            }
            let total: i64 = s.revocations.iter().map(|x| x.serials.len() as i64).sum();
            if total > 1_000_000 {
                return Err(errors::too_many_trust_store_revocation_entries(
                    "The trust store has too many revocation entries",
                ));
            }
            s.store.total_revoked_entries = Some(total);
            Ok(t::AddTrustStoreRevocationsOutput { trust_store_revocations: Some(out) })
        })
    }

    pub(crate) fn remove_trust_store_revocations_op(
        &self,
        ctx: &RequestContext,
        input: t::RemoveTrustStoreRevocationsInput,
    ) -> Result<t::RemoveTrustStoreRevocationsOutput, ServiceError> {
        self.authorize_on(ctx, "RemoveTrustStoreRevocations", &input.trust_store_arn)?;
        self.with_region(ctx, |r| {
            let s = r.trust_stores.get_mut(&input.trust_store_arn).ok_or_else(trust_store_not_found)?;
            for id in &input.revocation_ids {
                if !s.revocations.iter().any(|x| x.id == *id) {
                    return Err(errors::revocation_id_not_found(format!("Revocation ID '{id}' not found")));
                }
            }
            s.revocations.retain(|x| !input.revocation_ids.contains(&x.id));
            s.store.total_revoked_entries = Some(s.revocations.iter().map(|x| x.serials.len() as i64).sum());
            Ok(t::RemoveTrustStoreRevocationsOutput {})
        })
    }

    pub(crate) fn describe_trust_store_revocations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTrustStoreRevocationsInput,
    ) -> Result<t::DescribeTrustStoreRevocationsOutput, ServiceError> {
        names::authorize(ctx, "DescribeTrustStoreRevocations", "*", Default::default())?;
        let all = self.with_region(ctx, |r| {
            let s = r.trust_stores.get(&input.trust_store_arn).ok_or_else(trust_store_not_found)?;
            let ids = input.revocation_ids.clone().unwrap_or_default();
            for id in &ids {
                if !s.revocations.iter().any(|x| x.id == *id) {
                    return Err(errors::revocation_id_not_found(format!("Revocation ID '{id}' not found")));
                }
            }
            Ok(s.revocations
                .iter()
                .filter(|x| ids.is_empty() || ids.contains(&x.id))
                .map(|x| t::DescribeTrustStoreRevocation {
                    trust_store_arn: Some(input.trust_store_arn.clone()),
                    revocation_id: Some(x.id),
                    revocation_type: Some(x.ty.clone()),
                    number_of_revoked_entries: Some(x.serials.len() as i64),
                })
                .collect::<Vec<_>>())
        })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(t::DescribeTrustStoreRevocationsOutput { trust_store_revocations: Some(items), next_marker: next })
    }

    /// A link to the stored bundle, served unsigned by MWS (AWS hands out a
    /// presigned S3 URL).
    fn content_link(&self, ctx: &RequestContext, path: &str) -> String {
        let base = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
        format!("{}/_aws/elb/{path}", base.trim_end_matches('/'))
    }

    pub(crate) fn get_trust_store_ca_certificates_bundle_op(
        &self,
        ctx: &RequestContext,
        input: t::GetTrustStoreCaCertificatesBundleInput,
    ) -> Result<t::GetTrustStoreCaCertificatesBundleOutput, ServiceError> {
        self.authorize_on(ctx, "GetTrustStoreCaCertificatesBundle", &input.trust_store_arn)?;
        self.with_region(ctx, |r| {
            r.trust_stores.get(&input.trust_store_arn).map(|_| ()).ok_or_else(trust_store_not_found)
        })?;
        let account = account_of(ctx);
        let path = format!("trust-stores/{account}/{}/{}/bundle", ctx.region, urlencode(&input.trust_store_arn));
        Ok(t::GetTrustStoreCaCertificatesBundleOutput { location: Some(self.content_link(ctx, &path)) })
    }

    pub(crate) fn get_trust_store_revocation_content_op(
        &self,
        ctx: &RequestContext,
        input: t::GetTrustStoreRevocationContentInput,
    ) -> Result<t::GetTrustStoreRevocationContentOutput, ServiceError> {
        self.authorize_on(ctx, "GetTrustStoreRevocationContent", &input.trust_store_arn)?;
        self.with_region(ctx, |r| {
            let s = r.trust_stores.get(&input.trust_store_arn).ok_or_else(trust_store_not_found)?;
            if !s.revocations.iter().any(|x| x.id == input.revocation_id) {
                return Err(errors::revocation_id_not_found(format!(
                    "Revocation ID '{}' not found",
                    input.revocation_id
                )));
            }
            if input.revocation_id < 1 {
                return Err(validation("The revocation ID is not valid"));
            }
            Ok(())
        })?;
        let account = account_of(ctx);
        let path = format!(
            "trust-stores/{account}/{}/{}/revocations/{}",
            ctx.region,
            urlencode(&input.trust_store_arn),
            input.revocation_id
        );
        Ok(t::GetTrustStoreRevocationContentOutput { location: Some(self.content_link(ctx, &path)) })
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
