//! Custom domains: associations, their certificate and subdomain records,
//! and verification through Route 53.
//!
//! As in Amplify, an association first waits for the managed certificate's
//! validation CNAME (`PENDING_VERIFICATION`), then for each subdomain's
//! CNAME to the app's distribution (`AWAITING_APP_CNAME`), and is then
//! `AVAILABLE`. When the caller's account has a public hosted zone for the
//! domain, Amplify writes those records itself; otherwise they can be
//! created in any public hosted zone MWS serves.

use mws_core::{ConditionContext, RequestContext, Service, ServiceError};
use serde_json::json;

use crate::apps::{app_mut, authorize, branch};
use crate::generated::types;
use crate::names::{self, bad_request, not_found};
use crate::state::{AppRecord, DomainRecord};
use crate::Amplify;

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn fqdn(prefix: &str, domain: &str) -> String {
    if prefix.is_empty() {
        domain.to_string()
    } else {
        format!("{prefix}.{domain}")
    }
}

fn sub_domain(setting: types::SubDomainSetting, distribution: &str) -> types::SubDomain {
    let dns_record = format!("{} CNAME {distribution}", setting.prefix);
    types::SubDomain { sub_domain_setting: setting, verified: false, dns_record }
}

fn check_certificate(settings: Option<&types::CertificateSettings>) -> Result<(), ServiceError> {
    if let Some(c) = settings {
        if c.r#type == "CUSTOM" && c.custom_certificate_arn.as_deref().is_none_or(str::is_empty) {
            return Err(bad_request("customCertificateArn is required for a CUSTOM certificate."));
        }
        if let Some(arn) = &c.custom_certificate_arn {
            if !arn.starts_with("arn:aws:acm:us-east-1:") {
                return Err(bad_request("The custom certificate must be an ACM certificate in us-east-1."));
            }
        }
    }
    Ok(())
}

fn certificate(settings: Option<types::CertificateSettings>, record: &DomainRecord) -> types::Certificate {
    let settings =
        settings.unwrap_or(types::CertificateSettings { r#type: "AMPLIFY_MANAGED".into(), custom_certificate_arn: None });
    let managed = settings.r#type != "CUSTOM";
    types::Certificate {
        r#type: settings.r#type,
        custom_certificate_arn: settings.custom_certificate_arn,
        certificate_verification_dns_record: managed
            .then(|| format!("{} CNAME {}", record.verification_name, record.verification_value)),
    }
}

/// Update each branch's `customDomains` from the app's associations.
fn sync_branch_domains(rec: &mut AppRecord) {
    for b in rec.branches.values_mut() {
        b.branch.custom_domains.clear();
    }
    let mut mapped = Vec::new();
    for d in rec.domains.values() {
        for s in &d.domain.sub_domains {
            mapped.push((s.sub_domain_setting.branch_name.clone(), fqdn(&s.sub_domain_setting.prefix, &d.domain.domain_name)));
        }
    }
    for (branch, host) in mapped {
        if let Some(b) = rec.branches.get_mut(&branch) {
            b.branch.custom_domains.push(host);
        }
    }
}

impl Amplify {
    /// Recompute the status of the app's domain associations from DNS.
    pub(crate) fn refresh_domains(&self, rec: &mut AppRecord) {
        for d in rec.domains.values_mut() {
            let Some(r53) = &self.inner.route53 else {
                d.domain.domain_status = "AVAILABLE".into();
                for s in &mut d.domain.sub_domains {
                    s.verified = true;
                }
                continue;
            };
            let custom = d.domain.certificate.as_ref().is_some_and(|c| c.r#type == "CUSTOM");
            let has = |name: &str, value: &str| {
                r53.public_record_values(name, "CNAME").iter().any(|v| normalize(v) == normalize(value))
            };
            let cert_ok = custom || has(&d.verification_name, &d.verification_value);
            for s in &mut d.domain.sub_domains {
                let host = fqdn(&s.sub_domain_setting.prefix, &d.domain.domain_name);
                s.verified = cert_ok && (s.sub_domain_setting.prefix.is_empty() || has(&host, &d.distribution));
            }
            d.domain.domain_status = if !cert_ok {
                "PENDING_VERIFICATION"
            } else if d.domain.sub_domains.iter().all(|s| s.verified) {
                "AVAILABLE"
            } else {
                "AWAITING_APP_CNAME"
            }
            .into();
            d.domain.status_reason = String::new();
            if d.domain.update_status.is_some() {
                d.domain.update_status = Some(if d.domain.domain_status == "AVAILABLE" {
                    "UPDATE_COMPLETE".into()
                } else {
                    d.domain.domain_status.clone()
                });
            }
        }
    }

    /// Write the domain's records into the caller's public hosted zone for
    /// it, if there is one, as Amplify does for domains in Route 53.
    async fn write_dns_records(&self, ctx: &RequestContext, record: &DomainRecord) {
        let Some(r53) = &self.inner.route53 else { return };
        let domain = normalize(&record.domain.domain_name);
        let Ok(zones) = r53.invoke(ctx.clone(), "ListHostedZonesByName", json!({ "DNSName": domain })).await else {
            return;
        };
        let zone = zones["HostedZones"].as_array().into_iter().flatten().find(|z| {
            z["Name"].as_str().map(normalize).as_deref() == Some(domain.as_str())
                && z["Config"]["PrivateZone"].as_bool() != Some(true)
        });
        let Some(zone_id) = zone.and_then(|z| z["Id"].as_str()) else { return };
        let zone_id = zone_id.rsplit('/').next().unwrap_or(zone_id).to_string();
        let mut changes = Vec::new();
        let mut cname = |name: String, value: &str| {
            changes.push(json!({
                "Action": "UPSERT",
                "ResourceRecordSet": { "Name": name, "Type": "CNAME", "TTL": 300, "ResourceRecords": [{ "Value": value }] }
            }));
        };
        if record.domain.certificate.as_ref().is_none_or(|c| c.r#type != "CUSTOM") {
            cname(record.verification_name.clone(), &record.verification_value);
        }
        for s in &record.domain.sub_domains {
            if !s.sub_domain_setting.prefix.is_empty() {
                cname(fqdn(&s.sub_domain_setting.prefix, &domain), &record.distribution);
            }
        }
        let input = json!({
            "HostedZoneId": zone_id,
            "ChangeBatch": { "Comment": "Amplify domain association", "Changes": changes }
        });
        if let Err(e) = r53.invoke(ctx.clone(), "ChangeResourceRecordSets", input).await {
            tracing::debug!("Amplify could not write records for {domain}: {e:?}");
        }
    }

    pub(crate) async fn create_domain_association(
        &self,
        ctx: &RequestContext,
        input: types::CreateDomainAssociationRequest,
    ) -> Result<types::CreateDomainAssociationResult, ServiceError> {
        let domain_name = normalize(&input.domain_name);
        let record = {
            let mut st = self.write();
            let taken = st.apps.values().any(|a| {
                a.account == ctx.caller.account_id && a.domains.keys().any(|d| d == &domain_name)
            });
            let rec = app_mut(ctx, &mut st, &input.app_id)?;
            let arn = format!("{}/domains/{domain_name}", rec.app.app_arn);
            authorize(ctx, "CreateDomainAssociation", &arn, ConditionContext::new())?;
            if taken {
                return Err(bad_request(format!("Domain {domain_name} is already associated with an app.")));
            }
            check_certificate(input.certificate_settings.as_ref())?;
            for s in &input.sub_domain_settings {
                branch(rec, &s.branch_name)?;
            }
            let distribution = format!("d{}.cloudfront.net", names::random_alnum(13));
            let mut record = DomainRecord {
                verification_name: format!("_{}.{domain_name}.", names::random_hex(32)),
                verification_value: format!("_{}.{}.acm-validations.aws.", names::random_hex(32), names::random_alnum(10)),
                distribution: distribution.clone(),
                ..DomainRecord::default()
            };
            let cert = certificate(input.certificate_settings, &record);
            record.domain = types::DomainAssociation {
                domain_association_arn: arn,
                domain_name: domain_name.clone(),
                enable_auto_sub_domain: input.enable_auto_sub_domain.unwrap_or(false),
                auto_sub_domain_creation_patterns: input.auto_sub_domain_creation_patterns,
                auto_sub_domain_iam_role: input.auto_sub_domain_iam_role,
                domain_status: "CREATING".into(),
                update_status: None,
                status_reason: String::new(),
                certificate_verification_dns_record: cert.certificate_verification_dns_record.clone(),
                sub_domains: input.sub_domain_settings.into_iter().map(|s| sub_domain(s, &distribution)).collect(),
                certificate: Some(cert),
            };
            rec.domains.insert(domain_name.clone(), record.clone());
            sync_branch_domains(rec);
            record
        };
        self.write_dns_records(ctx, &record).await;
        Ok(types::CreateDomainAssociationResult { domain_association: record.domain })
    }

    pub(crate) async fn get_domain_association(
        &self,
        ctx: &RequestContext,
        input: types::GetDomainAssociationRequest,
    ) -> Result<types::GetDomainAssociationResult, ServiceError> {
        let domain_name = normalize(&input.domain_name);
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        let d = rec.domains.get(&domain_name).ok_or_else(|| not_found("Domain association", &domain_name))?;
        authorize(ctx, "GetDomainAssociation", &d.domain.domain_association_arn, ConditionContext::new())?;
        self.refresh_domains(rec);
        Ok(types::GetDomainAssociationResult { domain_association: rec.domains[&domain_name].domain.clone() })
    }

    pub(crate) async fn list_domain_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListDomainAssociationsRequest,
    ) -> Result<types::ListDomainAssociationsResult, ServiceError> {
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        authorize(ctx, "ListDomainAssociations", &format!("{}/domains/*", rec.app.app_arn), ConditionContext::new())?;
        self.refresh_domains(rec);
        let all: Vec<types::DomainAssociation> = rec.domains.values().map(|d| d.domain.clone()).collect();
        let (domain_associations, next_token) =
            names::paginate(&all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListDomainAssociationsResult { domain_associations, next_token })
    }

    pub(crate) async fn update_domain_association(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDomainAssociationRequest,
    ) -> Result<types::UpdateDomainAssociationResult, ServiceError> {
        let domain_name = normalize(&input.domain_name);
        let record = {
            let mut st = self.write();
            let rec = app_mut(ctx, &mut st, &input.app_id)?;
            let d = rec.domains.get(&domain_name).ok_or_else(|| not_found("Domain association", &domain_name))?;
            authorize(ctx, "UpdateDomainAssociation", &d.domain.domain_association_arn, ConditionContext::new())?;
            check_certificate(input.certificate_settings.as_ref())?;
            if let Some(settings) = &input.sub_domain_settings {
                for s in settings {
                    branch(rec, &s.branch_name)?;
                }
            }
            let d = rec.domains.get_mut(&domain_name).expect("domain exists");
            if let Some(v) = input.enable_auto_sub_domain {
                d.domain.enable_auto_sub_domain = v;
            }
            if let Some(v) = input.auto_sub_domain_creation_patterns {
                d.domain.auto_sub_domain_creation_patterns = Some(v);
            }
            if let Some(v) = input.auto_sub_domain_iam_role {
                d.domain.auto_sub_domain_iam_role = Some(v);
            }
            if let Some(settings) = input.sub_domain_settings {
                let distribution = d.distribution.clone();
                d.domain.sub_domains = settings.into_iter().map(|s| sub_domain(s, &distribution)).collect();
            }
            if let Some(c) = input.certificate_settings {
                let cert = certificate(Some(c), d);
                d.domain.certificate_verification_dns_record = cert.certificate_verification_dns_record.clone();
                d.domain.certificate = Some(cert);
            }
            d.domain.domain_status = "UPDATING".into();
            d.domain.update_status = Some("PENDING_DEPLOYMENT".into());
            let record = d.clone();
            sync_branch_domains(rec);
            record
        };
        self.write_dns_records(ctx, &record).await;
        Ok(types::UpdateDomainAssociationResult { domain_association: record.domain })
    }

    pub(crate) async fn delete_domain_association(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDomainAssociationRequest,
    ) -> Result<types::DeleteDomainAssociationResult, ServiceError> {
        let domain_name = normalize(&input.domain_name);
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        let d = rec.domains.get(&domain_name).ok_or_else(|| not_found("Domain association", &domain_name))?;
        authorize(ctx, "DeleteDomainAssociation", &d.domain.domain_association_arn, ConditionContext::new())?;
        let removed = rec.domains.remove(&domain_name).expect("domain exists");
        sync_branch_domains(rec);
        Ok(types::DeleteDomainAssociationResult { domain_association: removed.domain })
    }

    /// The app, branch and domain a request's host names, for custom
    /// domains.
    pub(crate) fn custom_domain_target(&self, host: &str) -> Option<(String, String)> {
        let host = normalize(host);
        let st = self.read();
        for (app_id, rec) in &st.apps {
            for d in rec.domains.values() {
                for s in &d.domain.sub_domains {
                    if fqdn(&s.sub_domain_setting.prefix, &d.domain.domain_name) == host {
                        return Some((app_id.clone(), s.sub_domain_setting.branch_name.clone()));
                    }
                }
            }
        }
        None
    }
}

/// Whether `domain` is one of the app's domains (its default domain or an
/// associated one), for `GenerateAccessLogs`.
pub(crate) fn app_has_domain(rec: &AppRecord, domain: &str) -> bool {
    let domain = normalize(domain);
    domain == rec.app.default_domain || rec.domains.contains_key(&domain)
}
