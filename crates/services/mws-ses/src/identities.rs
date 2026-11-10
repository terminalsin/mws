//! Identities: email addresses and domains, how they get verified (a link
//! mailed to the address; `_amazonses` TXT or DKIM CNAME records in a
//! Route 53 public hosted zone for domains), DKIM, custom MAIL FROM
//! domains, notification topics and sending authorization policies.

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::names::{self, authorize, region, region_ref};
use crate::outbox::{self, OutboxMessage};
use crate::state::{Identity, Region, State, VerificationLink};
use crate::v1::types as t1;
use crate::v2::types as t2;
use crate::{v1, v2, Ses};

const MAX_IDENTITIES: usize = 10_000;
const MAX_POLICIES: usize = 20;
/// Domains have 72 hours to publish their records.
const DOMAIN_WINDOW_HOURS: i64 = 72;
/// Verification links work for 24 hours.
const LINK_WINDOW_HOURS: i64 = 24;

/// v2 wording of a v1 verification status.
pub fn v2_status(s: &str) -> String {
    match s {
        "Success" => "SUCCESS",
        "Failed" => "FAILED",
        "TemporaryFailure" => "TEMPORARY_FAILURE",
        "NotStarted" => "NOT_STARTED",
        _ => "PENDING",
    }
    .into()
}

/// v1 wording of a v2 DKIM status.
fn v1_dkim_status(s: &str) -> String {
    match s {
        "SUCCESS" => "Success",
        "FAILED" => "Failed",
        "TEMPORARY_FAILURE" => "TemporaryFailure",
        "NOT_STARTED" => "NotStarted",
        _ => "Pending",
    }
    .into()
}

/// The verified identity that lets `address` send: the address itself,
/// or its domain or a parent domain.
pub fn sending_identity<'a>(r: &'a Region, address: &str) -> Option<&'a Identity> {
    let addr = names::canonical_identity(&names::bare_address(address));
    if let Some(i) = r.identities.get(&addr).filter(|i| i.verified()) {
        return Some(i);
    }
    let domain = names::domain_of(&addr)?;
    domain_identity(r, &domain).filter(|i| i.verified())
}

/// The domain identity for `domain` or its closest verified parent.
pub fn domain_identity<'a>(r: &'a Region, domain: &str) -> Option<&'a Identity> {
    let mut d = domain.to_ascii_lowercase();
    loop {
        if let Some(i) = r.identities.get(&d).filter(|i| i.is_domain() && i.verified()) {
            return Some(i);
        }
        match d.split_once('.') {
            Some((_, parent)) if parent.contains('.') => d = parent.to_string(),
            _ => return None,
        }
    }
}

/// Display name of a Region in SES's verification emails.
fn region_display(region: &str) -> String {
    let name = match region {
        "us-east-1" => "US East (N. Virginia)",
        "us-east-2" => "US East (Ohio)",
        "us-west-1" => "US West (N. California)",
        "us-west-2" => "US West (Oregon)",
        "eu-west-1" => "Europe (Ireland)",
        "eu-west-2" => "Europe (London)",
        "eu-central-1" => "Europe (Frankfurt)",
        "ap-southeast-1" => "Asia Pacific (Singapore)",
        "ap-southeast-2" => "Asia Pacific (Sydney)",
        "ap-northeast-1" => "Asia Pacific (Tokyo)",
        other => other,
    };
    name.to_string()
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.').eq_ignore_ascii_case(b.trim_end_matches('.'))
}

impl Ses {
    /// Bring pending identities up to date with DNS and the clock.
    pub(crate) fn refresh_identities(&self, r: &mut Region, ctx: &RequestContext) {
        let links = self.links();
        let now = ctx.received_at;
        crate::account::settle_review(r, now);
        let region_name = ctx.region.clone();
        for i in r.identities.values_mut() {
            if self.inner.auto_verify {
                if !i.verified() {
                    i.verification_status = "Success".into();
                    i.last_success = Some(now);
                }
                if i.is_domain() && i.dkim_status == "PENDING" {
                    i.dkim_status = "SUCCESS".into();
                }
                if i.mail_from_domain.is_some() && i.mail_from_status == "Pending" {
                    i.mail_from_status = "Success".into();
                }
                continue;
            }
            if !i.is_domain() {
                if i.verification_status == "Pending"
                    && now - i.verification_started > Duration::hours(LINK_WINDOW_HOURS)
                {
                    i.verification_status = "Failed".into();
                }
                continue;
            }
            let domain = i.name.clone();
            let txt_ok = || {
                i.verification_token.as_ref().is_some_and(|token| {
                    links.dns(&format!("_amazonses.{domain}"), "TXT").iter().any(|v| v.trim_matches('"') == token)
                })
            };
            let dkim_ok = match i.dkim_origin.as_str() {
                "EXTERNAL" => i.dkim_selector.as_ref().is_some_and(|sel| {
                    links.dns(&format!("{sel}._domainkey.{domain}"), "TXT").iter().any(|v| v.contains("p="))
                }),
                _ => {
                    !i.dkim_tokens.is_empty()
                        && i.dkim_tokens.iter().all(|t| {
                            links
                                .dns(&format!("{t}._domainkey.{domain}"), "CNAME")
                                .iter()
                                .any(|v| same_name(v, &format!("{t}.dkim.amazonses.com")))
                        })
                }
            };
            i.last_checked = Some(now);
            let expired = now - i.verification_started > Duration::hours(DOMAIN_WINDOW_HOURS);
            if i.dkim_status == "PENDING" || i.dkim_status == "FAILED" {
                if dkim_ok {
                    i.dkim_status = "SUCCESS".into();
                } else if expired {
                    i.dkim_status = "FAILED".into();
                }
            }
            if !i.verified() {
                if (txt_ok)() || i.dkim_status == "SUCCESS" {
                    i.verification_status = "Success".into();
                    i.last_success = Some(now);
                } else if expired {
                    i.verification_status = "Failed".into();
                }
            }
            if let Some(mf) = i.mail_from_domain.clone() {
                if i.mail_from_status != "Success" {
                    let target = format!("feedback-smtp.{region_name}.amazonses.com");
                    let mx = links.dns(&mf, "MX");
                    if mx.iter().any(|v| same_name(v.split_whitespace().last().unwrap_or(""), &target)) {
                        i.mail_from_status = "Success".into();
                    } else if expired {
                        i.mail_from_status = "Failed".into();
                    }
                }
            }
        }
    }

    /// The caller's Region state, refreshed.
    pub(crate) fn with_region<T>(&self, ctx: &RequestContext, f: impl FnOnce(&mut Region) -> T) -> T {
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        self.refresh_identities(r, ctx);
        f(r)
    }

    /// Mail the verification link for an email identity.
    fn mail_verification_link(
        st: &mut State,
        ctx: &RequestContext,
        address: &str,
        template: Option<(&crate::state::CustomVerificationTemplate, &str)>,
    ) {
        let token = uuid::Uuid::new_v4().simple().to_string();
        st.verification_links.insert(
            token.clone(),
            VerificationLink {
                account: ctx.caller.account_id.clone(),
                region: ctx.region.clone(),
                identity: address.to_string(),
                template: template.map(|(t, _)| t.name.clone()),
            },
        );
        let endpoint = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
        let link = format!("{endpoint}{}verify/{token}", outbox::PREFIX);
        let (from, subject, text, html, kind) = match template {
            Some((t, message_id)) => {
                let _ = message_id;
                let html = format!("{}<p><a href=\"{link}\">{link}</a></p>", t.content);
                (t.from.clone(), t.subject.clone(), None, Some(html), "CustomVerificationEmail")
            }
            None => {
                let region = region_display(&ctx.region);
                let text = format!(
                    "Dear Amazon Web Services Customer,\r\n\r\nWe have received a request to authorize this email address for use with Amazon SES and Amazon Pinpoint in region {region}. If you requested this verification, please go to the following URL to confirm that you are authorized to use this email address:\r\n\r\n{link}\r\n\r\nYour request will not be processed unless you confirm the address using this URL. This link expires 24 hours after your original verification request.\r\n\r\nIf you did NOT request to verify this email address, do not click on the link.\r\n\r\nSincerely,\r\n\r\nThe Amazon Web Services Team\r\n"
                );
                (
                    "no-reply-aws@amazon.com".to_string(),
                    format!("Amazon Web Services \u{2013} Email Address Verification Request in region {region}"),
                    Some(text),
                    None,
                    "VerificationEmail",
                )
            }
        };
        let message_id = names::message_id(ctx);
        let raw = crate::mime::compose(
            ctx,
            &crate::mime::Compose {
                message_id: &message_id,
                from: &from,
                to: &[address.to_string()],
                subject: &subject,
                text: text.as_deref(),
                html: html.as_deref(),
                ..Default::default()
            },
        );
        outbox::push(
            st,
            OutboxMessage {
                id: message_id,
                region: ctx.region.clone(),
                account_id: ctx.caller.account_id.clone(),
                source: from,
                destination: outbox::Destination { to_addresses: vec![address.to_string()], ..Default::default() },
                subject,
                body: outbox::Body { text_part: text, html_part: html },
                raw_data: raw,
                timestamp: names::iso(ctx.received_at),
                kind: kind.into(),
                verification_link: Some(link),
                ..Default::default()
            },
        );
    }

    /// Start verifying an email address identity (creating it if new).
    fn start_email_identity(
        &self,
        ctx: &RequestContext,
        address: &str,
        legacy: bool,
        custom: Option<&crate::state::CustomVerificationTemplate>,
    ) -> Result<(), ServiceError> {
        let mut st = self.lock();
        let key = names::canonical_identity(address);
        let auto = self.inner.auto_verify;
        let r = region(&mut st, ctx);
        if r.identities.len() >= MAX_IDENTITIES && !r.identities.contains_key(&key) {
            return Err(v1::errors::limit_exceeded("Maximum number of identities reached."));
        }
        let i = r.identities.entry(key.clone()).or_insert_with(|| Identity {
            name: key.clone(),
            kind: "EMAIL_ADDRESS".into(),
            created: ctx.received_at,
            verification_started: ctx.received_at,
            legacy,
            ..Default::default()
        });
        if i.verified() {
            return Ok(());
        }
        i.verification_status = "Pending".into();
        i.verification_started = ctx.received_at;
        if auto {
            i.verification_status = "Success".into();
            i.last_success = Some(ctx.received_at);
        }
        let message_id = names::message_id(ctx);
        Self::mail_verification_link(&mut st, ctx, &key, custom.map(|t| (t, message_id.as_str())));
        Ok(())
    }

    /// Start verifying a domain identity; returns its TXT token.
    fn start_domain_identity(&self, ctx: &RequestContext, domain: &str) -> Result<String, ServiceError> {
        let key = names::canonical_identity(domain);
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        if r.identities.len() >= MAX_IDENTITIES && !r.identities.contains_key(&key) {
            return Err(v1::errors::limit_exceeded("Maximum number of identities reached."));
        }
        let i = r.identities.entry(key.clone()).or_insert_with(|| Identity {
            name: key.clone(),
            kind: "DOMAIN".into(),
            created: ctx.received_at,
            verification_started: ctx.received_at,
            ..Default::default()
        });
        let token = i.verification_token.get_or_insert_with(names::verification_token).clone();
        if !i.verified() && i.verification_status != "Pending" {
            i.verification_status = "Pending".into();
            i.verification_started = ctx.received_at;
        }
        self.refresh_identities(r, ctx);
        Ok(token)
    }

    /// Easy DKIM tokens for a domain (made once).
    fn ensure_dkim(i: &mut Identity, ctx: &RequestContext) {
        if i.dkim_tokens.is_empty() || i.dkim_origin != "AWS_SES" {
            i.dkim_tokens = (0..3).map(|_| names::token(32)).collect();
            i.dkim_origin = "AWS_SES".into();
            i.dkim_key_generated = Some(ctx.received_at);
        }
        i.dkim_enabled = true;
        if i.dkim_status != "SUCCESS" {
            i.dkim_status = "PENDING".into();
            if i.verification_status != "Success" {
                i.verification_started = ctx.received_at;
            }
        }
    }

    /// Handle a click on a verification link.
    pub(crate) fn follow_verification_link(&self, token: &str) -> Option<Result<Option<String>, Option<String>>> {
        let mut st = self.lock();
        let link = st.verification_links.get(token)?.clone();
        let key = crate::state::region_key(&link.account, &link.region);
        let template = link
            .template
            .as_ref()
            .and_then(|t| st.regions.get(&key).and_then(|r| r.custom_verification_templates.get(t)).cloned());
        let r = st.regions.entry(key).or_default();
        let now = Utc::now();
        match r.identities.get_mut(&link.identity) {
            Some(i) if i.verification_status != "Failed" => {
                i.verification_status = "Success".into();
                i.last_success = Some(now);
                st.verification_links.remove(token);
                Some(Ok(template.map(|t| t.success_url)))
            }
            _ => Some(Err(template.map(|t| t.failure_url))),
        }
    }

    fn identity_names(&self, ctx: &RequestContext, ids: &[String]) -> Vec<(String, Identity)> {
        self.with_region(ctx, |r| {
            ids.iter()
                .filter_map(|id| {
                    let key = names::canonical_identity(id);
                    r.identities.get(&key).map(|i| (id.clone(), i.clone()))
                })
                .collect()
        })
    }

    fn update_identity<T>(
        &self,
        ctx: &RequestContext,
        name: &str,
        f: impl FnOnce(&mut Identity) -> Result<T, ServiceError>,
    ) -> Option<Result<T, ServiceError>> {
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        self.refresh_identities(r, ctx);
        r.identities.get_mut(&names::canonical_identity(name)).map(f)
    }

    // ------------------------------------------------------------ v1

    pub(crate) fn verify_email_identity_v1(
        &self,
        ctx: &RequestContext,
        input: t1::VerifyEmailIdentityRequest,
    ) -> Result<t1::VerifyEmailIdentityResponse, ServiceError> {
        authorize(ctx, "1", "VerifyEmailIdentity", &names::identity_arn(ctx, &input.email_address))?;
        names::check_address(&input.email_address)
            .map_err(|_| names::invalid_parameter(format!("Invalid email address<{}>.", input.email_address)))?;
        self.start_email_identity(ctx, &names::bare_address(&input.email_address), false, None)?;
        Ok(Default::default())
    }

    pub(crate) fn verify_email_address_v1(
        &self,
        ctx: &RequestContext,
        input: t1::VerifyEmailAddressRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "VerifyEmailAddress", "*")?;
        names::check_address(&input.email_address)
            .map_err(|_| names::invalid_parameter(format!("Invalid email address<{}>.", input.email_address)))?;
        self.start_email_identity(ctx, &names::bare_address(&input.email_address), true, None)
    }

    pub(crate) fn verify_domain_identity_v1(
        &self,
        ctx: &RequestContext,
        input: t1::VerifyDomainIdentityRequest,
    ) -> Result<t1::VerifyDomainIdentityResponse, ServiceError> {
        authorize(ctx, "1", "VerifyDomainIdentity", &names::identity_arn(ctx, &input.domain))?;
        if !names::is_domain(input.domain.trim_end_matches('.')) {
            return Err(names::invalid_parameter(format!("Invalid domain name {}.", input.domain)));
        }
        let token = self.start_domain_identity(ctx, &input.domain)?;
        Ok(t1::VerifyDomainIdentityResponse { verification_token: token })
    }

    pub(crate) fn verify_domain_dkim_v1(
        &self,
        ctx: &RequestContext,
        input: t1::VerifyDomainDkimRequest,
    ) -> Result<t1::VerifyDomainDkimResponse, ServiceError> {
        authorize(ctx, "1", "VerifyDomainDkim", &names::identity_arn(ctx, &input.domain))?;
        if !names::is_domain(input.domain.trim_end_matches('.')) {
            return Err(names::invalid_parameter(format!("Invalid domain name {}.", input.domain)));
        }
        let key = names::canonical_identity(&input.domain);
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        let i = r.identities.entry(key.clone()).or_insert_with(|| Identity {
            name: key.clone(),
            kind: "DOMAIN".into(),
            created: ctx.received_at,
            verification_started: ctx.received_at,
            ..Default::default()
        });
        Self::ensure_dkim(i, ctx);
        let tokens = i.dkim_tokens.clone();
        self.refresh_identities(r, ctx);
        Ok(t1::VerifyDomainDkimResponse { dkim_tokens: tokens })
    }

    pub(crate) fn delete_identity_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteIdentityRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "DeleteIdentity", &names::identity_arn(ctx, &input.identity))?;
        region(&mut self.lock(), ctx).identities.remove(&names::canonical_identity(&input.identity));
        Ok(())
    }

    pub(crate) fn delete_verified_email_address_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteVerifiedEmailAddressRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "DeleteVerifiedEmailAddress", "*")?;
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        let key = names::canonical_identity(&input.email_address);
        if r.identities.get(&key).is_some_and(|i| !i.is_domain()) {
            r.identities.remove(&key);
        }
        Ok(())
    }

    pub(crate) fn list_identities_v1(
        &self,
        ctx: &RequestContext,
        input: t1::ListIdentitiesRequest,
    ) -> Result<t1::ListIdentitiesResponse, ServiceError> {
        authorize(ctx, "1", "ListIdentities", "*")?;
        let want = match input.identity_type.as_deref() {
            Some("EmailAddress") => Some(false),
            Some("Domain") => Some(true),
            Some(other) => return Err(names::invalid_parameter(format!("Invalid identity type {other}."))),
            None => None,
        };
        let all: Vec<String> = self.with_region(ctx, |r| {
            r.identities.values().filter(|i| want.is_none_or(|d| i.is_domain() == d)).map(|i| i.name.clone()).collect()
        });
        if input.max_items.is_some_and(|m| m > 1000) {
            return Err(names::invalid_parameter("MaxItems must be at most 1000."));
        }
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.max_items, 1000);
        Ok(t1::ListIdentitiesResponse { identities: page, next_token: next })
    }

    pub(crate) fn list_verified_email_addresses_v1(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<t1::ListVerifiedEmailAddressesResponse, ServiceError> {
        authorize(ctx, "1", "ListVerifiedEmailAddresses", "*")?;
        let all = self.with_region(ctx, |r| {
            r.identities.values().filter(|i| !i.is_domain() && i.verified()).map(|i| i.name.clone()).collect()
        });
        Ok(t1::ListVerifiedEmailAddressesResponse { verified_email_addresses: Some(all) })
    }

    pub(crate) fn get_identity_verification_attributes_v1(
        &self,
        ctx: &RequestContext,
        input: t1::GetIdentityVerificationAttributesRequest,
    ) -> Result<t1::GetIdentityVerificationAttributesResponse, ServiceError> {
        authorize(ctx, "1", "GetIdentityVerificationAttributes", "*")?;
        if input.identities.len() > 100 {
            return Err(names::invalid_parameter("Too many identities. The maximum is 100."));
        }
        let attrs = self
            .identity_names(ctx, &input.identities)
            .into_iter()
            .map(|(name, i)| {
                let a = t1::IdentityVerificationAttributes {
                    verification_status: i.verification_status.clone(),
                    verification_token: if i.is_domain() { i.verification_token.clone() } else { None },
                };
                (name, a)
            })
            .collect();
        Ok(t1::GetIdentityVerificationAttributesResponse { verification_attributes: attrs })
    }

    pub(crate) fn get_identity_dkim_attributes_v1(
        &self,
        ctx: &RequestContext,
        input: t1::GetIdentityDkimAttributesRequest,
    ) -> Result<t1::GetIdentityDkimAttributesResponse, ServiceError> {
        authorize(ctx, "1", "GetIdentityDkimAttributes", "*")?;
        if input.identities.len() > 100 {
            return Err(names::invalid_parameter("Too many identities. The maximum is 100."));
        }
        let attrs = self.with_region(ctx, |r| {
            input
                .identities
                .iter()
                .filter_map(|id| {
                    let i = r.identities.get(&names::canonical_identity(id))?;
                    let a = if i.is_domain() {
                        t1::IdentityDkimAttributes {
                            dkim_enabled: i.dkim_enabled,
                            dkim_verification_status: v1_dkim_status(&i.dkim_status),
                            dkim_tokens: (!i.dkim_tokens.is_empty() && i.dkim_origin == "AWS_SES")
                                .then(|| i.dkim_tokens.clone()),
                        }
                    } else {
                        let domain = names::domain_of(&i.name).and_then(|d| r.identities.get(&d));
                        t1::IdentityDkimAttributes {
                            dkim_enabled: i.dkim_enabled || domain.is_some_and(|d| d.dkim_enabled),
                            dkim_verification_status: domain
                                .map(|d| v1_dkim_status(&d.dkim_status))
                                .unwrap_or_else(|| "NotStarted".into()),
                            dkim_tokens: None,
                        }
                    };
                    Some((id.clone(), a))
                })
                .collect()
        });
        Ok(t1::GetIdentityDkimAttributesResponse { dkim_attributes: attrs })
    }

    pub(crate) fn set_identity_dkim_enabled_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SetIdentityDkimEnabledRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "SetIdentityDkimEnabled", &names::identity_arn(ctx, &input.identity))?;
        let enable = input.dkim_enabled;
        self.update_identity(ctx, &input.identity, |i| {
            if enable && i.is_domain() && i.dkim_status != "SUCCESS" {
                return Err(names::invalid_parameter(format!("Domain {} is not verified for DKIM signing.", i.name)));
            }
            i.dkim_enabled = enable;
            Ok(())
        })
        .unwrap_or_else(|| Err(names::invalid_parameter(format!("Identity {} is invalid.", input.identity))))
    }

    pub(crate) fn get_identity_mail_from_domain_attributes_v1(
        &self,
        ctx: &RequestContext,
        input: t1::GetIdentityMailFromDomainAttributesRequest,
    ) -> Result<t1::GetIdentityMailFromDomainAttributesResponse, ServiceError> {
        authorize(ctx, "1", "GetIdentityMailFromDomainAttributes", "*")?;
        let attrs = self
            .identity_names(ctx, &input.identities)
            .into_iter()
            .map(|(name, i)| {
                let a = t1::IdentityMailFromDomainAttributes {
                    mail_from_domain: i.mail_from_domain.clone().unwrap_or_default(),
                    mail_from_domain_status: i.mail_from_status.clone(),
                    behavior_on_mx_failure: i.behavior_on_mx_failure.clone(),
                };
                (name, a)
            })
            .collect();
        Ok(t1::GetIdentityMailFromDomainAttributesResponse { mail_from_domain_attributes: attrs })
    }

    fn set_mail_from(
        &self,
        ctx: &RequestContext,
        identity: &str,
        domain: Option<String>,
        behavior: Option<String>,
        bad: fn(String) -> ServiceError,
        missing: impl FnOnce() -> ServiceError,
    ) -> Result<(), ServiceError> {
        self.update_identity(ctx, identity, |i| {
            let base = if i.is_domain() { i.name.clone() } else { names::domain_of(&i.name).unwrap_or_default() };
            match domain.as_deref().filter(|d| !d.is_empty()) {
                Some(d) => {
                    let d = d.trim_end_matches('.').to_ascii_lowercase();
                    if !d.ends_with(&format!(".{base}")) {
                        return Err(bad(format!(
                            "Provided MAIL-FROM domain '{d}' is not subdomain of the domain of the identity '{}'.",
                            i.name
                        )));
                    }
                    if i.mail_from_domain.as_deref() != Some(d.as_str()) {
                        i.mail_from_status = "Pending".into();
                        i.verification_started = i.verification_started.max(ctx.received_at - Duration::hours(1));
                    }
                    i.mail_from_domain = Some(d);
                }
                None => {
                    i.mail_from_domain = None;
                    i.mail_from_status = "Pending".into();
                }
            }
            if let Some(b) = behavior {
                i.behavior_on_mx_failure = b;
            }
            Ok(())
        })
        .unwrap_or_else(|| Err(missing()))
    }

    pub(crate) fn set_identity_mail_from_domain_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SetIdentityMailFromDomainRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "SetIdentityMailFromDomain", &names::identity_arn(ctx, &input.identity))?;
        let identity = input.identity.clone();
        self.set_mail_from(
            ctx,
            &input.identity,
            input.mail_from_domain,
            input.behavior_on_mx_failure,
            names::invalid_parameter,
            || names::invalid_parameter(format!("Identity {identity} is invalid.")),
        )
    }

    pub(crate) fn get_identity_notification_attributes_v1(
        &self,
        ctx: &RequestContext,
        input: t1::GetIdentityNotificationAttributesRequest,
    ) -> Result<t1::GetIdentityNotificationAttributesResponse, ServiceError> {
        authorize(ctx, "1", "GetIdentityNotificationAttributes", "*")?;
        let attrs = self
            .identity_names(ctx, &input.identities)
            .into_iter()
            .map(|(name, i)| {
                let a = t1::IdentityNotificationAttributes {
                    bounce_topic: i.bounce_topic.clone().unwrap_or_default(),
                    complaint_topic: i.complaint_topic.clone().unwrap_or_default(),
                    delivery_topic: i.delivery_topic.clone().unwrap_or_default(),
                    forwarding_enabled: i.feedback_forwarding,
                    headers_in_bounce_notifications_enabled: i.headers_in_bounce,
                    headers_in_complaint_notifications_enabled: i.headers_in_complaint,
                    headers_in_delivery_notifications_enabled: i.headers_in_delivery,
                };
                (name, a)
            })
            .collect();
        Ok(t1::GetIdentityNotificationAttributesResponse { notification_attributes: attrs })
    }

    pub(crate) fn set_identity_notification_topic_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SetIdentityNotificationTopicRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "SetIdentityNotificationTopic", &names::identity_arn(ctx, &input.identity))?;
        let kind = input.notification_type.clone();
        if !matches!(kind.as_str(), "Bounce" | "Complaint" | "Delivery") {
            return Err(names::invalid_parameter(format!("Invalid notification type {kind}.")));
        }
        let topic = input.sns_topic.filter(|t| !t.is_empty());
        if let Some(t) = &topic {
            let arn = names::identity_arn(ctx, &input.identity);
            self.links()
                .check_sns(ctx, t, &ctx.caller.account_id, &arn)
                .map_err(|_| names::invalid_parameter(format!("Invalid SNS topic <{t}>.")))?;
        }
        let identity = input.identity.clone();
        self.update_identity(ctx, &input.identity, |i| {
            match kind.as_str() {
                "Bounce" => i.bounce_topic = topic,
                "Complaint" => i.complaint_topic = topic,
                _ => i.delivery_topic = topic,
            }
            if i.bounce_topic.is_none() || i.complaint_topic.is_none() {
                i.feedback_forwarding = true;
            }
            Ok(())
        })
        .unwrap_or_else(|| Err(names::invalid_parameter(format!("Identity <{identity}> does not exist."))))
    }

    pub(crate) fn set_identity_feedback_forwarding_enabled_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SetIdentityFeedbackForwardingEnabledRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "SetIdentityFeedbackForwardingEnabled", &names::identity_arn(ctx, &input.identity))?;
        let enabled = input.forwarding_enabled;
        let identity = input.identity.clone();
        self.update_identity(ctx, &input.identity, |i| {
            if !enabled && (i.bounce_topic.is_none() || i.complaint_topic.is_none()) {
                return Err(names::invalid_parameter(
                    "Feedback forwarding cannot be disabled until you set a bounce and a complaint topic.",
                ));
            }
            i.feedback_forwarding = enabled;
            Ok(())
        })
        .unwrap_or_else(|| Err(names::invalid_parameter(format!("Identity <{identity}> does not exist."))))
    }

    pub(crate) fn set_identity_headers_in_notifications_enabled_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SetIdentityHeadersInNotificationsEnabledRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "SetIdentityHeadersInNotificationsEnabled", &names::identity_arn(ctx, &input.identity))?;
        let kind = input.notification_type.clone();
        let enabled = input.enabled;
        let identity = input.identity.clone();
        self.update_identity(ctx, &input.identity, |i| {
            match kind.as_str() {
                "Bounce" => i.headers_in_bounce = enabled,
                "Complaint" => i.headers_in_complaint = enabled,
                "Delivery" => i.headers_in_delivery = enabled,
                other => return Err(names::invalid_parameter(format!("Invalid notification type {other}."))),
            }
            Ok(())
        })
        .unwrap_or_else(|| Err(names::invalid_parameter(format!("Identity <{identity}> does not exist."))))
    }

    fn check_policy(policy: &str) -> Result<(), String> {
        let v: serde_json::Value = serde_json::from_str(policy).map_err(|_| "Policy is not valid JSON.".to_string())?;
        if v.get("Statement").is_none() {
            return Err("Policy has no statements.".into());
        }
        mws_iam_policy::Policy::parse(policy, mws_iam_policy::PolicyKind::Resource).map_err(|e| e.to_string())?;
        if policy.len() > 4096 {
            return Err("Policy exceeds the maximum size of 4 KB.".into());
        }
        Ok(())
    }

    pub(crate) fn put_identity_policy_v1(
        &self,
        ctx: &RequestContext,
        input: t1::PutIdentityPolicyRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "PutIdentityPolicy", &names::identity_arn(ctx, &input.identity))?;
        Self::check_policy(&input.policy).map_err(v1::errors::invalid_policy)?;
        let identity = input.identity.clone();
        self.update_identity(ctx, &input.identity, |i| {
            if !i.policies.contains_key(&input.policy_name) && i.policies.len() >= MAX_POLICIES {
                return Err(names::invalid_parameter("Maximum number of policies reached."));
            }
            i.policies.insert(input.policy_name, input.policy);
            Ok(())
        })
        .unwrap_or_else(|| Err(names::invalid_parameter(format!("Identity <{identity}> does not exist."))))
    }

    pub(crate) fn delete_identity_policy_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteIdentityPolicyRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "DeleteIdentityPolicy", &names::identity_arn(ctx, &input.identity))?;
        self.update_identity(ctx, &input.identity, |i| {
            i.policies.remove(&input.policy_name);
            Ok(())
        })
        .unwrap_or(Ok(()))
    }

    pub(crate) fn get_identity_policies_v1(
        &self,
        ctx: &RequestContext,
        input: t1::GetIdentityPoliciesRequest,
    ) -> Result<t1::GetIdentityPoliciesResponse, ServiceError> {
        authorize(ctx, "1", "GetIdentityPolicies", &names::identity_arn(ctx, &input.identity))?;
        if input.policy_names.len() > 20 {
            return Err(names::invalid_parameter("Too many policy names. The maximum is 20."));
        }
        let policies = self.with_region(ctx, |r| {
            r.identities
                .get(&names::canonical_identity(&input.identity))
                .map(|i| {
                    input
                        .policy_names
                        .iter()
                        .filter_map(|n| i.policies.get(n).map(|p| (n.clone(), p.clone())))
                        .collect()
                })
                .unwrap_or_default()
        });
        Ok(t1::GetIdentityPoliciesResponse { policies })
    }

    pub(crate) fn list_identity_policies_v1(
        &self,
        ctx: &RequestContext,
        input: t1::ListIdentityPoliciesRequest,
    ) -> Result<t1::ListIdentityPoliciesResponse, ServiceError> {
        authorize(ctx, "1", "ListIdentityPolicies", &names::identity_arn(ctx, &input.identity))?;
        let names_list = self.with_region(ctx, |r| {
            r.identities
                .get(&names::canonical_identity(&input.identity))
                .map(|i| i.policies.keys().cloned().collect())
                .unwrap_or_default()
        });
        Ok(t1::ListIdentityPoliciesResponse { policy_names: names_list })
    }

    pub(crate) fn send_custom_verification_email_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SendCustomVerificationEmailRequest,
    ) -> Result<t1::SendCustomVerificationEmailResponse, ServiceError> {
        authorize(ctx, "1", "SendCustomVerificationEmail", "*")?;
        if let Some(cs) = &input.configuration_set_name {
            if self.configuration_set(ctx, cs).is_none() {
                return Err(v1::errors::configuration_set_does_not_exist(format!(
                    "Configuration set <{cs}> does not exist."
                )));
            }
        }
        let t = self.custom_template_for_send(ctx, &input.template_name).ok_or_else(|| {
            v1::errors::custom_verification_email_template_does_not_exist(format!(
                "Custom verification email template {} does not exist.",
                input.template_name
            ))
        })?;
        if !self.is_verified_sender(ctx, &t.from) {
            return Err(v1::errors::from_email_address_not_verified(format!(
                "Email address {} is not verified.",
                t.from
            )));
        }
        names::check_address(&input.email_address)
            .map_err(|_| names::invalid_parameter(format!("Invalid email address<{}>.", input.email_address)))?;
        self.start_email_identity(ctx, &names::bare_address(&input.email_address), false, Some(&t))?;
        let id = self.lock().outbox.last().map(|m| m.id.clone());
        Ok(t1::SendCustomVerificationEmailResponse { message_id: id })
    }

    // ------------------------------------------------------------ v2

    fn dkim_attributes(i: &Identity, r: &Region) -> t2::DkimAttributes {
        if i.is_domain() {
            t2::DkimAttributes {
                signing_enabled: i.dkim_enabled,
                status: Some(i.dkim_status.clone()),
                tokens: (i.dkim_origin != "EXTERNAL" && !i.dkim_tokens.is_empty()).then(|| i.dkim_tokens.clone()),
                signing_hosted_zone: None,
                signing_attributes_origin: Some(i.dkim_origin.clone()),
                next_signing_key_length: (i.dkim_origin == "AWS_SES").then(|| i.dkim_next_key_length.clone()),
                current_signing_key_length: (i.dkim_origin == "AWS_SES").then(|| i.dkim_key_length.clone()),
                last_key_generation_timestamp: i.dkim_key_generated,
            }
        } else {
            let domain = names::domain_of(&i.name).and_then(|d| r.identities.get(&d));
            t2::DkimAttributes {
                signing_enabled: domain.is_some_and(|d| d.dkim_enabled) || i.dkim_enabled,
                status: Some(domain.map(|d| d.dkim_status.clone()).unwrap_or_else(|| "NOT_STARTED".into())),
                signing_attributes_origin: Some("AWS_SES".into()),
                ..Default::default()
            }
        }
    }

    fn sending_verified(i: &Identity, r: &Region) -> bool {
        i.verified() || (!i.is_domain() && names::domain_of(&i.name).is_some_and(|d| domain_identity(r, &d).is_some()))
    }

    pub(crate) fn create_email_identity_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateEmailIdentityRequest,
    ) -> Result<t2::CreateEmailIdentityResponse, ServiceError> {
        let tags = names::tags_pairs(input.tags.as_deref());
        names::authorize_create(ctx, "CreateEmailIdentity", &names::identity_arn(ctx, &input.email_identity), &tags)?;
        names::check_tags(&tags)?;
        let name = input.email_identity.trim().to_string();
        let is_email = name.contains('@');
        if is_email {
            names::check_address(&name).map_err(|m| v2::errors::bad_request(format!("Invalid email address: {m}")))?;
        } else if !names::is_domain(name.trim_end_matches('.')) {
            return Err(v2::errors::bad_request(format!("Invalid domain name: {name}")));
        }
        if let Some(cs) = &input.configuration_set_name {
            if self.configuration_set(ctx, cs).is_none() {
                return Err(v2::errors::not_found(format!("Configuration set <{cs}> does not exist.")));
            }
        }
        let key = names::canonical_identity(&name);
        if self.with_region(ctx, |r| r.identities.contains_key(&key)) {
            return Err(v2::errors::already_exists(format!("Email identity {name} already exist.")));
        }
        if is_email {
            if input.dkim_signing_attributes.is_some() {
                return Err(v2::errors::bad_request(
                    "DKIM signing attributes are only supported for domain identities.",
                ));
            }
            self.start_email_identity(ctx, &key, false, None)?;
        } else {
            let mut st = self.lock();
            let r = region(&mut st, ctx);
            if r.identities.len() >= MAX_IDENTITIES {
                return Err(v2::errors::limit_exceeded("Maximum number of identities reached."));
            }
            let mut i = Identity {
                name: key.clone(),
                kind: "DOMAIN".into(),
                created: ctx.received_at,
                verification_started: ctx.received_at,
                ..Default::default()
            };
            match &input.dkim_signing_attributes {
                Some(a) if a.domain_signing_private_key.is_some() || a.domain_signing_selector.is_some() => {
                    let (Some(sel), Some(_key)) = (&a.domain_signing_selector, &a.domain_signing_private_key) else {
                        return Err(v2::errors::bad_request(
                            "Both DomainSigningSelector and DomainSigningPrivateKey are required for BYODKIM.",
                        ));
                    };
                    i.dkim_origin = "EXTERNAL".into();
                    i.dkim_selector = Some(sel.clone());
                    i.dkim_enabled = true;
                    i.dkim_status = "PENDING".into();
                }
                Some(a) => {
                    Self::ensure_dkim(&mut i, ctx);
                    if let Some(len) = &a.next_signing_key_length {
                        i.dkim_next_key_length = len.clone();
                        i.dkim_key_length = len.clone();
                    }
                    if let Some(o) = &a.domain_signing_attributes_origin {
                        i.dkim_origin = o.clone();
                    }
                }
                None => Self::ensure_dkim(&mut i, ctx),
            }
            r.identities.insert(key.clone(), i);
        }
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        self.refresh_identities(r, ctx);
        let i = r.identities.get_mut(&key).expect("identity just created");
        i.tags = tags.into_iter().collect();
        i.configuration_set = input.configuration_set_name;
        let i = i.clone();
        Ok(t2::CreateEmailIdentityResponse {
            identity_type: Some(if i.is_domain() { "DOMAIN".into() } else { "EMAIL_ADDRESS".into() }),
            verified_for_sending_status: Self::sending_verified(&i, r),
            dkim_attributes: Some(Self::dkim_attributes(&i, r)),
        })
    }

    fn identity_v2(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: &str,
    ) -> Result<(Identity, bool, t2::DkimAttributes), ServiceError> {
        let arn = names::identity_arn(ctx, name);
        let found = self.with_region(ctx, |r| {
            r.identities
                .get(&names::canonical_identity(name))
                .map(|i| (i.clone(), Self::sending_verified(i, r), Self::dkim_attributes(i, r)))
        });
        names::authorize_tagged(ctx, "2", action, &arn, &found.as_ref().map(|f| f.0.tags.clone()).unwrap_or_default())?;
        found.ok_or_else(|| v2::errors::not_found(format!("Email identity {name} does not exist.")))
    }

    pub(crate) fn get_email_identity_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetEmailIdentityRequest,
    ) -> Result<t2::GetEmailIdentityResponse, ServiceError> {
        let (i, verified, dkim) = self.identity_v2(ctx, "GetEmailIdentity", &input.email_identity)?;
        Ok(t2::GetEmailIdentityResponse {
            identity_type: Some(if i.is_domain() { "DOMAIN".into() } else { "EMAIL_ADDRESS".into() }),
            feedback_forwarding_status: i.feedback_forwarding,
            verified_for_sending_status: verified,
            dkim_attributes: Some(dkim),
            mail_from_attributes: Some(t2::MailFromAttributes {
                mail_from_domain: i.mail_from_domain.clone().unwrap_or_default(),
                mail_from_domain_status: match i.mail_from_status.as_str() {
                    "Success" => "SUCCESS",
                    "Failed" => "FAILED",
                    "TemporaryFailure" => "TEMPORARY_FAILURE",
                    _ => "PENDING",
                }
                .into(),
                behavior_on_mx_failure: match i.behavior_on_mx_failure.as_str() {
                    "RejectMessage" => "REJECT_MESSAGE",
                    _ => "USE_DEFAULT_VALUE",
                }
                .into(),
            }),
            policies: Some(i.policies.clone()),
            tags: Some(names::tag_list(&i.tags)),
            configuration_set_name: i.configuration_set.clone(),
            verification_status: Some(v2_status(&i.verification_status)),
            verification_info: Some(t2::VerificationInfo {
                last_checked_timestamp: i.last_checked,
                last_success_timestamp: i.last_success,
                error_type: (i.verification_status == "Failed").then(|| {
                    if i.is_domain() {
                        "DNS_SERVER_ERROR".to_string()
                    } else {
                        "HOST_NOT_FOUND".to_string()
                    }
                }),
                soa_record: None,
            }),
        })
    }

    pub(crate) fn delete_email_identity_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteEmailIdentityRequest,
    ) -> Result<t2::DeleteEmailIdentityResponse, ServiceError> {
        self.identity_v2(ctx, "DeleteEmailIdentity", &input.email_identity)?;
        region(&mut self.lock(), ctx).identities.remove(&names::canonical_identity(&input.email_identity));
        Ok(Default::default())
    }

    pub(crate) fn list_email_identities_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListEmailIdentitiesRequest,
    ) -> Result<t2::ListEmailIdentitiesResponse, ServiceError> {
        authorize(ctx, "2", "ListEmailIdentities", "*")?;
        names::check_token(input.next_token.as_deref())?;
        if input.page_size.is_some_and(|p| !(1..=1000).contains(&p)) {
            return Err(v2::errors::bad_request("PageSize must be between 1 and 1000."));
        }
        let all: Vec<t2::IdentityInfo> = self.with_region(ctx, |r| {
            r.identities
                .values()
                .map(|i| t2::IdentityInfo {
                    identity_type: Some(if i.is_domain() { "DOMAIN".into() } else { "EMAIL_ADDRESS".into() }),
                    identity_name: Some(i.name.clone()),
                    sending_enabled: Self::sending_verified(i, r),
                    verification_status: Some(v2_status(&i.verification_status)),
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListEmailIdentitiesResponse { email_identities: Some(page), next_token: next })
    }

    fn update_identity_v2<T>(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: &str,
        f: impl FnOnce(&mut Identity) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        self.identity_v2(ctx, action, name)?;
        self.update_identity(ctx, name, f)
            .unwrap_or_else(|| Err(v2::errors::not_found(format!("Email identity {name} does not exist."))))
    }

    pub(crate) fn create_email_identity_policy_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateEmailIdentityPolicyRequest,
    ) -> Result<t2::CreateEmailIdentityPolicyResponse, ServiceError> {
        Self::check_policy(&input.policy).map_err(v2::errors::bad_request)?;
        self.update_identity_v2(ctx, "CreateEmailIdentityPolicy", &input.email_identity, |i| {
            if i.policies.contains_key(&input.policy_name) {
                return Err(v2::errors::already_exists(format!("Policy {} already exists.", input.policy_name)));
            }
            if i.policies.len() >= MAX_POLICIES {
                return Err(v2::errors::limit_exceeded("Maximum number of policies reached."));
            }
            i.policies.insert(input.policy_name, input.policy);
            Ok(Default::default())
        })
    }

    pub(crate) fn update_email_identity_policy_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateEmailIdentityPolicyRequest,
    ) -> Result<t2::UpdateEmailIdentityPolicyResponse, ServiceError> {
        Self::check_policy(&input.policy).map_err(v2::errors::bad_request)?;
        self.update_identity_v2(ctx, "UpdateEmailIdentityPolicy", &input.email_identity, |i| {
            let Some(p) = i.policies.get_mut(&input.policy_name) else {
                return Err(v2::errors::not_found(format!("Policy {} does not exist.", input.policy_name)));
            };
            *p = input.policy;
            Ok(Default::default())
        })
    }

    pub(crate) fn delete_email_identity_policy_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteEmailIdentityPolicyRequest,
    ) -> Result<t2::DeleteEmailIdentityPolicyResponse, ServiceError> {
        self.update_identity_v2(ctx, "DeleteEmailIdentityPolicy", &input.email_identity, |i| {
            if i.policies.remove(&input.policy_name).is_none() {
                return Err(v2::errors::not_found(format!("Policy {} does not exist.", input.policy_name)));
            }
            Ok(Default::default())
        })
    }

    pub(crate) fn get_email_identity_policies_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetEmailIdentityPoliciesRequest,
    ) -> Result<t2::GetEmailIdentityPoliciesResponse, ServiceError> {
        let (i, _, _) = self.identity_v2(ctx, "GetEmailIdentityPolicies", &input.email_identity)?;
        Ok(t2::GetEmailIdentityPoliciesResponse { policies: Some(i.policies) })
    }

    pub(crate) fn put_email_identity_configuration_set_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutEmailIdentityConfigurationSetAttributesRequest,
    ) -> Result<t2::PutEmailIdentityConfigurationSetAttributesResponse, ServiceError> {
        if let Some(cs) = &input.configuration_set_name {
            if self.configuration_set(ctx, cs).is_none() {
                return Err(v2::errors::not_found(format!("Configuration set <{cs}> does not exist.")));
            }
        }
        self.update_identity_v2(ctx, "PutEmailIdentityConfigurationSetAttributes", &input.email_identity, |i| {
            i.configuration_set = input.configuration_set_name;
            Ok(Default::default())
        })
    }

    pub(crate) fn put_email_identity_dkim_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutEmailIdentityDkimAttributesRequest,
    ) -> Result<t2::PutEmailIdentityDkimAttributesResponse, ServiceError> {
        let enable = input.signing_enabled;
        self.update_identity_v2(ctx, "PutEmailIdentityDkimAttributes", &input.email_identity, |i| {
            if enable && i.is_domain() && i.dkim_status != "SUCCESS" {
                return Err(v2::errors::bad_request(format!("Domain {} is not verified for DKIM signing.", i.name)));
            }
            i.dkim_enabled = enable;
            Ok(Default::default())
        })
    }

    pub(crate) fn put_email_identity_dkim_signing_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutEmailIdentityDkimSigningAttributesRequest,
    ) -> Result<t2::PutEmailIdentityDkimSigningAttributesResponse, ServiceError> {
        let origin = input.signing_attributes_origin.clone();
        let attrs = input.signing_attributes.clone();
        let r = self.update_identity_v2(ctx, "PutEmailIdentityDkimSigningAttributes", &input.email_identity, |i| {
            if !i.is_domain() {
                return Err(v2::errors::bad_request(
                    "DKIM signing attributes are only supported for domain identities.",
                ));
            }
            match origin.as_str() {
                "EXTERNAL" => {
                    let a = attrs.unwrap_or_default();
                    let (Some(sel), Some(_)) = (a.domain_signing_selector, a.domain_signing_private_key) else {
                        return Err(v2::errors::bad_request(
                            "Both DomainSigningSelector and DomainSigningPrivateKey are required for BYODKIM.",
                        ));
                    };
                    i.dkim_origin = "EXTERNAL".into();
                    i.dkim_selector = Some(sel);
                    i.dkim_tokens.clear();
                    i.dkim_status = "PENDING".into();
                    i.dkim_enabled = true;
                }
                _ => {
                    let rotating = i.dkim_origin == "AWS_SES" && !i.dkim_tokens.is_empty();
                    if let Some(len) = attrs.and_then(|a| a.next_signing_key_length) {
                        i.dkim_next_key_length = len;
                    }
                    if !rotating {
                        Self::ensure_dkim(i, ctx);
                    } else {
                        i.dkim_key_length = i.dkim_next_key_length.clone();
                        i.dkim_key_generated = Some(ctx.received_at);
                    }
                    i.dkim_origin = origin.clone();
                }
            }
            Ok((i.dkim_status.clone(), i.dkim_tokens.clone()))
        })?;
        Ok(t2::PutEmailIdentityDkimSigningAttributesResponse {
            dkim_status: Some(r.0),
            dkim_tokens: (!r.1.is_empty()).then_some(r.1),
            signing_hosted_zone: None,
        })
    }

    pub(crate) fn put_email_identity_feedback_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutEmailIdentityFeedbackAttributesRequest,
    ) -> Result<t2::PutEmailIdentityFeedbackAttributesResponse, ServiceError> {
        let enabled = input.email_forwarding_enabled;
        self.update_identity_v2(ctx, "PutEmailIdentityFeedbackAttributes", &input.email_identity, |i| {
            if !enabled && (i.bounce_topic.is_none() || i.complaint_topic.is_none()) {
                return Err(v2::errors::bad_request(
                    "Feedback forwarding cannot be disabled until you set a bounce and a complaint topic.",
                ));
            }
            i.feedback_forwarding = enabled;
            Ok(Default::default())
        })
    }

    pub(crate) fn put_email_identity_mail_from_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutEmailIdentityMailFromAttributesRequest,
    ) -> Result<t2::PutEmailIdentityMailFromAttributesResponse, ServiceError> {
        self.identity_v2(ctx, "PutEmailIdentityMailFromAttributes", &input.email_identity)?;
        let behavior = input.behavior_on_mx_failure.map(|b| match b.as_str() {
            "REJECT_MESSAGE" => "RejectMessage".to_string(),
            _ => "UseDefaultValue".to_string(),
        });
        let identity = input.email_identity.clone();
        self.set_mail_from(
            ctx,
            &input.email_identity,
            input.mail_from_domain,
            behavior,
            v2::errors::bad_request,
            || v2::errors::not_found(format!("Email identity {identity} does not exist.")),
        )?;
        Ok(Default::default())
    }

    pub(crate) fn associate_email_identity_certificate_v2(
        &self,
        ctx: &RequestContext,
        input: t2::AssociateEmailIdentityCertificateRequest,
    ) -> Result<t2::AssociateEmailIdentityCertificateResponse, ServiceError> {
        let from = input.from_address.clone().unwrap_or_default();
        self.update_identity_v2(ctx, "AssociateEmailIdentityCertificate", &input.email_identity, |i| {
            if i.certificates.contains_key(&from) {
                return Err(v2::errors::already_exists("A certificate is already associated with this address."));
            }
            i.certificates.insert(from, input.certificate_arn);
            Ok(Default::default())
        })
    }

    pub(crate) fn disassociate_email_identity_certificate_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DisassociateEmailIdentityCertificateRequest,
    ) -> Result<t2::DisassociateEmailIdentityCertificateResponse, ServiceError> {
        let from = input.from_address.clone().unwrap_or_default();
        self.update_identity_v2(ctx, "DisassociateEmailIdentityCertificate", &input.email_identity, |i| {
            if i.certificates.remove(&from).is_none() {
                return Err(v2::errors::not_found("No certificate is associated with this address."));
            }
            Ok(Default::default())
        })
    }

    pub(crate) fn list_email_identity_certificates_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListEmailIdentityCertificatesRequest,
    ) -> Result<t2::ListEmailIdentityCertificatesResponse, ServiceError> {
        let (i, _, _) = self.identity_v2(ctx, "ListEmailIdentityCertificates", &input.email_identity)?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::IdentityCertificate> = i
            .certificates
            .iter()
            .map(|(from, arn)| t2::IdentityCertificate {
                from_address: (!from.is_empty()).then(|| from.clone()),
                status: Some("ACTIVE".into()),
                certificate_arn: Some(arn.clone()),
                certificate_expiry_time: None,
            })
            .collect();
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListEmailIdentityCertificatesResponse { certificates: Some(page), next_token: next })
    }

    pub(crate) fn send_custom_verification_email_v2(
        &self,
        ctx: &RequestContext,
        input: t2::SendCustomVerificationEmailRequest,
    ) -> Result<t2::SendCustomVerificationEmailResponse, ServiceError> {
        authorize(ctx, "2", "SendCustomVerificationEmail", &names::identity_arn(ctx, &input.email_address))?;
        if let Some(cs) = &input.configuration_set_name {
            if self.configuration_set(ctx, cs).is_none() {
                return Err(v2::errors::not_found(format!("Configuration set <{cs}> does not exist.")));
            }
        }
        let t = self.custom_template_for_send(ctx, &input.template_name).ok_or_else(|| {
            v2::errors::not_found(format!("Custom verification email template {} does not exist.", input.template_name))
        })?;
        if !self.is_verified_sender(ctx, &t.from) {
            return Err(v2::errors::message_rejected(format!(
                "Email address is not verified. The following identities failed the check in region {}: {}",
                names::upper_region(ctx),
                t.from
            )));
        }
        names::check_address(&input.email_address)
            .map_err(|m| v2::errors::bad_request(format!("Invalid email address: {m}")))?;
        self.start_email_identity(ctx, &names::bare_address(&input.email_address), false, Some(&t))?;
        let id = self.lock().outbox.last().map(|m| m.id.clone());
        Ok(t2::SendCustomVerificationEmailResponse { message_id: id })
    }

    /// Force an identity verified (the `/_aws/ses/verify-identity` side
    /// channel).
    pub(crate) fn force_verify(&self, account: &str, region_name: &str, identity: &str, now: DateTime<Utc>) -> bool {
        let mut st = self.lock();
        let r = st.regions.entry(crate::state::region_key(account, region_name)).or_default();
        match r.identities.get_mut(&names::canonical_identity(identity)) {
            Some(i) => {
                i.verification_status = "Success".into();
                i.last_success = Some(now);
                if i.is_domain() && i.dkim_status == "PENDING" {
                    i.dkim_status = "SUCCESS".into();
                }
                if i.mail_from_domain.is_some() {
                    i.mail_from_status = "Success".into();
                }
                true
            }
            None => false,
        }
    }

    pub(crate) fn region_snapshot(&self, ctx: &RequestContext) -> Option<Region> {
        region_ref(&self.lock(), ctx).cloned()
    }
}
