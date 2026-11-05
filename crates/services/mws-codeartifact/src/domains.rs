//! Domains, domain permissions policies, authorization tokens and tags.

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types;
use crate::names::{self, conflict, domain_not_found, validation};
use crate::state::{domain_key, Domain, PackageGroup, ResourcePolicy, Token};
use crate::{request_tags, CodeArtifact};

/// Default and longest token lifetime: 12 hours.
const MAX_TOKEN_SECONDS: i64 = 43_200;
const MIN_TOKEN_SECONDS: i64 = 900;

pub(crate) fn tags_to_map(tags: &[types::Tag]) -> std::collections::BTreeMap<String, String> {
    tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect()
}

pub(crate) fn tags_from_map(tags: &std::collections::BTreeMap<String, String>) -> Vec<types::Tag> {
    tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()
}

pub(crate) fn describe(d: &Domain) -> types::DomainDescription {
    types::DomainDescription {
        name: Some(d.name.clone()),
        owner: Some(d.owner.clone()),
        arn: Some(d.arn.clone()),
        status: Some("Active".into()),
        created_time: Some(d.created),
        encryption_key: Some(d.encryption_key.clone()),
        repository_count: d.repositories.len() as i32,
        asset_size_bytes: d
            .repositories
            .values()
            .flat_map(|r| r.packages.values())
            .flat_map(|p| p.versions.values())
            .flat_map(|v| v.assets.iter())
            .map(|a| a.content.len() as i64)
            .sum(),
        s3_bucket_arn: Some(d.s3_bucket_arn.clone()),
    }
}

pub(crate) fn policy_out(arn: &str, p: &ResourcePolicy) -> types::ResourcePolicy {
    types::ResourcePolicy {
        resource_arn: Some(arn.to_string()),
        revision: Some(p.revision.clone()),
        document: Some(p.document.clone()),
    }
}

pub(crate) fn check_policy_document(document: &str) -> Result<(), ServiceError> {
    mws_iam_policy::Policy::parse(document, mws_iam_policy::PolicyKind::Resource)
        .map(|_| ())
        .map_err(|e| validation(format!("Invalid policy document: {}", e.0)))
}

pub(crate) fn new_revision() -> String {
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn root_group(ctx: &RequestContext, owner: &str, domain: &str) -> PackageGroup {
    let mut g = PackageGroup {
        pattern: crate::groups::ROOT.into(),
        arn: names::package_group_arn(&ctx.partition, &ctx.region, owner, domain, crate::groups::ROOT),
        created: ctx.received_at,
        ..Default::default()
    };
    for t in crate::groups::RESTRICTION_TYPES {
        g.restrictions.insert(t.to_string(), "ALLOW".into());
    }
    g
}

impl CodeArtifact {
    pub(crate) fn create_domain(
        &self,
        ctx: &RequestContext,
        input: types::CreateDomainRequest,
    ) -> Result<types::CreateDomainResult, ServiceError> {
        let owner = ctx.caller.account_id.clone();
        let arn = names::domain_arn(&ctx.partition, &ctx.region, &owner, &input.domain);
        let tags = input.tags.unwrap_or_default();
        ctx.authorize("codeartifact:CreateDomain", &arn, request_tags(&tags))?;
        if !tags.is_empty() {
            ctx.authorize("codeartifact:TagResource", &arn, request_tags(&tags))?;
        }
        let key = domain_key(&ctx.region, &owner, &input.domain);
        if self.read().domains.contains_key(&key) {
            return Err(conflict(
                "domain",
                &input.domain,
                format!("Domain already exists. Domain name: '{}'", input.domain),
            ));
        }
        let encryption_key = match input.encryption_key.filter(|k| !k.is_empty()) {
            Some(k) => {
                if !k.starts_with("arn:") {
                    return Err(validation("encryptionKey must be the ARN of a KMS key."));
                }
                k
            }
            None => match &self.inner.kms {
                Some(kms) => kms.aws_managed_key(ctx, "codeartifact"),
                None => format!("arn:{}:kms:{}:{owner}:key/{}", ctx.partition, ctx.region, uuid::Uuid::new_v4()),
            },
        };
        let bucket_id: u64 = rand::random();
        let domain = Domain {
            name: input.domain.clone(),
            owner: owner.clone(),
            region: ctx.region.clone(),
            partition: ctx.partition.clone(),
            arn,
            created: ctx.received_at,
            encryption_key,
            s3_bucket_arn: format!("arn:{}:s3:::assets-{bucket_id:012x}-{}", ctx.partition, ctx.region),
            policy: None,
            tags: tags_to_map(&tags),
            repositories: Default::default(),
            groups: [(crate::groups::ROOT.to_string(), root_group(ctx, &owner, &input.domain))].into(),
        };
        let out = describe(&domain);
        let mut st = self.write();
        if st.domains.contains_key(&key) {
            return Err(conflict(
                "domain",
                &input.domain,
                format!("Domain already exists. Domain name: '{}'", input.domain),
            ));
        }
        st.domains.insert(key, domain);
        Ok(types::CreateDomainResult { domain: Some(out) })
    }

    pub(crate) fn describe_domain(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDomainRequest,
    ) -> Result<types::DescribeDomainResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:DescribeDomain")?;
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        Ok(types::DescribeDomainResult { domain: Some(describe(d)) })
    }

    pub(crate) fn delete_domain(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDomainRequest,
    ) -> Result<types::DeleteDomainResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:DeleteDomain")?;
        let key = Self::key(ctx, &owner, &input.domain);
        let mut st = self.write();
        let d = st.domains.get(&key).ok_or_else(|| domain_not_found(&input.domain))?;
        if !d.repositories.is_empty() {
            return Err(conflict(
                "domain",
                &input.domain,
                format!("Domain '{}' cannot be deleted because it contains repositories.", input.domain),
            ));
        }
        let mut out = describe(d);
        out.status = Some("Deleted".into());
        st.domains.remove(&key);
        st.tokens.retain(|_, t| t.domain != key);
        Ok(types::DeleteDomainResult { domain: Some(out) })
    }

    pub(crate) fn list_domains(
        &self,
        ctx: &RequestContext,
        input: types::ListDomainsRequest,
    ) -> Result<types::ListDomainsResult, ServiceError> {
        ctx.authorize("codeartifact:ListDomains", "*", ConditionContext::new())?;
        let st = self.read();
        let all: Vec<types::DomainSummary> = st
            .domains
            .values()
            .filter(|d| d.region == ctx.region && d.owner == ctx.caller.account_id)
            .map(|d| types::DomainSummary {
                name: Some(d.name.clone()),
                owner: Some(d.owner.clone()),
                arn: Some(d.arn.clone()),
                status: Some("Active".into()),
                created_time: Some(d.created),
                encryption_key: Some(d.encryption_key.clone()),
            })
            .collect();
        let (domains, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
        Ok(types::ListDomainsResult { domains: Some(domains), next_token })
    }

    pub(crate) fn put_domain_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutDomainPermissionsPolicyRequest,
    ) -> Result<types::PutDomainPermissionsPolicyResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:PutDomainPermissionsPolicy")?;
        check_policy_document(&input.policy_document)?;
        let mut st = self.write();
        let d = st
            .domains
            .get_mut(&Self::key(ctx, &owner, &input.domain))
            .ok_or_else(|| domain_not_found(&input.domain))?;
        check_revision(d.policy.as_ref(), input.policy_revision.as_deref(), &d.arn)?;
        let p = ResourcePolicy { document: input.policy_document, revision: new_revision() };
        let out = policy_out(&d.arn, &p);
        d.policy = Some(p);
        Ok(types::PutDomainPermissionsPolicyResult { policy: Some(out) })
    }

    pub(crate) fn get_domain_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetDomainPermissionsPolicyRequest,
    ) -> Result<types::GetDomainPermissionsPolicyResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:GetDomainPermissionsPolicy")?;
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        let p = d.policy.as_ref().ok_or_else(|| no_policy("domain", &d.arn))?;
        Ok(types::GetDomainPermissionsPolicyResult { policy: Some(policy_out(&d.arn, p)) })
    }

    pub(crate) fn delete_domain_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDomainPermissionsPolicyRequest,
    ) -> Result<types::DeleteDomainPermissionsPolicyResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:DeleteDomainPermissionsPolicy")?;
        let mut st = self.write();
        let d = st
            .domains
            .get_mut(&Self::key(ctx, &owner, &input.domain))
            .ok_or_else(|| domain_not_found(&input.domain))?;
        let p = d.policy.as_ref().ok_or_else(|| no_policy("domain", &d.arn))?;
        check_revision(Some(p), input.policy_revision.as_deref(), &d.arn)?;
        let out = policy_out(&d.arn, p);
        d.policy = None;
        Ok(types::DeleteDomainPermissionsPolicyResult { policy: Some(out) })
    }

    pub(crate) fn get_authorization_token(
        &self,
        ctx: &RequestContext,
        input: types::GetAuthorizationTokenRequest,
    ) -> Result<types::GetAuthorizationTokenResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:GetAuthorizationToken")?;
        // CodeArtifact tokens are service bearer tokens: STS must allow them too.
        let mut cond = ConditionContext::new();
        cond.insert("sts:AWSServiceName".into(), vec!["codeartifact.amazonaws.com".into()]);
        ctx.authorize("sts:GetServiceBearerToken", "*", cond)?;
        let key = Self::key(ctx, &owner, &input.domain);
        if !self.read().domains.contains_key(&key) {
            return Err(domain_not_found(&input.domain));
        }
        let duration = input.duration_seconds.unwrap_or(MAX_TOKEN_SECONDS);
        let session_end = ctx.caller.session.as_ref().map(|s| s.expires_at);
        let expires = match duration {
            0 => session_end.unwrap_or(ctx.received_at + chrono::Duration::seconds(MAX_TOKEN_SECONDS)),
            d if !(MIN_TOKEN_SECONDS..=MAX_TOKEN_SECONDS).contains(&d) => {
                return Err(validation(format!(
                    "durationSeconds must be 0, or between {MIN_TOKEN_SECONDS} and {MAX_TOKEN_SECONDS}."
                )))
            }
            d => {
                let e = ctx.received_at + chrono::Duration::seconds(d);
                // A token never outlives the credentials that asked for it.
                session_end.map_or(e, |s| s.min(e))
            }
        };
        let token = new_token(ctx, expires);
        let mut st = self.write();
        let now = ctx.received_at;
        st.tokens.retain(|_, t| t.expires > now);
        st.tokens.insert(token.clone(), Token { domain: key, caller: ctx.caller.clone(), expires });
        Ok(types::GetAuthorizationTokenResult { authorization_token: Some(token), expiration: Some(expires) })
    }

    pub(crate) fn find_tags_mut<'a>(
        st: &'a mut crate::state::State,
        arn: &str,
    ) -> Option<&'a mut std::collections::BTreeMap<String, String>> {
        for d in st.domains.values_mut() {
            if d.arn == arn {
                return Some(&mut d.tags);
            }
            for r in d.repositories.values_mut() {
                if r.arn == arn {
                    return Some(&mut r.tags);
                }
            }
            for g in d.groups.values_mut() {
                if g.arn == arn {
                    return Some(&mut g.tags);
                }
            }
        }
        None
    }

    fn tags_of(&self, arn: &str) -> Result<std::collections::BTreeMap<String, String>, ServiceError> {
        let mut st = self.write();
        Self::find_tags_mut(&mut st, arn)
            .map(|t| t.clone())
            .ok_or_else(|| names::not_found("resource", arn, format!("Resource not found. Resource ARN: '{arn}'")))
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResult, ServiceError> {
        let tags = self.tags_of(&input.resource_arn);
        ctx.authorize(
            "codeartifact:ListTagsForResource",
            &input.resource_arn,
            crate::resource_tags(tags.as_ref().unwrap_or(&Default::default())),
        )?;
        Ok(types::ListTagsForResourceResult { tags: Some(tags_from_map(&tags?)) })
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResult, ServiceError> {
        let existing = self.tags_of(&input.resource_arn);
        let mut cond = request_tags(&input.tags);
        cond.extend(crate::resource_tags(existing.as_ref().unwrap_or(&Default::default())));
        ctx.authorize("codeartifact:TagResource", &input.resource_arn, cond)?;
        existing?;
        let mut st = self.write();
        let tags = Self::find_tags_mut(&mut st, &input.resource_arn).expect("checked above");
        let mut merged = tags.clone();
        merged.extend(tags_to_map(&input.tags));
        if merged.len() > 50 {
            return Err(names::quota("tag", &input.resource_arn, "The resource cannot have more than 50 tags."));
        }
        *tags = merged;
        Ok(types::TagResourceResult {})
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResult, ServiceError> {
        let existing = self.tags_of(&input.resource_arn);
        let mut cond = crate::resource_tags(existing.as_ref().unwrap_or(&Default::default()));
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        ctx.authorize("codeartifact:UntagResource", &input.resource_arn, cond)?;
        existing?;
        let mut st = self.write();
        let tags = Self::find_tags_mut(&mut st, &input.resource_arn).expect("checked above");
        for k in &input.tag_keys {
            tags.remove(k);
        }
        Ok(types::UntagResourceResult {})
    }
}

pub(crate) fn no_policy(kind: &str, arn: &str) -> ServiceError {
    names::not_found(kind, arn, format!("No resource policy found for resource: '{arn}'"))
}

/// `policyRevision`, when given, must be the current revision.
pub(crate) fn check_revision(
    current: Option<&ResourcePolicy>,
    expected: Option<&str>,
    arn: &str,
) -> Result<(), ServiceError> {
    let Some(expected) = expected else { return Ok(()) };
    if current.map(|p| p.revision.as_str()) != Some(expected) {
        return Err(conflict(
            "resource-policy",
            arn,
            "The policy revision provided does not match the current policy revision.",
        ));
    }
    Ok(())
}

/// A token shaped like CodeArtifact's (a JWE-like base64url string).
fn new_token(ctx: &RequestContext, expires: chrono::DateTime<chrono::Utc>) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = serde_json::json!({
        "ver": 1,
        "isu": ctx.received_at.timestamp(),
        "enc": "A128GCM",
        "tag": b64.encode(rand::random::<[u8; 16]>()),
        "exp": expires.timestamp(),
        "alg": "A128GCMKW",
        "iv": b64.encode(rand::random::<[u8; 12]>()),
    });
    let secret: Vec<u8> = (0..96).map(|_| rand::random::<u8>()).collect();
    format!("{}.{}.{}", b64.encode(header.to_string()), b64.encode(rand::random::<[u8; 16]>()), b64.encode(secret))
}
