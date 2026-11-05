//! Tags, account limits, security policies and resource policies.

use mws_core::{RequestContext, ServiceError};

use crate::names::{self, validation};
use crate::state::RegionState;
use crate::v2::{errors, types as t};
use crate::{catalog, Elb};

/// Whether `arn` names an existing ELBv2 resource, or the error AWS gives.
fn check_exists(r: &RegionState, arn: &str) -> Result<(), ServiceError> {
    let resource = arn.splitn(6, ':').nth(5).unwrap_or_default();
    let (exists, err): (bool, fn() -> ServiceError) = if resource.starts_with("loadbalancer/") {
        (r.load_balancers.contains_key(arn), super::lb::lb_not_found)
    } else if resource.starts_with("targetgroup/") {
        (r.target_groups.contains_key(arn), super::tg::tg_not_found)
    } else if resource.starts_with("listener/") {
        (r.listeners.contains_key(arn), super::listener::listener_not_found)
    } else if resource.starts_with("listener-rule/") {
        (r.rules.contains_key(arn), super::rule::rule_not_found)
    } else if resource.starts_with("truststore/") {
        (r.trust_stores.contains_key(arn), super::trust::trust_store_not_found)
    } else {
        return Err(validation(format!("'{arn}' is not a valid resource ARN")));
    };
    if exists {
        Ok(())
    } else {
        Err(err())
    }
}

impl Elb {
    pub(crate) fn add_tags_op(&self, ctx: &RequestContext, input: t::AddTagsInput) -> Result<t::AddTagsOutput, ServiceError> {
        names::check_tags(&input.tags)?;
        for arn in &input.resource_arns {
            let ctx_tags = names::merge(
                names::resource_tag_context(&self.tags_of(ctx, arn)),
                names::request_tag_context(&input.tags),
            );
            names::authorize(ctx, "AddTags", arn, ctx_tags)?;
        }
        self.with_region(ctx, |r| {
            for arn in &input.resource_arns {
                check_exists(r, arn)?;
            }
            for arn in &input.resource_arns {
                let tags = r.tags.entry(arn.clone()).or_default();
                let mut next = tags.clone();
                for tag in &input.tags {
                    match next.iter_mut().find(|x| x.key == tag.key) {
                        Some(x) => x.value = tag.value.clone(),
                        None => next.push(tag.clone()),
                    }
                }
                if next.len() > 50 {
                    return Err(errors::too_many_tags("The resource has too many tags; a resource can have at most 50 tags"));
                }
                *tags = next;
            }
            Ok(t::AddTagsOutput {})
        })
    }

    pub(crate) fn remove_tags_op(&self, ctx: &RequestContext, input: t::RemoveTagsInput) -> Result<t::RemoveTagsOutput, ServiceError> {
        for arn in &input.resource_arns {
            let mut c = names::resource_tag_context(&self.tags_of(ctx, arn));
            c.insert("aws:TagKeys".into(), input.tag_keys.clone());
            names::authorize(ctx, "RemoveTags", arn, c)?;
        }
        self.with_region(ctx, |r| {
            for arn in &input.resource_arns {
                check_exists(r, arn)?;
            }
            for arn in &input.resource_arns {
                if let Some(tags) = r.tags.get_mut(arn) {
                    tags.retain(|x| !input.tag_keys.contains(&x.key));
                    if tags.is_empty() {
                        r.tags.remove(arn);
                    }
                }
            }
            Ok(t::RemoveTagsOutput {})
        })
    }

    pub(crate) fn describe_tags_op(&self, ctx: &RequestContext, input: t::DescribeTagsInput) -> Result<t::DescribeTagsOutput, ServiceError> {
        names::authorize(ctx, "DescribeTags", "*", Default::default())?;
        if input.resource_arns.len() > 20 {
            return Err(validation("You can describe the tags of at most 20 resources at a time"));
        }
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for arn in &input.resource_arns {
                check_exists(r, arn)?;
                out.push(t::TagDescription { resource_arn: Some(arn.clone()), tags: Some(r.tags.get(arn).cloned().unwrap_or_default()) });
            }
            Ok(t::DescribeTagsOutput { tag_descriptions: Some(out) })
        })
    }

    pub(crate) fn describe_account_limits_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeAccountLimitsInput,
    ) -> Result<t::DescribeAccountLimitsOutput, ServiceError> {
        names::authorize(ctx, "DescribeAccountLimits", "*", Default::default())?;
        let all: Vec<t::Limit> = catalog::V2_LIMITS
            .iter()
            .map(|(n, m)| t::Limit { name: Some(n.to_string()), max: Some(m.to_string()) })
            .collect();
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(t::DescribeAccountLimitsOutput { limits: Some(items), next_marker: next })
    }

    pub(crate) fn describe_ssl_policies_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSSLPoliciesInput,
    ) -> Result<t::DescribeSSLPoliciesOutput, ServiceError> {
        names::authorize(ctx, "DescribeSSLPolicies", "*", Default::default())?;
        let wanted = input.names.unwrap_or_default();
        let mut all = Vec::new();
        for (name, _, _) in catalog::SSL_POLICIES {
            if !wanted.is_empty() && !wanted.iter().any(|w| w == name) {
                continue;
            }
            let (name, protocols, ciphers) = catalog::ssl_policy(name).expect("listed policy");
            let types: Vec<String> = catalog::ssl_policy_load_balancer_types().iter().map(|s| s.to_string()).collect();
            if let Some(ty) = &input.load_balancer_type {
                if !types.contains(ty) {
                    continue;
                }
            }
            all.push(t::SslPolicy {
                ssl_protocols: Some(protocols.iter().map(|s| s.to_string()).collect()),
                ciphers: Some(
                    ciphers
                        .iter()
                        .enumerate()
                        .map(|(i, c)| t::Cipher { name: Some(c.to_string()), priority: Some(i as i32 + 1) })
                        .collect(),
                ),
                name: Some(name.to_string()),
                supported_load_balancer_types: Some(types),
            });
        }
        for w in &wanted {
            if catalog::ssl_policy(w).is_none() {
                return Err(errors::ssl_policy_not_found(format!("One or more SSL policies not found: '{w}'")));
            }
        }
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(t::DescribeSSLPoliciesOutput { ssl_policies: Some(items), next_marker: next })
    }

    pub(crate) fn get_resource_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::GetResourcePolicyInput,
    ) -> Result<t::GetResourcePolicyOutput, ServiceError> {
        names::authorize(ctx, "GetResourcePolicy", &input.resource_arn, Default::default())?;
        // Resource policies come from RAM shares; MWS shares nothing, so no
        // resource has one.
        self.with_region(ctx, |r| {
            if !r.trust_stores.contains_key(&input.resource_arn) {
                return Err(errors::resource_not_found(format!("The specified resource '{}' does not exist", input.resource_arn)));
            }
            Err(errors::resource_not_found(format!("The specified resource '{}' has no resource policy", input.resource_arn)))
        })
    }
}
