//! Cross-account attachments: an account lets principals (accounts or
//! accelerators) use its endpoints and BYOIP address ranges.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{
    self, account, attachment_not_found, authorize, check_tags, invalid, now_ms, page, request_tags, resource_tags,
    tag_map, time, EndpointKind, REGIONS,
};
use crate::state::{Attachment, AttachmentResource, State};
use crate::{GlobalAccelerator, Lookup};

const PRINCIPAL_LIMIT: usize = 100;
const RESOURCE_LIMIT: usize = 100;

fn describe(t: &Attachment) -> types::Attachment {
    types::Attachment {
        attachment_arn: Some(t.arn.clone()),
        name: Some(t.name.clone()),
        principals: Some(t.principals.clone()),
        resources: Some(
            t.resources
                .iter()
                .map(|r| types::Resource {
                    endpoint_id: r.endpoint_id.clone().unwrap_or_default(),
                    cidr: r.cidr.clone(),
                    region: r.region.clone(),
                })
                .collect(),
        ),
        last_modified_time: Some(time(t.modified)),
        created_time: Some(time(t.created)),
    }
}

fn check_name(name: &str) -> Result<(), ServiceError> {
    if name.is_empty()
        || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
    {
        return Err(invalid(
            "The name can have a maximum of 64 characters and can contain only alphanumeric characters, hyphens (-), underscores (_) and spaces.",
        ));
    }
    Ok(())
}

fn check_principals(principals: &[String]) -> Result<(), ServiceError> {
    for p in principals {
        let account = p.len() == 12 && p.chars().all(|c| c.is_ascii_digit());
        let accelerator = names::parse(p).is_some_and(|path| path.listener.is_none());
        if !account && !accelerator {
            return Err(invalid(format!("Principal {p} must be an AWS account ID or an accelerator ARN.")));
        }
    }
    Ok(())
}

fn principal_matches(st: &State, principal: &str, caller: &str) -> bool {
    principal == caller || st.accelerators.get(principal).is_some_and(|a| a.account == caller)
}

impl GlobalAccelerator {
    /// Resources from the request, checked: endpoints the caller owns (and
    /// that exist), or BYOIP address ranges the caller provisioned.
    fn resources(
        &self,
        st: &State,
        caller: &str,
        input: &[types::Resource],
    ) -> Result<Vec<AttachmentResource>, ServiceError> {
        let mut out = Vec::new();
        for r in input {
            let endpoint = Some(r.endpoint_id.clone()).filter(|e| !e.is_empty());
            let cidr = r.cidr.clone().filter(|c| !c.is_empty());
            match (&endpoint, &cidr) {
                (Some(_), Some(_)) => {
                    return Err(errors::conflict("A resource can have an endpoint ID or a CIDR, but not both."))
                }
                (None, None) => return Err(invalid("A resource must have an endpoint ID or a CIDR.")),
                (Some(id), None) => {
                    let subnet = id.starts_with("subnet-");
                    let kind = EndpointKind::of(id);
                    if kind.is_none() && !subnet {
                        return Err(invalid(format!("The endpoint ID {id} is not a supported endpoint type.")));
                    }
                    let region = match (&r.region, names::elb_region_account(id)) {
                        (Some(region), _) => region.clone(),
                        (None, Some((region, _))) if id.starts_with("arn:") => region.to_string(),
                        _ => return Err(invalid(format!("Region is required for endpoint {id}."))),
                    };
                    if !REGIONS.contains(&region.as_str()) {
                        return Err(invalid(format!("Region {region} is not supported.")));
                    }
                    if let Some((lb_region, lb_account)) =
                        names::elb_region_account(id).filter(|_| id.starts_with("arn:"))
                    {
                        if lb_account != caller {
                            return Err(invalid(format!("You can only share endpoints that your account owns: {id}.")));
                        }
                        if lb_region != region {
                            return Err(invalid(format!("Endpoint {id} isn't in Region {region}.")));
                        }
                    }
                    let missing = if subnet {
                        self.lookup_subnet(caller, &region, id) == Lookup::Missing
                    } else {
                        self.lookup_endpoint(caller, &region, id) == Lookup::Missing
                    };
                    if missing {
                        return Err(invalid(format!("Endpoint {id} doesn't exist in Region {region}.")));
                    }
                }
                (None, Some(c)) => {
                    let owned =
                        st.byoip.values().any(|b| b.account == caller && &b.cidr == c && b.state != "DEPROVISIONED");
                    if !owned {
                        return Err(invalid(format!(
                            "The address range {c} isn't provisioned for Global Accelerator in your account."
                        )));
                    }
                }
            }
            let resource = AttachmentResource { endpoint_id: endpoint, cidr, region: r.region.clone() };
            if !out.contains(&resource) {
                out.push(resource);
            }
        }
        Ok(out)
    }

    pub fn create_cross_account_attachment(
        &self,
        ctx: &RequestContext,
        input: types::CreateCrossAccountAttachmentRequest,
    ) -> Result<types::CreateCrossAccountAttachmentResponse, ServiceError> {
        let tags = tag_map(input.tags.as_deref().unwrap_or_default());
        authorize(ctx, "CreateCrossAccountAttachment", "*", request_tags(&tags))?;
        if !tags.is_empty() {
            authorize(ctx, "TagResource", "*", request_tags(&tags))?;
        }
        check_name(&input.name)?;
        check_tags(&tags)?;
        let principals = input.principals.unwrap_or_default();
        check_principals(&principals)?;
        let now = now_ms(ctx);
        let caller = account(ctx);
        let mut st = self.settled(ctx);
        let key = format!("{caller}/CreateCrossAccountAttachment/{}", input.idempotency_token);
        if let Some(t) = st.idempotency.get(&key).and_then(|arn| st.attachments.get(arn)) {
            return Ok(types::CreateCrossAccountAttachmentResponse { cross_account_attachment: Some(describe(t)) });
        }
        let resources = self.resources(&st, &caller, input.resources.as_deref().unwrap_or_default())?;
        if principals.len() > PRINCIPAL_LIMIT || resources.len() > RESOURCE_LIMIT {
            return Err(errors::limit_exceeded("An attachment can have at most 100 principals and 100 resources."));
        }
        let mut deduped: Vec<String> = Vec::new();
        for p in principals {
            if !deduped.contains(&p) {
                deduped.push(p);
            }
        }
        let t = Attachment {
            arn: names::attachment_arn(ctx),
            account: caller,
            seq: st.next_seq(),
            name: input.name,
            principals: deduped,
            resources,
            created: now,
            modified: now,
            tags,
        };
        st.idempotency.insert(key, t.arn.clone());
        st.attachments.insert(t.arn.clone(), t.clone());
        Ok(types::CreateCrossAccountAttachmentResponse { cross_account_attachment: Some(describe(&t)) })
    }

    fn own_attachment<'a>(st: &'a State, ctx: &RequestContext, arn: &str) -> Result<&'a Attachment, ServiceError> {
        st.attachments.get(arn).filter(|t| t.account == ctx.caller.account_id).ok_or_else(|| attachment_not_found(arn))
    }

    pub fn describe_cross_account_attachment(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCrossAccountAttachmentRequest,
    ) -> Result<types::DescribeCrossAccountAttachmentResponse, ServiceError> {
        let st = self.settled(ctx);
        let t = Self::own_attachment(&st, ctx, &input.attachment_arn)?;
        authorize(ctx, "DescribeCrossAccountAttachment", &t.arn, resource_tags(&t.tags))?;
        Ok(types::DescribeCrossAccountAttachmentResponse { cross_account_attachment: Some(describe(t)) })
    }

    pub fn update_cross_account_attachment(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCrossAccountAttachmentRequest,
    ) -> Result<types::UpdateCrossAccountAttachmentResponse, ServiceError> {
        let now = now_ms(ctx);
        let caller = account(ctx);
        let mut st = self.settled(ctx);
        let t = Self::own_attachment(&st, ctx, &input.attachment_arn)?;
        authorize(ctx, "UpdateCrossAccountAttachment", &t.arn, resource_tags(&t.tags))?;
        let mut t = t.clone();
        if let Some(n) = &input.name {
            check_name(n)?;
            t.name = n.clone();
        }
        if let Some(add) = &input.add_principals {
            check_principals(add)?;
            for p in add {
                if !t.principals.contains(p) {
                    t.principals.push(p.clone());
                }
            }
        }
        if let Some(remove) = &input.remove_principals {
            t.principals.retain(|p| !remove.contains(p));
        }
        if let Some(add) = &input.add_resources {
            for r in self.resources(&st, &caller, add)? {
                if !t.resources.contains(&r) {
                    t.resources.push(r);
                }
            }
        }
        if let Some(remove) = &input.remove_resources {
            t.resources.retain(|r| {
                !remove.iter().any(|x| {
                    let id = Some(x.endpoint_id.clone()).filter(|e| !e.is_empty());
                    let cidr = x.cidr.clone().filter(|c| !c.is_empty());
                    r.endpoint_id == id && r.cidr == cidr && (x.region.is_none() || r.region == x.region)
                })
            });
        }
        if t.principals.len() > PRINCIPAL_LIMIT || t.resources.len() > RESOURCE_LIMIT {
            return Err(errors::limit_exceeded("An attachment can have at most 100 principals and 100 resources."));
        }
        t.modified = now;
        st.attachments.insert(t.arn.clone(), t.clone());
        Ok(types::UpdateCrossAccountAttachmentResponse { cross_account_attachment: Some(describe(&t)) })
    }

    pub fn delete_cross_account_attachment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCrossAccountAttachmentRequest,
    ) -> Result<(), ServiceError> {
        let mut st = self.settled(ctx);
        let t = Self::own_attachment(&st, ctx, &input.attachment_arn)?;
        authorize(ctx, "DeleteCrossAccountAttachment", &t.arn, resource_tags(&t.tags))?;
        st.attachments.remove(&input.attachment_arn);
        st.idempotency.retain(|_, v| v != &input.attachment_arn);
        Ok(())
    }

    pub fn list_cross_account_attachments(
        &self,
        ctx: &RequestContext,
        input: types::ListCrossAccountAttachmentsRequest,
    ) -> Result<types::ListCrossAccountAttachmentsResponse, ServiceError> {
        authorize(ctx, "ListCrossAccountAttachments", "*", ConditionContext::new())?;
        let st = self.settled(ctx);
        let mut items: Vec<&Attachment> =
            st.attachments.values().filter(|t| t.account == ctx.caller.account_id).collect();
        items.sort_by_key(|t| t.seq);
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref(), 10)?;
        Ok(types::ListCrossAccountAttachmentsResponse {
            cross_account_attachments: Some(items.into_iter().map(describe).collect()),
            next_token,
        })
    }

    pub fn list_cross_account_resource_accounts(
        &self,
        ctx: &RequestContext,
        _input: types::ListCrossAccountResourceAccountsRequest,
    ) -> Result<types::ListCrossAccountResourceAccountsResponse, ServiceError> {
        authorize(ctx, "ListCrossAccountResourceAccounts", "*", ConditionContext::new())?;
        let caller = account(ctx);
        let st = self.settled(ctx);
        let mut accounts: Vec<String> = st
            .attachments
            .values()
            .filter(|t| t.principals.iter().any(|p| principal_matches(&st, p, &caller)))
            .map(|t| t.account.clone())
            .collect();
        accounts.sort();
        accounts.dedup();
        Ok(types::ListCrossAccountResourceAccountsResponse { resource_owner_aws_account_ids: Some(accounts) })
    }

    pub fn list_cross_account_resources(
        &self,
        ctx: &RequestContext,
        input: types::ListCrossAccountResourcesRequest,
    ) -> Result<types::ListCrossAccountResourcesResponse, ServiceError> {
        authorize(ctx, "ListCrossAccountResources", "*", ConditionContext::new())?;
        let caller = account(ctx);
        let st = self.settled(ctx);
        if let Some(arn) = &input.accelerator_arn {
            if !st.accelerators.get(arn).is_some_and(|a| a.account == caller) {
                return Err(names::accelerator_not_found(arn));
            }
        }
        let mut attachments: Vec<&Attachment> =
            st.attachments.values().filter(|t| t.account == input.resource_owner_aws_account_id).collect();
        attachments.sort_by_key(|t| t.seq);
        let mut out = Vec::new();
        for t in attachments {
            let granted = t.principals.iter().any(|p| match &input.accelerator_arn {
                Some(arn) => p == &caller || p == arn,
                None => principal_matches(&st, p, &caller),
            });
            if !granted {
                continue;
            }
            for r in &t.resources {
                out.push(types::CrossAccountResource {
                    endpoint_id: r.endpoint_id.clone(),
                    cidr: r.cidr.clone(),
                    attachment_arn: Some(t.arn.clone()),
                });
            }
        }
        let (items, next_token) = page(out, input.max_results, input.next_token.as_deref(), 100)?;
        Ok(types::ListCrossAccountResourcesResponse { cross_account_resources: Some(items), next_token })
    }
}
