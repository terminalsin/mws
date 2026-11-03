//! Reusable delegation sets.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::limits::{MAX_REUSABLE_DELEGATION_SETS_BY_OWNER, MAX_ZONES_BY_REUSABLE_DELEGATION_SET};
use crate::state::{DelegationSet, State};
use crate::{arn, max_items, new_id, strip_id, Route53};

fn no_such(id: &str) -> ServiceError {
    errors::no_such_delegation_set(format!("A reusable delegation set with the specified ID does not exist: {id}"))
}

impl DelegationSet {
    fn wire(&self) -> types::DelegationSet {
        types::DelegationSet {
            id: Some(format!("/delegationset/{}", self.id)),
            caller_reference: Some(self.caller_reference.clone()),
            name_servers: self.name_servers.clone(),
        }
    }
}

impl State {
    fn delegation_set(&self, id: &str) -> Result<&DelegationSet, ServiceError> {
        self.delegation_sets.get(id).ok_or_else(|| no_such(id))
    }
}

impl Route53 {
    pub(crate) fn create_reusable_delegation_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateReusableDelegationSetRequest,
    ) -> Result<types::CreateReusableDelegationSetResponse, ServiceError> {
        self.authorize(ctx, "CreateReusableDelegationSet", "*")?;
        let mut st = self.lock();
        if st.delegation_sets.values().any(|d| d.caller_reference == input.caller_reference) {
            return Err(errors::delegation_set_already_created(
                "A delegation set with the same owner and caller reference combination has already been created.",
            ));
        }
        if st.delegation_sets.len() as i64 >= MAX_REUSABLE_DELEGATION_SETS_BY_OWNER {
            return Err(errors::limits_exceeded(
                "This operation can't be completed because the current account has reached the limit on reusable delegation sets.",
            ));
        }
        let id = new_id('N');
        let name_servers = match input.hosted_zone_id.as_deref().map(strip_id) {
            Some(zone_id) => {
                let zone = st.zone(zone_id)?;
                if zone.private {
                    return Err(errors::hosted_zone_not_found(format!(
                        "The specified HostedZone {zone_id} is a private hosted zone."
                    )));
                }
                if let Some(existing) = &zone.delegation_set_id {
                    return Err(errors::delegation_set_already_reusable(format!(
                        "The hosted zone {zone_id} already uses the reusable delegation set {existing}."
                    )));
                }
                zone.name_servers.clone()
            }
            None => crate::zones::name_servers(),
        };
        let set = DelegationSet { id: id.clone(), caller_reference: input.caller_reference, name_servers };
        if let Some(zone_id) = input.hosted_zone_id.as_deref().map(strip_id) {
            st.zone_mut(zone_id)?.delegation_set_id = Some(id.clone());
        }
        let delegation_set = set.wire();
        st.delegation_sets.insert(id.clone(), set);
        Ok(types::CreateReusableDelegationSetResponse {
            delegation_set,
            location: format!("https://route53.amazonaws.com/2013-04-01/delegationset/{id}"),
        })
    }

    pub(crate) fn get_reusable_delegation_set(
        &self,
        ctx: &RequestContext,
        input: types::GetReusableDelegationSetRequest,
    ) -> Result<types::GetReusableDelegationSetResponse, ServiceError> {
        let id = strip_id(&input.id);
        self.authorize(ctx, "GetReusableDelegationSet", &arn(ctx, "delegationset", id))?;
        let st = self.lock();
        Ok(types::GetReusableDelegationSetResponse { delegation_set: st.delegation_set(id)?.wire() })
    }

    pub(crate) fn list_reusable_delegation_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListReusableDelegationSetsRequest,
    ) -> Result<types::ListReusableDelegationSetsResponse, ServiceError> {
        self.authorize(ctx, "ListReusableDelegationSets", "*")?;
        let limit = max_items(input.max_items, 100, 100);
        let st = self.lock();
        let sets: Vec<&DelegationSet> = st
            .delegation_sets
            .values()
            .filter(|d| input.marker.as_deref().is_none_or(|m| d.id.as_str() >= strip_id(m)))
            .collect();
        let next = sets.get(limit).map(|d| d.id.clone());
        Ok(types::ListReusableDelegationSetsResponse {
            delegation_sets: sets.iter().take(limit).map(|d| d.wire()).collect(),
            marker: input.marker.unwrap_or_default(),
            is_truncated: next.is_some(),
            next_marker: next,
            max_items: limit as i32,
        })
    }

    pub(crate) fn delete_reusable_delegation_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteReusableDelegationSetRequest,
    ) -> Result<types::DeleteReusableDelegationSetResponse, ServiceError> {
        let id = strip_id(&input.id);
        self.authorize(ctx, "DeleteReusableDelegationSet", &arn(ctx, "delegationset", id))?;
        let mut st = self.lock();
        st.delegation_set(id)?;
        if st.zones.values().any(|z| z.delegation_set_id.as_deref() == Some(id)) {
            return Err(errors::delegation_set_in_use(
                "The specified delegation contains associated hosted zones which must be deleted before the reusable delegation set can be deleted.",
            ));
        }
        st.delegation_sets.remove(id);
        Ok(types::DeleteReusableDelegationSetResponse {})
    }

    pub(crate) fn get_reusable_delegation_set_limit(
        &self,
        ctx: &RequestContext,
        input: types::GetReusableDelegationSetLimitRequest,
    ) -> Result<types::GetReusableDelegationSetLimitResponse, ServiceError> {
        let id = strip_id(&input.delegation_set_id);
        self.authorize(ctx, "GetReusableDelegationSetLimit", &arn(ctx, "delegationset", id))?;
        if input.r#type != "MAX_ZONES_BY_REUSABLE_DELEGATION_SET" {
            return Err(errors::invalid_input(format!("Invalid limit type: {}", input.r#type)));
        }
        let st = self.lock();
        st.delegation_set(id)?;
        let count = st.zones.values().filter(|z| z.delegation_set_id.as_deref() == Some(id)).count();
        Ok(types::GetReusableDelegationSetLimitResponse {
            limit: types::ReusableDelegationSetLimit {
                r#type: input.r#type,
                value: MAX_ZONES_BY_REUSABLE_DELEGATION_SET,
            },
            count: count as i64,
        })
    }
}
