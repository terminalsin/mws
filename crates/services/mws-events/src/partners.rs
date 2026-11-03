//! SaaS partner event sources: partners create them for customer
//! accounts, customers activate them by creating a partner event bus with
//! the same name, and `PutPartnerEvents` reaches that bus.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{self, not_found, own_region, validation, BusRef};
use crate::state::{EventSource, PartnerAccount, PartnerSource};
use crate::Events;

fn source_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:events:{}::event-source/{name}", ctx.partition, ctx.region)
}

fn source_missing(name: &str) -> ServiceError {
    not_found(format!("Event source {name} does not exist."))
}

impl Events {
    pub fn create_partner_event_source(
        &self,
        ctx: &RequestContext,
        input: types::CreatePartnerEventSourceRequest,
    ) -> Result<types::CreatePartnerEventSourceResponse, ServiceError> {
        let arn = source_arn(ctx, &input.name);
        ctx.authorize("events:CreatePartnerEventSource", &arn, ConditionContext::new())?;
        if !input.name.starts_with("aws.partner/") || input.name.split('/').count() < 3 {
            return Err(validation(
                "Parameter Name is not valid. Reason: Partner event source names look like aws.partner/partner_name/event_namespace/event_name.",
            ));
        }
        let now = ctx.received_at;
        let expiration = now + chrono::Duration::days(15);
        let mut st = self.lock();
        let partner = own_region(&mut st, ctx);
        let source = partner.partner_sources.entry(input.name.clone()).or_insert_with(|| PartnerSource {
            name: input.name.clone(),
            arn: arn.clone(),
            ..PartnerSource::default()
        });
        if source.accounts.contains_key(&input.account) {
            return Err(errors::resource_already_exists(format!(
                "Event source {} already exists for account {}.",
                input.name, input.account
            )));
        }
        source.accounts.insert(
            input.account.clone(),
            PartnerAccount { creation_time: Some(now), expiration_time: Some(expiration) },
        );
        let customer = st.region_mut(&ctx.partition, &input.account, &ctx.region, now);
        customer.event_sources.insert(
            input.name.clone(),
            EventSource {
                name: input.name.clone(),
                arn: arn.clone(),
                created_by: ctx.caller.account_id.clone(),
                creation_time: Some(now),
                expiration_time: Some(expiration),
                state: "PENDING".into(),
            },
        );
        Ok(types::CreatePartnerEventSourceResponse { event_source_arn: Some(arn) })
    }

    pub fn delete_partner_event_source(
        &self,
        ctx: &RequestContext,
        input: types::DeletePartnerEventSourceRequest,
    ) -> Result<(), ServiceError> {
        ctx.authorize("events:DeletePartnerEventSource", &source_arn(ctx, &input.name), ConditionContext::new())?;
        let now = ctx.received_at;
        let mut st = self.lock();
        let partner = own_region(&mut st, ctx);
        if let Some(s) = partner.partner_sources.get_mut(&input.name) {
            s.accounts.remove(&input.account);
            if s.accounts.is_empty() {
                partner.partner_sources.remove(&input.name);
            }
        }
        let customer = st.region_mut(&ctx.partition, &input.account, &ctx.region, now);
        if let Some(es) = customer.event_sources.get_mut(&input.name) {
            es.state = "DELETED".into();
        }
        Ok(())
    }

    pub fn describe_partner_event_source(
        &self,
        ctx: &RequestContext,
        input: types::DescribePartnerEventSourceRequest,
    ) -> Result<types::DescribePartnerEventSourceResponse, ServiceError> {
        ctx.authorize("events:DescribePartnerEventSource", &source_arn(ctx, &input.name), ConditionContext::new())?;
        let mut st = self.lock();
        let s = own_region(&mut st, ctx).partner_sources.get(&input.name).ok_or_else(|| source_missing(&input.name))?;
        Ok(types::DescribePartnerEventSourceResponse { arn: Some(s.arn.clone()), name: Some(s.name.clone()) })
    }

    pub fn list_partner_event_sources(
        &self,
        ctx: &RequestContext,
        input: types::ListPartnerEventSourcesRequest,
    ) -> Result<types::ListPartnerEventSourcesResponse, ServiceError> {
        ctx.authorize("events:ListPartnerEventSources", "*", ConditionContext::new())?;
        let items: Vec<types::PartnerEventSource> = {
            let mut st = self.lock();
            own_region(&mut st, ctx)
                .partner_sources
                .values()
                .filter(|s| s.name.starts_with(&input.name_prefix))
                .map(|s| types::PartnerEventSource { arn: Some(s.arn.clone()), name: Some(s.name.clone()) })
                .collect()
        };
        let (page, next_token) = names::paginate(items, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListPartnerEventSourcesResponse { partner_event_sources: Some(page), next_token })
    }

    pub fn list_partner_event_source_accounts(
        &self,
        ctx: &RequestContext,
        input: types::ListPartnerEventSourceAccountsRequest,
    ) -> Result<types::ListPartnerEventSourceAccountsResponse, ServiceError> {
        ctx.authorize(
            "events:ListPartnerEventSourceAccounts",
            &source_arn(ctx, &input.event_source_name),
            ConditionContext::new(),
        )?;
        let items: Vec<types::PartnerEventSourceAccount> = {
            let mut st = self.lock();
            let accounts = own_region(&mut st, ctx)
                .partner_sources
                .get(&input.event_source_name)
                .map(|s| s.accounts.clone())
                .ok_or_else(|| source_missing(&input.event_source_name))?;
            accounts
                .into_iter()
                .map(|(account, a)| {
                    let state = st
                        .region(&account, &ctx.region)
                        .and_then(|r| r.event_sources.get(&input.event_source_name))
                        .map(|s| s.state.clone());
                    types::PartnerEventSourceAccount {
                        account: Some(account),
                        creation_time: a.creation_time,
                        expiration_time: a.expiration_time,
                        state,
                    }
                })
                .collect()
        };
        let (page, next_token) = names::paginate(items, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListPartnerEventSourceAccountsResponse { partner_event_source_accounts: Some(page), next_token })
    }

    fn event_source(&self, ctx: &RequestContext, name: &str) -> Result<EventSource, ServiceError> {
        let mut st = self.lock();
        own_region(&mut st, ctx).event_sources.get(name).cloned().ok_or_else(|| source_missing(name))
    }

    pub fn describe_event_source(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEventSourceRequest,
    ) -> Result<types::DescribeEventSourceResponse, ServiceError> {
        let s = self.event_source(ctx, &input.name)?;
        ctx.authorize("events:DescribeEventSource", &s.arn, ConditionContext::new())?;
        Ok(types::DescribeEventSourceResponse {
            arn: Some(s.arn),
            created_by: Some(s.created_by),
            creation_time: s.creation_time,
            expiration_time: s.expiration_time,
            name: Some(s.name),
            state: Some(s.state),
        })
    }

    pub fn list_event_sources(
        &self,
        ctx: &RequestContext,
        input: types::ListEventSourcesRequest,
    ) -> Result<types::ListEventSourcesResponse, ServiceError> {
        ctx.authorize("events:ListEventSources", "*", ConditionContext::new())?;
        let items: Vec<types::EventSource> = {
            let mut st = self.lock();
            own_region(&mut st, ctx)
                .event_sources
                .values()
                .filter(|s| input.name_prefix.as_deref().is_none_or(|p| s.name.starts_with(p)))
                .map(|s| types::EventSource {
                    arn: Some(s.arn.clone()),
                    created_by: Some(s.created_by.clone()),
                    creation_time: s.creation_time,
                    expiration_time: s.expiration_time,
                    name: Some(s.name.clone()),
                    state: Some(s.state.clone()),
                })
                .collect()
        };
        let (page, next_token) = names::paginate(items, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListEventSourcesResponse { event_sources: Some(page), next_token })
    }

    fn set_source_state(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: &str,
        state: &str,
    ) -> Result<(), ServiceError> {
        let s = self.event_source(ctx, name)?;
        ctx.authorize(action, &s.arn, ConditionContext::new())?;
        let mut st = self.lock();
        let es = own_region(&mut st, ctx).event_sources.get_mut(name).ok_or_else(|| source_missing(name))?;
        if es.state == "DELETED" {
            return Err(errors::invalid_state(format!("Event source {name} is in state DELETED.")));
        }
        es.state = state.into();
        Ok(())
    }

    pub fn activate_event_source(
        &self,
        ctx: &RequestContext,
        input: types::ActivateEventSourceRequest,
    ) -> Result<(), ServiceError> {
        self.set_source_state(ctx, "events:ActivateEventSource", &input.name, "ACTIVE")
    }

    pub fn deactivate_event_source(
        &self,
        ctx: &RequestContext,
        input: types::DeactivateEventSourceRequest,
    ) -> Result<(), ServiceError> {
        self.set_source_state(ctx, "events:DeactivateEventSource", &input.name, "PENDING")
    }

    /// The customer accounts of a partner event source the caller created.
    pub(crate) fn partner_accounts(&self, ctx: &RequestContext, source: &str) -> Option<Vec<String>> {
        let st = self.lock();
        st.region(&ctx.caller.account_id, &ctx.region)?
            .partner_sources
            .get(source)
            .map(|s| s.accounts.keys().cloned().collect())
    }

    /// Whether the customer's event source is active and has its bus.
    pub(crate) fn partner_source_active(&self, bus: &BusRef) -> bool {
        let st = self.lock();
        st.region(&bus.account, &bus.region).is_some_and(|r| {
            r.event_sources.get(&bus.name).is_some_and(|s| s.state == "ACTIVE") && r.buses.contains_key(&bus.name)
        })
    }
}
