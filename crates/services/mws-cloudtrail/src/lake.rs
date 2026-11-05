//! CloudTrail Lake: event data stores, queries, imports, channels,
//! dashboards, federation and delegated administrators.

use std::io::Read;

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::generated::{errors, types};
use crate::names::{self, channel_arn, dashboard_arn, eds_arn, validate_lake_name};
use crate::resources::check_tags;
use crate::selectors;
use crate::sql;
use crate::state::{Channel, Dashboard, EventDataStore, Import, Query, State};
use crate::CloudTrail;

const MAX_EVENT_DATA_STORES: usize = 10;
const MAX_CHANNELS: usize = 25;

fn eds_not_found(id: &str) -> ServiceError {
    errors::event_data_store_not_found(format!("The event data store {id} was not found."))
}

fn query_not_found(id: &str) -> ServiceError {
    errors::query_id_not_found(format!("The query ID {id} does not exist or does not map to a query."))
}

fn eds_view(e: &EventDataStore) -> types::GetEventDataStoreResponse {
    types::GetEventDataStoreResponse {
        event_data_store_arn: Some(e.arn.clone()),
        name: Some(e.name.clone()),
        status: Some(e.status.clone()),
        advanced_event_selectors: Some(e.advanced_event_selectors.clone()),
        multi_region_enabled: Some(e.multi_region_enabled),
        organization_enabled: Some(e.organization_enabled),
        retention_period: Some(e.retention_period),
        termination_protection_enabled: Some(e.termination_protection_enabled),
        created_timestamp: Some(e.created),
        updated_timestamp: Some(e.updated),
        kms_key_id: e.kms_key_id.clone(),
        billing_mode: Some(e.billing_mode.clone()),
        federation_status: e.federation_status.clone(),
        federation_role_arn: e.federation_role_arn.clone(),
        partition_keys: None,
    }
}

/// Retention limits by billing mode.
fn check_retention(days: i32, billing: &str) -> Result<(), ServiceError> {
    let max = if billing == "FIXED_RETENTION_PRICING" { 2557 } else { 3653 };
    if !(7..=max).contains(&days) {
        return Err(errors::invalid_parameter(format!(
            "RetentionPeriod must be between 7 and {max} days for billing mode {billing}."
        )));
    }
    Ok(())
}

impl CloudTrail {
    /// The ARN of the caller's event data store named by an id or ARN.
    pub(crate) fn eds_key(&self, st: &State, ctx: &RequestContext, id: &str) -> Result<String, ServiceError> {
        if id.starts_with("arn:") {
            let a = names::parse_arn(id).filter(|a| a.kind == "eventdatastore").ok_or_else(|| {
                errors::event_data_store_arn_invalid(format!("The event data store ARN {id} is not valid."))
            })?;
            let _ = a;
        } else if id.len() < 3 {
            return Err(errors::event_data_store_arn_invalid(format!("The event data store ARN {id} is not valid.")));
        }
        st.accounts
            .get(&ctx.caller.account_id)
            .into_iter()
            .flat_map(|a| a.event_data_stores.values())
            .find(|e| e.arn == id || e.id() == id)
            .map(|e| e.arn.clone())
            .ok_or_else(|| eds_not_found(id))
    }

    fn eds_mut<'a>(st: &'a mut State, ctx: &RequestContext, arn: &str) -> &'a mut EventDataStore {
        st.account(&ctx.caller.account_id).event_data_stores.get_mut(arn).expect("event data store exists")
    }

    fn eds<'a>(st: &'a State, ctx: &RequestContext, arn: &str) -> &'a EventDataStore {
        &st.accounts[&ctx.caller.account_id].event_data_stores[arn]
    }

    fn active_eds(&self, st: &State, ctx: &RequestContext, id: &str) -> Result<String, ServiceError> {
        let arn = self.eds_key(st, ctx, id)?;
        if Self::eds(st, ctx, &arn).status == "PENDING_DELETION" {
            return Err(errors::inactive_event_data_store(format!(
                "Event data store {arn} is in PENDING_DELETION status."
            )));
        }
        Ok(arn)
    }

    fn check_org(&self, ctx: &RequestContext) -> Result<Option<String>, ServiceError> {
        let account = &ctx.caller.account_id;
        let org = self
            .organization(account)
            .ok_or_else(|| errors::organizations_not_in_use("This account is not part of an organization."))?;
        let delegated =
            self.lock().accounts.get(&org.management_account_id).is_some_and(|a| a.delegated_admins.contains(account));
        if !org.is_management(account) && !delegated {
            return Err(errors::not_organization_master_account(
                "The request was rejected because the account is not the management account of the organization.",
            ));
        }
        if !org.all_features {
            return Err(errors::organization_not_in_all_features_mode(
                "This organization is in consolidated billing mode. All features must be enabled.",
            ));
        }
        Ok(Some(org.organization_id))
    }

    fn check_eds_key(&self, key: &str) -> Result<String, ServiceError> {
        let Some(kms) = self.inner.kms.get() else { return Ok(key.to_string()) };
        let c = ConditionContext::new();
        match kms.key_for_service(key, "cloudtrail.amazonaws.com", &["kms:GenerateDataKey", "kms:Decrypt"], &c) {
            Ok(k) => Ok(k.arn),
            Err(e) if e.code == "NotFoundException" => {
                Err(errors::kms_key_not_found(format!("KMS key {key} does not exist or is not accessible.")))
            }
            Err(_) => Err(errors::insufficient_encryption_policy(format!(
                "Insufficient permissions to access KMS key {key}."
            ))),
        }
    }

    pub(crate) fn create_event_data_store(
        &self,
        ctx: &RequestContext,
        input: types::CreateEventDataStoreRequest,
    ) -> Result<types::CreateEventDataStoreResponse, ServiceError> {
        let id = uuid::Uuid::new_v4().to_string();
        let arn = eds_arn(ctx, &id);
        ctx.authorize("cloudtrail:CreateEventDataStore", &arn, ConditionContext::new())?;
        validate_lake_name(&input.name, "Event data store")?;
        let selectors = input.advanced_event_selectors.clone().unwrap_or_else(selectors::default_advanced_selectors);
        selectors::validate_advanced(&selectors, false)?;
        let billing = input.billing_mode.clone().unwrap_or_else(|| "EXTENDABLE_RETENTION_PRICING".into());
        let retention = input.retention_period.unwrap_or(if billing == "FIXED_RETENTION_PRICING" { 2557 } else { 366 });
        check_retention(retention, &billing)?;
        let tags = input.tags_list.clone().unwrap_or_default();
        check_tags(&tags)?;
        let organization_id = if input.organization_enabled.unwrap_or(false) { self.check_org(ctx)? } else { None };
        let kms_key_id = match input.kms_key_id.as_deref().filter(|k| !k.is_empty()) {
            Some(k) => Some(self.check_eds_key(k)?),
            None => None,
        };
        let mut st = self.lock();
        let account = st.account(&ctx.caller.account_id);
        if account.event_data_stores.values().any(|e| e.name == input.name && e.home_region == ctx.region) {
            return Err(errors::event_data_store_already_exists(format!(
                "An event data store with the name {} already exists.",
                input.name
            )));
        }
        let live = account.event_data_stores.values().filter(|e| e.home_region == ctx.region).count();
        if live >= MAX_EVENT_DATA_STORES {
            return Err(errors::event_data_store_max_limit_exceeded(
                "Your account has used the maximum number of event data stores.",
            ));
        }
        let now = ctx.received_at;
        let eds = EventDataStore {
            arn: arn.clone(),
            name: input.name.clone(),
            home_region: ctx.region.clone(),
            status: if input.start_ingestion.unwrap_or(true) { "ENABLED" } else { "STOPPED_INGESTION" }.into(),
            advanced_event_selectors: selectors,
            multi_region_enabled: input.multi_region_enabled.unwrap_or(true),
            organization_enabled: organization_id.is_some(),
            organization_id,
            retention_period: retention,
            termination_protection_enabled: input.termination_protection_enabled.unwrap_or(true),
            kms_key_id,
            billing_mode: billing,
            created: now,
            updated: now,
            tags: tags.clone(),
            ..EventDataStore::default()
        };
        let v = eds_view(&eds);
        account.event_data_stores.insert(arn, eds);
        Ok(types::CreateEventDataStoreResponse {
            event_data_store_arn: v.event_data_store_arn,
            name: v.name,
            // A new event data store reports CREATED; it is ENABLED as soon
            // as it is read back.
            status: Some(if v.status.as_deref() == Some("ENABLED") {
                "CREATED".into()
            } else {
                v.status.unwrap_or_default()
            }),
            advanced_event_selectors: v.advanced_event_selectors,
            multi_region_enabled: v.multi_region_enabled,
            organization_enabled: v.organization_enabled,
            retention_period: v.retention_period,
            termination_protection_enabled: v.termination_protection_enabled,
            tags_list: Some(tags),
            created_timestamp: v.created_timestamp,
            updated_timestamp: v.updated_timestamp,
            kms_key_id: v.kms_key_id,
            billing_mode: v.billing_mode,
        })
    }

    pub(crate) fn get_event_data_store(
        &self,
        ctx: &RequestContext,
        input: types::GetEventDataStoreRequest,
    ) -> Result<types::GetEventDataStoreResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.eds_key(&st, ctx, &input.event_data_store)?;
        ctx.authorize("cloudtrail:GetEventDataStore", &arn, ConditionContext::new())?;
        sweep(&mut st, ctx);
        let st = &*st;
        match st.accounts.get(&ctx.caller.account_id).and_then(|a| a.event_data_stores.get(&arn)) {
            Some(e) => Ok(eds_view(e)),
            None => Err(eds_not_found(&input.event_data_store)),
        }
    }

    pub(crate) fn list_event_data_stores(
        &self,
        ctx: &RequestContext,
        input: types::ListEventDataStoresRequest,
    ) -> Result<types::ListEventDataStoresResponse, ServiceError> {
        ctx.authorize("cloudtrail:ListEventDataStores", "*", ConditionContext::new())?;
        let max = input.max_results.unwrap_or(1000);
        if !(1..=1000).contains(&max) {
            return Err(errors::invalid_max_results("MaxResults must be between 1 and 1000."));
        }
        let mut st = self.lock();
        sweep(&mut st, ctx);
        let all: Vec<types::EventDataStore> = st
            .accounts
            .get(&ctx.caller.account_id)
            .into_iter()
            .flat_map(|a| a.event_data_stores.values())
            .filter(|e| e.home_region == ctx.region)
            .map(|e| types::EventDataStore {
                event_data_store_arn: Some(e.arn.clone()),
                name: Some(e.name.clone()),
                termination_protection_enabled: Some(e.termination_protection_enabled),
                status: Some(e.status.clone()),
                advanced_event_selectors: Some(e.advanced_event_selectors.clone()),
                multi_region_enabled: Some(e.multi_region_enabled),
                organization_enabled: Some(e.organization_enabled),
                retention_period: Some(e.retention_period),
                created_timestamp: Some(e.created),
                updated_timestamp: Some(e.updated),
            })
            .collect();
        let (page, next) = names::page(&all, input.next_token.as_deref(), max as usize)?;
        Ok(types::ListEventDataStoresResponse { event_data_stores: Some(page), next_token: next })
    }

    pub(crate) fn update_event_data_store(
        &self,
        ctx: &RequestContext,
        input: types::UpdateEventDataStoreRequest,
    ) -> Result<types::UpdateEventDataStoreResponse, ServiceError> {
        let arn = {
            let st = self.lock();
            self.active_eds(&st, ctx, &input.event_data_store)?
        };
        ctx.authorize("cloudtrail:UpdateEventDataStore", &arn, ConditionContext::new())?;
        if let Some(n) = &input.name {
            validate_lake_name(n, "Event data store")?;
        }
        if let Some(s) = &input.advanced_event_selectors {
            selectors::validate_advanced(s, false)?;
        }
        let org = if input.organization_enabled == Some(true) { self.check_org(ctx)? } else { None };
        let key = match input.kms_key_id.as_deref().filter(|k| !k.is_empty()) {
            Some(k) => Some(self.check_eds_key(k)?),
            None => None,
        };
        let mut st = self.lock();
        if let Some(n) = &input.name {
            let clash = st.accounts[&ctx.caller.account_id]
                .event_data_stores
                .values()
                .any(|e| &e.name == n && e.arn != arn && e.home_region == ctx.region);
            if clash {
                return Err(errors::event_data_store_already_exists(format!(
                    "An event data store with the name {n} already exists."
                )));
            }
        }
        let e = Self::eds_mut(&mut st, ctx, &arn);
        if let Some(b) = &input.billing_mode {
            if e.billing_mode == "EXTENDABLE_RETENTION_PRICING" && b == "FIXED_RETENTION_PRICING" {
                return Err(errors::invalid_parameter(
                    "You cannot change the billing mode from EXTENDABLE_RETENTION_PRICING to FIXED_RETENTION_PRICING.",
                ));
            }
        }
        if e.kms_key_id.is_some() && key.as_ref().is_some_and(|k| Some(k) != e.kms_key_id.as_ref()) {
            return Err(errors::invalid_parameter("You cannot change the KMS key of an event data store."));
        }
        let billing = input.billing_mode.clone().unwrap_or_else(|| e.billing_mode.clone());
        let retention = input.retention_period.unwrap_or(e.retention_period);
        check_retention(retention, &billing)?;
        if let Some(n) = input.name {
            e.name = n;
        }
        if let Some(s) = input.advanced_event_selectors {
            e.advanced_event_selectors = s;
        }
        if let Some(m) = input.multi_region_enabled {
            e.multi_region_enabled = m;
        }
        if let Some(o) = input.organization_enabled {
            e.organization_enabled = o;
            e.organization_id = if o { org } else { None };
        }
        if let Some(t) = input.termination_protection_enabled {
            e.termination_protection_enabled = t;
        }
        if key.is_some() {
            e.kms_key_id = key;
        }
        e.billing_mode = billing;
        e.retention_period = retention;
        e.updated = ctx.received_at;
        let v = eds_view(e);
        Ok(types::UpdateEventDataStoreResponse {
            event_data_store_arn: v.event_data_store_arn,
            name: v.name,
            status: v.status,
            advanced_event_selectors: v.advanced_event_selectors,
            multi_region_enabled: v.multi_region_enabled,
            organization_enabled: v.organization_enabled,
            retention_period: v.retention_period,
            termination_protection_enabled: v.termination_protection_enabled,
            created_timestamp: v.created_timestamp,
            updated_timestamp: v.updated_timestamp,
            kms_key_id: v.kms_key_id,
            billing_mode: v.billing_mode,
            federation_status: v.federation_status,
            federation_role_arn: v.federation_role_arn,
        })
    }

    pub(crate) fn delete_event_data_store(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEventDataStoreRequest,
    ) -> Result<types::DeleteEventDataStoreResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.active_eds(&st, ctx, &input.event_data_store)?;
        ctx.authorize("cloudtrail:DeleteEventDataStore", &arn, ConditionContext::new())?;
        let account = &st.accounts[&ctx.caller.account_id];
        if account.channels.values().any(|c| c.destinations.iter().any(|d| d.location == arn)) {
            return Err(errors::channel_exists_for_eds(format!(
                "Event data store {arn} cannot be deleted because a channel uses it as a destination."
            )));
        }
        if account.imports.values().any(|i| i.status == "IN_PROGRESS" && i.destinations.contains(&arn)) {
            return Err(errors::event_data_store_has_ongoing_import(format!(
                "Event data store {arn} has an ongoing import."
            )));
        }
        let e = Self::eds_mut(&mut st, ctx, &arn);
        if e.termination_protection_enabled {
            return Err(errors::event_data_store_termination_protected(format!(
                "Event data store {arn} cannot be deleted because termination protection is enabled."
            )));
        }
        if e.federation_status.as_deref() == Some("ENABLED") {
            return Err(errors::event_data_store_federation_enabled(format!(
                "Event data store {arn} cannot be deleted because federation is enabled."
            )));
        }
        e.status_before_deletion = Some(e.status.clone());
        e.status = "PENDING_DELETION".into();
        e.deleted_at = Some(ctx.received_at);
        e.updated = ctx.received_at;
        Ok(types::DeleteEventDataStoreResponse {})
    }

    pub(crate) fn restore_event_data_store(
        &self,
        ctx: &RequestContext,
        input: types::RestoreEventDataStoreRequest,
    ) -> Result<types::RestoreEventDataStoreResponse, ServiceError> {
        let mut st = self.lock();
        sweep(&mut st, ctx);
        let arn = self.eds_key(&st, ctx, &input.event_data_store)?;
        ctx.authorize("cloudtrail:RestoreEventDataStore", &arn, ConditionContext::new())?;
        let e = Self::eds_mut(&mut st, ctx, &arn);
        if e.status != "PENDING_DELETION" {
            return Err(errors::invalid_event_data_store_status(format!(
                "Event data store {arn} is not in PENDING_DELETION status."
            )));
        }
        e.status = e.status_before_deletion.take().unwrap_or_else(|| "ENABLED".into());
        e.deleted_at = None;
        e.updated = ctx.received_at;
        let v = eds_view(e);
        Ok(types::RestoreEventDataStoreResponse {
            event_data_store_arn: v.event_data_store_arn,
            name: v.name,
            status: v.status,
            advanced_event_selectors: v.advanced_event_selectors,
            multi_region_enabled: v.multi_region_enabled,
            organization_enabled: v.organization_enabled,
            retention_period: v.retention_period,
            termination_protection_enabled: v.termination_protection_enabled,
            created_timestamp: v.created_timestamp,
            updated_timestamp: v.updated_timestamp,
            kms_key_id: v.kms_key_id,
            billing_mode: v.billing_mode,
        })
    }

    fn set_ingestion(&self, ctx: &RequestContext, id: &str, action: &str, on: bool) -> Result<(), ServiceError> {
        let mut st = self.lock();
        let arn = self.active_eds(&st, ctx, id)?;
        ctx.authorize(action, &arn, ConditionContext::new())?;
        let e = Self::eds_mut(&mut st, ctx, &arn);
        if !matches!(e.category().as_deref(), Some("Management") | Some("Data")) {
            return Err(errors::invalid_event_data_store_category(
                "Ingestion can only be started or stopped on event data stores that collect CloudTrail events.",
            ));
        }
        let (from, to) = if on { ("STOPPED_INGESTION", "ENABLED") } else { ("ENABLED", "STOPPED_INGESTION") };
        if e.status != from {
            return Err(errors::invalid_event_data_store_status(format!(
                "Event data store {arn} is in {} status.",
                e.status
            )));
        }
        e.status = to.into();
        e.updated = ctx.received_at;
        Ok(())
    }

    pub(crate) fn start_event_data_store_ingestion(
        &self,
        ctx: &RequestContext,
        input: types::StartEventDataStoreIngestionRequest,
    ) -> Result<types::StartEventDataStoreIngestionResponse, ServiceError> {
        self.set_ingestion(ctx, &input.event_data_store, "cloudtrail:StartEventDataStoreIngestion", true)?;
        Ok(types::StartEventDataStoreIngestionResponse {})
    }

    pub(crate) fn stop_event_data_store_ingestion(
        &self,
        ctx: &RequestContext,
        input: types::StopEventDataStoreIngestionRequest,
    ) -> Result<types::StopEventDataStoreIngestionResponse, ServiceError> {
        self.set_ingestion(ctx, &input.event_data_store, "cloudtrail:StopEventDataStoreIngestion", false)?;
        Ok(types::StopEventDataStoreIngestionResponse {})
    }

    pub(crate) fn put_eds_insight_selectors(
        &self,
        ctx: &RequestContext,
        eds: &str,
        destination: Option<&str>,
        insight_selectors: Vec<types::InsightSelector>,
    ) -> Result<types::PutInsightSelectorsResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.active_eds(&st, ctx, eds)?;
        ctx.authorize("cloudtrail:PutInsightSelectors", &arn, ConditionContext::new())?;
        let destination = match destination {
            Some(d) => Some(self.active_eds(&st, ctx, d)?),
            None if insight_selectors.is_empty() => None,
            None => {
                return Err(errors::invalid_parameter_combination(
                    "You must specify an InsightsDestination when enabling Insights on an event data store.",
                ))
            }
        };
        let e = Self::eds_mut(&mut st, ctx, &arn);
        e.insight_selectors = insight_selectors.clone();
        e.insights_destination = destination.clone();
        Ok(types::PutInsightSelectorsResponse {
            trail_arn: None,
            insight_selectors: Some(insight_selectors),
            event_data_store_arn: Some(arn),
            insights_destination: destination,
        })
    }

    pub(crate) fn get_eds_insight_selectors(
        &self,
        ctx: &RequestContext,
        eds: &str,
    ) -> Result<types::GetInsightSelectorsResponse, ServiceError> {
        let st = self.lock();
        let arn = self.eds_key(&st, ctx, eds)?;
        ctx.authorize("cloudtrail:GetInsightSelectors", &arn, ConditionContext::new())?;
        let e = Self::eds(&st, ctx, &arn);
        if e.insight_selectors.is_empty() {
            return Err(errors::insight_not_enabled(format!("Event data store {arn} does not have Insights enabled.")));
        }
        Ok(types::GetInsightSelectorsResponse {
            trail_arn: None,
            insight_selectors: Some(e.insight_selectors.clone()),
            event_data_store_arn: Some(arn),
            insights_destination: e.insights_destination.clone(),
        })
    }

    pub(crate) fn put_eds_event_configuration(
        &self,
        ctx: &RequestContext,
        eds: &str,
        input: types::PutEventConfigurationRequest,
    ) -> Result<types::PutEventConfigurationResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.active_eds(&st, ctx, eds)?;
        ctx.authorize("cloudtrail:PutEventConfiguration", &arn, ConditionContext::new())?;
        let e = Self::eds_mut(&mut st, ctx, &arn);
        if input.max_event_size.is_some() {
            e.max_event_size = input.max_event_size;
        }
        if input.context_key_selectors.is_some() {
            e.context_key_selectors = input.context_key_selectors;
        }
        if input.aggregation_configurations.is_some() {
            e.aggregation_configurations = input.aggregation_configurations;
        }
        Ok(types::PutEventConfigurationResponse {
            trail_arn: None,
            event_data_store_arn: Some(arn),
            max_event_size: e.max_event_size.clone(),
            context_key_selectors: e.context_key_selectors.clone(),
            aggregation_configurations: e.aggregation_configurations.clone(),
        })
    }

    pub(crate) fn get_eds_event_configuration(
        &self,
        ctx: &RequestContext,
        eds: &str,
    ) -> Result<types::GetEventConfigurationResponse, ServiceError> {
        let st = self.lock();
        let arn = self.eds_key(&st, ctx, eds)?;
        ctx.authorize("cloudtrail:GetEventConfiguration", &arn, ConditionContext::new())?;
        let e = Self::eds(&st, ctx, &arn);
        Ok(types::GetEventConfigurationResponse {
            trail_arn: None,
            event_data_store_arn: Some(arn),
            max_event_size: Some(e.max_event_size.clone().unwrap_or_else(|| "Standard".into())),
            context_key_selectors: e.context_key_selectors.clone(),
            aggregation_configurations: e.aggregation_configurations.clone(),
        })
    }

    // ---- queries -----------------------------------------------------------

    /// Run a query now and keep its results. Returns the query id.
    fn run_query(
        &self,
        ctx: &RequestContext,
        statement: &str,
        parameters: &[String],
        delivery: Option<String>,
        alias: Option<String>,
        refresh_id: Option<String>,
    ) -> Result<String, ServiceError> {
        // `?` placeholders take the query parameters in order.
        let mut statement_text = String::new();
        let mut params = parameters.iter();
        for c in statement.chars() {
            if c == '?' {
                match params.next() {
                    Some(p) => statement_text.push_str(&format!("'{}'", p.replace('\'', "''"))),
                    None => {
                        return Err(errors::invalid_query_statement(
                            "The query has more placeholders than QueryParameters.",
                        ))
                    }
                }
            } else {
                statement_text.push(c);
            }
        }
        let q = sql::parse(&statement_text)
            .map_err(|e| errors::invalid_query_statement(format!("Query statement is not valid: {e}")))?;
        let started = std::time::Instant::now();
        let st = self.lock();
        let mut arns = Vec::new();
        for from in &q.from {
            let arn = self.eds_key(&st, ctx, from)?;
            let e = Self::eds(&st, ctx, &arn);
            if e.status == "PENDING_DELETION" {
                return Err(errors::inactive_event_data_store(format!(
                    "Event data store {arn} is in PENDING_DELETION status."
                )));
            }
            ctx.authorize("cloudtrail:StartQuery", &arn, ConditionContext::new())?;
            arns.push(arn);
        }
        let account = &st.accounts[&ctx.caller.account_id];
        let events: Vec<&Value> = arns.iter().flat_map(|a| account.event_data_stores[a].events.iter()).collect();
        let id = uuid::Uuid::new_v4().to_string();
        let mut query = Query {
            id: id.clone(),
            statement: statement_text.clone(),
            event_data_stores: arns,
            created: ctx.received_at,
            delivery_s3_uri: delivery.clone(),
            alias,
            refresh_id,
            ..Query::default()
        };
        match sql::run(&q, &events, ctx.received_at) {
            Ok(out) => {
                query.status = "FINISHED".into();
                query.columns = out.columns;
                query.rows = out.rows;
                query.events_scanned = out.scanned as i64;
                query.events_matched = out.matched as i64;
                query.bytes_scanned = out.bytes as i64;
            }
            Err(e) => {
                query.status = "FAILED".into();
                query.error_message = Some(e);
            }
        }
        query.execution_time_ms = started.elapsed().as_millis().min(i32::MAX as u128) as i32;
        drop(st);
        if let (Some(uri), "FINISHED") = (&delivery, query.status.as_str()) {
            query.delivery_status = Some(self.deliver_query_results(ctx, &query, uri));
        }
        self.lock().account(&ctx.caller.account_id).queries.insert(id.clone(), query);
        Ok(id)
    }

    /// Write a query's results as CSV to `s3://bucket/prefix`.
    fn deliver_query_results(&self, ctx: &RequestContext, q: &Query, uri: &str) -> String {
        let Some(s3) = self.inner.s3.get() else { return "FAILED".into() };
        let Some(rest) = uri.strip_prefix("s3://") else { return "FAILED".into() };
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let mut csv = q.columns.iter().map(|c| quote(c)).collect::<Vec<_>>().join(",");
        csv.push('\n');
        for row in &q.rows {
            csv.push_str(&row.iter().map(|v| quote(v.as_deref().unwrap_or(""))).collect::<Vec<_>>().join(","));
            csv.push('\n');
        }
        let date = ctx.received_at.format("%Y/%m/%d");
        let prefix = prefix.trim_end_matches('/');
        let base = if prefix.is_empty() { String::new() } else { format!("{prefix}/") };
        let key = format!("{base}{}/{date}/{}/result_1.csv.gz", ctx.caller.account_id, q.id);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let _ = std::io::Write::write_all(&mut gz, csv.as_bytes());
        let put = mws_s3::ServicePutObject {
            bucket,
            key: &key,
            body: gz.finish().unwrap_or_default(),
            content_type: "text/csv",
            service_principal: "cloudtrail.amazonaws.com",
            source_account: &ctx.caller.account_id,
            source_arn: q.event_data_stores.first().map(String::as_str).unwrap_or_default(),
            acl: None,
            partition: &ctx.partition,
        };
        match s3.put_object_as_service(put) {
            Ok(_) => "SUCCESS".into(),
            Err(mws_s3::ServicePutError::NoSuchBucket) => "RESOURCE_NOT_FOUND".into(),
            Err(_) => "ACCESS_DENIED".into(),
        }
    }

    pub(crate) fn start_query(
        &self,
        ctx: &RequestContext,
        input: types::StartQueryRequest,
    ) -> Result<types::StartQueryResponse, ServiceError> {
        let statement = match (&input.query_statement, &input.query_alias) {
            (Some(s), _) => s.clone(),
            (None, Some(_)) => {
                return Err(errors::invalid_parameter(
                    "Query aliases name managed dashboard queries, which MWS does not have.",
                ))
            }
            (None, None) => {
                return Err(errors::invalid_parameter("You must specify a QueryStatement or a QueryAlias."))
            }
        };
        if let Some(uri) = &input.delivery_s3_uri {
            let bucket = uri.strip_prefix("s3://").map(|r| r.split('/').next().unwrap_or_default()).unwrap_or_default();
            if bucket.is_empty() {
                return Err(errors::invalid_s3_bucket_name(format!("The S3 URI {uri} is not valid.")));
            }
            if let Some(s3) = self.inner.s3.get() {
                if s3.bucket_owner(bucket).is_none() {
                    return Err(errors::s3_bucket_does_not_exist(format!("S3 bucket {bucket} does not exist.")));
                }
            }
        }
        let id = self.run_query(
            ctx,
            &statement,
            input.query_parameters.as_deref().unwrap_or_default(),
            input.delivery_s3_uri,
            input.query_alias,
            None,
        )?;
        Ok(types::StartQueryResponse { query_id: Some(id), event_data_store_owner_account_id: None })
    }

    fn find_query<'a>(&self, st: &'a State, ctx: &RequestContext, id: &str) -> Result<&'a Query, ServiceError> {
        st.accounts.get(&ctx.caller.account_id).and_then(|a| a.queries.get(id)).ok_or_else(|| query_not_found(id))
    }

    pub(crate) fn describe_query(
        &self,
        ctx: &RequestContext,
        input: types::DescribeQueryRequest,
    ) -> Result<types::DescribeQueryResponse, ServiceError> {
        let st = self.lock();
        let q = match (&input.query_id, &input.refresh_id) {
            (Some(id), _) => self.find_query(&st, ctx, id)?,
            (None, Some(r)) => st
                .accounts
                .get(&ctx.caller.account_id)
                .and_then(|a| {
                    a.queries.values().find(|q| {
                        q.refresh_id.as_deref() == Some(r)
                            && (input.query_alias.is_none() || q.alias == input.query_alias)
                    })
                })
                .ok_or_else(|| query_not_found(r))?,
            (None, None) => {
                return Err(errors::invalid_parameter("You must specify a QueryId, or a QueryAlias and RefreshId."))
            }
        };
        let resource = q.event_data_stores.first().cloned().unwrap_or_else(|| "*".into());
        ctx.authorize("cloudtrail:DescribeQuery", &resource, ConditionContext::new())?;
        Ok(types::DescribeQueryResponse {
            query_id: Some(q.id.clone()),
            query_string: Some(q.statement.clone()),
            query_status: Some(q.status.clone()),
            query_statistics: Some(types::QueryStatisticsForDescribeQuery {
                events_matched: Some(q.events_matched),
                events_scanned: Some(q.events_scanned),
                bytes_scanned: Some(q.bytes_scanned),
                execution_time_in_millis: Some(q.execution_time_ms),
                creation_time: Some(q.created),
            }),
            error_message: q.error_message.clone(),
            delivery_s3_uri: q.delivery_s3_uri.clone(),
            delivery_status: q.delivery_status.clone(),
            prompt: q.prompt.clone(),
            event_data_store_owner_account_id: None,
        })
    }

    pub(crate) fn get_query_results(
        &self,
        ctx: &RequestContext,
        input: types::GetQueryResultsRequest,
    ) -> Result<types::GetQueryResultsResponse, ServiceError> {
        let max = input.max_query_results.unwrap_or(1000);
        if !(1..=1000).contains(&max) {
            return Err(errors::invalid_max_results("MaxQueryResults must be between 1 and 1000."));
        }
        let st = self.lock();
        let q = self.find_query(&st, ctx, &input.query_id)?;
        let resource = q.event_data_stores.first().cloned().unwrap_or_else(|| "*".into());
        ctx.authorize("cloudtrail:GetQueryResults", &resource, ConditionContext::new())?;
        let rows: Vec<Vec<std::collections::BTreeMap<String, String>>> = q
            .rows
            .iter()
            .map(|r| {
                q.columns
                    .iter()
                    .zip(r)
                    .filter_map(|(c, v)| v.as_ref().map(|v| std::collections::BTreeMap::from([(c.clone(), v.clone())])))
                    .collect()
            })
            .collect();
        let (page, next) = names::page(&rows, input.next_token.as_deref(), max as usize)?;
        Ok(types::GetQueryResultsResponse {
            query_status: Some(q.status.clone()),
            query_statistics: Some(types::QueryStatistics {
                results_count: Some(page.len() as i32),
                total_results_count: Some(rows.len() as i32),
                bytes_scanned: Some(q.bytes_scanned),
            }),
            query_result_rows: Some(page),
            next_token: next,
            error_message: q.error_message.clone(),
        })
    }

    pub(crate) fn cancel_query(
        &self,
        ctx: &RequestContext,
        input: types::CancelQueryRequest,
    ) -> Result<types::CancelQueryResponse, ServiceError> {
        let st = self.lock();
        let q = self.find_query(&st, ctx, &input.query_id)?;
        let resource = q.event_data_stores.first().cloned().unwrap_or_else(|| "*".into());
        ctx.authorize("cloudtrail:CancelQuery", &resource, ConditionContext::new())?;
        // Queries finish as they are started, so there is never one to
        // cancel.
        Err(errors::inactive_query(format!(
            "The specified query cannot be canceled because it is in the {} state.",
            q.status
        )))
    }

    pub(crate) fn list_queries(
        &self,
        ctx: &RequestContext,
        input: types::ListQueriesRequest,
    ) -> Result<types::ListQueriesResponse, ServiceError> {
        let st = self.lock();
        let arn = self.eds_key(&st, ctx, &input.event_data_store)?;
        ctx.authorize("cloudtrail:ListQueries", &arn, ConditionContext::new())?;
        if let (Some(s), Some(e)) = (input.start_time, input.end_time) {
            if s > e {
                return Err(errors::invalid_date_range("Start time must be before end time."));
            }
        }
        if let Some(s) = &input.query_status {
            if !types::QUERY_STATUS.contains(&s.as_str()) {
                return Err(errors::invalid_query_status(format!("Query status {s} is not valid.")));
            }
        }
        let mut all: Vec<&Query> = st.accounts[&ctx.caller.account_id]
            .queries
            .values()
            .filter(|q| q.event_data_stores.contains(&arn))
            .filter(|q| {
                input.start_time.is_none_or(|s| q.created >= s) && input.end_time.is_none_or(|e| q.created <= e)
            })
            .filter(|q| input.query_status.as_ref().is_none_or(|s| &q.status == s))
            .collect();
        all.sort_by_key(|q| std::cmp::Reverse(q.created));
        let all: Vec<types::Query> = all
            .into_iter()
            .map(|q| types::Query {
                query_id: Some(q.id.clone()),
                query_status: Some(q.status.clone()),
                creation_time: Some(q.created),
            })
            .collect();
        let (page, next) =
            names::page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(1000).max(1) as usize)?;
        Ok(types::ListQueriesResponse { queries: Some(page), next_token: next })
    }

    pub(crate) fn generate_query(
        &self,
        ctx: &RequestContext,
        input: types::GenerateQueryRequest,
    ) -> Result<types::GenerateQueryResponse, ServiceError> {
        let st = self.lock();
        let mut ids = Vec::new();
        for e in &input.event_data_stores {
            let arn = self.eds_key(&st, ctx, e)?;
            ctx.authorize("cloudtrail:GenerateQuery", &arn, ConditionContext::new())?;
            ids.push(Self::eds(&st, ctx, &arn).id().to_string());
        }
        // No model writes the SQL: a few patterns in the prompt pick the
        // filter.
        let prompt = input.prompt.to_lowercase();
        let mut filters = Vec::new();
        if prompt.contains("error") || prompt.contains("fail") || prompt.contains("denied") {
            filters.push("errorCode IS NOT NULL".to_string());
        }
        if prompt.contains("write") || prompt.contains("change") {
            filters.push("readOnly = false".to_string());
        }
        for word in input.prompt.split(|c: char| !c.is_ascii_alphanumeric()) {
            if word.len() > 3
                && word.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && word.chars().any(|c| c.is_ascii_lowercase())
            {
                filters.push(format!("eventName = '{word}'"));
                break;
            }
        }
        let filter = if filters.is_empty() { String::new() } else { format!(" WHERE {}", filters.join(" AND ")) };
        let statement = format!(
            "SELECT eventTime, eventSource, eventName, userIdentity.arn, errorCode FROM {}{filter} ORDER BY eventTime DESC LIMIT 100",
            ids.first().cloned().unwrap_or_default()
        );
        Ok(types::GenerateQueryResponse {
            query_statement: Some(statement),
            query_alias: Some(format!("generated-{}", &uuid::Uuid::new_v4().to_string()[..8])),
            event_data_store_owner_account_id: None,
        })
    }

    pub(crate) fn search_sample_queries(
        &self,
        ctx: &RequestContext,
        input: types::SearchSampleQueriesRequest,
    ) -> Result<types::SearchSampleQueriesResponse, ServiceError> {
        ctx.authorize("cloudtrail:SearchSampleQueries", "*", ConditionContext::new())?;
        const SAMPLES: &[(&str, &str, &str)] = &[
            ("Top API calls", "The most frequent API calls in the event data store.", "SELECT eventName, COUNT(*) AS numberOfCalls FROM $EDS_ID GROUP BY eventName ORDER BY COUNT(*) DESC LIMIT 10"),
            ("Access denied errors", "Calls that failed with an access denied error.", "SELECT eventTime, eventSource, eventName, userIdentity.arn, errorCode FROM $EDS_ID WHERE errorCode IN ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation')"),
            ("Console sign-ins", "Console sign-in events.", "SELECT eventTime, userIdentity.arn, sourceIPAddress FROM $EDS_ID WHERE eventName = 'ConsoleLogin'"),
            ("Root user activity", "API calls made by the root user.", "SELECT eventTime, eventSource, eventName FROM $EDS_ID WHERE userIdentity.type = 'Root'"),
            ("S3 bucket changes", "Changes to S3 bucket configuration.", "SELECT eventTime, eventName, element_at(requestParameters, 'bucketName') AS bucket FROM $EDS_ID WHERE eventSource = 's3.amazonaws.com' AND readOnly = false"),
            ("IAM user creation", "IAM users created.", "SELECT eventTime, userIdentity.arn, element_at(requestParameters, 'userName') AS userName FROM $EDS_ID WHERE eventName = 'CreateUser'"),
            ("Activity by user", "API calls per principal.", "SELECT userIdentity.arn, COUNT(*) AS calls FROM $EDS_ID GROUP BY userIdentity.arn ORDER BY calls DESC"),
            ("KMS key deletions", "KMS keys scheduled for deletion.", "SELECT eventTime, userIdentity.arn, element_at(requestParameters, 'keyId') AS keyId FROM $EDS_ID WHERE eventName = 'ScheduleKeyDeletion'"),
        ];
        let words: Vec<String> = input.search_phrase.to_lowercase().split_whitespace().map(str::to_string).collect();
        let mut results: Vec<types::SearchSampleQueriesSearchResult> = SAMPLES
            .iter()
            .filter_map(|(name, description, sql)| {
                let text = format!("{name} {description} {sql}").to_lowercase();
                let hits = words.iter().filter(|w| text.contains(w.as_str())).count();
                (hits > 0).then(|| types::SearchSampleQueriesSearchResult {
                    name: Some(name.to_string()),
                    description: Some(description.to_string()),
                    sql: Some(sql.to_string()),
                    relevance: hits as f32 / words.len().max(1) as f32,
                })
            })
            .collect();
        results.sort_by(|a, b| b.relevance.partial_cmp(&a.relevance).unwrap_or(std::cmp::Ordering::Equal));
        let (page, next) =
            names::page(&results, input.next_token.as_deref(), input.max_results.unwrap_or(10).max(1) as usize)?;
        Ok(types::SearchSampleQueriesResponse { search_results: Some(page), next_token: next })
    }

    // ---- imports -----------------------------------------------------------

    pub(crate) fn start_import(
        &self,
        ctx: &RequestContext,
        input: types::StartImportRequest,
    ) -> Result<types::StartImportResponse, ServiceError> {
        // Restarting an existing import.
        if let Some(id) = &input.import_id {
            let existing = self.lock().accounts.get(&ctx.caller.account_id).and_then(|a| a.imports.get(id)).cloned();
            let i = existing.ok_or_else(|| errors::import_not_found(format!("Import {id} was not found.")))?;
            return self.run_import(ctx, i);
        }
        let destinations = input.destinations.unwrap_or_default();
        let source = input
            .import_source
            .ok_or_else(|| errors::invalid_parameter("You must specify ImportSource and Destinations."))?;
        if destinations.is_empty() {
            return Err(errors::invalid_parameter("You must specify ImportSource and Destinations."));
        }
        {
            let st = self.lock();
            for d in &destinations {
                let arn = self.active_eds(&st, ctx, d)?;
                ctx.authorize("cloudtrail:StartImport", &arn, ConditionContext::new())?;
                if !matches!(Self::eds(&st, ctx, &arn).category().as_deref(), Some("Management") | Some("Data")) {
                    return Err(errors::invalid_event_data_store_category(
                        "Imports can only go to event data stores that collect CloudTrail events.",
                    ));
                }
            }
        }
        if let (Some(s), Some(e)) = (input.start_event_time, input.end_event_time) {
            if s > e {
                return Err(errors::invalid_parameter("StartEventTime must be before EndEventTime."));
            }
        }
        let now = ctx.received_at;
        let import = Import {
            id: uuid::Uuid::new_v4().to_string(),
            destinations,
            source,
            start_event_time: input.start_event_time,
            end_event_time: input.end_event_time,
            status: "INITIALIZING".into(),
            created: now,
            updated: now,
            ..Import::default()
        };
        self.run_import(ctx, import)
    }

    /// Read trail log files from S3 (as the import's role) into the
    /// destinations.
    fn run_import(&self, ctx: &RequestContext, mut i: Import) -> Result<types::StartImportResponse, ServiceError> {
        let s = &i.source.s3;
        let rest = s.s3_location_uri.strip_prefix("s3://").ok_or_else(|| {
            errors::invalid_import_source(format!("The S3 location {} is not valid.", s.s3_location_uri))
        })?;
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let s3 = self.inner.s3.get().ok_or_else(|| errors::invalid_import_source("S3 is not available."))?;
        if let Some(sts) = self.inner.sts.get() {
            let role_ctx = self
                .role_context(sts, ctx, &s.s3_bucket_access_role_arn, &i.destinations[0])
                .map_err(|_| errors::invalid_import_source("CloudTrail cannot assume the S3 bucket access role."))?;
            role_ctx
                .authorize("s3:ListBucket", &format!("arn:{}:s3:::{bucket}", ctx.partition), ConditionContext::new())
                .map_err(|_| errors::invalid_import_source("The S3 bucket access role cannot list the bucket."))?;
        }
        let keys = s3
            .object_keys(bucket, prefix)
            .ok_or_else(|| errors::invalid_import_source(format!("The S3 bucket {bucket} does not exist.")))?;
        let mut events = Vec::new();
        let mut stats =
            types::ImportStatistics { prefixes_found: Some(1), prefixes_completed: Some(1), ..Default::default() };
        let (mut files, mut failed) = (0i64, 0i64);
        i.failures.clear();
        for key in keys.iter().filter(|k| k.ends_with(".json.gz") && k.contains("/CloudTrail/")) {
            let parsed = s3.object_bytes(bucket, key).and_then(|b| {
                let mut plain = Vec::new();
                flate2::read::GzDecoder::new(&b[..]).read_to_end(&mut plain).ok()?;
                serde_json::from_slice::<Value>(&plain).ok()
            });
            match parsed.as_ref().and_then(|v| v.get("Records")).and_then(Value::as_array) {
                Some(records) => {
                    files += 1;
                    for r in records {
                        let t = r
                            .get("eventTime")
                            .and_then(Value::as_str)
                            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                            .map(|t| t.with_timezone(&chrono::Utc));
                        let inside = t.is_some_and(|t| {
                            i.start_event_time.is_none_or(|s| t >= s) && i.end_event_time.is_none_or(|e| t <= e)
                        });
                        if inside {
                            events.push(r.clone());
                        }
                    }
                }
                None => {
                    failed += 1;
                    i.failures.push(types::ImportFailureListItem {
                        location: Some(format!("s3://{bucket}/{key}")),
                        status: Some("FAILED".into()),
                        error_type: Some("FileParseError".into()),
                        error_message: Some("The file is not a CloudTrail log file.".into()),
                        last_updated_time: Some(ctx.received_at),
                    });
                }
            }
        }
        stats.files_completed = Some(files);
        stats.events_completed = Some(events.len() as i64);
        stats.failed_entries = Some(failed);
        i.statistics = stats;
        i.status = "COMPLETED".into();
        i.updated = ctx.received_at;
        let mut st = self.lock();
        for d in i.destinations.clone() {
            if let Ok(arn) = self.eds_key(&st, ctx, &d) {
                let e = Self::eds_mut(&mut st, ctx, &arn);
                e.events.extend(events.iter().cloned());
                e.events.sort_by(|a, b| {
                    let t = |v: &Value| v.get("eventTime").and_then(Value::as_str).unwrap_or_default().to_string();
                    t(a).cmp(&t(b))
                });
            }
        }
        st.account(&ctx.caller.account_id).imports.insert(i.id.clone(), i.clone());
        Ok(types::StartImportResponse {
            import_id: Some(i.id),
            destinations: Some(i.destinations),
            import_source: Some(i.source),
            start_event_time: i.start_event_time,
            end_event_time: i.end_event_time,
            import_status: Some(i.status),
            created_timestamp: Some(i.created),
            updated_timestamp: Some(i.updated),
        })
    }

    fn find_import(&self, ctx: &RequestContext, id: &str) -> Result<Import, ServiceError> {
        ctx.authorize("cloudtrail:GetImport", "*", ConditionContext::new())?;
        self.lock()
            .accounts
            .get(&ctx.caller.account_id)
            .and_then(|a| a.imports.get(id))
            .cloned()
            .ok_or_else(|| errors::import_not_found(format!("Import {id} was not found.")))
    }

    pub(crate) fn get_import(
        &self,
        ctx: &RequestContext,
        input: types::GetImportRequest,
    ) -> Result<types::GetImportResponse, ServiceError> {
        let i = self.find_import(ctx, &input.import_id)?;
        Ok(types::GetImportResponse {
            import_id: Some(i.id),
            destinations: Some(i.destinations),
            import_source: Some(i.source),
            start_event_time: i.start_event_time,
            end_event_time: i.end_event_time,
            import_status: Some(i.status),
            created_timestamp: Some(i.created),
            updated_timestamp: Some(i.updated),
            import_statistics: Some(i.statistics),
        })
    }

    pub(crate) fn stop_import(
        &self,
        ctx: &RequestContext,
        input: types::StopImportRequest,
    ) -> Result<types::StopImportResponse, ServiceError> {
        let mut i = self.find_import(ctx, &input.import_id)?;
        ctx.authorize("cloudtrail:StopImport", "*", ConditionContext::new())?;
        if matches!(i.status.as_str(), "INITIALIZING" | "IN_PROGRESS") {
            i.status = "STOPPED".into();
            i.updated = ctx.received_at;
            self.lock().account(&ctx.caller.account_id).imports.insert(i.id.clone(), i.clone());
        }
        Ok(types::StopImportResponse {
            import_id: Some(i.id),
            import_source: Some(i.source),
            destinations: Some(i.destinations),
            import_status: Some(i.status),
            created_timestamp: Some(i.created),
            updated_timestamp: Some(i.updated),
            start_event_time: i.start_event_time,
            end_event_time: i.end_event_time,
            import_statistics: Some(i.statistics),
        })
    }

    pub(crate) fn list_imports(
        &self,
        ctx: &RequestContext,
        input: types::ListImportsRequest,
    ) -> Result<types::ListImportsResponse, ServiceError> {
        ctx.authorize("cloudtrail:ListImports", "*", ConditionContext::new())?;
        let st = self.lock();
        let dest = match &input.destination {
            Some(d) => Some(self.eds_key(&st, ctx, d)?),
            None => None,
        };
        let all: Vec<types::ImportsListItem> = st
            .accounts
            .get(&ctx.caller.account_id)
            .into_iter()
            .flat_map(|a| a.imports.values())
            .filter(|i| dest.as_ref().is_none_or(|d| i.destinations.iter().any(|x| x == d || d.ends_with(x.as_str()))))
            .filter(|i| input.import_status.as_ref().is_none_or(|s| &i.status == s))
            .map(|i| types::ImportsListItem {
                import_id: Some(i.id.clone()),
                import_status: Some(i.status.clone()),
                destinations: Some(i.destinations.clone()),
                created_timestamp: Some(i.created),
                updated_timestamp: Some(i.updated),
            })
            .collect();
        let (page, next) =
            names::page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(1000).max(1) as usize)?;
        Ok(types::ListImportsResponse { imports: Some(page), next_token: next })
    }

    pub(crate) fn list_import_failures(
        &self,
        ctx: &RequestContext,
        input: types::ListImportFailuresRequest,
    ) -> Result<types::ListImportFailuresResponse, ServiceError> {
        let i = self.find_import(ctx, &input.import_id)?;
        let (page, next) =
            names::page(&i.failures, input.next_token.as_deref(), input.max_results.unwrap_or(1000).max(1) as usize)?;
        Ok(types::ListImportFailuresResponse { failures: Some(page), next_token: next })
    }

    // ---- channels ----------------------------------------------------------

    fn check_destinations(
        &self,
        st: &State,
        ctx: &RequestContext,
        d: &mut [types::Destination],
    ) -> Result<(), ServiceError> {
        if d.is_empty() || d.len() > 200 {
            return Err(errors::invalid_parameter("A channel must have between 1 and 200 destinations."));
        }
        for dest in d {
            match dest.r#type.as_str() {
                "EVENT_DATA_STORE" => {
                    let arn = self.active_eds(st, ctx, &dest.location)?;
                    if Self::eds(st, ctx, &arn).category().as_deref() != Some("ActivityAuditLog") {
                        return Err(errors::invalid_event_data_store_category(format!(
                            "Event data store {arn} does not collect events from integrations (eventCategory ActivityAuditLog)."
                        )));
                    }
                    dest.location = arn;
                }
                "AWS_SERVICE" => {}
                other => return Err(errors::invalid_parameter(format!("Destination type {other} is not valid."))),
            }
        }
        Ok(())
    }

    fn find_channel(&self, st: &State, ctx: &RequestContext, id: &str) -> Result<String, ServiceError> {
        if id.starts_with("arn:") && names::parse_arn(id).is_none_or(|a| a.kind != "channel") {
            return Err(errors::channel_arn_invalid(format!("Channel ARN {id} is not valid.")));
        }
        st.accounts
            .get(&ctx.caller.account_id)
            .into_iter()
            .flat_map(|a| a.channels.values())
            .find(|c| c.arn == id || c.arn.ends_with(&format!("/{id}")))
            .map(|c| c.arn.clone())
            .ok_or_else(|| errors::channel_not_found(format!("Channel {id} was not found.")))
    }

    pub(crate) fn create_channel(
        &self,
        ctx: &RequestContext,
        input: types::CreateChannelRequest,
    ) -> Result<types::CreateChannelResponse, ServiceError> {
        let arn = channel_arn(ctx, &uuid::Uuid::new_v4().to_string());
        ctx.authorize("cloudtrail:CreateChannel", &arn, ConditionContext::new())?;
        validate_lake_name(&input.name, "Channel")?;
        if input.source != "Custom" && !input.source.starts_with("arn:") && input.source.is_empty() {
            return Err(errors::invalid_source(format!("Source {} is not valid.", input.source)));
        }
        let tags = input.tags.clone().unwrap_or_default();
        check_tags(&tags)?;
        let mut st = self.lock();
        let mut destinations = input.destinations.clone();
        self.check_destinations(&st, ctx, &mut destinations)?;
        let account = st.account(&ctx.caller.account_id);
        if account.channels.values().any(|c| c.name == input.name) {
            return Err(errors::channel_already_exists(format!("Channel {} already exists.", input.name)));
        }
        if account.channels.len() >= MAX_CHANNELS {
            return Err(errors::channel_max_limit_exceeded("The maximum number of channels has been reached."));
        }
        account.channels.insert(
            arn.clone(),
            Channel {
                arn: arn.clone(),
                name: input.name.clone(),
                source: input.source.clone(),
                destinations: destinations.clone(),
                tags: tags.clone(),
                apply_to_all_regions: false,
                advanced_event_selectors: Vec::new(),
            },
        );
        Ok(types::CreateChannelResponse {
            channel_arn: Some(arn),
            name: Some(input.name),
            source: Some(input.source),
            destinations: Some(destinations),
            tags: Some(tags),
        })
    }

    pub(crate) fn get_channel(
        &self,
        ctx: &RequestContext,
        input: types::GetChannelRequest,
    ) -> Result<types::GetChannelResponse, ServiceError> {
        let st = self.lock();
        let arn = self.find_channel(&st, ctx, &input.channel)?;
        ctx.authorize("cloudtrail:GetChannel", &arn, ConditionContext::new())?;
        let c = &st.accounts[&ctx.caller.account_id].channels[&arn];
        Ok(types::GetChannelResponse {
            channel_arn: Some(c.arn.clone()),
            name: Some(c.name.clone()),
            source: Some(c.source.clone()),
            source_config: Some(types::SourceConfig {
                apply_to_all_regions: Some(c.apply_to_all_regions),
                advanced_event_selectors: Some(c.advanced_event_selectors.clone()),
            }),
            destinations: Some(c.destinations.clone()),
            ingestion_status: Some(types::IngestionStatus::default()),
        })
    }

    pub(crate) fn list_channels(
        &self,
        ctx: &RequestContext,
        input: types::ListChannelsRequest,
    ) -> Result<types::ListChannelsResponse, ServiceError> {
        ctx.authorize("cloudtrail:ListChannels", "*", ConditionContext::new())?;
        let st = self.lock();
        let all: Vec<types::Channel> = st
            .accounts
            .get(&ctx.caller.account_id)
            .into_iter()
            .flat_map(|a| a.channels.values())
            .map(|c| types::Channel { channel_arn: Some(c.arn.clone()), name: Some(c.name.clone()) })
            .collect();
        let (page, next) =
            names::page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(1000).max(1) as usize)?;
        Ok(types::ListChannelsResponse { channels: Some(page), next_token: next })
    }

    pub(crate) fn update_channel(
        &self,
        ctx: &RequestContext,
        input: types::UpdateChannelRequest,
    ) -> Result<types::UpdateChannelResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.find_channel(&st, ctx, &input.channel)?;
        ctx.authorize("cloudtrail:UpdateChannel", &arn, ConditionContext::new())?;
        let mut destinations = None;
        if let Some(mut d) = input.destinations {
            self.check_destinations(&st, ctx, &mut d)?;
            destinations = Some(d);
        }
        if let Some(n) = &input.name {
            validate_lake_name(n, "Channel")?;
            if st.accounts[&ctx.caller.account_id].channels.values().any(|c| &c.name == n && c.arn != arn) {
                return Err(errors::channel_already_exists(format!("Channel {n} already exists.")));
            }
        }
        let c = st.account(&ctx.caller.account_id).channels.get_mut(&arn).expect("channel exists");
        if let Some(n) = input.name {
            c.name = n;
        }
        if let Some(d) = destinations {
            c.destinations = d;
        }
        Ok(types::UpdateChannelResponse {
            channel_arn: Some(c.arn.clone()),
            name: Some(c.name.clone()),
            source: Some(c.source.clone()),
            destinations: Some(c.destinations.clone()),
        })
    }

    pub(crate) fn delete_channel(
        &self,
        ctx: &RequestContext,
        input: types::DeleteChannelRequest,
    ) -> Result<types::DeleteChannelResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.find_channel(&st, ctx, &input.channel)?;
        ctx.authorize("cloudtrail:DeleteChannel", &arn, ConditionContext::new())?;
        let a = st.account(&ctx.caller.account_id);
        a.channels.remove(&arn);
        a.resource_policies.remove(&arn);
        Ok(types::DeleteChannelResponse {})
    }

    // ---- dashboards --------------------------------------------------------

    fn find_dashboard(&self, st: &State, ctx: &RequestContext, id: &str) -> Result<String, ServiceError> {
        st.accounts
            .get(&ctx.caller.account_id)
            .into_iter()
            .flat_map(|a| a.dashboards.values())
            .find(|d| d.arn == id || d.name == id)
            .map(|d| d.arn.clone())
            .ok_or_else(|| errors::resource_not_found(format!("Dashboard {id} was not found.")))
    }

    fn check_widgets(
        &self,
        st: &State,
        ctx: &RequestContext,
        widgets: &[types::RequestWidget],
    ) -> Result<Vec<types::Widget>, ServiceError> {
        if widgets.len() > 10 {
            return Err(errors::invalid_parameter("A dashboard can have at most 10 widgets."));
        }
        let mut out = Vec::new();
        for w in widgets {
            let q = sql::parse(&w.query_statement.replace('?', "''"))
                .map_err(|e| errors::invalid_query_statement(format!("Query statement is not valid: {e}")))?;
            for from in &q.from {
                self.active_eds(st, ctx, from)?;
            }
            out.push(types::Widget {
                query_alias: None,
                query_statement: Some(w.query_statement.clone()),
                query_parameters: w.query_parameters.clone(),
                view_properties: Some(w.view_properties.clone()),
            });
        }
        Ok(out)
    }

    pub(crate) fn create_dashboard(
        &self,
        ctx: &RequestContext,
        input: types::CreateDashboardRequest,
    ) -> Result<types::CreateDashboardResponse, ServiceError> {
        let arn = dashboard_arn(ctx, &input.name);
        ctx.authorize("cloudtrail:CreateDashboard", &arn, ConditionContext::new())?;
        validate_lake_name(&input.name, "Dashboard")?;
        let tags = input.tags_list.clone().unwrap_or_default();
        check_tags(&tags)?;
        let mut st = self.lock();
        let widgets = self.check_widgets(&st, ctx, input.widgets.as_deref().unwrap_or_default())?;
        let account = st.account(&ctx.caller.account_id);
        if account.dashboards.contains_key(&arn) {
            return Err(errors::conflict(format!("Dashboard {} already exists.", input.name)));
        }
        let d = Dashboard {
            arn: arn.clone(),
            name: input.name.clone(),
            kind: "CUSTOM".into(),
            status: "CREATED".into(),
            widgets: widgets.clone(),
            refresh_schedule: input.refresh_schedule.clone(),
            termination_protection_enabled: input.termination_protection_enabled.unwrap_or(false),
            created: ctx.received_at,
            updated: ctx.received_at,
            tags: tags.clone(),
            ..Dashboard::default()
        };
        account.dashboards.insert(arn.clone(), d);
        Ok(types::CreateDashboardResponse {
            dashboard_arn: Some(arn),
            name: Some(input.name),
            r#type: Some("CUSTOM".into()),
            widgets: Some(widgets),
            tags_list: Some(tags),
            refresh_schedule: input.refresh_schedule,
            termination_protection_enabled: Some(input.termination_protection_enabled.unwrap_or(false)),
        })
    }

    pub(crate) fn get_dashboard(
        &self,
        ctx: &RequestContext,
        input: types::GetDashboardRequest,
    ) -> Result<types::GetDashboardResponse, ServiceError> {
        let st = self.lock();
        let arn = self.find_dashboard(&st, ctx, &input.dashboard_id)?;
        ctx.authorize("cloudtrail:GetDashboard", &arn, ConditionContext::new())?;
        let d = &st.accounts[&ctx.caller.account_id].dashboards[&arn];
        Ok(types::GetDashboardResponse {
            dashboard_arn: Some(d.arn.clone()),
            r#type: Some(d.kind.clone()),
            status: Some(d.status.clone()),
            widgets: Some(d.widgets.clone()),
            refresh_schedule: d.refresh_schedule.clone(),
            created_timestamp: Some(d.created),
            updated_timestamp: Some(d.updated),
            last_refresh_id: d.last_refresh_id.clone(),
            last_refresh_failure_reason: d.last_refresh_failure_reason.clone(),
            termination_protection_enabled: Some(d.termination_protection_enabled),
        })
    }

    pub(crate) fn list_dashboards(
        &self,
        ctx: &RequestContext,
        input: types::ListDashboardsRequest,
    ) -> Result<types::ListDashboardsResponse, ServiceError> {
        ctx.authorize("cloudtrail:ListDashboards", "*", ConditionContext::new())?;
        let st = self.lock();
        let all: Vec<types::DashboardDetail> = st
            .accounts
            .get(&ctx.caller.account_id)
            .into_iter()
            .flat_map(|a| a.dashboards.values())
            .filter(|d| input.name_prefix.as_ref().is_none_or(|p| d.name.starts_with(p.as_str())))
            .filter(|d| input.r#type.as_ref().is_none_or(|t| &d.kind == t))
            .map(|d| types::DashboardDetail { dashboard_arn: Some(d.arn.clone()), r#type: Some(d.kind.clone()) })
            .collect();
        let (page, next) =
            names::page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(1000).max(1) as usize)?;
        Ok(types::ListDashboardsResponse { dashboards: Some(page), next_token: next })
    }

    pub(crate) fn update_dashboard(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDashboardRequest,
    ) -> Result<types::UpdateDashboardResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.find_dashboard(&st, ctx, &input.dashboard_id)?;
        ctx.authorize("cloudtrail:UpdateDashboard", &arn, ConditionContext::new())?;
        let widgets = match &input.widgets {
            Some(w) => Some(self.check_widgets(&st, ctx, w)?),
            None => None,
        };
        let d = st.account(&ctx.caller.account_id).dashboards.get_mut(&arn).expect("dashboard exists");
        if let Some(w) = widgets {
            d.widgets = w;
        }
        if input.refresh_schedule.is_some() {
            d.refresh_schedule = input.refresh_schedule;
        }
        if let Some(t) = input.termination_protection_enabled {
            d.termination_protection_enabled = t;
        }
        d.status = "UPDATED".into();
        d.updated = ctx.received_at;
        Ok(types::UpdateDashboardResponse {
            dashboard_arn: Some(d.arn.clone()),
            name: Some(d.name.clone()),
            r#type: Some(d.kind.clone()),
            widgets: Some(d.widgets.clone()),
            refresh_schedule: d.refresh_schedule.clone(),
            termination_protection_enabled: Some(d.termination_protection_enabled),
            created_timestamp: Some(d.created),
            updated_timestamp: Some(d.updated),
        })
    }

    pub(crate) fn delete_dashboard(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDashboardRequest,
    ) -> Result<types::DeleteDashboardResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.find_dashboard(&st, ctx, &input.dashboard_id)?;
        ctx.authorize("cloudtrail:DeleteDashboard", &arn, ConditionContext::new())?;
        let a = st.account(&ctx.caller.account_id);
        if a.dashboards[&arn].termination_protection_enabled {
            return Err(errors::conflict(format!(
                "Dashboard {arn} cannot be deleted because termination protection is enabled."
            )));
        }
        a.dashboards.remove(&arn);
        a.resource_policies.remove(&arn);
        Ok(types::DeleteDashboardResponse {})
    }

    pub(crate) fn start_dashboard_refresh(
        &self,
        ctx: &RequestContext,
        input: types::StartDashboardRefreshRequest,
    ) -> Result<types::StartDashboardRefreshResponse, ServiceError> {
        let widgets = {
            let st = self.lock();
            let arn = self.find_dashboard(&st, ctx, &input.dashboard_id)?;
            ctx.authorize("cloudtrail:StartDashboardRefresh", &arn, ConditionContext::new())?;
            let widgets = st.accounts[&ctx.caller.account_id].dashboards[&arn].widgets.clone();
            (arn, widgets)
        };
        let (arn, widgets) = widgets;
        let refresh_id = uuid::Uuid::new_v4().to_string();
        let values = input.query_parameter_values.unwrap_or_default();
        let mut ids = Vec::new();
        let mut failure = None;
        for w in &widgets {
            // `$StartTime$`-style parameters take the given values.
            let params: Vec<String> = w
                .query_parameters
                .iter()
                .flatten()
                .map(|p| {
                    values.get(p.trim_matches('$')).or_else(|| values.get(p)).cloned().unwrap_or_else(|| p.clone())
                })
                .collect();
            match self.run_query(
                ctx,
                w.query_statement.as_deref().unwrap_or_default(),
                &params,
                None,
                w.query_alias.clone(),
                Some(refresh_id.clone()),
            ) {
                Ok(id) => ids.push(id),
                Err(e) => failure = Some(e.message.to_string()),
            }
        }
        let mut st = self.lock();
        if let Some(d) = st.account(&ctx.caller.account_id).dashboards.get_mut(&arn) {
            d.last_refresh_id = Some(refresh_id.clone());
            d.last_refresh_failure_reason = failure;
            d.refreshes.insert(refresh_id.clone(), ids);
        }
        Ok(types::StartDashboardRefreshResponse { refresh_id: Some(refresh_id) })
    }

    // ---- federation and delegated administrators ---------------------------

    pub(crate) fn enable_federation(
        &self,
        ctx: &RequestContext,
        input: types::EnableFederationRequest,
    ) -> Result<types::EnableFederationResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.active_eds(&st, ctx, &input.event_data_store)?;
        ctx.authorize("cloudtrail:EnableFederation", &arn, ConditionContext::new())?;
        let mut pass = ConditionContext::new();
        pass.insert("iam:PassedToService".into(), vec!["cloudtrail.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", &input.federation_role_arn, pass)?;
        let e = Self::eds_mut(&mut st, ctx, &arn);
        if e.federation_status.as_deref() == Some("ENABLED") {
            return Err(errors::event_data_store_federation_enabled(format!(
                "Federation is already enabled for event data store {arn}."
            )));
        }
        e.federation_status = Some("ENABLED".into());
        e.federation_role_arn = Some(input.federation_role_arn.clone());
        Ok(types::EnableFederationResponse {
            event_data_store_arn: Some(arn),
            federation_status: Some("ENABLED".into()),
            federation_role_arn: Some(input.federation_role_arn),
        })
    }

    pub(crate) fn disable_federation(
        &self,
        ctx: &RequestContext,
        input: types::DisableFederationRequest,
    ) -> Result<types::DisableFederationResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.active_eds(&st, ctx, &input.event_data_store)?;
        ctx.authorize("cloudtrail:DisableFederation", &arn, ConditionContext::new())?;
        let e = Self::eds_mut(&mut st, ctx, &arn);
        e.federation_status = Some("DISABLED".into());
        e.federation_role_arn = None;
        Ok(types::DisableFederationResponse {
            event_data_store_arn: Some(arn),
            federation_status: Some("DISABLED".into()),
        })
    }

    fn management_account(&self, ctx: &RequestContext) -> Result<String, ServiceError> {
        let account = &ctx.caller.account_id;
        let org = self
            .organization(account)
            .ok_or_else(|| errors::organizations_not_in_use("This account is not part of an organization."))?;
        if !org.is_management(account) {
            return Err(errors::not_organization_management_account(
                "This operation can be performed only by the management account of the organization.",
            ));
        }
        if !org.all_features {
            return Err(errors::organization_not_in_all_features_mode(
                "This organization is in consolidated billing mode. All features must be enabled.",
            ));
        }
        Ok(account.clone())
    }

    pub(crate) fn register_organization_delegated_admin(
        &self,
        ctx: &RequestContext,
        input: types::RegisterOrganizationDelegatedAdminRequest,
    ) -> Result<types::RegisterOrganizationDelegatedAdminResponse, ServiceError> {
        ctx.authorize("cloudtrail:RegisterOrganizationDelegatedAdmin", "*", ConditionContext::new())?;
        let mgmt = self.management_account(ctx)?;
        let member = &input.member_account_id;
        if member == &mgmt {
            return Err(errors::cannot_delegate_management_account(
                "You cannot register the management account as a delegated administrator.",
            ));
        }
        let org = self.organization(&mgmt).map(|o| o.organization_id);
        if self.organization(member).map(|o| o.organization_id) != org {
            return Err(errors::account_not_found(format!("Account {member} is not a member of the organization.")));
        }
        let mut st = self.lock();
        let a = st.account(&mgmt);
        if a.delegated_admins.contains(member) {
            return Err(errors::account_registered(format!("Account {member} is already a delegated administrator.")));
        }
        if a.delegated_admins.len() >= 3 {
            return Err(errors::delegated_admin_account_limit_exceeded(
                "The organization already has the maximum number of delegated administrators.",
            ));
        }
        a.delegated_admins.insert(member.clone());
        Ok(types::RegisterOrganizationDelegatedAdminResponse {})
    }

    pub(crate) fn deregister_organization_delegated_admin(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterOrganizationDelegatedAdminRequest,
    ) -> Result<types::DeregisterOrganizationDelegatedAdminResponse, ServiceError> {
        ctx.authorize("cloudtrail:DeregisterOrganizationDelegatedAdmin", "*", ConditionContext::new())?;
        let mgmt = self.management_account(ctx)?;
        if !self.lock().account(&mgmt).delegated_admins.remove(&input.delegated_admin_account_id) {
            return Err(errors::account_not_registered(format!(
                "Account {} is not a delegated administrator.",
                input.delegated_admin_account_id
            )));
        }
        Ok(types::DeregisterOrganizationDelegatedAdminResponse {})
    }
}

/// Event data stores pending deletion for 7 days are gone; expired events
/// leave with their retention period.
fn sweep(st: &mut State, ctx: &RequestContext) {
    let now = ctx.received_at;
    if let Some(a) = st.accounts.get_mut(&ctx.caller.account_id) {
        a.event_data_stores.retain(|_, e| e.deleted_at.is_none_or(|d| now - d < Duration::days(7)));
        for e in a.event_data_stores.values_mut() {
            let cutoff = (now - Duration::days(i64::from(e.retention_period))).to_rfc3339();
            e.events.retain(|r| r.get("eventTime").and_then(Value::as_str).is_none_or(|t| t >= cutoff.as_str()));
        }
    }
}
