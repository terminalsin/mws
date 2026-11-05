//! Connectors: V1 CSPM connectors (Azure) and V2 connectors to Jira
//! Cloud, ServiceNow and Azure, with Jira's OAuth registration and tickets
//! opened for findings. No external system is contacted: Jira connectors
//! connect once `RegisterConnectorV2` completes the OAuth flow, ServiceNow
//! and Azure connectors connect at creation.

use mws_core::{RequestContext, ServiceError};

use crate::common::{self, account, authorize_hub, hub, hub_mut, invalid_input, not_found, paginate};
use crate::generated::{errors, types};
use crate::state::ConnectorRec;
use crate::SecurityHub;

fn health(c: &ConnectorRec) -> types::HealthCheck {
    types::HealthCheck {
        connector_status: c.status.clone(),
        message: (c.status == "PENDING_AUTHORIZATION").then(|| "Complete the authorization in Jira Cloud.".to_string()),
        last_checked_at: c.updated_at,
        issues: None,
    }
}

fn azure_detail(c: &ConnectorRec) -> types::AzureDetail {
    match &c.provider {
        types::ProviderDetail::Azure(a) => a.clone(),
        _ => types::AzureDetail::default(),
    }
}

impl SecurityHub {
    fn find_connector<'h>(h: &'h crate::state::Hub, id: &str, v2: bool) -> Result<&'h ConnectorRec, ServiceError> {
        h.connectors
            .values()
            .find(|c| (c.id == id || c.arn == id) && c.v2 == v2)
            .ok_or_else(|| not_found(format!("Connector {id} not found.")))
    }

    fn insert_connector(
        &self,
        ctx: &RequestContext,
        v2: bool,
        name: String,
        description: Option<String>,
        kms_key_arn: Option<String>,
        provider: types::ProviderDetail,
        tags: std::collections::BTreeMap<String, String>,
    ) -> Result<ConnectorRec, ServiceError> {
        let (provider_name, status) = match &provider {
            types::ProviderDetail::JiraCloud(_) => ("JIRA_CLOUD", "PENDING_AUTHORIZATION"),
            types::ProviderDetail::ServiceNow(_) => ("SERVICENOW", "CONNECTED"),
            types::ProviderDetail::Azure(_) => ("AZURE", "CONNECTED"),
        };
        let mut state = self.write();
        let key = crate::state::key(account(ctx), &ctx.region);
        let h = hub_mut(&mut state, ctx)?;
        if h.connectors.values().any(|c| c.name == name && c.v2 == v2) {
            return Err(errors::conflict(format!("A connector named {name} already exists.")));
        }
        if h.connectors.len() >= 100 {
            return Err(errors::service_quota_exceeded("You can't create more than 100 connectors."));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let arn = common::arn(ctx, &format!("{}/{id}", if v2 { "connectorv2" } else { "connector" }));
        let rec = ConnectorRec {
            id: id.clone(),
            arn: arn.clone(),
            name,
            description,
            v2,
            kms_key_arn,
            provider_name: provider_name.into(),
            provider,
            status: status.into(),
            created_at: ctx.received_at,
            updated_at: ctx.received_at,
            created_by: ctx.caller.arn.clone(),
            tickets: Default::default(),
        };
        h.connectors.insert(id.clone(), rec.clone());
        if !tags.is_empty() {
            h.resource_tags.insert(arn, tags);
        }
        if status == "PENDING_AUTHORIZATION" {
            state.pending_oauth.insert(id.clone(), (key, id));
        }
        Ok(rec)
    }

    fn auth_url(ctx: &RequestContext, c: &ConnectorRec) -> Option<String> {
        (c.status == "PENDING_AUTHORIZATION").then(|| {
            format!(
                "https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=securityhub-{}&scope=read%3Ajira-work%20write%3Ajira-work%20offline_access&redirect_uri=https%3A%2F%2F{}.console.aws.amazon.com%2Fsecurityhub%2Fv2%2Fhome%2Fconnectors&state={}&response_type=code&prompt=consent",
                ctx.region, ctx.region, c.id
            )
        })
    }

    // ---- V2 ----------------------------------------------------------------------

    pub(crate) fn create_connector_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateConnectorV2Request,
    ) -> Result<types::CreateConnectorV2Response, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        common::authorize_with(ctx, "CreateConnectorV2", &common::hub_arn(ctx, account(ctx)), common::tag_conditions(&tags))?;
        crate::v2::require_v2(&self.read(), ctx)?;
        let provider = match input.provider {
            types::ProviderConfiguration::JiraCloud(j) => types::ProviderDetail::JiraCloud(types::JiraCloudDetail {
                cloud_id: None,
                project_key: j.project_key,
                domain: None,
                auth_url: None,
                auth_status: None,
            }),
            types::ProviderConfiguration::ServiceNow(s) => types::ProviderDetail::ServiceNow(types::ServiceNowDetail {
                instance_name: Some(s.instance_name),
                secret_arn: s.secret_arn,
                auth_status: "ACTIVE".into(),
            }),
            types::ProviderConfiguration::Azure(a) => types::ProviderDetail::Azure(types::AzureDetail {
                aws_config_connector_arn: a.aws_config_connector_arn,
                scope_configuration: a.scope_configuration,
                azure_regions: a.azure_regions,
            }),
        };
        let rec = self.insert_connector(ctx, true, input.name, input.description, input.kms_key_arn, provider, tags)?;
        let auth_url = Self::auth_url(ctx, &rec);
        Ok(types::CreateConnectorV2Response {
            connector_arn: rec.arn,
            connector_id: rec.id,
            auth_url,
            connector_status: Some(rec.status),
            enablement_status: Some("ENABLED".into()),
        })
    }

    pub(crate) fn register_connector_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::RegisterConnectorV2Request,
    ) -> Result<types::RegisterConnectorV2Response, ServiceError> {
        authorize_hub(ctx, "RegisterConnectorV2")?;
        if input.auth_code.is_empty() {
            return Err(errors::validation("AuthCode must not be empty."));
        }
        let mut state = self.write();
        let (hub_key, id) =
            state.pending_oauth.get(&input.auth_state).cloned().ok_or_else(|| errors::validation("The AuthState is invalid or expired."))?;
        if hub_key != crate::state::key(account(ctx), &ctx.region) {
            return Err(errors::validation("The AuthState is invalid or expired."));
        }
        state.pending_oauth.remove(&input.auth_state);
        let h = hub_mut(&mut state, ctx)?;
        let c = h.connectors.get_mut(&id).ok_or_else(|| not_found(format!("Connector {id} not found.")))?;
        if let types::ProviderDetail::JiraCloud(j) = &mut c.provider {
            let cloud = uuid::Uuid::new_v4().to_string();
            j.domain = Some(format!("https://mws-{}.atlassian.net", &cloud[..8]));
            j.cloud_id = Some(cloud);
            j.auth_status = Some("ACTIVE".into());
        }
        c.status = "CONNECTED".into();
        c.updated_at = ctx.received_at;
        Ok(types::RegisterConnectorV2Response { connector_arn: Some(c.arn.clone()), connector_id: c.id.clone() })
    }

    pub(crate) fn get_connector_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetConnectorV2Request,
    ) -> Result<types::GetConnectorV2Response, ServiceError> {
        authorize_hub(ctx, "GetConnectorV2")?;
        let state = self.read();
        let c = Self::find_connector(hub(&state, ctx)?, &input.connector_id, true)?.clone();
        let mut detail = c.provider.clone();
        if let types::ProviderDetail::JiraCloud(j) = &mut detail {
            j.auth_url = Self::auth_url(ctx, &c);
        }
        Ok(types::GetConnectorV2Response {
            connector_arn: Some(c.arn.clone()),
            connector_id: c.id.clone(),
            name: c.name.clone(),
            description: c.description.clone(),
            kms_key_arn: c.kms_key_arn.clone(),
            created_at: c.created_at,
            last_updated_at: c.updated_at,
            health: health(&c),
            provider_detail: detail,
            enablement_status: Some("ENABLED".into()),
            enablement_status_reason: None,
        })
    }

    pub(crate) fn update_connector_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateConnectorV2Request,
    ) -> Result<types::UpdateConnectorV2Response, ServiceError> {
        authorize_hub(ctx, "UpdateConnectorV2")?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let id = Self::find_connector(h, &input.connector_id, true)?.id.clone();
        let c = h.connectors.get_mut(&id).expect("found");
        if input.description.is_some() {
            c.description = input.description;
        }
        match (input.provider, &mut c.provider) {
            (Some(types::ProviderUpdateConfiguration::JiraCloud(u)), types::ProviderDetail::JiraCloud(j)) => {
                if u.project_key.is_some() {
                    j.project_key = u.project_key;
                }
            }
            (Some(types::ProviderUpdateConfiguration::ServiceNow(u)), types::ProviderDetail::ServiceNow(s)) => {
                if let Some(arn) = u.secret_arn {
                    s.secret_arn = arn;
                }
            }
            (Some(types::ProviderUpdateConfiguration::Azure(u)), types::ProviderDetail::Azure(a)) => {
                a.scope_configuration = u.scope_configuration;
                a.azure_regions = u.azure_regions;
            }
            (None, _) => {}
            _ => return Err(invalid_input("The provider configuration doesn't match the connector's provider.")),
        }
        c.updated_at = ctx.received_at;
        Ok(types::UpdateConnectorV2Response { connector_status: Some(c.status.clone()), enablement_status: Some("ENABLED".into()) })
    }

    pub(crate) fn delete_connector_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteConnectorV2Request,
    ) -> Result<types::DeleteConnectorV2Response, ServiceError> {
        authorize_hub(ctx, "DeleteConnectorV2")?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let c = Self::find_connector(h, &input.connector_id, true)?.clone();
        h.connectors.remove(&c.id);
        h.resource_tags.remove(&c.arn);
        state.pending_oauth.remove(&c.id);
        Ok(types::DeleteConnectorV2Response { enablement_status: Some("DISABLED".into()) })
    }

    pub(crate) fn list_connectors_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::ListConnectorsV2Request,
    ) -> Result<types::ListConnectorsV2Response, ServiceError> {
        authorize_hub(ctx, "ListConnectorsV2")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let all: Vec<types::ConnectorSummary> = h
            .connectors
            .values()
            .filter(|c| c.v2)
            .filter(|c| input.provider_name.as_ref().is_none_or(|p| *p == c.provider_name))
            .filter(|c| input.connector_status.as_ref().is_none_or(|s| *s == c.status))
            .map(|c| types::ConnectorSummary {
                connector_arn: Some(c.arn.clone()),
                connector_id: c.id.clone(),
                name: c.name.clone(),
                description: c.description.clone(),
                provider_summary: types::ProviderSummary {
                    provider_name: Some(c.provider_name.clone()),
                    connector_status: Some(c.status.clone()),
                    provider_configuration: None,
                },
                created_at: c.created_at,
                enablement_status: Some("ENABLED".into()),
                enablement_status_reason: None,
            })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListConnectorsV2Response { next_token, connectors: page })
    }

    pub(crate) fn create_ticket_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateTicketV2Request,
    ) -> Result<types::CreateTicketV2Response, ServiceError> {
        authorize_hub(ctx, "CreateTicketV2")?;
        let mut state = self.write();
        crate::v2::require_v2(&state, ctx)?;
        let exists = crate::findings::visible_findings(&state, account(ctx), &ctx.region)
            .iter()
            .any(|(_, _, f)| crate::ocsf::metadata_uid(&f.finding) == input.finding_metadata_uid);
        if !exists {
            return Err(not_found(format!("Finding {} not found.", input.finding_metadata_uid)));
        }
        let h = hub_mut(&mut state, ctx)?;
        let id = Self::find_connector(h, &input.connector_id, true)?.id.clone();
        let c = h.connectors.get_mut(&id).expect("found");
        if c.status != "CONNECTED" {
            return Err(errors::conflict(format!("Connector {} is not connected.", c.id)));
        }
        let n = c.tickets.len() + 1;
        let (ticket_id, url) = match &c.provider {
            types::ProviderDetail::JiraCloud(j) => {
                let key = format!("{}-{n}", j.project_key.clone().unwrap_or_else(|| "SEC".into()));
                let url = format!("{}/browse/{key}", j.domain.clone().unwrap_or_default());
                (key, url)
            }
            types::ProviderDetail::ServiceNow(s) => {
                let sys_id = uuid::Uuid::new_v4().simple().to_string();
                let url = format!(
                    "https://{}.service-now.com/nav_to.do?uri=incident.do?sys_id={sys_id}",
                    s.instance_name.clone().unwrap_or_default()
                );
                (format!("INC{n:07}"), url)
            }
            types::ProviderDetail::Azure(_) => return Err(invalid_input("Azure connectors can't create tickets.")),
        };
        if input.mode.as_deref() != Some("DRYRUN") {
            c.tickets.insert(ticket_id.clone(), input.finding_metadata_uid);
        }
        Ok(types::CreateTicketV2Response { ticket_id, ticket_src_url: Some(url) })
    }

    // ---- V1 (CSPM) -------------------------------------------------------------------

    pub(crate) fn create_connector_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateConnectorRequest,
    ) -> Result<types::CreateConnectorResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        common::authorize_with(ctx, "CreateConnector", &common::hub_arn(ctx, account(ctx)), common::tag_conditions(&tags))?;
        let types::CspmProviderConfiguration::Azure(a) = input.provider;
        let provider = types::ProviderDetail::Azure(types::AzureDetail {
            aws_config_connector_arn: a.aws_config_connector_arn,
            scope_configuration: a.scope_configuration,
            azure_regions: a.azure_regions,
        });
        let rec = self.insert_connector(ctx, false, input.name, input.description, None, provider, tags)?;
        Ok(types::CreateConnectorResponse {
            connector_arn: rec.arn,
            connector_id: rec.id,
            connector_status: Some(rec.status),
            enablement_status: Some("ENABLED".into()),
        })
    }

    pub(crate) fn get_connector_op(
        &self,
        ctx: &RequestContext,
        input: types::GetConnectorRequest,
    ) -> Result<types::GetConnectorResponse, ServiceError> {
        authorize_hub(ctx, "GetConnector")?;
        let state = self.read();
        let c = Self::find_connector(hub(&state, ctx)?, &input.connector_id, false)?.clone();
        Ok(types::GetConnectorResponse {
            connector_arn: Some(c.arn.clone()),
            connector_id: c.id.clone(),
            name: c.name.clone(),
            description: c.description.clone(),
            created_at: c.created_at,
            last_updated_at: c.updated_at,
            health: types::CspmHealthCheck {
                connector_status: c.status.clone(),
                message: None,
                last_checked_at: c.updated_at,
                issues: None,
            },
            provider_detail: types::CspmProviderDetail::Azure(azure_detail(&c)),
            created_by: Some(c.created_by.clone()),
            enablement_status: Some("ENABLED".into()),
        })
    }

    pub(crate) fn update_connector_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateConnectorRequest,
    ) -> Result<types::UpdateConnectorResponse, ServiceError> {
        authorize_hub(ctx, "UpdateConnector")?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let id = Self::find_connector(h, &input.connector_id, false)?.id.clone();
        let c = h.connectors.get_mut(&id).expect("found");
        if input.description.is_some() {
            c.description = input.description;
        }
        if let (Some(types::CspmProviderUpdateConfiguration::Azure(u)), types::ProviderDetail::Azure(a)) = (input.provider, &mut c.provider) {
            a.scope_configuration = u.scope_configuration;
            a.azure_regions = u.azure_regions;
        }
        c.updated_at = ctx.received_at;
        Ok(types::UpdateConnectorResponse { connector_status: Some(c.status.clone()), enablement_status: Some("ENABLED".into()) })
    }

    pub(crate) fn delete_connector_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteConnectorRequest,
    ) -> Result<types::DeleteConnectorResponse, ServiceError> {
        authorize_hub(ctx, "DeleteConnector")?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let c = Self::find_connector(h, &input.connector_id, false)?.clone();
        h.connectors.remove(&c.id);
        h.resource_tags.remove(&c.arn);
        Ok(types::DeleteConnectorResponse { enablement_status: Some("DISABLED".into()) })
    }

    pub(crate) fn list_connectors_op(
        &self,
        ctx: &RequestContext,
        input: types::ListConnectorsRequest,
    ) -> Result<types::ListConnectorsResponse, ServiceError> {
        authorize_hub(ctx, "ListConnectors")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let all: Vec<types::CspmConnectorSummary> = h
            .connectors
            .values()
            .filter(|c| !c.v2)
            .filter(|c| input.provider_name.as_ref().is_none_or(|p| *p == c.provider_name))
            .filter(|c| input.connector_status.as_ref().is_none_or(|s| *s == c.status))
            .map(|c| types::CspmConnectorSummary {
                connector_arn: Some(c.arn.clone()),
                connector_id: Some(c.id.clone()),
                name: Some(c.name.clone()),
                description: c.description.clone(),
                provider_summary: Some(types::CspmProviderSummary {
                    provider_name: Some(c.provider_name.clone()),
                    connector_status: Some(c.status.clone()),
                    provider_configuration: None,
                }),
                created_at: Some(c.created_at),
                created_by: Some(c.created_by.clone()),
                enablement_status: Some("ENABLED".into()),
            })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListConnectorsResponse { next_token, connectors: page })
    }
}
