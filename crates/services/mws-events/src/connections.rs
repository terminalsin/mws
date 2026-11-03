//! Connections, API destinations, and invoking API destinations over HTTP
//! with the connection's authorization.

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::deliver::{Delivery, TargetError};
use crate::generated::types;
use crate::http_client;
use crate::names::{self, arn, not_found, own_region, validation};
use crate::state::{ApiDestination, Connection};
use crate::Events;

fn connection_missing(name: &str) -> ServiceError {
    not_found(format!("Failed to describe the connection(s). Connection '{name}' does not exist."))
}

fn destination_missing(name: &str) -> ServiceError {
    not_found(format!("Failed to describe the api-destination(s). An api-destination '{name}' does not exist."))
}

fn check_auth(kind: &str, auth: &types::CreateConnectionAuthRequestParameters) -> Result<(), ServiceError> {
    let present = match kind {
        "BASIC" => auth.basic_auth_parameters.is_some(),
        "API_KEY" => auth.api_key_auth_parameters.is_some(),
        "OAUTH_CLIENT_CREDENTIALS" => auth.o_auth_parameters.is_some(),
        _ => return Err(validation(format!("Parameter AuthorizationType is not valid: {kind}."))),
    };
    if !present {
        let which = match kind {
            "BASIC" => "BasicAuthParameters",
            "API_KEY" => "ApiKeyAuthParameters",
            _ => "OAuthParameters",
        };
        return Err(validation(format!("Parameter(s) {which} must be specified for authorization type {kind}.")));
    }
    if let Some(o) = &auth.o_auth_parameters {
        check_url(&o.authorization_endpoint, "AuthorizationEndpoint")?;
    }
    Ok(())
}

fn check_url(url: &str, what: &str) -> Result<(), ServiceError> {
    if url.starts_with("https://") || url.starts_with("http://") {
        Ok(())
    } else {
        Err(validation(format!("Parameter {what} is not valid. Reason: {url} is not a valid HTTP(S) URL.")))
    }
}

/// HTTP parameters as `DescribeConnection` shows them: secret values hidden.
fn hide_secrets(p: &types::ConnectionHttpParameters) -> types::ConnectionHttpParameters {
    types::ConnectionHttpParameters {
        header_parameters: p.header_parameters.as_ref().map(|v| {
            v.iter()
                .map(|h| types::ConnectionHeaderParameter {
                    value: if h.is_value_secret { None } else { h.value.clone() },
                    ..h.clone()
                })
                .collect()
        }),
        query_string_parameters: p.query_string_parameters.as_ref().map(|v| {
            v.iter()
                .map(|h| types::ConnectionQueryStringParameter {
                    value: if h.is_value_secret { None } else { h.value.clone() },
                    ..h.clone()
                })
                .collect()
        }),
        body_parameters: p.body_parameters.as_ref().map(|v| {
            v.iter()
                .map(|h| types::ConnectionBodyParameter {
                    value: if h.is_value_secret { None } else { h.value.clone() },
                    ..h.clone()
                })
                .collect()
        }),
    }
}

fn summary(c: &Connection) -> types::Connection {
    types::Connection {
        connection_arn: Some(c.arn.clone()),
        name: Some(c.name.clone()),
        connection_state: Some(c.state.clone()),
        state_reason: c.state_reason.clone(),
        authorization_type: Some(c.authorization_type.clone()),
        creation_time: c.creation_time,
        last_modified_time: c.last_modified_time,
        last_authorized_time: c.last_authorized_time,
    }
}

impl Events {
    fn connection(&self, ctx: &RequestContext, name: &str) -> Result<Connection, ServiceError> {
        let mut st = self.lock();
        own_region(&mut st, ctx).connections.get(name).cloned().ok_or_else(|| connection_missing(name))
    }

    pub fn create_connection(
        &self,
        ctx: &RequestContext,
        input: types::CreateConnectionRequest,
    ) -> Result<types::CreateConnectionResponse, ServiceError> {
        let id = uuid::Uuid::new_v4().to_string();
        let conn_arn = arn(ctx, &format!("connection/{}/{id}", input.name));
        ctx.authorize("events:CreateConnection", &conn_arn, ConditionContext::new())?;
        check_auth(&input.authorization_type, &input.auth_parameters)?;
        let oauth = input.authorization_type == "OAUTH_CLIENT_CREDENTIALS";
        let now = ctx.received_at;
        let suffix: String = id.chars().filter(|c| c.is_ascii_alphanumeric()).take(6).collect();
        let c = Connection {
            name: input.name.clone(),
            arn: conn_arn.clone(),
            description: input.description,
            state: if oauth { "AUTHORIZING" } else { "AUTHORIZED" }.into(),
            state_reason: None,
            authorization_type: input.authorization_type,
            auth: input.auth_parameters,
            invocation_connectivity_parameters: input.invocation_connectivity_parameters,
            kms_key_identifier: input.kms_key_identifier,
            secret_arn: format!(
                "arn:{}:secretsmanager:{}:{}:secret:events!connection/{}/{id}-{suffix}",
                ctx.partition, ctx.region, ctx.caller.account_id, input.name
            ),
            creation_time: Some(now),
            last_modified_time: Some(now),
            last_authorized_time: (!oauth).then_some(now),
            oauth_token: None,
        };
        {
            let mut st = self.lock();
            let region = own_region(&mut st, ctx);
            if region.connections.contains_key(&input.name) {
                return Err(crate::generated::errors::resource_already_exists(format!(
                    "Connection {} already exists.",
                    input.name
                )));
            }
            region.connections.insert(input.name.clone(), c.clone());
        }
        if oauth {
            self.spawn_authorize(ctx, &input.name);
        }
        Ok(types::CreateConnectionResponse {
            connection_arn: Some(conn_arn),
            connection_state: Some(c.state),
            creation_time: Some(now),
            last_modified_time: Some(now),
        })
    }

    /// Fetch an OAuth token in the background and record the outcome.
    fn spawn_authorize(&self, ctx: &RequestContext, name: &str) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let me = self.clone();
        let ctx = ctx.clone();
        let name = name.to_string();
        tokio::spawn(async move {
            let _ = me.oauth_token(&ctx.caller.account_id, &ctx.region, &name, true).await;
        });
    }

    /// The connection's OAuth access token, fetched from its authorization
    /// endpoint when there is none yet (or `refresh`).
    async fn oauth_token(&self, account: &str, region: &str, name: &str, refresh: bool) -> Result<String, TargetError> {
        let conn = {
            let st = self.lock();
            st.region(account, region).and_then(|r| r.connections.get(name)).cloned()
        };
        let Some(conn) = conn else {
            return Err(TargetError::permanent(
                "ResourceNotFoundException",
                format!("Connection {name} does not exist."),
            ));
        };
        if let (Some(t), false) = (&conn.oauth_token, refresh) {
            return Ok(t.clone());
        }
        let Some(o) = conn.auth.o_auth_parameters.clone() else {
            return Err(TargetError::permanent("InvalidConnection", "The connection has no OAuth parameters."));
        };
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", o.client_parameters.client_id, o.client_parameters.client_secret));
        let mut headers = vec![
            ("Authorization".to_string(), format!("Basic {credentials}")),
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let mut query = Vec::new();
        let mut form = vec!["grant_type=client_credentials".to_string()];
        if let Some(p) = &o.o_auth_http_parameters {
            for h in p.header_parameters.iter().flatten() {
                headers.push((h.key.clone().unwrap_or_default(), h.value.clone().unwrap_or_default()));
            }
            for q in p.query_string_parameters.iter().flatten() {
                query.push(format!(
                    "{}={}",
                    http_client::encode(q.key.as_deref().unwrap_or_default()),
                    http_client::encode(q.value.as_deref().unwrap_or_default())
                ));
            }
            for b in p.body_parameters.iter().flatten() {
                form.push(format!(
                    "{}={}",
                    http_client::encode(b.key.as_deref().unwrap_or_default()),
                    http_client::encode(b.value.as_deref().unwrap_or_default())
                ));
            }
        }
        let url = with_query(&o.authorization_endpoint, &query);
        let result = http_client::send(http_client::Request {
            method: &o.http_method,
            url: &url,
            headers,
            body: (o.http_method != "GET").then(|| form.join("&").into_bytes()),
        })
        .await;
        let token = match result {
            Ok(r) if (200..300).contains(&r.status) => serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|v| v.get("access_token").and_then(Value::as_str).map(str::to_string))
                .ok_or_else(|| "The authorization endpoint's response has no access_token.".to_string()),
            Ok(r) => Err(format!("The authorization endpoint answered HTTP {}.", r.status)),
            Err(e) => Err(e),
        };
        let now = self.now();
        let mut st = self.lock();
        let c = st.regions.get_mut(&format!("{account}/{region}")).and_then(|r| r.connections.get_mut(name));
        match token {
            Ok(t) => {
                if let Some(c) = c {
                    c.oauth_token = Some(t.clone());
                    c.state = "AUTHORIZED".into();
                    c.state_reason = None;
                    c.last_authorized_time = Some(now);
                }
                Ok(t)
            }
            Err(m) => {
                if let Some(c) = c {
                    c.oauth_token = None;
                    c.state = "DEAUTHORIZED".into();
                    c.state_reason = Some(m.clone());
                }
                Err(TargetError::retryable("ConnectionAuthorizationFailed", m))
            }
        }
    }

    pub fn describe_connection(
        &self,
        ctx: &RequestContext,
        input: types::DescribeConnectionRequest,
    ) -> Result<types::DescribeConnectionResponse, ServiceError> {
        let c = self.connection(ctx, &input.name)?;
        ctx.authorize("events:DescribeConnection", &c.arn, ConditionContext::new())?;
        let a = &c.auth;
        let auth = types::ConnectionAuthResponseParameters {
            basic_auth_parameters: a
                .basic_auth_parameters
                .as_ref()
                .map(|b| types::ConnectionBasicAuthResponseParameters { username: Some(b.username.clone()) }),
            o_auth_parameters: a.o_auth_parameters.as_ref().map(|o| types::ConnectionOAuthResponseParameters {
                client_parameters: Some(types::ConnectionOAuthClientResponseParameters {
                    client_id: Some(o.client_parameters.client_id.clone()),
                }),
                authorization_endpoint: Some(o.authorization_endpoint.clone()),
                http_method: Some(o.http_method.clone()),
                o_auth_http_parameters: o.o_auth_http_parameters.as_ref().map(hide_secrets),
            }),
            api_key_auth_parameters: a
                .api_key_auth_parameters
                .as_ref()
                .map(|k| types::ConnectionApiKeyAuthResponseParameters { api_key_name: Some(k.api_key_name.clone()) }),
            invocation_http_parameters: a.invocation_http_parameters.as_ref().map(hide_secrets),
            connectivity_parameters: None,
        };
        Ok(types::DescribeConnectionResponse {
            connection_arn: Some(c.arn.clone()),
            name: Some(c.name.clone()),
            description: c.description.clone(),
            invocation_connectivity_parameters: None,
            connection_state: Some(c.state.clone()),
            state_reason: c.state_reason.clone(),
            authorization_type: Some(c.authorization_type.clone()),
            secret_arn: Some(c.secret_arn.clone()),
            kms_key_identifier: c.kms_key_identifier.clone(),
            auth_parameters: Some(auth),
            creation_time: c.creation_time,
            last_modified_time: c.last_modified_time,
            last_authorized_time: c.last_authorized_time,
        })
    }

    pub fn list_connections(
        &self,
        ctx: &RequestContext,
        input: types::ListConnectionsRequest,
    ) -> Result<types::ListConnectionsResponse, ServiceError> {
        ctx.authorize("events:ListConnections", "*", ConditionContext::new())?;
        let items: Vec<types::Connection> = {
            let mut st = self.lock();
            own_region(&mut st, ctx)
                .connections
                .values()
                .filter(|c| input.name_prefix.as_deref().is_none_or(|p| c.name.starts_with(p)))
                .filter(|c| input.connection_state.as_deref().is_none_or(|s| c.state == s))
                .map(summary)
                .collect()
        };
        let (page, next_token) = names::paginate(items, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListConnectionsResponse { connections: Some(page), next_token })
    }

    pub fn update_connection(
        &self,
        ctx: &RequestContext,
        input: types::UpdateConnectionRequest,
    ) -> Result<types::UpdateConnectionResponse, ServiceError> {
        let existing = self.connection(ctx, &input.name)?;
        ctx.authorize("events:UpdateConnection", &existing.arn, ConditionContext::new())?;
        let mut c = existing;
        if let Some(kind) = &input.authorization_type {
            c.authorization_type = kind.clone();
        }
        if let Some(a) = input.auth_parameters {
            if let Some(b) = a.basic_auth_parameters {
                let cur = c.auth.basic_auth_parameters.get_or_insert_with(Default::default);
                if let Some(u) = b.username {
                    cur.username = u;
                }
                if let Some(p) = b.password {
                    cur.password = p;
                }
            }
            if let Some(k) = a.api_key_auth_parameters {
                let cur = c.auth.api_key_auth_parameters.get_or_insert_with(Default::default);
                if let Some(n) = k.api_key_name {
                    cur.api_key_name = n;
                }
                if let Some(v) = k.api_key_value {
                    cur.api_key_value = v;
                }
            }
            if let Some(o) = a.o_auth_parameters {
                let cur = c.auth.o_auth_parameters.get_or_insert_with(Default::default);
                if let Some(cp) = o.client_parameters {
                    if let Some(id) = cp.client_id {
                        cur.client_parameters.client_id = id;
                    }
                    if let Some(s) = cp.client_secret {
                        cur.client_parameters.client_secret = s;
                    }
                }
                if let Some(e) = o.authorization_endpoint {
                    cur.authorization_endpoint = e;
                }
                if let Some(m) = o.http_method {
                    cur.http_method = m;
                }
                if o.o_auth_http_parameters.is_some() {
                    cur.o_auth_http_parameters = o.o_auth_http_parameters;
                }
            }
            if a.invocation_http_parameters.is_some() {
                c.auth.invocation_http_parameters = a.invocation_http_parameters;
            }
        }
        if input.description.is_some() {
            c.description = input.description;
        }
        if input.kms_key_identifier.is_some() {
            c.kms_key_identifier = input.kms_key_identifier.filter(|k| !k.is_empty());
        }
        check_auth(&c.authorization_type, &c.auth)?;
        let now = ctx.received_at;
        let oauth = c.authorization_type == "OAUTH_CLIENT_CREDENTIALS";
        c.state = if oauth { "AUTHORIZING" } else { "AUTHORIZED" }.into();
        c.state_reason = None;
        c.oauth_token = None;
        c.last_modified_time = Some(now);
        if !oauth {
            c.last_authorized_time = Some(now);
        }
        let out = types::UpdateConnectionResponse {
            connection_arn: Some(c.arn.clone()),
            connection_state: Some(c.state.clone()),
            creation_time: c.creation_time,
            last_modified_time: c.last_modified_time,
            last_authorized_time: c.last_authorized_time,
        };
        {
            let mut st = self.lock();
            own_region(&mut st, ctx).connections.insert(c.name.clone(), c);
        }
        if oauth {
            self.spawn_authorize(ctx, &input.name);
        }
        Ok(out)
    }

    pub fn deauthorize_connection(
        &self,
        ctx: &RequestContext,
        input: types::DeauthorizeConnectionRequest,
    ) -> Result<types::DeauthorizeConnectionResponse, ServiceError> {
        let c = self.connection(ctx, &input.name)?;
        ctx.authorize("events:DeauthorizeConnection", &c.arn, ConditionContext::new())?;
        let now = ctx.received_at;
        let mut st = self.lock();
        let c =
            own_region(&mut st, ctx).connections.get_mut(&input.name).ok_or_else(|| connection_missing(&input.name))?;
        c.state = "DEAUTHORIZED".into();
        c.oauth_token = None;
        c.last_modified_time = Some(now);
        Ok(types::DeauthorizeConnectionResponse {
            connection_arn: Some(c.arn.clone()),
            connection_state: Some("DEAUTHORIZING".into()),
            creation_time: c.creation_time,
            last_modified_time: c.last_modified_time,
            last_authorized_time: c.last_authorized_time,
        })
    }

    pub fn delete_connection(
        &self,
        ctx: &RequestContext,
        input: types::DeleteConnectionRequest,
    ) -> Result<types::DeleteConnectionResponse, ServiceError> {
        let c = self.connection(ctx, &input.name)?;
        ctx.authorize("events:DeleteConnection", &c.arn, ConditionContext::new())?;
        let mut st = self.lock();
        let region = own_region(&mut st, ctx);
        region.connections.remove(&input.name);
        region.tags.remove(&c.arn);
        Ok(types::DeleteConnectionResponse {
            connection_arn: Some(c.arn),
            connection_state: Some("DELETING".into()),
            creation_time: c.creation_time,
            last_modified_time: c.last_modified_time,
            last_authorized_time: c.last_authorized_time,
        })
    }

    // ----- API destinations -----

    fn api_destination(&self, ctx: &RequestContext, name: &str) -> Result<ApiDestination, ServiceError> {
        let mut st = self.lock();
        own_region(&mut st, ctx).api_destinations.get(name).cloned().ok_or_else(|| destination_missing(name))
    }

    fn connection_by_arn(&self, ctx: &RequestContext, connection_arn: &str) -> Result<Connection, ServiceError> {
        let mut st = self.lock();
        own_region(&mut st, ctx)
            .connections
            .values()
            .find(|c| c.arn == connection_arn)
            .cloned()
            .ok_or_else(|| not_found(format!("Connection '{connection_arn}' does not exist.")))
    }

    pub fn create_api_destination(
        &self,
        ctx: &RequestContext,
        input: types::CreateApiDestinationRequest,
    ) -> Result<types::CreateApiDestinationResponse, ServiceError> {
        let id = uuid::Uuid::new_v4().to_string();
        let dest_arn = arn(ctx, &format!("api-destination/{}/{id}", input.name));
        ctx.authorize("events:CreateApiDestination", &dest_arn, ConditionContext::new())?;
        check_url(&input.invocation_endpoint, "InvocationEndpoint")?;
        self.connection_by_arn(ctx, &input.connection_arn)?;
        let now = ctx.received_at;
        let mut st = self.lock();
        let region = own_region(&mut st, ctx);
        if region.api_destinations.contains_key(&input.name) {
            return Err(crate::generated::errors::resource_already_exists(format!(
                "An api-destination '{}' already exists.",
                input.name
            )));
        }
        region.api_destinations.insert(
            input.name.clone(),
            ApiDestination {
                name: input.name.clone(),
                arn: dest_arn.clone(),
                description: input.description,
                state: "ACTIVE".into(),
                connection_arn: input.connection_arn,
                invocation_endpoint: input.invocation_endpoint,
                http_method: input.http_method,
                invocation_rate_limit_per_second: input.invocation_rate_limit_per_second,
                creation_time: Some(now),
                last_modified_time: Some(now),
            },
        );
        Ok(types::CreateApiDestinationResponse {
            api_destination_arn: Some(dest_arn),
            api_destination_state: Some("ACTIVE".into()),
            creation_time: Some(now),
            last_modified_time: Some(now),
        })
    }

    pub fn describe_api_destination(
        &self,
        ctx: &RequestContext,
        input: types::DescribeApiDestinationRequest,
    ) -> Result<types::DescribeApiDestinationResponse, ServiceError> {
        let d = self.api_destination(ctx, &input.name)?;
        ctx.authorize("events:DescribeApiDestination", &d.arn, ConditionContext::new())?;
        Ok(types::DescribeApiDestinationResponse {
            api_destination_arn: Some(d.arn),
            name: Some(d.name),
            description: d.description,
            api_destination_state: Some(d.state),
            connection_arn: Some(d.connection_arn),
            invocation_endpoint: Some(d.invocation_endpoint),
            http_method: Some(d.http_method),
            invocation_rate_limit_per_second: Some(d.invocation_rate_limit_per_second.unwrap_or(300)),
            creation_time: d.creation_time,
            last_modified_time: d.last_modified_time,
        })
    }

    pub fn list_api_destinations(
        &self,
        ctx: &RequestContext,
        input: types::ListApiDestinationsRequest,
    ) -> Result<types::ListApiDestinationsResponse, ServiceError> {
        ctx.authorize("events:ListApiDestinations", "*", ConditionContext::new())?;
        let items: Vec<types::ApiDestination> = {
            let mut st = self.lock();
            own_region(&mut st, ctx)
                .api_destinations
                .values()
                .filter(|d| input.name_prefix.as_deref().is_none_or(|p| d.name.starts_with(p)))
                .filter(|d| input.connection_arn.as_deref().is_none_or(|c| d.connection_arn == c))
                .map(|d| types::ApiDestination {
                    api_destination_arn: Some(d.arn.clone()),
                    name: Some(d.name.clone()),
                    api_destination_state: Some(d.state.clone()),
                    connection_arn: Some(d.connection_arn.clone()),
                    invocation_endpoint: Some(d.invocation_endpoint.clone()),
                    http_method: Some(d.http_method.clone()),
                    invocation_rate_limit_per_second: Some(d.invocation_rate_limit_per_second.unwrap_or(300)),
                    creation_time: d.creation_time,
                    last_modified_time: d.last_modified_time,
                })
                .collect()
        };
        let (page, next_token) = names::paginate(items, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListApiDestinationsResponse { api_destinations: Some(page), next_token })
    }

    pub fn update_api_destination(
        &self,
        ctx: &RequestContext,
        input: types::UpdateApiDestinationRequest,
    ) -> Result<types::UpdateApiDestinationResponse, ServiceError> {
        let d = self.api_destination(ctx, &input.name)?;
        ctx.authorize("events:UpdateApiDestination", &d.arn, ConditionContext::new())?;
        if let Some(e) = &input.invocation_endpoint {
            check_url(e, "InvocationEndpoint")?;
        }
        if let Some(c) = &input.connection_arn {
            self.connection_by_arn(ctx, c)?;
        }
        let now = ctx.received_at;
        let mut st = self.lock();
        let d = own_region(&mut st, ctx)
            .api_destinations
            .get_mut(&input.name)
            .ok_or_else(|| destination_missing(&input.name))?;
        if input.description.is_some() {
            d.description = input.description;
        }
        if let Some(c) = input.connection_arn {
            d.connection_arn = c;
        }
        if let Some(e) = input.invocation_endpoint {
            d.invocation_endpoint = e;
        }
        if let Some(m) = input.http_method {
            d.http_method = m;
        }
        if input.invocation_rate_limit_per_second.is_some() {
            d.invocation_rate_limit_per_second = input.invocation_rate_limit_per_second;
        }
        d.last_modified_time = Some(now);
        Ok(types::UpdateApiDestinationResponse {
            api_destination_arn: Some(d.arn.clone()),
            api_destination_state: Some(d.state.clone()),
            creation_time: d.creation_time,
            last_modified_time: d.last_modified_time,
        })
    }

    pub fn delete_api_destination(
        &self,
        ctx: &RequestContext,
        input: types::DeleteApiDestinationRequest,
    ) -> Result<types::DeleteApiDestinationResponse, ServiceError> {
        let d = self.api_destination(ctx, &input.name)?;
        ctx.authorize("events:DeleteApiDestination", &d.arn, ConditionContext::new())?;
        let mut st = self.lock();
        let region = own_region(&mut st, ctx);
        region.api_destinations.remove(&input.name);
        region.tags.remove(&d.arn);
        Ok(types::DeleteApiDestinationResponse {})
    }

    /// Send an event to an API destination.
    pub(crate) async fn deliver_api_destination(
        &self,
        ctx: &RequestContext,
        d: &Delivery,
        payload: &str,
    ) -> Result<(), TargetError> {
        let Some((_, _, region, account, resource)) = names::split_arn(&d.target.arn) else {
            return Err(TargetError::permanent("InvalidTarget", "The target ARN is not valid."));
        };
        let name = resource.trim_start_matches("api-destination/").split('/').next().unwrap_or_default().to_string();
        let (dest, conn) = {
            let st = self.lock();
            let r = st.region(account, region);
            let dest = r.and_then(|r| r.api_destinations.get(&name)).filter(|x| x.arn == d.target.arn).cloned();
            let conn = dest
                .as_ref()
                .and_then(|x| r.and_then(|r| r.connections.values().find(|c| c.arn == x.connection_arn)).cloned());
            (dest, conn)
        };
        let Some(dest) = dest else {
            return Err(TargetError::permanent(
                "ResourceNotFoundException",
                format!("API destination {name} does not exist."),
            ));
        };
        let Some(conn) = conn else {
            return Err(TargetError::permanent(
                "ResourceNotFoundException",
                "The API destination's connection does not exist.",
            ));
        };
        if conn.state == "DEAUTHORIZED" && conn.authorization_type != "OAUTH_CLIENT_CREDENTIALS" {
            return Err(TargetError::permanent(
                "ConnectionDeauthorized",
                format!("Connection {} is deauthorized.", conn.name),
            ));
        }
        let http = d.target.http_parameters.clone().unwrap_or_default();
        // Path parameters replace the endpoint's `*` wildcards in order.
        let mut url = String::new();
        let mut values = http.path_parameter_values.iter().flatten();
        for (i, part) in dest.invocation_endpoint.split('*').enumerate() {
            if i > 0 {
                url.push_str(values.next().map(String::as_str).unwrap_or_default());
            }
            url.push_str(part);
        }
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json; charset=utf-8".to_string()),
            ("User-Agent".to_string(), "Amazon/EventBridge/ApiDestinations".to_string()),
        ];
        let mut query = Vec::new();
        let mut body_params = Vec::new();
        if let Some(p) = &conn.auth.invocation_http_parameters {
            for h in p.header_parameters.iter().flatten() {
                headers.push((h.key.clone().unwrap_or_default(), h.value.clone().unwrap_or_default()));
            }
            for q in p.query_string_parameters.iter().flatten() {
                query.push((q.key.clone().unwrap_or_default(), q.value.clone().unwrap_or_default()));
            }
            for b in p.body_parameters.iter().flatten() {
                body_params.push((b.key.clone().unwrap_or_default(), b.value.clone().unwrap_or_default()));
            }
        }
        for (k, v) in http.header_parameters.iter().flatten() {
            headers.push((k.clone(), v.clone()));
        }
        for (k, v) in http.query_string_parameters.iter().flatten() {
            query.push((k.clone(), v.clone()));
        }
        match conn.authorization_type.as_str() {
            "BASIC" => {
                if let Some(b) = &conn.auth.basic_auth_parameters {
                    let c = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", b.username, b.password));
                    headers.push(("Authorization".into(), format!("Basic {c}")));
                }
            }
            "API_KEY" => {
                if let Some(k) = &conn.auth.api_key_auth_parameters {
                    headers.push((k.api_key_name.clone(), k.api_key_value.clone()));
                }
            }
            _ => {
                let token = self.oauth_token(account, region, &conn.name, false).await?;
                headers.push(("Authorization".into(), format!("Bearer {token}")));
            }
        }
        let mut body = payload.to_string();
        if !body_params.is_empty() {
            if let Ok(Value::Object(mut m)) = serde_json::from_str::<Value>(&body) {
                for (k, v) in body_params {
                    m.insert(k, Value::String(v));
                }
                body = Value::Object(m).to_string();
            }
        }
        let query: Vec<String> =
            query.iter().map(|(k, v)| format!("{}={}", http_client::encode(k), http_client::encode(v))).collect();
        let url = with_query(&url, &query);
        let method = dest.http_method.clone();
        let sends_body = !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE");
        let response = http_client::send(http_client::Request {
            method: &method,
            url: &url,
            headers,
            body: sends_body.then(|| body.into_bytes()),
        })
        .await
        .map_err(|e| TargetError::retryable("SdkClientException", e))?;
        let _ = ctx;
        match response.status {
            200..=299 => Ok(()),
            401 | 407 if conn.authorization_type == "OAUTH_CLIENT_CREDENTIALS" => {
                let _ = self.oauth_token(account, region, &conn.name, true).await;
                Err(TargetError::retryable("ConnectionAuthorizationFailed", format!("HTTP {}", response.status)))
            }
            409 | 429 | 500..=599 => Err(TargetError::retryable(
                "ApiDestinationError",
                format!("The API destination answered HTTP {}.", response.status),
            )),
            s => Err(TargetError::permanent("ApiDestinationError", format!("The API destination answered HTTP {s}."))),
        }
    }
}

fn with_query(url: &str, query: &[String]) -> String {
    if query.is_empty() {
        return url.to_string();
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{}", query.join("&"))
}
