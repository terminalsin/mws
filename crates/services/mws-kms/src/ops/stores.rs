//! Custom key stores. MWS has no CloudHSM clusters and cannot reach an
//! external key store proxy, so stores are created and managed as AWS does,
//! but CloudHSM stores cannot be created (their cluster does not exist) and
//! connecting an external key store fails the way an unreachable proxy does.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{page, validation};
use crate::crypto;
use crate::generated::{errors, types};
use crate::state::CustomKeyStore;
use crate::Kms;

fn not_found(id: &str) -> ServiceError {
    errors::custom_key_store_not_found(format!("Custom key store {id} was not found."))
}

fn entry(s: &CustomKeyStore) -> types::CustomKeyStoresListEntry {
    types::CustomKeyStoresListEntry {
        custom_key_store_id: Some(s.id.clone()),
        custom_key_store_name: Some(s.name.clone()),
        cloud_hsm_cluster_id: s.cloud_hsm_cluster_id.clone(),
        trust_anchor_certificate: s.trust_anchor_certificate.clone(),
        connection_state: Some(s.connection_state.clone()),
        connection_error_code: s.connection_error_code.clone(),
        creation_date: Some(s.created_at),
        custom_key_store_type: Some(s.store_type.clone()),
        xks_proxy_configuration: s.xks.clone(),
    }
}

impl Kms {
    pub(crate) fn create_custom_key_store(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomKeyStoreRequest,
    ) -> Result<types::CreateCustomKeyStoreResponse, ServiceError> {
        self.authorize_account(ctx, "CreateCustomKeyStore", ConditionContext::new())?;
        let store_type = input.custom_key_store_type.unwrap_or_else(|| "AWS_CLOUDHSM".into());
        let mut st = self.lock();
        let account = ctx.caller.account_id.clone();
        if st.custom_key_stores.values().any(|s| s.account == account && s.name == input.custom_key_store_name) {
            return Err(errors::custom_key_store_name_in_use(format!(
                "Custom key store name {} is already in use.",
                input.custom_key_store_name
            )));
        }
        let xks = match store_type.as_str() {
            "AWS_CLOUDHSM" => {
                let cluster = input
                    .cloud_hsm_cluster_id
                    .ok_or_else(|| validation("CloudHsmClusterId is required for an AWS_CLOUDHSM key store."))?;
                return Err(errors::cloud_hsm_cluster_not_found(format!(
                    "AWS CloudHSM cluster {cluster} was not found."
                )));
            }
            "EXTERNAL_KEY_STORE" => {
                let endpoint = input
                    .xks_proxy_uri_endpoint
                    .ok_or_else(|| validation("XksProxyUriEndpoint is required for an EXTERNAL_KEY_STORE."))?;
                let path = input
                    .xks_proxy_uri_path
                    .ok_or_else(|| validation("XksProxyUriPath is required for an EXTERNAL_KEY_STORE."))?;
                let cred = input.xks_proxy_authentication_credential.ok_or_else(|| {
                    validation("XksProxyAuthenticationCredential is required for an EXTERNAL_KEY_STORE.")
                })?;
                let connectivity = input.xks_proxy_connectivity.unwrap_or_else(|| "PUBLIC_ENDPOINT".into());
                if connectivity == "VPC_ENDPOINT_SERVICE" && input.xks_proxy_vpc_endpoint_service_name.is_none() {
                    return Err(validation(
                        "XksProxyVpcEndpointServiceName is required when XksProxyConnectivity is VPC_ENDPOINT_SERVICE.",
                    ));
                }
                if st.custom_key_stores.values().any(|s| {
                    s.account == account
                        && s.xks.as_ref().is_some_and(|x| {
                            x.uri_endpoint.as_deref() == Some(endpoint.as_str())
                                && x.uri_path.as_deref() == Some(path.as_str())
                        })
                }) {
                    return Err(errors::xks_proxy_uri_in_use(format!(
                        "The XKS proxy URI {endpoint}{path} is already used by another external key store."
                    )));
                }
                Some(types::XksProxyConfigurationType {
                    connectivity: Some(connectivity),
                    access_key_id: Some(cred.access_key_id),
                    uri_endpoint: Some(endpoint),
                    uri_path: Some(path),
                    vpc_endpoint_service_name: input.xks_proxy_vpc_endpoint_service_name,
                    vpc_endpoint_service_owner: input.xks_proxy_vpc_endpoint_service_owner,
                })
            }
            other => return Err(validation(format!("Invalid CustomKeyStoreType {other}"))),
        };
        let id = format!("cks-{}", &crypto::random_hex(9)[..17]);
        st.custom_key_stores.insert(
            id.clone(),
            CustomKeyStore {
                id: id.clone(),
                account,
                region: ctx.region.clone(),
                name: input.custom_key_store_name,
                store_type,
                created_at: ctx.received_at,
                connection_state: "DISCONNECTED".into(),
                connection_error_code: None,
                cloud_hsm_cluster_id: None,
                trust_anchor_certificate: None,
                xks,
            },
        );
        Ok(types::CreateCustomKeyStoreResponse { custom_key_store_id: Some(id) })
    }

    pub(crate) fn describe_custom_key_stores(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCustomKeyStoresRequest,
    ) -> Result<types::DescribeCustomKeyStoresResponse, ServiceError> {
        self.authorize_account(ctx, "DescribeCustomKeyStores", ConditionContext::new())?;
        let st = self.lock();
        let mine = |s: &&CustomKeyStore| s.account == ctx.caller.account_id && s.region == ctx.region;
        let items: Vec<(String, types::CustomKeyStoresListEntry)> = st
            .custom_key_stores
            .values()
            .filter(mine)
            .filter(|s| input.custom_key_store_id.as_ref().is_none_or(|id| *id == s.id))
            .filter(|s| input.custom_key_store_name.as_ref().is_none_or(|n| *n == s.name))
            .map(|s| (s.id.clone(), entry(s)))
            .collect();
        if items.is_empty() {
            if let Some(id) = &input.custom_key_store_id {
                return Err(not_found(id));
            }
            if let Some(name) = &input.custom_key_store_name {
                return Err(not_found(name));
            }
        }
        let (stores, next_marker, truncated) = page(items, input.limit, 100, input.marker.as_deref())?;
        Ok(types::DescribeCustomKeyStoresResponse { custom_key_stores: Some(stores), next_marker, truncated })
    }

    fn store_mut<'a>(
        st: &'a mut crate::state::State,
        ctx: &RequestContext,
        id: &str,
    ) -> Result<&'a mut CustomKeyStore, ServiceError> {
        st.custom_key_stores
            .get_mut(id)
            .filter(|s| s.account == ctx.caller.account_id && s.region == ctx.region)
            .ok_or_else(|| not_found(id))
    }

    pub(crate) fn connect_custom_key_store(
        &self,
        ctx: &RequestContext,
        input: types::ConnectCustomKeyStoreRequest,
    ) -> Result<types::ConnectCustomKeyStoreResponse, ServiceError> {
        self.authorize_account(ctx, "ConnectCustomKeyStore", ConditionContext::new())?;
        let mut st = self.lock();
        let s = Self::store_mut(&mut st, ctx, &input.custom_key_store_id)?;
        if !matches!(s.connection_state.as_str(), "DISCONNECTED" | "FAILED") {
            return Err(errors::custom_key_store_invalid_state(format!(
                "The custom key store {} is {}.",
                s.id, s.connection_state
            )));
        }
        // Connecting happens asynchronously; MWS cannot reach the proxy.
        s.connection_state = "FAILED".into();
        s.connection_error_code = Some("XKS_PROXY_NOT_REACHABLE".into());
        Ok(types::ConnectCustomKeyStoreResponse {})
    }

    pub(crate) fn disconnect_custom_key_store(
        &self,
        ctx: &RequestContext,
        input: types::DisconnectCustomKeyStoreRequest,
    ) -> Result<types::DisconnectCustomKeyStoreResponse, ServiceError> {
        self.authorize_account(ctx, "DisconnectCustomKeyStore", ConditionContext::new())?;
        let mut st = self.lock();
        let s = Self::store_mut(&mut st, ctx, &input.custom_key_store_id)?;
        s.connection_state = "DISCONNECTED".into();
        s.connection_error_code = None;
        Ok(types::DisconnectCustomKeyStoreResponse {})
    }

    pub(crate) fn update_custom_key_store(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomKeyStoreRequest,
    ) -> Result<types::UpdateCustomKeyStoreResponse, ServiceError> {
        self.authorize_account(ctx, "UpdateCustomKeyStore", ConditionContext::new())?;
        let mut st = self.lock();
        if let Some(name) = &input.new_custom_key_store_name {
            if st
                .custom_key_stores
                .values()
                .any(|s| s.account == ctx.caller.account_id && &s.name == name && s.id != input.custom_key_store_id)
            {
                return Err(errors::custom_key_store_name_in_use(format!(
                    "Custom key store name {name} is already in use."
                )));
            }
        }
        let s = Self::store_mut(&mut st, ctx, &input.custom_key_store_id)?;
        if s.connection_state != "DISCONNECTED" {
            return Err(errors::custom_key_store_invalid_state(format!(
                "The custom key store {} must be disconnected to update it.",
                s.id
            )));
        }
        if let Some(name) = input.new_custom_key_store_name {
            s.name = name;
        }
        if let Some(x) = s.xks.as_mut() {
            if let Some(v) = input.xks_proxy_uri_endpoint {
                x.uri_endpoint = Some(v);
            }
            if let Some(v) = input.xks_proxy_uri_path {
                x.uri_path = Some(v);
            }
            if let Some(v) = input.xks_proxy_vpc_endpoint_service_name {
                x.vpc_endpoint_service_name = Some(v);
            }
            if let Some(v) = input.xks_proxy_vpc_endpoint_service_owner {
                x.vpc_endpoint_service_owner = Some(v);
            }
            if let Some(v) = input.xks_proxy_authentication_credential {
                x.access_key_id = Some(v.access_key_id);
            }
            if let Some(v) = input.xks_proxy_connectivity {
                x.connectivity = Some(v);
            }
        }
        Ok(types::UpdateCustomKeyStoreResponse {})
    }

    pub(crate) fn delete_custom_key_store(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomKeyStoreRequest,
    ) -> Result<types::DeleteCustomKeyStoreResponse, ServiceError> {
        self.authorize_account(ctx, "DeleteCustomKeyStore", ConditionContext::new())?;
        let mut st = self.lock();
        let has_keys = st.keys.values().any(|k| k.custom_key_store_id.as_deref() == Some(&input.custom_key_store_id));
        let s = Self::store_mut(&mut st, ctx, &input.custom_key_store_id)?;
        if s.connection_state != "DISCONNECTED" {
            return Err(errors::custom_key_store_invalid_state(format!(
                "The custom key store {} must be disconnected to delete it.",
                s.id
            )));
        }
        if has_keys {
            return Err(errors::custom_key_store_has_cm_ks(format!(
                "The custom key store {} contains KMS keys. Delete them first.",
                s.id
            )));
        }
        st.custom_key_stores.remove(&input.custom_key_store_id);
        Ok(types::DeleteCustomKeyStoreResponse {})
    }
}
