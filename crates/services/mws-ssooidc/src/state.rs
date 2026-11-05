//! OIDC state: registered clients, pending authorizations and tokens.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by client id.
    pub clients: BTreeMap<String, Client>,
    /// Keyed by device code.
    pub devices: BTreeMap<String, DeviceAuth>,
    /// Keyed by authorization code.
    pub codes: BTreeMap<String, AuthCode>,
    /// Keyed by access token.
    pub tokens: BTreeMap<String, Token>,
    /// Refresh token → the session it continues.
    pub refresh: BTreeMap<String, Session>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Client {
    pub id: String,
    pub secret: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    /// The AWS access portal (start URL) or issuer the client signs in to.
    pub issuer_url: Option<String>,
    pub application_arn: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum Approval {
    #[default]
    Pending,
    Approved {
        user_id: String,
    },
    Denied,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DeviceAuth {
    pub client_id: String,
    pub user_code: String,
    pub identity_store_id: String,
    pub expires_at: DateTime<Utc>,
    pub approval: Approval,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub scopes: Vec<String>,
    pub identity_store_id: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
}

/// Who a token stands for and what it may do.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Session {
    pub client_id: String,
    pub identity_store_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    /// Set for tokens CreateTokenWithIAM issued to an application.
    pub application_arn: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Token {
    pub session: Session,
    pub expires_at: DateTime<Utc>,
}
