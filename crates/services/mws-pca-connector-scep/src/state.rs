use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Connector {
    pub arn: String,
    pub id: String,
    pub owner: String,
    pub region: String,
    pub ca_arn: String,
    pub ty: String,
    pub mdm: Option<types::MobileDeviceManagement>,
    pub openid: Option<types::OpenIdConfiguration>,
    pub status: String,
    pub status_reason: Option<String>,
    pub endpoint: String,
    pub created: Option<DateTime<Utc>>,
    pub updated: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
    /// The registration authority's key (PKCS#8) and certificate (DER),
    /// issued by the connector's CA: clients encrypt requests to it, and it
    /// signs replies.
    pub ra_key: Vec<u8>,
    pub ra_cert: Vec<u8>,
    /// Certificates issued, by SCEP transaction id (for `GetCertInitial`).
    pub issued: BTreeMap<String, Vec<u8>>,
    /// While `CREATING` or `DELETING`: when that started (the change
    /// completes after `mws_core::settle`'s window).
    pub transition_since: Option<DateTime<Utc>>,
    /// The status (and reason) a `CREATING` connector settles into.
    pub settles_to: Option<(String, Option<String>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Challenge {
    pub arn: String,
    pub connector_arn: String,
    pub owner: String,
    pub password: String,
    pub created: Option<DateTime<Utc>>,
    pub updated: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct State {
    pub connectors: BTreeMap<String, Connector>,
    pub challenges: BTreeMap<String, Challenge>,
    /// `{account}/{token}` -> the ARN a create call made.
    pub client_tokens: HashMap<String, String>,
}
