//! KMS state: keys with their key material, aliases, grants, import
//! parameters and custom key stores. Everything is keyed by ARN (or id), so
//! one `State` holds every account and region.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

/// Serialize key material as base64 rather than a list of numbers.
pub(crate) mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// One version of a key's material. Symmetric keys gain a new one on every
/// rotation and keep the old ones to decrypt older ciphertexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Material {
    /// 64 hex characters, as KMS reports `KeyMaterialId`.
    pub id: String,
    /// Raw AES or HMAC key bytes, a PKCS#8 private key, or an ML-KEM
    /// decapsulation key, depending on the key spec. Empty once imported
    /// material is deleted or expires.
    #[serde(with = "b64")]
    pub secret: Vec<u8>,
    pub created_at: DateTime<Utc>,
    /// `AUTOMATIC` or `ON_DEMAND` for material that came from a rotation.
    #[serde(default)]
    pub rotation_type: Option<String>,
    #[serde(default)]
    pub imported: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub expiration_model: Option<String>,
    #[serde(default)]
    pub valid_to: Option<DateTime<Utc>>,
    /// Imported as `NEW_KEY_MATERIAL`, waiting for `RotateKeyOnDemand`.
    #[serde(default)]
    pub pending: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LastUsage {
    pub operation: String,
    pub at: DateTime<Utc>,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub arn: String,
    pub key_id: String,
    pub account: String,
    pub region: String,
    pub created_at: DateTime<Utc>,
    pub description: String,
    pub key_usage: String,
    pub key_spec: String,
    pub origin: String,
    /// `CUSTOMER`, or `AWS` for AWS managed keys (`alias/aws/...`).
    pub key_manager: String,
    /// `Enabled`, `Disabled`, `PendingDeletion`, `PendingImport`,
    /// `PendingReplicaDeletion`, `Unavailable`, `Creating` or `Updating`.
    pub state: String,
    /// The state to return to when imported material is (re)imported.
    #[serde(default)]
    pub enabled_flag: bool,
    pub deletion_date: Option<DateTime<Utc>>,
    pub pending_window_days: Option<i32>,
    pub policy: String,
    pub tags: BTreeMap<String, String>,
    /// Oldest first. The current material is `current_material`.
    pub materials: Vec<Material>,
    pub current_material: Option<String>,
    /// Automatic rotation period, when rotation is enabled.
    pub rotation_period_days: Option<i32>,
    pub next_rotation: Option<DateTime<Utc>>,
    pub multi_region: bool,
    /// Region of the primary key, for multi-Region keys.
    pub primary_region: Option<String>,
    pub custom_key_store_id: Option<String>,
    pub xks_key_id: Option<String>,
    #[serde(default)]
    pub last_usage: Option<LastUsage>,
    /// Work KMS is still doing on the key (`Creating`, `Updating`).
    #[serde(default)]
    pub transition: Option<Transition>,
}

/// A key in `Creating` or `Updating`: the state it settles into, and when
/// the work started (see `mws_core::settle`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub since: DateTime<Utc>,
    /// The key state once the work is done.
    pub to: String,
    /// `UpdatePrimaryRegion`: the Region that becomes the primary.
    #[serde(default)]
    pub primary_region: Option<String>,
}

impl Key {
    pub fn is_symmetric(&self) -> bool {
        self.key_spec == "SYMMETRIC_DEFAULT"
    }

    /// The material new ciphertexts and signatures use, if it is present.
    pub fn current(&self) -> Option<&Material> {
        let id = self.current_material.as_ref()?;
        self.material(id)
    }

    /// Material by id, unless it was deleted or has expired.
    pub fn material(&self, id: &str) -> Option<&Material> {
        self.materials.iter().find(|m| m.id == id && !m.secret.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alias {
    pub arn: String,
    /// `alias/...`
    pub name: String,
    pub target_key_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    pub key_arn: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub grantee_principal: Option<String>,
    pub retiring_principal: Option<String>,
    #[serde(default)]
    pub grantee_service_principal: Option<String>,
    #[serde(default)]
    pub retiring_service_principal: Option<String>,
    pub issuing_account: String,
    pub operations: Vec<String>,
    pub constraints: Option<types::GrantConstraints>,
    pub tokens: Vec<String>,
}

/// What `GetParametersForImport` handed out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportParams {
    pub key_arn: String,
    pub wrapping_algorithm: String,
    pub wrapping_key_spec: String,
    /// PKCS#8 of the RSA wrapping key.
    #[serde(with = "b64")]
    pub wrapping_key: Vec<u8>,
    pub valid_to: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomKeyStore {
    pub id: String,
    pub account: String,
    pub region: String,
    pub name: String,
    pub store_type: String,
    pub created_at: DateTime<Utc>,
    pub connection_state: String,
    pub connection_error_code: Option<String>,
    pub cloud_hsm_cluster_id: Option<String>,
    pub trust_anchor_certificate: Option<String>,
    pub xks: Option<types::XksProxyConfigurationType>,
    /// The proxy authentication credential's secret (never returned).
    #[serde(default)]
    pub xks_secret: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By key ARN.
    pub keys: BTreeMap<String, Key>,
    /// By alias ARN.
    pub aliases: BTreeMap<String, Alias>,
    /// By grant id.
    pub grants: BTreeMap<String, Grant>,
    /// By import token (hex).
    pub imports: BTreeMap<String, ImportParams>,
    /// By custom key store id.
    pub custom_key_stores: BTreeMap<String, CustomKeyStore>,
}
