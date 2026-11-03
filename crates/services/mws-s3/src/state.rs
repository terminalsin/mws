//! S3 state: buckets, their configuration, and object versions.

use std::collections::BTreeMap;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub buckets: BTreeMap<String, Bucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Bucket {
    pub name: String,
    pub region: String,
    /// Account id of the owner.
    pub owner: String,
    pub created: DateTime<Utc>,
    /// `Enabled` or `Suspended`; `None` for a bucket that never had
    /// versioning configured.
    pub versioning: Option<String>,
    pub mfa_delete: Option<String>,
    /// Every version of every key, oldest first.
    pub objects: BTreeMap<String, Vec<ObjectVersion>>,
    pub uploads: BTreeMap<String, Upload>,
    pub policy: Option<String>,
    pub tags: Option<Vec<types::Tag>>,
    pub cors: Option<types::CORSConfiguration>,
    /// `None` means the default (SSE-S3).
    pub encryption: Option<types::ServerSideEncryptionConfiguration>,
    pub lifecycle: Option<types::BucketLifecycleConfiguration>,
    pub website: Option<types::WebsiteConfiguration>,
    pub logging: Option<types::LoggingEnabled>,
    pub notification: types::NotificationConfiguration,
    /// `None` once ownership controls are deleted.
    pub ownership: Option<String>,
    /// `None` once the configuration is deleted.
    pub public_access_block: Option<types::PublicAccessBlockConfiguration>,
    /// Grants beyond nothing; the owner's FULL_CONTROL grant is included.
    pub acl: Vec<types::Grant>,
    pub accelerate: Option<String>,
    pub request_payer: String,
    pub replication: Option<types::ReplicationConfiguration>,
    pub object_lock_enabled: bool,
    pub object_lock: Option<types::ObjectLockConfiguration>,
    pub analytics: BTreeMap<String, types::AnalyticsConfiguration>,
    pub metrics: BTreeMap<String, types::MetricsConfiguration>,
    pub inventory: BTreeMap<String, types::InventoryConfiguration>,
    pub intelligent_tiering: BTreeMap<String, types::IntelligentTieringConfiguration>,
    pub abac: Option<String>,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            name: String::new(),
            region: "us-east-1".into(),
            owner: String::new(),
            created: DateTime::<Utc>::UNIX_EPOCH,
            versioning: None,
            mfa_delete: None,
            objects: BTreeMap::new(),
            uploads: BTreeMap::new(),
            policy: None,
            tags: None,
            cors: None,
            encryption: None,
            lifecycle: None,
            website: None,
            logging: None,
            notification: types::NotificationConfiguration::default(),
            ownership: Some("BucketOwnerEnforced".into()),
            public_access_block: Some(types::PublicAccessBlockConfiguration {
                block_public_acls: Some(true),
                ignore_public_acls: Some(true),
                block_public_policy: Some(true),
                restrict_public_buckets: Some(true),
            }),
            acl: Vec::new(),
            accelerate: None,
            request_payer: "BucketOwner".into(),
            replication: None,
            object_lock_enabled: false,
            object_lock: None,
            analytics: BTreeMap::new(),
            metrics: BTreeMap::new(),
            inventory: BTreeMap::new(),
            intelligent_tiering: BTreeMap::new(),
            abac: None,
        }
    }
}

impl Bucket {
    pub fn versioning_enabled(&self) -> bool {
        self.versioning.as_deref() == Some("Enabled")
    }

    /// ACLs are honoured unless ownership controls enforce bucket-owner
    /// ownership.
    pub fn acls_enabled(&self) -> bool {
        self.ownership.as_deref() != Some("BucketOwnerEnforced")
    }

    pub fn pab(&self) -> types::PublicAccessBlockConfiguration {
        self.public_access_block.clone().unwrap_or_default()
    }

    /// The newest version of `key`, delete markers included.
    pub fn latest(&self, key: &str) -> Option<&ObjectVersion> {
        self.objects.get(key).and_then(|v| v.last())
    }

    pub fn version(&self, key: &str, version_id: &str) -> Option<&ObjectVersion> {
        self.objects.get(key)?.iter().find(|v| v.version_id == version_id)
    }

    pub fn version_mut(&mut self, key: &str, version_id: Option<&str>) -> Option<&mut ObjectVersion> {
        let versions = self.objects.get_mut(key)?;
        match version_id {
            Some(id) => versions.iter_mut().find(|v| v.version_id == id),
            None => versions.last_mut(),
        }
    }

    /// Whether the bucket holds no objects, versions or delete markers.
    pub fn is_empty(&self) -> bool {
        self.objects.values().all(Vec::is_empty)
    }

    /// Add a new version of `key` as the versioning state dictates: replace
    /// the `null` version unless versioning is enabled.
    pub fn insert_version(&mut self, key: &str, mut version: ObjectVersion) -> String {
        let versions = self.objects.entry(key.to_string()).or_default();
        if self.versioning.as_deref() == Some("Enabled") {
            version.version_id = new_version_id();
        } else {
            version.version_id = "null".into();
            versions.retain(|v| v.version_id != "null");
        }
        let id = version.version_id.clone();
        versions.push(version);
        id
    }
}

/// An object version or a delete marker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ObjectVersion {
    pub version_id: String,
    pub delete_marker: bool,
    pub last_modified: DateTime<Utc>,
    #[serde(with = "b64")]
    pub data: Bytes,
    /// Quoted, as sent in `ETag` headers.
    pub etag: String,
    pub owner: String,
    pub content_type: Option<String>,
    pub cache_control: Option<String>,
    pub content_disposition: Option<String>,
    pub content_encoding: Option<String>,
    pub content_language: Option<String>,
    pub expires: Option<String>,
    pub website_redirect: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub storage_class: String,
    pub tags: Vec<types::Tag>,
    pub checksum: Option<Checksum>,
    /// Parts of an object created by a multipart upload.
    pub parts: Vec<PartInfo>,
    pub sse: Sse,
    pub acl: Vec<types::Grant>,
    pub lock_mode: Option<String>,
    pub lock_until: Option<DateTime<Utc>>,
    pub legal_hold: Option<String>,
    /// When a restored copy of an archived object expires.
    pub restored_until: Option<DateTime<Utc>>,
    /// `COMPLETED`, `FAILED` or `REPLICA`, once replication has acted.
    pub replication_status: Option<String>,
}

impl Default for ObjectVersion {
    fn default() -> Self {
        Self {
            version_id: "null".into(),
            delete_marker: false,
            last_modified: DateTime::<Utc>::UNIX_EPOCH,
            data: Bytes::new(),
            etag: String::new(),
            owner: String::new(),
            content_type: None,
            cache_control: None,
            content_disposition: None,
            content_encoding: None,
            content_language: None,
            expires: None,
            website_redirect: None,
            metadata: BTreeMap::new(),
            storage_class: "STANDARD".into(),
            tags: Vec::new(),
            checksum: None,
            parts: Vec::new(),
            sse: Sse::default(),
            acl: Vec::new(),
            lock_mode: None,
            lock_until: None,
            legal_hold: None,
            restored_until: None,
            replication_status: None,
        }
    }
}

impl ObjectVersion {
    pub fn size(&self) -> i64 {
        self.data.len() as i64
    }

    /// Whether object lock protects this version from deletion right now.
    pub fn locked(&self, now: DateTime<Utc>) -> Option<&str> {
        if self.legal_hold.as_deref() == Some("ON") {
            return Some("LEGAL_HOLD");
        }
        match (&self.lock_mode, self.lock_until) {
            (Some(mode), Some(until)) if until > now => Some(mode.as_str()),
            _ => None,
        }
    }

    pub fn is_archived(&self) -> bool {
        matches!(self.storage_class.as_str(), "GLACIER" | "DEEP_ARCHIVE")
    }
}

/// A full-object or composite checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum {
    /// `CRC32`, `CRC32C`, `CRC64NVME`, `SHA1`, `SHA256`, ...
    pub algorithm: String,
    /// Base64, with `-N` for composite checksums.
    pub value: String,
    /// `FULL_OBJECT` or `COMPOSITE`.
    pub kind: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PartInfo {
    pub size: i64,
    pub etag: String,
    pub checksum: Option<String>,
}

/// Server-side encryption of one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Sse {
    /// `AES256`, `aws:kms` or `aws:kms:dsse`; `None` for SSE-C objects.
    pub algorithm: Option<String>,
    pub kms_key_id: Option<String>,
    pub kms_context: Option<String>,
    pub bucket_key: bool,
    /// Base64 MD5 of the customer key, for SSE-C.
    pub customer_key_md5: Option<String>,
    /// The object's data key, encrypted under the KMS key (base64), for
    /// SSE-KMS through MWS's KMS.
    pub kms_data_key: Option<String>,
    /// The KMS key was not named: use the AWS managed key `aws/s3`.
    #[serde(skip)]
    pub kms_default_key: bool,
}

impl Default for Sse {
    fn default() -> Self {
        Self {
            algorithm: Some("AES256".into()),
            kms_key_id: None,
            kms_context: None,
            bucket_key: false,
            customer_key_md5: None,
            kms_data_key: None,
            kms_default_key: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Upload {
    pub upload_id: String,
    pub key: String,
    pub initiated: DateTime<Utc>,
    pub initiator: String,
    /// Initiator ARN and id, for ListMultipartUploads.
    pub initiator_arn: String,
    /// Everything but the data, applied to the completed object.
    pub template: ObjectVersion,
    pub checksum_algorithm: Option<String>,
    /// `COMPOSITE` or `FULL_OBJECT`.
    pub checksum_type: Option<String>,
    pub parts: BTreeMap<i32, Part>,
}

impl Default for Upload {
    fn default() -> Self {
        Self {
            upload_id: String::new(),
            key: String::new(),
            initiated: DateTime::<Utc>::UNIX_EPOCH,
            initiator: String::new(),
            initiator_arn: String::new(),
            template: ObjectVersion::default(),
            checksum_algorithm: None,
            checksum_type: None,
            parts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Part {
    pub etag: String,
    pub last_modified: DateTime<Utc>,
    #[serde(with = "b64")]
    pub data: Bytes,
    /// Base64 checksum in the upload's algorithm.
    pub checksum: Option<String>,
}

impl Default for Part {
    fn default() -> Self {
        Self { etag: String::new(), last_modified: DateTime::<Utc>::UNIX_EPOCH, data: Bytes::new(), checksum: None }
    }
}

const ID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._";

fn random_id(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len).map(|_| ID_ALPHABET[rng.gen_range(0..ID_ALPHABET.len())] as char).collect()
}

/// A 32-character version id like S3's.
pub fn new_version_id() -> String {
    random_id(32)
}

pub fn new_upload_id() -> String {
    random_id(64).replace('.', "-")
}

mod b64 {
    use base64::Engine;
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map(Bytes::from).map_err(serde::de::Error::custom)
    }
}
