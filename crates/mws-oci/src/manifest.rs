//! Image manifests and indexes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DOCKER_SCHEMA1: &str = "application/vnd.docker.distribution.manifest.v1+json";
pub const DOCKER_SCHEMA1_SIGNED: &str = "application/vnd.docker.distribution.manifest.v1+prettyjws";
pub const DOCKER_SCHEMA2: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";

/// Every manifest media type a registry accepts.
pub const MEDIA_TYPES: &[&str] =
    &[DOCKER_SCHEMA1, DOCKER_SCHEMA1_SIGNED, DOCKER_SCHEMA2, DOCKER_LIST, OCI_MANIFEST, OCI_INDEX];

/// Layers a registry does not store (Windows base layers and the like).
const FOREIGN_LAYERS: &[&str] = &[
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
];

/// A content descriptor.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Descriptor {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Value>,
}

impl Descriptor {
    /// Whether the registry stores this blob (foreign layers live
    /// elsewhere).
    pub fn is_distributable(&self) -> bool {
        !FOREIGN_LAYERS.contains(&self.media_type.as_str())
    }
}

/// What a manifest says about itself and what it references.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    pub media_type: String,
    pub config: Option<Descriptor>,
    pub layers: Vec<Descriptor>,
    /// For indexes and manifest lists.
    pub manifests: Vec<Descriptor>,
    pub subject: Option<Descriptor>,
    /// The `artifactType` field, or for an OCI manifest whose config is not
    /// an image config, the config's media type.
    pub artifact_type: Option<String>,
    pub annotations: Option<serde_json::Map<String, Value>>,
}

impl Manifest {
    pub fn is_index(&self) -> bool {
        matches!(self.media_type.as_str(), DOCKER_LIST | OCI_INDEX)
    }

    /// The blobs a registry must hold before it accepts this manifest.
    pub fn required_blobs(&self) -> Vec<&Descriptor> {
        self.config.iter().chain(self.layers.iter()).filter(|d| d.is_distributable()).collect()
    }

    /// The size an image takes up: the sum of its layers.
    pub fn layers_size(&self) -> i64 {
        self.layers.iter().map(|l| l.size.max(0)).sum()
    }
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Not JSON, or not a manifest.
    Invalid(String),
    /// The declared media type (`Content-Type`) disagrees with the
    /// document's `mediaType`.
    MediaTypeMismatch { declared: String, document: String },
    /// A media type no registry accepts.
    Unsupported(String),
}

fn descriptor(v: &Value, what: &str) -> Result<Descriptor, ManifestError> {
    let d: Descriptor =
        serde_json::from_value(v.clone()).map_err(|e| ManifestError::Invalid(format!("{what}: {e}")))?;
    if !crate::digest::is_valid(&d.digest) {
        return Err(ManifestError::Invalid(format!("{what}: invalid digest {:?}", d.digest)));
    }
    Ok(d)
}

fn descriptors(v: Option<&Value>, what: &str) -> Result<Vec<Descriptor>, ManifestError> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|i| descriptor(i, what)).collect(),
        Some(_) => Err(ManifestError::Invalid(format!("{what} must be an array"))),
    }
}

/// Parse a manifest. `declared` is the media type the client sent with it
/// (`Content-Type`, or the API's media type parameter).
pub fn parse(bytes: &[u8], declared: Option<&str>) -> Result<Manifest, ManifestError> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| ManifestError::Invalid(e.to_string()))?;
    let obj = doc.as_object().ok_or_else(|| ManifestError::Invalid("manifest must be a JSON object".into()))?;
    let schema = obj.get("schemaVersion").and_then(Value::as_i64);
    let field = obj.get("mediaType").and_then(Value::as_str).map(str::to_string);
    let declared = declared.map(|d| d.split(';').next().unwrap_or(d).trim().to_string()).filter(|d| !d.is_empty());
    let declared = declared.filter(|d| d != "application/json" && d != "application/octet-stream");
    let media_type = match (schema, &declared, &field) {
        (Some(1), Some(d), _) => d.clone(),
        (Some(1), None, _) => {
            if obj.contains_key("signatures") {
                DOCKER_SCHEMA1_SIGNED.into()
            } else {
                DOCKER_SCHEMA1.into()
            }
        }
        (Some(2), Some(d), Some(f)) if d != f => {
            return Err(ManifestError::MediaTypeMismatch { declared: d.clone(), document: f.clone() });
        }
        (Some(2), Some(d), _) => d.clone(),
        (Some(2), None, Some(f)) => f.clone(),
        (Some(2), None, None) => {
            if obj.contains_key("manifests") {
                OCI_INDEX.into()
            } else {
                OCI_MANIFEST.into()
            }
        }
        _ => return Err(ManifestError::Invalid("unknown schemaVersion".into())),
    };
    if !MEDIA_TYPES.contains(&media_type.as_str()) {
        return Err(ManifestError::Unsupported(media_type));
    }
    let mut m = Manifest { media_type, ..Default::default() };
    match m.media_type.as_str() {
        DOCKER_SCHEMA1 | DOCKER_SCHEMA1_SIGNED => {
            let layers = obj.get("fsLayers").and_then(Value::as_array).cloned().unwrap_or_default();
            for l in layers {
                let digest = l.get("blobSum").and_then(Value::as_str).unwrap_or_default().to_string();
                if !crate::digest::is_valid(&digest) {
                    return Err(ManifestError::Invalid(format!("invalid blobSum {digest:?}")));
                }
                // Schema 1 lists layers top first and repeats empty ones.
                if !m.layers.iter().any(|d| d.digest == digest) {
                    m.layers.push(Descriptor { digest, size: 0, ..Default::default() });
                }
            }
        }
        DOCKER_LIST | OCI_INDEX => {
            m.manifests = descriptors(obj.get("manifests"), "manifests")?;
        }
        _ => {
            let config = obj.get("config").ok_or_else(|| ManifestError::Invalid("config is required".into()))?;
            m.config = Some(descriptor(config, "config")?);
            m.layers = descriptors(obj.get("layers"), "layers")?;
        }
    }
    if let Some(s) = obj.get("subject").filter(|s| !s.is_null()) {
        m.subject = Some(descriptor(s, "subject")?);
    }
    m.artifact_type = obj.get("artifactType").and_then(Value::as_str).map(str::to_string);
    if m.artifact_type.is_none() && m.media_type == OCI_MANIFEST {
        let config_type = m.config.as_ref().map(|c| c.media_type.clone()).unwrap_or_default();
        if !config_type.is_empty() && config_type != OCI_CONFIG && config_type != OCI_EMPTY {
            m.artifact_type = Some(config_type);
        }
    }
    m.annotations = obj.get("annotations").and_then(Value::as_object).cloned();
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn docker_manifest() {
        let doc = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": DOCKER_SCHEMA2,
            "config": {"mediaType": DOCKER_CONFIG, "size": 10, "digest": D1},
            "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 7, "digest": D1}]
        });
        let m = parse(doc.to_string().as_bytes(), Some(DOCKER_SCHEMA2)).unwrap();
        assert_eq!(m.media_type, DOCKER_SCHEMA2);
        assert_eq!(m.required_blobs().len(), 2);
        assert_eq!(m.layers_size(), 7);
        assert!(matches!(
            parse(doc.to_string().as_bytes(), Some(OCI_MANIFEST)),
            Err(ManifestError::MediaTypeMismatch { .. })
        ));
    }

    #[test]
    fn artifact_manifest() {
        let doc = serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.example.sbom", "size": 2, "digest": D1},
            "layers": [],
            "subject": {"mediaType": OCI_MANIFEST, "size": 2, "digest": D1}
        });
        let m = parse(doc.to_string().as_bytes(), None).unwrap();
        assert_eq!(m.media_type, OCI_MANIFEST);
        assert_eq!(m.artifact_type.as_deref(), Some("application/vnd.example.sbom"));
        assert_eq!(m.subject.unwrap().digest, D1);
    }
}
