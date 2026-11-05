//! One repository's content: blobs, uploads in progress, images (by
//! manifest digest) and tags. Times are epoch milliseconds.

use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::digest;
use crate::manifest::{self, Manifest, ManifestError};

mod b64 {
    use base64::Engine;
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map(Bytes::from).map_err(serde::de::Error::custom)
    }
}

/// A stored blob (a layer or a config).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Blob {
    #[serde(with = "b64")]
    pub data: Bytes,
    pub stored_at: i64,
}

/// A blob upload in progress.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Upload {
    pub id: String,
    #[serde(with = "b64")]
    pub data: Bytes,
    /// The size of each part received.
    pub parts: Vec<u64>,
    pub started_at: i64,
}

/// An image: one manifest, by digest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Image {
    pub digest: String,
    /// The manifest exactly as pushed.
    pub manifest: String,
    pub media_type: String,
    pub artifact_type: Option<String>,
    /// The digest of the manifest this one refers to (`subject`).
    pub subject: Option<String>,
    pub config_media_type: Option<String>,
    /// Blob digests this image references.
    pub blobs: Vec<String>,
    /// Manifest digests an index references.
    pub children: Vec<String>,
    pub size: i64,
    pub pushed_at: i64,
    pub last_pulled_at: Option<i64>,
}

impl Image {
    /// Parse the stored manifest again.
    pub fn parsed(&self) -> Option<Manifest> {
        manifest::parse(self.manifest.as_bytes(), Some(&self.media_type)).ok()
    }
}

/// A repository's content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Repository {
    pub blobs: BTreeMap<String, Blob>,
    pub uploads: BTreeMap<String, Upload>,
    pub images: BTreeMap<String, Image>,
    /// Tag to manifest digest.
    pub tags: BTreeMap<String, String>,
}

/// Why an upload step failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    NotFound,
    /// A part did not start where the upload ends.
    InvalidRange {
        expected_first: u64,
    },
    InvalidDigest,
    DigestMismatch {
        actual: String,
    },
}

/// What completing an upload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completed {
    pub digest: String,
    pub size: u64,
    /// The repository already had the blob.
    pub already_existed: bool,
    pub parts: Vec<u64>,
}

/// A manifest to store.
#[derive(Debug, Clone, Default)]
pub struct PutManifest {
    pub manifest: String,
    /// The media type the client declared, if any.
    pub media_type: Option<String>,
    pub tag: Option<String>,
    /// The digest the client expects the manifest to have.
    pub digest: Option<String>,
}

/// What storing a manifest did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutOutcome {
    pub digest: String,
    /// The image was already stored (and so was the tag, if one was given).
    pub unchanged: bool,
    /// The image existed already, without this tag.
    pub image_existed: bool,
    /// The image that held the tag before, if it moved.
    pub tag_moved_from: Option<String>,
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutError {
    Manifest(ManifestError),
    DigestMismatch {
        computed: String,
    },
    InvalidDigest(String),
    MissingBlobs(Vec<String>),
    MissingManifests(Vec<String>),
    /// The tag points at another image and may not move.
    TagImmutable {
        tag: String,
    },
}

/// Docker's tag grammar.
pub fn is_valid_tag(tag: &str) -> bool {
    let b = tag.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

impl Repository {
    /// The tags that point at `digest`, sorted.
    pub fn tags_of(&self, digest: &str) -> Vec<String> {
        self.tags.iter().filter(|(_, d)| *d == digest).map(|(t, _)| t.clone()).collect()
    }

    /// The image a tag or digest names.
    pub fn resolve(&self, reference: &str) -> Option<&Image> {
        if reference.contains(':') {
            self.images.get(reference)
        } else {
            self.tags.get(reference).and_then(|d| self.images.get(d))
        }
    }

    pub fn resolve_digest(&self, reference: &str) -> Option<String> {
        self.resolve(reference).map(|i| i.digest.clone())
    }

    pub fn start_upload(&mut self, now: i64) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.uploads.insert(id.clone(), Upload { id: id.clone(), started_at: now, ..Default::default() });
        id
    }

    /// Append a part. With `first`, the part must start where the upload
    /// ends. Returns the upload's size afterwards.
    pub fn append_upload(&mut self, id: &str, first: Option<u64>, data: &[u8]) -> Result<u64, UploadError> {
        let upload = self.uploads.get_mut(id).ok_or(UploadError::NotFound)?;
        let len = upload.data.len() as u64;
        if let Some(first) = first {
            if first != len {
                return Err(UploadError::InvalidRange { expected_first: len });
            }
        }
        if !data.is_empty() {
            let mut joined = Vec::with_capacity(upload.data.len() + data.len());
            joined.extend_from_slice(&upload.data);
            joined.extend_from_slice(data);
            upload.data = Bytes::from(joined);
            upload.parts.push(data.len() as u64);
        }
        Ok(upload.data.len() as u64)
    }

    /// Finish an upload whose content must have `expected` as its digest.
    pub fn complete_upload(&mut self, id: &str, expected: &str, now: i64) -> Result<Completed, UploadError> {
        let upload = self.uploads.get(id).ok_or(UploadError::NotFound)?;
        if !digest::is_valid(expected) {
            return Err(UploadError::InvalidDigest);
        }
        let actual = digest::compute_like(expected, &upload.data).ok_or(UploadError::InvalidDigest)?;
        if actual != expected {
            return Err(UploadError::DigestMismatch { actual });
        }
        let upload = self.uploads.remove(id).expect("checked above");
        let size = upload.data.len() as u64;
        let already_existed = self.blobs.contains_key(expected);
        if !already_existed {
            self.blobs.insert(expected.to_string(), Blob { data: upload.data, stored_at: now });
        }
        Ok(Completed { digest: expected.to_string(), size, already_existed, parts: upload.parts })
    }

    /// Store a blob in one go (monolithic upload, cross-repository mount).
    pub fn put_blob(&mut self, digest: &str, data: Bytes, now: i64) -> bool {
        if self.blobs.contains_key(digest) {
            return false;
        }
        self.blobs.insert(digest.to_string(), Blob { data, stored_at: now });
        true
    }

    /// Check and store a manifest. `tag_locked` says whether a tag that
    /// already points at another image must stay where it is.
    pub fn put_manifest(
        &mut self,
        put: &PutManifest,
        now: i64,
        tag_locked: impl Fn(&str) -> bool,
    ) -> Result<(PutOutcome, Manifest), PutError> {
        self.store_manifest(put, now, tag_locked, true)
    }

    /// Store a manifest a pull-through cache fetched from upstream: the
    /// blobs and child manifests it names arrive later, when clients ask
    /// for them.
    pub fn put_cached_manifest(
        &mut self,
        put: &PutManifest,
        now: i64,
        tag_locked: impl Fn(&str) -> bool,
    ) -> Result<(PutOutcome, Manifest), PutError> {
        self.store_manifest(put, now, tag_locked, false)
    }

    fn store_manifest(
        &mut self,
        put: &PutManifest,
        now: i64,
        tag_locked: impl Fn(&str) -> bool,
        check_references: bool,
    ) -> Result<(PutOutcome, Manifest), PutError> {
        let parsed = manifest::parse(put.manifest.as_bytes(), put.media_type.as_deref()).map_err(PutError::Manifest)?;
        let computed = match &put.digest {
            Some(d) if !digest::is_valid(d) => return Err(PutError::InvalidDigest(d.clone())),
            Some(d) => digest::compute_like(d, put.manifest.as_bytes()).expect("valid digests have known algorithms"),
            None => digest::sha256(put.manifest.as_bytes()),
        };
        if let Some(d) = &put.digest {
            if *d != computed {
                return Err(PutError::DigestMismatch { computed });
            }
        }
        let missing: Vec<String> = parsed
            .required_blobs()
            .iter()
            .filter(|b| !self.blobs.contains_key(&b.digest))
            .map(|b| b.digest.clone())
            .collect();
        if check_references && !missing.is_empty() {
            return Err(PutError::MissingBlobs(missing));
        }
        let missing: Vec<String> = parsed
            .manifests
            .iter()
            .filter(|m| !self.images.contains_key(&m.digest))
            .map(|m| m.digest.clone())
            .collect();
        if check_references && !missing.is_empty() {
            return Err(PutError::MissingManifests(missing));
        }
        let previous = put.tag.as_ref().and_then(|t| self.tags.get(t)).cloned();
        if let (Some(tag), Some(prev)) = (&put.tag, &previous) {
            if *prev != computed && tag_locked(tag) {
                return Err(PutError::TagImmutable { tag: tag.clone() });
            }
        }
        let image_existed = self.images.contains_key(&computed);
        let unchanged = image_existed && (put.tag.is_none() || previous.as_deref() == Some(computed.as_str()));
        if !image_existed {
            let size = if parsed.is_index() {
                parsed.manifests.iter().filter_map(|m| self.images.get(&m.digest)).map(|i| i.size).max().unwrap_or(0)
            } else {
                parsed.layers_size()
            };
            let image = Image {
                digest: computed.clone(),
                manifest: put.manifest.clone(),
                media_type: parsed.media_type.clone(),
                artifact_type: parsed.artifact_type.clone(),
                subject: parsed.subject.as_ref().map(|s| s.digest.clone()),
                config_media_type: parsed.config.as_ref().map(|c| c.media_type.clone()).filter(|m| !m.is_empty()),
                blobs: parsed.required_blobs().iter().map(|b| b.digest.clone()).collect(),
                children: parsed.manifests.iter().map(|m| m.digest.clone()).collect(),
                size,
                pushed_at: now,
                last_pulled_at: None,
            };
            self.images.insert(computed.clone(), image);
        }
        if let Some(tag) = &put.tag {
            self.tags.insert(tag.clone(), computed.clone());
        }
        let tag_moved_from = previous.filter(|p| *p != computed);
        Ok((PutOutcome { digest: computed, unchanged, image_existed, tag_moved_from }, parsed))
    }

    /// Remove an image and every tag pointing at it.
    pub fn delete_image(&mut self, digest: &str) -> Option<Image> {
        let image = self.images.remove(digest)?;
        self.tags.retain(|_, d| d != digest);
        Some(image)
    }

    /// Remove a tag. Returns the digest it pointed at.
    pub fn untag(&mut self, tag: &str) -> Option<String> {
        self.tags.remove(tag)
    }

    /// Images whose subject is `digest`, optionally only those of one
    /// artifact type.
    pub fn referrers(&self, digest: &str, artifact_type: Option<&str>) -> Vec<&Image> {
        self.images
            .values()
            .filter(|i| i.subject.as_deref() == Some(digest))
            .filter(|i| {
                artifact_type.is_none_or(|t| i.artifact_type.as_deref().or(i.config_media_type.as_deref()) == Some(t))
            })
            .collect()
    }

    /// Whether some index in the repository references
    /// `digest`.
    pub fn referenced_by_index(&self, digest: &str) -> bool {
        self.images.values().any(|i| i.children.iter().any(|c| c == digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(repo: &mut Repository, data: &[u8]) -> String {
        let id = repo.start_upload(0);
        repo.append_upload(&id, Some(0), data).unwrap();
        repo.complete_upload(&id, &digest::sha256(data), 0).unwrap().digest
    }

    #[test]
    fn push_and_tag() {
        let mut repo = Repository::default();
        let config = layer(&mut repo, b"{}");
        let l = layer(&mut repo, b"layer");
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": manifest::DOCKER_SCHEMA2,
            "config": {"mediaType": manifest::DOCKER_CONFIG, "size": 2, "digest": config},
            "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 5, "digest": l}]
        })
        .to_string();
        let put = PutManifest { manifest: manifest.clone(), tag: Some("v1".into()), ..Default::default() };
        let (out, _) = repo.put_manifest(&put, 1, |_| true).unwrap();
        assert!(!out.unchanged);
        assert_eq!(repo.resolve("v1").unwrap().size, 5);
        let (again, _) = repo.put_manifest(&put, 2, |_| true).unwrap();
        assert!(again.unchanged);
        let other = PutManifest { manifest: format!("{manifest} "), tag: Some("v1".into()), ..Default::default() };
        assert_eq!(repo.put_manifest(&other, 3, |_| true).unwrap_err(), PutError::TagImmutable { tag: "v1".into() });
        let (moved, _) = repo.put_manifest(&other, 3, |_| false).unwrap();
        assert_eq!(moved.tag_moved_from.as_deref(), Some(out.digest.as_str()));
    }

    #[test]
    fn missing_layers_are_refused() {
        let mut repo = Repository::default();
        let d = digest::sha256(b"x");
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": manifest::OCI_MANIFEST,
            "config": {"mediaType": manifest::OCI_CONFIG, "size": 1, "digest": d},
            "layers": []
        })
        .to_string();
        let err = repo.put_manifest(&PutManifest { manifest, ..Default::default() }, 0, |_| false).unwrap_err();
        assert_eq!(err, PutError::MissingBlobs(vec![d]));
    }

    #[test]
    fn upload_ranges() {
        let mut repo = Repository::default();
        let id = repo.start_upload(0);
        assert_eq!(repo.append_upload(&id, Some(0), b"ab").unwrap(), 2);
        assert_eq!(repo.append_upload(&id, Some(5), b"c"), Err(UploadError::InvalidRange { expected_first: 2 }));
        assert!(matches!(
            repo.complete_upload(&id, &digest::sha256(b"abc"), 0),
            Err(UploadError::DigestMismatch { .. })
        ));
        assert!(repo.complete_upload(&id, &digest::sha256(b"ab"), 0).is_ok());
    }
}
