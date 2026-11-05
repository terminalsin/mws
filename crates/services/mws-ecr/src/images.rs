//! Images and layers: uploads through the API, PutImage (shared with the
//! registry endpoint), reads, deletes, listings, scans, storage classes and
//! authorization tokens.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_oci::store::{PutError, PutManifest, PutOutcome};
use mws_oci::{digest, manifest::ManifestError};
use serde_json::json;

use crate::generated::{errors, types};
use crate::names::{self, authorize_repo, dt, image_not_found, invalid_parameter, now_ms, repository_arn};
use crate::state::{ImageMeta, Registry, Repo, Scan, State};
use crate::{Ecr, EcrEvent};

/// The part size `InitiateLayerUpload` asks for.
const PART_SIZE: i64 = 10 * 1024 * 1024;
/// Parts other than the last must be at least this big.
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
const MAX_PART_SIZE: usize = 20 * 1024 * 1024;
/// How long a registry password lasts.
pub(crate) const TOKEN_HOURS: i64 = 12;
/// How often an image may be scanned with basic scanning.
const SCAN_INTERVAL_MS: i64 = 24 * 3600 * 1000;

/// How a manifest is being put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    Api,
    Registry,
    /// Replication or a backfill: no events or further replication.
    Replication,
}

pub(crate) fn digest_ok(d: &str) -> bool {
    let Some((alg, hex)) = d.split_once(':') else { return false };
    !alg.is_empty()
        && alg.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_+.".contains(&b))
        && !hex.is_empty()
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn failure(id: &types::ImageIdentifier, code: &str, reason: &str) -> types::ImageFailure {
    types::ImageFailure {
        image_id: Some(id.clone()),
        failure_code: Some(code.into()),
        failure_reason: Some(reason.into()),
    }
}

/// The digest an image id names, or the batch failure ECR reports.
fn resolve_id(repo: &Repo, id: &types::ImageIdentifier) -> Result<String, types::ImageFailure> {
    match (&id.image_digest, &id.image_tag) {
        (None, None) => {
            Err(failure(id, "MissingDigestAndTag", "Invalid request parameters: both tag and digest cannot be null"))
        }
        (Some(d), _) if !digest_ok(d) => Err(failure(
            id,
            "InvalidImageDigest",
            "Invalid request parameters: image digest should satisfy the regex '[a-zA-Z0-9-_+.]+:[a-fA-F0-9]+'",
        )),
        (Some(d), Some(t)) => match repo.content.tags.get(t) {
            Some(td) if td == d => Ok(d.clone()),
            Some(_) => Err(failure(
                id,
                "ImageTagDoesNotMatchDigest",
                "Invalid request parameters: given tag and digest do not point to the same image",
            )),
            None => Err(failure(id, "ImageNotFound", "Requested image not found")),
        },
        (Some(d), None) => repo
            .content
            .images
            .contains_key(d)
            .then(|| d.clone())
            .ok_or_else(|| failure(id, "ImageNotFound", "Requested image not found")),
        (None, Some(t)) => {
            repo.content.tags.get(t).cloned().ok_or_else(|| failure(id, "ImageNotFound", "Requested image not found"))
        }
    }
}

/// The digest an image id names, or `ImageNotFoundException`.
pub(crate) fn find_image(reg: &Registry, name: &str, id: &types::ImageIdentifier) -> Result<String, ServiceError> {
    let repo = &reg.repositories[name];
    resolve_id(repo, id).map_err(|f| match f.failure_code.as_deref() {
        Some("InvalidImageDigest") | Some("MissingDigestAndTag") => {
            invalid_parameter(f.failure_reason.unwrap_or_default())
        }
        _ => image_not_found(id, name, &reg.account),
    })
}

pub(crate) fn image_event(
    partition: &str,
    reg: &Registry,
    repo: &str,
    action: &str,
    digest: &str,
    tag: Option<&str>,
    now: i64,
) -> EcrEvent {
    let mut detail = json!({
        "result": "SUCCESS",
        "repository-name": repo,
        "image-digest": digest,
        "action-type": action,
    });
    if let Some(t) = tag {
        detail["image-tag"] = json!(t);
    }
    EcrEvent {
        partition: partition.to_string(),
        account: reg.account.clone(),
        region: reg.region.clone(),
        detail_type: "ECR Image Action".into(),
        resources: vec![],
        detail,
        time: dt(now),
    }
}

fn scan_event(partition: &str, reg: &Registry, repo: &Repo, digest: &str, now: i64) -> EcrEvent {
    EcrEvent {
        partition: partition.to_string(),
        account: reg.account.clone(),
        region: reg.region.clone(),
        detail_type: "ECR Image Scan".into(),
        resources: vec![repo.arn.clone()],
        detail: json!({
            "scan-status": "COMPLETE",
            "repository-name": repo.name,
            "finding-severity-counts": {},
            "image-digest": digest,
            "image-tags": repo.content.tags_of(digest),
        }),
        time: dt(now),
    }
}

pub(crate) fn put_error(e: PutError, name: &str, account: &str) -> ServiceError {
    match e {
        PutError::Manifest(ManifestError::Invalid(_)) => {
            invalid_parameter("Invalid parameter at 'ImageManifest' failed to satisfy constraint: 'Invalid JSON syntax'")
        }
        PutError::Manifest(ManifestError::MediaTypeMismatch { declared, document }) => invalid_parameter(format!(
            "Invalid parameter at 'imageManifestMediaType' failed to satisfy constraint: 'Manifest MediaType '{document}' does not match the provided MediaType '{declared}''"
        )),
        PutError::Manifest(ManifestError::Unsupported(t)) => invalid_parameter(format!(
            "Invalid parameter at 'imageManifestMediaType' failed to satisfy constraint: 'Unsupported manifest media type '{t}''"
        )),
        PutError::DigestMismatch { computed } => errors::image_digest_does_not_match(format!(
            "The provided image digest does not match the digest of the manifest '{computed}'"
        )),
        PutError::InvalidDigest(_) => invalid_parameter(
            "Invalid parameter at 'imageDigest' failed to satisfy constraint: 'must satisfy regular expression '[a-zA-Z0-9-_+.]+:[a-fA-F0-9]+''",
        ),
        PutError::MissingBlobs(d) => errors::layers_not_found(format!(
            "Layers with digests '[{}]' required for pushing image into repository with name '{name}' in registry with id '{account}' do not exist",
            d.join(", ")
        )),
        PutError::MissingManifests(d) => errors::referenced_images_not_found(format!(
            "Images with digests '[{}]' referenced by the manifest list do not exist in the repository with name '{name}' in registry with id '{account}'",
            d.join(", ")
        )),
        PutError::TagImmutable { tag } => errors::image_tag_already_exists(format!(
            "The image tag '{tag}' already exists in the '{name}' repository and cannot be overwritten because the repository is immutable."
        )),
    }
}

/// Whether the registry's scanning rules scan `repo` on push.
fn scans_on_push(reg: &Registry, repo: &Repo) -> bool {
    let rules = reg.scanning.as_ref().and_then(|s| s.rules.clone()).unwrap_or_default();
    repo.scan_on_push
        || rules.iter().any(|r| {
            matches!(r.scan_frequency.as_str(), "SCAN_ON_PUSH" | "CONTINUOUS_SCAN")
                && r.repository_filters.iter().any(|f| names::wildcard(&f.filter, &repo.name))
        })
}

impl Ecr {
    /// Store a manifest in a repository and apply what follows a push:
    /// scans, signing, replication and events.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn put_image_in(
        &self,
        st: &mut State,
        partition: &str,
        account: &str,
        region: &str,
        name: &str,
        put: PutManifest,
        via: Via,
        now: i64,
    ) -> Result<(PutOutcome, Vec<EcrEvent>), ServiceError> {
        let reg = st.registry_mut(account, region);
        let repo = reg.repositories.get_mut(name).ok_or_else(|| names::repository_not_found(name, account))?;
        let tag = put.tag.clone();
        let locked = repo.clone();
        let (outcome, parsed) =
            repo.content.put_manifest(&put, now, |t| locked.tag_locked(t)).map_err(|e| put_error(e, name, account))?;
        if outcome.unchanged {
            if via == Via::Api {
                let message = match &tag {
                    Some(t) => format!(
                        "Image with digest '{}' and tag '{t}' already exists in the repository with name '{name}' in registry with id '{account}'",
                        outcome.digest
                    ),
                    None => format!(
                        "Image with digest '{}' already exists in the repository with name '{name}' in registry with id '{account}'",
                        outcome.digest
                    ),
                };
                return Err(errors::image_already_exists(message));
            }
            return Ok((outcome, Vec::new()));
        }
        let mut events = Vec::new();
        let d = outcome.digest.clone();
        if !outcome.image_existed {
            repo.meta.insert(d.clone(), ImageMeta::default());
        }
        let reg = st.registry(account, region).expect("exists");
        let repo = &reg.repositories[name];
        let scan = !outcome.image_existed && scans_on_push(reg, repo) && via != Via::Replication;
        let signing: Vec<types::ImageSigningStatus> = reg
            .signing
            .iter()
            .flat_map(|s| s.rules.iter())
            .filter(|r| {
                r.repository_filters
                    .as_ref()
                    .is_none_or(|f| f.is_empty() || f.iter().any(|f| names::wildcard(&f.filter, name)))
            })
            .map(|r| types::ImageSigningStatus {
                signing_profile_arn: Some(r.signing_profile_arn.clone()),
                failure_code: Some("SIGNING_PROFILE_NOT_FOUND".into()),
                failure_reason: Some("MWS does not emulate AWS Signer, so images are not signed.".into()),
                status: Some("FAILED".into()),
            })
            .collect();
        if via != Via::Replication {
            events.push(image_event(partition, reg, name, "PUSH", &d, tag.as_deref(), now));
        }
        if scan {
            let status =
                if parsed.is_index() || parsed.artifact_type.is_some() { "UNSUPPORTED_IMAGE" } else { "COMPLETE" };
            if status == "COMPLETE" {
                events.push(scan_event(partition, reg, repo, &d, now));
            }
            let repo = st.registry_mut(account, region).repositories.get_mut(name).expect("exists");
            let meta = repo.meta.entry(d.clone()).or_default();
            meta.scan = Some(Scan { status: status.into(), started_at: now, completed_at: Some(now) });
        }
        if !signing.is_empty() && !outcome.image_existed {
            let repo = st.registry_mut(account, region).repositories.get_mut(name).expect("exists");
            repo.meta.entry(d.clone()).or_default().signing = signing;
        }
        if via != Via::Replication {
            let statuses = crate::replication::replicate(st, partition, account, region, name, &d, now);
            if !statuses.is_empty() {
                let repo = st.registry_mut(account, region).repositories.get_mut(name).expect("exists");
                repo.meta.entry(d.clone()).or_default().replication = statuses;
            }
        }
        Ok((outcome, events))
    }

    pub(crate) fn put_image(
        &self,
        ctx: &RequestContext,
        input: types::PutImageRequest,
    ) -> Result<types::PutImageResponse, ServiceError> {
        let account = Ecr::target(ctx, input.registry_id.as_deref());
        let name = input.repository_name.clone();
        let arn = repository_arn(&ctx.partition, &ctx.region, &account, &name);
        let now = now_ms(ctx);
        let (out, events) = {
            let mut st = self.lock();
            let reg = st.registry_mut(&account, &ctx.region);
            authorize_repo(ctx, "ecr:PutImage", &arn, reg.repositories.get(&name), ConditionContext::new())?;
            if !reg.repositories.contains_key(&name) {
                return Err(names::repository_not_found(&name, &account));
            }
            let put = PutManifest {
                manifest: input.image_manifest.clone(),
                media_type: input.image_manifest_media_type.clone(),
                tag: input.image_tag.clone(),
                digest: input.image_digest.clone(),
            };
            let (outcome, events) =
                self.put_image_in(&mut st, &ctx.partition, &account, &ctx.region, &name, put, Via::Api, now)?;
            let reg = st.registry(&account, &ctx.region).expect("exists");
            let image = &reg.repositories[&name].content.images[&outcome.digest];
            let out = types::Image {
                registry_id: Some(account.clone()),
                repository_name: Some(name.clone()),
                image_id: Some(types::ImageIdentifier {
                    image_digest: Some(outcome.digest.clone()),
                    image_tag: input.image_tag.clone(),
                }),
                image_manifest: Some(image.manifest.clone()),
                image_manifest_media_type: Some(image.media_type.clone()),
            };
            (out, events)
        };
        self.emit(ctx, events);
        Ok(types::PutImageResponse { image: Some(out) })
    }

    pub(crate) fn batch_get_image(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetImageRequest,
    ) -> Result<types::BatchGetImageResponse, ServiceError> {
        let now = now_ms(ctx);
        let caller = ctx.caller.arn.clone();
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:BatchGetImage",
            |_, reg, name| {
                let excluded = pull_time_excluded(reg, ctx);
                let account = reg.account.clone();
                let repo = reg.repositories.get_mut(name).expect("checked");
                let mut images = Vec::new();
                let mut failures = Vec::new();
                for id in &input.image_ids {
                    match resolve_id(repo, id) {
                        Err(f) => failures.push(f),
                        Ok(d) if repo.status(&d) != "ACTIVE" => failures.push(failure(
                            id,
                            "ImageNotFound",
                            "Requested image is archived. Restore it to standard storage to pull it.",
                        )),
                        Ok(d) => {
                            let image = repo.content.images.get_mut(&d).expect("resolved");
                            if !excluded {
                                image.last_pulled_at = Some(now);
                            }
                            images.push(types::Image {
                                registry_id: Some(account.clone()),
                                repository_name: Some(name.to_string()),
                                image_id: Some(types::ImageIdentifier {
                                    image_digest: Some(d.clone()),
                                    image_tag: id.image_tag.clone(),
                                }),
                                image_manifest: Some(image.manifest.clone()),
                                image_manifest_media_type: Some(image.media_type.clone()),
                            });
                        }
                    }
                }
                let _ = &caller;
                Ok(types::BatchGetImageResponse { images: Some(images), failures: Some(failures) })
            },
        )
    }

    pub(crate) fn batch_delete_image(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteImageRequest,
    ) -> Result<types::BatchDeleteImageResponse, ServiceError> {
        let now = now_ms(ctx);
        let partition = ctx.partition.clone();
        let (out, events) = self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:BatchDeleteImage",
            |_, reg, name| {
                let mut deleted = Vec::new();
                let mut failures = Vec::new();
                let mut events = Vec::new();
                for id in &input.image_ids {
                    let repo = reg.repositories.get_mut(name).expect("checked");
                    let d = match resolve_id(repo, id) {
                        Ok(d) => d,
                        Err(f) => {
                            failures.push(f);
                            continue;
                        }
                    };
                    let untag_only = id.image_digest.is_none();
                    let remaining = repo.content.tags_of(&d).len();
                    if untag_only && remaining > 1 {
                        let tag = id.image_tag.clone().expect("tag-only id");
                        repo.content.untag(&tag);
                        deleted.push(types::ImageIdentifier {
                            image_digest: Some(d.clone()),
                            image_tag: Some(tag.clone()),
                        });
                        continue;
                    }
                    let parents: Vec<String> = repo
                        .content
                        .images
                        .values()
                        .filter(|i| i.children.contains(&d))
                        .map(|i| i.digest.clone())
                        .collect();
                    if !parents.is_empty() {
                        failures.push(failure(
                            id,
                            "ImageReferencedByManifestList",
                            &format!("Requested image referenced by manifest list: [{}]", parents.join(", ")),
                        ));
                        continue;
                    }
                    let tags = repo.content.tags_of(&d);
                    repo.content.delete_image(&d);
                    repo.meta.remove(&d);
                    if tags.is_empty() {
                        deleted.push(types::ImageIdentifier { image_digest: Some(d.clone()), image_tag: None });
                    }
                    for t in &tags {
                        deleted
                            .push(types::ImageIdentifier { image_digest: Some(d.clone()), image_tag: Some(t.clone()) });
                    }
                    let reg_ref: &Registry = reg;
                    events.push(image_event(
                        &partition,
                        reg_ref,
                        name,
                        "DELETE",
                        &d,
                        tags.first().map(String::as_str),
                        now,
                    ));
                }
                Ok((types::BatchDeleteImageResponse { image_ids: Some(deleted), failures: Some(failures) }, events))
            },
        )?;
        self.emit(ctx, events);
        Ok(out)
    }

    pub(crate) fn list_images(
        &self,
        ctx: &RequestContext,
        input: types::ListImagesRequest,
    ) -> Result<types::ListImagesResponse, ServiceError> {
        self.with_repo(ctx, input.registry_id.as_deref(), &input.repository_name, "ecr:ListImages", |_, reg, name| {
            let repo = &reg.repositories[name];
            let tag_status = input.filter.as_ref().and_then(|f| f.tag_status.clone()).unwrap_or_else(|| "ANY".into());
            let image_status =
                input.filter.as_ref().and_then(|f| f.image_status.clone()).unwrap_or_else(|| "ACTIVE".into());
            let mut ids = Vec::new();
            for image in repo.content.images.values() {
                if image_status != "ANY" && repo.status(&image.digest) != image_status {
                    continue;
                }
                let tags = repo.content.tags_of(&image.digest);
                if tags.is_empty() {
                    if tag_status != "TAGGED" {
                        ids.push(types::ImageIdentifier { image_digest: Some(image.digest.clone()), image_tag: None });
                    }
                } else if tag_status != "UNTAGGED" {
                    for t in tags {
                        ids.push(types::ImageIdentifier {
                            image_digest: Some(image.digest.clone()),
                            image_tag: Some(t),
                        });
                    }
                }
            }
            let (image_ids, next_token) = names::page(&ids, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(types::ListImagesResponse { image_ids: Some(image_ids), next_token })
        })
    }

    pub(crate) fn image_detail(reg: &Registry, repo: &Repo, d: &str) -> types::ImageDetail {
        let image = &repo.content.images[d];
        let meta = repo.meta(d);
        let tags = repo.content.tags_of(d);
        let scan = meta.scan.as_ref();
        types::ImageDetail {
            registry_id: Some(reg.account.clone()),
            repository_name: Some(repo.name.clone()),
            image_digest: Some(d.to_string()),
            image_tags: (!tags.is_empty()).then_some(tags),
            image_size_in_bytes: Some(image.size),
            image_pushed_at: Some(dt(image.pushed_at)),
            image_scan_status: scan.map(|s| scan_status(&s.status)),
            image_scan_findings_summary: scan.filter(|s| s.status == "COMPLETE").map(|s| {
                types::ImageScanFindingsSummary {
                    image_scan_completed_at: s.completed_at.map(dt),
                    vulnerability_source_updated_at: s.completed_at.map(dt),
                    finding_severity_counts: Some(Default::default()),
                }
            }),
            image_manifest_media_type: Some(image.media_type.clone()),
            artifact_media_type: image.config_media_type.clone(),
            last_recorded_pull_time: image.last_pulled_at.map(dt),
            subject_manifest_digest: image.subject.clone(),
            image_status: Some(repo.status(d)),
            last_archived_at: meta.last_archived_at.map(dt),
            last_activated_at: meta.last_activated_at.map(dt),
        }
    }

    pub(crate) fn describe_images(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImagesRequest,
    ) -> Result<types::DescribeImagesResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:DescribeImages",
            |_, reg, name| {
                let repo = &reg.repositories[name];
                let digests: Vec<String> = match &input.image_ids {
                    Some(ids) => {
                        let mut out = Vec::new();
                        for id in ids {
                            let d = find_image(reg, name, id)?;
                            if !out.contains(&d) {
                                out.push(d);
                            }
                        }
                        out
                    }
                    None => {
                        let tag_status =
                            input.filter.as_ref().and_then(|f| f.tag_status.clone()).unwrap_or_else(|| "ANY".into());
                        let image_status = input
                            .filter
                            .as_ref()
                            .and_then(|f| f.image_status.clone())
                            .unwrap_or_else(|| "ACTIVE".into());
                        let mut images: Vec<_> = repo.content.images.values().collect();
                        images.sort_by_key(|i| (i.pushed_at, i.digest.clone()));
                        images
                            .into_iter()
                            .filter(|i| image_status == "ANY" || repo.status(&i.digest) == image_status)
                            .filter(|i| {
                                let tagged = !repo.content.tags_of(&i.digest).is_empty();
                                match tag_status.as_str() {
                                    "TAGGED" => tagged,
                                    "UNTAGGED" => !tagged,
                                    _ => true,
                                }
                            })
                            .map(|i| i.digest.clone())
                            .collect()
                    }
                };
                let details: Vec<_> = digests.iter().map(|d| Self::image_detail(reg, repo, d)).collect();
                let (image_details, next_token) =
                    names::page(&details, input.next_token.as_deref(), input.max_results, 100)?;
                Ok(types::DescribeImagesResponse { image_details: Some(image_details), next_token })
            },
        )
    }

    pub(crate) fn batch_check_layer_availability(
        &self,
        ctx: &RequestContext,
        input: types::BatchCheckLayerAvailabilityRequest,
    ) -> Result<types::BatchCheckLayerAvailabilityResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:BatchCheckLayerAvailability",
            |_, reg, name| {
                let repo = &reg.repositories[name];
                let mut layers = Vec::new();
                let mut failures = Vec::new();
                for d in &input.layer_digests {
                    if !digest_ok(d) {
                        failures.push(types::LayerFailure {
                            layer_digest: Some(d.clone()),
                            failure_code: Some("InvalidLayerDigest".into()),
                            failure_reason: Some("Invalid layer digest".into()),
                        });
                        continue;
                    }
                    match repo.content.blobs.get(d) {
                        Some(b) => layers.push(types::Layer {
                            layer_digest: Some(d.clone()),
                            layer_availability: Some("AVAILABLE".into()),
                            layer_size: Some(b.data.len() as i64),
                            media_type: layer_media_type(repo, d),
                        }),
                        None => failures.push(types::LayerFailure {
                            layer_digest: Some(d.clone()),
                            failure_code: Some("MissingLayerDigest".into()),
                            failure_reason: Some("Could not find the layer".into()),
                        }),
                    }
                }
                Ok(types::BatchCheckLayerAvailabilityResponse { layers: Some(layers), failures: Some(failures) })
            },
        )
    }

    pub(crate) fn initiate_layer_upload(
        &self,
        ctx: &RequestContext,
        input: types::InitiateLayerUploadRequest,
    ) -> Result<types::InitiateLayerUploadResponse, ServiceError> {
        let now = now_ms(ctx);
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:InitiateLayerUpload",
            |_, reg, name| {
                let id = reg.repositories.get_mut(name).expect("checked").content.start_upload(now);
                Ok(types::InitiateLayerUploadResponse { upload_id: Some(id), part_size: Some(PART_SIZE) })
            },
        )
    }

    fn upload_not_found(id: &str, name: &str, account: &str) -> ServiceError {
        errors::upload_not_found(format!(
            "The upload with id '{id}' does not exist in the repository with name '{name}' in the registry with id '{account}'"
        ))
    }

    pub(crate) fn upload_layer_part(
        &self,
        ctx: &RequestContext,
        input: types::UploadLayerPartRequest,
    ) -> Result<types::UploadLayerPartResponse, ServiceError> {
        self.with_repo(ctx, input.registry_id.as_deref(), &input.repository_name, "ecr:UploadLayerPart", |_, reg, name| {
            let account = reg.account.clone();
            let repo = reg.repositories.get_mut(name).expect("checked");
            let id = &input.upload_id;
            let upload = repo.content.uploads.get(id).ok_or_else(|| Self::upload_not_found(id, name, &account))?;
            let have = upload.data.len() as i64;
            let invalid = || {
                errors::invalid_layer_part(format!(
                    "The layer part size is not valid, or the first byte specified is not consecutive to the last byte of a previous layer part upload. Last valid byte received: {}",
                    have - 1
                ))
                .with_field("registryId", mws_core::ErrorValue::String(account.clone()))
                .with_field("repositoryName", mws_core::ErrorValue::String(name.to_string()))
                .with_field("uploadId", mws_core::ErrorValue::String(id.clone()))
            };
            let len = input.layer_part_blob.len() as i64;
            if input.part_first_byte != have || input.part_last_byte - input.part_first_byte + 1 != len || len == 0 {
                return Err(invalid());
            }
            if input.layer_part_blob.len() > MAX_PART_SIZE {
                return Err(errors::limit_exceeded(format!(
                    "The layer part is larger than the maximum of {MAX_PART_SIZE} bytes."
                )));
            }
            let last = repo
                .content
                .append_upload(id, Some(input.part_first_byte as u64), &input.layer_part_blob)
                .map_err(|_| invalid())?;
            Ok(types::UploadLayerPartResponse {
                registry_id: Some(account.clone()),
                repository_name: Some(name.to_string()),
                upload_id: Some(id.clone()),
                last_byte_received: Some(last as i64 - 1),
            })
        })
    }

    pub(crate) fn complete_layer_upload(
        &self,
        ctx: &RequestContext,
        input: types::CompleteLayerUploadRequest,
    ) -> Result<types::CompleteLayerUploadResponse, ServiceError> {
        let now = now_ms(ctx);
        self.with_repo(ctx, input.registry_id.as_deref(), &input.repository_name, "ecr:CompleteLayerUpload", |_, reg, name| {
            let account = reg.account.clone();
            let repo = reg.repositories.get_mut(name).expect("checked");
            let id = &input.upload_id;
            let upload = repo.content.uploads.get(id).ok_or_else(|| Self::upload_not_found(id, name, &account))?;
            if upload.data.is_empty() {
                return Err(errors::empty_upload(format!(
                    "The upload with id '{id}' does not contain any layer parts in the repository with name '{name}' in the registry with id '{account}'"
                )));
            }
            let parts = upload.parts.clone();
            if parts.len() > 1 && parts[..parts.len() - 1].iter().any(|p| *p < MIN_PART_SIZE) {
                return Err(errors::layer_part_too_small(format!(
                    "Layer part size must be at least {MIN_PART_SIZE} bytes, except for the last part."
                )));
            }
            let expected = input.layer_digests.first().cloned().unwrap_or_default();
            if !digest::is_valid(&expected) {
                return Err(errors::invalid_layer(format!("The layer digest '{expected}' is not valid.")));
            }
            if repo.content.blobs.contains_key(&expected) {
                repo.content.uploads.remove(id);
                return Err(errors::layer_already_exists(format!(
                    "The layer with digest '{expected}' already exists in the repository with name '{name}' in the registry with id '{account}'"
                )));
            }
            let done = repo.content.complete_upload(id, &expected, now).map_err(|e| match e {
                mws_oci::UploadError::DigestMismatch { actual } => errors::invalid_layer(format!(
                    "The layer digest calculated for upload id '{id}' ('{actual}') does not match the expected digest '{expected}'"
                )),
                _ => errors::invalid_layer(format!("The layer digest '{expected}' is not valid.")),
            })?;
            Ok(types::CompleteLayerUploadResponse {
                registry_id: Some(account.clone()),
                repository_name: Some(name.to_string()),
                upload_id: Some(id.clone()),
                layer_digest: Some(done.digest),
            })
        })
    }

    pub(crate) fn get_download_url_for_layer(
        &self,
        ctx: &RequestContext,
        input: types::GetDownloadUrlForLayerRequest,
    ) -> Result<types::GetDownloadUrlForLayerResponse, ServiceError> {
        let endpoint = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
        let now = now_ms(ctx);
        let key = self.lock().token_key.clone();
        let region = ctx.region.clone();
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:GetDownloadUrlForLayer",
            |_, reg, name| {
                let repo = &reg.repositories[name];
                let d = &input.layer_digest;
                let referenced = repo.content.images.values().any(|i| i.blobs.contains(d));
                if !repo.content.blobs.contains_key(d) || !referenced {
                    return Err(errors::layers_not_found(format!(
                        "The image layer '{d}' does not exist in the repository with name '{name}' in the registry with id '{}'",
                        reg.account
                    )));
                }
                let token = crate::registry::layer_url_token(&key, &reg.account, &region, name, d, now);
                Ok(types::GetDownloadUrlForLayerResponse {
                    download_url: Some(format!("{endpoint}{}{token}", crate::LAYER_PATH)),
                    layer_digest: Some(d.clone()),
                })
            },
        )
    }

    pub(crate) fn list_image_referrers(
        &self,
        ctx: &RequestContext,
        input: types::ListImageReferrersRequest,
    ) -> Result<types::ListImageReferrersResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:BatchGetImage",
            |_, reg, name| {
                let repo = &reg.repositories[name];
                let subject = &input.subject_id.image_digest;
                let types_filter = input.filter.as_ref().and_then(|f| f.artifact_types.clone()).unwrap_or_default();
                let status_filter =
                    input.filter.as_ref().and_then(|f| f.artifact_status.clone()).unwrap_or_else(|| "ACTIVE".into());
                let referrers: Vec<types::ImageReferrer> = repo
                    .content
                    .referrers(subject, None)
                    .into_iter()
                    .filter(|i| status_filter == "ANY" || repo.status(&i.digest) == status_filter)
                    .filter(|i| {
                        let t = i.artifact_type.as_ref().or(i.config_media_type.as_ref());
                        types_filter.is_empty() || t.is_some_and(|t| types_filter.contains(t))
                    })
                    .map(|i| types::ImageReferrer {
                        digest: i.digest.clone(),
                        media_type: i.media_type.clone(),
                        artifact_type: i.artifact_type.clone().or_else(|| i.config_media_type.clone()),
                        size: i.manifest.len() as i64,
                        annotations: i.parsed().and_then(|p| p.annotations).map(|a| {
                            a.into_iter()
                                .map(|(k, v)| (k, v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                                .collect()
                        }),
                        artifact_status: Some(repo.status(&i.digest)),
                    })
                    .collect();
                let (referrers, next_token) =
                    names::page(&referrers, input.next_token.as_deref(), input.max_results, 50)?;
                Ok(types::ListImageReferrersResponse { referrers: Some(referrers), next_token })
            },
        )
    }

    pub(crate) fn update_image_storage_class(
        &self,
        ctx: &RequestContext,
        input: types::UpdateImageStorageClassRequest,
    ) -> Result<types::UpdateImageStorageClassResponse, ServiceError> {
        let now = now_ms(ctx);
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:UpdateImageStorageClass",
            |_, reg, name| {
                let d = find_image(reg, name, &input.image_id)?;
                let account = reg.account.clone();
                let repo = reg.repositories.get_mut(name).expect("checked");
                let image = &repo.content.images[&d];
                if image.subject.is_some() || image.media_type == mws_oci::manifest::DOCKER_SCHEMA1_SIGNED {
                    return Err(errors::image_storage_class_update_not_supported(
                        "The storage class of this image cannot be changed.",
                    ));
                }
                let status = repo.status(&d);
                let meta = repo.meta.entry(d.clone()).or_default();
                match (input.target_storage_class.as_str(), status.as_str()) {
                    ("ARCHIVE", "ACTIVE") => {
                        meta.status = "ARCHIVED".into();
                        meta.last_archived_at = Some(now);
                    }
                    ("STANDARD", "ARCHIVED") => {
                        meta.status = "ACTIVATING".into();
                        meta.activates_at = Some(now + crate::lifecycle::RESTORE_MS);
                    }
                    (target, current) => {
                        return Err(errors::image_storage_class_update_not_supported(format!(
                            "Cannot transition image with status '{current}' to storage class '{target}'."
                        )))
                    }
                }
                Ok(types::UpdateImageStorageClassResponse {
                    registry_id: Some(account),
                    repository_name: Some(name.to_string()),
                    image_id: Some(types::ImageIdentifier {
                        image_digest: Some(d.clone()),
                        image_tag: input.image_id.image_tag.clone(),
                    }),
                    image_status: Some(meta.status.clone()),
                })
            },
        )
    }

    pub(crate) fn start_image_scan(
        &self,
        ctx: &RequestContext,
        input: types::StartImageScanRequest,
    ) -> Result<types::StartImageScanResponse, ServiceError> {
        let now = now_ms(ctx);
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:StartImageScan",
            |_, reg, name| {
                let d = find_image(reg, name, &input.image_id)?;
                let account = reg.account.clone();
                let repo = reg.repositories.get_mut(name).expect("checked");
                let image = &repo.content.images[&d];
                if !image.children.is_empty() || image.artifact_type.is_some() {
                    return Err(errors::unsupported_image_type("The operation is not supported for this image type."));
                }
                if repo.status(&d) != "ACTIVE" {
                    return Err(errors::image_archived("The image is archived and cannot be scanned."));
                }
                let meta = repo.meta.entry(d.clone()).or_default();
                if meta.scan.as_ref().is_some_and(|s| now - s.started_at < SCAN_INTERVAL_MS) {
                    return Err(errors::limit_exceeded(
                        "The scan quota per image has been exceeded. Wait and try again.",
                    ));
                }
                meta.scan = Some(Scan { status: "IN_PROGRESS".into(), started_at: now, completed_at: None });
                Ok(types::StartImageScanResponse {
                    registry_id: Some(account),
                    repository_name: Some(name.to_string()),
                    image_id: Some(types::ImageIdentifier {
                        image_digest: Some(d),
                        image_tag: input.image_id.image_tag.clone(),
                    }),
                    image_scan_status: Some(scan_status("IN_PROGRESS")),
                })
            },
        )
    }

    pub(crate) fn describe_image_scan_findings(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImageScanFindingsRequest,
    ) -> Result<types::DescribeImageScanFindingsResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:DescribeImageScanFindings",
            |_, reg, name| {
                let d = find_image(reg, name, &input.image_id)?;
                let repo = &reg.repositories[name];
                let scan = repo.meta(&d).scan.ok_or_else(|| {
                    errors::scan_not_found(format!(
                        "Image scan does not exist for the image with '{}' in the repository with name '{name}' in the registry with id '{}'",
                        names::image_id_text(&input.image_id),
                        reg.account
                    ))
                })?;
                let findings = (scan.status == "COMPLETE").then(|| types::ImageScanFindings {
                    image_scan_completed_at: scan.completed_at.map(dt),
                    vulnerability_source_updated_at: scan.completed_at.map(dt),
                    finding_severity_counts: Some(Default::default()),
                    findings: Some(Vec::new()),
                    enhanced_findings: None,
                });
                Ok(types::DescribeImageScanFindingsResponse {
                    registry_id: Some(reg.account.clone()),
                    repository_name: Some(name.to_string()),
                    image_id: Some(types::ImageIdentifier { image_digest: Some(d), image_tag: input.image_id.image_tag.clone() }),
                    image_scan_status: Some(scan_status(&scan.status)),
                    image_scan_findings: findings,
                    next_token: None,
                })
            },
        )
    }

    pub(crate) fn describe_image_signing_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImageSigningStatusRequest,
    ) -> Result<types::DescribeImageSigningStatusResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:DescribeImageSigningStatus",
            |_, reg, name| {
                let d = find_image(reg, name, &input.image_id)?;
                let repo = &reg.repositories[name];
                Ok(types::DescribeImageSigningStatusResponse {
                    repository_name: Some(name.to_string()),
                    image_id: Some(types::ImageIdentifier {
                        image_digest: Some(d.clone()),
                        image_tag: input.image_id.image_tag.clone(),
                    }),
                    registry_id: Some(reg.account.clone()),
                    signing_statuses: Some(repo.meta(&d).signing),
                })
            },
        )
    }

    pub(crate) fn describe_image_replication_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImageReplicationStatusRequest,
    ) -> Result<types::DescribeImageReplicationStatusResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:DescribeImageReplicationStatus",
            |_, reg, name| {
                let d = find_image(reg, name, &input.image_id)?;
                let repo = &reg.repositories[name];
                Ok(types::DescribeImageReplicationStatusResponse {
                    repository_name: Some(name.to_string()),
                    image_id: Some(types::ImageIdentifier {
                        image_digest: Some(d.clone()),
                        image_tag: input.image_id.image_tag.clone(),
                    }),
                    replication_statuses: Some(repo.meta(&d).replication),
                })
            },
        )
    }

    pub(crate) fn get_authorization_token(
        &self,
        ctx: &RequestContext,
        input: types::GetAuthorizationTokenRequest,
    ) -> Result<types::GetAuthorizationTokenResponse, ServiceError> {
        names::authorize_registry(ctx, "ecr:GetAuthorizationToken", "*")?;
        let access_key_id = ctx.caller.access_key_id.clone();
        if access_key_id.is_empty() {
            return Err(invalid_parameter("The request must be signed with an access key."));
        }
        let key = self.lock().token_key.clone();
        let registries =
            input.registry_ids.filter(|r| !r.is_empty()).unwrap_or_else(|| vec![ctx.caller.account_id.clone()]);
        let expires = ctx.received_at + chrono::Duration::hours(TOKEN_HOURS);
        let wall_expires = chrono::Utc::now() + chrono::Duration::hours(TOKEN_HOURS);
        let session_token = crate::SESSION_TOKEN.try_with(|t| t.clone()).ok().flatten();
        let data = registries
            .iter()
            .map(|account| {
                let claims = mws_oci::token::Claims {
                    audience: crate::AUDIENCE.into(),
                    access_key_id: access_key_id.clone(),
                    session_token: session_token.clone(),
                    region: ctx.region.clone(),
                    expires: wall_expires.timestamp(),
                    nonce: mws_oci::token::nonce(),
                };
                let password = mws_oci::token::issue(&claims, &key);
                let host = self.registry_host(account, &ctx.region);
                let scheme = if self.inner.registry_host.get().is_some() { "http" } else { "https" };
                types::AuthorizationData {
                    authorization_token: Some(mws_oci::token::basic_credentials("AWS", &password)),
                    expires_at: Some(expires),
                    proxy_endpoint: Some(format!("{scheme}://{host}")),
                }
            })
            .collect();
        Ok(types::GetAuthorizationTokenResponse { authorization_data: Some(data) })
    }
}

/// Whether the caller's pulls leave `lastRecordedPullTime` alone.
pub(crate) fn pull_time_excluded(reg: &Registry, ctx: &RequestContext) -> bool {
    let caller = &ctx.caller.arn;
    let role = match &ctx.caller.kind {
        mws_core::CallerKind::AssumedRole { role_name, .. } => {
            Some(format!("arn:{}:iam::{}:role/{role_name}", ctx.partition, ctx.caller.account_id))
        }
        _ => None,
    };
    reg.pull_time_exclusions.keys().any(|p| p == caller || Some(p) == role.as_ref())
}

pub(crate) fn scan_status(status: &str) -> types::ImageScanStatus {
    let description = match status {
        "COMPLETE" => "The scan was completed successfully.",
        "IN_PROGRESS" => "The scan is in progress.",
        "UNSUPPORTED_IMAGE" => "The operation is not supported for this image type.",
        _ => "",
    };
    types::ImageScanStatus {
        status: Some(status.to_string()),
        description: (!description.is_empty()).then(|| description.to_string()),
    }
}

/// The media type manifests in the repository give a blob.
fn layer_media_type(repo: &Repo, d: &str) -> Option<String> {
    repo.content.images.values().filter(|i| i.blobs.iter().any(|b| b == d)).find_map(|i| {
        let m = i.parsed()?;
        m.config
            .iter()
            .chain(m.layers.iter())
            .find(|x| x.digest == d)
            .map(|x| x.media_type.clone())
            .filter(|t| !t.is_empty())
    })
}
