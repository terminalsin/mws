//! Container recipes: build the image (on the build instance with EC2's
//! Docker backend, or as a small marker image without one) and push it to
//! ECR through ECR's own layer and image APIs.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

use base64::Engine;
use mws_core::{RequestContext, Service};
use serde_json::{json, Value};
use sha2::Digest;

use crate::generated::types as t;
use crate::toe::{sh_quote, Document};

/// The Dockerfile template AWS uses when a recipe gives none.
const DEFAULT_TEMPLATE: &str =
    "FROM {{{ imagebuilder:parentImage }}}\n{{{ imagebuilder:environments }}}\n{{{ imagebuilder:components }}}\n";

const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
/// ECR's largest layer part.
const PART_SIZE: usize = 20 * 1024 * 1024;

fn sha256(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)))
}

/// Files of a build context: path and contents.
pub(crate) type BuildContext = Vec<(String, Vec<u8>)>;

/// A built image, ready to push anywhere.
#[derive(Debug, Clone)]
pub(crate) struct OciImage {
    config: Vec<u8>,
    /// Gzipped layers.
    layers: Vec<Vec<u8>>,
}

/// A component to bake into the image.
pub(crate) struct BakeComponent<'a> {
    pub arn: &'a str,
    pub doc: &'a Document,
    pub params: &'a BTreeMap<String, String>,
}

/// The Dockerfile and build context for a container recipe: each
/// component's build and validate phases become a script the Dockerfile
/// runs.
pub(crate) fn render(
    recipe: &t::ContainerRecipe,
    template: Option<&str>,
    components: &[BakeComponent<'_>],
) -> Result<(String, BuildContext), String> {
    let mut files = Vec::new();
    let mut runs = String::new();
    for (i, c) in components.iter().enumerate() {
        let mut script = String::from("#!/bin/sh\nset -e\n");
        for phase in ["build", "validate"] {
            for step in c.doc.plan(phase, c.params).map_err(|e| format!("Component '{}': {e}", c.arn))? {
                let on_fail = if step.on_failure == "Abort" {
                    format!(
                        "{{ echo {} >&2; exit 1; }}",
                        sh_quote(&format!("Component '{}' failed in phase '{phase}', step '{}'", c.arn, step.name))
                    )
                } else {
                    "true".to_string()
                };
                // The Dockerfile runs every step in one `docker build`, so
                // nested documents and step outputs are not available.
                let body = step
                    .script(&BTreeMap::new())
                    .map_err(|e| format!("Component '{}', step '{}': {e} in a container recipe", c.arn, step.name))?;
                script.push_str(&format!(
                    "# {phase}: {} ({})\n( set -e\n{body}\n) || {on_fail}\n",
                    step.name, step.action
                ));
            }
        }
        let name = format!("imagebuilder/component-{i}.sh");
        runs.push_str(&format!("RUN sh /tmp/{name}\n"));
        files.push((name, script.into_bytes()));
    }
    let components_block = if files.is_empty() {
        String::new()
    } else {
        format!("COPY imagebuilder/ /tmp/imagebuilder/\n{runs}RUN rm -rf /tmp/imagebuilder\n")
    };
    let mut env = String::new();
    if let Some(dir) = &recipe.working_directory {
        env.push_str(&format!("WORKDIR {dir}\n"));
    }
    let dockerfile = template
        .or(recipe.dockerfile_template_data.as_deref())
        .unwrap_or(DEFAULT_TEMPLATE)
        .replace("{{{ imagebuilder:parentImage }}}", recipe.parent_image.as_deref().unwrap_or_default())
        .replace("{{{ imagebuilder:environments }}}", &env)
        .replace("{{{ imagebuilder:components }}}", &components_block);
    Ok((dockerfile, files))
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_default()
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data).read_to_end(&mut out).map_err(|e| format!("a layer is not valid gzip: {e}"))?;
    Ok(out)
}

/// The files of a tar archive (regular files only).
fn untar(data: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut pos = 0;
    let mut long_name: Option<String> = None;
    while pos + 512 <= data.len() {
        let h = &data[pos..pos + 512];
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let field = |a: usize, b: usize| String::from_utf8_lossy(&h[a..b]).trim_end_matches('\0').to_string();
        let size = usize::from_str_radix(field(124, 136).trim(), 8).unwrap_or(0);
        let mut name = field(0, 100);
        let prefix = field(345, 500);
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let kind = h[156];
        let body = &data[(pos + 512).min(data.len())..(pos + 512 + size).min(data.len())];
        match kind {
            b'L' => long_name = Some(String::from_utf8_lossy(body).trim_end_matches('\0').to_string()),
            b'0' | 0 => {
                out.insert(long_name.take().unwrap_or(name), body.to_vec());
            }
            _ => long_name = None,
        }
        pos += 512 + size.div_ceil(512) * 512;
    }
    out
}

/// A tar archive of `files` (with their parent directories).
fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    fn header(name: &str, size: usize, kind: u8, mode: &str) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len().min(100)].copy_from_slice(&name.as_bytes()[..name.len().min(100)]);
        let put = |h: &mut [u8; 512], at: usize, s: &str| h[at..at + s.len()].copy_from_slice(s.as_bytes());
        put(&mut h, 100, mode);
        put(&mut h, 108, "0000000\0");
        put(&mut h, 116, "0000000\0");
        put(&mut h, 124, &format!("{size:011o}\0"));
        put(&mut h, 136, "00000000000\0");
        h[156] = kind;
        put(&mut h, 257, "ustar\0");
        put(&mut h, 263, "00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        put(&mut h, 148, &format!("{sum:06o}\0 "));
        h
    }
    let mut out = Vec::new();
    let mut dirs = std::collections::BTreeSet::new();
    for (name, data) in files {
        let parts: Vec<&str> = name.split('/').collect();
        for i in 1..parts.len() {
            let dir = format!("{}/", parts[..i].join("/"));
            if dirs.insert(dir.clone()) {
                out.extend_from_slice(&header(&dir, 0, b'5', "0000755\0"));
            }
        }
        out.extend_from_slice(&header(name, data.len(), b'0', "0000644\0"));
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

impl OciImage {
    /// The image in a `docker save` archive (either layout: both carry
    /// `manifest.json`).
    pub(crate) fn from_docker_save(archive: &[u8]) -> Result<Self, String> {
        let files = untar(archive);
        let manifest: Value = files
            .get("manifest.json")
            .and_then(|m| serde_json::from_slice(m).ok())
            .ok_or("the image archive has no manifest.json")?;
        let entry = manifest.get(0).ok_or("the image archive's manifest is empty")?;
        let config_path = entry["Config"].as_str().ok_or("the image archive names no config")?;
        let config = files.get(config_path).cloned().ok_or("the image archive lacks its config")?;
        let mut layers = Vec::new();
        for l in entry["Layers"].as_array().into_iter().flatten() {
            let path = l.as_str().unwrap_or_default();
            let data = files.get(path).ok_or_else(|| format!("the image archive lacks layer {path}"))?;
            layers.push(if data.starts_with(&[0x1f, 0x8b]) { data.clone() } else { gzip(data) });
        }
        Ok(Self { config: Self::oci_config(&config, &layers)?, layers })
    }

    /// Rewrite the config's `rootfs.diff_ids` to match `layers`, keeping
    /// everything else.
    fn oci_config(config: &[u8], layers: &[Vec<u8>]) -> Result<Vec<u8>, String> {
        let mut v: Value = serde_json::from_slice(config).map_err(|e| format!("the image config is not JSON: {e}"))?;
        let mut diff_ids = Vec::new();
        for l in layers {
            diff_ids.push(Value::String(sha256(&gunzip(l)?)));
        }
        v["rootfs"] = json!({ "type": "layers", "diff_ids": diff_ids });
        Ok(serde_json::to_vec(&v).unwrap_or_default())
    }

    /// A one-layer image recording what was built, for when nothing can
    /// run a real build (EC2's metadata backend).
    pub(crate) fn marker(recipe: &t::ContainerRecipe, image_arn: &str, dockerfile: &str) -> Self {
        let info = json!({
            "imageBuildVersionArn": image_arn,
            "containerRecipeArn": recipe.arn,
            "parentImage": recipe.parent_image,
        });
        let info = serde_json::to_vec_pretty(&info).unwrap_or_default();
        let layer = gzip(&tar(&[
            ("etc/imagebuilder/image.json", info.as_slice()),
            ("etc/imagebuilder/Dockerfile", dockerfile.as_bytes()),
        ]));
        let config = json!({
            "architecture": "amd64",
            "os": if recipe.platform.as_deref() == Some("Windows") { "windows" } else { "linux" },
            "config": {
                "Labels": {
                    "com.amazonaws.imagebuilder.image": image_arn,
                    "com.amazonaws.imagebuilder.parent-image": recipe.parent_image.clone().unwrap_or_default(),
                },
                "Cmd": ["/bin/sh"],
            },
            "rootfs": { "type": "layers", "diff_ids": [] },
            "history": [{ "created_by": "EC2 Image Builder" }],
        });
        let layers = vec![layer];
        let config = Self::oci_config(&serde_json::to_vec(&config).unwrap_or_default(), &layers).unwrap_or_default();
        Self { config, layers }
    }

    fn manifest(&self) -> String {
        json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST_TYPE,
            "config": { "mediaType": CONFIG_TYPE, "digest": sha256(&self.config), "size": self.config.len() },
            "layers": self.layers.iter().map(|l| json!({
                "mediaType": LAYER_TYPE,
                "digest": sha256(l),
                "size": l.len(),
            })).collect::<Vec<_>>(),
        })
        .to_string()
    }

    /// Push to an ECR repository under each of `tags`; returns the
    /// repository URI and the image digest.
    pub(crate) async fn push(
        &self,
        ecr: &Arc<dyn Service>,
        ctx: &RequestContext,
        repository: &str,
        tags: &[String],
    ) -> Result<(String, String), String> {
        let repo = ecr
            .invoke(ctx.clone(), "DescribeRepositories", json!({ "repositoryNames": [repository] }))
            .await
            .map_err(|e| e.message)?;
        let uri = repo["repositories"][0]["repositoryUri"].as_str().unwrap_or_default().to_string();
        let mut blobs: Vec<&[u8]> = vec![&self.config];
        blobs.extend(self.layers.iter().map(Vec::as_slice));
        let digests: Vec<String> = blobs.iter().map(|b| sha256(b)).collect();
        let have = ecr
            .invoke(
                ctx.clone(),
                "BatchCheckLayerAvailability",
                json!({ "repositoryName": repository, "layerDigests": digests }),
            )
            .await
            .map_err(|e| e.message)?;
        let available: Vec<&str> = have["layers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|l| l["layerAvailability"] == "AVAILABLE")
            .filter_map(|l| l["layerDigest"].as_str())
            .collect();
        for (blob, digest) in blobs.iter().zip(&digests) {
            if available.contains(&digest.as_str()) {
                continue;
            }
            let up = ecr
                .invoke(ctx.clone(), "InitiateLayerUpload", json!({ "repositoryName": repository }))
                .await
                .map_err(|e| e.message)?;
            let upload_id = up["uploadId"].as_str().unwrap_or_default().to_string();
            for (i, part) in blob.chunks(PART_SIZE).enumerate() {
                let first = i * PART_SIZE;
                ecr.invoke(
                    ctx.clone(),
                    "UploadLayerPart",
                    json!({
                        "repositoryName": repository,
                        "uploadId": upload_id,
                        "partFirstByte": first,
                        "partLastByte": first + part.len() - 1,
                        "layerPartBlob": base64::engine::general_purpose::STANDARD.encode(part),
                    }),
                )
                .await
                .map_err(|e| e.message)?;
            }
            match ecr
                .invoke(
                    ctx.clone(),
                    "CompleteLayerUpload",
                    json!({ "repositoryName": repository, "uploadId": upload_id, "layerDigests": [digest] }),
                )
                .await
            {
                Ok(_) => {}
                Err(e) if e.code == "LayerAlreadyExistsException" => {}
                Err(e) => return Err(e.message),
            }
        }
        let manifest = self.manifest();
        let digest = sha256(manifest.as_bytes());
        for tag in tags {
            match ecr
                .invoke(
                    ctx.clone(),
                    "PutImage",
                    json!({
                        "repositoryName": repository,
                        "imageManifest": manifest,
                        "imageManifestMediaType": MANIFEST_TYPE,
                        "imageTag": tag,
                    }),
                )
                .await
            {
                Ok(_) => {}
                Err(e) if e.code == "ImageAlreadyExistsException" => {}
                Err(e) => return Err(e.message),
            }
        }
        Ok((uri, digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_round_trip() {
        let archive = tar(&[("etc/a.txt", b"hello"), ("b", b"")]);
        let files = untar(&archive);
        assert_eq!(files.get("etc/a.txt").map(Vec::as_slice), Some(&b"hello"[..]));
        assert_eq!(files.get("b").map(Vec::as_slice), Some(&b""[..]));
    }

    #[test]
    fn marker_image_config_matches_layers() {
        let recipe = t::ContainerRecipe { parent_image: Some("alpine:3.20".into()), ..Default::default() };
        let img = OciImage::marker(&recipe, "arn:x", "FROM alpine");
        let config: Value = serde_json::from_slice(&img.config).unwrap();
        assert_eq!(config["rootfs"]["diff_ids"][0], sha256(&gunzip(&img.layers[0]).unwrap()));
        let manifest: Value = serde_json::from_str(&img.manifest()).unwrap();
        assert_eq!(manifest["layers"][0]["digest"], sha256(&img.layers[0]));
    }

    #[test]
    fn docker_save_archives_load() {
        let layer = tar(&[("hello", b"world")]);
        let config = br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#;
        let manifest = br#"[{"Config":"config.json","RepoTags":["x:1"],"Layers":["l1/layer.tar"]}]"#;
        let archive = tar(&[("manifest.json", manifest), ("config.json", config), ("l1/layer.tar", &layer)]);
        let img = OciImage::from_docker_save(&archive).unwrap();
        assert_eq!(img.layers.len(), 1);
        let config: Value = serde_json::from_slice(&img.config).unwrap();
        assert_eq!(config["rootfs"]["diff_ids"][0], sha256(&layer));
    }
}
