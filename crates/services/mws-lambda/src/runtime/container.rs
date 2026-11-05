//! Container image functions run as Docker containers (or any engine that
//! speaks Docker's command line, such as Podman: `MWS_LAMBDA_DOCKER`).
//!
//! The image comes from ECR's own storage: MWS writes it as an image
//! archive (OCI layout plus Docker's `manifest.json`, as `docker save`
//! writes) and `docker load`s it once, tagged `mws-lambda:<digest>`, so no
//! registry login or pull is involved. Containers share the host's network,
//! so the Runtime API on a loopback port and `AWS_ENDPOINT_URL` reach MWS
//! as they do for local processes. As in Lambda, the root file system is
//! read-only and `/tmp` is writable, sized by the function's ephemeral
//! storage.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;

use super::{LaunchError, Runtimes};
use crate::image::ContainerImage;

/// How a container environment starts.
#[derive(Debug, Clone)]
pub struct ContainerLaunch {
    /// The local tag the image was loaded as.
    pub image: String,
    /// The effective entry point and command (`ImageConfig` over the
    /// image's own).
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    pub working_dir: Option<String>,
    /// `/tmp`'s size.
    pub ephemeral_mb: i32,
}

/// The container engine's command line program.
pub(crate) fn docker() -> OsString {
    std::env::var_os("MWS_LAMBDA_DOCKER").filter(|p| !p.is_empty()).unwrap_or_else(|| "docker".into())
}

/// The local tag an image is loaded as.
pub fn image_tag(digest: &str) -> String {
    format!("mws-lambda:{}", digest.trim_start_matches("sha256:"))
}

/// Variables the engine's own command line needs; these go to the
/// container as `-e K=V` rather than through the engine's environment.
fn engine_variable(key: &str) -> bool {
    matches!(key, "PATH" | "HOME" | "TMPDIR" | "XDG_RUNTIME_DIR") || key.starts_with("DOCKER_")
}

impl Runtimes {
    /// Whether `tag` was loaded by this process.
    pub fn image_loaded(&self, tag: &str) -> bool {
        self.images.lock().expect("lock").contains(tag)
    }

    /// Make sure the engine has `image` as `tag`.
    pub async fn load_image(&self, tag: &str, image: Option<&ContainerImage>) -> Result<(), LaunchError> {
        let _guard = self.loading.lock().await;
        if self.image_loaded(tag) {
            return Ok(());
        }
        let present = tokio::process::Command::new(docker())
            .args(["image", "inspect", "--format", "{{.Id}}", tag])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| {
                LaunchError::Unsupported(format!(
                    "MWS runs container image functions with Docker, which is not available: {e}"
                ))
            })?
            .success();
        if !present {
            let Some(image) = image else {
                return Err(LaunchError::Io("the function's image is no longer in its repository".into()));
            };
            let archive = archive(tag, image);
            let mut child = tokio::process::Command::new(docker())
                .args(["load", "-q"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| LaunchError::Io(format!("docker load: {e}")))?;
            let mut stdin = child.stdin.take().expect("piped");
            let writer = tokio::spawn(async move {
                let _ = stdin.write_all(&archive).await;
                let _ = stdin.shutdown().await;
            });
            let out = child.wait_with_output().await.map_err(|e| LaunchError::Io(format!("docker load: {e}")))?;
            let _ = writer.await;
            if !out.status.success() {
                return Err(LaunchError::Io(format!("docker load: {}", String::from_utf8_lossy(&out.stderr).trim())));
            }
        }
        self.images.lock().expect("lock").insert(tag.to_string());
        Ok(())
    }
}

/// The program and arguments that start a container, and the environment
/// the engine's command line runs with (variables passed by name).
pub(super) struct Command {
    pub program: OsString,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

pub(super) fn command(
    c: &ContainerLaunch,
    name: &str,
    function_arn: &str,
    memory_mb: i32,
    env: &BTreeMap<String, String>,
) -> Result<Command, LaunchError> {
    let argv: Vec<&String> = c.entrypoint.iter().chain(&c.command).collect();
    let Some((program, rest)) = argv.split_first() else {
        return Err(LaunchError::InvalidEntrypoint("No command specified".into()));
    };
    let mut args: Vec<String> = [
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        name,
        "--label",
        &format!("mws.lambda.function={function_arn}"),
        "--network",
        "host",
        "--read-only",
        "--tmpfs",
        &format!("/tmp:rw,exec,size={}m", c.ephemeral_mb.max(512)),
        "--memory",
        &format!("{}m", memory_mb.max(128)),
        "--entrypoint",
        program,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(w) = c.working_dir.as_ref().filter(|w| !w.is_empty()) {
        args.push("--workdir".into());
        args.push(w.clone());
    }
    let mut by_name = BTreeMap::new();
    for (k, v) in env {
        args.push("-e".into());
        if engine_variable(k) {
            args.push(format!("{k}={v}"));
        } else {
            args.push(k.clone());
            by_name.insert(k.clone(), v.clone());
        }
    }
    args.push(c.image.clone());
    args.extend(rest.iter().map(|s| s.to_string()));
    Ok(Command { program: docker(), args, env: by_name })
}

/// Remove a container (its engine command line may already be gone).
pub(super) async fn remove(name: &str) {
    let _ = tokio::process::Command::new(docker())
        .args(["rm", "-f", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// An image archive `docker load` takes: an OCI image layout with Docker's
/// `manifest.json` beside it.
fn archive(tag: &str, image: &ContainerImage) -> Vec<u8> {
    let hex = |d: &str| d.trim_start_matches("sha256:").to_string();
    let path = |d: &str| format!("blobs/sha256/{}", hex(d));
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": image.manifest_media_type,
            "digest": image.digest,
            "size": image.manifest.len(),
            "annotations": {
                "io.containerd.image.name": format!("docker.io/library/{tag}"),
                "org.opencontainers.image.ref.name": tag.rsplit_once(':').map_or(tag, |(_, t)| t),
            },
        }],
    });
    let docker_manifest = serde_json::json!([{
        "Config": path(&image.config.digest),
        "RepoTags": [tag],
        "Layers": image.layers.iter().map(|l| path(&l.digest)).collect::<Vec<_>>(),
    }]);
    let mut tar = Tar::default();
    tar.dir("blobs/");
    tar.dir("blobs/sha256/");
    tar.file(&path(&image.digest), &image.manifest);
    tar.file(&path(&image.config.digest), &image.config.data);
    let mut seen = std::collections::BTreeSet::new();
    for l in &image.layers {
        if seen.insert(l.digest.clone()) {
            tar.file(&path(&l.digest), &l.data);
        }
    }
    tar.file("index.json", index.to_string().as_bytes());
    tar.file("manifest.json", docker_manifest.to_string().as_bytes());
    tar.file("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    tar.finish()
}

/// A minimal ustar writer.
#[derive(Default)]
struct Tar(Vec<u8>);

impl Tar {
    fn header(&mut self, name: &str, size: usize, kind: u8, mode: &str) {
        let mut h = [0u8; 512];
        let put = |h: &mut [u8; 512], at: usize, v: &[u8]| h[at..at + v.len()].copy_from_slice(v);
        put(&mut h, 0, name.as_bytes());
        put(&mut h, 100, format!("{mode}\0").as_bytes());
        put(&mut h, 108, b"0000000\0");
        put(&mut h, 116, b"0000000\0");
        put(&mut h, 124, format!("{size:011o}\0").as_bytes());
        put(&mut h, 136, b"00000000000\0");
        put(&mut h, 148, b"        ");
        h[156] = kind;
        put(&mut h, 257, b"ustar\0");
        put(&mut h, 263, b"00");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        put(&mut h, 148, format!("{sum:06o}\0 ").as_bytes());
        self.0.extend_from_slice(&h);
    }

    fn dir(&mut self, name: &str) {
        self.header(name, 0, b'5', "0000755");
    }

    fn file(&mut self, name: &str, data: &[u8]) {
        self.header(name, data.len(), b'0', "0000644");
        self.0.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        self.0.extend(std::iter::repeat_n(0u8, pad));
    }

    fn finish(mut self) -> Vec<u8> {
        self.0.extend(std::iter::repeat_n(0u8, 1024));
        self.0
    }
}
