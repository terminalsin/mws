//! Container image functions: where their images come from (ECR, through
//! [`ImageSource`]) and how Lambda resolves `ImageUri` when code is set.

use bytes::Bytes;
use mws_core::{RequestContext, ServiceError};

use crate::generated::errors;
use crate::Lambda;

/// A blob of an image (its config or a layer).
#[derive(Debug, Clone)]
pub struct ImageBlob {
    pub digest: String,
    pub media_type: String,
    pub data: Bytes,
}

/// One single-platform image, as pulled from its registry.
#[derive(Debug, Clone)]
pub struct ContainerImage {
    /// `<registry>/<repository>@<digest>` (`ResolvedImageUri`).
    pub resolved_uri: String,
    /// The digest in `resolved_uri` (an index's for multi-platform images;
    /// `CodeSha256` is its hex).
    pub resolved_digest: String,
    /// The digest of the platform manifest below (`sha256:...`).
    pub digest: String,
    pub manifest: Bytes,
    pub manifest_media_type: String,
    pub config: ImageBlob,
    /// Base layer first.
    pub layers: Vec<ImageBlob>,
}

impl ContainerImage {
    /// What the image's config says about starting it.
    pub(crate) fn run_config(&self) -> crate::state::ImageRunConfig {
        let config = serde_json::from_slice::<serde_json::Value>(&self.config.data)
            .ok()
            .and_then(|v| v.get("config").cloned())
            .unwrap_or_default();
        let list =
            |k: &str| config[k].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect());
        crate::state::ImageRunConfig {
            entrypoint: list("Entrypoint").unwrap_or_default(),
            command: list("Cmd").unwrap_or_default(),
            working_dir: config["WorkingDir"].as_str().filter(|w| !w.is_empty()).map(str::to_string),
        }
    }
}

/// Why an image could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    /// The URI does not name an ECR repository.
    Invalid,
    NotFound,
    AccessDenied,
    /// Not a runnable image for the function's architecture.
    Unsupported,
}

/// Where container images come from (ECR, wired in by the server).
pub trait ImageSource: Send + Sync {
    /// Resolve `uri` as the caller setting a function's code: the caller
    /// must be allowed to pull the image (`ecr:BatchGetImage` and
    /// `ecr:GetDownloadUrlForLayer`). `architecture` is the OCI name of the
    /// function's architecture (`amd64`, `arm64`), which picks the manifest
    /// of an index.
    fn resolve(&self, ctx: &RequestContext, uri: &str, architecture: &str) -> Result<ContainerImage, ImageError>;

    /// Fetch an image already resolved (by digest) to start an execution
    /// environment. Registries without an account or Region in their host
    /// name are the function's (`account`, `region`).
    fn fetch(&self, account: &str, region: &str, resolved_uri: &str, architecture: &str) -> Option<ContainerImage>;
}

/// The OCI architecture of a Lambda one.
pub(crate) fn oci_architecture(architectures: Option<&[String]>) -> &'static str {
    match architectures.and_then(|a| a.first()).map(String::as_str) {
        Some("arm64") => "arm64",
        _ => "amd64",
    }
}

impl Lambda {
    /// Container images come from here (ECR).
    pub fn set_image_source(&self, source: std::sync::Arc<dyn ImageSource>) {
        let _ = self.inner.images.set(source);
    }

    /// Resolve the image a function's code names, with Lambda's errors.
    /// Without an image source (Lambda alone), the URI is kept as given.
    pub(crate) fn resolve_image(
        &self,
        ctx: &RequestContext,
        uri: &str,
        architectures: Option<&[String]>,
    ) -> Result<Option<ContainerImage>, ServiceError> {
        let Some(source) = self.inner.images.get() else { return Ok(None) };
        match source.resolve(ctx, uri, oci_architecture(architectures)) {
            Ok(image) => Ok(Some(image)),
            Err(ImageError::Invalid) => Err(errors::invalid_parameter_value(format!(
                "Source image {uri} is not valid. Provide a valid source image."
            ))),
            Err(ImageError::NotFound) => Err(errors::invalid_parameter_value(format!(
                "Source image {uri} does not exist. Provide a valid source image."
            ))),
            Err(ImageError::AccessDenied) => Err(ServiceError::client(
                "AccessDeniedException",
                403,
                "Lambda does not have permission to access the ECR image. Check the ECR permissions.",
            )),
            Err(ImageError::Unsupported) => Err(errors::invalid_parameter_value(format!(
                "The image manifest, config or layer media type for the source image {uri} is not supported."
            ))),
        }
    }

    pub(crate) fn fetch_image(
        &self,
        account: &str,
        region: &str,
        resolved_uri: &str,
        architectures: Option<&[String]>,
    ) -> Option<ContainerImage> {
        self.inner.images.get()?.fetch(account, region, resolved_uri, oci_architecture(architectures))
    }
}
