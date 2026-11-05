//! The OCI distribution protocol (the Docker registry HTTP API v2), for
//! services that host container registries.
//!
//! - [`digest`]: content digests (`sha256:<hex>`).
//! - [`manifest`]: image manifests and indexes (Docker schema 1 and 2, OCI),
//!   the blobs and manifests they reference, subjects and artifact types.
//! - [`store`]: one repository's content: blobs, chunked uploads, images
//!   and tags, with the rules every registry applies on push.
//! - [`token`]: registry passwords bound to an access key, so a registry
//!   can authenticate `docker login` with the key's secret.
//! - [`server`]: the `/v2/` HTTP API on top of a [`server::Backend`] that
//!   decides who may do what and where repositories live.

pub mod digest;
pub mod manifest;
pub mod server;
pub mod store;
pub mod token;

pub use manifest::{Descriptor, Manifest};
pub use server::{Backend, Op, RegistryError};
pub use store::{Image, PutError, PutManifest, PutOutcome, Repository, UploadError};
