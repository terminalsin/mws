//! Server code generation from Smithy models.
//!
//! A service crate calls [`build_aws_query`] from its `build.rs`; the result
//! is `include!`d into the crate. Generated code contains:
//!
//! * `types`: one Rust type per structure and union in the service's closure,
//! * `errors`: a constructor per modeled error, with its wire code and status,
//! * `Handler`: an async trait with one method per operation, each defaulting
//!   to a `NotImplemented` error,
//! * `dispatch`: decodes and validates a request, calls the handler and
//!   encodes the response or error.
//!
//! Only protocol modules live here; nothing is specific to one service.

mod common;
mod ec2_query;
mod http_routes;
mod json;
mod json_codec;
mod naming;
mod query;
mod regex_compat;
mod rest_json;
mod rest_xml;
mod rust_types;
mod xml_ser;

use std::path::{Path, PathBuf};

pub use ec2_query::Ec2QueryOptions;
pub use json::JsonOptions;
pub use mws_smithy::Model;
pub use rest_json::RestJsonOptions;
pub use rest_xml::RestXmlOptions;

/// Generate awsQuery server code for the model at `model_path`.
pub fn generate_aws_query(model: &Model) -> String {
    query::generate(model, None, "ValidationError")
}

/// Build-script helper: read `model_path` (relative to the crate), write the
/// generated code to `$OUT_DIR/{out_name}`, and register rebuild triggers.
pub fn build_aws_query(model_path: impl AsRef<Path>, out_name: &str) {
    let model_path = model_path.as_ref();
    println!("cargo:rerun-if-changed={}", model_path.display());
    let model =
        Model::load(model_path).unwrap_or_else(|e| panic!("loading Smithy model {}: {e}", model_path.display()));
    let code = generate_aws_query(&model);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo")).join(out_name);
    std::fs::write(&out, code).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}

/// Build-script helper generating awsQuery server code for an
/// `awsQueryCompatible` awsJson model (SQS), whose real service still
/// answers awsQuery requests from older SDKs. The model no longer names its
/// XML namespace, so the caller does.
/// Request validation errors carry `validation_error`, as in the service's
/// awsJson answers.
pub fn build_aws_query_compatible(
    model_path: impl AsRef<Path>,
    out_name: &str,
    xml_namespace: &str,
    validation_error: &str,
) {
    let model_path = model_path.as_ref();
    println!("cargo:rerun-if-changed={}", model_path.display());
    let model =
        Model::load(model_path).unwrap_or_else(|e| panic!("loading Smithy model {}: {e}", model_path.display()));
    let code = query::generate(&model, Some(xml_namespace), validation_error);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo")).join(out_name);
    std::fs::write(&out, code).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}

/// Generate ec2Query server code for `model`.
pub fn generate_ec2_query(model: &Model, options: &Ec2QueryOptions) -> String {
    ec2_query::generate(model, options)
}

/// Build-script helper for ec2Query services (EC2); see [`build_aws_query`].
pub fn build_ec2_query(model_path: impl AsRef<Path>, out_name: &str, options: Ec2QueryOptions) {
    let model_path = model_path.as_ref();
    println!("cargo:rerun-if-changed={}", model_path.display());
    let model =
        Model::load(model_path).unwrap_or_else(|e| panic!("loading Smithy model {}: {e}", model_path.display()));
    let code = generate_ec2_query(&model, &options);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo")).join(out_name);
    std::fs::write(&out, code).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}

/// Generate restXml server code for `model`.
pub fn generate_rest_xml(model: &Model, options: &RestXmlOptions) -> String {
    rest_xml::generate(model, options)
}

/// Build-script helper for restXml services; see [`build_aws_query`].
pub fn build_rest_xml(model_path: impl AsRef<Path>, out_name: &str, options: RestXmlOptions) {
    let model_path = model_path.as_ref();
    println!("cargo:rerun-if-changed={}", model_path.display());
    let model =
        Model::load(model_path).unwrap_or_else(|e| panic!("loading Smithy model {}: {e}", model_path.display()));
    let code = generate_rest_xml(&model, &options);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo")).join(out_name);
    std::fs::write(&out, code).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}

/// Generate awsJson1.0/1.1 server code for `model`.
pub fn generate_aws_json(model: &Model, options: &JsonOptions) -> String {
    json::generate(model, options)
}

/// Build-script helper for awsJson services; see [`build_aws_query`].
pub fn build_aws_json(model_path: impl AsRef<Path>, out_name: &str, options: JsonOptions) {
    let model_path = model_path.as_ref();
    println!("cargo:rerun-if-changed={}", model_path.display());
    let model =
        Model::load(model_path).unwrap_or_else(|e| panic!("loading Smithy model {}: {e}", model_path.display()));
    let code = generate_aws_json(&model, &options);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo")).join(out_name);
    std::fs::write(&out, code).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}

/// Generate restJson1 server code for `model`.
pub fn generate_rest_json(model: &Model, options: &RestJsonOptions) -> String {
    rest_json::generate(model, options)
}

/// Build-script helper for restJson1 services; see [`build_aws_query`].
pub fn build_rest_json(model_path: impl AsRef<Path>, out_name: &str, options: RestJsonOptions) {
    let model_path = model_path.as_ref();
    println!("cargo:rerun-if-changed={}", model_path.display());
    let model =
        Model::load(model_path).unwrap_or_else(|e| panic!("loading Smithy model {}: {e}", model_path.display()));
    let code = generate_rest_json(&model, &options);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo")).join(out_name);
    std::fs::write(&out, code).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}
