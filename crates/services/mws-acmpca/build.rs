fn main() {
    mws_codegen::build_aws_json(
        "model/acm-pca.json",
        "acmpca_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException", ..Default::default() },
    );
}
