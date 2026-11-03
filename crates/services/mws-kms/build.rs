fn main() {
    mws_codegen::build_aws_json(
        "model/kms.json",
        "kms_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException" },
    );
}
