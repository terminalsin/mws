fn main() {
    mws_codegen::build_aws_json(
        "model/identitystore.json",
        "identitystore_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException" },
    );
}
