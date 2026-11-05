fn main() {
    mws_codegen::build_aws_json(
        "model/marketplace-metering.json",
        "metering_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException" },
    );
}
