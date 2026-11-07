fn main() {
    mws_codegen::build_aws_json(
        "model/cloudtrail.json",
        "cloudtrail_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException", ..Default::default() },
    );
}
