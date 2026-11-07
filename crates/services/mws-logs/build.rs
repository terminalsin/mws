fn main() {
    mws_codegen::build_aws_json(
        "model/logs.json",
        "logs_generated.rs",
        mws_codegen::JsonOptions {
            validation_error: "InvalidParameterException",
            declared_validation_errors: &["ValidationException"],
        },
    );
}
