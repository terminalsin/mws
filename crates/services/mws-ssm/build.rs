fn main() {
    mws_codegen::build_aws_json(
        "model/ssm.json",
        "ssm_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException" },
    );
}
