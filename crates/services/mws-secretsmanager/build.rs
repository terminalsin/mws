fn main() {
    mws_codegen::build_aws_json(
        "model/secretsmanager.json",
        "secretsmanager_generated.rs",
        mws_codegen::JsonOptions { validation_error: "InvalidParameterException" },
    );
}
