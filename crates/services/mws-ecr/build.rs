fn main() {
    mws_codegen::build_aws_json(
        "model/ecr.json",
        "ecr_generated.rs",
        mws_codegen::JsonOptions { validation_error: "InvalidParameterException" },
    );
}
