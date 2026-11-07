fn main() {
    mws_codegen::build_aws_json(
        "model/ecr-public.json",
        "ecr_public_generated.rs",
        mws_codegen::JsonOptions { validation_error: "InvalidParameterException", ..Default::default() },
    );
}
