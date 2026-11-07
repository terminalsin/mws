fn main() {
    mws_codegen::build_aws_json(
        "model/ecs.json",
        "ecs_generated.rs",
        mws_codegen::JsonOptions { validation_error: "InvalidParameterException", ..Default::default() },
    );
}
