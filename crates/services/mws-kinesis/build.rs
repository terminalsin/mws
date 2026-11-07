fn main() {
    mws_codegen::build_aws_json(
        "model/kinesis.json",
        "kinesis_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException", ..Default::default() },
    );
}
