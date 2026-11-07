fn main() {
    mws_codegen::build_aws_json(
        "model/eventbridge.json",
        "events_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException", ..Default::default() },
    );
}
