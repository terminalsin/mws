fn main() {
    mws_codegen::build_rest_json(
        "model/cloudtrail-data.json",
        "cloudtrail_data_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "ValidationException",
            error_message_key: "message",
            error_fault_key: None,
        },
    );
}
