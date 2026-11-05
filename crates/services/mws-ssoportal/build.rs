fn main() {
    mws_codegen::build_rest_json(
        "model/sso.json",
        "ssoportal_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "InvalidRequestException",
            error_message_key: "message",
            error_fault_key: None,
        },
    );
}
