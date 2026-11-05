fn main() {
    mws_codegen::build_rest_json(
        "model/amplify.json",
        "amplify_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "BadRequestException",
            error_message_key: "message",
            error_fault_key: None,
            error_code_key: None,
        },
    );
}
