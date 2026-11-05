fn main() {
    mws_codegen::build_rest_json(
        "model/codeartifact.json",
        "codeartifact_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "ValidationException",
            error_code_key: None,
            error_message_key: "message",
            error_fault_key: None,
        },
    );
}
