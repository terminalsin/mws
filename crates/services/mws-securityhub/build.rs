fn main() {
    mws_codegen::build_rest_json(
        "model/securityhub.json",
        "securityhub_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "InvalidInputException",
            error_message_key: "Message",
            error_fault_key: None,
            error_code_key: None,
        },
    );
}
