fn main() {
    mws_codegen::build_rest_json(
        "model/efs.json",
        "efs_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "BadRequest",
            error_message_key: "Message",
            error_fault_key: None,
            error_code_key: Some("ErrorCode"),
        },
    );
}
