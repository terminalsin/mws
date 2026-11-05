fn main() {
    mws_codegen::build_rest_json(
        "model/imagebuilder.json",
        "imagebuilder_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "InvalidRequestException",
            error_message_key: "message",
            error_fault_key: None,
            error_code_key: None,
        },
    );
}
