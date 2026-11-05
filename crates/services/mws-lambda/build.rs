fn main() {
    mws_codegen::build_rest_json(
        "model/lambda.json",
        "lambda_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "ValidationException",
            error_message_key: "Message",
            error_fault_key: Some("Type"),
            error_code_key: None,
        },
    );
}
