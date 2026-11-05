fn main() {
    mws_codegen::build_aws_query("model/ses.json", "ses_generated.rs");
    mws_codegen::build_rest_json(
        "model/sesv2.json",
        "sesv2_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "BadRequestException",
            error_message_key: "message",
            error_fault_key: None,
        },
    );
}
