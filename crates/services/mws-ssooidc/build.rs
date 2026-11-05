fn main() {
    mws_codegen::build_rest_json(
        "model/sso-oidc.json",
        "ssooidc_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "InvalidRequestException",
            error_code_key: None,
            error_message_key: "error_description",
            error_fault_key: None,
        },
    );
}
