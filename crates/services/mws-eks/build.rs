fn main() {
    mws_codegen::build_rest_json(
        "model/eks.json",
        "eks_generated.rs",
        mws_codegen::RestJsonOptions {
            validation_error: "InvalidParameterException",
            error_message_key: "message",
            error_fault_key: None,
        },
    );
}
