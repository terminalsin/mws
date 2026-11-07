fn main() {
    mws_codegen::build_aws_json(
        "model/marketplace-entitlement-service.json",
        "entitlement_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException", ..Default::default() },
    );
}
