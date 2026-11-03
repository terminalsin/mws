fn main() {
    mws_codegen::build_aws_json(
        "model/acm.json",
        "acm_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException" },
    );
}
