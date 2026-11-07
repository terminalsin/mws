fn main() {
    mws_codegen::build_aws_json(
        "model/servicequotas.json",
        "servicequotas_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException", ..Default::default() },
    );
}
