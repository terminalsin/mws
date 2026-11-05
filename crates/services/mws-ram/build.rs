fn main() {
    mws_codegen::build_rest_json(
        "model/ram.json",
        "ram_generated.rs",
        mws_codegen::RestJsonOptions { validation_error: "InvalidParameterException", ..Default::default() },
    );
}
