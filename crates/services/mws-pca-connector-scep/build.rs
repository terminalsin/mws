fn main() {
    mws_codegen::build_rest_json(
        "model/pca-connector-scep.json",
        "pca_connector_scep_generated.rs",
        mws_codegen::RestJsonOptions::default(),
    );
}
