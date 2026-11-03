fn main() {
    mws_codegen::build_rest_xml(
        "model/s3control.json",
        "s3control_generated.rs",
        mws_codegen::RestXmlOptions {
            validation_error: "InvalidRequest",
            optional_query_literals: &[],
            request_id_header: "x-amz-request-id",
        },
    );
}
