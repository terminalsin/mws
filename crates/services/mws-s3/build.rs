fn main() {
    mws_codegen::build_rest_xml(
        "model/s3.json",
        "s3_generated.rs",
        mws_codegen::RestXmlOptions {
            validation_error: "InvalidArgument",
            optional_query_literals: &["x-id"],
            request_id_header: "x-amz-request-id",
        },
    );
}
