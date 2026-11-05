fn main() {
    mws_codegen::build_aws_query_with(
        "model/rds.json",
        "rds_generated.rs",
        mws_codegen::QueryOptions { validation_error: "InvalidParameterValue".into(), operations: None },
    );
}
