fn main() {
    mws_codegen::build_aws_query_with(
        "model/elasticache.json",
        "elasticache_generated.rs",
        mws_codegen::QueryOptions { validation_error: "InvalidParameterValue".into(), operations: None },
    );
}
