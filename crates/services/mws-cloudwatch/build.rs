fn main() {
    // rpcv2Cbor (current SDKs) and awsJson1.0 share one generated module.
    mws_codegen::build_aws_json(
        "model/cloudwatch.json",
        "cloudwatch_generated.rs",
        mws_codegen::JsonOptions { validation_error: "ValidationException", ..Default::default() },
    );
    // Older SDKs speak awsQuery.
    mws_codegen::build_aws_query("model/cloudwatch.json", "cloudwatch_query_generated.rs");
}
