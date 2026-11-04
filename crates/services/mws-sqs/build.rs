fn main() {
    mws_codegen::build_aws_json(
        "model/sqs.json",
        "sqs_generated.rs",
        mws_codegen::JsonOptions { validation_error: "InvalidParameterValue" },
    );
    // Older SDKs still speak awsQuery to SQS.
    mws_codegen::build_aws_query_compatible(
        "model/sqs.json",
        "sqs_query_generated.rs",
        "http://queue.amazonaws.com/doc/2012-11-05/",
        "InvalidParameterValue",
    );
}
