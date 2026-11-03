fn main() {
    mws_codegen::build_aws_json(
        "model/organizations.json",
        "organizations_generated.rs",
        mws_codegen::JsonOptions { validation_error: "InvalidInputException" },
    );
}
