fn main() {
    mws_codegen::build_aws_query("model/cloudformation.json", "cloudformation_generated.rs");
}
