fn main() {
    mws_codegen::build_aws_query("model/elbv2.json", "elbv2_generated.rs");
    mws_codegen::build_aws_query("model/elb.json", "elb_generated.rs");
}
