fn main() {
    mws_codegen::build_aws_query("model/autoscaling.json", "autoscaling_generated.rs");
}
