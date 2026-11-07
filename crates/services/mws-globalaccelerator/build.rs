fn main() {
    mws_codegen::build_aws_json(
        "model/global-accelerator.json",
        "globalaccelerator_generated.rs",
        mws_codegen::JsonOptions { validation_error: "InvalidArgumentException", ..Default::default() },
    );
}
