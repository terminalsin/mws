fn main() {
    mws_codegen::build_rest_xml(
        "model/route53.json",
        "route53_generated.rs",
        mws_codegen::RestXmlOptions { validation_error: "InvalidInput" },
    );
}
