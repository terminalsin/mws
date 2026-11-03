//! Generation steps every protocol shares: error constructors, the handler
//! trait, and constraint checks.

use std::collections::BTreeSet;
use std::fmt::Write;

use mws_smithy::{Bounds, Member, Model, Shape, ShapeType};
use serde_json::Value;

use crate::naming::{ident, rust_str, snake_case, type_name};
use crate::regex_compat;
use crate::rust_types::enum_const_name;

/// Every error the service and its operations declare.
pub fn all_errors(service: &Shape, ops: &[&Shape]) -> BTreeSet<String> {
    let mut errors: BTreeSet<String> = service.errors.iter().cloned().collect();
    for o in ops {
        errors.extend(o.errors.iter().cloned());
    }
    errors
}

/// `pub mod errors`: a constant and constructor per modeled error. Error
/// members that are lists of strings get a `{name}_with_{member}`
/// constructor that carries them.
pub fn emit_errors(model: &Model, errors: &BTreeSet<String>, w: &mut String) {
    let _ = writeln!(w, "\n/// Constructors for every error the model declares.\npub mod errors {{");
    let _ = writeln!(w, "    #[allow(unused_imports)]\n    use ::mws_core::{{ErrorFault, ErrorValue, ServiceError}};");
    for id in errors {
        let s = model.expect(id);
        let (code, status) = error_code_and_status(s);
        let fault = if s.get_trait("error").and_then(Value::as_str) == Some("server") { "Server" } else { "Client" };
        let fn_name = snake_case(s.name().strip_suffix("Exception").unwrap_or(s.name()));
        let _ = writeln!(w, "    /// `{code}` (HTTP {status}), from `{id}`.");
        let _ = writeln!(w, "    pub const {}: &str = {};", fn_name.to_ascii_uppercase(), rust_str(&code));
        let _ = writeln!(
            w,
            "    pub fn {fn_name}(message: impl Into<String>) -> ServiceError {{ ServiceError::new({}, {status}, ErrorFault::{fault}, message) }}",
            rust_str(&code)
        );
        for m in &s.members {
            let target = model.expect(&m.target);
            if !matches!(target.ty, ShapeType::List | ShapeType::Set) {
                continue;
            }
            let item = target.member.as_ref().unwrap();
            if model.expect(&item.target).ty != ShapeType::String {
                continue;
            }
            let item_name = item.get_trait("xmlName").and_then(Value::as_str).unwrap_or("member");
            let wire = m.get_trait("xmlName").and_then(Value::as_str).unwrap_or(&m.name);
            let _ = writeln!(
                w,
                "    pub fn {fn_name}_with_{}(message: impl Into<String>, values: Vec<String>) -> ServiceError {{ {fn_name}(message).with_field({}, ErrorValue::List {{ item: {}.into(), values }}) }}",
                snake_case(&m.name),
                rust_str(wire),
                rust_str(item_name)
            );
        }
    }
    let _ = writeln!(w, "}}");
}

pub fn io_types(model: &Model, op: &Shape) -> (String, String) {
    let input = op.input.as_ref().map(|i| format!("types::{}", type_name(model.expect(i).name())));
    let output = op.output.as_ref().map(|o| format!("types::{}", type_name(model.expect(o).name())));
    (input.unwrap_or_else(|| "()".into()), output.unwrap_or_else(|| "()".into()))
}

/// The async `Handler` trait: one method per operation, each answering
/// `NotImplemented` until the service overrides it.
pub fn emit_handler(model: &Model, ops: &[&Shape], w: &mut String) {
    let _ = writeln!(w, "\n/// Implement the operations you support; the rest answer `NotImplemented`.");
    let _ = writeln!(w, "#[async_trait::async_trait]\npub trait Handler: Send + Sync {{");
    for op in ops {
        let (input, output) = io_types(model, op);
        let _ = writeln!(
            w,
            "    async fn {}(&self, ctx: &RequestContext, input: {input}) -> Result<{output}, ServiceError> {{\n        let _ = (ctx, input);\n        Err(ServiceError::not_implemented({}))\n    }}",
            ident(&snake_case(op.name())),
            rust_str(op.name())
        );
    }
    let _ = writeln!(w, "}}");
}

/// Constraint-check emission. Patterns are compiled once into `RE_n`
/// statics, emitted by [`Constraints::emit_statics`].
#[derive(Default)]
pub struct Constraints {
    regexes: Vec<String>,
}

impl Constraints {
    /// Validation statements for value var `v` (a `&T`) at path var `p`,
    /// against decoder var `d` (anything that derefs to `mws_core::Validator`).
    pub fn checks(&mut self, member: Option<&Member>, target: &Shape) -> String {
        let pick = |name: &str| member.and_then(|m| m.get_trait(name)).or_else(|| target.get_trait(name)).cloned();
        let mut out = String::new();
        let is_string = matches!(target.ty, ShapeType::String | ShapeType::Enum);
        if let Some(b) = Bounds::from_trait(pick("length").as_ref()) {
            let (len, shown) = match target.ty {
                ShapeType::String | ShapeType::Enum => ("v.chars().count()", "v.as_str()".to_string()),
                ShapeType::List | ShapeType::Set => ("v.len()", "&::mws_core::render_list(v)".to_string()),
                _ => ("v.len()", "\"\"".to_string()),
            };
            let _ = writeln!(out, "d.check_length(&p, {shown}, {len}, {}, {});", opt_u64(b.min), opt_u64(b.max));
        }
        if is_string {
            if let Some(Value::String(pat)) = pick("pattern") {
                if let Some(translated) = regex_compat::translate(&pat) {
                    let idx = match self.regexes.iter().position(|r| *r == translated) {
                        Some(i) => i,
                        None => {
                            self.regexes.push(translated);
                            self.regexes.len() - 1
                        }
                    };
                    let _ = writeln!(out, "d.check_pattern(&p, v, &RE_{idx}, {});", rust_str(&pat));
                } else {
                    let _ =
                        writeln!(out, "// pattern {} is not expressible with the regex crate; skipped", rust_str(&pat));
                }
            }
        }
        if let Some(b) = Bounds::from_trait(pick("range").as_ref()) {
            if !matches!(target.ty, ShapeType::String) {
                let _ = writeln!(out, "d.check_range(&p, *v as f64, {}, {});", opt_f64(b.min), opt_f64(b.max));
            }
        }
        if target.ty == ShapeType::Enum {
            let _ = writeln!(out, "d.check_enum(&p, v, types::{});", enum_const_name(target));
        }
        out
    }

    /// `static RE_n` definitions, using the regex re-export of `runtime`.
    pub fn emit_statics(&self, runtime: &str, w: &mut String) {
        for (i, pat) in self.regexes.iter().enumerate() {
            let _ = writeln!(
                w,
                "    pub(super) static RE_{i}: ::std::sync::LazyLock<{runtime}::__private::regex::Regex> = ::std::sync::LazyLock::new(|| {runtime}::__private::regex::Regex::new({}).unwrap());",
                rust_str(pat)
            );
        }
    }
}

pub fn de_fn_name(s: &Shape) -> String {
    format!("de_{}", snake_case(s.name()))
}

pub fn ser_fn_name(s: &Shape) -> String {
    format!("ser_{}", snake_case(s.name()))
}

/// The Rust type of `target` as seen from a sibling of the `types` module.
pub fn qualified_type(model: &Model, target: &str) -> String {
    let s = model.expect(target);
    match s.ty {
        ShapeType::Structure | ShapeType::Union => format!("types::{}", type_name(s.name())),
        ShapeType::List | ShapeType::Set => {
            format!("::std::vec::Vec<{}>", qualified_type(model, &s.member.as_ref().unwrap().target))
        }
        ShapeType::Map => format!(
            "::std::collections::BTreeMap<::std::string::String, {}>",
            qualified_type(model, &s.value.as_ref().unwrap().target)
        ),
        _ => crate::rust_types::scalar_type(s.ty).to_string(),
    }
}

/// Wire code and HTTP status of an error shape. awsQuery services may
/// override both with `awsQueryError`; otherwise the code is the shape name.
pub fn error_code_and_status(s: &Shape) -> (String, u16) {
    if let Some(q) = s.get_trait("aws.protocols#awsQueryError") {
        let code = q.get("code").and_then(Value::as_str).unwrap_or(s.name()).to_string();
        let status = q.get("httpResponseCode").and_then(Value::as_u64).unwrap_or(400) as u16;
        return (code, status);
    }
    let status = s.get_trait("httpError").and_then(Value::as_u64).map(|v| v as u16).unwrap_or_else(|| {
        if s.get_trait("error").and_then(Value::as_str) == Some("server") {
            500
        } else {
            400
        }
    });
    (s.name().to_string(), status)
}

fn opt_u64(v: Option<f64>) -> String {
    v.map(|v| format!("Some({})", v as u64)).unwrap_or_else(|| "None".into())
}

fn opt_f64(v: Option<f64>) -> String {
    v.map(|v| format!("Some({v:?})")).unwrap_or_else(|| "None".into())
}
