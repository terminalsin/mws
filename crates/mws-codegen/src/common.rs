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

/// How a protocol names modeled errors on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCodes {
    /// The shape name (awsJson, restJson1).
    Shape,
    /// The `awsQueryError` code and status when present (awsQuery, restXml).
    Query,
    /// awsJson with `awsQueryCompatible`: the shape name in `__type`, the
    /// `awsQueryError` status, and the query code in `x-amzn-query-error`
    /// (see [`query_compatible_codes`]).
    QueryCompatible,
}

/// `(shape name, awsQuery code)` for every error, for the
/// `x-amzn-query-error` header of `awsQueryCompatible` services.
pub fn query_compatible_codes(model: &Model, errors: &BTreeSet<String>) -> Vec<(String, String)> {
    errors
        .iter()
        .map(|id| {
            let s = model.expect(id);
            (s.name().to_string(), error_code_and_status(s, true).0)
        })
        .collect()
}

/// `pub mod errors`: a constant and constructor per modeled error. Error
/// members that are lists of strings get a `{name}_with_{member}`
/// constructor that carries them.
pub fn emit_errors(model: &Model, errors: &BTreeSet<String>, codes: ErrorCodes, w: &mut String) {
    let _ = writeln!(w, "\n/// Constructors for every error the model declares.\npub mod errors {{");
    let _ = writeln!(w, "    #[allow(unused_imports)]\n    use ::mws_core::{{ErrorFault, ErrorValue, ServiceError}};");
    // `FooException` is `foo()`, unless the model also has a `Foo` error
    // (CloudWatch: `ResourceNotFound` and `ResourceNotFoundException`).
    let names: BTreeSet<&str> = errors.iter().map(|id| model.expect(id).name()).collect();
    for id in errors {
        let s = model.expect(id);
        let (code, status) = match codes {
            ErrorCodes::Shape => error_code_and_status(s, false),
            ErrorCodes::Query => error_code_and_status(s, true),
            ErrorCodes::QueryCompatible => (s.name().to_string(), error_code_and_status(s, true).1),
        };
        let fault = if s.get_trait("error").and_then(Value::as_str) == Some("server") { "Server" } else { "Client" };
        let fn_name = match s.name().strip_suffix("Exception") {
            Some(base) if !names.contains(base) => snake_case(base),
            _ => snake_case(s.name()),
        };
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
    emit_trail(model, w);
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

/// `TRAIL`: what audit logs (CloudTrail) need from the model: the
/// service's event source and the fields holding sensitive values.
fn emit_trail(model: &Model, w: &mut String) {
    let service = model.service().expect("model has a service");
    let info = service.get_trait("aws.api#service");
    let event_source = info
        .and_then(|i| i.get("cloudTrailEventSource"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            let prefix = info.and_then(|i| i.get("endpointPrefix")).and_then(Value::as_str).unwrap_or(service.name());
            format!("{}.amazonaws.com", prefix.to_ascii_lowercase())
        });
    let sensitive_shape = |id: &str| {
        let Some(t) = model.shape(id) else { return false };
        t.has_trait("sensitive")
            || [&t.member, &t.value]
                .into_iter()
                .flatten()
                .any(|m| m.has_trait("sensitive") || model.shape(&m.target).is_some_and(|e| e.has_trait("sensitive")))
    };
    let mut sensitive = BTreeSet::new();
    for s in model.shapes() {
        if !matches!(s.ty, ShapeType::Structure | ShapeType::Union) {
            continue;
        }
        for m in &s.members {
            if m.has_trait("sensitive") || sensitive_shape(&m.target) {
                sensitive.insert(crate::rust_types::field_name(m).trim_start_matches("r#").to_string());
            }
        }
    }
    let mut error_names = BTreeSet::new();
    for s in model.shapes() {
        let code = s.get_trait("aws.protocols#awsQueryError").and_then(|q| q.get("code")).and_then(Value::as_str);
        if let Some(code) = code.filter(|c| *c != s.name()) {
            error_names.insert(format!("({}, {})", rust_str(code), rust_str(s.name())));
        }
    }
    let _ = writeln!(
        w,
        "\n/// What audit logs need from the model.\npub const TRAIL: ::mws_core::trail::ServiceTrail = ::mws_core::trail::ServiceTrail {{ event_source: {}, sensitive: &[{}], error_names: &[{}] }};",
        rust_str(&event_source),
        sensitive.iter().map(|s| rust_str(s)).collect::<Vec<_>>().join(", "),
        error_names.into_iter().collect::<Vec<_>>().join(", ")
    );
}

/// The call to `handler`'s method for `op`, as an expression of type
/// `Result<Output, ServiceError>`, noted for audit logs. `input` is the
/// decoded input (`()` for none).
pub fn handler_call(op: &Shape, input: &str) -> String {
    let method = ident(&snake_case(op.name()));
    format!(
        "::mws_core::trail::call(&TRAIL, {}, {}, {input}, |input| handler.{method}(ctx, input)).await",
        rust_str(op.name()),
        op.has_trait("readonly")
    )
}

/// Constraint-check emission. Patterns are compiled once into `RE_n`
/// statics, emitted by [`Constraints::emit_statics`].
#[derive(Default)]
pub struct Constraints {
    regexes: Vec<String>,
    /// Patterns that need look-around or back-references.
    fancy_regexes: Vec<String>,
}

impl Constraints {
    /// Validation statements for value var `v` (a `&T`) at path var `p`,
    /// against decoder var `d` (anything that derefs to `mws_core::Validator`).
    pub fn checks(&mut self, member: Option<&Member>, target: &Shape) -> String {
        let pick = |name: &str| member.and_then(|m| m.get_trait(name)).or_else(|| target.get_trait(name)).cloned();
        let mut out = String::new();
        let is_string = matches!(target.ty, ShapeType::String | ShapeType::Enum);
        // AWS leaves `@sensitive` values out of validation messages.
        let sensitive = member.is_some_and(|m| m.has_trait("sensitive")) || target.has_trait("sensitive");
        if let Some(b) = Bounds::from_trait(pick("length").as_ref()) {
            let (len, shown) = match target.ty {
                ShapeType::String | ShapeType::Enum => ("v.chars().count()", "v.as_str()".to_string()),
                ShapeType::List | ShapeType::Set => ("v.len()", "&::mws_core::render_list(v)".to_string()),
                _ => ("v.len()", "\"\"".to_string()),
            };
            if sensitive {
                let _ = writeln!(out, "d.check_length_redacted(&p, {len}, {}, {});", opt_u64(b.min), opt_u64(b.max));
            } else {
                let _ = writeln!(out, "d.check_length(&p, {shown}, {len}, {}, {});", opt_u64(b.min), opt_u64(b.max));
            }
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
                    let check = if sensitive { "check_pattern_redacted" } else { "check_pattern" };
                    let _ = writeln!(out, "d.{check}(&p, v, &RE_{idx}, {});", rust_str(&pat));
                } else if let Some(translated) = regex_compat::translate_fancy(&pat) {
                    let idx = match self.fancy_regexes.iter().position(|r| *r == translated) {
                        Some(i) => i,
                        None => {
                            self.fancy_regexes.push(translated);
                            self.fancy_regexes.len() - 1
                        }
                    };
                    // A match that gives up (backtrack limit) is not a violation.
                    let matched = format!("FANCY_RE_{idx}.is_match(v).unwrap_or(true)");
                    let _ = if sensitive {
                        writeln!(out, "d.check_pattern_result_redacted(&p, {matched}, {});", rust_str(&pat))
                    } else {
                        writeln!(out, "d.check_pattern_result(&p, v, {matched}, {});", rust_str(&pat))
                    };
                } else {
                    let _ = writeln!(out, "// pattern {} is not supported; skipped", rust_str(&pat));
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
        for (i, pat) in self.fancy_regexes.iter().enumerate() {
            let _ = writeln!(
                w,
                "    pub(super) static FANCY_RE_{i}: ::std::sync::LazyLock<::mws_core::__private::fancy_regex::Regex> = ::std::sync::LazyLock::new(|| ::mws_core::__private::fancy_regex::Regex::new({}).unwrap());",
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
/// `query_codes` says whether the protocol honours `awsQueryError`: awsQuery
/// does, awsJson only for services marked `awsQueryCompatible`.
pub fn error_code_and_status(s: &Shape, query_codes: bool) -> (String, u16) {
    if let Some(q) = s.get_trait("aws.protocols#awsQueryError").filter(|_| query_codes) {
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
