//! JSON encoding and decoding of a service's shapes, keyed by Smithy member
//! name. awsJson uses it on the wire; every protocol uses it for
//! [`emit_invoke`], the protocol-independent entry point MWS uses to run
//! operations from JSON (scenario files).

use std::collections::BTreeSet;
use std::fmt::Write;

use mws_smithy::{Member, Model, Shape, ShapeType};

use crate::common::{de_fn_name, qualified_type, ser_fn_name, Constraints};
use crate::naming::{ident, lower_camel, rust_str, snake_case, type_name};
use crate::rust_types::{field_name, presence, Presence, TypeGen};

const RT: &str = "::mws_proto_json";

pub struct JsonCodec<'t, 'm> {
    model: &'m Model,
    types: &'t TypeGen<'m>,
    constraints: Constraints,
}

impl<'t, 'm> JsonCodec<'t, 'm> {
    pub fn new(model: &'m Model, types: &'t TypeGen<'m>) -> Self {
        Self { model, types, constraints: Constraints::default() }
    }

    /// `mod {name}`: a decoder per structure, union, list and map in
    /// `closure`, with constraint checks.
    pub fn de_module(&mut self, closure: &BTreeSet<String>, name: &str) -> String {
        let mut de = String::new();
        for id in closure {
            let s = self.model.expect(id);
            match s.ty {
                ShapeType::Structure | ShapeType::Union => self.emit_de_aggregate(s, &mut de),
                ShapeType::List | ShapeType::Set => self.emit_de_list(s, &mut de),
                ShapeType::Map => self.emit_de_map(s, &mut de),
                _ => {}
            }
        }
        let mut out = String::new();
        let _ = writeln!(
            out,
            "\n#[allow(unused_variables, unused_mut, unused_imports, clippy::all)]\nmod {name} {{\n    use super::*;"
        );
        let _ = writeln!(out, "    use {RT}::{{Decoder, Map, Value}};");
        self.constraints.emit_statics(RT, &mut out);
        out.push_str(&de);
        let _ = writeln!(out, "}}");
        out
    }

    /// `mod {name}`: an encoder per structure, union, list and map in
    /// `closure`.
    pub fn ser_module(&self, closure: &BTreeSet<String>, name: &str) -> String {
        let mut ser = String::new();
        for id in closure {
            let s = self.model.expect(id);
            match s.ty {
                ShapeType::Structure | ShapeType::Union => self.emit_ser_aggregate(s, &mut ser),
                ShapeType::List | ShapeType::Set => self.emit_ser_list(s, &mut ser),
                ShapeType::Map => self.emit_ser_map(s, &mut ser),
                _ => {}
            }
        }
        let mut out = String::new();
        let _ = writeln!(
            out,
            "\n#[allow(unused_variables, unused_mut, unused_imports, clippy::all)]\nmod {name} {{\n    use super::*;"
        );
        let _ = writeln!(out, "    use {RT}::{{Map, Value}};");
        out.push_str(&ser);
        let _ = writeln!(out, "}}");
        out
    }

    // ---- decoding ----------------------------------------------------------

    /// `Option<T>` decoding `target` from `src` (an `Option<&Value>`).
    fn de_expr(&self, target: &str, src: &str) -> String {
        self.de_expr_in(target, src, "")
    }

    /// [`JsonCodec::de_expr`] from outside the decoder module: aggregate
    /// decoders are named with `module` (e.g. `"json_de::"`).
    pub(crate) fn de_expr_in(&self, target: &str, src: &str, module: &str) -> String {
        let s = self.model.expect(target);
        match s.ty {
            ShapeType::String | ShapeType::Enum | ShapeType::BigInteger | ShapeType::BigDecimal => {
                format!("d.string({src}, &p)")
            }
            ShapeType::Document => format!("Decoder::present({src}).map(|v| v.to_string())"),
            ShapeType::Boolean => format!("d.boolean({src}, &p)"),
            ShapeType::Byte => format!("d.integer::<i8>({src}, &p)"),
            ShapeType::Short => format!("d.integer::<i16>({src}, &p)"),
            ShapeType::Integer | ShapeType::IntEnum => format!("d.integer::<i32>({src}, &p)"),
            ShapeType::Long => format!("d.integer::<i64>({src}, &p)"),
            ShapeType::Float => format!("d.float({src}, &p).map(|f| f as f32)"),
            ShapeType::Double => format!("d.float({src}, &p)"),
            ShapeType::Timestamp => format!("d.timestamp({src}, &p)"),
            ShapeType::Blob => format!("d.blob({src}, &p)"),
            _ => format!("{module}{}(d, {src}, &p)", de_fn_name(s)),
        }
    }

    fn emit_de_aggregate(&mut self, s: &Shape, w: &mut String) {
        let ty = type_name(s.name());
        let is_union = s.ty == ShapeType::Union;
        let _ = writeln!(
            w,
            "    pub(super) fn {}(d: &mut Decoder, v: Option<&Value>, path: &str) -> Option<types::{ty}> {{",
            de_fn_name(s)
        );
        let _ = writeln!(w, "        let obj = d.object(v, if path.is_empty() {{ \"input\" }} else {{ path }})?;");
        if is_union {
            let _ = writeln!(w, "        let mut out: Option<types::{ty}> = None;");
        } else {
            let _ = writeln!(w, "        let mut out = types::{ty}::default();");
        }
        for m in &s.members {
            let target = self.model.expect(&m.target).clone();
            let camel = lower_camel(&m.name);
            let _ = writeln!(w, "        {{");
            let _ = writeln!(
                w,
                "            let p = if path.is_empty() {{ {}.to_string() }} else {{ format!(\"{{path}}.{camel}\") }};",
                rust_str(&camel)
            );
            let _ = writeln!(
                w,
                "            let val = {};",
                self.de_expr(&m.target, &format!("obj.get({})", rust_str(&m.name)))
            );
            let checks = self.constraints.checks(Some(m), &target);
            if !checks.is_empty() {
                let _ = writeln!(w, "            if let Some(v) = &val {{ {checks} }}");
            }
            let boxed = self.types.is_boxed(&s.id, &m.target);
            let wrap = if boxed { "::std::boxed::Box::new(v)" } else { "v" };
            let field = field_name(m);
            if is_union {
                let _ = writeln!(
                    w,
                    "            if out.is_none() {{ if let Some(v) = val {{ out = Some(types::{ty}::{}({wrap})); }} }}",
                    type_name(&m.name)
                );
            } else if self.is_event_stream(m) {
                let _ = writeln!(w, "            out.{field} = val.into_iter().collect();");
            } else {
                let stmt = match presence(m) {
                    Presence::Required => {
                        format!("d.required(&val, &p); if let Some(v) = val {{ out.{field} = {wrap}; }}")
                    }
                    Presence::Defaulted => format!("if let Some(v) = val {{ out.{field} = {wrap}; }}"),
                    Presence::Optional => format!("out.{field} = val.map(|v| {wrap});"),
                };
                let _ = writeln!(w, "            {stmt}");
            }
            let _ = writeln!(w, "        }}");
        }
        let _ = writeln!(w, "        {}", if is_union { "out" } else { "Some(out)" });
        let _ = writeln!(w, "    }}");
    }

    fn emit_de_list(&mut self, s: &Shape, w: &mut String) {
        let member = s.member.clone().unwrap();
        let target = self.model.expect(&member.target).clone();
        let _ = writeln!(
            w,
            "    pub(super) fn {}(d: &mut Decoder, v: Option<&Value>, path: &str) -> Option<{}> {{",
            de_fn_name(s),
            qualified_type(self.model, &s.id)
        );
        let _ = writeln!(w, "        let arr = d.array(v, path)?;");
        let _ = writeln!(w, "        let mut out = Vec::with_capacity(arr.len());");
        let _ = writeln!(w, "        for (i, item) in arr.iter().enumerate() {{");
        let _ = writeln!(w, "            let p = format!(\"{{path}}.{{}}.member\", i + 1);");
        let _ = writeln!(w, "            let val = {};", self.de_expr(&member.target, "Some(item)"));
        let checks = self.constraints.checks(Some(&member), &target);
        let _ = writeln!(w, "            if let Some(v) = val {{ {{ let v = &v; {checks} }} out.push(v); }}");
        let _ = writeln!(w, "        }}");
        let _ = writeln!(w, "        Some(out)");
        let _ = writeln!(w, "    }}");
    }

    fn emit_de_map(&mut self, s: &Shape, w: &mut String) {
        let key_m = s.key.clone().unwrap();
        let val_m = s.value.clone().unwrap();
        let key_target = self.model.expect(&key_m.target).clone();
        let val_target = self.model.expect(&val_m.target).clone();
        let value_ty = qualified_type(self.model, &val_m.target);
        let _ = writeln!(
            w,
            "    pub(super) fn {}(d: &mut Decoder, v: Option<&Value>, path: &str) -> Option<::std::collections::BTreeMap<String, {value_ty}>> {{",
            de_fn_name(s)
        );
        let _ = writeln!(w, "        let obj = d.object(v, path)?;");
        let _ = writeln!(w, "        let mut out = ::std::collections::BTreeMap::new();");
        let _ = writeln!(w, "        for (k, item) in obj {{");
        let _ = writeln!(w, "            let p = format!(\"{{path}}.{{k}}\");");
        let kc = self.constraints.checks(Some(&key_m), &key_target);
        let _ = writeln!(w, "            {{ let v = k; {kc} }}");
        let _ = writeln!(w, "            let val = {};", self.de_expr(&val_m.target, "Some(item)"));
        let vc = self.constraints.checks(Some(&val_m), &val_target);
        let _ = writeln!(w, "            if let Some(v) = val {{ {{ let v = &v; {vc} }} out.insert(k.clone(), v); }}");
        let _ = writeln!(w, "        }}");
        let _ = writeln!(w, "        Some(out)");
        let _ = writeln!(w, "    }}");
    }

    // ---- serialization -----------------------------------------------------

    /// `Value` expression for reference expr `x` of `target`.
    fn ser_expr(&self, target: &str, x: &str) -> String {
        self.ser_expr_in(target, x, "")
    }

    /// [`JsonCodec::ser_expr`] from outside the encoder module.
    pub(crate) fn ser_expr_in(&self, target: &str, x: &str, module: &str) -> String {
        let s = self.model.expect(target);
        match s.ty {
            ShapeType::String | ShapeType::Enum | ShapeType::BigInteger | ShapeType::BigDecimal => {
                format!("Value::String(({x}).clone())")
            }
            ShapeType::Document => {
                format!("{RT}::__private::serde_json::from_str(&{x}).unwrap_or(Value::Null)")
            }
            ShapeType::Boolean => format!("Value::Bool(*{x})"),
            ShapeType::Byte | ShapeType::Short | ShapeType::Integer | ShapeType::IntEnum | ShapeType::Long => {
                format!("Value::from(*{x})")
            }
            ShapeType::Float | ShapeType::Double => format!("{RT}::ser_float(*{x} as f64)"),
            ShapeType::Timestamp => format!("{RT}::ser_timestamp({x})"),
            ShapeType::Blob => format!("{RT}::ser_blob({x})"),
            _ => format!("{module}{}({x})", ser_fn_name(s)),
        }
    }

    fn emit_ser_aggregate(&self, s: &Shape, w: &mut String) {
        let ty = type_name(s.name());
        let _ = writeln!(w, "    pub(super) fn {}(v: &types::{ty}) -> Value {{", ser_fn_name(s));
        let _ = writeln!(w, "        let mut m = Map::new();");
        if s.ty == ShapeType::Union {
            let _ = writeln!(w, "        match v {{");
            for mem in &s.members {
                let deref = if self.types.is_boxed(&s.id, &mem.target) { "&**x" } else { "x" };
                let _ = writeln!(
                    w,
                    "            types::{ty}::{}(x) => {{ m.insert({}.into(), {}); }}",
                    type_name(&mem.name),
                    rust_str(&mem.name),
                    self.ser_expr(&mem.target, deref)
                );
            }
            let _ = writeln!(w, "        }}");
        } else {
            for mem in &s.members {
                let field = field_name(mem);
                let boxed = self.types.is_boxed(&s.id, &mem.target);
                let name = rust_str(&mem.name);
                if self.is_event_stream(mem) {
                    let _ = writeln!(
                        w,
                        "        m.insert({name}.into(), Value::Array(v.{field}.iter().map(|x| {}).collect()));",
                        self.ser_expr(&mem.target, "x")
                    );
                    continue;
                }
                match presence(mem) {
                    Presence::Optional => {
                        let x = if boxed { "&**x" } else { "x" };
                        let _ = writeln!(
                            w,
                            "        if let Some(x) = &v.{field} {{ m.insert({name}.into(), {}); }}",
                            self.ser_expr(&mem.target, x)
                        );
                    }
                    _ => {
                        let x = if boxed { format!("&*v.{field}") } else { format!("&v.{field}") };
                        let _ = writeln!(w, "        m.insert({name}.into(), {});", self.ser_expr(&mem.target, &x));
                    }
                }
            }
        }
        let _ = writeln!(w, "        Value::Object(m)\n    }}");
    }

    /// A structure member holding an event stream (a `Vec` of events).
    fn is_event_stream(&self, m: &Member) -> bool {
        let t = self.model.expect(&m.target);
        t.ty == ShapeType::Union && t.has_trait("streaming")
    }

    fn emit_ser_list(&self, s: &Shape, w: &mut String) {
        let member = s.member.as_ref().unwrap();
        let elem_ty = qualified_type(self.model, &member.target);
        let _ = writeln!(
            w,
            "    pub(super) fn {}(v: &[{elem_ty}]) -> Value {{ Value::Array(v.iter().map(|x| {}).collect()) }}",
            ser_fn_name(s),
            self.ser_expr(&member.target, "x")
        );
    }

    fn emit_ser_map(&self, s: &Shape, w: &mut String) {
        let val_m = s.value.as_ref().unwrap();
        let value_ty = qualified_type(self.model, &val_m.target);
        let _ = writeln!(
            w,
            "    pub(super) fn {}(v: &::std::collections::BTreeMap<String, {value_ty}>) -> Value {{ Value::Object(v.iter().map(|(k, x)| (k.clone(), {})).collect()) }}",
            ser_fn_name(s),
            self.ser_expr(&val_m.target, "x")
        );
    }
}

/// `pub async fn invoke`: run an operation by name with JSON input and get
/// JSON output, using the decoders in `de_mod` and encoders in `ser_mod`.
/// Input is validated exactly like a wire request; constraint violations
/// use `validation_error`.
pub fn emit_invoke(model: &Model, ops: &[&Shape], de_mod: &str, ser_mod: &str, validation_error: &str, w: &mut String) {
    let _ = writeln!(
        w,
        "\n/// Run `operation` with input given as JSON (Smithy member names) and return its output as JSON.\n#[allow(unused_mut, clippy::all)]\npub async fn invoke<H: Handler + ?Sized>(handler: &H, ctx: &RequestContext, operation: &str, input: {RT}::Value) -> Result<{RT}::Value, ServiceError> {{"
    );
    let _ = writeln!(w, "    match operation {{");
    for op in ops {
        let method = ident(&snake_case(op.name()));
        let _ = writeln!(w, "        {} => {{", rust_str(op.name()));
        match &op.input {
            Some(i) => {
                let _ = writeln!(w, "            let mut d = {RT}::Decoder::new();");
                let _ = writeln!(
                    w,
                    "            let input = {de_mod}::{}(&mut d, Some(&input), \"\").unwrap_or_default();",
                    de_fn_name(model.expect(i))
                );
                let _ = writeln!(w, "            d.finish({})?;", rust_str(validation_error));
                let _ = writeln!(w, "            let out = handler.{method}(ctx, input).await?;");
            }
            None => {
                let _ = writeln!(w, "            let out = handler.{method}(ctx, ()).await?;");
            }
        }
        match &op.output {
            Some(o) => {
                let _ = writeln!(w, "            Ok({ser_mod}::{}(&out))", ser_fn_name(model.expect(o)));
            }
            None => {
                let _ = writeln!(w, "            let () = out;\n            Ok({RT}::Value::Object({RT}::Map::new()))");
            }
        }
        let _ = writeln!(w, "        }}");
    }
    let _ = writeln!(w, "        other => Err(::mws_core::ServiceError::unknown_operation(other)),");
    let _ = writeln!(w, "    }}\n}}");
}
