//! Protocol-independent parts of code generation: which shapes to emit,
//! their Rust types, and their struct/enum definitions.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;

use mws_smithy::{local_name, Member, Model, Shape, ShapeType};
use serde_json::Value;

use crate::naming::{ident, rust_str, snake_case, type_name};

/// How a structure member is stored in its Rust struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// `@required`: stored as `T`.
    Required,
    /// `@default`: stored as `T`, filled with the default when absent.
    Defaulted,
    /// Everything else: `Option<T>`.
    Optional,
}

pub fn presence(member: &Member) -> Presence {
    if member.has_trait("required") {
        Presence::Required
    } else if member.get_trait("default").is_some_and(|v| !v.is_null()) {
        Presence::Defaulted
    } else {
        Presence::Optional
    }
}

pub fn field_name(member: &Member) -> String {
    ident(&snake_case(&member.name))
}

pub struct TypeGen<'m> {
    pub model: &'m Model,
    /// Structure/union ids that reach themselves through direct members, so
    /// the edge needs a `Box`.
    boxed_edges: BTreeSet<(String, String)>,
}

impl<'m> TypeGen<'m> {
    pub fn new(model: &'m Model) -> Self {
        let mut tg = Self { model, boxed_edges: BTreeSet::new() };
        tg.find_recursive_edges();
        tg
    }

    /// The Rust type for a member target, from inside the `types` module.
    pub fn rust_type(&self, target: &str) -> String {
        let s = self.model.expect(target);
        match s.ty {
            ShapeType::List | ShapeType::Set => {
                format!("::std::vec::Vec<{}>", self.rust_type(&s.member.as_ref().unwrap().target))
            }
            ShapeType::Map => format!(
                "::std::collections::BTreeMap<::std::string::String, {}>",
                self.rust_type(&s.value.as_ref().unwrap().target)
            ),
            ShapeType::Structure | ShapeType::Union => type_name(s.name()),
            other => scalar_type(other).to_string(),
        }
    }

    pub fn is_boxed(&self, owner: &str, target: &str) -> bool {
        self.boxed_edges.contains(&(owner.to_string(), target.to_string()))
    }

    /// The field type including `Box` and `Option` wrappers.
    pub fn field_type(&self, owner: &Shape, member: &Member) -> String {
        let target = self.model.expect(&member.target);
        if owner.ty == ShapeType::Structure && target.ty == ShapeType::Union && target.has_trait("streaming") {
            // An event stream: the events, in order.
            return format!("::std::vec::Vec<{}>", type_name(target.name()));
        }
        let mut t = self.rust_type(&member.target);
        if self.is_boxed(&owner.id, &member.target) {
            t = format!("::std::boxed::Box<{t}>");
        }
        match (owner.ty, presence(member)) {
            (ShapeType::Union, _) => t,
            (_, Presence::Optional) => format!("::std::option::Option<{t}>"),
            _ => t,
        }
    }

    fn direct_aggregate_targets(&self, s: &Shape) -> Vec<String> {
        s.members
            .iter()
            .filter(|m| matches!(self.model.expect(&m.target).ty, ShapeType::Structure | ShapeType::Union))
            .map(|m| m.target.clone())
            .collect()
    }

    fn find_recursive_edges(&mut self) {
        let aggregates: Vec<&Shape> =
            self.model.shapes().filter(|s| matches!(s.ty, ShapeType::Structure | ShapeType::Union)).collect();
        let mut graph: HashMap<&str, Vec<String>> = HashMap::new();
        for s in &aggregates {
            graph.insert(&s.id, self.direct_aggregate_targets(s));
        }
        for s in &aggregates {
            for t in &graph[s.id.as_str()] {
                if reaches(&graph, t, &s.id) {
                    self.boxed_edges.insert((s.id.clone(), t.clone()));
                }
            }
        }
    }

    /// All shapes reachable from `roots` through members (including roots).
    pub fn closure(&self, roots: impl IntoIterator<Item = String>) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<String> = roots.into_iter().collect();
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let s = self.model.expect(&id);
            for m in s.members.iter().chain(s.member.iter()).chain(s.key.iter()).chain(s.value.iter()) {
                if s.ty != ShapeType::Enum && s.ty != ShapeType::IntEnum {
                    stack.push(m.target.clone());
                }
            }
        }
        seen
    }

    /// Emit Rust definitions for every structure and union in `ids`.
    pub fn emit_types(&self, ids: &BTreeSet<String>, out: &mut String) {
        for id in ids {
            let s = self.model.expect(id);
            match s.ty {
                ShapeType::Structure if s.members.is_empty() && id == mws_smithy::UNIT => {}
                ShapeType::Structure => self.emit_struct(s, out),
                ShapeType::Union => self.emit_union(s, out),
                ShapeType::Enum => self.emit_enum_values(s, out),
                _ => {}
            }
        }
    }

    fn emit_struct(&self, s: &Shape, out: &mut String) {
        let name = type_name(s.name());
        let _ = writeln!(out, "/// Smithy shape `{}`.", s.id);
        let _ = writeln!(out, "#[derive(Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize)]");
        let _ = writeln!(out, "#[serde(default)]");
        let _ = writeln!(out, "pub struct {name} {{");
        for m in &s.members {
            let _ = writeln!(out, "    pub {}: {},", field_name(m), self.field_type(s, m));
        }
        let _ = writeln!(out, "}}");
        let _ = writeln!(out, "impl ::std::default::Default for {name} {{");
        let _ = writeln!(out, "    fn default() -> Self {{");
        let _ = writeln!(out, "        Self {{");
        for m in &s.members {
            let _ = writeln!(out, "            {}: {},", field_name(m), self.default_expr(m));
        }
        let _ = writeln!(out, "        }}");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(out, "}}");
    }

    fn default_expr(&self, m: &Member) -> String {
        if presence(m) == Presence::Defaulted {
            let target = self.model.expect(&m.target);
            match (m.get_trait("default"), target.ty) {
                (Some(Value::Bool(b)), _) => return b.to_string(),
                (Some(Value::String(s)), ShapeType::String | ShapeType::Enum) => {
                    return format!("::std::string::String::from({})", rust_str(s));
                }
                (Some(Value::Number(n)), ShapeType::Float | ShapeType::Double) => {
                    return format!("{}_f64 as _", n.as_f64().unwrap_or(0.0));
                }
                (Some(Value::Number(n)), _) if n.as_i64().is_some() => {
                    return format!("{}", n.as_i64().unwrap());
                }
                _ => {}
            }
        }
        "::std::default::Default::default()".into()
    }

    fn emit_union(&self, s: &Shape, out: &mut String) {
        let name = type_name(s.name());
        let _ = writeln!(out, "/// Smithy union `{}`.", s.id);
        let _ = writeln!(out, "#[derive(Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize)]");
        let _ = writeln!(out, "pub enum {name} {{");
        for m in &s.members {
            let _ = writeln!(out, "    {}({}),", type_name(&m.name), self.field_type(s, m));
        }
        let _ = writeln!(out, "}}");
        let first = &s.members[0];
        let _ = writeln!(
            out,
            "impl ::std::default::Default for {name} {{ fn default() -> Self {{ Self::{}(::std::default::Default::default()) }} }}",
            type_name(&first.name)
        );
    }

    fn emit_enum_values(&self, s: &Shape, out: &mut String) {
        let values = enum_values(s);
        let _ = writeln!(out, "/// Allowed values of the Smithy enum `{}`.", s.id);
        let _ = writeln!(
            out,
            "pub const {}: &[&str] = &[{}];",
            enum_const_name(s),
            values.iter().map(|v| rust_str(v)).collect::<Vec<_>>().join(", ")
        );
    }
}

/// Rust type of a simple (scalar) shape.
pub fn scalar_type(ty: ShapeType) -> &'static str {
    match ty {
        ShapeType::String | ShapeType::Enum | ShapeType::BigInteger | ShapeType::BigDecimal | ShapeType::Document => {
            "::std::string::String"
        }
        ShapeType::Boolean => "bool",
        ShapeType::Byte => "i8",
        ShapeType::Short => "i16",
        ShapeType::Integer | ShapeType::IntEnum => "i32",
        ShapeType::Long => "i64",
        ShapeType::Float => "f32",
        ShapeType::Double => "f64",
        ShapeType::Timestamp => "chrono::DateTime<chrono::Utc>",
        ShapeType::Blob => "::std::vec::Vec<u8>",
        other => panic!("{other:?} is not a scalar shape"),
    }
}

pub fn enum_values(s: &Shape) -> Vec<String> {
    s.members
        .iter()
        .map(|m| m.get_trait("enumValue").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| m.name.clone()))
        .collect()
}

pub fn enum_const_name(s: &Shape) -> String {
    snake_case(local_name(&s.id)).to_ascii_uppercase()
}

fn reaches(graph: &HashMap<&str, Vec<String>>, from: &str, to: &str) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack = vec![from.to_string()];
    while let Some(n) = stack.pop() {
        if n == to {
            return true;
        }
        if !seen.insert(n.clone()) {
            continue;
        }
        if let Some(next) = graph.get(n.as_str()) {
            stack.extend(next.iter().cloned());
        }
    }
    false
}
