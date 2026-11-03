//! XML serializers for output shapes, shared by awsQuery and restXml. The
//! emitted functions write through `XmlWriter` (from `mws-xml`).

use std::collections::BTreeSet;
use std::fmt::Write;

use mws_smithy::{Member, Model, Shape, ShapeType};
use serde_json::Value;

use crate::common::{qualified_type, ser_fn_name};
use crate::naming::{rust_str, type_name};
use crate::rust_types::{field_name, presence, Presence, TypeGen};

/// Members bound to the HTTP message rather than the XML body.
pub fn is_http_bound(m: &Member) -> bool {
    ["httpLabel", "httpQuery", "httpQueryParams", "httpHeader", "httpPrefixHeaders", "httpResponseCode", "httpPayload"]
        .iter()
        .any(|t| m.has_trait(t))
}

/// The XML element name of a member.
pub fn wire_name(m: &Member) -> &str {
    m.get_trait("xmlName").and_then(Value::as_str).unwrap_or(&m.name)
}

pub struct XmlSer<'a, 'm> {
    pub model: &'m Model,
    pub types: &'a TypeGen<'m>,
}

impl XmlSer<'_, '_> {
    /// Emit `ser_*` functions for every aggregate in `closure`.
    pub fn emit_all(&self, closure: &BTreeSet<String>, w: &mut String) {
        for id in closure {
            let s = self.model.expect(id);
            match s.ty {
                ShapeType::Structure => self.emit_struct(s, w),
                ShapeType::Union => self.emit_union(s, w),
                ShapeType::List | ShapeType::Set => self.emit_list(s, w),
                ShapeType::Map => self.emit_map(s, w),
                _ => {}
            }
        }
    }

    /// Statements writing value expr `v` (a reference) as element `name`.
    pub fn value(&self, target: &str, v: &str, name: &str, flat: bool) -> String {
        let s = self.model.expect(target);
        match s.ty {
            ShapeType::String
            | ShapeType::Enum
            | ShapeType::BigInteger
            | ShapeType::BigDecimal
            | ShapeType::Document => format!("w.leaf({name}, {v});"),
            ShapeType::Boolean => format!("w.leaf_bool({name}, *{v});"),
            ShapeType::Byte
            | ShapeType::Short
            | ShapeType::Integer
            | ShapeType::IntEnum
            | ShapeType::Long
            | ShapeType::Float
            | ShapeType::Double => format!("w.leaf_num({name}, {v});"),
            ShapeType::Timestamp => format!("w.leaf_timestamp({name}, {v});"),
            ShapeType::Blob => format!("w.leaf_blob({name}, {v});"),
            ShapeType::Structure | ShapeType::Union => {
                format!("w.open({name}); {}(w, {v}); w.close({name});", ser_fn_name(s))
            }
            ShapeType::List | ShapeType::Set | ShapeType::Map => format!("{}(w, {name}, {v}, {flat});", ser_fn_name(s)),
            _ => String::new(),
        }
    }

    fn emit_struct(&self, s: &Shape, w: &mut String) {
        let ty = type_name(s.name());
        let _ = writeln!(w, "    pub(super) fn {}(w: &mut XmlWriter, v: &types::{ty}) {{", ser_fn_name(s));
        for m in s.members.iter().filter(|m| !is_http_bound(m)) {
            let wire = wire_name(m);
            let flat = m.has_trait("xmlFlattened");
            let field = field_name(m);
            let boxed = self.types.is_boxed(&s.id, &m.target);
            match presence(m) {
                Presence::Optional => {
                    let deref = if boxed { "&**" } else { "" };
                    let stmt = self.value(&m.target, &format!("{deref}x"), &rust_str(wire), flat);
                    let _ = writeln!(w, "        if let Some(x) = &v.{field} {{ {stmt} }}");
                }
                _ => {
                    let deref = if boxed { "&*" } else { "" };
                    let stmt = self.value(&m.target, &format!("{deref}&v.{field}"), &rust_str(wire), flat);
                    let _ = writeln!(w, "        {stmt}");
                }
            }
        }
        let _ = writeln!(w, "    }}");
    }

    fn emit_union(&self, s: &Shape, w: &mut String) {
        let ty = type_name(s.name());
        let _ = writeln!(w, "    pub(super) fn {}(w: &mut XmlWriter, v: &types::{ty}) {{", ser_fn_name(s));
        let _ = writeln!(w, "        match v {{");
        for m in &s.members {
            let deref = if self.types.is_boxed(&s.id, &m.target) { "&**" } else { "" };
            let stmt =
                self.value(&m.target, &format!("{deref}x"), &rust_str(wire_name(m)), m.has_trait("xmlFlattened"));
            let _ = writeln!(w, "            types::{ty}::{}(x) => {{ {stmt} }}", type_name(&m.name));
        }
        let _ = writeln!(w, "        }}\n    }}");
    }

    fn emit_list(&self, s: &Shape, w: &mut String) {
        let member = s.member.as_ref().unwrap();
        let item_name = member.get_trait("xmlName").and_then(Value::as_str).unwrap_or("member");
        let elem_ty = qualified_type(self.model, &member.target);
        let item_stmt = self.value(&member.target, "x", &rust_str(item_name), false);
        let flat_stmt = self.value(&member.target, "x", "name", false);
        let _ = writeln!(
            w,
            "    pub(super) fn {}(w: &mut XmlWriter, name: &str, v: &[{elem_ty}], flat: bool) {{",
            ser_fn_name(s)
        );
        let _ = writeln!(w, "        if flat {{ for x in v {{ {flat_stmt} }} return; }}");
        let _ = writeln!(w, "        w.open(name);");
        let _ = writeln!(w, "        for x in v {{ {item_stmt} }}");
        let _ = writeln!(w, "        w.close(name);");
        let _ = writeln!(w, "    }}");
    }

    fn emit_map(&self, s: &Shape, w: &mut String) {
        let key_m = s.key.as_ref().unwrap();
        let val_m = s.value.as_ref().unwrap();
        let key_name = key_m.get_trait("xmlName").and_then(Value::as_str).unwrap_or("key");
        let val_name = val_m.get_trait("xmlName").and_then(Value::as_str).unwrap_or("value");
        let value_ty = qualified_type(self.model, &val_m.target);
        let val_stmt = self.value(&val_m.target, "x", &rust_str(val_name), false);
        let _ = writeln!(
            w,
            "    pub(super) fn {}(w: &mut XmlWriter, name: &str, v: &::std::collections::BTreeMap<String, {value_ty}>, flat: bool) {{",
            ser_fn_name(s)
        );
        let _ = writeln!(w, "        if !flat {{ w.open(name); }}");
        let _ = writeln!(w, "        for (k, x) in v {{");
        let _ = writeln!(w, "            w.open(if flat {{ name }} else {{ \"entry\" }});");
        let _ = writeln!(w, "            w.leaf({}, k);", rust_str(key_name));
        let _ = writeln!(w, "            {val_stmt}");
        let _ = writeln!(w, "            w.close(if flat {{ name }} else {{ \"entry\" }});");
        let _ = writeln!(w, "        }}");
        let _ = writeln!(w, "        if !flat {{ w.close(name); }}");
        let _ = writeln!(w, "    }}");
    }
}
