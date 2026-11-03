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
        self.value_ns(target, v, name, flat, None)
    }

    /// [`XmlSer::value`] for a member, honouring its `xmlNamespace`.
    fn member_value(&self, m: &Member, v: &str, flat: bool) -> String {
        let ns = m.get_trait("xmlNamespace").map(|ns| {
            let uri = ns.get("uri").and_then(Value::as_str).unwrap_or_default().to_string();
            let attr = match ns.get("prefix").and_then(Value::as_str) {
                Some(p) => format!("xmlns:{p}"),
                None => "xmlns".into(),
            };
            (attr, uri)
        });
        self.value_ns(&m.target, v, &rust_str(wire_name(m)), flat, ns)
    }

    fn value_ns(&self, target: &str, v: &str, name: &str, flat: bool, ns: Option<(String, String)>) -> String {
        let s = self.model.expect(target);
        let attr_members: Vec<&Member> = s.members.iter().filter(|m| m.has_trait("xmlAttribute")).collect();
        if matches!(s.ty, ShapeType::Structure) && (ns.is_some() || !attr_members.is_empty()) {
            let mut stmt = String::from("{ let s = ");
            stmt.push_str(v);
            stmt.push_str("; let mut attrs: Vec<(&str, String)> = Vec::new(); ");
            if let Some((attr, uri)) = &ns {
                let _ = write!(stmt, "attrs.push(({}, {}.to_string())); ", rust_str(attr), rust_str(uri));
            }
            for m in attr_members {
                let field = field_name(m);
                let key = rust_str(wire_name(m));
                match presence(m) {
                    Presence::Optional => {
                        let _ = write!(stmt, "if let Some(a) = &s.{field} {{ attrs.push(({key}, a.to_string())); }} ");
                    }
                    _ => {
                        let _ = write!(stmt, "attrs.push(({key}, s.{field}.to_string())); ");
                    }
                }
            }
            let _ = write!(stmt, "w.open_attrs({name}, &attrs); {}(w, s); w.close({name}); }}", ser_fn_name(s));
            return stmt;
        }
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
        for m in s.members.iter().filter(|m| !is_http_bound(m) && !m.has_trait("xmlAttribute")) {
            let flat = m.has_trait("xmlFlattened");
            let field = field_name(m);
            let boxed = self.types.is_boxed(&s.id, &m.target);
            match presence(m) {
                Presence::Optional => {
                    let deref = if boxed { "&**" } else { "" };
                    let stmt = self.member_value(m, &format!("{deref}x"), flat);
                    let _ = writeln!(w, "        if let Some(x) = &v.{field} {{ {stmt} }}");
                }
                _ => {
                    let deref = if boxed { "&*" } else { "" };
                    let stmt = self.member_value(m, &format!("{deref}&v.{field}"), flat);
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
            let stmt = self.member_value(m, &format!("{deref}x"), m.has_trait("xmlFlattened"));
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
